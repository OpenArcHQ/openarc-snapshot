import { z } from "zod";

import { IsoTimestampSchema } from "../primitives.js";
import {
  CommerceAgentIdSchema,
  CommerceOrganizationIdSchema,
} from "./identity.js";
import {
  CommercePolicyContentSchema,
  type CommercePolicyContent,
} from "./control-policy.js";

/**
 * P03 exact budget arithmetic kernel.
 *
 * Pure arithmetic only. Nothing here reserves money, approves an action,
 * verifies a policy requirement, owns a clock, authorizes a principal, makes a
 * listing purchasable or publishes a capability. PostgreSQL remains the sole
 * authority: a later SQL transaction must reload and revalidate the complete
 * exposure under stable subject locks and reproduce these vectors. The current
 * listing `paymentLane` stays unavailable.
 *
 * Both functions handle untrusted `unknown` input through a total `safeParse`
 * and never echo caller content: any invalid input fails with the single fixed
 * `COMMERCE_BUDGET_INPUT_INVALID` error. They do NOT validate provider/listing
 * scope, current authorization, allowlist/expiry/session/listing status or any
 * verified requirement. `assessment` is advisory numerical bookkeeping, never
 * a reservation, grant or approval.
 */

export const COMMERCE_BUDGET_INPUT_INVALID =
  "COMMERCE_BUDGET_INPUT_INVALID" as const;

// Version nibble is pinned to 4 (frozen canonical UUIDv4); the variant nibble
// is [89ab]. Versions 1-3 and 5-8 are not this boundary's canonical identity.
const UUID_PATTERN =
  "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";

// `(?![\s\S])` pins the absolute end of input so a trailing LF cannot satisfy
// `$`. This new boundary is stricter than the legacy primitive `$` regex.
export const CommerceActionIdSchema = z.string().regex(
  new RegExp(`^openarc:action:${UUID_PATTERN}(?![\\s\\S])`),
  { message: "Expected a canonical lower-case openarc:action: UUID" },
);

export type CommerceActionId = z.infer<typeof CommerceActionIdSchema>;

/**
 * Stable exposure identity. Deliberately excludes policy id/revision: a
 * different policy root cannot reset one subject's already-existing exposure.
 */
export const CommerceExposureKeySchema = z.strictObject({
  organizationId: CommerceOrganizationIdSchema,
  subjectAgentId: CommerceAgentIdSchema,
  networkId: z.literal("eip155:5042002"),
  asset: z.literal("USDC"),
  representation: z.literal("erc20"),
  decimals: z.literal(6),
});

export type CommerceExposureKey = z.infer<typeof CommerceExposureKeySchema>;

// Canonical nonnegative decimal of at most 128 digits with an absolute input
// end. Used only for bounded aggregate DTOs; individual amount components stay
// uint256 and sums are accumulated as exact BigInt without wrap or clamp.
const EXPOSURE_TOTAL_PATTERN = /^(0|[1-9][0-9]{0,127})(?![\s\S])/u;

export const CommerceExposureTotalSchema = z
  .string()
  .regex(EXPOSURE_TOTAL_PATTERN, {
    message: "Expected a canonical nonnegative decimal of at most 128 digits",
  });

export type CommerceExposureTotal = z.infer<typeof CommerceExposureTotalSchema>;

// Canonical positive uint256 with an absolute input end.
const POSITIVE_UINT256_PATTERN = /^[1-9][0-9]{0,77}(?![\s\S])/u;
const UINT256_PATTERN = /^(0|[1-9][0-9]{0,77})(?![\s\S])/u;
const MAX_UINT256 = (1n << 256n) - 1n;

function isPositiveUint256(value: string): boolean {
  return (
    POSITIVE_UINT256_PATTERN.test(value) && BigInt(value) <= MAX_UINT256
  );
}

function isCanonicalUint256(value: string): boolean {
  return UINT256_PATTERN.test(value) && BigInt(value) <= MAX_UINT256;
}

// A computed aggregate stays inside the exported bounded DTO contract: at most
// 128 canonical decimal digits. Zero counts as one digit. This is a check, not
// a clamp — values above the bound are rejected, never wrapped or truncated.
function isWithinExposureTotalDigits(value: bigint): boolean {
  return value < 10n ** 128n;
}

const PositiveUint256DecimalSchema = z
  .string()
  .regex(POSITIVE_UINT256_PATTERN, {
    message: "Expected a canonical positive uint256",
  })
  .refine(isPositiveUint256, {
    message: "Expected a canonical positive uint256",
  });

const Uint256DecimalAbsoluteSchema = z
  .string()
  .regex(UINT256_PATTERN, { message: "Expected a canonical uint256" })
  .refine(isCanonicalUint256, { message: "Expected a canonical uint256" });

// Canonical whole-second window 1..2592000 with an absolute input end.
const WINDOW_SECONDS_PATTERN = /^[1-9][0-9]{0,6}(?![\s\S])/u;

export const CommerceWindowSecondsSchema = z
  .string()
  .regex(WINDOW_SECONDS_PATTERN, {
    message: "Expected canonical window seconds 1..2592000",
  })
  .refine(
    (value) =>
      WINDOW_SECONDS_PATTERN.test(value) && BigInt(value) <= 2592000n,
    { message: "Expected canonical window seconds 1..2592000" },
  );

export type CommerceWindowSeconds = z.infer<typeof CommerceWindowSecondsSchema>;

const CommerceCommittedRecordSchema = z.strictObject({
  actionId: CommerceActionIdSchema,
  amountAtomic: PositiveUint256DecimalSchema,
  committedAt: IsoTimestampSchema,
});

const CommerceUnresolvedRecordSchema = z.strictObject({
  actionId: CommerceActionIdSchema,
  amountAtomic: PositiveUint256DecimalSchema,
  createdAt: IsoTimestampSchema,
});

const CommerceBudgetExposureInputSchema = z
  .strictObject({
    exposureKey: CommerceExposureKeySchema,
    now: IsoTimestampSchema,
    windowSeconds: CommerceWindowSecondsSchema,
    complete: z.literal(true),
    committed: z.array(CommerceCommittedRecordSchema).max(4096),
    unresolved: z.array(CommerceUnresolvedRecordSchema).max(4096),
  })
  .superRefine((value, ctx) => {
    const committedIds = value.committed.map((record) => record.actionId);
    const unresolvedIds = value.unresolved.map((record) => record.actionId);
    if (!isStrictlyAscending(committedIds)) {
      ctx.addIssue({
        code: "custom",
        path: ["committed"],
        message: "committed actionIds must be strictly ascending and unique",
      });
    }
    if (!isStrictlyAscending(unresolvedIds)) {
      ctx.addIssue({
        code: "custom",
        path: ["unresolved"],
        message: "unresolved actionIds must be strictly ascending and unique",
      });
    }
    const committedSet = new Set(committedIds);
    if (unresolvedIds.some((id) => committedSet.has(id))) {
      ctx.addIssue({
        code: "custom",
        path: ["unresolved"],
        message: "committed and unresolved actionIds must be disjoint",
      });
    }
  });

export type CommerceBudgetExposureInput = z.infer<
  typeof CommerceBudgetExposureInputSchema
>;

/**
 * Exact nanosecond epoch conversion of an accepted ISO UTC timestamp. Whole
 * seconds come from a calendar conversion; the fractional digits are carried
 * as integer nanoseconds. Returns null for any value whose calendar form is
 * impossible or whose seconds are not finite, so callers can reject with the
 * fixed non-echoing error instead of throwing raw parser output.
 */
function isoToEpochNanoseconds(iso: string): bigint | null {
  const match =
    /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z$/u.exec(iso);
  if (!match) return null;
  const wholeSecond = match[1]!;
  const secondsMs = Date.parse(`${wholeSecond}Z`);
  if (!Number.isFinite(secondsMs) || secondsMs % 1000 !== 0) return null;
  // Reject calendar roll-over (for example 2025-02-30) rather than silently
  // accepting the normalized instant.
  const normalized = new Date(secondsMs).toISOString();
  if (normalized.slice(0, 19) !== wholeSecond) return null;
  const fraction = (match[2] ?? "").padEnd(9, "0");
  const fractionNs = BigInt(fraction);
  return BigInt(secondsMs / 1000) * 1000000000n + fractionNs;
}

function isStrictlyAscending(values: readonly string[]): boolean {
  for (let index = 1; index < values.length; index += 1) {
    if (!(values[index - 1]! < values[index]!)) return false;
  }
  return true;
}

function invalidInput(): never {
  throw new Error(COMMERCE_BUDGET_INPUT_INVALID);
}

export interface CommerceBudgetExposure {
  readonly exposureKey: CommerceExposureKey;
  readonly asOf: string;
  readonly windowSeconds: string;
  readonly committedInWindowAtomic: string;
  readonly unresolvedAtomic: string;
  readonly totalExposureAtomic: string;
}

/**
 * Calculate the exact complete caller-loaded exposure for one exposure key.
 *
 * `committedInWindowAtomic` sums the committed records whose `committedAt` falls
 * inside the true rolling interval `(now - windowSeconds, now]` with exact
 * fractional-second (nanosecond) comparison: the cutoff is excluded and `now`
 * is included. `unresolvedAtomic` includes ALL unresolved reservations
 * regardless of age or status; unknown/claimed is never treated as expired or
 * released and no status label authorizes exclusion. The caller must supply the
 * complete DB-loaded records: `complete: true` is a declaration, not proof, and
 * this function is never an HTTP authority.
 */
export function calculateCommerceBudgetExposure(
  input: unknown,
): CommerceBudgetExposure {
  const parsed = CommerceBudgetExposureInputSchema.safeParse(input);
  if (!parsed.success) invalidInput();
  const value = parsed.data;

  const nowNs = isoToEpochNanoseconds(value.now);
  if (nowNs === null) invalidInput();
  const cutoffNs = nowNs - BigInt(value.windowSeconds) * 1000000000n;

  let committedInWindow = 0n;
  for (const record of value.committed) {
    const committedNs = isoToEpochNanoseconds(record.committedAt);
    if (committedNs === null) invalidInput();
    if (committedNs > nowNs) invalidInput();
    if (committedNs > cutoffNs) {
      committedInWindow += BigInt(record.amountAtomic);
    }
  }

  let unresolved = 0n;
  for (const record of value.unresolved) {
    const createdNs = isoToEpochNanoseconds(record.createdAt);
    if (createdNs === null) invalidInput();
    if (createdNs > nowNs) invalidInput();
    unresolved += BigInt(record.amountAtomic);
  }

  return Object.freeze({
    exposureKey: Object.freeze({ ...value.exposureKey }),
    asOf: value.now,
    windowSeconds: value.windowSeconds,
    committedInWindowAtomic: committedInWindow.toString(),
    unresolvedAtomic: unresolved.toString(),
    totalExposureAtomic: (committedInWindow + unresolved).toString(),
  });
}

function policyMonetaryLeavesAreCanonical(
  policy: CommercePolicyContent,
): boolean {
  const nullable: readonly (string | null)[] = [
    policy.perActionLimit,
    policy.rollingLimit,
    policy.approval.threshold,
  ];
  for (const leaf of nullable) {
    if (leaf !== null && !isCanonicalUint256(leaf)) return false;
  }
  return isCanonicalUint256(policy.feeLimit);
}

function sameExposureKey(
  policy: CommercePolicyContent,
  key: CommerceExposureKey,
): boolean {
  return (
    policy.organizationId === key.organizationId &&
    policy.subjectAgentId === key.subjectAgentId &&
    policy.networkId === key.networkId &&
    policy.asset === key.asset &&
    policy.representation === key.representation &&
    policy.decimals === key.decimals
  );
}

const CommerceBudgetAssessmentInputSchema = z.strictObject({
  policy: CommercePolicyContentSchema,
  exposureKey: CommerceExposureKeySchema,
  committedExposureAtomic: CommerceExposureTotalSchema,
  unresolvedExposureAtomic: CommerceExposureTotalSchema,
  candidate: z.strictObject({
    amountAtomic: PositiveUint256DecimalSchema,
    feeAtomic: Uint256DecimalAbsoluteSchema,
  }),
});

export type CommerceBudgetAssessmentInput = z.infer<
  typeof CommerceBudgetAssessmentInputSchema
>;

export type CommerceBudgetAssessment =
  | "within_limits"
  | "needs_approval"
  | "denied";

export type CommerceBudgetAssessmentReason =
  | "fee_limit_exceeded"
  | "per_action_limit_exceeded"
  | "existing_exposure_deficit"
  | "rolling_limit_exceeded"
  | "approval_required"
  | "limits_satisfied";

export interface CommerceBudgetAssessmentResult {
  readonly assessment: CommerceBudgetAssessment;
  readonly reason: CommerceBudgetAssessmentReason;
  readonly debitAtomic: string;
  readonly totalExposureAtomic: string;
  readonly projectedExposureAtomic: string;
  readonly availableAtomic: string | null;
  readonly deficitAtomic: string;
}

/**
 * Assess advisory NUMERICAL limits for one candidate action. This is not a
 * reservation, approval or grant: it never verifies provider/listing scope,
 * allowlist/expiry/session/listing status, separate approver or any verified
 * requirement. Those remain mandatory future DB checks and are not silently
 * guaranteed by `within_limits`.
 *
 * `debit = candidate.amountAtomic + candidate.feeAtomic` and applies to BOTH
 * `perActionLimit` and `rollingLimit`. A zero cap denies a positive debit. A
 * null cap is uncapped only for that cap; when the rolling cap is null there is
 * no rolling enforcement, and the supplied committed total is still returned
 * exactly without inventing a lifetime cap. `availableAtomic` is null without a
 * rolling cap; `deficitAtomic` never hides an existing over-limit exposure.
 */
export function assessCommerceBudgetLimits(
  input: unknown,
): CommerceBudgetAssessmentResult {
  const parsed = CommerceBudgetAssessmentInputSchema.safeParse(input);
  if (!parsed.success) invalidInput();
  const value = parsed.data;

  if (!policyMonetaryLeavesAreCanonical(value.policy)) invalidInput();
  if (!sameExposureKey(value.policy, value.exposureKey)) invalidInput();

  const debit = BigInt(value.candidate.amountAtomic) + BigInt(value.candidate.feeAtomic);
  const existingExposure =
    BigInt(value.committedExposureAtomic) + BigInt(value.unresolvedExposureAtomic);
  // Computed aggregates are bounded to the exported 128-digit total contract;
  // a sum above that bound fails instead of clamping/wrapping the exact BigInt.
  if (!isWithinExposureTotalDigits(existingExposure)) invalidInput();
  const projectedExposure = existingExposure + debit;
  if (!isWithinExposureTotalDigits(projectedExposure)) invalidInput();

  const feeLimit = BigInt(value.policy.feeLimit);
  const perActionLimit =
    value.policy.perActionLimit === null ? null : BigInt(value.policy.perActionLimit);
  const rollingLimit =
    value.policy.rollingLimit === null ? null : BigInt(value.policy.rollingLimit);

  const available =
    rollingLimit === null
      ? null
      : rollingLimit > existingExposure
        ? rollingLimit - existingExposure
        : 0n;
  const deficit =
    rollingLimit === null
      ? 0n
      : existingExposure > rollingLimit
        ? existingExposure - rollingLimit
        : 0n;

  const resultBase = {
    debitAtomic: debit.toString(),
    totalExposureAtomic: existingExposure.toString(),
    projectedExposureAtomic: projectedExposure.toString(),
    availableAtomic: available === null ? null : available.toString(),
    deficitAtomic: deficit.toString(),
  } as const;

  if (BigInt(value.candidate.feeAtomic) > feeLimit) {
    return Object.freeze({
      ...resultBase,
      assessment: "denied",
      reason: "fee_limit_exceeded",
    });
  }
  if (perActionLimit !== null && debit > perActionLimit) {
    return Object.freeze({
      ...resultBase,
      assessment: "denied",
      reason: "per_action_limit_exceeded",
    });
  }
  if (deficit > 0n) {
    return Object.freeze({
      ...resultBase,
      assessment: "denied",
      reason: "existing_exposure_deficit",
    });
  }
  if (rollingLimit !== null && projectedExposure > rollingLimit) {
    return Object.freeze({
      ...resultBase,
      assessment: "denied",
      reason: "rolling_limit_exceeded",
    });
  }

  const approval = value.policy.approval;
  const approvalRequired =
    approval.mode === "always" ||
    (approval.mode === "above" &&
      approval.threshold !== null &&
      debit > BigInt(approval.threshold));
  if (approvalRequired) {
    return Object.freeze({
      ...resultBase,
      assessment: "needs_approval",
      reason: "approval_required",
    });
  }
  return Object.freeze({
    ...resultBase,
    assessment: "within_limits",
    reason: "limits_satisfied",
  });
}
