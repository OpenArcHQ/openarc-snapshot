import { z } from "zod";

import {
  IsoTimestampSchema,
  Sha256DigestSchema,
  Uint256DecimalSchema,
  compareIsoTimestamps,
} from "../primitives.js";
import {
  CommerceAgentIdSchema,
  CommerceOrganizationIdSchema,
  CommerceProviderIdSchema,
} from "./identity.js";
import { CommerceListingIdSchema } from "./listing.js";

/**
 * Pure strict policy contract DTOs (schema shape only).
 *
 * There is no SQL, transport, server clock, hashing, approval decision,
 * reservation or spend authority here. Parsing one of these records never
 * proves a digest was verified, that a caller is a principal, or that a spend
 * is permitted. `digest` is a DECLARED leaf, not a cryptographic check.
 * Economic/count quantities are canonical decimal strings, never JS numbers.
 */

export const COMMERCE_POLICY_SCHEMA_VERSION =
  "openarc.control.policy.v1" as const;
export const COMMERCE_POLICY_ROOT_SCHEMA_VERSION =
  "openarc.control.policy-root.v1" as const;

const UUID_PATTERN =
  "[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";

// (?![\s\S]) pins the absolute end of input so a trailing newline cannot
// satisfy `$`; the UUID is canonical lower-case with version 1-8 and variant
// 8/9/a/b, matching the accepted identity leaf grammar.
export const CommercePolicyIdSchema = z.string().regex(
  new RegExp(`^openarc:policy:${UUID_PATTERN}(?![\\s\\S])`),
  { message: "Expected a canonical lower-case openarc:policy: UUID" },
);

export type CommercePolicyId = z.infer<typeof CommercePolicyIdSchema>;

const positiveCanonicalIntegerPattern = /^[1-9][0-9]{0,8}(?![\s\S])/u;

function canonicalBoundedIntegerSchema(max: bigint, message: string) {
  return z
    .string()
    .regex(positiveCanonicalIntegerPattern, { message })
    .refine(
      (value) =>
        positiveCanonicalIntegerPattern.test(value) && BigInt(value) <= max,
      { message },
    );
}

export const CommercePolicyRevisionNumberSchema =
  canonicalBoundedIntegerSchema(
    999999999n,
    "Expected a canonical revision 1..999999999",
  );

export type CommercePolicyRevisionNumber = z.infer<
  typeof CommercePolicyRevisionNumberSchema
>;

// window is null iff rollingLimit is null; otherwise canonical decimal seconds
// from 1 through the frozen 30-day bound (2592000).
const CommercePolicyRollingWindowSecondsSchema = canonicalBoundedIntegerSchema(
  2592000n,
  "Expected canonical seconds 1..2592000",
);

const POLICY_NETWORK_ID = "eip155:5042002" as const;
const POLICY_ASSET = "USDC" as const;
const POLICY_REPRESENTATION = "erc20" as const;
const POLICY_DECIMALS = 6 as const;

export const CommercePolicyApprovalSchema = z
  .strictObject({
    mode: z.enum(["none", "always", "above"]),
    threshold: Uint256DecimalSchema.nullable(),
    separateApprover: z.boolean(),
  })
  .superRefine((value, ctx) => {
    if (value.mode === "above") {
      // Zod runs downstream refinements even when the nested uint256 leaf
      // already failed, so the raw string here may not be a canonical
      // integer ("1e2", "1.5", ...). Guard the BigInt conversion with the
      // accepted integer validator to keep safeParse total on untrusted data.
      const thresholdIsUint256 =
        value.threshold !== null &&
        Uint256DecimalSchema.safeParse(value.threshold).success;
      if (!thresholdIsUint256 || BigInt(value.threshold!) <= 0n) {
        ctx.addIssue({
          code: "custom",
          path: ["threshold"],
          message: "above approval requires a positive threshold",
        });
      }
    } else if (value.threshold !== null) {
      ctx.addIssue({
        code: "custom",
        path: ["threshold"],
        message: "non-above approval requires a null threshold",
      });
    }
    if (value.mode === "none" && value.separateApprover !== false) {
      ctx.addIssue({
        code: "custom",
        path: ["separateApprover"],
        message: "none approval requires separateApprover false",
      });
    }
  });

export type CommercePolicyApproval = z.infer<
  typeof CommercePolicyApprovalSchema
>;

function isStrictlySortedUnique(values: readonly string[]): boolean {
  for (let index = 1; index < values.length; index += 1) {
    if (!(values[index - 1]! < values[index]!)) return false;
  }
  return true;
}

const CommercePolicyProviderIdListSchema = z
  .array(CommerceProviderIdSchema)
  .max(64)
  .refine(isStrictlySortedUnique, {
    message: "allowedProviderIds must be ascending, unique and at most 64",
  });

const CommercePolicyListingIdListSchema = z
  .array(CommerceListingIdSchema)
  .max(128)
  .refine(isStrictlySortedUnique, {
    message: "allowedListingIds must be ascending, unique and at most 128",
  });

const commercePolicyContentShape = {
  organizationId: CommerceOrganizationIdSchema,
  subjectAgentId: CommerceAgentIdSchema,
  networkId: z.literal(POLICY_NETWORK_ID),
  asset: z.literal(POLICY_ASSET),
  representation: z.literal(POLICY_REPRESENTATION),
  decimals: z.literal(POLICY_DECIMALS),
  perActionLimit: Uint256DecimalSchema.nullable(),
  rollingLimit: Uint256DecimalSchema.nullable(),
  rollingWindowSeconds: CommercePolicyRollingWindowSecondsSchema.nullable(),
  feeLimit: Uint256DecimalSchema,
  allowedProviderIds: CommercePolicyProviderIdListSchema,
  allowedListingIds: CommercePolicyListingIdListSchema,
  approval: CommercePolicyApprovalSchema,
  expiresAt: IsoTimestampSchema.nullable(),
} as const;

interface PolicyCapFields {
  readonly perActionLimit: string | null;
  readonly rollingLimit: string | null;
  readonly rollingWindowSeconds: string | null;
}

interface PolicyContentIssue {
  path: (string | number)[];
  readonly message: string;
}

function policyCapIssues(value: PolicyCapFields): readonly PolicyContentIssue[] {
  const issues: PolicyContentIssue[] = [];
  if (value.perActionLimit === null && value.rollingLimit === null) {
    issues.push({
      path: ["perActionLimit"],
      message: "at least one cap must be non-null",
    });
  }
  if ((value.rollingWindowSeconds === null) !== (value.rollingLimit === null)) {
    issues.push({
      path: ["rollingWindowSeconds"],
      message: "rollingWindowSeconds must be null iff rollingLimit is null",
    });
  }
  return issues;
}

export const CommercePolicyContentSchema = z
  .strictObject(commercePolicyContentShape)
  .superRefine((value, ctx) => {
    for (const issue of policyCapIssues(value)) {
      ctx.addIssue({ code: "custom", ...issue });
    }
  });

export type CommercePolicyContent = z.infer<typeof CommercePolicyContentSchema>;

function expiryFollowsCreatedAt(value: {
  createdAt: string;
  expiresAt: string | null;
}): boolean {
  if (value.expiresAt === null) return true;
  if (!IsoTimestampSchema.safeParse(value.createdAt).success) return true;
  if (!IsoTimestampSchema.safeParse(value.expiresAt).success) return true;
  return compareIsoTimestamps(value.expiresAt, value.createdAt) > 0;
}

export const CommercePolicyRevisionSchema = z
  .strictObject({
    schemaVersion: z.literal(COMMERCE_POLICY_SCHEMA_VERSION),
    policyId: CommercePolicyIdSchema,
    revision: CommercePolicyRevisionNumberSchema,
    ...commercePolicyContentShape,
    createdAt: IsoTimestampSchema,
    digest: Sha256DigestSchema,
  })
  .superRefine((value, ctx) => {
    for (const issue of policyCapIssues(value)) {
      ctx.addIssue({ code: "custom", ...issue });
    }
    if (!expiryFollowsCreatedAt(value)) {
      ctx.addIssue({
        code: "custom",
        path: ["expiresAt"],
        message: "expiresAt must strictly follow createdAt",
      });
    }
  });

export type CommercePolicyRevision = z.infer<
  typeof CommercePolicyRevisionSchema
>;

function hasNonDecreasingTimestamps(value: {
  createdAt: string;
  updatedAt: string;
}): boolean {
  if (!IsoTimestampSchema.safeParse(value.createdAt).success) return true;
  if (!IsoTimestampSchema.safeParse(value.updatedAt).success) return true;
  return compareIsoTimestamps(value.updatedAt, value.createdAt) >= 0;
}

export const CommercePolicyRootSchema = z
  .strictObject({
    schemaVersion: z.literal(COMMERCE_POLICY_ROOT_SCHEMA_VERSION),
    policyId: CommercePolicyIdSchema,
    organizationId: CommerceOrganizationIdSchema,
    subjectAgentId: CommerceAgentIdSchema,
    currentRevision: CommercePolicyRevisionNumberSchema,
    status: z.enum(["active", "paused", "revoked"]),
    createdAt: IsoTimestampSchema,
    updatedAt: IsoTimestampSchema,
  })
  .refine(hasNonDecreasingTimestamps, {
    message: "updatedAt must not precede createdAt",
  });

export type CommercePolicyRoot = z.infer<typeof CommercePolicyRootSchema>;
