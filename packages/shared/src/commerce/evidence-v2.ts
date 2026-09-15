import { z } from "zod";

import { Bytes32Schema, EvidenceIdSchema } from "../evidence.js";
import { ARC_TESTNET } from "../network.js";
import {
  IsoTimestampSchema,
  Sha256DigestSchema,
  Uint256DecimalSchema,
  Uint64DecimalSchema,
  compareIsoTimestamps,
} from "../primitives.js";
import { CanonicalTransferIdSchema } from "../x402-evidence.js";
import { CommerceReservationIdSchema } from "./control-action.js";
import { CommerceActionIdSchema } from "./control-budget.js";
import { CommerceGrantIdSchema } from "./control-grant.js";
import type { Erc8183JobStatusFact, Erc8183RefundFact } from "./erc8183-job-mirror.js";
import { ERC8183_DEPLOYED_STATUSES, ERC8183_TERMINAL_STATUSES } from "./erc8183-manifest.js";
import {
  CommerceAccountIdSchema,
  CommerceAgentIdSchema,
  CommerceOrganizationIdSchema,
  CommerceProviderIdSchema,
} from "./identity.js";
import { CommerceEvidenceClassSchema, type CommerceEvidenceClass } from "./states.js";

/**
 * P05-01a — `openarc.evidence.v2` shared contracts.
 *
 * Pure contracts only: no clock, no I/O, no persistence. Every schema is strict
 * (no passthrough, no stripping, no defaults). Nothing here can carry a
 * signature, authorization payload, nonce signature, key, token or session
 * hash: there is no slot for one, free text rejects secret-shaped runs, and a
 * compile-time proof fails the build if such a key is ever added.
 *
 * Payment certainty is deliberately narrow. There is no settled, paid,
 * refunded, failed or released payment state. Only a finalized Arc chain
 * observation that matches the Gateway batch transaction yields
 * `onchain_confirmed`.
 */

export const EVIDENCE_V2_SCHEMA_VERSION = "openarc.evidence.v2" as const;
/**
 * v2: agreeing facts from different sources are `corroborated`, not a
 * `multiple_sources` conflict. v1 reported agreement as uncertainty.
 */
export const EVIDENCE_V2_CONFLICT_RULE_VERSION = "openarc.evidence.v2.conflict.v2" as const;
export const EVIDENCE_V2_PAYMENT_CERTAINTY_RULE_VERSION = "openarc.evidence.v2.payment-certainty.v1" as const;

// ───────────────────────── source classes (decision 1) ─────────────────────────

/** Exactly the nine evidence classes of the engineering source of truth §5.3 / §9. */
export const EvidenceV2SourceClassSchema = CommerceEvidenceClassSchema;
export type EvidenceV2SourceClass = CommerceEvidenceClass;
export const EVIDENCE_V2_SOURCE_CLASSES = CommerceEvidenceClassSchema.options;

/** Human-readable names. `local` is an OpenArc control-plane record in the server v2 contract. */
export const EVIDENCE_V2_SOURCE_CLASS_LABELS: Readonly<Record<EvidenceV2SourceClass, string>> = Object.freeze({
  local: "OpenArc control-plane record",
  signed: "Signed statement",
  agent_reported: "Agent-reported claim",
  provider: "Provider attestation",
  facilitator: "Facilitator response",
  gateway: "Gateway response",
  onchain: "Arc chain observation",
  evaluator: "Evaluator result",
  openarc_derived: "OpenArc-derived rule output",
});

// ───────────────────────── primitives ─────────────────────────

const END = "(?![\\s\\S])";
const UUID_ANY = "[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";

/** Printable ASCII with no secret-shaped run (long hex, base64/JWT-like tokens). */
const SECRET_SHAPED = [/[0-9a-fA-F]{40,}/u, /[A-Za-z0-9+/_-]{40,}/u, /eyJ[A-Za-z0-9_-]{8,}/u] as const;
const safeText = (maximum: number) =>
  z
    .string()
    .min(1)
    .max(maximum)
    .regex(/^[\x20-\x7e]+$/u, "Expected printable ASCII")
    .refine((value) => value.trim() === value, "Expected trimmed text")
    .refine((value) => SECRET_SHAPED.every((pattern) => !pattern.test(value)), "Text looks like secret material");

const lowercaseAddress = z.string().regex(new RegExp(`^0x[0-9a-f]{40}${END}`, "u"), "Expected a lowercase address");

export const EvidenceV2SourceIdSchema = z.string().regex(new RegExp(`^[a-z][a-z0-9._-]{1,63}${END}`, "u"));
export const EvidenceV2OriginSchema = z
  .string()
  .max(120)
  .regex(
    new RegExp(
      `^(?:https://[a-z0-9](?:[a-z0-9.-]{0,98}[a-z0-9])?(?::[1-9][0-9]{0,4})?|openarc:(?:control-plane|worker|reconciler|observer))${END}`,
      "u",
    ),
    "Expected an https origin without path or an openarc: component origin",
  );
/** Adapter or rule version, e.g. `openarc.gateway-transfer.m07.v1`. */
export const EvidenceV2AdapterVersionSchema = z
  .string()
  .regex(new RegExp(`^openarc\\.[a-z0-9][a-z0-9.-]{0,78}\\.v[1-9][0-9]{0,3}${END}`, "u"));

export const EvidenceV2FinalitySchema = z.enum(["finalized", "unfinalized"]);
export type EvidenceV2Finality = z.infer<typeof EvidenceV2FinalitySchema>;

export const EvidenceV2ChainAnchorSchema = z.strictObject({
  network: z.literal(ARC_TESTNET.caip2),
  blockNumber: Uint64DecimalSchema,
  blockHash: Bytes32Schema,
  finality: EvidenceV2FinalitySchema,
});
export type EvidenceV2ChainAnchor = z.infer<typeof EvidenceV2ChainAnchorSchema>;

export const EvidenceV2DataClassSchema = z.enum(["public", "organization_protected"]);

const sourceFor = <const C extends readonly [EvidenceV2SourceClass, ...EvidenceV2SourceClass[]]>(classes: C) =>
  z.strictObject({
    class: z.enum(classes),
    sourceId: EvidenceV2SourceIdSchema,
    origin: EvidenceV2OriginSchema,
    adapterVersion: EvidenceV2AdapterVersionSchema,
  });

export const EvidenceV2SourceSchema = z.strictObject({
  class: EvidenceV2SourceClassSchema,
  sourceId: EvidenceV2SourceIdSchema,
  origin: EvidenceV2OriginSchema,
  adapterVersion: EvidenceV2AdapterVersionSchema,
});
export type EvidenceV2Source = z.infer<typeof EvidenceV2SourceSchema>;

// ───────────────────────── actors (decision 2) ─────────────────────────

/** Server-side identifiers only. There is no token, session or credential hash slot. */
export const EvidenceV2ActorSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("human_account"), accountId: CommerceAccountIdSchema }),
  z.strictObject({ kind: z.literal("agent"), agentId: CommerceAgentIdSchema }),
  z.strictObject({ kind: z.literal("provider"), providerId: CommerceProviderIdSchema }),
  z.strictObject({ kind: z.literal("system"), component: z.enum(["api", "worker", "reconciler", "observer"]) }),
  z.strictObject({
    kind: z.literal("external_party"),
    role: z.enum(["facilitator", "gateway", "arc_chain", "erc8183_client", "erc8183_provider", "erc8183_evaluator"]),
    address: lowercaseAddress.nullable(),
  }),
]);
export type EvidenceV2Actor = z.infer<typeof EvidenceV2ActorSchema>;
export const EVIDENCE_V2_ACTOR_KINDS = ["human_account", "agent", "provider", "system", "external_party"] as const;

// ───────────────────────── subjects ─────────────────────────

const actionSubject = z.strictObject({ kind: z.literal("action"), canonicalId: CommerceActionIdSchema });
const grantSubject = z.strictObject({ kind: z.literal("authorization_grant"), canonicalId: CommerceGrantIdSchema });
const reservationSubject = z.strictObject({ kind: z.literal("budget_reservation"), canonicalId: CommerceReservationIdSchema });
const listingSubject = z.strictObject({
  kind: z.literal("listing"),
  canonicalId: z.string().regex(new RegExp(`^openarc:listing:${UUID_ANY}:[1-9][0-9]{0,8}${END}`, "u")),
});
const arcTransactionSubject = z.strictObject({
  kind: z.literal("arc_transaction"),
  canonicalId: z.string().regex(new RegExp(`^eip155:5042002:tx:0x[0-9a-f]{64}${END}`, "u")),
});
const jobSubject = z.strictObject({
  kind: z.literal("erc8183_job"),
  canonicalId: z.string().regex(new RegExp(`^eip155:5042002:erc8183:0x[0-9a-f]{40}:[1-9][0-9]{0,77}${END}`, "u")),
});

export const EvidenceV2SubjectSchema = z.discriminatedUnion("kind", [
  actionSubject, grantSubject, reservationSubject, listingSubject, arcTransactionSubject, jobSubject,
]);
export type EvidenceV2Subject = z.infer<typeof EvidenceV2SubjectSchema>;

export const EvidenceV2ScopeSchema = z.strictObject({
  organizationId: CommerceOrganizationIdSchema,
  providerId: CommerceProviderIdSchema.nullable(),
  actionId: CommerceActionIdSchema.nullable(),
});

// ───────────────────────── payment certainty (decision 5) ─────────────────────────

export const EVIDENCE_V2_PAYMENT_CERTAINTIES = ["unknown", "pending", "submitted_pending_chain", "onchain_confirmed"] as const;
export const EvidenceV2PaymentCertaintySchema = z.enum(EVIDENCE_V2_PAYMENT_CERTAINTIES);
export type EvidenceV2PaymentCertainty = z.infer<typeof EvidenceV2PaymentCertaintySchema>;

/** Payment states that must never be representable in v2 evidence. */
export type EvidenceV2ForbiddenPaymentState =
  | "settled"
  | "paid"
  | "refunded"
  | "failed"
  | "released"
  | "released_unsent"
  | "rejected"
  | "cancelled"
  | "not_paid"
  | "nonpayment";

/** Mirrors `LaneUnknownReason` in packages/x402 (shared cannot depend on x402). */
export const EVIDENCE_V2_LANE_UNKNOWN_REASONS = [
  "timeout",
  "transport_error",
  "http_error",
  "malformed_response",
  "not_found",
  "not_found_after_expiry",
  "nonce_already_used",
  "gateway_failed_not_terminal",
  "ambiguous_records",
  "record_mismatch",
  "completed_without_batch_hash",
  "unrecognized_status",
] as const;
export type EvidenceV2LaneUnknownReason = (typeof EVIDENCE_V2_LANE_UNKNOWN_REASONS)[number];

export const EVIDENCE_V2_UNKNOWN_PAYMENT_LIMITATION =
  "Payment outcome is unknown; the exposure may be spent and remains held." as const;
export const EVIDENCE_V2_GATEWAY_COMMITTED_LIMITATION =
  "Gateway reports completed; the batch transaction is not verified onchain." as const;

/** Structurally identical to `LaneExposure` from packages/x402, so a lane result passes directly. */
export const EvidenceV2LaneExposureSchema = z.discriminatedUnion("state", [
  z.strictObject({
    state: z.literal("unknown"),
    disposition: z.literal("held"),
    reason: z.enum(EVIDENCE_V2_LANE_UNKNOWN_REASONS),
  }),
  z.strictObject({
    state: z.literal("pending"),
    disposition: z.literal("held"),
    transferId: z.string().min(1).max(128),
    gatewayStatus: z.enum(["received", "batched", "confirmed"]),
    batchTxHash: Bytes32Schema.nullable(),
  }),
  z.strictObject({
    state: z.literal("committed"),
    disposition: z.literal("committed"),
    transferId: z.string().min(1).max(128),
    gatewayStatus: z.literal("completed"),
    batchTxHash: Bytes32Schema,
    onchainReceiptVerified: z.literal(false),
  }),
]);
export type EvidenceV2LaneExposure = z.infer<typeof EvidenceV2LaneExposureSchema>;
export type EvidenceV2LaneState = EvidenceV2LaneExposure["state"];

export const EvidenceV2ChainObservationSchema = z.strictObject({
  network: z.string().min(1).max(64),
  transactionHash: Bytes32Schema,
  blockNumber: Uint64DecimalSchema,
  blockHash: Bytes32Schema,
  finality: EvidenceV2FinalitySchema,
  receiptStatus: z.enum(["success", "reverted"]),
});
export type EvidenceV2ChainObservation = z.infer<typeof EvidenceV2ChainObservationSchema>;

export type EvidenceV2ChainCheck =
  | "not_applicable_lane_not_committed"
  | "not_observed"
  | "network_mismatch"
  | "transaction_mismatch"
  | "unfinalized"
  | "reverted_contradicts_gateway"
  | "matched_finalized";

export type EvidenceV2PaymentCertaintyResult =
  | { readonly ruleVersion: typeof EVIDENCE_V2_PAYMENT_CERTAINTY_RULE_VERSION; readonly certainty: "unknown"; readonly exposure: "held"; readonly chainCheck: "not_applicable_lane_not_committed" | "reverted_contradicts_gateway" }
  | { readonly ruleVersion: typeof EVIDENCE_V2_PAYMENT_CERTAINTY_RULE_VERSION; readonly certainty: "pending"; readonly exposure: "held"; readonly chainCheck: "not_applicable_lane_not_committed" }
  | { readonly ruleVersion: typeof EVIDENCE_V2_PAYMENT_CERTAINTY_RULE_VERSION; readonly certainty: "submitted_pending_chain"; readonly exposure: "committed"; readonly chainCheck: "not_observed" | "network_mismatch" | "transaction_mismatch" | "unfinalized" }
  | { readonly ruleVersion: typeof EVIDENCE_V2_PAYMENT_CERTAINTY_RULE_VERSION; readonly certainty: "onchain_confirmed"; readonly exposure: "committed"; readonly chainCheck: "matched_finalized" };

type IsNever<T> = [T] extends [never] ? true : false;

/** Resolves to `true` only while no forbidden payment state is representable. */
export type EvidenceV2PaymentAdmitsNoSettlement = IsNever<
  Extract<
    | EvidenceV2PaymentCertainty
    | EvidenceV2PaymentCertaintyResult["certainty"]
    | EvidenceV2PaymentCertaintyResult["exposure"]
    | EvidenceV2LaneState,
    EvidenceV2ForbiddenPaymentState
  >
>;
export const EVIDENCE_V2_PAYMENT_ADMITS_NO_SETTLEMENT: EvidenceV2PaymentAdmitsNoSettlement = true;

/** The certainty a lane state alone supports: never `onchain_confirmed`. */
export function evidenceV2CertaintyForLaneState(
  state: EvidenceV2LaneState,
): Exclude<EvidenceV2PaymentCertainty, "onchain_confirmed"> {
  switch (state) {
    case "unknown":
      return "unknown";
    case "pending":
      return "pending";
    case "committed":
      return "submitted_pending_chain";
  }
}

/**
 * Pure payment certainty rule. Lane `unknown` stays unknown and held; `pending`
 * stays pending; `committed` is Gateway-asserted only. A chain observation can
 * promote `committed` to `onchain_confirmed` only when it is on Arc Testnet,
 * names the batch transaction, is finalized and succeeded. A finalized
 * reverted receipt contradicts Gateway and is held as unknown. Malformed input
 * throws.
 */
export function derivePaymentCertainty(
  laneState: EvidenceV2LaneExposure,
  chainObservation?: EvidenceV2ChainObservation,
): EvidenceV2PaymentCertaintyResult {
  const lane = EvidenceV2LaneExposureSchema.parse(laneState);
  const chain = chainObservation === undefined ? undefined : EvidenceV2ChainObservationSchema.parse(chainObservation);
  const ruleVersion = EVIDENCE_V2_PAYMENT_CERTAINTY_RULE_VERSION;
  if (lane.state === "unknown") {
    return Object.freeze({ ruleVersion, certainty: "unknown", exposure: "held", chainCheck: "not_applicable_lane_not_committed" });
  }
  if (lane.state === "pending") {
    return Object.freeze({ ruleVersion, certainty: "pending", exposure: "held", chainCheck: "not_applicable_lane_not_committed" });
  }
  const submitted = (chainCheck: "not_observed" | "network_mismatch" | "transaction_mismatch" | "unfinalized") =>
    Object.freeze({ ruleVersion, certainty: "submitted_pending_chain", exposure: "committed", chainCheck } as const);
  if (chain === undefined) return submitted("not_observed");
  if (chain.network !== ARC_TESTNET.caip2) return submitted("network_mismatch");
  if (chain.transactionHash !== lane.batchTxHash) return submitted("transaction_mismatch");
  if (chain.finality !== "finalized") return submitted("unfinalized");
  if (chain.receiptStatus !== "success") {
    return Object.freeze({ ruleVersion, certainty: "unknown", exposure: "held", chainCheck: "reverted_contradicts_gateway" });
  }
  return Object.freeze({ ruleVersion, certainty: "onchain_confirmed", exposure: "committed", chainCheck: "matched_finalized" });
}

// ───────────────────────── exposure (decision 6) ─────────────────────────

/**
 * Four separate buckets as exact uint256 strings. There is intentionally no
 * merged "reserved, not resolved" total: `unknown` can never be folded in.
 */
export const EvidenceV2ExposureSummarySchema = z.strictObject({
  held: Uint256DecimalSchema,
  claimed: Uint256DecimalSchema,
  unknown: Uint256DecimalSchema,
  committed: Uint256DecimalSchema,
});
export type EvidenceV2ExposureSummary = z.infer<typeof EvidenceV2ExposureSummarySchema>;
export type EvidenceV2ExposureBucket = keyof EvidenceV2ExposureSummary;
export const EVIDENCE_V2_EXPOSURE_BUCKETS = ["held", "claimed", "unknown", "committed"] as const;

const MAX_UINT256 = (1n << 256n) - 1n;

export function summarizeEvidenceV2Exposure(
  entries: readonly { readonly bucket: EvidenceV2ExposureBucket; readonly amountAtomic: string }[],
): EvidenceV2ExposureSummary {
  const totals: Record<EvidenceV2ExposureBucket, bigint> = { held: 0n, claimed: 0n, unknown: 0n, committed: 0n };
  for (const entry of entries) {
    const bucket = z.enum(EVIDENCE_V2_EXPOSURE_BUCKETS).parse(entry.bucket);
    const amount = BigInt(Uint256DecimalSchema.parse(entry.amountAtomic));
    const next = totals[bucket] + amount;
    if (next > MAX_UINT256) throw new RangeError(`Exposure bucket ${bucket} exceeds uint256`);
    totals[bucket] = next;
  }
  return Object.freeze({
    held: totals.held.toString(),
    claimed: totals.claimed.toString(),
    unknown: totals.unknown.toString(),
    committed: totals.committed.toString(),
  });
}

// ───────────────────────── facts ─────────────────────────

const limitationsSchema = z
  .array(safeText(240))
  .min(1)
  .max(8)
  .refine((items) => new Set(items).size === items.length, "Expected unique limitations");

const base = {
  schemaVersion: z.literal(EVIDENCE_V2_SCHEMA_VERSION),
  evidenceId: EvidenceIdSchema,
  scope: EvidenceV2ScopeSchema,
  actor: EvidenceV2ActorSchema,
  occurredAt: IsoTimestampSchema.nullable(),
  observedAt: IsoTimestampSchema,
  digest: Sha256DigestSchema.nullable(),
  dataClass: EvidenceV2DataClassSchema,
  limitations: limitationsSchema,
};

const paymentObservationNormalized = z.discriminatedUnion("laneState", [
  z.strictObject({
    laneState: z.literal("unknown"),
    certainty: z.literal("unknown"),
    unknownReason: z.enum(EVIDENCE_V2_LANE_UNKNOWN_REASONS),
  }),
  z.strictObject({
    laneState: z.literal("pending"),
    certainty: z.literal("pending"),
    gatewayStatus: z.enum(["received", "batched", "confirmed"]),
    transferId: CanonicalTransferIdSchema,
    batchTransactionHash: Bytes32Schema.nullable(),
    amountAtomic: Uint256DecimalSchema,
    payer: lowercaseAddress,
    payTo: lowercaseAddress,
  }),
  z.strictObject({
    laneState: z.literal("committed"),
    certainty: z.literal("submitted_pending_chain"),
    gatewayStatus: z.literal("completed"),
    transferId: CanonicalTransferIdSchema,
    batchTransactionHash: Bytes32Schema,
    amountAtomic: Uint256DecimalSchema,
    payer: lowercaseAddress,
    payTo: lowercaseAddress,
  }),
]);

const jobStateNormalized = z.discriminatedUnion("knowledge", [
  z.strictObject({ knowledge: z.literal("known"), status: z.enum(ERC8183_DEPLOYED_STATUSES), terminal: z.boolean() }),
  z.strictObject({
    knowledge: z.literal("unknown"),
    reason: z.enum(["created_before_mirror_start", "event_conflict", "refund_unpaired"]),
    lastKnown: z.enum(ERC8183_DEPLOYED_STATUSES).nullable(),
  }),
]);

const variants = <const E extends z.ZodRawShape>(extra: E) =>
  [
    z.strictObject({
      ...base, ...extra,
      kind: z.literal("authorization_decision"),
      source: sourceFor(["local", "openarc_derived"]),
      subject: actionSubject,
      chain: z.null(),
      normalized: z.strictObject({
        decision: z.enum(["approval_requested", "approved", "rejected", "authorized", "denied", "expired", "cancelled"]),
      }),
    }),
    z.strictObject({
      ...base, ...extra,
      kind: z.literal("grant_state"),
      source: sourceFor(["local", "openarc_derived"]),
      subject: grantSubject,
      chain: z.null(),
      normalized: z.strictObject({ status: z.enum(["issued", "replaced", "claimed", "revoked", "expired"]) }),
    }),
    z.strictObject({
      ...base, ...extra,
      kind: z.literal("listing_state"),
      source: sourceFor(["local", "provider"]),
      subject: listingSubject,
      chain: z.null(),
      normalized: z.strictObject({ status: z.enum(["draft", "active", "paused", "retired"]) }),
    }),
    z.strictObject({
      ...base, ...extra,
      kind: z.literal("budget_exposure"),
      source: sourceFor(["local"]),
      subject: z.discriminatedUnion("kind", [actionSubject, reservationSubject]),
      chain: z.null(),
      normalized: z.strictObject({ exposure: EvidenceV2ExposureSummarySchema }),
    }),
    z.strictObject({
      ...base, ...extra,
      kind: z.literal("payment_observation"),
      source: sourceFor(["facilitator", "gateway"]),
      subject: actionSubject,
      chain: z.null(),
      normalized: paymentObservationNormalized,
    }),
    z.strictObject({
      ...base, ...extra,
      kind: z.literal("arc_transaction"),
      source: sourceFor(["onchain"]),
      subject: arcTransactionSubject,
      chain: EvidenceV2ChainAnchorSchema,
      normalized: z.strictObject({ transactionHash: Bytes32Schema, receiptStatus: z.enum(["success", "reverted"]) }),
    }),
    z.strictObject({
      ...base, ...extra,
      kind: z.literal("job_state"),
      source: sourceFor(["onchain"]),
      subject: jobSubject,
      chain: EvidenceV2ChainAnchorSchema,
      normalized: jobStateNormalized,
    }),
    z.strictObject({
      ...base, ...extra,
      kind: z.literal("job_refund"),
      source: sourceFor(["onchain"]),
      subject: jobSubject,
      chain: EvidenceV2ChainAnchorSchema,
      normalized: z.strictObject({
        cause: z.enum(["rejected", "expired"]),
        amountAtomic: Uint256DecimalSchema,
        transactionHash: Bytes32Schema,
      }),
    }),
    z.strictObject({
      ...base, ...extra,
      kind: z.literal("provider_delivery"),
      source: sourceFor(["provider"]),
      subject: actionSubject,
      chain: z.null(),
      normalized: z.strictObject({ reported: z.enum(["delivered", "not_delivered"]), responseDigest: Sha256DigestSchema.nullable() }),
    }),
    z.strictObject({
      ...base, ...extra,
      kind: z.literal("evaluator_result"),
      source: sourceFor(["evaluator"]),
      subject: z.discriminatedUnion("kind", [actionSubject, jobSubject]),
      chain: z.null(),
      normalized: z.strictObject({ result: z.enum(["accepted", "rejected"]) }),
    }),
  ] as const;

export const EVIDENCE_V2_FACT_KINDS = [
  "authorization_decision",
  "grant_state",
  "listing_state",
  "budget_exposure",
  "payment_observation",
  "arc_transaction",
  "job_state",
  "job_refund",
  "provider_delivery",
  "evaluator_result",
] as const;
export type EvidenceV2FactKind = (typeof EVIDENCE_V2_FACT_KINDS)[number];

/** Authority matrix: the only source classes each fact kind admits. */
export const EVIDENCE_V2_KIND_SOURCE_CLASSES: Readonly<Record<EvidenceV2FactKind, readonly EvidenceV2SourceClass[]>> = Object.freeze({
  authorization_decision: ["local", "openarc_derived"],
  grant_state: ["local", "openarc_derived"],
  listing_state: ["local", "provider"],
  budget_exposure: ["local"],
  payment_observation: ["facilitator", "gateway"],
  arc_transaction: ["onchain"],
  job_state: ["onchain"],
  job_refund: ["onchain"],
  provider_delivery: ["provider"],
  evaluator_result: ["evaluator"],
});

/** Kinds that may be marked `public` and therefore have a public view. */
export const EVIDENCE_V2_PUBLIC_KINDS = ["listing_state", "job_state", "job_refund"] as const;
/** Kinds a provider may see, and only for its own provider scope. */
export const EVIDENCE_V2_PROVIDER_KINDS = ["listing_state", "grant_state"] as const;
const PROVIDER_SCOPED_KINDS = new Set<EvidenceV2FactKind>(["grant_state", "listing_state", "provider_delivery"]);

type FactShape = z.infer<ReturnType<typeof variants<Record<never, never>>>[number]>;

function checkFact(fact: FactShape, context: z.RefinementCtx): void {
  const fail = (message: string, path: (string | number)[]) => context.addIssue({ code: "custom", message, path });
  if (fact.occurredAt !== null && compareIsoTimestamps(fact.occurredAt, fact.observedAt) > 0) {
    fail("Evidence cannot occur after it was observed", ["occurredAt"]);
  }
  if (fact.dataClass === "public" && !(EVIDENCE_V2_PUBLIC_KINDS as readonly string[]).includes(fact.kind)) {
    fail(`${fact.kind} evidence cannot be public`, ["dataClass"]);
  }
  if (fact.kind === "listing_state" && fact.dataClass === "public" && fact.normalized.status === "draft") {
    fail("A draft listing cannot be public", ["dataClass"]);
  }
  if (PROVIDER_SCOPED_KINDS.has(fact.kind) && fact.scope.providerId === null) {
    fail(`${fact.kind} evidence requires a provider scope`, ["scope", "providerId"]);
  }
  if (fact.actor.kind === "provider" && fact.actor.providerId !== fact.scope.providerId) {
    fail("A provider actor must match the provider scope", ["actor", "providerId"]);
  }
  if (fact.source.class === "provider" && fact.actor.kind !== "provider") {
    fail("Provider attestations must be attributed to the provider", ["actor"]);
  }
  if (fact.subject.kind === "action" && fact.scope.actionId !== fact.subject.canonicalId) {
    fail("Action subject must match the action scope", ["scope", "actionId"]);
  }
  if (fact.kind === "grant_state" && fact.source.class === "openarc_derived" && fact.normalized.status !== "expired") {
    fail("An OpenArc-derived grant fact can only be a derived expiry", ["source", "class"]);
  }
  if (fact.kind === "arc_transaction" && fact.subject.canonicalId !== `${ARC_TESTNET.caip2}:tx:${fact.normalized.transactionHash}`) {
    fail("Transaction subject must name the observed transaction", ["subject", "canonicalId"]);
  }
  if (fact.kind === "job_refund" && fact.chain.finality !== "finalized") {
    fail("A job refund exists only as a finalized mirror fact", ["chain", "finality"]);
  }
  if (fact.kind === "job_state" && fact.normalized.knowledge === "known" &&
    fact.normalized.terminal !== (ERC8183_TERMINAL_STATUSES as readonly string[]).includes(fact.normalized.status)) {
    fail("Job terminal flag disagrees with status", ["normalized", "terminal"]);
  }
  if (fact.kind === "payment_observation") {
    const required = fact.normalized.laneState === "unknown" ? EVIDENCE_V2_UNKNOWN_PAYMENT_LIMITATION
      : fact.normalized.laneState === "committed" ? EVIDENCE_V2_GATEWAY_COMMITTED_LIMITATION : null;
    if (required !== null && !fact.limitations.includes(required)) {
      fail(`${fact.normalized.laneState} payment evidence must state its limitation`, ["limitations"]);
    }
  }
}

export const EvidenceV2FactSchema = z.discriminatedUnion("kind", variants({})).superRefine(checkFact);
export type EvidenceV2Fact = z.infer<typeof EvidenceV2FactSchema>;
export type EvidenceV2FactOf<K extends EvidenceV2FactKind> = Extract<EvidenceV2Fact, { kind: K }>;

// ───────────────────────── no secrets (decision 4) ─────────────────────────

type DeepKeys<T> = T extends readonly (infer U)[]
  ? DeepKeys<U>
  : T extends object
    ? { [K in keyof T & string]: K | DeepKeys<T[K]> }[keyof T & string]
    : never;

type SecretKeyFragment =
  | "signature" | "Signature" | "token" | "Token" | "secret" | "Secret" | "password" | "Password"
  | "privateKey" | "PrivateKey" | "apiKey" | "ApiKey" | "session" | "Session" | "authorization"
  | "Authorization" | "nonce" | "Nonce" | "credential" | "Credential" | "mnemonic" | "Mnemonic"
  | "seed" | "Seed" | "payload" | "Payload" | "cookie" | "Cookie";
export type EvidenceV2ForbiddenKey = `${string}${SecretKeyFragment}${string}`;

// ───────────────────────── views (decision 3) ─────────────────────────

const PUBLIC_STATUSES = [
  "active", "paused", "retired", ...ERC8183_DEPLOYED_STATUSES, "job_status_unknown", "job_refund_paired",
] as const;

/**
 * Public view. No amount, address, actor, organization, evidence ID, digest or
 * block reference. Listing and ERC-8183 job canonical IDs are shown because the
 * frontend architecture routes them publicly (`/market/:listingId`, `/jobs/:jobId`
 * "public job facts only when marked public").
 */
export const EvidenceV2PublicViewSchema = z.strictObject({
  view: z.literal("public"),
  schemaVersion: z.literal(EVIDENCE_V2_SCHEMA_VERSION),
  kind: z.enum(EVIDENCE_V2_PUBLIC_KINDS),
  sourceClass: EvidenceV2SourceClassSchema,
  adapterVersion: EvidenceV2AdapterVersionSchema,
  subject: z.discriminatedUnion("kind", [listingSubject, jobSubject]),
  status: z.enum(PUBLIC_STATUSES),
  finality: EvidenceV2FinalitySchema.nullable(),
  occurredAt: IsoTimestampSchema.nullable(),
  observedAt: IsoTimestampSchema,
  limitations: limitationsSchema,
});
export type EvidenceV2PublicView = z.infer<typeof EvidenceV2PublicViewSchema>;

/** Provider view: only the provider's own listing and grant facts; no organization, actor ID or digest. */
export const EvidenceV2ProviderViewSchema = z.strictObject({
  view: z.literal("provider"),
  schemaVersion: z.literal(EVIDENCE_V2_SCHEMA_VERSION),
  evidenceId: EvidenceIdSchema,
  kind: z.enum(EVIDENCE_V2_PROVIDER_KINDS),
  sourceClass: EvidenceV2SourceClassSchema,
  subject: z.discriminatedUnion("kind", [listingSubject, grantSubject]),
  status: z.enum(["draft", "active", "paused", "retired", "issued", "replaced", "claimed", "revoked", "expired"]),
  actorKind: z.enum(EVIDENCE_V2_ACTOR_KINDS),
  occurredAt: IsoTimestampSchema.nullable(),
  observedAt: IsoTimestampSchema,
  limitations: limitationsSchema,
});
export type EvidenceV2ProviderView = z.infer<typeof EvidenceV2ProviderViewSchema>;

/** Operator view: the complete validated fact, tagged. Still strict and secret-free by construction. */
export const EvidenceV2OperatorViewSchema = z
  .discriminatedUnion("kind", variants({ view: z.literal("operator") }))
  .superRefine(checkFact);
export type EvidenceV2OperatorView = z.infer<typeof EvidenceV2OperatorViewSchema>;

/** Compile-time proof: no secret-named key exists on any fact or view. */
export type EvidenceV2AdmitsNoSecretKeys = IsNever<
  Extract<
    DeepKeys<EvidenceV2Fact | EvidenceV2PublicView | EvidenceV2ProviderView | EvidenceV2OperatorView>,
    EvidenceV2ForbiddenKey
  >
>;
export const EVIDENCE_V2_ADMITS_NO_SECRET_KEYS: EvidenceV2AdmitsNoSecretKeys = true;

/** The single comparable status of a fact, used by views and conflict resolution. */
export function evidenceV2FactStatus(fact: EvidenceV2Fact): string {
  switch (fact.kind) {
    case "authorization_decision":
      return fact.normalized.decision;
    case "grant_state":
    case "listing_state":
      return fact.normalized.status;
    case "budget_exposure":
      return "exposure_summary";
    case "payment_observation":
      return fact.normalized.laneState;
    case "arc_transaction":
      return fact.normalized.receiptStatus;
    case "job_state":
      return fact.normalized.knowledge === "known" ? fact.normalized.status : "job_status_unknown";
    case "job_refund":
      return "job_refund_paired";
    case "provider_delivery":
      return fact.normalized.reported;
    case "evaluator_result":
      return fact.normalized.result;
  }
}

/** Returns the public view, or null when the fact is not public. Throws on an invalid fact. */
export function projectEvidenceV2PublicView(input: EvidenceV2Fact): EvidenceV2PublicView | null {
  const fact = EvidenceV2FactSchema.parse(input);
  if (fact.dataClass !== "public") return null;
  if (fact.kind !== "listing_state" && fact.kind !== "job_state" && fact.kind !== "job_refund") return null;
  return Object.freeze(EvidenceV2PublicViewSchema.parse({
    view: "public",
    schemaVersion: fact.schemaVersion,
    kind: fact.kind,
    sourceClass: fact.source.class,
    adapterVersion: fact.source.adapterVersion,
    subject: { kind: fact.subject.kind, canonicalId: fact.subject.canonicalId },
    status: evidenceV2FactStatus(fact),
    finality: fact.chain === null ? null : fact.chain.finality,
    occurredAt: fact.occurredAt,
    observedAt: fact.observedAt,
    limitations: [...fact.limitations],
  }));
}

/** Returns the provider view only for that provider's own listing or grant fact; otherwise null. */
export function projectEvidenceV2ProviderView(input: EvidenceV2Fact, viewerProviderId: string): EvidenceV2ProviderView | null {
  const fact = EvidenceV2FactSchema.parse(input);
  const viewer = CommerceProviderIdSchema.parse(viewerProviderId);
  if (fact.kind !== "listing_state" && fact.kind !== "grant_state") return null;
  if (fact.scope.providerId !== viewer) return null;
  return Object.freeze(EvidenceV2ProviderViewSchema.parse({
    view: "provider",
    schemaVersion: fact.schemaVersion,
    evidenceId: fact.evidenceId,
    kind: fact.kind,
    sourceClass: fact.source.class,
    subject: { kind: fact.subject.kind, canonicalId: fact.subject.canonicalId },
    status: fact.normalized.status,
    actorKind: fact.actor.kind,
    occurredAt: fact.occurredAt,
    observedAt: fact.observedAt,
    limitations: [...fact.limitations],
  }));
}

/** Operator view of any valid fact. Re-validates, so a smuggled key throws instead of passing through. */
export function projectEvidenceV2OperatorView(input: EvidenceV2Fact): EvidenceV2OperatorView {
  const fact = EvidenceV2FactSchema.parse(input);
  return Object.freeze(EvidenceV2OperatorViewSchema.parse({ view: "operator", ...structuredCloneJson(fact) }));
}

function structuredCloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

// ───────────────────────── ERC-8183 mirror mapping ─────────────────────────

/** A job refund fact exists only when the mirror reports a paired refund (`Refunded` with `JobRejected`/`JobExpired`). */
export function evidenceV2JobRefundFromMirror(
  refund: Erc8183RefundFact,
): EvidenceV2FactOf<"job_refund">["normalized"] | null {
  if (refund.state !== "refunded") return null;
  return Object.freeze({ cause: refund.cause, amountAtomic: refund.amount, transactionHash: refund.transactionHash });
}

export function evidenceV2JobStateFromMirror(status: Erc8183JobStatusFact): EvidenceV2FactOf<"job_state">["normalized"] {
  return status.kind === "known"
    ? Object.freeze({ knowledge: "known", status: status.status, terminal: status.terminal })
    : Object.freeze({ knowledge: "unknown", reason: status.reason, lastKnown: status.lastKnown });
}

// ───────────────────────── conflicts (decision 7) ─────────────────────────

/**
 * `multiple_sources` stays in the vocabulary for compatibility, but rule v2
 * never emits it: sources that agree are `corroborated`, and sources that
 * disagree are reported by the specific mismatch reasons.
 */
export const EVIDENCE_V2_CONFLICT_REASONS = [
  "chain_anchor_mismatch",
  "evidence_id_reused",
  "multiple_sources",
  "normalized_mismatch",
  "status_mismatch",
] as const;
export type EvidenceV2ConflictReason = (typeof EVIDENCE_V2_CONFLICT_REASONS)[number];

export interface EvidenceV2ResolvedSource {
  readonly class: EvidenceV2SourceClass;
  readonly sourceId: string;
  readonly origin: string;
}

export type EvidenceV2ConflictResolution =
  | {
      readonly outcome: "resolved";
      readonly ruleVersion: typeof EVIDENCE_V2_CONFLICT_RULE_VERSION;
      readonly kind: EvidenceV2FactKind;
      readonly subject: EvidenceV2Subject;
      readonly source: EvidenceV2ResolvedSource;
      readonly status: string;
      readonly finality: EvidenceV2Finality | null;
      readonly evidenceIds: readonly string[];
      readonly firstObservedAt: string;
      readonly lastObservedAt: string;
    }
  | {
      /** Two or more distinct sources report the same status, normalized fields and chain anchor. */
      readonly outcome: "corroborated";
      readonly ruleVersion: typeof EVIDENCE_V2_CONFLICT_RULE_VERSION;
      readonly kind: EvidenceV2FactKind;
      readonly subject: EvidenceV2Subject;
      /** Every distinct source, sorted, at least two. */
      readonly sources: readonly EvidenceV2ResolvedSource[];
      readonly status: string;
      readonly finality: EvidenceV2Finality | null;
      readonly evidenceIds: readonly string[];
      readonly firstObservedAt: string;
      readonly lastObservedAt: string;
    }
  | {
      readonly outcome: "conflict";
      readonly ruleVersion: typeof EVIDENCE_V2_CONFLICT_RULE_VERSION;
      readonly kind: EvidenceV2FactKind;
      readonly subject: EvidenceV2Subject;
      readonly reasons: readonly EvidenceV2ConflictReason[];
      readonly evidenceIds: readonly string[];
      readonly facts: readonly EvidenceV2Fact[];
    };

export class EvidenceV2ConflictInputError extends Error {
  constructor(readonly detail: "empty" | "mixed_subject" | "mixed_kind") {
    super(`Evidence v2 conflict input invalid: ${detail}`);
    this.name = "EvidenceV2ConflictInputError";
  }
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function compareFacts(left: EvidenceV2Fact, right: EvidenceV2Fact): number {
  const time = compareIsoTimestamps(left.observedAt, right.observedAt);
  if (time !== 0) return time;
  if (left.evidenceId !== right.evidenceId) return left.evidenceId < right.evidenceId ? -1 : 1;
  const leftJson = canonicalJson(left);
  const rightJson = canonicalJson(right);
  return leftJson === rightJson ? 0 : leftJson < rightJson ? -1 : 1;
}

/**
 * Deterministic resolution for facts of one kind about one subject. Never
 * last-write-wins: different statuses, normalized fields or chain anchors, or
 * a reused evidence ID with different content, is an explicit `conflict`
 * listing every fact. Facts that agree resolve: from one source they are
 * `resolved`, from several distinct sources they are `corroborated` and list
 * every source. The result depends only on the set of facts, never on input
 * order, and finality never regresses from `finalized` when an unfinalized
 * observation arrives later.
 */
export function resolveEvidenceConflict(input: readonly EvidenceV2Fact[]): EvidenceV2ConflictResolution {
  if (input.length === 0) throw new EvidenceV2ConflictInputError("empty");
  const parsed = input.map((fact) => EvidenceV2FactSchema.parse(fact));
  const first = parsed[0] as EvidenceV2Fact;
  const subjectKey = canonicalJson(first.subject);
  for (const fact of parsed) {
    if (fact.kind !== first.kind) throw new EvidenceV2ConflictInputError("mixed_kind");
    if (canonicalJson(fact.subject) !== subjectKey) throw new EvidenceV2ConflictInputError("mixed_subject");
  }

  const byJson = new Map<string, EvidenceV2Fact>();
  for (const fact of parsed) byJson.set(canonicalJson(fact), fact);
  const facts = [...byJson.values()].sort(compareFacts);

  const reasons = new Set<EvidenceV2ConflictReason>();
  const idContent = new Map<string, string>();
  for (const [json, fact] of byJson) {
    const prior = idContent.get(fact.evidenceId);
    if (prior !== undefined && prior !== json) reasons.add("evidence_id_reused");
    idContent.set(fact.evidenceId, json);
  }
  if (new Set(facts.map(evidenceV2FactStatus)).size > 1) reasons.add("status_mismatch");
  if (new Set(facts.map((fact) => canonicalJson([fact.normalized, fact.occurredAt]))).size > 1) reasons.add("normalized_mismatch");
  const anchorKey = (fact: EvidenceV2Fact) =>
    fact.chain === null ? "null" : canonicalJson([fact.chain.network, fact.chain.blockNumber, fact.chain.blockHash]);
  if (new Set(facts.map(anchorKey)).size > 1) reasons.add("chain_anchor_mismatch");

  const evidenceIds = Object.freeze([...new Set(facts.map((fact) => fact.evidenceId))].sort());
  if (reasons.size > 0) {
    return Object.freeze({
      outcome: "conflict",
      ruleVersion: EVIDENCE_V2_CONFLICT_RULE_VERSION,
      kind: first.kind,
      subject: first.subject,
      reasons: Object.freeze([...reasons].sort()),
      evidenceIds,
      facts: Object.freeze(facts),
    });
  }

  const earliest = facts[0] as EvidenceV2Fact;
  const latest = facts[facts.length - 1] as EvidenceV2Fact;
  const finality: EvidenceV2Finality | null = earliest.chain === null ? null
    : facts.some((fact) => fact.chain?.finality === "finalized") ? "finalized" : "unfinalized";
  const sourcesByKey = new Map<string, EvidenceV2ResolvedSource>();
  for (const fact of facts) {
    const source = { class: fact.source.class, sourceId: fact.source.sourceId, origin: fact.source.origin };
    sourcesByKey.set(canonicalJson([source.class, source.sourceId, source.origin]), source);
  }
  const sources = [...sourcesByKey.entries()]
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .map(([, source]) => Object.freeze(source));
  if (sources.length > 1) {
    return Object.freeze({
      outcome: "corroborated",
      ruleVersion: EVIDENCE_V2_CONFLICT_RULE_VERSION,
      kind: earliest.kind,
      subject: earliest.subject,
      sources: Object.freeze(sources),
      status: evidenceV2FactStatus(earliest),
      finality,
      evidenceIds,
      firstObservedAt: earliest.observedAt,
      lastObservedAt: latest.observedAt,
    });
  }
  return Object.freeze({
    outcome: "resolved",
    ruleVersion: EVIDENCE_V2_CONFLICT_RULE_VERSION,
    kind: earliest.kind,
    subject: earliest.subject,
    source: sources[0] as EvidenceV2ResolvedSource,
    status: evidenceV2FactStatus(earliest),
    finality,
    evidenceIds,
    firstObservedAt: earliest.observedAt,
    lastObservedAt: latest.observedAt,
  });
}
