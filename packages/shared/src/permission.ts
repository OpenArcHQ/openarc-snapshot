import { z } from "zod";

import { ApiErrorCodeSchema, CAPABILITIES_PATH, WorkspaceOriginSchema } from "./api.js";
import { ARC_ACCOUNT_SNAPSHOT_PATH, ARC_TRANSACTION_EVIDENCE_PATH } from "./arc-observation.js";
import { AGENT_REGISTRY_EVIDENCE_PATH, AgentRegistryEvidenceRequestSchema } from "./agent-registry-evidence.js";
import { JOB_EVIDENCE_PATH, JobEvidenceRequestSchema } from "./job-evidence.js";
import { GATEWAY_TRANSFER_PATH, GatewayTransferRequestSchema } from "./x402-evidence.js";
// P04-06b: identifier grammars for the purchase-decision receipt. These modules
// import only ./primitives.js and each other, so nothing here can cycle back
// through vault.js or permission.js.
import { CommerceApprovalIdSchema } from "./commerce/control-action.js";
import { CommerceActionIdSchema } from "./commerce/control-budget.js";
import { CommercePolicyIdSchema } from "./commerce/control-policy.js";
import { CommerceOrganizationIdSchema, CommerceProviderIdSchema } from "./commerce/identity.js";
import { CommerceListingIdSchema } from "./commerce/listing.js";
import { CommerceTenantMutationIdSchema } from "./commerce/tenant-writes.js";
import { ARC_TESTNET } from "./network.js";
import { EvmAddressSchema, IsoTimestampSchema, TransactionHashSchema, compareIsoTimestamps } from "./primitives.js";
import { VaultRevisionSchema, WorkspaceRecordIdSchema } from "./workspace-primitives.js";

export const CAPABILITY_DISCLOSURE = Object.freeze({
  connectorId: "openarc_capabilities",
  purpose: "Inspect enabled OpenArc connections and limits.",
  credentials: "omit",
  openArcRetention: "No private workspace fields or response bodies are retained by the OpenArc API.",
  providerRetention: "No upstream provider is contacted by this check.",
  hostingMetadata: "OpenArc and its hosting provider receive ordinary network metadata, including IP and user-agent.",
} as const);

export const PermissionFailureCodeSchema = z.union([
  ApiErrorCodeSchema,
  z.enum(["REQUEST_UNAVAILABLE", "INVALID_RESPONSE", "RESPONSE_TOO_LARGE"]),
]);

export const CapabilityPermissionReceiptRecordSchema = z.strictObject({
  recordSchema: z.literal("openarc.permission-receipt.v1"),
  kind: z.literal("permission_receipt"),
  recordId: WorkspaceRecordIdSchema,
  recordRevision: VaultRevisionSchema,
  createdAt: IsoTimestampSchema,
  updatedAt: IsoTimestampSchema,
  connectorId: z.literal(CAPABILITY_DISCLOSURE.connectorId),
  destination: z.strictObject({
    origin: WorkspaceOriginSchema,
    path: z.literal(CAPABILITIES_PATH),
    method: z.literal("GET"),
    upstreams: z.tuple([]),
  }),
  releasedFields: z.tuple([]),
  purpose: z.literal(CAPABILITY_DISCLOSURE.purpose),
  credentials: z.literal(CAPABILITY_DISCLOSURE.credentials),
  openArcRetention: z.literal(CAPABILITY_DISCLOSURE.openArcRetention),
  providerRetention: z.literal(CAPABILITY_DISCLOSURE.providerRetention),
  hostingMetadata: z.literal(CAPABILITY_DISCLOSURE.hostingMetadata),
  approvedAt: IsoTimestampSchema,
  outcome: z.enum(["approved", "completed", "failed"]),
  resolvedAt: IsoTimestampSchema.nullable(),
  failureCode: PermissionFailureCodeSchema.nullable(),
}).superRefine((receipt, context) => {
  if (![receipt.createdAt, receipt.updatedAt, receipt.approvedAt, receipt.resolvedAt]
    .every((value) => value === null || IsoTimestampSchema.safeParse(value).success)) return;
  const fail = (message: string) => context.addIssue({ code: "custom", message });
  if (receipt.createdAt !== receipt.approvedAt) fail("Receipt creation must equal approval");
  if (receipt.updatedAt !== (receipt.resolvedAt ?? receipt.approvedAt)) {
    fail("Receipt update must match its last outcome time");
  }
  if (receipt.outcome === "approved") {
    if (receipt.resolvedAt !== null || receipt.failureCode !== null) fail("Approval is unresolved");
  } else {
    if (receipt.resolvedAt === null || compareIsoTimestamps(receipt.resolvedAt, receipt.approvedAt) < 0) {
      fail("Resolved receipt cannot predate approval");
    }
    if ((receipt.outcome === "failed") !== (receipt.failureCode !== null)) {
      fail("Only a failed receipt has a failure code");
    }
  }
});

export const ARC_OBSERVATION_DISCLOSURE = Object.freeze({
  credentials: "omit",
  openArcRetention: "No request or response body is retained by the OpenArc API. The approved result is stored only in the encrypted local workspace.",
  providerRetention: "Arc's public RPC receives the released public identifier under Arc's current terms and privacy policy.",
  hostingMetadata: "OpenArc, its hosting provider, and the Arc RPC receive ordinary network metadata, including IP and user-agent where applicable.",
} as const);

export const AGENT_REGISTRY_DISCLOSURE = Object.freeze({
  credentials: "omit",
  openArcRetention: "No request or response body is retained by the OpenArc API. The approved result is stored only in the encrypted local workspace.",
  providerRetention: "Arc's public RPC receives the released public registry identifiers under Arc's current terms and privacy policy.",
  hostingMetadata: "OpenArc, its hosting provider, and the Arc RPC receive ordinary network metadata, including IP and user-agent where applicable.",
} as const);

export const JOB_DISCLOSURE = Object.freeze({
  ...ARC_OBSERVATION_DISCLOSURE,
  providerRetention: "Arc's public RPC receives the job ID and optional submission transaction hash under Arc's current terms and privacy policy.",
} as const);

const observationBase = {
  recordSchema: z.literal("openarc.permission-receipt.v2"),
  kind: z.literal("permission_receipt"),
  recordId: WorkspaceRecordIdSchema,
  recordRevision: VaultRevisionSchema,
  createdAt: IsoTimestampSchema,
  updatedAt: IsoTimestampSchema,
  credentials: z.literal(ARC_OBSERVATION_DISCLOSURE.credentials),
  openArcRetention: z.literal(ARC_OBSERVATION_DISCLOSURE.openArcRetention),
  providerRetention: z.literal(ARC_OBSERVATION_DISCLOSURE.providerRetention),
  hostingMetadata: z.literal(ARC_OBSERVATION_DISCLOSURE.hostingMetadata),
  approvedAt: IsoTimestampSchema,
  outcome: z.enum(["approved", "completed", "failed"]),
  resolvedAt: IsoTimestampSchema.nullable(),
  failureCode: PermissionFailureCodeSchema.nullable(),
};

export const ArcObservationPermissionReceiptRecordSchema = z.discriminatedUnion("connectorId", [
  z.strictObject({
    ...observationBase,
    connectorId: z.literal("arc_account_snapshot"),
    destination: z.strictObject({ origin: WorkspaceOriginSchema,
      path: z.literal(ARC_ACCOUNT_SNAPSHOT_PATH), method: z.literal("POST"),
      upstreams: z.tuple([z.literal(ARC_TESTNET.rpcHttp)]) }),
    releasedFields: z.tuple([z.literal("network"), z.literal("address")]),
    released: z.strictObject({ network: z.literal(ARC_TESTNET.caip2), address: EvmAddressSchema }),
    purpose: z.literal("Observe one public Arc Testnet address at one exact final block."),
  }),
  z.strictObject({
    ...observationBase,
    connectorId: z.literal("arc_transaction_evidence"),
    destination: z.strictObject({ origin: WorkspaceOriginSchema,
      path: z.literal(ARC_TRANSACTION_EVIDENCE_PATH), method: z.literal("POST"),
      upstreams: z.tuple([z.literal(ARC_TESTNET.rpcHttp)]) }),
    releasedFields: z.tuple([z.literal("network"), z.literal("transactionHash")]),
    released: z.strictObject({ network: z.literal(ARC_TESTNET.caip2), transactionHash: TransactionHashSchema }),
    purpose: z.literal("Observe one public Arc Testnet transaction, receipt, anchor, fee, and USDC movement set."),
  }),
]).superRefine((receipt, context) => {
  if (![receipt.createdAt, receipt.updatedAt, receipt.approvedAt, receipt.resolvedAt]
    .every((value) => value === null || IsoTimestampSchema.safeParse(value).success)) return;
  const fail = (message: string) => context.addIssue({ code: "custom", message });
  if (receipt.createdAt !== receipt.approvedAt) fail("Receipt creation must equal approval");
  if (receipt.updatedAt !== (receipt.resolvedAt ?? receipt.approvedAt)) fail("Receipt update must match its last outcome time");
  if (receipt.outcome === "approved") {
    if (receipt.resolvedAt !== null || receipt.failureCode !== null) fail("Approval is unresolved");
  } else {
    if (receipt.resolvedAt === null || compareIsoTimestamps(receipt.resolvedAt, receipt.approvedAt) < 0) {
      fail("Resolved receipt cannot predate approval");
    }
    if ((receipt.outcome === "failed") !== (receipt.failureCode !== null)) fail("Only a failed receipt has a failure code");
  }
});

export const AgentRegistryPermissionReceiptRecordSchema = z.strictObject({
  recordSchema: z.literal("openarc.permission-receipt.v3"),
  kind: z.literal("permission_receipt"),
  recordId: WorkspaceRecordIdSchema,
  recordRevision: VaultRevisionSchema,
  createdAt: IsoTimestampSchema,
  updatedAt: IsoTimestampSchema,
  connectorId: z.literal("arc_agent_registry_evidence"),
  destination: z.strictObject({ origin: WorkspaceOriginSchema,
    path: z.literal(AGENT_REGISTRY_EVIDENCE_PATH), method: z.literal("POST"),
    upstreams: z.tuple([z.literal(ARC_TESTNET.rpcHttp)]) }),
  releasedFields: z.array(z.enum([
    "network", "agentId", "feedbackQuery.clientAddress", "feedbackQuery.feedbackIndex",
    "validationRequestHash",
  ])).min(2).max(5),
  released: AgentRegistryEvidenceRequestSchema,
  purpose: z.literal("Observe one ERC-8004 agent identity and optional exact observer or validator claims at one final Arc Testnet block."),
  credentials: z.literal(AGENT_REGISTRY_DISCLOSURE.credentials),
  openArcRetention: z.literal(AGENT_REGISTRY_DISCLOSURE.openArcRetention),
  providerRetention: z.literal(AGENT_REGISTRY_DISCLOSURE.providerRetention),
  hostingMetadata: z.literal(AGENT_REGISTRY_DISCLOSURE.hostingMetadata),
  approvedAt: IsoTimestampSchema,
  outcome: z.enum(["approved", "completed", "failed"]),
  resolvedAt: IsoTimestampSchema.nullable(),
  failureCode: PermissionFailureCodeSchema.nullable(),
}).superRefine((receipt, context) => {
  const expected = ["network", "agentId"];
  if (receipt.released.feedbackQuery) expected.push("feedbackQuery.clientAddress", "feedbackQuery.feedbackIndex");
  if (receipt.released.validationRequestHash) expected.push("validationRequestHash");
  if (JSON.stringify(receipt.releasedFields) !== JSON.stringify(expected)) {
    context.addIssue({ code: "custom", message: "Released-field disclosure must exactly match the request" });
  }
  const fail = (message: string) => context.addIssue({ code: "custom", message });
  if (receipt.createdAt !== receipt.approvedAt) fail("Receipt creation must equal approval");
  if (receipt.updatedAt !== (receipt.resolvedAt ?? receipt.approvedAt)) fail("Receipt update must match its last outcome time");
  if (receipt.outcome === "approved") {
    if (receipt.resolvedAt !== null || receipt.failureCode !== null) fail("Approval is unresolved");
  } else {
    if (receipt.resolvedAt === null || compareIsoTimestamps(receipt.resolvedAt, receipt.approvedAt) < 0) {
      fail("Resolved receipt cannot predate approval");
    }
    if ((receipt.outcome === "failed") !== (receipt.failureCode !== null)) fail("Only a failed receipt has a failure code");
  }
});

export const JobPermissionReceiptRecordSchema = z.strictObject({
  recordSchema: z.literal("openarc.permission-receipt.v4"),
  kind: z.literal("permission_receipt"),
  recordId: WorkspaceRecordIdSchema,
  recordRevision: VaultRevisionSchema,
  createdAt: IsoTimestampSchema,
  updatedAt: IsoTimestampSchema,
  connectorId: z.literal("arc_job_evidence"),
  destination: z.strictObject({ origin: WorkspaceOriginSchema,
    path: z.literal(JOB_EVIDENCE_PATH), method: z.literal("POST"),
    upstreams: z.tuple([z.literal(ARC_TESTNET.rpcHttp)]) }),
  releasedFields: z.array(z.enum([
    "network", "jobId", "submissionTransactionHash",
  ])).min(2).max(3),
  released: JobEvidenceRequestSchema,
  purpose: z.literal("Observe one job on the reviewed Arc Testnet reference contract and an optional exact submission receipt."),
  credentials: z.literal(JOB_DISCLOSURE.credentials),
  openArcRetention: z.literal(JOB_DISCLOSURE.openArcRetention),
  providerRetention: z.literal(JOB_DISCLOSURE.providerRetention),
  hostingMetadata: z.literal(JOB_DISCLOSURE.hostingMetadata),
  approvedAt: IsoTimestampSchema,
  outcome: z.enum(["approved", "completed", "failed"]),
  resolvedAt: IsoTimestampSchema.nullable(),
  failureCode: PermissionFailureCodeSchema.nullable(),
}).superRefine((receipt, context) => {
  const expected = ["network", "jobId"];
  if (![receipt.createdAt, receipt.updatedAt, receipt.approvedAt, receipt.resolvedAt]
    .every((value) => value === null || IsoTimestampSchema.safeParse(value).success)) return;
  if (receipt.released.submissionTransactionHash) expected.push("submissionTransactionHash");
  if (JSON.stringify(receipt.releasedFields) !== JSON.stringify(expected)) {
    context.addIssue({ code: "custom", message: "Released-field disclosure must exactly match the request" });
  }
  const fail = (message: string) => context.addIssue({ code: "custom", message });
  if (receipt.createdAt !== receipt.approvedAt) fail("Receipt creation must equal approval");
  if (receipt.updatedAt !== (receipt.resolvedAt ?? receipt.approvedAt)) fail("Receipt update must match its last outcome time");
  if (receipt.outcome === "approved") {
    if (receipt.resolvedAt !== null || receipt.failureCode !== null) fail("Approval is unresolved");
  } else {
    if (receipt.resolvedAt === null || compareIsoTimestamps(receipt.resolvedAt, receipt.approvedAt) < 0) {
      fail("Resolved receipt cannot predate approval");
    }
    if ((receipt.outcome === "failed") !== (receipt.failureCode !== null)) fail("Only a failed receipt has a failure code");
  }
});

export const GATEWAY_DISCLOSURE = Object.freeze({
  credentials: "omit",
  openArcRetention: "No request or response body is retained by the OpenArc API. The approved result is stored only in the encrypted local workspace.",
  providerRetention: "Circle Gateway receives the exact transfer UUID under Circle's current terms and privacy policy. Provider retention is not controlled by OpenArc.",
  hostingMetadata: "OpenArc, its hosting provider, and Circle Gateway receive ordinary network metadata, including IP and user-agent where applicable.",
} as const);

export const GatewayPermissionReceiptRecordSchema = z.strictObject({
  ...observationBase,
  recordSchema: z.literal("openarc.permission-receipt.v5"),
  connectorId: z.literal("circle_gateway_transfer"),
  destination: z.strictObject({ origin: WorkspaceOriginSchema,
    path: z.literal(GATEWAY_TRANSFER_PATH), method: z.literal("POST"),
    upstreams: z.tuple([z.literal("https://gateway-api-testnet.circle.com")]) }),
  releasedFields: z.tuple([z.literal("network"), z.literal("transferId")]),
  released: GatewayTransferRequestSchema,
  purpose: z.literal("Read one exact Circle Gateway Arc Testnet transfer; this does not verify fulfillment."),
  providerRetention: z.literal(GATEWAY_DISCLOSURE.providerRetention),
  hostingMetadata: z.literal(GATEWAY_DISCLOSURE.hostingMetadata),
}).superRefine((receipt, context) => {
  if (![receipt.createdAt, receipt.updatedAt, receipt.approvedAt, receipt.resolvedAt]
    .every((value) => value === null || IsoTimestampSchema.safeParse(value).success)) return;
  const fail = (message: string) => context.addIssue({ code: "custom", message });
  if (receipt.createdAt !== receipt.approvedAt) fail("Receipt creation must equal approval");
  if (receipt.updatedAt !== (receipt.resolvedAt ?? receipt.approvedAt)) fail("Receipt update must match its last outcome time");
  if (receipt.outcome === "approved") {
    if (receipt.resolvedAt !== null || receipt.failureCode !== null) fail("Approval is unresolved");
  } else {
    if (receipt.resolvedAt === null || compareIsoTimestamps(receipt.resolvedAt, receipt.approvedAt) < 0) {
      fail("Resolved receipt cannot predate approval");
    }
    if ((receipt.outcome === "failed") !== (receipt.failureCode !== null)) fail("Only a failed receipt has a failure code");
  }
});

/**
 * P04-06b — the browser purchase-decision receipt.
 *
 * The five receipts above all describe an OBSERVATION: a read whose released
 * fields are public identifiers. A purchase decision is not that. It is a human
 * act, sent to this deployment's own control API, and the thing worth recording
 * is what the human was looking at when they acted. So v6 carries two separate
 * blocks and never conflates them:
 *
 *   `released`  exactly the values that leave this browser on the wire, and
 *               nothing else. Verified against apps/web/src/tenant/action-client.ts:
 *               the organization ID and purchase ID are path segments, the
 *               decision is which of the two routes is called, and the mutation
 *               ID is the whole JSON body. The CSRF token and idempotency key
 *               are HEADERS and are deliberately NOT representable here.
 *   `reviewed`  what the console showed the human at decision time. It never
 *               leaves the browser; it is the evidence of informed consent.
 *
 * Every figure stays an exact integer string with its asset and decimals. No
 * field on this record can hold a secret, token, session hash or signature:
 * every member is a strict object of pinned identifier, enum or canonical
 * integer grammars, so there is nowhere for an opaque credential to live.
 */

/** The two browser action-decision routes, byte-identical to their ACTION_ROUTES templates. */
export const PURCHASE_DECISION_APPROVE_PATH =
  "/v2/control/organizations/:organizationId/actions/:actionId/approve" as const;
export const PURCHASE_DECISION_REJECT_PATH =
  "/v2/control/organizations/:organizationId/actions/:actionId/reject" as const;

export const PURCHASE_DECISION_ROUTE_BY_DECISION = Object.freeze({
  approve: PURCHASE_DECISION_APPROVE_PATH,
  reject: PURCHASE_DECISION_REJECT_PATH,
} as const);

export const PURCHASE_DECISION_DISCLOSURE = Object.freeze({
  connectorId: "openarc_purchase_decision",
  purpose: "Send one human approve-or-reject decision on one pending purchase to the OpenArc control API. Only the organization ID, the purchase ID, the decision and one mutation ID leave this browser; this moves no money.",
  credentials: "same-origin",
  openArcRetention: "The OpenArc API keeps this decision as its own authoritative control record. No reviewed purchase detail and no private workspace field is sent, and the record of what you reviewed is stored only in the encrypted local workspace.",
  providerRetention: "No upstream provider, seller or payment network is contacted by this decision.",
  hostingMetadata: "OpenArc and its hosting provider receive ordinary network metadata, including IP and user-agent.",
} as const);

// Canonical integer grammars, pinned here so the receipt cannot widen if a wire
// schema is ever relaxed. `(?![\s\S])` pins the absolute end of input.
const purchaseVersion = z.string().regex(/^[1-9][0-9]{0,8}(?![\s\S])/u);
const purchasePositiveAtomic = z.string().regex(/^[1-9][0-9]{0,77}(?![\s\S])/u);
const purchaseNonNegativeAtomic = z.string().regex(/^(?:0|[1-9][0-9]{0,77})(?![\s\S])/u);

/** Exactly what the console showed the human. Strict: nothing else is representable. */
export const PurchaseDecisionReviewedSchema = z.strictObject({
  listingId: CommerceListingIdSchema,
  listingVersion: purchaseVersion,
  providerId: CommerceProviderIdSchema,
  amountAtomic: purchasePositiveAtomic,
  feeAtomic: purchaseNonNegativeAtomic,
  debitAtomic: purchasePositiveAtomic,
  asset: z.literal("USDC"),
  decimals: z.literal(6),
  networkId: z.literal("eip155:5042002"),
  policyId: CommercePolicyIdSchema,
  policyRevision: purchaseVersion,
  approvalId: CommerceApprovalIdSchema.nullable(),
  approvalExpiresAt: IsoTimestampSchema.nullable(),
}).superRefine((reviewed, context) => {
  if (![reviewed.amountAtomic, reviewed.feeAtomic, reviewed.debitAtomic]
    .every((value) => /^(?:0|[1-9][0-9]{0,77})$/u.test(value))) return;
  if (BigInt(reviewed.debitAtomic) !== BigInt(reviewed.amountAtomic) + BigInt(reviewed.feeAtomic)) {
    context.addIssue({ code: "custom", path: ["debitAtomic"], message: "Reviewed budget must equal amount plus fee" });
  }
  if ((reviewed.approvalId === null) !== (reviewed.approvalExpiresAt === null)) {
    context.addIssue({ code: "custom", message: "An approval expiry requires the approval it belongs to" });
  }
});

/** Exactly the values that leave the browser: two path segments, one route choice, one body field. */
export const PurchaseDecisionReleasedSchema = z.strictObject({
  organizationId: CommerceOrganizationIdSchema,
  actionId: CommerceActionIdSchema,
  decision: z.enum(["approve", "reject"]),
  mutationId: CommerceTenantMutationIdSchema,
});

export const PurchaseDecisionPermissionReceiptRecordSchema = z.strictObject({
  recordSchema: z.literal("openarc.permission-receipt.v6"),
  kind: z.literal("permission_receipt"),
  recordId: WorkspaceRecordIdSchema,
  recordRevision: VaultRevisionSchema,
  createdAt: IsoTimestampSchema,
  updatedAt: IsoTimestampSchema,
  connectorId: z.literal(PURCHASE_DECISION_DISCLOSURE.connectorId),
  destination: z.strictObject({ origin: WorkspaceOriginSchema,
    path: z.union([z.literal(PURCHASE_DECISION_APPROVE_PATH), z.literal(PURCHASE_DECISION_REJECT_PATH)]),
    method: z.literal("POST"), upstreams: z.tuple([]) }),
  releasedFields: z.tuple([z.literal("organizationId"), z.literal("actionId"),
    z.literal("decision"), z.literal("mutationId")]),
  released: PurchaseDecisionReleasedSchema,
  reviewed: PurchaseDecisionReviewedSchema,
  purpose: z.literal(PURCHASE_DECISION_DISCLOSURE.purpose),
  credentials: z.literal(PURCHASE_DECISION_DISCLOSURE.credentials),
  openArcRetention: z.literal(PURCHASE_DECISION_DISCLOSURE.openArcRetention),
  providerRetention: z.literal(PURCHASE_DECISION_DISCLOSURE.providerRetention),
  hostingMetadata: z.literal(PURCHASE_DECISION_DISCLOSURE.hostingMetadata),
  approvedAt: IsoTimestampSchema,
  outcome: z.enum(["approved", "completed", "failed"]),
  resolvedAt: IsoTimestampSchema.nullable(),
  failureCode: PermissionFailureCodeSchema.nullable(),
}).superRefine((receipt, context) => {
  const fail = (message: string) => context.addIssue({ code: "custom", message });
  // The route is the decision. A receipt that says one thing and names the
  // other route would misdescribe the request that was actually sent.
  if (receipt.destination.path !== PURCHASE_DECISION_ROUTE_BY_DECISION[receipt.released.decision]) {
    fail("The destination route must be the one the recorded decision calls");
  }
  if (![receipt.createdAt, receipt.updatedAt, receipt.approvedAt, receipt.resolvedAt]
    .every((value) => value === null || IsoTimestampSchema.safeParse(value).success)) return;
  if (receipt.createdAt !== receipt.approvedAt) fail("Receipt creation must equal approval");
  if (receipt.updatedAt !== (receipt.resolvedAt ?? receipt.approvedAt)) fail("Receipt update must match its last outcome time");
  if (receipt.outcome === "approved") {
    if (receipt.resolvedAt !== null || receipt.failureCode !== null) fail("Approval is unresolved");
  } else {
    if (receipt.resolvedAt === null || compareIsoTimestamps(receipt.resolvedAt, receipt.approvedAt) < 0) {
      fail("Resolved receipt cannot predate approval");
    }
    if ((receipt.outcome === "failed") !== (receipt.failureCode !== null)) fail("Only a failed receipt has a failure code");
  }
});

export const PermissionReceiptRecordSchema = z.union([
  CapabilityPermissionReceiptRecordSchema,
  ArcObservationPermissionReceiptRecordSchema,
  AgentRegistryPermissionReceiptRecordSchema,
  JobPermissionReceiptRecordSchema,
  GatewayPermissionReceiptRecordSchema,
  PurchaseDecisionPermissionReceiptRecordSchema,
]);

export type PermissionReceiptRecord = z.infer<typeof PermissionReceiptRecordSchema>;
export type CapabilityPermissionReceiptRecord = z.infer<typeof CapabilityPermissionReceiptRecordSchema>;
export type ArcObservationPermissionReceiptRecord = z.infer<typeof ArcObservationPermissionReceiptRecordSchema>;
export type AgentRegistryPermissionReceiptRecord = z.infer<typeof AgentRegistryPermissionReceiptRecordSchema>;
export type PermissionFailureCode = z.infer<typeof PermissionFailureCodeSchema>;
export type JobPermissionReceiptRecord = z.infer<typeof JobPermissionReceiptRecordSchema>;
export type GatewayPermissionReceiptRecord = z.infer<typeof GatewayPermissionReceiptRecordSchema>;
export type PurchaseDecisionPermissionReceiptRecord = z.infer<typeof PurchaseDecisionPermissionReceiptRecordSchema>;
export type PurchaseDecisionReleased = z.infer<typeof PurchaseDecisionReleasedSchema>;
export type PurchaseDecisionReviewed = z.infer<typeof PurchaseDecisionReviewedSchema>;
