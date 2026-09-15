// PORT-08 compatibility rule (P08-01, §1.11 item 9): an independent, test-only re-derivation of the stored contracts
// of the ROOT build's Vault record kinds, re-typed from these ROOT build files (sha256-pinned in root-build-source.ts):
//   packages/shared/src/task-draft.ts, packages/shared/src/account-report-task.ts, packages/shared/src/research-run.ts
// It shares no code with packages/shared/src/vault-root-kinds.ts (digests here use node:crypto), so a later drift of
// the shipped reader away from the ROOT contract fails the tests. Only primitives that P08-00 found byte-identical in
// both builds are imported. Test-only; never imported by runtime code.
import { createHash } from "node:crypto";

import {
  ARC_TESTNET,
  ArcAccountSnapshotSchema,
  ArcTransactionEvidenceSchema,
  EvmAddressSchema,
  IsoTimestampSchema,
  Sha256DigestSchema,
  TransactionHashSchema,
  VaultRevisionSchema,
  WorkspaceRecordIdSchema,
  compareIsoTimestamps,
} from "@openarc/shared";
import { z } from "zod";

/** ROOT: `sha256:${sha256(stringToHex(JSON.stringify(value))).slice(2)}` (viem). */
export const rootDigest = (value: unknown): string =>
  `sha256:${createHash("sha256").update(JSON.stringify(value), "utf8").digest("hex")}`;

export interface RootDraftDigestInput { taskId: string; agentProfileRecordId: string; createdAt: string; instructions: string }

/** ROOT accountReportDraftDigest: the draft is parsed first, so instructions are trimmed. */
export const rootDraftDigest = (draft: RootDraftDigestInput): string =>
  rootDigest(["openarc.private-task.v1", draft.taskId, draft.agentProfileRecordId, draft.createdAt, draft.instructions.trim()]);

const ReferenceTaskDraft = z.strictObject({
  recordSchema: z.literal("openarc.task-draft-record.v1"),
  kind: z.literal("task_draft"),
  recordId: WorkspaceRecordIdSchema,
  recordRevision: VaultRevisionSchema,
  createdAt: IsoTimestampSchema,
  updatedAt: IsoTimestampSchema,
  taskId: z.string().regex(/^task_[0-9a-f]{32}$/u),
  network: z.literal(ARC_TESTNET.caip2),
  agentProfileRecordId: WorkspaceRecordIdSchema,
  instructions: z.string().trim().min(1).max(2000),
  state: z.enum(["draft", "cancelled"]),
  execution: z.literal("not_dispatched"),
  cancelledAt: IsoTimestampSchema.nullable(),
}).superRefine((record, ctx) => {
  if (!IsoTimestampSchema.safeParse(record.createdAt).success || !IsoTimestampSchema.safeParse(record.updatedAt).success) return;
  if (compareIsoTimestamps(record.updatedAt, record.createdAt) < 0) ctx.addIssue({ code: "custom", message: "predates" });
  if (record.state === "draft" && (record.cancelledAt !== null || record.updatedAt !== record.createdAt)) {
    ctx.addIssue({ code: "custom", message: "draft" });
  }
  if (record.state === "cancelled" && (record.cancelledAt === null || record.cancelledAt !== record.updatedAt)) {
    ctx.addIssue({ code: "custom", message: "cancelled" });
  }
});

const ReferenceRequest = z.strictObject({
  schemaVersion: z.literal("openarc.account-report-task.v1"),
  taskId: z.string().regex(/^task_[0-9a-f]{32}$/u),
  agentProfileRecordId: WorkspaceRecordIdSchema,
  taskDigest: Sha256DigestSchema,
  operation: z.literal("arc_account_report"),
  network: z.literal(ARC_TESTNET.caip2),
  address: EvmAddressSchema,
});
export type ReferenceRequest = z.infer<typeof ReferenceRequest>;

/** ROOT accountReportRequestDigest. */
export const rootRequestDigest = (request: ReferenceRequest): string => rootDigest([request.schemaVersion, request.taskId,
  request.agentProfileRecordId, request.taskDigest, request.operation, request.network, request.address]);

const ReferenceTaskReport = z.strictObject({
  recordSchema: z.literal("openarc.task-report-record.v1"),
  kind: z.literal("task_report"),
  recordId: WorkspaceRecordIdSchema,
  recordRevision: VaultRevisionSchema,
  createdAt: IsoTimestampSchema,
  updatedAt: IsoTimestampSchema,
  taskDraftRecordId: WorkspaceRecordIdSchema,
  observationRecordId: WorkspaceRecordIdSchema,
  request: ReferenceRequest,
  requestDigest: Sha256DigestSchema,
  execution: z.literal("read_only_report"),
  payment: z.literal("not_requested"),
}).superRefine((value, ctx) => {
  if (value.createdAt !== value.updatedAt || value.requestDigest !== rootRequestDigest(value.request)) {
    ctx.addIssue({ code: "custom", message: "report" });
  }
});

const ReferenceQuery = z.string().trim().min(3).max(300)
  .refine((value) => [...value].every((char) => char.charCodeAt(0) >= 32 && char.charCodeAt(0) !== 127));
const ReferenceInput = z.discriminatedUnion("operation", [
  z.strictObject({ operation: z.literal("account_investigation"), network: z.literal(ARC_TESTNET.caip2), address: EvmAddressSchema }),
  z.strictObject({ operation: z.literal("transaction_investigation"), network: z.literal(ARC_TESTNET.caip2), transactionHash: TransactionHashSchema }),
  z.strictObject({ operation: z.literal("web_research"), query: ReferenceQuery }),
]);
const ReferenceCitationUrl = z.string().url().max(2048).refine((value) => {
  const host = /^https:\/\/([a-z0-9.-]+)(?::443)?(?:[/?#]|$)/iu.exec(value)?.[1]?.toLowerCase();
  return !!host && /\.[a-z]{2,}$/u.test(host) && !host.endsWith(".local") && !host.endsWith(".localhost");
});
const ReferenceWebResult = z.strictObject({
  schemaVersion: z.literal("openarc.web-research.v1"),
  provider: z.literal("tavily"),
  query: ReferenceQuery,
  observedAt: IsoTimestampSchema,
  credits: z.literal(1),
  payment: z.literal("free_provider_credit"),
  results: z.array(z.strictObject({ title: z.string().min(1).max(300), url: ReferenceCitationUrl, excerpt: z.string().max(1600) })).max(5),
});
const ReferenceResearchRun = z.strictObject({
  recordSchema: z.literal("openarc.research-run.v1"),
  kind: z.literal("research_run"),
  recordId: WorkspaceRecordIdSchema,
  recordRevision: VaultRevisionSchema,
  createdAt: IsoTimestampSchema,
  updatedAt: IsoTimestampSchema,
  taskDraftRecordId: WorkspaceRecordIdSchema,
  taskDigest: Sha256DigestSchema,
  input: ReferenceInput,
  state: z.enum(["approved", "completed", "unavailable"]),
  result: z.union([ArcAccountSnapshotSchema, ArcTransactionEvidenceSchema, ReferenceWebResult]).nullable(),
  execution: z.literal("owner_requested_read_only"),
  payment: z.literal("not_requested"),
}).superRefine((run, ctx) => {
  const fail = () => ctx.addIssue({ code: "custom", message: "run" });
  if ((run.state === "completed") !== (run.result !== null)) fail();
  if (run.state === "approved" && run.updatedAt !== run.createdAt) fail();
  if (!run.result) return;
  const result = run.result;
  if (run.input.operation === "account_investigation") {
    if (result.schemaVersion !== "openarc.arc-account-snapshot.v1" || result.address !== run.input.address || result.network !== run.input.network) fail();
  } else if (run.input.operation === "transaction_investigation") {
    if (result.schemaVersion !== "openarc.arc-transaction-evidence.v1" || result.transaction.hash !== run.input.transactionHash || result.network !== run.input.network) fail();
  } else if (result.schemaVersion !== "openarc.web-research.v1" || result.query !== run.input.query) fail();
});

export const REFERENCE_ROOT_KIND_SCHEMAS: Readonly<Record<"task_draft" | "task_report" | "research_run", z.ZodType>> =
  Object.freeze({ task_draft: ReferenceTaskDraft, task_report: ReferenceTaskReport, research_run: ReferenceResearchRun });
