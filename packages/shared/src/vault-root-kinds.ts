// P08-01 additive dual reader: the ROOT build's Vault record kinds (task_draft, task_report, research_run). Stored
// schemas are copied VERBATIM (literals, regexes, bounds, trims and refinements) from these ROOT build files,
// re-verified by sha256 on 2026-09-15 before porting:
//   packages/shared/src/task-draft.ts          e23d8fb6835759f401169a23e5c37dd3d482d0755a512f41ad67742a1434bb5b
//   packages/shared/src/account-report-task.ts dbcf77c07f80226bcf160c90d4db19694b84e70224d54fe0508f5181607af81b
//   packages/shared/src/research-run.ts        9726ccd6ede6a328da7127e94a651a738cf60debf367242f159f883527ffcff2
// Only the persisted record contracts are ported. The ROOT build's writers, wire request/result/status schemas,
// research paths and provider egress are deliberately absent: this build reads, preserves, backs up, imports,
// recovers and rescues these records but never creates or edits them (PORT-08 compatibility rule, packet P08-01).
import { z } from "zod";

import { ArcAccountSnapshotSchema, ArcTransactionEvidenceSchema } from "./arc-observation.js";
import { ARC_TESTNET } from "./network.js";
import {
  EvmAddressSchema,
  IsoTimestampSchema,
  Sha256DigestSchema,
  TransactionHashSchema,
  compareIsoTimestamps,
} from "./primitives.js";
import { sha256HexUtf8 } from "./sha256.js";
import { VaultRevisionSchema, WorkspaceRecordIdSchema } from "./workspace-primitives.js";

// ---------------------------------------------------------------------------------------------------------------
// Digest. ROOT computes `sha256:${sha256(stringToHex(JSON.stringify(value))).slice(2)}` with viem, i.e. lowercase hex
// SHA-256 over the UTF-8 bytes of plain JSON.stringify, checked inside synchronous zod refinements.
// test/vault-root-kinds.test.ts pins it against node:crypto and viem's exact ROOT expression.
// ---------------------------------------------------------------------------------------------------------------

export { sha256HexUtf8 } from "./sha256.js";

const digest = (value: unknown) => `sha256:${sha256HexUtf8(JSON.stringify(value))}`;

// ---------------------------------------------------------------------------------------------------------------
// task_draft (ROOT build packages/shared/src/task-draft.ts:7-32)
// ---------------------------------------------------------------------------------------------------------------

/** Private owner intent only. Never a payment authorization or dispatch ledger. */
export const TaskDraftRecordSchema = z.strictObject({
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
  if (compareIsoTimestamps(record.updatedAt, record.createdAt) < 0) {
    ctx.addIssue({ code: "custom", message: "Task update predates creation" });
  }
  if (record.state === "draft" && (record.cancelledAt !== null || record.updatedAt !== record.createdAt)) {
    ctx.addIssue({ code: "custom", message: "A draft preserves its original owner intent" });
  }
  if (record.state === "cancelled" && (record.cancelledAt === null || record.cancelledAt !== record.updatedAt)) {
    ctx.addIssue({ code: "custom", message: "Cancellation requires its exact update timestamp" });
  }
});

export type TaskDraftRecord = z.infer<typeof TaskDraftRecordSchema>;

// ---------------------------------------------------------------------------------------------------------------
// task_report (ROOT build packages/shared/src/account-report-task.ts:9-22, :34-38, :54-64)
// ---------------------------------------------------------------------------------------------------------------

export const AccountReportTaskRequestSchema = z.strictObject({
  schemaVersion: z.literal("openarc.account-report-task.v1"),
  taskId: z.string().regex(/^task_[0-9a-f]{32}$/u),
  agentProfileRecordId: WorkspaceRecordIdSchema,
  taskDigest: Sha256DigestSchema,
  operation: z.literal("arc_account_report"),
  network: z.literal(ARC_TESTNET.caip2), address: EvmAddressSchema,
});
export type AccountReportTaskRequest = z.infer<typeof AccountReportTaskRequestSchema>;

export function accountReportDraftDigest(input: unknown): string {
  const draft = TaskDraftRecordSchema.parse(input);
  return digest(["openarc.private-task.v1", draft.taskId, draft.agentProfileRecordId, draft.createdAt, draft.instructions]);
}

export function accountReportRequestDigest(input: unknown): string {
  const request = AccountReportTaskRequestSchema.parse(input);
  return digest([request.schemaVersion, request.taskId, request.agentProfileRecordId,
    request.taskDigest, request.operation, request.network, request.address]);
}

/** Immutable local result linkage; the observation payload is encrypted once in
 * its existing arc_observation record. Never spending or execution authority. */
export const TaskReportRecordSchema = z.strictObject({
  recordSchema: z.literal("openarc.task-report-record.v1"), kind: z.literal("task_report"),
  recordId: WorkspaceRecordIdSchema, recordRevision: VaultRevisionSchema,
  createdAt: IsoTimestampSchema, updatedAt: IsoTimestampSchema,
  taskDraftRecordId: WorkspaceRecordIdSchema, observationRecordId: WorkspaceRecordIdSchema,
  request: AccountReportTaskRequestSchema, requestDigest: Sha256DigestSchema,
  execution: z.literal("read_only_report"), payment: z.literal("not_requested"),
}).superRefine((value, context) => {
  if (value.createdAt !== value.updatedAt || value.requestDigest !== accountReportRequestDigest(value.request))
    context.addIssue({ code: "custom", message: "Task report identity is immutable and must match its request" });
});
export type TaskReportRecord = z.infer<typeof TaskReportRecordSchema>;

// ---------------------------------------------------------------------------------------------------------------
// research_run (ROOT build packages/shared/src/research-run.ts:16-58). The stored literal is "openarc.research-run.v1" (no "-record").
// ---------------------------------------------------------------------------------------------------------------

/** ROOT `WebResearchRequestSchema.shape.query`; the wire request itself is not ported. */
const WebResearchQuerySchema = z.string().trim().min(3).max(300)
  .refine(value => [...value].every(char => char.charCodeAt(0) >= 32 && char.charCodeAt(0) !== 127), "Use a plain public search query");
export const ResearchInputSchema = z.discriminatedUnion("operation", [
  z.strictObject({ operation: z.literal("account_investigation"), network: z.literal(ARC_TESTNET.caip2), address: EvmAddressSchema }),
  z.strictObject({ operation: z.literal("transaction_investigation"), network: z.literal(ARC_TESTNET.caip2), transactionHash: TransactionHashSchema }),
  z.strictObject({ operation: z.literal("web_research"), query: WebResearchQuerySchema }),
]);
const PublicCitationUrlSchema = z.string().url().max(2048).refine(value => {
  const host = /^https:\/\/([a-z0-9.-]+)(?::443)?(?:[/?#]|$)/iu.exec(value)?.[1]?.toLowerCase();
  return !!host && /\.[a-z]{2,}$/u.test(host) && !host.endsWith(".local") && !host.endsWith(".localhost");
}, "Only public HTTPS source links are accepted");
/** Provider-supplied excerpts and URLs: untrusted text, never rendered as markup or opened automatically. */
export const WebResearchResultSchema = z.strictObject({
  schemaVersion: z.literal("openarc.web-research.v1"), provider: z.literal("tavily"),
  query: WebResearchQuerySchema, observedAt: IsoTimestampSchema,
  credits: z.literal(1), payment: z.literal("free_provider_credit"),
  results: z.array(z.strictObject({ title: z.string().min(1).max(300), url: PublicCitationUrlSchema,
    excerpt: z.string().max(1600) })).max(5),
});
export const ResearchResultSchema = z.union([ArcAccountSnapshotSchema, ArcTransactionEvidenceSchema, WebResearchResultSchema]);
export const ResearchRunRecordSchema = z.strictObject({
  recordSchema: z.literal("openarc.research-run.v1"), kind: z.literal("research_run"),
  recordId: WorkspaceRecordIdSchema, recordRevision: VaultRevisionSchema,
  createdAt: IsoTimestampSchema, updatedAt: IsoTimestampSchema,
  taskDraftRecordId: WorkspaceRecordIdSchema, taskDigest: Sha256DigestSchema,
  input: ResearchInputSchema, state: z.enum(["approved", "completed", "unavailable"]),
  result: ResearchResultSchema.nullable(),
  execution: z.literal("owner_requested_read_only"), payment: z.literal("not_requested"),
}).superRefine((run, context) => {
  const fail = () => context.addIssue({ code: "custom", message: "Research result must match the approved request" });
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
export type ResearchInput = z.infer<typeof ResearchInputSchema>;
export type ResearchRunRecord = z.infer<typeof ResearchRunRecordSchema>;
export type ResearchResult = z.infer<typeof ResearchResultSchema>;
