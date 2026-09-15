// P08-00: records shaped EXACTLY like the ROOT build's Vault record kinds, using the literals copied verbatim from
// these ROOT build files (repo-relative):
//   packages/shared/src/task-draft.ts          TaskDraftRecordSchema    "openarc.task-draft-record.v1"
//   packages/shared/src/account-report-task.ts TaskReportRecordSchema   "openarc.task-report-record.v1"
//   packages/shared/src/research-run.ts        ResearchRunRecordSchema  "openarc.research-run.v1"
// Deliberately free of @openarc/shared imports so the same builder can be validated against the ROOT build's own
// schemas (see root-build-source.ts). Test-only; never imported by runtime code.
import { createHash } from "node:crypto";

export const ROOT_KIND_RECORD_SCHEMAS = Object.freeze({
  task_draft: "openarc.task-draft-record.v1",
  task_report: "openarc.task-report-record.v1",
  research_run: "openarc.research-run.v1",
} as const);
export type RootKind = keyof typeof ROOT_KIND_RECORD_SCHEMAS;

const ARC_TESTNET_CAIP2 = "eip155:5042002";
const rootId = (n: number) => `7e570000-0000-4000-8000-${n.toString(16).padStart(12, "0")}`;
/** ROOT digest: `sha256:${sha256(stringToHex(JSON.stringify(value))).slice(2)}` (viem), i.e. SHA-256 over UTF-8 JSON. */
const rootDigest = (value: unknown) => `sha256:${createHash("sha256").update(JSON.stringify(value), "utf8").digest("hex")}`;

export interface RootKindInput {
  recordRevision: string;
  agentProfileRecordId: string;
  accountObservationRecordId: string;
  accountSnapshot: { schemaVersion: string; network: string; address: string } & Record<string, unknown>;
}

export function buildRootKindRecords(input: RootKindInput): Record<RootKind, Record<string, unknown> & { recordId: string }> {
  const createdAt = "2026-09-14T13:00:00Z";
  const taskDraft = { recordSchema: ROOT_KIND_RECORD_SCHEMAS.task_draft, kind: "task_draft", recordId: rootId(0x901),
    recordRevision: input.recordRevision, createdAt, updatedAt: createdAt, taskId: "task_7e570000000040008000000000000901",
    network: ARC_TESTNET_CAIP2, agentProfileRecordId: input.agentProfileRecordId,
    instructions: "TEST-ONLY root build task draft instructions", state: "draft", execution: "not_dispatched", cancelledAt: null };
  // accountReportDraftDigest(draft)
  const taskDigest = rootDigest(["openarc.private-task.v1", taskDraft.taskId, taskDraft.agentProfileRecordId, taskDraft.createdAt,
    taskDraft.instructions]);
  const request = { schemaVersion: "openarc.account-report-task.v1", taskId: taskDraft.taskId,
    agentProfileRecordId: input.agentProfileRecordId, taskDigest, operation: "arc_account_report",
    network: input.accountSnapshot.network, address: input.accountSnapshot.address };
  // accountReportRequestDigest(request)
  const requestDigest = rootDigest([request.schemaVersion, request.taskId, request.agentProfileRecordId, request.taskDigest,
    request.operation, request.network, request.address]);
  const taskReport = { recordSchema: ROOT_KIND_RECORD_SCHEMAS.task_report, kind: "task_report", recordId: rootId(0x902),
    recordRevision: input.recordRevision, createdAt, updatedAt: createdAt, taskDraftRecordId: taskDraft.recordId,
    observationRecordId: input.accountObservationRecordId, request, requestDigest,
    execution: "read_only_report", payment: "not_requested" };
  const researchRun = { recordSchema: ROOT_KIND_RECORD_SCHEMAS.research_run, kind: "research_run", recordId: rootId(0x903),
    recordRevision: input.recordRevision, createdAt, updatedAt: "2026-09-14T13:01:00Z", taskDraftRecordId: taskDraft.recordId,
    taskDigest, input: { operation: "account_investigation", network: input.accountSnapshot.network, address: input.accountSnapshot.address },
    state: "completed", result: input.accountSnapshot, execution: "owner_requested_read_only", payment: "not_requested" };
  return { task_draft: taskDraft, task_report: taskReport, research_run: researchRun };
}
