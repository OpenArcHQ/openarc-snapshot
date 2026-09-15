// P08-01 write-side rules for the ROOT-build Vault kinds (task_draft, task_report, research_run).
//
// assertTaskDraftChanges and assertResearchChanges are ported VERBATIM from these ROOT build files (sha256
// re-verified 2026-09-15):
//   apps/web/src/vault/task-drafts.ts    b1abe6715b368791c094faa28dc5fe836119ab35c05883b67585465c35b54f25 (:24-60)
//   apps/web/src/vault/research-runs.ts  7b231f57893075077157d093f34e8c3ac0f2b9b99f5b0abccfff5779900d7f44 (:4-19)
// so this build can never overwrite evidence a ROOT task report locks. The ROOT writers (createTaskDraftRecord,
// cancelTaskDraftRecord, research-flow) are NOT ported: this build has no editor for these kinds, so
// assertRootKindsReadOnly additionally refuses every create, edit or reclassification of them. They are preserved
// by every save, export, import, recovery and passphrase change, and removed only by whole-Vault deletion or a
// record deletion that leaves ROOT's relationship rules satisfied.
import { accountReportDraftDigest, compareIsoTimestamps, type WorkspaceRecord } from "@openarc/shared";

import { VaultError } from "./errors.js";

/** Checks against authenticated current records, never caller-supplied history. */
export function assertTaskDraftChanges(previous: readonly WorkspaceRecord[], changes: readonly WorkspaceRecord[]): void {
  const byId = new Map(previous.map(record => [record.recordId, record]));
  const protectedIds = new Set<string>();
  for (const report of previous.filter(record => record.kind === "task_report")) {
    protectedIds.add(report.observationRecordId);
    const observation = byId.get(report.observationRecordId);
    if (observation?.kind === "arc_observation") protectedIds.add(observation.permissionReceiptId);
  }
  for (const changed of changes) {
    if (protectedIds.has(changed.recordId)) throw new VaultError("INVALID_BACKUP", "Evidence linked to a saved task report is immutable.");
    const old = byId.get(changed.recordId);
    if (changed.kind === "task_report" || old?.kind === "task_report") {
      if (old) throw new VaultError("INVALID_BACKUP", "Saved task reports cannot be replaced or reclassified.");
      if (changed.kind === "task_report") {
        const draft = byId.get(changed.taskDraftRecordId);
        if (draft?.kind !== "task_draft" || draft.state !== "draft" ||
          changes.some(record => record.recordId === draft.recordId)) {
          throw new VaultError("INVALID_BACKUP", "Reports require an existing active saved draft.");
        }
      }
      continue;
    }
    if (changed.kind !== "task_draft" && old?.kind !== "task_draft") continue;
    const invalid = (): never => { throw new VaultError("INVALID_BACKUP", "Task identity and owner intent are immutable; only cancellation is allowed."); };
    if (changed.kind !== "task_draft") return invalid();
    if (!old) {
      if (changed.state !== "draft") invalid();
      continue;
    }
    if (old.kind !== "task_draft") return invalid();
    if (old.state !== "draft" || changed.state !== "cancelled"
      || old.taskId !== changed.taskId || old.instructions !== changed.instructions
      || old.agentProfileRecordId !== changed.agentProfileRecordId || old.createdAt !== changed.createdAt
      || compareIsoTimestamps(changed.updatedAt, old.updatedAt) < 0) invalid();
  }
}

export function assertResearchChanges(previous: readonly WorkspaceRecord[], changes: readonly WorkspaceRecord[]) {
  const invalid = (): never => { throw new VaultError("INVALID_BACKUP", "Research approval and completed evidence are immutable."); };
  for (const changed of changes) {
    const old = previous.find(record => record.recordId === changed.recordId);
    if (changed.kind !== "research_run" && old?.kind !== "research_run") continue;
    if (changed.kind !== "research_run") invalid();
    if (changed.kind !== "research_run") continue;
    const draft = previous.find(record => record.recordId === changed.taskDraftRecordId);
    if (draft?.kind !== "task_draft" || draft.state !== "draft" ||
      changed.taskDigest !== accountReportDraftDigest(draft) || changes.some(record => record.recordId === draft.recordId)) invalid();
    if (!old) { if (changed.state !== "approved") invalid(); continue; }
    if (old.kind !== "research_run" || old.state !== "approved" || changed.state === "approved" ||
      old.createdAt !== changed.createdAt || old.taskDraftRecordId !== changed.taskDraftRecordId ||
      old.taskDigest !== changed.taskDigest || JSON.stringify(old.input) !== JSON.stringify(changed.input)) invalid();
  }
}

export const ROOT_BUILD_RECORD_KINDS: ReadonlySet<WorkspaceRecord["kind"]> = new Set(["task_draft", "task_report", "research_run"]);

export const ROOT_KINDS_READ_ONLY_MESSAGE =
  "Task drafts, task reports and research runs are read-only in this OpenArc build. Nothing was saved.";

/** Integration-build rule: no write may create, change or reclassify a ROOT-build record. */
export function assertRootKindsReadOnly(previous: readonly WorkspaceRecord[], changes: readonly WorkspaceRecord[]): void {
  const previousKinds = new Map(previous.map(record => [record.recordId, record.kind]));
  for (const changed of changes) {
    const oldKind = previousKinds.get(changed.recordId);
    if (ROOT_BUILD_RECORD_KINDS.has(changed.kind) || (oldKind !== undefined && ROOT_BUILD_RECORD_KINDS.has(oldKind))) {
      throw new VaultError("INVALID_BACKUP", ROOT_KINDS_READ_ONLY_MESSAGE);
    }
  }
}
