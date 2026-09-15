import {
  JOB_DISCLOSURE,
  JOB_EVIDENCE_PATH,
  ARC_TESTNET,
  JobEvidenceRequestSchema,
  JobObservationRecordSchema,
  JobPermissionReceiptRecordSchema,
  compareIsoTimestamps,
  type JobEvidenceEnvelope,
  type JobEvidenceRequest,
  type JobObservationRecord,
  type JobPermissionReceiptRecord,
  type PermissionFailureCode,
  type WorkspaceRecord,
} from "@openarc/shared";

import type { UnlockedWorkspace } from "../vault/types.js";
import { OpenArcRequestError } from "./client.js";

export interface JobFlowOptions {
  workspace: UnlockedWorkspace;
  origin: string;
  request: JobEvidenceRequest;
  linkedActionRecordId: string | null;
  signal: AbortSignal;
  assertActive: () => void;
  save: (workspace: UnlockedWorkspace, records: readonly WorkspaceRecord[], assertActive: () => void,
    signal: AbortSignal) => Promise<UnlockedWorkspace>;
  /** Durable pre-egress recheck of the stored Vault revision and lock signal. */
  verifyStored?: (workspace: UnlockedWorkspace) => Promise<void>;
  fetch: (request: JobEvidenceRequest, signal: AbortSignal) => Promise<JobEvidenceEnvelope>;
  now?: () => string;
  id?: () => string;
}

export interface JobFlowResult {
  workspace: UnlockedWorkspace;
  observation: JobObservationRecord;
  receipt: JobPermissionReceiptRecord;
}

export class JobFinalizationError extends Error {
  constructor(readonly phase: "failed-request" | "completed-request", readonly storageCause: unknown) {
    super("Job evidence finished but its encrypted local result could not be saved.");
    this.name = "JobFinalizationError";
  }
}

export async function runJobPermissionFlow(options: JobFlowOptions): Promise<JobFlowResult> {
  const now = options.now ?? (() => new Date().toISOString());
  const id = options.id ?? (() => crypto.randomUUID());
  options.assertActive();
  const request = JobEvidenceRequestSchema.parse(options.request);
  if (options.linkedActionRecordId !== null && !options.workspace.records.some((record) =>
    record.kind === "action_envelope" && record.recordId === options.linkedActionRecordId)) {
    throw new OpenArcRequestError("INVALID_REQUEST", "pre-send");
  }
  const approvedAt = now();
  const releasedFields = ["network", "jobId"];
  if (request.submissionTransactionHash) releasedFields.push("submissionTransactionHash");
  const approved = JobPermissionReceiptRecordSchema.parse({
    recordSchema: "openarc.permission-receipt.v4", kind: "permission_receipt", recordId: id(),
    recordRevision: options.workspace.meta.revision, createdAt: approvedAt, updatedAt: approvedAt,
    connectorId: "arc_job_evidence", destination: { origin: options.origin,
      path: JOB_EVIDENCE_PATH, method: "POST", upstreams: [ARC_TESTNET.rpcHttp] },
    releasedFields, released: request,
    purpose: "Observe one job on the reviewed Arc Testnet reference contract and an optional exact submission receipt.",
    ...JOB_DISCLOSURE, approvedAt, outcome: "approved", resolvedAt: null, failureCode: null,
  });
  let current = await options.save(options.workspace, [approved], options.assertActive, options.signal);
  options.assertActive();
  // A peer lock/save/deletion committed in IndexedDB but not yet observed by
  // this tab must stop the request, not only an in-memory generation change.
  await options.verifyStored?.(current);
  options.assertActive();
  let envelope: JobEvidenceEnvelope;
  try { envelope = await options.fetch(request, options.signal); }
  catch (cause) {
    if (options.signal.aborted) throw cause;
    const failureCode: PermissionFailureCode = cause instanceof OpenArcRequestError
      ? cause.code : "REQUEST_UNAVAILABLE";
    try {
      const at = resolutionTime(now(), approvedAt);
      const failed = JobPermissionReceiptRecordSchema.parse({ ...approved,
        recordRevision: current.meta.revision, updatedAt: at, outcome: "failed", resolvedAt: at, failureCode });
      current = await options.save(current, [failed], options.assertActive, options.signal);
      options.assertActive();
    } catch (storageCause) {
      if (options.signal.aborted) throw storageCause;
      throw new JobFinalizationError("failed-request", storageCause);
    }
    throw cause;
  }
  options.assertActive();
  const at = resolutionTime(now(), approvedAt);
  const completed = JobPermissionReceiptRecordSchema.parse({ ...approved,
    recordRevision: current.meta.revision, updatedAt: at, outcome: "completed", resolvedAt: at, failureCode: null });
  const observation = JobObservationRecordSchema.parse({
    recordSchema: "openarc.job-observation-record.v1", kind: "job_observation",
    recordId: id(), recordRevision: current.meta.revision, createdAt: at, updatedAt: at,
    permissionReceiptId: approved.recordId, linkedActionRecordId: options.linkedActionRecordId,
    linkBasis: options.linkedActionRecordId === null ? null : "explicit_local_confirmation",
    observation: envelope.data,
  });
  try { current = await options.save(current, [completed, observation], options.assertActive, options.signal); }
  catch (cause) {
    if (options.signal.aborted) throw cause;
    throw new JobFinalizationError("completed-request", cause);
  }
  options.assertActive();
  const stored = current.records.find((record): record is JobObservationRecord =>
    record.kind === "job_observation" && record.recordId === observation.recordId);
  const storedReceipt = current.records.find((record): record is JobPermissionReceiptRecord =>
    record.kind === "permission_receipt" && record.recordSchema === "openarc.permission-receipt.v4" &&
    record.recordId === completed.recordId);
  if (!stored || !storedReceipt) throw new JobFinalizationError("completed-request", new Error("Atomic save missing"));
  return { workspace: current, observation: stored, receipt: storedReceipt };
}

function resolutionTime(candidate: string, approvedAt: string): string {
  return compareIsoTimestamps(candidate, approvedAt) < 0 ? approvedAt : candidate;
}
