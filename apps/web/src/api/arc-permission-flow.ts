import {
  ARC_ACCOUNT_SNAPSHOT_PATH,
  ARC_OBSERVATION_DISCLOSURE,
  ARC_TESTNET,
  ARC_TRANSACTION_EVIDENCE_PATH,
  ArcAccountSnapshotRequestSchema,
  ArcObservationPermissionReceiptRecordSchema,
  ArcObservationRecordSchema,
  ArcTransactionEvidenceRequestSchema,
  compareIsoTimestamps,
  type ArcAccountSnapshotEnvelope,
  type ArcAccountSnapshotRequest,
  type ArcObservationPermissionReceiptRecord,
  type ArcObservationRecord,
  type ArcTransactionEvidenceEnvelope,
  type ArcTransactionEvidenceRequest,
  type PermissionFailureCode,
  type WorkspaceRecord,
} from "@openarc/shared";

import type { UnlockedWorkspace } from "../vault/types.js";
import { OpenArcRequestError } from "./client.js";

export type ArcObservationInput =
  | { kind: "account"; request: ArcAccountSnapshotRequest }
  | { kind: "transaction"; request: ArcTransactionEvidenceRequest };
export type ArcObservationEnvelope = ArcAccountSnapshotEnvelope | ArcTransactionEvidenceEnvelope;

export interface ArcObservationFlowOptions {
  workspace: UnlockedWorkspace;
  origin: string;
  input: ArcObservationInput;
  signal: AbortSignal;
  assertActive: () => void;
  save: (workspace: UnlockedWorkspace, records: readonly WorkspaceRecord[], assertActive: () => void,
    signal: AbortSignal) => Promise<UnlockedWorkspace>;
  /** Durable pre-egress recheck of the stored Vault revision and lock signal. */
  verifyStored?: (workspace: UnlockedWorkspace) => Promise<void>;
  request: (input: ArcObservationInput, signal: AbortSignal) => Promise<ArcObservationEnvelope>;
  now?: () => string;
  id?: () => string;
}

export interface ArcObservationFlowResult {
  workspace: UnlockedWorkspace;
  observation: ArcObservationRecord;
  receipt: ArcObservationPermissionReceiptRecord;
}

export class ArcObservationFinalizationError extends Error {
  constructor(readonly phase: "failed-request" | "completed-request", readonly storageCause: unknown) {
    super("An Arc observation finished but its encrypted local result could not be saved.");
    this.name = "ArcObservationFinalizationError";
  }
}

export async function runArcObservationPermissionFlow(options: ArcObservationFlowOptions): Promise<ArcObservationFlowResult> {
  const now = options.now ?? (() => new Date().toISOString());
  const id = options.id ?? (() => crypto.randomUUID());
  options.assertActive();
  const input = options.input.kind === "account"
    ? { kind: "account" as const, request: ArcAccountSnapshotRequestSchema.parse(options.input.request) }
    : { kind: "transaction" as const, request: ArcTransactionEvidenceRequestSchema.parse(options.input.request) };
  const approvedAt = now();
  const approved = ArcObservationPermissionReceiptRecordSchema.parse(input.kind === "account" ? {
    recordSchema: "openarc.permission-receipt.v2", kind: "permission_receipt", recordId: id(),
    recordRevision: options.workspace.meta.revision, createdAt: approvedAt, updatedAt: approvedAt,
    connectorId: "arc_account_snapshot", destination: { origin: options.origin,
      path: ARC_ACCOUNT_SNAPSHOT_PATH, method: "POST", upstreams: [ARC_TESTNET.rpcHttp] },
    releasedFields: ["network", "address"], released: input.request,
    purpose: "Observe one public Arc Testnet address at one exact final block.",
    ...ARC_OBSERVATION_DISCLOSURE, approvedAt, outcome: "approved", resolvedAt: null, failureCode: null,
  } : {
    recordSchema: "openarc.permission-receipt.v2", kind: "permission_receipt", recordId: id(),
    recordRevision: options.workspace.meta.revision, createdAt: approvedAt, updatedAt: approvedAt,
    connectorId: "arc_transaction_evidence", destination: { origin: options.origin,
      path: ARC_TRANSACTION_EVIDENCE_PATH, method: "POST", upstreams: [ARC_TESTNET.rpcHttp] },
    releasedFields: ["network", "transactionHash"], released: input.request,
    purpose: "Observe one public Arc Testnet transaction, receipt, anchor, fee, and USDC movement set.",
    ...ARC_OBSERVATION_DISCLOSURE, approvedAt, outcome: "approved", resolvedAt: null, failureCode: null,
  });
  let current = await options.save(options.workspace, [approved], options.assertActive, options.signal);
  options.assertActive();
  // A peer lock/save/deletion committed in IndexedDB but not yet observed by
  // this tab must stop the request, not only an in-memory generation change.
  await options.verifyStored?.(current);
  options.assertActive();

  let envelope: ArcObservationEnvelope;
  try { envelope = await options.request(input, options.signal); }
  catch (cause) {
    if (options.signal.aborted) throw cause;
    const failureCode: PermissionFailureCode = cause instanceof OpenArcRequestError
      ? cause.code : "REQUEST_UNAVAILABLE";
    try {
      const at = resolutionTime(now(), approvedAt);
      const failed = ArcObservationPermissionReceiptRecordSchema.parse({ ...approved,
        recordRevision: current.meta.revision, updatedAt: at, outcome: "failed", resolvedAt: at, failureCode });
      current = await options.save(current, [failed], options.assertActive, options.signal);
      options.assertActive();
    } catch (storageCause) {
      if (options.signal.aborted) throw storageCause;
      throw new ArcObservationFinalizationError("failed-request", storageCause);
    }
    throw cause;
  }
  options.assertActive();
  const at = resolutionTime(now(), approvedAt);
  const completed = ArcObservationPermissionReceiptRecordSchema.parse({ ...approved,
    recordRevision: current.meta.revision, updatedAt: at, outcome: "completed", resolvedAt: at, failureCode: null });
  const observation = ArcObservationRecordSchema.parse({
    recordSchema: "openarc.arc-observation-record.v1", kind: "arc_observation", recordId: id(),
    recordRevision: current.meta.revision, createdAt: at, updatedAt: at,
    permissionReceiptId: approved.recordId, observation: envelope.data,
  });
  try {
    current = await options.save(current, [completed, observation], options.assertActive, options.signal);
  } catch (cause) {
    if (options.signal.aborted) throw cause;
    throw new ArcObservationFinalizationError("completed-request", cause);
  }
  options.assertActive();
  const stored = current.records.find((record): record is ArcObservationRecord =>
    record.kind === "arc_observation" && record.recordId === observation.recordId);
  const storedReceipt = current.records.find((record): record is ArcObservationPermissionReceiptRecord =>
    record.kind === "permission_receipt" && record.recordSchema === "openarc.permission-receipt.v2" &&
    record.recordId === completed.recordId);
  if (!stored || !storedReceipt) throw new ArcObservationFinalizationError("completed-request", new Error("Atomic save missing"));
  return { workspace: current, observation: stored, receipt: storedReceipt };
}

function resolutionTime(candidate: string, approvedAt: string): string {
  return compareIsoTimestamps(candidate, approvedAt) < 0 ? approvedAt : candidate;
}
