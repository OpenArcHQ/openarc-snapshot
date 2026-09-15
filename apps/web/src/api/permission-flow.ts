import {
  CAPABILITIES_PATH, CAPABILITY_DISCLOSURE, PermissionReceiptRecordSchema,
  compareIsoTimestamps,
  type CapabilitiesEnvelope, type PermissionFailureCode, type PermissionReceiptRecord,
} from "@openarc/shared";

import type { UnlockedWorkspace } from "../vault/types.js";
import { CapabilityRequestError } from "./capabilities.js";

export interface PermissionFlowOptions {
  workspace: UnlockedWorkspace;
  origin: string;
  signal: AbortSignal;
  assertActive: () => void;
  save: (workspace: UnlockedWorkspace, receipts: readonly PermissionReceiptRecord[], assertActive: () => void, signal: AbortSignal) => Promise<UnlockedWorkspace>;
  request: (signal: AbortSignal) => Promise<CapabilitiesEnvelope>;
  onCommitted: (workspace: UnlockedWorkspace, outcome: PermissionReceiptRecord["outcome"]) => void;
  /** Durable pre-egress recheck of the stored Vault revision and lock signal. */
  verifyStored?: (workspace: UnlockedWorkspace) => Promise<void>;
  now?: () => string;
  id?: () => string;
}

export interface PermissionFlowResult { workspace: UnlockedWorkspace; capabilities: CapabilitiesEnvelope }

export class PermissionFinalizationError extends Error {
  constructor(readonly phase: "failed-request" | "completed-request", readonly storageCause: unknown) {
    super("A capability request finished but its final receipt state could not be saved.");
    this.name = "PermissionFinalizationError";
  }
}

export async function runCapabilityPermissionFlow(options: PermissionFlowOptions): Promise<PermissionFlowResult> {
  const now = options.now ?? (() => new Date().toISOString());
  const id = options.id ?? (() => crypto.randomUUID());
  options.assertActive();
  const approvedAt = now();
  const approved = PermissionReceiptRecordSchema.parse({ recordSchema: "openarc.permission-receipt.v1",
    recordId: id(), recordRevision: options.workspace.meta.revision, kind: "permission_receipt",
    createdAt: approvedAt, updatedAt: approvedAt, connectorId: CAPABILITY_DISCLOSURE.connectorId,
    destination: { origin: options.origin, path: CAPABILITIES_PATH, method: "GET", upstreams: [] },
    releasedFields: [], purpose: CAPABILITY_DISCLOSURE.purpose, credentials: CAPABILITY_DISCLOSURE.credentials,
    openArcRetention: CAPABILITY_DISCLOSURE.openArcRetention, providerRetention: CAPABILITY_DISCLOSURE.providerRetention,
    hostingMetadata: CAPABILITY_DISCLOSURE.hostingMetadata, approvedAt, outcome: "approved", resolvedAt: null, failureCode: null });
  let current = await options.save(options.workspace, [approved], options.assertActive, options.signal);
  options.assertActive();
  options.onCommitted(current, "approved");
  // A peer lock/save/deletion committed in IndexedDB but not yet observed by
  // this tab must stop the request, not only an in-memory generation change.
  await options.verifyStored?.(current);
  options.assertActive();
  let capabilities: CapabilitiesEnvelope;
  try { capabilities = await options.request(options.signal); }
  catch (cause) {
    if (options.signal.aborted) throw cause;
    const failureCode: PermissionFailureCode = cause instanceof CapabilityRequestError ? cause.code : "REQUEST_UNAVAILABLE";
    try {
      const resolved = resolveReceipt(approved, current.meta.revision, resolutionTime(now(), approvedAt), "failed", failureCode);
      current = await options.save(current, [resolved], options.assertActive, options.signal);
      options.assertActive();
      options.onCommitted(current, "failed");
    } catch (storageCause) {
      if (options.signal.aborted) throw storageCause;
      // Preserve the approval, but propagate storage/CAS boundaries to the session owner.
      throw new PermissionFinalizationError("failed-request", storageCause);
    }
    throw cause;
  }
  options.assertActive();
  try {
    const completed = resolveReceipt(approved, current.meta.revision, resolutionTime(now(), approvedAt), "completed", null);
    current = await options.save(current, [completed], options.assertActive, options.signal);
  }
  catch (cause) {
    if (options.signal.aborted) throw cause;
    throw new PermissionFinalizationError("completed-request", cause);
  }
  options.assertActive();
  options.onCommitted(current, "completed");
  return { workspace: current, capabilities };
}

function resolutionTime(candidate: string, approvedAt: string): string {
  return compareIsoTimestamps(candidate, approvedAt) < 0 ? approvedAt : candidate;
}

function resolveReceipt(receipt: PermissionReceiptRecord, revision: string, at: string,
  outcome: "completed" | "failed", failureCode: PermissionFailureCode | null): PermissionReceiptRecord {
  return PermissionReceiptRecordSchema.parse({ ...receipt, recordRevision: revision,
    updatedAt: at, outcome, resolvedAt: at, failureCode });
}
