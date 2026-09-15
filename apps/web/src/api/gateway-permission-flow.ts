import {
  GATEWAY_DISCLOSURE, GATEWAY_TRANSFER_PATH, GatewayTransferRequestSchema,
  GatewayObservationRecordSchema, GatewayPermissionReceiptRecordSchema, compareIsoTimestamps,
  type GatewayTransferEnvelope, type GatewayTransferRequest, type GatewayObservationRecord,
  type GatewayPermissionReceiptRecord, type PermissionFailureCode, type WorkspaceRecord,
} from "@openarc/shared";
import type { UnlockedWorkspace } from "../vault/types.js";
import { OpenArcRequestError } from "./client.js";

export interface GatewayFlowOptions {
  workspace: UnlockedWorkspace;
  origin: string;
  request: GatewayTransferRequest;
  linkedBundleRecordId: string | null;
  signal: AbortSignal;
  assertActive: () => void;
  save: (workspace: UnlockedWorkspace, records: readonly WorkspaceRecord[], assertActive: () => void,
    signal: AbortSignal) => Promise<UnlockedWorkspace>;
  /** Durable pre-egress recheck of the stored Vault revision and lock signal. */
  verifyStored?: (workspace: UnlockedWorkspace) => Promise<void>;
  fetch: (request: GatewayTransferRequest, signal: AbortSignal) => Promise<GatewayTransferEnvelope>;
  now?: () => string;
  id?: () => string;
}

export class GatewayFinalizationError extends Error {
  constructor(readonly phase: "failed-request" | "completed-request", readonly storageCause: unknown) {
    super("Gateway evidence finished but its encrypted local result could not be saved.");
    this.name = "GatewayFinalizationError";
  }
}

export async function runGatewayPermissionFlow(options: GatewayFlowOptions): Promise<{
  workspace: UnlockedWorkspace; observation: GatewayObservationRecord; receipt: GatewayPermissionReceiptRecord;
}> {
  const now = options.now ?? (() => new Date().toISOString());
  const id = options.id ?? (() => crypto.randomUUID());
  options.assertActive();
  const request = GatewayTransferRequestSchema.parse(options.request);
  if (options.linkedBundleRecordId !== null && !options.workspace.records.some((record) =>
    record.kind === "x402_bundle" && record.recordId === options.linkedBundleRecordId)) {
    throw new OpenArcRequestError("INVALID_REQUEST", "pre-send");
  }
  const approvedAt = now();
  const resolvedTime = () => { const at = now(); return compareIsoTimestamps(at, approvedAt) < 0 ? approvedAt : at; };
  const approved = GatewayPermissionReceiptRecordSchema.parse({
    recordSchema: "openarc.permission-receipt.v5", kind: "permission_receipt", recordId: id(),
    recordRevision: options.workspace.meta.revision, createdAt: approvedAt, updatedAt: approvedAt,
    connectorId: "circle_gateway_transfer", destination: { origin: options.origin,
      path: GATEWAY_TRANSFER_PATH, method: "POST", upstreams: ["https://gateway-api-testnet.circle.com"] },
    releasedFields: ["network", "transferId"], released: request,
    purpose: "Read one exact Circle Gateway Arc Testnet transfer; this does not verify fulfillment.",
    ...GATEWAY_DISCLOSURE, approvedAt, outcome: "approved", resolvedAt: null, failureCode: null,
  });
  let current = await options.save(options.workspace, [approved], options.assertActive, options.signal);
  options.assertActive();
  // A peer lock/save/deletion committed in IndexedDB but not yet observed by
  // this tab must stop the request, not only an in-memory generation change.
  await options.verifyStored?.(current);
  options.assertActive();
  let envelope: GatewayTransferEnvelope;
  try { envelope = await options.fetch(request, options.signal); }
  catch (cause) {
    if (options.signal.aborted) throw cause;
    const failureCode: PermissionFailureCode = cause instanceof OpenArcRequestError ? cause.code : "REQUEST_UNAVAILABLE";
    try {
      const at = resolvedTime();
      const failed = GatewayPermissionReceiptRecordSchema.parse({ ...approved,
        recordRevision: current.meta.revision, updatedAt: at, outcome: "failed", resolvedAt: at, failureCode });
      current = await options.save(current, [failed], options.assertActive, options.signal);
      options.assertActive();
    } catch (storageCause) {
      if (options.signal.aborted) throw storageCause;
      throw new GatewayFinalizationError("failed-request", storageCause);
    }
    throw cause;
  }
  options.assertActive();
  const at = resolvedTime();
  const completed = GatewayPermissionReceiptRecordSchema.parse({ ...approved,
    recordRevision: current.meta.revision, updatedAt: at, outcome: "completed", resolvedAt: at, failureCode: null });
  const observation = GatewayObservationRecordSchema.parse({
    recordSchema: "openarc.gateway-observation-record.v1", kind: "gateway_observation",
    recordId: id(), recordRevision: current.meta.revision, createdAt: at, updatedAt: at,
    permissionReceiptId: approved.recordId, linkedBundleRecordId: options.linkedBundleRecordId,
    linkBasis: options.linkedBundleRecordId === null ? null : "explicit_local_confirmation", observation: envelope.data,
  });
  try { current = await options.save(current, [completed, observation], options.assertActive, options.signal); }
  catch (cause) {
    if (options.signal.aborted) throw cause;
    throw new GatewayFinalizationError("completed-request", cause);
  }
  options.assertActive();
  const stored = current.records.find((record): record is GatewayObservationRecord =>
    record.kind === "gateway_observation" && record.recordId === observation.recordId);
  const receipt = current.records.find((record): record is GatewayPermissionReceiptRecord =>
    record.kind === "permission_receipt" && record.recordSchema === "openarc.permission-receipt.v5" && record.recordId === completed.recordId);
  if (!stored || !receipt) throw new GatewayFinalizationError("completed-request", new Error("Atomic save missing"));
  return { workspace: current, observation: stored, receipt };
}
