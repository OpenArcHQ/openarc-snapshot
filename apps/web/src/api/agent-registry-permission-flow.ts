import {
  AGENT_REGISTRY_DISCLOSURE,
  AGENT_REGISTRY_EVIDENCE_PATH,
  ARC_TESTNET,
  AgentRegistryEvidenceRequestSchema,
  AgentRegistryObservationRecordSchema,
  AgentRegistryPermissionReceiptRecordSchema,
  compareIsoTimestamps,
  type AgentRegistryEvidenceEnvelope,
  type AgentRegistryEvidenceRequest,
  type AgentRegistryObservationRecord,
  type AgentRegistryPermissionReceiptRecord,
  type PermissionFailureCode,
  type WorkspaceRecord,
} from "@openarc/shared";

import type { UnlockedWorkspace } from "../vault/types.js";
import { OpenArcRequestError } from "./client.js";

export interface AgentRegistryFlowOptions {
  workspace: UnlockedWorkspace;
  origin: string;
  request: AgentRegistryEvidenceRequest;
  linkedAgentProfileRecordId: string | null;
  signal: AbortSignal;
  assertActive: () => void;
  save: (workspace: UnlockedWorkspace, records: readonly WorkspaceRecord[], assertActive: () => void,
    signal: AbortSignal) => Promise<UnlockedWorkspace>;
  /** Durable pre-egress recheck of the stored Vault revision and lock signal. */
  verifyStored?: (workspace: UnlockedWorkspace) => Promise<void>;
  fetch: (request: AgentRegistryEvidenceRequest, signal: AbortSignal) => Promise<AgentRegistryEvidenceEnvelope>;
  now?: () => string;
  id?: () => string;
}

export interface AgentRegistryFlowResult {
  workspace: UnlockedWorkspace;
  observation: AgentRegistryObservationRecord;
  receipt: AgentRegistryPermissionReceiptRecord;
}

export class AgentRegistryFinalizationError extends Error {
  constructor(readonly phase: "failed-request" | "completed-request", readonly storageCause: unknown) {
    super("Agent registry evidence finished but its encrypted local result could not be saved.");
    this.name = "AgentRegistryFinalizationError";
  }
}

export async function runAgentRegistryPermissionFlow(options: AgentRegistryFlowOptions): Promise<AgentRegistryFlowResult> {
  const now = options.now ?? (() => new Date().toISOString());
  const id = options.id ?? (() => crypto.randomUUID());
  options.assertActive();
  const request = AgentRegistryEvidenceRequestSchema.parse(options.request);
  if (options.linkedAgentProfileRecordId !== null && !options.workspace.records.some((record) =>
    record.kind === "agent_profile" && record.recordId === options.linkedAgentProfileRecordId)) {
    throw new OpenArcRequestError("INVALID_REQUEST", "pre-send");
  }
  const approvedAt = now();
  const releasedFields = ["network", "agentId"];
  if (request.feedbackQuery) releasedFields.push("feedbackQuery.clientAddress", "feedbackQuery.feedbackIndex");
  if (request.validationRequestHash) releasedFields.push("validationRequestHash");
  const approved = AgentRegistryPermissionReceiptRecordSchema.parse({
    recordSchema: "openarc.permission-receipt.v3", kind: "permission_receipt", recordId: id(),
    recordRevision: options.workspace.meta.revision, createdAt: approvedAt, updatedAt: approvedAt,
    connectorId: "arc_agent_registry_evidence", destination: { origin: options.origin,
      path: AGENT_REGISTRY_EVIDENCE_PATH, method: "POST", upstreams: [ARC_TESTNET.rpcHttp] },
    releasedFields, released: request,
    purpose: "Observe one ERC-8004 agent identity and optional exact observer or validator claims at one final Arc Testnet block.",
    ...AGENT_REGISTRY_DISCLOSURE, approvedAt, outcome: "approved", resolvedAt: null, failureCode: null,
  });
  let current = await options.save(options.workspace, [approved], options.assertActive, options.signal);
  options.assertActive();
  // A peer lock/save/deletion committed in IndexedDB but not yet observed by
  // this tab must stop the request, not only an in-memory generation change.
  await options.verifyStored?.(current);
  options.assertActive();
  let envelope: AgentRegistryEvidenceEnvelope;
  try { envelope = await options.fetch(request, options.signal); }
  catch (cause) {
    if (options.signal.aborted) throw cause;
    const failureCode: PermissionFailureCode = cause instanceof OpenArcRequestError
      ? cause.code : "REQUEST_UNAVAILABLE";
    try {
      const at = resolutionTime(now(), approvedAt);
      const failed = AgentRegistryPermissionReceiptRecordSchema.parse({ ...approved,
        recordRevision: current.meta.revision, updatedAt: at, outcome: "failed", resolvedAt: at, failureCode });
      current = await options.save(current, [failed], options.assertActive, options.signal);
      options.assertActive();
    } catch (storageCause) {
      if (options.signal.aborted) throw storageCause;
      throw new AgentRegistryFinalizationError("failed-request", storageCause);
    }
    throw cause;
  }
  options.assertActive();
  const at = resolutionTime(now(), approvedAt);
  const completed = AgentRegistryPermissionReceiptRecordSchema.parse({ ...approved,
    recordRevision: current.meta.revision, updatedAt: at, outcome: "completed", resolvedAt: at, failureCode: null });
  const observation = AgentRegistryObservationRecordSchema.parse({
    recordSchema: "openarc.agent-registry-observation-record.v1", kind: "agent_registry_observation",
    recordId: id(), recordRevision: current.meta.revision, createdAt: at, updatedAt: at,
    permissionReceiptId: approved.recordId, linkedAgentProfileRecordId: options.linkedAgentProfileRecordId,
    observation: envelope.data,
  });
  try { current = await options.save(current, [completed, observation], options.assertActive, options.signal); }
  catch (cause) {
    if (options.signal.aborted) throw cause;
    throw new AgentRegistryFinalizationError("completed-request", cause);
  }
  options.assertActive();
  const stored = current.records.find((record): record is AgentRegistryObservationRecord =>
    record.kind === "agent_registry_observation" && record.recordId === observation.recordId);
  const storedReceipt = current.records.find((record): record is AgentRegistryPermissionReceiptRecord =>
    record.kind === "permission_receipt" && record.recordSchema === "openarc.permission-receipt.v3" &&
    record.recordId === completed.recordId);
  if (!stored || !storedReceipt) throw new AgentRegistryFinalizationError("completed-request", new Error("Atomic save missing"));
  return { workspace: current, observation: stored, receipt: storedReceipt };
}

function resolutionTime(candidate: string, approvedAt: string): string {
  return compareIsoTimestamps(candidate, approvedAt) < 0 ? approvedAt : candidate;
}
