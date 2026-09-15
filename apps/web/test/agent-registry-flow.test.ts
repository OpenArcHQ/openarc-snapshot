import {
  API_CLIENT_HEADER,
  API_SCHEMA_VERSION,
  AGENT_REGISTRY_EVIDENCE_PATH,
  AGENT_REGISTRY_LIMITATIONS,
  AGENT_REGISTRY_PROXIES,
  ARC_ERC8004,
  ARC_ERC8004_DEPLOYMENT,
  ARC_TESTNET,
  AgentRegistryEvidenceEnvelopeSchema,
  VALIDATION_PENDING_REASON,
  type WorkspaceRecord,
} from "@openarc/shared";
import { describe, expect, it, vi } from "vitest";

import { requestAgentRegistryEvidence } from "../src/api/agent-registry.js";
import { AgentRegistryFinalizationError, runAgentRegistryPermissionFlow } from "../src/api/agent-registry-permission-flow.js";
import { OpenArcRequestError } from "../src/api/client.js";
import type { UnlockedWorkspace } from "../src/vault/types.js";

const owner = "0x1111111111111111111111111111111111111111";
const wallet = "0x2222222222222222222222222222222222222222";
const blockHash = `0x${"a".repeat(64)}`;
const request = { network: ARC_TESTNET.caip2, agentId: "1" } as const;
const registryCheck = (key: "identity" | "reputation" | "validation") => ({
  proxy: AGENT_REGISTRY_PROXIES[key], pinnedImplementation: ARC_ERC8004_DEPLOYMENT.implementations[key],
  observedImplementation: ARC_ERC8004_DEPLOYMENT.implementations[key], implementation: "match" as const,
  pinnedOwner: ARC_ERC8004_DEPLOYMENT.proxyOwner, observedOwner: ARC_ERC8004_DEPLOYMENT.proxyOwner, owner: "match" as const,
});
const envelope = AgentRegistryEvidenceEnvelopeSchema.parse({ ok: true,
  meta: { schemaVersion: API_SCHEMA_VERSION, requestId: "11111111-1111-4111-8111-111111111111", buildSha: "test-sha" },
  data: { schemaVersion: "openarc.agent-registry-evidence.v2", network: ARC_TESTNET.caip2, agentId: "1",
    anchor: { blockNumber: "100", blockHash, blockTimestamp: "2026-09-04T11:59:59Z",
      finality: "deterministic", confirmations: "1" },
    identity: { owner, agentWallet: wallet,
      metadata: { uri: "", kind: "none", trust: "untrusted_external_metadata", fetched: false } },
    feedback: null, validation: null,
    deployment: { status: "verified", implementationSlot: ARC_ERC8004_DEPLOYMENT.implementationSlot,
      sourceRevision: ARC_ERC8004_DEPLOYMENT.sourceRevision, reviewedAt: ARC_ERC8004_DEPLOYMENT.reviewedAt,
      registries: { identity: registryCheck("identity"), reputation: registryCheck("reputation"),
        validation: registryCheck("validation") } },
    source: { sourceId: "arc_primary_rpc", registrySourceId: "erc8004_registries", origin: ARC_TESTNET.rpcHttp,
      explorerOrigin: ARC_TESTNET.explorerOrigin, network: ARC_TESTNET.caip2,
      sourceRevision: ARC_ERC8004.sourceRevision, reviewedAt: ARC_ERC8004.reviewedAt,
      specificationStatus: "draft", contractsRevision: ARC_ERC8004.contractsRevision,
      registries: { identity: ARC_TESTNET.contracts.erc8004IdentityRegistry,
        reputation: ARC_TESTNET.contracts.erc8004ReputationRegistry,
        validation: ARC_TESTNET.contracts.erc8004ValidationRegistry },
      observedAt: "2026-09-04T12:00:00Z", adapterVersion: "openarc.agent-registry-evidence.m05.v2" },
    limitations: [...AGENT_REGISTRY_LIMITATIONS] } });

function setup() {
  let revision = 0;
  const initial = { meta: { revision: "A".repeat(32) }, records: [] } as unknown as UnlockedWorkspace;
  const writes: WorkspaceRecord[][] = [];
  const save = vi.fn(async (workspace: UnlockedWorkspace, changes: readonly WorkspaceRecord[]) => {
    writes.push(structuredClone([...changes]));
    revision += 1;
    const ids = new Set(changes.map((record) => record.recordId));
    return { ...workspace, meta: { ...workspace.meta, revision: String(revision).padStart(32, "A") },
      records: [...workspace.records.filter((record) => !ids.has(record.recordId)), ...changes] } as UnlockedWorkspace;
  });
  const ids = ["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"];
  const base = { workspace: initial, origin: "https://app.example.test", request,
    linkedAgentProfileRecordId: null, signal: new AbortController().signal, assertActive: () => undefined,
    save, fetch: vi.fn(async () => envelope),
    now: vi.fn().mockReturnValueOnce("2026-09-04T11:59:58Z").mockReturnValue("2026-09-04T12:00:01Z"),
    id: () => ids.shift()! };
  return { base, save, writes };
}

describe("M05 agent registry browser flow", () => {
  it("sends one fixed credentialless request and rejects a widened response", async () => {
    const fetcher = vi.fn(async () => new Response(JSON.stringify(envelope), { status: 200,
      headers: { "content-type": "application/json" } }));
    await requestAgentRegistryEvidence(request, new AbortController().signal, fetcher);
    expect(fetcher).toHaveBeenCalledWith(AGENT_REGISTRY_EVIDENCE_PATH, {
      method: "POST", headers: { "X-OpenArc-Client": API_CLIENT_HEADER, "Content-Type": "application/json" },
      body: JSON.stringify(request), credentials: "omit", redirect: "error", cache: "no-store",
      referrerPolicy: "no-referrer", signal: expect.any(AbortSignal),
    });
    await expect(requestAgentRegistryEvidence(request, new AbortController().signal, async () =>
      new Response(JSON.stringify({ ...envelope, data: { ...envelope.data, universalScore: 99 } }),
        { status: 200, headers: { "content-type": "application/json" } })))
      .rejects.toMatchObject({ code: "INVALID_RESPONSE" });
    const unexpectedFeedback = { observer: "0x3333333333333333333333333333333333333333", feedbackIndex: "0",
      value: "1", valueDecimals: 0, decimal: "1", tag1: "", tag2: "", revoked: false,
      relationship: "observer_specific_claim" } as const;
    await expect(requestAgentRegistryEvidence(request, new AbortController().signal, async () =>
      new Response(JSON.stringify({ ...envelope, data: { ...envelope.data, feedback: unexpectedFeedback } }),
        { status: 200, headers: { "content-type": "application/json" } })))
      .rejects.toMatchObject({ code: "INVALID_RESPONSE", phase: "post-send" });
  });

  it("binds optional claims to every exact released identifier", async () => {
    const exactRequest = { ...request, feedbackQuery: {
      clientAddress: "0x3333333333333333333333333333333333333333", feedbackIndex: "7" } } as const;
    const mismatched = { ...envelope, data: { ...envelope.data, feedback: {
      observer: exactRequest.feedbackQuery.clientAddress, feedbackIndex: "8", value: "1", valueDecimals: 0,
      decimal: "1", tag1: "", tag2: "", revoked: false, relationship: "observer_specific_claim" as const } } };
    await expect(requestAgentRegistryEvidence(exactRequest, new AbortController().signal, async () =>
      new Response(JSON.stringify(mismatched), { status: 200, headers: { "content-type": "application/json" } })))
      .rejects.toMatchObject({ code: "INVALID_RESPONSE", phase: "post-send" });
  });

  it("accepts an explicit pending validation but rejects a legacy getter-only response from the API", async () => {
    const requestHash = `0x${"b".repeat(64)}`;
    const validationRequest = { ...request, validationRequestHash: requestHash } as const;
    const respond = (data: unknown) => async () => new Response(JSON.stringify({ ...envelope, data }),
      { status: 200, headers: { "content-type": "application/json" } });
    const pending = { state: "pending_or_unobserved", requestHash, namedValidator: owner, agentId: "1", lastUpdate: "5",
      relationship: "request_names_validator_without_observed_response", reason: VALIDATION_PENDING_REASON };
    const result = await requestAgentRegistryEvidence(validationRequest, new AbortController().signal,
      respond({ ...envelope.data, validation: pending }));
    expect(result.data.validation?.state).toBe("pending_or_unobserved");
    await expect(requestAgentRegistryEvidence(validationRequest, new AbortController().signal,
      respond({ ...envelope.data, validation: { requestHash, validator: owner, agentId: "1", response: 0,
        responseHash: `0x${"0".repeat(64)}`, tag: "", lastUpdate: "5", relationship: "validator_specific_response" } })))
      .rejects.toMatchObject({ code: "INVALID_RESPONSE" });
  });

  it("encrypts exact disclosure before contact and atomically stores completion plus evidence", async () => {
    const { base, save, writes } = setup();
    const result = await runAgentRegistryPermissionFlow(base);
    expect(save).toHaveBeenCalledTimes(2);
    expect(save.mock.invocationCallOrder[0]).toBeLessThan(base.fetch.mock.invocationCallOrder[0]!);
    expect(writes[0]![0]).toMatchObject({ recordSchema: "openarc.permission-receipt.v3",
      connectorId: "arc_agent_registry_evidence", releasedFields: ["network", "agentId"], released: request,
      outcome: "approved" });
    expect(JSON.stringify(writes[0])).not.toContain("linkedAgentProfileRecordId");
    expect(writes[1]!.map((record) => record.kind).sort()).toEqual([
      "agent_registry_observation", "permission_receipt",
    ]);
    expect(result.observation.linkedAgentProfileRecordId).toBeNull();
  });

  it("causes zero network on approval failure and preserves the approved receipt on finalization failure", async () => {
    const first = setup();
    first.save.mockRejectedValueOnce(new Error("PRIVATE_STORAGE_CANARY"));
    await expect(runAgentRegistryPermissionFlow(first.base)).rejects.toThrow("PRIVATE_STORAGE_CANARY");
    expect(first.base.fetch).not.toHaveBeenCalled();

    const second = setup();
    const original = second.save.getMockImplementation()!;
    second.save.mockImplementationOnce(original).mockRejectedValueOnce(new Error("PRIVATE_QUOTA_CANARY"));
    await expect(runAgentRegistryPermissionFlow(second.base)).rejects.toBeInstanceOf(AgentRegistryFinalizationError);
    expect(second.writes).toHaveLength(1);
  });

  it("records a sanitized failed receipt without replacing prior evidence", async () => {
    const { base, writes } = setup();
    base.fetch.mockRejectedValueOnce(new OpenArcRequestError("SOURCE_NOT_FOUND", "post-send"));
    await expect(runAgentRegistryPermissionFlow(base)).rejects.toMatchObject({ code: "SOURCE_NOT_FOUND" });
    expect(writes[1]![0]).toMatchObject({ outcome: "failed", failureCode: "SOURCE_NOT_FOUND" });
    expect(writes.flat().some((record) => record.kind === "agent_registry_observation")).toBe(false);
  });
});
