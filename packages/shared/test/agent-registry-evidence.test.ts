import {
  AGENT_REGISTRY_EVIDENCE_PATH,
  AGENT_REGISTRY_LIMITATIONS,
  AGENT_REGISTRY_PROXIES,
  ARC_ERC8004,
  ARC_ERC8004_DEPLOYMENT,
  ARC_TESTNET,
  AgentRegistryEvidenceRequestSchema,
  AgentRegistryEvidenceSchema,
  AgentRegistryPermissionReceiptRecordSchema,
  StoredAgentRegistryEvidenceSchema,
  VALIDATION_PENDING_REASON,
} from "../src/index.js";
import { describe, expect, it } from "vitest";

const observer = "0x3333333333333333333333333333333333333333";
const requestHash = `0x${"a".repeat(64)}`;
const at = "2026-09-04T12:00:00.000Z";

const registryCheck = (key: "identity" | "reputation" | "validation") => ({
  proxy: AGENT_REGISTRY_PROXIES[key], pinnedImplementation: ARC_ERC8004_DEPLOYMENT.implementations[key],
  observedImplementation: ARC_ERC8004_DEPLOYMENT.implementations[key], implementation: "match",
  pinnedOwner: ARC_ERC8004_DEPLOYMENT.proxyOwner, observedOwner: ARC_ERC8004_DEPLOYMENT.proxyOwner, owner: "match",
});
const deployment = { status: "verified", implementationSlot: ARC_ERC8004_DEPLOYMENT.implementationSlot,
  sourceRevision: ARC_ERC8004_DEPLOYMENT.sourceRevision, reviewedAt: ARC_ERC8004_DEPLOYMENT.reviewedAt,
  registries: { identity: registryCheck("identity"), reputation: registryCheck("reputation"),
    validation: registryCheck("validation") } };
const source = (adapterVersion: string) => ({ sourceId: "arc_primary_rpc", registrySourceId: "erc8004_registries",
  origin: ARC_TESTNET.rpcHttp, explorerOrigin: ARC_TESTNET.explorerOrigin, network: ARC_TESTNET.caip2,
  sourceRevision: ARC_ERC8004.sourceRevision, reviewedAt: ARC_ERC8004.reviewedAt,
  specificationStatus: "draft", contractsRevision: ARC_ERC8004.contractsRevision,
  registries: { identity: ARC_TESTNET.contracts.erc8004IdentityRegistry,
    reputation: ARC_TESTNET.contracts.erc8004ReputationRegistry,
    validation: ARC_TESTNET.contracts.erc8004ValidationRegistry },
  observedAt: at, adapterVersion });
const base = {
  network: ARC_TESTNET.caip2, agentId: "1",
  anchor: { blockNumber: "2", blockHash: requestHash, blockTimestamp: at, finality: "deterministic", confirmations: "1" },
  identity: { owner: observer, agentWallet: observer,
    metadata: { uri: "https://example.test/agent.json", kind: "https", trust: "untrusted_external_metadata", fetched: false } },
  feedback: null,
};
const evidence = { ...base, schemaVersion: "openarc.agent-registry-evidence.v2", validation: null, deployment,
  source: source("openarc.agent-registry-evidence.m05.v2"), limitations: [...AGENT_REGISTRY_LIMITATIONS] };
const pending = { state: "pending_or_unobserved", requestHash, namedValidator: observer, agentId: "1", lastUpdate: "5",
  relationship: "request_names_validator_without_observed_response", reason: VALIDATION_PENDING_REASON };

describe("M05 ERC-8004 shared contracts", () => {
  it("accepts only one bounded exact agent, feedback, and validation request", () => {
    const parsed = AgentRegistryEvidenceRequestSchema.parse({ network: ARC_TESTNET.caip2, agentId: "1",
      feedbackQuery: { clientAddress: observer, feedbackIndex: "0" }, validationRequestHash: requestHash });
    expect(parsed.feedbackQuery?.clientAddress).toBe(observer);
    for (const invalid of [
      { ...parsed, agentId: (1n << 256n).toString() },
      { ...parsed, feedbackQuery: { ...parsed.feedbackQuery, feedbackIndex: (1n << 64n).toString() } },
      { ...parsed, registryAddress: observer },
    ]) expect(AgentRegistryEvidenceRequestSchema.safeParse(invalid).success).toBe(false);
  });

  it("requires exact disclosure fields and never includes a local profile link", () => {
    const receipt = { recordSchema: "openarc.permission-receipt.v3", kind: "permission_receipt",
      recordId: crypto.randomUUID(), recordRevision: "A".repeat(32), createdAt: at, updatedAt: at,
      connectorId: "arc_agent_registry_evidence", destination: { origin: "https://app.example.test",
        path: AGENT_REGISTRY_EVIDENCE_PATH, method: "POST", upstreams: [ARC_TESTNET.rpcHttp] },
      releasedFields: ["network", "agentId", "feedbackQuery.clientAddress", "feedbackQuery.feedbackIndex"],
      released: { network: ARC_TESTNET.caip2, agentId: "1",
        feedbackQuery: { clientAddress: observer, feedbackIndex: "0" } },
      purpose: "Observe one ERC-8004 agent identity and optional exact observer or validator claims at one final Arc Testnet block.",
      credentials: "omit",
      openArcRetention: "No request or response body is retained by the OpenArc API. The approved result is stored only in the encrypted local workspace.",
      providerRetention: "Arc's public RPC receives the released public registry identifiers under Arc's current terms and privacy policy.",
      hostingMetadata: "OpenArc, its hosting provider, and the Arc RPC receive ordinary network metadata, including IP and user-agent where applicable.",
      approvedAt: at, outcome: "approved", resolvedAt: null, failureCode: null };
    expect(AgentRegistryPermissionReceiptRecordSchema.parse(receipt).released.agentId).toBe("1");
    expect(AgentRegistryPermissionReceiptRecordSchema.safeParse({ ...receipt,
      releasedFields: ["network", "agentId"], linkedAgentProfileRecordId: crypto.randomUUID() }).success).toBe(false);
  });

  it("keeps metadata explicitly unfetched and claims observer-specific", () => {
    const parsed = AgentRegistryEvidenceSchema.parse(evidence);
    expect(parsed.identity.metadata.fetched).toBe(false);
    expect(AgentRegistryEvidenceSchema.safeParse({ ...parsed, identity: { ...parsed.identity,
      metadata: { ...parsed.identity.metadata, uri: "javascript:alert(1)", kind: "https" } } }).success).toBe(false);
    expect(AgentRegistryEvidenceSchema.safeParse({ ...parsed, identity: { ...parsed.identity,
      metadata: { ...parsed.identity.metadata, uri: "https://user:password@example.test/a", kind: "https" } } }).success).toBe(false);
  });

  it("keeps pending validation explicit and never carries a response value", () => {
    expect(AgentRegistryEvidenceSchema.parse({ ...evidence, validation: pending }).validation?.state)
      .toBe("pending_or_unobserved");
    expect(AgentRegistryEvidenceSchema.safeParse({ ...evidence, validation: { ...pending, response: 0 } }).success).toBe(false);
    expect(AgentRegistryEvidenceSchema.safeParse({ ...evidence, validation: { ...pending,
      relationship: "validator_specific_response" } }).success).toBe(false);
    const responded = { state: "responded", requestHash, validator: observer, agentId: "1", response: 0,
      responseHash: requestHash, tag: "", lastUpdate: "5", relationship: "validator_specific_response" };
    expect(AgentRegistryEvidenceSchema.safeParse({ ...evidence, validation: responded }).success).toBe(false);
    expect(AgentRegistryEvidenceSchema.safeParse({ ...evidence, validation: { ...responded,
      responseEvent: { transactionHash: requestHash, blockNumber: "2", logIndex: "0" } } }).success).toBe(true);
  });

  it("derives deployment status from every pin comparison", () => {
    const drift = { ...deployment, status: "drift", registries: { ...deployment.registries,
      validation: { ...registryCheck("validation"), observedImplementation: observer, implementation: "drift" } } };
    expect(AgentRegistryEvidenceSchema.safeParse({ ...evidence, deployment: drift }).success).toBe(true);
    expect(AgentRegistryEvidenceSchema.safeParse({ ...evidence, deployment: { ...drift, status: "verified" } }).success).toBe(false);
    expect(AgentRegistryEvidenceSchema.safeParse({ ...evidence, deployment: { ...deployment, registries: {
      ...deployment.registries, identity: { ...registryCheck("identity"), observedOwner: observer } } } }).success).toBe(false);
    const unknown = { ...deployment, status: "unknown", registries: { ...deployment.registries,
      identity: { ...registryCheck("identity"), observedImplementation: null, implementation: "unknown" } } };
    expect(AgentRegistryEvidenceSchema.safeParse({ ...evidence, deployment: unknown }).success).toBe(true);
    expect(AgentRegistryEvidenceSchema.safeParse({ ...evidence, deployment: undefined }).success).toBe(false);
  });

  it("reads original v1 records only as stored legacy data, never as a new API response", () => {
    const legacy = { ...base, schemaVersion: "openarc.agent-registry-evidence.v1",
      validation: { requestHash, validator: observer, agentId: "1", response: 0, responseHash: requestHash, tag: "",
        lastUpdate: "5", relationship: "validator_specific_response" },
      source: source("openarc.agent-registry-evidence.m05.v1"), limitations: AGENT_REGISTRY_LIMITATIONS.slice(0, 4) };
    expect(StoredAgentRegistryEvidenceSchema.parse(legacy).schemaVersion).toBe("openarc.agent-registry-evidence.v1");
    expect(AgentRegistryEvidenceSchema.safeParse(legacy).success).toBe(false);
  });
});
