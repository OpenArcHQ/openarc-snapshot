import { AGENT_REGISTRY_LIMITATIONS, AGENT_REGISTRY_PROXIES, ARC_ERC8004, ARC_ERC8004_DEPLOYMENT, ARC_TESTNET,
  AgentRegistryEvidenceSchema } from "@openarc/shared";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ArcAccountService } from "../src/arc/account-service.js";
import type { AgentRegistryService } from "../src/arc/agent-registry-service.js";
import type { ArcTransactionService } from "../src/arc/transaction-service.js";
import { createApp } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { SourceLease, type SourceBudget } from "../src/limits/budget.js";

const origin = "https://app.example.test";
const proxySecret = "synthetic_source_proxy_secret_for_m05_tests";
const metricsToken = "synthetic_metrics_token_for_m05_tests";
const headers = { origin, "x-openarc-client": "browser-v1", "content-type": "application/json",
  "x-openarc-proxy-secret": proxySecret, "x-openarc-proxy-client-ip": "192.0.2.50" };
const observer = "0x3333333333333333333333333333333333333333";
const blockHash = `0x${"a".repeat(64)}`;
const apps: ReturnType<typeof createApp>[] = [];
afterEach(async () => Promise.all(apps.splice(0).map((app) => app.close())));

const registryCheck = (key: "identity" | "reputation" | "validation") => ({
  proxy: AGENT_REGISTRY_PROXIES[key], pinnedImplementation: ARC_ERC8004_DEPLOYMENT.implementations[key],
  observedImplementation: ARC_ERC8004_DEPLOYMENT.implementations[key], implementation: "match",
  pinnedOwner: ARC_ERC8004_DEPLOYMENT.proxyOwner, observedOwner: ARC_ERC8004_DEPLOYMENT.proxyOwner, owner: "match",
});
const evidence = AgentRegistryEvidenceSchema.parse({
  schemaVersion: "openarc.agent-registry-evidence.v2", network: ARC_TESTNET.caip2, agentId: "1",
  anchor: { blockNumber: "100", blockHash, blockTimestamp: "2026-09-04T12:00:00Z",
    finality: "deterministic", confirmations: "1" },
  identity: { owner: "0x1111111111111111111111111111111111111111",
    agentWallet: "0x2222222222222222222222222222222222222222",
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
  limitations: [...AGENT_REGISTRY_LIMITATIONS],
});

function setup() {
  const begin = vi.fn(async (source: "arc_rpc", _route: "agent_registry", _peer: string | undefined,
    signal: AbortSignal) => new SourceLease(source, 16, async () => undefined, signal));
  const budget = { begin, ready: vi.fn(async () => true) } as unknown as SourceBudget;
  const observe = vi.fn(async () => evidence);
  const config = loadConfig({ NODE_ENV: "test", APP_ORIGIN: origin, COMMIT_SHA: "test-sha",
    API_BOUNDARY_ENABLED: "true", ARC_OBSERVATION_ENABLED: "true", AGENT_REGISTRY_ENABLED: "true",
    REDIS_URL: "redis://127.0.0.1:6379", ABUSE_LIMIT_SECRET: "synthetic_abuse_secret_for_m05_tests",
    SOURCE_PROXY_SECRET: proxySecret, METRICS_TOKEN: metricsToken, SOURCE_MAX_SUBCALLS: "16" });
  const app = createApp({ config, sourceBudget: budget,
    arcAccountService: {} as ArcAccountService, arcTransactionService: {} as ArcTransactionService,
    agentRegistryService: { observe } as unknown as AgentRegistryService });
  apps.push(app);
  return { app, begin, observe };
}

describe("M05 agent registry route", () => {
  it("reports cumulative capability truth and serves one strict bounded envelope", async () => {
    const { app, begin, observe } = setup();
    const capabilities = await app.inject({ method: "GET", url: "/v1/private/capabilities",
      headers: { origin, "x-openarc-client": "browser-v1" } });
    expect(capabilities.json().data).toMatchObject({ capabilityVersion: "openarc.capabilities.m05.v1",
      enabledConnectors: ["arc_primary_rpc", "erc8004_registries"],
      features: { arcObservation: true, agentRegistry: true }, sourceRevision: ARC_ERC8004.sourceRevision });
    const response = await app.inject({ method: "POST", url: "/v1/private/arc/agent-registry-evidence",
      headers, payload: { network: ARC_TESTNET.caip2, agentId: "1" } });
    expect(response.statusCode).toBe(200);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.json().data).toEqual(evidence);
    expect(observe).toHaveBeenCalledOnce();
    expect(begin).toHaveBeenCalledWith("arc_rpc", "agent_registry", "192.0.2.50", expect.any(AbortSignal));
  });

  it("rejects contract overrides, malformed IDs, and browser credentials before execution", async () => {
    const { app, begin, observe } = setup();
    for (const payload of [
      { network: ARC_TESTNET.caip2, agentId: "01" },
      { network: ARC_TESTNET.caip2, agentId: "1", registryAddress: observer },
      { network: ARC_TESTNET.caip2, agentId: "1", feedbackQuery: { clientAddress: observer } },
    ]) {
      const response = await app.inject({ method: "POST", url: "/v1/private/arc/agent-registry-evidence",
        headers, payload });
      expect(response.statusCode).toBe(400);
      expect(response.body).not.toContain(observer);
    }
    expect(begin).not.toHaveBeenCalled();
    expect(observe).not.toHaveBeenCalled();
  });
});
