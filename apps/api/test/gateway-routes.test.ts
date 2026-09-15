import { ARC_TESTNET, GATEWAY_TRANSFER_PATH, GatewayTransferObservationSchema } from "@openarc/shared";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ArcAccountService } from "../src/arc/account-service.js";
import type { AgentRegistryService } from "../src/arc/agent-registry-service.js";
import type { JobService } from "../src/arc/job-service.js";
import type { ArcTransactionService } from "../src/arc/transaction-service.js";
import type { GatewayTransferService } from "../src/gateway/transfer-service.js";
import { createApp, type CompletionLog } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { ApiBoundaryError } from "../src/http/errors.js";
import { SourceLease, type SourceBudget } from "../src/limits/budget.js";

const origin = "https://app.example.test";
const proxySecret = "synthetic_source_proxy_secret_for_m07_tests";
const metricsToken = "synthetic_metrics_token_for_m07_tests";
const id = "12345678-1234-4234-8234-123456789012";
const headers = { origin, "x-openarc-client": "browser-v1", "content-type": "application/json",
  "x-openarc-proxy-secret": proxySecret, "x-openarc-proxy-client-ip": "192.0.2.70" };
const payload = { network: ARC_TESTNET.caip2, transferId: id };
const apps: ReturnType<typeof createApp>[] = [];
afterEach(async () => Promise.all(apps.splice(0).map((app) => app.close())));

const evidence = GatewayTransferObservationSchema.parse({ schemaVersion: "openarc.gateway-transfer-observation.v1",
  network: ARC_TESTNET.caip2, transfer: { id, status: "received", token: "USDC",
    sendingNetwork: ARC_TESTNET.caip2, recipientNetwork: ARC_TESTNET.caip2,
    fromAddress: `0x${"11".repeat(20)}`, toAddress: `0x${"22".repeat(20)}`, amount: "1000000",
    nonce: `0x${"33".repeat(32)}`, txHash: null, createdAt: "2026-09-05T00:00:00Z", updatedAt: "2026-09-05T00:00:01Z" },
  source: { sourceId: "circle_gateway_testnet", origin: "https://gateway-api-testnet.circle.com",
    observedAt: "2026-09-05T00:00:02Z", adapterVersion: "openarc.gateway-transfer.m07.v1" } });
const environment = { NODE_ENV: "test", APP_ORIGIN: origin, COMMIT_SHA: "test-sha",
  API_BOUNDARY_ENABLED: "true", ARC_OBSERVATION_ENABLED: "true", AGENT_REGISTRY_ENABLED: "true", AGENT_JOBS_ENABLED: "true",
  GATEWAY_EVIDENCE_ENABLED: "true", REDIS_URL: "redis://127.0.0.1:6379", ABUSE_LIMIT_SECRET: "synthetic_abuse_secret_for_m07_tests",
  SOURCE_PROXY_SECRET: proxySecret, METRICS_TOKEN: metricsToken, SOURCE_MAX_SUBCALLS: "16" };
function setup() {
  const logs: CompletionLog[] = [];
  const begin = vi.fn(async (source: "gateway", _route: "gateway_transfer", _peer: string | undefined,
    signal: AbortSignal) => new SourceLease(source, 1, async () => undefined, signal));
  const ready = vi.fn(async () => true);
  const observe = vi.fn(async () => evidence);
  const app = createApp({ config: loadConfig(environment), sourceBudget: { begin, ready } as unknown as SourceBudget,
    logSink: (entry) => logs.push(entry), arcAccountService: {} as ArcAccountService, arcTransactionService: {} as ArcTransactionService,
    agentRegistryService: {} as AgentRegistryService, jobService: {} as JobService,
    gatewayTransferService: { observe } as unknown as GatewayTransferService });
  apps.push(app); return { app, begin, observe, ready, logs };
}

describe("M07 Gateway route boundary", () => {
  it("reports exact cumulative capabilities and returns no-store strict source evidence", async () => {
    const { app, begin, observe } = setup();
    const cap = await app.inject({ method: "GET", url: "/v1/private/capabilities", headers: { origin, "x-openarc-client": "browser-v1" } });
    expect(cap.statusCode).toBe(200);
    expect(cap.json().data).toMatchObject({ capabilityVersion: "openarc.capabilities.m07.v1",
      enabledConnectors: ["arc_primary_rpc", "erc8004_registries", "erc8183_reference", "circle_gateway_testnet"],
      sourceRevision: "circle-gateway-x402-2026-09-05", reviewedAt: "2026-09-05",
      writes: false, features: { arcObservation: true, agentRegistry: true, agentJobs: true, gatewayEvidence: true } });
    expect(observe).not.toHaveBeenCalled(); expect(begin).not.toHaveBeenCalled();
    const result = await app.inject({ method: "POST", url: GATEWAY_TRANSFER_PATH, headers, payload });
    expect(result.statusCode).toBe(200); expect(result.json().data).toEqual(evidence);
    expect(result.headers["cache-control"]).toBe("no-store"); expect(result.headers["referrer-policy"]).toBe("no-referrer");
    expect(observe).toHaveBeenCalledOnce();
    expect(begin).toHaveBeenCalledWith("gateway", "gateway_transfer", "192.0.2.70", expect.any(AbortSignal));
  });
  it("default-off routes reject POST and preflight; cumulative dependencies remain required", async () => {
    const app = createApp({ config: loadConfig({ NODE_ENV: "test" }) }); apps.push(app);
    for (const method of ["POST", "OPTIONS"] as const) {
      const result = await app.inject({ method, url: GATEWAY_TRANSFER_PATH, headers, ...(method === "POST" ? { payload } : {}) });
      expect(result.json().error.code).toBe("FEATURE_DISABLED"); expect(result.headers["cache-control"]).toBe("no-store");
    }
    expect(() => loadConfig({ NODE_ENV: "test", GATEWAY_EVIDENCE_ENABLED: "true" })).toThrow();
    expect(() => loadConfig({ ...environment, AGENT_JOBS_ENABLED: "false" })).toThrow();
    expect(() => loadConfig({ ...environment, REDIS_URL: undefined })).toThrow();
  });
  it("rejects URLs, credentials, unknown keys, non-UUID and foreign network before budget or provider", async () => {
    const { app, begin, observe } = setup();
    for (const value of [{ ...payload, transferId: `${id}?search=PRIVATE_CANARY` }, { ...payload, transferId: "invalid" },
      { ...payload, network: "eip155:1" }, { ...payload, url: "https://evil.test" },
      { ...payload, signature: "PRIVATE_CANARY" }, { ...payload, transferId: [id] }, [payload]]) {
      const result = await app.inject({ method: "POST", url: GATEWAY_TRANSFER_PATH, headers, payload: value });
      expect(result.statusCode).toBe(400); expect(result.body).not.toContain("PRIVATE_CANARY");
    }
    expect(begin).not.toHaveBeenCalled(); expect(observe).not.toHaveBeenCalled();
  });
  it("enforces credentialless exact origin and proxy assertions without identifier logging", async () => {
    const { app, begin, observe, logs } = setup();
    for (const override of [{ cookie: "PRIVATE_CANARY" }, { authorization: "PRIVATE_CANARY" },
      { "proxy-authorization": "PRIVATE_CANARY" }, { origin: "https://evil.test" }, { "x-openarc-proxy-secret": "invalid" }]) {
      const result = await app.inject({ method: "POST", url: GATEWAY_TRANSFER_PATH, headers: { ...headers, ...override }, payload });
      expect(result.statusCode).toBeGreaterThanOrEqual(400); expect(result.body).not.toContain("PRIVATE_CANARY");
    }
    expect(begin).not.toHaveBeenCalled(); expect(observe).not.toHaveBeenCalled();
    expect(JSON.stringify(logs)).not.toContain(id); expect(JSON.stringify(logs)).not.toContain("PRIVATE_CANARY");
    expect(logs.every((entry) => entry.route === "gateway_transfer")).toBe(true);
  });
  it("handles exact preflight without a source call; rejects method/query/body bypasses", async () => {
    const { app, begin } = setup();
    const preflight = await app.inject({ method: "OPTIONS", url: GATEWAY_TRANSFER_PATH, headers: { origin,
      "access-control-request-method": "POST", "access-control-request-headers": "content-type,x-openarc-client" } });
    expect(preflight.statusCode).toBe(204); expect(preflight.headers["access-control-allow-origin"]).toBe(origin);
    expect(preflight.headers["access-control-allow-credentials"]).toBeUndefined();
    for (const method of ["GET", "HEAD", "PUT"] as const) {
      expect((await app.inject({ method, url: GATEWAY_TRANSFER_PATH, headers })).statusCode).toBe(405);
    }
    expect((await app.inject({ method: "POST", url: `${GATEWAY_TRANSFER_PATH}?id=${id}`, headers, payload })).statusCode).toBe(400);
    expect((await app.inject({ method: "POST", url: GATEWAY_TRANSFER_PATH, headers: { ...headers, "content-type": "text/plain" }, payload: "PRIVATE_CANARY" })).statusCode).toBe(415);
    expect((await app.inject({ method: "POST", url: GATEWAY_TRANSFER_PATH, headers, payload: JSON.stringify({ x: "x".repeat(17000) }) })).statusCode).toBe(413);
    expect(begin).not.toHaveBeenCalled();
  });
  it("fails closed on budget outage and unavailable readiness, without calling a source", async () => {
    const { app, begin, observe, ready } = setup();
    begin.mockRejectedValueOnce(new ApiBoundaryError("BUDGET_STORE_UNAVAILABLE"));
    const response = await app.inject({ method: "POST", url: GATEWAY_TRANSFER_PATH, headers, payload });
    expect(response.json().error.code).toBe("BUDGET_STORE_UNAVAILABLE"); expect(observe).not.toHaveBeenCalled();
    ready.mockResolvedValueOnce(false);
    expect((await app.inject({ method: "GET", url: "/readyz" })).statusCode).toBe(503);
    expect(observe).not.toHaveBeenCalled();
  });
  it("sanitizes service failures, validates response contract and exposes only aggregate metrics", async () => {
    const { app, observe, logs } = setup();
    observe.mockRejectedValueOnce(new ApiBoundaryError("SOURCE_NOT_FOUND"));
    const missing = await app.inject({ method: "POST", url: GATEWAY_TRANSFER_PATH, headers, payload });
    expect(missing.statusCode).toBe(404); expect(missing.json().error.code).toBe("SOURCE_NOT_FOUND");
    observe.mockRejectedValueOnce(new Error(`PRIVATE_CANARY ${id}`));
    const failed = await app.inject({ method: "POST", url: GATEWAY_TRANSFER_PATH, headers, payload });
    expect(failed.statusCode).toBe(500); expect(failed.body).not.toContain(id);
    observe.mockResolvedValueOnce({ ...evidence, transfer: { ...evidence.transfer, amount: "invalid" } });
    expect((await app.inject({ method: "POST", url: GATEWAY_TRANSFER_PATH, headers, payload })).statusCode).toBe(502);
    const metrics = await app.inject({ method: "GET", url: "/metrics", headers: { authorization: `Bearer ${metricsToken}` } });
    expect(metrics.body).toContain('route="gateway_transfer"'); expect(metrics.body).not.toContain(id);
    expect(JSON.stringify(logs)).not.toContain(id); expect(JSON.stringify(logs)).not.toContain("PRIVATE_CANARY");
  });
});
