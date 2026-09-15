import { ARC_ERC8183, ARC_TESTNET } from "@openarc/shared";
import { jobTestEnvelope } from "../../../test-fixtures/job-evidence.js";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ArcAccountService } from "../src/arc/account-service.js";
import type { AgentRegistryService } from "../src/arc/agent-registry-service.js";
import type { JobService } from "../src/arc/job-service.js";
import type { ArcTransactionService } from "../src/arc/transaction-service.js";
import { createApp, type CompletionLog } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { SourceLease, type SourceBudget } from "../src/limits/budget.js";

const origin = "https://app.example.test";
const proxySecret = "synthetic_source_proxy_secret_for_m06_tests";
const metricsToken = "synthetic_metrics_token_for_m06_tests";
const headers = { origin, "x-openarc-client": "browser-v1", "content-type": "application/json",
  "x-openarc-proxy-secret": proxySecret, "x-openarc-proxy-client-ip": "192.0.2.50" };
const observer = "0x3333333333333333333333333333333333333333";
const apps: ReturnType<typeof createApp>[] = [];
afterEach(async () => Promise.all(apps.splice(0).map((app) => app.close())));

const evidence = jobTestEnvelope().data;

function setup() {
  const logs: CompletionLog[] = [];
  const begin = vi.fn(async (source: "arc_rpc", _route: "agent_job", _peer: string | undefined,
    signal: AbortSignal) => new SourceLease(source, 11, async () => undefined, signal));
  const budget = { begin, ready: vi.fn(async () => true) } as unknown as SourceBudget;
  const observe = vi.fn(async () => evidence);
  const config = loadConfig({ NODE_ENV: "test", APP_ORIGIN: origin, COMMIT_SHA: "test-sha",
    API_BOUNDARY_ENABLED: "true", ARC_OBSERVATION_ENABLED: "true", AGENT_REGISTRY_ENABLED: "true", AGENT_JOBS_ENABLED: "true",
    REDIS_URL: "redis://127.0.0.1:6379", ABUSE_LIMIT_SECRET: "synthetic_abuse_secret_for_m06_tests",
    SOURCE_PROXY_SECRET: proxySecret, METRICS_TOKEN: metricsToken, SOURCE_MAX_SUBCALLS: "16" });
  const app = createApp({ config, sourceBudget: budget, logSink: (entry) => logs.push(entry),
    arcAccountService: {} as ArcAccountService, arcTransactionService: {} as ArcTransactionService,
    agentRegistryService: {} as AgentRegistryService, jobService: { observe } as unknown as JobService });
  apps.push(app);
  return { app, begin, observe, logs };
}

describe("M06 job evidence route", () => {
  it("reports cumulative capability truth and serves one strict bounded envelope", async () => {
    const { app, begin, observe } = setup();
    const capabilities = await app.inject({ method: "GET", url: "/v1/private/capabilities",
      headers: { origin, "x-openarc-client": "browser-v1" } });
    expect(capabilities.json().data).toMatchObject({ capabilityVersion: "openarc.capabilities.m06.v1",
      enabledConnectors: ["arc_primary_rpc", "erc8004_registries", "erc8183_reference"],
      features: { arcObservation: true, agentRegistry: true, agentJobs: true }, sourceRevision: ARC_ERC8183.sourceRevision });
    const response = await app.inject({ method: "POST", url: "/v1/private/arc/job-evidence",
      headers, payload: { network: ARC_TESTNET.caip2, jobId: "1" } });
    expect(response.statusCode).toBe(200);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.json().data).toEqual(evidence);
    expect(observe).toHaveBeenCalledOnce();
    expect(begin).toHaveBeenCalledWith("arc_rpc", "agent_job", "192.0.2.50", expect.any(AbortSignal));
  });

  it("rejects contract overrides, malformed IDs, and browser credentials before execution", async () => {
    const { app, begin, observe } = setup();
    for (const payload of [
      { network: ARC_TESTNET.caip2, jobId: "01" },
      { network: ARC_TESTNET.caip2, jobId: "garbage" },
      { network: ARC_TESTNET.caip2, jobId: "1.0" },
      { network: ARC_TESTNET.caip2, jobId: "1", registryAddress: observer },
      { network: ARC_TESTNET.caip2, jobId: "1", feedbackQuery: { clientAddress: observer } },
    ]) {
      const response = await app.inject({ method: "POST", url: "/v1/private/arc/job-evidence",
        headers, payload });
      expect(response.statusCode).toBe(400);
      expect(response.body).not.toContain(observer);
    }
    expect(begin).not.toHaveBeenCalled();
    expect(observe).not.toHaveBeenCalled();
  });

  it("keeps jobs disabled by default and requires cumulative bounded configuration", async () => {
    const config = loadConfig({ NODE_ENV: "test" });
    const app = createApp({ config }); apps.push(app);
    expect((await app.inject({ method: "POST", url: "/v1/private/arc/job-evidence", payload: {} })).json().error.code)
      .toBe("FEATURE_DISABLED");
    expect(() => loadConfig({ NODE_ENV: "test", AGENT_JOBS_ENABLED: "true" })).toThrow();
    expect(() => loadConfig({ NODE_ENV: "test", API_BOUNDARY_ENABLED: "true", ARC_OBSERVATION_ENABLED: "true",
      AGENT_REGISTRY_ENABLED: "true", AGENT_JOBS_ENABLED: "true", REDIS_URL: "redis://127.0.0.1:6379",
      ABUSE_LIMIT_SECRET: "synthetic_abuse_secret_for_m06_tests", SOURCE_PROXY_SECRET: proxySecret,
      SOURCE_MAX_SUBCALLS: "15" })).toThrow();
  });

  it("rejects untrusted requests before spending a source unit and omits identifiers from logs", async () => {
    const { app, begin, logs } = setup();
    for (const extraHeaders of [{ cookie: "PRIVATE_JOB_CANARY" }, { authorization: "PRIVATE_JOB_CANARY" },
      { origin: "https://evil.example.test" }, { "x-openarc-proxy-secret": "not-trusted" }]) {
      const response = await app.inject({ method: "POST", url: "/v1/private/arc/job-evidence",
        headers: { ...headers, ...extraHeaders }, payload: { network: ARC_TESTNET.caip2, jobId: "1" } });
      expect(response.statusCode).toBeGreaterThanOrEqual(400);
      expect(response.body).not.toContain("PRIVATE_JOB_CANARY");
    }
    expect(begin).not.toHaveBeenCalled();
    expect(JSON.stringify(logs)).not.toContain("PRIVATE_JOB_CANARY");
    expect(logs.every((entry) => entry.route === "agent_job")).toBe(true);
  });
});
