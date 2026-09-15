import { ApiErrorEnvelopeSchema, CAPABILITIES_PATH, CapabilitiesEnvelopeSchema } from "@openarc/shared";
import { afterEach, describe, expect, it } from "vitest";

import { createApp, type CompletionLog } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { ApiBoundaryError } from "../src/http/errors.js";
import { AggregateMetrics } from "../src/ops/metrics.js";

const origin = "https://app.example.test";
const metricsToken = "synthetic_metrics_token_for_m03_tests";
const headers = { origin, "x-openarc-client": "browser-v1" };
const apps: ReturnType<typeof createApp>[] = [];
afterEach(async () => { await Promise.all(apps.splice(0).map((app) => app.close())); });
function setup(extra: NodeJS.ProcessEnv = {}, logSink?: (entry: Readonly<CompletionLog>) => void) {
  const app = createApp({ config: loadConfig({ NODE_ENV: "test", APP_ORIGIN: origin,
    COMMIT_SHA: "test-sha", API_BOUNDARY_ENABLED: "true", METRICS_TOKEN: metricsToken, ...extra }),
    logger: false, ...(logSink ? { logSink } : {}) });
  apps.push(app);
  return app;
}

describe("M03 configuration guards", () => {
  it("requires exact production origin, SHA, and a metrics secret", () => {
    const valid = { NODE_ENV: "production", APP_ORIGIN: origin, COMMIT_SHA: "a".repeat(40), METRICS_TOKEN: metricsToken };
    expect(loadConfig(valid).API_BOUNDARY_ENABLED).toBe(false);
    for (const mutation of [
      { APP_ORIGIN: undefined }, { APP_ORIGIN: "http://localhost:5183" }, { APP_ORIGIN: `${origin}/` },
      { COMMIT_SHA: "local" }, { METRICS_TOKEN: undefined }, { METRICS_TOKEN: "short" },
      { ABUSE_LIMIT_SECRET: metricsToken }, { NODE_ENV: "unknown" }, { API_BOUNDARY_ENABLED: "yes" },
      { ARC_TESTNET_RPC_URL: "https://evil.example.test" }, { SOURCE_MAX_SUBCALLS: "17" },
      { SOURCE_TIMEOUT_MS: "10001" }, { GLOBAL_SOURCE_UNITS_PER_DAY: "0" },
    ]) expect(() => loadConfig({ ...valid, ...mutation })).toThrow();
  });

  it("enables cumulative M04/M05 sources only with their exact boundary and infrastructure", () => {
    expect(loadConfig({ NODE_ENV: "test", API_BOUNDARY_ENABLED: "true", ARC_OBSERVATION_ENABLED: "true",
      REDIS_URL: "redis://127.0.0.1:6379", ABUSE_LIMIT_SECRET: "a".repeat(32),
      SOURCE_PROXY_SECRET: "b".repeat(32), METRICS_TOKEN: metricsToken }).ARC_OBSERVATION_ENABLED).toBe(true);
    for (const mutation of [
      { API_BOUNDARY_ENABLED: "false" }, { REDIS_URL: undefined }, { ABUSE_LIMIT_SECRET: undefined },
      { SOURCE_PROXY_SECRET: undefined }, { SOURCE_PROXY_SECRET: "a".repeat(32) }, { SOURCE_MAX_SUBCALLS: "4" },
    ]) expect(() => loadConfig({ NODE_ENV: "test", API_BOUNDARY_ENABLED: "true",
      ARC_OBSERVATION_ENABLED: "true", REDIS_URL: "redis://127.0.0.1:6379",
      ABUSE_LIMIT_SECRET: "a".repeat(32), SOURCE_PROXY_SECRET: "b".repeat(32),
      METRICS_TOKEN: metricsToken, ...mutation })).toThrow();
    expect(loadConfig({ NODE_ENV: "test", API_BOUNDARY_ENABLED: "true", ARC_OBSERVATION_ENABLED: "true",
      AGENT_REGISTRY_ENABLED: "true", REDIS_URL: "redis://127.0.0.1:6379", ABUSE_LIMIT_SECRET: "a".repeat(32),
      SOURCE_PROXY_SECRET: "b".repeat(32), METRICS_TOKEN: metricsToken, SOURCE_MAX_SUBCALLS: "16" })
      .AGENT_REGISTRY_ENABLED).toBe(true);
    for (const mutation of [
      { ARC_OBSERVATION_ENABLED: "false" }, { SOURCE_MAX_SUBCALLS: "15" }, { API_BOUNDARY_ENABLED: "false" },
    ]) expect(() => loadConfig({ NODE_ENV: "test", API_BOUNDARY_ENABLED: "true", ARC_OBSERVATION_ENABLED: "true",
      AGENT_REGISTRY_ENABLED: "true", REDIS_URL: "redis://127.0.0.1:6379", ABUSE_LIMIT_SECRET: "a".repeat(32),
      SOURCE_PROXY_SECRET: "b".repeat(32), METRICS_TOKEN: metricsToken, SOURCE_MAX_SUBCALLS: "16", ...mutation })).toThrow();
    for (const flag of ["AGENT_JOBS_ENABLED", "GATEWAY_EVIDENCE_ENABLED"]) {
      expect(() => loadConfig({ NODE_ENV: "test", [flag]: "true",
        REDIS_URL: "redis://127.0.0.1:6379", ABUSE_LIMIT_SECRET: "a".repeat(32), METRICS_TOKEN: metricsToken })).toThrow();
    }
  });
});

describe("M03 credentialless browser boundary", () => {
  it("returns only source-disabled validated metadata and no-store headers", async () => {
    const response = await setup().inject({ method: "GET", url: CAPABILITIES_PATH, headers });
    expect(response.statusCode).toBe(200);
    expect(CapabilitiesEnvelopeSchema.safeParse(response.json()).success).toBe(true);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.headers.pragma).toBe("no-cache");
    expect(response.headers["referrer-policy"]).toBe("no-referrer");
    expect(response.headers["x-content-type-options"]).toBe("nosniff");
    expect(response.headers["access-control-allow-origin"]).toBe(origin);
    expect(response.headers["access-control-allow-credentials"]).toBeUndefined();
    expect(response.headers["x-openarc-request-id"]).toBe(response.json().meta.requestId);
    expect(response.json().data.enabledConnectors).toEqual([]);
    expect(response.json().data.capabilityVersion).toBe("openarc.capabilities.m04.v1");
  });

  it("handles the same-origin GET missing-Origin case without granting cross-site access", async () => {
    const app = setup();
    const response = await app.inject({ method: "GET", url: CAPABILITIES_PATH,
      headers: { "x-openarc-client": "browser-v1", "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty" } });
    expect(response.statusCode).toBe(200);
    for (const mutation of [
      {}, { "x-openarc-client": "browser-v1" }, { origin: "null", "x-openarc-client": "browser-v1" },
      { origin: "https://evil.example.test", "x-openarc-client": "browser-v1" },
      { ...headers, "sec-fetch-site": "same-site" }, { ...headers, "sec-fetch-site": "cross-site" },
      { ...headers, "sec-fetch-mode": "navigate" }, { ...headers, "sec-fetch-dest": "iframe" },
      { ...headers, origin: [origin, "https://evil.example.test"] },
    ]) {
      const rejected = await app.inject({ method: "GET", url: CAPABILITIES_PATH, headers: mutation });
      expect(rejected.statusCode).toBe(403);
      expect(rejected.headers["cache-control"]).toBe("no-store");
      expect(rejected.headers["access-control-allow-origin"]).toBeUndefined();
      expect(ApiErrorEnvelopeSchema.safeParse(rejected.json()).success).toBe(true);
    }
  });

  it("rejects credentials, queries, bodies, and method substitutions", async () => {
    const app = setup();
    for (const field of ["cookie", "authorization", "proxy-authorization"]) {
      const response = await app.inject({ method: "GET", url: CAPABILITIES_PATH, headers: { ...headers, [field]: "PRIVATE_CANARY" } });
      expect(response.statusCode).toBe(400);
      expect(response.json().error.code).toBe("CREDENTIALS_NOT_ALLOWED");
      expect(response.body).not.toContain("PRIVATE_CANARY");
    }
    expect((await app.inject({ method: "GET", url: `${CAPABILITIES_PATH}?private=CANARY`, headers })).statusCode).toBe(400);
    expect((await app.inject({ method: "GET", url: CAPABILITIES_PATH, headers, payload: "[]" })).statusCode).toBe(400);
    for (const method of ["HEAD", "POST", "PUT", "PATCH", "DELETE"] as const) {
      const response = await app.inject({ method, url: CAPABILITIES_PATH, headers });
      expect(response.statusCode).toBe(405);
      expect(response.headers["cache-control"]).toBe("no-store");
    }
  });

  it("handles preflight only for the exact origin, method, and requested headers", async () => {
    const app = setup();
    const valid = { origin, "access-control-request-method": "GET", "access-control-request-headers": "x-openarc-client" };
    const response = await app.inject({ method: "OPTIONS", url: CAPABILITIES_PATH, headers: valid });
    expect(response.statusCode).toBe(204);
    expect(response.headers["access-control-allow-origin"]).toBe(origin);
    expect(response.headers["access-control-max-age"]).toBeUndefined();
    expect(response.headers["access-control-allow-credentials"]).toBeUndefined();
    expect(response.headers["cache-control"]).toBe("no-store");
    for (const mutation of [
      { origin: "null" }, { "access-control-request-method": "POST" },
      { "access-control-request-headers": "x-openarc-client,authorization" },
      { "access-control-request-headers": "x-openarc-client,x-openarc-client" },
      { "access-control-request-headers": "" },
    ]) expect((await app.inject({ method: "OPTIONS", url: CAPABILITIES_PATH, headers: { ...valid, ...mutation } })).statusCode).toBe(403);
  });

  it("keeps disabled paths disabled before parsing for every browser method", async () => {
    const app = setup({ API_BOUNDARY_ENABLED: "false" });
    for (const path of [CAPABILITIES_PATH, "/v1/private/arc/account-snapshot", "/v1/private/arc/transaction-evidence",
      "/v1/private/arc/agent-registry-evidence", "/v1/private/arc/job-evidence", "/v1/private/gateway/transfer-evidence"]) {
      for (const method of ["GET", "HEAD", "OPTIONS", "POST"] as const) {
        const response = await app.inject({ method, url: path, headers: { "content-type": "application/json" },
          ...(method === "POST" ? { payload: "{malformed PRIVATE_CANARY" } : {}) });
        expect(response.statusCode).toBe(503);
        expect(response.headers["cache-control"]).toBe("no-store");
        expect(response.body).not.toContain("PRIVATE_CANARY");
      }
    }
  });
});

describe("M03 logs and operations", () => {
  it("never echoes private parser/errors/URLs/credentials into responses, logs, or metrics", async () => {
    const logs: Readonly<CompletionLog>[] = [];
    const app = setup({}, (entry) => logs.push(entry));
    app.post("/test/parser", { bodyLimit: 32 }, async () => { throw new Error("PRIVATE_CANARY"); });
    app.post("/test/retry", async () => { throw new ApiBoundaryError("RATE_LIMITED", 10); });
    for (const request of [
      { method: "POST" as const, url: "/test/parser", headers: { "content-type": "application/json" }, payload: "{PRIVATE_CANARY" },
      { method: "POST" as const, url: "/test/parser", headers: { "content-type": "application/json" }, payload: `{"private":"${"PRIVATE_CANARY".repeat(20)}"}` },
      { method: "POST" as const, url: "/test/parser", headers: { "content-type": "application/json" }, payload: "{}" },
      { method: "GET" as const, url: "/unknown/PRIVATE_CANARY?private=PRIVATE_CANARY", headers: { cookie: "PRIVATE_CANARY", "x-openarc-request-id": "PRIVATE_CANARY" } },
    ]) {
      const response = await app.inject(request);
      expect(response.statusCode).toBeGreaterThanOrEqual(400);
      expect(ApiErrorEnvelopeSchema.safeParse(response.json()).success).toBe(true);
      expect(response.body).not.toContain("PRIVATE_CANARY");
      expect(response.headers["x-openarc-request-id"]).not.toBe("PRIVATE_CANARY");
    }
    const retry = await app.inject({ method: "POST", url: "/test/retry" });
    expect(retry.statusCode).toBe(429);
    expect(retry.headers["retry-after"]).toBe("10");
    const metrics = await app.inject({ method: "GET", url: "/metrics", headers: { authorization: `Bearer ${metricsToken}` } });
    expect(metrics.statusCode).toBe(200);
    expect(metrics.body).toContain("openarc_http_requests_total");
    expect(metrics.body).not.toContain("PRIVATE_CANARY");
    expect(metrics.body).not.toContain(metricsToken);
    expect(JSON.stringify(logs)).not.toContain("PRIVATE_CANARY");
    expect(JSON.stringify(logs)).not.toContain(metricsToken);
    expect(new Set(logs.map((entry) => entry.requestId)).size).toBe(logs.length);
    expect(logs.every((entry) => Object.keys(entry).length === 7)).toBe(true);
  });

  it("keeps failure and source metrics on closed label enums", async () => {
    const metrics = new AggregateMetrics();
    metrics.recordFailure("capabilities", "INVALID_ORIGIN");
    metrics.recordBudget("arc_rpc", "attempt_reserved");
    metrics.recordBudget("arc_rpc", "dispatched");
    metrics.recordBudget("private_canary" as never, "private_event" as never);
    const app = createApp({ config: loadConfig({ NODE_ENV: "test", APP_ORIGIN: origin,
      API_BOUNDARY_ENABLED: "true", METRICS_TOKEN: metricsToken }), logger: false, metrics });
    apps.push(app);
    const response = await app.inject({ method: "GET", url: "/metrics", headers: { authorization: `Bearer ${metricsToken}` } });
    expect(response.body).toContain('openarc_api_failures_total{route="capabilities",code="INVALID_ORIGIN"} 1');
    expect(response.body).toContain('openarc_source_events_total{source="arc_rpc",event="attempt_reserved"} 1');
    expect(response.body).toContain('openarc_source_events_total{source="arc_rpc",event="dispatched"} 1');
    expect(response.body).not.toContain("private_canary");
    expect(response.body).not.toContain("private_event");
  });

  it("requires metrics authentication and reports Redis not required, not healthy by assumption", async () => {
    const app = setup();
    for (const authorization of [undefined, "Bearer wrong", `Bearer ${"x".repeat(33)}`]) {
      const response = await app.inject({ method: "GET", url: "/metrics", headers: authorization ? { authorization } : {} });
      expect(response.statusCode).toBe(401);
      expect(response.headers["cache-control"]).toBe("no-store");
    }
    const readiness = await app.inject({ method: "GET", url: "/readyz" });
    expect(readiness.json().checks).toMatchObject({ redis: "not_required", sourceRoutes: "disabled" });
  });
});
