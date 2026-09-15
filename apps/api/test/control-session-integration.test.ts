import {
  SESSION_CAPABILITIES_PATH,
  SESSION_ROUTES,
  SessionCapabilitiesSuccessEnvelopeSchema,
} from "@openarc/shared";
import { afterEach, describe, expect, it, vi } from "vitest";

import { createApp, type CompletionLog } from "../src/app.js";
import type { AuthService } from "../src/auth/service.js";
import { loadConfig } from "../src/config.js";
import { CommerceSessionRateLimiter } from "../src/control/session-rate-limiter.js";
import { CommerceSessionService } from "../src/control/session-service.js";
import type {
  AgentSessionReadPort,
  CommerceSessionAuthPort,
  CommerceSessionStorePort,
} from "../src/control/session-ports.js";

/**
 * Integration coverage for the REAL `createApp` over real Fastify for the
 * commerce-session family. Auth/store/credential ports are HONESTLY MOCKED; no
 * PostgreSQL, network, Redis or server is claimed. This suite proves the exact
 * seven-route mount when enabled, fixed missing-service startup, disabled-family
 * fixed v2 no-store 404 across browser and agent roots, the 16KiB body/response
 * bound, coarse `tenant` metrics labels without raw identifiers, and the root
 * readiness wiring (no calls while disabled).
 */

const ORIGIN = "http://localhost:5183";
const BUILD_SHA = "0123456789abcdef0123456789abcdef01234567";
const AUTH_URL = "postgres://openarc_auth_app:x@127.0.0.1:5432/openarc_auth_test";
const TENANT_URL = "postgres://openarc_tenant_app:y@127.0.0.1:5432/openarc_auth_test";
const SECRET = "synthetic_auth_secret_for_session_integration_0123456789";
const ORG = "openarc:org:11111111-1111-4111-8111-111111111111";
const SESSION = "22222222-2222-4222-8222-222222222222";
const MUTATION = "33333333-3333-4333-8333-333333333333";
const AGENT_TOKEN = `oas_ag_${"a".repeat(42)}A`;

const AUTH: CommerceSessionAuthPort = {
  verifyCsrf: () => "binding",
  beginTenantRead: async () => ({ sessionHash: "a".repeat(64), accountId: ORG }),
  finishTenantRead: async () => undefined,
};

const STORE: CommerceSessionStorePort = {
  issueCommerceSession: async () => {
    throw new Error("unused");
  },
  exchangeCommerceSession: async () => {
    throw new Error("unused");
  },
  revokeCommerceSession: async () => {
    throw new Error("unused");
  },
  getCommerceSessionStatus: async () => ({ organizationId: ORG, item: null }),
  listCommerceSessions: async () => ({ items: [], nextCursor: null }),
  getHumanCommerceSessionMutationStatus: async () => ({ status: "not_found" }),
  getAgentCommerceSessionMutationStatus: async () => ({ status: "not_found" }),
};

const AGENT_SESSIONS: AgentSessionReadPort = {
  getAgentSession: async () => {
    throw new Error("unused");
  },
};

function makeService(): CommerceSessionService {
  return new CommerceSessionService({
    auth: AUTH,
    store: STORE,
    agentSessions: AGENT_SESSIONS,
    limits: new CommerceSessionRateLimiter({
      secret: SECRET,
      store: { consume: async () => ({ allowed: true }) },
    }),
  });
}

type App = ReturnType<typeof createApp>;
const apps: App[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map(async (app) => app.close()));
});

function build(options: {
  readonly enabled: boolean;
  readonly omitService?: boolean;
  readonly commerceSessionReady?: () => Promise<boolean>;
  readonly logs?: CompletionLog[];
}): App {
  const config = loadConfig({
    NODE_ENV: "test",
    APP_ORIGIN: ORIGIN,
    COMMIT_SHA: BUILD_SHA,
    ...(options.enabled
      ? {
          AUTH_ENABLED: "true",
          AUTH_DATABASE_URL: AUTH_URL,
          AUTH_SECRET: SECRET,
          AUTH_RP_ID: "localhost",
          TENANT_DATABASE_URL: TENANT_URL,
          COMMERCE_SESSIONS_ENABLED: "true",
        }
      : {}),
  });
  const app = createApp({
    config,
    logger: false,
    ...(options.logs !== undefined
      ? { logSink: (entry: CompletionLog) => options.logs!.push(entry) }
      : {}),
    ...(config.AUTH_ENABLED ? { authService: AUTH as unknown as AuthService } : {}),
    ...(config.AUTH_ENABLED ? { authReady: async () => true } : {}),
    ...(config.COMMERCE_SESSIONS_ENABLED && !options.omitService
      ? { commerceSessionService: makeService() }
      : {}),
    ...(options.commerceSessionReady !== undefined
      ? { commerceSessionReady: options.commerceSessionReady }
      : {}),
  });
  apps.push(app);
  return app;
}

function concretePath(path: string): string {
  return path
    .replace(":organizationId", ORG)
    .replace(":sessionId", SESSION)
    .replace(":mutationId", MUTATION);
}

function registeredRoutes(app: App): Set<string> {
  const actual = new Set<string>();
  for (const route of SESSION_ROUTES) {
    if (app.hasRoute({ method: route.method, url: route.path })) {
      actual.add(`${route.method} ${route.path}`);
    }
  }
  return actual;
}

describe("commerce session family mount", () => {
  it("registers exactly the seven frozen routes when enabled", () => {
    const app = build({ enabled: true });
    expect(SESSION_ROUTES).toHaveLength(7);
    for (const route of SESSION_ROUTES) {
      expect(
        app.hasRoute({ method: route.method, url: route.path }),
        `${route.method} ${route.path}`,
      ).toBe(true);
    }
    expect(registeredRoutes(app).size).toBe(7);
  });

  it("registers NO commerce-session route when the flag is off", () => {
    const app = build({ enabled: false });
    expect(registeredRoutes(app).size).toBe(0);
  });

  it("fails startup closed when the family is enabled without its service", () => {
    expect(() => build({ enabled: true, omitService: true })).toThrow(
      "Commerce session dependencies are unavailable",
    );
  });
});

describe("disabled family", () => {
  it("returns a fixed v2 no-store 404 for every route while disabled", async () => {
    const app = build({ enabled: false });
    for (const route of SESSION_ROUTES) {
      const response = await app.inject({
        method: route.method,
        url: concretePath(route.path),
      });
      expect(response.statusCode, `${route.method} ${route.path}`).toBe(404);
      expect(response.headers["cache-control"], route.path).toBe("no-store");
      expect(response.json().meta.schemaVersion, route.path).toBe(
        "openarc.api.v2",
      );
      expect(response.json().error.code, route.path).toBe("FEATURE_DISABLED");
    }
  });

  it("keeps lookalike agent prefixes on the legacy envelope", async () => {
    const app = build({ enabled: false });
    for (const url of [
      "/v2/agent/commerce-sessionsXYZ",
      "/v2/agentXYZ",
    ]) {
      const response = await app.inject({ method: "GET", url });
      expect(response.statusCode, url).toBe(404);
      expect(response.json().meta.schemaVersion, url).toBe("openarc.api.v1");
    }
  });
});

describe("protected session route host behavior", () => {
  const BASE = `/v2/control/organizations/${ORG}/commerce-sessions`;

  it("sets no-store and never a cookie or CORS grant when enabled", async () => {
    const app = build({ enabled: true });
    const response = await app.inject({
      method: "GET",
      url: BASE,
      headers: {
        origin: ORIGIN,
        "x-openarc-client": "browser-v1",
        cookie: "openarc_session=abc",
      },
    });
    expect([200, 401]).toContain(response.statusCode);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.headers["pragma"]).toBe("no-cache");
    expect(response.headers["set-cookie"]).toBeUndefined();
    expect(response.headers["access-control-allow-origin"]).toBeUndefined();
    expect(response.headers["x-openarc-request-id"]).toBeDefined();
  });

  it("enforces the bounded 16KiB body limit with a fixed v2 envelope", async () => {
    const app = build({ enabled: true });
    const response = await app.inject({
      method: "POST",
      url: BASE,
      headers: {
        origin: ORIGIN,
        "x-openarc-client": "browser-v1",
        cookie: "openarc_session=abc",
        "content-type": "application/json",
        "idempotency-key": `${"a".repeat(42)}A`,
        "x-openarc-csrf": "csrf",
      },
      payload: JSON.stringify({ mutationId: MUTATION, subjectAgentId: ORG, policyId: ORG, blob: "x".repeat(20 * 1024) }),
    });
    expect(response.statusCode).toBe(413);
    expect(response.json().meta.schemaVersion).toBe("openarc.api.v2");
    expect(response.headers["cache-control"]).toBe("no-store");
  });

  it("labels browser and agent session paths with the coarse tenant class only", async () => {
    const logs: CompletionLog[] = [];
    const app = build({ enabled: true, logs });
    await app.inject({
      method: "GET",
      url: BASE,
      headers: {
        origin: ORIGIN,
        "x-openarc-client": "browser-v1",
        cookie: "openarc_session=abc",
      },
    });
    await app.inject({
      method: "GET",
      url: `/v2/agent/commerce-session-mutations/${MUTATION}`,
      headers: { authorization: `Bearer ${AGENT_TOKEN}` },
    });
    expect(logs.map((entry) => entry.route)).toEqual(["tenant", "tenant"]);
    for (const entry of logs) {
      const serialized = JSON.stringify(entry);
      expect(serialized).not.toContain(ORG);
      expect(serialized).not.toContain(SESSION);
      expect(serialized).not.toContain(MUTATION);
      expect(serialized).not.toContain(AGENT_TOKEN);
      expect(entry.route).not.toContain("/v2/");
    }
  });
});

describe("root readiness wiring", () => {
  it("fails session readiness closed when the callback is down", async () => {
    const app = build({ enabled: true, commerceSessionReady: async () => false });
    const response = await app.inject({ method: "GET", url: "/readyz" });
    expect(response.statusCode).toBe(503);
    expect(response.json().checks.commerceSessionDatabase).toBe("down");
    expect(response.json().checks.authDatabase).toBe("up");
  });

  it("reports session readiness up when the callback is healthy", async () => {
    const app = build({ enabled: true, commerceSessionReady: async () => true });
    const response = await app.inject({ method: "GET", url: "/readyz" });
    expect(response.statusCode).toBe(200);
    expect(response.json().checks.commerceSessionDatabase).toBe("up");
  });

  it("never invokes session readiness when the flag is off", async () => {
    let calls = 0;
    const app = build({
      enabled: false,
      commerceSessionReady: async () => {
        calls += 1;
        return true;
      },
    });
    const response = await app.inject({ method: "GET", url: "/readyz" });
    expect(response.statusCode).toBe(200);
    expect(response.json().checks).not.toHaveProperty("commerceSessionDatabase");
    expect(calls).toBe(0);
  });
});

describe("session capability surface through createApp", () => {
  it("labels the capability path as the coarse capabilities class, not not_found", async () => {
    const logs: CompletionLog[] = [];
    const app = build({ enabled: false, logs });
    const response = await app.inject({
      method: "GET",
      url: SESSION_CAPABILITIES_PATH,
    });
    expect(response.statusCode).toBe(200);
    const entry = logs.at(-1);
    expect(entry?.route).toBe("capabilities");
    expect(entry?.route).not.toBe("not_found");
    for (const value of logs) {
      expect(JSON.stringify(value)).not.toContain(SESSION_CAPABILITIES_PATH);
      expect(value.route).not.toContain("/v2/");
    }
  });

  it("maps an unexpected non-AuthApiError handler failure to the fixed v2 envelope", async () => {
    const app = build({ enabled: false });
    const canary = "PRIVATE_CAPABILITY_CANARY";
    // HONESTLY FORCED: the real handler otherwise only raises fixed
    // AuthApiError values, so an unexpected internal failure is injected at the
    // exact shared response-schema seam. This proves the app classifies the
    // session capability path as a v2 surface instead of falling back to the
    // legacy v1 error normalization.
    const parseSpy = vi
      .spyOn(SessionCapabilitiesSuccessEnvelopeSchema, "parse")
      .mockImplementationOnce(() => {
        throw new Error(canary);
      });
    try {
      const response = await app.inject({
        method: "GET",
        url: SESSION_CAPABILITIES_PATH,
      });
      expect(response.statusCode).toBe(500);
      expect(response.json().meta.schemaVersion).toBe("openarc.api.v2");
      expect(response.json().error.code).toBe("INTERNAL_ERROR");
      expect(response.body).not.toContain(canary);
      expect(response.headers["cache-control"]).toBe("no-store");
    } finally {
      parseSpy.mockRestore();
    }
  });
});
