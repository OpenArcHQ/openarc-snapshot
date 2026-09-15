import { connect } from "node:net";

import { afterEach, describe, expect, it } from "vitest";

import {
  API_CLIENT_HEADER,
  CONTROL_CAPABILITIES_PATH,
  CONTROL_CAPABILITY_DEPENDENCIES,
  CONTROL_CAPABILITY_FAMILY_ORDER,
  CONTROL_CAPABILITY_VERSION,
  CONTROL_ROUTES,
  ControlCapabilitiesSuccessEnvelopeSchema,
  type ControlCapabilityState,
} from "@openarc/shared";

import { createApp } from "../src/app.js";
import type { AuthService } from "../src/auth/service.js";
import { loadConfig } from "../src/config.js";
import { PolicyService } from "../src/control/service.js";
import { buildControlCapabilityManifest } from "../src/commerce/control-capabilities.js";
import type {
  ControlPolicyAuthPort,
  ControlPolicyStorePort,
} from "../src/control/ports.js";

/**
 * Focused unit/inject coverage for the public `GET
 * /v2/public/control-capabilities` surface. The auth/store seams are
 * HONESTLY MOCKED and readiness callbacks are SYNTHETIC: no PostgreSQL,
 * AuthService or network is required. This suite proves the exact shared
 * version/one-family/ten-route manifest, the flag-dependent state mapping with
 * zero readiness calls while off, the single in-flight probe batch with a
 * fail-closed deadline, and the strict credentialless transport including the
 * exact eight opaque Railway exceptions.
 */

const ORIGIN = "http://localhost:5183";
const BUILD_SHA = "0123456789abcdef0123456789abcdef01234567";
const SECRET_CANARY = "SECRET_CANARY_DO_NOT_ECHO";
const AUTH_URL = "postgres://openarc_auth_app:x@127.0.0.1:5432/openarc_auth_test";
const TENANT_URL = "postgres://openarc_tenant_app:y@127.0.0.1:5432/openarc_auth_test";

const AUTH: ControlPolicyAuthPort = {
  verifyCsrf: () => "binding",
  beginTenantRead: async () => ({
    sessionHash: "a".repeat(64),
    accountId: "openarc:account:11111111-1111-4111-8111-111111111111",
  }),
  finishTenantRead: async () => undefined,
};

const STORE: ControlPolicyStorePort = {
  createPolicy: async () => {
    throw new Error("unused");
  },
  appendPolicyRevision: async () => {
    throw new Error("unused");
  },
  transitionPolicy: async () => {
    throw new Error("unused");
  },
  getPolicyRoot: async () => null,
  listPolicyRoots: async () => ({ items: [], nextCursor: null }),
  getPolicyRevision: async () => null,
  listPolicyRevisions: async () => ({ items: [], nextCursor: null }),
  getPolicyMutationStatus: async () => ({ status: "not_found" }),
};

type App = ReturnType<typeof createApp>;

const apps: App[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map(async (app) => app.close()));
});

interface HarnessOptions {
  readonly policyManagementEnabled?: boolean;
  readonly authEnabled?: boolean;
  readonly readiness?: {
    authReady?: () => Promise<boolean>;
    policyReady?: () => Promise<boolean>;
  };
  readonly maxResponseBytes?: number;
}

function harness(options: HarnessOptions = {}) {
  const policyManagementEnabled = options.policyManagementEnabled ?? false;
  const authEnabled = options.authEnabled ?? policyManagementEnabled;
  const config = loadConfig({
    NODE_ENV: "test",
    APP_ORIGIN: ORIGIN,
    COMMIT_SHA: BUILD_SHA,
    POLICY_MANAGEMENT_ENABLED: policyManagementEnabled ? "true" : "false",
    ...(authEnabled
      ? {
          AUTH_ENABLED: "true",
          AUTH_DATABASE_URL: AUTH_URL,
          AUTH_SECRET: "synthetic_auth_secret_for_control_capabilities_012",
          AUTH_RP_ID: "localhost",
        }
      : {}),
    ...(policyManagementEnabled ? { TENANT_DATABASE_URL: TENANT_URL } : {}),
  });
  const app = createApp({
    config,
    logger: false,
    ...(config.AUTH_ENABLED ? { authService: {} as AuthService } : {}),
    ...(config.POLICY_MANAGEMENT_ENABLED
      ? { policyManagementService: new PolicyService({ auth: AUTH, store: STORE }) }
      : {}),
    ...(options.readiness?.authReady !== undefined
      ? { authReady: options.readiness.authReady }
      : {}),
    ...(options.readiness?.policyReady !== undefined
      ? { policyReady: options.readiness.policyReady }
      : {}),
    ...(options.maxResponseBytes !== undefined
      ? { tenantMaxResponseBytes: options.maxResponseBytes }
      : {}),
  });
  apps.push(app);
  return app;
}

function stateOf(body: { data: { capabilities: ReadonlyArray<{ state: string }> } }): ControlCapabilityState {
  return body.data.capabilities[0]?.state as ControlCapabilityState;
}

describe("public control capability manifest", () => {
  it("serves the exact shared version, one family and ten routes with the flag off", async () => {
    let calls = 0;
    const app = harness({
      readiness: {
        authReady: async () => {
          calls += 1;
          return true;
        },
        policyReady: async () => {
          calls += 1;
          return true;
        },
      },
    });
    const response = await app.inject({
      method: "GET",
      url: CONTROL_CAPABILITIES_PATH,
    });
    expect(response.statusCode).toBe(200);
    expect(response.headers["set-cookie"]).toBeUndefined();
    expect(response.headers["access-control-allow-origin"]).toBeUndefined();

    const parsed = ControlCapabilitiesSuccessEnvelopeSchema.parse(
      response.json(),
    );
    expect(parsed.data.capabilityVersion).toBe(CONTROL_CAPABILITY_VERSION);
    expect(parsed.data.capabilities).toHaveLength(1);
    expect(parsed.data.capabilities[0]).toMatchObject({
      family: "policy_management",
      audience: "browser",
      state: "built_disabled",
      dependencies: ["auth", "tenantDatabase", "policyDatabase"],
    });
    expect(parsed.data.capabilities.map((entry) => entry.family)).toEqual([
      ...CONTROL_CAPABILITY_FAMILY_ORDER,
    ]);
    expect(parsed.data.capabilities[0]?.dependencies).toEqual([
      ...CONTROL_CAPABILITY_DEPENDENCIES.policy_management,
    ]);
    expect(parsed.data.routes).toHaveLength(10);
    expect(parsed.data.routes).toEqual(CONTROL_ROUTES);
    expect(parsed.meta.buildSha).toBe(BUILD_SHA);
    // Flag off: ZERO readiness callback calls.
    expect(calls).toBe(0);
    expect(response.body).not.toContain(SECRET_CANARY);
  });

  it("reports enabled only when the flag and every dependency are ready", async () => {
    const app = harness({
      policyManagementEnabled: true,
      readiness: {
        authReady: async () => true,
        policyReady: async () => true,
      },
    });
    const response = await app.inject({
      method: "GET",
      url: CONTROL_CAPABILITIES_PATH,
    });
    expect(response.statusCode).toBe(200);
    expect(stateOf(response.json())).toBe("enabled");
  });

  it("reports unavailable when auth or policy database is unready", async () => {
    const cases: ReadonlyArray<{
      readonly readiness: HarnessOptions["readiness"];
      readonly expected: ControlCapabilityState;
    }> = [
      {
        readiness: { authReady: async () => false, policyReady: async () => true },
        expected: "unavailable",
      },
      {
        readiness: { authReady: async () => true, policyReady: async () => false },
        expected: "unavailable",
      },
      {
        readiness: {},
        expected: "unavailable",
      },
    ];
    for (const entry of cases) {
      const app = harness({
        policyManagementEnabled: true,
        readiness: entry.readiness,
      });
      const response = await app.inject({
        method: "GET",
        url: CONTROL_CAPABILITIES_PATH,
      });
      expect(response.statusCode).toBe(200);
      expect(stateOf(response.json())).toBe(entry.expected);
    }
  });

  it("reports unavailable when the auth gating flag is missing while the own flag is on", async () => {
    // A config with the flag on but auth off is intentionally unreachable
    // through loadConfig (a fixed startup error), so the pure builder is
    // exercised directly with every dependency ready.
    const ready = {
      authReady: true,
      tenantDatabaseReady: true,
      policyDatabaseReady: true,
    };
    expect(
      buildControlCapabilityManifest(
        {
          policyManagementEnabled: true,
          authEnabled: false,
        },
        ready,
      ).capabilities[0]?.state,
    ).toBe("unavailable");
    // Tenant HTTP reads are NOT a prerequisite: with auth on and both labels
    // covered by the composed policy readiness the family is enabled.
    expect(
      buildControlCapabilityManifest(
        {
          policyManagementEnabled: true,
          authEnabled: true,
        },
        ready,
      ).capabilities[0]?.state,
    ).toBe("enabled");
  });

  it("never suggests execution, reservation or enforcement", async () => {
    const app = harness({ policyManagementEnabled: true });
    const response = await app.inject({
      method: "GET",
      url: CONTROL_CAPABILITIES_PATH,
    });
    const text = response.body.toLowerCase();
    for (const forbidden of ["execution", "reservation", "enforcement", "spend", "payment"]) {
      expect(text).not.toContain(forbidden);
    }
  });
});

describe("control capability readiness coordination", () => {
  it("invokes auth and policy once each, policy covering both DB labels, and shares a batch", async () => {
    const calls = { auth: 0, policy: 0 };
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const app = harness({
      policyManagementEnabled: true,
      readiness: {
        authReady: async () => {
          calls.auth += 1;
          await gate;
          return true;
        },
        policyReady: async () => {
          calls.policy += 1;
          await gate;
          return true;
        },
      },
    });
    const first = app.inject({ method: "GET", url: CONTROL_CAPABILITIES_PATH });
    const second = app.inject({ method: "GET", url: CONTROL_CAPABILITIES_PATH });
    await new Promise((resolve) => setImmediate(resolve));
    // The composed policy readiness covers BOTH tenantDatabase and
    // policyDatabase but is invoked exactly once.
    expect(calls).toEqual({ auth: 1, policy: 1 });
    release();
    const [a, b] = await Promise.all([first, second]);
    expect(stateOf(a.json())).toBe("enabled");
    expect(stateOf(b.json())).toBe("enabled");
  });

  it("fails closed after the deadline without a second overlapping batch", async () => {
    let calls = 0;
    let lateResolve!: (value: boolean) => void;
    const app = harness({
      policyManagementEnabled: true,
      readiness: {
        authReady: async () => true,
        policyReady: () => {
          calls += 1;
          return new Promise<boolean>((resolve) => {
            lateResolve = resolve;
          });
        },
      },
    });
    const started = Date.now();
    const response = await app.inject({
      method: "GET",
      url: CONTROL_CAPABILITIES_PATH,
    });
    expect(Date.now() - started).toBeGreaterThanOrEqual(1900);
    expect(response.statusCode).toBe(200);
    expect(stateOf(response.json())).toBe("unavailable");
    expect(calls).toBe(1);
    const concurrent = await app.inject({
      method: "GET",
      url: CONTROL_CAPABILITIES_PATH,
    });
    expect(calls).toBe(1);
    expect(stateOf(concurrent.json())).toBe("unavailable");
    lateResolve(true);
    await new Promise((resolve) => setImmediate(resolve));
  }, 15_000);

  it("does not echo a failing callback error", async () => {
    const app = harness({
      policyManagementEnabled: true,
      readiness: {
        authReady: async () => true,
        policyReady: async () => {
          throw new Error(SECRET_CANARY);
        },
      },
    });
    const response = await app.inject({
      method: "GET",
      url: CONTROL_CAPABILITIES_PATH,
    });
    expect(response.statusCode).toBe(200);
    expect(stateOf(response.json())).toBe("unavailable");
    expect(response.body).not.toContain(SECRET_CANARY);
  });
});

describe("public control capability transport", () => {
  it("accepts credentialless exact GET originless and with the browser marker", async () => {
    const app = harness();
    for (const headers of [
      {},
      { "x-openarc-client": API_CLIENT_HEADER },
      { origin: ORIGIN },
      { origin: ORIGIN, "x-openarc-client": API_CLIENT_HEADER },
    ]) {
      const response = await app.inject({
        method: "GET",
        url: CONTROL_CAPABILITIES_PATH,
        headers: headers as Record<string, string>,
      });
      expect(response.statusCode, JSON.stringify(headers)).toBe(200);
      expect(response.headers["set-cookie"]).toBeUndefined();
      expect(response.headers["access-control-allow-origin"]).toBeUndefined();
    }
  });

  it("rejects cookies, credentials, CSRF, idempotency and unknown client metadata", async () => {
    const app = harness();
    const forbidden: Record<string, string>[] = [
      { cookie: "openarc_session=abc" },
      { authorization: "Bearer x" },
      { "proxy-authorization": "Basic x" },
      { "x-openarc-csrf": "t" },
      { "idempotency-key": "k" },
      { "x-openarc-client": "other" },
      { "x-unknown-client": "x" },
    ];
    for (const headers of forbidden) {
      const response = await app.inject({
        method: "GET",
        url: CONTROL_CAPABILITIES_PATH,
        headers: headers as Record<string, string>,
      });
      expect(response.statusCode, JSON.stringify(headers)).toBe(400);
      expect(response.headers["set-cookie"]).toBeUndefined();
      expect(response.headers["access-control-allow-origin"]).toBeUndefined();
    }
  });

  it("returns a fixed v2 INVALID_ORIGIN envelope for a cross origin", async () => {
    const app = harness();
    const response = await app.inject({
      method: "GET",
      url: CONTROL_CAPABILITIES_PATH,
      headers: { origin: "https://evil.example" },
    });
    expect(response.statusCode).toBe(403);
    expect(response.json().error.code).toBe("INVALID_ORIGIN");
    expect(response.json().meta.schemaVersion).toBe("openarc.api.v2");
    expect(response.headers["access-control-allow-origin"]).toBeUndefined();
    expect(response.headers["set-cookie"]).toBeUndefined();
  });

  it("rejects wrong methods and bodies with a fixed v2 INVALID_REQUEST", async () => {
    const app = harness();
    for (const method of ["POST", "PUT", "DELETE", "PATCH"] as const) {
      const response = await app.inject({
        method,
        url: CONTROL_CAPABILITIES_PATH,
        payload: {},
      });
      expect(response.statusCode, method).toBe(405);
      expect(response.json().meta.schemaVersion, method).toBe("openarc.api.v2");
      expect(response.json().error.code, method).toBe("INVALID_REQUEST");
    }
  });

  it("rejects any query including a bare ? and oversized URLs with no raw echo", async () => {
    const app = harness();
    const queried = await app.inject({
      method: "GET",
      url: `${CONTROL_CAPABILITIES_PATH}?x=1`,
    });
    expect(queried.statusCode).toBe(400);
    expect(queried.body).not.toContain("x=1");

    const port = await listeningPort(app);
    const bare = await rawHttp(
      port,
      "GET",
      `${CONTROL_CAPABILITIES_PATH}?`,
      [],
    );
    expect(bare.status).toBe(400);
    expect(bare.text).toContain('"code":"INVALID_REQUEST"');

    const oversized = await app.inject({
      method: "GET",
      url: `${CONTROL_CAPABILITIES_PATH}?${"x".repeat(2100)}`,
    });
    expect(oversized.statusCode).toBe(400);
    expect(oversized.json().meta.schemaVersion).toBe("openarc.api.v2");
    expect(oversized.body).not.toContain("x".repeat(2100));
  });

  it("caps the response with the fixed v2 INTERNAL_ERROR", async () => {
    const app = harness({ maxResponseBytes: 10 });
    const response = await app.inject({
      method: "GET",
      url: CONTROL_CAPABILITIES_PATH,
    });
    expect(response.statusCode).toBe(500);
    expect(response.json().error.code).toBe("INTERNAL_ERROR");
  });

  it("leaves lookalike prefixes with no authority", async () => {
    const app = harness();
    for (const url of [
      `${CONTROL_CAPABILITIES_PATH}/extra`,
      "/v2/public/control-capabilitiesXYZ",
      "/v2/controlXYZ",
    ]) {
      const response = await app.inject({ method: "GET", url });
      expect(response.statusCode, url).toBe(404);
    }
  });

  it("always registers the capability route even with the flag off", async () => {
    const app = harness();
    expect(
      app.hasRoute({ method: "GET", url: CONTROL_CAPABILITIES_PATH }),
    ).toBe(true);
  });
});

/**
 * SECOND-EDGE REPRODUCTION: nginx strips the incoming transport headers and
 * uses the public HTTPS API upstream, after which Railway's second edge inserts
 * fresh routing headers BEFORE the API sees them. These are opaque, untrusted
 * informational proxy metadata: they must be ignored (never trusted, persisted,
 * echoed, logged, used for routing/origin) without weakening the credential,
 * Origin/Fetch-Site or request-shape protections.
 */
describe("second-edge Railway transport metadata is ignored", () => {
  const RAILWAY_EDGE_HEADERS: Record<string, string> = {
    "x-real-ip": "203.0.113.7",
    "x-forwarded-proto": "https",
    "x-forwarded-host": "control.openarc.test",
    "x-railway-edge": "lhr1",
    "x-request-start": "1700000000.123",
    "x-railway-request-id": "railway-req-abc",
  };
  const STANDARD_PROXY_HEADERS: Record<string, string> = {
    "x-forwarded-for": "203.0.113.7, 198.51.100.9",
    forwarded: "for=203.0.113.7;proto=https;host=control.openarc.test",
  };
  const UUID_V4 =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

  it("accepts the exact eight documented names simultaneously and separately", async () => {
    const app = harness();
    const single: ReadonlyArray<readonly [string, string]> = Object.entries(
      RAILWAY_EDGE_HEADERS,
    );
    const accepted: Record<string, string>[] = [
      RAILWAY_EDGE_HEADERS,
      ...Object.entries(STANDARD_PROXY_HEADERS).map(([name, value]) => ({
        [name]: value,
      })),
      ...single.map(([name, value]) => ({ [name]: value })),
    ];
    expect(Object.keys(RAILWAY_EDGE_HEADERS)).toHaveLength(6);
    expect(Object.keys(STANDARD_PROXY_HEADERS)).toHaveLength(2);
    for (const headers of accepted) {
      const response = await app.inject({
        method: "GET",
        url: CONTROL_CAPABILITIES_PATH,
        headers,
      });
      expect(response.statusCode, JSON.stringify(headers)).toBe(200);
      const parsed = ControlCapabilitiesSuccessEnvelopeSchema.parse(
        response.json(),
      );
      expect(parsed.data.routes).toHaveLength(10);
      expect(response.headers["set-cookie"]).toBeUndefined();
      expect(response.headers["access-control-allow-origin"]).toBeUndefined();
    }
  });

  it("never reflects spoofed proxy metadata and keeps the app requestId in charge", async () => {
    const app = harness();
    const spoofed: Record<string, string> = {
      ...RAILWAY_EDGE_HEADERS,
      ...STANDARD_PROXY_HEADERS,
      "x-railway-request-id": "attacker-supplied-request-id",
      "x-real-ip": "6.6.6.6",
      "x-forwarded-host": "<script>alert(1)</script>",
    };
    const response = await app.inject({
      method: "GET",
      url: CONTROL_CAPABILITIES_PATH,
      headers: spoofed,
    });
    expect(response.statusCode).toBe(200);
    const parsed = ControlCapabilitiesSuccessEnvelopeSchema.parse(
      response.json(),
    );
    expect(parsed.meta.requestId).toMatch(UUID_V4);
    expect(parsed.meta.requestId).not.toBe("attacker-supplied-request-id");
    const headerValues = Object.values(response.headers).map((value) =>
      String(value),
    );
    for (const value of Object.values(spoofed)) {
      expect(response.body, value).not.toContain(value);
      expect(headerValues, value).not.toContain(value);
    }
  });

  it("does not let edge metadata authorize credentials or weaken guards", async () => {
    const app = harness();
    const forbidden: Record<string, string>[] = [
      { cookie: "openarc_session=abc" },
      { authorization: "Bearer x" },
      { "x-openarc-csrf": "t" },
      { "idempotency-key": "k" },
      { "x-openarc-client": "other" },
      { "x-unknown-client": "x" },
    ];
    for (const extra of forbidden) {
      const response = await app.inject({
        method: "GET",
        url: CONTROL_CAPABILITIES_PATH,
        headers: { ...RAILWAY_EDGE_HEADERS, ...extra },
      });
      expect(response.statusCode, JSON.stringify(extra)).toBe(400);
      expect(response.json().error.code, JSON.stringify(extra)).toBe(
        "INVALID_REQUEST",
      );
    }
    const foreignOrigin = await app.inject({
      method: "GET",
      url: CONTROL_CAPABILITIES_PATH,
      headers: { ...RAILWAY_EDGE_HEADERS, origin: "https://evil.example" },
    });
    expect(foreignOrigin.statusCode).toBe(403);
    expect(foreignOrigin.json().error.code).toBe("INVALID_ORIGIN");
  });

  it("still rejects raw duplicate critical headers", async () => {
    const app = harness();
    const port = await listeningPort(app);
    const duplicates: ReadonlyArray<readonly string[]> = [
      ["Cookie: a=1", "Cookie: b=2"],
      ["Authorization: Bearer x", "Authorization: Bearer y"],
      ["Origin: " + ORIGIN, "Origin: " + ORIGIN],
      ["Idempotency-Key: a", "Idempotency-Key: b"],
      ["X-OpenArc-Csrf: a", "X-OpenArc-Csrf: b"],
      ["X-OpenArc-Client: browser-v1", "X-OpenArc-Client: browser-v1"],
    ];
    for (const duplicate of duplicates) {
      const response = await rawHttp(
        port,
        "GET",
        CONTROL_CAPABILITIES_PATH,
        [...duplicate],
      );
      expect(response.status, duplicate.join("|")).toBe(400);
      expect(response.text).toContain('"code":"INVALID_REQUEST"');
      expect(response.text.toLowerCase()).not.toContain("set-cookie");
    }
  });
});

function rawHttp(
  port: number,
  method: string,
  path: string,
  headers: readonly string[],
  body = "",
): Promise<{ status: number; text: string }> {
  const payload = Buffer.from(body, "utf8");
  const lines = [
    `${method} ${path} HTTP/1.1`,
    "Host: 127.0.0.1",
    ...headers,
    ...(payload.byteLength > 0 ? [`Content-Length: ${payload.byteLength}`] : []),
    "Connection: close",
    "",
    "",
  ];
  const wire = Buffer.concat([Buffer.from(lines.join("\r\n"), "utf8"), payload]);
  return new Promise((resolve, reject) => {
    const socket = connect({ host: "127.0.0.1", port });
    const chunks: Buffer[] = [];
    socket.on("connect", () => socket.write(wire));
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.on("error", reject);
    socket.on("end", () => {
      const text = Buffer.concat(chunks).toString("utf8");
      resolve({ status: Number.parseInt(text.slice(9, 12), 10), text });
    });
  });
}

async function listeningPort(app: App): Promise<number> {
  await app.listen({ port: 0, host: "127.0.0.1" });
  const address = app.server.address();
  if (address === null || typeof address === "string") {
    throw new Error("expected TCP address");
  }
  return address.port;
}
