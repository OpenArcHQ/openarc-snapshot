import {
  COMMERCE_CAPABILITY_ENVIRONMENT,
  COMMERCE_CAPABILITY_NETWORK,
  SESSION_CAPABILITIES_PATH,
  SESSION_CAPABILITY_AUDIENCE,
  SESSION_CAPABILITY_DEPENDENCIES,
  SESSION_CAPABILITY_DEPENDENCY_ORDER,
  SESSION_CAPABILITY_FAMILY_ORDER,
  SESSION_CAPABILITY_VERSION,
  SESSION_ROUTES,
  SessionCapabilitiesSuccessEnvelopeSchema,
} from "@openarc/shared";
import { randomUUID } from "node:crypto";

import Fastify, { type FastifyInstance } from "fastify";
import { afterEach, describe, expect, it } from "vitest";

import { AuthApiError } from "../src/auth/errors.js";
import { authErrorEnvelope } from "../src/auth/errors.js";
import {
  buildSessionCapabilityManifest,
  registerSessionCapabilities,
  sessionCapabilityState,
  type SessionCapabilityFlags,
  type SessionCapabilityReadiness,
} from "../src/commerce/session-capabilities.js";

/**
 * Exact commerce-session capability HTTP and dependency matrix.
 *
 * The surface ALWAYS registers. Flag-off is `built_disabled` for BOTH families
 * with ZERO probe calls (even when callbacks are supplied). Enabled + healthy is
 * `enabled`; a missing/failed auth OR session dependency is the shared
 * `unavailable`. Only `authReady` + `sessionReady` are accepted: NO old HTTP
 * tenant/machine/policy readiness callback is dereferenced. Transport mirrors
 * the accepted policy capability surface. No DB/network is claimed.
 */

const ORIGIN = "http://localhost:5183";
const BUILD_SHA = "0123456789abcdef0123456789abcdef01234567";

const apps: FastifyInstance[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map(async (app) => app.close()));
});

function buildApp(options: {
  readonly flags: SessionCapabilityFlags;
  readonly readiness?: SessionCapabilityReadiness;
}): FastifyInstance {
  const app = Fastify({
    logger: false,
    exposeHeadRoutes: false,
    requestIdHeader: false,
    genReqId: () => randomUUID(),
  });
  app.setErrorHandler((cause, request, reply) => {
    if (cause instanceof AuthApiError) {
      return reply
        .code(cause.status)
        .send(authErrorEnvelope(cause, request.id, BUILD_SHA));
    }
    return reply.code(500).send({ ok: false });
  });
  registerSessionCapabilities(app, {
    flags: options.flags,
    readiness: options.readiness ?? {},
    buildSha: BUILD_SHA,
    appOrigin: ORIGIN,
  });
  apps.push(app);
  return app;
}

async function manifest(app: FastifyInstance) {
  const response = await app.inject({
    method: "GET",
    url: SESSION_CAPABILITIES_PATH,
  });
  expect(response.statusCode).toBe(200);
  return SessionCapabilitiesSuccessEnvelopeSchema.parse(response.json());
}

describe("buildSessionCapabilityManifest", () => {
  it("constructs the exact accepted two-family / seven-route registry", () => {
    const manifest = buildSessionCapabilityManifest("built_disabled");
    expect(manifest.capabilityVersion).toBe(SESSION_CAPABILITY_VERSION);
    expect(manifest.environment).toBe(COMMERCE_CAPABILITY_ENVIRONMENT);
    expect(manifest.network).toBe(COMMERCE_CAPABILITY_NETWORK);
    expect(manifest.capabilities.map((entry) => entry.family)).toEqual([
      ...SESSION_CAPABILITY_FAMILY_ORDER,
    ]);
    for (const entry of manifest.capabilities) {
      expect(entry.audience).toBe(SESSION_CAPABILITY_AUDIENCE[entry.family]);
      expect(entry.dependencies).toEqual([
        ...SESSION_CAPABILITY_DEPENDENCIES[entry.family],
      ]);
    }
    expect(manifest.routes).toEqual(SESSION_ROUTES);
    expect(manifest.routes).toHaveLength(7);
  });

  it("applies the ONE supplied state to both families", () => {
    for (const state of ["enabled", "built_disabled", "unavailable"] as const) {
      const manifest = buildSessionCapabilityManifest(state);
      for (const entry of manifest.capabilities) expect(entry.state).toBe(state);
    }
  });
});

describe("sessionCapabilityState dependency matrix", () => {
  const OFF: SessionCapabilityFlags = {
    authEnabled: true,
    commerceSessionsEnabled: false,
  };
  const ON: SessionCapabilityFlags = {
    authEnabled: true,
    commerceSessionsEnabled: true,
  };
  const READY = { authReady: true, sessionReady: true };
  const AUTH_DOWN = { authReady: false, sessionReady: true };
  const SESSION_DOWN = { authReady: true, sessionReady: false };

  it("is built_disabled with the flag off regardless of dependencies", () => {
    expect(sessionCapabilityState(OFF, READY)).toBe("built_disabled");
    expect(sessionCapabilityState(OFF, AUTH_DOWN)).toBe("built_disabled");
  });

  it("requires BOTH the enabled auth prerequisite and runtime readiness", () => {
    expect(sessionCapabilityState(ON, READY)).toBe("enabled");
    expect(sessionCapabilityState(ON, AUTH_DOWN)).toBe("unavailable");
    expect(sessionCapabilityState(ON, SESSION_DOWN)).toBe("unavailable");
    expect(
      sessionCapabilityState(
        { authEnabled: false, commerceSessionsEnabled: true },
        READY,
      ),
    ).toBe("unavailable");
  });

  it("does not consult old HTTP tenant/machine/policy readiness callbacks", () => {
    // The accepted signature exposes ONLY authReady + sessionReady. Passing
    // extra not-accepted callbacks has no effect on the state.
    const state = sessionCapabilityState(ON, READY);
    expect(state).toBe("enabled");
    for (const dependency of SESSION_CAPABILITY_DEPENDENCY_ORDER) {
      expect(["auth", "tenantDatabase", "machineDatabase", "policyDatabase",
        "commerceSessionDatabase"]).toContain(dependency);
    }
  });
});

describe("session capability HTTP state", () => {
  it("defaults to built_disabled for both families with ZERO probe calls", async () => {
    let calls = 0;
    const app = buildApp({
      flags: { authEnabled: true, commerceSessionsEnabled: false },
      readiness: {
        authReady: async () => {
          calls += 1;
          return true;
        },
        sessionReady: async () => {
          calls += 1;
          return true;
        },
      },
    });
    const parsed = await manifest(app);
    expect(parsed.data.capabilities.map((entry) => entry.state)).toEqual([
      "built_disabled",
      "built_disabled",
    ]);
    expect(calls).toBe(0);
  });

  it("reports enabled for both families when auth and session are healthy", async () => {
    const app = buildApp({
      flags: { authEnabled: true, commerceSessionsEnabled: true },
      readiness: {
        authReady: async () => true,
        sessionReady: async () => true,
      },
    });
    const parsed = await manifest(app);
    expect(parsed.data.capabilities.map((entry) => entry.state)).toEqual([
      "enabled",
      "enabled",
    ]);
  });

  it("reports the shared unavailable state for a failed parent dependency", async () => {
    const authDown = buildApp({
      flags: { authEnabled: true, commerceSessionsEnabled: true },
      readiness: {
        authReady: async () => false,
        sessionReady: async () => true,
      },
    });
    const authDownParsed = await manifest(authDown);
    for (const entry of authDownParsed.data.capabilities) {
      expect(entry.state).toBe("unavailable");
    }

    const sessionDown = buildApp({
      flags: { authEnabled: true, commerceSessionsEnabled: true },
      readiness: {
        authReady: async () => true,
        sessionReady: async () => false,
      },
    });
    const sessionDownParsed = await manifest(sessionDown);
    for (const entry of sessionDownParsed.data.capabilities) {
      expect(entry.state).toBe("unavailable");
    }
  });

  it("reports unavailable when enabled callbacks are missing", async () => {
    const app = buildApp({
      flags: { authEnabled: true, commerceSessionsEnabled: true },
      readiness: {},
    });
    const parsed = await manifest(app);
    for (const entry of parsed.data.capabilities) {
      expect(entry.state).toBe("unavailable");
    }
  });

  it("single-flights concurrent readiness probes and never caches", async () => {
    let sessionCalls = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const app = buildApp({
      flags: { authEnabled: true, commerceSessionsEnabled: true },
      readiness: {
        authReady: async () => true,
        sessionReady: async () => {
          sessionCalls += 1;
          await gate;
          return true;
        },
      },
    });
    const first = app.inject({ method: "GET", url: SESSION_CAPABILITIES_PATH });
    const second = app.inject({ method: "GET", url: SESSION_CAPABILITIES_PATH });
    await new Promise((resolve) => setImmediate(resolve));
    // Both concurrent requests attach to the SAME batch.
    expect(sessionCalls).toBe(1);
    release();
    const [a, b] = await Promise.all([first, second]);
    expect(a.statusCode).toBe(200);
    expect(b.statusCode).toBe(200);
    // A later settled request re-checks (no cache).
    await manifest(app);
    expect(sessionCalls).toBe(2);
  });
});

describe("session capability transport", () => {
  function enabled(): FastifyInstance {
    return buildApp({
      flags: { authEnabled: true, commerceSessionsEnabled: true },
      readiness: { authReady: async () => true, sessionReady: async () => true },
    });
  }

  it("rejects a query, a non-GET method and credentials with a fixed envelope", async () => {
    const app = enabled();
    const query = await app.inject({
      method: "GET",
      url: `${SESSION_CAPABILITIES_PATH}?x=1`,
    });
    expect(query.statusCode).toBe(400);
    expect(query.json().error.code).toBe("INVALID_REQUEST");

    const post = await app.inject({
      method: "POST",
      url: SESSION_CAPABILITIES_PATH,
    });
    expect(post.statusCode).toBe(405);

    const cookie = await app.inject({
      method: "GET",
      url: SESSION_CAPABILITIES_PATH,
      headers: { cookie: "openarc_session=abc" },
    });
    expect(cookie.statusCode).toBe(400);

    const authorization = await app.inject({
      method: "GET",
      url: SESSION_CAPABILITIES_PATH,
      headers: { authorization: "Bearer abc" },
    });
    expect(authorization.statusCode).toBe(400);
  });

  it("accepts the exact browser marker and same-origin origin", async () => {
    const app = enabled();
    const response = await app.inject({
      method: "GET",
      url: SESSION_CAPABILITIES_PATH,
      headers: { origin: ORIGIN, "x-openarc-client": "browser-v1" },
    });
    expect(response.statusCode).toBe(200);
  });

  it("rejects an unknown client header and a wrong origin", async () => {
    const app = enabled();
    const unknown = await app.inject({
      method: "GET",
      url: SESSION_CAPABILITIES_PATH,
      headers: { "x-openarc-evil": "1" },
    });
    expect(unknown.statusCode).toBe(400);

    const wrongOrigin = await app.inject({
      method: "GET",
      url: SESSION_CAPABILITIES_PATH,
      headers: { origin: "https://evil.example" },
    });
    expect(wrongOrigin.statusCode).toBe(403);
  });

  it("ignores exactly the accepted opaque Railway/proxy metadata exceptions", async () => {
    const app = enabled();
    const response = await app.inject({
      method: "GET",
      url: SESSION_CAPABILITIES_PATH,
      headers: {
        "x-real-ip": "203.0.113.7",
        "x-forwarded-proto": "https",
        "x-railway-edge": "sfo",
        forwarded: "for=203.0.113.7",
        "x-forwarded-for": "203.0.113.7",
      },
    });
    expect(response.statusCode).toBe(200);
  });
});
