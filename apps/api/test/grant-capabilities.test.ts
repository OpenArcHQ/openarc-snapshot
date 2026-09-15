import { afterEach, describe, expect, it } from "vitest";
import Fastify, { type FastifyInstance } from "fastify";

import {
  COMMERCE_CAPABILITY_ENVIRONMENT,
  COMMERCE_CAPABILITY_NETWORK,
  GRANT_CAPABILITIES_PATH,
  GRANT_CAPABILITY_AUDIENCE,
  GRANT_CAPABILITY_DEPENDENCY_ORDER,
  GRANT_CAPABILITY_VERSION,
  GRANT_ROUTES,
  GrantCapabilityManifestSchema,
} from "@openarc/shared";

import { AuthApiError, authErrorEnvelope } from "../src/auth/errors.js";
import {
  buildGrantCapabilityManifest,
  grantCapabilityState,
  registerGrantCapabilities,
  type GrantCapabilityFlags,
} from "../src/commerce/grant-capabilities.js";
import { BUILD_SHA, MUTATION, ORIGIN } from "./grant-fixtures.js";

/**
 * Public authorization-grant capability metadata coverage.
 *
 * The manifest is availability metadata only: these tests pin the frozen
 * three-family / nine-route shape, the default `built_disabled` state, the
 * dependency-derived states and the fact that no readiness probe runs while the
 * gate is off. Nothing here grants payment, settlement or delivery authority.
 */

const apps: FastifyInstance[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map(async (app) => app.close()));
});

const ALL_OFF: GrantCapabilityFlags = {
  authEnabled: false,
  commerceSessionsEnabled: false,
  commerceActionsEnabled: false,
  commerceGrantsEnabled: false,
};

const ALL_ON: GrantCapabilityFlags = {
  authEnabled: true,
  commerceSessionsEnabled: true,
  commerceActionsEnabled: true,
  commerceGrantsEnabled: true,
};

interface Probes {
  authReady: number;
  sessionReady: number;
  actionReady: number;
  grantReady: number;
}

function build(
  flags: GrantCapabilityFlags,
  ready: {
    auth?: boolean;
    session?: boolean;
    action?: boolean;
    grant?: boolean;
  } = {},
): { app: FastifyInstance; probes: Probes } {
  const probes: Probes = {
    authReady: 0,
    sessionReady: 0,
    actionReady: 0,
    grantReady: 0,
  };
  const app = Fastify({
    logger: false,
    exposeHeadRoutes: false,
    genReqId: () => MUTATION,
  });
  app.setErrorHandler((cause, request, reply) => {
    if (cause instanceof AuthApiError) {
      return reply
        .code(cause.status)
        .send(authErrorEnvelope(cause, request.id, BUILD_SHA));
    }
    throw cause;
  });
  registerGrantCapabilities(app, {
    flags,
    readiness: {
      authReady: async () => {
        probes.authReady += 1;
        return ready.auth ?? true;
      },
      sessionReady: async () => {
        probes.sessionReady += 1;
        return ready.session ?? true;
      },
      actionReady: async () => {
        probes.actionReady += 1;
        return ready.action ?? true;
      },
      grantReady: async () => {
        probes.grantReady += 1;
        return ready.grant ?? true;
      },
    },
    buildSha: BUILD_SHA,
    appOrigin: ORIGIN,
  });
  apps.push(app);
  return { app, probes };
}

async function manifest(app: FastifyInstance): Promise<{
  status: number;
  data: Record<string, unknown>;
  raw: string;
}> {
  const response = await app.inject({
    method: "GET",
    url: GRANT_CAPABILITIES_PATH,
  });
  const body = response.json() as { data?: Record<string, unknown> };
  return {
    status: response.statusCode,
    data: body.data ?? {},
    raw: response.body,
  };
}

describe("frozen grant manifest shape", () => {
  it("publishes the exact accepted version, families and nine routes", async () => {
    const { app } = build(ALL_OFF);
    const result = await manifest(app);
    expect(result.status).toBe(200);
    expect(GRANT_CAPABILITIES_PATH).toBe("/v2/public/grant-capabilities");
    expect(result.data["capabilityVersion"]).toBe(GRANT_CAPABILITY_VERSION);
    expect(result.data["capabilityVersion"]).toBe(
      "openarc.capabilities.commerce-grants.v1",
    );
    expect(result.data["environment"]).toBe(COMMERCE_CAPABILITY_ENVIRONMENT);
    expect(result.data["network"]).toBe(COMMERCE_CAPABILITY_NETWORK);
    // The strict frozen schema accepts it, so order/inventory/state all hold.
    expect(GrantCapabilityManifestSchema.safeParse(result.data).success).toBe(
      true,
    );
    const capabilities = result.data["capabilities"] as {
      family: string;
      audience: string;
      state: string;
      dependencies: string[];
    }[];
    expect(capabilities).toHaveLength(3);
    expect(capabilities.map((entry) => entry.family)).toEqual([
      "commerce_grant_authorization",
      "commerce_grant_claim",
      "commerce_grant_management",
    ]);
    expect(capabilities.map((entry) => entry.audience)).toEqual([
      "agent",
      "provider",
      "browser",
    ]);
    for (const entry of capabilities) {
      expect(entry.audience).toBe(
        GRANT_CAPABILITY_AUDIENCE[
          entry.family as keyof typeof GRANT_CAPABILITY_AUDIENCE
        ],
      );
      expect(entry.dependencies).toEqual([
        ...GRANT_CAPABILITY_DEPENDENCY_ORDER,
      ]);
      expect(entry.dependencies).toContain("commerceGrantDatabase");
      expect(entry.dependencies).toContain("commerceActionDatabase");
      expect(entry.dependencies).toHaveLength(7);
    }
    const routes = result.data["routes"] as { id: string; path: string }[];
    expect(routes).toHaveLength(9);
    expect(routes.map((route) => route.id)).toEqual(
      GRANT_ROUTES.map((route) => route.id),
    );
    expect(routes.map((route) => route.path)).toEqual(
      GRANT_ROUTES.map((route) => route.path),
    );
  });

  it("carries no secret, flag name, database URL or private identity", async () => {
    const { app } = build(ALL_ON);
    const result = await manifest(app);
    for (const forbidden of [
      "COMMERCE_GRANTS_ENABLED",
      "AUTH_SECRET",
      "postgres://",
      "oag_v1_",
      "oacs_v1_",
      "oas_pr_",
      "tokenHash",
    ]) {
      expect([forbidden, result.raw.includes(forbidden)]).toEqual([
        forbidden,
        false,
      ]);
    }
  });
});

describe("state is derived from configured dependencies", () => {
  it("is built_disabled with the gate off and runs ZERO probes", async () => {
    const { app, probes } = build({ ...ALL_ON, commerceGrantsEnabled: false });
    const result = await manifest(app);
    const capabilities = result.data["capabilities"] as { state: string }[];
    expect(capabilities.map((entry) => entry.state)).toEqual([
      "built_disabled",
      "built_disabled",
      "built_disabled",
    ]);
    expect(probes).toEqual({
      authReady: 0,
      sessionReady: 0,
      actionReady: 0,
      grantReady: 0,
    });
  });

  it("is enabled only when every flag and every dependency holds", async () => {
    const { app, probes } = build(ALL_ON);
    const result = await manifest(app);
    const capabilities = result.data["capabilities"] as { state: string }[];
    expect(capabilities.map((entry) => entry.state)).toEqual([
      "enabled",
      "enabled",
      "enabled",
    ]);
    expect(probes.authReady).toBe(1);
    expect(probes.sessionReady).toBe(1);
    expect(probes.actionReady).toBe(1);
    expect(probes.grantReady).toBe(1);
  });

  it("is unavailable when any single dependency is unready", async () => {
    for (const key of ["auth", "session", "action", "grant"] as const) {
      const { app } = build(ALL_ON, { [key]: false });
      const result = await manifest(app);
      const capabilities = result.data["capabilities"] as { state: string }[];
      expect([key, capabilities.map((entry) => entry.state)]).toEqual([
        key,
        ["unavailable", "unavailable", "unavailable"],
      ]);
    }
  });

  it("is unavailable when a prerequisite FLAG is missing", () => {
    const ready = {
      authReady: true,
      sessionReady: true,
      actionReady: true,
      grantReady: true,
    };
    expect(grantCapabilityState(ALL_ON, ready)).toBe("enabled");
    for (const key of [
      "authEnabled",
      "commerceSessionsEnabled",
      "commerceActionsEnabled",
    ] as const) {
      expect([
        key,
        grantCapabilityState({ ...ALL_ON, [key]: false }, ready),
      ]).toEqual([key, "unavailable"]);
    }
    // Gate off always wins, no matter how healthy the dependencies are.
    expect(
      grantCapabilityState({ ...ALL_ON, commerceGrantsEnabled: false }, ready),
    ).toBe("built_disabled");
    expect(grantCapabilityState(ALL_OFF, ready)).toBe("built_disabled");
  });

  it("builds a schema-valid manifest for every published state", () => {
    for (const state of ["enabled", "built_disabled", "unavailable"] as const) {
      const built = buildGrantCapabilityManifest(state);
      expect(GrantCapabilityManifestSchema.safeParse(built).success).toBe(true);
      expect(built.capabilities.every((entry) => entry.state === state)).toBe(
        true,
      );
    }
  });
});

describe("public transport is credentialless", () => {
  it("rejects a credential, a query and a non-GET method", async () => {
    const { app, probes } = build(ALL_ON);
    for (const headers of [
      { cookie: "openarc_session=abc" },
      { authorization: "Bearer oacs_v1_x" },
      { "proxy-authorization": "Basic x" },
      { "x-openarc-csrf": "csrf" },
      { "idempotency-key": "A".repeat(43) },
    ]) {
      const response = await app.inject({
        method: "GET",
        url: GRANT_CAPABILITIES_PATH,
        headers,
      });
      expect(response.statusCode).toBe(400);
    }
    const query = await app.inject({
      method: "GET",
      url: `${GRANT_CAPABILITIES_PATH}?x=1`,
    });
    expect(query.statusCode).toBe(400);
    const post = await app.inject({
      method: "POST",
      url: GRANT_CAPABILITIES_PATH,
      payload: {},
    });
    expect(post.statusCode).toBe(405);
    const foreign = await app.inject({
      method: "GET",
      url: GRANT_CAPABILITIES_PATH,
      headers: { origin: "https://evil.example" },
    });
    expect(foreign.statusCode).toBe(403);
    expect(probes).toEqual({
      authReady: 0,
      sessionReady: 0,
      actionReady: 0,
      grantReady: 0,
    });
  });
});
