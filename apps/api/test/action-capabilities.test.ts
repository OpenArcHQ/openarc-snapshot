import { afterEach, describe, expect, it } from "vitest";
import Fastify, { type FastifyInstance } from "fastify";

import {
  ACTION_CAPABILITIES_PATH,
  ACTION_CAPABILITY_DEPENDENCY_ORDER,
  ACTION_CAPABILITY_VERSION,
  ACTION_ROUTES,
  ActionCapabilityManifestSchema,
  COMMERCE_CAPABILITY_ENVIRONMENT,
  COMMERCE_CAPABILITY_NETWORK,
} from "@openarc/shared";

import { AuthApiError, authErrorEnvelope } from "../src/auth/errors.js";
import {
  actionCapabilityState,
  buildActionCapabilityManifest,
  registerActionCapabilities,
  type ActionCapabilityFlags,
} from "../src/commerce/action-capabilities.js";
import { BUILD_SHA, MUTATION, ORIGIN } from "./action-fixtures.js";

/**
 * Public commerce-action capability metadata coverage.
 *
 * The manifest is availability metadata only: these tests pin the frozen
 * two-family / twelve-route shape, the default `built_disabled` state, the
 * dependency-derived states and the fact that no readiness probe runs while the
 * gate is off. Nothing here grants payment, settlement or delivery authority.
 */

const apps: FastifyInstance[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map(async (app) => app.close()));
});

const ALL_OFF: ActionCapabilityFlags = {
  authEnabled: false,
  commerceSessionsEnabled: false,
  commerceActionsEnabled: false,
};

const ALL_ON: ActionCapabilityFlags = {
  authEnabled: true,
  commerceSessionsEnabled: true,
  commerceActionsEnabled: true,
};

interface Probes {
  authReady: number;
  sessionReady: number;
  actionReady: number;
}

function build(
  flags: ActionCapabilityFlags,
  ready: { auth?: boolean; session?: boolean; action?: boolean } = {},
): { app: FastifyInstance; probes: Probes } {
  const probes: Probes = { authReady: 0, sessionReady: 0, actionReady: 0 };
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
  registerActionCapabilities(app, {
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
    url: ACTION_CAPABILITIES_PATH,
  });
  const body = response.json() as { data?: Record<string, unknown> };
  return {
    status: response.statusCode,
    data: body.data ?? {},
    raw: response.body,
  };
}

describe("frozen manifest shape", () => {
  it("publishes the exact accepted version, families and twelve routes", async () => {
    const { app } = build(ALL_OFF);
    const result = await manifest(app);
    expect(result.status).toBe(200);
    expect(result.data["capabilityVersion"]).toBe(ACTION_CAPABILITY_VERSION);
    expect(result.data["capabilityVersion"]).toBe(
      "openarc.capabilities.commerce-actions.v1",
    );
    expect(result.data["environment"]).toBe(COMMERCE_CAPABILITY_ENVIRONMENT);
    expect(result.data["network"]).toBe(COMMERCE_CAPABILITY_NETWORK);
    const capabilities = result.data["capabilities"] as {
      family: string;
      audience: string;
      dependencies: string[];
    }[];
    expect(capabilities).toHaveLength(2);
    expect(capabilities.map((entry) => entry.family)).toEqual([
      "commerce_action_management",
      "commerce_action_authorization",
    ]);
    expect(capabilities.map((entry) => entry.audience)).toEqual([
      "browser",
      "agent",
    ]);
    for (const entry of capabilities) {
      expect(entry.dependencies).toEqual([...ACTION_CAPABILITY_DEPENDENCY_ORDER]);
      expect(entry.dependencies).toContain("commerceActionDatabase");
    }
    const routes = result.data["routes"] as {
      id: string;
      method: string;
      path: string;
      audience: string;
    }[];
    expect(routes).toHaveLength(12);
    expect(routes).toEqual(ACTION_ROUTES.map((route) => ({ ...route })));
    expect(
      routes.filter((route) => route.audience === "browser"),
    ).toHaveLength(9);
    expect(routes.filter((route) => route.audience === "agent")).toHaveLength(3);
    // The served manifest re-parses against the frozen shared schema.
    expect(
      ActionCapabilityManifestSchema.safeParse(result.data).success,
    ).toBe(true);
  });

  it("never advertises a payment, settlement, grant or delivery route", async () => {
    const { app } = build(ALL_ON);
    const result = await manifest(app);
    for (const forbidden of [
      "payment",
      "settle",
      "settlement",
      "delivery",
      "refund",
      "grant",
      "wallet",
    ]) {
      expect(result.raw.toLowerCase()).not.toContain(forbidden);
    }
  });

  it("builds a frozen manifest for every published state", () => {
    for (const state of ["enabled", "built_disabled", "unavailable"] as const) {
      const built = buildActionCapabilityManifest(state);
      expect(built.capabilities.map((entry) => entry.state)).toEqual([
        state,
        state,
      ]);
      expect(built.routes).toHaveLength(12);
    }
  });
});

describe("per-family state comes from actual configured dependencies", () => {
  it("is built_disabled with the gate off and runs ZERO readiness probes", async () => {
    const { app, probes } = build(ALL_OFF);
    const result = await manifest(app);
    const capabilities = result.data["capabilities"] as { state: string }[];
    expect(capabilities.map((entry) => entry.state)).toEqual([
      "built_disabled",
      "built_disabled",
    ]);
    expect(probes).toEqual({
      authReady: 0,
      sessionReady: 0,
      actionReady: 0,
    });
  });

  it("stays built_disabled with the gate off even when every prerequisite holds", async () => {
    const { app, probes } = build({
      authEnabled: true,
      commerceSessionsEnabled: true,
      commerceActionsEnabled: false,
    });
    const result = await manifest(app);
    const capabilities = result.data["capabilities"] as { state: string }[];
    expect(capabilities.map((entry) => entry.state)).toEqual([
      "built_disabled",
      "built_disabled",
    ]);
    expect(probes.actionReady).toBe(0);
  });

  it("is enabled only when the gate, both prerequisites and all probes hold", async () => {
    const { app, probes } = build(ALL_ON);
    const result = await manifest(app);
    const capabilities = result.data["capabilities"] as { state: string }[];
    expect(capabilities.map((entry) => entry.state)).toEqual([
      "enabled",
      "enabled",
    ]);
    expect(probes).toEqual({
      authReady: 1,
      sessionReady: 1,
      actionReady: 1,
    });
  });

  it("is unavailable when the action dependency is not ready", async () => {
    const { app } = build(ALL_ON, { action: false });
    const result = await manifest(app);
    const capabilities = result.data["capabilities"] as { state: string }[];
    expect(capabilities.map((entry) => entry.state)).toEqual([
      "unavailable",
      "unavailable",
    ]);
  });

  it("is unavailable when a prerequisite flag or probe is missing", () => {
    const allReady = {
      authReady: true,
      sessionReady: true,
      actionReady: true,
    };
    expect(actionCapabilityState(ALL_ON, allReady)).toBe("enabled");
    expect(
      actionCapabilityState(
        { ...ALL_ON, authEnabled: false },
        allReady,
      ),
    ).toBe("unavailable");
    expect(
      actionCapabilityState(
        { ...ALL_ON, commerceSessionsEnabled: false },
        allReady,
      ),
    ).toBe("unavailable");
    expect(
      actionCapabilityState(ALL_ON, { ...allReady, sessionReady: false }),
    ).toBe("unavailable");
    expect(
      actionCapabilityState(ALL_ON, { ...allReady, authReady: false }),
    ).toBe("unavailable");
    expect(actionCapabilityState(ALL_OFF, allReady)).toBe("built_disabled");
  });

  it("treats a throwing readiness callback as unavailable, never enabled", async () => {
    const app = Fastify({
      logger: false,
      exposeHeadRoutes: false,
      genReqId: () => MUTATION,
    });
    registerActionCapabilities(app, {
      flags: ALL_ON,
      readiness: {
        authReady: async () => true,
        sessionReady: async () => true,
        actionReady: async () => {
          throw new Error("probe exploded");
        },
      },
      buildSha: BUILD_SHA,
      appOrigin: ORIGIN,
    });
    apps.push(app);
    const result = await manifest(app);
    const capabilities = result.data["capabilities"] as { state: string }[];
    expect(capabilities.map((entry) => entry.state)).toEqual([
      "unavailable",
      "unavailable",
    ]);
  });
});

describe("public transport strictness", () => {
  it("rejects credentials, queries and non-GET methods", async () => {
    const { app } = build(ALL_OFF);
    const cases: readonly [Record<string, string>, number][] = [
      [{ cookie: "openarc_session=abc" }, 400],
      [{ authorization: "Bearer oacs_v1_x" }, 400],
      [{ "x-openarc-csrf": "token" }, 400],
      [{ "idempotency-key": "key" }, 400],
      [{ origin: "https://evil.example" }, 403],
      [{ "x-openarc-client": "not-a-browser" }, 400],
    ];
    for (const [headers, status] of cases) {
      const response = await app.inject({
        method: "GET",
        url: ACTION_CAPABILITIES_PATH,
        headers,
      });
      expect([JSON.stringify(headers), response.statusCode]).toEqual([
        JSON.stringify(headers),
        status,
      ]);
    }
    const query = await app.inject({
      method: "GET",
      url: `${ACTION_CAPABILITIES_PATH}?x=1`,
    });
    expect(query.statusCode).toBe(400);
    const post = await app.inject({
      method: "POST",
      url: ACTION_CAPABILITIES_PATH,
      payload: {},
    });
    expect(post.statusCode).toBe(405);
  });

  it("serves the exact frozen path", () => {
    expect(ACTION_CAPABILITIES_PATH).toBe("/v2/public/action-capabilities");
  });
});
