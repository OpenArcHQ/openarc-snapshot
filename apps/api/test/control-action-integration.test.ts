import { afterEach, describe, expect, it } from "vitest";

import { ACTION_CAPABILITIES_PATH, ACTION_ROUTES } from "@openarc/shared";

import { createApp } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import type { CommerceActionService } from "../src/control/action-service.js";
import {
  ACTION,
  AGENT,
  APPROVAL,
  MUTATION,
  ORG,
  POLICY,
  SESSION_TOKEN,
} from "./action-fixtures.js";

/**
 * Whole-app wiring for the commerce-action lane in DEFAULT mode.
 *
 * The lane ships disabled: the default configuration registers the twelve exact
 * targets behind the gate, every one of them answers a real API error envelope
 * (never an HTML page, never a 200), the public capability manifest reports
 * `built_disabled`, and enabling the gate without its service is a fixed
 * startup failure instead of a silently missing surface.
 */

const ORIGIN = "http://localhost:5173";
const SHA = "0123456789abcdef0123456789abcdef01234567";

const apps: ReturnType<typeof createApp>[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map(async (app) => app.close()));
});

function defaultApp(): ReturnType<typeof createApp> {
  const app = createApp({
    config: loadConfig({
      NODE_ENV: "test",
      COMMIT_SHA: SHA,
      APP_ORIGIN: ORIGIN,
    }),
    logger: false,
  });
  apps.push(app);
  return app;
}

/** Every frozen descriptor as a concrete, canonical request target. */
function concreteTarget(id: string): { method: "GET" | "POST"; url: string } {
  const control = "/v2/control/organizations";
  switch (id) {
    case "action_list":
      return { method: "GET", url: `${control}/${ORG}/actions` };
    case "action_detail":
      return { method: "GET", url: `${control}/${ORG}/actions/${ACTION}` };
    case "approval_list":
      return { method: "GET", url: `${control}/${ORG}/approvals` };
    case "approval_detail":
      return { method: "GET", url: `${control}/${ORG}/approvals/${APPROVAL}` };
    case "action_exposure":
      return {
        method: "GET",
        url: `${control}/${ORG}/agents/${AGENT}/policies/${POLICY}/exposure`,
      };
    case "action_mutation_status":
      return {
        method: "GET",
        url: `${control}/${ORG}/action-mutations/${MUTATION}`,
      };
    case "action_approve":
      return {
        method: "POST",
        url: `${control}/${ORG}/actions/${ACTION}/approve`,
      };
    case "action_reject":
      return {
        method: "POST",
        url: `${control}/${ORG}/actions/${ACTION}/reject`,
      };
    case "action_cancel":
      return {
        method: "POST",
        url: `${control}/${ORG}/actions/${ACTION}/cancel`,
      };
    case "action_authorize":
      return { method: "POST", url: "/v2/agent/commerce-actions" };
    case "agent_action_detail":
      return { method: "GET", url: `/v2/agent/commerce-actions/${ACTION}` };
    case "agent_action_mutation_status":
      return {
        method: "GET",
        url: `/v2/agent/commerce-action-mutations/${MUTATION}`,
      };
    default:
      throw new Error(`unknown route id ${id}`);
  }
}

describe("the commerce-action lane ships disabled", () => {
  it("answers every frozen target with a real API error, never HTML or 200", async () => {
    const app = defaultApp();
    for (const route of ACTION_ROUTES) {
      const target = concreteTarget(route.id);
      const response = await app.inject({
        method: target.method,
        url: target.url,
        headers: {
          origin: ORIGIN,
          "x-openarc-client": "browser-v1",
          ...(target.method === "POST"
            ? { "content-type": "application/json" }
            : {}),
        },
        ...(target.method === "POST" ? { payload: {} } : {}),
      });
      expect([route.id, response.statusCode]).not.toEqual([route.id, 200]);
      expect([route.id, response.statusCode >= 400]).toEqual([route.id, true]);
      expect(response.headers["content-type"]).toContain("application/json");
      expect(response.body.toLowerCase()).not.toContain("<!doctype");
      expect(response.body.toLowerCase()).not.toContain("<html");
      const body = response.json() as { ok?: unknown; error?: { code?: string } };
      expect([route.id, body.ok]).toEqual([route.id, false]);
      expect(typeof body.error?.code).toBe("string");
      // No secret and no echo of the caller's own input.
      expect(response.body).not.toContain(SESSION_TOKEN);
      expect(response.body).not.toContain(target.url);
    }
  });

  it("publishes the frozen manifest with both families built_disabled", async () => {
    const app = defaultApp();
    const response = await app.inject({
      method: "GET",
      url: ACTION_CAPABILITIES_PATH,
    });
    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      data?: {
        capabilityVersion?: string;
        capabilities?: { family: string; state: string }[];
        routes?: unknown[];
      };
    };
    expect(body.data?.capabilityVersion).toBe(
      "openarc.capabilities.commerce-actions.v1",
    );
    expect(body.data?.routes).toHaveLength(12);
    expect(body.data?.capabilities?.map((entry) => entry.state)).toEqual([
      "built_disabled",
      "built_disabled",
    ]);
  });

  it("keeps the disabled lane out of the readiness dependency report", async () => {
    const app = defaultApp();
    const response = await app.inject({ method: "GET", url: "/readyz" });
    expect(response.body).not.toContain("commerceActionDatabase");
  });
});

describe("root readiness reports the action dependency", () => {
  /**
   * The enabled lane over the REAL `createApp`. The action service is an inert
   * transport stand-in and the readiness callback is injected, so no database,
   * pool or network is claimed by these assertions.
   */
  function readinessApp(options: {
    readonly enabled: boolean;
    readonly commerceActionReady?: () => Promise<boolean>;
  }): ReturnType<typeof createApp> {
    const config = loadConfig({
      NODE_ENV: "test",
      COMMIT_SHA: SHA,
      APP_ORIGIN: ORIGIN,
      ...(options.enabled
        ? {
            AUTH_ENABLED: "true",
            AUTH_DATABASE_URL:
              "postgres://openarc_auth_app:x@127.0.0.1:5432/openarc_auth_test",
            AUTH_SECRET: "synthetic_auth_secret_for_action_startup_0123456",
            AUTH_RP_ID: "localhost",
            TENANT_DATABASE_URL:
              "postgres://openarc_tenant_app:y@127.0.0.1:5432/openarc_auth_test",
            COMMERCE_SESSIONS_ENABLED: "true",
            COMMERCE_ACTIONS_ENABLED: "true",
          }
        : {}),
    });
    const app = createApp({
      config,
      logger: false,
      ...(config.AUTH_ENABLED
        ? {
            authService: {} as never,
            authReady: async () => true,
            commerceSessionService: {} as never,
            commerceSessionReady: async () => true,
          }
        : {}),
      ...(config.COMMERCE_ACTIONS_ENABLED
        ? { commerceActionService: {} as never }
        : {}),
      ...(options.commerceActionReady !== undefined
        ? { commerceActionReady: options.commerceActionReady }
        : {}),
    });
    apps.push(app);
    return app;
  }

  it("reports the action dependency up when the callback is healthy", async () => {
    const app = readinessApp({
      enabled: true,
      commerceActionReady: async () => true,
    });
    const response = await app.inject({ method: "GET", url: "/readyz" });
    expect(response.statusCode).toBe(200);
    expect(response.json().checks.commerceActionDatabase).toBe("up");
    expect(response.json().checks.commerceSessionDatabase).toBe("up");
  });

  it("fails action readiness closed when the callback is down", async () => {
    const app = readinessApp({
      enabled: true,
      commerceActionReady: async () => false,
    });
    const response = await app.inject({ method: "GET", url: "/readyz" });
    expect(response.statusCode).toBe(503);
    expect(response.json().checks.commerceActionDatabase).toBe("down");
    // The dependencies checked before it still report their real state.
    expect(response.json().checks.authDatabase).toBe("up");
    expect(response.json().checks.commerceSessionDatabase).toBe("up");
  });

  it("fails action readiness closed when the callback is missing entirely", async () => {
    const app = readinessApp({ enabled: true });
    const response = await app.inject({ method: "GET", url: "/readyz" });
    expect(response.statusCode).toBe(503);
    expect(response.json().checks.commerceActionDatabase).toBe("down");
  });

  it("fails action readiness closed when the callback itself throws", async () => {
    const app = readinessApp({
      enabled: true,
      commerceActionReady: async () => {
        throw new Error("probe exploded");
      },
    });
    const response = await app.inject({ method: "GET", url: "/readyz" });
    expect(response.statusCode).toBe(503);
    expect(response.json().checks.commerceActionDatabase).toBe("down");
    expect(response.body).not.toContain("probe exploded");
  });

  it("never invokes action readiness and omits the key when the flag is off", async () => {
    let calls = 0;
    const app = readinessApp({
      enabled: false,
      commerceActionReady: async () => {
        calls += 1;
        return true;
      },
    });
    const response = await app.inject({ method: "GET", url: "/readyz" });
    expect(response.statusCode).toBe(200);
    expect(response.json().checks).not.toHaveProperty(
      "commerceActionDatabase",
    );
    expect(calls).toBe(0);
  });
});

describe("enabling the lane requires its service", () => {
  it("fails startup closed rather than silently dropping the routes", () => {
    expect(() =>
      createApp({
        config: loadConfig({
          NODE_ENV: "test",
          COMMIT_SHA: SHA,
          APP_ORIGIN: ORIGIN,
          AUTH_ENABLED: "true",
          AUTH_DATABASE_URL:
            "postgres://openarc_auth_app:x@127.0.0.1:5432/openarc_auth_test",
          AUTH_SECRET: "synthetic_auth_secret_for_action_startup_0123456",
          AUTH_RP_ID: "localhost",
          TENANT_DATABASE_URL:
            "postgres://openarc_tenant_app:y@127.0.0.1:5432/openarc_auth_test",
          COMMERCE_SESSIONS_ENABLED: "true",
          COMMERCE_ACTIONS_ENABLED: "true",
        }),
        logger: false,
        authService: {} as never,
        // The commerce-session service is supplied, the action one is not.
        commerceSessionService: {} as never,
      }),
    ).toThrow("Commerce action dependencies are unavailable");
  });

  it("installs the twelve live targets when the service is supplied", async () => {
    const calls: string[] = [];
    const service = new Proxy(
      {},
      {
        get: (_target, property) => {
          if (typeof property !== "string") return undefined;
          return async () => {
            calls.push(property);
            throw new Error("unreachable in this transport-only assertion");
          };
        },
      },
    ) as unknown as CommerceActionService;
    const app = createApp({
      config: loadConfig({
        NODE_ENV: "test",
        COMMIT_SHA: SHA,
        APP_ORIGIN: ORIGIN,
        AUTH_ENABLED: "true",
        AUTH_DATABASE_URL:
          "postgres://openarc_auth_app:x@127.0.0.1:5432/openarc_auth_test",
        AUTH_SECRET: "synthetic_auth_secret_for_action_startup_0123456",
        AUTH_RP_ID: "localhost",
        TENANT_DATABASE_URL:
          "postgres://openarc_tenant_app:y@127.0.0.1:5432/openarc_auth_test",
        COMMERCE_SESSIONS_ENABLED: "true",
        COMMERCE_ACTIONS_ENABLED: "true",
      }),
      logger: false,
      authService: {} as never,
      commerceSessionService: {} as never,
      commerceActionService: service,
    });
    apps.push(app);
    // A canonical browser read now reaches the service instead of a 404/503.
    const response = await app.inject({
      method: "GET",
      url: `/v2/control/organizations/${ORG}/actions`,
      headers: {
        origin: ORIGIN,
        "x-openarc-client": "browser-v1",
        cookie: "openarc_session=abc",
      },
    });
    expect(calls).toEqual(["listActions"]);
    expect(response.statusCode).toBeGreaterThanOrEqual(500);
    expect(response.body.toLowerCase()).not.toContain("<html");
  });
});
