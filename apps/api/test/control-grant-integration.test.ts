import { afterEach, describe, expect, it } from "vitest";

import { GRANT_CAPABILITIES_PATH, GRANT_ROUTES } from "@openarc/shared";

import { createApp } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import type { CommerceGrantService } from "../src/control/grant-service.js";
import {
  ATTEMPT,
  GRANT,
  GRANT_TOKEN,
  MUTATION,
  ORG,
  PROVIDER_TOKEN,
  SESSION_TOKEN,
} from "./grant-fixtures.js";

/**
 * Whole-app wiring for the authorization-grant lane in DEFAULT mode.
 *
 * The lane ships disabled: the default configuration registers the nine exact
 * targets behind the gate, every one of them answers a real API error envelope
 * (never an HTML page, never a 200), the public capability manifest reports
 * `built_disabled`, and enabling the gate without its service is a fixed
 * startup failure instead of a silently missing surface.
 */

const ORIGIN = "http://localhost:5173";
const SHA = "0123456789abcdef0123456789abcdef01234567";
const AUTH_URL = "postgres://openarc_auth_app:x@127.0.0.1:5432/openarc_auth_test";
const TENANT_URL =
  "postgres://openarc_tenant_app:y@127.0.0.1:5432/openarc_auth_test";
const SECRET = "synthetic_auth_secret_for_grant_startup_01234567890";

const apps: ReturnType<typeof createApp>[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map(async (app) => app.close()));
});

function enabledEnvironment(
  overrides: Record<string, string> = {},
): Record<string, string> {
  return {
    NODE_ENV: "test",
    COMMIT_SHA: SHA,
    APP_ORIGIN: ORIGIN,
    AUTH_ENABLED: "true",
    AUTH_DATABASE_URL: AUTH_URL,
    AUTH_SECRET: SECRET,
    AUTH_RP_ID: "localhost",
    TENANT_DATABASE_URL: TENANT_URL,
    COMMERCE_SESSIONS_ENABLED: "true",
    COMMERCE_ACTIONS_ENABLED: "true",
    COMMERCE_GRANTS_ENABLED: "true",
    ...overrides,
  };
}

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
    case "grant_issue":
      return { method: "POST", url: "/v2/agent/commerce-grants" };
    case "grant_replace":
      return {
        method: "POST",
        url: `/v2/agent/commerce-grants/${GRANT}/replace`,
      };
    case "agent_grant_mutation_status":
      return {
        method: "GET",
        url: `/v2/agent/commerce-grant-mutations/${MUTATION}`,
      };
    case "provider_grant_introspect":
      return { method: "POST", url: "/v2/provider/grants/introspect" };
    case "provider_grant_claim":
      return { method: "POST", url: "/v2/provider/grants/claim" };
    case "provider_grant_attempt_status":
      return { method: "GET", url: `/v2/provider/grant-attempts/${ATTEMPT}` };
    case "grant_detail":
      return { method: "GET", url: `${control}/${ORG}/grants/${GRANT}` };
    case "grant_mutation_status":
      return {
        method: "GET",
        url: `${control}/${ORG}/grant-mutations/${MUTATION}`,
      };
    case "grant_revoke":
      return {
        method: "POST",
        url: `${control}/${ORG}/grants/${GRANT}/revoke`,
      };
    default:
      throw new Error(`unknown route id ${id}`);
  }
}

describe("the authorization-grant lane ships disabled", () => {
  it("answers every frozen target with a real API error, never HTML or 200", async () => {
    const app = defaultApp();
    for (const route of GRANT_ROUTES) {
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
      const body = response.json() as {
        ok?: unknown;
        error?: { code?: string };
      };
      expect([route.id, body.ok]).toEqual([route.id, false]);
      expect(typeof body.error?.code).toBe("string");
      // No secret and no echo of the caller's own input.
      expect(response.body).not.toContain(SESSION_TOKEN);
      expect(response.body).not.toContain(PROVIDER_TOKEN);
      expect(response.body).not.toContain(GRANT_TOKEN);
      expect(response.body).not.toContain(target.url);
    }
  });

  it("publishes the frozen manifest with all three families built_disabled", async () => {
    const app = defaultApp();
    const response = await app.inject({
      method: "GET",
      url: GRANT_CAPABILITIES_PATH,
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
      "openarc.capabilities.commerce-grants.v1",
    );
    expect(body.data?.routes).toHaveLength(9);
    expect(body.data?.capabilities?.map((entry) => entry.state)).toEqual([
      "built_disabled",
      "built_disabled",
      "built_disabled",
    ]);
  });

  it("keeps the disabled lane out of the readiness dependency report", async () => {
    const app = defaultApp();
    const response = await app.inject({ method: "GET", url: "/readyz" });
    expect(response.statusCode).toBe(200);
    expect(response.body).not.toContain("commerceGrantDatabase");
  });
});

describe("root readiness reports the grant dependency", () => {
  /**
   * The enabled lane over the REAL `createApp`. The grant service is an inert
   * transport stand-in and the readiness callback is injected, so no database,
   * pool or network is claimed by these assertions.
   */
  function readinessApp(options: {
    readonly enabled: boolean;
    readonly commerceGrantReady?: () => Promise<boolean>;
  }): ReturnType<typeof createApp> {
    const config = loadConfig(
      options.enabled
        ? enabledEnvironment()
        : { NODE_ENV: "test", COMMIT_SHA: SHA, APP_ORIGIN: ORIGIN },
    );
    const app = createApp({
      config,
      logger: false,
      ...(config.AUTH_ENABLED
        ? {
            authService: {} as never,
            authReady: async () => true,
            commerceSessionService: {} as never,
            commerceSessionReady: async () => true,
            commerceActionService: {} as never,
            commerceActionReady: async () => true,
          }
        : {}),
      ...(config.COMMERCE_GRANTS_ENABLED
        ? { commerceGrantService: {} as never }
        : {}),
      ...(options.commerceGrantReady !== undefined
        ? { commerceGrantReady: options.commerceGrantReady }
        : {}),
    });
    apps.push(app);
    return app;
  }

  it("reports the grant dependency up when the callback is healthy", async () => {
    const app = readinessApp({
      enabled: true,
      commerceGrantReady: async () => true,
    });
    const response = await app.inject({ method: "GET", url: "/readyz" });
    expect(response.statusCode).toBe(200);
    expect(response.json().checks.commerceGrantDatabase).toBe("up");
    expect(response.json().checks.commerceActionDatabase).toBe("up");
  });

  it("fails grant readiness closed when the callback is down, missing or throws", async () => {
    for (const probe of [
      async () => false,
      undefined,
      async () => {
        throw new Error("probe exploded");
      },
    ]) {
      const app = readinessApp({
        enabled: true,
        ...(probe !== undefined ? { commerceGrantReady: probe } : {}),
      });
      const response = await app.inject({ method: "GET", url: "/readyz" });
      expect(response.statusCode).toBe(503);
      expect(response.json().checks.commerceGrantDatabase).toBe("down");
      // The dependencies checked before it still report their real state.
      expect(response.json().checks.commerceActionDatabase).toBe("up");
      expect(response.body).not.toContain("probe exploded");
    }
  });

  it("never invokes grant readiness and omits the key when the flag is off", async () => {
    let calls = 0;
    const app = readinessApp({
      enabled: false,
      commerceGrantReady: async () => {
        calls += 1;
        return true;
      },
    });
    const response = await app.inject({ method: "GET", url: "/readyz" });
    expect(response.statusCode).toBe(200);
    expect(response.json().checks).not.toHaveProperty("commerceGrantDatabase");
    expect(calls).toBe(0);
  });
});

describe("enabling the lane requires its service", () => {
  it("fails startup closed rather than silently dropping the routes", () => {
    expect(() =>
      createApp({
        config: loadConfig(enabledEnvironment()),
        logger: false,
        authService: {} as never,
        commerceSessionService: {} as never,
        commerceActionService: {} as never,
        // Every other family's service is supplied, the grant one is not.
      }),
    ).toThrow("Commerce grant dependencies are unavailable");
  });

  it("installs the nine live targets when the service is supplied", async () => {
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
    ) as unknown as CommerceGrantService;
    const app = createApp({
      config: loadConfig(enabledEnvironment()),
      logger: false,
      authService: {} as never,
      commerceSessionService: {} as never,
      commerceActionService: {} as never,
      commerceGrantService: service,
    });
    apps.push(app);
    // A canonical browser read now reaches the service instead of a 404/503.
    const response = await app.inject({
      method: "GET",
      url: `/v2/control/organizations/${ORG}/grants/${GRANT}`,
      headers: {
        origin: ORIGIN,
        "x-openarc-client": "browser-v1",
        cookie: "openarc_session=abc",
      },
    });
    expect(calls).toEqual(["getGrant"]);
    expect(response.statusCode).toBeGreaterThanOrEqual(500);
    expect(response.body.toLowerCase()).not.toContain("<html");

    // A canonical provider read reaches it too, and the grant lane never
    // collides with the seller browser listing prefix.
    const provider = await app.inject({
      method: "GET",
      url: `/v2/provider/grant-attempts/${ATTEMPT}`,
      headers: { authorization: `Bearer ${PROVIDER_TOKEN}` },
    });
    expect(calls).toEqual(["getGrant", "getProviderAttemptStatus"]);
    expect(provider.statusCode).toBeGreaterThanOrEqual(500);
  });

  it("keeps the commerce-action lane's own twelve targets intact", async () => {
    const app = createApp({
      config: loadConfig(enabledEnvironment()),
      logger: false,
      authService: {} as never,
      commerceSessionService: {} as never,
      commerceActionService: {} as never,
      commerceGrantService: {} as never,
    });
    apps.push(app);
    // The grant family adds `grants`/`grant-mutations` under the SAME control
    // organization root; the action targets must still resolve to their own
    // handlers rather than being shadowed.
    const response = await app.inject({
      method: "GET",
      url: `/v2/control/organizations/${ORG}/actions`,
      headers: {
        origin: ORIGIN,
        "x-openarc-client": "browser-v1",
        cookie: "openarc_session=abc",
      },
    });
    expect(response.statusCode).not.toBe(404);
  });
});
