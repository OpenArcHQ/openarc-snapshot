import { afterEach, describe, expect, it } from "vitest";

import {
  COMMERCE_ROUTES,
  COMMERCE_CAPABILITIES_PATH,
  CommerceCapabilitiesSuccessEnvelopeSchema,
  CONTROL_CAPABILITIES_PATH,
  CONTROL_ROUTES,
  ControlCapabilitiesSuccessEnvelopeSchema,
  MARKETPLACE_CAPABILITIES_PATH,
  MARKETPLACE_ROUTES,
  MarketplaceCapabilitiesSuccessEnvelopeSchema,
} from "@openarc/shared";

import { createApp, type CompletionLog } from "../src/app.js";
import type { AuthService } from "../src/auth/service.js";
import { loadConfig } from "../src/config.js";
import { PolicyService } from "../src/control/service.js";
import type {
  ControlPolicyAuthPort,
  ControlPolicyStorePort,
} from "../src/control/ports.js";

/**
 * Integration coverage for the REAL `createApp` over real Fastify for the
 * control policy family. The auth/store ports are HONESTLY MOCKED; no
 * PostgreSQL, network, Redis or server is claimed. This suite proves the exact
 * ten-route mount when enabled, fixed missing-service startup, disabled-family
 * zero-registration, the fixed v2 framework envelope for lookalikes, protected
 * route no-store/body behavior, root readiness wiring and that the old public
 * commerce/marketplace capability inventories remain byte-equivalent.
 */

const ORIGIN = "http://localhost:5183";
const BUILD_SHA = "0123456789abcdef0123456789abcdef01234567";
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

function build(options: {
  readonly enabled: boolean;
  readonly omitService?: boolean;
  readonly policyReady?: () => Promise<boolean>;
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
          AUTH_SECRET: "synthetic_auth_secret_for_control_integration_012",
          AUTH_RP_ID: "localhost",
          TENANT_DATABASE_URL: TENANT_URL,
          POLICY_MANAGEMENT_ENABLED: "true",
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
    ...(config.POLICY_MANAGEMENT_ENABLED && !options.omitService
      ? {
          policyManagementService: new PolicyService({
            auth: AUTH,
            store: STORE,
          }),
        }
      : {}),
    ...(options.policyReady !== undefined
      ? { policyReady: options.policyReady }
      : {}),
  });
  apps.push(app);
  return app;
}

function actualRoutes(app: App): Set<string> {
  const actual = new Set<string>();
  for (const route of CONTROL_ROUTES) {
    if (app.hasRoute({ method: route.method, url: route.path })) {
      actual.add(`${route.method} ${route.path}`);
    }
  }
  return actual;
}

describe("control policy family mount", () => {
  it("registers exactly the ten frozen routes across GET and POST when enabled", () => {
    const app = build({ enabled: true });
    expect(CONTROL_ROUTES).toHaveLength(10);
    for (const route of CONTROL_ROUTES) {
      expect(
        app.hasRoute({ method: route.method, url: route.path }),
        `${route.method} ${route.path}`,
      ).toBe(true);
    }
    expect(actualRoutes(app).size).toBe(10);
  });

  it("registers NO control route when the flag is off", () => {
    const app = build({ enabled: false });
    expect(actualRoutes(app).size).toBe(0);
  });

  it("fails startup closed when the family is enabled without its service", () => {
    expect(() => build({ enabled: true, omitService: true })).toThrow(
      "Policy management dependencies are unavailable",
    );
  });
});

describe("disabled family and lookalike envelopes", () => {
  it("returns a bounded v2 404 for every control route when disabled", async () => {
    const app = build({ enabled: false });
    for (const route of CONTROL_ROUTES) {
      const response = await app.inject({ method: route.method, url: route.path });
      expect(response.statusCode, `${route.method} ${route.path}`).toBe(404);
      expect(response.json().meta.schemaVersion, route.path).toBe(
        "openarc.api.v2",
      );
      expect(response.json().error.code, route.path).toBe("FEATURE_DISABLED");
    }
  });

  it("keeps lookalike prefixes on the legacy envelope", async () => {
    const app = build({ enabled: false });
    for (const url of [
      "/v2/control/organizationsXYZ",
      "/v2/controlXYZ",
    ]) {
      const response = await app.inject({ method: "GET", url });
      expect(response.statusCode, url).toBe(404);
      expect(response.json().meta.schemaVersion, url).toBe("openarc.api.v1");
    }
  });
});

describe("protected control route host behavior", () => {
  const ORG = "openarc:org:11111111-1111-4111-8111-111111111111";
  const POLICY = "openarc:policy:11111111-1111-4111-8111-111111111111";
  const BASE = `/v2/control/organizations/${ORG}`;

  it("sets no-store and never a Set-Cookie when the family is enabled", async () => {
    const app = build({ enabled: true });
    const response = await app.inject({
      method: "GET",
      url: `${BASE}/policies`,
      headers: {
        origin: ORIGIN,
        "x-openarc-client": "browser-v1",
        cookie: "openarc_session=abc",
      },
    });
    // The service runs successfully against the honest fake even without a
    // real session; the transport headers are what this test inspects.
    expect([200, 401]).toContain(response.statusCode);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.headers["pragma"]).toBe("no-cache");
    expect(response.headers["set-cookie"]).toBeUndefined();
    expect(response.headers["access-control-allow-origin"]).toBeUndefined();
    expect(response.headers["x-openarc-request-id"]).toBeDefined();
  });

  it("rejects a body on a GET and a wrong method with a fixed v2 envelope", async () => {
    const app = build({ enabled: true });
    const body = await app.inject({
      method: "GET",
      url: `${BASE}/policies`,
      headers: {
        origin: ORIGIN,
        "x-openarc-client": "browser-v1",
        "content-length": "2",
      },
      payload: "{}",
    });
    expect(body.statusCode).toBe(400);
    expect(body.json().meta.schemaVersion).toBe("openarc.api.v2");
    expect(body.json().error.code).toBe("INVALID_REQUEST");

    const wrongMethod = await app.inject({
      method: "DELETE",
      url: `${BASE}/policies`,
      headers: { origin: ORIGIN, "x-openarc-client": "browser-v1" },
    });
    expect(wrongMethod.statusCode).toBe(405);
    expect(wrongMethod.json().meta.schemaVersion).toBe("openarc.api.v2");
    expect(wrongMethod.json().error.code).toBe("INVALID_REQUEST");
  });

  it("routes the coarse metrics label as tenant without leaking raw paths", async () => {
    const logs: CompletionLog[] = [];
    const app = build({ enabled: true, logs });
    await app.inject({
      method: "GET",
      url: `${BASE}/policies`,
      headers: {
        origin: ORIGIN,
        "x-openarc-client": "browser-v1",
        cookie: "openarc_session=abc",
      },
    });
    const entry = logs.at(-1);
    expect(entry?.route).toBe("tenant");
    for (const value of logs) {
      expect(JSON.stringify(value)).not.toContain(ORG);
      expect(JSON.stringify(value)).not.toContain(POLICY);
      expect(value.route).not.toContain("/v2/");
    }
  });
});

describe("root readiness wiring", () => {
  it("fails policy readiness closed when the callback is down", async () => {
    const app = build({ enabled: true, policyReady: async () => false });
    const response = await app.inject({ method: "GET", url: "/readyz" });
    expect(response.statusCode).toBe(503);
    expect(response.json().checks.policyDatabase).toBe("down");
    expect(response.json().checks.authDatabase).toBe("up");
  });

  it("reports policy readiness up when the callback is healthy", async () => {
    const app = build({ enabled: true, policyReady: async () => true });
    const response = await app.inject({ method: "GET", url: "/readyz" });
    expect(response.statusCode).toBe(200);
    expect(response.json().checks.policyDatabase).toBe("up");
  });

  it("never invokes policy readiness when the flag is off", async () => {
    let calls = 0;
    const app = build({
      enabled: false,
      policyReady: async () => {
        calls += 1;
        return true;
      },
    });
    const response = await app.inject({ method: "GET", url: "/readyz" });
    expect(response.statusCode).toBe(200);
    expect(response.json().checks).not.toHaveProperty("policyDatabase");
    expect(calls).toBe(0);
  });
});

/**
 * Capability independence through the REAL createApp: policy management is
 * independent of tenant HTTP reads/writes, machine and marketplace families.
 * The accepted policy store readiness composes the restricted tenant base
 * readiness, so only authReady + policyReady are consulted and NO tenantReady
 * callback is accepted or invoked.
 */
describe("control capability independence through createApp", () => {
  function independenceApp(options: {
    readonly authReady?: () => Promise<boolean>;
    readonly policyReady?: () => Promise<boolean>;
  }): App {
    const config = loadConfig({
      NODE_ENV: "test",
      APP_ORIGIN: ORIGIN,
      COMMIT_SHA: BUILD_SHA,
      AUTH_ENABLED: "true",
      AUTH_DATABASE_URL: AUTH_URL,
      AUTH_SECRET: "synthetic_auth_secret_for_control_integration_012",
      AUTH_RP_ID: "localhost",
      TENANT_DATABASE_URL: TENANT_URL,
      POLICY_MANAGEMENT_ENABLED: "true",
    });
    // Valid config: every independent tenant/market/machine flag is OFF.
    expect(config.TENANT_READS_ENABLED).toBe(false);
    expect(config.TENANT_WRITES_ENABLED).toBe(false);
    expect(config.MARKET_CATALOG_ENABLED).toBe(false);
    expect(config.LISTING_MANAGEMENT_ENABLED).toBe(false);
    expect(config.MARKET_MODERATION_ENABLED).toBe(false);
    expect(config.MACHINE_CREDENTIAL_MANAGEMENT_ENABLED).toBe(false);
    expect(config.MACHINE_SESSION_EXCHANGE_ENABLED).toBe(false);
    const app = createApp({
      config,
      logger: false,
      authService: AUTH as unknown as AuthService,
      ...(options.authReady !== undefined ? { authReady: options.authReady } : {}),
      policyManagementService: new PolicyService({ auth: AUTH, store: STORE }),
      ...(options.policyReady !== undefined
        ? { policyReady: options.policyReady }
        : {}),
      // Deliberately NO tenantReady / tenantReady callback is passed: the
      // capability must not require one.
    });
    apps.push(app);
    return app;
  }

  async function capabilityState(app: App): Promise<string> {
    const response = await app.inject({
      method: "GET",
      url: CONTROL_CAPABILITIES_PATH,
    });
    expect(response.statusCode).toBe(200);
    const parsed = ControlCapabilitiesSuccessEnvelopeSchema.parse(
      response.json(),
    );
    return parsed.data.capabilities[0]?.state ?? "";
  }

  it("enables the capability and mounts the ten routes with tenant/market/machine all off", async () => {
    const app = independenceApp({
      authReady: async () => true,
      policyReady: async () => true,
    });
    expect(actualRoutes(app).size).toBe(10);
    await expect(capabilityState(app)).resolves.toBe("enabled");
  });

  it("reports unavailable when the policy readiness callback is missing or false", async () => {
    const missing = independenceApp({ authReady: async () => true });
    await expect(capabilityState(missing)).resolves.toBe("unavailable");
    const failing = independenceApp({
      authReady: async () => true,
      policyReady: async () => false,
    });
    await expect(capabilityState(failing)).resolves.toBe("unavailable");
  });

  it("reports unavailable when the auth readiness callback is missing or false", async () => {
    const missing = independenceApp({ policyReady: async () => true });
    await expect(capabilityState(missing)).resolves.toBe("unavailable");
    const failing = independenceApp({
      authReady: async () => false,
      policyReady: async () => true,
    });
    await expect(capabilityState(failing)).resolves.toBe("unavailable");
  });
});

describe("old public inventories remain byte-equivalent", () => {
  it("serves the unchanged legacy 5/41 commerce and 3/18 marketplace manifests", async () => {
    const app = build({ enabled: false });

    const legacy = await app.inject({
      method: "GET",
      url: COMMERCE_CAPABILITIES_PATH,
    });
    expect(legacy.statusCode).toBe(200);
    const commerce = CommerceCapabilitiesSuccessEnvelopeSchema.parse(
      legacy.json(),
    );
    expect(commerce.data.routes).toEqual(COMMERCE_ROUTES);
    expect(commerce.data.routes).toHaveLength(41);

    const marketplace = await app.inject({
      method: "GET",
      url: MARKETPLACE_CAPABILITIES_PATH,
    });
    expect(marketplace.statusCode).toBe(200);
    const parsedMarket = MarketplaceCapabilitiesSuccessEnvelopeSchema.parse(
      marketplace.json(),
    );
    expect(parsedMarket.data.routes).toEqual(MARKETPLACE_ROUTES);
    expect(parsedMarket.data.routes).toHaveLength(18);

    const control = await app.inject({
      method: "GET",
      url: CONTROL_CAPABILITIES_PATH,
    });
    expect(control.statusCode).toBe(200);
    const parsedControl = ControlCapabilitiesSuccessEnvelopeSchema.parse(
      control.json(),
    );
    expect(parsedControl.data.routes).toHaveLength(10);
    expect(parsedControl.data.routes).not.toEqual(MARKETPLACE_ROUTES);
    expect(parsedControl.data.routes).not.toEqual(COMMERCE_ROUTES);
    // A separate registry: the control paths never appear in the old arrays.
    const oldPaths = new Set([
      ...MARKETPLACE_ROUTES.map((route) => route.path),
      ...COMMERCE_ROUTES.map((route) => route.path),
    ]);
    for (const route of CONTROL_ROUTES) {
      expect(oldPaths.has(route.path), route.path).toBe(false);
    }
  });
});
