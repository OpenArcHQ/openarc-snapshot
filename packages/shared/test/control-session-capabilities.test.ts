import { describe, expect, expectTypeOf, it } from "vitest";

import {
  COMMERCE_API_SCHEMA_VERSION,
  CommerceApiMetaSchema,
} from "../src/commerce/api.js";
import {
  COMMERCE_CAPABILITY_FAMILY_ORDER,
  COMMERCE_ROUTES,
} from "../src/commerce/capabilities.js";
import {
  MARKETPLACE_CAPABILITY_FAMILY_ORDER,
  MARKETPLACE_ROUTES,
} from "../src/commerce/market-capabilities.js";
import {
  SESSION_CAPABILITIES_PATH,
  SESSION_CAPABILITY_AUDIENCE,
  SESSION_CAPABILITY_DEPENDENCIES,
  SESSION_CAPABILITY_DEPENDENCY_LENGTH,
  SESSION_CAPABILITY_DEPENDENCY_ORDER,
  SESSION_CAPABILITY_ENTRIES,
  SESSION_CAPABILITY_FAMILY_ORDER,
  SESSION_CAPABILITY_MANIFEST,
  SESSION_CAPABILITY_STATE,
  SESSION_CAPABILITY_VERSION,
  SESSION_ROUTES,
  SESSION_ROUTE_IDS,
  SESSION_ROUTE_INDEX,
  SessionCapabilitiesSuccessEnvelopeSchema,
  SessionCapabilityEntrySchema,
  SessionCapabilityManifestSchema,
  SessionRouteDescriptorSchema,
  type SessionCapabilityFamily,
} from "../src/commerce/control-session-capabilities.js";

const SCHEMA = "openarc.api.v2" as const;
const REQUEST_ID = "9f1c2d34-5e6a-4b7c-8d9e-0f1a2b3c4d5e";
const BUILD_SHA = "0123456789abcdef0123456789abcdef01234567";
const CANARY = "SECRET_CANARY_DO_NOT_ECHO";

const META = {
  schemaVersion: SCHEMA,
  requestId: REQUEST_ID,
  buildSha: BUILD_SHA,
} as const;

const SESSION_DEPENDENCIES = [
  "auth",
  "tenantDatabase",
  "machineDatabase",
  "policyDatabase",
  "commerceSessionDatabase",
] as const;

/** Expected inventory transcribed literally from the frozen task.md. */
const EXPECTED_ROUTES: readonly {
  readonly id: string;
  readonly family: SessionCapabilityFamily;
  readonly audience: "browser" | "agent";
  readonly method: "GET" | "POST";
  readonly path: string;
}[] = [
  { id: "commerce_session_list", family: "commerce_session_management", audience: "browser", method: "GET", path: "/v2/control/organizations/:organizationId/commerce-sessions" },
  { id: "commerce_session_issue", family: "commerce_session_management", audience: "browser", method: "POST", path: "/v2/control/organizations/:organizationId/commerce-sessions" },
  { id: "commerce_session_status", family: "commerce_session_management", audience: "browser", method: "GET", path: "/v2/control/organizations/:organizationId/commerce-sessions/:sessionId" },
  { id: "commerce_session_revoke", family: "commerce_session_management", audience: "browser", method: "POST", path: "/v2/control/organizations/:organizationId/commerce-sessions/:sessionId/revoke" },
  { id: "commerce_session_human_mutation_status", family: "commerce_session_management", audience: "browser", method: "GET", path: "/v2/control/organizations/:organizationId/commerce-session-mutations/:mutationId" },
  { id: "commerce_session_exchange", family: "commerce_session_exchange", audience: "agent", method: "POST", path: "/v2/agent/commerce-sessions/exchange" },
  { id: "commerce_session_agent_mutation_status", family: "commerce_session_exchange", audience: "agent", method: "GET", path: "/v2/agent/commerce-session-mutations/:mutationId" },
];

const EXPECTED_ENTRIES = [
  {
    family: "commerce_session_management",
    audience: "browser",
    state: "enabled",
    dependencies: [...SESSION_DEPENDENCIES],
  },
  {
    family: "commerce_session_exchange",
    audience: "agent",
    state: "enabled",
    dependencies: [...SESSION_DEPENDENCIES],
  },
] as const;

describe("session capability contract constants", () => {
  it("publishes the exact path, version, environment and network", () => {
    expect(SESSION_CAPABILITIES_PATH).toBe("/v2/public/session-capabilities");
    expect(SESSION_CAPABILITY_VERSION).toBe(
      "openarc.capabilities.commerce-sessions.v1",
    );
    expect(SESSION_CAPABILITY_MANIFEST.environment).toBe("testnet");
    expect(SESSION_CAPABILITY_MANIFEST.network).toBe("eip155:5042002");
    expect(SESSION_CAPABILITY_MANIFEST.capabilityVersion).toBe(
      "openarc.capabilities.commerce-sessions.v1",
    );
  });

  it("freezes exactly two families in the deterministic order", () => {
    expect(SESSION_CAPABILITY_FAMILY_ORDER).toEqual([
      "commerce_session_management",
      "commerce_session_exchange",
    ]);
    expect(
      SESSION_CAPABILITY_MANIFEST.capabilities.map((entry) => entry.family),
    ).toEqual(["commerce_session_management", "commerce_session_exchange"]);
  });

  it("freezes exact audience and ordered five-token dependency array", () => {
    expect(SESSION_CAPABILITY_AUDIENCE).toEqual({
      commerce_session_management: "browser",
      commerce_session_exchange: "agent",
    });
    expect(SESSION_CAPABILITY_DEPENDENCIES.commerce_session_management).toEqual(
      [...SESSION_DEPENDENCIES],
    );
    expect(SESSION_CAPABILITY_DEPENDENCIES.commerce_session_exchange).toEqual([
      ...SESSION_DEPENDENCIES,
    ]);
    expect(SESSION_CAPABILITY_DEPENDENCY_ORDER).toEqual([
      ...SESSION_DEPENDENCIES,
    ]);
    expect(SESSION_CAPABILITY_DEPENDENCY_LENGTH).toBe(5);
  });

  it("shares one published state across both entries", () => {
    expect(SESSION_CAPABILITY_STATE).toBe("enabled");
    for (const entry of SESSION_CAPABILITY_ENTRIES) {
      expect(entry.state).toBe(SESSION_CAPABILITY_STATE);
    }
  });

  it("deeply freezes family order, audience, dependencies and manifest", () => {
    expect(Object.isFrozen(SESSION_CAPABILITY_FAMILY_ORDER)).toBe(true);
    expect(Object.isFrozen(SESSION_CAPABILITY_AUDIENCE)).toBe(true);
    expect(Object.isFrozen(SESSION_CAPABILITY_DEPENDENCIES)).toBe(true);
    for (const family of SESSION_CAPABILITY_FAMILY_ORDER) {
      expect(Object.isFrozen(SESSION_CAPABILITY_DEPENDENCIES[family])).toBe(
        true,
      );
    }
    expect(Object.isFrozen(SESSION_CAPABILITY_DEPENDENCY_ORDER)).toBe(true);
    expect(Object.isFrozen(SESSION_CAPABILITY_ENTRIES)).toBe(true);
    for (const entry of SESSION_CAPABILITY_ENTRIES) {
      expect(Object.isFrozen(entry)).toBe(true);
      expect(Object.isFrozen(entry.dependencies)).toBe(true);
    }
    expect(Object.isFrozen(SESSION_CAPABILITY_MANIFEST)).toBe(true);
    // Zod clones parsed input, so the parsed manifest layers are distinct
    // objects; assert every nested layer of the published manifest is frozen.
    expect(Object.isFrozen(SESSION_CAPABILITY_MANIFEST.capabilities)).toBe(
      true,
    );
    expect(Object.isFrozen(SESSION_CAPABILITY_MANIFEST.routes)).toBe(true);
    for (const entry of SESSION_CAPABILITY_MANIFEST.capabilities) {
      expect(Object.isFrozen(entry)).toBe(true);
      expect(Object.isFrozen(entry.dependencies)).toBe(true);
    }
    for (const route of SESSION_CAPABILITY_MANIFEST.routes) {
      expect(Object.isFrozen(route)).toBe(true);
    }
    expect(() => {
      (SESSION_CAPABILITY_AUDIENCE as Record<string, string>)
        .commerce_session_exchange = "browser";
    }).toThrow();
    expect(SESSION_CAPABILITY_AUDIENCE.commerce_session_exchange).toBe("agent");
  });

  it("rejects in-place mutation of every parsed manifest layer", () => {
    const manifest = SESSION_CAPABILITY_MANIFEST;
    const entry = manifest.capabilities[0]!;
    const route = manifest.routes[0]!;
    expect(() => {
      (manifest.capabilities as unknown as unknown[]).push(entry);
    }).toThrow();
    expect(() => {
      (manifest.routes as unknown as unknown[]).push(route);
    }).toThrow();
    expect(() => {
      (route as { path: string }).path = "/v2/control/evil";
    }).toThrow();
    expect(() => {
      (route as { method: string }).method = "DELETE";
    }).toThrow();
    expect(() => {
      (entry as { state: string }).state = "unavailable";
    }).toThrow();
    expect(() => {
      (entry.dependencies as unknown as unknown[]).push("marketDatabase");
    }).toThrow();
    expect(() => {
      (entry.dependencies as unknown as unknown[])[0] = "marketDatabase";
    }).toThrow();
    expect(manifest.capabilities).toHaveLength(2);
    expect(manifest.routes).toHaveLength(7);
    expect(route.path).toBe(EXPECTED_ROUTES[0]!.path);
    expect(route.method).toBe(EXPECTED_ROUTES[0]!.method);
    expect(entry.state).toBe("enabled");
    expect(entry.dependencies).toEqual([...SESSION_DEPENDENCIES]);
    expect(manifest).toEqual(
      SessionCapabilityManifestSchema.parse({
        capabilityVersion: "openarc.capabilities.commerce-sessions.v1",
        environment: "testnet",
        network: "eip155:5042002",
        capabilities: EXPECTED_ENTRIES,
        routes: EXPECTED_ROUTES,
      }),
    );
  });

  it("does not import payment/execution authority into session language", () => {
    const serialized = JSON.stringify(SESSION_CAPABILITY_MANIFEST);
    expect(/grant|payment|settlement|execution|wallet|spend/i.test(serialized))
      .toBe(false);
    for (const route of SESSION_ROUTES) {
      expect(/payment|execution|wallet|grant/i.test(route.path)).toBe(false);
    }
  });

  it("does not disturb the legacy 5-family / 41-route registry", () => {
    expect(COMMERCE_CAPABILITY_FAMILY_ORDER).toHaveLength(5);
    expect(COMMERCE_ROUTES).toHaveLength(41);
  });

  it("does not disturb the marketplace 3-family / 18-route registry", () => {
    expect(MARKETPLACE_CAPABILITY_FAMILY_ORDER).toHaveLength(3);
    expect(MARKETPLACE_ROUTES).toHaveLength(18);
  });
});

describe("frozen session route registry", () => {
  it("has exactly 7 unique routes in the frozen order", () => {
    expect(SESSION_ROUTES).toHaveLength(7);
    expect(SESSION_ROUTE_IDS).toHaveLength(7);
    expect(new Set(SESSION_ROUTE_IDS).size).toBe(7);
    expect(SESSION_ROUTE_IDS).toEqual(EXPECTED_ROUTES.map((route) => route.id));
    for (const route of SESSION_ROUTES) {
      expect(route.audience).toBe(
        SESSION_CAPABILITY_AUDIENCE[route.family],
      );
    }
  });

  it("maps one-to-one against the literal frozen inventory", () => {
    expect(EXPECTED_ROUTES).toHaveLength(7);
    expect(
      new Set(EXPECTED_ROUTES.map((route) => `${route.method} ${route.path}`))
        .size,
    ).toBe(7);
    for (const expected of EXPECTED_ROUTES) {
      const actual = SESSION_ROUTE_INDEX[expected.id];
      expect(actual, `missing id ${expected.id}`).toBeDefined();
      expect(actual).toMatchObject(expected);
    }
    for (const actual of SESSION_ROUTES) {
      const expected = EXPECTED_ROUTES.find((route) => route.id === actual.id);
      expect(expected, `extra id ${actual.id}`).toBeDefined();
      expect(actual).toMatchObject(expected as object);
    }
  });

  it("excludes capability/grant/payment descriptors", () => {
    const paths = SESSION_ROUTES.map((route) => route.path);
    expect(paths).not.toContain(SESSION_CAPABILITIES_PATH);
    for (const route of SESSION_ROUTES) {
      expect(route.method === "GET" || route.method === "POST").toBe(true);
      expect(/manifest|health|fallback|checkout|capacity|grant|payment/i.test(route.path))
        .toBe(false);
      expect(
        route.path.startsWith("/v2/control/organizations/:organizationId/") ||
          route.path.startsWith("/v2/agent/"),
      ).toBe(true);
    }
  });

  it("is deeply frozen so callers cannot mutate global truth", () => {
    expect(Object.isFrozen(SESSION_ROUTES)).toBe(true);
    for (const route of SESSION_ROUTES) {
      expect(Object.isFrozen(route)).toBe(true);
    }
    expect(Object.isFrozen(SESSION_ROUTE_IDS)).toBe(true);
    expect(Object.isFrozen(SESSION_ROUTE_INDEX)).toBe(true);
  });

  it("accepts every frozen descriptor and rejects altered tuples", () => {
    for (const route of EXPECTED_ROUTES) {
      expect(
        SessionRouteDescriptorSchema.safeParse(route).success,
        route.id,
      ).toBe(true);
    }
    const first = EXPECTED_ROUTES[0] as (typeof EXPECTED_ROUTES)[number];
    const exchange = EXPECTED_ROUTES[5] as (typeof EXPECTED_ROUTES)[number];
    const bad: unknown[] = [
      { ...first, method: "POST" },
      { ...first, path: `${first.path}/:sessionId` },
      { ...first, audience: "agent" },
      { ...first, family: "commerce_session_exchange" },
      { ...EXPECTED_ROUTES[1], method: "GET" },
      { ...EXPECTED_ROUTES[2], method: "POST" },
      { ...exchange, audience: "browser" },
      { ...exchange, method: "GET" },
      { ...first, id: "commerce_session_unknown" },
      { ...first, id: "Commerce_Session_List" },
      { ...first, id: "toString" },
      { ...first, id: "constructor" },
      { ...first, id: "__proto__" },
      { ...first, id: "hasOwnProperty" },
      { ...first, path: `${first.path}?x=1` },
      { ...first, path: `https://evil.example${first.path}` },
      { ...first, path: `${first.path}/${CANARY}` },
      { ...first, path: "" },
      { ...first, path: `/${"a".repeat(513)}` },
      { ...first, extra: CANARY },
    ];
    for (const route of bad) {
      expect(
        SessionRouteDescriptorSchema.safeParse(route).success,
        JSON.stringify(route),
      ).toBe(false);
    }
  });
});

describe("session entry validity and fail-closed input", () => {
  it("accepts exactly the three canonical states", () => {
    for (const state of ["enabled", "built_disabled", "unavailable"] as const) {
      expect(
        SessionCapabilityEntrySchema.safeParse({
          family: "commerce_session_management",
          audience: "browser",
          state,
          dependencies: [...SESSION_DEPENDENCIES],
        }).success,
        state,
      ).toBe(true);
    }
  });

  it("rejects invalid state, audience, dependency and extra keys", () => {
    const valid = {
      family: "commerce_session_management",
      audience: "browser",
      state: "enabled",
      dependencies: [...SESSION_DEPENDENCIES],
    } as const;
    const bad: unknown[] = [
      { ...valid, state: "planned" },
      { ...valid, state: "unknown" },
      { ...valid, state: "ENABLED" },
      { ...valid, state: "" },
      { ...valid, audience: "public" },
      { ...valid, audience: "machine" },
      { ...valid, family: "commerce_session_exchange" },
      { ...valid, dependencies: SESSION_DEPENDENCIES.slice(0, 4) },
      {
        ...valid,
        dependencies: [...SESSION_DEPENDENCIES, "marketDatabase"],
      },
      {
        ...valid,
        dependencies: [
          "commerceSessionDatabase",
          "policyDatabase",
          "machineDatabase",
          "tenantDatabase",
          "auth",
        ],
      },
      {
        ...valid,
        dependencies: ["auth", "tenantDatabase", "machineDatabase", "policyDatabase"],
      },
      {
        ...valid,
        dependencies: ["auth", "tenantDatabase", "machineDatabase", "policyDatabase", "marketDatabase"],
      },
      {
        ...valid,
        dependencies: ["auth", "tenantDatabase", "machineDatabase", "policyDatabase", "policyDatabase"],
      },
      { ...valid, dependencies: "auth" },
      { ...valid, dependencies: [] },
      { ...valid, extra: CANARY },
      {
        ...valid,
        dependencies: [...SESSION_DEPENDENCIES, CANARY],
      },
    ];
    for (const candidate of bad) {
      expect(
        SessionCapabilityEntrySchema.safeParse(candidate).success,
        JSON.stringify(candidate),
      ).toBe(false);
    }
  });

  it("safeParse never throws on arbitrary malformed bounded input", () => {
    const samples: unknown[] = [
      undefined,
      null,
      0,
      "",
      "x",
      true,
      [],
      {},
      { capabilities: null, routes: {} },
      { auth: true },
      { ...EXPECTED_ROUTES[0], method: 7, path: {} },
      { family: "unknown", audience: "browser", state: "enabled", dependencies: [] },
    ];
    for (const sample of samples) {
      expect(() => SessionCapabilityEntrySchema.safeParse(sample)).not.toThrow();
      expect(() => SessionRouteDescriptorSchema.safeParse(sample)).not.toThrow();
      expect(() => SessionCapabilityManifestSchema.safeParse(sample)).not.toThrow();
    }
  });
});

describe("session manifest schema and whole envelope", () => {
  it("validates the frozen manifest and exposes a strict success envelope", () => {
    expect(
      SessionCapabilityManifestSchema.safeParse(SESSION_CAPABILITY_MANIFEST)
        .success,
    ).toBe(true);
    const envelope = {
      ok: true as const,
      data: SESSION_CAPABILITY_MANIFEST,
      meta: META,
    };
    expect(
      SessionCapabilitiesSuccessEnvelopeSchema.safeParse(envelope).success,
    ).toBe(true);
    expect(CommerceApiMetaSchema.safeParse(META).success).toBe(true);
    expect(COMMERCE_API_SCHEMA_VERSION).toBe("openarc.api.v2");
  });

  it("rejects extra envelope keys, wrong ok and bad meta", () => {
    const envelope = {
      ok: true as const,
      data: SESSION_CAPABILITY_MANIFEST,
      meta: META,
    };
    const bad: unknown[] = [
      { ...envelope, extra: CANARY },
      { ...envelope, ok: false },
      { ok: true, data: SESSION_CAPABILITY_MANIFEST },
      {
        ok: true,
        data: { ...SESSION_CAPABILITY_MANIFEST, secretConfig: CANARY },
        meta: META,
      },
      { ...envelope, meta: { ...META, buildSha: "zz" } },
    ];
    for (const candidate of bad) {
      expect(
        SessionCapabilitiesSuccessEnvelopeSchema.safeParse(candidate).success,
        JSON.stringify(candidate).slice(0, 80),
      ).toBe(false);
    }
  });

  it("rejects mismatched shared states across the two entries", () => {
    const valid = SESSION_CAPABILITY_MANIFEST;
    const mismatched = {
      ...valid,
      capabilities: [
        valid.capabilities[0],
        { ...valid.capabilities[1], state: "built_disabled" },
      ],
    };
    expect(SessionCapabilityManifestSchema.safeParse(mismatched).success).toBe(
      false,
    );
  });

  it("rejects incomplete, duplicated, reordered and extra inventories", () => {
    const valid = SESSION_CAPABILITY_MANIFEST;
    const missingFamily = { ...valid, capabilities: [] };
    const duplicateFamily = {
      ...valid,
      capabilities: [valid.capabilities[0], valid.capabilities[0]],
    };
    const missingRoute = { ...valid, routes: valid.routes.slice(0, 6) };
    const extraRoute = {
      ...valid,
      routes: [...valid.routes, { ...valid.routes[0], id: "commerce_session_extra" }],
    };
    const reorderedRoutes = { ...valid, routes: [...valid.routes].reverse() };
    const swappedRoutes = {
      ...valid,
      routes: [valid.routes[1], valid.routes[0], ...valid.routes.slice(2)],
    };
    const reorderedFamilies = {
      ...valid,
      capabilities: [valid.capabilities[1], valid.capabilities[0]],
    };
    const unknownFamily = {
      ...valid,
      capabilities: [
        { ...valid.capabilities[0], family: "commerce_session_other" },
        valid.capabilities[1],
      ],
    };
    for (const candidate of [
      missingFamily,
      duplicateFamily,
      missingRoute,
      extraRoute,
      reorderedRoutes,
      swappedRoutes,
      reorderedFamilies,
      unknownFamily,
    ]) {
      expect(
        SessionCapabilityManifestSchema.safeParse(candidate).success,
        JSON.stringify(candidate).slice(0, 80),
      ).toBe(false);
    }
  });

  it("rejects altered version, network/environment and extra top-level fields", () => {
    const valid = SESSION_CAPABILITY_MANIFEST;
    const alteredVersion = {
      ...valid,
      capabilityVersion: "openarc.capabilities.control.v1",
    };
    const alteredNetwork = { ...valid, network: "eip155:1" };
    const alteredEnvironment = { ...valid, environment: "mainnet" };
    const extraTop = { ...valid, secretConfig: CANARY };
    for (const candidate of [
      alteredVersion,
      alteredNetwork,
      alteredEnvironment,
      extraTop,
    ]) {
      expect(
        SessionCapabilityManifestSchema.safeParse(candidate).success,
        JSON.stringify(candidate).slice(0, 80),
      ).toBe(false);
    }
  });

  it("rejects altered descriptor tuples inside the manifest", () => {
    const valid = SESSION_CAPABILITY_MANIFEST;
    const alteredMethod = {
      ...valid,
      routes: valid.routes.map((route) =>
        route.id === "commerce_session_issue" ? { ...route, method: "GET" } : route,
      ),
    };
    const alteredPath = {
      ...valid,
      routes: valid.routes.map((route) =>
        route.id === "commerce_session_list"
          ? { ...route, path: "/v2/control/organizations/:organizationId/x" }
          : route,
      ),
    };
    const alteredAudience = {
      ...valid,
      routes: valid.routes.map((route) => ({
        ...route,
        audience: "browser",
      })),
    };
    for (const candidate of [alteredMethod, alteredPath, alteredAudience]) {
      expect(
        SessionCapabilityManifestSchema.safeParse(candidate).success,
      ).toBe(false);
    }
  });
});

describe("static typing", () => {
  it("narrows manifest and entry types", () => {
    expectTypeOf(SESSION_CAPABILITY_MANIFEST.capabilityVersion)
      .toEqualTypeOf<"openarc.capabilities.commerce-sessions.v1">();
    expectTypeOf(SESSION_CAPABILITY_MANIFEST.capabilities[0]?.state)
      .toEqualTypeOf<
        "enabled" | "built_disabled" | "unavailable" | undefined
      >();
    expectTypeOf(SESSION_CAPABILITY_MANIFEST.capabilities[0]?.family)
      .toEqualTypeOf<
        "commerce_session_management" | "commerce_session_exchange" | undefined
      >();
  });
});
