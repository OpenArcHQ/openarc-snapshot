import { describe, expect, expectTypeOf, it } from "vitest";

import { COMMERCE_API_SCHEMA_VERSION, CommerceApiMetaSchema } from "../src/commerce/api.js";
import {
  COMMERCE_CAPABILITY_DEPENDENCIES,
  COMMERCE_CAPABILITY_FAMILY_ORDER,
  COMMERCE_ROUTES,
} from "../src/commerce/capabilities.js";
import {
  MARKETPLACE_CAPABILITY_DEPENDENCIES,
  MARKETPLACE_CAPABILITY_FAMILY_ORDER,
  MARKETPLACE_ROUTES,
} from "../src/commerce/market-capabilities.js";
import {
  CONTROL_CAPABILITY_AUDIENCE,
  CONTROL_CAPABILITY_DEPENDENCIES,
  CONTROL_CAPABILITY_DEPENDENCY_LENGTH,
  CONTROL_CAPABILITY_DEPENDENCY_ORDER,
  CONTROL_CAPABILITY_ENTRY,
  CONTROL_CAPABILITY_FAMILY_ORDER,
  CONTROL_CAPABILITY_MANIFEST,
  CONTROL_CAPABILITY_VERSION,
  CONTROL_CAPABILITIES_PATH,
  CONTROL_ROUTES,
  CONTROL_ROUTE_IDS,
  CONTROL_ROUTE_INDEX,
  ControlCapabilitiesSuccessEnvelopeSchema,
  ControlCapabilityEntrySchema,
  ControlCapabilityManifestSchema,
  ControlRouteDescriptorSchema,
  type ControlCapabilityFamily,
} from "../src/commerce/control-capabilities.js";

const SCHEMA = "openarc.api.v2" as const;
const REQUEST_ID = "9f1c2d34-5e6a-4b7c-8d9e-0f1a2b3c4d5e";
const BUILD_SHA = "0123456789abcdef0123456789abcdef01234567";
const CANARY = "SECRET_CANARY_DO_NOT_ECHO";

const META = {
  schemaVersion: SCHEMA,
  requestId: REQUEST_ID,
  buildSha: BUILD_SHA,
} as const;

/** Expected inventory transcribed literally from the frozen task.md. */
const EXPECTED_ROUTES: readonly {
  readonly id: string;
  readonly family: ControlCapabilityFamily;
  readonly audience: "browser";
  readonly method: "GET" | "POST";
  readonly path: string;
}[] = [
  { id: "policy_roots", family: "policy_management", audience: "browser", method: "GET", path: "/v2/control/organizations/:organizationId/policies" },
  { id: "policy_create", family: "policy_management", audience: "browser", method: "POST", path: "/v2/control/organizations/:organizationId/policies" },
  { id: "policy_root", family: "policy_management", audience: "browser", method: "GET", path: "/v2/control/organizations/:organizationId/policies/:policyId" },
  { id: "policy_revisions", family: "policy_management", audience: "browser", method: "GET", path: "/v2/control/organizations/:organizationId/policies/:policyId/revisions" },
  { id: "policy_revision_create", family: "policy_management", audience: "browser", method: "POST", path: "/v2/control/organizations/:organizationId/policies/:policyId/revisions" },
  { id: "policy_revision", family: "policy_management", audience: "browser", method: "GET", path: "/v2/control/organizations/:organizationId/policies/:policyId/revisions/:revision" },
  { id: "policy_pause", family: "policy_management", audience: "browser", method: "POST", path: "/v2/control/organizations/:organizationId/policies/:policyId/pause" },
  { id: "policy_resume", family: "policy_management", audience: "browser", method: "POST", path: "/v2/control/organizations/:organizationId/policies/:policyId/resume" },
  { id: "policy_revoke", family: "policy_management", audience: "browser", method: "POST", path: "/v2/control/organizations/:organizationId/policies/:policyId/revoke" },
  { id: "policy_mutation_status", family: "policy_management", audience: "browser", method: "GET", path: "/v2/control/organizations/:organizationId/policy-mutations/:mutationId" },
];

describe("control capability contract constants", () => {
  it("publishes the exact path, version, environment and network", () => {
    expect(CONTROL_CAPABILITIES_PATH).toBe("/v2/public/control-capabilities");
    expect(CONTROL_CAPABILITY_VERSION).toBe(
      "openarc.capabilities.control.v1",
    );
    expect(CONTROL_CAPABILITY_MANIFEST.environment).toBe("testnet");
    expect(CONTROL_CAPABILITY_MANIFEST.network).toBe("eip155:5042002");
    expect(CONTROL_CAPABILITY_MANIFEST.capabilityVersion).toBe(
      "openarc.capabilities.control.v1",
    );
  });

  it("freezes exactly one policy_management family in deterministic order", () => {
    expect(CONTROL_CAPABILITY_FAMILY_ORDER).toEqual(["policy_management"]);
    expect(
      CONTROL_CAPABILITY_MANIFEST.capabilities.map((entry) => entry.family),
    ).toEqual(["policy_management"]);
  });

  it("freezes exact audience and ordered dependency array", () => {
    expect(CONTROL_CAPABILITY_AUDIENCE).toEqual({
      policy_management: "browser",
    });
    expect(CONTROL_CAPABILITY_DEPENDENCIES.policy_management).toEqual([
      "auth",
      "tenantDatabase",
      "policyDatabase",
    ]);
    expect(CONTROL_CAPABILITY_DEPENDENCY_ORDER).toEqual([
      "auth",
      "tenantDatabase",
      "policyDatabase",
    ]);
    expect(CONTROL_CAPABILITY_DEPENDENCY_LENGTH).toBe(3);
  });

  it("deeply freezes family order, audience, dependencies and manifest", () => {
    expect(Object.isFrozen(CONTROL_CAPABILITY_FAMILY_ORDER)).toBe(true);
    expect(Object.isFrozen(CONTROL_CAPABILITY_AUDIENCE)).toBe(true);
    expect(Object.isFrozen(CONTROL_CAPABILITY_DEPENDENCIES)).toBe(true);
    expect(
      Object.isFrozen(CONTROL_CAPABILITY_DEPENDENCIES.policy_management),
    ).toBe(true);
    expect(Object.isFrozen(CONTROL_CAPABILITY_DEPENDENCY_ORDER)).toBe(true);
    expect(Object.isFrozen(CONTROL_CAPABILITY_ENTRY)).toBe(true);
    expect(Object.isFrozen(CONTROL_CAPABILITY_ENTRY.dependencies)).toBe(true);
    expect(Object.isFrozen(CONTROL_CAPABILITY_MANIFEST)).toBe(true);
    // Zod clones parsed input, so the parsed manifest layers are distinct
    // objects; assert every nested layer of the published manifest is frozen.
    expect(Object.isFrozen(CONTROL_CAPABILITY_MANIFEST.capabilities)).toBe(
      true,
    );
    expect(Object.isFrozen(CONTROL_CAPABILITY_MANIFEST.routes)).toBe(true);
    for (const entry of CONTROL_CAPABILITY_MANIFEST.capabilities) {
      expect(Object.isFrozen(entry)).toBe(true);
      expect(Object.isFrozen(entry.dependencies)).toBe(true);
    }
    for (const route of CONTROL_CAPABILITY_MANIFEST.routes) {
      expect(Object.isFrozen(route)).toBe(true);
    }
    expect(() => {
      (CONTROL_CAPABILITY_AUDIENCE as Record<string, string>)
        .policy_management = "public";
    }).toThrow();
    expect(CONTROL_CAPABILITY_AUDIENCE.policy_management).toBe("browser");
  });

  it("rejects in-place mutation of every parsed manifest layer", () => {
    const manifest = CONTROL_CAPABILITY_MANIFEST;
    const entry = manifest.capabilities[0]!;
    const route = manifest.routes[0]!;
    // Array-level pushes are rejected in strict mode.
    expect(() => {
      (manifest.capabilities as unknown as unknown[]).push(entry);
    }).toThrow();
    expect(() => {
      (manifest.routes as unknown as unknown[]).push(route);
    }).toThrow();
    // Route descriptor tuple fields are non-writable.
    expect(() => {
      (route as { path: string }).path = "/v2/control/evil";
    }).toThrow();
    expect(() => {
      (route as { method: string }).method = "DELETE";
    }).toThrow();
    // Capability entry state and dependency array are non-writable.
    expect(() => {
      (entry as { state: string }).state = "unavailable";
    }).toThrow();
    expect(() => {
      (entry.dependencies as unknown as unknown[]).push("marketDatabase");
    }).toThrow();
    expect(() => {
      (entry.dependencies as unknown as unknown[])[0] = "marketDatabase";
    }).toThrow();
    // Frozen truth is intact after every rejected mutation attempt.
    expect(manifest.capabilities).toHaveLength(1);
    expect(manifest.routes).toHaveLength(10);
    expect(route.path).toBe(EXPECTED_ROUTES[0]!.path);
    expect(route.method).toBe(EXPECTED_ROUTES[0]!.method);
    expect(entry.state).toBe("enabled");
    expect(entry.dependencies).toEqual([
      "auth",
      "tenantDatabase",
      "policyDatabase",
    ]);
    expect(manifest).toEqual(
      ControlCapabilityManifestSchema.parse({
        capabilityVersion: "openarc.capabilities.control.v1",
        environment: "testnet",
        network: "eip155:5042002",
        capabilities: [
          {
            family: "policy_management",
            audience: "browser",
            state: "enabled",
            dependencies: ["auth", "tenantDatabase", "policyDatabase"],
          },
        ],
        routes: EXPECTED_ROUTES,
      }),
    );
  });

  it("does not import payment/execution authority into control language", () => {
    const serialized = JSON.stringify(CONTROL_CAPABILITY_MANIFEST);
    expect(/grant|payment|settlement|execution|wallet|spend/i.test(serialized))
      .toBe(false);
    for (const route of CONTROL_ROUTES) {
      expect(/payment|execution|wallet|grant/i.test(route.path)).toBe(false);
    }
  });

  it("does not disturb the legacy 5-family / 41-route registry", () => {
    expect(COMMERCE_CAPABILITY_FAMILY_ORDER).toHaveLength(5);
    expect(COMMERCE_ROUTES).toHaveLength(41);
    expect(COMMERCE_CAPABILITY_DEPENDENCIES.human_accounts).toEqual(["auth"]);
  });

  it("does not disturb the marketplace 3-family / 18-route registry", () => {
    expect(MARKETPLACE_CAPABILITY_FAMILY_ORDER).toHaveLength(3);
    expect(MARKETPLACE_ROUTES).toHaveLength(18);
    expect(MARKETPLACE_CAPABILITY_DEPENDENCIES.public_catalog).toEqual([
      "marketDatabase",
    ]);
  });
});

describe("frozen control route registry", () => {
  it("has exactly 10 unique routes in the frozen order", () => {
    expect(CONTROL_ROUTES).toHaveLength(10);
    expect(CONTROL_ROUTE_IDS).toHaveLength(10);
    expect(new Set(CONTROL_ROUTE_IDS).size).toBe(10);
    expect(CONTROL_ROUTE_IDS).toEqual(EXPECTED_ROUTES.map((route) => route.id));
    for (const route of CONTROL_ROUTES) {
      expect(route.family).toBe("policy_management");
      expect(route.audience).toBe("browser");
    }
  });

  it("maps one-to-one against the literal frozen inventory", () => {
    expect(EXPECTED_ROUTES).toHaveLength(10);
    expect(
      new Set(EXPECTED_ROUTES.map((route) => `${route.method} ${route.path}`))
        .size,
    ).toBe(10);
    for (const expected of EXPECTED_ROUTES) {
      const actual = CONTROL_ROUTE_INDEX[expected.id];
      expect(actual, `missing id ${expected.id}`).toBeDefined();
      expect(actual).toMatchObject(expected);
    }
    for (const actual of CONTROL_ROUTES) {
      const expected = EXPECTED_ROUTES.find((route) => route.id === actual.id);
      expect(expected, `extra id ${actual.id}`).toBeDefined();
      expect(actual).toMatchObject(expected as object);
    }
  });

  it("excludes manifest/health/fallback/session/payment descriptors", () => {
    const paths = CONTROL_ROUTES.map((route) => route.path);
    expect(paths).not.toContain(CONTROL_CAPABILITIES_PATH);
    expect(paths).not.toContain("/v1/private/capabilities");
    for (const route of CONTROL_ROUTES) {
      expect(route.method === "GET" || route.method === "POST").toBe(true);
      expect(/manifest|health|fallback|checkout|sessions?|payment/i.test(route.path))
        .toBe(false);
      expect(route.path.startsWith("/v2/control/")).toBe(true);
    }
  });

  it("is deeply frozen so callers cannot mutate global truth", () => {
    expect(Object.isFrozen(CONTROL_ROUTES)).toBe(true);
    for (const route of CONTROL_ROUTES) {
      expect(Object.isFrozen(route)).toBe(true);
    }
    expect(Object.isFrozen(CONTROL_ROUTE_IDS)).toBe(true);
    expect(Object.isFrozen(CONTROL_ROUTE_INDEX)).toBe(true);
  });

  it("accepts every frozen descriptor and rejects altered tuples", () => {
    for (const route of EXPECTED_ROUTES) {
      expect(
        ControlRouteDescriptorSchema.safeParse(route).success,
        route.id,
      ).toBe(true);
    }
    const first = EXPECTED_ROUTES[0] as (typeof EXPECTED_ROUTES)[number];
    const bad: unknown[] = [
      { ...first, method: "POST" },
      { ...first, path: "/v2/control/organizations/:organizationId/policies/:policyId" },
      { ...first, audience: "public" },
      { ...first, family: "marketplace" },
      { ...EXPECTED_ROUTES[1], method: "GET" },
      { ...EXPECTED_ROUTES[5], method: "POST" },
      { ...first, id: "policy_unknown" },
      { ...first, id: "Policy_Roots" },
      { ...first, path: `${first.path}?x=1` },
      { ...first, path: `https://evil.example${first.path}` },
      { ...first, path: `${first.path}/${CANARY}` },
      { ...first, path: "" },
      { ...first, path: `/${"a".repeat(513)}` },
      { ...first, extra: CANARY },
    ];
    for (const route of bad) {
      expect(
        ControlRouteDescriptorSchema.safeParse(route).success,
        JSON.stringify(route),
      ).toBe(false);
    }
  });
});

describe("control entry validity and fail-closed input", () => {
  it("accepts exactly the three frozen states", () => {
    for (const state of ["enabled", "built_disabled", "unavailable"] as const) {
      expect(
        ControlCapabilityEntrySchema.safeParse({
          family: "policy_management",
          audience: "browser",
          state,
          dependencies: ["auth", "tenantDatabase", "policyDatabase"],
        }).success,
        state,
      ).toBe(true);
    }
  });

  it("rejects invalid state, audience, dependency and extra keys", () => {
    const valid = {
      family: "policy_management",
      audience: "browser",
      state: "enabled",
      dependencies: ["auth", "tenantDatabase", "policyDatabase"],
    } as const;
    const bad: unknown[] = [
      { ...valid, state: "planned" },
      { ...valid, state: "ENABLED" },
      { ...valid, state: "" },
      { ...valid, audience: "public" },
      { ...valid, audience: "machine" },
      { ...valid, dependencies: ["auth", "tenantDatabase"] },
      { ...valid, dependencies: ["auth", "tenantDatabase", "policyDatabase", "marketDatabase"] },
      { ...valid, dependencies: ["policyDatabase", "tenantDatabase", "auth"] },
      { ...valid, dependencies: ["auth", "policyDatabase", "tenantDatabase"] },
      { ...valid, dependencies: ["auth", "tenantDatabase", "marketDatabase"] },
      { ...valid, dependencies: ["auth", "tenantDatabase", "policyDatabase", "policyDatabase"] },
      { ...valid, dependencies: "auth" },
      { ...valid, dependencies: [] },
      { ...valid, family: "marketplace" },
      { ...valid, extra: CANARY },
      { ...valid, dependencies: ["auth", "tenantDatabase", "policyDatabase", CANARY] },
    ];
    for (const candidate of bad) {
      expect(
        ControlCapabilityEntrySchema.safeParse(candidate).success,
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
      expect(() => ControlCapabilityEntrySchema.safeParse(sample)).not.toThrow();
      expect(() => ControlRouteDescriptorSchema.safeParse(sample)).not.toThrow();
      expect(() => ControlCapabilityManifestSchema.safeParse(sample)).not.toThrow();
    }
  });
});

describe("control manifest schema and whole envelope", () => {
  it("validates the frozen manifest and exposes a strict success envelope", () => {
    expect(
      ControlCapabilityManifestSchema.safeParse(CONTROL_CAPABILITY_MANIFEST)
        .success,
    ).toBe(true);
    const envelope = {
      ok: true as const,
      data: CONTROL_CAPABILITY_MANIFEST,
      meta: META,
    };
    expect(
      ControlCapabilitiesSuccessEnvelopeSchema.safeParse(envelope).success,
    ).toBe(true);
    expect(CommerceApiMetaSchema.safeParse(META).success).toBe(true);
    expect(COMMERCE_API_SCHEMA_VERSION).toBe("openarc.api.v2");
  });

  it("rejects extra envelope keys, wrong ok and bad meta", () => {
    const envelope = {
      ok: true as const,
      data: CONTROL_CAPABILITY_MANIFEST,
      meta: META,
    };
    const bad: unknown[] = [
      { ...envelope, extra: CANARY },
      { ...envelope, ok: false },
      { ok: true, data: CONTROL_CAPABILITY_MANIFEST },
      { ok: true, data: { ...CONTROL_CAPABILITY_MANIFEST, secretConfig: CANARY }, meta: META },
      { ...envelope, meta: { ...META, buildSha: "zz" } },
    ];
    for (const candidate of bad) {
      expect(
        ControlCapabilitiesSuccessEnvelopeSchema.safeParse(candidate).success,
        JSON.stringify(candidate).slice(0, 80),
      ).toBe(false);
    }
  });

  it("rejects incomplete, duplicated, reordered and extra inventories", () => {
    const valid = CONTROL_CAPABILITY_MANIFEST;
    const missingFamily = { ...valid, capabilities: [] };
    const duplicateFamily = {
      ...valid,
      capabilities: [valid.capabilities[0], valid.capabilities[0]],
    };
    const missingRoute = { ...valid, routes: valid.routes.slice(0, 9) };
    const extraRoute = {
      ...valid,
      routes: [...valid.routes, { ...valid.routes[0], id: "policy_extra" }],
    };
    const reordered = { ...valid, routes: [...valid.routes].reverse() };
    const swapped = {
      ...valid,
      routes: [valid.routes[1], valid.routes[0], ...valid.routes.slice(2)],
    };
    const unknownFamily = {
      ...valid,
      capabilities: [{ ...valid.capabilities[0], family: "payments" }],
    };
    for (const candidate of [
      missingFamily,
      duplicateFamily,
      missingRoute,
      extraRoute,
      reordered,
      swapped,
      unknownFamily,
    ]) {
      expect(
        ControlCapabilityManifestSchema.safeParse(candidate).success,
        JSON.stringify(candidate).slice(0, 80),
      ).toBe(false);
    }
  });

  it("rejects altered version, network/environment and extra top-level fields", () => {
    const valid = CONTROL_CAPABILITY_MANIFEST;
    const alteredVersion = {
      ...valid,
      capabilityVersion: "openarc.capabilities.other.v1",
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
        ControlCapabilityManifestSchema.safeParse(candidate).success,
      ).toBe(false);
    }
  });

  it("rejects altered descriptor tuples inside the manifest", () => {
    const valid = CONTROL_CAPABILITY_MANIFEST;
    const alteredMethod = {
      ...valid,
      routes: valid.routes.map((route) =>
        route.id === "policy_create" ? { ...route, method: "GET" } : route,
      ),
    };
    const alteredPath = {
      ...valid,
      routes: valid.routes.map((route) =>
        route.id === "policy_roots"
          ? { ...route, path: "/v2/control/organizations/:organizationId/x" }
          : route,
      ),
    };
    const alteredAudience = {
      ...valid,
      routes: valid.routes.map((route) => ({
        ...route,
        audience: "public",
      })),
    };
    for (const candidate of [alteredMethod, alteredPath, alteredAudience]) {
      expect(
        ControlCapabilityManifestSchema.safeParse(candidate).success,
      ).toBe(false);
    }
  });
});

describe("static typing", () => {
  it("narrows manifest and entry types", () => {
    expectTypeOf(CONTROL_CAPABILITY_MANIFEST.capabilityVersion)
      .toEqualTypeOf<"openarc.capabilities.control.v1">();
    expectTypeOf(CONTROL_CAPABILITY_MANIFEST.capabilities[0]?.state)
      .toEqualTypeOf<
        "enabled" | "built_disabled" | "unavailable" | undefined
      >();
    expectTypeOf(CONTROL_CAPABILITY_MANIFEST.capabilities[0]?.family)
      .toEqualTypeOf<"policy_management" | undefined>();
  });
});
