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
  CONTROL_CAPABILITY_FAMILY_ORDER,
  CONTROL_ROUTES,
} from "../src/commerce/control-capabilities.js";
import {
  SESSION_CAPABILITY_FAMILY_ORDER,
  SESSION_ROUTES,
} from "../src/commerce/control-session-capabilities.js";
import {
  MARKETPLACE_CAPABILITY_FAMILY_ORDER,
  MARKETPLACE_ROUTES,
} from "../src/commerce/market-capabilities.js";
import {
  ACTION_CAPABILITIES_PATH,
  ACTION_CAPABILITY_AUDIENCE,
  ACTION_CAPABILITY_DEPENDENCIES,
  ACTION_CAPABILITY_DEPENDENCY_LENGTH,
  ACTION_CAPABILITY_DEPENDENCY_ORDER,
  ACTION_CAPABILITY_ENTRIES,
  ACTION_CAPABILITY_FAMILY_ORDER,
  ACTION_CAPABILITY_MANIFEST,
  ACTION_CAPABILITY_STATE,
  ACTION_CAPABILITY_VERSION,
  ACTION_ROUTES,
  ACTION_ROUTE_IDS,
  ACTION_ROUTE_INDEX,
  ActionCapabilitiesSuccessEnvelopeSchema,
  ActionCapabilityEntrySchema,
  ActionCapabilityManifestSchema,
  ActionRouteDescriptorSchema,
  type ActionCapabilityFamily,
} from "../src/commerce/control-action-capabilities.js";

const SCHEMA = "openarc.api.v2" as const;
const REQUEST_ID = "9f1c2d34-5e6a-4b7c-8d9e-0f1a2b3c4d5e";
const BUILD_SHA = "0123456789abcdef0123456789abcdef01234567";
const CANARY = "SECRET_CANARY_DO_NOT_ECHO";

const META = {
  schemaVersion: SCHEMA,
  requestId: REQUEST_ID,
  buildSha: BUILD_SHA,
} as const;

const ACTION_DEPENDENCIES = [
  "auth",
  "tenantDatabase",
  "machineDatabase",
  "policyDatabase",
  "commerceSessionDatabase",
  "commerceActionDatabase",
] as const;

/** Expected inventory transcribed literally from the frozen contract.md. */
const EXPECTED_ROUTES: readonly {
  readonly id: string;
  readonly family: ActionCapabilityFamily;
  readonly audience: "browser" | "agent";
  readonly method: "GET" | "POST";
  readonly path: string;
}[] = [
  { id: "action_list", family: "commerce_action_management", audience: "browser", method: "GET", path: "/v2/control/organizations/:organizationId/actions" },
  { id: "action_detail", family: "commerce_action_management", audience: "browser", method: "GET", path: "/v2/control/organizations/:organizationId/actions/:actionId" },
  { id: "approval_list", family: "commerce_action_management", audience: "browser", method: "GET", path: "/v2/control/organizations/:organizationId/approvals" },
  { id: "approval_detail", family: "commerce_action_management", audience: "browser", method: "GET", path: "/v2/control/organizations/:organizationId/approvals/:approvalId" },
  { id: "action_exposure", family: "commerce_action_management", audience: "browser", method: "GET", path: "/v2/control/organizations/:organizationId/agents/:subjectAgentId/policies/:policyId/exposure" },
  { id: "action_mutation_status", family: "commerce_action_management", audience: "browser", method: "GET", path: "/v2/control/organizations/:organizationId/action-mutations/:mutationId" },
  { id: "action_approve", family: "commerce_action_management", audience: "browser", method: "POST", path: "/v2/control/organizations/:organizationId/actions/:actionId/approve" },
  { id: "action_reject", family: "commerce_action_management", audience: "browser", method: "POST", path: "/v2/control/organizations/:organizationId/actions/:actionId/reject" },
  { id: "action_cancel", family: "commerce_action_management", audience: "browser", method: "POST", path: "/v2/control/organizations/:organizationId/actions/:actionId/cancel" },
  { id: "action_authorize", family: "commerce_action_authorization", audience: "agent", method: "POST", path: "/v2/agent/commerce-actions" },
  { id: "agent_action_detail", family: "commerce_action_authorization", audience: "agent", method: "GET", path: "/v2/agent/commerce-actions/:actionId" },
  { id: "agent_action_mutation_status", family: "commerce_action_authorization", audience: "agent", method: "GET", path: "/v2/agent/commerce-action-mutations/:mutationId" },
];

const EXPECTED_ENTRIES = [
  {
    family: "commerce_action_management",
    audience: "browser",
    state: "enabled",
    dependencies: [...ACTION_DEPENDENCIES],
  },
  {
    family: "commerce_action_authorization",
    audience: "agent",
    state: "enabled",
    dependencies: [...ACTION_DEPENDENCIES],
  },
] as const;

describe("action capability contract constants", () => {
  it("publishes the exact path, version, environment and network", () => {
    expect(ACTION_CAPABILITIES_PATH).toBe("/v2/public/action-capabilities");
    expect(ACTION_CAPABILITY_VERSION).toBe(
      "openarc.capabilities.commerce-actions.v1",
    );
    expect(ACTION_CAPABILITY_MANIFEST.environment).toBe("testnet");
    expect(ACTION_CAPABILITY_MANIFEST.network).toBe("eip155:5042002");
    expect(ACTION_CAPABILITY_MANIFEST.capabilityVersion).toBe(
      "openarc.capabilities.commerce-actions.v1",
    );
  });

  it("freezes exactly two families in the deterministic order", () => {
    expect(ACTION_CAPABILITY_FAMILY_ORDER).toEqual([
      "commerce_action_management",
      "commerce_action_authorization",
    ]);
    expect(
      ACTION_CAPABILITY_MANIFEST.capabilities.map((entry) => entry.family),
    ).toEqual([
      "commerce_action_management",
      "commerce_action_authorization",
    ]);
  });

  it("freezes exact audience and ordered six-token dependency array", () => {
    expect(ACTION_CAPABILITY_AUDIENCE).toEqual({
      commerce_action_management: "browser",
      commerce_action_authorization: "agent",
    });
    expect(ACTION_CAPABILITY_DEPENDENCIES.commerce_action_management).toEqual([
      ...ACTION_DEPENDENCIES,
    ]);
    expect(ACTION_CAPABILITY_DEPENDENCIES.commerce_action_authorization)
      .toEqual([...ACTION_DEPENDENCIES]);
    expect(ACTION_CAPABILITY_DEPENDENCY_ORDER).toEqual([
      ...ACTION_DEPENDENCIES,
    ]);
    expect(ACTION_CAPABILITY_DEPENDENCY_LENGTH).toBe(6);
  });

  it("shares one published state across both entries", () => {
    expect(ACTION_CAPABILITY_STATE).toBe("enabled");
    for (const entry of ACTION_CAPABILITY_ENTRIES) {
      expect(entry.state).toBe(ACTION_CAPABILITY_STATE);
    }
  });

  it("deeply freezes family order, audience, dependencies and manifest", () => {
    expect(Object.isFrozen(ACTION_CAPABILITY_FAMILY_ORDER)).toBe(true);
    expect(Object.isFrozen(ACTION_CAPABILITY_AUDIENCE)).toBe(true);
    expect(Object.isFrozen(ACTION_CAPABILITY_DEPENDENCIES)).toBe(true);
    for (const family of ACTION_CAPABILITY_FAMILY_ORDER) {
      expect(Object.isFrozen(ACTION_CAPABILITY_DEPENDENCIES[family])).toBe(
        true,
      );
    }
    expect(Object.isFrozen(ACTION_CAPABILITY_DEPENDENCY_ORDER)).toBe(true);
    expect(Object.isFrozen(ACTION_CAPABILITY_ENTRIES)).toBe(true);
    for (const entry of ACTION_CAPABILITY_ENTRIES) {
      expect(Object.isFrozen(entry)).toBe(true);
      expect(Object.isFrozen(entry.dependencies)).toBe(true);
    }
    expect(Object.isFrozen(ACTION_CAPABILITY_MANIFEST)).toBe(true);
    expect(Object.isFrozen(ACTION_CAPABILITY_MANIFEST.capabilities)).toBe(true);
    expect(Object.isFrozen(ACTION_CAPABILITY_MANIFEST.routes)).toBe(true);
    for (const entry of ACTION_CAPABILITY_MANIFEST.capabilities) {
      expect(Object.isFrozen(entry)).toBe(true);
      expect(Object.isFrozen(entry.dependencies)).toBe(true);
    }
    for (const route of ACTION_CAPABILITY_MANIFEST.routes) {
      expect(Object.isFrozen(route)).toBe(true);
    }
    expect(() => {
      (ACTION_CAPABILITY_AUDIENCE as Record<string, string>)
        .commerce_action_authorization = "browser";
    }).toThrow();
    expect(ACTION_CAPABILITY_AUDIENCE.commerce_action_authorization).toBe(
      "agent",
    );
  });

  it("rejects in-place mutation of every parsed manifest layer", () => {
    const manifest = ACTION_CAPABILITY_MANIFEST;
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
    expect(manifest.routes).toHaveLength(12);
    expect(route.path).toBe(EXPECTED_ROUTES[0]!.path);
    expect(route.method).toBe(EXPECTED_ROUTES[0]!.method);
    expect(entry.state).toBe("enabled");
    expect(entry.dependencies).toEqual([...ACTION_DEPENDENCIES]);
    expect(manifest).toEqual(
      ActionCapabilityManifestSchema.parse({
        capabilityVersion: "openarc.capabilities.commerce-actions.v1",
        environment: "testnet",
        network: "eip155:5042002",
        capabilities: EXPECTED_ENTRIES,
        routes: EXPECTED_ROUTES,
      }),
    );
  });

  it("does not claim payment/grant/execution/wallet runtime availability", () => {
    const serialized = JSON.stringify(ACTION_CAPABILITY_MANIFEST);
    expect(
      /grant|payment|settlement|execution|wallet|spend|lane/i.test(serialized),
    ).toBe(false);
    for (const route of ACTION_ROUTES) {
      expect(/payment|execution|wallet|grant|lane/i.test(route.path)).toBe(
        false,
      );
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

  it("does not disturb the policy 1-family / 10-route registry", () => {
    expect(CONTROL_CAPABILITY_FAMILY_ORDER).toEqual(["policy_management"]);
    expect(CONTROL_ROUTES).toHaveLength(10);
  });

  it("does not disturb the session 2-family / 7-route registry", () => {
    expect(SESSION_CAPABILITY_FAMILY_ORDER).toEqual([
      "commerce_session_management",
      "commerce_session_exchange",
    ]);
    expect(SESSION_ROUTES).toHaveLength(7);
  });
});

describe("frozen action route registry", () => {
  it("has exactly 12 unique routes in the frozen order", () => {
    expect(ACTION_ROUTES).toHaveLength(12);
    expect(ACTION_ROUTE_IDS).toHaveLength(12);
    expect(new Set(ACTION_ROUTE_IDS).size).toBe(12);
    expect(ACTION_ROUTE_IDS).toEqual(
      EXPECTED_ROUTES.map((route) => route.id),
    );
    for (const route of ACTION_ROUTES) {
      expect(route.audience).toBe(ACTION_CAPABILITY_AUDIENCE[route.family]);
    }
  });

  it("maps one-to-one against the literal frozen inventory", () => {
    expect(EXPECTED_ROUTES).toHaveLength(12);
    expect(
      new Set(EXPECTED_ROUTES.map((route) => `${route.method} ${route.path}`))
        .size,
    ).toBe(12);
    for (const expected of EXPECTED_ROUTES) {
      const actual = ACTION_ROUTE_INDEX[expected.id];
      expect(actual, `missing id ${expected.id}`).toBeDefined();
      expect(actual).toMatchObject(expected);
    }
    for (const actual of ACTION_ROUTES) {
      const expected = EXPECTED_ROUTES.find((route) => route.id === actual.id);
      expect(expected, `extra id ${actual.id}`).toBeDefined();
      expect(actual).toMatchObject(expected as object);
    }
  });

  it("excludes capability/grant/payment descriptors", () => {
    const paths = ACTION_ROUTES.map((route) => route.path);
    expect(paths).not.toContain(ACTION_CAPABILITIES_PATH);
    for (const route of ACTION_ROUTES) {
      expect(route.method === "GET" || route.method === "POST").toBe(true);
      expect(
        /manifest|health|fallback|checkout|capacity|grant|payment|lane/i.test(
          route.path,
        ),
      ).toBe(false);
      expect(
        route.path.startsWith(
          "/v2/control/organizations/:organizationId/",
        ) || route.path.startsWith("/v2/agent/"),
      ).toBe(true);
    }
  });

  it("is deeply frozen so callers cannot mutate global truth", () => {
    expect(Object.isFrozen(ACTION_ROUTES)).toBe(true);
    for (const route of ACTION_ROUTES) {
      expect(Object.isFrozen(route)).toBe(true);
    }
    expect(Object.isFrozen(ACTION_ROUTE_IDS)).toBe(true);
    expect(Object.isFrozen(ACTION_ROUTE_INDEX)).toBe(true);
  });

  it("accepts every frozen descriptor and rejects altered tuples", () => {
    for (const route of EXPECTED_ROUTES) {
      expect(
        ActionRouteDescriptorSchema.safeParse(route).success,
        route.id,
      ).toBe(true);
    }
    const first = EXPECTED_ROUTES[0] as (typeof EXPECTED_ROUTES)[number];
    const detail = EXPECTED_ROUTES[1] as (typeof EXPECTED_ROUTES)[number];
    const authorize = EXPECTED_ROUTES[9] as (typeof EXPECTED_ROUTES)[number];
    const bad: unknown[] = [
      { ...first, method: "POST" },
      { ...first, path: `${first.path}/:actionId` },
      { ...first, audience: "agent" },
      { ...first, family: "commerce_action_authorization" },
      { ...detail, method: "POST" },
      { ...detail, path: `${detail.path}/extra` },
      { ...EXPECTED_ROUTES[6], method: "GET" },
      { ...EXPECTED_ROUTES[7], method: "GET" },
      { ...EXPECTED_ROUTES[8], method: "GET" },
      { ...authorize, audience: "browser" },
      { ...authorize, method: "GET" },
      { ...authorize, family: "commerce_action_management" },
      { ...first, id: "action_unknown" },
      { ...first, id: "Action_List" },
      { ...first, id: "toString" },
      { ...first, id: "constructor" },
      { ...first, id: "__proto__" },
      { ...first, id: "hasOwnProperty" },
      { ...first, id: "valueOf" },
      { ...first, path: `${first.path}?x=1` },
      { ...first, path: `https://evil.example${first.path}` },
      { ...first, path: `${first.path}/${CANARY}` },
      { ...first, path: "" },
      { ...first, path: `/${"a".repeat(513)}` },
      { ...first, extra: CANARY },
    ];
    for (const route of bad) {
      expect(
        ActionRouteDescriptorSchema.safeParse(route).success,
        JSON.stringify(route),
      ).toBe(false);
    }
  });

  it("rejects prototype and inherited route ids as lookup targets", () => {
    for (const id of [
      "toString",
      "constructor",
      "__proto__",
      "hasOwnProperty",
      "valueOf",
      "isPrototypeOf",
    ]) {
      expect(Object.hasOwn(ACTION_ROUTE_INDEX, id)).toBe(false);
      expect(
        ActionRouteDescriptorSchema.safeParse({ ...EXPECTED_ROUTES[0], id })
          .success,
      ).toBe(false);
    }
  });
});

describe("action entry validity and fail-closed input", () => {
  it("accepts exactly the three canonical states", () => {
    for (const state of [
      "enabled",
      "built_disabled",
      "unavailable",
    ] as const) {
      expect(
        ActionCapabilityEntrySchema.safeParse({
          family: "commerce_action_management",
          audience: "browser",
          state,
          dependencies: [...ACTION_DEPENDENCIES],
        }).success,
        state,
      ).toBe(true);
    }
  });

  it("rejects invalid state, audience, dependency and extra keys", () => {
    const valid = {
      family: "commerce_action_management",
      audience: "browser",
      state: "enabled",
      dependencies: [...ACTION_DEPENDENCIES],
    } as const;
    const bad: unknown[] = [
      { ...valid, state: "planned" },
      { ...valid, state: "unknown" },
      { ...valid, state: "ENABLED" },
      { ...valid, state: "" },
      { ...valid, audience: "public" },
      { ...valid, audience: "machine" },
      { ...valid, family: "commerce_action_authorization" },
      { ...valid, dependencies: ACTION_DEPENDENCIES.slice(0, 5) },
      {
        ...valid,
        dependencies: [...ACTION_DEPENDENCIES, "marketDatabase"],
      },
      {
        ...valid,
        dependencies: [
          "commerceActionDatabase",
          "commerceSessionDatabase",
          "policyDatabase",
          "machineDatabase",
          "tenantDatabase",
          "auth",
        ],
      },
      {
        ...valid,
        dependencies: [
          "auth",
          "tenantDatabase",
          "machineDatabase",
          "policyDatabase",
          "commerceActionDatabase",
          "commerceSessionDatabase",
        ],
      },
      {
        ...valid,
        dependencies: [
          "auth",
          "tenantDatabase",
          "machineDatabase",
          "policyDatabase",
          "marketDatabase",
          "commerceActionDatabase",
        ],
      },
      {
        ...valid,
        dependencies: [
          "auth",
          "tenantDatabase",
          "machineDatabase",
          "policyDatabase",
          "commerceSessionDatabase",
          "commerceSessionDatabase",
        ],
      },
      { ...valid, dependencies: "auth" },
      { ...valid, dependencies: [] },
      { ...valid, extra: CANARY },
      { ...valid, dependencies: [...ACTION_DEPENDENCIES, CANARY] },
    ];
    for (const candidate of bad) {
      expect(
        ActionCapabilityEntrySchema.safeParse(candidate).success,
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
      {
        family: "unknown",
        audience: "browser",
        state: "enabled",
        dependencies: [],
      },
    ];
    for (const sample of samples) {
      expect(() => ActionCapabilityEntrySchema.safeParse(sample)).not.toThrow();
      expect(() =>
        ActionRouteDescriptorSchema.safeParse(sample),
      ).not.toThrow();
      expect(() =>
        ActionCapabilityManifestSchema.safeParse(sample),
      ).not.toThrow();
    }
  });
});

describe("action manifest schema and whole envelope", () => {
  it("validates the frozen manifest and exposes a strict success envelope", () => {
    expect(
      ActionCapabilityManifestSchema.safeParse(ACTION_CAPABILITY_MANIFEST)
        .success,
    ).toBe(true);
    const envelope = {
      ok: true as const,
      data: ACTION_CAPABILITY_MANIFEST,
      meta: META,
    };
    expect(
      ActionCapabilitiesSuccessEnvelopeSchema.safeParse(envelope).success,
    ).toBe(true);
    expect(CommerceApiMetaSchema.safeParse(META).success).toBe(true);
    expect(COMMERCE_API_SCHEMA_VERSION).toBe("openarc.api.v2");
  });

  it("rejects extra envelope keys, wrong ok and bad meta", () => {
    const envelope = {
      ok: true as const,
      data: ACTION_CAPABILITY_MANIFEST,
      meta: META,
    };
    const bad: unknown[] = [
      { ...envelope, extra: CANARY },
      { ...envelope, ok: false },
      { ok: true, data: ACTION_CAPABILITY_MANIFEST },
      {
        ok: true,
        data: { ...ACTION_CAPABILITY_MANIFEST, secretConfig: CANARY },
        meta: META,
      },
      { ...envelope, meta: { ...META, buildSha: "zz" } },
    ];
    for (const candidate of bad) {
      expect(
        ActionCapabilitiesSuccessEnvelopeSchema.safeParse(candidate).success,
        JSON.stringify(candidate).slice(0, 80),
      ).toBe(false);
    }
  });

  it("rejects mismatched shared states across the two entries", () => {
    const valid = ACTION_CAPABILITY_MANIFEST;
    const mismatched = {
      ...valid,
      capabilities: [
        valid.capabilities[0],
        { ...valid.capabilities[1], state: "built_disabled" },
      ],
    };
    expect(ActionCapabilityManifestSchema.safeParse(mismatched).success).toBe(
      false,
    );
  });

  it("rejects incomplete, duplicated, reordered and extra inventories", () => {
    const valid = ACTION_CAPABILITY_MANIFEST;
    const missingFamily = { ...valid, capabilities: [] };
    const duplicateFamily = {
      ...valid,
      capabilities: [valid.capabilities[0], valid.capabilities[0]],
    };
    const missingRoute = { ...valid, routes: valid.routes.slice(0, 11) };
    const extraRoute = {
      ...valid,
      routes: [
        ...valid.routes,
        { ...valid.routes[0], id: "action_extra" },
      ],
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
        { ...valid.capabilities[0], family: "commerce_action_other" },
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
        ActionCapabilityManifestSchema.safeParse(candidate).success,
        JSON.stringify(candidate).slice(0, 80),
      ).toBe(false);
    }
  });

  it("rejects altered version, network/environment and extra top-level fields", () => {
    const valid = ACTION_CAPABILITY_MANIFEST;
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
        ActionCapabilityManifestSchema.safeParse(candidate).success,
        JSON.stringify(candidate).slice(0, 80),
      ).toBe(false);
    }
  });

  it("rejects altered descriptor tuples inside the manifest", () => {
    const valid = ACTION_CAPABILITY_MANIFEST;
    const alteredMethod = {
      ...valid,
      routes: valid.routes.map((route) =>
        route.id === "action_approve"
          ? { ...route, method: "GET" as const }
          : route,
      ),
    };
    const alteredPath = {
      ...valid,
      routes: valid.routes.map((route) =>
        route.id === "action_list"
          ? { ...route, path: "/v2/control/organizations/:organizationId/x" }
          : route,
      ),
    };
    const alteredAudience = {
      ...valid,
      routes: valid.routes.map((route) => ({
        ...route,
        audience: "browser" as const,
      })),
    };
    for (const candidate of [alteredMethod, alteredPath, alteredAudience]) {
      expect(
        ActionCapabilityManifestSchema.safeParse(candidate).success,
      ).toBe(false);
    }
  });
});

describe("static typing", () => {
  it("narrows manifest and entry types", () => {
    expectTypeOf(ACTION_CAPABILITY_MANIFEST.capabilityVersion)
      .toEqualTypeOf<"openarc.capabilities.commerce-actions.v1">();
    expectTypeOf(ACTION_CAPABILITY_MANIFEST.capabilities[0]?.state)
      .toEqualTypeOf<
        "enabled" | "built_disabled" | "unavailable" | undefined
      >();
    expectTypeOf(ACTION_CAPABILITY_MANIFEST.capabilities[0]?.family)
      .toEqualTypeOf<
        | "commerce_action_management"
        | "commerce_action_authorization"
        | undefined
      >();
    expectTypeOf(ACTION_CAPABILITY_MANIFEST.routes[0]?.id).toEqualTypeOf<
      string | undefined
    >();
  });
});
