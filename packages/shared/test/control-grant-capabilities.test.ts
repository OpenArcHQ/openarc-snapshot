import { describe, expect, it } from "vitest";

import {
  ACTION_CAPABILITIES_PATH,
  ACTION_CAPABILITY_VERSION,
  ACTION_ROUTES,
  ACTION_ROUTE_IDS,
} from "../src/commerce/control-action-capabilities.js";
import {
  GRANT_CAPABILITIES_PATH,
  GRANT_CAPABILITY_AUDIENCE,
  GRANT_CAPABILITY_AUDIENCE_PREFIX,
  GRANT_CAPABILITY_CREDENTIAL,
  GRANT_CAPABILITY_DEPENDENCIES,
  GRANT_CAPABILITY_DEPENDENCY_LENGTH,
  GRANT_CAPABILITY_DEPENDENCY_ORDER,
  GRANT_CAPABILITY_ENTRIES,
  GRANT_CAPABILITY_FAMILY_ORDER,
  GRANT_CAPABILITY_MANIFEST,
  GRANT_CAPABILITY_STATE,
  GRANT_CAPABILITY_VERSION,
  GRANT_PROVIDER_FORBIDDEN_PREFIX,
  GRANT_ROUTES,
  GRANT_ROUTE_IDS,
  GRANT_ROUTE_INDEX,
  GrantCapabilitiesSuccessEnvelopeSchema,
  GrantCapabilityAudienceSchema,
  GrantCapabilityDependencySchema,
  GrantCapabilityEntrySchema,
  GrantCapabilityFamilySchema,
  GrantCapabilityManifestSchema,
  GrantCapabilityStateSchema,
  GrantRouteDescriptorSchema,
  type GrantCapabilityAudience,
  type GrantRouteDescriptor,
} from "../src/commerce/control-grant-capabilities.js";
import {
  GRANT_CAPABILITY_MANIFEST as INDEX_MANIFEST,
  GrantCapabilityManifestSchema as INDEX_MANIFEST_SCHEMA,
} from "../src/index.js";

const META = {
  schemaVersion: "openarc.api.v2" as const,
  requestId: "9f1c2d34-5e6a-4b7c-8d9e-0f1a2b3c4d5e",
  buildSha: "0123456789abcdef0123456789abcdef01234567",
};

/**
 * The frozen route table, restated independently of the module so a drift in
 * either direction fails. The API, proxy and UI are held to exactly this.
 */
const EXPECTED_ROUTES: readonly GrantRouteDescriptor[] = [
  {
    id: "grant_issue",
    family: "commerce_grant_authorization",
    audience: "agent",
    method: "POST",
    path: "/v2/agent/commerce-grants",
  },
  {
    id: "grant_replace",
    family: "commerce_grant_authorization",
    audience: "agent",
    method: "POST",
    path: "/v2/agent/commerce-grants/:grantId/replace",
  },
  {
    id: "agent_grant_mutation_status",
    family: "commerce_grant_authorization",
    audience: "agent",
    method: "GET",
    path: "/v2/agent/commerce-grant-mutations/:mutationId",
  },
  {
    id: "provider_grant_introspect",
    family: "commerce_grant_claim",
    audience: "provider",
    method: "POST",
    path: "/v2/provider/grants/introspect",
  },
  {
    id: "provider_grant_claim",
    family: "commerce_grant_claim",
    audience: "provider",
    method: "POST",
    path: "/v2/provider/grants/claim",
  },
  {
    id: "provider_grant_attempt_status",
    family: "commerce_grant_claim",
    audience: "provider",
    method: "GET",
    path: "/v2/provider/grant-attempts/:attemptId",
  },
  {
    id: "grant_detail",
    family: "commerce_grant_management",
    audience: "browser",
    method: "GET",
    path: "/v2/control/organizations/:organizationId/grants/:grantId",
  },
  {
    id: "grant_mutation_status",
    family: "commerce_grant_management",
    audience: "browser",
    method: "GET",
    path: "/v2/control/organizations/:organizationId/grant-mutations/:mutationId",
  },
  {
    id: "grant_revoke",
    family: "commerce_grant_management",
    audience: "browser",
    method: "POST",
    path: "/v2/control/organizations/:organizationId/grants/:grantId/revoke",
  },
];

function manifest(overrides: Record<string, unknown> = {}) {
  return {
    capabilityVersion: GRANT_CAPABILITY_VERSION,
    environment: "testnet",
    network: "eip155:5042002",
    capabilities: GRANT_CAPABILITY_ENTRIES.map((entry) => ({ ...entry })),
    routes: GRANT_ROUTES.map((route) => ({ ...route })),
    ...overrides,
  };
}

const DEPENDENCIES = [
  "auth",
  "tenantDatabase",
  "machineDatabase",
  "policyDatabase",
  "commerceSessionDatabase",
  "commerceActionDatabase",
  "commerceGrantDatabase",
];

describe("grant capability constants", () => {
  it("publishes the exact public path and capability version", () => {
    expect(GRANT_CAPABILITIES_PATH).toBe("/v2/public/grant-capabilities");
    expect(GRANT_CAPABILITY_VERSION).toBe(
      "openarc.capabilities.commerce-grants.v1",
    );
  });

  it("is separate from the accepted action capability registry", () => {
    expect(GRANT_CAPABILITIES_PATH).not.toBe(ACTION_CAPABILITIES_PATH);
    expect(GRANT_CAPABILITY_VERSION).not.toBe(ACTION_CAPABILITY_VERSION);
    for (const id of GRANT_ROUTE_IDS) {
      expect(ACTION_ROUTE_IDS.includes(id), id).toBe(false);
    }
    const actionPaths = new Set(ACTION_ROUTES.map((route) => route.path));
    for (const route of GRANT_ROUTES) {
      expect(actionPaths.has(route.path), route.path).toBe(false);
    }
  });

  it("re-exports the same manifest object from the package index", () => {
    expect(INDEX_MANIFEST).toBe(GRANT_CAPABILITY_MANIFEST);
    expect(INDEX_MANIFEST_SCHEMA).toBe(GrantCapabilityManifestSchema);
  });
});

describe("closed enums", () => {
  it("declares exactly three families in the frozen order", () => {
    expect(GrantCapabilityFamilySchema.options).toEqual([
      "commerce_grant_authorization",
      "commerce_grant_claim",
      "commerce_grant_management",
    ]);
    expect(GRANT_CAPABILITY_FAMILY_ORDER).toEqual(
      GrantCapabilityFamilySchema.options,
    );
    expect(Object.isFrozen(GRANT_CAPABILITY_FAMILY_ORDER)).toBe(true);
  });

  it("declares exactly three audiences and rejects anything else", () => {
    expect(GrantCapabilityAudienceSchema.options).toEqual([
      "browser",
      "agent",
      "provider",
    ]);
    for (const value of [
      "public",
      "seller",
      "machine",
      "provider_minimal",
      "browser\n",
      "",
    ]) {
      expect(GrantCapabilityAudienceSchema.safeParse(value).success, value).toBe(
        false,
      );
    }
  });

  it("declares exactly three states with no planned/unknown member", () => {
    expect(GrantCapabilityStateSchema.options).toEqual([
      "enabled",
      "built_disabled",
      "unavailable",
    ]);
    expect(GrantCapabilityStateSchema.safeParse("planned").success).toBe(false);
  });

  it("declares exactly the seven dependency tokens in the frozen order", () => {
    expect(GrantCapabilityDependencySchema.options).toEqual(DEPENDENCIES);
    expect(GRANT_CAPABILITY_DEPENDENCY_ORDER).toEqual(DEPENDENCIES);
    expect(GRANT_CAPABILITY_DEPENDENCY_LENGTH).toBe(7);
    expect(Object.isFrozen(GRANT_CAPABILITY_DEPENDENCY_ORDER)).toBe(true);
  });
});

describe("audience separation is explicit and strict", () => {
  it("pins exactly one audience per family", () => {
    expect(GRANT_CAPABILITY_AUDIENCE).toEqual({
      commerce_grant_authorization: "agent",
      commerce_grant_claim: "provider",
      commerce_grant_management: "browser",
    });
    expect(Object.isFrozen(GRANT_CAPABILITY_AUDIENCE)).toBe(true);
  });

  it("never lets two families share an audience", () => {
    const audiences = Object.values(GRANT_CAPABILITY_AUDIENCE);
    expect(new Set(audiences).size).toBe(audiences.length);
    expect(audiences.length).toBe(3);
  });

  it("pins one non-overlapping path prefix per audience", () => {
    expect(GRANT_CAPABILITY_AUDIENCE_PREFIX).toEqual({
      browser: "/v2/control/organizations/",
      agent: "/v2/agent/",
      provider: "/v2/provider/grant",
    });
    const prefixes = Object.values(GRANT_CAPABILITY_AUDIENCE_PREFIX);
    for (const left of prefixes) {
      for (const right of prefixes) {
        if (left === right) continue;
        expect(left.startsWith(right), `${left} vs ${right}`).toBe(false);
      }
    }
  });

  it("keeps the provider grant prefix out of the browser listing prefix", () => {
    expect(GRANT_PROVIDER_FORBIDDEN_PREFIX).toBe("/v2/provider/organizations/");
    expect(
      GRANT_CAPABILITY_AUDIENCE_PREFIX.provider.startsWith(
        GRANT_PROVIDER_FORBIDDEN_PREFIX,
      ),
    ).toBe(false);
    expect(
      GRANT_PROVIDER_FORBIDDEN_PREFIX.startsWith(
        GRANT_CAPABILITY_AUDIENCE_PREFIX.provider,
      ),
    ).toBe(false);
  });

  it("names a distinct credential class per audience", () => {
    expect(GRANT_CAPABILITY_CREDENTIAL).toEqual({
      browser: "browser_session_cookie",
      agent: "oacs_v1_commerce_session",
      provider: "oas_pr_provider_session+oag_v1_grant_token",
    });
    const credentials = Object.values(GRANT_CAPABILITY_CREDENTIAL);
    expect(new Set(credentials).size).toBe(3);
    expect(GRANT_CAPABILITY_CREDENTIAL.provider).toContain("oas_pr_");
    expect(GRANT_CAPABILITY_CREDENTIAL.provider).toContain("oag_v1_");
    expect(GRANT_CAPABILITY_CREDENTIAL.browser).not.toContain("oas_pr_");
    expect(GRANT_CAPABILITY_CREDENTIAL.browser).not.toContain("oacs_v1_");
    expect(GRANT_CAPABILITY_CREDENTIAL.agent).not.toContain("cookie");
    expect(Object.isFrozen(GRANT_CAPABILITY_CREDENTIAL)).toBe(true);
  });

  it("gives no route a browser credential outside the browser family", () => {
    for (const route of GRANT_ROUTES) {
      const credential = GRANT_CAPABILITY_CREDENTIAL[route.audience];
      if (route.family === "commerce_grant_management") {
        expect(credential).toBe("browser_session_cookie");
      } else {
        expect(credential, route.id).not.toBe("browser_session_cookie");
      }
    }
  });
});

describe("frozen route table", () => {
  it("freezes exactly nine routes with the exact descriptors", () => {
    expect(GRANT_ROUTES.length).toBe(9);
    expect(GRANT_ROUTES.map((route) => ({ ...route }))).toEqual(
      EXPECTED_ROUTES.map((route) => ({ ...route })),
    );
    expect(GRANT_ROUTE_IDS).toEqual(EXPECTED_ROUTES.map((route) => route.id));
  });

  it("splits three routes into each family", () => {
    const counts = new Map<string, number>();
    for (const route of GRANT_ROUTES) {
      counts.set(route.family, (counts.get(route.family) ?? 0) + 1);
    }
    expect(Object.fromEntries(counts)).toEqual({
      commerce_grant_authorization: 3,
      commerce_grant_claim: 3,
      commerce_grant_management: 3,
    });
  });

  it("gives every route the audience prefix of its own family", () => {
    for (const route of GRANT_ROUTES) {
      expect(route.audience).toBe(GRANT_CAPABILITY_AUDIENCE[route.family]);
      expect(
        route.path.startsWith(GRANT_CAPABILITY_AUDIENCE_PREFIX[route.audience]),
        route.id,
      ).toBe(true);
    }
  });

  it("never puts a provider route under the browser listing prefix", () => {
    for (const route of GRANT_ROUTES) {
      if (route.audience !== "provider") continue;
      expect(
        route.path.startsWith(GRANT_PROVIDER_FORBIDDEN_PREFIX),
        route.id,
      ).toBe(false);
    }
  });

  it("uses only GET and POST and unique ids", () => {
    for (const route of GRANT_ROUTES) {
      expect(["GET", "POST"].includes(route.method), route.id).toBe(true);
    }
    expect(new Set(GRANT_ROUTE_IDS).size).toBe(GRANT_ROUTE_IDS.length);
  });

  it("sends both token-bearing provider routes over POST", () => {
    for (const id of ["provider_grant_introspect", "provider_grant_claim"]) {
      expect(GRANT_ROUTE_INDEX[id]?.method, id).toBe("POST");
    }
    expect(GRANT_ROUTE_INDEX["provider_grant_attempt_status"]?.method).toBe(
      "GET",
    );
  });

  it("declares no list, page, capability or payment route", () => {
    for (const route of GRANT_ROUTES) {
      expect(route.path.includes("capabilit"), route.id).toBe(false);
      for (const word of ["payment", "settle", "refund", "deliver", "health"]) {
        expect(route.path.includes(word), `${route.id}:${word}`).toBe(false);
      }
    }
    expect(GRANT_ROUTE_IDS.includes("grant_list")).toBe(false);
  });

  it("indexes routes by own property only", () => {
    for (const route of GRANT_ROUTES) {
      expect(Object.hasOwn(GRANT_ROUTE_INDEX, route.id)).toBe(true);
    }
    for (const inherited of [
      "toString",
      "constructor",
      "hasOwnProperty",
      "__proto__",
      "valueOf",
    ]) {
      expect(Object.hasOwn(GRANT_ROUTE_INDEX, inherited), inherited).toBe(false);
    }
    expect(Object.isFrozen(GRANT_ROUTE_INDEX)).toBe(true);
    expect(Object.isFrozen(GRANT_ROUTES)).toBe(true);
    for (const route of GRANT_ROUTES) {
      expect(Object.isFrozen(route)).toBe(true);
    }
  });
});

describe("route descriptor schema", () => {
  it("accepts every frozen descriptor", () => {
    for (const route of GRANT_ROUTES) {
      expect(GrantRouteDescriptorSchema.safeParse({ ...route }).success).toBe(
        true,
      );
    }
  });

  it("rejects an id outside the frozen registry", () => {
    for (const id of [
      "grant_list",
      "toString",
      "constructor",
      "hasOwnProperty",
      "__proto__",
    ]) {
      expect(
        GrantRouteDescriptorSchema.safeParse({
          ...EXPECTED_ROUTES[0]!,
          id,
        }).success,
        id,
      ).toBe(false);
    }
  });

  it("rejects an id with a trailing newline or an uppercase character", () => {
    expect(
      GrantRouteDescriptorSchema.safeParse({
        ...EXPECTED_ROUTES[0]!,
        id: "grant_issue\n",
      }).success,
    ).toBe(false);
    expect(
      GrantRouteDescriptorSchema.safeParse({
        ...EXPECTED_ROUTES[0]!,
        id: "Grant_issue",
      }).success,
    ).toBe(false);
  });

  it("rejects any drift in family, audience, method or path", () => {
    const base = EXPECTED_ROUTES[3]!; // provider_grant_introspect
    for (const override of [
      { family: "commerce_grant_management" as const },
      { audience: "browser" as const },
      { method: "GET" as const },
      { path: "/v2/provider/grants/introspect/" },
      { path: "/v2/provider/grants/introspect\n" },
    ]) {
      expect(
        GrantRouteDescriptorSchema.safeParse({ ...base, ...override }).success,
        JSON.stringify(override),
      ).toBe(false);
    }
  });

  it("rejects a provider route placed under the browser listing prefix", () => {
    const parsed = GrantRouteDescriptorSchema.safeParse({
      ...EXPECTED_ROUTES[4]!,
      path: "/v2/provider/organizations/:organizationId/grants/claim",
    });
    expect(parsed.success).toBe(false);
    expect(
      parsed.success ? [] : parsed.error.issues.map((issue) => issue.message),
    ).toContain(
      "A provider grant route may not live under the browser listing-management prefix.",
    );
  });

  it("rejects a route path outside its own audience prefix", () => {
    const parsed = GrantRouteDescriptorSchema.safeParse({
      ...EXPECTED_ROUTES[0]!,
      path: "/v2/control/organizations/:organizationId/commerce-grants",
    });
    expect(parsed.success).toBe(false);
    expect(
      parsed.success ? [] : parsed.error.issues.map((issue) => issue.message),
    ).toContain("Route path does not start with its frozen audience prefix.");
  });

  it("rejects an unknown descriptor field and a non-GET/POST method", () => {
    expect(
      GrantRouteDescriptorSchema.safeParse({
        ...EXPECTED_ROUTES[0]!,
        credential: "browser_session_cookie",
      }).success,
    ).toBe(false);
    expect(
      GrantRouteDescriptorSchema.safeParse({
        ...EXPECTED_ROUTES[0]!,
        method: "DELETE",
      }).success,
    ).toBe(false);
  });
});

describe("capability entries", () => {
  it("publishes exactly three entries at one shared state", () => {
    expect(GRANT_CAPABILITY_STATE).toBe("enabled");
    expect(GRANT_CAPABILITY_ENTRIES.length).toBe(3);
    expect(
      GRANT_CAPABILITY_ENTRIES.map((entry) => entry.family),
    ).toEqual(GRANT_CAPABILITY_FAMILY_ORDER);
    for (const entry of GRANT_CAPABILITY_ENTRIES) {
      expect(entry.state).toBe(GRANT_CAPABILITY_STATE);
      expect(entry.audience).toBe(GRANT_CAPABILITY_AUDIENCE[entry.family]);
      expect(entry.dependencies).toEqual(DEPENDENCIES);
    }
  });

  it("gives all three families the same closed dependency list", () => {
    for (const family of GRANT_CAPABILITY_FAMILY_ORDER) {
      expect(GRANT_CAPABILITY_DEPENDENCIES[family]).toEqual(DEPENDENCIES);
    }
    expect(Object.isFrozen(GRANT_CAPABILITY_DEPENDENCIES)).toBe(true);
  });

  it("rejects an entry whose audience or dependencies drift", () => {
    expect(
      GrantCapabilityEntrySchema.safeParse({
        family: "commerce_grant_claim",
        audience: "browser",
        state: "enabled",
        dependencies: DEPENDENCIES,
      }).success,
    ).toBe(false);
    expect(
      GrantCapabilityEntrySchema.safeParse({
        family: "commerce_grant_claim",
        audience: "provider",
        state: "enabled",
        dependencies: DEPENDENCIES.slice(0, 6),
      }).success,
    ).toBe(false);
    expect(
      GrantCapabilityEntrySchema.safeParse({
        family: "commerce_grant_claim",
        audience: "provider",
        state: "enabled",
        dependencies: [...DEPENDENCIES].reverse(),
      }).success,
    ).toBe(false);
    expect(
      GrantCapabilityEntrySchema.safeParse({
        family: "commerce_grant_claim",
        audience: "provider",
        state: "enabled",
        dependencies: DEPENDENCIES,
        routes: [],
      }).success,
    ).toBe(false);
  });
});

describe("manifest", () => {
  it("parses the published manifest shape", () => {
    expect(GrantCapabilityManifestSchema.safeParse(manifest()).success).toBe(
      true,
    );
  });

  it("publishes exactly three capabilities and nine routes", () => {
    expect(GRANT_CAPABILITY_MANIFEST.capabilities.length).toBe(3);
    expect(GRANT_CAPABILITY_MANIFEST.routes.length).toBe(9);
    expect(GRANT_CAPABILITY_MANIFEST.capabilityVersion).toBe(
      GRANT_CAPABILITY_VERSION,
    );
    expect(GRANT_CAPABILITY_MANIFEST.environment).toBe("testnet");
    expect(GRANT_CAPABILITY_MANIFEST.network).toBe("eip155:5042002");
    expect(
      GRANT_CAPABILITY_MANIFEST.routes.map((route) => ({ ...route })),
    ).toEqual(EXPECTED_ROUTES.map((route) => ({ ...route })));
  });

  it("rejects an extra or a missing route", () => {
    expect(
      GrantCapabilityManifestSchema.safeParse(
        manifest({
          routes: [
            ...GRANT_ROUTES.map((route) => ({ ...route })),
            { ...EXPECTED_ROUTES[0]! },
          ],
        }),
      ).success,
    ).toBe(false);
    expect(
      GrantCapabilityManifestSchema.safeParse(
        manifest({
          routes: GRANT_ROUTES.slice(0, 8).map((route) => ({ ...route })),
        }),
      ).success,
    ).toBe(false);
  });

  it("rejects a duplicated route id even at the right length", () => {
    const routes = GRANT_ROUTES.map((route) => ({ ...route }));
    routes[8] = { ...EXPECTED_ROUTES[0]! };
    expect(
      GrantCapabilityManifestSchema.safeParse(manifest({ routes })).success,
    ).toBe(false);
  });

  it("rejects a reordered route array", () => {
    const routes = GRANT_ROUTES.map((route) => ({ ...route }));
    const [first, second, ...rest] = routes;
    expect(
      GrantCapabilityManifestSchema.safeParse(
        manifest({ routes: [second!, first!, ...rest] }),
      ).success,
    ).toBe(false);
  });

  it("rejects a reordered or duplicated family array", () => {
    const entries = GRANT_CAPABILITY_ENTRIES.map((entry) => ({ ...entry }));
    const [first, second, third] = entries;
    expect(
      GrantCapabilityManifestSchema.safeParse(
        manifest({ capabilities: [second!, first!, third!] }),
      ).success,
    ).toBe(false);
    expect(
      GrantCapabilityManifestSchema.safeParse(
        manifest({ capabilities: [first!, first!, third!] }),
      ).success,
    ).toBe(false);
  });

  it("rejects a mismatched entry state", () => {
    const entries = GRANT_CAPABILITY_ENTRIES.map((entry) => ({ ...entry }));
    entries[1] = { ...entries[1]!, state: "unavailable" };
    expect(
      GrantCapabilityManifestSchema.safeParse(
        manifest({ capabilities: entries }),
      ).success,
    ).toBe(false);
  });

  it("rejects an audience claimed by two families", () => {
    const entries = GRANT_CAPABILITY_ENTRIES.map((entry) => ({ ...entry }));
    entries[1] = {
      ...entries[1]!,
      audience: "browser" as GrantCapabilityAudience,
    };
    const parsed = GrantCapabilityManifestSchema.safeParse(
      manifest({ capabilities: entries }),
    );
    expect(parsed.success).toBe(false);
    const messages = parsed.success
      ? []
      : parsed.error.issues.map((issue) => issue.message);
    expect(messages).toContain(
      "Audience does not match the frozen family descriptor.",
    );
  });

  it("rejects a manifest whose version, environment or network drifts", () => {
    for (const override of [
      { capabilityVersion: "openarc.capabilities.commerce-grants.v2" },
      { capabilityVersion: ACTION_CAPABILITY_VERSION },
      { environment: "mainnet" },
      { network: "eip155:1" },
    ]) {
      expect(
        GrantCapabilityManifestSchema.safeParse(manifest(override)).success,
        JSON.stringify(override),
      ).toBe(false);
    }
  });

  it("rejects an unknown manifest field", () => {
    expect(
      GrantCapabilityManifestSchema.safeParse(
        manifest({ paymentLane: "available" }),
      ).success,
    ).toBe(false);
  });

  it("is deeply frozen", () => {
    expect(Object.isFrozen(GRANT_CAPABILITY_MANIFEST)).toBe(true);
    expect(Object.isFrozen(GRANT_CAPABILITY_MANIFEST.capabilities)).toBe(true);
    expect(Object.isFrozen(GRANT_CAPABILITY_MANIFEST.routes)).toBe(true);
    for (const entry of GRANT_CAPABILITY_MANIFEST.capabilities) {
      expect(Object.isFrozen(entry)).toBe(true);
      expect(Object.isFrozen(entry.dependencies)).toBe(true);
    }
    for (const route of GRANT_CAPABILITY_MANIFEST.routes) {
      expect(Object.isFrozen(route)).toBe(true);
    }
    expect(() => {
      (GRANT_CAPABILITY_MANIFEST.routes as GrantRouteDescriptor[]).push({
        ...EXPECTED_ROUTES[0]!,
      });
    }).toThrow();
  });

  it("wraps the manifest in the accepted v2 success envelope", () => {
    expect(
      GrantCapabilitiesSuccessEnvelopeSchema.safeParse({
        ok: true,
        data: manifest(),
        meta: META,
      }).success,
    ).toBe(true);
    expect(
      GrantCapabilitiesSuccessEnvelopeSchema.safeParse({
        ok: false,
        data: manifest(),
        meta: META,
      }).success,
    ).toBe(false);
  });
});
