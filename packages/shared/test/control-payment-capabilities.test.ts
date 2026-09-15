import { describe, expect, it } from "vitest";

import {
  PAYMENT_CAPABILITIES_PATH,
  PAYMENT_CAPABILITY_AUDIENCE,
  PAYMENT_CAPABILITY_AUDIENCE_PREFIX,
  PAYMENT_CAPABILITY_CREDENTIAL,
  PAYMENT_CAPABILITY_DEPENDENCY_ORDER,
  PAYMENT_CAPABILITY_FAMILY_ORDER,
  PAYMENT_CAPABILITY_VERSION,
  PAYMENT_ROUTES,
  PAYMENT_ROUTE_IDS,
  PAYMENT_ROUTE_INDEX,
  PaymentCapabilityManifestSchema,
  PaymentRouteDescriptorSchema,
} from "../src/commerce/control-payment-capabilities.js";
import { GRANT_CAPABILITIES_PATH, GRANT_ROUTES } from "../src/commerce/control-grant-capabilities.js";
import { COMMERCE_CAPABILITY_ENVIRONMENT, COMMERCE_CAPABILITY_NETWORK } from "../src/commerce/capabilities.js";
import { PAYMENT_ROUTES as INDEX_ROUTES } from "../src/index.js";

/** The frozen route table, restated independently of the module. */
const EXPECTED = [
  { id: "listing_payment_terms_record", family: "commerce_payment_terms", audience: "browser", method: "POST", path: "/v2/provider/organizations/:organizationId/listings/:listingId/versions/:version/payment-terms" },
  { id: "payment_requirement_register", family: "commerce_payment_attempt", audience: "agent", method: "POST", path: "/v2/agent/commerce-payment-requirements" },
  { id: "payment_attempt_persist", family: "commerce_payment_attempt", audience: "agent", method: "POST", path: "/v2/agent/commerce-payment-attempts" },
  { id: "payment_attempt_dispatch", family: "commerce_payment_attempt", audience: "agent", method: "POST", path: "/v2/agent/commerce-payment-attempts/:attemptId/dispatch" },
  { id: "payment_attempt_detail", family: "commerce_payment_attempt", audience: "agent", method: "GET", path: "/v2/agent/commerce-payment-attempts/:attemptId" },
] as const;

function manifest(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    capabilityVersion: PAYMENT_CAPABILITY_VERSION,
    environment: COMMERCE_CAPABILITY_ENVIRONMENT,
    network: COMMERCE_CAPABILITY_NETWORK,
    capabilities: PAYMENT_CAPABILITY_FAMILY_ORDER.map((family) => ({
      family,
      audience: PAYMENT_CAPABILITY_AUDIENCE[family],
      state: "built_disabled",
      dependencies: [...PAYMENT_CAPABILITY_DEPENDENCY_ORDER],
    })),
    routes: PAYMENT_ROUTES.map((route) => ({ ...route })),
    ...overrides,
  };
}

describe("payment capability registry", () => {
  it("freezes exactly five routes in two audiences with no observation route", () => {
    expect(PAYMENT_ROUTES).toEqual(EXPECTED);
    expect(INDEX_ROUTES).toBe(PAYMENT_ROUTES);
    expect(PAYMENT_ROUTE_IDS).toEqual(EXPECTED.map((route) => route.id));
    expect(Object.isFrozen(PAYMENT_ROUTES)).toBe(true);
    expect(Object.isFrozen(PAYMENT_ROUTES[0])).toBe(true);
    // Inherited names are never frozen ids: the lookup is own-property only.
    expect(Object.hasOwn(PAYMENT_ROUTE_INDEX, "toString")).toBe(false);
    expect(PaymentRouteDescriptorSchema.safeParse({ ...PAYMENT_ROUTES[1], id: "toString" }).success).toBe(false);
    for (const route of PAYMENT_ROUTES) {
      expect(route.path.startsWith(PAYMENT_CAPABILITY_AUDIENCE_PREFIX[route.audience])).toBe(true);
      expect(route.path).not.toMatch(/observ|settle|release|refund/iu);
    }
    expect(PAYMENT_CAPABILITIES_PATH).toBe("/v2/public/payment-capabilities");
    expect(PAYMENT_CAPABILITY_CREDENTIAL).toEqual({ browser: "browser_session_cookie", agent: "oacs_v1_commerce_session" });
    expect(PAYMENT_CAPABILITY_DEPENDENCY_ORDER.at(-1)).toBe("commercePaymentDatabase");
  });

  it("shares no path with the grant registry", () => {
    const grantPaths = new Set([GRANT_CAPABILITIES_PATH, ...GRANT_ROUTES.map((route) => route.path)]);
    for (const path of [PAYMENT_CAPABILITIES_PATH, ...PAYMENT_ROUTES.map((route) => route.path)]) {
      expect(grantPaths.has(path)).toBe(false);
    }
  });

  it("accepts the canonical manifest in every state", () => {
    for (const state of ["enabled", "built_disabled", "unavailable"]) {
      const value = manifest();
      (value["capabilities"] as { state: string }[]).forEach((entry) => {
        entry.state = state;
      });
      expect(PaymentCapabilityManifestSchema.safeParse(value).success).toBe(true);
    }
  });

  it("rejects a reordered, mixed-state, extended or drifted manifest", () => {
    const base = manifest();
    const capabilities = base["capabilities"] as Record<string, unknown>[];
    const routes = base["routes"] as Record<string, unknown>[];
    const rejected: Record<string, unknown>[] = [
      manifest({ capabilities: [...capabilities].reverse() }),
      manifest({ capabilities: [capabilities[0], { ...capabilities[1], state: "enabled" }] }),
      manifest({ routes: [...routes].reverse() }),
      manifest({ routes: [...routes, { ...routes[0] }] }),
      manifest({ routes: [{ ...routes[0], path: "/v2/agent/payment-terms" }, ...routes.slice(1)] }),
      manifest({ capabilities: [{ ...capabilities[0], audience: "agent" }, capabilities[1]] }),
      manifest({ capabilities: [{ ...capabilities[0], dependencies: [...PAYMENT_CAPABILITY_DEPENDENCY_ORDER].reverse() }, capabilities[1]] }),
      manifest({ extra: true }),
    ];
    for (const value of rejected) {
      expect(PaymentCapabilityManifestSchema.safeParse(value).success).toBe(false);
    }
    expect(PaymentRouteDescriptorSchema.safeParse({ id: "payment_attempt_observe", family: "commerce_payment_attempt", audience: "agent", method: "POST", path: "/v2/agent/commerce-payment-attempts/:attemptId/observe" }).success).toBe(false);
  });
});
