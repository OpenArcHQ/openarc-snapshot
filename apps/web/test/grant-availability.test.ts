import { describe, expect, it } from "vitest";

import { GRANT_ROUTES } from "@openarc/shared";

import { commerceGrantsEnabled } from "../src/tenant/grant-availability.js";
import {
  GRANT_AGENT_ROUTE_IDS,
  GRANT_BROWSER_ROUTE_IDS,
  GRANT_PROVIDER_ROUTE_IDS,
} from "../src/tenant/grant-client.js";
import {
  grantRouteHref,
  isGrantPath,
  parseGrantRoute,
} from "../src/tenant/grant-routes.js";
import { ACTION, GRANT, GRANT_B } from "./grant-test-fixtures.js";

/** All six prerequisites on, so a single flag can be flipped per case. */
const ALL_ON = ["true", "true", "true", "true", "true", "true"] as const;

function withFlagOff(index: number) {
  const args = [...ALL_ON] as Array<string | boolean | undefined>;
  args[index] = "false";
  return args as unknown as Parameters<typeof commerceGrantsEnabled>;
}

describe("commerce grant availability gate", () => {
  it("is false for every default/absent value", () => {
    expect(
      commerceGrantsEnabled(undefined, undefined, undefined, undefined, undefined, undefined),
    ).toBe(false);
    expect(commerceGrantsEnabled(false, false, false, false, false, false)).toBe(false);
    expect(commerceGrantsEnabled("false", "true", "true", "true", "true", "true")).toBe(false);
  });

  it("requires the exact literal true on all six flags", () => {
    expect(commerceGrantsEnabled(true, true, true, true, true, true)).toBe(true);
    expect(commerceGrantsEnabled(...ALL_ON)).toBe(true);
    // Each prerequisite alone is sufficient to keep the console off.
    for (let index = 0; index < ALL_ON.length; index += 1) {
      expect(commerceGrantsEnabled(...withFlagOff(index))).toBe(false);
    }
  });

  it("requires the commerce-action and commerce-session surfaces, not only its own flag", () => {
    // A grant exists only because an agent session issued it against an
    // approved action, so neither prerequisite is decorative.
    expect(commerceGrantsEnabled("true", "false", "true", "true", "true", "true")).toBe(false);
    expect(commerceGrantsEnabled("true", "true", "false", "true", "true", "true")).toBe(false);
  });

  it("does not accept truthy non-boolean values", () => {
    expect(commerceGrantsEnabled(1 as never, "true", "true", "true", "true", "true")).toBe(false);
    expect(commerceGrantsEnabled("TRUE", "true", "true", "true", "true", "true")).toBe(false);
    expect(commerceGrantsEnabled("yes", "true", "true", "true", "true", "true")).toBe(false);
    expect(commerceGrantsEnabled(" true", "true", "true", "true", "true", "true")).toBe(false);
    expect(commerceGrantsEnabled("1", "true", "true", "true", "true", "true")).toBe(false);
  });

  it("never depends on the tenant-writes, machine, listing, policy, Vault or wallet flags", () => {
    // The signature has no writes/machine/listing/policy parameter at all; the
    // gate is independent of them by construction.
    expect(commerceGrantsEnabled).toHaveLength(6);
  });
});

describe("grant route registry exposure", () => {
  it("exposes exactly the three frozen browser commerce_grant_management ids", () => {
    const expected = GRANT_ROUTES.filter(
      (route) => route.family === "commerce_grant_management",
    )
      .map((route) => route.id)
      .sort();
    expect([...GRANT_BROWSER_ROUTE_IDS].sort()).toEqual(expected);
    expect([...GRANT_BROWSER_ROUTE_IDS].sort()).toEqual([
      "grant_detail",
      "grant_mutation_status",
      "grant_revoke",
    ]);
    expect(GRANT_BROWSER_ROUTE_IDS).toHaveLength(3);
  });

  it("keeps the three agent and three provider ids out of the browser set", () => {
    expect([...GRANT_AGENT_ROUTE_IDS].sort()).toEqual([
      "agent_grant_mutation_status",
      "grant_issue",
      "grant_replace",
    ]);
    expect([...GRANT_PROVIDER_ROUTE_IDS].sort()).toEqual([
      "provider_grant_attempt_status",
      "provider_grant_claim",
      "provider_grant_introspect",
    ]);
    for (const id of [...GRANT_AGENT_ROUTE_IDS, ...GRANT_PROVIDER_ROUTE_IDS]) {
      expect(GRANT_BROWSER_ROUTE_IDS).not.toContain(id);
    }
    // The nine frozen routes are partitioned exactly three ways.
    expect(
      GRANT_BROWSER_ROUTE_IDS.length +
        GRANT_AGENT_ROUTE_IDS.length +
        GRANT_PROVIDER_ROUTE_IDS.length,
    ).toBe(GRANT_ROUTES.length);
  });

  it("keeps every browser route under the browser audience prefix", () => {
    for (const id of GRANT_BROWSER_ROUTE_IDS) {
      const route = GRANT_ROUTES.find((entry) => entry.id === id);
      expect(route?.audience).toBe("browser");
      expect(route?.path.startsWith("/v2/control/organizations/")).toBe(true);
    }
  });
});

describe("grant route parsing", () => {
  it("parses the lookup root", () => {
    expect(parseGrantRoute("/app/grants")).toEqual({ kind: "lookup" });
    expect(parseGrantRoute("/app/grants/")).toEqual({ kind: "lookup" });
  });

  it("parses a canonical grant id", () => {
    expect(parseGrantRoute(`/app/grants/${encodeURIComponent(GRANT)}`)).toEqual({
      kind: "detail",
      grantId: GRANT,
    });
  });

  it("rejects a non-canonical, double-encoded, traversal or cross-kind segment", () => {
    for (const bad of [
      "/app/grants/not-a-grant",
      `/app/grants/${encodeURIComponent(ACTION)}`,
      "/app/grants/openarc%253Agrant%253A1",
      "/app/grants/../secrets",
      `/app/grants/${GRANT}/extra`,
      "/app/grants/a/b",
      `/app/grants/${encodeURIComponent(GRANT).toUpperCase()}`,
    ]) {
      expect(parseGrantRoute(bad)).toEqual({ kind: "invalid" });
    }
  });

  it("returns null outside the grant subtree and never claims a neighbouring path", () => {
    expect(parseGrantRoute("/app/actions")).toBeNull();
    expect(parseGrantRoute("/app/sessions")).toBeNull();
    expect(parseGrantRoute("/app/grantsx")).toBeNull();
    expect(isGrantPath("/app/grants")).toBe(true);
    expect(isGrantPath("/app/actions")).toBe(false);
  });

  it("publishes no list or queue route at all", () => {
    // The accepted store exposes no list method, so this console must not have
    // one. Any pluralised sub-path is a plain invalid id, never a listing view.
    for (const bad of ["/app/grants/all", "/app/grants/list", "/app/grants/queue"]) {
      expect(parseGrantRoute(bad)).toEqual({ kind: "invalid" });
    }
  });

  it("round-trips every parsed route to a stable href", () => {
    expect(grantRouteHref({ kind: "lookup" })).toBe("/app/grants");
    expect(grantRouteHref({ kind: "detail", grantId: GRANT_B })).toBe(
      `/app/grants/${encodeURIComponent(GRANT_B)}`,
    );
    expect(grantRouteHref({ kind: "invalid" })).toBe("/app/grants");
  });
});
