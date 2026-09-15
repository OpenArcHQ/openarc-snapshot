import { describe, expect, it } from "vitest";

import { ACTION_ROUTES } from "@openarc/shared";

import { commerceActionsEnabled } from "../src/tenant/action-availability.js";
import {
  ACTION_ROUTE_IDS,
  ACTION_AGENT_ROUTE_IDS,
} from "../src/tenant/action-client.js";
import {
  actionRouteHref,
  isActionPath,
  parseActionRoute,
} from "../src/tenant/action-routes.js";
import { ACTION, ACTION_B, APPROVAL } from "./action-test-fixtures.js";

describe("commerce action availability gate", () => {
  it("is false for every default/absent value", () => {
    expect(commerceActionsEnabled(undefined, undefined, undefined, undefined)).toBe(false);
    expect(commerceActionsEnabled(false, false, false, false)).toBe(false);
    expect(commerceActionsEnabled("false", "true", "true", "true")).toBe(false);
  });

  it("requires the exact literal true on all four flags", () => {
    expect(commerceActionsEnabled(true, true, true, true)).toBe(true);
    expect(commerceActionsEnabled("true", "true", "true", "true")).toBe(true);
    expect(commerceActionsEnabled(true, true, true, false)).toBe(false);
    expect(commerceActionsEnabled(true, true, false, true)).toBe(false);
    expect(commerceActionsEnabled(true, false, true, true)).toBe(false);
  });

  it("does not accept truthy non-boolean values", () => {
    expect(commerceActionsEnabled(1 as never, "true", "true", "true")).toBe(false);
    expect(commerceActionsEnabled("TRUE", "true", "true", "true")).toBe(false);
    expect(commerceActionsEnabled("yes", "true", "true", "true")).toBe(false);
    expect(commerceActionsEnabled(" true", "true", "true", "true")).toBe(false);
  });

  it("never depends on the tenant-writes, machine, listing, policy or session flags", () => {
    // The signature has no writes/machine/listing/policy/session parameter at
    // all; the gate is independent by construction.
    expect(commerceActionsEnabled).toHaveLength(4);
  });
});

describe("action route registry exposure", () => {
  it("exposes exactly the nine frozen browser commerce_action_management ids", () => {
    const expected = ACTION_ROUTES.filter(
      (route) => route.family === "commerce_action_management",
    )
      .map((route) => route.id)
      .sort();
    expect([...ACTION_ROUTE_IDS].sort()).toEqual(expected);
    expect(ACTION_ROUTE_IDS).toHaveLength(9);
  });

  it("keeps the three agent-audience authorization ids out of the browser set", () => {
    expect([...ACTION_AGENT_ROUTE_IDS].sort()).toEqual([
      "action_authorize",
      "agent_action_detail",
      "agent_action_mutation_status",
    ]);
    for (const id of ACTION_AGENT_ROUTE_IDS) {
      expect(ACTION_ROUTE_IDS).not.toContain(id);
    }
  });
});

describe("action route parsing", () => {
  it("parses the three static routes", () => {
    expect(parseActionRoute("/app/actions")).toEqual({ kind: "queue" });
    expect(parseActionRoute("/app/actions/")).toEqual({ kind: "queue" });
    expect(parseActionRoute("/app/actions/approvals")).toEqual({ kind: "approvals" });
    expect(parseActionRoute("/app/actions/exposure")).toEqual({ kind: "exposure" });
  });

  it("matches the literal approvals and exposure segments before any dynamic id", () => {
    // `approvals` and `exposure` are not canonical action ids, so a dynamic
    // branch would have produced `invalid` instead of the static route.
    expect(parseActionRoute("/app/actions/approvals")).toEqual({ kind: "approvals" });
    expect(parseActionRoute("/app/actions/exposure")).toEqual({ kind: "exposure" });
  });

  it("parses a canonical action id and a canonical approval id", () => {
    expect(parseActionRoute(`/app/actions/${encodeURIComponent(ACTION)}`)).toEqual({
      kind: "detail",
      actionId: ACTION,
    });
    expect(
      parseActionRoute(`/app/actions/approvals/${encodeURIComponent(APPROVAL)}`),
    ).toEqual({ kind: "approval-detail", approvalId: APPROVAL });
  });

  it("rejects a non-canonical, double-encoded, traversal or cross-kind segment", () => {
    for (const bad of [
      "/app/actions/not-an-action",
      `/app/actions/${encodeURIComponent(APPROVAL)}`,
      `/app/actions/approvals/${encodeURIComponent(ACTION)}`,
      "/app/actions/openarc%253Aaction%253A1",
      "/app/actions/../secrets",
      `/app/actions/${ACTION}/extra`,
      "/app/actions/approvals/a/b",
    ]) {
      expect(parseActionRoute(bad)).toEqual({ kind: "invalid" });
    }
  });

  it("returns null outside the action subtree and never claims a neighbouring path", () => {
    expect(parseActionRoute("/app/sessions")).toBeNull();
    expect(parseActionRoute("/app/budgets")).toBeNull();
    expect(parseActionRoute("/app/actionsx")).toBeNull();
    expect(isActionPath("/app/actions")).toBe(true);
    expect(isActionPath("/app/sessions")).toBe(false);
  });

  it("round-trips every parsed route to a stable href", () => {
    expect(actionRouteHref({ kind: "queue" })).toBe("/app/actions");
    expect(actionRouteHref({ kind: "approvals" })).toBe("/app/actions/approvals");
    expect(actionRouteHref({ kind: "exposure" })).toBe("/app/actions/exposure");
    expect(actionRouteHref({ kind: "detail", actionId: ACTION_B })).toBe(
      `/app/actions/${encodeURIComponent(ACTION_B)}`,
    );
    expect(actionRouteHref({ kind: "approval-detail", approvalId: APPROVAL })).toBe(
      `/app/actions/approvals/${encodeURIComponent(APPROVAL)}`,
    );
    expect(actionRouteHref({ kind: "invalid" })).toBe("/app/actions");
  });
});
