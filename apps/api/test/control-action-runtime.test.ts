import { describe, expect, it } from "vitest";

import { CommerceActionService } from "../src/control/action-service.js";
import {
  actionDependenciesConfigured,
  startCommerceActionRuntime,
  type CommerceActionRuntimeDependencies,
} from "../src/control/action-runtime.js";

/**
 * Runtime wiring coverage with honest fakes.
 *
 * The runtime owns no pool and imports no database module: the DB10/DB11 store
 * is injected through the narrow port. These tests pin the DEFAULT-OFF gate,
 * the zero-side-effect disabled path, and the bounded readiness/close
 * behaviour. Nothing here opens a connection, moves funds or implies a payment.
 */

const STORE_METHODS = [
  "authorizeCommerceAction",
  "approveCommerceAction",
  "rejectCommerceAction",
  "cancelCommerceAction",
  "getHumanCommerceActionMutationStatus",
  "getAgentCommerceActionMutationStatus",
  "getCommerceAction",
  "getAgentCommerceAction",
  "getCommerceExposure",
  "listCommerceActions",
  "listCommerceApprovals",
  "getCommerceApproval",
] as const;

function fakeStore(touched: string[]): Record<string, unknown> {
  const store: Record<string, unknown> = {};
  for (const name of STORE_METHODS) {
    store[name] = async () => {
      touched.push(name);
      return {};
    };
  }
  return store;
}

interface Built {
  dependencies: CommerceActionRuntimeDependencies;
  touched: string[];
  lifecycle: string[];
}

function deps(
  overrides: Partial<CommerceActionRuntimeDependencies> = {},
  lifecycleOverrides: {
    initializeThrows?: boolean;
    readinessThrows?: boolean;
    readinessDelayMs?: number;
  } = {},
): Built {
  const touched: string[] = [];
  const lifecycle: string[] = [];
  const dependencies: CommerceActionRuntimeDependencies = {
    enabled: true,
    authSecret: "unit-test-secret",
    auth: {
      verifyCsrf: () => {
        touched.push("verifyCsrf");
        return "ok";
      },
      beginTenantRead: async () => {
        touched.push("beginTenantRead");
        return { sessionHash: "hash", accountId: "account" };
      },
      finishTenantRead: async () => {
        touched.push("finishTenantRead");
      },
    },
    rateLimitStore: {
      consume: async () => {
        touched.push("consume");
        return { allowed: true };
      },
    },
    store: fakeStore(touched) as never,
    commerceSessions: {
      getCommerceSessionByHash: async () => {
        touched.push("getCommerceSessionByHash");
        return {};
      },
    },
    lifecycle: {
      initialize: async () => {
        lifecycle.push("initialize");
        if (lifecycleOverrides.initializeThrows === true) {
          throw new Error("initialize failed");
        }
      },
      readiness: async () => {
        lifecycle.push("readiness");
        if (lifecycleOverrides.readinessDelayMs !== undefined) {
          await new Promise((resolve) =>
            setTimeout(resolve, lifecycleOverrides.readinessDelayMs),
          );
        }
        if (lifecycleOverrides.readinessThrows === true) {
          throw new Error("not ready");
        }
      },
      close: async () => {
        lifecycle.push("close");
      },
    },
    ...overrides,
  };
  return { dependencies, touched, lifecycle };
}

describe("the gate defaults OFF and fails closed", () => {
  it("reports built_disabled with no `enabled` field at all", async () => {
    const built = deps();
    const withoutFlag: CommerceActionRuntimeDependencies = {
      ...built.dependencies,
    };
    delete (withoutFlag as { enabled?: boolean }).enabled;
    expect(Object.hasOwn(withoutFlag, "enabled")).toBe(false);
    const runtime = await startCommerceActionRuntime(withoutFlag);
    expect(runtime.state).toBe("built_disabled");
    expect(runtime.service).toBeUndefined();
    expect(await runtime.ready()).toBe(false);
    await runtime.close();
    expect(built.lifecycle).toEqual([]);
    expect(built.touched).toEqual([]);
  });

  it("performs ZERO side effects for every incomplete configuration", async () => {
    const missing: readonly Partial<CommerceActionRuntimeDependencies>[] = [
      { enabled: false },
      { authSecret: "" },
      { authSecret: undefined },
      { auth: undefined },
      { rateLimitStore: undefined },
      { store: undefined },
      { commerceSessions: undefined },
      { auth: {} as never },
      { rateLimitStore: {} as never },
      { commerceSessions: {} as never },
    ];
    for (const override of missing) {
      const built = deps(override);
      expect(actionDependenciesConfigured(built.dependencies)).toBe(false);
      const runtime = await startCommerceActionRuntime(built.dependencies);
      expect([JSON.stringify(Object.keys(override)), runtime.state]).toEqual([
        JSON.stringify(Object.keys(override)),
        "built_disabled",
      ]);
      expect(runtime.service).toBeUndefined();
      expect(await runtime.ready()).toBe(false);
      await runtime.close();
      // No initialize, no readiness probe, no close, no store call.
      expect(built.lifecycle).toEqual([]);
      expect(built.touched).toEqual([]);
    }
  });

  it("reports built_disabled when the store is missing even one operation", async () => {
    for (const omitted of STORE_METHODS) {
      const touched: string[] = [];
      const store = fakeStore(touched);
      delete store[omitted];
      const built = deps({ store: store as never });
      const runtime = await startCommerceActionRuntime(built.dependencies);
      expect([omitted, runtime.state]).toEqual([omitted, "built_disabled"]);
      expect(built.lifecycle).toEqual([]);
    }
  });
});

describe("an enabled runtime wires the service exactly once", () => {
  it("initializes before the service exists and exposes it", async () => {
    const built = deps();
    const runtime = await startCommerceActionRuntime(built.dependencies);
    expect(runtime.state).toBe("enabled");
    expect(runtime.service).toBeInstanceOf(CommerceActionService);
    expect(built.lifecycle).toEqual(["initialize"]);
    await runtime.close();
    expect(built.lifecycle).toEqual(["initialize", "close"]);
  });

  it("closes the lifecycle exactly once when construction fails", async () => {
    const built = deps({}, { initializeThrows: true });
    await expect(
      startCommerceActionRuntime(built.dependencies),
    ).rejects.toThrow("COMMERCE_ACTION_RUNTIME_UNAVAILABLE");
    expect(built.lifecycle).toEqual(["initialize", "close"]);
  });

  it("reports ready, unready and never ready after close", async () => {
    const ok = deps();
    const runtime = await startCommerceActionRuntime(ok.dependencies);
    expect(await runtime.ready()).toBe(true);
    await runtime.close();
    expect(await runtime.ready()).toBe(false);
    // Close is idempotent.
    await runtime.close();
    expect(ok.lifecycle.filter((entry) => entry === "close")).toHaveLength(1);

    const bad = deps({}, { readinessThrows: true });
    const failing = await startCommerceActionRuntime(bad.dependencies);
    expect(await failing.ready()).toBe(false);
    await failing.close();
  });

  it("shares ONE in-flight readiness probe across concurrent callers", async () => {
    const built = deps({}, { readinessDelayMs: 25 });
    const runtime = await startCommerceActionRuntime(built.dependencies);
    const results = await Promise.all([
      runtime.ready(),
      runtime.ready(),
      runtime.ready(),
    ]);
    expect(results).toEqual([true, true, true]);
    expect(built.lifecycle.filter((entry) => entry === "readiness")).toHaveLength(
      1,
    );
    await runtime.close();
  });

  it("treats an absent lifecycle as ready without probing anything", async () => {
    const built = deps({ lifecycle: undefined });
    const runtime = await startCommerceActionRuntime(built.dependencies);
    expect(runtime.state).toBe("enabled");
    expect(await runtime.ready()).toBe(true);
    await runtime.close();
    expect(built.lifecycle).toEqual([]);
  });
});
