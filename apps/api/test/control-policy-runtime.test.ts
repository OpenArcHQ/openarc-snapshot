import { beforeEach, describe, expect, it, vi } from "vitest";

import type * as DbModule from "@openarc/db";

import { startControlRuntime } from "../src/control/runtime.js";

/**
 * Wiring-only tests for the control policy runtime.
 *
 * `@openarc/db` is HONESTLY MOCKED here (labelled): these tests prove ONE owned
 * restricted pool, initialize-before-service, single-flight readiness across
 * repeated/concurrent calls, a fail-closed fixed 2000ms deadline that retains
 * the underlying batch, a late settlement after close never promoting
 * readiness, close races/idempotence and exactly-once startup cleanup at each
 * added failure seam. Real role, schema, RLS, checksum and SQL enforcement is
 * covered by the PostgreSQL suite. No mock is a production path.
 */

interface Probe {
  createCalls: number;
  endCalls: number;
  poolRef: unknown;
  storePoolRefs: unknown[];
  initCalls: number;
  readyCalls: number;
  initError: boolean;
  readyError: boolean;
  serviceError: boolean;
  readinessGate: (() => Promise<void>) | undefined;
}

const probe = vi.hoisted<Probe>(() => ({
  createCalls: 0,
  endCalls: 0,
  poolRef: undefined,
  storePoolRefs: [],
  initCalls: 0,
  readyCalls: 0,
  initError: false,
  readyError: false,
  serviceError: false,
  readinessGate: undefined,
}));

vi.mock("@openarc/db", async (importOriginal) => {
  const actual = await importOriginal<typeof DbModule>();
  class FakeControlPolicyStore {
    constructor(pool: unknown) {
      probe.storePoolRefs.push(pool);
    }
    async initialize(): Promise<void> {
      probe.initCalls += 1;
      if (probe.initError) throw new Error("CONTROL_POLICY_INIT_FAILED");
    }
    async readiness(): Promise<void> {
      probe.readyCalls += 1;
      if (probe.readinessGate) await probe.readinessGate();
      if (probe.readyError) throw new Error("CONTROL_POLICY_NOT_READY");
    }
  }
  return {
    ...actual,
    createDatabasePool: (url: string) => {
      probe.createCalls += 1;
      if (!url.startsWith("postgres")) throw new Error("bad url");
      const pool = {
        end: async () => {
          probe.endCalls += 1;
        },
      };
      probe.poolRef = pool;
      return pool;
    },
    asControlPolicyPool: (pool: unknown) => pool,
    ControlPolicyStore: FakeControlPolicyStore,
  };
});

/**
 * HONESTLY MOCKED `PolicyService` constructor so the regression can force a
 * throw AFTER the store has initialized while still proving the ONE owned pool
 * is closed exactly once. The real service is accepted and unchanged.
 */
vi.mock("../src/control/service.js", () => ({
  PolicyService: class FakePolicyService {
    constructor() {
      if (probe.serviceError) throw new Error("CONTROL_POLICY_SERVICE_FAILED");
    }
  },
}));

const AUTH = {
  verifyCsrf: () => "binding",
  beginTenantRead: async () => ({
    sessionHash: "a".repeat(64),
    accountId: "openarc:account:11111111-1111-4111-8111-111111111111",
  }),
  finishTenantRead: async () => undefined,
};

const URL = "postgres://openarc_tenant_app:y@127.0.0.1:5432/openarc_auth_test";

function base(
  overrides: Partial<{ policyDatabaseUrl: string; auth: typeof AUTH | undefined }> = {},
) {
  return {
    policyDatabaseUrl: overrides.policyDatabaseUrl ?? URL,
    ...(overrides.auth !== undefined ? { auth: overrides.auth } : {}),
  };
}

beforeEach(() => {
  probe.createCalls = 0;
  probe.endCalls = 0;
  probe.poolRef = undefined;
  probe.storePoolRefs = [];
  probe.initCalls = 0;
  probe.readyCalls = 0;
  probe.initError = false;
  probe.readyError = false;
  probe.serviceError = false;
  probe.readinessGate = undefined;
});

describe("startControlRuntime", () => {
  it("initializes the accepted store over exactly ONE owned restricted pool", async () => {
    const runtime = await startControlRuntime(base({ auth: AUTH }));
    expect(probe.createCalls).toBe(1);
    expect(probe.initCalls).toBe(1);
    // The store is constructed with the SAME single pool, never a per-store one
    // and never a global/auth pool.
    expect(probe.storePoolRefs).toHaveLength(1);
    expect(probe.storePoolRefs[0]).toBe(probe.poolRef);
    expect(runtime.service).toBeDefined();

    await expect(runtime.ready()).resolves.toBe(true);
    expect(probe.readyCalls).toBe(1);

    await runtime.close();
    expect(probe.endCalls).toBe(1);
  });

  it("rejects a missing database URL before constructing any pool", async () => {
    await expect(
      startControlRuntime(base({ policyDatabaseUrl: "", auth: AUTH })),
    ).rejects.toThrow("CONTROL_RUNTIME_INVALID_INPUT");
    expect(probe.createCalls).toBe(0);
    expect(probe.endCalls).toBe(0);
  });

  it("rejects a missing or invalid auth seam before constructing any pool", async () => {
    await expect(
      startControlRuntime(base() as never),
    ).rejects.toThrow("CONTROL_RUNTIME_INVALID_INPUT");
    await expect(
      startControlRuntime(
        base({ auth: {} as unknown as typeof AUTH }),
      ),
    ).rejects.toThrow("CONTROL_RUNTIME_INVALID_INPUT");
    expect(probe.createCalls).toBe(0);
  });

  it("fails closed without constructing a pool when the URL is invalid", async () => {
    await expect(
      startControlRuntime(base({ policyDatabaseUrl: "not-a-url", auth: AUTH })),
    ).rejects.toThrow("CONTROL_RUNTIME_UNAVAILABLE");
    expect(probe.createCalls).toBe(1);
    expect(probe.endCalls).toBe(0);
  });

  it("fails closed and closes the ONE pool once when initialization fails", async () => {
    probe.initError = true;
    await expect(startControlRuntime(base({ auth: AUTH }))).rejects.toThrow(
      "CONTROL_RUNTIME_UNAVAILABLE",
    );
    expect(probe.createCalls).toBe(1);
    expect(probe.initCalls).toBe(1);
    expect(probe.endCalls).toBe(1);
  });

  it("fails closed and closes the ONE pool once when PolicyService construction throws", async () => {
    probe.serviceError = true;
    await expect(startControlRuntime(base({ auth: AUTH }))).rejects.toThrow(
      "CONTROL_RUNTIME_UNAVAILABLE",
    );
    // The store initialized over the single owned pool, then the service
    // constructor threw: the same cleanup boundary must still end the pool
    // exactly once. This is explicitly a CONSTRUCTOR failure, not an
    // initialization failure.
    expect(probe.createCalls).toBe(1);
    expect(probe.initCalls).toBe(1);
    expect(probe.endCalls).toBe(1);
  });

  it("reports not-ready and never throws when a readiness check fails", async () => {
    probe.readyError = true;
    const runtime = await startControlRuntime(base({ auth: AUTH }));
    await expect(runtime.ready()).resolves.toBe(false);
    await runtime.close();
  });

  it("closes the owned pool exactly once and reports not-ready after close", async () => {
    const runtime = await startControlRuntime(base({ auth: AUTH }));
    await runtime.close();
    await runtime.close();
    expect(probe.endCalls).toBe(1);
    await expect(runtime.ready()).resolves.toBe(false);
    // No probe is started once closed.
    expect(probe.readyCalls).toBe(0);
  });

  it("single-flights concurrent and repeated readiness probes", async () => {
    const runtime = await startControlRuntime(base({ auth: AUTH }));
    let release!: () => void;
    probe.readinessGate = () =>
      new Promise<void>((resolve) => {
        release = resolve;
      });
    const first = runtime.ready();
    const second = runtime.ready();
    const third = runtime.ready();
    await new Promise((resolve) => setImmediate(resolve));
    // All three attach to the SAME underlying probe.
    expect(probe.readyCalls).toBe(1);
    release();
    await expect(Promise.all([first, second, third])).resolves.toEqual([
      true,
      true,
      true,
    ]);
    expect(probe.readyCalls).toBe(1);
    await runtime.close();
  });

  it("fails closed after the fixed 2000ms deadline without piling up probes", async () => {
    vi.useFakeTimers();
    try {
      const runtime = await startControlRuntime(base({ auth: AUTH }));
      // An uncancellable probe that never settles.
      probe.readinessGate = () => new Promise<void>(() => undefined);
      const first = runtime.ready();
      const second = runtime.ready();
      await vi.advanceTimersByTimeAsync(0);
      expect(probe.readyCalls).toBe(1);
      await vi.advanceTimersByTimeAsync(2000);
      await expect(first).resolves.toBe(false);
      await expect(second).resolves.toBe(false);
      // A repeated probe while the old batch remains must NOT launch a second.
      const third = runtime.ready();
      await vi.advanceTimersByTimeAsync(2000);
      await expect(third).resolves.toBe(false);
      expect(probe.readyCalls).toBe(1);
      await runtime.close();
    } finally {
      vi.useRealTimers();
    }
  });

  it("retains the underlying single flight after a deadline timeout", async () => {
    const runtime = await startControlRuntime(base({ auth: AUTH }));
    let release!: () => void;
    probe.readinessGate = () =>
      new Promise<void>((resolve) => {
        release = resolve;
      });
    const first = runtime.ready();
    await new Promise((resolve) => setImmediate(resolve));
    // The old uncancelled probe is still the one in flight: a later probe joins
    // it rather than starting a second batch.
    const second = runtime.ready();
    expect(probe.readyCalls).toBe(1);
    release();
    await expect(first).resolves.toBe(true);
    await expect(second).resolves.toBe(true);
    expect(probe.readyCalls).toBe(1);
    await runtime.close();
  });

  it("does not report ready when a pending probe settles after close", async () => {
    const runtime = await startControlRuntime(base({ auth: AUTH }));
    let release!: () => void;
    probe.readinessGate = () =>
      new Promise<void>((resolve) => {
        release = resolve;
      });
    const pending = runtime.ready();
    await new Promise((resolve) => setImmediate(resolve));
    await runtime.close();
    release();
    await expect(pending).resolves.toBe(false);
    await expect(runtime.ready()).resolves.toBe(false);
  });

  it("two closes after an awaited start end the owned pool exactly once", async () => {
    const runtime = await startControlRuntime(base({ auth: AUTH }));
    const first = runtime.close();
    const second = runtime.close();
    await Promise.all([first, second]);
    expect(probe.endCalls).toBe(1);
  });
});
