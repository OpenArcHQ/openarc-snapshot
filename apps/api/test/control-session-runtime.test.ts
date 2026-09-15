import { beforeEach, describe, expect, it, vi } from "vitest";

import type * as DbModule from "@openarc/db";

import { startCommerceSessionRuntime } from "../src/control/session-runtime.js";

/**
 * Wiring-only tests for the commerce-session runtime.
 *
 * `@openarc/db` and the accepted service constructor are HONESTLY MOCKED here
 * (labelled): these tests prove ONE owned restricted pool shared by the session
 * store AND the credential current-agent read, initialize-before-service,
 * single-flight readiness across repeated/concurrent calls, a fail-closed fixed
 * 2000ms deadline that retains the underlying batch, a late settlement after
 * close never promoting readiness, close races/idempotence and exactly-once
 * startup cleanup at each added failure seam. Real role, schema, RLS, checksum
 * and SQL enforcement is covered by the PostgreSQL suite.
 */

interface Probe {
  createCalls: number;
  endCalls: number;
  poolRef: unknown;
  storePoolRefs: unknown[];
  credentialPoolRefs: unknown[];
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
  credentialPoolRefs: [],
  initCalls: 0,
  readyCalls: 0,
  initError: false,
  readyError: false,
  serviceError: false,
  readinessGate: undefined,
}));

vi.mock("@openarc/db", async (importOriginal) => {
  const actual = await importOriginal<typeof DbModule>();
  class FakeCommerceSessionStore {
    constructor(pool: unknown) {
      probe.storePoolRefs.push(pool);
    }
    async initialize(): Promise<void> {
      probe.initCalls += 1;
      if (probe.initError) throw new Error("COMMERCE_SESSION_INIT_FAILED");
    }
    async readiness(): Promise<void> {
      probe.readyCalls += 1;
      if (probe.readinessGate) await probe.readinessGate();
      if (probe.readyError) throw new Error("COMMERCE_SESSION_NOT_READY");
    }
  }
  class FakeCredentialStore {
    constructor(pool: unknown) {
      probe.credentialPoolRefs.push(pool);
    }
    async getAgentSession(): Promise<never> {
      throw new Error("unused");
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
    asCommerceSessionPool: (pool: unknown) => pool,
    asCredentialPool: (pool: unknown) => pool,
    CommerceSessionStore: FakeCommerceSessionStore,
    CredentialStore: FakeCredentialStore,
  };
});

/**
 * HONESTLY MOCKED service constructor so the regression can force a throw
 * AFTER the store initialized / the credential read was bound while still
 * proving the ONE owned pool is closed exactly once.
 */
vi.mock("../src/control/session-service.js", () => ({
  CommerceSessionService: class FakeCommerceSessionService {
    constructor() {
      if (probe.serviceError) throw new Error("COMMERCE_SESSION_SERVICE_FAILED");
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

const RATE_STORE = { consume: async () => ({ allowed: true }) };
const URL = "postgres://openarc_tenant_app:y@127.0.0.1:5432/openarc_auth_test";
const SECRET = "synthetic_auth_secret_for_session_runtime_0123456789";

function base(
  overrides: Partial<{
    tenantDatabaseUrl: string;
    authSecret: string;
    auth: unknown;
    rateLimitStore: unknown;
  }> = {},
) {
  return {
    tenantDatabaseUrl: overrides.tenantDatabaseUrl ?? URL,
    authSecret: overrides.authSecret ?? SECRET,
    auth: overrides.auth ?? AUTH,
    rateLimitStore: overrides.rateLimitStore ?? RATE_STORE,
  } as never;
}

beforeEach(() => {
  probe.createCalls = 0;
  probe.endCalls = 0;
  probe.poolRef = undefined;
  probe.storePoolRefs = [];
  probe.credentialPoolRefs = [];
  probe.initCalls = 0;
  probe.readyCalls = 0;
  probe.initError = false;
  probe.readyError = false;
  probe.serviceError = false;
  probe.readinessGate = undefined;
});

describe("startCommerceSessionRuntime", () => {
  it("initializes the accepted store and credential read over exactly ONE shared pool", async () => {
    const runtime = await startCommerceSessionRuntime(base());
    expect(probe.createCalls).toBe(1);
    expect(probe.initCalls).toBe(1);
    expect(probe.storePoolRefs).toHaveLength(1);
    expect(probe.storePoolRefs[0]).toBe(probe.poolRef);
    // The credential current-agent read is bound to the SAME single pool.
    expect(probe.credentialPoolRefs).toHaveLength(1);
    expect(probe.credentialPoolRefs[0]).toBe(probe.poolRef);
    expect(runtime.service).toBeDefined();

    await expect(runtime.ready()).resolves.toBe(true);
    expect(probe.readyCalls).toBe(1);

    await runtime.close();
    expect(probe.endCalls).toBe(1);
  });

  it("rejects a missing database URL before constructing any pool", async () => {
    await expect(
      startCommerceSessionRuntime(base({ tenantDatabaseUrl: "" })),
    ).rejects.toThrow("COMMERCE_SESSION_RUNTIME_INVALID_INPUT");
    expect(probe.createCalls).toBe(0);
    expect(probe.endCalls).toBe(0);
  });

  it("rejects a missing/empty rate secret before constructing any pool", async () => {
    await expect(
      startCommerceSessionRuntime(base({ authSecret: "" })),
    ).rejects.toThrow("COMMERCE_SESSION_RUNTIME_INVALID_INPUT");
    expect(probe.createCalls).toBe(0);
  });

  it("rejects a missing or invalid auth seam before constructing any pool", async () => {
    await expect(
      startCommerceSessionRuntime(base({ auth: {} })),
    ).rejects.toThrow("COMMERCE_SESSION_RUNTIME_INVALID_INPUT");
    expect(probe.createCalls).toBe(0);
  });

  it("rejects a missing or invalid rate-limit store seam before constructing any pool", async () => {
    await expect(
      startCommerceSessionRuntime(base({ rateLimitStore: {} })),
    ).rejects.toThrow("COMMERCE_SESSION_RUNTIME_INVALID_INPUT");
    expect(probe.createCalls).toBe(0);
  });

  it("fails closed without ending a pool that was never constructed", async () => {
    await expect(
      startCommerceSessionRuntime(base({ tenantDatabaseUrl: "not-a-url" })),
    ).rejects.toThrow("COMMERCE_SESSION_RUNTIME_UNAVAILABLE");
    expect(probe.createCalls).toBe(1);
    expect(probe.endCalls).toBe(0);
  });

  it("fails closed and closes the ONE pool once when initialization fails", async () => {
    probe.initError = true;
    await expect(startCommerceSessionRuntime(base())).rejects.toThrow(
      "COMMERCE_SESSION_RUNTIME_UNAVAILABLE",
    );
    expect(probe.createCalls).toBe(1);
    expect(probe.initCalls).toBe(1);
    expect(probe.endCalls).toBe(1);
  });

  it("fails closed and closes the ONE pool once when service construction throws", async () => {
    probe.serviceError = true;
    await expect(startCommerceSessionRuntime(base())).rejects.toThrow(
      "COMMERCE_SESSION_RUNTIME_UNAVAILABLE",
    );
    expect(probe.createCalls).toBe(1);
    expect(probe.initCalls).toBe(1);
    expect(probe.endCalls).toBe(1);
  });

  it("reports not-ready and never throws when a readiness check fails", async () => {
    probe.readyError = true;
    const runtime = await startCommerceSessionRuntime(base());
    await expect(runtime.ready()).resolves.toBe(false);
    await runtime.close();
  });

  it("closes the owned pool exactly once and reports not-ready after close", async () => {
    const runtime = await startCommerceSessionRuntime(base());
    await runtime.close();
    await runtime.close();
    expect(probe.endCalls).toBe(1);
    await expect(runtime.ready()).resolves.toBe(false);
    expect(probe.readyCalls).toBe(0);
  });

  it("single-flights concurrent and repeated readiness probes", async () => {
    const runtime = await startCommerceSessionRuntime(base());
    let release!: () => void;
    probe.readinessGate = () =>
      new Promise<void>((resolve) => {
        release = resolve;
      });
    const first = runtime.ready();
    const second = runtime.ready();
    const third = runtime.ready();
    await new Promise((resolve) => setImmediate(resolve));
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
      const runtime = await startCommerceSessionRuntime(base());
      probe.readinessGate = () => new Promise<void>(() => undefined);
      const first = runtime.ready();
      const second = runtime.ready();
      await vi.advanceTimersByTimeAsync(0);
      expect(probe.readyCalls).toBe(1);
      await vi.advanceTimersByTimeAsync(2000);
      await expect(first).resolves.toBe(false);
      await expect(second).resolves.toBe(false);
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
    const runtime = await startCommerceSessionRuntime(base());
    let release!: () => void;
    probe.readinessGate = () =>
      new Promise<void>((resolve) => {
        release = resolve;
      });
    const first = runtime.ready();
    await new Promise((resolve) => setImmediate(resolve));
    const second = runtime.ready();
    expect(probe.readyCalls).toBe(1);
    release();
    await expect(first).resolves.toBe(true);
    await expect(second).resolves.toBe(true);
    expect(probe.readyCalls).toBe(1);
    await runtime.close();
  });

  it("does not report ready when a pending probe settles after close", async () => {
    const runtime = await startCommerceSessionRuntime(base());
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
    const runtime = await startCommerceSessionRuntime(base());
    const first = runtime.close();
    const second = runtime.close();
    await Promise.all([first, second]);
    expect(probe.endCalls).toBe(1);
  });
});
