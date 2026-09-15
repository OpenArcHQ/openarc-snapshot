import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { actionDependenciesConfigured } from "../src/control/action-runtime.js";
import type * as ActionRuntimeModule from "../src/control/action-runtime.js";

/**
 * Startup ownership and binding regressions for the commerce-action runtime
 * seam in server.ts.
 *
 * `@openarc/db`, the other runtime factories and `createApp`/`listen` are
 * HONESTLY MOCKED (labelled). The commerce-action runtime itself is deliberately
 * NOT mocked: the real `startCommerceActionRuntime` runs, so these tests prove
 * the state it actually reaches for a given binding rather than asserting a
 * stub. No real server, network, database, pool or secret is constructed.
 *
 * What is proved here: with the flag on and every seam bound the runtime
 * reaches `enabled` and hands `createApp` a service plus a readiness callback;
 * the family opens exactly ONE pool, over the dedicated restricted URL, and
 * initializes all three stores exactly once before any route may serve; that
 * pool is closed exactly once on shutdown, on a createApp/listen failure and on
 * a `built_disabled` outcome; with a seam unbound the runtime still reports
 * `built_disabled`, hands over NO service and startup fails closed; and with
 * the flag off nothing is constructed, opened or closed at all.
 */

interface Handle {
  name: string;
  closeCalls: number;
}

type ServerConfig = Record<string, unknown>;

const state = vi.hoisted(() => ({
  order: [] as string[],
  handles: new Map<string, Handle>(),
  listenError: false,
  createAppError: false,
  exitCalls: 0,
  closed: 0,
  createAppArgs: undefined as Record<string, unknown> | undefined,
  config: {} as ServerConfig,
  // Mocked @openarc/db surface.
  poolUrls: [] as string[],
  poolEnds: 0,
  poolEndThrows: false,
  storeCalls: [] as string[],
  initializeThrows: false,
  // Seam-removal probe: the named dependency key is deleted from the object
  // server.ts actually built, immediately before the REAL runtime consumes it.
  dropSeam: undefined as string | undefined,
  capturedDeps: undefined as Record<string, unknown> | undefined,
  runtimeState: undefined as string | undefined,
}));

function defaultConfig(): ServerConfig {
  return {
    NODE_ENV: "test",
    AUTH_ENABLED: true,
    AUTH_DATABASE_URL: "postgres://openarc_auth_app:x@127.0.0.1:5432/openarc_auth_test",
    AUTH_SECRET: "synthetic_auth_secret_for_action_startup_0123456789",
    AUTH_RP_ID: "localhost",
    AUTH_RATE_GLOBAL_PER_MINUTE: 60,
    AUTH_RATE_PEER_PER_HOUR: 600,
    AUTH_RATE_BINDING_PER_HOUR: 60,
    AUTH_RATE_RECOVERY_PER_15MIN: 10,
    APP_ORIGIN: "http://localhost:5183",
    TENANT_READS_ENABLED: false,
    TENANT_WRITES_ENABLED: false,
    TENANT_DATABASE_URL: "postgres://openarc_tenant_app:y@127.0.0.1:5432/openarc_auth_test",
    POLICY_MANAGEMENT_ENABLED: false,
    COMMERCE_SESSIONS_ENABLED: false,
    COMMERCE_ACTIONS_ENABLED: true,
    MARKET_CATALOG_ENABLED: false,
    LISTING_MANAGEMENT_ENABLED: false,
    MARKET_MODERATION_ENABLED: false,
    MACHINE_CREDENTIAL_MANAGEMENT_ENABLED: false,
    MACHINE_SESSION_EXCHANGE_ENABLED: false,
    ARC_OBSERVATION_ENABLED: false,
    GATEWAY_EVIDENCE_ENABLED: false,
    REDIS_URL: undefined,
    COMMIT_SHA: "0123456789abcdef0123456789abcdef01234567",
    HOST: "127.0.0.1",
    PORT: 0,
  };
}

function makeHandle(name: string): Handle {
  const handle: Handle = { name, closeCalls: 0 };
  state.handles.set(name, handle);
  return handle;
}

/** HONEST MOCK of the database package: no pool, no socket, no SQL. */
vi.mock("@openarc/db", () => {
  const mutationMethods = [
    "authorizeCommerceAction",
    "approveCommerceAction",
    "rejectCommerceAction",
    "cancelCommerceAction",
    "getHumanMutationStatus",
    "getAgentMutationStatus",
    "readAction",
    "readAgentAction",
    "readExposure",
  ];
  function stub(target: Record<string, unknown>, names: readonly string[]): void {
    for (const name of names) {
      target[name] = async (): Promise<unknown> => ({});
    }
  }
  class FakeControlActionStore {
    constructor() {
      state.storeCalls.push("construct:mutations");
      stub(this as unknown as Record<string, unknown>, mutationMethods);
    }
    async initialize(): Promise<void> {
      state.storeCalls.push("initialize:mutations");
      if (state.initializeThrows) throw new Error("MUTATION_STORE_INIT_FAILED");
    }
    async readiness(): Promise<void> {
      state.storeCalls.push("readiness:mutations");
    }
  }
  class FakeControlActionReadStore {
    constructor() {
      state.storeCalls.push("construct:reads");
      stub(this as unknown as Record<string, unknown>, [
        "listActions",
        "listApprovals",
        "readApprovalById",
      ]);
    }
    async initialize(): Promise<void> {
      state.storeCalls.push("initialize:reads");
    }
    async readiness(): Promise<void> {
      state.storeCalls.push("readiness:reads");
    }
  }
  class FakeCommerceSessionStore {
    constructor() {
      state.storeCalls.push("construct:sessions");
      (this as unknown as Record<string, unknown>)["getCommerceSessionByHash"] =
        async (): Promise<unknown> => null;
    }
    async initialize(): Promise<void> {
      state.storeCalls.push("initialize:sessions");
    }
    async readiness(): Promise<void> {
      state.storeCalls.push("readiness:sessions");
    }
  }
  return {
    createDatabasePool: (url: string) => {
      state.poolUrls.push(url);
      state.order.push("pool");
      return {
        end: async (): Promise<void> => {
          state.poolEnds += 1;
          if (state.poolEndThrows) throw new Error("POOL_END_FAILED");
        },
      };
    },
    asControlActionPool: (pool: unknown) => pool,
    asControlActionReadPool: (pool: unknown) => pool,
    asCommerceSessionPool: (pool: unknown) => pool,
    ControlActionStore: FakeControlActionStore,
    ControlActionReadStore: FakeControlActionReadStore,
    CommerceSessionStore: FakeCommerceSessionStore,
  };
});

vi.mock("../src/auth/runtime.js", () => ({
  startAuthRuntime: async () => {
    state.order.push("auth");
    const handle = makeHandle("auth");
    return {
      service: {
        verifyCsrf: () => "ok",
        beginTenantRead: async () => ({ sessionHash: "hash", accountId: "account" }),
        finishTenantRead: async () => undefined,
      },
      rateLimitStore: { consume: async () => ({ allowed: true }) },
      ready: async () => true,
      close: async () => {
        handle.closeCalls += 1;
      },
    };
  },
}));

vi.mock("../src/tenant/runtime.js", () => ({
  startTenantRuntime: async () => {
    const handle = makeHandle("tenant");
    return { service: {}, ready: async () => true, close: async () => { handle.closeCalls += 1; } };
  },
}));

vi.mock("../src/market/runtime.js", () => ({
  startMarketRuntime: async () => {
    const handle = makeHandle("market");
    return { ready: async () => true, close: async () => { handle.closeCalls += 1; } };
  },
}));

vi.mock("../src/machine/runtime.js", () => ({
  startMachineRuntime: async () => {
    const handle = makeHandle("machine");
    return {
      managementService: {},
      sessionService: {},
      ready: async () => true,
      close: async () => { handle.closeCalls += 1; },
    };
  },
}));

vi.mock("../src/control/runtime.js", () => ({
  startControlRuntime: async () => {
    const handle = makeHandle("control");
    return { service: {}, ready: async () => true, close: async () => { handle.closeCalls += 1; } };
  },
}));

vi.mock("../src/control/session-runtime.js", () => ({
  startCommerceSessionRuntime: async () => {
    state.order.push("session");
    const handle = makeHandle("session");
    return { service: {}, ready: async () => true, close: async () => { handle.closeCalls += 1; } };
  },
}));

/**
 * NOT a stub: the REAL commerce-action runtime runs. This wrapper only records
 * the dependency object server.ts actually built and, when a seam-removal probe
 * is armed, deletes exactly that one key before handing the object to the real
 * implementation -- so `built_disabled` is produced by the real gate rather than
 * asserted by a fake.
 */
vi.mock("../src/control/action-runtime.js", async (importOriginal) => {
  const actual = await importOriginal<typeof ActionRuntimeModule>();
  return {
    ...actual,
    startCommerceActionRuntime: async (dependencies: Record<string, unknown>) => {
      state.capturedDeps = dependencies;
      const effective = { ...dependencies };
      if (state.dropSeam !== undefined) delete effective[state.dropSeam];
      const started = await actual.startCommerceActionRuntime(
        effective as Parameters<typeof actual.startCommerceActionRuntime>[0],
      );
      state.runtimeState = started.state;
      return started;
    },
  };
});

vi.mock("../src/app.js", () => ({
  createApp: (options: Record<string, unknown>) => {
    state.order.push("createApp");
    state.createAppArgs = options;
    if (state.createAppError) throw new Error("CREATE_APP_FAILED");
    return {
      close: async () => {
        state.closed += 1;
      },
      listen: async () => {
        state.order.push("listen");
        if (state.listenError) throw new Error("LISTEN_FAILED");
      },
    };
  },
}));

vi.mock("../src/config.js", () => ({
  loadConfig: () => state.config,
}));

async function loadServer(): Promise<void> {
  vi.resetModules();
  await import("../src/server.js");
  await new Promise((resolve) => setTimeout(resolve, 0));
}

let signalHandlers: Array<() => void> = [];

beforeEach(() => {
  state.order = [];
  state.handles = new Map();
  state.listenError = false;
  state.createAppError = false;
  state.exitCalls = 0;
  state.closed = 0;
  state.createAppArgs = undefined;
  state.config = defaultConfig();
  state.poolUrls = [];
  state.poolEnds = 0;
  state.poolEndThrows = false;
  state.storeCalls = [];
  state.initializeThrows = false;
  state.dropSeam = undefined;
  state.capturedDeps = undefined;
  state.runtimeState = undefined;
  signalHandlers = [];
  vi.spyOn(process, "once").mockImplementation(((event: string, handler: () => void) => {
    if (event === "SIGINT" || event === "SIGTERM") signalHandlers.push(handler);
    return process;
  }) as never);
  vi.spyOn(process, "exit").mockImplementation((() => {
    state.exitCalls += 1;
    return undefined;
  }) as never);
});

afterEach(() => {
  vi.restoreAllMocks();
});

function closeCount(name: string): number {
  return state.handles.get(name)?.closeCalls ?? 0;
}

describe("the bound commerce-action runtime reaches enabled", () => {
  it("opens one dedicated pool, initializes every store once and hands createApp a service", async () => {
    await loadServer();
    expect(state.exitCalls).toBe(0);
    // Exactly one pool, over the dedicated restricted tenant URL.
    expect(state.poolUrls).toEqual([state.config["TENANT_DATABASE_URL"]]);
    expect(state.order).toEqual(["auth", "pool", "createApp", "listen"]);
    // The three stores are constructed over that one pool and initialized
    // exactly once, BEFORE createApp may register any route.
    expect(state.storeCalls).toEqual([
      "construct:mutations",
      "construct:reads",
      "construct:sessions",
      "initialize:mutations",
      "initialize:reads",
      "initialize:sessions",
    ]);
    // The runtime reached `enabled`: a service and a readiness callback exist.
    expect(state.runtimeState).toBe("enabled");
    expect(state.createAppArgs?.["commerceActionService"]).toBeDefined();
    expect(typeof state.createAppArgs?.["commerceActionReady"]).toBe("function");
    // Every seam the enabled family requires was really bound by server.ts,
    // including the commerce-session bearer read this packet adds.
    const deps = state.capturedDeps as Record<string, unknown>;
    expect(deps["enabled"]).toBe(true);
    expect(deps["authSecret"]).toBe(state.config["AUTH_SECRET"]);
    expect(typeof (deps["commerceSessions"] as Record<string, unknown>)["getCommerceSessionByHash"])
      .toBe("function");
    expect(typeof (deps["store"] as Record<string, unknown>)["authorizeCommerceAction"]).toBe(
      "function",
    );
    expect(typeof (deps["store"] as Record<string, unknown>)["listCommerceActions"]).toBe(
      "function",
    );
    expect(actionDependenciesConfigured(deps as never)).toBe(true);
    // The bound read really reaches the store method this packet added.
    await (
      (deps["commerceSessions"] as { getCommerceSessionByHash: (h: unknown) => Promise<unknown> })
    ).getCommerceSessionByHash("a".repeat(64));
    // Nothing is closed while the server is serving.
    expect(state.poolEnds).toBe(0);
  });

  it("probes readiness through every bound store without migrating", async () => {
    await loadServer();
    const ready = state.createAppArgs?.["commerceActionReady"] as () => Promise<boolean>;
    state.storeCalls = [];
    expect(await ready()).toBe(true);
    expect(state.storeCalls).toEqual([
      "readiness:mutations",
      "readiness:reads",
      "readiness:sessions",
    ]);
    expect(state.poolEnds).toBe(0);
  });

  it("closes the one owned pool exactly once on shutdown", async () => {
    await loadServer();
    expect(signalHandlers.length).toBeGreaterThan(0);
    for (const handler of signalHandlers) handler();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(state.poolEnds).toBe(1);
    // A second shutdown signal must not double-close it.
    for (const handler of signalHandlers) handler();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(state.poolEnds).toBe(1);
  });
});

describe("the bound commerce-action runtime fails closed", () => {
  it.each(["store", "commerceSessions", "auth", "rateLimitStore", "authSecret", "enabled"])(
    "reports built_disabled and fails startup closed with the %s seam unbound",
    async (seam) => {
      state.dropSeam = seam;
      await loadServer();
      expect(state.runtimeState).toBe("built_disabled");
      // No service and no readiness callback are handed over, so the REAL
      // createApp has nothing to register and fails startup closed. That guard
      // ("Commerce action dependencies are unavailable") is proved against the
      // real createApp in control-action-integration.test.ts; createApp is a
      // stub here, so this test asserts only what server.ts itself owns.
      expect(state.createAppArgs?.["commerceActionService"]).toBeUndefined();
      expect(state.createAppArgs?.["commerceActionReady"]).toBeUndefined();
      // A disabled runtime performs ZERO side effects: no initialize, no
      // readiness probe and no store call at all.
      expect(state.storeCalls).toEqual([
        "construct:mutations",
        "construct:reads",
        "construct:sessions",
      ]);
      // The pool this binding opened is still released exactly once.
      expect(state.poolEnds).toBe(1);
    },
  );

  it("closes the pool exactly once when a store initialization rejects", async () => {
    state.initializeThrows = true;
    await loadServer();
    expect(state.order).not.toContain("createApp");
    expect(state.exitCalls).toBe(1);
    expect(state.poolEnds).toBe(1);
    expect(closeCount("auth")).toBe(1);
  });

  it("closes the pool exactly once when createApp rejects", async () => {
    state.createAppError = true;
    await loadServer();
    expect(state.order).toEqual(["auth", "pool", "createApp"]);
    expect(state.exitCalls).toBe(1);
    expect(state.poolEnds).toBe(1);
    expect(closeCount("auth")).toBe(1);
    expect(state.closed).toBe(0);
  });

  it("closes the pool exactly once when listen fails", async () => {
    state.listenError = true;
    await loadServer();
    expect(state.order).toContain("listen");
    expect(state.exitCalls).toBe(1);
    expect(state.poolEnds).toBe(1);
    expect(state.closed).toBe(1);
  });

  it("survives a pool that throws while closing without masking the failure", async () => {
    state.createAppError = true;
    state.poolEndThrows = true;
    await loadServer();
    expect(state.poolEnds).toBe(1);
    expect(state.exitCalls).toBe(1);
  });
});

describe("the commerce-action gate stays default OFF", () => {
  it("constructs no pool, no store and no runtime when the flag is off", async () => {
    state.config["COMMERCE_ACTIONS_ENABLED"] = false;
    await loadServer();
    expect(state.exitCalls).toBe(0);
    expect(state.poolUrls).toEqual([]);
    expect(state.storeCalls).toEqual([]);
    expect(state.poolEnds).toBe(0);
    expect(state.createAppArgs?.["commerceActionService"]).toBeUndefined();
    expect(state.createAppArgs?.["commerceActionReady"]).toBeUndefined();
    for (const handler of signalHandlers) handler();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(state.poolEnds).toBe(0);
  });
});
