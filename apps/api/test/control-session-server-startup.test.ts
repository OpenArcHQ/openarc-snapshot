import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Startup ownership regressions for the commerce-session runtime seam in
 * server.ts.
 *
 * Every runtime factory and `createApp`/`listen` is HONESTLY MOCKED (labelled):
 * these tests prove the session runtime is acquired under the SAME cleanup
 * try/catch, that a session start rejection closes the earlier auth/control
 * runtimes exactly once, that a later createApp/listen failure closes the
 * session runtime too, that successful startup wires the session service and
 * readiness callback with the dedicated URL/secret/auth/rate-limit store, and
 * that an OFF flag never starts or closes a session runtime. No real server,
 * network, database or secret is constructed.
 */

interface Handle {
  name: string;
  closeCalls: number;
}

type ServerConfig = Record<string, unknown>;

const state = vi.hoisted(() => ({
  order: [] as string[],
  handles: new Map<string, Handle>(),
  authError: false,
  controlError: false,
  sessionError: false,
  listenError: false,
  createAppError: false,
  exitCalls: 0,
  closed: 0,
  sessionArgs: undefined as Record<string, unknown> | undefined,
  createAppArgs: undefined as Record<string, unknown> | undefined,
  sessionStarts: 0,
  config: {} as ServerConfig,
}));

function defaultConfig(): ServerConfig {
  return {
    NODE_ENV: "test",
    AUTH_ENABLED: true,
    AUTH_DATABASE_URL: "postgres://openarc_auth_app:x@127.0.0.1:5432/openarc_auth_test",
    AUTH_SECRET: "synthetic_auth_secret_for_session_startup_0123456789",
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
    COMMERCE_SESSIONS_ENABLED: true,
    MARKET_CATALOG_ENABLED: false,
    LISTING_MANAGEMENT_ENABLED: false,
    MARKET_MODERATION_ENABLED: false,
    MACHINE_CREDENTIAL_MANAGEMENT_ENABLED: false,
    MACHINE_SESSION_EXCHANGE_ENABLED: false,
    ARC_OBSERVATION_ENABLED: false,
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

vi.mock("../src/auth/runtime.js", () => ({
  startAuthRuntime: async () => {
    state.order.push("auth");
    if (state.authError) throw new Error("AUTH_START_FAILED");
    const handle = makeHandle("auth");
    return {
      service: {},
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
    state.order.push("tenant");
    const handle = makeHandle("tenant");
    return {
      service: {},
      ready: async () => true,
      close: async () => {
        handle.closeCalls += 1;
      },
    };
  },
}));

vi.mock("../src/market/runtime.js", () => ({
  startMarketRuntime: async () => {
    state.order.push("market");
    const handle = makeHandle("market");
    return {
      ready: async () => true,
      close: async () => {
        handle.closeCalls += 1;
      },
    };
  },
}));

vi.mock("../src/machine/runtime.js", () => ({
  startMachineRuntime: async () => {
    state.order.push("machine");
    const handle = makeHandle("machine");
    return {
      managementService: {},
      sessionService: {},
      ready: async () => true,
      close: async () => {
        handle.closeCalls += 1;
      },
    };
  },
}));

vi.mock("../src/control/runtime.js", () => ({
  startControlRuntime: async () => {
    state.order.push("control");
    if (state.controlError) throw new Error("CONTROL_START_FAILED");
    const handle = makeHandle("control");
    return {
      service: {},
      ready: async () => true,
      close: async () => {
        handle.closeCalls += 1;
      },
    };
  },
}));

vi.mock("../src/control/session-runtime.js", () => ({
  startCommerceSessionRuntime: async (options: Record<string, unknown>) => {
    state.order.push("session");
    state.sessionStarts += 1;
    state.sessionArgs = options;
    if (state.sessionError) throw new Error("SESSION_START_FAILED");
    const handle = makeHandle("session");
    return {
      service: {},
      ready: async () => true,
      close: async () => {
        handle.closeCalls += 1;
      },
    };
  },
}));

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
  state.authError = false;
  state.controlError = false;
  state.sessionError = false;
  state.listenError = false;
  state.createAppError = false;
  state.exitCalls = 0;
  state.closed = 0;
  state.sessionArgs = undefined;
  state.createAppArgs = undefined;
  state.sessionStarts = 0;
  state.config = defaultConfig();
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

describe("commerce session runtime startup ownership", () => {
  it("closes the earlier auth runtime once when session start rejects", async () => {
    state.sessionError = true;
    await loadServer();
    expect(state.order).toEqual(["auth", "session"]);
    expect(closeCount("auth")).toBe(1);
    expect(closeCount("session")).toBe(0);
    expect(state.exitCalls).toBe(1);
  });

  it("closes the prior control and session runtimes when createApp rejects", async () => {
    state.config.POLICY_MANAGEMENT_ENABLED = true;
    state.createAppError = true;
    await loadServer();
    expect(state.order).toEqual(["auth", "control", "session", "createApp"]);
    expect(closeCount("auth")).toBe(1);
    expect(closeCount("control")).toBe(1);
    expect(closeCount("session")).toBe(1);
    expect(state.closed).toBe(0);
    expect(state.exitCalls).toBe(1);
  });

  it("closes the session runtime once when listen fails", async () => {
    state.listenError = true;
    await loadServer();
    expect(state.order).toContain("listen");
    expect(closeCount("session")).toBe(1);
    expect(state.closed).toBe(1);
    expect(state.exitCalls).toBe(1);
  });

  it("wires a successful startup and closes session exactly once on shutdown", async () => {
    await loadServer();
    expect(state.order).toEqual(["auth", "session", "createApp", "listen"]);
    expect(state.createAppArgs?.commerceSessionService).toBeDefined();
    expect(state.createAppArgs?.commerceSessionReady).toBeTypeOf("function");
    expect(closeCount("session")).toBe(0);
    expect(signalHandlers).toHaveLength(2);

    signalHandlers[0]?.();
    await vi.waitFor(() => {
      expect(state.exitCalls).toBe(1);
    });
    expect(state.closed).toBe(1);
    expect(closeCount("auth")).toBe(1);
    expect(closeCount("session")).toBe(1);
  });

  it("passes the restricted URL, secret, auth and durable rate-limit store", async () => {
    await loadServer();
    expect(state.sessionArgs).toMatchObject({
      tenantDatabaseUrl: state.config.TENANT_DATABASE_URL,
      authSecret: state.config.AUTH_SECRET,
    });
    expect(state.sessionArgs?.auth).toBeDefined();
    expect(state.sessionArgs?.rateLimitStore).toBeDefined();
  });

  it("starts session with tenant reads/writes, machine, market and policy all off", async () => {
    await loadServer();
    expect(state.order).toEqual(["auth", "session", "createApp", "listen"]);
    expect(state.order).not.toContain("tenant");
    expect(state.order).not.toContain("control");
    expect(state.order).not.toContain("machine");
    expect(state.order).not.toContain("market");
    expect(state.sessionStarts).toBe(1);
    expect(state.createAppArgs?.commerceSessionService).toBeDefined();
    expect(state.createAppArgs?.commerceSessionReady).toBeTypeOf("function");
    expect(state.createAppArgs?.tenantReadService).toBeUndefined();
    expect(state.createAppArgs?.policyManagementService).toBeUndefined();
    expect(state.createAppArgs?.machineSessionService).toBeUndefined();

    signalHandlers[0]?.();
    await vi.waitFor(() => {
      expect(state.exitCalls).toBe(1);
    });
    expect(closeCount("session")).toBe(1);
    expect(closeCount("tenant")).toBe(0);
    expect(closeCount("control")).toBe(0);
  });

  it("never starts the session runtime when the flag is off", async () => {
    state.config.COMMERCE_SESSIONS_ENABLED = false;
    await loadServer();
    expect(state.sessionStarts).toBe(0);
    expect(state.createAppArgs?.commerceSessionService).toBeUndefined();
    expect(state.createAppArgs?.commerceSessionReady).toBeUndefined();
    signalHandlers[0]?.();
    await vi.waitFor(() => {
      expect(state.exitCalls).toBe(1);
    });
    expect(closeCount("session")).toBe(0);
  });
});
