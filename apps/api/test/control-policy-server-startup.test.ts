import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Startup ownership regressions for the control policy runtime seam in
 * server.ts.
 *
 * Every runtime factory and `createApp`/`listen` is HONESTLY MOCKED (labelled):
 * these tests prove the control runtime is acquired under the SAME cleanup
 * try/finally, that a control start rejection closes the earlier auth/tenant
 * runtimes exactly once, that a later createApp/listen failure closes the
 * control runtime too, that successful startup wires the policy service and
 * readiness callback, and that an OFF flag never starts or closes a control
 * runtime. No real server, network, database or secret is constructed.
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
  tenantError: false,
  marketError: false,
  machineError: false,
  controlError: false,
  listenError: false,
  createAppError: false,
  exitCalls: 0,
  closed: 0,
  controlArgs: undefined as Record<string, unknown> | undefined,
  createAppArgs: undefined as Record<string, unknown> | undefined,
  controlStarts: 0,
  config: {} as ServerConfig,
}));

function defaultConfig(): ServerConfig {
  return {
    NODE_ENV: "test",
    AUTH_ENABLED: true,
    AUTH_DATABASE_URL: "postgres://openarc_auth_app:x@127.0.0.1:5432/openarc_auth_test",
    AUTH_SECRET: "synthetic_auth_secret_for_control_startup_0123456789",
    AUTH_RP_ID: "localhost",
    AUTH_RATE_GLOBAL_PER_MINUTE: 60,
    AUTH_RATE_PEER_PER_HOUR: 600,
    AUTH_RATE_BINDING_PER_HOUR: 60,
    AUTH_RATE_RECOVERY_PER_15MIN: 10,
    APP_ORIGIN: "http://localhost:5183",
    TENANT_READS_ENABLED: true,
    TENANT_WRITES_ENABLED: false,
    TENANT_DATABASE_URL: "postgres://openarc_tenant_app:y@127.0.0.1:5432/openarc_auth_test",
    POLICY_MANAGEMENT_ENABLED: true,
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
      rateLimitStore: {},
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
    if (state.tenantError) throw new Error("TENANT_START_FAILED");
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
    if (state.marketError) throw new Error("MARKET_START_FAILED");
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
    if (state.machineError) throw new Error("MACHINE_START_FAILED");
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
  startControlRuntime: async (options: Record<string, unknown>) => {
    state.order.push("control");
    state.controlStarts += 1;
    state.controlArgs = options;
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
  state.tenantError = false;
  state.marketError = false;
  state.machineError = false;
  state.controlError = false;
  state.listenError = false;
  state.createAppError = false;
  state.exitCalls = 0;
  state.closed = 0;
  state.controlArgs = undefined;
  state.createAppArgs = undefined;
  state.controlStarts = 0;
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

describe("control runtime startup ownership", () => {
  it("closes the earlier auth and tenant runtimes exactly once when control start rejects", async () => {
    state.controlError = true;
    await loadServer();
    expect(state.order).toEqual(["auth", "tenant", "control"]);
    expect(closeCount("auth")).toBe(1);
    expect(closeCount("tenant")).toBe(1);
    expect(closeCount("control")).toBe(0);
    expect(state.exitCalls).toBe(1);
  });

  it("closes the prior control runtime too when createApp rejects", async () => {
    state.createAppError = true;
    await loadServer();
    expect(closeCount("auth")).toBe(1);
    expect(closeCount("tenant")).toBe(1);
    expect(closeCount("control")).toBe(1);
    expect(state.closed).toBe(0);
    expect(state.exitCalls).toBe(1);
  });

  it("closes the control runtime once when listen fails", async () => {
    state.listenError = true;
    await loadServer();
    expect(state.order).toContain("listen");
    expect(closeCount("control")).toBe(1);
    expect(state.closed).toBe(1);
    expect(state.exitCalls).toBe(1);
  });

  it("wires a successful startup and closes control exactly once on shutdown", async () => {
    await loadServer();
    expect(state.order).toEqual([
      "auth",
      "tenant",
      "control",
      "createApp",
      "listen",
    ]);
    expect(state.createAppArgs?.policyManagementService).toBeDefined();
    expect(state.createAppArgs?.policyReady).toBeTypeOf("function");
    expect(closeCount("control")).toBe(0);
    expect(signalHandlers).toHaveLength(2);

    signalHandlers[0]?.();
    await vi.waitFor(() => {
      expect(state.exitCalls).toBe(1);
    });
    expect(state.closed).toBe(1);
    expect(closeCount("auth")).toBe(1);
    expect(closeCount("tenant")).toBe(1);
    expect(closeCount("control")).toBe(1);
  });

  it("passes the dedicated restricted URL and auth seam to the control runtime", async () => {
    await loadServer();
    expect(state.controlArgs).toMatchObject({
      policyDatabaseUrl: state.config.TENANT_DATABASE_URL,
    });
    expect(state.controlArgs?.auth).toBeDefined();
  });

  it("starts and wires policy with tenant reads/writes, machine and market all off", async () => {
    // Narrow independence case through the REAL server seam: AUTH + POLICY on,
    // every independent tenant/market/machine flag off. The policy runtime must
    // start and wire while the tenant runtime NEVER starts; a successful
    // shutdown closes each owned handle exactly once.
    state.config.TENANT_READS_ENABLED = false;
    state.config.TENANT_WRITES_ENABLED = false;
    state.config.MACHINE_CREDENTIAL_MANAGEMENT_ENABLED = false;
    state.config.MACHINE_SESSION_EXCHANGE_ENABLED = false;
    state.config.MARKET_CATALOG_ENABLED = false;
    state.config.LISTING_MANAGEMENT_ENABLED = false;
    state.config.MARKET_MODERATION_ENABLED = false;

    await loadServer();
    expect(state.order).toEqual(["auth", "control", "createApp", "listen"]);
    expect(state.order).not.toContain("tenant");
    expect(state.controlStarts).toBe(1);
    expect(state.createAppArgs?.policyManagementService).toBeDefined();
    expect(state.createAppArgs?.policyReady).toBeTypeOf("function");
    expect(state.createAppArgs?.tenantReadService).toBeUndefined();
    expect(state.createAppArgs?.tenantReady).toBeUndefined();
    expect(signalHandlers).toHaveLength(2);

    signalHandlers[0]?.();
    await vi.waitFor(() => {
      expect(state.exitCalls).toBe(1);
    });
    expect(state.closed).toBe(1);
    expect(closeCount("auth")).toBe(1);
    expect(closeCount("control")).toBe(1);
    // The tenant runtime never started, so it has no owned handle to close.
    expect(closeCount("tenant")).toBe(0);
  });

  it("never starts the control runtime when the flag is off", async () => {
    state.config.POLICY_MANAGEMENT_ENABLED = false;
    await loadServer();
    expect(state.controlStarts).toBe(0);
    expect(state.createAppArgs?.policyManagementService).toBeUndefined();
    expect(state.createAppArgs?.policyReady).toBeUndefined();
    signalHandlers[0]?.();
    await vi.waitFor(() => {
      expect(state.exitCalls).toBe(1);
    });
    expect(closeCount("control")).toBe(0);
  });
});
