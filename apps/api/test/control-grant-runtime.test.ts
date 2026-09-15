import { describe, expect, it } from "vitest";

import {
  createCommerceGrantSessionReadAdapter,
  createCommerceGrantStoreAdapter,
} from "../src/control/grant-store-adapter.js";
import {
  grantDependenciesConfigured,
  startCommerceGrantRuntime,
  type CommerceGrantRuntimeDependencies,
} from "../src/control/grant-runtime.js";
import type {
  CommerceGrantAuthPort,
  CommerceGrantRateLimitStorePort,
  CommerceGrantSessionReadPort,
  CommerceGrantStorePort,
} from "../src/control/grant-ports.js";
import {
  ATTEMPT,
  CLAIM_DIGEST,
  CLAIMED,
  GRANT,
  MUTATION,
  ORG,
  claimedProviderView,
  grantMetadata,
  grantReceipt,
  providerAttemptStatus,
  providerView,
} from "./grant-fixtures.js";

/**
 * Runtime gate and store-binding coverage with HONEST fakes.
 *
 * The gate is DEFAULT OFF and fails closed: a disabled or incompletely
 * configured family performs ZERO side effects — no initialize, no readiness
 * probe, no limiter construction, no store call and no close. Nothing here
 * opens a pool, runs a migration or performs a payment.
 */

const AUTH: CommerceGrantAuthPort = {
  verifyCsrf: () => "ok",
  beginTenantRead: async () => ({ sessionHash: "hash", accountId: "account" }),
  finishTenantRead: async () => undefined,
};

const RATE_STORE: CommerceGrantRateLimitStorePort = {
  consume: async () => ({ allowed: true }),
};

const SESSIONS: CommerceGrantSessionReadPort = {
  getCommerceSessionByHash: async () => null,
};

/** The exact nine operations the service depends on, one per frozen route. */
const STORE_METHODS = [
  "issueCommerceGrant",
  "replaceCommerceGrant",
  "getAgentCommerceGrantMutationStatus",
  "introspectCommerceGrant",
  "claimCommerceGrant",
  "getProviderCommerceGrantAttemptStatus",
  "getCommerceGrant",
  "getHumanCommerceGrantMutationStatus",
  "revokeCommerceGrant",
] as const;

function fakeStore(
  omit?: (typeof STORE_METHODS)[number],
): CommerceGrantStorePort {
  const store: Record<string, unknown> = {};
  for (const name of STORE_METHODS) {
    if (name === omit) continue;
    store[name] = async () => undefined;
  }
  return store as unknown as CommerceGrantStorePort;
}

function deps(
  overrides: Partial<CommerceGrantRuntimeDependencies> = {},
): CommerceGrantRuntimeDependencies {
  return {
    enabled: true,
    authSecret: "unit-test-secret",
    auth: AUTH,
    rateLimitStore: RATE_STORE,
    store: fakeStore(),
    commerceSessions: SESSIONS,
    ...overrides,
  };
}

interface LifecycleSpy {
  readonly calls: string[];
  initialize(): Promise<void>;
  readiness(): Promise<void>;
  close(): Promise<void>;
}

function lifecycle(options: { readyThrows?: boolean } = {}): LifecycleSpy {
  const calls: string[] = [];
  return {
    calls,
    async initialize() {
      calls.push("initialize");
    },
    async readiness() {
      calls.push("readiness");
      if (options.readyThrows === true) throw new Error("probe failed");
    },
    async close() {
      calls.push("close");
    },
  };
}

describe("the grant runtime gate is default off", () => {
  it("reports built_disabled with no gate, an absent gate or a missing seam", async () => {
    const cases: CommerceGrantRuntimeDependencies[] = [
      {},
      deps({ enabled: false }),
      { ...deps(), enabled: undefined },
      deps({ authSecret: "" }),
      deps({ authSecret: undefined }),
      deps({ auth: undefined }),
      deps({ auth: {} as unknown as CommerceGrantAuthPort }),
      deps({ rateLimitStore: undefined }),
      deps({ commerceSessions: undefined }),
      deps({ store: undefined }),
    ];
    for (const [index, dependency] of cases.entries()) {
      expect([index, grantDependenciesConfigured(dependency)]).toEqual([
        index,
        false,
      ]);
      const started = await startCommerceGrantRuntime(dependency);
      expect([index, started.state]).toEqual([index, "built_disabled"]);
      expect(started.service).toBeUndefined();
      expect(await started.ready()).toBe(false);
      await started.close();
    }
  });

  it("refuses a store that is missing ANY one of the nine operations", async () => {
    for (const method of STORE_METHODS) {
      const dependency = deps({ store: fakeStore(method) });
      expect([method, grantDependenciesConfigured(dependency)]).toEqual([
        method,
        false,
      ]);
      const started = await startCommerceGrantRuntime(dependency);
      expect([method, started.state]).toEqual([method, "built_disabled"]);
    }
  });

  it("performs ZERO side effects while disabled", async () => {
    const spy = lifecycle();
    const started = await startCommerceGrantRuntime(
      deps({ enabled: false, lifecycle: spy }),
    );
    expect(started.state).toBe("built_disabled");
    expect(await started.ready()).toBe(false);
    await started.close();
    // Not even `close` runs on a caller-supplied dependency the runtime never
    // took ownership of.
    expect(spy.calls).toEqual([]);
  });
});

describe("the enabled grant runtime", () => {
  it("initializes once, exposes a service and probes readiness read-only", async () => {
    const spy = lifecycle();
    const started = await startCommerceGrantRuntime(deps({ lifecycle: spy }));
    expect(started.state).toBe("enabled");
    expect(started.service).toBeDefined();
    expect(spy.calls).toEqual(["initialize"]);
    expect(await started.ready()).toBe(true);
    expect(spy.calls).toEqual(["initialize", "readiness"]);
    await started.close();
    expect(spy.calls).toEqual(["initialize", "readiness", "close"]);
  });

  it("reports not ready when the probe fails, and never after close", async () => {
    const failing = await startCommerceGrantRuntime(
      deps({ lifecycle: lifecycle({ readyThrows: true }) }),
    );
    expect(await failing.ready()).toBe(false);
    await failing.close();

    const spy = lifecycle();
    const started = await startCommerceGrantRuntime(deps({ lifecycle: spy }));
    await started.close();
    expect(await started.ready()).toBe(false);
    // A repeated close runs the injected close at most once.
    await started.close();
    expect(spy.calls.filter((entry) => entry === "close")).toHaveLength(1);
  });

  it("shares ONE in-flight readiness batch across concurrent probes", async () => {
    let probes = 0;
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const started = await startCommerceGrantRuntime(
      deps({
        lifecycle: {
          initialize: async () => undefined,
          readiness: async () => {
            probes += 1;
            await gate;
          },
          close: async () => undefined,
        },
      }),
    );
    const first = started.ready();
    const second = started.ready();
    release?.();
    expect(await first).toBe(true);
    expect(await second).toBe(true);
    expect(probes).toBe(1);
    await started.close();
  });

  it("releases the lifecycle exactly once when construction fails", async () => {
    const spy = lifecycle();
    await expect(
      startCommerceGrantRuntime(
        deps({
          lifecycle: {
            ...spy,
            initialize: async () => {
              spy.calls.push("initialize");
              throw new Error("initialize failed");
            },
          },
        }),
      ),
    ).rejects.toThrow("COMMERCE_GRANT_RUNTIME_UNAVAILABLE");
    expect(spy.calls).toEqual(["initialize", "close"]);
  });
});

/**
 * Store-adapter binding coverage.
 *
 * The adapter renames methods and reshapes results; it performs no authority,
 * validation, retry or logging of its own. These tests use a structural fake in
 * the shape of `ControlGrantStore`; the COMPILE-TIME proof that the real
 * `ControlGrantStore` satisfies these call sites lives in the adapter module
 * itself, whose parameter is typed as that class.
 */
class FakeGrantStore {
  readonly calls: { name: string; args: unknown[] }[] = [];

  async issueForReservedAction(...args: unknown[]): Promise<unknown> {
    this.calls.push({ name: "issueForReservedAction", args });
    return {
      replayed: false,
      metadata: grantMetadata(),
      receipt: grantReceipt("control.grant.issue"),
    };
  }
  async replaceUnclaimedGrant(...args: unknown[]): Promise<unknown> {
    this.calls.push({ name: "replaceUnclaimedGrant", args });
    return {
      replayed: false,
      metadata: grantMetadata({ generation: "2" }),
      receipt: grantReceipt("control.grant.replace"),
    };
  }
  async introspectGrant(...args: unknown[]): Promise<unknown> {
    this.calls.push({ name: "introspectGrant", args });
    return providerView();
  }
  async claimGrant(...args: unknown[]): Promise<unknown> {
    this.calls.push({ name: "claimGrant", args });
    return {
      replayed: false,
      view: claimedProviderView(),
      attemptId: ATTEMPT,
      claimedAt: CLAIMED,
      claimDigest: CLAIM_DIGEST,
      receipt: grantReceipt("control.grant.claim"),
    };
  }
  async revokeGrant(...args: unknown[]): Promise<unknown> {
    this.calls.push({ name: "revokeGrant", args });
    return {
      replayed: false,
      metadata: grantMetadata({ status: "revoked", revokedAt: CLAIMED, updatedAt: CLAIMED }),
      receipt: grantReceipt("control.grant.revoke"),
      released: true,
      actionStatus: "cancelled",
      reservationStatus: "released",
    };
  }
  async readGrant(...args: unknown[]): Promise<unknown> {
    this.calls.push({ name: "readGrant", args });
    return null;
  }
  async readProviderAttemptStatus(...args: unknown[]): Promise<unknown> {
    this.calls.push({ name: "readProviderAttemptStatus", args });
    return providerAttemptStatus();
  }
  async getHumanMutationStatus(...args: unknown[]): Promise<unknown> {
    this.calls.push({ name: "getHumanMutationStatus", args });
    return {
      status: "committed",
      receipt: grantReceipt("control.grant.revoke"),
    };
  }
  async getAgentMutationStatus(...args: unknown[]): Promise<unknown> {
    this.calls.push({ name: "getAgentMutationStatus", args });
    return { status: "not_found" };
  }
}

describe("the grant store adapter", () => {
  function adapter(): {
    port: CommerceGrantStorePort;
    store: FakeGrantStore;
  } {
    const store = new FakeGrantStore();
    return {
      port: createCommerceGrantStoreAdapter(
        store as unknown as Parameters<
          typeof createCommerceGrantStoreAdapter
        >[0],
      ),
      store,
    };
  }

  it("renames each port operation onto its DB12 method, arguments intact", async () => {
    const { port, store } = adapter();
    const metadata = { idempotencyKey: "A".repeat(43), mutationId: MUTATION };
    await port.issueCommerceGrant(
      "session-hash",
      { actionId: "a", grantTokenHash: "b" },
      metadata,
    );
    await port.replaceCommerceGrant(
      "session-hash",
      { grantId: GRANT, grantTokenHash: "b" },
      metadata,
    );
    await port.introspectCommerceGrant("provider-hash", "token-hash");
    await port.claimCommerceGrant(
      "provider-hash",
      { grantTokenHash: "b", expectedActionId: "a", attemptId: ATTEMPT },
      metadata,
    );
    await port.getProviderCommerceGrantAttemptStatus("provider-hash", ATTEMPT);
    await port.getCommerceGrant("human-hash", ORG, GRANT);
    await port.revokeCommerceGrant("human-hash", ORG, GRANT, metadata);
    expect(store.calls.map((call) => call.name)).toEqual([
      "issueForReservedAction",
      "replaceUnclaimedGrant",
      "introspectGrant",
      "claimGrant",
      "readProviderAttemptStatus",
      "readGrant",
      "revokeGrant",
    ]);
    expect(store.calls[2]?.args).toEqual(["provider-hash", "token-hash"]);
    expect(store.calls[6]?.args).toEqual(["human-hash", ORG, GRANT, metadata]);
  });

  it("wraps the four bare store results into the declared envelopes", async () => {
    const { port } = adapter();
    const introspection = await port.introspectCommerceGrant("p", "t");
    expect(Object.keys(introspection)).toEqual(["item"]);

    const attempt = await port.getProviderCommerceGrantAttemptStatus("p", ATTEMPT);
    expect(Object.keys(attempt).sort()).toEqual(["attemptId", "item"]);
    expect(attempt.attemptId).toBe(ATTEMPT);

    const detail = await port.getCommerceGrant("h", ORG, GRANT);
    expect(Object.keys(detail).sort()).toEqual([
      "grantId",
      "item",
      "organizationId",
    ]);
    // A missing grant under a passing authority is a safe null, not an error.
    expect(detail.item).toBeNull();

    const claim = await port.claimCommerceGrant(
      "p",
      { grantTokenHash: "b", expectedActionId: "a", attemptId: ATTEMPT },
      { idempotencyKey: "A".repeat(43), mutationId: MUTATION },
    );
    // DB12 names the projection `view`; the wire names it `item`.
    expect(Object.keys(claim).sort()).toEqual([
      "attemptId",
      "claimDigest",
      "claimedAt",
      "item",
      "receipt",
      "replayed",
    ]);
    expect(claim.item).toEqual(claimedProviderView());
  });

  it("passes the store's reservation status through without interpreting it", async () => {
    const { port } = adapter();
    const revoke = await port.revokeCommerceGrant(
      "h",
      ORG,
      GRANT,
      { idempotencyKey: "A".repeat(43), mutationId: MUTATION },
    );
    expect(revoke.reservationStatus).toBe("released");
    expect(revoke.released).toBe(true);
    expect(revoke.actionStatus).toBe("cancelled");
  });

  it("binds the two mutation-status reads onto the real DB14 store reads", async () => {
    const { port, store } = adapter();
    // The 503 stub is GONE: both ports now reach a real store method with the
    // caller arguments intact and in order, and return the store's own closed
    // committed-or-not-found answer verbatim.
    const agent = await port.getAgentCommerceGrantMutationStatus(
      "session",
      MUTATION,
    );
    const human = await port.getHumanCommerceGrantMutationStatus(
      "human-hash",
      ORG,
      MUTATION,
    );
    expect(store.calls.map((call) => call.name)).toEqual([
      "getAgentMutationStatus",
      "getHumanMutationStatus",
    ]);
    expect(store.calls[0]?.args).toEqual(["session", MUTATION]);
    expect(store.calls[1]?.args).toEqual(["human-hash", ORG, MUTATION]);
    // A miss stays a bare `not_found`; the adapter adds no echoed identifier.
    expect(agent).toEqual({ status: "not_found" });
    expect(Object.keys(agent)).toEqual(["status"]);
    // A committed receipt crosses unchanged and is the REVOKE receipt on the
    // human lane, never an agent issue/replace one.
    expect(human).toEqual({
      status: "committed",
      receipt: grantReceipt("control.grant.revoke"),
    });
    expect(Object.keys(human).sort()).toEqual(["receipt", "status"]);
    // The adapter never reaches for the grant projection or a mutation to
    // synthesize an answer.
    expect(
      store.calls.every(
        (call) =>
          call.name === "getAgentMutationStatus" ||
          call.name === "getHumanMutationStatus",
      ),
    ).toBe(true);
    // No stub error class survives in the adapter module.
    expect(
      Object.keys(
        (await import("../src/control/grant-store-adapter.js")) as Record<
          string,
          unknown
        >,
      ).sort(),
    ).toEqual([
      "createCommerceGrantSessionReadAdapter",
      "createCommerceGrantStoreAdapter",
    ]);
  });

  it("binds the commerce-session read as a pure rename", async () => {
    const calls: unknown[] = [];
    const port = createCommerceGrantSessionReadAdapter({
      getCommerceSessionByHash: async (hash: unknown) => {
        calls.push(hash);
        return { ok: true };
      },
    } as unknown as Parameters<
      typeof createCommerceGrantSessionReadAdapter
    >[0]);
    expect(await port.getCommerceSessionByHash("hash")).toEqual({ ok: true });
    expect(calls).toEqual(["hash"]);
  });
});
