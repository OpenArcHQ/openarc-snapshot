import { beforeEach, describe, expect, it } from "vitest";

import { AuthApiError } from "../src/auth/errors.js";
import {
  CommerceActionRateLimiter,
  type CommerceActionRateCheck,
} from "../src/control/action-rate-limiter.js";
import { CommerceActionService } from "../src/control/action-service.js";
import type {
  CommerceActionAuthPort,
  CommerceActionRateLimitStorePort,
  CommerceActionStorePort,
  CommerceSessionReadPort,
} from "../src/control/action-ports.js";
import {
  ACTION,
  ACTION_B,
  APPROVAL,
  AGENT,
  CSRF,
  IDEMPOTENCY,
  MUTATION,
  MUTATION_B,
  ORG,
  ORG_B,
  POLICY,
  SESSION_TOKEN,
  actionMetadata,
  actionReceipt,
  approvalMetadata,
  commerceSessionMetadata,
  exposureView,
} from "./action-fixtures.js";

/**
 * Service-level coverage with HONEST injected fakes. No database, network,
 * payment or provider call occurs; the fakes record the exact call order so the
 * "authenticate before disclosure" and "never retry an unknown outcome" rules
 * are proven rather than asserted.
 */

const CTX = {
  peerIp: "127.0.0.1",
  cookies: { session: "abc", binding: "def" },
} as unknown as Parameters<CommerceActionService["listActions"]>[0];

class StoreError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = "CommerceActionStoreError";
    this.code = code;
  }
}

class FakeStore {
  readonly calls: string[] = [];
  results: Record<string, unknown> = {};
  failures: Record<string, string | undefined> = {};

  #run(name: string, fallback: unknown): Promise<never> | Promise<unknown> {
    this.calls.push(name);
    const failure = this.failures[name];
    if (failure !== undefined) return Promise.reject(new StoreError(failure));
    return Promise.resolve(
      Object.hasOwn(this.results, name) ? this.results[name] : fallback,
    );
  }

  authorizeCommerceAction(): Promise<unknown> {
    return this.#run("authorizeCommerceAction", {
      replayed: false,
      metadata: actionMetadata(),
      receipt: actionReceipt("control.commerce_action.authorize"),
    });
  }
  approveCommerceAction(): Promise<unknown> {
    return this.#run("approveCommerceAction", {
      replayed: false,
      metadata: actionMetadata(),
      receipt: actionReceipt("control.commerce_action.approve"),
    });
  }
  rejectCommerceAction(): Promise<unknown> {
    return this.#run("rejectCommerceAction", {
      replayed: false,
      metadata: actionMetadata({ status: "rejected" }),
      receipt: actionReceipt("control.commerce_action.reject"),
    });
  }
  cancelCommerceAction(): Promise<unknown> {
    return this.#run("cancelCommerceAction", {
      replayed: false,
      metadata: actionMetadata({ status: "cancelled" }),
      receipt: actionReceipt("control.commerce_action.cancel"),
    });
  }
  getHumanCommerceActionMutationStatus(): Promise<unknown> {
    return this.#run("getHumanCommerceActionMutationStatus", {
      status: "not_found",
    });
  }
  getAgentCommerceActionMutationStatus(): Promise<unknown> {
    return this.#run("getAgentCommerceActionMutationStatus", {
      status: "not_found",
    });
  }
  getCommerceAction(): Promise<unknown> {
    return this.#run("getCommerceAction", {
      organizationId: ORG,
      item: actionMetadata(),
    });
  }
  getAgentCommerceAction(): Promise<unknown> {
    return this.#run("getAgentCommerceAction", {
      organizationId: ORG,
      item: actionMetadata(),
    });
  }
  getCommerceExposure(): Promise<unknown> {
    return this.#run("getCommerceExposure", {
      organizationId: ORG,
      subjectAgentId: AGENT,
      policyId: POLICY,
      item: exposureView(),
    });
  }
  listCommerceActions(): Promise<unknown> {
    return this.#run("listCommerceActions", {
      items: [actionMetadata()],
      nextCursor: ACTION,
    });
  }
  listCommerceApprovals(): Promise<unknown> {
    return this.#run("listCommerceApprovals", {
      items: [approvalMetadata()],
      nextCursor: APPROVAL,
    });
  }
  getCommerceApproval(): Promise<unknown> {
    return this.#run("getCommerceApproval", {
      organizationId: ORG,
      item: approvalMetadata(),
    });
  }
}

class FakeAuth {
  readonly calls: string[] = [];
  csrfThrows = false;

  verifyCsrf(): string {
    this.calls.push("verifyCsrf");
    if (this.csrfThrows) throw new AuthApiError("CSRF_REJECTED", 403, "INVALID_ORIGIN");
    return "ok";
  }
  async beginTenantRead(): Promise<{
    sessionHash: string;
    accountId: string;
  }> {
    this.calls.push("beginTenantRead");
    return { sessionHash: "hash", accountId: "account" };
  }
  async finishTenantRead(): Promise<void> {
    this.calls.push("finishTenantRead");
  }
}

class FakeCommerceSessions {
  readonly calls: string[] = [];
  results: unknown[] = [];
  failure: string | undefined;

  async getCommerceSessionByHash(): Promise<unknown> {
    this.calls.push("getCommerceSessionByHash");
    if (this.failure !== undefined) throw new StoreError(this.failure);
    const next = this.results.shift();
    return next === undefined ? commerceSessionMetadata() : next;
  }
}

const rateStore: CommerceActionRateLimitStorePort = {
  consume: async () => ({ allowed: true }),
};

interface Harness {
  service: CommerceActionService;
  store: FakeStore;
  auth: FakeAuth;
  sessions: FakeCommerceSessions;
  order: string[];
}

function harness(): Harness {
  const order: string[] = [];
  const store = new FakeStore();
  const auth = new FakeAuth();
  const sessions = new FakeCommerceSessions();
  const track = <T extends object>(target: T, label: string): T =>
    new Proxy(target, {
      get(object, property, receiver) {
        const value = Reflect.get(object, property, receiver);
        if (typeof value !== "function" || typeof property !== "string") {
          return value;
        }
        return (...args: unknown[]) => {
          order.push(`${label}.${property}`);
          return (value as (...input: unknown[]) => unknown).apply(
            object,
            args,
          );
        };
      },
    });
  const service = new CommerceActionService({
    auth: track(auth, "auth") as unknown as CommerceActionAuthPort,
    store: track(store, "store") as unknown as CommerceActionStorePort,
    commerceSessions: track(
      sessions,
      "session",
    ) as unknown as CommerceSessionReadPort,
    limits: new CommerceActionRateLimiter({
      secret: "unit-test-secret",
      store: rateStore,
    }),
  });
  return { service, store, auth, sessions, order };
}

function writeEnvelope(body: unknown) {
  return { csrf: CSRF, idempotencyKey: IDEMPOTENCY, body };
}

async function failure(promise: Promise<unknown>): Promise<AuthApiError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(AuthApiError);
    return error as AuthApiError;
  }
  throw new Error("expected a rejection");
}

let h: Harness;
beforeEach(() => {
  h = harness();
});

describe("browser reads authenticate before any disclosure", () => {
  it("begins and finishes the tenant read around exactly one store read", async () => {
    const page = await h.service.listActions(CTX, { organizationId: ORG });
    expect(page.organizationId).toBe(ORG);
    expect(h.order).toEqual([
      "auth.beginTenantRead",
      "store.listCommerceActions",
      "auth.finishTenantRead",
    ]);
  });

  it("still runs the current-authorization check for a MISSING result", async () => {
    h.store.results["getCommerceAction"] = { organizationId: ORG, item: null };
    const detail = await h.service.getAction(CTX, {
      organizationId: ORG,
      actionId: ACTION,
    });
    expect(detail.item).toBeNull();
    expect(h.order).toEqual([
      "auth.beginTenantRead",
      "store.getCommerceAction",
      "auth.finishTenantRead",
    ]);
  });

  it("still runs the current-authorization check for a not_found mutation status", async () => {
    const status = await h.service.getHumanMutationStatus(CTX, {
      organizationId: ORG,
      mutationId: MUTATION,
    });
    expect(status).toEqual({ status: "not_found" });
    expect(h.order).toEqual([
      "auth.beginTenantRead",
      "store.getHumanCommerceActionMutationStatus",
      "auth.finishTenantRead",
    ]);
  });

  it("never reaches the store for a malformed request", async () => {
    for (const request of [
      { organizationId: "not-an-org" },
      { organizationId: ORG, limit: "0" },
      { organizationId: ORG, limit: "51" },
      { organizationId: ORG, afterActionId: "nope" },
      { organizationId: ORG, unexpected: true },
      { organizationId: ORG, limit: undefined },
    ]) {
      const error = await failure(h.service.listActions(CTX, request));
      expect(error.status).toBe(400);
    }
    expect(h.store.calls).toEqual([]);
    expect(h.auth.calls).toEqual([]);
  });

  it("rejects a store page bound to a foreign organization", async () => {
    h.store.results["listCommerceActions"] = {
      items: [
        actionMetadata({
          exposureKey: {
            organizationId: ORG_B,
            subjectAgentId: AGENT,
            networkId: "eip155:5042002",
            asset: "USDC",
            representation: "erc20",
            decimals: 6,
          },
        }),
      ],
      nextCursor: ACTION,
    };
    const error = await failure(
      h.service.listActions(CTX, { organizationId: ORG }),
    );
    expect(error.status).toBe(503);
  });

  it("rejects a detail whose store organization does not match the request", async () => {
    h.store.results["getCommerceAction"] = {
      organizationId: ORG_B,
      item: null,
    };
    const error = await failure(
      h.service.getAction(CTX, { organizationId: ORG, actionId: ACTION }),
    );
    expect(error.status).toBe(503);
  });

  it("rejects a store envelope carrying an extra key", async () => {
    h.store.results["getCommerceApproval"] = {
      organizationId: ORG,
      item: null,
      extra: "smuggled",
    };
    const error = await failure(
      h.service.getApproval(CTX, {
        organizationId: ORG,
        approvalId: APPROVAL,
      }),
    );
    expect(error.status).toBe(503);
  });

  it("returns exposure amounts as exact integer strings", async () => {
    const data = await h.service.getExposure(CTX, {
      organizationId: ORG,
      subjectAgentId: AGENT,
      policyId: POLICY,
    });
    expect(data.item?.committedAtomic).toBe("123456789012345678901234567890");
    expect(data.item?.totalExposureAtomic).toBe(
      "123456789012345678901234567891",
    );
    expect(typeof data.item?.availableAtomic).toBe("string");
  });
});

describe("browser writes", () => {
  it("validates input, then CSRF, then begins, then mutates exactly once", async () => {
    const data = await h.service.approve(
      CTX,
      ORG,
      ACTION,
      writeEnvelope({ mutationId: MUTATION }),
    );
    expect(data.replayed).toBe(false);
    expect(data.receipt.operation).toBe("control.commerce_action.approve");
    expect(h.order).toEqual([
      "auth.verifyCsrf",
      "auth.beginTenantRead",
      "store.approveCommerceAction",
    ]);
  });

  it("rejects a malformed body before CSRF or any store call", async () => {
    for (const body of [
      {},
      { mutationId: "nope" },
      { mutationId: MUTATION, extra: 1 },
      { mutationId: MUTATION, operation: "control.commerce_action.approve" },
    ]) {
      const error = await failure(
        h.service.reject(CTX, ORG, ACTION, writeEnvelope(body)),
      );
      expect(error.status).toBe(400);
    }
    expect(h.auth.calls).toEqual([]);
    expect(h.store.calls).toEqual([]);
  });

  it("never mutates when CSRF is rejected", async () => {
    h.auth.csrfThrows = true;
    const error = await failure(
      h.service.cancel(CTX, ORG, ACTION, writeEnvelope({ mutationId: MUTATION })),
    );
    expect(error.status).toBe(403);
    expect(h.store.calls).toEqual([]);
  });

  it("rejects a receipt bound to the wrong operation, mutation or action", async () => {
    const drifts: readonly Record<string, unknown>[] = [
      {
        replayed: false,
        metadata: actionMetadata(),
        receipt: actionReceipt("control.commerce_action.cancel"),
      },
      {
        replayed: false,
        metadata: actionMetadata(),
        receipt: actionReceipt("control.commerce_action.approve", {
          mutationId: MUTATION_B,
        }),
      },
      {
        replayed: false,
        metadata: actionMetadata(),
        receipt: actionReceipt("control.commerce_action.approve", {
          resourceId: ACTION_B,
        }),
      },
      {
        replayed: "yes",
        metadata: actionMetadata(),
        receipt: actionReceipt("control.commerce_action.approve"),
      },
    ];
    for (const drift of drifts) {
      const local = harness();
      local.store.results["approveCommerceAction"] = drift;
      const error = await failure(
        local.service.approve(
          CTX,
          ORG,
          ACTION,
          writeEnvelope({ mutationId: MUTATION }),
        ),
      );
      expect(error.status).toBe(503);
    }
  });

  it("maps the fixed store failure vocabulary without echoing input", async () => {
    // The EXACT and COMPLETE DB10 `ControlActionStoreError` vocabulary, in the
    // store's own spelling. A code the store cannot raise is not listed here:
    // there is no APPROVAL_REQUIRED (an approval requirement is a SUCCESS
    // outcome), no BUDGET_EXCEEDED and no RESERVATION_CONFLICT.
    const expected: readonly [string, number, string][] = [
      ["CONTROL_ACTION_STORE_INPUT_INVALID", 400, "INVALID_REQUEST"],
      ["CONTROL_ACTION_STORE_SESSION_INVALID", 401, "UNAUTHENTICATED"],
      ["CONTROL_ACTION_STORE_FORBIDDEN", 403, "FORBIDDEN"],
      ["CONTROL_ACTION_STORE_NOT_FOUND", 403, "FORBIDDEN"],
      ["CONTROL_ACTION_STORE_CONFLICT", 409, "POLICY_DENIED"],
      ["CONTROL_ACTION_STORE_IDEMPOTENCY_CONFLICT", 409, "IDEMPOTENCY_CONFLICT"],
      ["CONTROL_ACTION_STORE_BUDGET_DENIED", 409, "BUDGET_LIMIT_EXCEEDED"],
      [
        "CONTROL_ACTION_STORE_POTENTIAL_EXPOSURE",
        409,
        "BUDGET_RESERVATION_CONFLICT",
      ],
      ["CONTROL_ACTION_STORE_STALE_TERMS", 409, "POLICY_DENIED"],
      ["CONTROL_ACTION_STORE_REQUIREMENT_UNAVAILABLE", 503, "INTERNAL_ERROR"],
      ["CONTROL_ACTION_STORE_OUTCOME_UNKNOWN", 500, "INTERNAL_ERROR"],
      ["CONTROL_ACTION_STORE_UNAVAILABLE", 503, "INTERNAL_ERROR"],
      ["SOMETHING_ELSE_ENTIRELY", 503, "INTERNAL_ERROR"],
    ];
    for (const [code, status, apiCode] of expected) {
      const local = harness();
      local.store.failures["approveCommerceAction"] = code;
      const error = await failure(
        local.service.approve(
          CTX,
          ORG,
          ACTION,
          writeEnvelope({ mutationId: MUTATION }),
        ),
      );
      expect([code, error.status]).toEqual([code, status]);
      expect([code, error.code]).toEqual([code, apiCode]);
      expect(error.message).not.toContain(ORG);
      expect(error.message).not.toContain(ACTION);
      expect(error.message).not.toContain(IDEMPOTENCY);
      expect(error.message).not.toContain(CSRF);
    }
  });

  it("never maps a stale code the real store cannot raise to a caller answer", async () => {
    // The previous vocabulary is not DB10's. If any of it survived, one of
    // these would stop being the fixed unrecognized-dependency 503.
    for (const code of [
      "COMMERCE_ACTION_STORE_INPUT_INVALID",
      "COMMERCE_ACTION_STORE_SESSION_INVALID",
      "COMMERCE_ACTION_STORE_FORBIDDEN",
      "COMMERCE_ACTION_STORE_NOT_FOUND",
      "COMMERCE_ACTION_STORE_CONFLICT",
      "COMMERCE_ACTION_STORE_APPROVAL_REQUIRED",
      "COMMERCE_ACTION_STORE_BUDGET_EXCEEDED",
      "COMMERCE_ACTION_STORE_RESERVATION_CONFLICT",
      "COMMERCE_ACTION_STORE_IDEMPOTENCY_CONFLICT",
      "COMMERCE_ACTION_STORE_OUTCOME_UNKNOWN",
      "COMMERCE_ACTION_STORE_UNAVAILABLE",
      "CONTROL_ACTION_STORE_APPROVAL_REQUIRED",
      "CONTROL_ACTION_STORE_BUDGET_EXCEEDED",
      "CONTROL_ACTION_STORE_RESERVATION_CONFLICT",
    ]) {
      const local = harness();
      local.store.failures["approveCommerceAction"] = code;
      const error = await failure(
        local.service.approve(
          CTX,
          ORG,
          ACTION,
          writeEnvelope({ mutationId: MUTATION }),
        ),
      );
      expect([code, error.status, error.code]).toEqual([
        code,
        503,
        "INTERNAL_ERROR",
      ]);
    }
  });
});

describe("an unknown outcome is terminal", () => {
  it("maps an unknown outcome to the fixed non-retryable result and never retries", async () => {
    for (const method of [
      "approveCommerceAction",
      "rejectCommerceAction",
      "cancelCommerceAction",
    ] as const) {
      const local = harness();
      local.store.failures[method] = "CONTROL_ACTION_STORE_OUTCOME_UNKNOWN";
      const call =
        method === "approveCommerceAction"
          ? local.service.approve(
              CTX,
              ORG,
              ACTION,
              writeEnvelope({ mutationId: MUTATION }),
            )
          : method === "rejectCommerceAction"
            ? local.service.reject(
                CTX,
                ORG,
                ACTION,
                writeEnvelope({ mutationId: MUTATION }),
              )
            : local.service.cancel(
                CTX,
                ORG,
                ACTION,
                writeEnvelope({ mutationId: MUTATION }),
              );
      const error = await failure(call);
      // A DEFINITIVE 500, never the 503 that a client, agent or proxy may read
      // as a transient outage worth repeating, and never the generic
      // unavailable mapping every other dependency failure collapses to.
      expect(error.status).toBe(500);
      expect(error.code).toBe("INTERNAL_ERROR");
      expect(error.status).not.toBe(503);
      // Never reported as success, a refund or a release, and never retried.
      expect(local.store.calls).toEqual([method]);
      expect(local.store.calls.filter((name) => name === method)).toHaveLength(
        1,
      );
      expect(error.message.toLowerCase()).not.toContain("refund");
      expect(error.message.toLowerCase()).not.toContain("release");
      expect(error.message.toLowerCase()).not.toContain("retry");
    }
  });

  it("never re-dispatches the agent authorization after an unknown outcome", async () => {
    h.store.failures["authorizeCommerceAction"] =
      "CONTROL_ACTION_STORE_OUTCOME_UNKNOWN";
    const error = await failure(
      h.service.authorize(SESSION_TOKEN, "127.0.0.1", {
        idempotencyKey: IDEMPOTENCY,
        body: {
          mutationId: MUTATION,
          actionId: ACTION,
          requirementId: `openarc:requirement:${MUTATION}`,
        },
      }),
    );
    expect(error.status).toBe(500);
    expect(error.status).not.toBe(503);
    expect(error.code).toBe("INTERNAL_ERROR");
    expect(error.message.toLowerCase()).not.toContain("refund");
    expect(error.message.toLowerCase()).not.toContain("release");
    expect(error.message.toLowerCase()).not.toContain("retry");
    expect(h.store.calls).toEqual(["authorizeCommerceAction"]);
    // No recovery read is attempted on the caller's behalf.
    expect(h.sessions.calls).toEqual(["getCommerceSessionByHash"]);
  });

  it("keeps an unknown outcome distinct from every other store failure", async () => {
    // Money-adjacent exposure must not be collapsible into the retryable-looking
    // dependency 503 that UNAVAILABLE, REQUIREMENT_UNAVAILABLE and an
    // unrecognized code all share.
    const seen = new Map<string, number>();
    for (const code of [
      "CONTROL_ACTION_STORE_OUTCOME_UNKNOWN",
      "CONTROL_ACTION_STORE_UNAVAILABLE",
      "CONTROL_ACTION_STORE_REQUIREMENT_UNAVAILABLE",
      "SOMETHING_ELSE_ENTIRELY",
    ]) {
      const local = harness();
      local.store.failures["authorizeCommerceAction"] = code;
      const error = await failure(
        local.service.authorize(SESSION_TOKEN, "127.0.0.1", {
          idempotencyKey: IDEMPOTENCY,
          body: {
            mutationId: MUTATION,
            actionId: ACTION,
            requirementId: `openarc:requirement:${MUTATION}`,
          },
        }),
      );
      seen.set(code, error.status);
      expect(local.store.calls).toEqual(["authorizeCommerceAction"]);
    }
    expect(seen.get("CONTROL_ACTION_STORE_OUTCOME_UNKNOWN")).toBe(500);
    expect(seen.get("CONTROL_ACTION_STORE_UNAVAILABLE")).toBe(503);
    expect(seen.get("CONTROL_ACTION_STORE_REQUIREMENT_UNAVAILABLE")).toBe(503);
    expect(seen.get("SOMETHING_ELSE_ENTIRELY")).toBe(503);
  });

  it("offers recovery only through the bounded status read", async () => {
    h.store.results["getHumanCommerceActionMutationStatus"] = {
      status: "committed",
      receipt: actionReceipt("control.commerce_action.approve"),
    };
    const status = await h.service.getHumanMutationStatus(CTX, {
      organizationId: ORG,
      mutationId: MUTATION,
    });
    expect(status.status).toBe("committed");
    expect(h.store.calls).toEqual(["getHumanCommerceActionMutationStatus"]);
  });
});

describe("mutation status stays bound to its caller and family", () => {
  it("rejects a committed receipt for a different mutation id", async () => {
    h.store.results["getHumanCommerceActionMutationStatus"] = {
      status: "committed",
      receipt: actionReceipt("control.commerce_action.approve", {
        mutationId: MUTATION_B,
      }),
    };
    const error = await failure(
      h.service.getHumanMutationStatus(CTX, {
        organizationId: ORG,
        mutationId: MUTATION,
      }),
    );
    expect(error.status).toBe(503);
  });

  it("never surfaces an agent authorization through the browser status read", async () => {
    h.store.results["getHumanCommerceActionMutationStatus"] = {
      status: "committed",
      receipt: actionReceipt("control.commerce_action.authorize"),
    };
    const error = await failure(
      h.service.getHumanMutationStatus(CTX, {
        organizationId: ORG,
        mutationId: MUTATION,
      }),
    );
    expect(error.status).toBe(503);
  });

  it("never surfaces a browser decision through the agent status read", async () => {
    h.store.results["getAgentCommerceActionMutationStatus"] = {
      status: "committed",
      receipt: actionReceipt("control.commerce_action.cancel"),
    };
    const error = await failure(
      h.service.getAgentMutationStatus(SESSION_TOKEN, "127.0.0.1", {
        mutationId: MUTATION,
      }),
    );
    expect(error.status).toBe(503);
  });

  it("rejects an unknown status discriminant", async () => {
    h.store.results["getHumanCommerceActionMutationStatus"] = {
      status: "in_flight",
    };
    const error = await failure(
      h.service.getHumanMutationStatus(CTX, {
        organizationId: ORG,
        mutationId: MUTATION,
      }),
    );
    expect(error.status).toBe(503);
  });
});

describe("agent calls resolve the current session first", () => {
  it("resolves the commerce session before the store on every agent call", async () => {
    await h.service.getAgentAction(SESSION_TOKEN, "127.0.0.1", {
      actionId: ACTION,
    });
    expect(h.order).toEqual([
      "session.getCommerceSessionByHash",
      "store.getAgentCommerceAction",
      "session.getCommerceSessionByHash",
    ]);
  });

  it("rejects a revoked commerce session before any store call", async () => {
    h.sessions.results = [
      commerceSessionMetadata({ revokedAt: "2026-01-01T00:01:00.000Z" }),
    ];
    const error = await failure(
      h.service.getAgentAction(SESSION_TOKEN, "127.0.0.1", {
        actionId: ACTION,
      }),
    );
    expect(error.status).toBe(401);
    expect(h.store.calls).toEqual([]);
  });

  it("rejects a session that changed across an agent read", async () => {
    h.sessions.results = [
      commerceSessionMetadata(),
      commerceSessionMetadata({ organizationId: ORG_B }),
    ];
    const error = await failure(
      h.service.getAgentMutationStatus(SESSION_TOKEN, "127.0.0.1", {
        mutationId: MUTATION,
      }),
    );
    expect(error.status).toBe(503);
  });

  it("rejects a malformed or foreign bearer before any work", async () => {
    for (const token of [
      undefined,
      "",
      "oacs_v1_short",
      `oas_ag_${"A".repeat(43)}`,
      `Bearer oacs_v1_${"E".repeat(43)}`,
      `oacs_v1_${"E".repeat(43)}\n`,
    ]) {
      const error = await failure(
        h.service.getAgentAction(token, "127.0.0.1", { actionId: ACTION }),
      );
      expect([String(token), error.status]).toEqual([String(token), 401]);
    }
    expect(h.sessions.calls).toEqual([]);
    expect(h.store.calls).toEqual([]);
  });

  it("binds the agent detail to the token-derived organization only", async () => {
    h.store.results["getAgentCommerceAction"] = {
      organizationId: ORG_B,
      item: null,
    };
    const error = await failure(
      h.service.getAgentAction(SESSION_TOKEN, "127.0.0.1", {
        actionId: ACTION,
      }),
    );
    expect(error.status).toBe(503);
  });

  it("binds an authorization result to the token organization and requirement", async () => {
    const body = {
      mutationId: MUTATION,
      actionId: ACTION,
      requirementId: `openarc:requirement:${MUTATION_B}`,
    };
    const error = await failure(
      h.service.authorize(SESSION_TOKEN, "127.0.0.1", {
        idempotencyKey: IDEMPOTENCY,
        body,
      }),
    );
    // The fake store answers with the canonical requirement, which does not
    // match the requested one: a binding violation, never a silent success.
    expect(error.status).toBe(503);
  });

  it("accepts a correctly bound authorization without implying a payment", async () => {
    const data = await h.service.authorize(SESSION_TOKEN, "127.0.0.1", {
      idempotencyKey: IDEMPOTENCY,
      body: {
        mutationId: MUTATION,
        actionId: ACTION,
        requirementId: `openarc:requirement:${MUTATION}`,
      },
    });
    expect(data.receipt.operation).toBe("control.commerce_action.authorize");
    expect(data.receipt.resourceType).toBe("commerce_action");
    expect(data.metadata.debitAtomic).toBe("123456789012345678901234567891");
    expect(Object.keys(data).sort()).toEqual([
      "metadata",
      "receipt",
      "replayed",
    ]);
    expect(JSON.stringify(data)).not.toContain(SESSION_TOKEN);
    expect(JSON.stringify(data)).not.toContain(IDEMPOTENCY);
  });

  it("returns a pending_approval authorization as a normal success with a zero reservation", async () => {
    // DB10 routes an always-approve or above-threshold policy to a PENDING
    // action with ZERO reservation and returns it normally. An approval
    // requirement is therefore an OUTCOME, never a store error, so this service
    // must hand it back as an ordinary 2xx payload and must not synthesize an
    // APPROVAL_REQUIRED failure, a denial or a dependency error.
    h.store.results["authorizeCommerceAction"] = {
      replayed: false,
      metadata: actionMetadata({
        status: "pending_approval",
        reservationId: null,
        approvalId: APPROVAL,
      }),
      receipt: actionReceipt("control.commerce_action.authorize"),
    };
    const data = await h.service.authorize(SESSION_TOKEN, "127.0.0.1", {
      idempotencyKey: IDEMPOTENCY,
      body: {
        mutationId: MUTATION,
        actionId: ACTION,
        requirementId: `openarc:requirement:${MUTATION}`,
      },
    });
    expect(data.metadata.status).toBe("pending_approval");
    // ZERO reservation: nothing is reserved while approval is outstanding.
    expect(data.metadata.reservationId).toBeNull();
    expect(data.metadata.approvalId).toBe(APPROVAL);
    expect(data.replayed).toBe(false);
    expect(data.receipt.operation).toBe("control.commerce_action.authorize");
    // Money stays an exact integer string, never a float.
    expect(data.metadata.amountAtomic).toBe("123456789012345678901234567890");
    expect(data.metadata.debitAtomic).toBe("123456789012345678901234567891");
    // Exactly one store call, and no second authorization attempt.
    expect(h.store.calls).toEqual(["authorizeCommerceAction"]);
  });
});

describe("rate limiting fails closed", () => {
  it("denies the request and never reaches the store when a bucket is exhausted", async () => {
    const store = new FakeStore();
    const auth = new FakeAuth();
    const service = new CommerceActionService({
      auth: auth as unknown as CommerceActionAuthPort,
      store: store as unknown as CommerceActionStorePort,
      commerceSessions:
        new FakeCommerceSessions() as unknown as CommerceSessionReadPort,
      limits: new CommerceActionRateLimiter({
        secret: "unit-test-secret",
        store: { consume: async () => ({ allowed: false }) },
      }),
    });
    const error = await failure(
      service.listActions(CTX, { organizationId: ORG }),
    );
    expect(error.status).toBe(429);
    expect(store.calls).toEqual([]);
  });

  it("fails closed when the limiter store itself errors", async () => {
    const store = new FakeStore();
    const service = new CommerceActionService({
      auth: new FakeAuth() as unknown as CommerceActionAuthPort,
      store: store as unknown as CommerceActionStorePort,
      commerceSessions:
        new FakeCommerceSessions() as unknown as CommerceSessionReadPort,
      limits: new CommerceActionRateLimiter({
        secret: "unit-test-secret",
        store: {
          consume: async () => {
            throw new Error("limiter down");
          },
        },
      }),
    });
    const error = await failure(
      service.authorize(SESSION_TOKEN, "127.0.0.1", {
        idempotencyKey: IDEMPOTENCY,
        body: {
          mutationId: MUTATION,
          actionId: ACTION,
          requirementId: `openarc:requirement:${MUTATION}`,
        },
      }),
    );
    expect(error.status).toBe(503);
    expect(store.calls).toEqual([]);
  });

  it("never puts a raw bearer, account or IP in a limiter key", async () => {
    const seen: string[] = [];
    const limits = new CommerceActionRateLimiter({
      secret: "unit-test-secret",
      store: {
        consume: async (input) => {
          seen.push(input.keyHash);
          return { allowed: true };
        },
      },
    });
    await limits.consumeAll([
      { family: "authorize", bucket: "token", value: SESSION_TOKEN, limit: 1 },
      { family: "read", bucket: "peer", value: "203.0.113.7", limit: 1 },
    ]);
    expect(seen).toHaveLength(2);
    for (const key of seen) {
      expect(key).toMatch(/^[0-9a-f]{64}$/u);
      expect(key).not.toContain(SESSION_TOKEN);
      expect(key).not.toContain("203.0.113.7");
    }
  });
});

describe("every route consumes its buckets in the frozen order", () => {
  /**
   * Records the EXACT ordered bucket sequence each route consumes. `consumeAll`
   * delegates to `consume`, so overriding it observes the real ordering without
   * weakening the limiter: `super.consume` still runs, so a deny is still a 429
   * and a limiter outage is still a fixed 503 before any store authority.
   */
  class RecordingLimiter extends CommerceActionRateLimiter {
    readonly seen: {
      family: string;
      bucket: string;
      value: string;
      limit: number;
    }[] = [];

    override async consume(check: CommerceActionRateCheck): Promise<void> {
      this.seen.push({
        family: check.family,
        bucket: check.bucket,
        value: check.value,
        limit: check.limit,
      });
      await super.consume(check);
    }
  }

  interface Recorded {
    service: CommerceActionService;
    store: FakeStore;
    limits: RecordingLimiter;
    order: string[];
  }

  function recorded(): Recorded {
    const order: string[] = [];
    const store = new FakeStore();
    const limits = new RecordingLimiter({
      secret: "unit-test-secret",
      store: {
        consume: async () => {
          order.push("limiter.consume");
          return { allowed: true };
        },
      },
    });
    const trackedStore = new Proxy(store, {
      get(object, property, receiver) {
        const value = Reflect.get(object, property, receiver);
        if (typeof value !== "function" || typeof property !== "string") {
          return value;
        }
        return (...args: unknown[]) => {
          order.push(`store.${property}`);
          return (value as (...input: unknown[]) => unknown).apply(
            object,
            args,
          );
        };
      },
    });
    const service = new CommerceActionService({
      auth: new FakeAuth() as unknown as CommerceActionAuthPort,
      store: trackedStore as unknown as CommerceActionStorePort,
      commerceSessions:
        new FakeCommerceSessions() as unknown as CommerceSessionReadPort,
      limits,
    });
    return { service, store, limits, order };
  }

  const READ_SEQUENCE = [
    { family: "read", bucket: "global", limit: 600 },
    { family: "read", bucket: "peer", limit: 120 },
    { family: "read", bucket: "subject", limit: 60 },
  ] as const;

  function shape(
    limits: RecordingLimiter,
  ): { family: string; bucket: string; limit: number }[] {
    return limits.seen.map((check) => ({
      family: check.family,
      bucket: check.bucket,
      limit: check.limit,
    }));
  }

  it("consumes global, then peer, then subject on every browser read", async () => {
    const reads: readonly [string, (r: Recorded) => Promise<unknown>][] = [
      ["listActions", (r) => r.service.listActions(CTX, { organizationId: ORG })],
      [
        "listApprovals",
        (r) => r.service.listApprovals(CTX, { organizationId: ORG }),
      ],
      [
        "getAction",
        (r) =>
          r.service.getAction(CTX, { organizationId: ORG, actionId: ACTION }),
      ],
      [
        "getApproval",
        (r) =>
          r.service.getApproval(CTX, {
            organizationId: ORG,
            approvalId: APPROVAL,
          }),
      ],
      [
        "getExposure",
        (r) =>
          r.service.getExposure(CTX, {
            organizationId: ORG,
            subjectAgentId: AGENT,
            policyId: POLICY,
          }),
      ],
      [
        "getHumanMutationStatus",
        (r) =>
          r.service.getHumanMutationStatus(CTX, {
            organizationId: ORG,
            mutationId: MUTATION,
          }),
      ],
    ];
    for (const [name, call] of reads) {
      const r = recorded();
      await call(r);
      expect([name, shape(r.limits)]).toEqual([name, [...READ_SEQUENCE]]);
      // Global is the unkeyed bucket; peer and subject bind the caller.
      expect([name, r.limits.seen.map((check) => check.value)]).toEqual([
        name,
        ["*", "127.0.0.1", "account"],
      ]);
      // All three buckets are consumed BEFORE the store is ever touched.
      expect([name, r.order.slice(0, 3)]).toEqual([
        name,
        ["limiter.consume", "limiter.consume", "limiter.consume"],
      ]);
      expect([name, r.order[3]?.startsWith("store.")]).toEqual([name, true]);
    }
  });

  it("consumes global, then peer, then subject on every agent read", async () => {
    const reads: readonly [string, (r: Recorded) => Promise<unknown>][] = [
      [
        "getAgentAction",
        (r) =>
          r.service.getAgentAction(SESSION_TOKEN, "203.0.113.7", {
            actionId: ACTION,
          }),
      ],
      [
        "getAgentMutationStatus",
        (r) =>
          r.service.getAgentMutationStatus(SESSION_TOKEN, "203.0.113.7", {
            mutationId: MUTATION,
          }),
      ],
    ];
    for (const [name, call] of reads) {
      const r = recorded();
      await call(r);
      expect([name, shape(r.limits)]).toEqual([name, [...READ_SEQUENCE]]);
      expect([name, r.limits.seen.map((check) => check.value)]).toEqual([
        name,
        ["*", "203.0.113.7", SESSION_TOKEN],
      ]);
      expect([name, r.order.slice(0, 3)]).toEqual([
        name,
        ["limiter.consume", "limiter.consume", "limiter.consume"],
      ]);
    }
  });

  it("consumes global, then peer, then token on the agent authorization", async () => {
    const r = recorded();
    await r.service.authorize(SESSION_TOKEN, "203.0.113.7", {
      idempotencyKey: IDEMPOTENCY,
      body: {
        mutationId: MUTATION,
        actionId: ACTION,
        requirementId: `openarc:requirement:${MUTATION}`,
      },
    });
    expect(shape(r.limits)).toEqual([
      { family: "authorize", bucket: "global", limit: 600 },
      { family: "authorize", bucket: "peer", limit: 120 },
      { family: "authorize", bucket: "token", limit: 60 },
    ]);
    expect(r.limits.seen.map((check) => check.value)).toEqual([
      "*",
      "203.0.113.7",
      SESSION_TOKEN,
    ]);
    // The whole ordered sequence precedes any store authority.
    expect(r.order).toEqual([
      "limiter.consume",
      "limiter.consume",
      "limiter.consume",
      "store.authorizeCommerceAction",
    ]);
  });

  it("consumes exactly the account bucket on every browser decision", async () => {
    const decisions: readonly [string, (r: Recorded) => Promise<unknown>][] = [
      [
        "approve",
        (r) =>
          r.service.approve(
            CTX,
            ORG,
            ACTION,
            writeEnvelope({ mutationId: MUTATION }),
          ),
      ],
      [
        "reject",
        (r) =>
          r.service.reject(
            CTX,
            ORG,
            ACTION,
            writeEnvelope({ mutationId: MUTATION }),
          ),
      ],
      [
        "cancel",
        (r) =>
          r.service.cancel(
            CTX,
            ORG,
            ACTION,
            writeEnvelope({ mutationId: MUTATION }),
          ),
      ],
    ];
    for (const [name, call] of decisions) {
      const r = recorded();
      await call(r);
      // The decision family is deliberately account-only: it never borrows the
      // read family's global/peer allowance, and never the other way round.
      expect([name, shape(r.limits)]).toEqual([
        name,
        [{ family: "decision", bucket: "account", limit: 30 }],
      ]);
      expect([name, r.limits.seen.map((check) => check.value)]).toEqual([
        name,
        ["account"],
      ]);
      expect([name, r.order[0]]).toEqual([name, "limiter.consume"]);
      expect([name, r.order[1]?.startsWith("store.")]).toEqual([name, true]);
    }
  });

  it("stops at the FIRST exhausted bucket and consumes no later one", async () => {
    for (const denyAt of [0, 1, 2]) {
      let seen = 0;
      const store = new FakeStore();
      const limits = new RecordingLimiter({
        secret: "unit-test-secret",
        store: {
          consume: async () => ({ allowed: seen++ !== denyAt }),
        },
      });
      const service = new CommerceActionService({
        auth: new FakeAuth() as unknown as CommerceActionAuthPort,
        store: store as unknown as CommerceActionStorePort,
        commerceSessions:
          new FakeCommerceSessions() as unknown as CommerceSessionReadPort,
        limits,
      });
      const error = await failure(
        service.listActions(CTX, { organizationId: ORG }),
      );
      expect([denyAt, error.status]).toEqual([denyAt, 429]);
      // Exactly the buckets up to and including the denied one were consumed.
      expect([denyAt, shape(limits)]).toEqual([
        denyAt,
        READ_SEQUENCE.slice(0, denyAt + 1).map((check) => ({ ...check })),
      ]);
      expect([denyAt, store.calls]).toEqual([denyAt, []]);
    }
  });
});
