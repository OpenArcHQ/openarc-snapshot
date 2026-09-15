import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  COMMERCE_API_ERRORS,
  COMMERCE_PAYMENT_ASSET_ADDRESS,
  COMMERCE_PAYMENT_NETWORK,
  COMMERCE_PAYMENT_VERIFYING_CONTRACT,
} from "@openarc/shared";
import {
  CONTROL_PAYMENT_ATTEMPT_STORE_ERROR_MESSAGES,
  ControlPaymentAttemptStoreError,
  type ControlPaymentAttemptStoreErrorCode,
} from "@openarc/db";

import { AUTH_ERRORS, AuthApiError } from "../src/auth/errors.js";
import type { AuthRequestContext } from "../src/auth/service.js";
import { CommercePaymentRateLimiter } from "../src/control/payment-rate-limiter.js";
import {
  COMMERCE_PAYMENT_STORE_ERROR_MAPPING,
  CommercePaymentService,
} from "../src/control/payment-service.js";
import type {
  CommercePaymentAuthPort,
  CommercePaymentStorePort,
} from "../src/control/payment-ports.js";
import {
  ACCOUNT,
  ACTION,
  AMOUNT,
  ATTEMPT,
  BINDING_DIGEST,
  COOKIE,
  CSRF,
  GRANT,
  GRANT_TOKEN,
  IDEMPOTENCY,
  LISTING,
  MACHINE_AGENT_TOKEN,
  MUTATION,
  NONCE,
  ORG,
  ORG_B,
  PAY_TO,
  PAY_TO_MIXED,
  PROVIDER_TOKEN,
  REQUIREMENT,
  REQUIREMENT_DIGEST,
  SESSION_TOKEN,
  VERSION,
  attemptRecord,
  commerceSessionMetadata,
  dispatchedAttempt,
  paymentActionMetadata,
  persistBody,
  termsData,
  verifiedRequirement,
} from "./payment-fixtures.js";

/**
 * Service-level coverage for the migration-0015 payment slice with honest
 * injected fakes: the store error mapping table, strict bodies, the
 * server-derived binding, the replay path, the never-success second dispatch
 * and the secret canary. Nothing here signs, sends or settles anything.
 */

const HUMAN_HASH = "b".repeat(64);
const CTX = { peerIp: "127.0.0.1", cookies: {} } as unknown as AuthRequestContext;

type StoreMethod = keyof CommercePaymentStorePort;

class FakeStore implements CommercePaymentStorePort {
  readonly calls: { name: StoreMethod; args: unknown[] }[] = [];
  readonly results: Partial<Record<StoreMethod, unknown>> = {};
  readonly failures: Partial<Record<StoreMethod, unknown>> = {};

  async #run(name: StoreMethod, args: unknown[], fallback: unknown): Promise<never> {
    this.calls.push({ name, args });
    if (this.failures[name] !== undefined) throw this.failures[name];
    return (Object.hasOwn(this.results, name) ? this.results[name] : fallback) as never;
  }
  recordListingPaymentTerms(...args: unknown[]) {
    return this.#run("recordListingPaymentTerms", args, termsData());
  }
  registerVerifiedRequirement(...args: unknown[]) {
    return this.#run("registerVerifiedRequirement", args, verifiedRequirement());
  }
  persistBuyerAttempt(...args: unknown[]) {
    return this.#run("persistBuyerAttempt", args, { replayed: false, attempt: attemptRecord() });
  }
  recordAttemptDispatch(...args: unknown[]) {
    return this.#run("recordAttemptDispatch", args, dispatchedAttempt());
  }
  readAgentAttempt(...args: unknown[]) {
    return this.#run("readAgentAttempt", args, { attemptId: ATTEMPT, item: dispatchedAttempt() });
  }
}

interface Harness {
  service: CommercePaymentService;
  store: FakeStore;
  auth: { calls: string[] };
  sessions: { calls: number; next: unknown[] };
  actions: { calls: unknown[][]; next: unknown };
  limiterCalls: number;
}

function harness(): Harness {
  const store = new FakeStore();
  const authCalls: string[] = [];
  const auth: CommercePaymentAuthPort = {
    verifyCsrf(_cookies, csrf) {
      authCalls.push("csrf");
      if (csrf !== CSRF) throw AUTH_ERRORS.csrfRejected();
      return "ok";
    },
    async beginTenantRead() {
      authCalls.push("begin");
      return { sessionHash: HUMAN_HASH, accountId: ACCOUNT };
    },
    async finishTenantRead() {
      authCalls.push("finish");
    },
  };
  const sessions = { calls: 0, next: [] as unknown[] };
  const actions = { calls: [] as unknown[][], next: { organizationId: ORG, item: paymentActionMetadata() } as unknown };
  const h: Harness = {
    store,
    auth: { calls: authCalls },
    sessions,
    actions,
    limiterCalls: 0,
    service: undefined as unknown as CommercePaymentService,
  };
  h.service = new CommercePaymentService({
    auth,
    store,
    commerceSessions: {
      async getCommerceSessionByHash() {
        sessions.calls += 1;
        return sessions.next.length > 0 ? sessions.next.shift() : commerceSessionMetadata();
      },
    },
    actions: {
      async getAgentCommerceAction(...args: unknown[]) {
        actions.calls.push(args);
        if (actions.next instanceof Error) throw actions.next;
        return actions.next as { organizationId: unknown; item: unknown };
      },
    },
    limits: new CommercePaymentRateLimiter({
      secret: "synthetic_payment_rate_secret_0123456789",
      store: {
        consume: async () => {
          h.limiterCalls += 1;
          return { allowed: true };
        },
      },
    }),
  });
  return h;
}

async function rejection(promise: Promise<unknown>): Promise<AuthApiError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(AuthApiError);
    return error as AuthApiError;
  }
  throw new Error("expected an AuthApiError");
}

const terms = (h: Harness, body: unknown = { mutationId: MUTATION, payToAddress: PAY_TO }, csrf: unknown = CSRF) =>
  h.service.recordListingPaymentTerms(CTX, ORG, LISTING, VERSION, { csrf, idempotencyKey: IDEMPOTENCY, body });

/** Exact expected HTTP mapping per store code, restated independently. */
const EXPECTED: Record<ControlPaymentAttemptStoreErrorCode, { status: number; code: string }> = {
  CONTROL_PAYMENT_ATTEMPT_STORE_INPUT_INVALID: { status: 400, code: AUTH_ERRORS.invalidRequest().code },
  CONTROL_PAYMENT_ATTEMPT_STORE_SESSION_INVALID: { status: 401, code: "UNAUTHENTICATED" },
  CONTROL_PAYMENT_ATTEMPT_STORE_FORBIDDEN: { status: 403, code: "FORBIDDEN" },
  CONTROL_PAYMENT_ATTEMPT_STORE_NOT_FOUND: { status: 403, code: "FORBIDDEN" },
  CONTROL_PAYMENT_ATTEMPT_STORE_CONFLICT: { status: 409, code: "POLICY_DENIED" },
  CONTROL_PAYMENT_ATTEMPT_STORE_ATTEMPT_CONFLICT: { status: 409, code: "POLICY_DENIED" },
  CONTROL_PAYMENT_ATTEMPT_STORE_GRANT_EXPIRED: { status: 409, code: "GRANT_EXPIRED" },
  CONTROL_PAYMENT_ATTEMPT_STORE_POTENTIAL_EXPOSURE: { status: 409, code: "BUDGET_RESERVATION_CONFLICT" },
  CONTROL_PAYMENT_ATTEMPT_STORE_REQUIREMENT_UNAVAILABLE: { status: 503, code: AUTH_ERRORS.unavailable().code },
  CONTROL_PAYMENT_ATTEMPT_STORE_IDEMPOTENCY_CONFLICT: { status: 409, code: "IDEMPOTENCY_CONFLICT" },
  CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE: { status: 503, code: AUTH_ERRORS.unavailable().code },
  CONTROL_PAYMENT_ATTEMPT_STORE_OUTCOME_UNKNOWN: { status: 500, code: "INTERNAL_ERROR" },
};

describe("store error mapping table", () => {
  it("covers exactly the store's error vocabulary", () => {
    const vocabulary = Object.keys(CONTROL_PAYMENT_ATTEMPT_STORE_ERROR_MESSAGES).sort();
    expect(Object.keys(COMMERCE_PAYMENT_STORE_ERROR_MAPPING).sort()).toEqual(vocabulary);
    expect(Object.keys(EXPECTED).sort()).toEqual(vocabulary);
  });

  it("maps every store code to its fixed non-retryable HTTP result on every operation", async () => {
    for (const code of Object.keys(EXPECTED) as ControlPaymentAttemptStoreErrorCode[]) {
      const operations: [StoreMethod, (h: Harness) => Promise<unknown>][] = [
        ["recordListingPaymentTerms", (h) => terms(h)],
        ["registerVerifiedRequirement", (h) => h.service.registerRequirement(SESSION_TOKEN, "127.0.0.1", { body: { requirementId: REQUIREMENT, listingId: LISTING } })],
        ["persistBuyerAttempt", (h) => h.service.persistAttempt(SESSION_TOKEN, "127.0.0.1", { body: persistBody() })],
        ["recordAttemptDispatch", (h) => h.service.dispatchAttempt(SESSION_TOKEN, "127.0.0.1", ATTEMPT, { body: { bindingDigest: BINDING_DIGEST } })],
        ["readAgentAttempt", (h) => h.service.getAttempt(SESSION_TOKEN, "127.0.0.1", { attemptId: ATTEMPT })],
      ];
      for (const [method, run] of operations) {
        const h = harness();
        h.store.failures[method] = new ControlPaymentAttemptStoreError(code);
        const error = await rejection(run(h));
        expect([code, method, error.status, error.code]).toEqual([code, method, EXPECTED[code].status, EXPECTED[code].code]);
        expect(COMMERCE_API_ERRORS[error.code].retryable).toBe(false);
        // The fixed message never echoes the store's own detail.
        expect(error.message).not.toContain("ControlPaymentAttemptStore");
      }
    }
  });

  it("maps an unrecognized or plain error to the fixed 503", async () => {
    for (const failure of [new Error("boom"), { code: "SOMETHING_ELSE" }, "string"]) {
      const h = harness();
      h.store.failures.recordAttemptDispatch = failure;
      const error = await rejection(h.service.dispatchAttempt(SESSION_TOKEN, "127.0.0.1", ATTEMPT, { body: { bindingDigest: BINDING_DIGEST } }));
      expect(error.status).toBe(503);
    }
  });
});

describe("agent audience and strict bodies", () => {
  it("refuses oas_ag_, oas_pr_ and grant tokens before any limiter, session, action or store work", async () => {
    for (const token of [MACHINE_AGENT_TOKEN, PROVIDER_TOKEN, GRANT_TOKEN, `${SESSION_TOKEN} `, undefined]) {
      const h = harness();
      for (const run of [
        () => h.service.registerRequirement(token, "127.0.0.1", { body: { requirementId: REQUIREMENT, listingId: LISTING } }),
        () => h.service.persistAttempt(token, "127.0.0.1", { body: persistBody() }),
        () => h.service.dispatchAttempt(token, "127.0.0.1", ATTEMPT, { body: { bindingDigest: BINDING_DIGEST } }),
        () => h.service.getAttempt(token, "127.0.0.1", { attemptId: ATTEMPT }),
      ]) {
        expect((await rejection(run())).status).toBe(401);
      }
      expect([h.limiterCalls, h.sessions.calls, h.actions.calls.length, h.store.calls.length]).toEqual([0, 0, 0, 0]);
    }
  });

  it("never accepts an amount, network, asset, verifying contract, source kind or unknown key from the wire", async () => {
    const forbidden: Record<string, unknown>[] = [
      { value: AMOUNT },
      { amountAtomic: AMOUNT },
      { network: COMMERCE_PAYMENT_NETWORK },
      { asset: COMMERCE_PAYMENT_ASSET_ADDRESS },
      { verifyingContract: COMMERCE_PAYMENT_VERIFYING_CONTRACT },
      { sourceKind: "internal_fixture" },
      { grantRequirementDigest: REQUIREMENT_DIGEST },
      { schemaVersion: "openarc.x402.lane-binding.v1" },
      { signature: `0x${"5a".repeat(65)}` },
      { unexpected: true },
    ];
    for (const extra of forbidden) {
      const h = harness();
      expect((await rejection(h.service.persistAttempt(SESSION_TOKEN, "127.0.0.1", { body: persistBody(extra) }))).status).toBe(400);
      expect((await rejection(h.service.registerRequirement(SESSION_TOKEN, "127.0.0.1", { body: { requirementId: REQUIREMENT, listingId: LISTING, ...extra } }))).status).toBe(400);
      expect((await rejection(h.service.dispatchAttempt(SESSION_TOKEN, "127.0.0.1", ATTEMPT, { body: { bindingDigest: BINDING_DIGEST, ...extra } }))).status).toBe(400);
      expect((await rejection(terms(h, { mutationId: MUTATION, payToAddress: PAY_TO, ...extra }))).status).toBe(400);
      expect(h.store.calls).toEqual([]);
      expect(h.auth.calls).toEqual([]);
    }
  });

  it("rebuilds the binding from server constants and the buyer's own action", async () => {
    const h = harness();
    const result = await h.service.persistAttempt(SESSION_TOKEN, "127.0.0.1", { body: persistBody() });
    expect(result).toMatchObject({ replayed: false, attempt: { state: "persisted", attemptId: ATTEMPT } });
    expect(h.actions.calls).toHaveLength(1);
    expect(h.actions.calls[0]?.[1]).toBe(ACTION);
    const call = h.store.calls.find((entry) => entry.name === "persistBuyerAttempt");
    expect(call?.args[1]).toEqual({
      binding: {
        schemaVersion: "openarc.x402.lane-binding.v1",
        role: "buyer",
        network: COMMERCE_PAYMENT_NETWORK,
        grantId: GRANT,
        actionId: ACTION,
        attemptId: ATTEMPT,
        grantRequirementDigest: REQUIREMENT_DIGEST,
        laneRequirementDigest: persistBody()["laneRequirementDigest"],
        verifyingContract: COMMERCE_PAYMENT_VERIFYING_CONTRACT,
        asset: COMMERCE_PAYMENT_ASSET_ADDRESS,
        from: persistBody()["from"],
        to: PAY_TO_MIXED,
        value: AMOUNT,
        validAfter: persistBody()["validAfter"],
        validBefore: persistBody()["validBefore"],
        nonce: NONCE,
      },
      bindingDigest: BINDING_DIGEST,
    });
    // The store only ever receives the one-way digest, never the raw bearer.
    expect(JSON.stringify(h.store.calls)).not.toContain(SESSION_TOKEN);
  });

  it("refuses a missing or foreign action without touching the store", async () => {
    const missing = harness();
    missing.actions.next = { organizationId: ORG, item: null };
    expect((await rejection(missing.service.persistAttempt(SESSION_TOKEN, "127.0.0.1", { body: persistBody() }))).status).toBe(403);
    expect(missing.store.calls).toEqual([]);
    const foreign = harness();
    foreign.actions.next = { organizationId: ORG_B, item: paymentActionMetadata() };
    expect((await rejection(foreign.service.persistAttempt(SESSION_TOKEN, "127.0.0.1", { body: persistBody() }))).status).toBe(503);
    expect(foreign.store.calls).toEqual([]);
    const refused = harness();
    refused.actions.next = Object.assign(new Error("x"), { code: "CONTROL_ACTION_STORE_SESSION_INVALID" });
    expect((await rejection(refused.service.persistAttempt(SESSION_TOKEN, "127.0.0.1", { body: persistBody() }))).status).toBe(401);
  });

  it("fails closed when the store binds different terms than the server derived", async () => {
    for (const drift of [{ valueAtomic: "2000000" }, { requirementDigest: `sha256:${"f".repeat(64)}` }, { organizationId: ORG_B }, { bindingDigest: `sha256:${"0".repeat(64)}` }]) {
      const h = harness();
      h.store.results.persistBuyerAttempt = { replayed: false, attempt: attemptRecord(drift) };
      expect((await rejection(h.service.persistAttempt(SESSION_TOKEN, "127.0.0.1", { body: persistBody() }))).status).toBe(503);
    }
  });
});

describe("replay, dispatch and recovery", () => {
  it("returns an exact terms replay and binds it to the request", async () => {
    const h = harness();
    h.store.results.recordListingPaymentTerms = termsData({ replayed: true });
    const first = await terms(h, { mutationId: MUTATION, payToAddress: PAY_TO.toUpperCase().replace("0X", "0x") });
    expect(first.replayed).toBe(true);
    expect(h.store.calls[0]?.args).toEqual([HUMAN_HASH, ORG, LISTING, VERSION, { payToAddress: PAY_TO.toUpperCase().replace("0X", "0x") }, { idempotencyKey: IDEMPOTENCY, mutationId: MUTATION }]);
    expect(h.auth.calls).toEqual(["csrf", "begin"]);
    // A mismatched replay (different pay-to or mutation) is never passed through.
    const drift = harness();
    drift.store.results.recordListingPaymentTerms = termsData({ receipt: { ...(termsData()["receipt"] as object), mutationId: ATTEMPT.replace("1234", "9999") } });
    expect((await rejection(terms(drift))).status).toBe(503);
  });

  it("verifies CSRF before any session, limiter or store work", async () => {
    const h = harness();
    const error = await rejection(terms(h, { mutationId: MUTATION, payToAddress: PAY_TO }, "wrong"));
    expect(error.code).toBe("CSRF_REJECTED");
    expect(h.auth.calls).toEqual(["csrf"]);
    expect([h.limiterCalls, h.store.calls.length]).toEqual([0, 0]);
  });

  it("accepts an attempt replay but never a first persist outside the persisted state", async () => {
    const replay = harness();
    replay.store.results.persistBuyerAttempt = { replayed: true, attempt: dispatchedAttempt() };
    expect((await replay.service.persistAttempt(SESSION_TOKEN, "127.0.0.1", { body: persistBody() })).replayed).toBe(true);
    const bad = harness();
    bad.store.results.persistBuyerAttempt = { replayed: false, attempt: dispatchedAttempt() };
    expect((await rejection(bad.service.persistAttempt(SESSION_TOKEN, "127.0.0.1", { body: persistBody() }))).status).toBe(503);
  });

  it("reports a dispatch only as unknown and never turns a second dispatch into success", async () => {
    const h = harness();
    const first = await h.service.dispatchAttempt(SESSION_TOKEN, "127.0.0.1", ATTEMPT, { body: { bindingDigest: BINDING_DIGEST } });
    expect(first.attempt.state).toBe("unknown");
    h.store.failures.recordAttemptDispatch = new ControlPaymentAttemptStoreError("CONTROL_PAYMENT_ATTEMPT_STORE_ATTEMPT_CONFLICT");
    const second = await rejection(h.service.dispatchAttempt(SESSION_TOKEN, "127.0.0.1", ATTEMPT, { body: { bindingDigest: BINDING_DIGEST } }));
    expect([second.status, second.code]).toEqual([409, "POLICY_DENIED"]);
    // A store that claimed a still-persisted attempt was dispatched is refused.
    const lying = harness();
    lying.store.results.recordAttemptDispatch = attemptRecord();
    expect((await rejection(lying.service.dispatchAttempt(SESSION_TOKEN, "127.0.0.1", ATTEMPT, { body: { bindingDigest: BINDING_DIGEST } }))).status).toBe(503);
  });

  it("reads a missing attempt as item null and requires the same session before and after", async () => {
    const h = harness();
    h.store.results.readAgentAttempt = { attemptId: ATTEMPT, item: null };
    expect(await h.service.getAttempt(SESSION_TOKEN, "127.0.0.1", { attemptId: ATTEMPT })).toEqual({ attemptId: ATTEMPT, item: null });
    expect(h.sessions.calls).toBe(2);
    const rotated = harness();
    rotated.sessions.next = [commerceSessionMetadata(), commerceSessionMetadata({ policyId: `openarc:policy:22345678-1234-4234-8123-123456789abc` })];
    expect((await rejection(rotated.service.getAttempt(SESSION_TOKEN, "127.0.0.1", { attemptId: ATTEMPT }))).status).toBe(503);
    const revoked = harness();
    revoked.sessions.next = [commerceSessionMetadata({ revokedAt: "2026-01-01T00:01:00.000Z" })];
    expect((await rejection(revoked.service.getAttempt(SESSION_TOKEN, "127.0.0.1", { attemptId: ATTEMPT }))).status).toBe(401);
  });
});

describe("secret canary", () => {
  let writes: string[];
  beforeEach(() => {
    writes = [];
    for (const method of ["log", "info", "warn", "error", "debug"] as const) {
      vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
        writes.push(args.map(String).join(" "));
      });
    }
    vi.spyOn(process.stdout, "write").mockImplementation((chunk: unknown) => {
      writes.push(String(chunk));
      return true;
    });
    vi.spyOn(process.stderr, "write").mockImplementation((chunk: unknown) => {
      writes.push(String(chunk));
      return true;
    });
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("never logs and never puts a credential into a result or an error", async () => {
    const h = harness();
    const outputs: unknown[] = [];
    outputs.push(await terms(h));
    outputs.push(await h.service.registerRequirement(SESSION_TOKEN, "127.0.0.1", { body: { requirementId: REQUIREMENT, listingId: LISTING } }));
    outputs.push(await h.service.persistAttempt(SESSION_TOKEN, "127.0.0.1", { body: persistBody() }));
    outputs.push(await h.service.dispatchAttempt(SESSION_TOKEN, "127.0.0.1", ATTEMPT, { body: { bindingDigest: BINDING_DIGEST } }));
    outputs.push(await h.service.getAttempt(SESSION_TOKEN, "127.0.0.1", { attemptId: ATTEMPT }));
    for (const code of Object.keys(EXPECTED) as ControlPaymentAttemptStoreErrorCode[]) {
      const failing = harness();
      failing.store.failures.persistBuyerAttempt = new ControlPaymentAttemptStoreError(code);
      const error = await rejection(failing.service.persistAttempt(SESSION_TOKEN, "127.0.0.1", { body: persistBody() }));
      outputs.push({ message: error.message, code: error.code, json: JSON.stringify(error) });
    }
    outputs.push(await rejection(h.service.persistAttempt(MACHINE_AGENT_TOKEN, "127.0.0.1", { body: persistBody() })).then((error) => error.message));
    const serialized = JSON.stringify(outputs);
    for (const secret of [SESSION_TOKEN, MACHINE_AGENT_TOKEN, PROVIDER_TOKEN, GRANT_TOKEN, CSRF, COOKIE, IDEMPOTENCY, HUMAN_HASH]) {
      expect(serialized).not.toContain(secret);
    }
    expect(writes).toEqual([]);
  });
});
