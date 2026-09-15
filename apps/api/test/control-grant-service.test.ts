import { describe, expect, it } from "vitest";

import { AuthApiError } from "../src/auth/errors.js";
import { CommerceGrantRateLimiter } from "../src/control/grant-rate-limiter.js";
import { CommerceGrantService } from "../src/control/grant-service.js";
import type {
  CommerceGrantAuthPort,
  CommerceGrantRateLimitStorePort,
  CommerceGrantSessionReadPort,
  CommerceGrantStorePort,
} from "../src/control/grant-ports.js";
import { hashCommerceGrantToken } from "../src/control/grant-crypto.js";
import { hashSessionToken } from "../src/machine/session-token.js";
import {
  ACTION,
  ACTION_B,
  ATTEMPT,
  ATTEMPT_B,
  CLAIM_DIGEST,
  CLAIMED,
  CSRF,
  GRANT,
  GRANT_B,
  GRANT_TOKEN,
  IDEMPOTENCY,
  MACHINE_AGENT_TOKEN,
  MUTATION,
  MUTATION_B,
  ORG,
  ORG_B,
  PROVIDER_TOKEN,
  SESSION_ID,
  SESSION_TOKEN,
  claimedProviderView,
  commerceSessionMetadata,
  grantMetadata,
  grantReceipt,
  providerAttemptStatus,
  providerView,
} from "./grant-fixtures.js";

/**
 * Service-level coverage with HONEST injected fakes. No database, network,
 * payment or provider call occurs; the fakes record the exact call order so the
 * "authenticate before disclosure", "never retry an unknown outcome" and
 * "deliver the one-shot token exactly once" rules are proven rather than
 * asserted.
 */

const PEER = "127.0.0.1";

const CTX = {
  peerIp: PEER,
  cookies: { session: "abc", binding: "def" },
} as unknown as Parameters<CommerceGrantService["getGrant"]>[0];

class StoreError extends Error {
  readonly code: string;
  constructor(code: string) {
    super("fixed non-echoing store failure");
    this.name = "ControlGrantStoreError";
    this.code = code;
  }
}

class FakeStore {
  readonly calls: string[] = [];
  readonly inputs: unknown[] = [];
  results: Record<string, unknown> = {};
  failures: Record<string, string | undefined> = {};

  #run(
    name: string,
    fallback: unknown,
    ...args: unknown[]
  ): Promise<unknown> {
    this.calls.push(name);
    this.inputs.push(args);
    const failure = this.failures[name];
    if (failure !== undefined) return Promise.reject(new StoreError(failure));
    return Promise.resolve(
      Object.hasOwn(this.results, name) ? this.results[name] : fallback,
    );
  }

  issueCommerceGrant(...args: unknown[]): Promise<unknown> {
    return this.#run(
      "issueCommerceGrant",
      {
        replayed: false,
        metadata: grantMetadata(),
        receipt: grantReceipt("control.grant.issue"),
      },
      ...args,
    );
  }
  replaceCommerceGrant(...args: unknown[]): Promise<unknown> {
    return this.#run(
      "replaceCommerceGrant",
      {
        replayed: false,
        metadata: grantMetadata({ generation: "2" }),
        receipt: grantReceipt("control.grant.replace"),
      },
      ...args,
    );
  }
  getAgentCommerceGrantMutationStatus(...args: unknown[]): Promise<unknown> {
    return this.#run(
      "getAgentCommerceGrantMutationStatus",
      { status: "not_found" },
      ...args,
    );
  }
  introspectCommerceGrant(...args: unknown[]): Promise<unknown> {
    return this.#run(
      "introspectCommerceGrant",
      { item: providerView() },
      ...args,
    );
  }
  claimCommerceGrant(...args: unknown[]): Promise<unknown> {
    return this.#run(
      "claimCommerceGrant",
      {
        replayed: false,
        item: claimedProviderView(),
        attemptId: ATTEMPT,
        claimedAt: CLAIMED,
        claimDigest: CLAIM_DIGEST,
        receipt: grantReceipt("control.grant.claim"),
      },
      ...args,
    );
  }
  getProviderCommerceGrantAttemptStatus(...args: unknown[]): Promise<unknown> {
    return this.#run(
      "getProviderCommerceGrantAttemptStatus",
      { attemptId: ATTEMPT, item: providerAttemptStatus() },
      ...args,
    );
  }
  getCommerceGrant(...args: unknown[]): Promise<unknown> {
    return this.#run(
      "getCommerceGrant",
      { organizationId: ORG, grantId: GRANT, item: grantMetadata() },
      ...args,
    );
  }
  getHumanCommerceGrantMutationStatus(...args: unknown[]): Promise<unknown> {
    return this.#run(
      "getHumanCommerceGrantMutationStatus",
      { status: "not_found" },
      ...args,
    );
  }
  revokeCommerceGrant(...args: unknown[]): Promise<unknown> {
    return this.#run(
      "revokeCommerceGrant",
      {
        replayed: false,
        metadata: grantMetadata({
          status: "revoked",
          revokedAt: CLAIMED,
          updatedAt: CLAIMED,
        }),
        receipt: grantReceipt("control.grant.revoke"),
        released: true,
        actionStatus: "cancelled",
        reservationStatus: "released",
      },
      ...args,
    );
  }
}

class FakeAuth {
  readonly calls: string[] = [];
  csrfThrows = false;

  verifyCsrf(): string {
    this.calls.push("verifyCsrf");
    if (this.csrfThrows) {
      throw new AuthApiError("CSRF_REJECTED", 403, "INVALID_ORIGIN");
    }
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

const rateStore: CommerceGrantRateLimitStorePort = {
  consume: async () => ({ allowed: true }),
};

interface Harness {
  service: CommerceGrantService;
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
  const service = new CommerceGrantService({
    auth: track(auth, "auth") as unknown as CommerceGrantAuthPort,
    store: track(store, "store") as unknown as CommerceGrantStorePort,
    commerceSessions: track(
      sessions,
      "session",
    ) as unknown as CommerceGrantSessionReadPort,
    limits: new CommerceGrantRateLimiter({
      secret: "unit-test-secret",
      store: rateStore,
    }),
  });
  return { service, store, auth, sessions, order };
}

async function failure(promise: Promise<unknown>): Promise<AuthApiError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(AuthApiError);
    return error as AuthApiError;
  }
  throw new Error("expected the call to fail");
}

const ISSUE_BODY = { mutationId: MUTATION, actionId: ACTION };
const CLAIM_BODY = {
  mutationId: MUTATION,
  grantToken: GRANT_TOKEN,
  expectedActionId: ACTION,
  attemptId: ATTEMPT,
};

function agentEnvelope(body: unknown) {
  return { idempotencyKey: IDEMPOTENCY, body };
}

describe("agent issue and replace", () => {
  it("authenticates the current session before any store authority", async () => {
    const { service, order } = harness();
    await service.issue(SESSION_TOKEN, PEER, agentEnvelope(ISSUE_BODY));
    expect(order).toEqual([
      "session.getCommerceSessionByHash",
      "store.issueCommerceGrant",
    ]);
  });

  it("hands the store ONLY a one-way digest, never the raw secret", async () => {
    const { service, store } = harness();
    const data = await service.issue(
      SESSION_TOKEN,
      PEER,
      agentEnvelope(ISSUE_BODY),
    );
    const [, input] = store.inputs[0] as [unknown, { grantTokenHash: string }];
    expect(input.grantTokenHash).toMatch(/^[0-9a-f]{64}(?![\s\S])/u);
    expect(JSON.stringify(store.inputs)).not.toContain("oag_v1_");
    // The digest the store received is exactly the digest of the token the
    // caller was handed: one hash domain, used consistently.
    if (data.replayed) throw new Error("expected a first delivery");
    expect(hashCommerceGrantToken(data.grantToken)).toBe(input.grantTokenHash);
  });

  it("delivers the raw token on a first commit and NEVER on a replay", async () => {
    const { service, store } = harness();
    const first = await service.issue(
      SESSION_TOKEN,
      PEER,
      agentEnvelope(ISSUE_BODY),
    );
    expect(first.replayed).toBe(false);
    expect(first).toHaveProperty("grantToken");

    store.results["issueCommerceGrant"] = {
      replayed: true,
      metadata: grantMetadata({ status: "claimed", claimedAt: CLAIMED, updatedAt: CLAIMED }),
      receipt: grantReceipt("control.grant.issue"),
    };
    const replay = await service.issue(
      SESSION_TOKEN,
      PEER,
      agentEnvelope(ISSUE_BODY),
    );
    expect(replay.replayed).toBe(true);
    expect(Object.hasOwn(replay, "grantToken")).toBe(false);
    expect(JSON.stringify(replay)).not.toContain("oag_v1_");
  });

  it("mints a DIFFERENT secret on every attempt", async () => {
    const { service, store } = harness();
    await service.issue(SESSION_TOKEN, PEER, agentEnvelope(ISSUE_BODY));
    await service.issue(SESSION_TOKEN, PEER, agentEnvelope(ISSUE_BODY));
    const [, first] = store.inputs[0] as [unknown, { grantTokenHash: string }];
    const [, second] = store.inputs[1] as [unknown, { grantTokenHash: string }];
    expect(first.grantTokenHash).not.toBe(second.grantTokenHash);
  });

  it("binds the returned grant to the CURRENT session and organization", async () => {
    const { service, store } = harness();
    store.results["issueCommerceGrant"] = {
      replayed: false,
      metadata: grantMetadata({ organizationId: ORG_B }),
      receipt: grantReceipt("control.grant.issue"),
    };
    expect((await failure(
      service.issue(SESSION_TOKEN, PEER, agentEnvelope(ISSUE_BODY)),
    )).status).toBe(503);

    store.results["issueCommerceGrant"] = {
      replayed: false,
      metadata: grantMetadata({ commerceSessionId: MUTATION_B }),
      receipt: grantReceipt("control.grant.issue"),
    };
    expect((await failure(
      service.issue(SESSION_TOKEN, PEER, agentEnvelope(ISSUE_BODY)),
    )).status).toBe(503);

    store.results["issueCommerceGrant"] = {
      replayed: false,
      metadata: grantMetadata({ actionId: ACTION_B }),
      receipt: grantReceipt("control.grant.issue"),
    };
    expect((await failure(
      service.issue(SESSION_TOKEN, PEER, agentEnvelope(ISSUE_BODY)),
    )).status).toBe(503);
    expect(commerceSessionMetadata()["sessionId"]).toBe(SESSION_ID);
  });

  it("rejects a receipt for the wrong operation, mutation or resource", async () => {
    const { service, store } = harness();
    for (const receipt of [
      grantReceipt("control.grant.replace"),
      grantReceipt("control.grant.issue", { mutationId: MUTATION_B }),
      grantReceipt("control.grant.issue", { resourceId: GRANT_B }),
    ]) {
      store.results["issueCommerceGrant"] = {
        replayed: false,
        metadata: grantMetadata(),
        receipt,
      };
      const error = await failure(
        service.issue(SESSION_TOKEN, PEER, agentEnvelope(ISSUE_BODY)),
      );
      expect(error.status).toBe(503);
    }
  });

  it("rejects an extra key in the store envelope", async () => {
    const { service, store } = harness();
    store.results["issueCommerceGrant"] = {
      replayed: false,
      metadata: grantMetadata(),
      receipt: grantReceipt("control.grant.issue"),
      grantTokenHash: "a".repeat(64),
    };
    expect((await failure(
      service.issue(SESSION_TOKEN, PEER, agentEnvelope(ISSUE_BODY)),
    )).status).toBe(503);
  });

  it("requires a canonical commerce-session bearer and idempotency key", async () => {
    const { service, store } = harness();
    for (const token of [
      undefined,
      "",
      PROVIDER_TOKEN,
      MACHINE_AGENT_TOKEN,
      GRANT_TOKEN,
      `${SESSION_TOKEN}\n`,
    ]) {
      const error = await failure(
        service.issue(token, PEER, agentEnvelope(ISSUE_BODY)),
      );
      expect(error.status).toBe(401);
    }
    const badKey = await failure(
      service.issue(SESSION_TOKEN, PEER, { idempotencyKey: "short", body: ISSUE_BODY }),
    );
    expect(badKey.status).toBe(400);
    expect(store.calls).toEqual([]);
  });

  it("requires the path grant id to match the replaced grant", async () => {
    const { service, store } = harness();
    store.results["replaceCommerceGrant"] = {
      replayed: false,
      metadata: grantMetadata({ grantId: GRANT_B, generation: "2" }),
      receipt: grantReceipt("control.grant.replace", { resourceId: GRANT_B }),
    };
    expect((await failure(
      service.replace(SESSION_TOKEN, PEER, GRANT, agentEnvelope({ mutationId: MUTATION })),
    )).status).toBe(503);
  });

  it("refuses a first-delivery replacement that is not a later generation", async () => {
    const { service, store } = harness();
    store.results["replaceCommerceGrant"] = {
      replayed: false,
      metadata: grantMetadata({ generation: "1" }),
      receipt: grantReceipt("control.grant.replace"),
    };
    expect((await failure(
      service.replace(SESSION_TOKEN, PEER, GRANT, agentEnvelope({ mutationId: MUTATION })),
    )).status).toBe(503);
  });
});

describe("agent mutation status", () => {
  it("re-checks the current session AFTER the read, including not_found", async () => {
    const { service, order } = harness();
    const status = await service.getAgentMutationStatus(SESSION_TOKEN, PEER, {
      mutationId: MUTATION,
    });
    expect(status).toEqual({ status: "not_found" });
    expect(order).toEqual([
      "session.getCommerceSessionByHash",
      "store.getAgentCommerceGrantMutationStatus",
      "session.getCommerceSessionByHash",
    ]);
  });

  it("refuses to disclose a status when the session changed mid-read", async () => {
    const { service, sessions } = harness();
    sessions.results = [
      commerceSessionMetadata(),
      commerceSessionMetadata({ revokedAt: null, sessionId: MUTATION_B }),
    ];
    expect((await failure(
      service.getAgentMutationStatus(SESSION_TOKEN, PEER, { mutationId: MUTATION }),
    )).status).toBe(503);
  });

  it("never surfaces a browser or provider receipt on the agent lane", async () => {
    const { service, store } = harness();
    for (const operation of ["control.grant.revoke", "control.grant.claim"]) {
      store.results["getAgentCommerceGrantMutationStatus"] = {
        status: "committed",
        receipt: grantReceipt(operation),
      };
      expect((await failure(
        service.getAgentMutationStatus(SESSION_TOKEN, PEER, { mutationId: MUTATION }),
      )).status).toBe(503);
    }
    store.results["getAgentCommerceGrantMutationStatus"] = {
      status: "committed",
      receipt: grantReceipt("control.grant.issue"),
    };
    const ok = await service.getAgentMutationStatus(SESSION_TOKEN, PEER, {
      mutationId: MUTATION,
    });
    expect(ok.status).toBe("committed");
    // A status read is structurally incapable of carrying the one-use secret.
    expect(Object.hasOwn(ok, "grantToken")).toBe(false);
    expect(JSON.stringify(ok)).not.toContain("oag_v1_");
  });

  it("rejects a committed receipt bound to a different mutation", async () => {
    const { service, store } = harness();
    store.results["getAgentCommerceGrantMutationStatus"] = {
      status: "committed",
      receipt: grantReceipt("control.grant.issue", { mutationId: MUTATION_B }),
    };
    expect((await failure(
      service.getAgentMutationStatus(SESSION_TOKEN, PEER, { mutationId: MUTATION }),
    )).status).toBe(503);
  });
});

describe("the provider lane requires BOTH factors", () => {
  it("refuses a claim that presents only a provider session", async () => {
    const { service, store } = harness();
    for (const body of [
      { mutationId: MUTATION, expectedActionId: ACTION, attemptId: ATTEMPT },
      { ...CLAIM_BODY, grantToken: "oag_v1_not-canonical" },
      { ...CLAIM_BODY, grantToken: SESSION_TOKEN },
      { ...CLAIM_BODY, grantToken: null },
    ]) {
      const error = await failure(
        service.claim(PROVIDER_TOKEN, PEER, agentEnvelope(body)),
      );
      expect(error.status).toBe(400);
    }
    // Introspection is identically refused with a session but no valid token.
    const introspect = await failure(
      service.introspect(PROVIDER_TOKEN, PEER, { body: {} }),
    );
    expect(introspect.status).toBe(400);
    expect(store.calls).toEqual([]);
  });

  it("refuses a claim that presents only the buyer grant token", async () => {
    const { service, store } = harness();
    for (const session of [
      undefined,
      "",
      SESSION_TOKEN,
      MACHINE_AGENT_TOKEN,
      GRANT_TOKEN,
      `${PROVIDER_TOKEN}\n`,
    ]) {
      const error = await failure(
        service.claim(session, PEER, agentEnvelope(CLAIM_BODY)),
      );
      expect(error.status).toBe(401);
      const introspect = await failure(
        service.introspect(session, PEER, { body: { grantToken: GRANT_TOKEN } }),
      );
      expect(introspect.status).toBe(401);
    }
    expect(store.calls).toEqual([]);
  });

  it("hashes both factors and passes NEITHER raw value to the store", async () => {
    const { service, store } = harness();
    await service.claim(PROVIDER_TOKEN, PEER, agentEnvelope(CLAIM_BODY));
    const [sessionHash, input] = store.inputs[0] as [
      string,
      { grantTokenHash: string },
    ];
    expect(sessionHash).toBe(hashSessionToken("provider", PROVIDER_TOKEN));
    expect(input.grantTokenHash).toBe(hashCommerceGrantToken(GRANT_TOKEN));
    const serialized = JSON.stringify(store.inputs);
    expect(serialized).not.toContain(PROVIDER_TOKEN);
    expect(serialized).not.toContain(GRANT_TOKEN);
  });

  it("rejects a claim result bound to a different action or attempt", async () => {
    const { service, store } = harness();
    store.results["claimCommerceGrant"] = {
      replayed: false,
      item: claimedProviderView({ actionId: ACTION_B }),
      attemptId: ATTEMPT,
      claimedAt: CLAIMED,
      claimDigest: CLAIM_DIGEST,
      receipt: grantReceipt("control.grant.claim"),
    };
    expect((await failure(
      service.claim(PROVIDER_TOKEN, PEER, agentEnvelope(CLAIM_BODY)),
    )).status).toBe(503);

    store.results["claimCommerceGrant"] = {
      replayed: false,
      item: claimedProviderView({ claimedAttemptId: ATTEMPT_B }),
      attemptId: ATTEMPT_B,
      claimedAt: CLAIMED,
      claimDigest: CLAIM_DIGEST,
      receipt: grantReceipt("control.grant.claim"),
    };
    expect((await failure(
      service.claim(PROVIDER_TOKEN, PEER, agentEnvelope(CLAIM_BODY)),
    )).status).toBe(503);
  });

  it("keeps the claim projection free of buyer-private fields and of the secret", async () => {
    const { service } = harness();
    const data = await service.claim(
      PROVIDER_TOKEN,
      PEER,
      agentEnvelope(CLAIM_BODY),
    );
    const serialized = JSON.stringify(data);
    for (const forbidden of [
      "organizationId",
      "subjectAgentId",
      "policyId",
      "commerceSessionId",
      "reservationId",
      "grantToken",
      "oag_v1_",
    ]) {
      expect([forbidden, serialized.includes(forbidden)]).toEqual([
        forbidden,
        false,
      ]);
    }
    // Money is an exact integer string on the provider projection.
    expect(data.item.amountAtomic).toBe("123456789012345678901234567890");
    expect(data.item.debitAtomic).toBe("123456789012345678901234567891");
  });

  it("echoes only the attempt id the provider already owns", async () => {
    const { service, store } = harness();
    const data = await service.getProviderAttemptStatus(PROVIDER_TOKEN, PEER, {
      attemptId: ATTEMPT,
    });
    expect(data.attemptId).toBe(ATTEMPT);
    store.results["getProviderCommerceGrantAttemptStatus"] = {
      attemptId: ATTEMPT_B,
      item: providerAttemptStatus(),
    };
    expect((await failure(
      service.getProviderAttemptStatus(PROVIDER_TOKEN, PEER, { attemptId: ATTEMPT }),
    )).status).toBe(503);
  });

  it("returns a bare not_found for a missing or foreign attempt", async () => {
    const { service, store } = harness();
    store.results["getProviderCommerceGrantAttemptStatus"] = {
      attemptId: ATTEMPT,
      item: { status: "not_found" },
    };
    const data = await service.getProviderAttemptStatus(PROVIDER_TOKEN, PEER, {
      attemptId: ATTEMPT,
    });
    expect(data.item).toEqual({ status: "not_found" });
    // The recovery read still needed the current provider authority: the store
    // was reached exactly once and answered under that session.
    expect(store.calls).toEqual(["getProviderCommerceGrantAttemptStatus"]);
  });
});

describe("browser management", () => {
  it("runs the finish guard before disclosing a missing grant", async () => {
    const { service, store, order } = harness();
    store.results["getCommerceGrant"] = {
      organizationId: ORG,
      grantId: GRANT,
      item: null,
    };
    const detail = await service.getGrant(CTX, {
      organizationId: ORG,
      grantId: GRANT,
    });
    expect(detail.item).toBeNull();
    expect(order).toEqual([
      "auth.beginTenantRead",
      "store.getCommerceGrant",
      "auth.finishTenantRead",
    ]);
  });

  it("rejects a foreign organization or grant even with a null item", async () => {
    const { service, store } = harness();
    for (const raw of [
      { organizationId: ORG_B, grantId: GRANT, item: null },
      { organizationId: ORG, grantId: GRANT_B, item: null },
    ]) {
      store.results["getCommerceGrant"] = raw;
      expect((await failure(
        service.getGrant(CTX, { organizationId: ORG, grantId: GRANT }),
      )).status).toBe(503);
    }
  });

  it("verifies CSRF before the live session and the store", async () => {
    const { service, auth, order } = harness();
    auth.csrfThrows = true;
    const error = await failure(
      service.revoke(CTX, ORG, GRANT, {
        csrf: CSRF,
        idempotencyKey: IDEMPOTENCY,
        body: { mutationId: MUTATION },
      }),
    );
    expect(error.status).toBe(403);
    expect(order).toEqual(["auth.verifyCsrf"]);
  });

  it("drops the store reservation status and never invents a vocabulary", async () => {
    const { service } = harness();
    const data = await service.revoke(CTX, ORG, GRANT, {
      csrf: CSRF,
      idempotencyKey: IDEMPOTENCY,
      body: { mutationId: MUTATION },
    });
    expect(Object.keys(data).sort()).toEqual([
      "actionStatus",
      "metadata",
      "receipt",
      "released",
      "replayed",
    ]);
    const serialized = JSON.stringify(data);
    expect(serialized).not.toContain("reservationStatus");
    expect(serialized).not.toContain("released_to");
    // No refund, settlement, payment or delivery leaf is representable.
    for (const forbidden of ["refund", "settle", "payment", "delivery"]) {
      expect([forbidden, serialized.includes(forbidden)]).toEqual([
        forbidden,
        false,
      ]);
    }
  });

  it("refuses to call a claimed grant released", async () => {
    const { service, store } = harness();
    store.results["revokeCommerceGrant"] = {
      replayed: false,
      metadata: grantMetadata({
        status: "revoked",
        claimedAt: CLAIMED,
        revokedAt: CLAIMED,
        updatedAt: CLAIMED,
      }),
      receipt: grantReceipt("control.grant.revoke"),
      released: true,
      actionStatus: "cancelled",
      reservationStatus: "claimed",
    };
    expect((await failure(
      service.revoke(CTX, ORG, GRANT, {
        csrf: CSRF,
        idempotencyKey: IDEMPOTENCY,
        body: { mutationId: MUTATION },
      }),
    )).status).toBe(503);
  });

  it("never surfaces an agent or provider receipt on the browser lane", async () => {
    const { service, store } = harness();
    for (const operation of [
      "control.grant.issue",
      "control.grant.replace",
      "control.grant.claim",
    ]) {
      store.results["getHumanCommerceGrantMutationStatus"] = {
        status: "committed",
        receipt: grantReceipt(operation),
      };
      expect((await failure(
        service.getHumanMutationStatus(CTX, {
          organizationId: ORG,
          mutationId: MUTATION,
        }),
      )).status).toBe(503);
    }
    store.results["getHumanCommerceGrantMutationStatus"] = {
      status: "committed",
      receipt: grantReceipt("control.grant.revoke"),
    };
    const ok = await service.getHumanMutationStatus(CTX, {
      organizationId: ORG,
      mutationId: MUTATION,
    });
    expect(ok.status).toBe("committed");
  });

  it("runs the finish guard for a not_found recovery read", async () => {
    const { service, order } = harness();
    await service.getHumanMutationStatus(CTX, {
      organizationId: ORG,
      mutationId: MUTATION,
    });
    expect(order).toEqual([
      "auth.beginTenantRead",
      "store.getHumanCommerceGrantMutationStatus",
      "auth.finishTenantRead",
    ]);
  });
});

/**
 * The COMPLETE DB12 store error table. Every code the accepted
 * `ControlGrantStore` declares appears here with its exact wire mapping; the
 * service's `satisfies Record<ControlGrantStoreErrorCode, true>` makes an
 * upstream rename or addition a BUILD failure rather than a silent 503.
 */
const STORE_ERROR_TABLE: readonly {
  code: string;
  status: number;
  wire: string;
}[] = [
  { code: "CONTROL_GRANT_STORE_INPUT_INVALID", status: 400, wire: "INVALID_REQUEST" },
  { code: "CONTROL_GRANT_STORE_SESSION_INVALID", status: 401, wire: "UNAUTHENTICATED" },
  { code: "CONTROL_GRANT_STORE_FORBIDDEN", status: 403, wire: "FORBIDDEN" },
  { code: "CONTROL_GRANT_STORE_NOT_FOUND", status: 403, wire: "FORBIDDEN" },
  { code: "CONTROL_GRANT_STORE_CONFLICT", status: 409, wire: "POLICY_DENIED" },
  { code: "CONTROL_GRANT_STORE_GRANT_CONFLICT", status: 409, wire: "POLICY_DENIED" },
  { code: "CONTROL_GRANT_STORE_GRANT_EXPIRED", status: 409, wire: "GRANT_EXPIRED" },
  {
    code: "CONTROL_GRANT_STORE_POTENTIAL_EXPOSURE",
    status: 409,
    wire: "BUDGET_RESERVATION_CONFLICT",
  },
  {
    code: "CONTROL_GRANT_STORE_IDEMPOTENCY_CONFLICT",
    status: 409,
    wire: "IDEMPOTENCY_CONFLICT",
  },
  {
    code: "CONTROL_GRANT_STORE_REQUIREMENT_UNAVAILABLE",
    status: 503,
    wire: "INTERNAL_ERROR",
  },
  { code: "CONTROL_GRANT_STORE_UNAVAILABLE", status: 503, wire: "INTERNAL_ERROR" },
  // Terminal and DISTINCT from the 503 every other dependency failure shares.
  { code: "CONTROL_GRANT_STORE_OUTCOME_UNKNOWN", status: 500, wire: "INTERNAL_ERROR" },
];

describe("store error mapping", () => {
  it("maps every DB12 code to its exact fixed wire error", async () => {
    for (const entry of STORE_ERROR_TABLE) {
      const { service, store } = harness();
      store.failures["issueCommerceGrant"] = entry.code;
      const error = await failure(
        service.issue(SESSION_TOKEN, PEER, agentEnvelope(ISSUE_BODY)),
      );
      expect([entry.code, error.status]).toEqual([entry.code, entry.status]);
      expect([entry.code, error.code]).toEqual([entry.code, entry.wire]);
      // A fixed catalog message: never the store's own text, never the input.
      expect(error.message).not.toContain("ControlGrantStore");
      expect(error.message).not.toContain(GRANT);
    }
  });

  it("collapses an unrecognized store failure to the fixed 503", async () => {
    for (const thrown of [
      "CONTROL_GRANT_STORE_RENAMED",
      "",
      "control_grant_store_unavailable",
    ]) {
      const { service, store } = harness();
      store.failures["issueCommerceGrant"] = thrown;
      const error = await failure(
        service.issue(SESSION_TOKEN, PEER, agentEnvelope(ISSUE_BODY)),
      );
      expect(error.status).toBe(503);
      expect(error.code).toBe("INTERNAL_ERROR");
    }
  });

  it("keeps the unknown outcome DISTINCT from every retryable 503", async () => {
    const { service, store } = harness();
    store.failures["issueCommerceGrant"] = "CONTROL_GRANT_STORE_OUTCOME_UNKNOWN";
    const unknown = await failure(
      service.issue(SESSION_TOKEN, PEER, agentEnvelope(ISSUE_BODY)),
    );
    store.failures["issueCommerceGrant"] = "CONTROL_GRANT_STORE_UNAVAILABLE";
    const outage = await failure(
      service.issue(SESSION_TOKEN, PEER, agentEnvelope(ISSUE_BODY)),
    );
    expect(unknown.status).toBe(500);
    expect(outage.status).toBe(503);
    expect(unknown.status).not.toBe(outage.status);
  });

  it("never retries, re-dispatches or issues a recovery read on an unknown outcome", async () => {
    for (const operation of [
      "issueCommerceGrant",
      "replaceCommerceGrant",
      "claimCommerceGrant",
      "revokeCommerceGrant",
    ] as const) {
      const { service, store, order } = harness();
      store.failures[operation] = "CONTROL_GRANT_STORE_OUTCOME_UNKNOWN";
      const call =
        operation === "issueCommerceGrant"
          ? service.issue(SESSION_TOKEN, PEER, agentEnvelope(ISSUE_BODY))
          : operation === "replaceCommerceGrant"
            ? service.replace(
                SESSION_TOKEN,
                PEER,
                GRANT,
                agentEnvelope({ mutationId: MUTATION }),
              )
            : operation === "claimCommerceGrant"
              ? service.claim(PROVIDER_TOKEN, PEER, agentEnvelope(CLAIM_BODY))
              : service.revoke(CTX, ORG, GRANT, {
                  csrf: CSRF,
                  idempotencyKey: IDEMPOTENCY,
                  body: { mutationId: MUTATION },
                });
      const error = await failure(call);
      expect([operation, error.status]).toEqual([operation, 500]);
      // EXACTLY ONE store invocation: no retry, no re-dispatch and no
      // mutation-status or attempt-status recovery read on the caller's behalf.
      expect([operation, store.calls]).toEqual([operation, [operation]]);
      expect(
        order.filter((entry) => entry.startsWith("store.")),
      ).toHaveLength(1);
      expect(
        order.some((entry) => entry.includes("MutationStatus")),
      ).toBe(false);
      expect(
        order.some((entry) => entry.includes("AttemptStatus")),
      ).toBe(false);
      // The message never claims a refund, release, retry or settlement.
      for (const word of ["refund", "release", "retry", "settle", "committed"]) {
        expect([operation, word, error.message.toLowerCase().includes(word)])
          .toEqual([operation, word, false]);
      }
    }
  });

  it("keeps a commerce-session outage a 503 and an unknown outcome a 500", async () => {
    const outage = harness();
    outage.sessions.failure = "COMMERCE_SESSION_STORE_UNAVAILABLE";
    expect((await failure(
      outage.service.issue(SESSION_TOKEN, PEER, agentEnvelope(ISSUE_BODY)),
    )).status).toBe(503);

    const unknown = harness();
    unknown.sessions.failure = "CONTROL_GRANT_STORE_OUTCOME_UNKNOWN";
    expect((await failure(
      unknown.service.issue(SESSION_TOKEN, PEER, agentEnvelope(ISSUE_BODY)),
    )).status).toBe(500);

    const invalid = harness();
    invalid.sessions.failure = "COMMERCE_SESSION_STORE_NOT_FOUND";
    expect((await failure(
      invalid.service.issue(SESSION_TOKEN, PEER, agentEnvelope(ISSUE_BODY)),
    )).status).toBe(401);
    expect(invalid.store.calls).toEqual([]);
  });

  it("never trusts a revoked commerce session", async () => {
    const { service, store, sessions } = harness();
    sessions.results = [commerceSessionMetadata({ revokedAt: EXPIRED })];
    const error = await failure(
      service.issue(SESSION_TOKEN, PEER, agentEnvelope(ISSUE_BODY)),
    );
    expect(error.status).toBe(401);
    expect(store.calls).toEqual([]);
  });
});

const EXPIRED = "2026-01-01T00:04:00.000Z";

describe("rate limiting fails closed", () => {
  it("returns the fixed 503 before any store authority when the limiter errors", async () => {
    const store = new FakeStore();
    const service = new CommerceGrantService({
      auth: new FakeAuth() as unknown as CommerceGrantAuthPort,
      store: store as unknown as CommerceGrantStorePort,
      commerceSessions:
        new FakeCommerceSessions() as unknown as CommerceGrantSessionReadPort,
      limits: new CommerceGrantRateLimiter({
        secret: "unit-test-secret",
        store: {
          consume: async () => {
            throw new Error("limiter down");
          },
        },
      }),
    });
    const error = await failure(
      service.issue(SESSION_TOKEN, PEER, agentEnvelope(ISSUE_BODY)),
    );
    expect(error.status).toBe(503);
    expect(store.calls).toEqual([]);
  });

  it("returns a fixed 429 for a denied bucket and never reaches the store", async () => {
    const store = new FakeStore();
    const service = new CommerceGrantService({
      auth: new FakeAuth() as unknown as CommerceGrantAuthPort,
      store: store as unknown as CommerceGrantStorePort,
      commerceSessions:
        new FakeCommerceSessions() as unknown as CommerceGrantSessionReadPort,
      limits: new CommerceGrantRateLimiter({
        secret: "unit-test-secret",
        store: { consume: async () => ({ allowed: false }) },
      }),
    });
    const error = await failure(
      service.claim(PROVIDER_TOKEN, PEER, agentEnvelope(CLAIM_BODY)),
    );
    expect(error.status).toBe(429);
    expect(store.calls).toEqual([]);
  });
});
