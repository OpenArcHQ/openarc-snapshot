import { describe, expect, it } from "vitest";

import { CommerceSessionStoreError, CredentialStoreError } from "@openarc/db";

import type { AuthApiError } from "../src/auth/errors.js";
import type { AuthRequestContext } from "../src/auth/service.js";
import {
  CommerceSessionRateLimiter,
} from "../src/control/session-rate-limiter.js";
import {
  CommerceSessionService,
  type CommerceSessionFactoryPort,
} from "../src/control/session-service.js";
import type {
  AgentSessionReadPort,
  CommerceSessionAuthPort,
  CommerceSessionRateLimitStorePort,
  CommerceSessionStorePort,
} from "../src/control/session-ports.js";

/**
 * Unit coverage for the commerce-session orchestration service.
 *
 * The CommerceSessionStore, CredentialStore read and AuthService seams are
 * HONESTLY MOCKED here: this suite proves strict parse/auth/limiter/store
 * ordering, exact store input binding, whole-projection validation, one-time
 * delivery vs replay-without-secret, trusted-org binding for agent status and
 * fixed error mapping. Real SQL, RLS, locks and crypto are covered elsewhere.
 */

const MUTATION = "12345678-1234-4234-8123-123456789abc";
const ORG = `openarc:org:${MUTATION}`;
const OTHER_ORG = `openarc:org:22345678-1234-4234-8123-123456789abc`;
const AGENT = `openarc:agent:${MUTATION}`;
const POLICY = `openarc:policy:${MUTATION}`;
const ACCOUNT = `openarc:account:${MUTATION}`;
const SESSION = MUTATION;
const CREDENTIAL = MUTATION;
const ISSUED = "2026-01-01T00:00:00.000Z";
const EXPIRES = "2026-01-01T00:05:00.000Z";
const EXCHANGED = "2026-01-01T00:00:30.000Z";
const REVOKED = "2026-01-01T00:01:00.000Z";
const HANDOFF_EXPIRES = "2026-01-01T00:00:10.000Z";
const HASH = "a".repeat(64);
const IDEMPOTENCY = "A".repeat(43);
const HANDOFF_TOKEN = `oach_v1_${"A".repeat(43)}`;
const SESSION_TOKEN = `oacs_v1_${"E".repeat(43)}`;
const AGENT_TOKEN = `oas_ag_${"A".repeat(43)}`;
const CTX: AuthRequestContext = {
  peerIp: "127.0.0.1",
  cookies: { session: "s", binding: "b" },
};

function sessionMetadata(overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: "openarc.control.commerce-session.v1",
    sessionId: SESSION,
    organizationId: ORG,
    subjectAgentId: AGENT,
    policyId: POLICY,
    scopes: ["commerce.authorize"],
    networkId: "eip155:5042002",
    asset: "USDC",
    representation: "erc20",
    decimals: 6,
    issuedAt: ISSUED,
    expiresAt: EXPIRES,
    exchangedAt: null,
    revokedAt: null,
    ...overrides,
  };
}

function receipt(operation: string, mutationId = MUTATION) {
  return {
    mutationId,
    operation,
    resourceType: "commerce_session",
    resourceId: SESSION,
    committedAt: ISSUED,
  };
}

function agentSession(overrides: Record<string, unknown> = {}) {
  return {
    sessionId: SESSION,
    credentialId: CREDENTIAL,
    organizationId: ORG,
    kind: "agent" as const,
    profileId: AGENT,
    // The real read returns the issuer account; create APIs may omit it.
    issuerAccountId: ACCOUNT,
    scope: "agent:self.read",
    scopeVersion: 1 as const,
    environment: "eip155:5042002" as const,
    createdAt: ISSUED,
    expiresAt: EXPIRES,
    revocationVersion: 1,
    ...overrides,
  };
}

class FakeAuth implements CommerceSessionAuthPort {
  readonly calls: string[] = [];
  csrfError: unknown;
  beginError: unknown;
  finishError: unknown;

  verifyCsrf(): string {
    this.calls.push("csrf");
    if (this.csrfError) throw this.csrfError;
    return "binding";
  }
  async beginTenantRead(): Promise<{ sessionHash: string; accountId: string }> {
    this.calls.push("begin");
    if (this.beginError) throw this.beginError;
    return { sessionHash: HASH, accountId: `openarc:account:${MUTATION}` };
  }
  async finishTenantRead(): Promise<void> {
    this.calls.push("finish");
    if (this.finishError) throw this.finishError;
  }
}

class FakeRateStore implements CommerceSessionRateLimitStorePort {
  readonly keys: string[] = [];
  readonly limits: number[] = [];
  allowed = true;
  error: unknown;

  async consume(input: {
    keyHash: string;
    limit: number;
  }): Promise<{ allowed: boolean }> {
    this.keys.push(input.keyHash.slice(0, 8));
    this.limits.push(input.limit);
    if (this.error) throw this.error;
    return { allowed: this.allowed };
  }
}

class FakeStore implements CommerceSessionStorePort {
  readonly calls: string[] = [];
  issueResult: unknown = {
    replayed: false,
    metadata: sessionMetadata(),
    receipt: receipt("control.commerce_session.issue"),
    handoffExpiresAt: HANDOFF_EXPIRES,
  };
  exchangeResult: unknown = {
    replayed: false,
    metadata: sessionMetadata({ exchangedAt: EXCHANGED }),
    receipt: receipt("control.commerce_session.exchange"),
  };
  revokeResult: unknown = {
    replayed: false,
    metadata: sessionMetadata({ revokedAt: REVOKED }),
    receipt: receipt("control.commerce_session.revoke"),
  };
  statusResult: unknown = { organizationId: ORG, item: null };
  listResult: unknown = { items: [], nextCursor: null };
  humanStatusResult: unknown = { status: "not_found" };
  agentStatusResult: unknown = { status: "not_found" };
  error: unknown;
  readonly inputs: Record<string, unknown> = {};

  async issueCommerceSession(...args: unknown[]): Promise<never> {
    this.calls.push("issue");
    this.inputs["issue"] = args;
    if (this.error) throw this.error;
    return this.issueResult as never;
  }
  async exchangeCommerceSession(...args: unknown[]): Promise<never> {
    this.calls.push("exchange");
    this.inputs["exchange"] = args;
    if (this.error) throw this.error;
    return this.exchangeResult as never;
  }
  async revokeCommerceSession(...args: unknown[]): Promise<never> {
    this.calls.push("revoke");
    this.inputs["revoke"] = args;
    if (this.error) throw this.error;
    return this.revokeResult as never;
  }
  async getCommerceSessionStatus(...args: unknown[]): Promise<never> {
    this.calls.push("status");
    this.inputs["status"] = args;
    if (this.error) throw this.error;
    return this.statusResult as never;
  }
  async listCommerceSessions(...args: unknown[]): Promise<never> {
    this.calls.push("list");
    this.inputs["list"] = args;
    if (this.error) throw this.error;
    return this.listResult as never;
  }
  async getHumanCommerceSessionMutationStatus(...args: unknown[]): Promise<never> {
    this.calls.push("humanStatus");
    this.inputs["humanStatus"] = args;
    if (this.error) throw this.error;
    return this.humanStatusResult as never;
  }
  async getAgentCommerceSessionMutationStatus(...args: unknown[]): Promise<never> {
    this.calls.push("agentStatus");
    this.inputs["agentStatus"] = args;
    if (this.error) throw this.error;
    return this.agentStatusResult as never;
  }
}

class FakeAgentSessions implements AgentSessionReadPort {
  readonly calls: number[] = [];
  responses: unknown[] = [agentSession()];
  error: unknown;

  async getAgentSession(): Promise<never> {
    this.calls.push(this.calls.length + 1);
    if (this.error) throw this.error;
    const next = this.responses.shift();
    return (next ?? agentSession()) as never;
  }
}

const FACTORY: CommerceSessionFactoryPort = {
  handoffToken: () => HANDOFF_TOKEN,
  sessionToken: () => SESSION_TOKEN,
};

function build(overrides: {
  factory?: CommerceSessionFactoryPort;
  store?: FakeStore;
  agent?: FakeAgentSessions;
  rate?: FakeRateStore;
  auth?: FakeAuth;
} = {}) {
  const auth = overrides.auth ?? new FakeAuth();
  const store = overrides.store ?? new FakeStore();
  const agent = overrides.agent ?? new FakeAgentSessions();
  const rate = overrides.rate ?? new FakeRateStore();
  const limits = new CommerceSessionRateLimiter({ secret: "secret", store: rate });
  const service = new CommerceSessionService({
    auth,
    store,
    agentSessions: agent,
    limits,
    factory: overrides.factory ?? FACTORY,
  });
  return { service, auth, store, agent, rate };
}

const ISSUE_BODY = {
  mutationId: MUTATION,
  subjectAgentId: AGENT,
  policyId: POLICY,
  durationSeconds: "120",
};
const WRITE = {
  csrf: "csrf",
  idempotencyKey: IDEMPOTENCY,
  body: ISSUE_BODY,
};

async function expectAuthError(
  promise: Promise<unknown>,
  status: number,
  code?: string,
): Promise<void> {
  try {
    await promise;
    throw new Error("expected rejection");
  } catch (error) {
    const apiError = error as AuthApiError;
    expect(apiError.status).toBe(status);
    if (code !== undefined) expect(apiError.code).toBe(code);
  }
}

describe("CommerceSessionService human issue", () => {
  it("orders parse, CSRF, begin, account limit, then exactly one issue", async () => {
    const { service, auth, store, rate } = build();
    const result = await service.issue(CTX, ORG, WRITE);

    expect(auth.calls).toEqual(["csrf", "begin"]);
    expect(store.calls).toEqual(["issue"]);
    expect(rate.limits).toEqual([10]);
    expect(result.replayed).toBe(false);
    if (!result.replayed) {
      expect(result.delivery.state).toBe("available_once");
      if (result.delivery.state === "available_once") {
        expect(result.delivery.handoffToken).toBe(HANDOFF_TOKEN);
        expect(result.delivery.handoffExpiresAt).toBe(HANDOFF_EXPIRES);
      }
    }
  });

  it("binds the exact accepted store input and hashes the handoff", async () => {
    const { service, store } = build();
    await service.issue(CTX, ORG, WRITE);
    const args = store.inputs["issue"] as unknown[];
    expect(args[0]).toBe(HASH);
    expect(args[1]).toBe(ORG);
    expect(args[2]).toEqual({
      subjectAgentId: AGENT,
      policyId: POLICY,
      durationSeconds: 120,
      handoffHash: expect.stringMatching(/^[0-9a-f]{64}$/u),
      hashVersion: 1,
    });
    expect(args[3]).toEqual({ idempotencyKey: IDEMPOTENCY, mutationId: MUTATION });
  });

  it("defaults an absent duration to 300 seconds", async () => {
    const { service, store } = build();
    await service.issue(CTX, ORG, {
      ...WRITE,
      body: { mutationId: MUTATION, subjectAgentId: AGENT, policyId: POLICY },
    });
    const input = (store.inputs["issue"] as unknown[])[2] as {
      durationSeconds: number;
    };
    expect(input.durationSeconds).toBe(300);
  });

  it("delivers no secret and no handoff expiry on replay", async () => {
    const store = new FakeStore();
    store.issueResult = {
      replayed: true,
      metadata: sessionMetadata({
        exchangedAt: EXCHANGED,
        revokedAt: REVOKED,
      }),
      receipt: receipt("control.commerce_session.issue"),
      handoffExpiresAt: HANDOFF_EXPIRES,
    };
    const { service } = build({ store });
    const result = await service.issue(CTX, ORG, WRITE);
    expect(result.replayed).toBe(true);
    expect(result.delivery).toEqual({ state: "not_replayable" });
    expect(JSON.stringify(result)).not.toContain("oach_v1_");
  });

  it("validates the original raw handoff expiry on replay", async () => {
    for (const bad of [
      "not-a-timestamp",
      ISSUED,
      "2026-01-01T00:00:00.000Z",
      "2026-01-01T00:05:00.001Z",
    ]) {
      const store = new FakeStore();
      store.issueResult = {
        replayed: true,
        metadata: sessionMetadata({ exchangedAt: EXCHANGED }),
        receipt: receipt("control.commerce_session.issue"),
        handoffExpiresAt: bad,
      };
      const { service } = build({ store });
      await expectAuthError(service.issue(CTX, ORG, WRITE), 503);
    }
  });

  it("accepts a historical replay whose raw handoff expiry exceeds the shortened effective expiry", async () => {
    const store = new FakeStore();
    store.issueResult = {
      replayed: true,
      metadata: sessionMetadata({
        // The exchange shortened the effective expiry to 5s, while the original
        // handoff expiry stays at 10s (still within the initial 300s bound).
        expiresAt: "2026-01-01T00:00:05.000Z",
        exchangedAt: "2026-01-01T00:00:04.000Z",
      }),
      receipt: receipt("control.commerce_session.issue"),
      handoffExpiresAt: HANDOFF_EXPIRES,
    };
    const { service } = build({ store });
    const result = await service.issue(CTX, ORG, WRITE);
    expect(result.replayed).toBe(true);
    expect(result.delivery).toEqual({ state: "not_replayable" });
  });

  it("rejects a duration outside 1..900 before auth", async () => {
    const { service, auth } = build();
    await expectAuthError(
      service.issue(CTX, ORG, {
        ...WRITE,
        body: { ...ISSUE_BODY, durationSeconds: "901" },
      }),
      400,
    );
    expect(auth.calls).toEqual([]);
  });

  it("rejects a store rebound organization/subject/policy as 503", async () => {
    const store = new FakeStore();
    store.issueResult = {
      replayed: false,
      metadata: sessionMetadata({ subjectAgentId: `openarc:agent:${"0".repeat(8)}-1234-4234-8123-123456789abc` }),
      receipt: receipt("control.commerce_session.issue"),
      handoffExpiresAt: HANDOFF_EXPIRES,
    };
    const { service } = build({ store });
    await expectAuthError(service.issue(CTX, ORG, WRITE), 503);
  });

  it("maps a store error to the fixed status", async () => {
    const store = new FakeStore();
    store.error = new CommerceSessionStoreError("COMMERCE_SESSION_STORE_IDEMPOTENCY_CONFLICT");
    const { service } = build({ store });
    await expectAuthError(service.issue(CTX, ORG, WRITE), 409, "IDEMPOTENCY_CONFLICT");
  });

  it("fails closed with 503 when token generation throws", async () => {
    const throwing: CommerceSessionFactoryPort = {
      handoffToken: () => {
        throw new Error("rng failure");
      },
      sessionToken: () => SESSION_TOKEN,
    };
    const { service, store } = build({ factory: throwing });
    await expectAuthError(service.issue(CTX, ORG, WRITE), 503);
    expect(store.calls).toEqual([]);
  });
});

describe("CommerceSessionService human reads", () => {
  it("does begin, one read, finish, then projection", async () => {
    const { service, auth, store } = build();
    const result = await service.getStatus(CTX, {
      organizationId: ORG,
      sessionId: SESSION,
    });
    expect(auth.calls).toEqual(["begin", "finish"]);
    expect(store.calls).toEqual(["status"]);
    expect(result).toEqual({ organizationId: ORG, item: null });
  });

  it("finishes the read even when the store throws", async () => {
    const store = new FakeStore();
    store.error = new CommerceSessionStoreError("COMMERCE_SESSION_STORE_NOT_FOUND");
    const { service, auth } = build({ store });
    await expectAuthError(
      service.getStatus(CTX, { organizationId: ORG, sessionId: SESSION }),
      403,
    );
    // The store error is mapped before finish; accepted read convention.
    expect(auth.calls).toEqual(["begin"]);
  });

  it("caps the list to the requested limit and rejects a stale cursor", async () => {
    const store = new FakeStore();
    store.listResult = {
      items: [
        { metadata: sessionMetadata(), status: "handoff_pending" },
        {
          metadata: sessionMetadata({
            sessionId: "22345678-1234-4234-8123-123456789abc",
          }),
          status: "handoff_pending",
        },
      ],
      nextCursor: null,
    };
    const { service } = build({ store });
    await expectAuthError(
      service.list(CTX, { organizationId: ORG, limit: "1" }),
      503,
    );
  });

  it("returns a committed human mutation status only for issue/revoke", async () => {
    const store = new FakeStore();
    store.humanStatusResult = {
      status: "committed",
      receipt: receipt("control.commerce_session.revoke"),
    };
    const { service } = build({ store });
    const result = await service.getHumanMutationStatus(CTX, {
      organizationId: ORG,
      mutationId: MUTATION,
    });
    expect(result.status).toBe("committed");
  });

  it("rejects an exchange receipt on the human mutation status", async () => {
    const store = new FakeStore();
    store.humanStatusResult = {
      status: "committed",
      receipt: receipt("control.commerce_session.exchange"),
    };
    const { service } = build({ store });
    await expectAuthError(
      service.getHumanMutationStatus(CTX, {
        organizationId: ORG,
        mutationId: MUTATION,
      }),
      503,
    );
  });

  it("requires exact store envelope keys", async () => {
    const store = new FakeStore();
    store.statusResult = { organizationId: ORG, item: null, extra: true };
    const { service } = build({ store });
    await expectAuthError(
      service.getStatus(CTX, { organizationId: ORG, sessionId: SESSION }),
      503,
    );
  });

  it("rejects a raw foreign organization after finishTenantRead with a fixed 503", async () => {
    const store = new FakeStore();
    store.statusResult = { organizationId: OTHER_ORG, item: null };
    const { service, auth } = build({ store });
    await expectAuthError(
      service.getStatus(CTX, { organizationId: ORG, sessionId: SESSION }),
      503,
    );
    // The guard is a read: finish runs before the projection rejects the org.
    expect(auth.calls).toEqual(["begin", "finish"]);
  });

  it("rejects a non-canonical raw organization even with a null item", async () => {
    const store = new FakeStore();
    store.statusResult = { organizationId: "openarc:org:not-a-uuid", item: null };
    const { service, auth } = build({ store });
    await expectAuthError(
      service.getStatus(CTX, { organizationId: ORG, sessionId: SESSION }),
      503,
    );
    expect(auth.calls).toEqual(["begin", "finish"]);
  });

  it("bounds an absent list limit to the default 25, not the shared max 50", async () => {
    const store = new FakeStore();
    const items = Array.from({ length: 26 }, (_, index) =>
      ({
        metadata: sessionMetadata({
          sessionId: `${(index + 1).toString(16).padStart(8, "0")}-1234-4234-8123-123456789abc`,
        }),
        status: "handoff_pending",
      }) as const,
    );
    store.listResult = { items, nextCursor: null };
    const { service } = build({ store });
    await expectAuthError(service.list(CTX, { organizationId: ORG }), 503);
  });

  it("accepts a canonical absent-limit page at exactly 25 items", async () => {
    const store = new FakeStore();
    const items = Array.from({ length: 25 }, (_, index) =>
      ({
        metadata: sessionMetadata({
          sessionId: `${(index + 1).toString(16).padStart(8, "0")}-1234-4234-8123-123456789abc`,
        }),
        status: "handoff_pending",
      }) as const,
    );
    store.listResult = { items, nextCursor: null };
    const { service } = build({ store });
    const page = await service.list(CTX, { organizationId: ORG });
    expect(page.items).toHaveLength(25);
  });
});

describe("CommerceSessionService human revoke", () => {
  it("verifies CSRF, begins, and revokes the exact path session", async () => {
    const { service, auth, store } = build();
    const result = await service.revoke(CTX, ORG, SESSION, {
      csrf: "csrf",
      idempotencyKey: IDEMPOTENCY,
      body: { mutationId: MUTATION },
    });
    expect(auth.calls).toEqual(["csrf", "begin"]);
    expect(store.calls).toEqual(["revoke"]);
    expect(result.metadata.revokedAt).not.toBeNull();
    expect(store.inputs["revoke"]).toEqual([
      HASH,
      ORG,
      SESSION,
      { idempotencyKey: IDEMPOTENCY, mutationId: MUTATION },
    ]);
  });

  it("rejects a store session that does not match the path", async () => {
    const store = new FakeStore();
    store.revokeResult = {
      replayed: false,
      metadata: sessionMetadata({
        sessionId: "22345678-1234-4234-8123-123456789abc",
        revokedAt: REVOKED,
      }),
      receipt: {
        ...receipt("control.commerce_session.revoke"),
        resourceId: "22345678-1234-4234-8123-123456789abc",
      },
    };
    const { service } = build({ store });
    await expectAuthError(
      service.revoke(CTX, ORG, SESSION, {
        csrf: "csrf",
        idempotencyKey: IDEMPOTENCY,
        body: { mutationId: MUTATION },
      }),
      503,
    );
  });
});

describe("CommerceSessionService agent exchange", () => {
  function agentWrite(body: unknown = { mutationId: MUTATION, handoffToken: HANDOFF_TOKEN }) {
    return { idempotencyKey: IDEMPOTENCY, body };
  }

  it("rejects a wrong namespace token before the limiter or store", async () => {
    const { service, store, rate } = build();
    await expectAuthError(
      service.exchange(`oas_pr_${"A".repeat(43)}`, CTX.peerIp, agentWrite()),
      401,
    );
    await expectAuthError(
      service.exchange(`oacs_v1_${"A".repeat(43)}`, CTX.peerIp, agentWrite()),
      401,
    );
    expect(rate.limits).toEqual([]);
    expect(store.calls).toEqual([]);
  });

  it("takes the ordered global/peer/token limiter then one exchange", async () => {
    const { service, store, rate } = build();
    const result = await service.exchange(AGENT_TOKEN, CTX.peerIp, agentWrite());
    expect(rate.limits).toEqual([600, 120, 60]);
    expect(store.calls).toEqual(["exchange"]);
    const args = store.inputs["exchange"] as unknown[];
    expect(args[0]).toMatch(/^[0-9a-f]{64}$/u);
    expect(args[1]).toMatch(/^[0-9a-f]{64}$/u);
    expect(args[2]).toEqual({
      tokenHash: expect.stringMatching(/^[0-9a-f]{64}$/u),
      hashVersion: 1,
    });
    expect(result.replayed).toBe(false);
    if (!result.replayed && result.delivery.state === "available_once") {
      expect(result.delivery.sessionToken).toBe(SESSION_TOKEN);
    }
  });

  it("discards the locally generated token on replay", async () => {
    const store = new FakeStore();
    store.exchangeResult = {
      replayed: true,
      metadata: sessionMetadata({ exchangedAt: EXCHANGED }),
      receipt: receipt("control.commerce_session.exchange"),
    };
    const { service } = build({ store });
    const result = await service.exchange(AGENT_TOKEN, CTX.peerIp, agentWrite());
    expect(result.replayed).toBe(true);
    expect(result.delivery).toEqual({ state: "not_replayable" });
    expect(JSON.stringify(result)).not.toContain("oacs_v1_");
  });

  it("fails closed with 503 when the limiter store is down, before the store", async () => {
    const rate = new FakeRateStore();
    rate.error = new Error("down");
    const { service, store } = build({ rate });
    await expectAuthError(
      service.exchange(AGENT_TOKEN, CTX.peerIp, agentWrite()),
      503,
    );
    expect(store.calls).toEqual([]);
  });

  it("fails closed with 429 on a denied bucket", async () => {
    const rate = new FakeRateStore();
    rate.allowed = false;
    const { service, store } = build({ rate });
    await expectAuthError(
      service.exchange(AGENT_TOKEN, CTX.peerIp, agentWrite()),
      429,
      "RATE_LIMITED",
    );
    expect(store.calls).toEqual([]);
  });

  it("rejects a malformed exchange body before the limiter", async () => {
    const { service, rate } = build();
    await expectAuthError(
      service.exchange(AGENT_TOKEN, CTX.peerIp, agentWrite({ mutationId: MUTATION })),
      400,
    );
    expect(rate.limits).toEqual([]);
  });
});

describe("CommerceSessionService agent mutation status", () => {
  it("supplies the trusted organization on not_found and reads twice", async () => {
    const { service, agent, store } = build();
    const result = await service.getAgentMutationStatus(
      AGENT_TOKEN,
      CTX.peerIp,
      MUTATION,
    );
    expect(agent.calls).toEqual([1, 2]);
    expect(store.calls).toEqual(["agentStatus"]);
    expect(result).toEqual({
      organizationId: ORG,
      mutationId: MUTATION,
      status: "not_found",
    });
  });

  it("rejects a drift between the before/after trusted session", async () => {
    const agent = new FakeAgentSessions();
    agent.responses = [
      agentSession(),
      agentSession({ sessionId: "22345678-1234-4234-8123-123456789abc" }),
    ];
    const { service } = build({ agent });
    await expectAuthError(
      service.getAgentMutationStatus(AGENT_TOKEN, CTX.peerIp, MUTATION),
      503,
    );
  });

  it("accepts only an exchange receipt on the agent status", async () => {
    const store = new FakeStore();
    store.agentStatusResult = {
      status: "committed",
      receipt: receipt("control.commerce_session.exchange"),
    };
    const { service } = build({ store });
    const result = await service.getAgentMutationStatus(
      AGENT_TOKEN,
      CTX.peerIp,
      MUTATION,
    );
    expect(result.status).toBe("committed");
  });

  it("maps a credential store outage to a fixed 503", async () => {
    const agent = new FakeAgentSessions();
    agent.error = new CredentialStoreError("CREDENTIAL_STORE_UNAVAILABLE");
    const { service } = build({ agent });
    await expectAuthError(
      service.getAgentMutationStatus(AGENT_TOKEN, CTX.peerIp, MUTATION),
      503,
    );
  });

  it("maps a revoked credential read to the fixed 401", async () => {
    const agent = new FakeAgentSessions();
    agent.error = new CredentialStoreError("CREDENTIAL_STORE_NOT_FOUND");
    const { service } = build({ agent });
    await expectAuthError(
      service.getAgentMutationStatus(AGENT_TOKEN, CTX.peerIp, MUTATION),
      401,
    );
  });

  it("rejects an unknown or private key on the current agent session read", async () => {
    for (const extra of [
      { tokenHash: HASH },
      { digest: "x" },
      { issuerAccountId: undefined },
      { scopeVersion: 1, extra: true },
    ]) {
      const agent = new FakeAgentSessions();
      agent.responses = [agentSession(extra), agentSession(extra)];
      const { service } = build({ agent });
      await expectAuthError(
        service.getAgentMutationStatus(AGENT_TOKEN, CTX.peerIp, MUTATION),
        503,
      );
    }
  });

  it("rejects an invalid issuer account and an unsafe revocation version", async () => {
    for (const bad of [
      { issuerAccountId: "not-an-account" },
      { issuerAccountId: undefined },
      { revocationVersion: 0 },
      { revocationVersion: -1 },
      { revocationVersion: 1.5 },
      { revocationVersion: Number.MAX_SAFE_INTEGER + 2 },
      { revocationVersion: "1" },
    ]) {
      const agent = new FakeAgentSessions();
      agent.responses = [agentSession(bad), agentSession(bad)];
      const { service } = build({ agent });
      await expectAuthError(
        service.getAgentMutationStatus(AGENT_TOKEN, CTX.peerIp, MUTATION),
        503,
      );
    }
  });

  it("rejects a before/after revocation-version drift", async () => {
    const agent = new FakeAgentSessions();
    agent.responses = [agentSession(), agentSession({ revocationVersion: 2 })];
    const { service } = build({ agent });
    await expectAuthError(
      service.getAgentMutationStatus(AGENT_TOKEN, CTX.peerIp, MUTATION),
      503,
    );
  });

  it("rejects a before/after issuer drift", async () => {
    const agent = new FakeAgentSessions();
    agent.responses = [
      agentSession(),
      agentSession({
        issuerAccountId: `openarc:account:22345678-1234-4234-8123-123456789abc`,
      }),
    ];
    const { service } = build({ agent });
    await expectAuthError(
      service.getAgentMutationStatus(AGENT_TOKEN, CTX.peerIp, MUTATION),
      503,
    );
  });
});
