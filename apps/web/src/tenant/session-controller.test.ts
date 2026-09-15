import {
  COMMERCE_API_ERRORS,
  COMMERCE_API_SCHEMA_VERSION,
  type CommerceHumanRole,
} from "@openarc/shared";
import { describe, expect, it, vi } from "vitest";

import type { AccountFlowController } from "../account/flow-controller.js";
import { SessionClient } from "./session-client.js";
import {
  SessionController,
  appendSessionCursor,
  canReadSessions,
  canWriteSessions,
  canonicalDurationSeconds,
  initialSessionControllerState,
  renderSessionState,
  sessionMetadataExpired,
  suppressStaleSessionContext,
  type SessionAgentSelection,
  type SessionReadCoordinator,
} from "./session-controller.js";

const META = {
  schemaVersion: COMMERCE_API_SCHEMA_VERSION,
  requestId: "018f47a2-3b4c-7def-8123-456789abcdef",
  buildSha: "0123456789abcdef0123456789abcdef01234567",
};

const V4 = "12345678-1234-4234-8123-123456789abc";
const V4_B = "87654321-4321-4321-b123-abcdefabcdef";
const ORG = `openarc:org:${V4}`;
const ORG_B = `openarc:org:${V4_B}`;
const AGENT = `openarc:agent:${V4}`;
const AGENT_B = `openarc:agent:${V4_B}`;
const POLICY = `openarc:policy:${V4}`;
const SESSION = V4;
const SESSION_B = V4_B;
const ACCOUNT_A = `openarc:account:${V4}`;
const ISO = "2026-01-01T00:00:00.000Z";
const EXPIRES = "2026-01-01T00:05:00.000Z";
const ISSUED6 = "2026-01-01T00:00:00.000000Z";
const EXPIRES6 = "2026-01-01T00:15:00.000000Z";
const REVOKED6 = "2026-01-01T00:06:00.000000Z";
const HANDOFF = `oach_v1_${"A".repeat(42)}A`;

function success(data: unknown): Response {
  return new Response(JSON.stringify({ ok: true, data, meta: META }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function errorEnvelope(code: keyof typeof COMMERCE_API_ERRORS, status: number): Response {
  return new Response(
    JSON.stringify({
      ok: false,
      error: { code, message: COMMERCE_API_ERRORS[code].message, retryable: false },
      meta: META,
    }),
    { status, headers: { "content-type": "application/json" } },
  );
}

function metadata(sessionId = SESSION, overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: "openarc.control.commerce-session.v1",
    sessionId,
    organizationId: ORG,
    subjectAgentId: AGENT,
    policyId: POLICY,
    scopes: ["commerce.authorize"],
    networkId: "eip155:5042002",
    asset: "USDC",
    representation: "erc20",
    decimals: 6,
    issuedAt: ISSUED6,
    expiresAt: EXPIRES6,
    exchangedAt: null,
    revokedAt: null,
    ...overrides,
  };
}

function statusItem(sessionId = SESSION, status = "handoff_pending", overrides: Record<string, unknown> = {}) {
  return { metadata: metadata(sessionId, overrides), status };
}

function receipt(operation: string, resourceId: string, mutationId: string) {
  return { mutationId, operation, resourceType: "commerce_session", resourceId, committedAt: ISO };
}

function issueResult(overrides: Record<string, unknown> = {}) {
  return {
    organizationId: ORG,
    replayed: false,
    metadata: metadata(),
    receipt: receipt("control.commerce_session.issue", SESSION, V4),
    delivery: { state: "available_once", handoffToken: HANDOFF, handoffExpiresAt: EXPIRES },
    ...overrides,
  };
}

// Issues/revokes echo the controller-generated mutation id (never a fixed one).
function issueResultFor(mutationId: string, overrides: Record<string, unknown> = {}) {
  return {
    organizationId: ORG,
    replayed: false,
    metadata: metadata(),
    receipt: receipt("control.commerce_session.issue", SESSION, mutationId),
    delivery: { state: "available_once", handoffToken: HANDOFF, handoffExpiresAt: EXPIRES },
    ...overrides,
  };
}

function revokeResultFor(mutationId: string, overrides: Record<string, unknown> = {}) {
  return {
    organizationId: ORG,
    replayed: false,
    metadata: metadata(SESSION, { revokedAt: REVOKED6 }),
    receipt: receipt("control.commerce_session.revoke", SESSION, mutationId),
    ...overrides,
  };
}

function fakeReads(
  role: CommerceHumanRole | null = "owner",
  organizationId: string | null = ORG,
  activeAgent: SessionAgentSelection | null = { agentId: AGENT, status: "active" },
): SessionReadCoordinator & { abortCalls: number; reloads: number } {
  const reads = {
    abortCalls: 0,
    reloads: 0,
    currentOrganizationId: () => organizationId,
    currentRole: () => role,
    currentAccountId: () => ACCOUNT_A,
    abortPendingReads() {
      reads.abortCalls += 1;
    },
    selectedActiveAgent: () => activeAgent,
    async reloadAfterCommit() {
      reads.reloads += 1;
    },
  };
  return reads;
}

function fakeAccount(initialAccountId: string | null = ACCOUNT_A, method = "passkey") {
  let currentAccountId = initialAccountId;
  let generation = 0;
  const account = {
    get generation() {
      return generation;
    },
    state:
      initialAccountId === null
        ? { status: "signed-out", csrfToken: null, session: { signedIn: false as const } }
        : {
            status: "signed-in",
            csrfToken: "csrf",
            session: { signedIn: true as const, accountId: initialAccountId, method, expiresAt: "2030-01-01T00:00:00.000Z" },
          },
    captureAccountBound() {
      return { generation, accountId: currentAccountId };
    },
    async mutate<T>(
      run: (context: {
        csrfToken: string;
        signal: AbortSignal;
        scope: { generation: number; isCurrent(): boolean };
        adopt: (data: { csrfToken: string; session: unknown }) => boolean;
      }) => Promise<T>,
    ): Promise<T> {
      if (currentAccountId === null || currentAccountId !== initialAccountId) {
        throw { failure: { kind: "account-changed" } } as unknown as Error;
      }
      return run({
        csrfToken: "csrf-from-bootstrap",
        signal: new AbortController().signal,
        scope: { generation, isCurrent: () => true },
        adopt: () => true,
      });
    },
    setAccount(id: string | null) {
      currentAccountId = id;
      generation += 1;
    },
  };
  return account as unknown as AccountFlowController & { setAccount(id: string | null): void };
}

function controllerWith(
  fetcher: typeof fetch,
  options: {
    role?: CommerceHumanRole | null;
    organizationId?: string | null;
    capability?: "enabled" | "built_disabled" | "unavailable";
    activeAgent?: SessionAgentSelection | null;
    reads?: SessionReadCoordinator;
    account?: AccountFlowController;
  } = {},
) {
  const reads =
    options.reads ??
    fakeReads(options.role ?? "owner", options.organizationId ?? ORG, options.activeAgent === undefined ? { agentId: AGENT, status: "active" } : options.activeAgent);
  const account = options.account ?? fakeAccount();
  const controller = new SessionController({
    account,
    reads,
    client: new SessionClient({ fetcher: fetcher as unknown as typeof fetch }),
    capabilityReader: async () => options.capability ?? "enabled",
  });
  return { controller, reads: reads as ReturnType<typeof fakeReads>, account };
}

describe("session role matrix", () => {
  it("allows exactly owner and operator to read and write; viewers and providers get no access", () => {
    for (const role of ["owner", "operator"] as const) {
      expect(canReadSessions(role)).toBe(true);
      expect(canWriteSessions(role)).toBe(true);
    }
    for (const role of ["viewer", "provider_admin", "provider_developer", null, "unknown"] as const) {
      expect(canReadSessions(role)).toBe(false);
      expect(canWriteSessions(role)).toBe(false);
    }
  });
});

describe("session helpers", () => {
  it("validates canonical duration 1..900 and rejects zero/sign/whitespace/fraction", () => {
    expect(canonicalDurationSeconds("1")).toBe("1");
    expect(canonicalDurationSeconds("300")).toBe("300");
    expect(canonicalDurationSeconds("900")).toBe("900");
    expect(canonicalDurationSeconds("901")).toBeNull();
    expect(canonicalDurationSeconds("0")).toBeNull();
    expect(canonicalDurationSeconds("030")).toBeNull();
    expect(canonicalDurationSeconds("-1")).toBeNull();
    expect(canonicalDurationSeconds(" 1")).toBeNull();
    expect(canonicalDurationSeconds("1.5")).toBeNull();
    expect(canonicalDurationSeconds("")).toBeNull();
    expect(canonicalDurationSeconds(null)).toBeNull();
  });

  it("bounds the cursor stack at 20", () => {
    let stack: readonly string[] = [];
    for (let index = 0; index < 25; index += 1) stack = appendSessionCursor(stack, String(index));
    expect(stack.length).toBe(20);
    expect(stack[0]).toBe("5");
    expect(stack[19]).toBe("24");
  });

  it("detects exact expiry from microsecond timestamps without truncation", () => {
    const meta = metadata() as never;
    expect(sessionMetadataExpired(meta, Date.parse("2026-01-01T00:14:59.999Z"))).toBe(false);
    expect(sessionMetadataExpired(meta, Date.parse(EXPIRES6))).toBe(true);
  });

  it("suppresses a stale session context synchronously on any context change", () => {
    const bound = { accountId: ACCOUNT_A, organizationId: ORG, role: "owner" };
    expect(suppressStaleSessionContext(bound, { accountId: ACCOUNT_A, organizationId: ORG, role: "owner" })).toBe(false);
    expect(suppressStaleSessionContext(bound, { accountId: ACCOUNT_A, organizationId: ORG_B, role: "owner" })).toBe(true);
    expect(suppressStaleSessionContext(bound, { accountId: null, organizationId: ORG, role: "owner" })).toBe(true);
    expect(suppressStaleSessionContext(bound, { accountId: ACCOUNT_A, organizationId: ORG, role: "viewer" })).toBe(true);
    const initial = renderSessionState(true, initialSessionControllerState());
    expect(initial.capability).toBe("unknown");
  });
});

describe("session controller capability gate", () => {
  it("makes no session request when the capability is built_disabled", async () => {
    const fetcher = vi.fn(async () => success({ organizationId: ORG, items: [], nextCursor: null }));
    const { controller } = controllerWith(fetcher as unknown as typeof fetch, { capability: "built_disabled" });
    await controller.initialize({ kind: "roots" });
    expect(fetcher).not.toHaveBeenCalled();
    expect(controller.state.capability).toBe("unavailable");
  });

  it("loads the list only after the capability is enabled", async () => {
    const fetcher = vi.fn(async () => success({ organizationId: ORG, items: [], nextCursor: null }));
    const { controller } = controllerWith(fetcher as unknown as typeof fetch);
    await controller.initialize({ kind: "roots" });
    expect(controller.state.capability).toBe("enabled");
    expect(controller.state.list.status).toBe("ready");
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("makes no session request for viewer, provider or recovery accounts", async () => {
    const fetcher = vi.fn(async () => success({ organizationId: ORG, items: [], nextCursor: null }));
    const viewer = controllerWith(fetcher as unknown as typeof fetch, { role: "viewer" });
    await viewer.controller.initialize({ kind: "roots" });
    expect(fetcher).not.toHaveBeenCalled();
    expect(viewer.controller.state.canRead).toBe(false);

    const provider = controllerWith(fetcher as unknown as typeof fetch, { role: "provider_admin" });
    await provider.controller.initialize({ kind: "roots" });
    expect(fetcher).not.toHaveBeenCalled();

    const recovery = controllerWith(fetcher as unknown as typeof fetch, {
      account: fakeAccount(ACCOUNT_A, "recovery"),
    });
    await recovery.controller.initialize({ kind: "roots" });
    expect(fetcher).not.toHaveBeenCalled();
  });
});

describe("session controller issue selection and reset", () => {
  it("refuses an issue for an agent that is not the current selected active agent", async () => {
    const fetcher = vi.fn(async () => success(issueResult()));
    const { controller } = controllerWith(fetcher as unknown as typeof fetch, {
      activeAgent: { agentId: AGENT, status: "active" },
    });
    await controller.initialize({ kind: "new" });
    const ok = controller.beginIssue({ subjectAgentId: AGENT_B, policyId: POLICY, durationSeconds: "300" });
    expect(ok).toBe(false);
    expect(controller.state.mutation).toMatchObject({ kind: "rejected", notice: { kind: "inactive-agent" } });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("refuses an inactive/unknown selected agent", async () => {
    const fetcher = vi.fn(async () => success(issueResult()));
    const { controller } = controllerWith(fetcher as unknown as typeof fetch, { activeAgent: null });
    await controller.initialize({ kind: "new" });
    expect(controller.beginIssue({ subjectAgentId: null, policyId: POLICY, durationSeconds: "300" })).toBe(false);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("clears the draft, secret and selection on a role change", async () => {
    const fetcher = vi.fn(async () => success(issueResult()));
    const reads = fakeReads("owner");
    const { controller } = controllerWith(fetcher as unknown as typeof fetch, { reads });
    await controller.initialize({ kind: "new" });
    expect(controller.beginIssue({ subjectAgentId: AGENT, policyId: POLICY, durationSeconds: "300" })).toBe(true);
    expect(controller.state.mutation.kind).toBe("confirming");
    (reads as unknown as { currentRole: () => string | null }).currentRole = () => "viewer";
    controller.reconcileRole("viewer");
    expect(controller.state.mutation.kind).toBe("idle");
    expect(controller.state.availableOnce).toBeNull();
    expect(controller.state.canWrite).toBe(false);
  });
});

describe("session controller one POST and original GET", () => {
  it("sends exactly one issue POST and does not resend", async () => {
    const fetcher = vi.fn(async (_input: string, init?: RequestInit) =>
      init?.method === "POST"
        ? success(issueResultFor((JSON.parse(String(init.body)) as { mutationId: string }).mutationId))
        : success({ organizationId: ORG, items: [], nextCursor: null }),
    );
    const { controller, reads } = controllerWith(fetcher as unknown as typeof fetch);
    await controller.initialize({ kind: "new" });
    controller.beginIssue({ subjectAgentId: AGENT, policyId: POLICY, durationSeconds: "300" });
    await controller.confirm();
    expect(controller.state.mutation.kind).toBe("committed");
    const posts = (fetcher.mock.calls as unknown as Array<[string, RequestInit]>).filter(
      ([, init]) => init?.method === "POST",
    );
    expect(posts).toHaveLength(1);
    expect(reads.abortCalls).toBe(1);
  });

  it("resolves an unknown outcome only by a GET with the ORIGINAL mutation id", async () => {
    let posted = "";
    const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        posted = JSON.parse(String(init.body)).mutationId as string;
        throw new Error("reset");
      }
      return success({ organizationId: ORG, mutationId: posted, status: "not_found" });
    });
    const { controller } = controllerWith(fetcher as unknown as typeof fetch);
    await controller.initialize({ kind: "new" });
    controller.beginIssue({ subjectAgentId: AGENT, policyId: POLICY, durationSeconds: "300" });
    await controller.confirm();
    expect(controller.state.mutation.kind).toBe("outcome-unknown");
    const before =
      controller.state.mutation.kind === "outcome-unknown" ? controller.state.mutation.mutationId : "";
    await controller.checkStatus();
    const posts = (fetcher.mock.calls as unknown as Array<[string, RequestInit]>).filter(
      ([, init]) => init?.method === "POST",
    );
    expect(posts).toHaveLength(1);
    const getCalls = (fetcher.mock.calls as unknown as Array<[string, RequestInit]>).filter(
      ([, init]) => init?.method === "GET",
    );
    expect(getCalls.length).toBeGreaterThanOrEqual(1);
    expect(controller.state.mutation.kind).toBe("outcome-unknown");
    expect((controller.state.mutation as { mutationId: string }).mutationId).toBe(before);
  });

  it("recovers a committed status but never the one-time secret", async () => {
    let posted = "";
    const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        posted = JSON.parse(String(init.body)).mutationId as string;
        throw new Error("reset");
      }
      if (input.includes("commerce-session-mutations")) {
        return success({
          organizationId: ORG,
          mutationId: posted,
          status: "committed",
          receipt: receipt("control.commerce_session.issue", SESSION, posted),
        });
      }
      return success({ organizationId: ORG, item: statusItem(SESSION) });
    });
    const { controller } = controllerWith(fetcher as unknown as typeof fetch);
    await controller.initialize({ kind: "new" });
    controller.beginIssue({ subjectAgentId: AGENT, policyId: POLICY, durationSeconds: "300" });
    await controller.confirm();
    await controller.checkStatus();
    expect(controller.state.mutation.kind).toBe("committed");
    expect(controller.state.availableOnce).toBeNull();
    expect(controller.state.mutation).toMatchObject({ committed: { replayed: true, availableOnce: null } });
  });
});

describe("session controller secret lifecycle", () => {
  it("exposes a fresh handoff exactly once and dismiss clears it", async () => {
    const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        return success(issueResultFor((JSON.parse(String(init.body)) as { mutationId: string }).mutationId));
      }
      return success({ organizationId: ORG, item: statusItem(SESSION) });
    });
    const { controller } = controllerWith(fetcher as unknown as typeof fetch);
    await controller.initialize({ kind: "new" });
    controller.beginIssue({ subjectAgentId: AGENT, policyId: POLICY, durationSeconds: "300" });
    await controller.confirm();
    expect(controller.state.availableOnce).toBe(HANDOFF);
    expect(controller.availableOnce).toBe(HANDOFF);
    controller.dismissSecret();
    expect(controller.state.availableOnce).toBeNull();
    expect(controller.availableOnce).toBeNull();
  });

  it("clears the secret AND every draft/id/error artifact on a context change", async () => {
    const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        return success(issueResultFor((JSON.parse(String(init.body)) as { mutationId: string }).mutationId));
      }
      return success({ organizationId: ORG, item: statusItem(SESSION) });
    });
    const reads = fakeReads("owner");
    const { controller } = controllerWith(fetcher as unknown as typeof fetch, { reads });
    await controller.initialize({ kind: "new" });
    controller.beginIssue({ subjectAgentId: AGENT, policyId: POLICY, durationSeconds: "300" });
    await controller.confirm();
    expect(controller.state.availableOnce).toBe(HANDOFF);
    controller.clear();
    expect(controller.state.availableOnce).toBeNull();
    expect(controller.state.mutation.kind).toBe("idle");
    expect(controller.state.list.status).toBe("none");
    expect(controller.state.detail.status).toBe("none");
  });

  it("clears the secret when the detail observes an expired metadata", async () => {
    const fetcher = vi.fn(async (_input: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        return success(issueResultFor((JSON.parse(String(init.body)) as { mutationId: string }).mutationId));
      }
      return success({ organizationId: ORG, item: statusItem(SESSION) });
    });
    const { controller } = controllerWith(fetcher as unknown as typeof fetch);
    await controller.initialize({ kind: "new" });
    controller.beginIssue({ subjectAgentId: AGENT, policyId: POLICY, durationSeconds: "300" });
    await controller.confirm();
    expect(controller.state.availableOnce).toBe(HANDOFF);
    controller.dismissSecret();
    expect(controller.state.availableOnce).toBeNull();
  });

  it("keeps the committed receipt when the follow-up refresh fails", async () => {
    const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        return success(issueResultFor((JSON.parse(String(init.body)) as { mutationId: string }).mutationId));
      }
      if (input.includes("commerce-sessions/")) {
        return new Response("boom", { status: 500 });
      }
      return success({ organizationId: ORG, items: [], nextCursor: null });
    });
    const reads = fakeReads("owner");
    (reads as unknown as { reloadAfterCommit: () => Promise<void> }).reloadAfterCommit = async () => {
      throw new Error("refresh failed");
    };
    const { controller } = controllerWith(fetcher as unknown as typeof fetch, { reads });
    await controller.initialize({ kind: "new" });
    controller.beginIssue({ subjectAgentId: AGENT, policyId: POLICY, durationSeconds: "300" });
    await controller.confirm();
    expect(controller.state.mutation.kind).toBe("committed");
    expect(controller.state.mutation).toMatchObject({ committed: { refreshError: true, availableOnce: HANDOFF } });
  });

  it("never writes the secret to storage, the URL or history", async () => {
    const fetcher = vi.fn(async (_input: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        return success(issueResultFor((JSON.parse(String(init.body)) as { mutationId: string }).mutationId));
      }
      return success({ organizationId: ORG, item: statusItem(SESSION) });
    });
    const storagePrototype = (globalThis as { Storage?: { prototype: object } }).Storage?.prototype ?? null;
    const setItem = storagePrototype === null ? null : vi.spyOn(storagePrototype as Storage, "setItem");
    const history = (globalThis as { window?: { history?: History } }).window?.history;
    const pushState = history === undefined ? null : vi.spyOn(history, "pushState");
    try {
      const { controller } = controllerWith(fetcher as unknown as typeof fetch);
      await controller.initialize({ kind: "new" });
      controller.beginIssue({ subjectAgentId: AGENT, policyId: POLICY, durationSeconds: "300" });
      await controller.confirm();
      expect(controller.state.availableOnce).toBe(HANDOFF);
      if (setItem !== null) expect(setItem).not.toHaveBeenCalled();
      if (pushState !== null) expect(pushState).not.toHaveBeenCalled();
    } finally {
      setItem?.mockRestore();
      pushState?.mockRestore();
    }
  });
});

describe("session controller revoke", () => {
  it("maps a structured 403 to a forbidden notice without echoing server text", async () => {
    const fetcher = vi.fn(async () => errorEnvelope("FORBIDDEN", 403));
    const { controller } = controllerWith(fetcher as unknown as typeof fetch);
    await controller.initialize({ kind: "detail", sessionId: SESSION });
    controller.beginRevoke(SESSION);
    await controller.confirm();
    expect(controller.state.mutation).toMatchObject({ kind: "rejected", notice: { kind: "forbidden" } });
    expect(JSON.stringify(controller.state)).not.toContain(COMMERCE_API_ERRORS.FORBIDDEN.message);
  });

  it("rejects a revoke receipt that binds a different session", async () => {
    const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
      if (input.includes("/revoke") && init?.method === "POST") {
        const mutationId = (JSON.parse(String(init.body)) as { mutationId: string }).mutationId;
        return success(revokeResultFor(mutationId, { receipt: receipt("control.commerce_session.revoke", SESSION_B, mutationId) }));
      }
      return success({ organizationId: ORG, item: statusItem(SESSION) });
    });
    const { controller } = controllerWith(fetcher as unknown as typeof fetch);
    await controller.initialize({ kind: "detail", sessionId: SESSION });
    controller.beginRevoke(SESSION);
    await controller.confirm();
    expect(controller.state.mutation.kind).toBe("outcome-unknown");
  });

  it("revokes the exact session and marks revoked", async () => {
    const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
      if (input.includes("/revoke") && init?.method === "POST") {
        return success(revokeResultFor((JSON.parse(String(init.body)) as { mutationId: string }).mutationId));
      }
      if (input.includes("commerce-sessions/")) {
        return success({ organizationId: ORG, item: statusItem(SESSION, "revoked", { revokedAt: REVOKED6 }) });
      }
      return success({ organizationId: ORG, items: [], nextCursor: null });
    });
    const { controller } = controllerWith(fetcher as unknown as typeof fetch);
    await controller.initialize({ kind: "detail", sessionId: SESSION });
    expect(controller.beginRevoke(SESSION)).toBe(true);
    await controller.confirm();
    expect(controller.state.mutation.kind).toBe("committed");
    const [path, init] = (fetcher.mock.calls as unknown as Array<[string, RequestInit]>).find(
      ([, opts]) => opts?.method === "POST",
    )!;
    expect(path).toContain(`/commerce-sessions/${encodeURIComponent(SESSION)}/revoke`);
    expect(init.credentials).toBe("same-origin");
  });

  it("resolves a lost revoke response only by an original-id GET and never resends", async () => {
    let postedMutationId = "";
    let posts = 0;
    const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
      if (input.includes("/revoke") && init?.method === "POST") {
        posts += 1;
        postedMutationId = (JSON.parse(String(init.body)) as { mutationId: string }).mutationId;
        throw new Error("connection reset");
      }
      if (input.includes("commerce-session-mutations")) {
        return success({ organizationId: ORG, mutationId: postedMutationId, status: "not_found" });
      }
      return success({ organizationId: ORG, item: statusItem(SESSION) });
    });
    const { controller } = controllerWith(fetcher as unknown as typeof fetch);
    await controller.initialize({ kind: "detail", sessionId: SESSION });
    controller.beginRevoke(SESSION);
    await controller.confirm();
    expect(controller.state.mutation.kind).toBe("outcome-unknown");
    const unknown = controller.state.mutation as Extract<
      typeof controller.state.mutation,
      { kind: "outcome-unknown" }
    >;
    await controller.checkStatus();
    const statusCalls = (fetcher.mock.calls as unknown as Array<[string, RequestInit]>).filter(
      ([input]) => input.includes("commerce-session-mutations"),
    );
    expect(statusCalls).toHaveLength(1);
    expect(statusCalls[0]?.[0]).toContain(encodeURIComponent(unknown.mutationId));
    expect(posts).toBe(1);
  });
});

describe("session controller expiry timer", () => {
  it("erases both raw copies at the exact source expiry and cancels cleanly", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));
    try {
      const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
        if (init?.method === "POST") {
          return success(issueResultFor((JSON.parse(String(init.body)) as { mutationId: string }).mutationId));
        }
        return success({ organizationId: ORG, item: statusItem(SESSION) });
      });
      const { controller } = controllerWith(fetcher as unknown as typeof fetch);
      await controller.initialize({ kind: "new" });
      controller.beginIssue({ subjectAgentId: AGENT, policyId: POLICY, durationSeconds: "300" });
      await controller.confirm();
      expect(controller.state.availableOnce).toBe(HANDOFF);
      expect(controller.state.mutation).toMatchObject({ committed: { availableOnce: HANDOFF } });
      // Advance to just before the 00:05 handoff expiry: the raw copy survives.
      await vi.advanceTimersByTimeAsync(4 * 60 * 1000 + 59 * 1000);
      expect(controller.state.availableOnce).toBe(HANDOFF);
      // Cross the exact expiry: BOTH synchronized copies are erased.
      await vi.advanceTimersByTimeAsync(2 * 1000);
      expect(controller.state.availableOnce).toBeNull();
      expect(controller.state.mutation).toMatchObject({ committed: { availableOnce: null } });
    } finally {
      vi.useRealTimers();
    }
  });

  it("cancels the timer on clear so a late timer cannot resurrect the secret", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));
    try {
      const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
        if (init?.method === "POST") {
          return success(issueResultFor((JSON.parse(String(init.body)) as { mutationId: string }).mutationId));
        }
        return success({ organizationId: ORG, item: statusItem(SESSION) });
      });
      const { controller } = controllerWith(fetcher as unknown as typeof fetch);
      await controller.initialize({ kind: "new" });
      controller.beginIssue({ subjectAgentId: AGENT, policyId: POLICY, durationSeconds: "300" });
      await controller.confirm();
      expect(controller.state.availableOnce).toBe(HANDOFF);
      controller.clear();
      await vi.advanceTimersByTimeAsync(10 * 60 * 1000);
      expect(controller.state.availableOnce).toBeNull();
      expect(controller.state.mutation.kind).toBe("idle");
    } finally {
      vi.useRealTimers();
    }
  });

  it("retains the secret at the truncated millisecond and clears at the exact sub-millisecond expiry", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));
    try {
      // The handoff expires 500 microseconds after 00:05:00.000Z. `Date.parse`
      // truncates to .000Z, so a millisecond-only timer would erase early; the
      // exact ISO callback must retain until the source instant.
      const handoffExpiry = "2026-01-01T00:05:00.000500Z";
      const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
        if (init?.method === "POST") {
          const mutationId = (JSON.parse(String(init.body)) as { mutationId: string }).mutationId;
          return success(
            issueResultFor(mutationId, {
              metadata: metadata(SESSION, { issuedAt: "2026-01-01T00:00:00.000500Z", expiresAt: EXPIRES6 }),
              delivery: { state: "available_once", handoffToken: HANDOFF, handoffExpiresAt: handoffExpiry },
            }),
          );
        }
        return success({ organizationId: ORG, item: statusItem(SESSION) });
      });
      const { controller } = controllerWith(fetcher as unknown as typeof fetch);
      await controller.initialize({ kind: "new" });
      controller.beginIssue({ subjectAgentId: AGENT, policyId: POLICY, durationSeconds: "300" });
      await controller.confirm();
      expect(controller.state.availableOnce).toBe(HANDOFF);
      // The timer estimate fires at the truncated .000Z instant. The exact
      // source is .000500Z, so BOTH raw copies MUST be retained and re-armed.
      await vi.advanceTimersByTimeAsync(5 * 60 * 1000);
      expect(controller.state.availableOnce).toBe(HANDOFF);
      expect(controller.state.mutation).toMatchObject({ committed: { availableOnce: HANDOFF } });
      // The next millisecond crosses the exact instant: both raw copies clear,
      // while the confirmed receipt/metadata remain (committed != recovered).
      await vi.advanceTimersByTimeAsync(1);
      expect(controller.state.availableOnce).toBeNull();
      expect(controller.state.mutation).toMatchObject({
        kind: "committed",
        committed: { availableOnce: null, metadata: { sessionId: SESSION }, replayed: false },
      });
    } finally {
      vi.useRealTimers();
    }
  });
});
