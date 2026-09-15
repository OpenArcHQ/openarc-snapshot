import {
  API_CLIENT_HEADER,
  API_MAX_RESPONSE_BYTES,
  COMMERCE_API_ERRORS,
  COMMERCE_API_SCHEMA_VERSION,
  SESSION_CAPABILITIES_PATH,
  SESSION_ROUTES,
} from "@openarc/shared";
import { describe, expect, it, vi } from "vitest";

import {
  SESSION_MAX_BODY_BYTES,
  SESSION_REQUEST_TIMEOUT_MS,
  SESSION_ROUTE_IDS,
  SessionApiError,
  SessionClient,
  readCommerceSessionsCapability,
} from "./session-client.js";

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
const POLICY = `openarc:policy:${V4}`;
const SESSION = V4;
const SESSION_B = V4_B;
const MUTATION = V4;
const ISO = "2026-01-01T00:00:00.000Z";
const EXPIRES = "2026-01-01T00:05:00.000Z";
const ISSUED = "2026-01-01T00:00:00.000000Z";
const EXPIRES6 = "2026-01-01T00:15:00.000000Z";
const HANDOFF = `oach_v1_${"A".repeat(42)}A`;
const IDEMPOTENCY = `${"A".repeat(42)}A`;

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
    issuedAt: ISSUED,
    expiresAt: EXPIRES6,
    exchangedAt: null,
    revokedAt: null,
    ...overrides,
  };
}

function statusItem(sessionId = SESSION, status = "handoff_pending", overrides: Record<string, unknown> = {}) {
  return { metadata: metadata(sessionId, overrides), status };
}

function receipt(operation: string, resourceId: string, mutationId = MUTATION) {
  return {
    mutationId,
    operation,
    resourceType: "commerce_session",
    resourceId,
    committedAt: ISO,
  };
}

function issueResult(overrides: Record<string, unknown> = {}) {
  return {
    organizationId: ORG,
    replayed: false,
    metadata: metadata(),
    receipt: receipt("control.commerce_session.issue", SESSION, MUTATION),
    delivery: { state: "available_once", handoffToken: HANDOFF, handoffExpiresAt: EXPIRES },
    ...overrides,
  };
}

function revokeResult(overrides: Record<string, unknown> = {}) {
  return {
    organizationId: ORG,
    replayed: false,
    metadata: metadata(SESSION, { revokedAt: EXPECTED_REVOKED_AT }),
    receipt: receipt("control.commerce_session.revoke", SESSION, MUTATION),
    ...overrides,
  };
}

const EXPECTED_REVOKED_AT = "2026-01-01T00:06:00.000000Z";

function clientWith(fetcher: typeof fetch) {
  return new SessionClient({ fetcher: fetcher as unknown as typeof fetch });
}

describe("session client route registry", () => {
  it("exposes exactly the five frozen browser commerce_session_management route ids", () => {
    const expected = SESSION_ROUTES.filter((route) => route.family === "commerce_session_management")
      .map((route) => route.id)
      .sort();
    expect([...SESSION_ROUTE_IDS].sort()).toEqual(expected);
    expect(SESSION_ROUTE_IDS).toHaveLength(5);
  });
});

describe("session client reads", () => {
  it("sends a relative same-origin paginated GET with only the browser marker", async () => {
    const fetcher = vi.fn(async () => success({ organizationId: ORG, items: [], nextCursor: null }));
    const page = await clientWith(fetcher as unknown as typeof fetch).listSessions(
      { organizationId: ORG },
      new AbortController().signal,
    );
    expect(page).toEqual({ organizationId: ORG, items: [], nextCursor: null });
    expect(fetcher).toHaveBeenCalledWith(
      `/v2/control/organizations/${encodeURIComponent(ORG)}/commerce-sessions?limit=25`,
      {
        method: "GET",
        headers: { "X-OpenArc-Client": API_CLIENT_HEADER, Accept: "application/json" },
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        referrerPolicy: "no-referrer",
        signal: expect.any(AbortSignal),
      },
    );
  });

  it("sends no Authorization, no bearer and no machine credential on a read", async () => {
    const fetcher = vi.fn(async () => success({ organizationId: ORG, items: [], nextCursor: null }));
    await clientWith(fetcher as unknown as typeof fetch).listSessions(
      { organizationId: ORG },
      new AbortController().signal,
    );
    const [, init] = (fetcher.mock.calls as unknown as Array<[string, RequestInit]>)[0]!;
    const headers = (init.headers ?? {}) as Record<string, string>;
    expect(headers.Authorization).toBeUndefined();
    expect(headers["Proxy-Authorization"]).toBeUndefined();
    expect(init.body).toBeUndefined();
    expect(init.credentials).toBe("same-origin");
  });

  it("lists with an accepted canonical afterSessionId cursor and limit 50", async () => {
    const fetcher = vi.fn(async () =>
      success({ organizationId: ORG, items: [], nextCursor: null }),
    );
    await clientWith(fetcher as unknown as typeof fetch).listSessions(
      { organizationId: ORG, afterSessionId: SESSION_B, limit: 50 },
      new AbortController().signal,
    );
    const [path] = (fetcher.mock.calls as unknown as Array<[string]>)[0]!;
    expect(path).toBe(
      `/v2/control/organizations/${encodeURIComponent(ORG)}/commerce-sessions?afterSessionId=${encodeURIComponent(SESSION_B)}&limit=50`,
    );
  });

  it("rejects an invalid limit, cursor, org or session id before any fetch", async () => {
    const fetcher = vi.fn();
    await expect(
      clientWith(fetcher as unknown as typeof fetch).listSessions(
        { organizationId: ORG, limit: 51 },
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    await expect(
      clientWith(fetcher as unknown as typeof fetch).listSessions(
        { organizationId: ORG, afterSessionId: "not-a-session" },
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    await expect(
      clientWith(fetcher as unknown as typeof fetch).listSessions(
        { organizationId: "../evil" },
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("rejects a mismatched page organization", async () => {
    const fetcher = vi.fn(async () => success({ organizationId: ORG_B, items: [], nextCursor: null }));
    await expect(
      clientWith(fetcher as unknown as typeof fetch).listSessions(
        { organizationId: ORG },
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });

  it("rejects a continuation page whose first row is not past the cursor", async () => {
    const fetcher = vi.fn(async () =>
      success({ organizationId: ORG, items: [statusItem(SESSION)], nextCursor: null }),
    );
    await expect(
      clientWith(fetcher as unknown as typeof fetch).listSessions(
        { organizationId: ORG, afterSessionId: SESSION_B },
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });

  it("rejects an oversized page relative to the requested limit", async () => {
    const fetcher = vi.fn(async () =>
      success({ organizationId: ORG, items: [statusItem(SESSION), statusItem(SESSION_B)], nextCursor: null }),
    );
    await expect(
      clientWith(fetcher as unknown as typeof fetch).listSessions(
        { organizationId: ORG, limit: 1 },
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });

  it("reads a session status and binds the requested session id", async () => {
    const fetcher = vi.fn(async () =>
      success({ organizationId: ORG, item: statusItem(SESSION) }),
    );
    const status = await clientWith(fetcher as unknown as typeof fetch).readSession(
      { organizationId: ORG, sessionId: SESSION },
      new AbortController().signal,
    );
    expect(status.item?.metadata.sessionId).toBe(SESSION);
    const [path] = (fetcher.mock.calls as unknown as Array<[string]>)[0]!;
    expect(path).toBe(
      `/v2/control/organizations/${encodeURIComponent(ORG)}/commerce-sessions/${encodeURIComponent(SESSION)}`,
    );
  });

  it("accepts a truthful null status item and rejects a foreign session binding", async () => {
    const empty = vi.fn(async () => success({ organizationId: ORG, item: null }));
    const status = await clientWith(empty as unknown as typeof fetch).readSession(
      { organizationId: ORG, sessionId: SESSION },
      new AbortController().signal,
    );
    expect(status.item).toBeNull();

    const foreign = vi.fn(async () => success({ organizationId: ORG, item: statusItem(SESSION_B) }));
    await expect(
      clientWith(foreign as unknown as typeof fetch).readSession(
        { organizationId: ORG, sessionId: SESSION },
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });

  it("maps HTTP failures without reflecting server text", async () => {
    const cases: Array<[number, string]> = [
      [400, "validation"],
      [401, "unauthenticated"],
      [403, "forbidden"],
      [404, "not-found"],
      [409, "conflict"],
      [429, "unavailable"],
      [503, "unavailable"],
    ];
    for (const [status, kind] of cases) {
      const fetcher = vi.fn(async () => new Response("nope", { status }));
      await expect(
        clientWith(fetcher as unknown as typeof fetch).listSessions(
          { organizationId: ORG },
          new AbortController().signal,
        ),
      ).rejects.toMatchObject({ failure: { kind } });
    }
  });

  it("maps a structured error code and never echoes the message", async () => {
    const fetcher = vi.fn(async () => errorEnvelope("FORBIDDEN", 403));
    const error = await clientWith(fetcher as unknown as typeof fetch)
      .listSessions({ organizationId: ORG }, new AbortController().signal)
      .catch((cause: unknown) => cause);
    expect(error).toBeInstanceOf(SessionApiError);
    expect((error as SessionApiError).message).toBe("forbidden");
    expect(JSON.stringify(error)).not.toContain(COMMERCE_API_ERRORS.FORBIDDEN.message);
  });

  it("aborts a read on an already-aborted signal without calling fetch", async () => {
    const fetcher = vi.fn();
    const controller = new AbortController();
    controller.abort();
    await expect(
      clientWith(fetcher as unknown as typeof fetch).listSessions(
        { organizationId: ORG },
        controller.signal,
      ),
    ).rejects.toMatchObject({ failure: { kind: "aborted" } });
    expect(fetcher).not.toHaveBeenCalled();
  });
});

describe("session client writes", () => {
  it("issues with CSRF and idempotency headers and accepts a DB-generated canonical session", async () => {
    const fetcher = vi.fn(async () => success(issueResult()));
    const result = await clientWith(fetcher as unknown as typeof fetch).issue({
      organizationId: ORG,
      csrfToken: "csrf",
      idempotencyKey: IDEMPOTENCY,
      signal: new AbortController().signal,
      body: { mutationId: MUTATION, subjectAgentId: AGENT, policyId: POLICY, durationSeconds: "300" },
    });
    expect(result.receipt.resourceId).toBe(SESSION);
    expect(result.delivery).toEqual({ state: "available_once", handoffToken: HANDOFF, handoffExpiresAt: EXPIRES });
    const [path, init] = (fetcher.mock.calls as unknown as Array<[string, RequestInit]>)[0]!;
    expect(path).toBe(`/v2/control/organizations/${encodeURIComponent(ORG)}/commerce-sessions`);
    const headers = init.headers as Record<string, string>;
    expect(headers["X-OpenArc-CSRF"]).toBe("csrf");
    expect(headers["Idempotency-Key"]).toBe(IDEMPOTENCY);
    expect(headers["X-OpenArc-Client"]).toBe(API_CLIENT_HEADER);
    expect(init.credentials).toBe("same-origin");
    const body = JSON.parse(String(init.body)) as { durationSeconds?: string };
    expect(body.durationSeconds).toBe("300");
  });

  it("omits durationSeconds entirely when absent so the server default applies", async () => {
    const fetcher = vi.fn(async () => success(issueResult()));
    await clientWith(fetcher as unknown as typeof fetch).issue({
      organizationId: ORG,
      csrfToken: "csrf",
      idempotencyKey: IDEMPOTENCY,
      signal: new AbortController().signal,
      body: { mutationId: MUTATION, subjectAgentId: AGENT, policyId: POLICY },
    });
    const [, init] = (fetcher.mock.calls as unknown as Array<[string, RequestInit]>)[0]!;
    expect(JSON.parse(String(init.body))).not.toHaveProperty("durationSeconds");
  });

  it("never accepts a raw secret in a replay delivery and rejects a replay carrying one", async () => {
    const noSecret = vi.fn(async () =>
      success(issueResult({ replayed: true, delivery: { state: "not_replayable" } })),
    );
    const result = await clientWith(noSecret as unknown as typeof fetch).issue({
      organizationId: ORG,
      csrfToken: "csrf",
      idempotencyKey: IDEMPOTENCY,
      signal: new AbortController().signal,
      body: { mutationId: MUTATION, subjectAgentId: AGENT, policyId: POLICY },
    });
    expect(result.replayed).toBe(true);
    expect(result.delivery).toEqual({ state: "not_replayable" });
    expect(JSON.stringify(result)).not.toContain("oach_v1_");

    const secretOnReplay = vi.fn(async () =>
      success(issueResult({ replayed: true, delivery: { state: "available_once", handoffToken: HANDOFF, handoffExpiresAt: EXPIRES } })),
    );
    await expect(
      clientWith(secretOnReplay as unknown as typeof fetch).issue({
        organizationId: ORG,
        csrfToken: "csrf",
        idempotencyKey: IDEMPOTENCY,
        signal: new AbortController().signal,
        body: { mutationId: MUTATION, subjectAgentId: AGENT, policyId: POLICY },
      }),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });

  it("rejects a malformed duration, empty CSRF and a bad idempotency key before send", async () => {
    const fetcher = vi.fn();
    const common = {
      organizationId: ORG,
      csrfToken: "csrf",
      idempotencyKey: IDEMPOTENCY,
      signal: new AbortController().signal,
    };
    await expect(
      clientWith(fetcher as unknown as typeof fetch).issue({
        ...common,
        body: { mutationId: MUTATION, subjectAgentId: AGENT, policyId: POLICY, durationSeconds: "0" },
      }),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    await expect(
      clientWith(fetcher as unknown as typeof fetch).issue({
        ...common,
        csrfToken: "",
        body: { mutationId: MUTATION, subjectAgentId: AGENT, policyId: POLICY },
      }),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    await expect(
      clientWith(fetcher as unknown as typeof fetch).issue({
        ...common,
        idempotencyKey: "short",
        body: { mutationId: MUTATION, subjectAgentId: AGENT, policyId: POLICY },
      }),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("rejects an oversized body before fetch", async () => {
    const fetcher = vi.fn();
    await expect(
      clientWith(fetcher as unknown as typeof fetch).issue({
        organizationId: ORG,
        csrfToken: "csrf",
        idempotencyKey: IDEMPOTENCY,
        signal: new AbortController().signal,
        body: {
          mutationId: MUTATION,
          subjectAgentId: AGENT,
          policyId: POLICY,
          durationSeconds: "x".repeat(SESSION_MAX_BODY_BYTES),
        },
      }),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("reports outcome-unknown for a transport failure after send and a 5xx", async () => {
    const network = vi.fn(async () => {
      throw new Error("reset");
    });
    await expect(
      clientWith(network as unknown as typeof fetch).issue({
        organizationId: ORG,
        csrfToken: "csrf",
        idempotencyKey: IDEMPOTENCY,
        signal: new AbortController().signal,
        body: { mutationId: MUTATION, subjectAgentId: AGENT, policyId: POLICY },
      }),
    ).rejects.toMatchObject({ failure: { kind: "outcome-unknown" } });
    const server = vi.fn(async () => new Response("boom", { status: 500 }));
    await expect(
      clientWith(server as unknown as typeof fetch).issue({
        organizationId: ORG,
        csrfToken: "csrf",
        idempotencyKey: IDEMPOTENCY,
        signal: new AbortController().signal,
        body: { mutationId: MUTATION, subjectAgentId: AGENT, policyId: POLICY },
      }),
    ).rejects.toMatchObject({ failure: { kind: "outcome-unknown" } });
  });

  it("revokes the exact session with a bound receipt and never echoes the secret", async () => {
    const fetcher = vi.fn(async () => success(revokeResult()));
    const result = await clientWith(fetcher as unknown as typeof fetch).revoke({
      organizationId: ORG,
      sessionId: SESSION,
      csrfToken: "csrf",
      idempotencyKey: IDEMPOTENCY,
      signal: new AbortController().signal,
      body: { mutationId: MUTATION },
    });
    expect(result.receipt.resourceId).toBe(SESSION);
    const [path] = (fetcher.mock.calls as unknown as Array<[string]>)[0]!;
    expect(path).toBe(
      `/v2/control/organizations/${encodeURIComponent(ORG)}/commerce-sessions/${encodeURIComponent(SESSION)}/revoke`,
    );
    expect(JSON.stringify(result)).not.toContain("oacs_v1_");
    expect(JSON.stringify(result)).not.toContain("oach_v1_");
  });

  it("rejects a revoke receipt for a different canonical session", async () => {
    const fetcher = vi.fn(async () =>
      success(revokeResult({ receipt: receipt("control.commerce_session.revoke", SESSION_B, MUTATION) })),
    );
    await expect(
      clientWith(fetcher as unknown as typeof fetch).revoke({
        organizationId: ORG,
        sessionId: SESSION,
        csrfToken: "csrf",
        idempotencyKey: IDEMPOTENCY,
        signal: new AbortController().signal,
        body: { mutationId: MUTATION },
      }),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });
});

describe("session mutation status", () => {
  it("reads a committed status by the original mutation id and binds operation/resource", async () => {
    const fetcher = vi.fn(async () =>
      success({
        organizationId: ORG,
        mutationId: MUTATION,
        status: "committed",
        receipt: receipt("control.commerce_session.revoke", SESSION, MUTATION),
      }),
    );
    const status = await clientWith(fetcher as unknown as typeof fetch).readMutationStatus({
      organizationId: ORG,
      mutationId: MUTATION,
      operation: "control.commerce_session.revoke",
      expectedResourceId: SESSION,
      signal: new AbortController().signal,
    });
    expect(status.status).toBe("committed");
    const [path] = (fetcher.mock.calls as unknown as Array<[string]>)[0]!;
    expect(path).toBe(
      `/v2/control/organizations/${encodeURIComponent(ORG)}/commerce-session-mutations/${MUTATION}`,
    );
  });

  it("accepts a truthful not_found status with no successor fiction", async () => {
    const fetcher = vi.fn(async () => success({ organizationId: ORG, mutationId: MUTATION, status: "not_found" }));
    const status = await clientWith(fetcher as unknown as typeof fetch).readMutationStatus({
      organizationId: ORG,
      mutationId: MUTATION,
      operation: "control.commerce_session.revoke",
      expectedResourceId: SESSION,
      signal: new AbortController().signal,
    });
    expect(status.status).toBe("not_found");
  });

  it("binds the outer organizationId and mutationId on BOTH statuses", async () => {
    const request = {
      organizationId: ORG,
      mutationId: MUTATION,
      operation: "control.commerce_session.revoke" as const,
      expectedResourceId: SESSION,
      signal: new AbortController().signal,
    };
    const foreignOrg = vi.fn(async () =>
      success({ organizationId: ORG_B, mutationId: MUTATION, status: "not_found" }),
    );
    await expect(
      clientWith(foreignOrg as unknown as typeof fetch).readMutationStatus(request),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });

    const wrongMutation = vi.fn(async () =>
      success({ organizationId: ORG, mutationId: V4_B, status: "not_found" }),
    );
    await expect(
      clientWith(wrongMutation as unknown as typeof fetch).readMutationStatus(request),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });

    const wrongOp = vi.fn(async () =>
      success({
        organizationId: ORG,
        mutationId: MUTATION,
        status: "committed",
        receipt: receipt("control.commerce_session.issue", SESSION, MUTATION),
      }),
    );
    await expect(
      clientWith(wrongOp as unknown as typeof fetch).readMutationStatus(request),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });
});

describe("session credentialless capability transport", () => {
  it("omits credentials and sends no browser marker", async () => {
    const frozen = await import("@openarc/shared");
    const full = {
      ...frozen.SESSION_CAPABILITY_MANIFEST,
      capabilities: frozen.SESSION_CAPABILITY_MANIFEST.capabilities.map((entry) => ({
        ...entry,
        state: "enabled",
      })),
      routes: frozen.SESSION_ROUTES.map((route) => ({ ...route })),
    };
    const fetcher = vi.fn(async () => success(full));
    const state = await readCommerceSessionsCapability(
      new AbortController().signal,
      fetcher as unknown as typeof fetch,
    );
    expect(state).toBe("enabled");
    expect(fetcher).toHaveBeenCalledWith(SESSION_CAPABILITIES_PATH, {
      method: "GET",
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: expect.any(AbortSignal),
    });
  });

  it("returns built_disabled and unavailable truthfully", async () => {
    const frozen = await import("@openarc/shared");
    for (const expectedState of ["built_disabled", "unavailable"] as const) {
      const full = {
        ...frozen.SESSION_CAPABILITY_MANIFEST,
        capabilities: frozen.SESSION_CAPABILITY_MANIFEST.capabilities.map((entry) => ({
          ...entry,
          state: expectedState,
        })),
        routes: frozen.SESSION_ROUTES.map((route) => ({ ...route })),
      };
      const fetcher = vi.fn(async () => success(full));
      const state = await readCommerceSessionsCapability(
        new AbortController().signal,
        fetcher as unknown as typeof fetch,
      );
      expect(state).toBe(expectedState);
    }
  });
});

function stalledBodyResponse(firstChunk = "{", status = 200): Response {
  const encoder = new TextEncoder();
  return new Response(
    new ReadableStream<Uint8Array>({
      start(controller) {
        if (firstChunk.length > 0) controller.enqueue(encoder.encode(firstChunk));
      },
    }),
    { status, headers: { "content-type": "application/json" } },
  );
}

function bodyOfBytes(bytes: Uint8Array, status = 200): Response {
  return new Response(
    new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(bytes);
        controller.close();
      },
    }),
    { status, headers: { "content-type": "application/json" } },
  );
}

describe("session client total transport deadline (headers + body)", () => {
  it("times a stalled GET body out as unavailable, never stuck loading", async () => {
    vi.useFakeTimers();
    try {
      const fetcher = vi.fn(async () => stalledBodyResponse());
      const promise = clientWith(fetcher as unknown as typeof fetch).listSessions(
        { organizationId: ORG },
        new AbortController().signal,
      );
      const assertion = expect(promise).rejects.toMatchObject({ failure: { kind: "unavailable" } });
      await vi.advanceTimersByTimeAsync(SESSION_REQUEST_TIMEOUT_MS + 1);
      await assertion;
    } finally {
      vi.useRealTimers();
    }
  });

  it("times a stalled SENT write body out as outcome-unknown", async () => {
    vi.useFakeTimers();
    try {
      const fetcher = vi.fn(async () => stalledBodyResponse());
      const promise = clientWith(fetcher as unknown as typeof fetch).issue({
        organizationId: ORG,
        csrfToken: "csrf",
        idempotencyKey: IDEMPOTENCY,
        signal: new AbortController().signal,
        body: { mutationId: MUTATION, subjectAgentId: AGENT, policyId: POLICY },
      });
      const assertion = expect(promise).rejects.toMatchObject({ failure: { kind: "outcome-unknown" } });
      await vi.advanceTimersByTimeAsync(SESSION_REQUEST_TIMEOUT_MS + 1);
      await assertion;
    } finally {
      vi.useRealTimers();
    }
  });

  it("keeps the 64KiB streamed-body bound", async () => {
    const encoder = new TextEncoder();
    const oversized = bodyOfBytes(encoder.encode(`"${"x".repeat(API_MAX_RESPONSE_BYTES)}"`));
    await expect(
      clientWith((async () => oversized) as unknown as typeof fetch).listSessions(
        { organizationId: ORG },
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });
});
