import {
  API_CLIENT_HEADER,
  API_MAX_RESPONSE_BYTES,
  COMMERCE_API_ERRORS,
  COMMERCE_API_SCHEMA_VERSION,
  CONTROL_CAPABILITIES_PATH,
  CONTROL_ROUTES,
} from "@openarc/shared";
import { describe, expect, it, vi } from "vitest";

import {
  POLICY_MAX_BODY_BYTES,
  POLICY_REQUEST_TIMEOUT_MS,
  POLICY_ROUTE_IDS,
  PolicyApiError,
  PolicyClient,
  readPolicyManagementCapability,
} from "./policy-client.js";

const META = {
  schemaVersion: COMMERCE_API_SCHEMA_VERSION,
  requestId: "018f47a2-3b4c-7def-8123-456789abcdef",
  buildSha: "0123456789abcdef0123456789abcdef01234567",
};

const V4 = "12345678-1234-4234-8123-123456789abc";
const V4_B = "87654321-4321-4321-b123-abcdefabcdef";
const ORG = `openarc:org:${V4}`;
const ORG_B = `openarc:org:${V4_B}`;
const POLICY = `openarc:policy:${V4}`;
const POLICY_B = `openarc:policy:${V4_B}`;
const AGENT = `openarc:agent:${V4}`;
const ISO = "2026-01-01T00:00:00.000Z";
const DIGEST = `sha256:${"a".repeat(64)}`;
const MUTATION = V4;
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

function content(overrides: Record<string, unknown> = {}) {
  return {
    organizationId: ORG,
    subjectAgentId: AGENT,
    networkId: "eip155:5042002",
    asset: "USDC",
    representation: "erc20",
    decimals: 6,
    perActionLimit: "1000000",
    rollingLimit: null,
    rollingWindowSeconds: null,
    feeLimit: "10000",
    allowedProviderIds: [],
    allowedListingIds: [],
    approval: { mode: "none", threshold: null, separateApprover: false },
    expiresAt: null,
    ...overrides,
  };
}

function root(policyId = POLICY, currentRevision = "1", overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: "openarc.control.policy-root.v1",
    policyId,
    organizationId: ORG,
    subjectAgentId: AGENT,
    currentRevision,
    status: "active",
    createdAt: ISO,
    updatedAt: ISO,
    ...overrides,
  };
}

function revision(revisionNumber = "1", overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: "openarc.control.policy.v1",
    policyId: POLICY,
    revision: revisionNumber,
    ...content(),
    createdAt: ISO,
    digest: DIGEST,
    ...overrides,
  };
}

function summary(revisionNumber = "1", overrides: Record<string, unknown> = {}) {
  return {
    policyId: POLICY,
    organizationId: ORG,
    subjectAgentId: AGENT,
    revision: revisionNumber,
    digest: DIGEST,
    createdAt: ISO,
    expiresAt: null,
    ...overrides,
  };
}

function receipt(operation: string, resourceId: string, mutationId = MUTATION) {
  const resourceType =
    operation === "control.policy.create"
      ? "budget_policy"
      : operation === "control.policy.revision.create"
        ? "budget_policy_revision"
        : "budget_policy";
  return { mutationId, operation, resourceType, resourceId, committedAt: ISO };
}

function mutationResult(operation: string, resourceId: string, mutationId = MUTATION) {
  return { organizationId: ORG, replayed: false, receipt: receipt(operation, resourceId, mutationId) };
}

function clientWith(fetcher: typeof fetch) {
  return new PolicyClient({ fetcher: fetcher as unknown as typeof fetch });
}

describe("policy client route registry", () => {
  it("exposes exactly the ten frozen policy_management route ids", () => {
    const expected = CONTROL_ROUTES.filter((route) => route.family === "policy_management")
      .map((route) => route.id)
      .sort();
    expect([...POLICY_ROUTE_IDS].sort()).toEqual(expected);
    expect(POLICY_ROUTE_IDS).toHaveLength(10);
  });
});

describe("policy client reads", () => {
  it("sends a relative same-origin paginated GET with only the browser marker", async () => {
    const fetcher = vi.fn(async () => success({ organizationId: ORG, items: [], nextCursor: null }));
    const page = await clientWith(fetcher as unknown as typeof fetch).listRoots(
      { organizationId: ORG },
      new AbortController().signal,
    );
    expect(page).toEqual({ organizationId: ORG, items: [], nextCursor: null });
    expect(fetcher).toHaveBeenCalledWith(
      `/v2/control/organizations/${encodeURIComponent(ORG)}/policies?limit=25`,
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

  it("rejects a mismatched page organization", async () => {
    const fetcher = vi.fn(async () => success({ organizationId: ORG_B, items: [], nextCursor: null }));
    await expect(
      clientWith(fetcher as unknown as typeof fetch).listRoots(
        { organizationId: ORG },
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });

  it("encodes a canonical policy id exactly once and never a freeform path", async () => {
    const fetcher = vi.fn(async () =>
      success({ organizationId: ORG, policyId: POLICY, item: null }),
    );
    await clientWith(fetcher as unknown as typeof fetch).readRoot(
      { organizationId: ORG, policyId: POLICY },
      new AbortController().signal,
    );
    const [path] = (fetcher.mock.calls as unknown as Array<[string]>)[0]!;
    expect(path).toBe(
      `/v2/control/organizations/${encodeURIComponent(ORG)}/policies/${encodeURIComponent(POLICY)}`,
    );
    await expect(
      clientWith(fetcher as unknown as typeof fetch).readRoot(
        { organizationId: ORG, policyId: "../evil" },
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
  });

  it("lists revisions with an ascending afterRevision cursor", async () => {
    const fetcher = vi.fn(async () =>
      success({ organizationId: ORG, policyId: POLICY, items: [], nextCursor: null }),
    );
    await clientWith(fetcher as unknown as typeof fetch).listHistory(
      { organizationId: ORG, policyId: POLICY, afterRevision: "10", limit: 50 },
      new AbortController().signal,
    );
    const [path] = (fetcher.mock.calls as unknown as Array<[string]>)[0]!;
    expect(path).toBe(
      `/v2/control/organizations/${encodeURIComponent(ORG)}/policies/${encodeURIComponent(POLICY)}/revisions?afterRevision=10&limit=50`,
    );
  });

  it("reads a full revision detail and rejects a mismatched revision binding", async () => {
    const ok = vi.fn(async () =>
      success({ organizationId: ORG, policyId: POLICY, revision: "2", item: revision("2") }),
    );
    const detail = await clientWith(ok as unknown as typeof fetch).readRevision(
      { organizationId: ORG, policyId: POLICY, revision: "2" },
      new AbortController().signal,
    );
    expect(detail.revision).toBe("2");
    const bad = vi.fn(async () =>
      success({ organizationId: ORG, policyId: POLICY, revision: "3", item: revision("3") }),
    );
    await expect(
      clientWith(bad as unknown as typeof fetch).readRevision(
        { organizationId: ORG, policyId: POLICY, revision: "2" },
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
      [503, "unavailable"],
    ];
    for (const [status, kind] of cases) {
      const fetcher = vi.fn(async () => new Response("nope", { status }));
      await expect(
        clientWith(fetcher as unknown as typeof fetch).listRoots(
          { organizationId: ORG },
          new AbortController().signal,
        ),
      ).rejects.toMatchObject({ failure: { kind } });
    }
  });

  it("maps a structured error code and never echoes the message", async () => {
    const fetcher = vi.fn(async () => errorEnvelope("FORBIDDEN", 403));
    const error = await clientWith(fetcher as unknown as typeof fetch)
      .listRoots({ organizationId: ORG }, new AbortController().signal)
      .catch((cause: unknown) => cause);
    expect(error).toBeInstanceOf(PolicyApiError);
    expect((error as PolicyApiError).message).toBe("forbidden");
    expect(JSON.stringify(error)).not.toContain(COMMERCE_API_ERRORS.FORBIDDEN.message);
  });

  it("aborts a read on an already-aborted signal without calling fetch", async () => {
    const fetcher = vi.fn();
    const controller = new AbortController();
    controller.abort();
    await expect(
      clientWith(fetcher as unknown as typeof fetch).listRoots(
        { organizationId: ORG },
        controller.signal,
      ),
    ).rejects.toMatchObject({ failure: { kind: "aborted" } });
    expect(fetcher).not.toHaveBeenCalled();
  });
});

describe("policy client input and page bindings", () => {
  it("rejects an invalid afterRevision and an invalid limit before any fetch", async () => {
    const fetcher = vi.fn();
    await expect(
      clientWith(fetcher as unknown as typeof fetch).listHistory(
        { organizationId: ORG, policyId: POLICY, afterRevision: "01" },
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    await expect(
      clientWith(fetcher as unknown as typeof fetch).listRoots(
        { organizationId: ORG, limit: 51 },
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("rejects an oversized page relative to the requested limit", async () => {
    const fetcher = vi.fn(async () =>
      success({ organizationId: ORG, items: [root(POLICY_B), root(POLICY)], nextCursor: null }),
    );
    await expect(
      clientWith(fetcher as unknown as typeof fetch).listRoots(
        { organizationId: ORG, limit: 1 },
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });

  it("rejects a continuation page whose first row is not past the cursor", async () => {
    const fetcher = vi.fn(async () =>
      success({ organizationId: ORG, items: [root(POLICY)], nextCursor: null }),
    );
    await expect(
      clientWith(fetcher as unknown as typeof fetch).listRoots(
        { organizationId: ORG, afterPolicyId: POLICY_B },
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });

  it("rejects a stale revision cursor", async () => {
    const fetcher = vi.fn(async () =>
      success({ organizationId: ORG, policyId: POLICY, items: [summary("1")], nextCursor: null }),
    );
    await expect(
      clientWith(fetcher as unknown as typeof fetch).listHistory(
        { organizationId: ORG, policyId: POLICY, afterRevision: "10" },
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });
});

describe("policy client writes", () => {
  it("sends a create with CSRF and idempotency headers and binds the canonical policy resource", async () => {
    const fetcher = vi.fn(async () =>
      success(mutationResult("control.policy.create", POLICY, MUTATION)),
    );
    const result = await clientWith(fetcher as unknown as typeof fetch).createRevision({
      organizationId: ORG,
      csrfToken: "csrf",
      idempotencyKey: IDEMPOTENCY,
      signal: new AbortController().signal,
      body: { mutationId: MUTATION, content: content() },
    });
    expect(result.receipt.resourceId).toBe(POLICY);
    const [path, init] = (fetcher.mock.calls as unknown as Array<[string, RequestInit]>)[0]!;
    expect(path).toBe(`/v2/control/organizations/${encodeURIComponent(ORG)}/policies`);
    expect(init.method).toBe("POST");
    const headers = init.headers as Record<string, string>;
    expect(headers["X-OpenArc-CSRF"]).toBe("csrf");
    expect(headers["Idempotency-Key"]).toBe(IDEMPOTENCY);
    expect(headers["X-OpenArc-Client"]).toBe(API_CLIENT_HEADER);
    expect(init.credentials).toBe("same-origin");
    expect(init.redirect).toBe("error");
  });

  it("accepts a DB-generated canonical policy resource and rejects a non-canonical one", async () => {
    // A canonical `openarc:policy:<uuid>` resource generated by the database is
    // accepted even though it is unrelated to the mutation id.
    const canonical = vi.fn(async () =>
      success(mutationResult("control.policy.create", POLICY_B, MUTATION)),
    );
    const result = await clientWith(canonical as unknown as typeof fetch).createRevision({
      organizationId: ORG,
      csrfToken: "csrf",
      idempotencyKey: IDEMPOTENCY,
      signal: new AbortController().signal,
      body: { mutationId: MUTATION, content: content() },
    });
    expect(result.receipt.resourceId).toBe(POLICY_B);

    // A non-canonical resource id is rejected by the strict wire schema.
    const nonCanonical = vi.fn(async () =>
      success(mutationResult("control.policy.create", `openarc:policy:${MUTATION.toUpperCase()}`, MUTATION)),
    );
    await expect(
      clientWith(nonCanonical as unknown as typeof fetch).createRevision({
        organizationId: ORG,
        csrfToken: "csrf",
        idempotencyKey: IDEMPOTENCY,
        signal: new AbortController().signal,
        body: { mutationId: MUTATION, content: content() },
      }),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });

  it("appends with expectedRevision and binds policyId@(expectedRevision+1)", async () => {
    const fetcher = vi.fn(async () =>
      success(mutationResult("control.policy.revision.create", `${POLICY}@11`, MUTATION)),
    );
    const result = await clientWith(fetcher as unknown as typeof fetch).appendRevision({
      organizationId: ORG,
      policyId: POLICY,
      csrfToken: "csrf",
      idempotencyKey: IDEMPOTENCY,
      signal: new AbortController().signal,
      body: { mutationId: MUTATION, expectedRevision: "10", expectedUpdatedAt: ISO, content: content() },
    });
    expect(result.receipt.resourceId).toBe(`${POLICY}@11`);
    const [path, init] = (fetcher.mock.calls as unknown as Array<[string, RequestInit]>)[0]!;
    expect(path).toBe(
      `/v2/control/organizations/${encodeURIComponent(ORG)}/policies/${encodeURIComponent(POLICY)}/revisions`,
    );
    const body = JSON.parse(String(init.body)) as { expectedRevision: string };
    expect(body.expectedRevision).toBe("10");
  });

  it("rejects an append receipt for the wrong successor revision", async () => {
    const fetcher = vi.fn(async () =>
      success(mutationResult("control.policy.revision.create", `${POLICY}@9`, MUTATION)),
    );
    await expect(
      clientWith(fetcher as unknown as typeof fetch).appendRevision({
        organizationId: ORG,
        policyId: POLICY,
        csrfToken: "csrf",
        idempotencyKey: IDEMPOTENCY,
        signal: new AbortController().signal,
        body: { mutationId: MUTATION, expectedRevision: "10", expectedUpdatedAt: ISO, content: content() },
      }),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });

  it.each([
    ["pause", "control.policy.pause"],
    ["resume", "control.policy.resume"],
    ["revoke", "control.policy.revoke"],
  ] as const)("sends a %s transition with the exact CAS root", async (op, operation) => {
    const fetcher = vi.fn(async () =>
      success(mutationResult(operation, POLICY, MUTATION)),
    );
    const client = clientWith(fetcher as unknown as typeof fetch);
    const result = await client[op]({
      organizationId: ORG,
      policyId: POLICY,
      csrfToken: "csrf",
      idempotencyKey: IDEMPOTENCY,
      signal: new AbortController().signal,
      body: { mutationId: MUTATION, expectedRevision: "1", expectedUpdatedAt: ISO },
    });
    expect(result.receipt.operation).toBe(operation);
    const [path, init] = (fetcher.mock.calls as unknown as Array<[string, RequestInit]>)[0]!;
    expect(path).toContain(`/policies/${encodeURIComponent(POLICY)}/${op}`);
    const body = JSON.parse(String(init.body)) as { expectedRevision: string; expectedUpdatedAt: string };
    expect(body.expectedRevision).toBe("1");
    expect(body.expectedUpdatedAt).toBe(ISO);
  });

  it("rejects a mismatched receipt mutation id and an oversized body before fetch", async () => {
    const wrongId = vi.fn(async () =>
      success(mutationResult("control.policy.create", POLICY_B, V4_B)),
    );
    await expect(
      clientWith(wrongId as unknown as typeof fetch).createRevision({
        organizationId: ORG,
        csrfToken: "csrf",
        idempotencyKey: IDEMPOTENCY,
        signal: new AbortController().signal,
        body: { mutationId: MUTATION, content: content() },
      }),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });

    const fetcher = vi.fn();
    const huge = { mutationId: MUTATION, content: content({ expiresAt: "x".repeat(POLICY_MAX_BODY_BYTES) }) };
    await expect(
      clientWith(fetcher as unknown as typeof fetch).createRevision({
        organizationId: ORG,
        csrfToken: "csrf",
        idempotencyKey: IDEMPOTENCY,
        signal: new AbortController().signal,
        body: huge,
      }),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("rejects a canonical-foreign-org create/append response before any receipt is used", async () => {
    const foreignCreate = vi.fn(async () =>
      success({ organizationId: ORG_B, replayed: false, receipt: receipt("control.policy.create", POLICY, MUTATION) }),
    );
    await expect(
      clientWith(foreignCreate as unknown as typeof fetch).createRevision({
        organizationId: ORG,
        csrfToken: "csrf",
        idempotencyKey: IDEMPOTENCY,
        signal: new AbortController().signal,
        body: { mutationId: MUTATION, content: content() },
      }),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });

    const foreignAppend = vi.fn(async () =>
      success({
        organizationId: ORG_B,
        replayed: false,
        receipt: receipt("control.policy.revision.create", `${POLICY}@11`, MUTATION),
      }),
    );
    await expect(
      clientWith(foreignAppend as unknown as typeof fetch).appendRevision({
        organizationId: ORG,
        policyId: POLICY,
        csrfToken: "csrf",
        idempotencyKey: IDEMPOTENCY,
        signal: new AbortController().signal,
        body: { mutationId: MUTATION, expectedRevision: "10", expectedUpdatedAt: ISO, content: content() },
      }),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });

  it("rejects a create/append body whose content organization differs from the path org before fetch", async () => {
    const fetcher = vi.fn();
    await expect(
      clientWith(fetcher as unknown as typeof fetch).createRevision({
        organizationId: ORG,
        csrfToken: "csrf",
        idempotencyKey: IDEMPOTENCY,
        signal: new AbortController().signal,
        body: { mutationId: MUTATION, content: content({ organizationId: ORG_B }) },
      }),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    await expect(
      clientWith(fetcher as unknown as typeof fetch).appendRevision({
        organizationId: ORG,
        policyId: POLICY,
        csrfToken: "csrf",
        idempotencyKey: IDEMPOTENCY,
        signal: new AbortController().signal,
        body: {
          mutationId: MUTATION,
          expectedRevision: "10",
          expectedUpdatedAt: ISO,
          content: content({ organizationId: ORG_B }),
        },
      }),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("rejects an empty CSRF token and a malformed idempotency key before send", async () => {
    const fetcher = vi.fn();
    await expect(
      clientWith(fetcher as unknown as typeof fetch).createRevision({
        organizationId: ORG,
        csrfToken: "",
        idempotencyKey: IDEMPOTENCY,
        signal: new AbortController().signal,
        body: { mutationId: MUTATION, content: content() },
      }),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    await expect(
      clientWith(fetcher as unknown as typeof fetch).createRevision({
        organizationId: ORG,
        csrfToken: "csrf",
        idempotencyKey: "short",
        signal: new AbortController().signal,
        body: { mutationId: MUTATION, content: content() },
      }),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("reports outcome-unknown for a transport failure after send and a 5xx", async () => {
    const network = vi.fn(async () => {
      throw new Error("reset");
    });
    await expect(
      clientWith(network as unknown as typeof fetch).createRevision({
        organizationId: ORG,
        csrfToken: "csrf",
        idempotencyKey: IDEMPOTENCY,
        signal: new AbortController().signal,
        body: { mutationId: MUTATION, content: content() },
      }),
    ).rejects.toMatchObject({ failure: { kind: "outcome-unknown" } });
    const server = vi.fn(async () => new Response("boom", { status: 500 }));
    await expect(
      clientWith(server as unknown as typeof fetch).createRevision({
        organizationId: ORG,
        csrfToken: "csrf",
        idempotencyKey: IDEMPOTENCY,
        signal: new AbortController().signal,
        body: { mutationId: MUTATION, content: content() },
      }),
    ).rejects.toMatchObject({ failure: { kind: "outcome-unknown" } });
  });
});

describe("policy mutation status", () => {
  it("reads a committed status by the original mutation id and binds operation/resource", async () => {
    const fetcher = vi.fn(async () =>
      success({ organizationId: ORG, mutationId: MUTATION, status: "committed", receipt: receipt("control.policy.pause", POLICY, MUTATION) }),
    );
    const status = await clientWith(fetcher as unknown as typeof fetch).readMutationStatus({
      organizationId: ORG,
      mutationId: MUTATION,
      operation: "control.policy.pause",
      expectedResourceId: POLICY,
      signal: new AbortController().signal,
    });
    expect(status.status).toBe("committed");
    const [path] = (fetcher.mock.calls as unknown as Array<[string]>)[0]!;
    expect(path).toBe(
      `/v2/control/organizations/${encodeURIComponent(ORG)}/policy-mutations/${MUTATION}`,
    );
  });

  it("accepts a create status whose canonical policy resource was DB-generated", async () => {
    const fetcher = vi.fn(async () =>
      success({ organizationId: ORG, mutationId: MUTATION, status: "committed", receipt: receipt("control.policy.create", POLICY_B, MUTATION) }),
    );
    const status = await clientWith(fetcher as unknown as typeof fetch).readMutationStatus({
      organizationId: ORG,
      mutationId: MUTATION,
      operation: "control.policy.create",
      expectedResourceId: null,
      signal: new AbortController().signal,
    });
    expect(status.status).toBe("committed");
  });

  it("rejects a committed status with a mismatched operation or resource", async () => {
    const wrongOp = vi.fn(async () =>
      success({ organizationId: ORG, mutationId: MUTATION, status: "committed", receipt: receipt("control.policy.resume", POLICY, MUTATION) }),
    );
    await expect(
      clientWith(wrongOp as unknown as typeof fetch).readMutationStatus({
        organizationId: ORG,
        mutationId: MUTATION,
        operation: "control.policy.pause",
        expectedResourceId: POLICY,
        signal: new AbortController().signal,
      }),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });

    const wrongResource = vi.fn(async () =>
      success({ organizationId: ORG, mutationId: MUTATION, status: "committed", receipt: receipt("control.policy.pause", POLICY_B, MUTATION) }),
    );
    await expect(
      clientWith(wrongResource as unknown as typeof fetch).readMutationStatus({
        organizationId: ORG,
        mutationId: MUTATION,
        operation: "control.policy.pause",
        expectedResourceId: POLICY,
        signal: new AbortController().signal,
      }),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });

  it("accepts a truthful not_found status with no successor fiction", async () => {
    const fetcher = vi.fn(async () => success({ organizationId: ORG, mutationId: MUTATION, status: "not_found" }));
    const status = await clientWith(fetcher as unknown as typeof fetch).readMutationStatus({
      organizationId: ORG,
      mutationId: MUTATION,
      operation: "control.policy.pause",
      expectedResourceId: POLICY,
      signal: new AbortController().signal,
    });
    expect(status.status).toBe("not_found");
  });

  it("binds the outer organizationId and mutationId on BOTH committed and not_found statuses", async () => {
    const request = {
      organizationId: ORG,
      mutationId: MUTATION,
      operation: "control.policy.pause" as const,
      expectedResourceId: POLICY,
      signal: new AbortController().signal,
    };
    // A foreign-org committed status must be rejected before its receipt is used.
    const foreignOrgCommitted = vi.fn(async () =>
      success({ organizationId: ORG_B, mutationId: MUTATION, status: "committed", receipt: receipt("control.policy.pause", POLICY, MUTATION) }),
    );
    await expect(
      clientWith(foreignOrgCommitted as unknown as typeof fetch).readMutationStatus(request),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });

    // A foreign-org not_found status must be rejected too.
    const foreignOrgNotFound = vi.fn(async () =>
      success({ organizationId: ORG_B, mutationId: MUTATION, status: "not_found" }),
    );
    await expect(
      clientWith(foreignOrgNotFound as unknown as typeof fetch).readMutationStatus(request),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });

    // A wrong outer mutationId not_found status must be rejected.
    const wrongMutationNotFound = vi.fn(async () =>
      success({ organizationId: ORG, mutationId: V4_B, status: "not_found" }),
    );
    await expect(
      clientWith(wrongMutationNotFound as unknown as typeof fetch).readMutationStatus(request),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });
});

describe("policy capability transport", () => {
  it("omits credentials and sends no browser marker", async () => {
    const frozen = await import("@openarc/shared");
    const full = {
      ...frozen.CONTROL_CAPABILITY_MANIFEST,
      capabilities: [{ ...frozen.CONTROL_CAPABILITY_MANIFEST.capabilities[0]!, state: "enabled" }],
      routes: frozen.CONTROL_ROUTES.map((route) => ({ ...route })),
    };
    const fetcher = vi.fn(async () => success(full));
    const state = await readPolicyManagementCapability(
      new AbortController().signal,
      fetcher as unknown as typeof fetch,
    );
    expect(state).toBe("enabled");
    expect(fetcher).toHaveBeenCalledWith(CONTROL_CAPABILITIES_PATH, {
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
        ...frozen.CONTROL_CAPABILITY_MANIFEST,
        capabilities: [{ ...frozen.CONTROL_CAPABILITY_MANIFEST.capabilities[0]!, state: expectedState }],
        routes: frozen.CONTROL_ROUTES.map((route) => ({ ...route })),
      };
      const fetcher = vi.fn(async () => success(full));
      const state = await readPolicyManagementCapability(
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

describe("policy client total transport deadline (headers + body)", () => {
  it("times a stalled GET body out as unavailable, never stuck loading", async () => {
    vi.useFakeTimers();
    try {
      const fetcher = vi.fn(async () => stalledBodyResponse());
      const promise = clientWith(fetcher as unknown as typeof fetch).listRoots(
        { organizationId: ORG },
        new AbortController().signal,
      );
      const assertion = expect(promise).rejects.toMatchObject({ failure: { kind: "unavailable" } });
      await vi.advanceTimersByTimeAsync(POLICY_REQUEST_TIMEOUT_MS + 1);
      await assertion;
    } finally {
      vi.useRealTimers();
    }
  });

  it("times a stalled SENT write body out as outcome-unknown", async () => {
    vi.useFakeTimers();
    try {
      const fetcher = vi.fn(async () => stalledBodyResponse());
      const promise = clientWith(fetcher as unknown as typeof fetch).createRevision({
        organizationId: ORG,
        csrfToken: "csrf",
        idempotencyKey: IDEMPOTENCY,
        signal: new AbortController().signal,
        body: { mutationId: MUTATION, content: content() },
      });
      const assertion = expect(promise).rejects.toMatchObject({ failure: { kind: "outcome-unknown" } });
      await vi.advanceTimersByTimeAsync(POLICY_REQUEST_TIMEOUT_MS + 1);
      await assertion;
    } finally {
      vi.useRealTimers();
    }
  });

  it("keeps the 64KiB streamed-body bound", async () => {
    const encoder = new TextEncoder();
    const oversized = bodyOfBytes(encoder.encode(`"${"x".repeat(API_MAX_RESPONSE_BYTES)}"`));
    await expect(
      clientWith((async () => oversized) as unknown as typeof fetch).listRoots(
        { organizationId: ORG },
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });
});
