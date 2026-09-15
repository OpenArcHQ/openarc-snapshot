import {
  ACTION_CAPABILITIES_PATH,
  ACTION_CAPABILITY_MANIFEST,
  API_CLIENT_HEADER,
} from "@openarc/shared";
import { describe, expect, it, vi } from "vitest";

import {
  ACTION_DEFAULT_PAGE_LIMIT,
  ACTION_PAGE_LIMIT,
  ActionClient,
  createActionIdempotencyKey,
  createActionMutationId,
  readCommerceActionsCapability,
} from "../src/tenant/action-client.js";
import {
  ACTION,
  ACTION_B,
  AGENT,
  AGENT_B,
  APPROVAL,
  APPROVAL_B,
  META,
  MUTATION,
  ORG,
  ORG_B,
  POLICY,
  V4_B,
  actionMetadata,
  actionReceipt,
  approvalMetadata,
  errorEnvelope,
  exposureData,
  exposureView,
  mutationData,
  success,
} from "./action-test-fixtures.js";

const IDEMPOTENCY = `${"A".repeat(42)}A`;
const SIGNAL = () => new AbortController().signal;

function clientWith(fetcher: unknown) {
  return new ActionClient({ fetcher: fetcher as typeof fetch });
}

function calls(fetcher: ReturnType<typeof vi.fn>): Array<[string, RequestInit]> {
  return fetcher.mock.calls as unknown as Array<[string, RequestInit]>;
}

function capabilityManifest(state: string) {
  // Built from the frozen shared manifest so the fixture can never drift from
  // the accepted route/family inventory; only the shared state is varied.
  return {
    ...ACTION_CAPABILITY_MANIFEST,
    capabilities: ACTION_CAPABILITY_MANIFEST.capabilities.map((entry) => ({
      ...entry,
      dependencies: [...entry.dependencies],
      state,
    })),
    routes: ACTION_CAPABILITY_MANIFEST.routes.map((route) => ({ ...route })),
  };
}

describe("action client bounded reads", () => {
  it("sends a relative same-origin bounded GET with only the browser marker", async () => {
    const fetcher = vi.fn(async () => success({ organizationId: ORG, items: [], nextCursor: null }));
    const page = await clientWith(fetcher).listActions({ organizationId: ORG }, SIGNAL());
    expect(page).toEqual({ organizationId: ORG, items: [], nextCursor: null });
    expect(fetcher).toHaveBeenCalledWith(
      `/v2/control/organizations/${encodeURIComponent(ORG)}/actions?limit=${ACTION_DEFAULT_PAGE_LIMIT}`,
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

  it("always sends a bounded limit and never an unbounded read", async () => {
    const fetcher = vi.fn(async () => success({ organizationId: ORG, items: [], nextCursor: null }));
    const client = clientWith(fetcher);
    await client.listActions({ organizationId: ORG }, SIGNAL());
    await client.listActions({ organizationId: ORG, limit: ACTION_PAGE_LIMIT }, SIGNAL());
    await client.listApprovals({ organizationId: ORG }, SIGNAL());
    for (const [path] of calls(fetcher)) {
      expect(path).toMatch(/[?&]limit=(?:[1-9]|[1-4][0-9]|50)(?:&|$)/u);
    }
  });

  it("rejects a limit outside 1..50, a bad cursor and a bad organization before any fetch", async () => {
    const fetcher = vi.fn();
    const client = clientWith(fetcher);
    for (const bad of [0, 51, 1.5, -1, Number.NaN]) {
      await expect(
        client.listActions({ organizationId: ORG, limit: bad }, SIGNAL()),
      ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    }
    await expect(
      client.listActions({ organizationId: ORG, afterActionId: "not-an-action" }, SIGNAL()),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    await expect(
      client.listActions({ organizationId: "../evil" }, SIGNAL()),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    await expect(
      client.listApprovals({ organizationId: ORG, afterApprovalId: ACTION }, SIGNAL()),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("passes a lexical keyset cursor through exactly once, encoded", async () => {
    const fetcher = vi.fn(async () => success({ organizationId: ORG, items: [], nextCursor: null }));
    await clientWith(fetcher).listActions(
      { organizationId: ORG, afterActionId: ACTION, limit: 50 },
      SIGNAL(),
    );
    expect(calls(fetcher)[0]![0]).toBe(
      `/v2/control/organizations/${encodeURIComponent(ORG)}/actions?afterActionId=${encodeURIComponent(ACTION)}&limit=50`,
    );
  });

  it("rejects a page whose organization does not match the request", async () => {
    const fetcher = vi.fn(async () =>
      success({ organizationId: ORG_B, items: [], nextCursor: null }),
    );
    await expect(
      clientWith(fetcher).listActions({ organizationId: ORG }, SIGNAL()),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });

  it("rejects a continuation page whose first row is not past the cursor", async () => {
    const fetcher = vi.fn(async () =>
      success({ organizationId: ORG, items: [actionMetadata(ACTION)], nextCursor: ACTION }),
    );
    await expect(
      clientWith(fetcher).listActions({ organizationId: ORG, afterActionId: ACTION_B }, SIGNAL()),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });

  it("rejects a page larger than the exact requested limit", async () => {
    const fetcher = vi.fn(async () =>
      success({
        organizationId: ORG,
        items: [actionMetadata(ACTION), actionMetadata(ACTION_B)],
        nextCursor: ACTION_B,
      }),
    );
    await expect(
      clientWith(fetcher).listActions({ organizationId: ORG, limit: 1 }, SIGNAL()),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });

  it("accepts a well-formed page and keeps the server cursor", async () => {
    const fetcher = vi.fn(async () =>
      success({
        organizationId: ORG,
        items: [actionMetadata(ACTION), actionMetadata(ACTION_B)],
        nextCursor: ACTION_B,
      }),
    );
    const page = await clientWith(fetcher).listActions({ organizationId: ORG }, SIGNAL());
    expect(page.items).toHaveLength(2);
    expect(page.nextCursor).toBe(ACTION_B);
  });

  it("rejects a malformed action row, a wrong debit sum and an out-of-order page", async () => {
    const malformed = [
      // Unknown status.
      { organizationId: ORG, items: [actionMetadata(ACTION, { status: "paid" })], nextCursor: ACTION },
      // debitAtomic must equal amountAtomic + feeAtomic.
      { organizationId: ORG, items: [actionMetadata(ACTION, { debitAtomic: "1" })], nextCursor: ACTION },
      // Descending ids.
      {
        organizationId: ORG,
        items: [actionMetadata(ACTION_B), actionMetadata(ACTION)],
        nextCursor: ACTION,
      },
      // Unknown extra key.
      { organizationId: ORG, items: [], nextCursor: null, extra: true },
    ];
    for (const body of malformed) {
      const fetcher = vi.fn(async () => success(body));
      await expect(
        clientWith(fetcher).listActions({ organizationId: ORG }, SIGNAL()),
      ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
    }
  });

  it("reads one action detail and rejects a cross-bound item", async () => {
    const ok = vi.fn(async () =>
      success({ organizationId: ORG, actionId: ACTION, item: actionMetadata(ACTION) }),
    );
    const detail = await clientWith(ok).readAction(
      { organizationId: ORG, actionId: ACTION },
      SIGNAL(),
    );
    expect(detail.item?.actionId).toBe(ACTION);
    expect(calls(ok)[0]![0]).toBe(
      `/v2/control/organizations/${encodeURIComponent(ORG)}/actions/${encodeURIComponent(ACTION)}`,
    );

    const crossed = vi.fn(async () =>
      success({ organizationId: ORG, actionId: ACTION, item: actionMetadata(ACTION_B) }),
    );
    await expect(
      clientWith(crossed).readAction({ organizationId: ORG, actionId: ACTION }, SIGNAL()),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });

  it("reads a null action detail as a genuine absence, not an error", async () => {
    const fetcher = vi.fn(async () =>
      success({ organizationId: ORG, actionId: ACTION, item: null }),
    );
    const detail = await clientWith(fetcher).readAction(
      { organizationId: ORG, actionId: ACTION },
      SIGNAL(),
    );
    expect(detail.item).toBeNull();
  });

  it("reads approvals and one approval detail from the frozen paths", async () => {
    const page = vi.fn(async () =>
      success({ organizationId: ORG, items: [approvalMetadata(APPROVAL)], nextCursor: APPROVAL }),
    );
    await clientWith(page).listApprovals({ organizationId: ORG }, SIGNAL());
    expect(calls(page)[0]![0]).toBe(
      `/v2/control/organizations/${encodeURIComponent(ORG)}/approvals?limit=25`,
    );

    const detail = vi.fn(async () =>
      success({ organizationId: ORG, approvalId: APPROVAL, item: approvalMetadata(APPROVAL) }),
    );
    const read = await clientWith(detail).readApproval(
      { organizationId: ORG, approvalId: APPROVAL },
      SIGNAL(),
    );
    expect(read.item?.approvalId).toBe(APPROVAL);
    expect(calls(detail)[0]![0]).toBe(
      `/v2/control/organizations/${encodeURIComponent(ORG)}/approvals/${encodeURIComponent(APPROVAL)}`,
    );
  });

  it("rejects an approval whose id does not match the requested one", async () => {
    const fetcher = vi.fn(async () =>
      success({ organizationId: ORG, approvalId: APPROVAL, item: approvalMetadata(APPROVAL_B) }),
    );
    await expect(
      clientWith(fetcher).readApproval({ organizationId: ORG, approvalId: APPROVAL }, SIGNAL()),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });

  it("reads exposure from the frozen three-segment path and binds all three ids", async () => {
    const ok = vi.fn(async () => success(exposureData()));
    const data = await clientWith(ok).readExposure(
      { organizationId: ORG, subjectAgentId: AGENT, policyId: POLICY },
      SIGNAL(),
    );
    expect(data.item?.totalExposureAtomic).toBe("1250000");
    expect(calls(ok)[0]![0]).toBe(
      `/v2/control/organizations/${encodeURIComponent(ORG)}/agents/${encodeURIComponent(AGENT)}/policies/${encodeURIComponent(POLICY)}/exposure`,
    );

    const crossed = vi.fn(async () =>
      success({ ...exposureData(), subjectAgentId: AGENT_B }),
    );
    await expect(
      clientWith(crossed).readExposure(
        { organizationId: ORG, subjectAgentId: AGENT, policyId: POLICY },
        SIGNAL(),
      ),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });

  it("rejects an exposure view whose own arithmetic or invariants do not hold", async () => {
    const malformed = [
      // committed + unresolved must equal total.
      exposureView({ totalExposureAtomic: "9999999" }),
      // A positive deficit requires available to be exactly 0.
      exposureView({ deficitAtomic: "1", availableAtomic: "5" }),
      // A null available requires a zero deficit.
      exposureView({ availableAtomic: null, deficitAtomic: "1" }),
      // A float is not a canonical atomic string.
      exposureView({ committedAtomic: "1.5", totalExposureAtomic: "1.75" }),
      // A leading zero is not canonical.
      exposureView({ committedAtomic: "01000000" }),
    ];
    for (const item of malformed) {
      const fetcher = vi.fn(async () => success(exposureData(item)));
      await expect(
        clientWith(fetcher).readExposure(
          { organizationId: ORG, subjectAgentId: AGENT, policyId: POLICY },
          SIGNAL(),
        ),
      ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
    }
  });

  it("keeps every exposure quantity as the exact server string, never a number", async () => {
    const big = "123456789012345678901234567890";
    const fetcher = vi.fn(async () =>
      success(
        exposureData(
          exposureView({
            committedAtomic: big,
            unresolvedAtomic: "0",
            totalExposureAtomic: big,
            availableAtomic: "0",
            deficitAtomic: "0",
          }),
        ),
      ),
    );
    const data = await clientWith(fetcher).readExposure(
      { organizationId: ORG, subjectAgentId: AGENT, policyId: POLICY },
      SIGNAL(),
    );
    expect(data.item?.committedAtomic).toBe(big);
    expect(typeof data.item?.committedAtomic).toBe("string");
  });
});

describe("action client decisions", () => {
  const request = (body: unknown = { mutationId: MUTATION }) => ({
    organizationId: ORG,
    actionId: ACTION,
    csrfToken: "csrf-token",
    idempotencyKey: IDEMPOTENCY,
    signal: SIGNAL(),
    body,
  });

  it("posts approve, reject and cancel to their exact frozen paths, once each", async () => {
    for (const [decision, operation, suffix] of [
      ["approve", "control.commerce_action.approve", "approve"],
      ["reject", "control.commerce_action.reject", "reject"],
      ["cancel", "control.commerce_action.cancel", "cancel"],
    ] as const) {
      const fetcher = vi.fn(async () => success(mutationData(operation)));
      const client = clientWith(fetcher);
      const result = await client[decision](request());
      expect(result.receipt.operation).toBe(operation);
      expect(fetcher).toHaveBeenCalledTimes(1);
      const [path, init] = calls(fetcher)[0]!;
      expect(path).toBe(
        `/v2/control/organizations/${encodeURIComponent(ORG)}/actions/${encodeURIComponent(ACTION)}/${suffix}`,
      );
      expect(init.method).toBe("POST");
    }
  });

  it("carries the CSRF token and idempotency key as headers only, never in the URL or body", async () => {
    const fetcher = vi.fn(async () =>
      success(mutationData("control.commerce_action.approve")),
    );
    await clientWith(fetcher).approve(request());
    const [path, init] = calls(fetcher)[0]!;
    const headers = (init.headers ?? {}) as Record<string, string>;
    expect(headers["X-OpenArc-CSRF"]).toBe("csrf-token");
    expect(headers["Idempotency-Key"]).toBe(IDEMPOTENCY);
    expect(headers.Authorization).toBeUndefined();
    expect(path).not.toContain("csrf");
    expect(path).not.toContain(IDEMPOTENCY);
    expect(String(init.body)).toBe(JSON.stringify({ mutationId: MUTATION }));
    expect(String(init.body)).not.toContain("csrf");
    expect(String(init.body)).not.toContain(IDEMPOTENCY);
  });

  it("refuses a missing CSRF token, a bad idempotency key and a bad body before any fetch", async () => {
    const fetcher = vi.fn();
    const client = clientWith(fetcher);
    await expect(
      client.approve({ ...request(), csrfToken: "" }),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    await expect(
      client.approve({ ...request(), idempotencyKey: "short" }),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    await expect(
      client.approve(request({ mutationId: MUTATION, extra: 1 })),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    await expect(
      client.approve(request({ mutationId: "not-a-uuid" })),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("rejects a receipt bound to another operation, mutation, action or organization", async () => {
    const wrong = [
      mutationData("control.commerce_action.reject"),
      mutationData("control.commerce_action.approve", V4_B),
      {
        replayed: false,
        metadata: actionMetadata(ACTION_B),
        receipt: actionReceipt("control.commerce_action.approve", ACTION_B, MUTATION),
      },
      {
        replayed: false,
        metadata: actionMetadata(ACTION, {
          exposureKey: {
            organizationId: ORG_B,
            subjectAgentId: AGENT,
            networkId: "eip155:5042002",
            asset: "USDC",
            representation: "erc20",
            decimals: 6,
          },
        }),
        receipt: actionReceipt("control.commerce_action.approve", ACTION, MUTATION),
      },
    ];
    for (const body of wrong) {
      const fetcher = vi.fn(async () => success(body));
      await expect(clientWith(fetcher).approve(request())).rejects.toMatchObject({
        failure: { kind: "invalid-response" },
      });
    }
  });

  it("maps a lost write to outcome-unknown and never resends it", async () => {
    const fetcher = vi.fn(async () => {
      throw new TypeError("network down");
    });
    await expect(clientWith(fetcher).approve(request())).rejects.toMatchObject({
      failure: { kind: "outcome-unknown" },
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("maps a 5xx write to outcome-unknown and a 5xx read to unavailable, with no retry", async () => {
    const write = vi.fn(async () => errorEnvelope("INTERNAL_ERROR", 500));
    await expect(clientWith(write).reject(request())).rejects.toMatchObject({
      failure: { kind: "outcome-unknown" },
    });
    expect(write).toHaveBeenCalledTimes(1);

    const read = vi.fn(async () => errorEnvelope("INTERNAL_ERROR", 500));
    await expect(
      clientWith(read).listActions({ organizationId: ORG }, SIGNAL()),
    ).rejects.toMatchObject({ failure: { kind: "unavailable" } });
    expect(read).toHaveBeenCalledTimes(1);
  });

  it("maps a server denial to forbidden without retrying", async () => {
    const fetcher = vi.fn(async () => errorEnvelope("FORBIDDEN", 403));
    await expect(clientWith(fetcher).approve(request())).rejects.toMatchObject({
      failure: { kind: "forbidden" },
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("maps CSRF, feature-disabled, conflict and policy refusals to their own kinds", async () => {
    const cases = [
      ["CSRF_REJECTED", 403, "csrf"],
      ["FEATURE_DISABLED", 404, "feature-disabled"],
      ["IDEMPOTENCY_CONFLICT", 409, "conflict"],
      ["APPROVAL_REQUIRED", 403, "policy"],
      ["UNAUTHENTICATED", 401, "unauthenticated"],
    ] as const;
    for (const [code, status, kind] of cases) {
      const fetcher = vi.fn(async () => errorEnvelope(code, status));
      await expect(clientWith(fetcher).cancel(request())).rejects.toMatchObject({
        failure: { kind },
      });
    }
  });
});

describe("action client mutation status", () => {
  const status = (mutationId = MUTATION) => ({
    organizationId: ORG,
    mutationId,
    operation: "control.commerce_action.approve" as const,
    expectedResourceId: ACTION,
    signal: SIGNAL(),
  });

  it("reads the frozen status path with a plain GET and no body", async () => {
    const fetcher = vi.fn(async () => success({ status: "not_found" }));
    const result = await clientWith(fetcher).readMutationStatus(status());
    expect(result).toEqual({ status: "not_found" });
    const [path, init] = calls(fetcher)[0]!;
    expect(path).toBe(
      `/v2/control/organizations/${encodeURIComponent(ORG)}/action-mutations/${encodeURIComponent(MUTATION)}`,
    );
    expect(init.method).toBe("GET");
    expect(init.body).toBeUndefined();
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("accepts a committed receipt bound to the original mutation, operation and action", async () => {
    const fetcher = vi.fn(async () =>
      success({
        status: "committed",
        receipt: actionReceipt("control.commerce_action.approve", ACTION, MUTATION),
      }),
    );
    const result = await clientWith(fetcher).readMutationStatus(status());
    expect(result.status).toBe("committed");
  });

  it("rejects a committed receipt bound to another operation, mutation or action", async () => {
    const wrong = [
      { status: "committed", receipt: actionReceipt("control.commerce_action.cancel", ACTION, MUTATION) },
      { status: "committed", receipt: actionReceipt("control.commerce_action.approve", ACTION, V4_B) },
      { status: "committed", receipt: actionReceipt("control.commerce_action.approve", ACTION_B, MUTATION) },
    ];
    for (const body of wrong) {
      const fetcher = vi.fn(async () => success(body));
      await expect(clientWith(fetcher).readMutationStatus(status())).rejects.toMatchObject({
        failure: { kind: "invalid-response" },
      });
    }
  });

  it("rejects a status union that is neither not_found nor committed", async () => {
    for (const body of [
      { status: "pending" },
      { status: "not_found", receipt: actionReceipt("control.commerce_action.approve") },
      { status: "committed" },
    ]) {
      const fetcher = vi.fn(async () => success(body));
      await expect(clientWith(fetcher).readMutationStatus(status())).rejects.toMatchObject({
        failure: { kind: "invalid-response" },
      });
    }
  });
});

describe("action client envelope discipline", () => {
  it("rejects a non-JSON content type, a wrong envelope shape and a bad meta", async () => {
    const bad: Response[] = [
      new Response(JSON.stringify({ ok: true, data: {}, meta: META }), {
        status: 200,
        headers: { "content-type": "text/html" },
      }),
      new Response(JSON.stringify({ ok: true, data: { organizationId: ORG, items: [], nextCursor: null } }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
      new Response(
        JSON.stringify({
          ok: true,
          data: { organizationId: ORG, items: [], nextCursor: null },
          meta: { ...META, schemaVersion: "openarc.wrong.v9" },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
      new Response(
        JSON.stringify({
          ok: true,
          data: { organizationId: ORG, items: [], nextCursor: null },
          meta: META,
          extra: 1,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    ];
    for (const response of bad) {
      const fetcher = vi.fn(async () => response);
      await expect(
        clientWith(fetcher).listActions({ organizationId: ORG }, SIGNAL()),
      ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
    }
  });

  it("aborts without issuing a request when the caller signal is already aborted", async () => {
    const fetcher = vi.fn();
    const controller = new AbortController();
    controller.abort();
    await expect(
      clientWith(fetcher).listActions({ organizationId: ORG }, controller.signal),
    ).rejects.toMatchObject({ failure: { kind: "aborted" } });
    expect(fetcher).not.toHaveBeenCalled();
  });
});

describe("action capability probe", () => {
  it("reads the public manifest credentiallessly and returns the management state", async () => {
    const fetcher = vi.fn(async () => success(capabilityManifest("enabled")));
    const state = await readCommerceActionsCapability(
      SIGNAL(),
      fetcher as unknown as typeof fetch,
    );
    expect(state).toBe("enabled");
    const [path, init] = calls(fetcher)[0]!;
    expect(path).toBe(ACTION_CAPABILITIES_PATH);
    expect(init.credentials).toBe("omit");
    expect(init.headers).toBeUndefined();
  });

  it("returns a disabled state truthfully instead of a fabricated empty queue", async () => {
    for (const state of ["built_disabled", "unavailable"] as const) {
      const fetcher = vi.fn(async () => success(capabilityManifest(state)));
      await expect(
        readCommerceActionsCapability(SIGNAL(), fetcher as unknown as typeof fetch),
      ).resolves.toBe(state);
    }
  });

  it("rejects a manifest that does not parse", async () => {
    const fetcher = vi.fn(async () => success({ capabilities: [] }));
    await expect(
      readCommerceActionsCapability(SIGNAL(), fetcher as unknown as typeof fetch),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });
});

describe("action correlation material", () => {
  it("creates a canonical v4 mutation id and a 43-character idempotency key", () => {
    const mutationId = createActionMutationId();
    const key = createActionIdempotencyKey();
    expect(mutationId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
    expect(key).toHaveLength(43);
    expect(createActionMutationId()).not.toBe(mutationId);
  });
});
