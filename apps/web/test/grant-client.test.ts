import {
  API_CLIENT_HEADER,
  GRANT_CAPABILITIES_PATH,
  GRANT_CAPABILITY_MANIFEST,
  GRANT_ROUTES,
} from "@openarc/shared";
import { describe, expect, it, vi } from "vitest";

import {
  GRANT_AGENT_ROUTE_IDS,
  GRANT_PROVIDER_ROUTE_IDS,
  GrantClient,
  containsGrantSecret,
  createGrantCorrelation,
  createGrantIdempotencyKey,
  createGrantMutationId,
  readCommerceGrantsCapability,
} from "../src/tenant/grant-client.js";
import {
  ACTION,
  FAKE_GRANT_TOKEN,
  GRANT,
  GRANT_B,
  ISO_EXPIRES,
  META,
  MUTATION,
  ORG,
  ORG_B,
  V4_B,
  claimedRevokeData,
  claimedThenRevokedGrantMetadata,
  errorEnvelope,
  grantDetail,
  grantMetadata,
  grantReceipt,
  releasedRevokeData,
  success,
} from "./grant-test-fixtures.js";

const IDEMPOTENCY = `${"A".repeat(42)}A`;
const SIGNAL = () => new AbortController().signal;

function clientWith(fetcher: unknown) {
  return new GrantClient({ fetcher: fetcher as typeof fetch });
}

function calls(fetcher: ReturnType<typeof vi.fn>): Array<[string, RequestInit]> {
  return fetcher.mock.calls as unknown as Array<[string, RequestInit]>;
}

function capabilityManifest(state: string) {
  // Built from the frozen shared manifest so the fixture can never drift from
  // the accepted route/family inventory; only the shared state is varied.
  return {
    ...GRANT_CAPABILITY_MANIFEST,
    capabilities: GRANT_CAPABILITY_MANIFEST.capabilities.map((entry) => ({
      ...entry,
      dependencies: [...entry.dependencies],
      state,
    })),
    routes: GRANT_CAPABILITY_MANIFEST.routes.map((route) => ({ ...route })),
  };
}

const revokeRequest = (body: unknown = { mutationId: MUTATION }) => ({
  organizationId: ORG,
  grantId: GRANT,
  csrfToken: "csrf-token",
  idempotencyKey: IDEMPOTENCY,
  signal: SIGNAL(),
  body,
});

describe("grant client route confinement", () => {
  it("only ever builds the three frozen browser grant paths", async () => {
    const fetcher = vi.fn(async (path: string, init: RequestInit) => {
      if (init.method === "POST") return success(claimedRevokeData());
      if (path.includes("/grant-mutations/")) return success({ status: "not_found" });
      return success(grantDetail());
    });
    const client = clientWith(fetcher);
    await client.readGrant({ organizationId: ORG, grantId: GRANT }, SIGNAL());
    await client.revoke(revokeRequest());
    await client.readMutationStatus({
      organizationId: ORG,
      mutationId: MUTATION,
      expectedResourceId: GRANT,
      signal: SIGNAL(),
    });
    expect(calls(fetcher).map(([path]) => path)).toEqual([
      `/v2/control/organizations/${encodeURIComponent(ORG)}/grants/${encodeURIComponent(GRANT)}`,
      `/v2/control/organizations/${encodeURIComponent(ORG)}/grants/${encodeURIComponent(GRANT)}/revoke`,
      `/v2/control/organizations/${encodeURIComponent(ORG)}/grant-mutations/${encodeURIComponent(MUTATION)}`,
    ]);
    for (const [path] of calls(fetcher)) {
      expect(path.startsWith("/v2/control/organizations/")).toBe(true);
      expect(path.startsWith("/v2/agent/")).toBe(false);
      expect(path.startsWith("/v2/provider/")).toBe(false);
    }
  });

  it("exposes no method that can reach any agent or provider grant route", () => {
    const client = clientWith(vi.fn());
    const surface = [
      ...Object.getOwnPropertyNames(GrantClient.prototype),
      ...Object.getOwnPropertyNames(client),
    ];
    // The headless families' six route paths have no caller on this client.
    const headless = [...GRANT_AGENT_ROUTE_IDS, ...GRANT_PROVIDER_ROUTE_IDS];
    expect(headless).toHaveLength(6);
    for (const id of headless) {
      expect(surface).not.toContain(id);
      const route = GRANT_ROUTES.find((entry) => entry.id === id);
      expect(route?.audience === "agent" || route?.audience === "provider").toBe(true);
    }
    expect([...surface].sort()).toEqual([
      "constructor",
      "readGrant",
      "readMutationStatus",
      "revoke",
    ]);
  });

  it("rejects a bad organization or grant id before any fetch", async () => {
    const fetcher = vi.fn();
    const client = clientWith(fetcher);
    await expect(
      client.readGrant({ organizationId: "../evil", grantId: GRANT }, SIGNAL()),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    await expect(
      client.readGrant({ organizationId: ORG, grantId: ACTION }, SIGNAL()),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    await expect(
      client.readGrant({ organizationId: ORG, grantId: "not-a-grant" }, SIGNAL()),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    await expect(
      client.readMutationStatus({
        organizationId: ORG,
        mutationId: "not-a-uuid",
        expectedResourceId: GRANT,
        signal: SIGNAL(),
      }),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    expect(fetcher).not.toHaveBeenCalled();
  });
});

describe("grant client detail read", () => {
  it("sends a relative same-origin GET with only the browser marker", async () => {
    const fetcher = vi.fn(async () => success(grantDetail()));
    const detail = await clientWith(fetcher).readGrant(
      { organizationId: ORG, grantId: GRANT },
      SIGNAL(),
    );
    expect(detail.item?.grantId).toBe(GRANT);
    expect(fetcher).toHaveBeenCalledWith(
      `/v2/control/organizations/${encodeURIComponent(ORG)}/grants/${encodeURIComponent(GRANT)}`,
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

  it("reads a null item as a genuine absence, not an error", async () => {
    const fetcher = vi.fn(async () => success(grantDetail(null)));
    const detail = await clientWith(fetcher).readGrant(
      { organizationId: ORG, grantId: GRANT },
      SIGNAL(),
    );
    expect(detail.item).toBeNull();
  });

  it("rejects a detail bound to another organization or grant", async () => {
    for (const body of [
      grantDetail(grantMetadata(), { organizationId: ORG_B }),
      grantDetail(grantMetadata(GRANT_B), { grantId: GRANT_B }),
      grantDetail(grantMetadata(GRANT_B)),
      grantDetail(grantMetadata(GRANT, { organizationId: ORG_B })),
    ]) {
      const fetcher = vi.fn(async () => success(body));
      await expect(
        clientWith(fetcher).readGrant({ organizationId: ORG, grantId: GRANT }, SIGNAL()),
      ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
    }
  });

  it("rejects a malformed grant record", async () => {
    const malformed = [
      // Unknown status; there is no `paid`, `settled` or `delivered` status.
      grantMetadata(GRANT, { status: "paid" }),
      grantMetadata(GRANT, { status: "settled" }),
      // Expiry beyond the fixed 300-second ceiling.
      grantMetadata(GRANT, { expiresAt: "2026-01-01T00:05:01.000Z" }),
      // Expiry at or before issuance.
      grantMetadata(GRANT, { expiresAt: "2026-01-01T00:00:00.000Z" }),
      // `claimed` requires a non-null claimedAt.
      grantMetadata(GRANT, { status: "claimed" }),
      // `revoked` requires a non-null revokedAt.
      grantMetadata(GRANT, { status: "revoked" }),
      // `issued` forbids a claim.
      grantMetadata(GRANT, { claimedAt: "2026-01-01T00:01:00.000Z" }),
      // Unknown extra key.
      grantMetadata(GRANT, { amountAtomic: "1500000" }),
      // A token-bearing key is not representable on this wire.
      grantMetadata(GRANT, { grantToken: FAKE_GRANT_TOKEN }),
    ];
    for (const item of malformed) {
      const fetcher = vi.fn(async () => success(grantDetail(item)));
      await expect(
        clientWith(fetcher).readGrant({ organizationId: ORG, grantId: GRANT }, SIGNAL()),
      ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
    }
  });

  it("accepts the exact 300-second boundary and nothing past it", async () => {
    const ok = vi.fn(async () =>
      success(grantDetail(grantMetadata(GRANT, { expiresAt: "2026-01-01T00:05:00.000Z" }))),
    );
    await expect(
      clientWith(ok).readGrant({ organizationId: ORG, grantId: GRANT }, SIGNAL()),
    ).resolves.toMatchObject({ item: { expiresAt: "2026-01-01T00:05:00.000Z" } });
  });
});

describe("grant client secret refusal", () => {
  it("recognises raw grant-token material anywhere in a payload", () => {
    expect(containsGrantSecret(FAKE_GRANT_TOKEN)).toBe(true);
    expect(containsGrantSecret({ deep: { deeper: [FAKE_GRANT_TOKEN] } })).toBe(true);
    expect(containsGrantSecret({ grantToken: "anything" })).toBe(true);
    expect(containsGrantSecret({ token: "anything" })).toBe(true);
    expect(containsGrantSecret({ secret: "anything" })).toBe(true);
    // The accepted browser payloads are clean.
    expect(containsGrantSecret(grantDetail())).toBe(false);
    expect(containsGrantSecret(claimedRevokeData())).toBe(false);
    expect(containsGrantSecret(grantReceipt())).toBe(false);
    expect(containsGrantSecret({ status: "not_found" })).toBe(false);
  });

  it("refuses a response that carries grant-secret material rather than returning it", async () => {
    // Both the strict accepted schema AND the independent sweep refuse this.
    const fetcher = vi.fn(async () =>
      success({ ...grantDetail(), grantToken: FAKE_GRANT_TOKEN }),
    );
    await expect(
      clientWith(fetcher).readGrant({ organizationId: ORG, grantId: GRANT }, SIGNAL()),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });

  it("never places the CSRF token, idempotency key or any secret in a URL or body", async () => {
    const fetcher = vi.fn(async () => success(claimedRevokeData()));
    await clientWith(fetcher).revoke(revokeRequest());
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
    expect(String(init.body)).not.toContain("oag_v1_");
  });
});

describe("grant client revoke", () => {
  it("posts one revoke to the exact frozen path", async () => {
    const fetcher = vi.fn(async () => success(claimedRevokeData()));
    const result = await clientWith(fetcher).revoke(revokeRequest());
    expect(result.receipt.operation).toBe("control.grant.revoke");
    expect(result.receipt.resourceType).toBe("authorization_grant");
    expect(fetcher).toHaveBeenCalledTimes(1);
    const [path, init] = calls(fetcher)[0]!;
    expect(path).toBe(
      `/v2/control/organizations/${encodeURIComponent(ORG)}/grants/${encodeURIComponent(GRANT)}/revoke`,
    );
    expect(init.method).toBe("POST");
  });

  it("keeps the claim and refuses to release it for a claimed grant", async () => {
    const fetcher = vi.fn(async () => success(claimedRevokeData()));
    const result = await clientWith(fetcher).revoke(revokeRequest());
    expect(result.metadata.status).toBe("revoked");
    expect(result.metadata.claimedAt).not.toBeNull();
    expect(result.released).toBe(false);
  });

  it("rejects a revoke result that claims to have released a claimed grant", async () => {
    // The accepted shape forbids it outright: revocation is never a release of
    // a claimed exposure, and never a refund.
    const fetcher = vi.fn(async () =>
      success(claimedRevokeData(MUTATION, { released: true, actionStatus: "cancelled" })),
    );
    await expect(clientWith(fetcher).revoke(revokeRequest())).rejects.toMatchObject({
      failure: { kind: "invalid-response" },
    });
  });

  it("rejects a released revoke whose action is not cancelled", async () => {
    const fetcher = vi.fn(async () =>
      success(releasedRevokeData(MUTATION, { actionStatus: "grant_issued" })),
    );
    await expect(clientWith(fetcher).revoke(revokeRequest())).rejects.toMatchObject({
      failure: { kind: "invalid-response" },
    });
  });

  it("rejects a receipt bound to another operation, mutation, grant or organization", async () => {
    const wrong = [
      claimedRevokeData(MUTATION, {
        receipt: grantReceipt(GRANT, MUTATION, "control.grant.issue"),
      }),
      claimedRevokeData(MUTATION, { receipt: grantReceipt(GRANT, V4_B) }),
      claimedRevokeData(MUTATION, {
        metadata: claimedThenRevokedGrantMetadata(GRANT_B),
        receipt: grantReceipt(GRANT_B, MUTATION),
      }),
      claimedRevokeData(MUTATION, {
        metadata: claimedThenRevokedGrantMetadata(GRANT, { organizationId: ORG_B }),
      }),
      // A metadata status other than revoked cannot be revoke data.
      claimedRevokeData(MUTATION, { metadata: grantMetadata() }),
    ];
    for (const body of wrong) {
      const fetcher = vi.fn(async () => success(body));
      await expect(clientWith(fetcher).revoke(revokeRequest())).rejects.toMatchObject({
        failure: { kind: "invalid-response" },
      });
    }
  });

  it("refuses a missing CSRF token, a bad idempotency key and a bad body before any fetch", async () => {
    const fetcher = vi.fn();
    const client = clientWith(fetcher);
    await expect(
      client.revoke({ ...revokeRequest(), csrfToken: "" }),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    await expect(
      client.revoke({ ...revokeRequest(), idempotencyKey: "short" }),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    await expect(
      client.revoke(revokeRequest({ mutationId: MUTATION, extra: 1 })),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    await expect(
      client.revoke(revokeRequest({ mutationId: "not-a-uuid" })),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    // There is no reason, force, release or cascade field on this body.
    await expect(
      client.revoke(revokeRequest({ mutationId: MUTATION, released: true })),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    await expect(
      client.revoke(revokeRequest({ mutationId: MUTATION, grantToken: FAKE_GRANT_TOKEN })),
    ).rejects.toMatchObject({ failure: { kind: "pre-send" } });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("maps a server denial to forbidden without retrying", async () => {
    const fetcher = vi.fn(async () => errorEnvelope("FORBIDDEN", 403));
    await expect(clientWith(fetcher).revoke(revokeRequest())).rejects.toMatchObject({
      failure: { kind: "forbidden" },
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("maps a lost write to outcome-unknown and never resends it", async () => {
    const fetcher = vi.fn(async () => {
      throw new TypeError("network down");
    });
    await expect(clientWith(fetcher).revoke(revokeRequest())).rejects.toMatchObject({
      failure: { kind: "outcome-unknown" },
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("maps a 5xx write to outcome-unknown and a 5xx read to unavailable, with no retry", async () => {
    const write = vi.fn(async () => errorEnvelope("INTERNAL_ERROR", 500));
    await expect(clientWith(write).revoke(revokeRequest())).rejects.toMatchObject({
      failure: { kind: "outcome-unknown" },
    });
    expect(write).toHaveBeenCalledTimes(1);

    const read = vi.fn(async () => errorEnvelope("INTERNAL_ERROR", 500));
    await expect(
      clientWith(read).readGrant({ organizationId: ORG, grantId: GRANT }, SIGNAL()),
    ).rejects.toMatchObject({ failure: { kind: "unavailable" } });
    expect(read).toHaveBeenCalledTimes(1);
  });

  it("maps CSRF, feature-disabled, conflict and grant-state refusals to their own kinds", async () => {
    const cases = [
      ["CSRF_REJECTED", 403, "csrf"],
      ["FEATURE_DISABLED", 404, "feature-disabled"],
      ["IDEMPOTENCY_CONFLICT", 409, "conflict"],
      ["GRANT_EXPIRED", 403, "policy"],
      ["GRANT_REVOKED", 403, "policy"],
      ["GRANT_ALREADY_USED", 403, "policy"],
      ["UNAUTHENTICATED", 401, "unauthenticated"],
      ["TENANT_MISMATCH", 403, "forbidden"],
    ] as const;
    for (const [code, status, kind] of cases) {
      const fetcher = vi.fn(async () => errorEnvelope(code, status));
      await expect(clientWith(fetcher).revoke(revokeRequest())).rejects.toMatchObject({
        failure: { kind },
      });
      expect(fetcher).toHaveBeenCalledTimes(1);
    }
  });
});

describe("grant client mutation status", () => {
  const status = (mutationId = MUTATION) => ({
    organizationId: ORG,
    mutationId,
    expectedResourceId: GRANT,
    signal: SIGNAL(),
  });

  it("reads the frozen status path with a plain GET and no body", async () => {
    const fetcher = vi.fn(async () => success({ status: "not_found" }));
    const result = await clientWith(fetcher).readMutationStatus(status());
    expect(result).toEqual({ status: "not_found" });
    const [path, init] = calls(fetcher)[0]!;
    expect(path).toBe(
      `/v2/control/organizations/${encodeURIComponent(ORG)}/grant-mutations/${encodeURIComponent(MUTATION)}`,
    );
    expect(init.method).toBe("GET");
    expect(init.body).toBeUndefined();
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("accepts a committed receipt bound to the original mutation and grant", async () => {
    const fetcher = vi.fn(async () =>
      success({ status: "committed", receipt: grantReceipt(GRANT, MUTATION) }),
    );
    const result = await clientWith(fetcher).readMutationStatus(status());
    expect(result.status).toBe("committed");
  });

  it("rejects a committed receipt bound to another operation, mutation or grant", async () => {
    const wrong = [
      { status: "committed", receipt: grantReceipt(GRANT, MUTATION, "control.grant.issue") },
      { status: "committed", receipt: grantReceipt(GRANT, MUTATION, "control.grant.claim") },
      { status: "committed", receipt: grantReceipt(GRANT, V4_B) },
      { status: "committed", receipt: grantReceipt(GRANT_B, MUTATION) },
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
      { status: "not_found", receipt: grantReceipt() },
      { status: "committed" },
      // A status read must never be able to reconstruct the one-use secret.
      { status: "committed", receipt: grantReceipt(), grantToken: FAKE_GRANT_TOKEN },
    ]) {
      const fetcher = vi.fn(async () => success(body));
      await expect(clientWith(fetcher).readMutationStatus(status())).rejects.toMatchObject({
        failure: { kind: "invalid-response" },
      });
    }
  });
});

describe("grant client envelope discipline", () => {
  it("rejects a non-JSON content type, a wrong envelope shape and a bad meta", async () => {
    const bad: Response[] = [
      new Response(JSON.stringify({ ok: true, data: grantDetail(), meta: META }), {
        status: 200,
        headers: { "content-type": "text/html" },
      }),
      new Response(JSON.stringify({ ok: true, data: grantDetail() }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
      new Response(
        JSON.stringify({
          ok: true,
          data: grantDetail(),
          meta: { ...META, schemaVersion: "openarc.wrong.v9" },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
      new Response(
        JSON.stringify({ ok: true, data: grantDetail(), meta: META, extra: 1 }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    ];
    for (const response of bad) {
      const fetcher = vi.fn(async () => response);
      await expect(
        clientWith(fetcher).readGrant({ organizationId: ORG, grantId: GRANT }, SIGNAL()),
      ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
    }
  });

  it("aborts without issuing a request when the caller signal is already aborted", async () => {
    const fetcher = vi.fn();
    const controller = new AbortController();
    controller.abort();
    await expect(
      clientWith(fetcher).readGrant({ organizationId: ORG, grantId: GRANT }, controller.signal),
    ).rejects.toMatchObject({ failure: { kind: "aborted" } });
    expect(fetcher).not.toHaveBeenCalled();
  });
});

describe("grant capability probe", () => {
  it("reads the public manifest credentiallessly and returns the management state", async () => {
    const fetcher = vi.fn(async () => success(capabilityManifest("enabled")));
    const state = await readCommerceGrantsCapability(
      SIGNAL(),
      fetcher as unknown as typeof fetch,
    );
    expect(state).toBe("enabled");
    const [path, init] = calls(fetcher)[0]!;
    expect(path).toBe(GRANT_CAPABILITIES_PATH);
    expect(init.credentials).toBe("omit");
    expect(init.headers).toBeUndefined();
  });

  it("returns a disabled state truthfully instead of a fabricated grant", async () => {
    for (const state of ["built_disabled", "unavailable"] as const) {
      const fetcher = vi.fn(async () => success(capabilityManifest(state)));
      await expect(
        readCommerceGrantsCapability(SIGNAL(), fetcher as unknown as typeof fetch),
      ).resolves.toBe(state);
    }
  });

  it("rejects a manifest that does not parse", async () => {
    const fetcher = vi.fn(async () => success({ capabilities: [] }));
    await expect(
      readCommerceGrantsCapability(SIGNAL(), fetcher as unknown as typeof fetch),
    ).rejects.toMatchObject({ failure: { kind: "invalid-response" } });
  });
});

describe("grant correlation material", () => {
  it("creates a canonical v4 mutation id and a 43-character idempotency key", () => {
    const mutationId = createGrantMutationId();
    const key = createGrantIdempotencyKey();
    expect(mutationId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    );
    expect(key).toHaveLength(43);
    expect(createGrantMutationId()).not.toBe(mutationId);
    const correlation = createGrantCorrelation();
    expect(correlation.mutationId).not.toBe(mutationId);
    expect(correlation.idempotencyKey).toHaveLength(43);
    // Correlation material is never grant-secret material.
    expect(containsGrantSecret(correlation)).toBe(false);
    expect(correlation.idempotencyKey.startsWith("oag_v1_")).toBe(false);
  });
});

describe("grant wire has no money and no payment vocabulary", () => {
  it("carries no amount, fee, debit, price or balance field in a grant detail", async () => {
    const fetcher = vi.fn(async () => success(grantDetail()));
    const detail = await clientWith(fetcher).readGrant(
      { organizationId: ORG, grantId: GRANT },
      SIGNAL(),
    );
    const item = detail.item!;
    const keys = Object.keys(item);
    for (const forbidden of [
      "amountAtomic",
      "feeAtomic",
      "debitAtomic",
      "priceAtomic",
      "balance",
      "paidAt",
      "settledAt",
      "deliveredAt",
      "refundedAt",
      "grantToken",
      "tokenHash",
      "requirementDigest",
    ]) {
      expect(keys).not.toContain(forbidden);
    }
    expect(item.expiresAt).toBe(ISO_EXPIRES);
  });
});
