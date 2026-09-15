import {
  COMMERCE_API_ERRORS,
  COMMERCE_API_SCHEMA_VERSION,
  type CommerceHumanRole,
  type CommercePolicyContent,
} from "@openarc/shared";
import { describe, expect, it, vi } from "vitest";

import type { AccountFlowController } from "../account/flow-controller.js";
import { PolicyClient } from "./policy-client.js";
import {
  PolicyController,
  appendPolicyCursor,
  beginAppendFromRevision,
  canReadPolicies,
  canWritePolicies,
  contentFromRevision,
  expectedResourceIdOf,
  formatUsdcFromAtomic,
  parseCanonicalIdList,
  parseUsdcToAtomic,
  policyCasOf,
  policyIdOfReceipt,
  revisionOfReceipt,
  suppressStalePolicyContext,
  type PolicyReadCoordinator,
} from "./policy-controller.js";

const META = {
  schemaVersion: COMMERCE_API_SCHEMA_VERSION,
  requestId: "018f47a2-3b4c-7def-8123-456789abcdef",
  buildSha: "0123456789abcdef0123456789abcdef01234567",
};

const V4 = "12345678-1234-4234-8123-123456789abc";
const V4_B = "87654321-4321-4321-b123-abcdefabcdef";
const ORG = `openarc:org:${V4}`;
const POLICY = `openarc:policy:${V4}`;
const POLICY_B = `openarc:policy:${V4_B}`;
const AGENT = `openarc:agent:${V4}`;
const ACCOUNT_A = `openarc:account:${V4}`;
const ISO = "2026-01-01T00:00:00.000Z";
const ISO6 = "2026-01-01T00:00:00.123456Z";
const DIGEST = `sha256:${"a".repeat(64)}`;

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

function content(overrides: Record<string, unknown> = {}): CommercePolicyContent {
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
  } as CommercePolicyContent;
}

function root(
  policyId = POLICY,
  currentRevision = "1",
  overrides: Record<string, unknown> = {},
) {
  return {
    schemaVersion: "openarc.control.policy-root.v1",
    policyId,
    organizationId: ORG,
    subjectAgentId: AGENT,
    currentRevision,
    status: "active",
    createdAt: ISO,
    updatedAt: ISO6,
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

function receipt(operation: string, resourceId: string, mutationId: string) {
  const resourceType =
    operation === "control.policy.create"
      ? "budget_policy"
      : operation === "control.policy.revision.create"
        ? "budget_policy_revision"
        : "budget_policy";
  return { mutationId, operation, resourceType, resourceId, committedAt: ISO };
}

function fakeReads(
  role: CommerceHumanRole | null = "owner",
  organizationId: string | null = ORG,
): PolicyReadCoordinator & { abortCalls: number; reloads: number } {
  const reads = {
    abortCalls: 0,
    reloads: 0,
    currentOrganizationId: () => organizationId,
    currentRole: () => role,
    currentAccountId: () => ACCOUNT_A,
    abortPendingReads() {
      reads.abortCalls += 1;
    },
    async reloadAfterCommit() {
      reads.reloads += 1;
    },
  };
  return reads;
}

function fakeAccount(initialAccountId: string | null = ACCOUNT_A) {
  let currentAccountId = initialAccountId;
  let generation = 0;
  const account = {
    get generation() {
      return generation;
    },
    state: {
      status: initialAccountId === null ? "signed-out" : "signed-in",
      csrfToken: "csrf" as string | null,
      session: initialAccountId === null
        ? { signedIn: false as const }
        : { signedIn: true as const, accountId: initialAccountId, method: "passkey", expiresAt: "2030-01-01T00:00:00.000Z" },
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
    reads?: PolicyReadCoordinator;
    account?: AccountFlowController;
  } = {},
) {
  const reads = options.reads ?? fakeReads(options.role ?? "owner", options.organizationId ?? ORG);
  const account = options.account ?? fakeAccount();
  const controller = new PolicyController({
    account,
    reads,
    client: new PolicyClient({ fetcher: fetcher as unknown as typeof fetch }),
    capabilityReader: async () => options.capability ?? "enabled",
  });
  return { controller, reads: reads as ReturnType<typeof fakeReads>, account };
}

describe("policy role matrix", () => {
  it("allows exactly owner and operator to write", () => {
    expect(canWritePolicies("owner")).toBe(true);
    expect(canWritePolicies("operator")).toBe(true);
    expect(canWritePolicies("viewer")).toBe(false);
    expect(canWritePolicies("provider_admin")).toBe(false);
    expect(canWritePolicies("provider_developer")).toBe(false);
    expect(canWritePolicies(null)).toBe(false);
    expect(canWritePolicies("unknown")).toBe(false);
  });

  it("lets owner, operator and viewer read and denies provider roles", () => {
    expect(canReadPolicies("owner")).toBe(true);
    expect(canReadPolicies("operator")).toBe(true);
    expect(canReadPolicies("viewer")).toBe(true);
    expect(canReadPolicies("provider_admin")).toBe(false);
    expect(canReadPolicies("provider_developer")).toBe(false);
    expect(canReadPolicies(null)).toBe(false);
    expect(canReadPolicies("unknown")).toBe(false);
  });
});

describe("policy USDC conversion", () => {
  it("converts exactly six decimals with BigInt and never Number, zero valid", () => {
    expect(parseUsdcToAtomic("1")).toBe("1000000");
    expect(parseUsdcToAtomic("1.5")).toBe("1500000");
    expect(parseUsdcToAtomic("0.000001")).toBe("1");
    expect(parseUsdcToAtomic("0")).toBe("0");
    expect(formatUsdcFromAtomic("1000000")).toBe("1");
    expect(formatUsdcFromAtomic("1")).toBe("0.000001");
    expect(formatUsdcFromAtomic("0")).toBe("0");
  });

  it("rejects signs, exponents, whitespace and over-precision", () => {
    for (const bad of ["-1", "+1", "1e6", " 1", "01", "1.1234567", "", "abc"]) {
      expect(parseUsdcToAtomic(bad)).toBeNull();
    }
  });
});

describe("policy allowlist parsing", () => {
  it("accepts one canonical id per line, ascending unique", () => {
    const lower = `openarc:provider:${V4}`;
    const higher = `openarc:provider:${V4_B}`;
    expect(parseCanonicalIdList(`${higher}\n${lower}`, "provider")).toEqual([...([lower, higher].sort())]);
    expect(parseCanonicalIdList("", "provider")).toEqual([]);
  });

  it("rejects duplicates and non-canonical ids", () => {
    const id = `openarc:listing:${V4}`;
    expect(parseCanonicalIdList(`${id}\n${id}`, "listing")).toBeNull();
    expect(parseCanonicalIdList("not-an-id", "listing")).toBeNull();
  });
});

describe("policy history helpers", () => {
  it("bounds the cursor stack at 20", () => {
    let stack: readonly string[] = [];
    for (let index = 0; index < 25; index += 1) stack = appendPolicyCursor(stack, String(index));
    expect(stack.length).toBe(20);
    expect(stack[0]).toBe("5");
    expect(stack[19]).toBe("24");
  });

  it("uses the authoritative root currentRevision+updatedAt as the CAS root", () => {
    expect(policyCasOf(root(POLICY, "7") as never)).toEqual({
      expectedRevision: "7",
      expectedUpdatedAt: ISO6,
    });
  });

  it("extracts the canonical policy resource and successor revision", () => {
    expect(policyIdOfReceipt(receipt("control.policy.create", POLICY, V4) as never)).toBe(POLICY);
    expect(policyIdOfReceipt(receipt("control.policy.revision.create", `${POLICY}@2`, V4) as never)).toBe(POLICY);
    expect(revisionOfReceipt(receipt("control.policy.revision.create", `${POLICY}@2`, V4) as never)).toBe("2");
    expect(revisionOfReceipt(receipt("control.policy.pause", POLICY, V4) as never)).toBeNull();
  });
});

describe("policy controller capability gate", () => {
  it("makes no policy request when the capability is built_disabled", async () => {
    const fetcher = vi.fn(async () => success({ organizationId: ORG, items: [], nextCursor: null }));
    const { controller } = controllerWith(fetcher as unknown as typeof fetch, { capability: "built_disabled" });
    await controller.initialize({ kind: "roots" });
    expect(fetcher).not.toHaveBeenCalled();
    expect(controller.state.capability).toBe("unavailable");
  });

  it("makes no policy request when the capability is unavailable", async () => {
    const fetcher = vi.fn(async () => success({ organizationId: ORG, items: [], nextCursor: null }));
    const { controller } = controllerWith(fetcher as unknown as typeof fetch, { capability: "unavailable" });
    await controller.initialize({ kind: "roots" });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("loads roots only after the capability is enabled", async () => {
    const fetcher = vi.fn(async () => success({ organizationId: ORG, items: [root()], nextCursor: null }));
    const { controller } = controllerWith(fetcher as unknown as typeof fetch);
    await controller.initialize({ kind: "roots" });
    expect(controller.state.capability).toBe("enabled");
    expect(controller.state.roots.status).toBe("ready");
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
});

describe("policy controller reads", () => {
  it("bounds the root page and exposes an explicit next cursor", async () => {
    const fetcher = vi.fn(async (input: string) =>
      input.includes("afterPolicyId")
        ? success({ organizationId: ORG, items: [], nextCursor: null })
        : success({ organizationId: ORG, items: [root()], nextCursor: POLICY }),
    );
    const { controller } = controllerWith(fetcher as unknown as typeof fetch);
    await controller.initialize({ kind: "roots" });
    expect(controller.state.roots.nextCursor).toBe(POLICY);
    await controller.loadNextRoots();
    expect(controller.state.roots.hasPrevious).toBe(true);
    const secondPath = (fetcher.mock.calls as unknown as Array<[string]>)[1]?.[0] ?? "";
    expect(secondPath).toContain(`afterPolicyId=${encodeURIComponent(POLICY)}`);
  });

  it("fetches root and first history independently and keeps a truthful not-found", async () => {
    const fetcher = vi.fn(async (input: string) =>
      input.includes("/revisions")
        ? success({ organizationId: ORG, policyId: POLICY, items: [summary("1")], nextCursor: null })
        : success({ organizationId: ORG, policyId: POLICY, item: null }),
    );
    const { controller } = controllerWith(fetcher as unknown as typeof fetch);
    await controller.initialize({ kind: "detail", policyId: POLICY });
    expect(controller.state.detail.status).toBe("not-found");
    expect(controller.state.detail.history.items).toHaveLength(1);
  });

  it("paginates history across 2 before 10 and marks the final page complete", async () => {
    const fetcher = vi.fn(async (input: string) => {
      if (input.includes("/revisions") && input.includes("afterRevision=10")) {
        return success({ organizationId: ORG, policyId: POLICY, items: [summary("11")], nextCursor: null });
      }
      if (input.includes("/revisions")) {
        return success({ organizationId: ORG, policyId: POLICY, items: [summary("1"), summary("10")], nextCursor: "10" });
      }
      return success({ organizationId: ORG, policyId: POLICY, item: root(POLICY, "10") });
    });
    const { controller } = controllerWith(fetcher as unknown as typeof fetch);
    await controller.initialize({ kind: "detail", policyId: POLICY });
    expect(controller.state.detail.history.historyComplete).toBe(false);
    expect(controller.state.detail.history.items.map((item) => item.revision)).toEqual(["1", "10"]);
    expect(controller.state.detail.history.nextCursor).toBe("10");
    await controller.loadMoreRevisions();
    expect(controller.state.detail.history.historyComplete).toBe(true);
    expect(controller.state.detail.history.cursorStack).toEqual(["10"]);
  });

  it("reads a full revision separately from metadata-only summaries", async () => {
    const fetcher = vi.fn(async (input: string) => {
      if (/\/revisions\/2$/u.test(input)) {
        return success({ organizationId: ORG, policyId: POLICY, revision: "2", item: revision("2") });
      }
      if (input.includes("/revisions")) {
        return success({ organizationId: ORG, policyId: POLICY, items: [summary("1")], nextCursor: null });
      }
      return success({ organizationId: ORG, policyId: POLICY, item: root(POLICY, "1") });
    });
    const { controller } = controllerWith(fetcher as unknown as typeof fetch);
    await controller.initialize({ kind: "detail", policyId: POLICY });
    expect(controller.state.revision.status).toBe("none");
    const ok = await controller.readRevision("2");
    expect(ok).toBe(true);
    expect(controller.state.revision.revision?.revision).toBe("2");
    expect(controller.state.revision.revision?.perActionLimit).toBe("1000000");
  });
});

describe("policy controller CAS", () => {
  it("uses the authoritative root currentRevision and exact-microsecond updatedAt, not the history page", async () => {
    const routed = vi.fn(async (input: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        const body = JSON.parse(String(init.body)) as {
          mutationId: string;
          expectedRevision: string;
          expectedUpdatedAt: string;
        };
        return success({
          organizationId: ORG,
          replayed: false,
          receipt: receipt("control.policy.revision.create", `${POLICY}@3`, body.mutationId),
        });
      }
      if (input.includes("/revisions")) {
        // The final history page reports revision 2, but the authoritative root
        // reports currentRevision 2 with its own exact updatedAt.
        return success({ organizationId: ORG, policyId: POLICY, items: [summary("1"), summary("2")], nextCursor: null });
      }
      return success({ organizationId: ORG, policyId: POLICY, item: root(POLICY, "2", { updatedAt: "2026-03-03T00:00:00.000001Z" }) });
    });
    const { controller } = controllerWith(routed as unknown as typeof fetch);
    await controller.initialize({ kind: "detail", policyId: POLICY });
    expect(controller.beginAppend(content())).toBe(true);
    await controller.confirm();
    const post = (routed.mock.calls as unknown as Array<[string, RequestInit]>).find(([, init]) => init?.method === "POST");
    expect(post).toBeDefined();
    const body = JSON.parse(String(post![1].body)) as { expectedRevision: string; expectedUpdatedAt: string };
    expect(body.expectedRevision).toBe("2");
    expect(body.expectedUpdatedAt).toBe("2026-03-03T00:00:00.000001Z");
    expect(controller.state.mutation.kind).toBe("committed");
  });

  it("refuses an append when there is no authoritative root", async () => {
    const fetcher = vi.fn(async (input: string) =>
      input.includes("/revisions")
        ? success({ organizationId: ORG, policyId: POLICY, items: [], nextCursor: null })
        : success({ organizationId: ORG, policyId: POLICY, item: null }),
    );
    const { controller } = controllerWith(fetcher as unknown as typeof fetch);
    await controller.initialize({ kind: "detail", policyId: POLICY });
    expect(controller.beginAppend(content())).toBe(false);
  });

  it("permits lifecycle only for the matching root status and requires the exact CAS", async () => {
    const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        const body = JSON.parse(String(init.body)) as { mutationId: string };
        return success({
          organizationId: ORG,
          replayed: false,
          receipt: receipt("control.policy.pause", POLICY, body.mutationId),
        });
      }
      return success({ organizationId: ORG, policyId: POLICY, item: root(POLICY, "1", { status: "active" }) });
    });
    const { controller } = controllerWith(fetcher as unknown as typeof fetch);
    await controller.initialize({ kind: "detail", policyId: POLICY });
    expect(controller.beginLifecycle("pause")).toBe(true);
    await controller.confirm();
    const post = (fetcher.mock.calls as unknown as Array<[string, RequestInit]>).find(([, init]) => init?.method === "POST");
    const body = JSON.parse(String(post![1].body)) as { expectedRevision: string; expectedUpdatedAt: string };
    expect(body.expectedRevision).toBe("1");
    expect(body.expectedUpdatedAt).toBe(ISO6);
  });

  it("refuses resume on an active root and pause on a paused root", async () => {
    const fetcher = vi.fn(async () =>
      success({ organizationId: ORG, policyId: POLICY, item: root(POLICY, "1", { status: "active" }) }),
    );
    const { controller } = controllerWith(fetcher as unknown as typeof fetch);
    await controller.initialize({ kind: "detail", policyId: POLICY });
    expect(controller.beginLifecycle("resume")).toBe(false);
    expect(controller.beginLifecycle("pause")).toBe(true);
  });
});

describe("policy controller mutation outcomes", () => {
  it("creates a policy, stores the DB-generated canonical resource and opens it only after commit", async () => {
    const opened: string[] = [];
    let postedMutationId: string | null = null;
    const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        const body = JSON.parse(String(init.body)) as { mutationId: string };
        postedMutationId = body.mutationId;
        return success({
          organizationId: ORG,
          replayed: false,
          // The database chose a canonical policy id that is NOT derived from
          // the mutation id.
          receipt: receipt("control.policy.create", POLICY_B, body.mutationId),
        });
      }
      return success({ organizationId: ORG, items: [], nextCursor: null });
    });
    const controller = new PolicyController({
      account: fakeAccount(),
      reads: fakeReads(),
      client: new PolicyClient({ fetcher: fetcher as unknown as typeof fetch }),
      capabilityReader: async () => "enabled",
      onCommittedPolicy: (policyId) => opened.push(policyId),
    });
    await controller.initialize({ kind: "new" });
    expect(opened).toEqual([]);
    expect(controller.beginCreate(content())).toBe(true);
    await controller.confirm();
    expect(opened).toEqual([POLICY_B]);
    expect(controller.state.mutation.kind).toBe("committed");
    if (controller.state.mutation.kind === "committed") {
      expect(controller.state.mutation.policyId).toBe(POLICY_B);
    }
    expect(postedMutationId).not.toBeNull();
  });

  it("treats a transport failure after send as outcome-unknown with no resend", async () => {
    let posts = 0;
    const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        posts += 1;
        throw new Error("reset");
      }
      return success({ organizationId: ORG, policyId: POLICY, item: root(POLICY, "1", { status: "active" }) });
    });
    const { controller } = controllerWith(fetcher as unknown as typeof fetch);
    await controller.initialize({ kind: "detail", policyId: POLICY });
    expect(controller.beginLifecycle("pause")).toBe(true);
    await controller.confirm();
    expect(controller.state.mutation.kind).toBe("outcome-unknown");
    expect(posts).toBe(1);
  });

  it("resolves an unknown outcome only by an explicit original-id status GET and never resends", async () => {
    let posts = 0;
    let postedMutationId: string | null = null;
    const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        posts += 1;
        const body = JSON.parse(String(init.body)) as { mutationId: string };
        postedMutationId = body.mutationId;
        throw new Error("reset");
      }
      if (input.includes("policy-mutations/")) {
        return success({
          organizationId: ORG,
          mutationId: postedMutationId,
          status: "committed",
          receipt: receipt("control.policy.pause", POLICY, postedMutationId!),
        });
      }
      return success({ organizationId: ORG, policyId: POLICY, item: root(POLICY, "1", { status: "active" }) });
    });
    const { controller } = controllerWith(fetcher as unknown as typeof fetch);
    await controller.initialize({ kind: "detail", policyId: POLICY });
    controller.beginLifecycle("pause");
    await controller.confirm();
    expect(controller.state.mutation.kind).toBe("outcome-unknown");
    await controller.checkStatus();
    expect(controller.state.mutation.kind).toBe("committed");
    expect(posts).toBe(1);
    const statusCalls = (fetcher.mock.calls as unknown as Array<[string]>).filter(([path]) =>
      path.includes("policy-mutations/"),
    );
    expect(statusCalls).toHaveLength(1);
    expect(statusCalls[0]![0]).toContain(`/${postedMutationId}`);
  });

  it("never enables a resend on not_found and keeps the original id", async () => {
    let posts = 0;
    let postedMutationId: string | null = null;
    const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        posts += 1;
        const body = JSON.parse(String(init.body)) as { mutationId: string };
        postedMutationId = body.mutationId;
        throw new Error("reset");
      }
      if (input.includes("policy-mutations/")) {
        return success({ organizationId: ORG, mutationId: postedMutationId, status: "not_found" });
      }
      return success({ organizationId: ORG, policyId: POLICY, item: root(POLICY, "1", { status: "active" }) });
    });
    const { controller } = controllerWith(fetcher as unknown as typeof fetch);
    await controller.initialize({ kind: "detail", policyId: POLICY });
    controller.beginLifecycle("pause");
    await controller.confirm();
    await controller.checkStatus();
    const after = controller.state.mutation;
    expect(after.kind).toBe("outcome-unknown");
    if (after.kind === "outcome-unknown") {
      expect(after.mutationId).toBe(postedMutationId);
      expect(after.checking).toBe(false);
      expect(after.statusMessage).not.toBeNull();
    }
    expect(posts).toBe(1);
  });

  it("keeps an invalid post-send success outcome-unknown with original-ID status only and never resends", async () => {
    let posts = 0;
    let postedMutationId: string | null = null;
    const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        posts += 1;
        const body = JSON.parse(String(init.body)) as { mutationId: string };
        postedMutationId = body.mutationId;
        // A canonical-foreign-org success the client must reject: the write may
        // actually have committed, so it is NEVER resendable.
        return success({
          organizationId: `openarc:org:${V4_B}`,
          replayed: false,
          receipt: receipt("control.policy.pause", POLICY, body.mutationId),
        });
      }
      if (input.includes("policy-mutations/")) {
        return success({ organizationId: ORG, mutationId: postedMutationId, status: "not_found" });
      }
      return success({ organizationId: ORG, policyId: POLICY, item: root(POLICY, "1", { status: "active" }) });
    });
    const { controller } = controllerWith(fetcher as unknown as typeof fetch);
    await controller.initialize({ kind: "detail", policyId: POLICY });
    expect(controller.beginLifecycle("pause")).toBe(true);
    await controller.confirm();
    const unknown = controller.state.mutation;
    expect(unknown.kind).toBe("outcome-unknown");
    expect(posts).toBe(1);
    if (unknown.kind !== "outcome-unknown") return;
    expect(unknown.mutationId).toBe(postedMutationId);
    // Only an explicit status GET with the ORIGINAL id is allowed.
    await controller.checkStatus();
    expect(posts).toBe(1);
    const statusCalls = (fetcher.mock.calls as unknown as Array<[string]>).filter(([path]) =>
      path.includes("policy-mutations/"),
    );
    expect(statusCalls).toHaveLength(1);
    expect(statusCalls[0]![0]).toContain(`/${postedMutationId}`);
    const after = controller.state.mutation;
    expect(after.kind).toBe("outcome-unknown");
    if (after.kind === "outcome-unknown") {
      expect(after.mutationId).toBe(postedMutationId);
    }
  });

  it("stores the committed receipt even when the post-commit refresh fails", async () => {
    const reads = fakeReads();
    reads.reloadAfterCommit = async () => {
      throw new Error("refresh failed");
    };
    const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        const body = JSON.parse(String(init.body)) as { mutationId: string };
        return success({
          organizationId: ORG,
          replayed: false,
          receipt: receipt("control.policy.pause", POLICY, body.mutationId),
        });
      }
      return success({ organizationId: ORG, policyId: POLICY, item: root(POLICY, "1", { status: "active" }) });
    });
    const { controller } = controllerWith(fetcher as unknown as typeof fetch, { reads });
    await controller.initialize({ kind: "detail", policyId: POLICY });
    controller.beginLifecycle("pause");
    await controller.confirm();
    expect(controller.state.mutation.kind).toBe("committed");
    if (controller.state.mutation.kind === "committed") {
      expect(controller.state.mutation.refreshError).toBe(true);
    }
  });

  it("maps a definite conflict to a reviewable notice without auto-resubmission", async () => {
    const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
      if (init?.method === "POST") return errorEnvelope("IDEMPOTENCY_CONFLICT", 409);
      return success({ organizationId: ORG, policyId: POLICY, item: root(POLICY, "1", { status: "active" }) });
    });
    const { controller } = controllerWith(fetcher as unknown as typeof fetch);
    await controller.initialize({ kind: "detail", policyId: POLICY });
    controller.beginLifecycle("pause");
    await controller.confirm();
    expect(controller.state.mutation.kind).toBe("rejected");
    if (controller.state.mutation.kind === "rejected") {
      expect(controller.state.mutation.notice.kind).toBe("conflict");
    }
  });
});

describe("policy controller stale context and erasure", () => {
  it("suppresses a stale account/org/role context render", () => {
    const bound = { accountId: ACCOUNT_A, organizationId: ORG, role: "owner" };
    expect(suppressStalePolicyContext(bound, bound)).toBe(false);
    expect(suppressStalePolicyContext(bound, { accountId: `openarc:account:${V4_B}`, organizationId: ORG, role: "owner" })).toBe(true);
    expect(suppressStalePolicyContext(bound, { accountId: ACCOUNT_A, organizationId: `openarc:org:${V4_B}`, role: "owner" })).toBe(true);
    expect(suppressStalePolicyContext(bound, { accountId: ACCOUNT_A, organizationId: ORG, role: "viewer" })).toBe(true);
    expect(suppressStalePolicyContext(bound, { accountId: null, organizationId: ORG, role: null })).toBe(true);
    expect(suppressStalePolicyContext(null, bound)).toBe(false);
  });

  it("ignores a stale organization response", async () => {
    const deferred: { resolve: ((value: Response) => void) | null } = { resolve: null };
    const reads = fakeReads();
    const fetcher = vi.fn(
      () =>
        new Promise<Response>((resolve) => {
          deferred.resolve = resolve;
        }),
    );
    const { controller } = controllerWith(fetcher as unknown as typeof fetch, { reads });
    const pending = controller.initialize({ kind: "roots" });
    // Context changed while the read was in flight.
    (reads as { currentOrganizationId: () => string | null }).currentOrganizationId = () =>
      `openarc:org:${V4_B}`;
    controller.clear();
    deferred.resolve?.(success({ organizationId: ORG, items: [root()], nextCursor: null }));
    await pending;
    expect(controller.state.roots.status).toBe("none");
    expect(controller.state.roots.items).toHaveLength(0);
  });

  it("clears reads, selection, revision and mutation on clear()", async () => {
    const fetcher = vi.fn(async (input: string) => {
      if (/\/revisions\/1$/u.test(input)) {
        return success({ organizationId: ORG, policyId: POLICY, revision: "1", item: revision("1") });
      }
      if (input.includes("/revisions")) {
        return success({ organizationId: ORG, policyId: POLICY, items: [summary("1")], nextCursor: null });
      }
      return success({ organizationId: ORG, policyId: POLICY, item: root(POLICY, "1") });
    });
    const { controller } = controllerWith(fetcher as unknown as typeof fetch);
    await controller.initialize({ kind: "detail", policyId: POLICY });
    await controller.readRevision("1");
    expect(controller.state.revision.revision).not.toBeNull();
    controller.clear();
    expect(controller.state.selection.selectedRevision).toBeNull();
    expect(controller.state.revision.revision).toBeNull();
    expect(controller.state.mutation.kind).toBe("idle");
    expect(controller.state.detail.status).toBe("none");
    expect(controller.state.roots.status).toBe("none");
  });

  it("clears on a role change so a viewer never sees owner controls", async () => {
    const fetcher = vi.fn(async () => success({ organizationId: ORG, policyId: POLICY, item: root(POLICY, "1") }));
    const reads = fakeReads("owner");
    const { controller } = controllerWith(fetcher as unknown as typeof fetch, { reads });
    await controller.initialize({ kind: "detail", policyId: POLICY });
    expect(controller.state.canWrite).toBe(true);
    (reads as { currentRole: () => string | null }).currentRole = () => "viewer";
    controller.reconcileRole("viewer");
    expect(controller.state.canWrite).toBe(false);
  });

  it("denies provider roles any write control", async () => {
    const fetcher = vi.fn(async () => success({ organizationId: ORG, policyId: POLICY, item: root(POLICY, "1") }));
    const { controller } = controllerWith(fetcher as unknown as typeof fetch, { role: "provider_admin" });
    await controller.initialize({ kind: "detail", policyId: POLICY });
    expect(controller.state.canWrite).toBe(false);
    expect(controller.beginCreate(content())).toBe(false);
  });

  it("aborts the capability probe on clear and suppresses the late response", async () => {
    const deferred: { resolve: ((state: "enabled" | "unavailable") => void) | null } = { resolve: null };
    let receivedSignal: AbortSignal | null = null;
    const capabilityReader = (signal: AbortSignal) =>
      new Promise<"enabled" | "unavailable">((resolve) => {
        receivedSignal = signal;
        deferred.resolve = resolve;
      });
    const fetcher = vi.fn(async () => success({ organizationId: ORG, items: [], nextCursor: null }));
    const controller = new PolicyController({
      account: fakeAccount(),
      reads: fakeReads(),
      client: new PolicyClient({ fetcher: fetcher as unknown as typeof fetch }),
      capabilityReader,
    });
    const pending = controller.initialize({ kind: "roots" });
    expect(controller.state.capability).toBe("checking");
    controller.clear();
    expect((receivedSignal as AbortSignal | null)?.aborted).toBe(true);
    deferred.resolve?.("enabled");
    await pending;
    expect(controller.state.capability).not.toBe("enabled");
    expect(fetcher).not.toHaveBeenCalled();
  });
});

describe("policy content builders", () => {
  it("extracts content from a full revision and builds a valid append base", () => {
    const built = contentFromRevision(revision("3") as never);
    expect(built).not.toBeNull();
    expect(built?.perActionLimit).toBe("1000000");
    expect(built?.feeLimit).toBe("10000");
  });

  it("refuses to derive content from an invalid revision", () => {
    expect(contentFromRevision({ revision: "1" } as never)).toBeNull();
  });

  it("appends from the selected immutable revision with the prior content", async () => {
    const appended: string[] = [];
    const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        const body = JSON.parse(String(init.body)) as { mutationId: string; content: { perActionLimit: string } };
        appended.push(body.content.perActionLimit);
        return success({
          organizationId: ORG,
          replayed: false,
          receipt: receipt("control.policy.revision.create", `${POLICY}@4`, body.mutationId),
        });
      }
      if (/\/revisions\/3$/u.test(input)) {
        return success({ organizationId: ORG, policyId: POLICY, revision: "3", item: revision("3", { perActionLimit: "2000000" }) });
      }
      if (input.includes("/revisions")) {
        return success({ organizationId: ORG, policyId: POLICY, items: [summary("3")], nextCursor: null });
      }
      return success({ organizationId: ORG, policyId: POLICY, item: root(POLICY, "3") });
    });
    const { controller } = controllerWith(fetcher as unknown as typeof fetch);
    await controller.initialize({ kind: "detail", policyId: POLICY });
    await controller.readRevision("3");
    const selected = controller.state.revision.revision;
    expect(selected).not.toBeNull();
    expect(beginAppendFromRevision(controller, selected!)).toBe(true);
    await controller.confirm();
    expect(appended).toEqual(["2000000"]);
  });

  it("computes the exact create/append/transition expected resources", () => {
    expect(expectedResourceIdOf({ op: "create", content: content() }, V4)).toBeNull();
    expect(
      expectedResourceIdOf(
        { op: "append", policyId: POLICY, cas: { expectedRevision: "10", expectedUpdatedAt: ISO }, content: content() },
        V4,
      ),
    ).toBe(`${POLICY}@11`);
    expect(
      expectedResourceIdOf(
        { op: "revoke", policyId: POLICY, cas: { expectedRevision: "1", expectedUpdatedAt: ISO } },
        V4,
      ),
    ).toBe(POLICY);
  });
});
