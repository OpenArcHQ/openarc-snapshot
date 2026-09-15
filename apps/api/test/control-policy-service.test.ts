import { describe, expect, it } from "vitest";

import {
  ControlPolicyStoreError,
  type ControlPolicyMutationResult,
  type ControlPolicyMutationStatus,
  type ListPolicyRevisionsResult,
  type ListPolicyRootsResult,
  type PolicyRevisionSummary,
} from "@openarc/db";
import type {
  CommercePolicyRevision,
  CommercePolicyRoot,
} from "@openarc/shared";

import { AUTH_ERRORS, type AuthApiError } from "../src/auth/errors.js";
import type { AuthRequestContext } from "../src/auth/service.js";
import { PolicyService } from "../src/control/service.js";
import type {
  ControlPolicyAuthPort,
  ControlPolicyStorePort,
} from "../src/control/ports.js";

/**
 * Unit coverage for the protected control policy service.
 *
 * The ControlPolicyStore and auth seam are HONESTLY MOCKED: these tests prove
 * request validation BEFORE auth, CSRF-then-begin ordering and exactly one
 * repository invocation for writes, begin/repository/finish ordering for reads,
 * strict whole-result projection/binding (including unknown keys), closed
 * store-error mapping and slot redaction. Real roles, sessions, locks,
 * idempotency, CAS and SQL enforcement are a separately owned REAL-PG packet;
 * nothing here claims a real PostgreSQL run.
 */

const MUTATION = "12345678-1234-4234-8123-123456789abc";
const MUTATION2 = "22345678-1234-4234-8123-123456789abc";
const ORG = `openarc:org:${MUTATION}`;
const ORG2 = `openarc:org:${MUTATION2}`;
const AGENT = `openarc:agent:${MUTATION}`;
const AGENT2 = `openarc:agent:${MUTATION2}`;
const POLICY = `openarc:policy:${MUTATION}`;
const POLICY2 = `openarc:policy:${MUTATION2}`;
const PROVIDER = `openarc:provider:${MUTATION}`;
const HASH = "a".repeat(64);
const ACCOUNT = `openarc:account:${MUTATION}`;
const IDEMPOTENCY = "A".repeat(43);
const ISO = "2026-01-01T00:00:00.000Z";
const DIGEST = `sha256:${"1".repeat(64)}`;

function content(overrides: Record<string, unknown> = {}): Record<string, unknown> {
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
    allowedProviderIds: [PROVIDER],
    allowedListingIds: [],
    approval: { mode: "none", threshold: null, separateApprover: false },
    expiresAt: null,
    ...overrides,
  };
}

function rootItem(overrides: Record<string, unknown> = {}): CommercePolicyRoot {
  return {
    schemaVersion: "openarc.control.policy-root.v1",
    policyId: POLICY,
    organizationId: ORG,
    subjectAgentId: AGENT,
    currentRevision: "1",
    status: "active",
    createdAt: ISO,
    updatedAt: ISO,
    ...overrides,
  } as CommercePolicyRoot;
}

function revisionItem(
  overrides: Record<string, unknown> = {},
): CommercePolicyRevision {
  return {
    schemaVersion: "openarc.control.policy.v1",
    policyId: POLICY,
    revision: "1",
    ...content(),
    createdAt: ISO,
    digest: DIGEST,
    ...overrides,
  } as CommercePolicyRevision;
}

function summaryItem(
  overrides: Record<string, unknown> = {},
): PolicyRevisionSummary {
  return {
    policyId: POLICY,
    organizationId: ORG,
    subjectAgentId: AGENT,
    revision: "1",
    digest: DIGEST,
    createdAt: ISO,
    expiresAt: null,
    ...overrides,
  } as PolicyRevisionSummary;
}

function mutationResult(
  overrides: Record<string, unknown> = {},
): ControlPolicyMutationResult {
  return {
    replayed: false,
    receipt: {
      mutationId: MUTATION,
      operation: "control.policy.create",
      resourceType: "budget_policy",
      resourceId: POLICY,
      committedAt: ISO,
      ...overrides,
    },
  } as ControlPolicyMutationResult;
}

class FakeStore implements ControlPolicyStorePort {
  calls: string[] = [];
  error: unknown;
  createResult: unknown = mutationResult();
  appendResult: unknown = mutationResult({
    operation: "control.policy.revision.create",
    resourceType: "budget_policy_revision",
    resourceId: `${POLICY}@2`,
  });
  transitionResult: unknown = mutationResult({
    operation: "control.policy.pause",
    resourceType: "budget_policy",
    resourceId: POLICY,
  });
  rootResult: unknown = rootItem();
  rootsResult: unknown = { items: [rootItem()], nextCursor: null };
  revisionResult: unknown = revisionItem();
  revisionsResult: unknown = { items: [summaryItem()], nextCursor: null };
  statusResult: unknown = { status: "not_found" };

  #record(name: string): void {
    this.calls.push(name);
    if (this.error) throw this.error;
  }

  async createPolicy(): Promise<ControlPolicyMutationResult> {
    this.#record("createPolicy");
    return this.createResult as ControlPolicyMutationResult;
  }
  async appendPolicyRevision(): Promise<ControlPolicyMutationResult> {
    this.#record("appendPolicyRevision");
    return this.appendResult as ControlPolicyMutationResult;
  }
  async transitionPolicy(): Promise<ControlPolicyMutationResult> {
    this.#record("transitionPolicy");
    return this.transitionResult as ControlPolicyMutationResult;
  }
  async getPolicyRoot(): Promise<CommercePolicyRoot | null> {
    this.#record("getPolicyRoot");
    return this.rootResult as CommercePolicyRoot | null;
  }
  async listPolicyRoots(): Promise<ListPolicyRootsResult> {
    this.#record("listPolicyRoots");
    return this.rootsResult as ListPolicyRootsResult;
  }
  async getPolicyRevision(): Promise<CommercePolicyRevision | null> {
    this.#record("getPolicyRevision");
    return this.revisionResult as CommercePolicyRevision | null;
  }
  async listPolicyRevisions(): Promise<ListPolicyRevisionsResult> {
    this.#record("listPolicyRevisions");
    return this.revisionsResult as ListPolicyRevisionsResult;
  }
  async getPolicyMutationStatus(): Promise<ControlPolicyMutationStatus> {
    this.#record("getPolicyMutationStatus");
    return this.statusResult as ControlPolicyMutationStatus;
  }
}

class FakeAuth implements ControlPolicyAuthPort {
  csrfCalls = 0;
  beginCalls = 0;
  finishCalls = 0;
  order: string[] = [];
  csrfCookies: unknown[] = [];
  beginCtx: AuthRequestContext[] = [];
  csrfError: AuthApiError | undefined;
  beginError: AuthApiError | undefined;
  finishError: AuthApiError | undefined;

  verifyCsrf(cookies: AuthRequestContext["cookies"]): string {
    this.csrfCalls += 1;
    this.order.push("csrf");
    this.csrfCookies.push(cookies);
    if (this.csrfError) throw this.csrfError;
    return "binding";
  }
  async beginTenantRead(
    context: AuthRequestContext,
  ): Promise<{ sessionHash: string; accountId: string }> {
    this.beginCalls += 1;
    this.order.push("begin");
    this.beginCtx.push(context);
    if (this.beginError) throw this.beginError;
    return { sessionHash: HASH, accountId: ACCOUNT };
  }
  async finishTenantRead(): Promise<void> {
    this.finishCalls += 1;
    this.order.push("finish");
    if (this.finishError) throw this.finishError;
  }
}

function ctx(): AuthRequestContext {
  return { peerIp: "127.0.0.1", cookies: { session: null, binding: null } };
}

function harness() {
  const store = new FakeStore();
  const auth = new FakeAuth();
  const service = new PolicyService({ auth, store });
  return { store, auth, service };
}

function writeEnvelope(body: unknown) {
  return {
    csrf: "csrf",
    idempotencyKey: IDEMPOTENCY,
    body,
  };
}

describe("policy service read ordering and binding", () => {
  it("lists roots through begin -> one read -> finish", async () => {
    const { store, auth, service } = harness();
    const page = await service.listPolicyRoots(ctx(), { organizationId: ORG });
    expect(page.organizationId).toBe(ORG);
    expect(page.items).toHaveLength(1);
    expect(auth.order).toEqual(["begin", "finish"]);
    expect(store.calls).toEqual(["listPolicyRoots"]);
  });

  it("rejects an extra store envelope key before projection", async () => {
    const { store, service } = harness();
    store.rootsResult = { items: [], nextCursor: null, secret: "PRIVATE" };
    await expect(
      service.listPolicyRoots(ctx(), { organizationId: ORG }),
    ).rejects.toMatchObject({ status: 503 });
  });

  it("rejects over-limit pages and items not strictly beyond the cursor", async () => {
    const over = harness();
    over.store.rootsResult = { items: [rootItem()], nextCursor: null };
    await expect(
      over.service.listPolicyRoots(ctx(), { organizationId: ORG, limit: "0" }),
    ).rejects.toMatchObject({ status: 400 });

    const cursor = harness();
    cursor.store.rootsResult = {
      items: [rootItem({ policyId: POLICY })],
      nextCursor: null,
    };
    await expect(
      cursor.service.listPolicyRoots(ctx(), {
        organizationId: ORG,
        afterPolicyId: POLICY,
      }),
    ).rejects.toMatchObject({ status: 503 });
  });

  it("binds items to the requested organization", async () => {
    const { store, service } = harness();
    store.rootsResult = {
      items: [rootItem({ organizationId: ORG2 })],
      nextCursor: null,
    };
    await expect(
      service.listPolicyRoots(ctx(), { organizationId: ORG }),
    ).rejects.toMatchObject({ status: 503 });
  });

  it("returns {item:null} 200 for an authorized root miss and finishes first", async () => {
    const { store, auth, service } = harness();
    store.rootResult = null;
    const detail = await service.getPolicyRoot(ctx(), {
      organizationId: ORG,
      policyId: POLICY,
    });
    expect(detail.item).toBeNull();
    expect(auth.order).toEqual(["begin", "finish"]);
  });

  it("rejects an extra root key and a cross-policy root", async () => {
    const extra = harness();
    extra.store.rootResult = { ...rootItem(), secret: "PRIVATE" };
    await expect(
      extra.service.getPolicyRoot(ctx(), { organizationId: ORG, policyId: POLICY }),
    ).rejects.toMatchObject({ status: 503 });

    const cross = harness();
    cross.store.rootResult = rootItem({ policyId: POLICY2 });
    await expect(
      cross.service.getPolicyRoot(ctx(), { organizationId: ORG, policyId: POLICY }),
    ).rejects.toMatchObject({ status: 503 });
  });

  it("orders history by numeric revision and enforces one subject", async () => {
    const { store, service } = harness();
    store.revisionsResult = {
      items: [
        summaryItem({ revision: "2" }),
        summaryItem({ revision: "10" }),
      ],
      nextCursor: null,
    };
    const page = await service.listPolicyRevisions(ctx(), {
      organizationId: ORG,
      policyId: POLICY,
    });
    expect(page.items.map((item) => item.revision)).toEqual(["2", "10"]);

    const mixed = harness();
    mixed.store.revisionsResult = {
      items: [
        summaryItem({ revision: "1" }),
        summaryItem({ revision: "2", subjectAgentId: AGENT2 }),
      ],
      nextCursor: null,
    };
    await expect(
      mixed.service.listPolicyRevisions(ctx(), {
        organizationId: ORG,
        policyId: POLICY,
      }),
    ).rejects.toMatchObject({ status: 503 });
  });

  it("rejects a history item not strictly beyond afterRevision", async () => {
    const { store, service } = harness();
    store.revisionsResult = {
      items: [summaryItem({ revision: "2" })],
      nextCursor: null,
    };
    await expect(
      service.listPolicyRevisions(ctx(), {
        organizationId: ORG,
        policyId: POLICY,
        afterRevision: "2",
      }),
    ).rejects.toMatchObject({ status: 503 });
  });

  it("returns {item:null} 200 for an authorized revision miss", async () => {
    const { store, service } = harness();
    store.revisionResult = null;
    const detail = await service.getPolicyRevision(ctx(), {
      organizationId: ORG,
      policyId: POLICY,
      revision: "7",
    });
    expect(detail.item).toBeNull();
  });

  it("rejects a mismatched revision binding", async () => {
    const { store, service } = harness();
    store.revisionResult = revisionItem({ revision: "2" });
    await expect(
      service.getPolicyRevision(ctx(), {
        organizationId: ORG,
        policyId: POLICY,
        revision: "1",
      }),
    ).rejects.toMatchObject({ status: 503 });
  });

  it("rejects a read whose live session is revoked after the store call", async () => {
    const { store, auth, service } = harness();
    auth.finishError = AUTH_ERRORS.unauthenticated();
    await expect(
      service.listPolicyRoots(ctx(), { organizationId: ORG }),
    ).rejects.toMatchObject({ status: 401 });
    expect(store.calls).toEqual(["listPolicyRoots"]);
    expect(auth.order).toEqual(["begin", "finish"]);
  });
});

describe("policy service status variants", () => {
  it("serves a valid not_found status after finishing the read", async () => {
    const { auth, service } = harness();
    const status = await service.getPolicyMutationStatus(ctx(), {
      organizationId: ORG,
      mutationId: MUTATION,
    });
    expect(status.status).toBe("not_found");
    expect(auth.order).toEqual(["begin", "finish"]);
  });

  it("rejects a not_found status carrying an extra receipt key", async () => {
    const { store, service } = harness();
    store.statusResult = { status: "not_found", receipt: {} };
    await expect(
      service.getPolicyMutationStatus(ctx(), {
        organizationId: ORG,
        mutationId: MUTATION,
      }),
    ).rejects.toMatchObject({ status: 503 });
  });

  it("binds a committed receipt to the outer mutation id and operation set", async () => {
    const { store, service } = harness();
    store.statusResult = {
      status: "committed",
      receipt: {
        mutationId: MUTATION,
        operation: "control.policy.pause",
        resourceType: "budget_policy",
        resourceId: POLICY,
        committedAt: ISO,
      },
    };
    const status = await service.getPolicyMutationStatus(ctx(), {
      organizationId: ORG,
      mutationId: MUTATION,
    });
    expect(status.status).toBe("committed");

    const mismatch = harness();
    mismatch.store.statusResult = {
      status: "committed",
      receipt: {
        mutationId: MUTATION2,
        operation: "control.policy.pause",
        resourceType: "budget_policy",
        resourceId: POLICY,
        committedAt: ISO,
      },
    };
    await expect(
      mismatch.service.getPolicyMutationStatus(ctx(), {
        organizationId: ORG,
        mutationId: MUTATION,
      }),
    ).rejects.toMatchObject({ status: 503 });
  });
});

describe("policy service write ordering", () => {
  it("creates through csrf -> begin -> exactly one store call with no post-commit check", async () => {
    const { store, auth, service } = harness();
    auth.finishError = AUTH_ERRORS.unauthenticated();
    const result = await service.createPolicy(ctx(), ORG, writeEnvelope({
      mutationId: MUTATION,
      content: content(),
    }));
    expect(result.organizationId).toBe(ORG);
    expect(result.receipt.operation).toBe("control.policy.create");
    expect(auth.order).toEqual(["csrf", "begin"]);
    expect(auth.finishCalls).toBe(0);
    expect(store.calls).toEqual(["createPolicy"]);
  });

  it("validates the body before any auth work", async () => {
    const { auth, service } = harness();
    await expect(
      service.createPolicy(ctx(), ORG, writeEnvelope({ mutationId: MUTATION })),
    ).rejects.toMatchObject({ status: 400 });
    expect(auth.csrfCalls).toBe(0);
    expect(auth.beginCalls).toBe(0);
  });

  it("rejects a create receipt with an extra key or mismatched operation", async () => {
    const extra = harness();
    extra.store.createResult = { ...mutationResult(), secret: "PRIVATE" };
    await expect(
      extra.service.createPolicy(ctx(), ORG, writeEnvelope({
        mutationId: MUTATION,
        content: content(),
      })),
    ).rejects.toMatchObject({ status: 503 });

    const wrong = harness();
    wrong.store.createResult = mutationResult({
      operation: "control.policy.pause",
      resourceType: "budget_policy",
    });
    await expect(
      wrong.service.createPolicy(ctx(), ORG, writeEnvelope({
        mutationId: MUTATION,
        content: content(),
      })),
    ).rejects.toMatchObject({ status: 503 });
  });

  it("appends binding the receipt to policyId@(expectedRevision+1)", async () => {
    const { store, service } = harness();
    const result = await service.appendPolicyRevision(ctx(), ORG, POLICY, writeEnvelope({
      mutationId: MUTATION,
      expectedRevision: "1",
      expectedUpdatedAt: ISO,
      content: content(),
    }));
    expect(result.receipt.resourceId).toBe(`${POLICY}@2`);

    const wrong = harness();
    wrong.store.appendResult = mutationResult({
      operation: "control.policy.revision.create",
      resourceType: "budget_policy_revision",
      resourceId: `${POLICY}@3`,
    });
    await expect(
      wrong.service.appendPolicyRevision(ctx(), ORG, POLICY, writeEnvelope({
        mutationId: MUTATION,
        expectedRevision: "1",
        expectedUpdatedAt: ISO,
        content: content(),
      })),
    ).rejects.toMatchObject({ status: 503 });
    expect(store.calls).toEqual(["appendPolicyRevision"]);
  });

  it("fixes the transition operation by route and rejects a body operation key", async () => {
    const pause = harness();
    pause.store.transitionResult = mutationResult({
      operation: "control.policy.pause",
      resourceType: "budget_policy",
      resourceId: POLICY,
    });
    const paused = await pause.service.pausePolicy(ctx(), ORG, POLICY, writeEnvelope({
      mutationId: MUTATION,
      expectedRevision: "1",
      expectedUpdatedAt: ISO,
    }));
    expect(paused.receipt.operation).toBe("control.policy.pause");

    const resume = harness();
    resume.store.transitionResult = mutationResult({
      operation: "control.policy.resume",
      resourceType: "budget_policy",
      resourceId: POLICY,
    });
    const resumed = await resume.service.resumePolicy(ctx(), ORG, POLICY, writeEnvelope({
      mutationId: MUTATION,
      expectedRevision: "1",
      expectedUpdatedAt: ISO,
    }));
    expect(resumed.receipt.operation).toBe("control.policy.resume");

    const revoke = harness();
    revoke.store.transitionResult = mutationResult({
      operation: "control.policy.revoke",
      resourceType: "budget_policy",
      resourceId: POLICY,
    });
    const revoked = await revoke.service.revokePolicy(ctx(), ORG, POLICY, writeEnvelope({
      mutationId: MUTATION,
      expectedRevision: "1",
      expectedUpdatedAt: ISO,
    }));
    expect(revoked.receipt.operation).toBe("control.policy.revoke");

    const injected = harness();
    await expect(
      injected.service.pausePolicy(ctx(), ORG, POLICY, writeEnvelope({
        mutationId: MUTATION,
        expectedRevision: "1",
        expectedUpdatedAt: ISO,
        operation: "control.policy.revoke",
      })),
    ).rejects.toMatchObject({ status: 400 });
    expect(injected.auth.csrfCalls).toBe(0);

    const wrongReceipt = harness();
    wrongReceipt.store.transitionResult = mutationResult({
      operation: "control.policy.revoke",
      resourceType: "budget_policy",
      resourceId: POLICY,
    });
    await expect(
      wrongReceipt.service.pausePolicy(ctx(), ORG, POLICY, writeEnvelope({
        mutationId: MUTATION,
        expectedRevision: "1",
        expectedUpdatedAt: ISO,
      })),
    ).rejects.toMatchObject({ status: 503 });
  });

  it("uses the exact supplied method ctx for csrf and begin, never a body context", async () => {
    const { store, auth, service } = harness();
    const methodCtx: AuthRequestContext = {
      peerIp: "10.0.0.9",
      cookies: { session: "method-session", binding: "method-binding" },
    };
    // The envelope carries an EXTRA bogus `ctx`; the service must ignore it and
    // use only the explicit method ctx argument for csrf and begin.
    const result = await service.createPolicy(methodCtx, ORG, {
      csrf: "csrf",
      idempotencyKey: IDEMPOTENCY,
      ctx: { peerIp: "6.6.6.6", cookies: { session: "body-session", binding: null } },
      body: { mutationId: MUTATION, content: content() },
    });
    expect(result.receipt.operation).toBe("control.policy.create");
    expect(auth.csrfCookies).toEqual([{ session: "method-session", binding: "method-binding" }]);
    expect(auth.beginCtx).toEqual([methodCtx]);
    expect(store.calls).toEqual(["createPolicy"]);

    // A context smuggled INSIDE the parsed body is a strict-schema 400 before
    // any auth work, never a silent alternate principal.
    const injected = harness();
    await expect(
      injected.service.createPolicy(methodCtx, ORG, writeEnvelope({
        mutationId: MUTATION,
        content: content(),
        ctx: { peerIp: "6.6.6.6", cookies: { session: "body-session", binding: null } },
      })),
    ).rejects.toMatchObject({ status: 400 });
    expect(injected.auth.csrfCalls).toBe(0);
    expect(injected.auth.beginCalls).toBe(0);
    expect(injected.store.calls).toEqual([]);
  });

  it("rejects a create body whose content org differs from the path before auth/store", async () => {
    const { store, auth, service } = harness();
    await expect(
      service.createPolicy(ctx(), ORG, writeEnvelope({
        mutationId: MUTATION,
        content: content({ organizationId: ORG2 }),
      })),
    ).rejects.toMatchObject({ status: 400 });
    expect(auth.csrfCalls).toBe(0);
    expect(auth.beginCalls).toBe(0);
    expect(store.calls).toEqual([]);
  });

  it("rejects an append body whose content org differs from the path before auth/store", async () => {
    const { store, auth, service } = harness();
    await expect(
      service.appendPolicyRevision(ctx(), ORG, POLICY, writeEnvelope({
        mutationId: MUTATION,
        expectedRevision: "1",
        expectedUpdatedAt: ISO,
        content: content({ organizationId: ORG2 }),
      })),
    ).rejects.toMatchObject({ status: 400 });
    expect(auth.csrfCalls).toBe(0);
    expect(auth.beginCalls).toBe(0);
    expect(store.calls).toEqual([]);
  });
});

describe("policy service closed error mapping", () => {
  const cases: ReadonlyArray<readonly [string, number]> = [
    ["CONTROL_POLICY_STORE_INPUT_INVALID", 400],
    ["CONTROL_POLICY_STORE_SESSION_INVALID", 401],
    ["CONTROL_POLICY_STORE_FORBIDDEN", 403],
    ["CONTROL_POLICY_STORE_NOT_FOUND", 403],
    ["CONTROL_POLICY_STORE_CONFLICT", 409],
    ["CONTROL_POLICY_STORE_IDEMPOTENCY_CONFLICT", 409],
    ["CONTROL_POLICY_STORE_UNAVAILABLE", 503],
    ["CONTROL_POLICY_STORE_OUTCOME_UNKNOWN", 503],
  ];

  it("maps every frozen store error code without echoing detail", async () => {
    for (const [code, status] of cases) {
      const { store, service } = harness();
      store.error = new ControlPolicyStoreError(
        code as ConstructorParameters<typeof ControlPolicyStoreError>[0],
      );
      const error = await service
        .listPolicyRoots(ctx(), { organizationId: ORG })
        .then(() => null)
        .catch((caught: unknown) => caught);
      expect(error, code).toMatchObject({ status });
      expect(JSON.stringify(error)).not.toContain(code);
    }
  });

  it("does not retry an unknown-outcome write", async () => {
    const { store, service } = harness();
    store.error = new ControlPolicyStoreError("CONTROL_POLICY_STORE_OUTCOME_UNKNOWN");
    await expect(
      service.createPolicy(ctx(), ORG, writeEnvelope({
        mutationId: MUTATION,
        content: content(),
      })),
    ).rejects.toMatchObject({ status: 503 });
    expect(store.calls).toEqual(["createPolicy"]);
  });
});
