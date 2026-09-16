import {
  PURCHASE_DECISION_APPROVE_PATH,
  PURCHASE_DECISION_REJECT_PATH,
  type PurchaseDecisionPermissionReceiptRecord,
  type WorkspaceRecord,
} from "@openarc/shared";
import type { CommerceHumanRole } from "@openarc/shared";
import { describe, expect, it, vi } from "vitest";

import type { AccountFlowController } from "../src/account/flow-controller.js";
import { PurchaseReceiptUnavailableError, runPurchaseDecisionFlow } from "../src/api/purchase-decision-flow.js";
import { ActionClient } from "../src/tenant/action-client.js";
import type { ActionReadCoordinator } from "../src/tenant/action-controller.js";
import {
  PurchaseController,
  initialPurchaseControllerState,
  type PurchaseVaultBinding,
} from "../src/tenant/purchase-controller.js";
import { VaultError } from "../src/vault/errors.js";
import type { UnlockedWorkspace } from "../src/vault/types.js";
import {
  ACCOUNT_A,
  ACTION,
  AGENT,
  APPROVAL,
  ORG,
  POLICY,
  actionMetadata,
  actionReceipt,
  approvalMetadata,
  errorEnvelope,
  exposureData,
  success,
} from "./action-test-fixtures.js";

const CSRF = "csrf-from-bootstrap";

function fakeReads(
  role: CommerceHumanRole | null = "owner",
  organizationId: string | null = ORG,
): ActionReadCoordinator & { abortCalls: number } {
  const reads = {
    abortCalls: 0,
    currentOrganizationId: () => organizationId,
    currentRole: () => role,
    currentAccountId: () => ACCOUNT_A,
    abortPendingReads() {
      reads.abortCalls += 1;
    },
  };
  return reads;
}

function fakeAccount(accountId: string | null = ACCOUNT_A, method = "passkey") {
  const account = {
    state:
      accountId === null
        ? { status: "signed-out", csrfToken: null, session: { signedIn: false as const } }
        : {
            status: "signed-in",
            csrfToken: "csrf",
            session: {
              signedIn: true as const,
              accountId,
              method,
              expiresAt: "2030-01-01T00:00:00.000Z",
            },
          },
    captureAccountBound() {
      return { generation: 0, accountId };
    },
    async mutate<T>(run: (context: { csrfToken: string; signal: AbortSignal }) => Promise<T>): Promise<T> {
      return run({ csrfToken: CSRF, signal: new AbortController().signal });
    },
  };
  return account as unknown as AccountFlowController;
}

/** Answers exactly the browser-audience routes this flow is allowed to call. */
function purchaseFetcher(options: { approvalMissing?: boolean; exposureFails?: boolean } = {}) {
  return vi.fn(async (path: string, init?: RequestInit) => {
    const url = String(path);
    if (url.includes("/approve") || url.includes("/reject")) {
      const operation = url.includes("/approve")
        ? "control.commerce_action.approve"
        : "control.commerce_action.reject";
      const mutationId = (JSON.parse(String(init?.body)) as { mutationId: string }).mutationId;
      return success({
        replayed: false,
        metadata: actionMetadata(),
        receipt: actionReceipt(operation, ACTION, mutationId),
      });
    }
    if (url.includes("/exposure")) {
      if (options.exposureFails === true) return errorEnvelope("INTERNAL_ERROR", 500);
      return success(exposureData());
    }
    if (url.includes("/approvals/")) {
      return success({
        organizationId: ORG,
        approvalId: APPROVAL,
        item: options.approvalMissing === true ? null : approvalMetadata(),
      });
    }
    return success({ organizationId: ORG, actionId: ACTION, item: actionMetadata() });
  });
}

interface VaultProbe {
  readonly binding: PurchaseVaultBinding;
  readonly events: string[];
  readonly committed: WorkspaceRecord[][];
}

/**
 * A Vault binding stub that records the ORDER of receipt commit, revision
 * recheck and active-session assert. It asserts nothing about any Vault record
 * schema: this packet adds none.
 */
function fakeVault(options: { conflict?: boolean; buildsNoReceipt?: boolean } = {}): VaultProbe {
  const events: string[] = [];
  const committed: WorkspaceRecord[][] = [];
  const workspace = {
    meta: { vaultId: "vault", revision: "rev-1", coordinationRevision: "coord-1" },
    key: {},
    records: [],
  } as unknown as UnlockedWorkspace;
  const binding: PurchaseVaultBinding = {
    workspace,
    assertActive: () => {
      events.push("assert-active");
    },
    save: async (current, records) => {
      events.push("commit-receipt");
      committed.push([...records]);
      return current;
    },
    verifyStored: async () => {
      events.push("verify-stored");
      if (options.conflict === true) {
        throw new VaultError("VAULT_CONFLICT", "This encrypted workspace changed. Nothing was sent.");
      }
    },
    buildReceipt: () =>
      options.buildsNoReceipt === true
        ? []
        : ([{ kind: "purchase-decision-receipt-stub" }] as unknown as readonly WorkspaceRecord[]),
  };
  return { binding, events, committed };
}

function controllerWith(
  fetcher: unknown,
  options: {
    role?: CommerceHumanRole | null;
    capability?: "enabled" | "built_disabled" | "unavailable";
    vault?: PurchaseVaultBinding | null;
    account?: AccountFlowController;
  } = {},
) {
  const reads = fakeReads(options.role === undefined ? "owner" : options.role);
  const controller = new PurchaseController({
    account: options.account ?? fakeAccount(),
    reads,
    client: new ActionClient({ fetcher: fetcher as typeof fetch }),
    capabilityReader: async () => options.capability ?? "enabled",
    vault: options.vault ?? null,
    onState: () => undefined,
  });
  return { controller, reads };
}

describe("P04-06 purchase review", () => {
  it("reviews a pending purchase from the existing browser routes only", async () => {
    const fetcher = purchaseFetcher();
    const { controller } = controllerWith(fetcher, { vault: fakeVault().binding });
    await controller.initialize(ACTION);

    expect(controller.state.review.status).toBe("ready");
    const paths = fetcher.mock.calls.map((call) => String(call[0]));
    // Exactly the three browser-audience reads, and no agent-audience route.
    // Every canonical id is percent-encoded exactly once by the client.
    const id = encodeURIComponent;
    expect(paths).toHaveLength(3);
    expect(paths[0]).toBe(`/v2/control/organizations/${id(ORG)}/actions/${id(ACTION)}`);
    expect(paths[1]).toBe(`/v2/control/organizations/${id(ORG)}/approvals/${id(APPROVAL)}`);
    expect(paths[2]).toBe(
      `/v2/control/organizations/${id(ORG)}/agents/${id(AGENT)}/policies/${id(POLICY)}/exposure`,
    );
    for (const path of paths) expect(path).not.toContain("/v2/agent/");
  });

  it("shows what is bought, the exact amount, the budget and the approval expiry", async () => {
    const { controller } = controllerWith(purchaseFetcher());
    await controller.initialize(ACTION);
    const byKey = new Map(controller.reviewFields().map((field) => [field.key, field]));

    expect(byKey.get("listingId")?.value).toBe(`openarc:listing:12345678-1234-4234-8123-123456789abc`);
    expect(byKey.get("listingVersion")?.value).toBe("1");
    expect(byKey.get("amountAtomic")?.value).toBe("1500000");
    expect(byKey.get("debitAtomic")?.value).toBe("1750000");
    expect(byKey.get("asset")?.value).toBe("USDC");
    expect(byKey.get("policyId")?.value).toBe(POLICY);
    expect(byKey.get("policyRevision")?.value).toBe("1");
    expect(byKey.get("approvalExpiresAt")?.value).toBe("2026-01-01T00:15:00.000Z");
  });

  it("shows the seller-recorded payee as unknown because no browser route returns it", async () => {
    const { controller } = controllerWith(purchaseFetcher());
    await controller.initialize(ACTION);
    const payee = controller.reviewFields().find((field) => field.key === "payToAddress");
    expect({ known: payee?.known, value: payee?.value }).toEqual({ known: false, value: null });
  });

  it("keeps the review when the exposure read fails and never implies a zero budget", async () => {
    const { controller } = controllerWith(purchaseFetcher({ exposureFails: true }));
    await controller.initialize(ACTION);
    expect(controller.state.review.status).toBe("ready");
    expect(controller.state.review.exposureUnavailable).toBe(true);
    expect(controller.state.review.exposure).toBeNull();
  });

  it("reports a missing purchase as not found rather than an empty review", async () => {
    const fetcher = vi.fn(async () => success({ organizationId: ORG, actionId: ACTION, item: null }));
    const { controller } = controllerWith(fetcher);
    await controller.initialize(ACTION);
    expect(controller.state.review.status).toBe("not-found");
    expect(controller.state.review.action).toBeNull();
  });
});

describe("P04-06 purchase decision is receipt-gated", () => {
  it("commits the receipt, then re-checks the Vault, and only then sends one request", async () => {
    const fetcher = purchaseFetcher();
    const vault = fakeVault();
    const { controller } = controllerWith(fetcher, { vault: vault.binding });
    await controller.initialize(ACTION);
    const readCalls = fetcher.mock.calls.length;

    expect(controller.beginDecision("approve")).toBe(true);
    await controller.confirmDecision();

    // The receipt is committed and the guard runs BEFORE the request exists.
    const commitIndex = vault.events.indexOf("commit-receipt");
    const verifyIndex = vault.events.indexOf("verify-stored");
    expect(commitIndex).toBeGreaterThanOrEqual(0);
    expect(verifyIndex).toBeGreaterThan(commitIndex);
    expect(vault.events.slice(0, commitIndex)).toContain("assert-active");
    expect(vault.committed).toHaveLength(1);

    const writes = fetcher.mock.calls.slice(readCalls).filter((call) => call[1]?.method === "POST");
    expect(writes).toHaveLength(1);
    expect(String(writes[0]?.[0])).toBe(
      `/v2/control/organizations/${encodeURIComponent(ORG)}/actions/${encodeURIComponent(ACTION)}/approve`,
    );
    expect(controller.state.decision.kind).toBe("committed");
  });

  /** The packet rule: if the Vault changed, send nothing and keep the receipt. */
  it("sends ZERO requests when the Vault changed, and keeps the committed receipt", async () => {
    const fetcher = purchaseFetcher();
    const vault = fakeVault({ conflict: true });
    const { controller } = controllerWith(fetcher, { vault: vault.binding });
    await controller.initialize(ACTION);
    const readCalls = fetcher.mock.calls.length;

    expect(controller.beginDecision("approve")).toBe(true);
    await controller.confirmDecision();

    // Nothing left the browser after the guard refused.
    expect(fetcher.mock.calls.slice(readCalls)).toEqual([]);
    // The receipt of what the human reviewed is kept, never rolled back.
    expect(vault.committed).toHaveLength(1);
    expect(vault.events).toEqual(["assert-active", "commit-receipt", "assert-active", "verify-stored"]);
    expect(controller.state.decision).toEqual({
      kind: "rejected",
      notice: { kind: "vault-conflict" },
    });
  });

  it("sends ZERO requests when the session ended before the receipt committed", async () => {
    const fetcher = purchaseFetcher();
    const vault = fakeVault();
    const ended = new Error("vault session ended");
    const binding: PurchaseVaultBinding = {
      ...vault.binding,
      assertActive: () => {
        throw ended;
      },
    };
    const { controller } = controllerWith(fetcher, { vault: binding });
    await controller.initialize(ACTION);
    const readCalls = fetcher.mock.calls.length;

    expect(controller.beginDecision("reject")).toBe(true);
    await controller.confirmDecision();

    expect(fetcher.mock.calls.slice(readCalls)).toEqual([]);
    expect(vault.committed).toEqual([]);
  });

  it("refuses the decision and sends nothing when no Vault can receipt it", async () => {
    const fetcher = purchaseFetcher();
    const { controller } = controllerWith(fetcher, { vault: null });
    await controller.initialize(ACTION);
    const readCalls = fetcher.mock.calls.length;

    expect(controller.state.receiptUnavailable).toBe(true);
    expect(controller.beginDecision("approve")).toBe(false);
    await controller.confirmDecision();

    expect(fetcher.mock.calls.slice(readCalls)).toEqual([]);
    expect(controller.state.decision).toEqual({
      kind: "rejected",
      notice: { kind: "receipt-unavailable" },
    });
  });

  it("refuses when the receipt builder produces no record", async () => {
    const send = vi.fn(async () => "sent");
    const vault = fakeVault({ buildsNoReceipt: true });
    await expect(
      runPurchaseDecisionFlow({
        workspace: vault.binding.workspace,
        signal: new AbortController().signal,
        assertActive: vault.binding.assertActive,
        save: vault.binding.save,
        buildReceipt: vault.binding.buildReceipt,
        send,
      }),
    ).rejects.toBeInstanceOf(PurchaseReceiptUnavailableError);
    expect(send).not.toHaveBeenCalled();
    expect(vault.committed).toEqual([]);
  });

  it("does not send when the receipt itself could not be saved", async () => {
    const send = vi.fn(async () => "sent");
    await expect(
      runPurchaseDecisionFlow({
        workspace: fakeVault().binding.workspace,
        signal: new AbortController().signal,
        assertActive: () => undefined,
        save: async () => {
          throw new Error("storage refused");
        },
        buildReceipt: () => [{ kind: "stub" } as unknown as WorkspaceRecord],
        send,
      }),
    ).rejects.toMatchObject({ name: "PurchaseFinalizationError" });
    expect(send).not.toHaveBeenCalled();
  });

  it("reports a lost response as genuinely unknown and never resends", async () => {
    const vault = fakeVault();
    let posts = 0;
    const fetcher = vi.fn(async (path: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        posts += 1;
        throw new TypeError("network lost");
      }
      return purchaseFetcher()(path, init);
    });
    const { controller } = controllerWith(fetcher, { vault: vault.binding });
    await controller.initialize(ACTION);

    expect(controller.beginDecision("approve")).toBe(true);
    await controller.confirmDecision();

    expect(posts).toBe(1);
    expect(controller.state.decision.kind).toBe("outcome-unknown");
  });
});

describe("P04-06 purchase access and flag gates", () => {
  it("makes ZERO requests when the commerce-action capability is disabled", async () => {
    for (const capability of ["built_disabled", "unavailable"] as const) {
      const fetcher = vi.fn();
      const { controller } = controllerWith(fetcher, { capability, vault: fakeVault().binding });
      await controller.initialize(ACTION);
      expect(controller.state.capability).toBe("unavailable");
      expect(controller.state.review.status).toBe("none");
      expect(controller.beginDecision("approve")).toBe(false);
      expect(fetcher).not.toHaveBeenCalled();
    }
  });

  it("lets a viewer read the purchase but never decide it", async () => {
    const fetcher = purchaseFetcher();
    const { controller } = controllerWith(fetcher, { role: "viewer", vault: fakeVault().binding });
    await controller.initialize(ACTION);
    const readCalls = fetcher.mock.calls.length;

    expect(controller.state.canRead).toBe(true);
    expect(controller.state.canDecide).toBe(false);
    expect(controller.beginDecision("approve")).toBe(false);
    expect(fetcher.mock.calls.slice(readCalls)).toEqual([]);
  });

  it("refuses every read and decision for a recovery sign-in", async () => {
    const fetcher = vi.fn();
    const { controller } = controllerWith(fetcher, {
      account: fakeAccount(ACCOUNT_A, "recovery"),
      vault: fakeVault().binding,
    });
    await controller.initialize(ACTION);
    expect(controller.state.canRead).toBe(false);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("refuses a decision on a purchase that is no longer open", async () => {
    const fetcher = vi.fn(async (path: string) =>
      String(path).includes("/exposure")
        ? success(exposureData())
        : String(path).includes("/approvals/")
          ? success({ organizationId: ORG, approvalId: APPROVAL, item: approvalMetadata() })
          : success({
              organizationId: ORG,
              actionId: ACTION,
              item: actionMetadata(ACTION, {
                status: "grant_issued",
                reservationId: "openarc:reservation:12345678-1234-4234-8123-123456789abc",
              }),
            }),
    );
    const { controller } = controllerWith(fetcher, { vault: fakeVault().binding });
    await controller.initialize(ACTION);
    expect(controller.beginDecision("approve")).toBe(false);
    expect(controller.state.decision).toEqual({ kind: "rejected", notice: { kind: "validation" } });
  });

  it("clears every artifact without any request", async () => {
    const fetcher = purchaseFetcher();
    const { controller } = controllerWith(fetcher, { vault: fakeVault().binding });
    await controller.initialize(ACTION);
    const readCalls = fetcher.mock.calls.length;
    controller.clear();
    expect(controller.state.review).toEqual(initialPurchaseControllerState().review);
    expect(controller.state.decision).toEqual({ kind: "idle" });
    expect(fetcher.mock.calls.slice(readCalls)).toEqual([]);
  });
});

/**
 * P04-06b — the decision path with the real v6 receipt.
 *
 * The tests above use a stub record to prove ORDER. These prove CONTENT: the
 * receipt the Vault actually keeps describes exactly the request that actually
 * left the browser, and nothing more.
 */
describe("P04-06b the committed receipt describes the request that was sent", () => {
  /** A binding with no custom builder, so the controller builds the v6 receipt itself. */
  function realVault(options: { conflict?: boolean; origin?: string | null } = {}): VaultProbe {
    const events: string[] = [];
    const committed: WorkspaceRecord[][] = [];
    const workspace = {
      // A real 32-character Vault revision: the receipt schema pins the grammar.
      meta: { vaultId: "vault", revision: "A".repeat(32), coordinationRevision: "coord-1" },
      key: {},
      records: [],
    } as unknown as UnlockedWorkspace;
    const binding: PurchaseVaultBinding = {
      workspace,
      ...(options.origin === null ? {} : { origin: options.origin ?? "https://app.example.test" }),
      assertActive: () => {
        events.push("assert-active");
      },
      save: async (current, records) => {
        events.push("commit-receipt");
        committed.push([...records]);
        return current;
      },
      verifyStored: async () => {
        events.push("verify-stored");
        if (options.conflict === true) {
          throw new VaultError("VAULT_CONFLICT", "This encrypted workspace changed. Nothing was sent.");
        }
      },
    };
    return { binding, events, committed };
  }

  const receiptOf = (probe: VaultProbe): PurchaseDecisionPermissionReceiptRecord =>
    probe.committed[0]![0] as PurchaseDecisionPermissionReceiptRecord;

  it("commits a v6 receipt whose released fields equal the request body and route", async () => {
    const fetcher = purchaseFetcher();
    const vault = realVault();
    const { controller } = controllerWith(fetcher, { vault: vault.binding });
    await controller.initialize(ACTION);
    const readCalls = fetcher.mock.calls.length;

    expect(controller.beginDecision("approve")).toBe(true);
    await controller.confirmDecision();

    const writes = fetcher.mock.calls.slice(readCalls).filter((call) => call[1]?.method === "POST");
    expect(writes).toHaveLength(1);
    const path = String(writes[0]?.[0]);
    const body = JSON.parse(String(writes[0]?.[1]?.body)) as Record<string, unknown>;
    const receipt = receiptOf(vault);

    expect(receipt.recordSchema).toBe("openarc.permission-receipt.v6");
    expect(receipt.connectorId).toBe("openarc_purchase_decision");
    // The body is exactly one field, and the receipt discloses exactly it.
    expect(Object.keys(body)).toEqual(["mutationId"]);
    expect(receipt.released.mutationId).toBe(body.mutationId);
    // The two path segments that leave the browser are disclosed too.
    expect(path).toBe(
      `/v2/control/organizations/${encodeURIComponent(ORG)}/actions/${encodeURIComponent(ACTION)}/approve`,
    );
    expect(receipt.released.organizationId).toBe(ORG);
    expect(receipt.released.actionId).toBe(ACTION);
    // The decision IS the route, and the receipt names the route it called.
    expect(receipt.released.decision).toBe("approve");
    expect(receipt.destination.path).toBe(PURCHASE_DECISION_APPROVE_PATH);
    expect(receipt.destination.upstreams).toEqual([]);
    // Disclosure and payload agree exactly, with nothing disclosed that is not sent.
    expect([...receipt.releasedFields].sort()).toEqual(Object.keys(receipt.released).sort());
    expect(receipt.releasedFields).toEqual(["organizationId", "actionId", "decision", "mutationId"]);
  });

  it("never lets a CSRF token or idempotency key reach the receipt, though both are sent", async () => {
    const fetcher = purchaseFetcher();
    const vault = realVault();
    const { controller } = controllerWith(fetcher, { vault: vault.binding });
    await controller.initialize(ACTION);
    const readCalls = fetcher.mock.calls.length;
    expect(controller.beginDecision("approve")).toBe(true);
    await controller.confirmDecision();

    const write = fetcher.mock.calls.slice(readCalls).find((call) => call[1]?.method === "POST");
    const headers = write?.[1]?.headers as Record<string, string>;
    // Both really are on the wire, as headers...
    expect(headers["X-OpenArc-CSRF"]).toBe(CSRF);
    expect(headers["Idempotency-Key"]).toEqual(expect.any(String));
    // ...and neither appears anywhere in the stored receipt.
    const serialized = JSON.stringify(receiptOf(vault));
    expect(serialized).not.toContain(CSRF);
    expect(serialized).not.toContain(headers["Idempotency-Key"]);
  });

  it("records the reject route when the human rejects", async () => {
    const fetcher = purchaseFetcher();
    const vault = realVault();
    const { controller } = controllerWith(fetcher, { vault: vault.binding });
    await controller.initialize(ACTION);
    expect(controller.beginDecision("reject")).toBe(true);
    await controller.confirmDecision();
    const receipt = receiptOf(vault);
    expect(receipt.released.decision).toBe("reject");
    expect(receipt.destination.path).toBe(PURCHASE_DECISION_REJECT_PATH);
  });

  it("records what the human reviewed: listing version, exact amounts, policy and expiry", async () => {
    const fetcher = purchaseFetcher();
    const vault = realVault();
    const { controller } = controllerWith(fetcher, { vault: vault.binding });
    await controller.initialize(ACTION);
    expect(controller.beginDecision("approve")).toBe(true);
    await controller.confirmDecision();

    const reviewed = receiptOf(vault).reviewed;
    const shown = new Map(controller.reviewFields().map((field) => [field.key, field.value]));
    expect(reviewed.listingVersion).toBe(shown.get("listingVersion"));
    expect(reviewed.amountAtomic).toBe(shown.get("amountAtomic"));
    expect(reviewed.debitAtomic).toBe(shown.get("debitAtomic"));
    expect(reviewed.policyId).toBe(shown.get("policyId"));
    expect(reviewed.policyRevision).toBe(shown.get("policyRevision"));
    expect(reviewed.approvalExpiresAt).toBe(shown.get("approvalExpiresAt"));
    expect({ asset: reviewed.asset, decimals: reviewed.decimals }).toEqual({ asset: "USDC", decimals: 6 });
    // Amount plus fee is the budget, as exact integers.
    expect(BigInt(reviewed.debitAtomic)).toBe(BigInt(reviewed.amountAtomic) + BigInt(reviewed.feeAtomic));
  });

  it("sends ZERO requests when the Vault changed, and keeps the real receipt", async () => {
    const fetcher = purchaseFetcher();
    const vault = realVault({ conflict: true });
    const { controller } = controllerWith(fetcher, { vault: vault.binding });
    await controller.initialize(ACTION);
    const readCalls = fetcher.mock.calls.length;

    expect(controller.beginDecision("approve")).toBe(true);
    await controller.confirmDecision();

    expect(fetcher.mock.calls.slice(readCalls)).toEqual([]);
    expect(vault.committed).toHaveLength(1);
    expect(receiptOf(vault).recordSchema).toBe("openarc.permission-receipt.v6");
    expect(vault.events).toEqual(["assert-active", "commit-receipt", "assert-active", "verify-stored"]);
    expect(controller.state.decision).toEqual({ kind: "rejected", notice: { kind: "vault-conflict" } });
  });

  /** A receipt must name the exact origin it was sent to; one is never guessed. */
  it("refuses and sends nothing when no origin can be resolved for the receipt", async () => {
    const fetcher = purchaseFetcher();
    const vault = realVault({ origin: null });
    const { controller } = controllerWith(fetcher, { vault: vault.binding });
    await controller.initialize(ACTION);
    const readCalls = fetcher.mock.calls.length;

    expect(controller.beginDecision("approve")).toBe(true);
    await controller.confirmDecision();

    expect(fetcher.mock.calls.slice(readCalls)).toEqual([]);
    expect(vault.committed).toEqual([]);
    expect(controller.state.decision).toEqual({
      kind: "rejected",
      notice: { kind: "receipt-unavailable" },
    });
  });
});
