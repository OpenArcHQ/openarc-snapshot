// P04-06c — the purchase decision against a REAL encrypted Vault.
//
// The existing P04-06/P04-06b suites prove the ORDER and the CONTENT of the
// decision flow against a stubbed binding. This suite proves the thing that was
// missing: that the binding the workspace actually mounts is real. Every
// receipt here is committed into a real IndexedDB-backed Vault through
// `saveWorkspaceRecords`, and every refusal here comes from the real durable
// `assertStoredWorkspaceRevision` recheck reading real stored metadata.
//
// Nothing in this file introduces a Vault identifier, record schema, AAD, KDF,
// cap, channel or message type: the record is the v6 receipt the flow already
// builds, saved through the accepted service.
import "fake-indexeddb/auto";

import {
  PURCHASE_DECISION_APPROVE_PATH,
  PURCHASE_DECISION_REJECT_PATH,
  type PurchaseDecisionPermissionReceiptRecord,
  type WorkspaceRecord,
} from "@openarc/shared";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { AccountFlowController } from "../src/account/flow-controller.js";
import { ActionClient } from "../src/tenant/action-client.js";
import type { ActionReadCoordinator } from "../src/tenant/action-controller.js";
import { PurchaseController } from "../src/tenant/purchase-controller.js";
import {
  VAULT_DATABASE_NAME,
  markVaultDeleting,
  readVaultMeta,
  signalVaultLock,
} from "../src/vault/db.js";
import {
  createPurchaseVaultBinding,
  type PurchaseVaultSession,
} from "../src/vault/purchase-binding.js";
import {
  createAgentProfileRecord,
  createLocalWorkspace,
  saveWorkspaceRecords,
  unlockLocalWorkspace,
} from "../src/vault/service.js";
import type { UnlockedWorkspace } from "../src/vault/types.js";
import {
  ACCOUNT_A,
  ACTION,
  APPROVAL,
  ORG,
  actionMetadata,
  actionReceipt,
  approvalMetadata,
  exposureData,
  success,
} from "./action-test-fixtures.js";

vi.setConfig({ testTimeout: 60_000 });

const PASSPHRASE = "workspace purchase review passphrase 42";
const ORIGIN = "https://app.example.test";
const CSRF = "csrf-from-bootstrap";
const id = encodeURIComponent;

afterEach(async () => {
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase(VAULT_DATABASE_NAME);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
    request.onblocked = () => resolve();
  });
});

/** Answers exactly the browser-audience routes this flow may call. */
function purchaseFetcher() {
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
    if (url.includes("/exposure")) return success(exposureData());
    if (url.includes("/approvals/")) {
      return success({ organizationId: ORG, approvalId: APPROVAL, item: approvalMetadata() });
    }
    return success({ organizationId: ORG, actionId: ACTION, item: actionMetadata() });
  });
}

function fakeAccount(): AccountFlowController {
  return {
    state: {
      status: "signed-in",
      csrfToken: "csrf",
      session: {
        signedIn: true as const,
        accountId: ACCOUNT_A,
        method: "passkey",
        expiresAt: "2030-01-01T00:00:00.000Z",
      },
    },
    captureAccountBound: () => ({ generation: 0, accountId: ACCOUNT_A }),
    async mutate<T>(run: (context: { csrfToken: string; signal: AbortSignal }) => Promise<T>) {
      return run({ csrfToken: CSRF, signal: new AbortController().signal });
    },
  } as unknown as AccountFlowController;
}

function fakeReads(): ActionReadCoordinator {
  return {
    currentOrganizationId: () => ORG,
    currentRole: () => "owner",
    currentAccountId: () => ACCOUNT_A,
    abortPendingReads: () => undefined,
  };
}

interface Harness {
  readonly session: PurchaseVaultSession;
  readonly refusals: unknown[];
  readonly committed: UnlockedWorkspace[];
  current: () => UnlockedWorkspace | null;
}

/**
 * The workspace session exactly as `VaultWorkspace` supplies it: the live
 * unlocked workspace, this tab's active-session check, the origin the request
 * is sent to, adoption of the committed revision, and the refusal handler.
 */
function harness(
  workspace: UnlockedWorkspace | null,
  overrides: Partial<PurchaseVaultSession> = {},
): Harness {
  let live = workspace;
  const refusals: unknown[] = [];
  const committed: UnlockedWorkspace[] = [];
  const session: PurchaseVaultSession = {
    currentWorkspace: () => live,
    assertActive: () => undefined,
    isActive: () => true,
    origin: ORIGIN,
    onCommitted: (next) => {
      live = next;
      committed.push(next);
    },
    onRefused: (cause) => {
      refusals.push(cause);
    },
    ...overrides,
  };
  return { session, refusals, committed, current: () => live };
}

function controllerFor(
  fetcher: ReturnType<typeof purchaseFetcher>,
  session: PurchaseVaultSession,
) {
  return new PurchaseController({
    account: fakeAccount(),
    reads: fakeReads(),
    client: new ActionClient({ fetcher: fetcher as unknown as typeof fetch }),
    capabilityReader: async () => "enabled",
    vault: createPurchaseVaultBinding(session),
    onState: () => undefined,
  });
}

/** Every permission receipt the stored Vault actually holds, after re-unlock. */
async function storedReceipts(): Promise<PurchaseDecisionPermissionReceiptRecord[]> {
  const meta = await readVaultMeta();
  if (meta === null) return [];
  const unlocked = await unlockLocalWorkspace(meta, PASSPHRASE);
  return unlocked.records.filter(
    (record): record is PurchaseDecisionPermissionReceiptRecord =>
      record.kind === "permission_receipt" &&
      record.recordSchema === "openarc.permission-receipt.v6",
  );
}

describe("P04-06c the workspace binding commits a real receipt and sends one request", () => {
  it.each([
    ["approve", PURCHASE_DECISION_APPROVE_PATH, "approve"],
    ["reject", PURCHASE_DECISION_REJECT_PATH, "reject"],
  ] as const)(
    "%s commits exactly one v6 receipt whose released fields equal the wire body",
    async (decision, disclosedPath) => {
      const created = await createLocalWorkspace(PASSPHRASE);
      const probe = harness(created);
      const fetcher = purchaseFetcher();
      const controller = controllerFor(fetcher, probe.session);

      await controller.initialize(ACTION);
      expect(controller.state.receiptUnavailable).toBe(false);
      expect(controller.beginDecision(decision)).toBe(true);
      await controller.confirmDecision();
      expect(controller.state.decision.kind).toBe("committed");

      // Exactly one request left the browser, on exactly the route the decision
      // names, with a body of exactly one field.
      const writes = fetcher.mock.calls.filter((call) => call[1]?.method === "POST");
      expect(writes).toHaveLength(1);
      const path = String(writes[0]?.[0]);
      expect(path).toBe(`/v2/control/organizations/${id(ORG)}/actions/${id(ACTION)}/${decision}`);
      const body = JSON.parse(String(writes[0]?.[1]?.body)) as Record<string, unknown>;
      expect(Object.keys(body)).toEqual(["mutationId"]);

      // Exactly one receipt is durably in the encrypted Vault, and it describes
      // that request and nothing more.
      const receipts = await storedReceipts();
      expect(receipts).toHaveLength(1);
      const receipt = receipts[0]!;
      expect(receipt.released).toEqual({
        organizationId: ORG,
        actionId: ACTION,
        decision,
        mutationId: body.mutationId,
      });
      expect([...receipt.releasedFields].sort()).toEqual(Object.keys(receipt.released).sort());
      expect(receipt.destination).toEqual({
        origin: ORIGIN,
        path: disclosedPath,
        method: "POST",
        upstreams: [],
      });
      // The revision the receipt was committed into is the one this tab adopted.
      expect(probe.committed).toHaveLength(1);
      expect(probe.current()?.meta.revision).toBe(probe.committed[0]?.meta.revision);
      expect(probe.refusals).toEqual([]);
    },
  );

  it("keeps the CSRF token and idempotency key out of the stored Vault entirely", async () => {
    const created = await createLocalWorkspace(PASSPHRASE);
    const fetcher = purchaseFetcher();
    const controller = controllerFor(fetcher, harness(created).session);
    await controller.initialize(ACTION);
    expect(controller.beginDecision("approve")).toBe(true);
    await controller.confirmDecision();

    const write = fetcher.mock.calls.find((call) => call[1]?.method === "POST");
    const headers = write?.[1]?.headers as Record<string, string>;
    const serialized = JSON.stringify(await storedReceipts());
    expect(headers["X-OpenArc-CSRF"]).toBe(CSRF);
    expect(serialized).not.toContain(CSRF);
    expect(serialized).not.toContain(headers["Idempotency-Key"]);
  });
});

/**
 * The packet rule, now against the real guard: a peer that commits between the
 * receipt and the send stops the request, and the receipt is NEVER rolled back
 * to hide a refused egress.
 */
describe("P04-06c a peer change between receipt and send sends nothing", () => {
  type Peer = (saved: UnlockedWorkspace) => Promise<unknown>;
  const peers: [string, Peer][] = [
    ["peer lock signal", (saved) => signalVaultLock(saved.meta)],
    [
      "peer save",
      (saved) =>
        saveWorkspaceRecords(saved, [
          createAgentProfileRecord(
            { displayName: "Peer", walletAddress: "", frameworkLabel: "", purposeNote: "" },
            saved.meta.revision,
          ),
        ]),
    ],
    ["peer deletion marker", (saved) => markVaultDeleting(saved.meta.vaultId)],
  ];

  it.each(peers)("%s produces zero requests and keeps the receipt", async (_name, peer) => {
    const created = await createLocalWorkspace(PASSPHRASE);
    // The commit is the real encrypted save; the peer commits silently right
    // after it, exactly as another tab would, with no broadcast to this one.
    const probe = harness(created, {
      save: async (workspace, records, assertActive, signal) => {
        const saved = await saveWorkspaceRecords(workspace, records, assertActive, signal);
        await peer(saved);
        return saved;
      },
    });
    const fetcher = purchaseFetcher();
    const controller = controllerFor(fetcher, probe.session);

    await controller.initialize(ACTION);
    const reads = fetcher.mock.calls.length;
    expect(controller.beginDecision("approve")).toBe(true);
    await controller.confirmDecision();

    // Nothing at all left the browser after the review reads.
    expect(fetcher.mock.calls.slice(reads)).toEqual([]);
    expect(controller.state.decision).toEqual({
      kind: "rejected",
      notice: { kind: "vault-conflict" },
    });
    // The workspace's own refusal handler was told, so this tab can re-read the
    // stored Vault and lock instead of pretending nothing happened.
    expect(probe.refusals).toHaveLength(1);
    expect(probe.refusals[0]).toMatchObject({ code: "VAULT_CONFLICT" });
    // The receipt of what the human reviewed is still committed.
    const committed = probe.committed[0];
    expect(committed).toBeDefined();
    expect(
      committed!.records.filter(
        (record: WorkspaceRecord) => record.kind === "permission_receipt",
      ),
    ).toHaveLength(1);
  });

  it("leaves the kept receipt readable in the stored Vault after a peer lock", async () => {
    const created = await createLocalWorkspace(PASSPHRASE);
    const probe = harness(created, {
      save: async (workspace, records, assertActive, signal) => {
        const saved = await saveWorkspaceRecords(workspace, records, assertActive, signal);
        await signalVaultLock(saved.meta);
        return saved;
      },
    });
    const controller = controllerFor(purchaseFetcher(), probe.session);
    await controller.initialize(ACTION);
    expect(controller.beginDecision("approve")).toBe(true);
    await controller.confirmDecision();

    const receipts = await storedReceipts();
    expect(receipts).toHaveLength(1);
    expect(receipts[0]?.released.decision).toBe("approve");
    expect(receipts[0]?.outcome).toBe("approved");
  });
});

describe("P04-06c a locked or missing Vault offers no binding and sends nothing", () => {
  it.each([
    ["locked or absent workspace", { currentWorkspace: () => null }],
    ["no resolvable origin", { origin: null }],
  ] as const)("builds no binding for %s", async (_name, override) => {
    const created = await createLocalWorkspace(PASSPHRASE);
    const probe = harness(created, override as Partial<PurchaseVaultSession>);
    expect(createPurchaseVaultBinding(probe.session)).toBeNull();
  });

  it("refuses every decision and makes zero decision requests with no binding", async () => {
    const fetcher = purchaseFetcher();
    const controller = controllerFor(fetcher, harness(null).session);
    await controller.initialize(ACTION);
    const reads = fetcher.mock.calls.length;

    expect(controller.state.receiptUnavailable).toBe(true);
    expect(controller.beginDecision("approve")).toBe(false);
    await controller.confirmDecision();
    expect(controller.beginDecision("reject")).toBe(false);

    expect(fetcher.mock.calls.slice(reads)).toEqual([]);
    expect(controller.state.decision).toEqual({
      kind: "rejected",
      notice: { kind: "receipt-unavailable" },
    });
    expect(await storedReceipts()).toEqual([]);
  });

  it("refuses once this tab's Vault session is no longer the current one", async () => {
    const created = await createLocalWorkspace(PASSPHRASE);
    const probe = harness(created, {
      assertActive: () => {
        throw new Error("Vault session changed");
      },
    });
    const fetcher = purchaseFetcher();
    const controller = controllerFor(fetcher, probe.session);
    await controller.initialize(ACTION);
    const reads = fetcher.mock.calls.length;

    expect(controller.beginDecision("approve")).toBe(true);
    await controller.confirmDecision();

    expect(fetcher.mock.calls.slice(reads)).toEqual([]);
    expect(probe.committed).toEqual([]);
    expect(await storedReceipts()).toEqual([]);
  });
});
