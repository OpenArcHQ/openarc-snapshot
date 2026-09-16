// P04-06c — WHERE a purchase decision may be taken.
//
// One review, two surfaces. The encrypted workspace owns an unlocked Vault, so
// it renders the approve/reject controls. The protected console owns none, so
// it renders the same figures read-only and links to the workspace instead of
// offering a control that could never be receipted. These tests assert both the
// pure surface decision and the markup that follows from it, so "the console
// renders no decision control" is checked rather than assumed.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type { AccountFlowController } from "../src/account/flow-controller.js";
import { ActionClient } from "../src/tenant/action-client.js";
import type { ActionReadCoordinator } from "../src/tenant/action-controller.js";
import {
  PURCHASE_WORKSPACE_HREF,
  PURCHASE_WORKSPACE_VIEW,
  PurchaseController,
  type PurchaseControllerState,
} from "../src/tenant/purchase-controller.js";
import {
  PurchaseReviewPanel,
  purchaseDecisionControls,
  type PurchaseDecisionSurface,
} from "../src/tenant/PurchaseReviewPanel.js";
import type { PurchaseVaultBinding } from "../src/tenant/purchase-controller.js";
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

const CONSOLE: PurchaseDecisionSurface = { kind: "elsewhere", href: PURCHASE_WORKSPACE_HREF };
const WORKSPACE: PurchaseDecisionSurface = { kind: "workspace" };

function purchaseFetcher(status = "pending_approval") {
  return vi.fn(async (path: string, init?: RequestInit) => {
    const url = String(path);
    if (url.includes("/approve") || url.includes("/reject")) {
      const mutationId = (JSON.parse(String(init?.body)) as { mutationId: string }).mutationId;
      return success({
        replayed: false,
        metadata: actionMetadata(),
        receipt: actionReceipt("control.commerce_action.approve", ACTION, mutationId),
      });
    }
    if (url.includes("/exposure")) return success(exposureData());
    if (url.includes("/approvals/")) {
      return success({ organizationId: ORG, approvalId: APPROVAL, item: approvalMetadata() });
    }
    return success({
      organizationId: ORG,
      actionId: ACTION,
      item: actionMetadata(ACTION, status === "pending_approval" ? {} : { status }),
    });
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
      return run({ csrfToken: "csrf-from-bootstrap", signal: new AbortController().signal });
    },
  } as unknown as AccountFlowController;
}

function fakeReads(role: string | null = "owner"): ActionReadCoordinator {
  return {
    currentOrganizationId: () => ORG,
    currentRole: () => role,
    currentAccountId: () => ACCOUNT_A,
    abortPendingReads: () => undefined,
  };
}

/** A binding stub standing in for an unlocked workspace on the vault surface. */
function boundVault(): PurchaseVaultBinding {
  return {
    workspace: {
      meta: { vaultId: "vault", revision: "A".repeat(32), coordinationRevision: "coord-1" },
      key: {},
      records: [],
    } as unknown as UnlockedWorkspace,
    origin: "https://app.example.test",
    assertActive: () => undefined,
    save: async (current) => current,
    verifyStored: async () => undefined,
  };
}

async function readyState(options: {
  vault?: PurchaseVaultBinding | null;
  role?: string | null;
  status?: string;
  fetcher?: ReturnType<typeof purchaseFetcher>;
} = {}) {
  const fetcher = options.fetcher ?? purchaseFetcher(options.status ?? "pending_approval");
  const controller = new PurchaseController({
    account: fakeAccount(),
    reads: fakeReads(options.role === undefined ? "owner" : options.role),
    client: new ActionClient({ fetcher: fetcher as unknown as typeof fetch }),
    capabilityReader: async () => "enabled",
    vault: options.vault ?? null,
    onState: () => undefined,
  });
  await controller.initialize(ACTION);
  return { controller, fetcher, state: controller.state };
}

/** Every button label the rendered review offers. */
function buttonLabels(markup: string): string[] {
  return [...markup.matchAll(/<button[^>]*>(.*?)<\/button>/gsu)].map((match) =>
    match[1]!.replace(/<[^>]*>/gu, "").trim(),
  );
}

function render(state: PurchaseControllerState, controller: PurchaseController, surface: PurchaseDecisionSurface) {
  return renderToStaticMarkup(
    <PurchaseReviewPanel
      state={state}
      controller={controller}
      actionId={ACTION}
      decisions={surface}
    />,
  );
}

describe("P04-06c the protected console review is read-only", () => {
  it("renders no decision control and links to the private workspace instead", async () => {
    const { controller, state } = await readyState({ vault: null });
    const markup = render(state, controller, CONSOLE);

    // The review itself is unchanged: the exact figures are still shown.
    expect(markup).toContain("1750000");
    expect(markup).toContain("Review purchase");
    // No control that could begin, confirm or cancel a decision exists.
    const labels = buttonLabels(markup);
    expect(labels).toEqual(["Refresh purchase"]);
    for (const label of labels) expect(label).not.toMatch(/approve|reject/iu);
    // The handoff names the workspace, and says why the decision belongs there.
    expect(markup).toContain(`href="${PURCHASE_WORKSPACE_HREF}"`);
    expect(markup).toContain("encrypted receipt");
    expect(markup).toContain("private workspace");
  });

  it("issues no decision request from the console surface", async () => {
    const { controller, fetcher } = await readyState({ vault: null });
    const reads = fetcher.mock.calls.length;

    // Even asked directly, the console controller refuses before a request
    // exists: it has no Vault and therefore no way to receipt a decision.
    expect(controller.beginDecision("approve")).toBe(false);
    await controller.confirmDecision();
    expect(controller.beginDecision("reject")).toBe(false);

    expect(fetcher.mock.calls.slice(reads)).toEqual([]);
    expect(purchaseDecisionControls(controller.state, CONSOLE).kind).toBe("handoff");
  });

  it("points at the workspace view that actually hosts the review", () => {
    expect(PURCHASE_WORKSPACE_HREF).toBe(`/workspace?view=${PURCHASE_WORKSPACE_VIEW}`);
  });
});

describe("P04-06c the workspace review owns the decision", () => {
  it("renders the approve and reject controls when a Vault binding exists", async () => {
    const { controller, state } = await readyState({ vault: boundVault() });
    const markup = render(state, controller, WORKSPACE);

    expect(buttonLabels(markup)).toEqual([
      "Approve purchase",
      "Reject purchase",
      "Refresh purchase",
    ]);
    expect(markup).not.toContain(PURCHASE_WORKSPACE_HREF);
    expect(purchaseDecisionControls(state, WORKSPACE)).toEqual({ kind: "controls", busy: false });
  });

  it("says plainly why the controls are gone when no Vault is unlocked there", async () => {
    const { controller, state } = await readyState({ vault: null });
    const markup = render(state, controller, WORKSPACE);

    expect(buttonLabels(markup)).toEqual(["Refresh purchase"]);
    expect(markup).toContain("No encrypted workspace is unlocked");
    expect(purchaseDecisionControls(state, WORKSPACE)).toEqual({
      kind: "unavailable",
      reason: "no-receipt",
    });
  });
});

describe("P04-06c the surface never widens what the state allows", () => {
  it("offers no control on either surface once the purchase is closed", async () => {
    const { state } = await readyState({ vault: boundVault(), status: "grant_issued" });
    for (const surface of [CONSOLE, WORKSPACE]) {
      expect(purchaseDecisionControls(state, surface)).toEqual({
        kind: "unavailable",
        reason: "closed",
      });
    }
  });

  it("offers no control on either surface for a role that cannot decide", async () => {
    const { state } = await readyState({ vault: boundVault(), role: "viewer" });
    for (const surface of [CONSOLE, WORKSPACE]) {
      expect(purchaseDecisionControls(state, surface)).toEqual({
        kind: "unavailable",
        reason: "role",
      });
    }
  });
});
