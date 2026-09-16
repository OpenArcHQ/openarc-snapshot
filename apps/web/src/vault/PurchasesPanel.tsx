import { useCallback, useEffect, useRef, useState } from "react";

import type { CommerceActionMetadata } from "@openarc/shared";

import { AccountFlowController } from "../account/flow-controller.js";
import { commerceActionsEnabledFromEnv } from "../tenant/action-availability.js";
import { ActionClient, readCommerceActionsCapability } from "../tenant/action-client.js";
import {
  canReadActions,
  formatAtomicAmount,
  type ActionReadCoordinator,
} from "../tenant/action-controller.js";
import {
  PurchaseController,
  initialPurchaseControllerState,
  isDecidablePurchaseStatus,
  type PurchaseControllerState,
} from "../tenant/purchase-controller.js";
import { PurchaseReviewPanel } from "../tenant/PurchaseReviewPanel.js";
import {
  TenantController,
  initialTenantState,
  type TenantViewControllerState,
} from "../tenant/tenant-controller.js";
import { createPurchaseVaultBinding, type PurchaseVaultSession } from "./purchase-binding.js";
import type { UnlockedWorkspace } from "./types.js";
import { SectionHeading } from "./VaultWorkspace.js";

import tenantCssUrl from "../tenant/tenant.css?url";
import actionCssUrl from "../tenant/control-action.css?url";
import purchaseCssUrl from "./purchase-review.css?url";

/**
 * P04-06c — the purchase review, hosted where an unlocked Vault exists.
 *
 * A purchase decision may only be sent after an encrypted receipt of exactly
 * what the human reviewed is committed and the durable revision guard and the
 * active-session check have both passed. Only this workspace unlocks a Vault,
 * owns the lock/unlock lifecycle, the cross-tab coordination channel and the
 * revision guard — so this is the only surface in the build that can offer a
 * purchase decision at all. The protected console links here instead.
 *
 * Every request this view makes uses an EXISTING browser-audience route,
 * through the existing clients the protected console already uses:
 *
 *   - the public, credentialless commerce-action capability manifest;
 *   - the account session + bootstrap (`AccountFlowController`);
 *   - `organization_list` and `organization_context` (`TenantController`);
 *   - `action_list` for the pending purchases (`ActionClient`);
 *   - `action_detail`, `approval_detail` and `action_exposure` for the review,
 *     and `action_approve` / `action_reject` for the one decision request
 *     (`PurchaseController`).
 *
 * No route is added here, and no agent-audience route is reachable. Nothing is
 * read automatically: every network step is an explicit button, and with the
 * commerce-action flag off this view is never registered and constructs no
 * controller, no client and no stylesheet.
 */

const PURCHASE_REVIEW_ENABLED = commerceActionsEnabledFromEnv();
const PENDING_PAGE_LIMIT = 25;

/** True when this build may host the purchase review inside the workspace. */
export function purchaseReviewEnabled(): boolean {
  return PURCHASE_REVIEW_ENABLED;
}

type PendingState =
  | { readonly status: "none" }
  | { readonly status: "loading" }
  | {
      readonly status: "ready";
      readonly items: readonly CommerceActionMetadata[];
      /** True when the bounded page was full: there may be more, unread. */
      readonly more: boolean;
    }
  | { readonly status: "unavailable" }
  | { readonly status: "error" };

/** Mounts the two accepted console stylesheets for this view's lifetime only. */
function usePurchaseReviewStyles(): void {
  useEffect(() => {
    const links = [tenantCssUrl, actionCssUrl, purchaseCssUrl].map((href) => {
      const link = document.createElement("link");
      link.rel = "stylesheet";
      link.href = href;
      link.dataset.purchaseReviewStyle = "true";
      document.head.append(link);
      return link;
    });
    return () => {
      for (const link of links) link.remove();
    };
  }, []);
}

export function PurchasesPanel(props: {
  workspace: UnlockedWorkspace;
  busy: boolean;
  onOpenTour: (target: HTMLElement) => void;
  purchaseVaultSession: () => PurchaseVaultSession;
}) {
  const [tenantState, setTenantState] = useState<TenantViewControllerState>(initialTenantState);
  const [purchaseState, setPurchaseState] = useState<PurchaseControllerState>(
    initialPurchaseControllerState,
  );
  const [pending, setPending] = useState<PendingState>({ status: "none" });
  const [selected, setSelected] = useState<string | null>(null);
  const [bound, setBound] = useState(false);
  const tenantRef = useRef<TenantController | null>(null);
  const purchaseRef = useRef<PurchaseController | null>(null);
  const clientRef = useRef<ActionClient | null>(null);
  const listAbortRef = useRef<AbortController | null>(null);

  usePurchaseReviewStyles();

  // One account controller, one tenant controller, one action client and one
  // purchase controller for the lifetime of this view. The workspace remounts
  // this panel on every Vault session boundary, so none of them can outlive an
  // unlock, a lock or a coordination event.
  useEffect(() => {
    if (!PURCHASE_REVIEW_ENABLED) return;
    const account = new AccountFlowController();
    const tenant = new TenantController({ account, onState: setTenantState });
    const client = new ActionClient();
    const reads: ActionReadCoordinator = {
      currentOrganizationId: () => tenant.currentOrganizationId(),
      currentRole: () => tenant.currentRole(),
      currentAccountId: () =>
        account.state.session.signedIn ? account.state.session.accountId : null,
      abortPendingReads: () => tenant.abortPendingReads(),
    };
    const purchase = new PurchaseController({
      account,
      reads,
      client,
      vault: null,
      onState: setPurchaseState,
    });
    tenantRef.current = tenant;
    purchaseRef.current = purchase;
    clientRef.current = client;
    return () => {
      listAbortRef.current?.abort();
      listAbortRef.current = null;
      purchase.dispose();
      tenant.dispose();
      account.reset();
      tenantRef.current = null;
      purchaseRef.current = null;
      clientRef.current = null;
    };
  }, []);

  // The REAL Vault binding, rebuilt whenever the unlocked workspace advances a
  // revision. With no unlocked workspace the binding is null and the controller
  // refuses every decision before a request can be built.
  const makeSession = props.purchaseVaultSession;
  useEffect(() => {
    const purchase = purchaseRef.current;
    if (purchase === null) return;
    const binding = createPurchaseVaultBinding(makeSession());
    purchase.setVault(binding);
    setBound(binding !== null);
  }, [makeSession, props.workspace]);

  const organizationId = tenantState.selectedOrganizationId;
  const role = tenantState.context?.access.role ?? null;

  const loadPending = useCallback(async () => {
    const client = clientRef.current;
    const tenant = tenantRef.current;
    if (client === null || tenant === null) return;
    const scope = tenant.currentOrganizationId();
    if (scope === null || !canReadActions(tenant.currentRole())) return;
    listAbortRef.current?.abort();
    const controller = new AbortController();
    listAbortRef.current = controller;
    setSelected(null);
    setPending({ status: "loading" });
    try {
      // The same PUBLIC credentialless manifest the console uses. A build with
      // the family disabled makes no queue request at all.
      const capability = await readCommerceActionsCapability(controller.signal);
      if (controller.signal.aborted) return;
      if (capability !== "enabled") {
        setPending({ status: "unavailable" });
        return;
      }
      const page = await client.listActions(
        { organizationId: scope, limit: PENDING_PAGE_LIMIT },
        controller.signal,
      );
      if (controller.signal.aborted) return;
      setPending({
        status: "ready",
        items: page.items.filter((item) => isDecidablePurchaseStatus(item.status)),
        more: page.nextCursor !== null,
      });
    } catch {
      if (controller.signal.aborted) return;
      setPending({ status: "error" });
    }
  }, []);

  function openPurchase(actionId: string): void {
    setSelected(actionId);
    void purchaseRef.current?.initialize(actionId);
  }

  if (!PURCHASE_REVIEW_ENABLED) {
    return (
      <section className="workspace-section" aria-labelledby="purchases-title">
        <SectionHeading
          eyebrow="COMMERCE PURCHASES"
          title="Purchases"
          id="purchases-title"
          onLearn={props.onOpenTour}
        >
          Reviewing an agent purchase is not enabled in this build.
        </SectionHeading>
        <p className="workspace-card">
          The commerce purchase review is disabled here, so this workspace constructs no purchase
          controller and makes no request of any kind for it.
        </p>
      </section>
    );
  }

  return (
    <section className="workspace-section" aria-labelledby="purchases-title">
      <SectionHeading
        eyebrow="COMMERCE PURCHASES · DECIDED HERE"
        title="Purchases"
        id="purchases-title"
        onLearn={props.onOpenTour}
      >
        Review what an agent proposes to buy and approve or reject it. Your decision is written to
        this encrypted workspace first; only then does one request leave the browser. OpenArc
        connects no wallet, signs nothing and moves no money.
      </SectionHeading>

      <p className="workspace-card">
        {bound
          ? "This workspace is unlocked, so a decision can be receipted here. If it is locked or changed in another tab before the request is sent, nothing is sent and the receipt of what you reviewed is kept."
          : "No unlocked workspace is bound to this view, so no decision can be receipted and the controls stay unavailable. Nothing is sent."}
      </p>

      <div className="workspace-card form-stack">
        <h3>1. Connect to your organization account</h3>
        <p>
          This reads your signed-in account and the organizations it can see. It reads nothing about
          any purchase yet.
        </p>
        <button
          className="button"
          type="button"
          disabled={props.busy || tenantState.busy}
          onClick={() => void tenantRef.current?.initialize()}
        >
          {tenantState.principal.status === "loading" ? "Reading account…" : "Read account and organizations"}
        </button>
        {tenantState.principal.status === "signed-out" ? (
          <p role="status">
            No signed-in account. Sign in at <a href="/account">/account</a> in this browser, then
            read again. Your workspace passphrase is never involved in that sign-in.
          </p>
        ) : null}
        {tenantState.organizations.failure !== null ? (
          <p role="alert">
            The organization list could not be read. Nothing is shown rather than a guess.
          </p>
        ) : null}
        {tenantState.organizations.items.length > 0 ? (
          <ul className="workspace-purchase-list">
            {tenantState.organizations.items.map((organization) => (
              <li key={organization.organizationId}>
                <button
                  className="button button-small"
                  type="button"
                  aria-pressed={organization.organizationId === organizationId}
                  disabled={props.busy}
                  onClick={() => void tenantRef.current?.selectOrganization(organization.organizationId)}
                >
                  {organization.displayName}
                </button>
              </li>
            ))}
          </ul>
        ) : null}
      </div>

      {organizationId === null ? null : (
        <div className="workspace-card form-stack">
          <h3>2. Read the purchases still open to a decision</h3>
          <p>
            One bounded page of this organization&rsquo;s actions, narrowed to those a human can
            still approve or reject. Nothing is polled and nothing refreshes on its own.
          </p>
          {canReadActions(role) ? (
            <button
              className="button"
              type="button"
              disabled={props.busy || pending.status === "loading"}
              onClick={() => void loadPending()}
            >
              {pending.status === "loading" ? "Reading purchases…" : "Read pending purchases"}
            </button>
          ) : (
            <p role="status">
              Your role in this organization cannot read commerce purchases, so no request is made.
            </p>
          )}
          {pending.status === "unavailable" ? (
            <p role="status">
              Commerce actions are not enabled in this deployment, so no purchase queue was read.
            </p>
          ) : null}
          {pending.status === "error" ? (
            <p role="alert">
              The purchase queue could not be read. This is not an empty queue; nothing is claimed
              about what is pending.
            </p>
          ) : null}
          {pending.status === "ready" ? (
            pending.items.length === 0 ? (
              <p role="status">
                This bounded page held no purchase still open to a decision.
                {pending.more ? " There are further pages this view did not read." : ""}
              </p>
            ) : (
              <ul className="workspace-purchase-list">
                {pending.items.map((item) => (
                  <li key={item.actionId}>
                    <button
                      className="button button-small"
                      type="button"
                      aria-pressed={item.actionId === selected}
                      disabled={props.busy}
                      onClick={() => openPurchase(item.actionId)}
                    >
                      {formatAtomicAmount(item.debitAtomic, item.exposureKey.decimals) ??
                        item.debitAtomic}{" "}
                      {item.exposureKey.asset} · {item.actionId}
                    </button>
                  </li>
                ))}
              </ul>
            )
          ) : null}
        </div>
      )}

      {selected === null ? null : (
        <div className="workspace-purchase-review">
          <div className="tenant-actions-console">
            <PurchaseReviewPanel
              state={purchaseState}
              controller={purchaseRef.current}
              actionId={selected}
              decisions={{ kind: "workspace" }}
            />
          </div>
        </div>
      )}
    </section>
  );
}
