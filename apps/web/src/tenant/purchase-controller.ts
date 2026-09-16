import {
  CommerceActionIdSchema,
  CommerceActionMetadataSchema,
  CommerceApprovalMetadataSchema,
  CommerceExposureViewSchema,
  CommerceTenantIdempotencyKeySchema,
  CommerceTenantMutationIdSchema,
  PURCHASE_OUTCOME_EXPLANATIONS,
  PURCHASE_OUTCOME_LABELS,
  purchaseOutcomeForActionStatus,
  purchaseReviewFields,
  purchaseUnknownExposureLine,
  type ActionCapabilityState,
  type CommerceActionMetadata,
  type CommerceActionMutationReceipt,
  type CommerceApprovalMetadata,
  type CommerceExposureView,
  type PurchaseDecision,
  type PurchaseExposureLine,
  type PurchaseOutcome,
  type PurchaseReviewField,
  type WorkspaceRecord,
} from "@openarc/shared";

import type { AccountBoundToken, AccountFlowController } from "../account/flow-controller.js";
import {
  PurchaseReceiptUnavailableError,
  buildPurchaseDecisionReceipt,
  runPurchaseDecisionFlow,
} from "../api/purchase-decision-flow.js";
import type { UnlockedWorkspace } from "../vault/types.js";
import {
  ActionApiError,
  ActionClient,
  createActionIdempotencyKey,
  createActionMutationId,
  readCommerceActionsCapability,
  type ActionApiFailure,
} from "./action-client.js";
import { canDecideActions, canReadActions, type ActionReadCoordinator } from "./action-controller.js";

/**
 * P04-06 — the browser purchase handoff.
 *
 * A human reviews ONE pending agent purchase — what is being bought, from which
 * seller listing and version, the exact integer amount with its asset and
 * decimals, the payee, the policy and budget that would be committed, and the
 * approval's expiry — and then approves or rejects it.
 *
 * Two rules govern everything here.
 *
 * FIRST, nothing leaves the browser before an encrypted Vault receipt of what
 * the human saw and decided is committed and the durable revision guard and
 * active-session check have both passed. Without a Vault binding the decision
 * is REFUSED, not sent ungated: zero requests are made.
 *
 * SECOND, the outcome is reported in the accepted certainty vocabulary and
 * never beyond it. This console has no browser route that returns a payment
 * attempt, so where an attempt could exist it says so explicitly instead of
 * claiming "not requested". It never renders paid, settled, refunded, failed or
 * released as a payment outcome.
 *
 * Every read and write uses ONLY the existing browser-audience routes:
 * `action_detail`, `approval_detail`, `action_exposure`, `action_approve` and
 * `action_reject`. It never calls an agent-audience route.
 */

/**
 * P04-06c — where a purchase decision is actually taken. The encrypted
 * workspace is the only surface in this build that unlocks a Vault, so it is
 * the only surface that can receipt a decision. A console without one links
 * here instead of offering a control it could never honour.
 */
export const PURCHASE_WORKSPACE_VIEW = "purchases";
export const PURCHASE_WORKSPACE_HREF = `/workspace?view=${PURCHASE_WORKSPACE_VIEW}`;

export type PurchaseReviewStatus = "none" | "loading" | "ready" | "not-found" | "error";

export interface PurchaseReviewState {
  readonly status: PurchaseReviewStatus;
  readonly actionId: string | null;
  readonly action: CommerceActionMetadata | null;
  readonly approval: CommerceApprovalMetadata | null;
  readonly exposure: CommerceExposureView | null;
  /** True when the exposure read failed; the review still stands without it. */
  readonly exposureUnavailable: boolean;
}

export interface PurchaseOutcomeView {
  readonly outcome: PurchaseOutcome;
  readonly label: string;
  readonly explanation: string;
  /** Unresolved money is ALWAYS its own line, known or not. */
  readonly unknownExposure: PurchaseExposureLine;
}

export type PurchaseFailureNotice =
  | { readonly kind: "validation" }
  | { readonly kind: "policy" }
  | { readonly kind: "conflict" }
  | { readonly kind: "unauthenticated" }
  | { readonly kind: "csrf" }
  | { readonly kind: "forbidden" }
  | { readonly kind: "not-found" }
  | { readonly kind: "account-changed" }
  | { readonly kind: "capability-disabled" }
  | { readonly kind: "no-access" }
  /** The Vault changed or the session ended: nothing was sent, the receipt is kept. */
  | { readonly kind: "vault-conflict" }
  /** No encrypted receipt could be committed, so the decision was not sent. */
  | { readonly kind: "receipt-unavailable" };

export interface PurchaseCommittedState {
  readonly decision: PurchaseDecision;
  readonly receipt: CommerceActionMutationReceipt;
  readonly metadata: CommerceActionMetadata | null;
  readonly replayed: boolean;
}

export type PurchaseDecisionState =
  | { readonly kind: "idle" }
  | { readonly kind: "confirming"; readonly decision: PurchaseDecision; readonly actionId: string }
  | { readonly kind: "pending"; readonly decision: PurchaseDecision; readonly actionId: string; readonly mutationId: string }
  | { readonly kind: "committed"; readonly committed: PurchaseCommittedState }
  | { readonly kind: "rejected"; readonly notice: PurchaseFailureNotice }
  | {
      readonly kind: "outcome-unknown";
      readonly decision: PurchaseDecision;
      readonly actionId: string;
      readonly mutationId: string;
    };

export interface PurchaseControllerState {
  readonly capability: "unknown" | "checking" | "enabled" | "unavailable";
  readonly canRead: boolean;
  readonly canDecide: boolean;
  /** True once the server has refused a decision in this context. */
  readonly serverDeniedDecision: boolean;
  /** True when no Vault binding exists, so no decision can be receipted or sent. */
  readonly receiptUnavailable: boolean;
  readonly review: PurchaseReviewState;
  readonly decision: PurchaseDecisionState;
}

/** Only these statuses can still receive a human purchase decision. */
const DECIDABLE_STATUSES: ReadonlySet<string> = new Set([
  "pending_approval",
  "reserved_not_granted",
]);

/**
 * Whether a purchase in this status can still receive a human decision. It is
 * the one place that answer is defined, so the review, the decision gate and
 * the workspace's pending list can never drift apart.
 */
export function isDecidablePurchaseStatus(status: string): boolean {
  return DECIDABLE_STATUSES.has(status);
}

export function initialPurchaseReviewState(): PurchaseReviewState {
  return {
    status: "none",
    actionId: null,
    action: null,
    approval: null,
    exposure: null,
    exposureUnavailable: false,
  };
}

export function initialPurchaseControllerState(): PurchaseControllerState {
  return {
    capability: "unknown",
    canRead: false,
    canDecide: false,
    serverDeniedDecision: false,
    receiptUnavailable: false,
    review: initialPurchaseReviewState(),
    decision: { kind: "idle" },
  };
}

/**
 * The Vault binding a decision needs. It is deliberately optional: a console
 * without an unlocked Vault refuses to decide rather than sending an unrecorded
 * approval.
 */
export interface PurchaseVaultBinding {
  readonly workspace: UnlockedWorkspace;
  readonly assertActive: () => void;
  readonly save: (
    workspace: UnlockedWorkspace,
    records: readonly WorkspaceRecord[],
    assertActive: () => void,
    signal: AbortSignal,
  ) => Promise<UnlockedWorkspace>;
  readonly verifyStored?: (workspace: UnlockedWorkspace) => Promise<void>;
  /**
   * The exact origin the decision request is sent to, recorded on the receipt.
   * Defaults to this document's own origin; a binding with neither an origin
   * nor a custom builder refuses the decision rather than guessing one.
   */
  readonly origin?: string;
  /**
   * Builds the encrypted record of exactly what the human saw and decided.
   * Returning no record refuses the decision.
   *
   * Optional since P04-06b: with no override, the v6 purchase-decision receipt
   * is built from the reviewed purchase itself.
   */
  readonly buildReceipt?: (
    workspace: UnlockedWorkspace,
    reviewed: PurchaseReceiptSubject,
  ) => readonly WorkspaceRecord[];
  readonly onWorkspaceCommitted?: (workspace: UnlockedWorkspace) => void;
}

/** Exactly what the human saw and decided, handed to the receipt builder. */
export interface PurchaseReceiptSubject {
  readonly decision: PurchaseDecision;
  readonly actionId: string;
  readonly organizationId: string;
  readonly mutationId: string;
  readonly reviewedFields: readonly PurchaseReviewField[];
  readonly outcome: PurchaseOutcomeView;
  readonly action: CommerceActionMetadata;
  readonly approval: CommerceApprovalMetadata | null;
}

export interface PurchaseControllerDeps {
  readonly account: AccountFlowController;
  readonly reads: ActionReadCoordinator;
  readonly client?: ActionClient;
  readonly capabilityReader?: (signal: AbortSignal) => Promise<ActionCapabilityState>;
  readonly vault?: PurchaseVaultBinding | null;
  readonly onState?: (state: PurchaseControllerState) => void;
}

/**
 * The honest outcome view for a purchase, driven by the certainty vocabulary.
 * Unresolved money is always its own line.
 */
export function purchaseOutcomeView(action: CommerceActionMetadata | null): PurchaseOutcomeView {
  const outcome: PurchaseOutcome =
    action === null ? "not_visible" : purchaseOutcomeForActionStatus(action.status);
  return Object.freeze({
    outcome,
    label: PURCHASE_OUTCOME_LABELS[outcome],
    explanation: PURCHASE_OUTCOME_EXPLANATIONS[outcome],
    // No browser route returns the four-bucket exposure summary, so the
    // unknown bucket is reported as unknown rather than as a zero.
    unknownExposure: purchaseUnknownExposureLine(null),
  });
}

/** The exact review of what would be committed, from the server records only. */
export function purchaseReviewOf(
  action: CommerceActionMetadata,
  approval: CommerceApprovalMetadata | null,
): readonly PurchaseReviewField[] {
  return purchaseReviewFields({
    listingId: action.listingId,
    listingVersion: action.listingVersion,
    providerId: action.providerId,
    amountAtomic: action.amountAtomic,
    feeAtomic: action.feeAtomic,
    debitAtomic: action.debitAtomic,
    asset: action.exposureKey.asset,
    decimals: action.exposureKey.decimals,
    networkId: action.exposureKey.networkId,
    policyId: action.policyId,
    policyRevision: action.policyRevision,
    // No browser-audience route returns the seller's recorded pay-to address.
    payToAddress: null,
    approvalExpiresAt: approval?.expiresAt ?? null,
  });
}

export class PurchaseController {
  #state: PurchaseControllerState = initialPurchaseControllerState();
  #disposed = false;
  #generation = 0;
  #reviewAbort: AbortController | null = null;
  #capabilityAbort: AbortController | null = null;
  #capabilityChecked = false;
  readonly #client: ActionClient;
  readonly #account: AccountFlowController;
  readonly #reads: ActionReadCoordinator;
  readonly #capabilityReader: (signal: AbortSignal) => Promise<ActionCapabilityState>;
  #vault: PurchaseVaultBinding | null;
  readonly #onState: ((state: PurchaseControllerState) => void) | undefined;

  constructor(deps: PurchaseControllerDeps) {
    this.#client = deps.client ?? new ActionClient();
    this.#account = deps.account;
    this.#reads = deps.reads;
    this.#capabilityReader =
      deps.capabilityReader ?? ((signal) => readCommerceActionsCapability(signal));
    this.#vault = deps.vault ?? null;
    this.#onState = deps.onState;
  }

  get state(): PurchaseControllerState {
    return this.#state;
  }

  get disposed(): boolean {
    return this.#disposed;
  }

  /** Rebinds the Vault without touching any loaded review. */
  setVault(vault: PurchaseVaultBinding | null): void {
    if (this.#disposed) return;
    this.#vault = vault;
    this.#update({});
  }

  /**
   * Independent capability gate, then ONE review read. With the capability not
   * `enabled`, no purchase request is ever made.
   */
  async initialize(actionId: string): Promise<void> {
    if (this.#disposed) return;
    const generation = this.#generation;
    if (!this.#capabilityChecked) {
      this.#update({ capability: "checking" });
      this.#capabilityAbort?.abort();
      const controller = new AbortController();
      this.#capabilityAbort = controller;
      let state: ActionCapabilityState;
      try {
        state = await this.#capabilityReader(controller.signal);
      } catch {
        if (generation !== this.#generation || controller.signal.aborted) return;
        this.#update({ capability: "unavailable" });
        return;
      }
      if (!this.#stillCurrent(generation) || controller.signal.aborted) return;
      this.#capabilityAbort = null;
      this.#capabilityChecked = true;
      if (state !== "enabled") {
        this.#update({ capability: "unavailable" });
        return;
      }
      this.#update({ capability: "enabled" });
    }
    if (this.#state.capability !== "enabled") return;
    if (!this.#accessAllowed()) {
      this.#update({ decision: { kind: "rejected", notice: { kind: "no-access" } } });
      return;
    }
    await this.loadPurchase(actionId);
  }

  /**
   * Reads the action, its approval and the policy exposure through the existing
   * browser routes. A failed exposure read never blocks the review; it is
   * reported as unavailable instead of shown as a zero budget.
   */
  async loadPurchase(actionId: string): Promise<void> {
    if (this.#disposed || !this.#accessAllowed()) return;
    const organizationId = this.#currentOrganizationId();
    if (organizationId === null) return;
    if (!CommerceActionIdSchema.safeParse(actionId).success) {
      this.#update({ review: { ...initialPurchaseReviewState(), status: "error", actionId } });
      return;
    }
    const generation = this.#generation;
    this.#reviewAbort?.abort();
    const controller = new AbortController();
    this.#reviewAbort = controller;
    this.#update({ review: { ...initialPurchaseReviewState(), status: "loading", actionId } });

    let action: CommerceActionMetadata;
    try {
      const detail = await this.#client.readAction({ organizationId, actionId }, controller.signal);
      if (!this.#current(generation, organizationId)) return;
      if (detail.item === null) {
        this.#update({ review: { ...initialPurchaseReviewState(), status: "not-found", actionId } });
        return;
      }
      const parsed = CommerceActionMetadataSchema.safeParse(detail.item);
      if (!parsed.success) {
        this.#update({ review: { ...initialPurchaseReviewState(), status: "error", actionId } });
        return;
      }
      action = parsed.data;
    } catch {
      if (!this.#current(generation, organizationId)) return;
      this.#update({ review: { ...initialPurchaseReviewState(), status: "error", actionId } });
      return;
    }

    let approval: CommerceApprovalMetadata | null = null;
    if (action.approvalId !== null) {
      try {
        const detail = await this.#client.readApproval(
          { organizationId, approvalId: action.approvalId },
          controller.signal,
        );
        if (!this.#current(generation, organizationId)) return;
        const parsed =
          detail.item === null ? null : CommerceApprovalMetadataSchema.safeParse(detail.item);
        approval = parsed !== null && parsed.success ? parsed.data : null;
      } catch {
        if (!this.#current(generation, organizationId)) return;
        // The approval expiry is then genuinely absent, never invented.
        approval = null;
      }
    }

    let exposure: CommerceExposureView | null = null;
    let exposureUnavailable = false;
    try {
      const data = await this.#client.readExposure(
        {
          organizationId,
          subjectAgentId: action.exposureKey.subjectAgentId,
          policyId: action.policyId,
        },
        controller.signal,
      );
      if (!this.#current(generation, organizationId)) return;
      const parsed = data.item === null ? null : CommerceExposureViewSchema.safeParse(data.item);
      if (parsed !== null && parsed.success) exposure = parsed.data;
      else exposureUnavailable = true;
    } catch {
      if (!this.#current(generation, organizationId)) return;
      exposureUnavailable = true;
    }

    this.#update({
      review: { status: "ready", actionId, action, approval, exposure, exposureUnavailable },
    });
  }

  /** The exact review rows the human is shown, or an empty list before a read. */
  reviewFields(): readonly PurchaseReviewField[] {
    const action = this.#state.review.action;
    if (action === null) return Object.freeze([]);
    return purchaseReviewOf(action, this.#state.review.approval);
  }

  /** The honest outcome view for the loaded purchase. */
  outcome(): PurchaseOutcomeView {
    return purchaseOutcomeView(this.#state.review.action);
  }

  /**
   * Begins an explicit confirmation. No request, mutation id or idempotency key
   * exists yet. A missing Vault binding refuses here, before any of that.
   */
  beginDecision(decision: PurchaseDecision): boolean {
    if (this.#disposed) return false;
    if (this.#state.capability !== "enabled") {
      this.#update({ decision: { kind: "rejected", notice: { kind: "capability-disabled" } } });
      return false;
    }
    if (!this.#canDecide()) {
      this.#update({ decision: { kind: "rejected", notice: { kind: "no-access" } } });
      return false;
    }
    const action = this.#state.review.action;
    if (action === null || !DECIDABLE_STATUSES.has(action.status)) {
      this.#update({ decision: { kind: "rejected", notice: { kind: "validation" } } });
      return false;
    }
    if (this.#vault === null) {
      // No receipt can be committed, so no decision may be sent.
      this.#update({ decision: { kind: "rejected", notice: { kind: "receipt-unavailable" } } });
      return false;
    }
    this.#generation += 1;
    this.#update({ decision: { kind: "confirming", decision, actionId: action.actionId } });
    return true;
  }

  cancelDecision(): void {
    if (this.#disposed) return;
    if (this.#state.decision.kind === "pending") return;
    this.#generation += 1;
    this.#update({ decision: { kind: "idle" } });
  }

  /**
   * Commits the receipt, runs the revision guard and the active-session check,
   * and only then sends exactly ONE decision request with a frozen mutation id
   * and idempotency key. There is no automatic retry and no new key on failure.
   */
  async confirmDecision(): Promise<void> {
    if (this.#disposed) return;
    const current = this.#state.decision;
    if (current.kind !== "confirming") return;
    const action = this.#state.review.action;
    const vault = this.#vault;
    if (action === null || action.actionId !== current.actionId) {
      this.#update({ decision: { kind: "rejected", notice: { kind: "validation" } } });
      return;
    }
    if (vault === null) {
      this.#update({ decision: { kind: "rejected", notice: { kind: "receipt-unavailable" } } });
      return;
    }
    const organizationId = this.#currentOrganizationId();
    if (organizationId === null) return;
    const mutationId = createActionMutationId();
    const idempotencyKey = createActionIdempotencyKey();
    if (
      !CommerceTenantMutationIdSchema.safeParse(mutationId).success ||
      !CommerceTenantIdempotencyKeySchema.safeParse(idempotencyKey).success
    ) {
      this.#update({ decision: { kind: "rejected", notice: { kind: "validation" } } });
      return;
    }
    const decision = current.decision;
    const subject: PurchaseReceiptSubject = {
      decision,
      actionId: action.actionId,
      organizationId,
      mutationId,
      reviewedFields: purchaseReviewOf(action, this.#state.review.approval),
      outcome: purchaseOutcomeView(action),
      action,
      approval: this.#state.review.approval,
    };
    // P04-06b: with no override the v6 purchase-decision receipt is built here.
    // It needs the exact origin the request is sent to; a binding that supplies
    // neither an origin nor a builder refuses rather than recording a guess.
    const custom = vault.buildReceipt;
    const origin =
      vault.origin ?? (typeof window === "undefined" ? null : window.location.origin);
    const buildReceipt =
      custom !== undefined
        ? (workspace: UnlockedWorkspace) => custom(workspace, subject)
        : origin === null
          ? null
          : (workspace: UnlockedWorkspace) => [
              buildPurchaseDecisionReceipt(workspace, origin, subject),
            ];
    if (buildReceipt === null) {
      this.#update({ decision: { kind: "rejected", notice: { kind: "receipt-unavailable" } } });
      return;
    }
    const generation = this.#generation;
    this.#update({ decision: { kind: "pending", decision, actionId: action.actionId, mutationId } });
    this.#reads.abortPendingReads();
    const accountBound: AccountBoundToken = this.#account.captureAccountBound();
    try {
      const outcome = await this.#account.mutate(
        async ({ csrfToken, signal }) =>
          runPurchaseDecisionFlow({
            workspace: vault.workspace,
            signal,
            assertActive: vault.assertActive,
            save: vault.save,
            ...(vault.verifyStored === undefined ? {} : { verifyStored: vault.verifyStored }),
            buildReceipt,
            send: async (sendSignal) => {
              const request = {
                organizationId,
                actionId: action.actionId,
                csrfToken,
                idempotencyKey,
                signal: sendSignal,
                body: { mutationId },
              };
              return decision === "approve"
                ? this.#client.approve(request)
                : this.#client.reject(request);
            },
          }),
        { accountBound },
      );
      if (!this.#stillCurrent(generation)) return;
      vault.onWorkspaceCommitted?.(outcome.workspace);
      const metadata = CommerceActionMetadataSchema.safeParse(outcome.result.metadata);
      this.#update({
        decision: {
          kind: "committed",
          committed: {
            decision,
            receipt: outcome.result.receipt,
            metadata: metadata.success ? metadata.data : null,
            replayed: outcome.result.replayed,
          },
        },
      });
      await this.loadPurchase(action.actionId);
    } catch (error) {
      if (!this.#stillCurrent(generation)) return;
      this.#handleFailure(error, decision, action.actionId, mutationId);
    }
  }

  #handleFailure(
    error: unknown,
    decision: PurchaseDecision,
    actionId: string,
    mutationId: string,
  ): void {
    if (error instanceof PurchaseReceiptUnavailableError) {
      this.#update({ decision: { kind: "rejected", notice: { kind: "receipt-unavailable" } } });
      return;
    }
    if (isVaultConflict(error)) {
      // Nothing was sent and the committed receipt stands.
      this.#update({ decision: { kind: "rejected", notice: { kind: "vault-conflict" } } });
      return;
    }
    const failure = failureOf(error);
    switch (failure.kind) {
      case "unauthenticated":
      case "csrf":
      case "validation":
      case "policy":
      case "conflict":
      case "not-found":
      case "account-changed":
        this.#update({ decision: { kind: "rejected", notice: { kind: failure.kind } } });
        return;
      case "forbidden":
        this.#update({
          serverDeniedDecision: true,
          decision: { kind: "rejected", notice: { kind: "forbidden" } },
        });
        return;
      case "feature-disabled":
        this.#update({ decision: { kind: "rejected", notice: { kind: "capability-disabled" } } });
        return;
      case "aborted":
        this.#update({ decision: { kind: "idle" } });
        return;
      case "pre-send":
        this.#update({ decision: { kind: "rejected", notice: { kind: "validation" } } });
        return;
      default:
        // Sent but unconfirmed. It is never a success, a failure, a return of
        // money or a release; it is reported as genuinely unknown.
        this.#update({ decision: { kind: "outcome-unknown", decision, actionId, mutationId } });
        return;
    }
  }

  /** Clears every loaded review and decision artifact without any request. */
  clear(): void {
    if (this.#disposed) return;
    this.#generation += 1;
    this.#abortAll();
    this.#update({
      serverDeniedDecision: false,
      review: initialPurchaseReviewState(),
      decision: { kind: "idle" },
    });
  }

  dispose(): void {
    if (this.#disposed) return;
    this.#generation += 1;
    this.#abortAll();
    this.#disposed = true;
    this.#state = initialPurchaseControllerState();
    this.#onState?.(this.#state);
  }

  #abortAll(): void {
    this.#reviewAbort?.abort();
    this.#reviewAbort = null;
    this.#capabilityAbort?.abort();
    this.#capabilityAbort = null;
  }

  #accessAllowed(): boolean {
    if (!this.#capabilityChecked) return false;
    if (this.#account.state.session.signedIn !== true) return false;
    if (this.#account.state.session.method === "recovery") return false;
    return canReadActions(this.#reads.currentRole());
  }

  #canDecide(): boolean {
    if (this.#state.serverDeniedDecision) return false;
    return this.#accessAllowed() && canDecideActions(this.#reads.currentRole());
  }

  #currentOrganizationId(): string | null {
    return this.#reads.currentOrganizationId();
  }

  #current(generation: number, organizationId: string): boolean {
    return this.#stillCurrent(generation) && this.#currentOrganizationId() === organizationId;
  }

  #stillCurrent(generation: number): boolean {
    return !this.#disposed && generation === this.#generation;
  }

  #update(patch: Partial<PurchaseControllerState>): void {
    if (this.#disposed) return;
    this.#state = { ...this.#state, ...patch };
    this.#state = {
      ...this.#state,
      canRead: this.#accessAllowed(),
      canDecide: this.#canDecide(),
      receiptUnavailable: this.#vault === null,
    };
    this.#onState?.(this.#state);
  }
}

function isVaultConflict(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    (error as { code?: unknown }).code === "VAULT_CONFLICT"
  );
}

function failureOf(error: unknown): { kind: ActionApiFailure["kind"] | "account-changed" } {
  if (error instanceof ActionApiError) return { kind: error.failure.kind };
  if (typeof error === "object" && error !== null) {
    const failure = (error as { failure?: { kind?: unknown } }).failure;
    if (typeof failure === "object" && failure !== null) {
      const kind = (failure as { kind?: unknown }).kind;
      if (kind === "account-changed") return { kind: "account-changed" };
      if (typeof kind === "string") return { kind: kind as ActionApiFailure["kind"] };
    }
  }
  return { kind: "outcome-unknown" };
}

/** The single sentence describing what a decision state currently means. */
export function purchaseDecisionOutcomeLabel(decision: PurchaseDecisionState): string {
  switch (decision.kind) {
    case "idle":
      return "No decision in progress.";
    case "confirming":
      return "Waiting for your explicit confirmation. Nothing has been sent.";
    case "pending":
      return "One decision request is in flight. Do not resubmit.";
    case "committed":
      return decision.committed.replayed
        ? "The server reports this decision was already committed."
        : "The server committed this decision.";
    case "rejected":
      return "The decision was refused before it could commit.";
    case "outcome-unknown":
      return "The outcome is unknown. It is not a success, not a rejection and not a return of money.";
  }
}

/** The message for each refusal. None of these describes money moving. */
export function purchaseRejectionMessage(notice: PurchaseFailureNotice): string {
  switch (notice.kind) {
    case "validation":
      return "The request was refused as invalid before it could commit. Nothing changed.";
    case "policy":
      return "A policy rule refused this decision. Nothing changed and no money moved.";
    case "conflict":
      return "The server reported a conflicting state for this purchase. Nothing was resent. Refresh and look again.";
    case "unauthenticated":
      return "Your session is no longer signed in, so the decision was not sent. Sign in again.";
    case "csrf":
      return "The request was refused for a security check. Reload the page and decide again.";
    case "forbidden":
      return "The server refused this decision for your account. The server is the authority here, not this page.";
    case "not-found":
      return "The server does not have this purchase. Nothing changed.";
    case "account-changed":
      return "The signed-in account changed, so the decision was abandoned before it was sent.";
    case "capability-disabled":
      return "Commerce actions are not enabled in this deployment, so no decision was sent.";
    case "no-access":
      return "Your role cannot decide commerce purchases. No request was made.";
    case "vault-conflict":
      return "Your encrypted workspace changed or was locked in another tab. Nothing was sent, and the receipt of what you reviewed was kept. Unlock again before deciding.";
    case "receipt-unavailable":
      return "This decision was not sent because no encrypted local receipt of what you reviewed could be committed. Nothing left this browser.";
  }
}
