import {
  CommerceActionIdSchema,
  CommerceActionMetadataSchema,
  CommerceAgentIdSchema,
  CommerceApprovalMetadataSchema,
  CommerceExposureViewSchema,
  CommercePolicyIdSchema,
  CommerceTenantIdempotencyKeySchema,
  CommerceTenantMutationIdSchema,
  type CommerceActionMetadata,
  type CommerceActionMutationReceipt,
  type CommerceApprovalMetadata,
  type CommerceExposureView,
  type ActionCapabilityState,
} from "@openarc/shared";

import type { AccountBoundToken, AccountFlowController } from "../account/flow-controller.js";
import {
  ACTION_DECISION_OPERATIONS,
  ACTION_PAGE_LIMIT,
  ActionApiError,
  ActionClient,
  createActionIdempotencyKey,
  createActionMutationId,
  readCommerceActionsCapability,
  type ActionApiFailure,
  type ActionDecisionKind,
  type ActionMutationOperation,
} from "./action-client.js";
import type { ActionRoute } from "./action-routes.js";

/**
 * Bounded commerce action/approval console controller.
 *
 * The controller owns at most ONE explicit human decision at a time. A logical
 * mutation id, idempotency key, target action and body are frozen for the
 * lifetime of a request: there is no automatic retry, no polling, no new key
 * and no "latest state" preflight. A sent-but-unconfirmed outcome is reported
 * as `outcome-unknown` and can only be resolved by an explicit, user-initiated
 * status GET with the ORIGINAL mutation id.
 *
 * Nothing here is ever optimistic. A decision is never shown as applied before
 * a committed receipt arrives, and an unknown outcome is rendered as genuinely
 * unknown — never as success, failure, refund or release. An approval is not a
 * payment and a reservation is not a settlement: this console never renders a
 * paid/settled/delivered/purchased state, because no accepted shape on this
 * wire can carry one.
 *
 * Quantities stay canonical strings end to end. Exposure values are formatted
 * for display only, by exact string placement of the decimal separator; no
 * amount is ever parsed into a JavaScript number, rounded or approximated.
 */

export const ACTION_CURSOR_STACK_LIMIT = 20;

/**
 * Exact role matrix. Owner, operator and viewer on a current non-recovery
 * account may READ the queues, detail and exposure. Only owner and operator may
 * DECIDE. Provider, unknown and recovery sign-in get no access at all.
 *
 * This is a UI gate only. The server remains the final authority: a decision
 * denied by the server is recorded and disables the local controls rather than
 * letting this local guess stand.
 */
export function canReadActions(role: string | null | undefined): boolean {
  return role === "owner" || role === "operator" || role === "viewer";
}

export function canDecideActions(role: string | null | undefined): boolean {
  return role === "owner" || role === "operator";
}

/** Appends a cursor to the bounded previous-page stack (max 20). */
export function appendActionCursor(
  stack: readonly string[],
  cursor: string,
): readonly string[] {
  const next = [...stack, cursor];
  return next.length > ACTION_CURSOR_STACK_LIMIT
    ? next.slice(next.length - ACTION_CURSOR_STACK_LIMIT)
    : next;
}

const CANONICAL_AMOUNT = /^(0|[1-9][0-9]{0,127})(?![\s\S])/u;

/**
 * Places the decimal separator in a canonical atomic amount by EXACT string
 * arithmetic. There is no `Number`, no `parseFloat`, no rounding and no
 * truncation: every digit of the source survives, and an input that is not a
 * canonical nonnegative decimal returns null rather than a guessed value.
 */
export function formatAtomicAmount(atomic: string, decimals: number): string | null {
  if (typeof atomic !== "string" || !CANONICAL_AMOUNT.test(atomic)) return null;
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 36) return null;
  if (decimals === 0) return atomic;
  const padded = atomic.padStart(decimals + 1, "0");
  const whole = padded.slice(0, padded.length - decimals);
  const fraction = padded.slice(padded.length - decimals);
  return `${whole}.${fraction}`;
}

export interface ExposureRow {
  readonly key: string;
  readonly label: string;
  /** The exact canonical server string, or null when the server sent null. */
  readonly atomic: string | null;
  /** The same value with the decimal separator placed, or null. */
  readonly display: string | null;
  readonly explanation: string;
}

/**
 * The exact exposure figures, labelled in plain language and carrying BOTH the
 * canonical atomic string and its decimal placement. Nothing is derived,
 * summed, rounded or inferred here; a null `availableAtomic` means "no rolling
 * cap", which is stated rather than shown as a zero balance.
 */
export function exposureRows(view: CommerceExposureView): readonly ExposureRow[] {
  const decimals = view.decimals;
  const row = (
    key: string,
    label: string,
    atomic: string | null,
    explanation: string,
  ): ExposureRow => ({
    key,
    label,
    atomic,
    display: atomic === null ? null : formatAtomicAmount(atomic, decimals),
    explanation,
  });
  return Object.freeze([
    row(
      "available",
      "Available",
      view.availableAtomic,
      view.availableAtomic === null
        ? "This policy has no rolling cap, so the server reports no available figure. This is not a wallet balance."
        : "What the rolling policy cap still allows at the server's asOf instant. This is not a wallet balance.",
    ),
    row(
      "unresolved",
      "Reserved, not resolved",
      view.unresolvedAtomic,
      "Held against the cap for actions that have not resolved. A reservation is not a settlement and not a payment.",
    ),
    row(
      "committed",
      "Committed",
      view.committedAtomic,
      "Recorded by the server as committed exposure. It does not assert that anything was paid, settled or delivered.",
    ),
    row(
      "total",
      "Total exposure",
      view.totalExposureAtomic,
      "The server's exact committed + reserved total. It is reported, not recomputed here.",
    ),
    row(
      "deficit",
      "Over the cap by",
      view.deficitAtomic,
      "How far the server reports exposure exceeding the rolling cap. Zero means no reported deficit.",
    ),
  ]);
}

/**
 * The accepted action vocabulary has no expired-amount figure, so expiry is
 * reported per action rather than as an exposure total. This keeps the console
 * honest: it never invents an "expired" balance the server did not send.
 */
export function actionStatusLabel(status: string): string {
  switch (status) {
    case "pending_approval":
      return "Pending approval";
    case "reserved_not_granted":
      return "Reserved, not granted";
    case "grant_issued":
      return "Grant issued";
    case "rejected":
      return "Rejected";
    case "cancelled":
      return "Cancelled";
    case "expired":
      return "Expired";
    default:
      return "Unknown";
  }
}

/**
 * What a status does NOT mean. Every action status is explained so no reader
 * can take a reservation or a grant for a payment, settlement or delivery.
 */
export function actionStatusExplanation(status: string): string {
  switch (status) {
    case "pending_approval":
      return "Waiting for a human decision. Nothing has been reserved and nothing has been paid.";
    case "reserved_not_granted":
      return "An amount is held against the policy cap. No grant was issued, nothing was paid and nothing was settled.";
    case "grant_issued":
      return "A grant exists for this action. A grant is permission, not a payment, a settlement or a delivery.";
    case "rejected":
      return "A human rejected this action. No grant was issued.";
    case "cancelled":
      return "This action was cancelled. No grant was issued.";
    case "expired":
      return "This action expired without a decision. No grant was issued.";
    default:
      return "The server reported a status this console does not recognise. It is shown as unknown rather than guessed.";
  }
}

export function approvalStatusLabel(status: string): string {
  switch (status) {
    case "pending":
      return "Pending";
    case "approved":
      return "Approved";
    case "rejected":
      return "Rejected";
    case "expired":
      return "Expired";
    default:
      return "Unknown";
  }
}

/** Exactly what each decision does, in plain language, before it is sent. */
export function decisionSummary(decision: ActionDecisionKind): string {
  switch (decision) {
    case "approve":
      return "Approve records a human approval for this action. It is not a payment and it does not settle, deliver or purchase anything.";
    case "reject":
      return "Reject records a human rejection. No grant is issued and nothing is paid or refunded by this decision.";
    case "cancel":
      return "Cancel ends this action without a grant. It does not release, refund or settle money by itself.";
  }
}

export function decisionVerb(decision: ActionDecisionKind): string {
  switch (decision) {
    case "approve":
      return "Approve";
    case "reject":
      return "Reject";
    case "cancel":
      return "Cancel action";
  }
}

/**
 * The display fields of an action. `requirementDigest` is deliberately ABSENT:
 * a digest is never rendered, logged or copied by this console.
 */
export interface ActionDisplayField {
  readonly key: string;
  readonly label: string;
  readonly value: string;
}

export function actionDisplayFields(
  metadata: CommerceActionMetadata,
): readonly ActionDisplayField[] {
  const decimals = metadata.exposureKey.decimals;
  const amount = formatAtomicAmount(metadata.amountAtomic, decimals);
  const fee = formatAtomicAmount(metadata.feeAtomic, decimals);
  const debit = formatAtomicAmount(metadata.debitAtomic, decimals);
  return Object.freeze([
    { key: "actionId", label: "Action", value: metadata.actionId },
    { key: "status", label: "Status", value: actionStatusLabel(metadata.status) },
    { key: "subjectAgentId", label: "Subject agent", value: metadata.exposureKey.subjectAgentId },
    { key: "policyId", label: "Policy", value: metadata.policyId },
    { key: "policyRevision", label: "Policy revision", value: metadata.policyRevision },
    { key: "providerId", label: "Provider", value: metadata.providerId },
    { key: "listingId", label: "Listing", value: metadata.listingId },
    { key: "listingVersion", label: "Listing version", value: metadata.listingVersion },
    { key: "requirementId", label: "Requirement", value: metadata.requirementId },
    { key: "asset", label: "Asset", value: metadata.exposureKey.asset },
    { key: "networkId", label: "Network", value: metadata.exposureKey.networkId },
    {
      key: "amountAtomic",
      label: "Amount",
      value: `${amount ?? metadata.amountAtomic} (${metadata.amountAtomic} atomic)`,
    },
    {
      key: "feeAtomic",
      label: "Fee",
      value: `${fee ?? metadata.feeAtomic} (${metadata.feeAtomic} atomic)`,
    },
    {
      key: "debitAtomic",
      label: "Total debit if granted",
      value: `${debit ?? metadata.debitAtomic} (${metadata.debitAtomic} atomic)`,
    },
    {
      key: "reservationId",
      label: "Reservation",
      value: metadata.reservationId ?? "none",
    },
    { key: "approvalId", label: "Approval", value: metadata.approvalId ?? "none" },
    { key: "createdAt", label: "Created", value: metadata.createdAt },
    { key: "updatedAt", label: "Updated", value: metadata.updatedAt },
    { key: "expiresAt", label: "Expires", value: metadata.expiresAt },
  ]);
}

export type ActionDecisionDraft = {
  readonly decision: ActionDecisionKind;
  readonly actionId: string;
};

export type ActionFailureNotice =
  | { readonly kind: "validation" }
  | { readonly kind: "policy" }
  | { readonly kind: "conflict" }
  | { readonly kind: "unauthenticated" }
  | { readonly kind: "csrf" }
  | { readonly kind: "forbidden" }
  | { readonly kind: "not-found" }
  | { readonly kind: "account-changed" }
  | { readonly kind: "capability-disabled" }
  | { readonly kind: "no-access" };

export interface ActionOutcomeUnknown {
  readonly kind: "outcome-unknown";
  readonly mutationId: string;
  readonly organizationId: string;
  readonly operation: ActionMutationOperation;
  readonly decision: ActionDecisionKind;
  readonly actionId: string;
  readonly checking: boolean;
  readonly statusMessage: string | null;
}

export interface ActionCommittedState {
  readonly decision: ActionDecisionKind;
  readonly receipt: CommerceActionMutationReceipt;
  readonly metadata: CommerceActionMetadata | null;
  readonly replayed: boolean;
  readonly refreshError: boolean;
}

export type ActionDecisionState =
  | { readonly kind: "idle" }
  | { readonly kind: "confirming"; readonly draft: ActionDecisionDraft }
  | {
      readonly kind: "pending";
      readonly draft: ActionDecisionDraft;
      readonly mutationId: string;
    }
  | { readonly kind: "committed"; readonly committed: ActionCommittedState }
  | { readonly kind: "rejected"; readonly notice: ActionFailureNotice }
  | ActionOutcomeUnknown;

export type ActionQueueStatus = "none" | "loading" | "ready" | "error";

export interface ActionQueueState {
  readonly status: ActionQueueStatus;
  readonly items: readonly CommerceActionMetadata[];
  readonly nextCursor: string | null;
  readonly hasPrevious: boolean;
  readonly cursorStack: readonly string[];
}

export interface ApprovalQueueState {
  readonly status: ActionQueueStatus;
  readonly items: readonly CommerceApprovalMetadata[];
  readonly nextCursor: string | null;
  readonly hasPrevious: boolean;
  readonly cursorStack: readonly string[];
}

export interface ActionDetailState {
  readonly status: "none" | "loading" | "ready" | "not-found" | "error";
  readonly item: CommerceActionMetadata | null;
}

export interface ApprovalDetailState {
  readonly status: "none" | "loading" | "ready" | "not-found" | "error";
  readonly item: CommerceApprovalMetadata | null;
}

export interface ExposureState {
  readonly status: "none" | "loading" | "ready" | "not-found" | "error";
  readonly subjectAgentId: string | null;
  readonly policyId: string | null;
  readonly item: CommerceExposureView | null;
}

export interface ActionControllerState {
  readonly capability: "unknown" | "checking" | "enabled" | "unavailable";
  readonly role: string | null;
  readonly canRead: boolean;
  readonly canDecide: boolean;
  /**
   * True once the server has refused a decision for this context. The local
   * role matrix is only a guess; a server denial is authoritative and disables
   * the decision controls until the context changes.
   */
  readonly serverDeniedDecision: boolean;
  readonly selection: { readonly route: ActionRoute };
  readonly actions: ActionQueueState;
  readonly approvals: ApprovalQueueState;
  readonly detail: ActionDetailState;
  readonly approvalDetail: ApprovalDetailState;
  readonly exposure: ExposureState;
  readonly decision: ActionDecisionState;
}

export function initialActionQueueState(): ActionQueueState {
  return { status: "none", items: [], nextCursor: null, hasPrevious: false, cursorStack: [] };
}

export function initialApprovalQueueState(): ApprovalQueueState {
  return { status: "none", items: [], nextCursor: null, hasPrevious: false, cursorStack: [] };
}

export function initialActionDetailState(): ActionDetailState {
  return { status: "none", item: null };
}

export function initialApprovalDetailState(): ApprovalDetailState {
  return { status: "none", item: null };
}

export function initialExposureState(): ExposureState {
  return { status: "none", subjectAgentId: null, policyId: null, item: null };
}

export function initialActionControllerState(): ActionControllerState {
  return {
    capability: "unknown",
    role: null,
    canRead: false,
    canDecide: false,
    serverDeniedDecision: false,
    selection: { route: { kind: "queue" } },
    actions: initialActionQueueState(),
    approvals: initialApprovalQueueState(),
    detail: initialActionDetailState(),
    approvalDetail: initialApprovalDetailState(),
    exposure: initialExposureState(),
    decision: { kind: "idle" },
  };
}

export interface ActionReadCoordinator {
  currentOrganizationId(): string | null;
  currentRole(): string | null;
  currentAccountId(): string | null;
  abortPendingReads(): void;
}

export interface ActionControllerDeps {
  readonly client?: ActionClient;
  readonly account: AccountFlowController;
  readonly reads: ActionReadCoordinator;
  readonly capabilityReader?: (signal: AbortSignal) => Promise<ActionCapabilityState>;
  readonly onState?: (state: ActionControllerState) => void;
}

interface FrozenDecision {
  readonly draft: ActionDecisionDraft;
  readonly mutationId: string;
  readonly idempotencyKey: string;
  readonly organizationId: string;
}

export class ActionController {
  #state: ActionControllerState = initialActionControllerState();
  #disposed = false;
  #generation = 0;
  #actionsAbort: AbortController | null = null;
  #approvalsAbort: AbortController | null = null;
  #detailAbort: AbortController | null = null;
  #approvalDetailAbort: AbortController | null = null;
  #exposureAbort: AbortController | null = null;
  #statusAbort: AbortController | null = null;
  #capabilityAbort: AbortController | null = null;
  #capabilityChecked = false;
  readonly #client: ActionClient;
  readonly #account: AccountFlowController;
  readonly #reads: ActionReadCoordinator;
  readonly #capabilityReader: (signal: AbortSignal) => Promise<ActionCapabilityState>;
  readonly #onState: ((state: ActionControllerState) => void) | undefined;

  constructor(deps: ActionControllerDeps) {
    this.#client = deps.client ?? new ActionClient();
    this.#account = deps.account;
    this.#reads = deps.reads;
    this.#capabilityReader =
      deps.capabilityReader ?? ((signal) => readCommerceActionsCapability(signal));
    this.#onState = deps.onState;
  }

  get state(): ActionControllerState {
    return this.#state;
  }

  get disposed(): boolean {
    return this.#disposed;
  }

  /** Points the controller at a parsed route without issuing any request. */
  setRoute(route: ActionRoute): void {
    if (this.#disposed) return;
    this.#update({ selection: { route } });
  }

  /**
   * Independent capability gate. It runs BEFORE any action request and never
   * depends on tenant-writes, machine, listing, policy, session, Vault or
   * wallet flags. On a known action route with the flag on but the capability
   * not `enabled`, state is `unavailable` and NO action request is ever made.
   */
  async initialize(route: ActionRoute): Promise<void> {
    if (this.#disposed) return;
    if (route.kind === "invalid") {
      this.#update({ selection: { route } });
      return;
    }
    const generation = this.#generation;
    this.#update({ selection: { route } });
    if (!this.#capabilityChecked) {
      this.#update({ capability: "checking" });
      this.#capabilityAbort?.abort();
      const capabilityController = new AbortController();
      this.#capabilityAbort = capabilityController;
      let state: ActionCapabilityState;
      try {
        state = await this.#capabilityReader(capabilityController.signal);
      } catch {
        if (generation !== this.#generation) return;
        if (capabilityController.signal.aborted) return;
        this.#update({ capability: "unavailable" });
        return;
      }
      if (!this.#stillCurrent(generation)) return;
      if (capabilityController.signal.aborted) return;
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
      // No request, no control: a clear local no-access state.
      this.#update({ decision: { kind: "rejected", notice: { kind: "no-access" } } });
      return;
    }
    switch (route.kind) {
      case "queue":
        await this.loadActions();
        return;
      case "approvals":
        await this.loadApprovals();
        return;
      case "detail":
        await this.loadActionDetail(route.actionId);
        return;
      case "approval-detail":
        await this.loadApprovalDetail(route.approvalId);
        return;
      case "exposure":
        // The exposure view needs an explicit agent + policy selection. It makes
        // no request until the user supplies both.
        return;
      default:
        return;
    }
  }

  // ── Action queue ──────────────────────────────────────────────────────────

  async loadActions(): Promise<void> {
    await this.#loadActionPage(false);
  }

  async loadNextActions(): Promise<void> {
    await this.#loadActionPage(true);
  }

  async loadPreviousActions(): Promise<void> {
    if (this.#disposed || !this.#accessAllowed()) return;
    const stack = this.#state.actions.cursorStack;
    if (stack.length === 0) return;
    const cursor = stack[stack.length - 1] ?? null;
    const nextStack = stack.slice(0, -1);
    const organizationId = this.#currentOrganizationId();
    if (organizationId === null) return;
    const generation = this.#generation;
    this.#actionsAbort?.abort();
    const controller = new AbortController();
    this.#actionsAbort = controller;
    this.#update({ actions: { ...this.#state.actions, status: "loading" } });
    try {
      const page = await this.#client.listActions(
        { organizationId, ...(cursor === null ? {} : { afterActionId: cursor }) },
        controller.signal,
      );
      if (!this.#stillCurrent(generation) || this.#currentOrganizationId() !== organizationId) {
        return;
      }
      this.#update({
        actions: {
          status: "ready",
          items: page.items,
          nextCursor: page.nextCursor,
          hasPrevious: nextStack.length > 0,
          cursorStack: nextStack,
        },
      });
    } catch {
      if (!this.#stillCurrent(generation) || this.#currentOrganizationId() !== organizationId) {
        return;
      }
      this.#update({ actions: { ...this.#state.actions, status: "error" } });
    }
  }

  async #loadActionPage(next: boolean): Promise<void> {
    if (this.#disposed || !this.#accessAllowed()) return;
    const organizationId = this.#currentOrganizationId();
    if (organizationId === null) return;
    const cursor = next ? this.#state.actions.nextCursor : null;
    if (next && cursor === null) return;
    const generation = this.#generation;
    this.#actionsAbort?.abort();
    const controller = new AbortController();
    this.#actionsAbort = controller;
    this.#update({ actions: { ...this.#state.actions, status: "loading" } });
    try {
      const page = await this.#client.listActions(
        { organizationId, ...(cursor === null ? {} : { afterActionId: cursor }) },
        controller.signal,
      );
      if (!this.#stillCurrent(generation) || this.#currentOrganizationId() !== organizationId) {
        return;
      }
      this.#update({
        actions: {
          status: "ready",
          items: page.items,
          nextCursor: page.nextCursor,
          hasPrevious: next,
          // One page REPLACES the previous page; pages never accumulate.
          cursorStack: next
            ? appendActionCursor(this.#state.actions.cursorStack, cursor ?? "")
            : [],
        },
      });
    } catch {
      if (!this.#stillCurrent(generation) || this.#currentOrganizationId() !== organizationId) {
        return;
      }
      this.#update({ actions: { ...this.#state.actions, status: "error" } });
    }
  }

  // ── Approval queue ────────────────────────────────────────────────────────

  async loadApprovals(): Promise<void> {
    await this.#loadApprovalPage(false);
  }

  async loadNextApprovals(): Promise<void> {
    await this.#loadApprovalPage(true);
  }

  async loadPreviousApprovals(): Promise<void> {
    if (this.#disposed || !this.#accessAllowed()) return;
    const stack = this.#state.approvals.cursorStack;
    if (stack.length === 0) return;
    const cursor = stack[stack.length - 1] ?? null;
    const nextStack = stack.slice(0, -1);
    const organizationId = this.#currentOrganizationId();
    if (organizationId === null) return;
    const generation = this.#generation;
    this.#approvalsAbort?.abort();
    const controller = new AbortController();
    this.#approvalsAbort = controller;
    this.#update({ approvals: { ...this.#state.approvals, status: "loading" } });
    try {
      const page = await this.#client.listApprovals(
        { organizationId, ...(cursor === null ? {} : { afterApprovalId: cursor }) },
        controller.signal,
      );
      if (!this.#stillCurrent(generation) || this.#currentOrganizationId() !== organizationId) {
        return;
      }
      this.#update({
        approvals: {
          status: "ready",
          items: page.items,
          nextCursor: page.nextCursor,
          hasPrevious: nextStack.length > 0,
          cursorStack: nextStack,
        },
      });
    } catch {
      if (!this.#stillCurrent(generation) || this.#currentOrganizationId() !== organizationId) {
        return;
      }
      this.#update({ approvals: { ...this.#state.approvals, status: "error" } });
    }
  }

  async #loadApprovalPage(next: boolean): Promise<void> {
    if (this.#disposed || !this.#accessAllowed()) return;
    const organizationId = this.#currentOrganizationId();
    if (organizationId === null) return;
    const cursor = next ? this.#state.approvals.nextCursor : null;
    if (next && cursor === null) return;
    const generation = this.#generation;
    this.#approvalsAbort?.abort();
    const controller = new AbortController();
    this.#approvalsAbort = controller;
    this.#update({ approvals: { ...this.#state.approvals, status: "loading" } });
    try {
      const page = await this.#client.listApprovals(
        { organizationId, ...(cursor === null ? {} : { afterApprovalId: cursor }) },
        controller.signal,
      );
      if (!this.#stillCurrent(generation) || this.#currentOrganizationId() !== organizationId) {
        return;
      }
      this.#update({
        approvals: {
          status: "ready",
          items: page.items,
          nextCursor: page.nextCursor,
          hasPrevious: next,
          cursorStack: next
            ? appendActionCursor(this.#state.approvals.cursorStack, cursor ?? "")
            : [],
        },
      });
    } catch {
      if (!this.#stillCurrent(generation) || this.#currentOrganizationId() !== organizationId) {
        return;
      }
      this.#update({ approvals: { ...this.#state.approvals, status: "error" } });
    }
  }

  // ── Detail views ──────────────────────────────────────────────────────────

  async loadActionDetail(actionId: string): Promise<void> {
    if (this.#disposed || !this.#accessAllowed()) return;
    const organizationId = this.#currentOrganizationId();
    if (organizationId === null) return;
    const generation = this.#generation;
    this.#detailAbort?.abort();
    const controller = new AbortController();
    this.#detailAbort = controller;
    this.#update({ detail: { status: "loading", item: null } });
    try {
      const detail = await this.#client.readAction(
        { organizationId, actionId },
        controller.signal,
      );
      if (!this.#stillCurrent(generation) || this.#currentOrganizationId() !== organizationId) {
        return;
      }
      if (detail.item === null) {
        this.#update({ detail: { status: "not-found", item: null } });
        return;
      }
      const parsed = CommerceActionMetadataSchema.safeParse(detail.item);
      if (!parsed.success) {
        this.#update({ detail: { status: "error", item: null } });
        return;
      }
      this.#update({ detail: { status: "ready", item: parsed.data } });
    } catch {
      if (!this.#stillCurrent(generation) || this.#currentOrganizationId() !== organizationId) {
        return;
      }
      this.#update({ detail: { status: "error", item: null } });
    }
  }

  async loadApprovalDetail(approvalId: string): Promise<void> {
    if (this.#disposed || !this.#accessAllowed()) return;
    const organizationId = this.#currentOrganizationId();
    if (organizationId === null) return;
    const generation = this.#generation;
    this.#approvalDetailAbort?.abort();
    const controller = new AbortController();
    this.#approvalDetailAbort = controller;
    this.#update({ approvalDetail: { status: "loading", item: null } });
    try {
      const detail = await this.#client.readApproval(
        { organizationId, approvalId },
        controller.signal,
      );
      if (!this.#stillCurrent(generation) || this.#currentOrganizationId() !== organizationId) {
        return;
      }
      if (detail.item === null) {
        this.#update({ approvalDetail: { status: "not-found", item: null } });
        return;
      }
      const parsed = CommerceApprovalMetadataSchema.safeParse(detail.item);
      if (!parsed.success) {
        this.#update({ approvalDetail: { status: "error", item: null } });
        return;
      }
      this.#update({ approvalDetail: { status: "ready", item: parsed.data } });
    } catch {
      if (!this.#stillCurrent(generation) || this.#currentOrganizationId() !== organizationId) {
        return;
      }
      this.#update({ approvalDetail: { status: "error", item: null } });
    }
  }

  // ── Exposure ──────────────────────────────────────────────────────────────

  /** Records an explicit subject/policy selection without any request. */
  selectExposureSubject(subjectAgentId: string | null, policyId: string | null): void {
    if (this.#disposed) return;
    this.#exposureAbort?.abort();
    this.#exposureAbort = null;
    this.#update({
      exposure: { status: "none", subjectAgentId, policyId, item: null },
    });
  }

  async loadExposure(subjectAgentId: string, policyId: string): Promise<void> {
    if (this.#disposed || !this.#accessAllowed()) return;
    const organizationId = this.#currentOrganizationId();
    if (organizationId === null) return;
    if (
      !CommerceAgentIdSchema.safeParse(subjectAgentId).success ||
      !CommercePolicyIdSchema.safeParse(policyId).success
    ) {
      this.#update({
        exposure: { status: "error", subjectAgentId, policyId, item: null },
      });
      return;
    }
    const generation = this.#generation;
    this.#exposureAbort?.abort();
    const controller = new AbortController();
    this.#exposureAbort = controller;
    this.#update({ exposure: { status: "loading", subjectAgentId, policyId, item: null } });
    try {
      const data = await this.#client.readExposure(
        { organizationId, subjectAgentId, policyId },
        controller.signal,
      );
      if (!this.#stillCurrent(generation) || this.#currentOrganizationId() !== organizationId) {
        return;
      }
      if (data.item === null) {
        this.#update({
          exposure: { status: "not-found", subjectAgentId, policyId, item: null },
        });
        return;
      }
      const parsed = CommerceExposureViewSchema.safeParse(data.item);
      if (!parsed.success) {
        this.#update({
          exposure: { status: "error", subjectAgentId, policyId, item: null },
        });
        return;
      }
      this.#update({
        exposure: { status: "ready", subjectAgentId, policyId, item: parsed.data },
      });
    } catch {
      if (!this.#stillCurrent(generation) || this.#currentOrganizationId() !== organizationId) {
        return;
      }
      this.#update({
        exposure: { status: "error", subjectAgentId, policyId, item: null },
      });
    }
  }

  // ── Decisions ─────────────────────────────────────────────────────────────

  /**
   * Begins an explicit decision confirmation. No request, no mutation id and no
   * idempotency key is created here: the user must confirm first.
   */
  beginDecision(decision: ActionDecisionKind, actionId: string): boolean {
    if (this.#disposed) return false;
    if (this.#state.capability !== "enabled") {
      this.#update({ decision: { kind: "rejected", notice: { kind: "capability-disabled" } } });
      return false;
    }
    if (!this.#canDecide()) {
      this.#update({ decision: { kind: "rejected", notice: { kind: "no-access" } } });
      return false;
    }
    if (!CommerceActionIdSchema.safeParse(actionId).success) {
      this.#update({ decision: { kind: "rejected", notice: { kind: "validation" } } });
      return false;
    }
    this.#generation += 1;
    this.#update({ decision: { kind: "confirming", draft: { decision, actionId } } });
    return true;
  }

  cancelDecision(): void {
    if (this.#disposed) return;
    if (this.#state.decision.kind === "pending") return;
    this.#generation += 1;
    this.#update({ decision: { kind: "idle" } });
  }

  /**
   * Sends exactly ONE confirmed logical decision with a frozen id/key/body.
   * There is no automatic retry and no new key on failure.
   */
  async confirmDecision(): Promise<void> {
    if (this.#disposed) return;
    if (this.#state.decision.kind !== "confirming") return;
    const draft = this.#state.decision.draft;
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
    const generation = this.#generation;
    const frozen: FrozenDecision = { draft, mutationId, idempotencyKey, organizationId };
    this.#update({ decision: { kind: "pending", draft, mutationId } });
    this.#reads.abortPendingReads();
    const accountBound: AccountBoundToken = this.#account.captureAccountBound();
    try {
      const result = await this.#account.mutate(
        async ({ csrfToken, signal }) =>
          this.#runDecision(frozen, csrfToken, signal),
        { accountBound },
      );
      if (!this.#stillCurrent(generation)) return;
      await this.#afterCommit(draft.decision, result, generation);
    } catch (error) {
      if (!this.#stillCurrent(generation)) return;
      this.#handleFailure(error, frozen);
    }
  }

  async #runDecision(
    frozen: FrozenDecision,
    csrfToken: string,
    signal: AbortSignal,
  ): Promise<{
    receipt: CommerceActionMutationReceipt;
    metadata: CommerceActionMetadata;
    replayed: boolean;
  }> {
    const request = {
      organizationId: frozen.organizationId,
      actionId: frozen.draft.actionId,
      csrfToken,
      idempotencyKey: frozen.idempotencyKey,
      signal,
      body: { mutationId: frozen.mutationId },
    };
    const result =
      frozen.draft.decision === "approve"
        ? await this.#client.approve(request)
        : frozen.draft.decision === "reject"
          ? await this.#client.reject(request)
          : await this.#client.cancel(request);
    const parsed = CommerceActionMetadataSchema.safeParse(result.metadata);
    if (!parsed.success) throw new ActionApiError({ kind: "invalid-response" });
    return { receipt: result.receipt, metadata: parsed.data, replayed: result.replayed };
  }

  async #afterCommit(
    decision: ActionDecisionKind,
    result: {
      receipt: CommerceActionMutationReceipt;
      metadata: CommerceActionMetadata;
      replayed: boolean;
    },
    generation: number,
  ): Promise<void> {
    // The committed receipt is recorded FIRST and stands even if the follow-up
    // refresh fails. A failed read never demotes a committed decision.
    this.#update({
      decision: {
        kind: "committed",
        committed: {
          decision,
          receipt: result.receipt,
          metadata: result.metadata,
          replayed: result.replayed,
          refreshError: false,
        },
      },
    });
    await this.loadActionDetail(result.receipt.resourceId);
    if (!this.#stillCurrent(generation)) return;
    if (this.#state.decision.kind !== "committed") return;
    if (this.#state.detail.status === "error") {
      this.#update({
        decision: {
          kind: "committed",
          committed: { ...this.#state.decision.committed, refreshError: true },
        },
      });
    }
  }

  #handleFailure(error: unknown, frozen: FrozenDecision): void {
    const failure = failureOf(error);
    switch (failure.kind) {
      case "unauthenticated":
        this.#update({ decision: { kind: "rejected", notice: { kind: "unauthenticated" } } });
        return;
      case "csrf":
        this.#update({ decision: { kind: "rejected", notice: { kind: "csrf" } } });
        return;
      case "forbidden":
        // The server is authoritative. A denial disables the local decision
        // controls instead of letting the local role guess stand.
        this.#update({
          serverDeniedDecision: true,
          decision: { kind: "rejected", notice: { kind: "forbidden" } },
        });
        return;
      case "validation":
        this.#update({ decision: { kind: "rejected", notice: { kind: "validation" } } });
        return;
      case "policy":
        this.#update({ decision: { kind: "rejected", notice: { kind: "policy" } } });
        return;
      case "conflict":
        this.#update({ decision: { kind: "rejected", notice: { kind: "conflict" } } });
        return;
      case "not-found":
        this.#update({ decision: { kind: "rejected", notice: { kind: "not-found" } } });
        return;
      case "account-changed":
        this.#update({ decision: { kind: "rejected", notice: { kind: "account-changed" } } });
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
      default: {
        // Sent-but-unconfirmed: keep the frozen id and offer ONLY an explicit
        // status GET with the original id. Never resend, never mint a new key
        // and never present the outcome as success, failure or release.
        this.#update({
          decision: {
            kind: "outcome-unknown",
            mutationId: frozen.mutationId,
            organizationId: frozen.organizationId,
            operation: ACTION_DECISION_OPERATIONS[frozen.draft.decision],
            decision: frozen.draft.decision,
            actionId: frozen.draft.actionId,
            checking: false,
            statusMessage: null,
          },
        });
        return;
      }
    }
  }

  /**
   * Explicit, user-initiated safe status GET using the ORIGINAL mutation id.
   * It NEVER resubmits the decision, never mints a new id or key, and a
   * `not_found` result stays unknown rather than becoming a failure.
   */
  async checkDecisionStatus(): Promise<void> {
    if (this.#disposed || this.#state.decision.kind !== "outcome-unknown") return;
    const current = this.#state.decision;
    const generation = this.#generation;
    this.#statusAbort?.abort();
    const controller = new AbortController();
    this.#statusAbort = controller;
    this.#update({ decision: { ...current, checking: true, statusMessage: null } });
    let status;
    try {
      status = await this.#client.readMutationStatus({
        organizationId: current.organizationId,
        mutationId: current.mutationId,
        operation: current.operation,
        expectedResourceId: current.actionId,
        signal: controller.signal,
      });
    } catch {
      if (!this.#stillCurrent(generation) || this.#state.decision.kind !== "outcome-unknown") {
        return;
      }
      this.#update({
        decision: { ...current, checking: false, statusMessage: UNKNOWN_STATUS_MESSAGE },
      });
      return;
    }
    if (!this.#stillCurrent(generation) || this.#state.decision.kind !== "outcome-unknown") return;
    if (status.status === "committed") {
      this.#update({
        decision: {
          kind: "committed",
          committed: {
            decision: current.decision,
            receipt: status.receipt,
            metadata: null,
            replayed: true,
            refreshError: false,
          },
        },
      });
      await this.loadActionDetail(status.receipt.resourceId);
      return;
    }
    // `not_found` is NOT a failure and NOT a release: the decision may still
    // commit. It never enables a resend and never mints a new id or key.
    this.#update({
      decision: { ...current, checking: false, statusMessage: UNKNOWN_STATUS_MESSAGE },
    });
  }

  /**
   * Synchronously clears every queue, detail, exposure and decision artifact.
   * Used for account/organization/role/route/privacy-generation changes,
   * hidden/pagehide and logout. It never preserves a key that could be
   * resubmitted.
   */
  clear(): void {
    if (this.#disposed) return;
    this.#generation += 1;
    this.#abortAll();
    this.#update({
      role: this.#currentRole(),
      canRead: this.#accessAllowed(),
      canDecide: this.#canDecide(),
      serverDeniedDecision: false,
      actions: initialActionQueueState(),
      approvals: initialApprovalQueueState(),
      detail: initialActionDetailState(),
      approvalDetail: initialApprovalDetailState(),
      exposure: initialExposureState(),
      decision: { kind: "idle" },
    });
  }

  /** Role reconciliation: a role change clears every local artifact. */
  reconcileRole(role: string | null): void {
    if (this.#disposed) return;
    if (this.#state.role === role && this.#state.canRead === this.#accessAllowed()) {
      this.#update({ canDecide: this.#canDecide() });
      return;
    }
    this.clear();
  }

  dispose(): void {
    if (this.#disposed) return;
    this.#generation += 1;
    this.#abortAll();
    this.#disposed = true;
    this.#state = { ...initialActionControllerState(), role: this.#currentRole() };
    this.#onState?.(this.#state);
  }

  #abortAll(): void {
    this.#actionsAbort?.abort();
    this.#actionsAbort = null;
    this.#approvalsAbort?.abort();
    this.#approvalsAbort = null;
    this.#detailAbort?.abort();
    this.#detailAbort = null;
    this.#approvalDetailAbort?.abort();
    this.#approvalDetailAbort = null;
    this.#exposureAbort?.abort();
    this.#exposureAbort = null;
    this.#statusAbort?.abort();
    this.#statusAbort = null;
    this.#capabilityAbort?.abort();
    this.#capabilityAbort = null;
  }

  // Reads require the independent capability gate AND the local role/account
  // matrix. The server remains the authority for role and tenant.
  #accessAllowed(): boolean {
    if (!this.#capabilityChecked) return false;
    if (this.#account.state.session.signedIn !== true) return false;
    if (this.#account.state.session.method === "recovery") return false;
    return canReadActions(this.#currentRole());
  }

  #canDecide(): boolean {
    if (this.#state.serverDeniedDecision) return false;
    return this.#accessAllowed() && canDecideActions(this.#currentRole());
  }

  #currentRole(): string | null {
    return this.#reads.currentRole();
  }

  #currentOrganizationId(): string | null {
    return this.#reads.currentOrganizationId();
  }

  #stillCurrent(generation: number): boolean {
    return !this.#disposed && generation === this.#generation;
  }

  #update(patch: Partial<ActionControllerState>): void {
    if (this.#disposed) return;
    this.#state = { ...this.#state, ...patch };
    this.#state = {
      ...this.#state,
      role: this.#currentRole(),
      canRead: this.#accessAllowed(),
      canDecide: this.#canDecide(),
    };
    this.#onState?.(this.#state);
  }
}

export const UNKNOWN_STATUS_MESSAGE =
  "No committed result found yet. The decision may still complete. Nothing was resent; check again when you choose to.";

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

/**
 * Synchronous render-boundary guard for the action surface. React effects run
 * AFTER render, so an account/organization/role transition would otherwise
 * paint one frame of the previous context's queue, detail, exposure or
 * decision. The parent suppresses (by substituting the initial state) when it
 * does not match the current context.
 */
export interface ActionRenderContext {
  readonly accountId: string | null;
  readonly organizationId: string | null;
  readonly role: string | null;
}

export function suppressStaleActionContext(
  bound: ActionRenderContext | null,
  current: ActionRenderContext,
): boolean {
  if (bound === null) return false;
  if (current.accountId === null || current.organizationId === null) return true;
  return (
    bound.accountId !== current.accountId ||
    bound.organizationId !== current.organizationId ||
    bound.role !== current.role
  );
}

export function renderActionState(
  suppress: boolean,
  state: ActionControllerState,
  initial: () => ActionControllerState = initialActionControllerState,
): ActionControllerState {
  return suppress ? initial() : state;
}

/**
 * The single sentence describing what a decision state currently means. An
 * unknown outcome is always described as unknown; it is never presented as
 * success, failure, refund, release, payment or settlement.
 */
export function decisionOutcomeLabel(decision: ActionDecisionState): string {
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
      return "The outcome is unknown. It is not a success, not a failure, not a refund and not a release.";
  }
}

export const ACTION_PAGE_LIMIT_EXPORT = ACTION_PAGE_LIMIT;

export type { CommerceActionMetadata, CommerceApprovalMetadata, CommerceExposureView };
