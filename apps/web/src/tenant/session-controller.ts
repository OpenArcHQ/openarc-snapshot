import {
  CommerceControlSessionIssueResultSchema,
  CommerceControlSessionMetadataSchema,
  CommerceControlSessionRevokeResultSchema,
  CommerceControlSessionStatusItemSchema,
  CommerceControlSessionDurationSecondsSchema,
  CommerceAgentIdSchema,
  CommercePolicyIdSchema,
  CommerceTenantIdempotencyKeySchema,
  CommerceTenantMutationIdSchema,
  compareIsoTimestamps,
  type CommerceControlSessionIssueResult,
  type CommerceControlSessionList,
  type CommerceControlSessionMetadata,
  type CommerceControlSessionReceipt,
  type CommerceControlSessionRevokeResult,
  type CommerceControlSessionStatus,
  type CommerceControlSessionStatusItem,
  type SessionCapabilityState,
} from "@openarc/shared";

import type { AccountBoundToken, AccountFlowController } from "../account/flow-controller.js";
import {
  SESSION_PAGE_LIMIT,
  SessionApiError,
  SessionClient,
  createSessionIdempotencyKey,
  createSessionMutationId,
  readCommerceSessionsCapability,
  type SessionApiFailure,
  type SessionMutationOperation,
} from "./session-client.js";
import type { SessionRoute } from "./session-routes.js";

/**
 * Bounded commerce-session console controller.
 *
 * The controller owns at most one explicit human logical write at a time. A
 * logical mutation id, idempotency key, selected agent, policy id, duration and
 * body are frozen for the lifetime of a request: there is no automatic retry,
 * polling, new key or "latest state" preflight. A sent-but-unconfirmed outcome
 * is reported as `outcome-unknown` and can only be resolved by an explicit
 * status GET with the ORIGINAL mutation id.
 *
 * Secret lifecycle is critical. A fresh issue may expose the raw `oach_v1_`
 * handoff token exactly once, in `availableOnce`; it is held only in this
 * controller's memory, is never written to local/session storage, the URL,
 * history, a log or analytics, and is never put on the clipboard without an
 * explicit user click. `dismissSecret`, any account/organization/role/route/
 * privacy-generation change, expiry, `clear()` and `dispose()` synchronously
 * drop the secret AND every draft/id/error/mutation artifact. A replay or status
 * GET can never recreate a raw secret: `status committed != secret recovered`.
 * Lost delivery is only recoverable by an explicit revoke + new human issue.
 */

export const SESSION_CURSOR_STACK_LIMIT = 20;

// Exact role matrix. Owner and operator on a current non-recovery account may
// read and write. Viewers get NO access at all (never inferred read-only from
// policy), and provider/unknown/recovery roles get no request or control. The
// server remains the final authority; this is a UI gate only.
export function canReadSessions(role: string | null | undefined): boolean {
  return role === "owner" || role === "operator";
}

export function canWriteSessions(role: string | null | undefined): boolean {
  return role === "owner" || role === "operator";
}

// Appends a cursor to the bounded previous-page stack (max 20).
export function appendSessionCursor(
  stack: readonly string[],
  cursor: string,
): readonly string[] {
  const next = [...stack, cursor];
  return next.length > SESSION_CURSOR_STACK_LIMIT
    ? next.slice(next.length - SESSION_CURSOR_STACK_LIMIT)
    : next;
}

/**
 * Validates and canonicalises a human duration string. The wire form is a
 * canonical whole-second string 1..900; an empty/absent input returns null so
 * the caller passes no `durationSeconds` and the server default (300) applies.
 * A non-canonical input (leading zeros, zero, >900, whitespace, sign,
 * fraction) is refused before any request. Returns null for an invalid value.
 */
export function canonicalDurationSeconds(input: string | null | undefined): string | null {
  if (input === null || input === undefined || input.length === 0) return null;
  const parsed = CommerceControlSessionDurationSecondsSchema.safeParse(input);
  return parsed.success ? parsed.data : null;
}

/** A selected active agent from the current organization read state. */
export interface SessionAgentSelection {
  readonly agentId: string;
  readonly status: "active" | "suspended" | "revoked";
}

export type SessionMutationDraft =
  | {
      readonly op: "issue";
      readonly subjectAgentId: string;
      readonly policyId: string;
      readonly durationSeconds: string | null;
    }
  | { readonly op: "revoke"; readonly sessionId: string };

export type SessionFailureNotice =
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
  | { readonly kind: "inactive-agent" };

export interface SessionOutcomeUnknown {
  readonly kind: "outcome-unknown";
  readonly mutationId: string;
  readonly organizationId: string;
  readonly operation: SessionMutationOperation;
  // Null for an issue (DB-generated session id); the exact session id for revoke.
  readonly expectedResourceId: string | null;
  readonly sessionId: string | null;
  readonly checking: boolean;
  readonly statusMessage: string | null;
}

/**
 * The committed receipt plus the one-time raw delivery. `availableOnce` is the
 * raw `oach_v1_` handoff token, present ONLY on a fresh committed issue; it is
 * never reconstructed from a replay, a status, a page or a refresh, and is
 * cleared by expiry/dismiss/context change.
 */
export interface SessionCommittedState {
  readonly receipt: CommerceControlSessionReceipt;
  readonly metadata: CommerceControlSessionMetadata | null;
  readonly replayed: boolean;
  readonly handoffExpiresAt: string | null;
  readonly refreshError: boolean;
  /**
   * The one-time raw handoff token carried on the committed row itself, or null.
   * It mirrors `state.availableOnce` and BOTH copies are removed together by
   * expiry/dismiss/clear so a raw secret can never be read from the committed row
   * after it has been erased from the top-level state.
   */
  readonly availableOnce: string | null;
}

export type SessionMutationState =
  | { readonly kind: "idle" }
  | { readonly kind: "confirming"; readonly draft: SessionMutationDraft }
  | { readonly kind: "pending"; readonly draft: SessionMutationDraft; readonly mutationId: string }
  | { readonly kind: "committed"; readonly committed: SessionCommittedState }
  | { readonly kind: "rejected"; readonly notice: SessionFailureNotice }
  | SessionOutcomeUnknown;

export type SessionListStatus = "none" | "loading" | "ready" | "error";

export interface SessionListState {
  readonly status: SessionListStatus;
  readonly items: readonly CommerceControlSessionStatusItem[];
  readonly nextCursor: string | null;
  readonly hasPrevious: boolean;
  readonly cursorStack: readonly string[];
}

export interface SessionDetailState {
  readonly status: "none" | "loading" | "ready" | "not-found" | "error";
  readonly item: CommerceControlSessionStatusItem | null;
}

export interface SessionControllerState {
  readonly capability: "unknown" | "checking" | "enabled" | "unavailable";
  readonly role: string | null;
  readonly canRead: boolean;
  readonly canWrite: boolean;
  readonly selection: { readonly route: SessionRoute; readonly selectedAgentId: string | null };
  readonly list: SessionListState;
  readonly detail: SessionDetailState;
  readonly mutation: SessionMutationState;
  /** The one-time raw handoff secret, or null. Never persisted. */
  readonly availableOnce: string | null;
}

export function initialSessionListState(): SessionListState {
  return { status: "none", items: [], nextCursor: null, hasPrevious: false, cursorStack: [] };
}

export function initialSessionDetailState(): SessionDetailState {
  return { status: "none", item: null };
}

export function initialSessionControllerState(): SessionControllerState {
  return {
    capability: "unknown",
    role: null,
    canRead: false,
    canWrite: false,
    selection: { route: { kind: "roots" }, selectedAgentId: null },
    list: initialSessionListState(),
    detail: initialSessionDetailState(),
    mutation: { kind: "idle" },
    availableOnce: null,
  };
}

export interface SessionReadCoordinator {
  currentOrganizationId(): string | null;
  currentRole(): string | null;
  currentAccountId(): string | null;
  abortPendingReads(): void;
  /** The exact selected active agent, or null when none is active/selected. */
  selectedActiveAgent(): SessionAgentSelection | null;
  /** Reloads bounded reads relevant to a committed session. */
  reloadAfterCommit(sessionId: string): Promise<void>;
}

export interface SessionControllerDeps {
  readonly client?: SessionClient;
  readonly account: AccountFlowController;
  readonly reads: SessionReadCoordinator;
  readonly capabilityReader?: (signal: AbortSignal) => Promise<SessionCapabilityState>;
  /** Invoked after a committed fresh issue so the shell can open the new detail. */
  readonly onCommittedSession?: (sessionId: string) => void;
  readonly onState?: (state: SessionControllerState) => void;
}

interface FrozenSubmission {
  readonly draft: SessionMutationDraft;
  readonly mutationId: string;
  readonly idempotencyKey: string;
  readonly organizationId: string;
  readonly expectedResourceId: string | null;
}

export class SessionController {
  #state: SessionControllerState = initialSessionControllerState();
  #disposed = false;
  #generation = 0;
  #listAbort: AbortController | null = null;
  #detailAbort: AbortController | null = null;
  #statusAbort: AbortController | null = null;
  #capabilityAbort: AbortController | null = null;
  #secretTimer: ReturnType<typeof setTimeout> | null = null;
  #capabilityChecked = false;
  readonly #client: SessionClient;
  readonly #account: AccountFlowController;
  readonly #reads: SessionReadCoordinator;
  readonly #capabilityReader: (signal: AbortSignal) => Promise<SessionCapabilityState>;
  readonly #onCommittedSession: ((sessionId: string) => void) | undefined;
  readonly #onState: ((state: SessionControllerState) => void) | undefined;

  constructor(deps: SessionControllerDeps) {
    this.#client = deps.client ?? new SessionClient();
    this.#account = deps.account;
    this.#reads = deps.reads;
    this.#capabilityReader =
      deps.capabilityReader ?? ((signal) => readCommerceSessionsCapability(signal));
    this.#onCommittedSession = deps.onCommittedSession;
    this.#onState = deps.onState;
  }

  get state(): SessionControllerState {
    return this.#state;
  }

  get disposed(): boolean {
    return this.#disposed;
  }

  /** The one-time raw handoff token, or null. Reading never re-reveals it. */
  get availableOnce(): string | null {
    return this.#state.availableOnce;
  }

  // Points the controller at a parsed route without issuing any request.
  setRoute(route: SessionRoute): void {
    if (this.#disposed) return;
    this.#update({
      selection: { route, selectedAgentId: this.#state.selection.selectedAgentId },
      detail: initialSessionDetailState(),
    });
  }

  // Binds the console to ONE explicitly selected active agent. Selecting a
  // different agent clears the displayed secret, receipt, draft, list and
  // detail so a previous context can never survive.
  selectAgent(agentId: string | null): void {
    if (this.#disposed) return;
    if (agentId === this.#state.selection.selectedAgentId) return;
    this.#generation += 1;
    this.#listAbort?.abort();
    this.#listAbort = null;
    this.#detailAbort?.abort();
    this.#detailAbort = null;
    this.#clearSecret();
    this.#update({
      selection: { route: this.#state.selection.route, selectedAgentId: agentId },
      mutation: { kind: "idle" },
      detail: initialSessionDetailState(),
    });
  }

  // Independent capability gate. It runs BEFORE any session request and never
  // depends on tenant-writes, machine, listing, policy, Vault or wallet flags.
  // On a known session route with the flag on but the capability not `enabled`,
  // state is `unavailable` and no session request is ever made.
  async initialize(route: SessionRoute): Promise<void> {
    if (this.#disposed) return;
    if (route.kind === "invalid") {
      this.#update({ selection: { route, selectedAgentId: null }, detail: initialSessionDetailState() });
      return;
    }
    const generation = this.#generation;
    this.#update({
      selection: { route, selectedAgentId: this.#state.selection.selectedAgentId },
      detail: initialSessionDetailState(),
    });
    if (!this.#capabilityChecked) {
      this.#update({ capability: "checking" });
      this.#capabilityAbort?.abort();
      const capabilityController = new AbortController();
      this.#capabilityAbort = capabilityController;
      let state: SessionCapabilityState;
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
      this.#update({ mutation: { kind: "rejected", notice: { kind: "no-access" } } });
      return;
    }
    if (route.kind === "roots") {
      await this.loadList();
    } else if (route.kind === "detail") {
      await this.loadDetail(route.sessionId);
    }
  }

  async loadList(): Promise<void> {
    await this.#loadListPage(false);
  }

  async loadNextList(): Promise<void> {
    await this.#loadListPage(true);
  }

  async loadPreviousList(): Promise<void> {
    if (this.#disposed || !this.#accessAllowed()) return;
    const stack = this.#state.list.cursorStack;
    if (stack.length === 0) return;
    const cursor = stack[stack.length - 1] ?? null;
    const nextStack = stack.slice(0, -1);
    const organizationId = this.#currentOrganizationId();
    if (organizationId === null) return;
    const generation = this.#generation;
    this.#listAbort?.abort();
    const controller = new AbortController();
    this.#listAbort = controller;
    this.#update({ list: { ...this.#state.list, status: "loading" } });
    let page: CommerceControlSessionList;
    try {
      page = await this.#client.listSessions(
        { organizationId, ...(cursor === null ? {} : { afterSessionId: cursor }) },
        controller.signal,
      );
    } catch {
      if (!this.#stillCurrent(generation) || this.#currentOrganizationId() !== organizationId) return;
      this.#update({ list: { ...this.#state.list, status: "error" } });
      return;
    }
    if (!this.#stillCurrent(generation) || this.#currentOrganizationId() !== organizationId) return;
    this.#update({
      list: {
        status: "ready",
        items: page.items,
        nextCursor: page.nextCursor,
        hasPrevious: nextStack.length > 0,
        cursorStack: nextStack,
      },
    });
  }

  async #loadListPage(next: boolean): Promise<void> {
    if (this.#disposed || !this.#accessAllowed()) return;
    const organizationId = this.#currentOrganizationId();
    if (organizationId === null) return;
    const cursor = next ? this.#state.list.nextCursor : null;
    if (next && cursor === null) return;
    const generation = this.#generation;
    this.#listAbort?.abort();
    const controller = new AbortController();
    this.#listAbort = controller;
    this.#update({ list: { ...this.#state.list, status: "loading" } });
    let page: CommerceControlSessionList;
    try {
      page = await this.#client.listSessions(
        { organizationId, ...(cursor === null ? {} : { afterSessionId: cursor }) },
        controller.signal,
      );
    } catch {
      if (!this.#stillCurrent(generation) || this.#currentOrganizationId() !== organizationId) return;
      this.#update({ list: { ...this.#state.list, status: "error" } });
      return;
    }
    if (!this.#stillCurrent(generation) || this.#currentOrganizationId() !== organizationId) return;
    this.#update({
      list: {
        status: "ready",
        items: page.items,
        nextCursor: page.nextCursor,
        hasPrevious: next,
        cursorStack: next ? appendSessionCursor(this.#state.list.cursorStack, cursor ?? "") : [],
      },
    });
  }

  async loadDetail(sessionId: string): Promise<void> {
    if (this.#disposed || !this.#accessAllowed()) return;
    const organizationId = this.#currentOrganizationId();
    if (organizationId === null) return;
    const generation = this.#generation;
    this.#detailAbort?.abort();
    const controller = new AbortController();
    this.#detailAbort = controller;
    this.#update({ detail: { status: "loading", item: null } });
    let status: CommerceControlSessionStatus;
    try {
      status = await this.#client.readSession({ organizationId, sessionId }, controller.signal);
    } catch {
      if (!this.#stillCurrent(generation) || this.#currentOrganizationId() !== organizationId) return;
      this.#update({ detail: { status: "error", item: null } });
      return;
    }
    if (!this.#stillCurrent(generation) || this.#currentOrganizationId() !== organizationId) return;
    if (status.item === null) {
      this.#update({ detail: { status: "not-found", item: null } });
      return;
    }
    const parsed = CommerceControlSessionStatusItemSchema.safeParse(status.item);
    if (!parsed.success) {
      this.#update({ detail: { status: "error", item: null } });
      return;
    }
    this.#update({ detail: { status: "ready", item: parsed.data } });
  }

  /**
   * Begins an explicit issue confirmation. The selected active agent is read
   * from the current organization read state (never a stale org), and the
   * policy id and duration are validated locally. No request and no key is
   * created here.
   */
  beginIssue(input: {
    subjectAgentId: string | null;
    policyId: string;
    durationSeconds: string | null;
  }): boolean {
    if (this.#disposed) return false;
    if (this.#state.capability !== "enabled") {
      this.#update({ mutation: { kind: "rejected", notice: { kind: "capability-disabled" } } });
      return false;
    }
    if (!this.#canWrite()) {
      this.#update({ mutation: { kind: "rejected", notice: { kind: "no-access" } } });
      return false;
    }
    const selected = this.#reads.selectedActiveAgent();
    const subjectAgentId = input.subjectAgentId ?? selected?.agentId ?? null;
    if (subjectAgentId === null || !CommerceAgentIdSchema.safeParse(subjectAgentId).success) {
      this.#update({ mutation: { kind: "rejected", notice: { kind: "inactive-agent" } } });
      return false;
    }
    // The agent must be the CURRENT selected active agent, exactly. Never borrow
    // a stale/foreign agent id.
    if (selected === null || selected.agentId !== subjectAgentId) {
      this.#update({ mutation: { kind: "rejected", notice: { kind: "inactive-agent" } } });
      return false;
    }
    if (!CommercePolicyIdSchema.safeParse(input.policyId).success) {
      this.#update({ mutation: { kind: "rejected", notice: { kind: "validation" } } });
      return false;
    }
    let duration: string | null = null;
    if (input.durationSeconds !== null && input.durationSeconds.length > 0) {
      duration = canonicalDurationSeconds(input.durationSeconds);
      if (duration === null) {
        this.#update({ mutation: { kind: "rejected", notice: { kind: "validation" } } });
        return false;
      }
    }
    this.#generation += 1;
    this.#clearSecret();
    this.#update({
      mutation: {
        kind: "confirming",
        draft: { op: "issue", subjectAgentId, policyId: input.policyId, durationSeconds: duration },
      },
    });
    return true;
  }

  beginRevoke(sessionId: string): boolean {
    if (this.#disposed) return false;
    if (this.#state.capability !== "enabled") {
      this.#update({ mutation: { kind: "rejected", notice: { kind: "capability-disabled" } } });
      return false;
    }
    if (!this.#canWrite()) {
      this.#update({ mutation: { kind: "rejected", notice: { kind: "no-access" } } });
      return false;
    }
    if (!CommerceTenantMutationIdSchema.safeParse(sessionId).success) {
      this.#update({ mutation: { kind: "rejected", notice: { kind: "validation" } } });
      return false;
    }
    this.#generation += 1;
    this.#clearSecret();
    this.#update({ mutation: { kind: "confirming", draft: { op: "revoke", sessionId } } });
    return true;
  }

  cancel(): void {
    if (this.#disposed) return;
    if (this.#state.mutation.kind === "pending") return;
    this.#generation += 1;
    this.#clearSecret();
    this.#update({ mutation: { kind: "idle" } });
  }

  // Sends exactly one confirmed logical write with a frozen id/key/body. There
  // is no automatic retry and no new key on failure.
  async confirm(): Promise<void> {
    if (this.#disposed) return;
    if (this.#state.mutation.kind !== "confirming") return;
    const draft = this.#state.mutation.draft;
    const organizationId = this.#currentOrganizationId();
    if (organizationId === null) return;
    const mutationId = createSessionMutationId();
    const idempotencyKey = createSessionIdempotencyKey();
    if (
      !CommerceTenantMutationIdSchema.safeParse(mutationId).success ||
      !CommerceTenantIdempotencyKeySchema.safeParse(idempotencyKey).success
    ) {
      this.#update({ mutation: { kind: "rejected", notice: { kind: "validation" } } });
      return;
    }
    const generation = this.#generation;
    const frozen: FrozenSubmission = {
      draft,
      mutationId,
      idempotencyKey,
      organizationId,
      expectedResourceId: draft.op === "revoke" ? draft.sessionId : null,
    };
    this.#update({ mutation: { kind: "pending", draft, mutationId } });
    this.#reads.abortPendingReads();
    const accountBound: AccountBoundToken = this.#account.captureAccountBound();
    try {
      const result = await this.#account.mutate(
        async ({ csrfToken, signal }) =>
          this.#runAction(draft, organizationId, mutationId, idempotencyKey, csrfToken, signal),
        { accountBound },
      );
      if (!this.#stillCurrent(generation)) return;
      await this.#afterCommit(result, generation);
    } catch (error) {
      if (!this.#stillCurrent(generation)) return;
      this.#handleFailure(error, frozen);
    }
  }

  async #runAction(
    draft: SessionMutationDraft,
    organizationId: string,
    mutationId: string,
    idempotencyKey: string,
    csrfToken: string,
    signal: AbortSignal,
  ): Promise<{
    kind: "issue" | "revoke";
    receipt: CommerceControlSessionReceipt;
    metadata: CommerceControlSessionMetadata;
    replayed: boolean;
    availableOnce: string | null;
    handoffExpiresAt: string | null;
  }> {
    if (draft.op === "issue") {
      const body = {
        mutationId,
        subjectAgentId: draft.subjectAgentId,
        policyId: draft.policyId,
        ...(draft.durationSeconds === null ? {} : { durationSeconds: draft.durationSeconds }),
      };
      const result: CommerceControlSessionIssueResult = await this.#client.issue({
        organizationId,
        csrfToken,
        idempotencyKey,
        signal,
        body,
      });
      if (!CommerceControlSessionIssueResultSchema.safeParse(result).success) {
        throw new SessionApiError({ kind: "invalid-response" });
      }
      return {
        kind: "issue",
        receipt: result.receipt,
        metadata: result.metadata,
        replayed: result.replayed,
        availableOnce: result.replayed ? null : result.delivery.handoffToken,
        handoffExpiresAt: result.replayed ? null : result.delivery.handoffExpiresAt,
      };
    }
    const result: CommerceControlSessionRevokeResult = await this.#client.revoke({
      organizationId,
      sessionId: draft.sessionId,
      csrfToken,
      idempotencyKey,
      signal,
      body: { mutationId },
    });
    if (!CommerceControlSessionRevokeResultSchema.safeParse(result).success) {
      throw new SessionApiError({ kind: "invalid-response" });
    }
    return {
      kind: "revoke",
      receipt: result.receipt,
      metadata: result.metadata,
      replayed: result.replayed,
      availableOnce: null,
      handoffExpiresAt: null,
    };
  }

  async #afterCommit(
    result: {
      kind: "issue" | "revoke";
      receipt: CommerceControlSessionReceipt;
      metadata: CommerceControlSessionMetadata;
      replayed: boolean;
      availableOnce: string | null;
      handoffExpiresAt: string | null;
    },
    generation: number,
  ): Promise<void> {
    let refreshError = false;
    try {
      await this.#reads.reloadAfterCommit(result.receipt.resourceId);
    } catch {
      refreshError = true;
    }
    if (!this.#stillCurrent(generation)) return;
    if (result.kind === "issue") {
      // Bounded post-issue status reconciliation. It NEVER navigates away from
      // the one-time delivery screen and NEVER clears the freshly issued secret;
      // its only effect is to record a truthful follow-up refresh failure on the
      // committed receipt so a failed read can never demote a commit or hide the
      // one-time handoff.
      await this.loadDetail(result.receipt.resourceId);
      if (!this.#stillCurrent(generation)) return;
      if (this.#state.detail.status === "error") refreshError = true;
    }
    // The committed receipt is stored EVEN IF the follow-up refresh failed.
    // A committed status is never mislabeled as a lost write.
    this.#update({
      mutation: {
        kind: "committed",
        committed: {
          receipt: result.receipt,
          metadata: result.metadata,
          replayed: result.replayed,
          handoffExpiresAt: result.handoffExpiresAt,
          refreshError,
          // Fresh issue carries the one-time raw token on the committed row;
          // a replay/revoke is always null so a secret cannot be reconstructed.
          availableOnce:
            result.kind === "issue" && result.replayed === false ? result.availableOnce : null,
        },
      },
      // The raw secret lives in exactly TWO synchronized copies: the committed
      // row and `state.availableOnce`. Both are set only for a fresh issue and
      // never for a replay/status/refresh, and both are erased together by
      // expiry/dismiss/clear.
      availableOnce: result.kind === "issue" && result.replayed === false ? result.availableOnce : null,
    });
    if (result.kind === "issue" && result.replayed === false && result.availableOnce !== null) {
      // Bound the raw handoff to the exact server-issued expiry with a single
      // cancellable timer. The browser clock never extends or claims authority:
      // it only erases the local copy, and the server remains authoritative.
      this.#armSecretExpiry(result.metadata, result.handoffExpiresAt, generation);
    }
    if (refreshError) return;
    if (result.kind === "issue") {
      // The freshly committed one-time handoff MUST stay on the issue panel
      // (exactly one reveal). We do NOT auto-open the detail page, so the raw
      // secret is not lost to a context transition. The user can open the
      // session explicitly after dismissing.
      this.#onCommittedSession?.(result.receipt.resourceId);
    } else {
      await this.loadDetail(result.receipt.resourceId);
      await this.loadList();
    }
  }

  #handleFailure(error: unknown, frozen: FrozenSubmission): void {
    const failure = failureOf(error);
    switch (failure.kind) {
      case "unauthenticated":
        this.#update({ mutation: { kind: "rejected", notice: { kind: "unauthenticated" } } });
        return;
      case "csrf":
        this.#update({ mutation: { kind: "rejected", notice: { kind: "csrf" } } });
        return;
      case "forbidden":
        this.#update({ mutation: { kind: "rejected", notice: { kind: "forbidden" } } });
        return;
      case "validation":
        this.#update({ mutation: { kind: "rejected", notice: { kind: "validation" } } });
        return;
      case "policy":
        this.#update({ mutation: { kind: "rejected", notice: { kind: "policy" } } });
        return;
      case "conflict":
        this.#update({ mutation: { kind: "rejected", notice: { kind: "conflict" } } });
        return;
      case "not-found":
        this.#update({ mutation: { kind: "rejected", notice: { kind: "not-found" } } });
        return;
      case "account-changed":
        this.#update({ mutation: { kind: "rejected", notice: { kind: "account-changed" } } });
        return;
      case "feature-disabled":
        this.#update({ mutation: { kind: "rejected", notice: { kind: "capability-disabled" } } });
        return;
      case "aborted":
        this.#update({ mutation: { kind: "idle" } });
        return;
      case "pre-send":
        this.#update({ mutation: { kind: "rejected", notice: { kind: "validation" } } });
        return;
      default: {
        // Sent-but-unconfirmed: keep the frozen id and offer only an explicit
        // status GET with the original id. Never resend, never mint a new key.
        this.#update({
          mutation: {
            kind: "outcome-unknown",
            mutationId: frozen.mutationId,
            organizationId: frozen.organizationId,
            operation: operationOfDraft(frozen.draft),
            expectedResourceId: frozen.expectedResourceId,
            sessionId: frozen.draft.op === "revoke" ? frozen.draft.sessionId : null,
            checking: false,
            statusMessage: null,
          },
        });
        return;
      }
    }
  }

  // Explicit safe status GET using the ORIGINAL mutation id; no resubmission.
  // A `not_found` result NEVER enables a resend and never recovers a secret.
  async checkStatus(): Promise<void> {
    if (this.#disposed || this.#state.mutation.kind !== "outcome-unknown") return;
    const current = this.#state.mutation;
    const generation = this.#generation;
    this.#statusAbort?.abort();
    const controller = new AbortController();
    this.#statusAbort = controller;
    this.#update({ mutation: { ...current, checking: true, statusMessage: null } });
    let status;
    try {
      status = await this.#client.readMutationStatus({
        organizationId: current.organizationId,
        mutationId: current.mutationId,
        operation: current.operation,
        expectedResourceId: current.expectedResourceId,
        signal: controller.signal,
      });
    } catch {
      if (!this.#stillCurrent(generation) || this.#state.mutation.kind !== "outcome-unknown") return;
      this.#update({
        mutation: {
          ...current,
          checking: false,
          statusMessage: "No committed result found yet; it may still complete. Check again.",
        },
      });
      return;
    }
    if (!this.#stillCurrent(generation) || this.#state.mutation.kind !== "outcome-unknown") return;
    if (status.status === "committed") {
      // A committed status never recovers the raw handoff token.
      const existing = this.#state.detail.item;
      this.#update({
        mutation: {
          kind: "committed",
          committed: {
            receipt: status.receipt,
            metadata: existing?.metadata ?? null,
            replayed: true,
            handoffExpiresAt: null,
            refreshError: false,
            availableOnce: null,
          },
        },
        availableOnce: null,
      });
      await this.loadDetail(status.receipt.resourceId);
      return;
    }
    // not_found never enables a resend and never mints a new id/key.
    this.#update({
      mutation: {
        ...current,
        checking: false,
        statusMessage: "No committed result found yet; it may still complete. Check again.",
      },
    });
  }

  /** Removes the one-time raw handoff secret so it cannot be re-revealed. */
  dismissSecret(): void {
    if (this.#disposed) return;
    this.#clearSecret();
  }

  /**
   * Synchronously clears the secret AND every draft/id/error/mutation/list/
   * detail artifact. Used for account/organization/role/route/privacy-generation
   * changes, hidden/pagehide, logout and expiry. It never preserves a key that
   * could be resubmitted and never retains a raw secret.
   */
  clear(): void {
    if (this.#disposed) return;
    this.#generation += 1;
    this.#listAbort?.abort();
    this.#listAbort = null;
    this.#detailAbort?.abort();
    this.#detailAbort = null;
    this.#statusAbort?.abort();
    this.#statusAbort = null;
    this.#capabilityAbort?.abort();
    this.#capabilityAbort = null;
    this.#clearSecretTimer();
    this.#clearSecret();
    this.#update({
      role: this.#currentRole(),
      canRead: this.#accessAllowed(),
      canWrite: this.#canWrite(),
      list: initialSessionListState(),
      detail: initialSessionDetailState(),
      selection: { route: this.#state.selection.route, selectedAgentId: null },
      mutation: { kind: "idle" },
    });
  }

  /** Role reconciliation: a role change clears every local artifact. */
  reconcileRole(role: string | null): void {
    if (this.#disposed) return;
    if (this.#state.role === role && this.#state.canRead === this.#accessAllowed()) {
      this.#update({ canWrite: this.#canWrite() });
      return;
    }
    this.clear();
  }

  dispose(): void {
    if (this.#disposed) return;
    this.#generation += 1;
    this.#listAbort?.abort();
    this.#listAbort = null;
    this.#detailAbort?.abort();
    this.#detailAbort = null;
    this.#statusAbort?.abort();
    this.#statusAbort = null;
    this.#capabilityAbort?.abort();
    this.#capabilityAbort = null;
    this.#clearSecretTimer();
    this.#clearSecret();
    this.#disposed = true;
    this.#state = { ...initialSessionControllerState(), role: this.#currentRole() };
    this.#onState?.(this.#state);
  }

  // Reads/writes require the independent capability gate AND the exact local
  // role/account matrix. The server remains the authority for role and tenant.
  #accessAllowed(): boolean {
    if (!this.#capabilityChecked) return false;
    if (this.#account.state.session.signedIn !== true) return false;
    if (this.#account.state.session.method === "recovery") return false;
    return canReadSessions(this.#currentRole());
  }

  #canWrite(): boolean {
    return this.#accessAllowed() && canWriteSessions(this.#currentRole());
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

  #clearSecretTimer(): void {
    if (this.#secretTimer === null) return;
    clearTimeout(this.#secretTimer);
    this.#secretTimer = null;
  }

  #clearSecret(): void {
    this.#clearSecretTimer();
    const committed = this.#state.mutation.kind === "committed" ? this.#state.mutation.committed : null;
    if (this.#state.availableOnce === null && (committed === null || committed.availableOnce === null)) {
      return;
    }
    this.#update({
      availableOnce: null,
      ...(committed === null || committed.availableOnce === null
        ? {}
        : {
            mutation: {
              kind: "committed" as const,
              committed: { ...committed, availableOnce: null },
            },
          }),
    });
  }

  /**
   * Arms ONE cancellable timer that erases the raw one-time handoff, selecting
   * the earliest of `handoffExpiresAt` and the session `expiresAt` with the
   * shared EXACT fractional comparator. The timer delay is a millisecond
   * scheduling estimate only: `setTimeout` cannot express sub-millisecond source
   * precision (the source may carry 6-9 fractional digits), so the callback
   * never treats the estimate as expiry authority. Before erasing it re-checks
   * the selected source ISO instant exactly, the same rule as
   * `sessionMetadataExpired`/`sessionSecretRevealable`; when the timer fires
   * early it re-arms with a positive minimum delay instead of clearing (or
   * spinning at zero delay). It never extends the source expiry and never claims
   * clock authority: the server remains authoritative, and a late timer cannot
   * resurrect a cleared secret because it is generation-bound AND guarded by the
   * live exact expiry check.
   */
  #armSecretExpiry(
    metadata: CommerceControlSessionMetadata,
    handoffExpiresAt: string | null,
    generation: number,
  ): void {
    this.#clearSecretTimer();
    // Select the earliest source instant by EXACT fractional comparison. A raw
    // `Date.parse` minimum would truncate 6-9 fractional digits and could erase
    // before the server-issued instant.
    const sessionExpiry = metadata.expiresAt;
    const effective =
      handoffExpiresAt === null || compareIsoTimestamps(sessionExpiry, handoffExpiresAt) <= 0
        ? sessionExpiry
        : handoffExpiresAt;
    // The delay estimate may truncate; the callback below never does.
    const effectiveMs = Date.parse(effective);
    if (!Number.isFinite(effectiveMs)) return;
    // A non-positive estimate (a source instant already in the past, e.g. clock
    // skew) is clamped to the next timer turn rather than cleared synchronously:
    // the browser clock never claims expiry authority and a same-task caller
    // still observes the server-issued value before the erasure lands. A delay
    // beyond the 32-bit timer ceiling is capped and re-armed, so a far-future
    // source expiry is honoured without an overflow that would fire immediately.
    const MAX_TIMER_DELAY_MS = 2_147_483_647;
    const delay = effectiveMs - Date.now();
    this.#secretTimer = setTimeout(() => {
      this.#secretTimer = null;
      if (!this.#stillCurrent(generation)) return;
      if (this.#state.availableOnce === null) return;
      // Exact ISO comparison against the selected source expiry: only the
      // server-issued instant clears, never the truncated millisecond estimate.
      // A positive minimum re-arm (1ms) avoids a zero-delay busy loop while
      // still never erasing before the exact instant.
      if (compareIsoTimestamps(effective, new Date().toISOString()) > 0) {
        this.#armSecretExpiry(metadata, handoffExpiresAt, generation);
        return;
      }
      this.#clearSecret();
    }, delay > 0 ? Math.min(delay, MAX_TIMER_DELAY_MS) : 1);
  }

  #update(patch: Partial<SessionControllerState>): void {
    if (this.#disposed) return;
    this.#state = { ...this.#state, ...patch };
    this.#state = {
      ...this.#state,
      role: this.#currentRole(),
      canRead: this.#accessAllowed(),
      canWrite: this.#canWrite(),
    };
    this.#onState?.(this.#state);
  }
}

function operationOfDraft(draft: SessionMutationDraft): SessionMutationOperation {
  return draft.op === "issue"
    ? "control.commerce_session.issue"
    : "control.commerce_session.revoke";
}

function failureOf(error: unknown): { kind: SessionApiFailure["kind"] | "account-changed" } {
  if (error instanceof SessionApiError) return { kind: error.failure.kind };
  if (typeof error === "object" && error !== null) {
    const failure = (error as { failure?: { kind?: unknown } }).failure;
    if (typeof failure === "object" && failure !== null) {
      const kind = (failure as { kind?: unknown }).kind;
      if (kind === "account-changed") return { kind: "account-changed" };
      if (typeof kind === "string") return { kind: kind as SessionApiFailure["kind"] };
    }
  }
  return { kind: "outcome-unknown" };
}

/**
 * Synchronous render-boundary guard for the session surface. React effects run
 * AFTER render, so an account/organization/role transition would otherwise paint
 * one frame of the previous context's draft, receipt, list or one-time secret.
 * The parent suppresses (by substituting the initial state) when it does not
 * match the current context.
 */
export interface SessionRenderContext {
  readonly accountId: string | null;
  readonly organizationId: string | null;
  readonly role: string | null;
}

export function suppressStaleSessionContext(
  bound: SessionRenderContext | null,
  current: SessionRenderContext,
): boolean {
  if (bound === null) return false;
  if (current.accountId === null || current.organizationId === null) return true;
  return (
    bound.accountId !== current.accountId ||
    bound.organizationId !== current.organizationId ||
    bound.role !== current.role
  );
}

export function renderSessionState(
  suppress: boolean,
  state: SessionControllerState,
  initial: () => SessionControllerState = initialSessionControllerState,
): SessionControllerState {
  return suppress ? initial() : state;
}

/**
 * True when a session metadata timestamp has already expired, using the shared
 * exact fractional ISO comparison (never a truncated `Date.parse`). Used only
 * to clear a displayed one-time secret at expiry; the server remains
 * authoritative.
 */
export function sessionMetadataExpired(
  metadata: CommerceControlSessionMetadata,
  nowMs: number = Date.now(),
): boolean {
  const parsed = CommerceControlSessionMetadataSchema.safeParse(metadata);
  if (!parsed.success) return true;
  const nowIso = new Date(nowMs).toISOString();
  // Exact comparison against the source ISO leaf; Date.parse of the whole
  // timestamp never truncates the compared value here (the comparison uses the
  // shared exact fractional comparator once both are valid ISO instants).
  if (!Number.isFinite(nowMs)) return true;
  return compareIsoTimestamps(parsed.data.expiresAt, nowIso) <= 0;
}

/**
 * True when the one-time handoff may still be revealed/copied for the given
 * metadata and handoff expiry. The browser clock never grants authority; this
 * only refuses a copy of an already-expired local copy.
 */
export function sessionSecretRevealable(
  metadata: CommerceControlSessionMetadata | null,
  handoffExpiresAt: string | null,
  nowMs: number = Date.now(),
): boolean {
  if (metadata === null) return false;
  if (sessionMetadataExpired(metadata, nowMs)) return false;
  if (handoffExpiresAt === null) return false;
  const nowIso = new Date(nowMs).toISOString();
  return compareIsoTimestamps(handoffExpiresAt, nowIso) > 0;
}

export const SESSION_PAGE_LIMIT_EXPORT = SESSION_PAGE_LIMIT;

export function sessionStatusOf(item: CommerceControlSessionStatusItem): string {
  return item.status;
}

// Exported only so tests can compare exact ISO instants without Date.parse
// truncation.
export { compareIsoTimestamps };
export type {
  CommerceControlSessionList,
  CommerceControlSessionMetadata,
  CommerceControlSessionReceipt,
};
