import {
  CommercePolicyMutationReceiptSchema,
  CommercePolicyRevisionSchema,
  CommercePolicyRevisionSummarySchema,
  CommercePolicyRootSchema,
  CommercePolicyContentSchema,
  CommerceAgentIdSchema,
  CommerceProviderIdSchema,
  CommerceListingIdSchema,
  CommerceTenantIdempotencyKeySchema,
  CommerceTenantMutationIdSchema,
  type CommerceAgentId,
  type CommercePolicyContent,
  type CommercePolicyMutationReceipt,
  type CommercePolicyMutationResult,
  type CommercePolicyRevision,
  type CommercePolicyRevisionSummary,
  type CommercePolicyRoot,
  type ControlCapabilityState,
} from "@openarc/shared";

import type { AccountBoundToken, AccountFlowController } from "../account/flow-controller.js";
import {
  POLICY_PAGE_LIMIT,
  PolicyApiError,
  PolicyClient,
  createPolicyIdempotencyKey,
  createPolicyMutationId,
  readPolicyManagementCapability,
  type PolicyApiFailure,
  type PolicyMutationOperation,
} from "./policy-client.js";
import type { PolicyRoute } from "./policy-routes.js";

// Bounded policy-management controller.
//
// The controller owns at most one explicit logical write at a time. A logical
// mutation id, idempotency key, target, body and CAS token are frozen for the
// lifetime of a request: there is no automatic retry, polling, new key or
// "latest state" preflight. A sent-but-unconfirmed outcome is reported as
// `outcome-unknown` and can only be resolved by an explicit status GET with the
// ORIGINAL mutation id. Every account/organization/role/generation change and
// every hidden/pagehide/navigation event clears drafts, selections, keys,
// receipts, errors and in-flight state. Nothing sensitive is written to
// storage, the URL, history, a log or analytics.
//
// Critical policy difference from the listing controller: the CAS root is the
// authoritative root `currentRevision` + `updatedAt` (exact 6 microsecond
// timestamps). The latest revision is NEVER derived from a final history page:
// history pagination and CAS are independent.

export const POLICY_HISTORY_PAGE_LIMIT = POLICY_PAGE_LIMIT;
export const POLICY_CURSOR_STACK_LIMIT = 20;

// Exact write-role matrix. Owner and operator may attempt a server-authorized
// policy write; viewer is read-only. Provider roles and any unknown role get no
// controls. Local permission is a UI gate only: the server remains the sole
// authority, and availability is never a grant.
export function canWritePolicies(role: string | null | undefined): boolean {
  return role === "owner" || role === "operator";
}

export function canReadPolicies(role: string | null | undefined): boolean {
  return (
    role === "owner" ||
    role === "operator" ||
    role === "viewer"
  );
}

// Appends a cursor to the bounded previous-page stack (max 20).
export function appendPolicyCursor(
  stack: readonly string[],
  cursor: string,
): readonly string[] {
  const next = [...stack, cursor];
  return next.length > POLICY_CURSOR_STACK_LIMIT
    ? next.slice(next.length - POLICY_CURSOR_STACK_LIMIT)
    : next;
}

// The exact CAS the frozen append/transition bodies must carry: the
// authoritative root revision and its exact `updatedAt` timestamp.
export interface PolicyCas {
  readonly expectedRevision: string;
  readonly expectedUpdatedAt: string;
}

export function policyCasOf(root: CommercePolicyRoot): PolicyCas | null {
  const parsed = CommercePolicyRootSchema.safeParse(root);
  if (!parsed.success) return null;
  return {
    expectedRevision: parsed.data.currentRevision,
    expectedUpdatedAt: parsed.data.updatedAt,
  };
}

// Converts a human USDC decimal to the canonical 6-decimals atomic string
// using strings/BigInt only. Zero IS valid (a zero cap is an explicit
// deny-all), and no float is ever used. Rejects signs, whitespace, exponents,
// fractional over-precision and leading zeros on the integer part.
export function parseUsdcToAtomic(input: string): string | null {
  if (!/^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,6})?$/u.test(input)) return null;
  const [whole = "", fraction = ""] = input.split(".");
  const padded = fraction.padEnd(6, "0");
  try {
    return (BigInt(whole) * 1_000_000n + BigInt(padded)).toString();
  } catch {
    return null;
  }
}

// Formats a canonical 6-decimals atomic amount as a human decimal string.
export function formatUsdcFromAtomic(atomic: string): string {
  if (!/^(?:0|[1-9][0-9]*)$/u.test(atomic)) return "";
  const value = BigInt(atomic);
  const whole = (value / 1_000_000n).toString();
  const fraction = (value % 1_000_000n).toString().padStart(6, "0").replace(/0+$/u, "");
  return fraction.length === 0 ? whole : `${whole}.${fraction}`;
}

// Parses a newline/whitespace separated canonical provider/listing id list.
// One canonical id per line, ascending unique. Both empty means deny-all; both
// populated means intersect (enforced by the shared content schema semantics).
export function parseCanonicalIdList(input: string, kind: "provider" | "listing"): string[] | null {
  const schema = kind === "provider" ? CommerceProviderIdSchema : CommerceListingIdSchema;
  const lines = input
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  const out: string[] = [];
  for (const line of lines) {
    const parsed = schema.safeParse(line);
    if (!parsed.success) return null;
    out.push(parsed.data);
  }
  const sorted = [...out].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  for (let index = 1; index < sorted.length; index += 1) {
    if (sorted[index - 1] === sorted[index]) return null;
  }
  return sorted;
}

export interface PolicyApprovalInput {
  readonly mode: "none" | "always" | "above";
  readonly threshold: string | null;
  readonly separateApprover: boolean;
}

export interface PolicyContentInput {
  readonly organizationId: string;
  readonly subjectAgentId: string;
  readonly perActionLimit: string | null;
  readonly rollingLimit: string | null;
  readonly rollingWindowSeconds: string | null;
  readonly feeLimit: string;
  readonly allowedProviderIds: readonly string[];
  readonly allowedListingIds: readonly string[];
  readonly approval: PolicyApprovalInput;
  readonly expiresAt: string | null;
}

// Builds the exact strict policy content from already-parsed atomic values and
// accepted schema shapes. No invented defaults: approval/expiry are the
// caller's explicit choices, and a zero cap is a valid deny-all.
export function buildPolicyContent(input: PolicyContentInput): CommercePolicyContent | null {
  const candidate = {
    organizationId: input.organizationId,
    subjectAgentId: input.subjectAgentId,
    networkId: "eip155:5042002" as const,
    asset: "USDC" as const,
    representation: "erc20" as const,
    decimals: 6 as const,
    perActionLimit: input.perActionLimit,
    rollingLimit: input.rollingLimit,
    rollingWindowSeconds:
      input.rollingLimit === null ? null : input.rollingWindowSeconds,
    feeLimit: input.feeLimit,
    allowedProviderIds: [...input.allowedProviderIds],
    allowedListingIds: [...input.allowedListingIds],
    approval: {
      mode: input.approval.mode,
      threshold: input.approval.mode === "above" ? input.approval.threshold : null,
      separateApprover: input.approval.separateApprover,
    },
    expiresAt: input.expiresAt,
  };
  const parsed = CommercePolicyContentSchema.safeParse(candidate);
  return parsed.success ? parsed.data : null;
}

export function isCanonicalAgentId(value: string): value is CommerceAgentId {
  return CommerceAgentIdSchema.safeParse(value).success;
}

// Extracts the exact policy content from an immutable revision so an append
// starts from the prior accepted content. A revision is never edited in place.
export function contentFromRevision(revision: CommercePolicyRevision): CommercePolicyContent | null {
  const parsed = CommercePolicyRevisionSchema.safeParse(revision);
  if (!parsed.success) return null;
  return buildPolicyContent({
    organizationId: parsed.data.organizationId,
    subjectAgentId: parsed.data.subjectAgentId,
    perActionLimit: parsed.data.perActionLimit,
    rollingLimit: parsed.data.rollingLimit,
    rollingWindowSeconds: parsed.data.rollingWindowSeconds,
    feeLimit: parsed.data.feeLimit,
    allowedProviderIds: parsed.data.allowedProviderIds,
    allowedListingIds: parsed.data.allowedListingIds,
    approval: {
      mode: parsed.data.approval.mode,
      threshold: parsed.data.approval.mode === "above" ? parsed.data.approval.threshold : null,
      separateApprover: parsed.data.approval.separateApprover,
    },
    expiresAt: parsed.data.expiresAt,
  });
}

// Begins an append using the prior revision's exact content as the base. The
// authoritative CAS still comes from the root currentRevision + updatedAt.
export function beginAppendFromRevision(
  controller: PolicyController,
  revision: CommercePolicyRevision,
): boolean {
  const content = contentFromRevision(revision);
  if (content === null) return false;
  return controller.beginAppend(content);
}

// A history summary is metadata-only. This is a client-local guard so a
// summary can never be mistaken for a full revision.
export function isRevisionSummary(value: unknown): value is CommercePolicyRevisionSummary {
  return CommercePolicyRevisionSummarySchema.safeParse(value).success;
}

export interface PolicyReadCoordinator {
  currentOrganizationId(): string | null;
  currentRole(): string | null;
  currentAccountId(): string | null;
  abortPendingReads(): void;
  reloadAfterCommit(): Promise<void>;
}

export type PolicyStatus = "none" | "loading" | "ready" | "error";

export interface PolicyRootsState {
  readonly status: PolicyStatus;
  readonly items: readonly CommercePolicyRoot[];
  readonly nextCursor: string | null;
  readonly hasPrevious: boolean;
}

export interface PolicyHistoryState {
  readonly status: PolicyStatus;
  readonly items: readonly CommercePolicyRevisionSummary[];
  readonly nextCursor: string | null;
  readonly historyComplete: boolean;
  readonly cursorStack: readonly string[];
}

export interface PolicyDetailState {
  readonly status: "none" | "loading" | "ready" | "not-found" | "error";
  readonly root: CommercePolicyRoot | null;
  readonly history: PolicyHistoryState;
}

// An explicit revision read shows the FULL immutable content, never a summary.
export interface PolicyRevisionState {
  readonly status: "none" | "loading" | "ready" | "not-found" | "error";
  readonly revision: CommercePolicyRevision | null;
}

export type PolicyMutationDraft =
  | { readonly op: "create"; readonly content: CommercePolicyContent }
  | {
      readonly op: "append";
      readonly policyId: string;
      readonly cas: PolicyCas;
      readonly content: CommercePolicyContent;
    }
  | { readonly op: "pause"; readonly policyId: string; readonly cas: PolicyCas }
  | { readonly op: "resume"; readonly policyId: string; readonly cas: PolicyCas }
  | { readonly op: "revoke"; readonly policyId: string; readonly cas: PolicyCas };

export type PolicyMutationNotice =
  | { readonly kind: "validation" }
  | { readonly kind: "policy" }
  | { readonly kind: "conflict"; readonly reloadRequired: boolean }
  | { readonly kind: "unauthenticated" }
  | { readonly kind: "csrf" }
  | { readonly kind: "forbidden" }
  | { readonly kind: "not-found" }
  | { readonly kind: "account-changed" }
  | { readonly kind: "capability-disabled" };

export interface PolicyOutcomeUnknown {
  readonly kind: "outcome-unknown";
  readonly mutationId: string;
  readonly organizationId: string;
  readonly operation: PolicyMutationOperation;
  // Null for a create: the database generates the canonical policy resource,
  // so a status GET binds only the known mutation id and operation and then
  // accepts the canonical typed policy resource from the committed receipt.
  readonly expectedResourceId: string | null;
  readonly policyId: string | null;
  readonly checking: boolean;
  readonly statusMessage: string | null;
}

export type PolicyMutationState =
  | { readonly kind: "idle" }
  | { readonly kind: "confirming"; readonly draft: PolicyMutationDraft }
  | { readonly kind: "pending"; readonly draft: PolicyMutationDraft; readonly mutationId: string }
  | {
      readonly kind: "committed";
      readonly receipt: CommercePolicyMutationReceipt;
      readonly replayed: boolean;
      readonly resourceRevision: string | null;
      readonly policyId: string | null;
      readonly refreshError: boolean;
    }
  | { readonly kind: "rejected"; readonly notice: PolicyMutationNotice }
  | PolicyOutcomeUnknown;

export interface PolicySelection {
  readonly route: PolicyRoute;
  readonly selectedRevision: CommercePolicyRevision | null;
}

export interface PolicyControllerState {
  readonly capability: "unknown" | "checking" | "enabled" | "unavailable";
  readonly role: string | null;
  readonly canWrite: boolean;
  readonly roots: PolicyRootsState;
  readonly detail: PolicyDetailState;
  readonly revision: PolicyRevisionState;
  readonly selection: PolicySelection;
  readonly mutation: PolicyMutationState;
}

export function initialPolicyRootsState(): PolicyRootsState {
  return { status: "none", items: [], nextCursor: null, hasPrevious: false };
}

export function initialPolicyHistoryState(): PolicyHistoryState {
  return { status: "none", items: [], nextCursor: null, historyComplete: false, cursorStack: [] };
}

export function initialPolicyDetailState(): PolicyDetailState {
  return { status: "none", root: null, history: initialPolicyHistoryState() };
}

export function initialPolicyRevisionState(): PolicyRevisionState {
  return { status: "none", revision: null };
}

export function initialPolicyControllerState(): PolicyControllerState {
  return {
    capability: "unknown",
    role: null,
    canWrite: false,
    roots: initialPolicyRootsState(),
    detail: initialPolicyDetailState(),
    revision: initialPolicyRevisionState(),
    selection: { route: { kind: "roots" }, selectedRevision: null },
    mutation: { kind: "idle" },
  };
}

export interface PolicyControllerDeps {
  readonly client?: PolicyClient;
  readonly account: AccountFlowController;
  readonly reads: PolicyReadCoordinator;
  readonly capabilityReader?: (signal: AbortSignal) => Promise<ControlCapabilityState>;
  // Invoked after a committed first-revision create so the shell can open the
  // new detail page. The policy id comes from the committed receipt's canonical
  // typed policy resource; it is never optimistically assumed before commit.
  readonly onCommittedPolicy?: (policyId: string) => void;
  readonly onState?: (state: PolicyControllerState) => void;
}

interface FrozenSubmission {
  readonly draft: PolicyMutationDraft;
  readonly mutationId: string;
  readonly idempotencyKey: string;
  readonly organizationId: string;
  readonly expectedResourceId: string | null;
}

export class PolicyController {
  #state: PolicyControllerState = initialPolicyControllerState();
  #disposed = false;
  #generation = 0;
  #rootsAbort: AbortController | null = null;
  #detailAbort: AbortController | null = null;
  #revisionAbort: AbortController | null = null;
  #statusAbort: AbortController | null = null;
  #capabilityAbort: AbortController | null = null;
  #capabilityChecked = false;
  readonly #client: PolicyClient;
  readonly #account: AccountFlowController;
  readonly #reads: PolicyReadCoordinator;
  readonly #capabilityReader: (signal: AbortSignal) => Promise<ControlCapabilityState>;
  readonly #onCommittedPolicy: ((policyId: string) => void) | undefined;
  readonly #onState: ((state: PolicyControllerState) => void) | undefined;

  constructor(deps: PolicyControllerDeps) {
    this.#client = deps.client ?? new PolicyClient();
    this.#account = deps.account;
    this.#reads = deps.reads;
    this.#capabilityReader = deps.capabilityReader ?? ((signal) => readPolicyManagementCapability(signal));
    this.#onCommittedPolicy = deps.onCommittedPolicy;
    this.#onState = deps.onState;
  }

  get state(): PolicyControllerState {
    return this.#state;
  }

  get disposed(): boolean {
    return this.#disposed;
  }

  // Points the controller at a parsed route without issuing any request.
  setRoute(route: PolicyRoute): void {
    if (this.#disposed) return;
    this.#update({
      selection: { route, selectedRevision: null },
      detail: initialPolicyDetailState(),
      revision: initialPolicyRevisionState(),
    });
  }

  // Independent capability gate. It runs BEFORE any policy client/controller
  // request and never depends on tenant-writes, machine, listing, Vault or
  // wallet flags. On a known policy route with the flag on but the capability
  // not `enabled`, state is `unavailable` and no policy request is ever made.
  async initialize(route: PolicyRoute): Promise<void> {
    if (this.#disposed) return;
    const generation = this.#generation;
    this.#update({
      selection: { route, selectedRevision: null },
      detail: initialPolicyDetailState(),
      revision: initialPolicyRevisionState(),
    });
    if (!this.#capabilityChecked) {
      this.#update({ capability: "checking" });
      this.#capabilityAbort?.abort();
      const capabilityController = new AbortController();
      this.#capabilityAbort = capabilityController;
      let state: ControlCapabilityState;
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
    if (route.kind === "roots" || route.kind === "new") {
      await this.loadRoots();
    } else if (route.kind === "detail") {
      await this.loadDetail(route.policyId);
    }
  }

  async loadRoots(): Promise<void> {
    await this.#loadRootsPage(false);
  }

  async loadNextRoots(): Promise<void> {
    await this.#loadRootsPage(true);
  }

  async #loadRootsPage(next: boolean): Promise<void> {
    if (this.#disposed || !this.#authorized()) return;
    const organizationId = this.#currentOrganizationId();
    if (organizationId === null) return;
    const cursor = next ? this.#state.roots.nextCursor : null;
    if (next && cursor === null) return;
    const generation = this.#generation;
    this.#rootsAbort?.abort();
    const controller = new AbortController();
    this.#rootsAbort = controller;
    this.#patchRoots({ status: "loading" });
    let page;
    try {
      page = await this.#client.listRoots(
        { organizationId, ...(cursor === null ? {} : { afterPolicyId: cursor }) },
        controller.signal,
      );
    } catch {
      if (!this.#stillCurrent(generation)) return;
      this.#patchRoots({ status: "error", items: [], nextCursor: null, hasPrevious: next });
      return;
    }
    if (!this.#stillCurrent(generation) || this.#currentOrganizationId() !== organizationId) return;
    this.#patchRoots({ status: "ready", items: page.items, nextCursor: page.nextCursor, hasPrevious: next });
  }

  // Detail fetch: root and the first history page resolve INDEPENDENTLY. A
  // truthful `item: null` root becomes an honest `not-found`; a history failure
  // does not fabricate an empty history.
  async loadDetail(policyId: string): Promise<void> {
    if (this.#disposed || !this.#authorized()) return;
    const organizationId = this.#currentOrganizationId();
    if (organizationId === null) return;
    const generation = this.#generation;
    this.#detailAbort?.abort();
    const controller = new AbortController();
    this.#detailAbort = controller;
    this.#patchDetail({ status: "loading", root: null, history: initialPolicyHistoryState() });
    const [rootResult, historyResult] = await Promise.allSettled([
      this.#client.readRoot({ organizationId, policyId }, controller.signal),
      this.#client.listHistory({ organizationId, policyId }, controller.signal),
    ]);
    if (!this.#stillCurrent(generation) || this.#currentOrganizationId() !== organizationId) return;
    const root = rootResult.status === "fulfilled" ? rootResult.value.item : null;
    const rootFailed = rootResult.status === "rejected";
    const history =
      historyResult.status === "fulfilled"
        ? {
            status: "ready" as const,
            items: historyResult.value.items,
            nextCursor: historyResult.value.nextCursor,
            historyComplete: historyResult.value.nextCursor === null,
            cursorStack: [] as readonly string[],
          }
        : {
            status: "error" as const,
            items: [] as readonly CommercePolicyRevisionSummary[],
            nextCursor: null,
            historyComplete: false,
            cursorStack: [] as readonly string[],
          };
    if (root === null) {
      this.#patchDetail({ status: rootFailed ? "error" : "not-found", root: null, history });
      return;
    }
    this.#patchDetail({ status: "ready", root, history });
  }

  // Explicit bounded "load more revisions": ascending afterRevision, max 50.
  // History pagination is INDEPENDENT of the CAS root, which is always the
  // authoritative root currentRevision + updatedAt.
  async loadMoreRevisions(): Promise<void> {
    if (this.#disposed || !this.#authorized()) return;
    const detail = this.#state.detail;
    const root = detail.root;
    const organizationId = this.#currentOrganizationId();
    if (root === null || organizationId === null) return;
    const history = detail.history;
    if (history.status === "loading" || history.historyComplete || history.nextCursor === null) return;
    const cursor = history.nextCursor;
    const generation = this.#generation;
    this.#detailAbort?.abort();
    const controller = new AbortController();
    this.#detailAbort = controller;
    this.#patchDetail({ ...detail, history: { ...history, status: "loading" } });
    let page;
    try {
      page = await this.#client.listHistory(
        { organizationId, policyId: root.policyId, afterRevision: cursor },
        controller.signal,
      );
    } catch {
      if (!this.#stillCurrent(generation)) return;
      // Preserve the one prior bounded page and its cursor, but make the
      // continuation failure EXPLICIT.
      this.#patchDetail({ ...this.#state.detail, history: { ...history, status: "error" } });
      return;
    }
    if (!this.#stillCurrent(generation) || this.#currentOrganizationId() !== organizationId) return;
    const completed = page.nextCursor === null;
    const nextHistory: PolicyHistoryState = {
      status: "ready",
      items: page.items,
      nextCursor: page.nextCursor,
      historyComplete: completed,
      cursorStack: appendPolicyCursor(history.cursorStack, cursor),
    };
    this.#patchDetail({ ...this.#state.detail, history: nextHistory });
  }

  // Explicit FULL revision read. History summaries are metadata-only, so this
  // is the only read that reveals full content.
  async readRevision(revision: string): Promise<boolean> {
    if (this.#disposed || !this.#authorized()) return false;
    const root = this.#state.detail.root;
    const organizationId = this.#currentOrganizationId();
    if (root === null || organizationId === null) return false;
    const generation = this.#generation;
    this.#revisionAbort?.abort();
    const controller = new AbortController();
    this.#revisionAbort = controller;
    this.#update({
      revision: { status: "loading", revision: null },
      selection: { route: this.#state.selection.route, selectedRevision: null },
    });
    let detail;
    try {
      detail = await this.#client.readRevision(
        { organizationId, policyId: root.policyId, revision },
        controller.signal,
      );
    } catch {
      if (!this.#stillCurrent(generation)) return false;
      this.#update({ revision: { status: "error", revision: null } });
      return false;
    }
    if (!this.#stillCurrent(generation) || this.#currentOrganizationId() !== organizationId) return false;
    if (detail.item === null) {
      this.#update({ revision: { status: "not-found", revision: null } });
      return false;
    }
    const parsed = CommercePolicyRevisionSchema.safeParse(detail.item);
    if (!parsed.success) {
      this.#update({ revision: { status: "error", revision: null } });
      return false;
    }
    this.#update({
      revision: { status: "ready", revision: parsed.data },
      selection: { route: this.#state.selection.route, selectedRevision: parsed.data },
    });
    return true;
  }

  // Begins the explicit confirmation stage; sends nothing and mints no key.
  beginCreate(content: CommercePolicyContent): boolean {
    return this.#begin({ op: "create", content });
  }

  beginAppend(content: CommercePolicyContent): boolean {
    const root = this.#state.detail.root;
    if (root === null) return false;
    const cas = policyCasOf(root);
    if (cas === null) return false;
    return this.#begin({ op: "append", policyId: root.policyId, cas, content });
  }

  beginLifecycle(op: "pause" | "resume" | "revoke"): boolean {
    const root = this.#state.detail.root;
    if (root === null) return false;
    const cas = policyCasOf(root);
    if (cas === null) return false;
    if (op === "pause" && root.status !== "active") return false;
    if (op === "resume" && root.status !== "paused") return false;
    if (op === "revoke" && root.status === "revoked") return false;
    return this.#begin({ op, policyId: root.policyId, cas });
  }

  #begin(draft: PolicyMutationDraft): boolean {
    if (this.#disposed) return false;
    if (this.#state.capability !== "enabled") {
      this.#update({ mutation: { kind: "rejected", notice: { kind: "capability-disabled" } } });
      return false;
    }
    if (!canWritePolicies(this.#currentRole())) {
      this.#update({ mutation: { kind: "rejected", notice: { kind: "forbidden" } } });
      return false;
    }
    this.#generation += 1;
    this.#update({ mutation: { kind: "confirming", draft } });
    return true;
  }

  cancel(): void {
    if (this.#disposed) return;
    if (this.#state.mutation.kind === "pending") return;
    this.#generation += 1;
    this.#update({ mutation: { kind: "idle" } });
  }

  // Sends exactly one confirmed logical write with a frozen id/key/CAS.
  async confirm(): Promise<void> {
    if (this.#disposed) return;
    if (this.#state.mutation.kind !== "confirming") return;
    const draft = this.#state.mutation.draft;
    const organizationId = this.#currentOrganizationId();
    if (organizationId === null) return;
    const mutationId = createPolicyMutationId();
    const idempotencyKey = createPolicyIdempotencyKey();
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
      expectedResourceId: expectedResourceIdOf(draft, mutationId),
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

  // Runs exactly one frozen logical action. The mutation id and idempotency key
  // are supplied by the controller and never re-minted here.
  async #runAction(
    draft: PolicyMutationDraft,
    organizationId: string,
    mutationId: string,
    idempotencyKey: string,
    csrfToken: string,
    signal: AbortSignal,
  ): Promise<{ receipt: CommercePolicyMutationReceipt; replayed: boolean; policyId: string | null }> {
    const common = { organizationId, csrfToken, idempotencyKey, signal };
    let result: CommercePolicyMutationResult;
    switch (draft.op) {
      case "create":
        result = await this.#client.createRevision({
          ...common,
          body: { mutationId, content: draft.content },
        });
        break;
      case "append":
        result = await this.#client.appendRevision({
          ...common,
          policyId: draft.policyId,
          body: {
            mutationId,
            expectedRevision: draft.cas.expectedRevision,
            expectedUpdatedAt: draft.cas.expectedUpdatedAt,
            content: draft.content,
          },
        });
        break;
      case "pause":
        result = await this.#client.pause({ ...common, policyId: draft.policyId, body: transitionBody(draft, mutationId) });
        break;
      case "resume":
        result = await this.#client.resume({ ...common, policyId: draft.policyId, body: transitionBody(draft, mutationId) });
        break;
      case "revoke":
        result = await this.#client.revoke({ ...common, policyId: draft.policyId, body: transitionBody(draft, mutationId) });
        break;
    }
    assertReceiptBinding(result, mutationId);
    return {
      receipt: result.receipt,
      replayed: result.replayed,
      policyId: policyIdOfReceipt(result.receipt),
    };
  }

  async #afterCommit(
    result: { receipt: CommercePolicyMutationReceipt; replayed: boolean; policyId: string | null },
    generation: number,
  ): Promise<void> {
    let refreshError = false;
    try {
      await this.#reads.reloadAfterCommit();
    } catch {
      refreshError = true;
    }
    if (!this.#stillCurrent(generation)) return;
    // The committed receipt is stored EVEN IF the post-commit refresh failed.
    // It is never mislabeled as safely retryable.
    this.#update({
      mutation: {
        kind: "committed",
        receipt: result.receipt,
        replayed: result.replayed,
        resourceRevision: revisionOfReceipt(result.receipt),
        policyId: result.policyId,
        refreshError,
      },
    });
    if (result.receipt.operation === "control.policy.create" && result.policyId !== null) {
      this.#onCommittedPolicy?.(result.policyId);
    }
    if (refreshError) return;
    const route = this.#state.selection.route;
    if (route.kind === "detail") {
      await this.loadDetail(route.policyId);
    } else {
      await this.loadRoots();
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
        this.#update({ mutation: { kind: "rejected", notice: { kind: "conflict", reloadRequired: true } } });
        return;
      case "not-found":
        this.#update({ mutation: { kind: "rejected", notice: { kind: "not-found" } } });
        return;
      case "account-changed":
        this.#update({ mutation: { kind: "rejected", notice: { kind: "account-changed" } } });
        return;
      case "aborted":
        this.#update({ mutation: { kind: "idle" } });
        return;
      case "pre-send":
        this.#update({ mutation: { kind: "rejected", notice: { kind: "validation" } } });
        return;
      default: {
        // Sent-but-unconfirmed: keep the frozen id and offer only an explicit
        // status GET with the original id.
        this.#update({
          mutation: {
            kind: "outcome-unknown",
            mutationId: frozen.mutationId,
            organizationId: frozen.organizationId,
            operation: operationOf(draftOp(frozen.draft)),
            expectedResourceId: frozen.expectedResourceId,
            policyId: draftPolicyIdOf(frozen.draft),
            checking: false,
            statusMessage: null,
          },
        });
        return;
      }
    }
  }

  // Explicit safe status GET using the ORIGINAL mutation id; no resubmission.
  // A `not_found` result NEVER enables a resend.
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
      await this.#afterCommit(
        {
          receipt: status.receipt,
          replayed: true,
          policyId: policyIdOfReceipt(status.receipt),
        },
        generation,
      );
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

  // Account/org/role/session/hidden/pagehide/navigation/dispose: clear form,
  // selection, revision, mutation key/id/receipt/errors/request state.
  clear(): void {
    if (this.#disposed) return;
    this.#generation += 1;
    this.#rootsAbort?.abort();
    this.#rootsAbort = null;
    this.#detailAbort?.abort();
    this.#detailAbort = null;
    this.#revisionAbort?.abort();
    this.#revisionAbort = null;
    this.#statusAbort?.abort();
    this.#statusAbort = null;
    this.#capabilityAbort?.abort();
    this.#capabilityAbort = null;
    this.#update({
      role: this.#currentRole(),
      canWrite: this.#canWrite(),
      roots: initialPolicyRootsState(),
      detail: initialPolicyDetailState(),
      revision: initialPolicyRevisionState(),
      selection: { route: this.#state.selection.route, selectedRevision: null },
      mutation: { kind: "idle" },
    });
  }

  // Role reconciliation: a role change clears every local artifact.
  reconcileRole(role: string | null): void {
    if (this.#disposed) return;
    if (this.#state.role === role && this.#state.canWrite === canWritePolicies(role)) return;
    this.clear();
  }

  // Clears only the credential/form artifacts, not the bounded read pages.
  clearSensitive(): void {
    if (this.#disposed) return;
    this.#generation += 1;
    this.#revisionAbort?.abort();
    this.#revisionAbort = null;
    this.#statusAbort?.abort();
    this.#statusAbort = null;
    this.#capabilityAbort?.abort();
    this.#capabilityAbort = null;
    this.#update({
      selection: { route: this.#state.selection.route, selectedRevision: null },
      revision: initialPolicyRevisionState(),
      mutation: { kind: "idle" },
    });
  }

  dispose(): void {
    if (this.#disposed) return;
    this.clear();
    this.#disposed = true;
    this.#onState?.(this.#state);
  }

  // Reads require only the independent capability gate. The server remains the
  // authority for role and tenant scope, so a role that arrives after the first
  // initialize never strands the surface. Write controls are gated separately
  // by the exact local role matrix in `#canWrite`.
  #authorized(): boolean {
    return this.#state.capability === "enabled";
  }

  // Writes additionally require the exact write-role matrix.
  #canWrite(): boolean {
    return this.#state.capability === "enabled" && canWritePolicies(this.#currentRole());
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

  #patchRoots(patch: Partial<PolicyRootsState>): void {
    this.#update({ roots: { ...this.#state.roots, ...patch } });
  }

  #patchDetail(detail: PolicyDetailState): void {
    this.#update({ detail });
  }

  #update(patch: Partial<PolicyControllerState>): void {
    if (this.#disposed) return;
    this.#state = { ...this.#state, ...patch };
    this.#state = {
      ...this.#state,
      role: this.#currentRole(),
      canWrite: this.#canWrite(),
    };
    this.#onState?.(this.#state);
  }
}

type FailureKind = PolicyApiFailure["kind"] | "account-changed";

function transitionBody(
  draft: Extract<PolicyMutationDraft, { op: "pause" | "resume" | "revoke" }>,
  mutationId: string,
): { mutationId: string; expectedRevision: string; expectedUpdatedAt: string } {
  return {
    mutationId,
    expectedRevision: draft.cas.expectedRevision,
    expectedUpdatedAt: draft.cas.expectedUpdatedAt,
  };
}

function draftOp(draft: PolicyMutationDraft): PolicyMutationDraft["op"] {
  return draft.op;
}

function operationOf(op: PolicyMutationDraft["op"]): PolicyMutationOperation {
  switch (op) {
    case "create":
      return "control.policy.create";
    case "append":
      return "control.policy.revision.create";
    case "pause":
      return "control.policy.pause";
    case "resume":
      return "control.policy.resume";
    case "revoke":
      return "control.policy.revoke";
  }
}

function draftPolicyIdOf(draft: PolicyMutationDraft): string | null {
  return draft.op === "create" ? null : draft.policyId;
}

// The exact operation and expected resource a frozen logical action must
// receive back. A create is DB-assigned: the canonical policy resource comes
// from the committed receipt, never from a mutationId-derived guess. An append
// is exactly `policyId@(expectedRevision + 1)`; a transition is `policyId`.
export function expectedResourceIdOf(draft: PolicyMutationDraft, mutationId: string): string | null {
  switch (draft.op) {
    case "create":
      // The database generates the canonical policy resource. A status GET for
      // a create binds only the mutation id and operation and never a guessed
      // resource derived from the mutation id.
      void mutationId;
      return null;
    case "append":
      return `${draft.policyId}@${(BigInt(draft.cas.expectedRevision) + 1n).toString()}`;
    case "pause":
    case "resume":
    case "revoke":
      return draft.policyId;
  }
}

// Where a committed receipt's canonical policy resource is read for create.
export function policyIdOfReceipt(receipt: CommercePolicyMutationReceipt): string | null {
  if (receipt.operation !== "control.policy.create") {
    const at = receipt.resourceId.lastIndexOf("@");
    return at === -1 ? receipt.resourceId : receipt.resourceId.slice(0, at);
  }
  return receipt.resourceId;
}

export function revisionOfReceipt(receipt: CommercePolicyMutationReceipt): string | null {
  if (receipt.operation !== "control.policy.revision.create") return null;
  const at = receipt.resourceId.lastIndexOf("@");
  return at === -1 ? null : receipt.resourceId.slice(at + 1);
}

export function assertReceiptBinding(
  result: CommercePolicyMutationResult,
  mutationId: string,
): void {
  if (!CommercePolicyMutationReceiptSchema.safeParse(result.receipt).success) {
    throw new PolicyApiError({ kind: "invalid-response" });
  }
  if (result.receipt.mutationId !== mutationId) {
    throw new PolicyApiError({ kind: "invalid-response" });
  }
}

function failureOf(error: unknown): { kind: FailureKind } {
  if (error instanceof PolicyApiError) return { kind: error.failure.kind };
  if (typeof error === "object" && error !== null) {
    const failure = (error as { failure?: { kind?: unknown } }).failure;
    if (typeof failure === "object" && failure !== null) {
      const kind = (failure as { kind?: unknown }).kind;
      if (kind === "account-changed") return { kind: "account-changed" };
    }
  }
  return { kind: "outcome-unknown" };
}

export type { PolicyRoute };

// Synchronous render-boundary guard for the policy surface.
//
// React effects run AFTER render, so an account/organization/role transition
// would otherwise paint one frame of the previous context's draft, receipt or
// list. The parent computes the bound context during render and suppresses (by
// substituting the initial state) when it does not match the current context.
export interface PolicyRenderContext {
  readonly accountId: string | null;
  readonly organizationId: string | null;
  readonly role: string | null;
}

export function suppressStalePolicyContext(
  bound: PolicyRenderContext | null,
  current: PolicyRenderContext,
): boolean {
  if (bound === null) return false;
  if (current.accountId === null || current.organizationId === null) return true;
  return (
    bound.accountId !== current.accountId ||
    bound.organizationId !== current.organizationId ||
    bound.role !== current.role
  );
}

export function renderPolicyState(
  suppress: boolean,
  state: PolicyControllerState,
  initial: () => PolicyControllerState = initialPolicyControllerState,
): PolicyControllerState {
  return suppress ? initial() : state;
}
