import {
  COMMERCE_GRANT_MAX_LIFETIME_SECONDS,
  CommerceGrantIdSchema,
  CommerceGrantMetadataSchema,
  CommerceTenantIdempotencyKeySchema,
  CommerceTenantMutationIdSchema,
  compareIsoTimestamps,
  type CommerceActionStatus,
  type CommerceGrantMetadata,
  type CommerceGrantRevokeReceipt,
  type GrantCapabilityState,
} from "@openarc/shared";

import type { AccountBoundToken, AccountFlowController } from "../account/flow-controller.js";
import {
  GrantApiError,
  GrantClient,
  createGrantIdempotencyKey,
  createGrantMutationId,
  readCommerceGrantsCapability,
  type GrantApiFailure,
} from "./grant-client.js";
import type { GrantRoute } from "./grant-routes.js";

/**
 * Bounded authorization-grant console controller.
 *
 * The controller owns at most ONE explicit human revoke at a time. A logical
 * mutation id, idempotency key and target grant are frozen for the lifetime of
 * a request: there is no automatic retry, no polling, no new key and no "latest
 * state" preflight. A sent-but-unconfirmed outcome is reported as
 * `outcome-unknown` and can only be resolved by an explicit, user-initiated
 * status GET with the ORIGINAL mutation id.
 *
 * Nothing here is ever optimistic. A revoke is never shown as applied before a
 * committed receipt arrives, and an unknown outcome is rendered as genuinely
 * unknown — never as success, failure, refund or release.
 *
 * The single most important rule in this file: REVOCATION AFTER A CLAIM RETAINS
 * THE CLAIM. A grant that was claimed and then revoked keeps `claimedAt`, keeps
 * its held exposure, and may still have been paid. This console states that
 * plainly and never presents revocation as a refund, a release or a
 * cancellation of payment. It also never renders an optimistic or implied
 * "paid", "settled", "delivered" or "refunded" status: no accepted browser
 * shape can carry one, and an unknown outcome reads as genuinely unknown.
 *
 * No raw grant token can reach this module. The browser `commerce_grant_
 * management` family never receives one — `grantToken` is an inbound field on
 * exactly two headless PROVIDER routes this client cannot call — and the
 * displayed field list below is a positive allowlist over accepted metadata,
 * which has no token, no token hash and no amount of any kind.
 */

/**
 * Exact role matrix. Owner, operator and viewer on a current non-recovery
 * account may READ a grant. Only owner and operator may REVOKE. Provider,
 * unknown and recovery sign-in get no access at all.
 *
 * This is a UI gate only. The server remains the final authority: a revoke
 * denied by the server is recorded and disables the local controls rather than
 * letting this local guess stand.
 */
export function canReadGrants(role: string | null | undefined): boolean {
  return role === "owner" || role === "operator" || role === "viewer";
}

export function canRevokeGrants(role: string | null | undefined): boolean {
  return role === "owner" || role === "operator";
}

/** The fixed lifetime ceiling, restated for display from the accepted wire. */
export const GRANT_MAX_LIFETIME_SECONDS = COMMERCE_GRANT_MAX_LIFETIME_SECONDS;

export const GRANT_LIFETIME_NOTICE =
  `A grant lives at most ${GRANT_MAX_LIFETIME_SECONDS} seconds from issuance. The exact expiry instant below is the server's, shown verbatim; this console runs no countdown and never extends it.`;

/**
 * THE load-bearing copy of this console. A grant that was claimed and then
 * revoked keeps its claim fact and its held exposure, and may still have been
 * paid. Revocation is never a refund, a release or a cancellation of payment.
 */
export const GRANT_CLAIMED_THEN_REVOKED_NOTICE =
  "This grant was claimed before it was revoked. Revoking it did not undo the claim: the claim fact is retained, the held exposure is retained, and this grant may still have been paid. Revocation is not a refund, not a release and not a cancellation of payment. This console is not told whether payment, settlement or delivery happened, so it does not say.";

/** The never-claimed revoke case. A released hold is a cap adjustment only. */
export const GRANT_RELEASED_REVOKE_NOTICE =
  "The server reports this grant was never claimed and its held amount was released back against the policy cap, and the bound action is cancelled. Releasing a hold is a cap adjustment, not a refund: no money moved and none was owed.";

/** An unknown release outcome must read as unknown, never as a release. */
export const GRANT_RELEASE_UNKNOWN_NOTICE =
  "The server did not report whether the held amount was released. That is unknown, not a release and not a refund.";

export const UNKNOWN_GRANT_STATUS_MESSAGE =
  "No committed result found yet. The revoke may still complete. Nothing was resent; check again when you choose to.";

export type GrantLifeState = "claimable" | "expired" | "claimed" | "revoked";

/**
 * True when the grant's own expiry instant is at or before `nowIso`. A `nowIso`
 * this function cannot parse returns TRUE: failing closed means a grant is
 * never implied to be still claimable on the strength of an unreadable clock.
 */
export function grantExpired(metadata: CommerceGrantMetadata, nowIso: string): boolean {
  try {
    return compareIsoTimestamps(nowIso, metadata.expiresAt) >= 0;
  } catch {
    return true;
  }
}

/**
 * The grant's life state at an EXPLICIT instant. The clock is a parameter, not
 * an ambient read, so this is pure and the console never drifts. An `issued`
 * grant past its expiry is `expired`: the server's stored status can lag, and a
 * lagging status must never be rendered as still claimable.
 */
export function grantLifeState(
  metadata: CommerceGrantMetadata,
  nowIso: string,
): GrantLifeState {
  if (metadata.status === "revoked") return "revoked";
  if (metadata.status === "claimed") return "claimed";
  if (metadata.status === "expired") return "expired";
  return grantExpired(metadata, nowIso) ? "expired" : "claimable";
}

export function grantStatusLabel(status: string): string {
  switch (status) {
    case "issued":
      return "Issued";
    case "claimed":
      return "Claimed";
    case "revoked":
      return "Revoked";
    case "expired":
      return "Expired";
    default:
      return "Unknown";
  }
}

/**
 * What a grant status does NOT mean. Every branch refuses to assert payment,
 * settlement, delivery or a refund, because no accepted browser shape reports
 * any of them.
 */
export function grantStatusExplanation(
  metadata: CommerceGrantMetadata,
  nowIso: string,
): string {
  const life = grantLifeState(metadata, nowIso);
  switch (life) {
    case "claimable":
      return "The server holds this grant as issued and its expiry has not passed. A grant is one-use permission for the provider to claim. It is not a payment, a settlement or a delivery, and nothing here says it was used.";
    case "expired":
      return metadata.status === "issued"
        ? "This grant's expiry instant has passed, so it is expired and can no longer be claimed, even though the server still records it as issued. Expiry alone says nothing about whether anything was paid, settled or delivered."
        : "This grant expired without ever being claimed. Expiry retires permission; it is not evidence that anything was, or was not, paid.";
    case "claimed":
      return "A provider claimed this grant. A claim records that the grant was presented and accepted; it is not a receipt. Whether payment, settlement or delivery followed is not reported to this console and is not shown here.";
    case "revoked":
      return metadata.claimedAt === null
        ? "This grant was revoked before any claim, so no provider ever presented it."
        : GRANT_CLAIMED_THEN_REVOKED_NOTICE;
  }
}

/** Exactly what the revoke does, in plain language, before it is sent. */
export function revokeSummary(metadata: CommerceGrantMetadata | null): string {
  const base =
    "Revoking retires this grant so it can no longer be claimed. It is a flag, not an erasure. It pays nothing, refunds nothing, settles nothing and cancels no payment.";
  if (metadata === null) return base;
  if (metadata.claimedAt !== null) {
    return `${base} ${GRANT_CLAIMED_THEN_REVOKED_NOTICE}`;
  }
  return `${base} This grant has no recorded claim yet. If it is still unclaimed when the server applies the revoke, the server may release its held amount against the policy cap and cancel the bound action; that is a cap adjustment, not a refund.`;
}

/**
 * The display fields of a grant. This is a POSITIVE ALLOWLIST over the accepted
 * metadata: every field is named explicitly, so no future wire addition can
 * leak into a view by accident. The accepted metadata has no token, no token
 * hash, no digest and no amount, and none is synthesized here — this console
 * therefore renders no money at all and needs no numeric conversion, so no
 * `Number`, `parseFloat` or rounding appears anywhere in this module.
 */
export interface GrantDisplayField {
  readonly key: string;
  readonly label: string;
  readonly value: string;
}

export function grantDisplayFields(
  metadata: CommerceGrantMetadata,
  nowIso: string,
): readonly GrantDisplayField[] {
  return Object.freeze([
    { key: "grantId", label: "Grant", value: metadata.grantId },
    { key: "status", label: "Status", value: grantStatusLabel(metadata.status) },
    {
      key: "life",
      label: "Claimable now",
      value:
        grantLifeState(metadata, nowIso) === "claimable"
          ? "Yes, until the expiry instant below"
          : "No",
    },
    { key: "organizationId", label: "Organization", value: metadata.organizationId },
    { key: "subjectAgentId", label: "Subject agent", value: metadata.subjectAgentId },
    { key: "actionId", label: "Action", value: metadata.actionId },
    { key: "reservationId", label: "Reservation", value: metadata.reservationId },
    { key: "commerceSessionId", label: "Commerce session", value: metadata.commerceSessionId },
    { key: "providerId", label: "Provider", value: metadata.providerId },
    { key: "listingId", label: "Listing", value: metadata.listingId },
    { key: "listingVersion", label: "Listing version", value: metadata.listingVersion },
    { key: "generation", label: "Generation", value: metadata.generation },
    { key: "issuedAt", label: "Issued", value: metadata.issuedAt },
    { key: "expiresAt", label: "Expires", value: metadata.expiresAt },
    { key: "updatedAt", label: "Updated", value: metadata.updatedAt },
    {
      key: "claimedAt",
      label: "Claimed",
      value: metadata.claimedAt ?? "no claim recorded",
    },
    {
      key: "revokedAt",
      label: "Revoked",
      value: metadata.revokedAt ?? "not revoked",
    },
  ]);
}

export type GrantFailureNotice =
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

export interface GrantOutcomeUnknown {
  readonly kind: "outcome-unknown";
  readonly mutationId: string;
  readonly organizationId: string;
  readonly grantId: string;
  readonly checking: boolean;
  readonly statusMessage: string | null;
}

export interface GrantCommittedState {
  readonly receipt: CommerceGrantRevokeReceipt;
  readonly metadata: CommerceGrantMetadata | null;
  /**
   * The server's exact `released` flag, or NULL when only a receipt is known
   * (a recovered status read carries no release flag). Null renders as
   * genuinely unknown and never as a release.
   */
  readonly released: boolean | null;
  /** The server's bound action status, or null when it was not reported. */
  readonly actionStatus: CommerceActionStatus | null;
  readonly replayed: boolean;
  readonly refreshError: boolean;
}

export type GrantRevokeState =
  | { readonly kind: "idle" }
  | { readonly kind: "confirming"; readonly draft: { readonly grantId: string } }
  | {
      readonly kind: "pending";
      readonly draft: { readonly grantId: string };
      readonly mutationId: string;
    }
  | { readonly kind: "committed"; readonly committed: GrantCommittedState }
  | { readonly kind: "rejected"; readonly notice: GrantFailureNotice }
  | GrantOutcomeUnknown;

export interface GrantDetailState {
  readonly status: "none" | "loading" | "ready" | "not-found" | "error";
  readonly item: CommerceGrantMetadata | null;
}

export interface GrantControllerState {
  readonly capability: "unknown" | "checking" | "enabled" | "unavailable";
  readonly role: string | null;
  readonly canRead: boolean;
  readonly canRevoke: boolean;
  /**
   * True once the server has refused a revoke for this context. The local role
   * matrix is only a guess; a server denial is authoritative and disables the
   * revoke controls until the context changes.
   */
  readonly serverDeniedRevoke: boolean;
  readonly selection: { readonly route: GrantRoute };
  /** An explicit lookup id typed by the operator. No request follows it. */
  readonly lookupGrantId: string | null;
  readonly detail: GrantDetailState;
  readonly revoke: GrantRevokeState;
}

export function initialGrantDetailState(): GrantDetailState {
  return { status: "none", item: null };
}

export function initialGrantControllerState(): GrantControllerState {
  return {
    capability: "unknown",
    role: null,
    canRead: false,
    canRevoke: false,
    serverDeniedRevoke: false,
    selection: { route: { kind: "lookup" } },
    lookupGrantId: null,
    detail: initialGrantDetailState(),
    revoke: { kind: "idle" },
  };
}

export interface GrantReadCoordinator {
  currentOrganizationId(): string | null;
  currentRole(): string | null;
  currentAccountId(): string | null;
  abortPendingReads(): void;
}

export interface GrantControllerDeps {
  readonly client?: GrantClient;
  readonly account: AccountFlowController;
  readonly reads: GrantReadCoordinator;
  readonly capabilityReader?: (signal: AbortSignal) => Promise<GrantCapabilityState>;
  readonly onState?: (state: GrantControllerState) => void;
}

interface FrozenRevoke {
  readonly grantId: string;
  readonly mutationId: string;
  readonly idempotencyKey: string;
  readonly organizationId: string;
}

export class GrantController {
  #state: GrantControllerState = initialGrantControllerState();
  #disposed = false;
  #generation = 0;
  #detailAbort: AbortController | null = null;
  #statusAbort: AbortController | null = null;
  #capabilityAbort: AbortController | null = null;
  #capabilityChecked = false;
  readonly #client: GrantClient;
  readonly #account: AccountFlowController;
  readonly #reads: GrantReadCoordinator;
  readonly #capabilityReader: (signal: AbortSignal) => Promise<GrantCapabilityState>;
  readonly #onState: ((state: GrantControllerState) => void) | undefined;

  constructor(deps: GrantControllerDeps) {
    this.#client = deps.client ?? new GrantClient();
    this.#account = deps.account;
    this.#reads = deps.reads;
    this.#capabilityReader =
      deps.capabilityReader ?? ((signal) => readCommerceGrantsCapability(signal));
    this.#onState = deps.onState;
  }

  get state(): GrantControllerState {
    return this.#state;
  }

  get disposed(): boolean {
    return this.#disposed;
  }

  /** Points the controller at a parsed route without issuing any request. */
  setRoute(route: GrantRoute): void {
    if (this.#disposed) return;
    this.#update({ selection: { route } });
  }

  /** Records an explicit lookup id without any request. */
  selectLookupGrantId(grantId: string | null): void {
    if (this.#disposed) return;
    this.#update({ lookupGrantId: grantId });
  }

  /**
   * Independent capability gate. It runs BEFORE any grant request and never
   * depends on tenant-writes, machine, listing, policy, Vault or wallet flags.
   * On a known grant route with the flag on but the capability not `enabled`,
   * state is `unavailable` and NO grant request is ever made.
   */
  async initialize(route: GrantRoute): Promise<void> {
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
      let state: GrantCapabilityState;
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
      this.#update({ revoke: { kind: "rejected", notice: { kind: "no-access" } } });
      return;
    }
    if (route.kind === "detail") {
      await this.loadGrantDetail(route.grantId);
      return;
    }
    // The lookup route has nothing to read: there is no grant list endpoint and
    // this console will not invent one. It makes no request at all.
  }

  async loadGrantDetail(grantId: string): Promise<void> {
    if (this.#disposed || !this.#accessAllowed()) return;
    const organizationId = this.#currentOrganizationId();
    if (organizationId === null) return;
    if (!CommerceGrantIdSchema.safeParse(grantId).success) {
      this.#update({ detail: { status: "error", item: null } });
      return;
    }
    const generation = this.#generation;
    this.#detailAbort?.abort();
    const controller = new AbortController();
    this.#detailAbort = controller;
    this.#update({ detail: { status: "loading", item: null } });
    try {
      const detail = await this.#client.readGrant(
        { organizationId, grantId },
        controller.signal,
      );
      if (!this.#stillCurrent(generation) || this.#currentOrganizationId() !== organizationId) {
        return;
      }
      if (detail.item === null) {
        this.#update({ detail: { status: "not-found", item: null } });
        return;
      }
      const parsed = CommerceGrantMetadataSchema.safeParse(detail.item);
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

  /**
   * Begins an explicit revoke confirmation. No request, no mutation id and no
   * idempotency key is created here: the user must confirm first.
   */
  beginRevoke(grantId: string): boolean {
    if (this.#disposed) return false;
    if (this.#state.capability !== "enabled") {
      this.#update({ revoke: { kind: "rejected", notice: { kind: "capability-disabled" } } });
      return false;
    }
    if (!this.#canRevoke()) {
      this.#update({ revoke: { kind: "rejected", notice: { kind: "no-access" } } });
      return false;
    }
    if (!CommerceGrantIdSchema.safeParse(grantId).success) {
      this.#update({ revoke: { kind: "rejected", notice: { kind: "validation" } } });
      return false;
    }
    this.#generation += 1;
    this.#update({ revoke: { kind: "confirming", draft: { grantId } } });
    return true;
  }

  cancelRevoke(): void {
    if (this.#disposed) return;
    if (this.#state.revoke.kind === "pending") return;
    this.#generation += 1;
    this.#update({ revoke: { kind: "idle" } });
  }

  /**
   * Sends exactly ONE confirmed logical revoke with a frozen id/key/body. There
   * is no automatic retry and no new key on failure.
   */
  async confirmRevoke(): Promise<void> {
    if (this.#disposed) return;
    if (this.#state.revoke.kind !== "confirming") return;
    const draft = this.#state.revoke.draft;
    const organizationId = this.#currentOrganizationId();
    if (organizationId === null) return;
    const mutationId = createGrantMutationId();
    const idempotencyKey = createGrantIdempotencyKey();
    if (
      !CommerceTenantMutationIdSchema.safeParse(mutationId).success ||
      !CommerceTenantIdempotencyKeySchema.safeParse(idempotencyKey).success
    ) {
      this.#update({ revoke: { kind: "rejected", notice: { kind: "validation" } } });
      return;
    }
    const generation = this.#generation;
    const frozen: FrozenRevoke = {
      grantId: draft.grantId,
      mutationId,
      idempotencyKey,
      organizationId,
    };
    this.#update({ revoke: { kind: "pending", draft, mutationId } });
    this.#reads.abortPendingReads();
    const accountBound: AccountBoundToken = this.#account.captureAccountBound();
    try {
      const result = await this.#account.mutate(
        async ({ csrfToken, signal }) => {
          const data = await this.#client.revoke({
            organizationId: frozen.organizationId,
            grantId: frozen.grantId,
            csrfToken,
            idempotencyKey: frozen.idempotencyKey,
            signal,
            body: { mutationId: frozen.mutationId },
          });
          const parsed = CommerceGrantMetadataSchema.safeParse(data.metadata);
          if (!parsed.success) throw new GrantApiError({ kind: "invalid-response" });
          return {
            receipt: data.receipt,
            metadata: parsed.data,
            released: data.released,
            actionStatus: data.actionStatus,
            replayed: data.replayed,
          };
        },
        { accountBound },
      );
      if (!this.#stillCurrent(generation)) return;
      await this.#afterCommit(result, generation);
    } catch (error) {
      if (!this.#stillCurrent(generation)) return;
      this.#handleFailure(error, frozen);
    }
  }

  async #afterCommit(
    result: {
      receipt: CommerceGrantRevokeReceipt;
      metadata: CommerceGrantMetadata;
      released: boolean;
      actionStatus: CommerceActionStatus;
      replayed: boolean;
    },
    generation: number,
  ): Promise<void> {
    // The committed receipt is recorded FIRST and stands even if the follow-up
    // refresh fails. A failed read never demotes a committed revoke.
    this.#update({
      revoke: {
        kind: "committed",
        committed: {
          receipt: result.receipt,
          metadata: result.metadata,
          released: result.released,
          actionStatus: result.actionStatus,
          replayed: result.replayed,
          refreshError: false,
        },
      },
    });
    await this.loadGrantDetail(result.receipt.resourceId);
    if (!this.#stillCurrent(generation)) return;
    if (this.#state.revoke.kind !== "committed") return;
    if (this.#state.detail.status === "error") {
      this.#update({
        revoke: {
          kind: "committed",
          committed: { ...this.#state.revoke.committed, refreshError: true },
        },
      });
    }
  }

  #handleFailure(error: unknown, frozen: FrozenRevoke): void {
    const failure = failureOf(error);
    switch (failure.kind) {
      case "unauthenticated":
        this.#update({ revoke: { kind: "rejected", notice: { kind: "unauthenticated" } } });
        return;
      case "csrf":
        this.#update({ revoke: { kind: "rejected", notice: { kind: "csrf" } } });
        return;
      case "forbidden":
        // The server is authoritative. A denial disables the local revoke
        // controls instead of letting the local role guess stand.
        this.#update({
          serverDeniedRevoke: true,
          revoke: { kind: "rejected", notice: { kind: "forbidden" } },
        });
        return;
      case "validation":
        this.#update({ revoke: { kind: "rejected", notice: { kind: "validation" } } });
        return;
      case "policy":
        this.#update({ revoke: { kind: "rejected", notice: { kind: "policy" } } });
        return;
      case "conflict":
        this.#update({ revoke: { kind: "rejected", notice: { kind: "conflict" } } });
        return;
      case "not-found":
        this.#update({ revoke: { kind: "rejected", notice: { kind: "not-found" } } });
        return;
      case "account-changed":
        this.#update({ revoke: { kind: "rejected", notice: { kind: "account-changed" } } });
        return;
      case "feature-disabled":
        this.#update({ revoke: { kind: "rejected", notice: { kind: "capability-disabled" } } });
        return;
      case "aborted":
        this.#update({ revoke: { kind: "idle" } });
        return;
      case "pre-send":
        this.#update({ revoke: { kind: "rejected", notice: { kind: "validation" } } });
        return;
      default: {
        // Sent-but-unconfirmed: keep the frozen id and offer ONLY an explicit
        // status GET with the original id. Never resend, never mint a new key
        // and never present the outcome as success, failure, refund or release.
        this.#update({
          revoke: {
            kind: "outcome-unknown",
            mutationId: frozen.mutationId,
            organizationId: frozen.organizationId,
            grantId: frozen.grantId,
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
   * It NEVER resubmits the revoke, never mints a new id or key, and a
   * `not_found` result stays unknown rather than becoming a failure.
   *
   * A recovered committed receipt carries NO release flag and NO action status,
   * so both are recorded as null and render as genuinely unknown.
   */
  async checkRevokeStatus(): Promise<void> {
    if (this.#disposed || this.#state.revoke.kind !== "outcome-unknown") return;
    const current = this.#state.revoke;
    const generation = this.#generation;
    this.#statusAbort?.abort();
    const controller = new AbortController();
    this.#statusAbort = controller;
    this.#update({ revoke: { ...current, checking: true, statusMessage: null } });
    let status;
    try {
      status = await this.#client.readMutationStatus({
        organizationId: current.organizationId,
        mutationId: current.mutationId,
        expectedResourceId: current.grantId,
        signal: controller.signal,
      });
    } catch {
      if (!this.#stillCurrent(generation) || this.#state.revoke.kind !== "outcome-unknown") {
        return;
      }
      this.#update({
        revoke: { ...current, checking: false, statusMessage: UNKNOWN_GRANT_STATUS_MESSAGE },
      });
      return;
    }
    if (!this.#stillCurrent(generation) || this.#state.revoke.kind !== "outcome-unknown") return;
    if (status.status === "committed") {
      this.#update({
        revoke: {
          kind: "committed",
          committed: {
            receipt: status.receipt,
            metadata: null,
            released: null,
            actionStatus: null,
            replayed: true,
            refreshError: false,
          },
        },
      });
      await this.loadGrantDetail(status.receipt.resourceId);
      return;
    }
    // `not_found` is NOT a failure and NOT a release: the revoke may still
    // commit. It never enables a resend and never mints a new id or key.
    this.#update({
      revoke: { ...current, checking: false, statusMessage: UNKNOWN_GRANT_STATUS_MESSAGE },
    });
  }

  /**
   * Synchronously clears every detail, lookup and revoke artifact. Used for
   * account/organization/role/route/privacy-generation changes, hidden/pagehide
   * and logout. It never preserves a key that could be resubmitted.
   */
  clear(): void {
    if (this.#disposed) return;
    this.#generation += 1;
    this.#abortAll();
    this.#update({
      role: this.#currentRole(),
      canRead: this.#accessAllowed(),
      canRevoke: this.#canRevoke(),
      serverDeniedRevoke: false,
      lookupGrantId: null,
      detail: initialGrantDetailState(),
      revoke: { kind: "idle" },
    });
  }

  /** Role reconciliation: a role change clears every local artifact. */
  reconcileRole(role: string | null): void {
    if (this.#disposed) return;
    if (this.#state.role === role && this.#state.canRead === this.#accessAllowed()) {
      this.#update({ canRevoke: this.#canRevoke() });
      return;
    }
    this.clear();
  }

  dispose(): void {
    if (this.#disposed) return;
    this.#generation += 1;
    this.#abortAll();
    this.#disposed = true;
    this.#state = { ...initialGrantControllerState(), role: this.#currentRole() };
    this.#onState?.(this.#state);
  }

  #abortAll(): void {
    this.#detailAbort?.abort();
    this.#detailAbort = null;
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
    return canReadGrants(this.#currentRole());
  }

  #canRevoke(): boolean {
    if (this.#state.serverDeniedRevoke) return false;
    return this.#accessAllowed() && canRevokeGrants(this.#currentRole());
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

  #update(patch: Partial<GrantControllerState>): void {
    if (this.#disposed) return;
    this.#state = { ...this.#state, ...patch };
    this.#state = {
      ...this.#state,
      role: this.#currentRole(),
      canRead: this.#accessAllowed(),
      canRevoke: this.#canRevoke(),
    };
    this.#onState?.(this.#state);
  }
}

function failureOf(error: unknown): { kind: GrantApiFailure["kind"] | "account-changed" } {
  if (error instanceof GrantApiError) return { kind: error.failure.kind };
  if (typeof error === "object" && error !== null) {
    const failure = (error as { failure?: { kind?: unknown } }).failure;
    if (typeof failure === "object" && failure !== null) {
      const kind = (failure as { kind?: unknown }).kind;
      if (kind === "account-changed") return { kind: "account-changed" };
      if (typeof kind === "string") return { kind: kind as GrantApiFailure["kind"] };
    }
  }
  return { kind: "outcome-unknown" };
}

/**
 * Synchronous render-boundary guard for the grant surface. React effects run
 * AFTER render, so an account/organization/role transition would otherwise
 * paint one frame of the previous context's grant detail or revoke state. The
 * parent suppresses (by substituting the initial state) when it does not match
 * the current context.
 */
export interface GrantRenderContext {
  readonly accountId: string | null;
  readonly organizationId: string | null;
  readonly role: string | null;
}

export function suppressStaleGrantContext(
  bound: GrantRenderContext | null,
  current: GrantRenderContext,
): boolean {
  if (bound === null) return false;
  if (current.accountId === null || current.organizationId === null) return true;
  return (
    bound.accountId !== current.accountId ||
    bound.organizationId !== current.organizationId ||
    bound.role !== current.role
  );
}

export function renderGrantState(
  suppress: boolean,
  state: GrantControllerState,
  initial: () => GrantControllerState = initialGrantControllerState,
): GrantControllerState {
  return suppress ? initial() : state;
}

/**
 * The single sentence describing what a revoke state currently means. An
 * unknown outcome is always described as unknown; it is never presented as
 * success, failure, refund, release, payment or settlement.
 */
export function revokeOutcomeLabel(revoke: GrantRevokeState): string {
  switch (revoke.kind) {
    case "idle":
      return "No revoke in progress.";
    case "confirming":
      return "Waiting for your explicit confirmation. Nothing has been sent.";
    case "pending":
      return "One revoke request is in flight. Do not resubmit.";
    case "committed":
      return revoke.committed.replayed
        ? "The server reports this grant was already revoked."
        : "The server revoked this grant.";
    case "rejected":
      return "The revoke was refused before it could commit.";
    case "outcome-unknown":
      return "The outcome is unknown. It is not a success, not a failure, not a refund and not a release.";
  }
}

/**
 * What the committed revoke says about the held amount. A claimed grant keeps
 * its exposure and may still have been paid; an unreported flag is unknown.
 */
export function revokeReleaseNotice(committed: GrantCommittedState): string {
  if (committed.metadata !== null && committed.metadata.claimedAt !== null) {
    return GRANT_CLAIMED_THEN_REVOKED_NOTICE;
  }
  if (committed.released === null) return GRANT_RELEASE_UNKNOWN_NOTICE;
  if (committed.released) return GRANT_RELEASED_REVOKE_NOTICE;
  return "The server did not release this grant's held amount. Nothing was refunded and nothing was returned; the hold stands as the server reports it.";
}

export function revokeRejectionMessage(notice: GrantFailureNotice): string {
  switch (notice.kind) {
    case "validation":
      return "The request was refused as invalid before it could commit. Nothing changed.";
    case "policy":
      return "A policy rule refused this revoke. Nothing changed, nothing was paid and nothing was refunded.";
    case "conflict":
      return "The server reported a conflicting state for this grant. Nothing was resent. Refresh the grant and look again.";
    case "unauthenticated":
      return "Your session is no longer signed in, so the revoke was not sent. Sign in again.";
    case "csrf":
      return "The request was refused for a security check. Reload the page and revoke again.";
    case "forbidden":
      return "The server refused this revoke for your account. The server is the authority here, not this page.";
    case "not-found":
      return "The server does not have this grant. Nothing changed.";
    case "account-changed":
      return "The signed-in account changed, so the revoke was abandoned before it was sent.";
    case "capability-disabled":
      return "Authorization grants are not enabled in this deployment, so no revoke was sent.";
    case "no-access":
      return "Your role cannot revoke authorization grants. No request was made.";
  }
}

export type { CommerceGrantMetadata };
