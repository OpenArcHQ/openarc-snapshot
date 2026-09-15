import type {
  CommerceGrantAgentMutationStatus,
  CommerceGrantDetail,
  CommerceGrantHumanMutationStatus,
  CommerceGrantIssueData,
  CommerceGrantMetadata,
  CommerceGrantProviderAttemptStatusData,
  CommerceGrantProviderClaimData,
  CommerceGrantProviderIntrospection,
  CommerceGrantProviderView,
  CommerceGrantReplaceData,
  CommerceGrantRevokeData,
} from "@openarc/shared";

import type { TenantWriteAuthPort } from "../tenant/write-ports.js";

/**
 * Structural dependency seams for the authorization-grant HTTP slice.
 *
 * The store port exposes EXACTLY the nine authorization-grant operations the
 * frozen route registry needs and nothing else. It cannot reach a raw pool,
 * client, SQL string, generic callback, migration or non-grant operation. The
 * concrete runtime implementation is the reviewed DB12 `ControlGrantStore`,
 * which is authored independently and is deliberately NOT imported here: this
 * module must stay compilable and testable without it, and unit tests inject
 * honest fakes.
 *
 * Every store payload crosses this seam as `unknown`. The service re-validates
 * each one against the accepted shared grant wire schemas before it is
 * projected, so a drifting or hostile store result can never reach a caller
 * unchecked, and a concrete store with narrower return types stays structurally
 * assignable.
 *
 * SECRET DISCIPLINE. No raw secret is representable on this seam. The two
 * provider inputs and the two agent mint paths carry ONLY the one-way 64-hex
 * `grantTokenHash`; the raw `oag_v1_` token, the `oacs_v1_` commerce bearer,
 * the `oas_pr_` provider bearer, the browser cookie and the CSRF value never
 * cross it, are never logged and are never echoed. The single raw token this
 * surface ever emits is minted by the service, handed to the caller once after
 * commit, and never reconstructed from anything the store returns.
 *
 * Human auth is EXACTLY the accepted tenant write auth port: CSRF verification
 * for writes plus the internal read-session begin/finish guards. This module
 * introduces no new auth method and never mints, rotates or clears a cookie.
 */

/** Canonical durable mutation metadata for the four grant mutations. */
export interface CommerceGrantMutationMetadata {
  readonly idempotencyKey: string;
  readonly mutationId: string;
}

/**
 * Agent issue input. The operation, the organization, the agent, the policy and
 * the buyer session are all derived from the presented `oacs_v1_` commerce
 * session, so none of them is representable here. `grantTokenHash` is the
 * one-way digest of a secret the SERVICE minted; the raw value never appears.
 */
export interface CommerceGrantIssueInput {
  readonly actionId: string;
  readonly grantTokenHash: string;
}

/** Agent replace input. The grant id is path derived, never body supplied. */
export interface CommerceGrantReplaceInput {
  readonly grantId: string;
  readonly grantTokenHash: string;
}

/**
 * Provider claim input. The provider states the action it believes it is
 * claiming and supplies its OWN attempt id, which is later the only recovery
 * key. The buyer's one-use token reaches the store only as a digest.
 */
export interface CommerceGrantClaimInput {
  readonly grantTokenHash: string;
  readonly expectedActionId: string;
  readonly attemptId: string;
}

/** Issue/replace envelope before validation. */
export interface CommerceGrantMutationDbResult {
  readonly replayed: unknown;
  readonly metadata: unknown;
  readonly receipt: unknown;
}

/**
 * Revoke envelope before validation.
 *
 * `reservationStatus` is present because the accepted store returns it, and the
 * service deliberately DROPS it: no accepted shared reservation-status
 * vocabulary exists and the transport must not invent one.
 */
export interface CommerceGrantRevokeDbResult {
  readonly replayed: unknown;
  readonly metadata: unknown;
  readonly receipt: unknown;
  readonly released: unknown;
  readonly actionStatus: unknown;
  readonly reservationStatus: unknown;
}

/** Provider claim envelope before validation. */
export interface CommerceGrantClaimDbResult {
  readonly replayed: unknown;
  readonly item: unknown;
  readonly attemptId: unknown;
  readonly claimedAt: unknown;
  readonly claimDigest: unknown;
  readonly receipt: unknown;
}

/** Provider introspection envelope before validation. */
export interface CommerceGrantIntrospectionDbResult {
  readonly item: unknown;
}

/** Provider attempt-status recovery envelope before validation. */
export interface CommerceGrantAttemptStatusDbResult {
  readonly attemptId: unknown;
  readonly item: unknown;
}

/** Buyer grant detail envelope before validation. */
export interface CommerceGrantDetailDbResult {
  readonly organizationId: unknown;
  readonly grantId: unknown;
  readonly item: unknown;
}

/** `{status:'not_found'}` or `{status:'committed', receipt}` before validation. */
export interface CommerceGrantMutationDbStatus {
  readonly status: unknown;
  readonly receipt?: unknown;
}

/**
 * The exact nine authorization-grant store operations, one per frozen route.
 *
 * Agent operations are scoped by the hashed `oacs_v1_` commerce bearer alone;
 * provider operations by the hashed `oas_pr_` provider session PLUS the hashed
 * one-use grant token (introspect/claim) or the provider's own attempt id
 * (recovery); human operations by the internal browser session hash plus the
 * organization. A caller can therefore never widen its own scope through a
 * parameter.
 *
 * No payment, settlement, delivery, refund or release operation exists on this
 * seam, and the store exposes no grant list or page method, so none is declared.
 */
export interface CommerceGrantStorePort {
  /* -- commerce_grant_authorization (agent) ---------------------------- */

  issueCommerceGrant(
    commerceSessionHash: unknown,
    input: CommerceGrantIssueInput,
    metadata: CommerceGrantMutationMetadata,
  ): Promise<CommerceGrantMutationDbResult>;
  replaceCommerceGrant(
    commerceSessionHash: unknown,
    input: CommerceGrantReplaceInput,
    metadata: CommerceGrantMutationMetadata,
  ): Promise<CommerceGrantMutationDbResult>;
  getAgentCommerceGrantMutationStatus(
    commerceSessionHash: unknown,
    mutationId: unknown,
  ): Promise<CommerceGrantMutationDbStatus>;

  /* -- commerce_grant_claim (provider) --------------------------------- */

  /** Strictly read-only: it consumes nothing and mutates no row. */
  introspectCommerceGrant(
    providerSessionHash: unknown,
    grantTokenHash: unknown,
  ): Promise<CommerceGrantIntrospectionDbResult>;
  claimCommerceGrant(
    providerSessionHash: unknown,
    input: CommerceGrantClaimInput,
    metadata: CommerceGrantMutationMetadata,
  ): Promise<CommerceGrantClaimDbResult>;
  getProviderCommerceGrantAttemptStatus(
    providerSessionHash: unknown,
    attemptId: unknown,
  ): Promise<CommerceGrantAttemptStatusDbResult>;

  /* -- commerce_grant_management (browser) ----------------------------- */

  getCommerceGrant(
    humanSessionHash: unknown,
    organizationId: unknown,
    grantId: unknown,
  ): Promise<CommerceGrantDetailDbResult>;
  getHumanCommerceGrantMutationStatus(
    humanSessionHash: unknown,
    organizationId: unknown,
    mutationId: unknown,
  ): Promise<CommerceGrantMutationDbStatus>;
  revokeCommerceGrant(
    humanSessionHash: unknown,
    organizationId: unknown,
    grantId: unknown,
    metadata: CommerceGrantMutationMetadata,
  ): Promise<CommerceGrantRevokeDbResult>;
}

/**
 * Narrow read that resolves the CURRENT commerce session behind a presented
 * `oacs_v1_` bearer. Only this read is reachable: no issuance, exchange,
 * revoke, KDF, verifier or pool access is exposed. Structurally identical to
 * the commerce-action slice's own read seam, declared separately so this slice
 * compiles and tests without importing the action family.
 */
export interface CommerceGrantSessionReadPort {
  getCommerceSessionByHash(tokenHash: unknown): Promise<unknown>;
}

/**
 * Auth seam for the browser grant-management family. EXACTLY the accepted
 * tenant write auth port; the service introduces no new auth method.
 */
export type CommerceGrantAuthPort = TenantWriteAuthPort;

/**
 * Narrow bound interface over the accepted durable `AuthStore.consumeRateLimit`
 * fixed-window increment. Only `consume` is reachable; no pool, full store or
 * counter-read is exposed.
 */
export interface CommerceGrantRateLimitStorePort {
  consume(input: {
    keyHash: string;
    limit: number;
    windowSeconds: number;
  }): Promise<{ allowed: boolean }>;
}

/** Validated wire results returned by the authorization-grant service. */
export type {
  CommerceGrantAgentMutationStatus,
  CommerceGrantDetail,
  CommerceGrantHumanMutationStatus,
  CommerceGrantIssueData,
  CommerceGrantMetadata,
  CommerceGrantProviderAttemptStatusData,
  CommerceGrantProviderClaimData,
  CommerceGrantProviderIntrospection,
  CommerceGrantProviderView,
  CommerceGrantReplaceData,
  CommerceGrantRevokeData,
};
