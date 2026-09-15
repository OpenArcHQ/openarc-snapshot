import type {
  CommerceActionDetail,
  CommerceActionMetadata,
  CommerceActionMutationData,
  CommerceActionMutationReceipt,
  CommerceActionMutationStatus,
  CommerceActionPage,
  CommerceApprovalDetail,
  CommerceApprovalMetadata,
  CommerceApprovalPage,
  CommerceExposureData,
  CommerceExposureView,
} from "@openarc/shared";

import type { TenantWriteAuthPort } from "../tenant/write-ports.js";

/**
 * Structural dependency seams for the commerce-action HTTP slice.
 *
 * The store port exposes EXACTLY the twelve commerce-action operations the
 * frozen route registry needs and nothing else. It cannot reach a raw pool,
 * client, SQL string, generic callback, migration or non-action operation. The
 * concrete runtime implementation will be the reviewed DB10/DB11
 * commerce-action store, which is authored independently and is deliberately
 * NOT imported here: this module must stay compilable and testable without it,
 * and unit tests inject honest fakes.
 *
 * Every store payload crosses this seam as `unknown`. The service re-validates
 * each one against the accepted shared wire schemas before it is projected, so
 * a drifting or hostile store result can never reach a caller unchecked, and a
 * concrete store with narrower return types stays structurally assignable.
 *
 * Human auth is EXACTLY the accepted tenant write auth port: CSRF verification
 * for writes plus the internal read-session begin/finish guards. This module
 * introduces no new auth method and never mints, rotates or clears a cookie.
 *
 * Metadata is the canonical `{mutationId, idempotencyKey}` pair. The raw
 * idempotency key, the presented commerce-session bearer, cookie values and
 * CSRF tokens are never logged, stored or echoed by this module.
 */

/** Canonical durable mutation metadata for the four action mutations. */
export interface CommerceActionMutationMetadata {
  readonly idempotencyKey: string;
  readonly mutationId: string;
}

/** Agent authorize input. The operation itself is endpoint-derived. */
export interface CommerceActionAuthorizeInput {
  readonly actionId: string;
  readonly requirementId: string;
}

/** Bounded list options. `limit` is an exact integer, never a coerced string. */
export interface CommerceActionListOptions {
  readonly afterActionId?: string;
  readonly limit?: number;
}

export interface CommerceApprovalListOptions {
  readonly afterApprovalId?: string;
  readonly limit?: number;
}

/**
 * Mutation envelope returned by the four action mutations. Payload leaves are
 * `unknown` because the service validates them against the accepted wire
 * schemas; a concrete store returning the exact DTOs remains assignable.
 */
export interface CommerceActionMutationDbResult {
  readonly replayed: unknown;
  readonly metadata: unknown;
  readonly receipt: unknown;
}

/** `{status:'not_found'}` or `{status:'committed', receipt}` before validation. */
export interface CommerceActionMutationDbStatus {
  readonly status: unknown;
  readonly receipt?: unknown;
}

export interface CommerceActionDetailDbResult {
  readonly organizationId: unknown;
  readonly item: unknown;
}

export interface CommerceApprovalDetailDbResult {
  readonly organizationId: unknown;
  readonly item: unknown;
}

export interface CommerceActionPageDbResult {
  readonly items: unknown;
  readonly nextCursor: unknown;
}

export interface CommerceApprovalPageDbResult {
  readonly items: unknown;
  readonly nextCursor: unknown;
}

export interface CommerceExposureDbResult {
  readonly organizationId: unknown;
  readonly subjectAgentId: unknown;
  readonly policyId: unknown;
  readonly item: unknown;
}

/**
 * The exact twelve commerce-action store operations.
 *
 * Human operations are scoped by the internal human session hash plus the
 * organization; agent operations are scoped by the hashed commerce-session
 * bearer alone, so the store derives the tenant itself and a caller can never
 * widen its own scope through a parameter.
 *
 * Nine DB10 authority operations (four mutations plus five scoped reads) and
 * three DB11 list/detail reads. No provider call, payment, settlement,
 * delivery, grant issuance or refund/release operation exists on this seam.
 */
export interface CommerceActionStorePort {
  /* -- DB10 mutations ------------------------------------------------- */

  /**
   * Agent authorization of an existing action requirement. Authorizing is NOT
   * a payment, settlement or delivery; it records a bounded control decision.
   */
  authorizeCommerceAction(
    commerceSessionHash: unknown,
    input: CommerceActionAuthorizeInput,
    metadata: CommerceActionMutationMetadata,
  ): Promise<CommerceActionMutationDbResult>;
  approveCommerceAction(
    humanSessionHash: unknown,
    organizationId: unknown,
    actionId: unknown,
    metadata: CommerceActionMutationMetadata,
  ): Promise<CommerceActionMutationDbResult>;
  rejectCommerceAction(
    humanSessionHash: unknown,
    organizationId: unknown,
    actionId: unknown,
    metadata: CommerceActionMutationMetadata,
  ): Promise<CommerceActionMutationDbResult>;
  cancelCommerceAction(
    humanSessionHash: unknown,
    organizationId: unknown,
    actionId: unknown,
    metadata: CommerceActionMutationMetadata,
  ): Promise<CommerceActionMutationDbResult>;

  /* -- DB10 scoped status and detail reads ----------------------------- */

  getHumanCommerceActionMutationStatus(
    humanSessionHash: unknown,
    organizationId: unknown,
    mutationId: unknown,
  ): Promise<CommerceActionMutationDbStatus>;
  getAgentCommerceActionMutationStatus(
    commerceSessionHash: unknown,
    mutationId: unknown,
  ): Promise<CommerceActionMutationDbStatus>;
  getCommerceAction(
    humanSessionHash: unknown,
    organizationId: unknown,
    actionId: unknown,
  ): Promise<CommerceActionDetailDbResult>;
  getAgentCommerceAction(
    commerceSessionHash: unknown,
    actionId: unknown,
  ): Promise<CommerceActionDetailDbResult>;

  /**
   * Declared server exposure for one (organization, subject agent, policy).
   * This is a DB `asOf` declaration of recorded state, never a wallet balance,
   * a cap, a new permission or a liveness claim.
   */
  getCommerceExposure(
    humanSessionHash: unknown,
    organizationId: unknown,
    subjectAgentId: unknown,
    policyId: unknown,
  ): Promise<CommerceExposureDbResult>;

  /* -- DB11 list and detail reads -------------------------------------- */

  listCommerceActions(
    humanSessionHash: unknown,
    organizationId: unknown,
    options?: CommerceActionListOptions,
  ): Promise<CommerceActionPageDbResult>;
  listCommerceApprovals(
    humanSessionHash: unknown,
    organizationId: unknown,
    options?: CommerceApprovalListOptions,
  ): Promise<CommerceApprovalPageDbResult>;
  getCommerceApproval(
    humanSessionHash: unknown,
    organizationId: unknown,
    approvalId: unknown,
  ): Promise<CommerceApprovalDetailDbResult>;
}

/**
 * Narrow read that resolves the CURRENT commerce session behind a presented
 * bearer. Only this read is reachable: no issuance, exchange, revoke, KDF,
 * verifier or pool access is exposed. The returned value is validated against
 * the accepted `CommerceControlSessionMetadata` schema by the service before
 * any tenant is trusted.
 */
export interface CommerceSessionReadPort {
  getCommerceSessionByHash(tokenHash: unknown): Promise<unknown>;
}

/**
 * Auth seam for the browser action-management family. EXACTLY the accepted
 * tenant write auth port; the service introduces no new auth method.
 */
export type CommerceActionAuthPort = TenantWriteAuthPort;

/**
 * Narrow bound interface over the accepted durable `AuthStore.consumeRateLimit`
 * fixed-window increment. Only `consume` is reachable; no pool, full store or
 * counter-read is exposed.
 */
export interface CommerceActionRateLimitStorePort {
  consume(input: {
    keyHash: string;
    limit: number;
    windowSeconds: number;
  }): Promise<{ allowed: boolean }>;
}

/** Validated wire results returned by the commerce-action service. */
export type {
  CommerceActionDetail,
  CommerceActionMetadata,
  CommerceActionMutationData,
  CommerceActionMutationReceipt,
  CommerceActionMutationStatus,
  CommerceActionPage,
  CommerceApprovalDetail,
  CommerceApprovalMetadata,
  CommerceApprovalPage,
  CommerceExposureData,
  CommerceExposureView,
};
