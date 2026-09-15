import type { CommerceSessionStore, ControlGrantStore } from "@openarc/db";

import type {
  CommerceGrantAttemptStatusDbResult,
  CommerceGrantClaimDbResult,
  CommerceGrantClaimInput,
  CommerceGrantDetailDbResult,
  CommerceGrantIntrospectionDbResult,
  CommerceGrantIssueInput,
  CommerceGrantMutationDbResult,
  CommerceGrantMutationDbStatus,
  CommerceGrantMutationMetadata,
  CommerceGrantReplaceInput,
  CommerceGrantRevokeDbResult,
  CommerceGrantSessionReadPort,
  CommerceGrantStorePort,
} from "./grant-ports.js";

/**
 * Binds the authorization-grant service ports to the real DB12/DB14
 * `ControlGrantStore`.
 *
 * This adapter is deliberately thin and does exactly two things: it renames
 * methods and it reshapes four results into the wrapper shapes the port
 * declares. It performs NO authority, financial, transport or validation work
 * of its own — every authority decision stays in PostgreSQL and every output is
 * re-validated by the service against the accepted shared grant wire schemas.
 * It never widens a scope, never retries, never swallows an error, never logs
 * and never inspects a token or a digest beyond passing it straight through.
 *
 * ALL NINE port operations are bound to a real store call. The two grant
 * mutation-status reads used to have no DB backing at all — migration 0012
 * declared no such helper — so they reported the dependency UNAVAILABLE rather
 * than fake a `not_found`, which on a money-adjacent recovery read would be a
 * false negative telling a caller their mutation does not exist when it may
 * have committed. Migration 0014 adds the two SECURITY DEFINER readers and the
 * store exposes them, so nothing here reports a missing dependency any more.
 *
 * The store import is type-only and therefore erased; the concrete store is
 * injected, so the service remains testable with fakes.
 */
export function createCommerceGrantStoreAdapter(
  grants: ControlGrantStore,
): CommerceGrantStorePort {
  return {
    /* -- commerce_grant_authorization (agent) -------------------------- */

    issueCommerceGrant(
      commerceSessionHash: unknown,
      input: CommerceGrantIssueInput,
      metadata: CommerceGrantMutationMetadata,
    ): Promise<CommerceGrantMutationDbResult> {
      return grants.issueForReservedAction(commerceSessionHash, input, metadata);
    },
    replaceCommerceGrant(
      commerceSessionHash: unknown,
      input: CommerceGrantReplaceInput,
      metadata: CommerceGrantMutationMetadata,
    ): Promise<CommerceGrantMutationDbResult> {
      return grants.replaceUnclaimedGrant(commerceSessionHash, input, metadata);
    },

    /**
     * Agent lost-response recovery, served by DB14
     * `read_agent_grant_mutation_status` through the store.
     *
     * The store answers the closed committed-or-not-found shape and admits
     * ONLY the two agent operations, so no browser revoke and no provider claim
     * receipt can arrive on this lane. Nothing is reshaped here beyond widening
     * the closed union to the port's pre-validation envelope; the service
     * re-parses it against the accepted agent status schema.
     */
    getAgentCommerceGrantMutationStatus(
      commerceSessionHash: unknown,
      mutationId: unknown,
    ): Promise<CommerceGrantMutationDbStatus> {
      return grants.getAgentMutationStatus(commerceSessionHash, mutationId);
    },

    /* -- commerce_grant_claim (provider) ------------------------------- */

    async introspectCommerceGrant(
      providerSessionHash: unknown,
      grantTokenHash: unknown,
    ): Promise<CommerceGrantIntrospectionDbResult> {
      const item = await grants.introspectGrant(
        providerSessionHash,
        grantTokenHash,
      );
      return { item };
    },

    /**
     * DB12 names the provider projection `view`; the accepted wire shape names
     * it `item`. Only that rename happens here — no field is added, dropped or
     * reinterpreted, and the service re-validates the whole projection.
     */
    async claimCommerceGrant(
      providerSessionHash: unknown,
      input: CommerceGrantClaimInput,
      metadata: CommerceGrantMutationMetadata,
    ): Promise<CommerceGrantClaimDbResult> {
      const result = await grants.claimGrant(
        providerSessionHash,
        input,
        metadata,
      );
      return {
        replayed: result.replayed,
        item: result.view,
        attemptId: result.attemptId,
        claimedAt: result.claimedAt,
        claimDigest: result.claimDigest,
        receipt: result.receipt,
      };
    },

    /**
     * The store derives provider identity from the presented session and
     * answers a missing OR foreign attempt with the same `not_found`, so
     * echoing the requested attempt id alongside it discloses nothing the
     * caller did not already supply.
     */
    async getProviderCommerceGrantAttemptStatus(
      providerSessionHash: unknown,
      attemptId: unknown,
    ): Promise<CommerceGrantAttemptStatusDbResult> {
      const item = await grants.readProviderAttemptStatus(
        providerSessionHash,
        attemptId,
      );
      return { attemptId, item };
    },

    /* -- commerce_grant_management (browser) --------------------------- */

    /**
     * DB12's `readGrant` returns bare metadata or null, while the port carries
     * the organization and grant id alongside it. Echoing the requested pair is
     * safe here and ONLY here because the store validates the caller's current
     * authority against that exact organization and grant and throws otherwise —
     * the not-found path included — so a value is only ever echoed after
     * authority has already passed for it. The service still re-validates the
     * assembled shape against the accepted detail schema.
     */
    async getCommerceGrant(
      humanSessionHash: unknown,
      organizationId: unknown,
      grantId: unknown,
    ): Promise<CommerceGrantDetailDbResult> {
      const item = await grants.readGrant(
        humanSessionHash,
        organizationId,
        grantId,
      );
      return { organizationId, grantId, item };
    },

    /**
     * Buyer lost-response recovery, served by DB14
     * `read_human_grant_mutation_status` through the store. This is the read
     * the grant console depends on: it is the only safe way a buyer learns
     * whether a revoke whose response was lost actually committed. The store
     * admits ONLY `control.grant.revoke`, so a browser cookie can never be
     * handed an agent issue/replace or a provider claim receipt, and neither
     * the organization nor the mutation id is echoed onto the answer.
     */
    getHumanCommerceGrantMutationStatus(
      humanSessionHash: unknown,
      organizationId: unknown,
      mutationId: unknown,
    ): Promise<CommerceGrantMutationDbStatus> {
      return grants.getHumanMutationStatus(
        humanSessionHash,
        organizationId,
        mutationId,
      );
    },

    /**
     * DB12 returns `reservationStatus` alongside the revoke result. It crosses
     * this seam verbatim and the SERVICE drops it: no accepted shared
     * reservation-status vocabulary exists and the transport must not invent
     * one. This adapter neither interprets nor suppresses it.
     */
    async revokeCommerceGrant(
      humanSessionHash: unknown,
      organizationId: unknown,
      grantId: unknown,
      metadata: CommerceGrantMutationMetadata,
    ): Promise<CommerceGrantRevokeDbResult> {
      const result = await grants.revokeGrant(
        humanSessionHash,
        organizationId,
        grantId,
        metadata,
      );
      return {
        replayed: result.replayed,
        metadata: result.metadata,
        receipt: result.receipt,
        released: result.released,
        actionStatus: result.actionStatus,
        reservationStatus: result.reservationStatus,
      };
    },
  };
}

/**
 * Binds the commerce-session read port to the real DB9/DB13 session store.
 *
 * The agent lane authenticates a commerce-session BEARER, so the service needs
 * exactly one read: presented token hash -> safe session metadata. This adapter
 * is a pure rename onto `CommerceSessionStore.getCommerceSessionByHash` and
 * nothing else. It does not inspect, normalize, log or store the presented
 * hash, does not widen the port beyond that single method, never swallows or
 * relabels a store error (the service's own commerce-session error vocabulary
 * depends on the raw code reaching it), and never substitutes a null for a
 * failure. The service re-parses whatever comes back against the accepted
 * shared metadata schema and is the only place that judges revocation or expiry.
 */
export function createCommerceGrantSessionReadAdapter(
  sessions: CommerceSessionStore,
): CommerceGrantSessionReadPort {
  return {
    getCommerceSessionByHash(tokenHash: unknown): Promise<unknown> {
      return sessions.getCommerceSessionByHash(tokenHash);
    },
  };
}
