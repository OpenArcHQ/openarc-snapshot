import type {
  CommerceControlSessionMetadata,
  CommerceControlSessionReceipt,
  CommerceControlSessionStatusItem,
} from "@openarc/shared";
import type {
  CommerceSessionIssueDbResult,
  CommerceSessionMutationDbResult,
  CommerceSessionMutationStatus,
  CommerceSessionStatusResult,
  ExchangeCommerceSessionInput,
  IssueCommerceSessionInput,
  ListCommerceSessionsInput,
  ListCommerceSessionsResult,
  MachineSessionMetadata,
} from "@openarc/db";

import type { TenantWriteAuthPort } from "../tenant/write-ports.js";

/**
 * Structural dependency seams for the commerce-session HTTP slice.
 *
 * The store port exposes ONLY the seven exact accepted `CommerceSessionStore`
 * operations with their frozen signatures. It cannot reach a raw pool, client,
 * SQL string, generic callback or non-session operation. The concrete runtime
 * implementation is the reviewed `@openarc/db` `CommerceSessionStore`; unit
 * tests inject an honest fake. The concrete `CredentialStore` supplies ONLY the
 * current-agent session read for the trusted-org projection.
 *
 * Human auth is EXACTLY the accepted tenant write auth port: CSRF verification
 * for writes plus the internal read-session begin/finish guards. This module
 * introduces no new auth method and never mints, rotates or clears a cookie.
 *
 * Metadata is the canonical `{mutationId, idempotencyKey}` pair. The raw
 * idempotency key, handoff/session tokens and presented bearer are never
 * logged, stored or echoed by this module.
 */

export interface CommerceSessionMutationMetadata {
  readonly idempotencyKey: string;
  readonly mutationId: string;
}

/** The exact accepted concrete `CommerceSessionStore` operations. */
export interface CommerceSessionStorePort {
  issueCommerceSession(
    humanSessionHash: unknown,
    organizationId: unknown,
    input: IssueCommerceSessionInput,
    metadata: unknown,
  ): Promise<CommerceSessionIssueDbResult>;
  exchangeCommerceSession(
    agentSessionHash: unknown,
    handoffHash: unknown,
    input: ExchangeCommerceSessionInput,
    metadata: unknown,
  ): Promise<CommerceSessionMutationDbResult>;
  revokeCommerceSession(
    humanSessionHash: unknown,
    organizationId: unknown,
    sessionId: unknown,
    metadata: unknown,
  ): Promise<CommerceSessionMutationDbResult>;
  getCommerceSessionStatus(
    humanSessionHash: unknown,
    organizationId: unknown,
    sessionId: unknown,
  ): Promise<CommerceSessionStatusResult>;
  listCommerceSessions(
    humanSessionHash: unknown,
    organizationId: unknown,
    options?: ListCommerceSessionsInput,
  ): Promise<ListCommerceSessionsResult>;
  getHumanCommerceSessionMutationStatus(
    humanSessionHash: unknown,
    organizationId: unknown,
    mutationId: unknown,
  ): Promise<CommerceSessionMutationStatus>;
  getAgentCommerceSessionMutationStatus(
    agentSessionHash: unknown,
    mutationId: unknown,
  ): Promise<CommerceSessionMutationStatus>;
}

/**
 * Narrow read over the accepted `CredentialStore.getAgentSession`. Only the
 * current agent-session read is reachable; no KDF, verifier, issuance, revoke
 * or pool access is exposed.
 */
export interface AgentSessionReadPort {
  getAgentSession(tokenHash: unknown): Promise<MachineSessionMetadata>;
}

/**
 * Auth seam for the protected session family. EXACTLY the accepted tenant write
 * auth port; the service introduces no new auth method.
 */
export type CommerceSessionAuthPort = TenantWriteAuthPort;

/**
 * Narrow bound interface over the accepted durable `AuthStore.consumeRateLimit`
 * fixed-window increment. Only `consume` is reachable; no pool, full store or
 * counter-read is exposed.
 */
export interface CommerceSessionRateLimitStorePort {
  consume(input: {
    keyHash: string;
    limit: number;
    windowSeconds: number;
  }): Promise<{ allowed: boolean }>;
}

/** Validated wire results returned by the session services. */
export type {
  CommerceSessionIssueDbResult,
  CommerceSessionMutationDbResult,
  CommerceSessionMutationStatus,
  CommerceSessionStatusResult,
  CommerceControlSessionMetadata,
  CommerceControlSessionReceipt,
  CommerceControlSessionStatusItem,
  MachineSessionMetadata,
};
