import {
  CommerceControlSessionMetadataSchema,
  CommerceGrantAgentMutationRequestSchema,
  CommerceGrantAgentMutationStatusSchema,
  CommerceGrantDetailRequestSchema,
  CommerceGrantDetailSchema,
  CommerceGrantHumanMutationRequestSchema,
  CommerceGrantHumanMutationStatusSchema,
  CommerceGrantIdSchema,
  CommerceGrantIssueBodySchema,
  CommerceGrantIssueDataSchema,
  CommerceGrantMetadataSchema,
  CommerceGrantMutationReceiptSchema,
  CommerceGrantProviderAttemptStatusDataSchema,
  CommerceGrantProviderAttemptStatusRequestSchema,
  CommerceGrantProviderClaimBodySchema,
  CommerceGrantProviderClaimDataSchema,
  CommerceGrantProviderIntrospectBodySchema,
  CommerceGrantProviderIntrospectionSchema,
  CommerceGrantReplaceBodySchema,
  CommerceGrantReplaceDataSchema,
  CommerceGrantRevokeBodySchema,
  CommerceGrantRevokeDataSchema,
  CommerceOrganizationIdSchema,
  CommerceTenantIdempotencyKeySchema,
  type CommerceGrantAgentMutationStatus,
  type CommerceGrantDetail,
  type CommerceGrantHumanMutationStatus,
  type CommerceGrantIssueData,
  type CommerceGrantMetadata,
  type CommerceGrantMutationReceipt,
  type CommerceGrantProviderAttemptStatusData,
  type CommerceGrantProviderClaimData,
  type CommerceGrantProviderIntrospection,
  type CommerceGrantReplaceData,
  type CommerceGrantRevokeData,
} from "@openarc/shared";
import type { ControlGrantStoreErrorCode } from "@openarc/db";
import type { ZodType } from "zod";

import { AUTH_ERRORS, AuthApiError } from "../auth/errors.js";
import type { AuthRequestContext } from "../auth/service.js";
import {
  hashSessionToken,
  isSessionTokenForKind,
} from "../machine/session-token.js";
import {
  generateCommerceGrantToken,
  hashCommerceGrantToken,
} from "./grant-crypto.js";
import { hashCommerceSessionToken } from "./session-crypto.js";
import {
  COMMERCE_GRANT_RATE_LIMITS,
  type CommerceGrantRateLimiter,
} from "./grant-rate-limiter.js";
import type {
  CommerceGrantAuthPort,
  CommerceGrantMutationMetadata,
  CommerceGrantSessionReadPort,
  CommerceGrantStorePort,
} from "./grant-ports.js";

/**
 * Orchestration for the authorization-grant HTTP slice.
 *
 * THREE strictly separated audiences, each with its own credential class and
 * its own authorization path:
 *
 *   * agent (`oacs_v1_` commerce session) issues and replaces a grant and
 *     reads its own mutation status;
 *   * provider (live `oas_pr_` provider session AND the buyer's exact one-use
 *     `oag_v1_` token) introspects and claims, and recovers an attempt status
 *     by its OWN attempt id;
 *   * browser (cookie session inside the buyer organization) reads a grant,
 *     reads a revoke mutation status and revokes.
 *
 * Neither provider factor alone authorizes anything: the session is transport
 * state that only the store can bind, and the token is a body field that is
 * useless without a current matching provider session. This service never
 * accepts one in place of the other.
 *
 * Browser reads parse the request BEFORE any auth work, then `beginTenantRead`,
 * the bounded read limiter, EXACTLY ONE store read, the `finishTenantRead`
 * guard (even for a null/not-found result) and only then DTO validation and
 * binding. Browser writes parse, verify CSRF, begin the live session, take the
 * revoke limiter and invoke EXACTLY ONE store mutation with no post-commit
 * live-session check.
 *
 * Agent calls resolve the CURRENT commerce session behind the presented bearer
 * before anything is disclosed. Agent reads additionally re-resolve it after
 * the store read and require both snapshots to match. Provider calls carry
 * their current-authorization check INSIDE the store transaction, which binds
 * the live provider session to the very row it reads or writes; a missing
 * attempt and a foreign attempt are the same `not_found`. A missing result is
 * never a shortcut past the current-authorization check.
 *
 * ONE-SHOT TOKEN DISCIPLINE. The service mints a fresh `oag_v1_` secret, hands
 * the store nothing but its one-way digest, and returns the raw value EXACTLY
 * ONCE — in the `replayed: false` arm of an issue/replace response, after the
 * commit. The accepted wire union gives the replay arm no `grantToken` key at
 * all, so a replay, a status read, a detail read, a revoke result, an
 * introspection and a claim are all STRUCTURALLY incapable of carrying it. A
 * replayed mutation discards the freshly minted secret unused; it is never
 * persisted, logged, echoed or reconstructed.
 *
 * An UNKNOWN store outcome is terminal: it maps to its OWN fixed non-retryable
 * "outcome unknown" 500 — deliberately not the 503 every other dependency
 * failure collapses to — and this service never retries, re-dispatches,
 * substitutes an idempotency key, polls, issues a recovery read on the caller's
 * behalf, reports it as success, or describes it as a refund, release, payment,
 * settlement or delivery.
 *
 * Issuing, claiming or revoking a grant is a bounded control decision. It is
 * NOT a payment, a settlement or a delivery, and nothing here moves funds.
 *
 * Money crosses this service only as canonical integer strings from the
 * accepted schemas; no amount is ever parsed into a JS number.
 */

const ISSUE_OPERATION = "control.grant.issue" as const;
const REPLACE_OPERATION = "control.grant.replace" as const;
const CLAIM_OPERATION = "control.grant.claim" as const;
const REVOKE_OPERATION = "control.grant.revoke" as const;

/** An agent mutation status may only report the two agent operations. */
const AGENT_OPERATIONS: ReadonlySet<string> = new Set([
  ISSUE_OPERATION,
  REPLACE_OPERATION,
]);

/** A browser mutation status may only ever report `revoke`. */
const HUMAN_OPERATIONS: ReadonlySet<string> = new Set([REVOKE_OPERATION]);

export interface CommerceGrantServiceOptions {
  readonly auth: CommerceGrantAuthPort;
  readonly store: CommerceGrantStorePort;
  readonly commerceSessions: CommerceGrantSessionReadPort;
  readonly limits: CommerceGrantRateLimiter;
}

export interface CommerceGrantWriteEnvelope {
  readonly csrf: unknown;
  readonly idempotencyKey: unknown;
  readonly body: unknown;
}

export interface CommerceGrantAgentEnvelope {
  readonly idempotencyKey: unknown;
  readonly body: unknown;
}

export interface CommerceGrantProviderEnvelope {
  readonly idempotencyKey: unknown;
  readonly body: unknown;
}

/** Introspection commits nothing, so it carries no idempotency key at all. */
export interface CommerceGrantProviderReadEnvelope {
  readonly body: unknown;
}

function invalidInput(): AuthApiError {
  return AUTH_ERRORS.invalidRequest();
}

function unauthenticated(): AuthApiError {
  return AUTH_ERRORS.unauthenticated();
}

function forbidden(): AuthApiError {
  return AUTH_ERRORS.forbidden();
}

function unavailable(): AuthApiError {
  return AUTH_ERRORS.unavailable();
}

function idempotencyConflict(): AuthApiError {
  return new AuthApiError("IDEMPOTENCY_CONFLICT", 409, "INVALID_REQUEST");
}

function policyDenied(): AuthApiError {
  return new AuthApiError("POLICY_DENIED", 409, "INVALID_REQUEST");
}

function grantExpired(): AuthApiError {
  return new AuthApiError("GRANT_EXPIRED", 409, "INVALID_REQUEST");
}

function budgetReservationConflict(): AuthApiError {
  return new AuthApiError(
    "BUDGET_RESERVATION_CONFLICT",
    409,
    "INVALID_REQUEST",
  );
}

/**
 * The accepted terminal "outcome unknown" result, and the ONLY mapping in this
 * module that is not shared with another store code.
 *
 * A store that cannot say whether its grant write committed is a DEFINITIVE
 * 500, deliberately NOT the 503 that every other dependency failure collapses
 * to: a 503 reads as a transient outage that a client, agent, provider or proxy
 * may safely repeat, and repeating an unknown-outcome grant mutation is exactly
 * the double-spend this surface must never invite. The wire code stays the
 * fixed non-echoing `INTERNAL_ERROR`, so the distinction discloses nothing
 * about the grant, the organization, the provider or the store; it claims no
 * payment, settlement or delivery; it never claims success; and it never
 * implies a reversal, refund or release. Recovery is only ever the CALLER's own
 * bounded status read — the mutation status by `mutationId`, or, for a provider
 * claim, the attempt status by `attemptId` — which this service never performs
 * on the caller's behalf.
 */
export function outcomeUnknown(): AuthApiError {
  return AUTH_ERRORS.internal();
}

/**
 * A malformed/shape-invalid store result (or a binding violation) is a fixed
 * 503. Frozen contract: invalid DB data is an unavailable dependency, not a
 * caller error, and is never echoed back.
 */
function projectionFailure(): AuthApiError {
  return AUTH_ERRORS.unavailable();
}

/**
 * Compile-time coupling to DB12's real error vocabulary.
 *
 * `Record<ControlGrantStoreErrorCode, true>` requires EVERY code DB12 declares
 * to appear here, so adding one upstream breaks the build; `satisfies` rejects
 * any key DB12 does not declare, so a rename or removal breaks it too. Without
 * this, a renamed store code would silently fall through to the unrecognized
 * 503 branch and, worse, an OUTCOME_UNKNOWN would lose its distinct
 * non-retryable mapping. The import is type-only and therefore erased, so this
 * adds no runtime dependency on the store and the service stays testable with
 * injected fakes.
 */
const CONTROL_GRANT_STORE_ERROR_CODES = {
  CONTROL_GRANT_STORE_INPUT_INVALID: true,
  CONTROL_GRANT_STORE_SESSION_INVALID: true,
  CONTROL_GRANT_STORE_FORBIDDEN: true,
  CONTROL_GRANT_STORE_NOT_FOUND: true,
  CONTROL_GRANT_STORE_CONFLICT: true,
  CONTROL_GRANT_STORE_GRANT_CONFLICT: true,
  CONTROL_GRANT_STORE_GRANT_EXPIRED: true,
  CONTROL_GRANT_STORE_POTENTIAL_EXPOSURE: true,
  CONTROL_GRANT_STORE_REQUIREMENT_UNAVAILABLE: true,
  CONTROL_GRANT_STORE_IDEMPOTENCY_CONFLICT: true,
  CONTROL_GRANT_STORE_UNAVAILABLE: true,
  CONTROL_GRANT_STORE_OUTCOME_UNKNOWN: true,
} as const satisfies Record<ControlGrantStoreErrorCode, true>;

export type CommerceGrantStoreErrorCode =
  keyof typeof CONTROL_GRANT_STORE_ERROR_CODES;

/** Raw `.code` extraction with no vocabulary assumption. */
function rawErrorCode(error: unknown): string | null {
  if (typeof error !== "object" || error === null) return null;
  const code = (error as { code?: unknown }).code;
  return typeof code === "string" ? code : null;
}

/**
 * Narrows to DB12's vocabulary only. An unrecognized string returns null, which
 * every caller treats as the unrecognized case and fails closed on.
 */
function storeErrorCode(error: unknown): CommerceGrantStoreErrorCode | null {
  const code = rawErrorCode(error);
  if (code === null) return null;
  return Object.hasOwn(CONTROL_GRANT_STORE_ERROR_CODES, code)
    ? (code as CommerceGrantStoreErrorCode)
    : null;
}

function mapStoreError(error: unknown): never {
  if (error instanceof AuthApiError) throw error;
  switch (storeErrorCode(error)) {
    case "CONTROL_GRANT_STORE_INPUT_INVALID":
      throw invalidInput();
    case "CONTROL_GRANT_STORE_SESSION_INVALID":
      // The presented commerce/provider/browser authority is not currently
      // valid. A fixed 401 with no hint about which factor failed.
      throw unauthenticated();
    case "CONTROL_GRANT_STORE_FORBIDDEN":
    case "CONTROL_GRANT_STORE_NOT_FOUND":
      // A cross-actor or unknown target is the same fixed denial: no
      // organization/grant/action existence oracle is exposed by the transport.
      throw forbidden();
    case "CONTROL_GRANT_STORE_CONFLICT":
    case "CONTROL_GRANT_STORE_GRANT_CONFLICT":
      // The store collapses "already claimed", "revoked" and "superseded
      // generation" into one grant-state code. Reporting `GRANT_ALREADY_USED`
      // would assert a CONSUMED grant — and therefore a possible payment — for
      // a merely revoked or replaced one, so the safe fixed refusal is the
      // generic 409 denial. It moved no funds and released nothing.
      throw policyDenied();
    case "CONTROL_GRANT_STORE_GRANT_EXPIRED":
      // Grant authority lapsed. Deliberately NOT a 401 (which reads as
      // "re-authenticate and repeat") and NOT a 503 (which reads as
      // "retry later"): the grant is terminally past its expiry.
      throw grantExpired();
    case "CONTROL_GRANT_STORE_POTENTIAL_EXPOSURE":
      // A replacement refused because the target still carries unresolved or
      // already-claimed exposure. The conflict is with that live reservation,
      // so it is reported as such and NEVER as a release.
      throw budgetReservationConflict();
    case "CONTROL_GRANT_STORE_IDEMPOTENCY_CONFLICT":
      throw idempotencyConflict();
    case "CONTROL_GRANT_STORE_REQUIREMENT_UNAVAILABLE":
      // The requirement cannot be admitted by THIS deployment. That is a
      // dependency the operator must fix, not a request the caller can correct,
      // and it must not become a provenance oracle, so it stays the fixed 503.
      throw unavailable();
    case "CONTROL_GRANT_STORE_OUTCOME_UNKNOWN":
      // Terminal, and the one mapping that is NOT the generic 503. No retry,
      // no re-dispatch, no recovery read, no reversal claim.
      throw outcomeUnknown();
    case "CONTROL_GRANT_STORE_UNAVAILABLE":
    default:
      throw unavailable();
  }
}

/**
 * Commerce-session repository failures during agent calls collapse to the same
 * fixed 401 without an existence oracle. Genuine outages stay a 503.
 *
 * This extractor is deliberately RAW and vocabulary-free: this path can match
 * commerce-SESSION codes alongside grant ones, and narrowing to DB12's list
 * here would discard the session outage codes and silently downgrade a genuine
 * outage to a 401.
 */
function mapCommerceSessionError(error: unknown): never {
  if (error instanceof AuthApiError) throw error;
  const code = rawErrorCode(error);
  if (
    code === "COMMERCE_SESSION_STORE_UNAVAILABLE" ||
    code === "COMMERCE_SESSION_STORE_OUTCOME_UNKNOWN" ||
    code === "CONTROL_GRANT_STORE_UNAVAILABLE"
  ) {
    throw unavailable();
  }
  if (code === "CONTROL_GRANT_STORE_OUTCOME_UNKNOWN") {
    // An unknown outcome keeps its own terminal mapping even on this path: it
    // must never be downgraded to a repeatable 401 or 503.
    throw outcomeUnknown();
  }
  throw unauthenticated();
}

function parseRequest<T>(schema: ZodType<T>, input: unknown): T {
  const parsed = schema.safeParse(input);
  if (!parsed.success) throw invalidInput();
  return parsed.data;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Reject a store envelope that carries keys other than the accepted ones, so an
 * extra key (a stray token, hash or secret among them) can never be silently
 * stripped into a passing projection.
 */
function requireExactKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
): void {
  const keys = Object.keys(value);
  if (keys.length !== allowed.length) throw projectionFailure();
  for (const key of keys) {
    if (!allowed.includes(key)) throw projectionFailure();
  }
}

/**
 * Canonical, non-echoing snapshot of the CURRENT commerce session behind a
 * presented bearer. Only the accepted metadata leaves are retained; no token,
 * hash or secret is ever carried here.
 */
interface TrustedCommerceSession {
  readonly sessionId: string;
  readonly organizationId: string;
  readonly subjectAgentId: string;
  readonly policyId: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly exchangedAt: string | null;
  readonly revokedAt: string | null;
}

/**
 * Validate the WHOLE commerce-session read against the accepted shared schema
 * before any tenant is trusted. A revoked session is never trusted.
 */
function trustedCommerceSession(raw: unknown): TrustedCommerceSession {
  const parsed = CommerceControlSessionMetadataSchema.safeParse(raw);
  if (!parsed.success) throw unauthenticated();
  if (parsed.data.revokedAt !== null) throw unauthenticated();
  return {
    sessionId: parsed.data.sessionId,
    organizationId: parsed.data.organizationId,
    subjectAgentId: parsed.data.subjectAgentId,
    policyId: parsed.data.policyId,
    issuedAt: parsed.data.issuedAt,
    expiresAt: parsed.data.expiresAt,
    exchangedAt: parsed.data.exchangedAt,
    revokedAt: parsed.data.revokedAt,
  };
}

function sameCommerceSession(
  left: TrustedCommerceSession,
  right: TrustedCommerceSession,
): boolean {
  return (
    left.sessionId === right.sessionId &&
    left.organizationId === right.organizationId &&
    left.subjectAgentId === right.subjectAgentId &&
    left.policyId === right.policyId &&
    left.issuedAt === right.issuedAt &&
    left.expiresAt === right.expiresAt &&
    left.exchangedAt === right.exchangedAt &&
    left.revokedAt === right.revokedAt
  );
}

export class CommerceGrantService {
  readonly #auth: CommerceGrantAuthPort;
  readonly #store: CommerceGrantStorePort;
  readonly #commerceSessions: CommerceGrantSessionReadPort;
  readonly #limits: CommerceGrantRateLimiter;

  constructor(options: CommerceGrantServiceOptions) {
    this.#auth = options.auth;
    this.#store = options.store;
    this.#commerceSessions = options.commerceSessions;
    this.#limits = options.limits;
  }

  /* ---------------------------------------------------------------- */
  /* commerce_grant_authorization (agent)                              */
  /* ---------------------------------------------------------------- */

  /**
   * Issue the single grant of a reserved action. The raw `oag_v1_` secret is
   * minted HERE, delivered to the buyer exactly once after commit, and never
   * written to the store, a log or any other response.
   */
  async issue(
    token: unknown,
    peerIp: string,
    envelope: CommerceGrantAgentEnvelope,
  ): Promise<CommerceGrantIssueData> {
    const presented = this.#requireCommerceSessionToken(token);
    const body = parseRequest(CommerceGrantIssueBodySchema, envelope.body);
    const idempotencyKey = parseRequest(
      CommerceTenantIdempotencyKeySchema,
      envelope.idempotencyKey,
    );
    await this.#consumeAuthorizationLimits(peerIp, presented);
    const sessionHash = this.#hashCommerceSession(presented);
    // Authenticate the CURRENT caller before any store authority or disclosure.
    const current = await this.#currentCommerceSession(sessionHash);
    const minted = this.#mintGrantToken();
    let raw: unknown;
    try {
      raw = await this.#store.issueCommerceGrant(
        sessionHash,
        { actionId: body.actionId, grantTokenHash: minted.hash },
        { idempotencyKey, mutationId: body.mutationId },
      );
    } catch (error) {
      mapStoreError(error);
    }
    // No post-commit live-session re-read: a business mutation is never
    // retried, re-dispatched or re-evaluated after it has been committed.
    const { replayed, metadata, receipt } = this.#projectMutationEnvelope(raw, {
      operation: ISSUE_OPERATION,
      mutationId: body.mutationId,
      organizationId: current.organizationId,
      commerceSessionId: current.sessionId,
    });
    if (metadata.actionId !== body.actionId) throw projectionFailure();
    // The freshly minted secret is delivered ONLY on a first commit. A replay
    // returns the original grant, whose live secret this service does not hold
    // and can never reconstruct, so the replay arm carries no token key at all.
    const data = CommerceGrantIssueDataSchema.safeParse(
      replayed
        ? { replayed: true, metadata, receipt }
        : { replayed: false, metadata, receipt, grantToken: minted.token },
    );
    if (!data.success) throw projectionFailure();
    return data.data;
  }

  /**
   * Replace the still-unclaimed generation of an existing grant. A replacement
   * mints a NEW secret on the SAME grant and can never extend the original
   * expiry; the accepted wire schema enforces both.
   */
  async replace(
    token: unknown,
    peerIp: string,
    grantId: unknown,
    envelope: CommerceGrantAgentEnvelope,
  ): Promise<CommerceGrantReplaceData> {
    const presented = this.#requireCommerceSessionToken(token);
    const grant = parseRequest(CommerceGrantIdSchema, grantId);
    const body = parseRequest(CommerceGrantReplaceBodySchema, envelope.body);
    const idempotencyKey = parseRequest(
      CommerceTenantIdempotencyKeySchema,
      envelope.idempotencyKey,
    );
    await this.#consumeAuthorizationLimits(peerIp, presented);
    const sessionHash = this.#hashCommerceSession(presented);
    const current = await this.#currentCommerceSession(sessionHash);
    const minted = this.#mintGrantToken();
    let raw: unknown;
    try {
      raw = await this.#store.replaceCommerceGrant(
        sessionHash,
        { grantId: grant, grantTokenHash: minted.hash },
        { idempotencyKey, mutationId: body.mutationId },
      );
    } catch (error) {
      mapStoreError(error);
    }
    const { replayed, metadata, receipt } = this.#projectMutationEnvelope(raw, {
      operation: REPLACE_OPERATION,
      mutationId: body.mutationId,
      organizationId: current.organizationId,
      commerceSessionId: current.sessionId,
    });
    if (metadata.grantId !== grant) throw projectionFailure();
    const data = CommerceGrantReplaceDataSchema.safeParse(
      replayed
        ? { replayed: true, metadata, receipt }
        : { replayed: false, metadata, receipt, grantToken: minted.token },
    );
    if (!data.success) throw projectionFailure();
    return data.data;
  }

  async getAgentMutationStatus(
    token: unknown,
    peerIp: string,
    request: unknown,
  ): Promise<CommerceGrantAgentMutationStatus> {
    const presented = this.#requireCommerceSessionToken(token);
    const parsed = parseRequest(
      CommerceGrantAgentMutationRequestSchema,
      request,
    );
    await this.#consumeAgentReadLimits(peerIp, presented);
    const sessionHash = this.#hashCommerceSession(presented);
    // The current-authorization check runs BEFORE and AFTER, including for a
    // `not_found` recovery read.
    const before = await this.#currentCommerceSession(sessionHash);
    let raw: unknown;
    try {
      raw = await this.#store.getAgentCommerceGrantMutationStatus(
        sessionHash,
        parsed.mutationId,
      );
    } catch (error) {
      mapStoreError(error);
    }
    const after = await this.#currentCommerceSession(sessionHash);
    if (!sameCommerceSession(before, after)) throw projectionFailure();
    const status = this.#projectMutationStatus(
      raw,
      parsed.mutationId,
      AGENT_OPERATIONS,
    );
    const agent = CommerceGrantAgentMutationStatusSchema.safeParse(status);
    if (!agent.success) throw projectionFailure();
    return agent.data;
  }

  /* ---------------------------------------------------------------- */
  /* commerce_grant_claim (provider)                                   */
  /* ---------------------------------------------------------------- */

  /**
   * Provider introspection under BOTH factors. Read-only: it consumes nothing
   * and reserves nothing. The projection is the accepted positive allowlist, so
   * no buyer organization, agent, policy, session, account or balance field is
   * representable in the response.
   */
  async introspect(
    providerToken: unknown,
    peerIp: string,
    envelope: CommerceGrantProviderReadEnvelope,
  ): Promise<CommerceGrantProviderIntrospection> {
    const presented = this.#requireProviderSessionToken(providerToken);
    const body = parseRequest(
      CommerceGrantProviderIntrospectBodySchema,
      envelope.body,
    );
    await this.#consumeProviderReadLimits(peerIp, presented);
    const sessionHash = this.#hashProviderSession(presented);
    const tokenHash = this.#hashGrantToken(body.grantToken);
    let raw: unknown;
    try {
      // The store binds the CURRENT provider session to the very row it reads,
      // inside one transaction. Neither factor alone reaches a grant.
      raw = await this.#store.introspectCommerceGrant(sessionHash, tokenHash);
    } catch (error) {
      mapStoreError(error);
    }
    if (!isRecord(raw)) throw projectionFailure();
    requireExactKeys(raw, ["item"]);
    const data = CommerceGrantProviderIntrospectionSchema.safeParse({
      item: raw["item"],
    });
    if (!data.success) throw projectionFailure();
    return data.data;
  }

  /**
   * Provider claim under BOTH factors. Exactly one concurrent claimant wins the
   * single compare-and-set in the database; this service never retries and
   * never re-dispatches. A claim is not a payment, a settlement or a delivery.
   */
  async claim(
    providerToken: unknown,
    peerIp: string,
    envelope: CommerceGrantProviderEnvelope,
  ): Promise<CommerceGrantProviderClaimData> {
    const presented = this.#requireProviderSessionToken(providerToken);
    const body = parseRequest(
      CommerceGrantProviderClaimBodySchema,
      envelope.body,
    );
    const idempotencyKey = parseRequest(
      CommerceTenantIdempotencyKeySchema,
      envelope.idempotencyKey,
    );
    await this.#consumeClaimLimits(peerIp, presented);
    const sessionHash = this.#hashProviderSession(presented);
    const tokenHash = this.#hashGrantToken(body.grantToken);
    const metadata: CommerceGrantMutationMetadata = {
      idempotencyKey,
      mutationId: body.mutationId,
    };
    let raw: unknown;
    try {
      raw = await this.#store.claimCommerceGrant(
        sessionHash,
        {
          grantTokenHash: tokenHash,
          expectedActionId: body.expectedActionId,
          attemptId: body.attemptId,
        },
        metadata,
      );
    } catch (error) {
      mapStoreError(error);
    }
    if (!isRecord(raw)) throw projectionFailure();
    requireExactKeys(raw, [
      "replayed",
      "item",
      "attemptId",
      "claimedAt",
      "claimDigest",
      "receipt",
    ]);
    const replayed = this.#requireReplayed(raw["replayed"]);
    if (raw["attemptId"] !== body.attemptId) throw projectionFailure();
    const receipt = this.#requireReceipt(
      raw["receipt"],
      CLAIM_OPERATION,
      body.mutationId,
    );
    const data = CommerceGrantProviderClaimDataSchema.safeParse({
      replayed,
      item: raw["item"],
      attemptId: body.attemptId,
      claimedAt: raw["claimedAt"],
      claimDigest: raw["claimDigest"],
      receipt,
    });
    if (!data.success) throw projectionFailure();
    // The provider stated the action it believed it was claiming; a different
    // action is a binding violation, never a silently accepted claim.
    if (data.data.item.actionId !== body.expectedActionId) {
      throw projectionFailure();
    }
    return data.data;
  }

  /**
   * Provider attempt-status recovery keyed ONLY by the provider's own attempt
   * id. A missing attempt and a foreign attempt are indistinguishable: both are
   * the accepted `not_found` arm, which carries nothing but its status.
   */
  async getProviderAttemptStatus(
    providerToken: unknown,
    peerIp: string,
    request: unknown,
  ): Promise<CommerceGrantProviderAttemptStatusData> {
    const presented = this.#requireProviderSessionToken(providerToken);
    const parsed = parseRequest(
      CommerceGrantProviderAttemptStatusRequestSchema,
      request,
    );
    await this.#consumeProviderReadLimits(peerIp, presented);
    const sessionHash = this.#hashProviderSession(presented);
    let raw: unknown;
    try {
      // A missing result still requires the current provider authority: the
      // store binds the live session before it can answer `not_found`.
      raw = await this.#store.getProviderCommerceGrantAttemptStatus(
        sessionHash,
        parsed.attemptId,
      );
    } catch (error) {
      mapStoreError(error);
    }
    if (!isRecord(raw)) throw projectionFailure();
    requireExactKeys(raw, ["attemptId", "item"]);
    if (raw["attemptId"] !== parsed.attemptId) throw projectionFailure();
    const data = CommerceGrantProviderAttemptStatusDataSchema.safeParse({
      attemptId: parsed.attemptId,
      item: raw["item"],
    });
    if (!data.success) throw projectionFailure();
    return data.data;
  }

  /* ---------------------------------------------------------------- */
  /* commerce_grant_management (browser)                               */
  /* ---------------------------------------------------------------- */

  async getGrant(
    ctx: AuthRequestContext,
    request: unknown,
  ): Promise<CommerceGrantDetail> {
    const parsed = parseRequest(CommerceGrantDetailRequestSchema, request);
    const begun = await this.#auth.beginTenantRead(ctx);
    await this.#consumeReadLimits(ctx, begun.accountId);
    let raw: unknown;
    try {
      raw = await this.#store.getCommerceGrant(
        begun.sessionHash,
        parsed.organizationId,
        parsed.grantId,
      );
    } catch (error) {
      mapStoreError(error);
    }
    // A missing item is still an authorized read: the finish guard runs before
    // anything (including absence) is disclosed.
    await this.#auth.finishTenantRead(ctx, begun);
    if (!isRecord(raw)) throw projectionFailure();
    requireExactKeys(raw, ["organizationId", "grantId", "item"]);
    // The raw identity is authoritative, never replaced by the requested one: a
    // foreign/invalid organization or grant (even with item:null) is a 503.
    if (
      raw["organizationId"] !== parsed.organizationId ||
      raw["grantId"] !== parsed.grantId
    ) {
      throw projectionFailure();
    }
    const detail = CommerceGrantDetailSchema.safeParse({
      organizationId: parsed.organizationId,
      grantId: parsed.grantId,
      item: raw["item"],
    });
    if (!detail.success) throw projectionFailure();
    return detail.data;
  }

  async getHumanMutationStatus(
    ctx: AuthRequestContext,
    request: unknown,
  ): Promise<CommerceGrantHumanMutationStatus> {
    const parsed = parseRequest(
      CommerceGrantHumanMutationRequestSchema,
      request,
    );
    const begun = await this.#auth.beginTenantRead(ctx);
    await this.#consumeReadLimits(ctx, begun.accountId);
    let raw: unknown;
    try {
      raw = await this.#store.getHumanCommerceGrantMutationStatus(
        begun.sessionHash,
        parsed.organizationId,
        parsed.mutationId,
      );
    } catch (error) {
      mapStoreError(error);
    }
    // A `not_found` recovery read is still an authorized read.
    await this.#auth.finishTenantRead(ctx, begun);
    const status = this.#projectMutationStatus(
      raw,
      parsed.mutationId,
      HUMAN_OPERATIONS,
    );
    const human = CommerceGrantHumanMutationStatusSchema.safeParse(status);
    if (!human.success) throw projectionFailure();
    return human.data;
  }

  /**
   * Human revoke. Revocation is a FLAG, never an erasure: a claimed grant keeps
   * its claim fact and its held exposure, and `released` is true only when the
   * grant was never claimed and its reservation was actually released. The
   * store's raw reservation status is deliberately dropped here — no accepted
   * shared vocabulary exists for it and the transport must not invent one.
   */
  async revoke(
    ctx: AuthRequestContext,
    organizationId: unknown,
    grantId: unknown,
    envelope: CommerceGrantWriteEnvelope,
  ): Promise<CommerceGrantRevokeData> {
    const organization = parseRequest(
      CommerceOrganizationIdSchema,
      organizationId,
    );
    const grant = parseRequest(CommerceGrantIdSchema, grantId);
    const body = parseRequest(CommerceGrantRevokeBodySchema, envelope.body);
    const idempotencyKey = parseRequest(
      CommerceTenantIdempotencyKeySchema,
      envelope.idempotencyKey,
    );
    // Input validation is complete; now CSRF, then the live-session begin.
    this.#auth.verifyCsrf(ctx.cookies, envelope.csrf);
    const begun = await this.#auth.beginTenantRead(ctx);
    await this.#limits.consumeAll([
      {
        family: "revoke",
        bucket: "account",
        value: begun.accountId,
        limit: COMMERCE_GRANT_RATE_LIMITS.revoke.account,
      },
    ]);
    let raw: unknown;
    try {
      raw = await this.#store.revokeCommerceGrant(
        begun.sessionHash,
        organization,
        grant,
        { idempotencyKey, mutationId: body.mutationId },
      );
    } catch (error) {
      mapStoreError(error);
    }
    if (!isRecord(raw)) throw projectionFailure();
    requireExactKeys(raw, [
      "replayed",
      "metadata",
      "receipt",
      "released",
      "actionStatus",
      "reservationStatus",
    ]);
    const replayed = this.#requireReplayed(raw["replayed"]);
    const released = this.#requireReplayed(raw["released"]);
    const metadata = this.#requireMetadata(raw["metadata"]);
    if (
      metadata.grantId !== grant ||
      metadata.organizationId !== organization
    ) {
      throw projectionFailure();
    }
    const receipt = this.#requireReceipt(
      raw["receipt"],
      REVOKE_OPERATION,
      body.mutationId,
    );
    const data = CommerceGrantRevokeDataSchema.safeParse({
      replayed,
      metadata,
      receipt,
      released,
      actionStatus: raw["actionStatus"],
    });
    if (!data.success) throw projectionFailure();
    return data.data;
  }

  /* ---------------------------------------------------------------- */
  /* Internal helpers                                                  */
  /* ---------------------------------------------------------------- */

  #requireCommerceSessionToken(token: unknown): string {
    if (
      typeof token !== "string" ||
      !/^oacs_v1_[A-Za-z0-9_-]{43}(?![\s\S])/u.test(token)
    ) {
      throw unauthenticated();
    }
    return token;
  }

  /**
   * Exactly a canonical `oas_pr_` PROVIDER session token. An agent `oas_ag_`
   * token, a commerce `oacs_v1_` bearer and a raw `oag_v1_` grant token are all
   * rejected here: the provider lane's first factor has its own namespace.
   */
  #requireProviderSessionToken(token: unknown): string {
    if (!isSessionTokenForKind("provider", token)) throw unauthenticated();
    return token;
  }

  #hashCommerceSession(token: string): string {
    try {
      return hashCommerceSessionToken(token);
    } catch {
      throw unauthenticated();
    }
  }

  #hashProviderSession(token: string): string {
    try {
      return hashSessionToken("provider", token);
    } catch {
      throw unauthenticated();
    }
  }

  /**
   * One-way digest of the buyer's presented one-use secret. The raw value never
   * leaves this frame: only the digest crosses the store seam, and no error
   * raised here echoes any part of the token.
   */
  #hashGrantToken(token: string): string {
    try {
      return hashCommerceGrantToken(token);
    } catch {
      throw unauthenticated();
    }
  }

  /**
   * Mint a fresh one-use secret and its digest. Only the digest is persisted;
   * the raw token is returned to the buyer exactly once, after commit, and is
   * dropped unused when the store reports a replay.
   */
  #mintGrantToken(): { token: string; hash: string } {
    let token: string;
    try {
      token = generateCommerceGrantToken();
    } catch {
      throw unavailable();
    }
    return { token, hash: this.#hashGrantToken(token) };
  }

  async #currentCommerceSession(
    sessionHash: string,
  ): Promise<TrustedCommerceSession> {
    let raw: unknown;
    try {
      raw = await this.#commerceSessions.getCommerceSessionByHash(sessionHash);
    } catch (error) {
      mapCommerceSessionError(error);
    }
    return trustedCommerceSession(raw);
  }

  async #consumeReadLimits(
    ctx: AuthRequestContext,
    accountId: string,
  ): Promise<void> {
    await this.#limits.consumeAll([
      {
        family: "read",
        bucket: "global",
        value: "*",
        limit: COMMERCE_GRANT_RATE_LIMITS.read.global,
      },
      {
        family: "read",
        bucket: "peer",
        value: ctx.peerIp,
        limit: COMMERCE_GRANT_RATE_LIMITS.read.peer,
      },
      {
        family: "read",
        bucket: "subject",
        value: accountId,
        limit: COMMERCE_GRANT_RATE_LIMITS.read.subject,
      },
    ]);
  }

  async #consumeAgentReadLimits(
    peerIp: string,
    presented: string,
  ): Promise<void> {
    await this.#consumeBearerReadLimits(peerIp, presented);
  }

  async #consumeProviderReadLimits(
    peerIp: string,
    presented: string,
  ): Promise<void> {
    await this.#consumeBearerReadLimits(peerIp, presented);
  }

  async #consumeBearerReadLimits(
    peerIp: string,
    presented: string,
  ): Promise<void> {
    await this.#limits.consumeAll([
      {
        family: "read",
        bucket: "global",
        value: "*",
        limit: COMMERCE_GRANT_RATE_LIMITS.read.global,
      },
      {
        family: "read",
        bucket: "peer",
        value: peerIp,
        limit: COMMERCE_GRANT_RATE_LIMITS.read.peer,
      },
      {
        family: "read",
        bucket: "subject",
        value: presented,
        limit: COMMERCE_GRANT_RATE_LIMITS.read.subject,
      },
    ]);
  }

  /** Ordered global/peer/presented-token limiter BEFORE any hash or authority. */
  async #consumeAuthorizationLimits(
    peerIp: string,
    presented: string,
  ): Promise<void> {
    await this.#limits.consumeAll([
      {
        family: "authorization",
        bucket: "global",
        value: "*",
        limit: COMMERCE_GRANT_RATE_LIMITS.authorization.global,
      },
      {
        family: "authorization",
        bucket: "peer",
        value: peerIp,
        limit: COMMERCE_GRANT_RATE_LIMITS.authorization.peer,
      },
      {
        family: "authorization",
        bucket: "token",
        value: presented,
        limit: COMMERCE_GRANT_RATE_LIMITS.authorization.token,
      },
    ]);
  }

  async #consumeClaimLimits(peerIp: string, presented: string): Promise<void> {
    await this.#limits.consumeAll([
      {
        family: "claim",
        bucket: "global",
        value: "*",
        limit: COMMERCE_GRANT_RATE_LIMITS.claim.global,
      },
      {
        family: "claim",
        bucket: "peer",
        value: peerIp,
        limit: COMMERCE_GRANT_RATE_LIMITS.claim.peer,
      },
      {
        family: "claim",
        bucket: "token",
        value: presented,
        limit: COMMERCE_GRANT_RATE_LIMITS.claim.token,
      },
    ]);
  }

  /**
   * Shared issue/replace envelope projection: exact keys, a strict boolean
   * replay flag, accepted grant metadata bound to the CURRENT commerce session
   * and its organization, and a receipt bound to this operation and mutation.
   */
  #projectMutationEnvelope(
    raw: unknown,
    expected: {
      operation: string;
      mutationId: string;
      organizationId: string;
      commerceSessionId: string;
    },
  ): {
    replayed: boolean;
    metadata: CommerceGrantMetadata;
    receipt: CommerceGrantMutationReceipt;
  } {
    if (!isRecord(raw)) throw projectionFailure();
    requireExactKeys(raw, ["replayed", "metadata", "receipt"]);
    const replayed = this.#requireReplayed(raw["replayed"]);
    const metadata = this.#requireMetadata(raw["metadata"]);
    // Cross-tenant binding: the grant must belong to the organization AND the
    // exact commerce session the presented bearer currently resolves to.
    if (
      metadata.organizationId !== expected.organizationId ||
      metadata.commerceSessionId !== expected.commerceSessionId
    ) {
      throw projectionFailure();
    }
    const receipt = this.#requireReceipt(
      raw["receipt"],
      expected.operation,
      expected.mutationId,
    );
    if (receipt.resourceId !== metadata.grantId) throw projectionFailure();
    return { replayed, metadata, receipt };
  }

  #requireMetadata(value: unknown): CommerceGrantMetadata {
    const parsed = CommerceGrantMetadataSchema.safeParse(value);
    if (!parsed.success) throw projectionFailure();
    return parsed.data;
  }

  #projectMutationStatus(
    raw: unknown,
    mutationId: string,
    operations: ReadonlySet<string>,
  ): { status: "not_found" } | { status: "committed"; receipt: unknown } {
    if (!isRecord(raw)) throw projectionFailure();
    if (raw["status"] === "not_found") {
      requireExactKeys(raw, ["status"]);
      return { status: "not_found" };
    }
    if (raw["status"] !== "committed") throw projectionFailure();
    requireExactKeys(raw, ["status", "receipt"]);
    const receipt = CommerceGrantMutationReceiptSchema.safeParse(
      raw["receipt"],
    );
    if (!receipt.success) throw projectionFailure();
    // The receipt must belong to the requested mutation AND to this audience's
    // operations, so a browser read can never surface an agent issue/replace or
    // a provider claim, and an agent read can never surface a human revoke.
    if (
      receipt.data.mutationId !== mutationId ||
      !operations.has(receipt.data.operation)
    ) {
      throw projectionFailure();
    }
    return { status: "committed", receipt: receipt.data };
  }

  #requireReplayed(value: unknown): boolean {
    if (value === true) return true;
    if (value === false) return false;
    throw projectionFailure();
  }

  #requireReceipt(
    value: unknown,
    operation: string,
    mutationId: string,
  ): CommerceGrantMutationReceipt {
    const parsed = CommerceGrantMutationReceiptSchema.safeParse(value);
    if (!parsed.success) throw projectionFailure();
    if (
      parsed.data.operation !== operation ||
      parsed.data.mutationId !== mutationId
    ) {
      throw projectionFailure();
    }
    return parsed.data;
  }
}
