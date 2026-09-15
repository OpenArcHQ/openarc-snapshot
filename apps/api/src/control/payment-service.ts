import {
  COMMERCE_PAYMENT_ASSET_ADDRESS,
  COMMERCE_PAYMENT_BINDING_ROLE,
  COMMERCE_PAYMENT_BINDING_SCHEMA_VERSION,
  COMMERCE_PAYMENT_NETWORK,
  COMMERCE_PAYMENT_VERIFYING_CONTRACT,
  CommerceActionMetadataSchema,
  CommerceControlSessionMetadataSchema,
  CommerceGrantAttemptIdSchema,
  CommerceListingIdSchema,
  CommerceListingVersionSchema,
  CommerceOrganizationIdSchema,
  CommercePaymentAttemptDispatchBodySchema,
  CommercePaymentAttemptDispatchDataSchema,
  CommercePaymentAttemptPersistBodySchema,
  CommercePaymentAttemptPersistDataSchema,
  CommercePaymentAttemptReadDataSchema,
  CommercePaymentAttemptReadRequestSchema,
  CommercePaymentRequirementBodySchema,
  CommercePaymentTermsBodySchema,
  CommercePaymentTermsDataSchema,
  CommercePaymentVerifiedRequirementSchema,
  CommerceTenantIdempotencyKeySchema,
  type CommercePaymentAttemptDispatchData,
  type CommercePaymentAttemptPersistData,
  type CommercePaymentAttemptReadData,
  type CommercePaymentTermsData,
  type CommercePaymentVerifiedRequirement,
} from "@openarc/shared";
import type { ControlPaymentAttemptStoreErrorCode } from "@openarc/db";
import type { ZodType } from "zod";

import { AUTH_ERRORS, AuthApiError } from "../auth/errors.js";
import type { AuthRequestContext } from "../auth/service.js";
import { hashCommerceSessionToken } from "./session-crypto.js";
import {
  COMMERCE_PAYMENT_RATE_LIMITS,
  type CommercePaymentRateFamily,
  type CommercePaymentRateLimiter,
} from "./payment-rate-limiter.js";
import type {
  CommercePaymentActionReadPort,
  CommercePaymentAuthPort,
  CommercePaymentBindingInput,
  CommercePaymentSessionReadPort,
  CommercePaymentStorePort,
} from "./payment-ports.js";

/**
 * Orchestration for the migration-0015 payment HTTP slice.
 *
 * TWO strictly separated audiences:
 *
 *   * browser (cookie session + CSRF inside the SELLER organization) records
 *     the immutable pay-to terms of one listing version. Recovery of a lost
 *     response is an EXACT replay of the same idempotency key and mutation id;
 *   * agent (exactly one `oacs_v1_` commerce session bearer) registers a
 *     verified requirement, persists a lane attempt, records its one dispatch
 *     and reads it back. The read-only `oas_ag_` machine credential is never
 *     accepted.
 *
 * SERVER-DERIVED TERMS. The agent never supplies an amount, network, asset,
 * verifying contract or source kind. The persist binding is rebuilt here from
 * the frozen wire constants and from the buyer's OWN authorized action (its
 * `amountAtomic` and `requirementDigest`), and the store then recomputes the
 * binding digest and re-derives every term in SQL. A lane that signed anything
 * else cannot produce a matching digest.
 *
 * NOTHING HERE SIGNS, SENDS OR SETTLES. A recorded dispatch is `unknown`: it
 * means the attempt may now leave the lane, never that a payment happened.
 * A second dispatch is a fixed non-retryable 409, never a success. An unknown
 * store outcome is its own non-retryable 500; this service never retries,
 * re-dispatches, polls or reads back on the caller's behalf. The observation
 * recorder is migrator-private and unreachable from this service.
 */

const TERMS_OPERATION = "market.listing.payment_terms.record" as const;

export interface CommercePaymentServiceOptions {
  readonly auth: CommercePaymentAuthPort;
  readonly store: CommercePaymentStorePort;
  readonly commerceSessions: CommercePaymentSessionReadPort;
  readonly actions: CommercePaymentActionReadPort;
  readonly limits: CommercePaymentRateLimiter;
}

export interface CommercePaymentWriteEnvelope {
  readonly csrf: unknown;
  readonly idempotencyKey: unknown;
  readonly body: unknown;
}

/** Agent writes are keyed by their own canonical ids; no idempotency header. */
export interface CommercePaymentAgentEnvelope {
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

function policyDenied(): AuthApiError {
  return new AuthApiError("POLICY_DENIED", 409, "INVALID_REQUEST");
}

function grantExpired(): AuthApiError {
  return new AuthApiError("GRANT_EXPIRED", 409, "INVALID_REQUEST");
}

function budgetReservationConflict(): AuthApiError {
  return new AuthApiError("BUDGET_RESERVATION_CONFLICT", 409, "INVALID_REQUEST");
}

function idempotencyConflict(): AuthApiError {
  return new AuthApiError("IDEMPOTENCY_CONFLICT", 409, "INVALID_REQUEST");
}

/**
 * The terminal "outcome unknown" result: a DEFINITIVE non-retryable 500, never
 * the repeatable 503. For a dispatch it means the caller must NOT send.
 */
export function outcomeUnknown(): AuthApiError {
  return AUTH_ERRORS.internal();
}

/** A malformed or mis-bound store result is a fixed 503, never echoed. */
function projectionFailure(): AuthApiError {
  return AUTH_ERRORS.unavailable();
}

/**
 * Compile-time coupling to the schema15 store's real error vocabulary, exactly
 * as the action and grant families couple to theirs. `Record<..., true>`
 * requires every declared code; `satisfies` rejects any undeclared one.
 */
const CONTROL_PAYMENT_ATTEMPT_STORE_ERROR_CODES = {
  CONTROL_PAYMENT_ATTEMPT_STORE_INPUT_INVALID: true,
  CONTROL_PAYMENT_ATTEMPT_STORE_SESSION_INVALID: true,
  CONTROL_PAYMENT_ATTEMPT_STORE_FORBIDDEN: true,
  CONTROL_PAYMENT_ATTEMPT_STORE_NOT_FOUND: true,
  CONTROL_PAYMENT_ATTEMPT_STORE_CONFLICT: true,
  CONTROL_PAYMENT_ATTEMPT_STORE_ATTEMPT_CONFLICT: true,
  CONTROL_PAYMENT_ATTEMPT_STORE_GRANT_EXPIRED: true,
  CONTROL_PAYMENT_ATTEMPT_STORE_POTENTIAL_EXPOSURE: true,
  CONTROL_PAYMENT_ATTEMPT_STORE_REQUIREMENT_UNAVAILABLE: true,
  CONTROL_PAYMENT_ATTEMPT_STORE_IDEMPOTENCY_CONFLICT: true,
  CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE: true,
  CONTROL_PAYMENT_ATTEMPT_STORE_OUTCOME_UNKNOWN: true,
} as const satisfies Record<ControlPaymentAttemptStoreErrorCode, true>;

export type CommercePaymentStoreErrorCode =
  keyof typeof CONTROL_PAYMENT_ATTEMPT_STORE_ERROR_CODES;

/**
 * The exact HTTP mapping per store code, itself exhaustive over the store
 * vocabulary. Exported so the mapping table is tested directly.
 */
export const COMMERCE_PAYMENT_STORE_ERROR_MAPPING = Object.freeze({
  CONTROL_PAYMENT_ATTEMPT_STORE_INPUT_INVALID: invalidInput,
  // The presented commerce or browser authority is not currently valid.
  CONTROL_PAYMENT_ATTEMPT_STORE_SESSION_INVALID: unauthenticated,
  // Cross-actor and unknown targets are the same fixed denial: no oracle.
  CONTROL_PAYMENT_ATTEMPT_STORE_FORBIDDEN: forbidden,
  CONTROL_PAYMENT_ATTEMPT_STORE_NOT_FOUND: forbidden,
  // An existing row with different terms (reused requirement or attempt id).
  CONTROL_PAYMENT_ATTEMPT_STORE_CONFLICT: policyDenied,
  // Already dispatched, wrong state, wrong pay-to or a consumed grant. A fixed
  // non-retryable 409 that never reads as success and never claims a payment.
  CONTROL_PAYMENT_ATTEMPT_STORE_ATTEMPT_CONFLICT: policyDenied,
  // Terminal 409, like the action and grant families: not a 401, not a 503.
  CONTROL_PAYMENT_ATTEMPT_STORE_GRANT_EXPIRED: grantExpired,
  // Held exposure is reported as such and NEVER as a release.
  CONTROL_PAYMENT_ATTEMPT_STORE_POTENTIAL_EXPOSURE: budgetReservationConflict,
  // Not admissible in this deployment (e.g. internal_fixture provenance):
  // an operator dependency and not a provenance oracle, so the fixed 503.
  CONTROL_PAYMENT_ATTEMPT_STORE_REQUIREMENT_UNAVAILABLE: unavailable,
  CONTROL_PAYMENT_ATTEMPT_STORE_IDEMPOTENCY_CONFLICT: idempotencyConflict,
  CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE: unavailable,
  // Terminal and the one non-503 dependency failure: do not send, do not retry.
  CONTROL_PAYMENT_ATTEMPT_STORE_OUTCOME_UNKNOWN: outcomeUnknown,
} as const satisfies Record<ControlPaymentAttemptStoreErrorCode, () => AuthApiError>);

function rawErrorCode(error: unknown): string | null {
  if (typeof error !== "object" || error === null) return null;
  const code = (error as { code?: unknown }).code;
  return typeof code === "string" ? code : null;
}

function storeErrorCode(error: unknown): CommercePaymentStoreErrorCode | null {
  const code = rawErrorCode(error);
  if (code === null) return null;
  return Object.hasOwn(CONTROL_PAYMENT_ATTEMPT_STORE_ERROR_CODES, code)
    ? (code as CommercePaymentStoreErrorCode)
    : null;
}

function mapStoreError(error: unknown): never {
  if (error instanceof AuthApiError) throw error;
  const code = storeErrorCode(error);
  if (code === null) throw unavailable();
  throw COMMERCE_PAYMENT_STORE_ERROR_MAPPING[code]();
}

/**
 * Commerce-session repository failures collapse to a fixed 401 without an
 * existence oracle. Genuine outages stay 503; an unknown outcome stays 500.
 */
function mapCommerceSessionError(error: unknown): never {
  if (error instanceof AuthApiError) throw error;
  const code = rawErrorCode(error);
  if (
    code === "COMMERCE_SESSION_STORE_UNAVAILABLE" ||
    code === "COMMERCE_SESSION_STORE_OUTCOME_UNKNOWN" ||
    code === "CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE"
  ) {
    throw unavailable();
  }
  if (code === "CONTROL_PAYMENT_ATTEMPT_STORE_OUTCOME_UNKNOWN") {
    throw outcomeUnknown();
  }
  throw unauthenticated();
}

/** The agent action read uses the action store's own vocabulary. */
function mapActionReadError(error: unknown): never {
  if (error instanceof AuthApiError) throw error;
  switch (rawErrorCode(error)) {
    case "CONTROL_ACTION_STORE_INPUT_INVALID":
      throw invalidInput();
    case "CONTROL_ACTION_STORE_SESSION_INVALID":
      throw unauthenticated();
    case "CONTROL_ACTION_STORE_FORBIDDEN":
    case "CONTROL_ACTION_STORE_NOT_FOUND":
      throw forbidden();
    case "CONTROL_ACTION_STORE_OUTCOME_UNKNOWN":
      throw outcomeUnknown();
    default:
      throw unavailable();
  }
}

function parseRequest<T>(schema: ZodType<T>, input: unknown): T {
  const parsed = schema.safeParse(input);
  if (!parsed.success) throw invalidInput();
  return parsed.data;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

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

interface TrustedCommerceSession {
  readonly sessionId: string;
  readonly organizationId: string;
  readonly subjectAgentId: string;
  readonly policyId: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly exchangedAt: string | null;
}

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
    left.exchangedAt === right.exchangedAt
  );
}

const AGENT_TOKEN = /^oacs_v1_[A-Za-z0-9_-]{43}(?![\s\S])/u;

export class CommercePaymentService {
  readonly #auth: CommercePaymentAuthPort;
  readonly #store: CommercePaymentStorePort;
  readonly #commerceSessions: CommercePaymentSessionReadPort;
  readonly #actions: CommercePaymentActionReadPort;
  readonly #limits: CommercePaymentRateLimiter;

  constructor(options: CommercePaymentServiceOptions) {
    this.#auth = options.auth;
    this.#store = options.store;
    this.#commerceSessions = options.commerceSessions;
    this.#actions = options.actions;
    this.#limits = options.limits;
  }

  /* ---------------------------------------------------------------- */
  /* commerce_payment_terms (browser)                                  */
  /* ---------------------------------------------------------------- */

  /**
   * Seller human records the immutable pay-to of one listing version. The
   * database requires a fresh non-recovery owner/provider_admin session of the
   * owning organization. A lost response is recovered by an EXACT replay: the
   * same idempotency key and mutation id return `replayed: true`.
   */
  async recordListingPaymentTerms(
    ctx: AuthRequestContext,
    organizationId: unknown,
    listingId: unknown,
    version: unknown,
    envelope: CommercePaymentWriteEnvelope,
  ): Promise<CommercePaymentTermsData> {
    const organization = parseRequest(CommerceOrganizationIdSchema, organizationId);
    const listing = parseRequest(CommerceListingIdSchema, listingId);
    const listingVersion = parseRequest(CommerceListingVersionSchema, version);
    const body = parseRequest(CommercePaymentTermsBodySchema, envelope.body);
    const idempotencyKey = parseRequest(
      CommerceTenantIdempotencyKeySchema,
      envelope.idempotencyKey,
    );
    this.#auth.verifyCsrf(ctx.cookies, envelope.csrf);
    const begun = await this.#auth.beginTenantRead(ctx);
    await this.#limits.consumeAll([
      {
        family: "terms",
        bucket: "account",
        value: begun.accountId,
        limit: COMMERCE_PAYMENT_RATE_LIMITS.terms.account,
      },
    ]);
    let raw: unknown;
    try {
      raw = await this.#store.recordListingPaymentTerms(
        begun.sessionHash,
        organization,
        listing,
        listingVersion,
        { payToAddress: body.payToAddress },
        { idempotencyKey, mutationId: body.mutationId },
      );
    } catch (error) {
      mapStoreError(error);
    }
    if (!isRecord(raw)) throw projectionFailure();
    requireExactKeys(raw, ["replayed", "terms", "receipt"]);
    const data = CommercePaymentTermsDataSchema.safeParse({
      replayed: raw["replayed"],
      terms: raw["terms"],
      receipt: raw["receipt"],
    });
    if (!data.success) throw projectionFailure();
    if (
      data.data.terms.organizationId !== organization ||
      data.data.terms.listingId !== listing ||
      data.data.terms.version !== listingVersion ||
      data.data.terms.payToAddress !== body.payToAddress.toLowerCase() ||
      data.data.receipt.mutationId !== body.mutationId ||
      data.data.receipt.operation !== TERMS_OPERATION
    ) {
      throw projectionFailure();
    }
    return data.data;
  }

  /* ---------------------------------------------------------------- */
  /* commerce_payment_attempt (agent)                                  */
  /* ---------------------------------------------------------------- */

  async registerRequirement(
    token: unknown,
    peerIp: string,
    envelope: CommercePaymentAgentEnvelope,
  ): Promise<CommercePaymentVerifiedRequirement> {
    const presented = this.#requireCommerceSessionToken(token);
    const body = parseRequest(CommercePaymentRequirementBodySchema, envelope.body);
    await this.#consumeAgentLimits("requirement", peerIp, presented);
    const sessionHash = this.#hashCommerceSession(presented);
    const current = await this.#currentCommerceSession(sessionHash);
    let raw: unknown;
    try {
      raw = await this.#store.registerVerifiedRequirement(sessionHash, {
        requirementId: body.requirementId,
        listingId: body.listingId,
      });
    } catch (error) {
      mapStoreError(error);
    }
    const data = CommercePaymentVerifiedRequirementSchema.safeParse(raw);
    if (!data.success) throw projectionFailure();
    if (
      data.data.organizationId !== current.organizationId ||
      data.data.requirementId !== body.requirementId ||
      data.data.listingId !== body.listingId
    ) {
      throw projectionFailure();
    }
    return data.data;
  }

  /**
   * Persist the lane attempt BEFORE any signature may leave the lane. The
   * binding is rebuilt here; the caller's `bindingDigest` must equal the digest
   * of that server-built binding or the store refuses it.
   */
  async persistAttempt(
    token: unknown,
    peerIp: string,
    envelope: CommercePaymentAgentEnvelope,
  ): Promise<CommercePaymentAttemptPersistData> {
    const presented = this.#requireCommerceSessionToken(token);
    const body = parseRequest(CommercePaymentAttemptPersistBodySchema, envelope.body);
    await this.#consumeAgentLimits("attempt", peerIp, presented);
    const sessionHash = this.#hashCommerceSession(presented);
    const current = await this.#currentCommerceSession(sessionHash);
    const action = await this.#agentAction(sessionHash, body.actionId, current);
    const binding: CommercePaymentBindingInput = {
      schemaVersion: COMMERCE_PAYMENT_BINDING_SCHEMA_VERSION,
      role: COMMERCE_PAYMENT_BINDING_ROLE,
      network: COMMERCE_PAYMENT_NETWORK,
      grantId: body.grantId,
      actionId: body.actionId,
      attemptId: body.attemptId,
      grantRequirementDigest: action.requirementDigest,
      laneRequirementDigest: body.laneRequirementDigest,
      verifyingContract: COMMERCE_PAYMENT_VERIFYING_CONTRACT,
      asset: COMMERCE_PAYMENT_ASSET_ADDRESS,
      from: body.from,
      to: body.to,
      value: action.amountAtomic,
      validAfter: body.validAfter,
      validBefore: body.validBefore,
      nonce: body.nonce,
    };
    let raw: unknown;
    try {
      raw = await this.#store.persistBuyerAttempt(sessionHash, {
        binding,
        bindingDigest: body.bindingDigest,
      });
    } catch (error) {
      mapStoreError(error);
    }
    if (!isRecord(raw)) throw projectionFailure();
    requireExactKeys(raw, ["replayed", "attempt"]);
    const data = CommercePaymentAttemptPersistDataSchema.safeParse({
      replayed: raw["replayed"],
      attempt: raw["attempt"],
    });
    if (!data.success) throw projectionFailure();
    const attempt = data.data.attempt;
    if (
      attempt.organizationId !== current.organizationId ||
      attempt.attemptId !== body.attemptId ||
      attempt.grantId !== body.grantId ||
      attempt.actionId !== body.actionId ||
      attempt.bindingDigest !== body.bindingDigest ||
      attempt.valueAtomic !== action.amountAtomic ||
      attempt.requirementDigest !== action.requirementDigest
    ) {
      throw projectionFailure();
    }
    return data.data;
  }

  /**
   * Record the ONE dispatch of a persisted attempt. It commits before the lane
   * may send. A second call is a fixed 409 and never a success.
   */
  async dispatchAttempt(
    token: unknown,
    peerIp: string,
    attemptId: unknown,
    envelope: CommercePaymentAgentEnvelope,
  ): Promise<CommercePaymentAttemptDispatchData> {
    const presented = this.#requireCommerceSessionToken(token);
    const attempt = parseRequest(CommerceGrantAttemptIdSchema, attemptId);
    const body = parseRequest(CommercePaymentAttemptDispatchBodySchema, envelope.body);
    await this.#consumeAgentLimits("dispatch", peerIp, presented);
    const sessionHash = this.#hashCommerceSession(presented);
    const current = await this.#currentCommerceSession(sessionHash);
    let raw: unknown;
    try {
      raw = await this.#store.recordAttemptDispatch(sessionHash, {
        attemptId: attempt,
        bindingDigest: body.bindingDigest,
      });
    } catch (error) {
      mapStoreError(error);
    }
    const data = CommercePaymentAttemptDispatchDataSchema.safeParse({ attempt: raw });
    if (!data.success) throw projectionFailure();
    if (
      data.data.attempt.organizationId !== current.organizationId ||
      data.data.attempt.attemptId !== attempt ||
      data.data.attempt.bindingDigest !== body.bindingDigest
    ) {
      throw projectionFailure();
    }
    return data.data;
  }

  /**
   * Restart recovery by the lane's own attempt id. Missing and foreign are the
   * same `item: null`, and the current session is checked before AND after.
   */
  async getAttempt(
    token: unknown,
    peerIp: string,
    request: unknown,
  ): Promise<CommercePaymentAttemptReadData> {
    const presented = this.#requireCommerceSessionToken(token);
    const parsed = parseRequest(CommercePaymentAttemptReadRequestSchema, request);
    await this.#consumeReadLimits(peerIp, presented);
    const sessionHash = this.#hashCommerceSession(presented);
    const before = await this.#currentCommerceSession(sessionHash);
    let raw: unknown;
    try {
      raw = await this.#store.readAgentAttempt(sessionHash, parsed.attemptId);
    } catch (error) {
      mapStoreError(error);
    }
    const after = await this.#currentCommerceSession(sessionHash);
    if (!sameCommerceSession(before, after)) throw projectionFailure();
    if (!isRecord(raw)) throw projectionFailure();
    requireExactKeys(raw, ["attemptId", "item"]);
    if (raw["attemptId"] !== parsed.attemptId) throw projectionFailure();
    const data = CommercePaymentAttemptReadDataSchema.safeParse({
      attemptId: parsed.attemptId,
      item: raw["item"],
    });
    if (!data.success) throw projectionFailure();
    if (
      data.data.item !== null &&
      data.data.item.organizationId !== before.organizationId
    ) {
      throw projectionFailure();
    }
    return data.data;
  }

  /* ---------------------------------------------------------------- */
  /* Internal helpers                                                  */
  /* ---------------------------------------------------------------- */

  /**
   * Exactly a canonical `oacs_v1_` commerce session. An `oas_ag_` machine
   * credential, an `oas_pr_` provider session and a raw grant token are all
   * refused before any limiter, hash or store work.
   */
  #requireCommerceSessionToken(token: unknown): string {
    if (typeof token !== "string" || !AGENT_TOKEN.test(token)) {
      throw unauthenticated();
    }
    return token;
  }

  #hashCommerceSession(token: string): string {
    try {
      return hashCommerceSessionToken(token);
    } catch {
      throw unauthenticated();
    }
  }

  async #currentCommerceSession(sessionHash: string): Promise<TrustedCommerceSession> {
    let raw: unknown;
    try {
      raw = await this.#commerceSessions.getCommerceSessionByHash(sessionHash);
    } catch (error) {
      mapCommerceSessionError(error);
    }
    return trustedCommerceSession(raw);
  }

  /** The buyer's own authorized action, the ONLY source of value and digest. */
  async #agentAction(
    sessionHash: string,
    actionId: string,
    current: TrustedCommerceSession,
  ): Promise<{ amountAtomic: string; requirementDigest: string }> {
    let raw: unknown;
    try {
      raw = await this.#actions.getAgentCommerceAction(sessionHash, actionId);
    } catch (error) {
      mapActionReadError(error);
    }
    if (!isRecord(raw)) throw projectionFailure();
    if (raw["organizationId"] !== current.organizationId) throw projectionFailure();
    // A missing and a foreign action are the same fixed denial.
    if (raw["item"] === null) throw forbidden();
    const item = CommerceActionMetadataSchema.safeParse(raw["item"]);
    if (!item.success) throw projectionFailure();
    if (item.data.actionId !== actionId) throw projectionFailure();
    return {
      amountAtomic: item.data.amountAtomic,
      requirementDigest: item.data.requirementDigest,
    };
  }

  async #consumeAgentLimits(
    family: Exclude<CommercePaymentRateFamily, "terms" | "read">,
    peerIp: string,
    presented: string,
  ): Promise<void> {
    const limits = COMMERCE_PAYMENT_RATE_LIMITS[family];
    await this.#limits.consumeAll([
      { family, bucket: "global", value: "*", limit: limits.global },
      { family, bucket: "peer", value: peerIp, limit: limits.peer },
      { family, bucket: "token", value: presented, limit: limits.token },
    ]);
  }

  async #consumeReadLimits(peerIp: string, presented: string): Promise<void> {
    const limits = COMMERCE_PAYMENT_RATE_LIMITS.read;
    await this.#limits.consumeAll([
      { family: "read", bucket: "global", value: "*", limit: limits.global },
      { family: "read", bucket: "peer", value: peerIp, limit: limits.peer },
      { family: "read", bucket: "subject", value: presented, limit: limits.subject },
    ]);
  }
}
