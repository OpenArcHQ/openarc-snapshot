import {
  CommerceActionAgentDetailRequestSchema,
  CommerceActionAgentMutationRequestSchema,
  CommerceActionAuthorizeBodySchema,
  CommerceActionCancelBodySchema,
  CommerceActionDecisionBodySchema,
  CommerceActionDetailRequestSchema,
  CommerceActionDetailSchema,
  CommerceActionHumanMutationRequestSchema,
  CommerceActionIdSchema,
  CommerceActionListRequestSchema,
  CommerceActionMetadataSchema,
  CommerceActionMutationDataSchema,
  CommerceActionMutationReceiptSchema,
  CommerceActionMutationStatusSchema,
  CommerceActionPageSchema,
  CommerceApprovalDetailRequestSchema,
  CommerceApprovalDetailSchema,
  CommerceApprovalListRequestSchema,
  CommerceApprovalPageSchema,
  CommerceControlSessionMetadataSchema,
  CommerceExposureDataSchema,
  CommerceExposureRequestSchema,
  CommerceOrganizationIdSchema,
  CommerceTenantIdempotencyKeySchema,
  type CommerceActionDetail,
  type CommerceActionMutationData,
  type CommerceActionMutationReceipt,
  type CommerceActionMutationStatus,
  type CommerceActionPage,
  type CommerceApprovalDetail,
  type CommerceApprovalPage,
  type CommerceExposureData,
} from "@openarc/shared";
import type { ControlActionStoreErrorCode } from "@openarc/db";
import type { ZodType } from "zod";

import { AUTH_ERRORS, AuthApiError } from "../auth/errors.js";
import type { AuthRequestContext } from "../auth/service.js";
import { hashCommerceSessionToken } from "./session-crypto.js";
import {
  COMMERCE_ACTION_RATE_LIMITS,
  type CommerceActionRateLimiter,
} from "./action-rate-limiter.js";
import type {
  CommerceActionAuthPort,
  CommerceActionMutationMetadata,
  CommerceActionStorePort,
  CommerceSessionReadPort,
} from "./action-ports.js";

/**
 * Orchestration for the commerce-action HTTP slice.
 *
 * Browser reads parse the request BEFORE any auth work, then `beginTenantRead`,
 * the bounded read limiter, EXACTLY ONE store read, the `finishTenantRead`
 * guard (even for a null/not-found result) and only then DTO validation and
 * binding. Browser writes parse, verify CSRF, begin the live session, take the
 * decision limiter and invoke EXACTLY ONE store mutation with no post-commit
 * live-session check.
 *
 * Agent calls resolve the CURRENT commerce session behind the presented bearer
 * before anything is disclosed. Agent reads additionally re-resolve it after
 * the store read and require both snapshots to match, so a session revoked
 * mid-read can never leak a replay, conflict or status. A missing result
 * (`not_found`, `item: null`) takes the same authorization path as a present
 * one: absence is never a shortcut past the current-authorization check.
 *
 * An UNKNOWN store outcome is terminal: it maps to its OWN fixed non-retryable
 * "outcome unknown" 500 — deliberately not the 503 every other dependency
 * failure collapses to — and this service never retries, re-dispatches,
 * substitutes an idempotency key, polls, reports it as success, or describes it
 * as a refund, release, payment, settlement or delivery. The caller's own
 * recovery path is the bounded mutation-status read, which returns only the
 * accepted `not_found` / `committed` union bound to the current caller.
 *
 * Authorizing an action is a bounded control decision. It is NOT a payment, a
 * settlement, a delivery or a grant, and nothing here moves funds.
 *
 * Money crosses this service only as canonical integer strings from the
 * accepted schemas; no amount is ever parsed into a JS number.
 */

/** Absent list limit is bounded to 25 by this port, not only the shared max 50. */
const DEFAULT_LIST_LIMIT = 25;

const AUTHORIZE_OPERATION = "control.commerce_action.authorize" as const;
const APPROVE_OPERATION = "control.commerce_action.approve" as const;
const REJECT_OPERATION = "control.commerce_action.reject" as const;
const CANCEL_OPERATION = "control.commerce_action.cancel" as const;

/** A browser mutation status may only report a browser-family operation. */
const HUMAN_OPERATIONS: ReadonlySet<string> = new Set([
  APPROVE_OPERATION,
  REJECT_OPERATION,
  CANCEL_OPERATION,
]);

/** An agent mutation status may only ever report `authorize`. */
const AGENT_OPERATIONS: ReadonlySet<string> = new Set([AUTHORIZE_OPERATION]);

export interface CommerceActionServiceOptions {
  readonly auth: CommerceActionAuthPort;
  readonly store: CommerceActionStorePort;
  readonly commerceSessions: CommerceSessionReadPort;
  readonly limits: CommerceActionRateLimiter;
}

export interface CommerceActionWriteEnvelope {
  readonly csrf: unknown;
  readonly idempotencyKey: unknown;
  readonly body: unknown;
}

export interface CommerceActionAgentEnvelope {
  readonly idempotencyKey: unknown;
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

function budgetLimitExceeded(): AuthApiError {
  return new AuthApiError("BUDGET_LIMIT_EXCEEDED", 409, "INVALID_REQUEST");
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
 * A store that cannot say whether its money-adjacent write committed is a
 * DEFINITIVE 500, deliberately NOT the 503 that every other dependency failure
 * collapses to: a 503 reads as a transient outage that a client, agent or proxy
 * may safely repeat, and repeating an unknown-outcome authorization is exactly
 * the double-spend this surface must never invite. The wire code stays the
 * fixed non-echoing `INTERNAL_ERROR`, so the distinction discloses nothing
 * about the action, the organization or the store; it claims no payment,
 * settlement, delivery or grant lane; it never claims success; and it never
 * implies a reversal, refund or release. Recovery is only ever the caller's own
 * bounded mutation-status read with the SAME logical mutation id.
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
 * Fixed commerce-action store failure vocabulary: the EXACT and COMPLETE DB10
 * `ControlActionStoreError` code list.
 *
 * The concrete DB10/DB11 store is authored independently, so the mapping is
 * STRUCTURAL on the error `code` rather than an `instanceof` against a class
 * this module must not import. An unrecognized shape is an unavailable
 * dependency, never a success and never a caller error.
 *
 * There is deliberately NO `APPROVAL_REQUIRED` member: an above-threshold or
 * always-approve policy is a SUCCESS outcome in DB10, which routes the action
 * to `pending_approval` with a ZERO reservation and returns it normally. This
 * service therefore never turns an approval requirement into an error.
 */
/**
 * Compile-time coupling to DB10's real error vocabulary.
 *
 * `Record<ControlActionStoreErrorCode, true>` requires EVERY code DB10 declares
 * to appear here, so adding one upstream breaks the build; `satisfies` rejects
 * any key DB10 does not declare, so a rename or removal breaks it too. Without
 * this, a renamed store code would silently fall through to the unrecognized
 * 503 branch and, worse, an OUTCOME_UNKNOWN would lose its distinct
 * non-retryable mapping. The import is type-only and therefore erased, so this
 * adds no runtime dependency on the store and the service stays testable with
 * injected fakes.
 */
const CONTROL_ACTION_STORE_ERROR_CODES = {
  CONTROL_ACTION_STORE_INPUT_INVALID: true,
  CONTROL_ACTION_STORE_SESSION_INVALID: true,
  CONTROL_ACTION_STORE_FORBIDDEN: true,
  CONTROL_ACTION_STORE_NOT_FOUND: true,
  CONTROL_ACTION_STORE_CONFLICT: true,
  CONTROL_ACTION_STORE_EXPIRED: true,
  CONTROL_ACTION_STORE_IDEMPOTENCY_CONFLICT: true,
  CONTROL_ACTION_STORE_BUDGET_DENIED: true,
  CONTROL_ACTION_STORE_POTENTIAL_EXPOSURE: true,
  CONTROL_ACTION_STORE_REQUIREMENT_UNAVAILABLE: true,
  CONTROL_ACTION_STORE_STALE_TERMS: true,
  CONTROL_ACTION_STORE_OUTCOME_UNKNOWN: true,
  CONTROL_ACTION_STORE_UNAVAILABLE: true,
} as const satisfies Record<ControlActionStoreErrorCode, true>;

export type CommerceActionStoreErrorCode =
  keyof typeof CONTROL_ACTION_STORE_ERROR_CODES;

/** Raw `.code` extraction with no vocabulary assumption. */
function rawErrorCode(error: unknown): string | null {
  if (typeof error !== "object" || error === null) return null;
  const code = (error as { code?: unknown }).code;
  return typeof code === "string" ? code : null;
}

/**
 * Narrows to DB10's vocabulary only. An unrecognized string returns null, which
 * every caller treats as the unrecognized case and fails closed on.
 */
function storeErrorCode(
  error: unknown,
): CommerceActionStoreErrorCode | null {
  const code = rawErrorCode(error);
  if (code === null) return null;
  return Object.hasOwn(CONTROL_ACTION_STORE_ERROR_CODES, code)
    ? (code as CommerceActionStoreErrorCode)
    : null;
}

function mapStoreError(error: unknown): never {
  if (error instanceof AuthApiError) throw error;
  switch (storeErrorCode(error)) {
    case "CONTROL_ACTION_STORE_INPUT_INVALID":
      throw invalidInput();
    case "CONTROL_ACTION_STORE_SESSION_INVALID":
      throw unauthenticated();
    case "CONTROL_ACTION_STORE_FORBIDDEN":
    case "CONTROL_ACTION_STORE_NOT_FOUND":
      // A cross-actor or unknown target is the same fixed denial: no
      // organization/action existence oracle is exposed by the transport.
      throw forbidden();
    case "CONTROL_ACTION_STORE_CONFLICT":
      throw policyDenied();
    // Terminal, and deliberately a 409 rather than a 401 or a 503. The target's
    // own authority lapsed: re-authenticating and repeating cannot help, and a
    // 5xx would invite a proxy or agent to retry a money-adjacent write. The
    // caller must re-read current state, not resend.
    case "CONTROL_ACTION_STORE_EXPIRED":
      throw policyDenied();
    case "CONTROL_ACTION_STORE_IDEMPOTENCY_CONFLICT":
      throw idempotencyConflict();
    case "CONTROL_ACTION_STORE_BUDGET_DENIED":
      // The store's own budget assessment answered `denied`. A deterministic,
      // caller-visible refusal that moved no funds and reserved nothing.
      throw budgetLimitExceeded();
    case "CONTROL_ACTION_STORE_POTENTIAL_EXPOSURE":
      // A cancel refused because the action still carries an unresolved or
      // already-claimed budget reservation. The conflict is with that live
      // reservation, so it is reported as such and NEVER as a release.
      throw budgetReservationConflict();
    case "CONTROL_ACTION_STORE_STALE_TERMS":
      // The policy terms the request pinned are no longer the terms in force.
      // The applicable policy therefore denies it; the caller must re-read the
      // current terms and submit a NEW logical mutation, never repeat this one.
      throw policyDenied();
    case "CONTROL_ACTION_STORE_REQUIREMENT_UNAVAILABLE":
      // The requirement cannot be admitted by THIS deployment. That is a
      // dependency the operator must fix, not a request the caller can correct,
      // and it must not become a provenance oracle, so it stays the fixed 503.
      throw unavailable();
    case "CONTROL_ACTION_STORE_OUTCOME_UNKNOWN":
      // Terminal, and the one mapping that is NOT the generic 503. No retry,
      // no re-dispatch, no reversal claim.
      throw outcomeUnknown();
    case "CONTROL_ACTION_STORE_UNAVAILABLE":
    default:
      throw unavailable();
  }
}

/**
 * Commerce-session repository failures during agent calls collapse to the same
 * fixed 401 without an existence oracle. Genuine outages stay a 503.
 */
function mapCommerceSessionError(error: unknown): never {
  if (error instanceof AuthApiError) throw error;
  // Raw, because this path matches the commerce-SESSION vocabulary alongside
  // the action one; narrowing to DB10 codes here would discard the session
  // outage codes and silently downgrade a genuine outage to a 401.
  const code = rawErrorCode(error);
  if (
    code === "COMMERCE_SESSION_STORE_UNAVAILABLE" ||
    code === "COMMERCE_SESSION_STORE_OUTCOME_UNKNOWN" ||
    code === "CONTROL_ACTION_STORE_UNAVAILABLE" ||
    code === "CONTROL_ACTION_STORE_OUTCOME_UNKNOWN"
  ) {
    throw unavailable();
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
 * extra key can never be silently stripped into a passing projection.
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
 * Exact canonical decimal limit to a bounded integer. The wire limit is a
 * canonical `1..50` string, so this is an exact small-integer conversion and
 * never a coercion of caller text. Money is never converted this way.
 */
function limitToInteger(limit: string | undefined): number | undefined {
  if (limit === undefined) return undefined;
  if (!/^(?:[1-9]|[1-4][0-9]|50)(?![\s\S])/u.test(limit)) throw invalidInput();
  return Number(limit);
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

export class CommerceActionService {
  readonly #auth: CommerceActionAuthPort;
  readonly #store: CommerceActionStorePort;
  readonly #commerceSessions: CommerceSessionReadPort;
  readonly #limits: CommerceActionRateLimiter;

  constructor(options: CommerceActionServiceOptions) {
    this.#auth = options.auth;
    this.#store = options.store;
    this.#commerceSessions = options.commerceSessions;
    this.#limits = options.limits;
  }

  /* ---------------------------------------------------------------- */
  /* Browser reads                                                     */
  /* ---------------------------------------------------------------- */

  async listActions(
    ctx: AuthRequestContext,
    request: unknown,
  ): Promise<CommerceActionPage> {
    const parsed = parseRequest(CommerceActionListRequestSchema, request);
    const begun = await this.#auth.beginTenantRead(ctx);
    await this.#consumeReadLimits(ctx, begun.accountId);
    const limit = limitToInteger(parsed.limit);
    let raw: unknown;
    try {
      raw = await this.#store.listCommerceActions(
        begun.sessionHash,
        parsed.organizationId,
        {
          ...(parsed.afterActionId !== undefined
            ? { afterActionId: parsed.afterActionId }
            : {}),
          ...(limit !== undefined ? { limit } : {}),
        },
      );
    } catch (error) {
      mapStoreError(error);
    }
    await this.#auth.finishTenantRead(ctx, begun);
    if (!isRecord(raw)) throw projectionFailure();
    requireExactKeys(raw, ["items", "nextCursor"]);
    const page = CommerceActionPageSchema.safeParse({
      organizationId: parsed.organizationId,
      items: raw["items"],
      nextCursor: raw["nextCursor"],
    });
    if (!page.success) throw projectionFailure();
    if (page.data.items.length > (limit ?? DEFAULT_LIST_LIMIT)) {
      throw projectionFailure();
    }
    if (parsed.afterActionId !== undefined) {
      const first = page.data.items[0]?.actionId;
      if (first !== undefined && first <= parsed.afterActionId) {
        throw projectionFailure();
      }
    }
    return page.data;
  }

  async listApprovals(
    ctx: AuthRequestContext,
    request: unknown,
  ): Promise<CommerceApprovalPage> {
    const parsed = parseRequest(CommerceApprovalListRequestSchema, request);
    const begun = await this.#auth.beginTenantRead(ctx);
    await this.#consumeReadLimits(ctx, begun.accountId);
    const limit = limitToInteger(parsed.limit);
    let raw: unknown;
    try {
      raw = await this.#store.listCommerceApprovals(
        begun.sessionHash,
        parsed.organizationId,
        {
          ...(parsed.afterApprovalId !== undefined
            ? { afterApprovalId: parsed.afterApprovalId }
            : {}),
          ...(limit !== undefined ? { limit } : {}),
        },
      );
    } catch (error) {
      mapStoreError(error);
    }
    await this.#auth.finishTenantRead(ctx, begun);
    if (!isRecord(raw)) throw projectionFailure();
    requireExactKeys(raw, ["items", "nextCursor"]);
    const page = CommerceApprovalPageSchema.safeParse({
      organizationId: parsed.organizationId,
      items: raw["items"],
      nextCursor: raw["nextCursor"],
    });
    if (!page.success) throw projectionFailure();
    if (page.data.items.length > (limit ?? DEFAULT_LIST_LIMIT)) {
      throw projectionFailure();
    }
    if (parsed.afterApprovalId !== undefined) {
      const first = page.data.items[0]?.approvalId;
      if (first !== undefined && first <= parsed.afterApprovalId) {
        throw projectionFailure();
      }
    }
    return page.data;
  }

  async getAction(
    ctx: AuthRequestContext,
    request: unknown,
  ): Promise<CommerceActionDetail> {
    const parsed = parseRequest(CommerceActionDetailRequestSchema, request);
    const begun = await this.#auth.beginTenantRead(ctx);
    await this.#consumeReadLimits(ctx, begun.accountId);
    let raw: unknown;
    try {
      raw = await this.#store.getCommerceAction(
        begun.sessionHash,
        parsed.organizationId,
        parsed.actionId,
      );
    } catch (error) {
      mapStoreError(error);
    }
    // A missing item is still an authorized read: the finish guard runs before
    // anything (including absence) is disclosed.
    await this.#auth.finishTenantRead(ctx, begun);
    return this.#projectActionDetail(
      raw,
      parsed.organizationId,
      parsed.actionId,
    );
  }

  async getApproval(
    ctx: AuthRequestContext,
    request: unknown,
  ): Promise<CommerceApprovalDetail> {
    const parsed = parseRequest(CommerceApprovalDetailRequestSchema, request);
    const begun = await this.#auth.beginTenantRead(ctx);
    await this.#consumeReadLimits(ctx, begun.accountId);
    let raw: unknown;
    try {
      raw = await this.#store.getCommerceApproval(
        begun.sessionHash,
        parsed.organizationId,
        parsed.approvalId,
      );
    } catch (error) {
      mapStoreError(error);
    }
    await this.#auth.finishTenantRead(ctx, begun);
    if (!isRecord(raw)) throw projectionFailure();
    requireExactKeys(raw, ["organizationId", "item"]);
    // The raw organization is authoritative, never replaced by the requested
    // one: a foreign/invalid org (even with item:null) is a 503.
    if (raw["organizationId"] !== parsed.organizationId) {
      throw projectionFailure();
    }
    const detail = CommerceApprovalDetailSchema.safeParse({
      organizationId: parsed.organizationId,
      approvalId: parsed.approvalId,
      item: raw["item"],
    });
    if (!detail.success) throw projectionFailure();
    return detail.data;
  }

  /**
   * Declared exposure for one (organization, subject agent, policy). The result
   * is a recorded `asOf` declaration only: it is not a wallet balance, a spend
   * cap, a new permission, a payment lane or a liveness guarantee.
   */
  async getExposure(
    ctx: AuthRequestContext,
    request: unknown,
  ): Promise<CommerceExposureData> {
    const parsed = parseRequest(CommerceExposureRequestSchema, request);
    const begun = await this.#auth.beginTenantRead(ctx);
    await this.#consumeReadLimits(ctx, begun.accountId);
    let raw: unknown;
    try {
      raw = await this.#store.getCommerceExposure(
        begun.sessionHash,
        parsed.organizationId,
        parsed.subjectAgentId,
        parsed.policyId,
      );
    } catch (error) {
      mapStoreError(error);
    }
    await this.#auth.finishTenantRead(ctx, begun);
    if (!isRecord(raw)) throw projectionFailure();
    requireExactKeys(raw, [
      "organizationId",
      "subjectAgentId",
      "policyId",
      "item",
    ]);
    if (
      raw["organizationId"] !== parsed.organizationId ||
      raw["subjectAgentId"] !== parsed.subjectAgentId ||
      raw["policyId"] !== parsed.policyId
    ) {
      throw projectionFailure();
    }
    const data = CommerceExposureDataSchema.safeParse({
      organizationId: parsed.organizationId,
      subjectAgentId: parsed.subjectAgentId,
      policyId: parsed.policyId,
      item: raw["item"],
    });
    if (!data.success) throw projectionFailure();
    return data.data;
  }

  async getHumanMutationStatus(
    ctx: AuthRequestContext,
    request: unknown,
  ): Promise<CommerceActionMutationStatus> {
    const parsed = parseRequest(
      CommerceActionHumanMutationRequestSchema,
      request,
    );
    const begun = await this.#auth.beginTenantRead(ctx);
    await this.#consumeReadLimits(ctx, begun.accountId);
    let raw: unknown;
    try {
      raw = await this.#store.getHumanCommerceActionMutationStatus(
        begun.sessionHash,
        parsed.organizationId,
        parsed.mutationId,
      );
    } catch (error) {
      mapStoreError(error);
    }
    // A `not_found` recovery read is still an authorized read.
    await this.#auth.finishTenantRead(ctx, begun);
    return this.#projectMutationStatus(
      raw,
      parsed.mutationId,
      HUMAN_OPERATIONS,
    );
  }

  /* ---------------------------------------------------------------- */
  /* Browser writes                                                    */
  /* ---------------------------------------------------------------- */

  async approve(
    ctx: AuthRequestContext,
    organizationId: unknown,
    actionId: unknown,
    envelope: CommerceActionWriteEnvelope,
  ): Promise<CommerceActionMutationData> {
    return this.#decide(
      ctx,
      organizationId,
      actionId,
      envelope,
      APPROVE_OPERATION,
    );
  }

  async reject(
    ctx: AuthRequestContext,
    organizationId: unknown,
    actionId: unknown,
    envelope: CommerceActionWriteEnvelope,
  ): Promise<CommerceActionMutationData> {
    return this.#decide(
      ctx,
      organizationId,
      actionId,
      envelope,
      REJECT_OPERATION,
    );
  }

  async cancel(
    ctx: AuthRequestContext,
    organizationId: unknown,
    actionId: unknown,
    envelope: CommerceActionWriteEnvelope,
  ): Promise<CommerceActionMutationData> {
    return this.#decide(
      ctx,
      organizationId,
      actionId,
      envelope,
      CANCEL_OPERATION,
    );
  }

  /* ---------------------------------------------------------------- */
  /* Agent authorization and reads                                     */
  /* ---------------------------------------------------------------- */

  /**
   * Record an agent authorization decision for an existing requirement. This
   * is NOT a payment, settlement, delivery or grant, and it moves no funds.
   */
  async authorize(
    token: unknown,
    peerIp: string,
    envelope: CommerceActionAgentEnvelope,
  ): Promise<CommerceActionMutationData> {
    const presented = this.#requireCommerceSessionToken(token);
    const body = parseRequest(
      CommerceActionAuthorizeBodySchema,
      envelope.body,
    );
    const idempotencyKey = parseRequest(
      CommerceTenantIdempotencyKeySchema,
      envelope.idempotencyKey,
    );
    // Ordered global/peer/presented-token limiter BEFORE any hash or database
    // authority.
    await this.#limits.consumeAll([
      {
        family: "authorize",
        bucket: "global",
        value: "*",
        limit: COMMERCE_ACTION_RATE_LIMITS.authorize.global,
      },
      {
        family: "authorize",
        bucket: "peer",
        value: peerIp,
        limit: COMMERCE_ACTION_RATE_LIMITS.authorize.peer,
      },
      {
        family: "authorize",
        bucket: "token",
        value: presented,
        limit: COMMERCE_ACTION_RATE_LIMITS.authorize.token,
      },
    ]);
    const sessionHash = this.#hashCommerceSession(presented);
    // Authenticate the CURRENT caller before any store authority or disclosure.
    const current = await this.#currentCommerceSession(sessionHash);
    const metadata: CommerceActionMutationMetadata = {
      idempotencyKey,
      mutationId: body.mutationId,
    };
    let raw: unknown;
    try {
      raw = await this.#store.authorizeCommerceAction(
        sessionHash,
        { actionId: body.actionId, requirementId: body.requirementId },
        metadata,
      );
    } catch (error) {
      mapStoreError(error);
    }
    // No post-commit live-session re-read: a business mutation is never
    // retried, re-dispatched or re-evaluated after it has been committed.
    return this.#projectMutationData(raw, {
      operation: AUTHORIZE_OPERATION,
      mutationId: body.mutationId,
      actionId: body.actionId,
      organizationId: current.organizationId,
      requirementId: body.requirementId,
    });
  }

  async getAgentAction(
    token: unknown,
    peerIp: string,
    request: unknown,
  ): Promise<CommerceActionDetail> {
    const presented = this.#requireCommerceSessionToken(token);
    const parsed = parseRequest(
      CommerceActionAgentDetailRequestSchema,
      request,
    );
    await this.#consumeAgentReadLimits(peerIp, presented);
    const sessionHash = this.#hashCommerceSession(presented);
    const before = await this.#currentCommerceSession(sessionHash);
    let raw: unknown;
    try {
      raw = await this.#store.getAgentCommerceAction(
        sessionHash,
        parsed.actionId,
      );
    } catch (error) {
      mapStoreError(error);
    }
    const after = await this.#currentCommerceSession(sessionHash);
    if (!sameCommerceSession(before, after)) throw projectionFailure();
    return this.#projectActionDetail(
      raw,
      before.organizationId,
      parsed.actionId,
    );
  }

  async getAgentMutationStatus(
    token: unknown,
    peerIp: string,
    request: unknown,
  ): Promise<CommerceActionMutationStatus> {
    const presented = this.#requireCommerceSessionToken(token);
    const parsed = parseRequest(
      CommerceActionAgentMutationRequestSchema,
      request,
    );
    await this.#consumeAgentReadLimits(peerIp, presented);
    const sessionHash = this.#hashCommerceSession(presented);
    // The current-authorization check runs BEFORE and AFTER, including for a
    // `not_found` recovery read.
    const before = await this.#currentCommerceSession(sessionHash);
    let raw: unknown;
    try {
      raw = await this.#store.getAgentCommerceActionMutationStatus(
        sessionHash,
        parsed.mutationId,
      );
    } catch (error) {
      mapStoreError(error);
    }
    const after = await this.#currentCommerceSession(sessionHash);
    if (!sameCommerceSession(before, after)) throw projectionFailure();
    return this.#projectMutationStatus(
      raw,
      parsed.mutationId,
      AGENT_OPERATIONS,
    );
  }

  /* ---------------------------------------------------------------- */
  /* Internal helpers                                                  */
  /* ---------------------------------------------------------------- */

  async #decide(
    ctx: AuthRequestContext,
    organizationId: unknown,
    actionId: unknown,
    envelope: CommerceActionWriteEnvelope,
    operation:
      | typeof APPROVE_OPERATION
      | typeof REJECT_OPERATION
      | typeof CANCEL_OPERATION,
  ): Promise<CommerceActionMutationData> {
    const organization = parseRequest(
      CommerceOrganizationIdSchema,
      organizationId,
    );
    const action = parseRequest(CommerceActionIdSchema, actionId);
    const body = parseRequest(
      operation === CANCEL_OPERATION
        ? CommerceActionCancelBodySchema
        : CommerceActionDecisionBodySchema,
      envelope.body,
    );
    const idempotencyKey = parseRequest(
      CommerceTenantIdempotencyKeySchema,
      envelope.idempotencyKey,
    );
    // Input validation is complete; now CSRF, then the live-session begin.
    this.#auth.verifyCsrf(ctx.cookies, envelope.csrf);
    const begun = await this.#auth.beginTenantRead(ctx);
    await this.#limits.consumeAll([
      {
        family: "decision",
        bucket: "account",
        value: begun.accountId,
        limit: COMMERCE_ACTION_RATE_LIMITS.decision.account,
      },
    ]);
    const metadata: CommerceActionMutationMetadata = {
      idempotencyKey,
      mutationId: body.mutationId,
    };
    let raw: unknown;
    try {
      raw = await (operation === APPROVE_OPERATION
        ? this.#store.approveCommerceAction(
            begun.sessionHash,
            organization,
            action,
            metadata,
          )
        : operation === REJECT_OPERATION
          ? this.#store.rejectCommerceAction(
              begun.sessionHash,
              organization,
              action,
              metadata,
            )
          : this.#store.cancelCommerceAction(
              begun.sessionHash,
              organization,
              action,
              metadata,
            ));
    } catch (error) {
      mapStoreError(error);
    }
    return this.#projectMutationData(raw, {
      operation,
      mutationId: body.mutationId,
      actionId: action,
      organizationId: organization,
    });
  }

  #requireCommerceSessionToken(token: unknown): string {
    if (
      typeof token !== "string" ||
      !/^oacs_v1_[A-Za-z0-9_-]{43}(?![\s\S])/u.test(token)
    ) {
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
        limit: COMMERCE_ACTION_RATE_LIMITS.read.global,
      },
      {
        family: "read",
        bucket: "peer",
        value: ctx.peerIp,
        limit: COMMERCE_ACTION_RATE_LIMITS.read.peer,
      },
      {
        family: "read",
        bucket: "subject",
        value: accountId,
        limit: COMMERCE_ACTION_RATE_LIMITS.read.subject,
      },
    ]);
  }

  async #consumeAgentReadLimits(
    peerIp: string,
    presented: string,
  ): Promise<void> {
    await this.#limits.consumeAll([
      {
        family: "read",
        bucket: "global",
        value: "*",
        limit: COMMERCE_ACTION_RATE_LIMITS.read.global,
      },
      {
        family: "read",
        bucket: "peer",
        value: peerIp,
        limit: COMMERCE_ACTION_RATE_LIMITS.read.peer,
      },
      {
        family: "read",
        bucket: "subject",
        value: presented,
        limit: COMMERCE_ACTION_RATE_LIMITS.read.subject,
      },
    ]);
  }

  #projectActionDetail(
    raw: unknown,
    organizationId: string,
    actionId: string,
  ): CommerceActionDetail {
    if (!isRecord(raw)) throw projectionFailure();
    requireExactKeys(raw, ["organizationId", "item"]);
    // The raw organization is authoritative, never replaced by the requested or
    // token-derived one: a foreign/invalid org (even with item:null) is a 503.
    if (raw["organizationId"] !== organizationId) throw projectionFailure();
    const detail = CommerceActionDetailSchema.safeParse({
      organizationId,
      actionId,
      item: raw["item"],
    });
    if (!detail.success) throw projectionFailure();
    return detail.data;
  }

  #projectMutationData(
    raw: unknown,
    expected: {
      operation: string;
      mutationId: string;
      actionId: string;
      organizationId: string;
      requirementId?: string;
    },
  ): CommerceActionMutationData {
    if (!isRecord(raw)) throw projectionFailure();
    requireExactKeys(raw, ["replayed", "metadata", "receipt"]);
    const replayed = this.#requireReplayed(raw["replayed"]);
    const parsedMetadata = CommerceActionMetadataSchema.safeParse(
      raw["metadata"],
    );
    if (!parsedMetadata.success) throw projectionFailure();
    const metadata = parsedMetadata.data;
    if (
      metadata.actionId !== expected.actionId ||
      metadata.exposureKey.organizationId !== expected.organizationId
    ) {
      throw projectionFailure();
    }
    if (
      expected.requirementId !== undefined &&
      metadata.requirementId !== expected.requirementId
    ) {
      throw projectionFailure();
    }
    const receipt = this.#requireReceipt(
      raw["receipt"],
      expected.operation,
      expected.mutationId,
      expected.actionId,
    );
    const data = CommerceActionMutationDataSchema.safeParse({
      replayed,
      metadata,
      receipt,
    });
    if (!data.success) throw projectionFailure();
    return data.data;
  }

  #projectMutationStatus(
    raw: unknown,
    mutationId: string,
    operations: ReadonlySet<string>,
  ): CommerceActionMutationStatus {
    if (!isRecord(raw)) throw projectionFailure();
    if (raw["status"] === "not_found") {
      requireExactKeys(raw, ["status"]);
      const status = CommerceActionMutationStatusSchema.safeParse({
        status: "not_found",
      });
      if (!status.success) throw projectionFailure();
      return status.data;
    }
    if (raw["status"] !== "committed") throw projectionFailure();
    requireExactKeys(raw, ["status", "receipt"]);
    const status = CommerceActionMutationStatusSchema.safeParse({
      status: "committed",
      receipt: raw["receipt"],
    });
    if (!status.success || status.data.status !== "committed") {
      throw projectionFailure();
    }
    // The receipt must belong to the requested mutation AND to this family's
    // operations, so a browser read can never surface an agent authorization
    // and vice versa.
    if (
      status.data.receipt.mutationId !== mutationId ||
      !operations.has(status.data.receipt.operation)
    ) {
      throw projectionFailure();
    }
    return status.data;
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
    actionId: string,
  ): CommerceActionMutationReceipt {
    const parsed = CommerceActionMutationReceiptSchema.safeParse(value);
    if (!parsed.success) throw projectionFailure();
    if (
      parsed.data.operation !== operation ||
      parsed.data.mutationId !== mutationId ||
      parsed.data.resourceId !== actionId
    ) {
      throw projectionFailure();
    }
    return parsed.data;
  }
}
