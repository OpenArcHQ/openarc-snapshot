import {
  CommerceAccountIdSchema,
  CommerceControlSessionExchangeBodySchema,
  CommerceControlSessionExchangeResultSchema,
  CommerceControlSessionIssueBodySchema,
  CommerceControlSessionIssueResultSchema,
  CommerceControlSessionMetadataSchema,
  CommerceControlSessionListRequestSchema,
  CommerceControlSessionListSchema,
  CommerceControlSessionMutationRequestSchema,
  CommerceControlSessionMutationStatusSchema,
  CommerceControlSessionReceiptSchema,
  CommerceControlSessionRequestSchema,
  CommerceControlSessionRevokeBodySchema,
  CommerceControlSessionRevokeResultSchema,
  CommerceControlSessionStatusSchema,
  CommerceControlSessionIdSchema,
  CommerceMachineSessionMetadataSchema,
  CommerceOrganizationIdSchema,
  CommerceTenantIdempotencyKeySchema,
  CommerceTenantMutationIdSchema,
  compareIsoTimestamps,
  IsoTimestampSchema,
  type CommerceControlSessionExchangeResult,
  type CommerceControlSessionIssueResult,
  type CommerceControlSessionList,
  type CommerceControlSessionMetadata,
  type CommerceControlSessionMutationStatus,
  type CommerceControlSessionReceipt,
  type CommerceControlSessionRevokeResult,
  type CommerceControlSessionStatus,
} from "@openarc/shared";
import { CommerceSessionStoreError, CredentialStoreError } from "@openarc/db";
import type { ZodType } from "zod";

import { AUTH_ERRORS, AuthApiError } from "../auth/errors.js";
import type { AuthRequestContext } from "../auth/service.js";
import {
  generateCommerceHandoffToken,
  generateCommerceSessionToken,
  hashCommerceHandoffToken,
  hashCommerceSessionToken,
} from "./session-crypto.js";
import {
  isSessionTokenForKind,
  hashSessionToken,
} from "../machine/session-token.js";
import {
  COMMERCE_SESSION_RATE_LIMITS,
  type CommerceSessionRateLimiter,
} from "./session-rate-limiter.js";
import type {
  AgentSessionReadPort,
  CommerceSessionAuthPort,
  CommerceSessionMutationMetadata,
  CommerceSessionStorePort,
} from "./session-ports.js";

/**
 * Orchestration for the commerce-session HTTP slice.
 *
 * Human reads are strict: parse the request BEFORE any auth work, then
 * `beginTenantRead`, the bounded read limiter, exactly one accepted repository
 * read, the `finishTenantRead` guard (even for a null/not-found result) and only
 * then validate/bind the returned DTO. Human writes parse, verify CSRF, begin
 * (which returns the current hash and account), take the optional issuance
 * account limit, generate + hash the one-time handoff and invoke exactly ONE
 * accepted repository mutation with NO post-commit live-session check.
 *
 * Agent exchange parses the bounded bearer/body, takes the ordered durable
 * global/peer/presented-token limiter, hashes the presented agent session and
 * raw handoff, generates + hashes a fresh session token and invokes exactly ONE
 * exchange. Agent status resolves the trusted organization from the current
 * agent session before and after the DB9 status read and requires both
 * snapshots to match. No method retries, polls, substitutes an idempotency key
 * or acts on an unknown outcome.
 */

const DEFAULT_DURATION_SECONDS = 300;
/** Absent list limit is bounded to 25 by this port, not only the shared max 50. */
const DEFAULT_LIST_LIMIT = 25;
/** Frozen maximum handoff lifetime, independent of a shortened effective expiry. */
const MAX_HANDOFF_LIFETIME_SECONDS = 300;
const ISSUE_OPERATION = "control.commerce_session.issue" as const;
const EXCHANGE_OPERATION = "control.commerce_session.exchange" as const;
const REVOKE_OPERATION = "control.commerce_session.revoke" as const;

/** Human mutation status may only report issue/revoke, never exchange. */
const HUMAN_OPERATIONS: ReadonlySet<string> = new Set([
  ISSUE_OPERATION,
  REVOKE_OPERATION,
]);

const AGENT_OPERATIONS: ReadonlySet<string> = new Set([EXCHANGE_OPERATION]);

/** Injectable independent one-time token source (real CSPRNG in production). */
export interface CommerceSessionFactoryPort {
  handoffToken(): string;
  sessionToken(): string;
}

export interface CommerceSessionServiceOptions {
  readonly auth: CommerceSessionAuthPort;
  readonly store: CommerceSessionStorePort;
  readonly agentSessions: AgentSessionReadPort;
  readonly limits: CommerceSessionRateLimiter;
  readonly factory?: CommerceSessionFactoryPort;
}

export interface CommerceSessionWriteEnvelope {
  readonly csrf: unknown;
  readonly idempotencyKey: unknown;
  readonly body: unknown;
}

export interface CommerceSessionAgentEnvelope {
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

/**
 * A malformed/shape-invalid repository result (or a binding violation) is a
 * fixed 503. Frozen contract: invalid DB data is an unavailable dependency, not
 * a caller error.
 */
function projectionFailure(): AuthApiError {
  return AUTH_ERRORS.unavailable();
}

function mapStoreError(error: unknown): never {
  if (error instanceof AuthApiError) throw error;
  if (error instanceof CommerceSessionStoreError) {
    switch (error.code) {
      case "COMMERCE_SESSION_STORE_INPUT_INVALID":
        throw invalidInput();
      case "COMMERCE_SESSION_STORE_SESSION_INVALID":
        throw unauthenticated();
      case "COMMERCE_SESSION_STORE_FORBIDDEN":
      case "COMMERCE_SESSION_STORE_NOT_FOUND":
        // A cross-actor or unknown target is the same fixed denial: no
        // organization-existence oracle is exposed by the transport.
        throw forbidden();
      case "COMMERCE_SESSION_STORE_CONFLICT":
        throw policyDenied();
      case "COMMERCE_SESSION_STORE_IDEMPOTENCY_CONFLICT":
        throw idempotencyConflict();
      case "COMMERCE_SESSION_STORE_UNAVAILABLE":
      case "COMMERCE_SESSION_STORE_OUTCOME_UNKNOWN":
      default:
        throw unavailable();
    }
  }
  throw unavailable();
}

/**
 * Credential/session repository failures during agent reads collapse to the
 * same fixed 401 without an existence oracle. Genuine store outages remain a
 * non-retryable 503.
 */
function mapCredentialError(error: unknown): never {
  if (error instanceof AuthApiError) throw error;
  if (error instanceof CredentialStoreError) {
    switch (error.code) {
      case "CREDENTIAL_STORE_SESSION_INVALID":
      case "CREDENTIAL_STORE_FORBIDDEN":
      case "CREDENTIAL_STORE_NOT_FOUND":
      case "CREDENTIAL_STORE_CONFLICT":
      case "CREDENTIAL_STORE_INPUT_INVALID":
        throw unauthenticated();
      case "CREDENTIAL_STORE_UNAVAILABLE":
      case "CREDENTIAL_STORE_OUTCOME_UNKNOWN":
      case "CREDENTIAL_STORE_IDEMPOTENCY_CONFLICT":
      default:
        throw unavailable();
    }
  }
  throw unavailable();
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
 * Exact whole-second shift onto an accepted ISO leaf, preserving the original
 * fractional digits so the bound comparison stays exact (a `Date.parse` on the
 * whole timestamp would truncate the fraction).
 */
function shiftIsoSeconds(iso: string, seconds: number): string | null {
  const match =
    /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z$/u.exec(iso);
  if (!match) return null;
  const baseMs = Date.parse(`${match[1]}Z`);
  if (!Number.isFinite(baseMs)) return null;
  const shifted = new Date(baseMs + seconds * 1000).toISOString();
  const secondPart = shifted.slice(0, 19);
  return match[2] === undefined
    ? `${secondPart}Z`
    : `${secondPart}.${match[2]}Z`;
}

/**
 * Validate the ORIGINAL raw `handoffExpiresAt` on every issue result, including
 * a replay whose delivery is replaced with `not_replayable`. It must be an
 * accepted timestamp strictly after `issuedAt` and at or before
 * `issuedAt + 300s`. A historical replay may carry a shortened effective
 * `expiresAt`, so the effective expiry is deliberately NOT compared here.
 */
function requireHandoffExpiresAt(value: unknown, issuedAt: string): string {
  if (!IsoTimestampSchema.safeParse(value).success) throw projectionFailure();
  const expiry = value as string;
  if (compareIsoTimestamps(expiry, issuedAt) <= 0) throw projectionFailure();
  const maxExpiry = shiftIsoSeconds(issuedAt, MAX_HANDOFF_LIFETIME_SECONDS);
  if (maxExpiry === null || compareIsoTimestamps(expiry, maxExpiry) > 0) {
    throw projectionFailure();
  }
  return expiry;
}

/**
 * Canonical, non-echoing shape of the current agent session for binding.
 *
 * This mirrors the accepted `MachineSessionMetadata` read (every required key
 * plus the current revocation version), not the create-API shape. The optional
 * `issuerAccountId` is retained and compared so before/after drift in the
 * issuer cannot be hidden by a strip-and-project.
 */
interface TrustedAgentSession {
  readonly sessionId: string;
  readonly credentialId: string;
  readonly organizationId: string;
  readonly kind: "agent";
  readonly profileId: string;
  readonly issuerAccountId: string | undefined;
  readonly scope: string;
  readonly scopeVersion: 1;
  readonly environment: "eip155:5042002";
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly revocationVersion: number;
}

/** Exact required keys of the accepted `MachineSessionMetadata` read. */
const TRUSTED_AGENT_SESSION_REQUIRED_KEYS: readonly string[] = [
  "sessionId",
  "credentialId",
  "organizationId",
  "kind",
  "profileId",
  "scope",
  "scopeVersion",
  "environment",
  "createdAt",
  "expiresAt",
  "revocationVersion",
];

/**
 * Validate the WHOLE actual `CredentialStore.getAgentSession` return before
 * any projection: exact required keys, only the one accepted optional issuer
 * key, no private/unknown key, safe positive integer `revocationVersion`, and
 * the accepted scope/environment/timestamp shape. A present-but-`undefined`
 * value is invalid for every key.
 */
function trustedAgentSession(raw: unknown): TrustedAgentSession {
  if (!isRecord(raw)) throw projectionFailure();
  const allowed = new Set([
    ...TRUSTED_AGENT_SESSION_REQUIRED_KEYS,
    "issuerAccountId",
  ]);
  for (const key of Object.keys(raw)) {
    if (!allowed.has(key)) throw projectionFailure();
  }
  for (const key of TRUSTED_AGENT_SESSION_REQUIRED_KEYS) {
    if (!Object.hasOwn(raw, key)) throw projectionFailure();
  }
  let issuerAccountId: string | undefined;
  if (Object.hasOwn(raw, "issuerAccountId")) {
    const parsedIssuer = CommerceAccountIdSchema.safeParse(
      raw["issuerAccountId"],
    );
    if (!parsedIssuer.success) throw projectionFailure();
    issuerAccountId = parsedIssuer.data;
  }
  const revocationVersion = raw["revocationVersion"];
  if (
    typeof revocationVersion !== "number" ||
    !Number.isSafeInteger(revocationVersion) ||
    revocationVersion < 1
  ) {
    throw projectionFailure();
  }
  const parsed = CommerceMachineSessionMetadataSchema.safeParse({
    sessionId: raw["sessionId"],
    credentialId: raw["credentialId"],
    organizationId: raw["organizationId"],
    kind: raw["kind"],
    profileId: raw["profileId"],
    environment: raw["environment"],
    scopes: [raw["scope"]],
    scopeVersion: raw["scopeVersion"],
    createdAt: raw["createdAt"],
    expiresAt: raw["expiresAt"],
  });
  if (!parsed.success || parsed.data.kind !== "agent") throw projectionFailure();
  return {
    sessionId: parsed.data.sessionId,
    credentialId: parsed.data.credentialId,
    organizationId: parsed.data.organizationId,
    kind: "agent",
    profileId: parsed.data.profileId,
    issuerAccountId,
    scope: parsed.data.scopes[0],
    scopeVersion: parsed.data.scopeVersion,
    environment: parsed.data.environment,
    createdAt: parsed.data.createdAt,
    expiresAt: parsed.data.expiresAt,
    revocationVersion,
  };
}

function sameAgentSession(
  left: TrustedAgentSession,
  right: TrustedAgentSession,
): boolean {
  return (
    left.sessionId === right.sessionId &&
    left.credentialId === right.credentialId &&
    left.organizationId === right.organizationId &&
    left.kind === right.kind &&
    left.profileId === right.profileId &&
    left.issuerAccountId === right.issuerAccountId &&
    left.scope === right.scope &&
    left.scopeVersion === right.scopeVersion &&
    left.environment === right.environment &&
    left.createdAt === right.createdAt &&
    left.expiresAt === right.expiresAt &&
    left.revocationVersion === right.revocationVersion
  );
}

export class CommerceSessionService {
  readonly #auth: CommerceSessionAuthPort;
  readonly #store: CommerceSessionStorePort;
  readonly #agentSessions: AgentSessionReadPort;
  readonly #limits: CommerceSessionRateLimiter;
  readonly #factory: CommerceSessionFactoryPort;

  constructor(options: CommerceSessionServiceOptions) {
    this.#auth = options.auth;
    this.#store = options.store;
    this.#agentSessions = options.agentSessions;
    this.#limits = options.limits;
    this.#factory =
      options.factory ??
      ({
        handoffToken: generateCommerceHandoffToken,
        sessionToken: generateCommerceSessionToken,
      } satisfies CommerceSessionFactoryPort);
  }

  /* ---------------------------------------------------------------- */
  /* Human reads                                                       */
  /* ---------------------------------------------------------------- */

  async list(
    ctx: AuthRequestContext,
    request: unknown,
  ): Promise<CommerceControlSessionList> {
    const parsed = parseRequest(CommerceControlSessionListRequestSchema, request);
    const begun = await this.#auth.beginTenantRead(ctx);
    await this.#consumeReadLimits(ctx, begun.accountId);
    const limit =
      parsed.limit === undefined ? undefined : Number(parsed.limit);
    let raw: unknown;
    try {
      raw = await this.#store.listCommerceSessions(
        begun.sessionHash,
        parsed.organizationId,
        {
          ...(parsed.afterSessionId !== undefined
            ? { afterSessionId: parsed.afterSessionId }
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
    const page = CommerceControlSessionListSchema.safeParse({
      organizationId: parsed.organizationId,
      items: raw["items"],
      nextCursor: raw["nextCursor"],
    });
    if (!page.success) throw projectionFailure();
    // An absent limit is still bounded by this port's default 25, not only the
    // shared schema maximum of 50.
    const outputLimit = limit ?? DEFAULT_LIST_LIMIT;
    if (page.data.items.length > outputLimit) throw projectionFailure();
    if (parsed.afterSessionId !== undefined) {
      const first = page.data.items[0]?.metadata.sessionId;
      if (first !== undefined && first <= parsed.afterSessionId) {
        throw projectionFailure();
      }
    }
    return page.data;
  }

  async getStatus(
    ctx: AuthRequestContext,
    request: unknown,
  ): Promise<CommerceControlSessionStatus> {
    const parsed = parseRequest(CommerceControlSessionRequestSchema, request);
    const begun = await this.#auth.beginTenantRead(ctx);
    await this.#consumeReadLimits(ctx, begun.accountId);
    let raw: unknown;
    try {
      raw = await this.#store.getCommerceSessionStatus(
        begun.sessionHash,
        parsed.organizationId,
        parsed.sessionId,
      );
    } catch (error) {
      mapStoreError(error);
    }
    await this.#auth.finishTenantRead(ctx, begun);
    if (!isRecord(raw)) throw projectionFailure();
    requireExactKeys(raw, ["organizationId", "item"]);
    // The raw organization is authoritative output, never replaced by the
    // requested one: a foreign/invalid org (even with item:null) is a 503.
    if (raw["organizationId"] !== parsed.organizationId) throw projectionFailure();
    const status = CommerceControlSessionStatusSchema.safeParse({
      organizationId: parsed.organizationId,
      item: raw["item"],
    });
    if (!status.success) throw projectionFailure();
    if (
      status.data.item !== null &&
      status.data.item.metadata.sessionId !== parsed.sessionId
    ) {
      throw projectionFailure();
    }
    return status.data;
  }

  async getHumanMutationStatus(
    ctx: AuthRequestContext,
    request: unknown,
  ): Promise<CommerceControlSessionMutationStatus> {
    const parsed = parseRequest(
      CommerceControlSessionMutationRequestSchema,
      request,
    );
    const begun = await this.#auth.beginTenantRead(ctx);
    await this.#consumeReadLimits(ctx, begun.accountId);
    let raw: unknown;
    try {
      raw = await this.#store.getHumanCommerceSessionMutationStatus(
        begun.sessionHash,
        parsed.organizationId,
        parsed.mutationId,
      );
    } catch (error) {
      mapStoreError(error);
    }
    await this.#auth.finishTenantRead(ctx, begun);
    return this.#projectMutationStatus(
      raw,
      parsed.organizationId,
      parsed.mutationId,
      HUMAN_OPERATIONS,
    );
  }

  /* ---------------------------------------------------------------- */
  /* Human writes                                                      */
  /* ---------------------------------------------------------------- */

  async issue(
    ctx: AuthRequestContext,
    organizationId: unknown,
    envelope: CommerceSessionWriteEnvelope,
  ): Promise<CommerceControlSessionIssueResult> {
    const organization = parseRequest(
      CommerceOrganizationIdSchema,
      organizationId,
    );
    const body = parseRequest(
      CommerceControlSessionIssueBodySchema,
      envelope.body,
    );
    const idempotencyKey = parseRequest(
      CommerceTenantIdempotencyKeySchema,
      envelope.idempotencyKey,
    );
    const durationSeconds =
      body.durationSeconds === undefined
        ? DEFAULT_DURATION_SECONDS
        : Number(body.durationSeconds);
    // Input validation is complete; now CSRF, then the live-session begin.
    this.#auth.verifyCsrf(ctx.cookies, envelope.csrf);
    const begun = await this.#auth.beginTenantRead(ctx);
    await this.#limits.consumeAll([
      {
        family: "issue",
        bucket: "account",
        value: begun.accountId,
        limit: COMMERCE_SESSION_RATE_LIMITS.issue.account,
      },
    ]);
    const handoffToken = this.#generateHandoff();
    const handoffHash = this.#hashHandoff(handoffToken);
    const metadata: CommerceSessionMutationMetadata = {
      idempotencyKey,
      mutationId: body.mutationId,
    };
    let raw: unknown;
    try {
      raw = await this.#store.issueCommerceSession(
        begun.sessionHash,
        organization,
        {
          subjectAgentId: body.subjectAgentId,
          policyId: body.policyId,
          durationSeconds,
          handoffHash,
          hashVersion: 1,
        },
        metadata,
      );
    } catch (error) {
      mapStoreError(error);
    }
    return this.#projectIssue(raw, {
      organizationId: organization,
      subjectAgentId: body.subjectAgentId,
      policyId: body.policyId,
      mutationId: body.mutationId,
      handoffToken,
    });
  }

  async revoke(
    ctx: AuthRequestContext,
    organizationId: unknown,
    sessionId: unknown,
    envelope: CommerceSessionWriteEnvelope,
  ): Promise<CommerceControlSessionRevokeResult> {
    const organization = parseRequest(
      CommerceOrganizationIdSchema,
      organizationId,
    );
    const body = parseRequest(
      CommerceControlSessionRevokeBodySchema,
      envelope.body,
    );
    const idempotencyKey = parseRequest(
      CommerceTenantIdempotencyKeySchema,
      envelope.idempotencyKey,
    );
    const session = parseRequest(CommerceControlSessionIdSchema, sessionId);
    this.#auth.verifyCsrf(ctx.cookies, envelope.csrf);
    const begun = await this.#auth.beginTenantRead(ctx);
    const metadata: CommerceSessionMutationMetadata = {
      idempotencyKey,
      mutationId: body.mutationId,
    };
    let raw: unknown;
    try {
      raw = await this.#store.revokeCommerceSession(
        begun.sessionHash,
        organization,
        session,
        metadata,
      );
    } catch (error) {
      mapStoreError(error);
    }
    return this.#projectRevoke(raw, {
      organizationId: organization,
      sessionId: session,
      mutationId: body.mutationId,
    });
  }

  /* ---------------------------------------------------------------- */
  /* Agent exchange and status                                         */
  /* ---------------------------------------------------------------- */

  async exchange(
    token: unknown,
    peerIp: string,
    envelope: CommerceSessionAgentEnvelope,
  ): Promise<CommerceControlSessionExchangeResult> {
    const presented = this.#requireAgentSessionToken(token);
    const body = parseRequest(
      CommerceControlSessionExchangeBodySchema,
      envelope.body,
    );
    const idempotencyKey = parseRequest(
      CommerceTenantIdempotencyKeySchema,
      envelope.idempotencyKey,
    );
    // Ordered global/peer/presented-token limiter BEFORE any hash, token
    // generation or database authority.
    await this.#limits.consumeAll([
      {
        family: "exchange",
        bucket: "global",
        value: "*",
        limit: COMMERCE_SESSION_RATE_LIMITS.exchange.global,
      },
      {
        family: "exchange",
        bucket: "peer",
        value: peerIp,
        limit: COMMERCE_SESSION_RATE_LIMITS.exchange.peer,
      },
      {
        family: "exchange",
        bucket: "token",
        value: presented,
        limit: COMMERCE_SESSION_RATE_LIMITS.exchange.token,
      },
    ]);
    const agentHash = this.#hashAgentSession(presented);
    const handoffHash = this.#hashHandoff(body.handoffToken);
    const sessionToken = this.#generateSession();
    const tokenHash = this.#hashSession(sessionToken);
    const metadata: CommerceSessionMutationMetadata = {
      idempotencyKey,
      mutationId: body.mutationId,
    };
    let raw: unknown;
    try {
      raw = await this.#store.exchangeCommerceSession(
        agentHash,
        handoffHash,
        { tokenHash, hashVersion: 1 },
        metadata,
      );
    } catch (error) {
      mapStoreError(error);
    }
    return this.#projectExchange(raw, {
      mutationId: body.mutationId,
      sessionToken,
    });
  }

  async getAgentMutationStatus(
    token: unknown,
    peerIp: string,
    mutationId: unknown,
  ): Promise<CommerceControlSessionMutationStatus> {
    const presented = this.#requireAgentSessionToken(token);
    const mutation = parseRequest(CommerceTenantMutationIdSchema, mutationId);
    await this.#consumeAgentReadLimits(peerIp, presented);
    const agentHash = this.#hashAgentSession(presented);
    // Resolve the trusted organization from the CURRENT agent session before
    // the DB9 status read (which independently checks the exact requester).
    let beforeRaw: unknown;
    try {
      beforeRaw = await this.#agentSessions.getAgentSession(agentHash);
    } catch (error) {
      mapCredentialError(error);
    }
    const before = trustedAgentSession(beforeRaw);
    let raw: unknown;
    try {
      raw = await this.#store.getAgentCommerceSessionMutationStatus(
        agentHash,
        mutation,
      );
    } catch (error) {
      mapStoreError(error);
    }
    let afterRaw: unknown;
    try {
      afterRaw = await this.#agentSessions.getAgentSession(agentHash);
    } catch (error) {
      mapCredentialError(error);
    }
    const after = trustedAgentSession(afterRaw);
    if (!sameAgentSession(before, after)) throw projectionFailure();
    return this.#projectMutationStatus(
      raw,
      before.organizationId,
      mutation,
      AGENT_OPERATIONS,
    );
  }

  /* ---------------------------------------------------------------- */
  /* Internal helpers                                                  */
  /* ---------------------------------------------------------------- */

  #requireAgentSessionToken(token: unknown): string {
    if (!isSessionTokenForKind("agent", token)) throw unauthenticated();
    return token;
  }

  #generateHandoff(): string {
    try {
      return this.#factory.handoffToken();
    } catch {
      throw unavailable();
    }
  }

  #generateSession(): string {
    try {
      return this.#factory.sessionToken();
    } catch {
      throw unavailable();
    }
  }

  #hashHandoff(value: unknown): string {
    try {
      return hashCommerceHandoffToken(value);
    } catch {
      throw unavailable();
    }
  }

  #hashSession(value: unknown): string {
    try {
      return hashCommerceSessionToken(value);
    } catch {
      throw unavailable();
    }
  }

  #hashAgentSession(token: string): string {
    try {
      return hashSessionToken("agent", token);
    } catch {
      throw unauthenticated();
    }
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
        limit: COMMERCE_SESSION_RATE_LIMITS.read.global,
      },
      {
        family: "read",
        bucket: "peer",
        value: ctx.peerIp,
        limit: COMMERCE_SESSION_RATE_LIMITS.read.peer,
      },
      {
        family: "read",
        bucket: "subject",
        value: accountId,
        limit: COMMERCE_SESSION_RATE_LIMITS.read.subject,
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
        limit: COMMERCE_SESSION_RATE_LIMITS.read.global,
      },
      {
        family: "read",
        bucket: "peer",
        value: peerIp,
        limit: COMMERCE_SESSION_RATE_LIMITS.read.peer,
      },
      {
        family: "read",
        bucket: "subject",
        value: presented,
        limit: COMMERCE_SESSION_RATE_LIMITS.read.subject,
      },
    ]);
  }

  #projectIssue(
    raw: unknown,
    expected: {
      organizationId: string;
      subjectAgentId: string;
      policyId: string;
      mutationId: string;
      handoffToken: string;
    },
  ): CommerceControlSessionIssueResult {
    if (!isRecord(raw)) throw projectionFailure();
    requireExactKeys(raw, [
      "replayed",
      "metadata",
      "receipt",
      "handoffExpiresAt",
    ]);
    const replayed = this.#requireReplayed(raw["replayed"]);
    const metadata = this.#requireMetadata(raw["metadata"]);
    if (
      metadata.organizationId !== expected.organizationId ||
      metadata.subjectAgentId !== expected.subjectAgentId ||
      metadata.policyId !== expected.policyId
    ) {
      throw projectionFailure();
    }
    const receipt = this.#requireReceipt(
      raw["receipt"],
      ISSUE_OPERATION,
      expected.mutationId,
      metadata.sessionId,
    );
    // Validate the ORIGINAL handoff expiry even on replay, before the delivery
    // is replaced with not_replayable.
    const handoffExpiresAt = requireHandoffExpiresAt(
      raw["handoffExpiresAt"],
      metadata.issuedAt,
    );
    const result = replayed
      ? {
          organizationId: expected.organizationId,
          replayed: true as const,
          metadata,
          receipt,
          delivery: { state: "not_replayable" as const },
        }
      : {
          organizationId: expected.organizationId,
          replayed: false as const,
          metadata,
          receipt,
          delivery: {
            state: "available_once" as const,
            handoffToken: expected.handoffToken,
            handoffExpiresAt,
          },
        };
    const parsed = CommerceControlSessionIssueResultSchema.safeParse(result);
    if (!parsed.success) throw projectionFailure();
    return parsed.data;
  }

  #projectExchange(
    raw: unknown,
    expected: { mutationId: string; sessionToken: string },
  ): CommerceControlSessionExchangeResult {
    if (!isRecord(raw)) throw projectionFailure();
    requireExactKeys(raw, ["replayed", "metadata", "receipt"]);
    const replayed = this.#requireReplayed(raw["replayed"]);
    const metadata = this.#requireMetadata(raw["metadata"]);
    const receipt = this.#requireReceipt(
      raw["receipt"],
      EXCHANGE_OPERATION,
      expected.mutationId,
      metadata.sessionId,
    );
    const result = replayed
      ? {
          organizationId: metadata.organizationId,
          replayed: true as const,
          metadata,
          receipt,
          delivery: { state: "not_replayable" as const },
        }
      : {
          organizationId: metadata.organizationId,
          replayed: false as const,
          metadata,
          receipt,
          delivery: {
            state: "available_once" as const,
            sessionToken: expected.sessionToken,
          },
        };
    const parsed = CommerceControlSessionExchangeResultSchema.safeParse(result);
    if (!parsed.success) throw projectionFailure();
    return parsed.data;
  }

  #projectRevoke(
    raw: unknown,
    expected: {
      organizationId: string;
      sessionId: string;
      mutationId: string;
    },
  ): CommerceControlSessionRevokeResult {
    if (!isRecord(raw)) throw projectionFailure();
    requireExactKeys(raw, ["replayed", "metadata", "receipt"]);
    const replayed = this.#requireReplayed(raw["replayed"]);
    const metadata = this.#requireMetadata(raw["metadata"]);
    if (
      metadata.organizationId !== expected.organizationId ||
      metadata.sessionId !== expected.sessionId
    ) {
      throw projectionFailure();
    }
    const receipt = this.#requireReceipt(
      raw["receipt"],
      REVOKE_OPERATION,
      expected.mutationId,
      metadata.sessionId,
    );
    const result = {
      organizationId: expected.organizationId,
      replayed,
      metadata,
      receipt,
    };
    const parsed = CommerceControlSessionRevokeResultSchema.safeParse(result);
    if (!parsed.success) throw projectionFailure();
    return parsed.data;
  }

  #projectMutationStatus(
    raw: unknown,
    organizationId: string,
    mutationId: string,
    operations: ReadonlySet<string>,
  ): CommerceControlSessionMutationStatus {
    if (!isRecord(raw)) throw projectionFailure();
    if (raw["status"] === "not_found") {
      requireExactKeys(raw, ["status"]);
      const status = CommerceControlSessionMutationStatusSchema.safeParse({
        organizationId,
        mutationId,
        status: "not_found",
      });
      if (!status.success) throw projectionFailure();
      return status.data;
    }
    if (raw["status"] !== "committed") throw projectionFailure();
    requireExactKeys(raw, ["status", "receipt"]);
    const status = CommerceControlSessionMutationStatusSchema.safeParse({
      organizationId,
      mutationId,
      status: "committed",
      receipt: raw["receipt"],
    });
    if (!status.success || status.data.status !== "committed") {
      throw projectionFailure();
    }
    if (!operations.has(status.data.receipt.operation)) {
      throw projectionFailure();
    }
    return status.data;
  }

  #requireReplayed(value: unknown): boolean {
    if (value === true) return true;
    if (value === false) return false;
    throw projectionFailure();
  }

  #requireMetadata(value: unknown) {
    const parsed = CommerceControlSessionMetadataSchemaSafe(value);
    if (parsed === null) throw projectionFailure();
    return parsed;
  }

  #requireReceipt(
    value: unknown,
    operation: string,
    mutationId: string,
    sessionId: string,
  ) {
    const parsed = CommerceControlSessionReceiptSchemaSafe(value);
    if (parsed === null) throw projectionFailure();
    if (
      parsed.operation !== operation ||
      parsed.mutationId !== mutationId ||
      parsed.resourceId !== sessionId
    ) {
      throw projectionFailure();
    }
    return parsed;
  }
}

function CommerceControlSessionMetadataSchemaSafe(
  value: unknown,
): CommerceControlSessionMetadata | null {
  const parsed = CommerceControlSessionMetadataSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

function CommerceControlSessionReceiptSchemaSafe(
  value: unknown,
): CommerceControlSessionReceipt | null {
  const parsed = CommerceControlSessionReceiptSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}
