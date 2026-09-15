import { createHash } from 'node:crypto';
import type { Pool } from 'pg';
import {
  CommerceControlSessionMetadataSchema,
  CommerceControlSessionStatusItemSchema,
  CommerceControlSessionListSchema,
  CommerceControlSessionMutationStatusSchema,
  CommerceControlSessionReceiptSchema,
  compareIsoTimestamps,
  type CommerceControlSessionMetadata,
  type CommerceControlSessionReceipt,
  type CommerceControlSessionStatusItem,
} from '@openarc/shared';
import { loadMigrations } from './migrate.js';
import { TenantStore, type TenantClient, type TenantPool } from './tenant-store.js';
import { parseMutationId } from './tenant-durability.js';
import { ControlPolicyStore } from './control-policy-store.js';
import { CredentialStore } from './credential-store.js';
import {
  CONTROL_SESSION_RESOURCE_TYPE,
  digestCommerceSessionExchangeRequest,
  digestCommerceSessionHumanContext,
  digestCommerceSessionIdempotencyKey,
  digestCommerceSessionIssueRequest,
  digestCommerceSessionMachineContext,
  digestCommerceSessionRevokeRequest,
  parseCommerceDurationSeconds,
  parseCommerceHandoffHash,
  parseCommerceSessionId,
  parseCommerceTokenHash,
  requireIdempotencyKey,
  type CommerceSessionOperation,
} from './control-session-mutations.js';

/**
 * CommerceSessionStore over the restricted tenant pool. Every method runs in
 * one connection/transaction through the reviewed SECURITY DEFINER helpers and
 * never migrates. Outputs strict-parse the frozen shared commerce-session DTOs;
 * a malformed driver row collapses to a fixed UNAVAILABLE error and hash/parent
 * columns are never projected.
 */

export const COMMERCE_SESSION_STORE_ERROR_MESSAGES = {
  COMMERCE_SESSION_STORE_INPUT_INVALID: 'CommerceSessionStore input is invalid.',
  COMMERCE_SESSION_STORE_SESSION_INVALID: 'CommerceSessionStore session is not valid.',
  COMMERCE_SESSION_STORE_FORBIDDEN: 'CommerceSessionStore caller is not permitted.',
  COMMERCE_SESSION_STORE_NOT_FOUND: 'CommerceSessionStore target was not found.',
  COMMERCE_SESSION_STORE_CONFLICT: 'CommerceSessionStore operation conflicts with existing state.',
  COMMERCE_SESSION_STORE_IDEMPOTENCY_CONFLICT:
    'CommerceSessionStore mutation conflicts with an existing idempotency record.',
  COMMERCE_SESSION_STORE_UNAVAILABLE: 'CommerceSessionStore is not available.',
  COMMERCE_SESSION_STORE_OUTCOME_UNKNOWN:
    'CommerceSessionStore mutation outcome could not be confirmed; it may have committed.',
} as const;

export type CommerceSessionStoreErrorCode = keyof typeof COMMERCE_SESSION_STORE_ERROR_MESSAGES;

/** Fixed, non-echoing repository error. Never carries driver detail. */
export class CommerceSessionStoreError extends Error {
  readonly code: CommerceSessionStoreErrorCode;

  constructor(code: CommerceSessionStoreErrorCode) {
    super(COMMERCE_SESSION_STORE_ERROR_MESSAGES[code]);
    this.name = 'CommerceSessionStoreError';
    this.code = code;
  }
}

export interface CommerceSessionMutationMetadata {
  readonly idempotencyKey: string;
  readonly mutationId: string;
}

export interface IssueCommerceSessionInput {
  readonly subjectAgentId: string;
  readonly policyId: string;
  readonly durationSeconds?: number;
  readonly handoffHash: string;
  readonly hashVersion: 1;
}

export interface ExchangeCommerceSessionInput {
  readonly tokenHash: string;
  readonly hashVersion: 1;
}

export interface CommerceSessionIssueDbResult {
  readonly replayed: boolean;
  readonly metadata: CommerceControlSessionMetadata;
  readonly receipt: CommerceControlSessionReceipt;
  readonly handoffExpiresAt: string;
}

export interface CommerceSessionMutationDbResult {
  readonly replayed: boolean;
  readonly metadata: CommerceControlSessionMetadata;
  readonly receipt: CommerceControlSessionReceipt;
}

export interface CommerceSessionStatusResult {
  readonly organizationId: string;
  readonly item: CommerceControlSessionStatusItem | null;
}

export interface ListCommerceSessionsInput {
  readonly afterSessionId?: string;
  readonly limit?: number;
}

export interface ListCommerceSessionsResult {
  readonly items: CommerceControlSessionStatusItem[];
  readonly nextCursor: string | null;
}

export type CommerceSessionMutationStatus =
  | { readonly status: 'committed'; readonly receipt: CommerceControlSessionReceipt }
  | { readonly status: 'not_found' };

const HEX64 = /^[0-9a-f]{64}$(?![\s\S])/;
const SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const ORG_ID = /^openarc:org:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const AGENT_ID = /^openarc:agent:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const POLICY_ID = /^openarc:policy:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const DEFAULT_PAGE = 25;
const MAX_PAGE = 50;
const DEFAULT_DURATION = 300;

export const COMMERCE_SESSION_STATEMENT_TIMEOUT_MS = 15000;
export const COMMERCE_SESSION_LOCK_TIMEOUT_MS = 10000;

function fail(code: CommerceSessionStoreErrorCode): never {
  throw new CommerceSessionStoreError(code);
}

function failOutput(): never {
  fail('COMMERCE_SESSION_STORE_UNAVAILABLE');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireSessionHash(value: unknown): string {
  if (typeof value !== 'string' || !HEX64.test(value)) fail('COMMERCE_SESSION_STORE_INPUT_INVALID');
  return value;
}

function requireOrganization(value: unknown): string {
  if (typeof value !== 'string' || !ORG_ID.test(value)) fail('COMMERCE_SESSION_STORE_INPUT_INVALID');
  return value;
}

function requireAgent(value: unknown): string {
  if (typeof value !== 'string' || !AGENT_ID.test(value)) fail('COMMERCE_SESSION_STORE_INPUT_INVALID');
  return value;
}

function requirePolicy(value: unknown): string {
  if (typeof value !== 'string' || !POLICY_ID.test(value)) fail('COMMERCE_SESSION_STORE_INPUT_INVALID');
  return value;
}

function requireSessionId(value: unknown): string {
  try {
    return parseCommerceSessionId(value);
  } catch {
    fail('COMMERCE_SESSION_STORE_INPUT_INVALID');
  }
}

function requireHandoffHash(value: unknown): string {
  try {
    return parseCommerceHandoffHash(value);
  } catch {
    fail('COMMERCE_SESSION_STORE_INPUT_INVALID');
  }
}

function requireTokenHash(value: unknown): string {
  try {
    return parseCommerceTokenHash(value);
  } catch {
    fail('COMMERCE_SESSION_STORE_INPUT_INVALID');
  }
}

function requireHashVersionOne(value: unknown): 1 {
  if (value !== 1) fail('COMMERCE_SESSION_STORE_INPUT_INVALID');
  return 1;
}

function requireDuration(value: unknown): number {
  if (value === undefined) return DEFAULT_DURATION;
  try {
    return parseCommerceDurationSeconds(value);
  } catch {
    fail('COMMERCE_SESSION_STORE_INPUT_INVALID');
  }
}

function requireMetadata(value: unknown): CommerceSessionMutationMetadata {
  if (!isRecord(value)) fail('COMMERCE_SESSION_STORE_INPUT_INVALID');
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    fail('COMMERCE_SESSION_STORE_INPUT_INVALID');
  }
  const keys = Object.keys(value);
  if (keys.length !== 2 || !keys.includes('idempotencyKey') || !keys.includes('mutationId')) {
    fail('COMMERCE_SESSION_STORE_INPUT_INVALID');
  }
  let mutationId: string;
  try {
    mutationId = parseMutationId(value['mutationId']);
    requireIdempotencyKey(value['idempotencyKey']);
  } catch {
    fail('COMMERCE_SESSION_STORE_INPUT_INVALID');
  }
  return { idempotencyKey: value['idempotencyKey'] as string, mutationId };
}

function requireOptions(value: unknown, allowed: readonly string[]): Record<string, unknown> {
  if (value === undefined) return {};
  if (!isRecord(value)) fail('COMMERCE_SESSION_STORE_INPUT_INVALID');
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    fail('COMMERCE_SESSION_STORE_INPUT_INVALID');
  }
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) fail('COMMERCE_SESSION_STORE_INPUT_INVALID');
  }
  return value;
}

/** Strict exact keyset: every allowed key present/absent as declared, no others. */
function requireExactKeys(
  value: Record<string, unknown>,
  keys: readonly string[],
): void {
  const present = Object.keys(value);
  for (const key of present) {
    if (!keys.includes(key)) fail('COMMERCE_SESSION_STORE_INPUT_INVALID');
  }
}

function requirePage(value: unknown): number {
  if (value === undefined) return DEFAULT_PAGE;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1 || value > MAX_PAGE) {
    fail('COMMERCE_SESSION_STORE_INPUT_INVALID');
  }
  return value;
}

function normalizeError(error: unknown): CommerceSessionStoreError {
  if (error instanceof CommerceSessionStoreError) return error;
  if (isRecord(error) && typeof error.code === 'string') {
    switch (error.code) {
      case '28000':
        return new CommerceSessionStoreError('COMMERCE_SESSION_STORE_SESSION_INVALID');
      case '42501':
        return new CommerceSessionStoreError('COMMERCE_SESSION_STORE_FORBIDDEN');
      case '23503':
        return new CommerceSessionStoreError('COMMERCE_SESSION_STORE_NOT_FOUND');
      case '23505':
        return new CommerceSessionStoreError('COMMERCE_SESSION_STORE_CONFLICT');
      case 'P0D01':
        return new CommerceSessionStoreError('COMMERCE_SESSION_STORE_IDEMPOTENCY_CONFLICT');
      case '22023':
      case '22P02':
      case '22001':
      case '22003':
      case '23514':
        return new CommerceSessionStoreError('COMMERCE_SESSION_STORE_INPUT_INVALID');
      default:
        return new CommerceSessionStoreError('COMMERCE_SESSION_STORE_UNAVAILABLE');
    }
  }
  return new CommerceSessionStoreError('COMMERCE_SESSION_STORE_UNAVAILABLE');
}

interface SessionRow extends Record<string, unknown> {
  readonly out_session_id: string;
  readonly out_organization_id: string;
  readonly out_subject_agent_id: string;
  readonly out_policy_id: string;
  readonly out_issued_at: string | Date;
  readonly out_initial_expires_at: string | Date;
  readonly out_expires_at: string | Date;
  readonly out_exchanged_at: string | Date | null;
  readonly out_agent_session_id: string | null;
  readonly out_credential_id: string | null;
  readonly out_revoked_at: string | Date | null;
  readonly out_status?: string | null;
}

interface MutationRow extends SessionRow {
  readonly out_replayed: boolean;
  readonly out_handoff_expires_at: string | Date | null;
  readonly out_committed_at: string | Date;
}

function iso(value: unknown): string {
  if (value instanceof Date) {
    if (!Number.isFinite(value.getTime())) failOutput();
    // Date carries millisecond precision; present the exact UTC6 form.
    const text = value.toISOString();
    return `${text.slice(0, 19)}.${text.slice(20, 23)}000Z`;
  }
  if (typeof value !== 'string') failOutput();
  const match = PG_TIMESTAMP.exec(value);
  if (match === null) failOutput();
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, fraction, sign, offHourText, offMinuteText] = match;
  const year = Number.parseInt(yearText ?? '', 10);
  const month = Number.parseInt(monthText ?? '', 10);
  const day = Number.parseInt(dayText ?? '', 10);
  const hour = Number.parseInt(hourText ?? '', 10);
  const minute = Number.parseInt(minuteText ?? '', 10);
  const second = Number.parseInt(secondText ?? '', 10);
  const offHour = Number.parseInt(offHourText ?? '0', 10);
  const offMinute = Number.parseInt(offMinuteText ?? '0', 10);
  if (
    !Number.isInteger(year) || !Number.isInteger(month) || !Number.isInteger(day) ||
    !Number.isInteger(hour) || !Number.isInteger(minute) || !Number.isInteger(second) ||
    !Number.isInteger(offHour) || !Number.isInteger(offMinute) ||
    year < 1 || year > 9999 || month < 1 || month > 12 || day < 1 ||
    day > daysInMonth(year, month) || hour > 23 || minute > 59 || second > 59 ||
    offHour > 23 || offMinute > 59
  ) {
    failOutput();
  }
  const micros = (fraction ?? '').padEnd(6, '0').slice(0, 6);
  const offsetMinutes = (sign === '-' ? -1 : 1) * (offHour * 60 + offMinute);
  const local = new Date(0);
  local.setUTCFullYear(year, month - 1, day);
  local.setUTCHours(hour, minute, second, 0);
  const normalized = new Date(local.getTime() - offsetMinutes * 60_000);
  if (!Number.isFinite(normalized.getTime())) failOutput();
  const base = normalized.toISOString();
  return `${base.slice(0, 19)}.${micros}Z`;
}

function isoOrNull(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  return iso(value);
}

const PG_TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?([+-])(\d{2})(?::?(\d{2}))?$/;

function daysInMonth(year: number, month: number): number {
  return new Date(Date.UTC(year, month, 0)).getUTCDate();
}

export class CommerceSessionStore {
  readonly #pool: TenantPool;
  readonly #base: TenantStore;
  #initialized = false;

  constructor(pool: TenantPool) {
    if (pool === null || typeof pool !== 'object' || typeof pool.connect !== 'function') {
      fail('COMMERCE_SESSION_STORE_INPUT_INVALID');
    }
    this.#pool = pool;
    this.#base = new TenantStore(pool);
  }

  async initialize(): Promise<void> {
    if (this.#initialized) return;
    await this.#baseChecks(() => this.#base.initialize());
    await this.#baseChecks(() => new ControlPolicyStore(this.#pool).initialize());
    await this.#baseChecks(() => new CredentialStore(this.#pool).initialize());
    await this.#withTransaction(async (client) => {
      await this.#assertReady(client);
    });
    this.#initialized = true;
  }

  async readiness(): Promise<void> {
    await this.#baseChecks(() => this.#base.readiness());
    await this.#baseChecks(() => new ControlPolicyStore(this.#pool).readiness());
    await this.#baseChecks(() => new CredentialStore(this.#pool).readiness());
    await this.#withTransaction(async (client) => {
      await this.#assertReady(client);
    });
  }

  async #baseChecks(run: () => Promise<void>): Promise<void> {
    try {
      await run();
    } catch {
      fail('COMMERCE_SESSION_STORE_UNAVAILABLE');
    }
  }

  async issueCommerceSession(
    humanSessionHash: unknown,
    organizationId: unknown,
    input: IssueCommerceSessionInput,
    metadata: unknown,
  ): Promise<CommerceSessionIssueDbResult> {
    const hash = requireSessionHash(humanSessionHash);
    const organization = requireOrganization(organizationId);
    if (!isRecord(input)) fail('COMMERCE_SESSION_STORE_INPUT_INVALID');
    requireExactKeys(input, ['subjectAgentId', 'policyId', 'durationSeconds', 'handoffHash', 'hashVersion']);
    for (const required of ['subjectAgentId', 'policyId', 'handoffHash', 'hashVersion']) {
      if (!(required in input)) fail('COMMERCE_SESSION_STORE_INPUT_INVALID');
    }
    const subject = requireAgent(input.subjectAgentId);
    const policy = requirePolicy(input.policyId);
    const duration = requireDuration(input.durationSeconds);
    const handoffHash = requireHandoffHash(input.handoffHash);
    requireHashVersionOne(input.hashVersion);
    const meta = requireMetadata(metadata);
    const operation: CommerceSessionOperation = 'control.commerce_session.issue';
    const sessionContextDigest = digestCommerceSessionHumanContext(operation, hash);
    const keyHash = digestCommerceSessionIdempotencyKey(operation, meta.idempotencyKey);
    return this.#withTransaction(async (client) => {
      const { actor, role } = await this.#lockHumanWriter(client, hash, organization);
      const requestDigest = digestCommerceSessionIssueRequest(
        {
          organizationId: organization,
          actorAccountId: actor,
          actorRole: role,
          sessionContextDigest,
          mutationId: meta.mutationId,
        },
        subject,
        policy,
        duration,
      );
      const result = await client.query<MutationRow>(
        `SELECT out_replayed, out_session_id, out_organization_id, out_subject_agent_id, out_policy_id,
                out_issued_at::text AS out_issued_at,
                out_initial_expires_at::text AS out_initial_expires_at,
                out_expires_at::text AS out_expires_at,
                out_exchanged_at::text AS out_exchanged_at,
                out_agent_session_id, out_credential_id,
                out_revoked_at::text AS out_revoked_at,
                out_handoff_expires_at::text AS out_handoff_expires_at,
                out_committed_at::text AS out_committed_at
           FROM openarc_durable.issue_commerce_session(
             $1, $2, $3, $4, $5, $6, $7::uuid, $8, $9, $10)`,
        [
          hash,
          organization,
          subject,
          policy,
          duration,
          handoffHash,
          meta.mutationId,
          keyHash,
          requestDigest,
          sessionContextDigest,
        ],
      );
      const row = requireExactlyOne(result.rows);
      requireMutationRowKeys(row);
      const handoffExpiresAt = iso(row.out_handoff_expires_at);
      const metadataOut = this.#projectMetadata(row, organization, subject, policy);
      const receipt = this.#projectReceipt(row, operation, meta.mutationId, row.out_session_id);
      requireHandoffExpiryBounds(
        handoffExpiresAt,
        metadataOut.issuedAt,
        iso(row.out_initial_expires_at),
      );
      if (
        metadataOut.organizationId !== organization ||
        metadataOut.subjectAgentId !== subject ||
        metadataOut.policyId !== policy ||
        metadataOut.sessionId !== row.out_session_id
      ) {
        failOutput();
      }
      return {
        replayed: requireOutputBoolean(row.out_replayed),
        metadata: metadataOut,
        receipt,
        handoffExpiresAt,
      };
    });
  }

  async exchangeCommerceSession(
    agentSessionHash: unknown,
    handoffHash: unknown,
    input: ExchangeCommerceSessionInput,
    metadata: unknown,
  ): Promise<CommerceSessionMutationDbResult> {
    const hash = requireSessionHash(agentSessionHash);
    const handoff = requireHandoffHash(handoffHash);
    if (!isRecord(input)) fail('COMMERCE_SESSION_STORE_INPUT_INVALID');
    requireExactKeys(input, ['tokenHash', 'hashVersion']);
    const tokenHash = requireTokenHash(input.tokenHash);
    requireHashVersionOne(input.hashVersion);
    const meta = requireMetadata(metadata);
    const operation: CommerceSessionOperation = 'control.commerce_session.exchange';
    const sessionContextDigest = digestCommerceSessionMachineContext(hash);
    const keyHash = digestCommerceSessionIdempotencyKey(operation, meta.idempotencyKey);
    return this.#withTransaction(async (client) => {
      // Narrow immutable-ID resolution only: NO old locking authority helper runs
      // before the exchange helper's canonical locked sequence. Every returned
      // binding is revalidated inside the helper under the full lock order.
      const machine = await this.#resolveMachineContext(client, hash);
      const requestDigest = digestCommerceSessionExchangeRequest({
        organizationId: machine.organizationId,
        issuerAccountId: machine.issuerAccountId,
        agentSessionHash: hash,
        credentialId: machine.credentialId,
        handoffHash: handoff,
        sessionContextDigest,
        mutationId: meta.mutationId,
      });
      const result = await client.query<MutationRow>(
        `SELECT out_replayed, out_session_id, out_organization_id, out_subject_agent_id,
                out_policy_id,
                out_issued_at::text AS out_issued_at,
                out_initial_expires_at::text AS out_initial_expires_at,
                out_expires_at::text AS out_expires_at,
                out_exchanged_at::text AS out_exchanged_at,
                out_agent_session_id, out_credential_id,
                out_revoked_at::text AS out_revoked_at,
                out_handoff_expires_at::text AS out_handoff_expires_at,
                out_committed_at::text AS out_committed_at
           FROM openarc_durable.exchange_commerce_session(
             $1, $2, $3, $4::uuid, $5, $6, $7)`,
        [hash, handoff, tokenHash, meta.mutationId, keyHash, requestDigest, sessionContextDigest],
      );
      const row = requireExactlyOne(result.rows);
      requireMutationRowKeys(row);
      // The exchange helper always returns the handoff expiry still bound.
      if (row.out_handoff_expires_at === null || row.out_handoff_expires_at === undefined) failOutput();
      iso(row.out_handoff_expires_at);
      const metadataOut = this.#projectMetadata(
        row,
        machine.organizationId,
        row.out_subject_agent_id,
        row.out_policy_id,
      );
      const receipt = this.#projectReceipt(row, operation, meta.mutationId, row.out_session_id);
      if (
        metadataOut.organizationId !== machine.organizationId ||
        metadataOut.sessionId !== row.out_session_id
      ) {
        failOutput();
      }
      return {
        replayed: requireOutputBoolean(row.out_replayed),
        metadata: metadataOut,
        receipt,
      };
    });
  }

  async revokeCommerceSession(
    humanSessionHash: unknown,
    organizationId: unknown,
    sessionId: unknown,
    metadata: unknown,
  ): Promise<CommerceSessionMutationDbResult> {
    const hash = requireSessionHash(humanSessionHash);
    const organization = requireOrganization(organizationId);
    const session = requireSessionId(sessionId);
    const meta = requireMetadata(metadata);
    const operation: CommerceSessionOperation = 'control.commerce_session.revoke';
    const sessionContextDigest = digestCommerceSessionHumanContext(operation, hash);
    const keyHash = digestCommerceSessionIdempotencyKey(operation, meta.idempotencyKey);
    return this.#withTransaction(async (client) => {
      const { actor, role } = await this.#lockHumanWriter(client, hash, organization);
      const requestDigest = digestCommerceSessionRevokeRequest(
        {
          organizationId: organization,
          actorAccountId: actor,
          actorRole: role,
          sessionContextDigest,
          mutationId: meta.mutationId,
        },
        session,
      );
      const result = await client.query<MutationRow>(
        `SELECT out_replayed, out_session_id, out_organization_id, out_subject_agent_id, out_policy_id,
                out_issued_at::text AS out_issued_at,
                out_initial_expires_at::text AS out_initial_expires_at,
                out_expires_at::text AS out_expires_at,
                out_exchanged_at::text AS out_exchanged_at,
                out_agent_session_id, out_credential_id,
                out_revoked_at::text AS out_revoked_at,
                out_handoff_expires_at::text AS out_handoff_expires_at,
                out_committed_at::text AS out_committed_at
           FROM openarc_durable.revoke_commerce_session(
             $1, $2, $3::uuid, $4::uuid, $5, $6, $7)`,
        [hash, organization, session, meta.mutationId, keyHash, requestDigest, sessionContextDigest],
      );
      const row = requireExactlyOne(result.rows);
      requireMutationRowKeys(row);
      // The revoke helper never returns a handoff binding: SQL returns exact
      // NULL. A present-but-undefined value is malformed, not an absent binding.
      if (row.out_handoff_expires_at !== null) failOutput();
      const metadataOut = this.#projectMetadata(
        row,
        organization,
        row.out_subject_agent_id,
        row.out_policy_id,
      );
      const receipt = this.#projectReceipt(row, operation, meta.mutationId, row.out_session_id);
      if (metadataOut.revokedAt === null) failOutput();
      if (metadataOut.organizationId !== organization || metadataOut.sessionId !== session) {
        failOutput();
      }
      return {
        replayed: requireOutputBoolean(row.out_replayed),
        metadata: metadataOut,
        receipt,
      };
    });
  }

  /**
   * Resolve a presented commerce-session BEARER token hash into safe session
   * metadata, or null when that hash names no exchanged session.
   *
   * This is the ONE read the agent lane needs: `getCommerceSessionStatus`
   * requires a HUMAN session hash plus an organization and a session id, so it
   * can never resolve a bearer. The schema13 helper keys solely on the
   * exchanged handoff's `token_hash`, so nothing the caller supplies other than
   * that hash can influence the row, and the organization, subject, policy and
   * session id are read back from the resolved row rather than echoed.
   *
   * It REPORTS, it does not judge. A revoked or expired session still resolves,
   * carrying its real `revokedAt`/`expiresAt`, so the service can reject it
   * explicitly instead of seeing an indistinguishable not-found. An unknown
   * hash, a handoff hash, a human or machine session hash and an
   * unexchanged handoff are all the identical `null`.
   *
   * Validation mirrors every other read in this module exactly: the driver row
   * must carry the precise expected keyset (so an internal hash/parent column
   * can never be silently stripped into a passing projection), every field is
   * re-validated before projection, and a row whose identity is internally
   * inconsistent raises the module's fixed UNAVAILABLE rather than being
   * relabelled as a not-found or an input error.
   */
  async getCommerceSessionByHash(
    tokenHash: unknown,
  ): Promise<CommerceControlSessionMetadata | null> {
    const hash = requireTokenHash(tokenHash);
    return this.#withTransaction(async (client) => {
      const result = await client.query<SessionRow>(
        `SELECT out_session_id, out_organization_id, out_subject_agent_id, out_policy_id,
                out_issued_at::text AS out_issued_at,
                out_initial_expires_at::text AS out_initial_expires_at,
                out_expires_at::text AS out_expires_at,
                out_exchanged_at::text AS out_exchanged_at,
                out_agent_session_id, out_credential_id,
                out_revoked_at::text AS out_revoked_at
           FROM openarc_durable.read_commerce_session_by_token($1)`,
        [hash],
      );
      const row = requireAtMostOne(result.rows);
      if (row === undefined) return null;
      requireSessionRowKeys(row, false);
      const metadata = this.#projectMetadata(
        row,
        row.out_organization_id,
        row.out_subject_agent_id,
        row.out_policy_id,
      );
      // A bearer only exists on a CONSUMED handoff, and the schema9 exchange
      // shape constraint pairs that consumption with a non-null exchangedAt and
      // a complete machine binding. A row reaching here unexchanged is a
      // malformed/forged driver row, never a legitimate pending session, so it
      // is the fixed UNAVAILABLE rather than a silent null.
      if (metadata.exchangedAt === null) failOutput();
      if (
        metadata.organizationId !== row.out_organization_id ||
        metadata.subjectAgentId !== row.out_subject_agent_id ||
        metadata.policyId !== row.out_policy_id ||
        metadata.sessionId !== row.out_session_id
      ) {
        failOutput();
      }
      return metadata;
    });
  }

  async getCommerceSessionStatus(
    humanSessionHash: unknown,
    organizationId: unknown,
    sessionId: unknown,
  ): Promise<CommerceSessionStatusResult> {
    const hash = requireSessionHash(humanSessionHash);
    const organization = requireOrganization(organizationId);
    const session = requireSessionId(sessionId);
    return this.#withTransaction(async (client) => {
      const result = await client.query<SessionRow>(
        `SELECT out_session_id, out_organization_id, out_subject_agent_id, out_policy_id,
                out_issued_at::text AS out_issued_at,
                out_initial_expires_at::text AS out_initial_expires_at,
                out_expires_at::text AS out_expires_at,
                out_exchanged_at::text AS out_exchanged_at,
                out_agent_session_id, out_credential_id,
                out_revoked_at::text AS out_revoked_at,
                out_status
           FROM openarc_durable.read_commerce_session($1, $2, $3::uuid)`,
        [hash, organization, session],
      );
      const row = requireAtMostOne(result.rows);
      if (row === undefined) return { organizationId: organization, item: null };
      if (row.out_session_id !== session || row.out_organization_id !== organization) failOutput();
      const item = this.#projectStatusItem(row);
      if (item.metadata.sessionId !== session || item.metadata.organizationId !== organization) {
        failOutput();
      }
      return { organizationId: organization, item };
    });
  }

  async listCommerceSessions(
    humanSessionHash: unknown,
    organizationId: unknown,
    options?: ListCommerceSessionsInput,
  ): Promise<ListCommerceSessionsResult> {
    const hash = requireSessionHash(humanSessionHash);
    const organization = requireOrganization(organizationId);
    const parsedOptions = requireOptions(options, ['afterSessionId', 'limit']);
    const limit = requirePage(parsedOptions['limit']);
    const after =
      parsedOptions['afterSessionId'] === undefined
        ? null
        : requireSessionId(parsedOptions['afterSessionId']);
    return this.#withTransaction(async (client) => {
      const result = await client.query<SessionRow>(
        `SELECT out_session_id, out_organization_id, out_subject_agent_id, out_policy_id,
                out_issued_at::text AS out_issued_at,
                out_initial_expires_at::text AS out_initial_expires_at,
                out_expires_at::text AS out_expires_at,
                out_exchanged_at::text AS out_exchanged_at,
                out_agent_session_id, out_credential_id,
                out_revoked_at::text AS out_revoked_at,
                out_status
           FROM openarc_durable.list_commerce_sessions($1, $2, $3::uuid, $4)`,
        [hash, organization, after, limit + 1],
      );
      if (result.rows.length > limit + 1) failOutput();
      const projected = result.rows.map((row) => this.#projectStatusItem(row));
      // Validate the whole fetched lookahead (limit+1) BEFORE slicing: every row
      // must bind the requested organisation and ids must be strictly ascending.
      let previousSessionId: string | undefined;
      for (const item of projected) {
        if (item.metadata.organizationId !== organization) failOutput();
        if (previousSessionId !== undefined && !(previousSessionId < item.metadata.sessionId)) {
          failOutput();
        }
        previousSessionId = item.metadata.sessionId;
      }
      const visible = projected.slice(0, limit);
      const nextCursor =
        result.rows.length > limit ? visible[visible.length - 1]?.metadata.sessionId ?? null : null;
      const page = CommerceControlSessionListSchema.safeParse({
        organizationId: organization,
        items: visible,
        nextCursor,
      });
      if (!page.success) failOutput();
      if (after !== null) {
        const first = visible[0]?.metadata.sessionId;
        if (first !== undefined && first <= after) failOutput();
      }
      return { items: visible, nextCursor };
    });
  }

  async getHumanCommerceSessionMutationStatus(
    humanSessionHash: unknown,
    organizationId: unknown,
    mutationId: unknown,
  ): Promise<CommerceSessionMutationStatus> {
    const hash = requireSessionHash(humanSessionHash);
    const organization = requireOrganization(organizationId);
    const mutation = requireMutationInput(mutationId);
    return this.#withTransaction(async (client) => {
      const result = await client.query<ReceiptFields>(
        `SELECT out_mutation_id, out_operation, out_resource_type, out_resource_id,
                out_committed_at::text AS out_committed_at
           FROM openarc_durable.read_human_commerce_session_mutation_status($1, $2, $3::uuid)`,
        [hash, organization, mutation],
      );
      return this.#projectStatusResult(organization, mutation, result.rows, HUMAN_RECEIPT_ROW_KEYS);
    });
  }

  async getAgentCommerceSessionMutationStatus(
    agentSessionHash: unknown,
    mutationId: unknown,
  ): Promise<CommerceSessionMutationStatus> {
    const hash = requireSessionHash(agentSessionHash);
    const mutation = requireMutationInput(mutationId);
    return this.#withTransaction(async (client) => {
      const result = await client.query<ReceiptFields & { out_organization_id: string }>(
        `SELECT out_mutation_id, out_operation, out_resource_type, out_resource_id,
                out_committed_at::text AS out_committed_at, out_organization_id
           FROM openarc_durable.read_agent_commerce_session_mutation_status($1, $2::uuid)`,
        [hash, mutation],
      );
      const row = requireAtMostOne(result.rows);
      if (row === undefined) return { status: 'not_found' } as const;
      return this.#projectStatusResult(
        row.out_organization_id,
        mutation,
        [row],
        AGENT_RECEIPT_ROW_KEYS,
      );
    });
  }

  #projectStatusResult(
    organization: string,
    mutation: string,
    rows: readonly ReceiptFields[],
    expectedKeys: readonly string[],
  ): CommerceSessionMutationStatus {
    const row = requireAtMostOne(rows);
    if (row === undefined) return { status: 'not_found' } as const;
    // The reader must return the exact keyset and the exact mutation that was
    // requested; a mismatched/echoed row is a fixed UNAVAILABLE.
    requireOutputKeyset(row as unknown as Record<string, unknown>, expectedKeys);
    if (row.out_mutation_id !== mutation) failOutput();
    if (!ORG_ID.test(organization)) failOutput();
    const operation = this.#requireOperation(row.out_operation);
    if (row.out_resource_type !== CONTROL_SESSION_RESOURCE_TYPE) failOutput();
    if (!SESSION_ID.test(row.out_resource_id)) failOutput();
    const sessionId = row.out_resource_id;
    const receipt = this.#receiptFrom(
      operation,
      mutation,
      sessionId,
      iso(row.out_committed_at),
    );
    const parsed = CommerceControlSessionMutationStatusSchema.safeParse({
      organizationId: organization,
      mutationId: mutation,
      status: 'committed',
      receipt,
    });
    if (!parsed.success) failOutput();
    return { status: 'committed' as const, receipt };
  }

  async #lockHumanWriter(
    client: TenantClient,
    hash: string,
    organization: string,
  ): Promise<{ actor: string; role: string }> {
    const result = await client.query<{ out_actor: string; out_role: string }>(
      `SELECT out_actor, out_role FROM openarc_durable.lock_commerce_writer($1, $2)`,
      [hash, organization],
    );
    const row = result.rows[0];
    if (
      row === undefined ||
      typeof row.out_actor !== 'string' ||
      typeof row.out_role !== 'string'
    ) {
      fail('COMMERCE_SESSION_STORE_FORBIDDEN');
    }
    return { actor: row.out_actor, role: row.out_role };
  }

  async #resolveMachineContext(
    client: TenantClient,
    hash: string,
  ): Promise<{ organizationId: string; issuerAccountId: string; credentialId: string }> {
    const result = await client.query<{
      out_organization_id: string;
      out_credential_id: string;
      out_issuer_account_id: string;
    }>(
      `SELECT out_organization_id, out_credential_id, out_issuer_account_id
         FROM openarc_durable.resolve_agent_session_context($1)`,
      [hash],
    );
    const row = result.rows[0];
    if (
      row === undefined ||
      typeof row.out_organization_id !== 'string' ||
      typeof row.out_credential_id !== 'string' ||
      typeof row.out_issuer_account_id !== 'string'
    ) {
      fail('COMMERCE_SESSION_STORE_FORBIDDEN');
    }
    return {
      organizationId: row.out_organization_id,
      issuerAccountId: row.out_issuer_account_id,
      credentialId: row.out_credential_id,
    };
  }

  #requireOperation(value: unknown): CommerceSessionOperation {
    if (
      value !== 'control.commerce_session.issue' &&
      value !== 'control.commerce_session.exchange' &&
      value !== 'control.commerce_session.revoke'
    ) {
      failOutput();
    }
    return value;
  }

  #projectMetadata(
    row: SessionRow,
    organization: string,
    subject: string,
    policy: string,
  ): CommerceControlSessionMetadata {
    // Bind the REAL helper row values, never the request. A driver row that
    // names a different org/subject/policy/session is a fixed UNAVAILABLE.
    if (
      !SESSION_ID.test(row.out_session_id) ||
      !ORG_ID.test(row.out_organization_id) ||
      !AGENT_ID.test(row.out_subject_agent_id) ||
      !POLICY_ID.test(row.out_policy_id) ||
      row.out_organization_id !== organization ||
      row.out_subject_agent_id !== subject ||
      row.out_policy_id !== policy
    ) {
      failOutput();
    }
    const issuedAt = iso(row.out_issued_at);
    const initialExpiresAt = iso(row.out_initial_expires_at);
    const expiresAt = iso(row.out_expires_at);
    const exchangedAt = isoOrNull(row.out_exchanged_at);
    const revokedAt = isoOrNull(row.out_revoked_at);
    // The INITIAL issuance window is a durable historical fact and is validated
    // independently of any later exchange-shortened effective expiry.
    if (compareIsoTimestamps(initialExpiresAt, issuedAt) <= 0) failOutput();
    if (isoToMicros(initialExpiresAt) > isoToMicros(issuedAt) + 900_000_000n) failOutput();
    if (compareIsoTimestamps(expiresAt, initialExpiresAt) > 0) failOutput();
    // Machine binding is paired and canonical, and must agree with exchangedAt.
    const agentSessionId = row.out_agent_session_id;
    const credentialId = row.out_credential_id;
    // DB outputs are explicit null when unexchanged. A present-but-undefined
    // binding field is a malformed driver row, never a valid unexchanged state.
    if (agentSessionId === undefined || credentialId === undefined) failOutput();
    const hasAgentSession = agentSessionId !== null;
    const hasCredential = credentialId !== null;
    if (hasAgentSession !== hasCredential) failOutput();
    if (hasAgentSession) {
      if (
        typeof agentSessionId !== 'string' ||
        typeof credentialId !== 'string' ||
        !SESSION_ID.test(agentSessionId) ||
        !SESSION_ID.test(credentialId)
      ) {
        failOutput();
      }
    }
    if ((exchangedAt === null) !== !hasAgentSession) failOutput();
    const parsed = CommerceControlSessionMetadataSchema.safeParse({
      schemaVersion: 'openarc.control.commerce-session.v1',
      sessionId: row.out_session_id,
      organizationId: organization,
      subjectAgentId: subject,
      policyId: policy,
      scopes: ['commerce.authorize'],
      networkId: 'eip155:5042002',
      asset: 'USDC',
      representation: 'erc20',
      decimals: 6,
      issuedAt,
      expiresAt,
      exchangedAt,
      revokedAt,
    });
    if (!parsed.success) failOutput();
    return parsed.data;
  }

  #projectStatusItem(row: SessionRow): CommerceControlSessionStatusItem {
    requireSessionRowKeys(row, true);
    const metadata = this.#projectMetadata(
      row,
      row.out_organization_id,
      row.out_subject_agent_id,
      row.out_policy_id,
    );
    const status = requireStatusValue(row.out_status);
    const parsed = CommerceControlSessionStatusItemSchema.safeParse({ metadata, status });
    if (!parsed.success) failOutput();
    return parsed.data;
  }

  #projectReceipt(
    row: MutationRow,
    operation: CommerceSessionOperation,
    mutationId: string,
    sessionId: string,
  ): CommerceControlSessionReceipt {
    const committedAt = iso(row.out_committed_at);
    return this.#receiptFrom(operation, mutationId, sessionId, committedAt);
  }

  #receiptFrom(
    operation: CommerceSessionOperation,
    mutationId: string,
    sessionId: string,
    committedAt: string,
  ): CommerceControlSessionReceipt {
    const parsed = CommerceControlSessionReceiptSchema.safeParse({
      mutationId,
      operation,
      resourceType: CONTROL_SESSION_RESOURCE_TYPE,
      resourceId: sessionId,
      committedAt,
    });
    if (!parsed.success) failOutput();
    return parsed.data;
  }

  async #assertReady(client: TenantClient): Promise<void> {
    const tables = await client.query<{ n: number; all_enabled: boolean; all_forced: boolean }>(
      `SELECT count(*)::int AS n,
              bool_and(c.relrowsecurity) AS all_enabled,
              bool_and(c.relforcerowsecurity) AS all_forced
         FROM pg_class c
         JOIN pg_namespace ns ON ns.oid = c.relnamespace
        WHERE ns.nspname = 'openarc_durable'
          AND c.relkind = 'r'
          AND c.relname IN ('commerce_sessions', 'commerce_session_handoffs')`,
    );
    const state = tables.rows[0];
    if (state === undefined || state.n !== 2 || state.all_enabled !== true || state.all_forced !== true) {
      fail('COMMERCE_SESSION_STORE_UNAVAILABLE');
    }
    const owners = await client.query<{ n: number }>(
      `SELECT count(*)::int AS n
         FROM pg_class c
         JOIN pg_namespace ns ON ns.oid = c.relnamespace
         JOIN pg_roles r ON r.oid = c.relowner
        WHERE ns.nspname = 'openarc_durable'
          AND c.relkind = 'r'
          AND c.relname IN ('commerce_sessions', 'commerce_session_handoffs')
          AND r.rolname = 'openarc_migrator'`,
    );
    if ((owners.rows[0]?.n ?? -1) !== 2) fail('COMMERCE_SESSION_STORE_UNAVAILABLE');

    const access = await client.query<{ n: number }>(
      `WITH reachable AS (
         SELECT r.oid FROM pg_roles r
          WHERE r.oid = (SELECT oid FROM pg_roles WHERE rolname = current_user)
             OR pg_has_role(current_user, r.oid, 'MEMBER')
       )
       SELECT count(*)::int AS n
         FROM pg_class c
         JOIN pg_namespace ns ON ns.oid = c.relnamespace
        WHERE ns.nspname = 'openarc_durable'
          AND c.relkind = 'r'
          AND c.relname IN ('commerce_sessions', 'commerce_session_handoffs')
          AND EXISTS (
            SELECT 1 FROM reachable x
             WHERE has_table_privilege(x.oid, c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
          )`,
    );
    if ((access.rows[0]?.n ?? -1) !== 0) fail('COMMERCE_SESSION_STORE_UNAVAILABLE');

    await this.#assertIntegrity(client);
    await this.#assertHelpers(client);
  }

  async #assertIntegrity(client: TenantClient): Promise<void> {
    const expectedConstraints: readonly {
      readonly table: string;
      readonly name: string;
      readonly type: string;
      readonly def: string;
    }[] = [
      {
        table: 'commerce_sessions',
        name: 'commerce_sessions_org_fk',
        type: 'f',
        def: 'FOREIGN KEY (organization_id) REFERENCES openarc_tenant.organizations(organization_id) ON DELETE RESTRICT',
      },
      {
        table: 'commerce_sessions',
        name: 'commerce_sessions_parent_human_account_id_fkey',
        type: 'f',
        def: 'FOREIGN KEY (parent_human_account_id) REFERENCES openarc_auth.accounts(account_id) ON DELETE RESTRICT',
      },
      {
        table: 'commerce_sessions',
        name: 'commerce_sessions_subject_fk',
        type: 'f',
        def: 'FOREIGN KEY (organization_id, subject_agent_id) REFERENCES openarc_tenant.agents(organization_id, agent_id) ON DELETE RESTRICT',
      },
      {
        table: 'commerce_sessions',
        name: 'commerce_sessions_policy_fk',
        type: 'f',
        def: 'FOREIGN KEY (organization_id, policy_id) REFERENCES openarc_tenant.budget_policy_roots(organization_id, policy_id) ON DELETE RESTRICT',
      },
      {
        table: 'commerce_sessions',
        name: 'commerce_sessions_credential_fk',
        type: 'f',
        def: 'FOREIGN KEY (organization_id, credential_id) REFERENCES openarc_durable.agent_credentials(organization_id, credential_id) ON DELETE RESTRICT',
      },
      {
        table: 'commerce_sessions',
        name: 'commerce_sessions_agent_session_fk',
        type: 'f',
        def: 'FOREIGN KEY (agent_session_id) REFERENCES openarc_durable.agent_sessions(session_id) ON DELETE RESTRICT',
      },
      {
        table: 'commerce_sessions',
        name: 'commerce_sessions_id_valid',
        type: 'c',
        def: 'CHECK (openarc_durable.is_canonical_commerce_session_id((session_id)::text))',
      },
      {
        table: 'commerce_sessions',
        name: 'commerce_sessions_parent_hash_valid',
        type: 'c',
        def: 'CHECK (openarc_durable.is_canonical_hex64(parent_human_session_hash))',
      },
      {
        table: 'commerce_sessions',
        name: 'commerce_sessions_subject_valid',
        type: 'c',
        def: 'CHECK (openarc_durable.is_canonical_agent_id(subject_agent_id))',
      },
      {
        table: 'commerce_sessions',
        name: 'commerce_sessions_policy_valid',
        type: 'c',
        def: 'CHECK (openarc_durable.is_canonical_policy_id(policy_id))',
      },
      {
        table: 'commerce_sessions',
        name: 'commerce_sessions_scope_valid',
        type: 'c',
        def: "CHECK (((scope = 'commerce.authorize'::text) AND (scope_version = 1)))",
      },
      {
        table: 'commerce_sessions',
        name: 'commerce_sessions_network_valid',
        type: 'c',
        def: "CHECK (((network_id = 'eip155:5042002'::text) AND (asset = 'USDC'::text) AND (representation = 'erc20'::text) AND (decimals = 6)))",
      },
      {
        table: 'commerce_sessions',
        name: 'commerce_sessions_exchange_shape',
        type: 'c',
        def: 'CHECK ((((agent_session_id IS NULL) AND (credential_id IS NULL) AND (exchanged_at IS NULL)) OR ((agent_session_id IS NOT NULL) AND (credential_id IS NOT NULL) AND (exchanged_at IS NOT NULL) AND (exchanged_at >= issued_at) AND (exchanged_at < initial_expires_at) AND (exchanged_at <= expires_at))))',
      },
      {
        table: 'commerce_sessions',
        name: 'commerce_sessions_issuance_window',
        type: 'c',
        def: "CHECK (((initial_expires_at > issued_at) AND (initial_expires_at <= (issued_at + '00:15:00'::interval))))",
      },
      {
        table: 'commerce_sessions',
        name: 'commerce_sessions_expiry_valid',
        type: 'c',
        def: 'CHECK (((expires_at > issued_at) AND (expires_at <= initial_expires_at)))',
      },
      {
        table: 'commerce_sessions',
        name: 'commerce_sessions_revocation_shape',
        type: 'c',
        def: 'CHECK (((revoked_at IS NULL) OR ((revoked_at >= issued_at) AND ((exchanged_at IS NULL) OR (revoked_at >= exchanged_at)))))',
      },
      {
        table: 'commerce_sessions',
        name: 'commerce_sessions_session_unique',
        type: 'u',
        def: 'UNIQUE (session_id)',
      },
      {
        table: 'commerce_session_handoffs',
        name: 'commerce_session_handoffs_hash_valid',
        type: 'c',
        def: 'CHECK (openarc_durable.is_canonical_hex64(handoff_hash))',
      },
      {
        table: 'commerce_session_handoffs',
        name: 'commerce_session_handoffs_hash_version_valid',
        type: 'c',
        def: 'CHECK ((hash_version = 1))',
      },
      {
        table: 'commerce_session_handoffs',
        name: 'commerce_session_handoffs_window',
        type: 'c',
        def: "CHECK (((expires_at > issued_at) AND (expires_at <= (issued_at + '00:05:00'::interval))))",
      },
      {
        table: 'commerce_session_handoffs',
        name: 'commerce_session_handoffs_session_fk',
        type: 'f',
        def: 'FOREIGN KEY (organization_id, session_id) REFERENCES openarc_durable.commerce_sessions(organization_id, session_id) ON DELETE RESTRICT',
      },
      {
        table: 'commerce_session_handoffs',
        name: 'commerce_session_handoffs_session_unique',
        type: 'u',
        def: 'UNIQUE (organization_id, session_id)',
      },
      {
        table: 'commerce_session_handoffs',
        name: 'commerce_session_handoffs_consumption_shape',
        type: 'c',
        def: 'CHECK ((((consumed_at IS NULL) AND (token_hash IS NULL) AND (token_hash_version IS NULL)) OR ((consumed_at IS NOT NULL) AND (consumed_at >= issued_at) AND (token_hash IS NOT NULL) AND openarc_durable.is_canonical_hex64(token_hash) AND (token_hash_version = 1) AND (consumed_at <= expires_at))))',
      },
      {
        table: 'commerce_session_handoffs',
        name: 'commerce_session_handoffs_token_unique',
        type: 'u',
        def: 'UNIQUE (token_hash)',
      },
    ];
    const constraints = await client.query<{
      relname: string;
      conname: string;
      contype: string;
      convalidated: boolean;
      condef: string;
    }>(
      `SELECT c.relname, con.conname, con.contype, con.convalidated,
              pg_get_constraintdef(con.oid) AS condef
         FROM pg_constraint con
         JOIN pg_class c ON c.oid = con.conrelid
         JOIN pg_namespace ns ON ns.oid = c.relnamespace
        WHERE ns.nspname = 'openarc_durable'
          AND c.relname IN ('commerce_sessions', 'commerce_session_handoffs')
          AND con.conname = ANY ($1::text[])`,
      [expectedConstraints.map((entry) => entry.name)],
    );
    const byName = new Map(constraints.rows.map((row) => [row.conname, row]));
    for (const expected of expectedConstraints) {
      const row = byName.get(expected.name);
      if (row === undefined) fail('COMMERCE_SESSION_STORE_UNAVAILABLE');
      if (
        row.relname !== expected.table ||
        row.contype !== expected.type ||
        row.convalidated !== true ||
        typeof row.condef !== 'string' ||
        row.condef !== expected.def
      ) {
        fail('COMMERCE_SESSION_STORE_UNAVAILABLE');
      }
    }

    const expectedTriggers: readonly {
      readonly table: string;
      readonly name: string;
      readonly func: string;
      readonly events: number;
    }[] = [
      {
        table: 'commerce_sessions',
        name: 'commerce_sessions_mutation',
        func: 'openarc_durable.enforce_commerce_session_mutation',
        events: 27, // BEFORE UPDATE OR DELETE, FOR EACH ROW
      },
      {
        table: 'commerce_sessions',
        name: 'commerce_sessions_binding',
        func: 'openarc_durable.enforce_commerce_session_binding',
        events: 19, // BEFORE UPDATE, FOR EACH ROW
      },
      {
        table: 'commerce_session_handoffs',
        name: 'commerce_session_handoffs_mutation',
        func: 'openarc_durable.enforce_commerce_handoff_mutation',
        events: 27, // BEFORE UPDATE OR DELETE, FOR EACH ROW
      },
      {
        table: 'commerce_session_handoffs',
        name: 'commerce_session_handoffs_window',
        func: 'openarc_durable.enforce_commerce_handoff_window',
        events: 7, // BEFORE INSERT, FOR EACH ROW
      },
    ];
    const triggers = await client.query<{
      relname: string;
      tgname: string;
      tgenabled: string;
      events: number;
      func: string;
      fn_owner: string;
      fn_config: string[];
      fn_secdef: boolean;
    }>(
      `SELECT c.relname, t.tgname, t.tgenabled, (t.tgtype & 127)::int AS events,
              format('%I.%I', fn.nspname, f.proname) AS func,
              fr.rolname AS fn_owner,
              coalesce(f.proconfig, ARRAY[]::text[]) AS fn_config,
              f.prosecdef AS fn_secdef
         FROM pg_trigger t
         JOIN pg_class c ON c.oid = t.tgrelid
         JOIN pg_namespace ns ON ns.oid = c.relnamespace
         JOIN pg_proc f ON f.oid = t.tgfoid
         JOIN pg_namespace fn ON fn.oid = f.pronamespace
         JOIN pg_roles fr ON fr.oid = f.proowner
        WHERE ns.nspname = 'openarc_durable'
          AND NOT t.tgisinternal
          AND t.tgname = ANY ($1::text[])`,
      [expectedTriggers.map((entry) => entry.name)],
    );
    const triggerByName = new Map(triggers.rows.map((row) => [row.tgname, row]));
    for (const expected of expectedTriggers) {
      const row = triggerByName.get(expected.name);
      if (row === undefined) fail('COMMERCE_SESSION_STORE_UNAVAILABLE');
      if (
        row.relname !== expected.table ||
        row.tgenabled !== 'O' ||
        row.func !== expected.func ||
        row.events !== expected.events
      ) {
        fail('COMMERCE_SESSION_STORE_UNAVAILABLE');
      }
      if (
        row.fn_owner !== 'openarc_migrator' ||
        row.fn_secdef !== false ||
        !Array.isArray(row.fn_config) ||
        !row.fn_config.includes('search_path=pg_catalog')
      ) {
        fail('COMMERCE_SESSION_STORE_UNAVAILABLE');
      }
    }

    const tokenIndex = await client.query<{
      indisunique: boolean;
      indisvalid: boolean;
      indisready: boolean;
    }>(
      `SELECT i.indisunique, i.indisvalid, i.indisready
         FROM pg_index i
         JOIN pg_class ic ON ic.oid = i.indexrelid
         JOIN pg_namespace ns ON ns.oid = ic.relnamespace
        WHERE ns.nspname = 'openarc_durable'
          AND ic.relname = 'commerce_session_handoffs_token_unique'`,
    );
    const token = tokenIndex.rows[0];
    if (
      token === undefined ||
      token.indisunique !== true ||
      token.indisvalid !== true ||
      token.indisready !== true
    ) {
      fail('COMMERCE_SESSION_STORE_UNAVAILABLE');
    }
  }

  async #assertHelpers(client: TenantClient): Promise<void> {
    const expected: readonly { name: string; args: string }[] = [
      {
        name: 'issue_commerce_session',
        args: 'human_session_hash text, organization_id text, subject_agent_id text, policy_id_input text, duration_seconds integer, handoff_hash text, mutation_id uuid, key_hash text, request_digest text, session_context_digest text',
      },
      {
        name: 'exchange_commerce_session',
        args: 'agent_session_hash text, handoff_hash text, token_hash text, mutation_id uuid, key_hash text, request_digest text, session_context_digest text',
      },
      {
        name: 'revoke_commerce_session',
        args: 'human_session_hash text, organization_id text, session_id_input uuid, mutation_id uuid, key_hash text, request_digest text, session_context_digest text',
      },
      { name: 'read_commerce_session', args: 'human_session_hash text, organization_id text, session_id_input uuid' },
      { name: 'read_commerce_session_by_token', args: 'commerce_token_hash text' },
      { name: 'list_commerce_sessions', args: 'human_session_hash text, organization_id text, after_session_id uuid, page_limit integer' },
      { name: 'read_human_commerce_session_mutation_status', args: 'human_session_hash text, organization_id text, mutation_id uuid' },
      { name: 'read_agent_commerce_session_mutation_status', args: 'agent_session_hash text, mutation_id uuid' },
      { name: 'lock_commerce_reader', args: 'session_hash text, organization_id text' },
      { name: 'lock_commerce_writer', args: 'session_hash text, organization_id text' },
      { name: 'resolve_agent_session_context', args: 'agent_session_token_hash text' },
    ];
    const helpers = await client.query<{
      proname: string;
      args: string;
      owner: string;
      prosecdef: boolean;
      config: string[];
      app_exec: boolean;
      public_grants: number;
      forbidden_grants: number;
    }>(
      `SELECT p.proname,
              pg_get_function_identity_arguments(p.oid) AS args,
              r.rolname AS owner,
              p.prosecdef,
              coalesce(p.proconfig, ARRAY[]::text[]) AS config,
              has_function_privilege('openarc_tenant_app', p.oid, 'EXECUTE') AS app_exec,
              (SELECT count(*)::int
                 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE') AS public_grants,
              (SELECT count(*)::int
                 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                 JOIN pg_roles gr ON gr.oid = a.grantee
                WHERE gr.rolname IN ('openarc_worker_app', 'openarc_auth_app')
                  AND a.privilege_type = 'EXECUTE') AS forbidden_grants
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         JOIN pg_roles r ON r.oid = p.proowner
        WHERE n.nspname = 'openarc_durable'
          AND p.prokind = 'f'
          AND p.proname IN (
            'issue_commerce_session', 'exchange_commerce_session', 'revoke_commerce_session',
            'read_commerce_session', 'read_commerce_session_by_token', 'list_commerce_sessions',
            'read_human_commerce_session_mutation_status',
            'read_agent_commerce_session_mutation_status', 'lock_commerce_reader',
            'lock_commerce_writer', 'resolve_agent_session_context'
          )
        ORDER BY p.proname, p.oid`,
    );
    const byName = new Map(helpers.rows.map((row) => [row.proname, row]));
    for (const spec of expected) {
      const row = byName.get(spec.name);
      if (row === undefined) fail('COMMERCE_SESSION_STORE_UNAVAILABLE');
      if (
        row.args !== spec.args ||
        row.owner !== 'openarc_migrator' ||
        row.prosecdef !== true ||
        !Array.isArray(row.config) ||
        !row.config.includes('search_path=pg_catalog') ||
        row.app_exec !== true ||
        row.public_grants !== 0 ||
        row.forbidden_grants !== 0
      ) {
        fail('COMMERCE_SESSION_STORE_UNAVAILABLE');
      }
    }
    if (helpers.rows.length !== expected.length) fail('COMMERCE_SESSION_STORE_UNAVAILABLE');

    const internalNames = [
      'lock_commerce_human',
      'enforce_commerce_session_mutation',
      'enforce_commerce_handoff_mutation',
      'enforce_commerce_handoff_window',
      'enforce_commerce_session_binding',
      'derive_commerce_session_status',
    ] as const;
    const internal = await client.query<{
      proname: string;
      owner: string;
      config: string[];
      reachable: boolean;
    }>(
      `SELECT p.proname, r.rolname AS owner,
              coalesce(p.proconfig, ARRAY[]::text[]) AS config,
              (has_function_privilege('openarc_tenant_app', p.oid, 'EXECUTE')
               OR has_function_privilege('openarc_worker_app', p.oid, 'EXECUTE')
               OR has_function_privilege('openarc_auth_app', p.oid, 'EXECUTE')
               OR EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                           WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE')) AS reachable
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         JOIN pg_roles r ON r.oid = p.proowner
        WHERE n.nspname = 'openarc_durable'
          AND p.proname = ANY ($1::text[])`,
      [internalNames],
    );
    const internalByName = new Map(internal.rows.map((row) => [row.proname, row]));
    for (const name of internalNames) {
      const row = internalByName.get(name);
      if (
        row === undefined ||
        row.owner !== 'openarc_migrator' ||
        !Array.isArray(row.config) ||
        !row.config.includes('search_path=pg_catalog') ||
        row.reachable !== false
      ) {
        fail('COMMERCE_SESSION_STORE_UNAVAILABLE');
      }
    }

    const applied = await client.query<{ id: string; checksum: string }>(
      `SELECT id, checksum FROM openarc_meta.schema_migrations ORDER BY id`,
    );
    this.#assertExactManifest(applied.rows);
  }

  #assertExactManifest(applied: readonly { readonly id: string; readonly checksum: string }[]): void {
    let migrations: readonly { readonly id: string; readonly sql: string }[];
    try {
      migrations = loadMigrations();
    } catch {
      fail('COMMERCE_SESSION_STORE_UNAVAILABLE');
    }
    if (applied.length !== migrations.length) fail('COMMERCE_SESSION_STORE_UNAVAILABLE');
    for (let index = 0; index < applied.length; index += 1) {
      const record = applied[index];
      const manifest = migrations[index];
      if (record === undefined || manifest === undefined) fail('COMMERCE_SESSION_STORE_UNAVAILABLE');
      if (record.id !== manifest.id) fail('COMMERCE_SESSION_STORE_UNAVAILABLE');
      const checksum = createHash('sha256').update(manifest.sql, 'utf8').digest('hex');
      if (record.checksum !== checksum) fail('COMMERCE_SESSION_STORE_UNAVAILABLE');
    }
  }

  async #withTransaction<T>(work: (client: TenantClient) => Promise<T>): Promise<T> {
    let client: TenantClient;
    try {
      client = await this.#pool.connect();
    } catch {
      fail('COMMERCE_SESSION_STORE_UNAVAILABLE');
    }
    try {
      await client.query('BEGIN');
    } catch {
      this.#release(client, true);
      fail('COMMERCE_SESSION_STORE_UNAVAILABLE');
    }
    let result: T;
    try {
      result = await work(client);
    } catch (error) {
      let rolledBack = false;
      try {
        await client.query('ROLLBACK');
        rolledBack = true;
      } catch {
        rolledBack = false;
      }
      this.#release(client, !rolledBack);
      throw normalizeError(error);
    }
    try {
      await client.query('COMMIT');
    } catch {
      this.#release(client, true);
      fail('COMMERCE_SESSION_STORE_OUTCOME_UNKNOWN');
    }
    this.#release(client, false);
    return result;
  }

  #release(client: TenantClient, destroy: boolean): void {
    try {
      client.release(destroy);
    } catch {
      // A release failure after a confirmed outcome cannot change it.
    }
  }
}

interface ReceiptFields extends Record<string, unknown> {
  readonly out_mutation_id: string;
  readonly out_operation: string;
  readonly out_resource_type: string;
  readonly out_resource_id: string;
  readonly out_committed_at: string | Date;
}

function requireMutationInput(value: unknown): string {
  try {
    return parseMutationId(value);
  } catch {
    fail('COMMERCE_SESSION_STORE_INPUT_INVALID');
  }
}

function requireAtMostOne<T>(rows: readonly T[]): T | undefined {
  if (rows.length > 1) failOutput();
  return rows[0];
}

const SESSION_ROW_KEYS = [
  'out_session_id',
  'out_organization_id',
  'out_subject_agent_id',
  'out_policy_id',
  'out_issued_at',
  'out_initial_expires_at',
  'out_expires_at',
  'out_exchanged_at',
  'out_agent_session_id',
  'out_credential_id',
  'out_revoked_at',
] as const;

const MUTATION_ROW_KEYS = [
  'out_replayed',
  'out_session_id',
  'out_organization_id',
  'out_subject_agent_id',
  'out_policy_id',
  'out_issued_at',
  'out_initial_expires_at',
  'out_expires_at',
  'out_exchanged_at',
  'out_agent_session_id',
  'out_credential_id',
  'out_revoked_at',
  'out_handoff_expires_at',
  'out_committed_at',
] as const;

function requireMutationRowKeys(row: Record<string, unknown>): void {
  const actual = Object.keys(row).sort();
  const wanted = [...MUTATION_ROW_KEYS].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    failOutput();
  }
}

const HUMAN_RECEIPT_ROW_KEYS = [
  'out_mutation_id',
  'out_operation',
  'out_resource_type',
  'out_resource_id',
  'out_committed_at',
] as const;

const AGENT_RECEIPT_ROW_KEYS = [
  ...HUMAN_RECEIPT_ROW_KEYS,
  'out_organization_id',
] as const;

/**
 * Exact expected keyset for a projected session row. Unknown/internal columns
 * (hash, parent context, token hash) are rejected, never silently stripped.
 * Status rows additionally require the derived out_status column.
 */
function requireSessionRowKeys(row: Record<string, unknown>, withStatus: boolean): void {
  const expected: string[] = [...SESSION_ROW_KEYS];
  if (withStatus) expected.push('out_status');
  const actual = Object.keys(row).sort();
  const wanted = expected.sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    failOutput();
  }
}

/** Exact output keyset for a driver row; any malformed shape is UNAVAILABLE. */
function requireOutputKeyset(row: Record<string, unknown>, keys: readonly string[]): void {
  const actual = Object.keys(row).sort();
  const wanted = [...keys].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    failOutput();
  }
}

function requireStatusValue(value: unknown): CommerceControlSessionStatusItem['status'] {
  if (
    value !== 'handoff_pending' &&
    value !== 'active' &&
    value !== 'revoked' &&
    value !== 'expired' &&
    value !== 'invalidated'
  ) {
    failOutput();
  }
  return value;
}

function requireOutputBoolean(value: unknown): boolean {
  if (value !== true && value !== false) failOutput();
  return value;
}

/**
 * Handoff expiry must strictly follow issuance, be at or before the session's
 * INITIAL expiry, and be at most issued+300s. It is deliberately NOT compared
 * against the possibly exchange-shortened effective expiry: the handoff window
 * is a historical issuance fact. Compared with exact fractional precision.
 */
function requireHandoffExpiryBounds(
  handoffExpiresAt: string,
  issuedAt: string,
  initialExpiresAt: string,
): void {
  if (compareIsoTimestamps(handoffExpiresAt, issuedAt) <= 0) failOutput();
  if (compareIsoTimestamps(handoffExpiresAt, initialExpiresAt) > 0) failOutput();
  if (isoToMicros(handoffExpiresAt) > isoToMicros(issuedAt) + 300_000_000n) failOutput();
}

const ISO_MICROS = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/;

/** Exact microseconds-since-epoch for a canonical UTC ISO leaf. */
function isoToMicros(value: string): bigint {
  const match = ISO_MICROS.exec(value);
  if (match === null) failOutput();
  const [, y, mo, d, h, mi, s, fraction] = match;
  const millis = Date.UTC(
    Number.parseInt(y ?? '', 10),
    Number.parseInt(mo ?? '', 10) - 1,
    Number.parseInt(d ?? '', 10),
    Number.parseInt(h ?? '', 10),
    Number.parseInt(mi ?? '', 10),
    Number.parseInt(s ?? '', 10),
  );
  if (!Number.isFinite(millis)) failOutput();
  const micros = (fraction ?? '').padEnd(6, '0').slice(0, 6);
  return BigInt(millis) * 1000n + BigInt(micros);
}

function requireExactlyOne<T>(rows: readonly T[]): T {
  if (rows.length !== 1) failOutput();
  return rows[0] as T;
}

/** Structural adapter for callers that hold a raw `pg` Pool. */
export function asCommerceSessionPool(pool: Pool): TenantPool {
  return pool as unknown as TenantPool;
}

export type { Pool };
