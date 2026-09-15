import { createHash } from 'node:crypto';
import type { Pool } from 'pg';
import {
  CommerceGrantMetadataSchema,
  CommerceGrantProviderAttemptStatusSchema,
  CommerceGrantProviderViewSchema,
  CommerceGrantTokenSchema,
  COMMERCE_GRANT_METADATA_SCHEMA_VERSION,
  COMMERCE_GRANT_PROVIDER_VIEW_SCHEMA_VERSION,
  compareIsoTimestamps,
  type CommerceGrantMetadata,
  type CommerceGrantProviderAttemptStatus,
  type CommerceGrantProviderView,
  type CommerceGrantStatus,
} from '@openarc/shared';
import { loadMigrations } from './migrate.js';
import { TenantStore, type TenantClient, type TenantPool } from './tenant-store.js';
import { parseMutationId } from './tenant-durability.js';
import { CommerceSessionStore } from './control-session-store.js';
import { ControlActionStore } from './control-action-store.js';
import {
  CommerceActionInputError,
  parseCommerceActionHash,
  parseCommerceActionId,
  requireIdempotencyKey,
} from './control-action-mutations.js';

/**
 * ControlGrantStore: the DB12 one-use authorization grant repository over the
 * accepted restricted tenant pool.
 *
 * Every method runs one statement inside one transaction through the reviewed
 * schema12 SECURITY DEFINER helpers and never migrates. The four production
 * wrappers receive the literal 'production' mode; no option, flag, callback or
 * environment value can select the migrator-only fixture core.
 *
 * Authority, unchanged from the frozen review resolution:
 *   * issue/replace authenticate the EXACT oacs_v1_ commerce-session hash and
 *     its bound action;
 *   * a provider claim needs BOTH a current matching oas_pr_ provider session
 *     and the buyer's exact one-use oag_v1_ grant token - neither alone;
 *   * revoke needs a current fresh buyer owner/operator non-recovery proof.
 *
 * Token handling is hash-only. `digestCommerceGrantToken` is the ONLY place a
 * raw oag_v1_ secret is touched, it is a pure one-way domain-separated digest,
 * and no method, receipt, projection, status, replay or error ever returns,
 * stores or logs raw secret material or a stored token hash.
 */

export const CONTROL_GRANT_STORE_ERROR_MESSAGES = {
  CONTROL_GRANT_STORE_INPUT_INVALID: 'ControlGrantStore input is invalid.',
  CONTROL_GRANT_STORE_SESSION_INVALID: 'ControlGrantStore session is not valid.',
  CONTROL_GRANT_STORE_FORBIDDEN: 'ControlGrantStore caller is not permitted.',
  CONTROL_GRANT_STORE_NOT_FOUND: 'ControlGrantStore target was not found.',
  CONTROL_GRANT_STORE_CONFLICT: 'ControlGrantStore operation conflicts with existing state.',
  CONTROL_GRANT_STORE_GRANT_CONFLICT:
    'ControlGrantStore grant is not in a state that permits this operation.',
  CONTROL_GRANT_STORE_GRANT_EXPIRED: 'ControlGrantStore grant authority has expired.',
  CONTROL_GRANT_STORE_POTENTIAL_EXPOSURE:
    'ControlGrantStore target has potential exposure and cannot be replaced.',
  CONTROL_GRANT_STORE_REQUIREMENT_UNAVAILABLE:
    'ControlGrantStore requirement is unavailable in production.',
  CONTROL_GRANT_STORE_IDEMPOTENCY_CONFLICT:
    'ControlGrantStore mutation conflicts with an existing idempotency record.',
  CONTROL_GRANT_STORE_UNAVAILABLE: 'ControlGrantStore is not available.',
  CONTROL_GRANT_STORE_OUTCOME_UNKNOWN:
    'ControlGrantStore mutation outcome could not be confirmed; it may have committed.',
} as const;

export type ControlGrantStoreErrorCode = keyof typeof CONTROL_GRANT_STORE_ERROR_MESSAGES;

/** Fixed, non-echoing repository error. Never carries driver or input detail. */
export class ControlGrantStoreError extends Error {
  readonly code: ControlGrantStoreErrorCode;

  constructor(code: ControlGrantStoreErrorCode) {
    super(CONTROL_GRANT_STORE_ERROR_MESSAGES[code]);
    this.name = 'ControlGrantStoreError';
    this.code = code;
  }
}

export const CONTROL_GRANT_OPERATIONS = [
  'control.grant.issue',
  'control.grant.replace',
  'control.grant.revoke',
  'control.grant.claim',
] as const;

export type CommerceGrantOperation = (typeof CONTROL_GRANT_OPERATIONS)[number];

export const CONTROL_GRANT_RESOURCE_TYPE = 'authorization_grant' as const;
export type CommerceGrantResourceType = typeof CONTROL_GRANT_RESOURCE_TYPE;

export const CONTROL_GRANT_NETWORK = 'eip155:5042002' as const;

export const CONTROL_GRANT_EVENT_BY_OPERATION = Object.freeze({
  'control.grant.issue': 'control.grant.issued',
  'control.grant.replace': 'control.grant.replaced',
  'control.grant.revoke': 'control.grant.revoked',
  'control.grant.claim': 'control.grant.claimed',
}) satisfies Readonly<Record<CommerceGrantOperation, string>>;

export const CONTROL_GRANT_KEY_DOMAIN_BY_OPERATION = Object.freeze({
  'control.grant.issue': 'openarc.control.grant.issue.idempotency.v1',
  'control.grant.replace': 'openarc.control.grant.replace.idempotency.v1',
  'control.grant.revoke': 'openarc.control.grant.revoke.idempotency.v1',
  'control.grant.claim': 'openarc.control.grant.claim.idempotency.v1',
}) satisfies Readonly<Record<CommerceGrantOperation, string>>;

export const CONTROL_GRANT_SESSION_DOMAIN_BY_OPERATION = Object.freeze({
  'control.grant.issue': 'openarc.control.grant.issue.session.v1',
  'control.grant.replace': 'openarc.control.grant.replace.session.v1',
  'control.grant.revoke': 'openarc.control.grant.revoke.session.v1',
  'control.grant.claim': 'openarc.control.grant.claim.session.v1',
}) satisfies Readonly<Record<CommerceGrantOperation, string>>;

export const CONTROL_GRANT_DIGEST_DOMAIN_BY_OPERATION = Object.freeze({
  'control.grant.issue': 'control.grant.issue.v1',
  'control.grant.replace': 'control.grant.replace.v1',
  'control.grant.revoke': 'control.grant.revoke.v1',
  'control.grant.claim': 'control.grant.claim.v1',
}) satisfies Readonly<Record<CommerceGrantOperation, string>>;

/**
 * The single domain-separation label for a raw oag_v1_ grant secret. The
 * digest is one-way: neither this module nor the database can reconstruct the
 * secret from it, and the raw value is never retained anywhere.
 */
export const CONTROL_GRANT_TOKEN_DOMAIN = 'openarc.control.grant.token.v1' as const;

/** The accepted stored grant-token hash version. Exactly one exists. */
export const CONTROL_GRANT_TOKEN_HASH_VERSION = 1 as const;

const HEX64 = /^[0-9a-f]{64}$(?![\s\S])/;
const ORG_ID = /^openarc:org:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const GRANT_ID = /^openarc:grant:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const GENERATION = /^[1-9][0-9]{0,9}$(?![\s\S])/;
// Absolute-end canonical bounded decimals. A plain `$` would accept a trailing
// LF in JavaScript, relabeling a malformed operand as valid.
const UINT256 = /^(0|[1-9][0-9]{0,77})$(?![\s\S])/;
const DEBIT = /^[1-9][0-9]{0,127}$(?![\s\S])/;
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$(?![\s\S])/;

const GRANT_IDENTITY = {
  networkId: 'eip155:5042002',
  asset: 'USDC',
  representation: 'erc20',
  decimals: 6,
} as const;

const GRANT_MAX_GENERATION = 2147483647n;

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function fail(code: ControlGrantStoreErrorCode): never {
  throw new ControlGrantStoreError(code);
}

function failOutput(): never {
  fail('CONTROL_GRANT_STORE_UNAVAILABLE');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * One-way domain-separated digest of a RAW `oag_v1_` grant token. The caller
 * generates the 32-byte CSPRNG secret, delivers it to the buyer only AFTER the
 * issuing transaction commits, and hands this store nothing but the digest.
 * The grammar is the accepted shared primitive, unchanged.
 */
export function digestCommerceGrantToken(rawGrantToken: unknown): string {
  const parsed = CommerceGrantTokenSchema.safeParse(rawGrantToken);
  if (!parsed.success) fail('CONTROL_GRANT_STORE_INPUT_INVALID');
  return sha256Hex(`${CONTROL_GRANT_TOKEN_DOMAIN}:${parsed.data}`);
}

export function digestCommerceGrantIdempotencyKey(
  operation: CommerceGrantOperation,
  rawKey: string,
): string {
  let key: string;
  try {
    key = requireIdempotencyKey(rawKey);
  } catch {
    fail('CONTROL_GRANT_STORE_INPUT_INVALID');
  }
  return sha256Hex(`${CONTROL_GRANT_KEY_DOMAIN_BY_OPERATION[operation]}:${key}`);
}

/** Domain-separated digest of the exact presented session/token hash. */
export function digestCommerceGrantSessionContext(
  operation: CommerceGrantOperation,
  presentedHash: string,
): string {
  if (typeof presentedHash !== 'string' || !HEX64.test(presentedHash)) {
    fail('CONTROL_GRANT_STORE_INPUT_INVALID');
  }
  return sha256Hex(
    `${CONTROL_GRANT_SESSION_DOMAIN_BY_OPERATION[operation]}:${presentedHash}`,
  );
}

function digestGrantRequest(
  operation: CommerceGrantOperation,
  fields: readonly unknown[],
): string {
  return sha256Hex(
    JSON.stringify([
      CONTROL_GRANT_DIGEST_DOMAIN_BY_OPERATION[operation],
      CONTROL_GRANT_NETWORK,
      ...fields,
    ]),
  );
}

export interface CommerceGrantCommerceDigestContext {
  readonly organizationId: string;
  readonly parentHumanAccountId: string;
  readonly commerceSessionId: string;
  readonly agentSessionId: string;
  readonly credentialId: string;
  readonly policyId: string;
  readonly sessionContextDigest: string;
  readonly mutationId: string;
}

/**
 * Issue replay digest. It binds the DB-resolved immutable commerce chain and
 * the exact target action, so a retry with the same logical body matches and a
 * changed body conflicts. It deliberately excludes the grant token hash: an
 * operation-specific token regeneration must NEVER enter the logical request
 * digest, or a lost reply would look like a different request.
 */
export function digestCommerceGrantIssueRequest(
  context: CommerceGrantCommerceDigestContext,
  actionId: string,
): string {
  return digestGrantRequest('control.grant.issue', [
    context.organizationId,
    context.parentHumanAccountId,
    context.commerceSessionId,
    context.agentSessionId,
    context.credentialId,
    context.policyId,
    requireAction(actionId),
    context.sessionContextDigest,
    requireMutationInput(context.mutationId),
  ]);
}

/** Replacement replay digest. Also excludes the regenerated token hash. */
export function digestCommerceGrantReplaceRequest(
  context: CommerceGrantCommerceDigestContext,
  grantId: string,
): string {
  return digestGrantRequest('control.grant.replace', [
    context.organizationId,
    context.parentHumanAccountId,
    context.commerceSessionId,
    context.agentSessionId,
    context.credentialId,
    context.policyId,
    requireGrant(grantId),
    context.sessionContextDigest,
    requireMutationInput(context.mutationId),
  ]);
}

/**
 * Claim replay digest. It binds the exact expected action, the provider's own
 * attempt id and the ORIGINAL provider-session context digest, so a replay
 * from a new provider session is a conflict rather than a second claim. It
 * carries no grant token hash and no caller price, origin or payload.
 */
export function digestCommerceGrantClaimRequest(
  sessionContextDigest: string,
  expectedActionId: string,
  attemptId: string,
  mutationId: string,
): string {
  return digestGrantRequest('control.grant.claim', [
    requireHash(sessionContextDigest),
    requireAction(expectedActionId),
    requireAttempt(attemptId),
    requireMutationInput(mutationId),
  ]);
}

export function digestCommerceGrantRevokeRequest(
  organizationId: string,
  actorAccountId: string,
  sessionContextDigest: string,
  grantId: string,
  mutationId: string,
): string {
  return digestGrantRequest('control.grant.revoke', [
    requireOrganization(organizationId),
    actorAccountId,
    requireHash(sessionContextDigest),
    requireGrant(grantId),
    requireMutationInput(mutationId),
  ]);
}

export interface CommerceGrantMutationMetadata {
  readonly idempotencyKey: string;
  readonly mutationId: string;
}

export interface IssueCommerceGrantInput {
  readonly actionId: string;
  readonly grantTokenHash: string;
}

export interface ReplaceCommerceGrantInput {
  readonly grantId: string;
  readonly grantTokenHash: string;
}

export interface ClaimCommerceGrantInput {
  readonly grantTokenHash: string;
  readonly expectedActionId: string;
  readonly attemptId: string;
}

export interface CommerceGrantTransactionReceipt {
  readonly mutationId: string;
  readonly operation: CommerceGrantOperation;
  readonly resourceType: CommerceGrantResourceType;
  readonly resourceId: string;
  readonly committedAt: string;
}

export interface CommerceGrantMutationDbResult {
  readonly replayed: boolean;
  readonly metadata: CommerceGrantMetadata;
  readonly receipt: CommerceGrantTransactionReceipt;
}

/**
 * Revocation result. `released` is true ONLY when the grant was never claimed
 * and its held reservation was actually released; a claimed, unknown or
 * committed reservation retains its exposure and the action stays
 * `grant_issued`, so a revoked display status never erases a possible payment.
 */
export interface CommerceGrantRevokeDbResult extends CommerceGrantMutationDbResult {
  readonly released: boolean;
  readonly actionStatus: string;
  readonly reservationStatus: string;
}

/**
 * Lost-response recovery answer for a grant mutation. Closed two-state shape:
 * a committed receipt or `not_found`, never a third state and never a partial
 * receipt. `not_found` carries no field besides `status`, so a miss discloses
 * nothing about another organization, buyer or audience.
 */
export type CommerceGrantMutationStatus =
  | { readonly status: 'committed'; readonly receipt: CommerceGrantTransactionReceipt }
  | { readonly status: 'not_found' };

/**
 * The audience a mutation-status projection speaks for. It is an explicit
 * non-transposable label rather than a boolean precisely so the human and the
 * agent projections can never be swapped by an argument-order mistake: a
 * transposed boolean is still a valid call, a transposed label is not a value
 * of this type at all.
 */
export type CommerceGrantStatusAudience = 'human' | 'agent';

/**
 * The exact schema3 receipt columns the two status helpers project. Every
 * field is re-validated before it reaches a receipt; the declared driver types
 * are a convenience, never the trust boundary.
 */
interface GrantReceiptRow extends Record<string, unknown> {
  readonly out_mutation_id: string;
  readonly out_operation: string;
  readonly out_resource_type: string;
  readonly out_resource_id: string;
  readonly out_committed_at: string | Date;
}

/** Provider claim result. It carries no buyer organization, policy or account. */
export interface CommerceGrantClaimDbResult {
  readonly replayed: boolean;
  readonly view: CommerceGrantProviderView;
  readonly attemptId: string;
  readonly claimedAt: string;
  readonly claimDigest: string;
  readonly receipt: CommerceGrantTransactionReceipt;
}

function requireHash(value: unknown): string {
  try {
    return parseCommerceActionHash(value);
  } catch {
    fail('CONTROL_GRANT_STORE_INPUT_INVALID');
  }
}

function requireOrganization(value: unknown): string {
  if (typeof value !== 'string' || !ORG_ID.test(value)) fail('CONTROL_GRANT_STORE_INPUT_INVALID');
  return value;
}

function requireAction(value: unknown): string {
  try {
    return parseCommerceActionId(value);
  } catch {
    fail('CONTROL_GRANT_STORE_INPUT_INVALID');
  }
}

function requireGrant(value: unknown): string {
  if (typeof value !== 'string' || !GRANT_ID.test(value)) fail('CONTROL_GRANT_STORE_INPUT_INVALID');
  return value;
}

function requireAttempt(value: unknown): string {
  if (typeof value !== 'string' || !UUID_V4.test(value)) fail('CONTROL_GRANT_STORE_INPUT_INVALID');
  return value;
}

function requireMutationInput(value: unknown): string {
  try {
    return parseMutationId(value);
  } catch {
    fail('CONTROL_GRANT_STORE_INPUT_INVALID');
  }
}

function requireMetadata(value: unknown): CommerceGrantMutationMetadata {
  if (!isRecord(value)) fail('CONTROL_GRANT_STORE_INPUT_INVALID');
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    fail('CONTROL_GRANT_STORE_INPUT_INVALID');
  }
  const keys = Object.keys(value);
  if (keys.length !== 2 || !keys.includes('idempotencyKey') || !keys.includes('mutationId')) {
    fail('CONTROL_GRANT_STORE_INPUT_INVALID');
  }
  const mutationId = requireMutationInput(value['mutationId']);
  try {
    requireIdempotencyKey(value['idempotencyKey']);
  } catch {
    fail('CONTROL_GRANT_STORE_INPUT_INVALID');
  }
  return { idempotencyKey: value['idempotencyKey'] as string, mutationId };
}

function requireInputShape(value: unknown, allowed: readonly string[]): Record<string, unknown> {
  if (!isRecord(value)) fail('CONTROL_GRANT_STORE_INPUT_INVALID');
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    fail('CONTROL_GRANT_STORE_INPUT_INVALID');
  }
  const keys = Object.keys(value);
  if (keys.length !== allowed.length) fail('CONTROL_GRANT_STORE_INPUT_INVALID');
  for (const key of keys) {
    if (!allowed.includes(key)) fail('CONTROL_GRANT_STORE_INPUT_INVALID');
    if (value[key] === undefined) fail('CONTROL_GRANT_STORE_INPUT_INVALID');
  }
  return value;
}

function requireExactlyOne<T>(rows: readonly T[]): T {
  if (rows.length !== 1 || rows[0] === undefined) failOutput();
  return rows[0];
}

function requireAtMostOne<T>(rows: readonly T[]): T | undefined {
  if (rows.length > 1) failOutput();
  return rows[0];
}

function normalizeError(error: unknown): ControlGrantStoreError {
  if (error instanceof ControlGrantStoreError) return error;
  if (error instanceof CommerceActionInputError) {
    return new ControlGrantStoreError('CONTROL_GRANT_STORE_INPUT_INVALID');
  }
  if (isRecord(error) && typeof error.code === 'string') {
    switch (error.code) {
      case '28000':
        return new ControlGrantStoreError('CONTROL_GRANT_STORE_SESSION_INVALID');
      case '42501':
        return new ControlGrantStoreError('CONTROL_GRANT_STORE_FORBIDDEN');
      case '23503':
        return new ControlGrantStoreError('CONTROL_GRANT_STORE_NOT_FOUND');
      case '23505':
        return new ControlGrantStoreError('CONTROL_GRANT_STORE_CONFLICT');
      case 'P0D01':
        return new ControlGrantStoreError('CONTROL_GRANT_STORE_IDEMPOTENCY_CONFLICT');
      case 'P0D10':
        return new ControlGrantStoreError('CONTROL_GRANT_STORE_REQUIREMENT_UNAVAILABLE');
      case 'P0D13':
        return new ControlGrantStoreError('CONTROL_GRANT_STORE_POTENTIAL_EXPOSURE');
      case 'P0D14':
        return new ControlGrantStoreError('CONTROL_GRANT_STORE_GRANT_CONFLICT');
      case 'P0D15':
        return new ControlGrantStoreError('CONTROL_GRANT_STORE_GRANT_EXPIRED');
      case '22023':
      case '22P02':
      case '22001':
      case '22003':
      case '23514':
        return new ControlGrantStoreError('CONTROL_GRANT_STORE_INPUT_INVALID');
      default:
        return new ControlGrantStoreError('CONTROL_GRANT_STORE_UNAVAILABLE');
    }
  }
  return new ControlGrantStoreError('CONTROL_GRANT_STORE_UNAVAILABLE');
}

const PG_TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?([+-])(\d{2})(?::?(\d{2}))?$/;

function daysInMonth(year: number, month: number): number {
  return new Date(Date.UTC(year, month, 0)).getUTCDate();
}

function iso(value: unknown): string {
  if (value instanceof Date) {
    if (!Number.isFinite(value.getTime())) failOutput();
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

const GRANT_COLUMNS = `out_organization_id, out_grant_id, out_action_id, out_reservation_id,
                out_subject_agent_id, out_commerce_session_id, out_provider_id, out_listing_id,
                out_listing_version, out_generation::text AS out_generation, out_status,
                out_issued_at::text AS out_issued_at,
                out_updated_at::text AS out_updated_at,
                out_expires_at::text AS out_expires_at,
                out_claimed_at::text AS out_claimed_at,
                out_revoked_at::text AS out_revoked_at`;

const PROVIDER_VIEW_COLUMNS = `out_grant_id, out_action_id, out_provider_id, out_listing_id,
                out_listing_version, out_requirement_id, out_requirement_digest,
                out_amount_atomic, out_fee_atomic, out_debit_atomic,
                out_expires_at::text AS out_expires_at, out_status`;

export class ControlGrantStore {
  readonly #pool: TenantPool;
  readonly #base: TenantStore;
  #initialized = false;

  constructor(pool: TenantPool) {
    if (pool === null || typeof pool !== 'object' || typeof pool.connect !== 'function') {
      fail('CONTROL_GRANT_STORE_INPUT_INVALID');
    }
    this.#pool = pool;
    this.#base = new TenantStore(pool);
  }

  async initialize(): Promise<void> {
    if (this.#initialized) return;
    await this.#baseChecks(() => this.#base.initialize());
    await this.#baseChecks(() => new CommerceSessionStore(this.#pool).initialize());
    await this.#baseChecks(() => new ControlActionStore(this.#pool).initialize());
    await this.#withTransaction(async (client) => {
      await this.#assertReady(client);
    });
    this.#initialized = true;
  }

  async readiness(): Promise<void> {
    await this.#baseChecks(() => this.#base.readiness());
    await this.#baseChecks(() => new CommerceSessionStore(this.#pool).readiness());
    await this.#baseChecks(() => new ControlActionStore(this.#pool).readiness());
    await this.#withTransaction(async (client) => {
      await this.#assertReady(client);
    });
  }

  async #baseChecks(run: () => Promise<void>): Promise<void> {
    try {
      await run();
    } catch {
      fail('CONTROL_GRANT_STORE_UNAVAILABLE');
    }
  }

  /**
   * Issue the single grant of a reserved action. The caller presents ONLY the
   * exact consumed oacs_v1_ commerce token hash, the bound action id and the
   * one-way hash of a raw oag_v1_ secret it generated itself. The raw secret
   * never reaches this store and is delivered to the buyer only after commit.
   */
  async issueForReservedAction(
    commerceTokenHash: unknown,
    input: unknown,
    metadata: unknown,
  ): Promise<CommerceGrantMutationDbResult> {
    const tokenHash = requireHash(commerceTokenHash);
    const shape = requireInputShape(input, ['actionId', 'grantTokenHash']);
    const actionId = requireAction(shape['actionId']);
    const grantTokenHash = requireHash(shape['grantTokenHash']);
    const meta = requireMetadata(metadata);
    const operation: CommerceGrantOperation = 'control.grant.issue';
    const sessionContextDigest = digestCommerceGrantSessionContext(operation, tokenHash);
    const keyHash = digestCommerceGrantIdempotencyKey(operation, meta.idempotencyKey);
    return this.#withTransaction(async (client) => {
      const context = await this.#resolveCommerceContext(client, tokenHash);
      const requestDigest = digestCommerceGrantIssueRequest(
        { ...context, sessionContextDigest, mutationId: meta.mutationId },
        actionId,
      );
      const result = await client.query<Record<string, unknown>>(
        `SELECT out_replayed, ${GRANT_COLUMNS}, out_committed_at::text AS out_committed_at
           FROM openarc_durable.issue_authorization_grant(
             $1, $2, $3, $4::int, $5::uuid, $6, $7, $8)`,
        [
          tokenHash, actionId, grantTokenHash, CONTROL_GRANT_TOKEN_HASH_VERSION,
          meta.mutationId, keyHash, requestDigest, sessionContextDigest,
        ],
      );
      const row = requireExactlyOne(result.rows);
      const metadataOut = this.#projectMetadata(row);
      if (metadataOut.actionId !== actionId) failOutput();
      return {
        replayed: this.#requireBoolean(row['out_replayed']),
        metadata: metadataOut,
        receipt: this.#receiptFrom(operation, meta.mutationId, metadataOut.grantId, iso(row['out_committed_at'])),
      };
    });
  }

  /**
   * Replace the still-unclaimed generation of an existing grant. It retires
   * the old hash and mints the next generation on the SAME grant and the SAME
   * reservation, and it can never extend the original expiry.
   */
  async replaceUnclaimedGrant(
    commerceTokenHash: unknown,
    input: unknown,
    metadata: unknown,
  ): Promise<CommerceGrantMutationDbResult> {
    const tokenHash = requireHash(commerceTokenHash);
    const shape = requireInputShape(input, ['grantId', 'grantTokenHash']);
    const grantId = requireGrant(shape['grantId']);
    const grantTokenHash = requireHash(shape['grantTokenHash']);
    const meta = requireMetadata(metadata);
    const operation: CommerceGrantOperation = 'control.grant.replace';
    const sessionContextDigest = digestCommerceGrantSessionContext(operation, tokenHash);
    const keyHash = digestCommerceGrantIdempotencyKey(operation, meta.idempotencyKey);
    return this.#withTransaction(async (client) => {
      const context = await this.#resolveCommerceContext(client, tokenHash);
      const requestDigest = digestCommerceGrantReplaceRequest(
        { ...context, sessionContextDigest, mutationId: meta.mutationId },
        grantId,
      );
      const result = await client.query<Record<string, unknown>>(
        `SELECT out_replayed, ${GRANT_COLUMNS}, out_committed_at::text AS out_committed_at
           FROM openarc_durable.replace_authorization_grant(
             $1, $2, $3, $4::int, $5::uuid, $6, $7, $8)`,
        [
          tokenHash, grantId, grantTokenHash, CONTROL_GRANT_TOKEN_HASH_VERSION,
          meta.mutationId, keyHash, requestDigest, sessionContextDigest,
        ],
      );
      const row = requireExactlyOne(result.rows);
      const metadataOut = this.#projectMetadata(row);
      if (metadataOut.grantId !== grantId) failOutput();
      return {
        replayed: this.#requireBoolean(row['out_replayed']),
        metadata: metadataOut,
        receipt: this.#receiptFrom(operation, meta.mutationId, grantId, iso(row['out_committed_at'])),
      };
    });
  }

  /**
   * Provider introspection under BOTH factors. It is strictly read-only: it
   * consumes nothing, reserves nothing and mutates no row, so repeated calls
   * leave the grant, its generation and its reservation identical.
   */
  async introspectGrant(
    providerSessionHash: unknown,
    grantTokenHash: unknown,
  ): Promise<CommerceGrantProviderView> {
    const session = requireHash(providerSessionHash);
    const token = requireHash(grantTokenHash);
    return this.#withTransaction(async (client) => {
      const result = await client.query<Record<string, unknown>>(
        `SELECT ${PROVIDER_VIEW_COLUMNS}, out_claimed_attempt_id
           FROM openarc_durable.introspect_authorization_grant($1, $2)`,
        [session, token],
      );
      const row = requireExactlyOne(result.rows);
      return this.#projectProviderView(row, row['out_claimed_attempt_id'] ?? null);
    });
  }

  /**
   * Provider claim. BOTH the current matching provider session and the exact
   * one-use grant token are required; neither alone permits a claim. Exactly
   * one concurrent claimant wins the single compare-and-set in the database.
   */
  async claimGrant(
    providerSessionHash: unknown,
    input: unknown,
    metadata: unknown,
  ): Promise<CommerceGrantClaimDbResult> {
    const session = requireHash(providerSessionHash);
    const shape = requireInputShape(input, ['grantTokenHash', 'expectedActionId', 'attemptId']);
    const token = requireHash(shape['grantTokenHash']);
    const expectedActionId = requireAction(shape['expectedActionId']);
    const attemptId = requireAttempt(shape['attemptId']);
    const meta = requireMetadata(metadata);
    const operation: CommerceGrantOperation = 'control.grant.claim';
    const sessionContextDigest = digestCommerceGrantSessionContext(operation, session);
    const keyHash = digestCommerceGrantIdempotencyKey(operation, meta.idempotencyKey);
    const requestDigest = digestCommerceGrantClaimRequest(
      sessionContextDigest, expectedActionId, attemptId, meta.mutationId,
    );
    return this.#withTransaction(async (client) => {
      const result = await client.query<Record<string, unknown>>(
        `SELECT out_replayed, ${PROVIDER_VIEW_COLUMNS}, out_attempt_id,
                out_claimed_at::text AS out_claimed_at, out_claim_digest,
                out_committed_at::text AS out_committed_at
           FROM openarc_durable.claim_authorization_grant(
             $1, $2, $3, $4::uuid, $5::uuid, $6, $7, $8)`,
        [session, token, expectedActionId, attemptId, meta.mutationId, keyHash, requestDigest, sessionContextDigest],
      );
      const row = requireExactlyOne(result.rows);
      const view = this.#projectProviderView(row, row['out_attempt_id'] ?? null);
      if (view.actionId !== expectedActionId) failOutput();
      const claimedAttempt = requireAttempt(row['out_attempt_id']);
      if (claimedAttempt !== attemptId) failOutput();
      const claimDigest = row['out_claim_digest'];
      if (typeof claimDigest !== 'string' || !SHA256_DIGEST.test(claimDigest)) failOutput();
      return {
        replayed: this.#requireBoolean(row['out_replayed']),
        view,
        attemptId: claimedAttempt,
        claimedAt: iso(row['out_claimed_at']),
        claimDigest,
        receipt: this.#receiptFrom(operation, meta.mutationId, view.grantId, iso(row['out_committed_at'])),
      };
    });
  }

  /**
   * Human revoke with safe never-claimed cleanup. A claimed grant keeps its
   * claim fact and its held exposure; only a never-claimed held reservation is
   * released and its action cancelled.
   */
  async revokeGrant(
    humanSessionHash: unknown,
    organizationId: unknown,
    grantId: unknown,
    metadata: unknown,
  ): Promise<CommerceGrantRevokeDbResult> {
    const hash = requireHash(humanSessionHash);
    const organization = requireOrganization(organizationId);
    const grant = requireGrant(grantId);
    const meta = requireMetadata(metadata);
    const operation: CommerceGrantOperation = 'control.grant.revoke';
    const sessionContextDigest = digestCommerceGrantSessionContext(operation, hash);
    const keyHash = digestCommerceGrantIdempotencyKey(operation, meta.idempotencyKey);
    return this.#withTransaction(async (client) => {
      const actor = await this.#lockHumanWriter(client, hash, organization);
      const requestDigest = digestCommerceGrantRevokeRequest(
        organization, actor, sessionContextDigest, grant, meta.mutationId,
      );
      const result = await client.query<Record<string, unknown>>(
        `SELECT out_replayed, ${GRANT_COLUMNS}, out_action_status, out_reservation_status,
                out_released, out_committed_at::text AS out_committed_at
           FROM openarc_durable.revoke_authorization_grant(
             $1, $2, $3, $4::uuid, $5, $6, $7)`,
        [hash, organization, grant, meta.mutationId, keyHash, requestDigest, sessionContextDigest],
      );
      const row = requireExactlyOne(result.rows);
      const metadataOut = this.#projectMetadata(row);
      if (metadataOut.grantId !== grant || metadataOut.organizationId !== organization) {
        failOutput();
      }
      const actionStatus = row['out_action_status'];
      const reservationStatus = row['out_reservation_status'];
      if (typeof actionStatus !== 'string' || typeof reservationStatus !== 'string') failOutput();
      return {
        replayed: this.#requireBoolean(row['out_replayed']),
        metadata: metadataOut,
        receipt: this.#receiptFrom(operation, meta.mutationId, grant, iso(row['out_committed_at'])),
        released: this.#requireBoolean(row['out_released']),
        actionStatus,
        reservationStatus,
      };
    });
  }

  /**
   * Buyer grant projection. A missing or foreign grant under a valid current
   * authority is a safe null, never an error that distinguishes the two.
   */
  async readGrant(
    humanSessionHash: unknown,
    organizationId: unknown,
    grantId: unknown,
  ): Promise<CommerceGrantMetadata | null> {
    const hash = requireHash(humanSessionHash);
    const organization = requireOrganization(organizationId);
    const grant = requireGrant(grantId);
    return this.#withTransaction(async (client) => {
      const result = await client.query<Record<string, unknown>>(
        `SELECT ${GRANT_COLUMNS}
           FROM openarc_durable.read_authorization_grant($1, $2, $3)`,
        [hash, organization, grant],
      );
      const row = requireAtMostOne(result.rows);
      if (row === undefined) return null;
      const metadata = this.#projectMetadata(row);
      if (metadata.grantId !== grant || metadata.organizationId !== organization) failOutput();
      return metadata;
    });
  }

  /**
   * Buyer lost-response recovery for a grant mutation the BROWSER performed.
   *
   * It answers only for `control.grant.revoke` and only when the receipt was
   * earned by this exact actor under this exact presented browser session, so
   * a co-owner's receipt, a second live session's receipt and an agent-issued
   * receipt are all the same safe `not_found`. It never reconstructs a grant
   * token: the receipt carries the grant id and the commit instant and nothing
   * else.
   */
  async getHumanMutationStatus(
    humanSessionHash: unknown,
    organizationId: unknown,
    mutationId: unknown,
  ): Promise<CommerceGrantMutationStatus> {
    const hash = requireHash(humanSessionHash);
    const organization = requireOrganization(organizationId);
    const mutation = requireMutationInput(mutationId);
    return this.#withTransaction(async (client) => {
      const result = await client.query<GrantReceiptRow>(
        `SELECT out_mutation_id, out_operation, out_resource_type, out_resource_id,
                out_committed_at::text AS out_committed_at
           FROM openarc_durable.read_human_grant_mutation_status($1, $2, $3::uuid)`,
        [hash, organization, mutation],
      );
      return this.#projectMutationStatus(mutation, requireAtMostOne(result.rows), 'human');
    });
  }

  /**
   * Agent lost-response recovery for a grant mutation the COMMERCE BEARER
   * performed. There is no organization argument: the buyer organization is
   * DB-derived from the presented session and re-asserted here, so a presenter
   * can never widen its own scope. It answers only for `control.grant.issue`
   * and `control.grant.replace`.
   */
  async getAgentMutationStatus(
    commerceTokenHash: unknown,
    mutationId: unknown,
  ): Promise<CommerceGrantMutationStatus> {
    const hash = requireHash(commerceTokenHash);
    const mutation = requireMutationInput(mutationId);
    return this.#withTransaction(async (client) => {
      const result = await client.query<GrantReceiptRow & { out_organization_id: string }>(
        `SELECT out_mutation_id, out_operation, out_resource_type, out_resource_id,
                out_committed_at::text AS out_committed_at, out_organization_id
           FROM openarc_durable.read_agent_grant_mutation_status($1, $2::uuid)`,
        [hash, mutation],
      );
      const row = requireAtMostOne(result.rows);
      if (row === undefined) return { status: 'not_found' } as const;
      // A committed agent row must carry the DB-derived buyer organization.
      if (typeof row.out_organization_id !== 'string' || !ORG_ID.test(row.out_organization_id)) {
        failOutput();
      }
      return this.#projectMutationStatus(mutation, row, 'agent');
    });
  }

  /**
   * Provider historical claim recovery keyed by the provider's OWN attempt id.
   * A NEW valid session for the SAME provider recovers the minimal claim fact
   * plus a `grantRevoked` flag, because retirement alone is not evidence of
   * nonpayment. A missing attempt and a foreign attempt are indistinguishable:
   * both return exactly `{ status: 'not_found' }`.
   */
  async readProviderAttemptStatus(
    currentProviderSessionHash: unknown,
    attemptId: unknown,
  ): Promise<CommerceGrantProviderAttemptStatus> {
    const session = requireHash(currentProviderSessionHash);
    const attempt = requireAttempt(attemptId);
    return this.#withTransaction(async (client) => {
      const result = await client.query<Record<string, unknown>>(
        `SELECT out_found, out_attempt_id, out_grant_id, out_action_id, out_provider_id,
                out_listing_id, out_listing_version,
                out_claimed_at::text AS out_claimed_at, out_grant_revoked
           FROM openarc_durable.read_provider_grant_attempt_status($1, $2::uuid)`,
        [session, attempt],
      );
      const row = requireExactlyOne(result.rows);
      if (row['out_found'] !== true) {
        if (row['out_found'] !== false) failOutput();
        const missing = CommerceGrantProviderAttemptStatusSchema.safeParse({ status: 'not_found' });
        if (!missing.success) failOutput();
        return missing.data;
      }
      const parsed = CommerceGrantProviderAttemptStatusSchema.safeParse({
        status: 'claimed',
        attemptId: row['out_attempt_id'],
        grantId: row['out_grant_id'],
        actionId: row['out_action_id'],
        providerId: row['out_provider_id'],
        listingId: row['out_listing_id'],
        listingVersion: row['out_listing_version'],
        claimedAt: iso(row['out_claimed_at']),
        grantRevoked: row['out_grant_revoked'],
      });
      if (!parsed.success) failOutput();
      if (parsed.data.status !== 'claimed' || parsed.data.attemptId !== attempt) failOutput();
      return parsed.data;
    });
  }

  async #resolveCommerceContext(
    client: TenantClient,
    tokenHash: string,
  ): Promise<{
    organizationId: string;
    parentHumanAccountId: string;
    commerceSessionId: string;
    agentSessionId: string;
    credentialId: string;
    policyId: string;
  }> {
    const result = await client.query<Record<string, unknown>>(
      `SELECT out_organization_id, out_parent_human_account_id, out_commerce_session_id,
              out_agent_session_id, out_credential_id, out_policy_id
         FROM openarc_durable.resolve_commerce_action_context($1)`,
      [tokenHash],
    );
    const row = requireExactlyOne(result.rows);
    const organizationId = row['out_organization_id'];
    const parentHumanAccountId = row['out_parent_human_account_id'];
    const commerceSessionId = row['out_commerce_session_id'];
    const agentSessionId = row['out_agent_session_id'];
    const credentialId = row['out_credential_id'];
    const policyId = row['out_policy_id'];
    if (
      typeof organizationId !== 'string' || !ORG_ID.test(organizationId) ||
      typeof parentHumanAccountId !== 'string' ||
      typeof commerceSessionId !== 'string' ||
      typeof agentSessionId !== 'string' ||
      typeof credentialId !== 'string' ||
      typeof policyId !== 'string'
    ) {
      fail('CONTROL_GRANT_STORE_FORBIDDEN');
    }
    return {
      organizationId, parentHumanAccountId, commerceSessionId,
      agentSessionId, credentialId, policyId,
    };
  }

  async #lockHumanWriter(
    client: TenantClient,
    hash: string,
    organization: string,
  ): Promise<string> {
    const result = await client.query<{ out_actor: string; out_role: string }>(
      `SELECT out_actor, out_role FROM openarc_durable.lock_action_human($1, $2, true)`,
      [hash, organization],
    );
    const row = result.rows[0];
    if (row === undefined || typeof row.out_actor !== 'string') {
      fail('CONTROL_GRANT_STORE_FORBIDDEN');
    }
    return row.out_actor;
  }

  #requireBoolean(value: unknown): boolean {
    if (value !== true && value !== false) failOutput();
    return value;
  }

  #receiptFrom(
    operation: CommerceGrantOperation,
    mutationId: string,
    grantId: string,
    committedAt: string,
  ): CommerceGrantTransactionReceipt {
    return {
      mutationId,
      operation,
      resourceType: CONTROL_GRANT_RESOURCE_TYPE,
      resourceId: grantId,
      committedAt,
    };
  }

  /**
   * Strict committed-or-not-found projection. No row is `not_found`; a row is
   * only ever a receipt after EVERY column has been re-validated, including
   * that the echoed mutation id is the one that was asked for and that the
   * operation belongs to this audience.
   */
  #projectMutationStatus(
    mutation: string,
    row: GrantReceiptRow | undefined,
    audience: CommerceGrantStatusAudience,
  ): CommerceGrantMutationStatus {
    if (row === undefined) return { status: 'not_found' } as const;
    if (row.out_mutation_id !== mutation) failOutput();
    const operation = this.#requireStatusOperation(row.out_operation, audience);
    if (row.out_resource_type !== CONTROL_GRANT_RESOURCE_TYPE) failOutput();
    const grantId = row.out_resource_id;
    if (typeof grantId !== 'string' || !GRANT_ID.test(grantId)) failOutput();
    const committedAt = iso(row.out_committed_at);
    return {
      status: 'committed' as const,
      receipt: this.#receiptFrom(operation, mutation, grantId, committedAt),
    };
  }

  /**
   * The agent status reader may only ever surface issue/replace; the human
   * status reader may only ever surface revoke. A provider claim receipt is
   * surfaced by NEITHER: it has its own attempt-keyed recovery read. The
   * audience is named explicitly so the two projections can never be
   * transposed.
   */
  #requireStatusOperation(
    value: unknown,
    audience: CommerceGrantStatusAudience,
  ): CommerceGrantOperation {
    if (audience === 'agent') {
      if (value !== 'control.grant.issue' && value !== 'control.grant.replace') failOutput();
      return value;
    }
    if (value !== 'control.grant.revoke') failOutput();
    return value;
  }

  #projectMetadata(row: Record<string, unknown>): CommerceGrantMetadata {
    const generation = row['out_generation'];
    if (
      typeof generation !== 'string' || !GENERATION.test(generation) ||
      BigInt(generation) > GRANT_MAX_GENERATION
    ) {
      failOutput();
    }
    const parsed = CommerceGrantMetadataSchema.safeParse({
      schemaVersion: COMMERCE_GRANT_METADATA_SCHEMA_VERSION,
      grantId: row['out_grant_id'],
      organizationId: row['out_organization_id'],
      subjectAgentId: row['out_subject_agent_id'],
      actionId: row['out_action_id'],
      reservationId: row['out_reservation_id'],
      commerceSessionId: row['out_commerce_session_id'],
      providerId: row['out_provider_id'],
      listingId: row['out_listing_id'],
      listingVersion: row['out_listing_version'],
      generation,
      status: row['out_status'] as CommerceGrantStatus,
      issuedAt: iso(row['out_issued_at']),
      updatedAt: iso(row['out_updated_at']),
      expiresAt: iso(row['out_expires_at']),
      claimedAt: isoOrNull(row['out_claimed_at']),
      revokedAt: isoOrNull(row['out_revoked_at']),
    });
    if (!parsed.success) failOutput();
    // The 300-second ceiling is enforced in SQL; re-assert it on the exact
    // projected instants so a malformed row can never widen a grant window.
    if (
      compareIsoTimestamps(parsed.data.expiresAt, parsed.data.issuedAt) <= 0 ||
      compareIsoTimestamps(parsed.data.updatedAt, parsed.data.issuedAt) < 0
    ) {
      failOutput();
    }
    return parsed.data;
  }

  #projectProviderView(
    row: Record<string, unknown>,
    claimedAttemptId: unknown,
  ): CommerceGrantProviderView {
    const amountAtomic = row['out_amount_atomic'];
    const feeAtomic = row['out_fee_atomic'];
    const debitAtomic = row['out_debit_atomic'];
    if (
      typeof amountAtomic !== 'string' || !UINT256.test(amountAtomic) || amountAtomic === '0' ||
      typeof feeAtomic !== 'string' || !UINT256.test(feeAtomic) ||
      typeof debitAtomic !== 'string' || !DEBIT.test(debitAtomic)
    ) {
      failOutput();
    }
    // Exact integer arithmetic only; money never passes through a JS float.
    if (BigInt(amountAtomic) + BigInt(feeAtomic) !== BigInt(debitAtomic)) failOutput();
    const parsed = CommerceGrantProviderViewSchema.safeParse({
      schemaVersion: COMMERCE_GRANT_PROVIDER_VIEW_SCHEMA_VERSION,
      grantId: row['out_grant_id'],
      actionId: row['out_action_id'],
      providerId: row['out_provider_id'],
      listingId: row['out_listing_id'],
      listingVersion: row['out_listing_version'],
      requirementId: row['out_requirement_id'],
      requirementDigest: row['out_requirement_digest'],
      networkId: GRANT_IDENTITY.networkId,
      asset: GRANT_IDENTITY.asset,
      representation: GRANT_IDENTITY.representation,
      decimals: GRANT_IDENTITY.decimals,
      amountAtomic,
      feeAtomic,
      debitAtomic,
      expiresAt: iso(row['out_expires_at']),
      status: row['out_status'] as CommerceGrantStatus,
      claimedAttemptId: claimedAttemptId ?? null,
    });
    if (!parsed.success) failOutput();
    return parsed.data;
  }

  async #withTransaction<T>(work: (client: TenantClient) => Promise<T>): Promise<T> {
    let client: TenantClient;
    try {
      client = await this.#pool.connect();
    } catch {
      fail('CONTROL_GRANT_STORE_UNAVAILABLE');
    }
    try {
      await client.query('BEGIN');
    } catch {
      client.release(true);
      fail('CONTROL_GRANT_STORE_UNAVAILABLE');
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
      client.release(!rolledBack);
      throw normalizeError(error);
    }
    try {
      await client.query('COMMIT');
    } catch {
      // A lost COMMIT reply is a fixed OUTCOME_UNKNOWN with a destroyed
      // connection and no retry; the provider must inspect status instead of
      // ever triggering a second external payment.
      client.release(true);
      fail('CONTROL_GRANT_STORE_OUTCOME_UNKNOWN');
    }
    client.release(false);
    return result;
  }

  async #assertReady(client: TenantClient): Promise<void> {
    const EXPECTED_TABLES = [
      'authorization_grants',
      'authorization_grant_tokens',
      'authorization_grant_claims',
    ];
    const tables = await client.query<{
      n: number; all_enabled: boolean; all_forced: boolean; owned: number;
    }>(
      `SELECT count(*)::int AS n,
              bool_and(c.relrowsecurity) AS all_enabled,
              bool_and(c.relforcerowsecurity) AS all_forced,
              count(*) FILTER (WHERE r.rolname = 'openarc_migrator')::int AS owned
         FROM pg_class c
         JOIN pg_namespace ns ON ns.oid = c.relnamespace
         JOIN pg_roles r ON r.oid = c.relowner
        WHERE ns.nspname = 'openarc_durable'
          AND c.relkind = 'r'
          AND c.relname = ANY ($1::text[])`,
      [EXPECTED_TABLES],
    );
    const state = tables.rows[0];
    if (
      state === undefined ||
      state.n !== EXPECTED_TABLES.length ||
      state.all_enabled !== true ||
      state.all_forced !== true ||
      state.owned !== EXPECTED_TABLES.length
    ) {
      fail('CONTROL_GRANT_STORE_UNAVAILABLE');
    }
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
          AND c.relname = ANY ($1::text[])
          AND EXISTS (
            SELECT 1 FROM reachable x
             WHERE has_table_privilege(x.oid, c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))`,
      [EXPECTED_TABLES],
    );
    if ((access.rows[0]?.n ?? -1) !== 0) fail('CONTROL_GRANT_STORE_UNAVAILABLE');
    await this.#assertHelpers(client);
  }

  async #assertHelpers(client: TenantClient): Promise<void> {
    const production: readonly { name: string; args: string }[] = [
      { name: 'issue_authorization_grant', args: 'commerce_token_hash text, action_id_input text, token_hash_input text, token_hash_version integer, mutation_id uuid, key_hash text, request_digest text, session_context_digest text' },
      { name: 'replace_authorization_grant', args: 'commerce_token_hash text, grant_id_input text, token_hash_input text, token_hash_version integer, mutation_id uuid, key_hash text, request_digest text, session_context_digest text' },
      { name: 'introspect_authorization_grant', args: 'provider_session_hash text, grant_token_hash text' },
      { name: 'claim_authorization_grant', args: 'provider_session_hash text, grant_token_hash text, expected_action_id text, attempt_id_input uuid, mutation_id uuid, key_hash text, request_digest text, session_context_digest text' },
      { name: 'revoke_authorization_grant', args: 'human_session_hash text, organization_id text, grant_id_input text, mutation_id uuid, key_hash text, request_digest text, session_context_digest text' },
      { name: 'read_authorization_grant', args: 'human_session_hash text, organization_id text, grant_id_input text' },
      { name: 'read_provider_grant_attempt_status', args: 'provider_session_hash text, attempt_id_input uuid' },
      { name: 'read_human_grant_mutation_status', args: 'human_session_hash text, organization_id text, mutation_id uuid' },
      { name: 'read_agent_grant_mutation_status', args: 'commerce_token_hash text, mutation_id uuid' },
    ];
    // The closed cores, the two lock chains, the provider identity resolver
    // and the claim digest helper must stay unreachable from the runtime.
    const privateHelpers: readonly { name: string; args: string }[] = [
      { name: 'issue_authorization_grant_core', args: 'mode text, commerce_token_hash text, action_id_input text, token_hash_input text, token_hash_version integer, mutation_id uuid, key_hash text, request_digest text, session_context_digest text' },
      { name: 'replace_authorization_grant_core', args: 'mode text, commerce_token_hash text, grant_id_input text, token_hash_input text, token_hash_version integer, mutation_id uuid, key_hash text, request_digest text, session_context_digest text' },
      { name: 'introspect_authorization_grant_core', args: 'mode text, provider_session_hash text, grant_token_hash text' },
      { name: 'claim_authorization_grant_core', args: 'mode text, provider_session_hash text, grant_token_hash text, expected_action_id text, attempt_id_input uuid, mutation_id uuid, key_hash text, request_digest text, session_context_digest text' },
      { name: 'lock_grant_commerce_chain', args: 'commerce_token_hash text, action_id_input text' },
      { name: 'lock_grant_provider_chain', args: 'provider_session_hash text, grant_id_input text' },
      { name: 'lock_grant_provider_identity', args: 'provider_session_hash text' },
    ];
    const rows = await client.query<{
      proname: string;
      args: string;
      owner: string;
      secdef: boolean;
      config: string[];
      app_exec: boolean;
      public_grants: number;
    }>(
      `SELECT p.proname, pg_get_function_identity_arguments(p.oid) AS args,
              r.rolname AS owner, p.prosecdef AS secdef,
              coalesce(p.proconfig, ARRAY[]::text[]) AS config,
              has_function_privilege('openarc_tenant_app', p.oid, 'EXECUTE') AS app_exec,
              (SELECT count(*)::int FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE') AS public_grants
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         JOIN pg_roles r ON r.oid = p.proowner
        WHERE n.nspname = 'openarc_durable'
          AND p.prokind = 'f'
          AND p.proname = ANY ($1::text[])`,
      [[...production, ...privateHelpers].map((entry) => entry.name)],
    );
    const byName = new Map(rows.rows.map((row) => [`${row.proname}(${row.args})`, row]));
    for (const expected of production) {
      const row = byName.get(`${expected.name}(${expected.args})`);
      if (row === undefined) fail('CONTROL_GRANT_STORE_UNAVAILABLE');
      if (
        row.owner !== 'openarc_migrator' ||
        row.secdef !== true ||
        !row.config.includes('search_path=pg_catalog') ||
        row.public_grants !== 0 ||
        row.app_exec !== true
      ) {
        fail('CONTROL_GRANT_STORE_UNAVAILABLE');
      }
    }
    for (const expected of privateHelpers) {
      const row = byName.get(`${expected.name}(${expected.args})`);
      if (row === undefined) fail('CONTROL_GRANT_STORE_UNAVAILABLE');
      if (
        row.owner !== 'openarc_migrator' ||
        row.secdef !== true ||
        !row.config.includes('search_path=pg_catalog') ||
        row.public_grants !== 0 ||
        row.app_exec !== false
      ) {
        fail('CONTROL_GRANT_STORE_UNAVAILABLE');
      }
    }
    const applied = await client.query<{ id: string; checksum: string }>(
      `SELECT id, checksum FROM openarc_meta.schema_migrations ORDER BY id`,
    );
    let migrations: readonly { readonly id: string; readonly sql: string }[];
    try {
      migrations = loadMigrations();
    } catch {
      fail('CONTROL_GRANT_STORE_UNAVAILABLE');
    }
    if (applied.rows.length !== migrations.length) fail('CONTROL_GRANT_STORE_UNAVAILABLE');
    for (let index = 0; index < applied.rows.length; index += 1) {
      const record = applied.rows[index];
      const manifest = migrations[index];
      if (record === undefined || manifest === undefined || record.id !== manifest.id) {
        fail('CONTROL_GRANT_STORE_UNAVAILABLE');
      }
      const checksum = createHash('sha256').update(manifest.sql, 'utf8').digest('hex');
      if (record.checksum !== checksum) fail('CONTROL_GRANT_STORE_UNAVAILABLE');
    }
  }
}

/** Structural adapter for callers that hold a raw `pg` Pool. */
export function asControlGrantPool(pool: Pool): TenantPool {
  return pool as unknown as TenantPool;
}
