import { createHash } from 'node:crypto';
import type { Pool } from 'pg';
import {
  CommerceActionMetadataSchema,
  CommerceActionPageSchema,
  CommerceApprovalDetailSchema,
  CommerceApprovalMetadataSchema,
  CommerceApprovalPageSchema,
  compareIsoTimestamps,
  type CommerceActionMetadata,
  type CommerceActionPage,
  type CommerceActionStatus,
  type CommerceApprovalDetail,
  type CommerceApprovalMetadata,
  type CommerceApprovalPage,
  type CommerceApprovalStatus,
} from '@openarc/shared';
import { loadMigrations } from './migrate.js';
import { TenantStore, type TenantClient, type TenantPool } from './tenant-store.js';
import {
  CommerceActionInputError,
  parseCommerceActionHash,
  parseCommerceActionId,
  parseCommerceActionMetadata,
  parseCommerceApprovalId,
  parseCommerceApprovalMetadata,
} from './control-action-mutations.js';

/**
 * ControlActionReadStore: the DB11 bounded commerce action/approval READ
 * queues over the accepted restricted tenant pool.
 *
 * This repository is reads only. It adds no authority, performs no mutation,
 * writes no durability or outbox evidence, issues no grant and moves no funds.
 * Every method runs one statement inside one transaction through the reviewed
 * schema11 SECURITY DEFINER projections, which re-assert the SAME current human
 * authority as the schema10 readers (live non-recovery session, current active
 * owner/operator membership) after the projection, including the empty and
 * not-found paths. Outputs strict-parse the frozen shared page/detail DTOs and
 * collapse any malformed driver row to a fixed UNAVAILABLE error.
 *
 * The wrapper organization is always the DB-derived organization the database
 * actually authorized, never the caller-supplied lookup argument.
 */

export const CONTROL_ACTION_READ_STORE_ERROR_MESSAGES = {
  CONTROL_ACTION_READ_STORE_INPUT_INVALID: 'ControlActionReadStore input is invalid.',
  CONTROL_ACTION_READ_STORE_SESSION_INVALID: 'ControlActionReadStore session is not valid.',
  CONTROL_ACTION_READ_STORE_FORBIDDEN: 'ControlActionReadStore caller is not permitted.',
  CONTROL_ACTION_READ_STORE_UNAVAILABLE: 'ControlActionReadStore is not available.',
} as const;

export type ControlActionReadStoreErrorCode =
  keyof typeof CONTROL_ACTION_READ_STORE_ERROR_MESSAGES;

/** Fixed, non-echoing repository error. Never carries driver or input detail. */
export class ControlActionReadStoreError extends Error {
  readonly code: ControlActionReadStoreErrorCode;

  constructor(code: ControlActionReadStoreErrorCode) {
    super(CONTROL_ACTION_READ_STORE_ERROR_MESSAGES[code]);
    this.name = 'ControlActionReadStoreError';
    this.code = code;
  }
}

/** Accepted action list request: exclusive lexical cursor plus bounded limit. */
export interface CommerceActionListQuery {
  readonly afterActionId?: string;
  readonly limit?: string;
}

/** Accepted approval list request: exclusive lexical cursor plus bounded limit. */
export interface CommerceApprovalListQuery {
  readonly afterApprovalId?: string;
  readonly limit?: string;
}

/**
 * The four exposure buckets of one agent/policy window, kept SEPARATE.
 *
 * The schema10 exposure read collapses held/claimed/unknown into a single
 * `unresolved` numeric inside PL/pgSQL, so no caller above the database can
 * tell unknown money apart from money that is merely outstanding. These four
 * fields are the un-collapsed buckets; there is deliberately no total, no
 * available amount and no deficit here, because every one of those is a sum
 * that would hide `unknownAtomic` again.
 */
export interface CommerceExposureBuckets {
  readonly organizationId: string;
  readonly subjectAgentId: string;
  readonly policyId: string;
  readonly policyRevision: string;
  readonly networkId: string;
  readonly asset: string;
  readonly representation: string;
  readonly decimals: number;
  readonly windowSeconds: string | null;
  readonly heldAtomic: string;
  readonly claimedAtomic: string;
  readonly unknownAtomic: string;
  readonly committedAtomic: string;
  readonly policyExpiresAt: string | null;
  readonly asOf: string;
}

/**
 * Exposure-bucket answer. An unknown, inactive or foreign policy under a valid
 * current authority is `item: null` and still carries the DB-derived
 * authenticated organization, so "absent" and "another organization's" are
 * indistinguishable.
 */
export interface CommerceExposureBucketDetail {
  readonly organizationId: string;
  readonly subjectAgentId: string;
  readonly policyId: string;
  readonly item: CommerceExposureBuckets | null;
}

/** The three frozen sources an operator stuck/unknown queue entry comes from. */
export const OPERATOR_QUEUE_KINDS = [
  'authorization_grant',
  'budget_reservation',
  'payment_attempt',
] as const;

export type OperatorQueueKind = (typeof OPERATOR_QUEUE_KINDS)[number];

/** One stuck/unknown entry. `amountAtomic` is always an exact integer string. */
export interface OperatorQueueEntry {
  readonly kind: OperatorQueueKind;
  readonly entryId: string;
  readonly status: string;
  readonly subjectAgentId: string;
  readonly actionId: string;
  readonly amountAtomic: string;
  readonly startedAt: string;
  readonly expiresAt: string | null;
}

/** The exclusive keyset cursor: the exact (kind, entryId) pair last returned. */
export interface OperatorQueueCursor {
  readonly kind: OperatorQueueKind;
  readonly entryId: string;
}

export interface OperatorQueuePage {
  readonly organizationId: string;
  readonly items: readonly OperatorQueueEntry[];
  readonly nextCursor: OperatorQueueCursor | null;
  readonly asOf: string;
}

/**
 * Accepted stuck-queue request. Both windows are canonical second strings; the
 * cursor halves are presented together or neither is.
 */
export interface OperatorQueueListQuery {
  readonly attemptMaxAgeSeconds?: string;
  readonly grantExpiryWindowSeconds?: string;
  readonly afterKind?: string;
  readonly afterEntryId?: string;
  readonly limit?: string;
}

const ORG_ID = /^openarc:org:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const AGENT_ID = /^openarc:agent:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const POLICY_ID = /^openarc:policy:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const ACTION_ID = /^openarc:action:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const RESERVATION_ID = /^openarc:reservation:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const GRANT_ID = /^openarc:grant:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const POLICY_REVISION = /^[1-9][0-9]{0,8}$(?![\s\S])/;
const DECIMAL = /^(0|[1-9][0-9]{0,127})$(?![\s\S])/;
// A positive exact integer amount: reservation debit, attempt value, action debit.
const POSITIVE_DECIMAL = /^[1-9][0-9]{0,127}$(?![\s\S])/;
// Frozen accepted policy rolling-window bound: canonical seconds 1..2592000.
const WINDOW_SECONDS = /^[1-9][0-9]{0,6}$(?![\s\S])/;
// Caller-supplied queue windows admit zero, so the boundary case is testable.
const QUEUE_SECONDS = /^(0|[1-9][0-9]{0,6})$(?![\s\S])/;
const WINDOW_SECONDS_MAX = 2592000n;

/**
 * The single frozen exposure identity every schema10 bucket is denominated in.
 * A row that disagrees is a fixed UNAVAILABLE, never silently relabeled.
 */
const EXPOSURE_IDENTITY = {
  networkId: 'eip155:5042002',
  asset: 'USDC',
  representation: 'erc20',
  decimals: 6,
} as const;

const RESERVATION_QUEUE_STATUSES = new Set(['unknown']);
const ATTEMPT_QUEUE_STATUSES = new Set(['unknown', 'pending']);
const GRANT_QUEUE_STATUSES = new Set(['issued']);
// Canonical wire limit 1..50 with an absolute end. A plain `$` would accept a
// trailing LF in JavaScript, relabeling a malformed operand as valid.
const LIST_LIMIT = /^(?:[1-9]|[1-4][0-9]|50)$(?![\s\S])/;

/** Accepted default page size, applied here when the request omits `limit`. */
export const CONTROL_ACTION_READ_DEFAULT_LIMIT = 25;
/** Accepted maximum page size. */
export const CONTROL_ACTION_READ_MAX_LIMIT = 50;
/** Accepted default stuck-queue attempt age, applied here, never by the DB. */
export const OPERATOR_QUEUE_DEFAULT_ATTEMPT_MAX_AGE_SECONDS = 900;
/** Accepted default stuck-queue grant expiry window, applied here. */
export const OPERATOR_QUEUE_DEFAULT_GRANT_EXPIRY_WINDOW_SECONDS = 900;
/** Hard ceiling on both caller-supplied queue windows: 30 days in seconds. */
export const OPERATOR_QUEUE_MAX_WINDOW_SECONDS = 2592000;

const ACTION_LIST_KEYS = ['afterActionId', 'limit'] as const;
const APPROVAL_LIST_KEYS = ['afterApprovalId', 'limit'] as const;
const QUEUE_LIST_KEYS = [
  'attemptMaxAgeSeconds',
  'grantExpiryWindowSeconds',
  'afterKind',
  'afterEntryId',
  'limit',
] as const;

function fail(code: ControlActionReadStoreErrorCode): never {
  throw new ControlActionReadStoreError(code);
}

function failOutput(): never {
  fail('CONTROL_ACTION_READ_STORE_UNAVAILABLE');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireHash(value: unknown): string {
  try {
    return parseCommerceActionHash(value);
  } catch {
    fail('CONTROL_ACTION_READ_STORE_INPUT_INVALID');
  }
}

function requireOrganization(value: unknown): string {
  if (typeof value !== 'string' || !ORG_ID.test(value)) {
    fail('CONTROL_ACTION_READ_STORE_INPUT_INVALID');
  }
  return value;
}

function requireApproval(value: unknown): string {
  try {
    return parseCommerceApprovalId(value);
  } catch {
    fail('CONTROL_ACTION_READ_STORE_INPUT_INVALID');
  }
}

/**
 * Strict bounded query envelope. A plain object with only the allowed keys is
 * accepted; an unknown key, a prototype-bearing object, or a present key whose
 * value is `undefined` is a fixed input fault, never a silent default.
 */
function requireQueryShape(
  value: unknown,
  allowed: readonly string[],
): Record<string, unknown> {
  if (value === undefined || value === null) return {};
  if (!isRecord(value)) fail('CONTROL_ACTION_READ_STORE_INPUT_INVALID');
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    fail('CONTROL_ACTION_READ_STORE_INPUT_INVALID');
  }
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) fail('CONTROL_ACTION_READ_STORE_INPUT_INVALID');
    if (value[key] === undefined) fail('CONTROL_ACTION_READ_STORE_INPUT_INVALID');
  }
  return value;
}

/**
 * The canonical string limit 1..50. Absent means the accepted default 25; the
 * default is applied HERE, never by the database and never by coercion. A
 * number, a non-canonical string ('05', ' 5', '5\n', '0', '51') is rejected.
 */
function requireLimit(value: unknown): number {
  if (value === undefined) return CONTROL_ACTION_READ_DEFAULT_LIMIT;
  if (typeof value !== 'string' || !LIST_LIMIT.test(value)) {
    fail('CONTROL_ACTION_READ_STORE_INPUT_INVALID');
  }
  const limit = Number.parseInt(value, 10);
  if (!Number.isInteger(limit) || limit < 1 || limit > CONTROL_ACTION_READ_MAX_LIMIT) {
    fail('CONTROL_ACTION_READ_STORE_INPUT_INVALID');
  }
  return limit;
}

function requireActionCursor(value: unknown): string | null {
  if (value === undefined) return null;
  try {
    return parseCommerceActionId(value);
  } catch {
    fail('CONTROL_ACTION_READ_STORE_INPUT_INVALID');
  }
}

function requireApprovalCursor(value: unknown): string | null {
  if (value === undefined) return null;
  try {
    return parseCommerceApprovalId(value);
  } catch {
    fail('CONTROL_ACTION_READ_STORE_INPUT_INVALID');
  }
}

function requireAgent(value: unknown): string {
  if (typeof value !== 'string' || !AGENT_ID.test(value)) {
    fail('CONTROL_ACTION_READ_STORE_INPUT_INVALID');
  }
  return value;
}

function requirePolicy(value: unknown): string {
  if (typeof value !== 'string' || !POLICY_ID.test(value)) {
    fail('CONTROL_ACTION_READ_STORE_INPUT_INVALID');
  }
  return value;
}

/**
 * A canonical 0..2592000 second window. Absent means the accepted default,
 * applied HERE and never by the database, never by coercion. A number, a
 * non-canonical string ('0900', ' 90', '90\n', '2592001') is rejected.
 */
function requireQueueSeconds(value: unknown, fallback: number): number {
  if (value === undefined) return fallback;
  if (typeof value !== 'string' || !QUEUE_SECONDS.test(value)) {
    fail('CONTROL_ACTION_READ_STORE_INPUT_INVALID');
  }
  if (BigInt(value) > WINDOW_SECONDS_MAX) {
    fail('CONTROL_ACTION_READ_STORE_INPUT_INVALID');
  }
  const seconds = Number.parseInt(value, 10);
  if (!Number.isInteger(seconds) || seconds < 0 || seconds > OPERATOR_QUEUE_MAX_WINDOW_SECONDS) {
    fail('CONTROL_ACTION_READ_STORE_INPUT_INVALID');
  }
  return seconds;
}

function isOperatorQueueKind(value: unknown): value is OperatorQueueKind {
  return (
    value === 'authorization_grant' ||
    value === 'budget_reservation' ||
    value === 'payment_attempt'
  );
}

/**
 * The composite queue cursor. Both halves are presented together or neither
 * is, and the id shape must match the kind it claims: a grant id under
 * `payment_attempt` is a fixed input fault, never a silently widened scan.
 */
function requireQueueCursor(
  kind: unknown,
  entryId: unknown,
): { readonly kind: OperatorQueueKind | null; readonly entryId: string | null } {
  if (kind === undefined && entryId === undefined) return { kind: null, entryId: null };
  if (kind === undefined || entryId === undefined) {
    fail('CONTROL_ACTION_READ_STORE_INPUT_INVALID');
  }
  if (!isOperatorQueueKind(kind) || typeof entryId !== 'string') {
    fail('CONTROL_ACTION_READ_STORE_INPUT_INVALID');
  }
  const shaped =
    (kind === 'authorization_grant' && GRANT_ID.test(entryId)) ||
    (kind === 'budget_reservation' && RESERVATION_ID.test(entryId)) ||
    (kind === 'payment_attempt' && UUID_V4.test(entryId));
  if (!shaped) fail('CONTROL_ACTION_READ_STORE_INPUT_INVALID');
  return { kind, entryId };
}

function normalizeError(error: unknown): ControlActionReadStoreError {
  if (error instanceof ControlActionReadStoreError) return error;
  if (error instanceof CommerceActionInputError) {
    return new ControlActionReadStoreError('CONTROL_ACTION_READ_STORE_INPUT_INVALID');
  }
  if (isRecord(error) && typeof error.code === 'string') {
    switch (error.code) {
      case '28000':
        return new ControlActionReadStoreError('CONTROL_ACTION_READ_STORE_SESSION_INVALID');
      case '42501':
        return new ControlActionReadStoreError('CONTROL_ACTION_READ_STORE_FORBIDDEN');
      case '22023':
      case '22P02':
      case '22001':
      case '22003':
      case '23514':
        return new ControlActionReadStoreError('CONTROL_ACTION_READ_STORE_INPUT_INVALID');
      default:
        return new ControlActionReadStoreError('CONTROL_ACTION_READ_STORE_UNAVAILABLE');
    }
  }
  return new ControlActionReadStoreError('CONTROL_ACTION_READ_STORE_UNAVAILABLE');
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

const ACTION_COLUMNS = `out_organization_id, out_found, out_action_id, out_subject_agent_id,
                out_commerce_session_id, out_status, out_policy_id, out_policy_revision,
                out_provider_id, out_listing_id, out_listing_version, out_requirement_id,
                out_requirement_digest, out_network_id, out_asset, out_representation,
                out_decimals, out_amount_atomic, out_fee_atomic, out_debit_atomic,
                out_reservation_id, out_approval_id,
                out_created_at::text AS out_created_at,
                out_updated_at::text AS out_updated_at,
                out_expires_at::text AS out_expires_at`;

const APPROVAL_COLUMNS = `out_organization_id, out_found, out_approval_id, out_action_id,
                out_subject_agent_id, out_commerce_session_id, out_status, out_policy_id,
                out_policy_revision, out_requested_by, out_separate_approver, out_decided_by,
                out_created_at::text AS out_created_at,
                out_expires_at::text AS out_expires_at,
                out_decided_at::text AS out_decided_at`;

const BUCKET_COLUMNS = `out_organization_id, out_found, out_subject_agent_id, out_policy_id,
                out_policy_revision, out_network_id, out_asset, out_representation, out_decimals,
                out_window_seconds, out_held_atomic, out_claimed_atomic, out_unknown_atomic,
                out_committed_atomic,
                out_policy_expires_at::text AS out_policy_expires_at,
                out_as_of::text AS out_as_of`;

const QUEUE_COLUMNS = `out_organization_id, out_found, out_kind, out_entry_id, out_status,
                out_subject_agent_id, out_action_id, out_amount_atomic,
                out_started_at::text AS out_started_at,
                out_expires_at::text AS out_expires_at,
                out_as_of::text AS out_as_of`;

export class ControlActionReadStore {
  readonly #pool: TenantPool;
  readonly #base: TenantStore;
  #initialized = false;

  constructor(pool: TenantPool) {
    if (pool === null || typeof pool !== 'object' || typeof pool.connect !== 'function') {
      fail('CONTROL_ACTION_READ_STORE_INPUT_INVALID');
    }
    this.#pool = pool;
    this.#base = new TenantStore(pool);
  }

  async initialize(): Promise<void> {
    if (this.#initialized) return;
    await this.#baseChecks(() => this.#base.initialize());
    await this.#withTransaction(async (client) => {
      await this.#assertReady(client);
    });
    this.#initialized = true;
  }

  async readiness(): Promise<void> {
    await this.#baseChecks(() => this.#base.readiness());
    await this.#withTransaction(async (client) => {
      await this.#assertReady(client);
    });
  }

  async #baseChecks(run: () => Promise<void>): Promise<void> {
    try {
      await run();
    } catch {
      fail('CONTROL_ACTION_READ_STORE_UNAVAILABLE');
    }
  }

  /**
   * Bounded action page for the current human caller. Reads EVERY status: no
   * hidden server-side status filter exists. The page organization is the
   * DB-derived authenticated organization; `nextCursor` is non-null only when
   * a further page actually exists, and then is exactly the last returned id.
   */
  async listActions(
    humanSessionHash: unknown,
    organizationId: unknown,
    query?: unknown,
  ): Promise<CommerceActionPage> {
    const hash = requireHash(humanSessionHash);
    const organization = requireOrganization(organizationId);
    const shape = requireQueryShape(query, ACTION_LIST_KEYS);
    const cursor = requireActionCursor(shape['afterActionId']);
    const limit = requireLimit(shape['limit']);
    return this.#withTransaction(async (client) => {
      // limit + 1 detects a further page without a count or an offset.
      const result = await client.query<Record<string, unknown>>(
        `SELECT ${ACTION_COLUMNS}
           FROM openarc_durable.list_commerce_actions($1, $2, $3, $4::int)`,
        [hash, organization, cursor, limit],
      );
      const rows = result.rows;
      if (rows.length === 0 || rows.length > limit + 1) failOutput();
      const authenticated = this.#requireUniformOrganization(rows, organization);
      const fetched: CommerceActionMetadata[] = [];
      if (rows.length !== 1 || rows[0]?.['out_found'] !== false) {
        for (const row of rows) {
          if (row['out_found'] !== true) failOutput();
          fetched.push(this.#projectAction(row, authenticated));
        }
      }
      const ids = fetched.map((item) => item.actionId);
      this.#requireStrictlyAscending(ids);
      const hasMore = fetched.length > limit;
      const items = fetched.slice(0, limit);
      const last = items[items.length - 1];
      const nextCursor = hasMore && last !== undefined ? last.actionId : null;
      const parsed = CommerceActionPageSchema.safeParse({
        organizationId: authenticated,
        items,
        nextCursor,
      });
      if (!parsed.success) failOutput();
      return parsed.data;
    });
  }

  /**
   * Bounded approval page for the current human caller. Reads EVERY status.
   */
  async listApprovals(
    humanSessionHash: unknown,
    organizationId: unknown,
    query?: unknown,
  ): Promise<CommerceApprovalPage> {
    const hash = requireHash(humanSessionHash);
    const organization = requireOrganization(organizationId);
    const shape = requireQueryShape(query, APPROVAL_LIST_KEYS);
    const cursor = requireApprovalCursor(shape['afterApprovalId']);
    const limit = requireLimit(shape['limit']);
    return this.#withTransaction(async (client) => {
      const result = await client.query<Record<string, unknown>>(
        `SELECT ${APPROVAL_COLUMNS}
           FROM openarc_durable.list_commerce_approvals($1, $2, $3, $4::int)`,
        [hash, organization, cursor, limit],
      );
      const rows = result.rows;
      if (rows.length === 0 || rows.length > limit + 1) failOutput();
      const authenticated = this.#requireUniformOrganization(rows, organization);
      const fetched: CommerceApprovalMetadata[] = [];
      if (rows.length !== 1 || rows[0]?.['out_found'] !== false) {
        for (const row of rows) {
          if (row['out_found'] !== true) failOutput();
          fetched.push(this.#projectApproval(row, authenticated));
        }
      }
      const ids = fetched.map((item) => item.approvalId);
      this.#requireStrictlyAscending(ids);
      const hasMore = fetched.length > limit;
      const items = fetched.slice(0, limit);
      const last = items[items.length - 1];
      const nextCursor = hasMore && last !== undefined ? last.approvalId : null;
      const parsed = CommerceApprovalPageSchema.safeParse({
        organizationId: authenticated,
        items,
        nextCursor,
      });
      if (!parsed.success) failOutput();
      return parsed.data;
    });
  }

  /**
   * Approval detail keyed by the APPROVAL id, which is what the accepted wire
   * contract requires. The schema10 action-id reader is untouched. A missing or
   * foreign approval under a valid CURRENT authority is a safe not-found that
   * still carries the DB-derived authenticated organization.
   */
  async readApprovalById(
    humanSessionHash: unknown,
    organizationId: unknown,
    approvalId: unknown,
  ): Promise<CommerceApprovalDetail> {
    const hash = requireHash(humanSessionHash);
    const organization = requireOrganization(organizationId);
    const approval = requireApproval(approvalId);
    return this.#withTransaction(async (client) => {
      const result = await client.query<Record<string, unknown>>(
        `SELECT ${APPROVAL_COLUMNS}
           FROM openarc_durable.read_commerce_approval_by_id($1, $2, $3)`,
        [hash, organization, approval],
      );
      const rows = result.rows;
      if (rows.length !== 1) failOutput();
      const authenticated = this.#requireUniformOrganization(rows, organization);
      const row = rows[0];
      if (row === undefined) failOutput();
      let item: CommerceApprovalMetadata | null = null;
      if (row['out_found'] === true) {
        item = this.#projectApproval(row, authenticated);
        if (item.approvalId !== approval) failOutput();
      } else if (row['out_found'] !== false) {
        failOutput();
      }
      const parsed = CommerceApprovalDetailSchema.safeParse({
        organizationId: authenticated,
        approvalId: approval,
        item,
      });
      if (!parsed.success) failOutput();
      return parsed.data;
    });
  }

  /**
   * The FOUR exposure buckets of one agent/policy window, kept separate.
   *
   * `unknownAtomic` is never merged into anything: the answer carries no
   * total, no available amount and no deficit, because each of those is a sum
   * that would hide it again. A completeness-bound overflow in either
   * accounting source fails closed (UNAVAILABLE) rather than returning a
   * partial bucket, and an unknown, inactive or foreign policy under a valid
   * current authority is `item: null` carrying the DB-derived organization.
   */
  async readExposureBuckets(
    humanSessionHash: unknown,
    organizationId: unknown,
    subjectAgentId: unknown,
    policyId: unknown,
  ): Promise<CommerceExposureBucketDetail> {
    const hash = requireHash(humanSessionHash);
    const organization = requireOrganization(organizationId);
    const subject = requireAgent(subjectAgentId);
    const policy = requirePolicy(policyId);
    return this.#withTransaction(async (client) => {
      const result = await client.query<Record<string, unknown>>(
        `SELECT ${BUCKET_COLUMNS}
           FROM openarc_durable.read_commerce_exposure_buckets($1, $2, $3, $4)`,
        [hash, organization, subject, policy],
      );
      const rows = result.rows;
      if (rows.length !== 1) failOutput();
      const authenticated = this.#requireUniformOrganization(rows, organization);
      const row = rows[0];
      if (row === undefined) failOutput();
      let item: CommerceExposureBuckets | null = null;
      if (row['out_found'] === true) {
        item = this.#projectBuckets(row, authenticated, subject, policy);
      } else if (row['out_found'] !== false) {
        failOutput();
      }
      return {
        organizationId: authenticated,
        subjectAgentId: subject,
        policyId: policy,
        item,
      };
    });
  }

  /**
   * Bounded stuck/unknown operator queue for the whole organization.
   *
   * Membership is fixed in SQL: reservations in `unknown`, payment attempts in
   * `unknown` or `pending` dispatched at or before the caller's bounded age,
   * and never-claimed `issued` grants expiring at or before the caller's
   * bounded window. Ordering is the deterministic (kind, entryId) total order
   * and `nextCursor` is non-null only when a further page actually exists, and
   * then is exactly the last returned pair.
   */
  async listStuckQueue(
    humanSessionHash: unknown,
    organizationId: unknown,
    query?: unknown,
  ): Promise<OperatorQueuePage> {
    const hash = requireHash(humanSessionHash);
    const organization = requireOrganization(organizationId);
    const shape = requireQueryShape(query, QUEUE_LIST_KEYS);
    const attemptMaxAge = requireQueueSeconds(
      shape['attemptMaxAgeSeconds'],
      OPERATOR_QUEUE_DEFAULT_ATTEMPT_MAX_AGE_SECONDS,
    );
    const grantWindow = requireQueueSeconds(
      shape['grantExpiryWindowSeconds'],
      OPERATOR_QUEUE_DEFAULT_GRANT_EXPIRY_WINDOW_SECONDS,
    );
    const cursor = requireQueueCursor(shape['afterKind'], shape['afterEntryId']);
    const limit = requireLimit(shape['limit']);
    return this.#withTransaction(async (client) => {
      const result = await client.query<Record<string, unknown>>(
        `SELECT ${QUEUE_COLUMNS}
           FROM openarc_durable.list_operator_stuck_queue(
             $1, $2, $3::int, $4::int, $5, $6, $7::int)`,
        [hash, organization, attemptMaxAge, grantWindow, cursor.kind, cursor.entryId, limit],
      );
      const rows = result.rows;
      if (rows.length === 0 || rows.length > limit + 1) failOutput();
      const authenticated = this.#requireUniformOrganization(rows, organization);
      const asOf = this.#requireUniformAsOf(rows);
      const fetched: OperatorQueueEntry[] = [];
      if (rows.length !== 1 || rows[0]?.['out_found'] !== false) {
        for (const row of rows) {
          if (row['out_found'] !== true) failOutput();
          fetched.push(this.#projectQueueEntry(row));
        }
      }
      this.#requireStrictlyAscending(fetched.map((item) => `${item.kind} ${item.entryId}`));
      const hasMore = fetched.length > limit;
      const items = fetched.slice(0, limit);
      const last = items[items.length - 1];
      const nextCursor =
        hasMore && last !== undefined ? { kind: last.kind, entryId: last.entryId } : null;
      return { organizationId: authenticated, items, nextCursor, asOf };
    });
  }

  /**
   * Every row of one page must carry the SAME DB-derived organization. A page
   * whose rows disagree is a fixed UNAVAILABLE, never a silently relabeled mix.
   */
  #requireUniformOrganization(
    rows: readonly Record<string, unknown>[],
    requested: string,
  ): string {
    const first = rows[0];
    if (first === undefined) failOutput();
    const organization = first['out_organization_id'];
    if (typeof organization !== 'string' || !ORG_ID.test(organization)) failOutput();
    for (const row of rows) {
      if (row['out_organization_id'] !== organization) failOutput();
    }
    // The projection authorized the requested organization, so the DB-derived
    // value must be exactly it. A disagreement is a fixed UNAVAILABLE and is
    // never silently relabeled to either side.
    if (organization !== requested) failOutput();
    return organization;
  }

  /** Every row of one queue page must carry the SAME database read instant. */
  #requireUniformAsOf(rows: readonly Record<string, unknown>[]): string {
    const first = rows[0];
    if (first === undefined) failOutput();
    const asOf = iso(first['out_as_of']);
    for (const row of rows) {
      if (iso(row['out_as_of']) !== asOf) failOutput();
    }
    return asOf;
  }

  #requireDecimal(value: unknown): string {
    if (typeof value !== 'string' || !DECIMAL.test(value)) failOutput();
    return value;
  }

  #requirePositiveDecimal(value: unknown): string {
    if (typeof value !== 'string' || !POSITIVE_DECIMAL.test(value)) failOutput();
    return value;
  }

  #requireWindowSeconds(value: unknown): string | null {
    if (value === null || value === undefined) return null;
    if (
      typeof value !== 'string' || !WINDOW_SECONDS.test(value) ||
      BigInt(value) > WINDOW_SECONDS_MAX
    ) {
      failOutput();
    }
    return value;
  }

  #projectBuckets(
    row: Record<string, unknown>,
    organization: string,
    subject: string,
    policy: string,
  ): CommerceExposureBuckets {
    // Validate the returned identity against the frozen allowed identity
    // BEFORE projecting: a wrong network/asset/representation/decimals is a
    // fixed UNAVAILABLE, never silently relabeled to the literal.
    if (
      row['out_network_id'] !== EXPOSURE_IDENTITY.networkId ||
      row['out_asset'] !== EXPOSURE_IDENTITY.asset ||
      row['out_representation'] !== EXPOSURE_IDENTITY.representation ||
      row['out_decimals'] !== EXPOSURE_IDENTITY.decimals
    ) {
      failOutput();
    }
    if (row['out_organization_id'] !== organization) failOutput();
    if (requireAgent(row['out_subject_agent_id']) !== subject) failOutput();
    if (requirePolicy(row['out_policy_id']) !== policy) failOutput();
    const revision = row['out_policy_revision'];
    if (typeof revision !== 'string' || !POLICY_REVISION.test(revision)) failOutput();
    // Each bucket is validated on its own. They are NEVER added together here:
    // a sum is exactly the projection that loses `unknownAtomic`.
    const heldAtomic = this.#requireDecimal(row['out_held_atomic']);
    const claimedAtomic = this.#requireDecimal(row['out_claimed_atomic']);
    const unknownAtomic = this.#requireDecimal(row['out_unknown_atomic']);
    const committedAtomic = this.#requireDecimal(row['out_committed_atomic']);
    return {
      organizationId: organization,
      subjectAgentId: subject,
      policyId: policy,
      policyRevision: revision,
      networkId: EXPOSURE_IDENTITY.networkId,
      asset: EXPOSURE_IDENTITY.asset,
      representation: EXPOSURE_IDENTITY.representation,
      decimals: EXPOSURE_IDENTITY.decimals,
      windowSeconds: this.#requireWindowSeconds(row['out_window_seconds']),
      heldAtomic,
      claimedAtomic,
      unknownAtomic,
      committedAtomic,
      policyExpiresAt: isoOrNull(row['out_policy_expires_at']),
      asOf: iso(row['out_as_of']),
    };
  }

  #projectQueueEntry(row: Record<string, unknown>): OperatorQueueEntry {
    const kind = row['out_kind'];
    if (!isOperatorQueueKind(kind)) failOutput();
    const entryId = row['out_entry_id'];
    const status = row['out_status'];
    if (typeof entryId !== 'string' || typeof status !== 'string') failOutput();
    // The id shape and the status must both match the kind the row claims, so
    // a mislabeled source can never be presented as a different one.
    const shaped =
      (kind === 'authorization_grant' &&
        GRANT_ID.test(entryId) && GRANT_QUEUE_STATUSES.has(status)) ||
      (kind === 'budget_reservation' &&
        RESERVATION_ID.test(entryId) && RESERVATION_QUEUE_STATUSES.has(status)) ||
      (kind === 'payment_attempt' &&
        UUID_V4.test(entryId) && ATTEMPT_QUEUE_STATUSES.has(status));
    if (!shaped) failOutput();
    const actionId = row['out_action_id'];
    if (typeof actionId !== 'string' || !ACTION_ID.test(actionId)) failOutput();
    // Only a grant carries an expiry; the other two sources have none, and a
    // stray value there is a fixed UNAVAILABLE.
    const expiresAt = isoOrNull(row['out_expires_at']);
    if (kind === 'authorization_grant') {
      if (expiresAt === null) failOutput();
    } else if (expiresAt !== null) {
      failOutput();
    }
    return {
      kind,
      entryId,
      status,
      subjectAgentId: requireAgent(row['out_subject_agent_id']),
      actionId,
      amountAtomic: this.#requirePositiveDecimal(row['out_amount_atomic']),
      startedAt: iso(row['out_started_at']),
      expiresAt,
    };
  }

  #requireStrictlyAscending(ids: readonly string[]): void {
    for (let index = 1; index < ids.length; index += 1) {
      const previous = ids[index - 1];
      const current = ids[index];
      if (previous === undefined || current === undefined || !(previous < current)) {
        failOutput();
      }
    }
  }

  #projectAction(
    row: Record<string, unknown>,
    organization: string,
  ): CommerceActionMetadata {
    const parsed = CommerceActionMetadataSchema.safeParse({
      schemaVersion: 'openarc.control.action.v1',
      actionId: row['out_action_id'],
      exposureKey: {
        organizationId: row['out_organization_id'],
        subjectAgentId: row['out_subject_agent_id'],
        networkId: row['out_network_id'],
        asset: row['out_asset'],
        representation: row['out_representation'],
        decimals: row['out_decimals'],
      },
      commerceSessionId: row['out_commerce_session_id'],
      policyId: row['out_policy_id'],
      policyRevision: row['out_policy_revision'],
      providerId: row['out_provider_id'],
      listingId: row['out_listing_id'],
      listingVersion: row['out_listing_version'],
      requirementId: row['out_requirement_id'],
      requirementDigest: row['out_requirement_digest'],
      amountAtomic: row['out_amount_atomic'],
      feeAtomic: row['out_fee_atomic'],
      debitAtomic: row['out_debit_atomic'],
      status: row['out_status'] as CommerceActionStatus,
      reservationId: row['out_reservation_id'] ?? null,
      approvalId: row['out_approval_id'] ?? null,
      createdAt: iso(row['out_created_at']),
      updatedAt: iso(row['out_updated_at']),
      expiresAt: iso(row['out_expires_at']),
    });
    if (!parsed.success) failOutput();
    if (
      compareIsoTimestamps(parsed.data.updatedAt, parsed.data.createdAt) < 0 ||
      compareIsoTimestamps(parsed.data.expiresAt, parsed.data.createdAt) <= 0
    ) {
      failOutput();
    }
    if (parsed.data.exposureKey.organizationId !== organization) failOutput();
    return parseCommerceActionMetadata(parsed.data);
  }

  #projectApproval(
    row: Record<string, unknown>,
    organization: string,
  ): CommerceApprovalMetadata {
    const parsed = CommerceApprovalMetadataSchema.safeParse({
      schemaVersion: 'openarc.control.approval.v1',
      approvalId: row['out_approval_id'],
      actionId: row['out_action_id'],
      organizationId: row['out_organization_id'],
      subjectAgentId: row['out_subject_agent_id'],
      commerceSessionId: row['out_commerce_session_id'],
      policyId: row['out_policy_id'],
      policyRevision: row['out_policy_revision'],
      requestedBy: row['out_requested_by'],
      separateApprover: row['out_separate_approver'],
      status: row['out_status'] as CommerceApprovalStatus,
      decidedBy: row['out_decided_by'] ?? null,
      createdAt: iso(row['out_created_at']),
      expiresAt: iso(row['out_expires_at']),
      decidedAt: isoOrNull(row['out_decided_at']),
    });
    if (!parsed.success) failOutput();
    if (parsed.data.organizationId !== organization) failOutput();
    return parseCommerceApprovalMetadata(parsed.data);
  }

  async #withTransaction<T>(work: (client: TenantClient) => Promise<T>): Promise<T> {
    let client: TenantClient;
    try {
      client = await this.#pool.connect();
    } catch {
      fail('CONTROL_ACTION_READ_STORE_UNAVAILABLE');
    }
    try {
      await client.query('BEGIN');
    } catch {
      client.release(true);
      fail('CONTROL_ACTION_READ_STORE_UNAVAILABLE');
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
    // A read commits nothing; a failed COMMIT on a read is still UNAVAILABLE
    // and never an unknown-outcome mutation.
    try {
      await client.query('COMMIT');
    } catch {
      client.release(true);
      fail('CONTROL_ACTION_READ_STORE_UNAVAILABLE');
    }
    client.release(false);
    return result;
  }

  async #assertReady(client: TenantClient): Promise<void> {
    // schema18 adds three operator reads over three further frozen tables; the
    // runtime must hold no direct privilege on any of them either.
    const EXPECTED_TABLES = [
      'commerce_actions',
      'commerce_approvals',
      'budget_reservations',
      'budget_events',
      'authorization_grants',
      'payment_attempts',
    ];
    const tables = await client.query<{
      n: number;
      all_enabled: boolean;
      all_forced: boolean;
      owned: number;
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
      fail('CONTROL_ACTION_READ_STORE_UNAVAILABLE');
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
    if ((access.rows[0]?.n ?? -1) !== 0) fail('CONTROL_ACTION_READ_STORE_UNAVAILABLE');
    await this.#assertHelpers(client);
  }

  async #assertHelpers(client: TenantClient): Promise<void> {
    interface HelperExpectation {
      readonly name: string;
      readonly args: string;
      /** pg_proc.provolatile: 's' = STABLE, 'v' = VOLATILE. */
      readonly volatility: 'i' | 's' | 'v';
    }
    const production: readonly HelperExpectation[] = [
      {
        name: 'list_commerce_actions',
        args: 'human_session_hash text, organization_id text, after_action_id text, limit_count integer',
        volatility: 'v',
      },
      {
        name: 'list_commerce_approvals',
        args: 'human_session_hash text, organization_id text, after_approval_id text, limit_count integer',
        volatility: 'v',
      },
      {
        name: 'read_commerce_approval_by_id',
        args: 'human_session_hash text, organization_id text, approval_id_input text',
        volatility: 'v',
      },
      // schema18 operator control-room reads. They are STABLE: an operator read
      // that could be relabeled VOLATILE is one that could be given a write.
      {
        name: 'read_commerce_exposure_buckets',
        args: 'human_session_hash text, organization_id text, subject_agent_id_input text, policy_id_input text',
        volatility: 's',
      },
      {
        name: 'list_operator_stuck_queue',
        args: 'human_session_hash text, organization_id text, attempt_max_age_seconds integer, grant_expiry_window_seconds integer, after_kind text, after_entry_id text, limit_count integer',
        volatility: 's',
      },
    ];
    const privateHelpers: readonly HelperExpectation[] = [
      {
        name: 'resolve_action_reader_org',
        args: 'session_hash text, organization_id text',
        volatility: 'v',
      },
    ];
    const rows = await client.query<{
      proname: string;
      args: string;
      owner: string;
      secdef: boolean;
      volatility: string;
      config: string[];
      app_exec: boolean;
      public_grants: number;
    }>(
      `SELECT p.proname, pg_get_function_identity_arguments(p.oid) AS args,
              r.rolname AS owner, p.prosecdef AS secdef,
              p.provolatile::text AS volatility,
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
    // Exactly one overload per inventoried name: a second signature (for
    // example one accepting a caller-supplied organization filter or an
    // unbounded page size) is a readiness failure, never a silent fallback.
    const counts = new Map<string, number>();
    for (const row of rows.rows) counts.set(row.proname, (counts.get(row.proname) ?? 0) + 1);
    for (const count of counts.values()) {
      if (count !== 1) fail('CONTROL_ACTION_READ_STORE_UNAVAILABLE');
    }
    const byName = new Map(rows.rows.map((row) => [`${row.proname}(${row.args})`, row]));
    const check = (entries: readonly HelperExpectation[], appExec: boolean): void => {
      for (const expected of entries) {
        const row = byName.get(`${expected.name}(${expected.args})`);
        if (row === undefined) fail('CONTROL_ACTION_READ_STORE_UNAVAILABLE');
        if (
          row.owner !== 'openarc_migrator' ||
          row.secdef !== true ||
          row.volatility !== expected.volatility ||
          !row.config.includes('search_path=pg_catalog') ||
          row.public_grants !== 0 ||
          row.app_exec !== appExec
        ) {
          fail('CONTROL_ACTION_READ_STORE_UNAVAILABLE');
        }
      }
    };
    check(production, true);
    check(privateHelpers, false);
    const applied = await client.query<{ id: string; checksum: string }>(
      `SELECT id, checksum FROM openarc_meta.schema_migrations ORDER BY id`,
    );
    let migrations: readonly { readonly id: string; readonly sql: string }[];
    try {
      migrations = loadMigrations();
    } catch {
      fail('CONTROL_ACTION_READ_STORE_UNAVAILABLE');
    }
    if (applied.rows.length !== migrations.length) {
      fail('CONTROL_ACTION_READ_STORE_UNAVAILABLE');
    }
    for (let index = 0; index < applied.rows.length; index += 1) {
      const record = applied.rows[index];
      const manifest = migrations[index];
      if (record === undefined || manifest === undefined || record.id !== manifest.id) {
        fail('CONTROL_ACTION_READ_STORE_UNAVAILABLE');
      }
      const checksum = createHash('sha256').update(manifest.sql, 'utf8').digest('hex');
      if (record.checksum !== checksum) fail('CONTROL_ACTION_READ_STORE_UNAVAILABLE');
    }
  }
}

/** Structural adapter for callers that hold a raw `pg` Pool. */
export function asControlActionReadPool(pool: Pool): TenantPool {
  return pool as unknown as TenantPool;
}
