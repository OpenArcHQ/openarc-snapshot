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

const ORG_ID = /^openarc:org:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
// Canonical wire limit 1..50 with an absolute end. A plain `$` would accept a
// trailing LF in JavaScript, relabeling a malformed operand as valid.
const LIST_LIMIT = /^(?:[1-9]|[1-4][0-9]|50)$(?![\s\S])/;

/** Accepted default page size, applied here when the request omits `limit`. */
export const CONTROL_ACTION_READ_DEFAULT_LIMIT = 25;
/** Accepted maximum page size. */
export const CONTROL_ACTION_READ_MAX_LIMIT = 50;

const ACTION_LIST_KEYS = ['afterActionId', 'limit'] as const;
const APPROVAL_LIST_KEYS = ['afterApprovalId', 'limit'] as const;

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
    const EXPECTED_TABLES = ['commerce_actions', 'commerce_approvals'];
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
    const production: readonly { name: string; args: string }[] = [
      {
        name: 'list_commerce_actions',
        args: 'human_session_hash text, organization_id text, after_action_id text, limit_count integer',
      },
      {
        name: 'list_commerce_approvals',
        args: 'human_session_hash text, organization_id text, after_approval_id text, limit_count integer',
      },
      {
        name: 'read_commerce_approval_by_id',
        args: 'human_session_hash text, organization_id text, approval_id_input text',
      },
    ];
    const privateHelpers: readonly { name: string; args: string }[] = [
      { name: 'resolve_action_reader_org', args: 'session_hash text, organization_id text' },
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
      if (row === undefined) fail('CONTROL_ACTION_READ_STORE_UNAVAILABLE');
      if (
        row.owner !== 'openarc_migrator' ||
        row.secdef !== true ||
        !row.config.includes('search_path=pg_catalog') ||
        row.public_grants !== 0 ||
        row.app_exec !== true
      ) {
        fail('CONTROL_ACTION_READ_STORE_UNAVAILABLE');
      }
    }
    for (const expected of privateHelpers) {
      const row = byName.get(`${expected.name}(${expected.args})`);
      if (row === undefined) fail('CONTROL_ACTION_READ_STORE_UNAVAILABLE');
      if (
        row.owner !== 'openarc_migrator' ||
        row.secdef !== true ||
        !row.config.includes('search_path=pg_catalog') ||
        row.public_grants !== 0 ||
        row.app_exec !== false
      ) {
        fail('CONTROL_ACTION_READ_STORE_UNAVAILABLE');
      }
    }
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
