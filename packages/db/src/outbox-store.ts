import type { PoolClient } from 'pg';
import type { Pool } from 'pg';
import { loadMigrations } from './migrate.js';
import { createHash } from 'node:crypto';

/**
 * OutboxStore over the restricted `openarc_worker_app` role.
 *
 * This is the worker-facing half of the durability slice. It can only claim
 * cross-org opaque jobs and acknowledge them by id + lease generation through
 * the narrow definer helpers. It has no actor/session/key data, no business
 * payload, no organization choice and no arbitrary SQL. The worker process that
 * drives it is a later packet.
 */

export const OUTBOX_STORE_ERROR_MESSAGES = {
  OUTBOX_STORE_INPUT_INVALID: 'OutboxStore input is invalid.',
  OUTBOX_STORE_FORBIDDEN: 'OutboxStore caller is not permitted.',
  OUTBOX_STORE_NOT_FOUND: 'OutboxStore target was not found.',
  OUTBOX_STORE_UNAVAILABLE: 'OutboxStore is not available.',
  OUTBOX_STORE_OUTCOME_UNKNOWN:
    'OutboxStore mutation outcome could not be confirmed; it may have applied.',
} as const;

export type OutboxStoreErrorCode = keyof typeof OUTBOX_STORE_ERROR_MESSAGES;

/** Fixed, non-echoing repository error. Never carries driver detail. */
export class OutboxStoreError extends Error {
  readonly code: OutboxStoreErrorCode;

  constructor(code: OutboxStoreErrorCode) {
    super(OUTBOX_STORE_ERROR_MESSAGES[code]);
    this.name = 'OutboxStoreError';
    this.code = code;
  }
}

export interface OutboxQueryResult<T> {
  readonly rows: T[];
  readonly rowCount: number | null;
}

/** Narrow client port, structurally satisfied by `pg` PoolClient. */
export interface OutboxClient {
  query<T extends Record<string, unknown>>(
    text: string,
    values?: unknown[],
  ): Promise<OutboxQueryResult<T>>;
  release(destroy?: boolean): void;
}

export interface OutboxPool {
  connect(): Promise<OutboxClient>;
}

export type ClaimedOutboxEvent = {
  readonly eventId: string;
  readonly organizationId: string;
  readonly mutationId: string;
  readonly payloadVersion: 1;
  readonly leaseGeneration: string;
  readonly leaseUntil: string;
  readonly attemptCount: number;
} & (
  | { readonly resourceType: 'organization'; readonly resourceId: string; readonly eventType: 'tenant.organization.created' }
  | { readonly resourceType: 'agent'; readonly resourceId: string; readonly eventType: 'tenant.agent.created' | 'tenant.agent.updated' }
  | { readonly resourceType: 'provider'; readonly resourceId: string; readonly eventType: 'tenant.provider.created' | 'tenant.provider.updated' }
  | { readonly resourceType: 'membership'; readonly resourceId: string; readonly eventType: 'tenant.membership.set' }
  | { readonly resourceType: 'agent_credential'; readonly resourceId: string; readonly eventType: 'tenant.agent.credential.created' | 'tenant.agent.credential.revoked' }
  | { readonly resourceType: 'provider_credential'; readonly resourceId: string; readonly eventType: 'tenant.provider.credential.created' | 'tenant.provider.credential.revoked' }
  | { readonly resourceType: 'listing'; readonly resourceId: string; readonly eventType: 'market.listing.created' }
  | { readonly resourceType: 'listing_version'; readonly resourceId: string; readonly eventType: 'market.listing.version.created' | 'market.listing.origin_review.recorded' | 'market.listing.version.published' | 'market.listing.version.paused' | 'market.listing.version.retired' }
  | { readonly resourceType: 'budget_policy'; readonly resourceId: string; readonly eventType: 'control.policy.created' | 'control.policy.paused' | 'control.policy.resumed' | 'control.policy.revoked' }
  | { readonly resourceType: 'budget_policy_revision'; readonly resourceId: string; readonly eventType: 'control.policy.revision.created' }
  | { readonly resourceType: 'commerce_session'; readonly resourceId: string; readonly eventType: 'control.commerce_session.issued' | 'control.commerce_session.exchanged' | 'control.commerce_session.revoked' }
  | { readonly resourceType: 'commerce_action'; readonly resourceId: string; readonly eventType: 'control.commerce_action.authorized' | 'control.commerce_action.approved' | 'control.commerce_action.rejected' | 'control.commerce_action.cancelled' }
  | { readonly resourceType: 'authorization_grant'; readonly resourceId: string; readonly eventType: 'control.grant.issued' | 'control.grant.replaced' | 'control.grant.revoked' | 'control.grant.claimed' }
);

const ORG_ID = /^openarc:org:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const AGENT_ID = /^openarc:agent:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PROVIDER_ID = /^openarc:provider:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ACCOUNT_ID = /^openarc:account:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CREDENTIAL_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const LISTING_ID = /^openarc:listing:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
// Internal version resource: canonical listing id + '@' + canonical version >= 2
// (version 1 is the draft root). Length is bounded before any split/coercion.
const LISTING_VERSION_RESOURCE_MAX_LENGTH = 128;
const LISTING_VERSION_RESOURCE = /^openarc:listing:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}@(?!1$)[1-9][0-9]{0,8}$/;

function isListingVersionResource(value: string): boolean {
  return value.length <= LISTING_VERSION_RESOURCE_MAX_LENGTH && LISTING_VERSION_RESOURCE.test(value);
}

// Lifecycle resource: the same canonical listing id + '@' + version, but the
// version may be 1. `market.listing.version.created` is only emitted for a
// version >= 2 because creating version 1 is already reported by
// `market.listing.created`, so that event alone excludes `@1`. Origin review,
// publish, pause and retire all legitimately target a listing's FIRST version,
// so reusing the stricter pattern here would reject a real event and fail the
// whole claim batch closed.
const LISTING_VERSION_LIFECYCLE_RESOURCE =
  /^openarc:listing:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}@[1-9][0-9]{0,8}$(?![\s\S])/;

function isListingVersionLifecycleResource(value: string): boolean {
  return (
    value.length <= LISTING_VERSION_RESOURCE_MAX_LENGTH &&
    LISTING_VERSION_LIFECYCLE_RESOURCE.test(value)
  );
}

const POLICY_ID = /^openarc:policy:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const POLICY_REVISION_RESOURCE_MAX_LENGTH = 160;
const POLICY_REVISION_RESOURCE = /^openarc:policy:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}@(?!1$)[1-9][0-9]{0,8}$/;

function isPolicyRevisionResource(value: string): boolean {
  return value.length <= POLICY_REVISION_RESOURCE_MAX_LENGTH && POLICY_REVISION_RESOURCE.test(value);
}

const COMMERCE_SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const COMMERCE_ACTION_ID = /^openarc:action:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
// Mirrors openarc_durable.is_canonical_grant_id (schema12) with an absolute end.
const GRANT_ID = /^openarc:grant:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;

export interface ClaimInput {
  readonly limit?: number;
}

export type OutboxFailureCode =
  | 'dependency_unavailable'
  | 'invalid_event'
  | 'handler_failed';

export interface OutboxAckResult {
  readonly applied: boolean;
}

const DEFAULT_CLAIM_LIMIT = 10;
const MAX_CLAIM_LIMIT = 50;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const FAILURE_CODES: readonly OutboxFailureCode[] = [
  'dependency_unavailable',
  'invalid_event',
  'handler_failed',
];

function fail(code: OutboxStoreErrorCode): never {
  throw new OutboxStoreError(code);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireLimit(value: unknown): number {
  if (value === undefined) return DEFAULT_CLAIM_LIMIT;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1 || value > MAX_CLAIM_LIMIT) {
    fail('OUTBOX_STORE_INPUT_INVALID');
  }
  return value;
}

function requireEventId(value: unknown): string {
  if (typeof value !== 'string' || !UUID.test(value)) fail('OUTBOX_STORE_INPUT_INVALID');
  return value;
}

function requireLeaseGeneration(value: unknown): string {
  if (typeof value !== 'string' || value.length > 20 || !DECIMAL.test(value)) {
    fail('OUTBOX_STORE_INPUT_INVALID');
  }
  return value;
}

function requireFailureCode(value: unknown): OutboxFailureCode {
  if (typeof value !== 'string' || !FAILURE_CODES.includes(value as OutboxFailureCode)) {
    fail('OUTBOX_STORE_INPUT_INVALID');
  }
  return value as OutboxFailureCode;
}

function requireString(value: unknown): string {
  if (typeof value !== 'string') fail('OUTBOX_STORE_UNAVAILABLE');
  return value;
}

function requireDate(value: unknown): Date {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    fail('OUTBOX_STORE_UNAVAILABLE');
  }
  return value;
}

function requireCount(value: unknown): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > 5) {
    fail('OUTBOX_STORE_UNAVAILABLE');
  }
  return value;
}

function normalizeError(error: unknown): OutboxStoreError {
  if (error instanceof OutboxStoreError) return error;
  if (isRecord(error) && typeof error.code === 'string') {
    switch (error.code) {
      case '42501':
        return new OutboxStoreError('OUTBOX_STORE_FORBIDDEN');
      case '23503':
        return new OutboxStoreError('OUTBOX_STORE_NOT_FOUND');
      case '22023':
      case '22P02':
      case '22001':
      case '22003':
      case '23514':
        return new OutboxStoreError('OUTBOX_STORE_INPUT_INVALID');
      default:
        return new OutboxStoreError('OUTBOX_STORE_UNAVAILABLE');
    }
  }
  return new OutboxStoreError('OUTBOX_STORE_UNAVAILABLE');
}

/**
 * Outbox repository bound to a pool authenticated as the restricted worker role.
 */
export class OutboxStore {
  readonly #pool: OutboxPool;
  #initialized = false;

  constructor(pool: OutboxPool) {
    if (pool === null || typeof pool !== 'object' || typeof pool.connect !== 'function') {
      fail('OUTBOX_STORE_INPUT_INVALID');
    }
    this.#pool = pool;
  }

  /** Verify the exact bundled schema and restricted worker role once. */
  async initialize(): Promise<void> {
    if (this.#initialized) return;
    await this.#withTransaction(async (client) => {
      await this.#assertReady(client);
    });
    this.#initialized = true;
  }

  /** Read-only readiness re-check; safe to call repeatedly. */
  async readiness(): Promise<void> {
    await this.#withTransaction(async (client) => {
      await this.#assertReady(client);
    });
  }

  /** Claim up to `limit` opaque jobs with a fixed 30s lease, max 5 attempts. */
  async claim(input?: ClaimInput): Promise<ClaimedOutboxEvent[]> {
    const limit = requireLimit(input?.limit);
    return this.#withTransaction(async (client) => {
      const result = await client.query<{
        event_id: string;
        organization_id: string;
        mutation_id: string;
        resource_type: string;
        resource_id: string;
        event_type: string;
        payload_version: number;
        lease_generation: string;
        lease_until: Date;
        attempt_count: number;
      }>(`SELECT event_id, organization_id, mutation_id, resource_type, resource_id,
                 event_type, payload_version, lease_generation::text AS lease_generation,
                 lease_until, attempt_count
            FROM openarc_durable.claim_outbox_jobs($1)`, [limit]);
      return result.rows.map((row) => this.#projectClaim(row));
    });
  }

  /** Fenced completion. Stale/expired/completed/missing safely return false. */
  async complete(eventId: unknown, leaseGeneration: unknown): Promise<OutboxAckResult> {
    const id = requireEventId(eventId);
    const generation = requireLeaseGeneration(leaseGeneration);
    return this.#withTransaction(async (client) => {
      const result = await client.query<{ applied: boolean }>(
        'SELECT openarc_durable.complete_outbox_job($1::uuid, $2::bigint) AS applied',
        [id, generation],
      );
      return { applied: result.rows[0]?.applied === true };
    });
  }

  /** Fenced failure with a fixed failure-code vocabulary. */
  async fail(
    eventId: unknown,
    leaseGeneration: unknown,
    code: unknown,
  ): Promise<OutboxAckResult> {
    const id = requireEventId(eventId);
    const generation = requireLeaseGeneration(leaseGeneration);
    const failure = requireFailureCode(code);
    return this.#withTransaction(async (client) => {
      const result = await client.query<{ applied: boolean }>(
        'SELECT openarc_durable.fail_outbox_job($1::uuid, $2::bigint, $3) AS applied',
        [id, generation, failure],
      );
      return { applied: result.rows[0]?.applied === true };
    });
  }

  #projectClaim(row: {
    event_id: string;
    organization_id: string;
    mutation_id: string;
    resource_type: string;
    resource_id: string;
    event_type: string;
    payload_version: number;
    lease_generation: string;
    lease_until: Date;
    attempt_count: number;
  }): ClaimedOutboxEvent {
    if (row.payload_version !== 1) fail('OUTBOX_STORE_UNAVAILABLE');
    const generation = requireString(row.lease_generation);
    if (!DECIMAL.test(generation)) fail('OUTBOX_STORE_UNAVAILABLE');
    const base = {
      eventId: requireEventId(row.event_id),
      organizationId: requireString(row.organization_id),
      mutationId: requireEventId(row.mutation_id),
      payloadVersion: 1 as const,
      leaseGeneration: generation,
      leaseUntil: requireDate(row.lease_until).toISOString(),
      attemptCount: requireCount(row.attempt_count),
    };
    const resourceId = requireString(row.resource_id);
    const eventType = requireString(row.event_type);
    const key = `${row.resource_type}|${eventType}`;
    switch (key) {
      case 'organization|tenant.organization.created':
        if (!ORG_ID.test(resourceId)) fail('OUTBOX_STORE_UNAVAILABLE');
        return { ...base, resourceType: 'organization', resourceId, eventType: 'tenant.organization.created' };
      case 'agent|tenant.agent.created':
      case 'agent|tenant.agent.updated':
        if (!AGENT_ID.test(resourceId)) fail('OUTBOX_STORE_UNAVAILABLE');
        return {
          ...base,
          resourceType: 'agent',
          resourceId,
          eventType: eventType as 'tenant.agent.created' | 'tenant.agent.updated',
        };
      case 'provider|tenant.provider.created':
      case 'provider|tenant.provider.updated':
        if (!PROVIDER_ID.test(resourceId)) fail('OUTBOX_STORE_UNAVAILABLE');
        return {
          ...base,
          resourceType: 'provider',
          resourceId,
          eventType: eventType as 'tenant.provider.created' | 'tenant.provider.updated',
        };
      case 'membership|tenant.membership.set':
        if (!ACCOUNT_ID.test(resourceId)) fail('OUTBOX_STORE_UNAVAILABLE');
        return { ...base, resourceType: 'membership', resourceId, eventType: 'tenant.membership.set' };
      case 'agent_credential|tenant.agent.credential.created':
      case 'agent_credential|tenant.agent.credential.revoked':
        if (!CREDENTIAL_ID.test(resourceId)) fail('OUTBOX_STORE_UNAVAILABLE');
        return {
          ...base,
          resourceType: 'agent_credential',
          resourceId,
          eventType: eventType as 'tenant.agent.credential.created' | 'tenant.agent.credential.revoked',
        };
      case 'provider_credential|tenant.provider.credential.created':
      case 'provider_credential|tenant.provider.credential.revoked':
        if (!CREDENTIAL_ID.test(resourceId)) fail('OUTBOX_STORE_UNAVAILABLE');
        return {
          ...base,
          resourceType: 'provider_credential',
          resourceId,
          eventType: eventType as 'tenant.provider.credential.created' | 'tenant.provider.credential.revoked',
        };
      case 'listing|market.listing.created':
        if (!LISTING_ID.test(resourceId)) fail('OUTBOX_STORE_UNAVAILABLE');
        return { ...base, resourceType: 'listing', resourceId, eventType: 'market.listing.created' };
      case 'listing_version|market.listing.version.created':
        if (!isListingVersionResource(resourceId)) fail('OUTBOX_STORE_UNAVAILABLE');
        return { ...base, resourceType: 'listing_version', resourceId, eventType: 'market.listing.version.created' };
      case 'listing_version|market.listing.origin_review.recorded':
      case 'listing_version|market.listing.version.published':
      case 'listing_version|market.listing.version.paused':
      case 'listing_version|market.listing.version.retired':
        if (!isListingVersionLifecycleResource(resourceId)) fail('OUTBOX_STORE_UNAVAILABLE');
        return {
          ...base,
          resourceType: 'listing_version',
          resourceId,
          eventType: eventType as
            | 'market.listing.origin_review.recorded'
            | 'market.listing.version.published'
            | 'market.listing.version.paused'
            | 'market.listing.version.retired',
        };
      case 'budget_policy|control.policy.created':
      case 'budget_policy|control.policy.paused':
      case 'budget_policy|control.policy.resumed':
      case 'budget_policy|control.policy.revoked':
        if (!POLICY_ID.test(resourceId)) fail('OUTBOX_STORE_UNAVAILABLE');
        return {
          ...base,
          resourceType: 'budget_policy',
          resourceId,
          eventType: eventType as
            | 'control.policy.created'
            | 'control.policy.paused'
            | 'control.policy.resumed'
            | 'control.policy.revoked',
        };
      case 'budget_policy_revision|control.policy.revision.created':
        if (!isPolicyRevisionResource(resourceId)) fail('OUTBOX_STORE_UNAVAILABLE');
        return { ...base, resourceType: 'budget_policy_revision', resourceId, eventType: 'control.policy.revision.created' };
      case 'commerce_session|control.commerce_session.issued':
      case 'commerce_session|control.commerce_session.exchanged':
      case 'commerce_session|control.commerce_session.revoked':
        if (!COMMERCE_SESSION_ID.test(resourceId)) fail('OUTBOX_STORE_UNAVAILABLE');
        return {
          ...base,
          resourceType: 'commerce_session',
          resourceId,
          eventType: eventType as
            | 'control.commerce_session.issued'
            | 'control.commerce_session.exchanged'
            | 'control.commerce_session.revoked',
        };
      case 'commerce_action|control.commerce_action.authorized':
      case 'commerce_action|control.commerce_action.approved':
      case 'commerce_action|control.commerce_action.rejected':
      case 'commerce_action|control.commerce_action.cancelled':
        if (!COMMERCE_ACTION_ID.test(resourceId)) fail('OUTBOX_STORE_UNAVAILABLE');
        return {
          ...base,
          resourceType: 'commerce_action',
          resourceId,
          eventType: eventType as
            | 'control.commerce_action.authorized'
            | 'control.commerce_action.approved'
            | 'control.commerce_action.rejected'
            | 'control.commerce_action.cancelled',
        };
      case 'authorization_grant|control.grant.issued':
      case 'authorization_grant|control.grant.replaced':
      case 'authorization_grant|control.grant.revoked':
      case 'authorization_grant|control.grant.claimed':
        if (!GRANT_ID.test(resourceId)) fail('OUTBOX_STORE_UNAVAILABLE');
        return {
          ...base,
          resourceType: 'authorization_grant',
          resourceId,
          eventType: eventType as
            | 'control.grant.issued'
            | 'control.grant.replaced'
            | 'control.grant.revoked'
            | 'control.grant.claimed',
        };
      default:
        fail('OUTBOX_STORE_UNAVAILABLE');
    }
  }

  async #withTransaction<T>(work: (client: OutboxClient) => Promise<T>): Promise<T> {
    let client: OutboxClient;
    try {
      client = await this.#pool.connect();
    } catch {
      fail('OUTBOX_STORE_UNAVAILABLE');
    }
    try {
      await client.query('BEGIN');
    } catch {
      this.#release(client, true);
      fail('OUTBOX_STORE_UNAVAILABLE');
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
      fail('OUTBOX_STORE_OUTCOME_UNKNOWN');
    }
    this.#release(client, false);
    return result;
  }

  #release(client: OutboxClient, destroy: boolean): void {
    try {
      client.release(destroy);
    } catch {
      // A release failure after a confirmed outcome cannot change that outcome.
    }
  }

  /**
   * Read-only role/schema readiness. The worker must be the exact restricted
   * role, transitively an elevated role member, and own no durable object. It
   * must not be the tenant runtime and must be able to execute only the three
   * narrow helpers.
   */
  async #assertReady(client: OutboxClient): Promise<void> {
    const roleResult = await client.query<{
      role: string;
      rolsuper: boolean;
      rolbypassrls: boolean;
      rolcreatedb: boolean;
      rolcreaterole: boolean;
      elevated_memberships: number;
      migrator_member: boolean;
      tenant_member: boolean;
      auth_member: boolean;
    }>(
      `SELECT current_user AS role,
              r.rolsuper, r.rolbypassrls, r.rolcreatedb, r.rolcreaterole,
              (SELECT count(*)::int
                 FROM pg_roles g
                WHERE (g.rolsuper OR g.rolbypassrls OR g.rolcreatedb OR g.rolcreaterole)
                  AND pg_has_role(current_user, g.oid, 'MEMBER')) AS elevated_memberships,
              pg_has_role(current_user, 'openarc_migrator', 'MEMBER') AS migrator_member,
              pg_has_role(current_user, 'openarc_tenant_app', 'MEMBER') AS tenant_member,
              pg_has_role(current_user, 'openarc_auth_app', 'MEMBER') AS auth_member
         FROM pg_roles r
        WHERE r.rolname = current_user`,
    );
    const role = roleResult.rows[0];
    if (role === undefined) fail('OUTBOX_STORE_UNAVAILABLE');
    const ready =
      role.role === 'openarc_worker_app' &&
      role.rolsuper === false &&
      role.rolbypassrls === false &&
      role.rolcreatedb === false &&
      role.rolcreaterole === false &&
      role.elevated_memberships === 0 &&
      role.migrator_member === false &&
      role.tenant_member === false &&
      role.auth_member === false;
    if (!ready) fail('OUTBOX_STORE_UNAVAILABLE');

    const schemaOwner = await client.query<{ owner: string }>(
      `SELECT pg_get_userbyid(nspowner) AS owner
         FROM pg_namespace WHERE nspname = 'openarc_durable'`,
    );
    if (schemaOwner.rows[0]?.owner === role.role) fail('OUTBOX_STORE_UNAVAILABLE');

    const tables = await client.query<{ n: number; all_enabled: boolean; all_forced: boolean }>(
      `SELECT count(*)::int AS n,
              bool_and(c.relrowsecurity) AS all_enabled,
              bool_and(c.relforcerowsecurity) AS all_forced
         FROM pg_class c
         JOIN pg_namespace ns ON ns.oid = c.relnamespace
        WHERE ns.nspname = 'openarc_durable'
          AND c.relkind = 'r'
          AND c.relname IN ('idempotency_records', 'audit_events', 'outbox_events')`,
    );
    const tableState = tables.rows[0];
    if (
      tableState === undefined ||
      tableState.n !== 3 ||
      tableState.all_enabled !== true ||
      tableState.all_forced !== true
    ) {
      fail('OUTBOX_STORE_UNAVAILABLE');
    }

    // The worker owns no protected object. Check every protected schema, not
    // only the durable one.
    const owned = await client.query<{ n: number }>(
      `SELECT count(*)::int AS n
         FROM pg_class c
         JOIN pg_namespace ns ON ns.oid = c.relnamespace
        WHERE ns.nspname IN ('openarc_auth', 'openarc_tenant', 'openarc_durable')
          AND pg_get_userbyid(c.relowner) = current_user`,
    );
    if ((owned.rows[0]?.n ?? 0) !== 0) fail('OUTBOX_STORE_UNAVAILABLE');

    // Effective prohibited access: evaluate real privileges (not just direct
    // ACL rows) for the worker AND every role it can reach via membership. This
    // catches SELECT/INSERT/... granted on auth/tenant/durable relations, on
    // individual columns, on sequences, or schema CREATE, including grants
    // relayed through an ordinary intermediary role. The only allowed auth of
    // this kind is USAGE on the durable schema and the metadata SELECT on
    // openarc_meta.schema_migrations, neither of which this query flags.
    const access = await client.query<{
      table_access: number;
      sequence_access: number;
      schema_create: number;
    }>(
      `WITH reachable AS (
         SELECT r.oid
           FROM pg_roles r
          WHERE r.oid = (SELECT oid FROM pg_roles WHERE rolname = current_user)
             OR pg_has_role(current_user, r.oid, 'MEMBER')
       )
       SELECT
         (SELECT count(*)::int
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname IN ('openarc_auth', 'openarc_tenant', 'openarc_durable')
             AND c.relkind IN ('r', 'v', 'm', 'p', 'f')
             AND EXISTS (
               SELECT 1 FROM reachable x
                WHERE has_table_privilege(
                        x.oid, c.oid,
                        'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                   OR has_any_column_privilege(
                        x.oid, c.oid, 'SELECT,INSERT,UPDATE,REFERENCES')
             )) AS table_access,
         (SELECT count(*)::int
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname IN ('openarc_auth', 'openarc_tenant', 'openarc_durable')
             AND c.relkind = 'S'
             AND EXISTS (
               SELECT 1 FROM reachable x
                WHERE has_sequence_privilege(x.oid, c.oid, 'USAGE,SELECT,UPDATE')
             )) AS sequence_access,
         (SELECT count(*)::int
            FROM pg_namespace n
           WHERE n.nspname IN ('openarc_auth', 'openarc_tenant', 'openarc_durable')
             AND EXISTS (
               SELECT 1 FROM reachable x
                WHERE has_schema_privilege(x.oid, n.oid, 'CREATE')
             )) AS schema_create`,
    );
    const accessState = access.rows[0];
    if (
      accessState === undefined ||
      accessState.table_access !== 0 ||
      accessState.sequence_access !== 0 ||
      accessState.schema_create !== 0
    ) {
      fail('OUTBOX_STORE_UNAVAILABLE');
    }

    // The three helpers must be exactly the reviewed SECURITY DEFINER functions
    // owned by the migrator with a fixed pg_catalog search_path, zero PUBLIC
    // EXECUTE and an EXECUTE grant to this worker role. An overload or a
    // different owner/definer/search_path shape must fail readiness.
    const EXPECTED_HELPERS: readonly {
      readonly name: string;
      readonly args: string;
    }[] = [
      { name: 'claim_outbox_jobs', args: 'claim_limit integer' },
      { name: 'complete_outbox_job', args: 'target_event_id uuid, expected_generation bigint' },
      { name: 'fail_outbox_job', args: 'target_event_id uuid, expected_generation bigint, failure_code text' },
    ];
    const helpers = await client.query<{
      proname: string;
      args: string;
      owner: string;
      prosecdef: boolean;
      config: string[];
      app_exec: boolean;
      public_grants: number;
    }>(
      `SELECT p.proname,
              pg_get_function_identity_arguments(p.oid) AS args,
              r.rolname AS owner,
              p.prosecdef,
              coalesce(p.proconfig, ARRAY[]::text[]) AS config,
              has_function_privilege(current_user, p.oid, 'EXECUTE') AS app_exec,
              (SELECT count(*)::int
                 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE') AS public_grants
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         JOIN pg_roles r ON r.oid = p.proowner
        WHERE n.nspname = 'openarc_durable'
          AND p.prokind = 'f'
          AND p.proname IN ('claim_outbox_jobs', 'complete_outbox_job', 'fail_outbox_job')
        ORDER BY p.proname, p.oid`,
    );
    if (helpers.rows.length !== EXPECTED_HELPERS.length) fail('OUTBOX_STORE_UNAVAILABLE');
    for (let index = 0; index < EXPECTED_HELPERS.length; index += 1) {
      const expected = EXPECTED_HELPERS[index];
      const row = helpers.rows[index];
      if (expected === undefined || row === undefined) fail('OUTBOX_STORE_UNAVAILABLE');
      if (row.proname !== expected.name || row.args !== expected.args) {
        fail('OUTBOX_STORE_UNAVAILABLE');
      }
      if (
        row.owner !== 'openarc_migrator' ||
        row.prosecdef !== true ||
        !row.config.includes('search_path=pg_catalog') ||
        row.app_exec !== true ||
        row.public_grants !== 0
      ) {
        fail('OUTBOX_STORE_UNAVAILABLE');
      }
    }

    const applied = await client.query<{ id: string; checksum: string }>(
      `SELECT id, checksum
         FROM openarc_meta.schema_migrations
        ORDER BY id`,
    );
    this.#assertExactManifest(applied.rows);
  }

  #assertExactManifest(
    applied: readonly { readonly id: string; readonly checksum: string }[],
  ): void {
    let migrations: readonly { readonly id: string; readonly sql: string }[];
    try {
      migrations = loadMigrations();
    } catch {
      fail('OUTBOX_STORE_UNAVAILABLE');
    }
    if (applied.length !== migrations.length) fail('OUTBOX_STORE_UNAVAILABLE');
    for (let index = 0; index < applied.length; index += 1) {
      const record = applied[index];
      const manifest = migrations[index];
      if (record === undefined || manifest === undefined) fail('OUTBOX_STORE_UNAVAILABLE');
      if (record.id !== manifest.id) fail('OUTBOX_STORE_UNAVAILABLE');
      const checksum = createHash('sha256').update(manifest.sql, 'utf8').digest('hex');
      if (record.checksum !== checksum) fail('OUTBOX_STORE_UNAVAILABLE');
    }
  }
}

/** Structural adapter for callers that hold a raw `pg` Pool. */
export function asOutboxPool(pool: Pool): OutboxPool {
  return pool as unknown as OutboxPool;
}

export type { PoolClient };
