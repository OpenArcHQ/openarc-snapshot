import { createHash } from 'node:crypto';
import type { Pool } from 'pg';
import { loadMigrations } from './migrate.js';
import type { OutboxClient, OutboxPool } from './outbox-store.js';

/**
 * SettlementObservationStore: the schema17 worker-role half of post-dispatch
 * settlement observation.
 *
 * It is bound to a pool authenticated as `openarc_worker_app`, the ONLY
 * principal the schema grants the observation recorder to. Batched settlement
 * can land up to ~7 days after dispatch, after the buyer's commerce session,
 * handoff token and grant have all expired, so no request-serving path can
 * still be authenticated when the answer arrives; every other durable attempt
 * entry point derives its organization from a live commerce token.
 *
 * Guarantees, all enforced in SQL and re-asserted here:
 *   * only attempts in state `unknown` or `pending` are ever leasable: a
 *     `persisted` (never dispatched) or `committed` (terminal) attempt cannot
 *     be selected by any method below;
 *   * a lease is exclusive and bounded, so two workers never observe the same
 *     attempt concurrently and an unanswerable attempt is retried a bounded
 *     number of times and then simply left held;
 *   * only a POSITIVE observation can be recorded: the state input is the
 *     closed union `'pending' | 'committed'`. There is no release, failure,
 *     refund, expiry or cancellation input anywhere in this store, and an
 *     unclear answer is recorded as nothing at all -- `unknown` is already the
 *     held state;
 *   * the worker holds no table privilege: every method runs through a narrow
 *     SECURITY DEFINER helper.
 *
 * Every method runs one statement inside one transaction and makes no external
 * call. A lost COMMIT reply is OUTCOME_UNKNOWN.
 */

export const SETTLEMENT_OBSERVATION_STORE_ERROR_MESSAGES = {
  SETTLEMENT_OBSERVATION_STORE_INPUT_INVALID: 'SettlementObservationStore input is invalid.',
  SETTLEMENT_OBSERVATION_STORE_FORBIDDEN: 'SettlementObservationStore caller is not permitted.',
  SETTLEMENT_OBSERVATION_STORE_NOT_FOUND: 'SettlementObservationStore target was not found.',
  SETTLEMENT_OBSERVATION_STORE_ATTEMPT_CONFLICT:
    'SettlementObservationStore attempt is not in a state that permits this operation.',
  SETTLEMENT_OBSERVATION_STORE_UNAVAILABLE: 'SettlementObservationStore is not available.',
  SETTLEMENT_OBSERVATION_STORE_OUTCOME_UNKNOWN:
    'SettlementObservationStore mutation outcome could not be confirmed; it may have committed.',
} as const;

export type SettlementObservationStoreErrorCode =
  keyof typeof SETTLEMENT_OBSERVATION_STORE_ERROR_MESSAGES;

/** Fixed, non-echoing repository error. Never carries driver or input detail. */
export class SettlementObservationStoreError extends Error {
  readonly code: SettlementObservationStoreErrorCode;

  constructor(code: SettlementObservationStoreErrorCode) {
    super(SETTLEMENT_OBSERVATION_STORE_ERROR_MESSAGES[code]);
    this.name = 'SettlementObservationStoreError';
    this.code = code;
  }
}

/** The only attempt states an observation lease may ever cover. */
export const OBSERVABLE_ATTEMPT_STATES = ['unknown', 'pending'] as const;
export type ObservableAttemptState = (typeof OBSERVABLE_ATTEMPT_STATES)[number];

/**
 * The only observations that may ever be recorded. There is deliberately no
 * released, failed, refunded, expired or cancelled member: a settle answer
 * that is anything other than a positive Gateway record proves nothing, so it
 * is never written at all.
 */
export const RECORDABLE_OBSERVATION_STATES = ['pending', 'committed'] as const;
export type RecordableObservationState = (typeof RECORDABLE_OBSERVATION_STATES)[number];

/** States that would release held exposure. None may ever be recordable. */
export type ObservationForbiddenReleaseState =
  | 'released'
  | 'released_unsent'
  | 'failed'
  | 'rejected'
  | 'expired'
  | 'cancelled'
  | 'refunded'
  | 'not_paid'
  | 'nonpayment';

type IsNever<T> = [T] extends [never] ? true : false;
export type ObservationAdmitsNoRelease = IsNever<
  Extract<RecordableObservationState | ObservableAttemptState, ObservationForbiddenReleaseState>
>;
/** Compile-time proof: adding a release state to either union breaks the build here. */
export const OBSERVATION_ADMITS_NO_RELEASE: ObservationAdmitsNoRelease = true;

export type ObservationGatewayStatus = 'received' | 'batched' | 'confirmed' | 'completed';

/** One leased attempt, with exactly the non-secret fields an observer needs. */
export interface LeasedPaymentAttempt {
  readonly organizationId: string;
  readonly attemptId: string;
  readonly grantId: string;
  readonly actionId: string;
  readonly requirementDigest: string;
  readonly laneRequirementDigest: string;
  readonly networkId: string;
  readonly assetAddress: string;
  readonly verifyingContract: string;
  readonly payerAddress: string;
  readonly payToAddress: string;
  readonly valueAtomic: string;
  readonly validAfter: string;
  readonly validBefore: string;
  readonly nonce: string;
  readonly state: ObservableAttemptState;
  readonly dispatchedAt: string;
  readonly leaseGeneration: string;
  readonly leaseUntil: string;
  readonly attemptCount: number;
}

export interface RecordObservationInput {
  readonly organizationId: string;
  readonly attemptId: string;
  readonly leaseGeneration: string;
  readonly state: RecordableObservationState;
  readonly transferId: string;
  readonly gatewayStatus: ObservationGatewayStatus;
  readonly batchTxHash: string | null;
}

export interface RecordedObservation {
  readonly organizationId: string;
  readonly attemptId: string;
  readonly state: RecordableObservationState;
  readonly dispatchedAt: string;
  readonly observedAt: string;
  readonly transferId: string;
  readonly gatewayStatus: ObservationGatewayStatus;
  readonly batchTxHash: string | null;
}

export interface ClaimObservationsInput {
  readonly limit?: number;
}

export interface ReleaseLeaseResult {
  readonly released: boolean;
}

const DEFAULT_CLAIM_LIMIT = 5;
const MAX_CLAIM_LIMIT = 25;
/** Mirrors the schema17 retry ceiling exactly. */
export const MAX_OBSERVATION_ATTEMPTS = 10;

const ORG_ID = /^openarc:org:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const GRANT_ID = /^openarc:grant:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const ACTION_ID = /^openarc:action:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$(?![\s\S])/;
const UINT256 = /^(0|[1-9][0-9]{0,77})$(?![\s\S])/;
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$(?![\s\S])/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$(?![\s\S])/;
const BYTES32 = /^0x[0-9a-f]{64}$(?![\s\S])/;
const DECIMAL = /^(0|[1-9][0-9]*)$(?![\s\S])/;

const NETWORK_ID = 'eip155:5042002';
const ASSET_ADDRESS = '0x3600000000000000000000000000000000000000';
const VERIFYING_CONTRACT = '0x0077777d7EBA4688BDeF3E311b846F25870A19B9';

function fail(code: SettlementObservationStoreErrorCode): never {
  throw new SettlementObservationStoreError(code);
}

function failInput(): never {
  fail('SETTLEMENT_OBSERVATION_STORE_INPUT_INVALID');
}

function failOutput(): never {
  fail('SETTLEMENT_OBSERVATION_STORE_UNAVAILABLE');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireShape(value: unknown, allowed: readonly string[]): Record<string, unknown> {
  if (!isRecord(value)) failInput();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) failInput();
  const keys = Object.keys(value);
  if (keys.length !== allowed.length) failInput();
  for (const key of keys) {
    if (!allowed.includes(key)) failInput();
    if (value[key] === undefined) failInput();
  }
  return value;
}

function requirePattern(value: unknown, pattern: RegExp): string {
  if (typeof value !== 'string' || !pattern.test(value)) failInput();
  return value;
}

function requireLimit(value: unknown): number {
  if (value === undefined) return DEFAULT_CLAIM_LIMIT;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1 || value > MAX_CLAIM_LIMIT) {
    failInput();
  }
  return value;
}

function requireLeaseGeneration(value: unknown): string {
  const text = requirePattern(value, DECIMAL);
  if (text.length > 20 || text === '0') failInput();
  return text;
}

function normalizeError(error: unknown): SettlementObservationStoreError {
  if (error instanceof SettlementObservationStoreError) return error;
  if (isRecord(error) && typeof error.code === 'string') {
    switch (error.code) {
      case '42501':
        return new SettlementObservationStoreError('SETTLEMENT_OBSERVATION_STORE_FORBIDDEN');
      case '23503':
        return new SettlementObservationStoreError('SETTLEMENT_OBSERVATION_STORE_NOT_FOUND');
      case 'P0D14':
        return new SettlementObservationStoreError('SETTLEMENT_OBSERVATION_STORE_ATTEMPT_CONFLICT');
      case '22023':
      case '22P02':
      case '22001':
      case '22003':
      case '23514':
        return new SettlementObservationStoreError('SETTLEMENT_OBSERVATION_STORE_INPUT_INVALID');
      default:
        return new SettlementObservationStoreError('SETTLEMENT_OBSERVATION_STORE_UNAVAILABLE');
    }
  }
  return new SettlementObservationStoreError('SETTLEMENT_OBSERVATION_STORE_UNAVAILABLE');
}

function requireDate(value: unknown): string {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) failOutput();
  return value.toISOString();
}

const CLAIM_COLUMNS = `out_organization_id, out_attempt_id::text AS out_attempt_id, out_grant_id,
        out_action_id, out_requirement_digest, out_lane_requirement_digest, out_network_id,
        out_asset_address, out_verifying_contract, out_payer_address, out_pay_to_address,
        out_value_atomic, out_valid_after, out_valid_before, out_nonce, out_state,
        out_dispatched_at, out_lease_generation::text AS out_lease_generation,
        out_lease_until, out_attempt_count`;

const RECORD_COLUMNS = `out_organization_id, out_attempt_id::text AS out_attempt_id, out_state,
        out_dispatched_at, out_observed_at, out_transfer_id::text AS out_transfer_id,
        out_gateway_status, out_batch_tx_hash`;

export class SettlementObservationStore {
  readonly #pool: OutboxPool;
  #initialized = false;

  constructor(pool: OutboxPool) {
    if (pool === null || typeof pool !== 'object' || typeof pool.connect !== 'function') {
      failInput();
    }
    this.#pool = pool;
  }

  async initialize(): Promise<void> {
    if (this.#initialized) return;
    await this.#withTransaction(async (client) => {
      await this.#assertReady(client);
    });
    this.#initialized = true;
  }

  async readiness(): Promise<void> {
    await this.#withTransaction(async (client) => {
      await this.#assertReady(client);
    });
  }

  /**
   * Lease up to `limit` attempts that still need observation, oldest dispatch
   * first. Only `unknown` and `pending` attempts are ever returned.
   */
  async claim(input?: ClaimObservationsInput): Promise<LeasedPaymentAttempt[]> {
    const limit = requireLimit(input?.limit);
    return this.#withTransaction(async (client) => {
      const result = await client.query<Record<string, unknown>>(
        `SELECT ${CLAIM_COLUMNS}
           FROM openarc_durable.claim_payment_attempt_observations($1)`,
        [limit],
      );
      if (result.rows.length > limit) failOutput();
      return result.rows.map((row) => this.#projectLease(row));
    });
  }

  /**
   * Record one POSITIVE observation under the exact lease generation claimed.
   * A stale, expired or missing lease records nothing and returns null.
   */
  async recordObservation(input: unknown): Promise<RecordedObservation | null> {
    const shape = requireShape(input, [
      'organizationId', 'attemptId', 'leaseGeneration', 'state', 'transferId',
      'gatewayStatus', 'batchTxHash',
    ]);
    const organizationId = requirePattern(shape['organizationId'], ORG_ID);
    const attemptId = requirePattern(shape['attemptId'], UUID_V4);
    const leaseGeneration = requireLeaseGeneration(shape['leaseGeneration']);
    const state = shape['state'];
    if (state !== 'pending' && state !== 'committed') failInput();
    const transferId = requirePattern(shape['transferId'], UUID);
    const gatewayStatus = shape['gatewayStatus'];
    const batchTxHash = shape['batchTxHash'];
    // The closed positive shape, re-asserted before any statement runs.
    if (state === 'committed') {
      if (gatewayStatus !== 'completed') failInput();
      if (typeof batchTxHash !== 'string' || !BYTES32.test(batchTxHash)) failInput();
    } else {
      if (gatewayStatus !== 'received' && gatewayStatus !== 'batched' && gatewayStatus !== 'confirmed') {
        failInput();
      }
      if (batchTxHash !== null && (typeof batchTxHash !== 'string' || !BYTES32.test(batchTxHash))) {
        failInput();
      }
    }
    return this.#withTransaction(async (client) => {
      const result = await client.query<Record<string, unknown>>(
        `SELECT ${RECORD_COLUMNS}
           FROM openarc_durable.record_leased_payment_attempt_observation(
             $1, $2::uuid, $3::bigint, $4, $5::uuid, $6, $7)`,
        [organizationId, attemptId, leaseGeneration, state, transferId, gatewayStatus, batchTxHash],
      );
      if (result.rows.length > 1) failOutput();
      const row = result.rows[0];
      if (row === undefined) return null;
      const recorded = this.#projectRecorded(row);
      if (
        recorded.organizationId !== organizationId ||
        recorded.attemptId !== attemptId ||
        recorded.state !== state ||
        recorded.transferId !== transferId
      ) {
        failOutput();
      }
      return recorded;
    });
  }

  /**
   * End a lease early after an UNCLEAR answer. It writes nothing to the
   * attempt: the attempt keeps its exact state and stays held. The bounded
   * retry counter is never rewound.
   */
  async releaseLease(
    organizationId: unknown,
    attemptId: unknown,
    leaseGeneration: unknown,
  ): Promise<ReleaseLeaseResult> {
    const organization = requirePattern(organizationId, ORG_ID);
    const attempt = requirePattern(attemptId, UUID_V4);
    const generation = requireLeaseGeneration(leaseGeneration);
    return this.#withTransaction(async (client) => {
      const result = await client.query<{ released: boolean }>(
        `SELECT openarc_durable.release_payment_attempt_observation_lease(
           $1, $2::uuid, $3::bigint) AS released`,
        [organization, attempt, generation],
      );
      return { released: result.rows[0]?.released === true };
    });
  }

  #projectLease(row: Record<string, unknown>): LeasedPaymentAttempt {
    const text = (key: string, pattern: RegExp): string => {
      const value = row[key];
      if (typeof value !== 'string' || !pattern.test(value)) failOutput();
      return value;
    };
    const state = row['out_state'];
    // A claim that ever surfaced a persisted or committed attempt is a broken
    // database, not a recoverable row.
    if (state !== 'unknown' && state !== 'pending') failOutput();
    if (
      row['out_network_id'] !== NETWORK_ID ||
      row['out_asset_address'] !== ASSET_ADDRESS ||
      row['out_verifying_contract'] !== VERIFYING_CONTRACT
    ) {
      failOutput();
    }
    const attemptCount = row['out_attempt_count'];
    if (
      typeof attemptCount !== 'number' ||
      !Number.isInteger(attemptCount) ||
      attemptCount < 1 ||
      attemptCount > MAX_OBSERVATION_ATTEMPTS
    ) {
      failOutput();
    }
    const generation = text('out_lease_generation', DECIMAL);
    if (generation === '0' || generation.length > 20) failOutput();
    return {
      organizationId: text('out_organization_id', ORG_ID),
      attemptId: text('out_attempt_id', UUID_V4),
      grantId: text('out_grant_id', GRANT_ID),
      actionId: text('out_action_id', ACTION_ID),
      requirementDigest: text('out_requirement_digest', SHA256_DIGEST),
      laneRequirementDigest: text('out_lane_requirement_digest', SHA256_DIGEST),
      networkId: NETWORK_ID,
      assetAddress: ASSET_ADDRESS,
      verifyingContract: VERIFYING_CONTRACT,
      payerAddress: text('out_payer_address', ADDRESS),
      payToAddress: text('out_pay_to_address', ADDRESS),
      valueAtomic: text('out_value_atomic', UINT256),
      validAfter: text('out_valid_after', UINT256),
      validBefore: text('out_valid_before', UINT256),
      nonce: text('out_nonce', BYTES32),
      state,
      dispatchedAt: requireDate(row['out_dispatched_at']),
      leaseGeneration: generation,
      leaseUntil: requireDate(row['out_lease_until']),
      attemptCount,
    };
  }

  #projectRecorded(row: Record<string, unknown>): RecordedObservation {
    const state = row['out_state'];
    if (state !== 'pending' && state !== 'committed') failOutput();
    const gatewayStatus = row['out_gateway_status'];
    const batchTxHash = row['out_batch_tx_hash'];
    if (state === 'committed') {
      if (gatewayStatus !== 'completed') failOutput();
      if (typeof batchTxHash !== 'string' || !BYTES32.test(batchTxHash)) failOutput();
    } else if (
      gatewayStatus !== 'received' && gatewayStatus !== 'batched' && gatewayStatus !== 'confirmed'
    ) {
      failOutput();
    }
    if (batchTxHash !== null && (typeof batchTxHash !== 'string' || !BYTES32.test(batchTxHash))) {
      failOutput();
    }
    const organizationId = row['out_organization_id'];
    const attemptId = row['out_attempt_id'];
    const transferId = row['out_transfer_id'];
    if (typeof organizationId !== 'string' || !ORG_ID.test(organizationId)) failOutput();
    if (typeof attemptId !== 'string' || !UUID_V4.test(attemptId)) failOutput();
    if (typeof transferId !== 'string' || !UUID.test(transferId)) failOutput();
    return {
      organizationId,
      attemptId,
      state,
      dispatchedAt: requireDate(row['out_dispatched_at']),
      observedAt: requireDate(row['out_observed_at']),
      transferId,
      gatewayStatus: gatewayStatus as ObservationGatewayStatus,
      batchTxHash: batchTxHash as string | null,
    };
  }

  async #withTransaction<T>(work: (client: OutboxClient) => Promise<T>): Promise<T> {
    let client: OutboxClient;
    try {
      client = await this.#pool.connect();
    } catch {
      fail('SETTLEMENT_OBSERVATION_STORE_UNAVAILABLE');
    }
    try {
      await client.query('BEGIN');
    } catch {
      this.#release(client, true);
      fail('SETTLEMENT_OBSERVATION_STORE_UNAVAILABLE');
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
      fail('SETTLEMENT_OBSERVATION_STORE_OUTCOME_UNKNOWN');
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
   * Read-only role/schema readiness. The caller must be the exact restricted
   * worker role, own nothing, hold no table privilege on the attempt or lease
   * tables, and be able to execute exactly the schema17 observation surface
   * plus the schema15 recorder -- which must NOT be reachable by the tenant
   * runtime.
   */
  async #assertReady(client: OutboxClient): Promise<void> {
    const roleResult = await client.query<{
      role: string;
      rolsuper: boolean;
      rolbypassrls: boolean;
      elevated_memberships: number;
      migrator_member: boolean;
      tenant_member: boolean;
      auth_member: boolean;
    }>(
      `SELECT current_user AS role, r.rolsuper, r.rolbypassrls,
              (SELECT count(*)::int FROM pg_roles g
                WHERE (g.rolsuper OR g.rolbypassrls OR g.rolcreatedb OR g.rolcreaterole)
                  AND pg_has_role(current_user, g.oid, 'MEMBER')) AS elevated_memberships,
              pg_has_role(current_user, 'openarc_migrator', 'MEMBER') AS migrator_member,
              pg_has_role(current_user, 'openarc_tenant_app', 'MEMBER') AS tenant_member,
              pg_has_role(current_user, 'openarc_auth_app', 'MEMBER') AS auth_member
         FROM pg_roles r WHERE r.rolname = current_user`,
    );
    const role = roleResult.rows[0];
    if (
      role === undefined ||
      role.role !== 'openarc_worker_app' ||
      role.rolsuper !== false ||
      role.rolbypassrls !== false ||
      role.elevated_memberships !== 0 ||
      role.migrator_member !== false ||
      role.tenant_member !== false ||
      role.auth_member !== false
    ) {
      fail('SETTLEMENT_OBSERVATION_STORE_UNAVAILABLE');
    }

    const EXPECTED_TABLES = [
      'openarc_durable.payment_attempts',
      'openarc_durable.payment_attempt_observation_leases',
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
        WHERE c.relkind = 'r' AND ns.nspname || '.' || c.relname = ANY ($1::text[])`,
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
      fail('SETTLEMENT_OBSERVATION_STORE_UNAVAILABLE');
    }

    // The worker reaches both tables ONLY through definer helpers: it must hold
    // no table privilege, directly or through any role it can reach.
    const access = await client.query<{ n: number }>(
      `WITH reachable AS (
         SELECT r.oid FROM pg_roles r
          WHERE r.oid = (SELECT oid FROM pg_roles WHERE rolname = current_user)
             OR pg_has_role(current_user, r.oid, 'MEMBER')
       )
       SELECT count(*)::int AS n
         FROM pg_class c
         JOIN pg_namespace ns ON ns.oid = c.relnamespace
        WHERE c.relkind = 'r' AND ns.nspname || '.' || c.relname = ANY ($1::text[])
          AND EXISTS (
            SELECT 1 FROM reachable x
             WHERE has_table_privilege(x.oid, c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                OR has_any_column_privilege(x.oid, c.oid, 'SELECT,INSERT,UPDATE,REFERENCES'))`,
      [EXPECTED_TABLES],
    );
    if ((access.rows[0]?.n ?? -1) !== 0) fail('SETTLEMENT_OBSERVATION_STORE_UNAVAILABLE');

    await this.#assertHelpers(client);
    await this.#assertTriggers(client);
    await this.#assertMigrations(client);
  }

  async #assertHelpers(client: OutboxClient): Promise<void> {
    // Every schema17 function plus the schema15 recorder this packet grants,
    // with its exact identity signature, owner, SECURITY DEFINER flag, pinned
    // search_path, no PUBLIC grant, the exact worker EXECUTE expectation and
    // the exact tenant-runtime EXECUTE expectation. `worker:true, app:false` is
    // the whole point of the packet: the observation surface is the worker's
    // and nobody else's.
    interface Expected {
      readonly name: string;
      readonly args: string;
      readonly secdef: boolean;
      readonly worker: boolean;
      readonly app: boolean;
    }
    const expected: readonly Expected[] = [
      {
        name: 'claim_payment_attempt_observations',
        args: 'claim_limit integer',
        secdef: true, worker: true, app: false,
      },
      {
        name: 'record_leased_payment_attempt_observation',
        args: 'organization_id_input text, attempt_id_input uuid, lease_generation_input bigint, observed_state text, transfer_id_input uuid, gateway_status_input text, batch_tx_hash_input text',
        secdef: true, worker: true, app: false,
      },
      {
        name: 'release_payment_attempt_observation_lease',
        args: 'organization_id_input text, attempt_id_input uuid, lease_generation_input bigint',
        secdef: true, worker: true, app: false,
      },
      {
        name: 'record_payment_attempt_observation',
        args: 'organization_id text, attempt_id_input uuid, observed_state text, transfer_id_input uuid, gateway_status_input text, batch_tx_hash_input text',
        secdef: true, worker: true, app: false,
      },
      {
        name: 'enforce_observation_lease_mutation',
        args: '',
        secdef: false, worker: false, app: false,
      },
    ];
    const rows = await client.query<{
      proname: string;
      args: string;
      owner: string;
      secdef: boolean;
      config: string[];
      worker_exec: boolean;
      app_exec: boolean;
      public_grants: number;
      source: string;
    }>(
      `SELECT p.proname, pg_get_function_identity_arguments(p.oid) AS args,
              r.rolname AS owner, p.prosecdef AS secdef,
              coalesce(p.proconfig, ARRAY[]::text[]) AS config,
              has_function_privilege('openarc_worker_app', p.oid, 'EXECUTE') AS worker_exec,
              has_function_privilege('openarc_tenant_app', p.oid, 'EXECUTE') AS app_exec,
              (SELECT count(*)::int FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE') AS public_grants,
              p.prosrc AS source
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         JOIN pg_roles r ON r.oid = p.proowner
        WHERE n.nspname = 'openarc_durable' AND p.proname = ANY ($1::text[])`,
      [expected.map((entry) => entry.name)],
    );
    // Exactly one overload per inventoried name: a second signature (for
    // example one accepting a caller-chosen state) is a readiness failure.
    if (rows.rows.length !== expected.length) fail('SETTLEMENT_OBSERVATION_STORE_UNAVAILABLE');
    const byName = new Map(rows.rows.map((row) => [`${row.proname}(${row.args})`, row]));
    if (byName.size !== expected.length) fail('SETTLEMENT_OBSERVATION_STORE_UNAVAILABLE');
    for (const entry of expected) {
      const row = byName.get(`${entry.name}(${entry.args})`);
      if (
        row === undefined ||
        row.owner !== 'openarc_migrator' ||
        row.secdef !== entry.secdef ||
        !row.config.includes('search_path=pg_catalog') ||
        row.public_grants !== 0 ||
        row.worker_exec !== entry.worker ||
        row.app_exec !== entry.app
      ) {
        fail('SETTLEMENT_OBSERVATION_STORE_UNAVAILABLE');
      }
    }
    // The claim surface may select ONLY unknown and pending attempts, and the
    // fenced recorder must still delegate to the unchanged schema15 recorder.
    const claim = byName.get('claim_payment_attempt_observations(claim_limit integer)');
    const claimSource = claim?.source ?? '';
    if (!claimSource.includes("p.state IN ('unknown', 'pending')")) {
      fail('SETTLEMENT_OBSERVATION_STORE_UNAVAILABLE');
    }
    for (const forbidden of ['persisted', 'committed', 'released', 'failed', 'refunded']) {
      if (claimSource.includes(`'${forbidden}'`)) fail('SETTLEMENT_OBSERVATION_STORE_UNAVAILABLE');
    }
    const fenced = byName.get(
      'record_leased_payment_attempt_observation(organization_id_input text, attempt_id_input uuid, lease_generation_input bigint, observed_state text, transfer_id_input uuid, gateway_status_input text, batch_tx_hash_input text)',
    );
    if (!(fenced?.source ?? '').includes('openarc_durable.record_payment_attempt_observation(')) {
      fail('SETTLEMENT_OBSERVATION_STORE_UNAVAILABLE');
    }
    // The schema15 recorder is unchanged: it still admits exactly the two
    // positive observations and no release of any kind.
    const recorder = byName.get(
      'record_payment_attempt_observation(organization_id text, attempt_id_input uuid, observed_state text, transfer_id_input uuid, gateway_status_input text, batch_tx_hash_input text)',
    );
    const recorderSource = recorder?.source ?? '';
    if (!recorderSource.includes("observed_state NOT IN ('pending', 'committed')")) {
      fail('SETTLEMENT_OBSERVATION_STORE_UNAVAILABLE');
    }
    for (const forbidden of ['released', 'failed', 'refunded', 'cancelled', 'expired']) {
      if (recorderSource.includes(`'${forbidden}'`)) {
        fail('SETTLEMENT_OBSERVATION_STORE_UNAVAILABLE');
      }
    }
  }

  async #assertTriggers(client: OutboxClient): Promise<void> {
    const expected: readonly { table: string; trigger: string }[] = [
      {
        table: 'openarc_durable.payment_attempt_observation_leases',
        trigger: 'payment_attempt_observation_leases_mutation',
      },
      { table: 'openarc_durable.payment_attempts', trigger: 'payment_attempts_mutation' },
    ];
    const rows = await client.query<{ relname: string; tgname: string; enabled: string }>(
      `SELECT n.nspname || '.' || c.relname AS relname, t.tgname, t.tgenabled::text AS enabled
         FROM pg_trigger t
         JOIN pg_class c ON c.oid = t.tgrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'openarc_durable' AND NOT t.tgisinternal
          AND t.tgname = ANY ($1::text[])`,
      [expected.map((entry) => entry.trigger)],
    );
    if (rows.rows.length !== expected.length) fail('SETTLEMENT_OBSERVATION_STORE_UNAVAILABLE');
    for (const entry of expected) {
      const row = rows.rows.find((candidate) => candidate.tgname === entry.trigger);
      if (row === undefined || row.relname !== entry.table || row.enabled !== 'O') {
        fail('SETTLEMENT_OBSERVATION_STORE_UNAVAILABLE');
      }
    }
  }

  async #assertMigrations(client: OutboxClient): Promise<void> {
    const applied = await client.query<{ id: string; checksum: string }>(
      `SELECT id, checksum FROM openarc_meta.schema_migrations ORDER BY id`,
    );
    let migrations: readonly { readonly id: string; readonly sql: string }[];
    try {
      migrations = loadMigrations();
    } catch {
      fail('SETTLEMENT_OBSERVATION_STORE_UNAVAILABLE');
    }
    if (applied.rows.length !== migrations.length) fail('SETTLEMENT_OBSERVATION_STORE_UNAVAILABLE');
    if (!migrations.some((migration) => migration.id === '0017_settlement_observation')) {
      fail('SETTLEMENT_OBSERVATION_STORE_UNAVAILABLE');
    }
    for (let index = 0; index < applied.rows.length; index += 1) {
      const record = applied.rows[index];
      const manifest = migrations[index];
      if (record === undefined || manifest === undefined || record.id !== manifest.id) {
        fail('SETTLEMENT_OBSERVATION_STORE_UNAVAILABLE');
      }
      const checksum = createHash('sha256').update(manifest.sql, 'utf8').digest('hex');
      if (record.checksum !== checksum) fail('SETTLEMENT_OBSERVATION_STORE_UNAVAILABLE');
    }
  }
}

/** Structural adapter for callers that hold a raw `pg` Pool. */
export function asSettlementObservationPool(pool: Pool): OutboxPool {
  return pool as unknown as OutboxPool;
}
