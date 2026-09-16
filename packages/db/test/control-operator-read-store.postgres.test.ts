import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import {
  ControlActionReadStore,
  ControlActionReadStoreError,
  ControlGrantStore,
  ControlGrantStoreError,
  createDatabasePool,
  loadMigrations,
  migrate,
} from '../src/index.js';
import { readPermittedOutboxEventPairs } from './outbox-event-catalog.js';
import {
  adminPool,
  ensureRoles,
  migratorUrl,
  resetSchema,
  tenantUrl,
  workerUrl,
} from './postgres-fixture.js';
import {
  PaymentAttemptFixture,
  fixtureAgentId,
  fixtureOrgId,
  fixturePolicyId,
  fixtureSha256,
  fixtureUuid,
  type DispatchedAttempt,
} from './payment-attempt-fixture.js';

/**
 * schema18 PG proofs: the three operator control-room reads.
 *
 * Everything under test is READ ONLY. Every chain below is built through the
 * accepted production paths by the shared payment-attempt fixture; the extra
 * exposure rows are bulk-seeded as the privileged fixture role ONLY to reach a
 * bucket mix or an accounting bound, exactly as the schema10 suite does, and no
 * constraint, trigger or grant is relaxed to admit them. Nothing here signs,
 * settles, releases, cancels or advances any state, and no assertion depends on
 * a floating-point amount: every amount is compared as an exact integer string.
 */

const HELD = 'openarc:reservation:';
const SYNTH_ACTION = '4a000000-0000-4000-8000-';
const SYNTH_RESERVATION = '4b000000-0000-4000-8000-';
const SYNTH_EVENT = '4c000000-0000-4000-8000-';
const SYNTH_GRANT = '4d000000-0000-4000-8000-';

let admin: Pool;
let migrator: ReturnType<typeof createDatabasePool>;
let tenant: ReturnType<typeof createDatabasePool>;
let reads: ControlActionReadStore;
let grants: ControlGrantStore;
let fixture: PaymentAttemptFixture;

beforeAll(async () => {
  admin = adminPool();
  await ensureRoles(admin);
  migrator = createDatabasePool(migratorUrl());
  tenant = createDatabasePool(tenantUrl());
});

afterAll(async () => {
  try {
    await resetSchema(admin);
  } finally {
    await tenant.end();
    await migrator.end();
    await admin.end();
  }
});

beforeEach(async () => {
  await resetSchema(admin);
  await migrate(migrator);
  reads = new ControlActionReadStore(tenant);
  grants = new ControlGrantStore(tenant);
  fixture = new PaymentAttemptFixture({ admin, tenant });
});

/* ── chain identity, derived exactly as the shared fixture derives it ────── */

interface Chain {
  readonly seed: number;
  readonly org: string;
  readonly hash: string;
  readonly agent: string;
  readonly policy: string;
  readonly attempt: DispatchedAttempt;
}

async function seedChain(
  seed: number,
  options: { readonly dispatch?: boolean } = {},
): Promise<Chain> {
  const attempt = await fixture.seedDispatchedAttempt(seed, options);
  return {
    seed,
    org: fixtureOrgId(seed),
    hash: fixtureSha256(`session:${seed}`),
    agent: fixtureAgentId(seed),
    policy: fixturePolicyId(seed),
    attempt,
  };
}

async function rawError(promise: Promise<unknown>): Promise<{ code?: string }> {
  try {
    await promise;
  } catch (error) {
    return error as { code?: string };
  }
  throw new Error('expected a rejection');
}

async function expectReadCode(promise: Promise<unknown>, code: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ControlActionReadStoreError);
    expect((error as ControlActionReadStoreError).code).toBe(code);
    return;
  }
  throw new Error(`expected ControlActionReadStoreError ${code}`);
}

async function expectGrantCode(promise: Promise<unknown>, code: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ControlGrantStoreError);
    expect((error as ControlGrantStoreError).code).toBe(code);
    return;
  }
  throw new Error(`expected ControlGrantStoreError ${code}`);
}

async function waitForLockWait(): Promise<void> {
  for (let attempt = 0; attempt < 600; attempt += 1) {
    const probe = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM pg_stat_activity
        WHERE datname = current_database() AND wait_event_type = 'Lock' AND pid <> pg_backend_pid()`,
    );
    if ((probe.rows[0]?.n ?? 0) > 0) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error('no lock wait observed');
}

async function shortenSession(hash: string, seconds: number): Promise<void> {
  await admin.query(
    `UPDATE openarc_auth.sessions
        SET expires_at = clock_timestamp() + make_interval(secs => $2)
      WHERE token_hash = $1`,
    [hash, seconds],
  );
}

async function waitUntilSessionExpired(hash: string): Promise<void> {
  for (let attempt = 0; attempt < 600; attempt += 1) {
    const probe = await admin.query<{ expired: boolean }>(
      `SELECT clock_timestamp() >= expires_at AS expired
         FROM openarc_auth.sessions WHERE token_hash = $1`,
      [hash],
    );
    if (probe.rows[0]?.expired === true) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error('session did not expire');
}

/* ── synthetic exposure and grant rows ──────────────────────────────────── */

/**
 * Clone the chain's single real action into `count` synthetic actions, each
 * with its own reservation in `status` and (for 'committed') its own committed
 * budget event. The clones share the action's exposure identity, subject agent
 * and debit exactly, so they land in the same policy window the read projects.
 */
async function seedReservations(
  chain: Chain,
  status: 'held' | 'claimed' | 'unknown' | 'committed' | 'released',
  from: number,
  to: number,
): Promise<void> {
  const expected = to - from + 1;
  const actions = await admin.query(
    `INSERT INTO openarc_durable.commerce_actions (
       organization_id, action_id, subject_agent_id, parent_human_account_id, commerce_session_id,
       agent_session_id, credential_id, policy_id, policy_revision, seller_organization_id,
       provider_id, listing_id, listing_version, requirement_id, requirement_digest, network_id,
       asset, representation, decimals, amount_atomic, fee_atomic, debit_atomic, request_digest,
       source_kind, status, reservation_id, approval_id, created_at, updated_at, expires_at)
     SELECT a.organization_id,
            'openarc:action:' || $5 || lpad(i::text, 11, '0'),
            a.subject_agent_id, a.parent_human_account_id, a.commerce_session_id,
            a.agent_session_id, a.credential_id, a.policy_id, a.policy_revision,
            a.seller_organization_id, a.provider_id, a.listing_id, a.listing_version,
            a.requirement_id, a.requirement_digest, a.network_id, a.asset, a.representation,
            a.decimals, a.amount_atomic, a.fee_atomic, a.debit_atomic, a.request_digest,
            a.source_kind, 'reserved_not_granted',
            'openarc:reservation:' || $6 || lpad(i::text, 11, '0'),
            NULL, a.created_at, a.updated_at, a.expires_at
       FROM openarc_durable.commerce_actions a, generate_series($3::int, $4::int) AS i
      WHERE a.organization_id = $1 AND a.action_id = $2`,
    [
      chain.org, chain.attempt.actionId, from, to,
      SYNTH_ACTION + statusTag(status), SYNTH_RESERVATION + statusTag(status),
    ],
  );
  expect(actions.rowCount).toBe(expected);
  const reservations = await admin.query(
    `INSERT INTO openarc_durable.budget_reservations (
       organization_id, reservation_id, action_id, subject_agent_id, network_id, asset,
       representation, decimals, debit_atomic, source_kind, status, created_at, claimed_at,
       resolved_at)
     SELECT a.organization_id, a.reservation_id, a.action_id, a.subject_agent_id, a.network_id,
            a.asset, a.representation, a.decimals, a.debit_atomic, a.source_kind, $3,
            a.created_at,
            CASE WHEN $3 IN ('claimed', 'unknown') THEN a.created_at ELSE NULL END,
            CASE WHEN $3 IN ('committed', 'released') THEN clock_timestamp() ELSE NULL END
       FROM openarc_durable.commerce_actions a
      WHERE a.organization_id = $1
        AND a.action_id LIKE 'openarc:action:' || $2 || '%'
        AND NOT EXISTS (
          SELECT 1 FROM openarc_durable.budget_reservations r
           WHERE r.organization_id = a.organization_id AND r.action_id = a.action_id)`,
    [chain.org, SYNTH_ACTION + statusTag(status), status],
  );
  expect(reservations.rowCount).toBe(expected);
  if (status === 'committed') {
    const events = await admin.query(
      `INSERT INTO openarc_durable.budget_events (
         organization_id, event_id, action_id, reservation_id, subject_agent_id, network_id,
         asset, representation, decimals, amount_atomic, event_kind, event_time)
       SELECT r.organization_id,
              ($3 || substring(r.action_id FROM 40))::uuid,
              r.action_id, r.reservation_id, r.subject_agent_id, r.network_id, r.asset,
              r.representation, r.decimals, r.debit_atomic, 'committed', clock_timestamp()
         FROM openarc_durable.budget_reservations r
        WHERE r.organization_id = $1
          AND r.action_id LIKE 'openarc:action:' || $2 || '%'
          AND NOT EXISTS (
            SELECT 1 FROM openarc_durable.budget_events b
             WHERE b.organization_id = r.organization_id AND b.action_id = r.action_id
               AND b.event_kind = 'committed')`,
      [chain.org, SYNTH_ACTION + statusTag(status), SYNTH_EVENT],
    );
    expect(events.rowCount).toBe(expected);
  }
}

/** A one-hex tag per status so each status owns a disjoint id namespace. */
function statusTag(status: string): string {
  switch (status) {
    case 'held': return '1';
    case 'claimed': return '2';
    case 'unknown': return '3';
    case 'committed': return '4';
    default: return '5';
  }
}

/**
 * A synthetic never-claimed `issued` grant on a synthetic action, whose expiry
 * is placed at an exact offset from a DB instant read in the same call. The
 * schema12 grant triggers are BEFORE UPDATE/DELETE only, so a fixture INSERT
 * that satisfies every CHECK is admitted without relaxing anything.
 */
async function seedIssuedGrant(
  chain: Chain,
  index: number,
  expiresInSeconds: number,
): Promise<string> {
  const grantId = `openarc:grant:${SYNTH_GRANT}${String(index).padStart(12, '0')}`;
  const actionId = `openarc:action:${SYNTH_ACTION}9${String(index).padStart(11, '0')}`;
  const reservationId = `${HELD}${SYNTH_RESERVATION}9${String(index).padStart(11, '0')}`;
  await admin.query(
    `INSERT INTO openarc_durable.commerce_actions (
       organization_id, action_id, subject_agent_id, parent_human_account_id, commerce_session_id,
       agent_session_id, credential_id, policy_id, policy_revision, seller_organization_id,
       provider_id, listing_id, listing_version, requirement_id, requirement_digest, network_id,
       asset, representation, decimals, amount_atomic, fee_atomic, debit_atomic, request_digest,
       source_kind, status, reservation_id, approval_id, created_at, updated_at, expires_at)
     SELECT a.organization_id, $3, a.subject_agent_id, a.parent_human_account_id,
            a.commerce_session_id, a.agent_session_id, a.credential_id, a.policy_id,
            a.policy_revision, a.seller_organization_id, a.provider_id, a.listing_id,
            a.listing_version, a.requirement_id, a.requirement_digest, a.network_id, a.asset,
            a.representation, a.decimals, a.amount_atomic, a.fee_atomic, a.debit_atomic,
            a.request_digest, a.source_kind, 'grant_issued', $4, NULL,
            a.created_at, a.updated_at, a.expires_at
       FROM openarc_durable.commerce_actions a
      WHERE a.organization_id = $1 AND a.action_id = $2`,
    [chain.org, chain.attempt.actionId, actionId, reservationId],
  );
  await admin.query(
    `INSERT INTO openarc_durable.budget_reservations (
       organization_id, reservation_id, action_id, subject_agent_id, network_id, asset,
       representation, decimals, debit_atomic, source_kind, status, created_at)
     SELECT a.organization_id, a.reservation_id, a.action_id, a.subject_agent_id, a.network_id,
            a.asset, a.representation, a.decimals, a.debit_atomic, a.source_kind, 'held',
            a.created_at
       FROM openarc_durable.commerce_actions a
      WHERE a.organization_id = $1 AND a.action_id = $2`,
    [chain.org, actionId],
  );
  await admin.query(
    `INSERT INTO openarc_durable.authorization_grants (
       organization_id, grant_id, action_id, reservation_id, subject_agent_id,
       commerce_session_id, seller_organization_id, provider_id, listing_id, listing_version,
       requirement_id, source_kind, current_generation, status, issued_at, updated_at,
       expires_at, claimed_at, revoked_at)
     SELECT a.organization_id, $3, a.action_id, a.reservation_id, a.subject_agent_id,
            a.commerce_session_id, a.seller_organization_id, a.provider_id, a.listing_id,
            a.listing_version, a.requirement_id, a.source_kind, 1, 'issued',
            -- now() is the stable transaction instant, so the frozen 300-second
            -- grant window holds exactly; clock_timestamp() advances mid
            -- statement and would break it.
            now() + make_interval(secs => $4) - interval '300 seconds',
            now() + make_interval(secs => $4) - interval '300 seconds',
            now() + make_interval(secs => $4), NULL, NULL
       FROM openarc_durable.commerce_actions a
      WHERE a.organization_id = $1 AND a.action_id = $2`,
    [chain.org, actionId, grantId, expiresInSeconds],
  );
  return grantId;
}

async function bucketsOf(chain: Chain) {
  const detail = await reads.readExposureBuckets(chain.hash, chain.org, chain.agent, chain.policy);
  expect(detail.organizationId).toBe(chain.org);
  return detail.item;
}

async function queueIds(
  chain: Chain,
  query: Record<string, string> = {},
): Promise<string[]> {
  const page = await reads.listStuckQueue(chain.hash, chain.org, { limit: '50', ...query });
  expect(page.organizationId).toBe(chain.org);
  return page.items.map((item) => `${item.kind}:${item.entryId}`);
}

/* ── 1. manifest, ownership, ACLs, volatility ───────────────────────────── */

describe('schema18 manifest, ownership, ACLs and volatility', () => {
  it('records schema18 and grants the three reads to the tenant runtime alone', async () => {
    const applied = await admin.query<{ id: string }>(
      'SELECT id FROM openarc_meta.schema_migrations ORDER BY id',
    );
    expect(applied.rows.map((row) => row.id).slice(-2)).toEqual([
      '0017_settlement_observation',
      '0018_operator_reads',
    ]);
    const acl = await admin.query<{
      proname: string; args: string; owner: string; secdef: boolean; volatility: string;
      config: string[]; app: boolean; worker: boolean; auth: boolean; pub: number;
    }>(
      `SELECT p.proname, pg_get_function_identity_arguments(p.oid) AS args,
              r.rolname AS owner, p.prosecdef AS secdef, p.provolatile::text AS volatility,
              coalesce(p.proconfig, ARRAY[]::text[]) AS config,
              has_function_privilege('openarc_tenant_app', p.oid, 'EXECUTE') AS app,
              has_function_privilege('openarc_worker_app', p.oid, 'EXECUTE') AS worker,
              has_function_privilege('openarc_auth_app', p.oid, 'EXECUTE') AS auth,
              (SELECT count(*)::int FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE') AS pub
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         JOIN pg_roles r ON r.oid = p.proowner
        WHERE n.nspname = 'openarc_durable'
          AND p.proname IN ('read_commerce_exposure_buckets', 'list_operator_stuck_queue',
                            'list_authorization_grants')
        ORDER BY p.proname`,
    );
    // Exactly one overload of each: no second signature exists anywhere.
    expect(acl.rows.map((row) => row.proname)).toEqual([
      'list_authorization_grants', 'list_operator_stuck_queue', 'read_commerce_exposure_buckets',
    ]);
    for (const row of acl.rows) {
      expect([row.proname, row.owner]).toEqual([row.proname, 'openarc_migrator']);
      expect([row.proname, row.secdef]).toEqual([row.proname, true]);
      // STABLE: PostgreSQL itself forbids these readers from writing.
      expect([row.proname, row.volatility]).toEqual([row.proname, 's']);
      expect([row.proname, row.config]).toEqual([row.proname, ['search_path=pg_catalog']]);
      expect([row.proname, row.app, row.worker, row.auth, row.pub])
        .toEqual([row.proname, true, false, false, 0]);
    }
    expect(acl.rows.map((row) => row.args)).toEqual([
      'human_session_hash text, organization_id text, after_grant_id text, limit_count integer',
      'human_session_hash text, organization_id text, attempt_max_age_seconds integer, grant_expiry_window_seconds integer, after_kind text, after_entry_id text, limit_count integer',
      'human_session_hash text, organization_id text, subject_agent_id_input text, policy_id_input text',
    ]);
    // The runtime still holds no direct privilege on any table they read, and
    // the DB-derived authority resolver stays migrator-private.
    for (const table of [
      'openarc_durable.budget_reservations', 'openarc_durable.budget_events',
      'openarc_durable.authorization_grants', 'openarc_durable.payment_attempts',
    ]) {
      expect((await rawError(tenant.query(`SELECT count(*) FROM ${table}`))).code).toBe('42501');
    }
    expect(
      (await rawError(
        tenant.query('SELECT openarc_durable.resolve_action_reader_org($1, $2)', [
          'a'.repeat(64), fixtureOrgId(1),
        ]),
      )).code,
    ).toBe('42501');
    const worker = createDatabasePool(workerUrl());
    try {
      for (const call of [
        'SELECT * FROM openarc_durable.read_commerce_exposure_buckets($1, $2, $3, $4)',
      ]) {
        expect(
          (await rawError(
            worker.query(call, [
              'a'.repeat(64), fixtureOrgId(1), fixtureAgentId(1), fixturePolicyId(1),
            ]),
          )).code,
        ).toBe('42501');
      }
    } finally {
      await worker.end();
    }
  }, 120000);

  it('adds no table, trigger, constraint, index, role or outbox event type', async () => {
    const migration = loadMigrations().find((entry) => entry.id === '0018_operator_reads');
    expect(migration).toBeDefined();
    const sql = migration!.sql;
    // Comments are prose ABOUT the guarantees; the executable text is what must
    // contain no DDL other than CREATE FUNCTION and its ACLs, so nothing the
    // migration does can reach a table, a trigger or the outbox.
    const code = sql
      .split('\n')
      .map((line) => line.replace(/--.*$/, ''))
      .join('\n');
    for (const forbidden of [
      'CREATE TABLE', 'ALTER TABLE', 'CREATE TRIGGER', 'DROP ', 'CREATE INDEX',
      'CREATE ROLE', 'CREATE POLICY', 'ADD CONSTRAINT', 'CREATE OR REPLACE FUNCTION',
      'outbox', 'INSERT INTO', 'UPDATE ', 'DELETE FROM', 'GRANT SELECT', 'TO PUBLIC',
    ]) {
      expect([forbidden, code.includes(forbidden)]).toEqual([forbidden, false]);
    }
    expect(code.split('CREATE FUNCTION').length - 1).toBe(3);
    expect(code.split('REVOKE ALL ON FUNCTION').length - 1).toBe(3);
    expect(code.split('GRANT EXECUTE ON FUNCTION').length - 1).toBe(3);
    // The worker outbox guard derives its permitted set from the LIVE
    // constraints, so those must still describe exactly the schema17 set.
    const pairs = await readPermittedOutboxEventPairs(admin);
    expect(pairs.length).toBeGreaterThan(0);
    for (const pair of pairs) {
      expect(pair.eventType).not.toContain('operator');
      expect(pair.eventType).not.toContain('exposure_bucket');
      expect(pair.eventType).not.toContain('stuck_queue');
    }
  });
});

/* ── 2. the four buckets ────────────────────────────────────────────────── */

describe('four-bucket exposure', () => {
  it('projects held, claimed, unknown and committed separately when all four are non-zero', async () => {
    const chain = await seedChain(10);
    // The production chain already holds exactly one reservation of 1000000.
    await seedReservations(chain, 'held', 1, 2); // +2 held
    await seedReservations(chain, 'claimed', 1, 3); // 3 claimed
    await seedReservations(chain, 'unknown', 1, 5); // 5 unknown
    await seedReservations(chain, 'committed', 1, 7); // 7 committed events
    // A released reservation is exposure that ENDED: it is in no bucket.
    await seedReservations(chain, 'released', 1, 11);
    const item = await bucketsOf(chain);
    expect(item).not.toBeNull();
    expect({
      heldAtomic: item?.heldAtomic,
      claimedAtomic: item?.claimedAtomic,
      unknownAtomic: item?.unknownAtomic,
      committedAtomic: item?.committedAtomic,
    }).toEqual({
      heldAtomic: '3000000',
      claimedAtomic: '3000000',
      unknownAtomic: '5000000',
      committedAtomic: '7000000',
    });
    expect(item?.subjectAgentId).toBe(chain.agent);
    expect(item?.policyId).toBe(chain.policy);
    expect(item?.networkId).toBe('eip155:5042002');
    expect(item?.asset).toBe('USDC');
    expect(item?.decimals).toBe(6);
    expect(item?.windowSeconds).toBe('3600');
  }, 180000);

  it('never merges unknown into any projected column', async () => {
    const chain = await seedChain(11);
    await seedReservations(chain, 'unknown', 1, 4);
    const withUnknown = await bucketsOf(chain);
    expect(withUnknown?.unknownAtomic).toBe('4000000');
    expect(withUnknown?.heldAtomic).toBe('1000000');
    expect(withUnknown?.claimedAtomic).toBe('0');
    expect(withUnknown?.committedAtomic).toBe('0');
    // No projected key anywhere in the answer equals a sum that contains the
    // unknown bucket, and no total/available/deficit field exists at all.
    const keys = Object.keys(withUnknown ?? {});
    for (const forbidden of [
      'totalAtomic', 'totalExposureAtomic', 'unresolvedAtomic', 'availableAtomic', 'deficitAtomic',
    ]) {
      expect(keys).not.toContain(forbidden);
    }
    const values = Object.values(withUnknown ?? {}).filter(
      (value): value is string => typeof value === 'string' && /^[0-9]+$/.test(value),
    );
    const unknown = BigInt(withUnknown?.unknownAtomic ?? '0');
    const held = BigInt(withUnknown?.heldAtomic ?? '0');
    for (const value of values) {
      expect(BigInt(value)).not.toBe(unknown + held);
    }
    // A second read with the unknown reservations absent differs ONLY in the
    // unknown bucket, so unknown money is carried nowhere else.
    const other = await seedChain(12);
    const clean = await bucketsOf(other);
    expect(clean?.heldAtomic).toBe(withUnknown?.heldAtomic);
    expect(clean?.claimedAtomic).toBe(withUnknown?.claimedAtomic);
    expect(clean?.committedAtomic).toBe(withUnknown?.committedAtomic);
    expect(clean?.unknownAtomic).toBe('0');
  }, 180000);

  it('is a safe not-found for an unknown policy and for another organization', async () => {
    const chain = await seedChain(13);
    const stranger = await seedChain(14);
    const missing = await reads.readExposureBuckets(
      chain.hash, chain.org, chain.agent, fixturePolicyId(999),
    );
    expect(missing).toEqual({
      organizationId: chain.org,
      subjectAgentId: chain.agent,
      policyId: fixturePolicyId(999),
      item: null,
    });
    // Another organization's real policy is INDISTINGUISHABLE from missing.
    const foreign = await reads.readExposureBuckets(
      chain.hash, chain.org, stranger.agent, stranger.policy,
    );
    expect(foreign).toEqual({
      organizationId: chain.org,
      subjectAgentId: stranger.agent,
      policyId: stranger.policy,
      item: null,
    });
    // And presenting the other organization as the lookup argument is refused
    // without revealing whether the policy exists.
    await expectReadCode(
      reads.readExposureBuckets(chain.hash, stranger.org, stranger.agent, stranger.policy),
      'CONTROL_ACTION_READ_STORE_FORBIDDEN',
    );
  }, 180000);
});

describe('bounded completeness: 4096 accepted, 4097 fails closed', () => {
  it('refuses rather than returning a partial reservation bucket past the bound', async () => {
    const chain = await seedChain(15);
    // 1 real held + 4095 synthetic unknown = exactly the accepted 4096.
    await seedReservations(chain, 'unknown', 1, 4095);
    const at4096 = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM openarc_durable.budget_reservations
        WHERE status IN ('held', 'claimed', 'unknown')`,
    );
    expect(at4096.rows[0]?.n).toBe(4096);
    const accepted = await bucketsOf(chain);
    expect(accepted?.unknownAtomic).toBe('4095000000');
    expect(accepted?.heldAtomic).toBe('1000000');

    // 4097 is REJECTED: no partial bucket, no partial sum, nothing returned.
    await seedReservations(chain, 'claimed', 1, 1);
    const overflowed = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM openarc_durable.budget_reservations
        WHERE status IN ('held', 'claimed', 'unknown')`,
    );
    expect(overflowed.rows[0]?.n).toBe(4097);
    await expectReadCode(
      reads.readExposureBuckets(chain.hash, chain.org, chain.agent, chain.policy),
      'CONTROL_ACTION_READ_STORE_UNAVAILABLE',
    );
    const direct = await rawError(
      migrator.query(
        'SELECT * FROM openarc_durable.read_commerce_exposure_buckets($1, $2, $3, $4)',
        [chain.hash, chain.org, chain.agent, chain.policy],
      ),
    );
    // The SAME fail-closed code the schema10 exposure read raises.
    expect(direct.code).toBe('P0D11');
  }, 600000);

  it('refuses past the bound on the committed source too', async () => {
    const chain = await seedChain(16);
    await seedReservations(chain, 'committed', 1, 4097);
    const events = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM openarc_durable.budget_events WHERE event_kind = 'committed'`,
    );
    expect(events.rows[0]?.n).toBe(4097);
    await expectReadCode(
      reads.readExposureBuckets(chain.hash, chain.org, chain.agent, chain.policy),
      'CONTROL_ACTION_READ_STORE_UNAVAILABLE',
    );
  }, 600000);
});

/* ── 3. the stuck/unknown queue ─────────────────────────────────────────── */

describe('stuck queue membership', () => {
  it('admits only unknown reservations, aged unknown/pending attempts and unclaimed expiring grants', async () => {
    const chain = await seedChain(20);
    await seedReservations(chain, 'unknown', 1, 2);
    await seedReservations(chain, 'claimed', 1, 1);
    await seedReservations(chain, 'committed', 1, 1);
    await seedReservations(chain, 'released', 1, 1);
    // attemptMaxAge 0 and grant window 300 admit the chain's own dispatched
    // attempt and its own never-claimed issued grant.
    const page = await reads.listStuckQueue(chain.hash, chain.org, {
      limit: '50', attemptMaxAgeSeconds: '0', grantExpiryWindowSeconds: '2592000',
    });
    const kinds = page.items.map((item) => item.kind);
    expect(kinds.filter((kind) => kind === 'budget_reservation')).toHaveLength(2);
    expect(kinds.filter((kind) => kind === 'payment_attempt')).toHaveLength(1);
    expect(kinds.filter((kind) => kind === 'authorization_grant')).toHaveLength(1);
    const reservations = page.items.filter((item) => item.kind === 'budget_reservation');
    for (const entry of reservations) {
      expect(entry.status).toBe('unknown');
      expect(entry.amountAtomic).toBe('1000000');
      expect(entry.subjectAgentId).toBe(chain.agent);
      expect(entry.expiresAt).toBeNull();
    }
    const attempt = page.items.find((item) => item.kind === 'payment_attempt');
    expect(attempt?.entryId).toBe(chain.attempt.attemptId);
    expect(attempt?.status).toBe('unknown');
    expect(attempt?.amountAtomic).toBe(chain.attempt.valueAtomic);
    expect(attempt?.expiresAt).toBeNull();
    const grant = page.items.find((item) => item.kind === 'authorization_grant');
    expect(grant?.entryId).toBe(chain.attempt.grantId);
    expect(grant?.status).toBe('issued');
    expect(grant?.expiresAt).not.toBeNull();
  }, 180000);

  it('drops an attempt once it commits and a grant once it is claimed or revoked', async () => {
    const chain = await seedChain(21);
    const before = await queueIds(chain, { attemptMaxAgeSeconds: '0', grantExpiryWindowSeconds: '2592000' });
    expect(before).toContain(`payment_attempt:${chain.attempt.attemptId}`);
    expect(before).toContain(`authorization_grant:${chain.attempt.grantId}`);
    // A pending observation keeps the attempt in the queue; a committed one
    // retires it. Neither is performed by the reader.
    await migrator.query(
      `SELECT * FROM openarc_durable.record_payment_attempt_observation($1, $2::uuid, $3, $4::uuid, $5, $6)`,
      [chain.org, chain.attempt.attemptId, 'pending', fixtureUuid(31), 'received', null],
    );
    const pending = await queueIds(chain, { attemptMaxAgeSeconds: '0', grantExpiryWindowSeconds: '2592000' });
    expect(pending).toContain(`payment_attempt:${chain.attempt.attemptId}`);
    await migrator.query(
      `SELECT * FROM openarc_durable.record_payment_attempt_observation($1, $2::uuid, $3, $4::uuid, $5, $6)`,
      [chain.org, chain.attempt.attemptId, 'committed', fixtureUuid(31), 'completed', `0x${'ab'.repeat(32)}`],
    );
    const committed = await queueIds(chain, { attemptMaxAgeSeconds: '0', grantExpiryWindowSeconds: '2592000' });
    expect(committed).not.toContain(`payment_attempt:${chain.attempt.attemptId}`);
    // A revoked grant leaves the queue too: the queue is unclaimed `issued`.
    await admin.query(
      `UPDATE openarc_durable.authorization_grants
          SET status = 'revoked', revoked_at = clock_timestamp(),
              updated_at = clock_timestamp() + interval '1 millisecond'
        WHERE organization_id = $1 AND grant_id = $2`,
      [chain.org, chain.attempt.grantId],
    );
    const revoked = await queueIds(chain, { attemptMaxAgeSeconds: '0', grantExpiryWindowSeconds: '2592000' });
    expect(revoked).not.toContain(`authorization_grant:${chain.attempt.grantId}`);
  }, 180000);

  it('applies the attempt age and the grant expiry window at their exact boundaries', async () => {
    const chain = await seedChain(22);
    // The attempt age comparison is `dispatched_at <= now - age`, inclusive.
    // At age 0 the boundary is `dispatched_at <= now`, which is satisfied by
    // equality and stays satisfied because the DB clock only advances.
    const atZero = await queueIds(chain, { attemptMaxAgeSeconds: '0', grantExpiryWindowSeconds: '0' });
    expect(atZero).toContain(`payment_attempt:${chain.attempt.attemptId}`);
    // One second past the boundary excludes it, and so does the ceiling.
    const aged = await queueIds(chain, { attemptMaxAgeSeconds: '300', grantExpiryWindowSeconds: '0' });
    expect(aged).not.toContain(`payment_attempt:${chain.attempt.attemptId}`);
    const maxAged = await queueIds(chain, { attemptMaxAgeSeconds: '2592000', grantExpiryWindowSeconds: '0' });
    expect(maxAged).not.toContain(`payment_attempt:${chain.attempt.attemptId}`);

    // The grant comparison is `expires_at <= now + window`, inclusive. A grant
    // seeded to expire exactly `window` seconds from a DB instant is admitted
    // at exactly that window (equality, preserved as the clock advances) and
    // refused at every strictly smaller window that the elapsed test time
    // cannot close.
    const near = await seedIssuedGrant(chain, 1, 100);
    const far = await seedIssuedGrant(chain, 2, 200);
    const atBoundary = await queueIds(chain, {
      attemptMaxAgeSeconds: '2592000', grantExpiryWindowSeconds: '100',
    });
    expect(atBoundary).toContain(`authorization_grant:${near}`);
    expect(atBoundary).not.toContain(`authorization_grant:${far}`);
    const belowBoundary = await queueIds(chain, {
      attemptMaxAgeSeconds: '2592000', grantExpiryWindowSeconds: '0',
    });
    expect(belowBoundary).not.toContain(`authorization_grant:${near}`);
    expect(belowBoundary).not.toContain(`authorization_grant:${far}`);
    const aboveBoundary = await queueIds(chain, {
      attemptMaxAgeSeconds: '2592000', grantExpiryWindowSeconds: '200',
    });
    expect(aboveBoundary).toContain(`authorization_grant:${near}`);
    expect(aboveBoundary).toContain(`authorization_grant:${far}`);
    // An already-expired never-claimed grant is in the queue at window 0.
    const lapsed = await seedIssuedGrant(chain, 3, -1);
    const atZeroWindow = await queueIds(chain, {
      attemptMaxAgeSeconds: '2592000', grantExpiryWindowSeconds: '0',
    });
    expect(atZeroWindow).toContain(`authorization_grant:${lapsed}`);
  }, 180000);
});

describe('stuck queue paging', () => {
  it('traverses every row exactly once with exact cursor boundaries and a held page cap', async () => {
    const chain = await seedChain(23);
    await seedReservations(chain, 'unknown', 1, 6);
    await seedIssuedGrant(chain, 1, 100);
    await seedIssuedGrant(chain, 2, 100);
    const query = { attemptMaxAgeSeconds: '0', grantExpiryWindowSeconds: '2592000' };
    const all = await reads.listStuckQueue(chain.hash, chain.org, { ...query, limit: '50' });
    // 6 synthetic unknown reservations + 3 grants + 1 attempt.
    expect(all.items).toHaveLength(10);
    expect(all.nextCursor).toBeNull();
    const expected = all.items.map((item) => `${item.kind}:${item.entryId}`);
    // Deterministic total order: kind ascending, then entry id ascending.
    expect([...expected].sort()).toEqual(expected);

    const seen: string[] = [];
    let cursor: { kind: string; entryId: string } | null = null;
    for (let page = 0; page < 20; page += 1) {
      const result: Awaited<ReturnType<ControlActionReadStore['listStuckQueue']>> =
        await reads.listStuckQueue(chain.hash, chain.org, {
          ...query,
          limit: '3',
          ...(cursor === null ? {} : { afterKind: cursor.kind, afterEntryId: cursor.entryId }),
        });
      // The hard page cap holds on every page.
      expect(result.items.length).toBeLessThanOrEqual(3);
      for (const item of result.items) seen.push(`${item.kind}:${item.entryId}`);
      if (result.nextCursor === null) break;
      // The cursor is EXACTLY the last returned pair, never a synthesized one.
      const last = result.items[result.items.length - 1];
      expect(result.nextCursor).toEqual({ kind: last?.kind, entryId: last?.entryId });
      cursor = result.nextCursor;
    }
    expect(seen).toEqual(expected);
    expect(new Set(seen).size).toBe(seen.length);

    // A cursor at the exact last pair yields an empty page with a null cursor.
    const lastEntry = all.items[all.items.length - 1];
    const empty = await reads.listStuckQueue(chain.hash, chain.org, {
      ...query, limit: '50', afterKind: lastEntry!.kind, afterEntryId: lastEntry!.entryId,
    });
    expect(empty.items).toEqual([]);
    expect(empty.nextCursor).toBeNull();
    expect(empty.organizationId).toBe(chain.org);

    // A cursor at the exact first pair excludes exactly that row and no other.
    const first = all.items[0];
    const afterFirst = await reads.listStuckQueue(chain.hash, chain.org, {
      ...query, limit: '50', afterKind: first!.kind, afterEntryId: first!.entryId,
    });
    expect(afterFirst.items.map((item) => `${item.kind}:${item.entryId}`)).toEqual(expected.slice(1));
  }, 180000);

  it('refuses an out-of-range page size, a half cursor and a cursor whose id contradicts its kind', async () => {
    const chain = await seedChain(24);
    for (const query of [
      { limit: '0' }, { limit: '51' }, { limit: '05' }, { limit: ' 5' }, { limit: '5\n' },
      { limit: 5 as unknown as string },
      { afterKind: 'budget_reservation' },
      { afterEntryId: `${HELD}${fixtureUuid(1)}` },
      { afterKind: 'payment_attempt', afterEntryId: `${HELD}${fixtureUuid(1)}` },
      { afterKind: 'budget_reservation', afterEntryId: fixtureUuid(1) },
      { afterKind: 'commerce_action', afterEntryId: fixtureUuid(1) },
      { attemptMaxAgeSeconds: '2592001' }, { attemptMaxAgeSeconds: '-1' },
      { attemptMaxAgeSeconds: '00' }, { grantExpiryWindowSeconds: '2592001' },
      { grantExpiryWindowSeconds: '1\n' },
      { nope: '1' } as unknown as Record<string, string>,
    ]) {
      await expectReadCode(
        reads.listStuckQueue(chain.hash, chain.org, query),
        'CONTROL_ACTION_READ_STORE_INPUT_INVALID',
      );
    }
    // The database refuses the same bounds directly, so the store is not the
    // only thing standing between a caller and an unbounded scan.
    for (const args of [
      [chain.hash, chain.org, 0, 0, null, null, 0],
      [chain.hash, chain.org, 0, 0, null, null, 51],
      [chain.hash, chain.org, -1, 0, null, null, 10],
      [chain.hash, chain.org, 0, 2592001, null, null, 10],
      [chain.hash, chain.org, 0, 0, 'budget_reservation', null, 10],
    ]) {
      expect(
        (await rawError(
          migrator.query(
            `SELECT * FROM openarc_durable.list_operator_stuck_queue($1, $2, $3::int, $4::int, $5, $6, $7::int)`,
            args,
          ),
        )).code,
      ).toBe('22023');
    }
  }, 180000);

  it('never shows another organization a single entry', async () => {
    const chain = await seedChain(25);
    const stranger = await seedChain(26);
    await seedReservations(stranger, 'unknown', 1, 3);
    const mine = await queueIds(chain, { attemptMaxAgeSeconds: '0', grantExpiryWindowSeconds: '2592000' });
    for (const id of mine) expect(id).not.toContain(stranger.attempt.attemptId);
    const page = await reads.listStuckQueue(chain.hash, chain.org, {
      limit: '50', attemptMaxAgeSeconds: '0', grantExpiryWindowSeconds: '2592000',
    });
    for (const item of page.items) expect(item.subjectAgentId).toBe(chain.agent);
    await expectReadCode(
      reads.listStuckQueue(chain.hash, stranger.org, { limit: '50' }),
      'CONTROL_ACTION_READ_STORE_FORBIDDEN',
    );
  }, 180000);
});

/* ── 4. the organization-wide grant page ────────────────────────────────── */

describe('organization-wide grant page', () => {
  it('pages every grant exactly once in ascending id order under the hard cap', async () => {
    const chain = await seedChain(30);
    const seeded = [chain.attempt.grantId];
    for (let index = 1; index <= 6; index += 1) {
      seeded.push(await seedIssuedGrant(chain, index, 100));
    }
    const expected = [...seeded].sort();
    const all = await grants.listGrants(chain.hash, chain.org, { limit: '50' });
    expect(all.organizationId).toBe(chain.org);
    expect(all.items.map((item) => item.grantId)).toEqual(expected);
    expect(all.nextCursor).toBeNull();

    const seen: string[] = [];
    let cursor: string | null = null;
    for (let page = 0; page < 20; page += 1) {
      const result: Awaited<ReturnType<ControlGrantStore['listGrants']>> =
        await grants.listGrants(chain.hash, chain.org, {
          limit: '2', ...(cursor === null ? {} : { afterGrantId: cursor }),
        });
      expect(result.items.length).toBeLessThanOrEqual(2);
      for (const item of result.items) seen.push(item.grantId);
      if (result.nextCursor === null) break;
      expect(result.nextCursor).toBe(result.items[result.items.length - 1]?.grantId);
      cursor = result.nextCursor;
    }
    expect(seen).toEqual(expected);
    expect(new Set(seen).size).toBe(seen.length);

    // Exact cursor boundaries: the first id excludes exactly itself, and the
    // last id yields an empty page with a null cursor.
    const afterFirst = await grants.listGrants(chain.hash, chain.org, {
      limit: '50', afterGrantId: expected[0]!,
    });
    expect(afterFirst.items.map((item) => item.grantId)).toEqual(expected.slice(1));
    const afterLast = await grants.listGrants(chain.hash, chain.org, {
      limit: '50', afterGrantId: expected[expected.length - 1]!,
    });
    expect(afterLast.items).toEqual([]);
    expect(afterLast.nextCursor).toBeNull();
    expect(afterLast.organizationId).toBe(chain.org);
  }, 180000);

  it('filters no status and derives expired exactly as the schema12 reader does', async () => {
    const chain = await seedChain(31);
    const lapsed = await seedIssuedGrant(chain, 1, -1);
    const live = await seedIssuedGrant(chain, 2, 200);
    await admin.query(
      `UPDATE openarc_durable.authorization_grants
          SET status = 'revoked', revoked_at = clock_timestamp(),
              updated_at = clock_timestamp() + interval '1 millisecond'
        WHERE organization_id = $1 AND grant_id = $2`,
      [chain.org, chain.attempt.grantId],
    );
    const page = await grants.listGrants(chain.hash, chain.org, { limit: '50' });
    const byId = new Map(page.items.map((item) => [item.grantId, item.status]));
    expect(byId.get(chain.attempt.grantId)).toBe('revoked');
    expect(byId.get(lapsed)).toBe('expired');
    expect(byId.get(live)).toBe('issued');
    // The page agrees with the frozen single-grant reader on every row.
    for (const item of page.items) {
      const single = await grants.readGrant(chain.hash, chain.org, item.grantId);
      expect(single).toEqual(item);
    }
  }, 180000);

  it('refuses an out-of-range page size and a malformed cursor, and hides other organizations', async () => {
    const chain = await seedChain(32);
    const stranger = await seedChain(33);
    for (const query of [
      { limit: '0' }, { limit: '51' }, { limit: '05' }, { limit: '5\n' },
      { limit: 5 as unknown as string },
      { afterGrantId: 'openarc:grant:not-a-uuid' },
      { afterGrantId: `openarc:grant:${fixtureUuid(1)}\n` },
      { nope: '1' } as unknown as Record<string, string>,
    ]) {
      await expectGrantCode(
        grants.listGrants(chain.hash, chain.org, query),
        'CONTROL_GRANT_STORE_INPUT_INVALID',
      );
    }
    const mine = await grants.listGrants(chain.hash, chain.org, { limit: '50' });
    expect(mine.items.map((item) => item.grantId)).not.toContain(stranger.attempt.grantId);
    for (const item of mine.items) expect(item.organizationId).toBe(chain.org);
    await expectGrantCode(
      grants.listGrants(chain.hash, stranger.org, { limit: '50' }),
      'CONTROL_GRANT_STORE_FORBIDDEN',
    );
    // A stranger's grant id under MY authority is a safe empty page, exactly
    // as a missing id is: the two are indistinguishable.
    const foreignCursor = await grants.listGrants(chain.hash, chain.org, {
      limit: '50', afterGrantId: stranger.attempt.grantId,
    });
    expect(foreignCursor.items.every((item) => item.grantId > stranger.attempt.grantId)).toBe(true);
  }, 180000);
});

/* ── 5. authority before and after ──────────────────────────────────────── */

describe('authority before and after the projection', () => {
  it('denies a viewer, a non-member and a recovery session on all three reads', async () => {
    const chain = await seedChain(40);
    const viewerAccount = `openarc:account:${fixtureUuid(940)}`;
    const viewerHash = fixtureSha256('viewer:940');
    await admin.query(
      "INSERT INTO openarc_auth.accounts (account_id, user_handle, status) VALUES ($1, $2, 'active')",
      [viewerAccount, `${fixtureSha256('handle:940').slice(0, 42)}A`],
    );
    await admin.query(
      `INSERT INTO openarc_auth.sessions (token_hash, account_id, method, created_at, expires_at)
       VALUES ($1, $2, 'passkey', now(), now() + interval '24 hours')`,
      [viewerHash, viewerAccount],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'viewer', 'active')",
      [chain.org, viewerAccount],
    );
    const outsiderAccount = `openarc:account:${fixtureUuid(941)}`;
    const outsiderHash = fixtureSha256('outsider:941');
    await admin.query(
      "INSERT INTO openarc_auth.accounts (account_id, user_handle, status) VALUES ($1, $2, 'active')",
      [outsiderAccount, `${fixtureSha256('handle:941').slice(0, 42)}A`],
    );
    await admin.query(
      `INSERT INTO openarc_auth.sessions (token_hash, account_id, method, created_at, expires_at)
       VALUES ($1, $2, 'passkey', now(), now() + interval '24 hours')`,
      [outsiderHash, outsiderAccount],
    );
    for (const hash of [viewerHash, outsiderHash]) {
      await expectReadCode(
        reads.readExposureBuckets(hash, chain.org, chain.agent, chain.policy),
        'CONTROL_ACTION_READ_STORE_FORBIDDEN',
      );
      await expectReadCode(
        reads.listStuckQueue(hash, chain.org, { limit: '50' }),
        'CONTROL_ACTION_READ_STORE_FORBIDDEN',
      );
      await expectGrantCode(
        grants.listGrants(hash, chain.org, { limit: '50' }),
        'CONTROL_GRANT_STORE_FORBIDDEN',
      );
    }
    // A suspended owner loses the reads too.
    await admin.query(
      "UPDATE openarc_tenant.memberships SET status = 'suspended' WHERE organization_id = $1 AND role = 'owner'",
      [chain.org],
    );
    await expectReadCode(
      reads.listStuckQueue(chain.hash, chain.org, { limit: '50' }),
      'CONTROL_ACTION_READ_STORE_FORBIDDEN',
    );
    await admin.query(
      "UPDATE openarc_tenant.memberships SET status = 'active' WHERE organization_id = $1 AND role = 'owner'",
      [chain.org],
    );
    // An operator membership IS accepted: the reads are owner-or-operator.
    await admin.query(
      "UPDATE openarc_tenant.memberships SET role = 'operator' WHERE organization_id = $1 AND account_id = $2",
      [chain.org, viewerAccount],
    );
    const asOperator = await reads.listStuckQueue(viewerHash, chain.org, { limit: '50' });
    expect(asOperator.organizationId).toBe(chain.org);
    // A recovery-method session is refused on every read.
    await admin.query(
      "UPDATE openarc_auth.sessions SET method = 'recovery' WHERE token_hash = $1",
      [chain.hash],
    );
    await expectReadCode(
      reads.readExposureBuckets(chain.hash, chain.org, chain.agent, chain.policy),
      'CONTROL_ACTION_READ_STORE_SESSION_INVALID',
    );
    await expectReadCode(
      reads.listStuckQueue(chain.hash, chain.org, { limit: '50' }),
      'CONTROL_ACTION_READ_STORE_SESSION_INVALID',
    );
    await expectGrantCode(
      grants.listGrants(chain.hash, chain.org, { limit: '50' }),
      'CONTROL_GRANT_STORE_SESSION_INVALID',
    );
  }, 180000);

  it('re-asserts the authority AFTER the projection when a session lapses under a lock wait', async () => {
    const chain = await seedChain(41);
    await shortenSession(chain.hash, 2);
    const blocker = await admin.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query(
        'SELECT 1 FROM openarc_tenant.organizations WHERE organization_id = $1 FOR UPDATE',
        [chain.org],
      );
      const pending = reads.listStuckQueue(chain.hash, chain.org, { limit: '50' });
      await waitForLockWait();
      await waitUntilSessionExpired(chain.hash);
      await blocker.query('COMMIT');
      await expectReadCode(pending, 'CONTROL_ACTION_READ_STORE_SESSION_INVALID');
    } finally {
      await blocker.query('ROLLBACK').catch(() => {});
      blocker.release();
    }
  }, 180000);

  it('re-asserts the authority on the EMPTY and NOT-FOUND paths under a lock wait', async () => {
    const chain = await seedChain(42);
    await shortenSession(chain.hash, 2);
    const blocker = await admin.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query(
        'SELECT 1 FROM openarc_tenant.organizations WHERE organization_id = $1 FOR UPDATE',
        [chain.org],
      );
      // An unknown policy: the answer the reader had already computed is the
      // safe not-found, and it must STILL be refused.
      const pending = reads.readExposureBuckets(
        chain.hash, chain.org, chain.agent, fixturePolicyId(999),
      );
      await waitForLockWait();
      await waitUntilSessionExpired(chain.hash);
      await blocker.query('COMMIT');
      await expectReadCode(pending, 'CONTROL_ACTION_READ_STORE_SESSION_INVALID');
    } finally {
      await blocker.query('ROLLBACK').catch(() => {});
      blocker.release();
    }
  }, 180000);

  it('calls the authority resolver twice, the last time after the projection', async () => {
    const definitions = await admin.query<{
      proname: string; body: string; volatile: string; secdef: boolean; config: string[];
    }>(
      `SELECT p.proname, pg_get_functiondef(p.oid) AS body, p.provolatile AS volatile,
              p.prosecdef AS secdef, coalesce(p.proconfig, ARRAY[]::text[]) AS config
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'openarc_durable'
          AND p.proname IN ('read_commerce_exposure_buckets', 'list_operator_stuck_queue',
                            'list_authorization_grants')`,
    );
    expect(definitions.rows).toHaveLength(3);
    for (const row of definitions.rows) {
      const calls = row.body.split('resolve_action_reader_org').length - 1;
      expect([row.proname, calls]).toEqual([row.proname, 2]);
      // The last authority call sits after the last projection statement, so
      // the re-assert cannot be skipped on any path.
      expect([
        row.proname,
        row.body.lastIndexOf('resolve_action_reader_org') > row.body.lastIndexOf('FROM openarc_durable.'),
      ]).toEqual([row.proname, true]);
      expect([row.proname, row.volatile]).toEqual([row.proname, 's']);
      expect([row.proname, row.secdef]).toEqual([row.proname, true]);
      expect([row.proname, row.config]).toEqual([row.proname, ['search_path=pg_catalog']]);
      // A STABLE reader can contain no write statement at all.
      for (const forbidden of ['INSERT INTO', 'UPDATE ', 'DELETE FROM', 'FOR UPDATE']) {
        expect([row.proname, forbidden, row.body.includes(forbidden)])
          .toEqual([row.proname, forbidden, false]);
      }
    }
  });
});

/* ── 6. readiness negative checks ───────────────────────────────────────── */

describe('readiness for every schema18 helper', () => {
  it('passes, then fails for every new helper that is missing, mis-signed, widened or bypassed', async () => {
    await reads.readiness();
    await grants.readiness();
    const expectUnready = async (label: string): Promise<void> => {
      let readFailed = false;
      try {
        await new ControlActionReadStore(tenant).readiness();
      } catch (error) {
        expect([label, (error as ControlActionReadStoreError).code])
          .toEqual([label, 'CONTROL_ACTION_READ_STORE_UNAVAILABLE']);
        readFailed = true;
      }
      let grantFailed = false;
      try {
        await new ControlGrantStore(tenant).readiness();
      } catch (error) {
        expect([label, (error as ControlGrantStoreError).code])
          .toEqual([label, 'CONTROL_GRANT_STORE_UNAVAILABLE']);
        grantFailed = true;
      }
      if (!readFailed && !grantFailed) {
        throw new Error(`readiness unexpectedly passed: ${label}`);
      }
    };
    const helpers: readonly { name: string; sig: string }[] = [
      {
        name: 'read_commerce_exposure_buckets',
        sig: 'openarc_durable.read_commerce_exposure_buckets(text, text, text, text)',
      },
      {
        name: 'list_operator_stuck_queue',
        sig: 'openarc_durable.list_operator_stuck_queue(text, text, integer, integer, text, text, integer)',
      },
      {
        name: 'list_authorization_grants',
        sig: 'openarc_durable.list_authorization_grants(text, text, text, integer)',
      },
    ];
    for (const helper of helpers) {
      // Missing.
      await migrator.query(`ALTER FUNCTION ${helper.sig} RENAME TO ${helper.name}_gone`);
      await expectUnready(`${helper.name}:missing`);
      await migrator.query(
        `ALTER FUNCTION ${helper.sig.replace(`.${helper.name}(`, `.${helper.name}_gone(`)} RENAME TO ${helper.name}`,
      );
      // Mis-signed: SECURITY INVOKER.
      await migrator.query(`ALTER FUNCTION ${helper.sig} SECURITY INVOKER`);
      await expectUnready(`${helper.name}:security`);
      await migrator.query(`ALTER FUNCTION ${helper.sig} SECURITY DEFINER`);
      // Mis-signed: volatility relabeled so a write could be added later.
      await migrator.query(`ALTER FUNCTION ${helper.sig} VOLATILE`);
      await expectUnready(`${helper.name}:volatility`);
      await migrator.query(`ALTER FUNCTION ${helper.sig} STABLE`);
      // Mis-signed: search_path no longer pinned.
      await migrator.query(`ALTER FUNCTION ${helper.sig} RESET search_path`);
      await expectUnready(`${helper.name}:search_path`);
      await migrator.query(`ALTER FUNCTION ${helper.sig} SET search_path = pg_catalog`);
      // Widened to PUBLIC.
      await migrator.query(`GRANT EXECUTE ON FUNCTION ${helper.sig} TO PUBLIC`);
      await expectUnready(`${helper.name}:public`);
      await migrator.query(`REVOKE EXECUTE ON FUNCTION ${helper.sig} FROM PUBLIC`);
      // Runtime reachability removed.
      await migrator.query(`REVOKE EXECUTE ON FUNCTION ${helper.sig} FROM openarc_tenant_app`);
      await expectUnready(`${helper.name}:runtime`);
      await migrator.query(`GRANT EXECUTE ON FUNCTION ${helper.sig} TO openarc_tenant_app`);
      await reads.readiness();
      await grants.readiness();
    }
    // A second overload of any new read is not ready.
    await migrator.query(
      `CREATE FUNCTION openarc_durable.list_authorization_grants(a text, b text, c text, d integer, e text)
       RETURNS void LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$ SELECT $$`,
    );
    await migrator.query(
      'REVOKE ALL ON FUNCTION openarc_durable.list_authorization_grants(text, text, text, integer, text) FROM PUBLIC',
    );
    await expectUnready('list_authorization_grants:overload');
    await migrator.query(
      'DROP FUNCTION openarc_durable.list_authorization_grants(text, text, text, integer, text)',
    );
    // The private authority resolver becoming runtime-reachable is not ready.
    await migrator.query(
      'GRANT EXECUTE ON FUNCTION openarc_durable.resolve_action_reader_org(text, text) TO openarc_tenant_app',
    );
    await expectUnready('resolve_action_reader_org:runtime');
    await migrator.query(
      'REVOKE EXECUTE ON FUNCTION openarc_durable.resolve_action_reader_org(text, text) FROM openarc_tenant_app',
    );
    // Any runtime table privilege on a source the new reads project is not ready.
    for (const table of [
      'openarc_durable.budget_reservations', 'openarc_durable.budget_events',
      'openarc_durable.authorization_grants', 'openarc_durable.payment_attempts',
    ]) {
      await migrator.query(`GRANT SELECT ON TABLE ${table} TO openarc_tenant_app`);
      await expectUnready(`${table}:runtime_select`);
      await migrator.query(`REVOKE SELECT ON TABLE ${table} FROM openarc_tenant_app`);
      await migrator.query(`ALTER TABLE ${table} NO FORCE ROW LEVEL SECURITY`);
      await expectUnready(`${table}:unforced`);
      await migrator.query(`ALTER TABLE ${table} FORCE ROW LEVEL SECURITY`);
    }
    await reads.readiness();
    await grants.readiness();
  }, 600000);
});
