import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import {
  SettlementObservationStore,
  createDatabasePool,
  loadMigrations,
  migrate,
  type LeasedPaymentAttempt,
  type SettlementObservationStoreError,
} from '../src/index.js';
import {
  adminPool,
  ensureRoles,
  migratorUrl,
  resetSchema,
  tenantUrl,
  workerUrl,
} from './postgres-fixture.js';
import { PaymentAttemptFixture, type DispatchedAttempt } from './payment-attempt-fixture.js';

/**
 * schema17 PG proofs: the settlement observation lease surface and its single
 * principal, the worker role.
 *
 * Everything that observes runs through the RESTRICTED WORKER ROLE, which is
 * the whole point of the packet: settlement can land days after the buyer's
 * commerce session expired, so no request-serving path may record it. Nothing
 * here calls a provider, Circle, Gateway or Arc endpoint, signs, settles or
 * moves funds: the "answers" are written straight into the recorder, exactly as
 * a classified lookup would be.
 */

const TRANSFER = '3f1c1b7e-8a1d-4f5e-9b2a-1c2d3e4f5a6b';
const OTHER_TRANSFER = '9a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d';
const BATCH = `0x${'ab'.repeat(32)}`;

const SCHEMA17_FUNCTIONS: readonly {
  name: string; sig: string; definer: boolean; worker: boolean;
}[] = [
  {
    name: 'claim_payment_attempt_observations',
    sig: 'openarc_durable.claim_payment_attempt_observations(integer)',
    definer: true, worker: true,
  },
  {
    name: 'record_leased_payment_attempt_observation',
    sig: 'openarc_durable.record_leased_payment_attempt_observation(text, uuid, bigint, text, uuid, text, text)',
    definer: true, worker: true,
  },
  {
    name: 'release_payment_attempt_observation_lease',
    sig: 'openarc_durable.release_payment_attempt_observation_lease(text, uuid, bigint)',
    definer: true, worker: true,
  },
  {
    // Granted by THIS migration to the worker role and to nobody else.
    name: 'record_payment_attempt_observation',
    sig: 'openarc_durable.record_payment_attempt_observation(text, uuid, text, uuid, text, text)',
    definer: true, worker: true,
  },
  {
    name: 'enforce_observation_lease_mutation',
    sig: 'openarc_durable.enforce_observation_lease_mutation()',
    definer: false, worker: false,
  },
];

let admin: Pool;
let migrator: ReturnType<typeof createDatabasePool>;
let tenant: ReturnType<typeof createDatabasePool>;
let worker: ReturnType<typeof createDatabasePool>;
let store: SettlementObservationStore;
let fixture: PaymentAttemptFixture;

beforeAll(async () => {
  admin = adminPool();
  await ensureRoles(admin);
  migrator = createDatabasePool(migratorUrl());
  tenant = createDatabasePool(tenantUrl());
  worker = createDatabasePool(workerUrl());
});

afterAll(async () => {
  try {
    await resetSchema(admin);
  } finally {
    await worker.end();
    await tenant.end();
    await migrator.end();
    await admin.end();
  }
});

beforeEach(async () => {
  await resetSchema(admin);
  await migrate(migrator);
  store = new SettlementObservationStore(worker);
  fixture = new PaymentAttemptFixture({ admin, tenant });
});

async function rawError(promise: Promise<unknown>): Promise<{ code?: string }> {
  try {
    await promise;
  } catch (error) {
    return error as { code?: string };
  }
  throw new Error('expected a rejection');
}

async function attemptRow(attemptId: string): Promise<Record<string, unknown>> {
  const result = await admin.query<Record<string, unknown>>(
    'SELECT * FROM openarc_durable.payment_attempts WHERE attempt_id = $1::uuid',
    [attemptId],
  );
  return result.rows[0]!;
}

async function leaseRow(attemptId: string): Promise<Record<string, unknown> | undefined> {
  const result = await admin.query<Record<string, unknown>>(
    'SELECT * FROM openarc_durable.payment_attempt_observation_leases WHERE attempt_id = $1::uuid',
    [attemptId],
  );
  return result.rows[0];
}

function committedOf(attempt: DispatchedAttempt, leaseGeneration: string) {
  return {
    organizationId: attempt.organizationId,
    attemptId: attempt.attemptId,
    leaseGeneration,
    state: 'committed' as const,
    transferId: TRANSFER,
    gatewayStatus: 'completed' as const,
    batchTxHash: BATCH,
  };
}

function pendingOf(attempt: DispatchedAttempt, leaseGeneration: string) {
  return {
    organizationId: attempt.organizationId,
    attemptId: attempt.attemptId,
    leaseGeneration,
    state: 'pending' as const,
    transferId: TRANSFER,
    gatewayStatus: 'received' as const,
    batchTxHash: null,
  };
}

// ---------------------------------------------------------------------------
describe('schema17 manifest, ownership, ACLs and readiness', () => {
  it('records schema17 and gives the observation surface to the worker role alone', async () => {
    const applied = await admin.query<{ id: string }>(
      'SELECT id FROM openarc_meta.schema_migrations ORDER BY id',
    );
    expect(applied.rows.map((row) => row.id).slice(-3)).toEqual([
      '0016_evidence_store', '0017_settlement_observation', '0018_operator_reads',
    ]);

    const table = await admin.query<{
      enabled: boolean; forced: boolean; owner: string; public_acl: number;
    }>(
      `SELECT c.relrowsecurity AS enabled, c.relforcerowsecurity AS forced, r.rolname AS owner,
              (SELECT count(*)::int FROM aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
                WHERE a.grantee <> c.relowner) AS public_acl
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_roles r ON r.oid = c.relowner
        WHERE n.nspname = 'openarc_durable' AND c.relname = 'payment_attempt_observation_leases'`,
    );
    expect(table.rows[0]).toEqual({
      enabled: true, forced: true, owner: 'openarc_migrator', public_acl: 0,
    });

    const acl = await admin.query<{
      proname: string; worker: boolean; app: boolean; auth: boolean; pub: number;
      secdef: boolean; config: string[]; grantees: string[];
    }>(
      `SELECT p.proname,
              has_function_privilege('openarc_worker_app', p.oid, 'EXECUTE') AS worker,
              has_function_privilege('openarc_tenant_app', p.oid, 'EXECUTE') AS app,
              has_function_privilege('openarc_auth_app', p.oid, 'EXECUTE') AS auth,
              (SELECT count(*)::int FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE') AS pub,
              p.prosecdef AS secdef, coalesce(p.proconfig, ARRAY[]::text[]) AS config,
              ARRAY(SELECT coalesce(g.rolname::text, 'PUBLIC')
                      FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                      LEFT JOIN pg_roles g ON g.oid = a.grantee ORDER BY 1) AS grantees
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'openarc_durable' AND p.proname = ANY ($1::text[])
        ORDER BY p.proname`,
      [SCHEMA17_FUNCTIONS.map((entry) => entry.name)],
    );
    expect(acl.rows).toHaveLength(SCHEMA17_FUNCTIONS.length);
    for (const expected of SCHEMA17_FUNCTIONS) {
      const row = acl.rows.find((candidate) => candidate.proname === expected.name)!;
      // The worker, and ONLY the worker: never the tenant runtime, never auth,
      // never PUBLIC.
      expect([expected.name, row.worker, row.app, row.auth, row.pub])
        .toEqual([expected.name, expected.worker, false, false, 0]);
      expect([expected.name, row.secdef, row.config])
        .toEqual([expected.name, expected.definer, ['search_path=pg_catalog']]);
      expect([expected.name, row.grantees]).toEqual([expected.name,
        expected.worker ? ['openarc_migrator', 'openarc_worker_app'] : ['openarc_migrator']]);
    }

    // The migration grants the tenant runtime nothing and adds no outbox event.
    const sql = loadMigrations().find((m) => m.id === '0017_settlement_observation')!.sql;
    expect(sql).not.toMatch(/GRANT[^;]*openarc_tenant_app/);
    expect(sql).not.toMatch(/GRANT[^;]*ON TABLE/);
    expect(sql).not.toContain('outbox_events');
    // The migration documents and applies the single-principal decision.
    expect(sql).toMatch(/GRANT[^;]*record_payment_attempt_observation[^;]*openarc_worker_app/);

    await store.readiness();
    await store.initialize();
  }, 120000);

  it('keeps every runtime role off the observation surface and both tables', async () => {
    const attempt = await fixture.seedDispatchedAttempt(10);
    for (const [label, pool] of [['tenant', tenant], ['worker', worker]] as const) {
      for (const sql of [
        'SELECT count(*) FROM openarc_durable.payment_attempt_observation_leases',
        'SELECT count(*) FROM openarc_durable.payment_attempts',
        "UPDATE openarc_durable.payment_attempts SET state = 'committed'",
        'DELETE FROM openarc_durable.payment_attempt_observation_leases',
      ]) {
        expect([label, sql, (await rawError(pool.query(sql))).code]).toEqual([label, sql, '42501']);
      }
    }
    // The tenant runtime cannot reach ANY observation entry point.
    for (const [sql, values] of [
      ['SELECT * FROM openarc_durable.claim_payment_attempt_observations($1)', [1]],
      [
        'SELECT * FROM openarc_durable.record_leased_payment_attempt_observation($1, $2::uuid, $3::bigint, $4, $5::uuid, $6, $7)',
        [attempt.organizationId, attempt.attemptId, '1', 'committed', TRANSFER, 'completed', BATCH],
      ],
      [
        'SELECT openarc_durable.release_payment_attempt_observation_lease($1, $2::uuid, $3::bigint)',
        [attempt.organizationId, attempt.attemptId, '1'],
      ],
      [
        'SELECT * FROM openarc_durable.record_payment_attempt_observation($1, $2::uuid, $3, $4::uuid, $5, $6)',
        [attempt.organizationId, attempt.attemptId, 'committed', TRANSFER, 'completed', BATCH],
      ],
    ] as const) {
      expect((await rawError(tenant.query(sql, [...values]))).code).toBe('42501');
    }
    expect(await attemptRow(attempt.attemptId)).toMatchObject({ state: 'unknown', observed_at: null });
  }, 180000);

  it('readiness passes, then fails for EVERY helper, grant, trigger and table guard that drifts', async () => {
    await store.readiness();
    const expectUnready = async (label: string): Promise<void> => {
      try {
        await new SettlementObservationStore(worker).readiness();
      } catch (error) {
        expect([label, (error as SettlementObservationStoreError).code])
          .toEqual([label, 'SETTLEMENT_OBSERVATION_STORE_UNAVAILABLE']);
        return;
      }
      throw new Error(`readiness unexpectedly passed: ${label}`);
    };

    for (const helper of SCHEMA17_FUNCTIONS) {
      // Missing.
      await migrator.query(`ALTER FUNCTION ${helper.sig} RENAME TO ${helper.name}_gone`);
      await expectUnready(`${helper.name}:missing`);
      await migrator.query(
        `ALTER FUNCTION ${helper.sig.replace(`.${helper.name}(`, `.${helper.name}_gone(`)} RENAME TO ${helper.name}`,
      );
      // Mis-signed: definer flag flipped.
      await migrator.query(`ALTER FUNCTION ${helper.sig} ${helper.definer ? 'SECURITY INVOKER' : 'SECURITY DEFINER'}`);
      await expectUnready(`${helper.name}:security`);
      await migrator.query(`ALTER FUNCTION ${helper.sig} ${helper.definer ? 'SECURITY DEFINER' : 'SECURITY INVOKER'}`);
      // search_path no longer pinned.
      await migrator.query(`ALTER FUNCTION ${helper.sig} RESET search_path`);
      await expectUnready(`${helper.name}:search_path`);
      await migrator.query(`ALTER FUNCTION ${helper.sig} SET search_path = pg_catalog`);
      // Widened to PUBLIC.
      await migrator.query(`GRANT EXECUTE ON FUNCTION ${helper.sig} TO PUBLIC`);
      await expectUnready(`${helper.name}:public`);
      await migrator.query(`REVOKE EXECUTE ON FUNCTION ${helper.sig} FROM PUBLIC`);
      // Worker reachability flipped: the packet's whole grant decision.
      await migrator.query(helper.worker
        ? `REVOKE EXECUTE ON FUNCTION ${helper.sig} FROM openarc_worker_app`
        : `GRANT EXECUTE ON FUNCTION ${helper.sig} TO openarc_worker_app`);
      await expectUnready(`${helper.name}:worker`);
      await migrator.query(helper.worker
        ? `GRANT EXECUTE ON FUNCTION ${helper.sig} TO openarc_worker_app`
        : `REVOKE EXECUTE ON FUNCTION ${helper.sig} FROM openarc_worker_app`);
      // Leaked to the tenant runtime, which must NEVER record an observation.
      await migrator.query(`GRANT EXECUTE ON FUNCTION ${helper.sig} TO openarc_tenant_app`);
      await expectUnready(`${helper.name}:tenant_leak`);
      await migrator.query(`REVOKE EXECUTE ON FUNCTION ${helper.sig} FROM openarc_tenant_app`);
      await store.readiness();
    }

    // A second overload (for example one taking a caller-chosen state) is not ready.
    await migrator.query(
      `CREATE FUNCTION openarc_durable.claim_payment_attempt_observations(a integer, b text)
       RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS $$ SELECT $$`,
    );
    await migrator.query(
      'REVOKE ALL ON FUNCTION openarc_durable.claim_payment_attempt_observations(integer, text) FROM PUBLIC',
    );
    await expectUnready('claim:overload');
    await migrator.query('DROP FUNCTION openarc_durable.claim_payment_attempt_observations(integer, text)');

    // A disabled guard trigger is not ready.
    for (const [table, trigger] of [
      ['openarc_durable.payment_attempt_observation_leases', 'payment_attempt_observation_leases_mutation'],
      ['openarc_durable.payment_attempts', 'payment_attempts_mutation'],
    ] as const) {
      await migrator.query(`ALTER TABLE ${table} DISABLE TRIGGER ${trigger}`);
      await expectUnready(`${trigger}:disabled`);
      await migrator.query(`ALTER TABLE ${table} ENABLE TRIGGER ${trigger}`);
    }

    // Unforced RLS or ANY worker table privilege is not ready.
    for (const table of [
      'openarc_durable.payment_attempts',
      'openarc_durable.payment_attempt_observation_leases',
    ]) {
      await migrator.query(`ALTER TABLE ${table} NO FORCE ROW LEVEL SECURITY`);
      await expectUnready(`${table}:unforced`);
      await migrator.query(`ALTER TABLE ${table} FORCE ROW LEVEL SECURITY`);
      await migrator.query(`GRANT SELECT ON TABLE ${table} TO openarc_worker_app`);
      await expectUnready(`${table}:worker_select`);
      await migrator.query(`REVOKE SELECT ON TABLE ${table} FROM openarc_worker_app`);
    }
    await store.readiness();
  }, 300000);
});

// ---------------------------------------------------------------------------
describe('what may be leased', () => {
  it('never leases a persisted attempt: it was never dispatched, so there is no exposure', async () => {
    const attempt = await fixture.seedDispatchedAttempt(20, { dispatch: false });
    expect(attempt.state).toBe('persisted');
    expect(await store.claim({ limit: 10 })).toEqual([]);
    expect(await leaseRow(attempt.attemptId)).toBeUndefined();
    expect(await attemptRow(attempt.attemptId)).toMatchObject({ state: 'persisted', observed_at: null });
  }, 180000);

  it('leases a dispatched unknown attempt and returns its exact durable binding', async () => {
    const attempt = await fixture.seedDispatchedAttempt(21);
    const leased = await store.claim({ limit: 10 });
    expect(leased).toHaveLength(1);
    expect(leased[0]).toMatchObject({
      organizationId: attempt.organizationId,
      attemptId: attempt.attemptId,
      grantId: attempt.grantId,
      actionId: attempt.actionId,
      requirementDigest: attempt.requirementDigest,
      laneRequirementDigest: attempt.laneRequirementDigest,
      networkId: 'eip155:5042002',
      payerAddress: attempt.payerAddress,
      payToAddress: attempt.payToAddress,
      valueAtomic: attempt.valueAtomic,
      nonce: attempt.nonce,
      state: 'unknown',
      leaseGeneration: '1',
      attemptCount: 1,
    });
    // No secret material is representable in a lease.
    const serialized = JSON.stringify(leased[0]);
    expect(serialized).not.toContain(attempt.commerceTokenHash);
    expect(serialized.toLowerCase()).not.toContain('signature');
  }, 180000);

  it('re-leases a pending attempt but never a committed one: committed is terminal', async () => {
    const attempt = await fixture.seedDispatchedAttempt(22);
    const first = await store.claim({ limit: 10 });
    expect(first[0]!.state).toBe('unknown');
    await store.recordObservation(pendingOf(attempt, first[0]!.leaseGeneration));
    expect(await attemptRow(attempt.attemptId)).toMatchObject({ state: 'pending' });

    // Still held, so still observable.
    const second = await store.claim({ limit: 10 });
    expect(second).toHaveLength(1);
    expect(second[0]).toMatchObject({ state: 'pending', leaseGeneration: '2', attemptCount: 2 });

    await store.recordObservation(committedOf(attempt, second[0]!.leaseGeneration));
    expect(await attemptRow(attempt.attemptId)).toMatchObject({
      state: 'committed', gateway_status: 'completed', batch_tx_hash: BATCH,
    });
    // Terminal: never leasable again, by any worker, ever.
    expect(await store.claim({ limit: 10 })).toEqual([]);
  }, 180000);

  it('stops leasing an attempt once the bounded retry ceiling is reached', async () => {
    const attempt = await fixture.seedDispatchedAttempt(23);
    for (let round = 1; round <= 10; round += 1) {
      const leased = await store.claim({ limit: 10 });
      expect([round, leased.length]).toEqual([round, 1]);
      expect([round, leased[0]!.attemptCount]).toEqual([round, round]);
      // Every round is an unclear answer: nothing is ever written.
      await store.releaseLease(attempt.organizationId, attempt.attemptId, leased[0]!.leaseGeneration);
    }
    expect(await store.claim({ limit: 10 })).toEqual([]);
    // The attempt is NOT failed or released: it simply stays exactly as held.
    expect(await attemptRow(attempt.attemptId)).toMatchObject({
      state: 'unknown', observed_at: null, transfer_id: null, gateway_status: null,
    });
  }, 180000);
});

// ---------------------------------------------------------------------------
describe('lease exclusivity', () => {
  it('never hands the same attempt to two concurrent workers', async () => {
    const attempts: DispatchedAttempt[] = [];
    for (const seed of [30, 31, 32]) {
      attempts.push(await fixture.seedDispatchedAttempt(seed));
    }
    const other = new SettlementObservationStore(createDatabasePool(workerUrl()));
    let first: LeasedPaymentAttempt[];
    let second: LeasedPaymentAttempt[];
    try {
      [first, second] = await Promise.all([store.claim({ limit: 3 }), other.claim({ limit: 3 })]);
    } finally {
      // The extra pool is closed through the store's own pool handle below.
    }
    const firstIds = first.map((entry) => entry.attemptId);
    const secondIds = second.map((entry) => entry.attemptId);
    expect(firstIds.filter((id) => secondIds.includes(id))).toEqual([]);
    expect(new Set([...firstIds, ...secondIds]).size).toBe(firstIds.length + secondIds.length);
    expect(firstIds.length + secondIds.length).toBeLessThanOrEqual(attempts.length);
    // A third claim while both leases are live returns nothing left over.
    const remaining = await store.claim({ limit: 3 });
    const all = [...firstIds, ...secondIds, ...remaining.map((entry) => entry.attemptId)];
    expect(new Set(all).size).toBe(all.length);
    expect(all.length).toBe(attempts.length);
  }, 300000);

  it('refuses a stale or already-consumed lease generation without changing anything', async () => {
    const attempt = await fixture.seedDispatchedAttempt(33);
    const leased = await store.claim({ limit: 1 });
    const generation = leased[0]!.leaseGeneration;
    // A generation that was never issued records nothing.
    expect(await store.recordObservation(committedOf(attempt, '99'))).toBeNull();
    expect(await attemptRow(attempt.attemptId)).toMatchObject({ state: 'unknown', observed_at: null });

    // The real generation records once...
    expect(await store.recordObservation(pendingOf(attempt, generation))).toMatchObject({
      state: 'pending', transferId: TRANSFER, gatewayStatus: 'received',
    });
    // ...and the SAME generation can never record again: the lease is consumed.
    expect(await store.recordObservation(committedOf(attempt, generation))).toBeNull();
    expect(await attemptRow(attempt.attemptId)).toMatchObject({
      state: 'pending', gateway_status: 'received',
    });
  }, 180000);
});

// ---------------------------------------------------------------------------
describe('observation outcomes', () => {
  it('an unclear answer changes absolutely nothing on the attempt', async () => {
    const attempt = await fixture.seedDispatchedAttempt(40);
    const before = await attemptRow(attempt.attemptId);
    const leased = await store.claim({ limit: 1 });
    // The worker simply releases: no observation is recorded at all.
    expect(await store.releaseLease(
      attempt.organizationId, attempt.attemptId, leased[0]!.leaseGeneration,
    )).toEqual({ released: true });
    const after = await attemptRow(attempt.attemptId);
    expect(after).toEqual(before);
    expect(after).toMatchObject({
      state: 'unknown', observed_at: null, transfer_id: null,
      gateway_status: null, batch_tx_hash: null,
    });
    // And it is immediately claimable again, with a fresh generation.
    const again = await store.claim({ limit: 1 });
    expect(again[0]).toMatchObject({ attemptId: attempt.attemptId, leaseGeneration: '2' });
  }, 180000);

  it('a positive observation advances the attempt exactly once', async () => {
    const attempt = await fixture.seedDispatchedAttempt(41);
    const leased = await store.claim({ limit: 1 });
    const recorded = await store.recordObservation(committedOf(attempt, leased[0]!.leaseGeneration));
    expect(recorded).toMatchObject({
      organizationId: attempt.organizationId,
      attemptId: attempt.attemptId,
      state: 'committed',
      transferId: TRANSFER,
      gatewayStatus: 'completed',
      batchTxHash: BATCH,
    });
    const row = await attemptRow(attempt.attemptId);
    expect(row).toMatchObject({ state: 'committed', transfer_id: TRANSFER, batch_tx_hash: BATCH });
    expect(row['observed_at']).not.toBeNull();
    // A second observation of any kind cannot move a committed attempt.
    expect(await store.claim({ limit: 10 })).toEqual([]);
    expect(await attemptRow(attempt.attemptId)).toEqual(row);
  }, 180000);

  it('refuses a different transfer id for an attempt already bound to one', async () => {
    const attempt = await fixture.seedDispatchedAttempt(42);
    const first = await store.claim({ limit: 1 });
    await store.recordObservation(pendingOf(attempt, first[0]!.leaseGeneration));
    const second = await store.claim({ limit: 1 });
    await expect(store.recordObservation({
      ...committedOf(attempt, second[0]!.leaseGeneration),
      transferId: OTHER_TRANSFER,
    })).rejects.toMatchObject({ code: 'SETTLEMENT_OBSERVATION_STORE_ATTEMPT_CONFLICT' });
    expect(await attemptRow(attempt.attemptId)).toMatchObject({
      state: 'pending', transfer_id: TRANSFER,
    });
  }, 180000);
});

// ---------------------------------------------------------------------------
describe('cross-organization isolation', () => {
  it('cannot observe one organization\'s attempt under another organization id', async () => {
    const mine = await fixture.seedDispatchedAttempt(50);
    const theirs = await fixture.seedDispatchedAttempt(60);
    expect(mine.organizationId).not.toBe(theirs.organizationId);
    const leased = await store.claim({ limit: 10 });
    expect(leased).toHaveLength(2);
    const mineLease = leased.find((entry) => entry.attemptId === mine.attemptId)!;

    // The other organization's id does not name this attempt: nothing is written.
    expect(await store.recordObservation({
      ...committedOf(mine, mineLease.leaseGeneration),
      organizationId: theirs.organizationId,
    })).toBeNull();
    expect(await store.recordObservation({
      ...committedOf(theirs, mineLease.leaseGeneration),
      attemptId: mine.attemptId,
    })).toBeNull();
    expect(await store.releaseLease(
      theirs.organizationId, mine.attemptId, mineLease.leaseGeneration,
    )).toEqual({ released: false });

    for (const attempt of [mine, theirs]) {
      expect([attempt.attemptId, await attemptRow(attempt.attemptId)]).toEqual([
        attempt.attemptId,
        expect.objectContaining({ state: 'unknown', observed_at: null, transfer_id: null }),
      ]);
    }

    // Each organization's own lease still works, and touches only its own row.
    expect(await store.recordObservation(committedOf(mine, mineLease.leaseGeneration)))
      .toMatchObject({ organizationId: mine.organizationId, state: 'committed' });
    expect(await attemptRow(mine.attemptId)).toMatchObject({ state: 'committed' });
    expect(await attemptRow(theirs.attemptId)).toMatchObject({ state: 'unknown', observed_at: null });
  }, 300000);
});
