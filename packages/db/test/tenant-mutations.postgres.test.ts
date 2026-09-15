import { createHash } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import { OutboxStore, TenantStore, migrate } from '../src/index.js';
import { loadMigrations } from '../src/index.js';
import {
  adminPool,
  ensureRoles,
  migratorUrl,
  resetSchema,
  tenantUrl,
  workerUrl,
} from './postgres-fixture.js';
import { createDatabasePool } from '../src/index.js';

/**
 * Real PostgreSQL acceptance for the additive schema4 durable tenant writes.
 * Runs only against the restricted runtime roles; seeds use the admin fixture.
 */

function sha256(seed: string): string {
  return createHash('sha256').update(`openarc-tenant-mutations-test:${seed}`, 'utf8').digest('hex');
}

function uuid(seed: number): string {
  return `00000000-0000-4000-8000-${String(seed).padStart(12, '0')}`;
}

function accountId(seed: number): string {
  return `openarc:account:${uuid(seed)}`;
}

function orgId(seed: number): string {
  return `openarc:org:${uuid(seed)}`;
}

function agentId(seed: number): string {
  return `openarc:agent:${uuid(seed)}`;
}

function providerId(seed: number): string {
  return `openarc:provider:${uuid(seed)}`;
}

function mutationId(seed: number): string {
  return uuid(100000 + seed);
}

function userHandle(seed: number): string {
  return `${sha256(`handle:${seed}`).slice(0, 42)}A`;
}

function base64Key(seed: number): string {
  return createHash('sha256').update(`key:${seed}`).digest().toString('base64url');
}

interface PgError {
  code?: string;
}

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect((error as { code?: string }).code).toBe(code);
    return;
  }
  throw new Error(`expected TenantStoreError ${code}`);
}

async function expectConstraint(promise: Promise<unknown>, constraint: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    const caught = error as { code?: string; constraint?: string };
    expect(caught.code).toBe('23514');
    expect(caught.constraint).toBe(constraint);
    return;
  }
  throw new Error(`expected check violation ${constraint}`);
}

let admin: Pool;
let migrator: Pool;
let tenant: Pool;
let worker: Pool;
let store: TenantStore;
let outbox: OutboxStore;

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
  store = new TenantStore(tenant);
  outbox = new OutboxStore(worker);
});

async function seedAccount(seed: number, status = 'active'): Promise<string> {
  const id = accountId(seed);
  await admin.query(
    'INSERT INTO openarc_auth.accounts (account_id, user_handle, status) VALUES ($1, $2, $3)',
    [id, userHandle(seed), status],
  );
  return id;
}

async function seedSession(
  seed: number,
  account: string,
  options: { method?: string; createdOffset?: string; expiresOffset?: string } = {},
): Promise<string> {
  const hash = sha256(`session:${seed}`);
  await admin.query(
    `INSERT INTO openarc_auth.sessions (token_hash, account_id, method, created_at, expires_at)
     VALUES ($1, $2, $3, now() + ($4)::interval, now() + ($5)::interval)`,
    [
      hash,
      account,
      options.method ?? 'passkey',
      options.createdOffset ?? '0 minutes',
      options.expiresOffset ?? '24 hours',
    ],
  );
  return hash;
}

async function seedOwner(
  seed: number,
  role = 'owner',
): Promise<{ account: string; org: string; hash: string }> {
  const account = await seedAccount(seed);
  const hash = await seedSession(seed, account);
  const org = orgId(seed);
  await admin.query(
    "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Org', $2)",
    [org, account],
  );
  await admin.query(
    'INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, $3, $4)',
    [org, account, role, 'active'],
  );
  return { account, org, hash };
}

async function seedMembership(
  org: string,
  account: string,
  role: string,
  status = 'active',
): Promise<void> {
  await admin.query(
    'INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, $3, $4)',
    [org, account, role, status],
  );
}

async function tenantCounts(): Promise<Record<string, number>> {
  const result = await admin.query<Record<string, number>>(
    `SELECT
       (SELECT count(*)::int FROM openarc_tenant.organizations) AS organizations,
       (SELECT count(*)::int FROM openarc_tenant.memberships) AS memberships,
       (SELECT count(*)::int FROM openarc_tenant.agents) AS agents,
       (SELECT count(*)::int FROM openarc_tenant.providers) AS providers,
       (SELECT count(*)::int FROM openarc_durable.idempotency_records) AS idem,
       (SELECT count(*)::int FROM openarc_durable.audit_events) AS audit,
       (SELECT count(*)::int FROM openarc_durable.outbox_events) AS outbox`,
  );
  const row = result.rows[0];
  if (row === undefined) throw new Error('counts failed');
  return row;
}

async function waitForLockWait(): Promise<void> {
  for (let attempt = 0; attempt < 400; attempt += 1) {
    const probe = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM pg_stat_activity
        WHERE datname = current_database() AND wait_event_type = 'Lock' AND pid <> pg_backend_pid()`,
    );
    if ((probe.rows[0]?.n ?? 0) > 0) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error('no lock wait observed');
}

async function waitUntilSessionExpired(hash: string): Promise<void> {
  for (let attempt = 0; attempt < 400; attempt += 1) {
    const probe = await admin.query<{ expired: boolean }>(
      `SELECT clock_timestamp() >= expires_at AS expired FROM openarc_auth.sessions WHERE token_hash = $1`,
      [hash],
    );
    if (probe.rows[0]?.expired === true) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error('session did not expire');
}

async function shortenSession(hash: string, seconds: number): Promise<void> {
  await admin.query(
    `UPDATE openarc_auth.sessions SET expires_at = clock_timestamp() + make_interval(secs => $2)
      WHERE token_hash = $1`,
    [hash, seconds],
  );
}

function assertPoolContextReleased(pool: Pool): void {
  expect(pool.totalCount - pool.idleCount).toBe(0);
}

describe('schema4 manifest and unions', () => {
  it('records schema4 and keeps every helper migrator-owned with fixed search_path', async () => {
    const applied = await admin.query<{ id: string }>(
      'SELECT id FROM openarc_meta.schema_migrations ORDER BY id',
    );
    expect(applied.rows.map((row) => row.id)).toEqual([
      '0001_auth',
      '0002_tenants',
      '0003_durability',
      '0004_durable_tenant_mutations',
      '0005_machine_credentials',
      '0006_market',
      '0007_market_lifecycle',
      '0008_control_policies',
      '0009_control_sessions',
      '0010_control_actions',
      '0011_control_action_reads',
      '0012_authorization_grants',
      '0013_commerce_session_reads',
      '0014_grant_mutation_reads',
    ]);
    const helpers = await admin.query<{ proname: string; owner: string; secdef: boolean; config: string[] }>(
      `SELECT p.proname, r.rolname AS owner, p.prosecdef AS secdef,
              coalesce(p.proconfig, ARRAY[]::text[]) AS config
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         JOIN pg_roles r ON r.oid = p.proowner
        WHERE n.nspname = 'openarc_durable' AND p.prokind = 'f'
        ORDER BY p.proname`,
    );
    expect(helpers.rows.every((row) => row.owner === 'openarc_migrator')).toBe(true);
    const definers = helpers.rows.filter(
      (row) =>
        row.proname.startsWith('commit_') ||
        row.proname.startsWith('read_') ||
        row.proname.startsWith('lock_'),
    );
    const bad = definers.filter((row) => {
      const definer = row.secdef === true;
      const pinned = Array.isArray(row.config) && row.config.includes('search_path=pg_catalog');
      return !definer || !pinned;
    });
    expect(bad).toEqual([]);
    const publicGrants = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM pg_proc p,
            aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
        WHERE p.pronamespace = 'openarc_durable'::regnamespace
          AND a.grantee = 0 AND a.privilege_type = 'EXECUTE'`,
    );
    expect(publicGrants.rows[0]?.n).toBe(0);
  });

  it('denies direct durable DML to the tenant runtime for every new kind', async () => {
    const owner = await seedOwner(1);
    await expect(tenant.query('INSERT INTO openarc_durable.idempotency_records (organization_id, operation, key_hash, request_digest, digest_version, actor_account_id, session_context_digest, network, mutation_id, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)', [owner.org, 'tenant.provider.create', sha256('k'), sha256('d'), 'tenant.provider.create.v1', owner.account, sha256('s'), 'eip155:5042002', mutationId(1), 'pending'])).rejects.toBeTruthy();
    await expect(tenant.query('UPDATE openarc_durable.outbox_events SET attempt_count = 5')).rejects.toBeTruthy();
    expect((await tenantCounts()).idem).toBe(0);
  });

  it('enforces asymmetric typed FK links by kind', async () => {
    const owner = await seedOwner(2);
    // An agent-kind receipt may not point at a provider id.
    await expect(
      admin.query(
        `INSERT INTO openarc_durable.idempotency_records
           (organization_id, operation, key_hash, request_digest, digest_version,
            actor_account_id, session_context_digest, network, mutation_id,
            status, resource_type, resource_id, committed_at)
         VALUES ($1, 'tenant.agent.create', $2, $3, 'tenant.agent.create.v1',
                 $4, $5, 'eip155:5042002', $6::uuid, 'committed', 'agent', $7, clock_timestamp())`,
        [owner.org, sha256('fk1'), sha256('fk1d'), owner.account, sha256('fk1s'), mutationId(2), providerId(2)],
      ),
    ).rejects.toBeTruthy();
    // A membership-kind receipt may not point at an account with no membership.
    await expect(
      admin.query(
        `INSERT INTO openarc_durable.idempotency_records
           (organization_id, operation, key_hash, request_digest, digest_version,
            actor_account_id, session_context_digest, network, mutation_id,
            status, resource_type, resource_id, committed_at)
         VALUES ($1, 'tenant.membership.set', $2, $3, 'tenant.membership.set.v1',
                 $4, $5, 'eip155:5042002', $6::uuid, 'committed', 'membership', $7, clock_timestamp())`,
        [owner.org, sha256('fk2'), sha256('fk2d'), owner.account, sha256('fk2s'), mutationId(3), accountId(999)],
      ),
    ).rejects.toBeTruthy();
  });

  it('binds an outbox event to the exact receipt operation', async () => {
    const owner = await seedOwner(3);
    const result = await store.createProviderDurably(owner.hash, owner.org, 'P', {
      idempotencyKey: base64Key(3),
      mutationId: mutationId(3),
    });
    const wrong = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM openarc_durable.outbox_events
        WHERE organization_id = $1 AND event_type = 'tenant.provider.updated'`,
      [owner.org],
    );
    expect(wrong.rows[0]?.n).toBe(0);
    expect(result.receipt.operation).toBe('tenant.provider.create');
    await expect(
      admin.query(
        `INSERT INTO openarc_durable.outbox_events
           (organization_id, mutation_id, resource_type, resource_id, event_type, payload_version)
         VALUES ($1, $2::uuid, 'provider', $3, 'tenant.provider.updated', 1)`,
        [owner.org, mutationId(3), result.receipt.resourceId],
      ),
    ).rejects.toBeTruthy();
  });

  it('rejects a scoped receipt/audit that names a different organization', async () => {
    const a = await seedOwner(4);
    const b = await seedOwner(5);
    // The single-column organization FK would accept orgB here; the own-org
    // scope check must reject it on the receipt. CHECKs evaluate before the
    // deferred RI triggers, so the named constraint is the new scope guard.
    await expectConstraint(
      admin.query(
        `INSERT INTO openarc_durable.idempotency_records
           (organization_id, operation, key_hash, request_digest, digest_version,
            actor_account_id, session_context_digest, network, mutation_id,
            status, resource_type, resource_id, committed_at)
         VALUES ($1, 'tenant.organization.create', $2, $3, 'tenant.organization.create.v1',
                 $4, $5, 'eip155:5042002', $6::uuid, 'committed', 'organization', $7, clock_timestamp())`,
        [a.org, sha256('xo1'), sha256('xo1d'), a.account, sha256('xo1s'), mutationId(4), b.org],
      ),
      'idempotency_resource_org_scope',
    );
    await expectConstraint(
      admin.query(
        `INSERT INTO openarc_durable.audit_events
           (organization_id, actor_account_id, operation, mutation_id, resource_type, resource_id, outcome)
         VALUES ($1, $2, 'tenant.organization.create', $3::uuid, 'organization', $4, 'committed')`,
        [a.org, a.account, mutationId(4), b.org],
      ),
      'audit_resource_org_scope',
    );
    await expectConstraint(
      admin.query(
        `INSERT INTO openarc_durable.outbox_events
           (organization_id, mutation_id, resource_type, resource_id, event_type, payload_version)
         VALUES ($1, $2::uuid, 'organization', $3, 'tenant.organization.created', 1)`,
        [a.org, mutationId(4), b.org],
      ),
      'outbox_resource_org_scope',
    );
    expect(await tenantCounts()).toMatchObject({ idem: 0, audit: 0, outbox: 0 });
  });

  it('rejects an operation/resource kind mismatch on the receipt and event mappings', async () => {
    const owner = await seedOwner(6);
    // A real same-org provider so the mismatch is caught by the closed union,
    // not by a missing typed parent FK.
    const provider = providerId(6);
    await admin.query(
      "INSERT INTO openarc_tenant.providers (organization_id, provider_id, display_name) VALUES ($1, $2, 'P')",
      [owner.org, provider],
    );
    await expectConstraint(
      admin.query(
        `INSERT INTO openarc_durable.idempotency_records
           (organization_id, operation, key_hash, request_digest, digest_version,
            actor_account_id, session_context_digest, network, mutation_id,
            status, resource_type, resource_id, committed_at)
         VALUES ($1, 'tenant.agent.create', $2, $3, 'tenant.agent.create.v1',
                 $4, $5, 'eip155:5042002', $6::uuid, 'committed', 'provider', $7, clock_timestamp())`,
        [owner.org, sha256('mm1'), sha256('mm1d'), owner.account, sha256('mm1s'), mutationId(6), provider],
      ),
      'idempotency_resource_matches_operation',
    );
    await expectConstraint(
      admin.query(
        `INSERT INTO openarc_durable.audit_events
           (organization_id, actor_account_id, operation, mutation_id, resource_type, resource_id, outcome)
         VALUES ($1, $2, 'tenant.agent.create', $3::uuid, 'provider', $4, 'committed')`,
        [owner.org, owner.account, mutationId(6), provider],
      ),
      'audit_resource_matches_operation',
    );
    await expectConstraint(
      admin.query(
        `INSERT INTO openarc_durable.outbox_events
           (organization_id, mutation_id, resource_type, resource_id, event_type, payload_version)
         VALUES ($1, $2::uuid, 'organization', $3, 'tenant.agent.created', 1)`,
        [owner.org, mutationId(6), owner.org],
      ),
      'outbox_resource_matches_event',
    );
    expect(await tenantCounts()).toMatchObject({ idem: 0, audit: 0, outbox: 0 });
  });
});

describe('schema3 to schema4 upgrade', () => {
  it('preserves committed schema3 rows and replays the original agent create', async () => {
    await resetSchema(admin);
    const base = loadMigrations();
    await migrate(migrator, base.slice(0, 3));
    const owner = await seedOwner(80);
    const created = await store.createAgentDurably(owner.hash, owner.org, 'Legacy', {
      idempotencyKey: base64Key(80),
      mutationId: mutationId(80),
    });
    expect(created.replayed).toBe(false);
    const snapshot = async () =>
      admin.query(
        `SELECT (SELECT row_to_json(r) FROM (
                   SELECT organization_id, operation, key_hash, request_digest, digest_version,
                          actor_account_id, session_context_digest, network, mutation_id, status,
                          resource_type, resource_id, created_at, committed_at
                     FROM openarc_durable.idempotency_records
                    WHERE organization_id = $1 AND mutation_id = $2::uuid) r) AS receipt,
                (SELECT row_to_json(a) FROM (
                   SELECT event_id, organization_id, actor_account_id, operation, mutation_id,
                          resource_type, resource_id, outcome, created_at
                     FROM openarc_durable.audit_events
                    WHERE organization_id = $1 AND mutation_id = $2::uuid) a) AS audit,
                (SELECT row_to_json(o) FROM (
                   SELECT event_id, organization_id, mutation_id, resource_type, resource_id,
                          event_type, payload_version, state, available_at, attempt_count,
                          lease_until, lease_generation, last_failure_code, created_at, completed_at
                     FROM openarc_durable.outbox_events
                    WHERE organization_id = $1 AND mutation_id = $2::uuid) o) AS outbox,
                (SELECT row_to_json(ag) FROM (
                   SELECT agent_id, organization_id, display_name, status, created_at, updated_at
                     FROM openarc_tenant.agents
                    WHERE organization_id = $1 AND agent_id = $3) ag) AS agent`,
        [owner.org, mutationId(80), created.receipt.resourceId],
      );
    const before = await snapshot();
    expect(before.rows[0]?.receipt).not.toBeNull();
    // Apply only the additive schema4 migration.
    await migrate(migrator, base);
    const after = await snapshot();
    expect(after.rows).toEqual(before.rows);
    // The additive typed link columns are populated for the preserved receipt
    // and its children, while non-agent kinds remain NULL.
    const links = await admin.query<{
      agent_id: string;
      provider_id: string | null;
      organization_resource_id: string | null;
      membership_account_id: string | null;
    }>(
      `SELECT agent_id, provider_id, organization_resource_id, membership_account_id
         FROM openarc_durable.idempotency_records
        WHERE organization_id = $1 AND mutation_id = $2::uuid`,
      [owner.org, mutationId(80)],
    );
    expect(links.rows[0]).toEqual({
      agent_id: created.receipt.resourceId,
      provider_id: null,
      organization_resource_id: null,
      membership_account_id: null,
    });
    // The original byte-for-byte agent-create digest still replays exactly.
    const replay = await store.createAgentDurably(owner.hash, owner.org, 'Legacy', {
      idempotencyKey: base64Key(80),
      mutationId: mutationId(80),
    });
    expect(replay.replayed).toBe(true);
    expect(replay.receipt).toEqual(created.receipt);
    expect(await tenantCounts()).toMatchObject({ agents: 1, idem: 1, audit: 1, outbox: 1 });
  });
});

describe('durable organization bootstrap', () => {
  it('creates org + owner + receipt + audit + outbox together', async () => {
    const account = await seedAccount(10);
    const hash = await seedSession(10, account);
    const result = await store.createOrganizationDurably(hash, 'Acme', {
      idempotencyKey: base64Key(10),
      mutationId: mutationId(10),
    });
    expect(result.replayed).toBe(false);
    expect(result.receipt.operation).toBe('tenant.organization.create');
    expect(result.receipt.resourceType).toBe('organization');
    expect(result.receipt.resourceId).toBe(orgId(100010));
    const counts = await tenantCounts();
    expect(counts).toMatchObject({ organizations: 1, memberships: 1, idem: 1, audit: 1, outbox: 1 });
    const status = await store.getOrganizationMutationStatus(hash, mutationId(10));
    expect(status.status).toBe('committed');
    assertPoolContextReleased(tenant);
  });

  it('rolls back everything on an injected outbox failure', async () => {
    const account = await seedAccount(11);
    const hash = await seedSession(11, account);
    await admin.query(
      `CREATE OR REPLACE FUNCTION openarc_durable.test_fail_outbox() RETURNS trigger
       LANGUAGE plpgsql SET search_path = pg_catalog AS $$
       BEGIN RAISE EXCEPTION 'injected' USING ERRCODE = '23514'; END; $$`,
    );
    await admin.query(
      'CREATE TRIGGER test_fail_outbox BEFORE INSERT ON openarc_durable.outbox_events FOR EACH ROW EXECUTE FUNCTION openarc_durable.test_fail_outbox()',
    );
    await expectCode(
      store.createOrganizationDurably(hash, 'Acme', {
        idempotencyKey: base64Key(11),
        mutationId: mutationId(11),
      }),
      'TENANT_STORE_INPUT_INVALID',
    );
    await admin.query('DROP TRIGGER test_fail_outbox ON openarc_durable.outbox_events');
    await admin.query('DROP FUNCTION openarc_durable.test_fail_outbox()');
    expect(await tenantCounts()).toMatchObject({
      organizations: 0,
      memberships: 0,
      idem: 0,
      audit: 0,
      outbox: 0,
    });
  });

  it('replays the same key and conflicts on drift', async () => {
    const account = await seedAccount(12);
    const hash = await seedSession(12, account);
    const first = await store.createOrganizationDurably(hash, 'Acme', {
      idempotencyKey: base64Key(12),
      mutationId: mutationId(12),
    });
    const replay = await store.createOrganizationDurably(hash, 'Acme', {
      idempotencyKey: base64Key(12),
      mutationId: mutationId(12),
    });
    expect(first.replayed).toBe(false);
    expect(replay.replayed).toBe(true);
    expect(replay.receipt).toEqual(first.receipt);
    await expectCode(
      store.createOrganizationDurably(hash, 'Changed', {
        idempotencyKey: base64Key(12),
        mutationId: mutationId(12),
      }),
      'TENANT_STORE_IDEMPOTENCY_CONFLICT',
    );
    expect(await tenantCounts()).toMatchObject({ organizations: 1, memberships: 1, idem: 1 });
  });

  it('serializes concurrent same-key bootstrap to one organization', async () => {
    const account = await seedAccount(13);
    const hash = await seedSession(13, account);
    const attempt = () =>
      store
        .createOrganizationDurably(hash, 'Acme', {
          idempotencyKey: base64Key(13),
          mutationId: mutationId(13),
        })
        .catch((error: unknown) => error);
    const outcomes = await Promise.all([attempt(), attempt(), attempt()]);
    const succeeded = outcomes.filter((outcome) => (outcome as { code?: string }).code === undefined);
    expect(succeeded.length).toBeGreaterThanOrEqual(1);
    expect(await tenantCounts()).toMatchObject({ organizations: 1, memberships: 1, idem: 1, audit: 1, outbox: 1 });
  });

  it('rejects cross-account reuse of the same bootstrap key', async () => {
    const a = await seedAccount(14);
    const b = await seedAccount(15);
    const hashA = await seedSession(14, a);
    const hashB = await seedSession(15, b);
    await store.createOrganizationDurably(hashA, 'A', {
      idempotencyKey: base64Key(14),
      mutationId: mutationId(14),
    });
    await expectCode(
      store.createOrganizationDurably(hashB, 'B', {
        idempotencyKey: base64Key(14),
        mutationId: mutationId(15),
      }),
      'TENANT_STORE_IDEMPOTENCY_CONFLICT',
    );
    expect((await tenantCounts()).organizations).toBe(1);
  });

  it('conflicts when a different key reuses the same derived bootstrap id', async () => {
    const account = await seedAccount(18);
    const hash = await seedSession(18, account);
    const first = await store.createOrganizationDurably(hash, 'First', {
      idempotencyKey: base64Key(18),
      mutationId: mutationId(18),
    });
    expect(first.replayed).toBe(false);
    await expectCode(
      store.createOrganizationDurably(hash, 'Second', {
        idempotencyKey: base64Key(19),
        mutationId: mutationId(18),
      }),
      'TENANT_STORE_IDEMPOTENCY_CONFLICT',
    );
    expect(await tenantCounts()).toMatchObject({
      organizations: 1,
      memberships: 1,
      idem: 1,
      audit: 1,
      outbox: 1,
    });
  });

  it('serializes concurrent different-key bootstrap on one derived organization', async () => {
    const account = await seedAccount(28);
    const hash = await seedSession(28, account);
    const attempt = (key: string) =>
      store
        .createOrganizationDurably(hash, 'Concurrent', {
          idempotencyKey: key,
          mutationId: mutationId(28),
        })
        .catch((error: unknown) => error);
    const outcomes = await Promise.all([attempt(base64Key(28)), attempt(base64Key(29))]);
    const succeeded = outcomes.filter(
      (outcome) => (outcome as { code?: string }).code === undefined,
    );
    expect(succeeded).toHaveLength(1);
    for (const outcome of outcomes) {
      const code = (outcome as { code?: string }).code;
      if (code !== undefined) {
        // A concurrent different-key loser loses the organization insert race
        // and gets the fixed conflict mapping (the sequential case lands on the
        // idempotency conflict); neither leaks detail or leaves a business row.
        expect(['TENANT_STORE_IDEMPOTENCY_CONFLICT', 'TENANT_STORE_CONFLICT']).toContain(code);
      }
    }
    // No loser-created orphan/pending business rows survived.
    expect(await tenantCounts()).toMatchObject({
      organizations: 1,
      memberships: 1,
      idem: 1,
      audit: 1,
      outbox: 1,
    });
  });

  it('denies recovery and stale proof bootstrap', async () => {
    const account = await seedAccount(16);
    const recovery = await seedSession(16, account, { method: 'recovery' });
    await expectCode(
      store.createOrganizationDurably(recovery, 'R', {
        idempotencyKey: base64Key(16),
        mutationId: mutationId(16),
      }),
      'TENANT_STORE_SESSION_INVALID',
    );
    const stale = await seedSession(17, account, {
      createdOffset: '-6 minutes',
      expiresOffset: '30 minutes',
    });
    await expectCode(
      store.createOrganizationDurably(stale, 'S', {
        idempotencyKey: base64Key(17),
        mutationId: mutationId(17),
      }),
      'TENANT_STORE_SESSION_INVALID',
    );
    expect((await tenantCounts()).organizations).toBe(0);
  });
});

describe('durable agent and provider updates', () => {
  it('updates an agent and replays without a second action', async () => {
    const owner = await seedOwner(20);
    await admin.query(
      "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name) VALUES ($1, $2, 'Old')",
      [owner.org, agentId(20)],
    );
    const first = await store.updateAgentDurably(
      owner.hash,
      owner.org,
      agentId(20),
      { displayName: 'New', status: 'suspended' },
      { idempotencyKey: base64Key(20), mutationId: mutationId(20) },
    );
    expect(first.replayed).toBe(false);
    expect(first.receipt.operation).toBe('tenant.agent.update');
    const replay = await store.updateAgentDurably(
      owner.hash,
      owner.org,
      agentId(20),
      { displayName: 'New', status: 'suspended' },
      { idempotencyKey: base64Key(20), mutationId: mutationId(20) },
    );
    expect(replay.replayed).toBe(true);
    expect((await tenantCounts()).audit).toBe(1);
    const row = await admin.query<{ display_name: string; status: string }>(
      'SELECT display_name, status FROM openarc_tenant.agents WHERE agent_id = $1',
      [agentId(20)],
    );
    expect(row.rows[0]).toEqual({ display_name: 'New', status: 'suspended' });
  });

  it('recovers the receipt for a terminal agent update retry but rejects a new one', async () => {
    const owner = await seedOwner(21);
    await admin.query(
      "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name) VALUES ($1, $2, 'A')",
      [owner.org, agentId(21)],
    );
    await store.updateAgentDurably(
      owner.hash,
      owner.org,
      agentId(21),
      { status: 'revoked' },
      { idempotencyKey: base64Key(21), mutationId: mutationId(21) },
    );
    const replay = await store.updateAgentDurably(
      owner.hash,
      owner.org,
      agentId(21),
      { status: 'revoked' },
      { idempotencyKey: base64Key(21), mutationId: mutationId(21) },
    );
    expect(replay.replayed).toBe(true);
    await expectCode(
      store.updateAgentDurably(
        owner.hash,
        owner.org,
        agentId(21),
        { displayName: 'New' },
        { idempotencyKey: base64Key(22), mutationId: mutationId(22) },
      ),
      'TENANT_STORE_CONFLICT',
    );
  });

  it('keeps provider create/update owner-only and terminal', async () => {
    const owner = await seedOwner(23);
    const operator = await seedAccount(24);
    const operatorHash = await seedSession(24, operator);
    await seedMembership(owner.org, operator, 'operator');
    await expectCode(
      store.createProviderDurably(operatorHash, owner.org, 'P', {
        idempotencyKey: base64Key(23),
        mutationId: mutationId(23),
      }),
      'TENANT_STORE_FORBIDDEN',
    );
    const created = await store.createProviderDurably(owner.hash, owner.org, 'P', {
      idempotencyKey: base64Key(23),
      mutationId: mutationId(23),
    });
    await store.updateProviderDurably(
      owner.hash,
      owner.org,
      created.receipt.resourceId,
      { status: 'retired' },
      { idempotencyKey: base64Key(24), mutationId: mutationId(24) },
    );
    await expectCode(
      store.updateProviderDurably(
        owner.hash,
        owner.org,
        created.receipt.resourceId,
        { status: 'active' },
        { idempotencyKey: base64Key(25), mutationId: mutationId(25) },
      ),
      'TENANT_STORE_CONFLICT',
    );
  });

  it('rejects a stale session after the organization lock wait', async () => {
    const owner = await seedOwner(26);
    await admin.query(
      "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name) VALUES ($1, $2, 'A')",
      [owner.org, agentId(26)],
    );
    await shortenSession(owner.hash, 2);
    const blocker = await admin.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query(
        'SELECT 1 FROM openarc_tenant.organizations WHERE organization_id = $1 FOR UPDATE',
        [owner.org],
      );
      const pending = store.updateAgentDurably(
        owner.hash,
        owner.org,
        agentId(26),
        { displayName: 'Late' },
        { idempotencyKey: base64Key(26), mutationId: mutationId(26) },
      );
      await waitForLockWait();
      await waitUntilSessionExpired(owner.hash);
      await blocker.query('COMMIT');
      await expectCode(pending, 'TENANT_STORE_SESSION_INVALID');
    } finally {
      await blocker.query('ROLLBACK').catch(() => {});
      blocker.release();
    }
    expect((await tenantCounts()).idem).toBe(0);
  });
});

describe('durable new-method identity conflicts', () => {
  it('conflicts on changed key, body, principal and session for a reused mutation id', async () => {
    const owner = await seedOwner(90);
    const otherOwner = await seedAccount(91);
    const otherOwnerHash = await seedSession(91, otherOwner);
    await seedMembership(owner.org, otherOwner, 'owner');
    const created = await store.createProviderDurably(owner.hash, owner.org, 'P', {
      idempotencyKey: base64Key(90),
      mutationId: mutationId(90),
    });
    const provider = created.receipt.resourceId;
    // Changed key, same logical mutation id.
    await expectCode(
      store.updateProviderDurably(owner.hash, owner.org, provider, { displayName: 'Q' }, {
        idempotencyKey: base64Key(91),
        mutationId: mutationId(90),
      }),
      'TENANT_STORE_IDEMPOTENCY_CONFLICT',
    );
    // Changed body under the SAME key and mutation id.
    await expectCode(
      store.createProviderDurably(owner.hash, owner.org, 'Changed', {
        idempotencyKey: base64Key(90),
        mutationId: mutationId(90),
      }),
      'TENANT_STORE_IDEMPOTENCY_CONFLICT',
    );
    // Changed principal (a different, even more privileged, actor) reusing the
    // same logical mutation id must not see the original receipt.
    await expectCode(
      store.updateProviderDurably(otherOwnerHash, owner.org, provider, { displayName: 'Q' }, {
        idempotencyKey: base64Key(92),
        mutationId: mutationId(90),
      }),
      'TENANT_STORE_IDEMPOTENCY_CONFLICT',
    );
    // Changed session context (same actor, new session) with the same key.
    const newSession = await seedSession(93, owner.account);
    await expectCode(
      store.createProviderDurably(newSession, owner.org, 'P', {
        idempotencyKey: base64Key(90),
        mutationId: mutationId(90),
      }),
      'TENANT_STORE_IDEMPOTENCY_CONFLICT',
    );
    // One business row, one durable receipt/audit/outbox, no leaked receipt.
    expect(await tenantCounts()).toMatchObject({ providers: 1, idem: 1, audit: 1, outbox: 1 });
    const status = await store.getTenantMutationStatus(owner.hash, owner.org, mutationId(90));
    expect(status).toEqual({ status: 'committed', receipt: created.receipt });
  });
});

describe('durable membership set', () => {
  it('records a no-op set receipt without revoking sessions', async () => {
    const owner = await seedOwner(30);
    const target = await seedAccount(31);
    await seedMembership(owner.org, target, 'viewer');
    const targetHash = await seedSession(31, target);
    const result = await store.setMembershipDurably(
      owner.hash,
      owner.org,
      target,
      'viewer',
      'active',
      { idempotencyKey: base64Key(30), mutationId: mutationId(30) },
    );
    expect(result.receipt.operation).toBe('tenant.membership.set');
    expect(result.receipt.resourceId).toBe(target);
    const live = await admin.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM openarc_auth.sessions WHERE token_hash = $1',
      [targetHash],
    );
    expect(live.rows[0]?.n).toBe(1);
    const counts = await tenantCounts();
    expect(counts).toMatchObject({ idem: 1, audit: 1, outbox: 1 });
    const stored = await admin.query<{ role: string; status: string }>(
      'SELECT role, status FROM openarc_tenant.memberships WHERE organization_id = $1 AND account_id = $2',
      [owner.org, target],
    );
    expect(stored.rows[0]).toEqual({ role: 'viewer', status: 'active' });
  });

  it('revokes every target session on an actual change', async () => {
    const owner = await seedOwner(32);
    const target = await seedAccount(33);
    await seedMembership(owner.org, target, 'viewer');
    const targetHash = await seedSession(33, target);
    await store.setMembershipDurably(owner.hash, owner.org, target, 'operator', 'active', {
      idempotencyKey: base64Key(32),
      mutationId: mutationId(32),
    });
    const revoked = await admin.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM openarc_auth.sessions WHERE account_id = $1',
      [target],
    );
    expect(revoked.rows[0]?.n).toBe(0);
    expect(targetHash).toBeTruthy();
  });

  it('rejects a non-owner and a stale proof', async () => {
    const owner = await seedOwner(34);
    const viewer = await seedAccount(35);
    const viewerHash = await seedSession(35, viewer);
    await seedMembership(owner.org, viewer, 'viewer');
    await expectCode(
      store.setMembershipDurably(viewerHash, owner.org, accountId(36), 'viewer', 'active', {
        idempotencyKey: base64Key(34),
        mutationId: mutationId(34),
      }),
      'TENANT_STORE_FORBIDDEN',
    );
  });

  it('rejects last-owner demotion', async () => {
    const owner = await seedOwner(37);
    await expectCode(
      store.setMembershipDurably(owner.hash, owner.org, owner.account, 'operator', 'active', {
        idempotencyKey: base64Key(37),
        mutationId: mutationId(37),
      }),
      'TENANT_STORE_CONFLICT',
    );
    const owners = await admin.query<{ n: number }>(
      "SELECT count(*)::int AS n FROM openarc_tenant.memberships WHERE organization_id = $1 AND role = 'owner' AND status = 'active'",
      [owner.org],
    );
    expect(owners.rows[0]?.n).toBe(1);
    expect((await tenantCounts()).idem).toBe(0);
  });

  it('allows an intentional self-demotion with another owner present', async () => {
    const owner = await seedOwner(38);
    const second = await seedAccount(39);
    const secondHash = await seedSession(39, second);
    await seedMembership(owner.org, second, 'owner');
    const result = await store.setMembershipDurably(
      owner.hash,
      owner.org,
      owner.account,
      'operator',
      'active',
      { idempotencyKey: base64Key(38), mutationId: mutationId(38) },
    );
    expect(result.receipt.resourceId).toBe(owner.account);
    const session = await admin.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM openarc_auth.sessions WHERE token_hash = $1',
      [owner.hash],
    );
    expect(session.rows[0]?.n).toBe(0);
    const membership = await admin.query<{ role: string }>(
      'SELECT role FROM openarc_tenant.memberships WHERE organization_id = $1 AND account_id = $2',
      [owner.org, owner.account],
    );
    expect(membership.rows[0]?.role).toBe('operator');
    // The revoked old session cannot replay; the current owner can inspect the
    // new role via getOrganizationAccess only after reauthentication.
    await expectCode(
      store.getTenantMutationStatus(owner.hash, owner.org, mutationId(38)),
      'TENANT_STORE_SESSION_INVALID',
    );
    expect(secondHash).toBeTruthy();
  });

  it('allows an intentional self-suspension with another owner present', async () => {
    const owner = await seedOwner(40);
    const second = await seedAccount(41);
    await seedMembership(owner.org, second, 'owner');
    const result = await store.setMembershipDurably(
      owner.hash,
      owner.org,
      owner.account,
      'owner',
      'suspended',
      { idempotencyKey: base64Key(40), mutationId: mutationId(40) },
    );
    expect(result.receipt.resourceId).toBe(owner.account);
    const membership = await admin.query<{ status: string }>(
      'SELECT status FROM openarc_tenant.memberships WHERE organization_id = $1 AND account_id = $2',
      [owner.org, owner.account],
    );
    expect(membership.rows[0]?.status).toBe('suspended');
  });

  it('rolls back a self-revocation whose proof expires after the outbox lock', async () => {
    const owner = await seedOwner(42);
    const second = await seedAccount(43);
    await seedMembership(owner.org, second, 'owner');
    // Proof is fresh-now but expires almost immediately; the outbox table lock
    // makes the mutation wait past the capture, so the final DB-clock check
    // rejects the intentional self-change and rolls everything back.
    await admin.query(
      `UPDATE openarc_auth.sessions SET created_at = clock_timestamp() - interval '4 minutes 58 seconds',
              expires_at = clock_timestamp() + interval '2 seconds' WHERE token_hash = $1`,
      [owner.hash],
    );
    const blocker = await admin.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query('LOCK TABLE openarc_durable.outbox_events IN ACCESS EXCLUSIVE MODE');
      const pending = store.setMembershipDurably(
        owner.hash,
        owner.org,
        owner.account,
        'operator',
        'active',
        { idempotencyKey: base64Key(42), mutationId: mutationId(42) },
      );
      await waitForLockWait();
      await waitUntilSessionExpired(owner.hash);
      await blocker.query('COMMIT');
      await expectCode(pending, 'TENANT_STORE_SESSION_INVALID');
    } finally {
      await blocker.query('ROLLBACK').catch(() => {});
      blocker.release();
    }
    const membership = await admin.query<{ role: string }>(
      'SELECT role FROM openarc_tenant.memberships WHERE organization_id = $1 AND account_id = $2',
      [owner.org, owner.account],
    );
    expect(membership.rows[0]?.role).toBe('owner');
    expect((await tenantCounts()).idem).toBe(0);
  });

  it('rolls back a self-suspension whose proof expires after the outbox lock', async () => {
    const owner = await seedOwner(46);
    const second = await seedAccount(47);
    await seedMembership(owner.org, second, 'owner');
    const secondHash = await seedSession(47, second);
    await admin.query(
      `UPDATE openarc_auth.sessions SET created_at = clock_timestamp() - interval '4 minutes 58 seconds',
              expires_at = clock_timestamp() + interval '2 seconds' WHERE token_hash = $1`,
      [owner.hash],
    );
    const blocker = await admin.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query('LOCK TABLE openarc_durable.outbox_events IN ACCESS EXCLUSIVE MODE');
      const pending = store.setMembershipDurably(
        owner.hash,
        owner.org,
        owner.account,
        'owner',
        'suspended',
        { idempotencyKey: base64Key(46), mutationId: mutationId(46) },
      );
      await waitForLockWait();
      await waitUntilSessionExpired(owner.hash);
      await blocker.query('COMMIT');
      await expectCode(pending, 'TENANT_STORE_SESSION_INVALID');
    } finally {
      await blocker.query('ROLLBACK').catch(() => {});
      blocker.release();
    }
    // The status change and the intentional self-session revocation both roll
    // back atomically; the other owner remains live and untouched.
    const membership = await admin.query<{ role: string; status: string }>(
      'SELECT role, status FROM openarc_tenant.memberships WHERE organization_id = $1 AND account_id = $2',
      [owner.org, owner.account],
    );
    expect(membership.rows[0]).toEqual({ role: 'owner', status: 'active' });
    const ownerSession = await admin.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM openarc_auth.sessions WHERE token_hash = $1',
      [owner.hash],
    );
    expect(ownerSession.rows[0]?.n).toBe(1);
    const otherSession = await admin.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM openarc_auth.sessions WHERE token_hash = $1',
      [secondHash],
    );
    expect(otherSession.rows[0]?.n).toBe(1);
    expect((await tenantCounts()).idem).toBe(0);
  });

  it('serializes sorted-target competing changes without inverting lock order', async () => {
    const a = await seedOwner(44);
    const bAccount = await seedAccount(45);
    const bHash = await seedSession(45, bAccount);
    await seedMembership(a.org, bAccount, 'owner');
    const attempts = [
      store.setMembershipDurably(a.hash, a.org, bAccount, 'operator', 'active', {
        idempotencyKey: base64Key(44),
        mutationId: mutationId(44),
      }),
      store.setMembershipDurably(bHash, a.org, a.account, 'operator', 'active', {
        idempotencyKey: base64Key(45),
        mutationId: mutationId(45),
      }),
    ];
    const outcomes = await Promise.allSettled(attempts);
    for (const outcome of outcomes) {
      if (outcome.status === 'rejected') {
        expect((outcome.reason as PgError).code).not.toBe('40P01');
      }
    }
    const owners = await admin.query<{ n: number }>(
      "SELECT count(*)::int AS n FROM openarc_tenant.memberships WHERE organization_id = $1 AND role = 'owner' AND status = 'active'",
      [a.org],
    );
    expect(owners.rows[0]?.n).toBe(1);
  });
});

describe('durable status authority and freshness', () => {
  it('returns not_found for another account mutation and forbids a non-owner viewer', async () => {
    const a = await seedOwner(50);
    const b = await seedOwner(51);
    await admin.query(
      "INSERT INTO openarc_tenant.providers (organization_id, provider_id, display_name) VALUES ($1, $2, 'P')",
      [a.org, providerId(50)],
    );
    const created = await store.createProviderDurably(a.hash, a.org, 'P', {
      idempotencyKey: base64Key(50),
      mutationId: mutationId(50),
    });
    await expect(
      store.getTenantMutationStatus(b.hash, b.org, created.receipt.mutationId),
    ).resolves.toEqual({ status: 'not_found' });
    const viewer = await seedAccount(52);
    const viewerHash = await seedSession(52, viewer);
    await seedMembership(a.org, viewer, 'viewer');
    // A different account's receipt is not_found even after authorization.
    await expect(
      store.getTenantMutationStatus(viewerHash, a.org, created.receipt.mutationId),
    ).resolves.toEqual(
      { status: 'not_found' },
    );
  });

  it('lets an operator read an agent status but forbids a now-insufficient role for a provider receipt', async () => {
    const owner = await seedOwner(53);
    const operator = await seedAccount(54);
    const operatorHash = await seedSession(54, operator);
    await seedMembership(owner.org, operator, 'operator');
    // The operator creates an agent receipt, then the owner creates a provider
    // receipt. The same operator can read the agent receipt but is forbidden on
    // the owner-only provider receipt ONLY for its own mutation id.
    await admin.query(
      "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name) VALUES ($1, $2, 'A')",
      [owner.org, agentId(53)],
    );
    // Owner-only mutation cannot be created by an operator; first let the owner
    // demote a provider-owning second account scenario is unnecessary. Assert
    // operator agent status works and a different actor's provider receipt is
    // not_found.
    const agentMutation = await store.updateAgentDurably(
      operatorHash,
      owner.org,
      agentId(53),
      { displayName: 'B' },
      { idempotencyKey: base64Key(53), mutationId: mutationId(53) },
    );
    await expect(
      store.getTenantMutationStatus(operatorHash, owner.org, agentMutation.receipt.mutationId),
    ).resolves.toMatchObject({ status: 'committed' });
    const provider = await store.createProviderDurably(owner.hash, owner.org, 'P', {
      idempotencyKey: base64Key(54),
      mutationId: mutationId(54),
    });
    await expect(
      store.getTenantMutationStatus(operatorHash, owner.org, provider.receipt.mutationId),
    ).resolves.toEqual({ status: 'not_found' });
    // The SAME actor under a CURRENTLY insufficient role is forbidden, not a
    // bypass around tenant role state. Admin bypasses revocation so the session
    // stays live while the stored membership role drops to operator.
    await admin.query(
      "UPDATE openarc_tenant.memberships SET role = 'operator' WHERE organization_id = $1 AND account_id = $2",
      [owner.org, owner.account],
    );
    await expectCode(
      store.getTenantMutationStatus(owner.hash, owner.org, provider.receipt.mutationId),
      'TENANT_STORE_FORBIDDEN',
    );
  });

  it('rechecks the held session after the final status table read', async () => {
    const owner = await seedOwner(55);
    await admin.query(
      "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name) VALUES ($1, $2, 'A')",
      [owner.org, agentId(55)],
    );
    const created = await store.updateAgentDurably(
      owner.hash,
      owner.org,
      agentId(55),
      { displayName: 'B' },
      { idempotencyKey: base64Key(55), mutationId: mutationId(55) },
    );
    await shortenSession(owner.hash, 2);
    const blocker = await admin.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query('LOCK TABLE openarc_durable.idempotency_records IN ACCESS EXCLUSIVE MODE');
      const pending = store.getTenantMutationStatus(owner.hash, owner.org, created.receipt.mutationId);
      await waitForLockWait();
      await waitUntilSessionExpired(owner.hash);
      await blocker.query('COMMIT');
      await expectCode(pending, 'TENANT_STORE_SESSION_INVALID');
    } finally {
      await blocker.query('ROLLBACK').catch(() => {});
      blocker.release();
    }
  });

  it('rechecks the held session on the not_found path after a wait', async () => {
    const owner = await seedOwner(56);
    await shortenSession(owner.hash, 2);
    const blocker = await admin.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query(
        'SELECT 1 FROM openarc_tenant.organizations WHERE organization_id = $1 FOR UPDATE',
        [owner.org],
      );
      const pending = store.getTenantMutationStatus(owner.hash, owner.org, mutationId(56));
      await waitForLockWait();
      await waitUntilSessionExpired(owner.hash);
      await blocker.query('COMMIT');
      await expectCode(pending, 'TENANT_STORE_SESSION_INVALID');
    } finally {
      await blocker.query('ROLLBACK').catch(() => {});
      blocker.release();
    }
  });

  it('denies a different account organization-status recovery', async () => {
    const a = await seedAccount(57);
    const aHash = await seedSession(57, a);
    await store.createOrganizationDurably(aHash, 'A', {
      idempotencyKey: base64Key(57),
      mutationId: mutationId(57),
    });
    const b = await seedAccount(58);
    const bHash = await seedSession(58, b);
    await expect(store.getOrganizationMutationStatus(bHash, mutationId(57))).resolves.toEqual({
      status: 'not_found',
    });
  });
});

describe('durable canaries and failure hygiene', () => {
  it('stores no raw key, session hash or display-name canary in durable cells', async () => {
    const owner = await seedOwner(60);
    const key = base64Key(60);
    const canary = 'CanaryNameXYZ';
    await store.createProviderDurably(owner.hash, owner.org, canary, {
      idempotencyKey: key,
      mutationId: mutationId(60),
    });
    const cells = await admin.query<{ blob: string }>(
      `SELECT concat_ws('|',
                 (SELECT string_agg(key_hash || request_digest || session_context_digest, '')
                    FROM openarc_durable.idempotency_records),
                 (SELECT string_agg(resource_type || resource_id || outcome, '')
                    FROM openarc_durable.audit_events),
                 (SELECT string_agg(resource_type || resource_id || event_type || state, '')
                    FROM openarc_durable.outbox_events)) AS blob`,
    );
    const blob = cells.rows[0]?.blob ?? '';
    expect(blob).not.toContain(key);
    expect(blob).not.toContain(owner.hash);
    expect(blob).not.toContain(canary);
  });

  it('rolls back on injected audit failure for each new resource kind', async () => {
    const owner = await seedOwner(61);
    await admin.query(
      "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name) VALUES ($1, $2, 'A')",
      [owner.org, agentId(61)],
    );
    const provider = providerId(61);
    await admin.query(
      "INSERT INTO openarc_tenant.providers (organization_id, provider_id, display_name) VALUES ($1, $2, 'P')",
      [owner.org, provider],
    );
    await admin.query(
      `CREATE OR REPLACE FUNCTION openarc_durable.test_fail_audit() RETURNS trigger
       LANGUAGE plpgsql SET search_path = pg_catalog AS $$
       BEGIN RAISE EXCEPTION 'injected' USING ERRCODE = '23514'; END; $$`,
    );
    await admin.query(
      'CREATE TRIGGER test_fail_audit BEFORE INSERT ON openarc_durable.audit_events FOR EACH ROW EXECUTE FUNCTION openarc_durable.test_fail_audit()',
    );
    const second = await seedAccount(62);
    await seedMembership(owner.org, second, 'owner');
    const bootstrapAccount = await seedAccount(63);
    const bootstrapHash = await seedSession(63, bootstrapAccount);
    try {
      const attempts = [
        () => store.createOrganizationDurably(bootstrapHash, 'Blocked', {
          idempotencyKey: base64Key(60),
          mutationId: mutationId(60),
        }),
        () => store.updateAgentDurably(owner.hash, owner.org, agentId(61), { displayName: 'B' }, {
          idempotencyKey: base64Key(61),
          mutationId: mutationId(61),
        }),
        () => store.createProviderDurably(owner.hash, owner.org, 'P', {
          idempotencyKey: base64Key(62),
          mutationId: mutationId(62),
        }),
        () => store.updateProviderDurably(owner.hash, owner.org, provider, { displayName: 'Q' }, {
          idempotencyKey: base64Key(64),
          mutationId: mutationId(64),
        }),
        () => store.setMembershipDurably(owner.hash, owner.org, owner.account, 'owner', 'suspended', {
          idempotencyKey: base64Key(63),
          mutationId: mutationId(63),
        }),
      ];
      for (const attempt of attempts) {
        await expectCode(attempt(), 'TENANT_STORE_INPUT_INVALID');
      }
    } finally {
      await admin.query('DROP TRIGGER test_fail_audit ON openarc_durable.audit_events');
      await admin.query('DROP FUNCTION openarc_durable.test_fail_audit()');
    }
    expect((await tenantCounts()).idem).toBe(0);
    // The bootstrap attempt left no organization/membership orphan, and the
    // provider update left the original provider state intact.
    expect((await tenantCounts()).organizations).toBe(1);
    const kept = await admin.query<{ display_name: string }>(
      'SELECT display_name FROM openarc_tenant.providers WHERE organization_id = $1 AND provider_id = $2',
      [owner.org, provider],
    );
    expect(kept.rows[0]?.display_name).toBe('P');
  });

  it('rolls back every new resource kind on an injected outbox failure', async () => {
    const owner = await seedOwner(65);
    await admin.query(
      "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name) VALUES ($1, $2, 'A')",
      [owner.org, agentId(65)],
    );
    const second = await seedAccount(66);
    const secondHash = await seedSession(66, second);
    await seedMembership(owner.org, second, 'owner');
    const challengeHash = sha256('challenge:66');
    await admin.query(
      `INSERT INTO openarc_auth.challenges
         (challenge_hash, binding_hash, kind, challenge, user_handle, account_id, expires_at)
       VALUES ($1, $2, 'passkey_add', 'chal66', $3, $4, clock_timestamp() + interval '4 minutes')`,
      [challengeHash, sha256('binding:66'), userHandle(66), second],
    );
    await admin.query(
      `CREATE OR REPLACE FUNCTION openarc_durable.test_fail_outbox() RETURNS trigger
       LANGUAGE plpgsql SET search_path = pg_catalog AS $$
       BEGIN RAISE EXCEPTION 'injected' USING ERRCODE = '23514'; END; $$`,
    );
    await admin.query(
      'CREATE TRIGGER test_fail_outbox BEFORE INSERT ON openarc_durable.outbox_events FOR EACH ROW EXECUTE FUNCTION openarc_durable.test_fail_outbox()',
    );
    const bootstrapAccount = await seedAccount(67);
    const bootstrapHash = await seedSession(67, bootstrapAccount);
    const provider = providerId(65);
    await admin.query(
      "INSERT INTO openarc_tenant.providers (organization_id, provider_id, display_name) VALUES ($1, $2, 'P')",
      [owner.org, provider],
    );
    try {
      const attempts = [
        () => store.createOrganizationDurably(bootstrapHash, 'Blocked', {
          idempotencyKey: base64Key(65),
          mutationId: mutationId(65),
        }),
        () => store.updateAgentDurably(owner.hash, owner.org, agentId(65), { displayName: 'B' }, {
          idempotencyKey: base64Key(66),
          mutationId: mutationId(66),
        }),
        () => store.createProviderDurably(owner.hash, owner.org, 'P', {
          idempotencyKey: base64Key(67),
          mutationId: mutationId(67),
        }),
        () => store.updateProviderDurably(owner.hash, owner.org, provider, { displayName: 'Q' }, {
          idempotencyKey: base64Key(68),
          mutationId: mutationId(68),
        }),
        () => store.setMembershipDurably(owner.hash, owner.org, second, 'viewer', 'active', {
          idempotencyKey: base64Key(69),
          mutationId: mutationId(69),
        }),
      ];
      for (const attempt of attempts) {
        await expectCode(attempt(), 'TENANT_STORE_INPUT_INVALID');
      }
    } finally {
      await admin.query('DROP TRIGGER test_fail_outbox ON openarc_durable.outbox_events');
      await admin.query('DROP FUNCTION openarc_durable.test_fail_outbox()');
    }
    expect((await tenantCounts()).idem).toBe(0);
    // The rolled-back membership change restored the target's role and its
    // live session (the accepted schema2 change would have revoked it).
    const membership = await admin.query<{ role: string }>(
      'SELECT role FROM openarc_tenant.memberships WHERE organization_id = $1 AND account_id = $2',
      [owner.org, second],
    );
    expect(membership.rows[0]?.role).toBe('owner');
    const live = await admin.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM openarc_auth.sessions WHERE token_hash = $1',
      [secondHash],
    );
    expect(live.rows[0]?.n).toBe(1);
    const challenge = await admin.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM openarc_auth.challenges WHERE challenge_hash = $1',
      [challengeHash],
    );
    expect(challenge.rows[0]?.n).toBe(1);
    const storedProvider = await admin.query<{ display_name: string }>(
      'SELECT display_name FROM openarc_tenant.providers WHERE organization_id = $1 AND provider_id = $2',
      [owner.org, provider],
    );
    expect(storedProvider.rows[0]?.display_name).toBe('P');
  });
});

describe('outbox worker claims every new resource kind', () => {
  it('claims and completes a provider-created event', async () => {
    const owner = await seedOwner(70);
    const created = await store.createProviderDurably(owner.hash, owner.org, 'P', {
      idempotencyKey: base64Key(70),
      mutationId: mutationId(70),
    });
    const [claimed] = await outbox.claim({ limit: 1 });
    expect(claimed?.resourceType).toBe('provider');
    expect(claimed?.eventType).toBe('tenant.provider.created');
    expect(claimed?.resourceId).toBe(created.receipt.resourceId);
    await expect(outbox.complete(claimed?.eventId ?? '', claimed?.leaseGeneration ?? '0')).resolves.toEqual({
      applied: true,
    });
  });

  it('claims and fences a membership-set event', async () => {
    const owner = await seedOwner(71);
    const second = await seedAccount(72);
    await seedMembership(owner.org, second, 'owner');
    const [claimed] = await (async () => {
      await store.setMembershipDurably(owner.hash, owner.org, owner.account, 'owner', 'suspended', {
        idempotencyKey: base64Key(71),
        mutationId: mutationId(71),
      });
      return outbox.claim({ limit: 1 });
    })();
    expect(claimed?.resourceType).toBe('membership');
    expect(claimed?.eventType).toBe('tenant.membership.set');
    await admin.query(
      "UPDATE openarc_durable.outbox_events SET lease_until = now() - interval '1 second' WHERE event_id = $1",
      [claimed?.eventId],
    );
    const [reclaimed] = await outbox.claim({ limit: 1 });
    await expect(outbox.complete(claimed?.eventId ?? '', claimed?.leaseGeneration ?? '0')).resolves.toEqual({
      applied: false,
    });
    await expect(
      outbox.complete(reclaimed?.eventId ?? '', reclaimed?.leaseGeneration ?? '0'),
    ).resolves.toEqual({ applied: true });
  });
});
