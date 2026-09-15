import { createHash } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import {
  ControlPolicyStore,
  ControlPolicyStoreError,
  TenantStore,
  createDatabasePool,
  loadMigrations,
  migrate,
} from '../src/index.js';
import {
  adminPool,
  appUrl,
  ensureRoles,
  migratorUrl,
  resetSchema,
  tenantUrl,
  workerUrl,
} from './postgres-fixture.js';

/**
 * Real PostgreSQL acceptance for schema8 control policies. Every mutation runs
 * against the restricted runtime role (openarc_tenant_app); direct table access
 * and forged GUCs must fail. Recording a policy is declared data only.
 */

function sha256(seed: string): string {
  return createHash('sha256').update(`openarc-policy-test:${seed}`, 'utf8').digest('hex');
}

function uuid(seed: number): string {
  return `20000000-0000-4000-8000-${String(seed).padStart(12, '0')}`;
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

function listingId(seed: number): string {
  return `openarc:listing:${uuid(seed)}`;
}

function mutationId(seed: number): string {
  return uuid(700000 + seed);
}

function key(seed: number): string {
  return createHash('sha256').update(`policy-key:${seed}`).digest().toString('base64url');
}

function userHandle(seed: number): string {
  return `${sha256(`handle:${seed}`).slice(0, 42)}A`;
}

function content(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    organizationId: orgId(1),
    subjectAgentId: agentId(1),
    networkId: 'eip155:5042002',
    asset: 'USDC',
    representation: 'erc20',
    decimals: 6,
    perActionLimit: '1000000',
    rollingLimit: '5000000',
    rollingWindowSeconds: '3600',
    feeLimit: '0',
    allowedProviderIds: [],
    allowedListingIds: [],
    approval: { mode: 'above', threshold: '1000000', separateApprover: true },
    expiresAt: '2099-01-01T00:00:00.000000Z',
    ...overrides,
  };
}

/** Content bound to the owner organization and one seeded subject agent. */
function policyContent(org: string, subjectSeed: number, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return content({ organizationId: org, subjectAgentId: agentId(subjectSeed), ...overrides });
}

interface PgError {
  code?: string;
}

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ControlPolicyStoreError);
    expect((error as ControlPolicyStoreError).code).toBe(code);
    return;
  }
  throw new Error(`expected ControlPolicyStoreError ${code}`);
}

async function rawError(promise: Promise<unknown>): Promise<PgError> {
  try {
    await promise;
  } catch (error) {
    return error as PgError;
  }
  throw new Error('expected a raw SQL rejection');
}

let admin: Pool;
let migrator: Pool;
let tenant: Pool;
let worker: Pool;
let auth: Pool;
let store: ControlPolicyStore;

beforeAll(async () => {
  admin = adminPool();
  await ensureRoles(admin);
  migrator = createDatabasePool(migratorUrl());
  tenant = createDatabasePool(tenantUrl());
  worker = createDatabasePool(workerUrl());
  auth = createDatabasePool(appUrl());
});

afterAll(async () => {
  try {
    await resetSchema(admin);
  } finally {
    await auth.end();
    await worker.end();
    await tenant.end();
    await migrator.end();
    await admin.end();
  }
});

beforeEach(async () => {
  await resetSchema(admin);
  await migrate(migrator);
  store = new ControlPolicyStore(tenant);
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

async function seedAgent(seed: number, org: string, status = 'active'): Promise<string> {
  const id = agentId(seed);
  await admin.query(
    'INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name, status) VALUES ($1, $2, $3, $4)',
    [org, id, `Agent ${seed}`, status],
  );
  return id;
}

async function seedMember(
  seed: number,
  org: string,
  role: string,
  options: { method?: string; createdOffset?: string } = {},
): Promise<{ account: string; hash: string }> {
  const account = await seedAccount(seed);
  const hash = await seedSession(seed, account, options);
  await admin.query(
    'INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, $3, $4)',
    [org, account, role, 'active'],
  );
  return { account, hash };
}

async function rootOf(
  org: string,
  policy: string,
): Promise<{ current_revision: string; status: string; updated_at: string }> {
  const result = await admin.query(
    `SELECT current_revision, status,
            to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS updated_at
       FROM openarc_tenant.budget_policy_roots
      WHERE organization_id = $1 AND policy_id = $2`,
    [org, policy],
  );
  const row = result.rows[0];
  if (row === undefined) throw new Error('policy root missing');
  return row;
}

async function counts(org: string): Promise<Record<string, number>> {
  const result = await admin.query(
    `SELECT
       (SELECT count(*)::int FROM openarc_tenant.budget_policy_roots WHERE organization_id = $1) AS roots,
       (SELECT count(*)::int FROM openarc_tenant.budget_policy_versions WHERE organization_id = $1) AS versions,
       (SELECT count(*)::int FROM openarc_durable.idempotency_records WHERE organization_id = $1 AND operation LIKE 'control.policy%') AS idem,
       (SELECT count(*)::int FROM openarc_durable.audit_events WHERE organization_id = $1 AND operation LIKE 'control.policy%') AS audit,
       (SELECT count(*)::int FROM openarc_durable.outbox_events WHERE organization_id = $1 AND event_type LIKE 'control.policy%') AS outbox`,
    [org],
  );
  return result.rows[0] as Record<string, number>;
}

async function shortenSession(hash: string, seconds: number): Promise<void> {
  await admin.query(
    `UPDATE openarc_auth.sessions
        SET expires_at = clock_timestamp() + make_interval(secs => $2)
      WHERE token_hash = $1`,
    [hash, seconds],
  );
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
      `SELECT clock_timestamp() >= expires_at AS expired
         FROM openarc_auth.sessions WHERE token_hash = $1`,
      [hash],
    );
    if (probe.rows[0]?.expired === true) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error('session did not expire');
}

async function createPolicy(owner: { hash: string; org: string }, seed: number, overrides: Record<string, unknown> = {}) {
  return store.createPolicy(owner.hash, owner.org, content({ organizationId: owner.org, subjectAgentId: agentId(seed), ...overrides }), {
    idempotencyKey: key(seed),
    mutationId: mutationId(seed),
  });
}

describe('schema8 manifest, ownership and ACLs', () => {
  it('records schema8 and keeps the policy helpers migrator-owned with fixed search_path', async () => {
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
    const tables = await admin.query<{ relname: string; owner: string; rls: boolean; forced: boolean }>(
      `SELECT c.relname, r.rolname AS owner, c.relrowsecurity AS rls, c.relforcerowsecurity AS forced
         FROM pg_class c
         JOIN pg_namespace n ON n.oid = c.relnamespace
         JOIN pg_roles r ON r.oid = c.relowner
        WHERE n.nspname = 'openarc_tenant'
          AND c.relname IN ('budget_policy_roots', 'budget_policy_versions')
        ORDER BY c.relname`,
    );
    expect(tables.rows).toEqual([
      { relname: 'budget_policy_roots', owner: 'openarc_migrator', rls: true, forced: true },
      { relname: 'budget_policy_versions', owner: 'openarc_migrator', rls: true, forced: true },
    ]);
    const helpers = await admin.query<{ proname: string; owner: string; secdef: boolean; config: string[] }>(
      `SELECT p.proname, r.rolname AS owner, p.prosecdef AS secdef,
              coalesce(p.proconfig, ARRAY[]::text[]) AS config
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         JOIN pg_roles r ON r.oid = p.proowner
        WHERE n.nspname = 'openarc_durable'
          AND p.proname IN (
            'commit_policy_mutation', 'lock_policy_writer', 'lock_policy_reader',
            'read_policy_root', 'list_policy_roots', 'read_policy_revision',
            'list_policy_revisions', 'read_policy_mutation_status'
          )
        ORDER BY p.proname`,
    );
    expect(helpers.rows).toHaveLength(8);
    expect(
      helpers.rows.every(
        (row) =>
          row.owner === 'openarc_migrator' &&
          row.secdef === true &&
          row.config.includes('search_path=pg_catalog'),
      ),
    ).toBe(true);
  });

  it('denies the runtime and worker direct policy table access and internal helper execute', async () => {
    expect((await rawError(tenant.query('SELECT count(*) FROM openarc_tenant.budget_policy_roots'))).code).toBe('42501');
    expect(
      (
        await rawError(
          tenant.query(
            `INSERT INTO openarc_tenant.budget_policy_roots
               (organization_id, policy_id, subject_agent_id, current_revision, status)
             VALUES ('x','y','z','1','active')`,
          ),
        )
      ).code,
    ).toBe('42501');
    const internal = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'openarc_durable'
          AND p.proname IN ('lock_policy_actor', 'assert_policy_content', 'is_valid_policy_content')
          AND (
            has_function_privilege('openarc_tenant_app', p.oid, 'EXECUTE')
            OR has_function_privilege('openarc_worker_app', p.oid, 'EXECUTE')
            OR has_function_privilege('openarc_auth_app', p.oid, 'EXECUTE')
            OR EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                        WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE')
          )`,
    );
    expect(internal.rows[0]?.n).toBe(0);
  });

  it('reaches healthy readiness and rejects tampered schema controls', async () => {
    await expect(store.readiness()).resolves.toBeUndefined();
    await admin.query('ALTER TABLE openarc_tenant.budget_policy_versions NO FORCE ROW LEVEL SECURITY');
    await expectCode(store.readiness(), 'CONTROL_POLICY_STORE_UNAVAILABLE');
  });

  // Independent tamper vectors for the DB8-owned integrity controls. Each test
  // starts from a freshly migrated schema (beforeEach) and breaks exactly one
  // control; readiness must fail closed with UNAVAILABLE.
  it('fails readiness when the immutable version trigger is disabled or dropped', async () => {
    await admin.query('ALTER TABLE openarc_tenant.budget_policy_versions DISABLE TRIGGER budget_policy_versions_immutable');
    await expectCode(store.readiness(), 'CONTROL_POLICY_STORE_UNAVAILABLE');
  });

  it('fails readiness when the root mutation trigger is disabled', async () => {
    await admin.query('ALTER TABLE openarc_tenant.budget_policy_roots DISABLE TRIGGER budget_policy_roots_mutation');
    await expectCode(store.readiness(), 'CONTROL_POLICY_STORE_UNAVAILABLE');
  });

  it('fails readiness when the current-revision foreign key is dropped', async () => {
    await admin.query('ALTER TABLE openarc_tenant.budget_policy_roots DROP CONSTRAINT budget_policy_roots_current_fk');
    await expectCode(store.readiness(), 'CONTROL_POLICY_STORE_UNAVAILABLE');
  });

  it('fails readiness when the version content CHECK is dropped', async () => {
    await admin.query('ALTER TABLE openarc_tenant.budget_policy_versions DROP CONSTRAINT budget_policy_versions_content_valid');
    await expectCode(store.readiness(), 'CONTROL_POLICY_STORE_UNAVAILABLE');
  });

  it('fails readiness when the one-active-policy index is dropped or invalidated', async () => {
    await admin.query('DROP INDEX openarc_tenant.budget_policy_roots_one_active');
    await expectCode(store.readiness(), 'CONTROL_POLICY_STORE_UNAVAILABLE');
  });

  it('fails readiness when a trigger helper is dropped or its search_path altered', async () => {
    await admin.query('DROP FUNCTION openarc_tenant.enforce_policy_root_mutation() CASCADE');
    await expectCode(store.readiness(), 'CONTROL_POLICY_STORE_UNAVAILABLE');
  });

  it('fails readiness when a trigger helper search_path is altered', async () => {
    await admin.query('ALTER FUNCTION openarc_tenant.enforce_policy_root_mutation() SET search_path = public');
    await expectCode(store.readiness(), 'CONTROL_POLICY_STORE_UNAVAILABLE');
  });

  it('fails readiness when an internal validator is dropped CASCADE', async () => {
    await admin.query('DROP FUNCTION openarc_durable.is_valid_policy_content(text, text, text, text, smallint, text, text, text, text, text[], text[], text, text, boolean, timestamptz, timestamptz) CASCADE');
    await expectCode(store.readiness(), 'CONTROL_POLICY_STORE_UNAVAILABLE');
  });
});

describe('owner lifecycle, viewer reads and denials', () => {
  it('creates, appends, pauses, resumes and revokes with revision-preserving status changes', async () => {
    const owner = await seedOwner(10);
    await seedAgent(10, owner.org);
    const created = await createPolicy(owner, 10);
    expect(created.replayed).toBe(false);
    expect(created.receipt.operation).toBe('control.policy.create');
    const policy = created.receipt.resourceId;
    expect(policy).toBe(`openarc:policy:${mutationId(10)}`);

    let root = await rootOf(owner.org, policy);
    expect(root.current_revision).toBe('1');
    expect(root.status).toBe('active');

    const appended = await store.appendPolicyRevision(
      owner.hash,
      owner.org,
      policy,
      {
        expectedRevision: '1',
        expectedUpdatedAt: root.updated_at,
        content: policyContent(owner.org, 10),
      },
      { idempotencyKey: key(11), mutationId: mutationId(11) },
    );
    expect(appended.receipt.resourceId).toBe(`${policy}@2`);
    root = await rootOf(owner.org, policy);
    expect(root.current_revision).toBe('2');
    expect(root.status).toBe('active');

    const paused = await store.transitionPolicy(
      owner.hash,
      owner.org,
      policy,
      { operation: 'control.policy.pause', expectedRevision: '2', expectedUpdatedAt: root.updated_at },
      { idempotencyKey: key(12), mutationId: mutationId(12) },
    );
    expect(paused.receipt.operation).toBe('control.policy.pause');
    root = await rootOf(owner.org, policy);
    // Status changes never increment the content revision.
    expect(root.current_revision).toBe('2');
    expect(root.status).toBe('paused');

    const resumed = await store.transitionPolicy(
      owner.hash,
      owner.org,
      policy,
      { operation: 'control.policy.resume', expectedRevision: '2', expectedUpdatedAt: root.updated_at },
      { idempotencyKey: key(13), mutationId: mutationId(13) },
    );
    expect(resumed.receipt.operation).toBe('control.policy.resume');
    root = await rootOf(owner.org, policy);
    expect(root.status).toBe('active');

    const revoked = await store.transitionPolicy(
      owner.hash,
      owner.org,
      policy,
      { operation: 'control.policy.revoke', expectedRevision: '2', expectedUpdatedAt: root.updated_at },
      { idempotencyKey: key(14), mutationId: mutationId(14) },
    );
    expect(revoked.receipt.operation).toBe('control.policy.revoke');
    root = await rootOf(owner.org, policy);
    expect(root.status).toBe('revoked');
  });

  it('lets a viewer read but never write, and denies provider roles entirely', async () => {
    const owner = await seedOwner(20);
    await seedAgent(20, owner.org);
    const viewer = await seedMember(21, owner.org, 'viewer');
    const provider = await seedMember(22, owner.org, 'provider_admin');
    const created = await createPolicy(owner, 20);
    const policy = created.receipt.resourceId;

    const rootRead = await store.getPolicyRoot(viewer.hash, owner.org, policy);
    expect(rootRead?.policyId).toBe(policy);
    await expectCode(store.createPolicy(viewer.hash, owner.org, content({ organizationId: owner.org }), { idempotencyKey: key(23), mutationId: mutationId(23) }), 'CONTROL_POLICY_STORE_FORBIDDEN');
    await expectCode(store.getPolicyRoot(provider.hash, owner.org, policy), 'CONTROL_POLICY_STORE_FORBIDDEN');
  });

  it('permits operator writes and recovery-session reads but denies recovery writes', async () => {
    const owner = await seedOwner(30);
    await seedAgent(30, owner.org);
    const operator = await seedMember(31, owner.org, 'operator');
    const recovery = await seedMember(32, owner.org, 'owner', { method: 'recovery' });
    const created = await store.createPolicy(
      operator.hash,
      owner.org,
      policyContent(owner.org, 30),
      { idempotencyKey: key(30), mutationId: mutationId(30) },
    );
    const policy = created.receipt.resourceId;
    await expect(store.getPolicyRoot(recovery.hash, owner.org, policy)).resolves.toMatchObject({ policyId: policy });
    await expectCode(
      store.createPolicy(recovery.hash, owner.org, policyContent(owner.org, 30), { idempotencyKey: key(31), mutationId: mutationId(31) }),
      'CONTROL_POLICY_STORE_SESSION_INVALID',
    );
  });

  it('rejects a stale non-recovery proof for writes', async () => {
    const owner = await seedOwner(40);
    await seedAgent(40, owner.org);
    const stale = await seedMember(41, owner.org, 'owner', { createdOffset: '-10 minutes', expiresOffset: '23 hours' });
    await expectCode(
      store.createPolicy(stale.hash, owner.org, content({ organizationId: owner.org }), { idempotencyKey: key(40), mutationId: mutationId(40) }),
      'CONTROL_POLICY_STORE_SESSION_INVALID',
    );
  });
});

describe('content, binding and immutability', () => {
  it('rejects a cross-organization subject agent but accepts external listing/provider allowlists', async () => {
    const owner = await seedOwner(50);
    await seedAgent(50, owner.org);
    const foreignOrg = orgId(51);
    const foreignAccount = await seedAccount(51);
    await admin.query(
      "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Foreign', $2)",
      [foreignOrg, foreignAccount],
    );
    const foreignAgent = await seedAgent(52, foreignOrg);
    await expectCode(
      store.createPolicy(
        owner.hash,
        owner.org,
        content({ organizationId: owner.org, subjectAgentId: foreignAgent }),
        { idempotencyKey: key(50), mutationId: mutationId(50) },
      ),
      'CONTROL_POLICY_STORE_NOT_FOUND',
    );
    await seedAgent(53, owner.org);
    const external = await createPolicy(owner, 53, {
      allowedProviderIds: [providerId(900)],
      allowedListingIds: [listingId(901)],
    });
    expect(external.receipt.resourceId).toMatch(/^openarc:policy:/);
  });

  it('rejects invalid content at the SQL layer and freezes version history', async () => {
    const owner = await seedOwner(60);
    await seedAgent(60, owner.org);
    const created = await createPolicy(owner, 60);
    const policy = created.receipt.resourceId;
    await expect(
      admin.query(
        `INSERT INTO openarc_tenant.budget_policy_versions
           (organization_id, policy_id, revision, subject_agent_id, network_id, asset, representation,
            decimals, per_action_limit, rolling_limit, rolling_window_seconds, fee_limit,
            allowed_provider_ids, allowed_listing_ids, approval_mode, approval_threshold,
            approval_separate_approver, expires_at, digest)
         VALUES ($1, $2, '2', $3, 'eip155:5042002', 'USDC', 'erc20', 6, NULL, NULL, NULL, '0',
                 ARRAY[]::text[], ARRAY[]::text[], 'none', NULL, false, NULL, 'sha256:' || repeat('a', 64))`,
        [owner.org, policy, agentId(60)],
      ),
    ).rejects.toBeTruthy();
    expect((await rawError(admin.query('UPDATE openarc_tenant.budget_policy_versions SET fee_limit = $1 WHERE policy_id = $2', ['1', policy]))).code).toBe('42501');
    expect((await rawError(admin.query('DELETE FROM openarc_tenant.budget_policy_versions WHERE policy_id = $1', [policy]))).code).toBe('42501');
    expect(
      (
        await rawError(
          admin.query('UPDATE openarc_tenant.budget_policy_roots SET subject_agent_id = $1 WHERE policy_id = $2', [agentId(61), policy]),
        )
      ).code,
    ).toBe('42501');
  });

  it('resists forged GUC authority', async () => {
    const target = await seedOwner(70);
    await seedAgent(70, target.org);
    const client = await tenant.connect();
    try {
      await client.query("SELECT set_config('openarc.account_id', $1, true)", [target.account]);
      await client.query("SELECT set_config('openarc.organization_id', $1, true)", [target.org]);
      await client.query("SELECT set_config('openarc.role', 'owner', true)");
      const denied = await rawError(client.query('SELECT count(*) FROM openarc_tenant.budget_policy_roots'));
      expect(denied.code).toBe('42501');
    } finally {
      client.release();
    }
    const bogus = 'f'.repeat(64);
    expect(
      (
        await rawError(
          tenant.query('SELECT * FROM openarc_durable.read_policy_root($1, $2, $3)', [
            bogus,
            target.org,
            `openarc:policy:${mutationId(70)}`,
          ]),
        )
      ).code,
    ).toBe('28000');
  });
});

describe('CAS, replay and conflicts', () => {
  it('serializes concurrent appends to exactly one winner', async () => {
    const owner = await seedOwner(80);
    await seedAgent(80, owner.org);
    const created = await createPolicy(owner, 80);
    const policy = created.receipt.resourceId;
    const root = await rootOf(owner.org, policy);
    const attempt = (seed: number) =>
      store.appendPolicyRevision(
        owner.hash,
        owner.org,
        policy,
        {
          expectedRevision: '1',
          expectedUpdatedAt: root.updated_at,
          content: policyContent(owner.org, 80),
        },
        { idempotencyKey: key(seed), mutationId: mutationId(seed) },
      );
    const settled = await Promise.allSettled([attempt(81), attempt(82)]);
    expect(settled.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    const after = await rootOf(owner.org, policy);
    expect(after.current_revision).toBe('2');
  }, 20000);

  it('serializes concurrent pause/resume on the root updatedAt CAS', async () => {
    const owner = await seedOwner(90);
    await seedAgent(90, owner.org);
    const created = await createPolicy(owner, 90);
    const policy = created.receipt.resourceId;
    const root = await rootOf(owner.org, policy);
    const attempt = (seed: number) =>
      store.transitionPolicy(
        owner.hash,
        owner.org,
        policy,
        { operation: 'control.policy.pause', expectedRevision: '1', expectedUpdatedAt: root.updated_at },
        { idempotencyKey: key(seed), mutationId: mutationId(seed) },
      );
    const settled = await Promise.allSettled([attempt(91), attempt(92)]);
    expect(settled.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    const after = await rootOf(owner.org, policy);
    expect(after.status).toBe('paused');
    expect(after.current_revision).toBe('1');
  }, 20000);

  it('replays an old receipt after a later revision and revoke', async () => {
    const owner = await seedOwner(100);
    await seedAgent(100, owner.org);
    const created = await createPolicy(owner, 100);
    const policy = created.receipt.resourceId;
    let root = await rootOf(owner.org, policy);
    const appendExpected = root.updated_at;
    await store.appendPolicyRevision(
      owner.hash,
      owner.org,
      policy,
      { expectedRevision: '1', expectedUpdatedAt: appendExpected, content: policyContent(owner.org, 100) },
      { idempotencyKey: key(101), mutationId: mutationId(101) },
    );
    root = await rootOf(owner.org, policy);
    await store.transitionPolicy(
      owner.hash,
      owner.org,
      policy,
      { operation: 'control.policy.revoke', expectedRevision: '2', expectedUpdatedAt: root.updated_at },
      { idempotencyKey: key(102), mutationId: mutationId(102) },
    );
    const replayCreate = await createPolicy(owner, 100);
    expect(replayCreate.replayed).toBe(true);
    expect(replayCreate.receipt.mutationId).toBe(mutationId(100));
    const replayAppend = await store.appendPolicyRevision(
      owner.hash,
      owner.org,
      policy,
      { expectedRevision: '1', expectedUpdatedAt: appendExpected, content: policyContent(owner.org, 100) },
      { idempotencyKey: key(101), mutationId: mutationId(101) },
    );
    expect(replayAppend.replayed).toBe(true);
    expect(replayAppend.receipt.resourceId).toBe(`${policy}@2`);
  });

  it('rejects a different body, actor or mutation for the same idempotency key', async () => {
    const owner = await seedOwner(110);
    await seedAgent(110, owner.org);
    await createPolicy(owner, 110);
    const other = await seedMember(111, owner.org, 'owner');
    await expectCode(
      store.createPolicy(owner.hash, owner.org, policyContent(owner.org, 110, { feeLimit: '1' }), { idempotencyKey: key(110), mutationId: mutationId(110) }),
      'CONTROL_POLICY_STORE_IDEMPOTENCY_CONFLICT',
    );
    await expectCode(
      store.createPolicy(other.hash, owner.org, policyContent(owner.org, 110), { idempotencyKey: key(110), mutationId: mutationId(110) }),
      'CONTROL_POLICY_STORE_IDEMPOTENCY_CONFLICT',
    );
    await expectCode(
      store.createPolicy(owner.hash, owner.org, policyContent(owner.org, 110), { idempotencyKey: key(112), mutationId: mutationId(110) }),
      'CONTROL_POLICY_STORE_IDEMPOTENCY_CONFLICT',
    );
  });

  it('resolves committed status only for the same verified actor', async () => {
    const owner = await seedOwner(120);
    await seedAgent(120, owner.org);
    const other = await seedMember(121, owner.org, 'operator');
    const created = await createPolicy(owner, 120);
    const own = await store.getPolicyMutationStatus(owner.hash, owner.org, mutationId(120));
    expect(own.status).toBe('committed');
    const foreign = await store.getPolicyMutationStatus(other.hash, owner.org, mutationId(120));
    expect(foreign).toEqual({ status: 'not_found' });
    void created;
  });

  it('hides a committed mutation from a second live session of the same account', async () => {
    const owner = await seedOwner(130);
    await seedAgent(130, owner.org);
    const created = await createPolicy(owner, 130);

    // The committing session resolves its own receipt.
    const own = await store.getPolicyMutationStatus(owner.hash, owner.org, mutationId(130));
    expect(own.status).toBe('committed');

    // A SECOND LIVE session for the SAME account (same org, unexpired,
    // non-recovery) is a different presented session context. Exact digest
    // binding must hide the receipt independently of the account identity and
    // session liveness checks that already exist.
    const secondHash = await seedSession(131, owner.account);
    expect(secondHash).not.toBe(owner.hash);
    const hidden = await store.getPolicyMutationStatus(secondHash, owner.org, mutationId(130));
    expect(hidden).toEqual({ status: 'not_found' });

    // Replaying the SAME mutation/key body from the second session is a
    // session-context idempotency conflict, never a replayed receipt.
    await expectCode(
      store.createPolicy(secondHash, owner.org, policyContent(owner.org, 130), {
        idempotencyKey: key(130),
        mutationId: mutationId(130),
      }),
      'CONTROL_POLICY_STORE_IDEMPOTENCY_CONFLICT',
    );

    // The original session still retrieves its own receipt unchanged and the
    // conflict left exactly one durable record for the mutation.
    const stillOwn = await store.getPolicyMutationStatus(owner.hash, owner.org, mutationId(130));
    expect(stillOwn.status).toBe('committed');
    const durable = await counts(owner.org);
    expect(durable.idem).toBe(1);
    expect(durable.audit).toBe(1);
    expect(durable.outbox).toBe(1);
    void created;
  });

  it('enforces at most one active root per organization and subject agent', async () => {
    const owner = await seedOwner(170);
    await seedAgent(170, owner.org);
    const subject = { subjectAgentId: agentId(170) };
    const first = await createPolicy(owner, 170);
    const firstPolicy = first.receipt.resourceId;
    // A second create for the same payer org/subject is rejected atomically.
    await expectCode(createPolicy(owner, 171, subject), 'CONTROL_POLICY_STORE_CONFLICT');
    let root = await rootOf(owner.org, firstPolicy);
    await store.transitionPolicy(
      owner.hash,
      owner.org,
      firstPolicy,
      { operation: 'control.policy.revoke', expectedRevision: '1', expectedUpdatedAt: root.updated_at },
      { idempotencyKey: key(172), mutationId: mutationId(172) },
    );
    const second = await createPolicy(owner, 173, subject);
    const secondPolicy = second.receipt.resourceId;
    root = await rootOf(owner.org, secondPolicy);
    await store.transitionPolicy(
      owner.hash,
      owner.org,
      secondPolicy,
      { operation: 'control.policy.pause', expectedRevision: '1', expectedUpdatedAt: root.updated_at },
      { idempotencyKey: key(174), mutationId: mutationId(174) },
    );
    // Only one active root may exist; a fresh create is allowed because the
    // second is paused, but resuming it while the third is active must fail.
    const third = await createPolicy(owner, 175, subject);
    const thirdPolicy = third.receipt.resourceId;
    expect((await rootOf(owner.org, thirdPolicy)).status).toBe('active');
    const secondRoot = await rootOf(owner.org, secondPolicy);
    await expectCode(
      store.transitionPolicy(
        owner.hash,
        owner.org,
        secondPolicy,
        { operation: 'control.policy.resume', expectedRevision: '1', expectedUpdatedAt: secondRoot.updated_at },
        { idempotencyKey: key(177), mutationId: mutationId(177) },
      ),
      'CONTROL_POLICY_STORE_CONFLICT',
    );
  });

  it('serializes simultaneous creates on two connections to exactly one active root', async () => {
    const owner = await seedOwner(180);
    await seedAgent(180, owner.org);
    const subject = { subjectAgentId: agentId(180) };
    const attempt = (seed: number) =>
      store.createPolicy(
        owner.hash,
        owner.org,
        policyContent(owner.org, 180, subject),
        { idempotencyKey: key(seed), mutationId: mutationId(seed) },
      );
    const settled = await Promise.allSettled([attempt(181), attempt(182)]);
    const fulfilled = settled.filter(
      (result): result is PromiseFulfilledResult<Awaited<ReturnType<typeof attempt>>> =>
        result.status === 'fulfilled',
    );
    const rejected = settled.filter(
      (result): result is PromiseRejectedResult => result.status === 'rejected',
    );
    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect(rejected[0]?.reason).toBeInstanceOf(ControlPolicyStoreError);
    expect((rejected[0]?.reason as ControlPolicyStoreError).code).toBe('CONTROL_POLICY_STORE_CONFLICT');
    // Exactly one active root and no orphan version rows.
    const active = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM openarc_tenant.budget_policy_roots
        WHERE organization_id = $1 AND subject_agent_id = $2 AND status = 'active'`,
      [owner.org, agentId(180)],
    );
    expect(active.rows[0]?.n).toBe(1);
    const all = await counts(owner.org);
    const winnerPolicy = fulfilled[0]?.value.receipt.resourceId as string;
    expect(all.roots).toBe(1);
    expect(all.versions).toBe(1);
    expect(all.idem).toBe(1);
    expect(all.audit).toBe(1);
    expect(all.outbox).toBe(1);
    // The loser left no idempotency, audit or outbox residue, and the winner is
    // the only policy root.
    const rows = await admin.query<{ policy_id: string }>(
      'SELECT policy_id FROM openarc_tenant.budget_policy_roots WHERE organization_id = $1',
      [owner.org],
    );
    expect(rows.rows.map((row) => row.policy_id)).toEqual([winnerPolicy]);
    const versions = await admin.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM openarc_tenant.budget_policy_versions WHERE organization_id = $1',
      [owner.org],
    );
    expect(versions.rows[0]?.n).toBe(1);
  }, 20000);

  it('loses a paused-root resume that races a new create for the same subject', async () => {
    const owner = await seedOwner(190);
    await seedAgent(190, owner.org);
    const subject = { subjectAgentId: agentId(190) };
    const first = await createPolicy(owner, 190, subject);
    const firstPolicy = first.receipt.resourceId;
    let root = await rootOf(owner.org, firstPolicy);
    await store.transitionPolicy(
      owner.hash,
      owner.org,
      firstPolicy,
      { operation: 'control.policy.pause', expectedRevision: '1', expectedUpdatedAt: root.updated_at },
      { idempotencyKey: key(191), mutationId: mutationId(191) },
    );
    root = await rootOf(owner.org, firstPolicy);
    // Baseline after the original root + pause. The race may add exactly one
    // winner's durability; neither branch deletes the paused root/history.
    const baseline = await counts(owner.org);
    expect(baseline).toMatchObject({ roots: 1, versions: 1, idem: 2, audit: 2, outbox: 2 });
    // Race: resume the paused root against a fresh create for the same subject.
    const settled = await Promise.allSettled([
      store.transitionPolicy(
        owner.hash,
        owner.org,
        firstPolicy,
        { operation: 'control.policy.resume', expectedRevision: '1', expectedUpdatedAt: root.updated_at },
        { idempotencyKey: key(192), mutationId: mutationId(192) },
      ),
      createPolicy(owner, 193, subject),
    ]);
    const fulfilled = settled.filter((result) => result.status === 'fulfilled');
    const rejected = settled.filter(
      (result): result is PromiseRejectedResult => result.status === 'rejected',
    );
    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect(rejected[0]?.reason).toBeInstanceOf(ControlPolicyStoreError);
    expect((rejected[0]?.reason as ControlPolicyStoreError).code).toBe('CONTROL_POLICY_STORE_CONFLICT');
    // Exactly one additional idempotency/audit/outbox record for the winner.
    const after = await counts(owner.org);
    expect(after.idem).toBe(baseline.idem + 1);
    expect(after.audit).toBe(baseline.audit + 1);
    expect(after.outbox).toBe(baseline.outbox + 1);
    // settled[1] is the create attempt. If create won, a root/version was
    // added; if resume won, the paused root/version counts are unchanged.
    const createWon = settled[1]?.status === 'fulfilled';
    if (createWon) {
      expect(after.roots).toBe(baseline.roots + 1);
      expect(after.versions).toBe(baseline.versions + 1);
    } else {
      expect(after.roots).toBe(baseline.roots);
      expect(after.versions).toBe(baseline.versions);
    }
    // The original paused root and its history survive every branch.
    const original = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM openarc_tenant.budget_policy_roots
        WHERE organization_id = $1 AND policy_id = $2`,
      [owner.org, firstPolicy],
    );
    expect(original.rows[0]?.n).toBe(1);
    const originalVersions = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM openarc_tenant.budget_policy_versions
        WHERE organization_id = $1 AND policy_id = $2`,
      [owner.org, firstPolicy],
    );
    expect(originalVersions.rows[0]?.n).toBeGreaterThanOrEqual(1);
    // The loser's mutation ID left no durability rows at all.
    const loserMutation = createWon ? mutationId(192) : mutationId(193);
    const residue = await admin.query<{ n: number }>(
      `SELECT (
                (SELECT count(*)::int FROM openarc_durable.idempotency_records
                  WHERE organization_id = $1 AND mutation_id = $2::uuid)
              + (SELECT count(*)::int FROM openarc_durable.audit_events
                  WHERE organization_id = $1 AND mutation_id = $2::uuid)
              + (SELECT count(*)::int FROM openarc_durable.outbox_events
                  WHERE organization_id = $1 AND mutation_id = $2::uuid)
              )::int AS n`,
      [owner.org, loserMutation],
    );
    expect(residue.rows[0]?.n).toBe(0);
    // Exactly one active root remains for the subject.
    const active = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM openarc_tenant.budget_policy_roots
        WHERE organization_id = $1 AND subject_agent_id = $2 AND status = 'active'`,
      [owner.org, agentId(190)],
    );
    expect(active.rows[0]?.n).toBe(1);
  }, 20000);
});

describe('lock waits, rollback and durability', () => {
  it('rechecks the held session after a blocking organization lock', async () => {
    const owner = await seedOwner(130);
    await seedAgent(130, owner.org);
    await shortenSession(owner.hash, 2);
    const blocker = await admin.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query(
        'SELECT 1 FROM openarc_tenant.organizations WHERE organization_id = $1 FOR UPDATE',
        [owner.org],
      );
      const attempt = createPolicy(owner, 130);
      await waitForLockWait();
      await waitUntilSessionExpired(owner.hash);
      await blocker.query('ROLLBACK');
      await expectCode(attempt, 'CONTROL_POLICY_STORE_SESSION_INVALID');
    } finally {
      await blocker.query('ROLLBACK').catch(() => {});
      blocker.release();
    }
  }, 20000);

  it('rolls back every row when the outbox insert fails', async () => {
    const owner = await seedOwner(140);
    await seedAgent(140, owner.org);
    await admin.query(
      `CREATE FUNCTION openarc_tenant.test_inject_policy_outbox_failure() RETURNS trigger
         LANGUAGE plpgsql SET search_path = pg_catalog AS $$
         BEGIN
           IF NEW.event_type LIKE 'control.policy%' THEN
             RAISE EXCEPTION 'injected_outbox_failure' USING ERRCODE = '42501';
           END IF;
           RETURN NEW;
         END;
         $$`,
    );
    await admin.query(
      `CREATE TRIGGER test_inject_policy_outbox_failure
         BEFORE INSERT ON openarc_durable.outbox_events
         FOR EACH ROW EXECUTE FUNCTION openarc_tenant.test_inject_policy_outbox_failure()`,
    );
    try {
      await expectCode(createPolicy(owner, 140), 'CONTROL_POLICY_STORE_FORBIDDEN');
      expect(await counts(owner.org)).toMatchObject({ roots: 0, versions: 0, idem: 0, audit: 0, outbox: 0 });
    } finally {
      await admin.query('DROP TRIGGER test_inject_policy_outbox_failure ON openarc_durable.outbox_events');
      await admin.query('DROP FUNCTION openarc_tenant.test_inject_policy_outbox_failure()');
    }
  });

  it('claims the five policy outbox tuples through the worker store', async () => {
    const owner = await seedOwner(150);
    await seedAgent(150, owner.org);
    const created = await createPolicy(owner, 150);
    const policy = created.receipt.resourceId;
    let root = await rootOf(owner.org, policy);
    await store.appendPolicyRevision(
      owner.hash,
      owner.org,
      policy,
      { expectedRevision: '1', expectedUpdatedAt: root.updated_at, content: policyContent(owner.org, 150) },
      { idempotencyKey: key(151), mutationId: mutationId(151) },
    );
    root = await rootOf(owner.org, policy);
    await store.transitionPolicy(
      owner.hash,
      owner.org,
      policy,
      { operation: 'control.policy.pause', expectedRevision: '2', expectedUpdatedAt: root.updated_at },
      { idempotencyKey: key(152), mutationId: mutationId(152) },
    );
    root = await rootOf(owner.org, policy);
    await store.transitionPolicy(
      owner.hash,
      owner.org,
      policy,
      { operation: 'control.policy.resume', expectedRevision: '2', expectedUpdatedAt: root.updated_at },
      { idempotencyKey: key(153), mutationId: mutationId(153) },
    );
    root = await rootOf(owner.org, policy);
    await store.transitionPolicy(
      owner.hash,
      owner.org,
      policy,
      { operation: 'control.policy.revoke', expectedRevision: '2', expectedUpdatedAt: root.updated_at },
      { idempotencyKey: key(154), mutationId: mutationId(154) },
    );
    const { OutboxStore } = await import('../src/index.js');
    const outbox = new OutboxStore(worker);
    const claimed = await outbox.claim({ limit: 10 });
    expect(claimed.map((event) => event.eventType).sort()).toEqual([
      'control.policy.created',
      'control.policy.paused',
      'control.policy.resumed',
      'control.policy.revision.created',
      'control.policy.revoked',
    ]);
    expect(claimed.find((event) => event.eventType === 'control.policy.revision.created')?.resourceId).toBe(`${policy}@2`);
  }, 20000);
});

describe('schema7 to schema8 upgrade preserves records and replay', () => {
  it('keeps tenant durable receipts and starts with zero policy rows', async () => {
    await resetSchema(admin);
    const all = loadMigrations();
    await migrate(migrator, all.slice(0, 7));
    const owner = await seedOwner(160);
    const base = new TenantStore(tenant);
    const meta = { idempotencyKey: key(160), mutationId: mutationId(160) };
    await base.createAgentDurably(owner.hash, owner.org, 'Legacy Agent', meta);
    await migrate(migrator);
    const applied = await admin.query<{ id: string }>('SELECT id FROM openarc_meta.schema_migrations ORDER BY id');
    expect(applied.rows.map((row) => row.id)).toContain('0008_control_policies');
    const replay = await base.createAgentDurably(owner.hash, owner.org, 'Legacy Agent', meta);
    expect(replay.replayed).toBe(true);
    expect(await counts(owner.org)).toMatchObject({ roots: 0, versions: 0, idem: 0 });
    await seedAgent(160, owner.org);
    await seedAgent(161, owner.org);
    const created = await createPolicy(owner, 161);
    expect(created.receipt.resourceId).toMatch(/^openarc:policy:/);
  }, 20000);
});
