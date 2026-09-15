import { createHash } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import {
  CommerceSessionStore,
  CommerceSessionStoreError,
  ControlPolicyStore,
  CredentialStore,
  OutboxStore,
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
 * Real PostgreSQL acceptance for schema9 explicit commerce-session persistence.
 * Every mutation runs against the restricted runtime role (openarc_tenant_app);
 * direct table access, forged GUCs and cross-principal reads must fail.
 */

function sha256(seed: string): string {
  return createHash('sha256').update(`openarc-commerce-session-test:${seed}`, 'utf8').digest('hex');
}

function uuid(seed: number): string {
  return `30000000-0000-4000-8000-${String(seed).padStart(12, '0')}`;
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

function policyId(seed: number): string {
  return `openarc:policy:${uuid(seed)}`;
}

function mutationId(seed: number): string {
  return uuid(700000 + seed);
}

function lookupId(seed: number): string {
  return uuid(900000 + seed);
}

function sessionUuid(seed: number): string {
  return uuid(600000 + seed);
}

function key(seed: number): string {
  return createHash('sha256').update(`commerce-session-key:${seed}`).digest().toString('base64url');
}

function userHandle(seed: number): string {
  return `${sha256(`handle:${seed}`).slice(0, 42)}A`;
}

const SALT = Buffer.alloc(16, 7).toString('base64url');
const DIGEST = Buffer.alloc(32, 8).toString('base64url');

function hashInput() {
  return {
    algorithm: 'scrypt' as const,
    hashVersion: 1 as const,
    pepperVersion: 1,
    N: 32768 as const,
    r: 8 as const,
    p: 1 as const,
    salt: SALT,
    digest: DIGEST,
  };
}

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(CommerceSessionStoreError);
    expect((error as CommerceSessionStoreError).code).toBe(code);
    return;
  }
  throw new Error(`expected CommerceSessionStoreError ${code}`);
}

async function rawError(promise: Promise<unknown>): Promise<{ code?: string }> {
  try {
    await promise;
  } catch (error) {
    return error as { code?: string };
  }
  throw new Error('expected a raw SQL rejection');
}

let admin: Pool;
let migrator: ReturnType<typeof createDatabasePool>;
let tenant: ReturnType<typeof createDatabasePool>;
let worker: ReturnType<typeof createDatabasePool>;
let auth: ReturnType<typeof createDatabasePool>;
let store: CommerceSessionStore;
let credentials: CredentialStore;

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
  store = new CommerceSessionStore(tenant);
  credentials = new CredentialStore(tenant);
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

interface SeededOwner {
  readonly account: string;
  readonly org: string;
  readonly hash: string;
}

async function seedOwner(seed: number, role = 'owner'): Promise<SeededOwner> {
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

async function seedAgent(seed: number, org: string, status = 'active'): Promise<string> {
  const id = agentId(seed);
  await admin.query(
    'INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name, status) VALUES ($1, $2, $3, $4)',
    [org, id, `Agent ${seed}`, status],
  );
  return id;
}

/** Seed an active policy root + revision directly (independent of DB8 store). */
async function seedPolicy(
  org: string,
  subject: string,
  seed: number,
  options: { status?: string; expiresOffset?: string } = {},
): Promise<string> {
  const id = policyId(seed);
  const client = await admin.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `INSERT INTO openarc_tenant.budget_policy_roots
         (organization_id, policy_id, subject_agent_id, current_revision, status)
       VALUES ($1, $2, $3, '1', $4)`,
      [org, id, subject, options.status ?? 'active'],
    );
    await client.query(
      `INSERT INTO openarc_tenant.budget_policy_versions
         (organization_id, policy_id, revision, subject_agent_id, network_id, asset,
          representation, decimals, per_action_limit, rolling_limit, rolling_window_seconds,
          fee_limit, allowed_provider_ids, allowed_listing_ids, approval_mode,
          approval_threshold, approval_separate_approver, expires_at, digest)
       VALUES ($1, $2, '1', $3, 'eip155:5042002', 'USDC', 'erc20', 6, '1000000', '5000000',
               '3600', '0', ARRAY[]::text[], ARRAY[]::text[], 'none', NULL, false,
               clock_timestamp() + ($4)::interval, 'sha256:' || repeat('a', 64))`,
      [org, id, subject, options.expiresOffset ?? '1 hour'],
    );
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
  return id;
}

interface SeededMachine {
  readonly agent: string;
  readonly policy: string;
  readonly credential: string;
  readonly tokenHash: string;
}

async function seedMachine(
  owner: SeededOwner,
  seed: number,
  options: { agentStatus?: string; policyStatus?: string; policyOffset?: string; expiresOffset?: string } = {},
): Promise<SeededMachine> {
  const agent = await seedAgent(seed, owner.org, options.agentStatus ?? 'active');
  const policy = await seedPolicy(owner.org, agent, seed, {
    status: options.policyStatus,
    expiresOffset: options.policyOffset,
  });
  const issued = await credentials.issueAgentCredentialDurably({
    sessionHash: owner.hash,
    organizationId: owner.org,
    profileId: agent,
    lookupId: lookupId(seed),
    hash: hashInput(),
    expiresAt: new Date(Date.now() + 30 * 60_000).toISOString(),
    metadata: { idempotencyKey: key(500000 + seed), mutationId: mutationId(500000 + seed) },
  });
  const credential = issued.receipt.credentialId;
  const tokenHash = sha256(`machine:${seed}`);
  await credentials.createAgentSession({
    organizationId: owner.org,
    profileId: agent,
    credentialId: credential,
    expectedVersion: 1,
    sessionId: sessionUuid(seed),
    tokenHash,
    expiresAt: options.expiresOffset
      ? new Date(Date.now() + Number.parseInt(options.expiresOffset, 10) * 60_000).toISOString()
      : new Date(Date.now() + 10 * 60_000).toISOString(),
  });
  return { agent, policy, credential, tokenHash };
}

function issueInput(machine: Pick<SeededMachine, 'agent' | 'policy'>, seed: number, overrides: Record<string, unknown> = {}) {
  return {
    subjectAgentId: machine.agent,
    policyId: machine.policy,
    handoffHash: sha256(`handoff:${seed}`),
    hashVersion: 1 as const,
    ...overrides,
  };
}

async function counts(org: string): Promise<Record<string, number>> {
  const result = await admin.query<Record<string, number>>(
    `SELECT
       (SELECT count(*)::int FROM openarc_durable.commerce_sessions WHERE organization_id = $1) AS sessions,
       (SELECT count(*)::int FROM openarc_durable.commerce_session_handoffs WHERE organization_id = $1) AS handoffs,
       (SELECT count(*)::int FROM openarc_durable.idempotency_records WHERE organization_id = $1 AND operation LIKE 'control.commerce_session%') AS idem,
       (SELECT count(*)::int FROM openarc_durable.audit_events WHERE organization_id = $1 AND operation LIKE 'control.commerce_session%') AS audit,
       (SELECT count(*)::int FROM openarc_durable.outbox_events WHERE organization_id = $1 AND event_type LIKE 'control.commerce_session%') AS outbox`,
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

async function shortenCredential(credentialId: string, seconds: number): Promise<void> {
  await admin.query(
    `UPDATE openarc_durable.agent_credentials
        SET expires_at = GREATEST(created_at + interval '1 millisecond',
                                  clock_timestamp() + make_interval(secs => $2))
      WHERE credential_id = $1::uuid`,
    [credentialId, seconds],
  );
}

async function expireCommerceSession(sessionId: string): Promise<void> {
  await admin.query(
    `UPDATE openarc_durable.commerce_sessions
        SET expires_at = COALESCE(exchanged_at + interval '1 microsecond',
                                  issued_at + interval '1 millisecond')
      WHERE session_id = $1::uuid`,
    [sessionId],
  );
}

async function statusOf(hash: string, org: string, sessionId: string): Promise<string | null> {
  const result = await store.getCommerceSessionStatus(hash, org, sessionId);
  return result.item?.status ?? null;
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

describe('schema9 manifest, ownership, ACLs and readiness', () => {
  it('records schema9 and keeps the commerce-session helpers migrator-owned with fixed search_path', async () => {
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
        WHERE n.nspname = 'openarc_durable'
          AND c.relname IN ('commerce_sessions', 'commerce_session_handoffs')
        ORDER BY c.relname`,
    );
    expect(tables.rows).toEqual([
      { relname: 'commerce_session_handoffs', owner: 'openarc_migrator', rls: true, forced: true },
      { relname: 'commerce_sessions', owner: 'openarc_migrator', rls: true, forced: true },
    ]);
    const helpers = await admin.query<{ proname: string; owner: string; secdef: boolean; config: string[] }>(
      `SELECT p.proname, r.rolname AS owner, p.prosecdef AS secdef,
              coalesce(p.proconfig, ARRAY[]::text[]) AS config
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         JOIN pg_roles r ON r.oid = p.proowner
        WHERE n.nspname = 'openarc_durable'
          AND p.proname IN (
            'issue_commerce_session', 'exchange_commerce_session', 'revoke_commerce_session',
            'read_commerce_session', 'list_commerce_sessions',
            'read_human_commerce_session_mutation_status',
            'read_agent_commerce_session_mutation_status'
          )
        ORDER BY p.proname`,
    );
    expect(helpers.rows).toHaveLength(7);
    expect(
      helpers.rows.every(
        (row) =>
          row.owner === 'openarc_migrator' &&
          row.secdef === true &&
          row.config.includes('search_path=pg_catalog'),
      ),
    ).toBe(true);
  });

  it('denies the runtime and worker direct commerce-session access and internal helper execute', async () => {
    expect(
      (await rawError(tenant.query('SELECT count(*) FROM openarc_durable.commerce_sessions'))).code,
    ).toBe('42501');
    expect(
      (
        await rawError(
          tenant.query(
            `INSERT INTO openarc_durable.commerce_sessions
               (organization_id, session_id, parent_human_session_hash, parent_human_account_id,
                subject_agent_id, policy_id, scope, scope_version, network_id, asset,
                representation, decimals, issued_at, initial_expires_at, expires_at)
             VALUES ('x', gen_random_uuid(), repeat('a',64), 'y', 'z', 'p', 'commerce.authorize',
                     1, 'eip155:5042002', 'USDC', 'erc20', 6, now(), now(), now())`,
          ),
        )
      ).code,
    ).toBe('42501');
    expect(
      (await rawError(worker.query('SELECT count(*) FROM openarc_durable.commerce_sessions'))).code,
    ).toBe('42501');
    const internal = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'openarc_durable'
          AND p.proname IN ('lock_commerce_human', 'enforce_commerce_session_mutation',
                            'enforce_commerce_handoff_mutation', 'enforce_commerce_handoff_window',
                            'enforce_commerce_session_binding')
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
    await admin.query('ALTER TABLE openarc_durable.commerce_sessions NO FORCE ROW LEVEL SECURITY');
    await expectCode(store.readiness(), 'COMMERCE_SESSION_STORE_UNAVAILABLE');
  });

  it('fails readiness when the session immutability trigger is disabled', async () => {
    await admin.query('ALTER TABLE openarc_durable.commerce_sessions DISABLE TRIGGER commerce_sessions_mutation');
    await expectCode(store.readiness(), 'COMMERCE_SESSION_STORE_UNAVAILABLE');
  });

  it('fails readiness when the handoff window trigger is disabled', async () => {
    await admin.query('ALTER TABLE openarc_durable.commerce_session_handoffs DISABLE TRIGGER commerce_session_handoffs_window');
    await expectCode(store.readiness(), 'COMMERCE_SESSION_STORE_UNAVAILABLE');
  });

  it('fails readiness when the exchange shape CHECK is dropped', async () => {
    await admin.query('ALTER TABLE openarc_durable.commerce_sessions DROP CONSTRAINT commerce_sessions_exchange_shape');
    await expectCode(store.readiness(), 'COMMERCE_SESSION_STORE_UNAVAILABLE');
  });

  it('fails readiness when the handoff session FK is dropped', async () => {
    await admin.query('ALTER TABLE openarc_durable.commerce_session_handoffs DROP CONSTRAINT commerce_session_handoffs_session_fk');
    await expectCode(store.readiness(), 'COMMERCE_SESSION_STORE_UNAVAILABLE');
  });

  it('fails readiness when the token-hash unique index is dropped', async () => {
    await admin.query('ALTER TABLE openarc_durable.commerce_session_handoffs DROP CONSTRAINT commerce_session_handoffs_token_unique');
    await expectCode(store.readiness(), 'COMMERCE_SESSION_STORE_UNAVAILABLE');
  });

  it('fails readiness when a trigger helper search_path is altered', async () => {
    await admin.query('ALTER FUNCTION openarc_durable.enforce_commerce_session_mutation() SET search_path = public');
    await expectCode(store.readiness(), 'COMMERCE_SESSION_STORE_UNAVAILABLE');
  });

  it('resists forged GUC authority and bogus session hashes', async () => {
    const owner = await seedOwner(70);
    const machine = await seedMachine(owner, 70);
    const client = await tenant.connect();
    try {
      await client.query("SELECT set_config('openarc.account_id', $1, true)", [owner.account]);
      await client.query("SELECT set_config('openarc.organization_id', $1, true)", [owner.org]);
      await client.query("SELECT set_config('openarc.role', 'owner', true)");
      const denied = await rawError(client.query('SELECT count(*) FROM openarc_durable.commerce_sessions'));
      expect(denied.code).toBe('42501');
    } finally {
      client.release();
    }
    await expectCode(
      store.issueCommerceSession(
        'f'.repeat(64),
        owner.org,
        issueInput(machine, 70),
        { idempotencyKey: key(70), mutationId: mutationId(70) },
      ),
      'COMMERCE_SESSION_STORE_SESSION_INVALID',
    );
  });
});

describe('human issue, exchange, revoke lifecycle', () => {
  it('issues a pending session with a bounded handoff, then exchanges and revokes', async () => {
    const owner = await seedOwner(10);
    const machine = await seedMachine(owner, 10);
    const issued = await store.issueCommerceSession(
      owner.hash,
      owner.org,
      issueInput(machine, 10),
      { idempotencyKey: key(10), mutationId: mutationId(10) },
    );
    expect(issued.replayed).toBe(false);
    expect(issued.receipt.operation).toBe('control.commerce_session.issue');
    expect(issued.receipt.resourceType).toBe('commerce_session');
    expect(issued.receipt.resourceId).toBe(mutationId(10));
    expect(issued.metadata.exchangedAt).toBeNull();
    expect(issued.metadata.revokedAt).toBeNull();
    expect(JSON.parse(JSON.stringify(issued.metadata)).sessionId).toBe(mutationId(10));
    expect(JSON.stringify(issued)).not.toContain(machine.tokenHash);

    // Handoff expiry is within 300s of issued and at or before session expiry.
    const issuedMs = Date.parse(issued.metadata.issuedAt);
    const handoffMs = Date.parse(issued.handoffExpiresAt);
    const expiresMs = Date.parse(issued.metadata.expiresAt);
    expect(handoffMs).toBeGreaterThan(issuedMs);
    expect(handoffMs).toBeLessThanOrEqual(issuedMs + 300_000);
    expect(handoffMs).toBeLessThanOrEqual(expiresMs);

    const pending = await store.getCommerceSessionStatus(owner.hash, owner.org, mutationId(10));
    expect(pending.item?.status).toBe('handoff_pending');

    const exchanged = await store.exchangeCommerceSession(
      machine.tokenHash,
      issueInput(machine, 10).handoffHash,
      { tokenHash: sha256('session-token:10'), hashVersion: 1 },
      { idempotencyKey: key(11), mutationId: mutationId(11) },
    );
    expect(exchanged.replayed).toBe(false);
    expect(exchanged.receipt.operation).toBe('control.commerce_session.exchange');
    expect(exchanged.metadata.exchangedAt).not.toBeNull();
    expect(exchanged.metadata.revokedAt).toBeNull();

    const active = await store.getCommerceSessionStatus(owner.hash, owner.org, mutationId(10));
    expect(active.item?.status).toBe('active');

    const revoked = await store.revokeCommerceSession(
      owner.hash,
      owner.org,
      mutationId(10),
      { idempotencyKey: key(12), mutationId: mutationId(12) },
    );
    expect(revoked.replayed).toBe(false);
    expect(revoked.receipt.operation).toBe('control.commerce_session.revoke');
    expect(revoked.metadata.revokedAt).not.toBeNull();

    const after = await store.getCommerceSessionStatus(owner.hash, owner.org, mutationId(10));
    expect(after.item?.status).toBe('revoked');
    expect(await counts(owner.org)).toMatchObject({ sessions: 1, handoffs: 1, idem: 3, audit: 3, outbox: 3 });
  });

  it('replays an issue with a fresh random handoff hash and keeps the original record', async () => {
    const owner = await seedOwner(20);
    const machine = await seedMachine(owner, 20);
    const first = await store.issueCommerceSession(
      owner.hash,
      owner.org,
      issueInput(machine, 20),
      { idempotencyKey: key(20), mutationId: mutationId(20) },
    );
    const replay = await store.issueCommerceSession(
      owner.hash,
      owner.org,
      issueInput(machine, 20, { handoffHash: sha256('regenerated-handoff:20') }),
      { idempotencyKey: key(20), mutationId: mutationId(20) },
    );
    expect(replay.replayed).toBe(true);
    expect(replay.receipt).toEqual(first.receipt);
    expect(replay.handoffExpiresAt).toBe(first.handoffExpiresAt);
    expect(await counts(owner.org)).toMatchObject({ sessions: 1, handoffs: 1, idem: 1, audit: 1, outbox: 1 });
  });

  it('replays a committed issue after the policy is revoked', async () => {
    const owner = await seedOwner(30);
    const machine = await seedMachine(owner, 30);
    const first = await store.issueCommerceSession(
      owner.hash,
      owner.org,
      issueInput(machine, 30),
      { idempotencyKey: key(30), mutationId: mutationId(30) },
    );
    await admin.query(
      `UPDATE openarc_tenant.budget_policy_roots
          SET status = 'revoked',
              updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')
        WHERE organization_id = $1 AND policy_id = $2`,
      [owner.org, machine.policy],
    );
    const replay = await store.issueCommerceSession(
      owner.hash,
      owner.org,
      issueInput(machine, 30, { handoffHash: sha256('regen-30') }),
      { idempotencyKey: key(30), mutationId: mutationId(30) },
    );
    expect(replay.replayed).toBe(true);
    expect(replay.receipt).toEqual(first.receipt);
    // A fresh key cannot issue against the now-revoked policy.
    await expectCode(
      store.issueCommerceSession(
        owner.hash,
        owner.org,
        issueInput(machine, 30),
        { idempotencyKey: key(31), mutationId: mutationId(31) },
      ),
      'COMMERCE_SESSION_STORE_FORBIDDEN',
    );
  });

  it('finds a committed exchange replay after the approving parent session expired', async () => {
    const owner = await seedOwner(35);
    const machine = await seedMachine(owner, 35);
    const handoff = sha256('handoff:35');
    await store.issueCommerceSession(owner.hash, owner.org, issueInput(machine, 35), {
      idempotencyKey: key(35),
      mutationId: mutationId(35),
    });
    const exchanged = await store.exchangeCommerceSession(
      machine.tokenHash,
      handoff,
      { tokenHash: sha256('session-token:35'), hashVersion: 1 },
      { idempotencyKey: key(36), mutationId: mutationId(36) },
    );
    // Force the parent human session into the past WITHOUT deleting it.
    await admin.query(
      `UPDATE openarc_auth.sessions
          SET created_at = clock_timestamp() - interval '2 hours',
              expires_at = clock_timestamp() - interval '1 hour'
        WHERE token_hash = $1`,
      [owner.hash],
    );
    // The agent machine session is still live; replay must still find the receipt.
    const replay = await store.exchangeCommerceSession(
      machine.tokenHash,
      handoff,
      { tokenHash: sha256('regen-token:35'), hashVersion: 1 },
      { idempotencyKey: key(36), mutationId: mutationId(36) },
    );
    expect(replay.replayed).toBe(true);
    expect(replay.receipt).toEqual(exchanged.receipt);
    expect(JSON.stringify(replay)).not.toContain(sha256('session-token:35'));
  });

  it('replays an exchange after revoke without returning a token and never rebinds', async () => {
    const owner = await seedOwner(40);
    const machine = await seedMachine(owner, 40);
    const handoff = sha256('handoff:40');
    await store.issueCommerceSession(owner.hash, owner.org, issueInput(machine, 40), {
      idempotencyKey: key(40),
      mutationId: mutationId(40),
    });
    const exchanged = await store.exchangeCommerceSession(
      machine.tokenHash,
      handoff,
      { tokenHash: sha256('session-token:40'), hashVersion: 1 },
      { idempotencyKey: key(41), mutationId: mutationId(41) },
    );
    await store.revokeCommerceSession(owner.hash, owner.org, mutationId(40), {
      idempotencyKey: key(42),
      mutationId: mutationId(42),
    });
    const replay = await store.exchangeCommerceSession(
      machine.tokenHash,
      handoff,
      { tokenHash: sha256('regenerated-token:40'), hashVersion: 1 },
      { idempotencyKey: key(41), mutationId: mutationId(41) },
    );
    expect(replay.replayed).toBe(true);
    expect(replay.receipt).toEqual(exchanged.receipt);
    expect(JSON.stringify(replay)).not.toContain(sha256('session-token:40'));
    expect(await counts(owner.org)).toMatchObject({ sessions: 1, handoffs: 1, idem: 3, audit: 3, outbox: 3 });
  });
});

describe('authority, roles and proof', () => {
  it('lets a viewer/status reader read but denies writes, and denies recovery/provider writes', async () => {
    const owner = await seedOwner(110);
    const machine = await seedMachine(owner, 110);
    const viewer = await seedMember(111, owner.org, 'viewer');
    const provider = await seedMember(112, owner.org, 'provider_admin');
    const recovery = await seedMember(113, owner.org, 'owner', { method: 'recovery' });
    const issued = await store.issueCommerceSession(
      owner.hash,
      owner.org,
      issueInput(machine, 110),
      { idempotencyKey: key(110), mutationId: mutationId(110) },
    );
    // owner/operator may read status; viewer and provider are denied entirely.
    await expect(
      store.getCommerceSessionStatus(owner.hash, owner.org, issued.receipt.resourceId),
    ).resolves.toMatchObject({ organizationId: owner.org });
    await expectCode(
      store.getCommerceSessionStatus(viewer.hash, owner.org, issued.receipt.resourceId),
      'COMMERCE_SESSION_STORE_FORBIDDEN',
    );
    await expectCode(
      store.getCommerceSessionStatus(provider.hash, owner.org, issued.receipt.resourceId),
      'COMMERCE_SESSION_STORE_FORBIDDEN',
    );
    await expectCode(
      store.issueCommerceSession(viewer.hash, owner.org, issueInput(machine, 110), {
        idempotencyKey: key(111),
        mutationId: mutationId(111),
      }),
      'COMMERCE_SESSION_STORE_FORBIDDEN',
    );
    await expectCode(
      store.issueCommerceSession(recovery.hash, owner.org, issueInput(machine, 110), {
        idempotencyKey: key(112),
        mutationId: mutationId(112),
      }),
      'COMMERCE_SESSION_STORE_SESSION_INVALID',
    );
  });

  it('rejects a stale or recovery-session human proof for issue and revoke', async () => {
    const owner = await seedOwner(120);
    const machine = await seedMachine(owner, 120);
    const stale = await seedMember(121, owner.org, 'owner', {
      createdOffset: '-10 minutes',
      expiresOffset: '23 hours',
    });
    await expectCode(
      store.issueCommerceSession(stale.hash, owner.org, issueInput(machine, 120), {
        idempotencyKey: key(120),
        mutationId: mutationId(120),
      }),
      'COMMERCE_SESSION_STORE_SESSION_INVALID',
    );
    const recovery = await seedMember(122, owner.org, 'owner', { method: 'recovery' });
    await expectCode(
      store.issueCommerceSession(recovery.hash, owner.org, issueInput(machine, 120), {
        idempotencyKey: key(121),
        mutationId: mutationId(121),
      }),
      'COMMERCE_SESSION_STORE_SESSION_INVALID',
    );
  });

  it('lets a current owner revoke a delegation after its parent session expired', async () => {
    const owner = await seedOwner(130);
    const machine = await seedMachine(owner, 130);
    const issued = await store.issueCommerceSession(
      owner.hash,
      owner.org,
      issueInput(machine, 130),
      { idempotencyKey: key(130), mutationId: mutationId(130) },
    );
    // Expire the parent session without deleting it.
    await admin.query(
      `UPDATE openarc_auth.sessions
          SET created_at = clock_timestamp() - interval '2 hours',
              expires_at = clock_timestamp() - interval '1 hour'
        WHERE token_hash = $1`,
      [owner.hash],
    );
    // Revoke uses the CURRENT caller (a fresh operator), not the dead parent.
    const operator = await seedMember(131, owner.org, 'operator');
    const revoked = await store.revokeCommerceSession(
      operator.hash,
      owner.org,
      issued.receipt.resourceId,
      { idempotencyKey: key(131), mutationId: mutationId(131) },
    );
    expect(revoked.metadata.revokedAt).not.toBeNull();
  });

  it('locks differing parent/credential-issuer accounts in sorted order', async () => {
    const owner = await seedOwner(140);
    const operator = await seedMember(141, owner.org, 'operator');
    const agent = await seedAgent(140, owner.org);
    const policy = await seedPolicy(owner.org, agent, 140);
    const issued = await credentials.issueAgentCredentialDurably({
      sessionHash: operator.hash,
      organizationId: owner.org,
      profileId: agent,
      lookupId: lookupId(140),
      hash: hashInput(),
      expiresAt: new Date(Date.now() + 30 * 60_000).toISOString(),
      metadata: { idempotencyKey: key(140), mutationId: mutationId(140) },
    });
    const tokenHash = sha256('machine:140');
    await credentials.createAgentSession({
      organizationId: owner.org,
      profileId: agent,
      credentialId: issued.receipt.credentialId,
      expectedVersion: 1,
      sessionId: sessionUuid(140),
      tokenHash,
      expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
    });
    const session = await store.issueCommerceSession(
      owner.hash,
      owner.org,
      { subjectAgentId: agent, policyId: policy, handoffHash: sha256('handoff:140'), hashVersion: 1 },
      { idempotencyKey: key(141), mutationId: mutationId(141) },
    );
    const exchanged = await store.exchangeCommerceSession(
      tokenHash,
      sha256('handoff:140'),
      { tokenHash: sha256('session-token:140'), hashVersion: 1 },
      { idempotencyKey: key(142), mutationId: mutationId(142) },
    );
    expect(exchanged.metadata.sessionId).toBe(session.metadata.sessionId);
    expect(exchanged.metadata.exchangedAt).not.toBeNull();
  });
});

describe('exchange denials and one-exchange binding', () => {
  async function issueActive(seed: number, options: Record<string, unknown> = {}) {
    const owner = await seedOwner(seed);
    const machine = await seedMachine(owner, seed, options);
    const issued = await store.issueCommerceSession(
      owner.hash,
      owner.org,
      issueInput(machine, seed),
      { idempotencyKey: key(seed), mutationId: mutationId(seed) },
    );
    return { owner, machine, issued, handoff: issueInput(machine, seed).handoffHash };
  }

  it('rejects a wrong organisation handoff, a different agent and a live-credential mismatch', async () => {
    const a = await issueActive(210);
    const b = await issueActive(211);
    await expectCode(
      store.exchangeCommerceSession(
        a.machine.tokenHash,
        b.handoff,
        { tokenHash: sha256('token:210'), hashVersion: 1 },
        { idempotencyKey: key(210), mutationId: mutationId(210) },
      ),
      'COMMERCE_SESSION_STORE_NOT_FOUND',
    );
    // A different live agent machine session in the same org cannot bind it.
    const other = await seedMachine(a.owner, 212);
    await expectCode(
      store.exchangeCommerceSession(
        other.tokenHash,
        a.handoff,
        { tokenHash: sha256('token:212'), hashVersion: 1 },
        { idempotencyKey: key(211), mutationId: mutationId(211) },
      ),
      'COMMERCE_SESSION_STORE_NOT_FOUND',
    );
  });

  it('rejects a revoked credential and a revoked machine session', async () => {
    const owner = await seedOwner(220);
    const machine = await seedMachine(owner, 220);
    await store.issueCommerceSession(owner.hash, owner.org, issueInput(machine, 220), {
      idempotencyKey: key(220),
      mutationId: mutationId(220),
    });
    await credentials.revokeAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      credentialId: machine.credential,
      metadata: { idempotencyKey: key(221), mutationId: mutationId(221) },
    });
    await expectCode(
      store.exchangeCommerceSession(
        machine.tokenHash,
        issueInput(machine, 220).handoffHash,
        { tokenHash: sha256('token:220'), hashVersion: 1 },
        { idempotencyKey: key(222), mutationId: mutationId(222) },
      ),
      'COMMERCE_SESSION_STORE_FORBIDDEN',
    );
  });

  it('rejects a revoked approving parent and a revoked policy', async () => {
    const owner = await seedOwner(230);
    const machine = await seedMachine(owner, 230);
    await store.issueCommerceSession(owner.hash, owner.org, issueInput(machine, 230), {
      idempotencyKey: key(230),
      mutationId: mutationId(230),
    });
    await admin.query(
      `UPDATE openarc_tenant.memberships SET status = 'suspended'
        WHERE organization_id = $1 AND account_id = $2`,
      [owner.org, owner.account],
    );
    await expectCode(
      store.exchangeCommerceSession(
        machine.tokenHash,
        issueInput(machine, 230).handoffHash,
        { tokenHash: sha256('token:230'), hashVersion: 1 },
        { idempotencyKey: key(231), mutationId: mutationId(231) },
      ),
      'COMMERCE_SESSION_STORE_FORBIDDEN',
    );
  });

  it('allows exactly one exchange and never rebinds the handoff', async () => {
    const owner = await seedOwner(240);
    const machine = await seedMachine(owner, 240);
    const handoff = sha256('handoff:240');
    await store.issueCommerceSession(owner.hash, owner.org, issueInput(machine, 240), {
      idempotencyKey: key(240),
      mutationId: mutationId(240),
    });
    const attempt = (seed: number) =>
      store.exchangeCommerceSession(
        machine.tokenHash,
        handoff,
        { tokenHash: sha256(`token:240:${seed}`), hashVersion: 1 },
        { idempotencyKey: key(seed), mutationId: mutationId(seed) },
      );
    const settled = await Promise.allSettled([attempt(241), attempt(242)]);
    const fulfilled = settled.filter(
      (result): result is PromiseFulfilledResult<Awaited<ReturnType<typeof attempt>>> =>
        result.status === 'fulfilled',
    );
    const rejected = settled.filter(
      (result): result is PromiseRejectedResult => result.status === 'rejected',
    );
    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect(rejected[0]?.reason).toBeInstanceOf(CommerceSessionStoreError);
    const bound = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM openarc_durable.commerce_sessions
        WHERE organization_id = $1 AND exchanged_at IS NOT NULL`,
      [owner.org],
    );
    expect(bound.rows[0]?.n).toBe(1);
    const consumed = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM openarc_durable.commerce_session_handoffs
        WHERE organization_id = $1 AND consumed_at IS NOT NULL`,
      [owner.org],
    );
    expect(consumed.rows[0]?.n).toBe(1);
    expect(await counts(owner.org)).toMatchObject({ idem: 2, audit: 2, outbox: 2 });
  }, 20000);

  it('never creates a second session for one handoff', async () => {
    const owner = await seedOwner(250);
    const machine = await seedMachine(owner, 250);
    const handoff = sha256('handoff:250');
    await store.issueCommerceSession(owner.hash, owner.org, issueInput(machine, 250), {
      idempotencyKey: key(250),
      mutationId: mutationId(250),
    });
    await store.exchangeCommerceSession(
      machine.tokenHash,
      handoff,
      { tokenHash: sha256('token:250'), hashVersion: 1 },
      { idempotencyKey: key(251), mutationId: mutationId(251) },
    );
    // A different handoff hash cannot bind the already-bound session, and the
    // session binding is immutable.
    await expect(
      admin.query(
        `UPDATE openarc_durable.commerce_sessions
            SET exchanged_at = exchanged_at + interval '1 microsecond'
          WHERE organization_id = $1`,
        [owner.org],
      ),
    ).rejects.toBeTruthy();
    const sessions = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM openarc_durable.commerce_sessions WHERE organization_id = $1`,
      [owner.org],
    );
    expect(sessions.rows[0]?.n).toBe(1);
  });
});

describe('logout, recovery and history retention', () => {
  it('deletes the parent human session on logout/recovery without deleting commerce history', async () => {
    const owner = await seedOwner(310);
    const machine = await seedMachine(owner, 310);
    const issued = await store.issueCommerceSession(
      owner.hash,
      owner.org,
      issueInput(machine, 310),
      { idempotencyKey: key(310), mutationId: mutationId(310) },
    );
    await store.exchangeCommerceSession(
      machine.tokenHash,
      issueInput(machine, 310).handoffHash,
      { tokenHash: sha256('token:310'), hashVersion: 1 },
      { idempotencyKey: key(311), mutationId: mutationId(311) },
    );
    // Simulate logout/recovery deleting the auth.sessions parent row.
    await admin.query('DELETE FROM openarc_auth.sessions WHERE token_hash = $1', [owner.hash]);
    const sessions = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM openarc_durable.commerce_sessions WHERE organization_id = $1`,
      [owner.org],
    );
    expect(sessions.rows[0]?.n).toBe(1);
    // The retained parent hash/account remain the immutable evidence.
    const retained = await admin.query<{ parent_human_session_hash: string; parent_human_account_id: string }>(
      `SELECT parent_human_session_hash, parent_human_account_id
         FROM openarc_durable.commerce_sessions WHERE session_id = $1::uuid`,
      [issued.receipt.resourceId],
    );
    expect(retained.rows[0]?.parent_human_session_hash).toBe(owner.hash);
    expect(retained.rows[0]?.parent_human_account_id).toBe(owner.account);
  });

  it('retains history and lets an expired delegation be revoked', async () => {
    const owner = await seedOwner(320);
    const machine = await seedMachine(owner, 320);
    const issued = await store.issueCommerceSession(
      owner.hash,
      owner.org,
      issueInput(machine, 320),
      { idempotencyKey: key(320), mutationId: mutationId(320) },
    );
    await admin.query(
      `UPDATE openarc_durable.commerce_sessions
          SET expires_at = issued_at + interval '1 millisecond'
        WHERE session_id = $1::uuid`,
      [issued.receipt.resourceId],
    );
    await store.revokeCommerceSession(owner.hash, owner.org, issued.receipt.resourceId, {
      idempotencyKey: key(321),
      mutationId: mutationId(321),
    });
    const row = await admin.query<{ revoked_at: Date | null; expired: boolean }>(
      `SELECT revoked_at, clock_timestamp() >= expires_at AS expired
         FROM openarc_durable.commerce_sessions WHERE session_id = $1::uuid`,
      [issued.receipt.resourceId],
    );
    expect(row.rows[0]?.revoked_at).not.toBeNull();
    expect(row.rows[0]?.expired).toBe(true);
  });
});

describe('status, list and mutation status projections', () => {
  it('returns not_found for a foreign session and a bounded keyset page', async () => {
    const owner = await seedOwner(410);
    const machine = await seedMachine(owner, 410);
    const other = await seedOwner(411);
    const ids: string[] = [];
    for (let index = 0; index < 3; index += 1) {
      const issued = await store.issueCommerceSession(
        owner.hash,
        owner.org,
        issueInput(machine, 410, { handoffHash: sha256(`handoff:410:${index}`) }),
        { idempotencyKey: key(4100 + index), mutationId: mutationId(4100 + index) },
      );
      ids.push(issued.receipt.resourceId);
    }
    const sorted = [...ids].sort();
    const status = await store.getCommerceSessionStatus(owner.hash, owner.org, ids[0] as string);
    expect(status.item?.metadata.sessionId).toBe(ids[0]);
    // A missing same-org session id is a safe null, never another org's row.
    const missing = await store.getCommerceSessionStatus(owner.hash, owner.org, mutationId(999));
    expect(missing).toEqual({ organizationId: owner.org, item: null });
    // A principal outside the organization is denied entirely.
    await expectCode(
      store.getCommerceSessionStatus(other.hash, owner.org, ids[0] as string),
      'COMMERCE_SESSION_STORE_FORBIDDEN',
    );
    const first = await store.listCommerceSessions(owner.hash, owner.org, { limit: 2 });
    expect(first.items.map((item) => item.metadata.sessionId)).toEqual(sorted.slice(0, 2));
    expect(first.nextCursor).toBe(sorted[1]);
    const second = await store.listCommerceSessions(owner.hash, owner.org, {
      afterSessionId: first.nextCursor as string,
      limit: 2,
    });
    expect(second.items.map((item) => item.metadata.sessionId)).toEqual(sorted.slice(2));
    expect(second.nextCursor).toBeNull();
  });

  it('resolves mutation status only for the matching verified principal', async () => {
    const owner = await seedOwner(420);
    const machine = await seedMachine(owner, 420);
    const other = await seedMember(421, owner.org, 'operator');
    await store.issueCommerceSession(owner.hash, owner.org, issueInput(machine, 420), {
      idempotencyKey: key(420),
      mutationId: mutationId(420),
    });
    const own = await store.getHumanCommerceSessionMutationStatus(owner.hash, owner.org, mutationId(420));
    expect(own.status).toBe('committed');
    const foreign = await store.getHumanCommerceSessionMutationStatus(other.hash, owner.org, mutationId(420));
    expect(foreign).toEqual({ status: 'not_found' });

    await store.exchangeCommerceSession(
      machine.tokenHash,
      issueInput(machine, 420).handoffHash,
      { tokenHash: sha256('token:420'), hashVersion: 1 },
      { idempotencyKey: key(421), mutationId: mutationId(421) },
    );
    const agentStatus = await store.getAgentCommerceSessionMutationStatus(machine.tokenHash, mutationId(421));
    expect(agentStatus.status).toBe('committed');
    // A different live agent session cannot read this machine context.
    const otherMachine = await seedMachine(owner, 422);
    const agentForeign = await store.getAgentCommerceSessionMutationStatus(otherMachine.tokenHash, mutationId(421));
    expect(agentForeign).toEqual({ status: 'not_found' });
  });

  it('hides a committed issue/revoke receipt from a second LIVE session of the SAME account', async () => {
    const owner = await seedOwner(440);
    const machine = await seedMachine(owner, 440);
    // A SECOND live, non-recovery session for account A: same account, same
    // organization, unexpired. Account identity and liveness are NOT sufficient:
    // the reader binds the exact requesting human-session context digest.
    const second = await seedSession(4401, owner.account);

    await store.issueCommerceSession(owner.hash, owner.org, issueInput(machine, 440), {
      idempotencyKey: key(440),
      mutationId: mutationId(440),
    });
    const issueOriginal = await store.getHumanCommerceSessionMutationStatus(
      owner.hash,
      owner.org,
      mutationId(440),
    );
    expect(issueOriginal.status).toBe('committed');
    const issueSecond = await store.getHumanCommerceSessionMutationStatus(
      second,
      owner.org,
      mutationId(440),
    );
    expect(issueSecond).toEqual({ status: 'not_found' });

    const revoked = await store.revokeCommerceSession(owner.hash, owner.org, mutationId(440), {
      idempotencyKey: key(441),
      mutationId: mutationId(441),
    });
    expect(revoked.receipt.resourceId).toBe(mutationId(440));
    const revokeOriginal = await store.getHumanCommerceSessionMutationStatus(
      owner.hash,
      owner.org,
      mutationId(441),
    );
    expect(revokeOriginal.status).toBe('committed');
    const revokeSecond = await store.getHumanCommerceSessionMutationStatus(
      second,
      owner.org,
      mutationId(441),
    );
    expect(revokeSecond).toEqual({ status: 'not_found' });

    // The original session can still read both of its own receipts.
    expect(
      (await store.getHumanCommerceSessionMutationStatus(owner.hash, owner.org, mutationId(440))).status,
    ).toBe('committed');
    expect(
      (await store.getHumanCommerceSessionMutationStatus(owner.hash, owner.org, mutationId(441))).status,
    ).toBe('committed');
  });

  it('never exposes an exchange receipt through the human mutation-status reader', async () => {
    const owner = await seedOwner(450);
    const machine = await seedMachine(owner, 450);
    await store.issueCommerceSession(owner.hash, owner.org, issueInput(machine, 450), {
      idempotencyKey: key(450),
      mutationId: mutationId(450),
    });
    await store.exchangeCommerceSession(
      machine.tokenHash,
      issueInput(machine, 450).handoffHash,
      { tokenHash: sha256('token:450'), hashVersion: 1 },
      { idempotencyKey: key(451), mutationId: mutationId(451) },
    );
    // Exchange is a MACHINE context. The SAME requesting human session that
    // drove the issue must NOT be able to recover the exchange receipt through
    // the human reader, even though the recorded actor account matches.
    const humanView = await store.getHumanCommerceSessionMutationStatus(
      owner.hash,
      owner.org,
      mutationId(451),
    );
    expect(humanView).toEqual({ status: 'not_found' });
    // The exact agent machine session legitimately recovers it.
    const agentView = await store.getAgentCommerceSessionMutationStatus(machine.tokenHash, mutationId(451));
    expect(agentView.status).toBe('committed');
  });

  it('rejects malformed inputs before any SQL authority call', async () => {
    const owner = await seedOwner(430);
    const machine = await seedMachine(owner, 430);
    await expectCode(
      store.issueCommerceSession(owner.hash, owner.org, issueInput(machine, 430, { durationSeconds: 0 }), {
        idempotencyKey: key(430),
        mutationId: mutationId(430),
      }),
      'COMMERCE_SESSION_STORE_INPUT_INVALID',
    );
    await expectCode(
      store.issueCommerceSession(owner.hash, owner.org, issueInput(machine, 430, { durationSeconds: 901 }), {
        idempotencyKey: key(431),
        mutationId: mutationId(431),
      }),
      'COMMERCE_SESSION_STORE_INPUT_INVALID',
    );
    await expectCode(
      store.issueCommerceSession(owner.hash, owner.org, issueInput(machine, 430), {
        idempotencyKey: 'short',
        mutationId: mutationId(430),
      }),
      'COMMERCE_SESSION_STORE_INPUT_INVALID',
    );
    await expectCode(
      store.listCommerceSessions(owner.hash, owner.org, { limit: 51 }),
      'COMMERCE_SESSION_STORE_INPUT_INVALID',
    );
  });
});

describe('durability, rollback and worker tuples', () => {
  it('rolls back every row when the outbox insert fails', async () => {
    const owner = await seedOwner(510);
    const machine = await seedMachine(owner, 510);
    await admin.query(
      `CREATE FUNCTION openarc_tenant.test_inject_commerce_outbox_failure() RETURNS trigger
         LANGUAGE plpgsql SET search_path = pg_catalog AS $$
         BEGIN
           IF NEW.event_type LIKE 'control.commerce_session%' THEN
             RAISE EXCEPTION 'injected_outbox_failure' USING ERRCODE = '42501';
           END IF;
           RETURN NEW;
         END;
         $$`,
    );
    await admin.query(
      `CREATE TRIGGER test_inject_commerce_outbox_failure
         BEFORE INSERT ON openarc_durable.outbox_events
         FOR EACH ROW EXECUTE FUNCTION openarc_tenant.test_inject_commerce_outbox_failure()`,
    );
    try {
      await expectCode(
        store.issueCommerceSession(owner.hash, owner.org, issueInput(machine, 510), {
          idempotencyKey: key(510),
          mutationId: mutationId(510),
        }),
        'COMMERCE_SESSION_STORE_FORBIDDEN',
      );
      expect(await counts(owner.org)).toMatchObject({ sessions: 0, handoffs: 0, idem: 0, audit: 0, outbox: 0 });
    } finally {
      await admin.query('DROP TRIGGER test_inject_commerce_outbox_failure ON openarc_durable.outbox_events');
      await admin.query('DROP FUNCTION openarc_tenant.test_inject_commerce_outbox_failure()');
    }
  });

  it('claims the issued/exchanged/revoked outbox tuples through the worker store', async () => {
    const owner = await seedOwner(520);
    const machine = await seedMachine(owner, 520);
    await store.issueCommerceSession(owner.hash, owner.org, issueInput(machine, 520), {
      idempotencyKey: key(520),
      mutationId: mutationId(520),
    });
    await store.exchangeCommerceSession(
      machine.tokenHash,
      issueInput(machine, 520).handoffHash,
      { tokenHash: sha256('token:520'), hashVersion: 1 },
      { idempotencyKey: key(521), mutationId: mutationId(521) },
    );
    await store.revokeCommerceSession(owner.hash, owner.org, mutationId(520), {
      idempotencyKey: key(522),
      mutationId: mutationId(522),
    });
    const outbox = new OutboxStore(worker);
    const claimed = await outbox.claim({ limit: 10 });
    const commerce = claimed.filter((event) => event.resourceType === 'commerce_session');
    expect(commerce.map((event) => event.eventType).sort()).toEqual([
      'control.commerce_session.exchanged',
      'control.commerce_session.issued',
      'control.commerce_session.revoked',
    ]);
    expect(commerce.every((event) => event.resourceId === mutationId(520))).toBe(true);
  }, 20000);

  it('rolls back an issue whose caller proof expires after a blocked organization lock', async () => {
    const owner = await seedOwner(530);
    const machine = await seedMachine(owner, 530);
    await shortenSession(owner.hash, 2);
    const blocker = await admin.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query(
        'SELECT 1 FROM openarc_tenant.organizations WHERE organization_id = $1 FOR UPDATE',
        [owner.org],
      );
      const attempt = store.issueCommerceSession(
        owner.hash,
        owner.org,
        issueInput(machine, 530),
        { idempotencyKey: key(530), mutationId: mutationId(530) },
      );
      await waitForLockWait();
      await waitUntilSessionExpired(owner.hash);
      await blocker.query('ROLLBACK');
      await expectCode(attempt, 'COMMERCE_SESSION_STORE_SESSION_INVALID');
      expect(await counts(owner.org)).toMatchObject({ sessions: 0, handoffs: 0, idem: 0, audit: 0, outbox: 0 });
    } finally {
      await blocker.query('ROLLBACK').catch(() => {});
      blocker.release();
    }
  }, 20000);
});

describe('schema8 to schema9 upgrade preserves records and replay', () => {
  it('keeps tenant/policy durable receipts and starts with zero commerce rows', async () => {
    await resetSchema(admin);
    const all = loadMigrations();
    await migrate(migrator, all.slice(0, 8));
    const owner = await seedOwner(610);
    const agent = await seedAgent(610, owner.org);
    const policies = new ControlPolicyStore(tenant);
    const created = await policies.createPolicy(
      owner.hash,
      owner.org,
      {
        organizationId: owner.org,
        subjectAgentId: agent,
        networkId: 'eip155:5042002',
        asset: 'USDC',
        representation: 'erc20',
        decimals: 6,
        perActionLimit: '1000000',
        rollingLimit: null,
        rollingWindowSeconds: null,
        feeLimit: '0',
        allowedProviderIds: [],
        allowedListingIds: [],
        approval: { mode: 'none', threshold: null, separateApprover: false },
        expiresAt: null,
      },
      { idempotencyKey: key(610), mutationId: mutationId(610) },
    );
    await migrate(migrator);
    const applied = await admin.query<{ id: string }>(
      'SELECT id FROM openarc_meta.schema_migrations ORDER BY id',
    );
    expect(applied.rows.map((row) => row.id)).toContain('0009_control_sessions');
    const replay = await policies.createPolicy(
      owner.hash,
      owner.org,
      {
        organizationId: owner.org,
        subjectAgentId: agent,
        networkId: 'eip155:5042002',
        asset: 'USDC',
        representation: 'erc20',
        decimals: 6,
        perActionLimit: '1000000',
        rollingLimit: null,
        rollingWindowSeconds: null,
        feeLimit: '0',
        allowedProviderIds: [],
        allowedListingIds: [],
        approval: { mode: 'none', threshold: null, separateApprover: false },
        expiresAt: null,
      },
      { idempotencyKey: key(610), mutationId: mutationId(610) },
    );
    expect(replay.replayed).toBe(true);
    expect(replay.receipt).toEqual(created.receipt);
    const commerce = await admin.query<{ n: number }>(
      `SELECT ((SELECT count(*)::int FROM openarc_durable.commerce_sessions)
             + (SELECT count(*)::int FROM openarc_durable.commerce_session_handoffs))::int AS n`,
    );
    expect(commerce.rows[0]?.n).toBe(0);
    // A fresh commerce flow works on the upgraded schema.
    const machine = await seedMachine(owner, 611);
    const issued = await store.issueCommerceSession(
      owner.hash,
      owner.org,
      issueInput(machine, 611),
      { idempotencyKey: key(611), mutationId: mutationId(611) },
    );
    expect(issued.receipt.resourceId).toMatch(/^[0-9a-f-]{36}$/);
  }, 20000);
});

describe('DB-time status derivation precedence', () => {
  it('preserves exact microsecond precision across issue, exchange and status', async () => {
    const owner = await seedOwner(652);
    const machine = await seedMachine(owner, 652);
    const issued = await store.issueCommerceSession(
      owner.hash,
      owner.org,
      issueInput(machine, 652),
      { idempotencyKey: key(652), mutationId: mutationId(652) },
    );
    const stored = await admin.query<{ issued_at: string; initial_expires_at: string }>(
      `SELECT to_char(issued_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS issued_at,
              to_char(initial_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS initial_expires_at
         FROM openarc_durable.commerce_sessions WHERE session_id = $1::uuid`,
      [issued.receipt.resourceId],
    );
    // The public store must return the SAME microsecond instant, not a
    // millisecond-truncated Date rendering.
    expect(issued.metadata.issuedAt).toBe(stored.rows[0]?.issued_at);
    expect(issued.metadata.expiresAt).toMatch(/\.\d{6}Z$/);
    const exchanged = await store.exchangeCommerceSession(
      machine.tokenHash,
      issueInput(machine, 652).handoffHash,
      { tokenHash: sha256('token:652'), hashVersion: 1 },
      { idempotencyKey: key(653), mutationId: mutationId(653) },
    );
    expect(exchanged.metadata.exchangedAt).toMatch(/\.\d{6}Z$/);
    const status = await store.getCommerceSessionStatus(owner.hash, owner.org, issued.receipt.resourceId);
    expect(status.item?.metadata.exchangedAt).toBe(exchanged.metadata.exchangedAt);
  });

  it('derives expired once the effective commerce expiry passes', async () => {
    const owner = await seedOwner(640);
    const machine = await seedMachine(owner, 640);
    const issued = await store.issueCommerceSession(
      owner.hash,
      owner.org,
      issueInput(machine, 640),
      { idempotencyKey: key(640), mutationId: mutationId(640) },
    );
    expect(await statusOf(owner.hash, owner.org, issued.receipt.resourceId)).toBe('handoff_pending');
    await expireCommerceSession(issued.receipt.resourceId);
    expect(await statusOf(owner.hash, owner.org, issued.receipt.resourceId)).toBe('expired');
  });

  it('derives invalidated after the sponsoring parent session is deleted (logout)', async () => {
    const owner = await seedOwner(641);
    const reader = await seedMember(642, owner.org, 'operator');
    const machine = await seedMachine(owner, 641);
    const issued = await store.issueCommerceSession(
      owner.hash,
      owner.org,
      issueInput(machine, 641),
      { idempotencyKey: key(641), mutationId: mutationId(641) },
    );
    await admin.query('DELETE FROM openarc_auth.sessions WHERE token_hash = $1', [owner.hash]);
    expect(await statusOf(reader.hash, owner.org, issued.receipt.resourceId)).toBe('invalidated');
  });

  it('derives invalidated after the approving membership is suspended', async () => {
    const owner = await seedOwner(643);
    const reader = await seedMember(644, owner.org, 'operator');
    const machine = await seedMachine(owner, 643);
    const issued = await store.issueCommerceSession(
      owner.hash,
      owner.org,
      issueInput(machine, 643),
      { idempotencyKey: key(643), mutationId: mutationId(643) },
    );
    await admin.query(
      `UPDATE openarc_tenant.memberships SET status = 'suspended'
        WHERE organization_id = $1 AND account_id = $2`,
      [owner.org, owner.account],
    );
    expect(await statusOf(reader.hash, owner.org, issued.receipt.resourceId)).toBe('invalidated');
  });

  it('derives invalidated after the current policy is paused or revoked', async () => {
    for (const policyStatus of ['paused', 'revoked']) {
      const seed = policyStatus === 'paused' ? 645 : 646;
      const owner = await seedOwner(seed);
      const machine = await seedMachine(owner, seed);
      const issued = await store.issueCommerceSession(
        owner.hash,
        owner.org,
        issueInput(machine, seed),
        { idempotencyKey: key(seed), mutationId: mutationId(seed) },
      );
      await admin.query(
        `UPDATE openarc_tenant.budget_policy_roots
            SET status = $3,
                updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')
          WHERE organization_id = $1 AND policy_id = $2`,
        [owner.org, machine.policy, policyStatus],
      );
      expect(await statusOf(owner.hash, owner.org, issued.receipt.resourceId)).toBe('invalidated');
    }
  });

  it('derives invalidated after the bound machine session is revoked', async () => {
    const owner = await seedOwner(647);
    const machine = await seedMachine(owner, 647);
    const issued = await store.issueCommerceSession(
      owner.hash,
      owner.org,
      issueInput(machine, 647),
      { idempotencyKey: key(647), mutationId: mutationId(647) },
    );
    await store.exchangeCommerceSession(
      machine.tokenHash,
      issueInput(machine, 647).handoffHash,
      { tokenHash: sha256('token:647'), hashVersion: 1 },
      { idempotencyKey: key(648), mutationId: mutationId(648) },
    );
    expect(await statusOf(owner.hash, owner.org, issued.receipt.resourceId)).toBe('active');
    await admin.query(
      `UPDATE openarc_durable.agent_sessions
          SET revoked_at = clock_timestamp(), revocation_version = 2
        WHERE session_id = $1::uuid`,
      [sessionUuid(647)],
    );
    expect(await statusOf(owner.hash, owner.org, issued.receipt.resourceId)).toBe('invalidated');
  });

  it('keeps revoked terminal when the expired delegation is also revoked', async () => {
    const owner = await seedOwner(649);
    const machine = await seedMachine(owner, 649);
    const issued = await store.issueCommerceSession(
      owner.hash,
      owner.org,
      issueInput(machine, 649),
      { idempotencyKey: key(649), mutationId: mutationId(649) },
    );
    await expireCommerceSession(issued.receipt.resourceId);
    await store.revokeCommerceSession(owner.hash, owner.org, issued.receipt.resourceId, {
      idempotencyKey: key(650),
      mutationId: mutationId(650),
    });
    expect(await statusOf(owner.hash, owner.org, issued.receipt.resourceId)).toBe('revoked');
  });

  it('derives expired for a lapsed unexchanged handoff after its short duration', async () => {
    const owner = await seedOwner(651);
    const machine = await seedMachine(owner, 651);
    const issued = await store.issueCommerceSession(
      owner.hash,
      owner.org,
      issueInput(machine, 651, { durationSeconds: 1 }),
      { idempotencyKey: key(651), mutationId: mutationId(651) },
    );
    await new Promise((resolve) => setTimeout(resolve, 1200));
    expect(await statusOf(owner.hash, owner.org, issued.receipt.resourceId)).toBe('expired');
  }, 20000);
});

describe('committed exchange replay requires current requesting authority', () => {
  async function issueAndExchange(seed: number) {
    const owner = await seedOwner(seed);
    const machine = await seedMachine(owner, seed);
    const handoff = sha256(`handoff:${seed}`);
    const issued = await store.issueCommerceSession(owner.hash, owner.org, issueInput(machine, seed), {
      idempotencyKey: key(seed),
      mutationId: mutationId(seed),
    });
    const exchanged = await store.exchangeCommerceSession(
      machine.tokenHash,
      handoff,
      { tokenHash: sha256(`token:${seed}`), hashVersion: 1 },
      { idempotencyKey: key(seed + 1), mutationId: mutationId(seed + 1) },
    );
    return { owner, machine, issued, exchanged, handoff };
  }

  it('denies a committed replay once the requesting credential is revoked or expired', async () => {
    const revoked = await issueAndExchange(660);
    await credentials.revokeAgentCredentialDurably({
      sessionHash: revoked.owner.hash,
      organizationId: revoked.owner.org,
      credentialId: revoked.machine.credential,
      metadata: { idempotencyKey: key(6601), mutationId: mutationId(6601) },
    });
    await expectCode(
      store.exchangeCommerceSession(
        revoked.machine.tokenHash,
        revoked.handoff,
        { tokenHash: sha256('regen:660'), hashVersion: 1 },
        { idempotencyKey: key(661), mutationId: mutationId(661) },
      ),
      'COMMERCE_SESSION_STORE_FORBIDDEN',
    );

    const expired = await issueAndExchange(662);
    await shortenCredential(expired.machine.credential, 0.001);
    await new Promise((resolve) => setTimeout(resolve, 40));
    await expectCode(
      store.exchangeCommerceSession(
        expired.machine.tokenHash,
        expired.handoff,
        { tokenHash: sha256('regen:662'), hashVersion: 1 },
        { idempotencyKey: key(663), mutationId: mutationId(663) },
      ),
      'COMMERCE_SESSION_STORE_FORBIDDEN',
    );
  });

  it('denies a committed replay once the requesting machine session is revoked or expired', async () => {
    const session = await issueAndExchange(664);
    await admin.query(
      `UPDATE openarc_durable.agent_sessions
          SET revoked_at = clock_timestamp(), revocation_version = 2
        WHERE session_id = $1::uuid`,
      [sessionUuid(664)],
    );
    await expectCode(
      store.exchangeCommerceSession(
        session.machine.tokenHash,
        session.handoff,
        { tokenHash: sha256('regen:664'), hashVersion: 1 },
        { idempotencyKey: key(665), mutationId: mutationId(665) },
      ),
      'COMMERCE_SESSION_STORE_FORBIDDEN',
    );
  });

  it('still recovers the safe receipt for a valid requester after target revocation', async () => {
    const session = await issueAndExchange(666);
    await store.revokeCommerceSession(session.owner.hash, session.owner.org, session.issued.receipt.resourceId, {
      idempotencyKey: key(669),
      mutationId: mutationId(669),
    });
    const replay = await store.exchangeCommerceSession(
      session.machine.tokenHash,
      session.handoff,
      { tokenHash: sha256('regen:666'), hashVersion: 1 },
      { idempotencyKey: key(667), mutationId: mutationId(667) },
    );
    expect(replay.replayed).toBe(true);
    expect(replay.receipt).toEqual(session.exchanged.receipt);
    expect(JSON.stringify(replay)).not.toContain(sha256('token:666'));
  }, 20000);

  it('recovers the committed receipt after the exchange-shortened effective expiry passes', async () => {
    const session = await issueAndExchange(668);
    await expireCommerceSession(session.issued.receipt.resourceId);
    const replay = await store.exchangeCommerceSession(
      session.machine.tokenHash,
      session.handoff,
      { tokenHash: sha256('regen:668'), hashVersion: 1 },
      { idempotencyKey: key(669), mutationId: mutationId(669) },
    );
    expect(replay.replayed).toBe(true);
    expect(replay.receipt).toEqual(session.exchanged.receipt);
    expect(JSON.stringify(replay)).not.toContain(sha256('token:668'));
  }, 20000);

  it('replays the original issuance with its bounded handoff after the effective expiry shortened', async () => {
    const owner = await seedOwner(680);
    const machine = await seedMachine(owner, 680);
    const handoff = sha256('handoff:680');
    const issued = await store.issueCommerceSession(
      owner.hash,
      owner.org,
      issueInput(machine, 680, { handoffHash: handoff }),
      { idempotencyKey: key(680), mutationId: mutationId(680) },
    );
    await store.exchangeCommerceSession(
      machine.tokenHash,
      handoff,
      { tokenHash: sha256('token:680'), hashVersion: 1 },
      { idempotencyKey: key(681), mutationId: mutationId(681) },
    );
    // A later exchange shortening of the effective expiry must not invalidate
    // the historical issuance metadata or its ORIGINAL handoff window.
    await expireCommerceSession(issued.receipt.resourceId);
    const replay = await store.issueCommerceSession(
      owner.hash,
      owner.org,
      issueInput(machine, 680, { handoffHash: sha256('regen:680') }),
      { idempotencyKey: key(680), mutationId: mutationId(680) },
    );
    expect(replay.replayed).toBe(true);
    expect(replay.receipt).toEqual(issued.receipt);
    expect(replay.handoffExpiresAt).toBe(issued.handoffExpiresAt);
    const handoffMs = Date.parse(replay.handoffExpiresAt);
    expect(handoffMs).toBeGreaterThan(Date.parse(issued.metadata.issuedAt));
    expect(handoffMs).toBeLessThanOrEqual(Date.parse(issued.metadata.issuedAt) + 300_000);
    expect(handoffMs).toBeLessThanOrEqual(Date.parse(issued.metadata.expiresAt));
  }, 20000);

});

describe('exchange races, rollback and lock ordering', () => {
  it('rolls back a fresh exchange whose commerce session expires during a blocked account lock', async () => {
    const owner = await seedOwner(670);
    const machine = await seedMachine(owner, 670);
    const issued = await store.issueCommerceSession(
      owner.hash,
      owner.org,
      issueInput(machine, 670),
      { idempotencyKey: key(670), mutationId: mutationId(670) },
    );
    const blocker = await admin.connect();
    try {
      await blocker.query('BEGIN');
      // Block the LOWEST involved account row to exercise the sorted account
      // lock; the parent and issuer are the same owner here so this is exact.
      await blocker.query('SELECT 1 FROM openarc_auth.accounts WHERE account_id = $1 FOR UPDATE', [
        owner.account,
      ]);
      const attempt = store.exchangeCommerceSession(
        machine.tokenHash,
        issueInput(machine, 670).handoffHash,
        { tokenHash: sha256('token:670'), hashVersion: 1 },
        { idempotencyKey: key(671), mutationId: mutationId(671) },
      );
      await waitForLockWait();
      await shortenSession(owner.hash, 2);
      await waitUntilSessionExpired(owner.hash);
      await blocker.query('ROLLBACK');
      await expectCode(attempt, 'COMMERCE_SESSION_STORE_SESSION_INVALID');
      const row = await admin.query<{ exchanged_at: Date | null }>(
        `SELECT exchanged_at FROM openarc_durable.commerce_sessions WHERE session_id = $1::uuid`,
        [issued.receipt.resourceId],
      );
      expect(row.rows[0]?.exchanged_at).toBeNull();
      expect(await counts(owner.org)).toMatchObject({ sessions: 1, handoffs: 1, idem: 1, audit: 1, outbox: 1 });
    } finally {
      await blocker.query('ROLLBACK').catch(() => {});
      blocker.release();
    }
  }, 20000);

  it('rolls back all exchange business and durability rows when the outbox insert fails', async () => {
    const owner = await seedOwner(671);
    const machine = await seedMachine(owner, 671);
    const issued = await store.issueCommerceSession(
      owner.hash,
      owner.org,
      issueInput(machine, 671),
      { idempotencyKey: key(672), mutationId: mutationId(672) },
    );
    await admin.query(
      `CREATE FUNCTION openarc_tenant.test_inject_exchange_outbox_failure() RETURNS trigger
         LANGUAGE plpgsql SET search_path = pg_catalog AS $$
         BEGIN
           IF NEW.event_type = 'control.commerce_session.exchanged' THEN
             RAISE EXCEPTION 'injected_exchange_outbox_failure' USING ERRCODE = '42501';
           END IF;
           RETURN NEW;
         END;
         $$`,
    );
    await admin.query(
      `CREATE TRIGGER test_inject_exchange_outbox_failure
         BEFORE INSERT ON openarc_durable.outbox_events
         FOR EACH ROW EXECUTE FUNCTION openarc_tenant.test_inject_exchange_outbox_failure()`,
    );
    try {
      await expectCode(
        store.exchangeCommerceSession(
          machine.tokenHash,
          issueInput(machine, 671).handoffHash,
          { tokenHash: sha256('token:671'), hashVersion: 1 },
          { idempotencyKey: key(673), mutationId: mutationId(673) },
        ),
        'COMMERCE_SESSION_STORE_FORBIDDEN',
      );
      const row = await admin.query<{
        exchanged_at: Date | null;
        consumed_at: Date | null;
        token_hash: string | null;
      }>(
        `SELECT s.exchanged_at, h.consumed_at, h.token_hash
           FROM openarc_durable.commerce_sessions s
           JOIN openarc_durable.commerce_session_handoffs h
             ON h.organization_id = s.organization_id AND h.session_id = s.session_id
          WHERE s.session_id = $1::uuid`,
        [issued.receipt.resourceId],
      );
      expect(row.rows[0]?.exchanged_at).toBeNull();
      expect(row.rows[0]?.consumed_at).toBeNull();
      expect(row.rows[0]?.token_hash).toBeNull();
      expect(await counts(owner.org)).toMatchObject({ sessions: 1, handoffs: 1, idem: 1, audit: 1, outbox: 1 });
    } finally {
      await admin.query('DROP TRIGGER test_inject_exchange_outbox_failure ON openarc_durable.outbox_events');
      await admin.query('DROP FUNCTION openarc_tenant.test_inject_exchange_outbox_failure()');
    }
  }, 20000);

  it('serializes two public-path exchanges over opposing parent/issuer accounts without deadlock', async () => {
    const owner = await seedOwner(672);
    const operator = await seedMember(673, owner.org, 'operator');
    const agent = await seedAgent(672, owner.org);
    const policy = await seedPolicy(owner.org, agent, 672);
    const issuedCredential = await credentials.issueAgentCredentialDurably({
      sessionHash: operator.hash,
      organizationId: owner.org,
      profileId: agent,
      lookupId: lookupId(672),
      hash: hashInput(),
      expiresAt: new Date(Date.now() + 30 * 60_000).toISOString(),
      metadata: { idempotencyKey: key(672), mutationId: mutationId(672) },
    });
    const tokenHash = sha256('machine:672');
    await credentials.createAgentSession({
      organizationId: owner.org,
      profileId: agent,
      credentialId: issuedCredential.receipt.credentialId,
      expectedVersion: 1,
      sessionId: sessionUuid(672),
      tokenHash,
      expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
    });
    const handoff = sha256('handoff:672');
    await store.issueCommerceSession(
      owner.hash,
      owner.org,
      { subjectAgentId: agent, policyId: policy, handoffHash: handoff, hashVersion: 1 },
      { idempotencyKey: key(673), mutationId: mutationId(673) },
    );
    // The two involved accounts differ; block the lexicographically lower row
    // so both exchanges queue on the same first canonical lock.
    const [lower] = [owner.account, operator.account].sort();
    const blocker = await admin.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query('SELECT 1 FROM openarc_auth.accounts WHERE account_id = $1 FOR UPDATE', [lower]);
      const attempt = (seed: number) =>
        store.exchangeCommerceSession(
          tokenHash,
          handoff,
          { tokenHash: sha256(`token:672:${seed}`), hashVersion: 1 },
          { idempotencyKey: key(seed), mutationId: mutationId(seed) },
        );
      const first = attempt(674);
      await waitForLockWait();
      const second = attempt(675);
      await new Promise((resolve) => setTimeout(resolve, 50));
      await blocker.query('ROLLBACK');
      const settled = await Promise.allSettled([first, second]);
      const fulfilled = settled.filter((result) => result.status === 'fulfilled');
      expect(fulfilled).toHaveLength(1);
      for (const rejected of settled.filter((result) => result.status === 'rejected')) {
        expect((rejected as PromiseRejectedResult).reason).toBeInstanceOf(CommerceSessionStoreError);
      }
    } finally {
      await blocker.query('ROLLBACK').catch(() => {});
      blocker.release();
    }
    const bound = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM openarc_durable.commerce_sessions
        WHERE organization_id = $1 AND exchanged_at IS NOT NULL`,
      [owner.org],
    );
    expect(bound.rows[0]?.n).toBe(1);
  }, 20000);
});

describe('readiness rejects weakened or removed DB9 controls', () => {
  it('fails readiness when a CHECK is replaced by a trivially true definition', async () => {
    await admin.query('ALTER TABLE openarc_durable.commerce_sessions DROP CONSTRAINT commerce_sessions_exchange_shape');
    await admin.query(
      'ALTER TABLE openarc_durable.commerce_sessions ADD CONSTRAINT commerce_sessions_exchange_shape CHECK (true)',
    );
    await expectCode(store.readiness(), 'COMMERCE_SESSION_STORE_UNAVAILABLE');
  });

  it('fails readiness when a private helper is dropped or loses its fixed search_path', async () => {
    await admin.query('ALTER FUNCTION openarc_durable.derive_commerce_session_status(text, uuid) SET search_path = public');
    await expectCode(store.readiness(), 'COMMERCE_SESSION_STORE_UNAVAILABLE');
    await admin.query(
      'ALTER FUNCTION openarc_durable.derive_commerce_session_status(text, uuid) SET search_path = pg_catalog',
    );
  });

  it('fails readiness when a trigger is recreated with the wrong event mask', async () => {
    await admin.query('DROP TRIGGER commerce_session_handoffs_window ON openarc_durable.commerce_session_handoffs');
    await admin.query(
      `CREATE TRIGGER commerce_session_handoffs_window
         BEFORE UPDATE ON openarc_durable.commerce_session_handoffs
         FOR EACH ROW EXECUTE FUNCTION openarc_durable.enforce_commerce_handoff_window()`,
    );
    try {
      await expectCode(store.readiness(), 'COMMERCE_SESSION_STORE_UNAVAILABLE');
    } finally {
      await admin.query('DROP TRIGGER commerce_session_handoffs_window ON openarc_durable.commerce_session_handoffs');
      await admin.query(
        `CREATE TRIGGER commerce_session_handoffs_window
           BEFORE INSERT ON openarc_durable.commerce_session_handoffs
           FOR EACH ROW EXECUTE FUNCTION openarc_durable.enforce_commerce_handoff_window()`,
      );
    }
  });

  it('fails readiness when the handoff consumption trigger is disabled', async () => {
    await admin.query(
      'ALTER TABLE openarc_durable.commerce_session_handoffs DISABLE TRIGGER commerce_session_handoffs_mutation',
    );
    await expectCode(store.readiness(), 'COMMERCE_SESSION_STORE_UNAVAILABLE');
  });
});

/**
 * schema13 bearer read acceptance. The agent lane presents ONLY a
 * commerce-session token, so this read must resolve it with no organization or
 * session id, must report revocation/expiry truthfully so the service can
 * reject explicitly, must be indistinguishable on every miss, must leak no
 * digest, must mutate nothing and must stay executable by the restricted
 * runtime role alone.
 */
describe('schema13 commerce-session bearer read', () => {
  interface SeededBearer {
    readonly owner: SeededOwner;
    readonly machine: SeededMachine;
    readonly bearer: string;
    readonly handoff: string;
    readonly metadata: Awaited<ReturnType<CommerceSessionStore['exchangeCommerceSession']>>['metadata'];
  }

  async function seedExchanged(seed: number): Promise<SeededBearer> {
    const owner = await seedOwner(seed);
    const machine = await seedMachine(owner, seed);
    const handoff = sha256(`handoff:${seed}`);
    await store.issueCommerceSession(owner.hash, owner.org, issueInput(machine, seed), {
      idempotencyKey: key(seed),
      mutationId: mutationId(seed),
    });
    const bearer = sha256(`session-token:${seed}`);
    const exchanged = await store.exchangeCommerceSession(
      machine.tokenHash,
      handoff,
      { tokenHash: bearer, hashVersion: 1 },
      { idempotencyKey: key(seed + 1), mutationId: mutationId(seed + 1) },
    );
    return { owner, machine, bearer, handoff, metadata: exchanged.metadata };
  }

  /** Exact content digest of both schema9 session tables, every column included. */
  async function sessionTablesDigest(): Promise<{ digest: string; sessions: number; handoffs: number }> {
    const result = await admin.query<{ digest: string; sessions: number; handoffs: number }>(
      `SELECT md5(
                coalesce((SELECT string_agg(s::text, '|' ORDER BY s::text)
                            FROM openarc_durable.commerce_sessions s), '')
                || '#' ||
                coalesce((SELECT string_agg(h::text, '|' ORDER BY h::text)
                            FROM openarc_durable.commerce_session_handoffs h), '')
              ) AS digest,
              (SELECT count(*)::int FROM openarc_durable.commerce_sessions) AS sessions,
              (SELECT count(*)::int FROM openarc_durable.commerce_session_handoffs) AS handoffs`,
    );
    return result.rows[0] as { digest: string; sessions: number; handoffs: number };
  }

  it('resolves an exchanged live session with exact metadata and no digest of any kind', async () => {
    const seeded = await seedExchanged(900);
    const read = await store.getCommerceSessionByHash(seeded.bearer);
    expect(read).not.toBeNull();
    // Byte-exact agreement with the metadata the exchange itself committed.
    expect(read).toEqual(seeded.metadata);
    expect(read?.organizationId).toBe(seeded.owner.org);
    expect(read?.subjectAgentId).toBe(seeded.machine.agent);
    expect(read?.policyId).toBe(seeded.machine.policy);
    expect(read?.exchangedAt).not.toBeNull();
    expect(read?.revokedAt).toBeNull();
    expect(read?.schemaVersion).toBe('openarc.control.commerce-session.v1');
    expect(read?.scopes).toEqual(['commerce.authorize']);
    expect(read?.decimals).toBe(6);

    // No token hash, handoff hash, human session hash, machine session hash,
    // credential id or ANY 64-hex digest is representable in the output.
    const serialized = JSON.stringify(read);
    expect(serialized).not.toContain(seeded.bearer);
    expect(serialized).not.toContain(seeded.handoff);
    expect(serialized).not.toContain(seeded.owner.hash);
    expect(serialized).not.toContain(seeded.machine.tokenHash);
    expect(serialized).not.toContain(seeded.machine.credential);
    expect(serialized).not.toMatch(/[0-9a-f]{64}/);
  });

  it('resolves a REVOKED session carrying its real revokedAt rather than vanishing', async () => {
    const seeded = await seedExchanged(910);
    const revoked = await store.revokeCommerceSession(
      seeded.owner.hash,
      seeded.owner.org,
      mutationId(910),
      { idempotencyKey: key(912), mutationId: mutationId(912) },
    );
    expect(revoked.metadata.revokedAt).not.toBeNull();

    const read = await store.getCommerceSessionByHash(seeded.bearer);
    // The store REPORTS; the service is the one that rejects. A hidden row
    // would downgrade an explicit rejection into a not-found.
    expect(read).not.toBeNull();
    expect(read?.revokedAt).toBe(revoked.metadata.revokedAt);
    expect(read?.sessionId).toBe(mutationId(910));
    expect(read).toEqual(revoked.metadata);
    expect(JSON.stringify(read)).not.toMatch(/[0-9a-f]{64}/);
  });

  it('resolves an EXPIRED session carrying its real expiresAt', async () => {
    const seeded = await seedExchanged(920);
    await expireCommerceSession(mutationId(920));
    const expired = await admin.query<{ expires_at: string; expired: boolean }>(
      `SELECT expires_at::text AS expires_at, clock_timestamp() >= expires_at AS expired
         FROM openarc_durable.commerce_sessions WHERE session_id = $1::uuid`,
      [mutationId(920)],
    );
    expect(expired.rows[0]?.expired).toBe(true);

    const read = await store.getCommerceSessionByHash(seeded.bearer);
    expect(read).not.toBeNull();
    expect(read?.revokedAt).toBeNull();
    expect(read?.sessionId).toBe(mutationId(920));
    // The projected expiry is the row's real, shortened expiry, not the
    // original issuance window.
    expect(read?.expiresAt).not.toBe(seeded.metadata.expiresAt);
    expect(Date.parse(read?.expiresAt as string)).toBeLessThan(
      Date.parse(seeded.metadata.expiresAt),
    );
    expect(Date.parse(read?.expiresAt as string)).toBeLessThanOrEqual(Date.now());
    // The human status reader agrees the session is expired; the bearer read
    // still resolves it so the service can reject it explicitly.
    expect(await statusOf(seeded.owner.hash, seeded.owner.org, mutationId(920))).toBe('expired');
  });

  it('never resolves an issued-but-unexchanged handoff as a live session', async () => {
    const owner = await seedOwner(930);
    const machine = await seedMachine(owner, 930);
    const handoff = sha256('handoff:930');
    await store.issueCommerceSession(owner.hash, owner.org, issueInput(machine, 930), {
      idempotencyKey: key(930),
      mutationId: mutationId(930),
    });
    expect(await statusOf(owner.hash, owner.org, mutationId(930))).toBe('handoff_pending');
    // The pending handoff row exists but carries no token hash at all.
    const pending = await admin.query<{ token_hash: string | null; consumed_at: string | null }>(
      `SELECT token_hash, consumed_at::text AS consumed_at
         FROM openarc_durable.commerce_session_handoffs WHERE handoff_hash = $1`,
      [handoff],
    );
    expect(pending.rows[0]).toEqual({ token_hash: null, consumed_at: null });

    // Neither the handoff hash nor the token that has not been minted resolves.
    expect(await store.getCommerceSessionByHash(handoff)).toBeNull();
    expect(await store.getCommerceSessionByHash(sha256('session-token:930'))).toBeNull();

    // Only after a real exchange does the SAME bearer resolve.
    await store.exchangeCommerceSession(
      machine.tokenHash,
      handoff,
      { tokenHash: sha256('session-token:930'), hashVersion: 1 },
      { idempotencyKey: key(931), mutationId: mutationId(931) },
    );
    expect((await store.getCommerceSessionByHash(sha256('session-token:930')))?.sessionId).toBe(
      mutationId(930),
    );
    // The handoff hash is still not a bearer.
    expect(await store.getCommerceSessionByHash(handoff)).toBeNull();
  });

  it('makes an unknown hash and another organization indistinguishable', async () => {
    const first = await seedExchanged(940);
    const second = await seedExchanged(950);
    expect(first.owner.org).not.toBe(second.owner.org);

    // Each bearer resolves ONLY its own organization's session.
    expect((await store.getCommerceSessionByHash(first.bearer))?.organizationId).toBe(first.owner.org);
    expect((await store.getCommerceSessionByHash(second.bearer))?.organizationId).toBe(second.owner.org);
    expect((await store.getCommerceSessionByHash(first.bearer))?.sessionId).toBe(mutationId(940));
    expect((await store.getCommerceSessionByHash(second.bearer))?.sessionId).toBe(mutationId(950));

    // Every non-bearer digest is the SAME empty answer, whatever it names: an
    // unrelated hash, the other organization's handoff, its human session, its
    // machine session, or a hash of nothing at all. A miss therefore reveals
    // nothing about whether a session exists elsewhere.
    const misses = [
      sha256('never-issued-anything'),
      'f'.repeat(64),
      '0'.repeat(64),
      second.handoff,
      second.owner.hash,
      second.machine.tokenHash,
      first.handoff,
      first.owner.hash,
      first.machine.tokenHash,
    ];
    for (const miss of misses) {
      expect(await store.getCommerceSessionByHash(miss)).toBeNull();
    }

    // A non-canonical bearer is the fixed input error, never a row.
    await expectCode(
      store.getCommerceSessionByHash(first.bearer.toUpperCase()),
      'COMMERCE_SESSION_STORE_INPUT_INVALID',
    );
    await expectCode(store.getCommerceSessionByHash('nope'), 'COMMERCE_SESSION_STORE_INPUT_INVALID');
  });

  it('performs no mutation: identical row counts and table digest before and after', async () => {
    const seeded = await seedExchanged(960);
    const before = await sessionTablesDigest();
    const beforeCounts = await counts(seeded.owner.org);

    // Every reachable outcome: a hit, a miss and a rejected input.
    expect(await store.getCommerceSessionByHash(seeded.bearer)).not.toBeNull();
    expect(await store.getCommerceSessionByHash(sha256('absent'))).toBeNull();
    expect(await store.getCommerceSessionByHash(seeded.handoff)).toBeNull();
    await expectCode(store.getCommerceSessionByHash('short'), 'COMMERCE_SESSION_STORE_INPUT_INVALID');
    for (let repeat = 0; repeat < 5; repeat += 1) {
      await store.getCommerceSessionByHash(seeded.bearer);
    }

    const after = await sessionTablesDigest();
    expect(after).toEqual(before);
    expect(after.sessions).toBe(before.sessions);
    expect(after.handoffs).toBe(before.handoffs);
    // No durability, audit or outbox evidence is produced by a read either.
    expect(await counts(seeded.owner.org)).toEqual(beforeCounts);

    // PostgreSQL itself forbids the helper from writing: it is STABLE.
    const volatility = await admin.query<{ provolatile: string }>(
      `SELECT p.provolatile FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'openarc_durable' AND p.proname = 'read_commerce_session_by_token'`,
    );
    expect(volatility.rows[0]?.provolatile).toBe('s');
  });

  it('grants execute to the restricted runtime role alone and never to PUBLIC', async () => {
    const acl = await admin.query<{
      owner: string;
      secdef: boolean;
      config: string[];
      args: string;
      app_exec: boolean;
      worker_exec: boolean;
      auth_exec: boolean;
      public_grants: number;
    }>(
      `SELECT r.rolname AS owner,
              p.prosecdef AS secdef,
              coalesce(p.proconfig, ARRAY[]::text[]) AS config,
              pg_get_function_identity_arguments(p.oid) AS args,
              has_function_privilege('openarc_tenant_app', p.oid, 'EXECUTE') AS app_exec,
              has_function_privilege('openarc_worker_app', p.oid, 'EXECUTE') AS worker_exec,
              has_function_privilege('openarc_auth_app', p.oid, 'EXECUTE') AS auth_exec,
              (SELECT count(*)::int
                 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE') AS public_grants
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         JOIN pg_roles r ON r.oid = p.proowner
        WHERE n.nspname = 'openarc_durable' AND p.proname = 'read_commerce_session_by_token'`,
    );
    expect(acl.rows).toHaveLength(1);
    expect(acl.rows[0]).toMatchObject({
      owner: 'openarc_migrator',
      secdef: true,
      args: 'commerce_token_hash text',
      app_exec: true,
      worker_exec: false,
      auth_exec: false,
      public_grants: 0,
    });
    expect(acl.rows[0]?.config).toContain('search_path=pg_catalog');

    // The restricted runtime really can execute it, and the other runtime roles
    // really cannot: PUBLIC holds nothing to inherit.
    const seeded = await seedExchanged(970);
    expect((await store.getCommerceSessionByHash(seeded.bearer))?.sessionId).toBe(mutationId(970));
    expect(
      (
        await rawError(
          worker.query('SELECT * FROM openarc_durable.read_commerce_session_by_token($1)', [
            seeded.bearer,
          ]),
        )
      ).code,
    ).toBe('42501');
    expect(
      (
        await rawError(
          auth.query('SELECT * FROM openarc_durable.read_commerce_session_by_token($1)', [
            seeded.bearer,
          ]),
        )
      ).code,
    ).toBe('42501');
    // And it still cannot be used as a back door to the tables themselves.
    expect(
      (await rawError(tenant.query('SELECT count(*) FROM openarc_durable.commerce_session_handoffs')))
        .code,
    ).toBe('42501');
  });
});
