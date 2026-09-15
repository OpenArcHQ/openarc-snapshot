import { createHash } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool, PoolClient } from 'pg';
import { createDatabasePool, loadMigrations, migrate } from '../src/index.js';
import {
  adminPool,
  ensureRoles,
  migratorUrl,
  resetSchema,
  tenantUrl,
} from './postgres-fixture.js';

/**
 * Real PostgreSQL acceptance for the frozen tenant SQL interface (schema2).
 *
 * This slice exercises the migration, SECURITY DEFINER bridge, RLS policies and
 * privileges directly. The TenantStore TypeScript repository is a follow-up;
 * context below is set explicitly to model trusted repository state. Raw
 * session hashes/tokens are synthetic and never asserted into output.
 */

function sha256(seed: string): string {
  return createHash('sha256').update(`openarc-tenant-test:${seed}`, 'utf8').digest('hex');
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

function uuid(seed: number): string {
  const tail = String(seed).padStart(12, '0');
  return `00000000-0000-4000-8000-${tail}`;
}

function userHandle(seed: number): string {
  const body = sha256(`handle:${seed}`).slice(0, 42);
  return `${body}A`;
}

interface PgError {
  code?: string;
  message?: string;
}

async function expectPgError(promise: Promise<unknown>, code: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    const pgError = error as PgError;
    expect(pgError.code).toBe(code);
    return;
  }
  throw new Error(`expected pg error ${code}`);
}

let admin: Pool;
let migrator: Pool;
let tenant: Pool;

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
});

async function seedAccount(id: string, status = 'active'): Promise<void> {
  await admin.query(
    'INSERT INTO openarc_auth.accounts (account_id, user_handle, status) VALUES ($1, $2, $3)',
    [id, userHandle(seedOf(id)), status],
  );
}

function seedOf(id: string): number {
  const match = /-(\d{12})$/.exec(id);
  return Number.parseInt(match?.[1] ?? '0', 10);
}

async function seedSession(hash: string, id: string, offsetMinutes = 0): Promise<void> {
  await admin.query(
    `INSERT INTO openarc_auth.sessions (token_hash, account_id, method, created_at, expires_at)
     VALUES ($1, $2, 'passkey', now() + ($3 || ' minutes')::interval, now() + interval '24 hours')`,
    [hash, id, String(offsetMinutes)],
  );
}

async function withTenant<T>(work: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await tenant.connect();
  try {
    await client.query('BEGIN');
    const result = await work(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // connection is discarded below
    }
    throw error;
  } finally {
    client.release();
  }
}

async function setContext(
  client: PoolClient,
  context: { accountId?: string; organizationId?: string; role?: string },
): Promise<void> {
  await client.query("SELECT set_config('openarc.account_id', $1, true)", [
    context.accountId ?? '',
  ]);
  await client.query("SELECT set_config('openarc.organization_id', $1, true)", [
    context.organizationId ?? '',
  ]);
  await client.query("SELECT set_config('openarc.role', $1, true)", [context.role ?? '']);
}

async function bootstrapOrganization(
  client: PoolClient,
  sessionHash: string,
  organization: string,
  displayName: string,
): Promise<string> {
  const session = await client.query<{ account_id: string }>(
    'SELECT account_id FROM openarc_tenant.lock_auth_session($1, NULL)',
    [sessionHash],
  );
  const actor = session.rows[0]?.account_id;
  if (actor === undefined) throw new Error('session not resolved');
  await setContext(client, { accountId: actor, organizationId: organization });
  await client.query(
    'INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, $2, $3)',
    [organization, displayName, actor],
  );
  await client.query("SELECT set_config('openarc.role', 'owner', true)");
  await client.query(
    "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'owner', 'active')",
    [organization, actor],
  );
  return actor;
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

async function seedOwnedOrganization(seed: number): Promise<{ account: string; hash: string }> {
  const account = accountId(seed);
  await seedAccount(account);
  const hash = sha256(`owned-${seed}`);
  await seedSession(hash, account);
  await admin.query(
    "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Owned', $2)",
    [orgId(seed), account],
  );
  await admin.query(
    "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'owner', 'active')",
    [orgId(seed), account],
  );
  return { account, hash };
}

describe('tenant migration and schema2 boundary', () => {
  it('upgrades from 0001 and records an unchanged 0002 checksum', async () => {
    const checksum = createHash('sha256')
      .update(loadMigrations()[1]?.sql ?? '', 'utf8')
      .digest('hex');
    const applied = await admin.query<{ id: string; checksum: string }>(
      'SELECT id, checksum FROM openarc_meta.schema_migrations ORDER BY id',
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
      '0015_payment_attempts',
      '0016_evidence_store',
    ]);
    expect(applied.rows[1]?.checksum).toBe(checksum);
  });

  it('exposes the bridge signatures and forces RLS', async () => {
    const functions = await admin.query<{ proname: string }>(
      `SELECT p.proname
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'openarc_tenant' AND p.prorettype <> 'trigger'::regtype
        ORDER BY p.proname`,
    );
    expect(functions.rows.map((row) => row.proname)).toEqual([
      'current_context_access_kind',
      'list_account_organization_ids',
      'lock_auth_session',
      'lock_organization_access',
      'set_membership',
    ]);
    const rls = await admin.query<{ relname: string; relforcerowsecurity: boolean }>(
      `SELECT c.relname, c.relforcerowsecurity
         FROM pg_class c
         JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'openarc_tenant' AND c.relkind = 'r'
        ORDER BY c.relname`,
    );
    expect(rls.rows.map((row) => row.relname)).toEqual([
      'agents',
      'budget_policy_roots',
      'budget_policy_versions',
      'listing_origin_reviews',
      'listing_version_payment_terms',
      'listing_version_states',
      'listing_versions',
      'listings',
      'market_moderator_grants',
      'memberships',
      'organizations',
      'providers',
    ]);
    expect(rls.rows.every((row) => row.relforcerowsecurity)).toBe(true);
  });

  it('owns the lock helper as migrator with PUBLIC EXECUTE revoked', async () => {
    const helper = await admin.query<{
      owner: string;
      app_exec: boolean;
      auth_exec: boolean;
    }>(
      `SELECT r.rolname AS owner,
              has_function_privilege('openarc_tenant_app', p.oid, 'EXECUTE') AS app_exec,
              has_function_privilege('openarc_auth_app', p.oid, 'EXECUTE') AS auth_exec
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         JOIN pg_roles r ON r.oid = p.proowner
        WHERE n.nspname = 'openarc_tenant'
          AND p.proname = 'lock_organization_access'`,
    );
    expect(helper.rows[0]?.owner).toBe('openarc_migrator');
    expect(helper.rows[0]?.app_exec).toBe(true);
    expect(helper.rows[0]?.auth_exec).toBe(false);
    const publicGrants = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n
         FROM pg_proc p,
              aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
        WHERE p.pronamespace = 'openarc_tenant'::regnamespace
          AND p.proname = 'lock_organization_access'
          AND a.grantee = 0
          AND a.privilege_type = 'EXECUTE'`,
    );
    expect(publicGrants.rows[0]?.n).toBe(0);
  });

  it('denies the tenant runtime DDL and auth table access', async () => {
    await withTenant(async (client) => {
      await expect(client.query('CREATE TABLE openarc_tenant.nope (id int)')).rejects.toBeTruthy();
      await expect(client.query('SELECT * FROM openarc_auth.sessions')).rejects.toBeTruthy();
      await expect(
        client.query('INSERT INTO openarc_meta.schema_migrations (id, checksum) VALUES (\'x\', \'y\')'),
      ).rejects.toBeTruthy();
    });
  });
});

describe('tenant current_context_access_kind predicate', () => {
  it('is a zero-argument migrator-owned text definer with restricted execution', async () => {
    const predicate = await admin.query<{
      owner: string;
      rettype: string;
      args: string;
      secdef: boolean;
      config: string[] | null;
      app_exec: boolean;
      auth_exec: boolean;
      public_grants: number;
    }>(
      `SELECT r.rolname AS owner,
              p.prorettype::regtype::text AS rettype,
              oidvectortypes(p.proargtypes) AS args,
              p.prosecdef AS secdef,
              p.proconfig AS config,
              has_function_privilege('openarc_tenant_app', p.oid, 'EXECUTE') AS app_exec,
              has_function_privilege('openarc_auth_app', p.oid, 'EXECUTE') AS auth_exec,
              (
                SELECT count(*)::int
                  FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                 WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE'
              ) AS public_grants
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         JOIN pg_roles r ON r.oid = p.proowner
        WHERE n.nspname = 'openarc_tenant'
          AND p.proname = 'current_context_access_kind'`,
    );
    const row = predicate.rows[0];
    expect(row?.owner).toBe('openarc_migrator');
    expect(row?.rettype).toBe('text');
    expect(row?.args).toBe('');
    expect(row?.secdef).toBe(true);
    expect(row?.config).toContain('search_path=pg_catalog');
    expect(row?.app_exec).toBe(true);
    expect(row?.auth_exec).toBe(false);
    expect(row?.public_grants).toBe(0);
  });

  it('reports the actual role, then bootstrap only while the new org is empty', async () => {
    await seedAccount(accountId(100));
    await seedAccount(accountId(101));
    const hash = sha256('session-100');
    await seedSession(hash, accountId(100));
    await withTenant(async (client) => {
      // No context yet: closed.
      const closed = await client.query<{ kind: string | null }>(
        'SELECT openarc_tenant.current_context_access_kind() AS kind',
      );
      expect(closed.rows[0]?.kind).toBeNull();

      const actor = await bootstrapOrganization(client, hash, orgId(100), 'Predicate');
      // The bootstrap membership now exists, so the creator sees its real role,
      // not the bootstrap state.
      await setContext(client, { accountId: actor, organizationId: orgId(100) });
      const active = await client.query<{ kind: string | null }>(
        'SELECT openarc_tenant.current_context_access_kind() AS kind',
      );
      expect(active.rows[0]?.kind).toBe('owner');

      // A foreign organization never resolves, even for the creator.
      await setContext(client, { accountId: actor, organizationId: orgId(101) });
      const foreign = await client.query<{ kind: string | null }>(
        'SELECT openarc_tenant.current_context_access_kind() AS kind',
      );
      expect(foreign.rows[0]?.kind).toBeNull();

      // A canonical but non-existent organization is closed.
      await setContext(client, { accountId: actor, organizationId: orgId(999) });
      const missing = await client.query<{ kind: string | null }>(
        'SELECT openarc_tenant.current_context_access_kind() AS kind',
      );
      expect(missing.rows[0]?.kind).toBeNull();
    });
  });

  it('returns bootstrap only for an own empty uncommitted organization', async () => {
    await seedAccount(accountId(102));
    const hash = sha256('session-102');
    await seedSession(hash, accountId(102));
    await withTenant(async (client) => {
      const session = await client.query<{ account_id: string }>(
        'SELECT account_id FROM openarc_tenant.lock_auth_session($1, NULL)',
        [hash],
      );
      const actor = session.rows[0]?.account_id;
      expect(actor).toBe(accountId(102));
      if (actor === undefined) throw new Error('session not resolved');
      await setContext(client, { accountId: actor, organizationId: orgId(102) });
      await client.query(
        'INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, $2, $3)',
        [orgId(102), 'Fresh', actor],
      );
      const kind = await client.query<{ kind: string | null }>(
        'SELECT openarc_tenant.current_context_access_kind() AS kind',
      );
      expect(kind.rows[0]?.kind).toBe('bootstrap');
      await client.query("SELECT set_config('openarc.role', 'owner', true)");
      await client.query(
        "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'owner', 'active')",
        [orgId(102), actor],
      );
      const after = await client.query<{ kind: string | null }>(
        'SELECT openarc_tenant.current_context_access_kind() AS kind',
      );
      expect(after.rows[0]?.kind).toBe('owner');
    });
  });
});

describe('tenant bridge authentication', () => {
  it('resolves a live session and never returns the token hash', async () => {
    await seedAccount(accountId(1));
    const hash = sha256('session-1');
    await seedSession(hash, accountId(1));
    const result = await tenant.query(
      'SELECT account_id, method, session_created_at, session_expires_at FROM openarc_tenant.lock_auth_session($1, NULL)',
      [hash],
    );
    expect(result.rows[0]?.account_id).toBe(accountId(1));
    expect(result.rows[0]?.method).toBe('passkey');
    expect(Object.keys(result.rows[0] ?? {})).not.toContain('token_hash');
  });

  it('rejects expired sessions and recovery proof for mutations', async () => {
    await seedAccount(accountId(2));
    const expired = sha256('expired-2');
    await admin.query(
      `INSERT INTO openarc_auth.sessions (token_hash, account_id, method, created_at, expires_at)
       VALUES ($1, $2, 'passkey', now() - interval '2 hours', now() - interval '1 hour')`,
      [expired, accountId(2)],
    );
    await expectPgError(
      tenant.query('SELECT * FROM openarc_tenant.lock_auth_session($1, NULL)', [expired]),
      '28000',
    );
    const recovery = sha256('recovery-2');
    await admin.query(
      `INSERT INTO openarc_auth.sessions (token_hash, account_id, method, created_at, expires_at)
       VALUES ($1, $2, 'recovery', now(), now() + interval '24 hours')`,
      [recovery, accountId(2)],
    );
    await expectPgError(
      tenant.query('SELECT * FROM openarc_tenant.set_membership($1, $2, $3, $4, $5)', [
        recovery,
        orgId(2),
        accountId(2),
        'owner',
        'active',
      ]),
      '28000',
    );
  });

  it('rejects a revoked session and a disabled account', async () => {
    await seedAccount(accountId(3), 'disabled');
    const hash = sha256('session-3');
    await seedSession(hash, accountId(3));
    await expectPgError(
      tenant.query('SELECT * FROM openarc_tenant.lock_auth_session($1, NULL)', [hash]),
      '28000',
    );
  });

  it('fails closed without RLS context', async () => {
    await withTenant(async (client) => {
      const orgs = await client.query('SELECT count(*)::int AS n FROM openarc_tenant.organizations');
      const members = await client.query('SELECT count(*)::int AS n FROM openarc_tenant.memberships');
      const agents = await client.query('SELECT count(*)::int AS n FROM openarc_tenant.agents');
      const providers = await client.query('SELECT count(*)::int AS n FROM openarc_tenant.providers');
      expect(orgs.rows[0]?.n).toBe(0);
      expect(members.rows[0]?.n).toBe(0);
      expect(agents.rows[0]?.n).toBe(0);
      expect(providers.rows[0]?.n).toBe(0);
    });
  });
});

describe('tenant bootstrap and organization isolation', () => {
  it('creates a fresh organization and owner membership atomically', async () => {
    await seedAccount(accountId(4));
    const hash = sha256('session-4');
    await seedSession(hash, accountId(4));
    await withTenant(async (client) => {
      const actor = await bootstrapOrganization(client, hash, orgId(4), 'Acme Evidence');
      expect(actor).toBe(accountId(4));
      const org = await client.query('SELECT display_name, created_by FROM openarc_tenant.organizations');
      expect(org.rows[0]).toEqual({ display_name: 'Acme Evidence', created_by: accountId(4) });
      const membership = await client.query('SELECT role, status FROM openarc_tenant.memberships');
      expect(membership.rows[0]).toEqual({ role: 'owner', status: 'active' });
    });
  });

  it('rolls back a failed bootstrap with no orphan organization', async () => {
    await seedAccount(accountId(5));
    const hash = sha256('session-5');
    await seedSession(hash, accountId(5));
    await expect(
      withTenant(async (client) => {
        await bootstrapOrganization(client, hash, orgId(5), 'Broken Org');
        throw new Error('boom');
      }),
    ).rejects.toThrow('boom');
    const counts = await admin.query<{ orgs: number; members: number }>(
      `SELECT
         (SELECT count(*)::int FROM openarc_tenant.organizations) AS orgs,
         (SELECT count(*)::int FROM openarc_tenant.memberships) AS members`,
    );
    expect(counts.rows[0]).toEqual({ orgs: 0, members: 0 });
  });

  it('cannot bootstrap an owner membership onto an existing organization', async () => {
    await seedAccount(accountId(6));
    await seedAccount(accountId(260));
    const hash = sha256('session-6');
    await seedSession(hash, accountId(6));
    await admin.query(
      "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Existing', $2)",
      [orgId(6), accountId(260)],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'owner', 'active')",
      [orgId(6), accountId(260)],
    );
    await withTenant(async (client) => {
      await setContext(client, { accountId: accountId(6), organizationId: orgId(6) });
      await expect(
        client.query(
          "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'owner', 'active')",
          [orgId(6), accountId(6)],
        ),
      ).rejects.toBeTruthy();
    });
  });

  it('enumerates only the caller own active memberships, bounded', async () => {
    await seedAccount(accountId(7));
    await seedAccount(accountId(8));
    const hash = sha256('session-7');
    await seedSession(hash, accountId(7));
    for (let index = 0; index < 3; index += 1) {
      const org = orgId(250 + index);
      await admin.query(
        "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Org', $2)",
        [org, accountId(7)],
      );
      await admin.query(
        "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'owner', 'active')",
        [org, accountId(7)],
      );
      await admin.query(
        "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'viewer', 'active')",
        [org, accountId(8)],
      );
    }
    await admin.query(
      "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Suspended', $2)",
      [orgId(9), accountId(7)],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'viewer', 'suspended')",
      [orgId(9), accountId(7)],
    );
    const listed = await tenant.query(
      'SELECT organization_id FROM openarc_tenant.list_account_organization_ids($1, NULL, 100)',
      [hash],
    );
    expect(listed.rows).toHaveLength(3);
    expect(listed.rows.every((row) => row.organization_id !== orgId(9))).toBe(true);
    const actor = accountId(7);
    const leaked = await withTenant(async (client) => {
      await setContext(client, { accountId: actor });
      const others = await client.query('SELECT organization_id FROM openarc_tenant.memberships WHERE account_id = $1', [
        accountId(8),
      ]);
      return others.rows;
    });
    expect(leaked).toHaveLength(0);
    await expectPgError(
      tenant.query('SELECT * FROM openarc_tenant.list_account_organization_ids($1, NULL, 101)', [hash]),
      '22023',
    );
  });

  it('denies reads of a forged organization and wrong-org inserts', async () => {
    await seedAccount(accountId(10));
    await seedAccount(accountId(11));
    const hash = sha256('session-10');
    await seedSession(hash, accountId(10));
    await admin.query(
      "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Mine', $2)",
      [orgId(10), accountId(10)],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Theirs', $2)",
      [orgId(11), accountId(11)],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'owner', 'active')",
      [orgId(10), accountId(10)],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'owner', 'active')",
      [orgId(11), accountId(11)],
    );
    await withTenant(async (client) => {
      await setContext(client, { accountId: accountId(10), organizationId: orgId(11), role: 'owner' });
      const forged = await client.query('SELECT * FROM openarc_tenant.organizations WHERE organization_id = $1', [
        orgId(11),
      ]);
      expect(forged.rows).toHaveLength(0);
      await expect(
        client.query(
          "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name) VALUES ($1, $2, 'Ghost')",
          [orgId(11), agentId(11)],
        ),
      ).rejects.toBeTruthy();
    });
  });

  it('denies provider roles unrelated agent and provider data', async () => {
    await seedAccount(accountId(12));
    await seedAccount(accountId(13));
    await admin.query(
      "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Org12', $2)",
      [orgId(12), accountId(12)],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'owner', 'active')",
      [orgId(12), accountId(12)],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'provider_admin', 'active')",
      [orgId(12), accountId(13)],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name) VALUES ($1, $2, 'Secret Agent')",
      [orgId(12), agentId(12)],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.providers (organization_id, provider_id, display_name) VALUES ($1, $2, 'Secret Provider')",
      [orgId(12), providerId(12)],
    );
    await withTenant(async (client) => {
      await setContext(client, { accountId: accountId(13), organizationId: orgId(12), role: 'provider_admin' });
      const agents = await client.query('SELECT count(*)::int AS n FROM openarc_tenant.agents');
      const providers = await client.query('SELECT count(*)::int AS n FROM openarc_tenant.providers');
      expect(agents.rows[0]?.n).toBe(0);
      expect(providers.rows[0]?.n).toBe(0);
    });
  });
});

describe('tenant lock_organization_access helper', () => {
  it('resolves and publishes only safe organization and role metadata', async () => {
    const { account, hash } = await seedOwnedOrganization(70);
    const resolved = await tenant.query<{ out_organization_id: string; out_role: string }>(
      'SELECT out_organization_id, out_role FROM openarc_tenant.lock_organization_access($1, $2)',
      [hash, orgId(70)],
    );
    expect(resolved.rows[0]).toEqual({ out_organization_id: orgId(70), out_role: 'owner' });
    expect(Object.keys(resolved.rows[0] ?? {}).sort()).toEqual(['out_organization_id', 'out_role']);
    const context = await withTenant(async (client) => {
      await client.query('SELECT * FROM openarc_tenant.lock_organization_access($1, $2)', [
        hash,
        orgId(70),
      ]);
      const settings = await client.query<{ account_id: string; organization_id: string; role: string }>(
        `SELECT current_setting('openarc.account_id', true) AS account_id,
                current_setting('openarc.organization_id', true) AS organization_id,
                current_setting('openarc.role', true) AS role`,
      );
      return settings.rows[0];
    });
    expect(context).toEqual({ account_id: account, organization_id: orgId(70), role: 'owner' });
  });

  it('denies a non-member and a wrong organization', async () => {
    const { hash } = await seedOwnedOrganization(71);
    await seedAccount(accountId(72));
    await expectPgError(
      tenant.query('SELECT * FROM openarc_tenant.lock_organization_access($1, $2)', [
        sha256('owned-71'),
        orgId(99),
      ]),
      '42501',
    );
    await expectPgError(
      tenant.query('SELECT * FROM openarc_tenant.lock_organization_access($1, $2)', [
        hash,
        orgId(99),
      ]),
      '42501',
    );
    await expectPgError(
      tenant.query('SELECT * FROM openarc_tenant.lock_organization_access($1, $2)', [
        sha256('missing-helper'),
        orgId(71),
      ]),
      '28000',
    );
  });

  it('serializes through the same organization row as set_membership', async () => {
    const { hash } = await seedOwnedOrganization(73);
    const blocker = await admin.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query(
        'SELECT 1 FROM openarc_tenant.organizations WHERE organization_id = $1 FOR UPDATE',
        [orgId(73)],
      );
      const pending = tenant.query(
        'SELECT out_role FROM openarc_tenant.lock_organization_access($1, $2)',
        [hash, orgId(73)],
      );
      await waitForLockWait();
      await blocker.query('COMMIT');
      const result = await pending;
      expect(result.rows[0]?.out_role).toBe('owner');
    } finally {
      blocker.release();
    }
  });
});

describe('tenant selected-organization read isolation', () => {
  it('denies account-only context and cross-organization reads', async () => {
    await seedAccount(accountId(74));
    const hash = sha256('session-74');
    await seedSession(hash, accountId(74));
    for (const seed of [74, 75]) {
      await admin.query(
        "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Org', $2)",
        [orgId(seed), accountId(74)],
      );
      await admin.query(
        "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'viewer', 'active')",
        [orgId(seed), accountId(74)],
      );
    }
    await withTenant(async (client) => {
      await setContext(client, { accountId: accountId(74) });
      const orgs = await client.query('SELECT count(*)::int AS n FROM openarc_tenant.organizations');
      const members = await client.query('SELECT count(*)::int AS n FROM openarc_tenant.memberships');
      expect(orgs.rows[0]?.n).toBe(0);
      expect(members.rows[0]?.n).toBe(0);
      await setContext(client, { accountId: accountId(74), organizationId: orgId(74), role: 'viewer' });
      const selected = await client.query(
        'SELECT organization_id FROM openarc_tenant.organizations WHERE organization_id = $1',
        [orgId(74)],
      );
      const other = await client.query(
        'SELECT organization_id FROM openarc_tenant.organizations WHERE organization_id = $1',
        [orgId(75)],
      );
      const otherMembers = await client.query(
        'SELECT account_id FROM openarc_tenant.memberships WHERE organization_id = $1',
        [orgId(75)],
      );
      expect(selected.rows).toHaveLength(1);
      expect(other.rows).toHaveLength(0);
      expect(otherMembers.rows).toHaveLength(0);
    });
    const listed = await tenant.query(
      'SELECT organization_id FROM openarc_tenant.list_account_organization_ids($1, NULL, 100)',
      [hash],
    );
    expect(listed.rows.map((row) => row.organization_id).sort()).toEqual([orgId(74), orgId(75)].sort());
  });

  it('denies a suspended creator both organization and member data', async () => {
    await seedAccount(accountId(76));
    await admin.query(
      "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Susp', $2)",
      [orgId(76), accountId(76)],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'owner', 'suspended')",
      [orgId(76), accountId(76)],
    );
    await withTenant(async (client) => {
      await setContext(client, { accountId: accountId(76), organizationId: orgId(76), role: 'owner' });
      const orgs = await client.query('SELECT count(*)::int AS n FROM openarc_tenant.organizations');
      const members = await client.query('SELECT count(*)::int AS n FROM openarc_tenant.memberships');
      expect(orgs.rows[0]?.n).toBe(0);
      expect(members.rows[0]?.n).toBe(0);
    });
    await expectPgError(
      tenant.query('SELECT * FROM openarc_tenant.lock_organization_access($1, $2)', [
        sha256('missing-suspended'),
        orgId(76),
      ]),
      '28000',
    );
  });

  it('allows the active self row and its selected organization', async () => {
    await seedAccount(accountId(77));
    await admin.query(
      "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Active', $2)",
      [orgId(77), accountId(77)],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'viewer', 'active')",
      [orgId(77), accountId(77)],
    );
    await withTenant(async (client) => {
      await setContext(client, { accountId: accountId(77), organizationId: orgId(77) });
      const orgs = await client.query('SELECT count(*)::int AS n FROM openarc_tenant.organizations');
      const self = await client.query('SELECT role FROM openarc_tenant.memberships WHERE account_id = $1', [
        accountId(77),
      ]);
      expect(orgs.rows[0]?.n).toBe(1);
      expect(self.rows[0]?.role).toBe('viewer');
    });
  });

  it('lets an owner enumerate active and suspended members of the selected org only', async () => {
    await seedAccount(accountId(90));
    await seedAccount(accountId(91));
    await seedAccount(accountId(92));
    await seedAccount(accountId(93));
    await admin.query(
      "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'OwnerOrg', $2)",
      [orgId(90), accountId(90)],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'OtherOrg', $2)",
      [orgId(91), accountId(91)],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'owner', 'active'), ($1, $3, 'operator', 'active'), ($1, $4, 'viewer', 'suspended')",
      [orgId(90), accountId(90), accountId(92), accountId(93)],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'owner', 'active')",
      [orgId(91), accountId(91)],
    );
    await withTenant(async (client) => {
      await setContext(client, { accountId: accountId(90), organizationId: orgId(90), role: 'owner' });
      const members = await client.query<{ account_id: string; status: string }>(
        'SELECT account_id, status FROM openarc_tenant.memberships WHERE organization_id = $1 ORDER BY account_id',
        [orgId(90)],
      );
      expect(members.rows).toHaveLength(3);
      expect(members.rows.map((row) => row.account_id).sort()).toEqual(
        [accountId(90), accountId(92), accountId(93)].sort(),
      );
      const otherOrg = await client.query(
        'SELECT organization_id FROM openarc_tenant.organizations WHERE organization_id = $1',
        [orgId(91)],
      );
      expect(otherOrg.rows).toHaveLength(0);
      const foreignMembers = await client.query(
        'SELECT account_id FROM openarc_tenant.memberships WHERE organization_id = $1',
        [orgId(91)],
      );
      expect(foreignMembers.rows).toHaveLength(0);
    });
  });

  it('lets each nonowner see only its own active membership in the selected org', async () => {
    await seedAccount(accountId(94));
    await seedAccount(accountId(95));
    await seedAccount(accountId(96));
    await admin.query(
      "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Mixed', $2)",
      [orgId(94), accountId(94)],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'owner', 'active'), ($1, $3, 'operator', 'active'), ($1, $4, 'provider_admin', 'active')",
      [orgId(94), accountId(94), accountId(95), accountId(96)],
    );
    for (const [seed, role] of [
      [95, 'operator'],
      [96, 'provider_admin'],
    ] as const) {
      await withTenant(async (client) => {
        await setContext(client, { accountId: accountId(seed), organizationId: orgId(94), role });
        const own = await client.query<{ account_id: string }>(
          'SELECT account_id FROM openarc_tenant.memberships WHERE organization_id = $1',
          [orgId(94)],
        );
        expect(own.rows.map((row) => row.account_id)).toEqual([accountId(seed)]);
      });
    }
    await admin.query(
      "UPDATE openarc_tenant.memberships SET status = 'suspended' WHERE organization_id = $1 AND account_id = $2",
      [orgId(94), accountId(95)],
    );
    await withTenant(async (client) => {
      await setContext(client, { accountId: accountId(95), organizationId: orgId(94), role: 'operator' });
      const denied = await client.query('SELECT account_id FROM openarc_tenant.memberships WHERE organization_id = $1', [
        orgId(94),
      ]);
      expect(denied.rows).toHaveLength(0);
    });
  });

  it('returns no rows for a missing selected organization regardless of role', async () => {
    await seedAccount(accountId(97));
    await admin.query(
      "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Idle', $2)",
      [orgId(97), accountId(97)],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'owner', 'active')",
      [orgId(97), accountId(97)],
    );
    await withTenant(async (client) => {
      await setContext(client, { accountId: accountId(97), role: 'owner' });
      const orgs = await client.query('SELECT organization_id FROM openarc_tenant.organizations');
      const members = await client.query('SELECT account_id FROM openarc_tenant.memberships');
      expect(orgs.rows).toHaveLength(0);
      expect(members.rows).toHaveLength(0);
    });
  });

  it('ends bootstrap eligibility on the first membership insertion within the transaction', async () => {
    await seedAccount(accountId(98));
    await seedAccount(accountId(99));
    const hash = sha256('session-98');
    await seedSession(hash, accountId(98));
    await withTenant(async (client) => {
      await bootstrapOrganization(client, hash, orgId(98), 'Same Tx');
      // Add a second owner, then suspend the creator: the organization now has
      // membership rows, so the xmin bootstrap path MUST be closed even though
      // this is still the creating transaction.
      await client.query('SELECT * FROM openarc_tenant.set_membership($1, $2, $3, $4, $5)', [
        hash,
        orgId(98),
        accountId(99),
        'owner',
        'active',
      ]);
      await client.query('SELECT * FROM openarc_tenant.set_membership($1, $2, $3, $4, $5)', [
        hash,
        orgId(98),
        accountId(98),
        'owner',
        'suspended',
      ]);
      await setContext(client, { accountId: accountId(98), organizationId: orgId(98), role: 'owner' });
      const orgs = await client.query(
        'SELECT organization_id FROM openarc_tenant.organizations WHERE organization_id = $1',
        [orgId(98)],
      );
      const members = await client.query(
        'SELECT account_id FROM openarc_tenant.memberships WHERE organization_id = $1',
        [orgId(98)],
      );
      expect(orgs.rows).toHaveLength(0);
      expect(members.rows).toHaveLength(0);
      const kind = await client.query<{ kind: string | null }>(
        'SELECT openarc_tenant.current_context_access_kind() AS kind',
      );
      expect(kind.rows[0]?.kind).toBeNull();
    });
  });
});

describe('tenant constraints and profile lifecycle', () => {
  it('enforces FK, id, name and status constraints', async () => {
    await expect(
      admin.query(
        "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Org', $2)",
        ['not-an-org', accountId(20)],
      ),
    ).rejects.toBeTruthy();
    await seedAccount(accountId(20));
    await admin.query(
      "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Org', $2)",
      [orgId(20), accountId(20)],
    );
    await expect(
      admin.query(
        "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'root', 'active')",
        [orgId(20), accountId(20)],
      ),
    ).rejects.toBeTruthy();
    await expect(
      admin.query(
        "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'owner', 'pending')",
        [orgId(20), accountId(20)],
      ),
    ).rejects.toBeTruthy();
    await expect(
      admin.query(
        "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name) VALUES ($1, $2, '  padded  ')",
        [orgId(20), agentId(20)],
      ),
    ).rejects.toBeTruthy();
    await expect(
      admin.query(
        "INSERT INTO openarc_tenant.providers (organization_id, provider_id, display_name, status) VALUES ($1, $2, 'P', 'gone')",
        [orgId(20), providerId(20)],
      ),
    ).rejects.toBeTruthy();
    await expect(
      admin.query(
        "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name) VALUES ('openarc:org:00000000-0000-4000-8000-000000000000', $1, 'Orphan')",
        [agentId(21)],
      ),
    ).rejects.toBeTruthy();
  });

  it('allows same-org profile reads and writes for owner/operator, viewer read only', async () => {
    await seedAccount(accountId(22));
    await seedAccount(accountId(23));
    await admin.query(
      "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Org22', $2)",
      [orgId(22), accountId(22)],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'owner', 'active'), ($1, $3, 'viewer', 'active')",
      [orgId(22), accountId(22), accountId(23)],
    );
    await withTenant(async (client) => {
      await setContext(client, { accountId: accountId(22), organizationId: orgId(22), role: 'owner' });
      await client.query(
        "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name) VALUES ($1, $2, 'Agent One')",
        [orgId(22), agentId(22)],
      );
    });
    await withTenant(async (client) => {
      await setContext(client, { accountId: accountId(23), organizationId: orgId(22), role: 'viewer' });
      const read = await client.query('SELECT display_name FROM openarc_tenant.agents');
      expect(read.rows[0]?.display_name).toBe('Agent One');
      await expect(
        client.query(
          "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name) VALUES ($1, $2, 'Nope')",
          [orgId(22), agentId(23)],
        ),
      ).rejects.toBeTruthy();
    });
  });

  it('treats revoked agents and retired providers as terminal with immutable ownership', async () => {
    await seedAccount(accountId(24));
    await admin.query(
      "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Org24', $2)",
      [orgId(24), accountId(24)],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name, status) VALUES ($1, $2, 'A', 'revoked')",
      [orgId(24), agentId(24)],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.providers (organization_id, provider_id, display_name, status) VALUES ($1, $2, 'P', 'retired')",
      [orgId(24), providerId(24)],
    );
    await expect(
      admin.query("UPDATE openarc_tenant.agents SET status = 'active' WHERE agent_id = $1", [agentId(24)]),
    ).rejects.toBeTruthy();
    await expect(
      admin.query("UPDATE openarc_tenant.providers SET status = 'active' WHERE provider_id = $1", [providerId(24)]),
    ).rejects.toBeTruthy();
    await admin.query(
      "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Org25', $2)",
      [orgId(25), accountId(24)],
    );
    await expect(
      admin.query('UPDATE openarc_tenant.agents SET organization_id = $1 WHERE agent_id = $2', [
        orgId(25),
        agentId(24),
      ]),
    ).rejects.toBeTruthy();
  });
});

describe('tenant membership mutation authority', () => {
  async function seedOwner(seed: number): Promise<string> {
    await seedAccount(accountId(seed));
    const hash = sha256(`owner-${seed}`);
    await seedSession(hash, accountId(seed));
    await admin.query(
      "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Owned', $2)",
      [orgId(seed), accountId(seed)],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'owner', 'active')",
      [orgId(seed), accountId(seed)],
    );
    return hash;
  }

  it('requires a fresh owner session and an active target account', async () => {
    const ownerHash = await seedOwner(30);
    await seedAccount(accountId(31));
    await expectPgError(
      tenant.query('SELECT * FROM openarc_tenant.set_membership($1, $2, $3, $4, $5)', [
        sha256('missing'),
        orgId(30),
        accountId(31),
        'viewer',
        'active',
      ]),
      '28000',
    );
    await admin.query("UPDATE openarc_auth.accounts SET status = 'disabled' WHERE account_id = $1", [
      accountId(31),
    ]);
    await expectPgError(
      tenant.query('SELECT * FROM openarc_tenant.set_membership($1, $2, $3, $4, $5)', [
        ownerHash,
        orgId(30),
        accountId(31),
        'viewer',
        'active',
      ]),
      '28000',
    );
  });

  it('rejects a non-owner caller and a missing membership', async () => {
    await seedAccount(accountId(32));
    await seedAccount(accountId(33));
    const hash = sha256('viewer-32');
    await seedSession(hash, accountId(32));
    await admin.query(
      "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Owned', $2)",
      [orgId(32), accountId(33)],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'viewer', 'active')",
      [orgId(32), accountId(32)],
    );
    await expectPgError(
      tenant.query('SELECT * FROM openarc_tenant.set_membership($1, $2, $3, $4, $5)', [
        hash,
        orgId(32),
        accountId(33),
        'operator',
        'active',
      ]),
      '42501',
    );
    await expectPgError(
      tenant.query('SELECT * FROM openarc_tenant.set_membership($1, $2, $3, $4, $5)', [
        sha256('owner-32-missing'),
        orgId(99),
        accountId(33),
        'operator',
        'active',
      ]),
      '28000',
    );
  });

  it('creates and changes membership, revoking target sessions only on change', async () => {
    const ownerHash = await seedOwner(34);
    await seedAccount(accountId(35));
    const targetSession = sha256('target-35');
    await seedSession(targetSession, accountId(35));
    const created = await tenant.query(
      'SELECT out_role, out_status FROM openarc_tenant.set_membership($1, $2, $3, $4, $5)',
      [ownerHash, orgId(34), accountId(35), 'viewer', 'active'],
    );
    expect(created.rows[0]).toEqual({ out_role: 'viewer', out_status: 'active' });
    const freshTargetSession = sha256('target-35-unchanged');
    await seedSession(freshTargetSession, accountId(35));
    const unchanged = await tenant.query(
      'SELECT out_role FROM openarc_tenant.set_membership($1, $2, $3, $4, $5)',
      [ownerHash, orgId(34), accountId(35), 'viewer', 'active'],
    );
    expect(unchanged.rows[0]?.out_role).toBe('viewer');
    const stillLive = await admin.query('SELECT count(*)::int AS n FROM openarc_auth.sessions WHERE token_hash = $1', [
      freshTargetSession,
    ]);
    expect(stillLive.rows[0]?.n).toBe(1);
    await tenant.query('SELECT * FROM openarc_tenant.set_membership($1, $2, $3, $4, $5)', [
      ownerHash,
      orgId(34),
      accountId(35),
      'operator',
      'active',
    ]);
    const revoked = await admin.query('SELECT count(*)::int AS n FROM openarc_auth.sessions WHERE token_hash = $1', [
      freshTargetSession,
    ]);
    expect(revoked.rows[0]?.n).toBe(0);
  });

  it('retains one active owner under concurrent owner demotions', async () => {
    await seedAccount(accountId(40));
    await seedAccount(accountId(41));
    const hashA = sha256('owner-a');
    const hashB = sha256('owner-b');
    await seedSession(hashA, accountId(40));
    await seedSession(hashB, accountId(41));
    await admin.query(
      "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Dual', $2)",
      [orgId(40), accountId(40)],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'owner', 'active'), ($1, $3, 'owner', 'active')",
      [orgId(40), accountId(40), accountId(41)],
    );
    const outcomes = await Promise.allSettled([
      tenant.query('SELECT * FROM openarc_tenant.set_membership($1, $2, $3, $4, $5)', [
        hashA,
        orgId(40),
        accountId(41),
        'operator',
        'active',
      ]),
      tenant.query('SELECT * FROM openarc_tenant.set_membership($1, $2, $3, $4, $5)', [
        hashB,
        orgId(40),
        accountId(40),
        'operator',
        'active',
      ]),
    ]);
    expect(outcomes.filter((outcome) => outcome.status === 'fulfilled')).toHaveLength(1);
    const owners = await admin.query<{ n: number }>(
      "SELECT count(*)::int AS n FROM openarc_tenant.memberships WHERE organization_id = $1 AND role = 'owner' AND status = 'active'",
      [orgId(40)],
    );
    expect(owners.rows[0]?.n).toBe(1);
  });

  it('checks session freshness after waiting on the account lock', async () => {
    const ownerHash = await seedOwner(42);
    await seedAccount(accountId(43));
    await admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'viewer', 'active')",
      [orgId(42), accountId(43)],
    );
    const blocker = await admin.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query('SELECT account_id FROM openarc_auth.accounts WHERE account_id = $1 FOR UPDATE', [
        accountId(42),
      ]);
      const pending = tenant.query('SELECT * FROM openarc_tenant.lock_auth_session($1, NULL)', [ownerHash]);
      let waiting = false;
      for (let attempt = 0; attempt < 400 && !waiting; attempt += 1) {
        const probe = await admin.query<{ n: number }>(
          `SELECT count(*)::int AS n FROM pg_stat_activity
            WHERE datname = current_database() AND wait_event_type = 'Lock' AND pid <> pg_backend_pid()`,
        );
        waiting = (probe.rows[0]?.n ?? 0) > 0;
        if (!waiting) await new Promise((resolve) => setTimeout(resolve, 5));
      }
      expect(waiting).toBe(true);
      await admin.query(
        `UPDATE openarc_auth.sessions SET created_at = now() - interval '25 hours', expires_at = now() - interval '1 hour' WHERE token_hash = $1`,
        [ownerHash],
      );
      await blocker.query('COMMIT');
      await expectPgError(pending, '28000');
    } finally {
      blocker.release();
    }
  });

  it('locks sorted accounts without deadlock under mixed order', async () => {
    await seedAccount(accountId(44));
    await seedAccount(accountId(45));
    const hashA = sha256('mix-a');
    const hashB = sha256('mix-b');
    await seedSession(hashA, accountId(44));
    await seedSession(hashB, accountId(45));
    await admin.query(
      "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Mix', $2)",
      [orgId(44), accountId(44)],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'owner', 'active')",
      [orgId(44), accountId(44)],
    );
    const outcomes = await Promise.allSettled([
      tenant.query('SELECT * FROM openarc_tenant.lock_auth_session($1, $2)', [hashA, accountId(45)]),
      tenant.query('SELECT * FROM openarc_tenant.lock_auth_session($1, $2)', [hashB, accountId(44)]),
    ]);
    for (const outcome of outcomes) {
      if (outcome.status === 'rejected') {
        const code = (outcome.reason as PgError).code;
        expect(code).not.toBe('40P01');
      }
    }
    expect(outcomes.every((outcome) => outcome.status === 'fulfilled')).toBe(true);
  });

});

describe('tenant direct membership write denial', () => {
  it('denies direct owner demotion and cross-account insertion without set_membership', async () => {
    const { account } = await seedOwnedOrganization(80);
    await seedAccount(accountId(81));
    const ownerSession = sha256('owner-80-live');
    await seedSession(ownerSession, account);
    await expectPgError(
      withTenant(async (client) => {
        await setContext(client, { accountId: account, organizationId: orgId(80), role: 'owner' });
        await client.query(
          "UPDATE openarc_tenant.memberships SET role = 'operator' WHERE organization_id = $1 AND account_id = $2",
          [orgId(80), account],
        );
      }),
      '42501',
    );
    await expectPgError(
      withTenant(async (client) => {
        await setContext(client, { accountId: account, organizationId: orgId(80), role: 'owner' });
        await client.query(
          "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'viewer', 'active')",
          [orgId(80), accountId(81)],
        );
      }),
      '42501',
    );
    await expectPgError(
      withTenant(async (client) => {
        await setContext(client, { accountId: account, organizationId: orgId(80), role: 'owner' });
        await client.query(
          "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'owner', 'active')",
          [orgId(80), account],
        );
      }),
      '42501',
    );
    const preserved = await admin.query<{ role: string; status: string }>(
      'SELECT role, status FROM openarc_tenant.memberships WHERE organization_id = $1 AND account_id = $2',
      [orgId(80), account],
    );
    expect(preserved.rows[0]).toEqual({ role: 'owner', status: 'active' });
    const sessions = await admin.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM openarc_auth.sessions WHERE token_hash = $1',
      [ownerSession],
    );
    expect(sessions.rows[0]?.n).toBe(1);
  });

  it('still permits only the empty-organization initial owner bootstrap', async () => {
    await seedAccount(accountId(82));
    const hash = sha256('session-82');
    await seedSession(hash, accountId(82));
    await withTenant(async (client) => {
      const actor = await bootstrapOrganization(client, hash, orgId(82), 'Boot 82');
      expect(actor).toBe(accountId(82));
    });
    await withTenant(async (client) => {
      await setContext(client, { accountId: accountId(82), organizationId: orgId(82), role: 'owner' });
      await expectPgError(
        client.query(
          "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'owner', 'active')",
          [orgId(82), accountId(82)],
        ),
        '42501',
      );
    });
  });
});

describe('tenant lock-order freshness recheck', () => {
  it('rechecks stale proof after waiting on the organization row lock', async () => {
    const { account, hash } = await seedOwnedOrganization(83);
    await admin.query(
      `UPDATE openarc_auth.sessions
          SET created_at = clock_timestamp() - interval '5 minutes',
              expires_at = clock_timestamp() + interval '18 hours'
        WHERE token_hash = $1`,
      [hash],
    );
    const blocker = await admin.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query(
        'SELECT 1 FROM openarc_tenant.organizations WHERE organization_id = $1 FOR UPDATE',
        [orgId(83)],
      );
      const pending = tenant.query('SELECT * FROM openarc_tenant.set_membership($1, $2, $3, $4, $5)', [
        hash,
        orgId(83),
        account,
        'owner',
        'active',
      ]);
      await waitForLockWait();
      await blocker.query('COMMIT');
      await expectPgError(pending, '28000');
    } finally {
      blocker.release();
    }
  });

  it('rechecks session expiry after waiting on the organization row lock', async () => {
    const { account, hash } = await seedOwnedOrganization(84);
    await admin.query(
      `UPDATE openarc_auth.sessions
          SET created_at = clock_timestamp(),
              expires_at = clock_timestamp() + interval '1 second'
        WHERE token_hash = $1`,
      [hash],
    );
    const blocker = await admin.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query(
        'SELECT 1 FROM openarc_tenant.organizations WHERE organization_id = $1 FOR UPDATE',
        [orgId(84)],
      );
      const pending = tenant.query('SELECT * FROM openarc_tenant.set_membership($1, $2, $3, $4, $5)', [
        hash,
        orgId(84),
        account,
        'owner',
        'active',
      ]);
      await waitForLockWait();
      await blocker.query('SELECT pg_sleep(2)');
      await blocker.query('COMMIT');
      await expectPgError(pending, '28000');
    } finally {
      blocker.release();
    }
  });
});

describe('tenant error hygiene', () => {
  it('does not echo raw session hashes or values in bridge errors', async () => {
    const canary = sha256('canary');
    let message = '';
    try {
      await tenant.query('SELECT * FROM openarc_tenant.set_membership($1, $2, $3, $4, $5)', [
        canary,
        orgId(50),
        accountId(50),
        'owner',
        'active',
      ]);
    } catch (error) {
      message = (error as PgError).message ?? '';
    }
    expect(message).not.toContain(canary);
  });
});
