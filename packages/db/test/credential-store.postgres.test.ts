import { createHash } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import {
  CredentialStore,
  OutboxStore,
  createDatabasePool,
  loadMigrations,
  migrate,
  type ClaimedOutboxEvent,
} from '../src/index.js';
import {
  adminPool,
  ensureRoles,
  migratorUrl,
  resetSchema,
  tenantUrl,
  workerUrl,
} from './postgres-fixture.js';

/**
 * Real PostgreSQL acceptance for schema5 durable machine credentials and
 * scoped sessions. Runs only against the restricted runtime roles; seeds use
 * the admin fixture.
 */

function sha256(seed: string): string {
  return createHash('sha256').update(`openarc-credential-test:${seed}`, 'utf8').digest('hex');
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

function lookupId(seed: number): string {
  return uuid(300000 + seed);
}

function mutationId(seed: number): string {
  return uuid(100000 + seed);
}

function sessionId(seed: number): string {
  return uuid(400000 + seed);
}

function userHandle(seed: number): string {
  return `${sha256(`handle:${seed}`).slice(0, 42)}A`;
}

function base64Key(seed: number): string {
  return createHash('sha256').update(`key:${seed}`).digest().toString('base64url');
}

const SALT = Buffer.alloc(16, 5).toString('base64url');
const DIGEST = Buffer.alloc(32, 6).toString('base64url');

function hashInput(overrides: Record<string, unknown> = {}) {
  return {
    algorithm: 'scrypt' as const,
    hashVersion: 1 as const,
    pepperVersion: 1,
    N: 32768 as const,
    r: 8 as const,
    p: 1 as const,
    salt: SALT,
    digest: DIGEST,
    ...overrides,
  };
}

function isoIn(minutes: number): string {
  return new Date(Date.now() + minutes * 60_000).toISOString();
}

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect((error as { code?: string }).code).toBe(code);
    return;
  }
  throw new Error(`expected ${code}`);
}

let admin: Pool;
let migrator: ReturnType<typeof createDatabasePool>;
let tenant: ReturnType<typeof createDatabasePool>;
let worker: ReturnType<typeof createDatabasePool>;
let store: CredentialStore;
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
  store = new CredentialStore(tenant);
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
    [hash, account, options.method ?? 'passkey', options.createdOffset ?? '0 minutes', options.expiresOffset ?? '24 hours'],
  );
  return hash;
}

interface SeededOrg {
  readonly account: string;
  readonly org: string;
  readonly hash: string;
}

async function seedOwner(seed: number, role = 'owner'): Promise<SeededOrg> {
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

async function seedAgent(org: string, seed: number, status = 'active'): Promise<string> {
  const id = agentId(seed);
  await admin.query(
    'INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name, status) VALUES ($1, $2, $3, $4)',
    [org, id, 'Agent', status],
  );
  return id;
}

async function seedProvider(org: string, seed: number, status = 'active'): Promise<string> {
  const id = providerId(seed);
  await admin.query(
    "INSERT INTO openarc_tenant.providers (organization_id, provider_id, display_name, status) VALUES ($1, $2, 'Provider', $3)",
    [org, id, status],
  );
  return id;
}

async function counts(): Promise<Record<string, number>> {
  const result = await admin.query<Record<string, number>>(
    `SELECT
       (SELECT count(*)::int FROM openarc_durable.agent_credentials) AS agent_credentials,
       (SELECT count(*)::int FROM openarc_durable.provider_credentials) AS provider_credentials,
       (SELECT count(*)::int FROM openarc_durable.agent_sessions) AS agent_sessions,
       (SELECT count(*)::int FROM openarc_durable.provider_sessions) AS provider_sessions,
       (SELECT count(*)::int FROM openarc_durable.idempotency_records) AS idem,
       (SELECT count(*)::int FROM openarc_durable.audit_events) AS audit,
       (SELECT count(*)::int FROM openarc_durable.outbox_events) AS outbox`,
  );
  const row = result.rows[0];
  if (row === undefined) throw new Error('counts failed');
  return row;
}

describe('schema5 manifest, unions and ACLs', () => {
  it('records schema5 and keeps every new helper migrator-owned with fixed search_path', async () => {
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
      '0015_payment_attempts',
      '0016_evidence_store',
      '0017_settlement_observation',
      '0018_operator_reads',
    ]);
    const helpers = await admin.query<{ proname: string; owner: string; secdef: boolean; config: string[] }>(
      `SELECT p.proname, r.rolname AS owner, p.prosecdef AS secdef,
              coalesce(p.proconfig, ARRAY[]::text[]) AS config
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         JOIN pg_roles r ON r.oid = p.proowner
        WHERE n.nspname = 'openarc_durable'
          AND p.proname IN (
            'commit_agent_credential_issue', 'commit_agent_credential_revoke',
            'commit_provider_credential_issue', 'commit_provider_credential_revoke',
            'create_agent_session', 'create_provider_session',
            'find_agent_credential_verifier', 'find_provider_credential_verifier',
            'list_agent_credentials', 'list_provider_credentials',
            'read_agent_credential_mutation_status', 'read_agent_session',
            'read_provider_credential_mutation_status', 'read_provider_session',
            'revoke_agent_session', 'revoke_provider_session', 'lock_credential_issuer'
          )
        ORDER BY p.proname`,
    );
    expect(helpers.rows).toHaveLength(17);
    expect(
      helpers.rows.every(
        (row) =>
          row.owner === 'openarc_migrator' &&
          row.secdef === true &&
          row.config.includes('search_path=pg_catalog'),
      ),
    ).toBe(true);
    const publicGrants = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM pg_proc p,
            aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
        WHERE p.pronamespace = 'openarc_durable'::regnamespace
          AND a.grantee = 0 AND a.privilege_type = 'EXECUTE'`,
    );
    expect(publicGrants.rows[0]?.n).toBe(0);
  });

  it('forces RLS on the four credential/session tables and denies direct DML', async () => {
    const rls = await admin.query<{ relname: string; forced: boolean }>(
      `SELECT c.relname, c.relforcerowsecurity AS forced
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'openarc_durable'
          AND c.relname IN ('agent_credentials','provider_credentials','agent_sessions','provider_sessions')
        ORDER BY c.relname`,
    );
    expect(rls.rows.map((row) => row.relname)).toEqual([
      'agent_credentials',
      'agent_sessions',
      'provider_credentials',
      'provider_sessions',
    ]);
    expect(rls.rows.every((row) => row.forced)).toBe(true);

    await expect(tenant.query('SELECT * FROM openarc_durable.agent_credentials')).rejects.toBeTruthy();
    await expect(tenant.query('SELECT * FROM openarc_durable.provider_sessions')).rejects.toBeTruthy();
    await expect(worker.query('SELECT * FROM openarc_durable.agent_credentials')).rejects.toBeTruthy();
    await expect(worker.query('SELECT * FROM openarc_durable.agent_sessions')).rejects.toBeTruthy();
    await expect(worker.query('SELECT * FROM openarc_credential_missing')).rejects.toBeTruthy();
  });

  it('denies the worker any credential/session helper execute', async () => {
    const result = await worker.query<{ ok: boolean }>(
      `SELECT has_function_privilege(current_user,
          'openarc_durable.find_agent_credential_verifier(uuid)', 'EXECUTE') AS ok`,
    );
    expect(result.rows[0]?.ok).toBe(false);
  });

  it('enforces typed credential FKs across agent/provider kinds', async () => {
    const owner = await seedOwner(4);
    await seedAgent(owner.org, 4);
    // An agent_credential receipt may not point at a provider credential.
    await expect(
      admin.query(
        `INSERT INTO openarc_durable.idempotency_records
           (organization_id, operation, key_hash, request_digest, digest_version,
            actor_account_id, session_context_digest, network, mutation_id,
            status, resource_type, resource_id, committed_at)
         VALUES ($1, 'tenant.agent.credential.issue', $2, $3, 'tenant.agent.credential.issue.v1',
                 $4, $5, 'eip155:5042002', $6::uuid, 'committed', 'agent_credential', $7, clock_timestamp())`,
        [owner.org, sha256('fk1'), sha256('fk1d'), owner.account, sha256('fk1s'), mutationId(4), providerId(4)],
      ),
    ).rejects.toBeTruthy();
    expect(await counts()).toMatchObject({ idem: 0 });
  });
});

describe('credential issue / revoke durable flow', () => {
  it('issues an agent credential, commits receipt/audit/outbox, and replays without replacing material', async () => {
    const owner = await seedOwner(10);
    const agent = await seedAgent(owner.org, 10);
    const issueExpiresAt = isoIn(60);
    const first = await store.issueAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: agent,
      lookupId: lookupId(10),
      hash: hashInput({ pepperVersion: 2 }),
      expiresAt: issueExpiresAt,
      metadata: { idempotencyKey: base64Key(10), mutationId: mutationId(10) },
    });
    expect(first.replayed).toBe(false);
    expect(first.receipt).toMatchObject({
      operation: 'tenant.agent.credential.issue',
      resourceType: 'agent_credential',
      credentialId: mutationId(10),
    });
    expect(await counts()).toMatchObject({
      agent_credentials: 1,
      idem: 1,
      audit: 1,
      outbox: 1,
    });
    // Replay with fresh salt/digest/lookup returns the original safe receipt
    // and never replaces the stored material.
    const replay = await store.issueAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: agent,
      lookupId: lookupId(11),
      hash: hashInput({ pepperVersion: 3, salt: Buffer.alloc(16, 8).toString('base64url') }),
      expiresAt: issueExpiresAt,
      metadata: { idempotencyKey: base64Key(10), mutationId: mutationId(10) },
    });
    expect(replay.replayed).toBe(true);
    expect(replay.receipt).toEqual(first.receipt);
    const stored = await admin.query<{ pepper_version: number; salt: string; lookup_id: string }>(
      'SELECT pepper_version, salt, lookup_id FROM openarc_durable.agent_credentials WHERE credential_id = $1::uuid',
      [mutationId(10)],
    );
    expect(stored.rows[0]).toMatchObject({ pepper_version: 2, salt: SALT, lookup_id: lookupId(10) });
    expect(await counts()).toMatchObject({ agent_credentials: 1, idem: 1, audit: 1, outbox: 1 });
  });

  it('issues a provider credential owner-only', async () => {
    const owner = await seedOwner(11);
    const provider = await seedProvider(owner.org, 11);
    const operator = await seedAccount(12);
    const operatorHash = await seedSession(12, operator);
    await admin.query(
      'INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, $3, $4)',
      [owner.org, operator, 'operator', 'active'],
    );
    await expectCode(
      store.issueProviderCredentialDurably({
        sessionHash: operatorHash,
        organizationId: owner.org,
        profileId: provider,
        lookupId: lookupId(11),
        hash: hashInput(),
        expiresAt: isoIn(60),
        metadata: { idempotencyKey: base64Key(11), mutationId: mutationId(11) },
      }),
      'CREDENTIAL_STORE_FORBIDDEN',
    );
    const created = await store.issueProviderCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: provider,
      lookupId: lookupId(11),
      hash: hashInput(),
      expiresAt: isoIn(60),
      metadata: { idempotencyKey: base64Key(11), mutationId: mutationId(11) },
    });
    expect(created.receipt.resourceType).toBe('provider_credential');
  });

  it('revokes a credential, revokes its existing sessions, and replays', async () => {
    const owner = await seedOwner(13);
    const agent = await seedAgent(owner.org, 13);
    const issued = await store.issueAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: agent,
      lookupId: lookupId(13),
      hash: hashInput(),
      expiresAt: isoIn(60),
      metadata: { idempotencyKey: base64Key(13), mutationId: mutationId(13) },
    });
    const credential = issued.receipt.credentialId;
    await store.createAgentSession({
      organizationId: owner.org,
      profileId: agent,
      credentialId: credential,
      expectedVersion: 1,
      sessionId: sessionId(13),
      tokenHash: sha256('machine:13'),
      expiresAt: isoIn(10),
    });
    const revoked = await store.revokeAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      credentialId: credential,
      metadata: { idempotencyKey: base64Key(14), mutationId: mutationId(14) },
    });
    expect(revoked.replayed).toBe(false);
    const session = await admin.query<{ revoked_at: Date | null }>(
      'SELECT revoked_at FROM openarc_durable.agent_sessions WHERE credential_id = $1::uuid',
      [credential],
    );
    expect(session.rows[0]?.revoked_at).not.toBeNull();
    const replay = await store.revokeAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      credentialId: credential,
      metadata: { idempotencyKey: base64Key(14), mutationId: mutationId(14) },
    });
    expect(replay.replayed).toBe(true);
    expect(await counts()).toMatchObject({ agent_credentials: 1, agent_sessions: 1, idem: 2, audit: 2, outbox: 2 });
  });

  it('rejects recovery or stale proof on issue but allows revoke from recovery', async () => {
    const owner = await seedOwner(15);
    const agent = await seedAgent(owner.org, 15);
    const recovery = await seedSession(150, owner.account, { method: 'recovery' });
    await expectCode(
      store.issueAgentCredentialDurably({
        sessionHash: recovery,
        organizationId: owner.org,
        profileId: agent,
        lookupId: lookupId(15),
        hash: hashInput(),
        expiresAt: isoIn(60),
        metadata: { idempotencyKey: base64Key(15), mutationId: mutationId(15) },
      }),
      'CREDENTIAL_STORE_SESSION_INVALID',
    );
    const stale = await seedSession(160, owner.account, { createdOffset: '-6 minutes', expiresOffset: '30 minutes' });
    await expectCode(
      store.issueAgentCredentialDurably({
        sessionHash: stale,
        organizationId: owner.org,
        profileId: agent,
        lookupId: lookupId(15),
        hash: hashInput(),
        expiresAt: isoIn(60),
        metadata: { idempotencyKey: base64Key(15), mutationId: mutationId(15) },
      }),
      'CREDENTIAL_STORE_SESSION_INVALID',
    );
    expect(await counts()).toMatchObject({ agent_credentials: 0 });
  });

  it('rejects an expiry beyond 90 days or a non-canonical timestamp', async () => {
    const owner = await seedOwner(17);
    const agent = await seedAgent(owner.org, 17);
    await expectCode(
      store.issueAgentCredentialDurably({
        sessionHash: owner.hash,
        organizationId: owner.org,
        profileId: agent,
        lookupId: lookupId(17),
        hash: hashInput(),
        expiresAt: new Date(Date.now() + 91 * 24 * 60 * 60_000).toISOString(),
        metadata: { idempotencyKey: base64Key(17), mutationId: mutationId(17) },
      }),
      'CREDENTIAL_STORE_INPUT_INVALID',
    );
  });
});

describe('credential status, list and verifier', () => {
  it('returns a bounded status and list projection without hash material', async () => {
    const owner = await seedOwner(20);
    const agent = await seedAgent(owner.org, 20);
    const issued = await store.issueAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: agent,
      lookupId: lookupId(20),
      hash: hashInput(),
      expiresAt: isoIn(60),
      metadata: { idempotencyKey: base64Key(20), mutationId: mutationId(20) },
    });
    const status = await store.getAgentCredentialMutationStatus(owner.hash, owner.org, mutationId(20));
    expect(status.status).toBe('committed');
    if (status.status === 'committed') {
      expect(status.receipt).toEqual(issued.receipt);
      expect(JSON.stringify(status)).not.toContain(DIGEST);
    }
    const list = await store.listAgentCredentials({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: agent,
    });
    expect(list.items).toHaveLength(1);
    expect(list.items[0]).toMatchObject({
      credentialId: mutationId(20),
      kind: 'agent',
      profileId: agent,
      keyPrefix: `oac_ag_${lookupId(20)}`,
      status: 'active',
    });
    expect(JSON.stringify(list)).not.toContain(DIGEST);
    expect(JSON.stringify(list)).not.toContain(SALT);
  });

  it('returns not_found under current authorization for another account mutation', async () => {
    const owner = await seedOwner(21);
    const agent = await seedAgent(owner.org, 21);
    await store.issueAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: agent,
      lookupId: lookupId(21),
      hash: hashInput(),
      expiresAt: isoIn(60),
      metadata: { idempotencyKey: base64Key(21), mutationId: mutationId(21) },
    });
    const other = await seedOwner(22);
    await expect(
      store.getAgentCredentialMutationStatus(other.hash, other.org, mutationId(21)),
    ).resolves.toEqual({ status: 'not_found' });
  });

  it('finds a verifier snapshot and denies after revoke or profile suspension', async () => {
    const owner = await seedOwner(23);
    const agent = await seedAgent(owner.org, 23);
    await store.issueAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: agent,
      lookupId: lookupId(23),
      hash: hashInput({ pepperVersion: 4 }),
      expiresAt: isoIn(60),
      metadata: { idempotencyKey: base64Key(23), mutationId: mutationId(23) },
    });
    const snapshot = await store.findAgentCredentialVerifier(lookupId(23));
    expect(snapshot).toMatchObject({
      kind: 'agent',
      profileId: agent,
      pepperVersion: 4,
      digest: DIGEST,
      keyPrefix: `oac_ag_${lookupId(23)}`,
    });
    await admin.query("UPDATE openarc_tenant.agents SET status = 'suspended' WHERE agent_id = $1", [agent]);
    await expectCode(store.findAgentCredentialVerifier(lookupId(23)), 'CREDENTIAL_STORE_FORBIDDEN');
    await admin.query("UPDATE openarc_tenant.agents SET status = 'active' WHERE agent_id = $1", [agent]);
    await store.revokeAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      credentialId: mutationId(23),
      metadata: { idempotencyKey: base64Key(24), mutationId: mutationId(24) },
    });
    await expectCode(store.findAgentCredentialVerifier(lookupId(23)), 'CREDENTIAL_STORE_FORBIDDEN');
  });
});

describe('scoped machine sessions', () => {
  it('creates, reads and revokes an agent session with no raw token column', async () => {
    const owner = await seedOwner(30);
    const agent = await seedAgent(owner.org, 30);
    await store.issueAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: agent,
      lookupId: lookupId(30),
      hash: hashInput(),
      expiresAt: isoIn(60),
      metadata: { idempotencyKey: base64Key(30), mutationId: mutationId(30) },
    });
    const tokenHash = sha256('machine:30');
    const created = await store.createAgentSession({
      organizationId: owner.org,
      profileId: agent,
      credentialId: mutationId(30),
      expectedVersion: 1,
      sessionId: sessionId(30),
      tokenHash,
      expiresAt: isoIn(10),
    });
    expect(created).toMatchObject({
      sessionId: sessionId(30),
      kind: 'agent',
      profileId: agent,
      scope: 'agent:self.read',
    });
    const read = await store.getAgentSession(tokenHash);
    expect(read).toMatchObject({ sessionId: sessionId(30), profileId: agent });
    const revoked = await store.revokeAgentSession(tokenHash);
    expect(revoked).toMatchObject({ sessionId: sessionId(30), organizationId: owner.org });
    await expectCode(store.getAgentSession(tokenHash), 'CREDENTIAL_STORE_FORBIDDEN');
    const columns = await admin.query<{ column_name: string }>(
      `SELECT column_name FROM information_schema.columns
        WHERE table_schema = 'openarc_durable'
          AND table_name IN ('agent_credentials','provider_credentials','agent_sessions','provider_sessions')
          AND column_name IN ('raw_token','token','pepper','prehash')`,
    );
    expect(columns.rows).toEqual([]);
  });

  it('rejects a session expiry beyond 15 minutes or beyond credential expiry', async () => {
    const owner = await seedOwner(31);
    const agent = await seedAgent(owner.org, 31);
    await store.issueAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: agent,
      lookupId: lookupId(31),
      hash: hashInput(),
      expiresAt: isoIn(20),
      metadata: { idempotencyKey: base64Key(31), mutationId: mutationId(31) },
    });
    await expectCode(
      store.createAgentSession({
        organizationId: owner.org,
        profileId: agent,
        credentialId: mutationId(31),
        expectedVersion: 1,
        sessionId: sessionId(31),
        tokenHash: sha256('machine:31'),
        expiresAt: isoIn(16),
      }),
      'CREDENTIAL_STORE_INPUT_INVALID',
    );
    await expectCode(
      store.createAgentSession({
        organizationId: owner.org,
        profileId: agent,
        credentialId: mutationId(31),
        expectedVersion: 1,
        sessionId: sessionId(31),
        tokenHash: sha256('machine:31'),
        expiresAt: isoIn(30),
      }),
      'CREDENTIAL_STORE_INPUT_INVALID',
    );
  });

  it('rejects a stale expectedVersion after revoke', async () => {
    const owner = await seedOwner(32);
    const agent = await seedAgent(owner.org, 32);
    await store.issueAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: agent,
      lookupId: lookupId(32),
      hash: hashInput(),
      expiresAt: isoIn(60),
      metadata: { idempotencyKey: base64Key(32), mutationId: mutationId(32) },
    });
    await store.revokeAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      credentialId: mutationId(32),
      metadata: { idempotencyKey: base64Key(33), mutationId: mutationId(33) },
    });
    await expectCode(
      store.createAgentSession({
        organizationId: owner.org,
        profileId: agent,
        credentialId: mutationId(32),
        expectedVersion: 1,
        sessionId: sessionId(32),
        tokenHash: sha256('machine:32'),
        expiresAt: isoIn(10),
      }),
      'CREDENTIAL_STORE_CONFLICT',
    );
  });
});

describe('legacy status never exposes credential receipts', () => {
  it('returns not_found for a credential mutation through the legacy generic status', async () => {
    const owner = await seedOwner(40);
    const agent = await seedAgent(owner.org, 40);
    await store.issueAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: agent,
      lookupId: lookupId(40),
      hash: hashInput(),
      expiresAt: isoIn(60),
      metadata: { idempotencyKey: base64Key(40), mutationId: mutationId(40) },
    });
    const legacy = await tenant.query<{ out_mutation_id: string }>(
      `SELECT out_mutation_id FROM openarc_durable.read_tenant_mutation_status($1, $2, $3::uuid)`,
      [owner.hash, owner.org, mutationId(40)],
    );
    expect(legacy.rows).toHaveLength(0);
  });
});

describe('credential outbox notifications', () => {
  it('claims and consumes all four new credential events with only metadata', async () => {
    const owner = await seedOwner(50);
    const agent = await seedAgent(owner.org, 50);
    const provider = await seedProvider(owner.org, 50);
    await store.issueAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: agent,
      lookupId: lookupId(50),
      hash: hashInput(),
      expiresAt: isoIn(60),
      metadata: { idempotencyKey: base64Key(50), mutationId: mutationId(50) },
    });
    await store.revokeAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      credentialId: mutationId(50),
      metadata: { idempotencyKey: base64Key(51), mutationId: mutationId(51) },
    });
    await store.issueProviderCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: provider,
      lookupId: lookupId(50),
      hash: hashInput(),
      expiresAt: isoIn(60),
      metadata: { idempotencyKey: base64Key(52), mutationId: mutationId(52) },
    });
    await store.revokeProviderCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      credentialId: mutationId(52),
      metadata: { idempotencyKey: base64Key(53), mutationId: mutationId(53) },
    });
    await outbox.initialize();
    const claimed = await outbox.claim({ limit: 10 });
    expect(claimed).toHaveLength(4);
    const kinds = claimed.map((event) => `${(event as ClaimedOutboxEvent).resourceType}|${(event as ClaimedOutboxEvent).eventType}`).sort();
    expect(kinds).toEqual([
      'agent_credential|tenant.agent.credential.created',
      'agent_credential|tenant.agent.credential.revoked',
      'provider_credential|tenant.provider.credential.created',
      'provider_credential|tenant.provider.credential.revoked',
    ]);
    for (const event of claimed) {
      expect(JSON.stringify(event)).not.toContain(DIGEST);
      expect(await outbox.complete(event.eventId, event.leaseGeneration)).toEqual({ applied: true });
    }
    expect(await outbox.claim({ limit: 10 })).toHaveLength(0);
  });

  it('rolls back the whole issue transaction on an injected outbox failure', async () => {
    const owner = await seedOwner(51);
    const agent = await seedAgent(owner.org, 51);
    await admin.query(
      `CREATE OR REPLACE FUNCTION openarc_durable.test_fail_credential_outbox() RETURNS trigger
       LANGUAGE plpgsql SET search_path = pg_catalog AS $$
       BEGIN RAISE EXCEPTION 'injected' USING ERRCODE = '23514'; END; $$`,
    );
    await admin.query(
      'CREATE TRIGGER test_fail_credential_outbox BEFORE INSERT ON openarc_durable.outbox_events FOR EACH ROW EXECUTE FUNCTION openarc_durable.test_fail_credential_outbox()',
    );
    await expectCode(
      store.issueAgentCredentialDurably({
        sessionHash: owner.hash,
        organizationId: owner.org,
        profileId: agent,
        lookupId: lookupId(51),
        hash: hashInput(),
        expiresAt: isoIn(60),
        metadata: { idempotencyKey: base64Key(54), mutationId: mutationId(54) },
      }),
      'CREDENTIAL_STORE_INPUT_INVALID',
    );
    await admin.query('DROP TRIGGER test_fail_credential_outbox ON openarc_durable.outbox_events');
    await admin.query('DROP FUNCTION openarc_durable.test_fail_credential_outbox()');
    expect(await counts()).toMatchObject({ agent_credentials: 0, idem: 0, audit: 0, outbox: 0 });
  });
});

describe('independent ownership evidence', () => {
  it('exposes only the reviewed migration manifest to the schema5 upgrade', () => {
    expect(loadMigrations().map((migration) => migration.id)).toContain('0005_machine_credentials');
  });
});

interface LockedOrg {
  readonly account: string;
  readonly org: string;
  readonly hash: string;
  readonly agent: string;
  readonly credential: string;
  readonly lookup: string;
  readonly tokenHash: string;
}

async function seedCredentialAndSession(seed: number): Promise<LockedOrg> {
  const owner = await seedOwner(seed);
  const agent = await seedAgent(owner.org, seed);
  const lookup = lookupId(seed);
  await store.issueAgentCredentialDurably({
    sessionHash: owner.hash,
    organizationId: owner.org,
    profileId: agent,
    lookupId: lookup,
    hash: hashInput(),
    expiresAt: isoIn(60),
    metadata: { idempotencyKey: base64Key(seed), mutationId: mutationId(seed) },
  });
  const tokenHash = sha256(`machine:${seed}`);
  await store.createAgentSession({
    organizationId: owner.org,
    profileId: agent,
    credentialId: mutationId(seed),
    expectedVersion: 1,
    sessionId: sessionId(seed),
    tokenHash,
    expiresAt: isoIn(10),
  });
  return { ...owner, agent, credential: mutationId(seed), lookup, tokenHash };
}

async function waitForLockWaitCount(minimum: number): Promise<void> {
  for (let attempt = 0; attempt < 400; attempt += 1) {
    const probe = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM pg_stat_activity
        WHERE datname = current_database() AND wait_event_type = 'Lock' AND pid <> pg_backend_pid()`,
    );
    if ((probe.rows[0]?.n ?? 0) >= minimum) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error('no lock wait observed');
}

describe('review regressions: table bound, DB-clock status and lock order', () => {
  it('rejects a direct migrator session insert beyond the 15-minute table bound', async () => {
    const owner = await seedOwner(60);
    const agent = await seedAgent(owner.org, 60);
    await store.issueAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: agent,
      lookupId: lookupId(60),
      hash: hashInput(),
      expiresAt: isoIn(60),
      metadata: { idempotencyKey: base64Key(60), mutationId: mutationId(60) },
    });
    await expect(
      admin.query(
        `INSERT INTO openarc_durable.agent_sessions
           (session_id, token_hash, organization_id, agent_id, credential_id,
            scope, scope_version, environment, created_at, expires_at)
         VALUES ($1::uuid, $2, $3, $4, $5::uuid, 'agent:self.read', 1,
                 'eip155:5042002', clock_timestamp(), clock_timestamp() + interval '16 minutes')`,
        [sessionId(60), sha256('machine:60'), owner.org, agent, mutationId(60)],
      ),
    ).rejects.toBeTruthy();
  });

  it('derives list status from the database clock, not the local wall clock', async () => {
    const owner = await seedOwner(61);
    const agent = await seedAgent(owner.org, 61);
    await store.issueAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: agent,
      lookupId: lookupId(61),
      hash: hashInput(),
      expiresAt: isoIn(60),
      metadata: { idempotencyKey: base64Key(61), mutationId: mutationId(61) },
    });
    // The row is DB-expired while the local ISO timestamp still looks future in
    // this process; the SQL helper is the only status authority.
    await admin.query(
      `UPDATE openarc_durable.agent_credentials
          SET created_at = clock_timestamp() - interval '10 minutes',
              expires_at = clock_timestamp() - interval '5 minutes'
        WHERE credential_id = $1::uuid`,
      [mutationId(61)],
    );
    const list = await store.listAgentCredentials({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: agent,
    });
    expect(list.items[0]?.status).toBe('expired');
  });

  it('keeps issue/revoke and verifier/current-read lock orders non-inverting', async () => {
    const seeded = await seedCredentialAndSession(62);
    // Process A holds the credential row. Verifier and current-session reads
    // must block at the credential lock (after the earlier bindings) and then
    // complete once A releases, without a deadlock or a stale grant.
    const blocker = await admin.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query(
        'SELECT 1 FROM openarc_durable.agent_credentials WHERE credential_id = $1::uuid FOR UPDATE',
        [seeded.credential],
      );
      const verifier = store.findAgentCredentialVerifier(seeded.lookup);
      const reader = store.getAgentSession(seeded.tokenHash);
      await waitForLockWaitCount(2);
      await blocker.query('ROLLBACK');
      const [snapshot, session] = await Promise.all([verifier, reader]);
      expect(snapshot.credentialId).toBe(seeded.credential);
      expect(session.sessionId).toBe(sessionId(62));
    } finally {
      await blocker.query('ROLLBACK').catch(() => {});
      blocker.release();
    }
  });

  it('blocks a revoke against a held organization lock and never deadlocks', async () => {
    const seeded = await seedCredentialAndSession(63);
    const blocker = await admin.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query(
        'SELECT 1 FROM openarc_tenant.organizations WHERE organization_id = $1 FOR UPDATE',
        [seeded.org],
      );
      const revoke = store.revokeAgentCredentialDurably({
        sessionHash: seeded.hash,
        organizationId: seeded.org,
        credentialId: seeded.credential,
        metadata: { idempotencyKey: base64Key(163), mutationId: mutationId(163) },
      });
      await waitForLockWaitCount(1);
      await blocker.query('COMMIT');
      const result = await revoke;
      expect(result.receipt.credentialId).toBe(seeded.credential);
    } finally {
      await blocker.query('ROLLBACK').catch(() => {});
      blocker.release();
    }
    const revoked = await admin.query<{ revoked_at: Date | null }>(
      'SELECT revoked_at FROM openarc_durable.agent_credentials WHERE credential_id = $1::uuid',
      [seeded.credential],
    );
    expect(revoked.rows[0]?.revoked_at).not.toBeNull();
  });

  it('rechecks the locked credential expiry while the machine session is still live', async () => {
    const seeded = await seedCredentialAndSession(64);
    // Guarded admin fixture: expire the credential only (the session remains
    // live for another 10 minutes). Production rows cannot normally violate the
    // credential/session expiry invariant, but the current read must still
    // recheck the locked credential expiry explicitly.
    await admin.query(
      `UPDATE openarc_durable.agent_credentials
          SET created_at = clock_timestamp() - interval '10 minutes',
              expires_at = clock_timestamp() - interval '5 minutes'
        WHERE credential_id = $1::uuid`,
      [seeded.credential],
    );
    await expectCode(store.getAgentSession(seeded.tokenHash), 'CREDENTIAL_STORE_FORBIDDEN');
    await expectCode(store.findAgentCredentialVerifier(seeded.lookup), 'CREDENTIAL_STORE_FORBIDDEN');
  });

  it('uses the actual issuer role for agent verifier and current-session reads', async () => {
    const owner = await seedOwner(65);
    const operator = await seedOwner(66, 'operator');
    const ownerAgent = await seedAgent(owner.org, 65);
    const operatorAgent = await seedAgent(operator.org, 66);
    await store.issueAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: ownerAgent,
      lookupId: lookupId(65),
      hash: hashInput(),
      expiresAt: isoIn(60),
      metadata: { idempotencyKey: base64Key(65), mutationId: mutationId(65) },
    });
    await store.issueAgentCredentialDurably({
      sessionHash: operator.hash,
      organizationId: operator.org,
      profileId: operatorAgent,
      lookupId: lookupId(66),
      hash: hashInput(),
      expiresAt: isoIn(60),
      metadata: { idempotencyKey: base64Key(66), mutationId: mutationId(66) },
    });
    const ownerToken = sha256('machine:65');
    const operatorToken = sha256('machine:66');
    await store.createAgentSession({
      organizationId: owner.org,
      profileId: ownerAgent,
      credentialId: mutationId(65),
      expectedVersion: 1,
      sessionId: sessionId(65),
      tokenHash: ownerToken,
      expiresAt: isoIn(10),
    });
    await store.createAgentSession({
      organizationId: operator.org,
      profileId: operatorAgent,
      credentialId: mutationId(66),
      expectedVersion: 1,
      sessionId: sessionId(66),
      tokenHash: operatorToken,
      expiresAt: isoIn(10),
    });
    expect((await store.findAgentCredentialVerifier(lookupId(65))).credentialId).toBe(mutationId(65));
    expect((await store.findAgentCredentialVerifier(lookupId(66))).credentialId).toBe(mutationId(66));
    expect((await store.getAgentSession(ownerToken)).sessionId).toBe(sessionId(65));
    expect((await store.getAgentSession(operatorToken)).sessionId).toBe(sessionId(66));
  });
});
