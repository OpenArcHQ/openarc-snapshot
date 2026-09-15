import { createHash } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool, PoolClient } from 'pg';
import {
  OutboxStore,
  TenantStore,
  createDatabasePool,
  digestIdempotencyKey,
  digestSessionContext,
  migrate,
} from '../src/index.js';
import {
  adminPool,
  ensureRoles,
  migratorUrl,
  resetSchema,
  tenantUrl,
  workerUrl,
} from './postgres-fixture.js';
import {
  insertOutboxEventForPair,
  outboxPairKey,
  readPermittedOutboxEventPairs,
} from './outbox-event-catalog.js';

/**
 * Real PostgreSQL acceptance for the durability slice (schema3).
 *
 * Every mutation runs through the restricted runtime roles. Seeds are written
 * with the admin superuser so the runtime never gains auth-table privileges.
 * Timing is expressed with admin-only fixture locks and DB clock manipulation,
 * never fixed long sleeps.
 */

function sha256(seed: string): string {
  return createHash('sha256').update(`openarc-durability-test:${seed}`, 'utf8').digest('hex');
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

async function expectPgError(promise: Promise<unknown>, code: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect((error as PgError).code).toBe(code);
    return;
  }
  throw new Error(`expected pg error ${code}`);
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

async function seedOrg(seed: number, creator: string): Promise<string> {
  const org = orgId(seed);
  await admin.query(
    "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Org', $2)",
    [org, creator],
  );
  return org;
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

async function seedOwner(
  seed: number,
): Promise<{ account: string; org: string; hash: string }> {
  const account = await seedAccount(seed);
  const hash = await seedSession(seed, account);
  const org = await seedOrg(seed, account);
  await seedMembership(org, account, 'owner');
  return { account, org, hash };
}

async function counts(): Promise<{ agents: number; idem: number; audit: number; outbox: number }> {
  const result = await admin.query<{
    agents: number;
    idem: number;
    audit: number;
    outbox: number;
  }>(
    `SELECT
       (SELECT count(*)::int FROM openarc_tenant.agents) AS agents,
       (SELECT count(*)::int FROM openarc_durable.idempotency_records) AS idem,
       (SELECT count(*)::int FROM openarc_durable.audit_events) AS audit,
          (SELECT count(*)::int FROM openarc_durable.outbox_events) AS outbox`,
  );
  const row = result.rows[0];
  if (row === undefined) throw new Error('counts failed');
  return row;
}

async function seedOutboxEvent(
  seed: number,
  options: {
    org: string;
    state?: string;
    attempts?: number;
    availableOffset?: string;
    leaseOffset?: string;
    generation?: number;
  },
): Promise<string> {
  const eventId = uuid(200000 + seed);
  // The outbox row is bound by a compound FK to a committed idempotency
  // receipt. Seed a dedicated account and committed receipt so the worker
  // fixture reproduces a real coupled mutation.
  const actor = accountId(900000 + seed);
  await admin.query(
    'INSERT INTO openarc_auth.accounts (account_id, user_handle, status) VALUES ($1, $2, $3)',
    [actor, userHandle(900000 + seed), 'active'],
  );
  await admin.query(
    "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name) VALUES ($1, $2, 'Outbox Agent')",
    [options.org, agentId(seed)],
  );
  await admin.query(
    `INSERT INTO openarc_durable.idempotency_records
       (organization_id, operation, key_hash, request_digest, digest_version,
        actor_account_id, session_context_digest, network, mutation_id,
        status, resource_type, resource_id, committed_at)
     VALUES ($1, 'tenant.agent.create', $2, $3, 'tenant.agent.create.v1',
             $4, $5, 'eip155:5042002', $6::uuid,
             'committed', 'agent', $7, clock_timestamp())`,
    [
      options.org,
      sha256(`outbox-key:${seed}`),
      sha256(`outbox-digest:${seed}`),
      actor,
      sha256(`outbox-session:${seed}`),
      mutationId(seed),
      agentId(seed),
    ],
  );
  await admin.query(
    `INSERT INTO openarc_durable.outbox_events
       (event_id, organization_id, mutation_id, resource_type, resource_id, event_type,
        payload_version, state, available_at, attempt_count, lease_until, lease_generation)
     VALUES ($1, $2, $3::uuid, 'agent', $4, 'tenant.agent.created', 1, $5,
             now() + ($6)::interval, $7, CASE WHEN $8::text IS NULL THEN NULL ELSE now() + ($8)::interval END, $9)`,
    [
      eventId,
      options.org,
      mutationId(seed),
      agentId(seed),
      options.state ?? 'pending',
      options.availableOffset ?? '-1 minute',
      options.attempts ?? 0,
      options.leaseOffset ?? null,
      options.generation ?? 0,
    ],
  );
  return eventId;
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

function assertPoolContextReleased(pool: Pool): void {
  expect(pool.totalCount - pool.idleCount).toBe(0);
}

async function waitUntilLeaseExpired(eventId: string): Promise<void> {
  for (let attempt = 0; attempt < 400; attempt += 1) {
    const probe = await admin.query<{ expired: boolean }>(
      `SELECT clock_timestamp() >= lease_until AS expired
         FROM openarc_durable.outbox_events WHERE event_id = $1`,
      [eventId],
    );
    if (probe.rows[0]?.expired === true) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error('lease did not expire');
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

async function shortenSession(hash: string, seconds: number): Promise<void> {
  await admin.query(
    `UPDATE openarc_auth.sessions
        SET expires_at = clock_timestamp() + make_interval(secs => $2)
      WHERE token_hash = $1`,
    [hash, seconds],
  );
}

describe('durability migration and readiness', () => {
  it('records schema3 and exposes the durable definer helpers as migrator', async () => {
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
    ]);
    const helpers = await admin.query<{ proname: string; owner: string }>(
      `SELECT p.proname, r.rolname AS owner
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         JOIN pg_roles r ON r.oid = p.proowner
        WHERE n.nspname = 'openarc_durable' AND p.prorettype <> 'trigger'::regtype
        ORDER BY p.proname`,
    );
    expect(helpers.rows.map((row) => row.proname)).toEqual([
      'assert_action_decide_current',
      'assert_action_prereqs_current',
      'assert_listing_active_pointer',
      'assert_listing_content',
      'assert_policy_content',
      'assess_action_budget',
      'authorize_commerce_action',
      'authorize_commerce_action_core',
      'cancel_commerce_action',
      'cancel_commerce_action_core',
      'claim_authorization_grant',
      'claim_authorization_grant_core',
      'claim_outbox_jobs',
      'commit_agent_create',
      'commit_agent_credential_issue',
      'commit_agent_credential_revoke',
      'commit_agent_update',
      'commit_lifecycle_transition',
      'commit_listing_create',
      'commit_listing_payment_terms',
      'commit_listing_version_create',
      'commit_membership_set',
      'commit_organization_create',
      'commit_origin_review',
      'commit_policy_mutation',
      'commit_provider_create',
      'commit_provider_credential_issue',
      'commit_provider_credential_revoke',
      'commit_provider_update',
      'complete_outbox_job',
      'create_agent_session',
      'create_provider_session',
      'decide_commerce_action',
      'decide_commerce_action_core',
      'derive_commerce_session_status',
      'evidence_fact_digest',
      'exchange_commerce_session',
      'fail_outbox_job',
      'find_agent_credential_verifier',
      'find_provider_credential_verifier',
      'get_moderator_listing_version',
      'get_public_listing',
      'get_public_provider',
      'grant_claim_digest',
      'introspect_authorization_grant',
      'introspect_authorization_grant_core',
      'is_allowed_exposure_identity',
      'is_canonical_action_id',
      'is_canonical_agent_id',
      'is_canonical_approval_id',
      'is_canonical_base64url',
      'is_canonical_commerce_session_id',
      'is_canonical_display_name',
      'is_canonical_endpoint_origin',
      'is_canonical_endpoint_path',
      'is_canonical_evidence_id',
      'is_canonical_exposure_total',
      'is_canonical_grant_id',
      'is_canonical_hex64',
      'is_canonical_identifier',
      'is_canonical_listing_id',
      'is_canonical_listing_version',
      'is_canonical_org_id',
      'is_canonical_policy_id',
      'is_canonical_policy_revision',
      'is_canonical_provider_id',
      'is_canonical_requirement_id',
      'is_canonical_reservation_id',
      'is_canonical_sha256_digest',
      'is_canonical_source_kind',
      'is_canonical_uint256',
      'is_canonical_uint256_positive',
      'is_canonical_uuid_v4',
      'is_evidence_kind_source_allowed',
      'is_evidence_payload_secret_free',
      'is_evidence_subject_id',
      'is_evidence_text_secret_free',
      'is_js_trimmed_text',
      'is_positive_uint256',
      'is_valid_endpoint_contract',
      'is_valid_evidence_limitations',
      'is_valid_evidence_normalized',
      'is_valid_listing_availability',
      'is_valid_listing_content',
      'is_valid_listing_manifest',
      'is_valid_listing_price',
      'is_valid_policy_approval',
      'is_valid_policy_content',
      'is_valid_policy_listing_list',
      'is_valid_policy_provider_list',
      'is_valid_receipt_contract',
      'issue_authorization_grant',
      'issue_authorization_grant_core',
      'issue_commerce_session',
      'js_length',
      'list_agent_credentials',
      'list_commerce_actions',
      'list_commerce_approvals',
      'list_commerce_sessions',
      'list_evidence_facts',
      'list_market_providers',
      'list_policy_revisions',
      'list_policy_roots',
      'list_provider_credentials',
      'list_public_listings',
      'lock_action_commerce',
      'lock_action_commerce_state',
      'lock_action_decide_preamble',
      'lock_action_decision_chain',
      'lock_action_human',
      'lock_action_listing',
      'lock_action_reader',
      'lock_commerce_human',
      'lock_commerce_reader',
      'lock_commerce_writer',
      'lock_credential_issuer',
      'lock_grant_commerce_chain',
      'lock_grant_provider_chain',
      'lock_grant_provider_identity',
      'lock_lifecycle_writer',
      'lock_market_actor',
      'lock_membership_set',
      'lock_moderator_actor',
      'lock_policy_actor',
      'lock_policy_reader',
      'lock_policy_writer',
      'payment_attempt_binding_digest',
      'persist_payment_attempt',
      'read_agent_commerce_action',
      'read_agent_commerce_action_mutation_status',
      'read_agent_commerce_session_mutation_status',
      'read_agent_credential_mutation_status',
      'read_agent_grant_mutation_status',
      'read_agent_mutation_status',
      'read_agent_payment_attempt',
      'read_agent_session',
      'read_authorization_grant',
      'read_commerce_action',
      'read_commerce_approval',
      'read_commerce_approval_by_id',
      'read_commerce_exposure',
      'read_commerce_session',
      'read_commerce_session_by_token',
      'read_evidence_facts_by_subject',
      'read_human_commerce_action_mutation_status',
      'read_human_commerce_session_mutation_status',
      'read_human_grant_mutation_status',
      'read_lifecycle_mutation_status',
      'read_market_mutation_status',
      'read_organization_mutation_status',
      'read_owner_listing',
      'read_owner_listing_version',
      'read_owner_listing_versions',
      'read_owner_listings',
      'read_policy_mutation_status',
      'read_policy_revision',
      'read_policy_root',
      'read_provider_credential_mutation_status',
      'read_provider_grant_attempt_status',
      'read_provider_session',
      'read_tenant_mutation_status',
      'record_evidence_fact',
      'record_payment_attempt_dispatch',
      'record_payment_attempt_observation',
      'register_verified_commerce_requirement',
      'register_verified_commerce_requirement_core',
      'replace_authorization_grant',
      'replace_authorization_grant_core',
      'reservation_releasable',
      'resolve_action_reader_org',
      'resolve_agent_session_context',
      'resolve_commerce_action_context',
      'resolve_commerce_requirement',
      'reviewed_endpoint_digest',
      'revoke_agent_session',
      'revoke_authorization_grant',
      'revoke_commerce_session',
      'revoke_provider_session',
      'verified_requirement_digest',
    ]);
    expect(helpers.rows.every((row) => row.owner === 'openarc_migrator')).toBe(true);
    const identities = await admin.query<{ proname: string; args: string; prosecdef: boolean; config: string[] }>(
      `SELECT p.proname,
              pg_get_function_identity_arguments(p.oid) AS args,
              p.prosecdef,
              coalesce(p.proconfig, ARRAY[]::text[]) AS config
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'openarc_durable' AND p.prokind = 'f'
          AND p.proname IN ('claim_outbox_jobs', 'complete_outbox_job', 'fail_outbox_job')
        ORDER BY p.proname`,
    );
    expect(identities.rows).toEqual([
      {
        proname: 'claim_outbox_jobs',
        args: 'claim_limit integer',
        prosecdef: true,
        config: ['search_path=pg_catalog'],
      },
      {
        proname: 'complete_outbox_job',
        args: 'target_event_id uuid, expected_generation bigint',
        prosecdef: true,
        config: ['search_path=pg_catalog'],
      },
      {
        proname: 'fail_outbox_job',
        args: 'target_event_id uuid, expected_generation bigint, failure_code text',
        prosecdef: true,
        config: ['search_path=pg_catalog'],
      },
    ]);
    const triggers = await admin.query<{ tgname: string }>(
      `SELECT t.tgname
         FROM pg_trigger t
         JOIN pg_class c ON c.oid = t.tgrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'openarc_durable' AND NOT t.tgisinternal
        ORDER BY t.tgname`,
    );
    expect(triggers.rows.map((row) => row.tgname)).toEqual([
      'audit_events_append_only',
      'authorization_grant_claims_immutable',
      'authorization_grant_claims_payment_attempt',
      'authorization_grant_tokens_mutation',
      'authorization_grants_mutation',
      'budget_events_immutable',
      'budget_reservations_mutation',
      'budget_reservations_payment_exposure',
      'commerce_actions_mutation',
      'commerce_actions_payment_exposure',
      'commerce_approvals_mutation',
      'commerce_requirement_references_immutable',
      'commerce_requirement_references_verified',
      'commerce_session_handoffs_mutation',
      'commerce_session_handoffs_window',
      'commerce_sessions_binding',
      'commerce_sessions_mutation',
      'evidence_facts_append_only',
      'evidence_facts_insert_digest',
      'evidence_facts_no_truncate',
      'idempotency_records_immutable',
      'outbox_events_no_delete',
      'payment_attempts_mutation',
    ]);
  });

  it('forces RLS on all three durable tables', async () => {
    const rls = await admin.query<{ relname: string; forced: boolean }>(
      `SELECT c.relname, c.relforcerowsecurity AS forced
         FROM pg_class c
         JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'openarc_durable' AND c.relkind = 'r'
        ORDER BY c.relname`,
    );
    expect(rls.rows.map((row) => row.relname)).toEqual([
      'agent_credentials',
      'agent_sessions',
      'audit_events',
      'authorization_grant_claims',
      'authorization_grant_tokens',
      'authorization_grants',
      'budget_events',
      'budget_reservations',
      'commerce_actions',
      'commerce_approvals',
      'commerce_exposure_locks',
      'commerce_requirement_references',
      'commerce_session_handoffs',
      'commerce_sessions',
      'evidence_facts',
      'idempotency_records',
      'outbox_events',
      'payment_attempts',
      'provider_credentials',
      'provider_sessions',
    ]);
    expect(rls.rows.every((row) => row.forced)).toBe(true);
  });

  it('initializes and re-checks readiness for both restricted roles', async () => {
    await store.initialize();
    await store.readiness();
    await outbox.initialize();
    await outbox.readiness();
    assertPoolContextReleased(tenant);
    assertPoolContextReleased(worker);
  });

  it('denies the tenant role worker helpers and the worker role durable CRUD', async () => {
    await expect(
      tenant.query('SELECT * FROM openarc_durable.claim_outbox_jobs(1)'),
    ).rejects.toBeTruthy();
    await expect(
      worker.query('SELECT * FROM openarc_durable.idempotency_records'),
    ).rejects.toBeTruthy();
    await expect(
      worker.query('SELECT * FROM openarc_durable.audit_events'),
    ).rejects.toBeTruthy();
    await expect(
      worker.query('SELECT * FROM openarc_durable.outbox_events'),
    ).rejects.toBeTruthy();
  });

  it('denies durable DDL and auth-table access to both roles', async () => {
    await expect(
      tenant.query('CREATE TABLE openarc_durable.nope (id int)'),
    ).rejects.toBeTruthy();
    await expect(
      worker.query('CREATE TABLE openarc_durable.nope (id int)'),
    ).rejects.toBeTruthy();
    await expect(worker.query('SELECT * FROM openarc_auth.sessions')).rejects.toBeTruthy();
  });
});

describe('outbox readiness effective privilege and helper shape', () => {
  it('rejects a direct auth SELECT granted to the worker role', async () => {
    await admin.query('GRANT SELECT ON openarc_auth.accounts TO openarc_worker_app');
    try {
      await expect(outbox.readiness()).rejects.toMatchObject({
        code: 'OUTBOX_STORE_UNAVAILABLE',
      });
    } finally {
      await admin.query('REVOKE SELECT ON openarc_auth.accounts FROM openarc_worker_app');
    }
    await expect(outbox.readiness()).resolves.toBeUndefined();
  });

  it('rejects durable access relayed through an ordinary intermediary role', async () => {
    await admin.query('DROP ROLE IF EXISTS openarc_worker_helper');
    await admin.query(
      'CREATE ROLE openarc_worker_helper NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS',
    );
    await admin.query('GRANT SELECT ON openarc_durable.outbox_events TO openarc_worker_helper');
    await admin.query('GRANT openarc_worker_helper TO openarc_worker_app');
    try {
      await expect(outbox.readiness()).rejects.toMatchObject({
        code: 'OUTBOX_STORE_UNAVAILABLE',
      });
    } finally {
      await admin
        .query('REVOKE openarc_worker_helper FROM openarc_worker_app')
        .catch(() => {});
      await admin.query('DROP OWNED BY openarc_worker_helper').catch(() => {});
      await admin.query('DROP ROLE IF EXISTS openarc_worker_helper').catch(() => {});
    }
    await expect(outbox.readiness()).resolves.toBeUndefined();
  });

  it('rejects PUBLIC EXECUTE granted on a worker helper', async () => {
    await admin.query(
      'GRANT EXECUTE ON FUNCTION openarc_durable.complete_outbox_job(uuid, bigint) TO PUBLIC',
    );
    try {
      await expect(outbox.readiness()).rejects.toMatchObject({
        code: 'OUTBOX_STORE_UNAVAILABLE',
      });
    } finally {
      await admin.query(
        'REVOKE EXECUTE ON FUNCTION openarc_durable.complete_outbox_job(uuid, bigint) FROM PUBLIC',
      );
    }
    await expect(outbox.readiness()).resolves.toBeUndefined();
  });

  it('rejects an overloaded wrong-signature worker helper', async () => {
    await admin.query(
      `CREATE FUNCTION openarc_durable.complete_outbox_job(target_event_id uuid) RETURNS boolean
       LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS $$ SELECT false $$`,
    );
    try {
      await expect(outbox.readiness()).rejects.toMatchObject({
        code: 'OUTBOX_STORE_UNAVAILABLE',
      });
    } finally {
      await admin.query('DROP FUNCTION openarc_durable.complete_outbox_job(uuid)');
    }
    // The exact intended helper remains callable only by the worker role.
    await expect(outbox.readiness()).resolves.toBeUndefined();
    const [claimed] = await outbox.claim({ limit: 1 });
    expect(claimed).toBeUndefined();
  });
});

describe('durable agent create atomicity', () => {
  it('commits the agent, idempotency, audit and outbox together', async () => {
    const owner = await seedOwner(1);
    const result = await store.createAgentDurably(owner.hash, owner.org, 'Durable Agent', {
      idempotencyKey: base64Key(1),
      mutationId: mutationId(1),
    });
    expect(result.replayed).toBe(false);
    expect(result.receipt.resourceType).toBe('agent');
    expect(result.receipt.operation).toBe('tenant.agent.create');
    expect(result.receipt.committedAt.endsWith('Z')).toBe(true);
    expect(await counts()).toEqual({ agents: 1, idem: 1, audit: 1, outbox: 1 });
    assertPoolContextReleased(tenant);
  });

  it('rolls back everything when the audit insert fails', async () => {
    const owner = await seedOwner(2);
    // A trigger on audit that raises for this transaction's org forces failure
    // after the agent and idempotency inserts have run.
    await admin.query(
      `CREATE OR REPLACE FUNCTION openarc_durable.test_fail_audit() RETURNS trigger
       LANGUAGE plpgsql SET search_path = pg_catalog AS $$
       BEGIN RAISE EXCEPTION 'injected_audit_failure' USING ERRCODE = '23514'; END; $$`,
    );
    await admin.query(
      'CREATE TRIGGER test_fail_audit BEFORE INSERT ON openarc_durable.audit_events FOR EACH ROW EXECUTE FUNCTION openarc_durable.test_fail_audit()',
    );
    await expectCode(
      store.createAgentDurably(owner.hash, owner.org, 'Blocked', {
        idempotencyKey: base64Key(2),
        mutationId: mutationId(2),
      }),
      'TENANT_STORE_INPUT_INVALID',
    );
    await admin.query('DROP TRIGGER test_fail_audit ON openarc_durable.audit_events');
    await admin.query('DROP FUNCTION openarc_durable.test_fail_audit()');
    expect(await counts()).toEqual({ agents: 0, idem: 0, audit: 0, outbox: 0 });
    assertPoolContextReleased(tenant);
  });

  it('rolls back everything when the outbox insert fails', async () => {
    const owner = await seedOwner(3);
    await admin.query(
      `CREATE OR REPLACE FUNCTION openarc_durable.test_fail_outbox() RETURNS trigger
       LANGUAGE plpgsql SET search_path = pg_catalog AS $$
       BEGIN RAISE EXCEPTION 'injected_outbox_failure' USING ERRCODE = '23514'; END; $$`,
    );
    await admin.query(
      'CREATE TRIGGER test_fail_outbox BEFORE INSERT ON openarc_durable.outbox_events FOR EACH ROW EXECUTE FUNCTION openarc_durable.test_fail_outbox()',
    );
    await expectCode(
      store.createAgentDurably(owner.hash, owner.org, 'Blocked', {
        idempotencyKey: base64Key(3),
        mutationId: mutationId(3),
      }),
      'TENANT_STORE_INPUT_INVALID',
    );
    await admin.query('DROP TRIGGER test_fail_outbox ON openarc_durable.outbox_events');
    await admin.query('DROP FUNCTION openarc_durable.test_fail_outbox()');
    expect(await counts()).toEqual({ agents: 0, idem: 0, audit: 0, outbox: 0 });
    assertPoolContextReleased(tenant);
  });
});

describe('durable idempotency and conflict', () => {
  it('replays the same key/digest/mutation without a second action', async () => {
    const owner = await seedOwner(10);
    const first = await store.createAgentDurably(owner.hash, owner.org, 'Agent', {
      idempotencyKey: base64Key(10),
      mutationId: mutationId(10),
    });
    const replay = await store.createAgentDurably(owner.hash, owner.org, 'Agent', {
      idempotencyKey: base64Key(10),
      mutationId: mutationId(10),
    });
    expect(first.replayed).toBe(false);
    expect(replay.replayed).toBe(true);
    expect(replay.receipt).toEqual(first.receipt);
    expect(await counts()).toEqual({ agents: 1, idem: 1, audit: 1, outbox: 1 });
  });

  it('parses the same key twice in parallel into exactly one action', async () => {
    const owner = await seedOwner(11);
    const attempt = () =>
      store
        .createAgentDurably(owner.hash, owner.org, 'Agent', {
          idempotencyKey: base64Key(11),
          mutationId: mutationId(11),
        })
        .catch((error: unknown) => error);
    const outcomes = await Promise.all([attempt(), attempt()]);
    const successes = outcomes.filter((outcome) => {
      const code = (outcome as { code?: string }).code;
      return code === undefined;
    });
    expect(successes.length).toBeGreaterThanOrEqual(1);
    expect(await counts()).toMatchObject({ agents: 1, idem: 1, audit: 1, outbox: 1 });
  });

  it('conflicts on a changed digest/display name for the same key', async () => {
    const owner = await seedOwner(12);
    await store.createAgentDurably(owner.hash, owner.org, 'Original', {
      idempotencyKey: base64Key(12),
      mutationId: mutationId(12),
    });
    await expectCode(
      store.createAgentDurably(owner.hash, owner.org, 'Changed', {
        idempotencyKey: base64Key(12),
        mutationId: mutationId(12),
      }),
      'TENANT_STORE_IDEMPOTENCY_CONFLICT',
    );
    expect(await counts()).toEqual({ agents: 1, idem: 1, audit: 1, outbox: 1 });
  });

  it('conflicts on a reused mutation id with a different key', async () => {
    const owner = await seedOwner(13);
    await store.createAgentDurably(owner.hash, owner.org, 'Agent', {
      idempotencyKey: base64Key(13),
      mutationId: mutationId(13),
    });
    await expectCode(
      store.createAgentDurably(owner.hash, owner.org, 'Agent', {
        idempotencyKey: base64Key(14),
        mutationId: mutationId(13),
      }),
      'TENANT_STORE_IDEMPOTENCY_CONFLICT',
    );
    expect(await counts()).toEqual({ agents: 1, idem: 1, audit: 1, outbox: 1 });
  });

  it('isolates cross-organization changes to the same key', async () => {
    const a = await seedOwner(14);
    const b = await seedOwner(15);
    await store.createAgentDurably(a.hash, a.org, 'Agent A', {
      idempotencyKey: base64Key(15),
      mutationId: mutationId(15),
    });
    const result = await store.createAgentDurably(b.hash, b.org, 'Agent B', {
      idempotencyKey: base64Key(15),
      mutationId: mutationId(16),
    });
    expect(result.replayed).toBe(false);
    expect(await counts()).toEqual({ agents: 2, idem: 2, audit: 2, outbox: 2 });
  });
});

describe('durable authorization and status', () => {
  it('denies a viewer and a provider role', async () => {
    const owner = await seedOwner(20);
    const viewer = await seedAccount(21);
    const viewerHash = await seedSession(21, viewer);
    await seedMembership(owner.org, viewer, 'viewer');
    await expectCode(
      store.createAgentDurably(viewerHash, owner.org, 'Nope', {
        idempotencyKey: base64Key(20),
        mutationId: mutationId(20),
      }),
      'TENANT_STORE_FORBIDDEN',
    );
    await expectCode(
      store.getAgentMutationStatus(viewerHash, owner.org, mutationId(20)),
      'TENANT_STORE_FORBIDDEN',
    );
    expect(await counts()).toEqual({ agents: 0, idem: 0, audit: 0, outbox: 0 });
  });

  it('lets an operator create and recover status after session rotation', async () => {
    const owner = await seedOwner(22);
    const operator = await seedAccount(23);
    const operatorHash = await seedSession(23, operator);
    await seedMembership(owner.org, operator, 'operator');
    const created = await store.createAgentDurably(operatorHash, owner.org, 'Op Agent', {
      idempotencyKey: base64Key(22),
      mutationId: mutationId(22),
    });
    await admin.query('DELETE FROM openarc_auth.sessions WHERE token_hash = $1', [operatorHash]);
    const newHash = await seedSession(24, operator);
    const status = await store.getAgentMutationStatus(newHash, owner.org, mutationId(22));
    expect(status.status).toBe('committed');
    if (status.status === 'committed') {
      expect(status.receipt).toEqual(created.receipt);
    }
    // The rotated session can look up status but a retry with the old context is
    // a conflict, not a replacement mutation.
    await expectCode(
      store.createAgentDurably(newHash, owner.org, 'Op Agent', {
        idempotencyKey: base64Key(22),
        mutationId: mutationId(22),
      }),
      'TENANT_STORE_IDEMPOTENCY_CONFLICT',
    );
    expect(await counts()).toEqual({ agents: 1, idem: 1, audit: 1, outbox: 1 });
  });

  it('returns not_found for another account mutation without details', async () => {
    const a = await seedOwner(25);
    const b = await seedOwner(26);
    await store.createAgentDurably(a.hash, a.org, 'Agent A', {
      idempotencyKey: base64Key(25),
      mutationId: mutationId(25),
    });
    await expect(
      store.getAgentMutationStatus(b.hash, b.org, mutationId(25)),
    ).resolves.toEqual({ status: 'not_found' });
  });

  it('serializes through the same organization row as the existing bridge', async () => {
    const owner = await seedOwner(27);
    const blocker = await admin.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query(
        'SELECT 1 FROM openarc_tenant.organizations WHERE organization_id = $1 FOR UPDATE',
        [owner.org],
      );
      const pending = store.createAgentDurably(owner.hash, owner.org, 'Serialized', {
        idempotencyKey: base64Key(27),
        mutationId: mutationId(27),
      });
      await waitForLockWait();
      await blocker.query('COMMIT');
      const result = await pending;
      expect(result.replayed).toBe(false);
      expect(result.receipt.mutationId).toBe(mutationId(27));
    } finally {
      await blocker.query('ROLLBACK').catch(() => {});
      blocker.release();
    }
    expect(await counts()).toEqual({ agents: 1, idem: 1, audit: 1, outbox: 1 });
    assertPoolContextReleased(tenant);
  });

  it('rejects a revoked session through the raw bridge', async () => {
    const owner = await seedOwner(28);
    await admin.query('DELETE FROM openarc_auth.sessions WHERE token_hash = $1', [owner.hash]);
    await expectPgError(
      tenant.query('SELECT * FROM openarc_durable.read_agent_mutation_status($1, $2, $3::uuid)', [
        owner.hash,
        owner.org,
        mutationId(28),
      ]),
      '28000',
    );
  });
});

describe('durable conflict-forwarding and canaries', () => {
  it('reports OUTCOME_UNKNOWN on a lost COMMIT then recovers via status', async () => {
    const owner = await seedOwner(30);
    const observed: { committedThenThrew: boolean } = { committedThenThrew: false };
    const wrapper = {
      async connect() {
        const client = await tenant.connect();
        const originalQuery = client.query.bind(client);
        const wrapped = Object.create(client) as PoolClient;
        wrapped.query = (async (text: string, values?: unknown[]) => {
          if (typeof text === 'string' && text === 'COMMIT' && !observed.committedThenThrew) {
            await originalQuery(text, values);
            observed.committedThenThrew = true;
            throw new Error('lost commit reply');
          }
          return originalQuery(text, values);
        }) as PoolClient['query'];
        return wrapped;
      },
    };
    const faulty = new TenantStore(wrapper as never);
    await expectCode(
      faulty.createAgentDurably(owner.hash, owner.org, 'Agent', {
        idempotencyKey: base64Key(30),
        mutationId: mutationId(30),
      }),
      'TENANT_STORE_OUTCOME_UNKNOWN',
    );
    expect(observed.committedThenThrew).toBe(true);
    // No automatic replay: the durable action exists exactly once and status
    // independently recovers the original receipt.
    const status = await store.getAgentMutationStatus(owner.hash, owner.org, mutationId(30));
    expect(status.status).toBe('committed');
    expect(await counts()).toEqual({ agents: 1, idem: 1, audit: 1, outbox: 1 });
  });

  it('stores no raw key or display-name canary in durable cells', async () => {
    const owner = await seedOwner(31);
    const key = base64Key(31);
    const canaryName = 'CanaryNameXYZ';
    await store.createAgentDurably(owner.hash, owner.org, canaryName, {
      idempotencyKey: key,
      mutationId: mutationId(31),
    });
    const keyHash = digestIdempotencyKey(key);
    const sessionDigest = digestSessionContext(owner.hash);
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
    expect(blob).not.toContain(canaryName);
    expect(blob).toContain(keyHash);
    expect(blob).toContain(sessionDigest);
    // The authorized agent profile name remains the only location of the name.
    const profile = await admin.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM openarc_tenant.agents WHERE display_name = $1',
      [canaryName],
    );
    expect(profile.rows[0]?.n).toBe(1);
  });
});

describe('durable immutable rows and privilege denial', () => {
  it('rejects runtime edits to committed idempotency rows and audit/outbox', async () => {
    const owner = await seedOwner(40);
    await store.createAgentDurably(owner.hash, owner.org, 'Agent', {
      idempotencyKey: base64Key(40),
      mutationId: mutationId(40),
    });
    // The runtime has NO direct durable DML privilege: a committed receipt
    // cannot be rewritten (or a forged one inserted) outside the coupled
    // definer helper. This closes the pending-only/forged-committed bypass.
    await expect(
      tenant.query(
        "UPDATE openarc_durable.idempotency_records SET status = 'pending' WHERE organization_id = $1",
        [owner.org],
      ),
    ).rejects.toBeTruthy();
    const stored = await admin.query<{ status: string }>(
      'SELECT status FROM openarc_durable.idempotency_records WHERE organization_id = $1',
      [owner.org],
    );
    expect(stored.rows[0]?.status).toBe('committed');
    // Audit has no runtime UPDATE privilege at all.
    await expect(
      tenant.query('UPDATE openarc_durable.audit_events SET outcome = $1', ['pending']),
    ).rejects.toBeTruthy();
    // The immutable trigger is the last line behind RLS: even the migrator
    // cannot rewrite the identity/context of a committed record.
    await expect(
      admin.query(
        "UPDATE openarc_durable.idempotency_records SET actor_account_id = $1 WHERE organization_id = $2",
        [accountId(999), owner.org],
      ),
    ).rejects.toBeTruthy();
  });

  it('rejects a direct tenant insert that claims another actor', async () => {
    const owner = await seedOwner(41);
    await expect(
      tenant.query(
        `INSERT INTO openarc_durable.audit_events
           (organization_id, actor_account_id, operation, mutation_id, resource_type, resource_id, outcome)
         VALUES ($1, $2, 'tenant.agent.create', $3::uuid, 'agent', $4, 'committed')`,
        [owner.org, accountId(999), mutationId(41), agentId(41)],
      ),
    ).rejects.toBeTruthy();
    expect(await counts()).toEqual({ agents: 0, idem: 0, audit: 0, outbox: 0 });
  });
});

describe('durable direct-DML denial and receipt binding', () => {
  it('denies every direct tenant durable INSERT/UPDATE and leaves no row', async () => {
    const owner = await seedOwner(42);
    const agent = agentId(42);
    await admin.query(
      "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name) VALUES ($1, $2, 'Seeded')",
      [owner.org, agent],
    );
    const inserts = [
      `INSERT INTO openarc_durable.idempotency_records
         (organization_id, operation, key_hash, request_digest, digest_version,
          actor_account_id, session_context_digest, network, mutation_id, status)
       VALUES ($1, 'tenant.agent.create', $2, $3, 'tenant.agent.create.v1',
               $4, $5, 'eip155:5042002', $6::uuid, 'pending')`,
      `INSERT INTO openarc_durable.audit_events
         (organization_id, actor_account_id, operation, mutation_id, resource_type, resource_id, outcome)
       VALUES ($1, $4, 'tenant.agent.create', $6::uuid, 'agent', $7, 'committed')`,
      `INSERT INTO openarc_durable.outbox_events
         (organization_id, mutation_id, resource_type, resource_id, event_type, payload_version)
       VALUES ($1, $6::uuid, 'agent', $7, 'tenant.agent.created', 1)`,
    ];
    for (const sql of inserts) {
      await expect(
        tenant.query(sql, [
          owner.org,
          sha256('direct-key'),
          sha256('direct-digest'),
          owner.account,
          sha256('direct-session'),
          mutationId(42),
          agent,
        ]),
      ).rejects.toBeTruthy();
    }
    await expect(
      tenant.query(
        "UPDATE openarc_durable.idempotency_records SET status = 'committed' WHERE organization_id = $1",
        [owner.org],
      ),
    ).rejects.toBeTruthy();
    await expect(
      tenant.query(
        "UPDATE openarc_durable.outbox_events SET attempt_count = 5 WHERE organization_id = $1",
        [owner.org],
      ),
    ).rejects.toBeTruthy();
    const durable = await admin.query<{ n: number }>(
      `SELECT (SELECT count(*)::int FROM openarc_durable.idempotency_records)
            + (SELECT count(*)::int FROM openarc_durable.audit_events)
            + (SELECT count(*)::int FROM openarc_durable.outbox_events) AS n`,
    );
    expect(durable.rows[0]?.n).toBe(0);
  });

  it('rejects a privileged forged audit/outbox that names a different resource or actor', async () => {
    const owner = await seedOwner(43);
    const otherAgent = agentId(44);
    await admin.query(
      "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name) VALUES ($1, $2, 'A')",
      [owner.org, agentId(43)],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name) VALUES ($1, $2, 'B')",
      [owner.org, otherAgent],
    );
    await admin.query(
      `INSERT INTO openarc_durable.idempotency_records
         (organization_id, operation, key_hash, request_digest, digest_version,
          actor_account_id, session_context_digest, network, mutation_id,
          status, resource_type, resource_id, committed_at)
       VALUES ($1, 'tenant.agent.create', $2, $3, 'tenant.agent.create.v1',
               $4, $5, 'eip155:5042002', $6::uuid, 'committed', 'agent', $7, clock_timestamp())`,
      [
        owner.org,
        sha256('forged-key'),
        sha256('forged-digest'),
        owner.account,
        sha256('forged-session'),
        mutationId(43),
        agentId(43),
      ],
    );
    // A different same-org agent must not be nameable by the child row.
    await expect(
      admin.query(
        `INSERT INTO openarc_durable.audit_events
           (organization_id, actor_account_id, operation, mutation_id, resource_type, resource_id, outcome)
         VALUES ($1, $2, 'tenant.agent.create', $3::uuid, 'agent', $4, 'committed')`,
        [owner.org, owner.account, mutationId(43), otherAgent],
      ),
    ).rejects.toBeTruthy();
    await expect(
      admin.query(
        `INSERT INTO openarc_durable.outbox_events
           (organization_id, mutation_id, resource_type, resource_id, event_type, payload_version)
         VALUES ($1, $2::uuid, 'agent', $3, 'tenant.agent.created', 1)`,
        [owner.org, mutationId(43), otherAgent],
      ),
    ).rejects.toBeTruthy();
    // A different actor must not be nameable either.
    await expect(
      admin.query(
        `INSERT INTO openarc_durable.audit_events
           (organization_id, actor_account_id, operation, mutation_id, resource_type, resource_id, outcome)
         VALUES ($1, $2, 'tenant.agent.create', $3::uuid, 'agent', $4, 'committed')`,
        [owner.org, accountId(999), mutationId(43), agentId(43)],
      ),
    ).rejects.toBeTruthy();
    const children = await admin.query<{ n: number }>(
      `SELECT (SELECT count(*)::int FROM openarc_durable.audit_events)
            + (SELECT count(*)::int FROM openarc_durable.outbox_events) AS n`,
    );
    expect(children.rows[0]?.n).toBe(0);
  });

  it('does not bind a pending receipt to dependent audit/outbox rows', async () => {
    const owner = await seedOwner(45);
    await admin.query(
      "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name) VALUES ($1, $2, 'Pending')",
      [owner.org, agentId(45)],
    );
    await admin.query(
      `INSERT INTO openarc_durable.idempotency_records
         (organization_id, operation, key_hash, request_digest, digest_version,
          actor_account_id, session_context_digest, network, mutation_id, status)
       VALUES ($1, 'tenant.agent.create', $2, $3, 'tenant.agent.create.v1',
               $4, $5, 'eip155:5042002', $6::uuid, 'pending')`,
      [
        owner.org,
        sha256('pending-key'),
        sha256('pending-digest'),
        owner.account,
        sha256('pending-session'),
        mutationId(45),
      ],
    );
    await expect(
      admin.query(
        `INSERT INTO openarc_durable.audit_events
           (organization_id, actor_account_id, operation, mutation_id, resource_type, resource_id, outcome)
         VALUES ($1, $2, 'tenant.agent.create', $3::uuid, 'agent', $4, 'committed')`,
        [owner.org, owner.account, mutationId(45), agentId(45)],
      ),
    ).rejects.toBeTruthy();
    await expect(
      admin.query(
        `INSERT INTO openarc_durable.outbox_events
           (organization_id, mutation_id, resource_type, resource_id, event_type, payload_version)
         VALUES ($1, $2::uuid, 'agent', $3, 'tenant.agent.created', 1)`,
        [owner.org, mutationId(45), agentId(45)],
      ),
    ).rejects.toBeTruthy();
    const children = await admin.query<{ n: number }>(
      `SELECT (SELECT count(*)::int FROM openarc_durable.audit_events)
            + (SELECT count(*)::int FROM openarc_durable.outbox_events) AS n`,
    );
    expect(children.rows[0]?.n).toBe(0);
  });
});

describe('outbox worker claim and acknowledgement', () => {
  it('claims disjoint events across two workers with a 30s lease', async () => {
    const owner = await seedOwner(50);
    for (let index = 0; index < 4; index += 1) {
      await seedOutboxEvent(50 + index, { org: owner.org });
    }
    const before = Date.now();
    const first = await outbox.claim({ limit: 2 });
    const second = await outbox.claim({ limit: 2 });
    expect(first).toHaveLength(2);
    expect(second).toHaveLength(2);
    const ids = new Set([...first, ...second].map((event) => event.eventId));
    expect(ids.size).toBe(4);
    for (const event of first) {
      const lease = new Date(event.leaseUntil).getTime();
      expect(lease - before).toBeGreaterThan(25_000);
      expect(lease - before).toBeLessThanOrEqual(35_000);
      expect(event.attemptCount).toBe(1);
      expect(event.leaseGeneration).toBe('1');
    }
    assertPoolContextReleased(worker);
  });

  it('exhausts attempts, reclaims with a new generation, and dead-letters', async () => {
    const owner = await seedOwner(51);
    const eventId = await seedOutboxEvent(51, { org: owner.org, attempts: 4 });

    // Four prior attempts are already recorded. The fifth claim can retry once
    // more, and a terminal invalid_event moves the job to dead_letter.
    const [claimed] = await outbox.claim({ limit: 1 });
    expect(claimed?.eventId).toBe(eventId);
    expect(claimed?.attemptCount).toBe(5);
    const result = await outbox.fail(eventId, claimed?.leaseGeneration ?? '0', 'invalid_event');
    expect(result.applied).toBe(true);
    const row = await admin.query<{ state: string; attempt_count: number; last_failure_code: string }>(
      'SELECT state, attempt_count, last_failure_code FROM openarc_durable.outbox_events WHERE event_id = $1',
      [eventId],
    );
    expect(row.rows[0]).toEqual({
      state: 'dead_letter',
      attempt_count: 5,
      last_failure_code: 'invalid_event',
    });
    // A dead-lettered row is never silently vanished and never reclaimable.
    await expect(outbox.claim({ limit: 5 })).resolves.toEqual([]);
  });

  it('reclaims an expired lease, increments the fence, and rejects stale acks', async () => {
    const owner = await seedOwner(52);
    const eventId = await seedOutboxEvent(52, { org: owner.org });
    const [first] = await outbox.claim({ limit: 1 });
    if (first === undefined) throw new Error('no claim');
    // Force the lease into the past via the admin fixture.
    await admin.query(
      "UPDATE openarc_durable.outbox_events SET lease_until = now() - interval '1 second' WHERE event_id = $1",
      [eventId],
    );
    const [reclaimed] = await outbox.claim({ limit: 1 });
    expect(reclaimed?.eventId).toBe(eventId);
    expect(Number(reclaimed?.leaseGeneration)).toBe(Number(first.leaseGeneration) + 1);
    expect(reclaimed?.attemptCount).toBe(first.attemptCount + 1);
    // The old worker's acknowledgement is fenced out.
    await expect(outbox.complete(eventId, first.leaseGeneration)).resolves.toEqual({
      applied: false,
    });
    await expect(outbox.fail(eventId, first.leaseGeneration, 'handler_failed')).resolves.toEqual({
      applied: false,
    });
    // The current generation still applies.
    await expect(outbox.complete(eventId, reclaimed?.leaseGeneration ?? '0')).resolves.toEqual({
      applied: true,
    });
  });

  it('marks an expired final-attempt claim as dead_letter during maintenance', async () => {
    const owner = await seedOwner(53);
    const eventId = await seedOutboxEvent(53, {
      org: owner.org,
      state: 'leased',
      attempts: 5,
      leaseOffset: '-1 second',
      generation: 4,
    });
    await expect(outbox.claim({ limit: 5 })).resolves.toEqual([]);
    const row = await admin.query<{ state: string; last_failure_code: string }>(
      'SELECT state, last_failure_code FROM openarc_durable.outbox_events WHERE event_id = $1',
      [eventId],
    );
    expect(row.rows[0]).toEqual({ state: 'dead_letter', last_failure_code: 'attempts_exhausted' });
  });

  it('leaves a durable claim available for reclaim after a crash', async () => {
    const owner = await seedOwner(54);
    const eventId = await seedOutboxEvent(54, { org: owner.org });
    const [claimed] = await outbox.claim({ limit: 1 });
    expect(claimed?.eventId).toBe(eventId);
    // The worker "crashes" without acking; the leased row is durable and not
    // re-claimable until the lease expires.
    await expect(outbox.claim({ limit: 1 })).resolves.toEqual([]);
    await admin.query(
      "UPDATE openarc_durable.outbox_events SET lease_until = now() - interval '1 second' WHERE event_id = $1",
      [eventId],
    );
    const [recovered] = await outbox.claim({ limit: 1 });
    expect(recovered?.eventId).toBe(eventId);
    expect(recovered?.attemptCount).toBe(2);
  });

  it('caps retry backoff at 60 seconds and never stores raw exceptions', async () => {
    const owner = await seedOwner(55);
    const eventId = await seedOutboxEvent(55, { org: owner.org });
    const [claimed] = await outbox.claim({ limit: 1 });
    const before = Date.now();
    await outbox.fail(eventId, claimed?.leaseGeneration ?? '0', 'dependency_unavailable');
    const row = await admin.query<{ state: string; available_at: Date; last_failure_code: string }>(
      'SELECT state, available_at, last_failure_code FROM openarc_durable.outbox_events WHERE event_id = $1',
      [eventId],
    );
    expect(row.rows[0]?.state).toBe('pending');
    expect(row.rows[0]?.last_failure_code).toBe('dependency_unavailable');
    const delay = (row.rows[0]?.available_at.getTime() ?? 0) - before;
    expect(delay).toBeGreaterThan(0);
    expect(delay).toBeLessThanOrEqual(60_000);
    // No free-form exception text column exists at all.
    const columns = await admin.query<{ column_name: string }>(
      `SELECT column_name FROM information_schema.columns
        WHERE table_schema = 'openarc_durable' AND table_name = 'outbox_events'`,
    );
    const names = columns.rows.map((column) => column.column_name);
    expect(names).not.toContain('payload');
    expect(names).not.toContain('message');
    expect(names).not.toContain('error');
  });

  it('runs without any Redis or external dispatch dependency', async () => {
    const source = await admin.query<{ blob: string }>(
      `SELECT pg_get_functiondef(p.oid) AS blob
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'openarc_durable'
          AND p.proname IN ('claim_outbox_jobs', 'complete_outbox_job', 'fail_outbox_job')`,
    );
    const forbidden = 'redis|http|://';
    expect(source.rows.every((row) => !new RegExp(forbidden, 'i').test(row.blob))).toBe(true);
  });

  it('rejects a completion whose lease expires while the row lock is held', async () => {
    const owner = await seedOwner(56);
    const eventId = await seedOutboxEvent(56, { org: owner.org });
    const [claimed] = await outbox.claim({ limit: 1 });
    if (claimed === undefined) throw new Error('no claim');
    const generation = claimed.leaseGeneration;
    // Commit a short lease BEFORE the lock barrier so the pre-wait predicate
    // still passes and the DB clock can cross expiry while the row is locked.
    await admin.query(
      "UPDATE openarc_durable.outbox_events SET lease_until = clock_timestamp() + interval '1 second' WHERE event_id = $1",
      [eventId],
    );
    const holder = await admin.connect();
    try {
      await holder.query('BEGIN');
      await holder.query(
        'SELECT 1 FROM openarc_durable.outbox_events WHERE event_id = $1 FOR UPDATE',
        [eventId],
      );
      const pending = outbox.complete(eventId, generation);
      await waitForLockWait();
      await waitUntilLeaseExpired(eventId);
      await holder.query('COMMIT');
      await expect(pending).resolves.toEqual({ applied: false });
    } finally {
      await holder.query('ROLLBACK').catch(() => {});
      holder.release();
    }
    const row = await admin.query<{ state: string; lease_generation: string }>(
      'SELECT state, lease_generation::text AS lease_generation FROM openarc_durable.outbox_events WHERE event_id = $1',
      [eventId],
    );
    expect(row.rows[0]).toEqual({ state: 'leased', lease_generation: generation });
  });

  it('rejects a failure whose lease expires while the row lock is held', async () => {
    const owner = await seedOwner(57);
    const eventId = await seedOutboxEvent(57, { org: owner.org });
    const [claimed] = await outbox.claim({ limit: 1 });
    if (claimed === undefined) throw new Error('no claim');
    const generation = claimed.leaseGeneration;
    await admin.query(
      "UPDATE openarc_durable.outbox_events SET lease_until = clock_timestamp() + interval '1 second' WHERE event_id = $1",
      [eventId],
    );
    const holder = await admin.connect();
    try {
      await holder.query('BEGIN');
      await holder.query(
        'SELECT 1 FROM openarc_durable.outbox_events WHERE event_id = $1 FOR UPDATE',
        [eventId],
      );
      const pending = outbox.fail(eventId, generation, 'handler_failed');
      await waitForLockWait();
      await waitUntilLeaseExpired(eventId);
      await holder.query('COMMIT');
      await expect(pending).resolves.toEqual({ applied: false });
    } finally {
      await holder.query('ROLLBACK').catch(() => {});
      holder.release();
    }
    const row = await admin.query<{ state: string; attempt_count: number; lease_generation: string }>(
      'SELECT state, attempt_count, lease_generation::text AS lease_generation FROM openarc_durable.outbox_events WHERE event_id = $1',
      [eventId],
    );
    expect(row.rows[0]).toEqual({ state: 'leased', attempt_count: 1, lease_generation: generation });
  });

  it('does not let a locked poison event block available work during maintenance', async () => {
    const owner = await seedOwner(58);
    const poison = await seedOutboxEvent(58, {
      org: owner.org,
      state: 'leased',
      attempts: 5,
      leaseOffset: '-1 second',
      generation: 4,
    });
    const available = await seedOutboxEvent(59, { org: owner.org });
    const holder = await admin.connect();
    try {
      await holder.query('BEGIN');
      await holder.query(
        'SELECT 1 FROM openarc_durable.outbox_events WHERE event_id = $1 FOR UPDATE',
        [poison],
      );
      // The available job must be returned without waiting on the locked
      // poison row: maintenance selects candidates with SKIP LOCKED.
      const claimed = await outbox.claim({ limit: 5 });
      expect(claimed.map((event) => event.eventId)).toEqual([available]);
      await holder.query('COMMIT');
    } finally {
      await holder.query('ROLLBACK').catch(() => {});
      holder.release();
    }
    // A later claim dead-letters the previously skipped poison row.
    await expect(outbox.claim({ limit: 5 })).resolves.toEqual([]);
    const row = await admin.query<{ state: string; last_failure_code: string }>(
      'SELECT state, last_failure_code FROM openarc_durable.outbox_events WHERE event_id = $1',
      [poison],
    );
    expect(row.rows[0]).toEqual({ state: 'dead_letter', last_failure_code: 'attempts_exhausted' });
  });
});

describe('durable status and replay session revalidation under lock waits', () => {
  it('revalidates the held session when status waits on the organization lock', async () => {
    const owner = await seedOwner(60);
    const created = await store.createAgentDurably(owner.hash, owner.org, 'Agent', {
      idempotencyKey: base64Key(60),
      mutationId: mutationId(60),
    });
    await shortenSession(owner.hash, 2);
    const blocker = await admin.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query(
        'SELECT 1 FROM openarc_tenant.organizations WHERE organization_id = $1 FOR UPDATE',
        [owner.org],
      );
      const pending = store.getAgentMutationStatus(
        owner.hash,
        owner.org,
        created.receipt.mutationId,
      );
      await waitForLockWait();
      await waitUntilSessionExpired(owner.hash);
      await blocker.query('COMMIT');
      await expectCode(pending, 'TENANT_STORE_SESSION_INVALID');
    } finally {
      await blocker.query('ROLLBACK').catch(() => {});
      blocker.release();
    }
  });

  it('revalidates the held session on the not_found status path after a wait', async () => {
    const owner = await seedOwner(61);
    await shortenSession(owner.hash, 2);
    const blocker = await admin.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query(
        'SELECT 1 FROM openarc_tenant.organizations WHERE organization_id = $1 FOR UPDATE',
        [owner.org],
      );
      const pending = store.getAgentMutationStatus(owner.hash, owner.org, mutationId(61));
      await waitForLockWait();
      await waitUntilSessionExpired(owner.hash);
      await blocker.query('COMMIT');
      await expectCode(pending, 'TENANT_STORE_SESSION_INVALID');
    } finally {
      await blocker.query('ROLLBACK').catch(() => {});
      blocker.release();
    }
  });

  it('revalidates the held session on the replay path after a receipt lock wait', async () => {
    const owner = await seedOwner(62);
    await store.createAgentDurably(owner.hash, owner.org, 'Agent', {
      idempotencyKey: base64Key(62),
      mutationId: mutationId(62),
    });
    await shortenSession(owner.hash, 2);
    const blocker = await admin.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query(
        `SELECT 1 FROM openarc_durable.idempotency_records
          WHERE organization_id = $1 AND mutation_id = $2::uuid FOR UPDATE`,
        [owner.org, mutationId(62)],
      );
      const pending = store.createAgentDurably(owner.hash, owner.org, 'Agent', {
        idempotencyKey: base64Key(62),
        mutationId: mutationId(62),
      });
      await waitForLockWait();
      await waitUntilSessionExpired(owner.hash);
      await blocker.query('COMMIT');
      await expectCode(pending, 'TENANT_STORE_SESSION_INVALID');
    } finally {
      await blocker.query('ROLLBACK').catch(() => {});
      blocker.release();
    }
  });

  it('rejects a receipt whose session expires during the final status table-lock wait', async () => {
    const owner = await seedOwner(63);
    const created = await store.createAgentDurably(owner.hash, owner.org, 'Agent', {
      idempotencyKey: base64Key(63),
      mutationId: mutationId(63),
    });
    await shortenSession(owner.hash, 2);
    const blocker = await admin.connect();
    try {
      await blocker.query('BEGIN');
      // An ACCESS EXCLUSIVE table lock is the strongest barrier: the helper's
      // final buffered receipt SELECT cannot even take ACCESS SHARE until the
      // lock is released. The pre-read session is still live when the lookup
      // begins; it expires while the SELECT is proven waiting.
      await blocker.query(
        'LOCK TABLE openarc_durable.idempotency_records IN ACCESS EXCLUSIVE MODE',
      );
      const pending = store.getAgentMutationStatus(
        owner.hash,
        owner.org,
        created.receipt.mutationId,
      );
      await waitForLockWait();
      await waitUntilSessionExpired(owner.hash);
      await blocker.query('COMMIT');
      // The buffered row is discarded: the post-read recheck throws the fixed
      // session_invalid result, so no receipt can be returned.
      await expectCode(pending, 'TENANT_STORE_SESSION_INVALID');
      await expectPgError(
        tenant.query('SELECT * FROM openarc_durable.read_agent_mutation_status($1, $2, $3::uuid)', [
          owner.hash,
          owner.org,
          created.receipt.mutationId,
        ]),
        '28000',
      );
    } finally {
      await blocker.query('ROLLBACK').catch(() => {});
      blocker.release();
    }
  });

  it('revalidates the not_found status path after a final table-lock wait', async () => {
    const owner = await seedOwner(64);
    await shortenSession(owner.hash, 2);
    const blocker = await admin.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query(
        'LOCK TABLE openarc_durable.idempotency_records IN ACCESS EXCLUSIVE MODE',
      );
      const pending = store.getAgentMutationStatus(owner.hash, owner.org, mutationId(64));
      await waitForLockWait();
      await waitUntilSessionExpired(owner.hash);
      await blocker.query('COMMIT');
      await expectCode(pending, 'TENANT_STORE_SESSION_INVALID');
    } finally {
      await blocker.query('ROLLBACK').catch(() => {});
      blocker.release();
    }
  });
});

/**
 * Guard against a queue-jamming projection gap: one outbox row the store cannot
 * project fails the WHOLE claim batch, permanently. The permitted
 * (resource_type, event_type) set is read from the migrated CHECK constraints,
 * so a migration that adds an event type fails this suite until
 * OutboxStore projects it.
 */
describe('outbox store projects every DB-permitted event pair', () => {
  it('claims and completes a row for each pair the outbox CHECK constraints permit', async () => {
    const pairs = await readPermittedOutboxEventPairs(admin);
    expect(pairs.length).toBeGreaterThanOrEqual(32);
    expect(pairs.map(outboxPairKey)).toEqual(
      expect.arrayContaining([
        'authorization_grant|control.grant.issued',
        'authorization_grant|control.grant.replaced',
        'authorization_grant|control.grant.revoked',
        'authorization_grant|control.grant.claimed',
      ]),
    );
    const owner = await seedOwner(90);
    await outbox.initialize();
    const unprojectable: string[] = [];
    for (const [index, pair] of pairs.entries()) {
      const eventId = await insertOutboxEventForPair(admin, owner.org, pair, index);
      try {
        const claimed = await outbox.claim({ limit: 1 });
        expect(claimed).toHaveLength(1);
        expect(claimed[0]).toMatchObject({
          eventId,
          resourceType: pair.resourceType,
          eventType: pair.eventType,
        });
        await expect(outbox.complete(eventId, claimed[0]?.leaseGeneration)).resolves.toEqual({
          applied: true,
        });
      } catch {
        unprojectable.push(outboxPairKey(pair));
        // Retire the jammed row so the remaining pairs are still exercised.
        await admin.query(
          `UPDATE openarc_durable.outbox_events
              SET state = 'completed', lease_until = NULL, completed_at = clock_timestamp()
            WHERE event_id = $1`,
          [eventId],
        );
      }
    }
    expect(unprojectable).toEqual([]);
    assertPoolContextReleased(worker);
  });
});
