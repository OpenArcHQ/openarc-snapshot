import { createHash } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import {
  CommerceSessionStore,
  ControlActionReadStore,
  ControlActionReadStoreError,
  CredentialStore,
  MarketLifecycleStore,
  MarketStore,
  createDatabasePool,
  migrate,
  reviewedEndpointDigest,
} from '../src/index.js';
import {
  adminPool,
  ensureRoles,
  migratorUrl,
  resetSchema,
  tenantUrl,
} from './postgres-fixture.js';

/**
 * PostgreSQL regressions for the DB11 bounded action/approval READ queues.
 *
 * The rows under test are produced by the privileged schema10 core helper in
 * its 'internal_fixture' mode, exactly as the schema10 suite does; the store
 * under test only ever reaches the restricted 'production' schema11 read
 * projections through the tenant runtime role. Nothing here is production
 * purchase, reservation or grant evidence.
 */

const ORIGIN = 'https://api.example.com';
const PATH = '/v1/run';

function sha256(seed: string): string {
  return createHash('sha256').update(`openarc-action-read-test:${seed}`, 'utf8').digest('hex');
}

function uuid(seed: number): string {
  return `41000000-0000-4000-8000-${String(seed).padStart(12, '0')}`;
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

function policyId(seed: number): string {
  return `openarc:policy:${uuid(seed)}`;
}

function actionId(seed: number): string {
  return `openarc:action:${uuid(seed)}`;
}

function approvalId(seed: number): string {
  return `openarc:approval:${uuid(seed)}`;
}

function reservationId(seed: number): string {
  return `openarc:reservation:${uuid(seed)}`;
}

function requirementId(seed: number): string {
  return `openarc:requirement:${uuid(seed)}`;
}

function mutationId(seed: number): string {
  return uuid(700000 + seed);
}

function actionMutation(seed: number): string {
  return uuid(850000 + seed);
}

function lookupId(seed: number): string {
  return uuid(900000 + seed);
}

function machineSessionId(seed: number): string {
  return uuid(600000 + seed);
}

function key(seed: number): string {
  return createHash('sha256').update(`action-read-key:${seed}`).digest().toString('base64url');
}

function userHandle(seed: number): string {
  return `${sha256(`handle:${seed}`).slice(0, 42)}A`;
}

const SALT = Buffer.alloc(16, 7).toString('base64url');
const DIGEST = Buffer.alloc(32, 8).toString('base64url');
const HEX_A = 'a'.repeat(64);

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

function content(): Record<string, unknown> {
  return {
    kind: 'api',
    title: 'Example API',
    description: 'A bounded description',
    manifest: {
      schemaVersion: 'openarc.listing-manifest.v1',
      inputSchemaDigest: `sha256:${'1'.repeat(64)}`,
      outputSchemaDigest: `sha256:${'2'.repeat(64)}`,
    },
    price: {
      amount: {
        schemaVersion: 'openarc.usdc-amount.v1',
        networkId: 'eip155:5042002',
        asset: 'USDC',
        atomicAmount: '1000000',
        representation: 'erc20',
        decimals: 6,
      },
      pricingModel: 'fixed',
    },
    evidenceContract: {
      schemaVersion: 'openarc.receipt-contract.v1',
      receiptType: 'receipt.v1',
      receiptSchemaDigest: `sha256:${'3'.repeat(64)}`,
      deliveryFields: ['payload', 'status'],
    },
    endpointContract: { origin: ORIGIN, path: PATH },
    termsRevision: 'terms-v1',
    privacySummary: 'We store nothing.',
    paymentLane: 'unavailable',
    availability: { status: 'available', rateLimitPerMinute: '60' },
  };
}

let admin: Pool;
let migrator: ReturnType<typeof createDatabasePool>;
let tenant: ReturnType<typeof createDatabasePool>;
let store: ControlActionReadStore;
let credentials: CredentialStore;
let commerce: CommerceSessionStore;
let market: MarketStore;
let lifecycle: MarketLifecycleStore;

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
  store = new ControlActionReadStore(tenant);
  credentials = new CredentialStore(tenant);
  commerce = new CommerceSessionStore(tenant);
  market = new MarketStore(tenant);
  lifecycle = new MarketLifecycleStore(tenant);
});

interface Owner {
  readonly account: string;
  readonly hash: string;
  readonly org: string;
}

async function seedAccount(seed: number): Promise<string> {
  const id = accountId(seed);
  await admin.query(
    "INSERT INTO openarc_auth.accounts (account_id, user_handle, status) VALUES ($1, $2, 'active')",
    [id, userHandle(seed)],
  );
  return id;
}

async function seedSession(seed: number, account: string, method = 'passkey'): Promise<string> {
  const hash = sha256(`session:${seed}`);
  await admin.query(
    `INSERT INTO openarc_auth.sessions (token_hash, account_id, method, created_at, expires_at)
     VALUES ($1, $2, $3, now(), now() + interval '24 hours')`,
    [hash, account, method],
  );
  return hash;
}

async function seedOwner(seed: number, role = 'owner'): Promise<Owner> {
  const account = await seedAccount(seed);
  const hash = await seedSession(seed, account);
  const org = orgId(seed);
  await admin.query(
    "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Org', $2)",
    [org, account],
  );
  await admin.query(
    "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, $3, 'active')",
    [org, account, role],
  );
  return { account, hash, org };
}

async function seedAgent(seed: number, org: string): Promise<string> {
  const id = agentId(seed);
  await admin.query(
    "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name, status) VALUES ($1, $2, $3, 'active')",
    [org, id, `Agent ${seed}`],
  );
  return id;
}

async function seedProvider(seed: number, org: string): Promise<string> {
  const id = providerId(seed);
  await admin.query(
    "INSERT INTO openarc_tenant.providers (organization_id, provider_id, display_name, status) VALUES ($1, $2, $3, 'active')",
    [org, id, `Provider ${seed}`],
  );
  return id;
}

async function seedPolicy(
  org: string,
  subject: string,
  seed: number,
  provider: string,
): Promise<string> {
  const id = policyId(seed);
  const client = await admin.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `INSERT INTO openarc_tenant.budget_policy_roots
         (organization_id, policy_id, subject_agent_id, current_revision, status)
       VALUES ($1, $2, $3, '1', 'active')`,
      [org, id, subject],
    );
    // Approval mode 'always' routes every authorization to a pending approval
    // that reserves NOTHING, so the read queues can be seeded with many
    // actions and approvals without any spend, grant or rolling cap effect.
    await client.query(
      `INSERT INTO openarc_tenant.budget_policy_versions
         (organization_id, policy_id, revision, subject_agent_id, network_id, asset,
          representation, decimals, per_action_limit, rolling_limit, rolling_window_seconds,
          fee_limit, allowed_provider_ids, allowed_listing_ids, approval_mode,
          approval_threshold, approval_separate_approver, expires_at, digest)
       VALUES ($1, $2, '1', $3, 'eip155:5042002', 'USDC', 'erc20', 6, '5000000', NULL, NULL,
               '0', ARRAY[$4]::text[], ARRAY[]::text[], 'always', NULL, false,
               clock_timestamp() + interval '1 hour', 'sha256:' || repeat('a', 64))`,
      [org, id, subject, provider],
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

interface Machine {
  readonly agentSessionHash: string;
}

async function seedMachine(owner: Owner, seed: number, agent: string): Promise<Machine> {
  const issued = await credentials.issueAgentCredentialDurably({
    sessionHash: owner.hash,
    organizationId: owner.org,
    profileId: agent,
    lookupId: lookupId(seed),
    hash: hashInput(),
    expiresAt: new Date(Date.now() + 30 * 60_000).toISOString(),
    metadata: { idempotencyKey: key(500000 + seed), mutationId: mutationId(500000 + seed) },
  });
  const agentSessionHash = sha256(`machine:${seed}`);
  await credentials.createAgentSession({
    organizationId: owner.org,
    profileId: agent,
    credentialId: issued.receipt.credentialId,
    expectedVersion: 1,
    sessionId: machineSessionId(seed),
    tokenHash: agentSessionHash,
    expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
  });
  return { agentSessionHash };
}

async function seedPublishedListing(owner: Owner, provider: string, seed: number): Promise<string> {
  const draft = await market.createListingDraft(owner.hash, owner.org, provider, content(), {
    idempotencyKey: key(seed),
    mutationId: mutationId(seed),
  });
  const listing = draft.receipt.resourceId;
  const digest = reviewedEndpointDigest({ listingId: listing, version: '1', origin: ORIGIN, path: PATH });
  const s0 = await admin.query<{ updated_at: string }>(
    "SELECT to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS updated_at FROM openarc_tenant.listing_version_states WHERE organization_id = $1 AND listing_id = $2 AND version = '1'",
    [owner.org, listing],
  );
  const moderatorAccount = await seedAccount(seed + 8000);
  const moderatorHash = await seedSession(seed + 8000, moderatorAccount);
  await admin.query(
    "INSERT INTO openarc_tenant.market_moderator_grants (account_id, status) VALUES ($1, 'active')",
    [moderatorAccount],
  );
  await lifecycle.recordOriginReview(
    moderatorHash,
    owner.org,
    listing,
    '1',
    {
      expectedUpdatedAt: s0.rows[0]!.updated_at,
      decision: 'approved',
      reviewedEndpointDigest: digest,
      reasonCode: 'manual_review',
      reasonDigest: null,
    },
    { idempotencyKey: key(seed + 9000), mutationId: mutationId(seed + 9000) },
  );
  const s1 = await admin.query<{ updated_at: string }>(
    "SELECT to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS updated_at FROM openarc_tenant.listing_version_states WHERE organization_id = $1 AND listing_id = $2 AND version = '1'",
    [owner.org, listing],
  );
  await lifecycle.publishListingVersion(
    owner.hash,
    owner.org,
    listing,
    '1',
    { expectedUpdatedAt: s1.rows[0]!.updated_at, expectedActiveVersion: null },
    { idempotencyKey: key(seed + 1), mutationId: mutationId(seed + 1) },
  );
  return listing;
}

interface Chain {
  readonly owner: Owner;
  readonly agent: string;
  readonly provider: string;
  readonly listing: string;
  readonly policy: string;
  readonly commerceTokenHash: string;
  readonly seed: number;
}

async function seedChain(seed: number): Promise<Chain> {
  const owner = await seedOwner(seed);
  const agent = await seedAgent(seed, owner.org);
  const provider = await seedProvider(seed, owner.org);
  const listing = await seedPublishedListing(owner, provider, seed);
  const policy = await seedPolicy(owner.org, agent, seed, provider);
  const machine = await seedMachine(owner, seed, agent);
  const handoffHash = sha256(`handoff:${seed}`);
  const commerceTokenHash = sha256(`commerce:${seed}`);
  await commerce.issueCommerceSession(
    owner.hash,
    owner.org,
    { subjectAgentId: agent, policyId: policy, handoffHash, hashVersion: 1 },
    { idempotencyKey: key(100000 + seed), mutationId: mutationId(100000 + seed) },
  );
  await commerce.exchangeCommerceSession(
    machine.agentSessionHash,
    handoffHash,
    { tokenHash: commerceTokenHash, hashVersion: 1 },
    { idempotencyKey: key(200000 + seed), mutationId: mutationId(200000 + seed) },
  );
  return { owner, agent, provider, listing, policy, commerceTokenHash, seed };
}

async function seedRequirement(chain: Chain, seed: number): Promise<string> {
  const id = requirementId(seed);
  await admin.query(
    `INSERT INTO openarc_durable.commerce_requirement_references (
       organization_id, requirement_id, seller_organization_id, provider_id, listing_id,
       listing_version, network_id, asset, representation, decimals, amount_atomic,
       fee_atomic, requirement_digest, source_kind, created_at, valid_until)
     VALUES ($1, $2, $1, $3, $4, '1', 'eip155:5042002', 'USDC', 'erc20', 6, '1000000', '0',
             'sha256:' || repeat('c', 64), 'internal_fixture', clock_timestamp(),
             clock_timestamp() + interval '30 minutes')`,
    [chain.owner.org, id, chain.provider, chain.listing],
  );
  return id;
}

/**
 * Seeds `count` actions (and, through approval mode 'always', `count` pending
 * approvals) whose ids are seeds 1..count of THIS chain's id namespace, so the
 * lexical keyset order is known exactly.
 */
async function seedActions(chain: Chain, count: number): Promise<string[]> {
  const ids: string[] = [];
  for (let index = 1; index <= count; index += 1) {
    const seed = chain.seed * 1000 + index;
    const requirement = await seedRequirement(chain, seed);
    const action = actionId(seed);
    const rawKey = key(300000 + seed);
    const keyHash = createHash('sha256').update(rawKey, 'utf8').digest('hex');
    const contextDigest = createHash('sha256')
      .update(
        `openarc.control.commerce_action.authorize.session.v1:${chain.commerceTokenHash}`,
        'utf8',
      )
      .digest('hex');
    await migrator.query(
      `SELECT * FROM openarc_durable.authorize_commerce_action_core(
         'internal_fixture', $1, $2, $3, $4::uuid, $5, $6, $7)`,
      [
        chain.commerceTokenHash,
        requirement,
        action,
        actionMutation(seed),
        keyHash,
        HEX_A,
        contextDigest,
      ],
    );
    ids.push(action);
  }
  return ids;
}

function seedsOf(chain: Chain, count: number): number[] {
  return Array.from({ length: count }, (_value, index) => chain.seed * 1000 + index + 1);
}

async function counts(): Promise<Record<string, number>> {
  const result = await admin.query<Record<string, number>>(
    `SELECT (SELECT count(*)::int FROM openarc_durable.commerce_actions) AS actions,
            (SELECT count(*)::int FROM openarc_durable.commerce_approvals) AS approvals,
            (SELECT count(*)::int FROM openarc_durable.budget_reservations) AS reservations,
            (SELECT count(*)::int FROM openarc_durable.budget_events) AS events,
            (SELECT count(*)::int FROM openarc_durable.outbox_events) AS outbox`,
  );
  return result.rows[0]!;
}

async function expectStoreCode(promise: Promise<unknown>, code: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ControlActionReadStoreError);
    expect((error as ControlActionReadStoreError).code).toBe(code);
    return;
  }
  throw new Error(`expected ControlActionReadStoreError ${code}`);
}

describe('schema11 manifest, ownership and ACLs', () => {
  it('records schema11 and keeps the runtime denied on tables and the private resolver', async () => {
    const applied = await admin.query<{ id: string }>(
      'SELECT id FROM openarc_meta.schema_migrations ORDER BY id',
    );
    expect(applied.rows.map((row) => row.id).slice(-9)).toEqual([
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
    const helpers = await admin.query<{
      proname: string;
      owner: string;
      secdef: boolean;
      config: string[];
      app_exec: boolean;
      public_exec: number;
    }>(
      `SELECT p.proname, r.rolname AS owner, p.prosecdef AS secdef,
              coalesce(p.proconfig, ARRAY[]::text[]) AS config,
              has_function_privilege('openarc_tenant_app', p.oid, 'EXECUTE') AS app_exec,
              (SELECT count(*)::int FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE') AS public_exec
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         JOIN pg_roles r ON r.oid = p.proowner
        WHERE n.nspname = 'openarc_durable'
          AND p.proname IN ('list_commerce_actions', 'list_commerce_approvals',
                            'read_commerce_approval_by_id', 'resolve_action_reader_org')
        ORDER BY p.proname`,
    );
    expect(helpers.rows).toHaveLength(4);
    for (const row of helpers.rows) {
      expect(row.owner).toBe('openarc_migrator');
      expect(row.secdef).toBe(true);
      expect(row.config).toContain('search_path=pg_catalog');
      expect(row.public_exec).toBe(0);
      expect(row.app_exec).toBe(row.proname !== 'resolve_action_reader_org');
    }
    // The runtime still holds no direct table privilege after schema11.
    await expect(
      tenant.query('SELECT count(*) FROM openarc_durable.commerce_approvals'),
    ).rejects.toMatchObject({ code: '42501' });
    await expect(
      tenant.query('SELECT openarc_durable.resolve_action_reader_org($1, $2)', [HEX_A, orgId(1)]),
    ).rejects.toMatchObject({ code: '42501' });
    await store.readiness();
    await store.initialize();
  });
});

describe('action queue paging', () => {
  it('returns a null cursor when the result is shorter than the limit', async () => {
    const chain = await seedChain(10);
    const ids = await seedActions(chain, 4);
    const page = await store.listActions(chain.owner.hash, chain.owner.org, { limit: '10' });
    expect(page.organizationId).toBe(chain.owner.org);
    expect(page.items.map((item) => item.actionId)).toEqual(ids);
    expect(page.nextCursor).toBeNull();
  });

  it('returns a null cursor when exactly the limit is returned and no page follows', async () => {
    const chain = await seedChain(11);
    const ids = await seedActions(chain, 4);
    const page = await store.listActions(chain.owner.hash, chain.owner.org, { limit: '4' });
    expect(page.items.map((item) => item.actionId)).toEqual(ids);
    expect(page.nextCursor).toBeNull();
  });

  it('returns the last id as the cursor when exactly the limit is returned and a page follows', async () => {
    const chain = await seedChain(12);
    const ids = await seedActions(chain, 5);
    const page = await store.listActions(chain.owner.hash, chain.owner.org, { limit: '3' });
    expect(page.items.map((item) => item.actionId)).toEqual(ids.slice(0, 3));
    expect(page.nextCursor).toBe(ids[2]);
  });

  it('traverses every action exactly once in ascending id order', async () => {
    const chain = await seedChain(13);
    const ids = await seedActions(chain, 7);
    const seen: string[] = [];
    let cursor: string | null = null;
    let guard = 0;
    do {
      const query: { limit: string; afterActionId?: string } = { limit: '2' };
      if (cursor !== null) query.afterActionId = cursor;
      const page = await store.listActions(chain.owner.hash, chain.owner.org, query);
      expect(page.items.length).toBeLessThanOrEqual(2);
      seen.push(...page.items.map((item) => item.actionId));
      cursor = page.nextCursor;
      guard += 1;
    } while (cursor !== null && guard < 20);
    expect(cursor).toBeNull();
    expect(seen).toEqual(ids);
    expect(new Set(seen).size).toBe(ids.length);
    // The approval queue pages under the SAME keyset contract.
    const approvalIds = seedsOf(chain, 7).map((seed) => approvalId(seed));
    const seenApprovals: string[] = [];
    let approvalCursor: string | null = null;
    let approvalGuard = 0;
    do {
      const query: { limit: string; afterApprovalId?: string } = { limit: '3' };
      if (approvalCursor !== null) query.afterApprovalId = approvalCursor;
      const page = await store.listApprovals(chain.owner.hash, chain.owner.org, query);
      expect(page.items.length).toBeLessThanOrEqual(3);
      expect(page.organizationId).toBe(chain.owner.org);
      seenApprovals.push(...page.items.map((item) => item.approvalId));
      approvalCursor = page.nextCursor;
      approvalGuard += 1;
    } while (approvalCursor !== null && approvalGuard < 20);
    expect(approvalCursor).toBeNull();
    expect(seenApprovals).toEqual(approvalIds);
    // Exactly-limit-with-a-following-page yields the last returned approval id.
    const firstApprovalPage = await store.listApprovals(chain.owner.hash, chain.owner.org, {
      limit: '3',
    });
    expect(firstApprovalPage.nextCursor).toBe(approvalIds[2]);
    // Exactly-limit-with-nothing-after yields a null cursor.
    const exactApprovalPage = await store.listApprovals(chain.owner.hash, chain.owner.org, {
      limit: '7',
    });
    expect(exactApprovalPage.items).toHaveLength(7);
    expect(exactApprovalPage.nextCursor).toBeNull();
  });

  it('applies the default limit 25 when the request omits it', async () => {
    const chain = await seedChain(14);
    const ids = await seedActions(chain, 26);
    const page = await store.listActions(chain.owner.hash, chain.owner.org);
    expect(page.items).toHaveLength(25);
    expect(page.items.map((item) => item.actionId)).toEqual(ids.slice(0, 25));
    expect(page.nextCursor).toBe(ids[24]);
    const tail = await store.listActions(chain.owner.hash, chain.owner.org, {
      afterActionId: ids[24],
    });
    expect(tail.items.map((item) => item.actionId)).toEqual([ids[25]]);
    expect(tail.nextCursor).toBeNull();
  });

  it('returns an authorized empty page with a null cursor', async () => {
    const owner = await seedOwner(15);
    const page = await store.listActions(owner.hash, owner.org, { limit: '10' });
    expect(page).toEqual({ organizationId: owner.org, items: [], nextCursor: null });
    const approvals = await store.listApprovals(owner.hash, owner.org, { limit: '10' });
    expect(approvals).toEqual({ organizationId: owner.org, items: [], nextCursor: null });
  });

  it('rejects a non-canonical limit or cursor with the fixed input error', async () => {
    const chain = await seedChain(16);
    await seedActions(chain, 2);
    for (const bad of ['0', '51', '05', ' 1', '1\n', '', '100']) {
      await expectStoreCode(
        store.listActions(chain.owner.hash, chain.owner.org, { limit: bad }),
        'CONTROL_ACTION_READ_STORE_INPUT_INVALID',
      );
      await expectStoreCode(
        store.listApprovals(chain.owner.hash, chain.owner.org, { limit: bad }),
        'CONTROL_ACTION_READ_STORE_INPUT_INVALID',
      );
    }
    for (const bad of ['openarc:action:nope', 'nope', `${actionId(1)} `, approvalId(1)]) {
      await expectStoreCode(
        store.listActions(chain.owner.hash, chain.owner.org, { afterActionId: bad }),
        'CONTROL_ACTION_READ_STORE_INPUT_INVALID',
      );
    }
    for (const bad of ['openarc:approval:nope', 'nope', actionId(1)]) {
      await expectStoreCode(
        store.listApprovals(chain.owner.hash, chain.owner.org, { afterApprovalId: bad }),
        'CONTROL_ACTION_READ_STORE_INPUT_INVALID',
      );
    }
    // The DEFINER also refuses an out-of-band limit, so the bound is not a
    // repository-only convention.
    await expect(
      migrator.query(
        'SELECT * FROM openarc_durable.list_commerce_actions($1, $2, NULL, $3::int)',
        [chain.owner.hash, chain.owner.org, 51],
      ),
    ).rejects.toMatchObject({ code: '22023' });
    await expect(
      migrator.query(
        'SELECT * FROM openarc_durable.list_commerce_actions($1, $2, NULL, $3::int)',
        [chain.owner.hash, chain.owner.org, 0],
      ),
    ).rejects.toMatchObject({ code: '22023' });
  });
});

describe('status visibility, projection and isolation', () => {
  it('returns every action and approval status with no hidden server-side filter', async () => {
    const chain = await seedChain(20);
    const ids = await seedActions(chain, 5);
    const seeds = seedsOf(chain, 5);
    // Every seeded action starts pending_approval with a pending approval;
    // advance four of them along the frozen schema10 edges as the migrator.
    await admin.query(
      `UPDATE openarc_durable.commerce_actions
          SET status = 'reserved_not_granted', reservation_id = $3, updated_at = clock_timestamp()
        WHERE organization_id = $1 AND action_id = $2`,
      [chain.owner.org, ids[1], reservationId(seeds[1]!)],
    );
    for (const [index, status] of [[2, 'rejected'], [3, 'cancelled'], [4, 'expired']] as const) {
      await admin.query(
        `UPDATE openarc_durable.commerce_actions
            SET status = $3, updated_at = clock_timestamp()
          WHERE organization_id = $1 AND action_id = $2`,
        [chain.owner.org, ids[index], status],
      );
    }
    for (const [index, status] of [[1, 'approved'], [2, 'rejected'], [3, 'expired']] as const) {
      await admin.query(
        `UPDATE openarc_durable.commerce_approvals
            SET status = $3,
                decided_by = CASE WHEN $3 = 'expired' THEN NULL ELSE $4 END,
                decided_at = CASE WHEN $3 = 'expired' THEN NULL ELSE clock_timestamp() END
          WHERE organization_id = $1 AND approval_id = $2`,
        [chain.owner.org, approvalId(seeds[index]!), status, chain.owner.account],
      );
    }
    const actions = await store.listActions(chain.owner.hash, chain.owner.org, { limit: '50' });
    expect(actions.items.map((item) => item.status)).toEqual([
      'pending_approval',
      'reserved_not_granted',
      'rejected',
      'cancelled',
      'expired',
    ]);
    const approvals = await store.listApprovals(chain.owner.hash, chain.owner.org, {
      limit: '50',
    });
    expect(approvals.items.map((item) => item.status)).toEqual([
      'pending',
      'approved',
      'rejected',
      'expired',
      'pending',
    ]);
    expect(approvals.items.map((item) => item.approvalId)).toEqual(
      seeds.map((seed) => approvalId(seed)),
    );
  });

  it('projects only protected metadata and never a private or seller-internal field', async () => {
    const chain = await seedChain(21);
    await seedActions(chain, 1);
    const actions = await store.listActions(chain.owner.hash, chain.owner.org, { limit: '5' });
    expect(Object.keys(actions).sort()).toEqual(['items', 'nextCursor', 'organizationId']);
    expect(Object.keys(actions.items[0]!).sort()).toEqual([
      'actionId',
      'amountAtomic',
      'approvalId',
      'commerceSessionId',
      'createdAt',
      'debitAtomic',
      'expiresAt',
      'exposureKey',
      'feeAtomic',
      'listingId',
      'listingVersion',
      'policyId',
      'policyRevision',
      'providerId',
      'requirementDigest',
      'requirementId',
      'reservationId',
      'schemaVersion',
      'status',
      'updatedAt',
    ]);
    expect(Object.keys(actions.items[0]!.exposureKey).sort()).toEqual([
      'asset',
      'decimals',
      'networkId',
      'organizationId',
      'representation',
      'subjectAgentId',
    ]);
    const approvals = await store.listApprovals(chain.owner.hash, chain.owner.org, { limit: '5' });
    expect(Object.keys(approvals.items[0]!).sort()).toEqual([
      'actionId',
      'approvalId',
      'commerceSessionId',
      'createdAt',
      'decidedAt',
      'decidedBy',
      'expiresAt',
      'organizationId',
      'policyId',
      'policyRevision',
      'requestedBy',
      'schemaVersion',
      'separateApprover',
      'status',
      'subjectAgentId',
    ]);
    // The stored private columns exist but are not representable on the wire.
    const stored = await admin.query<{ request_digest: string; source_kind: string; seller_organization_id: string }>(
      'SELECT request_digest, source_kind, seller_organization_id FROM openarc_durable.commerce_actions LIMIT 1',
    );
    const secret = stored.rows[0]!;
    const serialized = `${JSON.stringify(actions)}${JSON.stringify(approvals)}`;
    expect(serialized).not.toContain(secret.request_digest);
    expect(serialized).not.toContain(secret.source_kind);
    expect(serialized).not.toContain('sourceKind');
    expect(serialized).not.toContain('requestDigest');
    expect(serialized).not.toContain('sellerOrganizationId');
    expect(serialized).not.toContain(chain.commerceTokenHash);
    expect(serialized).not.toContain(chain.owner.hash);
    // Amounts stay exact canonical integer strings.
    expect(actions.items[0]!.amountAtomic).toBe('1000000');
    expect(actions.items[0]!.feeAtomic).toBe('0');
    expect(actions.items[0]!.debitAtomic).toBe('1000000');
  });

  it('never leaks another organization and denies a wrong-organization wrapper', async () => {
    const a = await seedChain(22);
    const b = await seedChain(23);
    const idsA = await seedActions(a, 3);
    const idsB = await seedActions(b, 3);
    const pageA = await store.listActions(a.owner.hash, a.owner.org, { limit: '50' });
    expect(pageA.items.map((item) => item.actionId)).toEqual(idsA);
    for (const foreign of idsB) {
      expect(pageA.items.map((item) => item.actionId)).not.toContain(foreign);
    }
    for (const item of pageA.items) {
      expect(item.exposureKey.organizationId).toBe(a.owner.org);
    }
    const approvalsA = await store.listApprovals(a.owner.hash, a.owner.org, { limit: '50' });
    for (const item of approvalsA.items) {
      expect(item.organizationId).toBe(a.owner.org);
    }
    // A caller holding no membership in the other organization is denied on
    // every DB11 surface, list and detail alike.
    await expectStoreCode(
      store.listActions(a.owner.hash, b.owner.org, { limit: '5' }),
      'CONTROL_ACTION_READ_STORE_FORBIDDEN',
    );
    await expectStoreCode(
      store.listApprovals(a.owner.hash, b.owner.org, { limit: '5' }),
      'CONTROL_ACTION_READ_STORE_FORBIDDEN',
    );
    await expectStoreCode(
      store.readApprovalById(a.owner.hash, b.owner.org, approvalId(b.seed * 1000 + 1)),
      'CONTROL_ACTION_READ_STORE_FORBIDDEN',
    );
    // An organization that does not exist at all is equally denied.
    await expectStoreCode(
      store.listActions(a.owner.hash, orgId(999), { limit: '5' }),
      'CONTROL_ACTION_READ_STORE_FORBIDDEN',
    );
  });
});

describe('current authority', () => {
  it('denies a revoked, expired or recovery human session on both queues', async () => {
    const chain = await seedChain(30);
    await seedActions(chain, 2);
    await admin.query(
      `UPDATE openarc_auth.sessions
          SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 minute'
        WHERE token_hash = $1`,
      [chain.owner.hash],
    );
    await expectStoreCode(
      store.listActions(chain.owner.hash, chain.owner.org, { limit: '5' }),
      'CONTROL_ACTION_READ_STORE_SESSION_INVALID',
    );
    await expectStoreCode(
      store.listApprovals(chain.owner.hash, chain.owner.org, { limit: '5' }),
      'CONTROL_ACTION_READ_STORE_SESSION_INVALID',
    );
    await admin.query('DELETE FROM openarc_auth.sessions WHERE token_hash = $1', [
      chain.owner.hash,
    ]);
    await expectStoreCode(
      store.listActions(chain.owner.hash, chain.owner.org, { limit: '5' }),
      'CONTROL_ACTION_READ_STORE_SESSION_INVALID',
    );
    const recovery = await seedSession(30_500, chain.owner.account, 'recovery');
    await expectStoreCode(
      store.listApprovals(recovery, chain.owner.org, { limit: '5' }),
      'CONTROL_ACTION_READ_STORE_SESSION_INVALID',
    );
  });

  it('denies a current member whose role is not owner or operator', async () => {
    const chain = await seedChain(31);
    await seedActions(chain, 2);
    const viewerAccount = await seedAccount(31_500);
    const viewerHash = await seedSession(31_500, viewerAccount);
    await admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'viewer', 'active')",
      [chain.owner.org, viewerAccount],
    );
    await expectStoreCode(
      store.listActions(viewerHash, chain.owner.org, { limit: '5' }),
      'CONTROL_ACTION_READ_STORE_FORBIDDEN',
    );
    await expectStoreCode(
      store.listApprovals(viewerHash, chain.owner.org, { limit: '5' }),
      'CONTROL_ACTION_READ_STORE_FORBIDDEN',
    );
    // An owner demoted after the rows were created loses the read too.
    await admin.query(
      "UPDATE openarc_tenant.memberships SET role = 'viewer' WHERE organization_id = $1 AND account_id = $2",
      [chain.owner.org, chain.owner.account],
    );
    await expectStoreCode(
      store.listActions(chain.owner.hash, chain.owner.org, { limit: '5' }),
      'CONTROL_ACTION_READ_STORE_FORBIDDEN',
    );
    // A suspended membership is equally denied.
    await admin.query(
      "UPDATE openarc_tenant.memberships SET role = 'owner', status = 'suspended' WHERE organization_id = $1 AND account_id = $2",
      [chain.owner.org, chain.owner.account],
    );
    await expectStoreCode(
      store.listActions(chain.owner.hash, chain.owner.org, { limit: '5' }),
      'CONTROL_ACTION_READ_STORE_FORBIDDEN',
    );
  });

  it('validates current authority on the empty and not-found paths too', async () => {
    const owner = await seedOwner(32);
    // An organization with ZERO actions and approvals still denies a revoked
    // session and a demoted member rather than returning an empty page.
    await admin.query(
      "UPDATE openarc_tenant.memberships SET role = 'viewer' WHERE organization_id = $1 AND account_id = $2",
      [owner.org, owner.account],
    );
    await expectStoreCode(
      store.listActions(owner.hash, owner.org, { limit: '5' }),
      'CONTROL_ACTION_READ_STORE_FORBIDDEN',
    );
    await expectStoreCode(
      store.readApprovalById(owner.hash, owner.org, approvalId(777)),
      'CONTROL_ACTION_READ_STORE_FORBIDDEN',
    );
    await admin.query(
      "UPDATE openarc_tenant.memberships SET role = 'owner' WHERE organization_id = $1 AND account_id = $2",
      [owner.org, owner.account],
    );
    await expect(
      store.readApprovalById(owner.hash, owner.org, approvalId(777)),
    ).resolves.toEqual({ organizationId: owner.org, approvalId: approvalId(777), item: null });
    await admin.query('DELETE FROM openarc_auth.sessions WHERE token_hash = $1', [owner.hash]);
    await expectStoreCode(
      store.readApprovalById(owner.hash, owner.org, approvalId(777)),
      'CONTROL_ACTION_READ_STORE_SESSION_INVALID',
    );
  });
});

describe('approval detail by approval id', () => {
  it('returns the exact approval for a valid id and null for an unknown id', async () => {
    const chain = await seedChain(40);
    const ids = await seedActions(chain, 3);
    const seeds = seedsOf(chain, 3);
    const target = approvalId(seeds[1]!);
    const detail = await store.readApprovalById(chain.owner.hash, chain.owner.org, target);
    expect(detail.organizationId).toBe(chain.owner.org);
    expect(detail.approvalId).toBe(target);
    expect(detail.item).not.toBeNull();
    expect(detail.item?.approvalId).toBe(target);
    expect(detail.item?.actionId).toBe(ids[1]);
    expect(detail.item?.organizationId).toBe(chain.owner.org);
    expect(detail.item?.status).toBe('pending');
    expect(detail.item?.decidedBy).toBeNull();
    expect(detail.item?.decidedAt).toBeNull();
    const missing = await store.readApprovalById(
      chain.owner.hash,
      chain.owner.org,
      approvalId(987654),
    );
    expect(missing).toEqual({
      organizationId: chain.owner.org,
      approvalId: approvalId(987654),
      item: null,
    });
    await expectStoreCode(
      store.readApprovalById(chain.owner.hash, chain.owner.org, 'openarc:approval:nope'),
      'CONTROL_ACTION_READ_STORE_INPUT_INVALID',
    );
    await expectStoreCode(
      store.readApprovalById(chain.owner.hash, chain.owner.org, ids[0]),
      'CONTROL_ACTION_READ_STORE_INPUT_INVALID',
    );
  });

  it('never returns another buyer approval and leaves the schema10 action-id reader intact', async () => {
    const a = await seedChain(41);
    const b = await seedChain(42);
    await seedActions(a, 2);
    await seedActions(b, 2);
    const foreign = approvalId(b.seed * 1000 + 1);
    // The wrong buyer is denied outright, not answered with a null item.
    await expectStoreCode(
      store.readApprovalById(a.owner.hash, b.owner.org, foreign),
      'CONTROL_ACTION_READ_STORE_FORBIDDEN',
    );
    // Asking inside the caller's OWN organization for another org's approval
    // id is a safe not-found, never a cross-tenant read.
    const scoped = await store.readApprovalById(a.owner.hash, a.owner.org, foreign);
    expect(scoped).toEqual({ organizationId: a.owner.org, approvalId: foreign, item: null });
    // DB10's action-id keyed reader is untouched and still present.
    const db10 = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'openarc_durable' AND p.proname = 'read_commerce_approval'
          AND pg_get_function_identity_arguments(p.oid) =
              'human_session_hash text, organization_id text, action_id_input text'`,
    );
    expect(db10.rows[0]?.n).toBe(1);
  });
});

describe('reads never mutate', () => {
  it('leaves action, approval, reservation, budget-event and outbox counts unchanged', async () => {
    const chain = await seedChain(50);
    const ids = await seedActions(chain, 4);
    const seeds = seedsOf(chain, 4);
    const before = await counts();
    const beforeActions = await admin.query<{ digest: string }>(
      'SELECT md5(string_agg(t::text, $1 ORDER BY t.action_id)) AS digest FROM openarc_durable.commerce_actions t',
      ['|'],
    );
    const beforeApprovals = await admin.query<{ digest: string }>(
      'SELECT md5(string_agg(t::text, $1 ORDER BY t.approval_id)) AS digest FROM openarc_durable.commerce_approvals t',
      ['|'],
    );
    await store.listActions(chain.owner.hash, chain.owner.org, { limit: '2' });
    await store.listActions(chain.owner.hash, chain.owner.org, {
      limit: '2',
      afterActionId: ids[1],
    });
    await store.listApprovals(chain.owner.hash, chain.owner.org, { limit: '50' });
    await store.readApprovalById(chain.owner.hash, chain.owner.org, approvalId(seeds[0]!));
    await store.readApprovalById(chain.owner.hash, chain.owner.org, approvalId(987654));
    await expectStoreCode(
      store.listActions(chain.owner.hash, chain.owner.org, { limit: '0' }),
      'CONTROL_ACTION_READ_STORE_INPUT_INVALID',
    );
    const after = await counts();
    expect(after).toEqual(before);
    expect(before.actions).toBe(4);
    expect(before.approvals).toBe(4);
    expect(before.reservations).toBe(0);
    expect(before.events).toBe(0);
    const afterActions = await admin.query<{ digest: string }>(
      'SELECT md5(string_agg(t::text, $1 ORDER BY t.action_id)) AS digest FROM openarc_durable.commerce_actions t',
      ['|'],
    );
    const afterApprovals = await admin.query<{ digest: string }>(
      'SELECT md5(string_agg(t::text, $1 ORDER BY t.approval_id)) AS digest FROM openarc_durable.commerce_approvals t',
      ['|'],
    );
    expect(afterActions.rows[0]?.digest).toBe(beforeActions.rows[0]?.digest);
    expect(afterApprovals.rows[0]?.digest).toBe(beforeApprovals.rows[0]?.digest);
  });
});
