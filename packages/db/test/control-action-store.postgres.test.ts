import { createHash } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import {
  CommerceSessionStore,
  ControlActionStore,
  ControlActionStoreError,
  CredentialStore,
  MarketLifecycleStore,
  MarketStore,
  createDatabasePool,
  migrate,
  reviewedEndpointDigest,
  type TenantClient,
  type TenantPool,
  type TenantQueryResult,
} from '../src/index.js';
import {
  adminPool,
  ensureRoles,
  migratorUrl,
  resetSchema,
  tenantUrl,
} from './postgres-fixture.js';

/**
 * Privileged core-engine PG tests for schema10. Positive fixture-admission
 * cases execute the migrator-only core helper directly (mode
 * 'internal_fixture'); the restricted runtime only ever reaches the literal
 * 'production' wrapper. These are NOT production purchase/reservation or
 * restricted-runtime success evidence.
 */

const ORIGIN = 'https://api.example.com';
const PATH = '/v1/run';

function sha256(seed: string): string {
  return createHash('sha256').update(`openarc-action-test:${seed}`, 'utf8').digest('hex');
}

function uuid(seed: number): string {
  return `40000000-0000-4000-8000-${String(seed).padStart(12, '0')}`;
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

function requirementId(seed: number): string {
  return `openarc:requirement:${uuid(seed)}`;
}

function mutationId(seed: number): string {
  return uuid(700000 + seed);
}

// Distinct from market/credential/action-store seeds so an action mutation id
// never collides with the seeding mutations in the same organization.
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
  return createHash('sha256').update(`action-key:${seed}`).digest().toString('base64url');
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
let store: ControlActionStore;
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
  store = new ControlActionStore(tenant);
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

async function seedAccount(seed: number, status = 'active'): Promise<string> {
  const id = accountId(seed);
  await admin.query(
    'INSERT INTO openarc_auth.accounts (account_id, user_handle, status) VALUES ($1, $2, $3)',
    [id, userHandle(seed), status],
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
    'INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, $3, $4)',
    [org, account, role, 'active'],
  );
  return { account, hash, org };
}

async function seedAgent(seed: number, org: string): Promise<string> {
  const id = agentId(seed);
  await admin.query(
    'INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name, status) VALUES ($1, $2, $3, $4)',
    [org, id, `Agent ${seed}`, 'active'],
  );
  return id;
}

async function seedProvider(seed: number, org: string): Promise<string> {
  const id = providerId(seed);
  await admin.query(
    'INSERT INTO openarc_tenant.providers (organization_id, provider_id, display_name, status) VALUES ($1, $2, $3, $4)',
    [org, id, `Provider ${seed}`, 'active'],
  );
  return id;
}

interface PolicyOptions {
  readonly mode?: 'none' | 'always' | 'above';
  readonly threshold?: string | null;
  readonly separateApprover?: boolean;
  readonly perActionLimit?: string | null;
  readonly rollingLimit?: string | null;
  readonly feeLimit?: string;
  readonly providerAllow?: readonly string[] | null;
  readonly listingAllow?: readonly string[] | null;
  readonly expiresOffset?: string;
}

async function seedPolicy(
  org: string,
  subject: string,
  seed: number,
  provider: string,
  options: PolicyOptions = {},
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
    await client.query(
      `INSERT INTO openarc_tenant.budget_policy_versions
         (organization_id, policy_id, revision, subject_agent_id, network_id, asset,
          representation, decimals, per_action_limit, rolling_limit, rolling_window_seconds,
          fee_limit, allowed_provider_ids, allowed_listing_ids, approval_mode,
          approval_threshold, approval_separate_approver, expires_at, digest)
       VALUES ($1, $2, '1', $3, 'eip155:5042002', 'USDC', 'erc20', 6, $4, $5,
               CASE WHEN $5::text IS NULL THEN NULL ELSE '3600' END, $6,
               COALESCE($7::text[], ARRAY[$8]::text[]), COALESCE($9::text[], ARRAY[]::text[]),
               $10, $11, $12, clock_timestamp() + ($13)::interval, 'sha256:' || repeat('a', 64))`,
      [
        org,
        id,
        subject,
        options.perActionLimit ?? '5000000',
        options.rollingLimit === undefined ? '5000000' : options.rollingLimit,
        options.feeLimit ?? '0',
        options.providerAllow === null ? null : (options.providerAllow ?? [provider]),
        provider,
        options.listingAllow === null ? null : (options.listingAllow ?? null),
        options.mode ?? 'none',
        options.threshold ?? null,
        options.separateApprover ?? false,
        options.expiresOffset ?? '1 hour',
      ],
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
  readonly agent: string;
  readonly policy: string;
  readonly credential: string;
  readonly agentSessionHash: string;
}

async function seedMachine(owner: Owner, seed: number, policy: string, agent: string): Promise<Machine> {
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
  const agentSessionHash = sha256(`machine:${seed}`);
  await credentials.createAgentSession({
    organizationId: owner.org,
    profileId: agent,
    credentialId: credential,
    expectedVersion: 1,
    sessionId: machineSessionId(seed),
    tokenHash: agentSessionHash,
    expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
  });
  return { agent, policy, credential, agentSessionHash };
}

async function seedPublishedListing(
  owner: Owner,
  provider: string,
  seed: number,
): Promise<string> {
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
  readonly sellerOrg: string;
}

async function seedChain(seed: number, options: PolicyOptions = {}): Promise<Chain> {
  const owner = await seedOwner(seed);
  const agent = await seedAgent(seed, owner.org);
  const provider = await seedProvider(seed, owner.org);
  const listing = await seedPublishedListing(owner, provider, seed);
  const policy = await seedPolicy(owner.org, agent, seed, provider, options);
  const machine = await seedMachine(owner, seed, policy, agent);
  const handoffHash = sha256(`handoff:${seed}`);
  const commerceTokenHash = sha256(`commerce:${seed}`);
  const issued = await commerce.issueCommerceSession(
    owner.hash,
    owner.org,
    { subjectAgentId: agent, policyId: policy, handoffHash, hashVersion: 1 },
    { idempotencyKey: key(100000 + seed), mutationId: mutationId(100000 + seed) },
  );
  void issued;
  await commerce.exchangeCommerceSession(
    machine.agentSessionHash,
    handoffHash,
    { tokenHash: commerceTokenHash, hashVersion: 1 },
    { idempotencyKey: key(200000 + seed), mutationId: mutationId(200000 + seed) },
  );
  return { owner, agent, provider, listing, policy, commerceTokenHash, seed, sellerOrg: owner.org };
}

/**
 * Cross-organization chain: buyer A buys seller B's actual published/reviewed
 * listing. The buyer holds NO membership in the seller organization; the
 * provider/listing/version owner is the seller org. Requirement/action/
 * reservation/exposure remain buyer-scoped.
 */
async function seedCrossChain(
  buyerSeed: number,
  sellerSeed: number,
  options: PolicyOptions = {},
): Promise<Chain> {
  const buyer = await seedOwner(buyerSeed);
  const seller = await seedOwner(sellerSeed);
  const agent = await seedAgent(buyerSeed, buyer.org);
  const sellerProvider = await seedProvider(sellerSeed, seller.org);
  const listing = await seedPublishedListing(seller, sellerProvider, sellerSeed);
  const policy = await seedPolicy(
    buyer.org,
    agent,
    buyerSeed,
    sellerProvider,
    options,
  );
  const machine = await seedMachine(buyer, buyerSeed, policy, agent);
  const handoffHash = sha256(`handoff:${buyerSeed}`);
  const commerceTokenHash = sha256(`commerce:${buyerSeed}`);
  await commerce.issueCommerceSession(
    buyer.hash,
    buyer.org,
    { subjectAgentId: agent, policyId: policy, handoffHash, hashVersion: 1 },
    { idempotencyKey: key(100000 + buyerSeed), mutationId: mutationId(100000 + buyerSeed) },
  );
  await commerce.exchangeCommerceSession(
    machine.agentSessionHash,
    handoffHash,
    { tokenHash: commerceTokenHash, hashVersion: 1 },
    { idempotencyKey: key(200000 + buyerSeed), mutationId: mutationId(200000 + buyerSeed) },
  );
  return {
    owner: buyer,
    agent,
    provider: sellerProvider,
    listing,
    policy,
    commerceTokenHash,
    seed: buyerSeed,
    sellerOrg: seller.org,
  };
}

async function seedRequirement(
  chain: Chain,
  seed: number,
  overrides: {
    amountAtomic?: string;
    feeAtomic?: string;
    validUntil?: string;
    sourceKind?: string;
    listingVersion?: string;
  } = {},
): Promise<string> {
  const id = requirementId(seed);
  await admin.query(
    `INSERT INTO openarc_durable.commerce_requirement_references (
       organization_id, requirement_id, seller_organization_id, provider_id, listing_id,
       listing_version, network_id,
       asset, representation, decimals, amount_atomic, fee_atomic, requirement_digest,
       source_kind, created_at, valid_until)
     VALUES ($1, $2, $3, $4, $5, $10, 'eip155:5042002', 'USDC', 'erc20', 6, $6, $7,
             'sha256:' || repeat('c', 64), $8, clock_timestamp(),
             CASE WHEN $9::text IS NULL THEN clock_timestamp() + interval '30 minutes' ELSE $9::timestamptz END)`,
    [
      chain.owner.org,
      id,
      chain.sellerOrg,
      chain.provider,
      chain.listing,
      overrides.amountAtomic ?? '1000000',
      overrides.feeAtomic ?? '0',
      overrides.sourceKind ?? 'internal_fixture',
      overrides.validUntil ?? null,
      overrides.listingVersion ?? '1',
    ],
  );
  return id;
}

const HEX_A = 'a'.repeat(64);

function coreAuthorize(
  chain: Chain,
  requirement: string,
  action: string,
  meta: { key?: string; digest?: string; mutationId?: string } = {},
) {
  const rawKey = meta.key ?? key(chain.seed + 300000);
  // The core consumes the TRUSTED API key HASH, never the raw idempotency key.
  const keyHash = createHash('sha256').update(rawKey, 'utf8').digest('hex');
  // Canonical production session-context digest for the exact commerce token,
  // so the agent status reader can bind the same context.
  const contextDigest = createHash('sha256')
    .update(`openarc.control.commerce_action.authorize.session.v1:${chain.commerceTokenHash}`, 'utf8')
    .digest('hex');
  return migrator.query(
    `SELECT * FROM openarc_durable.authorize_commerce_action_core(
       'internal_fixture', $1, $2, $3, $4::uuid, $5, $6, $7)`,
    [
      chain.commerceTokenHash,
      requirement,
      action,
      meta.mutationId ?? actionMutation(chain.seed),
      keyHash,
      meta.digest ?? HEX_A,
      contextDigest,
    ],
  );
}

async function rawError(promise: Promise<unknown>): Promise<{ code?: string }> {
  try {
    await promise;
  } catch (error) {
    return error as { code?: string };
  }
  throw new Error('expected a rejection');
}

async function expectStoreCode(promise: Promise<unknown>, code: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ControlActionStoreError);
    expect((error as ControlActionStoreError).code).toBe(code);
    return;
  }
  throw new Error(`expected ControlActionStoreError ${code}`);
}

describe('schema10 manifest, ownership and ACLs', () => {
  it('records schema10 and keeps runtime denied on the core/table surface', async () => {
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
    const tables = await admin.query<{ n: number; enabled: boolean; forced: boolean }>(
      `SELECT count(*)::int AS n, bool_and(c.relrowsecurity) AS enabled,
              bool_and(c.relforcerowsecurity) AS forced
         FROM pg_class c JOIN pg_namespace ns ON ns.oid = c.relnamespace
        WHERE ns.nspname = 'openarc_durable' AND c.relkind = 'r'
          AND c.relname IN ('commerce_exposure_locks', 'commerce_requirement_references',
                            'commerce_actions', 'budget_reservations', 'commerce_approvals', 'budget_events')`,
    );
    expect(tables.rows[0]).toMatchObject({ n: 6, enabled: true, forced: true });
    expect(
      (await rawError(tenant.query('SELECT count(*) FROM openarc_durable.commerce_actions'))).code,
    ).toBe('42501');
    // The private core and fixture admission are not executable by runtime.
    expect(
      (await rawError(
        tenant.query(
          `SELECT * FROM openarc_durable.authorize_commerce_action_core(
             'internal_fixture', $1, $2, $3, $4::uuid, $5, $6, $7)`,
          [HEX_A, requirementId(1), actionId(1), mutationId(1), key(1), HEX_A, HEX_A],
        ),
      )).code,
    ).toBeTruthy();
  });

  it('creates zero requirement rows in the initial migration', async () => {
    const result = await admin.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM openarc_durable.commerce_requirement_references',
    );
    expect(result.rows[0]?.n).toBe(0);
  });
});

describe('privileged core authorize: budget and approval', () => {
  it('reserves exactly one held reservation within limits', async () => {
    const chain = await seedChain(10);
    const requirement = await seedRequirement(chain, 10);
    const action = actionId(10);
    const result = await coreAuthorize(chain, requirement, action);
    expect(result.rows[0]).toMatchObject({
      out_replayed: false,
      out_status: 'reserved_not_granted',
      out_reservation_id: `openarc:reservation:${uuid(10)}`,
      out_approval_id: null,
    });
    const counts = await admin.query<{ reservations: number; approvals: number }>(
      `SELECT (SELECT count(*)::int FROM openarc_durable.budget_reservations) AS reservations,
              (SELECT count(*)::int FROM openarc_durable.commerce_approvals) AS approvals`,
    );
    expect(counts.rows[0]).toMatchObject({ reservations: 1, approvals: 0 });
  });

  it('routes always and above-threshold policies to pending with ZERO reservation', async () => {
    for (const [seed, options] of [
      [11, { mode: 'always' as const }],
      [12, { mode: 'above' as const, threshold: '999999' }],
    ] as const) {
      await resetSchema(admin);
      await migrate(migrator);
      store = new ControlActionStore(tenant);
      const chain = await seedChain(seed, options);
      const requirement = await seedRequirement(chain, seed);
      const action = actionId(seed);
      const result = await coreAuthorize(chain, requirement, action);
      expect(result.rows[0]).toMatchObject({
        out_status: 'pending_approval',
        out_reservation_id: null,
        out_approval_id: `openarc:approval:${uuid(seed)}`,
      });
      const counts = await admin.query<{ reservations: number; approvals: number }>(
        `SELECT (SELECT count(*)::int FROM openarc_durable.budget_reservations) AS reservations,
                (SELECT count(*)::int FROM openarc_durable.commerce_approvals) AS approvals`,
      );
      expect(counts.rows[0]).toMatchObject({ reservations: 0, approvals: 1 });
    }
  });

  it('does not require approval exactly at the threshold (strictly above)', async () => {
    const chain = await seedChain(13, { mode: 'above', threshold: '1000000' });
    const requirement = await seedRequirement(chain, 13);
    const result = await coreAuthorize(chain, requirement, actionId(13));
    expect(result.rows[0]?.out_status).toBe('reserved_not_granted');
  });

  it('denies over-limit and creates no action/reservation/idempotency', async () => {
    const chain = await seedChain(14, { perActionLimit: '500' });
    const requirement = await seedRequirement(chain, 14);
    const error = await rawError(coreAuthorize(chain, requirement, actionId(14)));
    expect(error.code).toBe('P0D12');
    const counts = await admin.query<{ actions: number; reservations: number; idem: number }>(
      `SELECT (SELECT count(*)::int FROM openarc_durable.commerce_actions) AS actions,
              (SELECT count(*)::int FROM openarc_durable.budget_reservations) AS reservations,
              (SELECT count(*)::int FROM openarc_durable.idempotency_records
                WHERE operation LIKE 'control.commerce_action%') AS idem`,
    );
    expect(counts.rows[0]).toMatchObject({ actions: 0, reservations: 0, idem: 0 });
  });
});

describe('cross-organization buyer/seller binding', () => {
  it('authorizes seller B listing under buyer A and denies B a human read', async () => {
    const chain = await seedCrossChain(80, 1800);
    const requirement = await seedRequirement(chain, 80);
    const action = actionId(80);
    const result = await coreAuthorize(chain, requirement, action, {
      mutationId: uuid(850080),
      key: key(80),
    });
    expect(result.rows[0]).toMatchObject({
      out_status: 'reserved_not_granted',
      out_organization_id: chain.owner.org,
    });
    const stored = await admin.query<{ organization_id: string; seller_organization_id: string; provider_id: string; listing_id: string }>(
      `SELECT organization_id, seller_organization_id, provider_id, listing_id
         FROM openarc_durable.commerce_actions WHERE action_id = $1`,
      [action],
    );
    expect(stored.rows[0]).toMatchObject({
      organization_id: chain.owner.org,
      seller_organization_id: chain.sellerOrg,
      provider_id: chain.provider,
      listing_id: chain.listing,
    });
    const reservation = await admin.query<{ organization_id: string; subject_agent_id: string }>(
      `SELECT organization_id, subject_agent_id FROM openarc_durable.budget_reservations
        WHERE action_id = $1`,
      [action],
    );
    expect(reservation.rows[0]).toMatchObject({
      organization_id: chain.owner.org,
      subject_agent_id: chain.agent,
    });
    // The seller organization cannot see the buyer's action: reading from the
    // seller's own org returns no row (buyer-scoped), and reading the buyer's
    // org without membership is denied.
    const sellerHash = sha256('session:1800');
    await expect(store.readAction(sellerHash, chain.sellerOrg, action)).resolves.toBeNull();
    const direct = await rawError(
      migrator.query(`SELECT * FROM openarc_durable.read_commerce_action($1, $2, $3)`, [
        sellerHash,
        chain.owner.org,
        action,
      ]),
    );
    expect(direct.code).toBeTruthy();
  });

  it('rejects a tampered seller organization binding', async () => {
    const chain = await seedCrossChain(81, 1801);
    const requirement = await seedRequirement(chain, 81);
    // A different existing seller org cannot own this provider/listing pair.
    const error = await rawError(
      admin.query(
        `UPDATE openarc_durable.commerce_requirement_references
            SET seller_organization_id = $1 WHERE requirement_id = $2`,
        [orgId(1801), requirement],
      ),
    );
    expect(error.code).toBe('42501');
  });

  it('denies new authority once the seller provider is suspended', async () => {
    const chain = await seedCrossChain(82, 1802);
    const requirement = await seedRequirement(chain, 82);
    await admin.query(
      `UPDATE openarc_tenant.providers SET status = 'suspended'
        WHERE organization_id = $1 AND provider_id = $2`,
      [chain.sellerOrg, chain.provider],
    );
    const error = await rawError(
      coreAuthorize(chain, requirement, actionId(82), { key: key(82), mutationId: uuid(850082) }),
    );
    expect(error.code).toBe('42501');
    expect(await counts()).toMatchObject({ actions: 0, reservations: 0 });
  });

  it('lets a current buyer cancel an unclaimed held action after seller inactivity', async () => {
    const chain = await seedCrossChain(83, 1803);
    const requirement = await seedRequirement(chain, 83);
    const action = actionId(83);
    await coreAuthorize(chain, requirement, action, { key: key(83), mutationId: uuid(850083) });
    // The seller provider is suspended. The cancellation path tolerates dead
    // seller/original-parent authority because it re-asserts only the current
    // buyer caller.
    await admin.query(
      `UPDATE openarc_tenant.providers SET status = 'suspended'
        WHERE organization_id = $1 AND provider_id = $2`,
      [chain.sellerOrg, chain.provider],
    );
    const cancelled = await coreCancel(chain, action, 83);
    expect(cancelled.rows[0]).toMatchObject({ out_status: 'cancelled' });
    const reservation = await admin.query<{ status: string }>(
      'SELECT status FROM openarc_durable.budget_reservations WHERE action_id = $1',
      [action],
    );
    expect(reservation.rows[0]?.status).toBe('released');
  });

  it('serializes reverse A-buys-B / B-buys-A authorizations without deadlock', async () => {
    // Buyer A buys seller B's listing.
    const ab = await seedCrossChain(84, 1804);
    const requirementAB = await seedRequirement(ab, 84);
    // Buyer B buys seller A's listing.
    const ba = await seedCrossChain(1805, 85);
    const requirementBA = await seedRequirement(ba, 1805);
    const [first, second] = await Promise.allSettled([
      coreAuthorize(ab, requirementAB, actionId(84), { key: key(84), mutationId: uuid(850084) }),
      coreAuthorize(ba, requirementBA, actionId(85), { key: key(85), mutationId: uuid(850085) }),
    ]);
    expect(first.status).toBe('fulfilled');
    expect(second.status).toBe('fulfilled');
    expect(await counts()).toMatchObject({ actions: 2, reservations: 2 });
  });

  it('denies an action bound to a superseded listing active version', async () => {
    const chain = await seedCrossChain(86, 1806);
    const requirement = await seedRequirement(chain, 86);
    const seller = ownerRef(1806);
    // The seller publishes version 2 through the real market lifecycle stores.
    await seedListingVersionTwo(seller, chain.listing, 1806, 'approved');
    const listing = await admin.query<{ active_version: string; latest_version: string }>(
      'SELECT active_version, latest_version FROM openarc_tenant.listings WHERE listing_id = $1',
      [chain.listing],
    );
    expect(listing.rows[0]).toMatchObject({ active_version: '2', latest_version: '2' });
    // The immutable requirement still pins version 1, which is no longer the
    // current active version.
    const error = await rawError(
      coreAuthorize(chain, requirement, actionId(86), { key: key(86), mutationId: uuid(850086) }),
    );
    expect(error.code).toBe('42501');
    expect(await counts()).toMatchObject({ actions: 0, reservations: 0, approvals: 0 });
  });

  it('denies an action bound to a version whose origin review was rejected', async () => {
    const chain = await seedCrossChain(87, 1807);
    const seller = ownerRef(1807);
    await seedListingVersionTwo(seller, chain.listing, 1807, 'rejected');
    const review = await admin.query<{ decision: string }>(
      `SELECT decision FROM openarc_tenant.listing_origin_reviews
        WHERE organization_id = $1 AND listing_id = $2 AND version = '2'`,
      [seller.org, chain.listing],
    );
    expect(review.rows[0]?.decision).toBe('rejected');
    const state = await admin.query<{ status: string; origin_review_state: string }>(
      `SELECT status, origin_review_state FROM openarc_tenant.listing_version_states
        WHERE organization_id = $1 AND listing_id = $2 AND version = '2'`,
      [seller.org, chain.listing],
    );
    expect(state.rows[0]).toMatchObject({ status: 'draft', origin_review_state: 'rejected' });
    // A rejected origin review keeps the version out of the published/active
    // state entirely (SQL6 forbids active+unapproved), so an action bound to it
    // is denied by the current listing/origin gate rather than ever becoming
    // reachable. The denial below is that gate, not a missing row.
    const requirement = await seedRequirement(chain, 87, { listingVersion: '2' });
    const error = await rawError(
      coreAuthorize(chain, requirement, actionId(87), { key: key(87), mutationId: uuid(850087) }),
    );
    expect(error.code).toBe('42501');
    expect(await counts()).toMatchObject({ actions: 0, reservations: 0, approvals: 0 });
  });

  it('rejects a tampered price or identity binding on the action row', async () => {
    const chain = await seedCrossChain(88, 1808);
    const requirement = await seedRequirement(chain, 88);
    const action = actionId(88);
    await coreAuthorize(chain, requirement, action, { key: key(88), mutationId: uuid(850088) });
    // The composite requirement-binding FK is the immutable price/identity
    // anchor: an otherwise valid action row that changes the amount or the
    // requirement digest cannot exist at all.
    const price = await rawError(
      cloneActionRow(chain.owner.org, action, actionId(881), { amountAtomic: '999999' }),
    );
    expect(price.code).toBe('23503');
    const identity = await rawError(
      cloneActionRow(chain.owner.org, action, actionId(882), {
        requirementDigest: `sha256:${'d'.repeat(64)}`,
      }),
    );
    expect(identity.code).toBe('23503');
    expect(await counts()).toMatchObject({ actions: 1, reservations: 1 });
    const stored = await admin.query<{ amount_atomic: string; requirement_digest: string }>(
      'SELECT amount_atomic, requirement_digest FROM openarc_durable.commerce_actions WHERE action_id = $1',
      [action],
    );
    expect(stored.rows[0]).toMatchObject({
      amount_atomic: '1000000',
      requirement_digest: `sha256:${'c'.repeat(64)}`,
    });
  });
});

describe('production unavailable lane and fixture seam', () => {
  it('rejects an internal_fixture requirement through the production wrapper', async () => {
    const chain = await seedChain(20);
    const requirement = await seedRequirement(chain, 20);
    const error = await rawError(
      migrator.query(
        `SELECT * FROM openarc_durable.authorize_commerce_action($1, $2, $3, $4::uuid, $5, $6, $7)`,
        [
          chain.commerceTokenHash,
          requirement,
          actionId(20),
          actionMutation(20),
          createHash('sha256').update(key(20), 'utf8').digest('hex'),
          HEX_A,
          sha256('ctx'),
        ],
      ),
    );
    expect(error.code).toBe('P0D10');
    const counts = await admin.query<{ actions: number }>(
      'SELECT count(*)::int AS actions FROM openarc_durable.commerce_actions',
    );
    expect(counts.rows[0]?.actions).toBe(0);
  });

  it('rejects a machine-session hash presented as a commerce token', async () => {
    const chain = await seedChain(21);
    const requirement = await seedRequirement(chain, 21);
    const error = await rawError(
      migrator.query(
        `SELECT * FROM openarc_durable.authorize_commerce_action_core(
           'internal_fixture', $1, $2, $3, $4::uuid, $5, $6, $7)`,
        [
          sha256('machine:21'),
          requirement,
          actionId(21),
          actionMutation(21),
          createHash('sha256').update(key(21), 'utf8').digest('hex'),
          HEX_A,
          sha256('ctx'),
        ],
      ),
    );
    expect(error.code).toBe('42501');
  });
});

describe('replay, conflicts and exact commerce context', () => {
  it('replays the same key/context and conflicts on changed body or new key', async () => {
    const chain = await seedChain(30);
    const requirement = await seedRequirement(chain, 30);
    const action = actionId(30);
    const meta = { key: key(30), digest: HEX_A, mutationId: actionMutation(30) };
    const first = await coreAuthorize(chain, requirement, action, meta);
    expect(first.rows[0]?.out_replayed).toBe(false);
    const replay = await coreAuthorize(chain, requirement, action, meta);
    expect(replay.rows[0]?.out_replayed).toBe(true);
    const changed = await rawError(
      coreAuthorize(chain, requirement, action, { ...meta, digest: 'b'.repeat(64) }),
    );
    expect(changed.code).toBe('P0D01');
  });

  it('conflicts when a new key reuses an existing action', async () => {
    const chain = await seedChain(31);
    const requirement = await seedRequirement(chain, 31);
    const action = actionId(31);
    await coreAuthorize(chain, requirement, action, { key: key(31), mutationId: actionMutation(31) });
    const conflict = await rawError(
      coreAuthorize(chain, requirement, action, { key: key(32), mutationId: actionMutation(32) }),
    );
    expect(conflict.code).toBeTruthy();
  });

  it('denies authorize and agent status after the commerce session is revoked', async () => {
    const chain = await seedChain(33);
    const requirement = await seedRequirement(chain, 33);
    const action = actionId(33);
    const mutation = actionMutation(33);
    await coreAuthorize(chain, requirement, action, { mutationId: mutation, key: key(33) });
    await commerce.revokeCommerceSession(
      chain.owner.hash,
      chain.owner.org,
      (await admin.query<{ session_id: string }>(
        'SELECT session_id FROM openarc_durable.commerce_sessions WHERE organization_id = $1 LIMIT 1',
        [chain.owner.org],
      )).rows[0]!.session_id,
      { idempotencyKey: key(330), mutationId: mutationId(330) },
    );
    const error = await rawError(coreAuthorize(chain, requirement, actionId(33)));
    expect(error.code).toBe('42501');
    // The exact original mutation must also no longer be recoverable.
    const statusError = await rawError(
      migrator.query(
        `SELECT * FROM openarc_durable.read_agent_commerce_action_mutation_status($1, $2::uuid)`,
        [chain.commerceTokenHash, mutation],
      ),
    );
    expect(statusError.code).toBe('42501');
  });
});

function coreDecide(
  chain: Chain,
  action: string,
  decision: 'approve' | 'reject',
  seed: number,
  deciderHash = chain.owner.hash,
) {
  return migrator.query(
    `SELECT * FROM openarc_durable.decide_commerce_action_core(
       'internal_fixture', $1, $2, $3, $4, $5::uuid, $6, $7, $8)`,
    [
      deciderHash,
      chain.owner.org,
      action,
      decision,
      uuid(860000 + seed),
      createHash('sha256').update(key(seed), 'utf8').digest('hex'),
      HEX_A,
      sha256('ctx'),
    ],
  );
}

function coreCancel(chain: Chain, action: string, seed: number) {
  return migrator.query(
    `SELECT * FROM openarc_durable.cancel_commerce_action_core(
       $1, $2, $3, $4::uuid, $5, $6, $7)`,
    [
      chain.owner.hash,
      chain.owner.org,
      action,
      uuid(870000 + seed),
      createHash('sha256').update(key(seed), 'utf8').digest('hex'),
      HEX_A,
      sha256('ctx'),
    ],
  );
}

async function counts(): Promise<Record<string, number>> {
  const result = await admin.query<Record<string, number>>(
    `SELECT (SELECT count(*)::int FROM openarc_durable.commerce_actions) AS actions,
            (SELECT count(*)::int FROM openarc_durable.budget_reservations) AS reservations,
            (SELECT count(*)::int FROM openarc_durable.commerce_approvals) AS approvals,
            (SELECT count(*)::int FROM openarc_durable.budget_events) AS events`,
  );
  return result.rows[0] as Record<string, number>;
}

describe('privileged decide: approve and reject', () => {
  it('approve creates exactly one held reservation and marks the action reserved', async () => {
    const chain = await seedChain(40, { mode: 'always' });
    const requirement = await seedRequirement(chain, 40);
    const action = actionId(40);
    const pending = await coreAuthorize(chain, requirement, action);
    expect(pending.rows[0]).toMatchObject({ out_status: 'pending_approval', out_reservation_id: null });
    expect((await counts()).reservations).toBe(0);

    const decided = await coreDecide(chain, action, 'approve', 40);
    expect(decided.rows[0]).toMatchObject({
      out_replayed: false,
      out_status: 'reserved_not_granted',
      out_reservation_id: `openarc:reservation:${uuid(40)}`,
    });
    expect(await counts()).toMatchObject({ reservations: 1, approvals: 1 });
    const reservation = await admin.query<{ status: string }>(
      'SELECT status FROM openarc_durable.budget_reservations WHERE action_id = $1',
      [action],
    );
    expect(reservation.rows[0]?.status).toBe('held');
  });

  it('reject marks the approval/action rejected with no reservation', async () => {
    const chain = await seedChain(41, { mode: 'always' });
    const requirement = await seedRequirement(chain, 41);
    const action = actionId(41);
    await coreAuthorize(chain, requirement, action);
    const decided = await coreDecide(chain, action, 'reject', 41);
    expect(decided.rows[0]).toMatchObject({ out_status: 'rejected', out_reservation_id: null });
    expect(await counts()).toMatchObject({ reservations: 0 });
    const approval = await admin.query<{ status: string; decided_at: string | null }>(
      'SELECT status, decided_at FROM openarc_durable.commerce_approvals WHERE action_id = $1',
      [action],
    );
    expect(approval.rows[0]).toMatchObject({ status: 'rejected' });
    expect(approval.rows[0]?.decided_at).not.toBeNull();
  });

  it('separateApprover denies the requester and allows a different current owner', async () => {
    const chain = await seedChain(42, { mode: 'always', separateApprover: true });
    const requirement = await seedRequirement(chain, 42);
    const action = actionId(42);
    await coreAuthorize(chain, requirement, action);
    const self = await rawError(coreDecide(chain, action, 'approve', 42));
    expect(self.code).toBe('42501');

    const other = await seedOwner(420, 'owner');
    await admin.query(
      'INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, $3, $4)',
      [chain.owner.org, other.account, 'operator', 'active'],
    );
    const decided = await coreDecide(chain, action, 'approve', 420, other.hash);
    expect(decided.rows[0]?.out_status).toBe('reserved_not_granted');
  });

  it('is idempotent on same context and conflicts on a second decision', async () => {
    const chain = await seedChain(43, { mode: 'always' });
    const requirement = await seedRequirement(chain, 43);
    const action = actionId(43);
    await coreAuthorize(chain, requirement, action);
    const first = await coreDecide(chain, action, 'approve', 43);
    const replay = await migrator.query(
      `SELECT * FROM openarc_durable.decide_commerce_action_core(
         'internal_fixture', $1, $2, $3, 'approve', $4::uuid, $5, $6, $7)`,
      [
        chain.owner.hash,
        chain.owner.org,
        action,
        uuid(860043),
        createHash('sha256').update(key(43), 'utf8').digest('hex'),
        HEX_A,
        sha256('ctx'),
      ],
    );
    expect(first.rows[0]?.out_replayed).toBe(false);
    expect(replay.rows[0]?.out_replayed).toBe(true);
    const second = await rawError(coreDecide(chain, action, 'reject', 430));
    expect(second.code).toBe('23514');
    expect(await counts()).toMatchObject({ reservations: 1 });
  });
});

describe('privileged cancel: held vs potential exposure', () => {
  it('releases only an unclaimed held reservation and writes one released event', async () => {
    const chain = await seedChain(50);
    const requirement = await seedRequirement(chain, 50);
    const action = actionId(50);
    await coreAuthorize(chain, requirement, action);
    const cancelled = await coreCancel(chain, action, 50);
    expect(cancelled.rows[0]).toMatchObject({ out_status: 'cancelled' });
    const reservation = await admin.query<{ status: string; resolved_at: string | null }>(
      'SELECT status, resolved_at FROM openarc_durable.budget_reservations WHERE action_id = $1',
      [action],
    );
    expect(reservation.rows[0]?.status).toBe('released');
    expect(reservation.rows[0]?.resolved_at).not.toBeNull();
    const events = await admin.query<{ event_kind: string }>(
      'SELECT event_kind FROM openarc_durable.budget_events WHERE action_id = $1',
      [action],
    );
    expect(events.rows.map((row) => row.event_kind)).toEqual(['released']);
  });

  it('refuses cancellation of a claimed reservation without touching state', async () => {
    const chain = await seedChain(51);
    const requirement = await seedRequirement(chain, 51);
    const action = actionId(51);
    await coreAuthorize(chain, requirement, action);
    await admin.query(
      `UPDATE openarc_durable.budget_reservations
          SET status = 'claimed', claimed_at = clock_timestamp()
        WHERE action_id = $1`,
      [action],
    );
    const error = await rawError(coreCancel(chain, action, 51));
    expect(error.code).toBe('P0D13');
    const actionRow = await admin.query<{ status: string }>(
      'SELECT status FROM openarc_durable.commerce_actions WHERE action_id = $1',
      [action],
    );
    expect(actionRow.rows[0]?.status).toBe('reserved_not_granted');
  });

  it('cancels a pending approval to a safe expired state with null decision', async () => {
    const chain = await seedChain(52, { mode: 'always' });
    const requirement = await seedRequirement(chain, 52);
    const action = actionId(52);
    await coreAuthorize(chain, requirement, action);
    await coreCancel(chain, action, 52);
    const approval = await admin.query<{ status: string; decided_by: string | null; decided_at: string | null }>(
      'SELECT status, decided_by, decided_at FROM openarc_durable.commerce_approvals WHERE action_id = $1',
      [action],
    );
    expect(approval.rows[0]).toMatchObject({ status: 'expired', decided_by: null, decided_at: null });
  });
});

describe('exact agent context, exposure and concurrency', () => {
  it('binds agent status to the exact presented commerce token context', async () => {
    const chain = await seedChain(60);
    const requirement = await seedRequirement(chain, 60);
    const action = actionId(60);
    const mutation = actionMutation(60);
    await coreAuthorize(chain, requirement, action, { mutationId: mutation, key: key(60) });
    const found = await migrator.query(
      `SELECT * FROM openarc_durable.read_agent_commerce_action_mutation_status($1, $2::uuid)`,
      [chain.commerceTokenHash, mutation],
    );
    expect(found.rows).toHaveLength(1);

    // A SECOND VALID live commerce token sponsored by the SAME human/agent must
    // not recover the original receipt: the reader binds the exact presented
    // commerce session-context digest, not account identity.
    const secondHandoff = sha256('handoff:second:60');
    const secondToken = sha256('commerce:second:60');
    const secondAgentSessionHash = sha256('machine:60');
    await commerce.issueCommerceSession(
      chain.owner.hash,
      chain.owner.org,
      { subjectAgentId: chain.agent, policyId: chain.policy, handoffHash: secondHandoff, hashVersion: 1 },
      { idempotencyKey: key(60100), mutationId: uuid(660100) },
    );
    await commerce.exchangeCommerceSession(
      secondAgentSessionHash,
      secondHandoff,
      { tokenHash: secondToken, hashVersion: 1 },
      { idempotencyKey: key(60101), mutationId: uuid(660101) },
    );
    const other = await migrator.query(
      `SELECT * FROM openarc_durable.read_agent_commerce_action_mutation_status($1, $2::uuid)`,
      [secondToken, mutation],
    );
    expect(other.rows).toHaveLength(0);
  });

  it('reports exact exposure totals and available/deficit', async () => {
    const chain = await seedChain(61, { rollingLimit: '5000000' });
    const requirement = await seedRequirement(chain, 61);
    await coreAuthorize(chain, requirement, actionId(61));
    const exposure = await migrator.query<Record<string, string | null>>(
      `SELECT * FROM openarc_durable.read_commerce_exposure($1, $2, $3, $4)`,
      [chain.owner.hash, chain.owner.org, chain.agent, chain.policy],
    );
    expect(exposure.rows[0]).toMatchObject({
      out_committed_atomic: '0',
      out_unresolved_atomic: '1000000',
      out_total_atomic: '1000000',
      out_available_atomic: '4000000',
      out_deficit_atomic: '0',
    });
  });

  it('allows exactly one of two concurrent decisions to create the reservation', async () => {
    const chain = await seedChain(62, { mode: 'always' });
    const requirement = await seedRequirement(chain, 62);
    const action = actionId(62);
    await coreAuthorize(chain, requirement, action);
    const [a, b] = await Promise.allSettled([
      coreDecide(chain, action, 'approve', 620),
      coreDecide(chain, action, 'reject', 621),
    ]);
    const fulfilled = [a, b].filter((result) => result.status === 'fulfilled');
    expect(fulfilled.length).toBe(1);
    expect(await counts()).toMatchObject({ reservations: 1 });
  });
});

describe('runtime store, rollback and freshness barriers', () => {
  it('exposes only the literal production lane to the restricted runtime store', async () => {
    const chain = await seedChain(70);
    const requirement = await seedRequirement(chain, 70);
    await store.initialize();
    let code: string | undefined;
    try {
      await store.authorizeCommerceAction(
        chain.commerceTokenHash,
        { requirementId: requirement, actionId: actionId(70) },
        { idempotencyKey: key(70), mutationId: actionMutation(70) },
      );
    } catch (error) {
      expect(error).toBeInstanceOf(ControlActionStoreError);
      code = (error as ControlActionStoreError).code;
    }
    expect(code).toBe('CONTROL_ACTION_STORE_REQUIREMENT_UNAVAILABLE');
    expect(await counts()).toMatchObject({ actions: 0, reservations: 0 });
  });

  it('reads a committed action through the runtime store with exact binding', async () => {
    const chain = await seedChain(71);
    const requirement = await seedRequirement(chain, 71);
    const action = actionId(71);
    await coreAuthorize(chain, requirement, action, { mutationId: uuid(850071), key: key(71) });
    const metadata = await store.readAction(chain.owner.hash, chain.owner.org, action);
    expect(metadata?.actionId).toBe(action);
    expect(metadata?.status).toBe('reserved_not_granted');
    expect(metadata?.reservationId).toBe(`openarc:reservation:${uuid(71)}`);
  });

  it('rolls back everything when the outbox insert fails', async () => {
    const chain = await seedChain(72);
    const requirement = await seedRequirement(chain, 72);
    await admin.query(
      `CREATE FUNCTION openarc_durable.test_block_action_outbox() RETURNS trigger
       LANGUAGE plpgsql SET search_path = pg_catalog AS $$
       BEGIN
         IF NEW.event_type LIKE 'control.commerce_action%' THEN
           RAISE EXCEPTION 'test_outbox_blocked' USING ERRCODE = '23514';
         END IF;
         RETURN NEW;
       END; $$`,
    );
    await admin.query(
      `CREATE TRIGGER test_block_action_outbox BEFORE INSERT ON openarc_durable.outbox_events
         FOR EACH ROW EXECUTE FUNCTION openarc_durable.test_block_action_outbox()`,
    );
    const error = await rawError(coreAuthorize(chain, requirement, actionId(72), { mutationId: uuid(850072), key: key(72) }));
    expect(error.code).toBe('23514');
    await admin.query('DROP TRIGGER test_block_action_outbox ON openarc_durable.outbox_events');
    expect(await counts()).toMatchObject({ actions: 0, reservations: 0 });
    const idem = await admin.query<{ n: number }>(
      "SELECT count(*)::int AS n FROM openarc_durable.idempotency_records WHERE operation LIKE 'control.commerce_action%'",
    );
    expect(idem.rows[0]?.n).toBe(0);
  });

  it('denies a decision from a stale human proof', async () => {
    const chain = await seedChain(73, { mode: 'always' });
    const requirement = await seedRequirement(chain, 73);
    const action = actionId(73);
    await coreAuthorize(chain, requirement, action, { mutationId: uuid(850073), key: key(73) });
    await admin.query(
      `UPDATE openarc_auth.sessions
          SET created_at = now() - interval '6 minutes',
              expires_at = now() + interval '20 hours'
        WHERE token_hash = $1`,
      [chain.owner.hash],
    );
    const error = await rawError(coreDecide(chain, action, 'approve', 73));
    expect(error.code).toBe('28000');
  });

  it('denies a decision after the bound machine credential is revoked', async () => {
    const chain = await seedChain(74, { mode: 'always' });
    const requirement = await seedRequirement(chain, 74);
    const action = actionId(74);
    await coreAuthorize(chain, requirement, action, { mutationId: uuid(850074), key: key(74) });
    await admin.query(
      `UPDATE openarc_durable.agent_credentials SET revoked_at = clock_timestamp()
        WHERE organization_id = $1`,
      [chain.owner.org],
    );
    const error = await rawError(coreDecide(chain, action, 'approve', 74));
    expect(error.code).toBe('42501');
    expect(await counts()).toMatchObject({ reservations: 0 });
  });

  it('rolls back a decision whose fresh proof lapses during a real bounded lock wait', async () => {
    const chain = await seedChain(90, { mode: 'always' });
    const requirement = await seedRequirement(chain, 90);
    const action = actionId(90);
    await coreAuthorize(chain, requirement, action, { key: key(90), mutationId: uuid(850090) });
    // Seed the decider session JUST-FRESH: two seconds below the accepted
    // five-minute freshness threshold. The initial check passes; by the time
    // the operation returns from its real lock wait the proof must be stale.
    await admin.query(
      `UPDATE openarc_auth.sessions
          SET created_at = clock_timestamp() - interval '4 minutes 58 seconds',
              expires_at = clock_timestamp() - interval '4 minutes 58 seconds' + interval '1 hour'
        WHERE token_hash = $1`,
      [chain.owner.hash],
    );
    // A separate connection holds the action row so the real decide blocks
    // after its initial freshness check and before its final recheck.
    const barrier = await admin.connect();
    try {
      await barrier.query('BEGIN');
      await barrier.query(
        'SELECT action_id FROM openarc_durable.commerce_actions WHERE action_id = $1 FOR UPDATE',
        [action],
      );
      const pending = coreDecide(chain, action, 'approve', 90);
      const deadline = Date.now() + 12_000;
      let observedWait = false;
      for (;;) {
        const probe = await migrator.query<{ waiting: boolean; elapsed_ok: boolean }>(
          `SELECT EXISTS (
              SELECT 1
                FROM pg_locks l
                JOIN pg_stat_activity a ON a.pid = l.pid
               WHERE l.locktype = 'transactionid' AND NOT l.granted
                 AND a.query LIKE '%decide_commerce_action_core%') AS waiting,
            (SELECT bool_and(clock_timestamp() - created_at > interval '5 minutes')
               FROM openarc_auth.sessions WHERE token_hash = $1) AS elapsed_ok`,
          [chain.owner.hash],
        );
        if (probe.rows[0]?.waiting === true) observedWait = true;
        if (probe.rows[0]?.elapsed_ok === true) break;
        if (Date.now() > deadline) throw new Error('decide lock-wait barrier deadline exceeded');
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      expect(observedWait).toBe(true);
      await barrier.query('ROLLBACK');
      const error = await rawError(pending);
      expect(error.code).toBe('28000');
    } finally {
      await barrier.query('ROLLBACK').catch(() => {});
      barrier.release();
    }
    // The final freshness recheck rolled back ALL business and durable writes.
    const actionRow = await admin.query<{ status: string }>(
      'SELECT status FROM openarc_durable.commerce_actions WHERE action_id = $1',
      [action],
    );
    expect(actionRow.rows[0]?.status).toBe('pending_approval');
    const approval = await admin.query<{ status: string }>(
      'SELECT status FROM openarc_durable.commerce_approvals WHERE action_id = $1',
      [action],
    );
    expect(approval.rows[0]?.status).toBe('pending');
    expect(await counts()).toMatchObject({ reservations: 0 });
    const idem = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM openarc_durable.idempotency_records
        WHERE operation = 'control.commerce_action.approve'`,
    );
    expect(idem.rows[0]?.n).toBe(0);
  });
});

describe('reader coverage: approval and exact agent action', () => {
  it('reads a real pending and then decided approval through the runtime store', async () => {
    const chain = await seedChain(100, { mode: 'always' });
    const requirement = await seedRequirement(chain, 100);
    const action = actionId(100);
    await coreAuthorize(chain, requirement, action, { key: key(100), mutationId: uuid(850100) });
    const pending = await store.readApproval(chain.owner.hash, chain.owner.org, action);
    expect(pending).not.toBeNull();
    expect(pending?.status).toBe('pending');
    expect(pending?.commerceSessionId).toBeTruthy();
    expect(pending?.actionId).toBe(action);

    await coreDecide(chain, action, 'approve', 100);
    const decided = await store.readApproval(chain.owner.hash, chain.owner.org, action);
    expect(decided?.status).toBe('approved');
    expect(decided?.decidedBy).toBe(chain.owner.account);
    expect(decided?.decidedAt).not.toBeNull();
  });

  it('denies approval read to a wrong buyer and returns null for the wrong org', async () => {
    const chain = await seedChain(101, { mode: 'always' });
    const requirement = await seedRequirement(chain, 101);
    const action = actionId(101);
    await coreAuthorize(chain, requirement, action, { key: key(101), mutationId: uuid(850101) });
    const other = await seedOwner(1010, 'owner');
    // Reading the buyer org without membership is denied.
    await expectStoreCode(
      store.readApproval(other.hash, chain.owner.org, action) as Promise<unknown>,
      'CONTROL_ACTION_STORE_FORBIDDEN',
    );
    // Reading under the other's own org yields no approval row.
    await expect(store.readApproval(other.hash, other.org, action)).resolves.toBeNull();
  });

  it('reads only the exact commerce-session-bound action for an agent token', async () => {
    const chain = await seedChain(102);
    const requirement = await seedRequirement(chain, 102);
    const action = actionId(102);
    await coreAuthorize(chain, requirement, action, { key: key(102), mutationId: uuid(850102) });
    const own = await store.readAgentAction(chain.commerceTokenHash, action);
    expect(own.organizationId).toBe(chain.owner.org);
    expect(own.actionId).toBe(action);
    expect(own.item?.actionId).toBe(action);
    expect(own.item?.exposureKey.organizationId).toBe(chain.owner.org);

    // A SECOND VALID token sponsored by the same human/agent must not reveal a
    // foreign action: its exact commerce session is different.
    const secondHandoff = sha256('handoff:second:102');
    const secondToken = sha256('commerce:second:102');
    await commerce.issueCommerceSession(
      chain.owner.hash,
      chain.owner.org,
      { subjectAgentId: chain.agent, policyId: chain.policy, handoffHash: secondHandoff, hashVersion: 1 },
      { idempotencyKey: key(102100), mutationId: uuid(660102) },
    );
    await commerce.exchangeCommerceSession(
      sha256('machine:102'),
      secondHandoff,
      { tokenHash: secondToken, hashVersion: 1 },
      { idempotencyKey: key(102101), mutationId: uuid(660103) },
    );
    const foreign = await store.readAgentAction(secondToken, action);
    expect(foreign.organizationId).toBe(chain.owner.org);
    expect(foreign.item).toBeNull();

    // A rejected (missing) action id still returns the authenticated org.
    const missing = await store.readAgentAction(chain.commerceTokenHash, actionId(999));
    expect(missing.organizationId).toBe(chain.owner.org);
    expect(missing.item).toBeNull();
  });

  it('denies the agent action read once the exact commerce session is revoked', async () => {
    const chain = await seedChain(103);
    const requirement = await seedRequirement(chain, 103);
    const action = actionId(103);
    const mutation = uuid(850103);
    await coreAuthorize(chain, requirement, action, { key: key(103), mutationId: mutation });
    await commerce.revokeCommerceSession(
      chain.owner.hash,
      chain.owner.org,
      (await admin.query<{ session_id: string }>(
        'SELECT session_id FROM openarc_durable.commerce_sessions WHERE organization_id = $1 LIMIT 1',
        [chain.owner.org],
      )).rows[0]!.session_id,
      { idempotencyKey: key(103100), mutationId: uuid(660104) },
    );
    await expectStoreCode(
      store.readAgentAction(chain.commerceTokenHash, action) as Promise<unknown>,
      'CONTROL_ACTION_STORE_FORBIDDEN',
    );
    await expectStoreCode(
      store.readAgentAction(chain.commerceTokenHash, actionId(999)) as Promise<unknown>,
      'CONTROL_ACTION_STORE_FORBIDDEN',
    );
  });
});

// ---------------------------------------------------------------------------
// Original financial acceptance fixtures. Every helper below seeds explicit
// privileged rows as the migrator/superuser fixture role; none of them adds a
// runtime flag, GUC, callback or grant, and none fakes a clock: aged rows carry
// real DB `clock_timestamp()` offsets and every cutoff is the real DB clock.
// ---------------------------------------------------------------------------

/** A second exchanged commerce session over an EXISTING policy root. */
async function seedCommerceSessionFor(
  chain: Chain,
  policy: string,
  seed: number,
): Promise<Chain> {
  const handoffHash = sha256(`handoff:${seed}`);
  const commerceTokenHash = sha256(`commerce:${seed}`);
  await commerce.issueCommerceSession(
    chain.owner.hash,
    chain.owner.org,
    { subjectAgentId: chain.agent, policyId: policy, handoffHash, hashVersion: 1 },
    { idempotencyKey: key(100000 + seed), mutationId: mutationId(100000 + seed) },
  );
  await commerce.exchangeCommerceSession(
    sha256(`machine:${chain.seed}`),
    handoffHash,
    { tokenHash: commerceTokenHash, hashVersion: 1 },
    { idempotencyKey: key(200000 + seed), mutationId: mutationId(200000 + seed) },
  );
  return { ...chain, policy, commerceTokenHash, seed };
}

/** A SECOND policy root for the same buyer org/agent plus its own session. */
async function seedSiblingPolicySession(
  chain: Chain,
  seed: number,
  options: PolicyOptions = {},
): Promise<Chain> {
  const policy = await seedPolicy(chain.owner.org, chain.agent, seed, chain.provider, options);
  return seedCommerceSessionFor(chain, policy, seed);
}

/**
 * A real policy revision: a new immutable version row plus the root's
 * current_revision advancing by exactly one through the accepted SQL8 trigger.
 */
async function seedPolicyRevision(
  chain: Chain,
  revision: string,
  options: PolicyOptions = {},
): Promise<void> {
  const client = await admin.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `INSERT INTO openarc_tenant.budget_policy_versions
         (organization_id, policy_id, revision, subject_agent_id, network_id, asset,
          representation, decimals, per_action_limit, rolling_limit, rolling_window_seconds,
          fee_limit, allowed_provider_ids, allowed_listing_ids, approval_mode,
          approval_threshold, approval_separate_approver, expires_at, digest)
       VALUES ($1, $2, $3, $4, 'eip155:5042002', 'USDC', 'erc20', 6, $5, $6,
               CASE WHEN $6::text IS NULL THEN NULL ELSE '3600' END, $7,
               ARRAY[$8]::text[], ARRAY[]::text[], $9, $10, $11,
               clock_timestamp() + ($12)::interval, 'sha256:' || repeat('a', 64))`,
      [
        chain.owner.org,
        chain.policy,
        revision,
        chain.agent,
        options.perActionLimit ?? '5000000',
        options.rollingLimit === undefined ? '5000000' : options.rollingLimit,
        options.feeLimit ?? '0',
        chain.provider,
        options.mode ?? 'none',
        options.threshold ?? null,
        options.separateApprover ?? false,
        options.expiresOffset ?? '1 hour',
      ],
    );
    await client.query(
      `UPDATE openarc_tenant.budget_policy_roots
          SET current_revision = $3, updated_at = clock_timestamp()
        WHERE organization_id = $1 AND policy_id = $2`,
      [chain.owner.org, chain.policy, revision],
    );
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

function readExposureRow(chain: Chain, policy = chain.policy) {
  return migrator.query<Record<string, string | null>>(
    `SELECT * FROM openarc_durable.read_commerce_exposure($1, $2, $3, $4)`,
    [chain.owner.hash, chain.owner.org, chain.agent, policy],
  );
}

/**
 * Privileged committed-evidence fixture: resolve an existing held reservation to
 * `committed` and append its single immutable committed budget event at a real
 * DB-clock offset. There is no runtime helper for this transition in DB10.
 */
async function commitReservationFixture(
  chain: Chain,
  action: string,
  eventId: string,
  age: string,
): Promise<void> {
  const updated = await admin.query(
    `UPDATE openarc_durable.budget_reservations
        SET status = 'committed', resolved_at = clock_timestamp()
      WHERE organization_id = $1 AND action_id = $2 AND status = 'held'`,
    [chain.owner.org, action],
  );
  expect(updated.rowCount).toBe(1);
  const inserted = await admin.query(
    `INSERT INTO openarc_durable.budget_events (
       organization_id, event_id, action_id, reservation_id, subject_agent_id, network_id,
       asset, representation, decimals, amount_atomic, event_kind, event_time)
     SELECT r.organization_id, $3::uuid, r.action_id, r.reservation_id, r.subject_agent_id,
            r.network_id, r.asset, r.representation, r.decimals, r.debit_atomic, 'committed',
            clock_timestamp() - ($4)::interval
       FROM openarc_durable.budget_reservations r
      WHERE r.organization_id = $1 AND r.action_id = $2`,
    [chain.owner.org, action, eventId, age],
  );
  expect(inserted.rowCount).toBe(1);
}

async function ageReservationFixture(
  chain: Chain,
  action: string,
  status: 'claimed' | 'unknown',
  age: string,
): Promise<void> {
  const updated = await admin.query(
    `UPDATE openarc_durable.budget_reservations
        SET status = $3, claimed_at = clock_timestamp() - ($4)::interval
      WHERE organization_id = $1 AND action_id = $2 AND status = 'held'`,
    [chain.owner.org, action, status, age],
  );
  expect(updated.rowCount).toBe(1);
}

describe('shared stable exposure across policy roots and commerce sessions', () => {
  it('shares one exposure row so a second root/session cannot evade the first reservation', async () => {
    const chain = await seedChain(200, { rollingLimit: '1500000', perActionLimit: '1200000' });
    const first = await coreAuthorize(chain, await seedRequirement(chain, 200), actionId(200), {
      key: key(2001),
      mutationId: uuid(852001),
    });
    expect(first.rows[0]).toMatchObject({
      out_status: 'reserved_not_granted',
      out_policy_id: chain.policy,
      out_debit_atomic: '1000000',
    });

    // SQL8 allows at most one ACTIVE root per org/agent, so a second root is
    // reached by pausing the first and creating a new one. Rotating the policy
    // root AND the commerce session is exactly the evasion this must block.
    await admin.query(
      `UPDATE openarc_tenant.budget_policy_roots
          SET status = 'paused', updated_at = clock_timestamp()
        WHERE organization_id = $1 AND policy_id = $2`,
      [chain.owner.org, chain.policy],
    );
    const sibling = await seedSiblingPolicySession(chain, 210, {
      rollingLimit: '1500000',
      perActionLimit: '1200000',
    });
    // Two genuinely different policy roots and two different exchanged sessions.
    expect(sibling.policy).not.toBe(chain.policy);
    expect(sibling.commerceTokenHash).not.toBe(chain.commerceTokenHash);
    const sessions = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM openarc_durable.commerce_sessions
        WHERE organization_id = $1 AND exchanged_at IS NOT NULL AND revoked_at IS NULL`,
      [chain.owner.org],
    );
    expect(sessions.rows[0]?.n).toBe(2);
    const roots = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM openarc_tenant.budget_policy_roots
        WHERE organization_id = $1 AND subject_agent_id = $2`,
      [chain.owner.org, chain.agent],
    );
    expect(roots.rows[0]?.n).toBe(2);

    // The SECOND root/session sees the SAME exposure: 1000000 held + 1000000
    // projected exceeds its own 1500000 rolling cap.
    const denied = await rawError(
      coreAuthorize(sibling, await seedRequirement(sibling, 210), actionId(210), {
        key: key(2101),
        mutationId: uuid(852101),
      }),
    );
    expect(denied.code).toBe('P0D12');
    expect(await counts()).toMatchObject({ actions: 1, reservations: 1, approvals: 0 });

    // Exactly ONE stable exposure row, and both policy windows report it.
    const locks = await admin.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM openarc_durable.commerce_exposure_locks',
    );
    expect(locks.rows[0]?.n).toBe(1);
    // The NEW root's window reports the reservation made under the OLD root.
    const exposure = await readExposureRow(chain, sibling.policy);
    expect(exposure.rows[0]).toMatchObject({
      out_policy_id: sibling.policy,
      out_subject_agent_id: chain.agent,
      out_committed_atomic: '0',
      out_unresolved_atomic: '1000000',
      out_total_atomic: '1000000',
      out_available_atomic: '500000',
      out_deficit_atomic: '0',
    });
    // The reservation itself is still bound to the ORIGINAL root's action.
    const held = await admin.query<{ policy_id: string; status: string }>(
      `SELECT a.policy_id, r.status
         FROM openarc_durable.budget_reservations r
         JOIN openarc_durable.commerce_actions a
           ON a.organization_id = r.organization_id AND a.action_id = r.action_id`,
    );
    expect(held.rows).toEqual([{ policy_id: chain.policy, status: 'held' }]);

    // The exposure identity carries NO policy root/revision/session field.
    const pk = await admin.query<{ column_name: string }>(
      `SELECT a.attname AS column_name
         FROM pg_index i
         JOIN pg_class c ON c.oid = i.indrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
         JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY (i.indkey)
        WHERE n.nspname = 'openarc_durable' AND c.relname = 'commerce_exposure_locks'
          AND i.indisprimary
        ORDER BY a.attnum`,
    );
    expect(pk.rows.map((row) => row.column_name)).toEqual([
      'organization_id',
      'subject_agent_id',
      'network_id',
      'asset',
      'representation',
      'decimals',
    ]);
  });
});

describe('policy revision lowering the cap never resets spend', () => {
  it('retains exposure and deficit and denies new excess authorization', async () => {
    const chain = await seedChain(201, { rollingLimit: '5000000' });
    await coreAuthorize(chain, await seedRequirement(chain, 2011), actionId(2011), {
      key: key(2011),
      mutationId: uuid(852011),
    });
    await coreAuthorize(chain, await seedRequirement(chain, 2012), actionId(2012), {
      key: key(2012),
      mutationId: uuid(852012),
    });
    const before = await readExposureRow(chain);
    expect(before.rows[0]).toMatchObject({
      out_policy_revision: '1',
      out_total_atomic: '2000000',
      out_available_atomic: '3000000',
      out_deficit_atomic: '0',
    });

    // A REAL revision: a new immutable version row, root advanced by exactly one.
    await seedPolicyRevision(chain, '2', { rollingLimit: '1000000' });
    const root = await admin.query<{ current_revision: string }>(
      'SELECT current_revision FROM openarc_tenant.budget_policy_roots WHERE policy_id = $1',
      [chain.policy],
    );
    expect(root.rows[0]?.current_revision).toBe('2');

    // Accumulated exposure and the resulting deficit are RETAINED, not reset.
    const after = await readExposureRow(chain);
    expect(after.rows[0]).toMatchObject({
      out_policy_revision: '2',
      out_committed_atomic: '0',
      out_unresolved_atomic: '2000000',
      out_total_atomic: '2000000',
      out_available_atomic: '0',
      out_deficit_atomic: '1000000',
    });

    const denied = await rawError(
      coreAuthorize(chain, await seedRequirement(chain, 2013), actionId(2013), {
        key: key(2013),
        mutationId: uuid(852013),
      }),
    );
    expect(denied.code).toBe('P0D12');
    expect(await counts()).toMatchObject({ actions: 2, reservations: 2 });

    // A brand new commerce session under the revised policy does not reset it.
    const fresh = await seedCommerceSessionFor(chain, chain.policy, 2014);
    expect(fresh.commerceTokenHash).not.toBe(chain.commerceTokenHash);
    const stillDenied = await rawError(
      coreAuthorize(fresh, await seedRequirement(fresh, 2015), actionId(2015), {
        key: key(2015),
        mutationId: uuid(852015),
      }),
    );
    expect(stillDenied.code).toBe('P0D12');
    expect(await counts()).toMatchObject({ actions: 2, reservations: 2 });
    const unchanged = await readExposureRow(fresh);
    expect(unchanged.rows[0]).toMatchObject({
      out_total_atomic: '2000000',
      out_available_atomic: '0',
      out_deficit_atomic: '1000000',
    });
  });
});

describe('fee-inclusive rolling exposure window', () => {
  it('counts only in-window committed rows and every aged claimed/unknown reservation', async () => {
    const chain = await seedChain(202, {
      rollingLimit: '10000000',
      perActionLimit: '2000000',
      feeLimit: '250000',
    });
    const actions: string[] = [];
    for (const n of [1, 2, 3, 4]) {
      const requirement = await seedRequirement(chain, 2020 + n, {
        amountAtomic: '1000000',
        feeAtomic: '250000',
      });
      const action = actionId(2020 + n);
      const result = await coreAuthorize(chain, requirement, action, {
        key: key(2020 + n),
        mutationId: uuid(852020 + n),
      });
      // Fee is inside the per-action debit, not a separate uncounted charge.
      expect(result.rows[0]).toMatchObject({
        out_amount_atomic: '1000000',
        out_fee_atomic: '250000',
        out_debit_atomic: '1250000',
      });
      actions.push(action);
    }

    // Real committed evidence INSIDE and OUTSIDE the (now - 3600s, now] window.
    await commitReservationFixture(chain, actions[0]!, uuid(880001), '10 minutes');
    await commitReservationFixture(chain, actions[1]!, uuid(880002), '2 hours');
    // Aged claimed/unknown reservations must NEVER leave exposure.
    await ageReservationFixture(chain, actions[2]!, 'claimed', '10 days');
    await ageReservationFixture(chain, actions[3]!, 'unknown', '30 days');

    // The aged committed row really exists and really is outside the window by
    // the DB clock; nothing was deleted to make the total come out right.
    const events = await admin.query<{ total: string; n: number; aged: number }>(
      `SELECT coalesce(sum(amount_atomic::numeric), 0)::text AS total,
              count(*)::int AS n,
              count(*) FILTER (
                WHERE event_time <= clock_timestamp() - make_interval(secs => 3600))::int AS aged
         FROM openarc_durable.budget_events WHERE event_kind = 'committed'`,
    );
    expect(events.rows[0]).toMatchObject({ total: '2500000', n: 2, aged: 1 });

    const exposure = await readExposureRow(chain);
    expect(exposure.rows[0]).toMatchObject({
      out_window_seconds: '3600',
      out_committed_atomic: '1250000',
      out_unresolved_atomic: '2500000',
      out_total_atomic: '3750000',
      out_available_atomic: '6250000',
      out_deficit_atomic: '0',
    });
    const view = await store.readExposure(
      chain.owner.hash,
      chain.owner.org,
      chain.agent,
      chain.policy,
    );
    expect(view).toMatchObject({
      windowSeconds: '3600',
      committedAtomic: '1250000',
      unresolvedAtomic: '2500000',
      totalExposureAtomic: '3750000',
      availableAtomic: '6250000',
      deficitAtomic: '0',
    });

    // The authorize path applies the same fee-inclusive arithmetic and its own
    // fee ceiling: one atomic unit above the fee limit is denied.
    const overFee = await rawError(
      coreAuthorize(
        chain,
        await seedRequirement(chain, 2029, { amountAtomic: '1000000', feeAtomic: '250001' }),
        actionId(2029),
        { key: key(2029), mutationId: uuid(852029) },
      ),
    );
    expect(overFee.code).toBe('P0D12');
    expect(await counts()).toMatchObject({ actions: 4, reservations: 4, events: 2 });
  });
});

/**
 * Bounded-completeness fixtures. Synthetic rows are bulk-seeded as the migrator
 * fixture role ONLY to reach the accounting bound; every row mirrors a real
 * committed action and no constraint, grant or check is relaxed to admit them.
 */
const SYNTHETIC_ACTION_UUID = '41000000-0000-4000-8000-';
const SYNTHETIC_EVENT_UUID = '42000000-0000-4000-8000-';

async function bulkSeedSyntheticExposure(
  chain: Chain,
  template: string,
  from: number,
  to: number,
  kind: 'committed' | 'held',
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
            'openarc:action:' || $5 || lpad(i::text, 12, '0'),
            a.subject_agent_id, a.parent_human_account_id, a.commerce_session_id,
            a.agent_session_id, a.credential_id, a.policy_id, a.policy_revision,
            a.seller_organization_id, a.provider_id, a.listing_id, a.listing_version,
            a.requirement_id, a.requirement_digest, a.network_id, a.asset, a.representation,
            a.decimals, a.amount_atomic, a.fee_atomic, a.debit_atomic, a.request_digest,
            a.source_kind, 'reserved_not_granted',
            'openarc:reservation:' || $5 || lpad(i::text, 12, '0'),
            NULL, a.created_at, a.updated_at, a.expires_at
       FROM openarc_durable.commerce_actions a, generate_series($3::int, $4::int) AS i
      WHERE a.organization_id = $1 AND a.action_id = $2`,
    [chain.owner.org, template, from, to, SYNTHETIC_ACTION_UUID],
  );
  expect(actions.rowCount).toBe(expected);
  const reservations = await admin.query(
    `INSERT INTO openarc_durable.budget_reservations (
       organization_id, reservation_id, action_id, subject_agent_id, network_id, asset,
       representation, decimals, debit_atomic, source_kind, status, created_at, claimed_at, resolved_at)
     SELECT a.organization_id, a.reservation_id, a.action_id, a.subject_agent_id, a.network_id,
            a.asset, a.representation, a.decimals, a.debit_atomic, a.source_kind, $3,
            a.created_at, NULL,
            CASE WHEN $3 = 'committed' THEN clock_timestamp() ELSE NULL END
       FROM openarc_durable.commerce_actions a
      WHERE a.organization_id = $1 AND a.action_id LIKE 'openarc:action:' || $2 || '%'
        AND NOT EXISTS (
          SELECT 1 FROM openarc_durable.budget_reservations r
           WHERE r.organization_id = a.organization_id AND r.action_id = a.action_id)`,
    [chain.owner.org, SYNTHETIC_ACTION_UUID, kind],
  );
  expect(reservations.rowCount).toBe(expected);
  if (kind === 'committed') {
    const events = await admin.query(
      `INSERT INTO openarc_durable.budget_events (
         organization_id, event_id, action_id, reservation_id, subject_agent_id, network_id,
         asset, representation, decimals, amount_atomic, event_kind, event_time)
       SELECT r.organization_id,
              ($3 || substring(r.action_id FROM 40))::uuid,
              r.action_id, r.reservation_id, r.subject_agent_id, r.network_id, r.asset,
              r.representation, r.decimals, r.debit_atomic, 'committed', clock_timestamp()
         FROM openarc_durable.budget_reservations r
        WHERE r.organization_id = $1 AND r.action_id LIKE 'openarc:action:' || $2 || '%'
          AND NOT EXISTS (
            SELECT 1 FROM openarc_durable.budget_events b
             WHERE b.organization_id = r.organization_id AND b.action_id = r.action_id
               AND b.event_kind = 'committed')`,
      [chain.owner.org, SYNTHETIC_ACTION_UUID, SYNTHETIC_EVENT_UUID],
    );
    expect(events.rowCount).toBe(expected);
  }
}

async function durabilityCounts(): Promise<Record<string, number>> {
  const result = await admin.query<Record<string, number>>(
    `SELECT (SELECT count(*)::int FROM openarc_durable.idempotency_records
              WHERE operation LIKE 'control.commerce_action%') AS idempotency,
            (SELECT count(*)::int FROM openarc_durable.audit_events
              WHERE operation LIKE 'control.commerce_action%') AS audit,
            (SELECT count(*)::int FROM openarc_durable.outbox_events
              WHERE event_type LIKE 'control.commerce_action%') AS outbox`,
  );
  return result.rows[0] as Record<string, number>;
}

// These two cases seed 4,096-4,097 synthetic rows across actions, reservations and
// budget events, each firing its row triggers, on top of the per-test migration.
// They carry an explicit bulk-test timeout like the grant and adversarial suites;
// under vitest's 5 s default they timed out on the slower public CI runner, and
// the timed-out transaction then deadlocked the next test's schema reset. No
// assertion depends on the timeout.
describe('bounded completeness: 4096 accepted, 4097 fails closed', () => {
  it('bounds the COMMITTED exposure source and writes nothing after overflow', async () => {
    const chain = await seedChain(203, { rollingLimit: '99999999999999' });
    const template = actionId(203);
    await coreAuthorize(chain, await seedRequirement(chain, 203), template, {
      key: key(2031),
      mutationId: uuid(852031),
    });
    // Resolve the one real reservation so ONLY the committed source is bounded.
    await commitReservationFixture(chain, template, uuid(880203), '1 minute');
    await bulkSeedSyntheticExposure(chain, template, 1, 4095, 'committed');
    const at4096 = await admin.query<{ committed: number; unresolved: number }>(
      `SELECT (SELECT count(*)::int FROM openarc_durable.budget_events
                WHERE event_kind = 'committed') AS committed,
              (SELECT count(*)::int FROM openarc_durable.budget_reservations
                WHERE status IN ('held', 'claimed', 'unknown')) AS unresolved`,
    );
    expect(at4096.rows[0]).toMatchObject({ committed: 4096, unresolved: 0 });

    // Exactly 4096 is ACCEPTED and returns an exact total.
    const accepted = await store.readExposure(
      chain.owner.hash,
      chain.owner.org,
      chain.agent,
      chain.policy,
    );
    expect(accepted).toMatchObject({
      committedAtomic: '4096000000',
      unresolvedAtomic: '0',
      totalExposureAtomic: '4096000000',
    });

    // 4097 is REJECTED: the reader fails closed with no partial available value.
    await bulkSeedSyntheticExposure(chain, template, 4096, 4096, 'committed');
    const overflowed = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM openarc_durable.budget_events WHERE event_kind = 'committed'`,
    );
    expect(overflowed.rows[0]?.n).toBe(4097);
    await expectStoreCode(
      store.readExposure(chain.owner.hash, chain.owner.org, chain.agent, chain.policy),
      'CONTROL_ACTION_STORE_UNAVAILABLE',
    );
    expect((await rawError(readExposureRow(chain))).code).toBe('P0D11');

    // The authorize path also fails closed, and writes NO business or durable row.
    const requirement = await seedRequirement(chain, 2032);
    const businessBefore = await counts();
    const durableBefore = await durabilityCounts();
    const denied = await rawError(
      coreAuthorize(chain, requirement, actionId(2032), { key: key(2032), mutationId: uuid(852032) }),
    );
    expect(denied.code).toBe('P0D11');
    expect(await counts()).toEqual(businessBefore);
    expect(await durabilityCounts()).toEqual(durableBefore);
    const attempted = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM openarc_durable.commerce_actions WHERE action_id = $1`,
      [actionId(2032)],
    );
    expect(attempted.rows[0]?.n).toBe(0);
  }, 60000);

  it('bounds the UNRESOLVED exposure source and writes nothing after overflow', async () => {
    const chain = await seedChain(204, { rollingLimit: '99999999999999' });
    const template = actionId(204);
    await coreAuthorize(chain, await seedRequirement(chain, 204), template, {
      key: key(2041),
      mutationId: uuid(852041),
    });
    // The one real reservation stays held; 4095 synthetic held rows reach 4096.
    await bulkSeedSyntheticExposure(chain, template, 1, 4095, 'held');
    const at4096 = await admin.query<{ committed: number; unresolved: number }>(
      `SELECT (SELECT count(*)::int FROM openarc_durable.budget_events
                WHERE event_kind = 'committed') AS committed,
              (SELECT count(*)::int FROM openarc_durable.budget_reservations
                WHERE status IN ('held', 'claimed', 'unknown')) AS unresolved`,
    );
    expect(at4096.rows[0]).toMatchObject({ committed: 0, unresolved: 4096 });

    const accepted = await store.readExposure(
      chain.owner.hash,
      chain.owner.org,
      chain.agent,
      chain.policy,
    );
    expect(accepted).toMatchObject({
      committedAtomic: '0',
      unresolvedAtomic: '4096000000',
      totalExposureAtomic: '4096000000',
    });

    await bulkSeedSyntheticExposure(chain, template, 4096, 4096, 'held');
    const overflowed = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM openarc_durable.budget_reservations
        WHERE status IN ('held', 'claimed', 'unknown')`,
    );
    expect(overflowed.rows[0]?.n).toBe(4097);
    await expectStoreCode(
      store.readExposure(chain.owner.hash, chain.owner.org, chain.agent, chain.policy),
      'CONTROL_ACTION_STORE_UNAVAILABLE',
    );
    expect((await rawError(readExposureRow(chain))).code).toBe('P0D11');

    const requirement = await seedRequirement(chain, 2042);
    const businessBefore = await counts();
    const durableBefore = await durabilityCounts();
    const denied = await rawError(
      coreAuthorize(chain, requirement, actionId(2042), { key: key(2042), mutationId: uuid(852042) }),
    );
    expect(denied.code).toBe('P0D11');
    expect(await counts()).toEqual(businessBefore);
    expect(await durabilityCounts()).toEqual(durableBefore);
    const attempted = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM openarc_durable.commerce_actions WHERE action_id = $1`,
      [actionId(2042)],
    );
    expect(attempted.rows[0]?.n).toBe(0);
  }, 60000);
});

/** The already-seeded owner identity for a known seed (no new rows). */
function ownerRef(seed: number): Owner {
  return { account: accountId(seed), hash: sha256(`session:${seed}`), org: orgId(seed) };
}

/**
 * A REAL second listing version through the accepted market stores, reviewed by
 * the real moderator seeded with the listing. `approved` also publishes it, so
 * the listing's current active version genuinely supersedes version 1.
 */
async function seedListingVersionTwo(
  seller: Owner,
  listing: string,
  sellerSeed: number,
  decision: 'approved' | 'rejected',
): Promise<void> {
  await market.createListingVersion(
    seller.hash,
    seller.org,
    listing,
    { expectedLatestVersion: '1', content: { ...content(), termsRevision: 'terms-v2' } },
    { idempotencyKey: key(sellerSeed + 11000), mutationId: mutationId(sellerSeed + 11000) },
  );
  const reviewState = await admin.query<{ updated_at: string }>(
    `SELECT to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS updated_at
       FROM openarc_tenant.listing_version_states
      WHERE organization_id = $1 AND listing_id = $2 AND version = '2'`,
    [seller.org, listing],
  );
  await lifecycle.recordOriginReview(
    sha256(`session:${sellerSeed + 8000}`),
    seller.org,
    listing,
    '2',
    {
      expectedUpdatedAt: reviewState.rows[0]!.updated_at,
      decision,
      reviewedEndpointDigest: reviewedEndpointDigest({
        listingId: listing,
        version: '2',
        origin: ORIGIN,
        path: PATH,
      }),
      reasonCode: 'manual_review',
      reasonDigest: null,
    },
    { idempotencyKey: key(sellerSeed + 12000), mutationId: mutationId(sellerSeed + 12000) },
  );
  if (decision !== 'approved') return;
  const publishState = await admin.query<{ updated_at: string }>(
    `SELECT to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS updated_at
       FROM openarc_tenant.listing_version_states
      WHERE organization_id = $1 AND listing_id = $2 AND version = '2'`,
    [seller.org, listing],
  );
  await lifecycle.publishListingVersion(
    seller.hash,
    seller.org,
    listing,
    '2',
    { expectedUpdatedAt: publishState.rows[0]!.updated_at, expectedActiveVersion: '1' },
    { idempotencyKey: key(sellerSeed + 13000), mutationId: mutationId(sellerSeed + 13000) },
  );
}

/**
 * A privileged attempt to write an action row that mirrors a real committed one
 * but tampers with the immutable requirement price/identity binding.
 */
function cloneActionRow(
  org: string,
  template: string,
  newAction: string,
  overrides: { amountAtomic?: string; requirementDigest?: string; listingVersion?: string },
): Promise<unknown> {
  return admin.query(
    `INSERT INTO openarc_durable.commerce_actions (
       organization_id, action_id, subject_agent_id, parent_human_account_id, commerce_session_id,
       agent_session_id, credential_id, policy_id, policy_revision, seller_organization_id,
       provider_id, listing_id, listing_version, requirement_id, requirement_digest, network_id,
       asset, representation, decimals, amount_atomic, fee_atomic, debit_atomic, request_digest,
       source_kind, status, reservation_id, approval_id, created_at, updated_at, expires_at)
     SELECT a.organization_id, $3, a.subject_agent_id, a.parent_human_account_id,
            a.commerce_session_id, a.agent_session_id, a.credential_id, a.policy_id,
            a.policy_revision, a.seller_organization_id, a.provider_id, a.listing_id,
            COALESCE($6::text, a.listing_version), a.requirement_id,
            COALESCE($5::text, a.requirement_digest), a.network_id, a.asset, a.representation,
            a.decimals, COALESCE($4::text, a.amount_atomic), a.fee_atomic,
            (COALESCE($4::text, a.amount_atomic)::numeric + a.fee_atomic::numeric)::text,
            a.request_digest, a.source_kind, 'reserved_not_granted',
            'openarc:reservation:' || substring($3 FROM 16), NULL,
            a.created_at, a.updated_at, a.expires_at
       FROM openarc_durable.commerce_actions a
      WHERE a.organization_id = $1 AND a.action_id = $2`,
    [
      org,
      template,
      newAction,
      overrides.amountAtomic ?? null,
      overrides.requirementDigest ?? null,
      overrides.listingVersion ?? null,
    ],
  );
}

/**
 * Full durable snapshot of every action/reservation/approval/budget-event row
 * plus the action idempotency/audit/outbox rows. A rollback proof compares the
 * WHOLE snapshot, not just an error code.
 */
async function durableSnapshot(): Promise<unknown> {
  const result = await admin.query<{ snapshot: unknown }>(
    `SELECT jsonb_build_object(
        'actions', (SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY a.action_id), '[]'::jsonb)
                      FROM openarc_durable.commerce_actions a),
        'reservations', (SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.reservation_id), '[]'::jsonb)
                      FROM openarc_durable.budget_reservations r),
        'approvals', (SELECT coalesce(jsonb_agg(to_jsonb(ap) ORDER BY ap.approval_id), '[]'::jsonb)
                      FROM openarc_durable.commerce_approvals ap),
        'events', (SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY b.event_id), '[]'::jsonb)
                      FROM openarc_durable.budget_events b),
        'idempotency', (SELECT coalesce(jsonb_agg(to_jsonb(i) ORDER BY i.operation, i.key_hash), '[]'::jsonb)
                      FROM openarc_durable.idempotency_records i
                     WHERE i.operation LIKE 'control.commerce_action%'),
        'audit', (SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.mutation_id), '[]'::jsonb)
                      FROM openarc_durable.audit_events e
                     WHERE e.operation LIKE 'control.commerce_action%'),
        'outbox', (SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY o.mutation_id), '[]'::jsonb)
                      FROM openarc_durable.outbox_events o
                     WHERE o.event_type LIKE 'control.commerce_action%')
      ) AS snapshot`,
  );
  return result.rows[0]?.snapshot;
}

/** Injects a durable outbox failure for the four action events only. */
async function withBlockedActionOutbox<T>(run: () => Promise<T>): Promise<T> {
  await admin.query(
    `CREATE FUNCTION openarc_durable.test_block_action_outbox_injection() RETURNS trigger
     LANGUAGE plpgsql SET search_path = pg_catalog AS $$
     BEGIN
       IF NEW.event_type LIKE 'control.commerce_action%' THEN
         RAISE EXCEPTION 'test_outbox_blocked' USING ERRCODE = '23514';
       END IF;
       RETURN NEW;
     END; $$`,
  );
  await admin.query(
    `CREATE TRIGGER test_block_action_outbox_injection BEFORE INSERT ON openarc_durable.outbox_events
       FOR EACH ROW EXECUTE FUNCTION openarc_durable.test_block_action_outbox_injection()`,
  );
  try {
    return await run();
  } finally {
    await admin
      .query('DROP TRIGGER IF EXISTS test_block_action_outbox_injection ON openarc_durable.outbox_events')
      .catch(() => {});
    await admin
      .query('DROP FUNCTION IF EXISTS openarc_durable.test_block_action_outbox_injection()')
      .catch(() => {});
  }
}

describe('durability failure injection for approve, reject and cancel', () => {
  it('rolls back an approve and leaves every durable row byte-identical', async () => {
    const chain = await seedChain(205, { mode: 'always' });
    const action = actionId(205);
    await coreAuthorize(chain, await seedRequirement(chain, 205), action, {
      key: key(2051),
      mutationId: uuid(852051),
    });
    const before = await durableSnapshot();
    const error = await withBlockedActionOutbox(() =>
      rawError(coreDecide(chain, action, 'approve', 2052)),
    );
    expect(error.code).toBe('23514');
    expect(await durableSnapshot()).toEqual(before);
    const state = await admin.query<{ status: string; approval: string; reservations: number }>(
      `SELECT a.status,
              (SELECT ap.status FROM openarc_durable.commerce_approvals ap
                WHERE ap.action_id = a.action_id) AS approval,
              (SELECT count(*)::int FROM openarc_durable.budget_reservations) AS reservations
         FROM openarc_durable.commerce_actions a WHERE a.action_id = $1`,
      [action],
    );
    expect(state.rows[0]).toMatchObject({
      status: 'pending_approval',
      approval: 'pending',
      reservations: 0,
    });
  });

  it('rolls back a reject and leaves every durable row byte-identical', async () => {
    const chain = await seedChain(206, { mode: 'always' });
    const action = actionId(206);
    await coreAuthorize(chain, await seedRequirement(chain, 206), action, {
      key: key(2061),
      mutationId: uuid(852061),
    });
    const before = await durableSnapshot();
    const error = await withBlockedActionOutbox(() =>
      rawError(coreDecide(chain, action, 'reject', 2062)),
    );
    expect(error.code).toBe('23514');
    expect(await durableSnapshot()).toEqual(before);
    const approval = await admin.query<{ status: string; decided_by: string | null }>(
      'SELECT status, decided_by FROM openarc_durable.commerce_approvals WHERE action_id = $1',
      [action],
    );
    expect(approval.rows[0]).toMatchObject({ status: 'pending', decided_by: null });
    // The blocked decision must still be possible afterwards: nothing consumed.
    const decided = await coreDecide(chain, action, 'reject', 2063);
    expect(decided.rows[0]?.out_status).toBe('rejected');
  });

  it('rolls back a cancel and leaves the held reservation and events untouched', async () => {
    const chain = await seedChain(207);
    const action = actionId(207);
    await coreAuthorize(chain, await seedRequirement(chain, 207), action, {
      key: key(2071),
      mutationId: uuid(852071),
    });
    const before = await durableSnapshot();
    const error = await withBlockedActionOutbox(() => rawError(coreCancel(chain, action, 2072)));
    expect(error.code).toBe('23514');
    expect(await durableSnapshot()).toEqual(before);
    const reservation = await admin.query<{ status: string; resolved_at: string | null }>(
      'SELECT status, resolved_at FROM openarc_durable.budget_reservations WHERE action_id = $1',
      [action],
    );
    expect(reservation.rows[0]).toMatchObject({ status: 'held', resolved_at: null });
    expect(await counts()).toMatchObject({ events: 0 });
    // The cancellation is still available once durability is healthy.
    const cancelled = await coreCancel(chain, action, 2073);
    expect(cancelled.rows[0]?.out_status).toBe('cancelled');
  });
});

/**
 * A test pool that awaits the REAL PostgreSQL COMMIT and only then raises a
 * bounded transport failure. This is an EXPLICITLY INJECTED post-commit
 * transport fault, NOT a real random TCP fault: the commit above genuinely
 * reached and was applied by PostgreSQL before the error is raised.
 */
interface InjectedCommitFault {
  readonly pool: TenantPool;
  readonly statements: string[];
  commits: number;
  destroyed: boolean | undefined;
  backendPid: number | undefined;
}

function injectPostCommitTransportFault(source: Pool): InjectedCommitFault {
  const state = {
    statements: [] as string[],
    commits: 0,
    destroyed: undefined as boolean | undefined,
    backendPid: undefined as number | undefined,
  };
  const pool: TenantPool = {
    async connect(): Promise<TenantClient> {
      const client = await source.connect();
      state.backendPid = (client as unknown as { processID?: number }).processID;
      return {
        async query<T extends Record<string, unknown>>(
          text: string,
          values?: unknown[],
        ): Promise<TenantQueryResult<T>> {
          state.statements.push(text);
          const result = await client.query<T>(text, values);
          if (text === 'COMMIT') {
            state.commits += 1;
            const fault = new Error('injected post-commit transport fault');
            (fault as { code?: string }).code = 'ECONNRESET';
            throw fault;
          }
          return { rows: result.rows, rowCount: result.rowCount };
        },
        release(destroy?: boolean): void {
          state.destroyed = destroy === true;
          client.release(destroy);
        },
      };
    },
  };
  // The SAME mutable state object is returned so later mutations are visible.
  return Object.assign(state, { pool });
}

describe('injected post-commit transport uncertainty', () => {
  it('returns OUTCOME_UNKNOWN, destroys the connection and commits exactly once', async () => {
    const chain = await seedChain(208);
    const action = actionId(208);
    await coreAuthorize(chain, await seedRequirement(chain, 208), action, {
      key: key(2081),
      mutationId: uuid(852081),
    });

    const fault = injectPostCommitTransportFault(tenant);
    const faulted = new ControlActionStore(fault.pool);
    const cancelMutation = uuid(872081);
    await expectStoreCode(
      faulted.cancelCommerceAction(chain.owner.hash, chain.owner.org, action, {
        idempotencyKey: key(2082),
        mutationId: cancelMutation,
      }) as Promise<unknown>,
      'CONTROL_ACTION_STORE_OUTCOME_UNKNOWN',
    );

    // Exactly one COMMIT, exactly one cancel statement: no automatic retry and
    // no blind resend after the uncertain commit.
    expect(fault.commits).toBe(1);
    expect(
      fault.statements.filter((text) => text.includes('cancel_commerce_action')),
    ).toHaveLength(1);
    expect(fault.statements.filter((text) => text === 'COMMIT')).toHaveLength(1);
    expect(fault.statements.filter((text) => text === 'ROLLBACK')).toHaveLength(0);
    // The connection was released for DESTRUCTION, and the real backend is gone.
    expect(fault.destroyed).toBe(true);
    expect(typeof fault.backendPid).toBe('number');
    const deadline = Date.now() + 10_000;
    let alive = 1;
    for (;;) {
      const probe = await admin.query<{ n: number }>(
        'SELECT count(*)::int AS n FROM pg_stat_activity WHERE pid = $1',
        [fault.backendPid],
      );
      alive = probe.rows[0]?.n ?? 1;
      if (alive === 0) break;
      if (Date.now() > deadline) break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    expect(alive).toBe(0);

    // No raw token or session hash ever appears in the recorded statements.
    const recorded = fault.statements.join('\n');
    expect(recorded).not.toContain(chain.owner.hash);
    expect(recorded).not.toContain(chain.commerceTokenHash);
    expect(recorded).not.toMatch(/\b[0-9a-f]{64}\b/);

    // An INDEPENDENT connection observes EXACTLY ONE committed change.
    const state = await admin.query<{
      action_status: string;
      reservation_status: string;
      released: number;
      events: number;
      idem: number;
      audit: number;
      outbox: number;
    }>(
      `SELECT a.status AS action_status,
              (SELECT r.status FROM openarc_durable.budget_reservations r
                WHERE r.action_id = a.action_id) AS reservation_status,
              (SELECT count(*)::int FROM openarc_durable.budget_events b
                WHERE b.action_id = a.action_id AND b.event_kind = 'released') AS released,
              (SELECT count(*)::int FROM openarc_durable.budget_events) AS events,
              (SELECT count(*)::int FROM openarc_durable.idempotency_records i
                WHERE i.operation = 'control.commerce_action.cancel') AS idem,
              (SELECT count(*)::int FROM openarc_durable.audit_events e
                WHERE e.operation = 'control.commerce_action.cancel') AS audit,
              (SELECT count(*)::int FROM openarc_durable.outbox_events o
                WHERE o.event_type = 'control.commerce_action.cancelled') AS outbox
         FROM openarc_durable.commerce_actions a WHERE a.action_id = $1`,
      [action],
    );
    expect(state.rows[0]).toMatchObject({
      action_status: 'cancelled',
      reservation_status: 'released',
      released: 1,
      events: 1,
      idem: 1,
      audit: 1,
      outbox: 1,
    });

    // The runtime store on its own healthy pool recovers the single receipt.
    const status = await store.getHumanMutationStatus(
      chain.owner.hash,
      chain.owner.org,
      cancelMutation,
    );
    expect(status.status).toBe('committed');
    if (status.status === 'committed') {
      expect(status.receipt).toMatchObject({
        operation: 'control.commerce_action.cancel',
        resourceType: 'commerce_action',
        resourceId: action,
        mutationId: cancelMutation,
      });
    }
  });
});

describe('human and agent mutation status projections', () => {
  it('returns the human cancel receipt only for the exact human session context', async () => {
    const chain = await seedChain(211);
    const action = actionId(211);
    const authorizeMutation = uuid(852111);
    await coreAuthorize(chain, await seedRequirement(chain, 211), action, {
      key: key(2111),
      mutationId: authorizeMutation,
    });
    const cancelMutation = uuid(872111);
    await migrator.query(
      `SELECT * FROM openarc_durable.cancel_commerce_action_core($1, $2, $3, $4::uuid, $5, $6, $7)`,
      [
        chain.owner.hash,
        chain.owner.org,
        action,
        cancelMutation,
        createHash('sha256').update(key(2112), 'utf8').digest('hex'),
        HEX_A,
        createHash('sha256')
          .update(
            `openarc.control.commerce_action.cancel.session.v1:${chain.owner.hash}`,
            'utf8',
          )
          .digest('hex'),
      ],
    );

    // The human projection accepts the human operations, never the agent one.
    const human = await store.getHumanMutationStatus(
      chain.owner.hash,
      chain.owner.org,
      cancelMutation,
    );
    expect(human.status).toBe('committed');
    if (human.status === 'committed') {
      expect(human.receipt).toMatchObject({
        operation: 'control.commerce_action.cancel',
        resourceType: 'commerce_action',
        resourceId: action,
      });
    }
    // The agent's authorize mutation is NOT a human receipt.
    await expect(
      store.getHumanMutationStatus(chain.owner.hash, chain.owner.org, authorizeMutation),
    ).resolves.toMatchObject({ status: 'not_found' });
    // The agent projection returns the authorize receipt for its exact token.
    const agent = await store.getAgentMutationStatus(chain.commerceTokenHash, authorizeMutation);
    expect(agent.status).toBe('committed');
    if (agent.status === 'committed') {
      expect(agent.receipt).toMatchObject({
        operation: 'control.commerce_action.authorize',
        resourceId: action,
      });
    }
    // A different current owner in the same org never sees another human's receipt.
    const other = await seedOwner(2113, 'owner');
    await admin.query(
      'INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, $3, $4)',
      [chain.owner.org, other.account, 'operator', 'active'],
    );
    await expect(
      store.getHumanMutationStatus(other.hash, chain.owner.org, cancelMutation),
    ).resolves.toMatchObject({ status: 'not_found' });
  });
});

/** A second CURRENT owner/operator of the buyer org (its own fresh session). */
async function seedSecondDecider(chain: Chain, seed: number): Promise<Owner> {
  const other = await seedOwner(seed, 'owner');
  await admin.query(
    'INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, $3, $4)',
    [chain.owner.org, other.account, 'operator', 'active'],
  );
  return other;
}

describe('replay after target invalidation with a different live decider', () => {
  it('recovers the original approve receipt after the original parent human logs out', async () => {
    const chain = await seedChain(212, { mode: 'always', separateApprover: true });
    const decider = await seedSecondDecider(chain, 2120);
    const decided = actionId(2121);
    const pending = actionId(2122);
    await coreAuthorize(chain, await seedRequirement(chain, 2121), decided, {
      key: key(2121),
      mutationId: uuid(852121),
    });
    await coreAuthorize(chain, await seedRequirement(chain, 2122), pending, {
      key: key(2122),
      mutationId: uuid(852122),
    });
    const original = await coreDecide(chain, decided, 'approve', 2123, decider.hash);
    expect(original.rows[0]).toMatchObject({
      out_replayed: false,
      out_status: 'reserved_not_granted',
      out_decided_by: decider.account,
      out_policy_revision: '1',
    });

    // The ORIGINAL parent human session logs out: the ephemeral auth row is
    // deleted outright (there is no FK keeping it alive for commerce).
    const loggedOut = await admin.query('DELETE FROM openarc_auth.sessions WHERE token_hash = $1', [
      chain.owner.hash,
    ]);
    expect(loggedOut.rowCount).toBe(1);

    // The DIFFERENT still-live decider recovers the ORIGINAL committed receipt
    // through exact-context replay; nothing is decided or reserved again.
    const replay = await coreDecide(chain, decided, 'approve', 2123, decider.hash);
    expect(replay.rows[0]).toMatchObject({
      out_replayed: true,
      out_status: 'reserved_not_granted',
      out_reservation_id: original.rows[0]?.out_reservation_id,
      out_decided_by: decider.account,
    });
    expect(replay.rows[0]?.out_committed_at).toEqual(original.rows[0]?.out_committed_at);
    expect(await counts()).toMatchObject({ reservations: 1, approvals: 2, actions: 2 });

    // A NEW decision on the still-pending sibling action is DENIED: the dead
    // parent authority is never revived for the live decider.
    const denied = await rawError(coreDecide(chain, pending, 'approve', 2124, decider.hash));
    // The gate is the ORIGINAL parent human session lookup in the target
    // actionability assertion, which raises the fixed session-invalid code.
    expect(denied.code).toBe('28000');
    expect(await counts()).toMatchObject({ reservations: 1, approvals: 2 });
    const stillPending = await admin.query<{ status: string }>(
      'SELECT status FROM openarc_durable.commerce_approvals WHERE action_id = $1',
      [pending],
    );
    expect(stillPending.rows[0]?.status).toBe('pending');

    // The fresh caller's OWN authorization stays mandatory, replay included.
    await admin.query(
      `UPDATE openarc_tenant.memberships SET status = 'suspended'
        WHERE organization_id = $1 AND account_id = $2`,
      [chain.owner.org, decider.account],
    );
    const revoked = await rawError(coreDecide(chain, decided, 'approve', 2123, decider.hash));
    expect(revoked.code).toBe('42501');
  });

  it('recovers the original approve receipt after the policy revision changes', async () => {
    const chain = await seedChain(213, { mode: 'always', separateApprover: true });
    const decider = await seedSecondDecider(chain, 2130);
    const decided = actionId(2131);
    const pending = actionId(2132);
    await coreAuthorize(chain, await seedRequirement(chain, 2131), decided, {
      key: key(2131),
      mutationId: uuid(852131),
    });
    await coreAuthorize(chain, await seedRequirement(chain, 2132), pending, {
      key: key(2132),
      mutationId: uuid(852132),
    });
    const original = await coreDecide(chain, decided, 'approve', 2133, decider.hash);
    expect(original.rows[0]).toMatchObject({ out_replayed: false, out_policy_revision: '1' });

    await seedPolicyRevision(chain, '2', { mode: 'always', separateApprover: true });

    const replay = await coreDecide(chain, decided, 'approve', 2133, decider.hash);
    expect(replay.rows[0]).toMatchObject({
      out_replayed: true,
      out_status: 'reserved_not_granted',
      // The receipt keeps the PINNED revision; the replay never re-prices.
      out_policy_revision: '1',
      out_reservation_id: original.rows[0]?.out_reservation_id,
    });
    expect(replay.rows[0]?.out_committed_at).toEqual(original.rows[0]?.out_committed_at);

    const denied = await rawError(coreDecide(chain, pending, 'approve', 2134, decider.hash));
    expect(denied.code).toBe('42501');
    expect(await counts()).toMatchObject({ reservations: 1, approvals: 2 });
  });
});
