import { createHash } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import {
  MarketCatalogStore,
  MarketLifecycleStore,
  MarketStore,
  MarketStoreError,
  TenantStore,
  createDatabasePool,
  loadMigrations,
  migrate,
  reviewedEndpointDigest,
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
 * Real PostgreSQL acceptance for schema7 reviewed lifecycle + public catalog.
 * Runs against the restricted runtime role (openarc_tenant_app). A separate
 * regression block proves provider_admin/provider_developer draft/version and
 * lifecycle writes actually succeed after the migrator UPDATE-policy fix.
 */

function sha256(seed: string): string {
  return createHash('sha256').update(`openarc-lifecycle-test:${seed}`, 'utf8').digest('hex');
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

function providerId(seed: number): string {
  return `openarc:provider:${uuid(seed)}`;
}

function mutationId(seed: number): string {
  return uuid(900000 + seed);
}

function key(seed: number): string {
  return createHash('sha256').update(`lifecycle-key:${seed}`).digest().toString('base64url');
}

function userHandle(seed: number): string {
  return `${sha256(`handle:${seed}`).slice(0, 42)}A`;
}

const ORIGIN = 'https://api.example.com';
const PATH = '/v1/run';

function content(overrides: Record<string, unknown> = {}): Record<string, unknown> {
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
    ...overrides,
  };
}

interface PgError {
  code?: string;
}

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(MarketStoreError);
    expect((error as MarketStoreError).code).toBe(code);
    return;
  }
  throw new Error(`expected MarketStoreError ${code}`);
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
let lifecycle: MarketLifecycleStore;
let catalog: MarketCatalogStore;
let market: MarketStore;

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
  lifecycle = new MarketLifecycleStore(tenant);
  catalog = new MarketCatalogStore(tenant);
  market = new MarketStore(tenant);
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

async function seedProvider(seed: number, org: string, status = 'active'): Promise<string> {
  const id = providerId(seed);
  await admin.query(
    'INSERT INTO openarc_tenant.providers (organization_id, provider_id, display_name, status) VALUES ($1, $2, $3, $4)',
    [org, id, `Provider ${seed}`, status],
  );
  return id;
}

async function seedModerator(seed: number): Promise<{ account: string; hash: string }> {
  const account = await seedAccount(seed);
  const hash = await seedSession(seed, account);
  await admin.query(
    "INSERT INTO openarc_tenant.market_moderator_grants (account_id, status) VALUES ($1, 'active')",
    [account],
  );
  return { account, hash };
}

/**
 * Perform an origin review as an independent moderator (the provider is not a
 * member of the reviewed organization). Seeds a fresh moderator per call by
 * default so tests never accidentally self-review.
 */
async function review(
  org: string,
  listing: string,
  version: string,
  expectedUpdatedAt: string,
  decision: 'approved' | 'rejected',
  digest: string,
  seed: number,
  reasonCode = 'manual_review',
): Promise<{ replayed: boolean }> {
  const moderator = await seedModerator(seed + 8000);
  return lifecycle.recordOriginReview(
    moderator.hash,
    org,
    listing,
    version,
    {
      expectedUpdatedAt,
      decision,
      reviewedEndpointDigest: digest,
      reasonCode,
      reasonDigest: null,
    },
    { idempotencyKey: key(seed + 9000), mutationId: mutationId(seed + 9000) },
  );
}

async function createDraft(
  owner: { readonly org: string; readonly hash: string },
  provider: string,
  seed: number,
): Promise<string> {
  const result = await market.createListingDraft(owner.hash, owner.org, provider, content(), {
    idempotencyKey: key(seed),
    mutationId: mutationId(seed),
  });
  return result.receipt.resourceId;
}

async function createVersion(
  owner: { readonly org: string; readonly hash: string },
  listing: string,
  seed: number,
  expectedLatest = '1',
): Promise<string> {
  const result = await market.createListingVersion(
    owner.hash,
    owner.org,
    listing,
    { expectedLatestVersion: expectedLatest, content: content() },
    { idempotencyKey: key(seed), mutationId: mutationId(seed) },
  );
  return result.receipt.resourceId;
}

async function stateOf(
  org: string,
  listing: string,
  version: string,
): Promise<{ status: string; origin_review_state: string; published_at: string | null; updated_at: string }> {
  const result = await admin.query(
    `SELECT status, origin_review_state,
            to_char(published_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS published_at,
            to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS updated_at
       FROM openarc_tenant.listing_version_states
      WHERE organization_id = $1 AND listing_id = $2 AND version = $3`,
    [org, listing, version],
  );
  const row = result.rows[0];
  if (row === undefined) throw new Error('state missing');
  return row;
}

async function rootOf(org: string, listing: string): Promise<{ active_version: string | null; latest_version: string }> {
  const result = await admin.query(
    `SELECT active_version, latest_version FROM openarc_tenant.listings
      WHERE organization_id = $1 AND listing_id = $2`,
    [org, listing],
  );
  const row = result.rows[0];
  if (row === undefined) throw new Error('root missing');
  return row;
}

async function contentByte(
  org: string,
  listing: string,
  version: string,
): Promise<string> {
  const result = await admin.query<{ digest: string }>(
    `SELECT md5(row_to_json(v)::text) AS digest
       FROM openarc_tenant.listing_versions v
      WHERE organization_id = $1 AND listing_id = $2 AND version = $3`,
    [org, listing, version],
  );
  return result.rows[0]?.digest ?? '';
}

describe('schema7 manifest, ownership and ACLs', () => {
  it('records schema7 and keeps new helpers migrator-owned with a fixed search_path', async () => {
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
            'commit_origin_review', 'commit_lifecycle_transition',
            'lock_moderator_actor', 'read_lifecycle_mutation_status',
            'read_owner_listing', 'list_market_providers',
            'get_moderator_listing_version',
            'list_public_listings', 'get_public_listing', 'get_public_provider'
          )
        ORDER BY p.proname`,
    );
    expect(helpers.rows).toHaveLength(10);
    expect(
      helpers.rows.every(
        (row) =>
          row.owner === 'openarc_migrator' &&
          row.secdef === true &&
          row.config.includes('search_path=pg_catalog'),
      ),
    ).toBe(true);
  });

  it('zeroes seeded moderator grants and hides new tables from the runtime', async () => {
    const grants = await admin.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM openarc_tenant.market_moderator_grants',
    );
    expect(grants.rows[0]?.n).toBe(0);
    await expect(
      tenant.query('SELECT count(*) FROM openarc_tenant.listing_origin_reviews'),
    ).rejects.toBeTruthy();
    await expect(
      tenant.query('SELECT count(*) FROM openarc_tenant.market_moderator_grants'),
    ).rejects.toBeTruthy();
    await expect(
      tenant.query('SELECT count(*) FROM openarc_tenant.listings'),
    ).rejects.toBeTruthy();
  });

  it('keeps the four new resource grammars closed and denies the old versioncreate at version 1', async () => {
    const owner = await seedOwner(1);
    const provider = await seedProvider(1, owner.org);
    const listing = await createDraft(owner, provider, 1);
    // A hand-forged lifecycle receipt at the OLD create operation with version 1
    // must still be rejected by the closed resource constraint.
    const err = await rawError(
      admin.query(
        `INSERT INTO openarc_durable.idempotency_records (
           organization_id, operation, key_hash, request_digest, digest_version,
           actor_account_id, session_context_digest, network, mutation_id, status,
           resource_type, resource_id, committed_at
         ) VALUES ($1, 'market.listing.version.create', $2, $3, 'market.listing.version.create.v1',
           $4, $3, 'eip155:5042002', $5, 'committed', 'listing_version', $6 || '@1', clock_timestamp())`,
        [owner.org, 'a'.repeat(64), 'b'.repeat(64), owner.account, mutationId(50), listing],
      ),
    );
    expect(err.code).toBe('23514');
  });
});

describe('provider RLS regression for allowed market writers', () => {
  for (const role of ['owner', 'provider_admin', 'provider_developer'] as const) {
    it(`allows ${role} createDraft and createVersion to succeed`, async () => {
      const writer = await seedOwner(10, role);
      const provider = await seedProvider(10, writer.org);
      const listing = await createDraft(writer, provider, 10);
      expect(listing).toBe(`openarc:listing:${mutationId(10)}`);
      const version = await createVersion(writer, listing, 11);
      expect(version).toBe(`${listing}@2`);
    });
  }

  for (const role of ['operator', 'viewer'] as const) {
    it(`denies ${role} createDraft`, async () => {
      const writer = await seedOwner(12, role);
      const provider = await seedProvider(12, writer.org);
      await expectCode(
        market.createListingDraft(writer.hash, writer.org, provider, content(), {
          idempotencyKey: key(12),
          mutationId: mutationId(12),
        }),
        'MARKET_STORE_FORBIDDEN',
      );
    });
  }

  it('keeps raw tenant-app provider row access denied (no widened ACL)', async () => {
    const owner = await seedOwner(13);
    await seedProvider(13, owner.org);
    // The runtime has no table privilege and no matching RLS context, so its
    // raw read is filtered to zero rows and its raw write is denied.
    const raw = await tenant.query<{ n: number }>('SELECT count(*)::int AS n FROM openarc_tenant.providers');
    expect(raw.rows[0]?.n).toBe(0);
    // The raw UPDATE matches zero rows under the owner-only runtime policy and
    // the stored row is unchanged by admin inspection.
    const updated = await tenant.query(
      "UPDATE openarc_tenant.providers SET display_name = 'x' WHERE display_name = 'Provider 13'",
    );
    expect(updated.rowCount).toBe(0);
    const stored = await admin.query<{ display_name: string }>(
      'SELECT display_name FROM openarc_tenant.providers WHERE organization_id = $1',
      [owner.org],
    );
    expect(stored.rows[0]?.display_name).toBe('Provider 13');
  });

  it('denies a spoofed transaction-local provider role GUC from raw SQL', async () => {
    const owner = await seedOwner(14);
    await seedProvider(14, owner.org);
    // A spoofed role GUC alone cannot satisfy the runtime predicate policy: the
    // account/org context and a real active membership are also required.
    const client = await tenant.connect();
    try {
      await client.query('BEGIN');
      await client.query("SELECT set_config('openarc.role', 'owner', true)");
      const spoofed = await client.query<{ n: number }>(
        'SELECT count(*)::int AS n FROM openarc_tenant.providers',
      );
      expect(spoofed.rows[0]?.n).toBe(0);
      await client.query("UPDATE openarc_tenant.providers SET display_name = 'x'").catch(() => undefined);
      await client.query('ROLLBACK');
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  });
});

describe('reviewed lifecycle semantics', () => {
  it('approval does not activate, then publish activates with first publishedAt', async () => {
    const owner = await seedOwner(20);
    const provider = await seedProvider(20, owner.org);
    const listing = await createDraft(owner, provider, 20);
    const digest = reviewedEndpointDigest({ listingId: listing, version: '1', origin: ORIGIN, path: PATH });
    const before = await contentByte(owner.org, listing, '1');
    const reviewState = await stateOf(owner.org, listing, '1');

    const reviewResult = await review(owner.org, listing, '1', reviewState.updated_at, 'approved', digest, 20);
    expect(reviewResult.replayed).toBe(false);
    const afterReview = await stateOf(owner.org, listing, '1');
    expect(afterReview.origin_review_state).toBe('approved');
    expect(afterReview.status).toBe('draft');
    expect((await rootOf(owner.org, listing)).active_version).toBeNull();

    const publish = await lifecycle.publishListingVersion(
      owner.hash,
      owner.org,
      listing,
      '1',
      { expectedUpdatedAt: afterReview.updated_at, expectedActiveVersion: null },
      { idempotencyKey: key(21), mutationId: mutationId(21) },
    );
    expect(publish.receipt.operation).toBe('market.listing.version.publish');
    const published = await stateOf(owner.org, listing, '1');
    expect(published.status).toBe('active');
    expect(published.published_at).not.toBeNull();
    expect((await rootOf(owner.org, listing)).active_version).toBe('1');
    // Content byte-identical; latest_version unchanged by the lifecycle op.
    expect(await contentByte(owner.org, listing, '1')).toBe(before);
    expect((await rootOf(owner.org, listing)).latest_version).toBe('1');
  });

  it('denies review with a mismatched endpoint digest', async () => {
    const owner = await seedOwner(22);
    const provider = await seedProvider(22, owner.org);
    const listing = await createDraft(owner, provider, 22);
    const state = await stateOf(owner.org, listing, '1');
    const moderator = await seedModerator(220);
    await expectCode(
      lifecycle.recordOriginReview(
        moderator.hash,
        owner.org,
        listing,
        '1',
        {
          expectedUpdatedAt: state.updated_at,
          decision: 'approved',
          reviewedEndpointDigest: `sha256:${'d'.repeat(64)}`,
          reasonCode: 'manual_review',
          reasonDigest: null,
        },
        { idempotencyKey: key(22), mutationId: mutationId(22) },
      ),
      'MARKET_STORE_INPUT_INVALID',
    );
  });

  it('enforces strict CAS and idempotent replay', async () => {
    const owner = await seedOwner(24);
    const provider = await seedProvider(24, owner.org);
    const listing = await createDraft(owner, provider, 24);
    const digest = reviewedEndpointDigest({ listingId: listing, version: '1', origin: ORIGIN, path: PATH });
    const state = await stateOf(owner.org, listing, '1');
    const moderator = await seedModerator(240);
    const first = await lifecycle.recordOriginReview(
      moderator.hash,
      owner.org,
      listing,
      '1',
      {
        expectedUpdatedAt: state.updated_at,
        decision: 'approved',
        reviewedEndpointDigest: digest,
        reasonCode: 'manual_review',
        reasonDigest: null,
      },
      { idempotencyKey: key(9024), mutationId: mutationId(9024) },
    );
    expect(first.replayed).toBe(false);
    const replay = await lifecycle.recordOriginReview(
      moderator.hash,
      owner.org,
      listing,
      '1',
      {
        expectedUpdatedAt: state.updated_at,
        decision: 'approved',
        reviewedEndpointDigest: digest,
        reasonCode: 'manual_review',
        reasonDigest: null,
      },
      { idempotencyKey: key(9024), mutationId: mutationId(9024) },
    );
    expect(replay.replayed).toBe(true);
    // Stale CAS with a new mutation/key must conflict.
    await expectCode(
      lifecycle.recordOriginReview(
        moderator.hash,
        owner.org,
        listing,
        '1',
        {
          expectedUpdatedAt: state.updated_at,
          decision: 'approved',
          reviewedEndpointDigest: digest,
          reasonCode: 'manual_review',
          reasonDigest: null,
        },
        { idempotencyKey: key(25), mutationId: mutationId(25) },
      ),
      'MARKET_STORE_CONFLICT',
    );
    // Same key, changed payload -> idempotency conflict.
    await expectCode(
      lifecycle.recordOriginReview(
        moderator.hash,
        owner.org,
        listing,
        '1',
        {
          expectedUpdatedAt: state.updated_at,
          decision: 'rejected',
          reviewedEndpointDigest: digest,
          reasonCode: 'other',
          reasonDigest: null,
        },
        { idempotencyKey: key(9024), mutationId: mutationId(9024) },
      ),
      'MARKET_STORE_IDEMPOTENCY_CONFLICT',
    );
  });

  it('rejecting an active version pauses it and clears the root pointer', async () => {
    const owner = await seedOwner(26);
    const provider = await seedProvider(26, owner.org);
    const listing = await createDraft(owner, provider, 26);
    const digest = reviewedEndpointDigest({ listingId: listing, version: '1', origin: ORIGIN, path: PATH });
    const s0 = await stateOf(owner.org, listing, '1');
    const moderator = await seedModerator(260);
    await lifecycle.recordOriginReview(
      moderator.hash,
      owner.org,
      listing,
      '1',
      { expectedUpdatedAt: s0.updated_at, decision: 'approved', reviewedEndpointDigest: digest, reasonCode: 'manual_review', reasonDigest: null },
      { idempotencyKey: key(9026), mutationId: mutationId(9026) },
    );
    const s1 = await stateOf(owner.org, listing, '1');
    await lifecycle.publishListingVersion(
      owner.hash,
      owner.org,
      listing,
      '1',
      { expectedUpdatedAt: s1.updated_at, expectedActiveVersion: null },
      { idempotencyKey: key(27), mutationId: mutationId(27) },
    );
    expect((await rootOf(owner.org, listing)).active_version).toBe('1');
    const s2 = await stateOf(owner.org, listing, '1');
    await lifecycle.recordOriginReview(
      moderator.hash,
      owner.org,
      listing,
      '1',
      { expectedUpdatedAt: s2.updated_at, decision: 'rejected', reviewedEndpointDigest: digest, reasonCode: 'origin_policy', reasonDigest: null },
      { idempotencyKey: key(28), mutationId: mutationId(28) },
    );
    const paused = await stateOf(owner.org, listing, '1');
    expect(paused.status).toBe('paused');
    expect(paused.origin_review_state).toBe('rejected');
    expect((await rootOf(owner.org, listing)).active_version).toBeNull();
  });

  it('retire is terminal and rejects a second retire with a new mutation', async () => {
    const owner = await seedOwner(30);
    const provider = await seedProvider(30, owner.org);
    const listing = await createDraft(owner, provider, 30);
    const s0 = await stateOf(owner.org, listing, '1');
    await lifecycle.retireListingVersion(
      owner.hash,
      owner.org,
      listing,
      '1',
      { expectedUpdatedAt: s0.updated_at, expectedActiveVersion: null },
      { idempotencyKey: key(31), mutationId: mutationId(31) },
    );
    const retired = await stateOf(owner.org, listing, '1');
    expect(retired.status).toBe('retired');
    await expectCode(
      lifecycle.retireListingVersion(
        owner.hash,
        owner.org,
        listing,
        '1',
        { expectedUpdatedAt: retired.updated_at, expectedActiveVersion: null },
        { idempotencyKey: key(32), mutationId: mutationId(32) },
      ),
      'MARKET_STORE_INPUT_INVALID',
    );
  });
});

describe('moderator authority', () => {
  it('denies review with zero grants, and with a forged org role', async () => {
    const owner = await seedOwner(40);
    const provider = await seedProvider(40, owner.org);
    const listing = await createDraft(owner, provider, 40);
    const state = await stateOf(owner.org, listing, '1');
    const digest = reviewedEndpointDigest({ listingId: listing, version: '1', origin: ORIGIN, path: PATH });
    // owner is not a moderator even though they have an org role.
    await expectCode(
      lifecycle.recordOriginReview(
        owner.hash,
        owner.org,
        listing,
        '1',
        { expectedUpdatedAt: state.updated_at, decision: 'approved', reviewedEndpointDigest: digest, reasonCode: 'manual_review', reasonDigest: null },
        { idempotencyKey: key(40), mutationId: mutationId(40) },
      ),
      'MARKET_STORE_FORBIDDEN',
    );
  });

  it('allows an independent moderator and denies self-review via org membership', async () => {
    const owner = await seedOwner(42);
    const provider = await seedProvider(42, owner.org);
    const listing = await createDraft(owner, provider, 42);
    const state = await stateOf(owner.org, listing, '1');
    const digest = reviewedEndpointDigest({ listingId: listing, version: '1', origin: ORIGIN, path: PATH });
    const moderator = await seedModerator(43);
    const review = await lifecycle.recordOriginReview(
      moderator.hash,
      owner.org,
      listing,
      '1',
      { expectedUpdatedAt: state.updated_at, decision: 'approved', reviewedEndpointDigest: digest, reasonCode: 'manual_review', reasonDigest: null },
      { idempotencyKey: key(43), mutationId: mutationId(43) },
    );
    expect(review.receipt.operation).toBe('market.listing.origin_review.record');

    // A second moderator who is also a member of the target org is denied.
    const conflicted = await seedAccount(44);
    const conflictHash = await seedSession(44, conflicted);
    await admin.query(
      "INSERT INTO openarc_tenant.market_moderator_grants (account_id, status) VALUES ($1, 'active')",
      [conflicted],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'viewer', 'suspended')",
      [owner.org, conflicted],
    );
    const state2 = await stateOf(owner.org, listing, '1');
    await expectCode(
      lifecycle.recordOriginReview(
        conflictHash,
        owner.org,
        listing,
        '1',
        { expectedUpdatedAt: state2.updated_at, decision: 'approved', reviewedEndpointDigest: digest, reasonCode: 'manual_review', reasonDigest: null },
        { idempotencyKey: key(44), mutationId: mutationId(44) },
      ),
      'MARKET_STORE_FORBIDDEN',
    );
  });

  it('denies a revoked grant and a stale proof', async () => {
    const owner = await seedOwner(46);
    const provider = await seedProvider(46, owner.org);
    const listing = await createDraft(owner, provider, 46);
    const state = await stateOf(owner.org, listing, '1');
    const digest = reviewedEndpointDigest({ listingId: listing, version: '1', origin: ORIGIN, path: PATH });
    const revoked = await seedAccount(47);
    const revokedHash = await seedSession(47, revoked);
    await admin.query(
      "INSERT INTO openarc_tenant.market_moderator_grants (account_id, status) VALUES ($1, 'revoked')",
      [revoked],
    );
    await expectCode(
      lifecycle.recordOriginReview(
        revokedHash,
        owner.org,
        listing,
        '1',
        { expectedUpdatedAt: state.updated_at, decision: 'approved', reviewedEndpointDigest: digest, reasonCode: 'manual_review', reasonDigest: null },
        { idempotencyKey: key(47), mutationId: mutationId(47) },
      ),
      'MARKET_STORE_FORBIDDEN',
    );
    const stale = await seedAccount(48);
    const staleHash = await seedSession(48, stale, { createdOffset: '-10 minutes', expiresOffset: '+23 hours' });
    await admin.query(
      "INSERT INTO openarc_tenant.market_moderator_grants (account_id, status) VALUES ($1, 'active')",
      [stale],
    );
    await expectCode(
      lifecycle.recordOriginReview(
        staleHash,
        owner.org,
        listing,
        '1',
        { expectedUpdatedAt: state.updated_at, decision: 'approved', reviewedEndpointDigest: digest, reasonCode: 'manual_review', reasonDigest: null },
        { idempotencyKey: key(48), mutationId: mutationId(48) },
      ),
      'MARKET_STORE_SESSION_INVALID',
    );
  });
});

describe('public catalog eligibility and allowlist', () => {
  async function publishSeed(seed: number, providerStatus = 'active'): Promise<{ listing: string; owner: { org: string } }> {
    const owner = await seedOwner(seed);
    const provider = await seedProvider(seed, owner.org, providerStatus);
    const listing = await createDraft(owner, provider, seed);
    const digest = reviewedEndpointDigest({ listingId: listing, version: '1', origin: ORIGIN, path: PATH });
    const s0 = await stateOf(owner.org, listing, '1');
    const moderator = await seedModerator(seed + 8000);
    await lifecycle.recordOriginReview(
      moderator.hash,
      owner.org,
      listing,
      '1',
      { expectedUpdatedAt: s0.updated_at, decision: 'approved', reviewedEndpointDigest: digest, reasonCode: 'manual_review', reasonDigest: null },
      { idempotencyKey: key(seed + 9000), mutationId: mutationId(seed + 9000) },
    );
    const s1 = await stateOf(owner.org, listing, '1');
    await lifecycle.publishListingVersion(
      owner.hash,
      owner.org,
      listing,
      '1',
      { expectedUpdatedAt: s1.updated_at, expectedActiveVersion: null },
      { idempotencyKey: key(seed + 1), mutationId: mutationId(seed + 1) },
    );
    return { listing, owner };
  }

  it('excludes drafts and unreviewed versions, includes a published active version', async () => {
    const owner = await seedOwner(60);
    const provider = await seedProvider(60, owner.org);
    const listing = await createDraft(owner, provider, 60);
    expect(await catalog.getPublicListing(listing)).toBeNull();
    const digest = reviewedEndpointDigest({ listingId: listing, version: '1', origin: ORIGIN, path: PATH });
    const s0 = await stateOf(owner.org, listing, '1');
    const moderator = await seedModerator(600);
    await lifecycle.recordOriginReview(
      moderator.hash,
      owner.org,
      listing,
      '1',
      { expectedUpdatedAt: s0.updated_at, decision: 'approved', reviewedEndpointDigest: digest, reasonCode: 'manual_review', reasonDigest: null },
      { idempotencyKey: key(9060), mutationId: mutationId(9060) },
    );
    // Approved but not published is still excluded.
    expect(await catalog.getPublicListing(listing)).toBeNull();
    const s1 = await stateOf(owner.org, listing, '1');
    await lifecycle.publishListingVersion(
      owner.hash,
      owner.org,
      listing,
      '1',
      { expectedUpdatedAt: s1.updated_at, expectedActiveVersion: null },
      { idempotencyKey: key(61), mutationId: mutationId(61) },
    );
    const item = await catalog.getPublicListing(listing);
    expect(item?.listingId).toBe(listing);
    expect(item?.status).toBe('active');
    expect(Object.keys(item ?? {})).not.toContain('organizationId');
    expect(Object.keys(item ?? {})).not.toContain('endpointContract');
  });

  it('excludes an inactive provider and returns a public provider only when eligible', async () => {
    const active = await publishSeed(62);
    const activeItem = await catalog.getPublicListing(active.listing);
    expect(activeItem).not.toBeNull();
    // Publish under an active provider, then retire the provider's own status:
    // the already-published listing must drop out of the public catalog.
    const inactive = await publishSeed(63);
    await admin.query(
      "UPDATE openarc_tenant.providers SET status = 'suspended' WHERE organization_id = $1",
      [inactive.owner.org],
    );
    expect(await catalog.getPublicListing(inactive.listing)).toBeNull();

    const activeProvider = await admin.query<{ provider_id: string }>(
      'SELECT provider_id FROM openarc_tenant.providers WHERE organization_id = $1',
      [active.owner.org],
    );
    const pid = activeProvider.rows[0]?.provider_id;
    expect(pid).toBeDefined();
    expect(await catalog.getPublicProvider(pid)).toMatchObject({ status: 'active' });
  });

  it('searches q as a literal bounded substring and paginates by listing id', async () => {
    await publishSeed(64);
    await publishSeed(65);
    const page = await catalog.listPublicListings({ limit: 1 });
    expect(page.items).toHaveLength(1);
    expect(page.nextCursor).toBe(page.items[0]?.listingId);
    // A SQL wildcard is treated as a literal character, not a pattern.
    const wildcard = await catalog.listPublicListings({ q: '%' });
    expect(wildcard.items).toHaveLength(0);
    const hit = await catalog.listPublicListings({ q: 'Example' });
    expect(hit.items.length).toBeGreaterThan(0);
  });

  it('denies wrong active-pointer commits and preserves one active version per root', async () => {
    const owner = await seedOwner(66);
    const provider = await seedProvider(66, owner.org);
    const listing = await createDraft(owner, provider, 66);
    const raw = await rawError(
      admin.query(
        "UPDATE openarc_tenant.listings SET active_version = '1' WHERE organization_id = $1 AND listing_id = $2",
        [owner.org, listing],
      ),
    );
    expect(raw.code).toBe('42501');
  });
});

describe('lifecycle status and worker event grammar', () => {
  it('returns same-actor committed receipts and not_found for a cross-actor mutation', async () => {
    const owner = await seedOwner(70);
    const provider = await seedProvider(70, owner.org);
    const listing = await createDraft(owner, provider, 70);
    const s0 = await stateOf(owner.org, listing, '1');
    await lifecycle.retireListingVersion(
      owner.hash,
      owner.org,
      listing,
      '1',
      { expectedUpdatedAt: s0.updated_at, expectedActiveVersion: null },
      { idempotencyKey: key(71), mutationId: mutationId(71) },
    );
    const status = await lifecycle.getLifecycleMutationStatus(owner.hash, owner.org, mutationId(71));
    expect(status.status).toBe('committed');
    // A different active member of the SAME org resolves authority but cannot
    // read another actor's receipt: a truthful not_found, never a fabricated one.
    const otherAccount = await seedAccount(71);
    const otherHash = await seedSession(71, otherAccount);
    await admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'viewer', 'active')",
      [owner.org, otherAccount],
    );
    expect(await lifecycle.getLifecycleMutationStatus(otherHash, owner.org, mutationId(71))).toEqual({
      status: 'not_found',
    });
  });
});

async function waitForBlocked(needle: string): Promise<void> {
  for (let attempt = 0; attempt < 400; attempt += 1) {
    const result = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n
         FROM pg_stat_activity
        WHERE query LIKE $1 AND state = 'active' AND pid <> pg_backend_pid()`,
      [`%${needle}%`],
    );
    if ((result.rows[0]?.n ?? 0) > 0) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  const all = await admin.query<{ usename: string; state: string | null; wait_event_type: string | null; q: string }>(
    `SELECT usename, state, wait_event_type, left(query, 120) AS q
       FROM pg_stat_activity
      WHERE datname = current_database() AND pid <> pg_backend_pid()`,
  );
  throw new Error(`no blocked statement matched ${needle}: ${JSON.stringify(all.rows)}`);
}

describe('bounded first-review corrections', () => {
  it('replays an origin review after the version was retired (replay before state checks)', async () => {
    const owner = await seedOwner(100);
    const provider = await seedProvider(100, owner.org);
    const listing = await createDraft(owner, provider, 100);
    const digest = reviewedEndpointDigest({ listingId: listing, version: '1', origin: ORIGIN, path: PATH });
    const moderator = await seedModerator(1000);
    const meta = { idempotencyKey: key(9100), mutationId: mutationId(9100) };
    const body = {
      expectedUpdatedAt: (await stateOf(owner.org, listing, '1')).updated_at,
      decision: 'approved' as const,
      reviewedEndpointDigest: digest,
      reasonCode: 'manual_review' as const,
      reasonDigest: null,
    };
    const first = await lifecycle.recordOriginReview(moderator.hash, owner.org, listing, '1', body, meta);
    expect(first.replayed).toBe(false);
    const s1 = await stateOf(owner.org, listing, '1');
    await lifecycle.publishListingVersion(
      owner.hash, owner.org, listing, '1',
      { expectedUpdatedAt: s1.updated_at, expectedActiveVersion: null },
      { idempotencyKey: key(101), mutationId: mutationId(101) },
    );
    const s2 = await stateOf(owner.org, listing, '1');
    await lifecycle.retireListingVersion(
      owner.hash, owner.org, listing, '1',
      { expectedUpdatedAt: s2.updated_at, expectedActiveVersion: '1' },
      { idempotencyKey: key(102), mutationId: mutationId(102) },
    );
    expect((await stateOf(owner.org, listing, '1')).status).toBe('retired');
    // Same key/body/actor/session replays the ORIGINAL receipt even though the
    // version is now retired and its token has advanced.
    const replay = await lifecycle.recordOriginReview(moderator.hash, owner.org, listing, '1', body, meta);
    expect(replay.replayed).toBe(true);
    expect(replay.receipt.mutationId).toBe(meta.mutationId);
    expect(replay.receipt.operation).toBe('market.listing.origin_review.record');
  });

  it('resolves committed moderator status and denies zero/revoked/self-review, cross-actor not_found', async () => {
    const owner = await seedOwner(104);
    const provider = await seedProvider(104, owner.org);
    const listing = await createDraft(owner, provider, 104);
    const digest = reviewedEndpointDigest({ listingId: listing, version: '1', origin: ORIGIN, path: PATH });
    const moderator = await seedModerator(1004);
    const meta = { idempotencyKey: key(9104), mutationId: mutationId(9104) };
    const body = {
      expectedUpdatedAt: (await stateOf(owner.org, listing, '1')).updated_at,
      decision: 'approved' as const,
      reviewedEndpointDigest: digest,
      reasonCode: 'manual_review' as const,
      reasonDigest: null,
    };
    await lifecycle.recordOriginReview(moderator.hash, owner.org, listing, '1', body, meta);
    // Independent moderator resolves its own committed receipt.
    expect(await lifecycle.getLifecycleMutationStatus(moderator.hash, owner.org, meta.mutationId)).toMatchObject({
      status: 'committed',
    });
    // A different independent moderator has authority but is not the actor.
    const otherModerator = await seedModerator(1005);
    expect(await lifecycle.getLifecycleMutationStatus(otherModerator.hash, owner.org, meta.mutationId)).toEqual({
      status: 'not_found',
    });
    // Zero grant: no membership, no moderator grant -> forbidden, not not_found.
    const noGrant = await seedAccount(106);
    const noGrantHash = await seedSession(106, noGrant);
    await expectCode(
      lifecycle.getLifecycleMutationStatus(noGrantHash, owner.org, meta.mutationId),
      'MARKET_STORE_FORBIDDEN',
    );
    // Self-review via target-org membership is denied for status resolution too.
    const conflicted = await seedAccount(107);
    const conflictedHash = await seedSession(107, conflicted);
    await admin.query(
      "INSERT INTO openarc_tenant.market_moderator_grants (account_id, status) VALUES ($1, 'active')",
      [conflicted],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'viewer', 'suspended')",
      [owner.org, conflicted],
    );
    await expectCode(
      lifecycle.getLifecycleMutationStatus(conflictedHash, owner.org, meta.mutationId),
      'MARKET_STORE_FORBIDDEN',
    );
    // A revoked grant is forbidden.
    const revoked = await seedAccount(108);
    const revokedHash = await seedSession(108, revoked);
    await admin.query(
      "INSERT INTO openarc_tenant.market_moderator_grants (account_id, status) VALUES ($1, 'revoked')",
      [revoked],
    );
    await expectCode(
      lifecycle.getLifecycleMutationStatus(revokedHash, owner.org, meta.mutationId),
      'MARKET_STORE_FORBIDDEN',
    );
  });

  it('replays a committed publish after state advance and conflicts on changed body/new key', async () => {
    const owner = await seedOwner(118);
    const provider = await seedProvider(118, owner.org);
    const listing = await createDraft(owner, provider, 118);
    const digest = reviewedEndpointDigest({ listingId: listing, version: '1', origin: ORIGIN, path: PATH });
    const moderator = await seedModerator(1118);
    await lifecycle.recordOriginReview(
      moderator.hash, owner.org, listing, '1',
      {
        expectedUpdatedAt: (await stateOf(owner.org, listing, '1')).updated_at,
        decision: 'approved',
        reviewedEndpointDigest: digest,
        reasonCode: 'manual_review',
        reasonDigest: null,
      },
      { idempotencyKey: key(9118), mutationId: mutationId(9118) },
    );
    const token = (await stateOf(owner.org, listing, '1')).updated_at;
    const meta = { idempotencyKey: key(1180), mutationId: mutationId(1180) };
    const first = await lifecycle.publishListingVersion(
      owner.hash, owner.org, listing, '1',
      { expectedUpdatedAt: token, expectedActiveVersion: null },
      meta,
    );
    expect(first.replayed).toBe(false);
    const activeToken = (await stateOf(owner.org, listing, '1')).updated_at;
    // Same key/body/actor/session replays the original receipt even though the
    // state token has advanced past the original CAS token.
    const replay = await lifecycle.publishListingVersion(
      owner.hash, owner.org, listing, '1',
      { expectedUpdatedAt: token, expectedActiveVersion: null },
      meta,
    );
    expect(replay.replayed).toBe(true);
    expect(replay.receipt.mutationId).toBe(meta.mutationId);
    // Same key but a changed expectedActiveVersion is an idempotency conflict.
    await expectCode(
      lifecycle.publishListingVersion(
        owner.hash, owner.org, listing, '1',
        { expectedUpdatedAt: token, expectedActiveVersion: '1' },
        meta,
      ),
      'MARKET_STORE_IDEMPOTENCY_CONFLICT',
    );
    // A new key against the advanced CAS token is a strict conflict.
    await expectCode(
      lifecycle.publishListingVersion(
        owner.hash, owner.org, listing, '1',
        { expectedUpdatedAt: token, expectedActiveVersion: null },
        { idempotencyKey: key(119), mutationId: mutationId(119) },
      ),
      'MARKET_STORE_CONFLICT',
    );
    // A same-org cross-actor writer cannot replay another actor's receipt.
    const other = await seedOwner(119, 'owner');
    // The other account is a member of a DIFFERENT org, so targeting this org
    // without membership is forbidden (provider authority is org-scoped).
    await expectCode(
      lifecycle.getLifecycleMutationStatus(other.hash, owner.org, meta.mutationId),
      'MARKET_STORE_FORBIDDEN',
    );
    expect((await stateOf(owner.org, listing, '1')).updated_at).toBe(activeToken);
  });

  it('conflicts when the same key is replayed from a different held session', async () => {
    const owner = await seedOwner(152);
    const provider = await seedProvider(152, owner.org);
    const listing = await createDraft(owner, provider, 152);
    const digest = reviewedEndpointDigest({ listingId: listing, version: '1', origin: ORIGIN, path: PATH });
    const moderator = await seedModerator(1152);
    const meta = { idempotencyKey: key(9152), mutationId: mutationId(9152) };
    const body = {
      expectedUpdatedAt: (await stateOf(owner.org, listing, '1')).updated_at,
      decision: 'approved' as const,
      reviewedEndpointDigest: digest,
      reasonCode: 'manual_review' as const,
      reasonDigest: null,
    };
    await lifecycle.recordOriginReview(moderator.hash, owner.org, listing, '1', body, meta);
    // Same moderator account, but a second session changes the bound session
    // context digest, so the same key is a conflict rather than a replay.
    const rotated = await seedSession(15201, moderator.account);
    await expectCode(
      lifecycle.recordOriginReview(rotated, owner.org, listing, '1', body, meta),
      'MARKET_STORE_IDEMPOTENCY_CONFLICT',
    );
  });

  it('rejects raw SQL public q that violates the shared trimmed/control/UTF16 contract', async () => {
    const client = await tenant.connect();
    try {
      const cases = [' leading', 'trailing ', 'un\u0001it', 'a'.repeat(81)];
      for (const unsafe of cases) {
        const err = await rawError(
          client.query('SELECT * FROM openarc_durable.list_public_listings(NULL, 25, NULL, NULL, $1)', [unsafe]),
        );
        expect(err.code).toBe('22023');
      }
      // A literal wildcard is accepted as a literal character, not a pattern.
      const wildcard = await client.query(
        'SELECT * FROM openarc_durable.list_public_listings(NULL, 25, NULL, NULL, $1)',
        ['%'],
      );
      expect(wildcard.rows).toHaveLength(0);
    } finally {
      client.release();
    }
  });

  it('serializes concurrent publishes on two real connections to one CAS winner', async () => {
    const owner = await seedOwner(110);
    const provider = await seedProvider(110, owner.org);
    const listing = await createDraft(owner, provider, 110);
    const digest = reviewedEndpointDigest({ listingId: listing, version: '1', origin: ORIGIN, path: PATH });
    const moderator = await seedModerator(1100);
    await lifecycle.recordOriginReview(
      moderator.hash, owner.org, listing, '1',
      {
        expectedUpdatedAt: (await stateOf(owner.org, listing, '1')).updated_at,
        decision: 'approved',
        reviewedEndpointDigest: digest,
        reasonCode: 'manual_review',
        reasonDigest: null,
      },
      { idempotencyKey: key(9110), mutationId: mutationId(9110) },
    );
    const token = (await stateOf(owner.org, listing, '1')).updated_at;
    const results = await Promise.allSettled([
      lifecycle.publishListingVersion(
        owner.hash, owner.org, listing, '1',
        { expectedUpdatedAt: token, expectedActiveVersion: null },
        { idempotencyKey: key(111), mutationId: mutationId(111) },
      ),
      lifecycle.publishListingVersion(
        owner.hash, owner.org, listing, '1',
        { expectedUpdatedAt: token, expectedActiveVersion: null },
        { idempotencyKey: key(112), mutationId: mutationId(112) },
      ),
    ]);
    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    const rejected = results.filter((r) => r.status === 'rejected');
    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect((rejected[0] as PromiseRejectedResult).reason).toBeInstanceOf(MarketStoreError);
    expect((rejected[0] as PromiseRejectedResult).reason.code).toBe('MARKET_STORE_CONFLICT');
    expect((await rootOf(owner.org, listing)).active_version).toBe('1');
    expect((await stateOf(owner.org, listing, '1')).status).toBe('active');
  });

  it('rechecks session freshness after a blocked provider write', async () => {
    const owner = await seedOwner(114);
    const provider = await seedProvider(114, owner.org);
    const listing = await createDraft(owner, provider, 114);
    const digest = reviewedEndpointDigest({ listingId: listing, version: '1', origin: ORIGIN, path: PATH });
    const moderator = await seedModerator(1114);
    await lifecycle.recordOriginReview(
      moderator.hash, owner.org, listing, '1',
      {
        expectedUpdatedAt: (await stateOf(owner.org, listing, '1')).updated_at,
        decision: 'approved',
        reviewedEndpointDigest: digest,
        reasonCode: 'manual_review',
        reasonDigest: null,
      },
      { idempotencyKey: key(9114), mutationId: mutationId(9114) },
    );
    const token = (await stateOf(owner.org, listing, '1')).updated_at;
    // Give the held session a short remaining lifetime so it expires WHILE the
    // provider row lock blocks the write; no cross-transaction row update (which
    // would deadlock against the helper's own session/authority locks).
    await admin.query(
      "UPDATE openarc_auth.sessions SET expires_at = now() + interval '2 seconds' WHERE token_hash = $1",
      [owner.hash],
    );
    const blocker = await admin.connect();
    let blockerReleased = false;
    let pending: Promise<unknown> | undefined;
    try {
      await blocker.query('BEGIN');
      await blocker.query(
        'SELECT provider_id FROM openarc_tenant.providers WHERE organization_id = $1 FOR UPDATE',
        [owner.org],
      );
      pending = lifecycle.publishListingVersion(
        owner.hash, owner.org, listing, '1',
        { expectedUpdatedAt: token, expectedActiveVersion: null },
        { idempotencyKey: key(115), mutationId: mutationId(115) },
      );
      // Keep the eventual rejection observed while we deliberately block.
      pending.catch(() => undefined);
      await waitForBlocked('lock_lifecycle_writer');
      // Wait deterministically until the known expiry has passed, then unblock.
      await new Promise((resolve) => setTimeout(resolve, 2500));
      await blocker.query('ROLLBACK');
      blocker.release();
      blockerReleased = true;
      await expectCode(pending, 'MARKET_STORE_SESSION_INVALID');
    } finally {
      if (!blockerReleased) {
        await blocker.query('ROLLBACK').catch(() => undefined);
        blocker.release();
      }
      await pending?.catch(() => undefined);
    }
    // No state or receipt survived the failed late write.
    expect((await stateOf(owner.org, listing, '1')).status).toBe('draft');
    const idem = await admin.query<{ n: number }>(
      "SELECT count(*)::int AS n FROM openarc_durable.idempotency_records WHERE operation = 'market.listing.version.publish'",
    );
    expect(idem.rows[0]?.n).toBe(0);
  }, 20000);

  it('rolls back review/state/root/durable rows when the outbox insert fails', async () => {
    const owner = await seedOwner(116);
    const provider = await seedProvider(116, owner.org);
    const listing = await createDraft(owner, provider, 116);
    const digest = reviewedEndpointDigest({ listingId: listing, version: '1', origin: ORIGIN, path: PATH });
    const moderator = await seedModerator(1116);
    const before = {
      idem: (await admin.query<{ n: number }>('SELECT count(*)::int AS n FROM openarc_durable.idempotency_records')).rows[0]?.n,
      audit: (await admin.query<{ n: number }>('SELECT count(*)::int AS n FROM openarc_durable.audit_events')).rows[0]?.n,
      outbox: (await admin.query<{ n: number }>('SELECT count(*)::int AS n FROM openarc_durable.outbox_events')).rows[0]?.n,
    };
    await admin.query(
      `CREATE FUNCTION openarc_tenant.test_fail_outbox() RETURNS trigger
       LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected_outbox_failure' USING ERRCODE = '23514'; END; $$`,
    );
    await admin.query(
      `CREATE TRIGGER test_fail_outbox BEFORE INSERT ON openarc_durable.outbox_events
         FOR EACH ROW EXECUTE FUNCTION openarc_tenant.test_fail_outbox()`,
    );
    try {
      await expectCode(
        lifecycle.recordOriginReview(
          moderator.hash, owner.org, listing, '1',
          {
            expectedUpdatedAt: (await stateOf(owner.org, listing, '1')).updated_at,
            decision: 'approved',
            reviewedEndpointDigest: digest,
            reasonCode: 'manual_review',
            reasonDigest: null,
          },
          { idempotencyKey: key(9116), mutationId: mutationId(9116) },
        ),
        'MARKET_STORE_INPUT_INVALID',
      );
    } finally {
      await admin.query('DROP TRIGGER IF EXISTS test_fail_outbox ON openarc_durable.outbox_events');
      await admin.query('DROP FUNCTION IF EXISTS openarc_tenant.test_fail_outbox()');
    }
    const review = await stateOf(owner.org, listing, '1');
    expect(review.origin_review_state).toBe('unreviewed');
    expect(review.status).toBe('draft');
    expect((await rootOf(owner.org, listing)).active_version).toBeNull();
    const reviews = await admin.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM openarc_tenant.listing_origin_reviews',
    );
    expect(reviews.rows[0]?.n).toBe(0);
    // The only durable rows are the draft's; the failed review added none.
    expect((await admin.query<{ n: number }>('SELECT count(*)::int AS n FROM openarc_durable.idempotency_records')).rows[0]?.n).toBe(before.idem);
    expect((await admin.query<{ n: number }>('SELECT count(*)::int AS n FROM openarc_durable.audit_events')).rows[0]?.n).toBe(before.audit);
    expect((await admin.query<{ n: number }>('SELECT count(*)::int AS n FROM openarc_durable.outbox_events')).rows[0]?.n).toBe(before.outbox);
  }, 20000);

  it('allows provider_admin/provider_developer reviewed lifecycle transitions and denies operator/viewer', async () => {
    const allowed = ['provider_admin', 'provider_developer'] as const;
    for (let index = 0; index < allowed.length; index += 1) {
      const role = allowed[index] as (typeof allowed)[number];
      const seed = 120 + index;
      const writer = await seedOwner(seed, role);
      const provider = await seedProvider(seed, writer.org);
      const listing = await createDraft(writer, provider, seed);
      const digest = reviewedEndpointDigest({ listingId: listing, version: '1', origin: ORIGIN, path: PATH });
      const moderator = await seedModerator(1200 + index);
      await lifecycle.recordOriginReview(
        moderator.hash, writer.org, listing, '1',
        {
          expectedUpdatedAt: (await stateOf(writer.org, listing, '1')).updated_at,
          decision: 'approved',
          reviewedEndpointDigest: digest,
          reasonCode: 'manual_review',
          reasonDigest: null,
        },
        { idempotencyKey: key(9120 + index), mutationId: mutationId(9120 + index) },
      );
      const publish = await lifecycle.publishListingVersion(
        writer.hash, writer.org, listing, '1',
        { expectedUpdatedAt: (await stateOf(writer.org, listing, '1')).updated_at, expectedActiveVersion: null },
        { idempotencyKey: key(121 + index), mutationId: mutationId(121 + index) },
      );
      expect(publish.receipt.operation).toBe('market.listing.version.publish');
      expect((await rootOf(writer.org, listing)).active_version).toBe('1');
    }
    const denied = ['operator', 'viewer'] as const;
    for (let index = 0; index < denied.length; index += 1) {
      const role = denied[index] as (typeof denied)[number];
      const seed = 123 + index;
      const writer = await seedOwner(seed, role);
      const provider = await seedProvider(seed, writer.org);
      const listing = await createDraft(writer, provider, seed).catch(() => null);
      // operator/viewer cannot create a draft at all via the real market helper.
      expect(listing).toBeNull();
    }
  }, 20000);

  it('denies raw runtime writes to reviews and grants and exposes zero PUBLIC privileges', async () => {
    await expect(
      tenant.query(
        "INSERT INTO openarc_tenant.market_moderator_grants (account_id, status) VALUES ('openarc:account:x', 'active')",
      ),
    ).rejects.toBeTruthy();
    await expect(
      tenant.query(
        "INSERT INTO openarc_tenant.listing_origin_reviews (review_id, organization_id, listing_id, version, provider_id, mutation_id, reviewer_account_id, decision, reviewed_endpoint_digest, reason_code) VALUES ('00000000-0000-4000-8000-000000000001','x','y','1','z','00000000-0000-4000-8000-000000000002','a','approved','b','manual_review')",
      ),
    ).rejects.toBeTruthy();
    for (const table of ['listing_origin_reviews', 'market_moderator_grants']) {
      const pub = await admin.query<{ n: number }>(
        `SELECT count(*)::int AS n
           FROM pg_class c
           JOIN pg_namespace ns ON ns.oid = c.relnamespace
           CROSS JOIN LATERAL aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
          WHERE ns.nspname = 'openarc_tenant' AND c.relname = $1
            AND a.grantee = 0`,
        [table],
      );
      expect(pub.rows[0]?.n, table).toBe(0);
    }
  }, 20000);
});

describe('schema6 to schema7 upgrade preserves records and replay', () => {
  it('preserves tenant/machine/draft rows and replays an old market receipt', async () => {
    await resetSchema(admin);
    const all = loadMigrations();
    await migrate(migrator, all.slice(0, 6));
    const owner = await seedOwner(130);
    const provider = await seedProvider(130, owner.org);
    const base = new TenantStore(tenant);
    const agentMeta = { idempotencyKey: key(9130), mutationId: mutationId(9130) };
    await base.createAgentDurably(owner.hash, owner.org, 'Legacy Agent', agentMeta);
    const listing = await createDraft(owner, provider, 131);
    const contentBefore = await contentByte(owner.org, listing, '1');
    const stateBefore = await stateOf(owner.org, listing, '1');

    await migrate(migrator);
    const applied = await admin.query<{ id: string }>(
      'SELECT id FROM openarc_meta.schema_migrations ORDER BY id',
    );
    expect(applied.rows.map((row) => row.id)).toContain('0007_market_lifecycle');
    // Older versions and receipt replay are byte-for-byte intact.
    expect(await contentByte(owner.org, listing, '1')).toBe(contentBefore);
    expect((await stateOf(owner.org, listing, '1')).updated_at).toBe(stateBefore.updated_at);
    expect((await market.getMarketMutationStatus(owner.hash, owner.org, mutationId(131))).status).toBe('committed');
    const replay = await base.createAgentDurably(owner.hash, owner.org, 'Legacy Agent', agentMeta);
    expect(replay.replayed).toBe(true);
    // Zero seeded moderator grants after upgrade.
    const grants = await admin.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM openarc_tenant.market_moderator_grants',
    );
    expect(grants.rows[0]?.n).toBe(0);
  }, 20000);
});

describe('schema7 readiness fault injection', () => {
  const commitArgs =
    '(text, text, text, text, timestamptz, text, text, text, text, uuid, text, text, text)';

  it('accepts the healthy schema7 provider policy and full baseline', async () => {
    // Positive control: the exact accepted providers UPDATE policy expression
    // (current_user = 'openarc_migrator') must satisfy the readiness expression
    // check, and the composed catalog baseline must also reach a clean
    // readiness without constructing any auth session.
    await expect(lifecycle.readiness()).resolves.toBeUndefined();
    await expect(catalog.readiness()).resolves.toBeUndefined();
  });

  it('rejects a non-migrator-owned helper by altering its SECDEF posture', async () => {
    await admin.query(`ALTER FUNCTION openarc_durable.commit_origin_review${commitArgs} SECURITY INVOKER`);
    await expectCode(lifecycle.readiness(), 'MARKET_STORE_UNAVAILABLE');
  });

  it('rejects a PUBLIC EXECUTE grant on a new lifecycle helper', async () => {
    await admin.query(`GRANT EXECUTE ON FUNCTION openarc_durable.commit_origin_review${commitArgs} TO PUBLIC`);
    await expectCode(lifecycle.readiness(), 'MARKET_STORE_UNAVAILABLE');
  });

  it('rejects a new table that lost forced RLS', async () => {
    await admin.query('ALTER TABLE openarc_tenant.listing_origin_reviews NO FORCE ROW LEVEL SECURITY');
    await expectCode(lifecycle.readiness(), 'MARKET_STORE_UNAVAILABLE');
  });

  it('rejects a dropped approver UPDATE policy', async () => {
    await admin.query('DROP POLICY providers_update_migrator ON openarc_tenant.providers');
    await expectCode(lifecycle.readiness(), 'MARKET_STORE_UNAVAILABLE');
  });

  it('rejects an approver UPDATE policy whose expression drifted', async () => {
    // The accepted expression is the exact migrator equality. A broader
    // USING(true)/WITH CHECK(true) policy is rejected even though it keeps the
    // same name and role, so the expression itself is checked, not just names.
    await admin.query('DROP POLICY providers_update_migrator ON openarc_tenant.providers');
    await admin.query(
      `CREATE POLICY providers_update_migrator ON openarc_tenant.providers
         FOR UPDATE TO openarc_migrator USING (true) WITH CHECK (true)`,
    );
    await expectCode(lifecycle.readiness(), 'MARKET_STORE_UNAVAILABLE');
  });

  it('rejects an altered migration checksum through the composed baseline', async () => {
    await admin.query("UPDATE openarc_meta.schema_migrations SET checksum = 'altered' WHERE id = '0007_market_lifecycle'");
    await expectCode(lifecycle.readiness(), 'MARKET_STORE_UNAVAILABLE');
  });

  it('rejects a catalog helper with an unexpected identity argument', async () => {
    await admin.query('ALTER FUNCTION openarc_durable.get_public_provider(text) RENAME TO get_public_provider_renamed');
    await expectCode(catalog.readiness(), 'MARKET_STORE_UNAVAILABLE');
  });

  it('rejects a PUBLIC EXECUTE grant on a catalog helper', async () => {
    await admin.query('GRANT EXECUTE ON FUNCTION openarc_durable.list_public_listings(text, integer, text, text, text) TO PUBLIC');
    await expectCode(catalog.readiness(), 'MARKET_STORE_UNAVAILABLE');
  });

  // A catalog-only deployment must validate the full schema7 baseline through
  // the composed lifecycle store, even though it never records or transitions
  // lifecycle state. The fixture reset in beforeEach restores each mutation.
  it('rejects a schema7 table that lost forced RLS via a catalog-only initialize', async () => {
    // The catalog has not initialized yet, so the very first initialize must
    // run the composed lifecycle readiness and reject the altered table.
    const catalogOnly = new MarketCatalogStore(tenant);
    await admin.query('ALTER TABLE openarc_tenant.listing_origin_reviews NO FORCE ROW LEVEL SECURITY');
    await expectCode(catalogOnly.initialize(), 'MARKET_STORE_UNAVAILABLE');
  });

  it('rejects a runtime direct grant on a schema7 table via catalog-only readiness', async () => {
    const catalogOnly = new MarketCatalogStore(tenant);
    await admin.query('GRANT SELECT ON openarc_tenant.listing_origin_reviews TO openarc_tenant_app');
    await expectCode(catalogOnly.readiness(), 'MARKET_STORE_UNAVAILABLE');
  });
});

describe('frozen SQL surface and status registry separation', () => {
  it('grants no lifecycle/catalog EXECUTE to worker/auth and no PUBLIC SQL read', async () => {
    const surface = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'openarc_durable'
          AND p.proname IN (
            'commit_origin_review', 'commit_lifecycle_transition',
            'lock_moderator_actor', 'lock_lifecycle_writer', 'read_owner_listing',
            'list_market_providers', 'get_moderator_listing_version',
            'read_lifecycle_mutation_status',
            'list_public_listings', 'get_public_listing', 'get_public_provider'
          )
          AND (
            has_function_privilege('openarc_worker_app', p.oid, 'EXECUTE')
            OR has_function_privilege('openarc_auth_app', p.oid, 'EXECUTE')
            OR EXISTS (
              SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
               WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE'
            )
          )`,
    );
    expect(surface.rows[0]?.n).toBe(0);
  });

  it('keeps the market-creation and lifecycle status registries disjoint', async () => {
    const owner = await seedOwner(140);
    const provider = await seedProvider(140, owner.org);
    const listing = await createDraft(owner, provider, 140);
    // The market registry never resolves a lifecycle receipt.
    expect(await market.getMarketMutationStatus(owner.hash, owner.org, mutationId(9140))).toEqual({
      status: 'not_found',
    });
    const digest = reviewedEndpointDigest({ listingId: listing, version: '1', origin: ORIGIN, path: PATH });
    const moderator = await seedModerator(1140);
    await lifecycle.recordOriginReview(
      moderator.hash, owner.org, listing, '1',
      {
        expectedUpdatedAt: (await stateOf(owner.org, listing, '1')).updated_at,
        decision: 'approved',
        reviewedEndpointDigest: digest,
        reasonCode: 'manual_review',
        reasonDigest: null,
      },
      { idempotencyKey: key(9140), mutationId: mutationId(9140) },
    );
    expect((await lifecycle.getLifecycleMutationStatus(moderator.hash, owner.org, mutationId(9140))).status).toBe('committed');
    // The lifecycle registry never resolves an old market-creation receipt.
    expect(await lifecycle.getLifecycleMutationStatus(owner.hash, owner.org, mutationId(140))).toEqual({
      status: 'not_found',
    });
    // The old market registry still resolves its own creation receipt.
    expect((await market.getMarketMutationStatus(owner.hash, owner.org, mutationId(140))).status).toBe('committed');
  });

  it('keeps legacy TenantStore provider create/update/list owner-only via real DB functions', async () => {
    const base = new TenantStore(tenant);
    const owner = await seedOwner(150);
    const created = await base.createProvider(owner.hash, owner.org, 'Legacy Provider');
    expect(created.providerId).toMatch(/^openarc:provider:/);
    const updated = await base.updateProvider(owner.hash, owner.org, created.providerId, {
      displayName: 'Legacy Provider Renamed',
    });
    expect(updated.displayName).toBe('Legacy Provider Renamed');
    const listed = await base.listProviders(owner.hash, owner.org);
    expect(listed.items.map((item) => item.providerId)).toContain(created.providerId);

    const operator = await seedOwner(151, 'operator');
    await expect(base.createProvider(operator.hash, operator.org, 'Nope')).rejects.toBeTruthy();
    await expect(base.updateProvider(operator.hash, operator.org, created.providerId, { displayName: 'Nope' })).rejects.toBeTruthy();
    await expect(base.listProviders(operator.hash, operator.org)).rejects.toBeTruthy();
  });
});
