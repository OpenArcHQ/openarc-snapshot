import { createHash } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import {
  CredentialStore,
  loadMigrations,
  MarketStore,
  MarketStoreError,
  TenantStore,
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
import { createDatabasePool } from '../src/index.js';

/**
 * Real PostgreSQL acceptance for the additive schema6 market draft/version
 * persistence and owner reads. Runs against the restricted runtime role.
 */

function sha256(seed: string): string {
  return createHash('sha256').update(`openarc-market-test:${seed}`, 'utf8').digest('hex');
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
  return createHash('sha256').update(`key:${seed}`).digest().toString('base64url');
}

function userHandle(seed: number): string {
  return `${sha256(`handle:${seed}`).slice(0, 42)}A`;
}

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
    endpointContract: { origin: 'https://api.example.com', path: '/v1/run' },
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

let admin: Pool;
let migrator: Pool;
let tenant: Pool;
let worker: Pool;
let auth: Pool;
let store: MarketStore;

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
  store = new MarketStore(tenant);
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

async function seedAgent(seed: number, org: string, status = 'active'): Promise<string> {
  const id = `openarc:agent:${uuid(seed)}`;
  await admin.query(
    'INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name, status) VALUES ($1, $2, $3, $4)',
    [org, id, `Agent ${seed}`, status],
  );
  return id;
}

function credentialLookupId(seed: number): string {
  return uuid(300000 + seed);
}

const CREDENTIAL_SALT = Buffer.alloc(16, 5).toString('base64url');
const CREDENTIAL_DIGEST = Buffer.alloc(32, 6).toString('base64url');

function credentialHashInput(overrides: Record<string, unknown> = {}) {
  return {
    algorithm: 'scrypt' as const,
    hashVersion: 1 as const,
    pepperVersion: 1,
    N: 32768 as const,
    r: 8 as const,
    p: 1 as const,
    salt: CREDENTIAL_SALT,
    digest: CREDENTIAL_DIGEST,
    ...overrides,
  };
}

async function counts(): Promise<Record<string, number>> {
  const result = await admin.query<Record<string, number>>(
    `SELECT
       (SELECT count(*)::int FROM openarc_tenant.listings) AS listings,
       (SELECT count(*)::int FROM openarc_tenant.listing_versions) AS versions,
       (SELECT count(*)::int FROM openarc_tenant.listing_version_states) AS states,
       (SELECT count(*)::int FROM openarc_durable.idempotency_records) AS idem,
       (SELECT count(*)::int FROM openarc_durable.audit_events) AS audit,
       (SELECT count(*)::int FROM openarc_durable.outbox_events) AS outbox`,
  );
  const row = result.rows[0];
  if (row === undefined) throw new Error('counts failed');
  return row;
}

describe('schema6 manifest and ACLs', () => {
  it('records schema6 and keeps the market helpers migrator-owned', async () => {
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
    const helpers = await admin.query<{
      proname: string;
      owner: string;
      secdef: boolean;
      config: string[];
    }>(
      `SELECT p.proname, r.rolname AS owner, p.prosecdef AS secdef,
              coalesce(p.proconfig, ARRAY[]::text[]) AS config
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         JOIN pg_roles r ON r.oid = p.proowner
        WHERE n.nspname = 'openarc_durable'
          AND p.proname IN (
            'commit_listing_create', 'commit_listing_version_create',
            'lock_market_actor', 'read_market_mutation_status',
            'read_owner_listing_version', 'read_owner_listing_versions',
            'read_owner_listings'
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

  it('denies direct runtime table DML and helper invocation is scope-checked', async () => {
    await seedOwner(1);
    await expect(
      tenant.query('SELECT count(*) FROM openarc_tenant.listings'),
    ).rejects.toBeTruthy();
    await expect(
      tenant.query(
        "INSERT INTO openarc_tenant.listings (organization_id, provider_id, listing_id, latest_version) VALUES ('x','y','z','1')",
      ),
    ).rejects.toBeTruthy();
    // Direct definer invocation without a live session is denied.
    await expect(
      tenant.query('SELECT * FROM openarc_durable.lock_market_actor($1, $2, true, false)', [
        'f'.repeat(64),
        orgId(999),
      ]),
    ).rejects.toBeTruthy();
  });

  it('rejects invalid raw SQL content and immutable version UPDATE/DELETE', async () => {
    const owner = await seedOwner(2);
    const provider = await seedProvider(2, owner.org);
    const created = await store.createListingDraft(owner.hash, owner.org, provider, content(), {
      idempotencyKey: key(2),
      mutationId: mutationId(2),
    });
    const listingId = created.receipt.resourceId;
    await expect(
      admin.query(
        `INSERT INTO openarc_tenant.listing_versions
           (organization_id, listing_id, version, provider_id, kind, title, description,
            manifest, price, evidence_contract, endpoint_contract, terms_revision,
            privacy_summary, payment_lane, availability)
         VALUES ($1, $2, '2', $3, 'api', 't', 'd', '{}'::jsonb, '{}'::jsonb, '{}'::jsonb,
                 '{}'::jsonb, 't', 'p', 'unavailable', '{}'::jsonb)`,
        [owner.org, listingId, provider],
      ),
    ).rejects.toBeTruthy();
    await expect(
      admin.query("UPDATE openarc_tenant.listing_versions SET title = 'x'"),
    ).rejects.toMatchObject({ code: '42501' } satisfies PgError);
    await expect(
      admin.query('DELETE FROM openarc_tenant.listing_versions'),
    ).rejects.toMatchObject({ code: '42501' } satisfies PgError);
  });
});

describe('draft and version lifecycle', () => {
  it('creates a draft with a fixed first version and immutable content', async () => {
    const owner = await seedOwner(10);
    const provider = await seedProvider(10, owner.org);
    const result = await store.createListingDraft(owner.hash, owner.org, provider, content(), {
      idempotencyKey: key(10),
      mutationId: mutationId(10),
    });
    expect(result.replayed).toBe(false);
    expect(result.receipt.operation).toBe('market.listing.create');
    expect(result.receipt.resourceType).toBe('listing');
    expect(result.receipt.resourceId).toBe(`openarc:listing:${mutationId(10)}`);
    expect(result.receipt.committedAt).toMatch(/Z$/);

    const version = await store.getOwnerListingVersion(
      owner.hash,
      owner.org,
      result.receipt.resourceId,
      '1',
    );
    expect(version?.status).toBe('draft');
    expect(version?.originReviewState).toBe('unreviewed');
    expect(version?.publishedAt).toBeNull();
    expect(version?.paymentLane).toBe('unavailable');
    expect(version?.title).toBe('Example API');

    const totals = await counts();
    expect(totals).toMatchObject({ listings: 1, versions: 1, states: 1, idem: 1, audit: 1, outbox: 1 });
  });

  it('allocates the next canonical version with exact CAS and one-extra-row paging', async () => {
    const owner = await seedOwner(11);
    const provider = await seedProvider(11, owner.org);
    const draft = await store.createListingDraft(owner.hash, owner.org, provider, content(), {
      idempotencyKey: key(11),
      mutationId: mutationId(11),
    });
    const listingId = draft.receipt.resourceId;
    const next = await store.createListingVersion(
      owner.hash,
      owner.org,
      listingId,
      { expectedLatestVersion: '1', content: content({ title: 'Example API v2' }) },
      { idempotencyKey: key(11_1), mutationId: mutationId(11_1) },
    );
    expect(next.receipt.resourceId).toBe(`${listingId}@2`);

    await expectCode(
      store.createListingVersion(
        owner.hash,
        owner.org,
        listingId,
        { expectedLatestVersion: '1', content: content() },
        { idempotencyKey: key(11_2), mutationId: mutationId(11_2) },
      ),
      'MARKET_STORE_CONFLICT',
    );

    const page = await store.listOwnerListingVersions(owner.hash, owner.org, listingId, { limit: 1 });
    expect(page.items.map((item) => item.version)).toEqual(['1']);
    expect(page.nextCursor).toBe('1');
    const secondPage = await store.listOwnerListingVersions(owner.hash, owner.org, listingId, {
      afterVersion: '1',
      limit: 1,
    });
    expect(secondPage.items.map((item) => item.version)).toEqual(['2']);
    expect(secondPage.nextCursor).toBeNull();
  });

  it('replays the same key and conflicts on changed content', async () => {
    const owner = await seedOwner(12);
    const provider = await seedProvider(12, owner.org);
    const meta = { idempotencyKey: key(12), mutationId: mutationId(12) };
    const first = await store.createListingDraft(owner.hash, owner.org, provider, content(), meta);
    const replay = await store.createListingDraft(owner.hash, owner.org, provider, content(), meta);
    expect(replay.replayed).toBe(true);
    expect(replay.receipt).toEqual(first.receipt);
    await expectCode(
      store.createListingDraft(
        owner.hash,
        owner.org,
        provider,
        content({ title: 'Different' }),
        meta,
      ),
      'MARKET_STORE_IDEMPOTENCY_CONFLICT',
    );
    await expectCode(
      store.createListingDraft(owner.hash, owner.org, provider, content(), {
        idempotencyKey: key(12_1),
        mutationId: mutationId(12),
      }),
      'MARKET_STORE_IDEMPOTENCY_CONFLICT',
    );
  });

  it('enforces the write role matrix and provider binding', async () => {
    const owner = await seedOwner(13);
    const provider = await seedProvider(13, owner.org);
    const viewer = await seedAccount(14);
    const viewerHash = await seedSession(14, viewer);
    await admin.query(
      'INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, $3, $4)',
      [owner.org, viewer, 'viewer', 'active'],
    );
    await expectCode(
      store.createListingDraft(viewerHash, owner.org, provider, content(), {
        idempotencyKey: key(14),
        mutationId: mutationId(14),
      }),
      'MARKET_STORE_FORBIDDEN',
    );
    const otherOwner = await seedOwner(15);
    const foreignProvider = await seedProvider(15, otherOwner.org);
    await expectCode(
      store.createListingDraft(owner.hash, owner.org, foreignProvider, content(), {
        idempotencyKey: key(15),
        mutationId: mutationId(15),
      }),
      'MARKET_STORE_NOT_FOUND',
    );
  });

  it('denies retired-provider creation and stale/recovery proof writes', async () => {
    const owner = await seedOwner(16);
    const retired = await seedProvider(16, owner.org, 'retired');
    await expectCode(
      store.createListingDraft(owner.hash, owner.org, retired, content(), {
        idempotencyKey: key(16),
        mutationId: mutationId(16),
      }),
      'MARKET_STORE_FORBIDDEN',
    );
    const recovery = await seedAccount(17);
    const recoveryHash = await seedSession(17, recovery, { method: 'recovery' });
    await admin.query(
      'INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, $3, $4)',
      [owner.org, recovery, 'owner', 'active'],
    );
    const provider = await seedProvider(17, owner.org);
    await expectCode(
      store.createListingDraft(recoveryHash, owner.org, provider, content(), {
        idempotencyKey: key(17),
        mutationId: mutationId(17),
      }),
      'MARKET_STORE_SESSION_INVALID',
    );
  });

  it('allows all five active roles to read history but not write', async () => {
    const owner = await seedOwner(18);
    const provider = await seedProvider(18, owner.org);
    const draft = await store.createListingDraft(owner.hash, owner.org, provider, content(), {
      idempotencyKey: key(18),
      mutationId: mutationId(18),
    });
    for (const [index, role] of ['operator', 'provider_admin', 'provider_developer', 'viewer'].entries()) {
      const member = await seedAccount(20 + index);
      const memberHash = await seedSession(20 + index, member);
      await admin.query(
        'INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, $3, $4)',
        [owner.org, member, role, 'active'],
      );
      const page = await store.listOwnerListings(memberHash, owner.org);
      expect(page.items).toHaveLength(1);
      const version = await store.getOwnerListingVersion(
        memberHash,
        owner.org,
        draft.receipt.resourceId,
        '1',
      );
      expect(version?.version).toBe('1');
    }
  });

  it('reports market-only status and excludes other operations', async () => {
    const owner = await seedOwner(19);
    const provider = await seedProvider(19, owner.org);
    const draft = await store.createListingDraft(owner.hash, owner.org, provider, content(), {
      idempotencyKey: key(19),
      mutationId: mutationId(19),
    });
    const status = await store.getMarketMutationStatus(owner.hash, owner.org, mutationId(19));
    expect(status).toEqual({ status: 'committed', receipt: draft.receipt });

    const base = new TenantStore(tenant);
    const tenantStatus = await base.getAgentMutationStatus(owner.hash, owner.org, mutationId(19));
    expect(tenantStatus).toEqual({ status: 'not_found' });
    expect(await store.getMarketMutationStatus(owner.hash, owner.org, mutationId(999))).toEqual({
      status: 'not_found',
    });
  });

  it('rolls back a failed create leaving no orphan rows', async () => {
    const owner = await seedOwner(22);
    const provider = await seedProvider(22, owner.org);
    const before = await counts();
    await expectCode(
      store.createListingDraft(
        owner.hash,
        owner.org,
        provider,
        content({ endpointContract: { origin: 'https://api.example.com', path: '/a//b' } }),
        { idempotencyKey: key(22), mutationId: mutationId(22) },
      ),
      'MARKET_STORE_INPUT_INVALID',
    );
    expect(await counts()).toEqual(before);
  });

  it('reads are transaction-safe and readiness passes against schema6', async () => {
    await new MarketStore(tenant).readiness();
    const raw = await tenant.query<{ n: number }>(
      "SELECT count(*)::int AS n FROM pg_namespace WHERE nspname = 'openarc_market'",
    );
    expect(raw.rows[0]?.n).toBe(0);
  });
});

/**
 * Raw definer/table content validation: exercises the SQL validators directly
 * (bypassing the TS parser) so a malformed row can never be persisted even by a
 * privileged SQL caller. Every JSON null / wrong type / extra / missing key and
 * every endpoint/port/unicode boundary is asserted.
 */
async function rawAssertListingContent(candidate: Record<string, unknown>): Promise<void> {
  await admin.query(
    `SELECT openarc_durable.assert_listing_content(
       $1, $2, $3, $4::jsonb, $5::jsonb, $6::jsonb, $7::jsonb, $8, $9, $10, $11::jsonb)`,
    [
      candidate['kind'],
      candidate['title'],
      candidate['description'],
      JSON.stringify(candidate['manifest']),
      JSON.stringify(candidate['price']),
      JSON.stringify(candidate['evidenceContract']),
      JSON.stringify(candidate['endpointContract']),
      candidate['termsRevision'],
      candidate['privacySummary'],
      candidate['paymentLane'],
      JSON.stringify(candidate['availability']),
    ],
  );
}

function withManifest(patch: Record<string, unknown>): Record<string, unknown> {
  const base = content();
  return { ...base, manifest: { ...(base['manifest'] as Record<string, unknown>), ...patch } };
}

function withPriceAmount(patch: Record<string, unknown>): Record<string, unknown> {
  const base = content();
  const price = base['price'] as { amount: Record<string, unknown> };
  return { ...base, price: { ...price, amount: { ...price.amount, ...patch } } };
}

function withEvidence(patch: Record<string, unknown>): Record<string, unknown> {
  const base = content();
  return {
    ...base,
    evidenceContract: { ...(base['evidenceContract'] as Record<string, unknown>), ...patch },
  };
}

function withEndpoint(origin: string, path = '/v1/run'): Record<string, unknown> {
  return { ...content(), endpointContract: { origin, path } };
}

function withAvailability(patch: Record<string, unknown>): Record<string, unknown> {
  const base = content();
  return {
    ...base,
    availability: { ...(base['availability'] as Record<string, unknown>), ...patch },
  };
}

describe('raw SQL content validation matches the accepted strict schema', () => {
  it('rejects JSON null, wrong type, extra and missing keys in every nested contract', async () => {
    const cases: readonly Record<string, unknown>[] = [
      withManifest({ schemaVersion: null }),
      withManifest({ inputSchemaDigest: null }),
      withManifest({ inputSchemaDigest: 42 }),
      withManifest({ unexpected: 'x' }),
      (() => {
        const candidate = withManifest({});
        delete (candidate['manifest'] as Record<string, unknown>)['outputSchemaDigest'];
        return candidate;
      })(),
      { ...content(), manifest: null },
      { ...content(), price: null },
      withPriceAmount({ decimals: '6' }),
      withPriceAmount({ decimals: 7 }),
      withPriceAmount({ atomicAmount: null }),
      withPriceAmount({ atomicAmount: 1000000 }),
      withPriceAmount({ atomicAmount: '0' }),
      withPriceAmount({ atomicAmount: '01' }),
      withPriceAmount({
        atomicAmount:
          '115792089237316195423570985008687907853269984665640564039457584007913129639936',
      }),
      withEvidence({ receiptType: null }),
      withEvidence({ receiptType: 'Receipt' }),
      withEvidence({ deliveryFields: null }),
      withEvidence({ deliveryFields: ['ok', 5] }),
      withEvidence({ deliveryFields: ['dup', 'dup'] }),
      withEvidence({ deliveryFields: [] }),
      withEvidence({ deliveryFields: Array.from({ length: 33 }, (_v, i) => `f${i}`) }),
      withAvailability({ status: null }),
      withAvailability({ status: 'maybe' }),
      withAvailability({ rateLimitPerMinute: 60 }),
      withAvailability({ rateLimitPerMinute: '0' }),
      withAvailability({ rateLimitPerMinute: '1000001' }),
      withAvailability({ rateLimitPerMinute: '01' }),
      { ...content(), title: '\u00a0leading' },
      { ...content(), title: 'trailing\ufeff' },
      { ...content(), title: 'a\u0001b' },
      { ...content(), title: `a${'\u0085'}b` },
      { ...content(), title: '\u10348'.repeat(51) },
      withEndpoint(null as unknown as string),
      withEndpoint('https://api.example.com:443'),
      withEndpoint('https://api.example.com:0'),
      withEndpoint('https://api.example.com:099'),
      withEndpoint('https://api.example.com:65536'),
      withEndpoint('https://API.example.com'),
      withEndpoint('https://127.0.0.1'),
      withEndpoint('https://0x7f.1'),
      withEndpoint('https://api.example.com.'),
      withEndpoint('https://localhost'),
      withEndpoint('https://api.internal'),
      withEndpoint('https://api.example.com', '/v1//run'),
      withEndpoint('https://api.example.com', '/v1/../run'),
      withEndpoint('https://api.example.com', '/v1/%2e'),
      withEndpoint('https://api.example.com', 'no-leading-slash'),
    ];
    for (const candidate of cases) {
      await expect(
        rawAssertListingContent(candidate),
        `expected rejection for ${JSON.stringify(candidate)}`,
      ).rejects.toMatchObject({ code: '22023' } satisfies PgError);
    }
  });

  it('accepts the exact boundary content values through raw SQL', async () => {
    const maxAtomic =
      '115792089237316195423570985008687907853269984665640564039457584007913129639935';
    const valid: readonly Record<string, unknown>[] = [
      content(),
      withPriceAmount({ atomicAmount: '1' }),
      withPriceAmount({ atomicAmount: maxAtomic }),
      withAvailability({ rateLimitPerMinute: '1000000' }),
      withAvailability({ rateLimitPerMinute: null }),
      withEndpoint('https://api.example.com:8443'),
      { ...content(), title: '\u10348'.repeat(50) },
      { ...content(), title: 'ok\u10348' },
    ];
    for (const candidate of valid) {
      await expect(
        rawAssertListingContent(candidate),
        `expected acceptance for ${JSON.stringify(candidate)}`,
      ).resolves.toBeUndefined();
    }
  });

  it('validates the bare JSON check helpers against JSON null independently of NOT NULL', async () => {
    const probes: readonly { sql: string; expect: boolean }[] = [
      { sql: 'openarc_durable.is_valid_listing_manifest(NULL)', expect: false },
      { sql: "openarc_durable.is_valid_listing_manifest('null'::jsonb)", expect: false },
      { sql: 'openarc_durable.is_valid_listing_price(NULL)', expect: false },
      { sql: 'openarc_durable.is_valid_receipt_contract(NULL)', expect: false },
      { sql: 'openarc_durable.is_valid_endpoint_contract(NULL)', expect: false },
      { sql: 'openarc_durable.is_valid_listing_availability(NULL)', expect: false },
      { sql: "openarc_durable.is_canonical_endpoint_origin('https://api.example.com:8443')", expect: true },
      { sql: "openarc_durable.is_canonical_endpoint_origin('https://api.example.com')", expect: true },
    ];
    for (const probe of probes) {
      const result = await admin.query<{ value: boolean }>(`SELECT ${probe.sql} AS value`);
      expect(result.rows[0]?.value, probe.sql).toBe(probe.expect);
    }
  });

  it('bounds the complete origin at 253, not only the DNS host', async () => {
    // Four valid labels totalling exactly 252 host characters: 63.63.63.60.
    const host252 = ['a'.repeat(63), 'a'.repeat(63), 'a'.repeat(63), 'a'.repeat(60)].join('.');
    expect(host252).toHaveLength(252);
    const origin260 = `https://${host252}`;
    expect(origin260).toHaveLength(260);
    await expect(
      rawAssertListingContent(withEndpoint(origin260)),
      'full origin of 260 must be rejected even though the host is 252',
    ).rejects.toMatchObject({ code: '22023' } satisfies PgError);

    // A complete origin of exactly 253 (host 245) remains valid.
    const host245 = ['a'.repeat(63), 'a'.repeat(63), 'a'.repeat(63), 'a'.repeat(53)].join('.');
    expect(host245).toHaveLength(245);
    const origin253 = `https://${host245}`;
    expect(origin253).toHaveLength(253);
    await expect(rawAssertListingContent(withEndpoint(origin253))).resolves.toBeUndefined();
  });
});

describe('raw market resource shape constraints', () => {
  it('rejects listingId@2@extra and listingId@1 on receipts, audit and outbox', async () => {
    const owner = await seedOwner(44);
    const provider = await seedProvider(44, owner.org);
    const draft = await store.createListingDraft(owner.hash, owner.org, provider, content(), {
      idempotencyKey: key(44),
      mutationId: mutationId(44),
    });
    const listingId = draft.receipt.resourceId;
    await store.createListingVersion(
      owner.hash,
      owner.org,
      listingId,
      { expectedLatestVersion: '1', content: content() },
      { idempotencyKey: key(45), mutationId: mutationId(45) },
    );

    const malformed = [`${listingId}@2@extra`, `${listingId}@1`];
    let seed = 4600;
    for (const resourceId of malformed) {
      seed += 1;
      const mutation = uuid(seed);
      seed += 1;
      const keyHash = sha256(`shape-key:${seed}`);
      // The exact shape CHECK is evaluated during the row insert, before the
      // receipt-FK trigger, so this reaches `*_market_resource_shape` (23514)
      // and not an unrelated foreign-key/required-field failure.
      await expect(
        admin.query(
          `INSERT INTO openarc_durable.idempotency_records (
             organization_id, operation, key_hash, request_digest, digest_version,
             actor_account_id, session_context_digest, network, mutation_id, status,
             resource_type, resource_id, committed_at)
           VALUES ($1, 'market.listing.version.create', $2, $3,
                   'market.listing.version.create.v1', $4, $5, 'eip155:5042002',
                   $6::uuid, 'committed', 'listing_version', $7, clock_timestamp())`,
          [owner.org, keyHash, sha256(`req:${seed}`), owner.account, sha256(`sess:${seed}`), mutation, resourceId],
        ),
        `idempotency shape must reject ${resourceId}`,
      ).rejects.toMatchObject({ code: '23514' } satisfies PgError);

      await expect(
        admin.query(
          `INSERT INTO openarc_durable.audit_events (
             organization_id, actor_account_id, operation, mutation_id,
             resource_type, resource_id, outcome)
           VALUES ($1, $2, 'market.listing.version.create', $3::uuid,
                   'listing_version', $4, 'committed')`,
          [owner.org, owner.account, mutation, resourceId],
        ),
        `audit shape must reject ${resourceId}`,
      ).rejects.toMatchObject({ code: '23514' } satisfies PgError);

      await expect(
        admin.query(
          `INSERT INTO openarc_durable.outbox_events (
             organization_id, mutation_id, resource_type, resource_id, event_type)
           VALUES ($1, $2::uuid, 'listing_version', $3, 'market.listing.version.created')`,
          [owner.org, mutation, resourceId],
        ),
        `outbox shape must reject ${resourceId}`,
      ).rejects.toMatchObject({ code: '23514' } satisfies PgError);
    }

    // A valid listing_version receipt still inserts for all three tables.
    const goodMutation = uuid(4700);
    const goodResource = `${listingId}@2`;
    await admin.query(
      `INSERT INTO openarc_durable.idempotency_records (
         organization_id, operation, key_hash, request_digest, digest_version,
         actor_account_id, session_context_digest, network, mutation_id, status,
         resource_type, resource_id, committed_at)
       VALUES ($1, 'market.listing.version.create', $2, $3,
               'market.listing.version.create.v1', $4, $5, 'eip155:5042002',
               $6::uuid, 'committed', 'listing_version', $7, clock_timestamp())`,
      [owner.org, sha256('good-key'), sha256('good-req'), owner.account, sha256('good-sess'), goodMutation, goodResource],
    );
    await admin.query(
      `INSERT INTO openarc_durable.audit_events (
         organization_id, actor_account_id, operation, mutation_id,
         resource_type, resource_id, outcome)
       VALUES ($1, $2, 'market.listing.version.create', $3::uuid,
               'listing_version', $4, 'committed')`,
      [owner.org, owner.account, goodMutation, goodResource],
    );
    await admin.query(
      `INSERT INTO openarc_durable.outbox_events (
         organization_id, mutation_id, resource_type, resource_id, event_type)
       VALUES ($1, $2::uuid, 'listing_version', $3, 'market.listing.version.created')`,
      [owner.org, goodMutation, goodResource],
    );
  });
});

describe('root active_version pointer', () => {
  async function roots(listingId: string): Promise<{ active: string | null; latest: string | null }> {
    const result = await admin.query<{ active_version: string | null; latest_version: string }>(
      'SELECT active_version, latest_version FROM openarc_tenant.listings WHERE listing_id = $1',
      [listingId],
    );
    const row = result.rows[0];
    if (row === undefined) throw new Error('root missing');
    return { active: row.active_version, latest: row.latest_version };
  }

  it('keeps active_version NULL for a draft and after a next-version insert', async () => {
    const owner = await seedOwner(40);
    const provider = await seedProvider(40, owner.org);
    const draft = await store.createListingDraft(owner.hash, owner.org, provider, content(), {
      idempotencyKey: key(40),
      mutationId: mutationId(40),
    });
    const listingId = draft.receipt.resourceId;
    expect(await roots(listingId)).toEqual({ active: null, latest: '1' });

    await store.createListingVersion(
      owner.hash,
      owner.org,
      listingId,
      { expectedLatestVersion: '1', content: content() },
      { idempotencyKey: key(41), mutationId: mutationId(41) },
    );
    expect(await roots(listingId)).toEqual({ active: null, latest: '2' });

    const page = await store.listOwnerListings(owner.hash, owner.org);
    expect(page.items[0]?.activeVersion).toBeNull();
  });

  it('rejects cross-listing/nonexistent pointer values and any active_version UPDATE', async () => {
    const owner = await seedOwner(42);
    const provider = await seedProvider(42, owner.org);
    const draft = await store.createListingDraft(owner.hash, owner.org, provider, content(), {
      idempotencyKey: key(42),
      mutationId: mutationId(42),
    });
    const listingId = draft.receipt.resourceId;
    const foreignListing = 'openarc:listing:' + uuid(4242);

    // active_version referencing a nonexistent version is rejected by the FK.
    await expect(
      admin.query(
        `INSERT INTO openarc_tenant.listings
           (organization_id, provider_id, listing_id, latest_version, active_version)
         VALUES ($1, $2, $3, '1', '7')`,
        [owner.org, provider, foreignListing],
      ),
    ).rejects.toMatchObject({ code: '23503' } satisfies PgError);

    // latest_version referencing a nonexistent version is rejected at commit.
    await expect(
      admin.query(
        `INSERT INTO openarc_tenant.listings
           (organization_id, provider_id, listing_id, latest_version)
         VALUES ($1, $2, $3, '9')`,
        [owner.org, provider, 'openarc:listing:' + uuid(4243)],
      ),
    ).rejects.toMatchObject({ code: '23503' } satisfies PgError);

    // Any change to the separate active pointer is immutability-protected.
    await expect(
      admin.query('UPDATE openarc_tenant.listings SET active_version = $1 WHERE listing_id = $2', [
        '1',
        listingId,
      ]),
    ).rejects.toMatchObject({ code: '42501' } satisfies PgError);
    await expect(
      admin.query('UPDATE openarc_tenant.listings SET latest_version = $1 WHERE listing_id = $2', [
        '0',
        listingId,
      ]),
    ).rejects.toBeTruthy();
    expect(await roots(listingId)).toEqual({ active: null, latest: '1' });
  });
});

async function durableCounts(): Promise<Record<string, number>> {
  const result = await admin.query<Record<string, number>>(
    `SELECT
       (SELECT count(*)::int FROM openarc_durable.idempotency_records) AS idem,
       (SELECT count(*)::int FROM openarc_durable.audit_events) AS audit,
       (SELECT count(*)::int FROM openarc_durable.outbox_events) AS outbox,
       (SELECT count(*)::int FROM openarc_tenant.organizations) AS organizations,
       (SELECT count(*)::int FROM openarc_tenant.agents) AS agents,
       (SELECT count(*)::int FROM openarc_tenant.providers) AS providers,
       (SELECT count(*)::int FROM openarc_durable.agent_credentials) AS agent_credentials,
       (SELECT count(*)::int FROM openarc_durable.provider_credentials) AS provider_credentials`,
  );
  const row = result.rows[0];
  if (row === undefined) throw new Error('durable counts failed');
  return row;
}

/** Wait on an observed PostgreSQL lock wait, never a timing-only sleep. */
async function waitForProviderLockWait(): Promise<void> {
  for (let attempt = 0; attempt < 500; attempt += 1) {
    const result = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n
        FROM pg_stat_activity
        WHERE wait_event_type = 'Lock'
          AND query ILIKE '%commit_listing%'`,
    );
    if ((result.rows[0]?.n ?? 0) > 0) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error('provider lock wait was not observed');
}

/** Wait until an observed backend is actually blocked on a table lock. */
async function waitForBackendLockWait(queryFragment: string): Promise<void> {
  for (let attempt = 0; attempt < 500; attempt += 1) {
    const result = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n
         FROM pg_stat_activity
        WHERE wait_event_type = 'Lock'
          AND query ILIKE $1`,
      [`%${queryFragment}%`],
    );
    if ((result.rows[0]?.n ?? 0) > 0) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`lock wait was not observed for ${queryFragment}`);
}

describe('upgrade from schema5 preserves durable records and replay', () => {
  it('applies 0001-0005, keeps tenant durable rows/replay across 0006', async () => {
    await resetSchema(admin);
    const all = loadMigrations();
    await migrate(migrator, all.slice(0, 5));
    const owner = await seedOwner(50);
    const base = new TenantStore(tenant);
    const meta = { idempotencyKey: key(50), mutationId: mutationId(50) };
    await base.createAgentDurably(owner.hash, owner.org, 'Legacy Agent', meta);
    const before = await durableCounts();
    expect(before).toMatchObject({ idem: 1, audit: 1, outbox: 1, organizations: 1, agents: 1 });

    await migrate(migrator);
    const applied = await admin.query<{ id: string }>(
      'SELECT id FROM openarc_meta.schema_migrations ORDER BY id',
    );
    expect(applied.rows.map((row) => row.id)).toContain('0006_market');
    expect(await durableCounts()).toEqual(before);

    const replay = await base.createAgentDurably(owner.hash, owner.org, 'Legacy Agent', meta);
    expect(replay.replayed).toBe(true);
    expect(await durableCounts()).toEqual(before);
  });

  it('preserves provider + agent/provider credential durable replay across 0006', async () => {
    await resetSchema(admin);
    const all = loadMigrations();
    await migrate(migrator, all.slice(0, 5));
    const owner = await seedOwner(52);
    const agent = await seedAgent(52, owner.org);
    const provider = await seedProvider(52, owner.org);
    const credentials = new CredentialStore(tenant);
    const expiresAt = new Date(Date.now() + 60 * 60_000).toISOString();
    const agentIssue = await credentials.issueAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: agent,
      lookupId: credentialLookupId(52),
      hash: credentialHashInput(),
      expiresAt,
      metadata: { idempotencyKey: key(52), mutationId: mutationId(52) },
    });
    const providerIssue = await credentials.issueProviderCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: provider,
      lookupId: credentialLookupId(53),
      hash: credentialHashInput(),
      expiresAt,
      metadata: { idempotencyKey: key(53), mutationId: mutationId(53) },
    });
    expect(agentIssue.receipt.operation).toBe('tenant.agent.credential.issue');
    expect(providerIssue.receipt.operation).toBe('tenant.provider.credential.issue');
    const before = await durableCounts();
    expect(before).toMatchObject({
      idem: 2,
      audit: 2,
      outbox: 2,
      organizations: 1,
      agents: 1,
      providers: 1,
      agent_credentials: 1,
      provider_credentials: 1,
    });
    const storedAgent = await admin.query<{ pepper_version: number; salt: string; lookup_id: string }>(
      'SELECT pepper_version, salt, lookup_id FROM openarc_durable.agent_credentials WHERE credential_id = $1::uuid',
      [mutationId(52)],
    );

    await migrate(migrator);
    const applied = await admin.query<{ id: string }>(
      'SELECT id FROM openarc_meta.schema_migrations ORDER BY id',
    );
    expect(applied.rows.map((row) => row.id)).toContain('0006_market');
    expect(await durableCounts()).toEqual(before);
    // The stored credential material is byte-for-byte unchanged by the upgrade.
    expect(
      await admin.query<{ pepper_version: number; salt: string; lookup_id: string }>(
        'SELECT pepper_version, salt, lookup_id FROM openarc_durable.agent_credentials WHERE credential_id = $1::uuid',
        [mutationId(52)],
      ),
    ).toEqual(storedAgent);

    const agentReplay = await credentials.issueAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: agent,
      lookupId: credentialLookupId(54),
      hash: credentialHashInput({ pepperVersion: 2 }),
      expiresAt,
      metadata: { idempotencyKey: key(52), mutationId: mutationId(52) },
    });
    expect(agentReplay.replayed).toBe(true);
    expect(agentReplay.receipt).toEqual(agentIssue.receipt);
    const providerReplay = await credentials.issueProviderCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: provider,
      lookupId: credentialLookupId(55),
      hash: credentialHashInput({ pepperVersion: 2 }),
      expiresAt,
      metadata: { idempotencyKey: key(53), mutationId: mutationId(53) },
    });
    expect(providerReplay.replayed).toBe(true);
    expect(providerReplay.receipt).toEqual(providerIssue.receipt);
    expect(await durableCounts()).toEqual(before);
  });
});

describe('two real connection races', () => {
  it('same key and content: one create and one replay with exact row/audit/outbox counts', async () => {
    const owner = await seedOwner(60);
    const provider = await seedProvider(60, owner.org);
    const peer = createDatabasePool(tenantUrl());
    try {
      const meta = { idempotencyKey: key(60), mutationId: mutationId(60) };
      const [first, second] = await Promise.all([
        store.createListingDraft(owner.hash, owner.org, provider, content(), meta),
        new MarketStore(peer).createListingDraft(owner.hash, owner.org, provider, content(), meta),
      ]);
      const replayed = [first.replayed, second.replayed].sort();
      expect(replayed).toEqual([false, true]);
      expect(first.receipt).toEqual(second.receipt);
      expect(await counts()).toMatchObject({
        listings: 1,
        versions: 1,
        states: 1,
        idem: 1,
        audit: 1,
        outbox: 1,
      });
    } finally {
      await peer.end();
    }
  });

  it('same expectedLatestVersion with different keys: one version and one conflict', async () => {
    const owner = await seedOwner(61);
    const provider = await seedProvider(61, owner.org);
    const draft = await store.createListingDraft(owner.hash, owner.org, provider, content(), {
      idempotencyKey: key(61),
      mutationId: mutationId(61),
    });
    const listingId = draft.receipt.resourceId;
    const peer = createDatabasePool(tenantUrl());
    try {
      const results = await Promise.allSettled([
        store.createListingVersion(
          owner.hash,
          owner.org,
          listingId,
          { expectedLatestVersion: '1', content: content({ title: 'Race A' }) },
          { idempotencyKey: key(62), mutationId: mutationId(62) },
        ),
        new MarketStore(peer).createListingVersion(
          owner.hash,
          owner.org,
          listingId,
          { expectedLatestVersion: '1', content: content({ title: 'Race B' }) },
          { idempotencyKey: key(63), mutationId: mutationId(63) },
        ),
      ]);
      const fulfilled = results.filter((result) => result.status === 'fulfilled');
      const rejected = results.filter((result) => result.status === 'rejected');
      expect(fulfilled).toHaveLength(1);
      expect(rejected).toHaveLength(1);
      expect((rejected[0] as PromiseRejectedResult).reason).toMatchObject({
        code: 'MARKET_STORE_CONFLICT',
      });
      expect(await counts()).toMatchObject({ listings: 1, versions: 2, states: 2, idem: 2, audit: 2, outbox: 2 });
    } finally {
      await peer.end();
    }
  });
});

describe('cross-principal and same-mutation key conflicts', () => {
  it('rejects the same key reused by a different actor in the same organization', async () => {
    const owner = await seedOwner(70);
    const provider = await seedProvider(70, owner.org);
    const other = await seedAccount(71);
    const otherHash = await seedSession(71, other);
    await admin.query(
      'INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, $3, $4)',
      [owner.org, other, 'owner', 'active'],
    );
    const meta = { idempotencyKey: key(70), mutationId: mutationId(70) };
    await store.createListingDraft(owner.hash, owner.org, provider, content(), meta);
    await expectCode(
      store.createListingDraft(otherHash, owner.org, provider, content(), meta),
      'MARKET_STORE_IDEMPOTENCY_CONFLICT',
    );
    expect(await counts()).toMatchObject({ listings: 1, idem: 1, audit: 1, outbox: 1 });
  });

  it('rejects the same logical mutation under a new key', async () => {
    const owner = await seedOwner(72);
    const provider = await seedProvider(72, owner.org);
    const mutation = mutationId(72);
    await store.createListingDraft(owner.hash, owner.org, provider, content(), {
      idempotencyKey: key(72),
      mutationId: mutation,
    });
    await expectCode(
      store.createListingDraft(owner.hash, owner.org, provider, content(), {
        idempotencyKey: key(73),
        mutationId: mutation,
      }),
      'MARKET_STORE_IDEMPOTENCY_CONFLICT',
    );
    expect(await counts()).toMatchObject({ listings: 1, versions: 1, idem: 1 });
  });
});

describe('market status isolation and effective ACLs', () => {
  it('never returns a cross-registry receipt in either direction', async () => {
    const owner = await seedOwner(80);
    const provider = await seedProvider(80, owner.org);
    const marketMutation = mutationId(80);
    const draft = await store.createListingDraft(owner.hash, owner.org, provider, content(), {
      idempotencyKey: key(80),
      mutationId: marketMutation,
    });
    const base = new TenantStore(tenant);
    const tenantMutation = mutationId(81);
    await base.createAgentDurably(owner.hash, owner.org, 'Status Agent', {
      idempotencyKey: key(81),
      mutationId: tenantMutation,
    });

    expect(await store.getMarketMutationStatus(owner.hash, owner.org, marketMutation)).toEqual({
      status: 'committed',
      receipt: draft.receipt,
    });
    expect(await base.getAgentMutationStatus(owner.hash, owner.org, marketMutation)).toEqual({
      status: 'not_found',
    });
    expect(await store.getMarketMutationStatus(owner.hash, owner.org, tenantMutation)).toEqual({
      status: 'not_found',
    });
  });

  it('denies worker/auth direct content reads and public/forbidden helper EXECUTE', async () => {
    await seedOwner(82);
    await expect(worker.query('SELECT * FROM openarc_tenant.listings')).rejects.toBeTruthy();
    await expect(worker.query('SELECT * FROM openarc_tenant.listing_versions')).rejects.toBeTruthy();
    await expect(auth.query('SELECT * FROM openarc_tenant.listing_versions')).rejects.toBeTruthy();

    const grants = await admin.query<{ forbidden: number; public_grants: number }>(
      `SELECT
         (SELECT count(*)::int
            FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
            CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
            JOIN pg_roles gr ON gr.oid = a.grantee
           WHERE n.nspname = 'openarc_durable'
             AND p.proname IN (
               'commit_listing_create', 'commit_listing_version_create', 'lock_market_actor',
               'read_market_mutation_status', 'read_owner_listing_version',
               'read_owner_listing_versions', 'read_owner_listings')
             AND gr.rolname IN ('openarc_worker_app', 'openarc_auth_app')
             AND a.privilege_type = 'EXECUTE') AS forbidden,
         (SELECT count(*)::int
            FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
            CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
           WHERE n.nspname = 'openarc_durable'
             AND p.proname IN (
               'commit_listing_create', 'commit_listing_version_create', 'lock_market_actor',
               'read_market_mutation_status', 'read_owner_listing_version',
               'read_owner_listing_versions', 'read_owner_listings')
             AND a.grantee = 0 AND a.privilege_type = 'EXECUTE') AS public_grants`,
    );
    expect(grants.rows[0]).toEqual({ forbidden: 0, public_grants: 0 });
  });
});

describe('transactional atomicity and expiry under lock contention', () => {
  it('locks the provider before the listing for a next-version write', async () => {
    const owner = await seedOwner(93);
    const provider = await seedProvider(93, owner.org);
    const draft = await store.createListingDraft(owner.hash, owner.org, provider, content(), {
      idempotencyKey: key(93),
      mutationId: mutationId(93),
    });
    const holder = await admin.connect();
    try {
      await holder.query('BEGIN');
      await holder.query(
        'SELECT 1 FROM openarc_tenant.providers WHERE organization_id = $1 AND provider_id = $2 FOR UPDATE',
        [owner.org, provider],
      );
      const pending = store.createListingVersion(
        owner.hash,
        owner.org,
        draft.receipt.resourceId,
        { expectedLatestVersion: '1', content: content() },
        { idempotencyKey: key(94), mutationId: mutationId(94) },
      );
      // The write must block on the provider lock, proving provider precedes
      // listing in the lock order (the listing row is not held here).
      await waitForProviderLockWait();
      await holder.query('ROLLBACK');
      const result = await pending;
      expect(result.receipt.resourceId).toBe(`${draft.receipt.resourceId}@2`);
    } finally {
      try {
        await holder.query('ROLLBACK');
      } catch {
        // already rolled back
      }
      holder.release();
    }
    expect(await counts()).toMatchObject({ versions: 2, states: 2, idem: 2, audit: 2, outbox: 2 });
  }, 20000);

  it('rolls back every table when the audit write fails after root/version insert', async () => {
    const owner = await seedOwner(90);
    const provider = await seedProvider(90, owner.org);
    await admin.query(`
      CREATE FUNCTION openarc_tenant._market_test_fail_audit() RETURNS trigger
      LANGUAGE plpgsql SET search_path = pg_catalog AS $$
      BEGIN
        RAISE EXCEPTION 'injected_audit_failure' USING ERRCODE = '40001';
      END;
      $$;
      CREATE TRIGGER _market_test_fail_audit
        BEFORE INSERT ON openarc_durable.audit_events
        FOR EACH ROW EXECUTE FUNCTION openarc_tenant._market_test_fail_audit();
    `);
    await expectCode(
      store.createListingDraft(owner.hash, owner.org, provider, content(), {
        idempotencyKey: key(90),
        mutationId: mutationId(90),
      }),
      'MARKET_STORE_UNAVAILABLE',
    );
    expect(await counts()).toEqual({
      listings: 0,
      versions: 0,
      states: 0,
      idem: 0,
      audit: 0,
      outbox: 0,
    });
  });

  it('rolls back every table when the outbox write fails after the audit insert', async () => {
    const owner = await seedOwner(91);
    const provider = await seedProvider(91, owner.org);
    await admin.query(`
      CREATE FUNCTION openarc_tenant._market_test_fail_outbox() RETURNS trigger
      LANGUAGE plpgsql SET search_path = pg_catalog AS $$
      BEGIN
        RAISE EXCEPTION 'injected_outbox_failure' USING ERRCODE = '40001';
      END;
      $$;
      CREATE TRIGGER _market_test_fail_outbox
        BEFORE INSERT ON openarc_durable.outbox_events
        FOR EACH ROW EXECUTE FUNCTION openarc_tenant._market_test_fail_outbox();
    `);
    await expectCode(
      store.createListingDraft(owner.hash, owner.org, provider, content(), {
        idempotencyKey: key(91),
        mutationId: mutationId(91),
      }),
      'MARKET_STORE_UNAVAILABLE',
    );
    expect(await counts()).toEqual({
      listings: 0,
      versions: 0,
      states: 0,
      idem: 0,
      audit: 0,
      outbox: 0,
    });
  });

  it(
    'rolls back a write whose session expires while blocked, and denies the expired read',
    async () => {
      const owner = await seedOwner(92);
      const provider = await seedProvider(92, owner.org);
      await admin.query(
        "UPDATE openarc_auth.sessions SET expires_at = now() + interval '1500 milliseconds' WHERE token_hash = $1",
        [owner.hash],
      );
      const holder = await admin.connect();
      let pending: Promise<unknown> | undefined;
      try {
        await holder.query('BEGIN');
        await holder.query(
          'SELECT 1 FROM openarc_tenant.providers WHERE organization_id = $1 AND provider_id = $2 FOR UPDATE',
          [owner.org, provider],
        );
        pending = store.createListingDraft(owner.hash, owner.org, provider, content(), {
          idempotencyKey: key(92),
          mutationId: mutationId(92),
        });
        await waitForProviderLockWait();
        // Advance on the database clock, not a client sleep, until expiry.
        let expired = false;
        for (let attempt = 0; attempt < 500 && !expired; attempt += 1) {
          const clock = await admin.query<{ expired: boolean }>(
            `SELECT clock_timestamp() > (SELECT expires_at FROM openarc_auth.sessions WHERE token_hash = $1) AS expired`,
            [owner.hash],
          );
          expired = clock.rows[0]?.expired === true;
          if (!expired) await new Promise((resolve) => setTimeout(resolve, 20));
        }
        expect(expired).toBe(true);
        await holder.query('ROLLBACK');
        await expectCode(pending, 'MARKET_STORE_SESSION_INVALID');
      } finally {
        try {
          await holder.query('ROLLBACK');
        } catch {
          // already rolled back
        }
        holder.release();
      }
      expect(await counts()).toEqual({
        listings: 0,
        versions: 0,
        states: 0,
        idem: 0,
        audit: 0,
        outbox: 0,
      });
      await expectCode(store.listOwnerListings(owner.hash, owner.org), 'MARKET_STORE_SESSION_INVALID');
    },
    20000,
  );
});

describe('after-materialization rechecks under a real table lock', () => {
  async function expireIn(seconds: number, hash: string): Promise<void> {
    await admin.query(
      `UPDATE openarc_auth.sessions
          SET expires_at = clock_timestamp() + make_interval(secs => $2)
        WHERE token_hash = $1`,
      [hash, seconds],
    );
  }

  async function waitUntilExpired(hash: string): Promise<void> {
    for (let attempt = 0; attempt < 500; attempt += 1) {
      const clock = await admin.query<{ expired: boolean }>(
        `SELECT clock_timestamp() > (SELECT expires_at FROM openarc_auth.sessions WHERE token_hash = $1) AS expired`,
        [hash],
      );
      if (clock.rows[0]?.expired === true) return;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    throw new Error('session did not expire by the database clock');
  }

  it('denies a protected read whose session expires while its listings SELECT is blocked', async () => {
    const owner = await seedOwner(100);
    const provider = await seedProvider(100, owner.org);
    await store.createListingDraft(owner.hash, owner.org, provider, content(), {
      idempotencyKey: key(100),
      mutationId: mutationId(100),
    });
    await expireIn(1.5, owner.hash);
    const blocker = await admin.connect();
    let pending: Promise<unknown> | undefined;
    try {
      await blocker.query('BEGIN');
      await blocker.query('LOCK TABLE openarc_tenant.listings IN ACCESS EXCLUSIVE MODE');
      pending = store.listOwnerListings(owner.hash, owner.org);
      // The definer has resolved the actor and is now blocked in its SELECT,
      // i.e. materialization has begun but not returned.
      await waitForBackendLockWait('read_owner_listings');
      await waitUntilExpired(owner.hash);
      await blocker.query('ROLLBACK');
      await expectCode(pending, 'MARKET_STORE_SESSION_INVALID');
    } finally {
      try {
        await blocker.query('ROLLBACK');
      } catch {
        // already rolled back
      }
      blocker.release();
    }
  }, 20000);

  it('rolls back a next-version write whose session expires while blocked at the root', async () => {
    const owner = await seedOwner(101);
    const provider = await seedProvider(101, owner.org);
    const draft = await store.createListingDraft(owner.hash, owner.org, provider, content(), {
      idempotencyKey: key(101),
      mutationId: mutationId(101),
    });
    const listingId = draft.receipt.resourceId;
    await expireIn(1.5, owner.hash);
    const blocker = await admin.connect();
    let pending: Promise<unknown> | undefined;
    try {
      await blocker.query('BEGIN');
      await blocker.query(
        'SELECT 1 FROM openarc_tenant.listings WHERE organization_id = $1 AND listing_id = $2 FOR UPDATE',
        [owner.org, listingId],
      );
      pending = store.createListingVersion(
        owner.hash,
        owner.org,
        listingId,
        { expectedLatestVersion: '1', content: content() },
        { idempotencyKey: key(102), mutationId: mutationId(102) },
      );
      await waitForBackendLockWait('commit_listing_version_create');
      await waitUntilExpired(owner.hash);
      await blocker.query('ROLLBACK');
      await expectCode(pending, 'MARKET_STORE_SESSION_INVALID');
    } finally {
      try {
        await blocker.query('ROLLBACK');
      } catch {
        // already rolled back
      }
      blocker.release();
    }
    const root = await admin.query<{ latest_version: string }>(
      'SELECT latest_version FROM openarc_tenant.listings WHERE listing_id = $1',
      [listingId],
    );
    expect(root.rows[0]?.latest_version).toBe('1');
    expect(await counts()).toMatchObject({
      listings: 1,
      versions: 1,
      states: 1,
      idem: 1,
      audit: 1,
      outbox: 1,
    });
  }, 20000);

  it('rolls back a create whose session expires while the late outbox insert is blocked', async () => {
    const owner = await seedOwner(103);
    const provider = await seedProvider(103, owner.org);
    await expireIn(1.5, owner.hash);
    const blocker = await admin.connect();
    let pending: Promise<unknown> | undefined;
    try {
      await blocker.query('BEGIN');
      await blocker.query('LOCK TABLE openarc_durable.outbox_events IN ACCESS EXCLUSIVE MODE');
      pending = store.createListingDraft(owner.hash, owner.org, provider, content(), {
        idempotencyKey: key(103),
        mutationId: mutationId(103),
      });
      // Root, version, state and the committed receipt already exist; the final
      // outbox INSERT is blocked. Expiry must roll the whole transaction back.
      await waitForBackendLockWait('commit_listing_create');
      await waitUntilExpired(owner.hash);
      await blocker.query('ROLLBACK');
      await expectCode(pending, 'MARKET_STORE_SESSION_INVALID');
    } finally {
      try {
        await blocker.query('ROLLBACK');
      } catch {
        // already rolled back
      }
      blocker.release();
    }
    expect(await counts()).toEqual({
      listings: 0,
      versions: 0,
      states: 0,
      idem: 0,
      audit: 0,
      outbox: 0,
    });
  }, 20000);
});

describe('direct foreign-key ownership attacks', () => {
  it('rejects cross-org/provider/listing/version references through raw SQL', async () => {
    const owner = await seedOwner(95);
    const provider = await seedProvider(95, owner.org);
    const draft = await store.createListingDraft(owner.hash, owner.org, provider, content(), {
      idempotencyKey: key(95),
      mutationId: mutationId(95),
    });
    const listingId = draft.receipt.resourceId;
    const otherOwner = await seedOwner(96);
    const foreignProvider = await seedProvider(96, otherOwner.org);

    // Provider from another organization cannot own a root in this org.
    await expect(
      admin.query(
        `INSERT INTO openarc_tenant.listings (organization_id, provider_id, listing_id, latest_version)
         VALUES ($1, $2, $3, '1')`,
        [owner.org, foreignProvider, 'openarc:listing:' + uuid(9600)],
      ),
    ).rejects.toMatchObject({ code: '23503' } satisfies PgError);

    // A version cannot bind a foreign provider/listing combination.
    await expect(
      admin.query(
        `INSERT INTO openarc_tenant.listing_versions
           (organization_id, listing_id, version, provider_id, kind, title, description,
            manifest, price, evidence_contract, endpoint_contract, terms_revision,
            privacy_summary, payment_lane, availability)
         VALUES ($1, $2, '3', $3, 'api', 't', 'd',
                 $4::jsonb, $5::jsonb, $6::jsonb, $7::jsonb, 'terms', 'privacy', 'unavailable', $8::jsonb)`,
        [
          owner.org,
          listingId,
          foreignProvider,
          JSON.stringify(content()['manifest']),
          JSON.stringify(content()['price']),
          JSON.stringify(content()['evidenceContract']),
          JSON.stringify(content()['endpointContract']),
          JSON.stringify(content()['availability']),
        ],
      ),
    ).rejects.toMatchObject({ code: '23503' } satisfies PgError);

    // An active pointer may not reference another listing's version.
    await expect(
      admin.query(
        `INSERT INTO openarc_tenant.listings
           (organization_id, provider_id, listing_id, latest_version, active_version)
         VALUES ($1, $2, $3, '2', '2')`,
        [owner.org, provider, 'openarc:listing:' + uuid(9601)],
      ),
    ).rejects.toMatchObject({ code: '23503' } satisfies PgError);
  });
});

describe('market readiness fail-closed injections', () => {
  async function expectUnavailable(): Promise<void> {
    await expectCode(new MarketStore(tenant).readiness(), 'MARKET_STORE_UNAVAILABLE');
  }

  it('fails when a new table owner is not exactly the migrator', async () => {
    await admin.query('ALTER TABLE openarc_tenant.listings OWNER TO openarc_worker_app');
    await expectUnavailable();
  });

  it('fails when a forbidden worker/auth helper EXECUTE grant appears', async () => {
    await admin.query(
      `GRANT EXECUTE ON FUNCTION openarc_durable.commit_listing_create(
         text,text,text,text,text,text,jsonb,jsonb,jsonb,jsonb,text,text,text,jsonb,uuid,text,text,text)
       TO openarc_worker_app`,
    );
    await expectUnavailable();
  });

  it('fails when a market helper search_path drifts from pg_catalog', async () => {
    await admin.query(
      `ALTER FUNCTION openarc_durable.read_owner_listings(text,text,text,integer)
       SET search_path = public`,
    );
    await expectUnavailable();
  });

  it('fails when row level security is disabled or unforced on a new table', async () => {
    await admin.query('ALTER TABLE openarc_tenant.listing_version_states DISABLE ROW LEVEL SECURITY');
    await expectUnavailable();
  });

  it('fails on a migration checksum drift of 0006_market', async () => {
    await admin.query(
      "UPDATE openarc_meta.schema_migrations SET checksum = 'drift' WHERE id = '0006_market'",
    );
    await expectUnavailable();
  });

  it('passes when the schema is pristine', async () => {
    await new MarketStore(tenant).readiness();
  });
});
