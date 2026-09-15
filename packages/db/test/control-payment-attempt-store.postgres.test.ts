import { createHash } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import {
  CommerceSessionStore,
  ControlActionStore,
  ControlActionStoreError,
  ControlGrantStore,
  ControlGrantStoreError,
  ControlPaymentAttemptStore,
  ControlPaymentAttemptStoreError,
  CredentialStore,
  MarketLifecycleStore,
  MarketStore,
  createDatabasePool,
  digestCommerceGrantToken,
  digestPaymentAttemptBinding,
  migrate,
  reviewedEndpointDigest,
  type PaymentAttemptBindingInput,
} from '../src/index.js';
import type { TenantClient, TenantPool } from '../src/tenant-store.js';
import {
  adminPool,
  ensureRoles,
  migratorUrl,
  resetSchema,
  tenantUrl,
  workerUrl,
} from './postgres-fixture.js';

/**
 * schema15 PG proofs: verified requirement provenance and durable payment
 * attempts. The production success paths here run through the restricted
 * tenant runtime and the literal 'production' wrappers. The verified
 * requirement registration core and the post-dispatch observation recorder are
 * migrator-private (their runtime authority is unsettled) and are called as
 * the migrator. Nothing here signs, sends, settles or moves funds.
 */

const ORIGIN = 'https://api.example.com';
const PATH = '/v1/run';
const PAYER = '0x1111111111111111111111111111111111111111';
/** Seller terms are stored lowercase; the lane binding carries a mixed-case form. */
const PAY_TO = '0xabcdefabcdefabcdefabcdefabcdefabcdef2222';
const PAY_TO_MIXED = '0xAbCdEfAbCdEfAbCdEfAbCdEfAbCdEfAbCdEf2222';
const PAY_TO_V2 = '0xfedcbafedcbafedcbafedcbafedcbafedcba3333';
const GATEWAY_WALLET = '0x0077777d7EBA4688BDeF3E311b846F25870A19B9';
const USDC = '0x3600000000000000000000000000000000000000';
const SIGNATURE_CANARY = `0x${'5a'.repeat(65)}`;
const PRIVATE_KEY_CANARY = 'e7'.repeat(32);

function sha256(seed: string): string {
  return createHash('sha256').update(`openarc-attempt-test:${seed}`, 'utf8').digest('hex');
}

function uuid(seed: number): string {
  return `40000000-0000-4000-8000-${String(seed).padStart(12, '0')}`;
}

function accountId(seed: number): string { return `openarc:account:${uuid(seed)}`; }
function orgId(seed: number): string { return `openarc:org:${uuid(seed)}`; }
function agentId(seed: number): string { return `openarc:agent:${uuid(seed)}`; }
function providerId(seed: number): string { return `openarc:provider:${uuid(seed)}`; }
function policyId(seed: number): string { return `openarc:policy:${uuid(seed)}`; }
function actionId(seed: number): string { return `openarc:action:${uuid(seed)}`; }
function requirementId(seed: number): string { return `openarc:requirement:${uuid(seed)}`; }
function mutationId(seed: number): string { return uuid(700000 + seed); }
function lookupId(seed: number): string { return uuid(900000 + seed); }
function machineSessionId(seed: number): string { return uuid(600000 + seed); }
function providerSessionId(seed: number): string { return uuid(660000 + seed); }
function attemptId(seed: number): string { return uuid(770000 + seed); }

function key(seed: number): string {
  return createHash('sha256').update(`attempt-key:${seed}`).digest().toString('base64url');
}

function meta(seed: number): { idempotencyKey: string; mutationId: string } {
  return { idempotencyKey: key(seed), mutationId: mutationId(seed) };
}

function userHandle(seed: number): string {
  return `${sha256(`handle:${seed}`).slice(0, 42)}A`;
}

function rawGrantToken(seed: number): string {
  const material = createHash('sha256').update(`attempt-grant-secret:${seed}`).digest();
  return `oag_v1_${material.toString('base64url')}`;
}

const SALT = Buffer.alloc(16, 7).toString('base64url');
const DIGEST = Buffer.alloc(32, 8).toString('base64url');

function hashInput() {
  return {
    algorithm: 'scrypt' as const, hashVersion: 1 as const, pepperVersion: 1,
    N: 32768 as const, r: 8 as const, p: 1 as const, salt: SALT, digest: DIGEST,
  };
}

function content(atomicAmount = '1000000'): Record<string, unknown> {
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
        schemaVersion: 'openarc.usdc-amount.v1', networkId: 'eip155:5042002', asset: 'USDC',
        atomicAmount, representation: 'erc20', decimals: 6,
      },
      pricingModel: 'fixed',
    },
    evidenceContract: {
      schemaVersion: 'openarc.receipt-contract.v1', receiptType: 'receipt.v1',
      receiptSchemaDigest: `sha256:${'3'.repeat(64)}`, deliveryFields: ['payload', 'status'],
    },
    endpointContract: { origin: ORIGIN, path: PATH },
    termsRevision: 'terms-v1',
    privacySummary: 'We store nothing.',
    paymentLane: 'unavailable',
    availability: { status: 'available', rateLimitPerMinute: '60' },
  };
}

/** Independent reimplementation of the frozen schema15 verified digest string. */
function verifiedDigest(
  seller: string, provider: string, listing: string, version: string, payTo: string, amount: string, fee: string,
  overrides: { verifyingContract?: string; network?: string; asset?: string } = {},
): string {
  const text = [
    'openarc.control.requirement.verified_listing.v1', seller, provider, listing, version,
    overrides.network ?? 'eip155:5042002', 'exact', '2', 'GatewayWalletBatched', '1',
    overrides.verifyingContract ?? '0x0077777d7eba4688bdef3e311b846f25870a19b9',
    'USDC', overrides.asset ?? '0x3600000000000000000000000000000000000000', '6', 'erc20',
    payTo.toLowerCase(), amount, fee,
  ].join('\n');
  return `sha256:${createHash('sha256').update(text, 'utf8').digest('hex')}`;
}

/** Independent reimplementation of packages/x402 canonicalJson/digestCanonical. */
function laneCanonicalJson(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((k) => `${JSON.stringify(k)}:${laneCanonicalJson(record[k])}`).join(',')}}`;
}

function laneDigest(value: unknown): string {
  return `sha256:${createHash('sha256').update(laneCanonicalJson(value), 'utf8').digest('hex')}`;
}

let admin: Pool;
let migrator: ReturnType<typeof createDatabasePool>;
let tenant: ReturnType<typeof createDatabasePool>;
let store: ControlPaymentAttemptStore;
let actions: ControlActionStore;
let grants: ControlGrantStore;
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
  store = new ControlPaymentAttemptStore(tenant);
  actions = new ControlActionStore(tenant);
  grants = new ControlGrantStore(tenant);
  credentials = new CredentialStore(tenant);
  commerce = new CommerceSessionStore(tenant);
  market = new MarketStore(tenant);
  lifecycle = new MarketLifecycleStore(tenant);
});

interface Owner { readonly account: string; readonly hash: string; readonly org: string }

async function seedAccount(seed: number): Promise<string> {
  const id = accountId(seed);
  await admin.query(
    "INSERT INTO openarc_auth.accounts (account_id, user_handle, status) VALUES ($1, $2, 'active')",
    [id, userHandle(seed)],
  );
  return id;
}

async function seedSession(seed: number, account: string): Promise<string> {
  const hash = sha256(`session:${seed}`);
  await admin.query(
    `INSERT INTO openarc_auth.sessions (token_hash, account_id, method, created_at, expires_at)
     VALUES ($1, $2, 'passkey', now(), now() + interval '24 hours')`,
    [hash, account],
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

/** A second human in an EXISTING organization with the given role. */
async function seedMember(seed: number, org: string, role: string): Promise<Owner> {
  const account = await seedAccount(seed);
  const hash = await seedSession(seed, account);
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

async function seedPolicy(org: string, subject: string, seed: number, provider: string): Promise<string> {
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
       VALUES ($1, $2, '1', $3, 'eip155:5042002', 'USDC', 'erc20', 6, '5000000', '5000000',
               '3600', '0', ARRAY[$4]::text[], ARRAY[]::text[], 'none', NULL, false,
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

async function seedMachine(owner: Owner, seed: number, agent: string): Promise<string> {
  const issued = await credentials.issueAgentCredentialDurably({
    sessionHash: owner.hash,
    organizationId: owner.org,
    profileId: agent,
    lookupId: lookupId(seed),
    hash: hashInput(),
    expiresAt: new Date(Date.now() + 30 * 60_000).toISOString(),
    metadata: meta(500000 + seed),
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
  return agentSessionHash;
}

async function seedProviderSession(seller: Owner, provider: string, seed: number): Promise<string> {
  const issued = await credentials.issueProviderCredentialDurably({
    sessionHash: seller.hash,
    organizationId: seller.org,
    profileId: provider,
    lookupId: lookupId(4000 + seed),
    hash: hashInput(),
    expiresAt: new Date(Date.now() + 30 * 60_000).toISOString(),
    metadata: meta(600000 + seed),
  });
  const tokenHash = sha256(`provider-session:${seed}`);
  await credentials.createProviderSession({
    organizationId: seller.org,
    profileId: provider,
    credentialId: issued.receipt.credentialId,
    expectedVersion: 1,
    sessionId: providerSessionId(seed),
    tokenHash,
    expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
  });
  return tokenHash;
}

async function stateUpdatedAt(org: string, listing: string, version: string): Promise<string> {
  const result = await admin.query<{ updated_at: string }>(
    "SELECT to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS updated_at FROM openarc_tenant.listing_version_states WHERE organization_id = $1 AND listing_id = $2 AND version = $3",
    [org, listing, version],
  );
  return result.rows[0]!.updated_at;
}

async function reviewVersion(owner: Owner, listing: string, version: string, seed: number): Promise<void> {
  const moderatorSeed = seed + 8000;
  const exists = await admin.query('SELECT 1 FROM openarc_auth.accounts WHERE account_id = $1', [accountId(moderatorSeed)]);
  if (exists.rowCount === 0) {
    const moderatorAccount = await seedAccount(moderatorSeed);
    await seedSession(moderatorSeed, moderatorAccount);
    await admin.query(
      "INSERT INTO openarc_tenant.market_moderator_grants (account_id, status) VALUES ($1, 'active')",
      [moderatorAccount],
    );
  }
  await lifecycle.recordOriginReview(
    sha256(`session:${moderatorSeed}`), owner.org, listing, version,
    {
      expectedUpdatedAt: await stateUpdatedAt(owner.org, listing, version),
      decision: 'approved',
      reviewedEndpointDigest: reviewedEndpointDigest({ listingId: listing, version, origin: ORIGIN, path: PATH }),
      reasonCode: 'manual_review',
      reasonDigest: null,
    },
    meta(20000 + seed * 10 + Number(version)),
  );
}

async function publishVersion(owner: Owner, listing: string, version: string, active: string | null, seed: number): Promise<void> {
  await lifecycle.publishListingVersion(
    owner.hash, owner.org, listing, version,
    { expectedUpdatedAt: await stateUpdatedAt(owner.org, listing, version), expectedActiveVersion: active },
    meta(40000 + seed * 10 + Number(version)),
  );
}

async function seedDraftListing(owner: Owner, provider: string, seed: number): Promise<string> {
  const draft = await market.createListingDraft(owner.hash, owner.org, provider, content(), meta(10000 + seed));
  return draft.receipt.resourceId;
}

function recordTerms(owner: Owner, listing: string, version: string, payTo: string, seed: number) {
  return store.recordListingPaymentTerms(
    owner.hash, owner.org, listing, version, { payToAddress: payTo }, meta(70000 + seed * 10 + Number(version)),
  );
}

async function seedPublishedListing(owner: Owner, provider: string, seed: number, payTo: string | null = PAY_TO): Promise<string> {
  const listing = await seedDraftListing(owner, provider, seed);
  if (payTo !== null) await recordTerms(owner, listing, '1', payTo, seed);
  await reviewVersion(owner, listing, '1', seed);
  await publishVersion(owner, listing, '1', null, seed);
  return listing;
}

interface Chain {
  readonly buyer: Owner;
  readonly seller: Owner;
  readonly agent: string;
  readonly provider: string;
  readonly listing: string;
  readonly commerceTokenHash: string;
  readonly agentSessionHash: string;
  readonly seed: number;
}

/** Buyer A buys seller B's real published, origin-approved listing. */
async function seedCrossChain(buyerSeed: number, sellerSeed: number): Promise<Chain> {
  const buyer = await seedOwner(buyerSeed);
  const seller = await seedOwner(sellerSeed);
  const agent = await seedAgent(buyerSeed, buyer.org);
  const provider = await seedProvider(sellerSeed, seller.org);
  const listing = await seedPublishedListing(seller, provider, sellerSeed);
  const policy = await seedPolicy(buyer.org, agent, buyerSeed, provider);
  const agentSessionHash = await seedMachine(buyer, buyerSeed, agent);
  const handoffHash = sha256(`handoff:${buyerSeed}`);
  const commerceTokenHash = sha256(`commerce:${buyerSeed}`);
  await commerce.issueCommerceSession(
    buyer.hash, buyer.org,
    { subjectAgentId: agent, policyId: policy, handoffHash, hashVersion: 1 },
    meta(100000 + buyerSeed),
  );
  await commerce.exchangeCommerceSession(
    agentSessionHash, handoffHash, { tokenHash: commerceTokenHash, hashVersion: 1 }, meta(200000 + buyerSeed),
  );
  return { buyer, seller, agent, provider, listing, commerceTokenHash, agentSessionHash, seed: buyerSeed };
}

async function registerVerified(buyerOrg: string, requirement: string, listing: string) {
  const result = await migrator.query<Record<string, unknown>>(
    `SELECT *, out_created_at::text AS created_text,
            extract(epoch FROM (out_valid_until - out_created_at))::float8 AS window_seconds
       FROM openarc_durable.register_verified_commerce_requirement_core($1, $2, $3)`,
    [buyerOrg, requirement, listing],
  );
  return result.rows[0]!;
}

async function seedFixtureRequirement(chain: Chain, seed: number): Promise<string> {
  const id = requirementId(seed);
  await admin.query(
    `INSERT INTO openarc_durable.commerce_requirement_references (
       organization_id, requirement_id, seller_organization_id, provider_id, listing_id,
       listing_version, network_id, asset, representation, decimals, amount_atomic,
       fee_atomic, requirement_digest, source_kind, created_at, valid_until)
     VALUES ($1, $2, $3, $4, $5, '1', 'eip155:5042002', 'USDC', 'erc20', 6, '1000000', '0',
             'sha256:' || repeat('c', 64), 'internal_fixture', clock_timestamp(),
             clock_timestamp() + interval '30 minutes')`,
    [chain.buyer.org, id, chain.seller.org, chain.provider, chain.listing],
  );
  return id;
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
    expect(error).toBeInstanceOf(ControlPaymentAttemptStoreError);
    expect((error as ControlPaymentAttemptStoreError).code).toBe(code);
    return;
  }
  throw new Error(`expected ControlPaymentAttemptStoreError ${code}`);
}

async function expectRejectedWith<T extends Error & { code: string }>(
  promise: Promise<unknown>, type: new (...args: never[]) => T, code: string,
): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(type);
    expect((error as T).code).toBe(code);
    return;
  }
  throw new Error(`expected ${type.name} ${code}`);
}

interface Counts {
  terms: number;
  attempts: number; requirements: number; actions: number; reservations: number;
  released_reservations: number; events: number; grants: number; claims: number;
  idem: number; audit: number; outbox: number;
}

async function counts(): Promise<Counts> {
  const result = await admin.query<Counts & Record<string, unknown>>(
    `SELECT (SELECT count(*)::int FROM openarc_tenant.listing_version_payment_terms) AS terms,
            (SELECT count(*)::int FROM openarc_durable.payment_attempts) AS attempts,
            (SELECT count(*)::int FROM openarc_durable.commerce_requirement_references) AS requirements,
            (SELECT count(*)::int FROM openarc_durable.commerce_actions) AS actions,
            (SELECT count(*)::int FROM openarc_durable.budget_reservations) AS reservations,
            (SELECT count(*)::int FROM openarc_durable.budget_reservations WHERE status = 'released') AS released_reservations,
            (SELECT count(*)::int FROM openarc_durable.budget_events) AS events,
            (SELECT count(*)::int FROM openarc_durable.authorization_grants) AS grants,
            (SELECT count(*)::int FROM openarc_durable.authorization_grant_claims) AS claims,
            (SELECT count(*)::int FROM openarc_durable.idempotency_records) AS idem,
            (SELECT count(*)::int FROM openarc_durable.audit_events) AS audit,
            (SELECT count(*)::int FROM openarc_durable.outbox_events) AS outbox`,
  );
  return result.rows[0]!;
}

async function attemptRow(attempt: string): Promise<Record<string, unknown> | undefined> {
  const result = await admin.query<Record<string, unknown>>(
    'SELECT * FROM openarc_durable.payment_attempts WHERE attempt_id = $1::uuid', [attempt],
  );
  return result.rows[0];
}

async function reservationOf(action: string): Promise<Record<string, unknown>> {
  const result = await admin.query<Record<string, unknown>>(
    'SELECT * FROM openarc_durable.budget_reservations WHERE action_id = $1', [action],
  );
  return result.rows[0]!;
}

async function actionStatus(action: string): Promise<string> {
  const result = await admin.query<{ status: string }>(
    'SELECT status FROM openarc_durable.commerce_actions WHERE action_id = $1', [action],
  );
  return result.rows[0]!.status;
}

interface Verified {
  readonly chain: Chain;
  readonly requirement: string;
  readonly requirementDigest: string;
  readonly action: string;
  readonly grant: string;
  readonly grantTokenHash: string;
  readonly providerSessionHash: string;
}

/** A verified requirement, a PRODUCTION authorize and a PRODUCTION grant issue. */
async function seedVerifiedGrant(buyerSeed: number, sellerSeed: number): Promise<Verified> {
  const chain = await seedCrossChain(buyerSeed, sellerSeed);
  const requirement = requirementId(buyerSeed);
  const registered = await store.registerVerifiedRequirement(
    chain.commerceTokenHash, { requirementId: requirement, listingId: chain.listing },
  );
  const action = actionId(buyerSeed);
  const authorized = await actions.authorizeCommerceAction(
    chain.commerceTokenHash, { requirementId: requirement, actionId: action }, meta(300000 + buyerSeed),
  );
  expect(authorized.metadata ?? authorized).toBeTruthy();
  const grantTokenHash = digestCommerceGrantToken(rawGrantToken(buyerSeed));
  const issued = await grants.issueForReservedAction(
    chain.commerceTokenHash, { actionId: action, grantTokenHash }, meta(400000 + buyerSeed),
  );
  const providerSessionHash = await seedProviderSession(chain.seller, chain.provider, sellerSeed);
  return {
    chain,
    requirement,
    requirementDigest: registered.requirementDigest,
    action,
    grant: issued.metadata.grantId,
    grantTokenHash,
    providerSessionHash,
  };
}

function laneBinding(
  seeded: { grant: string; action: string; requirementDigest: string },
  seed: number,
  overrides: Partial<Record<keyof PaymentAttemptBindingInput, string>> = {},
): PaymentAttemptBindingInput {
  const now = Math.floor(Date.now() / 1000);
  return {
    schemaVersion: 'openarc.x402.lane-binding.v1',
    role: 'buyer',
    network: 'eip155:5042002',
    grantId: seeded.grant,
    actionId: seeded.action,
    attemptId: attemptId(seed),
    grantRequirementDigest: seeded.requirementDigest,
    laneRequirementDigest: `sha256:${sha256(`lane-requirement:${seed}`)}`,
    verifyingContract: GATEWAY_WALLET,
    asset: USDC,
    from: PAYER,
    to: PAY_TO_MIXED,
    value: '1000000',
    validAfter: String(now - 600),
    validBefore: String(now + 604800 + 900),
    nonce: `0x${sha256(`nonce:${seed}`)}`,
    ...overrides,
  };
}

function persistInput(binding: PaymentAttemptBindingInput) {
  return { binding, bindingDigest: digestPaymentAttemptBinding(binding) };
}

function rawPersistArgs(token: string, binding: PaymentAttemptBindingInput, digest: string): unknown[] {
  return [
    token, binding.grantId, binding.attemptId, binding.from, binding.to, binding.validAfter,
    binding.validBefore, binding.nonce, binding.laneRequirementDigest, digest,
  ];
}

const RAW_PERSIST = `SELECT * FROM openarc_durable.persist_payment_attempt(
  $1, $2, $3::uuid, $4, $5, $6, $7, $8, $9, $10)`;

function observe(org: string, attempt: string, state: string, transfer: string, status: string, hash: string | null) {
  return migrator.query<Record<string, unknown>>(
    `SELECT * FROM openarc_durable.record_payment_attempt_observation($1, $2::uuid, $3, $4::uuid, $5, $6)`,
    [org, attempt, state, transfer, status, hash],
  );
}

// ---------------------------------------------------------------------------
describe('schema15 manifest, ownership, ACLs and readiness', () => {
  it('records schema15 and keeps the runtime off the attempt table and every private helper', async () => {
    const applied = await admin.query<{ id: string }>('SELECT id FROM openarc_meta.schema_migrations ORDER BY id');
    expect(applied.rows.map((row) => row.id).slice(-3)).toEqual(['0014_grant_mutation_reads', '0015_payment_attempts', '0016_evidence_store']);
    const table = await admin.query<{ enabled: boolean; forced: boolean; owner: string }>(
      `SELECT c.relrowsecurity AS enabled, c.relforcerowsecurity AS forced, r.rolname AS owner
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_roles r ON r.oid = c.relowner
        WHERE n.nspname = 'openarc_durable' AND c.relname = 'payment_attempts'`,
    );
    expect(table.rows[0]).toEqual({ enabled: true, forced: true, owner: 'openarc_migrator' });
    expect((await rawError(tenant.query('SELECT count(*) FROM openarc_durable.payment_attempts'))).code).toBe('42501');
    expect((await rawError(tenant.query('SELECT count(*) FROM openarc_tenant.listing_version_payment_terms'))).code).toBe('42501');
    const terms = await admin.query<{ enabled: boolean; forced: boolean; owner: string }>(
      `SELECT c.relrowsecurity AS enabled, c.relforcerowsecurity AS forced, r.rolname AS owner
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_roles r ON r.oid = c.relowner
        WHERE n.nspname = 'openarc_tenant' AND c.relname = 'listing_version_payment_terms'`,
    );
    expect(terms.rows[0]).toEqual({ enabled: true, forced: true, owner: 'openarc_migrator' });
    for (const call of [
      ['SELECT * FROM openarc_durable.register_verified_commerce_requirement_core($1, $2, $3)', [orgId(1), requirementId(1), `openarc:listing:${uuid(1)}`]],
      ['SELECT * FROM openarc_durable.record_payment_attempt_observation($1, $2::uuid, $3, $4::uuid, $5, $6)', [orgId(1), uuid(1), 'pending', uuid(2), 'received', null]],
      ['SELECT openarc_durable.verified_requirement_digest($1, $2, $3, $4, $5, $6, $7)', ['a', 'b', 'c', 'd', 'e', 'f', 'g']],
      ['SELECT openarc_durable.is_canonical_source_kind($1)', ['verified_listing']],
    ] as const) {
      expect((await rawError(tenant.query(call[0], [...call[1]]))).code).toBe('42501');
    }
    const acl = await admin.query<{ proname: string; app: boolean; worker: boolean; auth: boolean; pub: number; secdef: boolean; config: string[] }>(
      `SELECT p.proname,
              has_function_privilege('openarc_tenant_app', p.oid, 'EXECUTE') AS app,
              has_function_privilege('openarc_worker_app', p.oid, 'EXECUTE') AS worker,
              has_function_privilege('openarc_auth_app', p.oid, 'EXECUTE') AS auth,
              (SELECT count(*)::int FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE') AS pub,
              p.prosecdef AS secdef, coalesce(p.proconfig, ARRAY[]::text[]) AS config
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'openarc_durable'
          AND p.proname IN ('persist_payment_attempt', 'record_payment_attempt_dispatch',
            'read_agent_payment_attempt', 'register_verified_commerce_requirement',
            'commit_listing_payment_terms', 'register_verified_commerce_requirement_core',
            'record_payment_attempt_observation', 'verified_requirement_digest',
            'payment_attempt_binding_digest', 'enforce_verified_requirement_insert',
            'enforce_payment_attempt_mutation', 'enforce_reservation_payment_exposure',
            'enforce_action_payment_exposure', 'enforce_claim_payment_attempt')
        ORDER BY p.proname`,
    );
    expect(acl.rows).toHaveLength(14);
    const runtime = new Set([
      'persist_payment_attempt', 'record_payment_attempt_dispatch', 'read_agent_payment_attempt',
      'register_verified_commerce_requirement', 'commit_listing_payment_terms',
    ]);
    for (const row of acl.rows) {
      expect([row.proname, row.app]).toEqual([row.proname, runtime.has(row.proname)]);
      expect([row.proname, row.worker, row.auth, row.pub]).toEqual([row.proname, false, false, 0]);
      expect([row.proname, row.config]).toEqual([row.proname, ['search_path=pg_catalog']]);
    }
    const worker = createDatabasePool(workerUrl());
    try {
      expect((await rawError(worker.query('SELECT * FROM openarc_durable.read_agent_payment_attempt($1, $2::uuid)', ['a'.repeat(64), uuid(1)]))).code).toBe('42501');
    } finally {
      await worker.end();
    }
    expect((await counts()).attempts).toBe(0);
  });

  it('readiness passes, then fails for EVERY new helper that is missing, mis-signed, widened or bypassed', async () => {
    await store.initialize();
    await store.readiness();
    const expectUnready = async (label: string): Promise<void> => {
      try {
        await new ControlPaymentAttemptStore(tenant).readiness();
      } catch (error) {
        expect([label, (error as ControlPaymentAttemptStoreError).code]).toEqual([label, 'CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE']);
        return;
      }
      throw new Error(`readiness unexpectedly passed: ${label}`);
    };
    const helpers: { sig: string; name: string; definer: boolean; runtime: boolean }[] = [
      { name: 'persist_payment_attempt', sig: 'openarc_durable.persist_payment_attempt(text, text, uuid, text, text, text, text, text, text, text)', definer: true, runtime: true },
      { name: 'record_payment_attempt_dispatch', sig: 'openarc_durable.record_payment_attempt_dispatch(text, uuid, text)', definer: true, runtime: true },
      { name: 'read_agent_payment_attempt', sig: 'openarc_durable.read_agent_payment_attempt(text, uuid)', definer: true, runtime: true },
      { name: 'register_verified_commerce_requirement', sig: 'openarc_durable.register_verified_commerce_requirement(text, text, text)', definer: true, runtime: true },
      { name: 'commit_listing_payment_terms', sig: 'openarc_durable.commit_listing_payment_terms(text, text, text, text, text, uuid, text, text, text)', definer: true, runtime: true },
      { name: 'revoke_authorization_grant', sig: 'openarc_durable.revoke_authorization_grant(text, text, text, uuid, text, text, text)', definer: true, runtime: true },
      { name: 'register_verified_commerce_requirement_core', sig: 'openarc_durable.register_verified_commerce_requirement_core(text, text, text)', definer: true, runtime: false },
      { name: 'record_payment_attempt_observation', sig: 'openarc_durable.record_payment_attempt_observation(text, uuid, text, uuid, text, text)', definer: true, runtime: false },
      { name: 'verified_requirement_digest', sig: 'openarc_durable.verified_requirement_digest(text, text, text, text, text, text, text)', definer: false, runtime: false },
      { name: 'payment_attempt_binding_digest', sig: 'openarc_durable.payment_attempt_binding_digest(text, text, text, text, text, text, text, text, text, text, text, text, text, text, text, text)', definer: false, runtime: false },
    ];
    for (const helper of helpers) {
      // Missing.
      await migrator.query(`ALTER FUNCTION ${helper.sig} RENAME TO ${helper.name}_gone`);
      await expectUnready(`${helper.name}:missing`);
      await migrator.query(`ALTER FUNCTION ${helper.sig.replace(`.${helper.name}(`, `.${helper.name}_gone(`)} RENAME TO ${helper.name}`);
      // Mis-signed: definer flag flipped.
      await migrator.query(`ALTER FUNCTION ${helper.sig} ${helper.definer ? 'SECURITY INVOKER' : 'SECURITY DEFINER'}`);
      await expectUnready(`${helper.name}:security`);
      await migrator.query(`ALTER FUNCTION ${helper.sig} ${helper.definer ? 'SECURITY DEFINER' : 'SECURITY INVOKER'}`);
      // Mis-signed: search_path no longer pinned.
      await migrator.query(`ALTER FUNCTION ${helper.sig} RESET search_path`);
      await expectUnready(`${helper.name}:search_path`);
      await migrator.query(`ALTER FUNCTION ${helper.sig} SET search_path = pg_catalog`);
      // Widened to PUBLIC.
      await migrator.query(`GRANT EXECUTE ON FUNCTION ${helper.sig} TO PUBLIC`);
      await expectUnready(`${helper.name}:public`);
      await migrator.query(`REVOKE EXECUTE ON FUNCTION ${helper.sig} FROM PUBLIC`);
      // Runtime reachability flipped.
      await migrator.query(helper.runtime
        ? `REVOKE EXECUTE ON FUNCTION ${helper.sig} FROM openarc_tenant_app`
        : `GRANT EXECUTE ON FUNCTION ${helper.sig} TO openarc_tenant_app`);
      await expectUnready(`${helper.name}:runtime`);
      await migrator.query(helper.runtime
        ? `GRANT EXECUTE ON FUNCTION ${helper.sig} TO openarc_tenant_app`
        : `REVOKE EXECUTE ON FUNCTION ${helper.sig} FROM openarc_tenant_app`);
      await store.readiness();
    }
    // A second overload (e.g. one accepting a caller price) is not ready.
    await migrator.query(
      `CREATE FUNCTION openarc_durable.register_verified_commerce_requirement_core(a text, b text, c text, price text)
       RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS $$ SELECT $$`,
    );
    await migrator.query('REVOKE ALL ON FUNCTION openarc_durable.register_verified_commerce_requirement_core(text, text, text, text) FROM PUBLIC');
    await expectUnready('register:overload');
    await migrator.query('DROP FUNCTION openarc_durable.register_verified_commerce_requirement_core(text, text, text, text)');
    // A disabled guard trigger is not ready.
    for (const [table, trigger] of [
      ['openarc_durable.budget_reservations', 'budget_reservations_payment_exposure'],
      ['openarc_durable.commerce_actions', 'commerce_actions_payment_exposure'],
      ['openarc_durable.authorization_grant_claims', 'authorization_grant_claims_payment_attempt'],
      ['openarc_durable.commerce_requirement_references', 'commerce_requirement_references_verified'],
      ['openarc_durable.payment_attempts', 'payment_attempts_mutation'],
      ['openarc_tenant.listing_version_payment_terms', 'listing_version_payment_terms_append_only'],
    ] as const) {
      await migrator.query(`ALTER TABLE ${table} DISABLE TRIGGER ${trigger}`);
      await expectUnready(`${trigger}:disabled`);
      await migrator.query(`ALTER TABLE ${table} ENABLE TRIGGER ${trigger}`);
    }
    // Both new tables: unforced RLS or any runtime table privilege is not ready.
    for (const table of ['openarc_durable.payment_attempts', 'openarc_tenant.listing_version_payment_terms']) {
      await migrator.query(`ALTER TABLE ${table} NO FORCE ROW LEVEL SECURITY`);
      await expectUnready(`${table}:unforced`);
      await migrator.query(`ALTER TABLE ${table} FORCE ROW LEVEL SECURITY`);
      await migrator.query(`GRANT SELECT ON TABLE ${table} TO openarc_tenant_app`);
      await expectUnready(`${table}:runtime_select`);
      await migrator.query(`REVOKE SELECT ON TABLE ${table} FROM openarc_tenant_app`);
    }
    // A source-kind set that no longer admits the verified kind is not ready.
    await migrator.query(
      `CREATE OR REPLACE FUNCTION openarc_durable.is_canonical_source_kind(value text) RETURNS boolean
       LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$ SELECT value IS NOT NULL AND value = 'internal_fixture'; $$`,
    );
    await expectUnready('source_kind:reverted');
    await migrator.query(
      `CREATE OR REPLACE FUNCTION openarc_durable.is_canonical_source_kind(value text) RETURNS boolean
       LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$ SELECT value IS NOT NULL AND value IN ('internal_fixture', 'verified_listing'); $$`,
    );
    await store.readiness();
  }, 240000);
});

// ---------------------------------------------------------------------------
describe('verified requirement provenance', () => {
  it('derives every term server-side from the published origin-approved listing version and the pinned manifest', async () => {
    const chain = await seedCrossChain(10, 1010);
    const registered = await registerVerified(chain.buyer.org, requirementId(10), chain.listing);
    expect(registered).toMatchObject({
      out_organization_id: chain.buyer.org,
      out_requirement_id: requirementId(10),
      out_seller_organization_id: chain.seller.org,
      out_provider_id: chain.provider,
      out_listing_id: chain.listing,
      out_listing_version: '1',
      out_network_id: 'eip155:5042002',
      out_asset: 'USDC',
      out_representation: 'erc20',
      out_decimals: 6,
      out_amount_atomic: '1000000',
      out_fee_atomic: '0',
      out_pay_to_address: PAY_TO,
      out_source_kind: 'verified_listing',
      window_seconds: 900,
    });
    expect(registered['out_requirement_digest']).toBe(
      verifiedDigest(chain.seller.org, chain.provider, chain.listing, '1', PAY_TO, '1000000', '0'),
    );
    const stored = await admin.query<Record<string, unknown>>(
      'SELECT * FROM openarc_durable.commerce_requirement_references WHERE requirement_id = $1', [requirementId(10)],
    );
    expect(stored.rows[0]).toMatchObject({ amount_atomic: '1000000', fee_atomic: '0', source_kind: 'verified_listing' });
    // A different recorded price yields exactly that exact numeric amount.
    const second = await seedOwner(1011);
    const secondProvider = await seedProvider(1011, second.org);
    const pricey = await market.createListingDraft(second.hash, second.org, secondProvider, content('123456789012345678901234567890'), meta(10000 + 1011));
    await recordTerms(second, pricey.receipt.resourceId, '1', PAY_TO, 1011);
    await reviewVersion(second, pricey.receipt.resourceId, '1', 1011);
    await publishVersion(second, pricey.receipt.resourceId, '1', null, 1011);
    const big = await registerVerified(chain.buyer.org, requirementId(11), pricey.receipt.resourceId);
    expect(big).toMatchObject({ out_amount_atomic: '123456789012345678901234567890', out_fee_atomic: '0' });
    // The ONLY registration signature takes a buyer org, a requirement id and a
    // listing id; there is no parameter for origin, price, network, asset,
    // verifying contract, pay-to or calldata, and no requirement column for them.
    const signature = await admin.query<{ args: string }>(
      `SELECT pg_get_function_identity_arguments(p.oid) AS args FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'openarc_durable' AND p.proname = 'register_verified_commerce_requirement_core'`,
    );
    expect(signature.rows).toEqual([{ args: 'buyer_organization_id text, requirement_id_input text, listing_id_input text' }]);
    const columns = await admin.query<{ column_name: string }>(
      `SELECT column_name FROM information_schema.columns
        WHERE table_schema = 'openarc_durable' AND table_name = 'commerce_requirement_references' ORDER BY column_name`,
    );
    // pay_to_address exists but is ONLY ever the seller's recorded terms (proven below).
    for (const forbidden of ['origin', 'endpoint', 'pay_to', 'calldata', 'verifying_contract', 'asset_address', 'price']) {
      expect(columns.rows.map((row) => row.column_name)).not.toContain(forbidden);
    }
    const overload = await rawError(migrator.query(
      'SELECT * FROM openarc_durable.register_verified_commerce_requirement_core($1, $2, $3, $4)',
      [chain.buyer.org, requirementId(12), chain.listing, '1'],
    ));
    expect(overload.code).toBe('42883');
  }, 120000);

  it('refuses supplied or overridden price, fee, network, asset, verifying contract, window and version even as migrator DML', async () => {
    const chain = await seedCrossChain(20, 1020);
    const insert = (seed: number, row: Record<string, string | null>, createdOffset = '0 seconds', window = '900 seconds') =>
      migrator.query(
        `WITH n AS (SELECT clock_timestamp() + $15::interval AS c)
         INSERT INTO openarc_durable.commerce_requirement_references (
           organization_id, requirement_id, seller_organization_id, provider_id, listing_id,
           listing_version, network_id, asset, representation, decimals, amount_atomic,
           fee_atomic, requirement_digest, source_kind, created_at, valid_until, pay_to_address)
         SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10::smallint, $11, $12, $13, $14, n.c, n.c + $16::interval, $17::text FROM n`,
        [
          chain.buyer.org, requirementId(seed), chain.seller.org, chain.provider, chain.listing,
          row['version'] ?? '1', row['network'] ?? 'eip155:5042002', row['asset'] ?? 'USDC',
          row['representation'] ?? 'erc20', row['decimals'] ?? '6', row['amount'] ?? '1000000',
          row['fee'] ?? '0',
          row['digest'] ?? verifiedDigest(chain.seller.org, chain.provider, chain.listing, row['version'] ?? '1', row['payTo'] ?? PAY_TO, row['amount'] ?? '1000000', row['fee'] ?? '0'),
          'verified_listing', createdOffset, window, row['payTo'] === undefined ? PAY_TO : row['payTo'],
        ],
      );
    const before = await counts();
    const d = (amount: string, fee: string, o: Parameters<typeof verifiedDigest>[7] = {}) =>
      verifiedDigest(chain.seller.org, chain.provider, chain.listing, '1', PAY_TO, amount, fee, o);
    // Lazy thunks: each insert starts only when awaited, so no refusal is ever unhandled.
    const cases: [string, () => Promise<unknown>][] = [
      ['price lowered', () => insert(21, { amount: '1', digest: d('1', '0') })],
      ['price raised', () => insert(22, { amount: '2000000', digest: d('2000000', '0') })],
      ['fee added', () => insert(23, { fee: '1', digest: d('1000000', '1') })],
      ['stale digest', () => insert(24, { digest: d('999999', '0') })],
      ['verifying contract', () => insert(25, { digest: d('1000000', '0', { verifyingContract: '0x0022222abe238cc2c7bb1f21003f0a260052475b' }) })],
      ['asset address', () => insert(26, { digest: d('1000000', '0', { asset: '0x0000000000000000000000000000000000000001' }) })],
      ['network in digest', () => insert(27, { digest: d('1000000', '0', { network: 'eip155:1' }) })],
      ['network column', () => insert(28, { network: 'eip155:1' })],
      ['asset column', () => insert(29, { asset: 'EURC' })],
      ['decimals', () => insert(30, { decimals: '18' })],
      ['unpublished version', () => insert(31, { version: '2' })],
      ['stretched window', () => insert(32, {}, '0 seconds', '1 hour')],
      ['backdated creation', () => insert(33, {}, '-10 minutes')],
      ['future creation', () => insert(34, {}, '10 minutes')],
      ['pay-to override', () => insert(37, { payTo: PAY_TO_V2, digest: verifiedDigest(chain.seller.org, chain.provider, chain.listing, '1', PAY_TO_V2, '1000000', '0') })],
      ['pay-to missing', () => insert(38, { payTo: null })],
    ];
    for (const [label, run] of cases) {
      const error = await rawError(run());
      expect([label, ['42501', '23514', '23503'].includes(error.code ?? '')]).toEqual([label, true]);
    }
    expect(await counts()).toEqual(before);
    // The exact server derivation IS admissible, whoever writes it: the trigger
    // proves terms, it does not trust the writer.
    await insert(35, {});
    expect((await counts()).requirements).toBe(before.requirements + 1);
    // Invalid identifiers never reach derivation.
    for (const args of [['nope', requirementId(36), chain.listing], [chain.buyer.org, 'nope', chain.listing], [chain.buyer.org, requirementId(36), 'nope']]) {
      expect((await rawError(migrator.query('SELECT * FROM openarc_durable.register_verified_commerce_requirement_core($1, $2, $3)', args))).code).toBe('22023');
    }
  }, 120000);

  it('refuses a paused, retired, unreviewed or superseded listing version, and production authorize refuses a superseded one with zero mutations', async () => {
    const chain = await seedCrossChain(40, 1040);
    const register = (seed: number, listing: string) =>
      rawError(registerVerified(chain.buyer.org, requirementId(seed), listing));
    // Unreviewed draft.
    const draft = await seedDraftListing(chain.seller, chain.provider, 1041);
    expect((await register(41, draft)).code).toBe('42501');
    // Reviewed but never published.
    await reviewVersion(chain.seller, draft, '1', 1041);
    expect((await register(42, draft)).code).toBe('42501');
    // Paused.
    const paused = await seedPublishedListing(chain.seller, chain.provider, 1043);
    await lifecycle.pauseListingVersion(
      chain.seller.hash, chain.seller.org, paused, '1',
      { expectedUpdatedAt: await stateUpdatedAt(chain.seller.org, paused, '1'), expectedActiveVersion: '1' },
      meta(60000 + 1043),
    );
    expect((await register(43, paused)).code).toBe('42501');
    // Retired.
    const retired = await seedPublishedListing(chain.seller, chain.provider, 1044);
    await lifecycle.retireListingVersion(
      chain.seller.hash, chain.seller.org, retired, '1',
      { expectedUpdatedAt: await stateUpdatedAt(chain.seller.org, retired, '1'), expectedActiveVersion: '1' },
      meta(62000 + 1044),
    );
    expect((await register(44, retired)).code).toBe('42501');
    expect((await counts()).requirements).toBe(0);

    // Superseded: register against v1, then publish v2 (which pauses v1).
    const v1 = await registerVerified(chain.buyer.org, requirementId(45), chain.listing);
    expect(v1['out_listing_version']).toBe('1');
    await market.createListingVersion(
      chain.seller.hash, chain.seller.org, chain.listing,
      { expectedLatestVersion: '1', content: content('2000000') }, meta(64000 + 1045),
    );
    // A different pay-to needs a new version: v2 carries its own terms.
    await recordTerms(chain.seller, chain.listing, '2', PAY_TO_V2, 1040);
    await reviewVersion(chain.seller, chain.listing, '2', 1040);
    await publishVersion(chain.seller, chain.listing, '2', '1', 1040);
    const v2 = await registerVerified(chain.buyer.org, requirementId(46), chain.listing);
    expect(v2).toMatchObject({ out_listing_version: '2', out_amount_atomic: '2000000', out_pay_to_address: PAY_TO_V2 });
    expect(v1['out_pay_to_address']).toBe(PAY_TO);
    const termsRows = await admin.query<{ version: string; pay_to_address: string }>(
      'SELECT version, pay_to_address FROM openarc_tenant.listing_version_payment_terms WHERE listing_id = $1 ORDER BY version',
      [chain.listing],
    );
    expect(termsRows.rows).toEqual([{ version: '1', pay_to_address: PAY_TO }, { version: '2', pay_to_address: PAY_TO_V2 }]);
    const directV1 = await rawError(migrator.query(
      `INSERT INTO openarc_durable.commerce_requirement_references (
         organization_id, requirement_id, seller_organization_id, provider_id, listing_id,
         listing_version, network_id, asset, representation, decimals, amount_atomic,
         fee_atomic, requirement_digest, source_kind, created_at, valid_until, pay_to_address)
       SELECT $1, $2, $3, $4, $5, '1', 'eip155:5042002', 'USDC', 'erc20', 6, '1000000', '0', $6,
              'verified_listing', n.c, n.c + interval '900 seconds', $7 FROM (SELECT clock_timestamp() AS c) n`,
      [chain.buyer.org, requirementId(47), chain.seller.org, chain.provider, chain.listing,
        verifiedDigest(chain.seller.org, chain.provider, chain.listing, '1', PAY_TO, '1000000', '0'), PAY_TO],
    ));
    expect(directV1.code).toBe('42501');
    const before = await counts();
    await expectRejectedWith(
      actions.authorizeCommerceAction(chain.commerceTokenHash, { requirementId: requirementId(45), actionId: actionId(45) }, meta(300045)),
      ControlActionStoreError, 'CONTROL_ACTION_STORE_FORBIDDEN',
    );
    expect(await counts()).toEqual(before);
  }, 180000);
});

// ---------------------------------------------------------------------------
describe('production path against verified provenance', () => {
  it('production authorize, issue, persist, dispatch and claim succeed for a verified requirement; internal_fixture is still refused with zero mutations', async () => {
    // internal_fixture is refused by the production wrappers exactly as before.
    const fixture = await seedCrossChain(50, 1050);
    const fixtureRequirement = await seedFixtureRequirement(fixture, 50);
    const beforeFixture = await counts();
    await expectRejectedWith(
      actions.authorizeCommerceAction(fixture.commerceTokenHash, { requirementId: fixtureRequirement, actionId: actionId(50) }, meta(300050)),
      ControlActionStoreError, 'CONTROL_ACTION_STORE_REQUIREMENT_UNAVAILABLE',
    );
    expect(await counts()).toEqual(beforeFixture);

    // A fixture-provenance grant (migrator cores) can never gain a durable attempt.
    const fixtureKey = createHash('sha256').update(key(310050), 'utf8').digest('hex');
    await migrator.query(
      `SELECT * FROM openarc_durable.authorize_commerce_action_core('internal_fixture', $1, $2, $3, $4::uuid, $5, $6, $7)`,
      [fixture.commerceTokenHash, fixtureRequirement, actionId(51), mutationId(310050), fixtureKey, 'a'.repeat(64),
        createHash('sha256').update(`openarc.control.commerce_action.authorize.session.v1:${fixture.commerceTokenHash}`, 'utf8').digest('hex')],
    );
    const fixtureGrant = await migrator.query<{ out_grant_id: string }>(
      `SELECT * FROM openarc_durable.issue_authorization_grant_core('internal_fixture', $1, $2, $3, 1, $4::uuid, $5, $6, $7)`,
      [fixture.commerceTokenHash, actionId(51), digestCommerceGrantToken(rawGrantToken(51)), mutationId(320051), 'b'.repeat(64), 'c'.repeat(64), 'd'.repeat(64)],
    );
    const fixtureBinding = laneBinding(
      { grant: fixtureGrant.rows[0]!.out_grant_id, action: actionId(51), requirementDigest: `sha256:${'c'.repeat(64)}` }, 51,
    );
    const beforeFixtureAttempt = await counts();
    await expectStoreCode(
      store.persistBuyerAttempt(fixture.commerceTokenHash, persistInput(fixtureBinding)),
      'CONTROL_PAYMENT_ATTEMPT_STORE_REQUIREMENT_UNAVAILABLE',
    );
    expect(await counts()).toEqual(beforeFixtureAttempt);

    // The verified requirement runs the WHOLE production path.
    const seeded = await seedVerifiedGrant(52, 1052);
    const action = await admin.query<Record<string, unknown>>(
      'SELECT status, source_kind, amount_atomic, fee_atomic, debit_atomic FROM openarc_durable.commerce_actions WHERE action_id = $1',
      [seeded.action],
    );
    expect(action.rows[0]).toEqual({
      status: 'grant_issued', source_kind: 'verified_listing', amount_atomic: '1000000', fee_atomic: '0', debit_atomic: '1000000',
    });
    const binding = laneBinding(seeded, 52);
    const persisted = await store.persistBuyerAttempt(seeded.chain.commerceTokenHash, persistInput(binding));
    expect(persisted).toMatchObject({ replayed: false, attempt: { state: 'persisted', bindingDigest: digestPaymentAttemptBinding(binding) } });
    const dispatched = await store.recordDispatch(seeded.chain.commerceTokenHash, { attemptId: binding.attemptId, bindingDigest: persisted.attempt.bindingDigest });
    expect(dispatched.state).toBe('unknown');
    const view = await grants.introspectGrant(seeded.providerSessionHash, seeded.grantTokenHash);
    expect(view).toMatchObject({ status: 'issued', amountAtomic: '1000000', requirementDigest: seeded.requirementDigest });
    const claimed = await grants.claimGrant(
      seeded.providerSessionHash,
      { grantTokenHash: seeded.grantTokenHash, expectedActionId: seeded.action, attemptId: binding.attemptId },
      meta(520052),
    );
    expect(claimed).toMatchObject({ replayed: false, attemptId: binding.attemptId, view: { status: 'claimed' } });
    expect(await reservationOf(seeded.action)).toMatchObject({ status: 'claimed', source_kind: 'verified_listing' });
  }, 180000);

  it('a verified grant cannot be claimed or advance past held before its attempt is durably dispatched, nor by another attempt id', async () => {
    const seeded = await seedVerifiedGrant(60, 1060);
    const binding = laneBinding(seeded, 60);
    const claim = (attempt: string, seed: number) => grants.claimGrant(
      seeded.providerSessionHash,
      { grantTokenHash: seeded.grantTokenHash, expectedActionId: seeded.action, attemptId: attempt },
      meta(seed),
    );
    // Before any attempt.
    await expectRejectedWith(claim(binding.attemptId, 520060), ControlGrantStoreError, 'CONTROL_GRANT_STORE_GRANT_CONFLICT');
    expect(await reservationOf(seeded.action)).toMatchObject({ status: 'held' });
    // Persisted but not dispatched.
    await store.persistBuyerAttempt(seeded.chain.commerceTokenHash, persistInput(binding));
    await expectRejectedWith(claim(binding.attemptId, 520061), ControlGrantStoreError, 'CONTROL_GRANT_STORE_GRANT_CONFLICT');
    // Direct DML cannot advance exposure past held without a dispatched attempt.
    for (const status of ['claimed', 'unknown']) {
      expect((await rawError(migrator.query(
        `UPDATE openarc_durable.budget_reservations SET status = $2, claimed_at = clock_timestamp() WHERE action_id = $1`,
        [seeded.action, status],
      ))).code).toBe('P0D14');
    }
    expect((await rawError(migrator.query(
      `UPDATE openarc_durable.budget_reservations SET status = 'committed', resolved_at = clock_timestamp() WHERE action_id = $1`,
      [seeded.action],
    ))).code).toBe('P0D14');
    await store.recordDispatch(seeded.chain.commerceTokenHash, { attemptId: binding.attemptId, bindingDigest: digestPaymentAttemptBinding(binding) });
    // Another attempt id is refused even after dispatch.
    await expectRejectedWith(claim(attemptId(69), 520062), ControlGrantStoreError, 'CONTROL_GRANT_STORE_GRANT_CONFLICT');
    expect((await counts()).claims).toBe(0);
    await claim(binding.attemptId, 520063);
    expect(await reservationOf(seeded.action)).toMatchObject({ status: 'claimed' });
  }, 180000);
});

// ---------------------------------------------------------------------------
describe('durable attempt persistence', () => {
  it('persists before exposure, echoes the recomputed digest, binds every DB-derived term and never takes a second attempt', async () => {
    const seeded = await seedVerifiedGrant(70, 1070);
    const binding = laneBinding(seeded, 70);
    const input = persistInput(binding);
    // The store, the SQL helper and an independent lane canonical JSON agree.
    expect(input.bindingDigest).toBe(laneDigest(binding));
    const sql = await migrator.query<{ digest: string }>(
      `SELECT openarc_durable.payment_attempt_binding_digest($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) AS digest`,
      [binding.actionId, binding.asset, binding.attemptId, binding.from, binding.grantId, binding.grantRequirementDigest,
        binding.laneRequirementDigest, binding.network, binding.nonce, binding.role, binding.schemaVersion, binding.to,
        binding.validAfter, binding.validBefore, binding.value, binding.verifyingContract],
    );
    expect(sql.rows[0]!.digest).toBe(input.bindingDigest);

    const token = seeded.chain.commerceTokenHash;
    const before = await counts();
    // DB-derived terms cannot be overridden through the runtime SQL surface:
    // a digest computed over a different amount, requirement digest, network,
    // asset or verifying contract does not match the database recomputation.
    for (const override of [
      { value: '2000000' },
      { grantRequirementDigest: `sha256:${'9'.repeat(64)}` },
      { network: 'eip155:1' },
      { asset: '0x0000000000000000000000000000000000000001' },
      { verifyingContract: '0x0022222ABE238Cc2C7Bb1f21003F0a260052475B' },
      { actionId: actionId(79) },
      { role: 'provider' },
    ] as Partial<Record<keyof PaymentAttemptBindingInput, string>>[]) {
      const forged = laneBinding(seeded, 70, override);
      const error = await rawError(tenant.query(RAW_PERSIST, rawPersistArgs(token, forged, laneDigest(forged))));
      expect([Object.keys(override)[0], error.code]).toEqual([Object.keys(override)[0], '22023']);
    }
    // Wrong pay-to: any payee other than the seller's recorded terms is refused,
    // even with a self-consistent binding digest; a case variant is the same payee.
    for (const other of [PAY_TO_V2, '0x2222222222222222222222222222222222222222', `0x${PAY_TO.slice(2, 40)}ff`]) {
      const wrong = laneBinding(seeded, 70, { to: other });
      await expectStoreCode(store.persistBuyerAttempt(token, persistInput(wrong)), 'CONTROL_PAYMENT_ATTEMPT_STORE_INPUT_INVALID');
      expect((await rawError(tenant.query(RAW_PERSIST, rawPersistArgs(token, wrong, laneDigest(wrong))))).code).toBe('22023');
    }
    // Validity outside the lane window is refused.
    const now = Math.floor(Date.now() / 1000);
    for (const override of [
      { validBefore: String(now + 3600) },
      { validBefore: String(now + 604800 + 3600 + 3600) },
      { validAfter: String(now + 3600), validBefore: String(now + 604800 + 3600) },
    ]) {
      await expectStoreCode(store.persistBuyerAttempt(token, persistInput(laneBinding(seeded, 70, override))), 'CONTROL_PAYMENT_ATTEMPT_STORE_INPUT_INVALID');
    }
    expect(await counts()).toEqual(before);

    const persisted = await store.persistBuyerAttempt(token, input);
    expect(persisted.replayed).toBe(false);
    expect(persisted.attempt).toMatchObject({
      grantId: seeded.grant, actionId: seeded.action, requirementId: seeded.requirement,
      requirementDigest: seeded.requirementDigest, valueAtomic: '1000000', networkId: 'eip155:5042002',
      assetAddress: USDC, verifyingContract: GATEWAY_WALLET, payerAddress: PAYER, payToAddress: PAY_TO_MIXED,
      nonce: binding.nonce, bindingDigest: input.bindingDigest, state: 'persisted', dispatchedAt: null,
    });
    // Durable now, while exposure is still held and the grant still issued.
    expect(await attemptRow(binding.attemptId)).toMatchObject({ state: 'persisted', binding_digest: input.bindingDigest });
    expect(await reservationOf(seeded.action)).toMatchObject({ status: 'held', claimed_at: null });
    const afterPersist = await counts();
    expect(afterPersist.attempts).toBe(before.attempts + 1);

    // Exact replay returns the same row; no second attempt, no other write.
    const replay = await store.persistBuyerAttempt(token, input);
    expect(replay).toMatchObject({ replayed: true, attempt: { attemptId: binding.attemptId, state: 'persisted' } });
    expect(await counts()).toEqual(afterPersist);
    // A different attempt id or different binding for the same grant is refused.
    await expectStoreCode(store.persistBuyerAttempt(token, persistInput(laneBinding(seeded, 71))), 'CONTROL_PAYMENT_ATTEMPT_STORE_ATTEMPT_CONFLICT');
    await expectStoreCode(
      store.persistBuyerAttempt(token, persistInput(laneBinding(seeded, 70, { nonce: `0x${sha256('other-nonce')}` }))),
      'CONTROL_PAYMENT_ATTEMPT_STORE_ATTEMPT_CONFLICT',
    );
    // The same payer nonce can never back a second grant.
    const second = await seedVerifiedGrant(72, 1072);
    await expectStoreCode(
      store.persistBuyerAttempt(second.chain.commerceTokenHash, persistInput(laneBinding(second, 72, { nonce: binding.nonce }))),
      'CONTROL_PAYMENT_ATTEMPT_STORE_CONFLICT',
    );
    expect((await counts()).attempts).toBe(afterPersist.attempts);
  }, 180000);

  it('rolls back everything when a failure is injected after the attempt write', async () => {
    const seeded = await seedVerifiedGrant(80, 1080);
    const binding = laneBinding(seeded, 80);
    const input = persistInput(binding);
    const token = seeded.chain.commerceTokenHash;
    const before = await counts();

    // (a) Same transaction: the row is durable-in-transaction, then a failure.
    const client = await tenant.connect();
    try {
      await client.query('BEGIN');
      const written = await client.query(RAW_PERSIST, rawPersistArgs(token, binding, input.bindingDigest));
      expect(written.rows[0]).toMatchObject({ out_state: 'persisted', out_replayed: false });
      const visible = await client.query('SELECT * FROM openarc_durable.read_agent_payment_attempt($1, $2::uuid)', [token, binding.attemptId]);
      expect(visible.rows).toHaveLength(1);
      expect((await rawError(client.query('SELECT 1/0'))).code).toBe('22012');
      await client.query('ROLLBACK');
    } finally {
      client.release();
    }
    expect(await counts()).toEqual(before);
    expect(await store.readAgentAttempt(token, binding.attemptId)).toBeNull();

    // (b) Through the store: the COMMIT is lost after the write.
    const lossy: TenantPool = {
      connect: async (): Promise<TenantClient> => {
        const inner = await tenant.connect();
        return {
          query: ((text: string, values?: unknown[]) =>
            text === 'COMMIT' ? Promise.reject(new Error('injected')) : inner.query(text, values)) as TenantClient['query'],
          release: (destroy?: boolean) => inner.release(destroy),
        };
      },
    };
    await expectStoreCode(new ControlPaymentAttemptStore(lossy).persistBuyerAttempt(token, input), 'CONTROL_PAYMENT_ATTEMPT_STORE_OUTCOME_UNKNOWN');
    // The destroyed backend rolls back; wait until no session of the tenant role is still in a transaction.
    for (let i = 0; i < 100; i += 1) {
      const open = await admin.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM pg_stat_activity WHERE usename = 'openarc_tenant_app' AND state LIKE 'idle in transaction%'`,
      );
      if (open.rows[0]!.n === 0) break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    expect(await counts()).toEqual(before);
    // Nothing committed: a fresh persist is a first write, not a replay.
    const fresh = await store.persistBuyerAttempt(token, input);
    expect(fresh.replayed).toBe(false);
    expect((await counts()).attempts).toBe(before.attempts + 1);
  }, 180000);

  it('a cross-organization or other-agent caller cannot persist against, dispatch or read another buyer\'s attempt; missing and foreign are indistinguishable', async () => {
    const victim = await seedVerifiedGrant(90, 1090);
    const binding = laneBinding(victim, 90);
    await store.persistBuyerAttempt(victim.chain.commerceTokenHash, persistInput(binding));
    const attacker = await seedVerifiedGrant(91, 1091);
    // A second agent in the SAME organization (seeded before the snapshot).
    const sibling = await seedAgent(95, victim.chain.buyer.org);
    await seedPolicy(victim.chain.buyer.org, sibling, 95, victim.chain.provider);
    const siblingMachine = await seedMachine(victim.chain.buyer, 95, sibling);
    await commerce.issueCommerceSession(
      victim.chain.buyer.hash, victim.chain.buyer.org,
      { subjectAgentId: sibling, policyId: policyId(95), handoffHash: sha256('handoff:95'), hashVersion: 1 },
      meta(100095),
    );
    await commerce.exchangeCommerceSession(siblingMachine, sha256('handoff:95'), { tokenHash: sha256('commerce:95'), hashVersion: 1 }, meta(200095));
    const before = await counts();
    // Persist against the victim's grant id with the attacker's token.
    await expectStoreCode(
      store.persistBuyerAttempt(attacker.chain.commerceTokenHash, persistInput(laneBinding({ ...victim }, 92))),
      'CONTROL_PAYMENT_ATTEMPT_STORE_NOT_FOUND',
    );
    await expectStoreCode(
      store.persistBuyerAttempt(attacker.chain.commerceTokenHash, persistInput(laneBinding({ ...attacker, grant: `openarc:grant:${uuid(99999)}` }, 93))),
      'CONTROL_PAYMENT_ATTEMPT_STORE_NOT_FOUND',
    );
    // Dispatch of the victim's attempt: same answer as a missing attempt.
    await expectStoreCode(
      store.recordDispatch(attacker.chain.commerceTokenHash, { attemptId: binding.attemptId, bindingDigest: digestPaymentAttemptBinding(binding) }),
      'CONTROL_PAYMENT_ATTEMPT_STORE_NOT_FOUND',
    );
    await expectStoreCode(
      store.recordDispatch(attacker.chain.commerceTokenHash, { attemptId: attemptId(99998), bindingDigest: digestPaymentAttemptBinding(binding) }),
      'CONTROL_PAYMENT_ATTEMPT_STORE_NOT_FOUND',
    );
    // Read: foreign and missing are both null.
    expect(await store.readAgentAttempt(attacker.chain.commerceTokenHash, binding.attemptId)).toBeNull();
    expect(await store.readAgentAttempt(attacker.chain.commerceTokenHash, attemptId(99997))).toBeNull();
    expect(await store.readAgentAttempt(victim.chain.commerceTokenHash, binding.attemptId)).toMatchObject({ state: 'persisted' });
    // A second agent in the SAME organization cannot read it either.
    expect(await store.readAgentAttempt(sha256('commerce:95'), binding.attemptId)).toBeNull();
    expect(await counts()).toEqual(before);
    expect(await attemptRow(binding.attemptId)).toMatchObject({ state: 'persisted' });
  }, 240000);
});

// ---------------------------------------------------------------------------
describe('attempt state machine', () => {
  it('dispatch only from persisted; a second dispatch is refused in every later state; unknown moves only to pending or committed', async () => {
    const seeded = await seedVerifiedGrant(100, 1100);
    const binding = laneBinding(seeded, 100);
    const token = seeded.chain.commerceTokenHash;
    const org = seeded.chain.buyer.org;
    const attempt = binding.attemptId;
    const digest = digestPaymentAttemptBinding(binding);
    const direct = (set: string) => rawError(migrator.query(`UPDATE openarc_durable.payment_attempts SET ${set} WHERE attempt_id = $1::uuid`, [attempt]));

    await store.persistBuyerAttempt(token, persistInput(binding));
    // Observations are impossible before dispatch.
    expect((await rawError(observe(org, attempt, 'pending', uuid(1), 'received', null))).code).toBe('P0D14');
    // Direct DML cannot skip dispatch or invent states.
    expect((await direct(`state = 'pending', dispatched_at = clock_timestamp(), observed_at = clock_timestamp(), transfer_id = '${uuid(1)}', gateway_status = 'received'`)).code).toBe('23514');
    for (const state of ['released', 'failed', 'expired', 'cancelled', 'released_unsent']) {
      expect([state, (await direct(`state = '${state}'`)).code]).toEqual([state, '23514']);
    }
    // A mismatching dispatch digest is refused and dispatches nothing.
    await expectStoreCode(store.recordDispatch(token, { attemptId: attempt, bindingDigest: `sha256:${'8'.repeat(64)}` }), 'CONTROL_PAYMENT_ATTEMPT_STORE_ATTEMPT_CONFLICT');
    expect(await attemptRow(attempt)).toMatchObject({ state: 'persisted', dispatched_at: null });

    const dispatched = await store.recordDispatch(token, { attemptId: attempt, bindingDigest: digest });
    expect(dispatched.state).toBe('unknown');
    const firstDispatchAt = (await attemptRow(attempt))!['dispatched_at'];
    // A second dispatch of an unknown attempt is refused, repeatedly.
    for (let i = 0; i < 3; i += 1) {
      await expectStoreCode(store.recordDispatch(token, { attemptId: attempt, bindingDigest: digest }), 'CONTROL_PAYMENT_ATTEMPT_STORE_ATTEMPT_CONFLICT');
    }
    // unknown cannot go back, sideways or to any release.
    // A recorded dispatch instant is immutable (42501) and the edge back to
    // persisted does not exist (23514): both are refusals.
    expect((await direct(`state = 'persisted', dispatched_at = NULL`)).code).toBe('42501');
    expect((await direct(`state = 'persisted'`)).code).toBe('23514');
    expect((await direct(`dispatched_at = clock_timestamp()`)).code).toBe('42501');
    expect((await direct(`state = 'unknown'`)).code).toBe('23514');
    expect((await direct(`payer_address = '0x3333333333333333333333333333333333333333'`)).code).toBe('42501');
    expect((await rawError(migrator.query('DELETE FROM openarc_durable.payment_attempts WHERE attempt_id = $1::uuid', [attempt]))).code).toBe('42501');

    // unknown -> pending -> pending(forward) -> committed.
    const transfer = uuid(123456);
    expect((await observe(org, attempt, 'pending', transfer, 'received', null)).rows[0]).toMatchObject({ out_state: 'pending', out_gateway_status: 'received' });
    expect((await observe(org, attempt, 'pending', transfer, 'batched', null)).rows[0]).toMatchObject({ out_gateway_status: 'batched' });
    // Regression, repetition and a different transfer are refused.
    expect((await rawError(observe(org, attempt, 'pending', transfer, 'received', null))).code).toBe('P0D14');
    expect((await rawError(observe(org, attempt, 'pending', transfer, 'batched', null))).code).toBe('P0D14');
    expect((await rawError(observe(org, attempt, 'pending', uuid(654321), 'confirmed', null))).code).toBe('P0D14');
    expect((await direct(`state = 'unknown', observed_at = NULL, transfer_id = NULL, gateway_status = NULL`)).code).toBe('42501');
    await expectStoreCode(store.recordDispatch(token, { attemptId: attempt, bindingDigest: digest }), 'CONTROL_PAYMENT_ATTEMPT_STORE_ATTEMPT_CONFLICT');
    const hash = `0x${sha256('batch')}`;
    expect((await observe(org, attempt, 'committed', transfer, 'completed', hash)).rows[0]).toMatchObject({ out_state: 'committed', out_batch_tx_hash: hash });
    // committed is terminal: nothing moves, not even a repeat.
    expect((await rawError(observe(org, attempt, 'committed', transfer, 'completed', hash))).code).toBe('P0D14');
    expect((await rawError(observe(org, attempt, 'pending', transfer, 'confirmed', hash))).code).toBe('P0D14');
    expect((await direct(`state = 'pending', gateway_status = 'confirmed'`)).code).toBe('23514');
    await expectStoreCode(store.recordDispatch(token, { attemptId: attempt, bindingDigest: digest }), 'CONTROL_PAYMENT_ATTEMPT_STORE_ATTEMPT_CONFLICT');
    expect(await attemptRow(attempt)).toMatchObject({ state: 'committed', dispatched_at: firstDispatchAt, transfer_id: transfer });

    // A second attempt proves unknown -> committed directly and that an
    // unknown classification is never written (no 'unknown' observation input).
    const other = await seedVerifiedGrant(101, 1101);
    const otherBinding = laneBinding(other, 101, { nonce: `0x${sha256('nonce:101')}` });
    await store.persistBuyerAttempt(other.chain.commerceTokenHash, persistInput(otherBinding));
    await store.recordDispatch(other.chain.commerceTokenHash, { attemptId: otherBinding.attemptId, bindingDigest: digestPaymentAttemptBinding(otherBinding) });
    expect((await rawError(observe(other.chain.buyer.org, otherBinding.attemptId, 'unknown', uuid(7), 'received', null))).code).toBe('22023');
    expect((await rawError(observe(other.chain.buyer.org, otherBinding.attemptId, 'committed', uuid(7), 'completed', null))).code).toBe('22023');
    expect((await observe(other.chain.buyer.org, otherBinding.attemptId, 'committed', uuid(7), 'completed', `0x${sha256('b2')}`)).rows[0]).toMatchObject({ out_state: 'committed' });
  }, 180000);

  it('the action exposure guard names exactly cancelled, expired and rejected and nothing else', async () => {
    const source = await admin.query<{ src: string }>(
      `SELECT p.prosrc AS src FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'openarc_durable' AND p.proname = 'enforce_action_payment_exposure'`,
    );
    expect(source.rows).toHaveLength(1);
    const src = source.rows[0]!.src;
    const lists = [...src.matchAll(/NEW\.status\s+IN\s*\(([^)]*)\)/g)];
    expect(lists).toHaveLength(1);
    const statuses = [...lists[0]![1]!.matchAll(/'([a-z_]+)'/g)].map((match) => match[1]).sort();
    expect(statuses).toEqual(['cancelled', 'expired', 'rejected']);
    // No other status predicate on NEW, so a future success status is not blocked.
    expect(src.match(/NEW\.status/g)).toHaveLength(1);
    expect(src).toContain("OLD.status = 'grant_issued'");
  });

  it('no path releases exposure once an attempt exists: repeated revoke, cancel, authority expiry and direct cleanup keep it held', async () => {
    // The only schema functions that release a reservation are these two; both are guarded.
    const releasers = await admin.query<{ proname: string }>(
      `SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'openarc_durable' AND p.prosrc ~ 'SET status = ''released''' ORDER BY p.proname`,
    );
    expect(releasers.rows.map((row) => row.proname)).toEqual(['cancel_commerce_action_core', 'revoke_authorization_grant']);

    let revokeSeed = 0;
    const revoke = (seeded: Verified) => grants.revokeGrant(seeded.chain.buyer.hash, seeded.chain.buyer.org, seeded.grant, meta(800000 + (revokeSeed += 1)));
    const assertHeld = async (seeded: Verified, reservation: string) => {
      expect(await reservationOf(seeded.action)).toMatchObject({ status: reservation, resolved_at: null });
      expect(await actionStatus(seeded.action)).toBe('grant_issued');
      const released = await admin.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM openarc_durable.budget_events WHERE action_id = $1 AND event_kind = 'released'`, [seeded.action],
      );
      expect(released.rows[0]!.n).toBe(0);
    };
    const cleanupRefused = async (seeded: Verified) => {
      expect((await rawError(migrator.query(
        `UPDATE openarc_durable.budget_reservations SET status = 'released', resolved_at = clock_timestamp() WHERE action_id = $1`, [seeded.action],
      ))).code).toMatch(/^(P0D13|23514)$/);
      expect((await rawError(migrator.query(
        `UPDATE openarc_durable.commerce_actions SET status = 'cancelled', updated_at = clock_timestamp() WHERE action_id = $1`, [seeded.action],
      ))).code).toMatch(/^(P0D13|23514)$/);
      try {
        await actions.cancelCommerceAction(seeded.chain.buyer.hash, seeded.chain.buyer.org, seeded.action, meta(810000 + (revokeSeed += 1)));
        throw new Error('cancel unexpectedly succeeded');
      } catch (error) {
        expect(error).toBeInstanceOf(ControlActionStoreError);
      }
    };

    // A: persisted only (never dispatched). Revoke retires the grant but releases nothing.
    const a = await seedVerifiedGrant(110, 1110);
    const aBinding = laneBinding(a, 110);
    await store.persistBuyerAttempt(a.chain.commerceTokenHash, persistInput(aBinding));
    const aRevoked = await revoke(a);
    expect(aRevoked).toMatchObject({ released: false, reservationStatus: 'held', actionStatus: 'grant_issued', metadata: { status: 'revoked' } });
    await assertHeld(a, 'held');
    await expectRejectedWith(revoke(a), ControlGrantStoreError, 'CONTROL_GRANT_STORE_GRANT_CONFLICT');
    await cleanupRefused(a);
    await assertHeld(a, 'held');
    // The attempt can no longer be dispatched, and it stays persisted (held).
    await expectStoreCode(
      store.recordDispatch(a.chain.commerceTokenHash, { attemptId: aBinding.attemptId, bindingDigest: digestPaymentAttemptBinding(aBinding) }),
      'CONTROL_PAYMENT_ATTEMPT_STORE_ATTEMPT_CONFLICT',
    );
    expect(await attemptRow(aBinding.attemptId)).toMatchObject({ state: 'persisted' });

    // B: dispatched (unknown), then the buyer's authority EXPIRES before any claim.
    const b = await seedVerifiedGrant(111, 1111);
    const bBinding = laneBinding(b, 111, { nonce: `0x${sha256('nonce:111')}` });
    await store.persistBuyerAttempt(b.chain.commerceTokenHash, persistInput(bBinding));
    await store.recordDispatch(b.chain.commerceTokenHash, { attemptId: bBinding.attemptId, bindingDigest: digestPaymentAttemptBinding(bBinding) });
    await admin.query(
      `UPDATE openarc_durable.commerce_sessions SET expires_at = greatest(exchanged_at, issued_at + interval '1 millisecond') WHERE organization_id = $1`,
      [b.chain.buyer.org],
    );
    await expectStoreCode(
      store.recordDispatch(b.chain.commerceTokenHash, { attemptId: bBinding.attemptId, bindingDigest: digestPaymentAttemptBinding(bBinding) }),
      'CONTROL_PAYMENT_ATTEMPT_STORE_FORBIDDEN',
    );
    await assertHeld(b, 'held');
    for (let i = 0; i < 2; i += 1) {
      if (i === 0) {
        expect(await revoke(b)).toMatchObject({ released: false, reservationStatus: 'held' });
      } else {
        await expectRejectedWith(revoke(b), ControlGrantStoreError, 'CONTROL_GRANT_STORE_GRANT_CONFLICT');
      }
      await assertHeld(b, 'held');
    }
    await cleanupRefused(b);
    await assertHeld(b, 'held');
    expect(await attemptRow(bBinding.attemptId)).toMatchObject({ state: 'unknown' });

    // C: dispatched, claimed, observed pending, then revoked: claimed exposure stays held.
    const c = await seedVerifiedGrant(112, 1112);
    const cBinding = laneBinding(c, 112, { nonce: `0x${sha256('nonce:112')}` });
    await store.persistBuyerAttempt(c.chain.commerceTokenHash, persistInput(cBinding));
    await store.recordDispatch(c.chain.commerceTokenHash, { attemptId: cBinding.attemptId, bindingDigest: digestPaymentAttemptBinding(cBinding) });
    await grants.claimGrant(c.providerSessionHash, { grantTokenHash: c.grantTokenHash, expectedActionId: c.action, attemptId: cBinding.attemptId }, meta(520112));
    await observe(c.chain.buyer.org, cBinding.attemptId, 'pending', uuid(112), 'confirmed', null);
    expect(await revoke(c)).toMatchObject({ released: false, reservationStatus: 'claimed' });
    await assertHeld(c, 'claimed');
    await cleanupRefused(c);
    await assertHeld(c, 'claimed');
    // Committing the observation is not a release either.
    await observe(c.chain.buyer.org, cBinding.attemptId, 'committed', uuid(112), 'completed', `0x${sha256('batch:112')}`);
    await assertHeld(c, 'claimed');
    expect((await counts()).released_reservations).toBe(0);
  }, 300000);
});

// ---------------------------------------------------------------------------
describe('secret material', () => {
  it('stores and returns no raw signature, authorization payload or key material anywhere', async () => {
    const seeded = await seedVerifiedGrant(120, 1120);
    const binding = laneBinding(seeded, 120);
    const token = seeded.chain.commerceTokenHash;
    const payload = Buffer.from(JSON.stringify({
      x402Version: 2,
      payload: { authorization: { from: PAYER, to: PAY_TO, value: '1000000', nonce: binding.nonce }, signature: SIGNATURE_CANARY },
      privateKey: PRIVATE_KEY_CANARY,
    })).toString('base64');

    // No input path accepts a signature, payload or key.
    const smuggled: unknown[] = [
      { ...persistInput(binding), signature: SIGNATURE_CANARY },
      { ...persistInput(binding), payload },
      { binding: { ...binding, signature: SIGNATURE_CANARY }, bindingDigest: digestPaymentAttemptBinding(binding) },
      { binding: { ...binding, privateKey: PRIVATE_KEY_CANARY }, bindingDigest: digestPaymentAttemptBinding(binding) },
      { binding: { ...binding, from: SIGNATURE_CANARY }, bindingDigest: digestPaymentAttemptBinding(binding) },
    ];
    for (const input of smuggled) {
      await expectStoreCode(store.persistBuyerAttempt(token, input), 'CONTROL_PAYMENT_ATTEMPT_STORE_INPUT_INVALID');
    }
    expect((await rawError(tenant.query(RAW_PERSIST, rawPersistArgs(token, { ...binding, to: SIGNATURE_CANARY }, digestPaymentAttemptBinding(binding))))).code).toBe('22023');
    expect((await rawError(tenant.query(RAW_PERSIST, rawPersistArgs(token, { ...binding, nonce: payload }, digestPaymentAttemptBinding(binding))))).code).toBe('22023');

    // The full flow, with every output captured.
    const outputs: unknown[] = [];
    outputs.push(await store.persistBuyerAttempt(token, persistInput(binding)));
    outputs.push(await store.recordDispatch(token, { attemptId: binding.attemptId, bindingDigest: digestPaymentAttemptBinding(binding) }));
    outputs.push(await grants.claimGrant(seeded.providerSessionHash, { grantTokenHash: seeded.grantTokenHash, expectedActionId: seeded.action, attemptId: binding.attemptId }, meta(520120)));
    const hash = `0x${sha256('batch:120')}`;
    outputs.push((await observe(seeded.chain.buyer.org, binding.attemptId, 'committed', uuid(120), 'completed', hash)).rows);
    outputs.push(await store.readAgentAttempt(token, binding.attemptId));

    const tables = await admin.query<{ schema: string; name: string }>(
      `SELECT table_schema AS schema, table_name AS name FROM information_schema.tables
        WHERE table_schema IN ('openarc_auth', 'openarc_tenant', 'openarc_durable') AND table_type = 'BASE TABLE'`,
    );
    let everything = '';
    for (const table of tables.rows) {
      const rows = await admin.query<{ j: string }>(`SELECT row_to_json(t)::text AS j FROM ${table.schema}.${table.name} t`);
      everything += rows.rows.map((row) => row.j).join('\n');
    }
    const outputText = JSON.stringify(outputs);
    for (const [label, text] of [['rows', everything], ['outputs', outputText]] as const) {
      expect([label, text.includes(SIGNATURE_CANARY.slice(2))]).toEqual([label, false]);
      expect([label, text.includes(PRIVATE_KEY_CANARY)]).toEqual([label, false]);
      expect([label, text.includes(payload)]).toEqual([label, false]);
      // Nothing signature-shaped (65 bytes of hex) exists anywhere.
      expect([label, /[0-9a-fA-F]{130}/.test(text)]).toEqual([label, false]);
    }
    // Every 64-hex value in the attempt rows and the attempt outputs is one of
    // the known non-secret binding identifiers; no token hash leaks out.
    const attemptText = JSON.stringify((await admin.query('SELECT * FROM openarc_durable.payment_attempts')).rows) + outputText;
    const allowed = new Set([
      binding.nonce.slice(2), digestPaymentAttemptBinding(binding).slice(7), binding.laneRequirementDigest.slice(7),
      seeded.requirementDigest.slice(7), hash.slice(2),
    ]);
    const claimDigest = (outputs[2] as { claimDigest: string }).claimDigest.slice(7);
    allowed.add(claimDigest);
    const found = attemptText.match(/[0-9a-f]{64}/g) ?? [];
    expect(found.length).toBeGreaterThan(0);
    for (const value of found) {
      expect([value, allowed.has(value)]).toEqual([value, true]);
    }
    for (const secret of [token, seeded.grantTokenHash, seeded.providerSessionHash, seeded.chain.agentSessionHash, rawGrantToken(120)]) {
      expect(outputText.includes(secret)).toBe(false);
    }
  }, 180000);
});

// ---------------------------------------------------------------------------
describe('seller payment terms', () => {
  it('records immutable pay-to terms exactly once per non-retired version with idempotency and audit receipts', async () => {
    const seller = await seedOwner(130);
    const provider = await seedProvider(130, seller.org);
    const listing = await seedPublishedListing(seller, provider, 130, null);
    const before = await counts();
    const recorded = await store.recordListingPaymentTerms(
      seller.hash, seller.org, listing, '1', { payToAddress: PAY_TO_MIXED }, meta(131),
    );
    expect(recorded).toMatchObject({
      replayed: false,
      terms: { organizationId: seller.org, listingId: listing, version: '1', payToAddress: PAY_TO },
      receipt: { operation: 'market.listing.payment_terms.record', resourceType: 'listing_version', resourceId: `${listing}@1` },
    });
    const after = await counts();
    expect(after).toMatchObject({ terms: before.terms + 1, idem: before.idem + 1, audit: before.audit + 1, outbox: before.outbox });
    const row = await admin.query<Record<string, unknown>>(
      'SELECT pay_to_address, recorded_by_account_id, provider_id FROM openarc_tenant.listing_version_payment_terms WHERE listing_id = $1',
      [listing],
    );
    expect(row.rows).toEqual([{ pay_to_address: PAY_TO, recorded_by_account_id: seller.account, provider_id: provider }]);
    // Exact replay: same receipt, no new rows.
    const replay = await store.recordListingPaymentTerms(
      seller.hash, seller.org, listing, '1', { payToAddress: PAY_TO_MIXED }, meta(131),
    );
    expect(replay).toMatchObject({ replayed: true, terms: { payToAddress: PAY_TO } });
    expect(await counts()).toEqual(after);
    // Same key, different pay-to: idempotency conflict. New key, same version: immutable.
    await expectStoreCode(
      store.recordListingPaymentTerms(seller.hash, seller.org, listing, '1', { payToAddress: PAY_TO_V2 }, meta(131)),
      'CONTROL_PAYMENT_ATTEMPT_STORE_IDEMPOTENCY_CONFLICT',
    );
    await expectStoreCode(
      store.recordListingPaymentTerms(seller.hash, seller.org, listing, '1', { payToAddress: PAY_TO_V2 }, meta(132)),
      'CONTROL_PAYMENT_ATTEMPT_STORE_CONFLICT',
    );
    // Direct DML cannot change or remove terms, even as the migrator.
    expect((await rawError(migrator.query(
      'UPDATE openarc_tenant.listing_version_payment_terms SET pay_to_address = $1 WHERE listing_id = $2', [PAY_TO_V2, listing],
    ))).code).toBe('42501');
    expect((await rawError(migrator.query(
      'DELETE FROM openarc_tenant.listing_version_payment_terms WHERE listing_id = $1', [listing],
    ))).code).toBe('42501');
    // Zero, GatewayWallet and USDC payees are refused by the database itself.
    for (const bad of ['0x0000000000000000000000000000000000000000', GATEWAY_WALLET, USDC]) {
      const error = await rawError(tenant.query(
        `SELECT * FROM openarc_durable.commit_listing_payment_terms($1, $2, $3, '1', $4, $5::uuid, $6, $7, $8)`,
        [seller.hash, seller.org, listing, bad, mutationId(133), 'a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64)],
      ));
      expect([bad, error.code]).toEqual([bad, '22023']);
    }
    // A new version with different terms; v1 keeps its own.
    await market.createListingVersion(
      seller.hash, seller.org, listing, { expectedLatestVersion: '1', content: content() }, meta(64000 + 130),
    );
    expect((await recordTerms(seller, listing, '2', PAY_TO_V2, 130)).terms.payToAddress).toBe(PAY_TO_V2);
    // A retired version cannot receive terms.
    await market.createListingVersion(
      seller.hash, seller.org, listing, { expectedLatestVersion: '2', content: content() }, meta(64000 + 131),
    );
    await lifecycle.retireListingVersion(
      seller.hash, seller.org, listing, '3',
      { expectedUpdatedAt: await stateUpdatedAt(seller.org, listing, '3'), expectedActiveVersion: '1' },
      meta(62000 + 130),
    );
    await expectStoreCode(recordTerms(seller, listing, '3', PAY_TO_V2, 130), 'CONTROL_PAYMENT_ATTEMPT_STORE_INPUT_INVALID');
    const final = await admin.query<{ version: string; pay_to_address: string }>(
      'SELECT version, pay_to_address FROM openarc_tenant.listing_version_payment_terms WHERE listing_id = $1 ORDER BY version',
      [listing],
    );
    expect(final.rows).toEqual([{ version: '1', pay_to_address: PAY_TO }, { version: '2', pay_to_address: PAY_TO_V2 }]);
  }, 180000);

  it('refuses non-owner roles, cross-organization sellers and stale proofs with zero mutations', async () => {
    const seller = await seedOwner(140);
    const provider = await seedProvider(140, seller.org);
    const listing = await seedPublishedListing(seller, provider, 140, null);
    const outsider = await seedOwner(141);
    const before = await counts();
    for (const [seed, role] of [[142, 'provider_developer'], [143, 'operator'], [144, 'viewer']] as const) {
      const member = await seedMember(seed, seller.org, role);
      await expectStoreCode(
        store.recordListingPaymentTerms(member.hash, seller.org, listing, '1', { payToAddress: PAY_TO }, meta(150 + seed)),
        'CONTROL_PAYMENT_ATTEMPT_STORE_FORBIDDEN',
      );
    }
    // A provider_admin of the owning organization IS allowed (checked last).
    // Another organization's owner, naming its own org or the seller's, is refused.
    await expectStoreCode(
      store.recordListingPaymentTerms(outsider.hash, seller.org, listing, '1', { payToAddress: PAY_TO }, meta(160)),
      'CONTROL_PAYMENT_ATTEMPT_STORE_FORBIDDEN',
    );
    await expectStoreCode(
      store.recordListingPaymentTerms(outsider.hash, outsider.org, listing, '1', { payToAddress: PAY_TO }, meta(161)),
      'CONTROL_PAYMENT_ATTEMPT_STORE_NOT_FOUND',
    );
    // A stale (older than five minutes) owner proof is refused.
    await admin.query(
      // Shift both instants so the session's own expiry-window CHECK still holds.
      `UPDATE openarc_auth.sessions
          SET created_at = created_at - interval '10 minutes', expires_at = expires_at - interval '10 minutes'
        WHERE token_hash = $1`, [seller.hash],
    );
    await expectStoreCode(
      store.recordListingPaymentTerms(seller.hash, seller.org, listing, '1', { payToAddress: PAY_TO }, meta(162)),
      'CONTROL_PAYMENT_ATTEMPT_STORE_SESSION_INVALID',
    );
    expect((await counts()).terms).toBe(before.terms);
    expect((await counts()).idem).toBe(before.idem);
    const admin2 = await seedMember(145, seller.org, 'provider_admin');
    const ok = await store.recordListingPaymentTerms(admin2.hash, seller.org, listing, '1', { payToAddress: PAY_TO }, meta(163));
    expect(ok.terms.payToAddress).toBe(PAY_TO);
  }, 180000);

  it('a published, approved version WITHOUT terms cannot back a verified requirement through any path', async () => {
    const chain = await seedCrossChain(170, 1170);
    const bare = await seedPublishedListing(chain.seller, chain.provider, 1171, null);
    const before = await counts();
    expect((await rawError(registerVerified(chain.buyer.org, requirementId(171), bare))).code).toBe('42501');
    await expectStoreCode(
      store.registerVerifiedRequirement(chain.commerceTokenHash, { requirementId: requirementId(172), listingId: bare }),
      'CONTROL_PAYMENT_ATTEMPT_STORE_FORBIDDEN',
    );
    const direct = await rawError(migrator.query(
      `INSERT INTO openarc_durable.commerce_requirement_references (
         organization_id, requirement_id, seller_organization_id, provider_id, listing_id,
         listing_version, network_id, asset, representation, decimals, amount_atomic,
         fee_atomic, requirement_digest, source_kind, created_at, valid_until, pay_to_address)
       SELECT $1, $2, $3, $4, $5, '1', 'eip155:5042002', 'USDC', 'erc20', 6, '1000000', '0', $6,
              'verified_listing', n.c, n.c + interval '900 seconds', $7 FROM (SELECT clock_timestamp() AS c) n`,
      [chain.buyer.org, requirementId(173), chain.seller.org, chain.provider, bare,
        verifiedDigest(chain.seller.org, chain.provider, bare, '1', PAY_TO, '1000000', '0'), PAY_TO],
    ));
    expect(direct.code).toBe('42501');
    expect(await counts()).toEqual(before);
  }, 180000);
});

// ---------------------------------------------------------------------------
describe('runtime verified requirement registrar', () => {
  it('derives the buyer organization from the exact commerce token and every term server-side; production authorize then succeeds', async () => {
    const chain = await seedCrossChain(180, 1180);
    const registered = await store.registerVerifiedRequirement(
      chain.commerceTokenHash, { requirementId: requirementId(180), listingId: chain.listing },
    );
    expect(registered).toMatchObject({
      organizationId: chain.buyer.org,
      sellerOrganizationId: chain.seller.org,
      providerId: chain.provider,
      listingVersion: '1',
      amountAtomic: '1000000',
      feeAtomic: '0',
      payToAddress: PAY_TO,
      sourceKind: 'verified_listing',
      requirementDigest: verifiedDigest(chain.seller.org, chain.provider, chain.listing, '1', PAY_TO, '1000000', '0'),
    });
    const authorized = await actions.authorizeCommerceAction(
      chain.commerceTokenHash, { requirementId: requirementId(180), actionId: actionId(180) }, meta(300180),
    );
    expect(authorized).toBeTruthy();
    expect(await actionStatus(actionId(180))).toBe('reserved_not_granted');
    // The signature takes no organization, price, network, asset, contract, pay-to or calldata.
    const signature = await admin.query<{ args: string }>(
      `SELECT pg_get_function_identity_arguments(p.oid) AS args FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'openarc_durable' AND p.proname = 'register_verified_commerce_requirement'`,
    );
    expect(signature.rows).toEqual([{ args: 'commerce_token_hash text, requirement_id_input text, listing_id_input text' }]);
  }, 180000);

  it('cross-organization tokens can only ever register for their own organization and cannot reuse or overwrite another buyer\'s requirement', async () => {
    const victim = await seedCrossChain(190, 1190);
    const attacker = await seedCrossChain(191, 1191);
    await store.registerVerifiedRequirement(victim.commerceTokenHash, { requirementId: requirementId(190), listingId: victim.listing });
    const before = await counts();
    await expectStoreCode(
      store.registerVerifiedRequirement(attacker.commerceTokenHash, { requirementId: requirementId(190), listingId: victim.listing }),
      'CONTROL_PAYMENT_ATTEMPT_STORE_CONFLICT',
    );
    expect(await counts()).toEqual(before);
    // The attacker's own registration against the victim seller's public listing is scoped to the ATTACKER org,
    const own = await store.registerVerifiedRequirement(attacker.commerceTokenHash, { requirementId: requirementId(192), listingId: victim.listing });
    expect(own.organizationId).toBe(attacker.buyer.org);
    // and the victim can never authorize against it (organization mismatch, zero mutations).
    const beforeAuthorize = await counts();
    await expectRejectedWith(
      actions.authorizeCommerceAction(victim.commerceTokenHash, { requirementId: requirementId(192), actionId: actionId(192) }, meta(300192)),
      ControlActionStoreError, 'CONTROL_ACTION_STORE_FORBIDDEN',
    );
    expect(await counts()).toEqual(beforeAuthorize);
    // A made-up token is refused outright.
    await expectStoreCode(
      store.registerVerifiedRequirement('f'.repeat(64), { requirementId: requirementId(193), listingId: victim.listing }),
      'CONTROL_PAYMENT_ATTEMPT_STORE_FORBIDDEN',
    );
  }, 180000);

  it('refuses revoked and expired commerce sessions with zero mutations; fixture provenance stays refused in production', async () => {
    const revoked = await seedCrossChain(200, 1200);
    await admin.query(
      'UPDATE openarc_durable.commerce_sessions SET revoked_at = clock_timestamp() WHERE organization_id = $1', [revoked.buyer.org],
    );
    const expired = await seedCrossChain(201, 1201);
    await admin.query(
      `UPDATE openarc_durable.commerce_sessions SET expires_at = greatest(exchanged_at, issued_at + interval '1 millisecond') WHERE organization_id = $1`,
      [expired.buyer.org],
    );
    const before = await counts();
    for (const chain of [revoked, expired]) {
      await expectStoreCode(
        store.registerVerifiedRequirement(chain.commerceTokenHash, { requirementId: requirementId(chain.seed), listingId: chain.listing }),
        'CONTROL_PAYMENT_ATTEMPT_STORE_FORBIDDEN',
      );
    }
    expect(await counts()).toEqual(before);
    // Fixture provenance is unchanged: still refused by production authorize with zero writes.
    const fixture = await seedCrossChain(202, 1202);
    const fixtureRequirement = await seedFixtureRequirement(fixture, 202);
    const beforeFixture = await counts();
    await expectRejectedWith(
      actions.authorizeCommerceAction(fixture.commerceTokenHash, { requirementId: fixtureRequirement, actionId: actionId(202) }, meta(300202)),
      ControlActionStoreError, 'CONTROL_ACTION_STORE_REQUIREMENT_UNAVAILABLE',
    );
    expect(await counts()).toEqual(beforeFixture);
  }, 180000);
});
