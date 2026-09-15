import { createHash } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import {
  CommerceSessionStore,
  ControlActionStore,
  ControlActionStoreError,
  ControlGrantStore,
  ControlGrantStoreError,
  CredentialStore,
  MarketLifecycleStore,
  MarketStore,
  createDatabasePool,
  digestCommerceGrantToken,
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
 * P03-06 independent race and adversarial suite.
 *
 * This file does NOT re-demonstrate the per-packet happy paths. Every case here
 * assumes the implementation is wrong and tries to prove it: it drives real
 * separate PostgreSQL connections against a controlled barrier, proves the
 * contention actually happened (a blocked backend observed by pid in
 * pg_stat_activity, or a contender that provably could not settle), and then
 * asserts on COMMITTED state - full durable row snapshots and exact integer
 * money strings - not merely on the thrown error code.
 *
 * Positive mechanics run the migrator-only cores with the closed literal
 * 'internal_fixture' mode exactly as the accepted per-packet suites do; the
 * restricted tenant runtime still only ever reaches the 'production' wrappers.
 * Nothing here is production purchase, grant, payment or settlement evidence.
 *
 * Redis is deliberately out of scope: packages/db has no Redis dependency and
 * Redis holds no financial authority in this design.
 */

const ORIGIN = 'https://api.example.com';
const PATH = '/v1/run';

const HEX_A = 'a'.repeat(64);
const HEX_B = 'b'.repeat(64);
const HEX_C = 'c'.repeat(64);
const HEX_D = 'd'.repeat(64);

function sha256(seed: string): string {
  return createHash('sha256').update(`openarc-adversarial-test:${seed}`, 'utf8').digest('hex');
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
function actionMutation(seed: number): string { return uuid(850000 + seed); }
function grantMutation(seed: number): string { return uuid(880000 + seed); }
function lookupId(seed: number): string { return uuid(900000 + seed); }
function machineSessionId(seed: number): string { return uuid(600000 + seed); }
function providerSessionId(seed: number): string { return uuid(660000 + seed); }
function attemptOf(seed: number): string { return uuid(770000 + seed); }

function key(seed: number): string {
  return createHash('sha256').update(`adversarial-key:${seed}`).digest().toString('base64url');
}

function keyHashOf(seed: number): string {
  return createHash('sha256').update(key(seed), 'utf8').digest('hex');
}

function userHandle(seed: number): string {
  return `${sha256(`handle:${seed}`).slice(0, 42)}A`;
}

/** A canonical raw oag_v1_ secret, generated exactly as the trusted API would.
 *  It is NEVER handed to the store or to the database. */
function rawGrantToken(seed: number): string {
  const material = createHash('sha256').update(`adversarial-secret:${seed}`).digest();
  return `oag_v1_${material.toString('base64url')}`;
}

function contextDigest(domain: string, hash: string): string {
  return createHash('sha256').update(`${domain}:${hash}`, 'utf8').digest('hex');
}

const AUTHORIZE_SESSION_DOMAIN = 'openarc.control.commerce_action.authorize.session.v1';

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
/** A dedicated admin pool reserved for barrier holders and lock probes, so a
 *  race observation never competes with fixture seeding for a connection. */
let probe: Pool;
let migrator: ReturnType<typeof createDatabasePool>;
let tenant: ReturnType<typeof createDatabasePool>;
let actions: ControlActionStore;
let grants: ControlGrantStore;
let credentials: CredentialStore;
let commerce: CommerceSessionStore;
let market: MarketStore;
let lifecycle: MarketLifecycleStore;

beforeAll(async () => {
  admin = adminPool();
  probe = adminPool();
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
    await probe.end();
    await admin.end();
  }
});

beforeEach(async () => {
  await resetSchema(admin);
  await migrate(migrator);
  actions = new ControlActionStore(tenant);
  grants = new ControlGrantStore(tenant);
  credentials = new CredentialStore(tenant);
  commerce = new CommerceSessionStore(tenant);
  market = new MarketStore(tenant);
  lifecycle = new MarketLifecycleStore(tenant);
});

// ---------------------------------------------------------------------------
// Seeding. Identical in approach to the accepted per-packet PG suites.
// ---------------------------------------------------------------------------

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

async function seedSession(seed: number, account: string): Promise<string> {
  const hash = sha256(`session:${seed}`);
  await admin.query(
    `INSERT INTO openarc_auth.sessions (token_hash, account_id, method, created_at, expires_at)
     VALUES ($1, $2, 'passkey', now(), now() + interval '24 hours')`,
    [hash, account],
  );
  return hash;
}

async function seedOwner(seed: number): Promise<Owner> {
  const account = await seedAccount(seed);
  const hash = await seedSession(seed, account);
  const org = orgId(seed);
  await admin.query(
    "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Org', $2)",
    [org, account],
  );
  await admin.query(
    "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'owner', 'active')",
    [org, account],
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

interface PolicyOptions {
  readonly perActionLimit?: string | null;
  readonly rollingLimit?: string | null;
  readonly feeLimit?: string;
  readonly mode?: 'none' | 'always' | 'above';
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
               ARRAY[$7]::text[], ARRAY[]::text[], $8, NULL, false,
               clock_timestamp() + interval '1 hour', 'sha256:' || repeat('a', 64))`,
      [
        org, id, subject,
        options.perActionLimit === undefined ? '5000000' : options.perActionLimit,
        options.rollingLimit === undefined ? '5000000' : options.rollingLimit,
        options.feeLimit ?? '0',
        provider,
        options.mode ?? 'none',
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

async function seedMachine(owner: Owner, seed: number, agent: string): Promise<string> {
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
  return agentSessionHash;
}

/** A live oas_pr_ provider session under the EXISTING provider:self.read scope. */
async function seedProviderSession(
  seller: Owner,
  provider: string,
  seed: number,
): Promise<string> {
  const issued = await credentials.issueProviderCredentialDurably({
    sessionHash: seller.hash,
    organizationId: seller.org,
    profileId: provider,
    lookupId: lookupId(4000 + seed),
    hash: hashInput(),
    expiresAt: new Date(Date.now() + 30 * 60_000).toISOString(),
    metadata: { idempotencyKey: key(600000 + seed), mutationId: mutationId(600000 + seed) },
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

/** A SECOND live session for the SAME provider credential. */
async function seedExtraProviderSession(
  seller: Owner,
  provider: string,
  seed: number,
): Promise<string> {
  const credential = await admin.query<{ credential_id: string }>(
    `SELECT credential_id FROM openarc_durable.provider_credentials
      WHERE organization_id = $1 AND provider_id = $2 AND revoked_at IS NULL`,
    [seller.org, provider],
  );
  const tokenHash = sha256(`provider-session-extra:${seed}`);
  await credentials.createProviderSession({
    organizationId: seller.org,
    profileId: provider,
    credentialId: credential.rows[0]!.credential_id,
    expectedVersion: 1,
    sessionId: providerSessionId(50000 + seed),
    tokenHash,
    expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
  });
  return tokenHash;
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
    moderatorHash, owner.org, listing, '1',
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
    owner.hash, owner.org, listing, '1',
    { expectedUpdatedAt: s1.rows[0]!.updated_at, expectedActiveVersion: null },
    { idempotencyKey: key(seed + 1), mutationId: mutationId(seed + 1) },
  );
  return listing;
}

interface Chain {
  readonly buyer: Owner;
  readonly seller: Owner;
  readonly agent: string;
  readonly provider: string;
  readonly listing: string;
  readonly policy: string;
  readonly commerceTokenHash: string;
  readonly agentSessionHash: string;
  readonly seed: number;
}

/** Buyer A buys seller B's real published, origin-approved listing. The buyer
 *  holds NO membership in the seller organization. */
async function seedCrossChain(
  buyerSeed: number,
  sellerSeed: number,
  options: PolicyOptions = {},
): Promise<Chain> {
  const buyer = await seedOwner(buyerSeed);
  const seller = await seedOwner(sellerSeed);
  const agent = await seedAgent(buyerSeed, buyer.org);
  const provider = await seedProvider(sellerSeed, seller.org);
  const listing = await seedPublishedListing(seller, provider, sellerSeed);
  const policy = await seedPolicy(buyer.org, agent, buyerSeed, provider, options);
  const agentSessionHash = await seedMachine(buyer, buyerSeed, agent);
  const handoffHash = sha256(`handoff:${buyerSeed}`);
  const commerceTokenHash = sha256(`commerce:${buyerSeed}`);
  await commerce.issueCommerceSession(
    buyer.hash, buyer.org,
    { subjectAgentId: agent, policyId: policy, handoffHash, hashVersion: 1 },
    { idempotencyKey: key(100000 + buyerSeed), mutationId: mutationId(100000 + buyerSeed) },
  );
  await commerce.exchangeCommerceSession(
    agentSessionHash, handoffHash,
    { tokenHash: commerceTokenHash, hashVersion: 1 },
    { idempotencyKey: key(200000 + buyerSeed), mutationId: mutationId(200000 + buyerSeed) },
  );
  return {
    buyer, seller, agent, provider, listing, policy,
    commerceTokenHash, agentSessionHash, seed: buyerSeed,
  };
}

/** A SECOND live commerce session for the SAME buyer/agent/policy. */
async function seedSecondCommerceSession(chain: Chain, seed: number): Promise<string> {
  const handoffHash = sha256(`handoff-second:${seed}`);
  const tokenHash = sha256(`commerce-second:${seed}`);
  await commerce.issueCommerceSession(
    chain.buyer.hash, chain.buyer.org,
    { subjectAgentId: chain.agent, policyId: chain.policy, handoffHash, hashVersion: 1 },
    { idempotencyKey: key(110000 + seed), mutationId: mutationId(110000 + seed) },
  );
  await commerce.exchangeCommerceSession(
    chain.agentSessionHash, handoffHash,
    { tokenHash, hashVersion: 1 },
    { idempotencyKey: key(210000 + seed), mutationId: mutationId(210000 + seed) },
  );
  return tokenHash;
}

async function seedRequirement(
  chain: Chain,
  seed: number,
  overrides: { amountAtomic?: string; feeAtomic?: string; validForSeconds?: number } = {},
): Promise<string> {
  const id = requirementId(seed);
  await admin.query(
    `INSERT INTO openarc_durable.commerce_requirement_references (
       organization_id, requirement_id, seller_organization_id, provider_id, listing_id,
       listing_version, network_id, asset, representation, decimals, amount_atomic,
       fee_atomic, requirement_digest, source_kind, created_at, valid_until)
     VALUES ($1, $2, $3, $4, $5, '1', 'eip155:5042002', 'USDC', 'erc20', 6, $6, $7,
             'sha256:' || repeat('c', 64), 'internal_fixture', clock_timestamp(),
             clock_timestamp() + make_interval(secs => $8::int))`,
    [
      chain.buyer.org, id, chain.seller.org, chain.provider, chain.listing,
      overrides.amountAtomic ?? '1000000',
      overrides.feeAtomic ?? '0',
      overrides.validForSeconds ?? 1800,
    ],
  );
  return id;
}

// ---------------------------------------------------------------------------
// Core drivers (migrator-only closed 'internal_fixture' lane).
// ---------------------------------------------------------------------------

type Queryable = { query: (text: string, values?: unknown[]) => Promise<{ rows: Record<string, unknown>[] }> };

interface CoreMeta {
  readonly mutation?: string;
  readonly keyHash?: string;
  readonly digest?: string;
  readonly context?: string;
}

function coreAuthorizeOn(
  runner: Queryable,
  chain: Chain,
  requirement: string,
  action: string,
  meta: CoreMeta = {},
  commerceTokenHash = chain.commerceTokenHash,
) {
  return runner.query(
    `SELECT * FROM openarc_durable.authorize_commerce_action_core(
       'internal_fixture', $1, $2, $3, $4::uuid, $5, $6, $7)`,
    [
      commerceTokenHash, requirement, action,
      meta.mutation ?? actionMutation(chain.seed),
      meta.keyHash ?? keyHashOf(300000 + chain.seed),
      meta.digest ?? HEX_A,
      meta.context ?? contextDigest(AUTHORIZE_SESSION_DOMAIN, commerceTokenHash),
    ],
  );
}

function coreAuthorize(chain: Chain, requirement: string, action: string, meta: CoreMeta = {}) {
  return coreAuthorizeOn(migrator, chain, requirement, action, meta);
}

function coreIssueOn(
  runner: Queryable,
  chain: Chain,
  action: string,
  tokenHash: string,
  meta: CoreMeta = {},
) {
  return runner.query(
    `SELECT * FROM openarc_durable.issue_authorization_grant_core(
       'internal_fixture', $1, $2, $3, 1, $4::uuid, $5, $6, $7)`,
    [
      chain.commerceTokenHash, action, tokenHash,
      meta.mutation ?? grantMutation(chain.seed), meta.keyHash ?? HEX_B,
      meta.digest ?? HEX_C, meta.context ?? HEX_D,
    ],
  );
}

function coreIssue(chain: Chain, action: string, tokenHash: string, meta: CoreMeta = {}) {
  return coreIssueOn(migrator, chain, action, tokenHash, meta);
}

function coreReplaceOn(
  runner: Queryable,
  chain: Chain,
  grant: string,
  tokenHash: string,
  meta: CoreMeta = {},
) {
  return runner.query(
    `SELECT * FROM openarc_durable.replace_authorization_grant_core(
       'internal_fixture', $1, $2, $3, 1, $4::uuid, $5, $6, $7)`,
    [
      chain.commerceTokenHash, grant, tokenHash,
      meta.mutation ?? grantMutation(90000 + chain.seed), meta.keyHash ?? HEX_A,
      meta.digest ?? HEX_C, meta.context ?? HEX_D,
    ],
  );
}

function coreClaimOn(
  runner: Queryable,
  providerSessionHash: string,
  grantTokenHash: string,
  action: string,
  attempt: string,
  meta: CoreMeta = {},
) {
  return runner.query(
    `SELECT * FROM openarc_durable.claim_authorization_grant_core(
       'internal_fixture', $1, $2, $3, $4::uuid, $5::uuid, $6, $7, $8)`,
    [
      providerSessionHash, grantTokenHash, action, attempt,
      meta.mutation ?? grantMutation(91000), meta.keyHash ?? HEX_B,
      meta.digest ?? HEX_C, meta.context ?? HEX_D,
    ],
  );
}

function coreRevokeOn(
  runner: Queryable,
  humanSessionHash: string,
  organization: string,
  grant: string,
  meta: CoreMeta = {},
) {
  return runner.query(
    `SELECT * FROM openarc_durable.revoke_authorization_grant($1, $2, $3, $4::uuid, $5, $6, $7)`,
    [
      humanSessionHash, organization, grant,
      meta.mutation ?? grantMutation(92000), meta.keyHash ?? HEX_A,
      meta.digest ?? HEX_C, meta.context ?? HEX_D,
    ],
  );
}

// ---------------------------------------------------------------------------
// Assertion and observation helpers.
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function rawError(promise: Promise<unknown>): Promise<{ code?: string }> {
  try {
    await promise;
  } catch (error) {
    return error as { code?: string };
  }
  throw new Error('expected a rejection');
}

async function expectActionCode(promise: Promise<unknown>, code: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ControlActionStoreError);
    expect((error as ControlActionStoreError).code).toBe(code);
    return;
  }
  throw new Error(`expected ControlActionStoreError ${code}`);
}

async function expectGrantCode(promise: Promise<unknown>, code: string, label = ''): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ControlGrantStoreError);
    expect(`${label}${(error as ControlGrantStoreError).code}`).toBe(`${label}${code}`);
    return;
  }
  throw new Error(`expected ControlGrantStoreError ${code}`);
}

/** A tracked contender: `settled` flips only when the real promise settles, so
 *  a test can prove a loser genuinely could not decide while blocked. */
interface Contender<T> {
  readonly promise: Promise<T>;
  settled: boolean;
}

function track<T>(promise: Promise<T>): Contender<T> {
  const state: Contender<T> = { promise, settled: false };
  promise.then(
    () => { state.settled = true; },
    () => { state.settled = true; },
  );
  return state;
}

/**
 * NON-VACUITY PROBE. Waits until exactly `expected` distinct backends are
 * genuinely blocked on a heavyweight lock inside the named function, and
 * returns their pids. If the contention never happens this THROWS, so a race
 * can never pass by silently having run sequentially.
 */
async function observeBlockedBackends(
  functionName: string,
  expected: number,
  timeoutMs = 25_000,
): Promise<number[]> {
  const deadline = Date.now() + timeoutMs;
  let seen = 0;
  for (;;) {
    const result = await probe.query<{ pid: number }>(
      `SELECT a.pid
         FROM pg_stat_activity a
        WHERE a.datname = current_database()
          AND a.state = 'active'
          AND a.wait_event_type = 'Lock'
          AND a.query LIKE $1
        ORDER BY a.pid`,
      [`%${functionName}%`],
    );
    seen = result.rows.length;
    if (seen >= expected) return result.rows.map((row) => row.pid);
    if (Date.now() > deadline) {
      throw new Error(
        `non-vacuity failed: only ${seen} of ${expected} backends were observed blocked in ${functionName}`,
      );
    }
    await sleep(40);
  }
}

/**
 * NON-VACUITY PROBE, by pid. Waits until PostgreSQL itself reports `blockerPid`
 * as a lock blocker of `waiterPid`. This is independent of which statement the
 * waiter happens to be executing, so it cannot be fooled by a helper trigger
 * taking the lock a statement earlier than expected. It THROWS on timeout, so a
 * race can never pass by having quietly run sequentially.
 */
async function observeBlockedBy(
  waiterPid: number,
  blockerPid: number,
  timeoutMs = 25_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const result = await probe.query<{ blockers: number[]; wait_event_type: string | null }>(
      `SELECT pg_blocking_pids($1) AS blockers,
              (SELECT a.wait_event_type FROM pg_stat_activity a WHERE a.pid = $1) AS wait_event_type`,
      [waiterPid],
    );
    const row = result.rows[0];
    if (row !== undefined && row.blockers.includes(blockerPid) && row.wait_event_type === 'Lock') {
      return;
    }
    if (Date.now() > deadline) {
      throw new Error(
        `non-vacuity failed: backend ${waiterPid} was never observed blocked by ${blockerPid}`,
      );
    }
    await sleep(40);
  }
}

/**
 * The blocking edges as PostgreSQL itself reports them. Row-lock waiters queue
 * behind each other, so the union over every waiter is the honest evidence that
 * a particular backend is the root of the contention.
 */
async function blockingPidsFor(pids: readonly number[]): Promise<number[]> {
  const result = await probe.query<{ blocked_by: number[] }>(
    'SELECT pg_blocking_pids(p) AS blocked_by FROM unnest($1::int[]) AS p',
    [pids],
  );
  const union = new Set<number>();
  for (const row of result.rows) for (const pid of row.blocked_by ?? []) union.add(pid);
  return [...union];
}

function pidOf(client: unknown): number {
  const value = (client as { processID?: number }).processID;
  if (typeof value !== 'number') throw new Error('expected a real backend pid');
  return value;
}

/**
 * A race harness that makes leakage impossible: every dedicated connection is
 * rolled back and DESTROYED and every dedicated pool is ended in `finally`,
 * even when an assertion throws mid-race. A leaked open transaction would
 * otherwise block the next fixture reset instead of failing this test.
 */
interface RaceHarness {
  /** A dedicated real connection, outside every shared pool. */
  connect(role?: 'migrator' | 'admin'): Promise<TrackedClient>;
}

interface TrackedClient {
  query: (text: string, values?: unknown[]) => Promise<{ rows: Record<string, unknown>[] }>;
  readonly pid: number;
}

async function withRace<T>(run: (harness: RaceHarness) => Promise<T>): Promise<T> {
  const pools: Pool[] = [];
  const pids: number[] = [];
  const clients: { release: (destroy?: boolean) => void; query: TrackedClient['query'] }[] = [];
  const harness: RaceHarness = {
    async connect(role: 'migrator' | 'admin' = 'migrator'): Promise<TrackedClient> {
      const pool = role === 'migrator' ? createDatabasePool(migratorUrl()) : adminPool();
      // The cleanup below terminates these backends on purpose; swallow the
      // resulting FATAL notice so it cannot surface as an unhandled error.
      pool.on('error', () => {});
      pools.push(pool as unknown as Pool);
      const client = await (pool as unknown as Pool).connect();
      client.on('error', () => {});
      const tracked = {
        query: ((text: string, values?: unknown[]) =>
          client.query(text, values) as unknown as Promise<{ rows: Record<string, unknown>[] }>),
        release: (destroy?: boolean) => { client.release(destroy); },
      };
      clients.push(tracked);
      const pid = pidOf(client);
      pids.push(pid);
      return { query: tracked.query, pid };
    },
  };
  try {
    return await run(harness);
  } finally {
    // Terminate every dedicated backend FIRST. A contender may still be parked
    // on a lock, and a polite ROLLBACK would queue behind it forever; a leaked
    // open transaction would then block the next fixture reset instead of
    // failing this test.
    for (const pid of pids) {
      await probe.query('SELECT pg_terminate_backend($1)', [pid]).catch(() => {});
    }
    for (const client of clients) client.release(true);
    await Promise.all(pools.map((pool) => pool.end().catch(() => {})));
  }
}

/** Swallow a contender promise so an assertion failure cannot leave it unhandled. */
function quiet(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    (value) => value,
    (error) => error,
  );
}

/** Full durable snapshot across BOTH the action and the grant surfaces. */
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
        'grants', (SELECT coalesce(jsonb_agg(to_jsonb(g) ORDER BY g.grant_id), '[]'::jsonb)
                      FROM openarc_durable.authorization_grants g),
        'tokens', (SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.grant_id, t.generation), '[]'::jsonb)
                      FROM openarc_durable.authorization_grant_tokens t),
        'claims', (SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY c.grant_id), '[]'::jsonb)
                      FROM openarc_durable.authorization_grant_claims c),
        'idempotency', (SELECT coalesce(jsonb_agg(to_jsonb(i) ORDER BY i.operation, i.key_hash), '[]'::jsonb)
                      FROM openarc_durable.idempotency_records i
                     WHERE i.operation LIKE 'control.commerce_action%'
                        OR i.operation LIKE 'control.grant.%'),
        'audit', (SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.mutation_id), '[]'::jsonb)
                      FROM openarc_durable.audit_events e
                     WHERE e.operation LIKE 'control.commerce_action%'
                        OR e.operation LIKE 'control.grant.%'),
        'outbox', (SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY o.mutation_id), '[]'::jsonb)
                      FROM openarc_durable.outbox_events o
                     WHERE o.event_type LIKE 'control.commerce_action%'
                        OR o.event_type LIKE 'control.grant.%')
      ) AS snapshot`,
  );
  return result.rows[0]?.snapshot;
}

/** Exact integer exposure arithmetic, computed in SQL numerics and returned as
 *  canonical decimal strings. Nothing passes through JS floating point. */
async function exposureTotals(org: string, subject: string): Promise<{
  unresolved: string;
  committed: string;
  released: string;
  heldCount: number;
  maxDebit: string;
}> {
  const result = await admin.query<{
    unresolved: string; committed: string; released: string; held_count: number; max_debit: string;
  }>(
    `SELECT
       (SELECT coalesce(sum(r.debit_atomic::numeric), 0)::text
          FROM openarc_durable.budget_reservations r
         WHERE r.organization_id = $1 AND r.subject_agent_id = $2
           AND r.status IN ('held', 'claimed', 'unknown')) AS unresolved,
       (SELECT coalesce(sum(b.amount_atomic::numeric), 0)::text
          FROM openarc_durable.budget_events b
         WHERE b.organization_id = $1 AND b.subject_agent_id = $2
           AND b.event_kind = 'committed') AS committed,
       (SELECT coalesce(sum(b.amount_atomic::numeric), 0)::text
          FROM openarc_durable.budget_events b
         WHERE b.organization_id = $1 AND b.subject_agent_id = $2
           AND b.event_kind = 'released') AS released,
       (SELECT count(*)::int FROM openarc_durable.budget_reservations r
         WHERE r.organization_id = $1 AND r.subject_agent_id = $2 AND r.status = 'held') AS held_count,
       (SELECT coalesce(max(r.debit_atomic::numeric), 0)::text
          FROM openarc_durable.budget_reservations r
         WHERE r.organization_id = $1 AND r.subject_agent_id = $2) AS max_debit`,
    [org, subject],
  );
  const row = result.rows[0]!;
  return {
    unresolved: row.unresolved,
    committed: row.committed,
    released: row.released,
    heldCount: row.held_count,
    maxDebit: row.max_debit,
  };
}

async function counts(): Promise<Record<string, number>> {
  const result = await admin.query<Record<string, number>>(
    `SELECT (SELECT count(*)::int FROM openarc_durable.commerce_actions) AS actions,
            (SELECT count(*)::int FROM openarc_durable.budget_reservations) AS reservations,
            (SELECT count(*)::int FROM openarc_durable.budget_events) AS events,
            (SELECT count(*)::int FROM openarc_durable.budget_events WHERE event_kind = 'released') AS released,
            (SELECT count(*)::int FROM openarc_durable.authorization_grants) AS grants,
            (SELECT count(*)::int FROM openarc_durable.authorization_grant_tokens) AS tokens,
            (SELECT count(*)::int FROM openarc_durable.authorization_grant_tokens WHERE retired_at IS NULL) AS live_tokens,
            (SELECT count(*)::int FROM openarc_durable.authorization_grant_claims) AS claims,
            (SELECT count(*)::int FROM openarc_durable.idempotency_records
              WHERE operation LIKE 'control.commerce_action%'
                 OR operation LIKE 'control.grant.%') AS idem`,
  );
  return result.rows[0]!;
}

async function actionRow(action: string): Promise<Record<string, unknown> | undefined> {
  const result = await admin.query<Record<string, unknown>>(
    'SELECT * FROM openarc_durable.commerce_actions WHERE action_id = $1',
    [action],
  );
  return result.rows[0];
}

async function grantRow(grant: string): Promise<Record<string, unknown> | undefined> {
  const result = await admin.query<Record<string, unknown>>(
    'SELECT * FROM openarc_durable.authorization_grants WHERE grant_id = $1',
    [grant],
  );
  return result.rows[0];
}

async function reservationRow(action: string): Promise<Record<string, unknown> | undefined> {
  const result = await admin.query<Record<string, unknown>>(
    'SELECT * FROM openarc_durable.budget_reservations WHERE action_id = $1',
    [action],
  );
  return result.rows[0];
}

/** An issued, unclaimed grant over a real reserved cross-organization action. */
interface Issued {
  readonly chain: Chain;
  readonly action: string;
  readonly grant: string;
  readonly tokenHash: string;
  readonly providerSessionHash: string;
}

async function seedIssuedGrant(
  buyerSeed: number,
  sellerSeed: number,
  overrides: { validForSeconds?: number } = {},
): Promise<Issued> {
  const chain = await seedCrossChain(buyerSeed, sellerSeed);
  const requirement = await seedRequirement(chain, buyerSeed, overrides);
  const action = actionId(buyerSeed);
  await coreAuthorize(chain, requirement, action);
  const tokenHash = digestCommerceGrantToken(rawGrantToken(buyerSeed));
  const issued = await coreIssue(chain, action, tokenHash);
  const providerSessionHash = await seedProviderSession(chain.seller, chain.provider, sellerSeed);
  return {
    chain,
    action,
    grant: issued.rows[0]!['out_grant_id'] as string,
    tokenHash,
    providerSessionHash,
  };
}

// ===========================================================================
// RACE 1 - Parallel authorization against one budget.
// ===========================================================================

describe('race 1: parallel authorization against one budget', () => {
  it('never oversubscribes one exposure cap under three genuinely blocked authorizations', async () => {
    // Cap 2,500,000 atomic; three concurrent 1,000,000 debits. At most two can
    // ever be admitted; a third would put unresolved exposure at 3,000,000.
    const chain = await seedCrossChain(10, 1010, {
      rollingLimit: '2500000',
      perActionLimit: '1200000',
    });
    const requirements = [
      await seedRequirement(chain, 101),
      await seedRequirement(chain, 102),
      await seedRequirement(chain, 103),
    ];
    const targets = [actionId(101), actionId(102), actionId(103)];

    const settled = await withRace(async (harness) => {
      const barrier = await harness.connect('admin');
      // The barrier holds the buyer organization row, which EVERY authorization
      // must lock, so all three contenders are pinned at the same point.
      await barrier.query('BEGIN');
      await barrier.query(
        'SELECT organization_id FROM openarc_tenant.organizations WHERE organization_id = $1 FOR UPDATE',
        [chain.buyer.org],
      );
      const contenders: Contender<unknown>[] = [];
      for (let index = 0; index < 3; index += 1) {
        const connection = await harness.connect();
        contenders.push(
          track(
            coreAuthorizeOn(connection, chain, requirements[index]!, targets[index]!, {
              mutation: actionMutation(1010 + index),
              keyHash: keyHashOf(1010 + index),
            }),
          ),
        );
      }
      const all = Promise.allSettled(contenders.map((entry) => entry.promise));
      void quiet(all);
      // NON-VACUITY: all three backends are observed blocked on a heavyweight
      // lock inside the authorize core, none of them can decide, and PostgreSQL
      // itself names the barrier backend as the root blocker.
      const blocked = await observeBlockedBackends('authorize_commerce_action_core', 3);
      expect(blocked).toHaveLength(3);
      expect(contenders.map((entry) => entry.settled)).toEqual([false, false, false]);
      expect(await blockingPidsFor(blocked)).toContain(barrier.pid);
      await barrier.query('ROLLBACK');
      return all;
    });

    const fulfilled = settled.filter((entry) => entry.status === 'fulfilled');
    const rejected = settled.filter((entry) => entry.status === 'rejected');
    expect(fulfilled).toHaveLength(2);
    expect(rejected).toHaveLength(1);
    for (const entry of rejected) {
      expect((entry.reason as { code?: string }).code).toBe('P0D12');
    }

    // Committed state, exact integers: two reservations of exactly 1,000,000.
    const totals = await exposureTotals(chain.buyer.org, chain.agent);
    expect(totals.unresolved).toBe('2000000');
    expect(totals.committed).toBe('0');
    expect(totals.released).toBe('0');
    expect(totals.heldCount).toBe(2);
    // No single reservation, and no total, exceeds the cap.
    expect(BigInt(totals.maxDebit) <= 2500000n).toBe(true);
    expect(BigInt(totals.unresolved) <= 2500000n).toBe(true);
    expect(await counts()).toMatchObject({ actions: 2, reservations: 2, events: 0 });

    // The loser left NO partial rows anywhere.
    const committedActions = await admin.query<{ action_id: string }>(
      'SELECT action_id FROM openarc_durable.commerce_actions ORDER BY action_id',
    );
    const survivors = new Set(committedActions.rows.map((row) => row.action_id));
    const losers = targets.filter((target) => !survivors.has(target));
    expect(losers).toHaveLength(1);
    const loser = losers[0]!;
    expect(await actionRow(loser)).toBeUndefined();
    expect(await reservationRow(loser)).toBeUndefined();
    const loserIndex = targets.indexOf(loser);
    const residue = await admin.query<{ idem: number; audit: number; outbox: number }>(
      `SELECT (SELECT count(*)::int FROM openarc_durable.idempotency_records i
                WHERE i.key_hash = $1 OR i.mutation_id = $2::uuid) AS idem,
              (SELECT count(*)::int FROM openarc_durable.audit_events e
                WHERE e.mutation_id = $2::uuid OR e.resource_id = $3) AS audit,
              (SELECT count(*)::int FROM openarc_durable.outbox_events o
                WHERE o.mutation_id = $2::uuid OR o.resource_id = $3) AS outbox`,
      [keyHashOf(1010 + loserIndex), actionMutation(1010 + loserIndex), loser],
    );
    expect(residue.rows[0]).toMatchObject({ idem: 0, audit: 0, outbox: 0 });
  }, 120000);

  it('denies an authorization that waited behind a committing sibling on the same cap', async () => {
    // A two-party version with a deterministic winner, so the loser's exact
    // failure and the exact surviving total are both pinned.
    const chain = await seedCrossChain(11, 1011, {
      rollingLimit: '1500000',
      perActionLimit: '1200000',
    });
    const first = await seedRequirement(chain, 111);
    const second = await seedRequirement(chain, 112);
    const winnerAction = actionId(111);
    const loserAction = actionId(112);

    const outcome = await withRace(async (harness) => {
      const holder = await harness.connect();
      const challenger = await harness.connect();
      await holder.query('BEGIN');
      const won = await coreAuthorizeOn(holder, chain, first, winnerAction, {
        mutation: actionMutation(1111),
        keyHash: keyHashOf(1111),
      });
      expect(won.rows[0]).toMatchObject({
        out_status: 'reserved_not_granted',
        out_debit_atomic: '1000000',
      });
      const loser = track(
        coreAuthorizeOn(challenger, chain, second, loserAction, {
          mutation: actionMutation(1112),
          keyHash: keyHashOf(1112),
        }),
      );
      const result = quiet(loser.promise);
      // NON-VACUITY: the loser is blocked by the still-open winner transaction.
      // NON-VACUITY: PostgreSQL itself names the blocker, the waiter is
      // parked inside the named core, and it provably cannot decide yet.
      await observeBlockedBy(challenger.pid, holder.pid);
      expect(loser.settled).toBe(false);
      expect(await observeBlockedBackends('authorize_commerce_action_core', 1)).toEqual([challenger.pid]);
      await holder.query('COMMIT');
      return result;
    });

    expect((outcome as { code?: string }).code).toBe('P0D12');

    const totals = await exposureTotals(chain.buyer.org, chain.agent);
    expect(totals.unresolved).toBe('1000000');
    expect(totals.heldCount).toBe(1);
    expect(await actionRow(loserAction)).toBeUndefined();
    expect(await reservationRow(loserAction)).toBeUndefined();
    expect((await actionRow(winnerAction))!['status']).toBe('reserved_not_granted');
    expect(await counts()).toMatchObject({ actions: 1, reservations: 1 });
  }, 120000);
});

// ===========================================================================
// RACE 2 - Cross-principal replay.
// ===========================================================================

/** A SECOND subject agent, policy and commerce session inside the SAME buyer
 *  organization, so a replay can be attempted across the agent axis. */
async function seedSiblingAgentSession(chain: Chain, seed: number): Promise<{
  agent: string;
  policy: string;
  commerceTokenHash: string;
}> {
  const agent = await seedAgent(seed, chain.buyer.org);
  const policy = await seedPolicy(chain.buyer.org, agent, seed, chain.provider);
  const agentSessionHash = await seedMachine(chain.buyer, seed, agent);
  const handoffHash = sha256(`handoff-sibling:${seed}`);
  const commerceTokenHash = sha256(`commerce-sibling:${seed}`);
  await commerce.issueCommerceSession(
    chain.buyer.hash, chain.buyer.org,
    { subjectAgentId: agent, policyId: policy, handoffHash, hashVersion: 1 },
    { idempotencyKey: key(120000 + seed), mutationId: mutationId(120000 + seed) },
  );
  await commerce.exchangeCommerceSession(
    agentSessionHash, handoffHash,
    { tokenHash: commerceTokenHash, hashVersion: 1 },
    { idempotencyKey: key(220000 + seed), mutationId: mutationId(220000 + seed) },
  );
  return { agent, policy, commerceTokenHash };
}

describe('race 2: cross-principal replay', () => {
  it('never returns another organization receipt for an identical replayed key', async () => {
    const victim = await seedCrossChain(20, 1020);
    const attacker = await seedCrossChain(21, 1021);
    const victimRequirement = await seedRequirement(victim, 201);
    const attackerRequirement = await seedRequirement(attacker, 202);
    const victimOnlyRequirement = await seedRequirement(victim, 203);
    const target = actionId(201);
    const attackerTarget = actionId(202);
    const victimOnlyAction = actionId(203);
    const sharedKeyHash = keyHashOf(2001);
    const sharedMutation = actionMutation(2001);
    const victimOnlyMutation = actionMutation(2003);

    const authorized = await coreAuthorize(victim, victimRequirement, target, {
      mutation: sharedMutation,
      keyHash: sharedKeyHash,
    });
    await coreAuthorize(victim, victimOnlyRequirement, victimOnlyAction, {
      mutation: victimOnlyMutation,
      keyHash: keyHashOf(2003),
    });
    expect(authorized.rows[0]).toMatchObject({
      out_replayed: false,
      out_organization_id: victim.buyer.org,
    });
    const victimAction = await actionRow(target);
    expect(victimAction!['organization_id']).toBe(victim.buyer.org);

    // The attacker replays the EXACT key, mutation and digest, but authenticates
    // with its OWN commerce token.
    const replayed = await coreAuthorizeOn(
      migrator, attacker, attackerRequirement, attackerTarget,
      {
        mutation: sharedMutation,
        keyHash: sharedKeyHash,
        digest: HEX_A,
        context: contextDigest(AUTHORIZE_SESSION_DOMAIN, attacker.commerceTokenHash),
      },
      attacker.commerceTokenHash,
    );
    // A brand new action in the attacker's OWN organization namespace, never
    // the victim's receipt and never `replayed`.
    expect(replayed.rows[0]).toMatchObject({
      out_replayed: false,
      out_organization_id: attacker.buyer.org,
      out_subject_agent_id: attacker.agent,
      out_action_id: attackerTarget,
    });
    expect(replayed.rows[0]!['out_committed_at']).not.toEqual(
      authorized.rows[0]!['out_committed_at'],
    );

    // The victim's committed row is byte-identical afterwards.
    const after = await admin.query<Record<string, unknown>>(
      'SELECT * FROM openarc_durable.commerce_actions WHERE organization_id = $1 AND action_id = $2',
      [victim.buyer.org, target],
    );
    expect(after.rows[0]).toEqual(victimAction);

    // Neither status reader crosses the organization boundary. A mutation id
    // the attacker never used is simply not found, even though it is a real
    // committed receipt one organization away.
    await actions.initialize();
    expect(await actions.getAgentMutationStatus(attacker.commerceTokenHash, victimOnlyMutation))
      .toEqual({ status: 'not_found' });
    expect(await actions.getHumanMutationStatus(attacker.buyer.hash, attacker.buyer.org, victimOnlyMutation))
      .toEqual({ status: 'not_found' });
    // Where the attacker DOES hold a same-numbered mutation of its own, the
    // reader returns the ATTACKER's resource and instant, never the victim's.
    const attackerOwn = await actions.getAgentMutationStatus(attacker.commerceTokenHash, sharedMutation);
    expect(attackerOwn).toMatchObject({
      status: 'committed',
      receipt: { resourceId: attackerTarget },
    });
    expect(attackerOwn.status === 'committed' ? attackerOwn.receipt.committedAt : null)
      .not.toBe(authorized.rows[0]!['out_committed_at']);
    // POSITIVE CONTROL: the rightful principal does recover its own receipt, so
    // the denials above are not vacuous.
    const own = await actions.getAgentMutationStatus(victim.commerceTokenHash, victimOnlyMutation);
    expect(own).toMatchObject({
      status: 'committed',
      receipt: { operation: 'control.commerce_action.authorize', resourceId: victimOnlyAction },
    });
  }, 120000);

  it('refuses a same-organization replay from a different session, agent or body', async () => {
    const chain = await seedCrossChain(22, 1022);
    const requirement = await seedRequirement(chain, 221);
    const target = actionId(221);
    const sharedKeyHash = keyHashOf(2201);
    const sharedMutation = actionMutation(2201);
    await coreAuthorize(chain, requirement, target, {
      mutation: sharedMutation,
      keyHash: sharedKeyHash,
    });
    const settled = await durableSnapshot();

    // Axis: a SECOND live commerce session of the SAME buyer, agent and policy.
    const secondSession = await seedSecondCommerceSession(chain, 222);
    const secondRequirement = await seedRequirement(chain, 222);
    const fromSecondSession = await rawError(
      coreAuthorizeOn(
        migrator, chain, secondRequirement, actionId(222),
        {
          mutation: sharedMutation,
          keyHash: sharedKeyHash,
          context: contextDigest(AUTHORIZE_SESSION_DOMAIN, secondSession),
        },
        secondSession,
      ),
    );
    expect(fromSecondSession.code).toBe('P0D01');

    // Axis: a DIFFERENT subject agent in the same organization.
    const sibling = await seedSiblingAgentSession(chain, 223);
    const siblingRequirement = await seedRequirement(chain, 223);
    const fromSibling = await rawError(
      coreAuthorizeOn(
        migrator, chain, siblingRequirement, actionId(223),
        {
          mutation: sharedMutation,
          keyHash: sharedKeyHash,
          context: contextDigest(AUTHORIZE_SESSION_DOMAIN, sibling.commerceTokenHash),
        },
        sibling.commerceTokenHash,
      ),
    );
    expect(fromSibling.code).toBe('P0D01');

    // Axis: the same principal and session but a DIFFERENT logical body.
    const differentBody = await rawError(
      coreAuthorize(chain, requirement, target, {
        mutation: sharedMutation,
        keyHash: sharedKeyHash,
        digest: HEX_B,
      }),
    );
    expect(differentBody.code).toBe('P0D01');

    // Axis: the same key but a different mutation id.
    const differentMutation = await rawError(
      coreAuthorize(chain, requirement, target, {
        mutation: actionMutation(2202),
        keyHash: sharedKeyHash,
      }),
    );
    expect(differentMutation.code).toBe('P0D01');

    // POSITIVE CONTROL: the exact original request still replays cleanly.
    const exact = await coreAuthorize(chain, requirement, target, {
      mutation: sharedMutation,
      keyHash: sharedKeyHash,
    });
    expect(exact.rows[0]).toMatchObject({ out_replayed: true, out_action_id: target });

    // Not one of the four cross-principal attempts changed committed state.
    expect(await durableSnapshot()).toEqual(settled);
    expect(await counts()).toMatchObject({ actions: 1, reservations: 1 });
  }, 120000);

  it('refuses a grant claim replayed from a different session of the same provider', async () => {
    const issued = await seedIssuedGrant(23, 1023);
    const attempt = attemptOf(231);
    const claimed = await coreClaimOn(
      migrator, issued.providerSessionHash, issued.tokenHash, issued.action, attempt,
      { mutation: grantMutation(2301), keyHash: keyHashOf(2301), context: HEX_D },
    );
    expect(claimed.rows[0]).toMatchObject({ out_replayed: false, out_status: 'claimed' });
    const settled = await durableSnapshot();

    // A NEW valid session for the SAME provider replays the exact key, mutation
    // and attempt. Its session-context digest differs, so it is a conflict and
    // never a second claim or a re-disclosed receipt.
    const second = await seedExtraProviderSession(issued.chain.seller, issued.chain.provider, 231);
    const replayed = await rawError(
      coreClaimOn(
        migrator, second, issued.tokenHash, issued.action, attempt,
        { mutation: grantMutation(2301), keyHash: keyHashOf(2301), context: HEX_A },
      ),
    );
    expect(replayed.code).toBeTruthy();
    expect(['P0D01', 'P0D14', '42501']).toContain(replayed.code);
    expect(await durableSnapshot()).toEqual(settled);
    expect(await counts()).toMatchObject({ claims: 1 });

    // POSITIVE CONTROL: the ORIGINAL session and context still replay exactly.
    const exact = await coreClaimOn(
      migrator, issued.providerSessionHash, issued.tokenHash, issued.action, attempt,
      { mutation: grantMutation(2301), keyHash: keyHashOf(2301), context: HEX_D },
    );
    expect(exact.rows[0]).toMatchObject({ out_replayed: true, out_attempt_id: attempt });
    expect(await counts()).toMatchObject({ claims: 1 });
  }, 120000);
});

// ===========================================================================
// RACE 8 - Concurrent claim.
// ===========================================================================

describe('race 8: concurrent claim', () => {
  it('elects exactly one winner when two sessions of the same provider race one grant', async () => {
    const issued = await seedIssuedGrant(80, 1080);
    const second = await seedExtraProviderSession(issued.chain.seller, issued.chain.provider, 801);

    const outcome = await withRace(async (harness) => {
      const holder = await harness.connect();
      const challenger = await harness.connect();
      await holder.query('BEGIN');
      const winner = await coreClaimOn(
        holder, issued.providerSessionHash, issued.tokenHash, issued.action, attemptOf(801),
        { mutation: grantMutation(8001), keyHash: keyHashOf(8001) },
      );
      expect(winner.rows[0]).toMatchObject({ out_status: 'claimed', out_attempt_id: attemptOf(801) });
      const loser = track(
        coreClaimOn(
          challenger, second, issued.tokenHash, issued.action, attemptOf(802),
          { mutation: grantMutation(8002), keyHash: keyHashOf(8002) },
        ),
      );
      const result = quiet(loser.promise);
      // NON-VACUITY: the second provider session is genuinely blocked on the
      // grant chain held by the first, and cannot decide until it commits.
      // NON-VACUITY: PostgreSQL itself names the blocker, the waiter is
      // parked inside the named core, and it provably cannot decide yet.
      await observeBlockedBy(challenger.pid, holder.pid);
      expect(loser.settled).toBe(false);
      expect(await observeBlockedBackends('claim_authorization_grant_core', 1)).toEqual([challenger.pid]);
      await holder.query('COMMIT');
      return result;
    });

    expect((outcome as { code?: string }).code).toBe('P0D14');
    const claims = await admin.query<{ attempt_id: string; provider_session_id: string }>(
      'SELECT attempt_id::text AS attempt_id, provider_session_id::text AS provider_session_id FROM openarc_durable.authorization_grant_claims',
    );
    expect(claims.rows).toHaveLength(1);
    expect(claims.rows[0]!.attempt_id).toBe(attemptOf(801));
    expect((await grantRow(issued.grant))!['status']).toBe('claimed');
    expect((await reservationRow(issued.action))!['status']).toBe('claimed');
    // Exposure is still held exactly once; a lost claim never doubles it.
    const totals = await exposureTotals(issued.chain.buyer.org, issued.chain.agent);
    expect(totals.unresolved).toBe('1000000');
    expect(totals.released).toBe('0');
  }, 120000);

  it('elects exactly one winner when the same provider session races itself on one attempt', async () => {
    const issued = await seedIssuedGrant(81, 1081);
    const attempt = attemptOf(811);

    const outcome = await withRace(async (harness) => {
      const holder = await harness.connect();
      const challenger = await harness.connect();
      await holder.query('BEGIN');
      await coreClaimOn(
        holder, issued.providerSessionHash, issued.tokenHash, issued.action, attempt,
        { mutation: grantMutation(8101), keyHash: keyHashOf(8101) },
      );
      // The SAME session and the SAME attempt, but a different idempotency key
      // and mutation: a retry that must never become a second claim.
      const loser = track(
        coreClaimOn(
          challenger, issued.providerSessionHash, issued.tokenHash, issued.action, attempt,
          { mutation: grantMutation(8102), keyHash: keyHashOf(8102) },
        ),
      );
      const result = quiet(loser.promise);
      // NON-VACUITY: PostgreSQL itself names the blocker, the waiter is
      // parked inside the named core, and it provably cannot decide yet.
      await observeBlockedBy(challenger.pid, holder.pid);
      expect(loser.settled).toBe(false);
      expect(await observeBlockedBackends('claim_authorization_grant_core', 1)).toEqual([challenger.pid]);
      await holder.query('COMMIT');
      return result;
    });

    expect((outcome as { code?: string }).code).toBe('P0D14');
    expect(await counts()).toMatchObject({ claims: 1 });
  }, 120000);

  it('never lets one provider attempt id claim two different grants', async () => {
    const first = await seedIssuedGrant(82, 1082);
    // A SECOND reserved action and grant for the SAME buyer, provider and
    // listing, so only the attempt-id uniqueness stands between them.
    const secondRequirement = await seedRequirement(first.chain, 821);
    const secondAction = actionId(821);
    await coreAuthorize(first.chain, secondRequirement, secondAction, {
      mutation: actionMutation(8201),
      keyHash: keyHashOf(8201),
    });
    const secondTokenHash = digestCommerceGrantToken(rawGrantToken(821));
    const secondIssued = await coreIssue(first.chain, secondAction, secondTokenHash, {
      mutation: grantMutation(8201),
      keyHash: keyHashOf(8202),
    });
    const secondGrant = secondIssued.rows[0]!['out_grant_id'] as string;
    expect(secondGrant).not.toBe(first.grant);

    const attempt = attemptOf(821);
    await coreClaimOn(
      migrator, first.providerSessionHash, first.tokenHash, first.action, attempt,
      { mutation: grantMutation(8203), keyHash: keyHashOf(8203) },
    );
    const settled = await durableSnapshot();
    const reused = await rawError(
      coreClaimOn(
        migrator, first.providerSessionHash, secondTokenHash, secondAction, attempt,
        { mutation: grantMutation(8204), keyHash: keyHashOf(8204) },
      ),
    );
    expect(reused.code).toBe('23505');
    expect(await durableSnapshot()).toEqual(settled);
    expect(await counts()).toMatchObject({ claims: 1 });
    expect((await grantRow(secondGrant))!['status']).toBe('issued');
    expect((await reservationRow(secondAction))!['status']).toBe('held');

    // POSITIVE CONTROL: a FRESH attempt id claims the second grant normally.
    const fresh = await coreClaimOn(
      migrator, first.providerSessionHash, secondTokenHash, secondAction, attemptOf(822),
      { mutation: grantMutation(8205), keyHash: keyHashOf(8205) },
    );
    expect(fresh.rows[0]).toMatchObject({ out_status: 'claimed' });
    expect(await counts()).toMatchObject({ claims: 2 });
  }, 120000);
});

// ===========================================================================
// RACE 4 - Post-claim expiry and revocation.
// ===========================================================================

/** Blocks until PostgreSQL's own clock has passed the grant expiry, and returns
 *  the proof that it really has. Nothing is mutated to fake the elapse. */
async function awaitGrantExpiry(grant: string, timeoutMs = 20_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const result = await admin.query<{ expired: boolean }>(
      `SELECT clock_timestamp() > g.expires_at AS expired
         FROM openarc_durable.authorization_grants g WHERE g.grant_id = $1`,
      [grant],
    );
    if (result.rows[0]?.expired === true) return;
    if (Date.now() > deadline) throw new Error('grant never reached its expiry within the bound');
    await sleep(100);
  }
}

describe('race 4: post-claim expiry and revocation', () => {
  it('releases nothing when a revoke loses the race to a committing claim', async () => {
    const issued = await seedIssuedGrant(40, 1040);
    await grants.initialize();

    const outcome = await withRace(async (harness) => {
      const claimer = await harness.connect();
      await claimer.query('BEGIN');
      await coreClaimOn(
        claimer, issued.providerSessionHash, issued.tokenHash, issued.action, attemptOf(401),
        { mutation: grantMutation(4001), keyHash: keyHashOf(4001) },
      );
      // The buyer tries to revoke WHILE the claim transaction is still open, so
      // the revoke can only ever observe the post-claim state.
      const revoker = await harness.connect();
      const revoke = track(
        coreRevokeOn(revoker, issued.chain.buyer.hash, issued.chain.buyer.org, issued.grant, {
          mutation: grantMutation(4002),
          keyHash: keyHashOf(4002),
        }),
      );
      const result = quiet(revoke.promise);
      // NON-VACUITY: the revoke is genuinely blocked behind the open claim.
      // NON-VACUITY: PostgreSQL itself names the blocker, the waiter is
      // parked inside the named core, and it provably cannot decide yet.
      await observeBlockedBy(revoker.pid, claimer.pid);
      expect(revoke.settled).toBe(false);
      expect(await observeBlockedBackends('revoke_authorization_grant', 1)).toEqual([revoker.pid]);
      await claimer.query('COMMIT');
      return result;
    });

    const rows = (outcome as { rows?: Record<string, unknown>[] }).rows;
    expect(rows).toBeDefined();
    expect(rows![0]).toMatchObject({
      out_released: false,
      out_status: 'revoked',
      out_action_status: 'grant_issued',
      out_reservation_status: 'claimed',
    });
    expect(rows![0]!['out_claimed_at']).not.toBeNull();

    // The claim fact and the held exposure both survive the revocation.
    expect(await counts()).toMatchObject({ claims: 1, released: 0 });
    expect((await reservationRow(issued.action))!['status']).toBe('claimed');
    expect((await actionRow(issued.action))!['status']).toBe('grant_issued');
    const totals = await exposureTotals(issued.chain.buyer.org, issued.chain.agent);
    expect(totals.unresolved).toBe('1000000');
    expect(totals.released).toBe('0');
    // The buyer projection keeps the claim instant under the revoked status.
    const projected = await grants.readGrant(
      issued.chain.buyer.hash, issued.chain.buyer.org, issued.grant,
    );
    expect(projected).toMatchObject({ status: 'revoked' });
    expect(projected?.claimedAt).not.toBeNull();
  }, 120000);

  it('releases nothing under every ordering of claim, expiry, revoke and repeat', async () => {
    // A deliberately short-lived grant so a REAL database clock expiry, not a
    // forged timestamp, follows the claim.
    const issued = await seedIssuedGrant(41, 1041, { validForSeconds: 5 });
    await grants.initialize();
    await coreClaimOn(
      migrator, issued.providerSessionHash, issued.tokenHash, issued.action, attemptOf(411),
      { mutation: grantMutation(4101), keyHash: keyHashOf(4101) },
    );
    expect(await counts()).toMatchObject({ claims: 1, released: 0 });

    // NON-VACUITY: the expiry genuinely elapsed on the database clock.
    await awaitGrantExpiry(issued.grant);
    const expiryProof = await admin.query<{ expired: boolean }>(
      `SELECT clock_timestamp() > g.expires_at AS expired
         FROM openarc_durable.authorization_grants g WHERE g.grant_id = $1`,
      [issued.grant],
    );
    expect(expiryProof.rows[0]?.expired).toBe(true);

    const beforeRevoke = await exposureTotals(issued.chain.buyer.org, issued.chain.agent);
    expect(beforeRevoke.unresolved).toBe('1000000');

    // Ordering: claim -> expire -> revoke. Expiry must not turn a claimed
    // reservation back into releasable exposure.
    const revoked = await grants.revokeGrant(
      issued.chain.buyer.hash, issued.chain.buyer.org, issued.grant,
      { idempotencyKey: key(4102), mutationId: grantMutation(4102) },
    );
    expect(revoked.released).toBe(false);
    expect(revoked.reservationStatus).toBe('claimed');
    expect(revoked.actionStatus).toBe('grant_issued');
    const afterRevoke = await durableSnapshot();

    // Ordering: ... -> revoke again with a FRESH key. It must release nothing.
    await expectGrantCode(
      grants.revokeGrant(issued.chain.buyer.hash, issued.chain.buyer.org, issued.grant,
        { idempotencyKey: key(4103), mutationId: grantMutation(4103) }),
      'CONTROL_GRANT_STORE_GRANT_CONFLICT',
    );
    expect(await durableSnapshot()).toEqual(afterRevoke);

    // Ordering: ... -> replay the ORIGINAL revoke key. A replay is a receipt,
    // never a second cleanup.
    const replayed = await grants.revokeGrant(
      issued.chain.buyer.hash, issued.chain.buyer.org, issued.grant,
      { idempotencyKey: key(4102), mutationId: grantMutation(4102) },
    );
    expect(replayed.replayed).toBe(true);
    expect(replayed.released).toBe(false);
    expect(await durableSnapshot()).toEqual(afterRevoke);

    // Exposure never moved through any of it.
    const totals = await exposureTotals(issued.chain.buyer.org, issued.chain.agent);
    expect(totals).toEqual(beforeRevoke);
    expect(await counts()).toMatchObject({ claims: 1, released: 0 });
    // The provider still recovers its claim through a NEW session of the same
    // provider: retirement alone is never evidence of nonpayment.
    const fresh = await seedExtraProviderSession(issued.chain.seller, issued.chain.provider, 411);
    expect(await grants.readProviderAttemptStatus(fresh, attemptOf(411)))
      .toMatchObject({ status: 'claimed', attemptId: attemptOf(411), grantRevoked: true });
  }, 120000);

  it('releases a never-claimed grant exactly once and never a second time', async () => {
    const issued = await seedIssuedGrant(42, 1042);
    await grants.initialize();
    const before = await exposureTotals(issued.chain.buyer.org, issued.chain.agent);
    expect(before.unresolved).toBe('1000000');

    const revoked = await grants.revokeGrant(
      issued.chain.buyer.hash, issued.chain.buyer.org, issued.grant,
      { idempotencyKey: key(4201), mutationId: grantMutation(4201) },
    );
    expect(revoked.released).toBe(true);
    const afterFirst = await durableSnapshot();
    const totals = await exposureTotals(issued.chain.buyer.org, issued.chain.agent);
    expect(totals.unresolved).toBe('0');
    expect(totals.released).toBe('1000000');
    expect(await counts()).toMatchObject({ released: 1, claims: 0 });

    // A second revoke with a fresh key, a replayed revoke, and a late claim on
    // the retired token all leave the single released event alone.
    await expectGrantCode(
      grants.revokeGrant(issued.chain.buyer.hash, issued.chain.buyer.org, issued.grant,
        { idempotencyKey: key(4202), mutationId: grantMutation(4202) }),
      'CONTROL_GRANT_STORE_GRANT_CONFLICT',
    );
    const lateClaim = await rawError(
      coreClaimOn(
        migrator, issued.providerSessionHash, issued.tokenHash, issued.action, attemptOf(421),
        { mutation: grantMutation(4203), keyHash: keyHashOf(4203) },
      ),
    );
    expect(lateClaim.code).toBe('42501');
    expect(await durableSnapshot()).toEqual(afterFirst);
    expect(await counts()).toMatchObject({ released: 1, claims: 0 });
    // Exactly one released budget event of exactly the reserved debit.
    const events = await admin.query<{ n: number; total: string }>(
      `SELECT count(*)::int AS n, coalesce(sum(amount_atomic::numeric), 0)::text AS total
         FROM openarc_durable.budget_events WHERE event_kind = 'released'`,
    );
    expect(events.rows[0]).toMatchObject({ n: 1, total: '1000000' });
  }, 120000);
});

// ===========================================================================
// RACE 7 - Token rotation races.
// ===========================================================================

describe('race 7: token rotation races', () => {
  it('refuses a replacement that lost the race to a committing claim', async () => {
    const issued = await seedIssuedGrant(70, 1070);
    const rotated = digestCommerceGrantToken(rawGrantToken(701));

    const outcome = await withRace(async (harness) => {
      const claimer = await harness.connect();
      await claimer.query('BEGIN');
      await coreClaimOn(
        claimer, issued.providerSessionHash, issued.tokenHash, issued.action, attemptOf(701),
        { mutation: grantMutation(7001), keyHash: keyHashOf(7001) },
      );
      const replacer = await harness.connect();
      const replace = track(
        coreReplaceOn(replacer, issued.chain, issued.grant, rotated, {
          mutation: grantMutation(7002),
          keyHash: keyHashOf(7002),
        }),
      );
      const result = quiet(replace.promise);
      // NON-VACUITY: the replacement is blocked behind the open claim.
      // NON-VACUITY: PostgreSQL itself names the blocker, the waiter is
      // parked inside the named core, and it provably cannot decide yet.
      await observeBlockedBy(replacer.pid, claimer.pid);
      expect(replace.settled).toBe(false);
      expect(await observeBlockedBackends('replace_authorization_grant_core', 1)).toEqual([replacer.pid]);
      await claimer.query('COMMIT');
      return result;
    });

    expect(['P0D14', 'P0D13']).toContain((outcome as { code?: string }).code);
    // The rotation left nothing behind: one generation, one live token, and the
    // new hash was never admitted.
    expect(await counts()).toMatchObject({ tokens: 1, live_tokens: 1, claims: 1 });
    expect((await grantRow(issued.grant))!['current_generation']).toBe(1);
    const minted = await admin.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM openarc_durable.authorization_grant_tokens WHERE token_hash = $1',
      [rotated],
    );
    expect(minted.rows[0]!.n).toBe(0);
  }, 120000);

  it('never lets a retired generation become authority again', async () => {
    const issued = await seedIssuedGrant(71, 1071);
    const second = digestCommerceGrantToken(rawGrantToken(711));
    await coreReplaceOn(migrator, issued.chain, issued.grant, second, {
      mutation: grantMutation(7101),
      keyHash: keyHashOf(7101),
    });
    expect((await grantRow(issued.grant))!['current_generation']).toBe(2);

    // The retired generation-1 hash is dead for introspection AND for claim.
    const settled = await durableSnapshot();
    expect((await rawError(migrator.query(
      `SELECT * FROM openarc_durable.introspect_authorization_grant_core('internal_fixture', $1, $2)`,
      [issued.providerSessionHash, issued.tokenHash],
    ))).code).toBe('42501');
    expect((await rawError(coreClaimOn(
      migrator, issued.providerSessionHash, issued.tokenHash, issued.action, attemptOf(711),
      { mutation: grantMutation(7102), keyHash: keyHashOf(7102) },
    ))).code).toBe('42501');
    expect(await durableSnapshot()).toEqual(settled);
    expect(await counts()).toMatchObject({ claims: 0 });

    // POSITIVE CONTROL: the CURRENT generation claims normally, so the two
    // denials above were caused by retirement and not by a broken fixture.
    const claimed = await coreClaimOn(
      migrator, issued.providerSessionHash, second, issued.action, attemptOf(712),
      { mutation: grantMutation(7103), keyHash: keyHashOf(7103) },
    );
    expect(claimed.rows[0]).toMatchObject({ out_status: 'claimed' });
    expect(await counts()).toMatchObject({ claims: 1, tokens: 2, live_tokens: 1 });
  }, 120000);

  it('admits exactly one of two replacements racing on the same new token hash', async () => {
    const issued = await seedIssuedGrant(72, 1072);
    const rotated = digestCommerceGrantToken(rawGrantToken(721));

    const outcome = await withRace(async (harness) => {
      const holder = await harness.connect();
      const challenger = await harness.connect();
      await holder.query('BEGIN');
      const winner = await coreReplaceOn(holder, issued.chain, issued.grant, rotated, {
        mutation: grantMutation(7201),
        keyHash: keyHashOf(7201),
      });
      expect(winner.rows[0]).toMatchObject({ out_generation: 2 });
      const loser = track(
        coreReplaceOn(challenger, issued.chain, issued.grant, rotated, {
          mutation: grantMutation(7202),
          keyHash: keyHashOf(7202),
        }),
      );
      const result = quiet(loser.promise);
      // NON-VACUITY: PostgreSQL itself names the blocker, the waiter is
      // parked inside the named core, and it provably cannot decide yet.
      await observeBlockedBy(challenger.pid, holder.pid);
      expect(loser.settled).toBe(false);
      expect(await observeBlockedBackends('replace_authorization_grant_core', 1)).toEqual([challenger.pid]);
      await holder.query('COMMIT');
      return result;
    });

    // Exactly one rotation survives: a duplicate hash can never be minted twice.
    expect((outcome as { code?: string }).code).toBe('23505');
    expect((await grantRow(issued.grant))!['current_generation']).toBe(2);
    expect(await counts()).toMatchObject({ tokens: 2, live_tokens: 1 });
    const hashes = await admin.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM openarc_durable.authorization_grant_tokens WHERE token_hash = $1',
      [rotated],
    );
    expect(hashes.rows[0]!.n).toBe(1);
  }, 120000);

  it('keeps generations strictly monotonic when two distinct rotations race', async () => {
    const issued = await seedIssuedGrant(73, 1073);
    const secondHash = digestCommerceGrantToken(rawGrantToken(731));
    const thirdHash = digestCommerceGrantToken(rawGrantToken(732));

    await withRace(async (harness) => {
      const holder = await harness.connect();
      const challenger = await harness.connect();
      await holder.query('BEGIN');
      await coreReplaceOn(holder, issued.chain, issued.grant, secondHash, {
        mutation: grantMutation(7301),
        keyHash: keyHashOf(7301),
      });
      const queued = track(
        coreReplaceOn(challenger, issued.chain, issued.grant, thirdHash, {
          mutation: grantMutation(7302),
          keyHash: keyHashOf(7302),
        }),
      );
      const result = quiet(queued.promise);
      // NON-VACUITY: PostgreSQL itself names the blocker, the waiter is
      // parked inside the named core, and it provably cannot decide yet.
      await observeBlockedBy(challenger.pid, holder.pid);
      expect(queued.settled).toBe(false);
      expect(await observeBlockedBackends('replace_authorization_grant_core', 1)).toEqual([challenger.pid]);
      await holder.query('COMMIT');
      await result;
    });

    // Both rotations are legitimate, but the outcome is a single linear chain.
    expect((await grantRow(issued.grant))!['current_generation']).toBe(3);
    expect(await counts()).toMatchObject({ tokens: 3, live_tokens: 1 });
    const live = await admin.query<{ token_hash: string; generation: number }>(
      `SELECT token_hash, generation FROM openarc_durable.authorization_grant_tokens
        WHERE retired_at IS NULL`,
    );
    expect(live.rows).toHaveLength(1);
    expect(live.rows[0]).toMatchObject({ token_hash: thirdHash, generation: 3 });

    // Every superseded hash is permanently dead.
    for (const dead of [issued.tokenHash, secondHash]) {
      expect((await rawError(coreClaimOn(
        migrator, issued.providerSessionHash, dead, issued.action, attemptOf(733),
        { mutation: grantMutation(7303), keyHash: keyHashOf(7303) },
      ))).code).toBe('42501');
    }
    expect(await counts()).toMatchObject({ claims: 0 });
    // POSITIVE CONTROL: only the surviving generation is authority.
    const claimed = await coreClaimOn(
      migrator, issued.providerSessionHash, thirdHash, issued.action, attemptOf(734),
      { mutation: grantMutation(7304), keyHash: keyHashOf(7304) },
    );
    expect(claimed.rows[0]).toMatchObject({ out_status: 'claimed' });
  }, 120000);
});

// ===========================================================================
// RACE 5 - Lowered limit raced against an in-flight authorization.
// ===========================================================================

describe('race 5: a policy revision lowering the cap mid-flight', () => {
  it('never retroactively releases exposure and denies all new spending', async () => {
    const chain = await seedCrossChain(50, 1050, { rollingLimit: '5000000' });
    const first = await seedRequirement(chain, 501);
    const second = await seedRequirement(chain, 502);
    const third = await seedRequirement(chain, 503);
    await coreAuthorize(chain, first, actionId(501), {
      mutation: actionMutation(5001), keyHash: keyHashOf(5001),
    });

    // A REAL policy revision races an authorization that is already in flight.
    await withRace(async (harness) => {
      const authorizer = await harness.connect();
      const reviser = await harness.connect('admin');
      await authorizer.query('BEGIN');
      const inFlight = await coreAuthorizeOn(authorizer, chain, second, actionId(502), {
        mutation: actionMutation(5002), keyHash: keyHashOf(5002),
      });
      expect(inFlight.rows[0]).toMatchObject({ out_policy_revision: '1' });

      await reviser.query('BEGIN');
      const revision = track(
        (async () => {
          await reviser.query(
            `INSERT INTO openarc_tenant.budget_policy_versions
               (organization_id, policy_id, revision, subject_agent_id, network_id, asset,
                representation, decimals, per_action_limit, rolling_limit, rolling_window_seconds,
                fee_limit, allowed_provider_ids, allowed_listing_ids, approval_mode,
                approval_threshold, approval_separate_approver, expires_at, digest)
             VALUES ($1, $2, '2', $3, 'eip155:5042002', 'USDC', 'erc20', 6, '5000000', '1500000',
                     '3600', '0', ARRAY[$4]::text[], ARRAY[]::text[], 'none', NULL, false,
                     clock_timestamp() + interval '1 hour', 'sha256:' || repeat('b', 64))`,
            [chain.buyer.org, chain.policy, chain.agent, chain.provider],
          );
          await reviser.query(
            `UPDATE openarc_tenant.budget_policy_roots
                SET current_revision = '2', updated_at = clock_timestamp()
              WHERE organization_id = $1 AND policy_id = $2`,
            [chain.buyer.org, chain.policy],
          );
        })(),
      );
      void quiet(revision.promise);
      // NON-VACUITY: PostgreSQL itself names the in-flight authorization as the
      // blocker of the revision, and the revision provably cannot land yet.
      await observeBlockedBy(reviser.pid, authorizer.pid);
      expect(revision.settled).toBe(false);
      await authorizer.query('COMMIT');
      await revision.promise;
      await reviser.query('COMMIT');
    });

    // The in-flight authorization committed under the OLD pinned revision and
    // the lowered cap released nothing that was already reserved.
    const rows = await admin.query<{ action_id: string; policy_revision: string }>(
      'SELECT action_id, policy_revision FROM openarc_durable.commerce_actions ORDER BY action_id',
    );
    expect(rows.rows).toHaveLength(2);
    for (const row of rows.rows) expect(row.policy_revision).toBe('1');
    const totals = await exposureTotals(chain.buyer.org, chain.agent);
    expect(totals.unresolved).toBe('2000000');
    expect(totals.released).toBe('0');
    expect(totals.heldCount).toBe(2);

    // New spending under the lowered cap is denied, and the exposure view
    // reports the exact deficit with no available headroom.
    const denied = await rawError(
      coreAuthorize(chain, third, actionId(503), {
        mutation: actionMutation(5003), keyHash: keyHashOf(5003),
      }),
    );
    expect(denied.code).toBe('P0D12');
    const exposure = await migrator.query<Record<string, string | null>>(
      'SELECT * FROM openarc_durable.read_commerce_exposure($1, $2, $3, $4)',
      [chain.buyer.hash, chain.buyer.org, chain.agent, chain.policy],
    );
    expect(exposure.rows[0]).toMatchObject({
      out_policy_revision: '2',
      out_committed_atomic: '0',
      out_unresolved_atomic: '2000000',
      out_total_atomic: '2000000',
      out_available_atomic: '0',
      out_deficit_atomic: '500000',
    });
    expect(await counts()).toMatchObject({ actions: 2, reservations: 2 });
  }, 120000);

  it('denies an authorization that waited behind a committing revision', async () => {
    const chain = await seedCrossChain(51, 1051, { rollingLimit: '5000000' });
    const first = await seedRequirement(chain, 511);
    const second = await seedRequirement(chain, 512);
    await coreAuthorize(chain, first, actionId(511), {
      mutation: actionMutation(5101), keyHash: keyHashOf(5101),
    });
    const before = await durableSnapshot();

    const outcome = await withRace(async (harness) => {
      const reviser = await harness.connect('admin');
      const authorizer = await harness.connect();
      await reviser.query('BEGIN');
      await reviser.query(
        `INSERT INTO openarc_tenant.budget_policy_versions
           (organization_id, policy_id, revision, subject_agent_id, network_id, asset,
            representation, decimals, per_action_limit, rolling_limit, rolling_window_seconds,
            fee_limit, allowed_provider_ids, allowed_listing_ids, approval_mode,
            approval_threshold, approval_separate_approver, expires_at, digest)
         VALUES ($1, $2, '2', $3, 'eip155:5042002', 'USDC', 'erc20', 6, '5000000', '900000',
                 '3600', '0', ARRAY[$4]::text[], ARRAY[]::text[], 'none', NULL, false,
                 clock_timestamp() + interval '1 hour', 'sha256:' || repeat('b', 64))`,
        [chain.buyer.org, chain.policy, chain.agent, chain.provider],
      );
      await reviser.query(
        `UPDATE openarc_tenant.budget_policy_roots
            SET current_revision = '2', updated_at = clock_timestamp()
          WHERE organization_id = $1 AND policy_id = $2`,
        [chain.buyer.org, chain.policy],
      );
      const late = track(
        coreAuthorizeOn(authorizer, chain, second, actionId(512), {
          mutation: actionMutation(5102), keyHash: keyHashOf(5102),
        }),
      );
      const result = quiet(late.promise);
      // NON-VACUITY: the authorization is blocked on the policy root the
      // uncommitted revision holds.
      // NON-VACUITY: PostgreSQL itself names the blocker, the waiter is
      // parked inside the named core, and it provably cannot decide yet.
      await observeBlockedBy(authorizer.pid, reviser.pid);
      expect(late.settled).toBe(false);
      expect(await observeBlockedBackends('authorize_commerce_action_core', 1)).toEqual([authorizer.pid]);
      await reviser.query('COMMIT');
      return result;
    });

    // The waiter re-reads the lowered cap and fails closed, and the already
    // reserved 1,000,000 is untouched.
    expect((outcome as { code?: string }).code).toBe('P0D12');
    expect(await durableSnapshot()).toEqual(before);
    const totals = await exposureTotals(chain.buyer.org, chain.agent);
    expect(totals.unresolved).toBe('1000000');
    expect(totals.released).toBe('0');
    expect(await actionRow(actionId(512))).toBeUndefined();
  }, 120000);
});

// ===========================================================================
// RACE 3 - Response loss after a real COMMIT.
// ===========================================================================

/**
 * A pool that awaits the REAL PostgreSQL COMMIT and only then raises a bounded
 * transport failure. This is an EXPLICITLY INJECTED post-commit transport
 * fault, not a random TCP fault: the commit genuinely reached and was applied
 * by PostgreSQL before the caller ever sees an error.
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
  return Object.assign(state, { pool });
}

/** Waits until the faulted backend is genuinely gone from the server. */
async function awaitBackendGone(pid: number | undefined, timeoutMs = 15_000): Promise<number> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const result = await admin.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM pg_stat_activity WHERE pid = $1',
      [pid],
    );
    const alive = result.rows[0]?.n ?? 1;
    if (alive === 0 || Date.now() > deadline) return alive;
    await sleep(100);
  }
}

describe('race 3: response loss after a real commit', () => {
  it('never lets an uncertain grant revoke become a second release', async () => {
    const issued = await seedIssuedGrant(30, 1030);
    await grants.initialize();
    const before = await exposureTotals(issued.chain.buyer.org, issued.chain.agent);
    expect(before.unresolved).toBe('1000000');

    const fault = injectPostCommitTransportFault(tenant as unknown as Pool);
    const faulted = new ControlGrantStore(fault.pool);
    await expectGrantCode(
      faulted.revokeGrant(issued.chain.buyer.hash, issued.chain.buyer.org, issued.grant, {
        idempotencyKey: key(3001),
        mutationId: grantMutation(3001),
      }),
      'CONTROL_GRANT_STORE_OUTCOME_UNKNOWN',
    );

    // NON-VACUITY: the COMMIT really happened once, no ROLLBACK was sent, the
    // connection was released for DESTRUCTION and the backend is actually gone.
    expect(fault.commits).toBe(1);
    expect(fault.statements.filter((text) => text.includes('revoke_authorization_grant'))).toHaveLength(1);
    expect(fault.statements.filter((text) => text === 'COMMIT')).toHaveLength(1);
    expect(fault.statements.filter((text) => text === 'ROLLBACK')).toHaveLength(0);
    expect(fault.destroyed).toBe(true);
    expect(await awaitBackendGone(fault.backendPid)).toBe(0);
    // No raw session or token material ever reached the recorded statements.
    const recorded = fault.statements.join('\n');
    expect(recorded).not.toContain(issued.chain.buyer.hash);
    expect(recorded).not.toContain(issued.tokenHash);

    // An INDEPENDENT connection observes EXACTLY ONE committed change.
    const committed = await durableSnapshot();
    const afterCommit = await exposureTotals(issued.chain.buyer.org, issued.chain.agent);
    expect(afterCommit.unresolved).toBe('0');
    expect(afterCommit.released).toBe('1000000');
    expect(await counts()).toMatchObject({ released: 1 });

    // ATTACK A: the naive caller "does not know", so it retries with a FRESH
    // idempotency key. That must fail closed and release nothing further.
    await expectGrantCode(
      grants.revokeGrant(issued.chain.buyer.hash, issued.chain.buyer.org, issued.grant, {
        idempotencyKey: key(3002),
        mutationId: grantMutation(3002),
      }),
      'CONTROL_GRANT_STORE_GRANT_CONFLICT',
    );
    expect(await durableSnapshot()).toEqual(committed);

    // ATTACK B: the caller reuses the key but invents a new mutation id.
    await expectGrantCode(
      grants.revokeGrant(issued.chain.buyer.hash, issued.chain.buyer.org, issued.grant, {
        idempotencyKey: key(3001),
        mutationId: grantMutation(3003),
      }),
      'CONTROL_GRANT_STORE_IDEMPOTENCY_CONFLICT',
    );
    expect(await durableSnapshot()).toEqual(committed);

    // RECOVERY: only the EXACT original request recovers the receipt, and it is
    // a replay, never a second cleanup.
    const recovered = await grants.revokeGrant(
      issued.chain.buyer.hash, issued.chain.buyer.org, issued.grant,
      { idempotencyKey: key(3001), mutationId: grantMutation(3001) },
    );
    expect(recovered.replayed).toBe(true);
    expect(recovered.receipt.resourceId).toBe(issued.grant);
    expect(await durableSnapshot()).toEqual(committed);
    const events = await admin.query<{ n: number; total: string }>(
      `SELECT count(*)::int AS n, coalesce(sum(amount_atomic::numeric), 0)::text AS total
         FROM openarc_durable.budget_events WHERE event_kind = 'released'`,
    );
    expect(events.rows[0]).toMatchObject({ n: 1, total: '1000000' });
  }, 120000);

  it('recovers an uncertain action cancel through status and never cancels twice', async () => {
    const chain = await seedCrossChain(31, 1031);
    const requirement = await seedRequirement(chain, 311);
    const action = actionId(311);
    await coreAuthorize(chain, requirement, action, {
      mutation: actionMutation(3101), keyHash: keyHashOf(3101),
    });
    await actions.initialize();
    const cancelMutation = actionMutation(3102);

    const fault = injectPostCommitTransportFault(tenant as unknown as Pool);
    const faulted = new ControlActionStore(fault.pool);
    await expectActionCode(
      faulted.cancelCommerceAction(chain.buyer.hash, chain.buyer.org, action, {
        idempotencyKey: key(3102),
        mutationId: cancelMutation,
      }) as Promise<unknown>,
      'CONTROL_ACTION_STORE_OUTCOME_UNKNOWN',
    );
    // NON-VACUITY: exactly one real COMMIT, no rollback, backend destroyed.
    expect(fault.commits).toBe(1);
    expect(fault.statements.filter((text) => text === 'ROLLBACK')).toHaveLength(0);
    expect(fault.destroyed).toBe(true);
    expect(await awaitBackendGone(fault.backendPid)).toBe(0);

    const committed = await durableSnapshot();
    expect((await actionRow(action))!['status']).toBe('cancelled');
    expect(await counts()).toMatchObject({ released: 1 });

    // The ONLY safe recovery is the status reader, and it reports exactly one
    // committed receipt for the uncertain mutation.
    const status = await actions.getHumanMutationStatus(
      chain.buyer.hash, chain.buyer.org, cancelMutation,
    );
    expect(status).toMatchObject({
      status: 'committed',
      receipt: {
        mutationId: cancelMutation,
        operation: 'control.commerce_action.cancel',
        resourceId: action,
      },
    });
    // Reading the status changed nothing.
    expect(await durableSnapshot()).toEqual(committed);

    // A blind retry with a fresh key cannot cancel a cancelled action again,
    // and it now says so honestly. This assertion is the whole point of the
    // recovery contract: a caller that lost a reply is told the target is in a
    // conflicting state - stop and reconcile through the status read above -
    // rather than being told to fix its input and resend, which is what the
    // collapsed 23514 bucket used to imply on precisely this path.
    await expectActionCode(
      actions.cancelCommerceAction(chain.buyer.hash, chain.buyer.org, action, {
        idempotencyKey: key(3103),
        mutationId: actionMutation(3103),
      }) as Promise<unknown>,
      'CONTROL_ACTION_STORE_CONFLICT',
    );
    expect(await durableSnapshot()).toEqual(committed);
    const events = await admin.query<{ n: number; total: string }>(
      `SELECT count(*)::int AS n, coalesce(sum(amount_atomic::numeric), 0)::text AS total
         FROM openarc_durable.budget_events WHERE event_kind = 'released'`,
    );
    expect(events.rows[0]).toMatchObject({ n: 1, total: '1000000' });
  }, 120000);
});

// ===========================================================================
// FINDING - reported, not fixed here. The owning packet must decide.
// ===========================================================================

describe('regression: ControlActionStore separates state conflicts from operand faults', () => {
  /**
   * `ControlActionStore.normalizeError` maps SQLSTATE 23514 to
   * CONTROL_ACTION_STORE_INPUT_INVALID together with the genuine operand codes
   * 22023 / 22P02 / 22001 / 22003. But migration 0010 raises 23514 for three
   * materially different families:
   *
   *   * `commerce_expired`            (11 sites) - authority lapsed,
   *   * `commerce_cancel_conflict`,
   *     `commerce_decision_conflict`  (3 sites)  - target state conflict,
   *   * the immutability/clock trigger invariants (4 sites).
   *
   * A caller therefore cannot distinguish "your request body is malformed"
   * (retry after fixing it) from "this action is already cancelled or expired"
   * (do NOT retry; read the status). That is exactly the wrong signal on the
   * response-loss recovery path above, where a caller that lost a reply is
   * told to fix its input rather than to stop and reconcile.
   *
   * ControlGrantStore does NOT have this problem: it carries dedicated
   * CONTROL_GRANT_STORE_GRANT_CONFLICT (P0D14) and
   * CONTROL_GRANT_STORE_GRANT_EXPIRED (P0D15) codes for the same families, and
   * ControlActionStore already owns an unused CONTROL_ACTION_STORE_CONFLICT
   * code reachable only from 23505.
   *
   * Financially it always failed CLOSED - nothing was released twice and no
   * state moved - so it was an error-contract defect, not a money defect.
   *
   * FIXED: `normalizeError` now classifies 23514 by the exact RAISE literal,
   * yielding CONTROL_ACTION_STORE_EXPIRED for `commerce_expired` and
   * CONTROL_ACTION_STORE_CONFLICT for the two conflict literals, while any
   * other 23514 - an unrecognised CHECK or trigger invariant - still returns
   * INPUT_INVALID exactly as before. Matching is on the full message, never a
   * substring, and those literals are internal and never caller-controlled.
   * This test now pins the SEPARATION rather than the collapse.
   */
  it('reports an already-cancelled action distinctly from a malformed operand', async () => {
    const chain = await seedCrossChain(90, 1090);
    const requirement = await seedRequirement(chain, 901);
    const action = actionId(901);
    await coreAuthorize(chain, requirement, action, {
      mutation: actionMutation(9001), keyHash: keyHashOf(9001),
    });
    await actions.initialize();
    await actions.cancelCommerceAction(chain.buyer.hash, chain.buyer.org, action, {
      idempotencyKey: key(9002), mutationId: actionMutation(9002),
    });
    expect((await actionRow(action))!['status']).toBe('cancelled');
    const settled = await durableSnapshot();

    // A pure STATE conflict: the action is already cancelled. The caller must
    // stop and reconcile through status, NOT fix a body and resend.
    await expectActionCode(
      actions.cancelCommerceAction(chain.buyer.hash, chain.buyer.org, action, {
        idempotencyKey: key(9003), mutationId: actionMutation(9003),
      }) as Promise<unknown>,
      'CONTROL_ACTION_STORE_CONFLICT',
    );
    // A pure INPUT fault: a structurally invalid action id.
    await expectActionCode(
      actions.cancelCommerceAction(chain.buyer.hash, chain.buyer.org, 'openarc:action:not-a-uuid', {
        idempotencyKey: key(9004), mutationId: actionMutation(9004),
      }) as Promise<unknown>,
      'CONTROL_ACTION_STORE_INPUT_INVALID',
    );
    // Distinguishable now, and the grant surface separates them the same way.
    const issued = await seedIssuedGrant(91, 1091);
    await grants.initialize();
    await grants.revokeGrant(issued.chain.buyer.hash, issued.chain.buyer.org, issued.grant, {
      idempotencyKey: key(9005), mutationId: grantMutation(9005),
    });
    await expectGrantCode(
      grants.revokeGrant(issued.chain.buyer.hash, issued.chain.buyer.org, issued.grant, {
        idempotencyKey: key(9006), mutationId: grantMutation(9006),
      }),
      'CONTROL_GRANT_STORE_GRANT_CONFLICT',
    );

    // The financial invariant still holds on both surfaces: exactly one
    // release per action, and neither failed call moved a row.
    const cancelled = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM openarc_durable.budget_events
        WHERE event_kind = 'released' AND action_id = $1`,
      [action],
    );
    expect(cancelled.rows[0]!.n).toBe(1);
    const snapshotNow = await durableSnapshot() as Record<string, unknown[]>;
    const settledActions = (settled as Record<string, unknown[]>)['actions']!;
    // The first chain's action rows are untouched by either failed attempt.
    expect((snapshotNow['actions'] as Record<string, unknown>[])
      .filter((row) => row['action_id'] === action))
      .toEqual((settledActions as Record<string, unknown>[])
        .filter((row) => row['action_id'] === action));
  }, 120000);
});

// ===========================================================================
// RACE 6 - Organization bypass across every store method.
// ===========================================================================

describe('race 6: organization bypass', () => {
  /**
   * NON-VACUITY for a non-race attack is the paired POSITIVE CONTROL: every
   * denial below is accompanied by the same call made by the rightful
   * principal, which succeeds (or reaches the production provenance seam, which
   * proves authorization was passed). Without that pairing a denial could
   * simply mean the fixture was empty.
   */
  it('fails closed on every cross-organization read and mutation', async () => {
    const issued = await seedIssuedGrant(60, 1060);
    const buyer = issued.chain.buyer;
    const seller = issued.chain.seller;
    // A completely unrelated third buyer and fourth seller.
    const foreign = await seedCrossChain(61, 1061);
    const foreignProviderSession = await seedProviderSession(
      foreign.seller, foreign.provider, 1061,
    );
    await actions.initialize();
    await grants.initialize();
    const before = await durableSnapshot();
    const attempt = attemptOf(601);

    // --- action reads ------------------------------------------------------
    // The seller is a real current owner of ITS OWN organization, so its proof
    // is valid; the buyer's action simply does not exist there.
    expect(await actions.readAction(seller.hash, seller.org, issued.action)).toBeNull();
    expect(await actions.readApproval(seller.hash, seller.org, issued.action)).toBeNull();
    // The exposure reader refuses an unknown (organization, policy, subject)
    // triple outright, and a FOREIGN triple is INDISTINGUISHABLE from a
    // fabricated one inside the caller's own organization: both are FORBIDDEN,
    // so the error discloses nothing about what exists elsewhere.
    await expectActionCode(
      actions.readExposure(seller.hash, seller.org, issued.chain.agent, issued.chain.policy),
      'CONTROL_ACTION_STORE_FORBIDDEN',
    );
    await expectActionCode(
      actions.readExposure(seller.hash, seller.org, agentId(60999), policyId(60999)),
      'CONTROL_ACTION_STORE_FORBIDDEN',
    );
    // Presenting a foreign organization with a valid proof is forbidden, not a
    // silent null: the caller holds no membership there.
    await expectActionCode(
      actions.readAction(buyer.hash, seller.org, issued.action),
      'CONTROL_ACTION_STORE_FORBIDDEN',
    );
    await expectActionCode(
      actions.readAction(seller.hash, buyer.org, issued.action),
      'CONTROL_ACTION_STORE_FORBIDDEN',
    );
    await expectActionCode(
      actions.readExposure(seller.hash, buyer.org, issued.chain.agent, issued.chain.policy),
      'CONTROL_ACTION_STORE_FORBIDDEN',
    );
    // POSITIVE CONTROL.
    expect((await actions.readAction(buyer.hash, buyer.org, issued.action))?.actionId)
      .toBe(issued.action);
    expect((await actions.readExposure(
      buyer.hash, buyer.org, issued.chain.agent, issued.chain.policy,
    ))?.unresolvedAtomic).toBe('1000000');

    // --- agent reads -------------------------------------------------------
    // A foreign but perfectly valid commerce token sees its OWN organization
    // and a null item; it never learns that the action exists elsewhere.
    const foreignView = await actions.readAgentAction(foreign.commerceTokenHash, issued.action);
    expect(foreignView).toEqual({
      organizationId: foreign.buyer.org,
      actionId: issued.action,
      item: null,
    });
    // POSITIVE CONTROL: the owning agent does see it.
    const ownView = await actions.readAgentAction(issued.chain.commerceTokenHash, issued.action);
    expect(ownView.organizationId).toBe(buyer.org);
    expect(ownView.item?.actionId).toBe(issued.action);

    // --- grant reads and mutations ----------------------------------------
    expect(await grants.readGrant(seller.hash, seller.org, issued.grant)).toBeNull();
    await expectGrantCode(
      grants.readGrant(buyer.hash, seller.org, issued.grant),
      'CONTROL_GRANT_STORE_FORBIDDEN',
    );
    // The seller cannot revoke the buyer's grant from its own organization...
    await expectGrantCode(
      grants.revokeGrant(seller.hash, seller.org, issued.grant, {
        idempotencyKey: key(6001), mutationId: grantMutation(6001),
      }),
      'CONTROL_GRANT_STORE_NOT_FOUND',
    );
    // ...nor by naming the buyer's organization it has no membership in.
    await expectGrantCode(
      grants.revokeGrant(seller.hash, buyer.org, issued.grant, {
        idempotencyKey: key(6002), mutationId: grantMutation(6002),
      }),
      'CONTROL_GRANT_STORE_FORBIDDEN',
    );
    // ...nor can the buyer revoke inside the seller organization.
    await expectGrantCode(
      grants.revokeGrant(buyer.hash, seller.org, issued.grant, {
        idempotencyKey: key(6003), mutationId: grantMutation(6003),
      }),
      'CONTROL_GRANT_STORE_FORBIDDEN',
    );
    // POSITIVE CONTROL.
    expect((await grants.readGrant(buyer.hash, buyer.org, issued.grant))?.grantId)
      .toBe(issued.grant);

    // --- provider surface --------------------------------------------------
    // A foreign provider session plus the real grant token is not two factors.
    await expectGrantCode(
      grants.introspectGrant(foreignProviderSession, issued.tokenHash),
      'CONTROL_GRANT_STORE_FORBIDDEN',
    );
    await expectGrantCode(
      grants.claimGrant(foreignProviderSession, {
        grantTokenHash: issued.tokenHash,
        expectedActionId: issued.action,
        attemptId: attempt,
      }, { idempotencyKey: key(6011), mutationId: grantMutation(6011) }),
      'CONTROL_GRANT_STORE_FORBIDDEN',
    );
    // The rightful provider presenting a FOREIGN action id is equally refused.
    await expectGrantCode(
      grants.claimGrant(issued.providerSessionHash, {
        grantTokenHash: issued.tokenHash,
        expectedActionId: actionId(61),
        attemptId: attempt,
      }, { idempotencyKey: key(6012), mutationId: grantMutation(6012) }),
      'CONTROL_GRANT_STORE_FORBIDDEN',
    );
    // POSITIVE CONTROL: the rightful provider with the rightful action gets
    // past every authority check and is stopped only by the production
    // provenance seam, which proves the refusals above were authorization ones.
    await expectGrantCode(
      grants.claimGrant(issued.providerSessionHash, {
        grantTokenHash: issued.tokenHash,
        expectedActionId: issued.action,
        attemptId: attempt,
      }, { idempotencyKey: key(6013), mutationId: grantMutation(6013) }),
      'CONTROL_GRANT_STORE_REQUIREMENT_UNAVAILABLE',
    );

    // --- provider historical recovery --------------------------------------
    await coreClaimOn(
      migrator, issued.providerSessionHash, issued.tokenHash, issued.action, attempt,
      { mutation: grantMutation(6004), keyHash: keyHashOf(6004) },
    );
    // A foreign provider cannot recover a claim and cannot tell a foreign
    // attempt from a missing one.
    expect(await grants.readProviderAttemptStatus(foreignProviderSession, attempt))
      .toEqual({ status: 'not_found' });
    expect(await grants.readProviderAttemptStatus(foreignProviderSession, attemptOf(609)))
      .toEqual({ status: 'not_found' });
    // POSITIVE CONTROL: the rightful provider recovers it.
    expect(await grants.readProviderAttemptStatus(issued.providerSessionHash, attempt))
      .toMatchObject({ status: 'claimed', attemptId: attempt });

    // Not one bypass attempt changed committed state; only the single claim did.
    const counted = await counts();
    expect(counted).toMatchObject({ claims: 1, released: 0, grants: 1 });
    expect(await durableSnapshot()).not.toEqual(before);
    const totals = await exposureTotals(buyer.org, issued.chain.agent);
    expect(totals.unresolved).toBe('1000000');
    expect(totals.released).toBe('0');
  }, 120000);

  it('never lets a foreign or wrong-kind session act as commerce identity', async () => {
    const issued = await seedIssuedGrant(62, 1062);
    await actions.initialize();
    const before = await durableSnapshot();

    // A provider session hash is not commerce identity.
    await expectActionCode(
      actions.readAgentAction(issued.providerSessionHash, issued.action),
      'CONTROL_ACTION_STORE_FORBIDDEN',
    );
    // Neither is the buyer's own HUMAN session hash.
    await expectActionCode(
      actions.readAgentAction(issued.chain.buyer.hash, issued.action),
      'CONTROL_ACTION_STORE_FORBIDDEN',
    );
    // Nor the buyer's machine (oas_ag_) session hash: a read-only machine
    // credential alone can never speak for a commerce session.
    await expectActionCode(
      actions.readAgentAction(issued.chain.agentSessionHash, issued.action),
      'CONTROL_ACTION_STORE_FORBIDDEN',
    );
    // The agent status reader is bound the same way.
    expect(await actions.getAgentMutationStatus(
      issued.chain.commerceTokenHash, actionMutation(9999),
    )).toEqual({ status: 'not_found' });
    // POSITIVE CONTROL: the real commerce token is accepted.
    expect((await actions.readAgentAction(
      issued.chain.commerceTokenHash, issued.action,
    )).item?.actionId).toBe(issued.action);

    expect(await durableSnapshot()).toEqual(before);
  }, 120000);
});
