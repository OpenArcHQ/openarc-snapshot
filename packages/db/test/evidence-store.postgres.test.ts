import { createHash } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import {
  EVIDENCE_V2_FACT_KINDS,
  EVIDENCE_V2_GATEWAY_COMMITTED_LIMITATION,
  EVIDENCE_V2_KIND_SOURCE_CLASSES,
  EVIDENCE_V2_SCHEMA_VERSION,
  EVIDENCE_V2_SOURCE_CLASSES,
  EVIDENCE_V2_UNKNOWN_PAYMENT_LIMITATION,
  EvidenceV2FactSchema,
  type EvidenceV2Fact,
  type EvidenceV2FactOf,
} from '@openarc/shared';
import {
  EvidenceStore,
  EvidenceStoreError,
  createDatabasePool,
  loadMigrations,
  migrate,
  type EvidenceStoreErrorCode,
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
 * schema16 PG proofs: the append-only evidence v2 store and its bounded
 * operator reads. Facts are recorded through the migrator-private recorder as
 * the migrator (its runtime principal is decided in P05-02c); every read runs
 * through the restricted tenant runtime. Nothing here calls a provider, signs,
 * settles or moves funds.
 */

function sha256(seed: string): string {
  return createHash('sha256').update(`openarc-evidence-test:${seed}`, 'utf8').digest('hex');
}

function uuid(seed: number): string {
  return `43000000-0000-4000-8000-${String(seed).padStart(12, '0')}`;
}

const accountId = (seed: number): string => `openarc:account:${uuid(seed)}`;
const orgId = (seed: number): string => `openarc:org:${uuid(seed)}`;
const actionId = (seed: number): string => `openarc:action:${uuid(seed)}`;
const evd = (n: number): string => `evd_${n.toString(16).padStart(32, '0')}`;

function userHandle(seed: number): string {
  return `${sha256(`handle:${seed}`).slice(0, 42)}A`;
}

const PROVIDER = `openarc:provider:${uuid(900001)}`;
const ACCOUNT = accountId(900002);
const AGENT = `openarc:agent:${uuid(900003)}`;
const ACTION = actionId(900004);
const GRANT = `openarc:grant:${uuid(900005)}`;
const LISTING = `openarc:listing:${uuid(900006)}:3`;
const TRANSFER = '3f1c1b7e-8a1d-4f5e-9b2a-1c2d3e4f5a6b';
const BATCH = `0x${'ab'.repeat(32)}`;
const OTHER_TX = `0x${'cd'.repeat(32)}`;
const BLOCK_HASH = `0x${'12'.repeat(32)}`;
const RESPONSE_DIGEST = `sha256:${'0f'.repeat(32)}`;
const JOB = `eip155:5042002:erc8183:0x${'9a'.repeat(20)}:7`;
const PAYER = `0x${'a1'.repeat(20)}`;
const PAY_TO = `0x${'b2'.repeat(20)}`;
const T1 = '2026-09-15T10:00:00Z';
const T2 = '2026-09-15T10:00:05Z';
const T3 = '2026-09-15T10:00:10Z';
const UINT256_MAX = '115792089237316195423570985008687907853269984665640564039457584007913129639935';

const SIGNATURE_CANARY = `0x${'5a'.repeat(65)}`;
const SESSION_CANARY = 'c3'.repeat(32);
const JWT_CANARY = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl';
const BEARER_CANARY = 'Zm9vYmFy'.repeat(6);
const CANARY_VALUES = [SIGNATURE_CANARY, SESSION_CANARY, JWT_CANARY, BEARER_CANARY];
const CANARY_KEYS = ['signature', 'authorization', 'authorizationPayload', 'payload', 'rawPayload', 'nonceSignature',
  'privateKey', 'apiKey', 'token', 'accessToken', 'sessionHash', 'sessionTokenHash', 'tokenHash', 'secret', 'password', 'cookie'];

// ---------------------------------------------------------------------------
// Fact fixtures (independent of the store's own operand mapping).
// ---------------------------------------------------------------------------
const common = (n: number) => ({
  schemaVersion: EVIDENCE_V2_SCHEMA_VERSION,
  evidenceId: evd(n),
  occurredAt: null,
  observedAt: T1,
  digest: null,
  dataClass: 'organization_protected' as const,
  limitations: ['Control-plane record; not an external observation.'],
});
const control = { class: 'local', sourceId: 'openarc.control', origin: 'openarc:control-plane', adapterVersion: 'openarc.control-projection.v1' } as const;
const gatewaySource = { class: 'gateway', sourceId: 'circle_gateway_testnet', origin: 'https://gateway-api-testnet.circle.com', adapterVersion: 'openarc.gateway-transfer.v2' } as const;
const chainSource = { class: 'onchain', sourceId: 'arc_rpc_testnet', origin: 'https://rpc.testnet.arc.io', adapterVersion: 'openarc.arc-observer.v1' } as const;
const anchor = (finality: 'finalized' | 'unfinalized' = 'finalized') =>
  ({ network: 'eip155:5042002', blockNumber: '1200', blockHash: BLOCK_HASH, finality }) as const;

function authorizationFact(org: string, n: number, subjectAction = ACTION): EvidenceV2FactOf<'authorization_decision'> {
  return { ...common(n), kind: 'authorization_decision', source: control, subject: { kind: 'action', canonicalId: subjectAction },
    scope: { organizationId: org, providerId: null, actionId: subjectAction }, actor: { kind: 'human_account', accountId: ACCOUNT },
    chain: null, normalized: { decision: 'approved' } };
}
function grantFact(org: string, n: number): EvidenceV2FactOf<'grant_state'> {
  return { ...common(n), kind: 'grant_state', source: control, subject: { kind: 'authorization_grant', canonicalId: GRANT },
    scope: { organizationId: org, providerId: PROVIDER, actionId: ACTION }, actor: { kind: 'provider', providerId: PROVIDER },
    chain: null, normalized: { status: 'claimed' } };
}
function derivedExpiryFact(org: string, n: number): EvidenceV2FactOf<'grant_state'> {
  return { ...common(n), kind: 'grant_state', source: { ...control, class: 'openarc_derived', sourceId: 'openarc.grant-expiry' },
    subject: { kind: 'authorization_grant', canonicalId: GRANT }, scope: { organizationId: org, providerId: PROVIDER, actionId: ACTION },
    actor: { kind: 'system', component: 'worker' }, chain: null, normalized: { status: 'expired' } };
}
function listingFact(org: string, n: number): EvidenceV2FactOf<'listing_state'> {
  return { ...common(n), dataClass: 'public', kind: 'listing_state', source: control, subject: { kind: 'listing', canonicalId: LISTING },
    scope: { organizationId: org, providerId: PROVIDER, actionId: null }, actor: { kind: 'system', component: 'api' },
    chain: null, normalized: { status: 'active' } };
}
function exposureFact(org: string, n: number): EvidenceV2FactOf<'budget_exposure'> {
  return { ...common(n), kind: 'budget_exposure', source: control, subject: { kind: 'action', canonicalId: ACTION },
    scope: { organizationId: org, providerId: null, actionId: ACTION }, actor: { kind: 'system', component: 'worker' },
    chain: null, normalized: { exposure: { held: '10', claimed: '0', unknown: '5', committed: '0' } } };
}
function committedPayment(org: string, n: number): EvidenceV2FactOf<'payment_observation'> {
  return { ...common(n), kind: 'payment_observation', source: gatewaySource, subject: { kind: 'action', canonicalId: ACTION },
    scope: { organizationId: org, providerId: PROVIDER, actionId: ACTION }, actor: { kind: 'external_party', role: 'gateway', address: null },
    chain: null, limitations: [EVIDENCE_V2_GATEWAY_COMMITTED_LIMITATION],
    normalized: { laneState: 'committed', certainty: 'submitted_pending_chain', gatewayStatus: 'completed', transferId: TRANSFER,
      batchTransactionHash: BATCH, amountAtomic: '1000000', payer: PAYER, payTo: PAY_TO } };
}
function pendingPayment(org: string, n: number): EvidenceV2FactOf<'payment_observation'> {
  return { ...common(n), kind: 'payment_observation', source: gatewaySource, subject: { kind: 'action', canonicalId: ACTION },
    scope: { organizationId: org, providerId: PROVIDER, actionId: ACTION }, actor: { kind: 'external_party', role: 'gateway', address: null },
    chain: null, normalized: { laneState: 'pending', certainty: 'pending', gatewayStatus: 'batched', transferId: TRANSFER,
      batchTransactionHash: null, amountAtomic: '1000000', payer: PAYER, payTo: PAY_TO } };
}
function unknownPayment(org: string, n: number): EvidenceV2FactOf<'payment_observation'> {
  return { ...common(n), kind: 'payment_observation', source: gatewaySource, subject: { kind: 'action', canonicalId: ACTION },
    scope: { organizationId: org, providerId: null, actionId: ACTION }, actor: { kind: 'system', component: 'worker' },
    chain: null, limitations: [EVIDENCE_V2_UNKNOWN_PAYMENT_LIMITATION],
    normalized: { laneState: 'unknown', certainty: 'unknown', unknownReason: 'timeout' } };
}
function arcTxFact(org: string, n: number, finality: 'finalized' | 'unfinalized' = 'finalized', observedAt = T1): EvidenceV2FactOf<'arc_transaction'> {
  return { ...common(n), observedAt, kind: 'arc_transaction', source: chainSource,
    subject: { kind: 'arc_transaction', canonicalId: `eip155:5042002:tx:${BATCH}` },
    scope: { organizationId: org, providerId: null, actionId: ACTION }, actor: { kind: 'external_party', role: 'arc_chain', address: null },
    chain: anchor(finality), normalized: { transactionHash: BATCH, receiptStatus: 'success' } };
}
function jobStateFact(org: string, n: number): EvidenceV2FactOf<'job_state'> {
  return { ...common(n), dataClass: 'public', kind: 'job_state', source: chainSource, subject: { kind: 'erc8183_job', canonicalId: JOB },
    scope: { organizationId: org, providerId: null, actionId: null }, actor: { kind: 'external_party', role: 'erc8183_evaluator', address: PAY_TO },
    chain: anchor(), normalized: { knowledge: 'known', status: 'Completed', terminal: true } };
}
function jobRefundFact(org: string, n: number): EvidenceV2FactOf<'job_refund'> {
  return { ...common(n), dataClass: 'public', kind: 'job_refund', source: chainSource, subject: { kind: 'erc8183_job', canonicalId: JOB },
    scope: { organizationId: org, providerId: null, actionId: null }, actor: { kind: 'external_party', role: 'erc8183_client', address: PAYER },
    chain: anchor(), normalized: { cause: 'rejected', amountAtomic: '2500000', transactionHash: OTHER_TX } };
}
function deliveryFact(org: string, n: number): EvidenceV2FactOf<'provider_delivery'> {
  return { ...common(n), kind: 'provider_delivery', source: { ...control, class: 'provider', origin: 'https://provider.example' },
    subject: { kind: 'action', canonicalId: ACTION }, scope: { organizationId: org, providerId: PROVIDER, actionId: ACTION },
    actor: { kind: 'provider', providerId: PROVIDER }, chain: null, normalized: { reported: 'delivered', responseDigest: RESPONSE_DIGEST } };
}
function evaluatorFact(org: string, n: number): EvidenceV2FactOf<'evaluator_result'> {
  return { ...common(n), kind: 'evaluator_result', source: { ...control, class: 'evaluator', origin: 'openarc:reconciler' },
    subject: { kind: 'action', canonicalId: ACTION }, scope: { organizationId: org, providerId: null, actionId: ACTION },
    actor: { kind: 'agent', agentId: AGENT }, chain: null, normalized: { result: 'accepted' } };
}

function allFacts(org: string, base: number): EvidenceV2Fact[] {
  const builders = [authorizationFact, grantFact, derivedExpiryFact, listingFact, exposureFact, committedPayment,
    pendingPayment, unknownPayment, arcTxFact, jobStateFact, jobRefundFact, deliveryFact, evaluatorFact] as const;
  return builders.map((build, index) => (build as (o: string, n: number) => EvidenceV2Fact)(org, base + index));
}

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

// ---------------------------------------------------------------------------
// Raw recorder access (bypassing the store's shared-schema validation, so the
// database itself is the refusing party).
// ---------------------------------------------------------------------------
const COLUMNS = ['schema_version', 'evidence_id', 'kind', 'source_class', 'source_id', 'source_origin', 'adapter_version',
  'subject_kind', 'subject_canonical_id', 'organization_id', 'provider_id', 'action_id', 'actor_kind', 'actor_id',
  'actor_address', 'chain_network', 'chain_block_number', 'chain_block_hash', 'chain_finality', 'occurred_at',
  'observed_at', 'digest', 'data_class', 'limitations', 'normalized'] as const;
type Column = (typeof COLUMNS)[number];
const TEXT_COLUMNS = COLUMNS.filter((column) => !['occurred_at', 'observed_at', 'limitations', 'normalized'].includes(column));

function columnsOf(fact: EvidenceV2Fact): Record<Column, unknown> {
  const actor = fact.actor;
  return {
    schema_version: fact.schemaVersion,
    evidence_id: fact.evidenceId,
    kind: fact.kind,
    source_class: fact.source.class,
    source_id: fact.source.sourceId,
    source_origin: fact.source.origin,
    adapter_version: fact.source.adapterVersion,
    subject_kind: fact.subject.kind,
    subject_canonical_id: fact.subject.canonicalId,
    organization_id: fact.scope.organizationId,
    provider_id: fact.scope.providerId,
    action_id: fact.scope.actionId,
    actor_kind: actor.kind,
    actor_id: actor.kind === 'human_account' ? actor.accountId : actor.kind === 'agent' ? actor.agentId
      : actor.kind === 'provider' ? actor.providerId : actor.kind === 'system' ? actor.component : actor.role,
    actor_address: actor.kind === 'external_party' ? actor.address : null,
    chain_network: fact.chain === null ? null : fact.chain.network,
    chain_block_number: fact.chain === null ? null : fact.chain.blockNumber,
    chain_block_hash: fact.chain === null ? null : fact.chain.blockHash,
    chain_finality: fact.chain === null ? null : fact.chain.finality,
    occurred_at: fact.occurredAt,
    observed_at: fact.observedAt,
    digest: fact.digest,
    data_class: fact.dataClass,
    limitations: [...fact.limitations],
    normalized: clone(fact.normalized),
  };
}

const RAW_RECORD = `SELECT out_replayed, out_evidence_id, out_fact_digest
  FROM openarc_durable.record_evidence_fact(
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
    $20::timestamptz, $21::timestamptz, $22, $23, $24::text[], $25::jsonb)`;

function rawRecord(pool: Pool, fact: EvidenceV2Fact, overrides: Partial<Record<Column, unknown>> = {}) {
  const columns = { ...columnsOf(fact), ...overrides };
  return pool.query<{ out_replayed: boolean; out_evidence_id: string; out_fact_digest: string }>(
    RAW_RECORD,
    COLUMNS.map((column) => (column === 'normalized' && columns.normalized !== null ? JSON.stringify(columns.normalized) : columns[column])),
  );
}

interface PgError {
  code?: string;
  message?: string;
}

async function rawError(promise: Promise<unknown>): Promise<PgError> {
  try {
    await promise;
  } catch (error) {
    return error as PgError;
  }
  throw new Error('expected a rejection');
}

async function expectStoreCode(promise: Promise<unknown>, code: EvidenceStoreErrorCode): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(EvidenceStoreError);
    expect((error as EvidenceStoreError).code).toBe(code);
    return;
  }
  throw new Error(`expected EvidenceStoreError ${code}`);
}

/** Refused by the database with a CHECK/input family and no row written. */
async function expectRefused(label: string, run: () => Promise<unknown>, literal?: string): Promise<void> {
  const before = await factCount();
  const error = await rawError(run());
  expect([label, ['22023', '23514'].includes(error.code ?? '')]).toEqual([label, true]);
  if (literal !== undefined) expect([label, error.message]).toEqual([label, literal]);
  expect([label, await factCount()]).toEqual([label, before]);
}

// ---------------------------------------------------------------------------
// Pools and seeds.
// ---------------------------------------------------------------------------
let admin: Pool;
let migrator: Pool;
let tenant: Pool;
let worker: Pool;
let authApp: Pool;
let store: EvidenceStore;
let recorder: EvidenceStore;

beforeAll(async () => {
  admin = adminPool();
  await ensureRoles(admin);
  migrator = createDatabasePool(migratorUrl());
  tenant = createDatabasePool(tenantUrl());
  worker = createDatabasePool(workerUrl());
  authApp = createDatabasePool(appUrl());
});

afterAll(async () => {
  try {
    await resetSchema(admin);
  } finally {
    await authApp.end();
    await worker.end();
    await tenant.end();
    await migrator.end();
    await admin.end();
  }
});

beforeEach(async () => {
  await resetSchema(admin);
  await migrate(migrator);
  store = new EvidenceStore(tenant);
  recorder = new EvidenceStore(migrator);
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

async function seedMember(org: string, seed: number, role: string, status = 'active'): Promise<Owner> {
  const account = await seedAccount(seed);
  const hash = await seedSession(seed, account);
  await admin.query(
    'INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, $3, $4)',
    [org, account, role, status],
  );
  return { account, hash, org };
}

async function factCount(): Promise<number> {
  const result = await admin.query<{ n: number }>('SELECT count(*)::int AS n FROM openarc_durable.evidence_facts');
  return result.rows[0]!.n;
}

async function tableSnapshot(): Promise<string> {
  const result = await admin.query<{ j: string }>(
    'SELECT row_to_json(f)::text AS j FROM openarc_durable.evidence_facts f ORDER BY evidence_id',
  );
  return sha256(result.rows.map((row) => row.j).join('\n'));
}

async function waitForLockWait(): Promise<void> {
  for (let attempt = 0; attempt < 600; attempt += 1) {
    const probe = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM pg_stat_activity
        WHERE datname = current_database() AND wait_event_type = 'Lock' AND pid <> pg_backend_pid()`,
    );
    if ((probe.rows[0]?.n ?? 0) > 0) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error('no lock wait observed');
}

async function shortenSession(hash: string, seconds: number): Promise<void> {
  await admin.query(
    `UPDATE openarc_auth.sessions
        SET expires_at = clock_timestamp() + make_interval(secs => $2)
      WHERE token_hash = $1`,
    [hash, seconds],
  );
}

async function waitUntilSessionExpired(hash: string): Promise<void> {
  for (let attempt = 0; attempt < 600; attempt += 1) {
    const probe = await admin.query<{ expired: boolean }>(
      'SELECT clock_timestamp() >= expires_at AS expired FROM openarc_auth.sessions WHERE token_hash = $1',
      [hash],
    );
    if (probe.rows[0]?.expired === true) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error('session did not expire');
}

/** Bulk-records `count` authorization facts about one action through the recorder, as the migrator. */
async function bulkRecord(org: string, subjectAction: string, from: number, to: number): Promise<void> {
  const result = await migrator.query<{ n: number }>(
    `SELECT count(*)::int AS n
       FROM generate_series($1::int, $2::int) AS i,
            LATERAL openarc_durable.record_evidence_fact(
              'openarc.evidence.v2', 'evd_' || lpad(to_hex(i), 32, '0'), 'authorization_decision', 'local',
              'openarc.control', 'openarc:control-plane', 'openarc.control-projection.v1', 'action', $3, $4,
              NULL, $3, 'system', 'api', NULL, NULL, NULL, NULL, NULL, NULL,
              '2026-09-15T00:00:00Z'::timestamptz + make_interval(secs => i), NULL, 'organization_protected',
              ARRAY['Control-plane record; not an external observation.'], '{"decision":"approved"}'::jsonb) AS r
      WHERE NOT r.out_replayed`,
    [from, to, subjectAction, org],
  );
  expect(result.rows[0]?.n).toBe(to - from + 1);
}

const SCHEMA16_FUNCTIONS: readonly { name: string; sig: string; definer: boolean; runtime: boolean; volatility: 'IMMUTABLE' | 'STABLE' | 'VOLATILE' }[] = [
  { name: 'read_evidence_facts_by_subject', sig: 'openarc_durable.read_evidence_facts_by_subject(text, text, text, text)', definer: true, runtime: true, volatility: 'STABLE' },
  { name: 'list_evidence_facts', sig: 'openarc_durable.list_evidence_facts(text, text, text, text, integer)', definer: true, runtime: true, volatility: 'STABLE' },
  { name: 'record_evidence_fact', sig: 'openarc_durable.record_evidence_fact(text, text, text, text, text, text, text, text, text, text, text, text, text, text, text, text, text, text, text, timestamptz, timestamptz, text, text, text[], jsonb)', definer: true, runtime: false, volatility: 'VOLATILE' },
  { name: 'is_canonical_evidence_id', sig: 'openarc_durable.is_canonical_evidence_id(text)', definer: false, runtime: false, volatility: 'IMMUTABLE' },
  { name: 'is_evidence_text_secret_free', sig: 'openarc_durable.is_evidence_text_secret_free(text, integer, integer)', definer: false, runtime: false, volatility: 'IMMUTABLE' },
  { name: 'is_valid_evidence_limitations', sig: 'openarc_durable.is_valid_evidence_limitations(text[])', definer: false, runtime: false, volatility: 'IMMUTABLE' },
  { name: 'is_evidence_payload_secret_free', sig: 'openarc_durable.is_evidence_payload_secret_free(jsonb)', definer: false, runtime: false, volatility: 'IMMUTABLE' },
  { name: 'is_evidence_kind_source_allowed', sig: 'openarc_durable.is_evidence_kind_source_allowed(text, text)', definer: false, runtime: false, volatility: 'IMMUTABLE' },
  { name: 'is_evidence_subject_id', sig: 'openarc_durable.is_evidence_subject_id(text, text)', definer: false, runtime: false, volatility: 'IMMUTABLE' },
  { name: 'is_valid_evidence_normalized', sig: 'openarc_durable.is_valid_evidence_normalized(text, jsonb)', definer: false, runtime: false, volatility: 'IMMUTABLE' },
  { name: 'evidence_fact_digest', sig: 'openarc_durable.evidence_fact_digest(openarc_durable.evidence_facts)', definer: false, runtime: false, volatility: 'STABLE' },
  { name: 'reject_evidence_fact_mutation', sig: 'openarc_durable.reject_evidence_fact_mutation()', definer: false, runtime: false, volatility: 'VOLATILE' },
  { name: 'enforce_evidence_fact_insert', sig: 'openarc_durable.enforce_evidence_fact_insert()', definer: false, runtime: false, volatility: 'VOLATILE' },
];

// ---------------------------------------------------------------------------
describe('schema16 manifest, ownership, ACLs and readiness', () => {
  it('records schema16 and keeps every runtime role off the evidence table and the recorder', async () => {
    const applied = await admin.query<{ id: string }>('SELECT id FROM openarc_meta.schema_migrations ORDER BY id');
    expect(applied.rows.map((row) => row.id).slice(-2)).toEqual(['0015_payment_attempts', '0016_evidence_store']);
    const table = await admin.query<{ enabled: boolean; forced: boolean; owner: string; public_acl: number }>(
      `SELECT c.relrowsecurity AS enabled, c.relforcerowsecurity AS forced, r.rolname AS owner,
              (SELECT count(*)::int FROM aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
                WHERE a.grantee <> c.relowner) AS public_acl
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_roles r ON r.oid = c.relowner
        WHERE n.nspname = 'openarc_durable' AND c.relname = 'evidence_facts'`,
    );
    expect(table.rows[0]).toEqual({ enabled: true, forced: true, owner: 'openarc_migrator', public_acl: 0 });
    const owner = await seedOwner(1);
    await recorder.recordFact(authorizationFact(owner.org, 1));
    for (const [label, pool] of [['tenant', tenant], ['worker', worker], ['auth', authApp]] as const) {
      for (const sql of [
        'SELECT count(*) FROM openarc_durable.evidence_facts',
        "UPDATE openarc_durable.evidence_facts SET source_id = 'openarc.forged'",
        'DELETE FROM openarc_durable.evidence_facts',
        'TRUNCATE openarc_durable.evidence_facts',
        "INSERT INTO openarc_durable.evidence_facts (evidence_id) VALUES ('evd_00000000000000000000000000000099')",
      ]) {
        expect([label, sql, (await rawError(pool.query(sql))).code]).toEqual([label, sql, '42501']);
      }
      expect([label, (await rawError(rawRecord(pool, authorizationFact(owner.org, 2)))).code]).toEqual([label, '42501']);
    }
    expect(await factCount()).toBe(1);
    const acl = await admin.query<{ proname: string; app: boolean; worker: boolean; auth: boolean; pub: number; secdef: boolean; config: string[]; volatile: string; grantees: string[] }>(
      `SELECT p.proname,
              has_function_privilege('openarc_tenant_app', p.oid, 'EXECUTE') AS app,
              has_function_privilege('openarc_worker_app', p.oid, 'EXECUTE') AS worker,
              has_function_privilege('openarc_auth_app', p.oid, 'EXECUTE') AS auth,
              (SELECT count(*)::int FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE') AS pub,
              p.prosecdef AS secdef, coalesce(p.proconfig, ARRAY[]::text[]) AS config, p.provolatile::text AS volatile,
              ARRAY(SELECT coalesce(g.rolname::text, 'PUBLIC') FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                      LEFT JOIN pg_roles g ON g.oid = a.grantee ORDER BY 1) AS grantees
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'openarc_durable' AND p.proname = ANY ($1::text[])
        ORDER BY p.proname`,
      [SCHEMA16_FUNCTIONS.map((entry) => entry.name)],
    );
    expect(acl.rows).toHaveLength(SCHEMA16_FUNCTIONS.length);
    for (const expected of SCHEMA16_FUNCTIONS) {
      const row = acl.rows.find((candidate) => candidate.proname === expected.name)!;
      expect([expected.name, row.app, row.worker, row.auth, row.pub]).toEqual([expected.name, expected.runtime, false, false, 0]);
      expect([expected.name, row.secdef, row.config]).toEqual([expected.name, expected.definer, ['search_path=pg_catalog']]);
      expect([expected.name, row.volatile]).toEqual([expected.name, expected.volatility[0]!.toLowerCase()]);
      expect([expected.name, row.grantees]).toEqual([expected.name,
        expected.runtime ? ['openarc_migrator', 'openarc_tenant_app'] : ['openarc_migrator']]);
    }
    // The migration grants the recorder to nobody and adds no outbox event type.
    const sql = loadMigrations().find((migration) => migration.id === '0016_evidence_store')!.sql;
    expect(sql).toContain('NOT granted to openarc_tenant_app');
    expect(sql).toContain('P05-02c');
    expect(sql).not.toMatch(/GRANT[^;]*record_evidence_fact/);
    expect(sql).not.toMatch(/GRANT[^;]*ON TABLE/);
    expect(sql).not.toContain('outbox_events');
    await store.readiness();
    await store.initialize();
  });

  it('readiness passes, then fails for EVERY new helper, trigger, constraint and table guard that is missing, mis-signed, widened or bypassed', async () => {
    await store.initialize();
    await store.readiness();
    const expectUnready = async (label: string): Promise<void> => {
      try {
        await new EvidenceStore(tenant).readiness();
      } catch (error) {
        expect([label, (error as EvidenceStoreError).code]).toEqual([label, 'EVIDENCE_STORE_UNAVAILABLE']);
        return;
      }
      throw new Error(`readiness unexpectedly passed: ${label}`);
    };
    const helpers = [
      ...SCHEMA16_FUNCTIONS,
      { name: 'resolve_action_reader_org', sig: 'openarc_durable.resolve_action_reader_org(text, text)', definer: true, runtime: false, volatility: 'VOLATILE' as const },
    ];
    for (const helper of helpers) {
      // Missing.
      await migrator.query(`ALTER FUNCTION ${helper.sig} RENAME TO ${helper.name}_gone`);
      await expectUnready(`${helper.name}:missing`);
      await migrator.query(`ALTER FUNCTION ${helper.sig.replace(`.${helper.name}(`, `.${helper.name}_gone(`)} RENAME TO ${helper.name}`);
      // Definer flag flipped.
      await migrator.query(`ALTER FUNCTION ${helper.sig} ${helper.definer ? 'SECURITY INVOKER' : 'SECURITY DEFINER'}`);
      await expectUnready(`${helper.name}:security`);
      await migrator.query(`ALTER FUNCTION ${helper.sig} ${helper.definer ? 'SECURITY DEFINER' : 'SECURITY INVOKER'}`);
      // search_path no longer pinned.
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
      // Volatility changed (a VOLATILE reader could write).
      await migrator.query(`ALTER FUNCTION ${helper.sig} ${helper.volatility === 'VOLATILE' ? 'STABLE' : 'VOLATILE'}`);
      await expectUnready(`${helper.name}:volatility`);
      await migrator.query(`ALTER FUNCTION ${helper.sig} ${helper.volatility}`);
      await store.readiness();
    }
    // A second overload (for example one accepting a caller organization list) is not ready.
    await migrator.query(
      `CREATE FUNCTION openarc_durable.list_evidence_facts(a text, b text, c text, d text, e integer, f text)
       RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS $$ SELECT $$`,
    );
    await migrator.query('REVOKE ALL ON FUNCTION openarc_durable.list_evidence_facts(text, text, text, text, integer, text) FROM PUBLIC');
    await expectUnready('list:overload');
    await migrator.query('DROP FUNCTION openarc_durable.list_evidence_facts(text, text, text, text, integer, text)');
    // Every trigger disabled, and the append-only trigger narrowed, is not ready.
    for (const trigger of ['evidence_facts_append_only', 'evidence_facts_no_truncate', 'evidence_facts_insert_digest']) {
      await migrator.query(`ALTER TABLE openarc_durable.evidence_facts DISABLE TRIGGER ${trigger}`);
      await expectUnready(`${trigger}:disabled`);
      await migrator.query(`ALTER TABLE openarc_durable.evidence_facts ENABLE TRIGGER ${trigger}`);
    }
    await migrator.query('ALTER TABLE openarc_durable.evidence_facts ENABLE ALWAYS TRIGGER evidence_facts_append_only');
    await expectUnready('append_only:replica_mode_changed');
    await migrator.query('ALTER TABLE openarc_durable.evidence_facts ENABLE TRIGGER evidence_facts_append_only');
    await migrator.query('DROP TRIGGER evidence_facts_append_only ON openarc_durable.evidence_facts');
    await migrator.query(`CREATE TRIGGER evidence_facts_append_only BEFORE DELETE ON openarc_durable.evidence_facts
      FOR EACH ROW EXECUTE FUNCTION openarc_durable.reject_evidence_fact_mutation()`);
    await expectUnready('append_only:update_uncovered');
    await migrator.query('DROP TRIGGER evidence_facts_append_only ON openarc_durable.evidence_facts');
    await migrator.query(`CREATE TRIGGER evidence_facts_append_only BEFORE UPDATE OR DELETE ON openarc_durable.evidence_facts
      FOR EACH ROW EXECUTE FUNCTION openarc_durable.reject_evidence_fact_mutation()`);
    await store.readiness();
    // Table guards.
    await migrator.query('ALTER TABLE openarc_durable.evidence_facts NO FORCE ROW LEVEL SECURITY');
    await expectUnready('table:unforced');
    await migrator.query('ALTER TABLE openarc_durable.evidence_facts FORCE ROW LEVEL SECURITY');
    for (const grantee of ['openarc_tenant_app', 'PUBLIC']) {
      await migrator.query(`GRANT SELECT ON TABLE openarc_durable.evidence_facts TO ${grantee}`);
      await expectUnready(`table:select:${grantee}`);
      await migrator.query(`REVOKE SELECT ON TABLE openarc_durable.evidence_facts FROM ${grantee}`);
    }
    // The SQL authority matrix drifting from the shared contract is not ready.
    const matrix = (await admin.query<{ def: string }>(
      "SELECT pg_get_functiondef('openarc_durable.is_evidence_kind_source_allowed(text, text)'::regprocedure) AS def",
    )).rows[0]!.def;
    await migrator.query(matrix.replace("WHEN 'grant_state' THEN source_class IN ('local', 'openarc_derived')", "WHEN 'grant_state' THEN source_class = 'local'"));
    await expectUnready('matrix:grant_state_narrowed');
    await migrator.query(matrix.replace("WHEN 'evaluator_result' THEN source_class = 'evaluator'", "WHEN 'evaluator_result' THEN source_class IN ('evaluator', 'agent_reported')"));
    await expectUnready('matrix:evaluator_widened');
    await migrator.query(matrix);
    await store.readiness();
    // A dropped, unvalidated or widened constraint is not ready.
    const constraints = await admin.query<{ conname: string; def: string }>(
      `SELECT c.conname, pg_get_constraintdef(c.oid) AS def FROM pg_constraint c
        WHERE c.conrelid = 'openarc_durable.evidence_facts'::regclass
          AND c.conname IN ('evidence_facts_derived_grant_expiry', 'evidence_facts_payment_certainty_valid',
                            'evidence_facts_payload_secret_free', 'evidence_facts_text_secret_free',
                            'evidence_facts_chain_valid', 'evidence_facts_source_class_allowed')`,
    );
    expect(constraints.rows).toHaveLength(6);
    for (const constraint of constraints.rows) {
      await migrator.query(`ALTER TABLE openarc_durable.evidence_facts DROP CONSTRAINT ${constraint.conname}`);
      await expectUnready(`${constraint.conname}:dropped`);
      await migrator.query(`ALTER TABLE openarc_durable.evidence_facts ADD CONSTRAINT ${constraint.conname} ${constraint.def} NOT VALID`);
      await expectUnready(`${constraint.conname}:not_valid`);
      await migrator.query(`ALTER TABLE openarc_durable.evidence_facts VALIDATE CONSTRAINT ${constraint.conname}`);
      await store.readiness();
    }
    await migrator.query('ALTER TABLE openarc_durable.evidence_facts DROP CONSTRAINT evidence_facts_payment_certainty_valid');
    await migrator.query(`ALTER TABLE openarc_durable.evidence_facts ADD CONSTRAINT evidence_facts_payment_certainty_valid
      CHECK (payment_certainty IS NULL OR payment_certainty IN ('unknown', 'pending', 'submitted_pending_chain', 'onchain_confirmed', 'settled'))`);
    await expectUnready('payment_certainty:settled_added');
    await migrator.query('ALTER TABLE openarc_durable.evidence_facts DROP CONSTRAINT evidence_facts_payment_certainty_valid');
    await migrator.query(`ALTER TABLE openarc_durable.evidence_facts ADD CONSTRAINT evidence_facts_payment_certainty_valid
      ${constraints.rows.find((row) => row.conname === 'evidence_facts_payment_certainty_valid')!.def}`);
    await store.readiness();
  }, 240000);
});

// ---------------------------------------------------------------------------
describe('append-only enforcement', () => {
  it('refuses UPDATE, DELETE and TRUNCATE as the migrator and the superuser, and a forged digest even as migrator DML', async () => {
    const owner = await seedOwner(2);
    await recorder.recordFact(authorizationFact(owner.org, 1));
    await recorder.recordFact(arcTxFact(owner.org, 2));
    const before = await tableSnapshot();
    for (const [label, pool] of [['migrator', migrator], ['superuser', admin]] as const) {
      for (const sql of [
        "UPDATE openarc_durable.evidence_facts SET source_id = 'openarc.forged'",
        'UPDATE openarc_durable.evidence_facts SET kind = kind',
        "UPDATE openarc_durable.evidence_facts SET chain_finality = 'finalized' WHERE kind = 'arc_transaction'",
        'DELETE FROM openarc_durable.evidence_facts',
        `DELETE FROM openarc_durable.evidence_facts WHERE evidence_id = '${evd(1)}'`,
        'TRUNCATE openarc_durable.evidence_facts',
      ]) {
        const error = await rawError(pool.query(sql));
        expect([label, sql, error.code, error.message]).toEqual([label, sql, '42501', 'evidence_facts_append_only']);
      }
    }
    expect(await tableSnapshot()).toBe(before);
    expect(await factCount()).toBe(2);
    // Ordinary migrator DML that copies a stored row under a new id keeps the
    // old digest, which no longer describes its content: refused.
    const forged = await rawError(migrator.query(
      `INSERT INTO openarc_durable.evidence_facts (
         evidence_id, schema_version, kind, source_class, source_id, source_origin, adapter_version,
         subject_kind, subject_canonical_id, organization_id, provider_id, action_id, actor_kind, actor_id,
         actor_address, chain_network, chain_block_number, chain_block_hash, chain_finality, occurred_at,
         observed_at, digest, data_class, limitations, normalized, fact_digest, recorded_at)
       SELECT $1, schema_version, kind, source_class, source_id, source_origin, adapter_version,
              subject_kind, subject_canonical_id, organization_id, provider_id, action_id, actor_kind, actor_id,
              actor_address, chain_network, chain_block_number, chain_block_hash, chain_finality, occurred_at,
              observed_at, digest, data_class, limitations, normalized, fact_digest, recorded_at
         FROM openarc_durable.evidence_facts WHERE evidence_id = $2`,
      [evd(3), evd(1)],
    ));
    expect([forged.code, forged.message]).toEqual(['23514', 'evidence_fact_digest_invalid']);
    // The generated certainty column cannot be written directly either.
    const generated = await rawError(migrator.query(
      "INSERT INTO openarc_durable.evidence_facts (evidence_id, payment_certainty) VALUES ($1, 'settled')", [evd(4)],
    ));
    expect(generated.code).toBe('428C9');
    expect(await factCount()).toBe(2);
    expect(await tableSnapshot()).toBe(before);
  });
});

// ---------------------------------------------------------------------------
describe('idempotent recording', () => {
  it('replays identical content, conflicts on different content for the same id, and records re-observations and finality upgrades as new rows', async () => {
    const owner = await seedOwner(3);
    const other = await seedOwner(4);
    const unfinalized = arcTxFact(owner.org, 10, 'unfinalized', T1);
    const first = await recorder.recordFact(unfinalized);
    expect(first).toMatchObject({ replayed: false, evidenceId: evd(10), organizationId: owner.org });
    const again = await recorder.recordFact(clone(unfinalized));
    expect(again).toEqual({ ...first, replayed: true });
    // The same instant written differently is the same content.
    expect(await recorder.recordFact({ ...unfinalized, observedAt: '2026-09-15T10:00:00.000000Z' })).toEqual({ ...first, replayed: true });
    const stored = await tableSnapshot();

    const conflicting: [string, EvidenceV2Fact][] = [
      ['finality', { ...unfinalized, chain: anchor('finalized') }],
      ['observedAt', { ...unfinalized, observedAt: T2 }],
      ['limitations', { ...unfinalized, limitations: ['Arc observer receipt; unfinalized.'] }],
      ['receipt', { ...unfinalized, normalized: { transactionHash: BATCH, receiptStatus: 'reverted' } }],
      ['organization', { ...unfinalized, scope: { ...unfinalized.scope, organizationId: other.org } }],
    ];
    for (const [label, fact] of conflicting) {
      try {
        await recorder.recordFact(fact);
        throw new Error(`conflict not raised: ${label}`);
      } catch (error) {
        expect([label, (error as EvidenceStoreError).code]).toEqual([label, 'EVIDENCE_STORE_CONFLICT']);
      }
      const raw = await rawError(rawRecord(migrator, fact));
      expect([label, raw.code, raw.message]).toEqual([label, '23505', 'evidence_id_conflict']);
    }
    expect(await tableSnapshot()).toBe(stored);
    expect(await factCount()).toBe(1);

    // A finality upgrade and a later re-observation are new facts with new ids.
    expect((await recorder.recordFact(arcTxFact(owner.org, 11, 'finalized', T2))).replayed).toBe(false);
    expect((await recorder.recordFact(arcTxFact(owner.org, 12, 'unfinalized', T3))).replayed).toBe(false);
    const read = await store.readBySubject(owner.hash, owner.org, unfinalized.subject);
    expect(read.items.map((item) => [item.operatorView.evidenceId, item.operatorView.chain?.finality])).toEqual([
      [evd(10), 'unfinalized'], [evd(11), 'finalized'], [evd(12), 'unfinalized'],
    ]);
    expect(read.items[0]!.factDigest).toBe(first.factDigest);

    // Concurrent identical records of one new id: exactly one insert.
    const racing = arcTxFact(owner.org, 13, 'finalized', T3);
    const results = await Promise.all(Array.from({ length: 5 }, () => recorder.recordFact(clone(racing))));
    expect(results.filter((result) => !result.replayed)).toHaveLength(1);
    expect(new Set(results.map((result) => result.recordedAt)).size).toBe(1);
    expect(await factCount()).toBe(4);
  });
});

// ---------------------------------------------------------------------------
describe('authority matrix and chain columns', () => {
  it('admits exactly the shared kind-by-source-class matrix for every kind and all nine classes', async () => {
    const owner = await seedOwner(5);
    let seed = 1000;
    let checked = 0;
    for (const fact of allFacts(owner.org, 100)) {
      for (const sourceClass of EVIDENCE_V2_SOURCE_CLASSES) {
        seed += 1;
        const candidate = clone(fact) as EvidenceV2Fact;
        (candidate as { evidenceId: string }).evidenceId = evd(seed);
        (candidate.source as { class: string }).class = sourceClass;
        if (sourceClass === 'provider') (candidate as { actor: unknown }).actor = { kind: 'provider', providerId: PROVIDER };
        const inMatrix = (EVIDENCE_V2_KIND_SOURCE_CLASSES[fact.kind] as readonly string[]).includes(sourceClass);
        const scopedOk = sourceClass !== 'provider' || fact.scope.providerId === PROVIDER;
        const derivedOk = !(fact.kind === 'grant_state' && sourceClass === 'openarc_derived' && fact.normalized.status !== 'expired');
        const expected = inMatrix && scopedOk && derivedOk;
        const label = `${fact.kind}/${sourceClass}/${fact.kind === 'grant_state' ? fact.normalized.status : ''}`;
        // The database agrees with the shared contract cell for cell.
        expect([label, EvidenceV2FactSchema.safeParse(candidate).success]).toEqual([label, expected]);
        if (expected) {
          const result = await rawRecord(migrator, candidate);
          expect([label, result.rows[0]?.out_replayed]).toEqual([label, false]);
        } else {
          await expectRefused(label, () => rawRecord(migrator, candidate),
            !inMatrix || !derivedOk ? 'evidence_source_class_forbidden' : undefined);
        }
        checked += 1;
      }
    }
    expect(checked).toBe(13 * 9);
    // signed and agent_reported are admitted for no kind at all.
    const stored = await admin.query<{ source_class: string }>('SELECT DISTINCT source_class FROM openarc_durable.evidence_facts');
    expect(stored.rows.map((row) => row.source_class)).not.toContain('signed');
    expect(stored.rows.map((row) => row.source_class)).not.toContain('agent_reported');
    expect(EVIDENCE_V2_FACT_KINDS).toHaveLength(10);
  }, 60000);

  it('admits grant_state from openarc_derived ONLY as a derived expiry', async () => {
    const owner = await seedOwner(6);
    const expired = derivedExpiryFact(owner.org, 1);
    expect((await recorder.recordFact(expired)).replayed).toBe(false);
    for (const [index, status] of (['revoked', 'issued', 'replaced', 'claimed'] as const).entries()) {
      const candidate = { ...derivedExpiryFact(owner.org, 10 + index), normalized: { status } };
      expect(EvidenceV2FactSchema.safeParse(candidate).success).toBe(false);
      // Past the recorder's matrix precheck, the dedicated CHECK refuses it.
      await expectRefused(`derived:${status}`, () => rawRecord(migrator, candidate), 'evidence_source_class_forbidden');
      await expectStoreCode(recorder.recordFact(candidate), 'EVIDENCE_STORE_INPUT_INVALID');
    }
    // The same statuses from a local source remain admissible.
    expect((await recorder.recordFact({ ...grantFact(owner.org, 20), normalized: { status: 'revoked' } })).replayed).toBe(false);
    const read = await store.readBySubject(owner.hash, owner.org, expired.subject);
    expect(read.items.map((item) => [item.operatorView.source.class, (item.operatorView.normalized as { status: string }).status]))
      .toEqual([['openarc_derived', 'expired'], ['local', 'revoked']]);
    const constraint = await admin.query<{ def: string }>(
      `SELECT pg_get_constraintdef(oid) AS def FROM pg_constraint
        WHERE conrelid = 'openarc_durable.evidence_facts'::regclass AND conname = 'evidence_facts_derived_grant_expiry'`,
    );
    expect(constraint.rows[0]?.def).toContain("'expired'");
  });

  it('requires the complete Arc chain anchor on onchain kinds and forbids every chain column elsewhere', async () => {
    const owner = await seedOwner(7);
    let seed = 2000;
    const next = () => evd((seed += 1));
    for (const fact of allFacts(owner.org, 200)) {
      const isChain = fact.chain !== null;
      if (isChain) {
        for (const column of ['chain_network', 'chain_block_number', 'chain_block_hash', 'chain_finality'] as const) {
          await expectRefused(`${fact.kind}:${column}:null`, () => rawRecord(migrator, fact, { evidence_id: next(), [column]: null }), 'evidence_fact_invalid');
        }
        for (const [column, value] of [
          ['chain_network', 'eip155:1'], ['chain_network', 'eip155:5042002 '], ['chain_block_number', '01'],
          ['chain_block_number', '-1'], ['chain_block_number', '1.0'], ['chain_block_number', '18446744073709551616'],
          ['chain_block_hash', `0x${'AB'.repeat(32)}`], ['chain_block_hash', BLOCK_HASH.slice(0, -2)],
          ['chain_finality', 'safe'], ['chain_finality', 'latest'],
        ] as const) {
          await expectRefused(`${fact.kind}:${column}=${value}`, () => rawRecord(migrator, fact, { evidence_id: next(), [column]: value }), 'evidence_fact_invalid');
        }
        for (const blockNumber of ['0', '18446744073709551615']) {
          const accepted = await rawRecord(migrator, fact, { evidence_id: next(), chain_block_number: blockNumber });
          expect(accepted.rows[0]?.out_replayed).toBe(false);
        }
      } else {
        for (const [column, value] of [
          ['chain_network', 'eip155:5042002'], ['chain_block_number', '1200'], ['chain_block_hash', BLOCK_HASH], ['chain_finality', 'finalized'],
        ] as const) {
          await expectRefused(`${fact.kind}:${column}`, () => rawRecord(migrator, fact, { evidence_id: next(), [column]: value }), 'evidence_fact_invalid');
        }
        await expectRefused(`${fact.kind}:full_anchor`, () => rawRecord(migrator, fact, {
          evidence_id: next(), chain_network: 'eip155:5042002', chain_block_number: '1200', chain_block_hash: BLOCK_HASH, chain_finality: 'finalized',
        }), 'evidence_fact_invalid');
      }
    }
    // A job refund exists only finalized; a transaction subject must name its hash.
    await expectRefused('job_refund:unfinalized', () => rawRecord(migrator, jobRefundFact(owner.org, 1), { evidence_id: next(), chain_finality: 'unfinalized' }), 'evidence_fact_invalid');
    await expectRefused('arc_tx:subject', () => rawRecord(migrator, arcTxFact(owner.org, 1), { evidence_id: next(), subject_canonical_id: `eip155:5042002:tx:${OTHER_TX}` }), 'evidence_fact_invalid');
  }, 60000);

  it('enforces canonical id grammars, exact integer amounts, strict payload shapes and the cross-field rules', async () => {
    const owner = await seedOwner(8);
    let seed = 3000;
    const next = () => evd((seed += 1));
    const org = owner.org;
    await expectRefused('evidence_id:short', () => rawRecord(migrator, authorizationFact(org, 1), { evidence_id: 'evd_' + '0'.repeat(31) }), 'evidence_input_invalid');
    await expectRefused('evidence_id:upper', () => rawRecord(migrator, authorizationFact(org, 1), { evidence_id: evd(1).toUpperCase() }), 'evidence_input_invalid');
    await expectRefused('org:upper', () => rawRecord(migrator, authorizationFact(org, 1), { evidence_id: next(), organization_id: org.toUpperCase() }), 'evidence_input_invalid');
    const unknownOrg = await rawError(rawRecord(migrator, authorizationFact(orgId(999), 1), { evidence_id: next() }));
    expect(unknownOrg.code).toBe('23503');
    await expectStoreCode(recorder.recordFact({ ...authorizationFact(orgId(999), 2), evidenceId: next() }), 'EVIDENCE_STORE_NOT_FOUND');

    const invalid: [string, EvidenceV2Fact, Partial<Record<Column, unknown>>][] = [
      ['schema_version', authorizationFact(org, 1), { schema_version: 'openarc.evidence.v1' }],
      ['kind:unknown', authorizationFact(org, 1), { kind: 'settlement' }],
      ['subject:action_v1', authorizationFact(org, 1), { subject_canonical_id: ACTION.replace('-4000-', '-1000-'), action_id: ACTION.replace('-4000-', '-1000-') }],
      ['subject:kind_mismatch', authorizationFact(org, 1), { subject_kind: 'authorization_grant', subject_canonical_id: GRANT }],
      ['subject:listing_version_0', listingFact(org, 1), { subject_canonical_id: LISTING.replace(':3', ':0') }],
      ['subject:tx_63', arcTxFact(org, 1), { subject_canonical_id: `eip155:5042002:tx:${BATCH.slice(0, -1)}` }],
      ['subject:job_0', jobStateFact(org, 1), { subject_canonical_id: JOB.replace(':7', ':0') }],
      ['scope:provider', grantFact(org, 1), { provider_id: 'openarc:provider:nope', actor_id: 'openarc:provider:nope' }],
      ['scope:provider_missing', grantFact(org, 1), { provider_id: null }],
      ['scope:action_mismatch', authorizationFact(org, 1), { action_id: actionId(5) }],
      ['actor:account_as_agent', authorizationFact(org, 1), { actor_id: AGENT }],
      ['actor:system_component', exposureFact(org, 1), { actor_id: 'cron' }],
      ['actor:external_role', unknownPayment(org, 1), { actor_kind: 'external_party', actor_id: 'bank', actor_address: null }],
      ['actor:address_upper', jobStateFact(org, 1), { actor_address: PAY_TO.toUpperCase().replace('0X', '0x') }],
      ['actor:address_on_human', authorizationFact(org, 1), { actor_address: PAYER }],
      ['actor:provider_mismatch', grantFact(org, 1), { actor_id: `openarc:provider:${uuid(900099)}` }],
      ['source:provider_without_provider_actor', deliveryFact(org, 1), { actor_kind: 'system', actor_id: 'api' }],
      ['source:origin_path', authorizationFact(org, 1), { source_origin: 'https://gateway.example/path' }],
      ['source:adapter', authorizationFact(org, 1), { adapter_version: 'gateway-v1' }],
      ['source:id', authorizationFact(org, 1), { source_id: 'Openarc' }],
      ['audience:public_payment', committedPayment(org, 1), { data_class: 'public' }],
      ['audience:public_draft', listingFact(org, 1), { normalized: { status: 'draft' } }],
      ['limitation:committed_missing', committedPayment(org, 1), { limitations: ['Gateway record.'] }],
      ['limitation:unknown_missing', unknownPayment(org, 1), { limitations: ['No outcome.'] }],
      ['clock:occurred_after_observed', authorizationFact(org, 1), { occurred_at: T2 }],
      ['digest:bare_hex', authorizationFact(org, 1), { digest: '0f'.repeat(32) }],
      ['limitations:empty', authorizationFact(org, 1), { limitations: [] }],
      ['limitations:nine', authorizationFact(org, 1), { limitations: Array.from({ length: 9 }, (_v, i) => `Limitation ${i}.`) }],
      ['limitations:duplicate', authorizationFact(org, 1), { limitations: ['Same.', 'Same.'] }],
      ['limitations:untrimmed', authorizationFact(org, 1), { limitations: [' Padded.'] }],
      ['limitations:non_ascii', authorizationFact(org, 1), { limitations: ['Café.'] }],
      ['limitations:too_long', authorizationFact(org, 1), { limitations: ['x'.repeat(241)] }],
      ['limitations:null_element', authorizationFact(org, 1), { limitations: ['Fine.', null] }],
      ['normalized:extra_key', authorizationFact(org, 1), { normalized: { decision: 'approved', note: 'x' } }],
      ['normalized:wrong_enum', authorizationFact(org, 1), { normalized: { decision: 'settled' } }],
      ['normalized:array', authorizationFact(org, 1), { normalized: ['approved'] }],
      ['normalized:terminal_string', jobStateFact(org, 1), { normalized: { knowledge: 'known', status: 'Completed', terminal: 'true' } }],
      ['normalized:terminal_disagrees', jobStateFact(org, 1), { normalized: { knowledge: 'known', status: 'Funded', terminal: true } }],
      ['normalized:job_status', jobStateFact(org, 1), { normalized: { knowledge: 'known', status: 'Settled', terminal: true } }],
      ['normalized:delivery_digest', deliveryFact(org, 1), { normalized: { reported: 'delivered', responseDigest: '0f'.repeat(32) } }],
      ['normalized:transfer_upper', pendingPayment(org, 1), { normalized: { ...pendingPayment(org, 1).normalized, transferId: TRANSFER.toUpperCase() } }],
      ['normalized:payer_upper', pendingPayment(org, 1), { normalized: { ...pendingPayment(org, 1).normalized, payer: PAYER.toUpperCase().replace('0X', '0x') } }],
      ['normalized:pending_completed', pendingPayment(org, 1), { normalized: { ...pendingPayment(org, 1).normalized, gatewayStatus: 'completed' } }],
      ['normalized:committed_null_batch', committedPayment(org, 1), { normalized: { ...committedPayment(org, 1).normalized, batchTransactionHash: null } }],
    ];
    for (const amount of ['1.5', '01', '-1', '1e3', ' 1', '', '0x10', `${UINT256_MAX.slice(0, -1)}6`, `1${'0'.repeat(78)}`]) {
      invalid.push([`amount:exposure:${amount}`, exposureFact(org, 1), { normalized: { exposure: { held: amount, claimed: '0', unknown: '5', committed: '0' } } }]);
      invalid.push([`amount:payment:${amount}`, pendingPayment(org, 1), { normalized: { ...pendingPayment(org, 1).normalized, amountAtomic: amount } }]);
      invalid.push([`amount:refund:${amount}`, jobRefundFact(org, 1), { normalized: { ...jobRefundFact(org, 1).normalized, amountAtomic: amount } }]);
    }
    invalid.push(['amount:json_number', exposureFact(org, 1), { normalized: { exposure: { held: 10, claimed: '0', unknown: '5', committed: '0' } } }]);
    for (const [label, fact, overrides] of invalid) {
      await expectRefused(label, () => rawRecord(migrator, fact, { evidence_id: next(), ...overrides }));
    }
    // The boundaries themselves are admissible.
    for (const fact of [
      { ...exposureFact(org, 1), evidenceId: next(), normalized: { exposure: { held: UINT256_MAX, claimed: '0', unknown: UINT256_MAX, committed: '0' } } },
      { ...pendingPayment(org, 1), evidenceId: next(), normalized: { ...pendingPayment(org, 1).normalized, amountAtomic: UINT256_MAX } },
      { ...authorizationFact(org, 1), evidenceId: next(), occurredAt: T1, limitations: [`${'abcd '.repeat(47)}abcde`] },
    ] as EvidenceV2Fact[]) {
      expect((await recorder.recordFact(fact)).replayed).toBe(false);
    }
    const size = await admin.query<{ def: string }>(
      `SELECT pg_get_constraintdef(oid) AS def FROM pg_constraint
        WHERE conrelid = 'openarc_durable.evidence_facts'::regclass AND conname = 'evidence_facts_normalized_size'`,
    );
    expect(size.rows[0]?.def).toContain('<= 2048');
  }, 60000);
});

// ---------------------------------------------------------------------------
function stringPaths(value: unknown, path: (string | number)[] = []): (string | number)[][] {
  if (typeof value === 'string') return [path];
  if (Array.isArray(value)) return value.flatMap((child, index) => stringPaths(child, [...path, index]));
  if (value !== null && typeof value === 'object') return Object.entries(value).flatMap(([key, child]) => stringPaths(child, [...path, key]));
  return [];
}
function objectPaths(value: unknown, path: string[] = []): string[][] {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return [];
  return [path, ...Object.entries(value).flatMap(([key, child]) => objectPaths(child, [...path, key]))];
}
function at(root: unknown, path: readonly (string | number)[]): Record<string | number, unknown> {
  return path.reduce<unknown>((node, key) => (node as Record<string | number, unknown>)[key], root) as Record<string | number, unknown>;
}

describe('secret material', () => {
  it('refuses secret-shaped values in every text column, limitation and payload string, and secret keys at every payload depth; no canary survives anywhere', async () => {
    const owner = await seedOwner(9);
    const facts = allFacts(owner.org, 400);
    let refusals = 0;
    for (const fact of facts) {
      for (const column of TEXT_COLUMNS) {
        for (const canary of CANARY_VALUES) {
          const label = `${fact.kind}:${column}:${canary.slice(0, 6)}`;
          const secretLiteral = canary === SIGNATURE_CANARY && column !== 'evidence_id' && column !== 'organization_id'
            ? 'evidence_secret_material_refused' : undefined;
          await expectRefused(label, () => rawRecord(migrator, fact, { [column]: canary }), secretLiteral);
          refusals += 1;
        }
      }
      for (const canary of CANARY_VALUES) {
        await expectRefused(`${fact.kind}:limitations:${canary.slice(0, 6)}`,
          () => rawRecord(migrator, fact, { limitations: [...fact.limitations, canary] }), 'evidence_secret_material_refused');
        refusals += 1;
      }
      for (const path of stringPaths(fact.normalized)) {
        for (const canary of CANARY_VALUES) {
          const normalized = clone(fact.normalized) as unknown;
          at(normalized, path.slice(0, -1))[path.at(-1)!] = canary;
          await expectRefused(`${fact.kind}:normalized.${path.join('.')}:${canary.slice(0, 6)}`,
            () => rawRecord(migrator, fact, { normalized }), canary === SIGNATURE_CANARY ? 'evidence_secret_material_refused' : undefined);
          refusals += 1;
        }
      }
      for (const path of objectPaths(fact.normalized)) {
        for (const key of CANARY_KEYS) {
          const normalized = clone(fact.normalized) as unknown;
          at(normalized, path)[key] = 'canary';
          await expectRefused(`${fact.kind}:normalized.${[...path, key].join('.')}`,
            () => rawRecord(migrator, fact, { normalized }), 'evidence_secret_material_refused');
          refusals += 1;
        }
      }
      // The store refuses a smuggled key before a connection.
      await expectStoreCode(recorder.recordFact({ ...fact, signature: SIGNATURE_CANARY }), 'EVIDENCE_STORE_INPUT_INVALID');
    }
    expect(refusals).toBeGreaterThan(1200);
    expect(await factCount()).toBe(0);

    // Record every valid fact and read everything back.
    const outputs: unknown[] = [];
    for (const fact of facts) outputs.push(await recorder.recordFact(fact));
    for (const fact of facts) outputs.push(await store.readBySubject(owner.hash, owner.org, fact.subject));
    for (const kind of EVIDENCE_V2_FACT_KINDS) outputs.push(await store.listByKind(owner.hash, owner.org, kind, { limit: '50' }));

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
      expect([label, text.includes(SESSION_CANARY)]).toEqual([label, false]);
      expect([label, text.includes(JWT_CANARY)]).toEqual([label, false]);
      expect([label, text.includes(BEARER_CANARY)]).toEqual([label, false]);
      expect([label, /[0-9a-fA-F]{65}/.test(text.replace(/[0-9]{65,78}/g, ''))]).toEqual([label, false]);
      expect([label, text.includes('canary')]).toEqual([label, false]);
    }
    // Every 64-hex value in the evidence rows and outputs is a known public
    // hash: a transaction or block hash, the response digest or a fact digest.
    const evidenceText = JSON.stringify((await admin.query('SELECT * FROM openarc_durable.evidence_facts')).rows) + outputText;
    const digests = await admin.query<{ fact_digest: string }>('SELECT fact_digest FROM openarc_durable.evidence_facts');
    const allowed = new Set([BATCH.slice(2), OTHER_TX.slice(2), BLOCK_HASH.slice(2), RESPONSE_DIGEST.slice(7),
      ...digests.rows.map((row) => row.fact_digest.slice(7))]);
    const found = evidenceText.match(/[0-9a-f]{64}/g) ?? [];
    expect(found.length).toBeGreaterThan(0);
    for (const value of found) expect([value, allowed.has(value)]).toEqual([value, true]);
    expect(outputText.includes(owner.hash)).toBe(false);
  }, 180000);
});

// ---------------------------------------------------------------------------
describe('payment certainty', () => {
  it('represents no settled, paid, released or refunded payment state in any column', async () => {
    const owner = await seedOwner(10);
    const definition = await admin.query<{ def: string }>(
      `SELECT pg_get_constraintdef(oid) AS def FROM pg_constraint
        WHERE conrelid = 'openarc_durable.evidence_facts'::regclass AND conname = 'evidence_facts_payment_certainty_valid'`,
    );
    const literals = [...(definition.rows[0]?.def ?? '').matchAll(/'([^']*)'::text/g)].map((match) => match[1]).sort();
    expect(literals).toEqual(['onchain_confirmed', 'pending', 'submitted_pending_chain', 'unknown']);
    const forbidden = ['settled', 'paid', 'released', 'released_unsent', 'refunded', 'failed', 'rejected', 'cancelled', 'not_paid', 'nonpayment'];
    let seed = 5000;
    const next = () => evd((seed += 1));
    for (const state of forbidden) {
      const committed = committedPayment(owner.org, 1);
      await expectRefused(`certainty:${state}`, () => rawRecord(migrator, committed, { evidence_id: next(), normalized: { ...committed.normalized, certainty: state } }));
      await expectRefused(`lane:${state}`, () => rawRecord(migrator, committed, { evidence_id: next(), normalized: { ...committed.normalized, laneState: state } }));
      await expectRefused(`lane_and_certainty:${state}`, () => rawRecord(migrator, committed, { evidence_id: next(), normalized: { ...committed.normalized, laneState: state, certainty: state } }));
      await expectRefused(`unknown_certainty:${state}`, () => rawRecord(migrator, unknownPayment(owner.org, 1), { evidence_id: next(), normalized: { laneState: 'unknown', certainty: state, unknownReason: 'timeout' } }));
      await expectRefused(`gateway_status:${state}`, () => rawRecord(migrator, committed, { evidence_id: next(), normalized: { ...committed.normalized, gatewayStatus: state } }));
    }
    // A Gateway observation cannot claim onchain confirmation either.
    const committed = committedPayment(owner.org, 1);
    await expectRefused('certainty:onchain_confirmed', () => rawRecord(migrator, committed, { evidence_id: next(), normalized: { ...committed.normalized, certainty: 'onchain_confirmed' } }));
    for (const fact of [committedPayment(owner.org, 1), pendingPayment(owner.org, 2), unknownPayment(owner.org, 3), authorizationFact(owner.org, 4)]) {
      await recorder.recordFact(fact);
    }
    const stored = await admin.query<{ kind: string; payment_certainty: string | null }>(
      'SELECT kind, payment_certainty FROM openarc_durable.evidence_facts ORDER BY evidence_id',
    );
    expect(stored.rows).toEqual([
      { kind: 'payment_observation', payment_certainty: 'submitted_pending_chain' },
      { kind: 'payment_observation', payment_certainty: 'pending' },
      { kind: 'payment_observation', payment_certainty: 'unknown' },
      { kind: 'authorization_decision', payment_certainty: null },
    ]);
    const everything = JSON.stringify((await admin.query('SELECT * FROM openarc_durable.evidence_facts')).rows);
    for (const state of ['settled', 'paid', 'released', 'refunded']) expect(everything).not.toContain(`"${state}"`);
  });
});

// ---------------------------------------------------------------------------
describe('operator read authority', () => {
  it('reads only for a current owner or operator and denies revoked, expired, recovery, viewer, suspended and non-member sessions', async () => {
    const owner = await seedOwner(11);
    await recorder.recordFact(authorizationFact(owner.org, 1));
    const subject = authorizationFact(owner.org, 1).subject;
    const operator = await seedMember(owner.org, 11_100, 'operator');
    for (const reader of [owner, operator]) {
      expect((await store.readBySubject(reader.hash, owner.org, subject)).items).toHaveLength(1);
      expect((await store.listByKind(reader.hash, owner.org, 'authorization_decision')).items).toHaveLength(1);
    }
    const reads = (hash: string) => [
      () => store.readBySubject(hash, owner.org, subject),
      () => store.listByKind(hash, owner.org, 'authorization_decision', { limit: '5' }),
    ];
    for (const role of ['viewer', 'provider_admin']) {
      const member = await seedMember(owner.org, role === 'viewer' ? 11_200 : 11_300, role);
      for (const call of reads(member.hash)) await expectStoreCode(call(), 'EVIDENCE_STORE_FORBIDDEN');
    }
    const suspended = await seedMember(owner.org, 11_400, 'owner', 'suspended');
    for (const call of reads(suspended.hash)) await expectStoreCode(call(), 'EVIDENCE_STORE_FORBIDDEN');
    const outsider = await seedOwner(11_500);
    for (const call of reads(outsider.hash)) await expectStoreCode(call(), 'EVIDENCE_STORE_FORBIDDEN');
    const recovery = await seedSession(11_600, owner.account, 'recovery');
    for (const call of reads(recovery)) await expectStoreCode(call(), 'EVIDENCE_STORE_SESSION_INVALID');
    await expectStoreCode(store.readBySubject(sha256('never-issued'), owner.org, subject), 'EVIDENCE_STORE_SESSION_INVALID');
    await admin.query(
      "UPDATE openarc_auth.sessions SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 minute' WHERE token_hash = $1",
      [operator.hash],
    );
    for (const call of reads(operator.hash)) await expectStoreCode(call(), 'EVIDENCE_STORE_SESSION_INVALID');
    await admin.query('DELETE FROM openarc_auth.sessions WHERE token_hash = $1', [owner.hash]);
    for (const call of reads(owner.hash)) await expectStoreCode(call(), 'EVIDENCE_STORE_SESSION_INVALID');
  });

  it('revalidates the current authority on the NOT-FOUND path after a lock wait', async () => {
    const owner = await seedOwner(12);
    await shortenSession(owner.hash, 2);
    const blocker = await admin.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query('SELECT 1 FROM openarc_tenant.organizations WHERE organization_id = $1 FOR UPDATE', [owner.org]);
      const pending = store.readBySubject(owner.hash, owner.org, { kind: 'action', canonicalId: ACTION });
      await waitForLockWait();
      await waitUntilSessionExpired(owner.hash);
      await blocker.query('COMMIT');
      await expectStoreCode(pending, 'EVIDENCE_STORE_SESSION_INVALID');
    } finally {
      await blocker.query('ROLLBACK').catch(() => {});
      blocker.release();
    }
  });

  it('revalidates the current authority AFTER the projection: a session that lapses while the read waits on the evidence table is refused on found, not-found, page and overflow paths', async () => {
    const owner = await seedOwner(13);
    await recorder.recordFact(authorizationFact(owner.org, 1));
    const subject = authorizationFact(owner.org, 1).subject;
    const overflowAction = actionId(13_000);
    await bulkRecord(owner.org, overflowAction, 100, 300);
    const calls: [string, () => Promise<unknown>][] = [
      ['found', () => store.readBySubject(owner.hash, owner.org, subject)],
      ['not_found', () => store.readBySubject(owner.hash, owner.org, { kind: 'action', canonicalId: actionId(13_001) })],
      ['page', () => store.listByKind(owner.hash, owner.org, 'authorization_decision', { limit: '5' })],
      ['empty_page', () => store.listByKind(owner.hash, owner.org, 'job_state', { limit: '5' })],
      ['overflow', () => store.readBySubject(owner.hash, owner.org, { kind: 'action', canonicalId: overflowAction })],
    ];
    for (const [label, call] of calls) {
      // Fresh valid session each round, then a short expiry.
      await admin.query("UPDATE openarc_auth.sessions SET expires_at = clock_timestamp() + interval '1 hour' WHERE token_hash = $1", [owner.hash]);
      await shortenSession(owner.hash, 2);
      const blocker = await admin.connect();
      try {
        await blocker.query('BEGIN');
        await blocker.query('LOCK TABLE openarc_durable.evidence_facts IN ACCESS EXCLUSIVE MODE');
        const pending = call();
        await waitForLockWait();
        // Non-vacuity: the waiting reader already passed its FIRST preamble,
        // so it holds the membership row lock while it waits on the table.
        const waiter = await admin.query<{ held: number }>(
          `SELECT count(*)::int AS held FROM pg_locks l JOIN pg_class c ON c.oid = l.relation
            WHERE l.granted AND c.relname = 'memberships'
              AND l.pid IN (SELECT pid FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE '%evidence_facts%')`,
        );
        expect([label, (waiter.rows[0]?.held ?? 0) > 0]).toEqual([label, true]);
        await waitUntilSessionExpired(owner.hash);
        await blocker.query('COMMIT');
        await expectStoreCode(pending, 'EVIDENCE_STORE_SESSION_INVALID');
      } finally {
        await blocker.query('ROLLBACK').catch(() => {});
        blocker.release();
      }
    }
  }, 60000);

  it('readers are STABLE definers that call the preamble twice and project only between the two calls', async () => {
    const definitions = await admin.query<{ proname: string; body: string; volatile: string; secdef: boolean; config: string[] }>(
      `SELECT p.proname, pg_get_functiondef(p.oid) AS body, p.provolatile::text AS volatile,
              p.prosecdef AS secdef, coalesce(p.proconfig, ARRAY[]::text[]) AS config
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'openarc_durable' AND p.proname IN ('read_evidence_facts_by_subject', 'list_evidence_facts')`,
    );
    expect(definitions.rows).toHaveLength(2);
    for (const row of definitions.rows) {
      const preamble = 'openarc_durable.resolve_action_reader_org(';
      expect([row.proname, row.body.split(preamble).length - 1]).toEqual([row.proname, 2]);
      const projection = row.body.indexOf('FROM openarc_durable.evidence_facts f');
      expect([row.proname, row.body.indexOf(preamble) < projection && projection < row.body.lastIndexOf(preamble)]).toEqual([row.proname, true]);
      expect([row.proname, row.volatile, row.secdef, row.config]).toEqual([row.proname, 's', true, ['search_path=pg_catalog']]);
    }
  });
});

// ---------------------------------------------------------------------------
describe('cross-organization isolation', () => {
  it('another organization\'s evidence is indistinguishable from missing on both reads, and a wrong-organization wrapper is denied', async () => {
    const a = await seedOwner(14);
    const b = await seedOwner(15);
    // The SAME subject has facts in both organizations.
    await recorder.recordFact(authorizationFact(a.org, 1));
    await recorder.recordFact(authorizationFact(b.org, 2));
    // A grant subject and a job subject exist only in A.
    await recorder.recordFact(grantFact(a.org, 3));
    await recorder.recordFact(jobStateFact(a.org, 4));
    const actionSubject = authorizationFact(a.org, 1).subject;
    const readA = await store.readBySubject(a.hash, a.org, actionSubject);
    const readB = await store.readBySubject(b.hash, b.org, actionSubject);
    expect(readA.items.map((item) => item.operatorView.evidenceId)).toEqual([evd(1)]);
    expect(readB.items.map((item) => item.operatorView.evidenceId)).toEqual([evd(2)]);
    for (const subject of [grantFact(a.org, 3).subject, jobStateFact(a.org, 4).subject]) {
      const foreign = await store.readBySubject(b.hash, b.org, subject);
      const missing = await store.readBySubject(b.hash, b.org, { kind: 'authorization_grant', canonicalId: `openarc:grant:${uuid(15_999)}` });
      expect(foreign).toEqual({ organizationId: b.org, subject, items: [] });
      expect({ ...foreign, subject: null }).toEqual({ ...missing, subject: null });
    }
    expect((await store.listByKind(b.hash, b.org, 'grant_state')).items).toEqual([]);
    expect((await store.listByKind(b.hash, b.org, 'authorization_decision')).items.map((item) => item.operatorView.evidenceId)).toEqual([evd(2)]);
    // A foreign evidence id as the cursor reveals nothing: it is only a lexical bound.
    expect((await store.listByKind(b.hash, b.org, 'authorization_decision', { afterEvidenceId: evd(1) })).items.map((item) => item.operatorView.evidenceId)).toEqual([evd(2)]);
    expect((await store.listByKind(b.hash, b.org, 'authorization_decision', { afterEvidenceId: evd(3) })).items).toEqual([]);
    // Presenting A's organization with B's session is denied, not emptied.
    await expectStoreCode(store.readBySubject(b.hash, a.org, actionSubject), 'EVIDENCE_STORE_FORBIDDEN');
    await expectStoreCode(store.listByKind(b.hash, a.org, 'grant_state'), 'EVIDENCE_STORE_FORBIDDEN');
    const raw = await rawError(tenant.query('SELECT * FROM openarc_durable.read_evidence_facts_by_subject($1, $2, $3, $4)', [b.hash, a.org, 'action', ACTION]));
    expect(raw.code).toBe('42501');
  });
});

// ---------------------------------------------------------------------------
describe('bounded keyset paging', () => {
  it('traverses every fact of one kind exactly once in ascending id order, with exact cursor boundaries and the default limit', async () => {
    const owner = await seedOwner(16);
    const other = await seedOwner(17);
    const ids: string[] = [];
    for (let n = 1; n <= 26; n += 1) {
      await recorder.recordFact(authorizationFact(owner.org, n, actionId(16_000 + n)));
      ids.push(evd(n));
    }
    await recorder.recordFact(grantFact(owner.org, 100));
    await recorder.recordFact(authorizationFact(other.org, 200));
    const seen: string[] = [];
    let cursor: string | null = null;
    let guard = 0;
    do {
      const query: { limit: string; afterEvidenceId?: string } = { limit: '4' };
      if (cursor !== null) query.afterEvidenceId = cursor;
      const page = await store.listByKind(owner.hash, owner.org, 'authorization_decision', query);
      expect(page.items.length).toBeLessThanOrEqual(4);
      expect(page.organizationId).toBe(owner.org);
      seen.push(...page.items.map((item) => item.operatorView.evidenceId));
      cursor = page.nextCursor;
      guard += 1;
    } while (cursor !== null && guard < 20);
    expect(cursor).toBeNull();
    expect(seen).toEqual(ids);
    expect(guard).toBe(7);
    const shorter = await store.listByKind(owner.hash, owner.org, 'authorization_decision', { limit: '30' });
    expect([shorter.items.length, shorter.nextCursor]).toEqual([26, null]);
    const exact = await store.listByKind(owner.hash, owner.org, 'authorization_decision', { limit: '26' });
    expect([exact.items.length, exact.nextCursor]).toEqual([26, null]);
    const following = await store.listByKind(owner.hash, owner.org, 'authorization_decision', { limit: '3' });
    expect(following.nextCursor).toBe(ids[2]);
    const byDefault = await store.listByKind(owner.hash, owner.org, 'authorization_decision');
    expect([byDefault.items.length, byDefault.nextCursor]).toEqual([25, ids[24]]);
    const tail = await store.listByKind(owner.hash, owner.org, 'authorization_decision', { afterEvidenceId: ids[24] });
    expect([tail.items.map((item) => item.operatorView.evidenceId), tail.nextCursor]).toEqual([[ids[25]], null]);
    expect(await store.listByKind(owner.hash, owner.org, 'job_refund', { limit: '50' }))
      .toEqual({ organizationId: owner.org, kind: 'job_refund', items: [], nextCursor: null });
    // The SQL itself enforces the hard page size, the cursor grammar and the kind set.
    for (const [label, params] of [
      ['limit:0', [owner.hash, owner.org, 'authorization_decision', null, 0]],
      ['limit:51', [owner.hash, owner.org, 'authorization_decision', null, 51]],
      ['limit:null', [owner.hash, owner.org, 'authorization_decision', null, null]],
      ['cursor', [owner.hash, owner.org, 'authorization_decision', 'evd_nope', 5]],
      ['kind', [owner.hash, owner.org, 'settlement', null, 5]],
    ] as const) {
      const error = await rawError(tenant.query('SELECT * FROM openarc_durable.list_evidence_facts($1, $2, $3, $4, $5::int)', [...params]));
      expect([label, error.code, error.message]).toEqual([label, '22023', 'evidence_input_invalid']);
    }
    const fifty = await tenant.query('SELECT * FROM openarc_durable.list_evidence_facts($1, $2, $3, NULL, 50)', [owner.hash, owner.org, 'authorization_decision']);
    expect(fifty.rows).toHaveLength(26);
    const subjectError = await rawError(tenant.query('SELECT * FROM openarc_durable.read_evidence_facts_by_subject($1, $2, $3, $4)', [owner.hash, owner.org, 'action', GRANT]));
    expect([subjectError.code, subjectError.message]).toEqual(['22023', 'evidence_input_invalid']);
  });
});

// These cases record 200-401 facts through the recorder, each firing the insert
// trigger and every CHECK, on top of the per-test migration. They carry an
// explicit bulk-test timeout like the DB10 bounded-completeness suite.
describe('bounded completeness: 200 facts per subject accepted, 201 fail closed', () => {
  it('returns exactly 200 facts for one subject in order, fails closed at 201, and the kind page still traverses every fact', async () => {
    const owner = await seedOwner(18);
    const subjectAction = actionId(18_000);
    const neighbour = actionId(18_001);
    await bulkRecord(owner.org, subjectAction, 1, 200);
    await recorder.recordFact(authorizationFact(owner.org, 5000, neighbour));
    const snapshot = await tableSnapshot();
    const at200 = await store.readBySubject(owner.hash, owner.org, { kind: 'action', canonicalId: subjectAction });
    expect(at200.items).toHaveLength(200);
    expect(at200.items.map((item) => item.operatorView.evidenceId)).toEqual(Array.from({ length: 200 }, (_v, i) => evd(i + 1)));
    const observed = at200.items.map((item) => item.operatorView.observedAt);
    expect([...observed].sort()).toEqual(observed);

    await bulkRecord(owner.org, subjectAction, 201, 201);
    await expectStoreCode(store.readBySubject(owner.hash, owner.org, { kind: 'action', canonicalId: subjectAction }), 'EVIDENCE_STORE_BOUND_EXCEEDED');
    const raw = await rawError(tenant.query('SELECT * FROM openarc_durable.read_evidence_facts_by_subject($1, $2, $3, $4)', [owner.hash, owner.org, 'action', subjectAction]));
    expect([raw.code, raw.message]).toEqual(['P0D11', 'evidence_read_bound_exceeded']);
    // Another subject of the same organization is unaffected.
    expect((await store.readBySubject(owner.hash, owner.org, { kind: 'action', canonicalId: neighbour })).items).toHaveLength(1);
    // The keyset page is bounded per page, not capped: all 202 facts, each once.
    const seen: string[] = [];
    let cursor: string | null = null;
    let pages = 0;
    do {
      const query: { limit: string; afterEvidenceId?: string } = { limit: '50' };
      if (cursor !== null) query.afterEvidenceId = cursor;
      const page = await store.listByKind(owner.hash, owner.org, 'authorization_decision', query);
      expect(page.items.length).toBeLessThanOrEqual(50);
      seen.push(...page.items.map((item) => item.operatorView.evidenceId));
      cursor = page.nextCursor;
      pages += 1;
    } while (cursor !== null && pages < 10);
    expect(pages).toBe(5);
    expect(seen).toHaveLength(202);
    expect(new Set(seen).size).toBe(202);
    expect([...seen].sort()).toEqual(seen);
    // A revoked session learns nothing about the overflow.
    await admin.query('DELETE FROM openarc_auth.sessions WHERE token_hash = $1', [owner.hash]);
    await expectStoreCode(store.readBySubject(owner.hash, owner.org, { kind: 'action', canonicalId: subjectAction }), 'EVIDENCE_STORE_SESSION_INVALID');
    // Reads never mutated anything except the one extra fact recorded above.
    expect(await factCount()).toBe(202);
    expect(snapshot).not.toBe(await tableSnapshot());
  }, 60000);

  it('reads never change a byte of the evidence table', async () => {
    const owner = await seedOwner(19);
    await bulkRecord(owner.org, actionId(19_000), 1, 60);
    for (const fact of allFacts(owner.org, 1000)) await recorder.recordFact(fact);
    const before = await tableSnapshot();
    const countBefore = await factCount();
    await store.readBySubject(owner.hash, owner.org, { kind: 'action', canonicalId: actionId(19_000) });
    for (const kind of EVIDENCE_V2_FACT_KINDS) await store.listByKind(owner.hash, owner.org, kind, { limit: '50' });
    for (const fact of allFacts(owner.org, 1000)) await store.readBySubject(owner.hash, owner.org, fact.subject);
    expect(await tableSnapshot()).toBe(before);
    expect(await factCount()).toBe(countBefore);
  }, 60000);
});
