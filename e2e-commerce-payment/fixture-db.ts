import { createHash, randomBytes, randomUUID } from "node:crypto";

// Type-only imports do not execute these modules.
import type { adminPool } from "../packages/db/test/postgres-fixture.js";
import type { createDatabasePool } from "../packages/db/src/index.js";

// Pure production primitives, imported READONLY so every hash crossing into the
// disposable database is the REAL production digest, never a mirror.
import {
  generateCommerceHandoffToken,
  generateCommerceSessionToken,
  hashCommerceHandoffToken,
  hashCommerceSessionToken,
} from "../apps/api/src/control/session-crypto.js";
import { hashSessionToken } from "../apps/api/src/machine/session-token.js";

// Accepted PORT-03 commerce fixtures, imported READONLY.
import {
  FixtureCoreRefusal,
  fixtureAuthorize,
  fixtureIssueGrant,
  readActionState,
  readGrantState,
  seedAgentMachineSession,
  seedBuyerPolicy,
  seedFixtureRequirement,
  seedProviderMachineSession,
  seedSellerListing,
  type SeededSeller,
} from "../e2e-commerce-production/fixture-db.js";

export { FixtureCoreRefusal, readActionState, readGrantState };
export type { SeededSeller };

type AdminPool = ReturnType<typeof adminPool>;
type DbPool = ReturnType<typeof createDatabasePool>;

/**
 * Bounded, test-only PORT-04 P04-03 payment fixture.
 *
 * Never imported by the web app, the API or either tool. Every function runs
 * behind `OPENARC_COMMERCE_PAYMENT_FIXTURE=1` plus the three accepted
 * production opt-ins, and the accepted `packages/db/test/postgres-fixture.ts`
 * guard asserts the exact synthetic loopback PostgreSQL URL before any
 * connection.
 *
 * NO FUNDS, NO KEY, NO LIVE ENDPOINT. Nothing here signs, sends, settles or
 * delivers, and no raw commerce session, provider session, handoff or grant
 * token is logged, persisted outside the database or returned from a read. Raw
 * tokens a journey must present live only in the caller's test memory.
 *
 * PROVENANCE, STATED PLAINLY. The `fixture*` helpers call the migrator-only
 * closed cores with the literal mode `internal_fixture`, exactly as the
 * accepted DB and PORT-03 suites do. Rows they create are fixture rows and are
 * never evidence of a production purchase, grant, claim, payment or delivery.
 */

const FLAGS = [
  "OPENARC_COMMERCE_PAYMENT_FIXTURE",
  "OPENARC_COMMERCE_PRODUCTION_FIXTURE",
  "OPENARC_SESSION_PRODUCTION_FIXTURE",
  "OPENARC_TENANT_PRODUCTION_FIXTURE",
] as const;

const ATTEMPT = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const ORG = /^openarc:org:[0-9a-f-]{36}$/u;
const LOWER_ADDRESS = /^0x[0-9a-f]{40}$/u;

export class PaymentFixtureError extends Error {
  constructor(code: "FIXTURE_DISABLED" | "FIXTURE_INPUT_INVALID" | "FIXTURE_UNAVAILABLE") {
    super(code);
    this.name = "PaymentFixtureError";
  }
}

function assertEnabled(): void {
  for (const flag of FLAGS) {
    if (process.env[flag] !== "1") throw new PaymentFixtureError("FIXTURE_DISABLED");
  }
}

async function loadFixtureModule() {
  assertEnabled();
  try {
    return await import("../packages/db/test/postgres-fixture.js");
  } catch {
    throw new PaymentFixtureError("FIXTURE_UNAVAILABLE");
  }
}

async function loadDbModule() {
  assertEnabled();
  try {
    return await import("../packages/db/src/index.js");
  } catch {
    throw new PaymentFixtureError("FIXTURE_UNAVAILABLE");
  }
}

async function withAdmin<T>(work: (admin: AdminPool) => Promise<T>): Promise<T> {
  const fixture = await loadFixtureModule();
  let admin: AdminPool | undefined;
  try {
    admin = fixture.adminPool();
    return await work(admin);
  } catch (error) {
    if (error instanceof PaymentFixtureError) throw error;
    throw new PaymentFixtureError("FIXTURE_UNAVAILABLE");
  } finally {
    if (admin !== undefined) await admin.end().catch(() => undefined);
  }
}

async function withPool<T>(
  role: "tenant" | "migrator",
  work: (db: Awaited<ReturnType<typeof loadDbModule>>, pool: DbPool) => Promise<T>,
): Promise<T> {
  const fixture = await loadFixtureModule();
  const db = await loadDbModule();
  let pool: DbPool | undefined;
  try {
    pool = db.createDatabasePool(role === "tenant" ? fixture.tenantUrl() : fixture.migratorUrl());
    return await work(db, pool);
  } finally {
    if (pool !== undefined) await pool.end().catch(() => undefined);
  }
}

/* -------------------------------------------------------------------------- */
/* Disposable database bootstrap                                               */
/* -------------------------------------------------------------------------- */

export interface MigratedSchema {
  readonly applied: number;
  /** The highest applied migration id, e.g. the schema15 payment migration. */
  readonly head: string;
}

/** Fixture roles, a clean schema and the migrations up to the current head. */
export async function prepareDatabase(): Promise<MigratedSchema> {
  const fixture = await loadFixtureModule();
  const db = await loadDbModule();
  const admin = fixture.adminPool();
  let migrator: DbPool | undefined;
  try {
    await fixture.ensureRoles(admin);
    await fixture.resetSchema(admin);
    migrator = db.createDatabasePool(fixture.migratorUrl());
    await db.migrate(migrator);
    const applied = await admin.query<{ applied: number; head: string | null }>(
      "SELECT count(*)::int AS applied, max(id) AS head FROM openarc_meta.schema_migrations",
    );
    const row = applied.rows[0];
    if (row === undefined || row.head === null) throw new PaymentFixtureError("FIXTURE_UNAVAILABLE");
    return { applied: row.applied, head: row.head };
  } finally {
    await migrator?.end().catch(() => undefined);
    await admin.end().catch(() => undefined);
  }
}

/* -------------------------------------------------------------------------- */
/* Buyer identity (synthetic account, session, organization, agent)            */
/* -------------------------------------------------------------------------- */

/** Human session hashes stay in this module and are never returned. */
const sessionHashes = new Map<string, string>();

function syntheticHash(seed: string): string {
  return createHash("sha256").update(`${seed}:${randomBytes(16).toString("hex")}`).digest("hex");
}

export interface SeededBuyer {
  readonly accountId: string;
  readonly organizationId: string;
  readonly agentId: string;
}

async function seedBuyerIdentity(): Promise<SeededBuyer> {
  const accountId = `openarc:account:${randomUUID()}`;
  const organizationId = `openarc:org:${randomUUID()}`;
  const agentId = `openarc:agent:${randomUUID()}`;
  const hash = syntheticHash("payment-fixture-session");
  await withAdmin(async (admin) => {
    await admin.query(
      "INSERT INTO openarc_auth.accounts (account_id, user_handle, status) VALUES ($1, $2, 'active')",
      [accountId, `${randomBytes(32).toString("base64url").slice(0, 42)}A`],
    );
    await admin.query(
      `INSERT INTO openarc_auth.sessions (token_hash, account_id, method, created_at, expires_at)
       VALUES ($1, $2, 'passkey', now(), now() + interval '2 hours')`,
      [hash, accountId],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Synthetic Buyer', $2)",
      [organizationId, accountId],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'owner', 'active')",
      [organizationId, accountId],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name, status) VALUES ($1, $2, 'Buyer agent', 'active')",
      [organizationId, agentId],
    );
  });
  sessionHashes.set(accountId, hash);
  return { accountId, organizationId, agentId };
}

async function liveSessionHash(accountId: string): Promise<string> {
  const known = sessionHashes.get(accountId);
  if (known !== undefined) return known;
  return withAdmin(async (admin) => {
    const result = await admin.query<{ token_hash: string }>(
      `SELECT token_hash FROM openarc_auth.sessions
        WHERE account_id = $1 AND expires_at > clock_timestamp()
        ORDER BY created_at DESC LIMIT 1`,
      [accountId],
    );
    const hash = result.rows[0]?.token_hash;
    if (hash === undefined) throw new PaymentFixtureError("FIXTURE_UNAVAILABLE");
    return hash;
  });
}

/* -------------------------------------------------------------------------- */
/* Seller payment terms through the REAL schema15 store                        */
/* -------------------------------------------------------------------------- */

/**
 * Records the seller's immutable pay-to for listing version 1 through the real
 * `ControlPaymentAttemptStore`. The browser route for this is the seller's own
 * accepted family and is covered there; this fixture uses the same store the
 * route calls, with the seller's real session.
 */
export async function recordPaymentTerms(
  seller: SeededSeller,
  payToAddress: string,
): Promise<string> {
  assertEnabled();
  if (!LOWER_ADDRESS.test(payToAddress)) throw new PaymentFixtureError("FIXTURE_INPUT_INVALID");
  const sellerHash = await liveSessionHash(seller.sellerAccountId);
  return withPool("tenant", async (db, pool) => {
    const store = new db.ControlPaymentAttemptStore(db.asControlPaymentAttemptPool(pool));
    await store.initialize();
    const result = await store.recordListingPaymentTerms(
      sellerHash,
      seller.sellerOrganizationId,
      seller.listingId,
      "1",
      { payToAddress },
      { idempotencyKey: createIdempotencyKey(), mutationId: randomUUID() },
    );
    return result.terms.payToAddress;
  });
}

function createIdempotencyKey(): string {
  const bytes = randomBytes(32);
  bytes[31] = (bytes[31] as number) & 0b11;
  return bytes.toString("base64url");
}

/* -------------------------------------------------------------------------- */
/* The whole buyer/seller chain                                                */
/* -------------------------------------------------------------------------- */

export interface SeededChain {
  readonly seller: SeededSeller;
  readonly buyer: SeededBuyer;
  readonly policyId: string;
  readonly payToAddress: string;
  /** Raw `oacs_v1_` commerce session: caller test memory ONLY, never logged. */
  readonly commerceSessionToken: string;
  /** Raw `oas_pr_` provider session: caller test memory ONLY, never logged. */
  readonly providerSessionToken: string;
}

/**
 * A published, origin-approved seller listing with recorded pay-to terms, a
 * buyer policy that admits the price, a real agent machine session and a real
 * exchanged commerce session.
 */
export async function seedChain(payToAddress: string): Promise<SeededChain> {
  assertEnabled();
  if (!LOWER_ADDRESS.test(payToAddress)) throw new PaymentFixtureError("FIXTURE_INPUT_INVALID");
  const seller = await seedSellerListing();
  const recorded = await recordPaymentTerms(seller, payToAddress);
  const providerSession = await seedProviderMachineSession(seller);
  const buyer = await seedBuyerIdentity();
  const policyId = await seedBuyerPolicy(
    buyer.accountId,
    buyer.organizationId,
    buyer.agentId,
    seller.providerId,
  );
  const machine = await seedAgentMachineSession(buyer.accountId, buyer.organizationId, buyer.agentId);
  const buyerHash = await liveSessionHash(buyer.accountId);
  const handoffToken = generateCommerceHandoffToken();
  const commerceSessionToken = generateCommerceSessionToken();
  await withPool("tenant", async (db, pool) => {
    const sessions = new db.CommerceSessionStore(db.asCommerceSessionPool(pool));
    await sessions.initialize();
    await sessions.issueCommerceSession(
      buyerHash,
      buyer.organizationId,
      {
        subjectAgentId: buyer.agentId,
        policyId,
        handoffHash: hashCommerceHandoffToken(handoffToken),
        hashVersion: 1,
      },
      { idempotencyKey: createIdempotencyKey(), mutationId: randomUUID() },
    );
    await sessions.exchangeCommerceSession(
      hashSessionToken("agent", machine.agentToken),
      hashCommerceHandoffToken(handoffToken),
      { tokenHash: hashCommerceSessionToken(commerceSessionToken), hashVersion: 1 },
      { idempotencyKey: createIdempotencyKey(), mutationId: randomUUID() },
    );
  });
  return {
    seller,
    buyer,
    policyId,
    payToAddress: recorded,
    commerceSessionToken,
    providerSessionToken: providerSession.providerToken,
  };
}

/* -------------------------------------------------------------------------- */
/* internal_fixture provenance (migrator-only closed cores)                     */
/* -------------------------------------------------------------------------- */

export interface FixtureGrantChain {
  readonly requirementId: string;
  readonly actionId: string;
  readonly grantId: string;
  readonly requirementDigest: string;
  readonly expiresAt: string;
  /** Raw `oag_v1_` token: caller test memory ONLY, never logged. */
  readonly grantToken: string;
}

/**
 * A fixture-provenance requirement, action and grant. The production paths
 * refuse this provenance; that refusal is exactly what the suite asserts.
 */
export async function seedFixtureGrantChain(
  chain: SeededChain,
  amountAtomic: string,
): Promise<FixtureGrantChain> {
  assertEnabled();
  const requirementId = await seedFixtureRequirement(
    chain.buyer.organizationId,
    chain.seller,
    amountAtomic,
  );
  const action = await fixtureAuthorize(chain.commerceSessionToken, requirementId);
  const grant = await fixtureIssueGrant(chain.commerceSessionToken, action.actionId);
  const details = await withAdmin(async (admin) => {
    const requirement = await admin.query<{ requirement_digest: string }>(
      "SELECT requirement_digest FROM openarc_durable.commerce_requirement_references WHERE requirement_id = $1",
      [requirementId],
    );
    // Read the expiry back as an exact ISO instant; a raw PostgreSQL rendering
    // is not a valid JavaScript date string.
    const expiry = await admin.query<{ expires_at: string }>(
      `SELECT to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at
         FROM openarc_durable.authorization_grants WHERE grant_id = $1`,
      [grant.grantId],
    );
    const digest = requirement.rows[0]?.requirement_digest;
    const expiresAt = expiry.rows[0]?.expires_at;
    if (digest === undefined || expiresAt === undefined) {
      throw new PaymentFixtureError("FIXTURE_UNAVAILABLE");
    }
    return { digest, expiresAt };
  });
  return {
    requirementId,
    actionId: action.actionId,
    grantId: grant.grantId,
    requirementDigest: details.digest,
    expiresAt: details.expiresAt,
    grantToken: grant.grantToken,
  };
}

/* -------------------------------------------------------------------------- */
/* Bounded non-secret observations                                             */
/* -------------------------------------------------------------------------- */

export interface AttemptRow {
  readonly state: string;
  readonly dispatched: boolean;
  readonly observed: boolean;
  readonly valueAtomic: string;
  readonly payToAddress: string;
}

export async function readAttemptRow(attemptId: unknown): Promise<AttemptRow | null> {
  assertEnabled();
  if (typeof attemptId !== "string" || !ATTEMPT.test(attemptId)) {
    throw new PaymentFixtureError("FIXTURE_INPUT_INVALID");
  }
  return withAdmin(async (admin) => {
    const result = await admin.query<{
      state: string;
      dispatched: boolean;
      observed: boolean;
      value_atomic: string;
      pay_to_address: string;
    }>(
      `SELECT state, dispatched_at IS NOT NULL AS dispatched, observed_at IS NOT NULL AS observed,
              value_atomic, pay_to_address
         FROM openarc_durable.payment_attempts WHERE attempt_id = $1::uuid`,
      [attemptId],
    );
    const row = result.rows[0];
    if (row === undefined) return null;
    return {
      state: row.state,
      dispatched: row.dispatched,
      observed: row.observed,
      valueAtomic: row.value_atomic,
      payToAddress: row.pay_to_address,
    };
  });
}

export async function countAttempts(organizationId: unknown): Promise<number> {
  assertEnabled();
  if (typeof organizationId !== "string" || !ORG.test(organizationId)) {
    throw new PaymentFixtureError("FIXTURE_INPUT_INVALID");
  }
  return withAdmin(async (admin) => {
    const result = await admin.query<{ count: number }>(
      "SELECT count(*)::int AS count FROM openarc_durable.payment_attempts WHERE organization_id = $1",
      [organizationId],
    );
    return result.rows[0]?.count ?? 0;
  });
}

/**
 * FIXTURE ONLY: record what the local fake reported, through the
 * migrator-private observation recorder. No runtime role can execute this
 * function and no route reaches it, which is exactly why a dispatched attempt
 * otherwise stays `unknown` and held. Recording an observation is not a
 * settlement and does not release exposure.
 */
export async function recordFixtureObservation(
  organizationId: string,
  attemptId: string,
  observedState: "pending" | "committed",
  transferId: string,
  gatewayStatus: string,
  batchTxHash: string | null,
): Promise<string> {
  assertEnabled();
  if (!ATTEMPT.test(attemptId) || !ORG.test(organizationId)) {
    throw new PaymentFixtureError("FIXTURE_INPUT_INVALID");
  }
  return withPool("migrator", async (_db, pool) => {
    const result = await pool.query<{ out_state: string }>(
      `SELECT out_state FROM openarc_durable.record_payment_attempt_observation(
         $1, $2::uuid, $3, $4::uuid, $5, $6)`,
      [organizationId, attemptId, observedState, transferId, gatewayStatus, batchTxHash],
    );
    const state = result.rows[0]?.out_state;
    if (state === undefined) throw new PaymentFixtureError("FIXTURE_UNAVAILABLE");
    return state;
  });
}
