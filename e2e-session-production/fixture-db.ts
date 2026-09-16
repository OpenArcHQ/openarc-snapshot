import { randomBytes, randomUUID } from "node:crypto";
import { realpathSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Type-only imports do not execute these modules. Pool types are derived from
// the workspace signatures, which resolve their own `pg` dependency.
import type { adminPool } from "../packages/db/test/postgres-fixture.js";
import type { createDatabasePool } from "../packages/db/src/index.js";

// Pure production crypto primitives: hashing a canonical handoff/session token
// is deterministic and side-effect free. They are imported READONLY so the DB
// hash-equality evidence below is the REAL production digest, never a mirror.
import {
  hashCommerceHandoffToken,
  hashCommerceSessionToken,
} from "../apps/api/src/control/session-crypto.js";
import {
  createSessionIdempotencyKey,
} from "../apps/web/src/tenant/session-client.js";

// The accepted PORT-01 production fixtures own the guarded bootstrap, seeding,
// session and durable-row helpers. This session fixture imports them READONLY
// and adds only the bounded commerce-session observations and the explicit
// synthetic policy/machine-session setup the session journeys need. It never
// returns a session hash, token hash, cookie, CSRF value or idempotency key.
import {
  FIXTURE_ERRORS,
  TenantFixtureError,
  countDurableRows as countAcceptedDurableRows,
  prepareProductionFixture,
  readDurableReceipt as readAcceptedDurableReceipt,
  seedAccount,
  seedAgents,
  seedMembership,
  seedOrganizationWithRole,
  seedOwnOrganizations,
  seedProviders,
} from "../e2e-tenant-write-production/fixture-db.js";

export {
  FIXTURE_ERRORS,
  TenantFixtureError,
  prepareProductionFixture,
  seedAccount,
  seedAgents,
  seedMembership,
  seedOrganizationWithRole,
  seedOwnOrganizations,
  seedProviders,
};
export type {
  DurableMutationCounts,
  DurableReceiptRow,
} from "../e2e-tenant-write-production/fixture-db.js";
export type {
  SeededOrganization,
  SeededProfile,
} from "../e2e-tenant-production/fixture-db.js";

type AdminPool = ReturnType<typeof adminPool>;
type DbPool = ReturnType<typeof createDatabasePool>;

/**
 * Bounded, test-only commerce-session fixture.
 *
 * This module is never imported by the web app or the API. Every function runs
 * behind BOTH `OPENARC_SESSION_PRODUCTION_FIXTURE=1` and
 * `OPENARC_TENANT_PRODUCTION_FIXTURE=1`, and the accepted
 * `packages/db/test/postgres-fixture.ts` guard asserts the exact synthetic
 * loopback PostgreSQL URL BEFORE any connection. It exposes no arbitrary SQL,
 * no raw handoff/session token, no token hash, no cookie and no idempotency key.
 * Every failure is a fixed non-echoing text.
 *
 * The commerce-session BUSINESS rows are always created through the real HTTP
 * API by the journey itself. This fixture only:
 *   - seeds synthetic organizations/agents/memberships;
 *   - preprovisions a REAL policy through the accepted `ControlPolicyStore`;
 *   - preprovisions a REAL agent credential + agent session through the
 *     accepted `CredentialStore`, using the actual production token
 *     generate/hash primitives (the raw `oas_ag_` token is returned to the
 *     caller's test memory ONLY and is never logged or asserted on);
 *   - performs bounded, non-secret observations (counts and hash-equality
 *     booleans) over those rows.
 */

const SESSION_FIXTURE_FLAG = "OPENARC_SESSION_PRODUCTION_FIXTURE";
const TENANT_FIXTURE_FLAG = "OPENARC_TENANT_PRODUCTION_FIXTURE";

const CANONICAL_ACCOUNT_ID =
  /^openarc:account:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CANONICAL_ORGANIZATION_ID =
  /^openarc:org:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CANONICAL_AGENT_ID =
  /^openarc:agent:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CANONICAL_POLICY_ID =
  /^openarc:policy:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CANONICAL_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;

function fail(code: (typeof FIXTURE_ERRORS)[keyof typeof FIXTURE_ERRORS]): never {
  throw new TenantFixtureError(code);
}

function assertEnabled(): void {
  if (process.env[SESSION_FIXTURE_FLAG] !== "1") fail("FIXTURE_DISABLED");
  if (process.env[TENANT_FIXTURE_FLAG] !== "1") fail("FIXTURE_DISABLED");
}

async function loadFixtureModule() {
  assertEnabled();
  try {
    return await import("../packages/db/test/postgres-fixture.js");
  } catch {
    fail("FIXTURE_UNAVAILABLE");
  }
}

async function loadDbModule() {
  assertEnabled();
  try {
    return await import("../packages/db/src/index.js");
  } catch {
    fail("FIXTURE_UNAVAILABLE");
  }
}

async function withAdmin<T>(work: (admin: AdminPool) => Promise<T>): Promise<T> {
  assertEnabled();
  const fixture = await loadFixtureModule();
  let admin: AdminPool | undefined;
  try {
    admin = fixture.adminPool();
    return await work(admin);
  } catch (error) {
    if (error instanceof TenantFixtureError) throw error;
    throw fixtureUnavailable(error);
  } finally {
    if (admin !== undefined) await admin.end().catch(() => undefined);
  }
}

function requireCanonicalAccountId(value: unknown): string {
  if (typeof value !== "string" || !CANONICAL_ACCOUNT_ID.test(value)) {
    fail("FIXTURE_INPUT_INVALID");
  }
  return value;
}

function requireCanonicalOrganizationId(value: unknown): string {
  if (typeof value !== "string" || !CANONICAL_ORGANIZATION_ID.test(value)) {
    fail("FIXTURE_INPUT_INVALID");
  }
  return value;
}

function requireCanonicalAgentId(value: unknown): string {
  if (typeof value !== "string" || !CANONICAL_AGENT_ID.test(value)) {
    fail("FIXTURE_INPUT_INVALID");
  }
  return value;
}

function requireCanonicalPolicyId(value: unknown): string {
  if (typeof value !== "string" || !CANONICAL_POLICY_ID.test(value)) {
    fail("FIXTURE_INPUT_INVALID");
  }
  return value;
}

function requireCanonicalUuid(value: unknown): string {
  if (typeof value !== "string" || !CANONICAL_UUID.test(value)) {
    fail("FIXTURE_INPUT_INVALID");
  }
  return value;
}

const HEX64 = /^[0-9a-f]{64}$/u;

function requireCanonicalHandoffToken(value: unknown): string {
  if (
    typeof value !== "string" ||
    !/^oach_v1_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/u.test(value)
  ) {
    fail("FIXTURE_INPUT_INVALID");
  }
  return value;
}

function requireCanonicalSessionToken(value: unknown): string {
  if (
    typeof value !== "string" ||
    !/^oacs_v1_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/u.test(value)
  ) {
    fail("FIXTURE_INPUT_INVALID");
  }
  return value;
}

/* -------------------------------------------------------------------------- */
/* Guarded durable observations (both opt-ins enforced before connect)         */
/* -------------------------------------------------------------------------- */

/** Exact per-receipt durable counts for one logical session mutation. */
export async function countDurableRows(
  organizationId: unknown,
  mutationId: unknown,
) {
  assertEnabled();
  return countAcceptedDurableRows(organizationId, mutationId);
}

/** Exact committed receipt fields for a session mutation, or null. */
export async function readDurableReceipt(
  organizationId: unknown,
  mutationId: unknown,
) {
  assertEnabled();
  return readAcceptedDurableReceipt(organizationId, mutationId);
}

/* -------------------------------------------------------------------------- */
/* Real policy + machine-session preprovision (same human/agent)               */
/* -------------------------------------------------------------------------- */

export interface SeededPolicy {
  readonly policyId: string;
}

/**
 * Returns the account's CURRENT live session hash for the accepted restricted
 * store calls. The hash is internal to this module and is NEVER returned to the
 * caller, logged or asserted on. It is read with the guarded admin pool only.
 */
async function currentSessionHash(accountId: string): Promise<string> {
  return withAdmin(async (admin) => {
    const result = await admin.query<{ token_hash: string }>(
      `SELECT token_hash FROM openarc_auth.sessions
        WHERE account_id = $1 AND expires_at > clock_timestamp()
        ORDER BY created_at DESC LIMIT 1`,
      [accountId],
    );
    const row = result.rows[0];
    if (row === undefined || !HEX64.test(row.token_hash)) {
      fail("FIXTURE_UNAVAILABLE");
    }
    return row.token_hash;
  });
}

async function withTenantPool<T>(work: (db: Awaited<ReturnType<typeof loadDbModule>>, pool: DbPool) => Promise<T>): Promise<T> {
  assertEnabled();
  const fixture = await loadFixtureModule();
  const db = await loadDbModule();
  let pool: DbPool | undefined;
  try {
    pool = db.createDatabasePool(fixture.tenantUrl());
    return await work(db, pool);
  } catch (error) {
    if (error instanceof TenantFixtureError) throw error;
    // The public message stays fixed, but a bare FIXTURE_UNAVAILABLE hides
    // transient pool failures and makes every future flake undiagnosable.
    // Carry the reason as a redacted cause; never surface a connection string.
    throw fixtureUnavailable(error);
  } finally {
    if (pool !== undefined) await pool.end().catch(() => undefined);
  }
}

/** FIXTURE_UNAVAILABLE carrying a redacted reason, never a connection string. */
function fixtureUnavailable(error: unknown): TenantFixtureError {
  const detail = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
  const unavailable = new TenantFixtureError("FIXTURE_UNAVAILABLE");
  (unavailable as { cause?: unknown }).cause = detail.replace(
    /postgres:\/\/\S*/gu,
    "postgres://[redacted]",
  );
  return unavailable;
}

/**
 * Preprovision ONE real active policy for the SAME human/agent through the
 * accepted `ControlPolicyStore`. No session business row is created. Only the
 * non-secret policy id is returned.
 */
export async function seedPolicyForAgent(
  accountId: unknown,
  organizationId: unknown,
  agentId: unknown,
): Promise<SeededPolicy> {
  const account = requireCanonicalAccountId(accountId);
  const organization = requireCanonicalOrganizationId(organizationId);
  const agent = requireCanonicalAgentId(agentId);
  const sessionHash = await currentSessionHash(account);
  return withTenantPool(async (db, pool) => {
    const store = new db.ControlPolicyStore(db.asTenantPool(pool));
    await store.initialize();
    const content = {
      organizationId: organization,
      subjectAgentId: agent,
      networkId: "eip155:5042002",
      asset: "USDC",
      representation: "erc20",
      decimals: 6,
      perActionLimit: "1000000",
      rollingLimit: null,
      rollingWindowSeconds: null,
      feeLimit: "10000",
      allowedProviderIds: [],
      allowedListingIds: [],
      approval: { mode: "none", threshold: null, separateApprover: false },
      expiresAt: null,
    };
    const metadata = {
      idempotencyKey: createSessionIdempotencyKey(),
      mutationId: randomUUID(),
    };
    const result = await store.createPolicy(sessionHash, organization, content, metadata);
    // The DB generates the canonical policy id; the locally attempted id is
    // never used. Only the receipt's non-secret resource id is returned.
    const policyId = requireCanonicalPolicyId(result.receipt.resourceId);
    return { policyId };
  });
}

export interface SeededAgentMachineSession {
  readonly credentialId: string;
  readonly sessionId: string;
  /**
   * Raw synthetic `oas_ag_` session token for the SAME human/agent. It exists
   * ONLY in the caller's test memory; the fixture never logs or returns it from
   * any DB read, and the caller MUST NOT persist, print or embed it.
   */
  readonly agentToken: string;
}

/**
 * Preprovision ONE real agent credential and ONE real agent session for the
 * SAME human/agent through the accepted `CredentialStore`, then extend it into
 * a live session using the ACTUAL production token generate/hash primitives.
 * Only the non-secret credential/session ids and the raw token (test memory
 * only) are returned.
 */
export async function seedAgentMachineSession(
  accountId: unknown,
  organizationId: unknown,
  agentId: unknown,
  expiresInSeconds: unknown,
): Promise<SeededAgentMachineSession> {
  assertEnabled();
  const account = requireCanonicalAccountId(accountId);
  const organization = requireCanonicalOrganizationId(organizationId);
  const agent = requireCanonicalAgentId(agentId);
  if (
    typeof expiresInSeconds !== "number" ||
    !Number.isInteger(expiresInSeconds) ||
    expiresInSeconds < 1 ||
    expiresInSeconds > 86_400
  ) {
    fail("FIXTURE_INPUT_INVALID");
  }
  const sessionHash = await currentSessionHash(account);
  const machineToken = await import("../apps/api/src/machine/session-token.js");
  const rawToken = machineToken.generateSessionToken("agent");
  const tokenHash = machineToken.hashSessionToken("agent", rawToken);
  return withTenantPool(async (db, pool) => {
    const store = new db.CredentialStore(db.asCredentialPool(pool));
    await store.initialize();
    const credentialId = randomUUID();
    const lookupId = randomUUID();
    const expiresAt = new Date(Date.now() + expiresInSeconds * 1000).toISOString();
    const hashInput = {
      algorithm: "scrypt" as const,
      hashVersion: 1 as const,
      pepperVersion: 1,
      N: 32768 as const,
      r: 8 as const,
      p: 1 as const,
      salt: randomBytes(16).toString("base64url"),
      digest: randomBytes(32).toString("base64url"),
    };
    db.parseCredentialHashInput(hashInput);
    await store.issueAgentCredentialDurably({
      sessionHash,
      organizationId: organization,
      profileId: agent,
      lookupId,
      hash: hashInput,
      expiresAt,
      metadata: {
        idempotencyKey: createSessionIdempotencyKey(),
        mutationId: credentialId,
      },
    });
    // The accepted `create_agent_session` helper caps a session at 15 minutes
    // (900s); the credential may live longer. Derive a session expiry inside
    // that bound AND inside the credential expiry.
    // schema05 refuses an agent session expiring later than the DATABASE clock
  // plus 15 minutes, but this value is computed on the CLIENT clock. Asking for
  // the full 900 s leaves zero margin, so any sub-second skew between the host
  // and the database container raises durable_expiry_invalid and the fixture
  // fails intermittently. Keep a margin well inside the cap.
  const sessionSeconds = Math.min(expiresInSeconds, 870);
    const sessionExpiresAt = new Date(Date.now() + sessionSeconds * 1000).toISOString();
    const session = await store.createAgentSession({
      organizationId: organization,
      profileId: agent,
      credentialId,
      expectedVersion: 1,
      sessionId: randomUUID(),
      tokenHash,
      expiresAt: sessionExpiresAt,
    });
    return { credentialId, sessionId: session.sessionId, agentToken: rawToken };
  });
}

/* -------------------------------------------------------------------------- */
/* Bounded commerce-session observations                                       */
/* -------------------------------------------------------------------------- */

export interface CommerceSessionRow {
  readonly sessionId: string;
  readonly organizationId: string;
  readonly subjectAgentId: string;
  readonly policyId: string;
  readonly exchangedAt: string | null;
  readonly revokedAt: string | null;
  readonly agentSessionId: string | null;
  readonly credentialId: string | null;
}

/**
 * Bounded non-secret read of ONE real commerce-session row. Hash/parent columns
 * are never selected; no token is representable.
 */
export async function readCommerceSession(
  organizationId: unknown,
  sessionId: unknown,
): Promise<CommerceSessionRow | null> {
  const organization = requireCanonicalOrganizationId(organizationId);
  const session = requireCanonicalUuid(sessionId);
  return withAdmin(async (admin) => {
    const result = await admin.query<{
      session_id: string;
      organization_id: string;
      subject_agent_id: string;
      policy_id: string;
      exchanged_at: Date | null;
      revoked_at: Date | null;
      agent_session_id: string | null;
      credential_id: string | null;
    }>(
      `SELECT session_id::text AS session_id, organization_id, subject_agent_id,
              policy_id, exchanged_at, revoked_at, agent_session_id::text AS agent_session_id,
              credential_id::text AS credential_id
         FROM openarc_durable.commerce_sessions
        WHERE organization_id = $1 AND session_id = $2::uuid`,
      [organization, session],
    );
    const row = result.rows[0];
    if (row === undefined) return null;
    return {
      sessionId: row.session_id,
      organizationId: row.organization_id,
      subjectAgentId: row.subject_agent_id,
      policyId: row.policy_id,
      exchangedAt: row.exchanged_at === null ? null : row.exchanged_at.toISOString(),
      revokedAt: row.revoked_at === null ? null : row.revoked_at.toISOString(),
      agentSessionId: row.agent_session_id,
      credentialId: row.credential_id,
    };
  });
}

export interface SessionRowCounts {
  readonly sessions: number;
  readonly handoffs: number;
}

/** Exact bounded counts for one session: one business row and one handoff. */
export async function countSessionRows(
  organizationId: unknown,
  sessionId: unknown,
): Promise<SessionRowCounts> {
  const organization = requireCanonicalOrganizationId(organizationId);
  const session = requireCanonicalUuid(sessionId);
  return withAdmin(async (admin) => {
    const result = await admin.query<{ sessions: number; handoffs: number }>(
      `SELECT
         (SELECT count(*)::int FROM openarc_durable.commerce_sessions
           WHERE organization_id = $1 AND session_id = $2::uuid) AS sessions,
         (SELECT count(*)::int FROM openarc_durable.commerce_session_handoffs
           WHERE organization_id = $1 AND session_id = $2::uuid) AS handoffs`,
      [organization, session],
    );
    const row = result.rows[0];
    return { sessions: row?.sessions ?? 0, handoffs: row?.handoffs ?? 0 };
  });
}

/**
 * Boolean production hash equality for the persisted handoff hash WITHOUT
 * returning the hash. The comparison happens in this module and only a boolean
 * crosses back.
 */
export async function handoffHashMatches(
  organizationId: unknown,
  sessionId: unknown,
  rawHandoffToken: unknown,
): Promise<boolean> {
  const organization = requireCanonicalOrganizationId(organizationId);
  const session = requireCanonicalUuid(sessionId);
  const raw = requireCanonicalHandoffToken(rawHandoffToken);
  let expected: string;
  try {
    expected = hashCommerceHandoffToken(raw);
  } catch {
    fail("FIXTURE_INPUT_INVALID");
  }
  return withAdmin(async (admin) => {
    const result = await admin.query<{ matches: boolean }>(
      `SELECT count(*)::int = 1 AS matches
         FROM openarc_durable.commerce_session_handoffs
        WHERE organization_id = $1 AND session_id = $2::uuid
          AND handoff_hash = $3 AND hash_version = 1`,
      [organization, session, expected],
    );
    return result.rows[0]?.matches === true;
  });
}

/**
 * Boolean production hash equality for the persisted session token hash
 * WITHOUT returning the hash. Only a boolean crosses back.
 */
export async function sessionTokenHashMatches(
  organizationId: unknown,
  sessionId: unknown,
  rawSessionToken: unknown,
): Promise<boolean> {
  const organization = requireCanonicalOrganizationId(organizationId);
  const session = requireCanonicalUuid(sessionId);
  const raw = requireCanonicalSessionToken(rawSessionToken);
  let expected: string;
  try {
    expected = hashCommerceSessionToken(raw);
  } catch {
    fail("FIXTURE_INPUT_INVALID");
  }
  return withAdmin(async (admin) => {
    const result = await admin.query<{ matches: boolean }>(
      `SELECT count(*)::int = 1 AS matches
         FROM openarc_durable.commerce_session_handoffs
        WHERE organization_id = $1 AND session_id = $2::uuid
          AND token_hash = $3 AND token_hash_version = 1
          AND consumed_at IS NOT NULL`,
      [organization, session, expected],
    );
    return result.rows[0]?.matches === true;
  });
}

/** True when the session has a persisted, consumed handoff (exchange happened). */
export async function hasConsumedHandoff(
  organizationId: unknown,
  sessionId: unknown,
): Promise<boolean> {
  const organization = requireCanonicalOrganizationId(organizationId);
  const session = requireCanonicalUuid(sessionId);
  return withAdmin(async (admin) => {
    const result = await admin.query<{ matches: boolean }>(
      `SELECT count(*)::int = 1 AS matches
         FROM openarc_durable.commerce_session_handoffs
        WHERE organization_id = $1 AND session_id = $2::uuid
          AND consumed_at IS NOT NULL`,
      [organization, session],
    );
    return result.rows[0]?.matches === true;
  });
}

function isDirectRun(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  try {
    return (
      realpathSync(resolve(entry)) === realpathSync(fileURLToPath(import.meta.url))
    );
  } catch {
    return false;
  }
}

if (isDirectRun()) {
  // Any direct invocation is import-only: no DB operation runs. The accepted
  // prepare entry point stays owned by the read production fixture.
  void requireCanonicalPolicyId;
}
