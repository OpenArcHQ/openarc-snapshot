import { realpathSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Type-only import: derives the admin pool shape without executing the module.
import type { adminPool } from "../packages/db/test/postgres-fixture.js";

// The accepted PORT-01 production fixtures own the guarded bootstrap, seeding,
// session and durable-row helpers. This control fixture imports them READONLY
// and adds only the bounded policy root/revision/durable observations the
// policy journeys need. It does not copy the ~600-line guarded setup, and it
// never returns a session hash, token, cookie, CSRF value or idempotency key.
import {
  FIXTURE_ERRORS,
  TenantFixtureError,
  countDurableRows as countTenantDurableRows,
  readDurableReceipt as readTenantDurableReceipt,
  seedAccount as seedTenantAccount,
  seedAgents as seedTenantAgents,
  seedOrganizationWithRole as seedTenantOrganizationWithRole,
  seedOwnOrganizations as seedTenantOwnOrganizations,
} from "../e2e-tenant-write-production/fixture-db.js";

export { FIXTURE_ERRORS, TenantFixtureError };
export type {
  DurableMutationCounts,
  DurableReceiptRow,
} from "../e2e-tenant-write-production/fixture-db.js";
export type {
  SeededOrganization,
  SeededProfile,
} from "../e2e-tenant-production/fixture-db.js";

type AdminPool = ReturnType<typeof adminPool>;

/**
 * Bounded, test-only control-policy durable observations.
 *
 * This module is never imported by the web app or the API. Every function runs
 * behind BOTH `OPENARC_CONTROL_PRODUCTION_FIXTURE=1` and
 * `OPENARC_TENANT_PRODUCTION_FIXTURE=1`, and the accepted
 * `packages/db/test/postgres-fixture.ts` guard asserts the exact synthetic
 * loopback PostgreSQL URL BEFORE any connection. It exposes no arbitrary SQL,
 * no session hash, no CSRF token, no idempotency key, no cookie and no policy
 * content insert. Every failure is a fixed non-echoing text.
 */

const CONTROL_FIXTURE_FLAG = "OPENARC_CONTROL_PRODUCTION_FIXTURE";
const TENANT_FIXTURE_FLAG = "OPENARC_TENANT_PRODUCTION_FIXTURE";

const CANONICAL_ORGANIZATION_ID =
  /^openarc:org:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CANONICAL_POLICY_ID =
  /^openarc:policy:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CANONICAL_REVISION = /^[1-9][0-9]{0,8}$/u;

function fail(code: (typeof FIXTURE_ERRORS)[keyof typeof FIXTURE_ERRORS]): never {
  throw new TenantFixtureError(code);
}

function assertControlEnabled(): void {
  if (process.env[CONTROL_FIXTURE_FLAG] !== "1") fail("FIXTURE_DISABLED");
  if (process.env[TENANT_FIXTURE_FLAG] !== "1") fail("FIXTURE_DISABLED");
}

function invalidInput(): never {
  fail("FIXTURE_INPUT_INVALID");
}

/**
 * Loads the accepted guarded fixture module (which asserts the exact synthetic
 * loopback database URL at import time) ONLY after both explicit opt-ins are
 * set. The guard runs before any connection.
 */
async function loadFixtureModule() {
  assertControlEnabled();
  try {
    return await import("../packages/db/test/postgres-fixture.js");
  } catch {
    fail("FIXTURE_UNAVAILABLE");
  }
}

async function withAdmin<T>(work: (admin: AdminPool) => Promise<T>): Promise<T> {
  assertControlEnabled();
  const fixture = await loadFixtureModule();
  let admin: AdminPool | undefined;
  try {
    admin = fixture.adminPool();
    return await work(admin);
  } catch (error) {
    if (error instanceof TenantFixtureError) throw error;
    throw new TenantFixtureError("FIXTURE_UNAVAILABLE");
  } finally {
    if (admin !== undefined) await admin.end().catch(() => undefined);
  }
}

function requireCanonicalOrganizationId(value: unknown): string {
  if (typeof value !== "string" || !CANONICAL_ORGANIZATION_ID.test(value)) invalidInput();
  return value;
}

function requireCanonicalPolicyId(value: unknown): string {
  if (typeof value !== "string" || !CANONICAL_POLICY_ID.test(value)) invalidInput();
  return value;
}

function requireCanonicalRevision(value: unknown): string {
  if (typeof value !== "string" || !CANONICAL_REVISION.test(value)) invalidInput();
  return value;
}

/* -------------------------------------------------------------------------- */
/* Guarded seed wrappers (both explicit opt-ins enforced before connect)       */
/* -------------------------------------------------------------------------- */

/**
 * Create one synthetic active account with no credential. Returns its id. The
 * accepted tenant guard is still authoritative for the connection.
 */
export async function seedAccount(): Promise<string> {
  assertControlEnabled();
  return seedTenantAccount();
}

export async function seedOwnOrganizations(
  accountId: unknown,
  displayNames: readonly string[],
) {
  assertControlEnabled();
  return seedTenantOwnOrganizations(accountId, displayNames);
}

export async function seedOrganizationWithRole(
  ownerAccountId: unknown,
  memberAccountId: unknown,
  displayName: unknown,
  role: unknown,
) {
  assertControlEnabled();
  return seedTenantOrganizationWithRole(
    ownerAccountId,
    memberAccountId,
    displayName,
    role,
  );
}

export async function seedAgents(organizationId: unknown, count: unknown) {
  assertControlEnabled();
  return seedTenantAgents(organizationId, count);
}

/* -------------------------------------------------------------------------- */
/* Bounded durable-policy observations                                         */
/* -------------------------------------------------------------------------- */

/**
 * Exact per-receipt durable counts for one logical mutation. A committed write
 * must have exactly one idempotency row, one audit row and one outbox row for
 * its mutation id.
 */
export async function countDurableRows(
  organizationId: unknown,
  mutationId: unknown,
) {
  assertControlEnabled();
  return countTenantDurableRows(organizationId, mutationId);
}

/** Exact committed receipt fields for a mutation, or null when absent. */
export async function readDurableReceipt(
  organizationId: unknown,
  mutationId: unknown,
) {
  assertControlEnabled();
  return readTenantDurableReceipt(organizationId, mutationId);
}

export interface PolicyRootRow {
  readonly organizationId: string;
  readonly policyId: string;
  readonly subjectAgentId: string;
  readonly currentRevision: string;
  readonly status: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

/**
 * Bounded direct read of one real `openarc_tenant.budget_policy_roots` row.
 * Only the non-secret lifecycle leaves are projected; no arbitrary SQL and no
 * actor key is returned.
 */
export async function readPolicyRoot(
  organizationId: unknown,
  policyId: unknown,
): Promise<PolicyRootRow | null> {
  const organization = requireCanonicalOrganizationId(organizationId);
  const policy = requireCanonicalPolicyId(policyId);
  return withAdmin(async (admin) => {
    const result = await admin.query<{
      policy_id: string;
      subject_agent_id: string;
      current_revision: string;
      status: string;
      created_at: string;
      updated_at: string;
    }>(
      `SELECT policy_id, subject_agent_id, current_revision, status,
              to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at,
              to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS updated_at
         FROM openarc_tenant.budget_policy_roots
        WHERE organization_id = $1 AND policy_id = $2`,
      [organization, policy],
    );
    const row = result.rows[0];
    if (row === undefined) return null;
    return {
      organizationId: organization,
      policyId: row.policy_id,
      subjectAgentId: row.subject_agent_id,
      currentRevision: row.current_revision,
      status: row.status,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  });
}

export interface PolicyRevisionRow {
  readonly revision: string;
  readonly subjectAgentId: string;
  readonly perActionLimit: string | null;
  readonly rollingLimit: string | null;
  readonly rollingWindowSeconds: string | null;
  readonly feeLimit: string;
  readonly allowedProviderIds: readonly string[];
  readonly allowedListingIds: readonly string[];
  readonly approvalMode: string;
  readonly approvalThreshold: string | null;
  readonly approvalSeparateApprover: boolean;
  readonly expiresAt: string | null;
  readonly digest: string;
  readonly createdAt: string;
}

/**
 * Bounded direct read of one immutable `openarc_tenant.budget_policy_versions`
 * row. Only the frozen content leaves are projected; no actor, key or raw
 * payload is exposed.
 */
export async function readPolicyRevision(
  organizationId: unknown,
  policyId: unknown,
  revision: unknown,
): Promise<PolicyRevisionRow | null> {
  const organization = requireCanonicalOrganizationId(organizationId);
  const policy = requireCanonicalPolicyId(policyId);
  const parsedRevision = requireCanonicalRevision(revision);
  return withAdmin(async (admin) => {
    const result = await admin.query<{
      revision: string;
      subject_agent_id: string;
      per_action_limit: string | null;
      rolling_limit: string | null;
      rolling_window_seconds: string | null;
      fee_limit: string;
      allowed_provider_ids: string[];
      allowed_listing_ids: string[];
      approval_mode: string;
      approval_threshold: string | null;
      approval_separate_approver: boolean;
      expires_at: string | null;
      digest: string;
      created_at: string;
    }>(
      `SELECT revision, subject_agent_id, per_action_limit, rolling_limit,
              rolling_window_seconds, fee_limit, allowed_provider_ids,
              allowed_listing_ids, approval_mode, approval_threshold,
              approval_separate_approver,
              to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS expires_at,
              digest,
              to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at
         FROM openarc_tenant.budget_policy_versions
        WHERE organization_id = $1 AND policy_id = $2 AND revision = $3`,
      [organization, policy, parsedRevision],
    );
    const row = result.rows[0];
    if (row === undefined) return null;
    return {
      revision: row.revision,
      subjectAgentId: row.subject_agent_id,
      perActionLimit: row.per_action_limit,
      rollingLimit: row.rolling_limit,
      rollingWindowSeconds: row.rolling_window_seconds,
      feeLimit: row.fee_limit,
      allowedProviderIds: row.allowed_provider_ids,
      allowedListingIds: row.allowed_listing_ids,
      approvalMode: row.approval_mode,
      approvalThreshold: row.approval_threshold,
      approvalSeparateApprover: row.approval_separate_approver,
      expiresAt: row.expires_at,
      digest: row.digest,
      createdAt: row.created_at,
    };
  });
}

/** Count the immutable revision rows for one real policy root. */
export async function countPolicyRevisions(
  organizationId: unknown,
  policyId: unknown,
): Promise<number> {
  const organization = requireCanonicalOrganizationId(organizationId);
  const policy = requireCanonicalPolicyId(policyId);
  return withAdmin(async (admin) => {
    const result = await admin.query<{ count: number }>(
      `SELECT count(*)::int AS count
         FROM openarc_tenant.budget_policy_versions
        WHERE organization_id = $1 AND policy_id = $2`,
      [organization, policy],
    );
    return result.rows[0]?.count ?? 0;
  });
}

function isDirectRun(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  try {
    return realpathSync(resolve(entry)) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isDirectRun()) {
  // Any direct invocation is import-only: no DB operation runs. Prepare/migrate
  // stays owned by the accepted read production fixture and runs once BEFORE
  // API startup, never from a test hook.
  void realpathSync;
}
