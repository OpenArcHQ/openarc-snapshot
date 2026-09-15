import { createHash, randomBytes, randomUUID } from "node:crypto";

import {
  asControlPolicyPool,
  AuthStore,
  ControlPolicyStore,
  createDatabasePool,
  migrate,
} from "@openarc/db";
import {
  COMMERCE_API_SCHEMA_VERSION,
  CommercePolicyMutationResultResponseSchema,
  CommercePolicyRootPageResponseSchema,
  CommercePolicyRootDetailResponseSchema,
  CommercePolicyHistoryPageResponseSchema,
  CommercePolicyRevisionDetailResponseSchema,
  CommercePolicyMutationStatusResponseSchema,
  ControlCapabilitiesSuccessEnvelopeSchema,
  CONTROL_CAPABILITIES_PATH,
  CONTROL_ROUTE_IDS,
} from "@openarc/shared";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { createApp } from "../src/app.js";
import { deriveCsrfToken, issueBindingCookie } from "../src/auth/cookies.js";
import type { AuthProofPort, AuthRuntime } from "../src/auth/ports.js";
import type { AuthOriginConfig } from "../src/auth/proofs.js";
import { AuthService, type AuthServiceConfig } from "../src/auth/service.js";
import { loadConfig } from "../src/config.js";
import { startControlRuntime, type StartedControlRuntime } from "../src/control/runtime.js";
import { PolicyService } from "../src/control/service.js";
import type {
  ControlPolicyAuthPort,
  ControlPolicyStorePort,
} from "../src/control/ports.js";
import {
  adminPool,
  appUrl,
  ensureRoles,
  migratorUrl,
  resetSchema,
  tenantUrl,
} from "../../../packages/db/test/postgres-fixture.js";

/**
 * Real API + PostgreSQL acceptance for the protected control policy family.
 *
 * The runtime objects under test are the REAL accepted implementations:
 * AuthService + AuthStore, ControlPolicyStore, PolicyService and
 * createApp/startControlRuntime, over the disposable restricted fixture roles,
 * the real schema8 SQL migration, RLS, the SECURITY DEFINER policy helpers and
 * the real audit/outbox/idempotency tables. `app.inject` is HTTP/PostgreSQL
 * integration, NOT actual TLS, production browser or WebAuthn cryptography.
 * The WebAuthn/SIWE proof adapter is HONESTLY MOCKED (labelled): these tests
 * prove HTTP-to-SQL orchestration and enforcement, not cryptography.
 *
 * Privileged fixture setup provisions synthetic accounts, organizations,
 * memberships, roles and agents, and owns the lock/expiry races. No test
 * inserts into the policy roots/history, audit, outbox or idempotency tables to
 * fabricate business acceptance: every policy row is created through the
 * protected HTTP mutations and every denial is observed at the HTTP boundary.
 */

type Pool = ReturnType<typeof adminPool>;
type AppInstance = ReturnType<typeof createApp>;

const ORIGIN = "http://localhost:5183";
const RP_ID = "localhost";
const SECRET = "synthetic_auth_secret_for_control_policy_pg_0123456789";
const BUILD_SHA = "0123456789abcdef0123456789abcdef01234567";
const CLIENT = { origin: ORIGIN, "x-openarc-client": "browser-v1" };
const SESSION_COOKIE = "openarc_session";
const BINDING_COOKIE = "openarc_binding";
const PREFIX = "/v2/control/organizations";

function uuid(seed: number): string {
  return `00000000-0000-4000-8000-${String(seed).padStart(12, "0")}`;
}

function accountId(seed: number): string {
  return `openarc:account:${uuid(seed)}`;
}

function policyIdFor(mutationId: string): string {
  return `openarc:policy:${mutationId}`;
}

const ORG1 = `openarc:org:${uuid(1)}`;
const ORG2 = `openarc:org:${uuid(2)}`;
const AGENT1 = `openarc:agent:${uuid(1)}`;
const AGENT2 = `openarc:agent:${uuid(2)}`;
const AGENT_REVOKED = `openarc:agent:${uuid(3)}`;
const AGENT_ORG2 = `openarc:agent:${uuid(4)}`;
const PROVIDER1 = `openarc:provider:${uuid(1)}`;
const PROVIDER2 = `openarc:provider:${uuid(2)}`;
const LISTING1 = `openarc:listing:${uuid(1)}`;
const A = accountId(201); // ORG1 owner (writer)
const B = accountId(202); // ORG1 operator (writer)
const C = accountId(203); // ORG1 viewer (reader, no write)
const D = accountId(204); // ORG1 provider_admin (denied)
const E = accountId(205); // ORG1 provider_developer (denied)
const F = accountId(206); // ORG2 owner (cross-org denied)
const G = accountId(207); // no membership (denied)

function b64(bytes: number): string {
  return randomBytes(bytes).toString("base64url");
}

function tokenHash(token: string): string {
  return createHash("sha256").update(`openarc:session:v1:${token}`, "utf8").digest("hex");
}

function idempotencyKey(): string {
  return randomBytes(32).toString("base64url");
}

function fakeProofs(): AuthProofPort {
  return {
    validateAuthOriginConfig: (input: unknown): AuthOriginConfig => input as AuthOriginConfig,
  } as unknown as AuthProofPort;
}

function fakeRuntime(): AuthRuntime {
  return { randomBytes: (size) => randomBytes(size), now: () => new Date() };
}

/** Valid declared policy content; external provider/listing allowlists allowed. */
function content(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    organizationId: ORG1,
    subjectAgentId: AGENT1,
    networkId: "eip155:5042002",
    asset: "USDC",
    representation: "erc20",
    decimals: 6,
    perActionLimit: "1000000",
    rollingLimit: null,
    rollingWindowSeconds: null,
    feeLimit: "10000",
    allowedProviderIds: [PROVIDER1],
    allowedListingIds: [],
    approval: { mode: "none", threshold: null, separateApprover: false },
    expiresAt: null,
    ...overrides,
  };
}

let admin: Pool;
let migrator: Pool;
let app: Pool;
let tenant: Pool;

beforeAll(async () => {
  admin = adminPool();
  await ensureRoles(admin);
  migrator = createDatabasePool(migratorUrl());
});

afterAll(async () => {
  try {
    await resetSchema(admin);
  } finally {
    await migrator.end();
    await admin.end();
  }
});

async function seedAccount(account: string): Promise<void> {
  await admin.query(
    `INSERT INTO openarc_auth.accounts (account_id, user_handle, status)
     VALUES ($1, $2, 'active')`,
    [account, b64(32)],
  );
}

async function seedSession(
  token: string,
  account: string,
  options: {
    method?: "passkey" | "wallet" | "recovery";
    expiresInSeconds?: number;
    ageSeconds?: number;
    expired?: boolean;
  } = {},
): Promise<void> {
  // A live session needs `expires_at > created_at` within the frozen 24h
  // window; an expired one must place BOTH bounds in the past.
  const age = options.expired === true ? 120 : (options.ageSeconds ?? 0);
  const lifetime = options.expired === true ? -60 : (options.expiresInSeconds ?? 900);
  await admin.query(
    `INSERT INTO openarc_auth.sessions (token_hash, account_id, method, created_at, expires_at)
     VALUES ($1, $2, $3, clock_timestamp() - ($4 || ' seconds')::interval,
             clock_timestamp() + ($5 || ' seconds')::interval)`,
    [
      tokenHash(token),
      account,
      options.method ?? "passkey",
      String(age),
      String(lifetime),
    ],
  );
}

async function seedOrganization(organizationId: string, createdBy: string): Promise<void> {
  await admin.query(
    `INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by)
     VALUES ($1, 'Org', $2)`,
    [organizationId, createdBy],
  );
}

async function seedMembership(organizationId: string, account: string, role: string): Promise<void> {
  await admin.query(
    `INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status)
     VALUES ($1, $2, $3, 'active')`,
    [organizationId, account, role],
  );
}

async function seedAgent(
  organizationId: string,
  agentId: string,
  status: "active" | "suspended" | "revoked" = "active",
): Promise<void> {
  await admin.query(
    `INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name, status)
     VALUES ($1, $2, $3, $4)`,
    [organizationId, agentId, `Agent ${agentId.slice(-4)}`, status],
  );
}

async function count(sql: string, values: unknown[] = []): Promise<number> {
  const result = await admin.query<{ n: string }>(sql, values);
  return Number(result.rows[0]?.n ?? "0");
}

const tokens = new Map<string, string>();

beforeEach(async () => {
  await resetSchema(admin);
  await migrate(migrator);
  app = createDatabasePool(appUrl());
  tenant = createDatabasePool(tenantUrl());

  for (const account of [A, B, C, D, E, F, G]) {
    await seedAccount(account);
  }
  await seedOrganization(ORG1, A);
  await seedOrganization(ORG2, F);
  await seedMembership(ORG1, A, "owner");
  await seedMembership(ORG1, B, "operator");
  await seedMembership(ORG1, C, "viewer");
  await seedMembership(ORG1, D, "provider_admin");
  await seedMembership(ORG1, E, "provider_developer");
  await seedMembership(ORG2, F, "owner");
  await seedAgent(ORG1, AGENT1);
  await seedAgent(ORG1, AGENT2);
  await seedAgent(ORG1, AGENT_REVOKED, "revoked");
  await seedAgent(ORG2, AGENT_ORG2);

  tokens.clear();
  for (const [label, account] of [
    ["a", A],
    ["b", B],
    ["c", C],
    ["d", D],
    ["e", E],
    ["f", F],
    ["g", G],
  ] as ReadonlyArray<readonly [string, string]>) {
    const token = b64(32);
    tokens.set(label, token);
    await seedSession(token, account);
  }
});

afterEach(async () => {
  await tenant.end();
  await app.end();
});

function authService(): AuthService {
  return new AuthService({
    config: {
      authSecret: SECRET,
      appOrigin: ORIGIN,
      rpId: RP_ID,
      environment: "development",
      secureCookies: false,
      cookieNames: { session: SESSION_COOKIE, binding: BINDING_COOKIE },
    } satisfies AuthServiceConfig,
    store: new AuthStore(app),
    proofs: fakeProofs(),
    runtime: fakeRuntime(),
  });
}

function writeHeadersFor(label: string, extra: Record<string, string> = {}): Record<string, string> {
  const token = tokens.get(label) ?? "";
  const binding = issueBindingCookie(SECRET, b64(16), Date.now());
  return {
    ...CLIENT,
    "content-type": "application/json",
    cookie: `${SESSION_COOKIE}=${token}; ${BINDING_COOKIE}=${binding}`,
    "x-openarc-csrf": deriveCsrfToken(SECRET, binding, tokenHash(token)),
    "idempotency-key": idempotencyKey(),
    ...extra,
  };
}

function readHeadersFor(label: string, extra: Record<string, string> = {}): Record<string, string> {
  return { ...CLIENT, cookie: `${SESSION_COOKIE}=${tokens.get(label) ?? ""}`, ...extra };
}

const policiesUrl = (organizationId: string, suffix = ""): string =>
  `${PREFIX}/${organizationId}/policies${suffix}`;
const mutationUrl = (organizationId: string, mutationId: string): string =>
  `${PREFIX}/${organizationId}/policy-mutations/${mutationId}`;

function listRoots(instance: AppInstance, label: string, query = "", organizationId = ORG1) {
  return instance.inject({
    method: "GET",
    url: `${policiesUrl(organizationId)}${query}`,
    headers: readHeadersFor(label),
  });
}

type InjectResponse = Awaited<ReturnType<AppInstance["inject"]>>;

function errorCode(response: InjectResponse): string {
  return (response.json().error as { code: string }).code;
}

function buildFlags(overrides: Record<string, string> = {}): Record<string, string> {
  return {
    NODE_ENV: "test",
    APP_ORIGIN: ORIGIN,
    COMMIT_SHA: BUILD_SHA,
    AUTH_ENABLED: "true",
    AUTH_DATABASE_URL: appUrl(),
    AUTH_SECRET: SECRET,
    AUTH_RP_ID: RP_ID,
    TENANT_READS_ENABLED: "false",
    TENANT_WRITES_ENABLED: "false",
    TENANT_DATABASE_URL: tenantUrl(),
    POLICY_MANAGEMENT_ENABLED: "true",
    ...overrides,
  };
}

/**
 * Wire the REAL accepted store/service over the shared restricted fixture
 * pools with tenant HTTP reads/writes, machine and marketplace families OFF.
 * `store` is the concrete accepted ControlPolicyStore; a caller may pass an
 * explicit `service` override for the gated lock races.
 */
async function buildApp(options: {
  readonly store?: ControlPolicyStore;
  readonly service?: PolicyService;
  readonly flags?: Record<string, string>;
  readonly policyReady?: () => Promise<boolean>;
} = {}): Promise<AppInstance> {
  const auth = authService();
  let service = options.service;
  if (service === undefined) {
    const store = options.store ?? new ControlPolicyStore(asControlPolicyPool(tenant));
    await store.initialize();
    service = new PolicyService({ auth, store: store as unknown as ControlPolicyStorePort });
  }
  const config = loadConfig(buildFlags(options.flags));
  return createApp({
    config,
    logger: false,
    authService: auth,
    authReady: async () => true,
    policyManagementService: service,
    policyReady: options.policyReady ?? (async () => true),
  });
}

interface CreatedPolicy {
  readonly response: InjectResponse;
  readonly policyId: string;
  readonly mutationId: string;
  readonly key: string;
}

async function createPolicy(
  instance: AppInstance,
  label: string,
  overrides: Record<string, unknown> = {},
  organizationId = ORG1,
  extra: Record<string, string> = {},
): Promise<CreatedPolicy> {
  const mutationId = randomUUID();
  const key = idempotencyKey();
  const response = await instance.inject({
    method: "POST",
    url: policiesUrl(organizationId),
    headers: writeHeadersFor(label, { "idempotency-key": key, ...extra }),
    payload: { mutationId, content: content({ organizationId, ...overrides }) },
  });
  return { response, policyId: policyIdFor(mutationId), mutationId, key };
}

async function readRoot(instance: AppInstance, label: string, policyId: string, organizationId = ORG1) {
  return instance.inject({
    method: "GET",
    url: policiesUrl(organizationId, `/${policyId}`),
    headers: readHeadersFor(label),
  });
}

async function readHistory(instance: AppInstance, label: string, policyId: string, organizationId = ORG1) {
  return instance.inject({
    method: "GET",
    url: policiesUrl(organizationId, `/${policyId}/revisions`),
    headers: readHeadersFor(label),
  });
}

async function readRevision(
  instance: AppInstance,
  label: string,
  policyId: string,
  revision: string,
  organizationId = ORG1,
) {
  return instance.inject({
    method: "GET",
    url: policiesUrl(organizationId, `/${policyId}/revisions/${revision}`),
    headers: readHeadersFor(label),
  });
}

async function appendRevision(
  instance: AppInstance,
  label: string,
  policyId: string,
  expectedRevision: string,
  expectedUpdatedAt: string,
  overrides: Record<string, unknown> = {},
  extra: Record<string, string> = {},
  organizationId = ORG1,
) {
  const mutationId = randomUUID();
  const key = extra["idempotency-key"] ?? idempotencyKey();
  const response = await instance.inject({
    method: "POST",
    url: policiesUrl(organizationId, `/${policyId}/revisions`),
    headers: writeHeadersFor(label, { "idempotency-key": key, ...extra }),
    payload: {
      mutationId,
      expectedRevision,
      expectedUpdatedAt,
      content: content({ organizationId, ...overrides }),
    },
  });
  return { response, mutationId, key };
}

async function transition(
  instance: AppInstance,
  label: string,
  policyId: string,
  operation: "pause" | "resume" | "revoke",
  expectedRevision: string,
  expectedUpdatedAt: string,
  extra: Record<string, string> = {},
) {
  const mutationId = randomUUID();
  const key = extra["idempotency-key"] ?? idempotencyKey();
  const response = await instance.inject({
    method: "POST",
    url: policiesUrl(ORG1, `/${policyId}/${operation}`),
    headers: writeHeadersFor(label, { "idempotency-key": key, ...extra }),
    payload: { mutationId, expectedRevision, expectedUpdatedAt },
  });
  return { response, mutationId, key };
}

async function readStatus(instance: AppInstance, label: string, mutationId: string, organizationId = ORG1) {
  return instance.inject({
    method: "GET",
    url: mutationUrl(organizationId, mutationId),
    headers: readHeadersFor(label),
  });
}

async function assertNoDurableRecord(organizationId: string, mutationId: string): Promise<void> {
  expect(
    await count(
      `SELECT count(*)::text AS n FROM openarc_durable.idempotency_records
        WHERE organization_id = $1 AND mutation_id = $2::uuid`,
      [organizationId, mutationId],
    ),
  ).toBe(0);
  expect(
    await count(
      `SELECT count(*)::text AS n FROM openarc_durable.audit_events
        WHERE organization_id = $1 AND mutation_id = $2::uuid`,
      [organizationId, mutationId],
    ),
  ).toBe(0);
  expect(
    await count(
      `SELECT count(*)::text AS n FROM openarc_durable.outbox_events
        WHERE organization_id = $1 AND mutation_id = $2::uuid`,
      [organizationId, mutationId],
    ),
  ).toBe(0);
}

async function assertExactlyOneDurableRecord(
  organizationId: string,
  mutationId: string,
  resourceType: string,
): Promise<void> {
  expect(
    await count(
      `SELECT count(*)::text AS n FROM openarc_durable.idempotency_records
        WHERE organization_id = $1 AND mutation_id = $2::uuid AND resource_type = $3`,
      [organizationId, mutationId, resourceType],
    ),
  ).toBe(1);
  expect(
    await count(
      `SELECT count(*)::text AS n FROM openarc_durable.audit_events
        WHERE organization_id = $1 AND mutation_id = $2::uuid AND resource_type = $3`,
      [organizationId, mutationId, resourceType],
    ),
  ).toBe(1);
  expect(
    await count(
      `SELECT count(*)::text AS n FROM openarc_durable.outbox_events
        WHERE organization_id = $1 AND mutation_id = $2::uuid AND resource_type = $3`,
      [organizationId, mutationId, resourceType],
    ),
  ).toBe(1);
}

function parsedRoot(instance: AppInstance, response: InjectResponse, policyId: string) {
  expect(response.statusCode).toBe(200);
  const parsed = CommercePolicyRootDetailResponseSchema.parse(response.json());
  expect(parsed.data.policyId).toBe(policyId);
  if (parsed.data.item === null) throw new Error("root item missing");
  return parsed.data.item;
}

describe("real-PG control policy lifecycle over HTTP", () => {
  it("creates an immutable root, appends revisions, reads history/detail and reports committed status", async () => {
    const instance = await buildApp();

    const created = await createPolicy(instance, "a");
    expect(created.response.statusCode).toBe(200);
    const createdBody = CommercePolicyMutationResultResponseSchema.parse(created.response.json());
    expect(createdBody.data.receipt.operation).toBe("control.policy.create");
    expect(createdBody.data.receipt.resourceType).toBe("budget_policy");
    expect(createdBody.data.receipt.resourceId).toBe(created.policyId);
    expect(createdBody.data.replayed).toBe(false);
    expect(created.response.headers["set-cookie"]).toBeUndefined();
    expect(created.response.headers["cache-control"]).toBe("no-store");
    expect(created.response.headers["access-control-allow-origin"]).toBeUndefined();

    const root = parsedRoot(instance, await readRoot(instance, "a", created.policyId), created.policyId);
    expect(root.organizationId).toBe(ORG1);
    expect(root.subjectAgentId).toBe(AGENT1);
    expect(root.currentRevision).toBe("1");
    expect(root.status).toBe("active");

    const revision1 = await readRevision(instance, "a", created.policyId, "1");
    expect(revision1.statusCode).toBe(200);
    const revisionBody = CommercePolicyRevisionDetailResponseSchema.parse(revision1.json());
    expect(revisionBody.data.item).not.toBeNull();
    expect(revisionBody.data.item?.digest).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(revisionBody.data.item?.allowedProviderIds).toEqual([PROVIDER1]);

    const append2 = await appendRevision(instance, "a", created.policyId, "1", root.updatedAt);
    expect(append2.response.statusCode).toBe(200);
    const appendBody = CommercePolicyMutationResultResponseSchema.parse(append2.response.json());
    expect(appendBody.data.receipt.operation).toBe("control.policy.revision.create");
    expect(appendBody.data.receipt.resourceType).toBe("budget_policy_revision");
    expect(appendBody.data.receipt.resourceId).toBe(`${created.policyId}@2`);

    const afterAppend = parsedRoot(instance, await readRoot(instance, "a", created.policyId), created.policyId);
    expect(afterAppend.currentRevision).toBe("2");

    const append3 = await appendRevision(instance, "a", created.policyId, "2", afterAppend.updatedAt, {
      perActionLimit: "2000000",
    });
    expect(append3.response.statusCode).toBe(200);

    const history = await readHistory(instance, "a", created.policyId);
    expect(history.statusCode).toBe(200);
    const historyBody = CommercePolicyHistoryPageResponseSchema.parse(history.json());
    expect(historyBody.data.items.map((item) => item.revision)).toEqual(["1", "2", "3"]);
    // History is metadata-only: no full content, allowlists or approval.
    expect(history.body).not.toContain("allowedProviderIds");
    expect(history.body).not.toContain("approval");
    expect(historyBody.data.nextCursor).toBeNull();

    const revision3 = await readRevision(instance, "a", created.policyId, "3");
    const revision3Body = CommercePolicyRevisionDetailResponseSchema.parse(revision3.json());
    expect(revision3Body.data.item?.perActionLimit).toBe("2000000");

    const missing = await readRoot(instance, "a", policyIdFor(randomUUID()));
    expect(missing.statusCode).toBe(200);
    const missingBody = CommercePolicyRootDetailResponseSchema.parse(missing.json());
    expect(missingBody.data.item).toBeNull();

    const emptyHistory = await readHistory(instance, "a", policyIdFor(randomUUID()));
    expect(emptyHistory.statusCode).toBe(200);
    const emptyBody = CommercePolicyHistoryPageResponseSchema.parse(emptyHistory.json());
    expect(emptyBody.data.items).toEqual([]);
    expect(emptyBody.data.nextCursor).toBeNull();

    const status = await readStatus(instance, "a", created.mutationId);
    expect(status.statusCode).toBe(200);
    const statusBody = CommercePolicyMutationStatusResponseSchema.parse(status.json());
    expect(statusBody.data.status).toBe("committed");
    if (statusBody.data.status !== "committed") throw new Error("expected committed");
    expect(statusBody.data.receipt.operation).toBe("control.policy.create");
    expect(statusBody.data.receipt.resourceId).toBe(created.policyId);

    const notFound = await readStatus(instance, "a", randomUUID());
    expect(notFound.statusCode).toBe(200);
    const notFoundBody = CommercePolicyMutationStatusResponseSchema.parse(notFound.json());
    expect(notFoundBody.data.status).toBe("not_found");

    await assertExactlyOneDurableRecord(ORG1, created.mutationId, "budget_policy");
    await assertExactlyOneDurableRecord(ORG1, append2.mutationId, "budget_policy_revision");
    await assertExactlyOneDurableRecord(ORG1, append3.mutationId, "budget_policy_revision");
    expect(
      await count(
        `SELECT count(*)::text AS n FROM openarc_tenant.budget_policy_versions
          WHERE organization_id = $1 AND policy_id = $2`,
        [ORG1, created.policyId],
      ),
    ).toBe(3);
  });

  it("pauses, resumes and revokes with exact microsecond CAS and rejects stale tokens", async () => {
    const instance = await buildApp();
    const created = await createPolicy(instance, "a");
    expect(created.response.statusCode).toBe(200);
    const root1 = parsedRoot(instance, await readRoot(instance, "a", created.policyId), created.policyId);

    const pause = await transition(instance, "a", created.policyId, "pause", "1", root1.updatedAt);
    expect(pause.response.statusCode).toBe(200);
    const pauseBody = CommercePolicyMutationResultResponseSchema.parse(pause.response.json());
    expect(pauseBody.data.receipt.operation).toBe("control.policy.pause");
    expect(pauseBody.data.receipt.resourceId).toBe(created.policyId);

    const paused = parsedRoot(instance, await readRoot(instance, "a", created.policyId), created.policyId);
    expect(paused.status).toBe("paused");

    // The paused root can be renewed: a new revision may be appended while paused.
    const append = await appendRevision(instance, "a", created.policyId, "1", paused.updatedAt, {
      perActionLimit: "3000000",
    });
    expect(append.response.statusCode).toBe(200);

    // Reusing the pre-append CAS token is a stale microsecond CAS: 409, no durable row.
    const afterAppend = parsedRoot(instance, await readRoot(instance, "a", created.policyId), created.policyId);
    expect(afterAppend.currentRevision).toBe("2");
    const staleRevision = await transition(instance, "a", created.policyId, "resume", "1", afterAppend.updatedAt);
    expect(staleRevision.response.statusCode).toBe(409);
    expect(errorCode(staleRevision.response)).toBe("POLICY_DENIED");
    await assertNoDurableRecord(ORG1, staleRevision.mutationId);

    const staleUpdatedAt = await transition(
      instance,
      "a",
      created.policyId,
      "resume",
      "2",
      root1.updatedAt,
    );
    expect(staleUpdatedAt.response.statusCode).toBe(409);
    expect(errorCode(staleUpdatedAt.response)).toBe("POLICY_DENIED");
    await assertNoDurableRecord(ORG1, staleUpdatedAt.mutationId);

    const resume = await transition(instance, "a", created.policyId, "resume", "2", afterAppend.updatedAt);
    expect(resume.response.statusCode).toBe(200);
    const resumed = parsedRoot(instance, await readRoot(instance, "a", created.policyId), created.policyId);
    expect(resumed.status).toBe("active");

    const revoke = await transition(instance, "a", created.policyId, "revoke", "2", resumed.updatedAt);
    expect(revoke.response.statusCode).toBe(200);
    const revoked = parsedRoot(instance, await readRoot(instance, "a", created.policyId), created.policyId);
    expect(revoked.status).toBe("revoked");

    // A revoked root can never be resumed or appended to.
    const resumeRevoked = await transition(instance, "a", created.policyId, "resume", "2", revoked.updatedAt);
    expect(resumeRevoked.response.statusCode).toBe(400);
    await assertNoDurableRecord(ORG1, resumeRevoked.mutationId);
    const appendRevoked = await appendRevision(instance, "a", created.policyId, "2", revoked.updatedAt);
    expect(appendRevoked.response.statusCode).toBe(400);
    await assertNoDurableRecord(ORG1, appendRevoked.mutationId);

    await assertExactlyOneDurableRecord(ORG1, pause.mutationId, "budget_policy");
    await assertExactlyOneDurableRecord(ORG1, append.mutationId, "budget_policy_revision");
    await assertExactlyOneDurableRecord(ORG1, resume.mutationId, "budget_policy");
    await assertExactlyOneDurableRecord(ORG1, revoke.mutationId, "budget_policy");
  });

  it("replays the original receipt after a later state change without a duplicate audit/outbox row", async () => {
    const instance = await buildApp();
    const created = await createPolicy(instance, "a");
    expect(created.response.statusCode).toBe(200);
    const root = parsedRoot(instance, await readRoot(instance, "a", created.policyId), created.policyId);

    const pause = await transition(instance, "a", created.policyId, "pause", "1", root.updatedAt);
    expect(pause.response.statusCode).toBe(200);
    const afterPause = parsedRoot(instance, await readRoot(instance, "a", created.policyId), created.policyId);
    expect(afterPause.status).toBe("paused");

    // Replay the CREATE after the root moved to paused: same logical mutation,
    // same key, same request => the original receipt, never a new one.
    const replay = await instance.inject({
      method: "POST",
      url: policiesUrl(ORG1),
      headers: writeHeadersFor("a", { "idempotency-key": created.key }),
      payload: { mutationId: created.mutationId, content: content() },
    });
    expect(replay.statusCode).toBe(200);
    const replayBody = CommercePolicyMutationResultResponseSchema.parse(replay.json());
    expect(replayBody.data.replayed).toBe(true);
    expect(replayBody.data.receipt.resourceId).toBe(created.policyId);
    await assertExactlyOneDurableRecord(ORG1, created.mutationId, "budget_policy");
    await assertExactlyOneDurableRecord(ORG1, pause.mutationId, "budget_policy");
    expect(
      await count(
        `SELECT count(*)::text AS n FROM openarc_tenant.budget_policy_roots
          WHERE organization_id = $1 AND policy_id = $2`,
        [ORG1, created.policyId],
      ),
    ).toBe(1);
  });

  it("rejects changed body, changed key and reused mutationId with idempotency conflicts", async () => {
    const instance = await buildApp();
    const created = await createPolicy(instance, "a");
    expect(created.response.statusCode).toBe(200);

    // Same key, changed body => request-digest conflict.
    const changedBody = await instance.inject({
      method: "POST",
      url: policiesUrl(ORG1),
      headers: writeHeadersFor("a", { "idempotency-key": created.key }),
      payload: {
        mutationId: created.mutationId,
        content: content({ perActionLimit: "9999999" }),
      },
    });
    expect(changedBody.statusCode).toBe(409);
    expect(errorCode(changedBody)).toBe("IDEMPOTENCY_CONFLICT");

    // Changed key, same mutationId => mutation-id conflict.
    const changedKey = await instance.inject({
      method: "POST",
      url: policiesUrl(ORG1),
      headers: writeHeadersFor("a", { "idempotency-key": idempotencyKey() }),
      payload: { mutationId: created.mutationId, content: content() },
    });
    expect(changedKey.statusCode).toBe(409);
    expect(errorCode(changedKey)).toBe("IDEMPOTENCY_CONFLICT");

    // A second mutation that tries to reuse the same idempotency key on the
    // SAME operation with a fresh logical id is also a conflict.
    const reusedKey = await instance.inject({
      method: "POST",
      url: policiesUrl(ORG1),
      headers: writeHeadersFor("a", { "idempotency-key": created.key }),
      payload: { mutationId: randomUUID(), content: content() },
    });
    expect(reusedKey.statusCode).toBe(409);
    expect(errorCode(reusedKey)).toBe("IDEMPOTENCY_CONFLICT");

    expect(
      await count(
        `SELECT count(*)::text AS n FROM openarc_tenant.budget_policy_roots WHERE organization_id = $1`,
        [ORG1],
      ),
    ).toBe(1);
    await assertExactlyOneDurableRecord(ORG1, created.mutationId, "budget_policy");
  });

  it("enforces one active root per organization/subject and allows renewal of a paused root", async () => {
    const instance = await buildApp();
    const first = await createPolicy(instance, "a");
    expect(first.response.statusCode).toBe(200);

    // A second ACTIVE create for the same organization/subject violates the
    // partial unique index and rolls back entirely.
    const conflict = await createPolicy(instance, "a");
    expect(conflict.response.statusCode).toBe(409);
    expect(errorCode(conflict.response)).toBe("POLICY_DENIED");
    await assertNoDurableRecord(ORG1, conflict.mutationId);

    const root = parsedRoot(instance, await readRoot(instance, "a", first.policyId), first.policyId);
    const pause = await transition(instance, "a", first.policyId, "pause", "1", root.updatedAt);
    expect(pause.response.statusCode).toBe(200);

    // After pausing, a NEW active root for the same subject is permitted.
    const second = await createPolicy(instance, "a");
    expect(second.response.statusCode).toBe(200);
    const pausedRoot = parsedRoot(instance, await readRoot(instance, "a", first.policyId), first.policyId);
    expect(pausedRoot.status).toBe("paused");

    // Resuming the first root while the second is active must fail atomically.
    const resume = await transition(instance, "a", first.policyId, "resume", "1", pausedRoot.updatedAt);
    expect(resume.response.statusCode).toBe(409);
    expect(errorCode(resume.response)).toBe("POLICY_DENIED");
    await assertNoDurableRecord(ORG1, resume.mutationId);

    const finalFirst = parsedRoot(instance, await readRoot(instance, "a", first.policyId), first.policyId);
    expect(finalFirst.status).toBe("paused");
    expect(
      await count(
        `SELECT count(*)::text AS n FROM openarc_tenant.budget_policy_roots
          WHERE organization_id = $1 AND subject_agent_id = $2 AND status = 'active'`,
        [ORG1, AGENT1],
      ),
    ).toBe(1);
  });

  it("accepts valid external provider and listing allowlists and rejects a cross-org subject body", async () => {
    const instance = await buildApp();
    const created = await createPolicy(instance, "a", {
      allowedProviderIds: [PROVIDER2],
      allowedListingIds: [LISTING1],
    });
    expect(created.response.statusCode).toBe(200);

    const revision = await readRevision(instance, "a", created.policyId, "1");
    const body = CommercePolicyRevisionDetailResponseSchema.parse(revision.json());
    expect(body.data.item?.allowedProviderIds).toEqual([PROVIDER2]);
    expect(body.data.item?.allowedListingIds).toEqual([LISTING1]);

    // A body carrying another organization's id is rejected before any auth.
    const forged = await instance.inject({
      method: "POST",
      url: policiesUrl(ORG1),
      headers: writeHeadersFor("a"),
      payload: {
        mutationId: randomUUID(),
        content: content({ organizationId: ORG2 }),
      },
    });
    expect(forged.statusCode).toBe(400);
    expect(errorCode(forged)).toBe("INVALID_REQUEST");
  });

  it("rejects a non-active subject agent and rolls the create back", async () => {
    const instance = await buildApp();
    const created = await createPolicy(instance, "a", { subjectAgentId: AGENT_REVOKED });
    expect(created.response.statusCode).toBe(403);
    expect(errorCode(created.response)).toBe("FORBIDDEN");
    await assertNoDurableRecord(ORG1, created.mutationId);

    // A missing subject agent is a non-disclosing 403, never an existence oracle.
    const missing = await createPolicy(instance, "a", { subjectAgentId: `openarc:agent:${uuid(99)}` });
    expect(missing.response.statusCode).toBe(403);
    expect(errorCode(missing.response)).toBe("FORBIDDEN");
    await assertNoDurableRecord(ORG1, missing.mutationId);
  });

  it("lists policy roots with canonical query bounds, strict errors and a real cursor", async () => {
    const instance = await buildApp();
    const first = await createPolicy(instance, "a");
    expect(first.response.statusCode).toBe(200);
    const second = await createPolicy(instance, "a", { subjectAgentId: AGENT2 });
    expect(second.response.statusCode).toBe(200);

    const listed = await listRoots(instance, "a");
    expect(listed.statusCode).toBe(200);
    const page = CommercePolicyRootPageResponseSchema.parse(listed.json());
    expect(page.meta.schemaVersion).toBe(COMMERCE_API_SCHEMA_VERSION);
    const ids = page.data.items.map((item) => item.policyId);
    expect(ids).toEqual([...ids].sort());
    expect(ids).toContain(first.policyId);
    expect(ids).toContain(second.policyId);
    expect(page.data.nextCursor).toBeNull();

    const limited = await listRoots(instance, "a", "?limit=1");
    expect(limited.statusCode).toBe(200);
    const limitedPage = CommercePolicyRootPageResponseSchema.parse(limited.json());
    expect(limitedPage.data.items).toHaveLength(1);
    const cursor = limitedPage.data.nextCursor;
    expect(cursor).toBe(limitedPage.data.items[0]?.policyId ?? null);

    const next = await listRoots(
      instance,
      "a",
      `?limit=1&afterPolicyId=${encodeURIComponent(cursor ?? "")}`,
    );
    expect(next.statusCode).toBe(200);
    const nextPage = CommercePolicyRootPageResponseSchema.parse(next.json());
    expect(nextPage.data.items).toHaveLength(1);
    expect((nextPage.data.items[0]?.policyId ?? "") > (cursor ?? "")).toBe(true);

    // Strict canonical query rejection: repeated, unknown, non-canonical and
    // bare queries never reach the store.
    for (const query of [
      "?limit=01",
      "?limit=0",
      "?limit=51",
      "?limit=1&limit=2",
      "?afterPolicyId=not-a-policy",
      "?unknown=1",
      "?limit=",
    ]) {
      const response = await listRoots(instance, "a", query);
      expect(response.statusCode, query).toBe(400);
    }
  });
});

describe("real-PG control policy authority over HTTP", () => {
  it("lets owner and operator write, lets viewer read and never write, and denies provider roles", async () => {
    const instance = await buildApp();

    const ownerCreate = await createPolicy(instance, "a");
    expect(ownerCreate.response.statusCode).toBe(200);
    const ownerRoot = parsedRoot(instance, await readRoot(instance, "a", ownerCreate.policyId), ownerCreate.policyId);

    const operatorAppend = await appendRevision(
      instance,
      "b",
      ownerCreate.policyId,
      "1",
      ownerRoot.updatedAt,
    );
    expect(operatorAppend.response.statusCode).toBe(200);

    // Viewer can read the root, history, revision and status.
    const viewerRoot = await readRoot(instance, "c", ownerCreate.policyId);
    expect(viewerRoot.statusCode).toBe(200);
    expect(CommercePolicyRootDetailResponseSchema.parse(viewerRoot.json()).data.item?.policyId).toBe(
      ownerCreate.policyId,
    );
    expect((await readHistory(instance, "c", ownerCreate.policyId)).statusCode).toBe(200);
    expect((await readRevision(instance, "c", ownerCreate.policyId, "1")).statusCode).toBe(200);
    expect((await readStatus(instance, "c", ownerCreate.mutationId)).statusCode).toBe(200);

    // Viewer cannot write any operation.
    const viewerCreate = await createPolicy(instance, "c");
    expect(viewerCreate.response.statusCode).toBe(403);
    expect(errorCode(viewerCreate.response)).toBe("FORBIDDEN");
    await assertNoDurableRecord(ORG1, viewerCreate.mutationId);

    const afterOperator = parsedRoot(
      instance,
      await readRoot(instance, "a", ownerCreate.policyId),
      ownerCreate.policyId,
    );
    const viewerPause = await transition(
      instance,
      "c",
      ownerCreate.policyId,
      "pause",
      "2",
      afterOperator.updatedAt,
    );
    expect(viewerPause.response.statusCode).toBe(403);
    await assertNoDurableRecord(ORG1, viewerPause.mutationId);

    // Provider-admin and provider-developer memberships are not policy
    // readers/writers: both the read and the write are a non-disclosing 403.
    for (const label of ["d", "e"] as const) {
      expect((await readRoot(instance, label, ownerCreate.policyId)).statusCode).toBe(403);
      expect((await readHistory(instance, label, ownerCreate.policyId)).statusCode).toBe(403);
      expect((await readStatus(instance, label, ownerCreate.mutationId)).statusCode).toBe(403);
      const write = await appendRevision(
        instance,
        label,
        ownerCreate.policyId,
        "2",
        afterOperator.updatedAt,
      );
      expect(write.response.statusCode).toBe(403);
      expect(errorCode(write.response)).toBe("FORBIDDEN");
      await assertNoDurableRecord(ORG1, write.mutationId);
    }

    // A non-member is denied without leaking whether the org exists.
    const nonMember = await readRoot(instance, "g", ownerCreate.policyId);
    expect(nonMember.statusCode).toBe(403);
    expect(nonMember.body).not.toContain(ownerCreate.policyId);
    await assertExactlyOneDurableRecord(ORG1, ownerCreate.mutationId, "budget_policy");
  });

  it("denies cross-organization reads and writes without an existence oracle", async () => {
    const instance = await buildApp();
    const created = await createPolicy(instance, "a");
    expect(created.response.statusCode).toBe(200);

    // ORG2's owner cannot read ORG1's policy or list ORG1's roots.
    const foreignRoot = await readRoot(instance, "f", created.policyId, ORG1);
    expect(foreignRoot.statusCode).toBe(403);
    expect(foreignRoot.body).not.toContain(created.policyId);

    const foreignList = await instance.inject({
      method: "GET",
      url: policiesUrl(ORG1),
      headers: readHeadersFor("f"),
    });
    expect(foreignList.statusCode).toBe(403);

    // ORG1's owner cannot read or list ORG2 (whose only policy sits in ORG1).
    const crossRead = await readRoot(instance, "a", created.policyId, ORG2);
    expect(crossRead.statusCode).toBe(403);

    // Cross-org mutation is denied and leaves no durable record in either org.
    const foreignAppend = await appendRevision(
      instance,
      "f",
      created.policyId,
      "1",
      new Date().toISOString(),
      {},
      {},
      ORG1,
    );
    expect(foreignAppend.response.statusCode).toBe(403);
    await assertNoDurableRecord(ORG1, foreignAppend.mutationId);

    // A mutation status genuinely scoped to another actor is `not_found`, never
    // a receipt disclosure.
    const otherActorStatus = await readStatus(instance, "f", created.mutationId);
    expect(otherActorStatus.statusCode).toBe(403);

    const peerStatus = await readStatus(instance, "b", created.mutationId);
    expect(peerStatus.statusCode).toBe(200);
    const peerBody = CommercePolicyMutationStatusResponseSchema.parse(peerStatus.json());
    expect(peerBody.data.status).toBe("not_found");
  });

  it("hides cross-account and cross-session mutation outcomes while the owner can read its own", async () => {
    const instance = await buildApp();
    const created = await createPolicy(instance, "a");
    expect(created.response.statusCode).toBe(200);

    const ownerStatus = await readStatus(instance, "a", created.mutationId);
    expect(ownerStatus.statusCode).toBe(200);
    expect(
      CommercePolicyMutationStatusResponseSchema.parse(ownerStatus.json()).data.status,
    ).toBe("committed");

    // A different live session for a DIFFERENT account in the same org sees no
    // receipt for this mutation.
    const operatorStatus = await readStatus(instance, "b", created.mutationId);
    expect(operatorStatus.statusCode).toBe(200);
    const operatorBody = CommercePolicyMutationStatusResponseSchema.parse(operatorStatus.json());
    expect(operatorBody.data.status).toBe("not_found");
    expect(JSON.stringify(operatorBody.data)).not.toContain("receipt");

    // An expired session is unauthenticated, not `not_found`.
    const expiredToken = b64(32);
    await seedSession(expiredToken, B, { expired: true });
    const expired = await instance.inject({
      method: "GET",
      url: mutationUrl(ORG1, created.mutationId),
      headers: { ...CLIENT, cookie: `${SESSION_COOKIE}=${expiredToken}` },
    });
    expect(expired.statusCode).toBe(401);
    expect(expired.body).not.toContain('"data"');
  });

  it("rejects an ORG2 subject agent on an ORG1 path/body and leaves no durable or policy rows", async () => {
    const instance = await buildApp();
    // Path AND body both name ORG1, so this is NOT a path/body consistency
    // check: only the SUBJECT AGENT's owning organization (ORG2) differs. A
    // foreign-org agent must never become an ORG1 policy subject.
    const created = await createPolicy(instance, "a", { subjectAgentId: AGENT_ORG2 });
    expect(created.response.statusCode).toBe(403);
    expect(errorCode(created.response)).toBe("FORBIDDEN");
    await assertNoDurableRecord(ORG1, created.mutationId);

    // No policy root/version was fabricated in either organization, and the
    // durable assertions above cover audit/outbox/idempotency.
    expect(
      await count(
        `SELECT count(*)::text AS n FROM openarc_tenant.budget_policy_roots
          WHERE organization_id IN ($1, $2)`,
        [ORG1, ORG2],
      ),
    ).toBe(0);
    expect(
      await count(
        `SELECT count(*)::text AS n FROM openarc_tenant.budget_policy_versions
          WHERE organization_id IN ($1, $2)`,
        [ORG1, ORG2],
      ),
    ).toBe(0);
  });

  it("hides a committed mutation from a second live session of the SAME account and denies its replay", async () => {
    const instance = await buildApp();
    const created = await createPolicy(instance, "a");
    expect(created.response.statusCode).toBe(200);

    // The original session sees its own committed receipt.
    const original = await readStatus(instance, "a", created.mutationId);
    expect(original.statusCode).toBe(200);
    expect(
      CommercePolicyMutationStatusResponseSchema.parse(original.json()).data.status,
    ).toBe("committed");

    // A SECOND LIVE session for the SAME account A (same account, same org,
    // unexpired, non-recovery) is a DIFFERENT session context. The receipt must
    // not be visible to it: exact session-context binding, independently of
    // account identity or session liveness.
    const secondToken = b64(32);
    await seedSession(secondToken, A);
    tokens.set("a2", secondToken);

    const secondStatus = await readStatus(instance, "a2", created.mutationId);
    expect(secondStatus.statusCode).toBe(200);
    const secondBody = CommercePolicyMutationStatusResponseSchema.parse(secondStatus.json());
    expect(secondBody.data.status).toBe("not_found");
    expect(JSON.stringify(secondBody.data)).not.toContain("receipt");

    // Replaying the SAME mutation/key from the second session is a session
    // context conflict, never a replayed receipt.
    const replay = await instance.inject({
      method: "POST",
      url: policiesUrl(ORG1),
      headers: writeHeadersFor("a2", { "idempotency-key": created.key }),
      payload: { mutationId: created.mutationId, content: content() },
    });
    expect(replay.statusCode).toBe(409);
    expect(errorCode(replay)).toBe("IDEMPOTENCY_CONFLICT");
    await assertExactlyOneDurableRecord(ORG1, created.mutationId, "budget_policy");

    // The original session still retrieves its own receipt unchanged.
    const stillOriginal = await readStatus(instance, "a", created.mutationId);
    expect(stillOriginal.statusCode).toBe(200);
    expect(
      CommercePolicyMutationStatusResponseSchema.parse(stillOriginal.json()).data.status,
    ).toBe("committed");
  });

  it("rejects a forged proof/session header and keeps the private error envelope non-echoing", async () => {
    const instance = await buildApp();
    const created = await createPolicy(instance, "a");
    expect(created.response.statusCode).toBe(200);

    const forgedCsrf = await instance.inject({
      method: "POST",
      url: policiesUrl(ORG1),
      headers: writeHeadersFor("a", { "x-openarc-csrf": "forged-csrf-value" }),
      payload: { mutationId: randomUUID(), content: content() },
    });
    expect(forgedCsrf.statusCode).toBe(403);
    expect(errorCode(forgedCsrf)).toBe("CSRF_REJECTED");
    expect(forgedCsrf.body).not.toContain("forged-csrf-value");

    const anonymousRead = await instance.inject({
      method: "GET",
      url: policiesUrl(ORG1),
      headers: { ...CLIENT },
    });
    expect(anonymousRead.statusCode).toBe(401);
    expect(anonymousRead.body).not.toContain('"data"');

    const credentialHeader = await instance.inject({
      method: "GET",
      url: policiesUrl(ORG1),
      headers: readHeadersFor("a", { authorization: "Bearer secret-canary" }),
    });
    expect(credentialHeader.statusCode).toBe(400);
    expect(credentialHeader.body).not.toContain("secret-canary");

    // A recovery session may READ but never WRITE.
    const recoveryToken = b64(32);
    await seedSession(recoveryToken, A, { method: "recovery" });
    const recoveryRead = await instance.inject({
      method: "GET",
      url: policiesUrl(ORG1),
      headers: { ...CLIENT, cookie: `${SESSION_COOKIE}=${recoveryToken}` },
    });
    expect(recoveryRead.statusCode).toBe(200);

    const binding = issueBindingCookie(SECRET, b64(16), Date.now());
    const recoveryWrite = await instance.inject({
      method: "POST",
      url: policiesUrl(ORG1),
      headers: {
        ...CLIENT,
        "content-type": "application/json",
        cookie: `${SESSION_COOKIE}=${recoveryToken}; ${BINDING_COOKIE}=${binding}`,
        "x-openarc-csrf": deriveCsrfToken(SECRET, binding, tokenHash(recoveryToken)),
        "idempotency-key": idempotencyKey(),
      },
      payload: { mutationId: randomUUID(), content: content() },
    });
    expect(recoveryWrite.statusCode).toBe(401);
    expect(recoveryWrite.body).not.toContain('"data"');
  });
});

describe("real-PG control policy runtime independence and capability", () => {
  it("enables policy management with tenant HTTP reads/writes OFF and no tenant runtime", async () => {
    // Deliberately DO NOT pass a tenantReadService/tenantWriteService and set
    // both tenant HTTP families OFF. Policy management must still start, report
    // ready and serve its routes over the real runtime.
    const runtime: StartedControlRuntime = await startControlRuntime({
      policyDatabaseUrl: tenantUrl(),
      auth: authService(),
    });
    try {
      await expect(runtime.ready()).resolves.toBe(true);

      const config = loadConfig(
        buildFlags({
          POLICY_MANAGEMENT_ENABLED: "true",
          TENANT_READS_ENABLED: "false",
          TENANT_WRITES_ENABLED: "false",
          LISTING_MANAGEMENT_ENABLED: "false",
          MARKET_CATALOG_ENABLED: "false",
          MARKET_MODERATION_ENABLED: "false",
          MACHINE_CREDENTIAL_MANAGEMENT_ENABLED: "false",
          MACHINE_SESSION_EXCHANGE_ENABLED: "false",
        }),
      );
      expect(config.TENANT_READS_ENABLED).toBe(false);
      expect(config.TENANT_WRITES_ENABLED).toBe(false);

      const authForApp = authService();
      const instance = createApp({
        config,
        logger: false,
        authService: authForApp,
        authReady: async () => true,
        policyManagementService: runtime.service,
        policyReady: () => runtime.ready(),
      });
      try {
        // /readyz is ready: auth + policy database are up, tenant is off.
        const ready = await instance.inject({ method: "GET", url: "/readyz" });
        expect(ready.statusCode).toBe(200);
        expect(ready.json().checks.policyDatabase).toBe("up");
        expect(ready.json().checks.tenantDatabase).toBeUndefined();

        // Capability is ENABLED: policy management is independent of tenant
        // HTTP reads. (Regression for the known pending runtime issue.)
        const capability = await instance.inject({
          method: "GET",
          url: CONTROL_CAPABILITIES_PATH,
        });
        expect(capability.statusCode).toBe(200);
        const manifest = ControlCapabilitiesSuccessEnvelopeSchema.parse(capability.json());
        expect(manifest.data.capabilityVersion).toBe("openarc.capabilities.control.v1");
        expect(manifest.data.routes.map((route) => route.id)).toEqual([...CONTROL_ROUTE_IDS]);
        expect(manifest.data.routes).toHaveLength(10);
        const policy = manifest.data.capabilities.find(
          (entry) => entry.family === "policy_management",
        );
        expect(policy?.state).toBe("enabled");
        expect(policy?.dependencies).toEqual(["auth", "tenantDatabase", "policyDatabase"]);

        // A real policy mutation works end-to-end with tenant reads OFF.
        const created = await createPolicy(instance, "a");
        expect(created.response.statusCode).toBe(200);
        const root = await readRoot(instance, "a", created.policyId);
        expect(root.statusCode).toBe(200);
      } finally {
        await instance.close();
      }
    } finally {
      await runtime.close();
    }
  });

  it("reports the capability unavailable when the real policy database readiness fails", async () => {
    const runtime = await startControlRuntime({
      policyDatabaseUrl: tenantUrl(),
      auth: authService(),
    });
    try {
      await expect(runtime.ready()).resolves.toBe(true);
      // One focused representative tamper: schema8 force-RLS posture drift.
      await admin.query(
        "ALTER TABLE openarc_tenant.budget_policy_roots NO FORCE ROW LEVEL SECURITY",
      );
      await expect(runtime.ready()).resolves.toBe(false);

      const instance = createApp({
        config: loadConfig(buildFlags()),
        logger: false,
        authService: authService(),
        authReady: async () => true,
        policyManagementService: runtime.service,
        policyReady: () => runtime.ready(),
      });
      try {
        const ready = await instance.inject({ method: "GET", url: "/readyz" });
        expect(ready.statusCode).toBe(503);
        expect(ready.json().checks.policyDatabase).toBe("down");

        const capability = await instance.inject({
          method: "GET",
          url: CONTROL_CAPABILITIES_PATH,
        });
        expect(capability.statusCode).toBe(200);
        const manifest = ControlCapabilitiesSuccessEnvelopeSchema.parse(capability.json());
        const policy = manifest.data.capabilities.find(
          (entry) => entry.family === "policy_management",
        );
        expect(policy?.state).toBe("unavailable");
      } finally {
        await instance.close();
      }
    } finally {
      await runtime.close();
    }
  });

  it("registers no policy route and reports built_disabled while the flag is OFF", async () => {
    const instance = createApp({
      config: loadConfig(
        buildFlags({ POLICY_MANAGEMENT_ENABLED: "false" }),
      ),
      logger: false,
      authService: authService(),
      authReady: async () => true,
    });
    try {
      for (const [method, url] of [
        ["GET", policiesUrl(ORG1)],
        ["POST", policiesUrl(ORG1)],
        ["GET", readOnlyPolicyUrl(ORG1)],
      ] as ReadonlyArray<readonly [string, string]>) {
        const response = await instance.inject({
          method: method as "GET" | "POST",
          url,
          headers: method === "GET" ? readHeadersFor("a") : writeHeadersFor("a"),
          ...(method === "POST" ? { payload: { mutationId: randomUUID(), content: content() } } : {}),
        });
        expect(response.statusCode).toBe(404);
      }

      const capability = await instance.inject({
        method: "GET",
        url: CONTROL_CAPABILITIES_PATH,
      });
      expect(capability.statusCode).toBe(200);
      const manifest = ControlCapabilitiesSuccessEnvelopeSchema.parse(capability.json());
      expect(manifest.data.capabilities[0]?.state).toBe("built_disabled");
      // The flag-OFF capability route performs zero readiness probes.
      expect(manifest.data.routes).toHaveLength(10);
    } finally {
      await instance.close();
    }
  });
});

function readOnlyPolicyUrl(organizationId: string): string {
  return policiesUrl(organizationId, `/${policyIdFor("00000000-0000-4000-8000-000000000000")}`);
}

/**
 * Poll `pg_stat_activity` from a SEPARATE connection until the real policy
 * helper issued by a pending request blocks on a held lock. Seeing the SQL
 * blocked proves the request reached the SECURITY DEFINER preamble and is a
 * deterministic real-lock observation, not a sleep-based race guess.
 */
async function waitForBlockedPolicyQuery(
  pool: Pool,
  functionName: string,
  timeoutMs = 8000,
): Promise<{ wait_event_type: string | null } | null> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const result = await pool.query<{ wait_event_type: string | null }>(
      `SELECT wait_event_type
         FROM pg_stat_activity
        WHERE query LIKE $1
          AND pid <> pg_backend_pid()
          AND wait_event_type = 'Lock'
        LIMIT 1`,
      [`%${functionName}%`],
    );
    if (result.rows.length > 0) return result.rows[0] ?? null;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return null;
}

function delay(ms: number): Promise<"timeout"> {
  return new Promise((resolve) => setTimeout(() => resolve("timeout"), ms));
}

function createGate() {
  let release: () => void = () => undefined;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  let reached: () => void = () => undefined;
  const atGate = new Promise<void>((resolve) => {
    reached = resolve;
  });
  return { gate, release, atGate, reached };
}

/**
 * Bind every ControlPolicyStorePort method to the concrete store, applying
 * explicit overrides. Only the gated race tests use this so the gated method
 * can pause BEFORE the real store call while every other method stays real.
 */
function delegateStore(
  store: ControlPolicyStore,
  overrides: Partial<ControlPolicyStorePort> = {},
): ControlPolicyStorePort {
  const target: Record<string, unknown> = {
    createPolicy: store.createPolicy.bind(store),
    appendPolicyRevision: store.appendPolicyRevision.bind(store),
    transitionPolicy: store.transitionPolicy.bind(store),
    getPolicyRoot: store.getPolicyRoot.bind(store),
    listPolicyRoots: store.listPolicyRoots.bind(store),
    getPolicyRevision: store.getPolicyRevision.bind(store),
    listPolicyRevisions: store.listPolicyRevisions.bind(store),
    getPolicyMutationStatus: store.getPolicyMutationStatus.bind(store),
  };
  for (const [name, fn] of Object.entries(overrides)) {
    target[name] = fn;
  }
  return target as unknown as ControlPolicyStorePort;
}

describe("real-PG control policy blocked-lock authority", () => {
  it("denies a writer whose session is revoked while it waits on the account lock", async () => {
    const gate = createGate();
    const store = new ControlPolicyStore(asControlPolicyPool(tenant));
    await store.initialize();
    const port = delegateStore(store, {
      transitionPolicy: async (...args) => {
        gate.reached();
        await gate.gate;
        return store.transitionPolicy(...args);
      },
    });
    const service = new PolicyService({ auth: authService() as ControlPolicyAuthPort, store: port });
    const instance = await buildApp({ service });

    const created = await createPolicy(instance, "a");
    expect(created.response.statusCode).toBe(200);
    const root = parsedRoot(instance, await readRoot(instance, "a", created.policyId), created.policyId);

    const blocker = await admin.connect();
    let pending: ReturnType<AppInstance["inject"]> | undefined;
    try {
      await blocker.query("BEGIN");
      // Hold the ACTOR ACCOUNT row lock. The helper's `lock_auth_session`
      // takes this account lock BEFORE the session row, so this request blocks
      // before locking the session and the session row stays mutable.
      await blocker.query(
        "SELECT 1 FROM openarc_auth.accounts WHERE account_id = $1 FOR UPDATE",
        [A],
      );
      const request = instance.inject({
        method: "POST",
        url: policiesUrl(ORG1, `/${created.policyId}/pause`),
        headers: writeHeadersFor("a"),
        payload: { mutationId: randomUUID(), expectedRevision: "1", expectedUpdatedAt: root.updatedAt },
      }) as unknown as Promise<InjectResponse>;
      pending = request;
      void request.then(() => undefined, () => undefined);

      const settled = await Promise.race([
        gate.atGate.then(() => "gated"),
        request.then((r) => String(r.statusCode), () => "rejected"),
        delay(4000),
      ]);
      expect(settled).toBe("gated");

      gate.release();
      const observed = await waitForBlockedPolicyQuery(admin, "lock_policy_writer", 8000);
      expect(observed).not.toBeNull();
      expect(observed?.wait_event_type).toBe("Lock");

      // Revoke THIS request's session while it waits; the SQL re-resolves the
      // same held session after the wait and must deny atomically.
      await admin.query("DELETE FROM openarc_auth.sessions WHERE token_hash = $1", [
        tokenHash(tokens.get("a") ?? ""),
      ]);
      await blocker.query("ROLLBACK");

      const response = await pending;
      expect(response.statusCode).toBe(401);
      expect(response.body).not.toContain('"data"');
    } finally {
      gate.release();
      try {
        await blocker.query("ROLLBACK");
      } catch {
        // An aborted transaction still releases the connection.
      }
      if (pending) await pending.catch(() => undefined);
      blocker.release();
    }

    // Restore a live session for A so the post-denial state can be observed.
    await seedSession(tokens.get("a") ?? "", A);
    const rootAfter = parsedRoot(instance, await readRoot(instance, "a", created.policyId), created.policyId);
    expect(rootAfter.status).toBe("active");
    expect(rootAfter.updatedAt).toBe(root.updatedAt);
    expect(
      await count(
        `SELECT count(*)::text AS n FROM openarc_durable.idempotency_records
          WHERE organization_id = $1 AND operation = 'control.policy.pause'`,
        [ORG1],
      ),
    ).toBe(0);
  }, 20_000);

  it("denies a writer whose proof aged past five minutes while it waits on the account lock", async () => {
    const gate = createGate();
    const store = new ControlPolicyStore(asControlPolicyPool(tenant));
    await store.initialize();
    const port = delegateStore(store, {
      appendPolicyRevision: async (...args) => {
        gate.reached();
        await gate.gate;
        return store.appendPolicyRevision(...args);
      },
    });
    const service = new PolicyService({ auth: authService() as ControlPolicyAuthPort, store: port });
    const instance = await buildApp({ service });

    const created = await createPolicy(instance, "a");
    expect(created.response.statusCode).toBe(200);
    const root = parsedRoot(instance, await readRoot(instance, "a", created.policyId), created.policyId);

    const blocker = await admin.connect();
    let pending: Promise<InjectResponse> | undefined;
    try {
      await blocker.query("BEGIN");
      // Hold the ACTOR ACCOUNT row lock (see the session-revocation race).
      await blocker.query(
        "SELECT 1 FROM openarc_auth.accounts WHERE account_id = $1 FOR UPDATE",
        [A],
      );
      const request = instance.inject({
        method: "POST",
        url: policiesUrl(ORG1, `/${created.policyId}/revisions`),
        headers: writeHeadersFor("a"),
        payload: {
          mutationId: randomUUID(),
          expectedRevision: "1",
          expectedUpdatedAt: root.updatedAt,
          content: content(),
        },
      }) as unknown as Promise<InjectResponse>;
      pending = request;
      void request.then(() => undefined, () => undefined);

      const settled = await Promise.race([
        gate.atGate.then(() => "gated"),
        request.then((r) => String(r.statusCode), () => "rejected"),
        delay(4000),
      ]);
      expect(settled).toBe("gated");

      gate.release();
      const observed = await waitForBlockedPolicyQuery(admin, "lock_policy_writer", 8000);
      expect(observed).not.toBeNull();

      // Age the caller's session past the five-minute non-recovery proof bound
      // while it waits. The helper's required session recheck must deny.
      await admin.query(
        `UPDATE openarc_auth.sessions
            SET created_at = clock_timestamp() - interval '6 minutes'
          WHERE token_hash = $1`,
        [tokenHash(tokens.get("a") ?? "")],
      );
      await blocker.query("ROLLBACK");

      const response = await pending;
      expect(response.statusCode).toBe(401);
      expect(response.body).not.toContain('"data"');
    } finally {
      gate.release();
      try {
        await blocker.query("ROLLBACK");
      } catch {
        // An aborted transaction still releases the connection.
      }
      if (pending) await pending.catch(() => undefined);
      blocker.release();
    }

    // Restore the caller's session freshness so the post-denial state can be
    // observed; the mutation itself already failed and rolled back.
    await admin.query(
      `UPDATE openarc_auth.sessions SET created_at = clock_timestamp()
        WHERE token_hash = $1`,
      [tokenHash(tokens.get("a") ?? "")],
    );
    const rootAfter = parsedRoot(instance, await readRoot(instance, "a", created.policyId), created.policyId);
    expect(rootAfter.currentRevision).toBe("1");
    expect(
      await count(
        `SELECT count(*)::text AS n FROM openarc_durable.idempotency_records
          WHERE organization_id = $1 AND operation = 'control.policy.revision.create'`,
        [ORG1],
      ),
    ).toBe(0); // the only append rolled back
  }, 20_000);
});

describe("real-PG control policy durability", () => {
  it("writes exactly one audit and outbox row for each of the five operations and none for a rollback", async () => {
    const instance = await buildApp();
    const created = await createPolicy(instance, "a");
    expect(created.response.statusCode).toBe(200);
    const root = parsedRoot(instance, await readRoot(instance, "a", created.policyId), created.policyId);

    const append = await appendRevision(instance, "a", created.policyId, "1", root.updatedAt);
    expect(append.response.statusCode).toBe(200);
    const afterAppend = parsedRoot(instance, await readRoot(instance, "a", created.policyId), created.policyId);

    // A failing append (stale microsecond CAS) must roll the whole transaction
    // back: no idempotency, audit, outbox or extra revision row. Run it while
    // the root is still active so the CAS failure, not a lifecycle state, is
    // the reason it is denied.
    const rolledBack = await appendRevision(
      instance,
      "a",
      created.policyId,
      "1",
      afterAppend.updatedAt,
      { perActionLimit: "4242424" },
    );
    expect(rolledBack.response.statusCode).toBe(409);
    expect(errorCode(rolledBack.response)).toBe("POLICY_DENIED");
    await assertNoDurableRecord(ORG1, rolledBack.mutationId);
    expect(
      await count(
        `SELECT count(*)::text AS n FROM openarc_tenant.budget_policy_versions
          WHERE organization_id = $1 AND policy_id = $2`,
        [ORG1, created.policyId],
      ),
    ).toBe(2);

    const pause = await transition(instance, "a", created.policyId, "pause", "2", afterAppend.updatedAt);
    expect(pause.response.statusCode).toBe(200);
    const paused = parsedRoot(instance, await readRoot(instance, "a", created.policyId), created.policyId);

    const resume = await transition(instance, "a", created.policyId, "resume", "2", paused.updatedAt);
    expect(resume.response.statusCode).toBe(200);
    const resumed = parsedRoot(instance, await readRoot(instance, "a", created.policyId), created.policyId);

    const revoke = await transition(instance, "a", created.policyId, "revoke", "2", resumed.updatedAt);
    expect(revoke.response.statusCode).toBe(200);

    await assertExactlyOneDurableRecord(ORG1, created.mutationId, "budget_policy");
    await assertExactlyOneDurableRecord(ORG1, append.mutationId, "budget_policy_revision");
    await assertExactlyOneDurableRecord(ORG1, pause.mutationId, "budget_policy");
    await assertExactlyOneDurableRecord(ORG1, resume.mutationId, "budget_policy");
    await assertExactlyOneDurableRecord(ORG1, revoke.mutationId, "budget_policy");

    expect(
      await count(
        `SELECT count(*)::text AS n FROM openarc_durable.audit_events
          WHERE organization_id = $1 AND operation LIKE 'control.policy.%'`,
        [ORG1],
      ),
    ).toBe(5);
    expect(
      await count(
        `SELECT count(*)::text AS n FROM openarc_durable.outbox_events
          WHERE organization_id = $1 AND event_type LIKE 'control.policy.%'`,
        [ORG1],
      ),
    ).toBe(5);

    expect(
      await count(
        `SELECT count(*)::text AS n FROM openarc_tenant.budget_policy_versions
          WHERE organization_id = $1 AND policy_id = $2`,
        [ORG1, created.policyId],
      ),
    ).toBe(2);
  });

  it("never echoes the idempotency key, CSRF, cookie or a private content canary", async () => {
    const logs: unknown[] = [];
    const store = new ControlPolicyStore(asControlPolicyPool(tenant));
    await store.initialize();
    const auth = authService();
    const service = new PolicyService({ auth, store: store as unknown as ControlPolicyStorePort });
    const instance = createApp({
      config: loadConfig(buildFlags()),
      logger: false,
      logSink: (entry) => logs.push(entry),
      authService: auth,
      authReady: async () => true,
      policyManagementService: service,
      policyReady: async () => true,
    });
    try {
      const key = idempotencyKey();
      const mutationId = randomUUID();
      const response = await instance.inject({
        method: "POST",
        url: policiesUrl(ORG1),
        headers: writeHeadersFor("a", { "idempotency-key": key }),
        payload: { mutationId, content: content() },
      });
      expect(response.statusCode).toBe(200);
      expect(response.body).not.toContain(key);
      expect(response.body).not.toContain(SESSION_COOKIE);
      expect(response.body).not.toContain("x-openarc-csrf");
      for (const entry of logs) {
        const serialized = JSON.stringify(entry);
        expect(serialized).not.toContain(key);
        expect(serialized).not.toContain(SECRET);
      }
    } finally {
      await instance.close();
    }
  });
});
