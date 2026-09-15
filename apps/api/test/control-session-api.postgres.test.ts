import { createHash, randomBytes, randomUUID } from "node:crypto";

import {
  asCommerceSessionPool,
  asControlPolicyPool,
  asCredentialPool,
  AuthStore,
  CommerceSessionStore,
  CommerceSessionStoreError,
  ControlPolicyStore,
  createDatabasePool,
  CredentialStore,
  migrate,
} from "@openarc/db";
import {
  CommerceControlSessionExchangeResultResponseSchema,
  CommerceControlSessionIssueResultResponseSchema,
  CommerceControlSessionListResponseSchema,
  CommerceControlSessionMutationStatusResponseSchema,
  CommerceControlSessionRevokeResultResponseSchema,
  CommerceControlSessionStatusResponseSchema,
  SESSION_CAPABILITIES_PATH,
  SESSION_ROUTES,
  SessionCapabilitiesSuccessEnvelopeSchema,
} from "@openarc/shared";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { createApp } from "../src/app.js";
import { deriveCsrfToken, issueBindingCookie } from "../src/auth/cookies.js";
import type { AuthProofPort, AuthRuntime } from "../src/auth/ports.js";
import type { AuthOriginConfig } from "../src/auth/proofs.js";
import { AuthService, type AuthServiceConfig } from "../src/auth/service.js";
import { loadConfig } from "../src/config.js";
import type { CommerceSessionStorePort } from "../src/control/session-ports.js";
import { CommerceSessionRateLimiter } from "../src/control/session-rate-limiter.js";
import { CommerceSessionService } from "../src/control/session-service.js";
import { startCommerceSessionRuntime } from "../src/control/session-runtime.js";
import {
  hashCommerceHandoffToken,
  hashCommerceSessionToken,
} from "../src/control/session-crypto.js";
import { generateSessionToken, hashSessionToken } from "../src/machine/session-token.js";
import {
  adminPool,
  appUrl,
  ensureRoles,
  migratorUrl,
  resetSchema,
  tenantUrl,
} from "../../../packages/db/test/postgres-fixture.js";

/**
 * REAL API + PostgreSQL acceptance for the protected commerce-session slice.
 *
 * The runtime objects under test are the REAL accepted implementations:
 * AuthService + AuthStore (durable rate limiter), the accepted
 * `CommerceSessionStore` over the restricted `openarc_tenant_app` fixture role,
 * the accepted `CredentialStore` current-agent read, the accepted
 * `ControlPolicyStore`, `CommerceSessionService`, the real schema9 migration,
 * RLS, SECURITY DEFINER helpers, locks and the audit/outbox/idempotency tables.
 * `app.inject` is HTTP/PostgreSQL integration, NOT actual TLS, a production
 * browser or WebAuthn cryptography. The WebAuthn/SIWE proof adapter is
 * HONESTLY MOCKED (labelled): this suite proves HTTP-to-SQL orchestration and
 * enforcement, not cryptography.
 *
 * Privileged fixture setup provisions synthetic auth accounts/sessions,
 * organizations, memberships, agents, policies (through `ControlPolicyStore`)
 * and machine credentials/sessions (through `CredentialStore`). No test
 * directly inserts a commerce-session, handoff, receipt, audit or outbox
 * business row: every commerce row is created through the protected HTTP
 * mutations and every denial is observed at the HTTP boundary.
 */

type Pool = ReturnType<typeof adminPool>;
type AppInstance = ReturnType<typeof createApp>;
type Inject = Awaited<ReturnType<AppInstance["inject"]>>;

const ORIGIN = "http://localhost:5183";
const RP_ID = "localhost";
const SECRET = "synthetic_auth_secret_for_control_session_pg_0123456789";
const BUILD_SHA = "0123456789abcdef0123456789abcdef01234567";
const CLIENT = { origin: ORIGIN, "x-openarc-client": "browser-v1" };
const SESSION_COOKIE = "openarc_session";
const BINDING_COOKIE = "openarc_binding";
const PREFIX = "/v2/control/organizations";
const EXCHANGE_PATH = "/v2/agent/commerce-sessions/exchange";
const AGENT_MUTATION_PREFIX = "/v2/agent/commerce-session-mutations";

function uuid(seed: number): string {
  return `00000000-0000-4000-8000-${String(seed).padStart(12, "0")}`;
}

function accountId(seed: number): string {
  return `openarc:account:${uuid(seed)}`;
}

const ORG1 = `openarc:org:${uuid(1)}`;
const ORG2 = `openarc:org:${uuid(2)}`;
const AGENT1 = `openarc:agent:${uuid(1)}`;
const AGENT2 = `openarc:agent:${uuid(2)}`;
const AGENT_ORG2 = `openarc:agent:${uuid(3)}`;
const A = accountId(201); // ORG1 owner
const B = accountId(202); // ORG1 operator
const C = accountId(203); // ORG1 viewer (denied)
const D = accountId(204); // ORG1 provider_admin (denied)
const E = accountId(205); // ORG1 provider_developer (denied)
const F = accountId(206); // ORG2 owner (cross-org denied)
const G = accountId(207); // no membership (denied)

const HASH_INPUT = {
  algorithm: "scrypt" as const,
  hashVersion: 1 as const,
  pepperVersion: 1,
  N: 32768 as const,
  r: 8 as const,
  p: 1 as const,
  salt: Buffer.alloc(16, 7).toString("base64url"),
  digest: Buffer.alloc(32, 8).toString("base64url"),
};

function b64(bytes: number): string {
  return randomBytes(bytes).toString("base64url");
}

function idempotencyKey(): string {
  return randomBytes(32).toString("base64url");
}

/** Exact accepted auth-session hash: sha256("openarc:session:v1:"+token). */
function authTokenHash(token: string): string {
  return createHash("sha256").update(`openarc:session:v1:${token}`, "utf8").digest("hex");
}

function fakeProofs(): AuthProofPort {
  return {
    validateAuthOriginConfig: (input: unknown): AuthOriginConfig => input as AuthOriginConfig,
  } as unknown as AuthProofPort;
}

function fakeRuntime(): AuthRuntime {
  return { randomBytes: (size) => randomBytes(size), now: () => new Date() };
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
    expired?: boolean;
    ageSeconds?: number;
  } = {},
): Promise<void> {
  const age = options.expired === true ? 120 : (options.ageSeconds ?? 0);
  const lifetime = options.expired === true ? -60 : (options.expiresInSeconds ?? 900);
  await admin.query(
    `INSERT INTO openarc_auth.sessions (token_hash, account_id, method, created_at, expires_at)
     VALUES ($1, $2, $3, clock_timestamp() - ($4 || ' seconds')::interval,
             clock_timestamp() + ($5 || ' seconds')::interval)`,
    [authTokenHash(token), account, options.method ?? "passkey", String(age), String(lifetime)],
  );
}

async function seedOrganization(organizationId: string, createdBy: string): Promise<void> {
  await admin.query(
    `INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by)
     VALUES ($1, 'Org', $2)`,
    [organizationId, createdBy],
  );
}

async function seedMembership(
  organizationId: string,
  account: string,
  role: string,
  status = "active",
): Promise<void> {
  await admin.query(
    `INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status)
     VALUES ($1, $2, $3, $4)`,
    [organizationId, account, role, status],
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

interface DurableCounts {
  readonly sessions: number;
  readonly handoffs: number;
  readonly idem: number;
  readonly audit: number;
  readonly outbox: number;
}

async function durableCounts(organizationId: string): Promise<DurableCounts> {
  const result = await admin.query<Record<keyof DurableCounts, string>>(
    `SELECT
       (SELECT count(*)::text FROM openarc_durable.commerce_sessions WHERE organization_id = $1) AS sessions,
       (SELECT count(*)::text FROM openarc_durable.commerce_session_handoffs WHERE organization_id = $1) AS handoffs,
       (SELECT count(*)::text FROM openarc_durable.idempotency_records WHERE organization_id = $1 AND operation LIKE 'control.commerce_session%') AS idem,
       (SELECT count(*)::text FROM openarc_durable.audit_events WHERE organization_id = $1 AND operation LIKE 'control.commerce_session%') AS audit,
       (SELECT count(*)::text FROM openarc_durable.outbox_events WHERE organization_id = $1 AND event_type LIKE 'control.commerce_session%') AS outbox`,
    [organizationId],
  );
  const row = result.rows[0];
  if (row === undefined) throw new Error("missing counts");
  return {
    sessions: Number(row.sessions),
    handoffs: Number(row.handoffs),
    idem: Number(row.idem),
    audit: Number(row.audit),
    outbox: Number(row.outbox),
  };
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
    COMMERCE_SESSIONS_ENABLED: "true",
    ...overrides,
  };
}

function writeHeadersFor(label: string, extra: Record<string, string> = {}): Record<string, string> {
  const token = tokens.get(label) ?? "";
  const binding = issueBindingCookie(SECRET, b64(16), Date.now());
  return {
    ...CLIENT,
    "content-type": "application/json",
    cookie: `${SESSION_COOKIE}=${token}; ${BINDING_COOKIE}=${binding}`,
    "x-openarc-csrf": deriveCsrfToken(SECRET, binding, authTokenHash(token)),
    "idempotency-key": idempotencyKey(),
    ...extra,
  };
}

function readHeadersFor(label: string, extra: Record<string, string> = {}): Record<string, string> {
  return { ...CLIENT, cookie: `${SESSION_COOKIE}=${tokens.get(label) ?? ""}`, ...extra };
}

const listUrl = (organizationId = ORG1): string => `${PREFIX}/${organizationId}/commerce-sessions`;
const statusUrl = (sessionId: string, organizationId = ORG1): string =>
  `${PREFIX}/${organizationId}/commerce-sessions/${sessionId}`;
const revokeUrl = (sessionId: string, organizationId = ORG1): string =>
  `${PREFIX}/${organizationId}/commerce-sessions/${sessionId}/revoke`;
const humanMutationUrl = (mutationId: string, organizationId = ORG1): string =>
  `${PREFIX}/${organizationId}/commerce-session-mutations/${mutationId}`;
const agentMutationUrl = (mutationId: string): string =>
  `${AGENT_MUTATION_PREFIX}/${mutationId}`;

function errorCode(response: Inject): string {
  return (response.json().error as { code: string }).code;
}

interface Built {
  readonly instance: AppInstance;
  readonly service: CommerceSessionService;
  readonly store: CommerceSessionStore;
  readonly credentials: CredentialStore;
}

async function build(options: { readonly storeOverride?: CommerceSessionStorePort } = {}): Promise<Built> {
  const auth = authService();
  const authStore = new AuthStore(app);
  const store = new CommerceSessionStore(asCommerceSessionPool(tenant));
  await store.initialize();
  const credentials = new CredentialStore(asCredentialPool(tenant));
  await credentials.initialize();
  const service = new CommerceSessionService({
    auth,
    store: options.storeOverride ?? (store as unknown as CommerceSessionStorePort),
    agentSessions: { getAgentSession: (hash: unknown) => credentials.getAgentSession(hash) },
    limits: new CommerceSessionRateLimiter({
      secret: SECRET,
      store: { consume: (input) => authStore.consumeRateLimit(input) },
    }),
  });
  const instance = createApp({
    config: loadConfig(buildFlags()),
    logger: false,
    authService: auth,
    authReady: async () => true,
    commerceSessionService: service,
    commerceSessionReady: async () => true,
  });
  return { instance, service, store, credentials };
}

/** Bind every port method to the concrete store, applying explicit overrides. */
function delegateStore(
  store: CommerceSessionStore,
  overrides: Partial<CommerceSessionStorePort> = {},
): CommerceSessionStorePort {
  const target: Record<string, unknown> = {
    issueCommerceSession: store.issueCommerceSession.bind(store),
    exchangeCommerceSession: store.exchangeCommerceSession.bind(store),
    revokeCommerceSession: store.revokeCommerceSession.bind(store),
    getCommerceSessionStatus: store.getCommerceSessionStatus.bind(store),
    listCommerceSessions: store.listCommerceSessions.bind(store),
    getHumanCommerceSessionMutationStatus: store.getHumanCommerceSessionMutationStatus.bind(store),
    getAgentCommerceSessionMutationStatus: store.getAgentCommerceSessionMutationStatus.bind(store),
  };
  for (const [name, fn] of Object.entries(overrides)) target[name] = fn;
  return target as unknown as CommerceSessionStorePort;
}

function policyContent(organizationId: string, subjectAgentId: string): Record<string, unknown> {
  return {
    organizationId,
    subjectAgentId,
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
}

async function createPolicy(
  organizationId: string,
  subjectAgentId: string,
  ownerLabel = "a",
): Promise<string> {
  const policies = new ControlPolicyStore(asControlPolicyPool(tenant));
  await policies.initialize();
  const result = await policies.createPolicy(
    authTokenHash(tokens.get(ownerLabel) ?? ""),
    organizationId,
    policyContent(organizationId, subjectAgentId),
    { idempotencyKey: idempotencyKey(), mutationId: randomUUID() },
  );
  return result.receipt.resourceId;
}

interface Machine {
  readonly token: string;
  readonly sessionId: string;
  readonly credentialId: string;
}

async function provisionMachine(
  credentials: CredentialStore,
  options: {
    readonly organizationId?: string;
    readonly agentId?: string;
    readonly ownerLabel?: string;
  } = {},
): Promise<Machine> {
  const organizationId = options.organizationId ?? ORG1;
  const agentId = options.agentId ?? AGENT1;
  const issued = await credentials.issueAgentCredentialDurably({
    sessionHash: authTokenHash(tokens.get(options.ownerLabel ?? "a") ?? ""),
    organizationId,
    profileId: agentId,
    lookupId: randomUUID(),
    hash: HASH_INPUT,
    expiresAt: new Date(Date.now() + 30 * 60_000).toISOString(),
    metadata: { idempotencyKey: idempotencyKey(), mutationId: randomUUID() },
  });
  const credentialId = issued.receipt.credentialId;
  const token = generateSessionToken("agent");
  const sessionId = randomUUID();
  await credentials.createAgentSession({
    organizationId,
    profileId: agentId,
    credentialId,
    expectedVersion: 1,
    sessionId,
    tokenHash: hashSessionToken("agent", token),
    expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
  });
  return { token, sessionId, credentialId };
}

interface Lifecycle {
  readonly policyId: string;
  readonly machine: Machine;
}

async function provisionLifecycle(
  built: Built,
  options: {
    readonly organizationId?: string;
    readonly agentId?: string;
    readonly ownerLabel?: string;
  } = {},
): Promise<Lifecycle> {
  const organizationId = options.organizationId ?? ORG1;
  const agentId = options.agentId ?? AGENT1;
  const policyId = await createPolicy(organizationId, agentId, options.ownerLabel ?? "a");
  const machine = await provisionMachine(built.credentials, options);
  return { policyId, machine };
}

interface MutationCall {
  readonly response: Inject;
  readonly mutationId: string;
  readonly key: string;
}

async function issue(
  instance: AppInstance,
  label: string,
  policyId: string,
  options: {
    readonly organizationId?: string;
    readonly subjectAgentId?: string;
    readonly durationSeconds?: string;
    readonly mutationId?: string;
    readonly key?: string;
    readonly extraHeaders?: Record<string, string>;
    readonly extraBody?: Record<string, unknown>;
    readonly headers?: Record<string, string>;
  } = {},
): Promise<MutationCall> {
  const mutationId = options.mutationId ?? randomUUID();
  const key = options.key ?? idempotencyKey();
  const response = await instance.inject({
    method: "POST",
    url: listUrl(options.organizationId ?? ORG1),
    headers: options.headers ?? writeHeadersFor(label, { "idempotency-key": key, ...options.extraHeaders }),
    payload: {
      mutationId,
      subjectAgentId: options.subjectAgentId ?? AGENT1,
      policyId,
      ...(options.durationSeconds !== undefined ? { durationSeconds: options.durationSeconds } : {}),
      ...options.extraBody,
    },
  });
  return { response, mutationId, key };
}

async function exchange(
  instance: AppInstance,
  token: string,
  handoffToken: string,
  options: {
    readonly mutationId?: string;
    readonly key?: string;
    readonly extraHeaders?: Record<string, string>;
    readonly omitIdempotency?: boolean;
  } = {},
): Promise<MutationCall> {
  const mutationId = options.mutationId ?? randomUUID();
  const key = options.key ?? idempotencyKey();
  const response = await instance.inject({
    method: "POST",
    url: EXCHANGE_PATH,
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      ...(options.omitIdempotency === true ? {} : { "idempotency-key": key }),
      ...options.extraHeaders,
    },
    payload: { mutationId, handoffToken },
  });
  return { response, mutationId, key };
}

async function revoke(
  instance: AppInstance,
  label: string,
  sessionId: string,
  options: {
    readonly organizationId?: string;
    readonly mutationId?: string;
    readonly key?: string;
    readonly extraHeaders?: Record<string, string>;
  } = {},
): Promise<MutationCall> {
  const mutationId = options.mutationId ?? randomUUID();
  const key = options.key ?? idempotencyKey();
  const response = await instance.inject({
    method: "POST",
    url: revokeUrl(sessionId, options.organizationId ?? ORG1),
    headers: writeHeadersFor(label, { "idempotency-key": key, ...options.extraHeaders }),
    payload: { mutationId },
  });
  return { response, mutationId, key };
}

function humanStatus(instance: AppInstance, label: string, sessionId: string, organizationId = ORG1) {
  return instance.inject({ method: "GET", url: statusUrl(sessionId, organizationId), headers: readHeadersFor(label) });
}

function humanMutationStatus(instance: AppInstance, label: string, mutationId: string, organizationId = ORG1) {
  return instance.inject({
    method: "GET",
    url: humanMutationUrl(mutationId, organizationId),
    headers: readHeadersFor(label),
  });
}

function humanList(instance: AppInstance, label: string, query = "", organizationId = ORG1) {
  return instance.inject({ method: "GET", url: `${listUrl(organizationId)}${query}`, headers: readHeadersFor(label) });
}

function agentStatus(instance: AppInstance, token: string, mutationId: string) {
  return instance.inject({
    method: "GET",
    url: agentMutationUrl(mutationId),
    headers: { authorization: `Bearer ${token}` },
  });
}

function issueResult(response: Inject) {
  expect(response.statusCode).toBe(200);
  return CommerceControlSessionIssueResultResponseSchema.parse(response.json());
}

function exchangeResult(response: Inject) {
  expect(response.statusCode).toBe(200);
  return CommerceControlSessionExchangeResultResponseSchema.parse(response.json());
}

describe("real-PG commerce-session lifecycle over HTTP", () => {
  it("issues, exchanges, reads detail/list and revokes one delegation end to end", async () => {
    const built = await build();
    const { policyId, machine } = await provisionLifecycle(built);

    const issued = await issue(built.instance, "a", policyId);
    const issueBody = issueResult(issued.response);
    expect(issueBody.data.replayed).toBe(false);
    if (issueBody.data.replayed !== false) throw new Error("expected fresh issue");
    expect(issueBody.data.receipt.operation).toBe("control.commerce_session.issue");
    expect(issueBody.data.receipt.resourceType).toBe("commerce_session");
    expect(issueBody.data.receipt.resourceId).toBe(issued.mutationId);
    expect(issueBody.data.metadata.sessionId).toBe(issued.mutationId);
    expect(issueBody.data.metadata.exchangedAt).toBeNull();
    expect(issueBody.data.metadata.revokedAt).toBeNull();
    const handoffToken = issueBody.data.delivery.handoffToken;
    expect(handoffToken).toMatch(/^oach_v1_/);
    expect(issued.response.headers["set-cookie"]).toBeUndefined();
    expect(issued.response.headers["cache-control"]).toBe("no-store");
    expect(issued.response.headers["access-control-allow-origin"]).toBeUndefined();

    const exchanged = await exchange(built.instance, machine.token, handoffToken);
    const exchangeBody = exchangeResult(exchanged.response);
    expect(exchangeBody.data.replayed).toBe(false);
    if (exchangeBody.data.replayed !== false) throw new Error("expected fresh exchange");
    expect(exchangeBody.data.receipt.operation).toBe("control.commerce_session.exchange");
    const sessionToken = exchangeBody.data.delivery.sessionToken;
    expect(sessionToken).toMatch(/^oacs_v1_/);
    expect(exchangeBody.data.metadata.exchangedAt).not.toBeNull();
    expect(Date.parse(exchangeBody.data.metadata.expiresAt)).toBeLessThanOrEqual(
      Date.parse(issueBody.data.metadata.expiresAt) + 1,
    );

    const detail = await humanStatus(built.instance, "a", issued.mutationId);
    expect(detail.statusCode).toBe(200);
    const detailBody = CommerceControlSessionStatusResponseSchema.parse(detail.json());
    expect(detailBody.data.item?.status).toBe("active");
    expect(detailBody.data.item?.metadata.sessionId).toBe(issued.mutationId);

    const listed = await humanList(built.instance, "a");
    expect(listed.statusCode).toBe(200);
    const page = CommerceControlSessionListResponseSchema.parse(listed.json());
    expect(page.data.items.map((item) => item.metadata.sessionId)).toEqual([issued.mutationId]);

    const revoked = await revoke(built.instance, "a", issued.mutationId);
    expect(revoked.response.statusCode).toBe(200);
    const revokeBody = CommerceControlSessionRevokeResultResponseSchema.parse(revoked.response.json());
    expect(revokeBody.data.receipt.operation).toBe("control.commerce_session.revoke");
    expect(revokeBody.data.metadata.revokedAt).not.toBeNull();

    const after = await humanStatus(built.instance, "a", issued.mutationId);
    const afterBody = CommerceControlSessionStatusResponseSchema.parse(after.json());
    expect(afterBody.data.item?.status).toBe("revoked");

    expect(await durableCounts(ORG1)).toEqual({
      sessions: 1,
      handoffs: 1,
      idem: 3,
      audit: 3,
      outbox: 3,
    });
    // Raw secrets are never persisted: only the canonical hashes exist.
    expect(
      await count(
        `SELECT count(*)::text AS n FROM openarc_durable.commerce_session_handoffs
          WHERE organization_id = $1 AND handoff_hash = $2`,
        [ORG1, handoffToken],
      ),
    ).toBe(0);
  });

  it("persists the exact production hash of each delivered raw secret, including version 1", async () => {
    const built = await build();
    const { policyId, machine } = await provisionLifecycle(built);

    const issued = await issue(built.instance, "a", policyId);
    const fresh = issueResult(issued.response);
    if (fresh.data.replayed !== false) throw new Error("expected fresh issue");
    const handoffToken = fresh.data.delivery.handoffToken;
    const handoffHash = hashCommerceHandoffToken(handoffToken);
    expect(handoffHash).toMatch(/^[0-9a-f]{64}$/);
    // The delivered raw handoff token maps to the stored hash version 1; the
    // raw value itself is never the stored credential.
    expect(
      await count(
        `SELECT count(*)::text AS n FROM openarc_durable.commerce_session_handoffs
          WHERE organization_id = $1 AND handoff_hash = $2 AND hash_version = 1
            AND consumed_at IS NULL`,
        [ORG1, handoffHash],
      ),
    ).toBe(1);
    expect(
      await count(
        `SELECT count(*)::text AS n FROM openarc_durable.commerce_session_handoffs
          WHERE organization_id = $1 AND handoff_hash = $2`,
        [ORG1, handoffToken],
      ),
    ).toBe(0);

    const exchanged = await exchange(built.instance, machine.token, handoffToken);
    const exchangeFresh = exchangeResult(exchanged.response);
    if (exchangeFresh.data.replayed !== false) throw new Error("expected fresh exchange");
    const sessionToken = exchangeFresh.data.delivery.sessionToken;
    const tokenHash = hashCommerceSessionToken(sessionToken);
    expect(tokenHash).toMatch(/^[0-9a-f]{64}$/);
    const stored = await admin.query<{ token_hash: string; token_hash_version: number }>(
      `SELECT token_hash, token_hash_version FROM openarc_durable.commerce_session_handoffs
        WHERE organization_id = $1`,
      [ORG1],
    );
    expect(stored.rows[0]?.token_hash).toBe(tokenHash);
    expect(stored.rows[0]?.token_hash_version).toBe(1);
    expect(stored.rows[0]?.token_hash).not.toBe(sessionToken);
  });

  it("lets an operator drive the lifecycle and honours the 300s default and an explicit duration", async () => {
    const built = await build();
    const { policyId } = await provisionLifecycle(built);

    const defaultIssue = await issue(built.instance, "b", policyId);
    const defaultBody = issueResult(defaultIssue.response);
    if (defaultBody.data.replayed !== false) throw new Error("expected fresh issue");
    const issuedMs = Date.parse(defaultBody.data.metadata.issuedAt);
    expect(Date.parse(defaultBody.data.metadata.expiresAt)).toBeLessThanOrEqual(issuedMs + 300_001);
    expect(Date.parse(defaultBody.data.delivery.handoffExpiresAt)).toBeLessThanOrEqual(issuedMs + 300_001);

    const explicitIssue = await issue(built.instance, "b", policyId, { durationSeconds: "120" });
    const explicitBody = issueResult(explicitIssue.response);
    if (explicitBody.data.replayed !== false) throw new Error("expected fresh issue");
    const explicitMs = Date.parse(explicitBody.data.metadata.issuedAt);
    expect(Date.parse(explicitBody.data.metadata.expiresAt)).toBeLessThanOrEqual(explicitMs + 120_001);
    expect(Date.parse(explicitBody.data.delivery.handoffExpiresAt)).toBeLessThanOrEqual(explicitMs + 120_001);
  });
});

describe("real-PG commerce-session exact replay", () => {
  it("replays issue, exchange and revoke without a fresh secret or extra durable rows", async () => {
    const built = await build();
    const { policyId, machine } = await provisionLifecycle(built);

    const issued = await issue(built.instance, "a", policyId);
    const fresh = issueResult(issued.response);
    if (fresh.data.replayed !== false) throw new Error("expected fresh issue");
    const handoffToken = fresh.data.delivery.handoffToken;

    // Exact issue replay (same mutation + key): no second handoff secret.
    const issueReplay = await issue(built.instance, "a", policyId, {
      mutationId: issued.mutationId,
      key: issued.key,
    });
    const issueReplayBody = issueResult(issueReplay.response);
    expect(issueReplayBody.data.replayed).toBe(true);
    expect(issueReplayBody.data.delivery).toEqual({ state: "not_replayable" });
    expect(issueReplay.response.body).not.toContain(handoffToken);

    const exchanged = await exchange(built.instance, machine.token, handoffToken);
    const exchangeFresh = exchangeResult(exchanged.response);
    if (exchangeFresh.data.replayed !== false) throw new Error("expected fresh exchange");
    const sessionToken = exchangeFresh.data.delivery.sessionToken;

    const exchangeReplay = await exchange(built.instance, machine.token, handoffToken, {
      mutationId: exchanged.mutationId,
      key: exchanged.key,
    });
    const exchangeReplayBody = exchangeResult(exchangeReplay.response);
    expect(exchangeReplayBody.data.replayed).toBe(true);
    expect(exchangeReplayBody.data.delivery).toEqual({ state: "not_replayable" });
    expect(exchangeReplay.response.body).not.toContain(sessionToken);

    const revoked = await revoke(built.instance, "a", issued.mutationId);
    expect(revoked.response.statusCode).toBe(200);
    const revokeReplay = await revoke(built.instance, "a", issued.mutationId, {
      mutationId: revoked.mutationId,
      key: revoked.key,
    });
    expect(revokeReplay.response.statusCode).toBe(200);
    const revokeReplayBody = CommerceControlSessionRevokeResultResponseSchema.parse(revokeReplay.response.json());
    expect(revokeReplayBody.data.replayed).toBe(true);

    // Historical issue replay after revoke still returns the original record,
    // never a new secret and never a duplicate durable row.
    const historical = await issue(built.instance, "a", policyId, {
      mutationId: issued.mutationId,
      key: issued.key,
    });
    const historicalBody = issueResult(historical.response);
    expect(historicalBody.data.replayed).toBe(true);
    expect(historicalBody.data.delivery).toEqual({ state: "not_replayable" });
    expect(historicalBody.data.metadata.revokedAt).not.toBeNull();
    expect(historical.response.body).not.toContain(handoffToken);
    expect(historical.response.body).not.toContain(sessionToken);

    expect(await durableCounts(ORG1)).toEqual({
      sessions: 1,
      handoffs: 1,
      idem: 3,
      audit: 3,
      outbox: 3,
    });
    // The single handoff token hash is the ORIGINAL one and unchanged.
    expect(
      await count(
        `SELECT count(*)::text AS n FROM openarc_durable.commerce_session_handoffs
          WHERE organization_id = $1 AND consumed_at IS NOT NULL`,
        [ORG1],
      ),
    ).toBe(1);
  });

  it("freezes changed body, changed key and reused mutation contexts as conflicts", async () => {
    const built = await build();
    const { policyId, machine } = await provisionLifecycle(built);

    const issued = await issue(built.instance, "a", policyId);
    expect(issued.response.statusCode).toBe(200);
    const fresh = issueResult(issued.response);
    if (fresh.data.replayed !== false) throw new Error("expected fresh issue");

    // Same key, changed body.
    const changedBody = await issue(built.instance, "a", policyId, {
      mutationId: issued.mutationId,
      key: issued.key,
      durationSeconds: "120",
    });
    expect(changedBody.response.statusCode).toBe(409);
    expect(errorCode(changedBody.response)).toBe("IDEMPOTENCY_CONFLICT");

    // Same mutation id, changed key.
    const changedKey = await issue(built.instance, "a", policyId, {
      mutationId: issued.mutationId,
      key: idempotencyKey(),
    });
    expect(changedKey.response.statusCode).toBe(409);
    expect(errorCode(changedKey.response)).toBe("IDEMPOTENCY_CONFLICT");

    // Reused key for a fresh mutation id on the same operation.
    const reusedKey = await issue(built.instance, "a", policyId, {
      mutationId: randomUUID(),
      key: issued.key,
    });
    expect(reusedKey.response.statusCode).toBe(409);
    expect(errorCode(reusedKey.response)).toBe("IDEMPOTENCY_CONFLICT");

    const exchanged = await exchange(built.instance, machine.token, fresh.data.delivery.handoffToken);
    expect(exchanged.response.statusCode).toBe(200);

    // Same exchange key, changed mutation id.
    const exchangeChangedKey = await exchange(built.instance, machine.token, fresh.data.delivery.handoffToken, {
      mutationId: randomUUID(),
      key: exchanged.key,
    });
    expect(exchangeChangedKey.response.statusCode).toBe(409);
    expect(errorCode(exchangeChangedKey.response)).toBe("IDEMPOTENCY_CONFLICT");

    // The original data is preserved: still exactly one session/handoff record.
    expect(await durableCounts(ORG1)).toMatchObject({ sessions: 1, handoffs: 1, idem: 2 });
    const row = await admin.query<{ consumed_at: Date | null }>(
      `SELECT consumed_at FROM openarc_durable.commerce_session_handoffs WHERE organization_id = $1`,
      [ORG1],
    );
    expect(row.rows[0]?.consumed_at).not.toBeNull();
    expect(await count(`SELECT count(*)::text AS n FROM openarc_durable.commerce_sessions WHERE organization_id = $1`, [ORG1])).toBe(1);
  });
});

describe("real-PG commerce-session principal binding", () => {
  it("binds the requesting human session context exactly and never leaks a receipt cross-actor", async () => {
    const built = await build();
    const { policyId } = await provisionLifecycle(built);

    const issued = await issue(built.instance, "a", policyId);
    expect(issued.response.statusCode).toBe(200);

    // The original session sees its own committed receipt.
    const own = await humanMutationStatus(built.instance, "a", issued.mutationId);
    expect(own.statusCode).toBe(200);
    const ownBody = CommerceControlSessionMutationStatusResponseSchema.parse(own.json());
    expect(ownBody.data.status).toBe("committed");

    // A DIFFERENT account (same org, live operator) sees a safe not_found and
    // no receipt fields at all.
    const foreignActor = await humanMutationStatus(built.instance, "b", issued.mutationId);
    expect(foreignActor.statusCode).toBe(200);
    const foreignActorBody = CommerceControlSessionMutationStatusResponseSchema.parse(foreignActor.json());
    expect(foreignActorBody.data.status).toBe("not_found");
    expect(JSON.stringify(foreignActorBody.data)).not.toContain("receipt");
    expect(foreignActor.body).not.toContain("receipt");

    // A foreign-organization caller is denied (no existence oracle).
    const foreignOrg = await humanMutationStatus(built.instance, "f", issued.mutationId);
    expect(foreignOrg.statusCode).toBe(403);
    expect(foreignOrg.body).not.toContain(issued.mutationId);

    // A SECOND LIVE session of the SAME account is a DIFFERENT session context:
    // replaying the exact same issue mutation is a frozen conflict, never a
    // recovered receipt, because the request digest binds the exact session hash.
    const secondToken = b64(32);
    await seedSession(secondToken, A);
    tokens.set("a2", secondToken);
    const replay = await issue(built.instance, "a2", policyId, {
      mutationId: issued.mutationId,
      key: issued.key,
    });
    expect(replay.response.statusCode).toBe(409);
    expect(errorCode(replay.response)).toBe("IDEMPOTENCY_CONFLICT");
    expect(replay.response.body).not.toContain("oach_v1_");

    // The original session still holds exactly one durable record.
    expect(await durableCounts(ORG1)).toMatchObject({ sessions: 1, handoffs: 1, idem: 1 });
  });

  it("hides issue and revoke receipts from a second live session of the SAME account and never exposes an exchange receipt", async () => {
    const built = await build();
    const { policyId, machine } = await provisionLifecycle(built);

    const issued = await issue(built.instance, "a", policyId);
    const fresh = issueResult(issued.response);
    if (fresh.data.replayed !== false) throw new Error("expected fresh issue");
    const handoffToken = fresh.data.delivery.handoffToken;
    const exchanged = await exchange(built.instance, machine.token, handoffToken);
    const exchangeFresh = exchangeResult(exchanged.response);
    if (exchangeFresh.data.replayed !== false) throw new Error("expected fresh exchange");
    const revoked = await revoke(built.instance, "a", issued.mutationId);
    expect(revoked.response.statusCode).toBe(200);

    // The ORIGINAL session sees its own committed issue and revoke receipts.
    for (const mutation of [issued.mutationId, revoked.mutationId]) {
      const own = await humanMutationStatus(built.instance, "a", mutation);
      expect(own.statusCode).toBe(200);
      const ownBody = CommerceControlSessionMutationStatusResponseSchema.parse(own.json());
      expect(ownBody.data.status).toBe("committed");
    }

    // Exchange is a MACHINE context: even the ORIGINAL issue-driving human
    // session must NOT recover the exchange receipt through the human endpoint.
    const humanExchange = await humanMutationStatus(built.instance, "a", exchanged.mutationId);
    expect(humanExchange.statusCode).toBe(200);
    const humanExchangeBody = CommerceControlSessionMutationStatusResponseSchema.parse(
      humanExchange.json(),
    );
    expect(humanExchangeBody.data.status).toBe("not_found");
    expect(JSON.stringify(humanExchangeBody.data)).not.toContain("receipt");
    expect(humanExchange.body).not.toContain("receipt");

    // A SECOND LIVE session for the SAME account A is a DIFFERENT session
    // context. It must not recover either the issue or the revoke receipt, and
    // must not recover the exchange receipt either.
    const secondToken = b64(32);
    await seedSession(secondToken, A);
    tokens.set("a2", secondToken);
    for (const mutation of [issued.mutationId, revoked.mutationId, exchanged.mutationId]) {
      const second = await humanMutationStatus(built.instance, "a2", mutation);
      expect(second.statusCode).toBe(200);
      const secondBody = CommerceControlSessionMutationStatusResponseSchema.parse(second.json());
      expect(secondBody.data.status).toBe("not_found");
      expect(JSON.stringify(secondBody.data)).not.toContain("receipt");
    }

    // No extra durable record was fabricated by any of the denied reads.
    expect(await durableCounts(ORG1)).toMatchObject({ sessions: 1, handoffs: 1, idem: 3, audit: 3, outbox: 3 });
  });

  it("binds the agent status read to the exact exchanged machine session", async () => {
    const built = await build();
    const { policyId, machine } = await provisionLifecycle(built);

    const issued = await issue(built.instance, "a", policyId);
    const fresh = issueResult(issued.response);
    if (fresh.data.replayed !== false) throw new Error("expected fresh issue");
    const exchanged = await exchange(built.instance, machine.token, fresh.data.delivery.handoffToken);
    expect(exchanged.response.statusCode).toBe(200);

    const own = await agentStatus(built.instance, machine.token, exchanged.mutationId);
    expect(own.statusCode).toBe(200);
    const ownBody = CommerceControlSessionMutationStatusResponseSchema.parse(own.json());
    expect(ownBody.data.status).toBe("committed");
    expect(ownBody.data.receipt.operation).toBe("control.commerce_session.exchange");

    // A SECOND live session for the SAME agent/credential is a different
    // machine session and cannot read the exchange receipt.
    const secondToken = generateSessionToken("agent");
    await built.credentials.createAgentSession({
      organizationId: ORG1,
      profileId: AGENT1,
      credentialId: machine.credentialId,
      expectedVersion: 1,
      sessionId: randomUUID(),
      tokenHash: hashSessionToken("agent", secondToken),
      expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
    });
    const second = await agentStatus(built.instance, secondToken, exchanged.mutationId);
    expect(second.statusCode).toBe(200);
    const secondBody = CommerceControlSessionMutationStatusResponseSchema.parse(second.json());
    expect(secondBody.data.status).toBe("not_found");
    expect(JSON.stringify(secondBody.data)).not.toContain("receipt");

    // A different agent (same organization) cannot read it either.
    const otherMachine = await provisionMachine(built.credentials, { agentId: AGENT2 });
    const other = await agentStatus(built.instance, otherMachine.token, exchanged.mutationId);
    expect(other.statusCode).toBe(200);
    expect(
      CommerceControlSessionMutationStatusResponseSchema.parse(other.json()).data.status,
    ).toBe("not_found");
    expect(other.body).not.toContain("receipt");

    // A foreign-organization agent cannot read it.
    const foreignMachine = await provisionMachine(built.credentials, {
      organizationId: ORG2,
      agentId: AGENT_ORG2,
      ownerLabel: "f",
    });
    const foreign = await agentStatus(built.instance, foreignMachine.token, exchanged.mutationId);
    expect(foreign.statusCode).toBe(200);
    expect(
      CommerceControlSessionMutationStatusResponseSchema.parse(foreign.json()).data.status,
    ).toBe("not_found");
  });
});

describe("real-PG commerce-session authority", () => {
  it("denies viewer and provider memberships every read and write", async () => {
    const built = await build();
    const { policyId } = await provisionLifecycle(built);
    const issued = await issue(built.instance, "a", policyId);
    expect(issued.response.statusCode).toBe(200);

    for (const label of ["c", "d", "e"] as const) {
      expect((await humanList(built.instance, label)).statusCode).toBe(403);
      expect((await humanStatus(built.instance, label, issued.mutationId)).statusCode).toBe(403);
      expect((await humanMutationStatus(built.instance, label, issued.mutationId)).statusCode).toBe(403);
      const write = await issue(built.instance, label, policyId);
      expect(write.response.statusCode).toBe(403);
      expect(errorCode(write.response)).toBe("FORBIDDEN");
      const revokeDenied = await revoke(built.instance, label, issued.mutationId);
      expect(revokeDenied.response.statusCode).toBe(403);
    }

    // Non-member is denied without an oracle.
    const nonMember = await humanStatus(built.instance, "g", issued.mutationId);
    expect(nonMember.statusCode).toBe(403);
    expect(nonMember.body).not.toContain(issued.mutationId);

    expect(await durableCounts(ORG1)).toMatchObject({ sessions: 1, handoffs: 1, idem: 1, audit: 1, outbox: 1 });
  });

  it("denies stale non-recovery proofs and every recovery session read/write", async () => {
    const built = await build();
    const { policyId } = await provisionLifecycle(built);

    // A recovered/stale session is denied both the write and the read paths.
    const recoveryToken = b64(32);
    await seedSession(recoveryToken, B, { method: "recovery" });
    tokens.set("recovery", recoveryToken);
    expect((await humanList(built.instance, "recovery")).statusCode).toBe(401);
    const recoveryIssue = await issue(built.instance, "recovery", policyId);
    expect(recoveryIssue.response.statusCode).toBe(401);

    // A non-recovery proof older than five minutes cannot write.
    await admin.query(
      `UPDATE openarc_auth.sessions SET created_at = clock_timestamp() - interval '6 minutes'
        WHERE token_hash = $1`,
      [authTokenHash(tokens.get("a") ?? "")],
    );
    const stale = await issue(built.instance, "a", policyId);
    expect(stale.response.statusCode).toBe(401);
    expect(await durableCounts(ORG1)).toEqual({ sessions: 0, handoffs: 0, idem: 0, audit: 0, outbox: 0 });
  });

  it("rejects a cross-org subject or policy and a same-org wrong-agent handoff with no business mutation", async () => {
    const built = await build();
    const { policyId } = await provisionLifecycle(built);

    // Cross-organization subject agent on an ORG1 path/body.
    const crossSubject = await issue(built.instance, "a", policyId, { subjectAgentId: AGENT_ORG2 });
    expect(crossSubject.response.statusCode).toBe(403);

    // Cross-organization policy id on an ORG1 request.
    const foreignPolicy = await createPolicy(ORG2, AGENT_ORG2, "f");
    const crossPolicy = await issue(built.instance, "a", foreignPolicy);
    expect(crossPolicy.response.statusCode).toBe(403);

    // A same-org handoff issued to AGENT1 cannot be consumed by an AGENT2 machine.
    const issued = await issue(built.instance, "a", policyId);
    const fresh = issueResult(issued.response);
    if (fresh.data.replayed !== false) throw new Error("expected fresh issue");
    const wrongAgent = await provisionMachine(built.credentials, { agentId: AGENT2 });
    const wrongExchange = await exchange(built.instance, wrongAgent.token, fresh.data.delivery.handoffToken);
    expect(wrongExchange.response.statusCode).toBe(403);
    expect(wrongExchange.response.body).not.toContain(fresh.data.delivery.handoffToken);
    expect(await durableCounts(ORG1)).toMatchObject({ sessions: 1, handoffs: 1, idem: 1 });
    const bound = await admin.query<{ exchanged_at: Date | null }>(
      `SELECT exchanged_at FROM openarc_durable.commerce_sessions WHERE organization_id = $1`,
      [ORG1],
    );
    expect(bound.rows[0]?.exchanged_at).toBeNull();
  });
});

describe("real-PG commerce-session concurrency and revocation", () => {
  it("allows exactly one of two concurrent exchanges under distinct mutation ids", async () => {
    const built = await build();
    const { policyId, machine } = await provisionLifecycle(built);
    const issued = await issue(built.instance, "a", policyId);
    const fresh = issueResult(issued.response);
    if (fresh.data.replayed !== false) throw new Error("expected fresh issue");
    const handoffToken = fresh.data.delivery.handoffToken;

    const settled = await Promise.allSettled([
      exchange(built.instance, machine.token, handoffToken),
      exchange(built.instance, machine.token, handoffToken),
    ]);
    const statuses = settled.map((entry) =>
      entry.status === "fulfilled" ? entry.value.response.statusCode : 0,
    );
    expect(statuses.filter((status) => status === 200)).toHaveLength(1);
    // The loser observes the already-consumed handoff as a fixed denial; it
    // must never succeed or create a second binding.
    expect(statuses.filter((status) => status !== 200)).toHaveLength(1);
    for (const status of statuses.filter((value) => value !== 200)) {
      expect([400, 403, 409]).toContain(status);
    }

    expect(
      await count(
        `SELECT count(*)::text AS n FROM openarc_durable.commerce_sessions
          WHERE organization_id = $1 AND exchanged_at IS NOT NULL`,
        [ORG1],
      ),
    ).toBe(1);
    expect(
      await count(
        `SELECT count(*)::text AS n FROM openarc_durable.commerce_session_handoffs
          WHERE organization_id = $1 AND consumed_at IS NOT NULL`,
        [ORG1],
      ),
    ).toBe(1);
    expect(await durableCounts(ORG1)).toMatchObject({ sessions: 1, handoffs: 1, idem: 2, audit: 2, outbox: 2 });
  }, 20_000);

  it("refuses a fresh exchange after the approving parent human session is gone", async () => {
    const built = await build();
    const { policyId, machine } = await provisionLifecycle(built);
    const issued = await issue(built.instance, "a", policyId);
    const fresh = issueResult(issued.response);
    if (fresh.data.replayed !== false) throw new Error("expected fresh issue");

    // Logout/recovery deletes the parent auth session row without deleting history.
    await admin.query("DELETE FROM openarc_auth.sessions WHERE token_hash = $1", [
      authTokenHash(tokens.get("a") ?? ""),
    ]);
    const denied = await exchange(built.instance, machine.token, fresh.data.delivery.handoffToken);
    // A dead parent session collapses to the fixed non-disclosing 401.
    expect(denied.response.statusCode).toBe(401);
    expect(denied.response.body).not.toContain(fresh.data.delivery.handoffToken);
    expect(await durableCounts(ORG1)).toMatchObject({ sessions: 1, handoffs: 1, idem: 1, audit: 1, outbox: 1 });
  });

  it("refuses a fresh exchange after the machine session or its credential is revoked", async () => {
    const built = await build();
    const { policyId, machine } = await provisionLifecycle(built);
    const issued = await issue(built.instance, "a", policyId);
    const fresh = issueResult(issued.response);
    if (fresh.data.replayed !== false) throw new Error("expected fresh issue");

    await built.credentials.revokeAgentSession(hashSessionToken("agent", machine.token));
    const denied = await exchange(built.instance, machine.token, fresh.data.delivery.handoffToken);
    expect(denied.response.statusCode).toBe(403);
    expect(await durableCounts(ORG1)).toMatchObject({ sessions: 1, handoffs: 1, idem: 1 });
  });

  it("denies a revoked requesting credential recovery of a committed exchange receipt", async () => {
    const built = await build();
    const { policyId, machine } = await provisionLifecycle(built);
    const issued = await issue(built.instance, "a", policyId);
    const fresh = issueResult(issued.response);
    if (fresh.data.replayed !== false) throw new Error("expected fresh issue");
    const exchanged = await exchange(built.instance, machine.token, fresh.data.delivery.handoffToken);
    expect(exchanged.response.statusCode).toBe(200);

    await built.credentials.revokeAgentCredentialDurably({
      sessionHash: authTokenHash(tokens.get("a") ?? ""),
      organizationId: ORG1,
      credentialId: machine.credentialId,
      metadata: { idempotencyKey: idempotencyKey(), mutationId: randomUUID() },
    });
    const replay = await exchange(built.instance, machine.token, fresh.data.delivery.handoffToken, {
      mutationId: exchanged.mutationId,
      key: exchanged.key,
    });
    expect(replay.response.statusCode).toBe(403);
    expect(replay.response.body).not.toContain('"receipt"');
    expect(await durableCounts(ORG1)).toMatchObject({ sessions: 1, handoffs: 1, idem: 2 });
  });
});

describe("real-PG commerce-session durability rollback", () => {
  it("rolls the whole issue back when the outbox insert fails", async () => {
    const built = await build();
    const { policyId } = await provisionLifecycle(built);
    await admin.query(
      `CREATE FUNCTION openarc_tenant.test_inject_session_issue_outbox() RETURNS trigger
         LANGUAGE plpgsql SET search_path = pg_catalog AS $$
         BEGIN
           IF NEW.event_type = 'control.commerce_session.issued' THEN
             RAISE EXCEPTION 'injected_outbox_failure' USING ERRCODE = '42501';
           END IF;
           RETURN NEW;
         END;
         $$`,
    );
    await admin.query(
      `CREATE TRIGGER test_inject_session_issue_outbox
         BEFORE INSERT ON openarc_durable.outbox_events
         FOR EACH ROW EXECUTE FUNCTION openarc_tenant.test_inject_session_issue_outbox()`,
    );
    try {
      const denied = await issue(built.instance, "a", policyId);
      expect(denied.response.statusCode).toBe(403);
      expect(await durableCounts(ORG1)).toEqual({ sessions: 0, handoffs: 0, idem: 0, audit: 0, outbox: 0 });
    } finally {
      await admin.query("DROP TRIGGER test_inject_session_issue_outbox ON openarc_durable.outbox_events");
      await admin.query("DROP FUNCTION openarc_tenant.test_inject_session_issue_outbox()");
    }
  }, 20_000);

  it("rolls the exchange back and leaves the handoff unconsumed when its outbox insert fails", async () => {
    const built = await build();
    const { policyId, machine } = await provisionLifecycle(built);
    const issued = await issue(built.instance, "a", policyId);
    const fresh = issueResult(issued.response);
    if (fresh.data.replayed !== false) throw new Error("expected fresh issue");
    await admin.query(
      `CREATE FUNCTION openarc_tenant.test_inject_session_exchange_outbox() RETURNS trigger
         LANGUAGE plpgsql SET search_path = pg_catalog AS $$
         BEGIN
           IF NEW.event_type = 'control.commerce_session.exchanged' THEN
             RAISE EXCEPTION 'injected_outbox_failure' USING ERRCODE = '42501';
           END IF;
           RETURN NEW;
         END;
         $$`,
    );
    await admin.query(
      `CREATE TRIGGER test_inject_session_exchange_outbox
         BEFORE INSERT ON openarc_durable.outbox_events
         FOR EACH ROW EXECUTE FUNCTION openarc_tenant.test_inject_session_exchange_outbox()`,
    );
    try {
      const denied = await exchange(built.instance, machine.token, fresh.data.delivery.handoffToken);
      expect(denied.response.statusCode).toBe(403);
      const row = await admin.query<{
        exchanged_at: Date | null;
        consumed_at: Date | null;
        token_hash: string | null;
      }>(
        `SELECT s.exchanged_at, h.consumed_at, h.token_hash
           FROM openarc_durable.commerce_sessions s
           JOIN openarc_durable.commerce_session_handoffs h
             ON h.organization_id = s.organization_id AND h.session_id = s.session_id
          WHERE s.organization_id = $1`,
        [ORG1],
      );
      expect(row.rows[0]?.exchanged_at).toBeNull();
      expect(row.rows[0]?.consumed_at).toBeNull();
      expect(row.rows[0]?.token_hash).toBeNull();
      expect(await durableCounts(ORG1)).toMatchObject({ sessions: 1, handoffs: 1, idem: 1, audit: 1, outbox: 1 });
    } finally {
      await admin.query("DROP TRIGGER test_inject_session_exchange_outbox ON openarc_durable.outbox_events");
      await admin.query("DROP FUNCTION openarc_tenant.test_inject_session_exchange_outbox()");
    }
  }, 20_000);
});

describe("real-PG commerce-session post-commit reply loss", () => {
  it("maps an unknown issue commit to a secret-free 503 and recovers only via explicit status", async () => {
    const store = new CommerceSessionStore(asCommerceSessionPool(tenant));
    await store.initialize();
    let calls = 0;
    const port = delegateStore(store, {
      issueCommerceSession: async (...args: Parameters<CommerceSessionStorePort["issueCommerceSession"]>) => {
        calls += 1;
        await store.issueCommerceSession(...args);
        // The transaction committed but the reply was lost.
        throw new CommerceSessionStoreError("COMMERCE_SESSION_STORE_OUTCOME_UNKNOWN");
      },
    });
    const built = await build({ storeOverride: port });
    const { policyId } = await provisionLifecycle(built);

    const denied = await issue(built.instance, "a", policyId);
    expect(denied.response.statusCode).toBe(503);
    expect(denied.response.json().error.retryable).toBe(false);
    expect(denied.response.body).not.toContain("oach_v1_");
    expect(calls).toBe(1);

    // An independent admin connection proves the operation committed exactly once.
    expect(await durableCounts(ORG1)).toEqual({ sessions: 1, handoffs: 1, idem: 1, audit: 1, outbox: 1 });

    // Only the explicit original mutation status recovers the safe receipt.
    const status = await humanMutationStatus(built.instance, "a", denied.mutationId);
    expect(status.statusCode).toBe(200);
    const statusBody = CommerceControlSessionMutationStatusResponseSchema.parse(status.json());
    expect(statusBody.data.status).toBe("committed");
    if (statusBody.data.status !== "committed") throw new Error("expected committed");
    expect(statusBody.data.receipt.operation).toBe("control.commerce_session.issue");
    expect(status.body).not.toContain("oach_v1_");
    expect(status.body).not.toContain("delivery");
    // No automatic resend occurred.
    expect(calls).toBe(1);
    expect(await durableCounts(ORG1)).toEqual({ sessions: 1, handoffs: 1, idem: 1, audit: 1, outbox: 1 });
  }, 20_000);

  it("maps an unknown exchange commit to a secret-free 503 with no second exchange", async () => {
    const store = new CommerceSessionStore(asCommerceSessionPool(tenant));
    await store.initialize();
    let calls = 0;
    const port = delegateStore(store, {
      exchangeCommerceSession: async (...args: Parameters<CommerceSessionStorePort["exchangeCommerceSession"]>) => {
        calls += 1;
        await store.exchangeCommerceSession(...args);
        throw new CommerceSessionStoreError("COMMERCE_SESSION_STORE_OUTCOME_UNKNOWN");
      },
    });
    const built = await build({ storeOverride: port });
    const { policyId, machine } = await provisionLifecycle(built);
    const issued = await issue(built.instance, "a", policyId);
    const fresh = issueResult(issued.response);
    if (fresh.data.replayed !== false) throw new Error("expected fresh issue");

    const denied = await exchange(built.instance, machine.token, fresh.data.delivery.handoffToken);
    expect(denied.response.statusCode).toBe(503);
    expect(denied.response.json().error.retryable).toBe(false);
    expect(denied.response.body).not.toContain("oacs_v1_");
    expect(calls).toBe(1);

    const status = await agentStatus(built.instance, machine.token, denied.mutationId);
    expect(status.statusCode).toBe(200);
    expect(
      CommerceControlSessionMutationStatusResponseSchema.parse(status.json()).data.status,
    ).toBe("committed");
    expect(status.body).not.toContain("oacs_v1_");
    expect(calls).toBe(1);
    expect(await durableCounts(ORG1)).toMatchObject({ sessions: 1, handoffs: 1, idem: 2, audit: 2, outbox: 2 });
  }, 20_000);
});

describe("real-PG commerce-session post-read guard", () => {
  it("denies a human status read whose session is revoked after the database read", async () => {
    const store = new CommerceSessionStore(asCommerceSessionPool(tenant));
    await store.initialize();
    const port = delegateStore(store, {
      getCommerceSessionStatus: async (
        ...args: Parameters<CommerceSessionStorePort["getCommerceSessionStatus"]>
      ) => {
        const result = await store.getCommerceSessionStatus(...args);
        await admin.query("DELETE FROM openarc_auth.sessions WHERE token_hash = $1", [
          authTokenHash(tokens.get("a") ?? ""),
        ]);
        return result;
      },
    });
    const built = await build({ storeOverride: port });
    const { policyId } = await provisionLifecycle(built);
    const issued = await issue(built.instance, "a", policyId);
    expect(issued.response.statusCode).toBe(200);

    const committed = await humanStatus(built.instance, "a", issued.mutationId);
    expect(committed.statusCode).toBe(401);
    expect(committed.body).not.toContain('"data"');

    // Restore the session and exercise the not-found result through the same guard.
    await seedSession(tokens.get("a") ?? "", A);
    const missing = await humanStatus(built.instance, "a", randomUUID());
    expect(missing.statusCode).toBe(401);
    expect(missing.body).not.toContain('"data"');
  }, 20_000);

  it("denies an agent status read whose machine session is revoked after the database read", async () => {
    const credentials = new CredentialStore(asCredentialPool(tenant));
    await credentials.initialize();
    const store = new CommerceSessionStore(asCommerceSessionPool(tenant));
    await store.initialize();
    const port = delegateStore(store, {
      getAgentCommerceSessionMutationStatus: async (
        ...args: Parameters<CommerceSessionStorePort["getAgentCommerceSessionMutationStatus"]>
      ) => {
        const result = await store.getAgentCommerceSessionMutationStatus(...args);
        await credentials.revokeAgentSession(args[0]);
        return result;
      },
    });
    const built = await build({ storeOverride: port });
    const { policyId, machine } = await provisionLifecycle(built);
    const issued = await issue(built.instance, "a", policyId);
    const fresh = issueResult(issued.response);
    if (fresh.data.replayed !== false) throw new Error("expected fresh issue");
    const exchanged = await exchange(built.instance, machine.token, fresh.data.delivery.handoffToken);
    expect(exchanged.response.statusCode).toBe(200);

    const denied = await agentStatus(built.instance, machine.token, exchanged.mutationId);
    expect(denied.statusCode).toBe(401);
    expect(denied.body).not.toContain('"data"');
  }, 20_000);

  it("denies an agent status read whose actual database not_found is followed by revocation", async () => {
    const credentials = new CredentialStore(asCredentialPool(tenant));
    await credentials.initialize();
    const store = new CommerceSessionStore(asCommerceSessionPool(tenant));
    await store.initialize();
    const port = delegateStore(store, {
      getAgentCommerceSessionMutationStatus: async (
        ...args: Parameters<CommerceSessionStorePort["getAgentCommerceSessionMutationStatus"]>
      ) => {
        // Exercise the not_found branch of the real DB9 reader: the requested
        // mutation genuinely does not exist for this machine session.
        const result = await store.getAgentCommerceSessionMutationStatus(...args);
        expect(result).toEqual({ status: "not_found" });
        await credentials.revokeAgentSession(args[0]);
        return result;
      },
    });
    const built = await build({ storeOverride: port });
    const { machine } = await provisionLifecycle(built);

    const denied = await agentStatus(built.instance, machine.token, randomUUID());
    expect(denied.statusCode).toBe(401);
    expect(denied.body).not.toContain('"data"');
    expect(denied.body).not.toContain('"receipt"');
  }, 20_000);
});

describe("real-PG commerce-session transport negatives", () => {
  it("rejects bad CSRF, foreign Origin, mixed credentials and wrong token namespaces before any business mutation", async () => {
    const built = await build();
    const { policyId, machine } = await provisionLifecycle(built);

    const forgedCsrf = await built.instance.inject({
      method: "POST",
      url: listUrl(),
      headers: writeHeadersFor("a", { "x-openarc-csrf": "forged-csrf-value" }),
      payload: { mutationId: randomUUID(), subjectAgentId: AGENT1, policyId },
    });
    expect(forgedCsrf.statusCode).toBe(403);
    expect(errorCode(forgedCsrf)).toBe("CSRF_REJECTED");
    expect(forgedCsrf.body).not.toContain("forged-csrf-value");

    const foreignOrigin = await built.instance.inject({
      method: "GET",
      url: listUrl(),
      headers: { origin: "https://evil.example", "x-openarc-client": "browser-v1", cookie: `${SESSION_COOKIE}=${tokens.get("a") ?? ""}` },
    });
    expect(foreignOrigin.statusCode).toBe(403);
    expect(errorCode(foreignOrigin)).toBe("INVALID_ORIGIN");

    // A human route bearing Authorization is a mixed-transport rejection.
    const mixedHuman = await built.instance.inject({
      method: "GET",
      url: listUrl(),
      headers: readHeadersFor("a", { authorization: `Bearer ${machine.token}` }),
    });
    expect(mixedHuman.statusCode).toBe(400);
    expect(mixedHuman.body).not.toContain(machine.token);

    // An agent route bearing a browser cookie is a mixed-transport rejection.
    const mixedAgent = await exchange(built.instance, machine.token, `oach_v1_${"A".repeat(43)}`, {
      extraHeaders: { cookie: `${SESSION_COOKIE}=${tokens.get("a") ?? ""}` },
    });
    expect(mixedAgent.response.statusCode).toBe(400);
    expect(mixedAgent.response.body).not.toContain(tokens.get("a") ?? "unlikely");

    // A provider-namespace bearer and a commerce-session token are both 401.
    const providerToken = generateSessionToken("provider");
    const wrongNamespace = await exchange(built.instance, providerToken, `oach_v1_${"A".repeat(43)}`);
    expect(wrongNamespace.response.statusCode).toBe(401);
    const commerceToken = `oacs_v1_${"A".repeat(43)}`;
    const commerceBearer = await exchange(built.instance, commerceToken, `oach_v1_${"A".repeat(43)}`);
    expect(commerceBearer.response.statusCode).toBe(401);

    // An unknown issue body field is rejected and fabricates nothing.
    const unknownBody = await issue(built.instance, "a", policyId, { extraBody: { unexpected: true } });
    expect(unknownBody.response.statusCode).toBe(400);
    expect(errorCode(unknownBody.response)).toBe("INVALID_REQUEST");
    expect(await durableCounts(ORG1)).toEqual({ sessions: 0, handoffs: 0, idem: 0, audit: 0, outbox: 0 });
  }, 20_000);

  it("paginates issued sessions with exact ordering, cursors and bounds and never leaks a raw secret", async () => {
    const logs: unknown[] = [];
    const auth = authService();
    const authStore = new AuthStore(app);
    const store = new CommerceSessionStore(asCommerceSessionPool(tenant));
    await store.initialize();
    const credentials = new CredentialStore(asCredentialPool(tenant));
    await credentials.initialize();
    const service = new CommerceSessionService({
      auth,
      store: store as unknown as CommerceSessionStorePort,
      agentSessions: { getAgentSession: (hash: unknown) => credentials.getAgentSession(hash) },
      limits: new CommerceSessionRateLimiter({
        secret: SECRET,
        store: { consume: (input) => authStore.consumeRateLimit(input) },
      }),
    });
    const instance = createApp({
      config: loadConfig(buildFlags()),
      logger: false,
      logSink: (entry) => logs.push(entry),
      authService: auth,
      authReady: async () => true,
      commerceSessionService: service,
      commerceSessionReady: async () => true,
    });

    const policyId = await createPolicy(ORG1, AGENT1);
    const machine = await provisionMachine(credentials, {});
    const secrets: string[] = [];
    const sessionIds: string[] = [];
    for (let index = 0; index < 3; index += 1) {
      const issued = await issue(instance, "a", policyId);
      const body = issueResult(issued.response);
      if (body.data.replayed !== false) throw new Error("expected fresh issue");
      secrets.push(body.data.delivery.handoffToken);
      sessionIds.push(body.data.metadata.sessionId);
    }
    const exchanged = await exchange(instance, machine.token, secrets[0] as string);
    const exchangeBody = exchangeResult(exchanged.response);
    if (exchangeBody.data.replayed !== false) throw new Error("expected fresh exchange");
    secrets.push(exchangeBody.data.delivery.sessionToken);
    const sorted = [...sessionIds].sort();

    const all = await humanList(instance, "a");
    expect(all.statusCode).toBe(200);
    const allPage = CommerceControlSessionListResponseSchema.parse(all.json());
    expect(allPage.data.items.map((item) => item.metadata.sessionId)).toEqual(sorted);
    expect(allPage.data.nextCursor).toBeNull();

    const first = await humanList(instance, "a", "?limit=2");
    const firstPage = CommerceControlSessionListResponseSchema.parse(first.json());
    expect(firstPage.data.items.map((item) => item.metadata.sessionId)).toEqual(sorted.slice(0, 2));
    expect(firstPage.data.nextCursor).toBe(sorted[1]);

    const second = await humanList(
      instance,
      "a",
      `?limit=2&afterSessionId=${encodeURIComponent(firstPage.data.nextCursor ?? "")}`,
    );
    const secondPage = CommerceControlSessionListResponseSchema.parse(second.json());
    expect(secondPage.data.items.map((item) => item.metadata.sessionId)).toEqual(sorted.slice(2));
    expect(secondPage.data.nextCursor).toBeNull();

    for (const query of ["?limit=0", "?limit=51", "?limit=01", "?limit=1&limit=2", "?unknown=1", "?afterSessionId=not-a-session"]) {
      const rejected = await humanList(instance, "a", query);
      expect(rejected.statusCode, query).toBe(400);
    }

    // No raw secret may appear in any list/status/error body or in the logs.
    const listBody = all.body + first.body + second.body;
    for (const secret of secrets) expect(listBody).not.toContain(secret);
    const detail = await humanStatus(instance, "a", sessionIds[0] as string);
    expect(detail.body).not.toContain(secrets[0] as string);
    expect(JSON.stringify(logs)).not.toContain(SECRET);
    for (const secret of secrets) expect(JSON.stringify(logs)).not.toContain(secret);
  }, 20_000);
});

describe("real-PG commerce-session runtime independence", () => {
  it("runs the preprovisioned lifecycle with the session runtime on and every other HTTP family off", async () => {
    const credentials = new CredentialStore(asCredentialPool(tenant));
    await credentials.initialize();
    const policyId = await createPolicy(ORG1, AGENT1);
    const machine = await provisionMachine(credentials, {});

    const runtime = await startCommerceSessionRuntime({
      tenantDatabaseUrl: tenantUrl(),
      authSecret: SECRET,
      auth: authService(),
      rateLimitStore: { consume: (input) => new AuthStore(app).consumeRateLimit(input) },
    });
    try {
      await expect(runtime.ready()).resolves.toBe(true);
      const instance = createApp({
        config: loadConfig(
          buildFlags({
            POLICY_MANAGEMENT_ENABLED: "false",
            MACHINE_CREDENTIAL_MANAGEMENT_ENABLED: "false",
            MACHINE_SESSION_EXCHANGE_ENABLED: "false",
            LISTING_MANAGEMENT_ENABLED: "false",
            MARKET_CATALOG_ENABLED: "false",
            MARKET_MODERATION_ENABLED: "false",
          }),
        ),
        logger: false,
        authService: authService(),
        authReady: async () => true,
        commerceSessionService: runtime.service,
        commerceSessionReady: () => runtime.ready(),
      });
      try {
        const ready = await instance.inject({ method: "GET", url: "/readyz" });
        expect(ready.statusCode).toBe(200);
        expect(ready.json().checks.commerceSessionDatabase).toBe("up");
        expect(ready.json().checks.tenantDatabase).toBeUndefined();
        expect(ready.json().checks.machineDatabase).toBeUndefined();
        expect(ready.json().checks.policyDatabase).toBeUndefined();

        const capability = await instance.inject({ method: "GET", url: SESSION_CAPABILITIES_PATH });
        expect(capability.statusCode).toBe(200);
        const manifest = SessionCapabilitiesSuccessEnvelopeSchema.parse(capability.json());
        expect(manifest.data.capabilities.map((entry) => entry.state)).toEqual(["enabled", "enabled"]);
        expect(manifest.data.routes).toHaveLength(7);

        const issued = await issue(instance, "a", policyId);
        const fresh = issueResult(issued.response);
        if (fresh.data.replayed !== false) throw new Error("expected fresh issue");
        const exchanged = await exchange(instance, machine.token, fresh.data.delivery.handoffToken);
        expect(exchanged.response.statusCode).toBe(200);
        const revoked = await revoke(instance, "a", issued.mutationId);
        expect(revoked.response.statusCode).toBe(200);
      } finally {
        await instance.close();
      }
    } finally {
      await runtime.close();
    }
  }, 30_000);

  it("registers none of the seven routes and reports built_disabled while the session flag is off", async () => {
    const instance = createApp({
      config: loadConfig(buildFlags({ COMMERCE_SESSIONS_ENABLED: "false" })),
      logger: false,
      authService: authService(),
      authReady: async () => true,
    });
    try {
      const browserHeaders = readHeadersFor("a");
      for (const route of SESSION_ROUTES) {
        const url = route.path
          .replace(":organizationId", ORG1)
          .replace(":sessionId", randomUUID())
          .replace(":mutationId", randomUUID());
        const isAgent = route.family === "commerce_session_exchange";
        const response = await instance.inject({
          method: route.method,
          url,
          headers: isAgent
            ? { authorization: `Bearer ${generateSessionToken("agent")}` }
            : route.method === "POST"
              ? writeHeadersFor("a")
              : browserHeaders,
          ...(route.method === "POST" && !isAgent ? { payload: { mutationId: randomUUID() } } : {}),
        });
        expect(response.statusCode, `${route.method} ${url}`).toBe(404);
      }

      const capability = await instance.inject({ method: "GET", url: SESSION_CAPABILITIES_PATH });
      expect(capability.statusCode).toBe(200);
      const manifest = SessionCapabilitiesSuccessEnvelopeSchema.parse(capability.json());
      expect(manifest.data.capabilities.map((entry) => entry.state)).toEqual([
        "built_disabled",
        "built_disabled",
      ]);
      expect(manifest.data.routes).toHaveLength(7);
    } finally {
      await instance.close();
    }
  });
});
