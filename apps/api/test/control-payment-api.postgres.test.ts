import { createHash } from "node:crypto";
import type { Pool } from "pg";
import Fastify, { type FastifyInstance } from "fastify";

import { API_MAX_REQUEST_BYTES } from "@openarc/shared";
import {
  asCommerceSessionPool,
  asControlActionPool,
  asControlGrantPool,
  asControlPaymentAttemptPool,
  CommerceSessionStore,
  ControlActionStore,
  ControlActionStoreError,
  ControlGrantStore,
  ControlPaymentAttemptStore,
  CredentialStore,
  MarketLifecycleStore,
  MarketStore,
  createDatabasePool,
  digestCommerceGrantToken,
  digestPaymentAttemptBinding,
  migrate,
  reviewedEndpointDigest,
  type PaymentAttemptBindingInput,
} from "@openarc/db";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { AUTH_ERRORS, AuthApiError, authErrorEnvelope } from "../src/auth/errors.js";
import type { CommercePaymentAuthPort } from "../src/control/payment-ports.js";
import { CommercePaymentRateLimiter } from "../src/control/payment-rate-limiter.js";
import { registerCommercePaymentRoutes } from "../src/control/payment-routes.js";
import { CommercePaymentService } from "../src/control/payment-service.js";
import {
  createCommercePaymentActionReadAdapter,
  createCommercePaymentSessionReadAdapter,
  createCommercePaymentStoreAdapter,
} from "../src/control/payment-store-adapter.js";
import {
  generateCommerceSessionToken,
  hashCommerceSessionToken,
} from "../src/control/session-crypto.js";
import {
  adminPool,
  ensureRoles,
  migratorUrl,
  resetSchema,
  tenantUrl,
} from "../../../packages/db/test/postgres-fixture.js";

/**
 * REAL PostgreSQL end-to-end proof for the migration-0015 payment HTTP slice.
 *
 * The five routes run through the real transport, the real service, the real
 * adapters and the real schema15 `ControlPaymentAttemptStore`, DB10 action store
 * and DB9/DB13 commerce-session store over the restricted `openarc_tenant_app`
 * role. The seller browser session is a seeded real session; only the cookie to
 * session-hash resolution is supplied by a minimal auth port, exactly the seam
 * the accepted auth service fills in production. Authorize and issue use the
 * accepted production stores directly (their own routes are already covered by
 * their families). Nothing signs, sends, settles or moves funds; there is no
 * wallet, no key and no network call.
 */

const ORIGIN = "http://localhost:5183";
const BUILD_SHA = "0123456789abcdef0123456789abcdef01234567";
const LISTING_ORIGIN = "https://api.example.com";
const LISTING_PATH = "/v1/run";
const PAYER = "0x1111111111111111111111111111111111111111";
const PAY_TO = "0xabcdefabcdefabcdefabcdefabcdefabcdef2222";
const PAY_TO_MIXED = "0xAbCdEfAbCdEfAbCdEfAbCdEfAbCdEfAbCdEf2222";
const PAY_TO_V2 = "0xfedcbafedcbafedcbafedcbafedcbafedcba3333";
const COOKIE = "openarc_session=synthetic-cookie";
const CSRF = "synthetic-csrf-token";

function sha256(seed: string): string {
  return createHash("sha256").update(`openarc-payment-api-test:${seed}`, "utf8").digest("hex");
}

function uuid(seed: number): string {
  return `50000000-0000-4000-8000-${String(seed).padStart(12, "0")}`;
}

const accountId = (seed: number) => `openarc:account:${uuid(seed)}`;
const orgId = (seed: number) => `openarc:org:${uuid(seed)}`;
const agentId = (seed: number) => `openarc:agent:${uuid(seed)}`;
const providerId = (seed: number) => `openarc:provider:${uuid(seed)}`;
const policyId = (seed: number) => `openarc:policy:${uuid(seed)}`;
const actionId = (seed: number) => `openarc:action:${uuid(seed)}`;
const requirementId = (seed: number) => `openarc:requirement:${uuid(seed)}`;
const mutationId = (seed: number) => uuid(700000 + seed);
const attemptId = (seed: number) => uuid(770000 + seed);

function key(seed: number): string {
  return createHash("sha256").update(`payment-api-key:${seed}`).digest().toString("base64url");
}

function meta(seed: number): { idempotencyKey: string; mutationId: string } {
  return { idempotencyKey: key(seed), mutationId: mutationId(seed) };
}

function rawGrantToken(seed: number): string {
  return `oag_v1_${createHash("sha256").update(`payment-api-grant:${seed}`).digest().toString("base64url")}`;
}

const SALT = Buffer.alloc(16, 7).toString("base64url");
const DIGEST = Buffer.alloc(32, 8).toString("base64url");

function hashInput() {
  return {
    algorithm: "scrypt" as const, hashVersion: 1 as const, pepperVersion: 1,
    N: 32768 as const, r: 8 as const, p: 1 as const, salt: SALT, digest: DIGEST,
  };
}

function content(): Record<string, unknown> {
  return {
    kind: "api",
    title: "Example API",
    description: "A bounded description",
    manifest: {
      schemaVersion: "openarc.listing-manifest.v1",
      inputSchemaDigest: `sha256:${"1".repeat(64)}`,
      outputSchemaDigest: `sha256:${"2".repeat(64)}`,
    },
    price: {
      amount: {
        schemaVersion: "openarc.usdc-amount.v1", networkId: "eip155:5042002", asset: "USDC",
        atomicAmount: "1000000", representation: "erc20", decimals: 6,
      },
      pricingModel: "fixed",
    },
    evidenceContract: {
      schemaVersion: "openarc.receipt-contract.v1", receiptType: "receipt.v1",
      receiptSchemaDigest: `sha256:${"3".repeat(64)}`, deliveryFields: ["payload", "status"],
    },
    endpointContract: { origin: LISTING_ORIGIN, path: LISTING_PATH },
    termsRevision: "terms-v1",
    privacySummary: "We store nothing.",
    paymentLane: "unavailable",
    availability: { status: "available", rateLimitPerMinute: "60" },
  };
}

let admin: Pool;
let migrator: Pool;
let tenant: Pool;
let payments: ControlPaymentAttemptStore;
let actions: ControlActionStore;
let grants: ControlGrantStore;
let sessions: CommerceSessionStore;
let credentials: CredentialStore;
let market: MarketStore;
let lifecycle: MarketLifecycleStore;
let app: FastifyInstance;
/** The seeded human session the auth seam resolves the browser cookie to. */
let currentHuman: { hash: string; account: string } = { hash: "0".repeat(64), account: accountId(0) };
const responses: string[] = [];

beforeAll(async () => {
  admin = adminPool();
  await ensureRoles(admin);
  migrator = createDatabasePool(migratorUrl());
  await resetSchema(admin);
  await migrate(migrator);
  tenant = createDatabasePool(tenantUrl());
  payments = new ControlPaymentAttemptStore(asControlPaymentAttemptPool(tenant));
  actions = new ControlActionStore(asControlActionPool(tenant));
  grants = new ControlGrantStore(asControlGrantPool(tenant));
  sessions = new CommerceSessionStore(asCommerceSessionPool(tenant));
  credentials = new CredentialStore(tenant as never);
  market = new MarketStore(tenant as never);
  lifecycle = new MarketLifecycleStore(tenant as never);
  await payments.initialize();
  await actions.initialize();
  await sessions.initialize();

  const auth: CommercePaymentAuthPort = {
    verifyCsrf(_cookies, csrf) {
      if (csrf !== CSRF) throw AUTH_ERRORS.csrfRejected();
      return "verified";
    },
    async beginTenantRead() {
      return { sessionHash: currentHuman.hash, accountId: currentHuman.account };
    },
    async finishTenantRead() {
      return undefined;
    },
  };
  const service = new CommercePaymentService({
    auth,
    store: createCommercePaymentStoreAdapter(payments),
    actions: createCommercePaymentActionReadAdapter(actions),
    commerceSessions: createCommercePaymentSessionReadAdapter(sessions),
    limits: new CommercePaymentRateLimiter({
      secret: "synthetic_payment_rate_secret_for_postgres_0123",
      store: { consume: async () => ({ allowed: true }) },
    }),
  });
  app = Fastify({ logger: false, bodyLimit: API_MAX_REQUEST_BYTES, exposeHeadRoutes: false });
  app.setErrorHandler((cause, request, reply) => {
    const mapped = cause instanceof AuthApiError ? cause : AUTH_ERRORS.invalidRequest();
    return reply.code(mapped.status).send(authErrorEnvelope(mapped, request.id, BUILD_SHA));
  });
  registerCommercePaymentRoutes(app, {
    appOrigin: ORIGIN,
    cookieNames: { session: "openarc_session", binding: "openarc_binding" },
    service,
    buildSha: BUILD_SHA,
    enabled: true,
  });
  app.setGenReqId?.(() => uuid(999999));
}, 180000);

afterAll(async () => {
  try {
    await app?.close();
    await resetSchema(admin);
  } finally {
    await tenant?.end();
    await migrator?.end();
    await admin?.end();
  }
});

interface Owner { readonly account: string; readonly hash: string; readonly org: string }

async function seedOwner(seed: number): Promise<Owner> {
  const account = accountId(seed);
  await admin.query(
    "INSERT INTO openarc_auth.accounts (account_id, user_handle, status) VALUES ($1, $2, 'active')",
    [account, `${sha256(`handle:${seed}`).slice(0, 42)}A`],
  );
  const hash = sha256(`session:${seed}`);
  await admin.query(
    `INSERT INTO openarc_auth.sessions (token_hash, account_id, method, created_at, expires_at)
     VALUES ($1, $2, 'passkey', now(), now() + interval '24 hours')`,
    [hash, account],
  );
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

async function stateUpdatedAt(org: string, listing: string, version: string): Promise<string> {
  const result = await admin.query<{ updated_at: string }>(
    "SELECT to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS updated_at FROM openarc_tenant.listing_version_states WHERE organization_id = $1 AND listing_id = $2 AND version = $3",
    [org, listing, version],
  );
  return result.rows[0]!.updated_at;
}

interface Chain {
  readonly buyer: Owner;
  readonly seller: Owner;
  readonly agent: string;
  readonly provider: string;
  readonly listing: string;
  readonly rawToken: string;
  readonly tokenHash: string;
}

/**
 * Seller B lists; the seller's terms are recorded by `recordTerms`, then the
 * version is origin-reviewed and published; buyer A gets a policy, a machine
 * session and a real exchanged `oacs_v1_` commerce session.
 */
async function seedChain(
  buyerSeed: number,
  sellerSeed: number,
  recordTerms: (seller: Owner, listing: string) => Promise<void>,
): Promise<Chain> {
  const buyer = await seedOwner(buyerSeed);
  const seller = await seedOwner(sellerSeed);
  const agent = agentId(buyerSeed);
  await admin.query(
    "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name, status) VALUES ($1, $2, 'Agent', 'active')",
    [buyer.org, agent],
  );
  const provider = providerId(sellerSeed);
  await admin.query(
    "INSERT INTO openarc_tenant.providers (organization_id, provider_id, display_name, status) VALUES ($1, $2, 'Provider', 'active')",
    [seller.org, provider],
  );
  const draft = await market.createListingDraft(seller.hash, seller.org, provider, content(), meta(10000 + sellerSeed));
  const listing = draft.receipt.resourceId;
  await recordTerms(seller, listing);

  const moderator = await seedOwner(sellerSeed + 8000);
  await admin.query("INSERT INTO openarc_tenant.market_moderator_grants (account_id, status) VALUES ($1, 'active')", [moderator.account]);
  await lifecycle.recordOriginReview(
    moderator.hash, seller.org, listing, "1",
    {
      expectedUpdatedAt: await stateUpdatedAt(seller.org, listing, "1"),
      decision: "approved",
      reviewedEndpointDigest: reviewedEndpointDigest({ listingId: listing, version: "1", origin: LISTING_ORIGIN, path: LISTING_PATH }),
      reasonCode: "manual_review",
      reasonDigest: null,
    },
    meta(20000 + sellerSeed),
  );
  await lifecycle.publishListingVersion(
    seller.hash, seller.org, listing, "1",
    { expectedUpdatedAt: await stateUpdatedAt(seller.org, listing, "1"), expectedActiveVersion: null },
    meta(40000 + sellerSeed),
  );

  const policy = policyId(buyerSeed);
  const client = await admin.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      `INSERT INTO openarc_tenant.budget_policy_roots (organization_id, policy_id, subject_agent_id, current_revision, status)
       VALUES ($1, $2, $3, '1', 'active')`,
      [buyer.org, policy, agent],
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
      [buyer.org, policy, agent, provider],
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }

  const issued = await credentials.issueAgentCredentialDurably({
    sessionHash: buyer.hash,
    organizationId: buyer.org,
    profileId: agent,
    lookupId: uuid(900000 + buyerSeed),
    hash: hashInput(),
    expiresAt: new Date(Date.now() + 30 * 60_000).toISOString(),
    metadata: meta(500000 + buyerSeed),
  });
  const agentSessionHash = sha256(`machine:${buyerSeed}`);
  await credentials.createAgentSession({
    organizationId: buyer.org,
    profileId: agent,
    credentialId: issued.receipt.credentialId,
    expectedVersion: 1,
    sessionId: uuid(600000 + buyerSeed),
    tokenHash: agentSessionHash,
    expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
  });
  const rawToken = generateCommerceSessionToken();
  const tokenHash = hashCommerceSessionToken(rawToken);
  const handoffHash = sha256(`handoff:${buyerSeed}`);
  await sessions.issueCommerceSession(
    buyer.hash, buyer.org,
    { subjectAgentId: agent, policyId: policy, handoffHash, hashVersion: 1 },
    meta(100000 + buyerSeed),
  );
  await sessions.exchangeCommerceSession(
    agentSessionHash, handoffHash, { tokenHash, hashVersion: 1 }, meta(200000 + buyerSeed),
  );
  return { buyer, seller, agent, provider, listing, rawToken, tokenHash };
}

async function counts(): Promise<{ terms: number; attempts: number; requirements: number }> {
  const result = await admin.query<{ terms: number; attempts: number; requirements: number }>(
    `SELECT (SELECT count(*)::int FROM openarc_tenant.listing_version_payment_terms) AS terms,
            (SELECT count(*)::int FROM openarc_durable.payment_attempts) AS attempts,
            (SELECT count(*)::int FROM openarc_durable.commerce_requirement_references) AS requirements`,
  );
  return result.rows[0]!;
}

async function send(
  method: "GET" | "POST",
  url: string,
  headers: Record<string, string>,
  payload?: unknown,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await app.inject({
    method,
    url,
    headers,
    ...(payload !== undefined ? { payload: payload as Record<string, unknown> } : {}),
  });
  responses.push(response.body);
  return { status: response.statusCode, body: response.json() as Record<string, unknown> };
}

const agent = (token: string, write: boolean): Record<string, string> => ({
  authorization: `Bearer ${token}`,
  ...(write ? { "content-type": "application/json" } : {}),
});

function browser(idempotencyKey: string): Record<string, string> {
  return {
    origin: ORIGIN,
    "x-openarc-client": "browser-v1",
    cookie: COOKIE,
    "x-openarc-csrf": CSRF,
    "idempotency-key": idempotencyKey,
    "content-type": "application/json",
  };
}

const termsUrl = (seller: Owner, listing: string) =>
  `/v2/provider/organizations/${seller.org}/listings/${listing}/versions/1/payment-terms`;

function laneBinding(
  grant: string,
  action: string,
  requirementDigest: string,
  seed: number,
  overrides: Partial<Record<keyof PaymentAttemptBindingInput, string>> = {},
): PaymentAttemptBindingInput {
  const now = Math.floor(Date.now() / 1000);
  return {
    schemaVersion: "openarc.x402.lane-binding.v1",
    role: "buyer",
    network: "eip155:5042002",
    grantId: grant,
    actionId: action,
    attemptId: attemptId(seed),
    grantRequirementDigest: requirementDigest,
    laneRequirementDigest: `sha256:${sha256(`lane-requirement:${seed}`)}`,
    verifyingContract: "0x0077777d7EBA4688BDeF3E311b846F25870A19B9",
    asset: "0x3600000000000000000000000000000000000000",
    from: PAYER,
    to: PAY_TO_MIXED,
    value: "1000000",
    validAfter: String(now - 600),
    validBefore: String(now + 604800 + 900),
    nonce: `0x${sha256(`nonce:${seed}`)}`,
    ...overrides,
  };
}

/** The wire body: ONLY the lane-chosen fields plus the lane's own digest. */
function wireBody(binding: PaymentAttemptBindingInput): Record<string, string> {
  return {
    grantId: binding.grantId,
    actionId: binding.actionId,
    attemptId: binding.attemptId,
    laneRequirementDigest: binding.laneRequirementDigest,
    from: binding.from,
    to: binding.to,
    validAfter: binding.validAfter,
    validBefore: binding.validBefore,
    nonce: binding.nonce,
    bindingDigest: digestPaymentAttemptBinding(binding),
  };
}

describe("migration-0015 payment HTTP slice over real PostgreSQL", () => {
  it("runs the production path: terms, requirement, authorize, issue, persist, dispatch and read", async () => {
    let termsReceipt: unknown;
    const chain = await seedChain(1, 1001, async (seller, listing) => {
      currentHuman = { hash: seller.hash, account: seller.account };
      const before = await counts();
      const first = await send("POST", termsUrl(seller, listing), browser(key(1)), { mutationId: mutationId(1), payToAddress: PAY_TO_MIXED });
      expect(first.status).toBe(200);
      expect(first.body).toMatchObject({
        ok: true,
        data: {
          replayed: false,
          terms: { organizationId: seller.org, listingId: listing, version: "1", payToAddress: PAY_TO },
          receipt: { mutationId: mutationId(1), operation: "market.listing.payment_terms.record", resourceType: "listing_version", resourceId: `${listing}@1` },
        },
      });
      termsReceipt = (first.body["data"] as Record<string, unknown>)["receipt"];
      expect((await counts()).terms).toBe(before.terms + 1);
      // Recovery is an EXACT replay: same key, same mutation, same body.
      const replay = await send("POST", termsUrl(seller, listing), browser(key(1)), { mutationId: mutationId(1), payToAddress: PAY_TO_MIXED });
      expect(replay.status).toBe(200);
      expect(replay.body).toMatchObject({ ok: true, data: { replayed: true, receipt: termsReceipt } });
      // The same key with a different pay-to is a conflict, never a second record.
      const changed = await send("POST", termsUrl(seller, listing), browser(key(1)), { mutationId: mutationId(1), payToAddress: PAY_TO_V2 });
      expect([changed.status, (changed.body["error"] as { code: string }).code]).toEqual([409, "IDEMPOTENCY_CONFLICT"]);
      // Wire amounts are not accepted at all.
      const priced = await send("POST", termsUrl(seller, listing), browser(key(2)), { mutationId: mutationId(2), payToAddress: PAY_TO, amountAtomic: "1" });
      expect(priced.status).toBe(400);
      expect((await counts()).terms).toBe(before.terms + 1);
    });

    // Register the verified requirement over HTTP with the real commerce bearer.
    const requirement = requirementId(1);
    const registered = await send("POST", "/v2/agent/commerce-payment-requirements", agent(chain.rawToken, true), {
      requirementId: requirement,
      listingId: chain.listing,
    });
    expect(registered.status).toBe(200);
    const verified = registered.body["data"] as Record<string, string>;
    expect(verified).toMatchObject({
      organizationId: chain.buyer.org,
      sellerOrganizationId: chain.seller.org,
      sourceKind: "verified_listing",
      amountAtomic: "1000000",
      feeAtomic: "0",
      payToAddress: PAY_TO,
    });
    // The read-only machine credential never reaches the store.
    const machineAttempt = await send("POST", "/v2/agent/commerce-payment-requirements", agent(`oas_ag_${"E".repeat(42)}Q`, true), {
      requirementId: requirementId(9), listingId: chain.listing,
    });
    expect(machineAttempt.status).toBe(401);

    // Production authorize and grant issue through the accepted stores.
    const action = actionId(1);
    await actions.authorizeCommerceAction(chain.tokenHash, { requirementId: requirement, actionId: action }, meta(300001));
    const issued = await grants.issueForReservedAction(
      chain.tokenHash, { actionId: action, grantTokenHash: digestCommerceGrantToken(rawGrantToken(1)) }, meta(400001),
    );
    const grant = issued.metadata.grantId;
    const digest = verified["requirementDigest"] as string;

    const before = await counts();
    // Wrong pay-to: a self-consistent digest over another payee is refused.
    const wrongPayTo = laneBinding(grant, action, digest, 2, { to: PAY_TO_V2 });
    const wrong = await send("POST", "/v2/agent/commerce-payment-attempts", agent(chain.rawToken, true), wireBody(wrongPayTo));
    expect([wrong.status, (wrong.body["error"] as { code: string }).code]).toEqual([400, "INVALID_REQUEST"]);
    // A lane that signed a different amount cannot match the server-built binding.
    const inflated = laneBinding(grant, action, digest, 3, { value: "2000000" });
    const tampered = await send("POST", "/v2/agent/commerce-payment-attempts", agent(chain.rawToken, true), wireBody(inflated));
    expect(tampered.status).toBe(400);
    // An amount on the wire is rejected before any store work.
    const priced = await send("POST", "/v2/agent/commerce-payment-attempts", agent(chain.rawToken, true), { ...wireBody(laneBinding(grant, action, digest, 4)), value: "1000000" });
    expect(priced.status).toBe(400);
    expect((await counts()).attempts).toBe(before.attempts);

    // Persist, then replay the same lane record.
    const binding = laneBinding(grant, action, digest, 1);
    const persisted = await send("POST", "/v2/agent/commerce-payment-attempts", agent(chain.rawToken, true), wireBody(binding));
    expect(persisted.status).toBe(200);
    expect(persisted.body).toMatchObject({
      ok: true,
      data: {
        replayed: false,
        attempt: {
          attemptId: binding.attemptId, grantId: grant, actionId: action, state: "persisted",
          valueAtomic: "1000000", requirementDigest: digest, bindingDigest: digestPaymentAttemptBinding(binding),
          dispatchedAt: null,
        },
      },
    });
    const replayed = await send("POST", "/v2/agent/commerce-payment-attempts", agent(chain.rawToken, true), wireBody(binding));
    expect(replayed.body).toMatchObject({ ok: true, data: { replayed: true, attempt: { state: "persisted" } } });
    expect((await counts()).attempts).toBe(before.attempts + 1);

    // Dispatch exactly once; the second is a non-retryable 409, never success.
    const dispatchUrl = `/v2/agent/commerce-payment-attempts/${binding.attemptId}/dispatch`;
    const dispatched = await send("POST", dispatchUrl, agent(chain.rawToken, true), { bindingDigest: digestPaymentAttemptBinding(binding) });
    expect(dispatched.status).toBe(200);
    expect(dispatched.body).toMatchObject({ ok: true, data: { attempt: { state: "unknown", transferId: null } } });
    const again = await send("POST", dispatchUrl, agent(chain.rawToken, true), { bindingDigest: digestPaymentAttemptBinding(binding) });
    expect(again.status).toBe(409);
    expect(again.body).toMatchObject({ ok: false, error: { code: "POLICY_DENIED", retryable: false } });
    expect(again.body["data"]).toBeUndefined();

    // Restart recovery by the lane's own attempt id.
    const read = await send("GET", `/v2/agent/commerce-payment-attempts/${binding.attemptId}`, agent(chain.rawToken, false));
    expect(read.status).toBe(200);
    expect(read.body).toMatchObject({ ok: true, data: { attemptId: binding.attemptId, item: { state: "unknown", grantId: grant } } });
    const missing = await send("GET", `/v2/agent/commerce-payment-attempts/${attemptId(99)}`, agent(chain.rawToken, false));
    expect(missing.body).toMatchObject({ ok: true, data: { attemptId: attemptId(99), item: null } });
    const cookieOnAgent = await send("GET", `/v2/agent/commerce-payment-attempts/${binding.attemptId}`, { ...agent(chain.rawToken, false), cookie: COOKIE });
    expect(cookieOnAgent.status).toBe(400);

    const row = await admin.query<{ state: string; value_atomic: string; pay_to_address: string }>(
      "SELECT state, value_atomic, pay_to_address FROM openarc_durable.payment_attempts WHERE attempt_id = $1::uuid",
      [binding.attemptId],
    );
    expect(row.rows).toEqual([{ state: "unknown", value_atomic: "1000000", pay_to_address: PAY_TO_MIXED }]);
  }, 180000);

  it("keeps internal_fixture provenance refused on the production path with zero attempts", async () => {
    const chain = await seedChain(2, 1002, async (seller, listing) => {
      await payments.recordListingPaymentTerms(seller.hash, seller.org, listing, "1", { payToAddress: PAY_TO }, meta(70002));
    });
    const fixtureRequirement = requirementId(2);
    await admin.query(
      `INSERT INTO openarc_durable.commerce_requirement_references (
         organization_id, requirement_id, seller_organization_id, provider_id, listing_id,
         listing_version, network_id, asset, representation, decimals, amount_atomic,
         fee_atomic, requirement_digest, source_kind, created_at, valid_until)
       VALUES ($1, $2, $3, $4, $5, '1', 'eip155:5042002', 'USDC', 'erc20', 6, '1000000', '0',
               'sha256:' || repeat('c', 64), 'internal_fixture', clock_timestamp(),
               clock_timestamp() + interval '30 minutes')`,
      [chain.buyer.org, fixtureRequirement, chain.seller.org, chain.provider, chain.listing],
    );
    const before = await counts();
    // The production authorize wrapper refuses fixture provenance outright.
    await expect(
      actions.authorizeCommerceAction(chain.tokenHash, { requirementId: fixtureRequirement, actionId: actionId(2) }, meta(300002)),
    ).rejects.toMatchObject({ code: "CONTROL_ACTION_STORE_REQUIREMENT_UNAVAILABLE" });
    await expect(
      actions.authorizeCommerceAction(chain.tokenHash, { requirementId: fixtureRequirement, actionId: actionId(2) }, meta(300003)),
    ).rejects.toBeInstanceOf(ControlActionStoreError);

    // Even a fixture grant built through the migrator-private cores can never
    // gain a durable attempt through the HTTP route.
    const fixtureAction = actionId(3);
    const fixtureKey = createHash("sha256").update(key(310003), "utf8").digest("hex");
    await migrator.query(
      `SELECT * FROM openarc_durable.authorize_commerce_action_core('internal_fixture', $1, $2, $3, $4::uuid, $5, $6, $7)`,
      [chain.tokenHash, fixtureRequirement, fixtureAction, mutationId(310003), fixtureKey, "a".repeat(64),
        createHash("sha256").update(`openarc.control.commerce_action.authorize.session.v1:${chain.tokenHash}`, "utf8").digest("hex")],
    );
    const fixtureGrant = await migrator.query<{ out_grant_id: string }>(
      `SELECT * FROM openarc_durable.issue_authorization_grant_core('internal_fixture', $1, $2, $3, 1, $4::uuid, $5, $6, $7)`,
      [chain.tokenHash, fixtureAction, digestCommerceGrantToken(rawGrantToken(3)), mutationId(320003), "b".repeat(64), "c".repeat(64), "d".repeat(64)],
    );
    const binding = laneBinding(fixtureGrant.rows[0]!.out_grant_id, fixtureAction, `sha256:${"c".repeat(64)}`, 5);
    const refused = await send("POST", "/v2/agent/commerce-payment-attempts", agent(chain.rawToken, true), wireBody(binding));
    expect(refused.status).toBe(503);
    expect(refused.body).toMatchObject({ ok: false, error: { retryable: false } });
    expect((await counts()).attempts).toBe(before.attempts);
  }, 180000);

  it("never returned a credential in any response", () => {
    const everything = responses.join("\n");
    expect(responses.length).toBeGreaterThan(10);
    expect(everything).not.toContain("oacs_v1_");
    expect(everything).not.toContain(COOKIE);
    expect(everything).not.toContain(CSRF);
    expect(everything).not.toContain("oag_v1_");
  });
});
