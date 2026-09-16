import { createHash } from 'node:crypto';
import type { Pool } from 'pg';
import {
  CommerceSessionStore,
  ControlActionStore,
  ControlGrantStore,
  ControlPaymentAttemptStore,
  CredentialStore,
  MarketLifecycleStore,
  MarketStore,
  digestCommerceGrantToken,
  digestPaymentAttemptBinding,
  reviewedEndpointDigest,
  type PaymentAttemptBindingInput,
} from '../src/index.js';
import type { TenantPool } from '../src/tenant-store.js';

/**
 * Shared seeding harness for the schema15 durable payment attempt chain, used
 * by the settlement observation suites in packages/db and apps/worker.
 *
 * It drives only the accepted PRODUCTION paths through the restricted tenant
 * runtime: a real published, origin-approved listing version with immutable
 * seller payment terms, a server-derived verified requirement, a production
 * authorize, a production grant issue, then persist and (optionally) dispatch.
 * Nothing here signs, sends, settles or moves funds, and nothing here observes:
 * observation is the system under test in the suites that use this fixture.
 */

const ORIGIN = 'https://api.example.com';
const PATH = '/v1/run';
const GATEWAY_WALLET = '0x0077777d7EBA4688BDeF3E311b846F25870A19B9';
const USDC = '0x3600000000000000000000000000000000000000';

export function fixtureSha256(seed: string): string {
  return createHash('sha256').update(`openarc-attempt-fixture:${seed}`, 'utf8').digest('hex');
}

export function fixtureUuid(seed: number): string {
  return `40000000-0000-4000-8000-${String(seed).padStart(12, '0')}`;
}

export const fixtureAccountId = (seed: number): string => `openarc:account:${fixtureUuid(seed)}`;
export const fixtureOrgId = (seed: number): string => `openarc:org:${fixtureUuid(seed)}`;
export const fixtureAgentId = (seed: number): string => `openarc:agent:${fixtureUuid(seed)}`;
export const fixtureProviderId = (seed: number): string => `openarc:provider:${fixtureUuid(seed)}`;
export const fixturePolicyId = (seed: number): string => `openarc:policy:${fixtureUuid(seed)}`;
export const fixtureActionId = (seed: number): string => `openarc:action:${fixtureUuid(seed)}`;
export const fixtureRequirementId = (seed: number): string => `openarc:requirement:${fixtureUuid(seed)}`;
export const fixtureAttemptId = (seed: number): string => fixtureUuid(770000 + seed);

/** A distinct lowercase payer/payee per seed, so nonce and payee never collide. */
function payerAddress(seed: number): string {
  return `0x${fixtureSha256(`payer:${seed}`).slice(0, 40)}`;
}

function payToAddress(seed: number): string {
  return `0x${fixtureSha256(`payto:${seed}`).slice(0, 40)}`;
}

function key(seed: number): string {
  return createHash('sha256').update(`attempt-fixture-key:${seed}`).digest().toString('base64url');
}

function meta(seed: number): { idempotencyKey: string; mutationId: string } {
  return { idempotencyKey: key(seed), mutationId: fixtureUuid(700000 + seed) };
}

function userHandle(seed: number): string {
  return `${fixtureSha256(`handle:${seed}`).slice(0, 42)}A`;
}

function rawGrantToken(seed: number): string {
  const material = createHash('sha256').update(`attempt-fixture-grant:${seed}`).digest();
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

export interface AttemptFixture {
  readonly admin: Pool;
  readonly tenant: TenantPool;
}

interface Owner {
  readonly account: string;
  readonly hash: string;
  readonly org: string;
}

/** One fully dispatched durable attempt, with everything an observer needs. */
export interface DispatchedAttempt {
  readonly organizationId: string;
  readonly sellerOrganizationId: string;
  readonly attemptId: string;
  readonly grantId: string;
  readonly actionId: string;
  readonly requirementDigest: string;
  readonly laneRequirementDigest: string;
  readonly payerAddress: string;
  readonly payToAddress: string;
  readonly valueAtomic: string;
  readonly validAfter: string;
  readonly validBefore: string;
  readonly nonce: string;
  readonly bindingDigest: string;
  readonly commerceTokenHash: string;
  readonly state: string;
}

export class PaymentAttemptFixture {
  readonly #admin: Pool;
  readonly #tenant: TenantPool;
  readonly #attempts: ControlPaymentAttemptStore;
  readonly #actions: ControlActionStore;
  readonly #grants: ControlGrantStore;
  readonly #credentials: CredentialStore;
  readonly #commerce: CommerceSessionStore;
  readonly #market: MarketStore;
  readonly #lifecycle: MarketLifecycleStore;

  constructor(fixture: AttemptFixture) {
    this.#admin = fixture.admin;
    this.#tenant = fixture.tenant;
    this.#attempts = new ControlPaymentAttemptStore(fixture.tenant);
    this.#actions = new ControlActionStore(fixture.tenant);
    this.#grants = new ControlGrantStore(fixture.tenant);
    this.#credentials = new CredentialStore(fixture.tenant);
    this.#commerce = new CommerceSessionStore(fixture.tenant);
    this.#market = new MarketStore(fixture.tenant);
    this.#lifecycle = new MarketLifecycleStore(fixture.tenant);
  }

  get tenantPool(): TenantPool {
    return this.#tenant;
  }

  async #seedAccount(seed: number): Promise<string> {
    const id = fixtureAccountId(seed);
    await this.#admin.query(
      "INSERT INTO openarc_auth.accounts (account_id, user_handle, status) VALUES ($1, $2, 'active')",
      [id, userHandle(seed)],
    );
    return id;
  }

  async #seedSession(seed: number, account: string): Promise<string> {
    const hash = fixtureSha256(`session:${seed}`);
    await this.#admin.query(
      `INSERT INTO openarc_auth.sessions (token_hash, account_id, method, created_at, expires_at)
       VALUES ($1, $2, 'passkey', now(), now() + interval '24 hours')`,
      [hash, account],
    );
    return hash;
  }

  async #seedOwner(seed: number): Promise<Owner> {
    const account = await this.#seedAccount(seed);
    const hash = await this.#seedSession(seed, account);
    const org = fixtureOrgId(seed);
    await this.#admin.query(
      "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Org', $2)",
      [org, account],
    );
    await this.#admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'owner', 'active')",
      [org, account],
    );
    return { account, hash, org };
  }

  async #seedAgent(seed: number, org: string): Promise<string> {
    const id = fixtureAgentId(seed);
    await this.#admin.query(
      "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name, status) VALUES ($1, $2, $3, 'active')",
      [org, id, `Agent ${seed}`],
    );
    return id;
  }

  async #seedProvider(seed: number, org: string): Promise<string> {
    const id = fixtureProviderId(seed);
    await this.#admin.query(
      "INSERT INTO openarc_tenant.providers (organization_id, provider_id, display_name, status) VALUES ($1, $2, $3, 'active')",
      [org, id, `Provider ${seed}`],
    );
    return id;
  }

  async #seedPolicy(org: string, subject: string, seed: number, provider: string): Promise<string> {
    const id = fixturePolicyId(seed);
    const client = await this.#admin.connect();
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

  async #seedMachine(owner: Owner, seed: number, agent: string): Promise<string> {
    const issued = await this.#credentials.issueAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: agent,
      lookupId: fixtureUuid(900000 + seed),
      hash: hashInput(),
      expiresAt: new Date(Date.now() + 30 * 60_000).toISOString(),
      metadata: meta(500000 + seed),
    });
    const agentSessionHash = fixtureSha256(`machine:${seed}`);
    await this.#credentials.createAgentSession({
      organizationId: owner.org,
      profileId: agent,
      credentialId: issued.receipt.credentialId,
      expectedVersion: 1,
      sessionId: fixtureUuid(600000 + seed),
      tokenHash: agentSessionHash,
      expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
    });
    return agentSessionHash;
  }

  async #stateUpdatedAt(org: string, listing: string, version: string): Promise<string> {
    const result = await this.#admin.query<{ updated_at: string }>(
      `SELECT to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS updated_at
         FROM openarc_tenant.listing_version_states
        WHERE organization_id = $1 AND listing_id = $2 AND version = $3`,
      [org, listing, version],
    );
    return result.rows[0]!.updated_at;
  }

  async #reviewVersion(owner: Owner, listing: string, version: string, seed: number): Promise<void> {
    const moderatorSeed = seed + 8000;
    const exists = await this.#admin.query(
      'SELECT 1 FROM openarc_auth.accounts WHERE account_id = $1',
      [fixtureAccountId(moderatorSeed)],
    );
    if (exists.rowCount === 0) {
      const moderatorAccount = await this.#seedAccount(moderatorSeed);
      await this.#seedSession(moderatorSeed, moderatorAccount);
      await this.#admin.query(
        "INSERT INTO openarc_tenant.market_moderator_grants (account_id, status) VALUES ($1, 'active')",
        [moderatorAccount],
      );
    }
    await this.#lifecycle.recordOriginReview(
      fixtureSha256(`session:${moderatorSeed}`), owner.org, listing, version,
      {
        expectedUpdatedAt: await this.#stateUpdatedAt(owner.org, listing, version),
        decision: 'approved',
        reviewedEndpointDigest: reviewedEndpointDigest({
          listingId: listing, version, origin: ORIGIN, path: PATH,
        }),
        reasonCode: 'manual_review',
        reasonDigest: null,
      },
      meta(20000 + seed * 10 + Number(version)),
    );
  }

  /**
   * Seed one production chain and persist an attempt. When `dispatch` is true
   * (the default) the attempt is also durably dispatched, so it is in state
   * `unknown`: exactly the state a settlement observation may act on.
   */
  async seedDispatchedAttempt(
    seed: number,
    options: { readonly dispatch?: boolean } = {},
  ): Promise<DispatchedAttempt> {
    const buyerSeed = seed;
    const sellerSeed = seed + 1000;
    const buyer = await this.#seedOwner(buyerSeed);
    const seller = await this.#seedOwner(sellerSeed);
    const agent = await this.#seedAgent(buyerSeed, buyer.org);
    const provider = await this.#seedProvider(sellerSeed, seller.org);

    const draft = await this.#market.createListingDraft(
      seller.hash, seller.org, provider, content(), meta(10000 + sellerSeed),
    );
    const listing = draft.receipt.resourceId;
    const payTo = payToAddress(seed);
    await this.#attempts.recordListingPaymentTerms(
      seller.hash, seller.org, listing, '1', { payToAddress: payTo }, meta(70000 + sellerSeed),
    );
    await this.#reviewVersion(seller, listing, '1', sellerSeed);
    await this.#lifecycle.publishListingVersion(
      seller.hash, seller.org, listing, '1',
      {
        expectedUpdatedAt: await this.#stateUpdatedAt(seller.org, listing, '1'),
        expectedActiveVersion: null,
      },
      meta(40000 + sellerSeed),
    );

    const policy = await this.#seedPolicy(buyer.org, agent, buyerSeed, provider);
    const agentSessionHash = await this.#seedMachine(buyer, buyerSeed, agent);
    const handoffHash = fixtureSha256(`handoff:${buyerSeed}`);
    const commerceTokenHash = fixtureSha256(`commerce:${buyerSeed}`);
    await this.#commerce.issueCommerceSession(
      buyer.hash, buyer.org,
      { subjectAgentId: agent, policyId: policy, handoffHash, hashVersion: 1 },
      meta(100000 + buyerSeed),
    );
    await this.#commerce.exchangeCommerceSession(
      agentSessionHash, handoffHash, { tokenHash: commerceTokenHash, hashVersion: 1 },
      meta(200000 + buyerSeed),
    );

    const requirement = fixtureRequirementId(buyerSeed);
    const registered = await this.#attempts.registerVerifiedRequirement(
      commerceTokenHash, { requirementId: requirement, listingId: listing },
    );
    const action = fixtureActionId(buyerSeed);
    await this.#actions.authorizeCommerceAction(
      commerceTokenHash, { requirementId: requirement, actionId: action }, meta(300000 + buyerSeed),
    );
    const grantTokenHash = digestCommerceGrantToken(rawGrantToken(buyerSeed));
    const issued = await this.#grants.issueForReservedAction(
      commerceTokenHash, { actionId: action, grantTokenHash }, meta(400000 + buyerSeed),
    );

    const now = Math.floor(Date.now() / 1000);
    const binding: PaymentAttemptBindingInput = {
      schemaVersion: 'openarc.x402.lane-binding.v1',
      role: 'buyer',
      network: 'eip155:5042002',
      grantId: issued.metadata.grantId,
      actionId: action,
      attemptId: fixtureAttemptId(seed),
      grantRequirementDigest: registered.requirementDigest,
      laneRequirementDigest: `sha256:${fixtureSha256(`lane-requirement:${seed}`)}`,
      verifyingContract: GATEWAY_WALLET,
      asset: USDC,
      from: payerAddress(seed),
      to: payTo,
      value: '1000000',
      validAfter: String(now - 600),
      validBefore: String(now + 604800 + 900),
      nonce: `0x${fixtureSha256(`nonce:${seed}`)}`,
    };
    const bindingDigest = digestPaymentAttemptBinding(binding);
    await this.#attempts.persistBuyerAttempt(commerceTokenHash, { binding, bindingDigest });
    let state = 'persisted';
    if (options.dispatch !== false) {
      const dispatched = await this.#attempts.recordDispatch(
        commerceTokenHash, { attemptId: binding.attemptId, bindingDigest },
      );
      state = dispatched.state;
    }

    return {
      organizationId: buyer.org,
      sellerOrganizationId: seller.org,
      attemptId: binding.attemptId,
      grantId: binding.grantId,
      actionId: action,
      requirementDigest: registered.requirementDigest,
      laneRequirementDigest: binding.laneRequirementDigest,
      payerAddress: binding.from,
      payToAddress: binding.to,
      valueAtomic: binding.value,
      validAfter: binding.validAfter,
      validBefore: binding.validBefore,
      nonce: binding.nonce,
      bindingDigest,
      commerceTokenHash,
      state,
    };
  }
}
