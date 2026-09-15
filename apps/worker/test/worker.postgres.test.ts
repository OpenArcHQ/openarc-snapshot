import { createHash } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  CommerceSessionStore,
  ControlActionStore,
  ControlPolicyStore,
  CredentialStore,
  MarketLifecycleStore,
  MarketStore,
  OutboxStore,
  TenantStore,
  createDatabasePool,
  digestCommerceGrantToken,
  migrate,
  reviewedEndpointDigest,
  type ClaimedOutboxEvent,
} from '@openarc/db';
import {
  adminPool,
  ensureRoles,
  migratorUrl,
  resetSchema,
  tenantUrl,
  workerUrl,
} from '../../../packages/db/test/postgres-fixture.js';
import {
  insertOutboxEventForPair,
  outboxPairKey,
  readPermittedOutboxEventPairs,
} from '../../../packages/db/test/outbox-event-catalog.js';
import { WorkerLoop, type WorkerLogRecord } from '../src/worker.js';
import {
  NOTIFICATION_EVENT_KEYS,
  createHandlerRegistry,
  eventKeyOf,
  validateNotification,
  type NotificationEventKey,
  type NotificationHandler,
} from '../src/handlers.js';

/**
 * Real PostgreSQL acceptance for the bounded tenant notification worker.
 *
 * The exhaustive helper/ACL/schema matrices are already proven by the frozen
 * packages/db postgres suites (postgres, postgres-boundaries, durability,
 * tenant-mutations); this suite reuses that evidence and does NOT clone those
 * assertions. It proves the worker-role path: legitimate durable tenant events
 * are consumed, concurrent workers split claims, a killed worker's lease is
 * reclaimed through the real DB clock, a stale generation cannot acknowledge,
 * exhausted attempts dead-letter, and a wrong role or stale schema fails
 * closed. Only the guarded disposable fixture database is reset.
 */

function sha256(seed: string): string {
  return createHash('sha256').update(`openarc-worker-test:${seed}`).digest('hex');
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function uuid(seed: number): string {
  return `00000000-0000-4000-8000-${String(seed).padStart(12, '0')}`;
}

function accountId(seed: number): string {
  return `openarc:account:${uuid(seed)}`;
}

function orgId(seed: number): string {
  return `openarc:org:${uuid(seed)}`;
}

function mutationId(seed: number): string {
  return uuid(100000 + seed);
}

function userHandle(seed: number): string {
  return `${sha256(`handle:${seed}`).slice(0, 42)}A`;
}

function base64Key(seed: number): string {
  return createHash('sha256').update(`key:${seed}`).digest().toString('base64url');
}

let admin: ReturnType<typeof adminPool>;
let migrator: ReturnType<typeof createDatabasePool>;
let tenant: ReturnType<typeof createDatabasePool>;
let worker: ReturnType<typeof createDatabasePool>;
let workerPeer: ReturnType<typeof createDatabasePool>;
let store: TenantStore;
let credentials: CredentialStore;
let outbox: OutboxStore;

beforeAll(async () => {
  admin = adminPool();
  await ensureRoles(admin);
  migrator = createDatabasePool(migratorUrl());
  tenant = createDatabasePool(tenantUrl());
  worker = createDatabasePool(workerUrl());
  workerPeer = createDatabasePool(workerUrl());
});

afterAll(async () => {
  try {
    await resetSchema(admin);
  } finally {
    await workerPeer.end();
    await worker.end();
    await tenant.end();
    await migrator.end();
    await admin.end();
  }
});

beforeEach(async () => {
  await resetSchema(admin);
  await migrate(migrator);
  store = new TenantStore(tenant);
  credentials = new CredentialStore(tenant);
  outbox = new OutboxStore(worker);
});

async function seedAccount(seed: number): Promise<string> {
  const id = accountId(seed);
  await admin.query(
    'INSERT INTO openarc_auth.accounts (account_id, user_handle, status) VALUES ($1, $2, $3)',
    [id, userHandle(seed), 'active'],
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

async function seedOrg(seed: number, creator: string): Promise<string> {
  const org = orgId(seed);
  await admin.query(
    "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Worker Org', $2)",
    [org, creator],
  );
  return org;
}

async function seedMembership(org: string, account: string, role: string): Promise<void> {
  await admin.query(
    'INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, $3, $4)',
    [org, account, role, 'active'],
  );
}

interface SeededOwner {
  readonly account: string;
  readonly org: string;
  readonly hash: string;
}

async function seedOwner(seed: number): Promise<SeededOwner> {
  const account = await seedAccount(seed);
  const hash = await seedSession(seed, account);
  const org = await seedOrg(seed, account);
  await seedMembership(org, account, 'owner');
  return { account, org, hash };
}

describe('worker role consumes durable tenant notifications', () => {
  it('initializes the exact worker role and consumes a legitimate agent event', async () => {
    const owner = await seedOwner(1);
    await store.createAgentDurably(owner.hash, owner.org, 'Worker Agent', {
      idempotencyKey: base64Key(1),
      mutationId: mutationId(1),
    });

    await outbox.initialize();
    const claimed = await outbox.claim({ limit: 10 });
    expect(claimed).toHaveLength(1);
    const event = claimed[0] as ClaimedOutboxEvent;
    expect(event.resourceType).toBe('agent');
    expect(event.eventType).toBe('tenant.agent.created');
    expect(event.mutationId).toBe(mutationId(1));
    expect(event.attemptCount).toBe(1);

    const completed = await outbox.complete(event.eventId, event.leaseGeneration);
    expect(completed).toEqual({ applied: true });
    expect(await outbox.claim({ limit: 10 })).toHaveLength(0);
  });

  it('consumes a legitimate provider event', async () => {
    const owner = await seedOwner(2);
    await store.createProviderDurably(owner.hash, owner.org, 'Worker Provider', {
      idempotencyKey: base64Key(2),
      mutationId: mutationId(2),
    });
    await outbox.initialize();
    const [event] = await outbox.claim({ limit: 10 });
    expect(event?.resourceType).toBe('provider');
    expect(event?.eventType).toBe('tenant.provider.created');
    expect(await outbox.complete(event?.eventId, event?.leaseGeneration)).toEqual({ applied: true });
  });

  it('gives concurrent workers distinct claims', async () => {
    const owner = await seedOwner(3);
    await store.createAgentDurably(owner.hash, owner.org, 'Agent A', {
      idempotencyKey: base64Key(3),
      mutationId: mutationId(3),
    });
    await store.createAgentDurably(owner.hash, owner.org, 'Agent B', {
      idempotencyKey: base64Key(4),
      mutationId: mutationId(4),
    });

    const outboxA = new OutboxStore(worker);
    const outboxB = new OutboxStore(workerPeer);
    await outboxA.initialize();
    await outboxB.initialize();
    const [a, b] = await Promise.all([outboxA.claim({ limit: 10 }), outboxB.claim({ limit: 10 })]);
    const ids = [...a, ...b].map((event) => event.eventId);
    expect(ids).toHaveLength(2);
    expect(new Set(ids).size).toBe(2);
    for (const event of [...a, ...b]) {
      expect(await outboxA.complete(event.eventId, event.leaseGeneration)).toEqual({ applied: true });
    }
  });

  it(
    'consumes a bounded 50-notification batch through the worker loop without artificial dead-letter',
    async () => {
      const owner = await seedOwner(4);
      for (let index = 0; index < 50; index += 1) {
        await store.createAgentDurably(owner.hash, owner.org, `Batch Agent ${index}`, {
          idempotencyKey: base64Key(4000 + index),
          mutationId: mutationId(4000 + index),
        });
      }

      await outbox.initialize();
      let claimed = 0;
      let completed = 0;
      let failed = 0;
      let stop: () => void = () => undefined;
      const loop = new WorkerLoop({
        store: outbox,
        claimLimit: 50,
        pollMs: 250,
        idleMaxMs: 1000,
        logger: {
          log: (record: WorkerLogRecord) => {
            if (record.status === 'claimed') claimed += record.count ?? 0;
            if (record.status === 'completed') completed += 1;
            if (
              record.status === 'failed' ||
              record.status === 'stale' ||
              record.status === 'outcome_unknown'
            ) {
              failed += 1;
            }
            if (record.status === 'claim_empty') stop();
          },
        },
      });
      stop = () => loop.requestStop();
      await loop.run();

      expect(claimed).toBe(50);
      expect(completed).toBe(50);
      expect(failed).toBe(0);
      const states = await admin.query<{ state: string }>(
        'SELECT state FROM openarc_durable.outbox_events WHERE organization_id = $1',
        [owner.org],
      );
      expect(states.rows).toHaveLength(50);
      expect(states.rows.every((row) => row.state === 'completed')).toBe(true);
    },
    30000,
  );

  it('reclaims a killed worker lease through the real clock and rejects a stale generation', async () => {
    const owner = await seedOwner(5);
    await store.createAgentDurably(owner.hash, owner.org, 'Reclaim Agent', {
      idempotencyKey: base64Key(5),
      mutationId: mutationId(5),
    });

    const killed = new OutboxStore(worker);
    await killed.initialize();
    const [first] = await killed.claim({ limit: 1 });
    expect(first).toBeDefined();
    const staleGeneration = first?.leaseGeneration ?? '';

    // Controlled fixture: age the still-leased row with admin SQL instead of a
    // 30s real sleep. This labels the observed durable lease, not a mock.
    await admin.query(
      `UPDATE openarc_durable.outbox_events
          SET lease_until = clock_timestamp() - interval '1 second'
        WHERE event_id = $1`,
      [first?.eventId],
    );

    const restarted = new OutboxStore(workerPeer);
    await restarted.initialize();
    const [second] = await restarted.claim({ limit: 1 });
    expect(second?.eventId).toBe(first?.eventId);
    expect(Number(second?.leaseGeneration)).toBe(Number(staleGeneration) + 1);
    expect(second?.attemptCount).toBe(2);

    // The killed worker's stale generation must never acknowledge the job.
    expect(await killed.complete(first?.eventId, staleGeneration)).toEqual({ applied: false });
    expect(await restarted.complete(second?.eventId, second?.leaseGeneration)).toEqual({
      applied: true,
    });
  });

  it('dead-letters an exhausted-lease final attempt', async () => {
    const owner = await seedOwner(6);
    await store.createAgentDurably(owner.hash, owner.org, 'Exhausted Agent', {
      idempotencyKey: base64Key(6),
      mutationId: mutationId(6),
    });
    await admin.query(
      `UPDATE openarc_durable.outbox_events
          SET state = 'leased',
              attempt_count = 5,
              lease_generation = lease_generation + 1,
              lease_until = clock_timestamp() - interval '1 second'
        WHERE mutation_id = $1::uuid`,
      [mutationId(6)],
    );

    await outbox.initialize();
    expect(await outbox.claim({ limit: 10 })).toHaveLength(0);
    const state = await admin.query<{ state: string; last_failure_code: string | null }>(
      'SELECT state, last_failure_code FROM openarc_durable.outbox_events WHERE mutation_id = $1::uuid',
      [mutationId(6)],
    );
    expect(state.rows[0]).toEqual({
      state: 'dead_letter',
      last_failure_code: 'attempts_exhausted',
    });
  });

  it('fails closed for a wrong role and a stale schema', async () => {
    const wrongRole = new OutboxStore(tenant);
    await expect(wrongRole.initialize()).rejects.toMatchObject({
      code: 'OUTBOX_STORE_UNAVAILABLE',
    });

    await admin.query("DELETE FROM openarc_meta.schema_migrations WHERE id = '0004_durable_tenant_mutations'");
    const stale = new OutboxStore(worker);
    await expect(stale.initialize()).rejects.toMatchObject({
      code: 'OUTBOX_STORE_UNAVAILABLE',
    });
  });

  it('denies direct durable DML to the worker role', async () => {
    await expect(worker.query('SELECT * FROM openarc_durable.outbox_events')).rejects.toBeTruthy();
    await expect(worker.query('SELECT * FROM openarc_durable.idempotency_records')).rejects.toBeTruthy();
    await expect(worker.query('SELECT * FROM openarc_durable.audit_events')).rejects.toBeTruthy();
    await expect(
      worker.query("UPDATE openarc_durable.outbox_events SET state = 'completed'"),
    ).rejects.toBeTruthy();
  });

  it('consumes all four notification-only credential events with only metadata', async () => {
    const owner = await seedOwner(20);
    const agent = 'openarc:agent:' + uuid(20);
    const provider = 'openarc:provider:' + uuid(20);
    await admin.query(
      "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name) VALUES ($1, $2, 'Worker Agent')",
      [owner.org, agent],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.providers (organization_id, provider_id, display_name) VALUES ($1, $2, 'Worker Provider')",
      [owner.org, provider],
    );
    const salt = Buffer.alloc(16, 5).toString('base64url');
    const digest = Buffer.alloc(32, 6).toString('base64url');
    const hash = {
      algorithm: 'scrypt' as const,
      hashVersion: 1 as const,
      pepperVersion: 1,
      N: 32768 as const,
      r: 8 as const,
      p: 1 as const,
      salt,
      digest,
    };
    await credentials.issueAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: agent,
      lookupId: uuid(500020),
      hash,
      expiresAt: new Date(Date.now() + 60 * 60_000).toISOString(),
      metadata: { idempotencyKey: base64Key(20), mutationId: mutationId(20) },
    });
    await credentials.revokeAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      credentialId: mutationId(20),
      metadata: { idempotencyKey: base64Key(21), mutationId: mutationId(21) },
    });
    await credentials.issueProviderCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: provider,
      lookupId: uuid(500022),
      hash,
      expiresAt: new Date(Date.now() + 60 * 60_000).toISOString(),
      metadata: { idempotencyKey: base64Key(22), mutationId: mutationId(22) },
    });
    await credentials.revokeProviderCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      credentialId: mutationId(22),
      metadata: { idempotencyKey: base64Key(23), mutationId: mutationId(23) },
    });

    await outbox.initialize();
    let claimed = 0;
    let completed = 0;
    let failed = 0;
    let stop: () => void = () => undefined;
    const loop = new WorkerLoop({
      store: outbox,
      claimLimit: 50,
      pollMs: 250,
      idleMaxMs: 1000,
      logger: {
        log: (record: WorkerLogRecord) => {
          if (record.status === 'claimed') claimed += record.count ?? 0;
          if (record.status === 'completed') completed += 1;
          if (record.status === 'failed' || record.status === 'stale' || record.status === 'outcome_unknown') {
            failed += 1;
          }
          if (record.status === 'claim_empty') stop();
        },
      },
    });
    stop = () => loop.requestStop();
    await loop.run();
    expect(claimed).toBe(4);
    expect(completed).toBe(4);
    expect(failed).toBe(0);
    const states = await admin.query<{ state: string; event_type: string }>(
      'SELECT state, event_type FROM openarc_durable.outbox_events WHERE organization_id = $1 ORDER BY event_type',
      [owner.org],
    );
    expect(states.rows.map((row) => row.event_type)).toEqual([
      'tenant.agent.credential.created',
      'tenant.agent.credential.revoked',
      'tenant.provider.credential.created',
      'tenant.provider.credential.revoked',
    ]);
    expect(states.rows.every((row) => row.state === 'completed')).toBe(true);
  });

  it('consumes the two new market listing notification events', async () => {
    const seed = 30;
    const account = accountId(seed);
    await admin.query(
      'INSERT INTO openarc_auth.accounts (account_id, user_handle) VALUES ($1, $2)',
      [account, userHandle(seed)],
    );
    const hash = sha256(`session:${seed}`);
    await admin.query(
      "INSERT INTO openarc_auth.sessions (token_hash, account_id, method, expires_at) VALUES ($1, $2, 'passkey', now() + interval '1 hour')",
      [hash, account],
    );
    const org = orgId(seed);
    await admin.query(
      "INSERT INTO openarc_tenant.organizations (organization_id, display_name, created_by) VALUES ($1, 'Worker Org', $2)",
      [org, account],
    );
    await admin.query(
      "INSERT INTO openarc_tenant.memberships (organization_id, account_id, role, status) VALUES ($1, $2, 'owner', 'active')",
      [org, account],
    );
    const provider = `openarc:provider:${uuid(seed + 1)}`;
    await admin.query(
      "INSERT INTO openarc_tenant.providers (organization_id, provider_id, display_name) VALUES ($1, $2, 'Worker Provider')",
      [org, provider],
    );
    const marketContent = {
      kind: 'api',
      title: 'Worker Listing',
      description: 'A bounded worker listing description',
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
        deliveryFields: ['payload'],
      },
      endpointContract: { origin: 'https://api.example.com', path: '/v1/run' },
      termsRevision: 'terms-v1',
      privacySummary: 'We store nothing.',
      paymentLane: 'unavailable',
      availability: { status: 'available', rateLimitPerMinute: '60' },
    };
    const market = new MarketStore(tenant);
    const draft = await market.createListingDraft(hash, org, provider, marketContent, {
      idempotencyKey: base64Key(30),
      mutationId: mutationId(30),
    });
    await market.createListingVersion(
      hash,
      org,
      draft.receipt.resourceId,
      { expectedLatestVersion: '1', content: marketContent },
      { idempotencyKey: base64Key(31), mutationId: mutationId(31) },
    );

    await outbox.initialize();
    const claimed = await outbox.claim({ limit: 50 });
    const marketEvents = claimed.filter(
      (event) => event.resourceType === 'listing' || event.resourceType === 'listing_version',
    );
    expect(marketEvents.map((event) => event.eventType).sort()).toEqual([
      'market.listing.created',
      'market.listing.version.created',
    ]);
    const registry = createHandlerRegistry();
    for (const event of marketEvents) {
      const key = eventKeyOf(event);
      expect(validateNotification(event)).toEqual(event);
      await registry[key](event, { signal: new AbortController().signal });
      expect((await outbox.complete(event.eventId, event.leaseGeneration)).applied).toBe(true);
    }
  });

  it('consumes the five control policy events from a real policy lifecycle without replay duplication', async () => {
    const seed = 40;
    const owner = await seedOwner(seed);
    const subjectAgent = 'openarc:agent:' + uuid(seed + 1);
    await admin.query(
      "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name) VALUES ($1, $2, 'Policy Agent')",
      [owner.org, subjectAgent],
    );

    const content = {
      organizationId: owner.org,
      subjectAgentId: subjectAgent,
      networkId: 'eip155:5042002',
      asset: 'USDC',
      representation: 'erc20',
      decimals: 6,
      perActionLimit: '1000',
      rollingLimit: null,
      rollingWindowSeconds: null,
      feeLimit: '10',
      allowedProviderIds: [],
      allowedListingIds: [],
      approval: { mode: 'none', threshold: null, separateApprover: false },
      expiresAt: null,
    } as const;
    const metadata = (offset: number) => ({
      idempotencyKey: base64Key(seed * 100 + offset),
      mutationId: mutationId(seed * 100 + offset),
    });

    const policies = new ControlPolicyStore(tenant);
    await policies.initialize();

    // createPolicy(hash, org, content, metadata): the receipt carries the
    // canonical openarc:policy: UUID generated by the real store.
    const created = await policies.createPolicy(owner.hash, owner.org, content, metadata(1));
    const policyId = created.receipt.resourceId;
    expect(policyId).toMatch(
      /^openarc:policy:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );

    const root = await policies.getPolicyRoot(owner.hash, owner.org, policyId);
    expect(root.currentRevision).toBe('1');

    // appendPolicyRevision(hash, org, id, {expectedRevision, expectedUpdatedAt,
    // content}, metadata): revision 2 becomes POLICY_ID@2.
    const appended = await policies.appendPolicyRevision(
      owner.hash,
      owner.org,
      policyId,
      { expectedRevision: root.currentRevision, expectedUpdatedAt: root.updatedAt, content },
      metadata(2),
    );
    expect(appended.receipt.resourceId).toBe(`${policyId}@2`);

    let cursor = await policies.getPolicyRoot(owner.hash, owner.org, policyId);
    for (const operation of ['control.policy.pause', 'control.policy.resume', 'control.policy.revoke'] as const) {
      const transitioned = await policies.transitionPolicy(
        owner.hash,
        owner.org,
        policyId,
        {
          operation,
          expectedRevision: cursor.currentRevision,
          expectedUpdatedAt: cursor.updatedAt,
        },
        metadata(operation === 'control.policy.pause' ? 3 : operation === 'control.policy.resume' ? 4 : 5),
      );
      expect(transitioned.receipt.resourceId).toBe(policyId);
      cursor = await policies.getPolicyRoot(owner.hash, owner.org, policyId);
    }
    expect(cursor.status).toBe('revoked');

    await outbox.initialize();
    const claimed = await outbox.claim({ limit: 50 });
    expect(claimed).toHaveLength(5);
    const safeTuples = claimed
      .map((event) => `${event.resourceType}|${event.eventType}|${event.resourceId}`)
      .sort();
    expect(safeTuples).toEqual(
      [
        `budget_policy|control.policy.created|${policyId}`,
        `budget_policy_revision|control.policy.revision.created|${policyId}@2`,
        `budget_policy|control.policy.paused|${policyId}`,
        `budget_policy|control.policy.resumed|${policyId}`,
        `budget_policy|control.policy.revoked|${policyId}`,
      ].sort(),
    );

    const registry = createHandlerRegistry();
    const acknowledged = new Set<string>();
    for (const event of claimed) {
      expect(validateNotification(event)).toEqual(event);
      const key = eventKeyOf(event);
      await registry[key](event, { signal: new AbortController().signal });
      const result = await outbox.complete(event.eventId, event.leaseGeneration);
      expect(result).toEqual({ applied: true });
      acknowledged.add(event.eventId);
    }
    expect(acknowledged.size).toBe(5);

    // The durable rows are completed and a second claim replays nothing.
    expect(await outbox.claim({ limit: 50 })).toHaveLength(0);
    const states = await admin.query<{ state: string }>(
      'SELECT state FROM openarc_durable.outbox_events WHERE organization_id = $1',
      [owner.org],
    );
    expect(states.rows).toHaveLength(5);
    expect(states.rows.every((row) => row.state === 'completed')).toBe(true);
  });

  it('consumes the three commerce-session events derived from a real issue/exchange/revoke lifecycle', async () => {
    const seed = 60;
    const owner = await seedOwner(seed);
    const subjectAgent = 'openarc:agent:' + uuid(seed + 1);
    await admin.query(
      "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name) VALUES ($1, $2, 'Session Agent')",
      [owner.org, subjectAgent],
    );

    const policyContent = {
      organizationId: owner.org,
      subjectAgentId: subjectAgent,
      networkId: 'eip155:5042002',
      asset: 'USDC',
      representation: 'erc20',
      decimals: 6,
      perActionLimit: '1000',
      rollingLimit: null,
      rollingWindowSeconds: null,
      feeLimit: '10',
      allowedProviderIds: [],
      allowedListingIds: [],
      approval: { mode: 'none', threshold: null, separateApprover: false },
      expiresAt: null,
    } as const;
    const metadata = (offset: number) => ({
      idempotencyKey: base64Key(seed * 100 + offset),
      mutationId: mutationId(seed * 100 + offset),
    });

    const policies = new ControlPolicyStore(tenant);
    await policies.initialize();
    const created = await policies.createPolicy(owner.hash, owner.org, policyContent, metadata(1));
    const policyId = created.receipt.resourceId;

    const salt = Buffer.alloc(16, 9).toString('base64url');
    const digest = Buffer.alloc(32, 10).toString('base64url');
    const hash = {
      algorithm: 'scrypt' as const,
      hashVersion: 1 as const,
      pepperVersion: 1,
      N: 32768 as const,
      r: 8 as const,
      p: 1 as const,
      salt,
      digest,
    };
    const issuedCredential = await credentials.issueAgentCredentialDurably({
      sessionHash: owner.hash,
      organizationId: owner.org,
      profileId: subjectAgent,
      lookupId: uuid(800060),
      hash,
      expiresAt: new Date(Date.now() + 60 * 60_000).toISOString(),
      metadata: { idempotencyKey: base64Key(seed * 100 + 2), mutationId: mutationId(seed * 100 + 2) },
    });
    const machineTokenHash = sha256(`machine-session:${seed}`);
    await credentials.createAgentSession({
      organizationId: owner.org,
      profileId: subjectAgent,
      credentialId: issuedCredential.receipt.credentialId,
      expectedVersion: 1,
      sessionId: uuid(610060),
      tokenHash: machineTokenHash,
      expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
    });

    const sessions = new CommerceSessionStore(tenant);
    const handoffHash = sha256(`handoff:${seed}`);
    const issued = await sessions.issueCommerceSession(
      owner.hash,
      owner.org,
      { subjectAgentId: subjectAgent, policyId, handoffHash, hashVersion: 1 },
      metadata(10),
    );
    const sessionId = issued.receipt.resourceId;
    expect(sessionId).toBe(mutationId(seed * 100 + 10));
    const exchanged = await sessions.exchangeCommerceSession(
      machineTokenHash,
      handoffHash,
      { tokenHash: sha256(`session-token:${seed}`), hashVersion: 1 },
      metadata(11),
    );
    expect(exchanged.receipt.resourceId).toBe(sessionId);
    const revoked = await sessions.revokeCommerceSession(owner.hash, owner.org, sessionId, metadata(12));
    expect(revoked.receipt.resourceId).toBe(sessionId);

    await outbox.initialize();
    // The real worker loop claims, validates and consumes each fenced event once.
    // A thin recorder captures the raw claimed rows without altering the real
    // claim/fence path, so the loop still owns every claim and acknowledgement.
    const claimedRows: ClaimedOutboxEvent[] = [];
    const recordingStore = {
      claim: async (input?: { limit?: number }) => {
        const batch = await outbox.claim(input);
        claimedRows.push(...batch);
        return batch;
      },
      complete: (eventId: unknown, leaseGeneration: unknown) =>
        outbox.complete(eventId, leaseGeneration),
      fail: (eventId: unknown, leaseGeneration: unknown, code: unknown) =>
        outbox.fail(eventId, leaseGeneration, code),
    };
    const records: WorkerLogRecord[] = [];
    let stop: () => void = () => undefined;
    const loop = new WorkerLoop({
      store: recordingStore,
      claimLimit: 50,
      pollMs: 250,
      idleMaxMs: 1000,
      logger: {
        log: (record) => {
          records.push(record);
          if (record.status === 'claim_empty') stop();
        },
      },
    });
    stop = () => loop.requestStop();
    await loop.run();

    const sessionEvents = claimedRows.filter((event) => event.resourceType === 'commerce_session');
    expect(sessionEvents).toHaveLength(3);
    expect(
      sessionEvents.map((event) => `${event.eventType}|${event.resourceId}`).sort(),
    ).toEqual(
      [
        `control.commerce_session.issued|${sessionId}`,
        `control.commerce_session.exchanged|${sessionId}`,
        `control.commerce_session.revoked|${sessionId}`,
      ].sort(),
    );
    // Every commerce-session resource id is the canonical UUIDv4 session id and
    // every claim mutation id is a canonical UUID that matches the durable row.
    for (const event of sessionEvents) {
      expect(event.resourceId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      );
      expect(event.mutationId).toMatch(UUID);
      expect(validateNotification(event)).toEqual(event);
    }
    const mutationByType = new Map(
      sessionEvents.map((event) => [event.eventType, event.mutationId]),
    );
    expect(mutationByType.get('control.commerce_session.issued')).toBe(mutationId(seed * 100 + 10));
    expect(mutationByType.get('control.commerce_session.exchanged')).toBe(mutationId(seed * 100 + 11));
    expect(mutationByType.get('control.commerce_session.revoked')).toBe(mutationId(seed * 100 + 12));

    const completedSession = records.filter(
      (record) => record.status === 'completed' && record.eventType?.startsWith('control.commerce_session.'),
    );
    expect(completedSession).toHaveLength(3);
    expect(records.some((record) => record.status === 'failed')).toBe(false);
    expect(completedSession.every((record) => record.count === 1)).toBe(true);
    // A second claim replays nothing: each job was acknowledged exactly once.
    expect(await outbox.claim({ limit: 50 })).toHaveLength(0);
    // The raw handoff and the machine/token hashes never leak into the emitted
    // event rows nor the bounded worker log records.
    const serializedLog = JSON.stringify(records);
    expect(serializedLog).not.toContain(handoffHash);
    expect(serializedLog).not.toContain(machineTokenHash);
    expect(serializedLog).not.toContain(sha256(`session-token:${seed}`));
    expect(serializedLog).not.toContain(sessionId);
    const durableRows = await admin.query<{ event_type: string; resource_id: string }>(
      `SELECT event_type, resource_id FROM openarc_durable.outbox_events
        WHERE organization_id = $1 AND resource_type = 'commerce_session'`,
      [owner.org],
    );
    expect(durableRows.rows).toHaveLength(3);
    const serializedRows = JSON.stringify(durableRows.rows);
    expect(serializedRows).not.toContain(handoffHash);
    expect(serializedRows).not.toContain(machineTokenHash);
    expect(durableRows.rows.every((row) => row.resource_id === sessionId)).toBe(true);
    const states = await admin.query<{ state: string }>(
      `SELECT state FROM openarc_durable.outbox_events
        WHERE organization_id = $1 AND resource_type = 'commerce_session'`,
      [owner.org],
    );
    expect(states.rows.every((row) => row.state === 'completed')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Real commerce-action lifecycle evidence (DB10 `0010_control_actions.sql` and
// DB11 `0011_control_action_reads.sql`).
//
// The helpers below deliberately MIRROR the frozen DB10 PostgreSQL suite
// (packages/db/test/control-action-store.postgres.test.ts) instead of inventing
// a parallel harness: a real reviewed+published listing, a real budget policy,
// a real machine credential and agent session, a real issued+exchanged commerce
// session and a real immutable requirement reference.
//
// EVERY commerce-action outbox row asserted below is written BY the action
// lifecycle transaction itself. No case here inserts an outbox row directly,
// and the cases prove that two independent ways: the notification row shares
// the exact PostgreSQL transaction id (`xmin`) of the business row the same
// statement wrote, and an uncommitted lifecycle transaction can see its own
// notification row while nothing outside the transaction can.
//
// SCOPE NOTE (schema10, not a worker defect): `is_canonical_source_kind`
// accepts exactly one requirement provenance, 'internal_fixture', and the
// 'production' mode of the authorize/decide cores refuses that provenance. So
// the only executable authorize/decide lifecycle today is the reviewed
// privileged fixture seam (mode 'internal_fixture') driven by the migrator
// role. `cancel_commerce_action_core` has NO provenance gate, so the cancel
// case below runs through the real restricted-runtime `ControlActionStore`.
// ---------------------------------------------------------------------------

const ACTION_ORIGIN = 'https://api.example.com';
const ACTION_PATH = '/v1/run';
const ACTION_REQUEST_DIGEST = 'a'.repeat(64);

function actionUuid(seed: number): string {
  return uuid(2_000_000 + seed);
}

function commerceActionId(seed: number): string {
  return `openarc:action:${actionUuid(seed)}`;
}

function commerceRequirementId(seed: number): string {
  return `openarc:requirement:${actionUuid(seed)}`;
}

function actionKey(seed: number, offset: number): string {
  return base64Key(2_000_000 + seed * 100 + offset);
}

function actionMutationId(seed: number, offset: number): string {
  return actionUuid(600_000 + seed * 100 + offset);
}

function actionHashInput() {
  return {
    algorithm: 'scrypt' as const,
    hashVersion: 1 as const,
    pepperVersion: 1,
    N: 32768 as const,
    r: 8 as const,
    p: 1 as const,
    salt: Buffer.alloc(16, 11).toString('base64url'),
    digest: Buffer.alloc(32, 12).toString('base64url'),
  };
}

function actionListingContent(): Record<string, unknown> {
  return {
    kind: 'api',
    title: 'Action Listing',
    description: 'A bounded action listing description',
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
    endpointContract: { origin: ACTION_ORIGIN, path: ACTION_PATH },
    termsRevision: 'terms-v1',
    privacySummary: 'We store nothing.',
    paymentLane: 'unavailable',
    availability: { status: 'available', rateLimitPerMinute: '60' },
  };
}

let actionMarket: MarketStore;
let actionLifecycle: MarketLifecycleStore;
let actionCommerce: CommerceSessionStore;

interface ActionChain {
  readonly owner: SeededOwner;
  readonly agent: string;
  readonly provider: string;
  readonly listing: string;
  readonly policy: string;
  readonly handoffHash: string;
  readonly agentSessionHash: string;
  readonly commerceTokenHash: string;
  readonly seed: number;
}

async function actionVersionUpdatedAt(org: string, listing: string): Promise<string> {
  const result = await admin.query<{ updated_at: string }>(
    `SELECT to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS updated_at
       FROM openarc_tenant.listing_version_states
      WHERE organization_id = $1 AND listing_id = $2 AND version = '1'`,
    [org, listing],
  );
  return result.rows[0]?.updated_at ?? '';
}

async function seedActionListing(
  owner: SeededOwner,
  provider: string,
  seed: number,
): Promise<string> {
  const draft = await actionMarket.createListingDraft(
    owner.hash,
    owner.org,
    provider,
    actionListingContent(),
    { idempotencyKey: actionKey(seed, 1), mutationId: actionMutationId(seed, 1) },
  );
  const listing = draft.receipt.resourceId;
  const digest = reviewedEndpointDigest({
    listingId: listing,
    version: '1',
    origin: ACTION_ORIGIN,
    path: ACTION_PATH,
  });
  const moderatorAccount = await seedAccount(9_000 + seed);
  const moderatorHash = await seedSession(9_000 + seed, moderatorAccount);
  await admin.query(
    "INSERT INTO openarc_tenant.market_moderator_grants (account_id, status) VALUES ($1, 'active')",
    [moderatorAccount],
  );
  await actionLifecycle.recordOriginReview(
    moderatorHash,
    owner.org,
    listing,
    '1',
    {
      expectedUpdatedAt: await actionVersionUpdatedAt(owner.org, listing),
      decision: 'approved',
      reviewedEndpointDigest: digest,
      reasonCode: 'manual_review',
      reasonDigest: null,
    },
    { idempotencyKey: actionKey(seed, 2), mutationId: actionMutationId(seed, 2) },
  );
  await actionLifecycle.publishListingVersion(
    owner.hash,
    owner.org,
    listing,
    '1',
    {
      expectedUpdatedAt: await actionVersionUpdatedAt(owner.org, listing),
      expectedActiveVersion: null,
    },
    { idempotencyKey: actionKey(seed, 3), mutationId: actionMutationId(seed, 3) },
  );
  return listing;
}

async function seedActionPolicy(
  org: string,
  subject: string,
  provider: string,
  seed: number,
  mode: 'none' | 'always',
): Promise<string> {
  const id = `openarc:policy:${actionUuid(seed)}`;
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
               '3600', '0', ARRAY[$4]::text[], ARRAY[]::text[], $5, NULL, false,
               clock_timestamp() + interval '1 hour', 'sha256:' || repeat('a', 64))`,
      [org, id, subject, provider, mode],
    );
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
  return id;
}

async function seedActionChain(seed: number, mode: 'none' | 'always'): Promise<ActionChain> {
  actionMarket = new MarketStore(tenant);
  actionLifecycle = new MarketLifecycleStore(tenant);
  actionCommerce = new CommerceSessionStore(tenant);

  const owner = await seedOwner(seed);
  const agent = `openarc:agent:${actionUuid(seed)}`;
  await admin.query(
    "INSERT INTO openarc_tenant.agents (organization_id, agent_id, display_name, status) VALUES ($1, $2, 'Action Agent', 'active')",
    [owner.org, agent],
  );
  const provider = `openarc:provider:${actionUuid(seed)}`;
  await admin.query(
    "INSERT INTO openarc_tenant.providers (organization_id, provider_id, display_name, status) VALUES ($1, $2, 'Action Provider', 'active')",
    [owner.org, provider],
  );
  const listing = await seedActionListing(owner, provider, seed);
  const policy = await seedActionPolicy(owner.org, agent, provider, seed, mode);

  const issued = await credentials.issueAgentCredentialDurably({
    sessionHash: owner.hash,
    organizationId: owner.org,
    profileId: agent,
    lookupId: actionUuid(700_000 + seed),
    hash: actionHashInput(),
    expiresAt: new Date(Date.now() + 30 * 60_000).toISOString(),
    metadata: { idempotencyKey: actionKey(seed, 4), mutationId: actionMutationId(seed, 4) },
  });
  const agentSessionHash = sha256(`action-machine:${seed}`);
  await credentials.createAgentSession({
    organizationId: owner.org,
    profileId: agent,
    credentialId: issued.receipt.credentialId,
    expectedVersion: 1,
    sessionId: actionUuid(800_000 + seed),
    tokenHash: agentSessionHash,
    // The durable helper caps a machine session at 15 minutes.
    expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
  });

  const handoffHash = sha256(`action-handoff:${seed}`);
  const commerceTokenHash = sha256(`action-commerce:${seed}`);
  await actionCommerce.issueCommerceSession(
    owner.hash,
    owner.org,
    { subjectAgentId: agent, policyId: policy, handoffHash, hashVersion: 1 },
    { idempotencyKey: actionKey(seed, 5), mutationId: actionMutationId(seed, 5) },
  );
  await actionCommerce.exchangeCommerceSession(
    agentSessionHash,
    handoffHash,
    { tokenHash: commerceTokenHash, hashVersion: 1 },
    { idempotencyKey: actionKey(seed, 6), mutationId: actionMutationId(seed, 6) },
  );

  return {
    owner,
    agent,
    provider,
    listing,
    policy,
    handoffHash,
    agentSessionHash,
    commerceTokenHash,
    seed,
  };
}

async function seedActionRequirement(chain: ActionChain, seed: number): Promise<string> {
  const id = commerceRequirementId(seed);
  await admin.query(
    `INSERT INTO openarc_durable.commerce_requirement_references (
       organization_id, requirement_id, seller_organization_id, provider_id, listing_id,
       listing_version, network_id, asset, representation, decimals, amount_atomic,
       fee_atomic, requirement_digest, source_kind, created_at, valid_until)
     VALUES ($1, $2, $1, $3, $4, '1', 'eip155:5042002', 'USDC', 'erc20', 6, '1000000', '0',
             'sha256:' || repeat('c', 64), 'internal_fixture', clock_timestamp(),
             clock_timestamp() + interval '30 minutes')`,
    [chain.owner.org, id, chain.provider, chain.listing],
  );
  return id;
}

const AUTHORIZE_CORE_SQL = `SELECT * FROM openarc_durable.authorize_commerce_action_core(
  'internal_fixture', $1, $2, $3, $4::uuid, $5, $6, $7)`;

/** Exact production session-context digest for the presented commerce token. */
function authorizeContextDigest(commerceTokenHash: string): string {
  return createHash('sha256')
    .update(`openarc.control.commerce_action.authorize.session.v1:${commerceTokenHash}`, 'utf8')
    .digest('hex');
}

function authorizeParams(
  chain: ActionChain,
  requirement: string,
  action: string,
  mutation: string,
  rawKey: string,
): unknown[] {
  return [
    chain.commerceTokenHash,
    requirement,
    action,
    mutation,
    // The core consumes the TRUSTED key HASH, never the raw idempotency key.
    createHash('sha256').update(rawKey, 'utf8').digest('hex'),
    ACTION_REQUEST_DIGEST,
    authorizeContextDigest(chain.commerceTokenHash),
  ];
}

function coreDecide(
  chain: ActionChain,
  action: string,
  decision: 'approve' | 'reject',
  mutation: string,
  rawKey: string,
) {
  return migrator.query<{ out_status: string; out_action_id: string; out_replayed: boolean }>(
    `SELECT * FROM openarc_durable.decide_commerce_action_core(
       'internal_fixture', $1, $2, $3, $4, $5::uuid, $6, $7, $8)`,
    [
      chain.owner.hash,
      chain.owner.org,
      action,
      decision,
      mutation,
      createHash('sha256').update(rawKey, 'utf8').digest('hex'),
      ACTION_REQUEST_DIGEST,
      sha256(`decide-context:${chain.seed}`),
    ],
  );
}

/** The exact PostgreSQL transaction id that wrote one durable row. */
async function txnOf(sql: string, params: readonly unknown[]): Promise<string> {
  const result = await admin.query<{ value: string }>(sql, [...params]);
  expect(result.rows).toHaveLength(1);
  return result.rows[0]?.value ?? '';
}

function outboxTxn(eventType: string, resourceId: string): Promise<string> {
  return txnOf(
    `SELECT xmin::text AS value FROM openarc_durable.outbox_events
      WHERE event_type = $1 AND resource_id = $2`,
    [eventType, resourceId],
  );
}

function rowTxn(table: string, action: string): Promise<string> {
  return txnOf(`SELECT xmin::text AS value FROM ${table} WHERE action_id = $1`, [action]);
}

/**
 * Full-row digest of every financial surface DB10 owns. This is a whole-row
 * snapshot (money kept as the exact stored integer strings), never a count.
 */
async function actionFinancialSnapshot(): Promise<unknown> {
  const result = await admin.query<{ snapshot: unknown }>(
    `SELECT jsonb_build_object(
       'actions', (SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY a.action_id), '[]'::jsonb)
                     FROM openarc_durable.commerce_actions a),
       'reservations', (SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.reservation_id), '[]'::jsonb)
                     FROM openarc_durable.budget_reservations r),
       'approvals', (SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY p.approval_id), '[]'::jsonb)
                     FROM openarc_durable.commerce_approvals p),
       'budget_events', (SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY b.event_id), '[]'::jsonb)
                     FROM openarc_durable.budget_events b),
       'exposure', (SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.organization_id, x.subject_agent_id), '[]'::jsonb)
                     FROM openarc_durable.commerce_exposure_locks x)
     ) AS snapshot`,
  );
  return result.rows[0]?.snapshot;
}

async function actionFinancialCounts(): Promise<Record<string, number>> {
  const result = await admin.query<Record<string, number>>(
    `SELECT (SELECT count(*)::int FROM openarc_durable.commerce_actions) AS actions,
            (SELECT count(*)::int FROM openarc_durable.budget_reservations) AS reservations,
            (SELECT count(*)::int FROM openarc_durable.commerce_approvals) AS approvals,
            (SELECT count(*)::int FROM openarc_durable.budget_events) AS budget_events,
            (SELECT count(*)::int FROM openarc_durable.commerce_exposure_locks) AS exposure`,
  );
  return result.rows[0] as Record<string, number>;
}

interface DispatchRecord {
  readonly registeredKey: NotificationEventKey;
  readonly derivedKey: NotificationEventKey;
  readonly eventType: string;
  readonly resourceId: string;
}

const COMMERCE_ACTION_KEYS: readonly NotificationEventKey[] = [
  'commerce_action|control.commerce_action.authorized',
  'commerce_action|control.commerce_action.approved',
  'commerce_action|control.commerce_action.rejected',
  'commerce_action|control.commerce_action.cancelled',
];

/**
 * A bounded recorder that preserves the default consumption behaviour
 * (validate, never side-effect) and additionally captures the registry key it
 * was registered under next to the key derived from the claimed event.
 */
function actionRecorder(key: NotificationEventKey, sink: DispatchRecord[]): NotificationHandler {
  return (event) => {
    validateNotification(event);
    sink.push({
      registeredKey: key,
      derivedKey: eventKeyOf(event),
      eventType: event.eventType,
      resourceId: event.resourceId,
    });
  };
}

function commerceActionRegistry(sink: DispatchRecord[]) {
  const overrides: Partial<Record<NotificationEventKey, NotificationHandler>> = {};
  for (const key of COMMERCE_ACTION_KEYS) overrides[key] = actionRecorder(key, sink);
  return createHandlerRegistry(overrides);
}

/**
 * Fixture hygiene: retire every NON commerce-action notification produced while
 * seeding, so the worker's claim batch contains only the action lifecycle.
 *
 * This is required today because `OutboxStore`'s claim projection
 * (packages/db/src/outbox-store.ts) does not yet accept the DB7 market
 * lifecycle event types a real reviewed+published listing emits
 * ('market.listing.origin_review.recorded', 'market.listing.version.published'),
 * even though the worker registry in apps/worker/src/handlers.ts does register
 * them; one such row makes the WHOLE claim batch fail closed. That gap lives in
 * packages/db and is REPORTED, not fixed here. No commerce-action row is ever
 * touched by this helper, and it never acknowledges on the worker's behalf.
 */
async function retireSeedingNotifications(): Promise<void> {
  const retired = await admin.query<{ event_type: string }>(
    `UPDATE openarc_durable.outbox_events
        SET state = 'completed', lease_until = NULL, completed_at = clock_timestamp()
      WHERE state <> 'completed' AND event_type NOT LIKE 'control.commerce_action%'
      RETURNING event_type`,
  );
  expect(retired.rows.every((row) => row.event_type.startsWith('control.commerce_action') === false)).toBe(
    true,
  );
  const remaining = await admin.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM openarc_durable.outbox_events
      WHERE state <> 'completed' AND event_type NOT LIKE 'control.commerce_action%'`,
  );
  expect(remaining.rows[0]?.n).toBe(0);
}

/** Thin recorder around the REAL store; the loop still owns every claim/ack. */
function recordingOutbox(source: OutboxStore, sink: ClaimedOutboxEvent[]) {
  return {
    claim: async (input?: { limit?: number }) => {
      const batch = await source.claim(input);
      sink.push(...batch);
      return batch;
    },
    complete: (eventId: unknown, leaseGeneration: unknown) =>
      source.complete(eventId, leaseGeneration),
    fail: (eventId: unknown, leaseGeneration: unknown, code: unknown) =>
      source.fail(eventId, leaseGeneration, code),
  };
}

/** Run the REAL worker loop until the durable queue is empty. */
async function runWorkerLoop(
  store: ReturnType<typeof recordingOutbox>,
  registry: ReturnType<typeof commerceActionRegistry>,
  records: WorkerLogRecord[],
): Promise<void> {
  let stop: () => void = () => undefined;
  const loop = new WorkerLoop({
    store,
    registry,
    claimLimit: 50,
    pollMs: 250,
    idleMaxMs: 1000,
    logger: {
      log: (record: WorkerLogRecord) => {
        records.push(record);
        // Stop on an empty queue; also stop on a claim error so a projection
        // failure surfaces as an assertion instead of an endless retry.
        if (record.status === 'claim_empty' || record.status === 'claim_error') stop();
      },
    },
  });
  stop = () => loop.requestStop();
  await loop.run();
}

describe('worker consumes commerce-action events produced by real lifecycle transactions', () => {
  it(
    'consumes authorized, approved, rejected and cancelled events emitted by real action transactions',
    async () => {
      const seed = 91;
      const chain = await seedActionChain(seed, 'always');
      const decidedAction = commerceActionId(seed * 10 + 1);
      const rejectedAction = commerceActionId(seed * 10 + 2);
      const decidedRequirement = await seedActionRequirement(chain, seed * 10 + 1);
      const rejectedRequirement = await seedActionRequirement(chain, seed * 10 + 2);

      // ---- real authorize x2 -------------------------------------------------
      const authorizeMutations = new Map<string, string>();
      const authorizeTxns = new Map<string, string>();
      for (const [action, requirement, offset] of [
        [decidedAction, decidedRequirement, 11],
        [rejectedAction, rejectedRequirement, 12],
      ] as const) {
        const mutation = actionMutationId(seed, offset);
        const result = await migrator.query<{
          out_status: string;
          out_action_id: string;
          out_replayed: boolean;
        }>(AUTHORIZE_CORE_SQL, authorizeParams(chain, requirement, action, mutation, actionKey(seed, offset)));
        expect(result.rows[0]).toMatchObject({
          out_replayed: false,
          out_action_id: action,
          out_status: 'pending_approval',
        });
        authorizeMutations.set(action, mutation);
        // The notification row was written BY this very lifecycle transaction:
        // it carries the SAME PostgreSQL transaction id as the action row the
        // same call inserted, so it cannot be a separate later write.
        const eventTxn = await outboxTxn('control.commerce_action.authorized', action);
        expect(eventTxn).toBe(await rowTxn('openarc_durable.commerce_actions', action));
        expect(eventTxn).toBe(
          await txnOf(
            `SELECT xmin::text AS value FROM openarc_durable.audit_events
              WHERE resource_id = $1 AND operation = 'control.commerce_action.authorize'`,
            [action],
          ),
        );
        authorizeTxns.set(action, eventTxn);
      }

      // The same-commit evidence is not vacuous: each authorize ran in its OWN
      // transaction, and neither shares the transaction that seeded the chain.
      expect(authorizeTxns.get(decidedAction)).not.toBe(authorizeTxns.get(rejectedAction));
      const seedingTxn = await txnOf(
        `SELECT xmin::text AS value FROM openarc_durable.commerce_sessions
          WHERE organization_id = $1`,
        [chain.owner.org],
      );
      expect(authorizeTxns.get(decidedAction)).not.toBe(seedingTxn);
      expect(authorizeTxns.get(rejectedAction)).not.toBe(seedingTxn);

      // ---- real approve ------------------------------------------------------
      const approveMutation = actionMutationId(seed, 21);
      const approved = await coreDecide(chain, decidedAction, 'approve', approveMutation, actionKey(seed, 21));
      expect(approved.rows[0]).toMatchObject({
        out_replayed: false,
        out_action_id: decidedAction,
        out_status: 'reserved_not_granted',
      });
      const approvedTxn = await outboxTxn('control.commerce_action.approved', decidedAction);
      // The approve transaction is the transaction that inserted the held
      // reservation, and it is NOT the earlier authorize transaction.
      expect(approvedTxn).toBe(await rowTxn('openarc_durable.budget_reservations', decidedAction));
      expect(approvedTxn).not.toBe(authorizeTxns.get(decidedAction));

      // ---- real reject -------------------------------------------------------
      const rejectMutation = actionMutationId(seed, 22);
      const rejected = await coreDecide(chain, rejectedAction, 'reject', rejectMutation, actionKey(seed, 22));
      expect(rejected.rows[0]).toMatchObject({
        out_replayed: false,
        out_action_id: rejectedAction,
        out_status: 'rejected',
      });
      const rejectedTxn = await outboxTxn('control.commerce_action.rejected', rejectedAction);
      expect(rejectedTxn).toBe(await rowTxn('openarc_durable.commerce_approvals', rejectedAction));
      expect(rejectedTxn).not.toBe(authorizeTxns.get(rejectedAction));

      // ---- real cancel through the RESTRICTED runtime store ------------------
      const cancelMutation = actionMutationId(seed, 23);
      const actionStore = new ControlActionStore(tenant);
      await actionStore.initialize();
      const cancelled = await actionStore.cancelCommerceAction(
        chain.owner.hash,
        chain.owner.org,
        decidedAction,
        { idempotencyKey: actionKey(seed, 23), mutationId: cancelMutation },
      );
      expect(cancelled.replayed).toBe(false);
      expect(cancelled.receipt).toMatchObject({
        resourceType: 'commerce_action',
        resourceId: decidedAction,
        operation: 'control.commerce_action.cancel',
        mutationId: cancelMutation,
      });
      const cancelledTxn = await outboxTxn('control.commerce_action.cancelled', decidedAction);
      expect(cancelledTxn).toBe(await rowTxn('openarc_durable.commerce_actions', decidedAction));
      expect(cancelledTxn).toBe(await rowTxn('openarc_durable.budget_events', decidedAction));
      expect(cancelledTxn).not.toBe(approvedTxn);

      // Exactly five action notifications, each bound to the canonical action id
      // the lifecycle transaction actually created and to its own mutation id.
      const durable = await admin.query<{
        event_type: string;
        resource_type: string;
        resource_id: string;
        mutation_id: string;
      }>(
        `SELECT event_type, resource_type, resource_id, mutation_id
           FROM openarc_durable.outbox_events
          WHERE event_type LIKE 'control.commerce_action%'`,
      );
      expect(
        durable.rows
          .map((row) => `${row.resource_type}|${row.event_type}|${row.resource_id}|${row.mutation_id}`)
          .sort(),
      ).toEqual(
        [
          `commerce_action|control.commerce_action.authorized|${decidedAction}|${authorizeMutations.get(decidedAction)}`,
          `commerce_action|control.commerce_action.authorized|${rejectedAction}|${authorizeMutations.get(rejectedAction)}`,
          `commerce_action|control.commerce_action.approved|${decidedAction}|${approveMutation}`,
          `commerce_action|control.commerce_action.rejected|${rejectedAction}|${rejectMutation}`,
          `commerce_action|control.commerce_action.cancelled|${decidedAction}|${cancelMutation}`,
        ].sort(),
      );

      // The financial surface is non-trivial before consumption and money is
      // held as exact integer strings, never a JS number.
      expect(await actionFinancialCounts()).toEqual({
        actions: 2,
        reservations: 1,
        approvals: 2,
        budget_events: 1,
        exposure: 1,
      });
      const money = await admin.query<{
        amount_atomic: string;
        fee_atomic: string;
        debit_atomic: string;
        released: string;
      }>(
        `SELECT a.amount_atomic, a.fee_atomic, a.debit_atomic,
                (SELECT b.amount_atomic FROM openarc_durable.budget_events b
                  WHERE b.action_id = a.action_id AND b.event_kind = 'released') AS released
           FROM openarc_durable.commerce_actions a WHERE a.action_id = $1`,
        [decidedAction],
      );
      expect(money.rows[0]).toEqual({
        amount_atomic: '1000000',
        fee_atomic: '0',
        debit_atomic: '1000000',
        released: '1000000',
      });
      const before = await actionFinancialSnapshot();

      // ---- the worker's REAL claim loop -------------------------------------
      await retireSeedingNotifications();
      await outbox.initialize();
      const claimedRows: ClaimedOutboxEvent[] = [];
      const dispatched: DispatchRecord[] = [];
      const records: WorkerLogRecord[] = [];
      await runWorkerLoop(
        recordingOutbox(outbox, claimedRows),
        commerceActionRegistry(dispatched),
        records,
      );

      const actionEvents = claimedRows.filter((event) => event.resourceType === 'commerce_action');
      expect(claimedRows).toHaveLength(5);
      expect(actionEvents).toHaveLength(5);
      for (const event of actionEvents) {
        // The resourceId is the canonical openarc:action:<uuidv4> of the action
        // the lifecycle transaction created.
        expect(event.resourceId).toMatch(
          /^openarc:action:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
        );
        expect(event.mutationId).toMatch(UUID);
        expect(validateNotification(event)).toEqual(event);
      }
      const storedActions = await admin.query<{ action_id: string }>(
        'SELECT action_id FROM openarc_durable.commerce_actions ORDER BY action_id',
      );
      expect([...new Set(actionEvents.map((event) => event.resourceId))].sort()).toEqual(
        storedActions.rows.map((row) => row.action_id).sort(),
      );

      // Each event selected the handler registered under its exact composite
      // resourceType|eventType key.
      expect(dispatched).toHaveLength(5);
      for (const entry of dispatched) expect(entry.derivedKey).toBe(entry.registeredKey);
      expect(dispatched.map((entry) => `${entry.registeredKey}|${entry.resourceId}`).sort()).toEqual(
        [
          `commerce_action|control.commerce_action.authorized|${decidedAction}`,
          `commerce_action|control.commerce_action.authorized|${rejectedAction}`,
          `commerce_action|control.commerce_action.approved|${decidedAction}`,
          `commerce_action|control.commerce_action.rejected|${rejectedAction}`,
          `commerce_action|control.commerce_action.cancelled|${decidedAction}`,
        ].sort(),
      );

      // Claimed and acknowledged exactly once, with no failure path taken.
      const completedAction = records.filter(
        (record) =>
          record.status === 'completed' &&
          record.eventType?.startsWith('control.commerce_action.') === true,
      );
      expect(completedAction).toHaveLength(5);
      expect(completedAction.every((record) => record.count === 1)).toBe(true);
      expect(
        records.some(
          (record) =>
            record.status === 'failed' ||
            record.status === 'stale' ||
            record.status === 'outcome_unknown' ||
            record.status === 'aborted' ||
            record.status === 'claim_error',
        ),
      ).toBe(false);
      expect(await outbox.claim({ limit: 50 })).toHaveLength(0);
      const states = await admin.query<{ state: string; attempt_count: number }>(
        `SELECT state, attempt_count FROM openarc_durable.outbox_events
          WHERE event_type LIKE 'control.commerce_action%'`,
      );
      expect(states.rows).toHaveLength(5);
      expect(states.rows.every((row) => row.state === 'completed' && row.attempt_count === 1)).toBe(
        true,
      );

      // Consumption has NO financial effect: every action, reservation,
      // approval, budget-event and exposure row is byte-identical.
      expect(await actionFinancialSnapshot()).toEqual(before);
      expect(await actionFinancialCounts()).toEqual({
        actions: 2,
        reservations: 1,
        approvals: 2,
        budget_events: 1,
        exposure: 1,
      });

      // No secret reaches the claimed payload, the dispatched handler view, the
      // bounded worker log, or the durable notification rows themselves.
      const secrets = [
        chain.commerceTokenHash,
        chain.agentSessionHash,
        chain.handoffHash,
        chain.owner.hash,
        ACTION_REQUEST_DIGEST,
        authorizeContextDigest(chain.commerceTokenHash),
        'c'.repeat(64),
        createHash('sha256').update(actionKey(seed, 11), 'utf8').digest('hex'),
        createHash('sha256').update(actionKey(seed, 21), 'utf8').digest('hex'),
        createHash('sha256').update(actionKey(seed, 23), 'utf8').digest('hex'),
        actionKey(seed, 11),
        actionKey(seed, 21),
        actionKey(seed, 23),
      ];
      const rawRows = await admin.query<{ row: Record<string, unknown> }>(
        `SELECT to_jsonb(o) AS row FROM openarc_durable.outbox_events o
          WHERE o.event_type LIKE 'control.commerce_action%'`,
      );
      const surfaces = [
        JSON.stringify(actionEvents),
        JSON.stringify(dispatched),
        JSON.stringify(records),
        JSON.stringify(rawRows.rows),
      ];
      for (const surface of surfaces) {
        for (const secret of secrets) expect(surface).not.toContain(secret);
        // No 64-hex value of ANY kind survives to a worker-visible surface.
        expect(surface).not.toMatch(/[0-9a-f]{64}/);
      }
    },
    60000,
  );

  it(
    'claims nothing when the action lifecycle transaction rolls back',
    async () => {
      const seed = 92;
      const chain = await seedActionChain(seed, 'none');
      const action = commerceActionId(seed * 10 + 1);
      const requirement = await seedActionRequirement(chain, seed * 10 + 1);
      const mutation = actionMutationId(seed, 11);

      await outbox.initialize();
      // Retire the seeding notifications so only the action lifecycle is in play.
      await retireSeedingNotifications();
      expect(await outbox.claim({ limit: 50 })).toHaveLength(0);
      const before = await actionFinancialSnapshot();

      const client = await migrator.connect();
      try {
        await client.query('BEGIN');
        const result = await client.query<{ out_action_id: string; out_status: string }>(
          AUTHORIZE_CORE_SQL,
          authorizeParams(chain, requirement, action, mutation, actionKey(seed, 11)),
        );
        expect(result.rows[0]).toMatchObject({
          out_action_id: action,
          out_status: 'reserved_not_granted',
        });
        // INSIDE the still-open lifecycle transaction the business rows and the
        // notification row already exist together...
        const inside = await client.query<{ actions: number; reservations: number; events: number }>(
          `SELECT (SELECT count(*)::int FROM openarc_durable.commerce_actions WHERE action_id = $1) AS actions,
                  (SELECT count(*)::int FROM openarc_durable.budget_reservations WHERE action_id = $1) AS reservations,
                  (SELECT count(*)::int FROM openarc_durable.outbox_events
                    WHERE event_type = 'control.commerce_action.authorized' AND resource_id = $1) AS events`,
          [action],
        );
        expect(inside.rows[0]).toEqual({ actions: 1, reservations: 1, events: 1 });
        // ...and NOTHING of it is visible outside the transaction, which is what
        // makes the notification a product of the lifecycle commit itself.
        const outside = await admin.query<{ n: number }>(
          `SELECT count(*)::int AS n FROM openarc_durable.outbox_events
            WHERE event_type LIKE 'control.commerce_action%'`,
        );
        expect(outside.rows[0]?.n).toBe(0);
        await client.query('ROLLBACK');
      } finally {
        client.release();
      }

      const after = await admin.query<{ actions: number; events: number }>(
        `SELECT (SELECT count(*)::int FROM openarc_durable.commerce_actions) AS actions,
                (SELECT count(*)::int FROM openarc_durable.outbox_events
                  WHERE event_type LIKE 'control.commerce_action%') AS events`,
      );
      expect(after.rows[0]).toEqual({ actions: 0, events: 0 });
      expect(await actionFinancialSnapshot()).toEqual(before);
      expect(await actionFinancialCounts()).toEqual({
        actions: 0,
        reservations: 0,
        approvals: 0,
        budget_events: 0,
        exposure: 0,
      });

      // The worker's real claim loop has nothing to claim and consumes nothing.
      const claimedRows: ClaimedOutboxEvent[] = [];
      const dispatched: DispatchRecord[] = [];
      const records: WorkerLogRecord[] = [];
      await runWorkerLoop(
        recordingOutbox(outbox, claimedRows),
        commerceActionRegistry(dispatched),
        records,
      );
      expect(claimedRows).toHaveLength(0);
      expect(dispatched).toHaveLength(0);
      expect(records.some((record) => record.status === 'claimed')).toBe(false);
      expect(records.some((record) => record.status === 'claim_error')).toBe(false);
    },
    60000,
  );

  it(
    'reclaims an expired commerce-action lease and acknowledges it exactly once',
    async () => {
      const seed = 93;
      const chain = await seedActionChain(seed, 'none');
      const action = commerceActionId(seed * 10 + 1);
      const requirement = await seedActionRequirement(chain, seed * 10 + 1);
      const mutation = actionMutationId(seed, 11);
      const authorized = await migrator.query<{ out_action_id: string; out_status: string }>(
        AUTHORIZE_CORE_SQL,
        authorizeParams(chain, requirement, action, mutation, actionKey(seed, 11)),
      );
      expect(authorized.rows[0]).toMatchObject({
        out_action_id: action,
        out_status: 'reserved_not_granted',
      });
      expect(await outboxTxn('control.commerce_action.authorized', action)).toBe(
        await rowTxn('openarc_durable.commerce_actions', action),
      );
      const before = await actionFinancialSnapshot();

      await retireSeedingNotifications();
      await outbox.initialize();
      const dispatched: DispatchRecord[] = [];
      const registry = commerceActionRegistry(dispatched);

      // First delivery: the real handler runs, but the lease dies before the ack.
      const first = await outbox.claim({ limit: 50 });
      expect(first).toHaveLength(1);
      const event = first[0] as ClaimedOutboxEvent;
      expect(event.resourceType).toBe('commerce_action');
      expect(event.eventType).toBe('control.commerce_action.authorized');
      expect(event.resourceId).toBe(action);
      expect(event.attemptCount).toBe(1);
      await registry[eventKeyOf(event)](event, { signal: new AbortController().signal });
      expect(dispatched).toHaveLength(1);

      // Controlled fixture: age the still-leased row with admin SQL exactly as
      // the existing reclaim case does. This labels the observed durable lease.
      await admin.query(
        `UPDATE openarc_durable.outbox_events
            SET lease_until = clock_timestamp() - interval '1 second'
          WHERE event_id = $1`,
        [event.eventId],
      );

      // Second delivery through the REAL loop on a restarted worker connection.
      const peer = new OutboxStore(workerPeer);
      await peer.initialize();
      const claimedRows: ClaimedOutboxEvent[] = [];
      const records: WorkerLogRecord[] = [];
      await runWorkerLoop(recordingOutbox(peer, claimedRows), registry, records);

      const redelivered = claimedRows.filter((claimed) => claimed.resourceType === 'commerce_action');
      expect(redelivered).toHaveLength(1);
      const second = redelivered[0] as ClaimedOutboxEvent;
      expect(second.eventId).toBe(event.eventId);
      expect(Number(second.leaseGeneration)).toBe(Number(event.leaseGeneration) + 1);
      expect(second.attemptCount).toBe(2);
      expect(dispatched).toHaveLength(2);
      for (const entry of dispatched) {
        expect(entry.derivedKey).toBe(entry.registeredKey);
        expect(entry.resourceId).toBe(action);
      }
      const completedAction = records.filter(
        (record) =>
          record.status === 'completed' &&
          record.eventType === 'control.commerce_action.authorized',
      );
      expect(completedAction).toHaveLength(1);
      expect(
        records.some(
          (record) =>
            record.status === 'failed' ||
            record.status === 'stale' ||
            record.status === 'outcome_unknown' ||
            record.status === 'claim_error',
        ),
      ).toBe(false);

      // The killed worker's stale generation can never acknowledge it again, so
      // the job is acknowledged exactly once overall.
      expect(await outbox.complete(event.eventId, event.leaseGeneration)).toEqual({
        applied: false,
      });
      const state = await admin.query<{ state: string; attempt_count: number }>(
        'SELECT state, attempt_count FROM openarc_durable.outbox_events WHERE event_id = $1',
        [event.eventId],
      );
      expect(state.rows[0]).toEqual({ state: 'completed', attempt_count: 2 });
      expect(await outbox.claim({ limit: 50 })).toHaveLength(0);
      expect(await peer.claim({ limit: 50 })).toHaveLength(0);

      // Redelivery caused NO duplicate financial effect.
      expect(await actionFinancialSnapshot()).toEqual(before);
      expect(await actionFinancialCounts()).toEqual({
        actions: 1,
        reservations: 1,
        approvals: 0,
        budget_events: 0,
        exposure: 1,
      });
    },
    60000,
  );
});

// ---------------------------------------------------------------------------
// No DB-permitted event may be unprojectable or unregistered. One such row
// fails the WHOLE claim batch and the loop stops after
// maxConsecutiveClaimErrors, so every notification of every type jams. The
// permitted set is read from the migrated outbox CHECK constraints, so a
// migration that adds an event type fails here until the store AND the worker
// handle it.
// ---------------------------------------------------------------------------
describe('every DB-permitted outbox event is projected and registered', () => {
  it('matches the worker registry exactly to the pairs the outbox CHECK constraints permit', async () => {
    const pairs = await readPermittedOutboxEventPairs(admin);
    const permitted = pairs.map(outboxPairKey).sort();
    expect(permitted).toContain('authorization_grant|control.grant.issued');
    expect([...NOTIFICATION_EVENT_KEYS].sort()).toEqual(permitted);
    const registry = createHandlerRegistry();
    expect(Object.keys(registry).sort()).toEqual(permitted);

    const owner = await seedOwner(95);
    await outbox.initialize();
    const failures: string[] = [];
    for (const [index, pair] of pairs.entries()) {
      const key = outboxPairKey(pair);
      const eventId = await insertOutboxEventForPair(admin, owner.org, pair, index);
      try {
        const claimed = await outbox.claim({ limit: 1 });
        expect(claimed).toHaveLength(1);
        const event = claimed[0] as ClaimedOutboxEvent;
        expect(event.eventId).toBe(eventId);
        expect(eventKeyOf(event)).toBe(key);
        expect(validateNotification(event)).toEqual(event);
        const handler = registry[key as NotificationEventKey];
        expect(handler).toBeTypeOf('function');
        await handler(event, { signal: new AbortController().signal });
        await expect(outbox.complete(eventId, event.leaseGeneration)).resolves.toEqual({
          applied: true,
        });
      } catch {
        failures.push(key);
        await admin.query(
          `UPDATE openarc_durable.outbox_events
              SET state = 'completed', lease_until = NULL, completed_at = clock_timestamp()
            WHERE event_id = $1`,
          [eventId],
        );
      }
    }
    expect(failures).toEqual([]);
  });
});

describe('worker consumes a real authorization-grant event without jamming the queue', () => {
  it(
    'claims and acks control.grant.issued from the real issue transaction and the event after it',
    async () => {
      const seed = 96;
      const chain = await seedActionChain(seed, 'none');
      const action = commerceActionId(seed * 10 + 1);
      const requirement = await seedActionRequirement(chain, seed * 10 + 1);
      const authorizeMutation = actionMutationId(seed, 11);
      const authorized = await migrator.query<{ out_status: string }>(
        AUTHORIZE_CORE_SQL,
        authorizeParams(chain, requirement, action, authorizeMutation, actionKey(seed, 11)),
      );
      expect(authorized.rows[0]).toMatchObject({ out_status: 'reserved_not_granted' });

      // ---- real grant issue (schema12 reviewed internal_fixture seam) --------
      const grantMutation = actionMutationId(seed, 31);
      const issued = await migrator.query<{ out_grant_id: string; out_status: string }>(
        `SELECT * FROM openarc_durable.issue_authorization_grant_core(
           'internal_fixture', $1, $2, $3, 1, $4::uuid, $5, $6, $7)`,
        [
          chain.commerceTokenHash,
          action,
          digestCommerceGrantToken(`oag_v1_${'A'.repeat(43)}`),
          grantMutation,
          'b'.repeat(64),
          'c'.repeat(64),
          'd'.repeat(64),
        ],
      );
      expect(issued.rows[0]).toMatchObject({ out_status: 'issued' });
      const grant = issued.rows[0]?.out_grant_id ?? '';
      expect(grant).toBe(`openarc:grant:${grantMutation}`);
      // Written by the issue transaction itself, not a separate insert.
      expect(await outboxTxn('control.grant.issued', grant)).toBe(
        await txnOf(
          'SELECT xmin::text AS value FROM openarc_durable.authorization_grants WHERE grant_id = $1',
          [grant],
        ),
      );

      // ---- an ordinary event committed AFTER the grant event -----------------
      const following = await store.createAgentDurably(chain.owner.hash, chain.owner.org, 'After Grant', {
        idempotencyKey: base64Key(9_600),
        mutationId: mutationId(9_600),
      });
      const followingAgent = following.receipt.resourceId;

      await outbox.initialize();
      const claimedRows: ClaimedOutboxEvent[] = [];
      const records: WorkerLogRecord[] = [];
      await runWorkerLoop(recordingOutbox(outbox, claimedRows), createHandlerRegistry(), records);

      expect(records.some((record) => record.status === 'claim_error')).toBe(false);
      expect(records.some((record) => record.status === 'failed')).toBe(false);
      const grantIndex = claimedRows.findIndex(
        (event) => event.resourceType === 'authorization_grant' && event.resourceId === grant,
      );
      const followingIndex = claimedRows.findIndex(
        (event) => event.eventType === 'tenant.agent.created' && event.resourceId === followingAgent,
      );
      expect(grantIndex).toBeGreaterThanOrEqual(0);
      expect(claimedRows[grantIndex]?.eventType).toBe('control.grant.issued');
      expect(followingIndex).toBeGreaterThan(grantIndex);
      expect(
        records.filter((record) => record.status === 'completed' && record.eventType === 'control.grant.issued'),
      ).toHaveLength(1);

      // The whole durable queue, grant event and the event after it included,
      // is acknowledged: nothing is left pending, leased or dead-lettered.
      const states = await admin.query<{ event_type: string; resource_id: string; state: string }>(
        'SELECT event_type, resource_id, state FROM openarc_durable.outbox_events',
      );
      expect(states.rows.filter((row) => row.state !== 'completed')).toEqual([]);
      expect(states.rows).toEqual(
        expect.arrayContaining([
          { event_type: 'control.grant.issued', resource_id: grant, state: 'completed' },
          { event_type: 'tenant.agent.created', resource_id: followingAgent, state: 'completed' },
        ]),
      );
    },
    60_000,
  );
});
