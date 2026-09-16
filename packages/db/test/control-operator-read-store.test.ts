import { describe, expect, it } from 'vitest';
import {
  ControlActionReadStore,
  ControlActionReadStoreError,
  ControlGrantStore,
  ControlGrantStoreError,
  CONTROL_GRANT_LIST_DEFAULT_LIMIT,
  CONTROL_GRANT_LIST_MAX_LIMIT,
  OPERATOR_QUEUE_DEFAULT_ATTEMPT_MAX_AGE_SECONDS,
  OPERATOR_QUEUE_DEFAULT_GRANT_EXPIRY_WINDOW_SECONDS,
  OPERATOR_QUEUE_KINDS,
  OPERATOR_QUEUE_MAX_WINDOW_SECONDS,
  type TenantClient,
  type TenantPool,
  type TenantQueryResult,
} from '../src/index.js';

/**
 * Driver-level unit regressions for the schema18 operator control-room reads.
 *
 * The scripted client proves the canonical input grammar, the store-applied
 * defaults, the limit + 1 fetch, the composite queue cursor rule, the
 * DB-derived organization binding, the exact-integer amount grammar and the
 * fixed non-echoing error vocabulary without a database. Every amount below is
 * compared as a string: no assertion here or in the store admits a float.
 */

type Row = Record<string, unknown>;

interface Route {
  readonly when: (text: string) => boolean;
  readonly rows?: Row[];
  readonly throws?: { readonly code?: string; readonly message?: string };
}

class FakeClient implements TenantClient {
  readonly calls: { text: string; values: unknown[] }[] = [];
  readonly releases: boolean[] = [];
  constructor(private readonly routes: Route[]) {}
  async query<T extends Record<string, unknown>>(
    text: string,
    values: unknown[] = [],
  ): Promise<TenantQueryResult<T>> {
    this.calls.push({ text, values });
    const route = this.routes.find((candidate) => candidate.when(text));
    if (route?.throws !== undefined) {
      const error = new Error(route.throws.message ?? 'scripted failure');
      if (route.throws.code !== undefined) (error as { code?: string }).code = route.throws.code;
      throw error;
    }
    const rows = (route?.rows ?? []) as T[];
    return { rows, rowCount: route?.rows === undefined ? null : rows.length };
  }
  release(destroy?: boolean): void {
    this.releases.push(destroy === true);
  }
}

class FakePool implements TenantPool {
  connectCalls = 0;
  readonly clients: FakeClient[] = [];
  constructor(private readonly make: () => FakeClient) {}
  async connect(): Promise<TenantClient> {
    this.connectCalls += 1;
    const client = this.make();
    this.clients.push(client);
    return client;
  }
}

const HASH = 'a'.repeat(64);
const ORG = 'openarc:org:00000000-0000-4000-8000-000000000001';
const OTHER_ORG = 'openarc:org:00000000-0000-4000-8000-0000000000ff';
const AGENT = 'openarc:agent:00000000-0000-4000-8000-000000000002';
const POLICY = 'openarc:policy:00000000-0000-4000-8000-000000000003';
const AS_OF = '2025-01-01 00:00:00.000000+00';

function uuid(seed: number): string {
  return `00000000-0000-4000-8000-${String(seed).padStart(12, '0')}`;
}

function actionId(seed: number): string {
  return `openarc:action:${uuid(seed)}`;
}

function reservationId(seed: number): string {
  return `openarc:reservation:${uuid(seed)}`;
}

function grantId(seed: number): string {
  return `openarc:grant:${uuid(seed)}`;
}

const isBuckets = (text: string): boolean => text.includes('read_commerce_exposure_buckets');
const isQueue = (text: string): boolean => text.includes('list_operator_stuck_queue');
const isGrantList = (text: string): boolean => text.includes('list_authorization_grants');
const isTx = (text: string): boolean =>
  text === 'BEGIN' || text === 'COMMIT' || text === 'ROLLBACK';

function bucketRow(overrides: Row = {}): Row {
  return {
    out_organization_id: ORG,
    out_found: true,
    out_subject_agent_id: AGENT,
    out_policy_id: POLICY,
    out_policy_revision: '1',
    out_network_id: 'eip155:5042002',
    out_asset: 'USDC',
    out_representation: 'erc20',
    out_decimals: 6,
    out_window_seconds: '3600',
    out_held_atomic: '1000000',
    out_claimed_atomic: '2000000',
    out_unknown_atomic: '3000000',
    out_committed_atomic: '4000000',
    out_policy_expires_at: AS_OF,
    out_as_of: AS_OF,
    ...overrides,
  };
}

function queueRow(kind: string, entry: string, overrides: Row = {}): Row {
  return {
    out_organization_id: ORG,
    out_found: true,
    out_kind: kind,
    out_entry_id: entry,
    out_status: kind === 'budget_reservation' ? 'unknown' : kind === 'payment_attempt' ? 'pending' : 'issued',
    out_subject_agent_id: AGENT,
    out_action_id: actionId(9),
    out_amount_atomic: '1000000',
    out_started_at: AS_OF,
    out_expires_at: kind === 'authorization_grant' ? AS_OF : null,
    out_as_of: AS_OF,
    ...overrides,
  };
}

function grantRow(id: string, overrides: Row = {}): Row {
  return {
    out_found: true,
    out_organization_id: ORG,
    out_grant_id: id,
    out_action_id: actionId(9),
    out_reservation_id: reservationId(9),
    out_subject_agent_id: AGENT,
    out_commerce_session_id: uuid(7),
    out_provider_id: `openarc:provider:${uuid(5)}`,
    out_listing_id: `openarc:listing:${uuid(6)}`,
    out_listing_version: '1',
    out_generation: '1',
    out_status: 'issued',
    out_issued_at: AS_OF,
    out_updated_at: AS_OF,
    out_expires_at: '2025-01-01 00:04:00.000000+00',
    out_claimed_at: null,
    out_revoked_at: null,
    ...overrides,
  };
}

function readStore(routes: Route[]): {
  store: ControlActionReadStore; pool: FakePool;
} {
  const pool = new FakePool(() => new FakeClient(routes));
  return { store: new ControlActionReadStore(pool), pool };
}

function grantStore(routes: Route[]): { store: ControlGrantStore; pool: FakePool } {
  const pool = new FakePool(() => new FakeClient(routes));
  return { store: new ControlGrantStore(pool), pool };
}

async function expectReadCode(promise: Promise<unknown>, code: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ControlActionReadStoreError);
    expect((error as ControlActionReadStoreError).code).toBe(code);
    return;
  }
  throw new Error(`expected ControlActionReadStoreError ${code}`);
}

async function expectGrantCode(promise: Promise<unknown>, code: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ControlGrantStoreError);
    expect((error as ControlGrantStoreError).code).toBe(code);
    return;
  }
  throw new Error(`expected ControlGrantStoreError ${code}`);
}

describe('schema18 accepted constants', () => {
  it('freezes the queue kinds and both window ceilings', () => {
    expect([...OPERATOR_QUEUE_KINDS]).toEqual([
      'authorization_grant', 'budget_reservation', 'payment_attempt',
    ]);
    expect(OPERATOR_QUEUE_MAX_WINDOW_SECONDS).toBe(2592000);
    expect(OPERATOR_QUEUE_DEFAULT_ATTEMPT_MAX_AGE_SECONDS).toBe(900);
    expect(OPERATOR_QUEUE_DEFAULT_GRANT_EXPIRY_WINDOW_SECONDS).toBe(900);
    expect(CONTROL_GRANT_LIST_DEFAULT_LIMIT).toBe(25);
    expect(CONTROL_GRANT_LIST_MAX_LIMIT).toBe(50);
  });
});

describe('four-bucket exposure read', () => {
  it('projects four separate exact integer buckets and no sum of them', async () => {
    const { store } = readStore([
      { when: isTx }, { when: isBuckets, rows: [bucketRow()] },
    ]);
    const detail = await store.readExposureBuckets(HASH, ORG, AGENT, POLICY);
    expect(detail.item).toEqual({
      organizationId: ORG,
      subjectAgentId: AGENT,
      policyId: POLICY,
      policyRevision: '1',
      networkId: 'eip155:5042002',
      asset: 'USDC',
      representation: 'erc20',
      decimals: 6,
      windowSeconds: '3600',
      heldAtomic: '1000000',
      claimedAtomic: '2000000',
      unknownAtomic: '3000000',
      committedAtomic: '4000000',
      policyExpiresAt: '2025-01-01T00:00:00.000000Z',
      asOf: '2025-01-01T00:00:00.000000Z',
    });
    // Every amount is a string: no float, and no total field exists.
    for (const value of [
      detail.item?.heldAtomic, detail.item?.claimedAtomic,
      detail.item?.unknownAtomic, detail.item?.committedAtomic,
    ]) {
      expect(typeof value).toBe('string');
    }
    expect(Object.keys(detail.item ?? {})).not.toContain('totalAtomic');
    expect(Object.keys(detail.item ?? {})).not.toContain('unresolvedAtomic');
  });

  it('returns a safe not-found that still carries the DB-derived organization', async () => {
    const { store } = readStore([
      { when: isTx },
      {
        when: isBuckets,
        rows: [{
          out_organization_id: ORG, out_found: false, out_as_of: AS_OF,
          out_subject_agent_id: null, out_policy_id: null, out_policy_revision: null,
          out_network_id: null, out_asset: null, out_representation: null, out_decimals: null,
          out_window_seconds: null, out_held_atomic: null, out_claimed_atomic: null,
          out_unknown_atomic: null, out_committed_atomic: null, out_policy_expires_at: null,
        }],
      },
    ]);
    expect(await store.readExposureBuckets(HASH, ORG, AGENT, POLICY)).toEqual({
      organizationId: ORG, subjectAgentId: AGENT, policyId: POLICY, item: null,
    });
  });

  it('refuses a malformed hash, organization, agent or policy before any query', async () => {
    const { store, pool } = readStore([{ when: isTx }, { when: isBuckets, rows: [bucketRow()] }]);
    for (const args of [
      ['nope', ORG, AGENT, POLICY], [`${HASH}\n`, ORG, AGENT, POLICY],
      [HASH, 'openarc:org:nope', AGENT, POLICY], [HASH, `${ORG}\n`, AGENT, POLICY],
      [HASH, ORG, 'openarc:agent:nope', POLICY], [HASH, ORG, `${AGENT}\n`, POLICY],
      [HASH, ORG, AGENT, 'openarc:policy:nope'], [HASH, ORG, AGENT, `${POLICY}\n`],
      [HASH, ORG, AGENT, 42 as unknown as string],
    ] as const) {
      await expectReadCode(
        store.readExposureBuckets(...(args as [string, string, string, string])),
        'CONTROL_ACTION_READ_STORE_INPUT_INVALID',
      );
    }
    expect(pool.connectCalls).toBe(0);
  });

  it('collapses a foreign organization, a wrong identity and a malformed bucket to UNAVAILABLE', async () => {
    for (const row of [
      bucketRow({ out_organization_id: OTHER_ORG }),
      bucketRow({ out_network_id: 'eip155:1' }),
      bucketRow({ out_asset: 'USDT' }),
      bucketRow({ out_representation: 'native' }),
      bucketRow({ out_decimals: 18 }),
      bucketRow({ out_unknown_atomic: '-1' }),
      bucketRow({ out_unknown_atomic: 3000000 }),
      bucketRow({ out_held_atomic: '01' }),
      bucketRow({ out_committed_atomic: '1000000\n' }),
      bucketRow({ out_policy_revision: '0' }),
      bucketRow({ out_window_seconds: '2592001' }),
      bucketRow({ out_subject_agent_id: `openarc:agent:${uuid(99)}` }),
      bucketRow({ out_found: 'yes' }),
    ]) {
      const { store } = readStore([{ when: isTx }, { when: isBuckets, rows: [row] }]);
      await expectReadCode(
        store.readExposureBuckets(HASH, ORG, AGENT, POLICY),
        'CONTROL_ACTION_READ_STORE_UNAVAILABLE',
      );
    }
    // Zero or two rows is never a valid answer for a single-row read.
    for (const rows of [[], [bucketRow(), bucketRow()]]) {
      const { store } = readStore([{ when: isTx }, { when: isBuckets, rows }]);
      await expectReadCode(
        store.readExposureBuckets(HASH, ORG, AGENT, POLICY),
        'CONTROL_ACTION_READ_STORE_UNAVAILABLE',
      );
    }
  });

  it('maps the fail-closed completeness bound to UNAVAILABLE, never to a partial answer', async () => {
    const { store } = readStore([
      { when: isTx }, { when: isBuckets, throws: { code: 'P0D11' } },
    ]);
    await expectReadCode(
      store.readExposureBuckets(HASH, ORG, AGENT, POLICY),
      'CONTROL_ACTION_READ_STORE_UNAVAILABLE',
    );
  });

  it('maps the fixed authority vocabulary', async () => {
    for (const [code, expected] of [
      ['28000', 'CONTROL_ACTION_READ_STORE_SESSION_INVALID'],
      ['42501', 'CONTROL_ACTION_READ_STORE_FORBIDDEN'],
      ['22023', 'CONTROL_ACTION_READ_STORE_INPUT_INVALID'],
      ['22003', 'CONTROL_ACTION_READ_STORE_INPUT_INVALID'],
    ] as const) {
      const { store } = readStore([{ when: isTx }, { when: isBuckets, throws: { code } }]);
      await expectReadCode(store.readExposureBuckets(HASH, ORG, AGENT, POLICY), expected);
    }
  });
});

describe('stuck queue', () => {
  it('applies the store-side defaults and the limit + 1 fetch', async () => {
    const { store, pool } = readStore([
      { when: isTx },
      { when: isQueue, rows: [queueRow('budget_reservation', reservationId(1))] },
    ]);
    const page = await store.listStuckQueue(HASH, ORG);
    expect(page.organizationId).toBe(ORG);
    expect(page.nextCursor).toBeNull();
    expect(page.asOf).toBe('2025-01-01T00:00:00.000000Z');
    const call = pool.clients[0]?.calls.find((entry) => isQueue(entry.text));
    expect(call?.values).toEqual([
      HASH, ORG,
      OPERATOR_QUEUE_DEFAULT_ATTEMPT_MAX_AGE_SECONDS,
      OPERATOR_QUEUE_DEFAULT_GRANT_EXPIRY_WINDOW_SECONDS,
      null, null,
      25,
    ]);
  });

  it('returns the last pair as the cursor only when a further page exists', async () => {
    const rows = [
      queueRow('budget_reservation', reservationId(1)),
      queueRow('budget_reservation', reservationId(2)),
      queueRow('budget_reservation', reservationId(3)),
    ];
    const { store } = readStore([{ when: isTx }, { when: isQueue, rows }]);
    const page = await store.listStuckQueue(HASH, ORG, { limit: '2' });
    expect(page.items.map((item) => item.entryId)).toEqual([reservationId(1), reservationId(2)]);
    expect(page.nextCursor).toEqual({ kind: 'budget_reservation', entryId: reservationId(2) });

    const { store: exact } = readStore([{ when: isTx }, { when: isQueue, rows: rows.slice(0, 2) }]);
    const full = await exact.listStuckQueue(HASH, ORG, { limit: '2' });
    expect(full.nextCursor).toBeNull();
  });

  it('accepts the canonical windows and cursor and sends them verbatim', async () => {
    const { store, pool } = readStore([
      { when: isTx },
      { when: isQueue, rows: [queueRow('payment_attempt', uuid(4))] },
    ]);
    await store.listStuckQueue(HASH, ORG, {
      attemptMaxAgeSeconds: '0',
      grantExpiryWindowSeconds: '2592000',
      afterKind: 'authorization_grant',
      afterEntryId: grantId(2),
      limit: '50',
    });
    const call = pool.clients[0]?.calls.find((entry) => isQueue(entry.text));
    expect(call?.values).toEqual([HASH, ORG, 0, 2592000, 'authorization_grant', grantId(2), 50]);
  });

  it('refuses a non-canonical window, a half cursor and a cursor id that contradicts its kind', async () => {
    const { store, pool } = readStore([{ when: isTx }, { when: isQueue, rows: [] }]);
    for (const query of [
      { attemptMaxAgeSeconds: '00' }, { attemptMaxAgeSeconds: '-1' },
      { attemptMaxAgeSeconds: ' 1' }, { attemptMaxAgeSeconds: '1\n' },
      { attemptMaxAgeSeconds: '2592001' },
      { attemptMaxAgeSeconds: 0 as unknown as string },
      { grantExpiryWindowSeconds: '2592001' }, { grantExpiryWindowSeconds: '01' },
      { afterKind: 'budget_reservation' },
      { afterEntryId: reservationId(1) },
      { afterKind: 'commerce_action', afterEntryId: reservationId(1) },
      { afterKind: 'budget_reservation', afterEntryId: grantId(1) },
      { afterKind: 'payment_attempt', afterEntryId: reservationId(1) },
      { afterKind: 'authorization_grant', afterEntryId: uuid(1) },
      { afterKind: 'budget_reservation', afterEntryId: `${reservationId(1)}\n` },
      { limit: '0' }, { limit: '51' }, { limit: '05' },
      { unexpected: '1' } as unknown as Record<string, string>,
      Object.assign(Object.create({ inherited: 1 }), { limit: '5' }) as Record<string, string>,
    ]) {
      await expectReadCode(
        store.listStuckQueue(HASH, ORG, query),
        'CONTROL_ACTION_READ_STORE_INPUT_INVALID',
      );
    }
    expect(pool.connectCalls).toBe(0);
  });

  it('collapses a mislabeled, out-of-order or foreign queue row to UNAVAILABLE', async () => {
    const cases: Row[][] = [
      // A status that does not belong to the kind it claims.
      [queueRow('budget_reservation', reservationId(1), { out_status: 'held' })],
      [queueRow('payment_attempt', uuid(1), { out_status: 'persisted' })],
      [queueRow('authorization_grant', grantId(1), { out_status: 'claimed' })],
      // An id shape that does not belong to the kind it claims.
      [queueRow('payment_attempt', reservationId(1))],
      [queueRow('budget_reservation', uuid(1))],
      // An unknown kind.
      [queueRow('commerce_action', actionId(1))],
      // An expiry on a source that has none, or a missing grant expiry.
      [queueRow('budget_reservation', reservationId(1), { out_expires_at: AS_OF })],
      [queueRow('authorization_grant', grantId(1), { out_expires_at: null })],
      // A non-integer or zero amount.
      [queueRow('budget_reservation', reservationId(1), { out_amount_atomic: '0' })],
      [queueRow('budget_reservation', reservationId(1), { out_amount_atomic: '1.5' })],
      [queueRow('budget_reservation', reservationId(1), { out_amount_atomic: 1000000 })],
      // Rows that disagree about the organization or the read instant.
      [
        queueRow('budget_reservation', reservationId(1)),
        queueRow('budget_reservation', reservationId(2), { out_organization_id: OTHER_ORG }),
      ],
      [
        queueRow('budget_reservation', reservationId(1)),
        queueRow('budget_reservation', reservationId(2), { out_as_of: '2025-01-01 00:00:01.000000+00' }),
      ],
      // A page that is not strictly ascending.
      [
        queueRow('budget_reservation', reservationId(2)),
        queueRow('budget_reservation', reservationId(1)),
      ],
      [
        queueRow('payment_attempt', uuid(1)),
        queueRow('authorization_grant', grantId(1)),
      ],
      // A sentinel mixed into a real page, and an over-long page.
      [
        queueRow('budget_reservation', reservationId(1)),
        queueRow('budget_reservation', reservationId(2), { out_found: false }),
      ],
      [],
    ];
    for (const rows of cases) {
      const { store } = readStore([{ when: isTx }, { when: isQueue, rows }]);
      await expectReadCode(
        store.listStuckQueue(HASH, ORG, { limit: '2' }),
        'CONTROL_ACTION_READ_STORE_UNAVAILABLE',
      );
    }
    const tooMany = [
      queueRow('budget_reservation', reservationId(1)),
      queueRow('budget_reservation', reservationId(2)),
      queueRow('budget_reservation', reservationId(3)),
      queueRow('budget_reservation', reservationId(4)),
    ];
    const { store } = readStore([{ when: isTx }, { when: isQueue, rows: tooMany }]);
    await expectReadCode(
      store.listStuckQueue(HASH, ORG, { limit: '2' }),
      'CONTROL_ACTION_READ_STORE_UNAVAILABLE',
    );
  });

  it('returns an empty page for the authorized sentinel row', async () => {
    const { store } = readStore([
      { when: isTx },
      {
        when: isQueue,
        rows: [{
          out_organization_id: ORG, out_found: false, out_kind: null, out_entry_id: null,
          out_status: null, out_subject_agent_id: null, out_action_id: null,
          out_amount_atomic: null, out_started_at: null, out_expires_at: null, out_as_of: AS_OF,
        }],
      },
    ]);
    const page = await store.listStuckQueue(HASH, ORG, { limit: '10' });
    expect(page).toEqual({
      organizationId: ORG, items: [], nextCursor: null, asOf: '2025-01-01T00:00:00.000000Z',
    });
  });
});

describe('organization-wide grant page', () => {
  it('applies the default limit and the limit + 1 fetch', async () => {
    const { store, pool } = grantStore([
      { when: isTx }, { when: isGrantList, rows: [grantRow(grantId(1))] },
    ]);
    const page = await store.listGrants(HASH, ORG);
    expect(page.organizationId).toBe(ORG);
    expect(page.items.map((item) => item.grantId)).toEqual([grantId(1)]);
    expect(page.nextCursor).toBeNull();
    const call = pool.clients[0]?.calls.find((entry) => isGrantList(entry.text));
    expect(call?.values).toEqual([HASH, ORG, null, CONTROL_GRANT_LIST_DEFAULT_LIMIT]);
  });

  it('returns the last id as the cursor only when a further page exists', async () => {
    const rows = [grantRow(grantId(1)), grantRow(grantId(2)), grantRow(grantId(3))];
    const { store } = grantStore([{ when: isTx }, { when: isGrantList, rows }]);
    const page = await store.listGrants(HASH, ORG, { limit: '2' });
    expect(page.items.map((item) => item.grantId)).toEqual([grantId(1), grantId(2)]);
    expect(page.nextCursor).toBe(grantId(2));
  });

  it('refuses a non-canonical limit or cursor before any query', async () => {
    const { store, pool } = grantStore([{ when: isTx }, { when: isGrantList, rows: [] }]);
    for (const query of [
      { limit: '0' }, { limit: '51' }, { limit: '05' }, { limit: ' 5' }, { limit: '5\n' },
      { limit: 5 as unknown as string },
      { afterGrantId: 'openarc:grant:nope' }, { afterGrantId: `${grantId(1)}\n` },
      { afterGrantId: reservationId(1) },
      { unexpected: '1' } as unknown as Record<string, string>,
    ]) {
      await expectGrantCode(
        store.listGrants(HASH, ORG, query),
        'CONTROL_GRANT_STORE_INPUT_INVALID',
      );
    }
    expect(pool.connectCalls).toBe(0);
  });

  it('collapses a foreign, out-of-order, cursor-violating or malformed page to UNAVAILABLE', async () => {
    const cases: { rows: Row[]; query?: Record<string, string> }[] = [
      { rows: [] },
      { rows: [grantRow(grantId(1), { out_organization_id: OTHER_ORG })] },
      { rows: [grantRow(grantId(2)), grantRow(grantId(1))] },
      { rows: [grantRow(grantId(1)), grantRow(grantId(1))] },
      { rows: [grantRow(grantId(1)), grantRow(grantId(2), { out_found: false })] },
      { rows: [grantRow(grantId(1), { out_generation: '0' })] },
      { rows: [grantRow(grantId(1), { out_generation: 1 })] },
      { rows: [grantRow(grantId(1), { out_status: 'nope' })] },
      // The cursor must be strictly below every returned id.
      { rows: [grantRow(grantId(1))], query: { afterGrantId: grantId(1) } },
      { rows: [grantRow(grantId(1))], query: { afterGrantId: grantId(2) } },
    ];
    for (const entry of cases) {
      const { store } = grantStore([{ when: isTx }, { when: isGrantList, rows: entry.rows }]);
      await expectGrantCode(
        store.listGrants(HASH, ORG, { limit: '5', ...entry.query }),
        'CONTROL_GRANT_STORE_UNAVAILABLE',
      );
    }
  });

  it('returns an empty page for the authorized sentinel row', async () => {
    const { store } = grantStore([
      { when: isTx },
      {
        when: isGrantList,
        rows: [{
          out_found: false, out_organization_id: ORG, out_grant_id: null, out_action_id: null,
          out_reservation_id: null, out_subject_agent_id: null, out_commerce_session_id: null,
          out_provider_id: null, out_listing_id: null, out_listing_version: null,
          out_generation: null, out_status: null, out_issued_at: null, out_updated_at: null,
          out_expires_at: null, out_claimed_at: null, out_revoked_at: null,
        }],
      },
    ]);
    expect(await store.listGrants(HASH, ORG, { limit: '10' })).toEqual({
      organizationId: ORG, items: [], nextCursor: null,
    });
  });

  it('maps the fixed authority vocabulary and never echoes driver detail', async () => {
    for (const [code, expected] of [
      ['28000', 'CONTROL_GRANT_STORE_SESSION_INVALID'],
      ['42501', 'CONTROL_GRANT_STORE_FORBIDDEN'],
      ['22023', 'CONTROL_GRANT_STORE_INPUT_INVALID'],
    ] as const) {
      const { store } = grantStore([{ when: isTx }, { when: isGrantList, throws: { code } }]);
      await expectGrantCode(store.listGrants(HASH, ORG, { limit: '5' }), expected);
    }
    const { store } = grantStore([
      { when: isTx },
      { when: isGrantList, throws: { code: '99999', message: 'openarc:grant:secret leaked' } },
    ]);
    try {
      await store.listGrants(HASH, ORG, { limit: '5' });
      throw new Error('expected a rejection');
    } catch (error) {
      expect((error as Error).message).not.toContain('secret');
    }
  });
});
