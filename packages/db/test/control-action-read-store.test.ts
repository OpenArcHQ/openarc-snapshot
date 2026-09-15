import { describe, expect, it } from 'vitest';
import {
  CONTROL_ACTION_READ_DEFAULT_LIMIT,
  CONTROL_ACTION_READ_MAX_LIMIT,
  CONTROL_ACTION_READ_STORE_ERROR_MESSAGES,
  ControlActionReadStore,
  ControlActionReadStoreError,
  asControlActionReadPool,
  type TenantClient,
  type TenantPool,
  type TenantQueryResult,
} from '../src/index.js';

/**
 * Driver-level unit regressions for the DB11 read store. The scripted client
 * proves the canonical input grammar, the store-applied default limit, the
 * limit + 1 fetch, the cursor rule, the DB-derived organization binding and the
 * fixed non-echoing error vocabulary without a database.
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
const SESSION = '00000000-0000-4000-8000-000000000004';
const PROVIDER = 'openarc:provider:00000000-0000-4000-8000-000000000007';
const LISTING = 'openarc:listing:00000000-0000-4000-8000-000000000008';
const REQUIREMENT = 'openarc:requirement:00000000-0000-4000-8000-000000000009';
const ACCOUNT = 'openarc:account:00000000-0000-4000-8000-00000000000a';
const DIGEST = `sha256:${'a'.repeat(64)}`;

function uuid(seed: number): string {
  return `00000000-0000-4000-8000-${String(seed).padStart(12, '0')}`;
}

function actionId(seed: number): string {
  return `openarc:action:${uuid(seed)}`;
}

function approvalId(seed: number): string {
  return `openarc:approval:${uuid(seed)}`;
}

function reservationId(seed: number): string {
  return `openarc:reservation:${uuid(seed)}`;
}

function actionRow(seed: number, overrides: Row = {}): Row {
  return {
    out_organization_id: ORG,
    out_found: true,
    out_action_id: actionId(seed),
    out_subject_agent_id: AGENT,
    out_commerce_session_id: SESSION,
    out_status: 'reserved_not_granted',
    out_policy_id: POLICY,
    out_policy_revision: '1',
    out_provider_id: PROVIDER,
    out_listing_id: LISTING,
    out_listing_version: '1',
    out_requirement_id: REQUIREMENT,
    out_requirement_digest: DIGEST,
    out_network_id: 'eip155:5042002',
    out_asset: 'USDC',
    out_representation: 'erc20',
    out_decimals: 6,
    out_amount_atomic: '100',
    out_fee_atomic: '5',
    out_debit_atomic: '105',
    out_reservation_id: reservationId(seed),
    out_approval_id: null,
    out_created_at: '2026-09-12 10:00:00.000000+00',
    out_updated_at: '2026-09-12 10:00:00.000000+00',
    out_expires_at: '2026-09-12 10:05:00.000000+00',
    ...overrides,
  };
}

function approvalRow(seed: number, overrides: Row = {}): Row {
  return {
    out_organization_id: ORG,
    out_found: true,
    out_approval_id: approvalId(seed),
    out_action_id: actionId(seed),
    out_subject_agent_id: AGENT,
    out_commerce_session_id: SESSION,
    out_status: 'pending',
    out_policy_id: POLICY,
    out_policy_revision: '1',
    out_requested_by: ACCOUNT,
    out_separate_approver: false,
    out_decided_by: null,
    out_created_at: '2026-09-12 10:00:00.000000+00',
    out_expires_at: '2026-09-12 10:05:00.000000+00',
    out_decided_at: null,
    ...overrides,
  };
}

function emptyActionRow(organization = ORG): Row {
  const row = actionRow(1);
  for (const key of Object.keys(row)) row[key] = null;
  row['out_organization_id'] = organization;
  row['out_found'] = false;
  return row;
}

function emptyApprovalRow(organization = ORG): Row {
  const row = approvalRow(1);
  for (const key of Object.keys(row)) row[key] = null;
  row['out_organization_id'] = organization;
  row['out_found'] = false;
  return row;
}

function storeWith(routes: Route[]): { store: ControlActionReadStore; pool: FakePool } {
  const pool = new FakePool(() => new FakeClient(routes));
  return { store: new ControlActionReadStore(pool), pool };
}

function actionsStore(rows: Row[]): { store: ControlActionReadStore; pool: FakePool } {
  return storeWith([{ when: (text) => text.includes('list_commerce_actions'), rows }]);
}

function approvalsStore(rows: Row[]): { store: ControlActionReadStore; pool: FakePool } {
  return storeWith([{ when: (text) => text.includes('list_commerce_approvals'), rows }]);
}

function detailStore(rows: Row[]): { store: ControlActionReadStore; pool: FakePool } {
  return storeWith([{ when: (text) => text.includes('read_commerce_approval_by_id'), rows }]);
}

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ControlActionReadStoreError);
    expect((error as ControlActionReadStoreError).code).toBe(code);
    return;
  }
  throw new Error(`expected ControlActionReadStoreError ${code}`);
}

describe('control action read store error vocabulary', () => {
  it('exposes fixed messages that never echo input', () => {
    for (const [code, message] of Object.entries(CONTROL_ACTION_READ_STORE_ERROR_MESSAGES)) {
      expect(message.startsWith('ControlActionReadStore')).toBe(true);
      expect(new ControlActionReadStoreError(
        code as keyof typeof CONTROL_ACTION_READ_STORE_ERROR_MESSAGES,
      ).message).toBe(message);
      expect(message).not.toContain('openarc:');
      expect(message).not.toContain('SELECT');
    }
    expect(CONTROL_ACTION_READ_DEFAULT_LIMIT).toBe(25);
    expect(CONTROL_ACTION_READ_MAX_LIMIT).toBe(50);
  });

  it('rejects a pool that cannot connect', () => {
    expect(() => new ControlActionReadStore({} as unknown as TenantPool)).toThrow(
      ControlActionReadStoreError,
    );
    expect(typeof asControlActionReadPool).toBe('function');
  });
});

describe('listActions input grammar', () => {
  it('rejects a malformed session hash, organization and query envelope', async () => {
    const { store } = actionsStore([emptyActionRow()]);
    for (const bad of ['', 'A'.repeat(64), `${HASH}\n`, 42, null]) {
      await expectCode(
        store.listActions(bad, ORG, {}),
        'CONTROL_ACTION_READ_STORE_INPUT_INVALID',
      );
    }
    for (const bad of ['openarc:org:nope', `${ORG}\n`, ORG.toUpperCase(), 7]) {
      await expectCode(
        store.listActions(HASH, bad, {}),
        'CONTROL_ACTION_READ_STORE_INPUT_INVALID',
      );
    }
    for (const bad of [[], 'x', 3, Object.create({ limit: '5' }) as object]) {
      await expectCode(
        store.listActions(HASH, ORG, bad),
        'CONTROL_ACTION_READ_STORE_INPUT_INVALID',
      );
    }
    await expectCode(
      store.listActions(HASH, ORG, { unknown: '1' }),
      'CONTROL_ACTION_READ_STORE_INPUT_INVALID',
    );
    await expectCode(
      store.listActions(HASH, ORG, { limit: undefined }),
      'CONTROL_ACTION_READ_STORE_INPUT_INVALID',
    );
  });

  it('rejects every non-canonical limit and accepts the canonical bounds', async () => {
    const { store } = actionsStore([emptyActionRow()]);
    for (const bad of ['0', '51', '05', ' 5', '5 ', '5\n', '+5', '25.0', '1e1', 25, null, '']) {
      await expectCode(
        store.listActions(HASH, ORG, { limit: bad }),
        'CONTROL_ACTION_READ_STORE_INPUT_INVALID',
      );
      await expectCode(
        store.listApprovals(HASH, ORG, { limit: bad }),
        'CONTROL_ACTION_READ_STORE_INPUT_INVALID',
      );
    }
    for (const good of ['1', '9', '10', '49', '50']) {
      await expect(store.listActions(HASH, ORG, { limit: good })).resolves.toMatchObject({
        items: [],
        nextCursor: null,
      });
    }
  });

  it('rejects a malformed cursor on both queues', async () => {
    const { store } = actionsStore([emptyActionRow()]);
    for (const bad of ['', 'openarc:action:nope', `${actionId(1)}\n`, approvalId(1), 5]) {
      await expectCode(
        store.listActions(HASH, ORG, { afterActionId: bad }),
        'CONTROL_ACTION_READ_STORE_INPUT_INVALID',
      );
    }
    const approvals = approvalsStore([emptyApprovalRow()]);
    for (const bad of ['', 'openarc:approval:nope', `${approvalId(1)}\n`, actionId(1), 5]) {
      await expectCode(
        approvals.store.listApprovals(HASH, ORG, { afterApprovalId: bad }),
        'CONTROL_ACTION_READ_STORE_INPUT_INVALID',
      );
    }
  });

  it('applies the default limit 25 and fetches limit + 1 rows', async () => {
    const { store, pool } = actionsStore([emptyActionRow()]);
    await store.listActions(HASH, ORG);
    const call = pool.clients[0]?.calls.find((entry) =>
      entry.text.includes('list_commerce_actions'),
    );
    expect(call?.values).toEqual([HASH, ORG, null, 25]);
    const explicit = actionsStore([emptyActionRow()]);
    await explicit.store.listActions(HASH, ORG, { limit: '7', afterActionId: actionId(3) });
    expect(
      explicit.pool.clients[0]?.calls.find((entry) =>
        entry.text.includes('list_commerce_actions'),
      )?.values,
    ).toEqual([HASH, ORG, actionId(3), 7]);
  });
});

describe('listActions paging contract', () => {
  it('returns a null cursor when fewer than limit rows come back', async () => {
    const { store } = actionsStore([actionRow(1), actionRow(2)]);
    const page = await store.listActions(HASH, ORG, { limit: '5' });
    expect(page.items.map((item) => item.actionId)).toEqual([actionId(1), actionId(2)]);
    expect(page.nextCursor).toBeNull();
    expect(page.organizationId).toBe(ORG);
  });

  it('returns a null cursor when exactly limit rows come back and no more exist', async () => {
    const { store } = actionsStore([actionRow(1), actionRow(2)]);
    const page = await store.listActions(HASH, ORG, { limit: '2' });
    expect(page.items).toHaveLength(2);
    expect(page.nextCursor).toBeNull();
  });

  it('returns the last item id as the cursor only when a further page exists', async () => {
    const { store } = actionsStore([actionRow(1), actionRow(2), actionRow(3)]);
    const page = await store.listActions(HASH, ORG, { limit: '2' });
    expect(page.items.map((item) => item.actionId)).toEqual([actionId(1), actionId(2)]);
    expect(page.nextCursor).toBe(actionId(2));
  });

  it('returns an empty page with a null cursor for the authorized empty result', async () => {
    const { store } = actionsStore([emptyActionRow()]);
    const page = await store.listActions(HASH, ORG, { limit: '3' });
    expect(page).toEqual({ organizationId: ORG, items: [], nextCursor: null });
  });

  it('rejects a driver page that exceeds limit + 1, is empty or disagrees on organization', async () => {
    await expectCode(
      actionsStore([actionRow(1), actionRow(2), actionRow(3)]).store.listActions(HASH, ORG, {
        limit: '1',
      }),
      'CONTROL_ACTION_READ_STORE_UNAVAILABLE',
    );
    await expectCode(
      actionsStore([]).store.listActions(HASH, ORG, { limit: '5' }),
      'CONTROL_ACTION_READ_STORE_UNAVAILABLE',
    );
    await expectCode(
      actionsStore([
        actionRow(1),
        actionRow(2, { out_organization_id: OTHER_ORG }),
      ]).store.listActions(HASH, ORG, { limit: '5' }),
      'CONTROL_ACTION_READ_STORE_UNAVAILABLE',
    );
  });

  it('rejects a non-ascending, duplicated or mixed-found driver page', async () => {
    await expectCode(
      actionsStore([actionRow(3), actionRow(1)]).store.listActions(HASH, ORG, { limit: '5' }),
      'CONTROL_ACTION_READ_STORE_UNAVAILABLE',
    );
    await expectCode(
      actionsStore([actionRow(2), actionRow(2)]).store.listActions(HASH, ORG, { limit: '5' }),
      'CONTROL_ACTION_READ_STORE_UNAVAILABLE',
    );
    await expectCode(
      actionsStore([actionRow(1), emptyActionRow()]).store.listActions(HASH, ORG, {
        limit: '5',
      }),
      'CONTROL_ACTION_READ_STORE_UNAVAILABLE',
    );
  });

  it('projects the exact protected action key set and no private field', async () => {
    const { store } = actionsStore([actionRow(1)]);
    const page = await store.listActions(HASH, ORG, { limit: '5' });
    expect(Object.keys(page).sort()).toEqual(['items', 'nextCursor', 'organizationId']);
    const item = page.items[0];
    expect(item).toBeDefined();
    expect(Object.keys(item ?? {}).sort()).toEqual([
      'actionId',
      'amountAtomic',
      'approvalId',
      'commerceSessionId',
      'createdAt',
      'debitAtomic',
      'expiresAt',
      'exposureKey',
      'feeAtomic',
      'listingId',
      'listingVersion',
      'policyId',
      'policyRevision',
      'providerId',
      'requirementDigest',
      'requirementId',
      'reservationId',
      'schemaVersion',
      'status',
      'updatedAt',
    ]);
    const serialized = JSON.stringify(page);
    for (const secret of [
      'sourceKind',
      'source_kind',
      'requestDigest',
      'request_digest',
      'sellerOrganizationId',
      'seller_organization_id',
      'tokenHash',
      'credentialId',
      'agentSessionId',
      'parentHumanAccountId',
    ]) {
      expect(serialized).not.toContain(secret);
    }
  });

  it('collapses a malformed or money-lossy action row to the fixed unavailable error', async () => {
    for (const overrides of [
      { out_amount_atomic: '0' },
      { out_debit_atomic: '106' },
      { out_amount_atomic: 100 },
      { out_status: 'granted' },
      { out_decimals: 2 },
      { out_asset: 'ETH' },
      { out_expires_at: '2026-09-12 09:00:00.000000+00' },
      { out_created_at: 'not-a-timestamp' },
    ]) {
      await expectCode(
        actionsStore([actionRow(1, overrides)]).store.listActions(HASH, ORG, { limit: '5' }),
        'CONTROL_ACTION_READ_STORE_UNAVAILABLE',
      );
    }
  });

  it('keeps every canonical status visible with no hidden filter', async () => {
    const statuses = [
      'pending_approval',
      'reserved_not_granted',
      'rejected',
      'cancelled',
      'expired',
    ] as const;
    const rows = statuses.map((status, index) =>
      actionRow(index + 1, {
        out_status: status,
        out_reservation_id: status === 'pending_approval' || status === 'rejected'
          ? null
          : reservationId(index + 1),
        out_approval_id: status === 'reserved_not_granted' ? null : approvalId(index + 1),
      }),
    );
    const page = await actionsStore(rows).store.listActions(HASH, ORG, { limit: '10' });
    expect(page.items.map((item) => item.status)).toEqual([...statuses]);
  });
});

describe('listApprovals and readApprovalById', () => {
  it('pages approvals with the same cursor rule', async () => {
    const { store } = approvalsStore([approvalRow(1), approvalRow(2), approvalRow(3)]);
    const page = await store.listApprovals(HASH, ORG, { limit: '2' });
    expect(page.items.map((item) => item.approvalId)).toEqual([approvalId(1), approvalId(2)]);
    expect(page.nextCursor).toBe(approvalId(2));
    const shortPage = await approvalsStore([approvalRow(1)]).store.listApprovals(HASH, ORG, {
      limit: '2',
    });
    expect(shortPage.nextCursor).toBeNull();
    const empty = await approvalsStore([emptyApprovalRow()]).store.listApprovals(HASH, ORG);
    expect(empty).toEqual({ organizationId: ORG, items: [], nextCursor: null });
  });

  it('projects the exact protected approval key set', async () => {
    const page = await approvalsStore([approvalRow(1)]).store.listApprovals(HASH, ORG, {
      limit: '5',
    });
    expect(Object.keys(page.items[0] ?? {}).sort()).toEqual([
      'actionId',
      'approvalId',
      'commerceSessionId',
      'createdAt',
      'decidedAt',
      'decidedBy',
      'expiresAt',
      'organizationId',
      'policyId',
      'policyRevision',
      'requestedBy',
      'schemaVersion',
      'separateApprover',
      'status',
      'subjectAgentId',
    ]);
    expect(JSON.stringify(page)).not.toContain('source');
  });

  it('keeps every approval status visible', async () => {
    const statuses = ['pending', 'approved', 'rejected', 'expired'] as const;
    const rows = statuses.map((status, index) =>
      approvalRow(index + 1, {
        out_status: status,
        out_decided_by: status === 'approved' || status === 'rejected' ? ACCOUNT : null,
        out_decided_at:
          status === 'approved' || status === 'rejected'
            ? '2026-09-12 10:01:00.000000+00'
            : null,
      }),
    );
    const page = await approvalsStore(rows).store.listApprovals(HASH, ORG, { limit: '10' });
    expect(page.items.map((item) => item.status)).toEqual([...statuses]);
  });

  it('returns the bound approval detail, a null item and the DB-derived organization', async () => {
    const found = await detailStore([approvalRow(4)]).store.readApprovalById(
      HASH,
      ORG,
      approvalId(4),
    );
    expect(found.organizationId).toBe(ORG);
    expect(found.approvalId).toBe(approvalId(4));
    expect(found.item?.approvalId).toBe(approvalId(4));
    const missing = await detailStore([emptyApprovalRow()]).store.readApprovalById(
      HASH,
      ORG,
      approvalId(9),
    );
    expect(missing).toEqual({ organizationId: ORG, approvalId: approvalId(9), item: null });
  });

  it('rejects an unbound approval id, a foreign organization row and a bad row count', async () => {
    await expectCode(
      detailStore([approvalRow(4)]).store.readApprovalById(HASH, ORG, approvalId(5)),
      'CONTROL_ACTION_READ_STORE_UNAVAILABLE',
    );
    await expectCode(
      detailStore([approvalRow(4, { out_organization_id: OTHER_ORG })]).store.readApprovalById(
        HASH,
        ORG,
        approvalId(4),
      ),
      'CONTROL_ACTION_READ_STORE_UNAVAILABLE',
    );
    await expectCode(
      detailStore([approvalRow(4), approvalRow(5)]).store.readApprovalById(
        HASH,
        ORG,
        approvalId(4),
      ),
      'CONTROL_ACTION_READ_STORE_UNAVAILABLE',
    );
    await expectCode(
      detailStore([approvalRow(4, { out_found: 'yes' })]).store.readApprovalById(
        HASH,
        ORG,
        approvalId(4),
      ),
      'CONTROL_ACTION_READ_STORE_UNAVAILABLE',
    );
    await expectCode(
      detailStore([approvalRow(4)]).store.readApprovalById(HASH, ORG, actionId(4)),
      'CONTROL_ACTION_READ_STORE_INPUT_INVALID',
    );
  });
});

describe('transaction and driver-error discipline', () => {
  it('maps driver SQLSTATEs onto the fixed read-store codes', async () => {
    const cases: readonly [string, string][] = [
      ['28000', 'CONTROL_ACTION_READ_STORE_SESSION_INVALID'],
      ['42501', 'CONTROL_ACTION_READ_STORE_FORBIDDEN'],
      ['22023', 'CONTROL_ACTION_READ_STORE_INPUT_INVALID'],
      ['22P02', 'CONTROL_ACTION_READ_STORE_INPUT_INVALID'],
      ['23514', 'CONTROL_ACTION_READ_STORE_INPUT_INVALID'],
      ['XX000', 'CONTROL_ACTION_READ_STORE_UNAVAILABLE'],
    ];
    for (const [sqlstate, code] of cases) {
      const { store } = storeWith([
        {
          when: (text) => text.includes('list_commerce_actions'),
          throws: { code: sqlstate, message: `openarc:org leak ${sqlstate}` },
        },
      ]);
      await expectCode(store.listActions(HASH, ORG, { limit: '5' }), code);
    }
  });

  it('never echoes driver detail in the thrown message', async () => {
    const { store } = storeWith([
      {
        when: (text) => text.includes('list_commerce_approvals'),
        throws: { code: '42501', message: `secret ${ORG} detail` },
      },
    ]);
    try {
      await store.listApprovals(HASH, ORG, { limit: '5' });
      throw new Error('expected rejection');
    } catch (error) {
      expect(error).toBeInstanceOf(ControlActionReadStoreError);
      expect((error as Error).message).toBe(
        CONTROL_ACTION_READ_STORE_ERROR_MESSAGES.CONTROL_ACTION_READ_STORE_FORBIDDEN,
      );
      expect((error as Error).message).not.toContain(ORG);
    }
  });

  it('issues exactly one BEGIN, one projection and one COMMIT and writes nothing', async () => {
    const { store, pool } = actionsStore([actionRow(1)]);
    await store.listActions(HASH, ORG, { limit: '5' });
    const texts = pool.clients[0]?.calls.map((entry) => entry.text.trim()) ?? [];
    expect(texts[0]).toBe('BEGIN');
    expect(texts[texts.length - 1]).toBe('COMMIT');
    expect(texts.filter((text) => text.includes('list_commerce_actions'))).toHaveLength(1);
    for (const text of texts) {
      expect(/\b(INSERT|UPDATE|DELETE|TRUNCATE|FOR UPDATE)\b/i.test(text)).toBe(false);
    }
    expect(pool.clients[0]?.releases).toEqual([false]);
  });

  it('rolls back and releases on a projection failure', async () => {
    const { store, pool } = storeWith([
      { when: (text) => text.includes('list_commerce_actions'), throws: { code: '42501' } },
    ]);
    await expectCode(
      store.listActions(HASH, ORG, { limit: '5' }),
      'CONTROL_ACTION_READ_STORE_FORBIDDEN',
    );
    expect(pool.clients[0]?.calls.map((entry) => entry.text)).toContain('ROLLBACK');
    expect(pool.clients[0]?.releases).toEqual([false]);
  });

  it('reports a failed commit as unavailable, never as an unknown mutation outcome', async () => {
    const { store } = storeWith([
      { when: (text) => text.includes('list_commerce_actions'), rows: [actionRow(1)] },
      { when: (text) => text === 'COMMIT', throws: { code: '08006' } },
    ]);
    await expectCode(
      store.listActions(HASH, ORG, { limit: '5' }),
      'CONTROL_ACTION_READ_STORE_UNAVAILABLE',
    );
    expect(
      Object.keys(CONTROL_ACTION_READ_STORE_ERROR_MESSAGES),
    ).not.toContain('CONTROL_ACTION_READ_STORE_OUTCOME_UNKNOWN');
  });
});
