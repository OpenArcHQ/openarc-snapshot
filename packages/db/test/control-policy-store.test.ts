import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  ControlPolicyStore,
  ControlPolicyStoreError,
  POLICY_EVENT_BY_OPERATION,
  POLICY_RESOURCE_BY_OPERATION,
  digestPolicyContent,
  digestPolicyCreateRequest,
  digestPolicyIdempotencyKey,
  digestPolicyRevisionCreateRequest,
  digestPolicySessionContext,
  digestPolicyTransitionRequest,
  parsePolicyContent,
  parsePolicyId,
  parsePolicyOperation,
  parsePolicyRevisionNumber,
  parsePolicyAppendRevision,
  policyRevisionResourceId,
  requirePolicyTimestamp,
  type PolicyDigestContext,
  type TenantClient,
  type TenantPool,
  type TenantQueryResult,
} from '../src/index.js';


type Row = Record<string, unknown>;

interface Route {
  readonly when: (text: string) => boolean;
  readonly rows?: Row[];
  readonly throws?: { readonly code?: string; readonly message?: string };
}

class FakeClient implements TenantClient {
  readonly calls: { text: string; values: unknown[] }[] = [];
  readonly releases: boolean[] = [];
  releaseThrows = false;
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
    if (this.releaseThrows) throw new Error('release failed');
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
const AGENT = 'openarc:agent:00000000-0000-4000-8000-000000000002';
const POLICY = 'openarc:policy:00000000-0000-4000-8000-000000000003';
const MUTATION = '00000000-0000-4000-8000-000000000004';
const PROVIDER = 'openarc:provider:00000000-0000-4000-8000-000000000005';
const LISTING = 'openarc:listing:00000000-0000-4000-8000-000000000006';
const KEY = 'A'.repeat(42) + 'A';
const ORG_NL = `${ORG}\n`;
const POLICY_NL = `${POLICY}\n`;

function content(overrides: Row = {}): Row {
  return {
    organizationId: ORG,
    subjectAgentId: AGENT,
    networkId: 'eip155:5042002',
    asset: 'USDC',
    representation: 'erc20',
    decimals: 6,
    perActionLimit: '1000000',
    rollingLimit: '5000000',
    rollingWindowSeconds: '3600',
    feeLimit: '0',
    allowedProviderIds: [PROVIDER],
    allowedListingIds: [LISTING],
    approval: { mode: 'above', threshold: '1000000', separateApprover: true },
    expiresAt: '2027-01-01T00:00:00.000000Z',
    ...overrides,
  };
}

function receiptRow(operation: string, resourceType: string, resourceId: string, replayed = false): Row {
  return {
    out_replayed: replayed,
    out_mutation_id: MUTATION,
    out_operation: operation,
    out_resource_type: resourceType,
    out_resource_id: resourceId,
    out_committed_at: '2026-09-12 10:00:00.123456+00',
  };
}

function rootRow(overrides: Row = {}): Row {
  return {
    out_policy_id: POLICY,
    out_organization_id: ORG,
    out_subject_agent_id: AGENT,
    out_current_revision: '1',
    out_status: 'active',
    out_created_at: '2026-09-12 10:00:00.000001+00',
    out_updated_at: '2026-09-12 10:00:00.000002+00',
    ...overrides,
  };
}

function summaryRow(overrides: Row = {}): Row {
  return {
    out_policy_id: POLICY,
    out_organization_id: ORG,
    out_subject_agent_id: AGENT,
    out_revision: '1',
    out_digest: `sha256:${'a'.repeat(64)}`,
    out_created_at: '2026-09-12 10:00:00.000001+00',
    out_expires_at: null,
    ...overrides,
  };
}

function metadata(mutationId = MUTATION, idempotencyKey = KEY): Row {
  return { mutationId, idempotencyKey };
}

const WRITER_ROUTE: Route = {
  when: (text) => text.includes('lock_policy_writer'),
  rows: [{ out_actor: 'openarc:account:00000000-0000-4000-8000-0000000000aa' }],
};

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ControlPolicyStoreError);
    expect((error as ControlPolicyStoreError).code).toBe(code);
    return;
  }
  throw new Error(`expected ControlPolicyStoreError ${code}`);
}

describe('policy content digest determinism', () => {
  it('is stable across object key order and independent of any generated id', () => {
    const first = parsePolicyContent(content());
    const reordered = parsePolicyContent({
      expiresAt: '2027-01-01T00:00:00.000000Z',
      approval: { separateApprover: true, threshold: '1000000', mode: 'above' },
      allowedListingIds: [LISTING],
      allowedProviderIds: [PROVIDER],
      feeLimit: '0',
      rollingWindowSeconds: '3600',
      rollingLimit: '5000000',
      perActionLimit: '1000000',
      decimals: 6,
      representation: 'erc20',
      asset: 'USDC',
      networkId: 'eip155:5042002',
      subjectAgentId: AGENT,
      organizationId: ORG,
    });
    expect(digestPolicyContent(first)).toBe(digestPolicyContent(reordered));
    expect(digestPolicyContent(first)).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('changes when any bound content field changes', () => {
    const base = digestPolicyContent(parsePolicyContent(content()));
    const variants: Row[] = [
      { organizationId: 'openarc:org:00000000-0000-4000-8000-0000000000bb' },
      { subjectAgentId: 'openarc:agent:00000000-0000-4000-8000-0000000000bb' },
      { perActionLimit: '2' },
      { rollingLimit: null, rollingWindowSeconds: null },
      { feeLimit: '1' },
      { allowedProviderIds: [] },
      { allowedListingIds: [] },
      { approval: { mode: 'none', threshold: null, separateApprover: false } },
      { expiresAt: null },
    ];
    for (const override of variants) {
      expect(digestPolicyContent(parsePolicyContent(content(override)))).not.toBe(base);
    }
  });

  it('binds allowlist order (canonical arrays are sorted)', () => {
    const second = 'openarc:provider:00000000-0000-4000-8000-0000000000cc';
    const base = digestPolicyContent(
      parsePolicyContent(content({ allowedProviderIds: [PROVIDER] })),
    );
    const appended = digestPolicyContent(
      parsePolicyContent(content({ allowedProviderIds: [PROVIDER, second] })),
    );
    expect(appended).not.toBe(base);
    expect(() => parsePolicyContent(content({ allowedProviderIds: [second, PROVIDER] }))).toThrow();
  });
});

describe('policy request/session/key binding', () => {
  const operation = 'control.policy.create' as const;
  const context: PolicyDigestContext = {
    organizationId: ORG,
    actorAccountId: 'openarc:account:00000000-0000-4000-8000-0000000000aa',
    actorRole: 'policy_writer',
    sessionContextDigest: digestPolicySessionContext(operation, HASH),
    mutationId: MUTATION,
  };

  it('derives a distinct stable session context per operation', () => {
    expect(digestPolicySessionContext(operation, HASH)).toMatch(/^[0-9a-f]{64}$/);
    expect(digestPolicySessionContext(operation, HASH)).not.toBe(
      digestPolicySessionContext('control.policy.pause', HASH),
    );
  });

  it('derives a distinct stable idempotency key per operation', () => {
    expect(digestPolicyIdempotencyKey(operation, KEY)).toMatch(/^[0-9a-f]{64}$/);
    expect(digestPolicyIdempotencyKey(operation, KEY)).not.toBe(
      digestPolicyIdempotencyKey('control.policy.pause', KEY),
    );
  });

  it('binds actor, role, session, mutation and target', () => {
    const contentDigest = digestPolicyContent(parsePolicyContent(content()));
    const base = digestPolicyCreateRequest(context, parsePolicyContent(content()), contentDigest);
    expect(
      digestPolicyCreateRequest({ ...context, actorRole: 'other' }, parsePolicyContent(content()), contentDigest),
    ).not.toBe(base);
    expect(
      digestPolicyCreateRequest(
        { ...context, mutationId: '00000000-0000-4000-8000-0000000000bb' },
        parsePolicyContent(content()),
        contentDigest,
      ),
    ).not.toBe(base);
    expect(
      digestPolicyCreateRequest(context, parsePolicyContent(content()), `sha256:${'b'.repeat(64)}`),
    ).not.toBe(base);
    const revision = digestPolicyRevisionCreateRequest(
      context,
      POLICY,
      { expectedRevision: '1', expectedUpdatedAt: '2026-09-12T10:00:00.000002Z' },
      contentDigest,
    );
    expect(revision).not.toBe(base);
    const transition = digestPolicyTransitionRequest('control.policy.pause', context, POLICY, {
      expectedRevision: '1',
      expectedUpdatedAt: '2026-09-12T10:00:00.000002Z',
    });
    expect(transition).not.toBe(revision);
  });

  it('rejects malformed digest/context inputs', () => {
    expect(() =>
      digestPolicyCreateRequest({ ...context, sessionContextDigest: 'nope' }, parsePolicyContent(content()), `sha256:${'a'.repeat(64)}`),
    ).toThrow();
    expect(() =>
      digestPolicyRevisionCreateRequest(
        context,
        POLICY,
        { expectedRevision: '1', expectedUpdatedAt: 'x' },
        'not-a-digest',
      ),
    ).toThrow();
  });
});

describe('policy scalar parsing', () => {
  it('accepts canonical ids/revisions/operations/timestamps', () => {
    expect(parsePolicyId(POLICY)).toBe(POLICY);
    expect(parsePolicyRevisionNumber('7')).toBe('7');
    expect(parsePolicyOperation('control.policy.revoke')).toBe('control.policy.revoke');
    expect(requirePolicyTimestamp('2026-09-12T10:00:00.000000Z')).toBe('2026-09-12T10:00:00.000000Z');
    expect(policyRevisionResourceId(POLICY, '2')).toBe(`${POLICY}@2`);
  });

  it('rejects malformed canonical values', () => {
    expect(() => parsePolicyId('openarc:policy:nope')).toThrow();
    expect(() => parsePolicyRevisionNumber('0')).toThrow();
    expect(() => parsePolicyOperation('control.policy.delete')).toThrow();
    expect(() => requirePolicyTimestamp('2026-09-12 10:00:00')).toThrow();
  });

  it('rejects invalid content payloads', () => {
    expect(() => parsePolicyContent(content({ perActionLimit: null, rollingLimit: null }))).toThrow();
    expect(() => parsePolicyContent(content({ feeLimit: '-1' }))).toThrow();
    expect(() => parsePolicyContent(content({ approval: { mode: 'above', threshold: null, separateApprover: true } }))).toThrow();
    expect(() => parsePolicyContent(content({ approval: { mode: 'none', threshold: null, separateApprover: true } }))).toThrow();
    expect(() => parsePolicyContent(content({ extra: true }))).toThrow();
    expect(() => parsePolicyContent(content({ decimals: 18 }))).toThrow();
  });
});

describe('strict input boundaries', () => {
  it('rejects impossible calendar, day and clock values', () => {
    expect(() => requirePolicyTimestamp('2026-02-30T00:00:00.000000Z')).toThrow();
    expect(() => requirePolicyTimestamp('2026-13-01T00:00:00.000000Z')).toThrow();
    expect(() => requirePolicyTimestamp('2026-00-01T00:00:00.000000Z')).toThrow();
    expect(() => requirePolicyTimestamp('2026-01-01T25:00:00.000000Z')).toThrow();
    expect(() => requirePolicyTimestamp('2026-01-01T00:61:00.000000Z')).toThrow();
    expect(() => requirePolicyTimestamp('2026-01-01T00:00:61.000000Z')).toThrow();
    expect(() => requirePolicyTimestamp('2026-01-01T00:00:00.000000Z\n')).toThrow();
    expect(() => requirePolicyTimestamp('2026-01-01T00:00:00Z\n')).toThrow();
    expect(requirePolicyTimestamp('2026-02-28T00:00:00.123456Z')).toBe('2026-02-28T00:00:00.123456Z');
  });

  it('pins local ids/digests against a trailing newline', async () => {
    const pool = new FakePool(() => new FakeClient([]));
    const store = new ControlPolicyStore(pool);
    await expectCode(store.createPolicy(`${HASH}\n`, ORG, content(), metadata()), 'CONTROL_POLICY_STORE_INPUT_INVALID');
    await expectCode(store.createPolicy(HASH, ORG_NL, content(), metadata()), 'CONTROL_POLICY_STORE_INPUT_INVALID');
    await expectCode(store.getPolicyRoot(HASH, ORG, POLICY_NL), 'CONTROL_POLICY_STORE_INPUT_INVALID');
    await expectCode(store.getPolicyRevision(HASH, ORG, POLICY, '1\n'), 'CONTROL_POLICY_STORE_INPUT_INVALID');
    expect(pool.connectCalls).toBe(0);
  });

  it('bounds append CAS at 999999998 while transitions accept 999999999', () => {
    expect(parsePolicyAppendRevision('999999998')).toBe('999999998');
    expect(() => parsePolicyAppendRevision('999999999')).toThrow();
    expect(parsePolicyRevisionNumber('999999999')).toBe('999999999');
    expect(() => parsePolicyAppendRevision('1\n')).toThrow();
  });

  it('fails append input over the append bound before touching the pool', async () => {
    const pool = new FakePool(() => new FakeClient([]));
    const store = new ControlPolicyStore(pool);
    await expectCode(
      store.appendPolicyRevision(
        HASH,
        ORG,
        POLICY,
        { expectedRevision: '999999999', expectedUpdatedAt: '2026-09-12T10:00:00.000000Z', content: content() },
        metadata(),
      ),
      'CONTROL_POLICY_STORE_INPUT_INVALID',
    );
    expect(pool.connectCalls).toBe(0);
  });
});

describe('closed operation metadata', () => {
  it('maps each operation to exactly one resource and event', () => {
    expect(POLICY_RESOURCE_BY_OPERATION['control.policy.create']).toBe('budget_policy');
    expect(POLICY_RESOURCE_BY_OPERATION['control.policy.revision.create']).toBe('budget_policy_revision');
    expect(POLICY_EVENT_BY_OPERATION['control.policy.resume']).toBe('control.policy.resumed');
  });
});

describe('ControlPolicyStore commit paths', () => {
  it('creates a policy and validates the generated root receipt', async () => {
    const pool = new FakePool(
      () =>
        new FakeClient([
          WRITER_ROUTE,
          {
            when: (text) => text.includes('commit_policy_mutation'),
            rows: [receiptRow('control.policy.create', 'budget_policy', POLICY)],
          },
        ]),
    );
    const store = new ControlPolicyStore(pool);
    const result = await store.createPolicy(HASH, ORG, content(), metadata());
    expect(result.replayed).toBe(false);
    expect(result.receipt.resourceId).toBe(POLICY);
    expect(result.receipt.operation).toBe('control.policy.create');
    const commit = pool.clients[0]?.calls.find((call) => call.text.includes('commit_policy_mutation'));
    expect(commit?.values[21]).toBe(digestPolicyContent(parsePolicyContent(content())));
  });

  it('binds the revision resource id on append', async () => {
    const pool = new FakePool(
      () =>
        new FakeClient([
          WRITER_ROUTE,
          {
            when: (text) => text.includes('commit_policy_mutation'),
            rows: [receiptRow('control.policy.revision.create', 'budget_policy_revision', `${POLICY}@2`)],
          },
        ]),
    );
    const store = new ControlPolicyStore(pool);
    const result = await store.appendPolicyRevision(
      HASH,
      ORG,
      POLICY,
      {
        expectedRevision: '1',
        expectedUpdatedAt: '2026-09-12T10:00:00.000002Z',
        content: content(),
      },
      metadata(),
    );
    expect(result.receipt.resourceId).toBe(`${POLICY}@2`);
  });

  it('rejects a malformed operation/resource driver row as UNAVAILABLE', async () => {
    const pool = new FakePool(
      () =>
        new FakeClient([
          WRITER_ROUTE,
          {
            when: (text) => text.includes('commit_policy_mutation'),
            rows: [receiptRow('control.policy.delete', 'budget_policy', POLICY)],
          },
        ]),
    );
    await expectCode(new ControlPolicyStore(pool).createPolicy(HASH, ORG, content(), metadata()), 'CONTROL_POLICY_STORE_UNAVAILABLE');
  });

  it('maps a lost COMMIT reply to OUTCOME_UNKNOWN without resend', async () => {
    const client = new FakeClient([
      WRITER_ROUTE,
      {
        when: (text) => text.includes('commit_policy_mutation'),
        rows: [receiptRow('control.policy.create', 'budget_policy', POLICY)],
      },
      { when: (text) => text === 'COMMIT', throws: { message: 'connection reset' } },
    ]);
    const pool = new FakePool(() => client);
    await expectCode(new ControlPolicyStore(pool).createPolicy(HASH, ORG, content(), metadata()), 'CONTROL_POLICY_STORE_OUTCOME_UNKNOWN');
    expect(client.releases).toContain(true);
  });

  it('normalizes a driver failure without echoing values or messages', async () => {
    const secret = 'raw-session-hash-should-not-leak';
    const client = new FakeClient([
      { when: (text) => text.includes('lock_policy_writer'), throws: { code: '42501', message: secret } },
    ]);
    const pool = new FakePool(() => client);
    try {
      await new ControlPolicyStore(pool).createPolicy(HASH, ORG, content(), metadata());
      throw new Error('expected rejection');
    } catch (error) {
      expect(error).toBeInstanceOf(ControlPolicyStoreError);
      const typed = error as ControlPolicyStoreError;
      expect(typed.code).toBe('CONTROL_POLICY_STORE_FORBIDDEN');
      expect(typed.message).not.toContain(secret);
      expect(typed.message).not.toContain(HASH);
    }
  });

  it('rejects an organization mismatch, bad metadata and unknown input keys before any query', async () => {
    const pool = new FakePool(() => new FakeClient([]));
    const store = new ControlPolicyStore(pool);
    await expectCode(
      store.createPolicy(HASH, ORG, content({ organizationId: 'openarc:org:00000000-0000-4000-8000-0000000000bb' }), metadata()),
      'CONTROL_POLICY_STORE_INPUT_INVALID',
    );
    await expectCode(store.createPolicy(HASH, ORG, content(), { mutationId: MUTATION }), 'CONTROL_POLICY_STORE_INPUT_INVALID');
    await expectCode(
      store.createPolicy(HASH, ORG, content(), { ...metadata(), extra: true }),
      'CONTROL_POLICY_STORE_INPUT_INVALID',
    );
    await expectCode(
      store.transitionPolicy(HASH, ORG, POLICY, { operation: 'control.policy.create', expectedRevision: '1', expectedUpdatedAt: 'x' }, metadata()),
      'CONTROL_POLICY_STORE_INPUT_INVALID',
    );
    expect(pool.connectCalls).toBe(0);
  });
});

describe('ControlPolicyStore read paths', () => {
  it('projects a strict root and rejects a malformed one', async () => {
    const good = new FakePool(() =>
      new FakeClient([
        { when: (text) => text.includes('lock_policy_reader'), rows: [{ out_actor: 'openarc:account:00000000-0000-4000-8000-0000000000aa' }] },
        { when: (text) => text.includes('read_policy_root'), rows: [rootRow()] },
      ]),
    );
    const root = await new ControlPolicyStore(good).getPolicyRoot(HASH, ORG, POLICY);
    expect(root?.policyId).toBe(POLICY);
    expect(root?.status).toBe('active');

    const bad = new FakePool(() =>
      new FakeClient([
        { when: (text) => text.includes('lock_policy_reader'), rows: [{ out_actor: 'openarc:account:00000000-0000-4000-8000-0000000000aa' }] },
        { when: (text) => text.includes('read_policy_root'), rows: [rootRow({ out_status: 'deleted' })] },
      ]),
    );
    await expectCode(new ControlPolicyStore(bad).getPolicyRoot(HASH, ORG, POLICY), 'CONTROL_POLICY_STORE_UNAVAILABLE');
  });

  it('returns null for a missing root and validates bound ids', async () => {
    const pool = new FakePool(() =>
      new FakeClient([
        { when: (text) => text.includes('lock_policy_reader'), rows: [{ out_actor: 'openarc:account:00000000-0000-4000-8000-0000000000aa' }] },
        { when: (text) => text.includes('read_policy_root'), rows: [] },
      ]),
    );
    await expect(new ControlPolicyStore(pool).getPolicyRoot(HASH, ORG, POLICY)).resolves.toBeNull();
  });

  it('returns bounded history summaries with exact keys only', async () => {
    const pool = new FakePool(() =>
      new FakeClient([
        { when: (text) => text.includes('lock_policy_reader'), rows: [{ out_actor: 'openarc:account:00000000-0000-4000-8000-0000000000aa' }] },
        { when: (text) => text.includes('list_policy_revisions'), rows: [summaryRow(), summaryRow({ out_revision: '2' })] },
      ]),
    );
    const result = await new ControlPolicyStore(pool).listPolicyRevisions(HASH, ORG, POLICY, { limit: 5 });
    expect(result.items).toHaveLength(2);
    expect(Object.keys(result.items[0] ?? {}).sort()).toEqual(
      ['createdAt', 'digest', 'expiresAt', 'organizationId', 'policyId', 'revision', 'subjectAgentId'].sort(),
    );
    expect(result.nextCursor).toBeNull();
  });

  it('rejects a history row that lost its ordering or leaked extra keys', async () => {
    const pool = new FakePool(() =>
      new FakeClient([
        { when: (text) => text.includes('lock_policy_reader'), rows: [{ out_actor: 'openarc:account:00000000-0000-4000-8000-0000000000aa' }] },
        { when: (text) => text.includes('list_policy_revisions'), rows: [summaryRow(), summaryRow({ out_revision: '1' })] },
      ]),
    );
    await expectCode(new ControlPolicyStore(pool).listPolicyRevisions(HASH, ORG, POLICY), 'CONTROL_POLICY_STORE_UNAVAILABLE');
  });

  it('rejects an out-of-range page without touching the pool', async () => {
    const pool = new FakePool(() => new FakeClient([]));
    await expectCode(new ControlPolicyStore(pool).listPolicyRoots(HASH, ORG, { limit: 51 }), 'CONTROL_POLICY_STORE_INPUT_INVALID');
    expect(pool.connectCalls).toBe(0);
  });

  it('resolves a committed status receipt and returns not_found for an empty result', async () => {
    const committed = new FakePool(() =>
      new FakeClient([
        { when: (text) => text.includes('lock_policy_reader'), rows: [{ out_actor: 'openarc:account:00000000-0000-4000-8000-0000000000aa' }] },
        {
          when: (text) => text.includes('read_policy_mutation_status'),
          rows: [
            {
              out_mutation_id: MUTATION,
              out_operation: 'control.policy.revoke',
              out_resource_type: 'budget_policy',
              out_resource_id: POLICY,
              out_committed_at: '2026-09-12 10:00:00.123456+00',
            },
          ],
        },
      ]),
    );
    const status = await new ControlPolicyStore(committed).getPolicyMutationStatus(HASH, ORG, MUTATION);
    expect(status.status).toBe('committed');
    const missing = new FakePool(() =>
      new FakeClient([
        { when: (text) => text.includes('lock_policy_reader'), rows: [{ out_actor: 'openarc:account:00000000-0000-4000-8000-0000000000aa' }] },
        { when: (text) => text.includes('read_policy_mutation_status'), rows: [] },
      ]),
    );
    await expect(new ControlPolicyStore(missing).getPolicyMutationStatus(HASH, ORG, MUTATION)).resolves.toEqual({ status: 'not_found' });
  });

  it('exposes tsc-independent digest helper values', () => {
    expect(createHash('sha256').update('x').digest('hex')).toHaveLength(64);
  });
});

describe('strict output binding', () => {
  const READER_ROUTE: Route = {
    when: (text) => text.includes('lock_policy_reader'),
    rows: [{ out_actor: 'openarc:account:00000000-0000-4000-8000-0000000000aa' }],
  };

  function statusRoute(row: Row): Route {
    return { when: (text) => text.includes('read_policy_mutation_status'), rows: [row] };
  }

  it('rejects a status row whose operation/resourceType tuple is invalid', async () => {
    const pool = new FakePool(() =>
      new FakeClient([
        READER_ROUTE,
        statusRoute({
          out_mutation_id: MUTATION,
          out_operation: 'control.policy.create',
          out_resource_type: 'budget_policy_revision',
          out_resource_id: `${POLICY}@2`,
          out_committed_at: '2026-09-12 10:00:00.123456+00',
        }),
      ]),
    );
    await expectCode(new ControlPolicyStore(pool).getPolicyMutationStatus(HASH, ORG, MUTATION), 'CONTROL_POLICY_STORE_UNAVAILABLE');
  });

  it('rejects budget_policy_revision@1 but accepts 10/100/max revisions', async () => {
    const first = new FakePool(() =>
      new FakeClient([
        READER_ROUTE,
        statusRoute({
          out_mutation_id: MUTATION,
          out_operation: 'control.policy.revision.create',
          out_resource_type: 'budget_policy_revision',
          out_resource_id: `${POLICY}@1`,
          out_committed_at: '2026-09-12 10:00:00.123456+00',
        }),
      ]),
    );
    await expectCode(new ControlPolicyStore(first).getPolicyMutationStatus(HASH, ORG, MUTATION), 'CONTROL_POLICY_STORE_UNAVAILABLE');

    for (const revision of ['10', '100', '999999999']) {
      const pool = new FakePool(() =>
        new FakeClient([
          READER_ROUTE,
          statusRoute({
            out_mutation_id: MUTATION,
            out_operation: 'control.policy.revision.create',
            out_resource_type: 'budget_policy_revision',
            out_resource_id: `${POLICY}@${revision}`,
            out_committed_at: '2026-09-12 10:00:00.123456+00',
          }),
        ]),
      );
      const status = await new ControlPolicyStore(pool).getPolicyMutationStatus(HASH, ORG, MUTATION);
      expect(status.status).toBe('committed');
      expect(status.status === 'committed' ? status.receipt.resourceId : null).toBe(`${POLICY}@${revision}`);
    }
  });

  it('rejects a history summary whose expiry does not follow its creation', async () => {
    const pool = new FakePool(() =>
      new FakeClient([
        READER_ROUTE,
        {
          when: (text) => text.includes('list_policy_revisions'),
          rows: [summaryRow({ out_created_at: '2026-09-12 10:00:00.000002+00', out_expires_at: '2026-09-12 09:00:00.000000+00' })],
        },
      ]),
    );
    await expectCode(new ControlPolicyStore(pool).listPolicyRevisions(HASH, ORG, POLICY), 'CONTROL_POLICY_STORE_UNAVAILABLE');
  });

  it('rejects a history page mixing subject agents within one policy', async () => {
    const pool = new FakePool(() =>
      new FakeClient([
        READER_ROUTE,
        {
          when: (text) => text.includes('list_policy_revisions'),
          rows: [
            summaryRow(),
            summaryRow({ out_revision: '2', out_subject_agent_id: 'openarc:agent:00000000-0000-4000-8000-0000000000bb' }),
          ],
        },
      ]),
    );
    await expectCode(new ControlPolicyStore(pool).listPolicyRevisions(HASH, ORG, POLICY), 'CONTROL_POLICY_STORE_UNAVAILABLE');
  });

  it('collapses malformed driver canaries to a fixed error without echo', async () => {
    const canary = 'raw-policy-canary-should-not-leak';
    const pool = new FakePool(() =>
      new FakeClient([
        READER_ROUTE,
        statusRoute({
          out_mutation_id: MUTATION,
          out_operation: canary,
          out_resource_type: canary,
          out_resource_id: canary,
          out_committed_at: '2026-09-12 10:00:00.123456+00',
        }),
      ]),
    );
    try {
      await new ControlPolicyStore(pool).getPolicyMutationStatus(HASH, ORG, MUTATION);
      throw new Error('expected rejection');
    } catch (error) {
      expect(error).toBeInstanceOf(ControlPolicyStoreError);
      expect((error as ControlPolicyStoreError).code).toBe('CONTROL_POLICY_STORE_UNAVAILABLE');
      expect((error as Error).message).not.toContain(canary);
    }
  });
});

describe('page lookahead projection', () => {
  const READER_ROUTE: Route = {
    when: (text) => text.includes('lock_policy_reader'),
    rows: [{ out_actor: 'openarc:account:00000000-0000-4000-8000-0000000000aa' }],
  };
  const FOREIGN_ORG = 'openarc:org:00000000-0000-4000-8000-0000000000bb';
  const OTHER_AGENT = 'openarc:agent:00000000-0000-4000-8000-0000000000bb';
  const LOWER_POLICY = 'openarc:policy:00000000-0000-4000-8000-000000000002';
  const HIGHER_POLICY = 'openarc:policy:00000000-0000-4000-8000-000000000004';

  function poolWith(when: (text: string) => boolean, rows: Row[]): FakePool {
    return new FakePool(() => new FakeClient([READER_ROUTE, { when, rows }]));
  }

  it('rejects a foreign-organization lookahead root row before the slice', async () => {
    const pool = poolWith(
      (text) => text.includes('list_policy_roots'),
      [rootRow(), rootRow({ out_organization_id: FOREIGN_ORG, out_policy_id: HIGHER_POLICY })],
    );
    await expectCode(new ControlPolicyStore(pool).listPolicyRoots(HASH, ORG, { limit: 1 }), 'CONTROL_POLICY_STORE_UNAVAILABLE');
  });

  it('rejects unordered lookahead root ids before the slice', async () => {
    const pool = poolWith(
      (text) => text.includes('list_policy_roots'),
      [rootRow(), rootRow({ out_policy_id: LOWER_POLICY })],
    );
    await expectCode(new ControlPolicyStore(pool).listPolicyRoots(HASH, ORG, { limit: 1 }), 'CONTROL_POLICY_STORE_UNAVAILABLE');
  });

  it('rejects a foreign-organization lookahead revision row before the slice', async () => {
    const pool = poolWith(
      (text) => text.includes('list_policy_revisions'),
      [summaryRow(), summaryRow({ out_revision: '2', out_organization_id: FOREIGN_ORG })],
    );
    await expectCode(new ControlPolicyStore(pool).listPolicyRevisions(HASH, ORG, POLICY, { limit: 1 }), 'CONTROL_POLICY_STORE_UNAVAILABLE');
  });

  it('rejects unordered lookahead revision rows before the slice', async () => {
    const pool = poolWith(
      (text) => text.includes('list_policy_revisions'),
      [summaryRow({ out_revision: '2' }), summaryRow({ out_revision: '1' })],
    );
    await expectCode(new ControlPolicyStore(pool).listPolicyRevisions(HASH, ORG, POLICY, { limit: 1 }), 'CONTROL_POLICY_STORE_UNAVAILABLE');
  });

  it('rejects mixed subject agents in the lookahead before the slice', async () => {
    const pool = poolWith(
      (text) => text.includes('list_policy_revisions'),
      [summaryRow(), summaryRow({ out_revision: '2', out_subject_agent_id: OTHER_AGENT })],
    );
    await expectCode(new ControlPolicyStore(pool).listPolicyRevisions(HASH, ORG, POLICY, { limit: 1 }), 'CONTROL_POLICY_STORE_UNAVAILABLE');
  });

  it('rejects an unknown out_private summary column without echoing it', async () => {
    const canary = 'raw-private-canary-should-not-leak';
    const pool = poolWith(
      (text) => text.includes('list_policy_revisions'),
      [summaryRow({ out_private: canary })],
    );
    try {
      await new ControlPolicyStore(pool).listPolicyRevisions(HASH, ORG, POLICY);
      throw new Error('expected rejection');
    } catch (error) {
      expect(error).toBeInstanceOf(ControlPolicyStoreError);
      expect((error as ControlPolicyStoreError).code).toBe('CONTROL_POLICY_STORE_UNAVAILABLE');
      expect((error as Error).message).not.toContain(canary);
    }
  });

  it('keeps a valid lookahead row and sets the cursor from the visible page only', async () => {
    const roots = poolWith(
      (text) => text.includes('list_policy_roots'),
      [rootRow(), rootRow({ out_policy_id: HIGHER_POLICY })],
    );
    const rootsResult = await new ControlPolicyStore(roots).listPolicyRoots(HASH, ORG, { limit: 1 });
    expect(rootsResult.items).toHaveLength(1);
    expect(rootsResult.nextCursor).toBe(POLICY);

    const revisions = poolWith(
      (text) => text.includes('list_policy_revisions'),
      [summaryRow(), summaryRow({ out_revision: '2' })],
    );
    const revisionsResult = await new ControlPolicyStore(revisions).listPolicyRevisions(HASH, ORG, POLICY, { limit: 1 });
    expect(revisionsResult.items).toHaveLength(1);
    expect(revisionsResult.nextCursor).toBe('1');
  });
});
