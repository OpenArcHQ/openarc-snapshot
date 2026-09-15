import { describe, expect, it } from 'vitest';
import {
  CONTROL_ACTION_EVENT_BY_OPERATION,
  ControlActionStore,
  ControlActionStoreError,
  CommerceActionInputError,
  OutboxStore,
  OutboxStoreError,
  digestCommerceActionAuthorizeRequest,
  digestCommerceActionCancelRequest,
  digestCommerceActionDecisionRequest,
  digestCommerceActionHumanContext,
  digestCommerceActionIdempotencyKey,
  digestCommerceActionMachineContext,
  parseCommerceActionId,
  parseCommerceActionMetadata,
  parseCommerceApprovalMetadata,
  parseCommerceRequirementId,
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
const TOKEN = 'b'.repeat(64);
const KEY = 'A'.repeat(42) + 'A';
const UUID_A = '00000000-0000-4000-8000-000000000010';
const ACTION = `openarc:action:${UUID_A}`;
const ORG = 'openarc:org:00000000-0000-4000-8000-000000000001';
const AGENT = 'openarc:agent:00000000-0000-4000-8000-000000000002';
const POLICY = 'openarc:policy:00000000-0000-4000-8000-000000000003';
const SESSION = '00000000-0000-4000-8000-000000000004';
const MUTATION = '00000000-0000-4000-8000-000000000005';
const CREDENTIAL = '00000000-0000-4000-8000-000000000006';
const PROVIDER = 'openarc:provider:00000000-0000-4000-8000-000000000007';
const LISTING = 'openarc:listing:00000000-0000-4000-8000-000000000008';
const REQUIREMENT = 'openarc:requirement:00000000-0000-4000-8000-000000000009';
const RESERVATION = `openarc:reservation:${UUID_A}`;
const ACCOUNT = 'openarc:account:00000000-0000-4000-8000-00000000000a';
const DIGEST = `sha256:${'a'.repeat(64)}`;

function metadata(): Row {
  return { mutationId: MUTATION, idempotencyKey: KEY };
}

function actionRow(overrides: Row = {}): Row {
  return {
    out_replayed: false,
    out_action_id: ACTION,
    out_organization_id: ORG,
    out_subject_agent_id: AGENT,
    out_commerce_session_id: SESSION,
    out_network_id: 'eip155:5042002',
    out_asset: 'USDC',
    out_representation: 'erc20',
    out_decimals: 6,
    out_source_kind: 'internal_fixture',
    out_status: 'reserved_not_granted',
    out_amount_atomic: '100',
    out_fee_atomic: '5',
    out_debit_atomic: '105',
    out_policy_id: POLICY,
    out_policy_revision: '1',
    out_provider_id: PROVIDER,
    out_listing_id: LISTING,
    out_listing_version: '1',
    out_requirement_id: REQUIREMENT,
    out_requirement_digest: DIGEST,
    out_reservation_id: RESERVATION,
    out_approval_id: null,
    out_created_at: '2026-09-12 10:00:00.000000+00',
    out_updated_at: '2026-09-12 10:00:00.000000+00',
    out_expires_at: '2026-09-12 10:05:00.000000+00',
    out_committed_at: '2026-09-12 10:00:00.500000+00',
    ...overrides,
  };
}

function resolveContextRow(): Row {
  return {
    out_organization_id: ORG,
    out_subject_agent_id: AGENT,
    out_credential_id: CREDENTIAL,
    out_issuer_account_id: ACCOUNT,
    out_parent_human_account_id: ACCOUNT,
    out_commerce_session_id: SESSION,
    out_policy_id: POLICY,
    out_agent_session_id: SESSION,
  };
}

function requirementRow(): Row {
  return {
    out_organization_id: ORG,
    out_requirement_id: REQUIREMENT,
    out_seller_organization_id: ORG,
    out_provider_id: PROVIDER,
    out_listing_id: LISTING,
    out_listing_version: '1',
    out_network_id: 'eip155:5042002',
    out_asset: 'USDC',
    out_representation: 'erc20',
    out_decimals: 6,
    out_amount_atomic: '100',
    out_fee_atomic: '5',
    out_requirement_digest: DIGEST,
    out_source_kind: 'internal_fixture',
    out_created_at: '2026-09-12 09:00:00.000000+00',
    out_valid_until: '2026-09-12 11:00:00.000000+00',
  };
}

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ControlActionStoreError);
    expect((error as ControlActionStoreError).code).toBe(code);
    return;
  }
  throw new Error(`expected ControlActionStoreError ${code}`);
}

describe('commerce action digest determinism and domain separation', () => {
  it('separates machine and human contexts and every operation domain', () => {
    expect(digestCommerceActionMachineContext(TOKEN)).toHaveLength(64);
    expect(digestCommerceActionMachineContext(TOKEN)).not.toBe(
      digestCommerceActionHumanContext('control.commerce_action.cancel', TOKEN),
    );
    expect(digestCommerceActionHumanContext('control.commerce_action.approve', HASH)).not.toBe(
      digestCommerceActionHumanContext('control.commerce_action.reject', HASH),
    );
    expect(digestCommerceActionIdempotencyKey('control.commerce_action.authorize', KEY)).not.toBe(
      digestCommerceActionIdempotencyKey('control.commerce_action.cancel', KEY),
    );
    expect(CONTROL_ACTION_EVENT_BY_OPERATION['control.commerce_action.authorize']).toBe(
      'control.commerce_action.authorized',
    );
  });

  it('binds the immutable authorization context and changes with any field', () => {
    const base = {
      organizationId: ORG,
      parentHumanAccountId: ACCOUNT,
      commerceSessionId: SESSION,
      agentSessionId: SESSION,
      credentialId: CREDENTIAL,
      policyId: POLICY,
      actionId: ACTION,
      requirementId: REQUIREMENT,
      requirementDigest: DIGEST,
      amountAtomic: '100',
      feeAtomic: '5',
      networkId: 'eip155:5042002',
      asset: 'USDC',
      representation: 'erc20',
      decimals: 6,
      sessionContextDigest: HASH,
      mutationId: MUTATION,
    };
    const digest = digestCommerceActionAuthorizeRequest(base);
    expect(digest).toHaveLength(64);
    expect(digestCommerceActionAuthorizeRequest({ ...base, amountAtomic: '101' })).not.toBe(digest);
    expect(digestCommerceActionAuthorizeRequest({ ...base, requirementDigest: `sha256:${'b'.repeat(64)}` })).not.toBe(digest);
    expect(
      digestCommerceActionDecisionRequest(
        'control.commerce_action.approve',
        { organizationId: ORG, actorAccountId: ACCOUNT, sessionContextDigest: HASH, mutationId: MUTATION },
        ACTION,
      ),
    ).not.toBe(
      digestCommerceActionCancelRequest(
        { organizationId: ORG, actorAccountId: ACCOUNT, sessionContextDigest: HASH, mutationId: MUTATION },
        ACTION,
      ),
    );
  });
});

describe('commerce action parsers', () => {
  it('rejects non-canonical ids and digests', () => {
    expect(() => parseCommerceActionId(`openarc:action:${'0'.repeat(8)}-0000-1000-8000-000000000000`)).toThrow(
      CommerceActionInputError,
    );
    expect(() => parseCommerceActionId('openarc:reservation:00000000-0000-4000-8000-000000000010')).toThrow(
      CommerceActionInputError,
    );
    expect(() => parseCommerceRequirementId('nope')).toThrow(CommerceActionInputError);
    expect(() => parseCommerceActionMetadata({})).toThrow(CommerceActionInputError);
    expect(() => parseCommerceApprovalMetadata({})).toThrow(CommerceActionInputError);
  });
});

describe('OutboxStore commerce_action claim boundary', () => {
  const EVENT = '00000000-0000-4000-8000-0000000000e1';
  const MUTATION = '00000000-0000-4000-8000-0000000000e2';
  const ORG = 'openarc:org:00000000-0000-4000-8000-0000000000e3';

  function claimRow(resourceId: string): Row {
    return {
      event_id: EVENT,
      organization_id: ORG,
      mutation_id: MUTATION,
      resource_type: 'commerce_action',
      resource_id: resourceId,
      event_type: 'control.commerce_action.authorized',
      payload_version: 1,
      lease_generation: '1',
      lease_until: new Date('2026-09-12T10:00:30.000Z'),
      attempt_count: 0,
    };
  }

  it('accepts a canonical action id and rejects trailing newline / UUIDv1', async () => {
    const canonical = `openarc:action:${UUID_A}`;
    const ok = new FakePool(
      () =>
        new FakeClient([
          { when: () => true, rows: [claimRow(canonical)] },
        ]),
    );
    const store = new OutboxStore(ok);
    const claimed = await store.claim({ limit: 1 });
    expect(claimed).toHaveLength(1);
    expect(claimed[0]?.resourceType).toBe('commerce_action');

    for (const bad of [`${canonical}\n`, 'openarc:action:00000000-0000-1000-8000-000000000010']) {
      const pool = new FakePool(() => new FakeClient([{ when: () => true, rows: [claimRow(bad)] }]));
      await expectCodeOutbox(new OutboxStore(pool).claim({ limit: 1 }), 'OUTBOX_STORE_UNAVAILABLE');
    }
  });
});

/**
 * Regression for a queue-blocking defect: DB7 really emits four listing-version
 * lifecycle events and the worker registers handlers for all four, but the
 * claim projection had no case for them and fell through to the fixed
 * UNAVAILABLE error. Because one unprojectable row fails the WHOLE batch, a
 * single published listing version stalled every notification permanently.
 *
 * These four legitimately target a listing's FIRST version, so unlike
 * `market.listing.version.created` — which is only emitted for version >= 2,
 * version 1 being reported by `market.listing.created` — they must accept `@1`.
 */
describe('OutboxStore listing_version lifecycle claim boundary', () => {
  const EVENT = '00000000-0000-4000-8000-0000000000f1';
  const MUTATION = '00000000-0000-4000-8000-0000000000f2';
  const ORG = 'openarc:org:00000000-0000-4000-8000-0000000000f3';
  const LISTING = 'openarc:listing:00000000-0000-4000-8000-0000000000f4';

  const LIFECYCLE_EVENTS = [
    'market.listing.origin_review.recorded',
    'market.listing.version.published',
    'market.listing.version.paused',
    'market.listing.version.retired',
  ] as const;

  function lifecycleRow(resourceId: string, eventType: string): Row {
    return {
      event_id: EVENT,
      organization_id: ORG,
      mutation_id: MUTATION,
      resource_type: 'listing_version',
      resource_id: resourceId,
      event_type: eventType,
      payload_version: 1,
      lease_generation: '1',
      lease_until: new Date('2026-09-15T10:00:30.000Z'),
      attempt_count: 0,
    };
  }

  it('projects all four lifecycle events, including on a listing first version', async () => {
    for (const eventType of LIFECYCLE_EVENTS) {
      for (const version of ['1', '2', '999999999']) {
        const pool = new FakePool(
          () =>
            new FakeClient([
              { when: () => true, rows: [lifecycleRow(`${LISTING}@${version}`, eventType)] },
            ]),
        );
        const claimed = await new OutboxStore(pool).claim({ limit: 1 });
        expect(claimed).toHaveLength(1);
        expect(claimed[0]?.resourceType).toBe('listing_version');
        expect(claimed[0]?.eventType).toBe(eventType);
        expect(claimed[0]?.resourceId).toBe(`${LISTING}@${version}`);
      }
    }
  });

  it('still rejects a malformed lifecycle resource without widening the boundary', async () => {
    const bad = [
      `${LISTING}@0`,
      `${LISTING}@01`,
      `${LISTING}@`,
      LISTING,
      `${LISTING}@1\n`,
      `${LISTING}@1 `,
      'openarc:listing:00000000-0000-4000-8000-0000000000f4@1x',
    ];
    for (const resourceId of bad) {
      const pool = new FakePool(
        () =>
          new FakeClient([
            {
              when: () => true,
              rows: [lifecycleRow(resourceId, 'market.listing.version.published')],
            },
          ]),
      );
      await expectCodeOutbox(new OutboxStore(pool).claim({ limit: 1 }), 'OUTBOX_STORE_UNAVAILABLE');
    }
  });

  it('keeps version.created excluding a first version', async () => {
    const pool = new FakePool(
      () =>
        new FakeClient([
          { when: () => true, rows: [lifecycleRow(`${LISTING}@1`, 'market.listing.version.created')] },
        ]),
    );
    await expectCodeOutbox(new OutboxStore(pool).claim({ limit: 1 }), 'OUTBOX_STORE_UNAVAILABLE');
  });
});

async function expectCodeOutbox(promise: Promise<unknown>, code: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(OutboxStoreError);
    expect((error as OutboxStoreError).code).toBe(code);
    return;
  }
  throw new Error(`expected OutboxStoreError ${code}`);
}

describe('ControlActionStore production boundary', () => {
  it('rejects malformed authorize input before any checkout', async () => {
    const pool = new FakePool(() => new FakeClient([]));
    const store = new ControlActionStore(pool);
    await expectCode(
      store.authorizeCommerceAction('not-a-hash', { actionId: ACTION, requirementId: REQUIREMENT }, metadata()),
      'CONTROL_ACTION_STORE_INPUT_INVALID',
    );
    await expectCode(
      store.authorizeCommerceAction(TOKEN, { actionId: ACTION, requirementId: REQUIREMENT, extra: 1 } as never, metadata()),
      'CONTROL_ACTION_STORE_INPUT_INVALID',
    );
    await expectCode(
      store.authorizeCommerceAction(TOKEN, { actionId: ACTION, requirementId: REQUIREMENT }, { mutationId: MUTATION }),
      'CONTROL_ACTION_STORE_INPUT_INVALID',
    );
    expect(pool.connectCalls).toBe(0);
  });

  it('maps REQUIREMENT_UNAVAILABLE, budget and exposure codes without echoing', async () => {
    const pool = new FakePool(() => new FakeClient([{ when: (t) => t.includes('resolve_commerce'), throws: { code: 'P0D10' } }]));
    const store = new ControlActionStore(pool);
    await expectCode(
      store.authorizeCommerceAction(TOKEN, { actionId: ACTION, requirementId: REQUIREMENT }, metadata()),
      'CONTROL_ACTION_STORE_REQUIREMENT_UNAVAILABLE',
    );
  });

  it('projects a valid authorize row into frozen action metadata', async () => {
    const client = new FakeClient([
      { when: (t) => t.includes('resolve_commerce_action_context'), rows: [resolveContextRow()] },
      { when: (t) => t.includes('resolve_commerce_requirement'), rows: [requirementRow()] },
      { when: (t) => t.includes('authorize_commerce_action'), rows: [actionRow()] },
    ]);
    const pool = new FakePool(() => client);
    const store = new ControlActionStore(pool);
    const result = await store.authorizeCommerceAction(
      TOKEN,
      { actionId: ACTION, requirementId: REQUIREMENT },
      metadata(),
    );
    expect(result.replayed).toBe(false);
    expect(result.metadata.actionId).toBe(ACTION);
    expect(result.metadata.status).toBe('reserved_not_granted');
    expect(result.receipt.operation).toBe('control.commerce_action.authorize');
    expect(result.receipt.resourceType).toBe('commerce_action');
    expect(client.releases).toEqual([false]);
  });

  it('turns a malformed mutation row into a fixed UNAVAILABLE error', async () => {
    const client = new FakeClient([
      { when: (t) => t.includes('resolve_commerce_action_context'), rows: [resolveContextRow()] },
      { when: (t) => t.includes('resolve_commerce_requirement'), rows: [requirementRow()] },
      { when: (t) => t.includes('authorize_commerce_action'), rows: [actionRow({ out_status: 'bogus' })] },
    ]);
    const pool = new FakePool(() => client);
    const store = new ControlActionStore(pool);
    await expectCode(
      store.authorizeCommerceAction(TOKEN, { actionId: ACTION, requirementId: REQUIREMENT }, metadata()),
      'CONTROL_ACTION_STORE_UNAVAILABLE',
    );
    expect(client.releases).toEqual([false]);
  });

  it('maps a post-COMMIT transport failure to OUTCOME_UNKNOWN and destroys the client', async () => {
    const client = new FakeClient([
      { when: (t) => t.includes('resolve_commerce_action_context'), rows: [resolveContextRow()] },
      { when: (t) => t.includes('resolve_commerce_requirement'), rows: [requirementRow()] },
      { when: (t) => t.includes('authorize_commerce_action'), rows: [actionRow()] },
      // This simulates a bounded transport failure after the database has
      // accepted COMMIT. The store must not retry or release a possibly-live
      // connection, and callers recover through mutation status.
      { when: (t) => t === 'COMMIT', throws: { message: 'injected post-commit transport failure' } },
    ]);
    const pool = new FakePool(() => client);
    const store = new ControlActionStore(pool);
    await expectCode(
      store.authorizeCommerceAction(
        TOKEN,
        { actionId: ACTION, requirementId: REQUIREMENT },
        metadata(),
      ),
      'CONTROL_ACTION_STORE_OUTCOME_UNKNOWN',
    );
    expect(client.releases).toEqual([true]);
  });

  it('returns null for a not-found action read', async () => {
    const client = new FakeClient([{ when: (t) => t.includes('read_commerce_action'), rows: [] }]);
    const pool = new FakePool(() => client);
    const store = new ControlActionStore(pool);
    await expect(store.readAction(HASH, ORG, ACTION)).resolves.toBeNull();
  });
});

function exposureRow(overrides: Row = {}): Row {
  return {
    out_organization_id: ORG,
    out_subject_agent_id: AGENT,
    out_policy_id: POLICY,
    out_policy_revision: '1',
    out_network_id: 'eip155:5042002',
    out_asset: 'USDC',
    out_representation: 'erc20',
    out_decimals: 6,
    out_window_seconds: '3600',
    out_committed_atomic: '100',
    out_unresolved_atomic: '200',
    out_total_atomic: '300',
    out_available_atomic: '700',
    out_deficit_atomic: '0',
    out_as_of: '2026-09-12 10:00:00.000000+00',
    ...overrides,
  };
}

function exposureStore(rows: Row[]): { store: ControlActionStore; client: FakeClient } {
  const client = new FakeClient([{ when: (t) => t.includes('read_commerce_exposure'), rows }]);
  return { store: new ControlActionStore(new FakePool(() => client)), client };
}

describe('readExposure exact projection and identity validation', () => {
  it('projects a valid exact exposure row', async () => {
    const { store } = exposureStore([exposureRow()]);
    const view = await store.readExposure(HASH, ORG, AGENT, POLICY);
    expect(view).toMatchObject({
      organizationId: ORG,
      subjectAgentId: AGENT,
      policyId: POLICY,
      networkId: 'eip155:5042002',
      asset: 'USDC',
      representation: 'erc20',
      decimals: 6,
      windowSeconds: '3600',
      committedAtomic: '100',
      unresolvedAtomic: '200',
      totalExposureAtomic: '300',
      availableAtomic: '700',
      deficitAtomic: '0',
    });
  });

  it('rejects a wrong DB identity instead of relabeling the literal', async () => {
    for (const override of [
      { out_network_id: 'eip155:1' },
      { out_asset: 'DAI' },
      { out_representation: 'native' },
      { out_decimals: 18 },
    ]) {
      const { store } = exposureStore([exposureRow(override)]);
      await expectCode(store.readExposure(HASH, ORG, AGENT, POLICY), 'CONTROL_ACTION_STORE_UNAVAILABLE');
    }
  });

  it('requires exact bounded committed + unresolved totals', async () => {
    const { store } = exposureStore([exposureRow({ out_total_atomic: '301' })]);
    await expectCode(store.readExposure(HASH, ORG, AGENT, POLICY), 'CONTROL_ACTION_STORE_UNAVAILABLE');
    const { store: missing } = exposureStore([exposureRow({ out_committed_atomic: undefined })]);
    await expectCode(missing.readExposure(HASH, ORG, AGENT, POLICY), 'CONTROL_ACTION_STORE_UNAVAILABLE');
  });

  it('accepts unbounded available null with zero deficit and rejects a nonzero deficit', async () => {
    const { store } = exposureStore([exposureRow({ out_available_atomic: null, out_deficit_atomic: '0' })]);
    const view = await store.readExposure(HASH, ORG, AGENT, POLICY);
    expect(view?.availableAtomic).toBeNull();
    const { store: badNull } = exposureStore([
      exposureRow({ out_available_atomic: null, out_deficit_atomic: '5' }),
    ]);
    await expectCode(badNull.readExposure(HASH, ORG, AGENT, POLICY), 'CONTROL_ACTION_STORE_UNAVAILABLE');
    const { store: badDeficit } = exposureStore([
      exposureRow({ out_available_atomic: '5', out_deficit_atomic: '1' }),
    ]);
    await expectCode(badDeficit.readExposure(HASH, ORG, AGENT, POLICY), 'CONTROL_ACTION_STORE_UNAVAILABLE');
  });

  it('uses the accepted policy window bound and absolute-end matching', async () => {
    for (const window of ['2592001', '3600\n', '0', '01', '']) {
      const { store } = exposureStore([exposureRow({ out_window_seconds: window })]);
      await expectCode(store.readExposure(HASH, ORG, AGENT, POLICY), 'CONTROL_ACTION_STORE_UNAVAILABLE');
    }
    const { store: ok } = exposureStore([exposureRow({ out_window_seconds: '2592000' })]);
    const view = await ok.readExposure(HASH, ORG, AGENT, POLICY);
    expect(view?.windowSeconds).toBe('2592000');
  });

  it('rejects aggregate fields carrying a suffix or newline without throwing raw', async () => {
    for (const field of [
      'out_committed_atomic',
      'out_unresolved_atomic',
      'out_total_atomic',
      'out_available_atomic',
      'out_deficit_atomic',
    ]) {
      const { store } = exposureStore([exposureRow({ [field]: '100\n' })]);
      await expectCode(store.readExposure(HASH, ORG, AGENT, POLICY), 'CONTROL_ACTION_STORE_UNAVAILABLE');
    }
  });

  it('readApproval SELECT includes the commerce session column it projects', async () => {
    const approvalRow: Row = {
      out_approval_id: `openarc:approval:${UUID_A}`,
      out_action_id: ACTION,
      out_organization_id: ORG,
      out_subject_agent_id: AGENT,
      out_commerce_session_id: SESSION,
      out_status: 'pending',
      out_policy_id: POLICY,
      out_policy_revision: '1',
      out_requested_by: ACCOUNT,
      out_separate_approver: false,
      out_decided_by: null,
      out_source_kind: 'internal_fixture',
      out_created_at: '2026-09-12 10:00:00.000000+00',
      out_expires_at: '2026-09-12 10:05:00.000000+00',
      out_decided_at: null,
    };
    const client = new FakeClient([{ when: (t) => t.includes('read_commerce_approval'), rows: [approvalRow] }]);
    const store = new ControlActionStore(new FakePool(() => client));
    const approval = await store.readApproval(HASH, ORG, ACTION);
    expect(approval?.commerceSessionId).toBe(SESSION);
    const select = client.calls.find((call) => call.text.includes('read_commerce_approval'))?.text ?? '';
    expect(select).toContain('out_commerce_session_id');
  });

  it('readAgentAction returns the authenticated org on not-found and projects own action', async () => {
    const contextRow: Row = {
      out_organization_id: ORG,
      out_action_id: ACTION,
      out_found: false,
    };
    const missingClient = new FakeClient([
      { when: (t) => t.includes('read_agent_commerce_action'), rows: [contextRow] },
    ]);
    const missing = await new ControlActionStore(new FakePool(() => missingClient)).readAgentAction(
      TOKEN,
      ACTION,
    );
    expect(missing).toEqual({ organizationId: ORG, actionId: ACTION, item: null });

    const foundClient = new FakeClient([
      {
        when: (t) => t.includes('read_agent_commerce_action'),
        rows: [actionRow({ out_found: true })],
      },
    ]);
    const found = await new ControlActionStore(new FakePool(() => foundClient)).readAgentAction(TOKEN, ACTION);
    expect(found.item?.actionId).toBe(ACTION);
    expect(found.organizationId).toBe(ORG);
  });
});

/**
 * Regression for the human/agent mutation-status projections. The human reader
 * may only ever surface approve/reject/cancel and the agent reader may only
 * ever surface authorize; transposing them silently hid every committed human
 * receipt behind a fixed UNAVAILABLE.
 */
describe('mutation status reader projections', () => {
  function statusRow(operation: string): Row {
    return {
      out_mutation_id: MUTATION,
      out_operation: operation,
      out_resource_type: 'commerce_action',
      out_resource_id: ACTION,
      out_committed_at: '2026-09-12 10:00:00.500000+00',
      out_organization_id: ORG,
    };
  }

  function statusPool(fragment: string, operation: string): FakePool {
    return new FakePool(
      () => new FakeClient([{ when: (text) => text.includes(fragment), rows: [statusRow(operation)] }]),
    );
  }

  async function expectUnavailable(promise: Promise<unknown>): Promise<void> {
    try {
      await promise;
    } catch (error) {
      expect(error).toBeInstanceOf(ControlActionStoreError);
      expect((error as ControlActionStoreError).code).toBe('CONTROL_ACTION_STORE_UNAVAILABLE');
      return;
    }
    throw new Error('expected CONTROL_ACTION_STORE_UNAVAILABLE');
  }

  it('projects every human operation receipt and refuses an agent operation', async () => {
    for (const operation of [
      'control.commerce_action.approve',
      'control.commerce_action.reject',
      'control.commerce_action.cancel',
    ]) {
      const store = new ControlActionStore(
        statusPool('read_human_commerce_action_mutation_status', operation),
      );
      await expect(store.getHumanMutationStatus(HASH, ORG, MUTATION)).resolves.toMatchObject({
        status: 'committed',
        receipt: {
          operation,
          mutationId: MUTATION,
          resourceType: 'commerce_action',
          resourceId: ACTION,
        },
      });
    }
    await expectUnavailable(
      new ControlActionStore(
        statusPool('read_human_commerce_action_mutation_status', 'control.commerce_action.authorize'),
      ).getHumanMutationStatus(HASH, ORG, MUTATION),
    );
  });

  it('projects only the authorize receipt for the agent reader', async () => {
    const store = new ControlActionStore(
      statusPool('read_agent_commerce_action_mutation_status', 'control.commerce_action.authorize'),
    );
    await expect(store.getAgentMutationStatus(TOKEN, MUTATION)).resolves.toMatchObject({
      status: 'committed',
      receipt: { operation: 'control.commerce_action.authorize', resourceId: ACTION },
    });
    for (const operation of [
      'control.commerce_action.approve',
      'control.commerce_action.reject',
      'control.commerce_action.cancel',
    ]) {
      await expectUnavailable(
        new ControlActionStore(
          statusPool('read_agent_commerce_action_mutation_status', operation),
        ).getAgentMutationStatus(TOKEN, MUTATION),
      );
    }
  });
});
