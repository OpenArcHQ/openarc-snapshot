import { describe, expect, it } from 'vitest';
import {
  CONTROL_GRANT_OPERATIONS,
  CONTROL_GRANT_RESOURCE_TYPE,
  CONTROL_GRANT_STORE_ERROR_MESSAGES,
  CONTROL_GRANT_TOKEN_HASH_VERSION,
  ControlGrantStore,
  ControlGrantStoreError,
  asControlGrantPool,
  digestCommerceGrantToken,
  type TenantClient,
  type TenantPool,
  type TenantQueryResult,
} from '../src/index.js';

/**
 * Driver-level unit regressions for the DB12 grant store. The scripted client
 * proves the canonical input grammar, the one-way token digest, the production
 * wrapper seam, the token hash staying OUT of the logical request digest, the
 * strict output projection and the fixed non-echoing error vocabulary without
 * a database.
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
const TOKEN_HASH = 'b'.repeat(64);
const OTHER_TOKEN_HASH = 'c'.repeat(64);
const ORG = 'openarc:org:00000000-0000-4000-8000-000000000001';
const OTHER_ORG = 'openarc:org:00000000-0000-4000-8000-0000000000ff';
const AGENT = 'openarc:agent:00000000-0000-4000-8000-000000000002';
const POLICY = 'openarc:policy:00000000-0000-4000-8000-000000000003';
const SESSION = '00000000-0000-4000-8000-000000000004';
const CREDENTIAL = '00000000-0000-4000-8000-000000000005';
const AGENT_SESSION = '00000000-0000-4000-8000-000000000006';
const PROVIDER = 'openarc:provider:00000000-0000-4000-8000-000000000007';
const LISTING = 'openarc:listing:00000000-0000-4000-8000-000000000008';
const REQUIREMENT = 'openarc:requirement:00000000-0000-4000-8000-000000000009';
const ACCOUNT = 'openarc:account:00000000-0000-4000-8000-00000000000a';
const ACTION = 'openarc:action:00000000-0000-4000-8000-00000000000b';
const RESERVATION = 'openarc:reservation:00000000-0000-4000-8000-00000000000c';
const GRANT = 'openarc:grant:00000000-0000-4000-8000-00000000000d';
const ATTEMPT = '00000000-0000-4000-8000-00000000000e';
const DIGEST = `sha256:${'7'.repeat(64)}`;
const RAW_TOKEN = `oag_v1_${Buffer.alloc(32, 9).toString('base64url')}`;
const OTHER_RAW_TOKEN = `oag_v1_${Buffer.alloc(32, 11).toString('base64url')}`;
const KEY = Buffer.alloc(32, 3).toString('base64url');
const MUTATION = '00000000-0000-4000-8000-0000000000f1';

function metadata(): { idempotencyKey: string; mutationId: string } {
  return { idempotencyKey: KEY, mutationId: MUTATION };
}

function contextRow(overrides: Row = {}): Row {
  return {
    out_organization_id: ORG,
    out_parent_human_account_id: ACCOUNT,
    out_commerce_session_id: SESSION,
    out_agent_session_id: AGENT_SESSION,
    out_credential_id: CREDENTIAL,
    out_policy_id: POLICY,
    ...overrides,
  };
}

function grantRow(overrides: Row = {}): Row {
  return {
    out_replayed: false,
    out_organization_id: ORG,
    out_grant_id: GRANT,
    out_action_id: ACTION,
    out_reservation_id: RESERVATION,
    out_subject_agent_id: AGENT,
    out_commerce_session_id: SESSION,
    out_provider_id: PROVIDER,
    out_listing_id: LISTING,
    out_listing_version: '1',
    out_generation: '1',
    out_status: 'issued',
    out_issued_at: '2026-09-12 10:00:00.000000+00',
    out_updated_at: '2026-09-12 10:00:00.000000+00',
    out_expires_at: '2026-09-12 10:05:00.000000+00',
    out_claimed_at: null,
    out_revoked_at: null,
    out_committed_at: '2026-09-12 10:00:00.000000+00',
    ...overrides,
  };
}

function providerViewRow(overrides: Row = {}): Row {
  return {
    out_replayed: false,
    out_grant_id: GRANT,
    out_action_id: ACTION,
    out_provider_id: PROVIDER,
    out_listing_id: LISTING,
    out_listing_version: '1',
    out_requirement_id: REQUIREMENT,
    out_requirement_digest: DIGEST,
    out_amount_atomic: '1000000',
    out_fee_atomic: '5',
    out_debit_atomic: '1000005',
    out_expires_at: '2026-09-12 10:05:00.000000+00',
    out_status: 'issued',
    out_claimed_attempt_id: null,
    ...overrides,
  };
}

function claimRow(overrides: Row = {}): Row {
  return {
    ...providerViewRow({ out_status: 'claimed' }),
    out_attempt_id: ATTEMPT,
    out_claimed_at: '2026-09-12 10:01:00.000000+00',
    out_claim_digest: DIGEST,
    out_committed_at: '2026-09-12 10:01:00.000000+00',
    ...overrides,
  };
}

function attemptRow(overrides: Row = {}): Row {
  return {
    out_found: true,
    out_attempt_id: ATTEMPT,
    out_grant_id: GRANT,
    out_action_id: ACTION,
    out_provider_id: PROVIDER,
    out_listing_id: LISTING,
    out_listing_version: '1',
    out_claimed_at: '2026-09-12 10:01:00.000000+00',
    out_grant_revoked: false,
    ...overrides,
  };
}

function storeWith(routes: Route[]): { store: ControlGrantStore; pool: FakePool } {
  const pool = new FakePool(() => new FakeClient(routes));
  return { store: new ControlGrantStore(pool), pool };
}

function issueStore(rows: Row[], routes: Route[] = []): { store: ControlGrantStore; pool: FakePool } {
  return storeWith([
    { when: (text) => text.includes('resolve_commerce_action_context'), rows: [contextRow()] },
    { when: (text) => text.includes('issue_authorization_grant'), rows },
    ...routes,
  ]);
}

function revokeStore(rows: Row[]): { store: ControlGrantStore; pool: FakePool } {
  return storeWith([
    { when: (text) => text.includes('lock_action_human'), rows: [{ out_actor: ACCOUNT, out_role: 'owner' }] },
    { when: (text) => text.includes('revoke_authorization_grant'), rows },
  ]);
}

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ControlGrantStoreError);
    expect((error as ControlGrantStoreError).code).toBe(code);
    return;
  }
  throw new Error(`expected ControlGrantStoreError ${code}`);
}

describe('control grant store error vocabulary', () => {
  it('exposes fixed messages that never echo input', () => {
    for (const [code, message] of Object.entries(CONTROL_GRANT_STORE_ERROR_MESSAGES)) {
      expect(message.startsWith('ControlGrantStore')).toBe(true);
      expect(new ControlGrantStoreError(
        code as keyof typeof CONTROL_GRANT_STORE_ERROR_MESSAGES,
      ).message).toBe(message);
      expect(message).not.toContain('openarc:');
      expect(message).not.toContain('oag_v1_');
      expect(message).not.toContain('SELECT');
    }
    expect(CONTROL_GRANT_OPERATIONS).toEqual([
      'control.grant.issue',
      'control.grant.replace',
      'control.grant.revoke',
      'control.grant.claim',
    ]);
    expect(CONTROL_GRANT_RESOURCE_TYPE).toBe('authorization_grant');
    expect(CONTROL_GRANT_TOKEN_HASH_VERSION).toBe(1);
  });

  it('maps every SQLSTATE the grant helpers raise to a fixed code', async () => {
    const cases: readonly [string, string][] = [
      ['28000', 'CONTROL_GRANT_STORE_SESSION_INVALID'],
      ['42501', 'CONTROL_GRANT_STORE_FORBIDDEN'],
      ['23503', 'CONTROL_GRANT_STORE_NOT_FOUND'],
      ['23505', 'CONTROL_GRANT_STORE_CONFLICT'],
      ['P0D01', 'CONTROL_GRANT_STORE_IDEMPOTENCY_CONFLICT'],
      ['P0D10', 'CONTROL_GRANT_STORE_REQUIREMENT_UNAVAILABLE'],
      ['P0D13', 'CONTROL_GRANT_STORE_POTENTIAL_EXPOSURE'],
      ['P0D14', 'CONTROL_GRANT_STORE_GRANT_CONFLICT'],
      ['P0D15', 'CONTROL_GRANT_STORE_GRANT_EXPIRED'],
      ['23514', 'CONTROL_GRANT_STORE_INPUT_INVALID'],
      ['XX000', 'CONTROL_GRANT_STORE_UNAVAILABLE'],
    ];
    for (const [sqlstate, expected] of cases) {
      const { store } = storeWith([
        { when: (text) => text.includes('resolve_commerce_action_context'), rows: [contextRow()] },
        { when: (text) => text.includes('issue_authorization_grant'), throws: { code: sqlstate } },
      ]);
      await expectCode(
        store.issueForReservedAction(HASH, { actionId: ACTION, grantTokenHash: TOKEN_HASH }, metadata()),
        expected,
      );
    }
  });
});

describe('raw grant secret handling', () => {
  it('digests a canonical oag_v1_ secret one way and never returns it', () => {
    const digest = digestCommerceGrantToken(RAW_TOKEN);
    expect(digest).toMatch(/^[0-9a-f]{64}$/);
    expect(digest).not.toContain(RAW_TOKEN.slice('oag_v1_'.length));
    expect(digestCommerceGrantToken(RAW_TOKEN)).toBe(digest);
    expect(digestCommerceGrantToken(OTHER_RAW_TOKEN)).not.toBe(digest);
  });

  it('rejects every non-canonical or foreign-namespace secret', () => {
    const material = Buffer.alloc(32, 9).toString('base64url');
    for (const candidate of [
      undefined, null, 42, {},
      material,
      `oacs_v1_${material}`,
      `oas_pr_${material}`,
      `oag_v1_${material}`.slice(0, -1),
      `oag_v1_${material}\n`,
      ` oag_v1_${material}`,
      `oag_v1_${material.toUpperCase()}`,
    ]) {
      expect(() => digestCommerceGrantToken(candidate)).toThrow(ControlGrantStoreError);
    }
    try {
      digestCommerceGrantToken(`oacs_v1_${material}`);
    } catch (error) {
      expect((error as ControlGrantStoreError).code).toBe('CONTROL_GRANT_STORE_INPUT_INVALID');
      expect((error as Error).message).not.toContain(material);
    }
  });
});

describe('issue', () => {
  it('calls the production wrapper, never a core or a fixture mode', async () => {
    const { pool, store } = issueStore([grantRow()]);
    await store.issueForReservedAction(
      HASH, { actionId: ACTION, grantTokenHash: TOKEN_HASH }, metadata(),
    );
    const calls = pool.clients[0]!.calls.map((call) => call.text).join('\n');
    expect(calls).toContain('openarc_durable.issue_authorization_grant(');
    expect(calls).not.toContain('_core(');
    expect(calls).not.toContain('internal_fixture');
    expect(calls).not.toContain('production');
  });

  it('keeps the regenerated token hash OUT of the logical request digest', async () => {
    const first = issueStore([grantRow()]);
    await first.store.issueForReservedAction(
      HASH, { actionId: ACTION, grantTokenHash: TOKEN_HASH }, metadata(),
    );
    const second = issueStore([grantRow()]);
    await second.store.issueForReservedAction(
      HASH, { actionId: ACTION, grantTokenHash: OTHER_TOKEN_HASH }, metadata(),
    );
    const firstCall = first.pool.clients[0]!.calls.find((call) => call.text.includes('issue_authorization_grant'))!;
    const secondCall = second.pool.clients[0]!.calls.find((call) => call.text.includes('issue_authorization_grant'))!;
    // values: [tokenHash, actionId, grantTokenHash, version, mutation, key, digest, context]
    expect(firstCall.values[2]).toBe(TOKEN_HASH);
    expect(secondCall.values[2]).toBe(OTHER_TOKEN_HASH);
    expect(firstCall.values[3]).toBe(1);
    expect(firstCall.values[6]).toBe(secondCall.values[6]);
    expect(firstCall.values[7]).toBe(secondCall.values[7]);
  });

  it('projects the grant metadata and a bound receipt', async () => {
    const { store } = issueStore([grantRow()]);
    const result = await store.issueForReservedAction(
      HASH, { actionId: ACTION, grantTokenHash: TOKEN_HASH }, metadata(),
    );
    expect(result.replayed).toBe(false);
    expect(result.metadata).toMatchObject({
      schemaVersion: 'openarc.control.grant.v1',
      grantId: GRANT,
      organizationId: ORG,
      actionId: ACTION,
      reservationId: RESERVATION,
      generation: '1',
      status: 'issued',
      claimedAt: null,
      revokedAt: null,
    });
    expect(result.receipt).toEqual({
      mutationId: MUTATION,
      operation: 'control.grant.issue',
      resourceType: 'authorization_grant',
      resourceId: GRANT,
      committedAt: '2026-09-12T10:00:00.000000Z',
    });
    expect(JSON.stringify(result)).not.toContain(TOKEN_HASH);
  });

  it('rejects malformed input before touching the pool', async () => {
    const { store, pool } = issueStore([grantRow()]);
    const bad: [unknown, unknown, unknown][] = [
      ['nope', { actionId: ACTION, grantTokenHash: TOKEN_HASH }, metadata()],
      [HASH, { actionId: 'openarc:action:nope', grantTokenHash: TOKEN_HASH }, metadata()],
      [HASH, { actionId: ACTION, grantTokenHash: 'zz' }, metadata()],
      [HASH, { actionId: ACTION }, metadata()],
      [HASH, { actionId: ACTION, grantTokenHash: TOKEN_HASH, extra: 1 }, metadata()],
      [HASH, Object.assign(Object.create({ evil: 1 }), { actionId: ACTION, grantTokenHash: TOKEN_HASH }), metadata()],
      [HASH, { actionId: ACTION, grantTokenHash: TOKEN_HASH }, { idempotencyKey: KEY }],
      [HASH, { actionId: ACTION, grantTokenHash: TOKEN_HASH }, { idempotencyKey: 'short', mutationId: MUTATION }],
      [HASH, { actionId: ACTION, grantTokenHash: TOKEN_HASH }, { idempotencyKey: KEY, mutationId: 'nope' }],
    ];
    for (const [token, input, meta] of bad) {
      await expectCode(
        store.issueForReservedAction(token, input, meta),
        'CONTROL_GRANT_STORE_INPUT_INVALID',
      );
    }
    expect(pool.connectCalls).toBe(0);
  });

  it('collapses a malformed or over-wide grant row to a fixed unavailable', async () => {
    const malformed: Row[] = [
      grantRow({ out_grant_id: 'openarc:grant:nope' }),
      grantRow({ out_generation: '0' }),
      grantRow({ out_generation: 1 }),
      grantRow({ out_status: 'granted' }),
      // A 301-second window can never be projected as a valid grant.
      grantRow({ out_expires_at: '2026-09-12 10:05:01.000000+00' }),
      grantRow({ out_expires_at: '2026-09-12 09:59:00.000000+00' }),
      grantRow({ out_status: 'claimed', out_claimed_at: null }),
      grantRow({ out_replayed: 'yes' }),
      grantRow({ out_action_id: 'openarc:action:00000000-0000-4000-8000-0000000000ff' }),
    ];
    for (const row of malformed) {
      const { store } = issueStore([row]);
      await expectCode(
        store.issueForReservedAction(HASH, { actionId: ACTION, grantTokenHash: TOKEN_HASH }, metadata()),
        'CONTROL_GRANT_STORE_UNAVAILABLE',
      );
    }
    const { store } = issueStore([grantRow(), grantRow()]);
    await expectCode(
      store.issueForReservedAction(HASH, { actionId: ACTION, grantTokenHash: TOKEN_HASH }, metadata()),
      'CONTROL_GRANT_STORE_UNAVAILABLE',
    );
  });

  it('reports a lost COMMIT as OUTCOME_UNKNOWN and destroys the connection', async () => {
    const { store, pool } = storeWith([
      { when: (text) => text.includes('resolve_commerce_action_context'), rows: [contextRow()] },
      { when: (text) => text.includes('issue_authorization_grant'), rows: [grantRow()] },
      { when: (text) => text === 'COMMIT', throws: { code: '08006' } },
    ]);
    await expectCode(
      store.issueForReservedAction(HASH, { actionId: ACTION, grantTokenHash: TOKEN_HASH }, metadata()),
      'CONTROL_GRANT_STORE_OUTCOME_UNKNOWN',
    );
    expect(pool.clients[0]!.releases).toEqual([true]);
  });
});

describe('replace', () => {
  it('calls the production wrapper with the grant id and version 1', async () => {
    const { store, pool } = storeWith([
      { when: (text) => text.includes('resolve_commerce_action_context'), rows: [contextRow()] },
      { when: (text) => text.includes('replace_authorization_grant'), rows: [grantRow({ out_generation: '2' })] },
    ]);
    const result = await store.replaceUnclaimedGrant(
      HASH, { grantId: GRANT, grantTokenHash: OTHER_TOKEN_HASH }, metadata(),
    );
    expect(result.metadata.generation).toBe('2');
    expect(result.receipt.operation).toBe('control.grant.replace');
    const call = pool.clients[0]!.calls.find((entry) => entry.text.includes('replace_authorization_grant'))!;
    expect(call.values[1]).toBe(GRANT);
    expect(call.values[3]).toBe(1);
    expect(call.text).not.toContain('_core(');
  });

  it('rejects a non-canonical grant id and a foreign row', async () => {
    const { store } = storeWith([
      { when: (text) => text.includes('resolve_commerce_action_context'), rows: [contextRow()] },
      { when: (text) => text.includes('replace_authorization_grant'), rows: [grantRow()] },
    ]);
    await expectCode(
      store.replaceUnclaimedGrant(HASH, { grantId: 'openarc:grant:nope', grantTokenHash: TOKEN_HASH }, metadata()),
      'CONTROL_GRANT_STORE_INPUT_INVALID',
    );
    await expectCode(
      store.replaceUnclaimedGrant(
        HASH,
        { grantId: 'openarc:grant:00000000-0000-4000-8000-0000000000aa', grantTokenHash: TOKEN_HASH },
        metadata(),
      ),
      'CONTROL_GRANT_STORE_UNAVAILABLE',
    );
  });
});

describe('introspect and claim', () => {
  it('projects a provider view with the frozen identity and exact integer money', async () => {
    const { store } = storeWith([
      { when: (text) => text.includes('introspect_authorization_grant'), rows: [providerViewRow()] },
    ]);
    const view = await store.introspectGrant(HASH, TOKEN_HASH);
    expect(view).toEqual({
      schemaVersion: 'openarc.control.grant-provider.v1',
      grantId: GRANT,
      actionId: ACTION,
      providerId: PROVIDER,
      listingId: LISTING,
      listingVersion: '1',
      requirementId: REQUIREMENT,
      requirementDigest: DIGEST,
      networkId: 'eip155:5042002',
      asset: 'USDC',
      representation: 'erc20',
      decimals: 6,
      amountAtomic: '1000000',
      feeAtomic: '5',
      debitAtomic: '1000005',
      expiresAt: '2026-09-12T10:05:00.000000Z',
      status: 'issued',
      claimedAttemptId: null,
    });
    // No buyer organization, policy, agent, account or session leaks through.
    const payload = JSON.stringify(view);
    for (const secret of [ORG, POLICY, AGENT, ACCOUNT, SESSION, TOKEN_HASH, HASH]) {
      expect(payload).not.toContain(secret);
    }
  });

  it('refuses a provider view whose debit is not amount + fee', async () => {
    for (const row of [
      providerViewRow({ out_debit_atomic: '1000006' }),
      providerViewRow({ out_amount_atomic: '0' }),
      providerViewRow({ out_amount_atomic: '1.5' }),
      providerViewRow({ out_fee_atomic: '-1' }),
      providerViewRow({ out_debit_atomic: '0' }),
    ]) {
      const { store } = storeWith([
        { when: (text) => text.includes('introspect_authorization_grant'), rows: [row] },
      ]);
      await expectCode(store.introspectGrant(HASH, TOKEN_HASH), 'CONTROL_GRANT_STORE_UNAVAILABLE');
    }
  });

  it('requires both presented hashes to be canonical before any query', async () => {
    const { store, pool } = storeWith([
      { when: (text) => text.includes('introspect_authorization_grant'), rows: [providerViewRow()] },
    ]);
    await expectCode(store.introspectGrant('nope', TOKEN_HASH), 'CONTROL_GRANT_STORE_INPUT_INVALID');
    await expectCode(store.introspectGrant(HASH, 'nope'), 'CONTROL_GRANT_STORE_INPUT_INVALID');
    expect(pool.connectCalls).toBe(0);
  });

  it('binds the claim receipt to the presented attempt and the returned grant', async () => {
    const { store, pool } = storeWith([
      { when: (text) => text.includes('claim_authorization_grant'), rows: [claimRow()] },
    ]);
    const result = await store.claimGrant(
      HASH,
      { grantTokenHash: TOKEN_HASH, expectedActionId: ACTION, attemptId: ATTEMPT },
      metadata(),
    );
    expect(result.replayed).toBe(false);
    expect(result.attemptId).toBe(ATTEMPT);
    expect(result.view.status).toBe('claimed');
    expect(result.view.claimedAttemptId).toBe(ATTEMPT);
    expect(result.claimDigest).toBe(DIGEST);
    expect(result.receipt).toEqual({
      mutationId: MUTATION,
      operation: 'control.grant.claim',
      resourceType: 'authorization_grant',
      resourceId: GRANT,
      committedAt: '2026-09-12T10:01:00.000000Z',
    });
    const call = pool.clients[0]!.calls.find((entry) => entry.text.includes('claim_authorization_grant'))!;
    expect(call.text).not.toContain('_core(');
    expect(call.values[0]).toBe(HASH);
    expect(call.values[2]).toBe(ACTION);
    expect(call.values[3]).toBe(ATTEMPT);
  });

  it('refuses a claim row that answers a different attempt or action', async () => {
    for (const row of [
      claimRow({ out_attempt_id: '00000000-0000-4000-8000-0000000000ee' }),
      claimRow({ out_action_id: 'openarc:action:00000000-0000-4000-8000-0000000000ee' }),
      claimRow({ out_claim_digest: 'sha256:zz' }),
      claimRow({ out_status: 'claimed', out_attempt_id: null }),
    ]) {
      const { store } = storeWith([
        { when: (text) => text.includes('claim_authorization_grant'), rows: [row] },
      ]);
      await expectCode(
        store.claimGrant(
          HASH,
          { grantTokenHash: TOKEN_HASH, expectedActionId: ACTION, attemptId: ATTEMPT },
          metadata(),
        ),
        'CONTROL_GRANT_STORE_UNAVAILABLE',
      );
    }
  });

  it('rejects a non-canonical attempt id and an incomplete claim input', async () => {
    const { store, pool } = storeWith([
      { when: (text) => text.includes('claim_authorization_grant'), rows: [claimRow()] },
    ]);
    for (const input of [
      { grantTokenHash: TOKEN_HASH, expectedActionId: ACTION, attemptId: 'nope' },
      { grantTokenHash: TOKEN_HASH, expectedActionId: ACTION, attemptId: `${ATTEMPT}\n` },
      { grantTokenHash: TOKEN_HASH, expectedActionId: ACTION },
      { grantTokenHash: TOKEN_HASH, expectedActionId: ACTION, attemptId: ATTEMPT, extra: 1 },
    ]) {
      await expectCode(store.claimGrant(HASH, input, metadata()), 'CONTROL_GRANT_STORE_INPUT_INVALID');
    }
    expect(pool.connectCalls).toBe(0);
  });
});

describe('revoke and safe status', () => {
  it('reports the released cleanup facts without any secret', async () => {
    const { store } = revokeStore([
      grantRow({
        out_status: 'revoked',
        out_revoked_at: '2026-09-12 10:02:00.000000+00',
        out_updated_at: '2026-09-12 10:02:00.000000+00',
        out_action_status: 'cancelled',
        out_reservation_status: 'released',
        out_released: true,
      }),
    ]);
    const result = await store.revokeGrant(HASH, ORG, GRANT, metadata());
    expect(result.released).toBe(true);
    expect(result.actionStatus).toBe('cancelled');
    expect(result.reservationStatus).toBe('released');
    expect(result.metadata.status).toBe('revoked');
    expect(result.metadata.claimedAt).toBeNull();
    expect(result.receipt.operation).toBe('control.grant.revoke');
  });

  it('retains a claim instant on a revoked grant that released nothing', async () => {
    const { store } = revokeStore([
      grantRow({
        out_status: 'revoked',
        out_claimed_at: '2026-09-12 10:01:00.000000+00',
        out_revoked_at: '2026-09-12 10:02:00.000000+00',
        out_updated_at: '2026-09-12 10:02:00.000000+00',
        out_action_status: 'grant_issued',
        out_reservation_status: 'claimed',
        out_released: false,
      }),
    ]);
    const result = await store.revokeGrant(HASH, ORG, GRANT, metadata());
    expect(result.released).toBe(false);
    expect(result.reservationStatus).toBe('claimed');
    expect(result.metadata.claimedAt).toBe('2026-09-12T10:01:00.000000Z');
    expect(result.metadata.revokedAt).toBe('2026-09-12T10:02:00.000000Z');
  });

  it('never relabels a row that answers a different organization or grant', async () => {
    const { store } = revokeStore([
      grantRow({
        out_organization_id: OTHER_ORG,
        out_status: 'revoked',
        out_revoked_at: '2026-09-12 10:02:00.000000+00',
        out_updated_at: '2026-09-12 10:02:00.000000+00',
        out_action_status: 'cancelled',
        out_reservation_status: 'released',
        out_released: true,
      }),
    ]);
    await expectCode(store.revokeGrant(HASH, ORG, GRANT, metadata()), 'CONTROL_GRANT_STORE_UNAVAILABLE');
  });

  it('returns null for an absent buyer grant and rejects a foreign projection', async () => {
    const empty = storeWith([
      { when: (text) => text.includes('read_authorization_grant'), rows: [] },
    ]);
    expect(await empty.store.readGrant(HASH, ORG, GRANT)).toBeNull();
    const foreign = storeWith([
      { when: (text) => text.includes('read_authorization_grant'), rows: [grantRow({ out_organization_id: OTHER_ORG })] },
    ]);
    await expectCode(foreign.store.readGrant(HASH, ORG, GRANT), 'CONTROL_GRANT_STORE_UNAVAILABLE');
  });

  it('projects provider attempt status and keeps missing indistinguishable', async () => {
    const found = storeWith([
      { when: (text) => text.includes('read_provider_grant_attempt_status'), rows: [attemptRow({ out_grant_revoked: true })] },
    ]);
    expect(await found.store.readProviderAttemptStatus(HASH, ATTEMPT)).toEqual({
      status: 'claimed',
      attemptId: ATTEMPT,
      grantId: GRANT,
      actionId: ACTION,
      providerId: PROVIDER,
      listingId: LISTING,
      listingVersion: '1',
      claimedAt: '2026-09-12T10:01:00.000000Z',
      grantRevoked: true,
    });
    const missing = storeWith([
      {
        when: (text) => text.includes('read_provider_grant_attempt_status'),
        rows: [{
          out_found: false, out_attempt_id: null, out_grant_id: null, out_action_id: null,
          out_provider_id: null, out_listing_id: null, out_listing_version: null,
          out_claimed_at: null, out_grant_revoked: null,
        }],
      },
    ]);
    const status = await missing.store.readProviderAttemptStatus(HASH, ATTEMPT);
    expect(status).toEqual({ status: 'not_found' });
    expect(Object.keys(status)).toEqual(['status']);
    const mismatched = storeWith([
      {
        when: (text) => text.includes('read_provider_grant_attempt_status'),
        rows: [attemptRow({ out_attempt_id: '00000000-0000-4000-8000-0000000000ee' })],
      },
    ]);
    await expectCode(
      mismatched.store.readProviderAttemptStatus(HASH, ATTEMPT),
      'CONTROL_GRANT_STORE_UNAVAILABLE',
    );
  });
});

function statusRow(overrides: Row = {}): Row {
  return {
    out_mutation_id: MUTATION,
    out_operation: 'control.grant.revoke',
    out_resource_type: 'authorization_grant',
    out_resource_id: GRANT,
    out_committed_at: '2026-09-12 10:02:00.000000+00',
    ...overrides,
  };
}

function humanStatusStore(rows: Row[]): { store: ControlGrantStore; pool: FakePool } {
  return storeWith([
    { when: (text) => text.includes('read_human_grant_mutation_status'), rows },
  ]);
}

function agentStatusStore(rows: Row[]): { store: ControlGrantStore; pool: FakePool } {
  return storeWith([
    { when: (text) => text.includes('read_agent_grant_mutation_status'), rows },
  ]);
}

describe('grant mutation-status recovery', () => {
  it('projects a committed human revoke receipt and a bare not_found', async () => {
    const found = humanStatusStore([statusRow()]);
    const status = await found.store.getHumanMutationStatus(HASH, ORG, MUTATION);
    expect(status).toEqual({
      status: 'committed',
      receipt: {
        mutationId: MUTATION,
        operation: 'control.grant.revoke',
        resourceType: CONTROL_GRANT_RESOURCE_TYPE,
        resourceId: GRANT,
        committedAt: '2026-09-12T10:02:00.000000Z',
      },
    });
    // The helper is reached by name, with the caller arguments in order.
    expect(
      found.pool.clients[0]?.calls.find((call) =>
        call.text.includes('read_human_grant_mutation_status'))?.values,
    ).toEqual([HASH, ORG, MUTATION]);
    const missing = humanStatusStore([]);
    const empty = await missing.store.getHumanMutationStatus(HASH, ORG, MUTATION);
    expect(empty).toEqual({ status: 'not_found' });
    // A miss carries NOTHING besides the discriminator.
    expect(Object.keys(empty)).toEqual(['status']);
  });

  it('projects the two committed agent receipts and a bare not_found', async () => {
    for (const operation of ['control.grant.issue', 'control.grant.replace'] as const) {
      const found = agentStatusStore([
        statusRow({ out_operation: operation, out_organization_id: ORG }),
      ]);
      const status = await found.store.getAgentMutationStatus(TOKEN_HASH, MUTATION);
      expect(status).toEqual({
        status: 'committed',
        receipt: {
          mutationId: MUTATION,
          operation,
          resourceType: CONTROL_GRANT_RESOURCE_TYPE,
          resourceId: GRANT,
          committedAt: '2026-09-12T10:02:00.000000Z',
        },
      });
      expect(
        found.pool.clients[0]?.calls.find((call) =>
          call.text.includes('read_agent_grant_mutation_status'))?.values,
      ).toEqual([TOKEN_HASH, MUTATION]);
    }
    const missing = agentStatusStore([]);
    const empty = await missing.store.getAgentMutationStatus(TOKEN_HASH, MUTATION);
    expect(empty).toEqual({ status: 'not_found' });
    expect(Object.keys(empty)).toEqual(['status']);
  });

  it('never lets one audience surface the other audience\u2019s operation', async () => {
    // The projections are keyed by an explicit non-transposable audience label,
    // so a row that somehow carried the WRONG audience's operation is a fixed
    // UNAVAILABLE, never a receipt the caller was not entitled to.
    for (const operation of ['control.grant.issue', 'control.grant.replace', 'control.grant.claim']) {
      const store = humanStatusStore([statusRow({ out_operation: operation })]);
      await expectCode(
        store.store.getHumanMutationStatus(HASH, ORG, MUTATION),
        'CONTROL_GRANT_STORE_UNAVAILABLE',
      );
    }
    for (const operation of ['control.grant.revoke', 'control.grant.claim']) {
      const store = agentStatusStore([
        statusRow({ out_operation: operation, out_organization_id: ORG }),
      ]);
      await expectCode(
        store.store.getAgentMutationStatus(TOKEN_HASH, MUTATION),
        'CONTROL_GRANT_STORE_UNAVAILABLE',
      );
    }
  });

  it('refuses a row whose mutation id, resource or organization does not answer the request', async () => {
    const OTHER_MUTATION = '00000000-0000-4000-8000-0000000000f2';
    const cases: { rows: Row[]; agent?: boolean }[] = [
      { rows: [statusRow({ out_mutation_id: OTHER_MUTATION })] },
      { rows: [statusRow({ out_resource_type: 'commerce_action' })] },
      { rows: [statusRow({ out_resource_id: ACTION })] },
      { rows: [statusRow({ out_resource_id: null })] },
      { rows: [statusRow({ out_committed_at: 'not-a-timestamp' })] },
    ];
    for (const entry of cases) {
      await expectCode(
        humanStatusStore(entry.rows).store.getHumanMutationStatus(HASH, ORG, MUTATION),
        'CONTROL_GRANT_STORE_UNAVAILABLE',
      );
    }
    // The agent reader additionally re-asserts the DB-DERIVED buyer org.
    for (const org of [null, 'openarc:org:not-canonical', 'a'.repeat(64)]) {
      await expectCode(
        agentStatusStore([
          statusRow({ out_operation: 'control.grant.issue', out_organization_id: org }),
        ]).store.getAgentMutationStatus(TOKEN_HASH, MUTATION),
        'CONTROL_GRANT_STORE_UNAVAILABLE',
      );
    }
    // More than one row for a single mutation id is never a receipt.
    await expectCode(
      humanStatusStore([statusRow(), statusRow()]).store.getHumanMutationStatus(HASH, ORG, MUTATION),
      'CONTROL_GRANT_STORE_UNAVAILABLE',
    );
  });

  it('rejects a malformed hash, organization or mutation id before any SQL', async () => {
    const human = humanStatusStore([statusRow()]);
    for (const bad of ['', 'not-a-hash', `${HASH}\n`, null, 7]) {
      await expectCode(
        human.store.getHumanMutationStatus(bad, ORG, MUTATION),
        'CONTROL_GRANT_STORE_INPUT_INVALID',
      );
    }
    for (const bad of ['', ORG.toUpperCase(), 'openarc:org:zz', null]) {
      await expectCode(
        human.store.getHumanMutationStatus(HASH, bad, MUTATION),
        'CONTROL_GRANT_STORE_INPUT_INVALID',
      );
    }
    for (const bad of ['', MUTATION.toUpperCase(), `${MUTATION}\n`, null]) {
      await expectCode(
        human.store.getHumanMutationStatus(HASH, ORG, bad),
        'CONTROL_GRANT_STORE_INPUT_INVALID',
      );
    }
    const agent = agentStatusStore([statusRow({ out_operation: 'control.grant.issue', out_organization_id: ORG })]);
    for (const bad of ['', 'not-a-hash', `${TOKEN_HASH}\n`, null]) {
      await expectCode(
        agent.store.getAgentMutationStatus(bad, MUTATION),
        'CONTROL_GRANT_STORE_INPUT_INVALID',
      );
    }
    await expectCode(
      agent.store.getAgentMutationStatus(TOKEN_HASH, 'nope'),
      'CONTROL_GRANT_STORE_INPUT_INVALID',
    );
    // Not one statement was issued for any rejected input.
    expect(human.pool.connectCalls).toBe(0);
    expect(agent.pool.connectCalls).toBe(0);
  });

  it('maps a database authority failure onto the fixed non-echoing vocabulary', async () => {
    for (const [code, expected] of [
      ['28000', 'CONTROL_GRANT_STORE_SESSION_INVALID'],
      ['42501', 'CONTROL_GRANT_STORE_FORBIDDEN'],
      ['22023', 'CONTROL_GRANT_STORE_INPUT_INVALID'],
    ] as const) {
      const human = storeWith([
        { when: (text) => text.includes('read_human_grant_mutation_status'), throws: { code, message: `boom ${ORG} ${MUTATION}` } },
      ]);
      await expectCode(human.store.getHumanMutationStatus(HASH, ORG, MUTATION), expected);
      const agent = storeWith([
        { when: (text) => text.includes('read_agent_grant_mutation_status'), throws: { code, message: `boom ${TOKEN_HASH}` } },
      ]);
      await expectCode(agent.store.getAgentMutationStatus(TOKEN_HASH, MUTATION), expected);
    }
    // The raised message never survives into the store error.
    const leaky = storeWith([
      { when: (text) => text.includes('read_human_grant_mutation_status'), throws: { code: '42501', message: `${HASH} ${ORG}` } },
    ]);
    try {
      await leaky.store.getHumanMutationStatus(HASH, ORG, MUTATION);
      throw new Error('expected a rejection');
    } catch (error) {
      expect(error).toBeInstanceOf(ControlGrantStoreError);
      expect((error as Error).message).not.toContain(HASH);
      expect((error as Error).message).not.toContain(ORG);
    }
  });

  it('carries no token, hash or digest in any recovered receipt', async () => {
    const human = await humanStatusStore([statusRow()])
      .store.getHumanMutationStatus(HASH, ORG, MUTATION);
    const agent = await agentStatusStore([
      statusRow({ out_operation: 'control.grant.issue', out_organization_id: ORG }),
    ]).store.getAgentMutationStatus(TOKEN_HASH, MUTATION);
    for (const payload of [JSON.stringify(human), JSON.stringify(agent)]) {
      expect(payload).not.toContain(HASH);
      expect(payload).not.toContain(TOKEN_HASH);
      expect(payload).not.toContain(digestCommerceGrantToken(RAW_TOKEN));
      // No 64-hex value of any kind survives into a status answer.
      expect(/[0-9a-f]{64}/.test(payload)).toBe(false);
    }
  });
});

describe('construction', () => {
  it('rejects a pool without connect and adapts a raw pg pool', () => {
    expect(() => new ControlGrantStore(null as unknown as TenantPool)).toThrow(ControlGrantStoreError);
    expect(() => new ControlGrantStore({} as unknown as TenantPool)).toThrow(ControlGrantStoreError);
    const pool = new FakePool(() => new FakeClient([]));
    expect(asControlGrantPool(pool as never)).toBe(pool);
  });
});
