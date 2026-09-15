import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  CommerceSessionStore,
  CommerceSessionStoreError,
  CONTROL_SESSION_RESOURCE_BY_OPERATION,
  digestCommerceSessionExchangeRequest,
  digestCommerceSessionHumanContext,
  digestCommerceSessionIdempotencyKey,
  digestCommerceSessionIssueRequest,
  digestCommerceSessionMachineContext,
  digestCommerceSessionRevokeRequest,
  parseCommerceHandoffHash,
  parseCommerceSessionId,
  parseCommerceTokenHash,
  type CommerceSessionHumanDigestContext,
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
const HANDOFF = 'b'.repeat(64);
const TOKEN = 'c'.repeat(64);
const ORG = 'openarc:org:00000000-0000-4000-8000-000000000001';
const AGENT = 'openarc:agent:00000000-0000-4000-8000-000000000002';
const POLICY = 'openarc:policy:00000000-0000-4000-8000-000000000003';
const SESSION = '00000000-0000-4000-8000-000000000004';
const MUTATION = '00000000-0000-4000-8000-000000000005';
const CREDENTIAL = '00000000-0000-4000-8000-000000000006';
const KEY = 'A'.repeat(42) + 'A';
const ACCOUNT = 'openarc:account:00000000-0000-4000-8000-00000000000a';

function metadata(): Row {
  return { mutationId: MUTATION, idempotencyKey: KEY };
}

function mutationRow(operation: string, replayed: boolean, overrides: Row = {}): Row {
  return {
    out_replayed: replayed,
    out_session_id: SESSION,
    out_organization_id: ORG,
    out_subject_agent_id: AGENT,
    out_policy_id: POLICY,
    out_issued_at: '2026-09-12 10:00:00.000001+00',
    out_initial_expires_at: '2026-09-12 10:05:00.000000+00',
    out_expires_at: '2026-09-12 10:05:00.000000+00',
    out_exchanged_at: operation === 'control.commerce_session.exchange' ? '2026-09-12 10:00:30.000000+00' : null,
    out_agent_session_id: operation === 'control.commerce_session.exchange' ? CREDENTIAL : null,
    out_credential_id: operation === 'control.commerce_session.exchange' ? CREDENTIAL : null,
    out_revoked_at: operation === 'control.commerce_session.revoke' ? '2026-09-12 10:01:00.000000+00' : null,
    out_handoff_expires_at:
      operation === 'control.commerce_session.revoke' ? null : '2026-09-12 10:03:00.000000+00',
    out_committed_at: '2026-09-12 10:00:00.123456+00',
    ...overrides,
  };
}

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(CommerceSessionStoreError);
    expect((error as CommerceSessionStoreError).code).toBe(code);
    return;
  }
  throw new Error(`expected CommerceSessionStoreError ${code}`);
}

describe('commerce-session digest determinism and binding', () => {
  it('is domain-separated and stable for human/machine contexts', () => {
    expect(digestCommerceSessionHumanContext('control.commerce_session.issue', HASH)).toHaveLength(64);
    expect(digestCommerceSessionHumanContext('control.commerce_session.issue', HASH)).not.toBe(
      digestCommerceSessionHumanContext('control.commerce_session.revoke', HASH),
    );
    expect(digestCommerceSessionMachineContext(HASH)).not.toBe(
      digestCommerceSessionHumanContext('control.commerce_session.issue', HASH),
    );
    expect(digestCommerceSessionIdempotencyKey('control.commerce_session.issue', KEY)).toHaveLength(64);
    expect(() => digestCommerceSessionHumanContext('control.commerce_session.issue', 'nope')).toThrow();
  });

  const context: CommerceSessionHumanDigestContext = {
    organizationId: ORG,
    actorAccountId: ACCOUNT,
    actorRole: 'owner',
    sessionContextDigest: digestCommerceSessionHumanContext('control.commerce_session.issue', HASH),
    mutationId: MUTATION,
  };

  it('changes when any bound issue field changes and never binds random handoff material', () => {
    const base = digestCommerceSessionIssueRequest(context, AGENT, POLICY, 300);
    expect(base).toHaveLength(64);
    expect(digestCommerceSessionIssueRequest(context, AGENT, POLICY, 301)).not.toBe(base);
    expect(
      digestCommerceSessionIssueRequest(
        { ...context, sessionContextDigest: digestCommerceSessionHumanContext('control.commerce_session.issue', TOKEN) },
        AGENT,
        POLICY,
        300,
      ),
    ).not.toBe(base);
    // Regenerated random handoff material is not an input to the digest at all.
    expect(digestCommerceSessionIssueRequest(context, AGENT, POLICY, 300)).toBe(base);
  });

  it('binds the exact machine session and credential on exchange', () => {
    const sessionContextDigest = digestCommerceSessionMachineContext(HASH);
    const machine = {
      organizationId: ORG,
      issuerAccountId: ACCOUNT,
      agentSessionHash: HASH,
      credentialId: CREDENTIAL,
      handoffHash: HANDOFF,
      sessionContextDigest,
      mutationId: MUTATION,
    };
    const base = digestCommerceSessionExchangeRequest(machine);
    expect(base).toHaveLength(64);
    expect(
      digestCommerceSessionExchangeRequest({ ...machine, credentialId: SESSION }),
    ).not.toBe(base);
    expect(
      digestCommerceSessionExchangeRequest({ ...machine, agentSessionHash: TOKEN }),
    ).not.toBe(base);
    expect(
      digestCommerceSessionExchangeRequest({ ...machine, handoffHash: TOKEN }),
    ).not.toBe(base);
    expect(() =>
      digestCommerceSessionExchangeRequest({ ...machine, handoffHash: 'nope' }),
    ).toThrow();
  });

  it('binds the target session on revoke', () => {
    const revokeContext = {
      ...context,
      sessionContextDigest: digestCommerceSessionHumanContext('control.commerce_session.revoke', HASH),
    };
    const base = digestCommerceSessionRevokeRequest(revokeContext, SESSION);
    expect(base).toHaveLength(64);
    expect(digestCommerceSessionRevokeRequest(revokeContext, CREDENTIAL)).not.toBe(base);
  });

  it('parses canonical identifiers and rejects near misses', () => {
    expect(parseCommerceSessionId(SESSION)).toBe(SESSION);
    expect(() => parseCommerceSessionId(`${SESSION}\n`)).toThrow();
    expect(() => parseCommerceSessionId('not-a-uuid')).toThrow();
    expect(parseCommerceHandoffHash(HANDOFF)).toBe(HANDOFF);
    expect(() => parseCommerceHandoffHash('A'.repeat(64))).toThrow();
    expect(parseCommerceTokenHash(TOKEN)).toBe(TOKEN);
    expect(() => parseCommerceTokenHash('x')).toThrow();
    expect(CONTROL_SESSION_RESOURCE_BY_OPERATION['control.commerce_session.revoke']).toBe('commerce_session');
  });
});

describe('CommerceSessionStore mutation projection', () => {
  const WRITER_ROUTE: Route = {
    when: (text) => text.includes('lock_commerce_writer'),
    rows: [{ out_actor: ACCOUNT, out_role: 'owner' }],
  };
  const MACHINE_ROUTE: Route = {
    when: (text) => text.includes('resolve_agent_session_context'),
    rows: [{ out_organization_id: ORG, out_credential_id: CREDENTIAL, out_issuer_account_id: ACCOUNT }],
  };

  it('projects a fresh issue with a bounded handoff expiry', async () => {
    const pool = new FakePool(() =>
      new FakeClient([
        WRITER_ROUTE,
        { when: (text) => text.includes('issue_commerce_session'), rows: [mutationRow('control.commerce_session.issue', false)] },
      ]),
    );
    const result = await new CommerceSessionStore(pool).issueCommerceSession(
      HASH,
      ORG,
      { subjectAgentId: AGENT, policyId: POLICY, handoffHash: HANDOFF, hashVersion: 1 },
      metadata(),
    );
    expect(result.replayed).toBe(false);
    expect(result.receipt.operation).toBe('control.commerce_session.issue');
    expect(result.receipt.resourceId).toBe(SESSION);
    expect(result.handoffExpiresAt).toBe('2026-09-12T10:03:00.000000Z');
    expect(JSON.stringify(result)).not.toContain(HASH);
  });

  it('projects an exchange and a revoke with a non-null exchanged/revoked timestamp', async () => {
    const exchange = new FakePool(() =>
      new FakeClient([
        MACHINE_ROUTE,
        { when: (text) => text.includes('exchange_commerce_session'), rows: [mutationRow('control.commerce_session.exchange', false)] },
      ]),
    );
    const exchanged = await new CommerceSessionStore(exchange).exchangeCommerceSession(
      HASH,
      HANDOFF,
      { tokenHash: TOKEN, hashVersion: 1 },
      metadata(),
    );
    expect(exchanged.metadata.exchangedAt).toBe('2026-09-12T10:00:30.000000Z');
    expect(exchanged.receipt.operation).toBe('control.commerce_session.exchange');

    const revoke = new FakePool(() =>
      new FakeClient([
        WRITER_ROUTE,
        { when: (text) => text.includes('revoke_commerce_session'), rows: [mutationRow('control.commerce_session.revoke', false)] },
      ]),
    );
    const revoked = await new CommerceSessionStore(revoke).revokeCommerceSession(HASH, ORG, SESSION, metadata());
    expect(revoked.metadata.revokedAt).not.toBeNull();
  });

  it('replays safely and never echoes a raw session/token hash', async () => {
    const pool = new FakePool(() =>
      new FakeClient([
        WRITER_ROUTE,
        { when: (text) => text.includes('issue_commerce_session'), rows: [mutationRow('control.commerce_session.issue', true)] },
      ]),
    );
    const result = await new CommerceSessionStore(pool).issueCommerceSession(
      HASH,
      ORG,
      { subjectAgentId: AGENT, policyId: POLICY, handoffHash: HANDOFF, hashVersion: 1 },
      metadata(),
    );
    expect(result.replayed).toBe(true);
    expect(JSON.stringify(result)).not.toContain(HANDOFF);
    expect(JSON.stringify(result)).not.toContain(HASH);
  });

  it('maps a lost COMMIT reply to OUTCOME_UNKNOWN without resending', async () => {
    const client = new FakeClient([
      WRITER_ROUTE,
      { when: (text) => text.includes('issue_commerce_session'), rows: [mutationRow('control.commerce_session.issue', false)] },
      { when: (text) => text === 'COMMIT', throws: { message: 'connection reset' } },
    ]);
    const pool = new FakePool(() => client);
    await expectCode(
      new CommerceSessionStore(pool).issueCommerceSession(
        HASH,
        ORG,
        { subjectAgentId: AGENT, policyId: POLICY, handoffHash: HANDOFF, hashVersion: 1 },
        metadata(),
      ),
      'COMMERCE_SESSION_STORE_OUTCOME_UNKNOWN',
    );
    expect(client.releases).toContain(true);
  });

  it('normalizes a driver failure without echoing values or messages', async () => {
    const secret = 'raw-parent-hash-should-not-leak';
    const client = new FakeClient([
      { when: (text) => text.includes('lock_commerce_writer'), throws: { code: '42501', message: secret } },
    ]);
    try {
      await new CommerceSessionStore(new FakePool(() => client)).issueCommerceSession(
        HASH,
        ORG,
        { subjectAgentId: AGENT, policyId: POLICY, handoffHash: HANDOFF, hashVersion: 1 },
        metadata(),
      );
      throw new Error('expected rejection');
    } catch (error) {
      expect(error).toBeInstanceOf(CommerceSessionStoreError);
      expect((error as CommerceSessionStoreError).code).toBe('COMMERCE_SESSION_STORE_FORBIDDEN');
      expect((error as Error).message).not.toContain(secret);
      expect((error as Error).message).not.toContain(HASH);
    }
  });

  it('rejects malformed inputs before any query', async () => {
    const pool = new FakePool(() => new FakeClient([]));
    const store = new CommerceSessionStore(pool);
    await expectCode(
      store.issueCommerceSession(HASH, ORG, { subjectAgentId: AGENT, policyId: POLICY, handoffHash: 'x', hashVersion: 1 }, metadata()),
      'COMMERCE_SESSION_STORE_INPUT_INVALID',
    );
    await expectCode(
      store.issueCommerceSession(HASH, ORG, { subjectAgentId: AGENT, policyId: POLICY, handoffHash: HANDOFF, hashVersion: 2 as 1 }, metadata()),
      'COMMERCE_SESSION_STORE_INPUT_INVALID',
    );
    await expectCode(
      store.issueCommerceSession(HASH, ORG, { subjectAgentId: AGENT, policyId: POLICY, handoffHash: HANDOFF, hashVersion: 1 }, { mutationId: MUTATION }),
      'COMMERCE_SESSION_STORE_INPUT_INVALID',
    );
    await expectCode(
      store.issueCommerceSession(HASH, ORG, { subjectAgentId: AGENT, policyId: POLICY, handoffHash: HANDOFF, hashVersion: 1 }, { ...metadata(), extra: true }),
      'COMMERCE_SESSION_STORE_INPUT_INVALID',
    );
    await expectCode(store.listCommerceSessions(HASH, ORG, { limit: 51 }), 'COMMERCE_SESSION_STORE_INPUT_INVALID');
    expect(pool.connectCalls).toBe(0);
  });
});

describe('CommerceSessionStore read projections', () => {
  const READER_ROUTE: Route = {
    when: (text) => text.includes('lock_commerce_reader'),
    rows: [{ out_actor: ACCOUNT, out_role: 'owner' }],
  };

  function sessionRow(overrides: Row = {}): Row {
    const base: Row = {
      out_session_id: SESSION,
      out_organization_id: ORG,
      out_subject_agent_id: AGENT,
      out_policy_id: POLICY,
      out_issued_at: '2026-09-12 10:00:00.000001+00',
      out_initial_expires_at: '2026-09-12 10:05:00.000000+00',
      out_expires_at: '2026-09-12 10:05:00.000000+00',
      out_exchanged_at: null,
      out_agent_session_id: null,
      out_credential_id: null,
      out_revoked_at: null,
      ...overrides,
    };
    // The SQL helpers derive a DB-time status column; the fake mirrors the
    // precedence the store re-validates against the strict DTO.
    if (base['out_revoked_at'] !== null) base['out_status'] = 'revoked';
    else if (base['out_exchanged_at'] !== null) base['out_status'] = 'active';
    else base['out_status'] = 'handoff_pending';
    // The SQL helpers pair the machine binding with exchanged_at.
    if (base['out_exchanged_at'] !== null) {
      base['out_agent_session_id'] = base['out_agent_session_id'] ?? CREDENTIAL;
      base['out_credential_id'] = base['out_credential_id'] ?? CREDENTIAL;
    }
    return base;
  }

  it('derives handoff_pending/active/revoked status from the row', async () => {
    const pending = new FakePool(() =>
      new FakeClient([READER_ROUTE, { when: (text) => text.includes('read_commerce_session'), rows: [sessionRow()] }]),
    );
    expect((await new CommerceSessionStore(pending).getCommerceSessionStatus(HASH, ORG, SESSION)).item?.status).toBe('handoff_pending');

    const active = new FakePool(() =>
      new FakeClient([
        READER_ROUTE,
        { when: (text) => text.includes('read_commerce_session'), rows: [sessionRow({ out_exchanged_at: '2026-09-12 10:00:30.000000+00' })] },
      ]),
    );
    expect((await new CommerceSessionStore(active).getCommerceSessionStatus(HASH, ORG, SESSION)).item?.status).toBe('active');

    const revoked = new FakePool(() =>
      new FakeClient([
        READER_ROUTE,
        { when: (text) => text.includes('read_commerce_session'), rows: [sessionRow({ out_revoked_at: '2026-09-12 10:01:00.000000+00' })] },
      ]),
    );
    expect((await new CommerceSessionStore(revoked).getCommerceSessionStatus(HASH, ORG, SESSION)).item?.status).toBe('revoked');
  });

  it('returns null for a missing session and rejects a foreign-bound row', async () => {
    const missing = new FakePool(() =>
      new FakeClient([READER_ROUTE, { when: (text) => text.includes('read_commerce_session'), rows: [] }]),
    );
    await expect(new CommerceSessionStore(missing).getCommerceSessionStatus(HASH, ORG, SESSION)).resolves.toEqual({
      organizationId: ORG,
      item: null,
    });
    const foreign = new FakePool(() =>
      new FakeClient([
        READER_ROUTE,
        { when: (text) => text.includes('read_commerce_session'), rows: [sessionRow({ out_organization_id: 'openarc:org:00000000-0000-4000-8000-0000000000bb' })] },
      ]),
    );
    await expectCode(new CommerceSessionStore(foreign).getCommerceSessionStatus(HASH, ORG, SESSION), 'COMMERCE_SESSION_STORE_UNAVAILABLE');
  });

  it('validates the whole list lookahead before slicing', async () => {
    const unordered = new FakePool(() =>
      new FakeClient([
        READER_ROUTE,
        {
          when: (text) => text.includes('list_commerce_sessions'),
          rows: [sessionRow(), sessionRow({ out_session_id: SESSION })],
        },
      ]),
    );
    await expectCode(new CommerceSessionStore(unordered).listCommerceSessions(HASH, ORG, { limit: 1 }), 'COMMERCE_SESSION_STORE_UNAVAILABLE');

    const ordered = new FakePool(() =>
      new FakeClient([
        READER_ROUTE,
        {
          when: (text) => text.includes('list_commerce_sessions'),
          rows: [sessionRow(), sessionRow({ out_session_id: '00000000-0000-4000-8000-0000000000ff' })],
        },
      ]),
    );
    const page = await new CommerceSessionStore(ordered).listCommerceSessions(HASH, ORG, { limit: 1 });
    expect(page.items).toHaveLength(1);
    expect(page.nextCursor).toBe(SESSION);
  });

  it('resolves committed mutation status and rejects a malformed operation tuple', async () => {
    const committed = new FakePool(() =>
      new FakeClient([
        READER_ROUTE,
        {
          when: (text) => text.includes('read_human_commerce_session_mutation_status'),
          rows: [
            {
              out_mutation_id: MUTATION,
              out_operation: 'control.commerce_session.issue',
              out_resource_type: 'commerce_session',
              out_resource_id: SESSION,
              out_committed_at: '2026-09-12 10:00:00.123456+00',
            },
          ],
        },
      ]),
    );
    const status = await new CommerceSessionStore(committed).getHumanCommerceSessionMutationStatus(HASH, ORG, MUTATION);
    expect(status.status).toBe('committed');
    if (status.status === 'committed') expect(status.receipt.resourceId).toBe(SESSION);

    const malformed = new FakePool(() =>
      new FakeClient([
        READER_ROUTE,
        {
          when: (text) => text.includes('read_human_commerce_session_mutation_status'),
          rows: [
            {
              out_mutation_id: MUTATION,
              out_operation: 'control.commerce_session.issue',
              out_resource_type: 'agent_credential',
              out_resource_id: SESSION,
              out_committed_at: '2026-09-12 10:00:00.123456+00',
            },
          ],
        },
      ]),
    );
    await expectCode(
      new CommerceSessionStore(malformed).getHumanCommerceSessionMutationStatus(HASH, ORG, MUTATION),
      'COMMERCE_SESSION_STORE_UNAVAILABLE',
    );
  });

  it('collapses malformed driver canaries to a fixed error without echo', async () => {
    const canary = 'raw-canary-should-not-leak';
    const pool = new FakePool(() =>
      new FakeClient([
        READER_ROUTE,
        {
          when: (text) => text.includes('read_human_commerce_session_mutation_status'),
          rows: [
            {
              out_mutation_id: canary,
              out_operation: canary,
              out_resource_type: canary,
              out_resource_id: canary,
              out_committed_at: '2026-09-12 10:00:00.123456+00',
            },
          ],
        },
      ]),
    );
    try {
      await new CommerceSessionStore(pool).getHumanCommerceSessionMutationStatus(HASH, ORG, MUTATION);
      throw new Error('expected rejection');
    } catch (error) {
      expect(error).toBeInstanceOf(CommerceSessionStoreError);
      expect((error as CommerceSessionStoreError).code).toBe('COMMERCE_SESSION_STORE_UNAVAILABLE');
      expect((error as Error).message).not.toContain(canary);
    }
  });

  it('exposes tsc-independent digest helper values', () => {
    expect(createHash('sha256').update('x').digest('hex')).toHaveLength(64);
  });
});

describe('CommerceSessionStore strict projection canaries', () => {
  const READER_ROUTE: Route = {
    when: (text) => text.includes('lock_commerce_reader'),
    rows: [{ out_actor: ACCOUNT, out_role: 'owner' }],
  };
  const MACHINE_ROUTE: Route = {
    when: (text) => text.includes('resolve_agent_session_context'),
    rows: [{ out_organization_id: ORG, out_credential_id: CREDENTIAL, out_issuer_account_id: ACCOUNT }],
  };

  function statusRow(overrides: Row = {}): Row {
    const base: Row = {
      out_session_id: SESSION,
      out_organization_id: ORG,
      out_subject_agent_id: AGENT,
      out_policy_id: POLICY,
      out_issued_at: '2026-09-12 10:00:00.000001+00',
      out_initial_expires_at: '2026-09-12 10:05:00.000000+00',
      out_expires_at: '2026-09-12 10:05:00.000000+00',
      out_exchanged_at: null,
      out_agent_session_id: null,
      out_credential_id: null,
      out_revoked_at: null,
      out_status: 'handoff_pending',
      ...overrides,
    };
    return base;
  }

  async function expectStatusUnavailable(rows: Row[]): Promise<void> {
    const pool = new FakePool(() =>
      new FakeClient([READER_ROUTE, { when: (text) => text.includes('read_commerce_session'), rows }]),
    );
    await expectCode(
      new CommerceSessionStore(pool).getCommerceSessionStatus(HASH, ORG, SESSION),
      'COMMERCE_SESSION_STORE_UNAVAILABLE',
    );
  }

  it('rejects an unknown/internal projected column', async () => {
    await expectStatusUnavailable([statusRow({ out_token_hash: TOKEN })]);
    await expectStatusUnavailable([statusRow({ out_parent_human_session_hash: HASH })]);
  });

  it('rejects a missing required projected column', async () => {
    const row = statusRow();
    delete row['out_revoked_at'];
    await expectStatusUnavailable([row]);
  });

  it('rejects a non-canonical subject agent id', async () => {
    await expectStatusUnavailable([statusRow({ out_subject_agent_id: AGENT.slice(1) })]);
  });

  it('rejects a foreign organisation id', async () => {
    await expectStatusUnavailable([
      statusRow({ out_organization_id: 'openarc:org:00000000-0000-4000-8000-0000000000bb' }),
    ]);
  });

  it('rejects a session id that does not echo the requested target', async () => {
    await expectStatusUnavailable([statusRow({ out_session_id: CREDENTIAL })]);
  });

  it('rejects a malformed timestamp unit', async () => {
    await expectStatusUnavailable([statusRow({ out_issued_at: '2026-09-12T10:00:00.000000Z' })]);
  });

  it('rejects a status value outside the closed enum', async () => {
    await expectStatusUnavailable([statusRow({ out_status: 'settled' })]);
  });

  it('rejects a status that contradicts its metadata', async () => {
    await expectStatusUnavailable([
      statusRow({ out_status: 'revoked', out_revoked_at: null }),
    ]);
    await expectStatusUnavailable([
      statusRow({ out_status: 'handoff_pending', out_exchanged_at: '2026-09-12 10:00:30.000000+00' }),
    ]);
  });

  it('rejects a wrong or echoed mutation id in mutation status', async () => {
    const mismatched = new FakePool(() =>
      new FakeClient([
        READER_ROUTE,
        {
          when: (text) => text.includes('read_human_commerce_session_mutation_status'),
          rows: [
            {
              out_mutation_id: CREDENTIAL,
              out_operation: 'control.commerce_session.issue',
              out_resource_type: 'commerce_session',
              out_resource_id: SESSION,
              out_committed_at: '2026-09-12 10:00:00.123456+00',
            },
          ],
        },
      ]),
    );
    await expectCode(
      new CommerceSessionStore(mismatched).getHumanCommerceSessionMutationStatus(HASH, ORG, MUTATION),
      'COMMERCE_SESSION_STORE_UNAVAILABLE',
    );
  });

  it('rejects an unknown key or a missing key in mutation status', async () => {
    const unknown = new FakePool(() =>
      new FakeClient([
        READER_ROUTE,
        {
          when: (text) => text.includes('read_human_commerce_session_mutation_status'),
          rows: [
            {
              out_mutation_id: MUTATION,
              out_operation: 'control.commerce_session.issue',
              out_resource_type: 'commerce_session',
              out_resource_id: SESSION,
              out_committed_at: '2026-09-12 10:00:00.123456+00',
              out_secret: TOKEN,
            },
          ],
        },
      ]),
    );
    await expectCode(
      new CommerceSessionStore(unknown).getHumanCommerceSessionMutationStatus(HASH, ORG, MUTATION),
      'COMMERCE_SESSION_STORE_UNAVAILABLE',
    );
    const missing = new FakePool(() =>
      new FakeClient([
        READER_ROUTE,
        {
          when: (text) => text.includes('read_human_commerce_session_mutation_status'),
          rows: [
            {
              out_mutation_id: MUTATION,
              out_operation: 'control.commerce_session.issue',
              out_resource_type: 'commerce_session',
              out_committed_at: '2026-09-12 10:00:00.123456+00',
            },
          ],
        },
      ]),
    );
    await expectCode(
      new CommerceSessionStore(missing).getHumanCommerceSessionMutationStatus(HASH, ORG, MUTATION),
      'COMMERCE_SESSION_STORE_UNAVAILABLE',
    );
  });

  it('rejects a non-boolean replayed flag', async () => {
    // A driver that coerces "true"/1 to a truthy non-boolean must fail closed.
    const mutationPool = new FakePool(() =>
      new FakeClient([
        {
          when: (text) => text.includes('lock_commerce_writer'),
          rows: [{ out_actor: ACCOUNT, out_role: 'owner' }],
        },
        {
          when: (text) => text.includes('issue_commerce_session'),
          rows: [{ ...mutationRow('control.commerce_session.issue', false), out_replayed: 1 }],
        },
      ]),
    );
    await expectCode(
      new CommerceSessionStore(mutationPool).issueCommerceSession(
        HASH,
        ORG,
        { subjectAgentId: AGENT, policyId: POLICY, handoffHash: HANDOFF, hashVersion: 1 },
        metadata(),
      ),
      'COMMERCE_SESSION_STORE_UNAVAILABLE',
    );
  });

  it('rejects unknown keys in issue and exchange inputs before any query', async () => {
    const pool = new FakePool(() => new FakeClient([]));
    const store = new CommerceSessionStore(pool);
    await expectCode(
      store.issueCommerceSession(
        HASH,
        ORG,
        { subjectAgentId: AGENT, policyId: POLICY, handoffHash: HANDOFF, hashVersion: 1, secret: TOKEN },
        metadata(),
      ),
      'COMMERCE_SESSION_STORE_INPUT_INVALID',
    );
    await expectCode(
      store.exchangeCommerceSession(HASH, HANDOFF, { tokenHash: TOKEN, hashVersion: 1, secret: TOKEN } as never, metadata()),
      'COMMERCE_SESSION_STORE_INPUT_INVALID',
    );
    expect(pool.connectCalls).toBe(0);
  });

  it('rejects a non-canonical resource id in human mutation status', async () => {
    const pool = new FakePool(() =>
      new FakeClient([
        READER_ROUTE,
        {
          when: (text) => text.includes('read_human_commerce_session_mutation_status'),
          rows: [
            {
              out_mutation_id: MUTATION,
              out_operation: 'control.commerce_session.issue',
              out_resource_type: 'commerce_session',
              out_resource_id: 'not-a-uuid',
              out_committed_at: '2026-09-12 10:00:00.123456+00',
            },
          ],
        },
      ]),
    );
    await expectCode(
      new CommerceSessionStore(pool).getHumanCommerceSessionMutationStatus(HASH, ORG, MUTATION),
      'COMMERCE_SESSION_STORE_UNAVAILABLE',
    );
  });

  it('rejects a non-canonical organization in agent mutation status', async () => {
    const pool = new FakePool(() =>
      new FakeClient([
        {
          when: (text) => text.includes('read_agent_commerce_session_mutation_status'),
          rows: [
            {
              out_mutation_id: MUTATION,
              out_operation: 'control.commerce_session.exchange',
              out_resource_type: 'commerce_session',
              out_resource_id: SESSION,
              out_committed_at: '2026-09-12 10:00:00.123456+00',
              out_organization_id: 'not-an-org',
            },
          ],
        },
      ]),
    );
    await expectCode(
      new CommerceSessionStore(pool).getAgentCommerceSessionMutationStatus(HASH, MUTATION),
      'COMMERCE_SESSION_STORE_UNAVAILABLE',
    );
  });

  it('rejects a machine binding that disagrees with exchangedAt', async () => {
    await expectStatusUnavailable([
      statusRow({ out_exchanged_at: '2026-09-12 10:00:30.000000+00' }),
    ]);
    await expectStatusUnavailable([
      statusRow({
        out_agent_session_id: CREDENTIAL,
        out_credential_id: null,
        out_exchanged_at: '2026-09-12 10:00:30.000000+00',
      }),
    ]);
    await expectStatusUnavailable([
      statusRow({
        out_agent_session_id: 'not-canonical',
        out_credential_id: CREDENTIAL,
        out_exchanged_at: '2026-09-12 10:00:30.000000+00',
      }),
    ]);
  });

  it('rejects a present-undefined agent session id before paired/null logic', async () => {
    await expectStatusUnavailable([statusRow({ out_agent_session_id: undefined })]);
  });

  it('rejects a present-undefined credential id before paired/null logic', async () => {
    await expectStatusUnavailable([statusRow({ out_credential_id: undefined })]);
  });

  it('rejects a present-undefined revoke handoff expiry where SQL returns exact NULL', async () => {
    const pool = new FakePool(() =>
      new FakeClient([
        {
          when: (text) => text.includes('lock_commerce_writer'),
          rows: [{ out_actor: ACCOUNT, out_role: 'owner' }],
        },
        {
          when: (text) => text.includes('revoke_commerce_session'),
          rows: [mutationRow('control.commerce_session.revoke', false, {
            out_handoff_expires_at: undefined,
          })],
        },
      ]),
    );
    await expectCode(
      new CommerceSessionStore(pool).revokeCommerceSession(HASH, ORG, SESSION, metadata()),
      'COMMERCE_SESSION_STORE_UNAVAILABLE',
    );
  });

  it('rejects an initial expiry beyond issued+900s or an effective expiry beyond initial', async () => {
    await expectStatusUnavailable([
      statusRow({
        out_issued_at: '2026-09-12 10:00:00.000000+00',
        out_initial_expires_at: '2026-09-12 10:20:00.000000+00',
        out_expires_at: '2026-09-12 10:10:00.000000+00',
      }),
    ]);
    await expectStatusUnavailable([
      statusRow({
        out_issued_at: '2026-09-12 10:00:00.000000+00',
        out_initial_expires_at: '2026-09-12 10:05:00.000000+00',
        out_expires_at: '2026-09-12 10:06:00.000000+00',
      }),
    ]);
  });

  it('rejects a revoke row that still carries a handoff binding', async () => {
    const pool = new FakePool(() =>
      new FakeClient([
        {
          when: (text) => text.includes('lock_commerce_writer'),
          rows: [{ out_actor: ACCOUNT, out_role: 'owner' }],
        },
        {
          when: (text) => text.includes('revoke_commerce_session'),
          rows: [mutationRow('control.commerce_session.revoke', false, {
            out_handoff_expires_at: '2026-09-12 10:03:00.000000+00',
          })],
        },
      ]),
    );
    await expectCode(
      new CommerceSessionStore(pool).revokeCommerceSession(HASH, ORG, SESSION, metadata()),
      'COMMERCE_SESSION_STORE_UNAVAILABLE',
    );
  });

  it('rejects an exchange row with no bound handoff expiry', async () => {
    const pool = new FakePool(() =>
      new FakeClient([
        MACHINE_ROUTE,
        {
          when: (text) => text.includes('exchange_commerce_session'),
          rows: [mutationRow('control.commerce_session.exchange', false, { out_handoff_expires_at: null })],
        },
      ]),
    );
    await expectCode(
      new CommerceSessionStore(pool).exchangeCommerceSession(
        HASH,
        HANDOFF,
        { tokenHash: TOKEN, hashVersion: 1 },
        metadata(),
      ),
      'COMMERCE_SESSION_STORE_UNAVAILABLE',
    );
  });
});

/**
 * schema13 bearer read. The agent lane presents only a commerce-session token,
 * so the store must resolve it without an organization or session id, must
 * report a revoked/expired session truthfully rather than hiding it, and must
 * never let an internal hash column survive into the projection.
 */
describe('CommerceSessionStore bearer session read', () => {
  const BY_TOKEN = (text: string): boolean => text.includes('read_commerce_session_by_token');

  function bearerRow(overrides: Row = {}): Row {
    return {
      out_session_id: SESSION,
      out_organization_id: ORG,
      out_subject_agent_id: AGENT,
      out_policy_id: POLICY,
      out_issued_at: '2026-09-12 10:00:00.000001+00',
      out_initial_expires_at: '2026-09-12 10:05:00.000000+00',
      out_expires_at: '2026-09-12 10:05:00.000000+00',
      out_exchanged_at: '2026-09-12 10:00:30.000000+00',
      out_agent_session_id: CREDENTIAL,
      out_credential_id: CREDENTIAL,
      out_revoked_at: null,
      ...overrides,
    };
  }

  function pool(rows: Row[] | undefined, extra: Route[] = []): FakePool {
    return new FakePool(
      () => new FakeClient([...extra, { when: BY_TOKEN, ...(rows === undefined ? {} : { rows }) }]),
    );
  }

  it('projects an exchanged session and passes the hash only as a bound parameter', async () => {
    const fake = pool([bearerRow()]);
    const metadata = await new CommerceSessionStore(fake).getCommerceSessionByHash(TOKEN);
    expect(metadata).toEqual({
      schemaVersion: 'openarc.control.commerce-session.v1',
      sessionId: SESSION,
      organizationId: ORG,
      subjectAgentId: AGENT,
      policyId: POLICY,
      scopes: ['commerce.authorize'],
      networkId: 'eip155:5042002',
      asset: 'USDC',
      representation: 'erc20',
      decimals: 6,
      issuedAt: '2026-09-12T10:00:00.000001Z',
      expiresAt: '2026-09-12T10:05:00.000000Z',
      exchangedAt: '2026-09-12T10:00:30.000000Z',
      revokedAt: null,
    });
    // No token hash, machine binding or digest survives into the output.
    expect(JSON.stringify(metadata)).not.toContain(TOKEN);
    expect(JSON.stringify(metadata)).not.toContain(CREDENTIAL);
    expect(/[0-9a-f]{64}/.test(JSON.stringify(metadata))).toBe(false);
    // The bearer travels as a bound parameter, never interpolated into SQL.
    const call = fake.clients[0]?.calls.find((entry) => BY_TOKEN(entry.text));
    expect(call?.values).toEqual([TOKEN]);
    expect(call?.text).not.toContain(TOKEN);
  });

  it('reports a revoked session instead of hiding it', async () => {
    const metadata = await new CommerceSessionStore(
      pool([bearerRow({ out_revoked_at: '2026-09-12 10:01:00.000000+00' })]),
    ).getCommerceSessionByHash(TOKEN);
    expect(metadata?.revokedAt).toBe('2026-09-12T10:01:00.000000Z');
    expect(metadata?.sessionId).toBe(SESSION);
  });

  it('reports the real expiry of an exchange-shortened session', async () => {
    const metadata = await new CommerceSessionStore(
      pool([bearerRow({ out_expires_at: '2026-09-12 10:00:31.000000+00' })]),
    ).getCommerceSessionByHash(TOKEN);
    expect(metadata?.expiresAt).toBe('2026-09-12T10:00:31.000000Z');
  });

  it('returns null for a hash that names no exchanged session', async () => {
    await expect(new CommerceSessionStore(pool([])).getCommerceSessionByHash(TOKEN)).resolves.toBeNull();
  });

  it('rejects a non-canonical bearer without connecting to the pool', async () => {
    for (const bad of [undefined, null, 42, TOKEN.slice(0, 63), `${TOKEN}0`, TOKEN.toUpperCase(), `${TOKEN}\n`]) {
      const fake = pool([bearerRow()]);
      await expectCode(
        new CommerceSessionStore(fake).getCommerceSessionByHash(bad),
        'COMMERCE_SESSION_STORE_INPUT_INVALID',
      );
      expect(fake.connectCalls).toBe(0);
    }
  });

  it('is a fixed UNAVAILABLE for an unexchanged, multi-row or leaking driver row', async () => {
    const unexchanged = pool([
      bearerRow({ out_exchanged_at: null, out_agent_session_id: null, out_credential_id: null }),
    ]);
    await expectCode(
      new CommerceSessionStore(unexchanged).getCommerceSessionByHash(TOKEN),
      'COMMERCE_SESSION_STORE_UNAVAILABLE',
    );

    const twoRows = pool([bearerRow(), bearerRow({ out_session_id: MUTATION })]);
    await expectCode(
      new CommerceSessionStore(twoRows).getCommerceSessionByHash(TOKEN),
      'COMMERCE_SESSION_STORE_UNAVAILABLE',
    );

    // An extra internal column is rejected outright, never silently stripped.
    const leaking = pool([{ ...bearerRow(), out_parent_human_session_hash: HASH }]);
    await expectCode(
      new CommerceSessionStore(leaking).getCommerceSessionByHash(TOKEN),
      'COMMERCE_SESSION_STORE_UNAVAILABLE',
    );

    const missingColumn = pool([(() => {
      const row = bearerRow();
      delete row['out_initial_expires_at'];
      return row;
    })()]);
    await expectCode(
      new CommerceSessionStore(missingColumn).getCommerceSessionByHash(TOKEN),
      'COMMERCE_SESSION_STORE_UNAVAILABLE',
    );

    // A half-paired machine binding is never a valid exchange.
    const halfBound = pool([bearerRow({ out_credential_id: null })]);
    await expectCode(
      new CommerceSessionStore(halfBound).getCommerceSessionByHash(TOKEN),
      'COMMERCE_SESSION_STORE_UNAVAILABLE',
    );

    // A malformed identity is UNAVAILABLE, never relabelled as input-invalid.
    const badOrg = pool([bearerRow({ out_organization_id: 'openarc:org:nope' })]);
    await expectCode(
      new CommerceSessionStore(badOrg).getCommerceSessionByHash(TOKEN),
      'COMMERCE_SESSION_STORE_UNAVAILABLE',
    );
  });

  it('maps a driver failure to the fixed vocabulary without echoing detail', async () => {
    const forbidden = new FakePool(
      () => new FakeClient([{ when: BY_TOKEN, throws: { code: '42501', message: TOKEN } }]),
    );
    await expectCode(
      new CommerceSessionStore(forbidden).getCommerceSessionByHash(TOKEN),
      'COMMERCE_SESSION_STORE_FORBIDDEN',
    );
    const invalid = new FakePool(
      () => new FakeClient([{ when: BY_TOKEN, throws: { code: '22023', message: TOKEN } }]),
    );
    await expectCode(
      new CommerceSessionStore(invalid).getCommerceSessionByHash(TOKEN),
      'COMMERCE_SESSION_STORE_INPUT_INVALID',
    );
    const unknown = new FakePool(
      () => new FakeClient([{ when: BY_TOKEN, throws: { code: 'XX000', message: TOKEN } }]),
    );
    await expectCode(
      new CommerceSessionStore(unknown).getCommerceSessionByHash(TOKEN),
      'COMMERCE_SESSION_STORE_UNAVAILABLE',
    );
  });
});
