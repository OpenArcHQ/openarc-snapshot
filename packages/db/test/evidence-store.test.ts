import { describe, expect, expectTypeOf, it } from 'vitest';
import {
  EVIDENCE_V2_GATEWAY_COMMITTED_LIMITATION,
  EVIDENCE_V2_SCHEMA_VERSION,
  EVIDENCE_V2_UNKNOWN_PAYMENT_LIMITATION,
  type EvidenceV2Fact,
  type EvidenceV2FactOf,
} from '@openarc/shared';
import {
  EVIDENCE_READ_DEFAULT_LIMIT,
  EVIDENCE_STORE_ERROR_MESSAGES,
  EVIDENCE_STORE_PAYMENT_CERTAINTIES,
  EVIDENCE_STORE_PAYMENT_CERTAINTY_ADMITS_NO_SETTLEMENT,
  EvidenceStore,
  EvidenceStoreError,
  evidenceFactOperands,
  parseEvidenceListLimit,
  type EvidenceStoreErrorCode,
  type EvidenceStorePaymentCertaintyAdmitsNoSettlement,
} from '../src/index.js';
import type { TenantClient, TenantPool } from '../src/tenant-store.js';

/**
 * Pure validation, mapping and output re-validation proofs for EvidenceStore.
 * No database: every refusal in the validation block must happen before a
 * connection is taken.
 */

const HASH = 'a'.repeat(64);
const ORG = 'openarc:org:43000000-0000-4000-8000-000000000001';
const OTHER_ORG = 'openarc:org:43000000-0000-4000-8000-000000000002';
const PROVIDER = 'openarc:provider:43000000-0000-4000-8000-000000000003';
const ACCOUNT = 'openarc:account:43000000-0000-4000-8000-000000000004';
const ACTION = 'openarc:action:43000000-0000-4000-8000-000000000005';
const GRANT = 'openarc:grant:43000000-0000-4000-8000-000000000006';
const BATCH = `0x${'ab'.repeat(32)}`;
const BLOCK_HASH = `0x${'12'.repeat(32)}`;
const SIGNATURE_CANARY = `0x${'5a'.repeat(65)}`;
const T1 = '2026-09-15T10:00:00Z';

const evd = (n: number): string => `evd_${n.toString(16).padStart(32, '0')}`;
const control = { class: 'local', sourceId: 'openarc.control', origin: 'openarc:control-plane', adapterVersion: 'openarc.control-projection.v1' } as const;
const common = (n: number) => ({
  schemaVersion: EVIDENCE_V2_SCHEMA_VERSION,
  evidenceId: evd(n),
  occurredAt: null,
  observedAt: T1,
  digest: null,
  dataClass: 'organization_protected' as const,
  limitations: ['Control-plane record; not an external observation.'],
});

function authorizationFact(n = 1): EvidenceV2FactOf<'authorization_decision'> {
  return { ...common(n), kind: 'authorization_decision', source: control, subject: { kind: 'action', canonicalId: ACTION },
    scope: { organizationId: ORG, providerId: null, actionId: ACTION }, actor: { kind: 'human_account', accountId: ACCOUNT },
    chain: null, normalized: { decision: 'approved' } };
}
function derivedExpiryFact(n = 2): EvidenceV2FactOf<'grant_state'> {
  return { ...common(n), kind: 'grant_state', source: { ...control, class: 'openarc_derived' },
    subject: { kind: 'authorization_grant', canonicalId: GRANT }, scope: { organizationId: ORG, providerId: PROVIDER, actionId: ACTION },
    actor: { kind: 'system', component: 'worker' }, chain: null, normalized: { status: 'expired' } };
}
function committedPayment(n = 3): EvidenceV2FactOf<'payment_observation'> {
  return { ...common(n), kind: 'payment_observation',
    source: { class: 'gateway', sourceId: 'circle_gateway_testnet', origin: 'https://gateway-api-testnet.circle.com', adapterVersion: 'openarc.gateway-transfer.v2' },
    subject: { kind: 'action', canonicalId: ACTION }, scope: { organizationId: ORG, providerId: PROVIDER, actionId: ACTION },
    actor: { kind: 'external_party', role: 'gateway', address: null }, chain: null, limitations: [EVIDENCE_V2_GATEWAY_COMMITTED_LIMITATION],
    normalized: { laneState: 'committed', certainty: 'submitted_pending_chain', gatewayStatus: 'completed',
      transferId: '3f1c1b7e-8a1d-4f5e-9b2a-1c2d3e4f5a6b', batchTransactionHash: BATCH, amountAtomic: '1000000',
      payer: `0x${'a1'.repeat(20)}`, payTo: `0x${'b2'.repeat(20)}` } };
}
function unknownPayment(n = 4): EvidenceV2FactOf<'payment_observation'> {
  return { ...committedPayment(n), limitations: [EVIDENCE_V2_UNKNOWN_PAYMENT_LIMITATION],
    normalized: { laneState: 'unknown', certainty: 'unknown', unknownReason: 'timeout' } };
}
function arcTxFact(n = 5): EvidenceV2FactOf<'arc_transaction'> {
  return { ...common(n), kind: 'arc_transaction',
    source: { class: 'onchain', sourceId: 'arc_rpc_testnet', origin: 'https://rpc.testnet.arc.io', adapterVersion: 'openarc.arc-observer.v1' },
    subject: { kind: 'arc_transaction', canonicalId: `eip155:5042002:tx:${BATCH}` }, scope: { organizationId: ORG, providerId: null, actionId: ACTION },
    actor: { kind: 'external_party', role: 'arc_chain', address: null },
    chain: { network: 'eip155:5042002', blockNumber: '1200', blockHash: BLOCK_HASH, finality: 'unfinalized' },
    normalized: { transactionHash: BATCH, receiptStatus: 'success' } };
}

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

interface Recorder {
  readonly pool: TenantPool;
  readonly queries: string[];
  readonly params: unknown[][];
  connects: number;
  destroyed: boolean[];
}

function recorder(
  respond: (text: string) => Promise<{ rows: Record<string, unknown>[] }> = async () => ({ rows: [] }),
): Recorder {
  const state: Recorder = {
    queries: [],
    params: [],
    connects: 0,
    destroyed: [],
    pool: {
      connect: async (): Promise<TenantClient> => {
        state.connects += 1;
        return {
          query: (async (text: string, params?: unknown[]) => {
            state.queries.push(text);
            state.params.push(params ?? []);
            return respond(text);
          }) as TenantClient['query'],
          release: (destroy?: boolean) => {
            state.destroyed.push(destroy === true);
          },
        };
      },
    },
  };
  return state;
}

function answering(rows: Record<string, unknown>[]): Recorder {
  return recorder(async (text) => (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(text) ? { rows: [] } : { rows }));
}

async function expectCode(promise: Promise<unknown>, code: EvidenceStoreErrorCode): Promise<EvidenceStoreError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(EvidenceStoreError);
    expect((error as EvidenceStoreError).code).toBe(code);
    return error as EvidenceStoreError;
  }
  throw new Error(`expected ${code}`);
}

/** '2026-09-15T10:00:00Z' -> PostgreSQL timestamptz text. */
function pgText(stamp: string): string {
  return `${stamp.replace('T', ' ').replace('Z', '')}+00`;
}

function rowOf(fact: EvidenceV2Fact, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const actor = fact.actor;
  const actorId = actor.kind === 'human_account' ? actor.accountId : actor.kind === 'agent' ? actor.agentId
    : actor.kind === 'provider' ? actor.providerId : actor.kind === 'system' ? actor.component : actor.role;
  return {
    out_organization_id: fact.scope.organizationId,
    out_found: true,
    out_evidence_id: fact.evidenceId,
    out_schema_version: fact.schemaVersion,
    out_kind: fact.kind,
    out_source_class: fact.source.class,
    out_source_id: fact.source.sourceId,
    out_source_origin: fact.source.origin,
    out_adapter_version: fact.source.adapterVersion,
    out_subject_kind: fact.subject.kind,
    out_subject_canonical_id: fact.subject.canonicalId,
    out_provider_id: fact.scope.providerId,
    out_action_id: fact.scope.actionId,
    out_actor_kind: actor.kind,
    out_actor_id: actorId,
    out_actor_address: actor.kind === 'external_party' ? actor.address : null,
    out_chain_network: fact.chain?.network ?? null,
    out_chain_block_number: fact.chain?.blockNumber ?? null,
    out_chain_block_hash: fact.chain?.blockHash ?? null,
    out_chain_finality: fact.chain?.finality ?? null,
    out_occurred_at: fact.occurredAt === null ? null : pgText(fact.occurredAt),
    out_observed_at: pgText(fact.observedAt),
    out_digest: fact.digest,
    out_data_class: fact.dataClass,
    out_limitations: [...fact.limitations],
    out_normalized: clone(fact.normalized),
    out_payment_certainty: fact.kind === 'payment_observation' ? fact.normalized.certainty : null,
    out_fact_digest: `sha256:${'f'.repeat(64)}`,
    out_recorded_at: '2026-09-15 10:00:01.5+00',
    ...extra,
  };
}

function sentinel(organization = ORG): Record<string, unknown> {
  const row = rowOf(authorizationFact());
  return Object.fromEntries(Object.keys(row).map((key) => [key,
    key === 'out_organization_id' ? organization : key === 'out_found' ? false : null]));
}

describe('EvidenceStore payment certainty model', () => {
  it('stores exactly the four shared certainties and proves no settlement state at the type level', () => {
    expect([...EVIDENCE_STORE_PAYMENT_CERTAINTIES]).toEqual(['unknown', 'pending', 'submitted_pending_chain', 'onchain_confirmed']);
    expect(EVIDENCE_STORE_PAYMENT_CERTAINTY_ADMITS_NO_SETTLEMENT).toBe(true);
    expectTypeOf<EvidenceStorePaymentCertaintyAdmitsNoSettlement>().toEqualTypeOf<true>();
    for (const forbidden of ['settled', 'paid', 'released', 'refunded', 'failed']) {
      expect(EVIDENCE_STORE_PAYMENT_CERTAINTIES as readonly string[]).not.toContain(forbidden);
    }
  });
});

describe('EvidenceStore input validation', () => {
  it('rejects a non-pool at construction', () => {
    expect(() => new EvidenceStore(null as unknown as TenantPool)).toThrow(EvidenceStoreError);
    expect(() => new EvidenceStore({} as TenantPool)).toThrow(EvidenceStoreError);
  });

  it('refuses every malformed, smuggled or database-inadmissible fact before taking a connection', async () => {
    const rec = recorder();
    const store = new EvidenceStore(rec.pool);
    const committed = committedPayment();
    const cases: [unknown, EvidenceStoreErrorCode][] = [
      [null, 'EVIDENCE_STORE_INPUT_INVALID'],
      ['fact', 'EVIDENCE_STORE_INPUT_INVALID'],
      [[authorizationFact()], 'EVIDENCE_STORE_INPUT_INVALID'],
      [{ ...authorizationFact(), signature: SIGNATURE_CANARY }, 'EVIDENCE_STORE_INPUT_INVALID'],
      [{ ...authorizationFact(), actor: { kind: 'human_account', accountId: ACCOUNT, sessionHash: HASH } }, 'EVIDENCE_STORE_INPUT_INVALID'],
      [{ ...committed, normalized: { ...committed.normalized, certainty: 'settled' } }, 'EVIDENCE_STORE_INPUT_INVALID'],
      [{ ...committed, normalized: { ...committed.normalized, laneState: 'released' } }, 'EVIDENCE_STORE_INPUT_INVALID'],
      [{ ...committed, normalized: { ...committed.normalized, amountAtomic: '1.5' } }, 'EVIDENCE_STORE_INPUT_INVALID'],
      [{ ...authorizationFact(), chain: arcTxFact().chain }, 'EVIDENCE_STORE_INPUT_INVALID'],
      [{ ...arcTxFact(), chain: null }, 'EVIDENCE_STORE_INPUT_INVALID'],
      [{ ...authorizationFact(), source: { ...control, class: 'signed' } }, 'EVIDENCE_STORE_INPUT_INVALID'],
      [{ ...derivedExpiryFact(), normalized: { status: 'revoked' } }, 'EVIDENCE_STORE_INPUT_INVALID'],
      [{ ...authorizationFact(), limitations: [SIGNATURE_CANARY] }, 'EVIDENCE_STORE_INPUT_INVALID'],
      [{ ...authorizationFact(), observedAt: '2026-09-15T10:00:00.1234567Z' }, 'EVIDENCE_STORE_INPUT_INVALID'],
      // Accepted by the shared schema, refused by the schema16 secret rule.
      [{ ...authorizationFact(), source: { ...control, sourceId: `s${'ab'.repeat(20)}` } }, 'EVIDENCE_STORE_SECRET_REFUSED'],
      [{ ...authorizationFact(), source: { ...control, adapterVersion: `openarc.${'cd'.repeat(20)}.v1` } }, 'EVIDENCE_STORE_SECRET_REFUSED'],
    ];
    for (const [input, code] of cases) {
      const error = await expectCode(store.recordFact(input), code);
      expect(error.message).toBe(EVIDENCE_STORE_ERROR_MESSAGES[code]);
      expect(error.message).not.toContain('0x');
    }
    expect(rec.connects).toBe(0);
  });

  it('refuses malformed read inputs and non-canonical limits before taking a connection', async () => {
    const rec = recorder();
    const store = new EvidenceStore(rec.pool);
    const subject = { kind: 'action', canonicalId: ACTION };
    for (const [hash, org, candidate] of [
      [HASH.toUpperCase(), ORG, subject],
      [HASH.slice(1), ORG, subject],
      [`${HASH}\n`, ORG, subject],
      [HASH, 'openarc:org:nope', subject],
      [HASH, ORG, { kind: 'payment', canonicalId: ACTION }],
      [HASH, ORG, { kind: 'action', canonicalId: GRANT }],
      [HASH, ORG, { ...subject, extra: 1 }],
      [HASH, ORG, null],
    ] as const) {
      await expectCode(store.readBySubject(hash, org, candidate), 'EVIDENCE_STORE_INPUT_INVALID');
    }
    for (const limit of ['0', '51', '05', ' 5', '5\n', '', '5.0', '1e1', 5, 50n, null]) {
      await expectCode(store.listByKind(HASH, ORG, 'grant_state', { limit }), 'EVIDENCE_STORE_INPUT_INVALID');
    }
    class Query { limit = '5'; }
    for (const query of [{ offset: '5' }, { limit: undefined }, { afterEvidenceId: 'evd_nope' }, { afterEvidenceId: evd(1).toUpperCase() }, new Query(), ['5']]) {
      await expectCode(store.listByKind(HASH, ORG, 'grant_state', query), 'EVIDENCE_STORE_INPUT_INVALID');
    }
    for (const kind of ['grant', 'GRANT_STATE', '', null]) {
      await expectCode(store.listByKind(HASH, ORG, kind), 'EVIDENCE_STORE_INPUT_INVALID');
    }
    expect(rec.connects).toBe(0);
  });

  it('converts only canonical limit strings, defaulting an absent limit to 25', () => {
    expect(parseEvidenceListLimit(undefined)).toBe(EVIDENCE_READ_DEFAULT_LIMIT);
    expect(parseEvidenceListLimit('1')).toBe(1);
    expect(parseEvidenceListLimit('50')).toBe(50);
    expect(parseEvidenceListLimit('25')).toBe(25);
    expect(() => parseEvidenceListLimit(25)).toThrow(EvidenceStoreError);
  });

  it('maps a fact to the 25 recorder operands in parameter order', () => {
    const operands = evidenceFactOperands(committedPayment());
    expect(operands).toHaveLength(25);
    expect(operands.slice(12, 15)).toEqual(['external_party', 'gateway', null]);
    expect(operands.slice(15, 19)).toEqual([null, null, null, null]);
    expect(JSON.parse(operands[24] as string)).toEqual(committedPayment().normalized);
    const chain = evidenceFactOperands(arcTxFact());
    expect(chain.slice(15, 19)).toEqual(['eip155:5042002', '1200', BLOCK_HASH, 'unfinalized']);
    expect(evidenceFactOperands(derivedExpiryFact()).slice(12, 15)).toEqual(['system', 'worker', null]);
  });
});

describe('EvidenceStore error mapping', () => {
  function failingWith(code: string, message: string): Recorder {
    return recorder(async (text) => {
      if (text === 'BEGIN' || text === 'ROLLBACK') return { rows: [] };
      throw Object.assign(new Error(message), { code, detail: `driver detail ${SIGNATURE_CANARY}` });
    });
  }

  it('classifies by exact SQLSTATE and RAISE literal, never echoes, and rolls back', async () => {
    const expected: [string, string, EvidenceStoreErrorCode][] = [
      ['28000', 'commerce_forbidden', 'EVIDENCE_STORE_SESSION_INVALID'],
      ['42501', 'commerce_forbidden', 'EVIDENCE_STORE_FORBIDDEN'],
      ['42501', 'permission denied for function record_evidence_fact', 'EVIDENCE_STORE_FORBIDDEN'],
      ['23503', 'insert or update violates foreign key constraint', 'EVIDENCE_STORE_NOT_FOUND'],
      ['23505', 'evidence_id_conflict', 'EVIDENCE_STORE_CONFLICT'],
      ['23505', 'duplicate key value violates unique constraint', 'EVIDENCE_STORE_UNAVAILABLE'],
      ['23505', 'evidence_id_conflict ', 'EVIDENCE_STORE_UNAVAILABLE'],
      ['23514', 'evidence_secret_material_refused', 'EVIDENCE_STORE_SECRET_REFUSED'],
      ['23514', 'evidence_source_class_forbidden', 'EVIDENCE_STORE_SOURCE_FORBIDDEN'],
      ['23514', 'evidence_fact_invalid', 'EVIDENCE_STORE_INPUT_INVALID'],
      ['23514', 'evidence_fact_digest_invalid', 'EVIDENCE_STORE_INPUT_INVALID'],
      ['23514', 'EVIDENCE_SECRET_MATERIAL_REFUSED', 'EVIDENCE_STORE_INPUT_INVALID'],
      ['23514', 'new row violates check constraint "evidence_facts_chain_valid"', 'EVIDENCE_STORE_INPUT_INVALID'],
      ['P0D11', 'evidence_read_bound_exceeded', 'EVIDENCE_STORE_BOUND_EXCEEDED'],
      ['P0D11', 'commerce_exposure_unavailable', 'EVIDENCE_STORE_UNAVAILABLE'],
      ['22023', 'evidence_input_invalid', 'EVIDENCE_STORE_INPUT_INVALID'],
      ['23502', 'null value', 'EVIDENCE_STORE_INPUT_INVALID'],
      ['22P02', 'invalid input syntax', 'EVIDENCE_STORE_INPUT_INVALID'],
      ['XX000', 'internal', 'EVIDENCE_STORE_UNAVAILABLE'],
      ['40001', 'serialization', 'EVIDENCE_STORE_UNAVAILABLE'],
    ];
    for (const [dbCode, message, storeCode] of expected) {
      for (const call of [
        (store: EvidenceStore) => store.recordFact(authorizationFact()),
        (store: EvidenceStore) => store.readBySubject(HASH, ORG, { kind: 'action', canonicalId: ACTION }),
        (store: EvidenceStore) => store.listByKind(HASH, ORG, 'authorization_decision', { limit: '5' }),
      ]) {
        const rec = failingWith(dbCode, message);
        const error = await expectCode(call(new EvidenceStore(rec.pool)), storeCode);
        expect(error.message).toBe(EVIDENCE_STORE_ERROR_MESSAGES[storeCode]);
        expect(error.message).not.toContain(message);
        expect(rec.queries).toContain('ROLLBACK');
        expect(rec.destroyed).toEqual([false]);
      }
    }
    const opaque = recorder(async (text) => {
      if (text === 'BEGIN' || text === 'ROLLBACK') return { rows: [] };
      throw new Error('no code at all');
    });
    await expectCode(new EvidenceStore(opaque.pool).recordFact(authorizationFact()), 'EVIDENCE_STORE_UNAVAILABLE');
  });

  it('reports a lost COMMIT as OUTCOME_UNKNOWN for a write and UNAVAILABLE for a read, destroying the connection', async () => {
    const write = recorder(async (text) => {
      if (text === 'COMMIT') throw new Error('connection lost');
      if (text === 'BEGIN') return { rows: [] };
      return { rows: [{ out_replayed: false, out_evidence_id: evd(1), out_organization_id: ORG,
        out_fact_digest: `sha256:${'e'.repeat(64)}`, out_recorded_at: '2026-09-15 10:00:01+00' }] };
    });
    await expectCode(new EvidenceStore(write.pool).recordFact(authorizationFact()), 'EVIDENCE_STORE_OUTCOME_UNKNOWN');
    expect(write.destroyed).toEqual([true]);
    const read = recorder(async (text) => {
      if (text === 'COMMIT') throw new Error('connection lost');
      if (text === 'BEGIN') return { rows: [] };
      return { rows: [sentinel()] };
    });
    await expectCode(new EvidenceStore(read.pool).readBySubject(HASH, ORG, { kind: 'action', canonicalId: ACTION }), 'EVIDENCE_STORE_UNAVAILABLE');
    expect(read.destroyed).toEqual([true]);
  });
});

describe('EvidenceStore output re-validation', () => {
  const recordRow = (extra: Record<string, unknown> = {}) => ({
    out_replayed: false, out_evidence_id: evd(1), out_organization_id: ORG,
    out_fact_digest: `sha256:${'e'.repeat(64)}`, out_recorded_at: '2026-09-15 10:00:01.25+00', ...extra,
  });

  it('accepts a well-formed record receipt and refuses one that disagrees with the fact', async () => {
    const ok = answering([recordRow()]);
    await expect(new EvidenceStore(ok.pool).recordFact(authorizationFact())).resolves.toEqual({
      replayed: false, evidenceId: evd(1), organizationId: ORG, factDigest: `sha256:${'e'.repeat(64)}`,
      recordedAt: '2026-09-15T10:00:01.250000Z',
    });
    expect(ok.params.find((params) => params.length === 25)).toEqual(evidenceFactOperands(authorizationFact()));
    for (const extra of [
      { out_replayed: 'yes' }, { out_evidence_id: evd(2) }, { out_organization_id: OTHER_ORG },
      { out_fact_digest: 'e'.repeat(64) }, { out_recorded_at: 'yesterday' },
    ]) {
      await expectCode(new EvidenceStore(answering([recordRow(extra)]).pool).recordFact(authorizationFact()), 'EVIDENCE_STORE_UNAVAILABLE');
    }
    await expectCode(new EvidenceStore(answering([recordRow(), recordRow()]).pool).recordFact(authorizationFact()), 'EVIDENCE_STORE_UNAVAILABLE');
  });

  it('projects a subject read to the full operator view and refuses malformed, relabeled or unordered rows', async () => {
    const subject = { kind: 'action', canonicalId: ACTION } as const;
    const facts: EvidenceV2Fact[] = [authorizationFact(1), committedPayment(3), { ...unknownPayment(4), observedAt: '2026-09-15T10:00:05Z' }];
    const read = await new EvidenceStore(answering(facts.map((fact) => rowOf(fact))).pool).readBySubject(HASH, ORG, subject);
    expect(read.organizationId).toBe(ORG);
    expect(read.items.map((item) => item.operatorView)).toEqual(facts.map((fact) => ({
      view: 'operator', ...clone(fact), observedAt: fact.observedAt.replace('Z', '.000000Z'),
    })));
    expect(read.items[0]?.recordedAt).toBe('2026-09-15T10:00:01.500000Z');
    expect(await new EvidenceStore(answering([sentinel()]).pool).readBySubject(HASH, ORG, subject))
      .toEqual({ organizationId: ORG, subject, items: [] });

    const bad: Record<string, unknown>[][] = [
      [rowOf(committedPayment(), { out_payment_certainty: 'settled' })],
      [rowOf(committedPayment(), { out_payment_certainty: 'unknown' })],
      [rowOf(committedPayment(), { out_normalized: { ...committedPayment().normalized, certainty: 'paid' } })],
      [rowOf(authorizationFact(), { out_payment_certainty: 'pending' })],
      [rowOf(authorizationFact(), { out_organization_id: OTHER_ORG })],
      [rowOf(authorizationFact(), { out_found: false })],
      [rowOf(authorizationFact(), { out_normalized: { decision: 'approved', signature: SIGNATURE_CANARY } })],
      [rowOf(authorizationFact(), { out_actor_address: `0x${'a1'.repeat(20)}` })],
      [rowOf(authorizationFact(), { out_chain_network: 'eip155:5042002' })],
      [rowOf(authorizationFact(), { out_fact_digest: null })],
      [rowOf(authorizationFact(), { out_subject_canonical_id: ACTION.replace('0005', '0009'), out_action_id: ACTION.replace('0005', '0009') })],
      [{ ...sentinel(), out_evidence_id: evd(1) }],
      [sentinel(OTHER_ORG)],
      [rowOf({ ...authorizationFact(2), observedAt: '2026-09-15T10:00:05Z' }), rowOf(authorizationFact(1))],
      [rowOf(authorizationFact(2)), rowOf(authorizationFact(1))],
      [rowOf(authorizationFact(1)), rowOf(authorizationFact(1))],
      [],
      Array.from({ length: 201 }, (_value, index) => rowOf({ ...authorizationFact(index + 1) })),
    ];
    for (const rows of bad) {
      await expectCode(new EvidenceStore(answering(rows).pool).readBySubject(HASH, ORG, subject), 'EVIDENCE_STORE_UNAVAILABLE');
    }
  });

  it('pages by kind with limit + 1 detection and refuses rows of another kind, out of order or behind the cursor', async () => {
    const rows = [1, 2, 3].map((n) => rowOf(authorizationFact(n)));
    const store = (list: Record<string, unknown>[]) => new EvidenceStore(answering(list).pool);
    const full = await store(rows).listByKind(HASH, ORG, 'authorization_decision', { limit: '2' });
    expect(full.items.map((item) => item.operatorView.evidenceId)).toEqual([evd(1), evd(2)]);
    expect(full.nextCursor).toBe(evd(2));
    const exact = await store(rows.slice(0, 2)).listByKind(HASH, ORG, 'authorization_decision', { limit: '2' });
    expect(exact.nextCursor).toBeNull();
    const rec = answering(rows.slice(0, 1));
    await new EvidenceStore(rec.pool).listByKind(HASH, ORG, 'authorization_decision');
    expect(rec.params.find((params) => params.length === 5)).toEqual([HASH, ORG, 'authorization_decision', null, 25]);
    expect(await store([sentinel()]).listByKind(HASH, ORG, 'authorization_decision'))
      .toEqual({ organizationId: ORG, kind: 'authorization_decision', items: [], nextCursor: null });
    await expectCode(store(rows).listByKind(HASH, ORG, 'grant_state', { limit: '5' }), 'EVIDENCE_STORE_UNAVAILABLE');
    await expectCode(store([rows[1]!, rows[0]!]).listByKind(HASH, ORG, 'authorization_decision'), 'EVIDENCE_STORE_UNAVAILABLE');
    await expectCode(store(rows).listByKind(HASH, ORG, 'authorization_decision', { limit: '1' }), 'EVIDENCE_STORE_UNAVAILABLE');
    await expectCode(store(rows).listByKind(HASH, ORG, 'authorization_decision', { afterEvidenceId: evd(2) }), 'EVIDENCE_STORE_UNAVAILABLE');
    await expectCode(store([]).listByKind(HASH, ORG, 'authorization_decision'), 'EVIDENCE_STORE_UNAVAILABLE');
  });
});
