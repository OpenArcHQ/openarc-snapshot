import { describe, expect, expectTypeOf, it } from 'vitest';
import type {
  LeasedPaymentAttempt,
  RecordedObservation,
  ReleaseLeaseResult,
} from '@openarc/db';
import type { LaneExposure, LaneLookupObservation, LaneTransferRecord } from '@openarc/x402';
import {
  SETTLEMENT_LIVE_MODE_MESSAGE,
  SettlementLiveModeUnsupportedError,
  WorkerConfigError,
  isLoopbackLookupUrl,
  parseSettlementConfig,
  requireSettlementLookupUrl,
} from '../src/config.js';
import {
  SETTLEMENT_ADMITS_NO_RELEASE,
  SettlementObservationError,
  SettlementObservationLoop,
  bindingOfLeasedAttempt,
  classifyLeasedAttempt,
  decideFromExposure,
  type SettlementAdmitsNoRelease,
  type SettlementClock,
  type SettlementDecision,
  type SettlementLogRecord,
  type SettlementLookupTransport,
  type SettlementObservationStorePort,
} from '../src/settlement-observation.js';

/**
 * Classification-mapping and operational proofs for the bounded settlement
 * observation loop, with a fake transport and a fake store. Nothing here opens
 * a socket, signs, sends or settles.
 */

const ORG = 'openarc:org:40000000-0000-4000-8000-000000000001';
const ATTEMPT = '40000000-0000-4000-8000-000000770001';
const GRANT = 'openarc:grant:40000000-0000-4000-8000-000000000001';
const ACTION = 'openarc:action:40000000-0000-4000-8000-000000000001';
const PAYER = '0x1111111111111111111111111111111111111111';
const PAY_TO = '0xabcdefabcdefabcdefabcdefabcdefabcdef2222';
const USDC = '0x3600000000000000000000000000000000000000';
const GATEWAY_WALLET = '0x0077777d7EBA4688BDeF3E311b846F25870A19B9';
const NONCE = `0x${'a1'.repeat(32)}`;
const TRANSFER = '3f1c1b7e-8a1d-4f5e-9b2a-1c2d3e4f5a6b';
const OTHER_TRANSFER = '9a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d';
const BATCH = `0x${'ab'.repeat(32)}` as `0x${string}`;
const NOW_SECONDS = 1_800_000_000;

function leased(overrides: Partial<LeasedPaymentAttempt> = {}): LeasedPaymentAttempt {
  return {
    organizationId: ORG,
    attemptId: ATTEMPT,
    grantId: GRANT,
    actionId: ACTION,
    requirementDigest: `sha256:${'1'.repeat(64)}`,
    laneRequirementDigest: `sha256:${'2'.repeat(64)}`,
    networkId: 'eip155:5042002',
    assetAddress: USDC,
    verifyingContract: GATEWAY_WALLET,
    payerAddress: PAYER,
    payToAddress: PAY_TO,
    valueAtomic: '1000000',
    validAfter: String(NOW_SECONDS - 600),
    validBefore: String(NOW_SECONDS + 604800),
    nonce: NONCE,
    state: 'unknown',
    dispatchedAt: new Date(NOW_SECONDS * 1000).toISOString(),
    leaseGeneration: '1',
    leaseUntil: new Date((NOW_SECONDS + 120) * 1000).toISOString(),
    attemptCount: 1,
    ...overrides,
  };
}

function transfer(overrides: Partial<LaneTransferRecord> = {}): LaneTransferRecord {
  return {
    id: TRANSFER,
    status: 'completed',
    fromAddress: PAYER,
    toAddress: PAY_TO,
    amount: '1000000',
    nonce: NONCE,
    sendingNetwork: 'eip155:5042002',
    recipientNetwork: 'eip155:5042002',
    txHash: BATCH,
    ...overrides,
  };
}

function records(list: readonly LaneTransferRecord[], hasMorePages = false): LaneLookupObservation {
  return { kind: 'records', transfers: list, hasMorePages };
}

function fakeTransport(
  answer: LaneLookupObservation | (() => Promise<never>),
): SettlementLookupTransport {
  return { lookup: typeof answer === 'function' ? answer : () => Promise.resolve(answer) };
}

async function classify(
  lookup: LaneLookupObservation | (() => Promise<never>),
  attempt: LeasedPaymentAttempt = leased(),
  nowUnixSeconds = NOW_SECONDS,
): Promise<SettlementDecision> {
  return classifyLeasedAttempt(attempt, fakeTransport(lookup), {
    nowUnixSeconds,
    signal: new AbortController().signal,
  });
}

/** The every-outcome hold reasons a lane classification can produce. */
const UNKNOWN_REASONS = [
  'timeout', 'transport_error', 'http_error', 'malformed_response', 'not_found',
  'not_found_after_expiry', 'nonce_already_used', 'gateway_failed_not_terminal',
  'ambiguous_records', 'record_mismatch', 'completed_without_batch_hash',
  'unrecognized_status',
] as const;

const FORBIDDEN_STATES = [
  'released', 'released_unsent', 'failed', 'rejected', 'expired',
  'cancelled', 'refunded', 'not_paid', 'nonpayment',
];

describe('exposure mapping', () => {
  it('maps a committed exposure to exactly one committed record', () => {
    const exposure: LaneExposure = {
      state: 'committed',
      disposition: 'committed',
      transferId: TRANSFER,
      gatewayStatus: 'completed',
      batchTxHash: BATCH,
      onchainReceiptVerified: false,
    };
    expect(decideFromExposure(exposure)).toEqual({
      kind: 'record', state: 'committed', transferId: TRANSFER,
      gatewayStatus: 'completed', batchTxHash: BATCH,
    });
  });

  it('maps each held pending status to a pending record that keeps the exposure held', () => {
    for (const gatewayStatus of ['received', 'batched', 'confirmed'] as const) {
      const exposure: LaneExposure = {
        state: 'pending', disposition: 'held', transferId: TRANSFER, gatewayStatus, batchTxHash: null,
      };
      expect(decideFromExposure(exposure)).toEqual({
        kind: 'record', state: 'pending', transferId: TRANSFER, gatewayStatus, batchTxHash: null,
      });
    }
  });

  it('maps EVERY unknown reason to a hold that writes nothing', () => {
    for (const reason of UNKNOWN_REASONS) {
      const exposure: LaneExposure = { state: 'unknown', disposition: 'held', reason };
      expect([reason, decideFromExposure(exposure)]).toEqual([reason, { kind: 'hold', reason }]);
    }
  });

  it('proves at compile time that no decision can release exposure', () => {
    expect(SETTLEMENT_ADMITS_NO_RELEASE).toBe(true);
    expectTypeOf<SettlementAdmitsNoRelease>().toEqualTypeOf<true>();
    expectTypeOf<Extract<SettlementDecision, { kind: 'record' }>['state']>()
      .toEqualTypeOf<'pending' | 'committed'>();
  });
});

describe('classification through the accepted lane rules', () => {
  it('records committed for exactly one fully matching completed transfer', async () => {
    expect(await classify(records([transfer()]))).toEqual({
      kind: 'record', state: 'committed', transferId: TRANSFER,
      gatewayStatus: 'completed', batchTxHash: BATCH,
    });
  });

  it('records pending for a received, batched or confirmed transfer', async () => {
    for (const status of ['received', 'batched', 'confirmed']) {
      const decision = await classify(records([transfer({ status, txHash: null })]));
      expect([status, decision]).toEqual([status, {
        kind: 'record', state: 'pending', transferId: TRANSFER,
        gatewayStatus: status, batchTxHash: null,
      }]);
    }
  });

  it('holds on a timeout, transport error, HTTP error or malformed body', async () => {
    const cases: readonly [LaneLookupObservation, string][] = [
      [{ kind: 'timeout' }, 'timeout'],
      [{ kind: 'transport_error' }, 'transport_error'],
      [{ kind: 'http_error', status: 500 }, 'http_error'],
      [{ kind: 'malformed' }, 'malformed_response'],
    ];
    for (const [lookup, reason] of cases) {
      expect([reason, await classify(lookup)]).toEqual([reason, { kind: 'hold', reason }]);
    }
  });

  it('holds when the record is not found, and distinguishes an expired window', async () => {
    expect(await classify(records([]))).toEqual({ kind: 'hold', reason: 'not_found' });
    // After validBefore the answer is still a hold, never a release.
    const expired = await classify(records([]), leased(), NOW_SECONDS + 604801);
    expect(expired).toEqual({ kind: 'hold', reason: 'not_found_after_expiry' });
  });

  it('holds on a failed status: a Gateway failure is not terminal for exposure', async () => {
    expect(await classify(records([transfer({ status: 'failed', txHash: null })])))
      .toEqual({ kind: 'hold', reason: 'gateway_failed_not_terminal' });
  });

  it('holds on an unrecognised status rather than guessing', async () => {
    for (const status of ['settled', 'refunded', 'cancelled', 'released', '']) {
      const decision = await classify(records([transfer({ status, txHash: null })]));
      expect([status, decision]).toEqual([status, { kind: 'hold', reason: 'unrecognized_status' }]);
    }
  });

  it('holds on a mismatched payee, amount or network', async () => {
    const mismatches: readonly Partial<LaneTransferRecord>[] = [
      { toAddress: '0x9999999999999999999999999999999999999999' },
      { amount: '999999' },
      { sendingNetwork: 'eip155:1' },
      { recipientNetwork: 'eip155:1' },
    ];
    for (const override of mismatches) {
      const decision = await classify(records([transfer(override)]));
      expect([JSON.stringify(override), decision]).toEqual([
        JSON.stringify(override), { kind: 'hold', reason: 'record_mismatch' },
      ]);
    }
  });

  it('holds when a record belongs to another payer or nonce', async () => {
    for (const override of [
      { fromAddress: '0x9999999999999999999999999999999999999999' },
      { nonce: `0x${'b2'.repeat(32)}` },
    ]) {
      const decision = await classify(records([transfer(override)]));
      expect([JSON.stringify(override), decision]).toEqual([
        JSON.stringify(override), { kind: 'hold', reason: 'record_mismatch' },
      ]);
    }
  });

  it('holds on multiple records or a further page', async () => {
    expect(await classify(records([transfer(), transfer({ id: OTHER_TRANSFER })])))
      .toEqual({ kind: 'hold', reason: 'ambiguous_records' });
    expect(await classify(records([transfer()], true)))
      .toEqual({ kind: 'hold', reason: 'ambiguous_records' });
  });

  it('holds on a completed transfer with no batch hash', async () => {
    expect(await classify(records([transfer({ txHash: null })])))
      .toEqual({ kind: 'hold', reason: 'completed_without_batch_hash' });
  });

  it('holds when the transport throws or the binding cannot be revalidated', async () => {
    expect(await classify(() => Promise.reject(new Error('boom'))))
      .toEqual({ kind: 'hold', reason: 'transport_threw' });
    for (const override of [
      { networkId: 'eip155:1' },
      { nonce: '0xdeadbeef' },
      { payerAddress: 'not-an-address' },
      { valueAtomic: '-1' },
    ] as Partial<LeasedPaymentAttempt>[]) {
      const decision = await classify(records([transfer()]), leased(override));
      expect([JSON.stringify(override), decision]).toEqual([
        JSON.stringify(override), { kind: 'hold', reason: 'binding_unreadable' },
      ]);
    }
  });

  it('holds when the lookup is aborted', async () => {
    const controller = new AbortController();
    controller.abort();
    const decision = await classifyLeasedAttempt(leased(), fakeTransport(records([transfer()])), {
      nowUnixSeconds: NOW_SECONDS,
      signal: controller.signal,
    });
    expect(decision).toEqual({ kind: 'hold', reason: 'lookup_aborted' });
  });

  it('never produces a release, failure or refund for ANY answer', async () => {
    const answers: LaneLookupObservation[] = [
      { kind: 'timeout' }, { kind: 'transport_error' }, { kind: 'http_error', status: 404 },
      { kind: 'malformed' }, records([]), records([transfer({ status: 'failed' })]),
      records([transfer({ status: 'refunded' })]), records([transfer({ status: 'released' })]),
      records([transfer(), transfer({ id: OTHER_TRANSFER })]),
    ];
    for (const answer of answers) {
      const decision = await classify(answer);
      if (decision.kind === 'record') {
        expect(FORBIDDEN_STATES).not.toContain(decision.state);
      }
    }
  });

  it('rebuilds the binding from the durable row and pins the manifest', () => {
    const binding = bindingOfLeasedAttempt(leased());
    expect(binding.network).toBe('eip155:5042002');
    expect(binding.asset.toLowerCase()).toBe(USDC);
    expect(binding.verifyingContract.toLowerCase()).toBe(GATEWAY_WALLET.toLowerCase());
    expect(binding.nonce).toBe(NONCE);
    expect(Object.keys(binding)).not.toContain('signature');
  });
});

// ---------------------------------------------------------------------------
type ObservationInput = Parameters<SettlementObservationStorePort['recordObservation']>[0];

class FakeStore implements SettlementObservationStorePort {
  readonly recorded: ObservationInput[] = [];
  readonly released: unknown[] = [];
  claimCalls = 0;
  recordResult: RecordedObservation | null | Error | 'echo' = 'echo';

  constructor(private readonly batches: (LeasedPaymentAttempt[] | Error)[]) {}

  claim(): Promise<LeasedPaymentAttempt[]> {
    this.claimCalls += 1;
    const next = this.batches.shift() ?? [];
    if (next instanceof Error) return Promise.reject(next);
    return Promise.resolve(next);
  }

  recordObservation(input: ObservationInput): Promise<RecordedObservation | null> {
    this.recorded.push(input);
    if (this.recordResult instanceof Error) return Promise.reject(this.recordResult);
    if (this.recordResult !== 'echo') return Promise.resolve(this.recordResult);
    return Promise.resolve({
      organizationId: input.organizationId,
      attemptId: input.attemptId,
      state: input.state,
      dispatchedAt: new Date(NOW_SECONDS * 1000).toISOString(),
      observedAt: new Date((NOW_SECONDS + 1) * 1000).toISOString(),
      transferId: input.transferId,
      gatewayStatus: input.gatewayStatus,
      batchTxHash: input.batchTxHash,
    });
  }

  releaseLease(
    organizationId: string,
    attemptId: string,
    leaseGeneration: string,
  ): Promise<ReleaseLeaseResult> {
    this.released.push({ organizationId, attemptId, leaseGeneration });
    return Promise.resolve({ released: true });
  }
}

/** Never sleeps for real; the loop under test must terminate on its own. */
function instantClock(): SettlementClock {
  return { now: () => NOW_SECONDS * 1000, sleep: () => Promise.resolve() };
}

/**
 * A clock that stops the loop the first time it backs off. Every batch is
 * therefore processed exactly once and the run terminates deterministically,
 * with no timers and no chance of a spin.
 */
function stoppingClock(ref: { loop?: SettlementObservationLoop }): SettlementClock {
  return {
    now: () => NOW_SECONDS * 1000,
    sleep: () => {
      ref.loop?.requestStop();
      return Promise.resolve();
    },
  };
}

function collectLogger(sink: SettlementLogRecord[]) {
  return { log: (record: SettlementLogRecord): void => void sink.push(record) };
}

function loopOptions(store: SettlementObservationStorePort, transport: SettlementLookupTransport) {
  return { store, transport, claimLimit: 5, pollMs: 1, idleMaxMs: 1, clock: instantClock() };
}

/** Drain every seeded batch exactly once, then stop. */
async function drain(
  store: SettlementObservationStorePort,
  transport: SettlementLookupTransport,
  logs?: SettlementLogRecord[],
): Promise<void> {
  const ref: { loop?: SettlementObservationLoop } = {};
  const loop = new SettlementObservationLoop({
    store,
    transport,
    claimLimit: 5,
    pollMs: 1,
    idleMaxMs: 1,
    clock: stoppingClock(ref),
    ...(logs === undefined ? {} : { logger: collectLogger(logs) }),
  });
  ref.loop = loop;
  await loop.run();
}

describe('bounded observation loop', () => {
  it('refuses to be constructed without a transport or with unbounded settings', () => {
    const store = new FakeStore([]);
    const transport = fakeTransport(records([]));
    expect(() => new SettlementObservationLoop({
      ...loopOptions(store, transport),
      transport: undefined as unknown as SettlementLookupTransport,
    })).toThrow(SettlementObservationError);
    for (const claimLimit of [0, 26, 1.5, -1]) {
      expect(() => new SettlementObservationLoop({ ...loopOptions(store, transport), claimLimit }))
        .toThrow(SettlementObservationError);
    }
    for (const lookupTimeoutMs of [0, 30_001, 1.5]) {
      expect(() => new SettlementObservationLoop({ ...loopOptions(store, transport), lookupTimeoutMs }))
        .toThrow(SettlementObservationError);
    }
    for (const maxConsecutiveClaimErrors of [0, 1001, 1.5]) {
      expect(() => new SettlementObservationLoop({
        ...loopOptions(store, transport), maxConsecutiveClaimErrors,
      })).toThrow(SettlementObservationError);
    }
    expect(() => new SettlementObservationLoop({
      ...loopOptions(store, transport), batchDeadlineMs: 120_001,
    })).toThrow(SettlementObservationError);
  });

  it('records a committed observation exactly once and never releases the lease', async () => {
    const store = new FakeStore([[leased()]]);
    const logs: SettlementLogRecord[] = [];
    await drain(store, fakeTransport(records([transfer()])), logs);
    expect(store.recorded).toHaveLength(1);
    expect(store.recorded[0]).toMatchObject({
      organizationId: ORG, attemptId: ATTEMPT, leaseGeneration: '1',
      state: 'committed', transferId: TRANSFER, gatewayStatus: 'completed', batchTxHash: BATCH,
    });
    expect(store.released).toHaveLength(0);
    expect(logs.filter((record) => record.status === 'observed_committed')).toHaveLength(1);
  });

  it('records a pending observation and still keeps the exposure held', async () => {
    const store = new FakeStore([[leased()]]);
    const logs: SettlementLogRecord[] = [];
    await drain(store, fakeTransport(records([transfer({ status: 'batched', txHash: null })])), logs);
    expect(store.recorded).toHaveLength(1);
    expect(store.recorded[0]).toMatchObject({ state: 'pending', gatewayStatus: 'batched' });
    expect(logs.filter((record) => record.status === 'observed_pending')).toHaveLength(1);
  });

  it('records nothing and releases the lease for an unclear answer', async () => {
    const store = new FakeStore([[leased()]]);
    const logs: SettlementLogRecord[] = [];
    await drain(store, fakeTransport({ kind: 'timeout' }), logs);
    expect(store.recorded).toHaveLength(0);
    expect(store.released).toEqual([
      { organizationId: ORG, attemptId: ATTEMPT, leaseGeneration: '1' },
    ]);
    expect(logs.some((record) => record.status === 'held' && record.reason === 'timeout')).toBe(true);
  });

  it('records nothing for every unclear transport answer', async () => {
    for (const answer of [
      { kind: 'timeout' } as const,
      { kind: 'transport_error' } as const,
      { kind: 'http_error', status: 502 } as const,
      { kind: 'malformed' } as const,
      records([]),
      records([transfer({ status: 'failed', txHash: null })]),
      records([transfer(), transfer({ id: OTHER_TRANSFER })]),
    ]) {
      const store = new FakeStore([[leased()]]);
      await drain(store, fakeTransport(answer));
      expect([JSON.stringify(answer), store.recorded]).toEqual([JSON.stringify(answer), []]);
    }
  });

  it('treats a stale lease as stale and does not retry the observation', async () => {
    const store = new FakeStore([[leased()]]);
    store.recordResult = null;
    const logs: SettlementLogRecord[] = [];
    await drain(store, fakeTransport(records([transfer()])), logs);
    expect(store.recorded).toHaveLength(1);
    expect(logs.some((record) => record.status === 'record_stale')).toBe(true);
  });

  it('never double-records when the recorder reply is lost', async () => {
    const store = new FakeStore([[leased()]]);
    store.recordResult = new Error('lost reply');
    const logs: SettlementLogRecord[] = [];
    await drain(store, fakeTransport(records([transfer()])), logs);
    expect(store.recorded).toHaveLength(1);
    expect(logs.some((record) => record.status === 'outcome_unknown')).toBe(true);
  });

  it('does not observe an attempt whose lease already expired', async () => {
    const store = new FakeStore([
      [leased({ leaseUntil: new Date((NOW_SECONDS - 1) * 1000).toISOString() })],
    ]);
    await drain(store, fakeTransport(records([transfer()])));
    expect(store.recorded).toHaveLength(0);
  });

  it('processes a whole batch and records each attempt exactly once', async () => {
    const batch = [
      leased(),
      leased({ attemptId: '40000000-0000-4000-8000-000000770002', leaseGeneration: '2' }),
      leased({ attemptId: '40000000-0000-4000-8000-000000770003', leaseGeneration: '3' }),
    ];
    const store = new FakeStore([batch]);
    await drain(store, fakeTransport(records([transfer()])));
    expect(store.recorded).toHaveLength(3);
    expect(store.recorded.map((entry) => entry.attemptId).sort()).toEqual(
      batch.map((entry) => entry.attemptId).sort(),
    );
  });

  it('stops after the configured number of consecutive claim failures', async () => {
    const failures = Array.from({ length: 10 }, () => new Error('claim failed'));
    const store = new FakeStore(failures);
    const logs: SettlementLogRecord[] = [];
    const loop = new SettlementObservationLoop({
      ...loopOptions(store, fakeTransport(records([]))),
      maxConsecutiveClaimErrors: 3,
      logger: collectLogger(logs),
    });
    await loop.run();
    expect(store.claimCalls).toBe(3);
    expect(logs.some((record) => record.status === 'stopping' && record.count === 3)).toBe(true);
    expect(logs.filter((record) => record.status === 'claim_error')).toHaveLength(3);
  });

  it('backs off on empty claims and never tight-loops', async () => {
    const store = new FakeStore([[]]);
    const logs: SettlementLogRecord[] = [];
    await drain(store, fakeTransport(records([])), logs);
    expect(logs.some((record) => record.status === 'claim_empty')).toBe(true);
    expect(logs.at(-1)?.status).toBe('stopped');
    expect(store.claimCalls).toBe(1);
  });

  it('refuses to run twice', async () => {
    const loop = new SettlementObservationLoop(
      loopOptions(new FakeStore([]), fakeTransport(records([]))),
    );
    loop.requestStop();
    await loop.run();
    await expect(loop.run()).rejects.toBeInstanceOf(SettlementObservationError);
  });

  it('emits only fixed allowlisted log fields and never leaks an identifier', async () => {
    const store = new FakeStore([[leased()]]);
    const logs: SettlementLogRecord[] = [];
    await drain(store, fakeTransport({ kind: 'http_error', status: 503 }), logs);
    expect(logs.length).toBeGreaterThan(0);
    for (const record of logs) {
      expect(Object.keys(record).every((key) => ['status', 'reason', 'count'].includes(key))).toBe(true);
      const serialized = JSON.stringify(record);
      for (const secret of [ORG, ATTEMPT, GRANT, ACTION, PAYER, PAY_TO, NONCE, TRANSFER, BATCH, '503']) {
        expect(serialized).not.toContain(secret);
      }
    }
  });
});

describe('settlement observation family configuration', () => {
  const base = {
    WORKER_ENABLED: 'true',
    WORKER_DATABASE_URL: 'postgres://openarc_worker_app:pw@127.0.0.1:5432/openarc_auth_test',
  };

  it('ships disabled by default and parses no transport when disabled', () => {
    expect(parseSettlementConfig({})).toEqual({ enabled: false });
    expect(parseSettlementConfig(base)).toEqual({ enabled: false });
    expect(parseSettlementConfig({
      ...base,
      WORKER_SETTLEMENT_OBSERVATION_ENABLED: 'false',
      WORKER_SETTLEMENT_LOOKUP_URL: 'https://gateway-api-testnet.circle.com',
    })).toEqual({ enabled: false });
  });

  it('requires the worker, a database URL and a loopback transport when enabled', () => {
    const enabled = {
      ...base,
      WORKER_SETTLEMENT_OBSERVATION_ENABLED: 'true',
      WORKER_SETTLEMENT_LOOKUP_URL: 'http://127.0.0.1:8099/gateway',
    };
    expect(parseSettlementConfig(enabled)).toEqual({
      enabled: true,
      databaseUrl: base.WORKER_DATABASE_URL,
      lookupUrl: 'http://127.0.0.1:8099/gateway',
      claimLimit: 5,
      pollMs: 1000,
      idleMaxMs: 5000,
      lookupTimeoutMs: 10000,
    });
    // The family cannot run without the worker process or its database URL.
    expect(() => parseSettlementConfig({ ...enabled, WORKER_ENABLED: 'false' })).toThrow(WorkerConfigError);
    const noDb: Record<string, string | undefined> = { ...enabled };
    delete noDb['WORKER_DATABASE_URL'];
    expect(() => parseSettlementConfig(noDb)).toThrow(WorkerConfigError);
    // No transport URL at all is a configuration error, never a default.
    const noUrl: Record<string, string | undefined> = { ...enabled };
    delete noUrl['WORKER_SETTLEMENT_LOOKUP_URL'];
    expect(() => parseSettlementConfig(noUrl)).toThrow(WorkerConfigError);
  });

  it('refuses every non-loopback transport URL', () => {
    for (const url of [
      'https://gateway-api-testnet.circle.com',
      'https://gateway-api.circle.com/v1/x402/transfers',
      'http://169.254.169.254/latest/meta-data',
      'http://127.0.0.1.evil.test/',
      'http://user:pw@127.0.0.1:8099/',
      'file:///etc/passwd',
      'ftp://127.0.0.1/',
      'not a url',
      '',
    ]) {
      expect([url, isLoopbackLookupUrl(url)]).toEqual([url, false]);
      expect(() => requireSettlementLookupUrl(url, false)).toThrow(WorkerConfigError);
    }
    for (const url of ['http://127.0.0.1:8099/gateway', 'http://localhost:8099', 'http://[::1]:8099/x']) {
      expect([url, isLoopbackLookupUrl(url)]).toEqual([url, true]);
      expect(requireSettlementLookupUrl(url, false)).toBe(url);
    }
  });

  it('refuses live mode outright and names the P04-07 prerequisites', () => {
    expect(() => requireSettlementLookupUrl('http://127.0.0.1:8099', true))
      .toThrow(SettlementLiveModeUnsupportedError);
    // Live mode is refused even with the real pinned facilitator origin.
    expect(() => requireSettlementLookupUrl('https://gateway-api-testnet.circle.com', true))
      .toThrow(SettlementLiveModeUnsupportedError);
    expect(() => parseSettlementConfig({
      WORKER_ENABLED: 'true',
      WORKER_DATABASE_URL: base.WORKER_DATABASE_URL,
      WORKER_SETTLEMENT_OBSERVATION_ENABLED: 'true',
      WORKER_SETTLEMENT_LIVE_MODE: 'true',
      WORKER_SETTLEMENT_LOOKUP_URL: 'http://127.0.0.1:8099',
    })).toThrow(SettlementLiveModeUnsupportedError);
    expect(SETTLEMENT_LIVE_MODE_MESSAGE).toContain('P04-07');
    expect(new SettlementLiveModeUnsupportedError().message).toContain('P04-07');
  });

  it('rejects strict invalid bounds', () => {
    const enabled = {
      ...base,
      WORKER_SETTLEMENT_OBSERVATION_ENABLED: 'true',
      WORKER_SETTLEMENT_LOOKUP_URL: 'http://127.0.0.1:8099',
    };
    for (const override of [
      { WORKER_SETTLEMENT_CLAIM_LIMIT: '0' },
      { WORKER_SETTLEMENT_CLAIM_LIMIT: '26' },
      { WORKER_SETTLEMENT_CLAIM_LIMIT: '1e1' },
      { WORKER_SETTLEMENT_POLL_MS: '249' },
      { WORKER_SETTLEMENT_POLL_MS: '10001' },
      { WORKER_SETTLEMENT_IDLE_MAX_MS: '999' },
      { WORKER_SETTLEMENT_LOOKUP_TIMEOUT_MS: '30001' },
      { WORKER_SETTLEMENT_POLL_MS: '5000', WORKER_SETTLEMENT_IDLE_MAX_MS: '1000' },
      { WORKER_SETTLEMENT_OBSERVATION_ENABLED: 'TRUE' },
    ]) {
      expect(() => parseSettlementConfig({ ...enabled, ...override })).toThrow();
    }
  });
});
