import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  SettlementObservationStore,
  createDatabasePool,
  migrate,
  type LeasedPaymentAttempt,
} from '@openarc/db';
import type { LaneLookupObservation, LaneTransferRecord } from '@openarc/x402';
import {
  adminPool,
  ensureRoles,
  migratorUrl,
  resetSchema,
  tenantUrl,
  workerUrl,
} from '../../../packages/db/test/postgres-fixture.js';
import {
  PaymentAttemptFixture,
  type DispatchedAttempt,
} from '../../../packages/db/test/payment-attempt-fixture.js';
import {
  SettlementObservationLoop,
  type SettlementClock,
  type SettlementLogRecord,
  type SettlementLookupTransport,
} from '../src/settlement-observation.js';

/**
 * Real PostgreSQL acceptance for the bounded settlement observation loop.
 *
 * The loop runs against the REAL restricted worker role and the real schema17
 * lease surface, with an INJECTED fake transport standing in for a Gateway
 * lookup. No network call is made, nothing is signed, sent or settled, and no
 * live Circle/Gateway/Arc endpoint is contacted. Only the guarded disposable
 * fixture database is reset.
 */

const TRANSFER = '3f1c1b7e-8a1d-4f5e-9b2a-1c2d3e4f5a6b';
const BATCH = `0x${'ab'.repeat(32)}`;

let admin: ReturnType<typeof adminPool>;
let migrator: ReturnType<typeof createDatabasePool>;
let tenant: ReturnType<typeof createDatabasePool>;
let worker: ReturnType<typeof createDatabasePool>;
let store: SettlementObservationStore;
let fixture: PaymentAttemptFixture;

beforeAll(async () => {
  admin = adminPool();
  await ensureRoles(admin);
  migrator = createDatabasePool(migratorUrl());
  tenant = createDatabasePool(tenantUrl());
  worker = createDatabasePool(workerUrl());
});

afterAll(async () => {
  try {
    await resetSchema(admin);
  } finally {
    await worker.end();
    await tenant.end();
    await migrator.end();
    await admin.end();
  }
});

beforeEach(async () => {
  await resetSchema(admin);
  await migrate(migrator);
  store = new SettlementObservationStore(worker);
  fixture = new PaymentAttemptFixture({ admin, tenant });
});

function matchingTransfer(
  attempt: DispatchedAttempt,
  overrides: Partial<LaneTransferRecord> = {},
): LaneTransferRecord {
  return {
    id: TRANSFER,
    status: 'completed',
    fromAddress: attempt.payerAddress,
    toAddress: attempt.payToAddress,
    amount: attempt.valueAtomic,
    nonce: attempt.nonce,
    sendingNetwork: 'eip155:5042002',
    recipientNetwork: 'eip155:5042002',
    txHash: BATCH,
    ...overrides,
  };
}

function transportOf(answer: LaneLookupObservation): SettlementLookupTransport & { calls: number } {
  const transport = {
    calls: 0,
    lookup(): Promise<LaneLookupObservation> {
      transport.calls += 1;
      return Promise.resolve(answer);
    },
  };
  return transport;
}

/** Stops the loop the first time it backs off, so a run is exactly one pass. */
function stoppingClock(ref: { loop?: SettlementObservationLoop }): SettlementClock {
  return {
    now: () => Date.now(),
    sleep: () => {
      ref.loop?.requestStop();
      return Promise.resolve();
    },
  };
}

async function runOnce(
  transport: SettlementLookupTransport,
  logs: SettlementLogRecord[] = [],
): Promise<SettlementLogRecord[]> {
  const ref: { loop?: SettlementObservationLoop } = {};
  const loop = new SettlementObservationLoop({
    store,
    transport,
    claimLimit: 5,
    pollMs: 1,
    idleMaxMs: 1,
    clock: stoppingClock(ref),
    logger: { log: (record) => void logs.push(record) },
  });
  ref.loop = loop;
  await loop.run();
  return logs;
}

async function attemptRow(attemptId: string): Promise<Record<string, unknown>> {
  const result = await admin.query<Record<string, unknown>>(
    'SELECT * FROM openarc_durable.payment_attempts WHERE attempt_id = $1::uuid',
    [attemptId],
  );
  return result.rows[0]!;
}

describe('settlement observation loop against real PostgreSQL', () => {
  it('initializes against the real worker role and the real schema17 surface', async () => {
    await store.initialize();
    await store.readiness();
  }, 120000);

  it('observes a real dispatched attempt to committed through the worker role', async () => {
    const attempt = await fixture.seedDispatchedAttempt(70);
    expect(await attemptRow(attempt.attemptId)).toMatchObject({ state: 'unknown' });

    const transport = transportOf({
      kind: 'records', transfers: [matchingTransfer(attempt)], hasMorePages: false,
    });
    const logs = await runOnce(transport);

    expect(transport.calls).toBe(1);
    expect(logs.filter((record) => record.status === 'observed_committed')).toHaveLength(1);
    expect(await attemptRow(attempt.attemptId)).toMatchObject({
      state: 'committed', transfer_id: TRANSFER, gateway_status: 'completed', batch_tx_hash: BATCH,
    });
    // Terminal: a second pass finds nothing to lease and asks nobody anything.
    const second = transportOf({ kind: 'records', transfers: [matchingTransfer(attempt)], hasMorePages: false });
    await runOnce(second);
    expect(second.calls).toBe(0);
  }, 300000);

  it('advances a real attempt to pending and keeps the exposure held', async () => {
    const attempt = await fixture.seedDispatchedAttempt(71);
    const transport = transportOf({
      kind: 'records',
      transfers: [matchingTransfer(attempt, { status: 'batched', txHash: null })],
      hasMorePages: false,
    });
    const logs = await runOnce(transport);
    expect(logs.filter((record) => record.status === 'observed_pending')).toHaveLength(1);
    expect(await attemptRow(attempt.attemptId)).toMatchObject({
      state: 'pending', gateway_status: 'batched', transfer_id: TRANSFER,
    });
  }, 300000);

  it('leaves a real attempt completely untouched for every unclear answer', async () => {
    const attempt = await fixture.seedDispatchedAttempt(72);
    const before = await attemptRow(attempt.attemptId);
    const answers: LaneLookupObservation[] = [
      { kind: 'timeout' },
      { kind: 'transport_error' },
      { kind: 'http_error', status: 503 },
      { kind: 'malformed' },
      { kind: 'records', transfers: [], hasMorePages: false },
      {
        kind: 'records',
        transfers: [matchingTransfer(attempt, { status: 'failed', txHash: null })],
        hasMorePages: false,
      },
      {
        kind: 'records',
        transfers: [matchingTransfer(attempt, { status: 'weird_new_status', txHash: null })],
        hasMorePages: false,
      },
      {
        kind: 'records',
        transfers: [matchingTransfer(attempt, { amount: '999999' })],
        hasMorePages: false,
      },
      {
        kind: 'records',
        transfers: [matchingTransfer(attempt), matchingTransfer(attempt, { id: '9a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d' })],
        hasMorePages: false,
      },
      {
        kind: 'records',
        transfers: [matchingTransfer(attempt, { txHash: null })],
        hasMorePages: false,
      },
    ];
    for (const answer of answers) {
      const logs = await runOnce(transportOf(answer));
      expect([JSON.stringify(answer).slice(0, 40), logs.some((r) => r.status === 'held')])
        .toEqual([JSON.stringify(answer).slice(0, 40), true]);
      // Never released, failed or refunded: byte-for-byte the same row.
      expect([JSON.stringify(answer).slice(0, 40), await attemptRow(attempt.attemptId)])
        .toEqual([JSON.stringify(answer).slice(0, 40), before]);
    }
    // Ten unclear passes exhausted the bounded retries; the attempt is still
    // exactly as held as it started, and simply stops being claimed.
    expect(await store.claim({ limit: 5 })).toEqual([]);
    expect(await attemptRow(attempt.attemptId)).toEqual(before);
  }, 600000);

  it('never lets two concurrent loops observe the same real attempt', async () => {
    const attempts: DispatchedAttempt[] = [];
    for (const seed of [80, 81]) attempts.push(await fixture.seedDispatchedAttempt(seed));
    const otherPool = createDatabasePool(workerUrl());
    try {
      const otherStore = new SettlementObservationStore(otherPool);
      const seen: string[] = [];
      const makeLoop = (target: SettlementObservationStore): SettlementObservationLoop => {
        const ref: { loop?: SettlementObservationLoop } = {};
        const loop = new SettlementObservationLoop({
          store: {
            claim: async (input) => {
              const leased: LeasedPaymentAttempt[] = await target.claim(input);
              for (const entry of leased) seen.push(entry.attemptId);
              return leased;
            },
            recordObservation: (input) => target.recordObservation(input),
            releaseLease: (org, id, generation) => target.releaseLease(org, id, generation),
          },
          // Answer about the attempt actually being asked about, so every
          // attempt reaches a positive observation and is leased exactly once.
          transport: {
            lookup: ({ binding }) => Promise.resolve({
              kind: 'records',
              transfers: attempts
                .filter((candidate) => candidate.nonce === binding.nonce)
                .map((candidate) => matchingTransfer(candidate)),
              hasMorePages: false,
            } as LaneLookupObservation),
          },
          claimLimit: 5,
          pollMs: 1,
          idleMaxMs: 1,
          clock: stoppingClock(ref),
        });
        ref.loop = loop;
        return loop;
      };
      await Promise.all([makeLoop(store).run(), makeLoop(otherStore).run()]);
      // Every attempt was leased at most once across both loops.
      expect(new Set(seen).size).toBe(seen.length);
      expect(seen.length).toBeLessThanOrEqual(attempts.length);
    } finally {
      await otherPool.end();
    }
  }, 600000);
});
