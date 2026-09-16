import { describe, expect, expectTypeOf, it } from 'vitest';
import {
  MAX_OBSERVATION_ATTEMPTS,
  OBSERVABLE_ATTEMPT_STATES,
  OBSERVATION_ADMITS_NO_RELEASE,
  RECORDABLE_OBSERVATION_STATES,
  SETTLEMENT_OBSERVATION_STORE_ERROR_MESSAGES,
  SettlementObservationStore,
  SettlementObservationStoreError,
  type ObservableAttemptState,
  type ObservationAdmitsNoRelease,
  type RecordableObservationState,
} from '../src/index.js';
import type { OutboxClient, OutboxPool } from '../src/outbox-store.js';

/**
 * Pure validation / mapping proofs for SettlementObservationStore. No
 * database: every refusal below must happen BEFORE a connection is taken, so a
 * malformed observation can never reach the recorder.
 */

const ORG = 'openarc:org:40000000-0000-4000-8000-000000000001';
const ATTEMPT = '40000000-0000-4000-8000-000000770001';
const TRANSFER = '3f1c1b7e-8a1d-4f5e-9b2a-1c2d3e4f5a6b';
const BATCH = `0x${'ab'.repeat(32)}`;
const SIGNATURE_CANARY = `0x${'5a'.repeat(65)}`;

/** A pool that fails the test if it is ever opened. */
function forbiddenPool(): OutboxPool {
  return {
    connect(): Promise<OutboxClient> {
      throw new Error('a refused input must never open a connection');
    },
  };
}

function store(): SettlementObservationStore {
  return new SettlementObservationStore(forbiddenPool());
}

function observation(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    organizationId: ORG,
    attemptId: ATTEMPT,
    leaseGeneration: '1',
    state: 'pending',
    transferId: TRANSFER,
    gatewayStatus: 'received',
    batchTxHash: null,
    ...overrides,
  };
}

async function expectInputInvalid(promise: Promise<unknown>, label: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect([label, error instanceof SettlementObservationStoreError]).toEqual([label, true]);
    expect([label, (error as SettlementObservationStoreError).code]).toEqual([
      label,
      'SETTLEMENT_OBSERVATION_STORE_INPUT_INVALID',
    ]);
    return;
  }
  throw new Error(`expected a refusal: ${label}`);
}

describe('closed observation vocabulary', () => {
  it('admits exactly the two positive observations and the two observable states', () => {
    expect([...RECORDABLE_OBSERVATION_STATES]).toEqual(['pending', 'committed']);
    expect([...OBSERVABLE_ATTEMPT_STATES]).toEqual(['unknown', 'pending']);
    expect(MAX_OBSERVATION_ATTEMPTS).toBe(10);
  });

  it('cannot represent any release, failure, refund, expiry or cancellation', () => {
    const forbidden = [
      'released', 'released_unsent', 'failed', 'rejected', 'expired',
      'cancelled', 'refunded', 'not_paid', 'nonpayment',
    ];
    for (const state of forbidden) {
      expect(RECORDABLE_OBSERVATION_STATES as readonly string[]).not.toContain(state);
      expect(OBSERVABLE_ATTEMPT_STATES as readonly string[]).not.toContain(state);
    }
    // `persisted` is never observable: an attempt that was never dispatched
    // has no exposure to observe. `committed` is terminal, never re-observed.
    expect(OBSERVABLE_ATTEMPT_STATES as readonly string[]).not.toContain('persisted');
    expect(OBSERVABLE_ATTEMPT_STATES as readonly string[]).not.toContain('committed');
  });

  it('proves at compile time that no release state is representable', () => {
    expect(OBSERVATION_ADMITS_NO_RELEASE).toBe(true);
    expectTypeOf<ObservationAdmitsNoRelease>().toEqualTypeOf<true>();
    expectTypeOf<RecordableObservationState>().toEqualTypeOf<'pending' | 'committed'>();
    expectTypeOf<ObservableAttemptState>().toEqualTypeOf<'unknown' | 'pending'>();
  });

  it('keeps a fixed, non-echoing error message table', () => {
    for (const message of Object.values(SETTLEMENT_OBSERVATION_STORE_ERROR_MESSAGES)) {
      expect(message.startsWith('SettlementObservationStore ')).toBe(true);
      expect(message).not.toContain(ORG);
      expect(message).not.toContain(ATTEMPT);
    }
  });
});

describe('construction', () => {
  it('refuses anything that is not a pool', () => {
    for (const value of [null, undefined, 0, 'pool', {}, { connect: 1 }, []]) {
      expect(() => new SettlementObservationStore(value as unknown as OutboxPool)).toThrow(
        SettlementObservationStoreError,
      );
    }
  });
});

describe('claim input', () => {
  it('refuses a limit outside 1..25 before opening a connection', async () => {
    for (const limit of [0, -1, 26, 1000, 1.5, Number.NaN, '5', null]) {
      await expectInputInvalid(
        store().claim({ limit } as unknown as { limit?: number }),
        `limit:${String(limit)}`,
      );
    }
  });
});

describe('observation input', () => {
  it('refuses an unknown, missing or undefined key without echoing it', async () => {
    await expectInputInvalid(
      store().recordObservation({ ...observation(), signature: SIGNATURE_CANARY }),
      'extra key',
    );
    const missing = observation();
    delete missing['batchTxHash'];
    await expectInputInvalid(store().recordObservation(missing), 'missing key');
    await expectInputInvalid(
      store().recordObservation(observation({ transferId: undefined })),
      'undefined value',
    );
    // Indexed labels: a null-prototype object cannot be coerced to a string.
    const shapes: unknown[] = [null, undefined, 'x', 7, [], Object.create(null) as object];
    for (let index = 0; index < shapes.length; index += 1) {
      await expectInputInvalid(store().recordObservation(shapes[index]), `shape:${index}`);
    }
  });

  it('refuses every non-positive state, including every release form', async () => {
    for (const state of [
      'unknown', 'persisted', 'released', 'released_unsent', 'failed', 'rejected',
      'expired', 'cancelled', 'refunded', 'not_paid', 'nonpayment', 'PENDING', '',
    ]) {
      await expectInputInvalid(store().recordObservation(observation({ state })), `state:${state}`);
    }
  });

  it('refuses a malformed organization, attempt, transfer or lease generation', async () => {
    for (const organizationId of [ORG.toUpperCase(), `${ORG}\n`, 'openarc:org:nope', '']) {
      await expectInputInvalid(
        store().recordObservation(observation({ organizationId })),
        `org:${organizationId}`,
      );
    }
    for (const attemptId of [`${ATTEMPT}\n`, '40000000-0000-1000-8000-000000770001', 'nope']) {
      await expectInputInvalid(
        store().recordObservation(observation({ attemptId })),
        `attempt:${attemptId}`,
      );
    }
    for (const transferId of ['nope', `${TRANSFER}\n`, '']) {
      await expectInputInvalid(
        store().recordObservation(observation({ transferId })),
        `transfer:${transferId}`,
      );
    }
    // Generation 0 is never a real lease, and a non-canonical decimal is refused.
    for (const leaseGeneration of ['0', '', '01', '1.0', '-1', 1 as unknown as string, '1e3', 'x']) {
      await expectInputInvalid(
        store().recordObservation(observation({ leaseGeneration })),
        `generation:${String(leaseGeneration)}`,
      );
    }
  });

  it('enforces the exact committed shape: completed status and a real batch hash', async () => {
    await expectInputInvalid(
      store().recordObservation(observation({ state: 'committed', gatewayStatus: 'completed', batchTxHash: null })),
      'committed without hash',
    );
    for (const gatewayStatus of ['received', 'batched', 'confirmed', 'failed']) {
      await expectInputInvalid(
        store().recordObservation(observation({ state: 'committed', gatewayStatus, batchTxHash: BATCH })),
        `committed status:${gatewayStatus}`,
      );
    }
    for (const batchTxHash of [`0x${'AB'.repeat(32)}`, '0xabc', `${BATCH}\n`, SIGNATURE_CANARY]) {
      await expectInputInvalid(
        store().recordObservation(observation({ state: 'committed', gatewayStatus: 'completed', batchTxHash })),
        `committed hash:${batchTxHash}`,
      );
    }
  });

  it('enforces the exact pending shape: a held gateway status, never completed', async () => {
    for (const gatewayStatus of ['completed', 'failed', 'settled', '']) {
      await expectInputInvalid(
        store().recordObservation(observation({ state: 'pending', gatewayStatus })),
        `pending status:${gatewayStatus}`,
      );
    }
    await expectInputInvalid(
      store().recordObservation(observation({ state: 'pending', batchTxHash: '0xnope' })),
      'pending bad hash',
    );
  });
});

describe('lease release input', () => {
  it('refuses a malformed identity or generation before opening a connection', async () => {
    await expectInputInvalid(store().releaseLease('nope', ATTEMPT, '1'), 'org');
    await expectInputInvalid(store().releaseLease(ORG, 'nope', '1'), 'attempt');
    await expectInputInvalid(store().releaseLease(ORG, ATTEMPT, '0'), 'generation zero');
    await expectInputInvalid(store().releaseLease(ORG, ATTEMPT, 1 as unknown as string), 'generation number');
  });
});
