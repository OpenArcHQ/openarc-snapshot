import { createHash } from 'node:crypto';
import { describe, expect, expectTypeOf, it } from 'vitest';
import {
  CONTROL_PAYMENT_ATTEMPT_STORE_ERROR_MESSAGES,
  ControlPaymentAttemptStore,
  ControlPaymentAttemptStoreError,
  PAYMENT_ATTEMPT_STATES,
  PAYMENT_ATTEMPT_STATE_ADMITS_NO_RELEASE,
  digestPaymentAttemptBinding,
  type PaymentAttemptBindingInput,
  type PaymentAttemptState,
  type PaymentAttemptStateAdmitsNoRelease,
} from '../src/index.js';
import type { TenantClient, TenantPool } from '../src/tenant-store.js';

/**
 * Pure validation / mapping proofs for ControlPaymentAttemptStore. No
 * database: every refusal below must happen before a connection is taken.
 */

const TOKEN = 'a'.repeat(64);
const SIGNATURE_CANARY = `0x${'5a'.repeat(65)}`;
const PRIVATE_KEY_CANARY = `0x${'e7'.repeat(32)}`;

function hex(seed: string): string {
  return createHash('sha256').update(seed, 'utf8').digest('hex');
}

/** Independent reimplementation of packages/x402 canonicalJson + digestCanonical. */
function laneCanonicalJson(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => laneCanonicalJson(item)).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${laneCanonicalJson(record[key])}`).join(',')}}`;
}

function laneDigest(value: unknown): string {
  return `sha256:${hex(laneCanonicalJson(value))}`;
}

function binding(overrides: Partial<Record<keyof PaymentAttemptBindingInput, string>> = {}): PaymentAttemptBindingInput {
  const now = 1_800_000_000;
  return {
    schemaVersion: 'openarc.x402.lane-binding.v1',
    role: 'buyer',
    network: 'eip155:5042002',
    grantId: 'openarc:grant:40000000-0000-4000-8000-000000000001',
    actionId: 'openarc:action:40000000-0000-4000-8000-000000000001',
    attemptId: '40000000-0000-4000-8000-000000770001',
    grantRequirementDigest: `sha256:${hex('grant-requirement')}`,
    laneRequirementDigest: `sha256:${hex('lane-requirement')}`,
    verifyingContract: '0x0077777d7EBA4688BDeF3E311b846F25870A19B9',
    asset: '0x3600000000000000000000000000000000000000',
    from: '0x1111111111111111111111111111111111111111',
    to: '0x2222222222222222222222222222222222222222',
    value: '1000000',
    validAfter: String(now - 600),
    validBefore: String(now + 604800 + 900),
    nonce: `0x${hex('nonce')}`,
    ...overrides,
  };
}

interface Recorder {
  readonly pool: TenantPool;
  readonly queries: string[];
  connects: number;
  destroyed: boolean[];
}

function recorder(
  respond: (text: string) => Promise<{ rows: Record<string, unknown>[] }> = async () => ({ rows: [] }),
): Recorder {
  const state: Recorder = {
    queries: [],
    connects: 0,
    destroyed: [],
    pool: {
      connect: async (): Promise<TenantClient> => {
        state.connects += 1;
        return {
          query: (async (text: string) => {
            state.queries.push(text);
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

async function expectCode(promise: Promise<unknown>, code: string): Promise<ControlPaymentAttemptStoreError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ControlPaymentAttemptStoreError);
    expect((error as ControlPaymentAttemptStoreError).code).toBe(code);
    return error as ControlPaymentAttemptStoreError;
  }
  throw new Error(`expected ${code}`);
}

describe('ControlPaymentAttemptStore state model', () => {
  it('mirrors LaneExposure with a pre-dispatch persisted state and no release state at the type level', () => {
    expect([...PAYMENT_ATTEMPT_STATES]).toEqual(['persisted', 'unknown', 'pending', 'committed']);
    expect(PAYMENT_ATTEMPT_STATE_ADMITS_NO_RELEASE).toBe(true);
    expectTypeOf<PaymentAttemptStateAdmitsNoRelease>().toEqualTypeOf<true>();
    // @ts-expect-error released is not a durable attempt state
    const released: PaymentAttemptState = 'released';
    // @ts-expect-error failed is not a durable attempt state
    const failed: PaymentAttemptState = 'failed';
    // @ts-expect-error released_unsent is not a durable attempt state
    const unsent: PaymentAttemptState = 'released_unsent';
    expect([released, failed, unsent]).toHaveLength(3);
  });
});

describe('ControlPaymentAttemptStore binding digest', () => {
  it('reproduces the lane canonical digest and is independent of key order', () => {
    const value = binding();
    expect(digestPaymentAttemptBinding(value)).toBe(laneDigest(value));
    const reversed = Object.fromEntries(Object.entries(value).reverse()) as unknown as PaymentAttemptBindingInput;
    expect(digestPaymentAttemptBinding(reversed)).toBe(digestPaymentAttemptBinding(value));
    expect(digestPaymentAttemptBinding(binding({ value: '1000001' }))).not.toBe(digestPaymentAttemptBinding(value));
  });
});

describe('ControlPaymentAttemptStore input validation', () => {
  it('rejects a non-pool at construction', () => {
    expect(() => new ControlPaymentAttemptStore(null as unknown as TenantPool)).toThrow(ControlPaymentAttemptStoreError);
    expect(() => new ControlPaymentAttemptStore({} as TenantPool)).toThrow(ControlPaymentAttemptStoreError);
  });

  it('refuses every malformed or overriding persist input before taking a connection', async () => {
    const rec = recorder();
    const store = new ControlPaymentAttemptStore(rec.pool);
    const good = binding();
    const cases: unknown[] = [
      { binding: good, bindingDigest: digestPaymentAttemptBinding(good), signature: SIGNATURE_CANARY },
      { binding: { ...good, signature: SIGNATURE_CANARY }, bindingDigest: digestPaymentAttemptBinding(good) },
      { binding: { ...good, privateKey: PRIVATE_KEY_CANARY }, bindingDigest: digestPaymentAttemptBinding(good) },
      { binding: { ...good, calldata: '0xdeadbeef' }, bindingDigest: digestPaymentAttemptBinding(good) },
      { binding: { ...good, origin: 'https://evil.example.com' }, bindingDigest: digestPaymentAttemptBinding(good) },
      { binding: good },
      [good],
      null,
    ];
    const overrides: Partial<Record<keyof PaymentAttemptBindingInput, string>>[] = [
      { schemaVersion: 'openarc.x402.lane-binding.v2' },
      { role: 'provider' },
      { network: 'eip155:1' },
      { network: 'eip155:5042002 ' },
      { asset: '0x0000000000000000000000000000000000000001' },
      { verifyingContract: '0x0077777d7eba4688bdef3e311b846f25870a19b9' },
      { verifyingContract: '0x0022222ABE238Cc2C7Bb1f21003F0a260052475B' },
      { from: '0x0000000000000000000000000000000000000000' },
      { from: 'not-an-address' },
      { to: '0x1111111111111111111111111111111111111111' },
      { to: '0x0077777d7eba4688bdef3e311b846f25870a19b9' },
      { to: '0x3600000000000000000000000000000000000000' },
      { value: '0' },
      { value: '0.01' },
      { value: '$0.01' },
      { value: '1e6' },
      { value: '01000000' },
      { value: `1${'0'.repeat(78)}` },
      { nonce: `0x${'0'.repeat(64)}` },
      { nonce: `0x${hex('nonce').toUpperCase()}` },
      { nonce: SIGNATURE_CANARY },
      { validBefore: String(1_800_000_000 - 600) },
      { validBefore: String(1_800_000_000 + 3600) },
      { attemptId: '40000000-0000-1000-8000-000000770001' },
      { grantId: 'openarc:grant:nope' },
      { grantRequirementDigest: 'sha256:xyz' },
      { laneRequirementDigest: hex('no-prefix') },
    ];
    for (const override of overrides) {
      const value = binding(override);
      cases.push({ binding: value, bindingDigest: digestPaymentAttemptBinding(value) });
    }
    // A digest that does not describe the binding is refused locally.
    cases.push({ binding: good, bindingDigest: digestPaymentAttemptBinding(binding({ value: '2' })) });
    for (const input of cases) {
      const error = await expectCode(store.persistBuyerAttempt(TOKEN, input), 'CONTROL_PAYMENT_ATTEMPT_STORE_INPUT_INVALID');
      // Fixed message: nothing from the input is ever echoed.
      expect(error.message).toBe(CONTROL_PAYMENT_ATTEMPT_STORE_ERROR_MESSAGES.CONTROL_PAYMENT_ATTEMPT_STORE_INPUT_INVALID);
      expect(error.message).not.toContain('0x');
    }
    await expectCode(
      store.persistBuyerAttempt('A'.repeat(64), { binding: good, bindingDigest: digestPaymentAttemptBinding(good) }),
      'CONTROL_PAYMENT_ATTEMPT_STORE_INPUT_INVALID',
    );
    await expectCode(store.recordDispatch(TOKEN, { attemptId: good.attemptId }), 'CONTROL_PAYMENT_ATTEMPT_STORE_INPUT_INVALID');
    await expectCode(
      store.recordDispatch(TOKEN, { attemptId: good.attemptId, bindingDigest: digestPaymentAttemptBinding(good), signature: SIGNATURE_CANARY }),
      'CONTROL_PAYMENT_ATTEMPT_STORE_INPUT_INVALID',
    );
    await expectCode(store.readAgentAttempt(TOKEN, 'not-a-uuid'), 'CONTROL_PAYMENT_ATTEMPT_STORE_INPUT_INVALID');
    expect(rec.connects).toBe(0);
  });

  it('refuses malformed payment-terms and registrar inputs before taking a connection', async () => {
    const rec = recorder();
    const store = new ControlPaymentAttemptStore(rec.pool);
    const org = 'openarc:org:40000000-0000-4000-8000-000000000001';
    const listing = 'openarc:listing:40000000-0000-4000-8000-000000000003';
    const goodMeta = { idempotencyKey: Buffer.alloc(32, 1).toString('base64url'), mutationId: '40000000-0000-4000-8000-000000000099' };
    const terms: [unknown, unknown, unknown, unknown, unknown][] = [
      [org, listing, '1', { payToAddress: '0x0000000000000000000000000000000000000000' }, goodMeta],
      [org, listing, '1', { payToAddress: '0x0077777d7EBA4688BDeF3E311b846F25870A19B9' }, goodMeta],
      [org, listing, '1', { payToAddress: '0x3600000000000000000000000000000000000000' }, goodMeta],
      [org, listing, '1', { payToAddress: 'nope' }, goodMeta],
      [org, listing, '1', { payToAddress: '0x2222222222222222222222222222222222222222', calldata: '0x' }, goodMeta],
      [org, listing, '1', { payToAddress: '0x2222222222222222222222222222222222222222', origin: 'https://evil.example.com' }, goodMeta],
      [org, listing, '01', { payToAddress: '0x2222222222222222222222222222222222222222' }, goodMeta],
      [org, 'openarc:listing:nope', '1', { payToAddress: '0x2222222222222222222222222222222222222222' }, goodMeta],
      ['openarc:org:nope', listing, '1', { payToAddress: '0x2222222222222222222222222222222222222222' }, goodMeta],
      [org, listing, '1', { payToAddress: '0x2222222222222222222222222222222222222222' }, { ...goodMeta, extra: 1 }],
      [org, listing, '1', { payToAddress: '0x2222222222222222222222222222222222222222' }, { ...goodMeta, idempotencyKey: 'short' }],
    ];
    for (const [o, l, v, input, meta] of terms) {
      await expectCode(store.recordListingPaymentTerms(TOKEN, o, l, v, input, meta), 'CONTROL_PAYMENT_ATTEMPT_STORE_INPUT_INVALID');
    }
    for (const input of [
      { requirementId: 'openarc:requirement:nope', listingId: listing },
      { requirementId: 'openarc:requirement:40000000-0000-4000-8000-000000000001' },
      { requirementId: 'openarc:requirement:40000000-0000-4000-8000-000000000001', listingId: listing, amountAtomic: '1' },
      { requirementId: 'openarc:requirement:40000000-0000-4000-8000-000000000001', listingId: listing, payTo: '0x2222222222222222222222222222222222222222' },
    ]) {
      await expectCode(store.registerVerifiedRequirement(TOKEN, input), 'CONTROL_PAYMENT_ATTEMPT_STORE_INPUT_INVALID');
    }
    expect(rec.connects).toBe(0);
  });
});

describe('ControlPaymentAttemptStore error mapping', () => {
  function failingOn(code: string): Recorder {
    return recorder(async (text) => {
      if (text === 'BEGIN' || text === 'ROLLBACK') return { rows: [] };
      throw Object.assign(new Error(`driver detail ${SIGNATURE_CANARY}`), { code });
    });
  }

  it('maps database codes to fixed non-echoing store codes and rolls back', async () => {
    const good = binding();
    const input = { binding: good, bindingDigest: digestPaymentAttemptBinding(good) };
    const expected: [string, string][] = [
      ['28000', 'CONTROL_PAYMENT_ATTEMPT_STORE_SESSION_INVALID'],
      ['42501', 'CONTROL_PAYMENT_ATTEMPT_STORE_FORBIDDEN'],
      ['23503', 'CONTROL_PAYMENT_ATTEMPT_STORE_NOT_FOUND'],
      ['23505', 'CONTROL_PAYMENT_ATTEMPT_STORE_CONFLICT'],
      ['P0D01', 'CONTROL_PAYMENT_ATTEMPT_STORE_IDEMPOTENCY_CONFLICT'],
      ['P0D10', 'CONTROL_PAYMENT_ATTEMPT_STORE_REQUIREMENT_UNAVAILABLE'],
      ['P0D13', 'CONTROL_PAYMENT_ATTEMPT_STORE_POTENTIAL_EXPOSURE'],
      ['P0D14', 'CONTROL_PAYMENT_ATTEMPT_STORE_ATTEMPT_CONFLICT'],
      ['P0D15', 'CONTROL_PAYMENT_ATTEMPT_STORE_GRANT_EXPIRED'],
      ['22023', 'CONTROL_PAYMENT_ATTEMPT_STORE_INPUT_INVALID'],
      ['23514', 'CONTROL_PAYMENT_ATTEMPT_STORE_INPUT_INVALID'],
      ['XX000', 'CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE'],
    ];
    for (const [dbCode, storeCode] of expected) {
      const rec = failingOn(dbCode);
      const error = await expectCode(new ControlPaymentAttemptStore(rec.pool).persistBuyerAttempt(TOKEN, input), storeCode);
      expect(error.message).not.toContain(SIGNATURE_CANARY);
      expect(error.message).not.toContain('driver detail');
      expect(rec.queries).toContain('ROLLBACK');
      expect(rec.destroyed).toEqual([false]);
    }
  });

  it('reports a lost COMMIT as OUTCOME_UNKNOWN and destroys the connection', async () => {
    const good = binding();
    const rec = recorder(async (text) => {
      if (text === 'COMMIT') throw new Error('connection lost');
      if (text === 'BEGIN') return { rows: [] };
      return { rows: [attemptRow(good, { out_replayed: false })] };
    });
    await expectCode(
      new ControlPaymentAttemptStore(rec.pool).persistBuyerAttempt(TOKEN, { binding: good, bindingDigest: digestPaymentAttemptBinding(good) }),
      'CONTROL_PAYMENT_ATTEMPT_STORE_OUTCOME_UNKNOWN',
    );
    expect(rec.destroyed).toEqual([true]);
  });
});

function attemptRow(value: PaymentAttemptBindingInput, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    out_organization_id: 'openarc:org:40000000-0000-4000-8000-000000000001',
    out_attempt_id: value.attemptId,
    out_grant_id: value.grantId,
    out_action_id: value.actionId,
    out_provider_id: 'openarc:provider:40000000-0000-4000-8000-000000000002',
    out_listing_id: 'openarc:listing:40000000-0000-4000-8000-000000000003',
    out_listing_version: '1',
    out_requirement_id: 'openarc:requirement:40000000-0000-4000-8000-000000000001',
    out_requirement_digest: value.grantRequirementDigest,
    out_network_id: 'eip155:5042002',
    out_asset_address: value.asset,
    out_verifying_contract: value.verifyingContract,
    out_payer_address: value.from,
    out_pay_to_address: value.to,
    out_value_atomic: value.value,
    out_valid_after: value.validAfter,
    out_valid_before: value.validBefore,
    out_nonce: value.nonce,
    out_lane_requirement_digest: value.laneRequirementDigest,
    out_binding_digest: digestPaymentAttemptBinding(value),
    out_state: 'persisted',
    out_persisted_at: '2026-09-15 20:00:00.123456+00',
    out_dispatched_at: null,
    out_observed_at: null,
    out_transfer_id: null,
    out_gateway_status: null,
    out_batch_tx_hash: null,
    ...extra,
  };
}

describe('ControlPaymentAttemptStore output re-validation', () => {
  it('accepts a well-formed persisted row and refuses rows that disagree with the binding or the state model', async () => {
    const good = binding();
    const input = { binding: good, bindingDigest: digestPaymentAttemptBinding(good) };
    const ok = recorder(async (text) => (text === 'BEGIN' || text === 'COMMIT' ? { rows: [] } : { rows: [attemptRow(good, { out_replayed: false })] }));
    const result = await new ControlPaymentAttemptStore(ok.pool).persistBuyerAttempt(TOKEN, input);
    expect(result.replayed).toBe(false);
    expect(result.attempt.bindingDigest).toBe(input.bindingDigest);
    expect(result.attempt.persistedAt).toBe('2026-09-15T20:00:00.123456Z');

    const bad: Record<string, unknown>[] = [
      { out_replayed: false, out_state: 'released' },
      { out_replayed: false, out_state: 'failed' },
      { out_replayed: false, out_binding_digest: `sha256:${hex('other')}` },
      { out_replayed: false, out_value_atomic: '2000000' },
      { out_replayed: false, out_verifying_contract: '0x0077777d7eba4688bdef3e311b846f25870a19b9' },
      { out_replayed: false, out_state: 'unknown' },
      { out_replayed: 'yes' },
      { out_replayed: true, out_state: 'committed', out_dispatched_at: '2026-09-15 20:00:01+00', out_observed_at: '2026-09-15 20:00:02+00', out_transfer_id: '40000000-0000-4000-8000-000000000009', out_gateway_status: 'completed', out_batch_tx_hash: null },
    ];
    for (const extra of bad) {
      const rec = recorder(async (text) => (text === 'BEGIN' || text === 'ROLLBACK' ? { rows: [] } : { rows: [attemptRow(good, extra)] }));
      await expectCode(new ControlPaymentAttemptStore(rec.pool).persistBuyerAttempt(TOKEN, input), 'CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE');
    }
    const dispatchedWrongState = recorder(async (text) => (text === 'BEGIN' || text === 'ROLLBACK' ? { rows: [] } : { rows: [attemptRow(good)] }));
    await expectCode(
      new ControlPaymentAttemptStore(dispatchedWrongState.pool).recordDispatch(TOKEN, { attemptId: good.attemptId, bindingDigest: input.bindingDigest }),
      'CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE',
    );
    const twoRows = recorder(async (text) => (text === 'BEGIN' || text === 'ROLLBACK' ? { rows: [] } : { rows: [attemptRow(good), attemptRow(good)] }));
    await expectCode(new ControlPaymentAttemptStore(twoRows.pool).readAgentAttempt(TOKEN, good.attemptId), 'CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE');
    const none = recorder(async () => ({ rows: [] }));
    expect(await new ControlPaymentAttemptStore(none.pool).readAgentAttempt(TOKEN, good.attemptId)).toBeNull();
  });
});
