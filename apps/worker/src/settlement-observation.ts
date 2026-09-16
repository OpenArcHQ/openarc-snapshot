import type {
  LeasedPaymentAttempt,
  RecordableObservationState,
  RecordedObservation,
  ReleaseLeaseResult,
  ClaimObservationsInput,
} from '@openarc/db';
import {
  LANE_BINDING_SCHEMA_VERSION,
  classifyLaneAttempt,
  parseLanePaymentBinding,
  type LaneExposure,
  type LaneLookupObservation,
  type LanePaymentBinding,
} from '@openarc/x402';

/**
 * Bounded settlement observation loop for durable payment attempts.
 *
 * LIMITATION: this loop OBSERVES. It leases attempts that were really
 * dispatched, asks an injected lookup transport about each one, classifies the
 * answer with the accepted packages/x402 resolution rules, and records only a
 * positive observation. It never signs, sends, settles, retries a payment,
 * moves funds or contacts a live Circle/Gateway/Arc endpoint, and there is no
 * code path anywhere below that can mark an attempt released, failed, refunded,
 * expired or cancelled.
 *
 * The classification rules are NOT reimplemented here: `classifyLaneAttempt`
 * from packages/x402 is the single authority, and this module only maps its
 * closed `LaneExposure` result onto the durable recorder's closed input.
 *
 *   LaneExposure            -> durable action
 *   ----------------------------------------------------------------
 *   committed               -> record 'committed' (consumes exposure)
 *   pending                 -> record 'pending'   (stays held)
 *   unknown (any reason)    -> record NOTHING, release the lease, stay held
 *
 * Every `unknown` reason -- timeout, transport_error, http_error,
 * malformed_response, not_found, not_found_after_expiry, nonce_already_used,
 * gateway_failed_not_terminal, ambiguous_records, record_mismatch,
 * completed_without_batch_hash, unrecognized_status -- leaves the attempt
 * exactly as it was. So does a binding this process cannot re-validate and any
 * transport that throws.
 */

export const SETTLEMENT_OBSERVATION_INVALID_MESSAGE =
  'Settlement observation input is invalid.';

/** Fixed, non-echoing error. Never carries attempt, binding or transport detail. */
export class SettlementObservationError extends Error {
  constructor() {
    super(SETTLEMENT_OBSERVATION_INVALID_MESSAGE);
    this.name = 'SettlementObservationError';
  }
}

/**
 * The injected lookup transport. There is deliberately NO default: a loop
 * constructed without one cannot ask anybody anything. It returns the lane's
 * own `LaneLookupObservation`, so a transport can never smuggle a settlement
 * conclusion past the classifier.
 */
export interface SettlementLookupTransport {
  lookup(request: {
    readonly binding: LanePaymentBinding;
    readonly signal: AbortSignal;
  }): Promise<LaneLookupObservation>;
}

/** The narrow store surface this loop needs; SettlementObservationStore satisfies it. */
export interface SettlementObservationStorePort {
  claim(input?: ClaimObservationsInput): Promise<LeasedPaymentAttempt[]>;
  recordObservation(input: {
    readonly organizationId: string;
    readonly attemptId: string;
    readonly leaseGeneration: string;
    readonly state: RecordableObservationState;
    readonly transferId: string;
    readonly gatewayStatus: 'received' | 'batched' | 'confirmed' | 'completed';
    readonly batchTxHash: string | null;
  }): Promise<RecordedObservation | null>;
  releaseLease(
    organizationId: string,
    attemptId: string,
    leaseGeneration: string,
  ): Promise<ReleaseLeaseResult>;
}

export interface SettlementClock {
  now(): number;
  sleep(milliseconds: number, signal: AbortSignal): Promise<void>;
}

export const systemSettlementClock: SettlementClock = {
  now: () => Date.now(),
  sleep: (milliseconds, signal) =>
    new Promise<void>((resolve, reject) => {
      if (signal.aborted) {
        reject(abortReason(signal));
        return;
      }
      const onAbort = (): void => {
        clearTimeout(timer);
        reject(abortReason(signal));
      };
      const timer = setTimeout(() => {
        signal.removeEventListener('abort', onAbort);
        resolve();
      }, milliseconds);
      signal.addEventListener('abort', onAbort, { once: true });
    }),
};

function abortReason(signal: AbortSignal): Error {
  return signal.reason instanceof Error ? signal.reason : new Error('aborted');
}

export type SettlementLogStatus =
  | 'ready'
  | 'claim_empty'
  | 'claim_error'
  | 'claimed'
  | 'observed_pending'
  | 'observed_committed'
  | 'held'
  | 'record_stale'
  | 'record_error'
  | 'outcome_unknown'
  | 'aborted'
  | 'stopping'
  | 'stopped';

/**
 * Bounded allowlisted log record. Only a fixed status, a fixed hold reason and
 * an aggregate count are ever emitted: no attempt, organization, grant,
 * action, transfer, payer, nonce, binding, URL, database URL, error or body is
 * ever logged.
 */
export interface SettlementLogRecord {
  readonly status: SettlementLogStatus;
  readonly reason?: SettlementHoldReason;
  readonly count?: number;
}

export interface SettlementLogger {
  log(record: SettlementLogRecord): void;
}

export const noopSettlementLogger: SettlementLogger = { log: () => undefined };

/** Why an attempt stayed held. Every member is a non-conclusion. */
export type SettlementHoldReason =
  | 'binding_unreadable'
  | 'transport_threw'
  | 'lookup_aborted'
  | LaneExposureUnknownReason;

type LaneExposureUnknownReason = Extract<LaneExposure, { state: 'unknown' }>['reason'];

/**
 * The decision for one attempt. `hold` carries no durable write at all; it is
 * the only outcome for every unclear answer.
 */
export type SettlementDecision =
  | {
      readonly kind: 'record';
      readonly state: RecordableObservationState;
      readonly transferId: string;
      readonly gatewayStatus: 'received' | 'batched' | 'confirmed' | 'completed';
      readonly batchTxHash: string | null;
    }
  | { readonly kind: 'hold'; readonly reason: SettlementHoldReason };

/** States that would release held exposure. None may ever be a decision. */
export type SettlementForbiddenState =
  | 'released'
  | 'released_unsent'
  | 'failed'
  | 'rejected'
  | 'expired'
  | 'cancelled'
  | 'refunded'
  | 'not_paid'
  | 'nonpayment';

type IsNever<T> = [T] extends [never] ? true : false;
export type SettlementAdmitsNoRelease = IsNever<
  Extract<Extract<SettlementDecision, { kind: 'record' }>['state'], SettlementForbiddenState>
>;
/** Compile-time proof: adding a release state to the decision breaks the build here. */
export const SETTLEMENT_ADMITS_NO_RELEASE: SettlementAdmitsNoRelease = true;

function hold(reason: SettlementHoldReason): SettlementDecision {
  return Object.freeze({ kind: 'hold', reason });
}

/**
 * Rebuild the lane binding from a leased attempt. The durable row carries only
 * non-secret binding fields; `parseLanePaymentBinding` re-validates every one
 * against the pinned manifest, so a row this process cannot re-validate is
 * held rather than guessed at.
 */
export function bindingOfLeasedAttempt(attempt: LeasedPaymentAttempt): LanePaymentBinding {
  return parseLanePaymentBinding({
    schemaVersion: LANE_BINDING_SCHEMA_VERSION,
    role: 'buyer',
    network: attempt.networkId,
    grantId: attempt.grantId,
    actionId: attempt.actionId,
    attemptId: attempt.attemptId,
    grantRequirementDigest: attempt.requirementDigest,
    laneRequirementDigest: attempt.laneRequirementDigest,
    verifyingContract: attempt.verifyingContract,
    asset: attempt.assetAddress,
    from: attempt.payerAddress,
    to: attempt.payToAddress,
    value: attempt.valueAtomic,
    validAfter: attempt.validAfter,
    validBefore: attempt.validBefore,
    nonce: attempt.nonce,
  });
}

/**
 * Map one lane classification onto a durable decision. This is the ONLY place
 * a lookup answer becomes an action, and it can only ever produce a positive
 * record or a hold.
 */
export function decideFromExposure(exposure: LaneExposure): SettlementDecision {
  switch (exposure.state) {
    case 'committed':
      return Object.freeze({
        kind: 'record',
        state: 'committed',
        transferId: exposure.transferId,
        gatewayStatus: exposure.gatewayStatus,
        batchTxHash: exposure.batchTxHash,
      });
    case 'pending':
      return Object.freeze({
        kind: 'record',
        state: 'pending',
        transferId: exposure.transferId,
        gatewayStatus: exposure.gatewayStatus,
        batchTxHash: exposure.batchTxHash,
      });
    case 'unknown':
      return hold(exposure.reason);
  }
}

/**
 * Classify one leased attempt end to end. Any failure to read the binding, any
 * transport throw and any abort are holds; everything else is delegated to the
 * accepted lane rules.
 */
export async function classifyLeasedAttempt(
  attempt: LeasedPaymentAttempt,
  transport: SettlementLookupTransport,
  options: { readonly nowUnixSeconds: number; readonly signal: AbortSignal },
): Promise<SettlementDecision> {
  let binding: LanePaymentBinding;
  try {
    binding = bindingOfLeasedAttempt(attempt);
  } catch {
    return hold('binding_unreadable');
  }
  let lookup: LaneLookupObservation;
  try {
    lookup = await transport.lookup({ binding, signal: options.signal });
  } catch {
    return options.signal.aborted ? hold('lookup_aborted') : hold('transport_threw');
  }
  if (options.signal.aborted) return hold('lookup_aborted');
  let exposure: LaneExposure;
  try {
    exposure = classifyLaneAttempt({
      binding,
      nowUnixSeconds: options.nowUnixSeconds,
      lookup,
    });
  } catch {
    return hold('malformed_response');
  }
  return decideFromExposure(exposure);
}

export interface SettlementObservationLoopOptions {
  readonly store: SettlementObservationStorePort;
  /** Required. There is no default transport. */
  readonly transport: SettlementLookupTransport;
  readonly claimLimit: number;
  readonly pollMs: number;
  readonly idleMaxMs: number;
  /** Bounded per-attempt lookup deadline. Integer in 1..30000. */
  readonly lookupTimeoutMs?: number;
  /** Bounded whole-batch deadline. Integer in 1..120000. */
  readonly batchDeadlineMs?: number;
  /**
   * Bound on CONSECUTIVE claim failures before the loop stops instead of
   * retrying forever, mirroring the tenant notification loop. A single
   * successful claim resets the counter. Integer in 1..1000; defaults to 10.
   */
  readonly maxConsecutiveClaimErrors?: number;
  readonly clock?: SettlementClock;
  readonly logger?: SettlementLogger;
}

const DEFAULT_LOOKUP_TIMEOUT_MS = 10_000;
const MAX_LOOKUP_TIMEOUT_MS = 30_000;
const DEFAULT_BATCH_DEADLINE_MS = 60_000;
const MAX_BATCH_DEADLINE_MS = 120_000;
const MAX_CLAIM_LIMIT = 25;

class SettlementShutdown extends Error {
  constructor() {
    super('settlement observation abort');
    this.name = 'SettlementShutdown';
  }
}

function isBoundedInteger(value: unknown, min: number, max: number): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= min && value <= max;
}

/**
 * Bounded observation loop. It claims a batch, processes it sequentially so a
 * single transport can never be asked more than one question at a time, and
 * never claims a next batch before the current one has settled.
 */
export class SettlementObservationLoop {
  readonly #store: SettlementObservationStorePort;
  readonly #transport: SettlementLookupTransport;
  readonly #claimLimit: number;
  readonly #pollMs: number;
  readonly #idleMaxMs: number;
  readonly #lookupTimeoutMs: number;
  readonly #batchDeadlineMs: number;
  readonly #maxConsecutiveClaimErrors: number;
  readonly #clock: SettlementClock;
  readonly #logger: SettlementLogger;
  readonly #stopController = new AbortController();
  readonly #workController = new AbortController();
  readonly #settled: Promise<void>;
  #resolveSettled: (() => void) | undefined;
  #stopRequested = false;
  #started = false;

  constructor(options: SettlementObservationLoopOptions) {
    if (options.store === undefined || typeof options.store.claim !== 'function') {
      throw new SettlementObservationError();
    }
    if (options.transport === undefined || typeof options.transport.lookup !== 'function') {
      // No transport means no questions may be asked at all.
      throw new SettlementObservationError();
    }
    if (!isBoundedInteger(options.claimLimit, 1, MAX_CLAIM_LIMIT)) {
      throw new SettlementObservationError();
    }
    if (!isBoundedInteger(options.pollMs, 1, 60_000)) throw new SettlementObservationError();
    if (!isBoundedInteger(options.idleMaxMs, options.pollMs, 300_000)) {
      throw new SettlementObservationError();
    }
    const lookupTimeout = options.lookupTimeoutMs ?? DEFAULT_LOOKUP_TIMEOUT_MS;
    if (!isBoundedInteger(lookupTimeout, 1, MAX_LOOKUP_TIMEOUT_MS)) {
      throw new SettlementObservationError();
    }
    const batchDeadline = options.batchDeadlineMs ?? DEFAULT_BATCH_DEADLINE_MS;
    if (!isBoundedInteger(batchDeadline, 1, MAX_BATCH_DEADLINE_MS)) {
      throw new SettlementObservationError();
    }
    const claimErrorBound = options.maxConsecutiveClaimErrors ?? 10;
    if (!isBoundedInteger(claimErrorBound, 1, 1000)) throw new SettlementObservationError();
    this.#store = options.store;
    this.#transport = options.transport;
    this.#claimLimit = options.claimLimit;
    this.#pollMs = options.pollMs;
    this.#idleMaxMs = options.idleMaxMs;
    this.#lookupTimeoutMs = lookupTimeout;
    this.#batchDeadlineMs = batchDeadline;
    this.#maxConsecutiveClaimErrors = claimErrorBound;
    this.#clock = options.clock ?? systemSettlementClock;
    this.#logger = options.logger ?? noopSettlementLogger;
    this.#settled = new Promise<void>((resolve) => {
      this.#resolveSettled = resolve;
    });
  }

  /** Resolves after the loop has drained and exited. */
  get settled(): Promise<void> {
    return this.#settled;
  }

  /** Stop claiming new batches immediately; inflight work is left to settle. */
  requestStop(): void {
    if (this.#stopRequested) return;
    this.#stopRequested = true;
    this.#stopController.abort(new SettlementShutdown());
  }

  /** Abort inflight lookups. No late observation will be recorded. */
  abort(): void {
    this.#workController.abort(new SettlementShutdown());
  }

  async run(): Promise<void> {
    if (this.#started) throw new SettlementObservationError();
    this.#started = true;
    let backoffMs = this.#pollMs;
    let consecutiveClaimErrors = 0;
    // One observation per attempt per sweep. Releasing the lease after an
    // unclear answer makes the attempt immediately claimable again, so without
    // this guard a single run could re-lease the same attempt back-to-back and
    // burn its whole bounded retry budget in a tight cycle. The set is cleared
    // whenever a sweep finds nothing fresh, so it stays bounded and an attempt
    // is retried on a later sweep.
    const processed = new Set<string>();
    try {
      while (!this.#stopRequested) {
        let leased: LeasedPaymentAttempt[];
        try {
          leased = await this.#store.claim({ limit: this.#claimLimit });
        } catch {
          consecutiveClaimErrors += 1;
          this.#logger.log({ status: 'claim_error', count: 1 });
          if (consecutiveClaimErrors >= this.#maxConsecutiveClaimErrors) {
            // Bounded: a permanently unclaimable queue would otherwise spin at
            // idleMaxMs forever. Stop so the supervisor sees the condition.
            this.#logger.log({ status: 'stopping', count: consecutiveClaimErrors });
            break;
          }
          await this.#backoff(backoffMs);
          backoffMs = Math.min(backoffMs * 2, this.#idleMaxMs);
          continue;
        }
        consecutiveClaimErrors = 0;
        if (this.#stopRequested) break;
        const fresh = leased.filter(
          (attempt) => !processed.has(`${attempt.organizationId}/${attempt.attemptId}`),
        );
        if (fresh.length === 0) {
          // The sweep is complete: nothing new is outstanding.
          processed.clear();
          this.#logger.log({ status: 'claim_empty' });
          await this.#backoff(backoffMs);
          backoffMs = Math.min(backoffMs * 2, this.#idleMaxMs);
          continue;
        }
        for (const attempt of fresh) {
          processed.add(`${attempt.organizationId}/${attempt.attemptId}`);
        }
        this.#logger.log({ status: 'claimed', count: fresh.length });
        const recorded = await this.#processBatch(fresh);
        if (recorded === 0) {
          // Nothing advanced: every answer was unclear. Backing off here keeps
          // one held attempt to ONE claim per pass, so a hold cannot quietly
          // burn two of its bounded retries, and the loop cannot hot-cycle
          // over attempts it has just released.
          await this.#backoff(backoffMs);
          backoffMs = Math.min(backoffMs * 2, this.#idleMaxMs);
        } else {
          backoffMs = this.#pollMs;
        }
      }
    } finally {
      this.#logger.log({ status: 'stopped' });
      this.#resolveSettled?.();
    }
  }

  /** Returns how many attempts this batch actually advanced durably. */
  async #processBatch(leased: readonly LeasedPaymentAttempt[]): Promise<number> {
    const batchController = new AbortController();
    const timer = setTimeout(() => {
      batchController.abort(new SettlementShutdown());
    }, this.#batchDeadlineMs);
    let recorded = 0;
    try {
      for (const attempt of leased) {
        if (batchController.signal.aborted || this.#workController.signal.aborted) {
          this.#logger.log({ status: 'aborted', count: 1 });
          return recorded;
        }
        // Never act on a lease the database has already reclaimed.
        const leaseUntil = Date.parse(attempt.leaseUntil);
        if (Number.isFinite(leaseUntil) && this.#clock.now() >= leaseUntil) {
          this.#logger.log({ status: 'aborted', count: 1 });
          continue;
        }
        if (await this.#processAttempt(attempt, batchController.signal)) recorded += 1;
      }
    } finally {
      clearTimeout(timer);
    }
    return recorded;
  }

  /** Returns true only when a positive observation was durably recorded. */
  async #processAttempt(
    attempt: LeasedPaymentAttempt,
    batchSignal: AbortSignal,
  ): Promise<boolean> {
    const decision = await this.#classify(attempt, batchSignal);
    if (decision.kind === 'hold') {
      this.#logger.log({ status: 'held', reason: decision.reason, count: 1 });
      // An unclear answer writes NOTHING to the attempt. Releasing only ends
      // this lease early; the attempt keeps its exact state and stays held.
      await this.#releaseQuietly(attempt);
      return false;
    }
    if (this.#workController.signal.aborted) {
      this.#logger.log({ status: 'aborted', count: 1 });
      return false;
    }
    try {
      const recorded = await this.#store.recordObservation({
        organizationId: attempt.organizationId,
        attemptId: attempt.attemptId,
        leaseGeneration: attempt.leaseGeneration,
        state: decision.state,
        transferId: decision.transferId,
        gatewayStatus: decision.gatewayStatus,
        batchTxHash: decision.batchTxHash,
      });
      if (recorded === null) {
        this.#logger.log({ status: 'record_stale', count: 1 });
        return false;
      }
      this.#logger.log({
        status: recorded.state === 'committed' ? 'observed_committed' : 'observed_pending',
        count: 1,
      });
      return true;
    } catch {
      // A lost reply may mean the observation applied. Never retry it here:
      // the recorder is exactly-once per state edge and a re-observation of an
      // already advanced attempt is refused by the database anyway.
      this.#logger.log({ status: 'outcome_unknown', count: 1 });
      return false;
    }
  }

  async #classify(
    attempt: LeasedPaymentAttempt,
    batchSignal: AbortSignal,
  ): Promise<SettlementDecision> {
    const controller = new AbortController();
    const onAbort = (): void => controller.abort(new SettlementShutdown());
    this.#workController.signal.addEventListener('abort', onAbort, { once: true });
    batchSignal.addEventListener('abort', onAbort, { once: true });
    const timer = setTimeout(onAbort, this.#lookupTimeoutMs);
    try {
      return await classifyLeasedAttempt(attempt, this.#transport, {
        nowUnixSeconds: Math.floor(this.#clock.now() / 1000),
        signal: controller.signal,
      });
    } catch {
      return hold('transport_threw');
    } finally {
      clearTimeout(timer);
      this.#workController.signal.removeEventListener('abort', onAbort);
      batchSignal.removeEventListener('abort', onAbort);
    }
  }

  async #releaseQuietly(attempt: LeasedPaymentAttempt): Promise<void> {
    try {
      await this.#store.releaseLease(
        attempt.organizationId,
        attempt.attemptId,
        attempt.leaseGeneration,
      );
    } catch {
      // A failed release changes nothing: the lease simply expires on its own
      // and the attempt stays exactly as held as it already was.
      this.#logger.log({ status: 'record_error', count: 1 });
    }
  }

  async #backoff(milliseconds: number): Promise<void> {
    try {
      await this.#clock.sleep(milliseconds, this.#stopController.signal);
    } catch {
      // Stop was requested while backing off; the loop condition exits.
    }
  }
}
