import type { ClaimInput, ClaimedOutboxEvent, OutboxAckResult } from '@openarc/db';
import {
  InvalidEventError,
  ackIdentityOf,
  createHandlerRegistry,
  eventKeyOf,
  type NotificationHandler,
  type NotificationHandlerRegistry,
  validateNotification,
} from './handlers.js';

/**
 * Bounded worker loop over durable tenant mutation notifications.
 *
 * LIMITATION: success means allowlisted metadata was validated and the event
 * was consumed. It is not a payment, projection, provider call, notification,
 * reconciliation or broadcast. The loop claims a batch, dispatches every claimed
 * event concurrently (bounded by the claim limit, at most 50), and never claims
 * a next batch before all dispatched work has settled. A whole batch is bounded
 * by a batch deadline (at most 20s) and each handler by 5s, so a full 50-event
 * claim cannot run past the lease. When the deadline or a shutdown aborts the
 * batch, every in-flight handler is cancelled and no late acknowledgement is
 * attempted; any acknowledgement that already landed still only lands with the
 * database's fresh lease/generation fence.
 */

/** The narrow store surface this loop needs; OutboxStore satisfies it. */
export interface WorkerStore {
  claim(input?: ClaimInput): Promise<ClaimedOutboxEvent[]>;
  complete(eventId: unknown, leaseGeneration: unknown): Promise<OutboxAckResult>;
  fail(eventId: unknown, leaseGeneration: unknown, code: unknown): Promise<OutboxAckResult>;
}

export interface WorkerClock {
  now(): number;
  sleep(milliseconds: number, signal: AbortSignal): Promise<void>;
}

export const systemClock: WorkerClock = {
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

export type WorkerLogStatus =
  | 'ready'
  | 'claim_empty'
  | 'claim_error'
  | 'claimed'
  | 'completed'
  | 'failed'
  | 'stale'
  | 'outcome_unknown'
  | 'aborted'
  | 'stopping'
  | 'stopped';

/**
 * Bounded allowlisted log record. Only fixed status, a validated eventType and
 * an aggregate count are ever emitted; no event/organization/resource/mutation
 * identifier, database URL, error or body is ever logged.
 */
export interface WorkerLogRecord {
  readonly status: WorkerLogStatus;
  readonly eventType?: string;
  readonly count?: number;
}

export interface WorkerLogger {
  log(record: WorkerLogRecord): void;
}

export const noopLogger: WorkerLogger = { log: () => undefined };

export interface WorkerLoopOptions {
  readonly store: WorkerStore;
  readonly registry?: NotificationHandlerRegistry;
  readonly claimLimit: number;
  readonly pollMs: number;
  readonly idleMaxMs: number;
  /** Bounded handler deadline. Must be an integer in 1..5000. */
  readonly handlerTimeoutMs?: number;
  /**
   * Bound on CONSECUTIVE claim failures before the loop stops instead of
   * retrying forever. A claim failure is not always transient: a durable row
   * the store cannot project fails the whole batch every time, which would
   * otherwise spin at `idleMaxMs` indefinitely and silently stall the queue.
   * Stopping surfaces the condition to the supervisor. Integer in 1..1000;
   * defaults to 10. A single successful claim resets the counter.
   */
  readonly maxConsecutiveClaimErrors?: number;
  /** Bounded whole-batch deadline. Must be an integer in 1..20000. */
  readonly batchDeadlineMs?: number;
  readonly clock?: WorkerClock;
  readonly logger?: WorkerLogger;
}

type InvokeOutcome =
  | { readonly kind: 'ok' }
  | { readonly kind: 'invalid' }
  | { readonly kind: 'error' }
  | { readonly kind: 'timeout' }
  | { readonly kind: 'aborted' };

const DEFAULT_HANDLER_TIMEOUT_MS = 5000;
const MAX_HANDLER_TIMEOUT_MS = 5000;
const DEFAULT_BATCH_DEADLINE_MS = 20000;
const MAX_BATCH_DEADLINE_MS = 20000;

class ShutdownSentinel extends Error {
  constructor() {
    super('worker abort');
    this.name = 'ShutdownSentinel';
  }
}

function isPositiveInteger(value: unknown, max: number): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1 && value <= max;
}

export class WorkerLoop {
  readonly #store: WorkerStore;
  readonly #registry: NotificationHandlerRegistry;
  readonly #claimLimit: number;
  readonly #pollMs: number;
  readonly #idleMaxMs: number;
  readonly #handlerTimeoutMs: number;
  readonly #maxConsecutiveClaimErrors: number;
  readonly #batchDeadlineMs: number;
  readonly #clock: WorkerClock;
  readonly #logger: WorkerLogger;
  readonly #stopController = new AbortController();
  readonly #handlerController = new AbortController();
  readonly #settled: Promise<void>;
  #resolveSettled: (() => void) | undefined;
  #stopRequested = false;
  #started = false;

  constructor(options: WorkerLoopOptions) {
    const timeout = options.handlerTimeoutMs ?? DEFAULT_HANDLER_TIMEOUT_MS;
    if (!isPositiveInteger(timeout, MAX_HANDLER_TIMEOUT_MS)) {
      throw new InvalidEventError();
    }
    const batchDeadline = options.batchDeadlineMs ?? DEFAULT_BATCH_DEADLINE_MS;
    if (!isPositiveInteger(batchDeadline, MAX_BATCH_DEADLINE_MS)) {
      throw new InvalidEventError();
    }
    this.#store = options.store;
    this.#registry = options.registry ?? createHandlerRegistry();
    this.#claimLimit = options.claimLimit;
    this.#pollMs = options.pollMs;
    this.#idleMaxMs = options.idleMaxMs;
    const claimErrorBound = options.maxConsecutiveClaimErrors ?? 10;
    if (
      !Number.isInteger(claimErrorBound) ||
      claimErrorBound < 1 ||
      claimErrorBound > 1000
    ) {
      throw new Error('maxConsecutiveClaimErrors must be an integer in 1..1000');
    }
    this.#maxConsecutiveClaimErrors = claimErrorBound;
    this.#handlerTimeoutMs = timeout;
    this.#batchDeadlineMs = batchDeadline;
    this.#clock = options.clock ?? systemClock;
    this.#logger = options.logger ?? noopLogger;
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
    this.#stopController.abort(new ShutdownSentinel());
  }

  /** Abort inflight handlers. No late completion/failure will be attempted. */
  abort(): void {
    this.#handlerController.abort(new ShutdownSentinel());
  }

  async run(): Promise<void> {
    if (this.#started) throw new InvalidEventError();
    this.#started = true;
    let backoffMs = this.#pollMs;
    let consecutiveClaimErrors = 0;
    try {
      while (!this.#stopRequested) {
        let events: ClaimedOutboxEvent[];
        try {
          events = await this.#store.claim({ limit: this.#claimLimit });
        } catch {
          consecutiveClaimErrors += 1;
          this.#logger.log({ status: 'claim_error', count: 1 });
          if (consecutiveClaimErrors >= this.#maxConsecutiveClaimErrors) {
            // Bounded: a permanently unprojectable row would otherwise stall the
            // queue forever behind a silent retry. Stop and let the supervisor
            // restart, so the condition is visible instead of invisible.
            this.#logger.log({ status: 'stopping', count: consecutiveClaimErrors });
            break;
          }
          await this.#backoff(backoffMs);
          backoffMs = Math.min(backoffMs * 2, this.#idleMaxMs);
          continue;
        }
        consecutiveClaimErrors = 0;
        if (this.#stopRequested) break;
        if (events.length === 0) {
          this.#logger.log({ status: 'claim_empty' });
          await this.#backoff(backoffMs);
          backoffMs = Math.min(backoffMs * 2, this.#idleMaxMs);
          continue;
        }
        backoffMs = this.#pollMs;
        this.#logger.log({ status: 'claimed', count: events.length });
        await this.#processBatch(events);
      }
    } finally {
      this.#logger.log({ status: 'stopped' });
      this.#resolveSettled?.();
    }
  }

  async #processBatch(events: readonly ClaimedOutboxEvent[]): Promise<void> {
    const batchController = new AbortController();
    const timer = setTimeout(() => {
      batchController.abort(new ShutdownSentinel());
    }, this.#batchDeadlineMs);
    try {
      // Dispatch every claimed event concurrently, bounded by the claim limit.
      // No next claim happens until all of this batch's work has settled.
      const dispatched = events.map((event) =>
        this.#processEvent(event, batchController.signal),
      );
      await Promise.allSettled(dispatched);
    } finally {
      clearTimeout(timer);
    }
  }

  async #processEvent(raw: unknown, batchSignal: AbortSignal): Promise<void> {
    let event: ClaimedOutboxEvent;
    try {
      event = validateNotification(raw);
    } catch {
      await this.#failInvalid(raw, batchSignal);
      return;
    }
    const handler = this.#registry[eventKeyOf(event)];
    if (handler === undefined) {
      await this.#failInvalid(raw, batchSignal);
      return;
    }

    // Do not dispatch work whose lease is already gone; the database recovers it.
    const leaseUntil = Date.parse(event.leaseUntil);
    if (Number.isFinite(leaseUntil) && this.#clock.now() >= leaseUntil) return;

    const outcome = await this.#invoke(handler, event, batchSignal);
    if (outcome.kind === 'aborted') {
      this.#logger.log({ status: 'aborted', eventType: event.eventType, count: 1 });
      return;
    }
    if (this.#stopRequested || batchSignal.aborted) {
      this.#logger.log({ status: 'aborted', eventType: event.eventType, count: 1 });
      return;
    }
    if (outcome.kind === 'invalid') {
      await this.#ackFail(event, 'invalid_event');
      return;
    }
    if (outcome.kind === 'timeout') {
      await this.#ackFail(event, 'dependency_unavailable');
      return;
    }
    if (outcome.kind === 'error') {
      await this.#ackFail(event, 'handler_failed');
      return;
    }
    await this.#ackComplete(event);
  }

  async #invoke(
    handler: NotificationHandler,
    event: ClaimedOutboxEvent,
    batchSignal: AbortSignal,
  ): Promise<InvokeOutcome> {
    if (batchSignal.aborted) return { kind: 'aborted' };
    const controller = new AbortController();
    let timedOut = false;
    const onAbort = (): void => controller.abort(new ShutdownSentinel());
    const onShutdown = (): void => onAbort();
    const onBatch = (): void => onAbort();
    this.#handlerController.signal.addEventListener('abort', onShutdown, { once: true });
    batchSignal.addEventListener('abort', onBatch, { once: true });
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort(new ShutdownSentinel());
    }, this.#handlerTimeoutMs);
    const aborted = new Promise<void>((resolve, reject) => {
      controller.signal.addEventListener(
        'abort',
        () => {
          if (timedOut) resolve();
          else reject(new ShutdownSentinel());
        },
        { once: true },
      );
    });
    try {
      await Promise.race([Promise.resolve(handler(event, { signal: controller.signal })), aborted]);
      if (timedOut) return { kind: 'timeout' };
      if (this.#handlerController.signal.aborted || batchSignal.aborted) return { kind: 'aborted' };
      return { kind: 'ok' };
    } catch (error) {
      if (timedOut) return { kind: 'timeout' };
      if (this.#handlerController.signal.aborted || batchSignal.aborted) return { kind: 'aborted' };
      if (error instanceof InvalidEventError) return { kind: 'invalid' };
      return { kind: 'error' };
    } finally {
      clearTimeout(timer);
      this.#handlerController.signal.removeEventListener('abort', onShutdown);
      batchSignal.removeEventListener('abort', onBatch);
    }
  }

  async #ackComplete(event: ClaimedOutboxEvent): Promise<void> {
    try {
      const result = await this.#store.complete(event.eventId, event.leaseGeneration);
      this.#logger.log({
        status: result.applied ? 'completed' : 'stale',
        eventType: event.eventType,
        count: 1,
      });
    } catch {
      // A lost response may mean the mutation applied. Never retry or double-ack.
      this.#logger.log({ status: 'outcome_unknown', eventType: event.eventType, count: 1 });
    }
  }

  async #ackFail(event: ClaimedOutboxEvent, code: 'invalid_event' | 'handler_failed' | 'dependency_unavailable'): Promise<void> {
    try {
      const result = await this.#store.fail(event.eventId, event.leaseGeneration, code);
      this.#logger.log({
        status: result.applied ? 'failed' : 'stale',
        eventType: event.eventType,
        count: 1,
      });
    } catch {
      this.#logger.log({ status: 'outcome_unknown', eventType: event.eventType, count: 1 });
    }
  }

  async #failInvalid(raw: unknown, batchSignal?: AbortSignal): Promise<void> {
    if (this.#stopRequested || batchSignal?.aborted === true) return;
    const identity = ackIdentityOf(raw);
    if (identity === null) {
      this.#logger.log({ status: 'aborted', count: 1 });
      return;
    }
    try {
      const result = await this.#store.fail(identity.eventId, identity.leaseGeneration, 'invalid_event');
      this.#logger.log({ status: result.applied ? 'failed' : 'stale', count: 1 });
    } catch {
      this.#logger.log({ status: 'outcome_unknown', count: 1 });
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
