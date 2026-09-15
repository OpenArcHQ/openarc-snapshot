import { describe, expect, it } from 'vitest';
import type { ClaimedOutboxEvent } from '@openarc/db';
import { parseWorkerConfig, WorkerConfigError } from '../src/config.js';
import {
  INVALID_EVENT_MESSAGE,
  InvalidEventError,
  NOTIFICATION_EVENT_KEYS,
  ackIdentityOf,
  createHandlerRegistry,
  eventKeyOf,
  validateNotification,
  type NotificationHandler,
} from '../src/handlers.js';
import { startWorkerRuntime, type WorkerOutboxStore, type WorkerRuntimeOptions } from '../src/runtime.js';
import {
  WorkerLoop,
  type WorkerClock,
  type WorkerLogger,
  type WorkerLogRecord,
  type WorkerStore,
} from '../src/worker.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function baseEvent(overrides: Record<string, unknown> = {}): ClaimedOutboxEvent {
  return {
    eventId: '00000000-0000-4000-8000-000000000001',
    organizationId: 'openarc:org:00000000-0000-4000-8000-000000000002',
    mutationId: '00000000-0000-4000-8000-000000000003',
    resourceType: 'agent',
    resourceId: 'openarc:agent:00000000-0000-4000-8000-000000000004',
    eventType: 'tenant.agent.created',
    payloadVersion: 1,
    leaseGeneration: '1',
    leaseUntil: new Date(Date.now() + 30000).toISOString(),
    attemptCount: 0,
    ...overrides,
  } as unknown as ClaimedOutboxEvent;
}

interface EventCase {
  readonly resourceType: string;
  readonly eventType: string;
  readonly resourceId: string;
}

const SIX_CASES: readonly EventCase[] = [
  {
    resourceType: 'organization',
    eventType: 'tenant.organization.created',
    resourceId: 'openarc:org:00000000-0000-4000-8000-000000000010',
  },
  {
    resourceType: 'agent',
    eventType: 'tenant.agent.created',
    resourceId: 'openarc:agent:00000000-0000-4000-8000-000000000011',
  },
  {
    resourceType: 'agent',
    eventType: 'tenant.agent.updated',
    resourceId: 'openarc:agent:00000000-0000-4000-8000-000000000012',
  },
  {
    resourceType: 'provider',
    eventType: 'tenant.provider.created',
    resourceId: 'openarc:provider:00000000-0000-4000-8000-000000000013',
  },
  {
    resourceType: 'provider',
    eventType: 'tenant.provider.updated',
    resourceId: 'openarc:provider:00000000-0000-4000-8000-000000000014',
  },
  {
    resourceType: 'membership',
    eventType: 'tenant.membership.set',
    resourceId: 'openarc:account:00000000-0000-4000-8000-000000000015',
  },
  {
    resourceType: 'agent_credential',
    eventType: 'tenant.agent.credential.created',
    resourceId: '00000000-0000-4000-8000-000000000016',
  },
  {
    resourceType: 'agent_credential',
    eventType: 'tenant.agent.credential.revoked',
    resourceId: '00000000-0000-4000-8000-000000000017',
  },
  {
    resourceType: 'provider_credential',
    eventType: 'tenant.provider.credential.created',
    resourceId: '00000000-0000-4000-8000-000000000018',
  },
  {
    resourceType: 'provider_credential',
    eventType: 'tenant.provider.credential.revoked',
    resourceId: '00000000-0000-4000-8000-000000000019',
  },
  {
    resourceType: 'listing',
    eventType: 'market.listing.created',
    resourceId: 'openarc:listing:00000000-0000-4000-8000-000000000020',
  },
  {
    resourceType: 'listing_version',
    eventType: 'market.listing.version.created',
    resourceId: 'openarc:listing:00000000-0000-4000-8000-000000000021@2',
  },
  {
    resourceType: 'listing_version',
    eventType: 'market.listing.origin_review.recorded',
    resourceId: 'openarc:listing:00000000-0000-4000-8000-000000000022@1',
  },
  {
    resourceType: 'listing_version',
    eventType: 'market.listing.version.published',
    resourceId: 'openarc:listing:00000000-0000-4000-8000-000000000023@1',
  },
  {
    resourceType: 'listing_version',
    eventType: 'market.listing.version.paused',
    resourceId: 'openarc:listing:00000000-0000-4000-8000-000000000024@1',
  },
  {
    resourceType: 'listing_version',
    eventType: 'market.listing.version.retired',
    resourceId: 'openarc:listing:00000000-0000-4000-8000-000000000025@1',
  },
];

const POLICY_ID = 'openarc:policy:00000000-0000-4000-8000-000000000040';

const POLICY_CASES: readonly EventCase[] = [
  {
    resourceType: 'budget_policy',
    eventType: 'control.policy.created',
    resourceId: POLICY_ID,
  },
  {
    resourceType: 'budget_policy_revision',
    eventType: 'control.policy.revision.created',
    resourceId: `${POLICY_ID}@2`,
  },
  {
    resourceType: 'budget_policy',
    eventType: 'control.policy.paused',
    resourceId: 'openarc:policy:00000000-0000-4000-8000-000000000041',
  },
  {
    resourceType: 'budget_policy',
    eventType: 'control.policy.resumed',
    resourceId: 'openarc:policy:00000000-0000-4000-8000-000000000042',
  },
  {
    resourceType: 'budget_policy',
    eventType: 'control.policy.revoked',
    resourceId: 'openarc:policy:00000000-0000-4000-8000-000000000043',
  },
];

const COMMERCE_SESSION_CASES: readonly EventCase[] = [
  {
    resourceType: 'commerce_session',
    eventType: 'control.commerce_session.issued',
    resourceId: '00000000-0000-4000-8000-000000000050',
  },
  {
    resourceType: 'commerce_session',
    eventType: 'control.commerce_session.exchanged',
    resourceId: '00000000-0000-4000-8000-000000000051',
  },
  {
    resourceType: 'commerce_session',
    eventType: 'control.commerce_session.revoked',
    resourceId: '00000000-0000-4000-8000-000000000052',
  },
];

const COMMERCE_ACTION_CASES: readonly EventCase[] = [
  {
    resourceType: 'commerce_action',
    eventType: 'control.commerce_action.authorized',
    resourceId: 'openarc:action:00000000-0000-4000-8000-000000000060',
  },
  {
    resourceType: 'commerce_action',
    eventType: 'control.commerce_action.approved',
    resourceId: 'openarc:action:00000000-0000-4000-8000-000000000061',
  },
  {
    resourceType: 'commerce_action',
    eventType: 'control.commerce_action.rejected',
    resourceId: 'openarc:action:00000000-0000-4000-8000-000000000062',
  },
  {
    resourceType: 'commerce_action',
    eventType: 'control.commerce_action.cancelled',
    resourceId: 'openarc:action:00000000-0000-4000-8000-000000000063',
  },
];

const GRANT_CASES: readonly EventCase[] = [
  {
    resourceType: 'authorization_grant',
    eventType: 'control.grant.issued',
    resourceId: 'openarc:grant:00000000-0000-4000-8000-000000000070',
  },
  {
    resourceType: 'authorization_grant',
    eventType: 'control.grant.replaced',
    resourceId: 'openarc:grant:00000000-0000-4000-8000-000000000071',
  },
  {
    resourceType: 'authorization_grant',
    eventType: 'control.grant.revoked',
    resourceId: 'openarc:grant:00000000-0000-4000-8000-000000000072',
  },
  {
    resourceType: 'authorization_grant',
    eventType: 'control.grant.claimed',
    resourceId: 'openarc:grant:00000000-0000-4000-8000-000000000073',
  },
];

/**
 * The exact closed inventory: 21 legacy tuples, the 3 commerce-session tuples,
 * the 4 notification-only commerce-action tuples and the 4 notification-only
 * authorization-grant tuples.
 */
const EXPECTED_EVENT_KEYS: readonly string[] = [
  'organization|tenant.organization.created',
  'agent|tenant.agent.created',
  'agent|tenant.agent.updated',
  'provider|tenant.provider.created',
  'provider|tenant.provider.updated',
  'membership|tenant.membership.set',
  'agent_credential|tenant.agent.credential.created',
  'agent_credential|tenant.agent.credential.revoked',
  'provider_credential|tenant.provider.credential.created',
  'provider_credential|tenant.provider.credential.revoked',
  'listing|market.listing.created',
  'listing_version|market.listing.version.created',
  'listing_version|market.listing.origin_review.recorded',
  'listing_version|market.listing.version.published',
  'listing_version|market.listing.version.paused',
  'listing_version|market.listing.version.retired',
  'budget_policy|control.policy.created',
  'budget_policy_revision|control.policy.revision.created',
  'budget_policy|control.policy.paused',
  'budget_policy|control.policy.resumed',
  'budget_policy|control.policy.revoked',
  'commerce_session|control.commerce_session.issued',
  'commerce_session|control.commerce_session.exchanged',
  'commerce_session|control.commerce_session.revoked',
  'commerce_action|control.commerce_action.authorized',
  'commerce_action|control.commerce_action.approved',
  'commerce_action|control.commerce_action.rejected',
  'commerce_action|control.commerce_action.cancelled',
  'authorization_grant|control.grant.issued',
  'authorization_grant|control.grant.replaced',
  'authorization_grant|control.grant.revoked',
  'authorization_grant|control.grant.claimed',
];

function eventFor(item: EventCase): ClaimedOutboxEvent {
  return baseEvent({
    resourceType: item.resourceType,
    eventType: item.eventType,
    resourceId: item.resourceId,
  });
}

class FakeStore implements WorkerStore {
  readonly batches: ClaimedOutboxEvent[][];
  claimCalls = 0;
  readonly completions: Array<{ eventId: string; leaseGeneration: string }> = [];
  readonly failures: Array<{ eventId: string; leaseGeneration: string; code: unknown }> = [];
  completeResult = true;
  failResult = true;
  claimError: Error | undefined;
  completeError: Error | undefined;
  failError: Error | undefined;

  constructor(batches: ClaimedOutboxEvent[][]) {
    this.batches = batches;
  }

  async claim(): Promise<ClaimedOutboxEvent[]> {
    this.claimCalls += 1;
    if (this.claimError !== undefined) throw this.claimError;
    return this.batches.shift() ?? [];
  }

  async complete(eventId: unknown, leaseGeneration: unknown): Promise<{ applied: boolean }> {
    this.completions.push({
      eventId: String(eventId),
      leaseGeneration: String(leaseGeneration),
    });
    if (this.completeError !== undefined) throw this.completeError;
    return { applied: this.completeResult };
  }

  async fail(
    eventId: unknown,
    leaseGeneration: unknown,
    code: unknown,
  ): Promise<{ applied: boolean }> {
    this.failures.push({
      eventId: String(eventId),
      leaseGeneration: String(leaseGeneration),
      code,
    });
    if (this.failError !== undefined) throw this.failError;
    return { applied: this.failResult };
  }
}

class FakeClock implements WorkerClock {
  current = 0;
  readonly sleeps: number[] = [];

  now(): number {
    return this.current;
  }

  async sleep(milliseconds: number, signal: AbortSignal): Promise<void> {
    this.sleeps.push(milliseconds);
    if (signal.aborted) throw new Error('aborted');
  }
}

interface Recorder {
  readonly records: WorkerLogRecord[];
  readonly logger: WorkerLogger;
}

function recorder(stopStatus: WorkerLogRecord['status'] | undefined, onStop: () => void): Recorder {
  const records: WorkerLogRecord[] = [];
  const logger: WorkerLogger = {
    log: (record) => {
      records.push(record);
      if (stopStatus !== undefined && record.status === stopStatus) onStop();
    },
  };
  return { records, logger };
}

interface Deferred<T> {
  readonly promise: Promise<T>;
  resolve(value: T): void;
}

function deferred<T>(): Deferred<T> {
  let resolve: (value: T) => void = () => undefined;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

async function waitUntil(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 400; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setImmediate(resolve));
  }
  throw new Error('condition not observed');
}

function enabledConfig() {
  const config = parseWorkerConfig({
    WORKER_ENABLED: 'true',
    WORKER_DATABASE_URL: 'postgres://openarc_worker_app:pw@127.0.0.1:5432/openarc_auth_test',
  });
  if (!config.enabled) throw new Error('expected enabled');
  return config;
}

describe('worker configuration', () => {
  it('is disabled by default and opens no database', async () => {
    expect(parseWorkerConfig({})).toEqual({ enabled: false });
    expect(parseWorkerConfig({ WORKER_ENABLED: 'false' })).toEqual({ enabled: false });
    let created = 0;
    const runtime = startWorkerRuntime({
      config: { enabled: false },
      createPool: () => {
        created += 1;
        throw new Error('must not create a pool');
      },
      installSignalHandlers: false,
    });
    expect(runtime.state).toBe('disabled');
    await runtime.stopped;
    expect(created).toBe(0);
  });

  it('parses the documented enabled settings and ignores unrelated variables', () => {
    const parsed = parseWorkerConfig({
      WORKER_ENABLED: 'true',
      WORKER_DATABASE_URL: 'postgres://openarc_worker_app:pw@127.0.0.1:5432/openarc_auth_test',
      WORKER_CLAIM_LIMIT: '7',
      WORKER_POLL_MS: '500',
      WORKER_IDLE_MAX_MS: '9000',
      WORKER_SHUTDOWN_GRACE_MS: '1000',
      PATH: '/unrelated',
      DATABASE_URL: 'postgres://admin@example.test/db',
    });
    expect(parsed).toEqual({
      enabled: true,
      databaseUrl: 'postgres://openarc_worker_app:pw@127.0.0.1:5432/openarc_auth_test',
      claimLimit: 7,
      pollMs: 500,
      idleMaxMs: 9000,
      shutdownGraceMs: 1000,
    });
  });

  it('rejects strict invalid values', () => {
    const url = 'postgres://openarc_worker_app:pw@127.0.0.1:5432/openarc_auth_test';
    const bad: Array<Record<string, string | undefined>> = [
      { WORKER_ENABLED: 'TRUE', WORKER_DATABASE_URL: url },
      { WORKER_ENABLED: 'true' },
      { WORKER_ENABLED: 'true', WORKER_DATABASE_URL: 'mysql://x' },
      { WORKER_ENABLED: 'true', WORKER_DATABASE_URL: '   ' },
      { WORKER_ENABLED: 'true', WORKER_DATABASE_URL: `postgres://${'a'.repeat(5000)}` },
      { WORKER_ENABLED: 'true', WORKER_DATABASE_URL: url, WORKER_CLAIM_LIMIT: '0' },
      { WORKER_ENABLED: 'true', WORKER_DATABASE_URL: url, WORKER_CLAIM_LIMIT: '51' },
      { WORKER_ENABLED: 'true', WORKER_DATABASE_URL: url, WORKER_POLL_MS: '249' },
      { WORKER_ENABLED: 'true', WORKER_DATABASE_URL: url, WORKER_POLL_MS: '10001' },
      { WORKER_ENABLED: 'true', WORKER_DATABASE_URL: url, WORKER_IDLE_MAX_MS: '999' },
      { WORKER_ENABLED: 'true', WORKER_DATABASE_URL: url, WORKER_IDLE_MAX_MS: '30001' },
      { WORKER_ENABLED: 'true', WORKER_DATABASE_URL: url, WORKER_SHUTDOWN_GRACE_MS: '99' },
      { WORKER_ENABLED: 'true', WORKER_DATABASE_URL: url, WORKER_SHUTDOWN_GRACE_MS: '15001' },
      { WORKER_ENABLED: 'true', WORKER_DATABASE_URL: url, WORKER_POLL_MS: '1000', WORKER_IDLE_MAX_MS: '500' },
      { WORKER_ENABLED: 'true', WORKER_DATABASE_URL: url, WORKER_CLAIM_LIMIT: '1e2' },
    ];
    for (const env of bad) {
      expect(() => parseWorkerConfig(env)).toThrow(WorkerConfigError);
    }
  });
});

describe('notification handler registry', () => {
  it('keeps the exact closed event inventory: 21 legacy tuples plus the 3 commerce-session, 4 commerce-action and 4 grant tuples', () => {
    expect([...NOTIFICATION_EVENT_KEYS]).toEqual(EXPECTED_EVENT_KEYS);
    const registry = createHandlerRegistry();
    expect(Object.keys(registry).sort()).toEqual([...EXPECTED_EVENT_KEYS].sort());
  });

  it('dispatches exactly the allowlisted events, including the five control policy tuples', async () => {
    const registry = createHandlerRegistry();
    expect(Object.keys(registry).sort()).toEqual([...NOTIFICATION_EVENT_KEYS].sort());
    for (const item of [
      ...SIX_CASES,
      ...POLICY_CASES,
      ...COMMERCE_SESSION_CASES,
      ...COMMERCE_ACTION_CASES,
      ...GRANT_CASES,
    ]) {
      const event = eventFor(item);
      const key = eventKeyOf(event);
      const handler = registry[key];
      expect(handler).toBeDefined();
      await handler?.(event, { signal: new AbortController().signal });
    }
  });

  it('accepts each of the three commerce-session tuples with a canonical UUIDv4 resource', async () => {
    const registry = createHandlerRegistry();
    for (const item of COMMERCE_SESSION_CASES) {
      const event = eventFor(item);
      const key = `${item.resourceType}|${item.eventType}`;
      expect(eventKeyOf(event)).toBe(key);
      expect(validateNotification(event)).toEqual(event);
      const handler = registry[key];
      expect(handler).toBeDefined();
      await handler?.(event, { signal: new AbortController().signal });
    }
  });

  it('rejects mismatched commerce-session resource/event tuples', () => {
    const mismatches = [
      // Correct tuple but a non-UUIDv4 resource (version nibble 1).
      baseEvent({
        resourceType: 'commerce_session',
        eventType: 'control.commerce_session.issued',
        resourceId: '00000000-0000-1000-8000-000000000050',
      }),
      // Wrong variant nibble.
      baseEvent({
        resourceType: 'commerce_session',
        eventType: 'control.commerce_session.exchanged',
        resourceId: '00000000-0000-4000-7000-000000000051',
      }),
      // Wrong resource type for a commerce-session event type.
      baseEvent({
        resourceType: 'budget_policy',
        eventType: 'control.commerce_session.issued',
        resourceId: '00000000-0000-4000-8000-000000000050',
      }),
      // Wrong event type for the commerce_session resource type.
      baseEvent({
        resourceType: 'commerce_session',
        eventType: 'control.policy.created',
        resourceId: '00000000-0000-4000-8000-000000000050',
      }),
    ];
    for (const event of mismatches) {
      expect(() => validateNotification(event)).toThrow(InvalidEventError);
    }
  });

  it('rejects malformed commerce-session resources including newlines without coercion', () => {
    const malformed = [
      '00000000-0000-4000-8000-00000000005', // short
      '00000000-0000-4000-8000-0000000000500', // long
      '00000000-0000-4000-8000-000000000050\n', // trailing newline
      '00000000-0000-4000-8000-000000000050 ', // trailing space
      ' 00000000-0000-4000-8000-000000000050', // leading space
      '00000000-0000-4000-8000-00000000005Z', // uppercase/non-hex
      'OPENARC00000-0000-4000-8000-000000000050', // non-hex prefix
      'openarc:session:00000000-0000-4000-8000-000000000050', // prefixed resource
      '00000000-0000-4000-8000-000000000050@2', // version suffix
      '00000000-0000-4000-8000-000000000050\n\n', // two newlines
    ];
    for (const resourceId of malformed) {
      expect(() =>
        validateNotification(
          baseEvent({
            resourceType: 'commerce_session',
            eventType: 'control.commerce_session.issued',
            resourceId,
          }),
        ),
      ).toThrow(InvalidEventError);
    }
    // Valid every event tuple still passes with each exact resource.
    for (const item of COMMERCE_SESSION_CASES) {
      expect(() => validateNotification(eventFor(item))).not.toThrow();
    }
  });

  it('rejects a private field on a commerce-session event without echoing it', () => {
    const CANARY = 'CANARY-private-commerce-key-9b42';
    const withCanary = baseEvent({
      resourceType: 'commerce_session',
      eventType: 'control.commerce_session.issued',
      resourceId: '00000000-0000-4000-8000-000000000050',
      privateCanary: CANARY,
    });
    let message = '';
    try {
      validateNotification(withCanary);
    } catch (error) {
      expect(error).toBeInstanceOf(InvalidEventError);
      message = error instanceof Error ? error.message : String(error);
    }
    expect(message).toBe(INVALID_EVENT_MESSAGE);
    expect(message).not.toContain(CANARY);
    expect(JSON.stringify(withCanary)).toContain(CANARY);
  });

  it('consumes a commerce-session event with an already-aborted signal without side effects', async () => {
    const controller = new AbortController();
    controller.abort();
    const event = eventFor(COMMERCE_SESSION_CASES[0]!);
    const handler = createHandlerRegistry()[eventKeyOf(event)];
    expect(handler).toBeDefined();
    expect(await handler?.(event, { signal: controller.signal })).toBeUndefined();
  });

  it('accepts each of the four commerce-action tuples with an exact canonical action id', async () => {
    const registry = createHandlerRegistry();
    for (const item of COMMERCE_ACTION_CASES) {
      const event = eventFor(item);
      const key = `${item.resourceType}|${item.eventType}`;
      expect(eventKeyOf(event)).toBe(key);
      expect(validateNotification(event)).toEqual(event);
      const handler = registry[key];
      expect(handler).toBeDefined();
      await handler?.(event, { signal: new AbortController().signal });
    }
  });

  it('keeps every commerce-action tuple in the registry with the exact key', () => {
    const registry = createHandlerRegistry();
    for (const item of COMMERCE_ACTION_CASES) {
      const key = `${item.resourceType}|${item.eventType}`;
      expect(NOTIFICATION_EVENT_KEYS).toContain(key);
      expect(EXPECTED_EVENT_KEYS).toContain(key);
      expect(registry[key as keyof typeof registry]).toBeTypeOf('function');
    }
  });

  it('accepts each of the four grant tuples and rejects a malformed grant id', async () => {
    const registry = createHandlerRegistry();
    for (const item of GRANT_CASES) {
      const event = eventFor(item);
      const key = `${item.resourceType}|${item.eventType}`;
      expect(eventKeyOf(event)).toBe(key);
      expect(validateNotification(event)).toEqual(event);
      const handler = registry[key as keyof typeof registry];
      expect(handler).toBeTypeOf('function');
      await handler(event, { signal: new AbortController().signal });
    }
    const malformed = [
      'openarc:grant:00000000-0000-4000-8000-000000000070\n',
      'openarc:grant:00000000-0000-1000-8000-000000000070',
      'openarc:grant:00000000-0000-4000-7000-000000000070',
      'OPENARC:GRANT:00000000-0000-4000-8000-000000000070',
      'openarc:action:00000000-0000-4000-8000-000000000070',
      '00000000-0000-4000-8000-000000000070',
    ];
    for (const resourceId of malformed) {
      expect(() =>
        validateNotification(
          baseEvent({ resourceType: 'authorization_grant', eventType: 'control.grant.issued', resourceId }),
        ),
      ).toThrow(InvalidEventError);
    }
    expect(() =>
      validateNotification(
        baseEvent({
          resourceType: 'commerce_action',
          eventType: 'control.grant.claimed',
          resourceId: 'openarc:grant:00000000-0000-4000-8000-000000000073',
        }),
      ),
    ).toThrow(InvalidEventError);
  });

  it('rejects mismatched commerce-action resource/event pairs', () => {
    const mismatches = [
      // Correct action namespace but a non-UUIDv4 resource (version nibble 1).
      baseEvent({
        resourceType: 'commerce_action',
        eventType: 'control.commerce_action.authorized',
        resourceId: 'openarc:action:00000000-0000-1000-8000-000000000060',
      }),
      // Wrong variant nibble.
      baseEvent({
        resourceType: 'commerce_action',
        eventType: 'control.commerce_action.approved',
        resourceId: 'openarc:action:00000000-0000-4000-7000-000000000061',
      }),
      // Wrong resource type for a commerce-action event type.
      baseEvent({
        resourceType: 'commerce_session',
        eventType: 'control.commerce_action.authorized',
        resourceId: 'openarc:action:00000000-0000-4000-8000-000000000060',
      }),
      // Wrong event type for the commerce_action resource type.
      baseEvent({
        resourceType: 'commerce_action',
        eventType: 'control.commerce_session.issued',
        resourceId: 'openarc:action:00000000-0000-4000-8000-000000000060',
      }),
      // Wrong namespace for an otherwise canonical UUIDv4.
      baseEvent({
        resourceType: 'commerce_action',
        eventType: 'control.commerce_action.rejected',
        resourceId: 'openarc:session:00000000-0000-4000-8000-000000000062',
      }),
    ];
    for (const event of mismatches) {
      expect(() => validateNotification(event)).toThrow(InvalidEventError);
    }
  });

  it('rejects malformed commerce-action resources including case, version and trailing newlines', () => {
    const malformed = [
      'openarc:action:00000000-0000-4000-8000-00000000006', // short uuid
      'openarc:action:00000000-0000-4000-8000-0000000000600', // long uuid
      'openarc:action:00000000-0000-0000-8000-000000000060', // version nibble 0
      'openarc:action:00000000-0000-4000-7000-000000000060', // variant 7
      'openarc:action:00000000-0000-4000-8000-00000000006Z', // uppercase/non-hex
      'OPENARC:ACTION:00000000-0000-4000-8000-000000000060', // wrong case prefix
      'Openarc:action:00000000-0000-4000-8000-000000000060', // mixed case prefix
      'openarc:action:00000000-0000-4000-8000-000000000060\n', // trailing LF
      'openarc:action:00000000-0000-4000-8000-000000000060\r', // trailing CR
      'openarc:action:00000000-0000-4000-8000-000000000060 ', // trailing space
      '  openarc:action:00000000-0000-4000-8000-000000000060', // leading space
      'openarc:action:00000000-0000-4000-8000-000000000060@2', // version suffix
      'openarc:action:00000000-0000-4000-8000-000000000060\n\n', // two newlines
      '00000000-0000-4000-8000-000000000060', // bare uuid, no namespace
      'openarc:action:', // namespace only
    ];
    for (const resourceId of malformed) {
      expect(() =>
        validateNotification(
          baseEvent({
            resourceType: 'commerce_action',
            eventType: 'control.commerce_action.authorized',
            resourceId,
          }),
        ),
      ).toThrow(InvalidEventError);
    }
    // Every valid tuple still passes with each exact resource.
    for (const item of COMMERCE_ACTION_CASES) {
      expect(() => validateNotification(eventFor(item))).not.toThrow();
    }
  });

  it('rejects a private field on a commerce-action event without echoing it', () => {
    const CANARY = 'CANARY-private-action-key-4d17';
    const withCanary = baseEvent({
      resourceType: 'commerce_action',
      eventType: 'control.commerce_action.authorized',
      resourceId: 'openarc:action:00000000-0000-4000-8000-000000000060',
      privateCanary: CANARY,
    });
    let message = '';
    try {
      validateNotification(withCanary);
    } catch (error) {
      expect(error).toBeInstanceOf(InvalidEventError);
      message = error instanceof Error ? error.message : String(error);
    }
    expect(message).toBe(INVALID_EVENT_MESSAGE);
    expect(message).not.toContain(CANARY);
    expect(JSON.stringify(withCanary)).toContain(CANARY);
  });

  it('consumes a commerce-action event with an already-aborted signal without side effects', async () => {
    const controller = new AbortController();
    controller.abort();
    const event = eventFor(COMMERCE_ACTION_CASES[0]!);
    const handler = createHandlerRegistry()[eventKeyOf(event)];
    expect(handler).toBeDefined();
    expect(await handler?.(event, { signal: controller.signal })).toBeUndefined();
  });

  it('accepts each of the five control policy tuples with its exact resource grammar', async () => {
    const registry = createHandlerRegistry();
    for (const item of POLICY_CASES) {
      const event = eventFor(item);
      const key = `${item.resourceType}|${item.eventType}`;
      expect(eventKeyOf(event)).toBe(key);
      expect(validateNotification(event)).toEqual(event);
      const handler = registry[key];
      expect(handler).toBeDefined();
      await handler?.(event, { signal: new AbortController().signal });
    }
  });

  it('rejects mismatched control policy resource/event tuples', () => {
    const mismatches = [
      baseEvent({
        resourceType: 'budget_policy',
        eventType: 'control.policy.revision.created',
        resourceId: POLICY_ID,
      }),
      baseEvent({
        resourceType: 'budget_policy_revision',
        eventType: 'control.policy.created',
        resourceId: `${POLICY_ID}@2`,
      }),
      baseEvent({
        resourceType: 'budget_policy',
        eventType: 'control.policy.paused',
        resourceId: `${POLICY_ID}@2`,
      }),
    ];
    for (const event of mismatches) {
      expect(() => validateNotification(event)).toThrow(InvalidEventError);
    }
  });

  it('rejects malformed policy ids and revisions without coercion', () => {
    const malformedIds = [
      'openarc:policy:00000000-0000-4000-8000-00000000004', // short
      'openarc:policy:00000000-0000-0000-8000-000000000040', // version nibble 0
      'openarc:policy:00000000-0000-4000-7000-000000000040', // variant 7
      'openarc:policy:00000000-0000-4000-8000-00000000004Z', // uppercase/non-hex
      'openarc:policy:00000000-0000-4000-8000-000000000040\n', // trailing newline
      `${POLICY_ID}@2`, // revision resource on a root event
      `${POLICY_ID} `, // trailing space
    ];
    for (const resourceId of malformedIds) {
      expect(() =>
        validateNotification(
          baseEvent({
            resourceType: 'budget_policy',
            eventType: 'control.policy.created',
            resourceId,
          }),
        ),
      ).toThrow(InvalidEventError);
    }

    const revisionEvent = (revision: string): ClaimedOutboxEvent =>
      baseEvent({
        resourceType: 'budget_policy_revision',
        eventType: 'control.policy.revision.created',
        resourceId: `${POLICY_ID}@${revision}`,
      });
    for (const good of ['2', '9', '10', '100', '999999999']) {
      expect(() => validateNotification(revisionEvent(good))).not.toThrow();
    }
    for (const bad of [
      '0',
      '1',
      '01',
      '1000000000', // overflow: 10 digits
      '1.0',
      '+2',
      '1e2',
      '2\n',
      '2 ',
      '2@3',
      '',
    ]) {
      expect(() => validateNotification(revisionEvent(bad))).toThrow(InvalidEventError);
    }
  });

  it('rejects unknown metadata keys without echoing a private canary', () => {
    const CANARY = 'CANARY-private-policy-key-7f31';
    const withCanary = baseEvent({
      resourceType: 'budget_policy',
      eventType: 'control.policy.created',
      resourceId: POLICY_ID,
      privateCanary: CANARY,
    });
    let message = '';
    try {
      validateNotification(withCanary);
    } catch (error) {
      expect(error).toBeInstanceOf(InvalidEventError);
      message = error instanceof Error ? error.message : String(error);
    }
    expect(message).toBe(INVALID_EVENT_MESSAGE);
    expect(message).not.toContain(CANARY);
    expect(JSON.stringify(withCanary)).toContain(CANARY);
  });

  it('consumes a policy event with an already-aborted signal without side effects', async () => {
    const controller = new AbortController();
    controller.abort();
    const event = eventFor(POLICY_CASES[0]!);
    const handler = createHandlerRegistry()[eventKeyOf(event)];
    expect(handler).toBeDefined();
    expect(await handler?.(event, { signal: controller.signal })).toBeUndefined();
  });

  it('rejects unknown and mismatched events without a truthy success', async () => {
    const registry = createHandlerRegistry();
    const unknown = baseEvent({ eventType: 'tenant.agent.deleted' });
    expect(() => eventKeyOf(unknown)).toThrow(InvalidEventError);

    const mismatched = baseEvent({ resourceType: 'agent', eventType: 'tenant.provider.created' });
    expect(() => validateNotification(mismatched)).toThrow(InvalidEventError);

    const wrongResource = baseEvent({ resourceId: 'openarc:org:00000000-0000-4000-8000-000000000099' });
    expect(() => validateNotification(wrongResource)).toThrow(InvalidEventError);

    expect(() => validateNotification(null)).toThrow(InvalidEventError);
    expect(ackIdentityOf(null)).toBeNull();
    expect(ackIdentityOf({ eventId: 'nope', leaseGeneration: '1' })).toBeNull();
    expect(await Promise.resolve(registry['agent|tenant.agent.created'])).toBeTypeOf('function');
  });

  it('accepts version 1 only for lifecycle events and denies created@1', () => {
    const listingId = 'openarc:listing:00000000-0000-4000-8000-000000000030';
    for (const eventType of [
      'market.listing.origin_review.recorded',
      'market.listing.version.published',
      'market.listing.version.paused',
      'market.listing.version.retired',
    ]) {
      const event = baseEvent({
        resourceType: 'listing_version',
        eventType,
        resourceId: `${listingId}@1`,
      });
      expect(() => validateNotification(event)).not.toThrow();
    }
    // The legacy create event still requires version >= 2.
    const created = baseEvent({
      resourceType: 'listing_version',
      eventType: 'market.listing.version.created',
      resourceId: `${listingId}@1`,
    });
    expect(() => validateNotification(created)).toThrow(InvalidEventError);
  });

  it('derives an ack identity only for well-formed ids', () => {
    const event = baseEvent();
    expect(ackIdentityOf(event)).toEqual({ eventId: event.eventId, leaseGeneration: '1' });
    const longGeneration = baseEvent({ leaseGeneration: '1'.repeat(30) });
    expect(ackIdentityOf(longGeneration)).toBeNull();
  });

  it('rejects malformed listing and version-resource grammars', () => {
    const badListingIds = [
      'openarc:listing:00000000-0000-0000-8000-000000000020', // version nibble 0
      'openarc:listing:00000000-0000-4000-7000-000000000020', // variant 7
      'openarc:listing:00000000-0000-4000-8000-00000000002', // short
    ];
    for (const resourceId of badListingIds) {
      expect(() =>
        validateNotification(
          baseEvent({ resourceType: 'listing', eventType: 'market.listing.created', resourceId }),
        ),
      ).toThrow(InvalidEventError);
    }
    const goodListing = 'openarc:listing:00000000-0000-4000-8000-000000000020';
    const badVersionResources = [
      `${goodListing}@1`, // version 1 is the draft root, never a version resource
      `${goodListing}@0`,
      `${goodListing}@01`,
      'openarc:listing:00000000-0000-0000-8000-000000000020@2',
      'openarc:listing:00000000-0000-4000-8000-000000000020@' + '2'.repeat(20),
      `${goodListing}@2@3`,
      `${'a'.repeat(130)}@2`,
    ];
    for (const resourceId of badVersionResources) {
      expect(() =>
        validateNotification(
          baseEvent({
            resourceType: 'listing_version',
            eventType: 'market.listing.version.created',
            resourceId,
          }),
        ),
      ).toThrow(InvalidEventError);
    }
    const goodVersion = `${goodListing}@2`;
    expect(
      validateNotification(
        baseEvent({
          resourceType: 'listing_version',
          eventType: 'market.listing.version.created',
          resourceId: goodVersion,
        }),
      ),
    ).toBeTruthy();
  });
});

describe('bounded worker loop', () => {
  it('claims one batch, settles it, then idles and never leaves work queued', async () => {
    const store = new FakeStore([[eventFor(SIX_CASES[1]!), eventFor(SIX_CASES[3]!)]]);
    const clock = new FakeClock();
    const state: { loop?: WorkerLoop } = {};
    const { records, logger } = recorder('claim_empty', () => state.loop?.requestStop());
    const loop = new WorkerLoop({ store, claimLimit: 10, pollMs: 250, idleMaxMs: 5000, clock, logger });
    state.loop = loop;
    await loop.run();

    expect(store.claimCalls).toBe(2);
    expect(store.completions).toHaveLength(2);
    expect(store.failures).toHaveLength(0);
    expect(clock.sleeps.length).toBeGreaterThanOrEqual(1);
    expect(records.some((record) => record.status === 'completed')).toBe(true);
  });

  it('backs off on empty claims and never tight-loops', async () => {
    const store = new FakeStore([]);
    const clock = new FakeClock();
    const state: { loop?: WorkerLoop } = {};
    const { logger } = recorder('claim_empty', () => state.loop?.requestStop());
    const loop = new WorkerLoop({ store, claimLimit: 5, pollMs: 250, idleMaxMs: 1000, clock, logger });
    state.loop = loop;
    await loop.run();
    expect(store.claimCalls).toBe(1);
    expect(clock.sleeps).toEqual([250]);
  });

  it('backs off on claim errors and never tight-loops', async () => {
    const store = new FakeStore([]);
    store.claimError = new Error('claim down');
    const clock = new FakeClock();
    const state: { loop?: WorkerLoop } = {};
    const { logger } = recorder('claim_error', () => state.loop?.requestStop());
    const loop = new WorkerLoop({ store, claimLimit: 5, pollMs: 250, idleMaxMs: 1000, clock, logger });
    state.loop = loop;
    await loop.run();
    expect(store.claimCalls).toBe(1);
    expect(clock.sleeps).toEqual([250]);
    expect(store.completions).toHaveLength(0);
  });

  it('does not acknowledge before the handler succeeds', async () => {
    const gate = deferred<void>();
    const event = eventFor(SIX_CASES[1]!);
    const store = new FakeStore([[event]]);
    const registry = createHandlerRegistry({
      'agent|tenant.agent.created': async () => {
        await gate.promise;
      },
    });
    const state: { loop?: WorkerLoop } = {};
    const { logger } = recorder('claim_empty', () => state.loop?.requestStop());
    const loop = new WorkerLoop({ store, registry, claimLimit: 5, pollMs: 250, idleMaxMs: 1000, clock: new FakeClock(), logger });
    state.loop = loop;
    const running = loop.run();
    await waitUntil(() => store.claimCalls === 1);
    expect(store.completions).toHaveLength(0);
    gate.resolve();
    await running;
    expect(store.completions).toHaveLength(1);
  });

  it('fails handler_failed exactly once when a handler throws', async () => {
    const event = eventFor(SIX_CASES[1]!);
    const store = new FakeStore([[event]]);
    const registry = createHandlerRegistry({
      'agent|tenant.agent.created': () => {
        throw new Error('boom');
      },
    });
    const state: { loop?: WorkerLoop } = {};
    const { logger } = recorder('failed', () => state.loop?.requestStop());
    const loop = new WorkerLoop({ store, registry, claimLimit: 5, pollMs: 250, idleMaxMs: 1000, clock: new FakeClock(), logger });
    state.loop = loop;
    await loop.run();
    expect(store.completions).toHaveLength(0);
    expect(store.failures).toHaveLength(1);
    expect(store.failures[0]?.code).toBe('handler_failed');
  });

  it('maps a bounded handler timeout to dependency_unavailable', async () => {
    const event = eventFor(SIX_CASES[1]!);
    const store = new FakeStore([[event]]);
    const registry = createHandlerRegistry({
      'agent|tenant.agent.created': () => new Promise<void>(() => undefined),
    });
    const state: { loop?: WorkerLoop } = {};
    const { logger } = recorder('failed', () => state.loop?.requestStop());
    const loop = new WorkerLoop({ store, registry, claimLimit: 5, pollMs: 250, idleMaxMs: 1000, handlerTimeoutMs: 20, clock: new FakeClock(), logger });
    state.loop = loop;
    await loop.run();
    expect(store.failures).toHaveLength(1);
    expect(store.failures[0]?.code).toBe('dependency_unavailable');
  });

  it('never fails again when a completion response is lost', async () => {
    const event = eventFor(SIX_CASES[1]!);
    const store = new FakeStore([[event]]);
    store.completeError = new Error('lost');
    const state: { loop?: WorkerLoop } = {};
    const { records, logger } = recorder('claim_empty', () => state.loop?.requestStop());
    const loop = new WorkerLoop({ store, claimLimit: 5, pollMs: 250, idleMaxMs: 1000, clock: new FakeClock(), logger });
    state.loop = loop;
    await loop.run();
    expect(store.completions).toHaveLength(1);
    expect(store.failures).toHaveLength(0);
    expect(records.some((record) => record.status === 'outcome_unknown')).toBe(true);
  });

  it('treats a stale completion as stale and does not retry', async () => {
    const event = eventFor(SIX_CASES[1]!);
    const store = new FakeStore([[event]]);
    store.completeResult = false;
    const state: { loop?: WorkerLoop } = {};
    const { records, logger } = recorder('claim_empty', () => state.loop?.requestStop());
    const loop = new WorkerLoop({ store, claimLimit: 5, pollMs: 250, idleMaxMs: 1000, clock: new FakeClock(), logger });
    state.loop = loop;
    await loop.run();
    expect(store.completions).toHaveLength(1);
    expect(store.failures).toHaveLength(0);
    expect(records.some((record) => record.status === 'stale')).toBe(true);
  });

  it('suppresses acknowledgement after a graceful stop and a late handler result', async () => {
    const gate = deferred<void>();
    const event = eventFor(SIX_CASES[1]!);
    const store = new FakeStore([[event]]);
    let started = false;
    const registry = createHandlerRegistry({
      'agent|tenant.agent.created': async () => {
        started = true;
        await gate.promise;
      },
    });
    const state: { loop?: WorkerLoop } = {};
    const { records, logger } = recorder(undefined, () => undefined);
    const loop = new WorkerLoop({ store, registry, claimLimit: 5, pollMs: 250, idleMaxMs: 1000, clock: new FakeClock(), logger });
    state.loop = loop;
    const running = loop.run();
    await waitUntil(() => started);
    loop.requestStop();
    gate.resolve();
    await running;
    expect(store.completions).toHaveLength(0);
    expect(store.failures).toHaveLength(0);
    expect(records.some((record) => record.status === 'aborted')).toBe(true);
  });

  it('suppresses acknowledgement after an abort', async () => {
    const event = eventFor(SIX_CASES[1]!);
    const store = new FakeStore([[event]]);
    let started = false;
    const registry = createHandlerRegistry({
      'agent|tenant.agent.created': async () => {
        started = true;
        await new Promise<void>(() => undefined);
      },
    });
    const state: { loop?: WorkerLoop } = {};
    const { records, logger } = recorder(undefined, () => undefined);
    const loop = new WorkerLoop({ store, registry, claimLimit: 5, pollMs: 250, idleMaxMs: 1000, clock: new FakeClock(), logger });
    state.loop = loop;
    const running = loop.run();
    await waitUntil(() => started);
    loop.requestStop();
    loop.abort();
    await running;
    expect(store.completions).toHaveLength(0);
    expect(store.failures).toHaveLength(0);
    expect(records.some((record) => record.status === 'aborted')).toBe(true);
  });

  it('dead-letters a well-formed unknown event once and fails closed otherwise', async () => {
    const unknown = baseEvent({ eventType: 'tenant.unknown.event' });
    const store = new FakeStore([[unknown]]);
    const state: { loop?: WorkerLoop } = {};
    const { logger } = recorder('failed', () => state.loop?.requestStop());
    const loop = new WorkerLoop({ store, claimLimit: 5, pollMs: 250, idleMaxMs: 1000, clock: new FakeClock(), logger });
    state.loop = loop;
    await loop.run();
    expect(store.completions).toHaveLength(0);
    expect(store.failures).toHaveLength(1);
    expect(store.failures[0]?.code).toBe('invalid_event');

    const notAckable = baseEvent({ eventId: 'not-an-id', eventType: 'tenant.unknown.event' });
    const store2 = new FakeStore([[notAckable]]);
    const state2: { loop?: WorkerLoop } = {};
    const { logger: logger2 } = recorder('aborted', () => state2.loop?.requestStop());
    const loop2 = new WorkerLoop({ store: store2, claimLimit: 5, pollMs: 250, idleMaxMs: 1000, clock: new FakeClock(), logger: logger2 });
    state2.loop = loop2;
    await loop2.run();
    expect(store2.failures).toHaveLength(0);
    expect(store2.completions).toHaveLength(0);
  });

  it('is harmless on duplicate delivery', async () => {
    const event = eventFor(SIX_CASES[1]!);
    const store = new FakeStore([[event], [event]]);
    const state: { loop?: WorkerLoop } = {};
    const { logger } = recorder('claim_empty', () => state.loop?.requestStop());
    const loop = new WorkerLoop({ store, claimLimit: 5, pollMs: 250, idleMaxMs: 1000, clock: new FakeClock(), logger });
    state.loop = loop;
    await loop.run();
    expect(store.completions).toHaveLength(2);
    expect(store.failures).toHaveLength(0);
  });

  it('does not dispatch an event whose lease already expired', async () => {
    const event = baseEvent({ leaseUntil: new Date(Date.now() - 1000).toISOString() });
    const store = new FakeStore([[event]]);
    const state: { loop?: WorkerLoop } = {};
    const { logger } = recorder('claim_empty', () => state.loop?.requestStop());
    const clock = new FakeClock();
    clock.current = Date.now();
    const loop = new WorkerLoop({ store, claimLimit: 5, pollMs: 250, idleMaxMs: 1000, clock, logger });
    state.loop = loop;
    await loop.run();
    expect(store.completions).toHaveLength(0);
    expect(store.failures).toHaveLength(0);
  });

  it('emits only fixed allowlisted log fields and never leaks identifiers', async () => {
    const CANARY = 'CANARY-secret-identifier';
    const event = baseEvent({ eventId: '00000000-0000-4000-8000-0000000000aa' });
    const store = new FakeStore([[event]]);
    store.completeError = new Error(CANARY);
    const state: { loop?: WorkerLoop } = {};
    const { records, logger } = recorder('claim_empty', () => state.loop?.requestStop());
    const loop = new WorkerLoop({
      store,
      registry: createHandlerRegistry({
        'agent|tenant.agent.created': Object.assign(
          (() => undefined) as NotificationHandler,
          { canary: CANARY },
        ),
      }),
      claimLimit: 5,
      pollMs: 250,
      idleMaxMs: 1000,
      clock: new FakeClock(),
      logger,
    });
    state.loop = loop;
    await loop.run();
    const serialized = JSON.stringify(records);
    expect(serialized).not.toContain(CANARY);
    for (const record of records) {
      for (const key of Object.keys(record)) {
        expect(['status', 'eventType', 'count']).toContain(key);
      }
    }
    expect(records.every((record) => UUID.test(record.eventType ?? '') === false)).toBe(true);
  });

  it('dispatches the whole delayed batch concurrently and suppresses late acknowledgements', async () => {
    const events = [
      baseEvent({ eventId: '00000000-0000-4000-8000-0000000000c1', resourceId: 'openarc:agent:00000000-0000-4000-8000-000000000021' }),
      baseEvent({ eventId: '00000000-0000-4000-8000-0000000000c2', resourceId: 'openarc:agent:00000000-0000-4000-8000-000000000022' }),
      baseEvent({ eventId: '00000000-0000-4000-8000-0000000000c3', resourceId: 'openarc:agent:00000000-0000-4000-8000-000000000023' }),
      baseEvent({ eventId: '00000000-0000-4000-8000-0000000000c4', resourceId: 'openarc:agent:00000000-0000-4000-8000-000000000024' }),
    ];
    const store = new FakeStore([events]);
    let starts = 0;
    const gate = deferred<void>();
    const registry = createHandlerRegistry({
      'agent|tenant.agent.created': async () => {
        starts += 1;
        await gate.promise;
      },
    });
    const state: { loop?: WorkerLoop } = {};
    const { records, logger } = recorder('aborted', () => state.loop?.requestStop());
    const loop = new WorkerLoop({
      store,
      registry,
      claimLimit: 50,
      pollMs: 250,
      idleMaxMs: 1000,
      handlerTimeoutMs: 5000,
      batchDeadlineMs: 20,
      clock: new FakeClock(),
      logger,
    });
    state.loop = loop;
    await loop.run();
    // Every claimed event was dispatched concurrently; the batch deadline
    // cancelled them all and no late acknowledgement was attempted.
    expect(store.claimCalls).toBe(1);
    expect(starts).toBe(4);
    expect(store.completions).toHaveLength(0);
    expect(store.failures).toHaveLength(0);
    expect(records.some((record) => record.status === 'aborted')).toBe(true);
  });

  it('never claims a next batch while a delayed batch is still active', async () => {
    const first = baseEvent({ resourceId: 'openarc:agent:00000000-0000-4000-8000-000000000031' });
    const second = baseEvent({ resourceId: 'openarc:agent:00000000-0000-4000-8000-000000000032' });
    const later = baseEvent({ resourceId: 'openarc:agent:00000000-0000-4000-8000-000000000033' });
    const store = new FakeStore([[first, second], [later]]);
    const gate = deferred<void>();
    let starts = 0;
    const registry = createHandlerRegistry({
      'agent|tenant.agent.created': async () => {
        starts += 1;
        await gate.promise;
      },
    });
    const { logger } = recorder(undefined, () => undefined);
    const loop = new WorkerLoop({
      store,
      registry,
      claimLimit: 5,
      pollMs: 250,
      idleMaxMs: 1000,
      handlerTimeoutMs: 5000,
      batchDeadlineMs: 20000,
      clock: new FakeClock(),
      logger,
    });
    const running = loop.run();
    await waitUntil(() => starts === 2);
    for (let tick = 0; tick < 20; tick += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    expect(store.claimCalls).toBe(1);
    expect(store.completions).toHaveLength(0);
    loop.requestStop();
    gate.resolve();
    await running;
    expect(store.claimCalls).toBe(1);
    expect(store.completions).toHaveLength(0);
  });

  it('starts all 50 claimed delayed handlers concurrently and acks each exactly once', async () => {
    const events = Array.from({ length: 50 }, (_unused, index) =>
      baseEvent({
        eventId: `00000000-0000-4000-8000-${String(index + 1).padStart(12, '0')}`,
        resourceId: `openarc:agent:00000000-0000-4000-8000-${String(index + 1001).padStart(12, '0')}`,
      }),
    );
    const store = new FakeStore([events]);
    let starts = 0;
    let active = 0;
    let maxActive = 0;
    const gate = deferred<void>();
    const registry = createHandlerRegistry({
      'agent|tenant.agent.created': async () => {
        starts += 1;
        active += 1;
        maxActive = Math.max(maxActive, active);
        await gate.promise;
        active -= 1;
      },
    });
    const state: { loop?: WorkerLoop } = {};
    const { logger } = recorder('claim_empty', () => state.loop?.requestStop());
    const loop = new WorkerLoop({
      store,
      registry,
      claimLimit: 50,
      pollMs: 250,
      idleMaxMs: 1000,
      handlerTimeoutMs: 5000,
      batchDeadlineMs: 20000,
      clock: new FakeClock(),
      logger,
    });
    state.loop = loop;
    const running = loop.run();
    await waitUntil(() => starts === 50);
    expect(store.completions).toHaveLength(0);
    gate.resolve();
    await running;
    expect(maxActive).toBe(50);
    expect(store.completions).toHaveLength(50);
    expect(store.failures).toHaveLength(0);
    expect(new Set(store.completions.map((completion) => completion.eventId)).size).toBe(50);
  });

  it('does not starve any position across repeated delivery cycles', async () => {
    const makeBatch = (cycle: number): ClaimedOutboxEvent[] =>
      Array.from({ length: 50 }, (_unused, index) =>
        baseEvent({
          eventId: `00000000-0000-4000-8000-${String(cycle * 100 + index + 1).padStart(12, '0')}`,
          resourceId: `openarc:agent:00000000-0000-4000-8000-${String(cycle * 100 + index + 2001).padStart(12, '0')}`,
        }),
      );
    const store = new FakeStore([makeBatch(0), makeBatch(1), makeBatch(2)]);
    let starts = 0;
    const registry = createHandlerRegistry({
      'agent|tenant.agent.created': async () => {
        starts += 1;
        await new Promise<void>((resolve) => setTimeout(resolve, 1));
      },
    });
    const state: { loop?: WorkerLoop } = {};
    const { logger } = recorder('claim_empty', () => state.loop?.requestStop());
    const loop = new WorkerLoop({
      store,
      registry,
      claimLimit: 50,
      pollMs: 250,
      idleMaxMs: 1000,
      handlerTimeoutMs: 5000,
      batchDeadlineMs: 20000,
      clock: new FakeClock(),
      logger,
    });
    state.loop = loop;
    await loop.run();
    expect(starts).toBe(150);
    expect(store.completions).toHaveLength(150);
    expect(store.failures).toHaveLength(0);
    expect(store.claimCalls).toBe(4);
  });
});

describe('runtime lifecycle', () => {
  it('closes the pool exactly once when initialization fails', async () => {
    let ended = 0;
    const pool = {
      end: async () => {
        ended += 1;
      },
    };
    const store: WorkerOutboxStore = {
      initialize: async () => {
        throw new Error('init failed');
      },
      claim: async () => [],
      complete: async () => ({ applied: true }),
      fail: async () => ({ applied: true }),
    };
    const runtime = startWorkerRuntime({
      config: enabledConfig(),
      createPool: (() => pool) as unknown as NonNullable<WorkerRuntimeOptions['createPool']>,
      createStore: () => store,
      installSignalHandlers: false,
      clock: new FakeClock(),
    });
    await expect(runtime.ready).rejects.toBeInstanceOf(Error);
    expect(runtime.state).toBe('failed');
    await runtime.stopped;
    expect(ended).toBe(1);
  });

  it('shuts down once and closes the pool once', async () => {
    let ended = 0;
    const pool = {
      end: async () => {
        ended += 1;
      },
    };
    const store: WorkerOutboxStore = {
      initialize: async () => undefined,
      claim: async () => [],
      complete: async () => ({ applied: true }),
      fail: async () => ({ applied: true }),
    };
    const runtime = startWorkerRuntime({
      config: enabledConfig(),
      createPool: (() => pool) as unknown as NonNullable<WorkerRuntimeOptions['createPool']>,
      createStore: () => store,
      installSignalHandlers: false,
      clock: new FakeClock(),
    });
    await runtime.ready;
    expect(runtime.state).toBe('ready');
    await Promise.all([runtime.shutdown(), runtime.shutdown()]);
    await runtime.stopped;
    expect(runtime.state).toBe('stopped');
    expect(ended).toBe(1);
  });

  it('does not resurrect readiness or claim when shutdown races initialize', async () => {
    let ended = 0;
    const pool = {
      end: async () => {
        ended += 1;
      },
    };
    const init = deferred<void>();
    let claimCalls = 0;
    const store: WorkerOutboxStore = {
      initialize: () => init.promise,
      claim: async () => {
        claimCalls += 1;
        return [];
      },
      complete: async () => ({ applied: true }),
      fail: async () => ({ applied: true }),
    };
    const runtime = startWorkerRuntime({
      config: enabledConfig(),
      createPool: (() => pool) as unknown as NonNullable<WorkerRuntimeOptions['createPool']>,
      createStore: () => store,
      installSignalHandlers: false,
      clock: new FakeClock(),
      poolCloseTimeoutMs: 50,
    });
    let readySettled = false;
    void runtime.ready.then(
      () => {
        readySettled = true;
      },
      () => {
        readySettled = true;
      },
    );
    const shutdown = runtime.shutdown();
    expect(runtime.state).toBe('stopping');
    init.resolve();
    await shutdown;
    await runtime.stopped;
    expect(runtime.state).toBe('stopped');
    expect(readySettled).toBe(false);
    expect(claimCalls).toBe(0);
    expect(ended).toBe(1);
  });

  it('settles a shutdown whose initialize never resolves', async () => {
    let ended = 0;
    const pool = {
      end: async () => {
        ended += 1;
      },
    };
    const store: WorkerOutboxStore = {
      initialize: () => new Promise<void>(() => undefined),
      claim: async () => [],
      complete: async () => ({ applied: true }),
      fail: async () => ({ applied: true }),
    };
    const runtime = startWorkerRuntime({
      config: enabledConfig(),
      createPool: (() => pool) as unknown as NonNullable<WorkerRuntimeOptions['createPool']>,
      createStore: () => store,
      installSignalHandlers: false,
      clock: new FakeClock(),
      poolCloseTimeoutMs: 50,
    });
    await runtime.shutdown();
    await runtime.stopped;
    expect(runtime.state).toBe('stopped');
    expect(ended).toBe(1);
  });
});

/**
 * Regression for an unbounded retry: a claim failure is not always transient.
 * A durable row the store cannot project fails the whole batch every time, so
 * the loop previously spun at `idleMaxMs` forever and stalled the queue
 * silently. The bound makes the condition visible to the supervisor.
 */
describe('bounded consecutive claim errors', () => {
  it('stops after the configured number of consecutive claim failures', async () => {
    let claims = 0;
    const store = {
      claim: async () => {
        claims += 1;
        throw new Error('unprojectable row');
      },
      complete: async () => ({ applied: true }),
      fail: async () => ({ applied: true }),
    };
    const records: { status: string; count?: number }[] = [];
    const loop = new WorkerLoop({
      store: store as never,
      claimLimit: 10,
      pollMs: 1,
      idleMaxMs: 2,
      maxConsecutiveClaimErrors: 3,
      logger: { log: (record) => records.push(record as never) },
    } as never);
    await loop.run();
    expect(claims).toBe(3);
    expect(records.filter((r) => r.status === 'claim_error')).toHaveLength(3);
    expect(records.some((r) => r.status === 'stopping' && r.count === 3)).toBe(true);
  });

  it('resets the counter after a successful claim', async () => {
    let calls = 0;
    const store = {
      claim: async () => {
        calls += 1;
        // fail, fail, succeed-empty, then fail three times to trip the bound
        if (calls === 3) return [];
        throw new Error('unprojectable row');
      },
      complete: async () => ({ applied: true }),
      fail: async () => ({ applied: true }),
    };
    const records: { status: string; count?: number }[] = [];
    const loop = new WorkerLoop({
      store: store as never,
      claimLimit: 10,
      pollMs: 1,
      idleMaxMs: 2,
      maxConsecutiveClaimErrors: 3,
      logger: { log: (record) => records.push(record as never) },
    } as never);
    await loop.run();
    // Without the reset the bound would trip at call 3; with it, the loop needs
    // three FURTHER consecutive failures, so it stops at call 6.
    expect(calls).toBe(6);
    expect(records.filter((r) => r.status === 'claim_error')).toHaveLength(5);
    expect(records.some((r) => r.status === 'claim_empty')).toBe(true);
  });

  it('rejects an out-of-range bound instead of accepting it', () => {
    for (const bound of [0, -1, 1001, 1.5, Number.NaN]) {
      expect(
        () =>
          new WorkerLoop({
            store: {} as never,
            claimLimit: 10,
            pollMs: 1,
            idleMaxMs: 2,
            maxConsecutiveClaimErrors: bound,
          } as never),
      ).toThrow(/maxConsecutiveClaimErrors/u);
    }
  });
});
