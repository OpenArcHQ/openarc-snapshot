/**
 * Bounded startup configuration for the tenant notification worker.
 *
 * LIMITATION: this worker consumes durable TENANT MUTATION NOTIFICATIONS only.
 * Accepted notification success means allowlisted metadata was validated and
 * the worker consumed the event. It is NOT a payment, provider call,
 * notification send, business projection, reconciliation or broadcast, and no
 * commerce side effect is claimed. A future projection phase owns side effects.
 *
 * Only the documented keys below are read; unrelated OS environment variables
 * are ignored. The database URL is never logged.
 */

export const WORKER_CONFIG_ERROR_MESSAGE = 'Worker configuration is invalid.';

/** Fixed, non-echoing configuration error. Never carries the bad value. */
export class WorkerConfigError extends Error {
  constructor() {
    super(WORKER_CONFIG_ERROR_MESSAGE);
    this.name = 'WorkerConfigError';
  }
}

export interface DisabledWorkerConfig {
  readonly enabled: false;
}

export interface EnabledWorkerConfig {
  readonly enabled: true;
  /** Dedicated worker connection URL. Never logged. */
  readonly databaseUrl: string;
  readonly claimLimit: number;
  readonly pollMs: number;
  readonly idleMaxMs: number;
  readonly shutdownGraceMs: number;
}

export type WorkerConfig = DisabledWorkerConfig | EnabledWorkerConfig;

export type WorkerEnvironment = Readonly<Record<string, string | undefined>>;

const CLAIM_LIMIT_DEFAULT = 10;
const CLAIM_LIMIT_MIN = 1;
const CLAIM_LIMIT_MAX = 50;
const POLL_MS_DEFAULT = 1000;
const POLL_MS_MIN = 250;
const POLL_MS_MAX = 10000;
const IDLE_MAX_MS_DEFAULT = 5000;
const IDLE_MAX_MS_MIN = 1000;
const IDLE_MAX_MS_MAX = 30000;
const SHUTDOWN_GRACE_MS_DEFAULT = 10000;
const SHUTDOWN_GRACE_MS_MIN = 100;
const SHUTDOWN_GRACE_MS_MAX = 15000;
const DATABASE_URL_MAX = 4096;

const INTEGER = /^(0|[1-9][0-9]*)$/;

function parseInteger(
  raw: string | undefined,
  fallback: number,
  min: number,
  max: number,
): number {
  if (raw === undefined) return fallback;
  if (raw.length === 0 || !INTEGER.test(raw)) throw new WorkerConfigError();
  const value = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new WorkerConfigError();
  }
  return value;
}

function parseEnabled(raw: string | undefined): boolean {
  if (raw === undefined || raw === 'false') return false;
  if (raw === 'true') return true;
  throw new WorkerConfigError();
}

function requireDatabaseUrl(raw: string | undefined): string {
  if (
    raw === undefined ||
    raw.length === 0 ||
    raw.length > DATABASE_URL_MAX ||
    (!raw.startsWith('postgres://') && !raw.startsWith('postgresql://'))
  ) {
    throw new WorkerConfigError();
  }
  return raw;
}

/**
 * Parse exactly the documented worker settings. Disabled is the default and a
 * disabled process requires no database URL and opens no connection.
 */
export function parseWorkerConfig(env: WorkerEnvironment): WorkerConfig {
  const enabled = parseEnabled(env['WORKER_ENABLED']);
  if (!enabled) return { enabled: false };

  const databaseUrl = requireDatabaseUrl(env['WORKER_DATABASE_URL']);
  const claimLimit = parseInteger(
    env['WORKER_CLAIM_LIMIT'],
    CLAIM_LIMIT_DEFAULT,
    CLAIM_LIMIT_MIN,
    CLAIM_LIMIT_MAX,
  );
  const pollMs = parseInteger(env['WORKER_POLL_MS'], POLL_MS_DEFAULT, POLL_MS_MIN, POLL_MS_MAX);
  const idleMaxMs = parseInteger(
    env['WORKER_IDLE_MAX_MS'],
    IDLE_MAX_MS_DEFAULT,
    IDLE_MAX_MS_MIN,
    IDLE_MAX_MS_MAX,
  );
  const shutdownGraceMs = parseInteger(
    env['WORKER_SHUTDOWN_GRACE_MS'],
    SHUTDOWN_GRACE_MS_DEFAULT,
    SHUTDOWN_GRACE_MS_MIN,
    SHUTDOWN_GRACE_MS_MAX,
  );
  if (idleMaxMs < pollMs) throw new WorkerConfigError();

  return { enabled: true, databaseUrl, claimLimit, pollMs, idleMaxMs, shutdownGraceMs };
}

/**
 * Settlement observation family (migration 0017).
 *
 * LIMITATION: this family OBSERVES durable payment attempts through an
 * injected lookup transport and records only a positive observation. It never
 * signs, sends, settles or moves funds.
 *
 * Like every other protected commerce family, it ships DEFAULT OFF and is an
 * INDEPENDENT flag: enabling it requires the worker itself to be enabled and
 * the dedicated worker database URL. A disabled family parses no transport
 * URL, opens no connection and starts no loop.
 */

export const SETTLEMENT_LIVE_MODE_MESSAGE =
  'Live settlement observation is not available in this build. ' +
  'Live Gateway lookups are P04-07 (live testnet acceptance) work and require, ' +
  'at minimum: a reviewed live transport against the pinned facilitator origin, ' +
  'a user-funded disposable testnet wallet, the unverified live behaviours in the ' +
  'P04-01 lane contract confirmed against the real endpoint, and an explicit ' +
  'operator decision to expose real funds. Until then the lookup transport must ' +
  'address a loopback fixture.';

/**
 * Refusing live-mode stub. Live mode is deliberately out of scope for this
 * packet: there is no code path here that can reach a real Circle, Gateway or
 * Arc endpoint.
 */
export class SettlementLiveModeUnsupportedError extends Error {
  constructor() {
    super(SETTLEMENT_LIVE_MODE_MESSAGE);
    this.name = 'SettlementLiveModeUnsupportedError';
  }
}

export interface DisabledSettlementConfig {
  readonly enabled: false;
}

export interface EnabledSettlementConfig {
  readonly enabled: true;
  /** Dedicated worker connection URL. Never logged. */
  readonly databaseUrl: string;
  /** Loopback-only lookup transport base URL. Never logged. */
  readonly lookupUrl: string;
  readonly claimLimit: number;
  readonly pollMs: number;
  readonly idleMaxMs: number;
  readonly lookupTimeoutMs: number;
}

export type SettlementConfig = DisabledSettlementConfig | EnabledSettlementConfig;

const SETTLEMENT_CLAIM_LIMIT_DEFAULT = 5;
const SETTLEMENT_CLAIM_LIMIT_MIN = 1;
const SETTLEMENT_CLAIM_LIMIT_MAX = 25;
const SETTLEMENT_POLL_MS_DEFAULT = 1000;
const SETTLEMENT_POLL_MS_MIN = 250;
const SETTLEMENT_POLL_MS_MAX = 10000;
const SETTLEMENT_IDLE_MAX_MS_DEFAULT = 5000;
const SETTLEMENT_IDLE_MAX_MS_MIN = 1000;
const SETTLEMENT_IDLE_MAX_MS_MAX = 30000;
const SETTLEMENT_LOOKUP_TIMEOUT_MS_DEFAULT = 10000;
const SETTLEMENT_LOOKUP_TIMEOUT_MS_MIN = 1;
const SETTLEMENT_LOOKUP_TIMEOUT_MS_MAX = 30000;
const LOOKUP_URL_MAX = 2048;

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]', '::1']);

/**
 * Exactly a loopback origin. A public host, a credentialed URL, a non-HTTP
 * scheme or any hostname that is not literally loopback is refused: without an
 * explicit live mode this process may not address a real endpoint, and live
 * mode itself is refused by `requireSettlementLookupUrl` below.
 */
export function isLoopbackLookupUrl(raw: string): boolean {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return false;
  if (url.username.length > 0 || url.password.length > 0) return false;
  if (url.hash.length > 0) return false;
  return LOOPBACK_HOSTS.has(url.hostname);
}

/**
 * Resolve the lookup transport URL. There is NO default: a missing URL is a
 * configuration error, never a silent fallback to some real endpoint. A
 * non-loopback URL is refused unless live mode is explicitly requested, and
 * live mode is itself refused as unimplemented (P04-07).
 */
export function requireSettlementLookupUrl(raw: string | undefined, live: boolean): string {
  if (live) throw new SettlementLiveModeUnsupportedError();
  if (raw === undefined || raw.length === 0 || raw.length > LOOKUP_URL_MAX) {
    throw new WorkerConfigError();
  }
  if (!isLoopbackLookupUrl(raw)) throw new WorkerConfigError();
  return raw;
}

/**
 * Parse exactly the documented settlement observation settings. Disabled is
 * the default; a disabled family requires no database URL and no transport.
 */
export function parseSettlementConfig(env: WorkerEnvironment): SettlementConfig {
  const enabled = parseEnabled(env['WORKER_SETTLEMENT_OBSERVATION_ENABLED']);
  if (!enabled) return { enabled: false };

  // An independent family still cannot run without the worker process itself.
  if (!parseEnabled(env['WORKER_ENABLED'])) throw new WorkerConfigError();
  const databaseUrl = requireDatabaseUrl(env['WORKER_DATABASE_URL']);
  const live = parseEnabled(env['WORKER_SETTLEMENT_LIVE_MODE']);
  const lookupUrl = requireSettlementLookupUrl(env['WORKER_SETTLEMENT_LOOKUP_URL'], live);
  const claimLimit = parseInteger(
    env['WORKER_SETTLEMENT_CLAIM_LIMIT'],
    SETTLEMENT_CLAIM_LIMIT_DEFAULT,
    SETTLEMENT_CLAIM_LIMIT_MIN,
    SETTLEMENT_CLAIM_LIMIT_MAX,
  );
  const pollMs = parseInteger(
    env['WORKER_SETTLEMENT_POLL_MS'],
    SETTLEMENT_POLL_MS_DEFAULT,
    SETTLEMENT_POLL_MS_MIN,
    SETTLEMENT_POLL_MS_MAX,
  );
  const idleMaxMs = parseInteger(
    env['WORKER_SETTLEMENT_IDLE_MAX_MS'],
    SETTLEMENT_IDLE_MAX_MS_DEFAULT,
    SETTLEMENT_IDLE_MAX_MS_MIN,
    SETTLEMENT_IDLE_MAX_MS_MAX,
  );
  const lookupTimeoutMs = parseInteger(
    env['WORKER_SETTLEMENT_LOOKUP_TIMEOUT_MS'],
    SETTLEMENT_LOOKUP_TIMEOUT_MS_DEFAULT,
    SETTLEMENT_LOOKUP_TIMEOUT_MS_MIN,
    SETTLEMENT_LOOKUP_TIMEOUT_MS_MAX,
  );
  if (idleMaxMs < pollMs) throw new WorkerConfigError();

  return { enabled: true, databaseUrl, lookupUrl, claimLimit, pollMs, idleMaxMs, lookupTimeoutMs };
}
