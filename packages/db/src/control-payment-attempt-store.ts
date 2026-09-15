import { createHash } from 'node:crypto';
import type { Pool } from 'pg';
import { loadMigrations } from './migrate.js';
import type { TenantClient, TenantPool } from './tenant-store.js';
import { ControlGrantStore } from './control-grant-store.js';
import { requireIdempotencyKey } from './market-mutations.js';

/**
 * ControlPaymentAttemptStore: the schema15 durable buyer payment-attempt
 * repository over the accepted restricted tenant pool.
 *
 * It is the durable half of the accepted packages/x402 two-phase flow
 * (prepare -> persist -> dispatch). The lane hands this store its
 * `LanePersistRecord` ({ binding, bindingDigest }); the store persists it
 * BEFORE any signature may leave the process and echoes the digest read back
 * from the database, exactly as `LanePersist` requires.
 *
 * Guarantees, all enforced in SQL and re-asserted here:
 *   * no raw signature, raw authorization payload or key material is ever
 *     accepted, stored or returned: the binding carries none, the input shape
 *     is closed and the table has no column that could hold one;
 *   * network, asset, verifying contract, value, role, action and grant
 *     requirement digest are DB-derived and the binding digest is recomputed by
 *     the database, so a caller cannot bind different payment terms;
 *   * a dispatch is recorded exactly once (persisted -> unknown); a second
 *     dispatch is refused and never reported as success, so an unknown attempt
 *     is never retried;
 *   * the persisted states mirror LaneExposure and admit no release.
 *
 * Every method runs one statement inside one transaction and makes no external
 * call. A lost COMMIT reply is OUTCOME_UNKNOWN: the caller must not send.
 */

export const CONTROL_PAYMENT_ATTEMPT_STORE_ERROR_MESSAGES = {
  CONTROL_PAYMENT_ATTEMPT_STORE_INPUT_INVALID: 'ControlPaymentAttemptStore input is invalid.',
  CONTROL_PAYMENT_ATTEMPT_STORE_SESSION_INVALID: 'ControlPaymentAttemptStore session is not valid.',
  CONTROL_PAYMENT_ATTEMPT_STORE_FORBIDDEN: 'ControlPaymentAttemptStore caller is not permitted.',
  CONTROL_PAYMENT_ATTEMPT_STORE_NOT_FOUND: 'ControlPaymentAttemptStore target was not found.',
  CONTROL_PAYMENT_ATTEMPT_STORE_CONFLICT:
    'ControlPaymentAttemptStore operation conflicts with existing state.',
  CONTROL_PAYMENT_ATTEMPT_STORE_ATTEMPT_CONFLICT:
    'ControlPaymentAttemptStore attempt is not in a state that permits this operation.',
  CONTROL_PAYMENT_ATTEMPT_STORE_GRANT_EXPIRED: 'ControlPaymentAttemptStore grant authority has expired.',
  CONTROL_PAYMENT_ATTEMPT_STORE_POTENTIAL_EXPOSURE:
    'ControlPaymentAttemptStore target has potential exposure that must stay held.',
  CONTROL_PAYMENT_ATTEMPT_STORE_REQUIREMENT_UNAVAILABLE:
    'ControlPaymentAttemptStore requirement is unavailable in production.',
  CONTROL_PAYMENT_ATTEMPT_STORE_IDEMPOTENCY_CONFLICT:
    'ControlPaymentAttemptStore mutation conflicts with an existing idempotency record.',
  CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE: 'ControlPaymentAttemptStore is not available.',
  CONTROL_PAYMENT_ATTEMPT_STORE_OUTCOME_UNKNOWN:
    'ControlPaymentAttemptStore mutation outcome could not be confirmed; it may have committed.',
} as const;

export type ControlPaymentAttemptStoreErrorCode = keyof typeof CONTROL_PAYMENT_ATTEMPT_STORE_ERROR_MESSAGES;

/** Fixed, non-echoing repository error. Never carries driver or input detail. */
export class ControlPaymentAttemptStoreError extends Error {
  readonly code: ControlPaymentAttemptStoreErrorCode;

  constructor(code: ControlPaymentAttemptStoreErrorCode) {
    super(CONTROL_PAYMENT_ATTEMPT_STORE_ERROR_MESSAGES[code]);
    this.name = 'ControlPaymentAttemptStoreError';
    this.code = code;
  }
}

/** Exactly the packages/x402 lane binding schema version this store persists. */
export const PAYMENT_ATTEMPT_BINDING_SCHEMA_VERSION = 'openarc.x402.lane-binding.v1' as const;
export const PAYMENT_ATTEMPT_NETWORK = 'eip155:5042002' as const;
/** EIP-55 checksummed forms exactly as the lane's `getAddress` emits them. */
export const PAYMENT_ATTEMPT_ASSET_ADDRESS = '0x3600000000000000000000000000000000000000' as const;
export const PAYMENT_ATTEMPT_VERIFYING_CONTRACT = '0x0077777d7EBA4688BDeF3E311b846F25870A19B9' as const;

/**
 * Durable attempt states. They mirror the accepted LaneExposure exactly:
 * `persisted` before dispatch, then only `unknown`, `pending` and `committed`.
 */
export const PAYMENT_ATTEMPT_STATES = ['persisted', 'unknown', 'pending', 'committed'] as const;
export type PaymentAttemptState = (typeof PAYMENT_ATTEMPT_STATES)[number];

/** States that would release held exposure. None may ever be a PaymentAttemptState. */
export type PaymentAttemptForbiddenReleaseState =
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
export type PaymentAttemptStateAdmitsNoRelease = IsNever<
  Extract<PaymentAttemptState, PaymentAttemptForbiddenReleaseState>
>;
/** Compile-time proof: adding a release state to the union breaks the build here. */
export const PAYMENT_ATTEMPT_STATE_ADMITS_NO_RELEASE: PaymentAttemptStateAdmitsNoRelease = true;

export type PaymentAttemptGatewayStatus = 'received' | 'batched' | 'confirmed' | 'completed';

/** The lane binding exactly as packages/x402 `LanePaymentBinding` (buyer role). */
export interface PaymentAttemptBindingInput {
  readonly schemaVersion: string;
  readonly role: string;
  readonly network: string;
  readonly grantId: string;
  readonly actionId: string;
  readonly attemptId: string;
  readonly grantRequirementDigest: string;
  readonly laneRequirementDigest: string;
  readonly verifyingContract: string;
  readonly asset: string;
  readonly from: string;
  readonly to: string;
  readonly value: string;
  readonly validAfter: string;
  readonly validBefore: string;
  readonly nonce: string;
}

/** The lane `LanePersistRecord`. There is deliberately no signature field. */
export interface PersistPaymentAttemptInput {
  readonly binding: PaymentAttemptBindingInput;
  readonly bindingDigest: string;
}

export interface RecordPaymentAttemptDispatchInput {
  readonly attemptId: string;
  readonly bindingDigest: string;
}

/** Durable, non-secret attempt projection. */
export interface PaymentAttemptRecord {
  readonly organizationId: string;
  readonly attemptId: string;
  readonly grantId: string;
  readonly actionId: string;
  readonly providerId: string;
  readonly listingId: string;
  readonly listingVersion: string;
  readonly requirementId: string;
  readonly requirementDigest: string;
  readonly networkId: typeof PAYMENT_ATTEMPT_NETWORK;
  readonly assetAddress: typeof PAYMENT_ATTEMPT_ASSET_ADDRESS;
  readonly verifyingContract: typeof PAYMENT_ATTEMPT_VERIFYING_CONTRACT;
  readonly payerAddress: string;
  readonly payToAddress: string;
  readonly valueAtomic: string;
  readonly validAfter: string;
  readonly validBefore: string;
  readonly nonce: string;
  readonly laneRequirementDigest: string;
  readonly bindingDigest: string;
  readonly state: PaymentAttemptState;
  readonly persistedAt: string;
  readonly dispatchedAt: string | null;
  readonly observedAt: string | null;
  readonly transferId: string | null;
  readonly gatewayStatus: PaymentAttemptGatewayStatus | null;
  readonly batchTxHash: string | null;
}

/** Seller payment terms operation (idempotency + audit; no outbox event). */
export const LISTING_PAYMENT_TERMS_OPERATION = 'market.listing.payment_terms.record' as const;
export const LISTING_PAYMENT_TERMS_KEY_DOMAIN = 'openarc.market.listing.payment_terms.record.idempotency.v1' as const;
export const LISTING_PAYMENT_TERMS_SESSION_DOMAIN = 'openarc.market.listing.payment_terms.record.session.v1' as const;
export const LISTING_PAYMENT_TERMS_DIGEST_DOMAIN = 'market.listing.payment_terms.record.v1' as const;

export interface RecordListingPaymentTermsInput {
  readonly payToAddress: string;
}

export interface ListingPaymentTermsDbResult {
  readonly replayed: boolean;
  readonly terms: {
    readonly organizationId: string;
    readonly listingId: string;
    readonly version: string;
    /** Lowercase canonical form, exactly as stored. */
    readonly payToAddress: string;
    readonly recordedAt: string;
  };
  readonly receipt: {
    readonly mutationId: string;
    readonly operation: typeof LISTING_PAYMENT_TERMS_OPERATION;
    readonly resourceType: 'listing_version';
    readonly resourceId: string;
    readonly committedAt: string;
  };
}

export interface RegisterVerifiedRequirementInput {
  readonly requirementId: string;
  readonly listingId: string;
}

/** A server-derived verified requirement. Every term comes from the database. */
export interface VerifiedRequirementRecord {
  readonly organizationId: string;
  readonly requirementId: string;
  readonly sellerOrganizationId: string;
  readonly providerId: string;
  readonly listingId: string;
  readonly listingVersion: string;
  readonly networkId: typeof PAYMENT_ATTEMPT_NETWORK;
  readonly asset: 'USDC';
  readonly representation: 'erc20';
  readonly decimals: 6;
  readonly amountAtomic: string;
  readonly feeAtomic: string;
  readonly payToAddress: string;
  readonly requirementDigest: string;
  readonly sourceKind: 'verified_listing';
  readonly createdAt: string;
  readonly validUntil: string;
}

export interface PersistPaymentAttemptDbResult {
  readonly replayed: boolean;
  readonly attempt: PaymentAttemptRecord;
}

const HEX64 = /^[0-9a-f]{64}$(?![\s\S])/;
const ORG_ID = /^openarc:org:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const GRANT_ID = /^openarc:grant:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const ACTION_ID = /^openarc:action:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const PROVIDER_ID = /^openarc:provider:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const LISTING_ID = /^openarc:listing:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const REQUIREMENT_ID = /^openarc:requirement:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const LISTING_VERSION = /^[1-9][0-9]{0,8}$(?![\s\S])/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$(?![\s\S])/;
const UINT256 = /^(0|[1-9][0-9]{0,77})$(?![\s\S])/;
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$(?![\s\S])/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$(?![\s\S])/;
const BYTES32 = /^0x[0-9a-f]{64}$(?![\s\S])/;
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
const LOWER_ADDRESS = /^0x[0-9a-f]{40}$(?![\s\S])/;
const MUTATION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const UINT256_MAX = (1n << 256n) - 1n;
const MIN_VALIDITY_SECONDS = 604800n;

const BINDING_KEYS = [
  'actionId', 'asset', 'attemptId', 'from', 'grantId', 'grantRequirementDigest',
  'laneRequirementDigest', 'network', 'nonce', 'role', 'schemaVersion', 'to',
  'validAfter', 'validBefore', 'value', 'verifyingContract',
] as const;

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function fail(code: ControlPaymentAttemptStoreErrorCode): never {
  throw new ControlPaymentAttemptStoreError(code);
}

function failInput(): never {
  fail('CONTROL_PAYMENT_ATTEMPT_STORE_INPUT_INVALID');
}

function failOutput(): never {
  fail('CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireShape(value: unknown, allowed: readonly string[]): Record<string, unknown> {
  if (!isRecord(value)) failInput();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) failInput();
  const keys = Object.keys(value);
  if (keys.length !== allowed.length) failInput();
  for (const key of keys) {
    if (!allowed.includes(key)) failInput();
    if (value[key] === undefined) failInput();
  }
  return value;
}

function requirePattern(value: unknown, pattern: RegExp): string {
  if (typeof value !== 'string' || !pattern.test(value)) failInput();
  return value;
}

function requireUint(value: unknown, positive: boolean): string {
  const text = requirePattern(value, UINT256);
  const parsed = BigInt(text);
  if (parsed > UINT256_MAX || (positive && parsed === 0n)) failInput();
  return text;
}

function requireAddress(value: unknown): string {
  const text = requirePattern(value, ADDRESS);
  if (text.toLowerCase() === ZERO_ADDRESS) failInput();
  return text;
}

function requireNonce(value: unknown): string {
  const text = requirePattern(value, BYTES32);
  if (BigInt(text) === 0n) failInput();
  return text;
}

/** Exact presented token hash grammar; never echoed. */
function requireHash(value: unknown): string {
  return requirePattern(value, HEX64);
}

function requireSellerPayTo(value: unknown): string {
  const text = requireAddress(value).toLowerCase();
  if (text === PAYMENT_ATTEMPT_ASSET_ADDRESS || text === PAYMENT_ATTEMPT_VERIFYING_CONTRACT.toLowerCase()) {
    failInput();
  }
  return text;
}

function requireMetadata(value: unknown): { idempotencyKey: string; mutationId: string } {
  const shape = requireShape(value, ['idempotencyKey', 'mutationId']);
  const mutationId = requirePattern(shape['mutationId'], MUTATION_ID);
  let idempotencyKey: string;
  try {
    idempotencyKey = requireIdempotencyKey(shape['idempotencyKey']);
  } catch {
    failInput();
  }
  return { idempotencyKey, mutationId };
}

export function digestListingPaymentTermsIdempotencyKey(rawKey: unknown): string {
  let key: string;
  try {
    key = requireIdempotencyKey(rawKey);
  } catch {
    failInput();
  }
  return sha256Hex(`${LISTING_PAYMENT_TERMS_KEY_DOMAIN}:${key}`);
}

export function digestListingPaymentTermsSessionContext(presentedHash: unknown): string {
  return sha256Hex(`${LISTING_PAYMENT_TERMS_SESSION_DOMAIN}:${requireHash(presentedHash)}`);
}

/**
 * Replay digest for a payment-terms write. It binds the DB-resolved actor, the
 * exact presented session context, the mutation, the listing version and the
 * lowercase pay-to, so a retry matches and a changed pay-to conflicts.
 */
export function digestListingPaymentTermsRequest(
  context: { organizationId: string; actorAccountId: string; sessionContextDigest: string; mutationId: string },
  listingId: string,
  version: string,
  payToAddress: string,
): string {
  return sha256Hex(JSON.stringify([
    LISTING_PAYMENT_TERMS_DIGEST_DOMAIN,
    PAYMENT_ATTEMPT_NETWORK,
    context.organizationId,
    context.actorAccountId,
    context.sessionContextDigest,
    context.mutationId,
    listingId,
    version,
    payToAddress.toLowerCase(),
  ]));
}

/**
 * Reproduces packages/x402 `digestLaneBinding` for an all-string binding:
 * sha256 over JSON with keys in JavaScript sort order.
 */
export function digestPaymentAttemptBinding(binding: PaymentAttemptBindingInput): string {
  const record = binding as unknown as Record<string, string>;
  const keys = Object.keys(record).sort();
  const json = `{${keys.map((key) => `${JSON.stringify(key)}:${JSON.stringify(record[key])}`).join(',')}}`;
  return `sha256:${sha256Hex(json)}`;
}

function requireBinding(value: unknown): PaymentAttemptBindingInput {
  const shape = requireShape(value, BINDING_KEYS);
  if (shape['schemaVersion'] !== PAYMENT_ATTEMPT_BINDING_SCHEMA_VERSION) failInput();
  if (shape['role'] !== 'buyer') failInput();
  if (shape['network'] !== PAYMENT_ATTEMPT_NETWORK) failInput();
  if (shape['asset'] !== PAYMENT_ATTEMPT_ASSET_ADDRESS) failInput();
  if (shape['verifyingContract'] !== PAYMENT_ATTEMPT_VERIFYING_CONTRACT) failInput();
  const binding: PaymentAttemptBindingInput = {
    schemaVersion: PAYMENT_ATTEMPT_BINDING_SCHEMA_VERSION,
    role: 'buyer',
    network: PAYMENT_ATTEMPT_NETWORK,
    grantId: requirePattern(shape['grantId'], GRANT_ID),
    actionId: requirePattern(shape['actionId'], ACTION_ID),
    attemptId: requirePattern(shape['attemptId'], UUID_V4),
    grantRequirementDigest: requirePattern(shape['grantRequirementDigest'], SHA256_DIGEST),
    laneRequirementDigest: requirePattern(shape['laneRequirementDigest'], SHA256_DIGEST),
    verifyingContract: PAYMENT_ATTEMPT_VERIFYING_CONTRACT,
    asset: PAYMENT_ATTEMPT_ASSET_ADDRESS,
    from: requireAddress(shape['from']),
    to: requireAddress(shape['to']),
    value: requireUint(shape['value'], true),
    validAfter: requireUint(shape['validAfter'], false),
    validBefore: requireUint(shape['validBefore'], true),
    nonce: requireNonce(shape['nonce']),
  };
  const payTo = binding.to.toLowerCase();
  if (
    payTo === binding.from.toLowerCase() ||
    payTo === PAYMENT_ATTEMPT_ASSET_ADDRESS ||
    payTo === PAYMENT_ATTEMPT_VERIFYING_CONTRACT.toLowerCase()
  ) {
    failInput();
  }
  if (BigInt(binding.validBefore) <= BigInt(binding.validAfter)) failInput();
  if (BigInt(binding.validBefore) - BigInt(binding.validAfter) < MIN_VALIDITY_SECONDS) failInput();
  return binding;
}

function normalizeError(error: unknown): ControlPaymentAttemptStoreError {
  if (error instanceof ControlPaymentAttemptStoreError) return error;
  if (isRecord(error) && typeof error.code === 'string') {
    switch (error.code) {
      case '28000':
        return new ControlPaymentAttemptStoreError('CONTROL_PAYMENT_ATTEMPT_STORE_SESSION_INVALID');
      case '42501':
        return new ControlPaymentAttemptStoreError('CONTROL_PAYMENT_ATTEMPT_STORE_FORBIDDEN');
      case '23503':
        return new ControlPaymentAttemptStoreError('CONTROL_PAYMENT_ATTEMPT_STORE_NOT_FOUND');
      case '23505':
        return new ControlPaymentAttemptStoreError('CONTROL_PAYMENT_ATTEMPT_STORE_CONFLICT');
      case 'P0D01':
        return new ControlPaymentAttemptStoreError('CONTROL_PAYMENT_ATTEMPT_STORE_IDEMPOTENCY_CONFLICT');
      case 'P0D10':
        return new ControlPaymentAttemptStoreError('CONTROL_PAYMENT_ATTEMPT_STORE_REQUIREMENT_UNAVAILABLE');
      case 'P0D13':
        return new ControlPaymentAttemptStoreError('CONTROL_PAYMENT_ATTEMPT_STORE_POTENTIAL_EXPOSURE');
      case 'P0D14':
        return new ControlPaymentAttemptStoreError('CONTROL_PAYMENT_ATTEMPT_STORE_ATTEMPT_CONFLICT');
      case 'P0D15':
        return new ControlPaymentAttemptStoreError('CONTROL_PAYMENT_ATTEMPT_STORE_GRANT_EXPIRED');
      case '22023':
      case '22P02':
      case '22001':
      case '22003':
      case '23514':
        return new ControlPaymentAttemptStoreError('CONTROL_PAYMENT_ATTEMPT_STORE_INPUT_INVALID');
      default:
        return new ControlPaymentAttemptStoreError('CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE');
    }
  }
  return new ControlPaymentAttemptStoreError('CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE');
}

const PG_TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?([+-])(\d{2})(?::?(\d{2}))?$/;

function daysInMonth(year: number, month: number): number {
  return new Date(Date.UTC(year, month, 0)).getUTCDate();
}

function iso(value: unknown): string {
  if (typeof value !== 'string') failOutput();
  const match = PG_TIMESTAMP.exec(value);
  if (match === null) failOutput();
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, fraction, sign, offHourText, offMinuteText] = match;
  const year = Number.parseInt(yearText ?? '', 10);
  const month = Number.parseInt(monthText ?? '', 10);
  const day = Number.parseInt(dayText ?? '', 10);
  const hour = Number.parseInt(hourText ?? '', 10);
  const minute = Number.parseInt(minuteText ?? '', 10);
  const second = Number.parseInt(secondText ?? '', 10);
  const offHour = Number.parseInt(offHourText ?? '0', 10);
  const offMinute = Number.parseInt(offMinuteText ?? '0', 10);
  if (
    year < 1 || year > 9999 || month < 1 || month > 12 || day < 1 ||
    day > daysInMonth(year, month) || hour > 23 || minute > 59 || second > 59 ||
    offHour > 23 || offMinute > 59
  ) {
    failOutput();
  }
  const micros = (fraction ?? '').padEnd(6, '0').slice(0, 6);
  const offsetMinutes = (sign === '-' ? -1 : 1) * (offHour * 60 + offMinute);
  const local = new Date(0);
  local.setUTCFullYear(year, month - 1, day);
  local.setUTCHours(hour, minute, second, 0);
  const normalized = new Date(local.getTime() - offsetMinutes * 60_000);
  if (!Number.isFinite(normalized.getTime())) failOutput();
  return `${normalized.toISOString().slice(0, 19)}.${micros}Z`;
}

function isoOrNull(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  return iso(value);
}

const ATTEMPT_COLUMNS = `out_organization_id, out_attempt_id::text AS out_attempt_id, out_grant_id,
                out_action_id, out_provider_id, out_listing_id, out_listing_version,
                out_requirement_id, out_requirement_digest, out_network_id, out_asset_address,
                out_verifying_contract, out_payer_address, out_pay_to_address, out_value_atomic,
                out_valid_after, out_valid_before, out_nonce, out_lane_requirement_digest,
                out_binding_digest, out_state,
                out_persisted_at::text AS out_persisted_at,
                out_dispatched_at::text AS out_dispatched_at,
                out_observed_at::text AS out_observed_at,
                out_transfer_id::text AS out_transfer_id, out_gateway_status, out_batch_tx_hash`;

function projectAttempt(row: Record<string, unknown>): PaymentAttemptRecord {
  const text = (key: string, pattern: RegExp): string => {
    const value = row[key];
    if (typeof value !== 'string' || !pattern.test(value)) failOutput();
    return value;
  };
  const state = row['out_state'];
  if (typeof state !== 'string' || !(PAYMENT_ATTEMPT_STATES as readonly string[]).includes(state)) {
    failOutput();
  }
  if (
    row['out_network_id'] !== PAYMENT_ATTEMPT_NETWORK ||
    row['out_asset_address'] !== PAYMENT_ATTEMPT_ASSET_ADDRESS ||
    row['out_verifying_contract'] !== PAYMENT_ATTEMPT_VERIFYING_CONTRACT
  ) {
    failOutput();
  }
  const gatewayStatus = row['out_gateway_status'];
  if (
    gatewayStatus !== null &&
    gatewayStatus !== 'received' && gatewayStatus !== 'batched' &&
    gatewayStatus !== 'confirmed' && gatewayStatus !== 'completed'
  ) {
    failOutput();
  }
  const transferId = row['out_transfer_id'];
  if (transferId !== null && (typeof transferId !== 'string' || !UUID.test(transferId))) failOutput();
  const batchTxHash = row['out_batch_tx_hash'];
  if (batchTxHash !== null && (typeof batchTxHash !== 'string' || !BYTES32.test(batchTxHash))) failOutput();
  const record: PaymentAttemptRecord = {
    organizationId: text('out_organization_id', ORG_ID),
    attemptId: text('out_attempt_id', UUID_V4),
    grantId: text('out_grant_id', GRANT_ID),
    actionId: text('out_action_id', ACTION_ID),
    providerId: text('out_provider_id', PROVIDER_ID),
    listingId: text('out_listing_id', LISTING_ID),
    listingVersion: text('out_listing_version', LISTING_VERSION),
    requirementId: text('out_requirement_id', REQUIREMENT_ID),
    requirementDigest: text('out_requirement_digest', SHA256_DIGEST),
    networkId: PAYMENT_ATTEMPT_NETWORK,
    assetAddress: PAYMENT_ATTEMPT_ASSET_ADDRESS,
    verifyingContract: PAYMENT_ATTEMPT_VERIFYING_CONTRACT,
    payerAddress: text('out_payer_address', ADDRESS),
    payToAddress: text('out_pay_to_address', ADDRESS),
    valueAtomic: text('out_value_atomic', UINT256),
    validAfter: text('out_valid_after', UINT256),
    validBefore: text('out_valid_before', UINT256),
    nonce: text('out_nonce', BYTES32),
    laneRequirementDigest: text('out_lane_requirement_digest', SHA256_DIGEST),
    bindingDigest: text('out_binding_digest', SHA256_DIGEST),
    state: state as PaymentAttemptState,
    persistedAt: iso(row['out_persisted_at']),
    dispatchedAt: isoOrNull(row['out_dispatched_at']),
    observedAt: isoOrNull(row['out_observed_at']),
    transferId: transferId as string | null,
    gatewayStatus: gatewayStatus as PaymentAttemptGatewayStatus | null,
    batchTxHash: batchTxHash as string | null,
  };
  // Re-assert the closed state shape on the projection itself.
  const shapeOk =
    (record.state === 'persisted' && record.dispatchedAt === null && record.transferId === null) ||
    (record.state === 'unknown' && record.dispatchedAt !== null && record.transferId === null &&
      record.gatewayStatus === null) ||
    (record.state === 'pending' && record.dispatchedAt !== null && record.transferId !== null &&
      record.gatewayStatus !== null && record.gatewayStatus !== 'completed') ||
    (record.state === 'committed' && record.dispatchedAt !== null && record.transferId !== null &&
      record.gatewayStatus === 'completed' && record.batchTxHash !== null);
  if (!shapeOk) failOutput();
  return record;
}

export class ControlPaymentAttemptStore {
  readonly #pool: TenantPool;
  #initialized = false;

  constructor(pool: TenantPool) {
    if (pool === null || typeof pool !== 'object' || typeof pool.connect !== 'function') {
      failInput();
    }
    this.#pool = pool;
  }

  async initialize(): Promise<void> {
    if (this.#initialized) return;
    await this.#baseChecks(() => new ControlGrantStore(this.#pool).initialize());
    await this.#withTransaction(async (client) => {
      await this.#assertReady(client);
    });
    this.#initialized = true;
  }

  async readiness(): Promise<void> {
    await this.#baseChecks(() => new ControlGrantStore(this.#pool).readiness());
    await this.#withTransaction(async (client) => {
      await this.#assertReady(client);
    });
  }

  async #baseChecks(run: () => Promise<void>): Promise<void> {
    try {
      await run();
    } catch {
      fail('CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE');
    }
  }

  /**
   * Persist the lane binding BEFORE any dispatch. Accepts exactly the lane
   * `LanePersistRecord`. The returned `attempt.bindingDigest` is read back from
   * the database and is the value the lane's persist callback must echo.
   */
  async persistBuyerAttempt(
    commerceTokenHash: unknown,
    input: unknown,
  ): Promise<PersistPaymentAttemptDbResult> {
    const tokenHash = requireHash(commerceTokenHash);
    const shape = requireShape(input, ['binding', 'bindingDigest']);
    const binding = requireBinding(shape['binding']);
    const bindingDigest = requirePattern(shape['bindingDigest'], SHA256_DIGEST);
    if (digestPaymentAttemptBinding(binding) !== bindingDigest) failInput();
    return this.#withTransaction(async (client) => {
      const result = await client.query<Record<string, unknown>>(
        `SELECT out_replayed, ${ATTEMPT_COLUMNS}
           FROM openarc_durable.persist_payment_attempt(
             $1, $2, $3::uuid, $4, $5, $6, $7, $8, $9, $10)`,
        [
          tokenHash, binding.grantId, binding.attemptId, binding.from, binding.to,
          binding.validAfter, binding.validBefore, binding.nonce,
          binding.laneRequirementDigest, bindingDigest,
        ],
      );
      if (result.rows.length !== 1 || result.rows[0] === undefined) failOutput();
      const row = result.rows[0];
      const replayed = row['out_replayed'];
      if (replayed !== true && replayed !== false) failOutput();
      const attempt = projectAttempt(row);
      if (
        attempt.attemptId !== binding.attemptId ||
        attempt.grantId !== binding.grantId ||
        attempt.actionId !== binding.actionId ||
        attempt.bindingDigest !== bindingDigest ||
        attempt.requirementDigest !== binding.grantRequirementDigest ||
        attempt.valueAtomic !== binding.value ||
        attempt.nonce !== binding.nonce
      ) {
        failOutput();
      }
      if (!replayed && attempt.state !== 'persisted') failOutput();
      return { replayed, attempt };
    });
  }

  /**
   * Record the one dispatch of a persisted attempt. It must COMMIT before the
   * process sends. A second call in any state is ATTEMPT_CONFLICT and never a
   * success; OUTCOME_UNKNOWN means the caller must not send.
   */
  async recordDispatch(
    commerceTokenHash: unknown,
    input: unknown,
  ): Promise<PaymentAttemptRecord> {
    const tokenHash = requireHash(commerceTokenHash);
    const shape = requireShape(input, ['attemptId', 'bindingDigest']);
    const attemptId = requirePattern(shape['attemptId'], UUID_V4);
    const bindingDigest = requirePattern(shape['bindingDigest'], SHA256_DIGEST);
    return this.#withTransaction(async (client) => {
      const result = await client.query<Record<string, unknown>>(
        `SELECT ${ATTEMPT_COLUMNS}
           FROM openarc_durable.record_payment_attempt_dispatch($1, $2::uuid, $3)`,
        [tokenHash, attemptId, bindingDigest],
      );
      if (result.rows.length !== 1 || result.rows[0] === undefined) failOutput();
      const attempt = projectAttempt(result.rows[0]);
      if (
        attempt.attemptId !== attemptId ||
        attempt.bindingDigest !== bindingDigest ||
        attempt.state !== 'unknown'
      ) {
        failOutput();
      }
      return attempt;
    });
  }

  /**
   * Restart recovery for the presenting agent. A missing attempt and an
   * attempt of another organization or agent are the same safe null.
   */
  async readAgentAttempt(
    commerceTokenHash: unknown,
    attemptId: unknown,
  ): Promise<PaymentAttemptRecord | null> {
    const tokenHash = requireHash(commerceTokenHash);
    const attempt = requirePattern(attemptId, UUID_V4);
    return this.#withTransaction(async (client) => {
      const result = await client.query<Record<string, unknown>>(
        `SELECT ${ATTEMPT_COLUMNS}
           FROM openarc_durable.read_agent_payment_attempt($1, $2::uuid)`,
        [tokenHash, attempt],
      );
      if (result.rows.length > 1) failOutput();
      const row = result.rows[0];
      if (row === undefined) return null;
      const projected = projectAttempt(row);
      if (projected.attemptId !== attempt) failOutput();
      return projected;
    });
  }

  /**
   * Seller human records the immutable pay-to terms of one listing version.
   * Requires a fresh non-recovery owner or provider_admin session of the
   * owning organization. Once recorded, the terms can never change; a new
   * pay-to needs a new listing version.
   */
  async recordListingPaymentTerms(
    sessionHash: unknown,
    organizationId: unknown,
    listingId: unknown,
    version: unknown,
    input: unknown,
    metadata: unknown,
  ): Promise<ListingPaymentTermsDbResult> {
    const hash = requireHash(sessionHash);
    const organization = requirePattern(organizationId, ORG_ID);
    const listing = requirePattern(listingId, LISTING_ID);
    const parsedVersion = requirePattern(version, LISTING_VERSION);
    const shape = requireShape(input, ['payToAddress']);
    const payTo = requireSellerPayTo(shape['payToAddress']);
    const meta = requireMetadata(metadata);
    const sessionContextDigest = digestListingPaymentTermsSessionContext(hash);
    const keyHash = digestListingPaymentTermsIdempotencyKey(meta.idempotencyKey);
    return this.#withTransaction(async (client) => {
      const writer = await client.query<{ out_actor: unknown }>(
        'SELECT out_actor FROM openarc_durable.lock_lifecycle_writer($1, $2, $3)',
        [hash, organization, listing],
      );
      const actor = writer.rows[0]?.out_actor;
      if (typeof actor !== 'string') fail('CONTROL_PAYMENT_ATTEMPT_STORE_FORBIDDEN');
      const requestDigest = digestListingPaymentTermsRequest(
        { organizationId: organization, actorAccountId: actor, sessionContextDigest, mutationId: meta.mutationId },
        listing, parsedVersion, payTo,
      );
      const result = await client.query<Record<string, unknown>>(
        `SELECT out_replayed, out_mutation_id::text AS out_mutation_id, out_operation, out_resource_type,
                out_resource_id, out_pay_to_address,
                out_recorded_at::text AS out_recorded_at,
                out_committed_at::text AS out_committed_at
           FROM openarc_durable.commit_listing_payment_terms(
             $1, $2, $3, $4, $5, $6::uuid, $7, $8, $9)`,
        [hash, organization, listing, parsedVersion, payTo, meta.mutationId, keyHash, requestDigest, sessionContextDigest],
      );
      if (result.rows.length !== 1 || result.rows[0] === undefined) failOutput();
      const row = result.rows[0];
      const replayed = row['out_replayed'];
      if (replayed !== true && replayed !== false) failOutput();
      const resourceId = `${listing}@${parsedVersion}`;
      if (
        row['out_mutation_id'] !== meta.mutationId ||
        row['out_operation'] !== LISTING_PAYMENT_TERMS_OPERATION ||
        row['out_resource_type'] !== 'listing_version' ||
        row['out_resource_id'] !== resourceId ||
        typeof row['out_pay_to_address'] !== 'string' ||
        !LOWER_ADDRESS.test(row['out_pay_to_address']) ||
        row['out_pay_to_address'] !== payTo
      ) {
        failOutput();
      }
      return {
        replayed,
        terms: {
          organizationId: organization,
          listingId: listing,
          version: parsedVersion,
          payToAddress: payTo,
          recordedAt: iso(row['out_recorded_at']),
        },
        receipt: {
          mutationId: meta.mutationId,
          operation: LISTING_PAYMENT_TERMS_OPERATION,
          resourceType: 'listing_version',
          resourceId,
          committedAt: iso(row['out_committed_at']),
        },
      };
    });
  }

  /**
   * Runtime verified requirement registration. The buyer organization is
   * derived from the exact consumed commerce token; the caller names only a
   * fresh requirement id and a listing id. Every term is server-derived.
   */
  async registerVerifiedRequirement(
    commerceTokenHash: unknown,
    input: unknown,
  ): Promise<VerifiedRequirementRecord> {
    const tokenHash = requireHash(commerceTokenHash);
    const shape = requireShape(input, ['requirementId', 'listingId']);
    const requirementId = requirePattern(shape['requirementId'], REQUIREMENT_ID);
    const listingId = requirePattern(shape['listingId'], LISTING_ID);
    return this.#withTransaction(async (client) => {
      const result = await client.query<Record<string, unknown>>(
        `SELECT out_organization_id, out_requirement_id, out_seller_organization_id, out_provider_id,
                out_listing_id, out_listing_version, out_network_id, out_asset, out_representation,
                out_decimals, out_amount_atomic, out_fee_atomic, out_pay_to_address,
                out_requirement_digest, out_source_kind,
                out_created_at::text AS out_created_at, out_valid_until::text AS out_valid_until
           FROM openarc_durable.register_verified_commerce_requirement($1, $2, $3)`,
        [tokenHash, requirementId, listingId],
      );
      if (result.rows.length !== 1 || result.rows[0] === undefined) failOutput();
      const row = result.rows[0];
      const text = (key: string, pattern: RegExp): string => {
        const value = row[key];
        if (typeof value !== 'string' || !pattern.test(value)) failOutput();
        return value;
      };
      if (
        row['out_requirement_id'] !== requirementId ||
        row['out_listing_id'] !== listingId ||
        row['out_network_id'] !== PAYMENT_ATTEMPT_NETWORK ||
        row['out_asset'] !== 'USDC' ||
        row['out_representation'] !== 'erc20' ||
        row['out_decimals'] !== 6 ||
        row['out_fee_atomic'] !== '0' ||
        row['out_source_kind'] !== 'verified_listing'
      ) {
        failOutput();
      }
      return {
        organizationId: text('out_organization_id', ORG_ID),
        requirementId,
        sellerOrganizationId: text('out_seller_organization_id', ORG_ID),
        providerId: text('out_provider_id', PROVIDER_ID),
        listingId,
        listingVersion: text('out_listing_version', LISTING_VERSION),
        networkId: PAYMENT_ATTEMPT_NETWORK,
        asset: 'USDC',
        representation: 'erc20',
        decimals: 6,
        amountAtomic: text('out_amount_atomic', UINT256),
        feeAtomic: '0',
        payToAddress: text('out_pay_to_address', LOWER_ADDRESS),
        requirementDigest: text('out_requirement_digest', SHA256_DIGEST),
        sourceKind: 'verified_listing',
        createdAt: iso(row['out_created_at']),
        validUntil: iso(row['out_valid_until']),
      };
    });
  }

  async #withTransaction<T>(work: (client: TenantClient) => Promise<T>): Promise<T> {
    let client: TenantClient;
    try {
      client = await this.#pool.connect();
    } catch {
      fail('CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE');
    }
    try {
      await client.query('BEGIN');
    } catch {
      client.release(true);
      fail('CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE');
    }
    let result: T;
    try {
      result = await work(client);
    } catch (error) {
      let rolledBack = false;
      try {
        await client.query('ROLLBACK');
        rolledBack = true;
      } catch {
        rolledBack = false;
      }
      client.release(!rolledBack);
      throw normalizeError(error);
    }
    try {
      await client.query('COMMIT');
    } catch {
      client.release(true);
      fail('CONTROL_PAYMENT_ATTEMPT_STORE_OUTCOME_UNKNOWN');
    }
    client.release(false);
    return result;
  }

  async #assertReady(client: TenantClient): Promise<void> {
    const EXPECTED_TABLES = ['openarc_durable.payment_attempts', 'openarc_tenant.listing_version_payment_terms'];
    const tables = await client.query<{
      n: number; all_enabled: boolean; all_forced: boolean; owned: number;
    }>(
      `SELECT count(*)::int AS n,
              bool_and(c.relrowsecurity) AS all_enabled,
              bool_and(c.relforcerowsecurity) AS all_forced,
              count(*) FILTER (WHERE r.rolname = 'openarc_migrator')::int AS owned
         FROM pg_class c
         JOIN pg_namespace ns ON ns.oid = c.relnamespace
         JOIN pg_roles r ON r.oid = c.relowner
        WHERE c.relkind = 'r'
          AND ns.nspname || '.' || c.relname = ANY ($1::text[])`,
      [EXPECTED_TABLES],
    );
    const state = tables.rows[0];
    if (
      state === undefined ||
      state.n !== EXPECTED_TABLES.length ||
      state.all_enabled !== true ||
      state.all_forced !== true ||
      state.owned !== EXPECTED_TABLES.length
    ) {
      fail('CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE');
    }
    const access = await client.query<{ n: number }>(
      `WITH reachable AS (
         SELECT r.oid FROM pg_roles r
          WHERE r.oid = (SELECT oid FROM pg_roles WHERE rolname = current_user)
             OR pg_has_role(current_user, r.oid, 'MEMBER')
       )
       SELECT count(*)::int AS n
         FROM pg_class c
         JOIN pg_namespace ns ON ns.oid = c.relnamespace
        WHERE c.relkind = 'r'
          AND ns.nspname || '.' || c.relname = ANY ($1::text[])
          AND EXISTS (
            SELECT 1 FROM reachable x
             WHERE has_table_privilege(x.oid, c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))`,
      [EXPECTED_TABLES],
    );
    if ((access.rows[0]?.n ?? -1) !== 0) fail('CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE');
    await this.#assertHelpers(client);
    await this.#assertTriggers(client);
    await this.#assertMigrations(client);
  }

  async #assertHelpers(client: TenantClient): Promise<void> {
    // Every schema15 definer helper is inventoried here, with its exact
    // identity signature, owner, SECURITY DEFINER, pinned search_path, no PUBLIC
    // grant and the exact runtime EXECUTE expectation.
    const production: readonly { name: string; args: string }[] = [
      { name: 'persist_payment_attempt', args: 'commerce_token_hash text, grant_id_input text, attempt_id_input uuid, payer_address_input text, pay_to_address_input text, valid_after_input text, valid_before_input text, nonce_input text, lane_requirement_digest_input text, binding_digest_input text' },
      { name: 'record_payment_attempt_dispatch', args: 'commerce_token_hash text, attempt_id_input uuid, binding_digest_input text' },
      { name: 'read_agent_payment_attempt', args: 'commerce_token_hash text, attempt_id_input uuid' },
      { name: 'register_verified_commerce_requirement', args: 'commerce_token_hash text, requirement_id_input text, listing_id_input text' },
      { name: 'commit_listing_payment_terms', args: 'session_hash text, organization_id text, listing_id text, version text, pay_to_address_input text, mutation_id uuid, key_hash text, request_digest text, session_context_digest text' },
      // Redefined by schema15 to keep attempt exposure held; still runtime-executable.
      { name: 'revoke_authorization_grant', args: 'human_session_hash text, organization_id text, grant_id_input text, mutation_id uuid, key_hash text, request_digest text, session_context_digest text' },
    ];
    const privateHelpers: readonly { name: string; args: string }[] = [
      { name: 'register_verified_commerce_requirement_core', args: 'buyer_organization_id text, requirement_id_input text, listing_id_input text' },
      { name: 'record_payment_attempt_observation', args: 'organization_id text, attempt_id_input uuid, observed_state text, transfer_id_input uuid, gateway_status_input text, batch_tx_hash_input text' },
    ];
    // Non-definer IMMUTABLE digest helpers: present, migrator-owned, pinned
    // search_path, and unreachable from the runtime.
    const privatePure: readonly { name: string; args: string }[] = [
      { name: 'verified_requirement_digest', args: 'seller_organization_id text, provider_id_input text, listing_id_input text, listing_version_input text, pay_to_address_input text, amount_atomic_input text, fee_atomic_input text' },
      { name: 'payment_attempt_binding_digest', args: 'action_id_input text, asset_input text, attempt_id_input text, from_input text, grant_id_input text, grant_requirement_digest_input text, lane_requirement_digest_input text, network_input text, nonce_input text, role_input text, schema_version_input text, to_input text, valid_after_input text, valid_before_input text, value_input text, verifying_contract_input text' },
    ];
    const rows = await client.query<{
      proname: string;
      args: string;
      owner: string;
      secdef: boolean;
      config: string[];
      app_exec: boolean;
      public_grants: number;
      source: string;
    }>(
      `SELECT p.proname, pg_get_function_identity_arguments(p.oid) AS args,
              r.rolname AS owner, p.prosecdef AS secdef,
              coalesce(p.proconfig, ARRAY[]::text[]) AS config,
              has_function_privilege('openarc_tenant_app', p.oid, 'EXECUTE') AS app_exec,
              (SELECT count(*)::int FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE') AS public_grants,
              p.prosrc AS source
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         JOIN pg_roles r ON r.oid = p.proowner
        WHERE n.nspname = 'openarc_durable'
          AND p.prokind = 'f'
          AND p.proname = ANY ($1::text[])`,
      [[...production, ...privateHelpers, ...privatePure, { name: 'is_canonical_source_kind' }].map((entry) => entry.name)],
    );
    // Exactly one overload per inventoried name: an extra signature (for
    // example one accepting a caller price or pay-to) is a readiness failure.
    const counts = new Map<string, number>();
    for (const row of rows.rows) counts.set(row.proname, (counts.get(row.proname) ?? 0) + 1);
    for (const count of counts.values()) {
      if (count !== 1) fail('CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE');
    }
    const byName = new Map(rows.rows.map((row) => [`${row.proname}(${row.args})`, row]));
    const check = (
      entries: readonly { name: string; args: string }[],
      secdef: boolean,
      appExec: boolean,
    ): void => {
      for (const expected of entries) {
        const row = byName.get(`${expected.name}(${expected.args})`);
        if (row === undefined) fail('CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE');
        if (
          row.owner !== 'openarc_migrator' ||
          row.secdef !== secdef ||
          !row.config.includes('search_path=pg_catalog') ||
          row.public_grants !== 0 ||
          row.app_exec !== appExec
        ) {
          fail('CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE');
        }
      }
    };
    check(production, true, true);
    check(privateHelpers, true, false);
    check(privatePure, false, false);
    const revokeEntry = production.find((entry) => entry.name === 'revoke_authorization_grant')!;
    const revoke = byName.get(`${revokeEntry.name}(${revokeEntry.args})`);
    if (revoke === undefined || !revoke.source.includes('openarc_durable.payment_attempts')) {
      fail('CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE');
    }
    const sourceKind = rows.rows.find((row) => row.proname === 'is_canonical_source_kind');
    if (
      sourceKind === undefined ||
      sourceKind.args !== 'value text' ||
      !sourceKind.source.includes("'verified_listing'") ||
      !sourceKind.source.includes("'internal_fixture'")
    ) {
      fail('CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE');
    }
  }

  async #assertTriggers(client: TenantClient): Promise<void> {
    const expected: readonly { table: string; trigger: string }[] = [
      { table: 'openarc_durable.authorization_grant_claims', trigger: 'authorization_grant_claims_payment_attempt' },
      { table: 'openarc_durable.budget_reservations', trigger: 'budget_reservations_payment_exposure' },
      { table: 'openarc_durable.commerce_actions', trigger: 'commerce_actions_payment_exposure' },
      { table: 'openarc_durable.commerce_requirement_references', trigger: 'commerce_requirement_references_verified' },
      { table: 'openarc_durable.payment_attempts', trigger: 'payment_attempts_mutation' },
      { table: 'openarc_tenant.listing_version_payment_terms', trigger: 'listing_version_payment_terms_append_only' },
    ];
    const rows = await client.query<{ relname: string; tgname: string; enabled: string }>(
      `SELECT n.nspname || '.' || c.relname AS relname, t.tgname, t.tgenabled::text AS enabled
         FROM pg_trigger t
         JOIN pg_class c ON c.oid = t.tgrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname IN ('openarc_durable', 'openarc_tenant') AND NOT t.tgisinternal
          AND t.tgname = ANY ($1::text[])`,
      [expected.map((entry) => entry.trigger)],
    );
    if (rows.rows.length !== expected.length) fail('CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE');
    for (const entry of expected) {
      const row = rows.rows.find((candidate) => candidate.tgname === entry.trigger);
      if (row === undefined || row.relname !== entry.table || row.enabled !== 'O') {
        fail('CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE');
      }
    }
  }

  async #assertMigrations(client: TenantClient): Promise<void> {
    const applied = await client.query<{ id: string; checksum: string }>(
      `SELECT id, checksum FROM openarc_meta.schema_migrations ORDER BY id`,
    );
    let migrations: readonly { readonly id: string; readonly sql: string }[];
    try {
      migrations = loadMigrations();
    } catch {
      fail('CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE');
    }
    if (applied.rows.length !== migrations.length) fail('CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE');
    if (!migrations.some((migration) => migration.id === '0015_payment_attempts')) {
      fail('CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE');
    }
    for (let index = 0; index < applied.rows.length; index += 1) {
      const record = applied.rows[index];
      const manifest = migrations[index];
      if (record === undefined || manifest === undefined || record.id !== manifest.id) {
        fail('CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE');
      }
      const checksum = createHash('sha256').update(manifest.sql, 'utf8').digest('hex');
      if (record.checksum !== checksum) fail('CONTROL_PAYMENT_ATTEMPT_STORE_UNAVAILABLE');
    }
  }
}

/** Structural adapter for callers that hold a raw `pg` Pool. */
export function asControlPaymentAttemptPool(pool: Pool): TenantPool {
  return pool as unknown as TenantPool;
}
