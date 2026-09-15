import { createHash } from 'node:crypto';
import {
  CommerceControlSessionIdSchema,
  CommerceControlSessionMetadataSchema,
  CommerceControlSessionReceiptSchema,
  CommerceControlSessionStatusItemSchema,
  CommerceControlSessionDurationSecondsSchema,
  IsoTimestampSchema,
  type CommerceControlSessionMetadata,
  type CommerceControlSessionReceipt,
  type CommerceControlSessionStatusItem,
} from '@openarc/shared';
import { requireIdempotencyKey, requireMutationId } from './market-mutations.js';

/**
 * Pure metadata authority for the three durable commerce-session operations.
 * This module exposes ONLY canonical parsers and deterministic digest helpers.
 * It accepts no callback, principal, role, clock, transport or crypto. All
 * server-side resolution happens inside the reviewed SQL definer helpers.
 *
 * The regenerated random handoff hash (issue) and session token hash (exchange)
 * are deliberately EXCLUDED from the logical request digest so an API retry
 * with fresh randomness still matches the original committed record and returns
 * replayed=true with no new authority or secret.
 */

export const CONTROL_SESSION_OPERATIONS = [
  'control.commerce_session.issue',
  'control.commerce_session.exchange',
  'control.commerce_session.revoke',
] as const;

export type CommerceSessionOperation = (typeof CONTROL_SESSION_OPERATIONS)[number];

export const CONTROL_SESSION_RESOURCE_TYPE = 'commerce_session' as const;
export type CommerceSessionResourceType = typeof CONTROL_SESSION_RESOURCE_TYPE;

export const CONTROL_SESSION_NETWORK = 'eip155:5042002' as const;
export const CONTROL_SESSION_ASSET = 'USDC' as const;
export const CONTROL_SESSION_REPRESENTATION = 'erc20' as const;
export const CONTROL_SESSION_DECIMALS = 6 as const;
export const CONTROL_SESSION_SCOPE = 'commerce.authorize' as const;

export const CONTROL_SESSION_RESOURCE_BY_OPERATION = Object.freeze({
  'control.commerce_session.issue': 'commerce_session',
  'control.commerce_session.exchange': 'commerce_session',
  'control.commerce_session.revoke': 'commerce_session',
}) satisfies Readonly<Record<CommerceSessionOperation, CommerceSessionResourceType>>;

export const CONTROL_SESSION_EVENT_BY_OPERATION = Object.freeze({
  'control.commerce_session.issue': 'control.commerce_session.issued',
  'control.commerce_session.exchange': 'control.commerce_session.exchanged',
  'control.commerce_session.revoke': 'control.commerce_session.revoked',
}) satisfies Readonly<Record<CommerceSessionOperation, string>>;

export const CONTROL_SESSION_SESSION_DOMAIN_BY_OPERATION = Object.freeze({
  'control.commerce_session.issue': 'openarc.control.commerce_session.issue.session.v1',
  'control.commerce_session.exchange': 'openarc.control.commerce_session.exchange.session.v1',
  'control.commerce_session.revoke': 'openarc.control.commerce_session.revoke.session.v1',
}) satisfies Readonly<Record<CommerceSessionOperation, string>>;

export const CONTROL_SESSION_KEY_DOMAIN_BY_OPERATION = Object.freeze({
  'control.commerce_session.issue': 'openarc.control.commerce_session.issue.idempotency.v1',
  'control.commerce_session.exchange': 'openarc.control.commerce_session.exchange.idempotency.v1',
  'control.commerce_session.revoke': 'openarc.control.commerce_session.revoke.idempotency.v1',
}) satisfies Readonly<Record<CommerceSessionOperation, string>>;

export const CONTROL_SESSION_DIGEST_DOMAIN_BY_OPERATION = Object.freeze({
  'control.commerce_session.issue': 'control.commerce_session.issue.v1',
  'control.commerce_session.exchange': 'control.commerce_session.exchange.v1',
  'control.commerce_session.revoke': 'control.commerce_session.revoke.v1',
}) satisfies Readonly<Record<CommerceSessionOperation, string>>;

const HEX64 = /^[0-9a-f]{64}$(?![\s\S])/;

/** Fixed, non-echoing commerce-session input error. Never carries caller detail. */
export class CommerceSessionInputError extends Error {
  constructor() {
    super('Commerce session input is invalid.');
    this.name = 'CommerceSessionInputError';
  }
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

export function parseCommerceSessionId(value: unknown): string {
  const parsed = CommerceControlSessionIdSchema.safeParse(value);
  if (!parsed.success) throw new CommerceSessionInputError();
  return parsed.data;
}

export function parseCommerceHandoffHash(value: unknown): string {
  if (typeof value !== 'string' || !HEX64.test(value)) throw new CommerceSessionInputError();
  return value;
}

export function parseCommerceTokenHash(value: unknown): string {
  if (typeof value !== 'string' || !HEX64.test(value)) throw new CommerceSessionInputError();
  return value;
}

/** Canonical whole-second duration 1..900, supplied as a number. */
export function parseCommerceDurationSeconds(value: unknown): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1 || value > 900) {
    throw new CommerceSessionInputError();
  }
  return value;
}

/**
 * Strict parse of stored/derived session metadata through the frozen shared
 * DTO, so every relationship (expiry window, exchanged/revoked ordering) is
 * enforced by the contract rather than a local copy.
 */
export function parseCommerceSessionMetadata(value: unknown): CommerceControlSessionMetadata {
  const parsed = CommerceControlSessionMetadataSchema.safeParse(value);
  if (!parsed.success) throw new CommerceSessionInputError();
  return parsed.data;
}

export function parseCommerceSessionStatusItem(value: unknown): CommerceControlSessionStatusItem {
  const parsed = CommerceControlSessionStatusItemSchema.safeParse(value);
  if (!parsed.success) throw new CommerceSessionInputError();
  return parsed.data;
}

export function parseCommerceSessionReceipt(value: unknown): CommerceControlSessionReceipt {
  const parsed = CommerceControlSessionReceiptSchema.safeParse(value);
  if (!parsed.success) throw new CommerceSessionInputError();
  return parsed.data;
}

export function parseCommerceTimestamp(value: unknown): string {
  const parsed = IsoTimestampSchema.safeParse(value);
  if (!parsed.success) throw new CommerceSessionInputError();
  return parsed.data;
}

export function parseCommerceDurationWire(value: unknown): string {
  const parsed = CommerceControlSessionDurationSecondsSchema.safeParse(value);
  if (!parsed.success) throw new CommerceSessionInputError();
  return parsed.data;
}

function digestCommerceSessionRequest(
  operation: CommerceSessionOperation,
  fields: readonly unknown[],
): string {
  return sha256Hex(
    JSON.stringify([
      CONTROL_SESSION_DIGEST_DOMAIN_BY_OPERATION[operation],
      CONTROL_SESSION_NETWORK,
      ...fields,
    ]),
  );
}

function requireHex64(value: unknown): string {
  if (typeof value !== 'string' || !HEX64.test(value)) throw new CommerceSessionInputError();
  return value;
}

/** Domain-separated digest of a presented human session hash. */
export function digestCommerceSessionHumanContext(
  operation: Extract<CommerceSessionOperation, 'control.commerce_session.issue' | 'control.commerce_session.revoke'>,
  humanSessionHash: string,
): string {
  return sha256Hex(
    `${CONTROL_SESSION_SESSION_DOMAIN_BY_OPERATION[operation]}:${requireHex64(humanSessionHash)}`,
  );
}

/** Domain-separated digest of a presented agent machine session hash. */
export function digestCommerceSessionMachineContext(agentSessionHash: string): string {
  return sha256Hex(
    `${CONTROL_SESSION_SESSION_DOMAIN_BY_OPERATION['control.commerce_session.exchange']}:${requireHex64(agentSessionHash)}`,
  );
}

export function digestCommerceSessionIdempotencyKey(
  operation: CommerceSessionOperation,
  rawKey: string,
): string {
  const key = requireIdempotencyKey(rawKey);
  return sha256Hex(`${CONTROL_SESSION_KEY_DOMAIN_BY_OPERATION[operation]}:${key}`);
}

export interface CommerceSessionHumanDigestContext {
  readonly organizationId: string;
  readonly actorAccountId: string;
  readonly actorRole: string;
  readonly sessionContextDigest: string;
  readonly mutationId: string;
}

export interface CommerceSessionMachineDigestContext {
  readonly organizationId: string;
  readonly issuerAccountId: string;
  readonly agentSessionHash: string;
  readonly credentialId: string;
  readonly handoffHash: string;
  readonly sessionContextDigest: string;
  readonly mutationId: string;
}

/**
 * Issue replay digest. Binds org, actor+role, session context, mutation id,
 * subject agent, exact policy and duration. It deliberately does NOT bind the
 * regenerated handoff hash, so a retry with fresh randomness still matches.
 */
export function digestCommerceSessionIssueRequest(
  context: CommerceSessionHumanDigestContext,
  subjectAgentId: string,
  policyId: string,
  durationSeconds: number,
): string {
  return digestCommerceSessionRequest('control.commerce_session.issue', [
    context.organizationId,
    context.actorAccountId,
    context.actorRole,
    context.sessionContextDigest,
    requireMutationId(context.mutationId),
    subjectAgentId,
    policyId,
    durationSeconds,
  ]);
}

/**
 * Exchange replay digest. Binds org, exact presented agent session + credential
 * and the credential issuer as the machine action actor, plus the presented
 * handoff target. The regenerated session token hash is NOT bound.
 */
export function digestCommerceSessionExchangeRequest(
  context: CommerceSessionMachineDigestContext,
): string {
  if (typeof context.handoffHash !== 'string' || !HEX64.test(context.handoffHash)) {
    throw new CommerceSessionInputError();
  }
  return digestCommerceSessionRequest('control.commerce_session.exchange', [
    context.organizationId,
    context.issuerAccountId,
    context.agentSessionHash,
    context.credentialId,
    context.handoffHash,
    context.sessionContextDigest,
    requireMutationId(context.mutationId),
  ]);
}

export function digestCommerceSessionRevokeRequest(
  context: CommerceSessionHumanDigestContext,
  sessionId: string,
): string {
  return digestCommerceSessionRequest('control.commerce_session.revoke', [
    context.organizationId,
    context.actorAccountId,
    context.actorRole,
    context.sessionContextDigest,
    requireMutationId(context.mutationId),
    sessionId,
  ]);
}

export { requireIdempotencyKey, requireMutationId };
