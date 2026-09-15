import { createHash } from 'node:crypto';
import {
  CommerceActionIdSchema,
  CommerceActionMetadataSchema,
  CommerceApprovalIdSchema,
  CommerceApprovalMetadataSchema,
  CommerceReservationIdSchema,
  CommerceRequirementIdSchema,
  type CommerceActionMetadata,
  type CommerceApprovalMetadata,
} from '@openarc/shared';
import { requireIdempotencyKey, requireMutationId } from './market-mutations.js';

/**
 * Pure metadata authority for the four durable action operations. This module
 * exposes ONLY canonical parsers and deterministic digest helpers. It accepts
 * no callback, principal, role, clock, transport or crypto selection. The
 * production runtime wrapper always passes the literal 'production' mode; the
 * fixture seam is a migrator-only SQL core and never a repository option.
 */

export const CONTROL_ACTION_OPERATIONS = [
  'control.commerce_action.authorize',
  'control.commerce_action.approve',
  'control.commerce_action.reject',
  'control.commerce_action.cancel',
] as const;

export type CommerceActionOperation = (typeof CONTROL_ACTION_OPERATIONS)[number];

export const CONTROL_ACTION_RESOURCE_TYPE = 'commerce_action' as const;
export type CommerceActionResourceType = typeof CONTROL_ACTION_RESOURCE_TYPE;

export const CONTROL_ACTION_NETWORK = 'eip155:5042002' as const;

export const CONTROL_ACTION_RESOURCE_BY_OPERATION = Object.freeze({
  'control.commerce_action.authorize': 'commerce_action',
  'control.commerce_action.approve': 'commerce_action',
  'control.commerce_action.reject': 'commerce_action',
  'control.commerce_action.cancel': 'commerce_action',
}) satisfies Readonly<Record<CommerceActionOperation, CommerceActionResourceType>>;

export const CONTROL_ACTION_EVENT_BY_OPERATION = Object.freeze({
  'control.commerce_action.authorize': 'control.commerce_action.authorized',
  'control.commerce_action.approve': 'control.commerce_action.approved',
  'control.commerce_action.reject': 'control.commerce_action.rejected',
  'control.commerce_action.cancel': 'control.commerce_action.cancelled',
}) satisfies Readonly<Record<CommerceActionOperation, string>>;

export const CONTROL_ACTION_SESSION_DOMAIN_BY_OPERATION = Object.freeze({
  'control.commerce_action.authorize': 'openarc.control.commerce_action.authorize.session.v1',
  'control.commerce_action.approve': 'openarc.control.commerce_action.approve.session.v1',
  'control.commerce_action.reject': 'openarc.control.commerce_action.reject.session.v1',
  'control.commerce_action.cancel': 'openarc.control.commerce_action.cancel.session.v1',
}) satisfies Readonly<Record<CommerceActionOperation, string>>;

export const CONTROL_ACTION_KEY_DOMAIN_BY_OPERATION = Object.freeze({
  'control.commerce_action.authorize': 'openarc.control.commerce_action.authorize.idempotency.v1',
  'control.commerce_action.approve': 'openarc.control.commerce_action.approve.idempotency.v1',
  'control.commerce_action.reject': 'openarc.control.commerce_action.reject.idempotency.v1',
  'control.commerce_action.cancel': 'openarc.control.commerce_action.cancel.idempotency.v1',
}) satisfies Readonly<Record<CommerceActionOperation, string>>;

export const CONTROL_ACTION_DIGEST_DOMAIN_BY_OPERATION = Object.freeze({
  'control.commerce_action.authorize': 'control.commerce_action.authorize.v1',
  'control.commerce_action.approve': 'control.commerce_action.approve.v1',
  'control.commerce_action.reject': 'control.commerce_action.reject.v1',
  'control.commerce_action.cancel': 'control.commerce_action.cancel.v1',
}) satisfies Readonly<Record<CommerceActionOperation, string>>;

const HEX64 = /^[0-9a-f]{64}$(?![\s\S])/;

/** Fixed, non-echoing action input error. Never carries caller detail. */
export class CommerceActionInputError extends Error {
  constructor() {
    super('Commerce action input is invalid.');
    this.name = 'CommerceActionInputError';
  }
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function requireHex64(value: unknown): string {
  if (typeof value !== 'string' || !HEX64.test(value)) throw new CommerceActionInputError();
  return value;
}

export function parseCommerceActionId(value: unknown): string {
  const parsed = CommerceActionIdSchema.safeParse(value);
  if (!parsed.success) throw new CommerceActionInputError();
  return parsed.data;
}

export function parseCommerceRequirementId(value: unknown): string {
  const parsed = CommerceRequirementIdSchema.safeParse(value);
  if (!parsed.success) throw new CommerceActionInputError();
  return parsed.data;
}

export function parseCommerceReservationId(value: unknown): string {
  const parsed = CommerceReservationIdSchema.safeParse(value);
  if (!parsed.success) throw new CommerceActionInputError();
  return parsed.data;
}

export function parseCommerceApprovalId(value: unknown): string {
  const parsed = CommerceApprovalIdSchema.safeParse(value);
  if (!parsed.success) throw new CommerceActionInputError();
  return parsed.data;
}

export function parseCommerceActionHash(value: unknown): string {
  return requireHex64(value);
}

export function parseCommerceActionMetadata(value: unknown): CommerceActionMetadata {
  const parsed = CommerceActionMetadataSchema.safeParse(value);
  if (!parsed.success) throw new CommerceActionInputError();
  return parsed.data;
}

export function parseCommerceApprovalMetadata(value: unknown): CommerceApprovalMetadata {
  const parsed = CommerceApprovalMetadataSchema.safeParse(value);
  if (!parsed.success) throw new CommerceActionInputError();
  return parsed.data;
}

function digestActionRequest(
  operation: CommerceActionOperation,
  fields: readonly unknown[],
): string {
  return sha256Hex(
    JSON.stringify([
      CONTROL_ACTION_DIGEST_DOMAIN_BY_OPERATION[operation],
      CONTROL_ACTION_NETWORK,
      ...fields,
    ]),
  );
}

/** Domain-separated digest of a presented human session hash. */
export function digestCommerceActionHumanContext(
  operation: Extract<
    CommerceActionOperation,
    | 'control.commerce_action.approve'
    | 'control.commerce_action.reject'
    | 'control.commerce_action.cancel'
  >,
  humanSessionHash: string,
): string {
  return sha256Hex(
    `${CONTROL_ACTION_SESSION_DOMAIN_BY_OPERATION[operation]}:${requireHex64(humanSessionHash)}`,
  );
}

/** Domain-separated digest of a presented commerce token hash. */
export function digestCommerceActionMachineContext(commerceTokenHash: string): string {
  return sha256Hex(
    `${CONTROL_ACTION_SESSION_DOMAIN_BY_OPERATION['control.commerce_action.authorize']}:${requireHex64(commerceTokenHash)}`,
  );
}

export function digestCommerceActionIdempotencyKey(
  operation: CommerceActionOperation,
  rawKey: string,
): string {
  const key = requireIdempotencyKey(rawKey);
  return sha256Hex(`${CONTROL_ACTION_KEY_DOMAIN_BY_OPERATION[operation]}:${key}`);
}

export interface CommerceActionAuthorizeDigestContext {
  readonly organizationId: string;
  readonly parentHumanAccountId: string;
  readonly commerceSessionId: string;
  readonly agentSessionId: string;
  readonly credentialId: string;
  readonly policyId: string;
  readonly actionId: string;
  readonly requirementId: string;
  readonly requirementDigest: string;
  readonly amountAtomic: string;
  readonly feeAtomic: string;
  readonly networkId: string;
  readonly asset: string;
  readonly representation: string;
  readonly decimals: number;
  readonly sessionContextDigest: string;
  readonly mutationId: string;
}

/**
 * Authorize replay digest. Binds the immutable resolved binding ids, the exact
 * requirement id+digest and the exact financial identity, so a retry with the
 * same logical body matches and a changed body conflicts. It deliberately does
 * NOT include anything regenerated per attempt.
 */
export function digestCommerceActionAuthorizeRequest(
  context: CommerceActionAuthorizeDigestContext,
): string {
  return digestActionRequest('control.commerce_action.authorize', [
    context.organizationId,
    context.parentHumanAccountId,
    context.commerceSessionId,
    context.agentSessionId,
    context.credentialId,
    context.policyId,
    parseCommerceActionId(context.actionId),
    parseCommerceRequirementId(context.requirementId),
    context.requirementDigest,
    context.amountAtomic,
    context.feeAtomic,
    context.networkId,
    context.asset,
    context.representation,
    context.decimals,
    context.sessionContextDigest,
    requireMutationId(context.mutationId),
  ]);
}

export interface CommerceActionHumanDigestContext {
  readonly organizationId: string;
  readonly actorAccountId: string;
  readonly sessionContextDigest: string;
  readonly mutationId: string;
}

export function digestCommerceActionDecisionRequest(
  operation: Extract<
    CommerceActionOperation,
    'control.commerce_action.approve' | 'control.commerce_action.reject'
  >,
  context: CommerceActionHumanDigestContext,
  actionId: string,
): string {
  return digestActionRequest(operation, [
    context.organizationId,
    context.actorAccountId,
    context.sessionContextDigest,
    requireMutationId(context.mutationId),
    parseCommerceActionId(actionId),
  ]);
}

export function digestCommerceActionCancelRequest(
  context: CommerceActionHumanDigestContext,
  actionId: string,
): string {
  return digestActionRequest('control.commerce_action.cancel', [
    context.organizationId,
    context.actorAccountId,
    context.sessionContextDigest,
    requireMutationId(context.mutationId),
    parseCommerceActionId(actionId),
  ]);
}

export { requireIdempotencyKey, requireMutationId };
