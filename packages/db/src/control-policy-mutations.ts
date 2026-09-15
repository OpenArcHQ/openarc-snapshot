import { createHash } from 'node:crypto';
import {
  CommercePolicyContentSchema,
  CommercePolicyIdSchema,
  CommercePolicyRevisionNumberSchema,
  IsoTimestampSchema,
  type CommercePolicyContent,
} from '@openarc/shared';
import { requireIdempotencyKey, requireMutationId } from './market-mutations.js';

/**
 * Pure metadata authority for the five control policy operations. This module
 * exposes ONLY canonical parsers and deterministic digest helpers. It accepts
 * no callback, principal, role, clock, network or filesystem. The recorded
 * policy content is declared data only; it is never spend authority.
 */

export const POLICY_OPERATIONS = [
  'control.policy.create',
  'control.policy.revision.create',
  'control.policy.pause',
  'control.policy.resume',
  'control.policy.revoke',
] as const;

export type PolicyOperation = (typeof POLICY_OPERATIONS)[number];

export type PolicyResourceType = 'budget_policy' | 'budget_policy_revision';

export const POLICY_RESOURCE_BY_OPERATION = Object.freeze({
  'control.policy.create': 'budget_policy',
  'control.policy.revision.create': 'budget_policy_revision',
  'control.policy.pause': 'budget_policy',
  'control.policy.resume': 'budget_policy',
  'control.policy.revoke': 'budget_policy',
}) satisfies Readonly<Record<PolicyOperation, PolicyResourceType>>;

export const POLICY_EVENT_BY_OPERATION = Object.freeze({
  'control.policy.create': 'control.policy.created',
  'control.policy.revision.create': 'control.policy.revision.created',
  'control.policy.pause': 'control.policy.paused',
  'control.policy.resume': 'control.policy.resumed',
  'control.policy.revoke': 'control.policy.revoked',
}) satisfies Readonly<Record<PolicyOperation, string>>;

export const POLICY_SESSION_DOMAIN_BY_OPERATION = Object.freeze({
  'control.policy.create': 'openarc.control.policy.create.session.v1',
  'control.policy.revision.create': 'openarc.control.policy.revision.create.session.v1',
  'control.policy.pause': 'openarc.control.policy.pause.session.v1',
  'control.policy.resume': 'openarc.control.policy.resume.session.v1',
  'control.policy.revoke': 'openarc.control.policy.revoke.session.v1',
}) satisfies Readonly<Record<PolicyOperation, string>>;

export const POLICY_KEY_DOMAIN_BY_OPERATION = Object.freeze({
  'control.policy.create': 'openarc.control.policy.create.idempotency.v1',
  'control.policy.revision.create': 'openarc.control.policy.revision.create.idempotency.v1',
  'control.policy.pause': 'openarc.control.policy.pause.idempotency.v1',
  'control.policy.resume': 'openarc.control.policy.resume.idempotency.v1',
  'control.policy.revoke': 'openarc.control.policy.revoke.idempotency.v1',
}) satisfies Readonly<Record<PolicyOperation, string>>;

export const POLICY_DIGEST_DOMAIN_BY_OPERATION = Object.freeze({
  'control.policy.create': 'control.policy.create.v1',
  'control.policy.revision.create': 'control.policy.revision.create.v1',
  'control.policy.pause': 'control.policy.pause.v1',
  'control.policy.resume': 'control.policy.resume.v1',
  'control.policy.revoke': 'control.policy.revoke.v1',
}) satisfies Readonly<Record<PolicyOperation, string>>;

export const POLICY_CONTENT_DIGEST_DOMAIN = 'openarc.control.policy.content.v1' as const;
export const POLICY_NETWORK = 'eip155:5042002' as const;

// Absolute-end pinned local leaves. Node's `$` also matches before a final
// newline, so every local validator uses `(?![\s\S])` instead of `$` and
// reuses the strict shared digest/ID schemas wherever they exist.
const HEX64 = /^[0-9a-f]{64}$(?![\s\S])/;
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$(?![\s\S])/;

/** Fixed, non-echoing policy input error. Never carries caller detail. */
export class PolicyInputError extends Error {
  constructor() {
    super('Policy input is invalid.');
    this.name = 'PolicyInputError';
  }
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

/** Strict parse of the exact frozen content shape; no caller digest/authority. */
export function parsePolicyContent(value: unknown): CommercePolicyContent {
  const parsed = CommercePolicyContentSchema.safeParse(value);
  if (!parsed.success) throw new PolicyInputError();
  return parsed.data;
}

export function parsePolicyId(value: unknown): string {
  const parsed = CommercePolicyIdSchema.safeParse(value);
  if (!parsed.success) throw new PolicyInputError();
  return parsed.data;
}

export function parsePolicyRevisionNumber(value: unknown): string {
  const parsed = CommercePolicyRevisionNumberSchema.safeParse(value);
  if (!parsed.success) throw new PolicyInputError();
  return parsed.data;
}

/**
 * Append CAS revision. A revision may only be appended when it still has a
 * successor, so the accepted top is one below the global maximum. Transitions
 * keep the full range so a maximum-revision policy can still be paused.
 */
export function parsePolicyAppendRevision(value: unknown): string {
  const parsed = CommercePolicyRevisionNumberSchema.safeParse(value);
  if (!parsed.success || BigInt(parsed.data) > 999999998n) {
    throw new PolicyInputError();
  }
  return parsed.data;
}

export function parsePolicyOperation(value: unknown): PolicyOperation {
  if (typeof value !== 'string' || !(POLICY_OPERATIONS as readonly string[]).includes(value)) {
    throw new PolicyInputError();
  }
  return value as PolicyOperation;
}

export function requirePolicyTimestamp(value: unknown): string {
  const parsed = IsoTimestampSchema.safeParse(value);
  if (!parsed.success) {
    throw new PolicyInputError();
  }
  return parsed.data;
}

/**
 * Canonical fixed-order projection of one policy content value. Every field is
 * extracted explicitly so object key order is irrelevant while any semantic
 * change (including allowlist array order) changes the digest.
 */
function canonicalPolicyContent(content: CommercePolicyContent): unknown[] {
  return [
    content.organizationId,
    content.subjectAgentId,
    content.networkId,
    content.asset,
    content.representation,
    content.decimals,
    content.perActionLimit,
    content.rollingLimit,
    content.rollingWindowSeconds,
    content.feeLimit,
    [...content.allowedProviderIds],
    [...content.allowedListingIds],
    content.approval.mode,
    content.approval.threshold,
    content.approval.separateApprover,
    content.expiresAt,
  ];
}

/**
 * Server-side deterministic content digest with a versioned domain and fixed
 * field order. It depends on no generated id, so a create retry produces the
 * exact same digest even before the derived root id is generated.
 */
export function digestPolicyContent(content: CommercePolicyContent): string {
  const canonical = JSON.stringify([
    POLICY_CONTENT_DIGEST_DOMAIN,
    ...canonicalPolicyContent(content),
  ]);
  return `sha256:${sha256Hex(canonical)}`;
}

export interface PolicyDigestContext {
  readonly organizationId: string;
  readonly actorAccountId: string;
  readonly actorRole: string;
  readonly sessionContextDigest: string;
  readonly mutationId: string;
}

function digestPolicyRequest(
  operation: PolicyOperation,
  context: PolicyDigestContext,
  target: unknown[],
): string {
  if (typeof context.organizationId !== 'string') throw new PolicyInputError();
  if (typeof context.actorAccountId !== 'string') throw new PolicyInputError();
  if (typeof context.actorRole !== 'string') throw new PolicyInputError();
  if (!HEX64.test(context.sessionContextDigest)) throw new PolicyInputError();
  const mutationId = requireMutationId(context.mutationId);
  return sha256Hex(
    JSON.stringify([
      POLICY_DIGEST_DOMAIN_BY_OPERATION[operation],
      POLICY_NETWORK,
      context.organizationId,
      context.actorAccountId,
      context.actorRole,
      context.sessionContextDigest,
      mutationId,
      ...target,
    ]),
  );
}

export function digestPolicyCreateRequest(
  context: PolicyDigestContext,
  content: CommercePolicyContent,
  contentDigest: string,
): string {
  if (!SHA256_DIGEST.test(contentDigest)) throw new PolicyInputError();
  return digestPolicyRequest('control.policy.create', context, [contentDigest]);
}

export interface PolicyRevisionCasFields {
  readonly expectedRevision: string;
  readonly expectedUpdatedAt: string;
}

export function digestPolicyRevisionCreateRequest(
  context: PolicyDigestContext,
  policyId: string,
  fields: PolicyRevisionCasFields,
  contentDigest: string,
): string {
  if (!SHA256_DIGEST.test(contentDigest)) throw new PolicyInputError();
  return digestPolicyRequest('control.policy.revision.create', context, [
    policyId,
    fields.expectedRevision,
    fields.expectedUpdatedAt,
    contentDigest,
  ]);
}

export function digestPolicyTransitionRequest(
  operation: PolicyOperation,
  context: PolicyDigestContext,
  policyId: string,
  fields: PolicyRevisionCasFields,
): string {
  return digestPolicyRequest(operation, context, [
    policyId,
    fields.expectedRevision,
    fields.expectedUpdatedAt,
  ]);
}

export function digestPolicySessionContext(
  operation: PolicyOperation,
  sessionHash: string,
): string {
  if (typeof sessionHash !== 'string' || !HEX64.test(sessionHash)) throw new PolicyInputError();
  return sha256Hex(`${POLICY_SESSION_DOMAIN_BY_OPERATION[operation]}:${sessionHash}`);
}

export function digestPolicyIdempotencyKey(
  operation: PolicyOperation,
  rawKey: string,
): string {
  const key = requireIdempotencyKey(rawKey);
  return sha256Hex(`${POLICY_KEY_DOMAIN_BY_OPERATION[operation]}:${key}`);
}

/** Canonical `policyId@revision` revision resource id with revision >= 2. */
export function policyRevisionResourceId(policyId: string, revision: string): string {
  const policy = parsePolicyId(policyId);
  const parsed = parsePolicyRevisionNumber(revision);
  return `${policy}@${parsed}`;
}

export { requireIdempotencyKey, requireMutationId };
