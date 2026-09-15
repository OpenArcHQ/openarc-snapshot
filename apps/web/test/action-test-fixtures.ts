import { COMMERCE_API_ERRORS, COMMERCE_API_SCHEMA_VERSION } from "@openarc/shared";

/**
 * Shared, accepted-shape fixtures for the commerce action/approval console
 * tests. Every record here parses against the frozen shared schemas; the tests
 * mutate copies to build the malformed cases they need.
 *
 * No fixture carries a token, cookie, CSRF value or session hash: the accepted
 * wire cannot represent one.
 */

export const META = {
  schemaVersion: COMMERCE_API_SCHEMA_VERSION,
  requestId: "018f47a2-3b4c-7def-8123-456789abcdef",
  buildSha: "0123456789abcdef0123456789abcdef01234567",
};

export const V4 = "12345678-1234-4234-8123-123456789abc";
export const V4_B = "87654321-4321-4321-b123-abcdefabcdef";

export const ORG = `openarc:org:${V4}`;
export const ORG_B = `openarc:org:${V4_B}`;
export const AGENT = `openarc:agent:${V4}`;
export const AGENT_B = `openarc:agent:${V4_B}`;
export const POLICY = `openarc:policy:${V4}`;
export const PROVIDER = `openarc:provider:${V4}`;
export const LISTING = `openarc:listing:${V4}`;
export const REQUIREMENT = `openarc:requirement:${V4}`;
export const RESERVATION = `openarc:reservation:${V4}`;
export const ACCOUNT_A = `openarc:account:${V4}`;
export const ACCOUNT_B = `openarc:account:${V4_B}`;
// `openarc:action:1234…` sorts strictly before `openarc:action:8765…`.
export const ACTION = `openarc:action:${V4}`;
export const ACTION_B = `openarc:action:${V4_B}`;
export const APPROVAL = `openarc:approval:${V4}`;
export const APPROVAL_B = `openarc:approval:${V4_B}`;
export const SESSION = V4;
export const MUTATION = V4;
export const DIGEST = `sha256:${"a".repeat(64)}`;

export const ISO = "2026-01-01T00:00:00.000Z";
export const ISO_LATER = "2026-01-01T00:15:00.000Z";

export const EXPOSURE_KEY = Object.freeze({
  organizationId: ORG,
  subjectAgentId: AGENT,
  networkId: "eip155:5042002",
  asset: "USDC",
  representation: "erc20",
  decimals: 6,
});

export function success(data: unknown): Response {
  return new Response(JSON.stringify({ ok: true, data, meta: META }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

export function errorEnvelope(
  code: keyof typeof COMMERCE_API_ERRORS,
  status: number,
): Response {
  return new Response(
    JSON.stringify({
      ok: false,
      error: { code, message: COMMERCE_API_ERRORS[code].message, retryable: false },
      meta: META,
    }),
    { status, headers: { "content-type": "application/json" } },
  );
}

/** A valid pending_approval action: amount 1.500000 + fee 0.250000 = 1.750000. */
export function actionMetadata(
  actionId = ACTION,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schemaVersion: "openarc.control.action.v1",
    actionId,
    exposureKey: { ...EXPOSURE_KEY },
    commerceSessionId: SESSION,
    policyId: POLICY,
    policyRevision: "1",
    providerId: PROVIDER,
    listingId: LISTING,
    listingVersion: "1",
    requirementId: REQUIREMENT,
    requirementDigest: DIGEST,
    amountAtomic: "1500000",
    feeAtomic: "250000",
    debitAtomic: "1750000",
    status: "pending_approval",
    reservationId: null,
    approvalId: APPROVAL,
    createdAt: ISO,
    updatedAt: ISO,
    expiresAt: ISO_LATER,
    ...overrides,
  };
}

export function approvalMetadata(
  approvalId = APPROVAL,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schemaVersion: "openarc.control.approval.v1",
    approvalId,
    actionId: ACTION,
    organizationId: ORG,
    subjectAgentId: AGENT,
    commerceSessionId: SESSION,
    policyId: POLICY,
    policyRevision: "1",
    requestedBy: ACCOUNT_A,
    separateApprover: true,
    status: "pending",
    decidedBy: null,
    createdAt: ISO,
    expiresAt: ISO_LATER,
    decidedAt: null,
    ...overrides,
  };
}

export function exposureView(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    organizationId: ORG,
    subjectAgentId: AGENT,
    policyId: POLICY,
    policyRevision: "1",
    networkId: "eip155:5042002",
    asset: "USDC",
    representation: "erc20",
    decimals: 6,
    windowSeconds: "86400",
    committedAtomic: "1000000",
    unresolvedAtomic: "250000",
    totalExposureAtomic: "1250000",
    availableAtomic: "8750000",
    deficitAtomic: "0",
    asOf: ISO,
    ...overrides,
  };
}

export function exposureData(item: unknown = exposureView()): Record<string, unknown> {
  return { organizationId: ORG, subjectAgentId: AGENT, policyId: POLICY, item };
}

export function actionReceipt(
  operation: string,
  resourceId = ACTION,
  mutationId = MUTATION,
): Record<string, unknown> {
  return {
    mutationId,
    operation,
    resourceType: "commerce_action",
    resourceId,
    committedAt: ISO,
  };
}

export function mutationData(
  operation: string,
  mutationId = MUTATION,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    replayed: false,
    metadata: actionMetadata(),
    receipt: actionReceipt(operation, ACTION, mutationId),
    ...overrides,
  };
}
