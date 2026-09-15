/**
 * Shared honest fixtures for the commerce-action HTTP slice.
 *
 * These are canonical wire-shaped values only. No production path, credential,
 * database or payment behavior lives here; injected fakes built on top of these
 * are never a production path.
 */

const UUID = "12345678-1234-4234-8123-123456789abc";
const UUID_B = "22345678-1234-4234-8123-123456789abc";

export const MUTATION = UUID;
export const MUTATION_B = UUID_B;
export const ORG = `openarc:org:${UUID}`;
export const ORG_B = `openarc:org:${UUID_B}`;
export const AGENT = `openarc:agent:${UUID}`;
export const ACCOUNT = `openarc:account:${UUID}`;
export const POLICY = `openarc:policy:${UUID}`;
export const PROVIDER = `openarc:provider:${UUID}`;
export const LISTING = `openarc:listing:${UUID}`;
export const ACTION = `openarc:action:${UUID}`;
export const ACTION_B = `openarc:action:${UUID_B}`;
export const APPROVAL = `openarc:approval:${UUID}`;
export const APPROVAL_B = `openarc:approval:${UUID_B}`;
export const REQUIREMENT = `openarc:requirement:${UUID}`;
export const RESERVATION = `openarc:reservation:${UUID}`;
export const SESSION_ID = UUID;

export const CREATED = "2026-01-01T00:00:00.000Z";
export const EXCHANGED = "2026-01-01T00:00:30.000Z";
export const EXPIRES = "2026-01-01T00:05:00.000Z";

export const IDEMPOTENCY = "A".repeat(43);
/** Canonical headless commerce-session bearer (never a real secret). */
export const SESSION_TOKEN = `oacs_v1_${"E".repeat(43)}`;
/** A machine agent-session token, which the action agent family must reject. */
export const AGENT_TOKEN = `oas_ag_${"A".repeat(43)}`;
export const BUILD_SHA = "0123456789abcdef0123456789abcdef01234567";
export const ORIGIN = "http://localhost:5183";
export const COOKIE = "openarc_session=abc";
export const CSRF = "csrf-token-value";

export const EXPOSURE_KEY = Object.freeze({
  organizationId: ORG,
  subjectAgentId: AGENT,
  networkId: "eip155:5042002",
  asset: "USDC",
  representation: "erc20",
  decimals: 6,
});

/** Canonical action metadata. Money stays an exact integer string. */
export function actionMetadata(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schemaVersion: "openarc.control.action.v1",
    actionId: ACTION,
    exposureKey: { ...EXPOSURE_KEY },
    commerceSessionId: SESSION_ID,
    policyId: POLICY,
    policyRevision: "1",
    providerId: PROVIDER,
    listingId: LISTING,
    listingVersion: "1",
    requirementId: REQUIREMENT,
    requirementDigest: `sha256:${"a".repeat(64)}`,
    amountAtomic: "123456789012345678901234567890",
    feeAtomic: "1",
    debitAtomic: "123456789012345678901234567891",
    status: "pending_approval",
    reservationId: null,
    approvalId: APPROVAL,
    createdAt: CREATED,
    updatedAt: CREATED,
    expiresAt: EXPIRES,
    ...overrides,
  };
}

export function approvalMetadata(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schemaVersion: "openarc.control.approval.v1",
    approvalId: APPROVAL,
    actionId: ACTION,
    organizationId: ORG,
    subjectAgentId: AGENT,
    commerceSessionId: SESSION_ID,
    policyId: POLICY,
    policyRevision: "1",
    requestedBy: ACCOUNT,
    separateApprover: false,
    status: "pending",
    decidedBy: null,
    createdAt: CREATED,
    expiresAt: EXPIRES,
    decidedAt: null,
    ...overrides,
  };
}

export function actionReceipt(
  operation: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    mutationId: MUTATION,
    operation,
    resourceType: "commerce_action",
    resourceId: ACTION,
    committedAt: CREATED,
    ...overrides,
  };
}

export function exposureView(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
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
    committedAtomic: "123456789012345678901234567890",
    unresolvedAtomic: "1",
    totalExposureAtomic: "123456789012345678901234567891",
    availableAtomic: "9",
    deficitAtomic: "0",
    asOf: CREATED,
    ...overrides,
  };
}

export function commerceSessionMetadata(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schemaVersion: "openarc.control.commerce-session.v1",
    sessionId: SESSION_ID,
    organizationId: ORG,
    subjectAgentId: AGENT,
    policyId: POLICY,
    scopes: ["commerce.authorize"],
    networkId: "eip155:5042002",
    asset: "USDC",
    representation: "erc20",
    decimals: 6,
    issuedAt: CREATED,
    expiresAt: EXPIRES,
    exchangedAt: EXCHANGED,
    revokedAt: null,
    ...overrides,
  };
}
