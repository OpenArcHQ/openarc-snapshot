/**
 * Shared honest fixtures for the authorization-grant HTTP slice.
 *
 * These are canonical wire-shaped values only. No production path, credential,
 * database or payment behavior lives here; injected fakes built on top of these
 * are never a production path. Every "token" below is a syntactically canonical
 * placeholder, never a real secret.
 */

const UUID = "12345678-1234-4234-8123-123456789abc";
const UUID_B = "22345678-1234-4234-8123-123456789abc";

export const MUTATION = UUID;
export const MUTATION_B = UUID_B;
export const ATTEMPT = UUID;
export const ATTEMPT_B = UUID_B;
export const ORG = `openarc:org:${UUID}`;
export const ORG_B = `openarc:org:${UUID_B}`;
export const AGENT = `openarc:agent:${UUID}`;
export const ACCOUNT = `openarc:account:${UUID}`;
export const POLICY = `openarc:policy:${UUID}`;
export const PROVIDER = `openarc:provider:${UUID}`;
export const LISTING = `openarc:listing:${UUID}`;
export const ACTION = `openarc:action:${UUID}`;
export const ACTION_B = `openarc:action:${UUID_B}`;
export const REQUIREMENT = `openarc:requirement:${UUID}`;
export const RESERVATION = `openarc:reservation:${UUID}`;
export const GRANT = `openarc:grant:${UUID}`;
export const GRANT_B = `openarc:grant:${UUID_B}`;
export const SESSION_ID = UUID;

export const ISSUED = "2026-01-01T00:00:00.000Z";
export const EXCHANGED = "2026-01-01T00:00:30.000Z";
/** Exactly the 300-second grant lifetime ceiling above `ISSUED`. */
export const GRANT_EXPIRES = "2026-01-01T00:05:00.000Z";
export const CLAIMED = "2026-01-01T00:02:00.000Z";
export const SESSION_EXPIRES = "2026-01-01T00:05:00.000Z";

export const IDEMPOTENCY = "A".repeat(43);

/**
 * Canonical headless credentials. Every placeholder uses a DISTINCT filler
 * character so a leak assertion can never pass or fail by accident: no
 * placeholder is a substring of another, and none contains the idempotency key.
 * The trailing base64url character of a 32-byte secret must come from the
 * zero-padding-bit alphabet `AEIMQUYcgkosw048`.
 */
export const SESSION_TOKEN = `oacs_v1_${"C".repeat(42)}Q`;
export const PROVIDER_TOKEN = `oas_pr_${"D".repeat(42)}Q`;
/** A machine AGENT-session token, which no grant family may accept. */
export const MACHINE_AGENT_TOKEN = `oas_ag_${"E".repeat(42)}Q`;
/** The buyer's one-use grant secret. It is a BODY field, never a path/query. */
export const GRANT_TOKEN = `oag_v1_${"F".repeat(42)}Y`;

export const BUILD_SHA = "0123456789abcdef0123456789abcdef01234567";
export const ORIGIN = "http://localhost:5183";
export const COOKIE = "openarc_session=abc";
export const CSRF = "csrf-token-value";

export const CLAIM_DIGEST = `sha256:${"b".repeat(64)}`;
export const REQUIREMENT_DIGEST = `sha256:${"a".repeat(64)}`;

/** Canonical grant metadata. Money never appears on it; identity does. */
export function grantMetadata(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schemaVersion: "openarc.control.grant.v1",
    grantId: GRANT,
    organizationId: ORG,
    subjectAgentId: AGENT,
    actionId: ACTION,
    reservationId: RESERVATION,
    commerceSessionId: SESSION_ID,
    providerId: PROVIDER,
    listingId: LISTING,
    listingVersion: "1",
    generation: "1",
    status: "issued",
    issuedAt: ISSUED,
    updatedAt: ISSUED,
    expiresAt: GRANT_EXPIRES,
    claimedAt: null,
    revokedAt: null,
    ...overrides,
  };
}

/**
 * Canonical provider projection. Money stays an exact integer string and
 * `debitAtomic` is exactly `amountAtomic + feeAtomic`.
 */
export function providerView(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schemaVersion: "openarc.control.grant-provider.v1",
    grantId: GRANT,
    actionId: ACTION,
    providerId: PROVIDER,
    listingId: LISTING,
    listingVersion: "1",
    requirementId: REQUIREMENT,
    requirementDigest: REQUIREMENT_DIGEST,
    networkId: "eip155:5042002",
    asset: "USDC",
    representation: "erc20",
    decimals: 6,
    amountAtomic: "123456789012345678901234567890",
    feeAtomic: "1",
    debitAtomic: "123456789012345678901234567891",
    expiresAt: GRANT_EXPIRES,
    status: "issued",
    claimedAttemptId: null,
    ...overrides,
  };
}

export function claimedProviderView(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return providerView({
    status: "claimed",
    claimedAttemptId: ATTEMPT,
    ...overrides,
  });
}

export function grantReceipt(
  operation: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    mutationId: MUTATION,
    operation,
    resourceType: "authorization_grant",
    resourceId: GRANT,
    committedAt: ISSUED,
    ...overrides,
  };
}

export function providerAttemptStatus(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    status: "claimed",
    attemptId: ATTEMPT,
    grantId: GRANT,
    actionId: ACTION,
    providerId: PROVIDER,
    listingId: LISTING,
    listingVersion: "1",
    claimedAt: CLAIMED,
    grantRevoked: false,
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
    issuedAt: ISSUED,
    expiresAt: SESSION_EXPIRES,
    exchangedAt: EXCHANGED,
    revokedAt: null,
    ...overrides,
  };
}
