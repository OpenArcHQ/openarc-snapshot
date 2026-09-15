import { COMMERCE_API_ERRORS, COMMERCE_API_SCHEMA_VERSION } from "@openarc/shared";

/**
 * Shared, accepted-shape fixtures for the authorization-grant console tests.
 * Every record here parses against the frozen shared schemas; the tests mutate
 * copies to build the malformed cases they need.
 *
 * No fixture carries a grant token, cookie, CSRF value or session hash: the
 * accepted BROWSER grant wire cannot represent one. `FAKE_GRANT_TOKEN` exists
 * only so a test can prove such a value is REFUSED, never accepted.
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
export const PROVIDER = `openarc:provider:${V4}`;
export const LISTING = `openarc:listing:${V4}`;
export const RESERVATION = `openarc:reservation:${V4}`;
export const ACTION = `openarc:action:${V4}`;
export const ACCOUNT_A = `openarc:account:${V4}`;
export const ACCOUNT_B = `openarc:account:${V4_B}`;
export const GRANT = `openarc:grant:${V4}`;
export const GRANT_B = `openarc:grant:${V4_B}`;
export const SESSION = V4;
export const MUTATION = V4;

/**
 * A syntactically valid `oag_v1_` grant token. It is NEVER part of a valid
 * fixture: it exists so a test can assert that a response carrying grant-secret
 * material is refused as an invalid response, and that no view field contains
 * it.
 */
export const FAKE_GRANT_TOKEN = `oag_v1_${"A".repeat(42)}A`;

export const ISO_ISSUED = "2026-01-01T00:00:00.000Z";
/** Exactly 120 seconds after issuance; well inside the 300-second ceiling. */
export const ISO_EXPIRES = "2026-01-01T00:02:00.000Z";
/** Inside the window, so a valid claim instant. */
export const ISO_CLAIMED = "2026-01-01T00:01:00.000Z";
/** After the claim; a valid revoke instant. */
export const ISO_REVOKED = "2026-01-01T00:01:30.000Z";
/** Before `ISO_EXPIRES`: a clock at which the grant is still claimable. */
export const NOW_BEFORE_EXPIRY = "2026-01-01T00:01:00.000Z";
/** After `ISO_EXPIRES`: a clock at which the grant is expired. */
export const NOW_AFTER_EXPIRY = "2026-01-01T00:09:00.000Z";

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

/**
 * A valid `issued`, never-claimed grant. The accepted metadata carries NO
 * token, NO token hash, NO digest and NO amount of any kind, so no fixture here
 * can supply one.
 */
export function grantMetadata(
  grantId = GRANT,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schemaVersion: "openarc.control.grant.v1",
    grantId,
    organizationId: ORG,
    subjectAgentId: AGENT,
    actionId: ACTION,
    reservationId: RESERVATION,
    commerceSessionId: SESSION,
    providerId: PROVIDER,
    listingId: LISTING,
    listingVersion: "1",
    generation: "1",
    status: "issued",
    issuedAt: ISO_ISSUED,
    updatedAt: ISO_ISSUED,
    expiresAt: ISO_EXPIRES,
    claimedAt: null,
    revokedAt: null,
    ...overrides,
  };
}

/** A grant the provider claimed, still live. */
export function claimedGrantMetadata(
  grantId = GRANT,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return grantMetadata(grantId, {
    status: "claimed",
    claimedAt: ISO_CLAIMED,
    updatedAt: ISO_CLAIMED,
    revokedAt: null,
    ...overrides,
  });
}

/**
 * THE case this console exists to render honestly: a grant that was claimed and
 * then revoked. `claimedAt` is retained by the accepted schema, and the revoke
 * wire forbids `released` from being true here.
 */
export function claimedThenRevokedGrantMetadata(
  grantId = GRANT,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return grantMetadata(grantId, {
    status: "revoked",
    claimedAt: ISO_CLAIMED,
    revokedAt: ISO_REVOKED,
    updatedAt: ISO_REVOKED,
    ...overrides,
  });
}

/** A grant revoked before any claim. */
export function unclaimedRevokedGrantMetadata(
  grantId = GRANT,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return grantMetadata(grantId, {
    status: "revoked",
    claimedAt: null,
    revokedAt: ISO_REVOKED,
    updatedAt: ISO_REVOKED,
    ...overrides,
  });
}

/** A grant the server itself marks expired (never claimed, never revoked). */
export function expiredGrantMetadata(
  grantId = GRANT,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return grantMetadata(grantId, { status: "expired", ...overrides });
}

export function grantDetail(
  item: unknown = grantMetadata(),
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return { organizationId: ORG, grantId: GRANT, item, ...overrides };
}

export function grantReceipt(
  resourceId = GRANT,
  mutationId = MUTATION,
  operation = "control.grant.revoke",
): Record<string, unknown> {
  return {
    mutationId,
    operation,
    resourceType: "authorization_grant",
    resourceId,
    committedAt: ISO_REVOKED,
  };
}

/**
 * A revoke result for a grant that was ALREADY CLAIMED. `released` must be
 * false and `claimedAt` stays non-null: the claim fact and the held exposure
 * are both retained.
 */
export function claimedRevokeData(
  mutationId = MUTATION,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    replayed: false,
    metadata: claimedThenRevokedGrantMetadata(),
    receipt: grantReceipt(GRANT, mutationId),
    released: false,
    actionStatus: "grant_issued",
    ...overrides,
  };
}

/**
 * A revoke result for a grant that was never claimed and whose hold the server
 * actually released; the accepted shape then requires a cancelled action.
 */
export function releasedRevokeData(
  mutationId = MUTATION,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    replayed: false,
    metadata: unclaimedRevokedGrantMetadata(),
    receipt: grantReceipt(GRANT, mutationId),
    released: true,
    actionStatus: "cancelled",
    ...overrides,
  };
}
