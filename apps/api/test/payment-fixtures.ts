/**
 * Shared honest fixtures for the migration-0015 payment HTTP slice.
 *
 * Canonical wire-shaped values only. No production path, credential, wallet,
 * database or payment behavior lives here. Every "token" is a syntactically
 * canonical placeholder with a DISTINCT filler character, so no placeholder is
 * a substring of another and a leak assertion can never pass by accident.
 */

import { actionMetadata as baseActionMetadata } from "./action-fixtures.js";

const UUID = "12345678-1234-4234-8123-123456789abc";
const UUID_B = "22345678-1234-4234-8123-123456789abc";

export const MUTATION = UUID;
export const ATTEMPT = UUID;
export const ATTEMPT_B = UUID_B;
export const ORG = `openarc:org:${UUID}`;
export const ORG_B = `openarc:org:${UUID_B}`;
export const ACCOUNT = `openarc:account:${UUID}`;
export const AGENT = `openarc:agent:${UUID}`;
export const POLICY = `openarc:policy:${UUID}`;
export const PROVIDER = `openarc:provider:${UUID}`;
export const LISTING = `openarc:listing:${UUID}`;
export const ACTION = `openarc:action:${UUID}`;
export const REQUIREMENT = `openarc:requirement:${UUID}`;
export const GRANT = `openarc:grant:${UUID}`;
export const SESSION_ID = UUID;
export const VERSION = "1";

/** The store's canonical microsecond UTC timestamps. */
export const STORED_AT = "2026-01-01T00:00:00.123456Z";
export const DISPATCHED_AT = "2026-01-01T00:00:01.123456Z";

export const PAYER = "0x1111111111111111111111111111111111111111";
export const PAY_TO = "0xabcdefabcdefabcdefabcdefabcdefabcdef2222";
export const PAY_TO_MIXED = "0xAbCdEfAbCdEfAbCdEfAbCdEfAbCdEfAbCdEf2222";
export const AMOUNT = "1000000";
export const REQUIREMENT_DIGEST = `sha256:${"a".repeat(64)}`;
export const LANE_DIGEST = `sha256:${"d".repeat(64)}`;
export const BINDING_DIGEST = `sha256:${"e".repeat(64)}`;
export const NONCE = `0x${"7".repeat(64)}`;
export const VALID_AFTER = "1767225000";
export const VALID_BEFORE = "1767830700";

export const IDEMPOTENCY = "A".repeat(43);
export const SESSION_TOKEN = `oacs_v1_${"C".repeat(42)}Q`;
export const PROVIDER_TOKEN = `oas_pr_${"D".repeat(42)}Q`;
/** The read-only machine credential. No payment family may accept it. */
export const MACHINE_AGENT_TOKEN = `oas_ag_${"E".repeat(42)}Q`;
export const GRANT_TOKEN = `oag_v1_${"F".repeat(42)}Y`;

export const BUILD_SHA = "0123456789abcdef0123456789abcdef01234567";
export const ORIGIN = "http://localhost:5183";
export const COOKIE = "openarc_session=abc";
export const CSRF = "csrf-token-value";

export function termsData(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    replayed: false,
    terms: {
      organizationId: ORG,
      listingId: LISTING,
      version: VERSION,
      payToAddress: PAY_TO,
      recordedAt: STORED_AT,
    },
    receipt: {
      mutationId: MUTATION,
      operation: "market.listing.payment_terms.record",
      resourceType: "listing_version",
      resourceId: `${LISTING}@${VERSION}`,
      committedAt: STORED_AT,
    },
    ...overrides,
  };
}

export function verifiedRequirement(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    organizationId: ORG,
    requirementId: REQUIREMENT,
    sellerOrganizationId: ORG_B,
    providerId: PROVIDER,
    listingId: LISTING,
    listingVersion: VERSION,
    networkId: "eip155:5042002",
    asset: "USDC",
    representation: "erc20",
    decimals: 6,
    amountAtomic: AMOUNT,
    feeAtomic: "0",
    payToAddress: PAY_TO,
    requirementDigest: REQUIREMENT_DIGEST,
    sourceKind: "verified_listing",
    createdAt: STORED_AT,
    validUntil: DISPATCHED_AT,
    ...overrides,
  };
}

export function attemptRecord(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    organizationId: ORG,
    attemptId: ATTEMPT,
    grantId: GRANT,
    actionId: ACTION,
    providerId: PROVIDER,
    listingId: LISTING,
    listingVersion: VERSION,
    requirementId: REQUIREMENT,
    requirementDigest: REQUIREMENT_DIGEST,
    networkId: "eip155:5042002",
    assetAddress: "0x3600000000000000000000000000000000000000",
    verifyingContract: "0x0077777d7EBA4688BDeF3E311b846F25870A19B9",
    payerAddress: PAYER,
    payToAddress: PAY_TO_MIXED,
    valueAtomic: AMOUNT,
    validAfter: VALID_AFTER,
    validBefore: VALID_BEFORE,
    nonce: NONCE,
    laneRequirementDigest: LANE_DIGEST,
    bindingDigest: BINDING_DIGEST,
    state: "persisted",
    persistedAt: STORED_AT,
    dispatchedAt: null,
    observedAt: null,
    transferId: null,
    gatewayStatus: null,
    batchTxHash: null,
    ...overrides,
  };
}

export function dispatchedAttempt(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return attemptRecord({ state: "unknown", dispatchedAt: DISPATCHED_AT, ...overrides });
}

export function persistBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    grantId: GRANT,
    actionId: ACTION,
    attemptId: ATTEMPT,
    laneRequirementDigest: LANE_DIGEST,
    from: PAYER,
    to: PAY_TO_MIXED,
    validAfter: VALID_AFTER,
    validBefore: VALID_BEFORE,
    nonce: NONCE,
    bindingDigest: BINDING_DIGEST,
    ...overrides,
  };
}

/** The buyer's authorized action: the ONLY source of value and digest. */
export function paymentActionMetadata(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return baseActionMetadata({
    requirementDigest: REQUIREMENT_DIGEST,
    amountAtomic: AMOUNT,
    feeAtomic: "0",
    debitAtomic: AMOUNT,
    ...overrides,
  });
}

export { commerceSessionMetadata } from "./action-fixtures.js";
