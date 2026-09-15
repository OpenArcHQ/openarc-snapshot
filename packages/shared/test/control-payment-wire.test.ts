import { describe, expect, it } from "vitest";

import {
  CommercePaymentAttemptDispatchBodySchema,
  CommercePaymentAttemptDispatchDataSchema,
  CommercePaymentAttemptPersistBodySchema,
  CommercePaymentAttemptPersistDataSchema,
  CommercePaymentAttemptReadDataSchema,
  CommercePaymentAttemptReadRequestSchema,
  CommercePaymentAttemptSchema,
  CommercePaymentRequirementBodySchema,
  CommercePaymentTermsBodySchema,
  CommercePaymentTermsDataSchema,
  CommercePaymentVerifiedRequirementSchema,
} from "../src/commerce/control-payment-wire.js";

const UUID = "12345678-1234-4234-8123-123456789abc";
const ORG = `openarc:org:${UUID}`;
const LISTING = `openarc:listing:${UUID}`;
const AT = "2026-01-01T00:00:00.123456Z";
const DIGEST = `sha256:${"a".repeat(64)}`;
const PAYER = "0x1111111111111111111111111111111111111111";
const PAY_TO = "0xAbCdEfAbCdEfAbCdEfAbCdEfAbCdEfAbCdEf2222";

function persistBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    grantId: `openarc:grant:${UUID}`,
    actionId: `openarc:action:${UUID}`,
    attemptId: UUID,
    laneRequirementDigest: DIGEST,
    from: PAYER,
    to: PAY_TO,
    validAfter: "1000",
    validBefore: "700000",
    nonce: `0x${"7".repeat(64)}`,
    bindingDigest: DIGEST,
    ...overrides,
  };
}

function attempt(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    organizationId: ORG,
    attemptId: UUID,
    grantId: `openarc:grant:${UUID}`,
    actionId: `openarc:action:${UUID}`,
    providerId: `openarc:provider:${UUID}`,
    listingId: LISTING,
    listingVersion: "1",
    requirementId: `openarc:requirement:${UUID}`,
    requirementDigest: DIGEST,
    networkId: "eip155:5042002",
    assetAddress: "0x3600000000000000000000000000000000000000",
    verifyingContract: "0x0077777d7EBA4688BDeF3E311b846F25870A19B9",
    payerAddress: PAYER,
    payToAddress: PAY_TO,
    valueAtomic: "1000000",
    validAfter: "1000",
    validBefore: "700000",
    nonce: `0x${"7".repeat(64)}`,
    laneRequirementDigest: DIGEST,
    bindingDigest: DIGEST,
    state: "persisted",
    persistedAt: AT,
    dispatchedAt: null,
    observedAt: null,
    transferId: null,
    gatewayStatus: null,
    batchTxHash: null,
    ...overrides,
  };
}

function shapeKeys(schema: unknown): string[] {
  return Object.keys((schema as { shape: Record<string, unknown> }).shape);
}

describe("payment wire bodies are closed and server-derived", () => {
  it("accepts only the lane-chosen persist fields", () => {
    expect(CommercePaymentAttemptPersistBodySchema.safeParse(persistBody()).success).toBe(true);
    for (const extra of ["value", "amountAtomic", "network", "asset", "verifyingContract", "sourceKind", "schemaVersion", "role", "grantRequirementDigest", "signature", "decimals"]) {
      expect([extra, CommercePaymentAttemptPersistBodySchema.safeParse(persistBody({ [extra]: "x" })).success]).toEqual([extra, false]);
    }
  });

  it("rejects non-canonical persist values", () => {
    for (const overrides of [
      { to: PAYER },
      { from: "0x0000000000000000000000000000000000000000" },
      { validBefore: "1000" },
      { validAfter: "01" },
      { nonce: `0x${"0".repeat(64)}` },
      { nonce: `0x${"A".repeat(64)}` },
      { attemptId: "12345678-1234-1234-8123-123456789abc" },
      { bindingDigest: `sha256:${"A".repeat(64)}` },
      { bindingDigest: `${DIGEST}\n` },
    ]) {
      expect(CommercePaymentAttemptPersistBodySchema.safeParse(persistBody(overrides)).success).toBe(false);
    }
  });

  it("closes the requirement, terms and dispatch bodies and the read request", () => {
    expect(CommercePaymentRequirementBodySchema.safeParse({ requirementId: `openarc:requirement:${UUID}`, listingId: LISTING }).success).toBe(true);
    expect(CommercePaymentRequirementBodySchema.safeParse({ requirementId: `openarc:requirement:${UUID}`, listingId: LISTING, sourceKind: "internal_fixture" }).success).toBe(false);
    expect(CommercePaymentRequirementBodySchema.safeParse({ requirementId: `openarc:requirement:${UUID}`, listingId: LISTING, amountAtomic: "1" }).success).toBe(false);
    expect(CommercePaymentTermsBodySchema.safeParse({ mutationId: UUID, payToAddress: PAY_TO }).success).toBe(true);
    expect(CommercePaymentTermsBodySchema.safeParse({ mutationId: UUID, payToAddress: PAY_TO, amountAtomic: "1" }).success).toBe(false);
    expect(CommercePaymentTermsBodySchema.safeParse({ mutationId: UUID, payToAddress: "0x0000000000000000000000000000000000000000" }).success).toBe(false);
    expect(CommercePaymentAttemptDispatchBodySchema.safeParse({ bindingDigest: DIGEST }).success).toBe(true);
    expect(CommercePaymentAttemptDispatchBodySchema.safeParse({ bindingDigest: DIGEST, attemptId: UUID }).success).toBe(false);
    expect(CommercePaymentAttemptReadRequestSchema.safeParse({ attemptId: UUID }).success).toBe(true);
    expect(CommercePaymentAttemptReadRequestSchema.safeParse({ attemptId: UUID, extra: 1 }).success).toBe(false);
    expect(CommercePaymentAttemptReadRequestSchema.safeParse({ attemptId: UUID, extra: undefined }).success).toBe(false);
  });

  it("represents no secret-bearing key in any body or projection", () => {
    for (const schema of [
      CommercePaymentAttemptPersistBodySchema,
      CommercePaymentRequirementBodySchema,
      CommercePaymentTermsBodySchema,
      CommercePaymentAttemptDispatchBodySchema,
      CommercePaymentAttemptSchema,
      CommercePaymentVerifiedRequirementSchema,
    ]) {
      for (const key of shapeKeys(schema)) {
        expect(key).not.toMatch(/signature|secret|token|private|password|authorization/iu);
      }
    }
  });
});

describe("payment wire projections", () => {
  it("admits only the closed attempt state shapes and no release state", () => {
    expect(CommercePaymentAttemptSchema.safeParse(attempt()).success).toBe(true);
    expect(CommercePaymentAttemptSchema.safeParse(attempt({ state: "unknown", dispatchedAt: AT })).success).toBe(true);
    expect(CommercePaymentAttemptSchema.safeParse(attempt({ state: "unknown" })).success).toBe(false);
    expect(CommercePaymentAttemptSchema.safeParse(attempt({ state: "committed", dispatchedAt: AT, transferId: UUID, gatewayStatus: "completed" })).success).toBe(false);
    expect(CommercePaymentAttemptSchema.safeParse(attempt({ state: "committed", dispatchedAt: AT, transferId: UUID, gatewayStatus: "completed", batchTxHash: `0x${"b".repeat(64)}` })).success).toBe(true);
    for (const state of ["released", "failed", "refunded", "cancelled"]) {
      expect(CommercePaymentAttemptSchema.safeParse(attempt({ state })).success).toBe(false);
    }
    expect(CommercePaymentAttemptSchema.safeParse(attempt({ networkId: "eip155:1" })).success).toBe(false);
  });

  it("requires a first persist to be persisted and a dispatch to be unknown", () => {
    expect(CommercePaymentAttemptPersistDataSchema.safeParse({ replayed: false, attempt: attempt() }).success).toBe(true);
    expect(CommercePaymentAttemptPersistDataSchema.safeParse({ replayed: false, attempt: attempt({ state: "unknown", dispatchedAt: AT }) }).success).toBe(false);
    expect(CommercePaymentAttemptPersistDataSchema.safeParse({ replayed: true, attempt: attempt({ state: "unknown", dispatchedAt: AT }) }).success).toBe(true);
    expect(CommercePaymentAttemptDispatchDataSchema.safeParse({ attempt: attempt({ state: "unknown", dispatchedAt: AT }) }).success).toBe(true);
    expect(CommercePaymentAttemptDispatchDataSchema.safeParse({ attempt: attempt() }).success).toBe(false);
    expect(CommercePaymentAttemptReadDataSchema.safeParse({ attemptId: UUID, item: null }).success).toBe(true);
    expect(CommercePaymentAttemptReadDataSchema.safeParse({ attemptId: "22345678-1234-4234-8123-123456789abc", item: attempt() }).success).toBe(false);
  });

  it("binds the terms receipt to the recorded version and refuses fixture provenance", () => {
    const terms = { organizationId: ORG, listingId: LISTING, version: "1", payToAddress: PAY_TO.toLowerCase(), recordedAt: AT };
    const receipt = { mutationId: UUID, operation: "market.listing.payment_terms.record", resourceType: "listing_version", resourceId: `${LISTING}@1`, committedAt: AT };
    expect(CommercePaymentTermsDataSchema.safeParse({ replayed: false, terms, receipt }).success).toBe(true);
    expect(CommercePaymentTermsDataSchema.safeParse({ replayed: false, terms, receipt: { ...receipt, resourceId: `${LISTING}@2` } }).success).toBe(false);
    expect(CommercePaymentTermsDataSchema.safeParse({ replayed: false, terms: { ...terms, payToAddress: PAY_TO }, receipt }).success).toBe(false);
    const requirement = {
      organizationId: ORG, requirementId: `openarc:requirement:${UUID}`, sellerOrganizationId: ORG,
      providerId: `openarc:provider:${UUID}`, listingId: LISTING, listingVersion: "1", networkId: "eip155:5042002",
      asset: "USDC", representation: "erc20", decimals: 6, amountAtomic: "1000000", feeAtomic: "0",
      payToAddress: PAY_TO.toLowerCase(), requirementDigest: DIGEST, sourceKind: "verified_listing", createdAt: AT, validUntil: AT,
    };
    expect(CommercePaymentVerifiedRequirementSchema.safeParse(requirement).success).toBe(true);
    expect(CommercePaymentVerifiedRequirementSchema.safeParse({ ...requirement, sourceKind: "internal_fixture" }).success).toBe(false);
    expect(CommercePaymentVerifiedRequirementSchema.safeParse({ ...requirement, feeAtomic: "1" }).success).toBe(false);
  });
});
