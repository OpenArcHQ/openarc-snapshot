import { describe, expect, it } from "vitest";

import {
  COMMERCE_GRANT_METADATA_SCHEMA_VERSION,
  COMMERCE_GRANT_MODEL_FIELD_CLASSES,
  COMMERCE_GRANT_PROVIDER_VIEW_SCHEMA_VERSION,
  CommerceGrantMetadataSchema,
  CommerceGrantProviderAttemptStatusSchema,
  CommerceGrantProviderViewSchema,
  CommerceGrantStatusSchema,
} from "../src/commerce/control-grant-model.js";
import {
  CommerceGrantMetadataSchema as INDEX_GRANT_METADATA,
  CommerceGrantProviderViewSchema as INDEX_PROVIDER_VIEW,
} from "../src/index.js";

const GRANT_ID = "openarc:grant:12345678-1234-4234-8123-123456789abc";
const ORG_ID = "openarc:org:99999999-9999-4999-8999-999999999999";
const AGENT_ID = "openarc:agent:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ACTION_ID = "openarc:action:11111111-1111-4111-8111-111111111111";
const RESERVATION_ID =
  "openarc:reservation:22222222-2222-4222-8222-222222222222";
const REQUIREMENT_ID =
  "openarc:requirement:44444444-4444-4444-8444-444444444444";
const SESSION_ID = "55555555-5555-4555-8555-555555555555";
const PROVIDER_ID =
  "openarc:provider:77777777-7777-4777-8777-777777777777";
const LISTING_ID = "openarc:listing:88888888-8888-4888-8888-888888888888";
const ATTEMPT_ID = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff";

const DIGEST = `sha256:${"a".repeat(64)}`;

const ISSUED_AT = "2025-01-01T00:00:00.000000001Z";
const UPDATED_AT = "2025-01-01T00:00:02Z";
const EXPIRES_AT = "2025-01-01T00:00:01Z";
const CLAIMED_AT = "2025-01-01T00:00:00.5Z";
const REVOKED_AT = "2025-01-01T00:00:00.75Z";

const MAX_UINT256 =
  "115792089237316195423570985008687907853269984665640564039457584007913129639935";
const MAX_SUM = (2n * ((1n << 256n) - 1n)).toString();

function grant(overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: COMMERCE_GRANT_METADATA_SCHEMA_VERSION,
    grantId: GRANT_ID,
    organizationId: ORG_ID,
    subjectAgentId: AGENT_ID,
    actionId: ACTION_ID,
    reservationId: RESERVATION_ID,
    commerceSessionId: SESSION_ID,
    providerId: PROVIDER_ID,
    listingId: LISTING_ID,
    listingVersion: "1",
    generation: "1",
    status: "issued",
    issuedAt: ISSUED_AT,
    updatedAt: UPDATED_AT,
    expiresAt: EXPIRES_AT,
    claimedAt: null,
    revokedAt: null,
    ...overrides,
  };
}

function providerView(overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: COMMERCE_GRANT_PROVIDER_VIEW_SCHEMA_VERSION,
    grantId: GRANT_ID,
    actionId: ACTION_ID,
    providerId: PROVIDER_ID,
    listingId: LISTING_ID,
    listingVersion: "1",
    requirementId: REQUIREMENT_ID,
    requirementDigest: DIGEST,
    networkId: "eip155:5042002",
    asset: "USDC",
    representation: "erc20",
    decimals: 6,
    amountAtomic: "100",
    feeAtomic: "1",
    debitAtomic: "101",
    expiresAt: EXPIRES_AT,
    status: "issued",
    claimedAttemptId: null,
    ...overrides,
  };
}

function claimedAttempt(overrides: Record<string, unknown> = {}) {
  return {
    status: "claimed",
    attemptId: ATTEMPT_ID,
    grantId: GRANT_ID,
    actionId: ACTION_ID,
    providerId: PROVIDER_ID,
    listingId: LISTING_ID,
    listingVersion: "1",
    claimedAt: CLAIMED_AT,
    grantRevoked: false,
    ...overrides,
  };
}

function expectNoThrow(value: unknown, schema: { safeParse: (v: unknown) => unknown }) {
  expect(() => schema.safeParse(value)).not.toThrow();
}

describe("grant model schema versions and index exports", () => {
  it("pins both schemaVersion literals", () => {
    expect(CommerceGrantMetadataSchema.safeParse(grant()).success).toBe(true);
    expect(providerView().schemaVersion).toBe(
      COMMERCE_GRANT_PROVIDER_VIEW_SCHEMA_VERSION,
    );
    for (const bad of [
      { ...grant(), schemaVersion: COMMERCE_GRANT_PROVIDER_VIEW_SCHEMA_VERSION },
      { ...grant(), schemaVersion: "openarc.control.grant.v2" },
      { ...providerView(), schemaVersion: COMMERCE_GRANT_METADATA_SCHEMA_VERSION },
      { ...providerView(), schemaVersion: "openarc.control.grant-provider.v2" },
    ]) {
      const schema = "generation" in bad
        ? CommerceGrantMetadataSchema
        : CommerceGrantProviderViewSchema;
      expect(schema.safeParse(bad).success).toBe(false);
    }
  });

  it("exposes the same schemas from the module and the index barrel", () => {
    expect(INDEX_GRANT_METADATA).toBe(CommerceGrantMetadataSchema);
    expect(INDEX_PROVIDER_VIEW).toBe(CommerceGrantProviderViewSchema);
  });
});

describe("CommerceGrantMetadataSchema strictness", () => {
  it("rejects unknown top-level fields and missing keys", () => {
    expect(
      CommerceGrantMetadataSchema.safeParse({ ...grant(), extra: 1 }).success,
    ).toBe(false);
    const withoutGeneration: Record<string, unknown> = { ...grant() };
    delete withoutGeneration.generation;
    expect(
      CommerceGrantMetadataSchema.safeParse(withoutGeneration).success,
    ).toBe(false);
  });

  it("rejects seller/hash/token/policy/receipt fields outright", () => {
    for (const key of [
      "sellerOrganizationId",
      "sellerOrg",
      "hash",
      "rawGrantToken",
      "grantToken",
      "parentAccount",
      "policyId",
      "content",
      "receipt",
      "amountAtomic",
      "networkId",
    ]) {
      expect(
        CommerceGrantMetadataSchema.safeParse({ ...grant(), [key]: 1 })
          .success,
      ).toBe(false);
    }
  });

  it("never throws on malformed input", () => {
    for (const bad of [null, undefined, {}, [], 42, "x", { status: "issued" }]) {
      expectNoThrow(bad, CommerceGrantMetadataSchema);
      expect(CommerceGrantMetadataSchema.safeParse(bad).success).toBe(false);
    }
  });
});

describe("grant id and cross-namespace leaves", () => {
  it("accepts only openarc:grant: UUIDv4 and rejects namespace crossings", () => {
    for (const bad of [
      ACTION_ID,
      RESERVATION_ID,
      SESSION_ID,
      ORG_ID,
      AGENT_ID,
      `openarc:grant:${GRANT_ID.slice("openarc:grant:".length).toUpperCase()}`,
      `${GRANT_ID}\n`,
      `${GRANT_ID} `,
    ]) {
      expect(
        CommerceGrantMetadataSchema.safeParse(grant({ grantId: bad })).success,
      ).toBe(false);
    }
  });

  it("rejects trailing newline on requirementDigest in the provider view", () => {
    expect(
      CommerceGrantProviderViewSchema.safeParse(
        providerView({ requirementDigest: `${DIGEST}\n` }),
      ).success,
    ).toBe(false);
    expect(
      CommerceGrantProviderViewSchema.safeParse(
        providerView({ requirementDigest: `sha256:${"A".repeat(64)}` }),
      ).success,
    ).toBe(false);
  });
});

describe("generation canonical range", () => {
  it("accepts 1 and 2147483647, rejects 0, over-range and trailing LF", () => {
    expect(
      CommerceGrantMetadataSchema.safeParse(grant({ generation: "1" })).success,
    ).toBe(true);
    expect(
      CommerceGrantMetadataSchema.safeParse(
        grant({ generation: "2147483647" }),
      ).success,
    ).toBe(true);
    for (const generation of ["0", "2147483648", "1\n", "01", "1.0", "10000000000"]) {
      expect(
        CommerceGrantMetadataSchema.safeParse(grant({ generation })).success,
      ).toBe(false);
    }
  });
});

describe("exact timestamp relationships and 300s boundary", () => {
  it("requires updatedAt >= issuedAt and expiresAt > issuedAt", () => {
    expect(
      CommerceGrantMetadataSchema.safeParse(
        grant({ updatedAt: "2024-12-31T23:59:59.999999999Z" }),
      ).success,
    ).toBe(false);
    expect(
      CommerceGrantMetadataSchema.safeParse(
        grant({ expiresAt: ISSUED_AT }),
      ).success,
    ).toBe(false);
  });

  it("accepts exactly the 300s boundary with preserved fractions", () => {
    expect(
      CommerceGrantMetadataSchema.safeParse(
        grant({ expiresAt: "2025-01-01T00:05:00.000000001Z" }),
      ).success,
    ).toBe(true);
    expect(
      CommerceGrantMetadataSchema.safeParse(
        grant({ expiresAt: "2025-01-01T00:05:00.000000000Z" }),
      ).success,
    ).toBe(true);
  });

  it("rejects one nanosecond beyond the 300s boundary", () => {
    expect(
      CommerceGrantMetadataSchema.safeParse(
        grant({ expiresAt: "2025-01-01T00:05:00.000000002Z" }),
      ).success,
    ).toBe(false);
  });

  it("preserves submillisecond fractions at a whole-second boundary", () => {
    expect(
      CommerceGrantMetadataSchema.safeParse(
        grant({
          issuedAt: "2025-01-01T00:00:00.9Z",
          updatedAt: "2025-01-01T00:00:00.95Z",
          expiresAt: "2025-01-01T00:05:00.9Z",
        }),
      ).success,
    ).toBe(true);
    expect(
      CommerceGrantMetadataSchema.safeParse(
        grant({
          issuedAt: "2025-01-01T00:00:00.9Z",
          updatedAt: "2025-01-01T00:00:00.95Z",
          expiresAt: "2025-01-01T00:05:00.900000001Z",
        }),
      ).success,
    ).toBe(false);
  });

  it("rejects malformed timestamps without throwing", () => {
    for (const bad of [
      grant({ issuedAt: "not-a-timestamp" }),
      grant({ issuedAt: "2025-01-01T00:00:00+00:00" }),
      grant({ issuedAt: "2025-01-01T00:00:00.0000000000Z" }),
      grant({ expiresAt: "2025-01-01T00:00:00.0000000001Z" }),
      grant({ status: "claimed", claimedAt: "nope" }),
      grant({ status: "revoked", revokedAt: "nope" }),
    ]) {
      expectNoThrow(bad, CommerceGrantMetadataSchema);
      expect(CommerceGrantMetadataSchema.safeParse(bad).success).toBe(false);
    }
    expectNoThrow(grant({ issuedAt: "nope" }), CommerceGrantMetadataSchema);
  });
});

describe("status and nullable combinations", () => {
  const combinations: ReadonlyArray<{
    status: "issued" | "claimed" | "revoked" | "expired";
    claimedAt: string | null;
    revokedAt: string | null;
    valid: boolean;
  }> = [
    { status: "issued", claimedAt: null, revokedAt: null, valid: true },
    { status: "issued", claimedAt: CLAIMED_AT, revokedAt: null, valid: false },
    { status: "issued", claimedAt: null, revokedAt: REVOKED_AT, valid: false },
    { status: "expired", claimedAt: null, revokedAt: null, valid: true },
    { status: "expired", claimedAt: CLAIMED_AT, revokedAt: null, valid: false },
    { status: "expired", claimedAt: null, revokedAt: REVOKED_AT, valid: false },
    { status: "claimed", claimedAt: CLAIMED_AT, revokedAt: null, valid: true },
    { status: "claimed", claimedAt: null, revokedAt: null, valid: false },
    { status: "claimed", claimedAt: CLAIMED_AT, revokedAt: REVOKED_AT, valid: false },
    { status: "revoked", claimedAt: null, revokedAt: REVOKED_AT, valid: true },
    { status: "revoked", claimedAt: CLAIMED_AT, revokedAt: REVOKED_AT, valid: true },
    { status: "revoked", claimedAt: null, revokedAt: null, valid: false },
  ];

  it("honours every enum/nullable combination", () => {
    for (const entry of combinations) {
      const value = grant({
        status: entry.status,
        claimedAt: entry.claimedAt,
        revokedAt: entry.revokedAt,
      });
      expect(
        CommerceGrantMetadataSchema.safeParse(value).success,
        `${entry.status}/${entry.claimedAt}/${entry.revokedAt}`,
      ).toBe(entry.valid);
    }
  });

  it("keeps a prior claim visible when the grant is later revoked", () => {
    const value = grant({
      status: "revoked",
      claimedAt: CLAIMED_AT,
      revokedAt: REVOKED_AT,
    });
    const parsed = CommerceGrantMetadataSchema.safeParse(value);
    expect(parsed.success).toBe(true);
    if (parsed.success) expect(parsed.data.claimedAt).toBe(CLAIMED_AT);
  });

  it("allows revocation after expiry", () => {
    const value = grant({
      status: "revoked",
      updatedAt: "2025-01-01T00:06:00Z",
      revokedAt: "2025-01-01T00:05:30Z",
    });
    expect(CommerceGrantMetadataSchema.safeParse(value).success).toBe(true);
  });

  it("rejects claimedAt/revokedAt ordering violations", () => {
    expect(
      CommerceGrantMetadataSchema.safeParse(
        grant({
          status: "claimed",
          claimedAt: "2025-01-01T00:00:00Z",
          updatedAt: "2025-01-01T00:00:00Z",
        }),
      ).success,
    ).toBe(false);
    expect(
      CommerceGrantMetadataSchema.safeParse(
        grant({
          status: "revoked",
          claimedAt: CLAIMED_AT,
          revokedAt: "2025-01-01T00:00:00.25Z",
        }),
      ).success,
    ).toBe(false);
  });

  it("is exactly the four grant statuses", () => {
    expect(CommerceGrantStatusSchema.options).toEqual([
      "issued",
      "claimed",
      "revoked",
      "expired",
    ]);
  });
});

describe("CommerceGrantProviderViewSchema strictness", () => {
  it("rejects every buyer-private and secret key", () => {
    for (const key of [
      "organizationId",
      "subjectAgentId",
      "commerceSessionId",
      "policyId",
      "policyRevision",
      "reservationId",
      "approvalId",
      "exposureKey",
      "createdAt",
      "updatedAt",
      "generation",
      "balance",
      "allowlists",
      "rawGrantToken",
      "grantToken",
      "hash",
      "signature",
      "paymentMaterial",
    ]) {
      expect(
        CommerceGrantProviderViewSchema.safeParse({
          ...providerView(),
          [key]: "x",
        }).success,
      ).toBe(false);
    }
  });

  it("pins network/asset/representation/decimals constants", () => {
    for (const bad of [
      { networkId: "eip155:1" },
      { asset: "ETH" },
      { representation: "native" },
      { decimals: 18 },
    ]) {
      expect(
        CommerceGrantProviderViewSchema.safeParse({
          ...providerView(),
          ...bad,
        }).success,
      ).toBe(false);
    }
  });

  it("enforces claimedAttemptId per status and never throws", () => {
    for (const bad of [null, {}, 5, "x"]) {
      expectNoThrow(bad, CommerceGrantProviderViewSchema);
      expect(CommerceGrantProviderViewSchema.safeParse(bad).success).toBe(false);
    }
    expect(
      CommerceGrantProviderViewSchema.safeParse(providerView()).success,
    ).toBe(true);
    expect(
      CommerceGrantProviderViewSchema.safeParse(
        providerView({ status: "expired" }),
      ).success,
    ).toBe(true);
    // claimed requires a non-null attempt id; issued/expired forbid one.
    expect(
      CommerceGrantProviderViewSchema.safeParse(
        providerView({ status: "claimed" }),
      ).success,
    ).toBe(false);
    expect(
      CommerceGrantProviderViewSchema.safeParse(
        providerView({ status: "issued", claimedAttemptId: ATTEMPT_ID }),
      ).success,
    ).toBe(false);
    // revoked may preserve history in either direction.
    expect(
      CommerceGrantProviderViewSchema.safeParse(
        providerView({ status: "revoked", claimedAttemptId: ATTEMPT_ID }),
      ).success,
    ).toBe(true);
    expect(
      CommerceGrantProviderViewSchema.safeParse(
        providerView({ status: "revoked", claimedAttemptId: null }),
      ).success,
    ).toBe(true);
  });
});

describe("provider money bounds", () => {
  it("accepts max uint256 with zero fee and rejects an over-range fee", () => {
    expect(
      CommerceGrantProviderViewSchema.safeParse(
        providerView({
          amountAtomic: MAX_UINT256,
          feeAtomic: "0",
          debitAtomic: MAX_UINT256,
        }),
      ).success,
    ).toBe(true);
    expect(
      CommerceGrantProviderViewSchema.safeParse(
        providerView({
          amountAtomic: "1",
          feeAtomic: (1n << 256n).toString(),
          debitAtomic: "2",
        }),
      ).success,
    ).toBe(false);
  });

  it("accepts the exact two-component max sum and rejects mismatch", () => {
    expect(MAX_SUM).toHaveLength(78);
    expect(
      CommerceGrantProviderViewSchema.safeParse(
        providerView({
          amountAtomic: MAX_UINT256,
          feeAtomic: MAX_UINT256,
          debitAtomic: MAX_SUM,
        }),
      ).success,
    ).toBe(true);
    expect(
      CommerceGrantProviderViewSchema.safeParse(
        providerView({
          amountAtomic: MAX_UINT256,
          feeAtomic: MAX_UINT256,
          debitAtomic: `${MAX_SUM}0`,
        }),
      ).success,
    ).toBe(false);
  });

  it("bounds debit to a canonical positive decimal up to 128 digits", () => {
    // 79-digit syntactically-valid debit still fails the crosssum bound.
    expect(
      CommerceGrantProviderViewSchema.safeParse(
        providerView({ debitAtomic: `1${"0".repeat(78)}` }),
      ).success,
    ).toBe(false);
    // 129 digits are not a canonical debit at all.
    expect(
      CommerceGrantProviderViewSchema.safeParse(
        providerView({ debitAtomic: "9".repeat(129) }),
      ).success,
    ).toBe(false);
    for (const debitAtomic of ["0", "01", "1.0", " 1", "1\n"]) {
      expect(
        CommerceGrantProviderViewSchema.safeParse(
          providerView({ debitAtomic }),
        ).success,
      ).toBe(false);
    }
  });
});

describe("CommerceGrantProviderAttemptStatusSchema", () => {
  it("accepts not_found with ONLY status", () => {
    expect(
      CommerceGrantProviderAttemptStatusSchema.safeParse({
        status: "not_found",
      }).success,
    ).toBe(true);
    for (const extra of [
      { status: "not_found", attemptId: ATTEMPT_ID },
      { status: "not_found", grantId: GRANT_ID },
      { status: "not_found", claimedAt: CLAIMED_AT },
      { status: "not_found", generation: "1" },
    ]) {
      expect(
        CommerceGrantProviderAttemptStatusSchema.safeParse(extra).success,
      ).toBe(false);
    }
  });

  it("accepts the claimed recovery projection without generation/token", () => {
    expect(
      CommerceGrantProviderAttemptStatusSchema.safeParse(claimedAttempt())
        .success,
    ).toBe(true);
    for (const key of ["generation", "grantToken", "organizationId", "signature"]) {
      expect(
        CommerceGrantProviderAttemptStatusSchema.safeParse({
          ...claimedAttempt(),
          [key]: "x",
        }).success,
      ).toBe(false);
    }
  });

  it("rejects malformed attempt ids and timestamps without throwing", () => {
    for (const bad of [
      claimedAttempt({ attemptId: `${ATTEMPT_ID}\n` }),
      claimedAttempt({ attemptId: "not-a-uuid" }),
      claimedAttempt({ claimedAt: "nope" }),
      claimedAttempt({ grantRevoked: "yes" }),
    ]) {
      expectNoThrow(bad, CommerceGrantProviderAttemptStatusSchema);
      expect(
        CommerceGrantProviderAttemptStatusSchema.safeParse(bad).success,
      ).toBe(false);
    }
    expectNoThrow({}, CommerceGrantProviderAttemptStatusSchema);
  });
});

describe("COMMERCE_GRANT_MODEL_FIELD_CLASSES", () => {
  it("is deeply frozen with the exact class mapping", () => {
    expect(Object.isFrozen(COMMERCE_GRANT_MODEL_FIELD_CLASSES)).toBe(true);
    for (const entry of Object.values(COMMERCE_GRANT_MODEL_FIELD_CLASSES)) {
      expect(Object.isFrozen(entry)).toBe(true);
      expect(Object.isFrozen(entry.fields)).toBe(true);
      expect(entry.dataClass).toBe("organization_protected");
      expect(
        Object.values(entry.fields).every(
          (value) => value === "organization_protected",
        ),
      ).toBe(true);
    }
    expect(COMMERCE_GRANT_MODEL_FIELD_CLASSES.grantMetadata.audience).toBe(
      "organization",
    );
    expect(COMMERCE_GRANT_MODEL_FIELD_CLASSES.providerView.audience).toBe(
      "provider_minimal",
    );
    expect(
      COMMERCE_GRANT_MODEL_FIELD_CLASSES.providerAttemptStatus.audience,
    ).toBe("provider_minimal");
  });

  it("maps exactly the declared schema fields", () => {
    const metadataKeys = Object.keys(CommerceGrantMetadataSchema.shape).sort();
    expect(
      Object.keys(COMMERCE_GRANT_MODEL_FIELD_CLASSES.grantMetadata.fields).sort(),
    ).toEqual(metadataKeys);

    const providerKeys = Object.keys(
      CommerceGrantProviderViewSchema.shape,
    ).sort();
    expect(
      Object.keys(COMMERCE_GRANT_MODEL_FIELD_CLASSES.providerView.fields).sort(),
    ).toEqual(providerKeys);

    const claimedShape =
      CommerceGrantProviderAttemptStatusSchema.options[1]!.shape;
    expect(
      Object.keys(
        COMMERCE_GRANT_MODEL_FIELD_CLASSES.providerAttemptStatus.fields,
      ).sort(),
    ).toEqual(Object.keys(claimedShape).sort());
  });
});
