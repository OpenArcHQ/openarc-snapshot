import { describe, expect, expectTypeOf, it } from "vitest";

import {
  COMMERCE_GRANT_MAX_LIFETIME_SECONDS,
  COMMERCE_GRANT_RESOURCE_TYPE,
  COMMERCE_GRANT_WIRE_FIELD_CLASSES,
  CommerceGrantAgentMutationRequestSchema,
  CommerceGrantAgentMutationStatusResponseSchema,
  CommerceGrantAgentMutationStatusSchema,
  CommerceGrantAgentReceiptSchema,
  CommerceGrantAttemptIdSchema,
  CommerceGrantClaimDigestSchema,
  CommerceGrantClaimReceiptSchema,
  CommerceGrantDetailRequestSchema,
  CommerceGrantDetailResponseSchema,
  CommerceGrantDetailSchema,
  CommerceGrantHumanMutationRequestSchema,
  CommerceGrantHumanMutationStatusSchema,
  CommerceGrantIssueBodySchema,
  CommerceGrantIssueDataResponseSchema,
  CommerceGrantIssueDataSchema,
  CommerceGrantIssueReceiptSchema,
  CommerceGrantMutationOutcomeSchema,
  CommerceGrantMutationReceiptSchema,
  CommerceGrantProviderAttemptStatusDataSchema,
  CommerceGrantProviderAttemptStatusRequestSchema,
  CommerceGrantProviderClaimBodySchema,
  CommerceGrantProviderClaimDataSchema,
  CommerceGrantProviderIntrospectBodySchema,
  CommerceGrantProviderIntrospectionSchema,
  CommerceGrantReplaceBodySchema,
  CommerceGrantReplaceDataSchema,
  CommerceGrantReplaceReceiptSchema,
  CommerceGrantReplacementContinuitySchema,
  CommerceGrantRevokeBodySchema,
  CommerceGrantRevokeDataSchema,
  CommerceGrantRevokeReceiptSchema,
  type CommerceGrantIssueData,
  type CommerceGrantMutationOutcome,
} from "../src/commerce/control-grant-wire.js";
import {
  CommerceGrantDetailSchema as INDEX_GRANT_DETAIL,
  CommerceGrantIssueDataSchema as INDEX_ISSUE_DATA,
  CommerceGrantMutationOutcomeSchema as INDEX_OUTCOME,
} from "../src/index.js";

const V4 = "12345678-1234-4234-8123-123456789abc";
const V4_B = "87654321-4321-4321-b321-cba987654321";

const GRANT_ID = `openarc:grant:${V4}`;
const GRANT_ID_B = `openarc:grant:${V4_B}`;
const ORG = "openarc:org:99999999-9999-4999-8999-999999999999";
const ORG_B = "openarc:org:11111111-1111-4111-8111-111111111111";
const AGENT = "openarc:agent:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ACTION_ID = "openarc:action:11111111-1111-4111-8111-111111111111";
const ACTION_ID_B = "openarc:action:22222222-2222-4222-9222-222222222222";
const RESERVATION_ID =
  "openarc:reservation:22222222-2222-4222-8222-222222222222";
const REQUIREMENT_ID =
  "openarc:requirement:44444444-4444-4444-8444-444444444444";
const SESSION_ID = "55555555-5555-4555-8555-555555555555";
const PROVIDER_ID = "openarc:provider:77777777-7777-4777-8777-777777777777";
const LISTING_ID = "openarc:listing:88888888-8888-4888-8888-888888888888";
const ATTEMPT_ID = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff";
const ATTEMPT_ID_B = "cccccccc-dddd-4eee-9fff-aaaaaaaaaaaa";
const MUTATION = V4;
const MUTATION_B = V4_B;

const GRANT_TOKEN = `oag_v1_${"A".repeat(42)}A`;
const GRANT_TOKEN_B = `oag_v1_${"B".repeat(42)}A`;
const COMMERCE_SESSION_TOKEN = `oacs_v1_${"A".repeat(42)}A`;
const PROVIDER_SESSION_TOKEN = `oas_pr_${"A".repeat(42)}A`;

const DIGEST = `sha256:${"a".repeat(64)}`;

const ISSUED_AT = "2025-01-01T00:00:00Z";
const CLAIMED_AT = "2025-01-01T00:01:00Z";
const REVOKED_AT = "2025-01-01T00:02:00Z";
const EXPIRES_AT = "2025-01-01T00:05:00Z"; // exactly issuedAt + 300s
const EXPIRES_OVER = "2025-01-01T00:05:01Z"; // issuedAt + 301s
const EXPIRES_EARLIER = "2025-01-01T00:04:00Z";

const META = {
  schemaVersion: "openarc.api.v2" as const,
  requestId: "9f1c2d34-5e6a-4b7c-8d9e-0f1a2b3c4d5e",
  buildSha: "0123456789abcdef0123456789abcdef01234567",
};

const MAX_UINT256 =
  "115792089237316195423570985008687907853269984665640564039457584007913129639935";
const OVER_UINT256 =
  "115792089237316195423570985008687907853269984665640564039457584007913129639936";

function grant(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: "openarc.control.grant.v1",
    grantId: GRANT_ID,
    organizationId: ORG,
    subjectAgentId: AGENT,
    actionId: ACTION_ID,
    reservationId: RESERVATION_ID,
    commerceSessionId: SESSION_ID,
    providerId: PROVIDER_ID,
    listingId: LISTING_ID,
    listingVersion: "1",
    generation: "1",
    status: "issued",
    issuedAt: ISSUED_AT,
    updatedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
    claimedAt: null,
    revokedAt: null,
    ...overrides,
  };
}

function claimedGrant(overrides: Record<string, unknown> = {}) {
  return grant({
    status: "claimed",
    claimedAt: CLAIMED_AT,
    updatedAt: CLAIMED_AT,
    ...overrides,
  });
}

function revokedAfterClaimGrant(overrides: Record<string, unknown> = {}) {
  return grant({
    status: "revoked",
    claimedAt: CLAIMED_AT,
    revokedAt: REVOKED_AT,
    updatedAt: REVOKED_AT,
    ...overrides,
  });
}

function revokedNeverClaimedGrant(overrides: Record<string, unknown> = {}) {
  return grant({
    status: "revoked",
    claimedAt: null,
    revokedAt: REVOKED_AT,
    updatedAt: REVOKED_AT,
    ...overrides,
  });
}

function providerView(overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: "openarc.control.grant-provider.v1",
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
    feeAtomic: "5",
    debitAtomic: "105",
    expiresAt: EXPIRES_AT,
    status: "issued",
    claimedAttemptId: null,
    ...overrides,
  };
}

function claimedProviderView(overrides: Record<string, unknown> = {}) {
  return providerView({
    status: "claimed",
    claimedAttemptId: ATTEMPT_ID,
    ...overrides,
  });
}

function receipt(
  operation: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    mutationId: MUTATION,
    operation,
    resourceType: "authorization_grant",
    resourceId: GRANT_ID,
    committedAt: ISSUED_AT,
    ...overrides,
  };
}

function issueData(overrides: Record<string, unknown> = {}) {
  return {
    replayed: false,
    metadata: grant(),
    receipt: receipt("control.grant.issue"),
    grantToken: GRANT_TOKEN,
    ...overrides,
  };
}

function replaceData(overrides: Record<string, unknown> = {}) {
  return {
    replayed: false,
    metadata: grant({ generation: "2" }),
    receipt: receipt("control.grant.replace"),
    grantToken: GRANT_TOKEN_B,
    ...overrides,
  };
}

function revokeData(overrides: Record<string, unknown> = {}) {
  return {
    replayed: false,
    metadata: revokedNeverClaimedGrant(),
    receipt: receipt("control.grant.revoke", { committedAt: REVOKED_AT }),
    released: true,
    actionStatus: "cancelled",
    ...overrides,
  };
}

function claimData(overrides: Record<string, unknown> = {}) {
  return {
    replayed: false,
    item: claimedProviderView(),
    attemptId: ATTEMPT_ID,
    claimedAt: CLAIMED_AT,
    claimDigest: DIGEST,
    receipt: receipt("control.grant.claim", { committedAt: CLAIMED_AT }),
    ...overrides,
  };
}

/** Every string leaf that must reject a trailing newline and a suffix. */
const SUFFIXES = ["\n", "\r\n", "\r", "\t", " ", "x"] as const;

/** Own-property `__proto__`, which an object literal cannot express. */
function withOwnProto(
  base: Record<string, unknown>,
): Record<string, unknown> {
  const merged = JSON.parse('{"__proto__":1}') as Record<string, unknown>;
  for (const [key, value] of Object.entries(base)) {
    merged[key] = value;
  }
  return merged;
}

/** Declared keys of a strict object schema, sorted; checks are transparent. */
function declaredKeys(schema: unknown): string[] {
  const shape = (schema as { shape?: Record<string, unknown> }).shape;
  if (shape === undefined) throw new Error("Expected a strict object schema");
  return Object.keys(shape).sort();
}

/** Declared keys of every arm of a discriminated union, sorted per arm. */
function declaredUnionKeys(schema: unknown): string[][] {
  const options = (schema as { options?: unknown[] }).options;
  if (options === undefined) throw new Error("Expected a discriminated union");
  return options.map((option) => declaredKeys(option));
}

describe("grant wire module constants", () => {
  it("freezes the resource type and restates the 300-second bound", () => {
    expect(COMMERCE_GRANT_RESOURCE_TYPE).toBe("authorization_grant");
    expect(COMMERCE_GRANT_MAX_LIFETIME_SECONDS).toBe(300);
  });

  it("re-exports the same schema objects from the package index", () => {
    expect(INDEX_ISSUE_DATA).toBe(CommerceGrantIssueDataSchema);
    expect(INDEX_GRANT_DETAIL).toBe(CommerceGrantDetailSchema);
    expect(INDEX_OUTCOME).toBe(CommerceGrantMutationOutcomeSchema);
  });
});

describe("attempt id and claim digest leaves", () => {
  it("accepts a canonical lower-case UUIDv4 attempt id", () => {
    expect(CommerceGrantAttemptIdSchema.safeParse(ATTEMPT_ID).success).toBe(
      true,
    );
  });

  it.each([
    ["uppercase", ATTEMPT_ID.toUpperCase()],
    ["v1 version nibble", "bbbbbbbb-cccc-1ddd-8eee-ffffffffffff"],
    ["bad variant nibble", "bbbbbbbb-cccc-4ddd-7eee-ffffffffffff"],
    ["namespaced", `openarc:attempt:${ATTEMPT_ID}`],
    ["empty", ""],
  ])("rejects a %s attempt id", (_label, value) => {
    expect(CommerceGrantAttemptIdSchema.safeParse(value).success).toBe(false);
  });

  it.each(SUFFIXES)("rejects an attempt id with a %j suffix", (suffix) => {
    expect(
      CommerceGrantAttemptIdSchema.safeParse(`${ATTEMPT_ID}${suffix}`).success,
    ).toBe(false);
  });

  it("accepts a lower-case sha256 claim digest and rejects drift", () => {
    expect(CommerceGrantClaimDigestSchema.safeParse(DIGEST).success).toBe(true);
    expect(
      CommerceGrantClaimDigestSchema.safeParse(`sha256:${"A".repeat(64)}`)
        .success,
    ).toBe(false);
    expect(
      CommerceGrantClaimDigestSchema.safeParse(`sha256:${"a".repeat(63)}`)
        .success,
    ).toBe(false);
    expect(CommerceGrantClaimDigestSchema.safeParse(`${"a".repeat(64)}`).success)
      .toBe(false);
  });

  it.each(SUFFIXES)("rejects a claim digest with a %j suffix", (suffix) => {
    expect(
      CommerceGrantClaimDigestSchema.safeParse(`${DIGEST}${suffix}`).success,
    ).toBe(false);
  });
});

describe("agent write bodies", () => {
  it("accepts the exact issue body", () => {
    const parsed = CommerceGrantIssueBodySchema.safeParse({
      mutationId: MUTATION,
      actionId: ACTION_ID,
    });
    expect(parsed.success).toBe(true);
  });

  it.each([
    ["organizationId", { organizationId: ORG }],
    ["subjectAgentId", { subjectAgentId: AGENT }],
    ["policyId", { policyId: "openarc:policy:12345678-1234-4234-8123-123456789abc" }],
    ["grantToken", { grantToken: GRANT_TOKEN }],
    ["expiresAt", { expiresAt: EXPIRES_AT }],
    ["amountAtomic", { amountAtomic: "100" }],
    ["operation", { operation: "control.grant.issue" }],
  ])("rejects an issue body carrying %s", (_label, extra) => {
    expect(
      CommerceGrantIssueBodySchema.safeParse({
        mutationId: MUTATION,
        actionId: ACTION_ID,
        ...extra,
      }).success,
    ).toBe(false);
  });

  it("rejects an own-property __proto__ key on a strict body", () => {
    expect(
      CommerceGrantIssueBodySchema.safeParse(
        withOwnProto({ mutationId: MUTATION, actionId: ACTION_ID }),
      ).success,
    ).toBe(false);
    expect(
      CommerceGrantRevokeBodySchema.safeParse(
        withOwnProto({ mutationId: MUTATION }),
      ).success,
    ).toBe(false);
  });

  it.each(SUFFIXES)(
    "rejects an issue body whose actionId carries a %j suffix",
    (suffix) => {
      expect(
        CommerceGrantIssueBodySchema.safeParse({
          mutationId: MUTATION,
          actionId: `${ACTION_ID}${suffix}`,
        }).success,
      ).toBe(false);
      expect(
        CommerceGrantIssueBodySchema.safeParse({
          mutationId: `${MUTATION}${suffix}`,
          actionId: ACTION_ID,
        }).success,
      ).toBe(false);
    },
  );

  it("accepts the replace body and refuses a body-borne grant id", () => {
    expect(
      CommerceGrantReplaceBodySchema.safeParse({ mutationId: MUTATION })
        .success,
    ).toBe(true);
    expect(
      CommerceGrantReplaceBodySchema.safeParse({
        mutationId: MUTATION,
        grantId: GRANT_ID,
      }).success,
    ).toBe(false);
    expect(
      CommerceGrantReplaceBodySchema.safeParse({
        mutationId: MUTATION,
        expiresAt: EXPIRES_AT,
      }).success,
    ).toBe(false);
  });

  it("accepts the revoke body and refuses release/erasure overrides", () => {
    expect(
      CommerceGrantRevokeBodySchema.safeParse({ mutationId: MUTATION }).success,
    ).toBe(true);
    for (const extra of [
      { released: true },
      { force: true },
      { reason: "x" },
      { cascade: true },
      { refund: true },
      { organizationId: ORG },
      { grantId: GRANT_ID },
    ]) {
      expect(
        CommerceGrantRevokeBodySchema.safeParse({
          mutationId: MUTATION,
          ...extra,
        }).success,
      ).toBe(false);
    }
  });
});

describe("provider write bodies carry the second factor only in a body", () => {
  it("accepts the introspect body with exactly the grant token", () => {
    expect(
      CommerceGrantProviderIntrospectBodySchema.safeParse({
        grantToken: GRANT_TOKEN,
      }).success,
    ).toBe(true);
  });

  it.each([
    ["a commerce session token", COMMERCE_SESSION_TOKEN],
    ["a provider session token", PROVIDER_SESSION_TOKEN],
    ["a bare secret", "A".repeat(43)],
    ["a truncated token", `oag_v1_${"A".repeat(42)}`],
    ["a noncanonical final character", `oag_v1_${"A".repeat(42)}B`],
  ])("rejects introspection with %s", (_label, token) => {
    expect(
      CommerceGrantProviderIntrospectBodySchema.safeParse({
        grantToken: token,
      }).success,
    ).toBe(false);
  });

  it.each(SUFFIXES)(
    "rejects an introspect token with a %j suffix",
    (suffix) => {
      expect(
        CommerceGrantProviderIntrospectBodySchema.safeParse({
          grantToken: `${GRANT_TOKEN}${suffix}`,
        }).success,
      ).toBe(false);
    },
  );

  it("rejects an introspect body carrying any buyer-private field", () => {
    for (const extra of [
      { organizationId: ORG },
      { subjectAgentId: AGENT },
      { commerceSessionId: SESSION_ID },
      { providerSessionToken: PROVIDER_SESSION_TOKEN },
    ]) {
      expect(
        CommerceGrantProviderIntrospectBodySchema.safeParse({
          grantToken: GRANT_TOKEN,
          ...extra,
        }).success,
      ).toBe(false);
    }
  });

  it("accepts the exact claim body", () => {
    expect(
      CommerceGrantProviderClaimBodySchema.safeParse({
        mutationId: MUTATION,
        grantToken: GRANT_TOKEN,
        expectedActionId: ACTION_ID,
        attemptId: ATTEMPT_ID,
      }).success,
    ).toBe(true);
  });

  it("rejects a claim body missing either factor field or carrying extras", () => {
    expect(
      CommerceGrantProviderClaimBodySchema.safeParse({
        mutationId: MUTATION,
        expectedActionId: ACTION_ID,
        attemptId: ATTEMPT_ID,
      }).success,
    ).toBe(false);
    for (const extra of [
      { organizationId: ORG },
      { policyId: "openarc:policy:12345678-1234-4234-8123-123456789abc" },
      { amountAtomic: "100" },
      { debitAtomic: "105" },
      { grantId: GRANT_ID },
      { providerId: PROVIDER_ID },
    ]) {
      expect(
        CommerceGrantProviderClaimBodySchema.safeParse({
          mutationId: MUTATION,
          grantToken: GRANT_TOKEN,
          expectedActionId: ACTION_ID,
          attemptId: ATTEMPT_ID,
          ...extra,
        }).success,
      ).toBe(false);
    }
  });
});

describe("read requests", () => {
  it("accepts the organization-scoped detail and mutation requests", () => {
    expect(
      CommerceGrantDetailRequestSchema.safeParse({
        organizationId: ORG,
        grantId: GRANT_ID,
      }).success,
    ).toBe(true);
    expect(
      CommerceGrantHumanMutationRequestSchema.safeParse({
        organizationId: ORG,
        mutationId: MUTATION,
      }).success,
    ).toBe(true);
    expect(
      CommerceGrantAgentMutationRequestSchema.safeParse({
        mutationId: MUTATION,
      }).success,
    ).toBe(true);
  });

  it("rejects unknown keys and explicit undefined values on requests", () => {
    expect(
      CommerceGrantDetailRequestSchema.safeParse({
        organizationId: ORG,
        grantId: GRANT_ID,
        limit: "1",
      }).success,
    ).toBe(false);
    expect(
      CommerceGrantDetailRequestSchema.safeParse({
        organizationId: ORG,
        grantId: GRANT_ID,
        afterGrantId: undefined,
      }).success,
    ).toBe(false);
    expect(
      CommerceGrantAgentMutationRequestSchema.safeParse({
        mutationId: MUTATION,
        organizationId: ORG,
      }).success,
    ).toBe(false);
  });

  it("keys provider recovery on the provider's own attempt id alone", () => {
    expect(
      CommerceGrantProviderAttemptStatusRequestSchema.safeParse({
        attemptId: ATTEMPT_ID,
      }).success,
    ).toBe(true);
    for (const extra of [
      { organizationId: ORG },
      { grantId: GRANT_ID },
      { grantToken: GRANT_TOKEN },
      { actionId: ACTION_ID },
      { providerId: PROVIDER_ID },
    ]) {
      expect(
        CommerceGrantProviderAttemptStatusRequestSchema.safeParse({
          attemptId: ATTEMPT_ID,
          ...extra,
        }).success,
      ).toBe(false);
    }
  });
});

describe("receipts", () => {
  it.each([
    ["issue", CommerceGrantIssueReceiptSchema, "control.grant.issue"],
    ["replace", CommerceGrantReplaceReceiptSchema, "control.grant.replace"],
    ["claim", CommerceGrantClaimReceiptSchema, "control.grant.claim"],
    ["revoke", CommerceGrantRevokeReceiptSchema, "control.grant.revoke"],
  ] as const)("accepts the %s receipt", (_label, schema, operation) => {
    expect(schema.safeParse(receipt(operation)).success).toBe(true);
  });

  it("pins each narrowed receipt to exactly one operation", () => {
    expect(
      CommerceGrantIssueReceiptSchema.safeParse(receipt("control.grant.replace"))
        .success,
    ).toBe(false);
    expect(
      CommerceGrantRevokeReceiptSchema.safeParse(receipt("control.grant.claim"))
        .success,
    ).toBe(false);
  });

  it("pins the resource type and rejects any extra receipt field", () => {
    expect(
      CommerceGrantIssueReceiptSchema.safeParse(
        receipt("control.grant.issue", { resourceType: "commerce_action" }),
      ).success,
    ).toBe(false);
    for (const extra of [
      { grantToken: GRANT_TOKEN },
      { grantTokenHash: "a".repeat(64) },
      { generation: "1" },
      { actorAccountId: "openarc:account:12345678-1234-4234-8123-123456789abc" },
      { idempotencyKey: "k" },
      { sessionContextDigest: DIGEST },
    ]) {
      expect(
        CommerceGrantIssueReceiptSchema.safeParse(
          receipt("control.grant.issue", extra),
        ).success,
      ).toBe(false);
    }
  });

  it.each(SUFFIXES)(
    "rejects a receipt committedAt with a %j suffix",
    (suffix) => {
      expect(
        CommerceGrantIssueReceiptSchema.safeParse(
          receipt("control.grant.issue", {
            committedAt: `${ISSUED_AT}${suffix}`,
          }),
        ).success,
      ).toBe(false);
    },
  );

  it("restricts the agent receipt union to issue and replace", () => {
    expect(
      CommerceGrantAgentReceiptSchema.safeParse(receipt("control.grant.issue"))
        .success,
    ).toBe(true);
    expect(
      CommerceGrantAgentReceiptSchema.safeParse(receipt("control.grant.replace"))
        .success,
    ).toBe(true);
    expect(
      CommerceGrantAgentReceiptSchema.safeParse(receipt("control.grant.claim"))
        .success,
    ).toBe(false);
    expect(
      CommerceGrantAgentReceiptSchema.safeParse(receipt("control.grant.revoke"))
        .success,
    ).toBe(false);
  });

  it("accepts all four operations on the full receipt union only", () => {
    for (const operation of [
      "control.grant.issue",
      "control.grant.replace",
      "control.grant.claim",
      "control.grant.revoke",
    ]) {
      expect(
        CommerceGrantMutationReceiptSchema.safeParse(receipt(operation)).success,
      ).toBe(true);
    }
    expect(
      CommerceGrantMutationReceiptSchema.safeParse(
        receipt("control.commerce_action.authorize"),
      ).success,
    ).toBe(false);
  });
});

describe("agent issue data delivers the raw token exactly once", () => {
  it("accepts a first delivery carrying the token", () => {
    expect(CommerceGrantIssueDataSchema.safeParse(issueData()).success).toBe(
      true,
    );
  });

  it("requires the token on a first delivery", () => {
    const withoutToken: Record<string, unknown> = { ...issueData() };
    delete withoutToken["grantToken"];
    expect(CommerceGrantIssueDataSchema.safeParse(withoutToken).success).toBe(
      false,
    );
  });

  it("accepts a replay and makes the token structurally unrepresentable", () => {
    expect(
      CommerceGrantIssueDataSchema.safeParse({
        replayed: true,
        metadata: grant(),
        receipt: receipt("control.grant.issue"),
      }).success,
    ).toBe(true);
    expect(
      CommerceGrantIssueDataSchema.safeParse({
        replayed: true,
        metadata: grant(),
        receipt: receipt("control.grant.issue"),
        grantToken: GRANT_TOKEN,
      }).success,
    ).toBe(false);
  });

  it("rejects every secret-shaped field on either arm", () => {
    for (const extra of [
      { grantTokenHash: "a".repeat(64) },
      { tokenHash: "a".repeat(64) },
      { salt: "a".repeat(32) },
      { pepper: "a".repeat(32) },
      { rawToken: GRANT_TOKEN },
      { secret: GRANT_TOKEN },
    ]) {
      expect(
        CommerceGrantIssueDataSchema.safeParse(issueData(extra)).success,
      ).toBe(false);
      expect(
        CommerceGrantIssueDataSchema.safeParse({
          replayed: true,
          metadata: grant(),
          receipt: receipt("control.grant.issue"),
          ...extra,
        }).success,
      ).toBe(false);
    }
  });

  it("binds the receipt resource id to the grant id", () => {
    expect(
      CommerceGrantIssueDataSchema.safeParse(
        issueData({
          receipt: receipt("control.grant.issue", { resourceId: GRANT_ID_B }),
        }),
      ).success,
    ).toBe(false);
  });

  it("requires the first generation and an issued status on a first delivery", () => {
    expect(
      CommerceGrantIssueDataSchema.safeParse(
        issueData({ metadata: grant({ generation: "2" }) }),
      ).success,
    ).toBe(false);
    expect(
      CommerceGrantIssueDataSchema.safeParse(
        issueData({ metadata: claimedGrant() }),
      ).success,
    ).toBe(false);
  });

  it("lets a replay report a grant that has since been claimed or revoked", () => {
    expect(
      CommerceGrantIssueDataSchema.safeParse({
        replayed: true,
        metadata: revokedAfterClaimGrant({ generation: "3" }),
        receipt: receipt("control.grant.issue"),
      }).success,
    ).toBe(true);
  });

  it("refuses a replace receipt on issue data", () => {
    expect(
      CommerceGrantIssueDataSchema.safeParse(
        issueData({ receipt: receipt("control.grant.replace") }),
      ).success,
    ).toBe(false);
  });

  it("enforces the 300-second grant bound through the reused metadata", () => {
    expect(
      CommerceGrantIssueDataSchema.safeParse(
        issueData({ metadata: grant({ expiresAt: EXPIRES_AT }) }),
      ).success,
    ).toBe(true);
    expect(
      CommerceGrantIssueDataSchema.safeParse(
        issueData({ metadata: grant({ expiresAt: EXPIRES_OVER }) }),
      ).success,
    ).toBe(false);
    expect(
      CommerceGrantIssueDataSchema.safeParse(
        issueData({ metadata: grant({ expiresAt: ISSUED_AT }) }),
      ).success,
    ).toBe(false);
  });

  it("types the first-delivery arm with a token and the replay arm without", () => {
    const parsed = CommerceGrantIssueDataSchema.parse(
      issueData(),
    ) as CommerceGrantIssueData;
    expect(parsed.replayed).toBe(false);
    if (!parsed.replayed) {
      expectTypeOf(parsed.grantToken).toEqualTypeOf<string>();
    }
    const replayParsed = CommerceGrantIssueDataSchema.parse({
      replayed: true,
      metadata: grant(),
      receipt: receipt("control.grant.issue"),
    });
    expect(Object.hasOwn(replayParsed, "grantToken")).toBe(false);
  });
});

describe("agent replace data", () => {
  it("accepts a first delivery on a later generation", () => {
    expect(CommerceGrantReplaceDataSchema.safeParse(replaceData()).success).toBe(
      true,
    );
  });

  it("refuses generation 1 on a first-delivery replacement", () => {
    expect(
      CommerceGrantReplaceDataSchema.safeParse(
        replaceData({ metadata: grant({ generation: "1" }) }),
      ).success,
    ).toBe(false);
  });

  it("refuses a replacement of a claimed grant", () => {
    expect(
      CommerceGrantReplaceDataSchema.safeParse(
        replaceData({ metadata: claimedGrant({ generation: "2" }) }),
      ).success,
    ).toBe(false);
  });

  it("never carries a token on a replay", () => {
    expect(
      CommerceGrantReplaceDataSchema.safeParse({
        replayed: true,
        metadata: grant({ generation: "2" }),
        receipt: receipt("control.grant.replace"),
      }).success,
    ).toBe(true);
    expect(
      CommerceGrantReplaceDataSchema.safeParse({
        replayed: true,
        metadata: grant({ generation: "2" }),
        receipt: receipt("control.grant.replace"),
        grantToken: GRANT_TOKEN_B,
      }).success,
    ).toBe(false);
  });

  it("refuses an issue receipt and a mismatched resource id", () => {
    expect(
      CommerceGrantReplaceDataSchema.safeParse(
        replaceData({ receipt: receipt("control.grant.issue") }),
      ).success,
    ).toBe(false);
    expect(
      CommerceGrantReplaceDataSchema.safeParse(
        replaceData({
          receipt: receipt("control.grant.replace", { resourceId: GRANT_ID_B }),
        }),
      ).success,
    ).toBe(false);
  });

  it("compares generations as BigInt beyond the safe integer range", () => {
    expect(
      CommerceGrantReplaceDataSchema.safeParse(
        replaceData({ metadata: grant({ generation: "2147483647" }) }),
      ).success,
    ).toBe(true);
    expect(
      CommerceGrantReplaceDataSchema.safeParse(
        replaceData({ metadata: grant({ generation: "2147483648" }) }),
      ).success,
    ).toBe(false);
  });
});

describe("replacement continuity: a replacement can never extend expiry", () => {
  const previous = grant();
  const next = grant({ generation: "2", updatedAt: CLAIMED_AT });

  it("accepts a same-expiry next generation of the same grant", () => {
    expect(
      CommerceGrantReplacementContinuitySchema.safeParse({ previous, next })
        .success,
    ).toBe(true);
  });

  it("accepts a shortened expiry", () => {
    expect(
      CommerceGrantReplacementContinuitySchema.safeParse({
        previous,
        next: grant({ generation: "2", expiresAt: EXPIRES_EARLIER }),
      }).success,
    ).toBe(true);
  });

  it("rejects an extended expiry even when both sides honor the 300s bound", () => {
    const parsed = CommerceGrantReplacementContinuitySchema.safeParse({
      previous: grant({ expiresAt: EXPIRES_EARLIER }),
      next: grant({ generation: "2", expiresAt: EXPIRES_AT }),
    });
    expect(parsed.success).toBe(false);
    expect(
      parsed.success
        ? []
        : parsed.error.issues.map((issue) => issue.message),
    ).toContain("a replacement must not extend the original expiry");
  });

  it("rejects a non-advancing or lower generation", () => {
    expect(
      CommerceGrantReplacementContinuitySchema.safeParse({
        previous: grant({ generation: "2" }),
        next: grant({ generation: "2" }),
      }).success,
    ).toBe(false);
    expect(
      CommerceGrantReplacementContinuitySchema.safeParse({
        previous: grant({ generation: "3" }),
        next: grant({ generation: "2" }),
      }).success,
    ).toBe(false);
  });

  it.each([
    ["grantId", { grantId: GRANT_ID_B }],
    ["organizationId", { organizationId: ORG_B }],
    ["actionId", { actionId: ACTION_ID_B }],
    ["issuedAt", { issuedAt: "2025-01-01T00:00:01Z" }],
  ])("rejects a replacement that changes %s", (_label, override) => {
    expect(
      CommerceGrantReplacementContinuitySchema.safeParse({
        previous,
        next: grant({ generation: "2", ...override }),
      }).success,
    ).toBe(false);
  });

  it("rejects replacing a claimed or revoked grant", () => {
    expect(
      CommerceGrantReplacementContinuitySchema.safeParse({
        previous: claimedGrant(),
        next: grant({ generation: "2" }),
      }).success,
    ).toBe(false);
    expect(
      CommerceGrantReplacementContinuitySchema.safeParse({
        previous: revokedNeverClaimedGrant(),
        next: grant({ generation: "2" }),
      }).success,
    ).toBe(false);
  });

  it("rejects a next grant that is not issued and any unknown key", () => {
    expect(
      CommerceGrantReplacementContinuitySchema.safeParse({
        previous,
        next: claimedGrant({ generation: "2" }),
      }).success,
    ).toBe(false);
    expect(
      CommerceGrantReplacementContinuitySchema.safeParse({
        previous,
        next,
        grantToken: GRANT_TOKEN,
      }).success,
    ).toBe(false);
  });
});

describe("human revoke data retains a claim, never erases it", () => {
  it("accepts a never-claimed release with a cancelled action", () => {
    expect(CommerceGrantRevokeDataSchema.safeParse(revokeData()).success).toBe(
      true,
    );
  });

  it("accepts a revoke after a claim that retains the claim and exposure", () => {
    const parsed = CommerceGrantRevokeDataSchema.safeParse(
      revokeData({
        metadata: revokedAfterClaimGrant(),
        released: false,
        actionStatus: "grant_issued",
      }),
    );
    expect(parsed.success).toBe(true);
    expect(
      parsed.success && parsed.data.metadata.claimedAt,
    ).toBe(CLAIMED_AT);
    expect(parsed.success && parsed.data.released).toBe(false);
  });

  it("refuses to release a claimed grant", () => {
    const parsed = CommerceGrantRevokeDataSchema.safeParse(
      revokeData({
        metadata: revokedAfterClaimGrant(),
        released: true,
        actionStatus: "cancelled",
      }),
    );
    expect(parsed.success).toBe(false);
    expect(
      parsed.success ? [] : parsed.error.issues.map((issue) => issue.message),
    ).toContain("a claimed grant retains its exposure and cannot be released");
  });

  it("requires a cancelled action behind a released revoke", () => {
    expect(
      CommerceGrantRevokeDataSchema.safeParse(
        revokeData({ actionStatus: "grant_issued" }),
      ).success,
    ).toBe(false);
  });

  it("allows a repeated revoke that releases nothing", () => {
    expect(
      CommerceGrantRevokeDataSchema.safeParse(
        revokeData({
          replayed: false,
          released: false,
          actionStatus: "cancelled",
        }),
      ).success,
    ).toBe(true);
  });

  it("requires a revoked metadata status", () => {
    expect(
      CommerceGrantRevokeDataSchema.safeParse(
        revokeData({ metadata: grant(), released: false }),
      ).success,
    ).toBe(false);
    expect(
      CommerceGrantRevokeDataSchema.safeParse(
        revokeData({ metadata: claimedGrant(), released: false }),
      ).success,
    ).toBe(false);
  });

  it("binds the revoke receipt and rejects any refund/settlement field", () => {
    expect(
      CommerceGrantRevokeDataSchema.safeParse(
        revokeData({
          receipt: receipt("control.grant.revoke", { resourceId: GRANT_ID_B }),
        }),
      ).success,
    ).toBe(false);
    expect(
      CommerceGrantRevokeDataSchema.safeParse(
        revokeData({ receipt: receipt("control.grant.issue") }),
      ).success,
    ).toBe(false);
    for (const extra of [
      { refunded: true },
      { settled: true },
      { reservationStatus: "released" },
      { grantToken: GRANT_TOKEN },
      { amountAtomic: "100" },
    ]) {
      expect(
        CommerceGrantRevokeDataSchema.safeParse(revokeData(extra)).success,
      ).toBe(false);
    }
  });

  it("rejects an action status outside the accepted closed enum", () => {
    expect(
      CommerceGrantRevokeDataSchema.safeParse(
        revokeData({ actionStatus: "released" }),
      ).success,
    ).toBe(false);
    expect(
      CommerceGrantRevokeDataSchema.safeParse(
        revokeData({ actionStatus: "cancelled\n" }),
      ).success,
    ).toBe(false);
  });
});

describe("provider introspection", () => {
  it("accepts the exact provider projection", () => {
    expect(
      CommerceGrantProviderIntrospectionSchema.safeParse({
        item: providerView(),
      }).success,
    ).toBe(true);
  });

  it("rejects any buyer-private field on the wrapper or the projection", () => {
    expect(
      CommerceGrantProviderIntrospectionSchema.safeParse({
        item: providerView(),
        organizationId: ORG,
      }).success,
    ).toBe(false);
    for (const extra of [
      { organizationId: ORG },
      { subjectAgentId: AGENT },
      { policyId: "openarc:policy:12345678-1234-4234-8123-123456789abc" },
      { commerceSessionId: SESSION_ID },
      { availableAtomic: "100" },
      { grantToken: GRANT_TOKEN },
    ]) {
      expect(
        CommerceGrantProviderIntrospectionSchema.safeParse({
          item: providerView(extra),
        }).success,
      ).toBe(false);
    }
  });

  it("compares money as exact BigInt, never through a float", () => {
    expect(
      CommerceGrantProviderIntrospectionSchema.safeParse({
        item: providerView({
          amountAtomic: "100",
          feeAtomic: "5",
          debitAtomic: "105",
        }),
      }).success,
    ).toBe(true);
    // A float implementation would accept this: Number(2^53) + 1 === Number(2^53).
    expect(
      CommerceGrantProviderIntrospectionSchema.safeParse({
        item: providerView({
          amountAtomic: "9007199254740992",
          feeAtomic: "1",
          debitAtomic: "9007199254740992",
        }),
      }).success,
    ).toBe(false);
    expect(
      CommerceGrantProviderIntrospectionSchema.safeParse({
        item: providerView({
          amountAtomic: "9007199254740992",
          feeAtomic: "1",
          debitAtomic: "9007199254740993",
        }),
      }).success,
    ).toBe(true);
  });

  it("accepts a full uint256 amount and rejects an overflow", () => {
    expect(
      CommerceGrantProviderIntrospectionSchema.safeParse({
        item: providerView({
          amountAtomic: MAX_UINT256,
          feeAtomic: "0",
          debitAtomic: MAX_UINT256,
        }),
      }).success,
    ).toBe(true);
    expect(
      CommerceGrantProviderIntrospectionSchema.safeParse({
        item: providerView({
          amountAtomic: OVER_UINT256,
          feeAtomic: "0",
          debitAtomic: OVER_UINT256,
        }),
      }).success,
    ).toBe(false);
    expect(
      CommerceGrantProviderIntrospectionSchema.safeParse({
        item: providerView({
          amountAtomic: MAX_UINT256,
          feeAtomic: OVER_UINT256,
          debitAtomic: "1",
        }),
      }).success,
    ).toBe(false);
  });

  it.each(SUFFIXES)("rejects a money leaf with a %j suffix", (suffix) => {
    expect(
      CommerceGrantProviderIntrospectionSchema.safeParse({
        item: providerView({ amountAtomic: `100${suffix}` }),
      }).success,
    ).toBe(false);
    expect(
      CommerceGrantProviderIntrospectionSchema.safeParse({
        item: providerView({ debitAtomic: `105${suffix}` }),
      }).success,
    ).toBe(false);
  });

  it("rejects noncanonical money spellings", () => {
    for (const amount of ["0100", "+100", "1e2", "100.0", "", " 100"]) {
      expect(
        CommerceGrantProviderIntrospectionSchema.safeParse({
          item: providerView({ amountAtomic: amount }),
        }).success,
      ).toBe(false);
    }
  });
});

describe("provider claim data", () => {
  it("accepts a claim bound to the provider's own attempt", () => {
    expect(
      CommerceGrantProviderClaimDataSchema.safeParse(claimData()).success,
    ).toBe(true);
  });

  it("requires a claimed attempt id equal to the returned attempt id", () => {
    expect(
      CommerceGrantProviderClaimDataSchema.safeParse(
        claimData({ attemptId: ATTEMPT_ID_B }),
      ).success,
    ).toBe(false);
    expect(
      CommerceGrantProviderClaimDataSchema.safeParse(
        claimData({
          item: providerView(),
          attemptId: ATTEMPT_ID,
        }),
      ).success,
    ).toBe(false);
  });

  it("keeps the claim visible after revocation", () => {
    expect(
      CommerceGrantProviderClaimDataSchema.safeParse(
        claimData({
          item: providerView({
            status: "revoked",
            claimedAttemptId: ATTEMPT_ID,
          }),
        }),
      ).success,
    ).toBe(true);
  });

  it("rejects an expired or out-of-order claim instant", () => {
    expect(
      CommerceGrantProviderClaimDataSchema.safeParse(
        claimData({ claimedAt: EXPIRES_AT }),
      ).success,
    ).toBe(false);
    expect(
      CommerceGrantProviderClaimDataSchema.safeParse(
        claimData({ claimedAt: "2025-01-01T00:06:00Z" }),
      ).success,
    ).toBe(false);
  });

  it("binds the claim receipt and refuses payment-shaped fields", () => {
    expect(
      CommerceGrantProviderClaimDataSchema.safeParse(
        claimData({
          receipt: receipt("control.grant.claim", { resourceId: GRANT_ID_B }),
        }),
      ).success,
    ).toBe(false);
    expect(
      CommerceGrantProviderClaimDataSchema.safeParse(
        claimData({ receipt: receipt("control.grant.revoke") }),
      ).success,
    ).toBe(false);
    for (const extra of [
      { grantToken: GRANT_TOKEN },
      { paymentProof: DIGEST },
      { settlementTx: "0x00" },
      { organizationId: ORG },
    ]) {
      expect(
        CommerceGrantProviderClaimDataSchema.safeParse(claimData(extra)).success,
      ).toBe(false);
    }
  });

  it.each(SUFFIXES)("rejects a claim digest with a %j suffix", (suffix) => {
    expect(
      CommerceGrantProviderClaimDataSchema.safeParse(
        claimData({ claimDigest: `${DIGEST}${suffix}` }),
      ).success,
    ).toBe(false);
  });
});

describe("provider attempt-status recovery", () => {
  it("returns a not_found arm that carries only its status", () => {
    const parsed = CommerceGrantProviderAttemptStatusDataSchema.safeParse({
      attemptId: ATTEMPT_ID,
      item: { status: "not_found" },
    });
    expect(parsed.success).toBe(true);
    expect(parsed.success && Object.keys(parsed.data.item)).toEqual(["status"]);
  });

  it("makes a missing attempt indistinguishable from a foreign one", () => {
    const missing = CommerceGrantProviderAttemptStatusDataSchema.parse({
      attemptId: ATTEMPT_ID,
      item: { status: "not_found" },
    });
    const foreign = CommerceGrantProviderAttemptStatusDataSchema.parse({
      attemptId: ATTEMPT_ID,
      item: { status: "not_found" },
    });
    expect(missing).toEqual(foreign);
    for (const extra of [
      { grantId: GRANT_ID },
      { reason: "foreign" },
      { providerId: PROVIDER_ID },
      { exists: false },
    ]) {
      expect(
        CommerceGrantProviderAttemptStatusDataSchema.safeParse({
          attemptId: ATTEMPT_ID,
          item: { status: "not_found", ...extra },
        }).success,
      ).toBe(false);
    }
  });

  it("retains the claim fact plus a grantRevoked flag", () => {
    const parsed = CommerceGrantProviderAttemptStatusDataSchema.safeParse({
      attemptId: ATTEMPT_ID,
      item: {
        status: "claimed",
        attemptId: ATTEMPT_ID,
        grantId: GRANT_ID,
        actionId: ACTION_ID,
        providerId: PROVIDER_ID,
        listingId: LISTING_ID,
        listingVersion: "1",
        claimedAt: CLAIMED_AT,
        grantRevoked: true,
      },
    });
    expect(parsed.success).toBe(true);
    expect(parsed.success && parsed.data.item.status).toBe("claimed");
  });

  it("requires the claimed arm to echo the requested attempt id", () => {
    expect(
      CommerceGrantProviderAttemptStatusDataSchema.safeParse({
        attemptId: ATTEMPT_ID_B,
        item: {
          status: "claimed",
          attemptId: ATTEMPT_ID,
          grantId: GRANT_ID,
          actionId: ACTION_ID,
          providerId: PROVIDER_ID,
          listingId: LISTING_ID,
          listingVersion: "1",
          claimedAt: CLAIMED_AT,
          grantRevoked: false,
        },
      }).success,
    ).toBe(false);
  });

  it("rejects a wrapper carrying anything beyond the attempt id and item", () => {
    for (const extra of [
      { organizationId: ORG },
      { grantToken: GRANT_TOKEN },
      { item2: null },
    ]) {
      expect(
        CommerceGrantProviderAttemptStatusDataSchema.safeParse({
          attemptId: ATTEMPT_ID,
          item: { status: "not_found" },
          ...extra,
        }).success,
      ).toBe(false);
    }
  });
});

describe("human grant detail", () => {
  it("accepts a bound item and a safe null", () => {
    expect(
      CommerceGrantDetailSchema.safeParse({
        organizationId: ORG,
        grantId: GRANT_ID,
        item: grant(),
      }).success,
    ).toBe(true);
    expect(
      CommerceGrantDetailSchema.safeParse({
        organizationId: ORG,
        grantId: GRANT_ID,
        item: null,
      }).success,
    ).toBe(true);
  });

  it("rejects a cross-id or cross-tenant item", () => {
    expect(
      CommerceGrantDetailSchema.safeParse({
        organizationId: ORG,
        grantId: GRANT_ID_B,
        item: grant(),
      }).success,
    ).toBe(false);
    expect(
      CommerceGrantDetailSchema.safeParse({
        organizationId: ORG_B,
        grantId: GRANT_ID,
        item: grant(),
      }).success,
    ).toBe(false);
  });

  it("cannot carry a raw token anywhere in the read", () => {
    for (const extra of [
      { grantToken: GRANT_TOKEN },
      { token: GRANT_TOKEN },
      { grantTokenHash: "a".repeat(64) },
    ]) {
      expect(
        CommerceGrantDetailSchema.safeParse({
          organizationId: ORG,
          grantId: GRANT_ID,
          item: grant(),
          ...extra,
        }).success,
      ).toBe(false);
      expect(
        CommerceGrantDetailSchema.safeParse({
          organizationId: ORG,
          grantId: GRANT_ID,
          item: grant(extra),
        }).success,
      ).toBe(false);
    }
  });

  it("keeps the revoked claim fact visible on a read", () => {
    const parsed = CommerceGrantDetailSchema.safeParse({
      organizationId: ORG,
      grantId: GRANT_ID,
      item: revokedAfterClaimGrant(),
    });
    expect(parsed.success).toBe(true);
    expect(parsed.success && parsed.data.item?.claimedAt).toBe(CLAIMED_AT);
    expect(parsed.success && parsed.data.item?.revokedAt).toBe(REVOKED_AT);
  });
});

describe("mutation status keeps audiences apart and stays token-free", () => {
  it("accepts the committed-or-not-found discipline on both lanes", () => {
    expect(
      CommerceGrantAgentMutationStatusSchema.safeParse({ status: "not_found" })
        .success,
    ).toBe(true);
    expect(
      CommerceGrantHumanMutationStatusSchema.safeParse({ status: "not_found" })
        .success,
    ).toBe(true);
    expect(
      CommerceGrantAgentMutationStatusSchema.safeParse({
        status: "committed",
        receipt: receipt("control.grant.issue"),
      }).success,
    ).toBe(true);
    expect(
      CommerceGrantHumanMutationStatusSchema.safeParse({
        status: "committed",
        receipt: receipt("control.grant.revoke"),
      }).success,
    ).toBe(true);
  });

  it("gives not_found exactly one key", () => {
    const parsed = CommerceGrantAgentMutationStatusSchema.parse({
      status: "not_found",
    });
    expect(Object.keys(parsed)).toEqual(["status"]);
    expect(
      CommerceGrantAgentMutationStatusSchema.safeParse({
        status: "not_found",
        receipt: receipt("control.grant.issue"),
      }).success,
    ).toBe(false);
  });

  it("refuses a browser receipt on the agent lane and vice versa", () => {
    expect(
      CommerceGrantAgentMutationStatusSchema.safeParse({
        status: "committed",
        receipt: receipt("control.grant.revoke"),
      }).success,
    ).toBe(false);
    expect(
      CommerceGrantAgentMutationStatusSchema.safeParse({
        status: "committed",
        receipt: receipt("control.grant.claim"),
      }).success,
    ).toBe(false);
    expect(
      CommerceGrantHumanMutationStatusSchema.safeParse({
        status: "committed",
        receipt: receipt("control.grant.issue"),
      }).success,
    ).toBe(false);
    expect(
      CommerceGrantHumanMutationStatusSchema.safeParse({
        status: "committed",
        receipt: receipt("control.grant.claim"),
      }).success,
    ).toBe(false);
  });

  it("cannot reconstruct the one-use token on any status arm", () => {
    for (const schema of [
      CommerceGrantAgentMutationStatusSchema,
      CommerceGrantHumanMutationStatusSchema,
    ]) {
      expect(
        schema.safeParse({ status: "not_found", grantToken: GRANT_TOKEN })
          .success,
      ).toBe(false);
      expect(
        schema.safeParse({
          status: "committed",
          receipt: receipt("control.grant.revoke"),
          grantToken: GRANT_TOKEN,
        }).success,
      ).toBe(false);
    }
  });

  it("rejects an unknown status literal", () => {
    expect(
      CommerceGrantAgentMutationStatusSchema.safeParse({ status: "unknown" })
        .success,
    ).toBe(false);
    expect(
      CommerceGrantAgentMutationStatusSchema.safeParse({ status: "committed" })
        .success,
    ).toBe(false);
  });
});

describe("unknown outcome is never success, failure, refund or release", () => {
  it("accepts all three arms", () => {
    expect(
      CommerceGrantMutationOutcomeSchema.safeParse({
        outcome: "committed",
        mutationId: MUTATION,
        receipt: receipt("control.grant.issue"),
      }).success,
    ).toBe(true);
    expect(
      CommerceGrantMutationOutcomeSchema.safeParse({
        outcome: "not_committed",
        mutationId: MUTATION,
      }).success,
    ).toBe(true);
    expect(
      CommerceGrantMutationOutcomeSchema.safeParse({
        outcome: "unknown",
        mutationId: MUTATION,
      }).success,
    ).toBe(true);
  });

  it("binds a committed receipt to the outcome mutation id", () => {
    expect(
      CommerceGrantMutationOutcomeSchema.safeParse({
        outcome: "committed",
        mutationId: MUTATION_B,
        receipt: receipt("control.grant.issue"),
      }).success,
    ).toBe(false);
  });

  it("gives the unknown arm exactly the outcome and mutation id", () => {
    const parsed = CommerceGrantMutationOutcomeSchema.parse({
      outcome: "unknown",
      mutationId: MUTATION,
    }) as CommerceGrantMutationOutcome;
    expect(Object.keys(parsed).sort()).toEqual(["mutationId", "outcome"]);
  });

  it.each([
    ["a receipt", { receipt: receipt("control.grant.issue") }],
    ["a committedAt", { committedAt: ISSUED_AT }],
    ["a resource id", { resourceId: GRANT_ID }],
    ["a released flag", { released: true }],
    ["a refunded flag", { refunded: true }],
    ["a settled flag", { settled: true }],
    ["a grant status", { status: "issued" }],
    ["a reservation", { reservationId: RESERVATION_ID }],
    ["an amount", { amountAtomic: "100" }],
    ["a raw token", { grantToken: GRANT_TOKEN }],
  ])("refuses to let the unknown arm carry %s", (_label, extra) => {
    expect(
      CommerceGrantMutationOutcomeSchema.safeParse({
        outcome: "unknown",
        mutationId: MUTATION,
        ...extra,
      }).success,
    ).toBe(false);
  });

  it("refuses to let the not_committed arm carry a receipt or a release", () => {
    expect(
      CommerceGrantMutationOutcomeSchema.safeParse({
        outcome: "not_committed",
        mutationId: MUTATION,
        receipt: receipt("control.grant.issue"),
      }).success,
    ).toBe(false);
    expect(
      CommerceGrantMutationOutcomeSchema.safeParse({
        outcome: "not_committed",
        mutationId: MUTATION,
        released: true,
      }).success,
    ).toBe(false);
  });

  it("keeps the three literals distinct and rejects near misses", () => {
    for (const outcome of [
      "unknown_outcome",
      "UNKNOWN",
      "unknown\n",
      "maybe",
      "committed_unknown",
    ]) {
      expect(
        CommerceGrantMutationOutcomeSchema.safeParse({
          outcome,
          mutationId: MUTATION,
        }).success,
      ).toBe(false);
    }
  });

  it("requires a receipt on the committed arm", () => {
    expect(
      CommerceGrantMutationOutcomeSchema.safeParse({
        outcome: "committed",
        mutationId: MUTATION,
      }).success,
    ).toBe(false);
  });
});

describe("success envelopes", () => {
  it("wraps grant data in the accepted v2 envelope", () => {
    expect(
      CommerceGrantIssueDataResponseSchema.safeParse({
        ok: true,
        data: issueData(),
        meta: META,
      }).success,
    ).toBe(true);
    expect(
      CommerceGrantDetailResponseSchema.safeParse({
        ok: true,
        data: {
          organizationId: ORG,
          grantId: GRANT_ID,
          item: null,
        },
        meta: META,
      }).success,
    ).toBe(true);
    expect(
      CommerceGrantAgentMutationStatusResponseSchema.safeParse({
        ok: true,
        data: { status: "not_found" },
        meta: META,
      }).success,
    ).toBe(true);
  });

  it("rejects an error-shaped or extended envelope", () => {
    expect(
      CommerceGrantDetailResponseSchema.safeParse({
        ok: false,
        data: { organizationId: ORG, grantId: GRANT_ID, item: null },
        meta: META,
      }).success,
    ).toBe(false);
    expect(
      CommerceGrantDetailResponseSchema.safeParse({
        ok: true,
        data: { organizationId: ORG, grantId: GRANT_ID, item: null },
        meta: META,
        grantToken: GRANT_TOKEN,
      }).success,
    ).toBe(false);
  });
});

describe("field classes", () => {
  const entries = Object.entries(COMMERCE_GRANT_WIRE_FIELD_CLASSES);

  it("declares every field organization_protected", () => {
    expect(entries.length).toBeGreaterThan(0);
    for (const [name, entry] of entries) {
      expect(entry.dataClass, name).toBe("organization_protected");
      for (const [field, value] of Object.entries(entry.fields)) {
        expect(value, `${name}.${field}`).toBe("organization_protected");
      }
    }
  });

  it("uses only the two accepted audiences", () => {
    for (const [name, entry] of entries) {
      expect(
        ["organization", "provider_minimal"].includes(entry.audience),
        name,
      ).toBe(true);
    }
  });

  it("keeps provider_minimal allowlists free of buyer-private fields", () => {
    const forbidden = [
      "organizationId",
      "subjectAgentId",
      "policyId",
      "policyRevision",
      "commerceSessionId",
      "accountId",
      "parentHumanAccountId",
      "reservationId",
      "approvalId",
      "availableAtomic",
      "committedAtomic",
      "unresolvedAtomic",
      "totalExposureAtomic",
      "deficitAtomic",
      "balanceAtomic",
    ];
    for (const [name, entry] of entries) {
      if (entry.audience !== "provider_minimal") continue;
      for (const field of forbidden) {
        expect(Object.hasOwn(entry.fields, field), `${name}.${field}`).toBe(
          false,
        );
      }
    }
  });

  it("classifies the provider shapes as provider_minimal", () => {
    for (const name of [
      "providerIntrospectBody",
      "providerClaimBody",
      "providerAttemptStatusRequest",
      "providerIntrospection",
      "providerClaimData",
      "providerAttemptStatusData",
    ] as const) {
      expect(COMMERCE_GRANT_WIRE_FIELD_CLASSES[name].audience).toBe(
        "provider_minimal",
      );
    }
  });

  it("names a grant token in exactly the three token-bearing shapes", () => {
    const bearing = entries
      .filter(([, entry]) => Object.hasOwn(entry.fields, "grantToken"))
      .map(([name]) => name)
      .sort();
    expect(bearing).toEqual([
      "issueData",
      "providerClaimBody",
      "providerIntrospectBody",
      "replaceData",
    ]);
  });

  it("keeps every status, detail and outcome class token-free", () => {
    for (const name of [
      "detail",
      "detailRequest",
      "mutationStatus",
      "mutationOutcome",
      "receipt",
      "revokeData",
      "providerAttemptStatusData",
      "providerIntrospection",
      "providerClaimData",
    ] as const) {
      expect(
        Object.hasOwn(COMMERCE_GRANT_WIRE_FIELD_CLASSES[name].fields, "grantToken"),
        name,
      ).toBe(false);
    }
  });

  it("is frozen at every layer", () => {
    expect(Object.isFrozen(COMMERCE_GRANT_WIRE_FIELD_CLASSES)).toBe(true);
    for (const [, entry] of entries) {
      expect(Object.isFrozen(entry)).toBe(true);
      expect(Object.isFrozen(entry.fields)).toBe(true);
    }
  });
});

describe("structural key inventories", () => {
  it("declares the exact key set of every request and body", () => {
    expect(declaredKeys(CommerceGrantIssueBodySchema)).toEqual([
      "actionId",
      "mutationId",
    ]);
    expect(declaredKeys(CommerceGrantReplaceBodySchema)).toEqual([
      "mutationId",
    ]);
    expect(declaredKeys(CommerceGrantRevokeBodySchema)).toEqual(["mutationId"]);
    expect(declaredKeys(CommerceGrantProviderIntrospectBodySchema)).toEqual([
      "grantToken",
    ]);
    expect(declaredKeys(CommerceGrantProviderClaimBodySchema)).toEqual([
      "attemptId",
      "expectedActionId",
      "grantToken",
      "mutationId",
    ]);
  });

  it("gives the issue/replace replay arm no key able to carry a token", () => {
    expect(declaredUnionKeys(CommerceGrantIssueDataSchema)).toEqual([
      ["grantToken", "metadata", "receipt", "replayed"],
      ["metadata", "receipt", "replayed"],
    ]);
    expect(declaredUnionKeys(CommerceGrantReplaceDataSchema)).toEqual([
      ["grantToken", "metadata", "receipt", "replayed"],
      ["metadata", "receipt", "replayed"],
    ]);
  });

  it("declares no token-capable key on any status, detail or outcome shape", () => {
    const tokenish = [
      "grantToken",
      "token",
      "rawToken",
      "secret",
      "grantTokenHash",
      "tokenHash",
      "salt",
      "pepper",
      "credential",
    ];
    const objectShapes: readonly [string, unknown][] = [
      ["detail", CommerceGrantDetailSchema],
      ["revokeData", CommerceGrantRevokeDataSchema],
      ["claimData", CommerceGrantProviderClaimDataSchema],
      ["introspection", CommerceGrantProviderIntrospectionSchema],
      ["attemptStatusData", CommerceGrantProviderAttemptStatusDataSchema],
      ["issueReceipt", CommerceGrantIssueReceiptSchema],
      ["replaceReceipt", CommerceGrantReplaceReceiptSchema],
      ["claimReceipt", CommerceGrantClaimReceiptSchema],
      ["revokeReceipt", CommerceGrantRevokeReceiptSchema],
    ];
    for (const [name, schema] of objectShapes) {
      const keys = declaredKeys(schema);
      for (const key of tokenish) {
        expect(keys.includes(key), `${name}.${key}`).toBe(false);
      }
    }
    const unionShapes: readonly [string, unknown][] = [
      ["agentStatus", CommerceGrantAgentMutationStatusSchema],
      ["humanStatus", CommerceGrantHumanMutationStatusSchema],
      ["outcome", CommerceGrantMutationOutcomeSchema],
      ["receiptUnion", CommerceGrantMutationReceiptSchema],
    ];
    for (const [name, schema] of unionShapes) {
      for (const keys of declaredUnionKeys(schema)) {
        for (const key of tokenish) {
          expect(keys.includes(key), `${name}.${key}`).toBe(false);
        }
      }
    }
  });

  it("declares the exact arms of the status and outcome unions", () => {
    expect(declaredUnionKeys(CommerceGrantAgentMutationStatusSchema)).toEqual([
      ["status"],
      ["receipt", "status"],
    ]);
    expect(declaredUnionKeys(CommerceGrantHumanMutationStatusSchema)).toEqual([
      ["status"],
      ["receipt", "status"],
    ]);
    expect(declaredUnionKeys(CommerceGrantMutationOutcomeSchema)).toEqual([
      ["mutationId", "outcome", "receipt"],
      ["mutationId", "outcome"],
      ["mutationId", "outcome"],
    ]);
  });

  it("declares the exact key set of the detail and revoke shapes", () => {
    expect(declaredKeys(CommerceGrantDetailSchema)).toEqual([
      "grantId",
      "item",
      "organizationId",
    ]);
    expect(declaredKeys(CommerceGrantRevokeDataSchema)).toEqual([
      "actionStatus",
      "metadata",
      "receipt",
      "released",
      "replayed",
    ]);
    expect(declaredKeys(CommerceGrantProviderAttemptStatusDataSchema)).toEqual([
      "attemptId",
      "item",
    ]);
    expect(declaredKeys(CommerceGrantProviderClaimDataSchema)).toEqual([
      "attemptId",
      "claimDigest",
      "claimedAt",
      "item",
      "receipt",
      "replayed",
    ]);
  });
});
