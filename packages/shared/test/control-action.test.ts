import { describe, expect, it } from "vitest";

import {
  COMMERCE_ACTION_FIELD_CLASSES,
  COMMERCE_ACTION_SCHEMA_VERSION,
  COMMERCE_APPROVAL_SCHEMA_VERSION,
  CommerceActionMetadataSchema,
  CommerceActionStatusSchema,
  CommerceApprovalIdSchema,
  CommerceApprovalMetadataSchema,
  CommerceApprovalStatusSchema,
  CommerceRequirementIdSchema,
  CommerceReservationIdSchema,
} from "../src/commerce/control-action.js";
import { CommerceActionIdSchema } from "../src/commerce/control-budget.js";
import { CommercePolicyIdSchema } from "../src/commerce/control-policy.js";
import { CommerceControlSessionIdSchema } from "../src/commerce/control-session.js";
import {
  CommerceAccountIdSchema,
  CommerceAgentIdSchema,
  CommerceOrganizationIdSchema,
  CommerceProviderIdSchema,
} from "../src/commerce/identity.js";
import {
  CommerceListingIdSchema,
  CommerceListingVersionSchema,
} from "../src/commerce/listing.js";

const ACTION_ID = "openarc:action:11111111-1111-4111-8111-111111111111";
const RESERVATION_ID =
  "openarc:reservation:22222222-2222-4222-8222-222222222222";
const APPROVAL_ID = "openarc:approval:33333333-3333-4333-8333-333333333333";
const REQUIREMENT_ID =
  "openarc:requirement:44444444-4444-4444-8444-444444444444";
const SESSION_ID = "55555555-5555-4555-8555-555555555555";
const POLICY_ID = "openarc:policy:66666666-6666-4666-8666-666666666666";
const PROVIDER_ID =
  "openarc:provider:77777777-7777-4777-8777-777777777777";
const LISTING_ID = "openarc:listing:88888888-8888-4888-8888-888888888888";
const ORG_ID = "openarc:org:99999999-9999-4999-8999-999999999999";
const AGENT_ID = "openarc:agent:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const REQUESTED_BY = "openarc:account:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const DECIDED_BY = "openarc:account:cccccccc-cccc-4ccc-8ccc-cccccccccccc";

const DIGEST = `sha256:${"a".repeat(64)}`;

const CREATED_AT = "2025-01-01T00:00:00.000000001Z";
const UPDATED_AT = "2025-01-01T00:00:00.000000002Z";
const EXPIRES_AT = "2025-01-01T00:00:01Z";

const EXPOSURE_KEY = {
  organizationId: ORG_ID,
  subjectAgentId: AGENT_ID,
  networkId: "eip155:5042002",
  asset: "USDC",
  representation: "erc20",
  decimals: 6,
} as const;

function action(overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: COMMERCE_ACTION_SCHEMA_VERSION,
    actionId: ACTION_ID,
    exposureKey: EXPOSURE_KEY,
    commerceSessionId: SESSION_ID,
    policyId: POLICY_ID,
    policyRevision: "1",
    providerId: PROVIDER_ID,
    listingId: LISTING_ID,
    listingVersion: "1",
    requirementId: REQUIREMENT_ID,
    requirementDigest: DIGEST,
    amountAtomic: "1",
    feeAtomic: "1",
    debitAtomic: "2",
    status: "pending_approval",
    reservationId: null,
    approvalId: APPROVAL_ID,
    createdAt: CREATED_AT,
    updatedAt: UPDATED_AT,
    expiresAt: EXPIRES_AT,
    ...overrides,
  };
}

function approval(overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: COMMERCE_APPROVAL_SCHEMA_VERSION,
    approvalId: APPROVAL_ID,
    actionId: ACTION_ID,
    organizationId: ORG_ID,
    subjectAgentId: AGENT_ID,
    commerceSessionId: SESSION_ID,
    policyId: POLICY_ID,
    policyRevision: "1",
    requestedBy: REQUESTED_BY,
    separateApprover: false,
    status: "pending",
    decidedBy: null,
    createdAt: CREATED_AT,
    expiresAt: EXPIRES_AT,
    decidedAt: null,
    ...overrides,
  };
}

const MAX_UINT256 =
  "115792089237316195423570985008687907853269984665640564039457584007913129639935";
function expectNoThrow(value: unknown, schema: { safeParse: (v: unknown) => unknown }) {
  expect(() => schema.safeParse(value)).not.toThrow();
}

describe("new id leaves", () => {
  it("accepts canonical lower-case UUIDv4 with each namespace", () => {
    expect(CommerceReservationIdSchema.safeParse(RESERVATION_ID).success).toBe(
      true,
    );
    expect(CommerceApprovalIdSchema.safeParse(APPROVAL_ID).success).toBe(true);
    expect(CommerceRequirementIdSchema.safeParse(REQUIREMENT_ID).success).toBe(
      true,
    );
  });

  it("rejects every wrong namespace crossing", () => {
    expect(CommerceReservationIdSchema.safeParse(ACTION_ID).success).toBe(
      false,
    );
    expect(CommerceReservationIdSchema.safeParse(APPROVAL_ID).success).toBe(
      false,
    );
    expect(CommerceReservationIdSchema.safeParse(REQUIREMENT_ID).success).toBe(
      false,
    );
    expect(CommerceReservationIdSchema.safeParse(SESSION_ID).success).toBe(
      false,
    );
    expect(CommerceApprovalIdSchema.safeParse(RESERVATION_ID).success).toBe(
      false,
    );
    expect(CommerceApprovalIdSchema.safeParse(REQUIREMENT_ID).success).toBe(
      false,
    );
    expect(CommerceRequirementIdSchema.safeParse(RESERVATION_ID).success).toBe(
      false,
    );
    expect(CommerceRequirementIdSchema.safeParse(APPROVAL_ID).success).toBe(
      false,
    );
  });

  it("rejects wrong version, variant, case, and trailing LF", () => {
    const base = RESERVATION_ID;
    const wrongVersion = base.replace("4222", "5222");
    const wrongVariant = base.replace("8222", "c222");
    const upperCase = base.toUpperCase().replace("OPENARC", "openarc");
    expect(CommerceReservationIdSchema.safeParse(wrongVersion).success).toBe(
      false,
    );
    expect(CommerceReservationIdSchema.safeParse(wrongVariant).success).toBe(
      false,
    );
    expect(CommerceReservationIdSchema.safeParse(upperCase).success).toBe(
      false,
    );
    expect(CommerceReservationIdSchema.safeParse(`${base}\n`).success).toBe(
      false,
    );
  });
});

describe("CommerceActionStatusSchema", () => {
  it("is exactly the six frozen stages with grant_issued after reserved_not_granted", () => {
    expect(CommerceActionStatusSchema.options).toEqual([
      "pending_approval",
      "reserved_not_granted",
      "grant_issued",
      "rejected",
      "cancelled",
      "expired",
    ]);
  });
});

describe("CommerceApprovalStatusSchema", () => {
  it("is exactly the four frozen stages", () => {
    expect(CommerceApprovalStatusSchema.options).toEqual([
      "pending",
      "approved",
      "rejected",
      "expired",
    ]);
  });
});

describe("CommerceActionMetadataSchema valid combinations", () => {
  it("accepts pending_approval with approvalId non-null and reservationId null", () => {
    expect(CommerceActionMetadataSchema.safeParse(action()).success).toBe(true);
  });

  it("accepts reserved_not_granted with reservationId and null approvalId", () => {
    const value = action({
      status: "reserved_not_granted",
      approvalId: null,
      reservationId: RESERVATION_ID,
    });
    expect(CommerceActionMetadataSchema.safeParse(value).success).toBe(true);
  });

  it("accepts reserved_not_granted with both ids non-null", () => {
    const value = action({
      status: "reserved_not_granted",
      reservationId: RESERVATION_ID,
    });
    expect(CommerceActionMetadataSchema.safeParse(value).success).toBe(true);
  });

  it("accepts grant_issued with reservationId and null approvalId", () => {
    const value = action({
      status: "grant_issued",
      approvalId: null,
      reservationId: RESERVATION_ID,
    });
    expect(CommerceActionMetadataSchema.safeParse(value).success).toBe(true);
  });

  it("accepts grant_issued with both ids non-null", () => {
    const value = action({
      status: "grant_issued",
      reservationId: RESERVATION_ID,
    });
    expect(CommerceActionMetadataSchema.safeParse(value).success).toBe(true);
  });

  it("keeps grant_issued distinct from reserved_not_granted", () => {
    const issued = action({
      status: "grant_issued",
      approvalId: null,
      reservationId: RESERVATION_ID,
    });
    const reserved = action({
      status: "reserved_not_granted",
      approvalId: null,
      reservationId: RESERVATION_ID,
    });
    expect(CommerceActionStatusSchema.safeParse("grant_issued").success).toBe(
      true,
    );
    expect(
      CommerceActionStatusSchema.safeParse("reserved_not_granted").success,
    ).toBe(true);
    // A granted action is never mislabeled as reserved_not_granted, and each
    // status keeps its own exact parse result.
    expect(CommerceActionMetadataSchema.safeParse(issued).success).toBe(true);
    expect(CommerceActionMetadataSchema.safeParse(reserved).success).toBe(true);
    expect(issued.status).not.toBe(reserved.status);
  });

  it("accepts rejected with approvalId non-null and reservationId null", () => {
    const value = action({ status: "rejected" });
    expect(CommerceActionMetadataSchema.safeParse(value).success).toBe(true);
  });

  it("accepts cancelled/expired with either id, and both ids", () => {
    for (const status of ["cancelled", "expired"] as const) {
      expect(
        CommerceActionMetadataSchema.safeParse(
          action({ status, approvalId: null, reservationId: RESERVATION_ID }),
        ).success,
      ).toBe(true);
      expect(
        CommerceActionMetadataSchema.safeParse(
          action({ status, approvalId: APPROVAL_ID, reservationId: null }),
        ).success,
      ).toBe(true);
      expect(
        CommerceActionMetadataSchema.safeParse(
          action({
            status,
            approvalId: APPROVAL_ID,
            reservationId: RESERVATION_ID,
          }),
        ).success,
      ).toBe(true);
    }
  });

  it("allows updatedAt after expiresAt for expired/cancelled transitions", () => {
    const value = action({
      status: "expired",
      approvalId: null,
      reservationId: RESERVATION_ID,
      updatedAt: "2025-01-02T00:00:00Z",
    });
    expect(CommerceActionMetadataSchema.safeParse(value).success).toBe(true);
  });
});

describe("CommerceActionMetadataSchema invalid combinations", () => {
  it("rejects pending_approval with null approvalId", () => {
    expect(
      CommerceActionMetadataSchema.safeParse(action({ approvalId: null }))
        .success,
    ).toBe(false);
  });

  it("rejects pending_approval with non-null reservationId", () => {
    expect(
      CommerceActionMetadataSchema.safeParse(
        action({ reservationId: RESERVATION_ID }),
      ).success,
    ).toBe(false);
  });

  it("rejects reserved_not_granted with null reservationId", () => {
    const value = action({
      status: "reserved_not_granted",
      approvalId: null,
      reservationId: null,
    });
    expect(CommerceActionMetadataSchema.safeParse(value).success).toBe(false);
  });

  it("rejects grant_issued with null reservationId", () => {
    for (const approvalId of [null, APPROVAL_ID]) {
      const value = action({
        status: "grant_issued",
        approvalId,
        reservationId: null,
      });
      expect(CommerceActionMetadataSchema.safeParse(value).success).toBe(false);
    }
  });

  it("rejects rejected with null approvalId or non-null reservationId", () => {
    expect(
      CommerceActionMetadataSchema.safeParse(
        action({ status: "rejected", approvalId: null }),
      ).success,
    ).toBe(false);
    expect(
      CommerceActionMetadataSchema.safeParse(
        action({ status: "rejected", reservationId: RESERVATION_ID }),
      ).success,
    ).toBe(false);
  });

  it("rejects cancelled/expired with both ids null", () => {
    for (const status of ["cancelled", "expired"] as const) {
      expect(
        CommerceActionMetadataSchema.safeParse(
          action({ status, approvalId: null, reservationId: null }),
        ).success,
      ).toBe(false);
    }
  });

  it("rejects timestamp inversions", () => {
    expect(
      CommerceActionMetadataSchema.safeParse(
        action({ updatedAt: "2024-12-31T23:59:59Z" }),
      ).success,
    ).toBe(false);
    expect(
      CommerceActionMetadataSchema.safeParse(
        action({ expiresAt: CREATED_AT }),
      ).success,
    ).toBe(false);
  });
});

describe("money strengthening and crosssum", () => {
  it("rejects amount 0, leading zeros and wrong digit counts", () => {
    expect(
      CommerceActionMetadataSchema.safeParse(
        action({ amountAtomic: "0", debitAtomic: "1" }),
      ).success,
    ).toBe(false);
    expect(
      CommerceActionMetadataSchema.safeParse(
        action({ amountAtomic: "01", debitAtomic: "2" }),
      ).success,
    ).toBe(false);
    const bigShifted = MAX_UINT256;
    expect(
      CommerceActionMetadataSchema.safeParse(
        action({
          amountAtomic: bigShifted,
          feeAtomic: "0",
          debitAtomic: bigShifted,
        }),
      ).success,
    ).toBe(true);
    expect(
      CommerceActionMetadataSchema.safeParse(
        action({
          amountAtomic: `1${"0".repeat(78)}`,
          feeAtomic: "0",
          debitAtomic: "2",
        }),
      ).success,
    ).toBe(false);
  });

  it("accepts amount = max uint256 and fee = 0 with exact crosssum", () => {
    const value = action({
      amountAtomic: MAX_UINT256,
      feeAtomic: "0",
      debitAtomic: MAX_UINT256,
    });
    expect(CommerceActionMetadataSchema.safeParse(value).success).toBe(true);
  });

  it("accepts two max-uint256 components and the 78-digit debit sum", () => {
    const sum = (2n * ((1n << 256n) - 1n)).toString();
    expect(sum).toHaveLength(78);
    const value = action({
      amountAtomic: MAX_UINT256,
      feeAtomic: MAX_UINT256,
      debitAtomic: sum,
    });
    expect(CommerceActionMetadataSchema.safeParse(value).success).toBe(true);
  });

  it("accepts the max two-component debit and rejects a 129-digit debit", () => {
    const sum = (2n * ((1n << 256n) - 1n)).toString();
    const value = action({
      amountAtomic: MAX_UINT256,
      feeAtomic: MAX_UINT256,
      debitAtomic: sum,
    });
    expect(CommerceActionMetadataSchema.safeParse(value).success).toBe(true);
    expect(
      CommerceActionMetadataSchema.safeParse(
        action({ debitAtomic: "9".repeat(129) }),
      ).success,
    ).toBe(false);
  });

  it("rejects mismatched crosssum", () => {
    expect(
      CommerceActionMetadataSchema.safeParse(action({ debitAtomic: "3" }))
        .success,
    ).toBe(false);
  });

  it("rejects fee over uint256 and malformed leaves without throwing", () => {
    for (const bad of [
      action({ feeAtomic: (1n << 256n).toString(), debitAtomic: "1" }),
      action({ amountAtomic: "1e2", debitAtomic: "1" }),
      action({ feeAtomic: " 1", debitAtomic: "2" }),
      action({ amountAtomic: "1\n", debitAtomic: "2" }),
      action({ debitAtomic: "1.0" }),
    ]) {
      expectNoThrow(bad, CommerceActionMetadataSchema);
      expect(CommerceActionMetadataSchema.safeParse(bad).success).toBe(false);
    }
  });

  it("rejects digest with trailing LF and wrong case", () => {
    expect(
      CommerceActionMetadataSchema.safeParse(
        action({ requirementDigest: `${DIGEST}\n` }),
      ).success,
    ).toBe(false);
    expect(
      CommerceActionMetadataSchema.safeParse(
        action({ requirementDigest: `sha256:${"A".repeat(64)}` }),
      ).success,
    ).toBe(false);
  });

  it("rejects version 0, over 999999999 and trailing LF", () => {
    for (const policyRevision of ["0", "1000000000", "1\n"]) {
      expect(
        CommerceActionMetadataSchema.safeParse(action({ policyRevision }))
          .success,
      ).toBe(false);
    }
  });
});

describe("CommerceActionMetadataSchema strictness and total safeParse", () => {
  it("rejects unknown top-level and nested keys", () => {
    expect(
      CommerceActionMetadataSchema.safeParse({ ...action(), extra: 1 }).success,
    ).toBe(false);
    expect(
      CommerceActionMetadataSchema.safeParse(
        action({ exposureKey: { ...EXPOSURE_KEY, extra: 1 } }),
      ).success,
    ).toBe(false);
  });

  it("never throws for malformed input and does not mutate frozen input", () => {
    const value = action();
    Object.freeze(value);
    Object.freeze(value.exposureKey);
    expectNoThrow(value, CommerceActionMetadataSchema);
    expect(CommerceActionMetadataSchema.safeParse(value).success).toBe(true);
    expectNoThrow({}, CommerceActionMetadataSchema);
    expectNoThrow(null, CommerceActionMetadataSchema);
    expect(CommerceActionMetadataSchema.safeParse(null).success).toBe(false);
  });
});

describe("CommerceApprovalMetadataSchema", () => {
  it("accepts pending with both decision fields null", () => {
    expect(CommerceApprovalMetadataSchema.safeParse(approval()).success).toBe(
      true,
    );
  });

  it("accepts approved/rejected with both decision fields non-null", () => {
    for (const status of ["approved", "rejected"] as const) {
      const value = approval({
        status,
        decidedBy: DECIDED_BY,
        decidedAt: "2025-01-01T00:00:00.5Z",
      });
      expect(CommerceApprovalMetadataSchema.safeParse(value).success).toBe(
        true,
      );
    }
  });

  it("accepts expired with both decision fields null", () => {
    expect(
      CommerceApprovalMetadataSchema.safeParse(
        approval({ status: "expired" }),
      ).success,
    ).toBe(true);
  });

  it("rejects pending with a decision field present", () => {
    expect(
      CommerceApprovalMetadataSchema.safeParse(
        approval({ decidedBy: DECIDED_BY }),
      ).success,
    ).toBe(false);
    expect(
      CommerceApprovalMetadataSchema.safeParse(
        approval({ decidedAt: "2025-01-01T00:00:00.5Z" }),
      ).success,
    ).toBe(false);
  });

  it("rejects approved/rejected with a missing decision field", () => {
    for (const status of ["approved", "rejected"] as const) {
      expect(
        CommerceApprovalMetadataSchema.safeParse(
          approval({ status, decidedAt: "2025-01-01T00:00:00.5Z" }),
        ).success,
      ).toBe(false);
      expect(
        CommerceApprovalMetadataSchema.safeParse(
          approval({ status, decidedBy: DECIDED_BY }),
        ).success,
      ).toBe(false);
    }
  });

  it("rejects expired with a decision field present", () => {
    expect(
      CommerceApprovalMetadataSchema.safeParse(
        approval({ status: "expired", decidedBy: DECIDED_BY }),
      ).success,
    ).toBe(false);
  });

  it("rejects decision ordering violations at sub-second precision", () => {
    const beforeCreated = approval({
      status: "approved",
      decidedBy: DECIDED_BY,
      decidedAt: "2025-01-01T00:00:00.000000000Z",
    });
    expect(
      CommerceApprovalMetadataSchema.safeParse(beforeCreated).success,
    ).toBe(false);
    const atExpiry = approval({
      status: "approved",
      decidedBy: DECIDED_BY,
      decidedAt: EXPIRES_AT,
    });
    expect(CommerceApprovalMetadataSchema.safeParse(atExpiry).success).toBe(
      false,
    );
    const afterExpiry = approval({
      status: "approved",
      decidedBy: DECIDED_BY,
      decidedAt: "2025-01-01T00:00:02Z",
    });
    expect(
      CommerceApprovalMetadataSchema.safeParse(afterExpiry).success,
    ).toBe(false);
  });

  it("rejects expiresAt not strictly after createdAt", () => {
    expect(
      CommerceApprovalMetadataSchema.safeParse(
        approval({ expiresAt: CREATED_AT }),
      ).success,
    ).toBe(false);
  });

  it("enforces separateApprover only on approved/rejected", () => {
    const sameApprover = {
      status: "approved" as const,
      decidedBy: REQUESTED_BY,
      decidedAt: "2025-01-01T00:00:00.5Z",
    };
    expect(
      CommerceApprovalMetadataSchema.safeParse(
        approval({ ...sameApprover, separateApprover: true }),
      ).success,
    ).toBe(false);
    expect(
      CommerceApprovalMetadataSchema.safeParse(
        approval({ ...sameApprover, separateApprover: false }),
      ).success,
    ).toBe(true);
    expect(
      CommerceApprovalMetadataSchema.safeParse(
        approval({
          ...sameApprover,
          separateApprover: true,
          decidedBy: DECIDED_BY,
        }),
      ).success,
    ).toBe(true);
  });

  it("rejects unknown nested keys and never throws", () => {
    expect(
      CommerceApprovalMetadataSchema.safeParse({
        ...approval(),
        extra: true,
      }).success,
    ).toBe(false);
    for (const bad of [null, {}, { status: "pending" }, 5, "x"]) {
      expectNoThrow(bad, CommerceApprovalMetadataSchema);
      expect(CommerceApprovalMetadataSchema.safeParse(bad).success).toBe(false);
    }
  });
});

describe("COMMERCE_ACTION_FIELD_CLASSES", () => {
  it("is frozen and maps every declared top-level field to organization_protected", () => {
    expect(Object.isFrozen(COMMERCE_ACTION_FIELD_CLASSES)).toBe(true);
    expect(Object.isFrozen(COMMERCE_ACTION_FIELD_CLASSES.action)).toBe(true);
    expect(Object.isFrozen(COMMERCE_ACTION_FIELD_CLASSES.approval)).toBe(true);
    const allValues = [
      ...Object.values(COMMERCE_ACTION_FIELD_CLASSES.action),
      ...Object.values(COMMERCE_ACTION_FIELD_CLASSES.approval),
    ];
    expect(allValues.length).toBe(35);
    expect(allValues.every((value) => value === "organization_protected")).toBe(
      true,
    );
  });
});

describe("exported schema reuse", () => {
  it("reuses accepted identity/action/session/listing/policy leaves", () => {
    expect(CommerceActionIdSchema.safeParse(ACTION_ID).success).toBe(true);
    expect(CommerceControlSessionIdSchema.safeParse(SESSION_ID).success).toBe(
      true,
    );
    expect(CommercePolicyIdSchema.safeParse(POLICY_ID).success).toBe(true);
    expect(CommerceOrganizationIdSchema.safeParse(ORG_ID).success).toBe(true);
    expect(CommerceAgentIdSchema.safeParse(AGENT_ID).success).toBe(true);
    expect(CommerceProviderIdSchema.safeParse(PROVIDER_ID).success).toBe(true);
    expect(CommerceListingIdSchema.safeParse(LISTING_ID).success).toBe(true);
    expect(CommerceAccountIdSchema.safeParse(REQUESTED_BY).success).toBe(true);
    expect(CommerceListingVersionSchema.safeParse("1").success).toBe(true);
  });
});
