import { describe, expect, expectTypeOf, it } from "vitest";

import {
  CommerceActionAgentDetailRequestSchema,
  CommerceActionAgentMutationRequestSchema,
  CommerceActionAuthorizeBodySchema,
  CommerceActionCancelBodySchema,
  CommerceActionDecisionBodySchema,
  CommerceActionDetailRequestSchema,
  CommerceActionDetailResponseSchema,
  CommerceActionDetailSchema,
  CommerceActionHumanMutationRequestSchema,
  CommerceActionListRequestSchema,
  CommerceActionMutationDataResponseSchema,
  CommerceActionMutationDataSchema,
  CommerceActionMutationReceiptSchema,
  CommerceActionMutationStatusResponseSchema,
  CommerceActionMutationStatusSchema,
  CommerceActionPageResponseSchema,
  CommerceActionPageSchema,
  CommerceApprovalDetailRequestSchema,
  CommerceApprovalDetailResponseSchema,
  CommerceApprovalDetailSchema,
  CommerceApprovalListRequestSchema,
  CommerceApprovalPageResponseSchema,
  CommerceApprovalPageSchema,
  CommerceExposureDataResponseSchema,
  CommerceExposureDataSchema,
  CommerceExposureRequestSchema,
  CommerceExposureViewSchema,
  COMMERCE_ACTION_WIRE_FIELD_CLASSES,
  type CommerceActionMutationReceipt,
  type CommerceExposureView,
} from "../src/index.js";

const V4 = "12345678-1234-4234-8123-123456789abc";
const V5 = "87654321-4321-4321-b321-cba987654321";
const ACTION_ID = `openarc:action:${V4}`;
const ACTION_ID_B = `openarc:action:${V5}`;
const APPROVAL_ID = `openarc:approval:${V4}`;
const APPROVAL_ID_B = `openarc:approval:${V5}`;
const REQUIREMENT_ID = `openarc:requirement:${V4}`;
const ORG = `openarc:org:${V4}`;
const ORG_B = `openarc:org:${V5}`;
const AGENT = `openarc:agent:${V4}`;
const AGENT_B = `openarc:agent:${V5}`;
const POLICY_ID = `openarc:policy:${V4}`;
const POLICY_ID_B = `openarc:policy:${V5}`;
const PROVIDER_ID = `openarc:provider:${V4}`;
const LISTING_ID = `openarc:listing:${V4}`;
const SESSION_ID = V4;
const MUTATION = V4;
const ACCOUNT = `openarc:account:${V4}`;
const DIGEST = `sha256:${"a".repeat(64)}`;
const CREATED_AT = "2025-01-01T00:00:00.000000Z";
const LATER_AT = "2025-02-01T00:00:00.000000Z";
const EXPIRES_AT = "2025-03-01T00:00:00.000000Z";

const META = {
  schemaVersion: "openarc.api.v2" as const,
  requestId: "9f1c2d34-5e6a-4b7c-8d9e-0f1a2b3c4d5e",
  buildSha: "0123456789abcdef0123456789abcdef01234567",
};

function action(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: "openarc.control.action.v1",
    actionId: ACTION_ID,
    exposureKey: {
      organizationId: ORG,
      subjectAgentId: AGENT,
      networkId: "eip155:5042002",
      asset: "USDC",
      representation: "erc20",
      decimals: 6,
    },
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
    updatedAt: LATER_AT,
    expiresAt: EXPIRES_AT,
    ...overrides,
  };
}

function approval(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: "openarc.control.approval.v1",
    approvalId: APPROVAL_ID,
    actionId: ACTION_ID,
    organizationId: ORG,
    subjectAgentId: AGENT,
    commerceSessionId: SESSION_ID,
    policyId: POLICY_ID,
    policyRevision: "1",
    requestedBy: ACCOUNT,
    separateApprover: false,
    status: "pending",
    decidedBy: null,
    createdAt: CREATED_AT,
    expiresAt: EXPIRES_AT,
    decidedAt: null,
    ...overrides,
  };
}

function receipt(
  operation: string,
  resourceId: string = ACTION_ID,
): Record<string, unknown> {
  return {
    mutationId: MUTATION,
    operation,
    resourceType: "commerce_action",
    resourceId,
    committedAt: LATER_AT,
  };
}

function view(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    organizationId: ORG,
    subjectAgentId: AGENT,
    policyId: POLICY_ID,
    policyRevision: "1",
    networkId: "eip155:5042002",
    asset: "USDC",
    representation: "erc20",
    decimals: 6,
    windowSeconds: null,
    committedAtomic: "0",
    unresolvedAtomic: "0",
    totalExposureAtomic: "0",
    availableAtomic: null,
    deficitAtomic: "0",
    asOf: LATER_AT,
    ...overrides,
  };
}

function envelope(data: unknown) {
  return { ok: true, data, meta: META };
}

describe("write bodies", () => {
  it("parses the authorize body strictly and without mutating input", () => {
    const input = {
      mutationId: MUTATION,
      actionId: ACTION_ID,
      requirementId: REQUIREMENT_ID,
    };
    const snapshot = structuredClone(input);
    expect(CommerceActionAuthorizeBodySchema.safeParse(input).success).toBe(true);
    expect(input).toEqual(snapshot);
    expect(
      CommerceActionAuthorizeBodySchema.safeParse({
        mutationId: MUTATION,
        actionId: ACTION_ID,
        requirementId: `${REQUIREMENT_ID}\n`,
      }).success,
    ).toBe(false);
  });

  it.each([
    ["missing actionId", { mutationId: MUTATION, requirementId: REQUIREMENT_ID }],
    ["missing requirementId", { mutationId: MUTATION, actionId: ACTION_ID }],
    [
      "unknown operation",
      {
        mutationId: MUTATION,
        actionId: ACTION_ID,
        requirementId: REQUIREMENT_ID,
        operation: "control.commerce_action.authorize",
      },
    ],
  ])("rejects authorize body %s", (_label, value) => {
    expect(CommerceActionAuthorizeBodySchema.safeParse(value).success).toBe(false);
  });

  it("accepts only mutationId for decision/cancel and rejects identity overrides", () => {
    expect(
      CommerceActionDecisionBodySchema.safeParse({ mutationId: MUTATION }).success,
    ).toBe(true);
    expect(
      CommerceActionCancelBodySchema.safeParse({ mutationId: MUTATION }).success,
    ).toBe(true);
    for (const value of [
      { mutationId: MUTATION, actionId: ACTION_ID },
      { mutationId: MUTATION, approvalId: APPROVAL_ID },
      { mutationId: MUTATION, organizationId: ORG },
      { mutationId: MUTATION, operation: "approve" },
      { mutationId: MUTATION, decision: "approve" },
    ]) {
      expect(CommerceActionDecisionBodySchema.safeParse(value).success).toBe(false);
    }
    expect(
      CommerceActionCancelBodySchema.safeParse({
        mutationId: MUTATION,
        actionId: ACTION_ID,
      }).success,
    ).toBe(false);
  });
});

describe("read requests", () => {
  it("accepts minimal and bounded list requests", () => {
    expect(
      CommerceActionListRequestSchema.safeParse({ organizationId: ORG }).success,
    ).toBe(true);
    expect(
      CommerceActionListRequestSchema.safeParse({
        organizationId: ORG,
        afterActionId: ACTION_ID,
        limit: "50",
      }).success,
    ).toBe(true);
    expect(
      CommerceApprovalListRequestSchema.safeParse({
        organizationId: ORG,
        afterApprovalId: APPROVAL_ID,
        limit: "1",
      }).success,
    ).toBe(true);
  });

  it.each(["0", "51", "01", "1.0", "1\n", "1e1", " 1", "+1", ""])(
    "rejects list limit %s",
    (limit) => {
      expect(
        CommerceActionListRequestSchema.safeParse({ organizationId: ORG, limit })
          .success,
      ).toBe(false);
      expect(
        CommerceApprovalListRequestSchema.safeParse({ organizationId: ORG, limit })
          .success,
      ).toBe(false);
    },
  );

  it.each(["afterActionId", "limit"] as const)(
    "rejects explicit undefined %s",
    (key) => {
      expect(
        CommerceActionListRequestSchema.safeParse({
          organizationId: ORG,
          [key]: undefined,
        }).success,
      ).toBe(false);
    },
  );

  it("rejects unknown filters on list requests", () => {
    expect(
      CommerceActionListRequestSchema.safeParse({
        organizationId: ORG,
        status: "pending_approval",
      }).success,
    ).toBe(false);
    expect(
      CommerceApprovalListRequestSchema.safeParse({
        organizationId: ORG,
        status: "pending",
      }).success,
    ).toBe(false);
  });

  it("accepts human and agent detail/mutation request shapes", () => {
    expect(
      CommerceActionDetailRequestSchema.safeParse({
        organizationId: ORG,
        actionId: ACTION_ID,
      }).success,
    ).toBe(true);
    expect(
      CommerceActionAgentDetailRequestSchema.safeParse({ actionId: ACTION_ID }).success,
    ).toBe(true);
    expect(
      CommerceApprovalDetailRequestSchema.safeParse({
        organizationId: ORG,
        approvalId: APPROVAL_ID,
      }).success,
    ).toBe(true);
    expect(
      CommerceActionHumanMutationRequestSchema.safeParse({
        organizationId: ORG,
        mutationId: MUTATION,
      }).success,
    ).toBe(true);
    expect(
      CommerceActionAgentMutationRequestSchema.safeParse({ mutationId: MUTATION })
        .success,
    ).toBe(true);
  });

  it("does not let agent requests accept a human organization id", () => {
    expect(
      CommerceActionAgentDetailRequestSchema.safeParse({
        actionId: ACTION_ID,
        organizationId: ORG,
      }).success,
    ).toBe(false);
    expect(
      CommerceActionAgentMutationRequestSchema.safeParse({
        mutationId: MUTATION,
        organizationId: ORG,
      }).success,
    ).toBe(false);
  });

  it("accepts the exposure request and rejects unknown keys", () => {
    expect(
      CommerceExposureRequestSchema.safeParse({
        organizationId: ORG,
        subjectAgentId: AGENT,
        policyId: POLICY_ID,
      }).success,
    ).toBe(true);
    expect(
      CommerceExposureRequestSchema.safeParse({
        organizationId: ORG,
        subjectAgentId: AGENT,
        policyId: POLICY_ID,
        windowSeconds: "100",
      }).success,
    ).toBe(false);
  });
});

describe("CommerceActionMutationReceiptSchema", () => {
  it.each([
    "control.commerce_action.authorize",
    "control.commerce_action.approve",
    "control.commerce_action.reject",
    "control.commerce_action.cancel",
  ])("accepts the %s tuple", (operation) => {
    expect(
      CommerceActionMutationReceiptSchema.safeParse(receipt(operation)).success,
    ).toBe(true);
  });

  it.each([
    ["unknown operation", receipt("control.commerce_action.decide")],
    [
      "wrong resource type",
      { ...receipt("control.commerce_action.approve"), resourceType: "action" },
    ],
    ["token like resource", receipt("control.commerce_action.approve", "oas_ag_abcd")],
    ["approval id as resource", receipt("control.commerce_action.approve", APPROVAL_ID)],
    ["unknown key", { ...receipt("control.commerce_action.cancel"), actor: "x" }],
    ["bad mutationId", { ...receipt("control.commerce_action.cancel"), mutationId: "nope" }],
  ])("rejects the %s receipt", (_label, value) => {
    expect(CommerceActionMutationReceiptSchema.safeParse(value).success).toBe(false);
  });

  it("exposes the advertised inferred type", () => {
    expectTypeOf<CommerceActionMutationReceipt["resourceId"]>().toEqualTypeOf<string>();
  });
});

describe("mutation data and status", () => {
  it("binds receipt.resourceId to metadata.actionId", () => {
    const value = {
      replayed: false,
      metadata: action(),
      receipt: receipt("control.commerce_action.authorize"),
    };
    expect(CommerceActionMutationDataSchema.safeParse(value).success).toBe(true);
    expect(
      CommerceActionMutationDataSchema.safeParse({
        ...value,
        receipt: receipt("control.commerce_action.authorize", ACTION_ID_B),
      }).success,
    ).toBe(false);
  });

  it("accepts a replay whose historical receipt differs from current metadata", () => {
    const value = {
      replayed: true,
      metadata: action({
        status: "reserved_not_granted",
        approvalId: null,
        reservationId: `openarc:reservation:${V5}`,
      }),
      receipt: receipt("control.commerce_action.approve"),
    };
    expect(CommerceActionMutationDataSchema.safeParse(value).success).toBe(true);
  });

  it("rejects tokens/hashes/unknown keys in mutation data", () => {
    for (const extra of [
      { token: "oacs_v1_x" },
      { requestHash: DIGEST },
      { sessionId: SESSION_ID },
    ]) {
      expect(
        CommerceActionMutationDataSchema.safeParse({
          replayed: false,
          metadata: action(),
          receipt: receipt("control.commerce_action.authorize"),
          ...extra,
        }).success,
      ).toBe(false);
    }
  });

  it("accepts the exact not_found and committed statuses and rejects extra fields", () => {
    expect(
      CommerceActionMutationStatusSchema.safeParse({ status: "not_found" }).success,
    ).toBe(true);
    expect(
      CommerceActionMutationStatusSchema.safeParse({
        status: "committed",
        receipt: receipt("control.commerce_action.cancel"),
      }).success,
    ).toBe(true);
    expect(
      CommerceActionMutationStatusSchema.safeParse({
        status: "not_found",
        receipt: receipt("control.commerce_action.cancel"),
      }).success,
    ).toBe(false);
    for (const outer of [
      { organizationId: ORG },
      { mutationId: MUTATION },
      { organizationId: ORG, mutationId: MUTATION },
    ]) {
      expect(
        CommerceActionMutationStatusSchema.safeParse({
          ...outer,
          status: "not_found",
        }).success,
      ).toBe(false);
      expect(
        CommerceActionMutationStatusSchema.safeParse({
          ...outer,
          status: "committed",
          receipt: receipt("control.commerce_action.cancel"),
        }).success,
      ).toBe(false);
    }
  });
});

describe("CommerceActionDetailSchema", () => {
  it("accepts a null item and a matching item", () => {
    expect(
      CommerceActionDetailSchema.safeParse({
        organizationId: ORG,
        actionId: ACTION_ID,
        item: null,
      }).success,
    ).toBe(true);
    expect(
      CommerceActionDetailSchema.safeParse({
        organizationId: ORG,
        actionId: ACTION_ID,
        item: action(),
      }).success,
    ).toBe(true);
  });

  it.each([
    ["wrong action binding", action({ actionId: ACTION_ID_B })],
    [
      "wrong tenant binding",
      action({
        exposureKey: {
          organizationId: ORG_B,
          subjectAgentId: AGENT,
          networkId: "eip155:5042002",
          asset: "USDC",
          representation: "erc20",
          decimals: 6,
        },
      }),
    ],
  ])("rejects detail item %s", (_label, item) => {
    expect(
      CommerceActionDetailSchema.safeParse({
        organizationId: ORG,
        actionId: ACTION_ID,
        item,
      }).success,
    ).toBe(false);
  });
});

describe("CommerceApprovalDetailSchema", () => {
  it("accepts a null item and a matching item", () => {
    expect(
      CommerceApprovalDetailSchema.safeParse({
        organizationId: ORG,
        approvalId: APPROVAL_ID,
        item: null,
      }).success,
    ).toBe(true);
    expect(
      CommerceApprovalDetailSchema.safeParse({
        organizationId: ORG,
        approvalId: APPROVAL_ID,
        item: approval(),
      }).success,
    ).toBe(true);
  });

  it.each([
    ["wrong approval binding", approval({ approvalId: APPROVAL_ID_B })],
    ["wrong tenant binding", approval({ organizationId: ORG_B })],
  ])("rejects approval detail item %s", (_label, item) => {
    expect(
      CommerceApprovalDetailSchema.safeParse({
        organizationId: ORG,
        approvalId: APPROVAL_ID,
        item,
      }).success,
    ).toBe(false);
  });
});

describe("pages", () => {
  it("accepts empty/null and binds a cursor to the last id", () => {
    expect(
      CommerceActionPageSchema.safeParse({
        organizationId: ORG,
        items: [],
        nextCursor: null,
      }).success,
    ).toBe(true);
    expect(
      CommerceActionPageSchema.safeParse({
        organizationId: ORG,
        items: [action({ actionId: ACTION_ID }), action({ actionId: ACTION_ID_B })],
        nextCursor: ACTION_ID_B,
      }).success,
    ).toBe(true);
    expect(
      CommerceActionPageSchema.safeParse({
        organizationId: ORG,
        items: [action({ actionId: ACTION_ID }), action({ actionId: ACTION_ID_B })],
        nextCursor: ACTION_ID,
      }).success,
    ).toBe(false);
    expect(
      CommerceActionPageSchema.safeParse({
        organizationId: ORG,
        items: [],
        nextCursor: ACTION_ID,
      }).success,
    ).toBe(false);
  });

  it.each([
    ["descending", [action({ actionId: ACTION_ID_B }), action({ actionId: ACTION_ID })]],
    ["duplicate", [action({ actionId: ACTION_ID }), action({ actionId: ACTION_ID })]],
  ])("rejects action page ordering %s", (_label, items) => {
    expect(
      CommerceActionPageSchema.safeParse({
        organizationId: ORG,
        items,
        nextCursor: null,
      }).success,
    ).toBe(false);
  });

  it("rejects a cross-tenant action page item", () => {
    expect(
      CommerceActionPageSchema.safeParse({
        organizationId: ORG,
        items: [
          action({
            exposureKey: {
              organizationId: ORG_B,
              subjectAgentId: AGENT,
              networkId: "eip155:5042002",
              asset: "USDC",
              representation: "erc20",
              decimals: 6,
            },
          }),
        ],
        nextCursor: null,
      }).success,
    ).toBe(false);
  });

  it("accepts and validates the approval page", () => {
    expect(
      CommerceApprovalPageSchema.safeParse({
        organizationId: ORG,
        items: [
          approval({ approvalId: APPROVAL_ID }),
          approval({ approvalId: APPROVAL_ID_B }),
        ],
        nextCursor: APPROVAL_ID_B,
      }).success,
    ).toBe(true);
    expect(
      CommerceApprovalPageSchema.safeParse({
        organizationId: ORG,
        items: [approval({ organizationId: ORG_B })],
        nextCursor: null,
      }).success,
    ).toBe(false);
    expect(
      CommerceApprovalPageSchema.safeParse({
        organizationId: ORG,
        items: [
          approval({ approvalId: APPROVAL_ID_B }),
          approval({ approvalId: APPROVAL_ID }),
        ],
        nextCursor: null,
      }).success,
    ).toBe(false);
  });
});

describe("CommerceExposureViewSchema", () => {
  it("accepts the exact shape with null cap and a 128-digit exact sum", () => {
    // 127 nines + 1 = 10^127, a 128-digit canonical amount.
    const committed = "9".repeat(127);
    const unresolved = "1";
    const total = (BigInt(committed) + BigInt(unresolved)).toString();
    const value = view({
      windowSeconds: "2592000",
      committedAtomic: committed,
      unresolvedAtomic: unresolved,
      totalExposureAtomic: total,
      availableAtomic: "0",
      deficitAtomic: "0",
    });
    expect(CommerceExposureViewSchema.safeParse(value).success).toBe(true);
    const parsed = CommerceExposureViewSchema.safeParse(value);
    if (parsed.success) {
      expectTypeOf(parsed.data).toMatchTypeOf<CommerceExposureView>();
    }
  });

  it("rejects a sum mismatch, overflow digit count and malformed leaves without throwing", () => {
    for (const value of [
      view({ totalExposureAtomic: "1" }),
      view({ committedAtomic: "9".repeat(129) }),
      view({ committedAtomic: "01" }),
      view({ deficitAtomic: "1e2" }),
      view({ policyRevision: "0" }),
      view({ policyRevision: "1000000000" }),
      view({ windowSeconds: "0" }),
      view({ windowSeconds: "2592001" }),
      view({ windowSeconds: "1\n" }),
      view({ asOf: "not-a-date" }),
    ]) {
      expect(() => CommerceExposureViewSchema.safeParse(value)).not.toThrow();
      expect(CommerceExposureViewSchema.safeParse(value).success).toBe(false);
    }
  });

  it.each(["1", "2592000"])("accepts windowSeconds %s", (windowSeconds) => {
    expect(
      CommerceExposureViewSchema.safeParse(view({ windowSeconds })).success,
    ).toBe(true);
  });

  it("enforces deficit/available semantics", () => {
    expect(
      CommerceExposureViewSchema.safeParse(
        view({
          committedAtomic: "10",
          totalExposureAtomic: "10",
          availableAtomic: "5",
          deficitAtomic: "3",
        }),
      ).success,
    ).toBe(false);
    expect(
      CommerceExposureViewSchema.safeParse(
        view({
          committedAtomic: "10",
          totalExposureAtomic: "10",
          availableAtomic: "0",
          deficitAtomic: "3",
        }),
      ).success,
    ).toBe(true);
    expect(
      CommerceExposureViewSchema.safeParse(
        view({ availableAtomic: null, deficitAtomic: "1" }),
      ).success,
    ).toBe(false);
  });
});

describe("CommerceExposureDataSchema", () => {
  it("binds a non-null item to all wrapper ids", () => {
    expect(
      CommerceExposureDataSchema.safeParse({
        organizationId: ORG,
        subjectAgentId: AGENT,
        policyId: POLICY_ID,
        item: view(),
      }).success,
    ).toBe(true);
    expect(
      CommerceExposureDataSchema.safeParse({
        organizationId: ORG,
        subjectAgentId: AGENT,
        policyId: POLICY_ID,
        item: null,
      }).success,
    ).toBe(true);
    for (const item of [
      view({ organizationId: ORG_B }),
      view({ subjectAgentId: AGENT_B }),
      view({ policyId: POLICY_ID_B }),
    ]) {
      expect(
        CommerceExposureDataSchema.safeParse({
          organizationId: ORG,
          subjectAgentId: AGENT,
          policyId: POLICY_ID,
          item,
        }).success,
      ).toBe(false);
    }
  });
});

describe("strict success envelopes", () => {
  const cases: readonly [
    string,
    { safeParse(v: unknown): { success: boolean } },
    unknown,
  ][] = [
    [
      "mutation data",
      CommerceActionMutationDataResponseSchema,
      {
        replayed: false,
        metadata: action(),
        receipt: receipt("control.commerce_action.authorize"),
      },
    ],
    [
      "mutation status",
      CommerceActionMutationStatusResponseSchema,
      { status: "not_found" },
    ],
    [
      "action detail",
      CommerceActionDetailResponseSchema,
      { organizationId: ORG, actionId: ACTION_ID, item: null },
    ],
    [
      "approval detail",
      CommerceApprovalDetailResponseSchema,
      { organizationId: ORG, approvalId: APPROVAL_ID, item: null },
    ],
    [
      "action page",
      CommerceActionPageResponseSchema,
      { organizationId: ORG, items: [], nextCursor: null },
    ],
    [
      "approval page",
      CommerceApprovalPageResponseSchema,
      { organizationId: ORG, items: [], nextCursor: null },
    ],
    [
      "exposure",
      CommerceExposureDataResponseSchema,
      { organizationId: ORG, subjectAgentId: AGENT, policyId: POLICY_ID, item: null },
    ],
  ];

  it("wraps each data shape with the shared v2 meta and rejects canaries", () => {
    for (const [label, schema, data] of cases) {
      expect(schema.safeParse(envelope(data)).success, label).toBe(true);
      expect(schema.safeParse({ ...envelope(data), ok: false }).success, label).toBe(
        false,
      );
      expect(
        schema.safeParse({
          ...envelope({ ...(data as object), secretToken: "SECRET" }),
        }).success,
        label,
      ).toBe(false);
    }
  });
});

describe("COMMERCE_ACTION_WIRE_FIELD_CLASSES", () => {
  it("is frozen and marks every field organization_protected", () => {
    expect(Object.isFrozen(COMMERCE_ACTION_WIRE_FIELD_CLASSES)).toBe(true);
    for (const group of Object.values(COMMERCE_ACTION_WIRE_FIELD_CLASSES)) {
      expect(Object.isFrozen(group)).toBe(true);
      expect(
        Object.values(group).every((value) => value === "organization_protected"),
      ).toBe(true);
    }
  });
});
