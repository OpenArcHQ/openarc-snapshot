import { describe, expect, expectTypeOf, it } from "vitest";

import {
  CommercePolicyAppendBodySchema,
  CommercePolicyCreateBodySchema,
  CommercePolicyHistoryPageSchema,
  CommercePolicyHistoryPageResponseSchema,
  CommercePolicyHistoryRequestSchema,
  CommercePolicyListRequestSchema,
  CommercePolicyMutationReceiptSchema,
  CommercePolicyMutationRequestSchema,
  CommercePolicyMutationResultSchema,
  CommercePolicyMutationResultResponseSchema,
  CommercePolicyMutationStatusSchema,
  CommercePolicyMutationStatusResponseSchema,
  CommercePolicyRevisionDetailSchema,
  CommercePolicyRevisionDetailResponseSchema,
  CommercePolicyRevisionRequestSchema,
  CommercePolicyRevisionSummarySchema,
  CommercePolicyRootDetailSchema,
  CommercePolicyRootDetailResponseSchema,
  CommercePolicyRootPageSchema,
  CommercePolicyRootPageResponseSchema,
  CommercePolicyRootRequestSchema,
  CommercePolicyTransitionBodySchema,
  type CommercePolicyMutationReceipt,
  type CommercePolicyMutationStatus,
  type CommercePolicyRevisionSummary,
} from "../src/index.js";
import {
  CommercePolicyMutationReceiptSchema as MODULE_RECEIPT,
} from "../src/commerce/control-policy-wire.js";

const V4 = "12345678-1234-4234-8123-123456789abc";
const V5 = "87654321-4321-4321-b321-cba987654321";
const POLICY_ID = `openarc:policy:${V4}`;
const POLICY_ID_B = `openarc:policy:${V5}`;
const ORG = `openarc:org:${V4}`;
const ORG_B = `openarc:org:${V5}`;
const AGENT = `openarc:agent:${V4}`;
const AGENT_B = `openarc:agent:${V5}`;
const MUTATION = V4;
const MUTATION_B = V5;
const CREATED_AT = "2025-01-01T00:00:00.000000Z";
const LATER_AT = "2025-02-01T00:00:00.000000Z";
const EXPIRES_AT = "2025-03-01T00:00:00.000000Z";
const DIGEST = `sha256:${"a".repeat(64)}`;

const META = {
  schemaVersion: "openarc.api.v2" as const,
  requestId: "9f1c2d34-5e6a-4b7c-8d9e-0f1a2b3c4d5e",
  buildSha: "0123456789abcdef0123456789abcdef01234567",
};

function content(): Record<string, unknown> {
  return {
    organizationId: ORG,
    subjectAgentId: AGENT,
    networkId: "eip155:5042002",
    asset: "USDC",
    representation: "erc20",
    decimals: 6,
    perActionLimit: "1000",
    rollingLimit: null,
    rollingWindowSeconds: null,
    feeLimit: "10",
    allowedProviderIds: [],
    allowedListingIds: [],
    approval: { mode: "none", threshold: null, separateApprover: false },
    expiresAt: null,
  };
}

function root(policyId = POLICY_ID, organizationId = ORG): Record<string, unknown> {
  return {
    schemaVersion: "openarc.control.policy-root.v1",
    policyId,
    organizationId,
    subjectAgentId: AGENT,
    currentRevision: "1",
    status: "active",
    createdAt: CREATED_AT,
    updatedAt: LATER_AT,
  };
}

function summary(
  revision: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    policyId: POLICY_ID,
    organizationId: ORG,
    subjectAgentId: AGENT,
    revision,
    digest: DIGEST,
    createdAt: CREATED_AT,
    expiresAt: null,
    ...overrides,
  };
}

function revisionRecord(revision = "1"): Record<string, unknown> {
  return {
    schemaVersion: "openarc.control.policy.v1",
    policyId: POLICY_ID,
    revision,
    ...content(),
    createdAt: CREATED_AT,
    digest: DIGEST,
  };
}

function receipt(
  operation: string,
  resourceType: string,
  resourceId: string,
): Record<string, unknown> {
  return {
    mutationId: MUTATION,
    operation,
    resourceType,
    resourceId,
    committedAt: LATER_AT,
  };
}

function envelope(data: unknown) {
  return { ok: true, data, meta: META };
}

describe("write bodies", () => {
  it("parses a strict create body without mutating input", () => {
    const input = { mutationId: MUTATION, content: content() };
    const snapshot = structuredClone(input);
    const parsed = CommercePolicyCreateBodySchema.safeParse(input);
    expect(parsed.success).toBe(true);
    expect(input).toEqual(snapshot);
    if (parsed.success) {
      expect(Object.keys(parsed.data).sort()).toEqual(["content", "mutationId"]);
    }
  });

  it.each([
    ["missing mutationId", { content: content() }],
    ["missing content", { mutationId: MUTATION }],
    ["unknown key", { mutationId: MUTATION, content: content(), note: "x" }],
    ["bad mutationId", { mutationId: "nope", content: content() }],
    ["raw reservation", { mutationId: MUTATION, content: content(), reservation: "1" }],
  ])("rejects create body %s", (_label, value) => {
    expect(CommercePolicyCreateBodySchema.safeParse(value).success).toBe(false);
  });

  it.each(["1", "2", "999999998"])(
    "accepts append expectedRevision %s",
    (expectedRevision) => {
      expect(
        CommercePolicyAppendBodySchema.safeParse({
          mutationId: MUTATION,
          expectedRevision,
          expectedUpdatedAt: LATER_AT,
          content: content(),
        }).success,
      ).toBe(true);
    },
  );

  it.each(["0", "999999999", "1000000000", "01", "1e2", "1.0", "1\n", "+1", ""])(
    "rejects append expectedRevision %s",
    (expectedRevision) => {
      expect(
        CommercePolicyAppendBodySchema.safeParse({
          mutationId: MUTATION,
          expectedRevision,
          expectedUpdatedAt: LATER_AT,
          content: content(),
        }).success,
      ).toBe(false);
    },
  );

  it("rejects append with a non-timestamp expectedUpdatedAt or extra key", () => {
    expect(
      CommercePolicyAppendBodySchema.safeParse({
        mutationId: MUTATION,
        expectedRevision: "1",
        expectedUpdatedAt: "2025-02-01",
        content: content(),
      }).success,
    ).toBe(false);
    expect(
      CommercePolicyAppendBodySchema.safeParse({
        mutationId: MUTATION,
        expectedRevision: "1",
        expectedUpdatedAt: LATER_AT,
        content: content(),
        operation: "control.policy.append",
      }).success,
    ).toBe(false);
  });

  it("parses a transition body and rejects an operation key", () => {
    const value = {
      mutationId: MUTATION,
      expectedRevision: "1",
      expectedUpdatedAt: LATER_AT,
    };
    expect(CommercePolicyTransitionBodySchema.safeParse(value).success).toBe(true);
    expect(
      CommercePolicyTransitionBodySchema.safeParse({
        ...value,
        operation: "control.policy.pause",
      }).success,
    ).toBe(false);
    expect(
      CommercePolicyTransitionBodySchema.safeParse({
        mutationId: MUTATION,
        expectedUpdatedAt: LATER_AT,
      }).success,
    ).toBe(false);
  });

  it.each(["1", "2", "999999998", "999999999"])(
    "accepts transition expectedRevision %s (full revision range)",
    (expectedRevision) => {
      expect(
        CommercePolicyTransitionBodySchema.safeParse({
          mutationId: MUTATION,
          expectedRevision,
          expectedUpdatedAt: LATER_AT,
        }).success,
      ).toBe(true);
    },
  );

  it("still reserves append room while allowing a max-revision transition", () => {
    expect(
      CommercePolicyAppendBodySchema.safeParse({
        mutationId: MUTATION,
        expectedRevision: "999999998",
        expectedUpdatedAt: LATER_AT,
        content: content(),
      }).success,
    ).toBe(true);
    expect(
      CommercePolicyAppendBodySchema.safeParse({
        mutationId: MUTATION,
        expectedRevision: "999999999",
        expectedUpdatedAt: LATER_AT,
        content: content(),
      }).success,
    ).toBe(false);
  });

  it.each(["0", "01", "1000000000", "1e2", "1.0", "1\n", "+1", ""])(
    "rejects transition expectedRevision %s without throwing",
    (expectedRevision) => {
      expect(() =>
        CommercePolicyTransitionBodySchema.safeParse({
          mutationId: MUTATION,
          expectedRevision,
          expectedUpdatedAt: LATER_AT,
        }),
      ).not.toThrow();
      expect(
        CommercePolicyTransitionBodySchema.safeParse({
          mutationId: MUTATION,
          expectedRevision,
          expectedUpdatedAt: LATER_AT,
        }).success,
      ).toBe(false);
    },
  );
});

describe("CommercePolicyRevisionSummarySchema", () => {
  it("parses null and later expiry", () => {
    expect(CommercePolicyRevisionSummarySchema.safeParse(summary("1")).success).toBe(
      true,
    );
    expect(
      CommercePolicyRevisionSummarySchema.safeParse(
        summary("1", { expiresAt: EXPIRES_AT }),
      ).success,
    ).toBe(true);
  });

  it.each([
    ["equal expiry", { createdAt: EXPIRES_AT, expiresAt: EXPIRES_AT }],
    ["earlier expiry", { createdAt: LATER_AT, expiresAt: CREATED_AT }],
    ["wrong policy id", { policyId: ORG }],
    ["bad digest", { digest: "sha256:ABC" }],
    ["unknown key", { allowedProviderIds: [] }],
    ["missing expiresAt", { expiresAt: undefined }],
  ])("rejects summary %s", (_label, patch) => {
    expect(CommercePolicyRevisionSummarySchema.safeParse(summary("1", patch)).success).toBe(
      false,
    );
  });

  it.each(["not-a-date", "2025-13-01T00:00:00Z", "1e2", "", "2025-01-01"])(
    "does not throw for malformed created/expiry %s",
    (value) => {
      expect(() =>
        CommercePolicyRevisionSummarySchema.safeParse(
          summary("1", { createdAt: value, expiresAt: value }),
        ),
      ).not.toThrow();
      expect(
        CommercePolicyRevisionSummarySchema.safeParse(
          summary("1", { createdAt: value, expiresAt: value }),
        ).success,
      ).toBe(false);
    },
  );
});

describe("read requests", () => {
  it("accepts minimal and bounded list requests", () => {
    expect(CommercePolicyListRequestSchema.safeParse({ organizationId: ORG }).success).toBe(
      true,
    );
    expect(
      CommercePolicyListRequestSchema.safeParse({
        organizationId: ORG,
        afterPolicyId: POLICY_ID,
        limit: "50",
      }).success,
    ).toBe(true);
    expect(
      CommercePolicyHistoryRequestSchema.safeParse({
        organizationId: ORG,
        policyId: POLICY_ID,
        afterRevision: "2",
        limit: "1",
      }).success,
    ).toBe(true);
  });

  it.each(["0", "51", "01", "1.0", "1\n", "1e1", " 1", "+1", ""])(
    "rejects list limit %s",
    (limit) => {
      expect(
        CommercePolicyListRequestSchema.safeParse({ organizationId: ORG, limit }).success,
      ).toBe(false);
    },
  );

  it.each(["afterPolicyId", "limit"] as const)(
    "rejects explicit undefined %s",
    (key) => {
      expect(
        CommercePolicyListRequestSchema.safeParse({
          organizationId: ORG,
          [key]: undefined,
        }).success,
      ).toBe(false);
    },
  );

  it.each(["afterRevision", "limit"] as const)(
    "rejects explicit undefined %s on history",
    (key) => {
      expect(
        CommercePolicyHistoryRequestSchema.safeParse({
          organizationId: ORG,
          policyId: POLICY_ID,
          [key]: undefined,
        }).success,
      ).toBe(false);
    },
  );

  it.each(["0", "1e2", "1\n", "9999999999"])(
    "rejects afterRevision %s",
    (afterRevision) => {
      expect(
        CommercePolicyHistoryRequestSchema.safeParse({
          organizationId: ORG,
          policyId: POLICY_ID,
          afterRevision,
        }).success,
      ).toBe(false);
    },
  );

  it("rejects unknown request keys on every read shape", () => {
    for (const [schema, value] of [
      [CommercePolicyListRequestSchema, { organizationId: ORG, extra: 1 }],
      [
        CommercePolicyRootRequestSchema,
        { organizationId: ORG, policyId: POLICY_ID, extra: 1 },
      ],
      [
        CommercePolicyHistoryRequestSchema,
        { organizationId: ORG, policyId: POLICY_ID, extra: 1 },
      ],
      [
        CommercePolicyRevisionRequestSchema,
        { organizationId: ORG, policyId: POLICY_ID, revision: "1", extra: 1 },
      ],
      [
        CommercePolicyMutationRequestSchema,
        { organizationId: ORG, mutationId: MUTATION, extra: 1 },
      ],
    ] as const) {
      expect(schema.safeParse(value).success).toBe(false);
    }
  });

  it("parses the plain root/revision/mutation requests", () => {
    expect(
      CommercePolicyRootRequestSchema.safeParse({ organizationId: ORG, policyId: POLICY_ID })
        .success,
    ).toBe(true);
    expect(
      CommercePolicyRevisionRequestSchema.safeParse({
        organizationId: ORG,
        policyId: POLICY_ID,
        revision: "10",
      }).success,
    ).toBe(true);
    expect(
      CommercePolicyMutationRequestSchema.safeParse({
        organizationId: ORG,
        mutationId: MUTATION,
      }).success,
    ).toBe(true);
    expect(
      CommercePolicyRevisionRequestSchema.safeParse({
        organizationId: ORG,
        policyId: POLICY_ID,
        revision: "0",
      }).success,
    ).toBe(false);
  });
});

describe("CommercePolicyMutationReceiptSchema", () => {
  const VALID: readonly [string, Record<string, unknown>][] = [
    ["create", receipt("control.policy.create", "budget_policy", POLICY_ID)],
    [
      "revision.create",
      receipt("control.policy.revision.create", "budget_policy_revision", `${POLICY_ID}@2`),
    ],
    [
      "revision.create max",
      receipt(
        "control.policy.revision.create",
        "budget_policy_revision",
        `${POLICY_ID}@999999999`,
      ),
    ],
    ["pause", receipt("control.policy.pause", "budget_policy", POLICY_ID)],
    ["resume", receipt("control.policy.resume", "budget_policy", POLICY_ID)],
    ["revoke", receipt("control.policy.revoke", "budget_policy", POLICY_ID)],
  ];

  it.each(VALID)("accepts the %s receipt tuple", (_label, value) => {
    expect(CommercePolicyMutationReceiptSchema.safeParse(value).success).toBe(true);
  });

  it.each([
    "2",
    "9",
    "10",
    "11",
    "19",
    "20",
    "99",
    "100",
    "101",
    "100000000",
    "999999999",
  ])(
    "accepts a revision.create resource id ending in %s (2..999999999)",
    (revision) => {
      expect(
        CommercePolicyMutationReceiptSchema.safeParse(
          receipt(
            "control.policy.revision.create",
            "budget_policy_revision",
            `${POLICY_ID}@${revision}`,
          ),
        ).success,
      ).toBe(true);
    },
  );

  it.each([
    "0",
    "1",
    "01",
    "1000000000",
    "1.0",
    "+2",
    "1e2",
    "2\n",
    "",
  ])(
    "rejects a revision.create resource id ending in %s",
    (revision) => {
      expect(
        CommercePolicyMutationReceiptSchema.safeParse(
          receipt(
            "control.policy.revision.create",
            "budget_policy_revision",
            `${POLICY_ID}@${revision}`,
          ),
        ).success,
      ).toBe(false);
    },
  );

  it.each([
    ["create with revision resource", receipt("control.policy.create", "budget_policy", `${POLICY_ID}@2`)],
    ["create wrong resourceType", receipt("control.policy.create", "budget_policy_revision", POLICY_ID)],
    ["revision.create plain policy id", receipt("control.policy.revision.create", "budget_policy_revision", POLICY_ID)],
    ["revision.create revision 1", receipt("control.policy.revision.create", "budget_policy_revision", `${POLICY_ID}@1`)],
    ["revision.create revision 0", receipt("control.policy.revision.create", "budget_policy_revision", `${POLICY_ID}@0`)],
    ["revision.create 10 digits", receipt("control.policy.revision.create", "budget_policy_revision", `${POLICY_ID}@1000000000`)],
    ["revision.create trailing newline", receipt("control.policy.revision.create", "budget_policy_revision", `${POLICY_ID}@2\n`)],
    ["pause with revision resource", receipt("control.policy.pause", "budget_policy", `${POLICY_ID}@2`)],
    ["unknown operation", receipt("control.policy.append", "budget_policy", POLICY_ID)],
    ["bad mutationId", { ...receipt("control.policy.create", "budget_policy", POLICY_ID), mutationId: "nope" }],
    ["unknown key", { ...receipt("control.policy.create", "budget_policy", POLICY_ID), key: "secret" }],
  ])("rejects the %s tuple", (_label, value) => {
    expect(CommercePolicyMutationReceiptSchema.safeParse(value).success).toBe(false);
  });

  it("is the same validator exported through the index", () => {
    expect(CommercePolicyMutationReceiptSchema).toBe(MODULE_RECEIPT);
    expectTypeOf<CommercePolicyMutationReceipt>().toMatchTypeOf<{
      operation: string;
      resourceType: string;
      resourceId: string;
      mutationId: string;
      committedAt: string;
    }>();
  });
});

describe("CommercePolicyRootPageSchema", () => {
  it("accepts empty/null and a null cursor on a nonempty last page", () => {
    expect(
      CommercePolicyRootPageSchema.safeParse({
        organizationId: ORG,
        items: [],
        nextCursor: null,
      }).success,
    ).toBe(true);
    expect(
      CommercePolicyRootPageSchema.safeParse({
        organizationId: ORG,
        items: [root(POLICY_ID), root(POLICY_ID_B)],
        nextCursor: null,
      }).success,
    ).toBe(true);
  });

  it("binds a non-null cursor to the last item", () => {
    expect(
      CommercePolicyRootPageSchema.safeParse({
        organizationId: ORG,
        items: [root(POLICY_ID), root(POLICY_ID_B)],
        nextCursor: POLICY_ID_B,
      }).success,
    ).toBe(true);
    expect(
      CommercePolicyRootPageSchema.safeParse({
        organizationId: ORG,
        items: [root(POLICY_ID)],
        nextCursor: POLICY_ID,
      }).success,
    ).toBe(true);
    expect(
      CommercePolicyRootPageSchema.safeParse({
        organizationId: ORG,
        items: [root(POLICY_ID), root(POLICY_ID_B)],
        nextCursor: POLICY_ID,
      }).success,
    ).toBe(false);
    expect(
      CommercePolicyRootPageSchema.safeParse({
        organizationId: ORG,
        items: [],
        nextCursor: POLICY_ID,
      }).success,
    ).toBe(false);
  });

  it.each([
    ["descending items", { items: [root(POLICY_ID_B), root(POLICY_ID)], nextCursor: null }],
    ["duplicate items", { items: [root(POLICY_ID), root(POLICY_ID)], nextCursor: null }],
    ["wrong org item", { items: [root(POLICY_ID, ORG_B)], nextCursor: null }],
    ["unknown key", { items: [], nextCursor: null, total: "1" }],
  ])("rejects root page %s", (_label, patch) => {
    expect(
      CommercePolicyRootPageSchema.safeParse({ organizationId: ORG, ...patch }).success,
    ).toBe(false);
  });

  it("rejects more than 50 roots", () => {
    const uuid = (index: number) =>
      `${index.toString(16).padStart(8, "0")}-1234-4234-8123-123456789abc`;
    const items = Array.from({ length: 51 }, (_, index) =>
      root(`openarc:policy:${uuid(index)}`),
    );
    expect(
      CommercePolicyRootPageSchema.safeParse({
        organizationId: ORG,
        items,
        nextCursor: null,
      }).success,
    ).toBe(false);
  });
});

describe("CommercePolicyRootDetailSchema", () => {
  it("accepts a null item and a matching item", () => {
    expect(
      CommercePolicyRootDetailSchema.safeParse({
        organizationId: ORG,
        policyId: POLICY_ID,
        item: null,
      }).success,
    ).toBe(true);
    expect(
      CommercePolicyRootDetailSchema.safeParse({
        organizationId: ORG,
        policyId: POLICY_ID,
        item: root(),
      }).success,
    ).toBe(true);
  });

  it.each([
    ["wrong item org", root(POLICY_ID, ORG_B)],
    ["wrong item policy", root(POLICY_ID_B)],
  ])("rejects %s", (_label, item) => {
    expect(
      CommercePolicyRootDetailSchema.safeParse({
        organizationId: ORG,
        policyId: POLICY_ID,
        item,
      }).success,
    ).toBe(false);
  });
});

describe("CommercePolicyHistoryPageSchema", () => {
  it("accepts empty/null and preserves numeric 2-vs-10 ordering", () => {
    expect(
      CommercePolicyHistoryPageSchema.safeParse({
        organizationId: ORG,
        policyId: POLICY_ID,
        items: [],
        nextCursor: null,
      }).success,
    ).toBe(true);
    // Lexically "10" < "2", but numerically 2 < 10, so ["2", "10"] is ascending.
    expect(
      CommercePolicyHistoryPageSchema.safeParse({
        organizationId: ORG,
        policyId: POLICY_ID,
        items: [summary("2"), summary("10")],
        nextCursor: "10",
      }).success,
    ).toBe(true);
  });

  it.each([
    ["lexical-looking but descending", ["10", "2"]],
    ["duplicate", ["3", "3"]],
    ["zero", ["0"]],
  ])("rejects %s revisions", (_label, revisions) => {
    expect(
      CommercePolicyHistoryPageSchema.safeParse({
        organizationId: ORG,
        policyId: POLICY_ID,
        items: revisions.map((revision) => summary(revision)),
        nextCursor: null,
      }).success,
    ).toBe(false);
  });

  it.each([
    ["wrong policy binding", { items: [summary("1", { policyId: POLICY_ID_B })], nextCursor: null }],
    ["wrong org binding", { items: [summary("1", { organizationId: ORG_B })], nextCursor: null }],
    ["wrong subject identity", { items: [summary("1"), summary("2", { subjectAgentId: AGENT_B })], nextCursor: null }],
    ["cursor on empty page", { items: [], nextCursor: "1" }],
    ["cursor not last", { items: [summary("1"), summary("2")], nextCursor: "1" }],
    ["unknown key", { items: [], nextCursor: null, total: "1" }],
  ])("rejects history page %s", (_label, patch) => {
    expect(
      CommercePolicyHistoryPageSchema.safeParse({
        organizationId: ORG,
        policyId: POLICY_ID,
        ...patch,
      }).success,
    ).toBe(false);
  });

  it("does not throw for malformed revisions", () => {
    for (const revision of ["not-a-number", "1e2", "1.5", "9999999999", "0", ""]) {
      expect(() =>
        CommercePolicyHistoryPageSchema.safeParse({
          organizationId: ORG,
          policyId: POLICY_ID,
          items: [summary(revision)],
          nextCursor: null,
        }),
      ).not.toThrow();
      expect(
        CommercePolicyHistoryPageSchema.safeParse({
          organizationId: ORG,
          policyId: POLICY_ID,
          items: [summary(revision)],
          nextCursor: null,
        }).success,
      ).toBe(false);
    }
  });

  it("accepts at most 50 summaries", () => {
    const items = Array.from({ length: 50 }, (_, index) =>
      summary(String(index + 1)),
    );
    expect(
      CommercePolicyHistoryPageSchema.safeParse({
        organizationId: ORG,
        policyId: POLICY_ID,
        items,
        nextCursor: "50",
      }).success,
    ).toBe(true);
    expect(
      CommercePolicyHistoryPageSchema.safeParse({
        organizationId: ORG,
        policyId: POLICY_ID,
        items: [...items, summary("51")],
        nextCursor: "51",
      }).success,
    ).toBe(false);
  });
});

describe("CommercePolicyRevisionDetailSchema", () => {
  it("accepts a null item and a matching item", () => {
    expect(
      CommercePolicyRevisionDetailSchema.safeParse({
        organizationId: ORG,
        policyId: POLICY_ID,
        revision: "1",
        item: null,
      }).success,
    ).toBe(true);
    expect(
      CommercePolicyRevisionDetailSchema.safeParse({
        organizationId: ORG,
        policyId: POLICY_ID,
        revision: "1",
        item: revisionRecord("1"),
      }).success,
    ).toBe(true);
  });

  it("rejects a mismatched revision, policy or org payload", () => {
    for (const item of [
      revisionRecord("2"),
      revisionRecord("1"),
      { ...revisionRecord("1"), policyId: POLICY_ID_B },
      { ...revisionRecord("1"), organizationId: ORG_B },
    ]) {
      const candidate =
        item.policyId === POLICY_ID_B
          ? { organizationId: ORG, policyId: POLICY_ID, revision: "1", item }
          : item.organizationId === ORG_B
            ? { organizationId: ORG, policyId: POLICY_ID, revision: "1", item }
            : { organizationId: ORG, policyId: POLICY_ID, revision: "1", item };
      const expectOk =
        item.revision === "1" &&
        item.policyId === POLICY_ID &&
        item.organizationId === ORG;
      expect(CommercePolicyRevisionDetailSchema.safeParse(candidate).success).toBe(
        expectOk,
      );
    }
  });
});

describe("mutation result and status", () => {
  it("strictly types replayed and rejects unknown keys", () => {
    expect(
      CommercePolicyMutationResultSchema.safeParse({
        organizationId: ORG,
        replayed: true,
        receipt: receipt("control.policy.create", "budget_policy", POLICY_ID),
      }).success,
    ).toBe(true);
    for (const replayed of ["true", 0, 1, null, undefined]) {
      expect(
        CommercePolicyMutationResultSchema.safeParse({
          organizationId: ORG,
          replayed,
          receipt: receipt("control.policy.create", "budget_policy", POLICY_ID),
        }).success,
      ).toBe(false);
    }
    expect(
      CommercePolicyMutationResultSchema.safeParse({
        organizationId: ORG,
        replayed: true,
        receipt: receipt("control.policy.create", "budget_policy", POLICY_ID),
        raw: "canary",
      }).success,
    ).toBe(false);
  });

  it("accepts not_found and committed statuses", () => {
    expect(
      CommercePolicyMutationStatusSchema.safeParse({
        organizationId: ORG,
        mutationId: MUTATION,
        status: "not_found",
      }).success,
    ).toBe(true);
    expect(
      CommercePolicyMutationStatusSchema.safeParse({
        organizationId: ORG,
        mutationId: MUTATION,
        status: "committed",
        receipt: receipt("control.policy.resume", "budget_policy", POLICY_ID),
      }).success,
    ).toBe(true);
    const committed = CommercePolicyMutationStatusSchema.safeParse({
      organizationId: ORG,
      mutationId: MUTATION,
      status: "committed",
      receipt: receipt("control.policy.resume", "budget_policy", POLICY_ID),
    });
    if (committed.success) {
      expectTypeOf(committed.data).toEqualTypeOf<CommercePolicyMutationStatus>();
    }
  });

  it("rejects mismatched receipt.mutationId and unknown status", () => {
    expect(
      CommercePolicyMutationStatusSchema.safeParse({
        organizationId: ORG,
        mutationId: MUTATION,
        status: "committed",
        receipt: {
          ...receipt("control.policy.resume", "budget_policy", POLICY_ID),
          mutationId: MUTATION_B,
        },
      }).success,
    ).toBe(false);
    expect(
      CommercePolicyMutationStatusSchema.safeParse({
        organizationId: ORG,
        mutationId: MUTATION,
        status: "pending",
      }).success,
    ).toBe(false);
    expect(
      CommercePolicyMutationStatusSchema.safeParse({
        organizationId: ORG,
        mutationId: MUTATION,
        status: "not_found",
        receipt: receipt("control.policy.resume", "budget_policy", POLICY_ID),
      }).success,
    ).toBe(false);
  });
});

describe("success envelopes", () => {
  it("wraps each of the six data shapes with the shared v2 meta", () => {
    const cases: readonly [string, { safeParse(v: unknown): { success: boolean } }, unknown][] = [
      [
        "root page",
        CommercePolicyRootPageResponseSchema,
        { organizationId: ORG, items: [], nextCursor: null },
      ],
      [
        "root detail",
        CommercePolicyRootDetailResponseSchema,
        { organizationId: ORG, policyId: POLICY_ID, item: null },
      ],
      [
        "history page",
        CommercePolicyHistoryPageResponseSchema,
        { organizationId: ORG, policyId: POLICY_ID, items: [], nextCursor: null },
      ],
      [
        "revision detail",
        CommercePolicyRevisionDetailResponseSchema,
        { organizationId: ORG, policyId: POLICY_ID, revision: "1", item: null },
      ],
      [
        "mutation result",
        CommercePolicyMutationResultResponseSchema,
        {
          organizationId: ORG,
          replayed: false,
          receipt: receipt("control.policy.create", "budget_policy", POLICY_ID),
        },
      ],
      [
        "mutation status",
        CommercePolicyMutationStatusResponseSchema,
        { organizationId: ORG, mutationId: MUTATION, status: "not_found" },
      ],
    ];
    for (const [label, schema, data] of cases) {
      expect(schema.safeParse(envelope(data)).success, label).toBe(true);
      expect(schema.safeParse({ ...envelope(data), ok: false }).success, label).toBe(
        false,
      );
      expect(
        schema.safeParse({
          ...envelope({ ...(data as object), privateCanary: "SECRET" }),
        }).success,
        label,
      ).toBe(false);
    }
  });

  it("exposes the advertised inferred types", () => {
    expectTypeOf<CommercePolicyRevisionSummary>().toMatchTypeOf<{
      policyId: string;
      organizationId: string;
      subjectAgentId: string;
      revision: string;
      digest: string;
      createdAt: string;
      expiresAt: string | null;
    }>();
    expectTypeOf<CommercePolicyMutationReceipt["resourceId"]>().toEqualTypeOf<string>();
  });
});
