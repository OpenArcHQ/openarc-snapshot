import { describe, expect, expectTypeOf, it } from "vitest";

import {
  COMMERCE_BUDGET_INPUT_INVALID,
  CommerceActionIdSchema,
  CommerceExposureKeySchema,
  CommerceExposureTotalSchema,
  CommerceWindowSecondsSchema,
  assessCommerceBudgetLimits,
  calculateCommerceBudgetExposure,
  type CommerceBudgetAssessmentResult,
  type CommerceBudgetExposure,
  type CommerceExposureKey,
  type CommercePolicyContent,
} from "../src/index.js";
import {
  COMMERCE_BUDGET_INPUT_INVALID as MODULE_ERROR,
  assessCommerceBudgetLimits as moduleAssess,
} from "../src/commerce/control-budget.js";

/**
 * Focused contract tests for the P03 exact budget arithmetic kernel. These
 * assert only this kernel's own grammar, arithmetic, ordering and the additive
 * index export; primitive uint256/timestamp/digest matrices are proven
 * elsewhere.
 */

const V1 = "11111111-1111-4111-8111-111111111111";
const V2 = "22222222-2222-4222-8222-222222222222";
const V3 = "33333333-3333-4333-8333-333333333333";
const V4 = "44444444-4444-4444-8444-444444444444";
const ORG_ID = `openarc:org:${V1}`;
const AGENT_ID = `openarc:agent:${V1}`;
const ACTION_1 = `openarc:action:${V1}`;
const ACTION_2 = `openarc:action:${V2}`;
const ACTION_3 = `openarc:action:${V3}`;
const ACTION_4 = `openarc:action:${V4}`;
const MAX_UINT256 =
  "115792089237316195423570985008687907853269984665640564039457584007913129639935";
const OVER_UINT256 =
  "115792089237316195423570985008687907853269984665640564039457584007913129639936";
const NOW = "2025-01-01T00:00:10.500000000Z";
const WINDOW_10 = "10";
const ERROR = COMMERCE_BUDGET_INPUT_INVALID;

const EXPOSURE_KEY: CommerceExposureKey = {
  organizationId: ORG_ID,
  subjectAgentId: AGENT_ID,
  networkId: "eip155:5042002",
  asset: "USDC",
  representation: "erc20",
  decimals: 6,
};

function exposureInput(): Record<string, unknown> {
  return {
    exposureKey: { ...EXPOSURE_KEY },
    now: NOW,
    windowSeconds: WINDOW_10,
    complete: true,
    committed: [],
    unresolved: [],
  };
}

function exposureWith(
  patch: Record<string, unknown>,
): Record<string, unknown> {
  return { ...exposureInput(), ...patch };
}

function policyContent(): Record<string, unknown> {
  return {
    organizationId: ORG_ID,
    subjectAgentId: AGENT_ID,
    networkId: "eip155:5042002",
    asset: "USDC",
    representation: "erc20",
    decimals: 6,
    perActionLimit: "1000",
    rollingLimit: "5000",
    rollingWindowSeconds: WINDOW_10,
    feeLimit: "10",
    allowedProviderIds: [],
    allowedListingIds: [],
    approval: { mode: "none", threshold: null, separateApprover: false },
    expiresAt: null,
  };
}

function assessmentInput(): Record<string, unknown> {
  return {
    policy: policyContent(),
    exposureKey: { ...EXPOSURE_KEY },
    committedExposureAtomic: "0",
    unresolvedExposureAtomic: "0",
    candidate: { amountAtomic: "100", feeAtomic: "1" },
  };
}

function assessmentWith(
  patch: Record<string, unknown>,
): Record<string, unknown> {
  return { ...assessmentInput(), ...patch };
}

function policyWith(patch: Record<string, unknown>): Record<string, unknown> {
  return { ...policyContent(), ...patch };
}

function candidateWith(
  patch: Record<string, unknown>,
): Record<string, unknown> {
  return { candidate: { ...(assessmentInput().candidate as object), ...patch } };
}

function committedRecord(
  actionId: string,
  amountAtomic: string,
  committedAt: string,
): Record<string, unknown> {
  return { actionId, amountAtomic, committedAt };
}

function unresolvedRecord(
  actionId: string,
  amountAtomic: string,
  createdAt: string,
): Record<string, unknown> {
  return { actionId, amountAtomic, createdAt };
}

describe("CommerceActionIdSchema", () => {
  it.each([ACTION_1, ACTION_4])("accepts canonical UUIDv4 action id %s", (value) => {
    expect(CommerceActionIdSchema.safeParse(value).success).toBe(true);
  });

  it("accepts an otherwise-boundary canonical UUIDv4 with low variant nibbles", () => {
    expect(
      CommerceActionIdSchema.safeParse(
        "openarc:action:aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
      ).success,
    ).toBe(true);
    expect(
      CommerceActionIdSchema.safeParse(ACTION_4).success,
    ).toBe(true);
  });

  it.each([
    ACTION_1.toUpperCase(),
    `${ACTION_1}\n`,
    `${ACTION_1} `,
    V1,
    `openarc:org:${V1}`,
    "openarc:action:11111111-1111-1111-8111-111111111111",
    "openarc:action:11111111-1111-7111-8111-111111111111",
    "openarc:action:11111111-1111-0111-8111-111111111111",
    "openarc:action:11111111-1111-4111-7111-111111111111",
    `${ACTION_1}extra`,
  ])("rejects non-canonical or non-v4 action id %s", (value) => {
    expect(CommerceActionIdSchema.safeParse(value).success).toBe(false);
  });
});

describe("CommerceExposureKeySchema", () => {
  it("accepts the six-field key and rejects extra keys", () => {
    expect(CommerceExposureKeySchema.safeParse(EXPOSURE_KEY).success).toBe(true);
    expect(
      CommerceExposureKeySchema.safeParse({
        ...EXPOSURE_KEY,
        policyId: `openarc:policy:${V1}`,
      }).success,
    ).toBe(false);
    expect(
      CommerceExposureKeySchema.safeParse({ ...EXPOSURE_KEY, networkId: "eip155:1" })
        .success,
    ).toBe(false);
    expect(
      CommerceExposureKeySchema.safeParse({ ...EXPOSURE_KEY, asset: "USDT" }).success,
    ).toBe(false);
    expect(
      CommerceExposureKeySchema.safeParse({
        ...EXPOSURE_KEY,
        representation: "native",
      }).success,
    ).toBe(false);
    expect(
      CommerceExposureKeySchema.safeParse({ ...EXPOSURE_KEY, decimals: 18 }).success,
    ).toBe(false);
  });
});

describe("CommerceExposureTotalSchema", () => {
  it("accepts canonical nonnegative decimals up to 128 digits", () => {
    expect(CommerceExposureTotalSchema.safeParse("0").success).toBe(true);
    expect(CommerceExposureTotalSchema.safeParse("1").success).toBe(true);
    expect(CommerceExposureTotalSchema.safeParse("9".repeat(128)).success).toBe(
      true,
    );
  });

  it.each([
    "",
    "01",
    "1\n",
    " 1",
    "-1",
    "1.0",
    "1e2",
    "9".repeat(129),
  ])("rejects non-canonical total %s", (value) => {
    expect(CommerceExposureTotalSchema.safeParse(value).success).toBe(false);
  });
});

describe("CommerceWindowSecondsSchema", () => {
  it.each(["1", "2592000"])("accepts window %s", (value) => {
    expect(CommerceWindowSecondsSchema.safeParse(value).success).toBe(true);
  });

  it.each(["0", "2592001", "01", "1\n", "1.5", ""])(
    "rejects window %s",
    (value) => {
      expect(CommerceWindowSecondsSchema.safeParse(value).success).toBe(false);
    },
  );
});

describe("calculateCommerceBudgetExposure", () => {
  it("sums in-window committed and all unresolved records exactly", () => {
    const result = calculateCommerceBudgetExposure(
      exposureWith({
        committed: [
          committedRecord(ACTION_1, "100", "2025-01-01T00:00:05.000000000Z"),
          committedRecord(ACTION_2, "250", NOW),
        ],
        unresolved: [
          unresolvedRecord(ACTION_3, "7", "2024-01-01T00:00:00.000000000Z"),
          unresolvedRecord(ACTION_4, "3", NOW),
        ],
      }),
    );
    expect(result).toStrictEqual({
      exposureKey: EXPOSURE_KEY,
      asOf: NOW,
      windowSeconds: WINDOW_10,
      committedInWindowAtomic: "350",
      unresolvedAtomic: "10",
      totalExposureAtomic: "360",
    });
    expectTypeOf(result).toEqualTypeOf<CommerceBudgetExposure>();
  });

  it("excludes the cutoff exactly and includes one nanosecond after it", () => {
    const cutoffExcluded = calculateCommerceBudgetExposure(
      exposureWith({
        committed: [
          committedRecord(ACTION_1, "5", "2025-01-01T00:00:00.500000000Z"),
        ],
      }),
    );
    expect(cutoffExcluded.committedInWindowAtomic).toBe("0");

    const oneNanosecondAfter = calculateCommerceBudgetExposure(
      exposureWith({
        committed: [
          committedRecord(ACTION_1, "5", "2025-01-01T00:00:00.500000001Z"),
        ],
      }),
    );
    expect(oneNanosecondAfter.committedInWindowAtomic).toBe("5");

    const exactlyNow = calculateCommerceBudgetExposure(
      exposureWith({
        committed: [committedRecord(ACTION_1, "9", NOW)],
      }),
    );
    expect(exactlyNow.committedInWindowAtomic).toBe("9");
  });

  it("keeps sums above uint256 exact without wrap or clamp", () => {
    const result = calculateCommerceBudgetExposure(
      exposureWith({
        committed: [
          committedRecord(ACTION_1, MAX_UINT256, "2025-01-01T00:00:05.000000000Z"),
          committedRecord(ACTION_2, MAX_UINT256, NOW),
        ],
      }),
    );
    const doubled =
      "231584178474632390847141970017375815706539969331281128078915168015826259279870";
    expect(result.committedInWindowAtomic).toBe(doubled);
    expect(result.totalExposureAtomic).toBe(doubled);
  });

  it.each([
    ["unknown top-level key", { privatePrompt: "SECRET_CANARY" }],
    ["complete false", { complete: false }],
    ["missing complete", { complete: undefined }],
    ["committed not array", { committed: "nope" }],
    ["committed record extra key", { committed: [{ ...committedRecord(ACTION_1, "1", NOW), status: "claimed" }] }],
    ["zero amount", { committed: [committedRecord(ACTION_1, "0", NOW)] }],
    ["leading zero amount", { committed: [committedRecord(ACTION_1, "01", NOW)] }],
    ["over uint256 amount", { committed: [committedRecord(ACTION_1, OVER_UINT256, NOW)] }],
    ["trailing LF amount", { committed: [committedRecord(ACTION_1, "1\n", NOW)] }],
    ["trailing LF action id", { committed: [committedRecord(`${ACTION_1}\n`, "1", NOW)] }],
    ["trailing LF now", { now: `${NOW}\n` }],
    ["trailing LF window", { windowSeconds: "10\n" }],
    ["non-canonical window", { windowSeconds: "0" }],
    ["unordered committed", { committed: [committedRecord(ACTION_2, "1", NOW), committedRecord(ACTION_1, "1", NOW)] }],
    ["duplicate committed", { committed: [committedRecord(ACTION_1, "1", NOW), committedRecord(ACTION_1, "2", NOW)] }],
    ["unordered unresolved", { unresolved: [unresolvedRecord(ACTION_4, "1", NOW), unresolvedRecord(ACTION_3, "1", NOW)] }],
    ["duplicate unresolved", { unresolved: [unresolvedRecord(ACTION_3, "1", NOW), unresolvedRecord(ACTION_3, "2", NOW)] }],
    ["overlapping ids", { committed: [committedRecord(ACTION_2, "1", NOW)], unresolved: [unresolvedRecord(ACTION_2, "1", NOW)] }],
    ["future committed", { committed: [committedRecord(ACTION_1, "1", "2025-01-01T00:00:11Z")] }],
    ["future unresolved", { unresolved: [unresolvedRecord(ACTION_1, "1", "2025-01-01T00:00:11Z")] }],
    ["impossible committed date", { committed: [committedRecord(ACTION_1, "1", "2025-02-30T00:00:00Z")] }],
    ["bad exposure key", { exposureKey: { ...EXPOSURE_KEY, decimals: 18 } }],
    ["unresolved not array", { unresolved: [1, 2] }],
  ])("rejects %s with the fixed non-echoing error", (_label, patch) => {
    let thrown: unknown;
    expect(() => {
      try {
        calculateCommerceBudgetExposure(exposureWith(patch));
      } catch (error) {
        thrown = error;
        throw error;
      }
    }).toThrow(COMMERCE_BUDGET_INPUT_INVALID);
    expect((thrown as Error).message).toBe(COMMERCE_BUDGET_INPUT_INVALID);
    expect((thrown as Error).message).not.toContain("SECRET_CANARY");
  });

  it("rejects arrays over the 4096 record bound without truncation", () => {
    const tooMany = Array.from({ length: 4097 }, (_, index) =>
      committedRecord(
        `openarc:action:${index.toString(16).padStart(8, "0")}-1111-4111-8111-111111111111`,
        "1",
        NOW,
      ),
    );
    expect(() =>
      calculateCommerceBudgetExposure(exposureWith({ committed: tooMany })),
    ).toThrow(COMMERCE_BUDGET_INPUT_INVALID);
  });

  it("accepts the full 4096 record bound without slicing", () => {
    const full = Array.from({ length: 4096 }, (_, index) =>
      committedRecord(
        `openarc:action:${index.toString(16).padStart(8, "0")}-1111-4111-8111-111111111111`,
        "1",
        NOW,
      ),
    );
    const result = calculateCommerceBudgetExposure(
      exposureWith({ committed: full }),
    );
    expect(result.committedInWindowAtomic).toBe("4096");
  });

  it("is deterministic, does not mutate and freezes its input view", () => {
    const input = exposureWith({
      committed: [committedRecord(ACTION_1, "100", NOW)],
    });
    const snapshot = structuredClone(input);
    const first = calculateCommerceBudgetExposure(input);
    const second = calculateCommerceBudgetExposure(input);
    expect(first).toStrictEqual(second);
    expect(input).toStrictEqual(snapshot);
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first.exposureKey)).toBe(true);
  });
});

describe("assessCommerceBudgetLimits", () => {
  it("computes debit and satisfaction for amount + fee", () => {
    const result = assessCommerceBudgetLimits(assessmentInput());
    expect(result).toStrictEqual({
      assessment: "within_limits",
      reason: "limits_satisfied",
      debitAtomic: "101",
      totalExposureAtomic: "0",
      projectedExposureAtomic: "101",
      availableAtomic: "5000",
      deficitAtomic: "0",
    });
    expectTypeOf(result).toEqualTypeOf<CommerceBudgetAssessmentResult>();
  });

  it("applies debit to both per-action and rolling caps", () => {
    const perAction = assessCommerceBudgetLimits(
      assessmentWith({
        ...candidateWith({ amountAtomic: "1000", feeAtomic: "1" }),
      }),
    );
    expect(perAction.reason).toBe("per_action_limit_exceeded");
    expect(perAction.assessment).toBe("denied");

    const rolling = assessCommerceBudgetLimits(
      assessmentWith({
        policy: policyWith({ perActionLimit: null }),
        committedExposureAtomic: "4900",
        ...candidateWith({ amountAtomic: "101", feeAtomic: "0" }),
      }),
    );
    expect(rolling.reason).toBe("rolling_limit_exceeded");
    expect(rolling.projectedExposureAtomic).toBe("5001");
  });

  it("enforces the fee cap before other limits", () => {
    const result = assessCommerceBudgetLimits(
      assessmentWith({
        ...candidateWith({ amountAtomic: MAX_UINT256, feeAtomic: "11" }),
      }),
    );
    expect(result.reason).toBe("fee_limit_exceeded");
    expect(result.debitAtomic).toBe((BigInt(MAX_UINT256) + 11n).toString());
  });

  it("treats null caps as uncapped only for that cap", () => {
    const result = assessCommerceBudgetLimits(
      assessmentWith({
        policy: policyWith({
          perActionLimit: MAX_UINT256,
          rollingLimit: null,
          rollingWindowSeconds: null,
        }),
        committedExposureAtomic: "123456789",
        ...candidateWith({ amountAtomic: MAX_UINT256, feeAtomic: "0" }),
      }),
    );
    expect(result.assessment).toBe("within_limits");
    expect(result.availableAtomic).toBeNull();
    expect(result.projectedExposureAtomic).toBe(
      (123456789n + BigInt(MAX_UINT256)).toString(),
    );
    expect(result.totalExposureAtomic).toBe("123456789");
  });

  it("denies a positive debit against a zero cap", () => {
    const perAction = assessCommerceBudgetLimits(
      assessmentWith({ policy: policyWith({ perActionLimit: "0" }) }),
    );
    expect(perAction.reason).toBe("per_action_limit_exceeded");
    const rolling = assessCommerceBudgetLimits(
      assessmentWith({
        policy: policyWith({ perActionLimit: null, rollingLimit: "0" }),
      }),
    );
    expect(rolling.reason).toBe("rolling_limit_exceeded");
  });

  it("accepts equality at the per-action cap", () => {
    const result = assessCommerceBudgetLimits(
      assessmentWith({
        policy: policyWith({ rollingLimit: null, rollingWindowSeconds: null }),
        ...candidateWith({ amountAtomic: "999", feeAtomic: "1" }),
      }),
    );
    expect(result.reason).toBe("limits_satisfied");
    expect(result.debitAtomic).toBe("1000");
  });

  it("reports a lowered rolling limit as an existing deficit", () => {
    const result = assessCommerceBudgetLimits(
      assessmentWith({
        committedExposureAtomic: "6000",
        ...candidateWith({ amountAtomic: "1", feeAtomic: "0" }),
      }),
    );
    expect(result.reason).toBe("existing_exposure_deficit");
    expect(result.assessment).toBe("denied");
    expect(result.deficitAtomic).toBe("1000");
    expect(result.availableAtomic).toBe("0");
  });

  it("rejects a policy exposure-key mismatch", () => {
    expect(() =>
      assessCommerceBudgetLimits(
        assessmentWith({
          exposureKey: { ...EXPOSURE_KEY, subjectAgentId: `openarc:agent:${V2}` },
        }),
      ),
    ).toThrow(COMMERCE_BUDGET_INPUT_INVALID);
  });

  it("strengthens monetary policy leaves against trailing LF", () => {
    for (const patch of [
      { feeLimit: "10\n" },
      { perActionLimit: "1000\n" },
      {
        rollingLimit: "5000\n",
      },
      {
        approval: { mode: "above", threshold: "1\n", separateApprover: false },
      },
    ]) {
      expect(() =>
        assessCommerceBudgetLimits(assessmentWith({ policy: policyWith(patch) })),
      ).toThrow(COMMERCE_BUDGET_INPUT_INVALID);
    }
  });

  it("requires approval strictly above the threshold", () => {
    const abovePolicy = policyWith({
      approval: { mode: "above", threshold: "100", separateApprover: false },
    });
    const equal = assessCommerceBudgetLimits(
      assessmentWith({
        policy: abovePolicy,
        ...candidateWith({ amountAtomic: "99", feeAtomic: "1" }),
      }),
    );
    expect(equal.reason).toBe("limits_satisfied");

    const above = assessCommerceBudgetLimits(
      assessmentWith({
        policy: abovePolicy,
        ...candidateWith({ amountAtomic: "100", feeAtomic: "1" }),
      }),
    );
    expect(above.assessment).toBe("needs_approval");
    expect(above.reason).toBe("approval_required");
  });

  it("requires approval for mode always and never grants it", () => {
    const result = assessCommerceBudgetLimits(
      assessmentWith({
        policy: policyWith({
          approval: { mode: "always", threshold: null, separateApprover: true },
        }),
      }),
    );
    expect(result.assessment).toBe("needs_approval");
    expect(result.reason).toBe("approval_required");
    expect(result).not.toHaveProperty("approved");
  });

  it("keeps near-boundary aggregate and projected totals at 128 digits exactly", () => {
    const existing = `1${"0".repeat(127)}`; // 128 digits
    const result = assessCommerceBudgetLimits(
      assessmentWith({
        committedExposureAtomic: existing,
        unresolvedExposureAtomic: "0",
        policy: policyWith({
          perActionLimit: MAX_UINT256,
          rollingLimit: null,
          rollingWindowSeconds: null,
        }),
      }),
    );
    expect(result.totalExposureAtomic).toBe(existing);
    expect(result.projectedExposureAtomic).toBe(
      (BigInt(existing) + 101n).toString(),
    );
    expect(result.projectedExposureAtomic.length).toBe(128);
  });

  it("rejects an existing aggregate sum that would exceed 128 digits", () => {
    const maxTotal = "9".repeat(128);
    expect(() =>
      assessCommerceBudgetLimits(
        assessmentWith({
          committedExposureAtomic: maxTotal,
          unresolvedExposureAtomic: "1",
          policy: policyWith({
            perActionLimit: MAX_UINT256,
            rollingLimit: null,
            rollingWindowSeconds: null,
          }),
        }),
      ),
    ).toThrow(COMMERCE_BUDGET_INPUT_INVALID);
  });

  it("rejects a projected aggregate sum that would exceed 128 digits", () => {
    const maxTotal = "9".repeat(128);
    expect(() =>
      assessCommerceBudgetLimits(
        assessmentWith({
          committedExposureAtomic: maxTotal,
          unresolvedExposureAtomic: "0",
          policy: policyWith({
            perActionLimit: MAX_UINT256,
            rollingLimit: null,
            rollingWindowSeconds: null,
          }),
          ...candidateWith({ amountAtomic: "1", feeAtomic: "0" }),
        }),
      ),
    ).toThrow(COMMERCE_BUDGET_INPUT_INVALID);
  });

  it.each([
    ["overlong aggregate", { committedExposureAtomic: "9".repeat(129) }],
    ["aggregate trailing LF", { committedExposureAtomic: "1\n" }],
    ["candidate trailing LF amount", { candidate: { amountAtomic: "1\n", feeAtomic: "0" } }],
    ["candidate zero amount", { candidate: { amountAtomic: "0", feeAtomic: "0" } }],
    ["candidate over uint256 amount", { candidate: { amountAtomic: OVER_UINT256, feeAtomic: "0" } }],
    ["candidate over uint256 fee", { candidate: { amountAtomic: "1", feeAtomic: OVER_UINT256 } }],
    ["candidate unknown key", { candidate: { amountAtomic: "1", feeAtomic: "0", extra: "x" } }],
    ["unknown top-level key", { privatePrompt: "SECRET_CANARY" }],
    ["invalid policy shape", { policy: policyWith({ allowedProviderIds: ["openarc:provider:b"] }) }],
  ])("rejects %s with the fixed non-echoing error", (_label, patch) => {
    let thrown: unknown;
    expect(() => {
      try {
        assessCommerceBudgetLimits(assessmentWith(patch));
      } catch (error) {
        thrown = error;
        throw error;
      }
    }).toThrow(COMMERCE_BUDGET_INPUT_INVALID);
    expect((thrown as Error).message).toBe(COMMERCE_BUDGET_INPUT_INVALID);
    expect((thrown as Error).message).not.toContain("SECRET_CANARY");
  });

  it("is deterministic, does not mutate and freezes its input view", () => {
    const input = assessmentInput();
    const snapshot = structuredClone(input);
    const first = assessCommerceBudgetLimits(input);
    const second = assessCommerceBudgetLimits(input);
    expect(first).toStrictEqual(second);
    expect(input).toStrictEqual(snapshot);
    expect(Object.isFrozen(first)).toBe(true);
  });
});

describe("shared root export closure", () => {
  it("re-exports the exact error constant and functions through the index", () => {
    expect(ERROR).toBe(MODULE_ERROR);
    expect(assessCommerceBudgetLimits).toBe(moduleAssess);
  });

  it("exposes the advertised inferred types", () => {
    expectTypeOf<CommerceExposureKey["decimals"]>().toEqualTypeOf<6>();
    expectTypeOf<CommercePolicyContent["feeLimit"]>().toEqualTypeOf<string>();
  });
});
