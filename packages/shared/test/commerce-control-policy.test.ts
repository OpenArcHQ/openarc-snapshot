import { describe, expect, expectTypeOf, it } from "vitest";

import {
  COMMERCE_POLICY_ROOT_SCHEMA_VERSION,
  COMMERCE_POLICY_SCHEMA_VERSION,
  CommercePolicyApprovalSchema,
  CommercePolicyContentSchema,
  CommercePolicyIdSchema,
  CommercePolicyRevisionNumberSchema,
  CommercePolicyRevisionSchema,
  CommercePolicyRootSchema,
  type CommercePolicyApproval,
  type CommercePolicyContent,
  type CommercePolicyRoot,
} from "../src/index.js";
import {
  COMMERCE_POLICY_SCHEMA_VERSION as MODULE_POLICY_VERSION,
  CommercePolicyRevisionSchema as ModulePolicyRevisionSchema,
} from "../src/commerce/control-policy.js";

/**
 * Focused contract tests for the pure policy DTOs. Primitive ID/uint256/
 * timestamp/digest matrices are already proven elsewhere, so this suite uses
 * compact tables and only asserts the policy-specific grammar, cross-field
 * rules, strictness and the additive index export.
 */

const V4 = "12345678-1234-4234-8123-123456789abc";
const V5 = "87654321-4321-4321-b321-cba987654321";
const POLICY_ID = `openarc:policy:${V4}`;
const ORG_ID = `openarc:org:${V4}`;
const AGENT_ID = `openarc:agent:${V4}`;
const PROVIDER_A = `openarc:provider:${V4}`;
const PROVIDER_B = `openarc:provider:${V5}`;
const LISTING_A = `openarc:listing:${V4}`;
const LISTING_B = `openarc:listing:${V5}`;
const CREATED_AT = "2025-01-01T00:00:00.000000Z";
const LATER_AT = "2025-01-02T00:00:00.000000Z";
const EXPIRES_AT = "2025-02-01T00:00:00.000000Z";
const DIGEST = `sha256:${"a".repeat(64)}`;
const MAX_UINT256 =
  "115792089237316195423570985008687907853269984665640564039457584007913129639935";
const OVER_UINT256 =
  "115792089237316195423570985008687907853269984665640564039457584007913129639936";

function baseContent(): Record<string, unknown> {
  return {
    organizationId: ORG_ID,
    subjectAgentId: AGENT_ID,
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

function baseRevision(): Record<string, unknown> {
  return {
    schemaVersion: "openarc.control.policy.v1",
    policyId: POLICY_ID,
    revision: "1",
    ...baseContent(),
    createdAt: CREATED_AT,
    digest: DIGEST,
  };
}

function baseRoot(): Record<string, unknown> {
  return {
    schemaVersion: "openarc.control.policy-root.v1",
    policyId: POLICY_ID,
    organizationId: ORG_ID,
    subjectAgentId: AGENT_ID,
    currentRevision: "1",
    status: "active",
    createdAt: CREATED_AT,
    updatedAt: LATER_AT,
  };
}

function contentWith(patch: Record<string, unknown>): Record<string, unknown> {
  return { ...baseContent(), ...patch };
}

function revisionWith(patch: Record<string, unknown>): Record<string, unknown> {
  return { ...baseRevision(), ...patch };
}

function rootWith(patch: Record<string, unknown>): Record<string, unknown> {
  return { ...baseRoot(), ...patch };
}

function providerIds(count: number): string[] {
  return Array.from({ length: count }, (_, index) =>
    `openarc:provider:${index.toString(16).padStart(8, "0")}-1234-4234-8123-123456789abc`,
  );
}

function listingIds(count: number): string[] {
  return Array.from({ length: count }, (_, index) =>
    `openarc:listing:${index.toString(16).padStart(8, "0")}-1234-4234-8123-123456789abc`,
  );
}

describe("CommercePolicyIdSchema", () => {
  it.each([V4, V5])("accepts canonical policy id %s", (uuid) => {
    expect(CommercePolicyIdSchema.safeParse(`openarc:policy:${uuid}`).success).toBe(
      true,
    );
  });

  it.each([
    `openarc:policy:${V4.toUpperCase()}`,
    `openarc:policy:${V4}\n`,
    `openarc:policy:${V4} `,
    "openarc:org:12345678-1234-4234-8123-123456789abc",
    "12345678-1234-4234-8123-123456789abc",
    "openarc:policy:12345678-1234-0234-8123-123456789abc",
    "openarc:policy:12345678-1234-4234-7123-123456789abc",
    `openarc:policy:${V4}extra`,
  ])("rejects non-canonical policy id %s", (value) => {
    expect(CommercePolicyIdSchema.safeParse(value).success).toBe(false);
  });
});

describe("canonical bounded decimal strings", () => {
  it.each(["1", "2", "999999999"])("accepts revision %s", (value) => {
    expect(CommercePolicyRevisionNumberSchema.safeParse(value).success).toBe(true);
  });

  it.each(["0", "01", "1000000000", "1.0", "-1", " 1", "1\n", ""])(
    "rejects revision %s",
    (value) => {
      expect(CommercePolicyRevisionNumberSchema.safeParse(value).success).toBe(
        false,
      );
    },
  );

  it.each(["1", "2592000"])("accepts window %s through content", (value) => {
    const parsed = CommercePolicyContentSchema.safeParse(
      contentWith({
        perActionLimit: null,
        rollingLimit: "1000",
        rollingWindowSeconds: value,
      }),
    );
    expect(parsed.success).toBe(true);
  });

  it.each(["0", "2592001", "01", "1\n", "1.5"])(
    "rejects window %s through content",
    (value) => {
      const parsed = CommercePolicyContentSchema.safeParse(
        contentWith({
          perActionLimit: null,
          rollingLimit: "1000",
          rollingWindowSeconds: value,
        }),
      );
      expect(parsed.success).toBe(false);
    },
  );
});

describe("CommercePolicyApprovalSchema", () => {
  const VALID: readonly [string, Record<string, unknown>][] = [
    ["none", { mode: "none", threshold: null, separateApprover: false }],
    ["always", { mode: "always", threshold: null, separateApprover: true }],
    ["above", { mode: "above", threshold: "1", separateApprover: false }],
    ["above separate", { mode: "above", threshold: MAX_UINT256, separateApprover: true }],
  ];

  it.each(VALID)("accepts %s approval", (_label, value) => {
    expect(CommercePolicyApprovalSchema.safeParse(value).success).toBe(true);
  });

  const INVALID: readonly [string, Record<string, unknown>][] = [
    ["none carrying approver", { mode: "none", threshold: null, separateApprover: true }],
    ["none with threshold", { mode: "none", threshold: "1", separateApprover: false }],
    ["always with threshold", { mode: "always", threshold: "1", separateApprover: false }],
    ["above null threshold", { mode: "above", threshold: null, separateApprover: false }],
    ["above zero threshold", { mode: "above", threshold: "0", separateApprover: false }],
    ["above over uint256", { mode: "above", threshold: OVER_UINT256, separateApprover: false }],
    ["unknown mode", { mode: "sometimes", threshold: null, separateApprover: false }],
    ["unknown key", { mode: "none", threshold: null, separateApprover: false, extra: 1 }],
  ];

  it.each(INVALID)("rejects %s approval", (_label, value) => {
    expect(CommercePolicyApprovalSchema.safeParse(value).success).toBe(false);
  });

  it.each([
    ["exponent", "1e2"],
    ["fraction", "1.5"],
    ["invalid letters", "not-a-number"],
    ["overflow", OVER_UINT256],
    ["trailing newline", "1\n"],
    ["leading sign", "+1"],
    ["empty", ""],
  ])(
    "does not throw for above + %s and reports an ordinary failure",
    (_label, threshold) => {
      let parsed: ReturnType<typeof CommercePolicyApprovalSchema.safeParse> | undefined;
      expect(() => {
        parsed = CommercePolicyApprovalSchema.safeParse({
          mode: "above",
          threshold,
          separateApprover: false,
        });
      }).not.toThrow();
      expect(parsed!.success).toBe(false);
    },
  );

  it.each([
    ["exponent", "1e2"],
    ["fraction", "1.5"],
    ["invalid letters", "not-a-number"],
    ["overflow", OVER_UINT256],
    ["trailing newline", "1\n"],
  ])(
    "does not throw for an above threshold %s nested in content",
    (_label, threshold) => {
      let parsed: ReturnType<typeof CommercePolicyContentSchema.safeParse> | undefined;
      expect(() => {
        parsed = CommercePolicyContentSchema.safeParse(
          contentWith({
            approval: { mode: "above", threshold, separateApprover: false },
          }),
        );
      }).not.toThrow();
      expect(parsed!.success).toBe(false);
    },
  );

  it.each([
    ["exponent", "1e2"],
    ["fraction", "1.5"],
    ["invalid letters", "not-a-number"],
    ["overflow", OVER_UINT256],
    ["trailing newline", "1\n"],
  ])(
    "does not throw for an above threshold %s nested in revision",
    (_label, threshold) => {
      let parsed: ReturnType<typeof CommercePolicyRevisionSchema.safeParse> | undefined;
      expect(() => {
        parsed = CommercePolicyRevisionSchema.safeParse(
          revisionWith({
            approval: { mode: "above", threshold, separateApprover: false },
          }),
        );
      }).not.toThrow();
      expect(parsed!.success).toBe(false);
    },
  );
});

describe("CommercePolicyContentSchema", () => {
  it("parses a valid flat content record without mutating input", () => {
    const input = contentWith({});
    const snapshot = structuredClone(input);
    const parsed = CommercePolicyContentSchema.safeParse(input);
    expect(parsed.success).toBe(true);
    expect(input).toEqual(snapshot);
    if (parsed.success) {
      expectTypeOf(parsed.data).toEqualTypeOf<CommercePolicyContent>();
      expect(Object.keys(parsed.data).sort()).toEqual(Object.keys(baseContent()).sort());
    }
  });

  it("allows a zero deny-all cap and an empty eligible set", () => {
    expect(
      CommercePolicyContentSchema.safeParse(
        contentWith({ perActionLimit: "0", rollingLimit: null }),
      ).success,
    ).toBe(true);
    expect(
      CommercePolicyContentSchema.safeParse(
        contentWith({
          perActionLimit: null,
          rollingLimit: "0",
          rollingWindowSeconds: "1",
        }),
      ).success,
    ).toBe(true);
  });

  it.each([
    ["both caps null", { perActionLimit: null, rollingLimit: null }],
    ["rolling window without rolling cap", { rollingWindowSeconds: "60" }],
    [
      "rolling cap without window",
      { perActionLimit: null, rollingLimit: "1000", rollingWindowSeconds: null },
    ],
    ["mainnet network", { networkId: "eip155:1" }],
    ["wrong asset", { asset: "USDC.e" }],
    ["native representation", { representation: "native" }],
    ["native decimals", { decimals: 18 }],
    ["missing fee", { feeLimit: undefined }],
    ["negative fee", { feeLimit: "-1" }],
    ["fee over uint256", { feeLimit: OVER_UINT256 }],
    ["overflow cap", { perActionLimit: OVER_UINT256 }],
    ["expires not timestamp", { expiresAt: "2025-02-01" }],
    ["unknown key", { privatePrompt: "canary" }],
  ])("rejects %s", (_label, patch) => {
    expect(CommercePolicyContentSchema.safeParse(contentWith(patch)).success).toBe(
      false,
    );
  });

  it.each([
    ["unsorted provider ids", { allowedProviderIds: [PROVIDER_B, PROVIDER_A] }],
    ["duplicate provider ids", { allowedProviderIds: [PROVIDER_A, PROVIDER_A] }],
    ["unsorted listing ids", { allowedListingIds: [LISTING_B, LISTING_A] }],
    ["duplicate listing ids", { allowedListingIds: [LISTING_A, LISTING_A] }],
  ])("rejects %s", (_label, patch) => {
    expect(CommercePolicyContentSchema.safeParse(contentWith(patch)).success).toBe(
      false,
    );
  });

  it("accepts sorted unique arrays and rejects over-bound arrays", () => {
    expect(
      CommercePolicyContentSchema.safeParse(
        contentWith({
          allowedProviderIds: providerIds(64),
          allowedListingIds: listingIds(128),
        }),
      ).success,
    ).toBe(true);
    expect(
      CommercePolicyContentSchema.safeParse(
        contentWith({ allowedProviderIds: providerIds(65) }),
      ).success,
    ).toBe(false);
    expect(
      CommercePolicyContentSchema.safeParse(
        contentWith({ allowedListingIds: listingIds(129) }),
      ).success,
    ).toBe(false);
  });
});

describe("CommercePolicyRevisionSchema", () => {
  it("parses a valid flat revision with microsecond ordering", () => {
    const parsed = CommercePolicyRevisionSchema.safeParse(
      revisionWith({ expiresAt: EXPIRES_AT }),
    );
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(Object.keys(parsed.data).sort()).toEqual(
        [
          "allowedListingIds",
          "allowedProviderIds",
          "approval",
          "asset",
          "createdAt",
          "decimals",
          "digest",
          "expiresAt",
          "feeLimit",
          "networkId",
          "organizationId",
          "perActionLimit",
          "policyId",
          "representation",
          "revision",
          "rollingLimit",
          "rollingWindowSeconds",
          "schemaVersion",
          "subjectAgentId",
        ].sort(),
      );
    }
  });

  it.each([
    ["wrong version", { schemaVersion: "openarc.control.policy.v2" }],
    ["wrong policy id", { policyId: `openarc:org:${V4}` }],
    ["zero revision", { revision: "0" }],
    ["expiry equal to createdAt", { createdAt: EXPIRES_AT, expiresAt: EXPIRES_AT }],
    ["expiry before createdAt", { createdAt: LATER_AT, expiresAt: CREATED_AT }],
    ["bad digest", { digest: "sha256:ABC" }],
    ["reservation shape", { reservation: { held: "1" } }],
  ])("rejects %s", (_label, patch) => {
    expect(CommercePolicyRevisionSchema.safeParse(revisionWith(patch)).success).toBe(
      false,
    );
  });

  it("rejects a null rolling window mismatch and both-null caps", () => {
    expect(
      CommercePolicyRevisionSchema.safeParse(
        revisionWith({ perActionLimit: null, rollingLimit: null }),
      ).success,
    ).toBe(false);
    expect(
      CommercePolicyRevisionSchema.safeParse(
        revisionWith({ rollingWindowSeconds: "60" }),
      ).success,
    ).toBe(false);
  });
});

describe("CommercePolicyRootSchema", () => {
  it("parses a valid root and enforces non-decreasing timestamps", () => {
    expect(CommercePolicyRootSchema.safeParse(baseRoot()).success).toBe(true);
    expect(
      CommercePolicyRootSchema.safeParse(
        rootWith({ createdAt: LATER_AT, updatedAt: CREATED_AT }),
      ).success,
    ).toBe(false);
  });

  it.each([
    ["wrong version", { schemaVersion: "openarc.control.policy-root.v2" }],
    ["bad status", { status: "deleted" }],
    ["current revision zero", { currentRevision: "0" }],
    ["unknown key", { availableBalance: "1" }],
    ["private canary", { privatePrompt: "SECRET_CANARY" }],
  ])("rejects %s", (_label, patch) => {
    expect(CommercePolicyRootSchema.safeParse(rootWith(patch)).success).toBe(false);
  });

  it("infers the root type", () => {
    const parsed = CommercePolicyRootSchema.parse(baseRoot());
    expectTypeOf(parsed).toEqualTypeOf<CommercePolicyRoot>();
    expectTypeOf(parsed.status).toEqualTypeOf<"active" | "paused" | "revoked">();
  });
});

describe("shared root export closure", () => {
  it("re-exports the exact policy validators through the index", () => {
    expect(COMMERCE_POLICY_SCHEMA_VERSION).toBe(MODULE_POLICY_VERSION);
    expect(COMMERCE_POLICY_ROOT_SCHEMA_VERSION).toBe(
      "openarc.control.policy-root.v1",
    );
    expect(CommercePolicyRevisionSchema).toBe(ModulePolicyRevisionSchema);
  });

  it("exposes the advertised inferred types", () => {
    expectTypeOf<CommercePolicyApproval>().toMatchTypeOf<{
      mode: "none" | "always" | "above";
      threshold: string | null;
      separateApprover: boolean;
    }>();
    expectTypeOf<CommercePolicyContent["feeLimit"]>().toEqualTypeOf<string>();
  });
});
