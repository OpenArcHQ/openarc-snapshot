import { describe, expect, expectTypeOf, it } from "vitest";

import {
  CommerceControlSessionExchangeBodySchema,
  CommerceControlSessionExchangeResultResponseSchema,
  CommerceControlSessionExchangeResultSchema,
  CommerceControlHandoffTokenSchema,
  CommerceControlSessionIdSchema,
  CommerceControlSessionIssueBodySchema,
  CommerceControlSessionIssueResultResponseSchema,
  CommerceControlSessionIssueResultSchema,
  CommerceControlSessionListRequestSchema,
  CommerceControlSessionListResponseSchema,
  CommerceControlSessionListSchema,
  CommerceControlSessionMetadataSchema,
  CommerceControlSessionMutationRequestSchema,
  CommerceControlSessionMutationStatusResponseSchema,
  CommerceControlSessionMutationStatusSchema,
  CommerceControlSessionReceiptSchema,
  CommerceControlSessionRequestSchema,
  CommerceControlSessionRevokeBodySchema,
  CommerceControlSessionRevokeResultResponseSchema,
  CommerceControlSessionRevokeResultSchema,
  CommerceControlSessionScopesSchema,
  CommerceControlSessionStatusItemSchema,
  CommerceControlSessionStatusResponseSchema,
  CommerceControlSessionStatusSchema,
  CommerceControlSessionTokenSchema as CONTROL_SESSION_TOKEN,
  type CommerceControlSessionMetadata,
  type CommerceControlSessionStatusItem,
} from "../src/index.js";
import {
  CommerceControlSessionTokenSchema as MODULE_TOKEN,
} from "../src/commerce/control-session.js";

const V4 = "12345678-1234-4234-8123-123456789abc";
const V4_B = "87654321-4321-4321-b123-cba987654321";

const ORG = `openarc:org:${V4}`;
const AGENT = `openarc:agent:${V4}`;
const POLICY = `openarc:policy:${V4}`;
const SESSION = V4;
const SESSION_B = V4_B;

const SECRET = `${"A".repeat(42)}A`;
const ZERO_BITS_SECRET = `${"A".repeat(42)}A`;
const HANDOFF = `oach_v1_${SECRET}`;
const SESSION_TOKEN = `oacs_v1_${SECRET}`;

const ISSUED = "2025-01-01T00:00:00.000000000Z";
const EXPIRES_MAX = "2025-01-01T00:15:00.000000000Z"; // exactly 900s
const EXPIRES_TOO_LATE = "2025-01-01T00:15:00.000000001Z"; // 900s + 1ns
const EXPIRES_SHORT = "2025-01-01T00:05:00.000000000Z";
const HANDOFF_MAX = "2025-01-01T00:05:00.000000000Z"; // exactly 300s
const HANDOFF_TOO_LATE = "2025-01-01T00:05:00.000000001Z"; // 300s + 1ns
const EXCHANGED_AT = "2025-01-01T00:01:00.000000000Z";
const REVOKED_AT = "2025-01-01T00:02:00.000000000Z";
const REVOKED_AFTER_EXPIRY = "2025-01-01T01:00:00.000000000Z";

const META = {
  schemaVersion: "openarc.api.v2" as const,
  requestId: "9f1c2d34-5e6a-4b7c-8d9e-0f1a2b3c4d5e",
  buildSha: "0123456789abcdef0123456789abcdef01234567",
};

function metadata(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schemaVersion: "openarc.control.commerce-session.v1",
    sessionId: SESSION,
    organizationId: ORG,
    subjectAgentId: AGENT,
    policyId: POLICY,
    scopes: ["commerce.authorize"],
    networkId: "eip155:5042002",
    asset: "USDC",
    representation: "erc20",
    decimals: 6,
    issuedAt: ISSUED,
    expiresAt: EXPIRES_SHORT,
    exchangedAt: null,
    revokedAt: null,
    ...overrides,
  };
}

function receipt(
  operation = "control.commerce_session.issue",
  resourceId = SESSION,
): Record<string, unknown> {
  return {
    mutationId: SESSION,
    operation,
    resourceType: "commerce_session",
    resourceId,
    committedAt: EXCHANGED_AT,
  };
}

function statusItem(
  status: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return { metadata: metadata(overrides), status };
}

function envelope(data: unknown) {
  return { ok: true, data, meta: META };
}

describe("metadata", () => {
  it("parses a strict pending metadata and preserves input", () => {
    const input = metadata();
    const snapshot = structuredClone(input);
    const parsed = CommerceControlSessionMetadataSchema.safeParse(input);
    expect(parsed.success).toBe(true);
    expect(input).toEqual(snapshot);
    if (parsed.success) {
      expectTypeOf(parsed.data).toEqualTypeOf<CommerceControlSessionMetadata>();
    }
  });

  it("accepts full 9-fraction-digit bounds exactly", () => {
    expect(
      CommerceControlSessionMetadataSchema.safeParse(
        metadata({ issuedAt: ISSUED, expiresAt: EXPIRES_MAX }),
      ).success,
    ).toBe(true);
  });

  it("rejects 900 seconds + 1 nanosecond and a too-early expiry", () => {
    expect(
      CommerceControlSessionMetadataSchema.safeParse(
        metadata({ expiresAt: EXPIRES_TOO_LATE }),
      ).success,
    ).toBe(false);
    expect(
      CommerceControlSessionMetadataSchema.safeParse(
        metadata({ expiresAt: ISSUED }),
      ).success,
    ).toBe(false);
    expect(
      CommerceControlSessionMetadataSchema.safeParse(
        metadata({ issuedAt: EXPIRES_SHORT, expiresAt: ISSUED }),
      ).success,
    ).toBe(false);
  });

  it("enforces exchangedAt bounds and revokedAt ordering", () => {
    expect(
      CommerceControlSessionMetadataSchema.safeParse(
        metadata({ exchangedAt: EXCHANGED_AT }),
      ).success,
    ).toBe(true);
    expect(
      CommerceControlSessionMetadataSchema.safeParse(
        metadata({ exchangedAt: ISSUED }),
      ).success,
    ).toBe(true);
    expect(
      CommerceControlSessionMetadataSchema.safeParse(
        metadata({ exchangedAt: EXPIRES_SHORT }),
      ).success,
    ).toBe(false);
    expect(
      CommerceControlSessionMetadataSchema.safeParse(
        metadata({ revokedAt: REVOKED_AT }),
      ).success,
    ).toBe(true);
    // Revocation may occur after expiry.
    expect(
      CommerceControlSessionMetadataSchema.safeParse(
        metadata({ revokedAt: REVOKED_AFTER_EXPIRY }),
      ).success,
    ).toBe(true);
    expect(
      CommerceControlSessionMetadataSchema.safeParse(
        metadata({ exchangedAt: EXCHANGED_AT, revokedAt: ISSUED }),
      ).success,
    ).toBe(false);
  });

  it.each([
    ["unknown key", { canary: "SECRET" }],
    ["missing exchangedAt", undefined],
    ["present-undefined exchangedAt", { exchangedAt: undefined }],
    ["wrong scope", { scopes: ["commerce.authorize", "commerce.spend"] }],
    ["old machine scope", { scopes: ["agent:self.read"] }],
    ["empty scope", { scopes: [] }],
    ["wrong asset", { asset: "USDT" }],
    ["wrong decimals", { decimals: 18 }],
    ["wrong network", { networkId: "eip155:1" }],
    ["wrong schemaVersion", { schemaVersion: "openarc.control.commerce-session.v2" }],
    ["bad policy id", { policyId: ORG }],
    ["uuid version 9", { sessionId: "12345678-1234-9234-8123-123456789abc" }],
  ])("rejects metadata %s", (_label, patch) => {
    const value = patch === undefined ? metadata() : { ...metadata(), ...patch };
    if (patch === undefined) {
      const withoutExchanged: Record<string, unknown> = metadata();
      delete withoutExchanged.exchangedAt;
      expect(
        CommerceControlSessionMetadataSchema.safeParse(withoutExchanged).success,
      ).toBe(false);
      return;
    }
    expect(CommerceControlSessionMetadataSchema.safeParse(value).success).toBe(
      false,
    );
  });

  it.each([
    "not-a-date",
    "2025-13-01T00:00:00Z",
    "2025-01-01",
    "1e2",
    "",
    "2025-01-01T00:00:00.1234567890Z",
  ])("does not throw for malformed issuedAt %s", (value) => {
    expect(() =>
      CommerceControlSessionMetadataSchema.safeParse(
        metadata({ issuedAt: value }),
      ),
    ).not.toThrow();
    expect(
      CommerceControlSessionMetadataSchema.safeParse(
        metadata({ issuedAt: value }),
      ).success,
    ).toBe(false);
  });

  it.each(["exchangedAt", "revokedAt"])(
    "does not throw for malformed %s",
    (key) => {
      expect(() =>
        CommerceControlSessionMetadataSchema.safeParse(
          metadata({ [key]: "not-a-date" }),
        ),
      ).not.toThrow();
      expect(
        CommerceControlSessionMetadataSchema.safeParse(
          metadata({ [key]: "not-a-date" }),
        ).success,
      ).toBe(false);
    },
  );
});

describe("status item", () => {
  it.each([
    ["handoff_pending", { exchangedAt: null, revokedAt: null }],
    ["active", { exchangedAt: EXCHANGED_AT, revokedAt: null }],
    ["revoked", { exchangedAt: null, revokedAt: REVOKED_AT }],
    ["expired", { exchangedAt: EXCHANGED_AT, revokedAt: null }],
    ["invalidated", { exchangedAt: EXCHANGED_AT, revokedAt: null }],
  ])("accepts %s", (status, overrides) => {
    expect(
      CommerceControlSessionStatusItemSchema.safeParse(
        statusItem(status, overrides),
      ).success,
    ).toBe(true);
  });

  it("rejects inconsistent status/metadata combinations", () => {
    expect(
      CommerceControlSessionStatusItemSchema.safeParse(
        statusItem("revoked", { revokedAt: null }),
      ).success,
    ).toBe(false);
    expect(
      CommerceControlSessionStatusItemSchema.safeParse(
        statusItem("active", { exchangedAt: null }),
      ).success,
    ).toBe(false);
    expect(
      CommerceControlSessionStatusItemSchema.safeParse(
        statusItem("handoff_pending", { exchangedAt: EXCHANGED_AT }),
      ).success,
    ).toBe(false);
    expect(
      CommerceControlSessionStatusItemSchema.safeParse(
        statusItem("expired", { revokedAt: REVOKED_AT }),
      ).success,
    ).toBe(false);
    expect(
      CommerceControlSessionStatusItemSchema.safeParse({
        metadata: metadata(),
        status: "pending",
      }).success,
    ).toBe(false);
    expect(
      CommerceControlSessionStatusItemSchema.safeParse({
        metadata: metadata(),
        status: "revoked",
        handoffToken: HANDOFF,
      }).success,
    ).toBe(false);
  });
});

describe("tokens and bodies", () => {
  it("accepts the two canonical namespaces with zero padding bits", () => {
    expect(CommerceControlHandoffTokenSchema.safeParse(HANDOFF).success).toBe(
      true,
    );
    expect(CONTROL_SESSION_TOKEN.safeParse(SESSION_TOKEN).success).toBe(true);
    expect(ZERO_BITS_SECRET.endsWith("A")).toBe(true);
  });

  it.each([
    ["machine agent session", `oas_ag_${SECRET}`],
    ["machine provider session", `oas_pr_${SECRET}`],
    ["machine credential", `oac_ag_${V4}_${SECRET}`],
    ["old oac namespace", `oac_${SECRET}`],
    ["wrong version", `oach_v1_${SECRET}`.replace("v1", "v2")],
    ["too short", `oach_v1_${"A".repeat(42)}`],
    ["too long", `oach_v1_${"A".repeat(44)}`],
    ["padding", `oach_v1_${"A".repeat(42)}=`],
    ["nonzero padding bits", `oach_v1_${"A".repeat(42)}B`],
    ["trailing newline", `${HANDOFF}\n`],
    ["trailing space", `${HANDOFF} `],
  ])("rejects the %s token", (_label, token) => {
    expect(CommerceControlHandoffTokenSchema.safeParse(token).success).toBe(
      false,
    );
    expect(CONTROL_SESSION_TOKEN.safeParse(token).success).toBe(false);
  });

  it("rejects cross-namespace substitution in both directions", () => {
    // The handoff namespace cannot accept a commerce session token and vice
    // versa, even though both share the same 43-character secret grammar.
    expect(CommerceControlHandoffTokenSchema.safeParse(SESSION_TOKEN).success).toBe(
      false,
    );
    expect(CONTROL_SESSION_TOKEN.safeParse(HANDOFF).success).toBe(false);
  });

  it("is the same token validator through the index", () => {
    expect(CONTROL_SESSION_TOKEN).toBe(MODULE_TOKEN);
    expect(CommerceControlSessionIdSchema).toBe(CommerceControlSessionIdSchema);
  });

  it.each(["1", "300", "900"])("accepts issue duration %s", (durationSeconds) => {
    expect(
      CommerceControlSessionIssueBodySchema.safeParse({
        mutationId: SESSION,
        subjectAgentId: AGENT,
        policyId: POLICY,
        durationSeconds,
      }).success,
    ).toBe(true);
  });

  it("accepts an issue body with no duration and inserts no default", () => {
    const parsed = CommerceControlSessionIssueBodySchema.safeParse({
      mutationId: SESSION,
      subjectAgentId: AGENT,
      policyId: POLICY,
    });
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect("durationSeconds" in parsed.data).toBe(false);
    }
  });

  it.each(["0", "901", "999", "1000", "01", "1.0", "1e2", "1\n", "", " 1", "+1"])(
    "rejects issue duration %s",
    (durationSeconds) => {
      expect(
        CommerceControlSessionIssueBodySchema.safeParse({
          mutationId: SESSION,
          subjectAgentId: AGENT,
          policyId: POLICY,
          durationSeconds,
        }).success,
      ).toBe(false);
    },
  );

  it("rejects unknown and explicit-undefined issue body keys", () => {
    expect(
      CommerceControlSessionIssueBodySchema.safeParse({
        mutationId: SESSION,
        subjectAgentId: AGENT,
        policyId: POLICY,
        organizationId: ORG,
      }).success,
    ).toBe(false);
    expect(
      CommerceControlSessionIssueBodySchema.safeParse({
        mutationId: SESSION,
        subjectAgentId: AGENT,
        policyId: POLICY,
        durationSeconds: undefined,
      }).success,
    ).toBe(false);
  });

  it("parses revoke and exchange bodies strictly", () => {
    expect(
      CommerceControlSessionRevokeBodySchema.safeParse({ mutationId: SESSION })
        .success,
    ).toBe(true);
    expect(
      CommerceControlSessionExchangeBodySchema.safeParse({
        mutationId: SESSION,
        handoffToken: HANDOFF,
      }).success,
    ).toBe(true);
    expect(
      CommerceControlSessionExchangeBodySchema.safeParse({
        mutationId: SESSION,
        handoffToken: SESSION_TOKEN,
      }).success,
    ).toBe(false);
    expect(
      CommerceControlSessionRevokeBodySchema.safeParse({
        mutationId: SESSION,
        actor: "human",
      }).success,
    ).toBe(false);
    expect(
      CommerceControlSessionExchangeBodySchema.safeParse({
        mutationId: SESSION,
        handoffToken: HANDOFF,
        proof: "x",
      }).success,
    ).toBe(false);
  });
});

describe("receipt", () => {
  it("accepts the three exact operation tuples", () => {
    for (const operation of [
      "control.commerce_session.issue",
      "control.commerce_session.exchange",
      "control.commerce_session.revoke",
    ]) {
      expect(
        CommerceControlSessionReceiptSchema.safeParse(receipt(operation)).success,
      ).toBe(true);
    }
  });

  it.each([
    ["unknown operation", receipt("control.commerce_session.cancel")],
    ["wrong resourceType", { ...receipt(), resourceType: "credential" }],
    ["bad resourceId", { ...receipt(), resourceId: "nope" }],
    ["unknown key", { ...receipt(), token: HANDOFF }],
  ])("rejects the %s receipt", (_label, value) => {
    expect(CommerceControlSessionReceiptSchema.safeParse(value).success).toBe(false);
  });
});

describe("issue result", () => {
  it("accepts a fresh handoff delivery with exact 300s bound", () => {
    expect(
      CommerceControlSessionIssueResultSchema.safeParse({
        organizationId: ORG,
        replayed: false,
        metadata: metadata({ expiresAt: EXPIRES_MAX }),
        receipt: receipt(),
        delivery: {
          state: "available_once",
          handoffToken: HANDOFF,
          handoffExpiresAt: HANDOFF_MAX,
        },
      }).success,
    ).toBe(true);
  });

  it("rejects 300s + 1ns and expiry-violating handoff deadlines", () => {
    expect(
      CommerceControlSessionIssueResultSchema.safeParse({
        organizationId: ORG,
        replayed: false,
        metadata: metadata({ expiresAt: EXPIRES_MAX }),
        receipt: receipt(),
        delivery: {
          state: "available_once",
          handoffToken: HANDOFF,
          handoffExpiresAt: HANDOFF_TOO_LATE,
        },
      }).success,
    ).toBe(false);
    expect(
      CommerceControlSessionIssueResultSchema.safeParse({
        organizationId: ORG,
        replayed: false,
        metadata: metadata({ expiresAt: "2025-01-01T00:04:59.000000000Z" }),
        receipt: receipt(),
        delivery: {
          state: "available_once",
          handoffToken: HANDOFF,
          handoffExpiresAt: HANDOFF_MAX,
        },
      }).success,
    ).toBe(false);
    expect(
      CommerceControlSessionIssueResultSchema.safeParse({
        organizationId: ORG,
        replayed: false,
        metadata: metadata(),
        receipt: receipt(),
        delivery: {
          state: "available_once",
          handoffToken: HANDOFF,
          handoffExpiresAt: ISSUED,
        },
      }).success,
    ).toBe(false);
  });

  it("rejects fresh issuance carrying exchanged/revoked state and bindings", () => {
    const base = {
      organizationId: ORG,
      replayed: false,
      receipt: receipt(),
      delivery: {
        state: "available_once",
        handoffToken: HANDOFF,
        handoffExpiresAt: HANDOFF_MAX,
      },
    };
    for (const patch of [
      { metadata: metadata({ exchangedAt: EXCHANGED_AT }) },
      { metadata: metadata({ revokedAt: REVOKED_AT }) },
      { receipt: receipt("control.commerce_session.exchange") },
      { receipt: receipt("control.commerce_session.issue", SESSION_B) },
      { organizationId: `openarc:org:${V4_B}` },
    ]) {
      expect(
        CommerceControlSessionIssueResultSchema.safeParse({ ...base, ...patch })
          .success,
      ).toBe(false);
    }
  });

  it("rejects a secret on the replayed issue", () => {
    expect(
      CommerceControlSessionIssueResultSchema.safeParse({
        organizationId: ORG,
        replayed: true,
        metadata: metadata({ exchangedAt: EXCHANGED_AT }),
        receipt: receipt(),
        delivery: { state: "not_replayable" },
      }).success,
    ).toBe(true);
    expect(
      CommerceControlSessionIssueResultSchema.safeParse({
        organizationId: ORG,
        replayed: true,
        metadata: metadata(),
        receipt: receipt(),
        delivery: { state: "not_replayable", handoffToken: HANDOFF },
      }).success,
    ).toBe(false);
  });
});

describe("exchange and revoke results", () => {
  it("accepts a fresh exchange with a session token and exchangedAt", () => {
    expect(
      CommerceControlSessionExchangeResultSchema.safeParse({
        organizationId: ORG,
        replayed: false,
        metadata: metadata({ exchangedAt: EXCHANGED_AT }),
        receipt: receipt("control.commerce_session.exchange"),
        delivery: { state: "available_once", sessionToken: SESSION_TOKEN },
      }).success,
    ).toBe(true);
  });

  it.each([
    ["handoff token in exchange", { state: "available_once", sessionToken: HANDOFF }],
    ["missing session token", { state: "available_once" }],
    [
      "extra handoffExpiresAt",
      {
        state: "available_once",
        sessionToken: SESSION_TOKEN,
        handoffExpiresAt: HANDOFF_MAX,
      },
    ],
  ])("rejects the %s delivery", (_label, delivery) => {
    expect(
      CommerceControlSessionExchangeResultSchema.safeParse({
        organizationId: ORG,
        replayed: false,
        metadata: metadata({ exchangedAt: EXCHANGED_AT }),
        receipt: receipt("control.commerce_session.exchange"),
        delivery,
      }).success,
    ).toBe(false);
  });

  it("rejects fresh exchange without exchangedAt or with revokedAt", () => {
    expect(
      CommerceControlSessionExchangeResultSchema.safeParse({
        organizationId: ORG,
        replayed: false,
        metadata: metadata(),
        receipt: receipt("control.commerce_session.exchange"),
        delivery: { state: "available_once", sessionToken: SESSION_TOKEN },
      }).success,
    ).toBe(false);
    expect(
      CommerceControlSessionExchangeResultSchema.safeParse({
        organizationId: ORG,
        replayed: false,
        metadata: metadata({ exchangedAt: EXCHANGED_AT, revokedAt: REVOKED_AT }),
        receipt: receipt("control.commerce_session.exchange"),
        delivery: { state: "available_once", sessionToken: SESSION_TOKEN },
      }).success,
    ).toBe(false);
  });

  it("accepts a revoke result and rejects a missing revokedAt or secret", () => {
    expect(
      CommerceControlSessionRevokeResultSchema.safeParse({
        organizationId: ORG,
        replayed: false,
        metadata: metadata({ revokedAt: REVOKED_AT }),
        receipt: receipt("control.commerce_session.revoke"),
      }).success,
    ).toBe(true);
    expect(
      CommerceControlSessionRevokeResultSchema.safeParse({
        organizationId: ORG,
        replayed: false,
        metadata: metadata(),
        receipt: receipt("control.commerce_session.revoke"),
      }).success,
    ).toBe(false);
    expect(
      CommerceControlSessionRevokeResultSchema.safeParse({
        organizationId: ORG,
        replayed: false,
        metadata: metadata({ revokedAt: REVOKED_AT }),
        receipt: receipt("control.commerce_session.revoke"),
        delivery: { state: "not_replayable" },
      }).success,
    ).toBe(false);
  });
});

describe("status, mutation status and list", () => {
  it("parses a null item and a bound item", () => {
    expect(
      CommerceControlSessionStatusSchema.safeParse({
        organizationId: ORG,
        item: null,
      }).success,
    ).toBe(true);
    expect(
      CommerceControlSessionStatusSchema.safeParse({
        organizationId: ORG,
        item: statusItem("handoff_pending"),
      }).success,
    ).toBe(true);
  });

  it("binds a present item organizationId to the outer organizationId", () => {
    const crossOrg = statusItem("handoff_pending", {
      organizationId: `openarc:org:${V4_B}`,
    });
    expect(
      CommerceControlSessionStatusSchema.safeParse({
        organizationId: ORG,
        item: crossOrg,
      }).success,
    ).toBe(false);
    // A null item carries no organization to bind and remains valid.
    expect(
      CommerceControlSessionStatusSchema.safeParse({
        organizationId: `openarc:org:${V4_B}`,
        item: null,
      }).success,
    ).toBe(true);
  });

  it("accepts not_found and committed mutation statuses with binding", () => {
    expect(
      CommerceControlSessionMutationStatusSchema.safeParse({
        organizationId: ORG,
        mutationId: SESSION,
        status: "not_found",
      }).success,
    ).toBe(true);
    expect(
      CommerceControlSessionMutationStatusSchema.safeParse({
        organizationId: ORG,
        mutationId: SESSION,
        status: "committed",
        receipt: receipt("control.commerce_session.revoke"),
      }).success,
    ).toBe(true);
    expect(
      CommerceControlSessionMutationStatusSchema.safeParse({
        organizationId: ORG,
        mutationId: SESSION_B,
        status: "committed",
        receipt: receipt("control.commerce_session.revoke"),
      }).success,
    ).toBe(false);
    expect(
      CommerceControlSessionMutationStatusSchema.safeParse({
        organizationId: ORG,
        mutationId: SESSION,
        status: "not_found",
        receipt: receipt("control.commerce_session.revoke"),
      }).success,
    ).toBe(false);
  });

  it("enforces ascending unique session ids and cursor binding", () => {
    const item = (sessionId: string) => ({
      metadata: metadata({ sessionId }),
      status: "handoff_pending",
    });
    expect(
      CommerceControlSessionListSchema.safeParse({
        organizationId: ORG,
        items: [],
        nextCursor: null,
      }).success,
    ).toBe(true);
    expect(
      CommerceControlSessionListSchema.safeParse({
        organizationId: ORG,
        items: [item(SESSION), item(SESSION_B)],
        nextCursor: SESSION_B,
      }).success,
    ).toBe(true);
    expect(
      CommerceControlSessionListSchema.safeParse({
        organizationId: ORG,
        items: [item(SESSION_B), item(SESSION)],
        nextCursor: null,
      }).success,
    ).toBe(false);
    expect(
      CommerceControlSessionListSchema.safeParse({
        organizationId: ORG,
        items: [item(SESSION), item(SESSION)],
        nextCursor: null,
      }).success,
    ).toBe(false);
    expect(
      CommerceControlSessionListSchema.safeParse({
        organizationId: ORG,
        items: [],
        nextCursor: SESSION,
      }).success,
    ).toBe(false);
    expect(
      CommerceControlSessionListSchema.safeParse({
        organizationId: ORG,
        items: [item(SESSION), item(SESSION_B)],
        nextCursor: SESSION,
      }).success,
    ).toBe(false);
    expect(
      CommerceControlSessionListSchema.safeParse({
        organizationId: ORG,
        items: [item(SESSION), item(SESSION_B)],
        nextCursor: null,
      }).success,
    ).toBe(true);
  });

  it("rejects cross-organization items and pages over 50", () => {
    expect(
      CommerceControlSessionListSchema.safeParse({
        organizationId: ORG,
        items: [
          {
            metadata: metadata({ organizationId: `openarc:org:${V4_B}` }),
            status: "handoff_pending",
          },
        ],
        nextCursor: null,
      }).success,
    ).toBe(false);
    const items = Array.from({ length: 51 }, (_, index) => {
      const suffix = index.toString(16).padStart(8, "0");
      return {
        metadata: metadata({
          sessionId: `${suffix}-1234-4234-8123-123456789abc`,
        }),
        status: "handoff_pending" as const,
      };
    });
    expect(
      CommerceControlSessionListSchema.safeParse({
        organizationId: ORG,
        items,
        nextCursor: null,
      }).success,
    ).toBe(false);
  });

  it("exposes a typed status item", () => {
    const parsed = CommerceControlSessionStatusItemSchema.safeParse(
      statusItem("active", { exchangedAt: EXCHANGED_AT }),
    );
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expectTypeOf(parsed.data).toEqualTypeOf<CommerceControlSessionStatusItem>();
    }
  });
});

describe("read requests", () => {
  it("accepts the three request shapes with bounded limit", () => {
    expect(
      CommerceControlSessionRequestSchema.safeParse({
        organizationId: ORG,
        sessionId: SESSION,
      }).success,
    ).toBe(true);
    expect(
      CommerceControlSessionMutationRequestSchema.safeParse({
        organizationId: ORG,
        mutationId: SESSION,
      }).success,
    ).toBe(true);
    expect(
      CommerceControlSessionListRequestSchema.safeParse({
        organizationId: ORG,
        afterSessionId: SESSION,
        limit: "50",
      }).success,
    ).toBe(true);
  });

  it.each(["0", "51", "01", "1.0", "1\n", "1e1", " 1", "+1", ""])(
    "rejects list limit %s",
    (limit) => {
      expect(
        CommerceControlSessionListRequestSchema.safeParse({
          organizationId: ORG,
          limit,
        }).success,
      ).toBe(false);
    },
  );

  it("rejects unknown and explicit-undefined request keys", () => {
    expect(
      CommerceControlSessionRequestSchema.safeParse({
        organizationId: ORG,
        sessionId: SESSION,
        extra: 1,
      }).success,
    ).toBe(false);
    for (const key of ["afterSessionId", "limit"] as const) {
      expect(
        CommerceControlSessionListRequestSchema.safeParse({
          organizationId: ORG,
          [key]: undefined,
        }).success,
      ).toBe(false);
    }
  });
});

describe("success envelopes", () => {
  const freshIssue = {
    organizationId: ORG,
    replayed: false,
    metadata: metadata({ expiresAt: EXPIRES_MAX }),
    receipt: receipt(),
    delivery: {
      state: "available_once",
      handoffToken: HANDOFF,
      handoffExpiresAt: HANDOFF_MAX,
    },
  };
  const freshExchange = {
    organizationId: ORG,
    replayed: false,
    metadata: metadata({ exchangedAt: EXCHANGED_AT }),
    receipt: receipt("control.commerce_session.exchange"),
    delivery: { state: "available_once", sessionToken: SESSION_TOKEN },
  };
  const revoke = {
    organizationId: ORG,
    replayed: false,
    metadata: metadata({ revokedAt: REVOKED_AT }),
    receipt: receipt("control.commerce_session.revoke"),
  };

  it("wraps each data variant with the shared v2 meta", () => {
    const cases: readonly [string, { safeParse(v: unknown): { success: boolean } }, unknown][] = [
      [
        "issue",
        CommerceControlSessionIssueResultResponseSchema,
        freshIssue,
      ],
      [
        "exchange",
        CommerceControlSessionExchangeResultResponseSchema,
        freshExchange,
      ],
      [
        "revoke",
        CommerceControlSessionRevokeResultResponseSchema,
        revoke,
      ],
      [
        "status",
        CommerceControlSessionStatusResponseSchema,
        { organizationId: ORG, item: null },
      ],
      [
        "mutation status",
        CommerceControlSessionMutationStatusResponseSchema,
        { organizationId: ORG, mutationId: SESSION, status: "not_found" },
      ],
      [
        "list",
        CommerceControlSessionListResponseSchema,
        { organizationId: ORG, items: [], nextCursor: null },
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

  it("never admits a secret in a replay/status/page envelope", () => {
    for (const value of [
      {
        organizationId: ORG,
        mutationId: SESSION,
        status: "not_found",
        handoffToken: HANDOFF,
      },
      {
        organizationId: ORG,
        item: { ...statusItem("handoff_pending"), sessionToken: SESSION_TOKEN },
      },
      {
        organizationId: ORG,
        items: [
          { ...statusItem("handoff_pending"), handoffToken: HANDOFF },
        ],
        nextCursor: null,
      },
    ]) {
      expect(
        CommerceControlSessionMutationStatusSchema.safeParse(value).success &&
          CommerceControlSessionStatusSchema.safeParse(value).success &&
          CommerceControlSessionListSchema.safeParse(value).success,
      ).toBe(false);
    }
    expect(
      CommerceControlSessionScopesSchema.safeParse(["commerce.authorize"]).success,
    ).toBe(true);
  });
});
