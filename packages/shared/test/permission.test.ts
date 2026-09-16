import { describe, expect, it } from "vitest";

import {
  ACTION_ROUTE_INDEX,
  ARC_ACCOUNT_SNAPSHOT_PATH,
  ARC_OBSERVATION_DISCLOSURE,
  ARC_TESTNET,
  ArcObservationPermissionReceiptRecordSchema,
  PURCHASE_DECISION_APPROVE_PATH,
  PURCHASE_DECISION_DISCLOSURE,
  PURCHASE_DECISION_REJECT_PATH,
  PURCHASE_DECISION_ROUTE_BY_DECISION,
  PermissionReceiptRecordSchema,
  PurchaseDecisionPermissionReceiptRecordSchema,
} from "../src/index.js";

const address = "0x1111111111111111111111111111111111111111";
const at = "2026-09-03T12:00:00Z";
const base = {
  recordSchema: "openarc.permission-receipt.v2",
  kind: "permission_receipt",
  recordId: "11111111-1111-4111-8111-111111111111",
  recordRevision: "A".repeat(32),
  createdAt: at,
  updatedAt: at,
  connectorId: "arc_account_snapshot",
  destination: { origin: "https://app.example.test", path: ARC_ACCOUNT_SNAPSHOT_PATH,
    method: "POST", upstreams: [ARC_TESTNET.rpcHttp] },
  releasedFields: ["network", "address"],
  released: { network: ARC_TESTNET.caip2, address },
  purpose: "Observe one public Arc Testnet address at one exact final block.",
  credentials: ARC_OBSERVATION_DISCLOSURE.credentials,
  openArcRetention: ARC_OBSERVATION_DISCLOSURE.openArcRetention,
  providerRetention: ARC_OBSERVATION_DISCLOSURE.providerRetention,
  hostingMetadata: ARC_OBSERVATION_DISCLOSURE.hostingMetadata,
  approvedAt: at,
  outcome: "completed",
  resolvedAt: at,
  failureCode: null,
} as const;

describe("M04 permission receipt contract", () => {
  it("pins the exact public disclosure, route, upstream, and resolved lifecycle", () => {
    const parsed = ArcObservationPermissionReceiptRecordSchema.parse(base);
    expect(parsed.released).toEqual({ network: ARC_TESTNET.caip2, address });
    expect(parsed.destination).toEqual({ origin: "https://app.example.test",
      path: ARC_ACCOUNT_SNAPSHOT_PATH, method: "POST", upstreams: [ARC_TESTNET.rpcHttp] });
    expect(PermissionReceiptRecordSchema.safeParse(parsed).success).toBe(true);
  });

  it.each([
    { ...base, destination: { ...base.destination, path: "/v1/private/arc/arbitrary" } },
    { ...base, destination: { ...base.destination, upstreams: ["https://evil.test"] } },
    { ...base, released: { ...base.released, privateKey: "canary" } },
    { ...base, releasedFields: ["network"] },
    { ...base, outcome: "completed", resolvedAt: null },
    { ...base, outcome: "failed", failureCode: null },
    { ...base, extra: "canary" },
  ])("rejects a widened or inconsistent receipt", (candidate) => {
    expect(ArcObservationPermissionReceiptRecordSchema.safeParse(candidate).success).toBe(false);
  });
});

describe("P04-06b purchase-decision permission receipt (v6)", () => {
  const V4 = "12345678-1234-4234-8123-123456789abc";
  const reviewed = {
    listingId: `openarc:listing:${V4}`,
    listingVersion: "1",
    providerId: `openarc:provider:${V4}`,
    amountAtomic: "1500000",
    feeAtomic: "250000",
    debitAtomic: "1750000",
    asset: "USDC",
    decimals: 6,
    networkId: "eip155:5042002",
    policyId: `openarc:policy:${V4}`,
    policyRevision: "1",
    approvalId: `openarc:approval:${V4}`,
    approvalExpiresAt: "2026-01-01T00:15:00.000Z",
  } as const;
  const v6 = {
    recordSchema: "openarc.permission-receipt.v6",
    kind: "permission_receipt",
    recordId: "22222222-2222-4222-8222-222222222222",
    recordRevision: "B".repeat(32),
    createdAt: at,
    updatedAt: at,
    connectorId: "openarc_purchase_decision",
    destination: { origin: "https://app.example.test", path: PURCHASE_DECISION_APPROVE_PATH,
      method: "POST", upstreams: [] },
    releasedFields: ["organizationId", "actionId", "decision", "mutationId"],
    released: { organizationId: `openarc:org:${V4}`, actionId: `openarc:action:${V4}`,
      decision: "approve", mutationId: V4 },
    reviewed,
    purpose: PURCHASE_DECISION_DISCLOSURE.purpose,
    credentials: PURCHASE_DECISION_DISCLOSURE.credentials,
    openArcRetention: PURCHASE_DECISION_DISCLOSURE.openArcRetention,
    providerRetention: PURCHASE_DECISION_DISCLOSURE.providerRetention,
    hostingMetadata: PURCHASE_DECISION_DISCLOSURE.hostingMetadata,
    approvedAt: at,
    outcome: "approved",
    resolvedAt: null,
    failureCode: null,
  } as const;

  it("pins the two browser action-decision routes byte-identically to ACTION_ROUTES", () => {
    // The receipt's destination must name the route the client actually calls.
    expect(PURCHASE_DECISION_APPROVE_PATH).toBe(ACTION_ROUTE_INDEX.action_approve!.path);
    expect(PURCHASE_DECISION_REJECT_PATH).toBe(ACTION_ROUTE_INDEX.action_reject!.path);
    for (const id of ["action_approve", "action_reject"] as const) {
      expect({ method: ACTION_ROUTE_INDEX[id]!.method, audience: ACTION_ROUTE_INDEX[id]!.audience })
        .toEqual({ method: "POST", audience: "browser" });
    }
    expect(PURCHASE_DECISION_ROUTE_BY_DECISION).toEqual({
      approve: PURCHASE_DECISION_APPROVE_PATH, reject: PURCHASE_DECISION_REJECT_PATH });
  });

  it("accepts an approve and a reject receipt and keeps both blocks exactly as written", () => {
    const parsed = PurchaseDecisionPermissionReceiptRecordSchema.parse(v6);
    expect(parsed.released).toEqual({ organizationId: `openarc:org:${V4}`,
      actionId: `openarc:action:${V4}`, decision: "approve", mutationId: V4 });
    expect(parsed.reviewed).toEqual(reviewed);
    expect(parsed.destination.upstreams).toEqual([]);
    expect(PermissionReceiptRecordSchema.safeParse(parsed).success).toBe(true);
    const rejected = { ...v6, destination: { ...v6.destination, path: PURCHASE_DECISION_REJECT_PATH },
      released: { ...v6.released, decision: "reject" } };
    expect(PurchaseDecisionPermissionReceiptRecordSchema.safeParse(rejected).success).toBe(true);
    expect(PermissionReceiptRecordSchema.safeParse(rejected).success).toBe(true);
  });

  it("records the decision exactly once: the route and the decision can never disagree", () => {
    for (const candidate of [
      { ...v6, released: { ...v6.released, decision: "reject" } },
      { ...v6, destination: { ...v6.destination, path: PURCHASE_DECISION_REJECT_PATH } },
    ]) {
      expect(PurchaseDecisionPermissionReceiptRecordSchema.safeParse(candidate).success).toBe(false);
    }
  });

  /**
   * The point of the released block: it is the wire, and nothing else. A CSRF
   * token, idempotency key, cookie or signature travels as a header and has
   * nowhere to live on this record.
   */
  it("cannot represent a secret, token, session hash or signature anywhere", () => {
    const canary = "CANARY_SECRET_VALUE";
    for (const candidate of [
      { ...v6, released: { ...v6.released, csrfToken: canary } },
      { ...v6, released: { ...v6.released, idempotencyKey: canary } },
      { ...v6, reviewed: { ...reviewed, sessionHash: canary } },
      { ...v6, reviewed: { ...reviewed, signature: `0x${"e".repeat(130)}` } },
      { ...v6, idempotencyKey: canary },
      { ...v6, csrfToken: canary },
      { ...v6, cookie: canary },
    ]) {
      expect(PurchaseDecisionPermissionReceiptRecordSchema.safeParse(candidate).success).toBe(false);
      expect(PermissionReceiptRecordSchema.safeParse(candidate).success).toBe(false);
    }
  });

  it("keeps every reviewed figure an exact integer with its asset and decimals", () => {
    for (const candidate of [
      { ...v6, reviewed: { ...reviewed, amountAtomic: "1.5" } },
      { ...v6, reviewed: { ...reviewed, amountAtomic: "1,500,000" } },
      { ...v6, reviewed: { ...reviewed, amountAtomic: "01500000" } },
      { ...v6, reviewed: { ...reviewed, amountAtomic: "1500000\n" } },
      { ...v6, reviewed: { ...reviewed, amountAtomic: "0" } },
      // The budget shown to the human must be amount + fee, never a rounded total.
      { ...v6, reviewed: { ...reviewed, debitAtomic: "1750001" } },
      { ...v6, reviewed: { ...reviewed, asset: "USDT" } },
      { ...v6, reviewed: { ...reviewed, decimals: 18 } },
      { ...v6, reviewed: { ...reviewed, networkId: "eip155:1" } },
      { ...v6, reviewed: { ...reviewed, listingVersion: "0" } },
      { ...v6, reviewed: { ...reviewed, policyRevision: "1.0" } },
    ]) {
      expect(PurchaseDecisionPermissionReceiptRecordSchema.safeParse(candidate).success).toBe(false);
    }
    const exact = PurchaseDecisionPermissionReceiptRecordSchema.parse(v6).reviewed;
    for (const value of [exact.amountAtomic, exact.feeAtomic, exact.debitAtomic]) {
      expect(value).toMatch(/^(?:0|[1-9][0-9]*)$/u);
    }
  });

  it("pairs the approval with its expiry and allows an action that has neither", () => {
    expect(PurchaseDecisionPermissionReceiptRecordSchema.safeParse({ ...v6,
      reviewed: { ...reviewed, approvalId: null, approvalExpiresAt: null } }).success).toBe(true);
    for (const candidate of [
      { ...v6, reviewed: { ...reviewed, approvalId: null } },
      { ...v6, reviewed: { ...reviewed, approvalExpiresAt: null } },
    ]) {
      expect(PurchaseDecisionPermissionReceiptRecordSchema.safeParse(candidate).success).toBe(false);
    }
  });

  it("refuses a widened destination, a widened disclosure and an inconsistent lifecycle", () => {
    for (const candidate of [
      { ...v6, destination: { ...v6.destination, path: "/v2/control/organizations/:organizationId/actions/:actionId/cancel" } },
      { ...v6, destination: { ...v6.destination, method: "GET" } },
      { ...v6, destination: { ...v6.destination, upstreams: ["https://gateway-api-testnet.circle.com"] } },
      { ...v6, connectorId: "circle_gateway_transfer" },
      { ...v6, purpose: `${PURCHASE_DECISION_DISCLOSURE.purpose} ` },
      { ...v6, credentials: "omit" },
      { ...v6, releasedFields: ["organizationId", "actionId", "decision"] },
      { ...v6, releasedFields: ["organizationId", "actionId", "mutationId", "decision"] },
      { ...v6, outcome: "completed", resolvedAt: null },
      { ...v6, outcome: "failed", failureCode: null },
      { ...v6, recordSchema: "openarc.permission-receipt.v5" },
      { ...v6, extra: "canary" },
    ]) {
      expect(PurchaseDecisionPermissionReceiptRecordSchema.safeParse(candidate).success).toBe(false);
    }
  });
});
