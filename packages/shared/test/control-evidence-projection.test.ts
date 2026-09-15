import { createHash } from "node:crypto";

import { describe, expect, expectTypeOf, it } from "vitest";

import {
  CONTROL_EVIDENCE_LIMITATIONS,
  CONTROL_EVIDENCE_PROJECTION_RULE_VERSION,
  CONTROL_PAYMENT_ATTEMPT_STATES,
  CONTROL_RESERVATION_STATUSES,
  CommerceActionStatusSchema,
  CommerceApprovalStatusSchema,
  ControlEvidenceProjectionInputError,
  EVIDENCE_V2_GATEWAY_COMMITTED_LIMITATION,
  EVIDENCE_V2_UNKNOWN_PAYMENT_LIMITATION,
  EvidenceV2FactSchema,
  controlEvidenceSha256Hex,
  derivePaymentCertainty,
  evidenceV2FactStatus,
  projectControlEvidence,
  resolveEvidenceConflict,
  type CommerceActionMetadata,
  type CommerceApprovalMetadata,
  type CommerceGrantMetadata,
  type ControlActionFacts,
  type ControlApprovalFacts,
  type ControlEvidenceProjection,
  type ControlEvidenceProjectionInput,
  type ControlGrantFacts,
  type ControlPaymentAttemptFacts,
  type ControlPaymentAttemptState,
  type ControlReservationFacts,
  type ControlReservationStatus,
  type EvidenceV2ExposureBucket,
  type EvidenceV2FactKind,
  type EvidenceV2FactOf,
} from "../src/index.js";
import type { CommerceStateDimensions } from "../src/commerce/states.js";

// ───────────────────────── fixtures ─────────────────────────

const ORG = "openarc:org:11111111-1111-4111-8111-111111111111";
const OTHER_ORG = "openarc:org:12121212-1212-4212-8212-121212121212";
const PROVIDER = "openarc:provider:22222222-2222-4222-8222-222222222222";
const OTHER_PROVIDER = "openarc:provider:33333333-3333-4333-8333-333333333333";
const APPROVER = "openarc:account:45454545-4545-4545-8545-454545454545";
const OPERATOR = "openarc:account:46464646-4646-4646-8646-464646464646";
const AGENT = "openarc:agent:55555555-5555-4555-8555-555555555555";
const ACTION = "openarc:action:66666666-6666-4666-8666-666666666666";
const OTHER_ACTION = "openarc:action:67676767-6767-4767-8767-676767676767";
const APPROVAL = "openarc:approval:77777777-7777-4777-8777-777777777777";
const RESERVATION = "openarc:reservation:88888888-8888-4888-8888-888888888888";
const GRANT = "openarc:grant:99999999-9999-4999-8999-999999999999";
const OTHER_GRANT = "openarc:grant:9a9a9a9a-9a9a-4a9a-8a9a-9a9a9a9a9a9a";
const ATTEMPT_A = "a1a1a1a1-a1a1-4a1a-8a1a-a1a1a1a1a1a1";
const ATTEMPT_B = "b2b2b2b2-b2b2-4b2b-8b2b-b2b2b2b2b2b2";
const ATTEMPT_C = "c3c3c3c3-c3c3-4c3c-8c3c-c3c3c3c3c3c3";
const TRANSFER = "3f1c1b7e-8a1d-4f5e-9b2a-1c2d3e4f5a6b";
const TRANSFER_BY_ATTEMPT: Readonly<Record<string, string>> = {
  [ATTEMPT_A]: TRANSFER,
  [ATTEMPT_B]: "4a2d2c8f-9b2e-4a6f-8c3b-2d3e4f5a6b7c",
  [ATTEMPT_C]: "5b3e3d9a-ac3f-4b7a-9d4c-3e4f5a6b7c8d",
};
const BATCH = `0x${"ab".repeat(32)}`;
const PAYER = `0x${"A1a1".repeat(10)}`;
const PAY_TO = `0x${"B2b2".repeat(10)}`;
const NONCE = `0x${"5e".repeat(32)}`;
const BINDING = `sha256:${"cd".repeat(32)}`;
const DEBIT = "1000500";
const VALUE = "1000000";

const CREATED = "2026-09-15T10:00:00.000000Z";
const DECIDED = "2026-09-15T10:00:30.000000Z";
const REPLACED = "2026-09-15T10:00:40.000000Z";
const CLAIMED = "2026-09-15T10:01:00.000000Z";
const PERSISTED = "2026-09-15T10:01:05.000000Z";
const DISPATCHED = "2026-09-15T10:01:10.000000Z";
const OBSERVED = "2026-09-15T10:01:20.000000Z";
const RESOLVED = "2026-09-15T10:02:00.000000Z";
const EVAL = "2026-09-15T10:03:00.000000Z";
const LATER_EVAL = "2026-09-15T10:04:00.000000Z";
const JUST_BEFORE = "2026-09-15T10:04:59.999999Z";
const EXPIRES = "2026-09-15T10:05:00.000000Z";
const AFTER = "2026-09-15T10:06:00.000000Z";

const GATEWAY = {
  class: "gateway", sourceId: "circle_gateway_testnet", origin: "https://gateway-api-testnet.circle.com",
  adapterVersion: "openarc.gateway-transfer.v2",
} as const;
const ZERO = { held: "0", claimed: "0", unknown: "0", committed: "0" } as const;
const L = CONTROL_EVIDENCE_LIMITATIONS;

function actionFacts(overrides: Partial<ControlActionFacts> = {}): ControlActionFacts {
  return {
    actionId: ACTION, exposureKey: { organizationId: ORG, subjectAgentId: AGENT }, providerId: PROVIDER,
    status: "reserved_not_granted", reservationId: RESERVATION, approvalId: null,
    createdAt: CREATED, updatedAt: CREATED, expiresAt: EXPIRES, ...overrides,
  };
}
const pendingAction = actionFacts({ status: "pending_approval", approvalId: APPROVAL, reservationId: null });

function approvalFacts(status: ControlApprovalFacts["status"], overrides: Partial<ControlApprovalFacts> = {}): ControlApprovalFacts {
  const decided = status === "approved" || status === "rejected";
  return {
    approvalId: APPROVAL, actionId: ACTION, organizationId: ORG, subjectAgentId: AGENT, status,
    decidedBy: decided ? APPROVER : null, createdAt: CREATED, expiresAt: EXPIRES, decidedAt: decided ? DECIDED : null, ...overrides,
  };
}

function reservationFacts(status: ControlReservationStatus, overrides: Partial<ControlReservationFacts> = {}): ControlReservationFacts {
  return {
    organizationId: ORG, reservationId: RESERVATION, actionId: ACTION, debitAtomic: DEBIT, status, createdAt: CREATED,
    claimedAt: status === "claimed" || status === "unknown" || status === "committed" ? CLAIMED : null,
    resolvedAt: status === "committed" || status === "released" ? RESOLVED : null, ...overrides,
  };
}

function grantFacts(status: ControlGrantFacts["status"], overrides: Partial<ControlGrantFacts> = {}): ControlGrantFacts {
  return {
    grantId: GRANT, organizationId: ORG, subjectAgentId: AGENT, actionId: ACTION, reservationId: RESERVATION, providerId: PROVIDER,
    generation: "1", status, issuedAt: CREATED,
    updatedAt: status === "claimed" ? CLAIMED : status === "revoked" ? RESOLVED : CREATED,
    expiresAt: EXPIRES, claimedAt: status === "claimed" ? CLAIMED : null, revokedAt: status === "revoked" ? RESOLVED : null, ...overrides,
  };
}

/** A schema15-like record, including fields the projection must never copy into evidence. */
function attemptRecord(state: ControlPaymentAttemptState, attemptId = ATTEMPT_A): ControlPaymentAttemptFacts {
  const observed = state === "pending" || state === "committed";
  const record = {
    organizationId: ORG, attemptId, grantId: GRANT, actionId: ACTION, providerId: PROVIDER,
    nonce: NONCE, bindingDigest: BINDING, laneRequirementDigest: BINDING,
    valueAtomic: VALUE, payerAddress: PAYER, payToAddress: PAY_TO, state, persistedAt: PERSISTED,
    dispatchedAt: state === "persisted" ? null : DISPATCHED, observedAt: observed ? OBSERVED : null,
    transferId: observed ? (TRANSFER_BY_ATTEMPT[attemptId] ?? TRANSFER) : null,
    gatewayStatus: state === "pending" ? ("batched" as const) : state === "committed" ? ("completed" as const) : null,
    batchTxHash: state === "committed" ? BATCH : null,
  };
  return record;
}

function projectionInput(overrides: Partial<ControlEvidenceProjectionInput> = {}): ControlEvidenceProjectionInput {
  return {
    evaluatedAt: EVAL, action: actionFacts(), approval: null, reservation: reservationFacts("held"), grant: null,
    paymentAttempts: [], paymentSource: GATEWAY, attribution: { cancelledBy: null, revokedBy: null }, ...overrides,
  };
}

function grantedInput(
  reservation: ControlReservationStatus,
  attempts: ControlPaymentAttemptFacts[],
  overrides: Partial<ControlEvidenceProjectionInput> = {},
): ControlEvidenceProjectionInput {
  return projectionInput({
    action: actionFacts({ status: "grant_issued" }), reservation: reservationFacts(reservation), grant: grantFacts("claimed"),
    paymentAttempts: attempts, ...overrides,
  });
}

type Row = string;
const rows = (projection: ControlEvidenceProjection, kind: EvidenceV2FactKind): Row[] =>
  projection.facts.filter((fact) => fact.kind === kind)
    .map((fact) => `${evidenceV2FactStatus(fact)}/${fact.source.class}/${fact.actor.kind}`);

function factOf<K extends EvidenceV2FactKind>(projection: ControlEvidenceProjection, kind: K, status: string): EvidenceV2FactOf<K> {
  const matches = projection.facts.filter((fact) => fact.kind === kind && evidenceV2FactStatus(fact) === status);
  expect(matches, `${kind}/${status}`).toHaveLength(1);
  return matches[0] as EvidenceV2FactOf<K>;
}

function wellFormed(projection: ControlEvidenceProjection): void {
  expect(projection.ruleVersion).toBe(CONTROL_EVIDENCE_PROJECTION_RULE_VERSION);
  for (const fact of projection.facts) {
    expect(EvidenceV2FactSchema.parse(fact)).toEqual(fact);
    expect(fact.evidenceId).toMatch(/^evd_[0-9a-f]{32}$/u);
  }
  const ids = projection.facts.map((fact) => fact.evidenceId);
  expect(new Set(ids).size).toBe(ids.length);
  expect(projection.evidenceIds).toEqual([...ids].sort());
  const json = JSON.stringify(projection);
  for (const hidden of [NONCE, BINDING, PAYER, PAY_TO]) expect(json).not.toContain(hidden);
  for (const forbidden of ['"paid"', '"settled"', '"refunded"', '"failed"', '"released"']) expect(json).not.toContain(forbidden);
}

function inputError(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    if (error instanceof ControlEvidenceProjectionInputError) return error.detail;
    throw error;
  }
  throw new Error("Expected a ControlEvidenceProjectionInputError");
}

function permutations<T>(items: readonly T[]): T[][] {
  if (items.length <= 1) return [[...items]];
  return items.flatMap((item, index) => permutations([...items.slice(0, index), ...items.slice(index + 1)]).map((rest) => [item, ...rest]));
}

// ───────────────────────── inputs ─────────────────────────

describe("control evidence projection inputs", () => {
  it("accepts the shared store DTOs structurally and projects into CommerceStateDimensions", () => {
    expectTypeOf<[CommerceActionMetadata] extends [ControlActionFacts] ? true : false>().toEqualTypeOf<true>();
    expectTypeOf<[CommerceApprovalMetadata] extends [ControlApprovalFacts] ? true : false>().toEqualTypeOf<true>();
    expectTypeOf<[CommerceGrantMetadata] extends [ControlGrantFacts] ? true : false>().toEqualTypeOf<true>();
    expectTypeOf<ControlEvidenceProjection["dimensions"]>().toEqualTypeOf<CommerceStateDimensions>();
    expect(CONTROL_EVIDENCE_PROJECTION_RULE_VERSION).toBe("openarc.control-evidence-projection.v1");
    wellFormed(projectControlEvidence(grantedInput("claimed", [attemptRecord("committed")])));
  });

  it("accepts canonical server IDs only for attribution", () => {
    const approvedAction = actionFacts({ approvalId: APPROVAL, updatedAt: DECIDED });
    const sessionHash = "ee".repeat(32);
    expect(inputError(() => projectControlEvidence(projectionInput({ action: approvedAction,
      approval: approvalFacts("approved", { decidedBy: `sha256:${sessionHash}` }) })))).toBe("invalid_input");
    expect(inputError(() => projectControlEvidence(projectionInput({ action: actionFacts({ status: "cancelled", updatedAt: RESOLVED }),
      reservation: reservationFacts("released"), attribution: { cancelledBy: sessionHash, revokedBy: null } })))).toBe("invalid_input");
    expect(inputError(() => projectControlEvidence(grantedInput("claimed", [], {
      attribution: { cancelledBy: null, revokedBy: `oag_v1_${"A".repeat(43)}` } })))).toBe("invalid_input");
    expect(inputError(() => projectControlEvidence(projectionInput({ action: approvedAction,
      approval: approvalFacts("approved", { decidedBy: APPROVER.toUpperCase() }) })))).toBe("invalid_input");
    expect(inputError(() => projectControlEvidence(projectionInput({
      action: actionFacts({ providerId: "3f1c1b7e-8a1d-4f5e-9b2a-1c2d3e4f5a6b" }) })))).toBe("invalid_input");
  });

  it("rejects rows that violate the store shapes", () => {
    const cases: ControlEvidenceProjectionInput[] = [
      projectionInput({ action: actionFacts({ status: "pending_approval", approvalId: APPROVAL }) }),
      projectionInput({ action: actionFacts({ expiresAt: CREATED }) }),
      projectionInput({ action: actionFacts({ approvalId: APPROVAL, updatedAt: DECIDED }), approval: approvalFacts("approved", { decidedBy: null }) }),
      projectionInput({ reservation: reservationFacts("held", { claimedAt: CLAIMED }) }),
      projectionInput({ reservation: reservationFacts("committed", { resolvedAt: null }) }),
      projectionInput({ reservation: { ...reservationFacts("held"), status: "settled" } as unknown as ControlReservationFacts }),
      projectionInput({ reservation: reservationFacts("held", { debitAtomic: "0" }) }),
      grantedInput("claimed", [], { grant: grantFacts("claimed", { claimedAt: null }) }),
      grantedInput("claimed", [], { grant: grantFacts("claimed", { generation: "0" }) }),
      grantedInput("claimed", [{ ...attemptRecord("unknown"), observedAt: OBSERVED }]),
      grantedInput("claimed", [{ ...attemptRecord("committed"), batchTxHash: null }]),
      grantedInput("claimed", [{ ...attemptRecord("committed"), batchTxHash: BATCH.toUpperCase().replace("0X", "0x") }]),
      grantedInput("claimed", [{ ...attemptRecord("pending"), gatewayStatus: "completed" }]),
      grantedInput("claimed", [attemptRecord("unknown"), attemptRecord("persisted")]),
      projectionInput({ evaluatedAt: "2026-09-15 10:03:00" }),
    ];
    for (const [index, candidate] of cases.entries()) {
      expect(inputError(() => projectControlEvidence(candidate)), `case ${index}`).toBe("invalid_input");
    }
  });

  it("rejects foreign or mismatched records", () => {
    const cases: [ControlEvidenceProjectionInput, string][] = [
      [projectionInput({ action: pendingAction, reservation: null, approval: approvalFacts("pending", { actionId: OTHER_ACTION }) }), "identity_mismatch"],
      [projectionInput({ approval: approvalFacts("pending") }), "identity_mismatch"],
      [projectionInput({ reservation: reservationFacts("held", { organizationId: OTHER_ORG }) }), "identity_mismatch"],
      [projectionInput({ action: actionFacts({ reservationId: null, status: "cancelled", approvalId: APPROVAL }), reservation: reservationFacts("released"),
        approval: approvalFacts("pending") }), "identity_mismatch"],
      [grantedInput("claimed", [], { grant: grantFacts("claimed", { providerId: OTHER_PROVIDER }) }), "identity_mismatch"],
      [grantedInput("claimed", [{ ...attemptRecord("unknown"), grantId: OTHER_GRANT }]), "identity_mismatch"],
      [grantedInput("claimed", [{ ...attemptRecord("unknown"), providerId: OTHER_PROVIDER }]), "identity_mismatch"],
      [grantedInput("claimed", [attemptRecord("unknown")], { grant: null }), "payment_attempt_without_grant"],
    ];
    for (const [candidate, detail] of cases) expect(inputError(() => projectControlEvidence(candidate))).toBe(detail);
  });

  it("refuses any record newer than the evaluation instant", () => {
    expect(inputError(() => projectControlEvidence(projectionInput({ evaluatedAt: "2026-09-15T09:59:59.000000Z" })))).toBe("record_after_evaluation");
    expect(inputError(() => projectControlEvidence(projectionInput({ evaluatedAt: "2026-09-15T10:00:10.000000Z",
      action: actionFacts({ approvalId: APPROVAL }), approval: approvalFacts("approved") })))).toBe("record_after_evaluation");
    expect(inputError(() => projectControlEvidence(grantedInput("claimed", [attemptRecord("pending")],
      { evaluatedAt: "2026-09-15T10:01:15.000000Z" })))).toBe("record_after_evaluation");
    expect(inputError(() => projectControlEvidence(grantedInput("claimed", [], { grant: grantFacts("expired") })))).toBe("record_after_evaluation");
  });
});

// ───────────────────────── action and approval ─────────────────────────

describe("action and approval → authorization_decision", () => {
  const cases: {
    name: string;
    input: ControlEvidenceProjectionInput;
    decisions: Row[];
    authorization: CommerceStateDimensions["authorization"];
    inconsistencies?: string[];
  }[] = [
    { name: "pending_approval with a pending approval", authorization: "pending",
      input: projectionInput({ action: pendingAction, approval: approvalFacts("pending"), reservation: null }),
      decisions: ["approval_requested/local/agent"] },
    { name: "pending_approval one microsecond before expiry", authorization: "pending",
      input: projectionInput({ evaluatedAt: JUST_BEFORE, action: pendingAction, approval: approvalFacts("pending"), reservation: null }),
      decisions: ["approval_requested/local/agent"] },
    { name: "pending_approval exactly at expiry", authorization: "expired",
      input: projectionInput({ evaluatedAt: EXPIRES, action: pendingAction, approval: approvalFacts("pending"), reservation: null }),
      decisions: ["approval_requested/local/agent", "expired/openarc_derived/system"] },
    { name: "reserved_not_granted authorized directly", authorization: "authorized",
      input: projectionInput(), decisions: ["authorized/local/agent"] },
    { name: "reserved_not_granted exactly at expiry", authorization: "expired",
      input: projectionInput({ evaluatedAt: EXPIRES }), decisions: ["authorized/local/agent", "expired/openarc_derived/system"] },
    { name: "reserved_not_granted after an approval", authorization: "authorized",
      input: projectionInput({ action: actionFacts({ approvalId: APPROVAL, updatedAt: DECIDED }), approval: approvalFacts("approved") }),
      decisions: ["approval_requested/local/agent", "approved/local/human_account", "authorized/local/human_account"] },
    { name: "grant_issued with an issued grant", authorization: "authorized",
      input: projectionInput({ action: actionFacts({ status: "grant_issued" }), grant: grantFacts("issued") }),
      decisions: ["authorized/local/agent"] },
    { name: "grant_issued is not expired by the action expiry once claimed", authorization: "authorized",
      input: grantedInput("claimed", [], { evaluatedAt: AFTER }), decisions: ["authorized/local/agent"] },
    { name: "rejected by an approver", authorization: "denied",
      input: projectionInput({ action: actionFacts({ status: "rejected", approvalId: APPROVAL, reservationId: null, updatedAt: DECIDED }),
        approval: approvalFacts("rejected"), reservation: null }),
      decisions: ["approval_requested/local/agent", "rejected/local/human_account"] },
    { name: "rejected without its approval record", authorization: "denied", inconsistencies: ["approval_record_missing"],
      input: projectionInput({ action: actionFacts({ status: "rejected", approvalId: APPROVAL, reservationId: null, updatedAt: DECIDED }),
        reservation: null }),
      decisions: ["approval_requested/local/agent", "rejected/local/system"] },
    { name: "cancelled while pending by a named operator", authorization: "revoked",
      input: projectionInput({ action: actionFacts({ status: "cancelled", approvalId: APPROVAL, reservationId: null, updatedAt: DECIDED }),
        approval: approvalFacts("pending"), reservation: null, attribution: { cancelledBy: OPERATOR, revokedBy: null } }),
      decisions: ["approval_requested/local/agent", "cancelled/local/human_account"] },
    { name: "cancelled after a released reservation, actor not recorded", authorization: "revoked",
      input: projectionInput({ action: actionFacts({ status: "cancelled", updatedAt: RESOLVED }), reservation: reservationFacts("released") }),
      decisions: ["authorized/local/agent", "cancelled/local/system"] },
    { name: "expired in the store", authorization: "expired",
      input: projectionInput({ evaluatedAt: AFTER, action: actionFacts({ status: "expired", approvalId: APPROVAL, reservationId: null, updatedAt: EXPIRES }),
        approval: approvalFacts("expired"), reservation: null }),
      decisions: ["approval_requested/local/agent", "expired/local/system"] },
    { name: "approval expired in the store while the action row is older", authorization: "expired",
      input: projectionInput({ evaluatedAt: AFTER, action: pendingAction, approval: approvalFacts("expired"), reservation: null }),
      decisions: ["approval_requested/local/agent", "expired/local/system"] },
    { name: "approval approved while the action snapshot is older", authorization: "pending", inconsistencies: ["approval_status_disagrees"],
      input: projectionInput({ action: pendingAction, approval: approvalFacts("approved"), reservation: null }),
      decisions: ["approval_requested/local/agent", "approved/local/human_account"] },
  ];

  it("covers every action status and every approval status", () => {
    expect(new Set(cases.map((entry) => entry.input.action.status))).toEqual(new Set(CommerceActionStatusSchema.options));
    expect(new Set(cases.flatMap((entry) => (entry.input.approval === null ? [] : [entry.input.approval.status]))))
      .toEqual(new Set(CommerceApprovalStatusSchema.options));
  });

  for (const entry of cases) {
    it(entry.name, () => {
      const projection = projectControlEvidence(entry.input);
      wellFormed(projection);
      expect(rows(projection, "authorization_decision")).toEqual(entry.decisions);
      expect(projection.dimensions.authorization).toBe(entry.authorization);
      expect(projection.inconsistencies).toEqual(entry.inconsistencies ?? []);
      expect(projection.dimensions.reconciliation).toBe(entry.inconsistencies === undefined ? "unreconciled" : "conflicting");
      expect(projection.dimensions).toMatchObject({ payment: "not_requested", delivery: "not_requested", evaluation: "not_requested",
        settlement: "not_requested" });
    });
  }

  it("attributes approval decisions to the deciding account and states missing actors", () => {
    const approved = projectControlEvidence(projectionInput({ action: actionFacts({ approvalId: APPROVAL, updatedAt: DECIDED }),
      approval: approvalFacts("approved") }));
    expect(factOf(approved, "authorization_decision", "approved")).toMatchObject({
      actor: { kind: "human_account", accountId: APPROVER }, occurredAt: DECIDED, observedAt: EVAL, limitations: [L.controlPlane],
      source: { class: "local", sourceId: "openarc.control-plane", origin: "openarc:control-plane", adapterVersion: CONTROL_EVIDENCE_PROJECTION_RULE_VERSION },
      scope: { organizationId: ORG, providerId: PROVIDER, actionId: ACTION }, dataClass: "organization_protected", digest: null });
    expect(factOf(approved, "authorization_decision", "authorized").actor).toEqual({ kind: "human_account", accountId: APPROVER });
    expect(factOf(approved, "authorization_decision", "approval_requested")).toMatchObject({ actor: { kind: "agent", agentId: AGENT }, occurredAt: CREATED });

    const unattributed = projectControlEvidence(projectionInput({ action: actionFacts({ status: "cancelled", updatedAt: RESOLVED }),
      reservation: reservationFacts("released") }));
    expect(factOf(unattributed, "authorization_decision", "cancelled")).toMatchObject({ actor: { kind: "system", component: "api" },
      occurredAt: RESOLVED, limitations: [L.controlPlane, L.actorNotRecorded] });

    const approvalMissing = projectControlEvidence(projectionInput({ action: actionFacts({ approvalId: APPROVAL, updatedAt: DECIDED }) }));
    expect(factOf(approvalMissing, "authorization_decision", "authorized")).toMatchObject({ actor: { kind: "system", component: "api" },
      occurredAt: null, limitations: [L.controlPlane, L.actorNotRecorded, L.instantNotRecorded] });
    expect(approvalMissing.inconsistencies).toEqual(["approval_record_missing"]);

    const storedApprovalExpiry = projectControlEvidence(projectionInput({ evaluatedAt: AFTER, action: pendingAction,
      approval: approvalFacts("expired"), reservation: null }));
    expect(factOf(storedApprovalExpiry, "authorization_decision", "expired")).toMatchObject({ occurredAt: null,
      limitations: [L.controlPlane, L.instantNotRecorded] });
  });

  it("derives expiry only against evaluatedAt, at the earliest expired authority", () => {
    const derived = projectControlEvidence(projectionInput({ evaluatedAt: "2026-09-15T10:04:30.000000Z", action: pendingAction,
      approval: approvalFacts("pending", { expiresAt: "2026-09-15T10:04:00.000000Z" }), reservation: null }));
    expect(factOf(derived, "authorization_decision", "expired")).toMatchObject({
      occurredAt: "2026-09-15T10:04:00.000000Z", observedAt: "2026-09-15T10:04:30.000000Z",
      actor: { kind: "system", component: "reconciler" }, limitations: [L.derivedExpiry],
      source: { class: "openarc_derived", sourceId: "openarc.control-projection", origin: "openarc:reconciler" } });
    for (const evaluatedAt of [EVAL, JUST_BEFORE]) {
      expect(rows(projectControlEvidence(projectionInput({ evaluatedAt })), "authorization_decision")).toEqual(["authorized/local/agent"]);
    }
    for (const evaluatedAt of [EXPIRES, AFTER]) {
      const expired = projectControlEvidence(projectionInput({ evaluatedAt }));
      expect(factOf(expired, "authorization_decision", "expired").occurredAt).toBe(EXPIRES);
    }
    // Terminal statuses never gain a derived expiry.
    const rejected = projectControlEvidence(projectionInput({ evaluatedAt: AFTER,
      action: actionFacts({ status: "rejected", approvalId: APPROVAL, reservationId: null, updatedAt: DECIDED }),
      approval: approvalFacts("rejected"), reservation: null }));
    expect(rows(rejected, "authorization_decision")).not.toContain("expired/openarc_derived/system");
  });
});

// ───────────────────────── reservation ─────────────────────────

describe("reservation → budget_exposure", () => {
  const expected: Record<ControlReservationStatus, { bucket: EvidenceV2ExposureBucket | null; occurredAt: string; limitations: string[] }> = {
    held: { bucket: "held", occurredAt: CREATED, limitations: [L.controlPlane] },
    claimed: { bucket: "claimed", occurredAt: CLAIMED, limitations: [L.controlPlane] },
    unknown: { bucket: "unknown", occurredAt: CLAIMED, limitations: [L.controlPlane, EVIDENCE_V2_UNKNOWN_PAYMENT_LIMITATION] },
    committed: { bucket: "committed", occurredAt: RESOLVED, limitations: [L.controlPlane] },
    released: { bucket: null, occurredAt: RESOLVED, limitations: [L.controlPlane, L.reservationReleased] },
  };

  for (const status of CONTROL_RESERVATION_STATUSES) {
    it(`projects a ${status} reservation into its own bucket`, () => {
      const input = status === "held" ? projectionInput()
        : status === "released" ? projectionInput({ action: actionFacts({ status: "cancelled", updatedAt: RESOLVED }), reservation: reservationFacts(status) })
          : grantedInput(status, []);
      const projection = projectControlEvidence(input);
      wellFormed(projection);
      const { bucket, occurredAt, limitations } = expected[status];
      const exposure = bucket === null ? { ...ZERO } : { ...ZERO, [bucket]: DEBIT };
      const fact = factOf(projection, "budget_exposure", "exposure_summary");
      expect(fact).toMatchObject({ subject: { kind: "budget_reservation", canonicalId: RESERVATION }, occurredAt, limitations,
        actor: { kind: "system", component: "api" }, normalized: { exposure } });
      expect(projection.exposure).toEqual(exposure);
      expect(projection.dimensions).toMatchObject({ payment: "not_requested", settlement: "not_requested" });
    });
  }

  it("reports a missing reservation record without inventing exposure", () => {
    const projection = projectControlEvidence(projectionInput({ reservation: null }));
    expect(projection.exposure).toEqual(ZERO);
    expect(projection.inconsistencies).toEqual(["reservation_record_missing"]);
    expect(projection.facts.filter((fact) => fact.kind === "budget_exposure")).toHaveLength(0);
  });
});

// ───────────────────────── grant ─────────────────────────

describe("grant → grant_state", () => {
  const cases: {
    name: string;
    input: ControlEvidenceProjectionInput;
    grantRows: Row[];
    authorization: CommerceStateDimensions["authorization"];
    inconsistencies?: string[];
  }[] = [
    { name: "issued, first generation", authorization: "authorized",
      input: projectionInput({ action: actionFacts({ status: "grant_issued" }), grant: grantFacts("issued") }),
      grantRows: ["issued/local/agent"] },
    { name: "issued, replaced generation", authorization: "authorized",
      input: projectionInput({ action: actionFacts({ status: "grant_issued" }), grant: grantFacts("issued", { generation: "2", updatedAt: REPLACED }) }),
      grantRows: ["issued/local/agent", "replaced/local/agent"] },
    { name: "claimed", authorization: "authorized", input: grantedInput("claimed", []),
      grantRows: ["claimed/local/provider", "issued/local/agent"] },
    { name: "claimed after two replacements", authorization: "authorized",
      input: grantedInput("claimed", [], { grant: grantFacts("claimed", { generation: "3" }) }),
      grantRows: ["claimed/local/provider", "issued/local/agent", "replaced/local/agent"] },
    { name: "revoked before any claim by a named operator", authorization: "revoked",
      input: projectionInput({ action: actionFacts({ status: "cancelled", updatedAt: RESOLVED }), reservation: reservationFacts("released"),
        grant: grantFacts("revoked"), attribution: { cancelledBy: OPERATOR, revokedBy: OPERATOR } }),
      grantRows: ["issued/local/agent", "revoked/local/human_account"] },
    { name: "revoked after a claim keeps the claim", authorization: "revoked",
      input: grantedInput("claimed", [], { grant: grantFacts("revoked", { claimedAt: CLAIMED }) }),
      grantRows: ["claimed/local/provider", "issued/local/agent", "revoked/local/system"] },
    { name: "expired in the store", authorization: "expired",
      input: projectionInput({ evaluatedAt: AFTER, action: actionFacts({ status: "grant_issued" }), grant: grantFacts("expired") }),
      grantRows: ["expired/local/system", "issued/local/agent"] },
    { name: "issued, exactly at expiry", authorization: "expired",
      input: projectionInput({ evaluatedAt: EXPIRES, action: actionFacts({ status: "grant_issued" }), grant: grantFacts("issued") }),
      grantRows: ["expired/openarc_derived/system", "issued/local/agent"] },
    { name: "issued, one microsecond before expiry", authorization: "authorized",
      input: projectionInput({ evaluatedAt: JUST_BEFORE, action: actionFacts({ status: "grant_issued" }), grant: grantFacts("issued") }),
      grantRows: ["issued/local/agent"] },
    { name: "claimed, evaluated after expiry", authorization: "authorized", input: grantedInput("claimed", [], { evaluatedAt: AFTER }),
      grantRows: ["claimed/local/provider", "issued/local/agent"] },
    { name: "grant with an action that never reached grant_issued", authorization: "authorized", inconsistencies: ["grant_status_disagrees"],
      input: projectionInput({ grant: grantFacts("issued") }), grantRows: ["issued/local/agent"] },
    { name: "claimed grant with a cancelled action", authorization: "revoked", inconsistencies: ["grant_status_disagrees"],
      input: projectionInput({ action: actionFacts({ status: "cancelled", updatedAt: RESOLVED }), reservation: reservationFacts("claimed"),
        grant: grantFacts("claimed") }),
      grantRows: ["claimed/local/provider", "issued/local/agent"] },
    { name: "grant_issued without its grant record", authorization: "authorized", inconsistencies: ["grant_record_missing"],
      input: projectionInput({ action: actionFacts({ status: "grant_issued" }) }), grantRows: [] },
  ];

  it("covers every grant status", () => {
    expect(new Set(cases.flatMap((entry) => (entry.input.grant === null ? [] : [entry.input.grant.status]))))
      .toEqual(new Set(["issued", "claimed", "revoked", "expired"]));
  });

  for (const entry of cases) {
    it(entry.name, () => {
      const projection = projectControlEvidence(entry.input);
      wellFormed(projection);
      expect(rows(projection, "grant_state").sort()).toEqual(entry.grantRows);
      expect(projection.dimensions.authorization).toBe(entry.authorization);
      expect(projection.inconsistencies).toEqual(entry.inconsistencies ?? []);
    });
  }

  it("attributes claims to the provider, keeps a claim after revoke and holds its exposure", () => {
    const revoked = projectControlEvidence(grantedInput("claimed", [], { grant: grantFacts("revoked", { claimedAt: CLAIMED }) }));
    expect(factOf(revoked, "grant_state", "claimed")).toMatchObject({ actor: { kind: "provider", providerId: PROVIDER }, occurredAt: CLAIMED,
      subject: { kind: "authorization_grant", canonicalId: GRANT }, scope: { organizationId: ORG, providerId: PROVIDER, actionId: ACTION } });
    expect(factOf(revoked, "grant_state", "revoked")).toMatchObject({ occurredAt: RESOLVED, limitations: [L.controlPlane, L.actorNotRecorded] });
    expect(revoked.exposure).toEqual({ ...ZERO, claimed: DEBIT });

    const replaced = projectControlEvidence(grantedInput("claimed", [], { grant: grantFacts("claimed", { generation: "3" }) }));
    expect(factOf(replaced, "grant_state", "replaced")).toMatchObject({ occurredAt: null, limitations: [L.controlPlane, L.instantNotRecorded] });
    const replacedLive = projectControlEvidence(projectionInput({ action: actionFacts({ status: "grant_issued" }),
      grant: grantFacts("issued", { generation: "2", updatedAt: REPLACED }) }));
    expect(factOf(replacedLive, "grant_state", "replaced").occurredAt).toBe(REPLACED);

    const derived = projectControlEvidence(projectionInput({ evaluatedAt: EXPIRES, action: actionFacts({ status: "grant_issued" }),
      grant: grantFacts("issued") }));
    expect(factOf(derived, "grant_state", "expired")).toMatchObject({ occurredAt: EXPIRES, limitations: [L.derivedExpiry],
      source: { class: "openarc_derived" }, actor: { kind: "system", component: "reconciler" } });
  });
});

// ───────────────────────── payment attempts ─────────────────────────

const ATTEMPT_IDS = [ATTEMPT_A, ATTEMPT_B, ATTEMPT_C] as const;
const DISPATCH_BUCKET: Record<ControlPaymentAttemptState, EvidenceV2ExposureBucket> = {
  persisted: "held", unknown: "unknown", pending: "held", committed: "committed",
};
const PRECEDENCE: Record<EvidenceV2ExposureBucket, number> = { held: 0, claimed: 1, committed: 2, unknown: 3 };

describe("payment attempts → payment_observation", () => {
  it("keeps payment not_requested without an attempt, whatever the reservation says", () => {
    for (const status of ["held", "claimed", "unknown", "committed"] as const) {
      const projection = projectControlEvidence(grantedInput(status, []));
      expect(projection.dimensions).toMatchObject({ payment: "not_requested", settlement: "not_requested" });
      expect(projection.paymentAttempts).toEqual([]);
      expect(projection.facts.filter((fact) => fact.kind === "payment_observation")).toHaveLength(0);
    }
  });

  it("projects a persisted attempt as required and held, with no observation", () => {
    const projection = projectControlEvidence(grantedInput("claimed", [attemptRecord("persisted")], { paymentSource: null }));
    wellFormed(projection);
    expect(projection.paymentAttempts).toEqual([{ attemptId: ATTEMPT_A, state: "persisted", certainty: null, exposureBucket: "held" }]);
    expect(projection.dimensions).toMatchObject({ payment: "required", settlement: "not_requested" });
    expect(projection.exposure).toEqual({ ...ZERO, claimed: DEBIT });
    expect(projection.facts.filter((fact) => fact.kind === "payment_observation")).toHaveLength(0);
  });

  it("surfaces an unknown attempt as unknown exposure in its own bucket, never folded into claimed", () => {
    for (const reservation of ["claimed", "unknown", "committed"] as const) {
      const projection = projectControlEvidence(grantedInput(reservation, [attemptRecord("unknown")], { paymentSource: null }));
      wellFormed(projection);
      expect(projection.exposure).toEqual({ ...ZERO, unknown: DEBIT });
      expect(projection.paymentAttempts).toEqual([{ attemptId: ATTEMPT_A, state: "unknown", certainty: "unknown", exposureBucket: "unknown" }]);
      expect(projection.dimensions).toMatchObject({ payment: "unknown", settlement: "unknown" });
      expect(projection.facts.filter((fact) => fact.kind === "payment_observation")).toHaveLength(0);
      const combined = projection.facts.filter((fact): fact is EvidenceV2FactOf<"budget_exposure"> =>
        fact.kind === "budget_exposure" && fact.subject.kind === "action");
      expect(combined).toHaveLength(1);
      expect(combined[0]).toMatchObject({ normalized: { exposure: { ...ZERO, unknown: DEBIT } }, actor: { kind: "system", component: "reconciler" },
        source: { class: "local", sourceId: "openarc.control-projection", origin: "openarc:reconciler" },
        limitations: [L.controlPlane, L.combinedExposure, EVIDENCE_V2_UNKNOWN_PAYMENT_LIMITATION] });
    }
  });

  it("maps a pending attempt strictly through derivePaymentCertainty", () => {
    const projection = projectControlEvidence(grantedInput("claimed", [attemptRecord("pending")]));
    wellFormed(projection);
    const rule = derivePaymentCertainty({ state: "pending", disposition: "held", transferId: TRANSFER, gatewayStatus: "batched", batchTxHash: null });
    expect(projection.paymentAttempts).toEqual([{ attemptId: ATTEMPT_A, state: "pending", certainty: rule.certainty, exposureBucket: rule.exposure }]);
    expect(factOf(projection, "payment_observation", "pending")).toMatchObject({
      source: GATEWAY, subject: { kind: "action", canonicalId: ACTION }, actor: { kind: "external_party", role: "gateway", address: null },
      occurredAt: null, observedAt: OBSERVED, limitations: [L.gatewayPending],
      normalized: { laneState: "pending", certainty: "pending", gatewayStatus: "batched", transferId: TRANSFER, batchTransactionHash: null,
        amountAtomic: VALUE, payer: PAYER.toLowerCase(), payTo: PAY_TO.toLowerCase() } });
    expect(projection.dimensions).toMatchObject({ payment: "submitted", settlement: "pending" });
    expect(projection.exposure).toEqual({ ...ZERO, claimed: DEBIT });
  });

  it("maps a committed attempt to submitted_pending_chain, committed exposure and never paid", () => {
    const projection = projectControlEvidence(grantedInput("claimed", [attemptRecord("committed")]));
    wellFormed(projection);
    const rule = derivePaymentCertainty({ state: "committed", disposition: "committed", transferId: TRANSFER, gatewayStatus: "completed",
      batchTxHash: BATCH, onchainReceiptVerified: false });
    expect(rule).toMatchObject({ certainty: "submitted_pending_chain", exposure: "committed" });
    expect(projection.paymentAttempts).toEqual([{ attemptId: ATTEMPT_A, state: "committed", certainty: rule.certainty, exposureBucket: "committed" }]);
    expect(factOf(projection, "payment_observation", "committed")).toMatchObject({
      limitations: [EVIDENCE_V2_GATEWAY_COMMITTED_LIMITATION],
      normalized: { laneState: "committed", certainty: "submitted_pending_chain", gatewayStatus: "completed", batchTransactionHash: BATCH } });
    expect(projection.dimensions).toMatchObject({ payment: "submitted", settlement: "pending" });
    expect(projection.exposure).toEqual({ ...ZERO, committed: DEBIT });
  });

  it("attributes an observation to the facilitator when the facilitator recorded it", () => {
    const source = { ...GATEWAY, class: "facilitator", sourceId: "x402_facilitator" } as const;
    const projection = projectControlEvidence(grantedInput("claimed", [attemptRecord("pending")], { paymentSource: source }));
    expect(factOf(projection, "payment_observation", "pending")).toMatchObject({ source, actor: { kind: "external_party", role: "facilitator" } });
  });

  it("covers every attempt state against every unresolved reservation status", () => {
    const combos: ControlPaymentAttemptState[][] = [[], ...CONTROL_PAYMENT_ATTEMPT_STATES.map((state) => [state]),
      ...CONTROL_PAYMENT_ATTEMPT_STATES.flatMap((first) => CONTROL_PAYMENT_ATTEMPT_STATES.map((second) => [first, second]))];
    let checked = 0;
    for (const reservation of ["held", "claimed", "unknown", "committed"] as const) {
      for (const combo of combos) {
        const attempts = combo.map((state, index) => attemptRecord(state, ATTEMPT_IDS[index]));
        const projection = projectControlEvidence(grantedInput(reservation, attempts));
        wellFormed(projection);
        const anyUnknown = combo.includes("unknown");
        const observed = combo.filter((state) => state === "pending" || state === "committed");
        const nonzero = Object.entries(projection.exposure).filter(([, amount]) => amount !== "0");
        expect(nonzero).toHaveLength(1);
        const bucket = [reservation, ...combo.map((state) => DISPATCH_BUCKET[state])]
          .reduce((left, right) => (PRECEDENCE[right] > PRECEDENCE[left] ? right : left));
        expect(nonzero[0]).toEqual([bucket, DEBIT]);
        expect(projection.exposure.unknown !== "0").toBe(anyUnknown || reservation === "unknown");
        expect(projection.dimensions.payment).toBe(combo.length === 0 ? "not_requested" : anyUnknown ? "unknown"
          : observed.length > 0 ? "submitted" : "required");
        expect(projection.dimensions.settlement).toBe(combo.length === 0 ? "not_requested" : anyUnknown ? "unknown"
          : observed.length > 0 ? "pending" : "not_requested");
        expect(projection.paymentAttempts.map((attempt) => attempt.certainty)).toEqual(combo.map((state) =>
          state === "persisted" ? null : state === "unknown" ? "unknown" : state === "pending" ? "pending" : "submitted_pending_chain"));
        expect(projection.facts.filter((fact) => fact.kind === "payment_observation")).toHaveLength(observed.length);
        checked += 1;
      }
    }
    expect(checked).toBe(4 * 21);
  });

  it("requires a payment source only for observed attempts", () => {
    expect(inputError(() => projectControlEvidence(grantedInput("claimed", [attemptRecord("pending")], { paymentSource: null }))))
      .toBe("payment_source_required");
    expect(inputError(() => projectControlEvidence(grantedInput("claimed", [attemptRecord("committed")], { paymentSource: null }))))
      .toBe("payment_source_required");
    expect(() => projectControlEvidence(grantedInput("claimed", [attemptRecord("persisted"), attemptRecord("unknown", ATTEMPT_B)],
      { paymentSource: null }))).not.toThrow();
  });

  it("collapses identical observations of one transfer into one fact", () => {
    const projection = projectControlEvidence(grantedInput("claimed", [attemptRecord("pending"),
      { ...attemptRecord("pending", ATTEMPT_B), transferId: TRANSFER }]));
    wellFormed(projection);
    expect(projection.paymentAttempts).toHaveLength(2);
    expect(projection.facts.filter((fact) => fact.kind === "payment_observation")).toHaveLength(1);
  });

  it("flags an attempt against a released reservation while keeping the attempt exposure", () => {
    const projection = projectControlEvidence(grantedInput("released", [attemptRecord("unknown")]));
    expect(projection.inconsistencies).toEqual(["reservation_released_with_payment_attempt"]);
    expect(projection.dimensions.reconciliation).toBe("conflicting");
    expect(projection.exposure).toEqual({ ...ZERO, unknown: DEBIT });
  });
});

// ───────────────────────── determinism ─────────────────────────

describe("control evidence projection determinism", () => {
  it("does not depend on payment attempt order", () => {
    const attempts = [attemptRecord("committed", ATTEMPT_A), attemptRecord("unknown", ATTEMPT_B), attemptRecord("persisted", ATTEMPT_C)];
    const outputs = permutations(attempts).map((order) => JSON.stringify(projectControlEvidence(grantedInput("claimed", order))));
    expect(outputs).toHaveLength(6);
    expect(new Set(outputs).size).toBe(1);
  });

  it("is identical when projected twice", () => {
    const input = grantedInput("claimed", [attemptRecord("pending")], {
      action: actionFacts({ status: "grant_issued", approvalId: APPROVAL, updatedAt: DECIDED }), approval: approvalFacts("approved") });
    expect(projectControlEvidence(input)).toEqual(projectControlEvidence(structuredClone(input)));
  });

  it("resolves re-observations at a later instant and keeps gateway observation IDs", () => {
    const early = projectControlEvidence(grantedInput("claimed", [attemptRecord("committed")]));
    const later = projectControlEvidence(grantedInput("claimed", [attemptRecord("committed")], { evaluatedAt: LATER_EVAL }));
    for (const order of permutations([factOf(early, "grant_state", "claimed"), factOf(later, "grant_state", "claimed")])) {
      expect(resolveEvidenceConflict(order)).toMatchObject({ outcome: "resolved", status: "claimed", firstObservedAt: EVAL,
        lastObservedAt: LATER_EVAL });
    }
    expect(factOf(early, "payment_observation", "committed").evidenceId).toBe(factOf(later, "payment_observation", "committed").evidenceId);
  });

  it("gives out-of-order snapshots the same IDs for the facts they share", () => {
    const older = projectControlEvidence(projectionInput({ action: actionFacts({ status: "grant_issued" }), grant: grantFacts("issued") }));
    const newer = projectControlEvidence(grantedInput("claimed", []));
    for (const [first, second] of [[older, newer], [newer, older]] as const) {
      const union = [...first.facts, ...second.facts].filter((fact) => fact.kind === "grant_state" && evidenceV2FactStatus(fact) === "issued");
      expect(new Set(union.map((fact) => fact.evidenceId)).size).toBe(1);
      expect(resolveEvidenceConflict(union)).toMatchObject({ outcome: "resolved", status: "issued" });
    }
    expect(factOf(older, "grant_state", "issued").evidenceId).toBe(factOf(newer, "grant_state", "issued").evidenceId);
  });
});

describe("controlEvidenceSha256Hex", () => {
  it("matches the FIPS 180-4 vectors and node:crypto across block boundaries and UTF-8", () => {
    expect(controlEvidenceSha256Hex("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(controlEvidenceSha256Hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect(controlEvidenceSha256Hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
      .toBe("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    const samples = [...Array.from({ length: 140 }, (_, length) => "x".repeat(length)), "é€😀 openarc", JSON.stringify(projectionInput())];
    for (const sample of samples) {
      expect(controlEvidenceSha256Hex(sample), `length ${sample.length}`).toBe(createHash("sha256").update(sample, "utf8").digest("hex"));
    }
  });
});
