import {
  PURCHASE_DECISION_SUMMARIES,
  PURCHASE_FORBIDDEN_OUTCOME_WORDS,
  PURCHASE_OUTCOMES,
  PURCHASE_OUTCOME_EXPLANATIONS,
  PURCHASE_OUTCOME_LABELS,
  forbiddenPaymentWordsIn,
  purchaseOutcomeForActionStatus,
  type CommerceActionStatus,
} from "@openarc/shared";
import { describe, expect, it } from "vitest";

import {
  purchaseDecisionOutcomeLabel,
  purchaseOutcomeView,
  purchaseRejectionMessage,
  purchaseReviewOf,
  type PurchaseDecisionState,
  type PurchaseFailureNotice,
} from "../src/tenant/purchase-controller.js";
import { actionMetadata, approvalMetadata } from "./action-test-fixtures.js";
import { CommerceActionMetadataSchema, CommerceApprovalMetadataSchema } from "@openarc/shared";

const ACTION_STATUSES: readonly CommerceActionStatus[] = [
  "pending_approval",
  "reserved_not_granted",
  "grant_issued",
  "rejected",
  "cancelled",
  "expired",
];

/** A valid action in the given status, built from the accepted shared schema. */
function actionIn(status: CommerceActionStatus) {
  const overrides: Record<string, unknown> = { status };
  if (status === "reserved_not_granted" || status === "grant_issued") {
    overrides["reservationId"] = "openarc:reservation:12345678-1234-4234-8123-123456789abc";
  }
  if (status === "cancelled" || status === "expired") {
    overrides["reservationId"] = "openarc:reservation:12345678-1234-4234-8123-123456789abc";
  }
  return CommerceActionMetadataSchema.parse(actionMetadata(undefined, overrides));
}

/**
 * The packet guard. This test fails if the words paid, settled, refunded,
 * failed or released ever render as a payment outcome anywhere in the browser
 * purchase flow — the outcome line, its explanation, the unresolved-money line,
 * the reviewed fields, the decision summaries, the lifecycle labels or any
 * refusal message.
 */
describe("P04-06 purchase flow payment vocabulary", () => {
  function everyRenderedString(): readonly string[] {
    const rendered: string[] = [
      ...Object.values(PURCHASE_OUTCOME_LABELS),
      ...Object.values(PURCHASE_OUTCOME_EXPLANATIONS),
      ...Object.values(PURCHASE_DECISION_SUMMARIES),
    ];
    for (const status of ACTION_STATUSES) {
      const action = actionIn(status);
      const view = purchaseOutcomeView(action);
      rendered.push(view.label, view.explanation, view.unknownExposure.label, view.unknownExposure.explanation);
      for (const field of purchaseReviewOf(action, CommerceApprovalMetadataSchema.parse(approvalMetadata()))) {
        rendered.push(field.label, field.explanation);
        if (field.value !== null) rendered.push(field.value);
      }
    }
    const notices: readonly PurchaseFailureNotice[] = [
      { kind: "validation" },
      { kind: "policy" },
      { kind: "conflict" },
      { kind: "unauthenticated" },
      { kind: "csrf" },
      { kind: "forbidden" },
      { kind: "not-found" },
      { kind: "account-changed" },
      { kind: "capability-disabled" },
      { kind: "no-access" },
      { kind: "vault-conflict" },
      { kind: "receipt-unavailable" },
    ];
    for (const notice of notices) rendered.push(purchaseRejectionMessage(notice));
    const states: readonly PurchaseDecisionState[] = [
      { kind: "idle" },
      { kind: "confirming", decision: "approve", actionId: "openarc:action:12345678-1234-4234-8123-123456789abc" },
      {
        kind: "pending",
        decision: "approve",
        actionId: "openarc:action:12345678-1234-4234-8123-123456789abc",
        mutationId: "12345678-1234-4234-8123-123456789abc",
      },
      { kind: "rejected", notice: { kind: "vault-conflict" } },
      {
        kind: "outcome-unknown",
        decision: "reject",
        actionId: "openarc:action:12345678-1234-4234-8123-123456789abc",
        mutationId: "12345678-1234-4234-8123-123456789abc",
      },
    ];
    for (const state of states) rendered.push(purchaseDecisionOutcomeLabel(state));
    return rendered;
  }

  it("never renders paid, settled, refunded, failed or released as a payment outcome", () => {
    for (const text of everyRenderedString()) {
      expect(forbiddenPaymentWordsIn(text), `forbidden payment word rendered in: ${text}`).toEqual([]);
    }
  });

  it("would fail if a forbidden word were introduced, so the guard is real", () => {
    // Proves the matcher actually detects each forbidden word in rendered text.
    for (const word of PURCHASE_FORBIDDEN_OUTCOME_WORDS) {
      expect(forbiddenPaymentWordsIn(`This purchase was ${word}.`)).toEqual([word]);
    }
  });

  it("reports no attempt as not requested and never as a failure or a cancellation", () => {
    for (const status of ["pending_approval", "reserved_not_granted", "rejected"] as const) {
      const view = purchaseOutcomeView(actionIn(status));
      expect(view.outcome).toBe("not_requested");
      expect(view.label).toBe("Not requested");
    }
  });

  it("refuses to claim not requested once a grant could have produced an attempt", () => {
    for (const status of ["grant_issued", "cancelled", "expired"] as const) {
      const view = purchaseOutcomeView(actionIn(status));
      expect(view.outcome).toBe("not_visible");
      expect(view.label).toBe("Unknown to this console");
      expect(view.explanation).toContain("will not claim");
    }
  });

  it("shows unresolved money on its own line, as unknown rather than zero", () => {
    for (const status of ACTION_STATUSES) {
      const line = purchaseOutcomeView(actionIn(status)).unknownExposure;
      expect(line.key).toBe("unknown");
      expect(line.known).toBe(false);
      expect(line.atomic).toBeNull();
      expect(line.explanation).toContain("It is not zero.");
    }
  });

  it("reads as confirmed only for an on-chain-confirmed fact", () => {
    const confirmed = PURCHASE_OUTCOMES.filter((outcome) =>
      /\bconfirmed\b/iu.test(PURCHASE_OUTCOME_LABELS[outcome]),
    );
    expect(confirmed).toEqual(["onchain_confirmed"]);
    // No action status alone can ever reach it.
    for (const status of ACTION_STATUSES) {
      expect(purchaseOutcomeForActionStatus(status)).not.toBe("onchain_confirmed");
    }
  });

  it("never shows a payee it does not have, and never invents an approval expiry", () => {
    const action = actionIn("pending_approval");
    const fields = purchaseReviewOf(action, null);
    const payee = fields.find((field) => field.key === "payToAddress");
    const expiry = fields.find((field) => field.key === "approvalExpiresAt");
    expect({ known: payee?.known, value: payee?.value }).toEqual({ known: false, value: null });
    expect({ known: expiry?.known, value: expiry?.value }).toEqual({ known: false, value: null });
  });
});
