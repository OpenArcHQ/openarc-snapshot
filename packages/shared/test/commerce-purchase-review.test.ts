import { describe, expect, it } from "vitest";

import {
  EVIDENCE_V2_PAYMENT_CERTAINTIES,
  PURCHASE_ADMITS_NO_SETTLEMENT,
  PURCHASE_DECISIONS,
  PURCHASE_DECISION_DISCLOSURE,
  PURCHASE_DECISION_SUMMARIES,
  PURCHASE_FORBIDDEN_OUTCOME_WORDS,
  PURCHASE_OUTCOMES,
  PURCHASE_OUTCOME_CERTAINTY,
  PURCHASE_OUTCOME_EXPLANATIONS,
  PURCHASE_OUTCOME_LABELS,
  PURCHASE_REVIEW_RULE_VERSION,
  forbiddenPaymentWordsIn,
  purchaseOutcomeForActionStatus,
  purchaseOutcomeForAttemptState,
  purchaseOutcomeForCertainty,
  purchaseReviewFields,
  purchaseUnknownExposureLine,
  type CommerceActionStatus,
  type ControlPaymentAttemptState,
  type PurchaseReviewSource,
} from "../src/index.js";

const SOURCE: PurchaseReviewSource = {
  listingId: "openarc:listing:12345678-1234-4234-8123-123456789abc",
  listingVersion: "3",
  providerId: "openarc:provider:12345678-1234-4234-8123-123456789abc",
  amountAtomic: "1500000",
  feeAtomic: "0",
  debitAtomic: "1500000",
  asset: "USDC",
  decimals: 6,
  networkId: "eip155:5042002",
  policyId: "openarc:policy:12345678-1234-4234-8123-123456789abc",
  policyRevision: "2",
  payToAddress: null,
  approvalExpiresAt: "2026-01-01T00:15:00.000Z",
};

describe("P04-06 purchase outcome vocabulary", () => {
  it("proves at the type level that no forbidden payment state is an outcome", () => {
    expect(PURCHASE_ADMITS_NO_SETTLEMENT).toBe(true);
    for (const forbidden of PURCHASE_FORBIDDEN_OUTCOME_WORDS) {
      expect(PURCHASE_OUTCOMES as readonly string[]).not.toContain(forbidden);
    }
  });

  /**
   * The packet guard: the words paid, settled, refunded, failed and released
   * must never render as a payment outcome anywhere in this flow.
   */
  it("never renders paid, settled, refunded, failed or released in any outcome text", () => {
    const rendered = [
      ...Object.values(PURCHASE_OUTCOME_LABELS),
      ...Object.values(PURCHASE_OUTCOME_EXPLANATIONS),
      ...Object.values(PURCHASE_DECISION_SUMMARIES),
      purchaseUnknownExposureLine(null).label,
      purchaseUnknownExposureLine(null).explanation,
      purchaseUnknownExposureLine("1500000").label,
      purchaseUnknownExposureLine("1500000").explanation,
      ...purchaseReviewFields(SOURCE).flatMap((field) => [field.label, field.explanation]),
    ];
    for (const text of rendered) {
      expect(forbiddenPaymentWordsIn(text), `forbidden payment word rendered in: ${text}`).toEqual([]);
    }
  });

  /**
   * P04-06b: the v6 purchase-decision receipt adds the only new human-facing
   * disclosure text in this flow. It is held to the same guard as every label
   * and explanation above.
   */
  it("never renders a forbidden payment word in the v6 purchase-decision disclosure", () => {
    for (const [field, text] of Object.entries(PURCHASE_DECISION_DISCLOSURE)) {
      expect(forbiddenPaymentWordsIn(text), `forbidden payment word in ${field}: ${text}`).toEqual([]);
    }
    // The disclosure must still say plainly that the decision moves no money.
    expect(PURCHASE_DECISION_DISCLOSURE.purpose).toContain("moves no money");
  });

  it("matches a forbidden word only as a whole word, so settlement and settling stay usable", () => {
    expect(forbiddenPaymentWordsIn("Submitted, awaiting settlement")).toEqual([]);
    expect(forbiddenPaymentWordsIn("the transfer is still settling")).toEqual([]);
    expect(forbiddenPaymentWordsIn("This was paid")).toEqual(["paid"]);
    expect(forbiddenPaymentWordsIn("SETTLED and refunded")).toEqual(["settled", "refunded"]);
    expect(forbiddenPaymentWordsIn("the request failed")).toEqual(["failed"]);
    expect(forbiddenPaymentWordsIn("exposure was released")).toEqual(["released"]);
  });

  it("uses the exact sentence the packet requires for every outcome", () => {
    expect(PURCHASE_OUTCOME_LABELS).toEqual({
      not_requested: "Not requested",
      possibly_sent: "Possibly sent; funds held",
      submitted_pending: "Submitted, awaiting settlement",
      submitted_pending_chain: "Submitted, awaiting on-chain confirmation",
      onchain_confirmed: "Confirmed on-chain",
      not_visible: "Unknown to this console",
    });
  });

  it("reads as confirmed only for an on-chain-confirmed fact", () => {
    const confirmed = PURCHASE_OUTCOMES.filter((outcome) =>
      /\bconfirmed\b/iu.test(PURCHASE_OUTCOME_LABELS[outcome]),
    );
    expect(confirmed).toEqual(["onchain_confirmed"]);
    expect(PURCHASE_OUTCOME_CERTAINTY.onchain_confirmed).toBe("onchain_confirmed");
  });

  it("maps every evidence-v2 certainty onto exactly one outcome and never onto paid", () => {
    for (const certainty of EVIDENCE_V2_PAYMENT_CERTAINTIES) {
      const outcome = purchaseOutcomeForCertainty(certainty);
      expect(PURCHASE_OUTCOMES).toContain(outcome);
      expect(PURCHASE_OUTCOME_CERTAINTY[outcome]).toBe(certainty);
      expect(forbiddenPaymentWordsIn(PURCHASE_OUTCOME_LABELS[outcome])).toEqual([]);
    }
    expect(purchaseOutcomeForCertainty("unknown")).toBe("possibly_sent");
    expect(purchaseOutcomeForCertainty("pending")).toBe("submitted_pending");
    expect(purchaseOutcomeForCertainty("submitted_pending_chain")).toBe("submitted_pending_chain");
  });

  it("treats a persisted or dispatched attempt as possibly sent with funds held", () => {
    const states: readonly ControlPaymentAttemptState[] = ["persisted", "unknown", "pending", "committed"];
    expect(states.map(purchaseOutcomeForAttemptState)).toEqual([
      "possibly_sent",
      "possibly_sent",
      "submitted_pending",
      "submitted_pending_chain",
    ]);
    // A lane committed is Gateway's word only; it is never confirmed.
    expect(purchaseOutcomeForAttemptState("committed")).not.toBe("onchain_confirmed");
  });

  it("says not requested only where no grant can exist, and never guesses otherwise", () => {
    const statuses: readonly CommerceActionStatus[] = [
      "pending_approval",
      "reserved_not_granted",
      "rejected",
      "grant_issued",
      "cancelled",
      "expired",
    ];
    expect(statuses.map(purchaseOutcomeForActionStatus)).toEqual([
      "not_requested",
      "not_requested",
      "not_requested",
      "not_visible",
      "not_visible",
      "not_visible",
    ]);
  });

  it("keeps unresolved money on its own line and never reports it as zero when unknown", () => {
    const unknown = purchaseUnknownExposureLine(null);
    expect(unknown.known).toBe(false);
    expect(unknown.atomic).toBeNull();
    expect(unknown.explanation).toContain("It is not zero.");
    const known = purchaseUnknownExposureLine("250000");
    expect({ known: known.known, atomic: known.atomic }).toEqual({ known: true, atomic: "250000" });
  });
});

describe("P04-06 purchase review fields", () => {
  it("shows the exact integer amount with its asset and decimals and never a float", () => {
    const fields = purchaseReviewFields(SOURCE);
    const byKey = new Map(fields.map((field) => [field.key, field]));
    expect(byKey.get("amountAtomic")?.value).toBe("1500000");
    expect(byKey.get("debitAtomic")?.value).toBe("1500000");
    expect(byKey.get("asset")?.value).toBe("USDC");
    expect(byKey.get("amountAtomic")?.explanation).toContain("6 decimals");
    // Every money figure stays an exact integer string: no decimal point, no
    // separator and no rounding survives into the reviewed value.
    for (const key of ["amountAtomic", "feeAtomic", "debitAtomic"]) {
      expect(byKey.get(key)?.value).toMatch(/^(?:0|[1-9][0-9]*)$/u);
    }
  });

  it("shows the seller-recorded payee as explicitly unknown when no route supplies it", () => {
    const payee = purchaseReviewFields(SOURCE).find((field) => field.key === "payToAddress");
    expect({ known: payee?.known, value: payee?.value }).toEqual({ known: false, value: null });
    expect(payee?.explanation).toContain("unknown");
  });

  it("shows the recorded payee when one is supplied", () => {
    const payToAddress = `0x${"a".repeat(40)}`;
    const payee = purchaseReviewFields({ ...SOURCE, payToAddress }).find(
      (field) => field.key === "payToAddress",
    );
    expect({ known: payee?.known, value: payee?.value }).toEqual({ known: true, value: payToAddress });
  });

  it("carries the listing version, policy revision and approval expiry the human must see", () => {
    const byKey = new Map(purchaseReviewFields(SOURCE).map((field) => [field.key, field.value]));
    expect(byKey.get("listingVersion")).toBe("3");
    expect(byKey.get("policyRevision")).toBe("2");
    expect(byKey.get("approvalExpiresAt")).toBe("2026-01-01T00:15:00.000Z");
  });

  it("marks a missing approval expiry as absent rather than filling one in", () => {
    const expiry = purchaseReviewFields({ ...SOURCE, approvalExpiresAt: null }).find(
      (field) => field.key === "approvalExpiresAt",
    );
    expect({ known: expiry?.known, value: expiry?.value }).toEqual({ known: false, value: null });
  });

  it("offers only approve and reject, and neither claims to move money", () => {
    expect(PURCHASE_DECISIONS).toEqual(["approve", "reject"]);
    expect(PURCHASE_DECISION_SUMMARIES.approve).toContain("does not pay the seller");
    expect(PURCHASE_REVIEW_RULE_VERSION).toBe("openarc.purchase-review.v1");
  });
});
