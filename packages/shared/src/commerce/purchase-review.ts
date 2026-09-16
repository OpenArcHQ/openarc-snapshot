import {
  EVIDENCE_V2_GATEWAY_COMMITTED_LIMITATION,
  EVIDENCE_V2_UNKNOWN_PAYMENT_LIMITATION,
  type EvidenceV2PaymentCertainty,
} from "./evidence-v2.js";
import type { ControlPaymentAttemptState } from "./control-evidence-projection.js";
import type { CommerceActionStatus } from "./control-action.js";

/**
 * P04-06 — pure browser purchase review and outcome vocabulary.
 *
 * Pure contracts only: no clock, no I/O, no transport and no persistence.
 * Nothing here pays, settles, delivers, signs or moves funds, and no value in
 * this module can describe a paid, settled, refunded, failed or released
 * payment. That is proved at the type level below and re-proved at runtime by
 * the shared vocabulary test.
 *
 * The outcome vocabulary is a projection of the accepted evidence-v2 payment
 * certainty (`openarc.evidence.v2.payment-certainty.v1`). It adds exactly one
 * state that certainty does not model, `not_visible`: the browser audience has
 * NO route that returns a payment attempt, so when an attempt could exist the
 * console says so explicitly instead of inventing "not requested".
 */

export const PURCHASE_REVIEW_RULE_VERSION = "openarc.purchase-review.v1" as const;

/**
 * The only outcomes this flow can render.
 *
 * `not_requested`          no payment attempt exists for this purchase.
 * `possibly_sent`          an attempt was persisted or dispatched. It may have
 *                          been sent; the exposure stays held. This is never a
 *                          failure and never a cancellation.
 * `submitted_pending`      Gateway received the transfer; not completed.
 * `submitted_pending_chain` the lane committed on Gateway's word alone.
 * `onchain_confirmed`      a finalized, matching, successful Arc receipt.
 * `not_visible`            an attempt may exist but no browser route exposes
 *                          it, so this console refuses to claim either way.
 */
export const PURCHASE_OUTCOMES = [
  "not_requested",
  "possibly_sent",
  "submitted_pending",
  "submitted_pending_chain",
  "onchain_confirmed",
  "not_visible",
] as const;
export type PurchaseOutcome = (typeof PURCHASE_OUTCOMES)[number];

/** Payment words this flow must never render as an outcome. */
export const PURCHASE_FORBIDDEN_OUTCOME_WORDS = [
  "paid",
  "settled",
  "refunded",
  "failed",
  "released",
] as const;
export type PurchaseForbiddenOutcomeWord = (typeof PURCHASE_FORBIDDEN_OUTCOME_WORDS)[number];

type IsNever<T> = [T] extends [never] ? true : false;

/** Resolves to `true` only while no forbidden payment state is an outcome. */
export type PurchaseAdmitsNoSettlement = IsNever<
  Extract<PurchaseOutcome, PurchaseForbiddenOutcomeWord>
>;
export const PURCHASE_ADMITS_NO_SETTLEMENT: PurchaseAdmitsNoSettlement = true;

/**
 * Matches a forbidden payment word as a WHOLE word only. "settlement" and
 * "settling" are legitimate descriptions of an unfinished transfer and must not
 * trip the guard; "settled" must.
 */
export const PURCHASE_FORBIDDEN_OUTCOME_PATTERN = new RegExp(
  `\\b(?:${PURCHASE_FORBIDDEN_OUTCOME_WORDS.join("|")})\\b`,
  "iu",
);

/** Every forbidden whole word present in `text`, lowercased and deduplicated. */
export function forbiddenPaymentWordsIn(text: string): readonly PurchaseForbiddenOutcomeWord[] {
  const found = new Set<PurchaseForbiddenOutcomeWord>();
  for (const word of PURCHASE_FORBIDDEN_OUTCOME_WORDS) {
    if (new RegExp(`\\b${word}\\b`, "iu").test(text)) found.add(word);
  }
  return Object.freeze([...found]);
}

/** The exact sentence each outcome renders. No outcome reads as confirmed unless it is. */
export const PURCHASE_OUTCOME_LABELS: Readonly<Record<PurchaseOutcome, string>> = Object.freeze({
  not_requested: "Not requested",
  possibly_sent: "Possibly sent; funds held",
  submitted_pending: "Submitted, awaiting settlement",
  submitted_pending_chain: "Submitted, awaiting on-chain confirmation",
  onchain_confirmed: "Confirmed on-chain",
  not_visible: "Unknown to this console",
});

/** What each outcome does and does not assert, in plain language. */
export const PURCHASE_OUTCOME_EXPLANATIONS: Readonly<Record<PurchaseOutcome, string>> = Object.freeze({
  not_requested:
    "No payment attempt exists for this purchase. Nothing has been sent and no money is held.",
  possibly_sent: EVIDENCE_V2_UNKNOWN_PAYMENT_LIMITATION,
  submitted_pending:
    "Gateway reports the transfer is not completed; the exposure remains held. This is not a completed transfer.",
  submitted_pending_chain: EVIDENCE_V2_GATEWAY_COMMITTED_LIMITATION,
  onchain_confirmed:
    "A finalized Arc Testnet receipt matches the Gateway batch transaction. This is the only outcome that is confirmed.",
  not_visible:
    "A payment attempt may exist for this purchase, but no browser route reports one. This console will not claim that money did or did not move.",
});

/** The evidence-v2 certainty each outcome corresponds to, or null when certainty does not model it. */
export const PURCHASE_OUTCOME_CERTAINTY: Readonly<
  Record<PurchaseOutcome, EvidenceV2PaymentCertainty | null>
> = Object.freeze({
  not_requested: null,
  possibly_sent: "unknown",
  submitted_pending: "pending",
  submitted_pending_chain: "submitted_pending_chain",
  onchain_confirmed: "onchain_confirmed",
  not_visible: null,
});

/** Projects an evidence-v2 payment certainty onto the rendered outcome. */
export function purchaseOutcomeForCertainty(certainty: EvidenceV2PaymentCertainty): PurchaseOutcome {
  switch (certainty) {
    case "unknown":
      return "possibly_sent";
    case "pending":
      return "submitted_pending";
    case "submitted_pending_chain":
      return "submitted_pending_chain";
    case "onchain_confirmed":
      return "onchain_confirmed";
  }
}

/**
 * Projects a durable attempt state onto the rendered outcome. A `persisted`
 * attempt was never dispatched, but PORT-04 treats anything after persist as
 * possibly sent and keeps its exposure held, so it is `possibly_sent` too.
 */
export function purchaseOutcomeForAttemptState(state: ControlPaymentAttemptState): PurchaseOutcome {
  switch (state) {
    case "persisted":
    case "unknown":
      return "possibly_sent";
    case "pending":
      return "submitted_pending";
    case "committed":
      return "submitted_pending_chain";
  }
}

/**
 * The outcome derivable from an action status ALONE, which is all the browser
 * audience can read today.
 *
 * A payment attempt requires an authorization grant (PORT-04), so every status
 * that cannot have a grant is honestly `not_requested`. `grant_issued` can have
 * one, and no browser route reports it, so it is `not_visible` rather than a
 * guess in either direction.
 */
export function purchaseOutcomeForActionStatus(status: CommerceActionStatus): PurchaseOutcome {
  switch (status) {
    case "pending_approval":
    case "reserved_not_granted":
    case "rejected":
      return "not_requested";
    case "grant_issued":
      return "not_visible";
    case "cancelled":
    case "expired":
      // A cancelled or expired action may still have held exposure from an
      // attempt made while it was granted. Never claim the money came back.
      return "not_visible";
  }
}

/** One figure on the outcome view, always carrying whether it is actually known. */
export interface PurchaseExposureLine {
  readonly key: string;
  readonly label: string;
  /** The exact canonical atomic string, or null when this console cannot know it. */
  readonly atomic: string | null;
  readonly known: boolean;
  readonly explanation: string;
}

/**
 * Unknown exposure is ALWAYS its own line and is never folded into another
 * figure (evidence-v2 decision 6). The browser audience has no route returning
 * the four-bucket summary, so the unknown bucket is reported as unknown rather
 * than as zero.
 */
export function purchaseUnknownExposureLine(atomic: string | null): PurchaseExposureLine {
  return Object.freeze({
    key: "unknown",
    label: "Money that is not resolved",
    atomic,
    known: atomic !== null,
    explanation:
      atomic === null
        ? "No browser route reports unresolved payment exposure for this purchase, so this console cannot show a figure. It is not zero."
        : "Exposure that is not resolved. It is never folded into another figure and never reported as returned.",
  });
}

/** A field of the purchase review that the browser audience may not be able to fill. */
export interface PurchaseReviewField {
  readonly key: string;
  readonly label: string;
  /** The exact server value, or null when no browser route supplies it. */
  readonly value: string | null;
  readonly known: boolean;
  readonly explanation: string;
}

export interface PurchaseReviewSource {
  readonly listingId: string;
  readonly listingVersion: string;
  readonly providerId: string;
  readonly amountAtomic: string;
  readonly feeAtomic: string;
  readonly debitAtomic: string;
  readonly asset: string;
  readonly decimals: number;
  readonly networkId: string;
  readonly policyId: string;
  readonly policyRevision: string;
  /** The pay-to address the seller recorded, when a browser route ever supplies one. */
  readonly payToAddress: string | null;
  /** The approval's expiry, from the approval detail route. */
  readonly approvalExpiresAt: string | null;
}

const UNKNOWN_PAYEE =
  "The seller's recorded pay-to address is not returned by any browser route, so this console shows it as unknown rather than inventing one.";
const UNKNOWN_APPROVAL_EXPIRY =
  "This action has no approval record, so there is no approval expiry to show.";

/**
 * The exact review of what would be committed. Every amount stays a canonical
 * integer string with its asset and decimals; nothing is parsed into a
 * JavaScript number, rounded or approximated here.
 */
export function purchaseReviewFields(source: PurchaseReviewSource): readonly PurchaseReviewField[] {
  const known = (key: string, label: string, value: string, explanation: string): PurchaseReviewField =>
    Object.freeze({ key, label, value, known: true, explanation });
  return Object.freeze([
    known("listingId", "Seller listing", source.listingId, "The listing this purchase would buy."),
    known(
      "listingVersion",
      "Listing version",
      source.listingVersion,
      "The exact published version whose recorded terms apply.",
    ),
    known("providerId", "Seller", source.providerId, "The provider that published the listing."),
    known(
      "amountAtomic",
      "Amount",
      source.amountAtomic,
      `The exact price as an integer in ${source.asset} atomic units (${source.decimals} decimals).`,
    ),
    known(
      "feeAtomic",
      "Fee",
      source.feeAtomic,
      `The exact fee as an integer in ${source.asset} atomic units (${source.decimals} decimals).`,
    ),
    known(
      "debitAtomic",
      "Budget that would be committed",
      source.debitAtomic,
      "Amount plus fee. This is what the policy budget would commit if you approve; it is not a payment.",
    ),
    known("asset", "Asset", source.asset, "The asset the recorded price is denominated in."),
    known("networkId", "Network", source.networkId, "The network the recorded terms name."),
    Object.freeze({
      key: "payToAddress",
      label: "Payee recorded by the seller",
      value: source.payToAddress,
      known: source.payToAddress !== null,
      explanation: source.payToAddress === null ? UNKNOWN_PAYEE : "The immutable pay-to address recorded for this listing version.",
    }),
    known("policyId", "Policy", source.policyId, "The policy whose budget this purchase would commit against."),
    known(
      "policyRevision",
      "Policy revision",
      source.policyRevision,
      "The exact policy revision the server bound to this action.",
    ),
    Object.freeze({
      key: "approvalExpiresAt",
      label: "Approval expires",
      value: source.approvalExpiresAt,
      known: source.approvalExpiresAt !== null,
      explanation:
        source.approvalExpiresAt === null
          ? UNKNOWN_APPROVAL_EXPIRY
          : "After this instant the approval can no longer be decided.",
    }),
  ]);
}

/** The decision a human can record on a pending purchase. There is no third option that moves money. */
export const PURCHASE_DECISIONS = ["approve", "reject"] as const;
export type PurchaseDecision = (typeof PURCHASE_DECISIONS)[number];

/** Exactly what each decision does, before it is sent. */
export const PURCHASE_DECISION_SUMMARIES: Readonly<Record<PurchaseDecision, string>> = Object.freeze({
  approve:
    "Approve records your approval of this purchase. It commits the budget shown above. It does not pay the seller, move money or complete a purchase by itself.",
  reject:
    "Reject records your rejection. No grant is issued and no budget is committed. It does not return money, because none has been sent by this decision.",
});
