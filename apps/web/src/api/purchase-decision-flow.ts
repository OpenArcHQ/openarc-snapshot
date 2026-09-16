import {
  PURCHASE_DECISION_DISCLOSURE,
  PURCHASE_DECISION_ROUTE_BY_DECISION,
  PurchaseDecisionPermissionReceiptRecordSchema,
  type CommerceActionMetadata,
  type CommerceApprovalMetadata,
  type PurchaseDecision,
  type PurchaseDecisionPermissionReceiptRecord,
  type WorkspaceRecord,
} from "@openarc/shared";

import type { UnlockedWorkspace } from "../vault/types.js";

/**
 * P04-06 — receipt-gated egress for a human purchase decision.
 *
 * The ordering is the accepted one from `permission-flow.ts` and the four
 * evidence flows, and it is the whole point of this module:
 *
 *   1. assert the Vault session is still active;
 *   2. commit an encrypted receipt of what the human saw and decided;
 *   3. assert again, then run the DURABLE pre-egress revision recheck;
 *   4. only then let the decision request leave the browser.
 *
 * If the Vault changed, was locked, replaced or marked for deletion between (2)
 * and (3), `verifyStored` throws and `send` is never called: nothing leaves the
 * browser and the committed receipt STAYS as the audit trail of what the human
 * approved. A receipt is never rolled back to hide a refused egress.
 *
 * This module holds no record schema of its own. It is generic over the record
 * the caller commits, so it can never widen, weaken or add a Vault record
 * identity; a caller that cannot build a receipt gets `send` refused outright
 * rather than an ungated request.
 */

/**
 * Raised BEFORE anything is sent when the caller cannot commit a receipt. The
 * decision is refused rather than sent ungated: an unrecorded purchase approval
 * is exactly what this gate exists to prevent.
 */
export class PurchaseReceiptUnavailableError extends Error {
  constructor(readonly reason: "no-receipt-builder" | "no-workspace") {
    super("This purchase decision was not sent because its encrypted local receipt could not be committed.");
    this.name = "PurchaseReceiptUnavailableError";
  }
}

/** Raised when the receipt committed but the decision's own storage step failed. */
export class PurchaseFinalizationError extends Error {
  constructor(readonly phase: "receipt", readonly storageCause: unknown) {
    super("A purchase decision receipt could not be saved, so nothing was sent.");
    this.name = "PurchaseFinalizationError";
  }
}

/** Exactly what the console showed the human, and exactly what it will send. */
export interface PurchaseDecisionReceiptSubject {
  readonly decision: PurchaseDecision;
  readonly organizationId: string;
  readonly actionId: string;
  readonly mutationId: string;
  readonly action: CommerceActionMetadata;
  /** Null when no approval record exists or its read failed: the expiry is then genuinely absent. */
  readonly approval: CommerceApprovalMetadata | null;
}

/**
 * Builds the v6 purchase-decision receipt.
 *
 * Synchronous and pure, as `buildReceipt` requires: the receipt describes the
 * reviewed state at the instant of the decision, with no chance of a later read
 * changing it. It parses through the frozen schema, so a value the receipt
 * cannot honestly represent throws HERE — before the revision guard, and
 * therefore before any request can exist.
 *
 * `released` is exactly the wire: the organization ID and purchase ID are path
 * segments, the decision is which of the two routes is called, and the mutation
 * ID is the entire JSON body. The CSRF token and idempotency key are headers
 * and are not representable on this record at all.
 */
export function buildPurchaseDecisionReceipt(
  workspace: UnlockedWorkspace,
  origin: string,
  subject: PurchaseDecisionReceiptSubject,
  clock: { readonly now?: () => string; readonly id?: () => string } = {},
): PurchaseDecisionPermissionReceiptRecord {
  const at = (clock.now ?? (() => new Date().toISOString()))();
  const recordId = (clock.id ?? (() => crypto.randomUUID()))();
  const action = subject.action;
  const approval = subject.approval;
  return PurchaseDecisionPermissionReceiptRecordSchema.parse({
    recordSchema: "openarc.permission-receipt.v6",
    kind: "permission_receipt",
    recordId,
    recordRevision: workspace.meta.revision,
    createdAt: at,
    updatedAt: at,
    connectorId: PURCHASE_DECISION_DISCLOSURE.connectorId,
    destination: {
      origin,
      path: PURCHASE_DECISION_ROUTE_BY_DECISION[subject.decision],
      method: "POST",
      upstreams: [],
    },
    releasedFields: ["organizationId", "actionId", "decision", "mutationId"],
    released: {
      organizationId: subject.organizationId,
      actionId: subject.actionId,
      decision: subject.decision,
      mutationId: subject.mutationId,
    },
    reviewed: {
      listingId: action.listingId,
      listingVersion: action.listingVersion,
      providerId: action.providerId,
      amountAtomic: action.amountAtomic,
      feeAtomic: action.feeAtomic,
      debitAtomic: action.debitAtomic,
      asset: action.exposureKey.asset,
      decimals: action.exposureKey.decimals,
      networkId: action.exposureKey.networkId,
      policyId: action.policyId,
      policyRevision: action.policyRevision,
      // The approval pair moves together: an expiry is never shown without the
      // approval it belongs to, and never invented when the read failed.
      approvalId: approval?.approvalId ?? null,
      approvalExpiresAt: approval?.expiresAt ?? null,
    },
    purpose: PURCHASE_DECISION_DISCLOSURE.purpose,
    credentials: PURCHASE_DECISION_DISCLOSURE.credentials,
    openArcRetention: PURCHASE_DECISION_DISCLOSURE.openArcRetention,
    providerRetention: PURCHASE_DECISION_DISCLOSURE.providerRetention,
    hostingMetadata: PURCHASE_DECISION_DISCLOSURE.hostingMetadata,
    approvedAt: at,
    outcome: "approved",
    resolvedAt: null,
    failureCode: null,
  });
}

export interface PurchaseDecisionFlowOptions<T> {
  readonly workspace: UnlockedWorkspace;
  readonly signal: AbortSignal;
  /** Throws when this tab's Vault session generation changed. */
  readonly assertActive: () => void;
  readonly save: (
    workspace: UnlockedWorkspace,
    records: readonly WorkspaceRecord[],
    assertActive: () => void,
    signal: AbortSignal,
  ) => Promise<UnlockedWorkspace>;
  /** Durable pre-egress recheck of the stored Vault revision and lock signal. */
  readonly verifyStored?: (workspace: UnlockedWorkspace) => Promise<void>;
  /**
   * Builds the encrypted record of what the human saw and decided. It must be
   * synchronous and pure so the receipt describes the reviewed state exactly,
   * with no chance of a later read changing it.
   */
  readonly buildReceipt: (workspace: UnlockedWorkspace) => readonly WorkspaceRecord[];
  /** The ONE decision request. It is called at most once and never retried here. */
  readonly send: (signal: AbortSignal) => Promise<T>;
}

export interface PurchaseDecisionFlowResult<T> {
  readonly workspace: UnlockedWorkspace;
  readonly result: T;
}

/**
 * Commits the receipt, re-checks the stored Vault, then sends exactly one
 * decision request. Returns the workspace the receipt was committed into.
 */
export async function runPurchaseDecisionFlow<T>(
  options: PurchaseDecisionFlowOptions<T>,
): Promise<PurchaseDecisionFlowResult<T>> {
  options.assertActive();
  const records = options.buildReceipt(options.workspace);
  if (records.length === 0) throw new PurchaseReceiptUnavailableError("no-receipt-builder");

  let current: UnlockedWorkspace;
  try {
    current = await options.save(options.workspace, records, options.assertActive, options.signal);
  } catch (cause) {
    if (options.signal.aborted) throw cause;
    // The receipt did not commit, so the decision is NOT sent.
    throw new PurchaseFinalizationError("receipt", cause);
  }
  options.assertActive();
  // A peer lock/save/deletion committed in IndexedDB but not yet observed by
  // this tab must stop the request, not only an in-memory generation change.
  await options.verifyStored?.(current);
  options.assertActive();
  const result = await options.send(options.signal);
  return { workspace: current, result };
}
