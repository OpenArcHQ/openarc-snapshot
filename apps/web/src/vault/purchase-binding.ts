import type { WorkspaceRecord } from "@openarc/shared";

import type { PurchaseVaultBinding } from "../tenant/purchase-controller.js";
import { assertStoredWorkspaceRevision } from "./revision-guard.js";
import { saveWorkspaceRecords } from "./service.js";
import type { UnlockedWorkspace } from "./types.js";

/**
 * P04-06c — the REAL Vault binding for the browser purchase decision.
 *
 * Every other receipt-gated flow in this build (capability probe, Arc
 * observation, agent registry, job and Gateway evidence) is wired the same way
 * inside the workspace: the live unlocked workspace, `saveWorkspaceRecords`,
 * the durable `assertStoredWorkspaceRevision` recheck, this tab's active
 * session check, and the workspace's own refusal handler which re-reads the
 * stored Vault and locks. This module is that wiring for the purchase
 * decision, extracted so it can be exercised against a real encrypted Vault
 * rather than only described.
 *
 * It adds NO Vault identifier, record schema, AAD, KDF, cap, channel or
 * message type. The record it commits is built by the purchase flow itself.
 *
 * A locked, deleting, replaced or absent workspace yields NO binding at all.
 * The purchase controller then refuses every decision before a request can
 * exist, instead of sending one that no receipt describes. There is no
 * auto-unlock here and no passphrase prompt: unlocking stays the workspace's
 * own explicit flow.
 */

export type SaveWorkspaceRecords = (
  workspace: UnlockedWorkspace,
  records: readonly WorkspaceRecord[],
  assertActive: () => void,
  signal: AbortSignal,
) => Promise<UnlockedWorkspace>;

export interface PurchaseVaultSession {
  /** The workspace unlocked in THIS tab right now, or null when it is not. */
  readonly currentWorkspace: () => UnlockedWorkspace | null;
  /** Throws when this tab's Vault session generation changed. */
  readonly assertActive: () => void;
  /** False once this tab's Vault session was superseded or unmounted. */
  readonly isActive: () => boolean;
  /**
   * The exact origin the decision request is sent to, recorded on the receipt.
   * A session that cannot name one produces no binding rather than a guess.
   */
  readonly origin: string | null;
  /** Adopts the workspace the receipt was committed into (revision included). */
  readonly onCommitted: (workspace: UnlockedWorkspace) => void;
  /**
   * The workspace's existing refusal handler. It re-reads the stored Vault and
   * moves this tab to the locked/deleting state it actually found.
   */
  readonly onRefused: (cause: unknown, isActive: () => boolean) => void;
  /** Injectable for tests; defaults to the real encrypted save. */
  readonly save?: SaveWorkspaceRecords;
  /** Injectable for tests; defaults to the durable stored-revision recheck. */
  readonly verifyStored?: (workspace: UnlockedWorkspace) => Promise<void>;
}

/**
 * Builds the binding, or returns null when no unlocked workspace can receipt a
 * decision. Null is the honest answer for a locked, deleting or missing Vault:
 * the controls are then unavailable and nothing is sent.
 */
export function createPurchaseVaultBinding(
  session: PurchaseVaultSession,
): PurchaseVaultBinding | null {
  const workspace = session.currentWorkspace();
  if (workspace === null) return null;
  const origin = session.origin;
  if (origin === null || origin.length === 0) return null;

  const save = session.save ?? saveWorkspaceRecords;
  const verify = session.verifyStored ?? ((current: UnlockedWorkspace) =>
    assertStoredWorkspaceRevision(current));
  // The workspace this binding speaks for. A commit advances it; anything else
  // replacing it means this binding is stale and must refuse.
  let expected = workspace;

  return {
    workspace,
    origin,
    assertActive: () => {
      session.assertActive();
      if (session.currentWorkspace() !== expected) throw new Error("Vault session changed");
    },
    save: async (current, records, assertActive, signal) => {
      const saved = await save(current, records, assertActive, signal);
      assertActive();
      expected = saved;
      session.onCommitted(saved);
      return saved;
    },
    verifyStored: async (current) => {
      try {
        await verify(current);
      } catch (cause) {
        // The stored Vault disagrees: nothing is sent, the committed receipt
        // stays, and this tab is moved to the state the Vault is actually in.
        session.onRefused(cause, session.isActive);
        throw cause;
      }
    },
  };
}
