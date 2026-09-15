/**
 * Cross-tab Vault coordination, extracted verbatim from `VaultWorkspace.tsx`
 * so the receiving behaviour can be exercised without a DOM. The channel name
 * and the message shape/types are frozen compatibility identifiers.
 */
import type { PublicVaultMeta, UnlockedWorkspace } from "./types.js";
import { vaultErrorMessage } from "./errors.js";

export const VAULT_COORDINATION_CHANNEL = "openarc-vault-coordination-v1";

export type CoordinationMessage = {
  sender: string;
  type: "changed" | "lock" | "deleting";
  vaultId: string;
};

export type VaultScreen =
  | { phase: "probing" }
  | { phase: "unsupported" }
  | { phase: "empty" }
  | { phase: "locked"; meta: PublicVaultMeta }
  | { phase: "unlocking"; meta: PublicVaultMeta }
  | { phase: "unlocked"; workspace: UnlockedWorkspace }
  | { phase: "locking"; meta: PublicVaultMeta }
  | { phase: "deleting"; meta: PublicVaultMeta | null }
  | { phase: "fatal"; message: string };

/** The refs and state setters of one mounted workspace view (one tab). */
export interface CoordinationTarget {
  sender: () => string;
  unlocked: () => UnlockedWorkspace | null;
  screen: () => VaultScreen;
  generation: () => number;
  /** Must rotate the session boundary and release the key and decrypted state. */
  clearPrivateState: (next: VaultScreen, message?: string) => void;
  setScreen: (next: VaultScreen) => void;
  setNotice: (message: string | null) => void;
  readMeta: () => Promise<PublicVaultMeta | null>;
}

export function isCoordinationMessage(value: unknown): value is CoordinationMessage {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Record<string, unknown>;
  return typeof candidate.sender === "string" && typeof candidate.vaultId === "string" && (candidate.type === "changed" || candidate.type === "lock" || candidate.type === "deleting");
}

export function handleCoordinationMessage(value: unknown, target: CoordinationTarget): void {
  if (!isCoordinationMessage(value) || value.sender === target.sender()) return;
  const current = target.unlocked();
  const currentScreen = target.screen();
  const currentMeta =
    current?.meta ??
    (currentScreen.phase === "locked" ||
    currentScreen.phase === "unlocking" ||
    currentScreen.phase === "locking" ||
    currentScreen.phase === "deleting"
      ? currentScreen.meta
      : null);
  if (!currentMeta && currentScreen.phase === "empty") {
    void target.readMeta()
      .then((meta) => {
        if (!meta || meta.vaultId !== value.vaultId) return;
        target.clearPrivateState(
          meta.deletionPending ? { phase: "deleting", meta } : { phase: "locked", meta },
          meta.deletionPending
            ? "Another tab is deleting this workspace. Workspace controls are unavailable."
            : "An encrypted workspace was created or restored in another tab. Unlock it here to continue.",
        );
      })
      .catch((cause) => {
        target.clearPrivateState({ phase: "fatal", message: vaultErrorMessage(cause) });
      });
    return;
  }
  if (!currentMeta || currentMeta.vaultId !== value.vaultId) return;
  if (value.type === "deleting") {
    void target.readMeta().then((meta) => {
      if (meta?.vaultId === value.vaultId && meta.deletionPending) {
        target.clearPrivateState({ phase: "deleting", meta }, "Another tab is deleting this workspace.");
      }
    }).catch(() => undefined);
  } else {
    lockFromOutside(
      target,
      currentMeta,
      value.type === "changed"
        ? "Workspace changed in another tab. Unlock again to load the latest encrypted revision."
        : "Workspace locked from another tab.",
    );
  }
}

/**
 * Same-document account session end (logout, account change, expiry). Drops
 * decrypted state exactly like a peer `lock`, without needing storage or a
 * vault id. Screens without metadata hold no decrypted state and are left as is.
 */
export function handleLocalSessionEnd(target: CoordinationTarget): void {
  const currentScreen = target.screen();
  const currentMeta =
    target.unlocked()?.meta ??
    (currentScreen.phase === "locked" || currentScreen.phase === "unlocking" || currentScreen.phase === "locking"
      ? currentScreen.meta
      : null);
  if (!currentMeta) return;
  lockFromOutside(target, currentMeta, "Workspace locked because the account session ended.");
}

function lockFromOutside(target: CoordinationTarget, currentMeta: PublicVaultMeta, message: string): void {
  target.clearPrivateState({ phase: "locking", meta: currentMeta }, message);
  // A coordination message is only a hint, not authoritative metadata.
  // Do not expose a form against the old revision: the next poll could
  // otherwise clear credentials entered into that stale form again.
  const boundaryGeneration = target.generation();
  void target.readMeta().then((meta) => {
    if (boundaryGeneration !== target.generation()) return;
    target.setScreen(meta
      ? meta.deletionPending ? { phase: "deleting", meta } : { phase: "locked", meta }
      : { phase: "empty" });
  }).catch((cause) => {
    if (boundaryGeneration !== target.generation()) return;
    target.setScreen({ phase: "fatal", message: vaultErrorMessage(cause) });
    target.setNotice(null);
  });
}
