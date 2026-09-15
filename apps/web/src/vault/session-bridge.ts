/**
 * Vault side of the account-session bridge (PORT-08 P08-02).
 *
 * Loaded only through a dynamic import from `app/vault-session-lock.ts`. It
 * performs exactly what a manual lock performs durably, without a key:
 * read public metadata -> `signalVaultLock` (new coordinationRevision only) ->
 * post the existing `{ sender, type: "lock", vaultId }` coordination message.
 *
 * It never creates a Vault or database, never deletes anything and changes no
 * identifier, format, metadata key set or message type.
 */
import type { VaultSessionLockStatus } from "../app/vault-session-lock.js";
import { VAULT_COORDINATION_CHANNEL, type CoordinationMessage } from "./coordination.js";
import { readVaultMeta, signalVaultLock, VAULT_DATABASE_NAME } from "./db.js";
import type { PublicVaultMeta } from "./types.js";

export interface SessionBridgeDeps {
  vaultDatabaseExists: () => Promise<boolean>;
  readMeta: () => Promise<PublicVaultMeta | null>;
  signalLock: (meta: Pick<PublicVaultMeta, "vaultId">) => Promise<unknown>;
  /** Returns false when no BroadcastChannel is available. */
  broadcastLock: (vaultId: string) => boolean;
}

export async function lockVaultForSessionEnd(
  deps: SessionBridgeDeps = defaultSessionBridgeDeps,
): Promise<VaultSessionLockStatus> {
  let meta: PublicVaultMeta | null;
  try {
    // `readVaultMeta` opens the database at version 1 and would create an
    // empty database when none exists. Probe first so logout never creates one.
    if (!(await deps.vaultDatabaseExists())) return "no-vault";
    meta = await deps.readMeta();
  } catch {
    return "storage-unavailable";
  }
  if (!meta) return "no-vault";
  let written = true;
  try {
    await deps.signalLock(meta);
  } catch {
    written = false;
  }
  let broadcast = false;
  try {
    broadcast = deps.broadcastLock(meta.vaultId);
  } catch {
    broadcast = false;
  }
  if (!written) return "lock-write-failed";
  return broadcast ? "locked" : "locked-poll-only";
}

/**
 * Opens without a version so a missing database fires `upgradeneeded`; that
 * upgrade is aborted, which leaves no database behind.
 */
export function vaultDatabaseExists(): Promise<boolean> {
  if (typeof indexedDB === "undefined") return Promise.reject(new Error("IndexedDB unavailable"));
  return new Promise((resolve, reject) => {
    let created = false;
    const request = indexedDB.open(VAULT_DATABASE_NAME);
    request.onupgradeneeded = () => {
      created = true;
      request.transaction?.abort();
    };
    request.onsuccess = () => {
      const db = request.result;
      const exists = db.objectStoreNames.contains("vaultMeta");
      db.close();
      resolve(exists);
    };
    request.onerror = () => {
      if (created) resolve(false);
      else reject(request.error ?? new Error("IndexedDB probe failed"));
    };
    request.onblocked = () => undefined;
  });
}

export function broadcastVaultLock(vaultId: string): boolean {
  if (typeof BroadcastChannel === "undefined" || typeof crypto.randomUUID !== "function") return false;
  const channel = new BroadcastChannel(VAULT_COORDINATION_CHANNEL);
  try {
    channel.postMessage({ sender: crypto.randomUUID(), type: "lock", vaultId } satisfies CoordinationMessage);
  } finally {
    channel.close();
  }
  return true;
}

export const defaultSessionBridgeDeps: SessionBridgeDeps = {
  vaultDatabaseExists,
  readMeta: readVaultMeta,
  signalLock: signalVaultLock,
  broadcastLock: broadcastVaultLock,
};
