/**
 * Account-session -> Vault lock trigger (PORT-08 P08-02, R55: "logout locks").
 *
 * This module is deliberately tiny and has NO static import of any Vault
 * module. The account and tenant shells import it statically; the Vault code
 * that reads metadata and writes the lock signal is loaded only through the
 * dynamic `import("../vault/session-bridge.js")` below, and only when a
 * session actually ends.
 *
 * It never creates, deletes or modifies Vault records, never needs a key and
 * never blocks the account flow: every path resolves within `timeoutMs`.
 */

export type VaultSessionEndReason =
  | "logout"
  | "logout-unconfirmed"
  | "account-changed"
  | "session-expired";

/**
 * Non-secret outcome. It carries no vault id, revision or record data.
 * - `no-vault`: nothing exists locally; nothing was created.
 * - `locked`: lock signal committed and the existing `lock` message broadcast.
 * - `locked-poll-only`: lock signal committed; BroadcastChannel unavailable, so
 *   other tabs detect the new coordination revision through their 2 s poll.
 * - `lock-write-failed`: metadata was read and `lock` was broadcast, but the
 *   durable lock signal could not be written.
 * - `storage-unavailable`: IndexedDB (or the Vault module) could not be used.
 * - `timeout`: the local storage did not answer in time; logout continued.
 */
export type VaultSessionLockStatus =
  | "no-vault"
  | "locked"
  | "locked-poll-only"
  | "lock-write-failed"
  | "storage-unavailable"
  | "timeout";

export interface VaultSessionBridge {
  lockVaultForSessionEnd: () => Promise<VaultSessionLockStatus>;
}

export interface VaultSessionLockOptions {
  timeoutMs?: number;
  loadBridge?: () => Promise<VaultSessionBridge>;
}

export const VAULT_SESSION_LOCK_TIMEOUT_MS = 1_500;

type LocalListener = (reason: VaultSessionEndReason) => void;
const localListeners = new Set<LocalListener>();

/**
 * Same-document subscription. A mounted Vault view drops its decrypted state
 * synchronously when this document ends an account session, even when
 * IndexedDB or BroadcastChannel is unavailable.
 */
export function subscribeVaultSessionEnd(listener: LocalListener): () => void {
  localListeners.add(listener);
  return () => {
    localListeners.delete(listener);
  };
}

const loadDefaultBridge = (): Promise<VaultSessionBridge> => import("../vault/session-bridge.js");

/**
 * Locks the Vault in this tab and every other tab. Resolves (never rejects)
 * with a non-secret status no later than `timeoutMs`.
 */
export async function lockVaultOnSessionEnd(
  reason: VaultSessionEndReason,
  options: VaultSessionLockOptions = {},
): Promise<VaultSessionLockStatus> {
  // 1. Drop in-memory plaintext in this document first; this needs no storage.
  for (const listener of [...localListeners]) {
    try {
      listener(reason);
    } catch {
      // A failing view must not prevent the durable lock or the logout.
    }
  }
  // 2. Metadata read -> lock-signal write -> `lock` broadcast, bounded in time.
  const loadBridge = options.loadBridge ?? loadDefaultBridge;
  const work = (async (): Promise<VaultSessionLockStatus> => {
    try {
      const bridge = await loadBridge();
      return await bridge.lockVaultForSessionEnd();
    } catch {
      return "storage-unavailable";
    }
  })();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<VaultSessionLockStatus>((resolve) => {
    timer = setTimeout(() => resolve("timeout"), options.timeoutMs ?? VAULT_SESSION_LOCK_TIMEOUT_MS);
  });
  try {
    return await Promise.race([work, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

/** True when the lock could not be confirmed and the user should be told. */
export function vaultLockNeedsAttention(status: VaultSessionLockStatus): boolean {
  return status === "lock-write-failed" || status === "storage-unavailable" || status === "timeout";
}

export const VAULT_LOCK_ATTENTION_NOTICE =
  "The local encrypted workspace could not be confirmed locked in other tabs. Close any open workspace tabs.";

/**
 * Converts observed account identities into Vault lock triggers.
 *
 * - `undefined -> anything` (first observation) and `guest -> account` (login)
 *   never lock.
 * - `account A -> account B` locks with `account-changed`.
 * - `account A -> guest` locks with `session-expired`, unless an explicit
 *   logout already locked for A.
 * - A disposed watcher (unmount) ignores transitions, so leaving a page or the
 *   controller's own unmount reset is never mistaken for a session end.
 */
export class VaultSessionEndWatcher {
  #previous: string | null | undefined = undefined;
  #handledLogoutFor: string | null = null;
  #disposed = false;
  readonly #lock: (reason: VaultSessionEndReason) => Promise<VaultSessionLockStatus>;
  readonly #onStatus: (status: VaultSessionLockStatus) => void;

  constructor(options: {
    lock?: (reason: VaultSessionEndReason) => Promise<VaultSessionLockStatus>;
    onStatus?: (status: VaultSessionLockStatus) => void;
  } = {}) {
    this.#lock = options.lock ?? ((reason) => lockVaultOnSessionEnd(reason));
    this.#onStatus = options.onStatus ?? (() => undefined);
  }

  /** Records a settled identity. Returns the lock promise when one started. */
  observe(identity: string | null): Promise<VaultSessionLockStatus> | null {
    if (this.#disposed) return null;
    const previous = this.#previous;
    this.#previous = identity;
    if (typeof previous !== "string" || previous === identity) return null;
    if (identity === null && this.#handledLogoutFor === previous) {
      this.#handledLogoutFor = null;
      return null;
    }
    this.#handledLogoutFor = null;
    return this.#run(identity === null ? "session-expired" : "account-changed");
  }

  /**
   * Explicit logout whose request was sent (confirmed or not). Always locks,
   * and suppresses the follow-up `A -> guest` transition for the same account.
   */
  logout(reason: "logout" | "logout-unconfirmed"): Promise<VaultSessionLockStatus> {
    if (typeof this.#previous === "string") this.#handledLogoutFor = this.#previous;
    return this.#run(reason);
  }

  dispose(): void {
    this.#disposed = true;
    this.#previous = undefined;
    this.#handledLogoutFor = null;
  }

  resume(): void {
    this.#disposed = false;
  }

  async #run(reason: VaultSessionEndReason): Promise<VaultSessionLockStatus> {
    const status = await this.#lock(reason);
    this.#onStatus(status);
    return status;
  }
}
