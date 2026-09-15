import { readVaultMeta } from "./db.js";
import { VaultError } from "./errors.js";
import type { PublicVaultMeta, UnlockedWorkspace } from "./types.js";

/**
 * Pre-egress durable recheck (frontend architecture §11 "Vault generation and
 * revision recheck"). The in-memory session generation only changes after this
 * tab learns of a peer lock through BroadcastChannel or its 2 s poll. Reading
 * the stored metadata immediately before a request closes that window: a lock
 * signal, save, replacement or deletion marker committed by any tab after this
 * workspace's last commit refuses the request with `VAULT_CONFLICT`.
 */
export async function assertStoredWorkspaceRevision(
  workspace: Pick<UnlockedWorkspace, "meta">,
  readMeta: () => Promise<PublicVaultMeta | null> = readVaultMeta,
): Promise<void> {
  const stored = await readMeta();
  if (
    !stored ||
    stored.vaultId !== workspace.meta.vaultId ||
    stored.revision !== workspace.meta.revision ||
    stored.coordinationRevision !== workspace.meta.coordinationRevision ||
    stored.deletionPending
  ) {
    throw new VaultError(
      "VAULT_CONFLICT",
      "This encrypted workspace changed or was locked in another tab. Nothing was sent. Unlock again before continuing.",
    );
  }
}
