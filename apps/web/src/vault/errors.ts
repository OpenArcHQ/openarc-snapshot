export type VaultErrorCode =
  | "INVALID_BACKUP"
  | "INVALID_PASSPHRASE"
  | "RECOVERY_FAILED"
  | "UNSUPPORTED_BROWSER"
  | "VAULT_CAPACITY"
  | "VAULT_CONFLICT"
  | "VAULT_EXISTS"
  | "VAULT_INCOMPATIBLE";

export class VaultError extends Error {
  readonly code: VaultErrorCode;

  constructor(code: VaultErrorCode, message: string) {
    super(message);
    this.name = "VaultError";
    this.code = code;
  }
}

export const VAULT_INCOMPATIBLE_MESSAGE =
  "This Vault contains records from a newer or different OpenArc build, so this build cannot open it. " +
  "Your passphrase was accepted and nothing was changed. Download an opaque rescue to keep the encrypted data, " +
  "then open this Vault with the OpenArc build that wrote it.";
export const VAULT_INCOMPATIBLE_BACKUP_MESSAGE =
  "This backup contains records from a newer or different OpenArc build, so this build cannot import it. " +
  "The backup passphrase was accepted and nothing was imported. Keep the backup file and import it with the " +
  "OpenArc build that wrote it.";

/**
 * `unknown_record_identity`: an authenticated record whose kind/recordSchema pair this build does not know (a new
 * kind or a future version). `unsupported_record_content`: a known pair whose content fails this build's rules.
 * Raised only AFTER key unwrap and AES-GCM authentication succeeded, so it is never a wrong passphrase. The error
 * carries no record contents, identifiers or field values.
 */
export type VaultIncompatibleReason = "unknown_record_identity" | "unsupported_record_content";

export class VaultIncompatibleError extends VaultError {
  constructor(readonly source: "vault" | "backup", readonly reason: VaultIncompatibleReason) {
    super("VAULT_INCOMPATIBLE", source === "vault" ? VAULT_INCOMPATIBLE_MESSAGE : VAULT_INCOMPATIBLE_BACKUP_MESSAGE);
    this.name = "VaultIncompatibleError";
  }
}

export function vaultErrorMessage(error: unknown): string {
  if (!(error instanceof VaultError)) {
    if (error instanceof DOMException && error.name === "QuotaExceededError") {
      return "This browser could not save the encrypted workspace because its local storage quota is full.";
    }
    return "OpenArc could not complete that local encrypted-workspace operation.";
  }
  switch (error.code) {
    case "INVALID_PASSPHRASE":
    case "RECOVERY_FAILED":
      return "Wrong passphrase or damaged workspace.";
    case "VAULT_INCOMPATIBLE":
      return error.message === VAULT_INCOMPATIBLE_BACKUP_MESSAGE ? VAULT_INCOMPATIBLE_BACKUP_MESSAGE : VAULT_INCOMPATIBLE_MESSAGE;
    case "INVALID_BACKUP":
    case "VAULT_CAPACITY":
    case "VAULT_CONFLICT":
    case "VAULT_EXISTS":
    case "UNSUPPORTED_BROWSER":
      return error.message;
  }
}
