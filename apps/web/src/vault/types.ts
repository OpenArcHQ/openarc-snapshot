import type { WorkspaceRecord } from "@openarc/shared";

export const VAULT_FORMAT = "openarc.encrypted-vault" as const;
export const VAULT_BACKUP_MAGIC = "OPENARC-ENCRYPTED-BACKUP" as const;
export const VAULT_FORMAT_VERSION = 1 as const;
export const VAULT_DATABASE_VERSION = 1 as const;
export const VAULT_SCHEMA_VERSION = 1 as const;
export const VAULT_KEY_VERSION = 1 as const;
export const VAULT_RECORD_SCHEMA = 1 as const;
export const VAULT_WRAP_KDF_ITERATIONS = 600_000;
export const VAULT_BACKUP_KDF_ITERATIONS = 600_000;
export const VAULT_RECORD_CAPS = Object.freeze({
  agent_profile: 100,
  monitoring_policy: 500,
  evidence_record: 5_000,
  action_envelope: 1_000,
  permission_receipt: 1_000,
  arc_observation: 1_000,
  agent_registry_observation: 1_000,
  job_observation: 1_000,
  x402_bundle: 1_000,
  gateway_observation: 1_000,
  agent_import: 32,
  agent_monitoring_policy: 100,
  workspace_settings: 1,
  sentinel: 1,
} as const);
// P08-01: caps of the ROOT build's kinds, equal to its apps/web/src/vault/types.ts:24-26. Kept in a separate additive
// constant because VAULT_RECORD_CAPS is frozen byte-for-byte by the P08-00 identifier test (item 6).
export const ROOT_VAULT_RECORD_CAPS = Object.freeze({
  task_draft: 100,
  task_report: 100,
  research_run: 100,
} as const);
/** Every stored kind with its cap; the type fails to compile if a union member has no cap. */
export const VAULT_RECORD_CAPS_BY_KIND: Readonly<Record<WorkspaceRecord["kind"], number>> = Object.freeze({
  ...VAULT_RECORD_CAPS,
  ...ROOT_VAULT_RECORD_CAPS,
});
// Combined capacity is independent of per-kind ceilings; keep the M02 manifest bound.
export const VAULT_MAX_RECORDS = 6_602;
export const VAULT_MAX_BACKUP_BYTES = 32 * 1024 * 1024;
export const VAULT_MAX_RESCUE_BYTES = 64 * 1024 * 1024;

export interface VaultKdf {
  version: "openarc.wrap-kdf.v1" | "openarc.backup-kdf.v1";
  algorithm: "PBKDF2-HMAC-SHA-256";
  iterations: number;
  salt: string;
}

export interface WrappedKey {
  algorithm: "AES-KW";
  ciphertext: string;
}

export interface PublicVaultMeta {
  key: "active";
  format: typeof VAULT_FORMAT;
  formatVersion: typeof VAULT_FORMAT_VERSION;
  databaseVersion: typeof VAULT_DATABASE_VERSION;
  vaultId: string;
  schemaVersion: typeof VAULT_SCHEMA_VERSION;
  keyVersion: typeof VAULT_KEY_VERSION;
  revision: string;
  coordinationRevision: string;
  deletionPending: boolean;
  passphraseKdf: VaultKdf;
  passphraseWrapper: WrappedKey;
  recoveryKdf: VaultKdf;
  recoveryWrapper: WrappedKey;
  sentinelRecordId: string;
}

export interface EncryptedEnvelope {
  id: string;
  iv: string;
  keyVersion: typeof VAULT_KEY_VERSION;
  schemaVersion: typeof VAULT_RECORD_SCHEMA;
  revision: string;
  ciphertext: string;
}

export interface LogicalBackupArchive {
  format: "openarc.logical-backup";
  formatVersion: typeof VAULT_FORMAT_VERSION;
  exportedAt: string;
  records: WorkspaceRecord[];
}

export interface StoredVaultSnapshot {
  vault: PublicVaultMeta;
  records: EncryptedEnvelope[];
}

export interface VaultBackupFile {
  magic: typeof VAULT_BACKUP_MAGIC;
  version: typeof VAULT_FORMAT_VERSION;
  kdf: VaultKdf;
  iv: string;
  ciphertext: string;
}

export interface OpaqueVaultRescue {
  magic: "OPENARC-OPAQUE-RESCUE";
  version: 1;
  exportedAt: string;
  warning: "ENCRYPTED_RESCUE_NOT_IMPORTABLE_BY_THIS_BUILD";
  vaultMeta: unknown;
  records: unknown[];
}

export interface VaultStorageStatus {
  supported: boolean;
  persistent: boolean | null;
  usage: number | null;
  quota: number | null;
}

export interface UnlockedWorkspace {
  meta: PublicVaultMeta;
  key: CryptoKey;
  records: WorkspaceRecord[];
}

export interface CreatedWorkspace extends UnlockedWorkspace {
  recoverySecret: string;
}

export interface VaultSessionIdentity {
  vaultId: string;
  generation: number;
  revision: string;
}
