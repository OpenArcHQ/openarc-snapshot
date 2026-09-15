import {
  IsoTimestampSchema,
  SentinelRecordSchema,
  WorkspaceRecordSchema,
  classifyWorkspaceRecordIdentity,
  type SentinelRecord,
  type WorkspaceRecord,
} from "@openarc/shared";

import { VaultError, VaultIncompatibleError } from "./errors.js";
import {
  VAULT_BACKUP_MAGIC,
  VAULT_DATABASE_VERSION,
  VAULT_FORMAT,
  VAULT_FORMAT_VERSION,
  VAULT_BACKUP_KDF_ITERATIONS,
  VAULT_KEY_VERSION,
  VAULT_MAX_BACKUP_BYTES,
  VAULT_MAX_RECORDS,
  VAULT_RECORD_CAPS_BY_KIND,
  VAULT_RECORD_SCHEMA,
  VAULT_SCHEMA_VERSION,
  VAULT_WRAP_KDF_ITERATIONS,
  type EncryptedEnvelope,
  type PublicVaultMeta,
  type LogicalBackupArchive,
  type VaultBackupFile,
  type VaultKdf,
  type WrappedKey,
} from "./types.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const RECOVERY_SECRET = /^OA1-[A-Za-z0-9_-]{43}$/u;
const MAX_RECORD_CIPHERTEXT = 2 * 1024 * 1024;

export interface CreatedVaultMaterial {
  meta: PublicVaultMeta;
  key: CryptoKey;
  recoverySecret: string;
}

export interface RecoveredVaultMaterial {
  meta: PublicVaultMeta;
  key: CryptoKey;
  records: WorkspaceRecord[];
  recoverySecret: string;
}

export function isVaultPlatformSupported(): boolean {
  return (
    globalThis.isSecureContext === true &&
    typeof globalThis.indexedDB !== "undefined" &&
    typeof globalThis.crypto?.subtle !== "undefined" &&
    typeof globalThis.crypto?.getRandomValues === "function" &&
    typeof globalThis.crypto?.randomUUID === "function" &&
    typeof globalThis.TextEncoder !== "undefined" &&
    typeof globalThis.TextDecoder !== "undefined" &&
    typeof globalThis.Blob !== "undefined" &&
    typeof globalThis.URL?.createObjectURL === "function"
  );
}

export async function probeVaultPlatform(): Promise<boolean> {
  if (!isVaultPlatformSupported()) return false;
  try {
    const kdf = createKdf("openarc.wrap-kdf.v1");
    const wrappingKey = await deriveKey("openarc-capability-probe", kdf, "AES-KW", [
      "wrapKey",
      "unwrapKey",
    ]);
    const dataKey = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"],
    );
    const wrapped = await crypto.subtle.wrapKey("raw", dataKey, wrappingKey, "AES-KW");
    const unwrapped = await crypto.subtle.unwrapKey(
      "raw",
      wrapped,
      wrappingKey,
      "AES-KW",
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
    const iv = randomBytes(12);
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, unwrapped, new Uint8Array());
    await crypto.subtle.decrypt({ name: "AES-GCM", iv }, unwrapped, ciphertext);
    return true;
  } catch {
    return false;
  }
}

export function validatePassphrase(passphrase: string): string {
  const normalized = passphrase.normalize("NFC");
  const length = Array.from(normalized).length;
  const byteLength = encoder.encode(normalized).byteLength;
  if (
    normalized !== normalized.trim() ||
    length < 12 ||
    length > 128 ||
    byteLength > 512 ||
    Array.from(normalized).some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint <= 0x1f || codePoint === 0x7f;
    })
  ) {
    throw new VaultError(
      "INVALID_PASSPHRASE",
      "Use 12–128 characters with no leading, trailing, or control whitespace.",
    );
  }
  return normalized;
}

export function validateRecoverySecret(secret: string): string {
  if (!RECOVERY_SECRET.test(secret)) {
    throw new VaultError("RECOVERY_FAILED", "Wrong passphrase or damaged workspace.");
  }
  return secret;
}

export async function createVaultMaterial(passphrase: string): Promise<CreatedVaultMaterial> {
  const normalized = validatePassphrase(passphrase);
  const vaultId = crypto.randomUUID();
  const sentinelRecordId = crypto.randomUUID();
  const recoverySecret = createRecoverySecret();
  const dataKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
  const passphraseKdf = createKdf("openarc.wrap-kdf.v1");
  const recoveryKdf = createKdf("openarc.wrap-kdf.v1");
  const passphraseWrapper = await wrapDataKey(dataKey, normalized, passphraseKdf);
  const recoveryWrapper = await wrapDataKey(dataKey, recoverySecret, recoveryKdf);
  const key = await unwrapDataKey(passphraseWrapper, normalized, passphraseKdf, false);
  const meta: PublicVaultMeta = {
    key: "active",
    format: VAULT_FORMAT,
    formatVersion: VAULT_FORMAT_VERSION,
    databaseVersion: VAULT_DATABASE_VERSION,
    vaultId,
    schemaVersion: VAULT_SCHEMA_VERSION,
    keyVersion: VAULT_KEY_VERSION,
    revision: createRevision(),
    coordinationRevision: createRevision(),
    deletionPending: false,
    passphraseKdf,
    passphraseWrapper,
    recoveryKdf,
    recoveryWrapper,
    sentinelRecordId,
  };
  return { meta, key, recoverySecret };
}

export async function unlockVaultSnapshot(
  metaInput: unknown,
  envelopesInput: unknown,
  passphrase: string,
): Promise<{ meta: PublicVaultMeta; key: CryptoKey; records: WorkspaceRecord[] }> {
  const meta = parsePublicVaultMeta(metaInput);
  const envelopes = parseEncryptedEnvelopes(envelopesInput);
  try {
    const key = await unwrapDataKey(
      meta.passphraseWrapper,
      validatePassphrase(passphrase),
      meta.passphraseKdf,
      false,
    );
    const records = await decryptAndValidateSnapshot(meta, key, envelopes);
    return { meta, key, records };
  } catch (error) {
    if (error instanceof VaultError && (error.code === "VAULT_CAPACITY" || error.code === "VAULT_INCOMPATIBLE")) throw error;
    throw new VaultError("INVALID_PASSPHRASE", "Wrong passphrase or damaged workspace.");
  }
}

export async function authenticateVaultSnapshot(
  metaInput: unknown,
  envelopesInput: unknown,
  sessionKey: CryptoKey,
): Promise<{ meta: PublicVaultMeta; records: WorkspaceRecord[] }> {
  const meta = parsePublicVaultMeta(metaInput);
  const envelopes = parseEncryptedEnvelopes(envelopesInput);
  const records = await decryptAndValidateSnapshot(meta, sessionKey, envelopes);
  return { meta, records };
}

export async function encryptWorkspaceRecord(
  meta: PublicVaultMeta,
  key: CryptoKey,
  recordInput: unknown,
  forbiddenIvs: Set<string> = new Set(),
): Promise<EncryptedEnvelope> {
  const parsedMeta = parsePublicVaultMeta(meta);
  const record = WorkspaceRecordSchema.parse(recordInput);
  if (record.recordRevision !== parsedMeta.revision) {
    throw new VaultError("VAULT_CONFLICT", "A workspace record was prepared for a different revision.");
  }
  const iv = uniqueRandomIv(forbiddenIvs);
  const plaintext = encoder.encode(canonicalJson(record));
  if (plaintext.byteLength > MAX_RECORD_CIPHERTEXT) {
    throw new VaultError("VAULT_CAPACITY", "One encrypted workspace record is too large.");
  }
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      tagLength: 128,
      additionalData: recordAad(parsedMeta, record.recordId, record.recordRevision),
    },
    key,
    plaintext,
  );
  return {
    id: record.recordId,
    iv: toBase64Url(iv),
    keyVersion: VAULT_KEY_VERSION,
    schemaVersion: VAULT_RECORD_SCHEMA,
    revision: record.recordRevision,
    ciphertext: toBase64Url(new Uint8Array(ciphertext)),
  };
}

export async function decryptWorkspaceRecord(
  meta: PublicVaultMeta,
  key: CryptoKey,
  envelopeInput: unknown,
): Promise<WorkspaceRecord> {
  const parsedMeta = parsePublicVaultMeta(meta);
  const envelope = parseEncryptedEnvelope(envelopeInput);
  let value: unknown;
  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: fromBase64Url(envelope.iv),
        tagLength: 128,
        additionalData: recordAad(parsedMeta, envelope.id, envelope.revision),
      },
      key,
      fromBase64Url(envelope.ciphertext),
    );
    value = JSON.parse(decoder.decode(plaintext)) as unknown;
  } catch {
    throw damagedRecord();
  }
  // From here the plaintext is authenticated. Identity binding is a damage check for every kind, known or not.
  const identity = value as { recordId?: unknown; recordRevision?: unknown } | null;
  if (typeof value !== "object" || identity === null || identity.recordId !== envelope.id ||
    identity.recordRevision !== envelope.revision) {
    throw damagedRecord();
  }
  const parsed = WorkspaceRecordSchema.safeParse(value);
  if (parsed.success) return parsed.data;
  // P08-01: only this parse-failure path changes. The record never leaves this function and is not described.
  const identityClass = classifyWorkspaceRecordIdentity(value);
  if (identityClass === "malformed") throw damagedRecord();
  throw new VaultIncompatibleError("vault",
    identityClass === "unknown" ? "unknown_record_identity" : "unsupported_record_content");
}

function damagedRecord(): VaultError {
  return new VaultError("INVALID_BACKUP", "An encrypted workspace record is damaged or incompatible.");
}

export async function createManifestSentinel(
  meta: PublicVaultMeta,
  key: CryptoKey,
  envelopes: readonly EncryptedEnvelope[],
  createdAt = new Date().toISOString(),
  forbiddenIvs: Set<string> = new Set(envelopes.map((envelope) => envelope.iv)),
): Promise<{ record: SentinelRecord; envelope: EncryptedEnvelope }> {
  const entries = await Promise.all(
    envelopes
      .filter((envelope) => envelope.id !== meta.sentinelRecordId)
      .sort((left, right) => left.id.localeCompare(right.id))
      .map(async (envelope) => ({
        recordId: envelope.id,
        revision: envelope.revision,
        digest: await encryptedEnvelopeDigest(envelope),
      })),
  );
  const record = SentinelRecordSchema.parse({
    recordSchema: "openarc.workspace-record.v1",
    recordId: meta.sentinelRecordId,
    recordRevision: meta.revision,
    kind: "sentinel",
    marker: "OPENARC_VAULT_SENTINEL_V1",
    vaultRevision: meta.revision,
    manifest: entries,
    createdAt,
    updatedAt: new Date().toISOString(),
  });
  return { record, envelope: await encryptWorkspaceRecord(meta, key, record, forbiddenIvs) };
}

export async function changeVaultPassphrase(
  metaInput: unknown,
  envelopesInput: unknown,
  currentPassphrase: string,
  nextPassphrase: string,
): Promise<{ meta: PublicVaultMeta; key: CryptoKey; records: WorkspaceRecord[] }> {
  const meta = parsePublicVaultMeta(metaInput);
  const envelopes = parseEncryptedEnvelopes(envelopesInput);
  try {
    const extractableKey = await unwrapDataKey(
      meta.passphraseWrapper,
      validatePassphrase(currentPassphrase),
      meta.passphraseKdf,
      true,
    );
    const records = await decryptAndValidateSnapshot(meta, extractableKey, envelopes);
    const passphraseKdf = createKdf("openarc.wrap-kdf.v1");
    const normalizedNext = validatePassphrase(nextPassphrase);
    const passphraseWrapper = await wrapDataKey(extractableKey, normalizedNext, passphraseKdf);
    const key = await unwrapDataKey(passphraseWrapper, normalizedNext, passphraseKdf, false);
    return {
      meta: { ...meta, revision: createRevision(), passphraseKdf, passphraseWrapper },
      key,
      records,
    };
  } catch (error) {
    if (error instanceof VaultError && (error.code === "VAULT_CAPACITY" || error.code === "VAULT_INCOMPATIBLE")) throw error;
    throw new VaultError("INVALID_PASSPHRASE", "Wrong passphrase or damaged workspace.");
  }
}

export async function recoverVaultSnapshot(
  metaInput: unknown,
  envelopesInput: unknown,
  recoverySecret: string,
  nextPassphrase: string,
): Promise<RecoveredVaultMaterial> {
  const meta = parsePublicVaultMeta(metaInput);
  const envelopes = parseEncryptedEnvelopes(envelopesInput);
  try {
    const extractableKey = await unwrapDataKey(
      meta.recoveryWrapper,
      validateRecoverySecret(recoverySecret),
      meta.recoveryKdf,
      true,
    );
    const records = await decryptAndValidateSnapshot(meta, extractableKey, envelopes);
    const normalizedNext = validatePassphrase(nextPassphrase);
    const nextRecoverySecret = createRecoverySecret();
    const passphraseKdf = createKdf("openarc.wrap-kdf.v1");
    const recoveryKdf = createKdf("openarc.wrap-kdf.v1");
    const passphraseWrapper = await wrapDataKey(extractableKey, normalizedNext, passphraseKdf);
    const recoveryWrapper = await wrapDataKey(extractableKey, nextRecoverySecret, recoveryKdf);
    const key = await unwrapDataKey(passphraseWrapper, normalizedNext, passphraseKdf, false);
    return {
      meta: {
        ...meta,
        revision: createRevision(),
        passphraseKdf,
        passphraseWrapper,
        recoveryKdf,
        recoveryWrapper,
      },
      key,
      records,
      recoverySecret: nextRecoverySecret,
    };
  } catch (error) {
    if (error instanceof VaultError && (error.code === "VAULT_CAPACITY" || error.code === "VAULT_INCOMPATIBLE")) throw error;
    throw new VaultError("RECOVERY_FAILED", "Wrong passphrase or damaged workspace.");
  }
}

export async function createEncryptedBackup(
  metaInput: unknown,
  envelopesInput: unknown,
  sessionKey: CryptoKey,
  backupPassphrase: string,
): Promise<VaultBackupFile> {
  const meta = parsePublicVaultMeta(metaInput);
  const envelopes = parseEncryptedEnvelopes(envelopesInput);
  const records = await decryptAndValidateSnapshot(meta, sessionKey, envelopes);
  const logicalRecords = records.filter((record) => record.kind !== "sentinel");
  assertLogicalBackupCapacity(logicalRecords);
  const archive: LogicalBackupArchive = {
    format: "openarc.logical-backup",
    formatVersion: VAULT_FORMAT_VERSION,
    exportedAt: new Date().toISOString(),
    records: [...logicalRecords].sort((left, right) => left.recordId.localeCompare(right.recordId)),
  };
  const kdf = createKdf("openarc.backup-kdf.v1");
  const iv = randomBytes(12);
  const backupKey = await deriveKey(validatePassphrase(backupPassphrase), kdf, "AES-GCM", [
    "encrypt",
  ]);
  const header = {
    magic: VAULT_BACKUP_MAGIC,
    version: VAULT_FORMAT_VERSION,
    kdf,
    iv: toBase64Url(iv),
  } as const;
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, tagLength: 128, additionalData: backupHeaderAad(header) },
    backupKey,
    encoder.encode(canonicalJson(archive)),
  );
  const backup: VaultBackupFile = {
    ...header,
    ciphertext: toBase64Url(new Uint8Array(ciphertext)),
  };
  if (encoder.encode(JSON.stringify(backup)).byteLength > VAULT_MAX_BACKUP_BYTES) {
    throw new VaultError("VAULT_CAPACITY", "Encrypted workspace backups are limited to 32 MiB.");
  }
  return backup;
}

export async function decryptEncryptedBackup(
  backupInput: unknown,
  passphrase: string,
): Promise<{ archive: LogicalBackupArchive; records: WorkspaceRecord[] }> {
  const backup = parseBackupFile(backupInput);
  try {
    const backupKey = await deriveKey(validatePassphrase(passphrase), backup.kdf, "AES-GCM", [
      "decrypt",
    ]);
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: fromBase64Url(backup.iv),
        tagLength: 128,
        additionalData: backupHeaderAad({
          magic: backup.magic,
          version: backup.version,
          kdf: backup.kdf,
          iv: backup.iv,
        }),
      },
      backupKey,
      fromBase64Url(backup.ciphertext),
    );
    const archive = parseLogicalBackupArchive(JSON.parse(decoder.decode(plaintext)) as unknown);
    return { archive, records: archive.records };
  } catch (error) {
    if (error instanceof VaultError && (error.code === "VAULT_CAPACITY" || error.code === "VAULT_INCOMPATIBLE")) throw error;
    throw new VaultError("INVALID_BACKUP", "Wrong backup passphrase or damaged encrypted backup.");
  }
}

export function parseBackupFile(value: unknown): VaultBackupFile {
  if (!isObjectWithKeys(value, ["magic", "version", "kdf", "iv", "ciphertext"])) {
    throw invalidBackup();
  }
  if (
    value.magic !== VAULT_BACKUP_MAGIC ||
    value.version !== VAULT_FORMAT_VERSION ||
    typeof value.iv !== "string" ||
    decodeLength(value.iv) !== 12 ||
    typeof value.ciphertext !== "string" ||
    value.ciphertext.length < 22 ||
    value.ciphertext.length > Math.ceil(VAULT_MAX_BACKUP_BYTES * 4 / 3) ||
    !BASE64URL.test(value.ciphertext)
  ) {
    throw invalidBackup();
  }
  return {
    magic: value.magic,
    version: value.version,
    kdf: parseKdf(value.kdf, "openarc.backup-kdf.v1"),
    iv: value.iv,
    ciphertext: value.ciphertext,
  };
}

export function parsePublicVaultMeta(value: unknown): PublicVaultMeta {
  const keys = [
    "key",
    "format",
    "formatVersion",
    "databaseVersion",
    "vaultId",
    "schemaVersion",
    "keyVersion",
    "revision",
    "coordinationRevision",
    "deletionPending",
    "passphraseKdf",
    "passphraseWrapper",
    "recoveryKdf",
    "recoveryWrapper",
    "sentinelRecordId",
  ];
  if (!isObjectWithKeys(value, keys)) throw invalidBackup();
  if (
    value.key !== "active" ||
    value.format !== VAULT_FORMAT ||
    value.formatVersion !== VAULT_FORMAT_VERSION ||
    value.databaseVersion !== VAULT_DATABASE_VERSION ||
    typeof value.vaultId !== "string" ||
    !UUID.test(value.vaultId) ||
    value.schemaVersion !== VAULT_SCHEMA_VERSION ||
    value.keyVersion !== VAULT_KEY_VERSION ||
    typeof value.revision !== "string" ||
    decodeLength(value.revision) !== 24 ||
    typeof value.coordinationRevision !== "string" ||
    decodeLength(value.coordinationRevision) !== 24 ||
    typeof value.deletionPending !== "boolean" ||
    typeof value.sentinelRecordId !== "string" ||
    !UUID.test(value.sentinelRecordId)
  ) {
    throw invalidBackup();
  }
  return {
    key: value.key,
    format: value.format,
    formatVersion: value.formatVersion,
    databaseVersion: value.databaseVersion,
    vaultId: value.vaultId,
    schemaVersion: value.schemaVersion,
    keyVersion: value.keyVersion,
    revision: value.revision,
    coordinationRevision: value.coordinationRevision,
    deletionPending: value.deletionPending,
    passphraseKdf: parseKdf(value.passphraseKdf, "openarc.wrap-kdf.v1"),
    passphraseWrapper: parseWrappedKey(value.passphraseWrapper),
    recoveryKdf: parseKdf(value.recoveryKdf, "openarc.wrap-kdf.v1"),
    recoveryWrapper: parseWrappedKey(value.recoveryWrapper),
    sentinelRecordId: value.sentinelRecordId,
  };
}

export function parseEncryptedEnvelope(value: unknown): EncryptedEnvelope {
  if (!isObjectWithKeys(value, ["id", "iv", "keyVersion", "schemaVersion", "revision", "ciphertext"])) {
    throw invalidBackup();
  }
  if (
    typeof value.id !== "string" ||
    !UUID.test(value.id) ||
    typeof value.iv !== "string" ||
    decodeLength(value.iv) !== 12 ||
    value.keyVersion !== VAULT_KEY_VERSION ||
    value.schemaVersion !== VAULT_RECORD_SCHEMA ||
    typeof value.revision !== "string" ||
    decodeLength(value.revision) !== 24 ||
    typeof value.ciphertext !== "string" ||
    value.ciphertext.length < 22 ||
    value.ciphertext.length > Math.ceil(MAX_RECORD_CIPHERTEXT * 4 / 3) ||
    !BASE64URL.test(value.ciphertext)
  ) {
    throw invalidBackup();
  }
  return {
    id: value.id,
    iv: value.iv,
    keyVersion: value.keyVersion,
    schemaVersion: value.schemaVersion,
    revision: value.revision,
    ciphertext: value.ciphertext,
  };
}

export function assertVaultCapacity(meta: PublicVaultMeta, records: readonly EncryptedEnvelope[]): void {
  if (records.length > VAULT_MAX_RECORDS) {
    throw new VaultError("VAULT_CAPACITY", `Encrypted workspaces are limited to ${VAULT_MAX_RECORDS} records.`);
  }
  const ids = new Set(records.map((record) => record.id));
  if (ids.size !== records.length) throw invalidBackup();
  const estimated = estimateBackupBytes(meta, records);
  if (estimated > VAULT_MAX_BACKUP_BYTES) {
    throw new VaultError("VAULT_CAPACITY", "This change would make the encrypted workspace impossible to back up.");
  }
}

export function assertWorkspaceRecordCapacity(records: readonly WorkspaceRecord[]): void {
  const withSentinel = records.length + (records.some((record) => record.kind === "sentinel") ? 0 : 1);
  if (withSentinel > VAULT_MAX_RECORDS) {
    throw new VaultError("VAULT_CAPACITY", `Encrypted workspaces are limited to ${VAULT_MAX_RECORDS} total records.`);
  }
  const counts = new Map<WorkspaceRecord["kind"], number>();
  for (const record of records) counts.set(record.kind, (counts.get(record.kind) ?? 0) + 1);
  for (const [kind, maximum] of Object.entries(VAULT_RECORD_CAPS_BY_KIND)) {
    if ((counts.get(kind as WorkspaceRecord["kind"]) ?? 0) > maximum) {
      throw new VaultError("VAULT_CAPACITY", `The encrypted workspace ${kind} limit is ${maximum}.`);
    }
  }
}

export function estimateBackupBytes(meta: PublicVaultMeta, records: readonly EncryptedEnvelope[]): number {
  void meta;
  const recordBytes = records.reduce(
    (sum, record) => sum + Math.max(0, decodeLength(record.ciphertext) - 16),
    0,
  );
  const encryptedBytes = recordBytes + records.length * 256 + 256 + 16;
  const encodedLength = Math.ceil(encryptedBytes / 3) * 4;
  const placeholder: VaultBackupFile = {
    magic: VAULT_BACKUP_MAGIC,
    version: VAULT_FORMAT_VERSION,
    kdf: {
      version: "openarc.backup-kdf.v1",
      algorithm: "PBKDF2-HMAC-SHA-256",
      iterations: VAULT_BACKUP_KDF_ITERATIONS,
      salt: "x".repeat(22),
    },
    iv: "x".repeat(16),
    ciphertext: "x".repeat(encodedLength),
  };
  return encoder.encode(JSON.stringify(placeholder)).byteLength;
}

export function assertLogicalBackupCapacity(records: readonly WorkspaceRecord[]): void {
  assertWorkspaceRecordCapacity(records);
  const archive: LogicalBackupArchive = {
    format: "openarc.logical-backup",
    formatVersion: VAULT_FORMAT_VERSION,
    exportedAt: "2000-01-01T00:00:00.000Z",
    records: [...records].sort((left, right) => left.recordId.localeCompare(right.recordId)),
  };
  const encryptedBytes = encoder.encode(canonicalJson(archive)).byteLength + 16;
  const encodedLength = Math.ceil(encryptedBytes / 3) * 4;
  const header: Omit<VaultBackupFile, "ciphertext"> = {
    magic: VAULT_BACKUP_MAGIC,
    version: VAULT_FORMAT_VERSION,
    kdf: {
      version: "openarc.backup-kdf.v1",
      algorithm: "PBKDF2-HMAC-SHA-256",
      iterations: VAULT_BACKUP_KDF_ITERATIONS,
      salt: "x".repeat(22),
    },
    iv: "x".repeat(16),
  };
  const exactBytes = encoder.encode(
    JSON.stringify({ ...header, ciphertext: "x".repeat(encodedLength) }),
  ).byteLength;
  if (exactBytes > VAULT_MAX_BACKUP_BYTES) {
    throw new VaultError("VAULT_CAPACITY", "This change would make the encrypted workspace impossible to back up.");
  }
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`)
    .join(",")}}`;
}

async function decryptAndValidateSnapshot(
  meta: PublicVaultMeta,
  key: CryptoKey,
  envelopes: readonly EncryptedEnvelope[],
): Promise<WorkspaceRecord[]> {
  assertVaultCapacity(meta, envelopes);
  // Every envelope is authenticated before any verdict, so the outcome never depends on decryption timing: damage
  // anywhere wins over incompatibility, and incompatibility is reported only for a Vault whose sentinel and manifest
  // also verify.
  const settled = await Promise.allSettled(envelopes.map((envelope) => decryptWorkspaceRecord(meta, key, envelope)));
  const records: WorkspaceRecord[] = [];
  let incompatible: VaultIncompatibleError | null = null;
  for (const result of settled) {
    if (result.status === "fulfilled") records.push(result.value);
    else if (result.reason instanceof VaultIncompatibleError) incompatible ??= result.reason;
    else throw result.reason;
  }
  const sentinels = records.filter((record) => record.kind === "sentinel");
  if (sentinels.length !== 1 || sentinels[0]?.recordId !== meta.sentinelRecordId) {
    throw invalidBackup();
  }
  await verifyManifest(meta, envelopes, sentinels[0]);
  if (incompatible) throw incompatible;
  assertWorkspaceRecordCapacity(records);
  return records.sort((left, right) => left.recordId.localeCompare(right.recordId));
}

async function verifyManifest(
  meta: PublicVaultMeta,
  envelopes: readonly EncryptedEnvelope[],
  sentinel: SentinelRecord,
): Promise<void> {
  if (sentinel.vaultRevision !== meta.revision || sentinel.recordRevision !== meta.revision) {
    throw invalidBackup();
  }
  const expected = await Promise.all(
    envelopes
      .filter((envelope) => envelope.id !== meta.sentinelRecordId)
      .sort((left, right) => left.id.localeCompare(right.id))
      .map(async (envelope) => ({
        recordId: envelope.id,
        revision: envelope.revision,
        digest: await encryptedEnvelopeDigest(envelope),
      })),
  );
  if (canonicalJson(expected) !== canonicalJson(sentinel.manifest)) throw invalidBackup();
}

async function encryptedEnvelopeDigest(envelope: EncryptedEnvelope): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(canonicalJson(envelope)));
  return `sha256:${Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("")}`;
}

function parseEncryptedEnvelopes(value: unknown): EncryptedEnvelope[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > VAULT_MAX_RECORDS) throw invalidBackup();
  return value.map(parseEncryptedEnvelope);
}

function parseLogicalBackupArchive(value: unknown): LogicalBackupArchive {
  if (!isObjectWithKeys(value, ["format", "formatVersion", "exportedAt", "records"])) {
    throw invalidBackup();
  }
  if (
    value.format !== "openarc.logical-backup" ||
    value.formatVersion !== VAULT_FORMAT_VERSION ||
    typeof value.exportedAt !== "string" ||
    !IsoTimestampSchema.safeParse(value.exportedAt).success
  ) {
    throw invalidBackup();
  }
  if (!Array.isArray(value.records) || value.records.length < 1 || value.records.length >= VAULT_MAX_RECORDS) {
    throw invalidBackup();
  }
  const records: WorkspaceRecord[] = [];
  let incompatible: VaultIncompatibleError | null = null;
  for (const candidate of value.records as unknown[]) {
    const parsed = WorkspaceRecordSchema.safeParse(candidate);
    if (parsed.success) {
      records.push(parsed.data);
      continue;
    }
    // P08-01: the archive already authenticated under the backup passphrase. A damaged record wins over any
    // incompatible one; nothing about either record is described.
    const identityClass = classifyWorkspaceRecordIdentity(candidate);
    if (identityClass === "malformed") throw invalidBackup();
    incompatible ??= new VaultIncompatibleError("backup",
      identityClass === "unknown" ? "unknown_record_identity" : "unsupported_record_content");
  }
  if (incompatible) throw incompatible;
  if (new Set(records.map((record) => record.recordId)).size !== records.length) throw invalidBackup();
  if (records.some((record) => record.kind === "sentinel")) throw invalidBackup();
  assertLogicalBackupCapacity(records);
  return {
    format: value.format,
    formatVersion: value.formatVersion,
    exportedAt: value.exportedAt,
    records,
  };
}

function createKdf(version: VaultKdf["version"]): VaultKdf {
  return {
    version,
    algorithm: "PBKDF2-HMAC-SHA-256",
    iterations:
      version === "openarc.wrap-kdf.v1"
        ? VAULT_WRAP_KDF_ITERATIONS
        : VAULT_BACKUP_KDF_ITERATIONS,
    salt: toBase64Url(randomBytes(16)),
  };
}

function parseKdf(value: unknown, expectedVersion: VaultKdf["version"]): VaultKdf {
  if (!isObjectWithKeys(value, ["version", "algorithm", "iterations", "salt"])) throw invalidBackup();
  const expectedIterations =
    expectedVersion === "openarc.wrap-kdf.v1"
      ? VAULT_WRAP_KDF_ITERATIONS
      : VAULT_BACKUP_KDF_ITERATIONS;
  if (
    value.version !== expectedVersion ||
    value.algorithm !== "PBKDF2-HMAC-SHA-256" ||
    value.iterations !== expectedIterations ||
    typeof value.salt !== "string" ||
    decodeLength(value.salt) !== 16
  ) {
    throw invalidBackup();
  }
  return {
    version: expectedVersion,
    algorithm: value.algorithm,
    iterations: value.iterations,
    salt: value.salt,
  };
}

function parseWrappedKey(value: unknown): WrappedKey {
  if (!isObjectWithKeys(value, ["algorithm", "ciphertext"])) throw invalidBackup();
  if (
    value.algorithm !== "AES-KW" ||
    typeof value.ciphertext !== "string" ||
    decodeLength(value.ciphertext) !== 40
  ) {
    throw invalidBackup();
  }
  return { algorithm: value.algorithm, ciphertext: value.ciphertext };
}

async function wrapDataKey(dataKey: CryptoKey, secret: string, kdf: VaultKdf): Promise<WrappedKey> {
  const wrappingKey = await deriveKey(secret, kdf, "AES-KW", ["wrapKey"]);
  const wrapped = await crypto.subtle.wrapKey("raw", dataKey, wrappingKey, "AES-KW");
  return { algorithm: "AES-KW", ciphertext: toBase64Url(new Uint8Array(wrapped)) };
}

async function unwrapDataKey(
  wrapper: WrappedKey,
  secret: string,
  kdf: VaultKdf,
  extractable: boolean,
): Promise<CryptoKey> {
  const wrappingKey = await deriveKey(secret, kdf, "AES-KW", ["unwrapKey"]);
  return crypto.subtle.unwrapKey(
    "raw",
    fromBase64Url(wrapper.ciphertext),
    wrappingKey,
    "AES-KW",
    { name: "AES-GCM", length: 256 },
    extractable,
    ["encrypt", "decrypt"],
  );
}

async function deriveKey(
  secret: string,
  kdf: VaultKdf,
  algorithm: "AES-GCM" | "AES-KW",
  usages: KeyUsage[],
): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", encoder.encode(secret), "PBKDF2", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: fromBase64Url(kdf.salt),
      iterations: kdf.iterations,
    },
    base,
    { name: algorithm, length: 256 },
    false,
    usages,
  );
}

function recordAad(
  meta: PublicVaultMeta,
  recordId: string,
  revision = meta.revision,
): Uint8Array<ArrayBuffer> {
  return encoder.encode(
    `openarc|vault-v1|${meta.vaultId}|${recordId}|${VAULT_RECORD_SCHEMA}|${meta.keyVersion}|${revision}`,
  );
}

function createRecoverySecret(): string {
  return `OA1-${toBase64Url(randomBytes(32))}`;
}

export function createRevision(): string {
  return toBase64Url(randomBytes(24));
}

function backupHeaderAad(
  header: Omit<VaultBackupFile, "ciphertext">,
): Uint8Array<ArrayBuffer> {
  return encoder.encode(canonicalJson(header));
}

function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(length));
}

function uniqueRandomIv(forbiddenIvs: Set<string>): Uint8Array<ArrayBuffer> {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const iv = randomBytes(12);
    const encoded = toBase64Url(iv);
    if (!forbiddenIvs.has(encoded)) {
      forbiddenIvs.add(encoded);
      return iv;
    }
  }
  throw new VaultError("VAULT_CONFLICT", "OpenArc could not create a unique encrypted-record IV.");
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
  if (!BASE64URL.test(value)) throw invalidBackup();
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  let decoded: string;
  try {
    decoded = atob(padded);
  } catch {
    throw invalidBackup();
  }
  const bytes = Uint8Array.from(decoded, (character) => character.charCodeAt(0));
  if (toBase64Url(bytes) !== value) throw invalidBackup();
  return bytes;
}

function decodeLength(value: string): number {
  try {
    return fromBase64Url(value).byteLength;
  } catch {
    return -1;
  }
}

function isObjectWithKeys(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function invalidBackup(): VaultError {
  return new VaultError("INVALID_BACKUP", "The encrypted workspace data is invalid or incompatible.");
}
