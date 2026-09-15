// P08-00: an INDEPENDENT reference codec for the frozen Vault v1 formats, written from the documented
// compatibility identifiers only (port08 gap doc §1.3, §1.4, §1.8, §1.11). It deliberately shares no code
// with apps/web/src/vault so that a silent change in src cannot also change what the tests expect.
// Test-only; never imported by runtime code.

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export const REFERENCE_PBKDF2_ITERATIONS = 600_000;
export const REFERENCE_BACKUP_MAGIC = "OPENARC-ENCRYPTED-BACKUP";

/** Recursively key-sorted JSON; arrays keep order. */
export function referenceCanonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(referenceCanonicalJson).join(",")}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${referenceCanonicalJson(object[key])}`).join(",")}}`;
}

export function fromB64u(value: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(Buffer.from(value, "base64url"));
}

export function toB64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export function referenceRecordAad(vaultId: string, recordId: string, revision: string): string {
  return `openarc|vault-v1|${vaultId}|${recordId}|1|1|${revision}`;
}

export interface ReferenceBackupHeader {
  magic: string;
  version: number;
  kdf: { version: string; algorithm: string; iterations: number; salt: string };
  iv: string;
}

export function referenceBackupAad(header: ReferenceBackupHeader): string {
  return referenceCanonicalJson({ magic: header.magic, version: header.version, kdf: header.kdf, iv: header.iv });
}

export async function referencePbkdf2Key(secret: string, salt: string, algorithm: "AES-KW" | "AES-GCM",
  usages: KeyUsage[]): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", encoder.encode(secret.normalize("NFC")), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: fromB64u(salt), iterations: REFERENCE_PBKDF2_ITERATIONS },
    base, { name: algorithm, length: 256 }, false, usages);
}

export async function referenceUnwrapDataKey(wrapperCiphertext: string, secret: string, salt: string): Promise<CryptoKey> {
  const kek = await referencePbkdf2Key(secret, salt, "AES-KW", ["unwrapKey"]);
  return crypto.subtle.unwrapKey("raw", fromB64u(wrapperCiphertext), kek, "AES-KW", { name: "AES-GCM", length: 256 },
    false, ["encrypt", "decrypt"]);
}

export interface ReferenceEnvelope {
  id: string;
  iv: string;
  keyVersion: 1;
  schemaVersion: 1;
  revision: string;
  ciphertext: string;
}

export async function referenceDecryptEnvelope(key: CryptoKey, vaultId: string,
  envelope: Pick<ReferenceEnvelope, "id" | "iv" | "revision" | "ciphertext">,
  aad = referenceRecordAad(vaultId, envelope.id, envelope.revision)): Promise<string> {
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64u(envelope.iv), tagLength: 128,
    additionalData: encoder.encode(aad) }, key, fromB64u(envelope.ciphertext));
  return decoder.decode(plaintext);
}

export async function referenceEncryptEnvelope(key: CryptoKey, vaultId: string, record: { recordId: string },
  revision: string, iv: string): Promise<ReferenceEnvelope> {
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: fromB64u(iv), tagLength: 128,
    additionalData: encoder.encode(referenceRecordAad(vaultId, record.recordId, revision)) },
  key, encoder.encode(referenceCanonicalJson(record)));
  return { id: record.recordId, iv, keyVersion: 1, schemaVersion: 1, revision,
    ciphertext: toB64u(new Uint8Array(ciphertext)) };
}

export async function referenceEncryptBackup(archive: unknown, passphrase: string, salt: string, iv: string) {
  const header: ReferenceBackupHeader = { magic: REFERENCE_BACKUP_MAGIC, version: 1,
    kdf: { version: "openarc.backup-kdf.v1", algorithm: "PBKDF2-HMAC-SHA-256", iterations: REFERENCE_PBKDF2_ITERATIONS, salt }, iv };
  const key = await referencePbkdf2Key(passphrase, salt, "AES-GCM", ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: fromB64u(iv), tagLength: 128,
    additionalData: encoder.encode(referenceBackupAad(header)) }, key, encoder.encode(referenceCanonicalJson(archive)));
  return { ...header, ciphertext: toB64u(new Uint8Array(ciphertext)) };
}

export async function referenceDecryptBackup(backup: ReferenceBackupHeader & { ciphertext: string },
  passphrase: string, aad = referenceBackupAad(backup)): Promise<string> {
  const key = await referencePbkdf2Key(passphrase, backup.kdf.salt, "AES-GCM", ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64u(backup.iv), tagLength: 128,
    additionalData: encoder.encode(aad) }, key, fromB64u(backup.ciphertext));
  return decoder.decode(plaintext);
}
