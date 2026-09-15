// P08-00 identifier freeze. Every value asserted here is a Private Vault compatibility identifier listed in
// PORT-08 Vault compatibility rules §1.11. A failure means an existing encrypted
// Vault, backup or rescue would stop opening. Do not update an expectation here to make a change pass.
import "fake-indexeddb/auto";

import { readFile } from "node:fs/promises";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";
import type { SentinelRecord, WorkspaceRecord } from "@openarc/shared";

import {
  canonicalJson,
  decryptEncryptedBackup,
  decryptWorkspaceRecord,
  parseBackupFile,
  parseEncryptedEnvelope,
  parsePublicVaultMeta,
  validatePassphrase,
  validateRecoverySecret,
} from "../src/vault/crypto.js";
import { VAULT_DATABASE_NAME } from "../src/vault/db.js";
import {
  createLocalWorkspace,
  exportOpaqueRescue,
  prepareLocalWorkspaceDeletion,
  signalWorkspaceLock,
  unlockLocalWorkspace,
} from "../src/vault/service.js";
import {
  VAULT_BACKUP_KDF_ITERATIONS,
  VAULT_BACKUP_MAGIC,
  VAULT_DATABASE_VERSION,
  VAULT_FORMAT,
  VAULT_FORMAT_VERSION,
  VAULT_KEY_VERSION,
  VAULT_MAX_BACKUP_BYTES,
  VAULT_MAX_RECORDS,
  VAULT_MAX_RESCUE_BYTES,
  VAULT_RECORD_CAPS,
  VAULT_RECORD_SCHEMA,
  VAULT_SCHEMA_VERSION,
  VAULT_WRAP_KDF_ITERATIONS,
  type EncryptedEnvelope,
  type LogicalBackupArchive,
  type OpaqueVaultRescue,
  type PublicVaultMeta,
  type VaultBackupFile,
} from "../src/vault/types.js";
import {
  VAULT_COMPAT_FILES,
  deleteIndexedDb,
  readFixtureJson,
  readFixtureText,
  readIndexedDbImage,
  readManifest,
  seedIndexedDbImage,
  sha256Hex,
  storeRows,
  type IndexedDbImage,
} from "./vault-compat/fixture-io.js";
import {
  fromB64u,
  referenceBackupAad,
  referenceCanonicalJson,
  referenceDecryptBackup,
  referenceDecryptEnvelope,
  referenceEncryptBackup,
  referenceRecordAad,
  referenceUnwrapDataKey,
  toB64u,
} from "./vault-compat/reference-codec.js";

const rule = (item: number, identifier: string) =>
  `COMPAT RULE PORT-08 Vault compatibility rules §1.11 item ${item}: ${identifier} is a frozen Private Vault ` +
  "identifier. Changing it makes existing encrypted Vaults, backups or rescues unreadable. Keep it byte-for-byte and add " +
  "an additive dual-read instead (P08-01)";

const manifest = await readManifest();
const snapshot = await readFixtureJson<IndexedDbImage>(VAULT_COMPAT_FILES.snapshot);
const expectedRecords = await readFixtureJson<WorkspaceRecord[]>(VAULT_COMPAT_FILES.expectedRecords);
const backup = JSON.parse(await readFixtureText(VAULT_COMPAT_FILES.encryptedBackup)) as VaultBackupFile;
const logicalBackup = await readFixtureJson<LogicalBackupArchive>(VAULT_COMPAT_FILES.logicalBackup);
const rescue = await readFixtureJson<OpaqueVaultRescue>(VAULT_COMPAT_FILES.opaqueRescue);
const meta = storeRows(snapshot, "vaultMeta")[0] as PublicVaultMeta;
const envelopes = storeRows(snapshot, "records") as EncryptedEnvelope[];
const sentinel = expectedRecords.find((record): record is SentinelRecord => record.kind === "sentinel")!;

const META_KEYS = ["coordinationRevision", "databaseVersion", "deletionPending", "format", "formatVersion", "key",
  "keyVersion", "passphraseKdf", "passphraseWrapper", "recoveryKdf", "recoveryWrapper", "revision", "schemaVersion",
  "sentinelRecordId", "vaultId"];
const ENVELOPE_KEYS = ["ciphertext", "id", "iv", "keyVersion", "revision", "schemaVersion"];
const KDF_KEYS = ["algorithm", "iterations", "salt", "version"];
const WRAPPED_KEY_KEYS = ["algorithm", "ciphertext"];
const BACKUP_KEYS = ["ciphertext", "iv", "kdf", "magic", "version"];
const LOGICAL_KEYS = ["exportedAt", "format", "formatVersion", "records"];
const RESCUE_KEYS = ["exportedAt", "magic", "records", "vaultMeta", "version", "warning"];
const keys = (value: unknown) => Object.keys(value as object).sort();
const byteLength = (value: string) => fromB64u(value).byteLength;

/** Runs a src operation that must succeed; a thrown error is re-raised with the compatibility rule attached. */
async function mustSucceed<T>(message: string, run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    const detail = error instanceof Error ? `${error.name}${"code" in error ? ` ${String(error.code)}` : ""}: ${error.message}` : String(error);
    throw new Error(`${message} [src operation failed: ${detail}]`, { cause: error });
  }
}

afterEach(async () => {
  await deleteIndexedDb(VAULT_DATABASE_NAME);
});

describe("P08-00 Private Vault identifier freeze", { timeout: 60_000 }, () => {
  it("item 1: database name, version, store names, key paths and the meta row key", async () => {
    expect(VAULT_DATABASE_NAME, rule(1, "IndexedDB database name")).toBe("openarc-vault");
    expect(VAULT_DATABASE_VERSION, rule(1, "IndexedDB database version")).toBe(1);
    await mustSucceed(rule(1, "IndexedDB layout"), () => createLocalWorkspace("TEST-ONLY identifier freeze passphrase"));
    const created = await readIndexedDbImage("openarc-vault");
    for (const image of [created!, snapshot]) {
      expect(image.database, rule(1, "IndexedDB database name/version")).toEqual({ name: "openarc-vault", version: 1 });
      expect(image.stores.map(({ name, keyPath, autoIncrement }) => ({ name, keyPath, autoIncrement })),
        rule(1, "IndexedDB store names and keyPaths (vaultMeta/key, records/id)"))
        .toEqual([{ name: "records", keyPath: "id", autoIncrement: false }, { name: "vaultMeta", keyPath: "key", autoIncrement: false }]);
      expect(storeRows(image, "vaultMeta").map((row) => (row as { key: string }).key), rule(1, 'meta row key "active"')).toEqual(["active"]);
    }
  });

  it("item 2: format and version literals", () => {
    expect({ VAULT_FORMAT, VAULT_FORMAT_VERSION, VAULT_DATABASE_VERSION, VAULT_SCHEMA_VERSION, VAULT_KEY_VERSION, VAULT_RECORD_SCHEMA },
      rule(2, "openarc.encrypted-vault and its version literals"))
      .toEqual({ VAULT_FORMAT: "openarc.encrypted-vault", VAULT_FORMAT_VERSION: 1, VAULT_DATABASE_VERSION: 1,
        VAULT_SCHEMA_VERSION: 1, VAULT_KEY_VERSION: 1, VAULT_RECORD_SCHEMA: 1 });
    expect({ key: meta.key, format: meta.format, formatVersion: meta.formatVersion, databaseVersion: meta.databaseVersion,
      schemaVersion: meta.schemaVersion, keyVersion: meta.keyVersion }, rule(2, "stored metadata literals"))
      .toEqual({ key: "active", format: "openarc.encrypted-vault", formatVersion: 1, databaseVersion: 1, schemaVersion: 1, keyVersion: 1 });
    for (const envelope of envelopes) {
      expect([envelope.keyVersion, envelope.schemaVersion], rule(2, "envelope keyVersion/schemaVersion")).toEqual([1, 1]);
    }
    for (const version of ["formatVersion", "databaseVersion", "schemaVersion", "keyVersion"] as const) {
      expect(() => parsePublicVaultMeta({ ...meta, [version]: 2 }), rule(2, `metadata ${version} === 1`)).toThrow();
    }
    expect(() => parsePublicVaultMeta({ ...meta, format: "openarc.encrypted-vault.v2" }), rule(2, "metadata format")).toThrow();
    expect(() => parseEncryptedEnvelope({ ...envelopes[0], schemaVersion: 2 }), rule(2, "envelope schemaVersion")).toThrow();
    expect(() => parseEncryptedEnvelope({ ...envelopes[0], keyVersion: 2 }), rule(2, "envelope keyVersion")).toThrow();
  });

  it("item 3: exact key sets of metadata, envelope, KDF, wrapped key, backup, logical archive and rescue", async () => {
    expect(keys(meta), rule(3, "PublicVaultMeta 15-key set")).toEqual(META_KEYS);
    for (const envelope of envelopes) expect(keys(envelope), rule(3, "EncryptedEnvelope 6-key set")).toEqual(ENVELOPE_KEYS);
    for (const kdf of [meta.passphraseKdf, meta.recoveryKdf, backup.kdf]) expect(keys(kdf), rule(3, "KDF 4-key set")).toEqual(KDF_KEYS);
    for (const wrapper of [meta.passphraseWrapper, meta.recoveryWrapper]) {
      expect(keys(wrapper), rule(3, "wrapped key 2-key set")).toEqual(WRAPPED_KEY_KEYS);
    }
    expect(keys(backup), rule(3, "encrypted backup file 5-key set")).toEqual(BACKUP_KEYS);
    expect(keys(logicalBackup), rule(3, "logical archive 4-key set")).toEqual(LOGICAL_KEYS);
    expect(keys(rescue), rule(3, "opaque rescue 6-key set")).toEqual(RESCUE_KEYS);
    await seedIndexedDbImage(snapshot);
    expect(keys(await mustSucceed(rule(3, "opaque rescue"), () => exportOpaqueRescue())), rule(3, "opaque rescue 6-key set (current writer)")).toEqual(RESCUE_KEYS);

    const withExtra = (value: object) => ({ ...value, p08Extra: true });
    const without = (value: object, key: string) => Object.fromEntries(Object.entries(value).filter(([name]) => name !== key));
    expect(() => parsePublicVaultMeta(withExtra(meta)), rule(3, "PublicVaultMeta rejects an added key")).toThrow();
    expect(() => parsePublicVaultMeta(without(meta, "sentinelRecordId")), rule(3, "PublicVaultMeta rejects a missing key")).toThrow();
    expect(() => parsePublicVaultMeta({ ...meta, passphraseKdf: withExtra(meta.passphraseKdf) }), rule(3, "KDF rejects an added key")).toThrow();
    expect(() => parsePublicVaultMeta({ ...meta, recoveryWrapper: withExtra(meta.recoveryWrapper) }), rule(3, "wrapped key rejects an added key")).toThrow();
    expect(() => parseEncryptedEnvelope(withExtra(envelopes[0]!)), rule(3, "EncryptedEnvelope rejects an added key")).toThrow();
    expect(() => parseEncryptedEnvelope(without(envelopes[0]!, "revision")), rule(3, "EncryptedEnvelope rejects a missing key")).toThrow();
    expect(() => parseBackupFile(withExtra(backup)), rule(3, "backup file rejects an added key")).toThrow();
    expect(() => parseBackupFile(without(backup, "iv")), rule(3, "backup file rejects a missing key")).toThrow();
    // The logical archive is only reachable through decryption; a reference-encrypted archive with one added key must fail.
    const iv = toB64u(new TextEncoder().encode("P08EXTRAKEY!"));
    const control = await referenceEncryptBackup(logicalBackup, manifest.secrets.backupPassphrase, backup.kdf.salt, iv);
    expect(await mustSucceed(rule(3, "logical archive key set (control)"), () => decryptEncryptedBackup(control, manifest.secrets.backupPassphrase)))
      .toMatchObject({ archive: logicalBackup });
    const extra = await referenceEncryptBackup(withExtra(logicalBackup), manifest.secrets.backupPassphrase, backup.kdf.salt, iv);
    await expect(decryptEncryptedBackup(extra, manifest.secrets.backupPassphrase), rule(3, "logical archive rejects an added key"))
      .rejects.toMatchObject({ code: "INVALID_BACKUP" });
  });

  it("item 4: KDF ids, PBKDF2-HMAC-SHA-256, exactly 600000 iterations, salt, IV and wrap sizes", () => {
    expect([VAULT_WRAP_KDF_ITERATIONS, VAULT_BACKUP_KDF_ITERATIONS], rule(4, "600000 PBKDF2 iterations")).toEqual([600_000, 600_000]);
    for (const [kdf, version] of [[meta.passphraseKdf, "openarc.wrap-kdf.v1"], [meta.recoveryKdf, "openarc.wrap-kdf.v1"],
      [backup.kdf, "openarc.backup-kdf.v1"]] as const) {
      expect({ ...kdf, salt: byteLength(kdf.salt) }, rule(4, `${version} KDF object (16-byte salt)`))
        .toEqual({ version, algorithm: "PBKDF2-HMAC-SHA-256", iterations: 600_000, salt: 16 });
    }
    for (const wrapper of [meta.passphraseWrapper, meta.recoveryWrapper]) {
      expect([wrapper.algorithm, byteLength(wrapper.ciphertext)], rule(4, "AES-KW 40-byte wrapped data key")).toEqual(["AES-KW", 40]);
    }
    for (const envelope of envelopes) {
      expect([byteLength(envelope.iv), byteLength(envelope.revision)], rule(4, "12-byte AES-GCM IV and 24-byte revision")).toEqual([12, 24]);
    }
    expect([byteLength(meta.revision), byteLength(meta.coordinationRevision), byteLength(backup.iv)],
      rule(4, "24-byte revisions and 12-byte backup IV")).toEqual([24, 24, 12]);
    // Iterations are an equality check, not a minimum: both neighbours must be refused.
    for (const iterations of [599_999, 600_001, 1_200_000]) {
      expect(() => parsePublicVaultMeta({ ...meta, passphraseKdf: { ...meta.passphraseKdf, iterations } }),
        rule(4, `wrap KDF iterations === 600000 (got ${iterations})`)).toThrow();
      expect(() => parseBackupFile({ ...backup, kdf: { ...backup.kdf, iterations } }),
        rule(4, `backup KDF iterations === 600000 (got ${iterations})`)).toThrow();
    }
    expect(() => parsePublicVaultMeta({ ...meta, passphraseKdf: { ...meta.passphraseKdf, algorithm: "PBKDF2-HMAC-SHA-512" } }),
      rule(4, "PBKDF2-HMAC-SHA-256")).toThrow();
    expect(() => parsePublicVaultMeta({ ...meta, passphraseKdf: { ...meta.passphraseKdf, version: "openarc.backup-kdf.v1" } }),
      rule(4, "openarc.wrap-kdf.v1 for wrappers")).toThrow();
    expect(() => parseBackupFile({ ...backup, kdf: { ...backup.kdf, version: "openarc.wrap-kdf.v1" } }),
      rule(4, "openarc.backup-kdf.v1 for backups")).toThrow();
    expect(() => parsePublicVaultMeta({ ...meta, passphraseKdf: { ...meta.passphraseKdf, salt: toB64u(new Uint8Array(15)) } }),
      rule(4, "16-byte salt")).toThrow();
    expect(() => parseEncryptedEnvelope({ ...envelopes[0], iv: toB64u(new Uint8Array(16)) }), rule(4, "12-byte IV")).toThrow();
    expect(() => parsePublicVaultMeta({ ...meta, passphraseWrapper: { algorithm: "AES-KW", ciphertext: toB64u(new Uint8Array(48)) } }),
      rule(4, "40-byte AES-KW wrap")).toThrow();
  });

  it("item 5: record AAD template, backup AAD, canonical JSON, AES-GCM-256 with 128-bit tag (independent reference decoder)", async () => {
    expect(canonicalJson({ b: 1, a: [{ d: null, c: "x" }, 2], é: true }), rule(5, "canonicalJson recursive key sort"))
      .toBe('{"a":[{"c":"x","d":null},2],"b":1,"é":true}');
    expect(referenceRecordAad(meta.vaultId, envelopes[0]!.id, envelopes[0]!.revision), rule(5, "record AAD template"))
      .toBe(`openarc|vault-v1|${meta.vaultId}|${envelopes[0]!.id}|1|1|${envelopes[0]!.revision}`);
    const expectedById = new Map(expectedRecords.map((record) => [record.recordId, record]));
    for (const [secret, wrapper, kdf] of [[manifest.secrets.workspacePassphrase, meta.passphraseWrapper, meta.passphraseKdf],
      [manifest.secrets.recoverySecret, meta.recoveryWrapper, meta.recoveryKdf]] as const) {
      const key = await referenceUnwrapDataKey(wrapper.ciphertext, secret, kdf.salt);
      for (const envelope of envelopes) {
        const plaintext = await referenceDecryptEnvelope(key, meta.vaultId, envelope);
        const expected = expectedById.get(envelope.id);
        expect(plaintext, rule(5, `AES-GCM record plaintext = canonicalJson(record) under the record AAD (${envelope.id})`))
          .toBe(referenceCanonicalJson(expected));
        expect(canonicalJson(expected), rule(5, "src canonicalJson equals the reference canonical JSON")).toBe(plaintext);
      }
      for (const envelope of envelopes) {
        expect(await mustSucceed(rule(5, `src decrypts frozen envelope ${envelope.id} under the v1 record AAD, AES-GCM-256 and PBKDF2 600000`),
          () => decryptWorkspaceRecord(meta, key, envelope)), rule(5, `src plaintext of ${envelope.id}`)).toEqual(expectedById.get(envelope.id));
      }
      await expect(referenceDecryptEnvelope(key, meta.vaultId, envelopes[0]!,
        `openarc|vault-v2|${meta.vaultId}|${envelopes[0]!.id}|1|1|${envelopes[0]!.revision}`), rule(5, "AAD binds vault-v1")).rejects.toThrow();
      await expect(referenceDecryptEnvelope(key, meta.vaultId, envelopes[0]!,
        referenceRecordAad(meta.vaultId, envelopes[1]!.id, envelopes[0]!.revision)), rule(5, "AAD binds the record id")).rejects.toThrow();
    }
    const header = referenceBackupAad(backup);
    expect(header, rule(5, "backup AAD = canonicalJson({magic, version, kdf, iv})")).toBe(
      `{"iv":"${backup.iv}","kdf":{"algorithm":"PBKDF2-HMAC-SHA-256","iterations":600000,"salt":"${backup.kdf.salt}",` +
      `"version":"openarc.backup-kdf.v1"},"magic":"OPENARC-ENCRYPTED-BACKUP","version":1}`);
    const archivePlaintext = await referenceDecryptBackup(backup, manifest.secrets.backupPassphrase);
    expect(archivePlaintext, rule(5, "backup plaintext = canonicalJson(logical archive)")).toBe(referenceCanonicalJson(logicalBackup));
    expect((await mustSucceed(rule(5, "src decrypts the frozen backup under the backup AAD"),
      () => decryptEncryptedBackup(backup, manifest.secrets.backupPassphrase))).archive, rule(5, "src backup plaintext")).toEqual(logicalBackup);
    await expect(referenceDecryptBackup(backup, manifest.secrets.backupPassphrase, header.replace('"version":1}', '"version":2}')),
      rule(5, "backup AAD binds the header")).rejects.toThrow();
  });

  it("item 6: sentinel marker, manifest digest rule, manifest max and total record cap", async () => {
    await seedIndexedDbImage(snapshot);
    await mustSucceed(rule(6, "sentinel manifest verification on unlock"), () => unlockLocalWorkspace(meta, manifest.secrets.workspacePassphrase));
    expect({ kind: sentinel.kind, recordSchema: sentinel.recordSchema, marker: sentinel.marker, recordId: sentinel.recordId,
      vaultRevision: sentinel.vaultRevision, recordRevision: sentinel.recordRevision }, rule(6, "OPENARC_VAULT_SENTINEL_V1 sentinel"))
      .toEqual({ kind: "sentinel", recordSchema: "openarc.workspace-record.v1", marker: "OPENARC_VAULT_SENTINEL_V1",
        recordId: meta.sentinelRecordId, vaultRevision: meta.revision, recordRevision: meta.revision });
    const manifestEntries = envelopes.filter((envelope) => envelope.id !== meta.sentinelRecordId)
      .sort((left, right) => left.id.localeCompare(right.id))
      .map((envelope) => ({ recordId: envelope.id, revision: envelope.revision,
        digest: `sha256:${sha256Hex(referenceCanonicalJson(envelope))}` }));
    expect(sentinel.manifest, rule(6, 'manifest digest = "sha256:" + hex(sha256(canonicalJson(envelope))), sorted by record id'))
      .toEqual(manifestEntries);
    expect(VAULT_MAX_RECORDS, rule(6, "VAULT_MAX_RECORDS 6602")).toBe(6_602);
    expect(VAULT_RECORD_CAPS, rule(6, "per-kind record caps")).toEqual({ agent_profile: 100, monitoring_policy: 500,
      evidence_record: 5_000, action_envelope: 1_000, permission_receipt: 1_000, arc_observation: 1_000,
      agent_registry_observation: 1_000, job_observation: 1_000, x402_bundle: 1_000, gateway_observation: 1_000,
      agent_import: 32, agent_monitoring_policy: 100, workspace_settings: 1, sentinel: 1 });
    expect(Object.isFrozen(VAULT_RECORD_CAPS)).toBe(true);
  });

  it("item 7: backup, logical and rescue magics, versions, warning literal, 2/32/64 MiB caps", async () => {
    expect([VAULT_BACKUP_MAGIC, backup.magic, backup.version], rule(7, "OPENARC-ENCRYPTED-BACKUP v1")).toEqual(["OPENARC-ENCRYPTED-BACKUP", "OPENARC-ENCRYPTED-BACKUP", 1]);
    expect([logicalBackup.format, logicalBackup.formatVersion], rule(7, "openarc.logical-backup v1")).toEqual(["openarc.logical-backup", 1]);
    expect(logicalBackup.records.some((record) => record.kind === "sentinel"), rule(7, "logical backup excludes the sentinel")).toBe(false);
    await seedIndexedDbImage(snapshot);
    for (const value of [rescue, await mustSucceed(rule(7, "opaque rescue export"), () => exportOpaqueRescue())]) {
      expect([value.magic, value.version, value.warning], rule(7, "OPENARC-OPAQUE-RESCUE v1 and warning literal"))
        .toEqual(["OPENARC-OPAQUE-RESCUE", 1, "ENCRYPTED_RESCUE_NOT_IMPORTABLE_BY_THIS_BUILD"]);
    }
    expect([VAULT_MAX_BACKUP_BYTES, VAULT_MAX_RESCUE_BYTES], rule(7, "32 MiB backup and 64 MiB rescue caps")).toEqual([33_554_432, 67_108_864]);
    expect(() => parseBackupFile({ ...backup, magic: "OPENARC-ENCRYPTED-BACKUP-V2" }), rule(7, "backup magic")).toThrow();
    expect(() => parseBackupFile({ ...backup, version: 2 }), rule(7, "backup version")).toThrow();
    const recordLimit = Math.ceil((2 * 1024 * 1024 * 4) / 3);
    expect(() => parseEncryptedEnvelope({ ...envelopes[0], ciphertext: "A".repeat(recordLimit) }), rule(7, "2 MiB record ciphertext bound (accepted at the limit)")).not.toThrow();
    expect(() => parseEncryptedEnvelope({ ...envelopes[0], ciphertext: "A".repeat(recordLimit + 1) }), rule(7, "2 MiB record ciphertext bound")).toThrow();
    const backupLimit = Math.ceil((32 * 1024 * 1024 * 4) / 3);
    expect(() => parseBackupFile({ ...backup, ciphertext: "A".repeat(backupLimit) }), rule(7, "32 MiB backup ciphertext bound (accepted at the limit)")).not.toThrow();
    expect(() => parseBackupFile({ ...backup, ciphertext: "A".repeat(backupLimit + 1) }), rule(7, "32 MiB backup ciphertext bound")).toThrow();
  });

  it("item 8: recovery secret format and passphrase normalization rules", async () => {
    const created = await mustSucceed(rule(8, "new Vault creation"), () => createLocalWorkspace("TEST-ONLY identifier writer passphrase"));
    expect(created.recoverySecret, rule(8, "newly written recovery secret OA1- + 43 base64url characters")).toMatch(/^OA1-[A-Za-z0-9_-]{43}$/u);
    expect(byteLength(created.recoverySecret.slice(4)), rule(8, "newly written recovery secret encodes 32 bytes")).toBe(32);
    expect(keys(created.meta), rule(3, "newly written PublicVaultMeta 15-key set")).toEqual(META_KEYS);
    for (const kdf of [created.meta.passphraseKdf, created.meta.recoveryKdf]) {
      expect({ ...kdf, salt: byteLength(kdf.salt) }, rule(4, "newly written wrap KDF object"))
        .toEqual({ version: "openarc.wrap-kdf.v1", algorithm: "PBKDF2-HMAC-SHA-256", iterations: 600_000, salt: 16 });
    }
    const secret = manifest.secrets.recoverySecret;
    expect(secret, rule(8, "recovery secret OA1- + 43 base64url characters")).toMatch(/^OA1-[A-Za-z0-9_-]{43}$/u);
    expect(byteLength(secret.slice(4)), rule(8, "recovery secret encodes 32 bytes")).toBe(32);
    expect(() => validateRecoverySecret(secret), rule(8, "frozen recovery secret accepted")).not.toThrow();
    for (const invalid of [`OA1-${secret.slice(4, -1)}`, `${secret}A`, `OA2-${secret.slice(4)}`, `oa1-${secret.slice(4)}`, secret.slice(4)]) {
      expect(() => validateRecoverySecret(invalid), rule(8, `recovery secret format rejects ${invalid.length}-char variant`)).toThrow();
    }
    expect(validatePassphrase("Café passphrase!"), rule(8, "NFC passphrase normalization")).toBe("Café passphrase!");
    expect(() => validatePassphrase(manifest.secrets.workspacePassphrase), rule(8, "frozen passphrase accepted")).not.toThrow();
    expect(validatePassphrase("a".repeat(12)), rule(8, "12 code point minimum")).toBe("a".repeat(12));
    expect(() => validatePassphrase("a".repeat(11)), rule(8, "12 code point minimum")).toThrow();
    expect(validatePassphrase("\u{1F512}".repeat(128)), rule(8, "128 code points / 512 bytes maximum")).toBe("\u{1F512}".repeat(128));
    expect(() => validatePassphrase("a".repeat(129)), rule(8, "128 code point maximum")).toThrow();
    for (const invalid of [" leading passphrase", "trailing passphrase ", "controlpassphrase", "deletepassphrase"]) {
      expect(() => validatePassphrase(invalid), rule(8, "no edge whitespace or control characters")).toThrow();
    }
  });

  it("item 9: recordSchema literal of every stored kind (see also packages/shared/test/vault-compat-literals.test.ts)", () => {
    const table = [...new Set(expectedRecords.map((record) => `${record.kind}=${record.recordSchema}`))].sort();
    expect(table, rule(9, "kind -> recordSchema literal table")).toEqual([
      "action_envelope=openarc.workspace-record.v1",
      "agent_import=openarc.agent-import-record.v1",
      "agent_monitoring_policy=openarc.agent-policy-record.v2",
      "agent_profile=openarc.workspace-record.v1",
      "agent_registry_observation=openarc.agent-registry-observation-record.v1",
      "arc_observation=openarc.arc-observation-record.v1",
      "evidence_record=openarc.workspace-record.v1",
      "gateway_observation=openarc.gateway-observation-record.v1",
      "job_observation=openarc.job-observation-record.v1",
      "monitoring_policy=openarc.workspace-record.v1",
      "permission_receipt=openarc.permission-receipt.v1",
      "permission_receipt=openarc.permission-receipt.v2",
      "permission_receipt=openarc.permission-receipt.v3",
      "permission_receipt=openarc.permission-receipt.v4",
      "permission_receipt=openarc.permission-receipt.v5",
      "sentinel=openarc.workspace-record.v1",
      "workspace_settings=openarc.workspace-record.v1",
      "x402_bundle=openarc.x402-bundle-record.v1",
    ]);
  });

  it("item 10: BroadcastChannel name and coordination message shape", async () => {
    // The channel name, message shape and predicate live in coordination.ts
    // (extracted verbatim from VaultWorkspace.tsx by P08-02). Every Vault
    // BroadcastChannel must be built from that single frozen constant, and every
    // writer must post the frozen message shape.
    const vaultDir = path.resolve(import.meta.dirname, "../src/vault");
    const coordination = await readFile(path.join(vaultDir, "coordination.ts"), "utf8");
    expect(coordination, rule(10, "BroadcastChannel name openarc-vault-coordination-v1")).toContain(
      'export const VAULT_COORDINATION_CHANNEL = "openarc-vault-coordination-v1";');
    expect(coordination.match(/openarc-vault-coordination/gu)?.length, rule(10, "exactly one channel name literal")).toBe(1);
    expect(coordination.replace(/\s+/gu, " "), rule(10, 'message {sender, type: "changed"|"lock"|"deleting", vaultId}'))
      .toContain('type CoordinationMessage = { sender: string; type: "changed" | "lock" | "deleting"; vaultId: string; };');
    expect(coordination, rule(10, "coordination message predicate")).toContain(
      'typeof candidate.sender === "string" && typeof candidate.vaultId === "string" && (candidate.type === "changed" || candidate.type === "lock" || candidate.type === "deleting")');
    const { readdir } = await import("node:fs/promises");
    const constructions: string[] = [];
    for (const file of (await readdir(vaultDir)).filter((name) => /\.tsx?$/u.test(name))) {
      const source = await readFile(path.join(vaultDir, file), "utf8");
      for (const match of source.matchAll(/new BroadcastChannel\(([^)]*)\)/gu)) constructions.push(`${file}:${match[1]}`);
      expect(source.includes("openarc-vault-coordination") && file !== "coordination.ts", rule(10, `no duplicate channel literal in ${file}`)).toBe(false);
    }
    expect(constructions.length, rule(10, "at least one Vault coordination channel")).toBeGreaterThan(0);
    for (const construction of constructions) {
      expect(construction.split(":")[1], rule(10, `channel built from the frozen constant (${construction})`)).toBe("VAULT_COORDINATION_CHANNEL");
    }
    const workspace = await readFile(path.join(vaultDir, "VaultWorkspace.tsx"), "utf8");
    expect(workspace, rule(10, "coordination message writer")).toContain(
      "channelRef.current?.postMessage({ sender: senderRef.current, type, vaultId } satisfies CoordinationMessage)");
    const bridge = await readFile(path.join(vaultDir, "session-bridge.ts"), "utf8");
    expect(bridge, rule(10, "session-end lock writer")).toContain(
      'channel.postMessage({ sender: crypto.randomUUID(), type: "lock", vaultId } satisfies CoordinationMessage)');
  });

  it("item 11: lock rotates only coordinationRevision and deletion sets the deletionPending marker", async () => {
    await seedIndexedDbImage(snapshot);
    const locked = await mustSucceed(rule(11, "lock signal"), () => signalWorkspaceLock(meta));
    expect({ ...locked, coordinationRevision: meta.coordinationRevision }, rule(11, "lock writes only coordinationRevision")).toEqual(meta);
    expect(locked.coordinationRevision).not.toBe(meta.coordinationRevision);
    await expect(unlockLocalWorkspace(meta, manifest.secrets.workspacePassphrase), rule(11, "CAS on coordinationRevision"))
      .rejects.toMatchObject({ code: "VAULT_CONFLICT" });
    expect(await mustSucceed(rule(11, "unlock after lock"), () => unlockLocalWorkspace(locked, manifest.secrets.workspacePassphrase)))
      .toMatchObject({ meta: locked });
    const deleting = await mustSucceed(rule(11, "deletion marker"), () => prepareLocalWorkspaceDeletion(locked));
    expect({ ...deleting, coordinationRevision: locked.coordinationRevision }, rule(11, "deletionPending marker"))
      .toEqual({ ...locked, deletionPending: true });
    await expect(unlockLocalWorkspace(deleting, manifest.secrets.workspacePassphrase), rule(11, "deletionPending blocks unlock"))
      .rejects.toMatchObject({ code: "VAULT_CONFLICT" });
  });
});
