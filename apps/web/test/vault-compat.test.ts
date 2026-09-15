// P08-00 Vault compatibility freeze: the CURRENT reader against FROZEN golden fixtures.
// Fixtures were produced once by integration build 0f5caa9 (see test/vault-compat/generate-fixtures.ts)
// and are only ever read here. If a test in this file fails, the reader regressed: fix the reader.
import "fake-indexeddb/auto";

import { readFile } from "node:fs/promises";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";
import type { WorkspaceRecord } from "@openarc/shared";

import { decryptEncryptedBackup } from "../src/vault/crypto.js";
import { VAULT_DATABASE_NAME, readVaultMeta } from "../src/vault/db.js";
import {
  assertWorkspaceIntegrity,
  deleteWorkspaceRecords,
  destroyLocalWorkspace,
  exportLocalWorkspace,
  exportOpaqueRescue,
  importLocalWorkspace,
  parseBackupFile,
  recoverLocalWorkspace,
  unlockLocalWorkspace,
  updateWorkspacePassphrase,
} from "../src/vault/service.js";
import type { LogicalBackupArchive, OpaqueVaultRescue, PublicVaultMeta } from "../src/vault/types.js";
import {
  VAULT_COMPAT_FILES,
  VAULT_COMPAT_FIXTURE_DIR,
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

const FROZEN = "COMPAT RULE P08-00 (PORT-08 Vault compatibility rules §2.1 and §1.11): Vault data written by " +
  "integration build 0f5caa9 must stay unlockable, importable, recoverable and rescuable by every later build. " +
  "Fix the reader; never edit or regenerate the frozen fixture";
const NEW_PASSPHRASE = "TEST-ONLY replacement passphrase";

const manifest = await readManifest();
const secrets = manifest.secrets;
const snapshot = await readFixtureJson<IndexedDbImage>(VAULT_COMPAT_FILES.snapshot);
const expectedRecords = await readFixtureJson<WorkspaceRecord[]>(VAULT_COMPAT_FILES.expectedRecords);
const logicalBackup = await readFixtureJson<LogicalBackupArchive>(VAULT_COMPAT_FILES.logicalBackup);
const opaqueRescue = await readFixtureJson<OpaqueVaultRescue>(VAULT_COMPAT_FILES.opaqueRescue);
const frozenMeta = storeRows(snapshot, "vaultMeta")[0] as PublicVaultMeta;
const logicalExpected = expectedRecords.filter((record) => record.kind !== "sentinel");

/** Runs a src operation that must succeed on frozen data; a thrown error is re-raised with the compatibility rule. */
async function frozen<T>(label: string, run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    const detail = error instanceof Error ? `${error.name}${"code" in error ? ` ${String(error.code)}` : ""}: ${error.message}` : String(error);
    throw new Error(`${FROZEN} [${label} failed on frozen data: ${detail}]`, { cause: error });
  }
}

async function frozenBackupInput(): Promise<unknown> {
  const text = await readFixtureText(VAULT_COMPAT_FILES.encryptedBackup);
  return frozen("parse frozen backup file", () =>
    parseBackupFile(new File([text], "openarc-workspace-2026-09-15.openarc", { type: "application/json" })));
}

function withoutRevision(record: unknown): unknown {
  return Object.fromEntries(Object.entries(record as Record<string, unknown>).filter(([key]) => key !== "recordRevision"));
}

function expectRecordByRecord(actual: readonly WorkspaceRecord[], expected: readonly WorkspaceRecord[], label: string,
  normalize: (record: unknown) => unknown = (record) => record) {
  const byId = new Map(actual.map((record) => [record.recordId, record]));
  expect([...byId.keys()].sort(), `${FROZEN} [${label}: record identity set]`)
    .toEqual(expected.map((record) => record.recordId).sort());
  for (const record of expected) {
    expect(normalize(byId.get(record.recordId)), `${FROZEN} [${label}: ${record.kind} ${record.recordId}]`)
      .toEqual(normalize(record));
  }
}

async function seedFrozenSnapshot(image: IndexedDbImage = snapshot): Promise<void> {
  await seedIndexedDbImage(image);
}

const unlockFrozen = (meta: PublicVaultMeta, passphrase: string, label: string) =>
  frozen(label, () => unlockLocalWorkspace(meta, passphrase));

afterEach(async () => {
  await deleteIndexedDb(VAULT_DATABASE_NAME);
});

describe("P08-00 frozen Vault fixtures from integration build 0f5caa9", { timeout: 60_000 }, () => {
  it("keeps every frozen fixture byte-identical to its manifest digest", async () => {
    expect(Object.keys(manifest.files).sort(), FROZEN).toEqual(Object.values(VAULT_COMPAT_FILES).sort());
    for (const [name, pinned] of Object.entries(manifest.files)) {
      const bytes = await readFile(path.join(VAULT_COMPAT_FIXTURE_DIR, name));
      expect(bytes.byteLength, `${FROZEN} [${name} size]`).toBe(pinned.bytes);
      expect(sha256Hex(bytes), `${FROZEN} [${name} sha256]`).toBe(pinned.sha256);
    }
  });

  it("covers all 14 record kinds, all five receipt versions and every permitted relationship", () => {
    const ofKind = <K extends WorkspaceRecord["kind"]>(kind: K) =>
      expectedRecords.filter((record): record is Extract<WorkspaceRecord, { kind: K }> => record.kind === kind);
    expect(new Set(expectedRecords.map((record) => record.kind))).toEqual(new Set(["agent_profile", "monitoring_policy",
      "evidence_record", "action_envelope", "workspace_settings", "sentinel", "permission_receipt", "arc_observation",
      "agent_registry_observation", "job_observation", "x402_bundle", "gateway_observation", "agent_import",
      "agent_monitoring_policy"]));
    const receipts = ofKind("permission_receipt");
    expect(new Set(receipts.map((record) => record.recordSchema))).toEqual(new Set(["openarc.permission-receipt.v1",
      "openarc.permission-receipt.v2", "openarc.permission-receipt.v3", "openarc.permission-receipt.v4",
      "openarc.permission-receipt.v5"]));
    expect(new Set(receipts.map((record) => record.outcome))).toEqual(new Set(["approved", "completed", "failed"]));
    const byId = new Map(expectedRecords.map((record) => [record.recordId, record]));
    const agents = ofKind("agent_profile");
    // agent_profile -> monitoring_policy
    expect(agents.some((agent) => agent.policyRecordIds.length > 0 &&
      agent.policyRecordIds.every((id) => byId.get(id)?.kind === "monitoring_policy"))).toBe(true);
    // action_envelope -> agent_profile and evidence_record -> action_envelope
    const action = ofKind("action_envelope")[0]!;
    expect(agents.some((agent) => agent.agentId === action.action.agentId)).toBe(true);
    expect(ofKind("evidence_record").every((record) => record.evidence.actionId === action.action.actionId)).toBe(true);
    // arc_observation -> v2 receipt (account and transaction)
    expect(ofKind("arc_observation").map((record) => byId.get(record.permissionReceiptId))
      .map((receipt) => receipt?.kind === "permission_receipt" ? `${receipt.recordSchema}|${receipt.connectorId}` : null).sort())
      .toEqual(["openarc.permission-receipt.v2|arc_account_snapshot", "openarc.permission-receipt.v2|arc_transaction_evidence"]);
    // agent_registry_observation -> v3 receipt + agent_profile
    const registry = ofKind("agent_registry_observation")[0]!;
    expect(byId.get(registry.permissionReceiptId)).toMatchObject({ recordSchema: "openarc.permission-receipt.v3" });
    expect(byId.get(registry.linkedAgentProfileRecordId ?? "")).toMatchObject({ kind: "agent_profile" });
    // job_observation -> v4 receipt + action_envelope
    const job = ofKind("job_observation")[0]!;
    expect(byId.get(job.permissionReceiptId)).toMatchObject({ recordSchema: "openarc.permission-receipt.v4" });
    expect(byId.get(job.linkedActionRecordId ?? "")).toMatchObject({ kind: "action_envelope" });
    // gateway_observation -> v5 receipt + x402_bundle
    const gateway = ofKind("gateway_observation")[0]!;
    expect(byId.get(gateway.permissionReceiptId)).toMatchObject({ recordSchema: "openarc.permission-receipt.v5" });
    expect(byId.get(gateway.linkedBundleRecordId ?? "")).toMatchObject({ kind: "x402_bundle" });
    // agent_import -> agent_profile and agent_monitoring_policy -> agent_profile
    expect(byId.get(ofKind("agent_import")[0]!.linkedAgentProfileRecordId)).toMatchObject({ kind: "agent_profile" });
    expect(byId.get(ofKind("agent_monitoring_policy")[0]!.policy.agentProfileRecordId)).toMatchObject({ kind: "agent_profile" });
    // Stored envelopes carry more than one revision, as a real multi-save Vault does.
    expect(new Set(storeRows(snapshot, "records").map((row) => (row as { revision: string }).revision)).size).toBeGreaterThan(1);
    expect(() => assertWorkspaceIntegrity(expectedRecords), `${FROZEN} [frozen relationships]`).not.toThrow();
    expect(logicalBackup.records).toEqual(logicalExpected);
    expect(opaqueRescue.vaultMeta).toEqual(frozenMeta);
    expect(opaqueRescue.records).toEqual(storeRows(snapshot, "records"));
  });

  it("reads and unlocks the frozen IndexedDB snapshot record by record without writing", async () => {
    await seedFrozenSnapshot();
    expect(await frozen("readVaultMeta", () => readVaultMeta()), FROZEN).toEqual(frozenMeta);
    const unlocked = await unlockFrozen(frozenMeta, secrets.workspacePassphrase, "unlock frozen snapshot");
    expect(unlocked.meta, FROZEN).toEqual(frozenMeta);
    expectRecordByRecord(unlocked.records, expectedRecords, "unlock");
    expect(await readIndexedDbImage(VAULT_DATABASE_NAME), `${FROZEN} [unlock must not write]`).toEqual(snapshot);
  });

  it("still reports a wrong passphrase on the frozen snapshot as INVALID_PASSPHRASE without writing", async () => {
    await seedFrozenSnapshot();
    await expect(unlockLocalWorkspace(frozenMeta, "TEST-ONLY wrong passphrase"), FROZEN).rejects.toMatchObject({ code: "INVALID_PASSPHRASE" });
    expect(await readIndexedDbImage(VAULT_DATABASE_NAME), FROZEN).toEqual(snapshot);
  });

  it("decrypts the frozen OPENARC-ENCRYPTED-BACKUP v1 file into the frozen logical backup", async () => {
    const input = await frozenBackupInput();
    const { archive, records } = await frozen("decrypt frozen backup", () => decryptEncryptedBackup(input, secrets.backupPassphrase));
    expect(archive, `${FROZEN} [logical backup archive]`).toEqual(logicalBackup);
    expectRecordByRecord(records, logicalExpected, "backup decrypt");
    await expect(decryptEncryptedBackup(input, "TEST-ONLY wrong backup passphrase"), FROZEN)
      .rejects.toMatchObject({ code: "INVALID_BACKUP" });
  });

  it("imports the frozen backup into an empty browser and unlocks the imported Vault", async () => {
    const input = await frozenBackupInput();
    const imported = await frozen("import frozen backup into empty browser", () =>
      importLocalWorkspace(input, secrets.backupPassphrase, NEW_PASSPHRASE, null));
    expect(imported.meta.vaultId).not.toBe(frozenMeta.vaultId);
    expectRecordByRecord(imported.records.filter((record) => record.kind !== "sentinel"), logicalExpected,
      "import into empty", withoutRevision);
    const unlocked = await unlockFrozen(imported.meta, NEW_PASSPHRASE, "unlock after import");
    expectRecordByRecord(unlocked.records, imported.records, "unlock after import");
  });

  it("imports the frozen backup over the frozen snapshot using its exact current revision", async () => {
    await seedFrozenSnapshot();
    const input = await frozenBackupInput();
    const imported = await frozen("import frozen backup over frozen snapshot", () =>
      importLocalWorkspace(input, secrets.backupPassphrase, NEW_PASSPHRASE, frozenMeta));
    expectRecordByRecord(imported.records.filter((record) => record.kind !== "sentinel"), logicalExpected,
      "import replacing snapshot", withoutRevision);
    expect((await readVaultMeta())?.vaultId, FROZEN).toBe(imported.meta.vaultId);
  });

  it("exports a new backup from the frozen snapshot holding the same logical records", async () => {
    await seedFrozenSnapshot();
    const unlocked = await unlockFrozen(frozenMeta, secrets.workspacePassphrase, "unlock frozen snapshot");
    const backup = await frozen("export backup from frozen snapshot", () => exportLocalWorkspace(unlocked, NEW_PASSPHRASE));
    const { archive } = await frozen("decrypt re-exported backup", () => decryptEncryptedBackup(backup, NEW_PASSPHRASE));
    expect([archive.format, archive.formatVersion], FROZEN).toEqual([logicalBackup.format, logicalBackup.formatVersion]);
    expectRecordByRecord(archive.records, logicalExpected, "export from snapshot");
  });

  it("recovers the frozen snapshot with the frozen recovery secret and rotates every secret", async () => {
    await seedFrozenSnapshot();
    const recovered = await frozen("recover frozen snapshot", () =>
      recoverLocalWorkspace(frozenMeta, secrets.recoverySecret, NEW_PASSPHRASE));
    expectRecordByRecord(recovered.records.filter((record) => record.kind !== "sentinel"), logicalExpected, "recovery");
    expect(recovered.recoverySecret).not.toBe(secrets.recoverySecret);
    await expect(unlockLocalWorkspace(recovered.meta, secrets.workspacePassphrase)).rejects.toMatchObject({ code: "INVALID_PASSPHRASE" });
    expectRecordByRecord((await unlockFrozen(recovered.meta, NEW_PASSPHRASE, "unlock after recovery")).records,
      recovered.records, "unlock after recovery");
    await expect(recoverLocalWorkspace(recovered.meta, secrets.recoverySecret, NEW_PASSPHRASE))
      .rejects.toMatchObject({ code: "RECOVERY_FAILED" });
  });

  it("changes the frozen snapshot passphrase, deletes a linked record set and destroys the Vault", async () => {
    await seedFrozenSnapshot();
    const unlocked = await unlockFrozen(frozenMeta, secrets.workspacePassphrase, "unlock frozen snapshot");
    const changed = await frozen("change frozen snapshot passphrase", () =>
      updateWorkspacePassphrase(unlocked, secrets.workspacePassphrase, NEW_PASSPHRASE));
    expectRecordByRecord(changed.records.filter((record) => record.kind !== "sentinel"), logicalExpected, "passphrase change");
    await expect(unlockLocalWorkspace(changed.meta, secrets.workspacePassphrase)).rejects.toMatchObject({ code: "INVALID_PASSPHRASE" });
    const reopened = await unlockFrozen(changed.meta, NEW_PASSPHRASE, "unlock after passphrase change");
    const gateway = expectedRecords.find((record) => record.kind === "gateway_observation");
    if (gateway?.kind !== "gateway_observation") throw new Error(`${FROZEN} [gateway observation missing]`);
    const linkedIds = [gateway.recordId, gateway.permissionReceiptId, gateway.linkedBundleRecordId!];
    const deleted = await frozen("delete linked gateway records", () => deleteWorkspaceRecords(reopened, linkedIds));
    expectRecordByRecord(deleted.records.filter((record) => record.kind !== "sentinel"),
      logicalExpected.filter((record) => !linkedIds.includes(record.recordId)), "linked deletion");
    await frozen("destroy frozen Vault", () => destroyLocalWorkspace());
    expect(await readVaultMeta(), FROZEN).toBeNull();
  });

  it("exports an opaque rescue from the frozen snapshot equal to the frozen OPENARC-OPAQUE-RESCUE v1 file", async () => {
    await seedFrozenSnapshot();
    const rescue = await frozen("export opaque rescue", () => exportOpaqueRescue());
    expect({ ...rescue, exportedAt: opaqueRescue.exportedAt }, `${FROZEN} [opaque rescue]`).toEqual(opaqueRescue);
  });

  it("restores the frozen opaque rescue bytes, then unlocks and recovers them record by record", async () => {
    await seedFrozenSnapshot({ ...snapshot, stores: snapshot.stores.map((store) => ({ ...store,
      rows: store.name === "vaultMeta" ? [opaqueRescue.vaultMeta] : opaqueRescue.records })) });
    const meta = await frozen("read restored rescue metadata", () => readVaultMeta());
    expect(meta, FROZEN).toEqual(frozenMeta);
    expectRecordByRecord((await unlockFrozen(frozenMeta, secrets.workspacePassphrase, "unlock restored rescue")).records,
      expectedRecords, "rescue unlock");
    const recovered = await frozen("recover restored rescue", () =>
      recoverLocalWorkspace(frozenMeta, secrets.recoverySecret, NEW_PASSPHRASE));
    expectRecordByRecord(recovered.records.filter((record) => record.kind !== "sentinel"), logicalExpected, "rescue recovery");
  });
});
