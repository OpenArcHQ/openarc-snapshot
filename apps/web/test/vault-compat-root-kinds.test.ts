// PORT-08 compatibility rule (packet P08-01, additive dual reader; §1.11 item 9 and §2.1). A Vault or encrypted backup
// written by the ROOT build and holding its Vault record kinds (task_draft, task_report, research_run) must unlock,
// recover, import, re-export, survive a passphrase change and stay rescuable on this build, byte-faithfully and
// read-only. P08-00 used these same fixtures to prove the opposite (unlock failed as a wrong passphrase and import as
// INVALID_BACKUP); those known-gap expectations are deliberately flipped here into positive compatibility tests.
// Fixture approach unchanged from P08-00: the frozen snapshot plus ROOT-kind envelopes AES-GCM encrypted under the
// frozen data key with the unchanged v1 record AAD by the independent reference codec, with a fresh manifest
// sentinel; backups are the frozen logical archive plus ROOT-kind records sealed by the same reference codec.
import "fake-indexeddb/auto";

import { afterEach, describe, expect, it } from "vitest";
import { WorkspaceRecordSchema, classifyWorkspaceRecordIdentity, type WorkspaceRecord } from "@openarc/shared";

import { assertWorkspaceRecordCapacity, createManifestSentinel } from "../src/vault/crypto.js";
import { VAULT_DATABASE_NAME, readVaultMeta } from "../src/vault/db.js";
import {
  VAULT_INCOMPATIBLE_BACKUP_MESSAGE,
  VAULT_INCOMPATIBLE_MESSAGE,
  VaultIncompatibleError,
  vaultErrorMessage,
} from "../src/vault/errors.js";
import { ROOT_KINDS_READ_ONLY_MESSAGE } from "../src/vault/root-kinds.js";
import {
  deleteWorkspaceRecords,
  destroyLocalWorkspace,
  exportLocalWorkspace,
  exportOpaqueRescue,
  importLocalWorkspace,
  markTourSeen,
  recoverLocalWorkspace,
  saveWorkspaceRecords,
  unlockLocalWorkspace,
  updateWorkspacePassphrase,
} from "../src/vault/service.js";
import {
  ROOT_VAULT_RECORD_CAPS,
  VAULT_MAX_RECORDS,
  VAULT_RECORD_CAPS,
  VAULT_RECORD_CAPS_BY_KIND,
  type EncryptedEnvelope,
  type LogicalBackupArchive,
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
  storeRows,
  type IndexedDbImage,
} from "./vault-compat/fixture-io.js";
import {
  fromB64u,
  referenceCanonicalJson,
  referenceDecryptBackup,
  referenceEncryptBackup,
  referenceEncryptEnvelope,
  toB64u,
} from "./vault-compat/reference-codec.js";
import {
  REFERENCE_ROOT_KIND_SCHEMAS,
  rootDraftDigest,
  rootRequestDigest,
  type ReferenceRequest,
  type RootDraftDigestInput,
} from "./vault-compat/root-build-reference.js";
import { ROOT_BUILD_DIR_ENV, loadRootBuild } from "./vault-compat/root-build-source.js";
import { ROOT_KIND_RECORD_SCHEMAS, buildRootKindRecords, type RootKind } from "./vault-compat/root-kind-records.js";

const RULE = "PORT-08 compatibility rule (P08-01 dual reader, §1.11 item 9, §2.1): data written by the ROOT build must " +
  "open on this build byte-faithfully and stay read-only. Fix the reader; never edit the frozen fixtures";
const NEW_PASSPHRASE = "TEST-ONLY replacement passphrase";

type Plain = Record<string, unknown> & { recordId: string; kind: string };

const manifest = await readManifest();
const secrets = manifest.secrets;
const snapshot = await readFixtureJson<IndexedDbImage>(VAULT_COMPAT_FILES.snapshot);
const expectedRecords = await readFixtureJson<WorkspaceRecord[]>(VAULT_COMPAT_FILES.expectedRecords);
const logicalBackup = await readFixtureJson<LogicalBackupArchive>(VAULT_COMPAT_FILES.logicalBackup);
const frozenBackup = JSON.parse(await readFixtureText(VAULT_COMPAT_FILES.encryptedBackup)) as VaultBackupFile;
const meta = storeRows(snapshot, "vaultMeta")[0] as PublicVaultMeta;
const account = expectedRecords.find((record) => record.kind === "arc_observation" &&
  record.observation.schemaVersion === "openarc.arc-account-snapshot.v1");
const walletAgent = expectedRecords.find((record) => record.kind === "agent_profile" && record.wallets.length > 0);
if (account?.kind !== "arc_observation" || walletAgent?.kind !== "agent_profile") throw new Error("Frozen fixture is missing its account observation or wallet agent");
const rootRecords = buildRootKindRecords({ recordRevision: meta.revision, agentProfileRecordId: walletAgent.recordId,
  accountObservationRecordId: account.recordId,
  accountSnapshot: account.observation as RootKindInputSnapshot });
type RootKindInputSnapshot = Parameters<typeof buildRootKindRecords>[0]["accountSnapshot"];
const rootId = (n: number) => `7e570000-0000-4000-8000-${n.toString(16).padStart(12, "0")}`;
const draft = rootRecords.task_draft as Plain;
const report = rootRecords.task_report as Plain;
const accountRun = rootRecords.research_run as Plain;

/** Further ROOT-writable states, built from the same ROOT literals: a web research run with untrusted provider text,
 * a cancelled draft with non-ASCII owner intent and an unavailable run. */
const webQuery = "TEST-ONLY public research query";
const webRun: Plain = { ...accountRun, recordId: rootId(0x904), input: { operation: "web_research", query: webQuery },
  result: { schemaVersion: "openarc.web-research.v1", provider: "tavily", query: webQuery, observedAt: "2026-09-14T13:00:30Z",
    credits: 1, payment: "free_provider_credit", results: [{ title: "TEST-ONLY résumé — ünïcode source", url: "https://example.com/source?q=1",
      excerpt: "<script>untrusted provider excerpt</script> kept as text" }] } };
const cancelledDraft: Plain = { ...draft, recordId: rootId(0x905), taskId: "task_7e570000000040008000000000000905",
  instructions: "TEST-ONLY cancelled owner intent — ✓ 日本語", state: "cancelled", updatedAt: "2026-09-14T14:00:00Z",
  cancelledAt: "2026-09-14T14:00:00Z" };
const unavailableRun: Plain = { ...accountRun, recordId: rootId(0x906), state: "unavailable", result: null };
const WIDE: Plain[] = [draft, report, accountRun, webRun, cancelledDraft, unavailableRun];

const SETS: [string, Plain[]][] = [
  ["task_draft", [draft]],
  ["task_draft with its task_report", [draft, report]],
  ["task_draft with its research_run", [draft, accountRun]],
  ["every ROOT kind and ROOT-writable state", WIDE],
];

/** A valid integration-kind record, used as the control for the reference-encrypted write path. */
const controlRecord = (() => {
  const receipt = expectedRecords.find((record) => record.kind === "permission_receipt" && record.recordSchema === "openarc.permission-receipt.v1")!;
  return { ...receipt, recordId: "7e570000-0000-4000-8000-000000000a01", recordRevision: meta.revision };
})();

const rootBuild = await loadRootBuild();

afterEach(async () => {
  await deleteIndexedDb(VAULT_DATABASE_NAME);
});

/**
 * Writes the frozen Vault plus extra records exactly as a ROOT build would store them: AES-GCM under the frozen data
 * key and the unchanged v1 record AAD, with a fresh valid manifest sentinel. `tamper` may alter the added envelopes
 * before the sentinel is computed, so a tampered ciphertext still matches the manifest.
 */
async function seedVaultWith(extra: readonly { recordId: string }[],
  tamper: (added: EncryptedEnvelope[]) => EncryptedEnvelope[] = (added) => added): Promise<IndexedDbImage> {
  await seedIndexedDbImage(snapshot);
  const { key } = await unlockLocalWorkspace(meta, secrets.workspacePassphrase);
  await deleteIndexedDb(VAULT_DATABASE_NAME);
  const encrypted: EncryptedEnvelope[] = [];
  for (const [index, record] of extra.entries()) {
    encrypted.push(await referenceEncryptEnvelope(key, meta.vaultId, record, meta.revision,
      toB64u(new TextEncoder().encode(`P08ROOTKIND${index}`))));
  }
  const added = tamper(encrypted);
  const others = (storeRows(snapshot, "records") as EncryptedEnvelope[]).filter((row) => row.id !== meta.sentinelRecordId);
  const sentinel = await createManifestSentinel(meta, key, [...others, ...added], "2026-09-15T09:00:00.000Z");
  const image: IndexedDbImage = { ...snapshot, stores: snapshot.stores.map((store) => store.name === "records"
    ? { ...store, rows: [...others, ...added, sentinel.envelope].sort((left, right) => left.id.localeCompare(right.id)) }
    : store) };
  await seedIndexedDbImage(image);
  return image;
}

async function backupWith(extra: readonly unknown[]): Promise<unknown> {
  const archive = { ...logicalBackup, records: [...logicalBackup.records, ...extra] };
  return referenceEncryptBackup(archive, secrets.backupPassphrase, frozenBackup.kdf.salt,
    toB64u(new TextEncoder().encode("P08ROOTBKUP!")));
}

const currentImage = () => readIndexedDbImage(VAULT_DATABASE_NAME);

function envelopeRows(image: IndexedDbImage | null, records: readonly { recordId: string }[]): unknown[] {
  const ids = new Set(records.map((record) => record.recordId));
  if (!image) throw new Error("Expected a stored Vault image");
  return storeRows(image, "records").filter((row) => ids.has((row as EncryptedEnvelope).id));
}

/** Byte-faithful: the canonical JSON (the exact encrypted plaintext form) of every ROOT record is unchanged. */
function expectPreserved(actual: readonly unknown[], extra: readonly Plain[], label: string, ignoreRevision = false) {
  const byId = new Map((actual as Plain[]).map((record) => [record.recordId, record]));
  const canonical = (record: Plain) => referenceCanonicalJson(ignoreRevision ? { ...record, recordRevision: null } : record);
  for (const record of extra) {
    const found = byId.get(record.recordId);
    expect(found, `${RULE} [${label}: ${record.kind} ${record.recordId} present]`).toBeDefined();
    expect(canonical(found!), `${RULE} [${label}: ${record.kind} ${record.recordId} bytes]`).toBe(canonical(record));
  }
}

/** Independent re-derivation of the ROOT build's schemas and relationship rules over re-exported logical records. */
function expectRootContracts(records: readonly unknown[], label: string): void {
  const plain = records as Plain[];
  const byId = new Map(plain.map((record) => [record.recordId, record]));
  const taskIds = plain.filter((record) => record.kind === "task_draft").map((record) => record.taskId);
  expect(new Set(taskIds).size, `${RULE} [${label}: unique taskId]`).toBe(taskIds.length);
  for (const record of plain) {
    if (!Object.hasOwn(REFERENCE_ROOT_KIND_SCHEMAS, record.kind)) {
      expect(WorkspaceRecordSchema.safeParse(record).success, `${RULE} [${label}: ${record.kind}]`).toBe(true);
      continue;
    }
    const parsed = REFERENCE_ROOT_KIND_SCHEMAS[record.kind as RootKind].safeParse(record);
    expect(parsed.success, `${RULE} [${label}: ROOT contract accepts ${record.kind} ${record.recordId}]`).toBe(true);
    expect(referenceCanonicalJson(parsed.data), `${RULE} [${label}: ROOT parse is lossless]`).toBe(referenceCanonicalJson(record));
    if (record.kind === "task_draft") {
      expect(byId.get(record.agentProfileRecordId as string)?.kind, `${RULE} [${label}: draft agent]`).toBe("agent_profile");
    } else if (record.kind === "research_run") {
      const linked = byId.get(record.taskDraftRecordId as string);
      expect(linked?.kind, `${RULE} [${label}: run draft]`).toBe("task_draft");
      expect(record.taskDigest, `${RULE} [${label}: run digest]`).toBe(rootDraftDigest(linked as unknown as RootDraftDigestInput));
    } else {
      const linked = byId.get(record.taskDraftRecordId as string) as unknown as RootDraftDigestInput & Plain;
      const request = record.request as ReferenceRequest;
      const observation = byId.get(record.observationRecordId as string) as Plain | undefined;
      expect(linked.kind, `${RULE} [${label}: report draft]`).toBe("task_draft");
      expect([request.taskId, request.agentProfileRecordId, request.taskDigest, record.requestDigest], `${RULE} [${label}: report digests]`)
        .toEqual([linked.taskId, linked.agentProfileRecordId, rootDraftDigest(linked), rootRequestDigest(request)]);
      expect(observation?.observation, `${RULE} [${label}: report observation]`).toMatchObject({
        schemaVersion: "openarc.arc-account-snapshot.v1", address: request.address, network: request.network });
    }
  }
}

function expectNoRecordContent(error: unknown, records: readonly Plain[]): void {
  const exposed = JSON.stringify({ message: (error as Error).message, name: (error as Error).name, ...(error as object) });
  for (const record of records) {
    for (const value of [record.recordId, record.recordSchema, record.kind, record.instructions, record.note, record.taskId]) {
      if (typeof value === "string" && value !== "") expect(exposed, `${RULE} [error must not describe the record]`).not.toContain(value);
    }
  }
}

const flipFirstCiphertextByte = (envelope: EncryptedEnvelope): EncryptedEnvelope => {
  const bytes = fromB64u(envelope.ciphertext);
  bytes[0] = bytes[0]! ^ 0x01;
  return { ...envelope, ciphertext: toB64u(bytes) };
};

describe("P08-01 dual reader: the ROOT build's Vault record kinds on this build", { timeout: 120_000 }, () => {
  it("accepts ROOT-build records with their ROOT literals, without transforming them", () => {
    expect(ROOT_KIND_RECORD_SCHEMAS).toEqual({ task_draft: "openarc.task-draft-record.v1",
      task_report: "openarc.task-report-record.v1", research_run: "openarc.research-run.v1" });
    for (const record of WIDE) {
      expect(record.recordSchema, RULE).toBe(ROOT_KIND_RECORD_SCHEMAS[record.kind as RootKind]);
      const parsed = WorkspaceRecordSchema.safeParse(record);
      expect(parsed.success, `${RULE} [integration WorkspaceRecordSchema accepts ${record.kind} ${record.recordId}]`).toBe(true);
      expect(parsed.data, `${RULE} [no transform]`).toEqual(record);
      expect(classifyWorkspaceRecordIdentity(record)).toBe("known");
    }
    expectRootContracts([...expectedRecords.filter((record) => record.kind !== "sentinel"), ...WIDE], "fixture records");
  });

  it("control: the same reference write path with an integration-known kind still unlocks and imports", async () => {
    const image = await seedVaultWith([controlRecord]);
    const unlocked = await unlockLocalWorkspace(meta, secrets.workspacePassphrase);
    expect(unlocked.records).toContainEqual(controlRecord);
    expect(await currentImage()).toEqual(image);
    await deleteIndexedDb(VAULT_DATABASE_NAME);
    const imported = await importLocalWorkspace(await backupWith([controlRecord]), secrets.backupPassphrase,
      "TEST-ONLY control import passphrase", null);
    expect(imported.records.map((record) => record.recordId)).toContain(controlRecord.recordId);
  });

  it.each(SETS)("unlocks, recovers and rescues a ROOT-build Vault holding %s, byte-faithfully, writing nothing on unlock",
    async (_label, extra) => {
      const image = await seedVaultWith(extra);
      const unlocked = await unlockLocalWorkspace(meta, secrets.workspacePassphrase);
      expect(unlocked.records, RULE).toHaveLength(expectedRecords.length + extra.length);
      expectPreserved(unlocked.records, extra, "unlock");
      for (const record of expectedRecords.filter((candidate) => candidate.kind !== "sentinel")) {
        expect(unlocked.records, `${RULE} [frozen ${record.kind} unchanged]`).toContainEqual(record);
      }
      expect(await currentImage(), `${RULE} [unlock never writes]`).toEqual(image);
      const rescue = await exportOpaqueRescue();
      expect(rescue.vaultMeta, RULE).toEqual(meta);
      expect(rescue.records, `${RULE} [opaque rescue keeps every envelope]`).toEqual(storeRows(image, "records"));

      const recovered = await recoverLocalWorkspace(meta, secrets.recoverySecret, NEW_PASSPHRASE);
      expectPreserved(recovered.records, extra, "recovery");
      expect(recovered.recoverySecret).not.toBe(secrets.recoverySecret);
      expect(envelopeRows(await currentImage(), extra), `${RULE} [recovery keeps ROOT envelopes byte-identical]`)
        .toEqual(envelopeRows(image, extra));
      expectPreserved((await unlockLocalWorkspace(recovered.meta, NEW_PASSPHRASE)).records, extra, "unlock after recovery");
    });

  it.each(SETS)("imports a ROOT-build backup holding %s and re-exports records the ROOT build's contracts still accept",
    async (_label, extra) => {
      const imported = await importLocalWorkspace(await backupWith(extra), secrets.backupPassphrase, NEW_PASSPHRASE, null);
      expectPreserved(imported.records, extra, "import", true);
      const reopened = await unlockLocalWorkspace(imported.meta, NEW_PASSPHRASE);
      expectPreserved(reopened.records, extra, "unlock after import", true);
      const backup = await exportLocalWorkspace(reopened, NEW_PASSPHRASE);
      const archive = JSON.parse(await referenceDecryptBackup(backup, NEW_PASSPHRASE)) as LogicalBackupArchive;
      expect([archive.format, archive.formatVersion, archive.records.length], RULE)
        .toEqual(["openarc.logical-backup", 1, logicalBackup.records.length + extra.length]);
      expectPreserved(archive.records, extra, "re-export", true);
      expectRootContracts(archive.records, "re-export");
    });

  it.each([["task_report", [report]], ["research_run", [accountRun]]] as [string, Plain[]][])(
    "refuses a ROOT-build %s without its task draft exactly as the ROOT build does, writing nothing",
    async (_label, extra) => {
      const image = await seedVaultWith(extra);
      await expect(unlockLocalWorkspace(meta, secrets.workspacePassphrase), RULE)
        .rejects.toMatchObject({ code: "INVALID_BACKUP", message: "Encrypted workspace records have invalid relationships." });
      expect(await currentImage(), RULE).toEqual(image);
      await deleteIndexedDb(VAULT_DATABASE_NAME);
      await expect(importLocalWorkspace(await backupWith(extra), secrets.backupPassphrase, NEW_PASSPHRASE, null), RULE)
        .rejects.toMatchObject({ code: "INVALID_BACKUP" });
      expect(await currentImage(), "a refused import creates no Vault").toBeNull();
    });

  it("keeps ROOT-build records byte-identical and read-only across passphrase change, unrelated saves and refused writes", async () => {
    const image = await seedVaultWith(WIDE);
    const unlocked = await unlockLocalWorkspace(meta, secrets.workspacePassphrase);
    const changed = await updateWorkspacePassphrase(unlocked, secrets.workspacePassphrase, NEW_PASSPHRASE);
    expectPreserved(changed.records, WIDE, "passphrase change");
    expect(envelopeRows(await currentImage(), WIDE), `${RULE} [passphrase change]`).toEqual(envelopeRows(image, WIDE));

    let current = await unlockLocalWorkspace(changed.meta, NEW_PASSPHRASE);
    const settings = current.records.find((record) => record.kind === "workspace_settings")!;
    current = await saveWorkspaceRecords(current, [markTourSeen(settings)]);
    expect(envelopeRows(await currentImage(), WIDE), `${RULE} [unrelated save]`).toEqual(envelopeRows(image, WIDE));
    current = await unlockLocalWorkspace(current.meta, NEW_PASSPHRASE);
    expectPreserved(current.records, WIDE, "unlock after unrelated save");

    const stored = (id: string) => current.records.find((record) => record.recordId === id)!;
    const later = "2026-09-15T10:00:00.000Z";
    const refused: [string, WorkspaceRecord[], string][] = [
      ["cancel an active draft (an edit the ROOT build allows)",
        [{ ...stored(draft.recordId), state: "cancelled", updatedAt: later, cancelledAt: later } as WorkspaceRecord], ROOT_KINDS_READ_ONLY_MESSAGE],
      ["create a new approved research run (a write the ROOT build allows)",
        [{ ...accountRun, recordId: rootId(0x907), state: "approved", result: null, updatedAt: accountRun.createdAt } as unknown as WorkspaceRecord],
        ROOT_KINDS_READ_ONLY_MESSAGE],
      ["rewrite the arc_observation a task report locks", [stored(account.recordId)], "Evidence linked to a saved task report is immutable."],
      ["rewrite the permission receipt a task report locks", [stored(account.permissionReceiptId)], "Evidence linked to a saved task report is immutable."],
      ["replace a saved task report", [stored(report.recordId)], "Saved task reports cannot be replaced or reclassified."],
      ["change a finished research run", [{ ...stored(unavailableRun.recordId), updatedAt: later } as WorkspaceRecord],
        "Research approval and completed evidence are immutable."],
    ];
    const before = await currentImage();
    for (const [label, changes, message] of refused) {
      await expect(saveWorkspaceRecords(current, changes), `${RULE} [${label}]`).rejects.toMatchObject({ code: "INVALID_BACKUP", message });
      expect(await currentImage(), `${RULE} [${label} writes nothing]`).toEqual(before);
    }
  });

  it("deletes ROOT-build records only through linked deletion or whole-Vault deletion", async () => {
    await seedVaultWith(WIDE);
    const unlocked = await unlockLocalWorkspace(meta, secrets.workspacePassphrase);
    const before = await currentImage();
    for (const [label, ids] of [["the observation a task report links", [account.recordId]],
      ["a task draft its report and runs still reference", [draft.recordId]]] as [string, string[]][]) {
      await expect(deleteWorkspaceRecords(unlocked, ids), `${RULE} [${label}]`).rejects.toMatchObject({ code: "INVALID_BACKUP" });
      expect(await currentImage(), `${RULE} [${label} writes nothing]`).toEqual(before);
    }
    const linked = [draft, report, accountRun, webRun, unavailableRun].map((record) => record.recordId);
    const deleted = await deleteWorkspaceRecords(unlocked, linked);
    expect(deleted.records.filter((record) => linked.includes(record.recordId)), RULE).toEqual([]);
    expectPreserved(deleted.records, [cancelledDraft], "linked deletion keeps unrelated ROOT records");
    expectPreserved((await unlockLocalWorkspace(deleted.meta, secrets.workspacePassphrase)).records, [cancelledDraft], "unlock after deletion");
    await destroyLocalWorkspace();
    expect(await readVaultMeta(), RULE).toBeNull();
  });

  it("enforces the ROOT build's per-kind caps additively, leaving the frozen caps and the 6,602 total unchanged", () => {
    expect(ROOT_VAULT_RECORD_CAPS).toEqual({ task_draft: 100, task_report: 100, research_run: 100 });
    expect(VAULT_RECORD_CAPS_BY_KIND).toEqual({ ...VAULT_RECORD_CAPS, ...ROOT_VAULT_RECORD_CAPS });
    expect(Object.isFrozen(ROOT_VAULT_RECORD_CAPS) && Object.isFrozen(VAULT_RECORD_CAPS_BY_KIND)).toBe(true);
    expect(VAULT_MAX_RECORDS).toBe(6_602);
    const drafts = (count: number) => Array.from({ length: count }, (_, index) =>
      ({ ...draft, recordId: rootId(0xb000 + index) }) as unknown as WorkspaceRecord);
    expect(() => assertWorkspaceRecordCapacity(drafts(100))).not.toThrow();
    expect(() => assertWorkspaceRecordCapacity(drafts(101))).toThrow("The encrypted workspace task_draft limit is 100.");
  });

  it.skipIf(rootBuild === null)(
    `cross-checks re-exported ROOT-build records against the ROOT build's own pinned sources (${ROOT_BUILD_DIR_ENV})`,
    async () => {
      const contracts = rootBuild!;
      const imported = await importLocalWorkspace(await backupWith(WIDE), secrets.backupPassphrase, NEW_PASSPHRASE, null);
      const backup = await exportLocalWorkspace(imported, NEW_PASSPHRASE);
      const archive = JSON.parse(await referenceDecryptBackup(backup, NEW_PASSPHRASE)) as LogicalBackupArchive;
      for (const record of archive.records) {
        const parsed = contracts.WorkspaceRecordSchema.safeParse(record);
        expect(parsed.success, `${RULE} [ROOT WorkspaceRecordSchema accepts re-exported ${record.kind} ${record.recordId}]`).toBe(true);
        expect(referenceCanonicalJson(parsed.data), RULE).toBe(referenceCanonicalJson(record));
      }
      const request = report.request as ReferenceRequest;
      expect([contracts.accountReportDraftDigest(draft), contracts.accountReportRequestDigest(request)], RULE)
        .toEqual([request.taskDigest, report.requestDigest]);
      expect(contracts.WorkspaceRecordSchema.safeParse({ ...report, requestDigest: `sha256:${"0".repeat(64)}` }).success).toBe(false);
    });
});

describe("P08-01 honest incompatible-Vault state", { timeout: 120_000 }, () => {
  const futureDraft: Plain = { ...draft, recordId: rootId(0xa02), taskId: "task_7e570000000040008000000000000a02",
    recordSchema: "openarc.task-draft-record.v2", instructions: "PRIVATE_FUTURE_INSTRUCTIONS_CANARY" };
  const unknownKind: Plain = { recordSchema: "openarc.private-note-record.v1", kind: "private_note", recordId: rootId(0xa03),
    recordRevision: meta.revision, createdAt: "2026-09-14T13:00:00Z", updatedAt: "2026-09-14T13:00:00Z", note: "PRIVATE_NOTE_CANARY" };
  const tamperedReport: Plain = { ...report, requestDigest: `sha256:${"0".repeat(64)}` };

  it("still reports a wrong passphrase on a Vault holding ROOT-build records as a wrong passphrase, writing nothing", async () => {
    const image = await seedVaultWith(WIDE);
    await expect(unlockLocalWorkspace(meta, "TEST-ONLY wrong passphrase"))
      .rejects.toMatchObject({ code: "INVALID_PASSPHRASE", message: "Wrong passphrase or damaged workspace." });
    await expect(recoverLocalWorkspace(meta, `OA1-${"A".repeat(43)}`, NEW_PASSPHRASE))
      .rejects.toMatchObject({ code: "RECOVERY_FAILED", message: "Wrong passphrase or damaged workspace." });
    expect(await currentImage()).toEqual(image);
  });

  it.each([["a future version of a ROOT kind", [draft, futureDraft]], ["a kind no build knows", [unknownKind]]] as [string, Plain[]][])(
    "reports a Vault holding %s as VAULT_INCOMPATIBLE, never a wrong passphrase; nothing is written and opaque rescue works",
    async (_label, extra) => {
      const image = await seedVaultWith(extra);
      const failure = await unlockLocalWorkspace(meta, secrets.workspacePassphrase).then(() => null, (cause: unknown) => cause);
      expect(failure).toBeInstanceOf(VaultIncompatibleError);
      expect(failure).toMatchObject({ code: "VAULT_INCOMPATIBLE", source: "vault", reason: "unknown_record_identity",
        message: VAULT_INCOMPATIBLE_MESSAGE });
      expect(vaultErrorMessage(failure)).toBe(VAULT_INCOMPATIBLE_MESSAGE);
      expect(VAULT_INCOMPATIBLE_MESSAGE).toMatch(/^This Vault contains records from a newer or different OpenArc build/u);
      expect(VAULT_INCOMPATIBLE_MESSAGE).toContain("opaque rescue");
      expect(VAULT_INCOMPATIBLE_MESSAGE).not.toContain("Wrong passphrase");
      expectNoRecordContent(failure, extra);
      await expect(recoverLocalWorkspace(meta, secrets.recoverySecret, NEW_PASSPHRASE))
        .rejects.toMatchObject({ code: "VAULT_INCOMPATIBLE", reason: "unknown_record_identity" });
      await expect(unlockLocalWorkspace(meta, "TEST-ONLY wrong passphrase"), "the key unwrap still fails first")
        .rejects.toMatchObject({ code: "INVALID_PASSPHRASE" });
      expect(await currentImage(), "an incompatible Vault is never written").toEqual(image);
      const rescue = await exportOpaqueRescue();
      expect(rescue.records).toEqual(storeRows(image, "records"));
      expect(rescue.vaultMeta).toEqual(meta);

      await deleteIndexedDb(VAULT_DATABASE_NAME);
      const importFailure = await importLocalWorkspace(await backupWith(extra), secrets.backupPassphrase, NEW_PASSPHRASE, null)
        .then(() => null, (cause: unknown) => cause);
      expect(importFailure).toMatchObject({ code: "VAULT_INCOMPATIBLE", source: "backup", reason: "unknown_record_identity",
        message: VAULT_INCOMPATIBLE_BACKUP_MESSAGE });
      expect(vaultErrorMessage(importFailure)).toBe(VAULT_INCOMPATIBLE_BACKUP_MESSAGE);
      expectNoRecordContent(importFailure, extra);
      await expect(importLocalWorkspace(await backupWith(extra), "TEST-ONLY wrong backup passphrase", NEW_PASSPHRASE, null))
        .rejects.toMatchObject({ code: "INVALID_BACKUP", message: "Wrong backup passphrase or damaged encrypted backup." });
      expect(await currentImage(), "an incompatible backup creates no Vault").toBeNull();
    });

  it("never presents a tampered ROOT-build digest as verified", async () => {
    expect(WorkspaceRecordSchema.safeParse(tamperedReport).success, "the integration schema recomputes the digest").toBe(false);
    expect(REFERENCE_ROOT_KIND_SCHEMAS.task_report.safeParse(tamperedReport).success, "the ROOT contract rejects it too").toBe(false);
    expect(classifyWorkspaceRecordIdentity(tamperedReport)).toBe("known");
    const image = await seedVaultWith([draft, tamperedReport]);
    await expect(unlockLocalWorkspace(meta, secrets.workspacePassphrase)).rejects.toMatchObject({
      code: "VAULT_INCOMPATIBLE", reason: "unsupported_record_content", message: VAULT_INCOMPATIBLE_MESSAGE });
    await expect(recoverLocalWorkspace(meta, secrets.recoverySecret, NEW_PASSPHRASE))
      .rejects.toMatchObject({ code: "VAULT_INCOMPATIBLE", reason: "unsupported_record_content" });
    expect(await currentImage()).toEqual(image);
    await deleteIndexedDb(VAULT_DATABASE_NAME);
    await expect(importLocalWorkspace(await backupWith([draft, tamperedReport]), secrets.backupPassphrase, NEW_PASSPHRASE, null))
      .rejects.toMatchObject({ code: "VAULT_INCOMPATIBLE", source: "backup", reason: "unsupported_record_content" });
    expect(await currentImage()).toBeNull();

    // A well-formed run digest that matches no draft passes the schema (format only) and fails the ROOT relationship.
    const tamperedRun: Plain = { ...accountRun, taskDigest: `sha256:${"f".repeat(64)}` };
    expect(WorkspaceRecordSchema.safeParse(tamperedRun).success).toBe(true);
    const runImage = await seedVaultWith([draft, tamperedRun]);
    await expect(unlockLocalWorkspace(meta, secrets.workspacePassphrase))
      .rejects.toMatchObject({ code: "INVALID_BACKUP", message: "Encrypted workspace records have invalid relationships." });
    expect(await currentImage()).toEqual(runImage);
  });

  it("reports a tampered ROOT-build ciphertext as damage, and damage wins over incompatibility", async () => {
    const image = await seedVaultWith([draft], (added) => added.map(flipFirstCiphertextByte));
    await expect(unlockLocalWorkspace(meta, secrets.workspacePassphrase))
      .rejects.toMatchObject({ code: "INVALID_PASSPHRASE", message: "Wrong passphrase or damaged workspace." });
    await expect(recoverLocalWorkspace(meta, secrets.recoverySecret, NEW_PASSPHRASE)).rejects.toMatchObject({ code: "RECOVERY_FAILED" });
    expect(await currentImage()).toEqual(image);
    await deleteIndexedDb(VAULT_DATABASE_NAME);

    const mixed = await seedVaultWith([unknownKind, draft],
      (added) => added.map((envelope) => envelope.id === draft.recordId ? flipFirstCiphertextByte(envelope) : envelope));
    await expect(unlockLocalWorkspace(meta, secrets.workspacePassphrase)).rejects.toMatchObject({ code: "INVALID_PASSPHRASE" });
    expect(await currentImage()).toEqual(mixed);
  });
});
