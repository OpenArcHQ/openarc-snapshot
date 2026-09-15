import "fake-indexeddb/auto";

import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ARC_ACCOUNT_SNAPSHOT_PATH,
  AGENT_REGISTRY_DISCLOSURE,
  AGENT_REGISTRY_EVIDENCE_PATH,
  ARC_ERC8004,
  ARC_OBSERVATION_DISCLOSURE,
  ARC_TESTNET,
  ArcAccountSnapshotSchema,
  ArcObservationRecordSchema,
  AgentRegistryObservationRecordSchema,
  AgentRegistryPermissionReceiptRecordSchema,
  CAPABILITY_DISCLOSURE,
  LegacyAgentRegistryEvidenceV1Schema,
  M01_FIXTURES,
  PermissionReceiptRecordSchema,
  reconcileAction,
  type WorkspaceRecord,
} from "@openarc/shared";

import {
  createRevision,
  decryptWorkspaceRecord,
  decryptEncryptedBackup,
  encryptWorkspaceRecord,
  assertWorkspaceRecordCapacity,
  validatePassphrase,
} from "../src/vault/crypto.js";
import {
  VAULT_DATABASE_NAME,
  installVaultDatabaseObserver,
  observeVaultDatabase,
  readVaultMeta,
  readVaultSnapshot,
} from "../src/vault/db.js";
import { VaultError } from "../src/vault/errors.js";
import { runArcObservationPermissionFlow } from "../src/api/arc-permission-flow.js";
import { OpenArcRequestError } from "../src/api/client.js";
import { runJobPermissionFlow } from "../src/api/job-permission-flow.js";
import { jobTestEnvelope, JOB_TEST_REQUEST } from "../../../test-fixtures/job-evidence.js";
import {
  assertWorkspaceIntegrity,
  createAgentProfileRecord,
  createFixtureWorkspaceRecords,
  createLocalWorkspace,
  deleteWorkspaceRecords,
  destroyLocalWorkspace,
  exportLocalWorkspace,
  exportOpaqueRescue,
  importLocalWorkspace,
  parseBackupFile,
  prepareLocalWorkspaceDeletion,
  recoverLocalWorkspace,
  saveWorkspaceRecords,
  signalWorkspaceLock,
  unlockLocalWorkspace,
  updateWorkspacePassphrase,
} from "../src/vault/service.js";

const originalPassphrase = "correct horse battery staple";
const backupPassphrase = "separate archive password";
const restoredPassphrase = "a fresh restored password";

function m04AccountRecords(recordRevision: string) {
  const at = "2026-09-03T12:00:00Z";
  const address = "0x1111111111111111111111111111111111111111";
  const receipt = PermissionReceiptRecordSchema.parse({
    recordSchema: "openarc.permission-receipt.v2", kind: "permission_receipt",
    recordId: crypto.randomUUID(), recordRevision, createdAt: at, updatedAt: at,
    connectorId: "arc_account_snapshot", destination: { origin: "https://app.example.test",
      path: ARC_ACCOUNT_SNAPSHOT_PATH, method: "POST", upstreams: [ARC_TESTNET.rpcHttp] },
    releasedFields: ["network", "address"], released: { network: ARC_TESTNET.caip2, address },
    purpose: "Observe one public Arc Testnet address at one exact final block.",
    ...ARC_OBSERVATION_DISCLOSURE, approvedAt: at, outcome: "completed", resolvedAt: at, failureCode: null,
  });
  const observation = ArcAccountSnapshotSchema.parse({
    schemaVersion: "openarc.arc-account-snapshot.v1", network: ARC_TESTNET.caip2, address,
    anchor: { blockNumber: "100", blockHash: `0x${"a".repeat(64)}`,
      blockTimestamp: "2026-09-03T11:59:59Z", finality: "deterministic", confirmations: "1" },
    nativeUsdc: { asset: "USDC", interface: "native",
      amount: { baseUnits: "1000000000000000000", decimals: 18, decimal: "1" } },
    erc20UsdcView: { asset: "USDC", interface: "erc20", contract: ARC_TESTNET.contracts.usdc,
      amount: { baseUnits: "1000000", decimals: 6, decimal: "1" },
      relationship: "same_underlying_balance", truncatesSubMicroUsdc: true },
    source: { sourceId: "arc_primary_rpc", origin: ARC_TESTNET.rpcHttp,
      explorerOrigin: ARC_TESTNET.explorerOrigin, network: ARC_TESTNET.caip2,
      sourceRevision: ARC_TESTNET.sourceRevision, observedAt: at,
      adapterVersion: "openarc.arc-observation.m04.v1" },
    limitations: ["This is a read-only observation at one exact Arc Testnet block.",
      "The 6-decimal ERC-20 view truncates native precision below one micro-USDC.",
      "A public address is not proof that its owner or controller is an agent."],
  });
  const record = ArcObservationRecordSchema.parse({ recordSchema: "openarc.arc-observation-record.v1",
    kind: "arc_observation", recordId: crypto.randomUUID(), recordRevision, createdAt: at, updatedAt: at,
    permissionReceiptId: receipt.recordId, observation });
  return { address, receipt, observation: record };
}

function m05RegistryRecords(recordRevision: string, linkedAgentProfileRecordId: string | null = null) {
  const at = "2026-09-04T12:00:00Z";
  const receipt = AgentRegistryPermissionReceiptRecordSchema.parse({
    recordSchema: "openarc.permission-receipt.v3", kind: "permission_receipt", recordId: crypto.randomUUID(),
    recordRevision, createdAt: at, updatedAt: at, connectorId: "arc_agent_registry_evidence",
    destination: { origin: "https://app.example.test", path: AGENT_REGISTRY_EVIDENCE_PATH,
      method: "POST", upstreams: [ARC_TESTNET.rpcHttp] }, releasedFields: ["network", "agentId"],
    released: { network: ARC_TESTNET.caip2, agentId: "1" },
    purpose: "Observe one ERC-8004 agent identity and optional exact observer or validator claims at one final Arc Testnet block.",
    ...AGENT_REGISTRY_DISCLOSURE, approvedAt: at, outcome: "completed", resolvedAt: at, failureCode: null,
  });
  // Original M05 v1 evidence must remain decryptable as legacy data after the v2 adapter change.
  const observation = LegacyAgentRegistryEvidenceV1Schema.parse({ schemaVersion: "openarc.agent-registry-evidence.v1",
    network: ARC_TESTNET.caip2, agentId: "1",
    anchor: { blockNumber: "100", blockHash: `0x${"b".repeat(64)}`, blockTimestamp: at,
      finality: "deterministic", confirmations: "1" },
    identity: { owner: "0x1111111111111111111111111111111111111111",
      agentWallet: "0x2222222222222222222222222222222222222222",
      metadata: { uri: "", kind: "none", trust: "untrusted_external_metadata", fetched: false } },
    feedback: null, validation: null,
    source: { sourceId: "arc_primary_rpc", registrySourceId: "erc8004_registries", origin: ARC_TESTNET.rpcHttp,
      explorerOrigin: ARC_TESTNET.explorerOrigin, network: ARC_TESTNET.caip2,
      sourceRevision: ARC_ERC8004.sourceRevision, reviewedAt: ARC_ERC8004.reviewedAt,
      specificationStatus: "draft", contractsRevision: ARC_ERC8004.contractsRevision,
      registries: { identity: ARC_TESTNET.contracts.erc8004IdentityRegistry,
        reputation: ARC_TESTNET.contracts.erc8004ReputationRegistry,
        validation: ARC_TESTNET.contracts.erc8004ValidationRegistry }, observedAt: at,
      adapterVersion: "openarc.agent-registry-evidence.m05.v1" },
    limitations: ["ERC-8004 is a draft standard; registry facts may change before finalization.",
      "Identity ownership and metadata are registry claims, not proof of safety, quality, or control.",
      "Feedback is one observer's claim and validation is one validator's response; neither is a universal score.",
      "Metadata is untrusted external text and was not fetched or rendered by OpenArc."],
  });
  const record = AgentRegistryObservationRecordSchema.parse({
    recordSchema: "openarc.agent-registry-observation-record.v1", kind: "agent_registry_observation",
    recordId: crypto.randomUUID(), recordRevision, createdAt: at, updatedAt: at,
    permissionReceiptId: receipt.recordId, linkedAgentProfileRecordId, observation,
  });
  return { receipt, observation: record };
}

afterEach(async () => {
  vi.restoreAllMocks();
  await deleteDatabase();
});

describe("encrypted local workspace", () => {
  it.each(["lock", "deletion", "record revision", "replacement"] as const)(
    "rejects a stale unlock when %s changes during key derivation without writing ciphertext", async (change) => {
      const created = await createLocalWorkspace(originalPassphrase);
      const originalRecords = (await readRawDatabase()).records;
      let reached!: () => void;
      let release!: () => void;
      const held = new Promise<void>(resolve => { reached = resolve; });
      const barrier = new Promise<void>(resolve => { release = resolve; });
      const derive = crypto.subtle.deriveKey.bind(crypto.subtle);
      vi.spyOn(crypto.subtle, "deriveKey").mockImplementationOnce(async (...args) => {
        reached(); await barrier; return derive(...args);
      });
      // Install only after creation: this barrier belongs to this unlock, not a capability probe.
      const pending = unlockLocalWorkspace(created.meta, originalPassphrase);
      const rejected = expect(pending).rejects.toMatchObject({ code: "VAULT_CONFLICT" });
      await held;
      try {
        if (change === "lock") await signalWorkspaceLock(created.meta);
        else if (change === "deletion") await prepareLocalWorkspaceDeletion(created.meta);
        else if (change === "record revision") {
          const profile = createAgentProfileRecord({ displayName: "Concurrent saved profile", walletAddress: "", frameworkLabel: "", purposeNote: "" }, created.meta.revision);
          await saveWorkspaceRecords(created, [profile]);
        } else {
          await destroyLocalWorkspace();
          await createLocalWorkspace(originalPassphrase);
        }
        const afterChange = await readRawDatabase();
        if (change === "lock" || change === "deletion") expect(afterChange.records).toEqual(originalRecords);
        release(); await rejected;
        expect((await readRawDatabase()).records).toEqual(afterChange.records);
        const freshMeta = await readVaultMeta();
        expect(freshMeta).not.toBeNull();
        if (change === "deletion") await expect(unlockLocalWorkspace(freshMeta!, originalPassphrase)).rejects.toMatchObject({ code: "VAULT_CONFLICT" });
        else await expect(unlockLocalWorkspace(freshMeta!, originalPassphrase)).resolves.toMatchObject({ meta: freshMeta });
      } finally { release(); }
    },
  );

  it("round-trips M06 job consent and evidence through backup, recovery, and paired deletion", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const result = await runJobPermissionFlow({ workspace: created, origin: "https://app.example.test",
      request: JOB_TEST_REQUEST, linkedActionRecordId: null, signal: new AbortController().signal,
      assertActive: () => undefined, save: saveWorkspaceRecords, fetch: async () => jobTestEnvelope() });
    const plaintext = JSON.stringify(await readRawDatabase());
    expect(plaintext).not.toContain("PUBLIC_UNTRUSTED_JOB_DESCRIPTION");
    expect(plaintext).not.toContain("arc_job_evidence");
    const backup = await exportLocalWorkspace(result.workspace, backupPassphrase);
    expect(JSON.stringify(backup)).not.toContain(jobTestEnvelope().data.client);
    const imported = await importLocalWorkspace(backup, backupPassphrase, restoredPassphrase, result.workspace.meta);
    const recovered = await recoverLocalWorkspace(imported.meta, imported.recoverySecret, originalPassphrase);
    expect(recovered.records).toContainEqual(expect.objectContaining({ kind: "job_observation", recordId: result.observation.recordId }));
    await expect(deleteWorkspaceRecords(recovered, [result.receipt.recordId])).rejects.toMatchObject({ code: "INVALID_BACKUP" });
    const deleted = await deleteWorkspaceRecords(recovered, [result.receipt.recordId, result.observation.recordId]);
    expect(deleted.records.some((record) => record.kind === "job_observation")).toBe(false);
  });

  it("rejects orphan, mismatched, duplicate, or nonexistent local job associations", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const result = await runJobPermissionFlow({ workspace: created, origin: "https://app.example.test",
      request: JOB_TEST_REQUEST, linkedActionRecordId: null, signal: new AbortController().signal,
      assertActive: () => undefined, save: saveWorkspaceRecords, fetch: async () => jobTestEnvelope() });
    const observation = result.observation;
    for (const records of [
      result.workspace.records.filter((record) => record.recordId !== result.receipt.recordId),
      result.workspace.records.map((record) => record.recordId === observation.recordId
        ? { ...observation, observation: { ...observation.observation, jobId: "2" } } : record),
      [...result.workspace.records, { ...observation, recordId: crypto.randomUUID() }],
      result.workspace.records.map((record) => record.recordId === observation.recordId
        ? { ...observation, linkedActionRecordId: crypto.randomUUID(), linkBasis: "explicit_local_confirmation" as const } : record),
    ]) expect(() => assertWorkspaceIntegrity(records)).toThrow(VaultError);
  });

  it("normalizes Unicode passphrases and rejects control or edge whitespace", () => {
    expect(validatePassphrase("Cafe\u0301 workspace passphrase")).toBe("Café workspace passphrase");
    expect(() => validatePassphrase(" leading workspace passphrase")).toThrow(VaultError);
    expect(() => validatePassphrase("workspace\u0000passphrase")).toThrow(VaultError);
  });

  it("creates a nonextractable session key and stores no plaintext profile data", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    expect(created.key.extractable).toBe(false);
    expect(created.meta.revision).toMatch(/^[A-Za-z0-9_-]{32}$/u);
    const profile = createAgentProfileRecord(
      {
        displayName: "PRIVATE_AGENT_CANARY",
        walletAddress: `0x${"1".repeat(40)}`,
        frameworkLabel: "PRIVATE_FRAMEWORK_CANARY",
        purposeNote: "PRIVATE_PURPOSE_CANARY",
      },
      created.meta.revision,
    );
    const saved = await saveWorkspaceRecords(created, [profile]);
    expect(saved.meta.revision).not.toBe(created.meta.revision);
    const raw = await readRawDatabase();
    expect(JSON.stringify(raw)).not.toContain("PRIVATE_AGENT_CANARY");
    expect(JSON.stringify(raw)).not.toContain("PRIVATE_FRAMEWORK_CANARY");
    expect(JSON.stringify(raw)).not.toContain(`0x${"1".repeat(40)}`);
    const ivs = (raw.records as { iv: string }[]).map((record) => record.iv);
    expect(new Set(ivs).size).toBe(ivs.length);
    await expect(unlockLocalWorkspace(saved.meta, "wrong password value")).rejects.toMatchObject({
      code: "INVALID_PASSPHRASE",
    });
    const unlocked = await unlockLocalWorkspace(saved.meta, originalPassphrase);
    expect(unlocked.records.some((record) => record.kind === "agent_profile")).toBe(true);
  });

  it("refuses expected-empty creation when orphan encrypted envelopes remain", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const backup = await exportLocalWorkspace(created, backupPassphrase);
    const before = await readRawDatabase();
    await deleteRawMeta();
    await expect(readVaultMeta()).rejects.toMatchObject({ code: "INVALID_BACKUP" });
    await expect(createLocalWorkspace(restoredPassphrase)).rejects.toMatchObject({
      code: "VAULT_EXISTS",
    });
    const after = await readRawDatabase();
    expect(after.meta).toBeUndefined();
    expect(after.records).toEqual(before.records);
    await expect(
      importLocalWorkspace(backup, backupPassphrase, restoredPassphrase, null),
    ).rejects.toMatchObject({ code: "VAULT_CONFLICT" });
    expect((await readRawDatabase()).records).toEqual(before.records);
  });

  it("detects ciphertext tamper, envelope removal, and stale revision writes", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const profile = createAgentProfileRecord(
      { displayName: "Agent one", walletAddress: "", frameworkLabel: "", purposeNote: "" },
      created.meta.revision,
    );
    const saved = await saveWorkspaceRecords(created, [profile]);
    await expect(saveWorkspaceRecords(created, [profile])).rejects.toMatchObject({ code: "VAULT_CONFLICT" });

    await deleteRawRecord(profile.recordId);
    await expect(unlockLocalWorkspace(saved.meta, originalPassphrase)).rejects.toMatchObject({
      code: "INVALID_PASSPHRASE",
    });
  });

  it("binds encrypted record identity and revision through authenticated data", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const snapshot = await readVaultSnapshot(
      created.meta.vaultId,
      created.meta.revision,
      created.meta.coordinationRevision,
    );
    const envelope = snapshot.records.find(
      (record) => record.id !== created.meta.sentinelRecordId,
    )!;
    await expect(
      decryptWorkspaceRecord(created.meta, created.key, {
        ...envelope,
        id: crypto.randomUUID(),
      }),
    ).rejects.toMatchObject({ code: "INVALID_BACKUP" });
    await expect(
      decryptWorkspaceRecord(created.meta, created.key, {
        ...envelope,
        revision: createRevision(),
      }),
    ).rejects.toMatchObject({ code: "INVALID_BACKUP" });
  });

  it("allows exactly one concurrent writer from the same opaque revision", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const first = createAgentProfileRecord(
      { displayName: "Concurrent writer one", walletAddress: "", frameworkLabel: "", purposeNote: "" },
      created.meta.revision,
    );
    const second = createAgentProfileRecord(
      { displayName: "Concurrent writer two", walletAddress: "", frameworkLabel: "", purposeNote: "" },
      created.meta.revision,
    );

    const outcomes = await Promise.allSettled([
      saveWorkspaceRecords(created, [first]),
      saveWorkspaceRecords(created, [second]),
    ]);
    const fulfilled = outcomes.filter(
      (outcome): outcome is PromiseFulfilledResult<Awaited<ReturnType<typeof saveWorkspaceRecords>>> =>
        outcome.status === "fulfilled",
    );
    const rejected = outcomes.filter(
      (outcome): outcome is PromiseRejectedResult => outcome.status === "rejected",
    );

    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect(rejected[0]?.reason).toMatchObject({ code: "VAULT_CONFLICT" });
    const unlocked = await unlockLocalWorkspace(fulfilled[0]!.value.meta, originalPassphrase);
    expect(unlocked.records.filter((record) => record.kind === "agent_profile")).toHaveLength(1);
  });

  it("treats a lock coordination change as a write conflict without rewriting ciphertext", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const lockedMeta = await signalWorkspaceLock(created.meta);
    expect(lockedMeta.revision).toBe(created.meta.revision);
    expect(lockedMeta.coordinationRevision).not.toBe(created.meta.coordinationRevision);
    const profile = createAgentProfileRecord(
      { displayName: "Stale after lock", walletAddress: "", frameworkLabel: "", purposeNote: "" },
      created.meta.revision,
    );
    await expect(saveWorkspaceRecords(created, [profile])).rejects.toMatchObject({
      code: "VAULT_CONFLICT",
    });
    const unlocked = await unlockLocalWorkspace(lockedMeta, originalPassphrase);
    expect(unlocked.records.some((record) => record.kind === "agent_profile")).toBe(false);
  });

  it("persists a lock marker even when a same-vault write races it", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const profile = createAgentProfileRecord(
      { displayName: "Racing writer", walletAddress: "", frameworkLabel: "", purposeNote: "" },
      created.meta.revision,
    );
    const [write, lock] = await Promise.allSettled([
      saveWorkspaceRecords(created, [profile]),
      signalWorkspaceLock(created.meta),
    ]);
    expect(lock.status).toBe("fulfilled");
    const current = await readVaultMeta();
    expect(current?.vaultId).toBe(created.meta.vaultId);
    expect(current?.coordinationRevision).not.toBe(
      write.status === "fulfilled"
        ? write.value.meta.coordinationRevision
        : created.meta.coordinationRevision,
    );
    if (write.status === "rejected") expect(write.reason).toMatchObject({ code: "VAULT_CONFLICT" });
  });

  it("marks deletion before making every regular workspace operation unavailable", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const marked = await prepareLocalWorkspaceDeletion(created.meta);
    expect(marked.deletionPending).toBe(true);
    expect(marked.coordinationRevision).not.toBe(created.meta.coordinationRevision);
    await expect(unlockLocalWorkspace(marked, originalPassphrase)).rejects.toMatchObject({
      code: "VAULT_CONFLICT",
    });
    const profile = createAgentProfileRecord(
      { displayName: "Too late", walletAddress: "", frameworkLabel: "", purposeNote: "" },
      created.meta.revision,
    );
    await expect(saveWorkspaceRecords(created, [profile])).rejects.toMatchObject({
      code: "VAULT_CONFLICT",
    });
  });

  it("classifies database version changes and unexpected closes without reporting intentional cleanup", async () => {
    const deletionReasons: string[] = [];
    const stopObserving = await observeVaultDatabase((reason) => deletionReasons.push(reason));
    await deleteDatabaseStrict();
    expect(deletionReasons).toEqual(["deletion"]);
    stopObserving();

    const versionReasons: string[] = [];
    const upgraded = createObserverDatabaseDouble();
    const stopUpgraded = installVaultDatabaseObserver(upgraded.database, (reason) =>
      versionReasons.push(reason),
    );
    upgraded.emitVersionChange();
    expect(versionReasons).toEqual(["versionchange"]);
    stopUpgraded();

    const closeReasons: string[] = [];
    const unexpected = createObserverDatabaseDouble();
    const stopUnexpected = installVaultDatabaseObserver(unexpected.database, (reason) =>
      closeReasons.push(reason),
    );
    unexpected.emitClose();
    unexpected.emitClose();
    expect(closeReasons).toEqual(["close"]);
    stopUnexpected();

    const intentionalReasons: string[] = [];
    const intentional = createObserverDatabaseDouble();
    const closeIntentionally = installVaultDatabaseObserver(intentional.database, (reason) =>
      intentionalReasons.push(reason),
    );
    closeIntentionally();
    intentional.emitClose();
    intentional.emitVersionChange();
    expect(intentionalReasons).toEqual([]);
  });

  it("detects an inserted envelope and a rolled metadata revision through the sentinel", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const inserted = createAgentProfileRecord(
      { displayName: "Inserted", walletAddress: "", frameworkLabel: "", purposeNote: "" },
      created.meta.revision,
    );
    const envelope = await encryptWorkspaceRecord(
      created.meta,
      created.key,
      inserted,
      new Set((await readVaultSnapshot(created.meta.vaultId, created.meta.revision, created.meta.coordinationRevision)).records.map((record) => record.iv)),
    );
    await putRawRecord(envelope);
    await expect(unlockLocalWorkspace(created.meta, originalPassphrase)).rejects.toMatchObject({
      code: "INVALID_PASSPHRASE",
    });

    await deleteRawRecord(inserted.recordId);
    const changedMeta = { ...created.meta, revision: createRevision() };
    await putRawMeta(changedMeta);
    await expect(unlockLocalWorkspace(changedMeta, originalPassphrase)).rejects.toMatchObject({
      code: "INVALID_PASSPHRASE",
    });
  });

  it("authenticates the current stored snapshot before blessing any mutation", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const raw = await readRawDatabase();
    const settings = (raw.records as { id: string; ciphertext: string }[]).find(
      (record) => record.id !== created.meta.sentinelRecordId,
    )!;
    await putRawRecord({
      ...settings,
      ciphertext: `${settings.ciphertext[0] === "A" ? "B" : "A"}${settings.ciphertext.slice(1)}`,
    });
    const profile = createAgentProfileRecord(
      { displayName: "Must not be written", walletAddress: "", frameworkLabel: "", purposeNote: "" },
      created.meta.revision,
    );
    await expect(saveWorkspaceRecords(created, [profile])).rejects.toBeInstanceOf(VaultError);
    const after = await readRawDatabase();
    expect(after.meta).toEqual(raw.meta);
    expect(JSON.stringify(after.records)).not.toContain(profile.recordId);
  });

  it("exports logical records under a distinct password and imports into fresh key material", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const profile = createAgentProfileRecord(
      { displayName: "ARCHIVE_CANARY", walletAddress: "", frameworkLabel: "", purposeNote: "" },
      created.meta.revision,
    );
    const saved = await saveWorkspaceRecords(created, [profile]);
    const backup = await exportLocalWorkspace(saved, backupPassphrase);
    expect(JSON.stringify(backup)).not.toContain("ARCHIVE_CANARY");
    await expect(decryptEncryptedBackup(backup, originalPassphrase)).rejects.toBeInstanceOf(VaultError);
    const logical = await decryptEncryptedBackup(backup, backupPassphrase);
    expect(logical.records.some((record) => record.kind === "sentinel")).toBe(false);
    expect(logical.records.some((record) => record.kind === "agent_profile")).toBe(true);
    await expect(
      decryptEncryptedBackup(
        { ...backup, iv: backup.iv === "AAAAAAAAAAAAAAAA" ? "AQAAAAAAAAAAAAAA" : "AAAAAAAAAAAAAAAA" },
        backupPassphrase,
      ),
    ).rejects.toMatchObject({ code: "INVALID_BACKUP" });
    await expect(
      decryptEncryptedBackup(
        { ...backup, kdf: { ...backup.kdf, iterations: 310_000 } },
        backupPassphrase,
      ),
    ).rejects.toMatchObject({ code: "INVALID_BACKUP" });

    await destroyLocalWorkspace();
    const restored = await importLocalWorkspace(
      backup,
      backupPassphrase,
      restoredPassphrase,
      null,
    );
    expect(restored.meta.vaultId).not.toBe(saved.meta.vaultId);
    expect(restored.meta.passphraseWrapper.ciphertext).not.toBe(saved.meta.passphraseWrapper.ciphertext);
    expect(restored.recoverySecret).not.toBe(created.recoverySecret);
    await expect(unlockLocalWorkspace(restored.meta, originalPassphrase)).rejects.toMatchObject({
      code: "INVALID_PASSPHRASE",
    });
    const unlocked = await unlockLocalWorkspace(restored.meta, restoredPassphrase);
    expect(unlocked.records.some((record) => record.kind === "agent_profile")).toBe(true);
  });

  it("refuses to replace a workspace whose revision changed during import verification", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const backup = await exportLocalWorkspace(created, backupPassphrase);
    const profile = createAgentProfileRecord(
      { displayName: "Concurrent save", walletAddress: "", frameworkLabel: "", purposeNote: "" },
      created.meta.revision,
    );
    const saved = await saveWorkspaceRecords(created, [profile]);
    await expect(
      importLocalWorkspace(backup, backupPassphrase, restoredPassphrase, created.meta),
    ).rejects.toMatchObject({ code: "VAULT_CONFLICT" });
    await expect(unlockLocalWorkspace(saved.meta, originalPassphrase)).resolves.toMatchObject({
      meta: { revision: saved.meta.revision },
    });
  });

  it("exports opaque encrypted bytes even when normal validation can no longer unlock them", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const rawBefore = await readRawDatabase();
    const firstRecord = rawBefore.records[0] as { id: string; ciphertext: string };
    await putRawRecord({
      ...firstRecord,
      ciphertext: `${firstRecord.ciphertext[0] === "A" ? "B" : "A"}${firstRecord.ciphertext.slice(1)}`,
    });
    await expect(unlockLocalWorkspace(created.meta, originalPassphrase)).rejects.toBeInstanceOf(VaultError);
    const rescue = await exportOpaqueRescue();
    expect(rescue.magic).toBe("OPENARC-OPAQUE-RESCUE");
    expect(rescue.warning).toBe("ENCRYPTED_RESCUE_NOT_IMPORTABLE_BY_THIS_BUILD");
    expect(JSON.stringify(rescue)).not.toContain(originalPassphrase);
    await expect(decryptEncryptedBackup(rescue, backupPassphrase)).rejects.toBeInstanceOf(VaultError);
  });

  it("validates all records before atomic recovery rotation", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const recovered = await recoverLocalWorkspace(
      created.meta,
      created.recoverySecret,
      restoredPassphrase,
    );
    expect(recovered.recoverySecret).not.toBe(created.recoverySecret);
    await expect(unlockLocalWorkspace(recovered.meta, originalPassphrase)).rejects.toMatchObject({
      code: "INVALID_PASSPHRASE",
    });
    await expect(
      recoverLocalWorkspace(recovered.meta, created.recoverySecret, "another valid password"),
    ).rejects.toMatchObject({ code: "RECOVERY_FAILED" });
    await expect(unlockLocalWorkspace(recovered.meta, restoredPassphrase)).resolves.toMatchObject({
      meta: { vaultId: recovered.meta.vaultId },
    });
  });

  it("rotates the passphrase wrapper without changing logical records or recovery access", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const updated = await updateWorkspacePassphrase(
      created,
      originalPassphrase,
      restoredPassphrase,
    );
    expect(updated.meta.revision).not.toBe(created.meta.revision);
    await expect(unlockLocalWorkspace(updated.meta, originalPassphrase)).rejects.toMatchObject({
      code: "INVALID_PASSPHRASE",
    });
    await expect(unlockLocalWorkspace(updated.meta, restoredPassphrase)).resolves.toMatchObject({
      records: expect.arrayContaining([expect.objectContaining({ kind: "workspace_settings" })]),
    });
    await expect(
      recoverLocalWorkspace(updated.meta, created.recoverySecret, "another rotated passphrase"),
    ).resolves.toMatchObject({ meta: { vaultId: created.meta.vaultId } });
  });

  it("leaves the original wrappers untouched when recovery finds corrupt ciphertext", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const rawBefore = await readRawDatabase();
    const firstRecord = rawBefore.records[0] as { ciphertext: string };
    await putRawRecord({
      ...firstRecord,
      ciphertext: `${firstRecord.ciphertext[0] === "A" ? "B" : "A"}${firstRecord.ciphertext.slice(1)}`,
    });
    await expect(
      recoverLocalWorkspace(created.meta, created.recoverySecret, restoredPassphrase),
    ).rejects.toMatchObject({ code: "RECOVERY_FAILED" });
    const rawAfter = await readRawDatabase();
    expect(rawAfter.meta).toEqual(rawBefore.meta);
  });

  it("rejects orphan relationships before any encrypted write", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const profile = createAgentProfileRecord(
      { displayName: "Orphan test", walletAddress: "", frameworkLabel: "", purposeNote: "" },
      created.meta.revision,
    );
    const invalid = { ...profile, policyRecordIds: [crypto.randomUUID()] };
    expect(() => assertWorkspaceIntegrity([...created.records, invalid])).toThrow(VaultError);
    await expect(saveWorkspaceRecords(created, [invalid])).rejects.toBeInstanceOf(VaultError);
    const snapshot = await readVaultSnapshot(
      created.meta.vaultId,
      created.meta.revision,
      created.meta.coordinationRevision,
    );
    expect(snapshot.records).toHaveLength(2);
  });

  it("rejects evidence cited through the wrong action relationship bucket", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const records = createFixtureWorkspaceRecords(M01_FIXTURES[0]!, created.meta.revision);
    const action = records.find((record) => record.kind === "action_envelope")!;
    if (action.kind !== "action_envelope") throw new Error("missing action fixture");
    const wrongRelationship = {
      ...action,
      action: {
        ...action.action,
        intentEvidenceIds: action.action.settlementEvidenceIds,
        settlementEvidenceIds: action.action.intentEvidenceIds,
      },
    };
    await expect(saveWorkspaceRecords(created, [wrongRelationship, ...records.filter((record) => record !== action)]))
      .rejects.toMatchObject({ code: "INVALID_BACKUP" });
    const snapshot = await readVaultSnapshot(
      created.meta.vaultId,
      created.meta.revision,
      created.meta.coordinationRevision,
    );
    expect(snapshot.records).toHaveLength(2);
  });

  it("rejects cached conclusions that cite absent evidence or policies", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const fixture = M01_FIXTURES[0]!;
    const records = createFixtureWorkspaceRecords(fixture, created.meta.revision);
    const action = records.find((record) => record.kind === "action_envelope")!;
    if (action.kind !== "action_envelope") throw new Error("missing action fixture");
    const result = reconcileAction({
      action: fixture.action,
      evidence: fixture.evidence,
      policies: fixture.policies,
      evaluatedAt: fixture.evaluatedAt,
    });
    const missingEvidenceId = `evd_${"f".repeat(32)}`;
    const missingPolicyId = `pol_${"f".repeat(32)}`;
    const policyEvaluation = {
      ...result.policyEvaluation,
      matchedPolicyIds: [missingPolicyId],
    };
    const invalid = {
      ...action,
      action: {
        ...action.action,
        policyEvaluation,
        reconciliation: {
          ...result,
          evidenceIds: [...result.evidenceIds, missingEvidenceId],
          policyEvaluation,
        },
      },
    };
    await expect(saveWorkspaceRecords(created, [invalid, ...records.filter((record) => record !== action)]))
      .rejects.toMatchObject({ code: "INVALID_BACKUP" });
  });

  it("rejects cached conclusions that cite another action or an unlinked agent policy", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const complete = createFixtureWorkspaceRecords(M01_FIXTURES[0]!, created.meta.revision);
    const missing = createFixtureWorkspaceRecords(M01_FIXTURES[1]!, created.meta.revision);
    const completeAction = complete.find((record) => record.kind === "action_envelope")!;
    const missingEvidence = missing.find((record) => record.kind === "evidence_record")!;
    if (completeAction.kind !== "action_envelope" || missingEvidence.kind !== "evidence_record") {
      throw new Error("missing fixture records");
    }
    const result = reconcileAction({
      action: M01_FIXTURES[0]!.action,
      evidence: M01_FIXTURES[0]!.evidence,
      policies: M01_FIXTURES[0]!.policies,
      evaluatedAt: M01_FIXTURES[0]!.evaluatedAt,
    });
    const crossAction = {
      ...completeAction,
      action: {
        ...completeAction.action,
        policyEvaluation: result.policyEvaluation,
        reconciliation: {
          ...result,
          evidenceIds: [...result.evidenceIds, missingEvidence.evidence.evidenceId],
        },
      },
    };
    await expect(
      saveWorkspaceRecords(created, [
        crossAction,
        ...complete.filter((record) => record !== completeAction),
        ...missing,
      ]),
    ).rejects.toMatchObject({ code: "INVALID_BACKUP" });

    const otherPolicyId = M01_FIXTURES[1]!.policies[0]!.policyId;
    const crossAgentPolicyEvaluation = {
      ...result.policyEvaluation,
      matchedPolicyIds: [otherPolicyId],
    };
    const crossAgentPolicy = {
      ...completeAction,
      action: {
        ...completeAction.action,
        policyEvaluation: crossAgentPolicyEvaluation,
        reconciliation: {
          ...result,
          policyEvaluation: crossAgentPolicyEvaluation,
        },
      },
    };
    await expect(
      saveWorkspaceRecords(created, [
        crossAgentPolicy,
        ...complete.filter((record) => record !== completeAction),
        ...missing,
      ]),
    ).rejects.toMatchObject({ code: "INVALID_BACKUP" });
  });

  it("recomputes cached M01 conclusions and rejects semantically inconsistent evidence", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const fixture = M01_FIXTURES[0]!;
    const records = createFixtureWorkspaceRecords(fixture, created.meta.revision);
    const result = reconcileAction({
      action: fixture.action,
      evidence: fixture.evidence,
      policies: fixture.policies,
      evaluatedAt: fixture.evaluatedAt,
    });
    const unresolvedTerminal = records.map((record) =>
      record.kind === "action_envelope"
        ? {
            ...record,
            action: { ...record.action, policyEvaluation: null, reconciliation: null },
          }
        : record,
    );
    await expect(saveWorkspaceRecords(created, unresolvedTerminal)).rejects.toMatchObject({
      code: "INVALID_BACKUP",
    });
    const inconsistent = records.map((record) => {
      if (record.kind === "action_envelope") {
        return {
          ...record,
          action: {
            ...record.action,
            policyEvaluation: result.policyEvaluation,
            reconciliation: result,
          },
        };
      }
      if (record.kind === "evidence_record" && record.evidence.evidenceType === "settlement") {
        return {
          ...record,
          evidence: {
            ...record.evidence,
            payload: { ...record.evidence.payload, settlementStatus: "failed" },
          },
        };
      }
      return record;
    });
    await expect(saveWorkspaceRecords(created, inconsistent)).rejects.toMatchObject({
      code: "INVALID_BACKUP",
    });
  });

  it("deletes only when the resulting manifest remains coherent", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const profile = createAgentProfileRecord(
      { displayName: "Disposable agent", walletAddress: "", frameworkLabel: "", purposeNote: "" },
      created.meta.revision,
    );
    const saved = await saveWorkspaceRecords(created, [profile]);
    const updated = await deleteWorkspaceRecords(saved, [profile.recordId]);
    const unlocked = await unlockLocalWorkspace(updated.meta, originalPassphrase);
    expect(unlocked.records.some((record) => record.kind === "agent_profile")).toBe(false);
  });

  it("aborts the whole transaction when browser storage rejects a record write", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const profile = createAgentProfileRecord(
      { displayName: "Quota rollback", walletAddress: "", frameworkLabel: "", purposeNote: "" },
      created.meta.revision,
    );
    const originalPut = IDBObjectStore.prototype.put;
    let putCalls = 0;
    IDBObjectStore.prototype.put = function mockedPut(...args: Parameters<IDBObjectStore["put"]>) {
      putCalls += 1;
      if (putCalls === 2) throw new DOMException("quota full", "QuotaExceededError");
      return originalPut.apply(this, args);
    };
    try {
      await expect(saveWorkspaceRecords(created, [profile])).rejects.toMatchObject({
        name: "QuotaExceededError",
      });
    } finally {
      IDBObjectStore.prototype.put = originalPut;
    }
    const snapshot = await readVaultSnapshot(
      created.meta.vaultId,
      created.meta.revision,
      created.meta.coordinationRevision,
    );
    expect(snapshot.meta.revision).toBe(created.meta.revision);
    expect(snapshot.records).toHaveLength(2);
  });

  it("checks the live session inside the transaction before committing a late write", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const profile = createAgentProfileRecord(
      { displayName: "Late write", walletAddress: "", frameworkLabel: "", purposeNote: "" },
      created.meta.revision,
    );
    await expect(
      saveWorkspaceRecords(created, [profile], () => {
        throw new Error("session locked");
      }),
    ).rejects.toThrow("session locked");
    const snapshot = await readVaultSnapshot(
      created.meta.vaultId,
      created.meta.revision,
      created.meta.coordinationRevision,
    );
    expect(snapshot.meta.revision).toBe(created.meta.revision);
    expect(snapshot.records).toHaveLength(2);
  });

  it("aborts a transaction when the session ends after its final active check", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const profile = createAgentProfileRecord(
      { displayName: "Abort between put and commit", walletAddress: "", frameworkLabel: "", purposeNote: "" },
      created.meta.revision,
    );
    const controller = new AbortController();
    await expect(
      saveWorkspaceRecords(
        created,
        [profile],
        () => queueMicrotask(() => controller.abort(new Error("session locked before commit"))),
        controller.signal,
      ),
    ).rejects.toThrow("session locked before commit");
    const snapshot = await readVaultSnapshot(
      created.meta.vaultId,
      created.meta.revision,
      created.meta.coordinationRevision,
    );
    expect(snapshot.records).toHaveLength(2);
  });

  it("does not commit a verified import after its initiating session is invalidated", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const backup = await exportLocalWorkspace(created, backupPassphrase);
    await destroyLocalWorkspace();
    await expect(
      importLocalWorkspace(backup, backupPassphrase, restoredPassphrase, null, () => {
        throw new Error("session left");
      }),
    ).rejects.toThrow("session left");
    expect((await readRawDatabase()).meta).toBeUndefined();
  });

  it("rejects an oversized backup before reading or deriving from it", async () => {
    let textCalled = false;
    const oversized = {
      size: 32 * 1024 * 1024 + 1,
      text: async () => {
        textCalled = true;
        return "{}";
      },
    } as File;
    await expect(parseBackupFile(oversized)).rejects.toMatchObject({ code: "INVALID_BACKUP" });
    expect(textCalled).toBe(false);
  });

  it("enforces the per-kind record ceiling before encryption", () => {
    const record = createAgentProfileRecord(
      { displayName: "Bounded", walletAddress: "", frameworkLabel: "", purposeNote: "" },
      "A".repeat(32),
    );
    expect(() => assertWorkspaceRecordCapacity(Array.from({ length: 101 }, () => record))).toThrow(
      /agent_profile limit is 100/u,
    );
  });

  it("keeps receipt and combined capacities inside the unchanged manifest ceiling", () => {
    const fake = (kind: WorkspaceRecord["kind"], count: number) => Array.from({ length: count }, () => ({ kind })) as WorkspaceRecord[];
    expect(() => assertWorkspaceRecordCapacity(fake("permission_receipt", 1_001))).toThrow(/permission_receipt limit is 1000/u);
    expect(() => assertWorkspaceRecordCapacity(fake("arc_observation", 1_001))).toThrow(/arc_observation limit is 1000/u);
    const maximum = [...fake("evidence_record", 5_000), ...fake("action_envelope", 600),
      ...fake("permission_receipt", 1_000), ...fake("workspace_settings", 1), ...fake("sentinel", 1)];
    expect(maximum).toHaveLength(6_602);
    expect(() => assertWorkspaceRecordCapacity(maximum)).not.toThrow();
    expect(() => assertWorkspaceRecordCapacity([...maximum, ...fake("agent_profile", 1)])).toThrow(/6602 total records/u);
  });

  it("encrypts, unlocks, exports, imports, recovers, and deletes mixed M02/M03 receipt records", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const at = "2026-09-03T12:00:00Z";
    const receipt = PermissionReceiptRecordSchema.parse({ recordSchema: "openarc.permission-receipt.v1",
      kind: "permission_receipt", recordId: crypto.randomUUID(), recordRevision: created.meta.revision,
      createdAt: at, updatedAt: at, connectorId: CAPABILITY_DISCLOSURE.connectorId,
      destination: { origin: "https://private-origin-canary.example.test", path: "/v1/private/capabilities", method: "GET", upstreams: [] },
      releasedFields: [], purpose: CAPABILITY_DISCLOSURE.purpose, credentials: CAPABILITY_DISCLOSURE.credentials,
      openArcRetention: CAPABILITY_DISCLOSURE.openArcRetention, providerRetention: CAPABILITY_DISCLOSURE.providerRetention,
      hostingMetadata: CAPABILITY_DISCLOSURE.hostingMetadata, approvedAt: at, outcome: "approved", resolvedAt: null, failureCode: null });
    const saved = await saveWorkspaceRecords(created, [receipt]);
    expect(JSON.stringify(await readRawDatabase())).not.toContain("private-origin-canary");
    const unlocked = await unlockLocalWorkspace(saved.meta, originalPassphrase);
    expect(unlocked.records).toContainEqual(expect.objectContaining({ kind: "permission_receipt", outcome: "approved" }));
    const backup = await exportLocalWorkspace(unlocked, backupPassphrase);
    expect(JSON.stringify(backup)).not.toContain("private-origin-canary");
    const imported = await importLocalWorkspace(backup, backupPassphrase, restoredPassphrase, saved.meta);
    expect(imported.records).toContainEqual(expect.objectContaining({ kind: "permission_receipt", outcome: "approved" }));
    const recovered = await recoverLocalWorkspace(imported.meta, imported.recoverySecret, originalPassphrase);
    expect(recovered.records).toContainEqual(expect.objectContaining({ recordId: receipt.recordId, kind: "permission_receipt" }));
    const deleted = await deleteWorkspaceRecords(recovered, [receipt.recordId]);
    expect(deleted.records.some((record) => record.kind === "permission_receipt")).toBe(false);
  });

  it("encrypts, exports, imports, recovers, and coherently deletes an M04 receipt and observation", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const records = m04AccountRecords(created.meta.revision);
    const saved = await saveWorkspaceRecords(created, [records.receipt, records.observation]);
    const raw = JSON.stringify(await readRawDatabase());
    expect(raw).not.toContain(records.address);
    expect(raw).not.toContain(ARC_TESTNET.rpcHttp);

    const unlocked = await unlockLocalWorkspace(saved.meta, originalPassphrase);
    expect(unlocked.records).toContainEqual(expect.objectContaining({
      kind: "arc_observation", permissionReceiptId: records.receipt.recordId,
    }));
    const backup = await exportLocalWorkspace(unlocked, backupPassphrase);
    expect(JSON.stringify(backup)).not.toContain(records.address);
    const imported = await importLocalWorkspace(backup, backupPassphrase, restoredPassphrase, saved.meta);
    const recovered = await recoverLocalWorkspace(imported.meta, imported.recoverySecret, originalPassphrase);
    expect(recovered.records).toContainEqual(expect.objectContaining({ recordId: records.observation.recordId }));
    await expect(deleteWorkspaceRecords(recovered, [records.receipt.recordId]))
      .rejects.toMatchObject({ code: "INVALID_BACKUP" });
    const deleted = await deleteWorkspaceRecords(recovered, [records.receipt.recordId, records.observation.recordId]);
    expect(deleted.records.some((record) => record.kind === "arc_observation")).toBe(false);
  });

  it("leaves prior encrypted observation bytes unchanged when an explicit refresh source fails", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const records = m04AccountRecords(created.meta.revision);
    const saved = await saveWorkspaceRecords(created, [records.receipt, records.observation]);
    const before = await readRawDatabase();
    const beforeEnvelope = before.records.find((candidate) =>
      (candidate as { id?: string }).id === records.observation.recordId);
    const controller = new AbortController();
    await expect(runArcObservationPermissionFlow({ workspace: saved, origin: "https://app.example.test",
      input: { kind: "account", request: { network: ARC_TESTNET.caip2, address: records.address } },
      signal: controller.signal, assertActive: () => undefined, save: saveWorkspaceRecords,
      request: async () => { throw new OpenArcRequestError("SOURCE_UNAVAILABLE", "post-send"); },
    })).rejects.toMatchObject({ code: "SOURCE_UNAVAILABLE" });
    const after = await readRawDatabase();
    const afterEnvelope = after.records.find((candidate) =>
      (candidate as { id?: string }).id === records.observation.recordId);
    expect(afterEnvelope).toEqual(beforeEnvelope);
    const currentMeta = await readVaultMeta();
    if (!currentMeta) throw new Error("expected active vault");
    const unlocked = await unlockLocalWorkspace(currentMeta, originalPassphrase);
    expect(unlocked.records).toContainEqual(expect.objectContaining({ recordId: records.observation.recordId }));
    expect(unlocked.records).toContainEqual(expect.objectContaining({
      kind: "permission_receipt", recordSchema: "openarc.permission-receipt.v2",
      connectorId: "arc_account_snapshot", outcome: "failed",
    }));
  });

  it("rejects orphan, mismatched, and duplicate M04 observation relationships before encryption", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const records = m04AccountRecords(created.meta.revision);
    const mismatched = { ...records.observation,
      observation: { ...records.observation.observation,
        address: "0x2222222222222222222222222222222222222222" } };
    for (const changes of [
      [records.observation],
      [records.receipt, mismatched],
      [records.receipt, records.observation, { ...records.observation, recordId: crypto.randomUUID() }],
    ]) await expect(saveWorkspaceRecords(created, changes)).rejects.toMatchObject({ code: "INVALID_BACKUP" });
    expect((await readRawDatabase()).records).toHaveLength(2);
  });

  it("encrypts M05 registry evidence and enforces its receipt and optional local-profile links", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const profile = createAgentProfileRecord({ displayName: "PRIVATE_REGISTRY_LABEL", walletAddress: "",
      frameworkLabel: "PRIVATE_FRAMEWORK", purposeNote: "PRIVATE_NOTE" }, created.meta.revision);
    const records = m05RegistryRecords(created.meta.revision, profile.recordId);
    const saved = await saveWorkspaceRecords(created, [profile, records.receipt, records.observation]);
    const raw = JSON.stringify(await readRawDatabase());
    expect(raw).not.toContain("PRIVATE_REGISTRY_LABEL");
    expect(raw).not.toContain(records.observation.observation.identity.owner);
    expect(raw).not.toContain(ARC_TESTNET.rpcHttp);
    await expect(deleteWorkspaceRecords(saved, [profile.recordId])).rejects.toMatchObject({ code: "INVALID_BACKUP" });
    await expect(deleteWorkspaceRecords(saved, [records.receipt.recordId])).rejects.toMatchObject({ code: "INVALID_BACKUP" });
    const deletedEvidence = await deleteWorkspaceRecords(saved, [records.receipt.recordId, records.observation.recordId]);
    const deletedProfile = await deleteWorkspaceRecords(deletedEvidence, [profile.recordId]);
    expect(deletedProfile.records.some((record) => record.kind === "agent_registry_observation")).toBe(false);
  });

  it("rejects orphaned or mismatched M05 registry evidence before encryption", async () => {
    const created = await createLocalWorkspace(originalPassphrase);
    const records = m05RegistryRecords(created.meta.revision);
    const mismatched = { ...records.observation,
      observation: { ...records.observation.observation, agentId: "2" } };
    for (const changes of [
      [records.observation],
      [records.receipt, mismatched],
      [records.receipt, records.observation, { ...records.observation, recordId: crypto.randomUUID() }],
    ]) await expect(saveWorkspaceRecords(created, changes)).rejects.toMatchObject({ code: "INVALID_BACKUP" });
  });
});

describe("M02 static privacy boundary", () => {
  it("contains no network, plaintext fallback, wallet, signing, or analytics APIs", async () => {
    const directory = path.resolve(import.meta.dirname, "../src/vault");
    const sources = await Promise.all(
      (await readdir(directory))
        .filter((file) => /\.(ts|tsx)$/u.test(file))
        .map(async (file) => `${file}\n${await readFile(path.join(directory, file), "utf8")}`),
    );
    const source = sources.join("\n");
    for (const token of [
      "fetch(",
      "XMLHttpRequest",
      "WebSocket",
      "EventSource",
      "sendBeacon",
      "localStorage",
      "sessionStorage",
      "document.cookie",
      "dangerouslySetInnerHTML",
      "src=\"http",
      "src={'http",
      'src={"http',
      "ethereum.request",
      "signMessage",
      "sendTransaction",
      "broadcastTransaction",
    ]) {
      expect(source).not.toContain(token);
    }
  });

  it("ships the production feature disabled with a local-only workspace CSP", async () => {
    const [dockerfile, nginx, workflow, productionTest] = await Promise.all([
      readFile(path.resolve(import.meta.dirname, "../Dockerfile"), "utf8"),
      readFile(path.resolve(import.meta.dirname, "../nginx.conf"), "utf8"),
      readFile(path.resolve(import.meta.dirname, "../../../docs/engineering/release-gates.reference.yml"), "utf8"),
      readFile(path.resolve(import.meta.dirname, "../../../e2e-production/workspace-production.spec.ts"), "utf8"),
    ]);
    expect(dockerfile).toContain("ARG VITE_ENCRYPTED_WORKSPACE_ENABLED=false");
    expect(nginx).toContain("connect-src 'none'");
    expect(nginx).toContain("worker-src 'none'");
    expect(nginx).toContain("object-src 'none'");
    expect(nginx).toContain('Strict-Transport-Security "max-age=31536000; includeSubDomains" always');
    expect(workflow).toContain("VITE_ENCRYPTED_WORKSPACE_ENABLED=true");
    expect(workflow).toContain("pnpm e2e:production");
    expect(productionTest).toContain("connect-src 'none'");
    expect(productionTest).toContain("PRODUCTION_ARTIFACT_PRIVATE_CANARY");
  });
});

async function readRawDatabase(): Promise<{ meta: unknown; records: unknown[] }> {
  const db = await openDatabase();
  try {
    const transaction = db.transaction(["vaultMeta", "records"], "readonly");
    const meta = await requestResult(transaction.objectStore("vaultMeta").get("active"));
    const records = await requestResult<unknown[]>(transaction.objectStore("records").getAll());
    return { meta, records };
  } finally {
    db.close();
  }
}

async function deleteRawRecord(recordId: string): Promise<void> {
  const db = await openDatabase();
  try {
    const transaction = db.transaction("records", "readwrite");
    transaction.objectStore("records").delete(recordId);
    await transactionDone(transaction);
  } finally {
    db.close();
  }
}

async function putRawRecord(record: unknown): Promise<void> {
  const db = await openDatabase();
  try {
    const transaction = db.transaction("records", "readwrite");
    transaction.objectStore("records").put(record);
    await transactionDone(transaction);
  } finally {
    db.close();
  }
}

async function putRawMeta(meta: unknown): Promise<void> {
  const db = await openDatabase();
  try {
    const transaction = db.transaction("vaultMeta", "readwrite");
    transaction.objectStore("vaultMeta").put(meta);
    await transactionDone(transaction);
  } finally {
    db.close();
  }
}

async function deleteRawMeta(): Promise<void> {
  const db = await openDatabase();
  try {
    const transaction = db.transaction("vaultMeta", "readwrite");
    transaction.objectStore("vaultMeta").delete("active");
    await transactionDone(transaction);
  } finally {
    db.close();
  }
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(VAULT_DATABASE_NAME, 1);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function requestResult<T = unknown>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(transaction.error);
    transaction.onerror = () => reject(transaction.error);
  });
}

function deleteDatabase(): Promise<void> {
  return new Promise((resolve) => {
    const request = indexedDB.deleteDatabase(VAULT_DATABASE_NAME);
    request.onsuccess = () => resolve();
    request.onerror = () => resolve();
    request.onblocked = () => resolve();
  });
}

function deleteDatabaseStrict(): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(VAULT_DATABASE_NAME);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
    request.onblocked = () => reject(new Error("Test database deletion was blocked"));
  });
}

function createObserverDatabaseDouble(): {
  database: IDBDatabase;
  emitClose: () => void;
  emitVersionChange: () => void;
} {
  const database = {
    onclose: null,
    onversionchange: null,
    close: () => undefined,
  } as unknown as IDBDatabase;
  return {
    database,
    emitClose: () => database.onclose?.(new Event("close")),
    emitVersionChange: () =>
      database.onversionchange?.(
        new IDBVersionChangeEvent("versionchange", { oldVersion: 1, newVersion: 2 }),
      ),
  };
}
