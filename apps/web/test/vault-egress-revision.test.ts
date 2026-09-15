import "fake-indexeddb/auto";

import { ARC_TESTNET, type CapabilitiesEnvelope, type WorkspaceRecord } from "@openarc/shared";
import { afterEach, describe, expect, it, vi } from "vitest";

import { JOB_TEST_REQUEST } from "../../../test-fixtures/job-evidence.js";
import { runAgentRegistryPermissionFlow } from "../src/api/agent-registry-permission-flow.js";
import { runArcObservationPermissionFlow } from "../src/api/arc-permission-flow.js";
import { runGatewayPermissionFlow } from "../src/api/gateway-permission-flow.js";
import { runJobPermissionFlow } from "../src/api/job-permission-flow.js";
import { runCapabilityPermissionFlow } from "../src/api/permission-flow.js";
import { GATEWAY_TEST_REQUEST } from "./gateway-test-fixtures.js";
import {
  VAULT_DATABASE_NAME,
  markVaultDeleting,
  readOpaqueVaultSnapshot,
  readVaultMeta,
  signalVaultLock,
} from "../src/vault/db.js";
import { assertStoredWorkspaceRevision } from "../src/vault/revision-guard.js";
import {
  createAgentProfileRecord,
  createLocalWorkspace,
  saveWorkspaceRecords,
  unlockLocalWorkspace,
} from "../src/vault/service.js";
import type { UnlockedWorkspace } from "../src/vault/types.js";

vi.setConfig({ testTimeout: 60_000 });

const passphrase = "egress recheck passphrase 42";
const origin = "https://app.example.test";

afterEach(async () => {
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase(VAULT_DATABASE_NAME);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
    request.onblocked = () => resolve();
  });
});

type PeerChange = (saved: UnlockedWorkspace) => Promise<unknown>;
const peerChanges: [string, PeerChange][] = [
  ["peer lock signal", (saved) => signalVaultLock(saved.meta)],
  ["peer save", (saved) => saveWorkspaceRecords(saved, [createAgentProfileRecord(
    { displayName: "Peer", walletAddress: "", frameworkLabel: "", purposeNote: "" }, saved.meta.revision)])],
  ["peer deletion marker", (saved) => markVaultDeleting(saved.meta.vaultId)],
];

/** Commits the approval like the workspace does, then lets a silent peer commit (no broadcast). */
function saveThenPeer(peer: PeerChange | null) {
  return async (workspace: UnlockedWorkspace, records: readonly WorkspaceRecord[], assertActive: () => void, signal: AbortSignal) => {
    const saved = await saveWorkspaceRecords(workspace, records, assertActive, signal);
    if (peer) await peer(saved);
    return saved;
  };
}

describe("P08-02 durable pre-egress Vault revision recheck", () => {
  it.each(peerChanges)("capability flow sends nothing after a silent %s", async (_name, peer) => {
    const created = await createLocalWorkspace(passphrase);
    const request = vi.fn(async () => ({ ok: true }) as unknown as CapabilitiesEnvelope);
    await expect(runCapabilityPermissionFlow({ workspace: created, origin, signal: new AbortController().signal,
      assertActive: () => undefined, save: saveThenPeer(peer), onCommitted: () => undefined,
      verifyStored: (workspace) => assertStoredWorkspaceRevision(workspace), request }))
      .rejects.toMatchObject({ code: "VAULT_CONFLICT" });
    expect(request).not.toHaveBeenCalled();
  });

  it.each(peerChanges)("Arc observation flow sends nothing after a silent %s", async (_name, peer) => {
    const created = await createLocalWorkspace(passphrase);
    const request = vi.fn(async () => { throw new Error("must not be called"); });
    await expect(runArcObservationPermissionFlow({ workspace: created, origin, signal: new AbortController().signal,
      input: { kind: "account", request: { network: ARC_TESTNET.caip2, address: "0x1111111111111111111111111111111111111111" } },
      assertActive: () => undefined, save: saveThenPeer(peer),
      verifyStored: (workspace) => assertStoredWorkspaceRevision(workspace), request }))
      .rejects.toMatchObject({ code: "VAULT_CONFLICT" });
    expect(request).not.toHaveBeenCalled();
  });

  it("keeps the committed approval as the audit trail when egress is refused", async () => {
    const created = await createLocalWorkspace(passphrase);
    await expect(runCapabilityPermissionFlow({ workspace: created, origin, signal: new AbortController().signal,
      assertActive: () => undefined, save: saveThenPeer((saved) => signalVaultLock(saved.meta)), onCommitted: () => undefined,
      verifyStored: (workspace) => assertStoredWorkspaceRevision(workspace), request: vi.fn() })).rejects.toThrow();
    const meta = await readVaultMeta();
    const unlocked = await unlockLocalWorkspace(meta!, passphrase);
    expect(unlocked.records.filter((record) => record.kind === "permission_receipt"))
      .toEqual([expect.objectContaining({ outcome: "approved" })]);
  });

  it("an unchanged stored revision proceeds to exactly one request", async () => {
    const created = await createLocalWorkspace(passphrase);
    const capabilities = { ok: true } as unknown as CapabilitiesEnvelope;
    const request = vi.fn(async () => capabilities);
    await expect(runCapabilityPermissionFlow({ workspace: created, origin, signal: new AbortController().signal,
      assertActive: () => undefined, save: saveThenPeer(null), onCommitted: () => undefined,
      verifyStored: (workspace) => assertStoredWorkspaceRevision(workspace), request }))
      .resolves.toMatchObject({ capabilities });
    expect(request).toHaveBeenCalledOnce();
  });

  type SaveRecords = ReturnType<typeof saveThenPeer>;
  type EvidenceFlowRun = (options: { workspace: UnlockedWorkspace; save: SaveRecords;
    fetch: (...args: unknown[]) => Promise<never> }) => Promise<unknown>;
  const evidenceFlows: [string, string, EvidenceFlowRun][] = [
    ["ERC-8004 agent registry", "arc_agent_registry_evidence", ({ workspace, save, fetch }) => runAgentRegistryPermissionFlow({
      workspace, origin, request: { network: ARC_TESTNET.caip2, agentId: "1" }, linkedAgentProfileRecordId: null,
      signal: new AbortController().signal, assertActive: () => undefined, save,
      verifyStored: (current) => assertStoredWorkspaceRevision(current), fetch })],
    ["ERC-8183 job", "arc_job_evidence", ({ workspace, save, fetch }) => runJobPermissionFlow({
      workspace, origin, request: JOB_TEST_REQUEST, linkedActionRecordId: null,
      signal: new AbortController().signal, assertActive: () => undefined, save,
      verifyStored: (current) => assertStoredWorkspaceRevision(current), fetch })],
    ["Circle Gateway transfer", "circle_gateway_transfer", ({ workspace, save, fetch }) => runGatewayPermissionFlow({
      workspace, origin, request: GATEWAY_TEST_REQUEST, linkedBundleRecordId: null,
      signal: new AbortController().signal, assertActive: () => undefined, save,
      verifyStored: (current) => assertStoredWorkspaceRevision(current), fetch })],
  ];

  const evidenceCases = evidenceFlows.flatMap(([flow, connectorId, run]) =>
    peerChanges.map(([change, peer]) => [flow, change, connectorId, run, peer] as const));

  it.each(evidenceCases)("%s flow sends nothing after a silent %s and keeps the approval", async (_flow, _change, connectorId, run, peer) => {
    const created = await createLocalWorkspace(passphrase);
    const fetch = vi.fn(async () => { throw new Error("must not be called"); });
    const commits: { workspace: UnlockedWorkspace; storedRecordCount: number }[] = [];
    const save: SaveRecords = async (workspace, records, assertActive, signal) => {
      const saved = await saveWorkspaceRecords(workspace, records, assertActive, signal);
      commits.push({ workspace: saved, storedRecordCount: (await readOpaqueVaultSnapshot()).records.length });
      await peer(saved);
      return saved;
    };
    await expect(run({ workspace: created, save, fetch })).rejects.toMatchObject({ code: "VAULT_CONFLICT" });
    expect(fetch).not.toHaveBeenCalled();

    // Exactly one commit happened: the approval. The refusal wrote nothing else.
    expect(commits).toHaveLength(1);
    const [commit] = commits;
    expect(commit!.workspace.records.filter((record) => record.kind === "permission_receipt"))
      .toEqual([expect.objectContaining({ connectorId, outcome: "approved" })]);
    const meta = await readVaultMeta();
    if (meta!.deletionPending) {
      // A pending deletion refuses every unlock by design; prove the committed
      // approval was not rolled back from the durable revision and ciphertext.
      expect(meta).toMatchObject({ vaultId: commit!.workspace.meta.vaultId, revision: commit!.workspace.meta.revision });
      expect((await readOpaqueVaultSnapshot()).records).toHaveLength(commit!.storedRecordCount);
      return;
    }
    const unlocked = await unlockLocalWorkspace(meta!, passphrase);
    expect(unlocked.records.filter((record) => record.kind === "permission_receipt"))
      .toEqual([expect.objectContaining({ connectorId, outcome: "approved" })]);
  });

  it.each(evidenceFlows)("%s flow with an unchanged stored revision sends exactly one request", async (_flow, _connectorId, run) => {
    const created = await createLocalWorkspace(passphrase);
    const sentinel = new Error("request reached the network boundary");
    const fetch = vi.fn(async () => { throw sentinel; });
    await expect(run({ workspace: created, save: saveThenPeer(null), fetch })).rejects.toBe(sentinel);
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("refuses when the Vault disappeared or was replaced", async () => {
    const created = await createLocalWorkspace(passphrase);
    await expect(assertStoredWorkspaceRevision(created, async () => null)).rejects.toMatchObject({ code: "VAULT_CONFLICT" });
    await expect(assertStoredWorkspaceRevision(created, async () => ({ ...created.meta, vaultId: crypto.randomUUID() })))
      .rejects.toMatchObject({ code: "VAULT_CONFLICT" });
    await expect(assertStoredWorkspaceRevision(created)).resolves.toBeUndefined();
  });
});
