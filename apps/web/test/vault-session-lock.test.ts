import "fake-indexeddb/auto";

import { readFile } from "node:fs/promises";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { AccountApiError } from "../src/account/auth-client.js";
import { logoutFailureLocksVault } from "../src/account/logout-vault-lock.js";
import {
  VAULT_LOCK_ATTENTION_NOTICE,
  VaultSessionEndWatcher,
  lockVaultOnSessionEnd,
  subscribeVaultSessionEnd,
  vaultLockNeedsAttention,
} from "../src/app/vault-session-lock.js";
import {
  VAULT_COORDINATION_CHANNEL,
  handleCoordinationMessage,
  handleLocalSessionEnd,
  type CoordinationTarget,
  type VaultScreen,
} from "../src/vault/coordination.js";
import { VAULT_DATABASE_NAME, readVaultMeta } from "../src/vault/db.js";
import { defaultSessionBridgeDeps, lockVaultForSessionEnd } from "../src/vault/session-bridge.js";
import {
  createAgentProfileRecord,
  createLocalWorkspace,
  saveWorkspaceRecords,
  signalWorkspaceLock,
  unlockLocalWorkspace,
} from "../src/vault/service.js";
import type { PublicVaultMeta, UnlockedWorkspace } from "../src/vault/types.js";

vi.setConfig({ testTimeout: 60_000 });

const passphrase = "session bridge passphrase 42";
const CANARY = "P0802_PRIVATE_PLAINTEXT_CANARY";
const open: { close: () => void }[] = [];

afterEach(async () => {
  vi.unstubAllGlobals();
  open.splice(0).forEach((item) => item.close());
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase(VAULT_DATABASE_NAME);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
    request.onblocked = () => resolve();
  });
});

function listen(): unknown[] {
  const messages: unknown[] = [];
  const channel = new BroadcastChannel(VAULT_COORDINATION_CHANNEL);
  channel.onmessage = (event: MessageEvent<unknown>) => messages.push(event.data);
  open.push(channel);
  return messages;
}

async function storedMeta(): Promise<PublicVaultMeta> {
  const meta = await readVaultMeta();
  if (!meta) throw new Error("missing meta");
  return meta;
}

async function unlockedWithCanary(): Promise<UnlockedWorkspace> {
  const created = await createLocalWorkspace(passphrase);
  const profile = createAgentProfileRecord(
    { displayName: CANARY, walletAddress: "", frameworkLabel: "", purposeNote: "" },
    created.meta.revision,
  );
  const saved = await saveWorkspaceRecords(created, [profile]);
  return unlockLocalWorkspace(saved.meta, passphrase);
}

/** One mounted workspace view, holding refs exactly like VaultWorkspace does. */
function mountTab(workspace: UnlockedWorkspace, options: { sameDocument: boolean; channel: boolean }) {
  const state = {
    unlocked: workspace as UnlockedWorkspace | null,
    screen: { phase: "unlocked", workspace } as VaultScreen,
    generation: 0,
    notice: null as string | null,
  };
  const sender = crypto.randomUUID();
  const target: CoordinationTarget = {
    sender: () => sender,
    unlocked: () => state.unlocked,
    screen: () => state.screen,
    generation: () => state.generation,
    clearPrivateState: (next, message) => {
      state.generation += 1;
      state.unlocked = null;
      state.screen = next;
      state.notice = message ?? null;
    },
    setScreen: (next) => { state.screen = next; },
    setNotice: (message) => { state.notice = message; },
    readMeta: readVaultMeta,
  };
  if (options.channel) {
    const channel = new BroadcastChannel(VAULT_COORDINATION_CHANNEL);
    channel.onmessage = (event: MessageEvent<unknown>) => handleCoordinationMessage(event.data, target);
    open.push(channel);
  }
  if (options.sameDocument) open.push({ close: subscribeVaultSessionEnd(() => handleLocalSessionEnd(target)) });
  return state;
}

function expectNoPlaintext(state: { unlocked: unknown; screen: unknown; notice: unknown }) {
  expect(state.unlocked).toBeNull();
  expect(JSON.stringify(state)).not.toContain(CANARY);
}

describe("P08-02 account session end locks the Vault in every tab", () => {
  it("logout reads metadata, writes the manual-lock signal and broadcasts the existing lock message", async () => {
    const created = await createLocalWorkspace(passphrase);
    const messages = listen();
    const watcher = new VaultSessionEndWatcher();
    expect(watcher.observe("account-a")).toBeNull();

    await expect(watcher.logout("logout")).resolves.toBe("locked");

    const after = await storedMeta();
    expect(after).toMatchObject({ vaultId: created.meta.vaultId, revision: created.meta.revision, deletionPending: false });
    expect(after.coordinationRevision).not.toBe(created.meta.coordinationRevision);
    expect(Object.keys(after).sort()).toEqual(Object.keys(created.meta).sort());
    await vi.waitFor(() => expect(messages).toHaveLength(1));
    expect(Object.keys(messages[0] as object).sort()).toEqual(["sender", "type", "vaultId"]);
    expect(messages[0]).toMatchObject({ type: "lock", vaultId: created.meta.vaultId });
    // Logout never deletes or rewrites records: the same passphrase still unlocks.
    await expect(unlockLocalWorkspace(after, passphrase)).resolves.toMatchObject({ meta: { vaultId: created.meta.vaultId } });
    // The follow-up reset to guest for the same account does not lock twice.
    expect(watcher.observe(null)).toBeNull();
  });

  it("a logout whose request was sent but not confirmed still locks", async () => {
    const created = await createLocalWorkspace(passphrase);
    expect(logoutFailureLocksVault(true, new AccountApiError({ kind: "outcome-unknown" }))).toBe(true);
    expect(logoutFailureLocksVault(true, new AccountApiError({ kind: "aborted" }))).toBe(true);
    expect(logoutFailureLocksVault(true, new AccountApiError({ kind: "server", code: "UNAUTHENTICATED" } as never))).toBe(true);
    expect(logoutFailureLocksVault(true, new AccountApiError({ kind: "pre-send" }))).toBe(false);
    expect(logoutFailureLocksVault(false, new AccountApiError({ kind: "account-changed" }))).toBe(false);
    const watcher = new VaultSessionEndWatcher();
    watcher.observe("account-a");
    await expect(watcher.logout("logout-unconfirmed")).resolves.toBe("locked");
    expect((await storedMeta()).coordinationRevision).not.toBe(created.meta.coordinationRevision);
  });

  it("an account switch locks", async () => {
    const created = await createLocalWorkspace(passphrase);
    const messages = listen();
    const statuses: string[] = [];
    const watcher = new VaultSessionEndWatcher({ onStatus: (status) => statuses.push(status) });
    watcher.observe("account-a");
    await expect(watcher.observe("account-b")).resolves.toBe("locked");
    expect(statuses).toEqual(["locked"]);
    expect((await storedMeta()).coordinationRevision).not.toBe(created.meta.coordinationRevision);
    await vi.waitFor(() => expect(messages).toEqual([expect.objectContaining({ type: "lock", vaultId: created.meta.vaultId })]));
  });

  it("a detected session expiry (account to guest) locks", async () => {
    const created = await createLocalWorkspace(passphrase);
    const watcher = new VaultSessionEndWatcher();
    watcher.observe("account-a");
    await expect(watcher.observe(null)).resolves.toBe("locked");
    expect((await storedMeta()).coordinationRevision).not.toBe(created.meta.coordinationRevision);
  });

  it("first observation, login, same-account refresh and unmount never lock", () => {
    const lock = vi.fn(async () => "locked" as const);
    const watcher = new VaultSessionEndWatcher({ lock });
    expect(watcher.observe(null)).toBeNull();
    expect(watcher.observe("account-a")).toBeNull();
    expect(watcher.observe("account-a")).toBeNull();
    watcher.dispose();
    expect(watcher.observe(null)).toBeNull();
    watcher.resume();
    expect(watcher.observe("account-a")).toBeNull();
    expect(lock).not.toHaveBeenCalled();
  });

  it("does nothing and creates nothing when no Vault exists", async () => {
    const messages = listen();
    await expect(lockVaultOnSessionEnd("logout")).resolves.toBe("no-vault");
    expect((await indexedDB.databases()).map((database) => database.name)).not.toContain(VAULT_DATABASE_NAME);
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(messages).toEqual([]);
    expect(vaultLockNeedsAttention("no-vault")).toBe(false);
  });

  it("IndexedDB unavailable: logout still resolves, this tab drops plaintext, status is non-secret", async () => {
    const workspace = await unlockedWithCanary();
    const tab = mountTab(workspace, { sameDocument: true, channel: false });
    vi.stubGlobal("indexedDB", undefined);

    await expect(lockVaultOnSessionEnd("session-expired")).resolves.toBe("storage-unavailable");

    expectNoPlaintext(tab);
    await vi.waitFor(() => expect(tab.screen.phase).toBe("fatal"));
    expectNoPlaintext(tab);
    expect(vaultLockNeedsAttention("storage-unavailable")).toBe(true);
    expect(VAULT_LOCK_ATTENTION_NOTICE).not.toContain(workspace.meta.vaultId);
  });

  it("a throwing lock write still broadcasts lock and reports the failure", async () => {
    const created = await createLocalWorkspace(passphrase);
    const messages = listen();
    const status = await lockVaultForSessionEnd({
      ...defaultSessionBridgeDeps,
      signalLock: async () => { throw new DOMException("quota", "QuotaExceededError"); },
    });
    expect(status).toBe("lock-write-failed");
    await vi.waitFor(() => expect(messages).toEqual([expect.objectContaining({ type: "lock", vaultId: created.meta.vaultId })]));
    expect((await storedMeta()).coordinationRevision).toBe(created.meta.coordinationRevision);
  });

  it("storage that never answers cannot block logout", async () => {
    const started = Date.now();
    await expect(lockVaultOnSessionEnd("logout", { timeoutMs: 25, loadBridge: () => new Promise(() => undefined) }))
      .resolves.toBe("timeout");
    expect(Date.now() - started).toBeLessThan(1_000);
  });

  it("without BroadcastChannel the durable lock signal is still written for polling tabs", async () => {
    const created = await createLocalWorkspace(passphrase);
    vi.stubGlobal("BroadcastChannel", undefined);
    await expect(lockVaultOnSessionEnd("logout")).resolves.toBe("locked-poll-only");
    expect((await storedMeta()).coordinationRevision).not.toBe(created.meta.coordinationRevision);
  });

  it("another open tab clears decrypted plaintext exactly as for a manual lock from another tab", async () => {
    const workspace = await unlockedWithCanary();
    expect(JSON.stringify(workspace.records)).toContain(CANARY);
    const receiving = mountTab(workspace, { sameDocument: false, channel: true });

    await expect(lockVaultOnSessionEnd("logout")).resolves.toBe("locked");

    await vi.waitFor(() => expect(receiving.screen.phase).toBe("locked"));
    expectNoPlaintext(receiving);
    expect(receiving.notice).toBe("Workspace locked from another tab.");
    const afterLogout = await storedMeta();
    expect((receiving.screen as { meta: PublicVaultMeta }).meta).toEqual(afterLogout);
    // The old in-memory session can no longer commit anything.
    await expect(saveWorkspaceRecords(workspace, [createAgentProfileRecord(
      { displayName: "late", walletAddress: "", frameworkLabel: "", purposeNote: "" }, workspace.meta.revision)]))
      .rejects.toMatchObject({ code: "VAULT_CONFLICT" });

    // Reference: the existing manual lock from another tab (signal + `lock`).
    const reunlocked = await unlockLocalWorkspace(afterLogout, passphrase);
    const manualReceiver = mountTab(reunlocked, { sameDocument: false, channel: true });
    const manualSender = new BroadcastChannel(VAULT_COORDINATION_CHANNEL);
    open.push(manualSender);
    await signalWorkspaceLock(reunlocked.meta);
    manualSender.postMessage({ sender: crypto.randomUUID(), type: "lock", vaultId: reunlocked.meta.vaultId });
    await vi.waitFor(() => expect(manualReceiver.screen.phase).toBe("locked"));
    expect({ phase: manualReceiver.screen.phase, notice: manualReceiver.notice, unlocked: manualReceiver.unlocked })
      .toEqual({ phase: receiving.screen.phase, notice: receiving.notice, unlocked: receiving.unlocked });
  });
});

describe("P08-02 lazy-loading boundary", () => {
  const source = (relative: string) => readFile(path.resolve(import.meta.dirname, "../src", relative), "utf8");
  const staticVaultImport = /^\s*import\s[^;]*?from\s+["'](?:\.\.\/vault\/|\.\/vault\/)/mu;

  it("account and tenant shells reach Vault code only through a dynamic import", async () => {
    const [account, tenant, trigger, logoutRule] = await Promise.all([
      source("account/AccountPage.tsx"), source("tenant/TenantApp.tsx"),
      source("app/vault-session-lock.ts"), source("account/logout-vault-lock.ts"),
    ]);
    for (const file of [account, tenant, trigger, logoutRule]) expect(file).not.toMatch(staticVaultImport);
    expect(trigger).toContain('import("../vault/session-bridge.js")');
    expect(account).toContain("vaultWatcherRef.current?.logout(\"logout\")");
    expect(tenant).toContain("vaultWatcherRef.current?.observe(accountId)");
  });

  it("the mounted workspace routes the existing channel and same-document session end through the shared handler", async () => {
    const [workspace, bridge] = await Promise.all([source("vault/VaultWorkspace.tsx"), source("vault/session-bridge.ts")]);
    expect(workspace).toContain("handleCoordinationMessage(event.data, target)");
    expect(workspace).toContain("subscribeVaultSessionEnd(() => handleLocalSessionEnd(target))");
    expect(bridge).not.toContain("VaultWorkspace");
    expect(bridge).toContain("signalVaultLock");
  });
});
