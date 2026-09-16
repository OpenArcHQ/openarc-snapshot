import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const localPassphrase = "local workspace test passphrase";
const backupPassphrase = "separate backup test passphrase";
const restoredPassphrase = "restored workspace test passphrase";
const recoveredPassphrase = "recovered workspace test passphrase";
const privateCanary = "PRIVATE_AGENT_BROWSER_CANARY";

test("runs the encrypted workspace lifecycle without plaintext or network leakage", async ({
  page,
  baseURL,
}, testInfo) => {
  // This combined lifecycle includes multiple independent PBKDF2 rounds for
  // creation, backup, restore and recovery. Bound the whole scenario without
  // changing any action/assertion timeout or application performance contract.
  test.setTimeout(60_000);
  page.setDefaultTimeout(30_000);
  const appOrigin = new URL(baseURL ?? "").origin;
  const dynamicRequests: string[] = [];
  const requestObservations: string[] = [];
  const consoleMessages: string[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    requestObservations.push(
      JSON.stringify({ method: request.method(), url: request.url(), body: request.postData(), headers: request.headers() }),
    );
    if (/\/(v1|rpc|graphql)(\/|\?|$)/u.test(url.pathname) || url.origin !== appOrigin) {
      dynamicRequests.push(`${request.method()} ${request.url()} ${request.postData() ?? ""}`);
    }
  });
  page.on("console", (message) => consoleMessages.push(message.text()));

  await page.goto("/workspace");
  await expect(page.getByRole("heading", { name: "Create a private workspace" })).toBeVisible();
  await page.getByLabel("Workspace passphrase", { exact: false }).fill(localPassphrase);
  await page.getByLabel("Confirm passphrase").fill(localPassphrase);
  await page.getByRole("button", { name: "Create encrypted workspace" }).click();

  const originalRecovery = await page.getByTestId("recovery-secret").innerText();
  expect(originalRecovery).toMatch(/^OA1-[A-Za-z0-9_-]{43}$/u);
  await page.getByRole("checkbox", { name: /I saved it somewhere private/u }).check();
  await page.getByRole("button", { name: "Continue to workspace" }).click();
  await page.getByRole("button", { name: "Skip" }).click();

  await page.getByRole("button", { name: /02 Agents/u }).click();
  await page.getByRole("button", { name: "Add agent profile" }).click();
  await page.getByLabel("Display name").fill(privateCanary);
  await page.getByLabel("Framework label (optional)").fill("PRIVATE_FRAMEWORK_CANARY");
  await page.getByLabel("Purpose note (optional)").fill("PRIVATE_PURPOSE_CANARY");
  await page.getByRole("button", { name: "Encrypt and save" }).click();
  await expect(page.getByRole("heading", { name: privateCanary })).toBeVisible();
  await page.getByRole("button", { name: "Copy Agent ID" }).click();
  await expect(page.getByRole("status")).toContainText(/Copied locally|Nothing was sent/u);

  await page.getByRole("button", { name: /04 Evidence/u }).click();
  await page.getByRole("button", { name: "Copy into workspace" }).first().click();
  await expect(page.getByText("6 evidence records")).toBeVisible();
  await expect(page.getByRole("button", { name: "Copy Action ID" })).toBeVisible();
  await page.getByRole("button", { name: /03 Policies/u }).click();
  await expect(page.getByRole("button", { name: "Copy Policy ID" })).toBeVisible();
  await page.getByRole("button", { name: /04 Evidence/u }).click();

  const raw = await readRawWorkspace(page);
  const rawText = JSON.stringify(raw);
  for (const secret of [
    privateCanary,
    "PRIVATE_FRAMEWORK_CANARY",
    "PRIVATE_PURPOSE_CANARY",
    localPassphrase,
    originalRecovery,
  ]) {
    expect(rawText).not.toContain(secret);
  }
  expect(await page.evaluate(async () => ({
    local: localStorage.length,
    session: sessionStorage.length,
    caches: await caches.keys(),
    cookie: document.cookie,
    serviceWorkers: (await navigator.serviceWorker?.getRegistrations())?.length ?? 0,
  }))).toEqual({ local: 0, session: 0, caches: [], cookie: "", serviceWorkers: 0 });

  await page.getByRole("button", { name: /05 Settings/u }).click();
  await page.getByLabel("Backup passphrase", { exact: true }).first().fill(backupPassphrase);
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download encrypted backup" }).click();
  const download = await downloadPromise;
  const backupPath = testInfo.outputPath("workspace-backup.openarc");
  await download.saveAs(backupPath);
  const backupText = await readTextFile(backupPath);
  expect(backupText).toContain("OPENARC-ENCRYPTED-BACKUP");
  expect(backupText).not.toContain(privateCanary);
  expect(backupText).not.toContain(localPassphrase);

  await page.reload();
  await expect(page.getByRole("heading", { name: "Unlock your private workspace" })).toBeVisible();
  await unlock(page, localPassphrase);
  await expect(page.getByText(privateCanary)).not.toBeVisible();
  await page.getByRole("button", { name: /02 Agents/u }).click();
  await expect(page.getByRole("heading", { name: privateCanary })).toBeVisible();

  await page.dispatchEvent("body", "pagehide");
  await expect(page.getByRole("heading", { name: "Unlock your private workspace" })).toBeVisible();
  await expect(page.getByText(privateCanary)).not.toBeVisible();
  await unlock(page, localPassphrase);

  await page.getByRole("button", { name: /05 Settings/u }).click();
  await page.evaluate(async () => {
    const request = indexedDB.open("openarc-vault", 1);
    const database = await new Promise<IDBDatabase>((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    Object.assign(globalThis, { __openArcBlocker: database });
  });
  await page.getByRole("checkbox", { name: /cannot be undone/u }).check();
  await page.getByRole("button", { name: "Permanently delete", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Deleting encrypted workspace" })).toBeVisible();
  await expect(page.getByRole("button", { name: /unlock|create|import|recover/iu })).toHaveCount(0);
  await page.evaluate(() => {
    const database = (globalThis as typeof globalThis & { __openArcBlocker?: IDBDatabase }).__openArcBlocker;
    database?.close();
  });
  await expect(page.getByRole("heading", { name: "Create a private workspace" })).toBeVisible();

  await page.getByRole("button", { name: "Import backup" }).click();
  await page.getByLabel("Encrypted .openarc backup").setInputFiles({
    name: "workspace-backup.openarc",
    mimeType: "application/json",
    buffer: Buffer.from(backupText),
  });
  await page.getByLabel("Backup passphrase").fill(backupPassphrase);
  await page.getByLabel("New workspace passphrase").fill(restoredPassphrase);
  await page.getByLabel("Confirm new passphrase").fill(restoredPassphrase);
  await page.getByRole("button", { name: "Verify and restore backup" }).click();
  const restoredRecovery = await page.getByTestId("recovery-secret").innerText();
  expect(restoredRecovery).not.toBe(originalRecovery);
  await page.getByRole("checkbox", { name: /I saved it somewhere private/u }).check();
  await page.getByRole("button", { name: "Continue to workspace" }).click();
  await page.getByRole("button", { name: /02 Agents/u }).click();
  await expect(page.getByRole("heading", { name: privateCanary })).toBeVisible();

  await page.getByRole("button", { name: "Lock workspace" }).click();
  await expect(page.getByRole("heading", { name: "Unlock your private workspace" })).toBeVisible();
  await page.getByRole("button", { name: "Recovery" }).click();
  await page.getByLabel("Recovery secret").fill(restoredRecovery);
  await page.getByLabel("New workspace passphrase").fill(recoveredPassphrase);
  await page.getByLabel("Confirm new passphrase").fill(recoveredPassphrase);
  await page.getByRole("button", { name: "Recover and rotate credentials" }).click();
  const nextRecovery = await page.getByTestId("recovery-secret").innerText();
  expect(nextRecovery).not.toBe(restoredRecovery);
  await page.getByRole("checkbox", { name: /I saved it somewhere private/u }).check();
  await page.getByRole("button", { name: "Continue to workspace" }).click();
  await page.reload();
  await page.getByLabel("Workspace passphrase", { exact: false }).fill(restoredPassphrase);
  await page.getByRole("button", { name: "Unlock workspace" }).click();
  await expect(page.getByText("Wrong passphrase or damaged workspace.")).toBeVisible();
  await page.getByLabel("Workspace passphrase", { exact: false }).fill(recoveredPassphrase);
  await page.getByRole("button", { name: "Unlock workspace" }).click();
  await expect(page.getByText("UNLOCKED LOCALLY")).toBeVisible();

  expect(dynamicRequests).toEqual([]);
  for (const secret of [
    privateCanary,
    "PRIVATE_FRAMEWORK_CANARY",
    "PRIVATE_PURPOSE_CANARY",
    localPassphrase,
    backupPassphrase,
    restoredPassphrase,
    recoveredPassphrase,
    originalRecovery,
    restoredRecovery,
    nextRecovery,
  ]) {
    expect(requestObservations.join("\n")).not.toContain(secret);
  }
  expect(consoleMessages.join("\n")).not.toContain(privateCanary);
  expect(page.url()).not.toContain(privateCanary);
  expect(await page.title()).not.toContain(privateCanary);
});

test("coordinates revision changes and lock across tabs", async ({ context, page }) => {
  await page.goto("/workspace");
  const second = await context.newPage();
  await second.goto("/workspace");
  await expect(second.getByRole("heading", { name: "Create a private workspace" })).toBeVisible();
  await page.getByLabel("Workspace passphrase", { exact: false }).fill(localPassphrase);
  await page.getByLabel("Confirm passphrase").fill(localPassphrase);
  await page.getByRole("button", { name: "Create encrypted workspace" }).click();
  await page.getByRole("checkbox", { name: /I saved it somewhere private/u }).check();
  await page.getByRole("button", { name: "Continue to workspace" }).click();
  // The peer must observe creation before we produce the separate tour-save
  // revision, so an old creation notice cannot satisfy the change handshake.
  await expect(second.getByRole("heading", { name: "Unlock your private workspace" })).toBeVisible();
  await page.getByRole("button", { name: "Skip" }).click();
  await expect(page.getByText("Tour preference saved inside the encrypted workspace.")).toBeVisible();
  await expect(second.getByText(/changed in another tab/u)).toBeVisible();
  await expect(second.getByRole("heading", { name: "Unlock your private workspace" })).toBeVisible();
  await unlock(second, localPassphrase);

  await page.getByRole("button", { name: /02 Agents/u }).click();
  await page.getByRole("button", { name: "Add agent profile" }).click();
  await page.getByLabel("Display name").fill("Cross-tab agent");
  await page.getByRole("button", { name: "Encrypt and save" }).click();
  await expect(second.getByRole("heading", { name: "Unlock your private workspace" })).toBeVisible();
  await expect(second.getByText(/changed in another tab/u)).toBeVisible();

  await unlock(second, localPassphrase);
  await page.getByRole("button", { name: "Lock workspace" }).click();
  await expect(second.getByRole("heading", { name: "Unlock your private workspace" })).toBeVisible();

  await unlock(page, localPassphrase);
  await second.evaluate(async () => {
    const request = indexedDB.open("openarc-vault", 1);
    const database = await new Promise<IDBDatabase>((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    Object.assign(globalThis, { __openArcLockedDeleteBlocker: database });
  });
  await page.getByRole("navigation").getByRole("button", { name: /^\d+ Settings\b/u }).click();
  await page.getByRole("checkbox", { name: /cannot be undone/u }).check();
  await page.getByRole("button", { name: "Permanently delete", exact: true }).click();
  await expect(second.getByRole("heading", { name: "Deleting encrypted workspace" })).toBeVisible();
  await expect(second.getByRole("button", { name: /unlock|create|import|recover/iu })).toHaveCount(0);
  await second.evaluate(() => {
    const database = (globalThis as typeof globalThis & { __openArcLockedDeleteBlocker?: IDBDatabase })
      .__openArcLockedDeleteBlocker;
    database?.close();
  });
  await expect(page.getByRole("heading", { name: "Create a private workspace" })).toBeVisible();
  await expect(second.getByRole("heading", { name: "Create a private workspace" })).toBeVisible();
});

test("rejects a stale decrypted session when a previously announced peer lock commits during derivation", async ({ context, page }) => {
  const sourceRequests: string[] = [];
  context.on("request", request => {
    if (["fetch", "xhr"].includes(request.resourceType())) sourceRequests.push(request.url());
  });
  await page.goto("/workspace");
  await page.getByLabel("Workspace passphrase", { exact: false }).fill(localPassphrase);
  await page.getByLabel("Confirm passphrase").fill(localPassphrase);
  await page.getByRole("button", { name: "Create encrypted workspace" }).click();
  await page.getByRole("checkbox", { name: /I saved it somewhere private/u }).check();
  await page.getByRole("button", { name: "Continue to workspace", exact: true }).click();
  await page.getByRole("button", { name: "Skip", exact: true }).click();
  await expect(page.getByText("Tour preference saved inside the encrypted workspace.", { exact: true })).toBeVisible();
  const second = await context.newPage();
  await second.goto("/workspace"); await unlock(second, localPassphrase);
  await page.evaluate(() => {
    const original = IDBFactory.prototype.open;
    IDBFactory.prototype.open = function (...args) {
      const request = original.apply(this, args);
      Object.defineProperty(request, "onsuccess", { configurable: true,
        set(callback: (this: IDBOpenDBRequest, event: Event) => unknown) {
          request.addEventListener("success", (event: Event) => {
            Object.assign(globalThis, { __openArcReleaseLockOpen: () => callback.call(request, event) });
          });
        },
      });
      IDBFactory.prototype.open = original;
      return request;
    };
  });
  // The real immediate hint clears the peer, while the durable write is held.
  await page.getByRole("button", { name: "Lock workspace", exact: true }).click();
  await expect(second.getByRole("heading", { name: "Unlock your private workspace", exact: true })).toBeVisible();
  await second.evaluate(() => {
    const original = crypto.subtle.deriveKey.bind(crypto.subtle);
    crypto.subtle.deriveKey = (...args) => {
      crypto.subtle.deriveKey = original;
      return new Promise((resolve, reject) => {
        Object.assign(globalThis, { __openArcReleaseUnlockDerivation: () => original(...args).then(resolve, reject) });
      });
    };
    let mounted = false;
    new MutationObserver(() => {
      if (document.body.textContent?.includes("UNLOCKED LOCALLY")) mounted = true;
    }).observe(document.body, { subtree: true, childList: true });
    Object.assign(globalThis, { __openArcStaleSessionMounted: () => mounted });
  });
  await second.getByLabel("Workspace passphrase", { exact: false }).fill(localPassphrase);
  await second.getByRole("button", { name: "Unlock workspace", exact: true }).click();
  await second.waitForFunction(() => "__openArcReleaseUnlockDerivation" in globalThis);
  await page.evaluate(() => (globalThis as typeof globalThis & { __openArcReleaseLockOpen: () => void }).__openArcReleaseLockOpen());
  // Sender access appears only after its durable lock transaction completes.
  await expect(page.getByRole("heading", { name: "Unlock your private workspace", exact: true })).toBeVisible();
  await second.evaluate(() => (globalThis as typeof globalThis & { __openArcReleaseUnlockDerivation: () => void }).__openArcReleaseUnlockDerivation());
  await second.waitForFunction(() =>
    (globalThis as typeof globalThis & { __openArcStaleSessionMounted: () => boolean }).__openArcStaleSessionMounted() ||
    document.body.textContent?.includes("The encrypted workspace changed while this action was finishing. Unlock again to load the latest revision."));
  expect(await second.evaluate(() => (globalThis as typeof globalThis & { __openArcStaleSessionMounted: () => boolean }).__openArcStaleSessionMounted())).toBe(false);
  await expect(second.getByText("The encrypted workspace changed while this action was finishing. Unlock again to load the latest revision.", { exact: true })).toBeVisible();
  await expect(second.getByRole("heading", { name: "Unlock your private workspace", exact: true })).toBeVisible();
  expect(await second.evaluate(() => (globalThis as typeof globalThis & { __openArcStaleSessionMounted: () => boolean }).__openArcStaleSessionMounted())).toBe(false);
  await expect(second.getByText("UNLOCKED LOCALLY", { exact: true })).toHaveCount(0);
  await unlock(second, localPassphrase);
  await expect(second.getByText("UNLOCKED LOCALLY", { exact: true })).toBeVisible();
  expect(sourceRequests).toEqual([]);
});

test("keeps peer access hidden until BroadcastChannel metadata readback completes", async ({ context, page }) => {
  const sourceRequests: string[] = [];
  context.on("request", request => {
    if (["fetch", "xhr"].includes(request.resourceType())) sourceRequests.push(request.url());
  });
  await page.goto("/workspace");
  await page.getByLabel("Workspace passphrase", { exact: false }).fill(localPassphrase);
  await page.getByLabel("Confirm passphrase").fill(localPassphrase);
  await page.getByRole("button", { name: "Create encrypted workspace" }).click();
  await page.getByRole("checkbox", { name: /I saved it somewhere private/u }).check();
  await page.getByRole("button", { name: "Continue to workspace" }).click();
  await page.getByRole("button", { name: "Skip", exact: true }).click();
  await expect(page.getByText("Tour preference saved inside the encrypted workspace.")).toBeVisible();
  const second = await context.newPage();
  await second.goto("/workspace");
  await unlock(second, localPassphrase);
  await second.evaluate(() => {
    const descriptor = Object.getOwnPropertyDescriptor(IDBTransaction.prototype, "oncomplete")!;
    const waiting: (() => void)[] = [];
    let completedReads = 0;
    let hold = true;
    Object.defineProperty(IDBTransaction.prototype, "oncomplete", { ...descriptor,
      set(this: IDBTransaction, callback: ((this: IDBTransaction, event: Event) => unknown) | null) {
        if (callback && this.db.name === "openarc-vault" && this.mode === "readonly" &&
          this.objectStoreNames.contains("vaultMeta") && this.objectStoreNames.contains("records")) {
          descriptor.set!.call(this, (event: Event) => {
            const complete = () => { completedReads++; callback.call(this, event); };
            if (hold) waiting.push(complete);
            else complete();
          });
        } else descriptor.set!.call(this, callback);
      },
    });
    Object.assign(globalThis, {
      __openArcPendingPeerReadbacks: () => waiting.length,
      __openArcCompletedPeerReadbacks: () => completedReads,
      __openArcReleasePeerReadbacks: () => {
        hold = false;
        for (const release of waiting.splice(0)) release();
      },
    });
  });
  // A changed notification follows the durable save. Peer-lock notifications
  // have a separate ordering contract and are not covered by this regression.
  await page.getByRole("button", { name: /^\d+ Agents\b/u }).click();
  await page.getByRole("button", { name: "Add agent profile", exact: true }).click();
  await page.getByLabel("Display name", { exact: true }).fill("Delayed peer readback agent");
  await page.getByRole("button", { name: "Encrypt and save", exact: true }).click();
  await expect.poll(() => second.evaluate(() =>
    (globalThis as typeof globalThis & { __openArcPendingPeerReadbacks?: () => number }).__openArcPendingPeerReadbacks?.() ?? 0)).toBeGreaterThan(0);
  await expect(second.getByRole("status")).toHaveText("Locking every active local view…");
  await expect(second.getByRole("button", { name: "Unlock workspace", exact: true })).toHaveCount(0);
  await expect(second.getByLabel("Workspace passphrase", { exact: false })).toHaveCount(0);
  await expect(second.getByText("UNLOCKED LOCALLY", { exact: true })).toHaveCount(0);
  await second.evaluate(() =>
    (globalThis as typeof globalThis & { __openArcReleasePeerReadbacks?: () => void }).__openArcReleasePeerReadbacks?.());
  await expect(second.getByRole("heading", { name: "Unlock your private workspace", exact: true })).toBeVisible();
  const completed = () => second.evaluate(() =>
    (globalThis as typeof globalThis & { __openArcCompletedPeerReadbacks?: () => number }).__openArcCompletedPeerReadbacks?.() ?? 0);
  const beforePoll = await completed();
  await second.getByLabel("Workspace passphrase", { exact: false }).fill(localPassphrase);
  // Observe an actual subsequent revision read, without a sleep or a retry.
  await expect.poll(completed, { timeout: 4_500 }).toBeGreaterThan(beforePoll);
  await expect(second.getByLabel("Workspace passphrase", { exact: false })).toHaveValue(localPassphrase);
  await unlock(second, localPassphrase);
  await second.getByRole("button", { name: /^\d+ Agents\b/u }).click();
  await expect(second.getByRole("heading", { name: "Delayed peer readback agent", exact: true })).toBeVisible();
  expect(sourceRequests).toEqual([]);
});

test("uses revision polling when BroadcastChannel is unavailable", async ({ context, page }) => {
  // This path intentionally performs seven production-strength PBKDF2
  // derivations (one create plus six unlocks).
  // A single-core hosted WebKit worker needs a wider test budget even though
  // every individual unlock remains bounded to 15 seconds.
  test.setTimeout(120_000);
  await context.addInitScript(() => {
    Object.defineProperty(globalThis, "BroadcastChannel", { configurable: true, value: undefined });
  });
  await page.goto("/workspace");
  const second = await context.newPage();
  await second.goto("/workspace");
  await expect(second.getByRole("heading", { name: "Create a private workspace" })).toBeVisible();
  await page.getByLabel("Workspace passphrase", { exact: false }).fill(localPassphrase);
  await page.getByLabel("Confirm passphrase").fill(localPassphrase);
  await page.getByRole("button", { name: "Create encrypted workspace" }).click();
  await page.getByRole("checkbox", { name: /I saved it somewhere private/u }).check();
  await page.getByRole("button", { name: "Continue to workspace" }).click();
  await expect(second.getByRole("heading", { name: "Unlock your private workspace" })).toBeVisible({
    timeout: 4_500,
  });
  await page.getByRole("button", { name: "Skip" }).click();
  await expect(page.getByText("Tour preference saved inside the encrypted workspace.")).toBeVisible();
  await expect(second.getByText("Workspace changed or locked in another tab. Unlock again to load the latest encrypted revision.", { exact: true })).toBeVisible({
    timeout: 4_500,
  });
  await expect(second.getByRole("heading", { name: "Unlock your private workspace" })).toBeVisible({
    timeout: 4_500,
  });
  await unlock(second, localPassphrase);
  await page.getByRole("button", { name: /02 Agents/u }).click();
  await page.getByRole("button", { name: "Add agent profile" }).click();
  await page.getByLabel("Display name").fill("Polling fallback agent");
  await page.getByRole("button", { name: "Encrypt and save" }).click();
  await expect(second.getByRole("heading", { name: "Unlock your private workspace" })).toBeVisible({
    timeout: 4_500,
  });

  await unlock(second, localPassphrase);
  await page.getByRole("button", { name: "Lock workspace" }).click();
  await expect(second.getByRole("heading", { name: "Unlock your private workspace" })).toBeVisible({
    timeout: 4_500,
  });

  await unlock(page, localPassphrase);
  await unlock(second, localPassphrase);
  await page.dispatchEvent("body", "pagehide");
  await expect(page.getByRole("heading", { name: "Unlock your private workspace" })).toBeVisible();
  await expect(second.getByRole("heading", { name: "Unlock your private workspace" })).toBeVisible({
    timeout: 4_500,
  });

  await unlock(page, localPassphrase);
  await unlock(second, localPassphrase);
  await second.evaluate(async () => {
    const request = indexedDB.open("openarc-vault", 1);
    const database = await new Promise<IDBDatabase>((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    Object.assign(globalThis, { __openArcDeleteBlocker: database });
  });
  await page.getByRole("navigation").getByRole("button", { name: /^\d+ Settings\b/u }).click();
  await page.getByRole("checkbox", { name: /cannot be undone/u }).check();
  await page.getByRole("button", { name: "Permanently delete", exact: true }).click();
  await expect(second.getByRole("heading", { name: "Deleting encrypted workspace" })).toBeVisible();
  await expect(second.getByRole("button", { name: /unlock|create|import|recover/iu })).toHaveCount(0);
  await second.evaluate(() => {
    const database = (globalThis as typeof globalThis & { __openArcDeleteBlocker?: IDBDatabase })
      .__openArcDeleteBlocker;
    database?.close();
  });
  await expect(page.getByRole("heading", { name: "Create a private workspace" })).toBeVisible();
  await expect(second.getByRole("heading", { name: "Create a private workspace" })).toBeVisible();
});

test("locks at the exact inactivity deadline", async ({ page }) => {
  await page.clock.install();
  await page.goto("/workspace");
  await page.getByLabel("Workspace passphrase", { exact: false }).fill(localPassphrase);
  await page.getByLabel("Confirm passphrase").fill(localPassphrase);
  await page.getByRole("button", { name: "Create encrypted workspace" }).click();
  await page.getByRole("checkbox", { name: /I saved it somewhere private/u }).check();
  await page.getByRole("button", { name: "Continue to workspace" }).click();
  await page.getByRole("button", { name: "Skip" }).click();
  // Tour dismissal saves asynchronously and its successful completion starts
  // a fresh idle interval. Finish setup before advancing the inactivity clock.
  await expect(page.getByText("Tour preference saved inside the encrypted workspace.")).toBeVisible();
  await page.clock.fastForward(10 * 60 * 1_000 + 1_000);
  // The deadline fires synchronously, then the lock marker commits through
  // IndexedDB before React can show the locked screen. Allow that bounded
  // transaction to settle under the parallel WebKit release load.
  await expect(page.getByRole("heading", { name: "Unlock your private workspace" })).toBeVisible({
    timeout: 15_000,
  });
  await expect(page.getByText(/10 minutes of inactivity/u)).toBeVisible();
});

test("cancels a hidden pre-unlock operation before it can persist or reveal plaintext", async ({ page }) => {
  await page.goto("/workspace");
  // The startup capability probe also derives a key. Hold only the intended
  // create operation after the probe has made the access form available.
  await expect(page.getByRole("heading", { name: "Create a private workspace", exact: true })).toBeVisible();
  await page.evaluate(() => {
    const subtle = crypto.subtle;
    const original = subtle.deriveKey.bind(subtle);
    let release: (() => void) | null = null;
    Object.defineProperty(subtle, "deriveKey", {
      configurable: true,
      value: (...args: unknown[]) =>
        new Promise<CryptoKey>((resolve, reject) => {
          release = () => {
            void (Reflect.apply(original, subtle, args) as Promise<CryptoKey>).then(resolve, reject);
          };
        }),
    });
    Object.assign(globalThis, { __releaseOpenArcKdf: () => release?.() });
  });
  await page.getByLabel("Workspace passphrase", { exact: false }).fill(localPassphrase);
  await page.getByLabel("Confirm passphrase").fill(localPassphrase);
  await page.getByRole("button", { name: "Create encrypted workspace" }).evaluate((button) => {
    button.click();
    window.dispatchEvent(new PageTransitionEvent("pagehide"));
  });
  await page.evaluate(() => {
    (globalThis as typeof globalThis & { __releaseOpenArcKdf?: () => void }).__releaseOpenArcKdf?.();
  });
  await expect(page.getByRole("heading", { name: "Create a private workspace" })).toBeVisible();
  await expect(page.getByText(/cancelled when this page was hidden or left/u)).toBeVisible();
  await expect(page.getByLabel("Workspace passphrase", { exact: false })).toHaveValue("");
  await expect(page.getByLabel("Confirm passphrase")).toHaveValue("");
  await expect(page.locator("body")).not.toContainText(localPassphrase);
  const raw = (await readRawWorkspace(page)) as { meta?: unknown; records: unknown[] };
  expect(raw.meta).toBeUndefined();
  expect(raw.records).toEqual([]);
});

test("clears every unsubmitted access draft when the page is hidden or left", async ({ page }) => {
  const unsubmittedCreate = "UNSUBMITTED_CREATE_PRIVATE_SECRET";
  await page.goto("/workspace");
  await page.getByLabel("Workspace passphrase", { exact: false }).fill(unsubmittedCreate);
  await page.getByLabel("Confirm passphrase").fill(unsubmittedCreate);
  await page.dispatchEvent("body", "pagehide");
  await expect(page.getByLabel("Workspace passphrase", { exact: false })).toHaveValue("");
  await expect(page.getByLabel("Confirm passphrase")).toHaveValue("");
  await expect(page.locator("body")).not.toContainText(unsubmittedCreate);

  await page.getByLabel("Workspace passphrase", { exact: false }).fill(localPassphrase);
  await page.getByLabel("Confirm passphrase").fill(localPassphrase);
  await page.getByRole("button", { name: "Create encrypted workspace" }).click();
  await page.getByRole("checkbox", { name: /I saved it somewhere private/u }).check();
  await page.getByRole("button", { name: "Continue to workspace" }).click();
  await page.getByRole("button", { name: "Skip" }).click();
  await page.getByRole("button", { name: "Lock workspace" }).click();

  const recoveryDraft = "UNSUBMITTED_RECOVERY_PRIVATE_SECRET";
  const nextPassphraseDraft = "UNSUBMITTED_NEXT_PRIVATE_SECRET";
  await page.getByRole("button", { name: "Recovery", exact: true }).click();
  await page.getByLabel("Recovery secret").fill(recoveryDraft);
  await page.getByLabel("New workspace passphrase").fill(nextPassphraseDraft);
  await page.getByLabel("Confirm new passphrase").fill(nextPassphraseDraft);
  await page.dispatchEvent("body", "pagehide");
  await expect(page.getByRole("button", { name: "Unlock", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator("body")).not.toContainText(recoveryDraft);
  await expect(page.locator("body")).not.toContainText(nextPassphraseDraft);

  const importDraft = "UNSUBMITTED_IMPORT_PRIVATE_SECRET";
  await page.getByRole("button", { name: "Import backup" }).click();
  await page.getByLabel("Encrypted .openarc backup").setInputFiles({
    name: "UNSUBMITTED_PRIVATE_FILE.openarc",
    mimeType: "application/json",
    buffer: Buffer.from("private draft only"),
  });
  await page.getByLabel("Backup passphrase").fill(importDraft);
  await page.getByLabel("New workspace passphrase").fill(nextPassphraseDraft);
  await page.getByLabel("Confirm new passphrase").fill(nextPassphraseDraft);
  await page.dispatchEvent("body", "pagehide");
  await expect(page.getByRole("button", { name: "Unlock", exact: true })).toHaveAttribute("aria-pressed", "true");
  await page.getByRole("button", { name: "Import backup" }).click();
  await expect(page.getByLabel("Backup passphrase")).toHaveValue("");
  await expect(page.getByLabel("New workspace passphrase")).toHaveValue("");
  expect(await page.getByLabel("Encrypted .openarc backup").evaluate((input: HTMLInputElement) => input.files?.length ?? 0)).toBe(0);

  await page.getByRole("button", { name: "Delete", exact: true }).click();
  await page.getByRole("checkbox", { name: /cannot be undone/u }).check();
  await page.dispatchEvent("body", "pagehide");
  await page.getByRole("button", { name: "Delete", exact: true }).click();
  await expect(page.getByRole("checkbox", { name: /cannot be undone/u })).not.toBeChecked();
});

test("keeps manual lock available and discards a delayed local backup export", async ({ page }) => {
  await page.goto("/workspace");
  await page.getByLabel("Workspace passphrase", { exact: false }).fill(localPassphrase);
  await page.getByLabel("Confirm passphrase").fill(localPassphrase);
  await page.getByRole("button", { name: "Create encrypted workspace" }).click();
  await page.getByRole("checkbox", { name: /I saved it somewhere private/u }).check();
  await page.getByRole("button", { name: "Continue to workspace" }).click();
  await page.getByRole("button", { name: "Skip" }).click();
  await page.getByRole("button", { name: /05 Settings/u }).click();
  const before = (await readRawWorkspace(page)) as { records: unknown[] };
  await page.evaluate(() => {
    const subtle = crypto.subtle;
    const original = subtle.deriveKey.bind(subtle);
    let release: (() => void) | null = null;
    Object.defineProperty(subtle, "deriveKey", {
      configurable: true,
      value: (...args: unknown[]) =>
        new Promise<CryptoKey>((resolve, reject) => {
          release = () => {
            void (Reflect.apply(original, subtle, args) as Promise<CryptoKey>).then(resolve, reject);
          };
        }),
    });
    Object.assign(globalThis, { __releaseOpenArcExportKdf: () => release?.() });
  });
  const exportPassphrase = "DELAYED_EXPORT_PRIVATE_PASSPHRASE";
  await page.getByLabel("Backup passphrase", { exact: true }).first().fill(exportPassphrase);
  await page.getByRole("button", { name: "Download encrypted backup" }).click();
  const lock = page.getByRole("button", { name: "Lock workspace" });
  await expect(lock).toBeEnabled();
  await lock.click();
  await expect(page.getByRole("heading", { name: "Unlock your private workspace" })).toBeVisible();
  const lateDownload = page.waitForEvent("download", { timeout: 750 }).then(() => true).catch(() => false);
  await page.evaluate(() => {
    (globalThis as typeof globalThis & { __releaseOpenArcExportKdf?: () => void }).__releaseOpenArcExportKdf?.();
  });
  expect(await lateDownload).toBe(false);
  await expect(page.locator("body")).not.toContainText(exportPassphrase);
  const after = (await readRawWorkspace(page)) as { records: unknown[] };
  expect(after.records).toEqual(before.records);
});

test("keeps validation and recovery-copy failures local, focused, and non-persistent", async ({ page }) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await page.goto("/workspace");
  await page.getByLabel("Workspace passphrase", { exact: false }).fill(localPassphrase);
  await page.getByLabel("Confirm passphrase").fill(localPassphrase);
  await page.getByRole("button", { name: "Create encrypted workspace" }).click();

  await page.evaluate(() => {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: () => Promise.reject(new Error("Denied for deterministic test")) },
    });
  });
  await page.getByRole("button", { name: "Copy recovery secret" }).click();
  await expect(page.getByRole("status")).toContainText(/Copy is unavailable.*Nothing was sent/u);
  await page.evaluate(() => {
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: undefined });
  });
  await page.getByRole("button", { name: "Copy recovery secret" }).click();
  await expect(page.getByRole("status")).toContainText(/copy the recovery secret manually/u);

  await page.getByRole("checkbox", { name: /I saved it somewhere private/u }).check();
  await page.getByRole("button", { name: "Continue to workspace" }).click();
  await page.getByRole("button", { name: "Skip" }).click();
  await page.getByRole("button", { name: /03 Policies/u }).click();
  await page.getByRole("button", { name: "Add monitoring policy" }).click();
  const before = await readRawWorkspace(page);

  await page.getByLabel("Policy label").fill("Valid local policy");
  await page.getByLabel("Maximum amount (base units)").fill("100");
  await page.getByLabel("Expiry (UTC ISO timestamp, optional)").fill("not-a-time");
  await page.getByRole("button", { name: "Encrypt and save" }).click();
  const invalidExpiry = page.getByRole("alert");
  await expect(invalidExpiry).toContainText(/optional UTC timestamp ending in Z/u);
  await expect(invalidExpiry).toBeFocused();

  await page.getByLabel("Expiry (UTC ISO timestamp, optional)").fill("");
  await page.getByLabel("Policy label").fill("   ");
  await page.getByRole("button", { name: "Encrypt and save" }).click();
  const whitespaceLabel = page.getByRole("alert");
  await expect(whitespaceLabel).toContainText(/visible label/u);
  await expect(whitespaceLabel).toBeFocused();

  expect(await readRawWorkspace(page)).toEqual(before);
  expect(pageErrors).toEqual([]);
});

test("keeps an encrypted-save failure visible and focused inside the open editor", async ({ page }) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await page.goto("/workspace");
  await page.getByLabel("Workspace passphrase", { exact: false }).fill(localPassphrase);
  await page.getByLabel("Confirm passphrase").fill(localPassphrase);
  await page.getByRole("button", { name: "Create encrypted workspace" }).click();
  await page.getByRole("checkbox", { name: /I saved it somewhere private/u }).check();
  await page.getByRole("button", { name: "Continue to workspace" }).click();
  await page.getByRole("button", { name: "Skip" }).click();
  await page.getByRole("button", { name: /02 Agents/u }).click();
  await page.getByRole("button", { name: "Add agent profile" }).click();
  await page.getByLabel("Display name").fill("Conflict-safe agent draft");
  const before = (await readRawWorkspace(page)) as { records: unknown[] };
  await page.evaluate(() => {
    const original = IDBObjectStore.prototype.put;
    Object.defineProperty(IDBObjectStore.prototype, "put", {
      configurable: true,
      value(this: IDBObjectStore, ...args: Parameters<IDBObjectStore["put"]>) {
        if (this.name === "records") {
          throw new DOMException("Deterministic local quota failure", "QuotaExceededError");
        }
        return Reflect.apply(original, this, args) as IDBRequest<IDBValidKey>;
      },
    });
  });
  await page.getByRole("button", { name: "Encrypt and save" }).click();
  const failure = page.getByRole("alert");
  await expect(failure).toContainText(/could not save.*Nothing changed/u);
  await expect(failure).toBeFocused();
  await expect(page.getByRole("dialog", { name: "Add agent profile" })).toBeVisible();
  const after = (await readRawWorkspace(page)) as { records: unknown[] };
  expect(after.records).toEqual(before.records);
  expect(pageErrors).toEqual([]);
});

test("fails closed before mounting controls when required browser crypto or storage is absent", async ({
  browser,
}) => {
  for (const missing of ["indexedDB", "crypto", "secureContext"] as const) {
    const context = await browser.newContext();
    await context.addInitScript((capability) => {
      if (capability === "indexedDB") {
        Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: undefined });
      } else if (capability === "crypto") {
        Object.defineProperty(globalThis.crypto, "subtle", { configurable: true, value: undefined });
      } else {
        Object.defineProperty(globalThis, "isSecureContext", { configurable: true, value: false });
      }
    }, missing);
    const page = await context.newPage();
    await page.goto("/workspace");
    await expect(page.getByRole("heading", { name: "Encrypted workspace unavailable" })).toBeVisible();
    await expect(page.getByRole("button", { name: /create|unlock|import|recover/iu })).toHaveCount(0);
    await context.close();
  }
});

test("keeps rescue and deletion available when metadata becomes unreadable before unlock", async ({ page }) => {
  await page.goto("/workspace");
  await page.getByLabel("Workspace passphrase", { exact: false }).fill(localPassphrase);
  await page.getByLabel("Confirm passphrase").fill(localPassphrase);
  await page.getByRole("button", { name: "Create encrypted workspace" }).click();
  await page.getByRole("checkbox", { name: /I saved it somewhere private/u }).check();
  await page.getByRole("button", { name: "Continue to workspace" }).click();
  await page.getByRole("button", { name: "Skip" }).click();
  await page.getByRole("button", { name: "Lock workspace" }).click();
  await page.evaluate(async () => {
    const request = indexedDB.open("openarc-vault", 1);
    const database = await new Promise<IDBDatabase>((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    try {
      const transaction = database.transaction("vaultMeta", "readwrite");
      const store = transaction.objectStore("vaultMeta");
      const read = store.get("active");
      const meta = await new Promise<Record<string, unknown>>((resolve, reject) => {
        read.onsuccess = () => resolve(read.result as Record<string, unknown>);
        read.onerror = () => reject(read.error);
      });
      store.put({ ...meta, format: "corrupt-format" });
      await new Promise<void>((resolve, reject) => {
        transaction.oncomplete = () => resolve();
        transaction.onerror = () => reject(transaction.error);
      });
    } finally {
      database.close();
    }
  });
  await page.getByLabel("Workspace passphrase", { exact: false }).fill(localPassphrase);
  await page.getByRole("button", { name: "Unlock workspace" }).click();
  await expect(page.getByRole("heading", { name: "Local workspace could not start" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Export opaque rescue" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Delete unreadable local data" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Create encrypted workspace" })).toHaveCount(0);
});

test("detects orphan ciphertext at startup and exposes only rescue or deletion", async ({ page }) => {
  await page.goto("/workspace");
  await page.getByLabel("Workspace passphrase", { exact: false }).fill(localPassphrase);
  await page.getByLabel("Confirm passphrase").fill(localPassphrase);
  await page.getByRole("button", { name: "Create encrypted workspace" }).click();
  await page.getByRole("checkbox", { name: /I saved it somewhere private/u }).check();
  await page.getByRole("button", { name: "Continue to workspace" }).click();
  await page.getByRole("button", { name: "Skip" }).click();
  await page.getByRole("button", { name: "Lock workspace" }).click();
  await page.evaluate(async () => {
    const request = indexedDB.open("openarc-vault");
    const database = await new Promise<IDBDatabase>((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    try {
      const transaction = database.transaction("vaultMeta", "readwrite");
      transaction.objectStore("vaultMeta").delete("active");
      await new Promise<void>((resolve, reject) => {
        transaction.oncomplete = () => resolve();
        transaction.onerror = () => reject(transaction.error);
      });
    } finally {
      database.close();
    }
  });
  await page.reload();
  await expect(page.getByRole("heading", { name: "Local workspace could not start" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Export opaque rescue" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Delete unreadable local data" })).toBeVisible();
  await expect(page.getByRole("button", { name: /create|unlock|import|recover/iu })).toHaveCount(0);
});

test("fails closed without plaintext or controls when browser storage is externally evicted", async ({ page }) => {
  await page.goto("/workspace");
  await page.getByLabel("Workspace passphrase", { exact: false }).fill(localPassphrase);
  await page.getByLabel("Confirm passphrase").fill(localPassphrase);
  await page.getByRole("button", { name: "Create encrypted workspace" }).click();
  await page.getByRole("checkbox", { name: /I saved it somewhere private/u }).check();
  await page.getByRole("button", { name: "Continue to workspace" }).click();
  await page.getByRole("button", { name: "Skip" }).click();
  await page.getByRole("button", { name: /02 Agents/u }).click();
  await page.getByRole("button", { name: "Add agent profile" }).click();
  await page.getByLabel("Display name").fill("EVICTED_PRIVATE_CANARY");
  await page.getByRole("button", { name: "Encrypt and save" }).click();
  await expect(page.getByRole("heading", { name: "EVICTED_PRIVATE_CANARY" })).toBeVisible();

  await page.evaluate(
    () =>
      new Promise<void>((resolve, reject) => {
        const request = indexedDB.deleteDatabase("openarc-vault");
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
        request.onblocked = () => reject(new Error("External storage eviction was blocked"));
      }),
  );

  await expect(page.getByRole("heading", { name: "Create a private workspace" })).toBeVisible({
    timeout: 4_500,
  });
  await expect(page.getByText("EVICTED_PRIVATE_CANARY")).toHaveCount(0);
  await expect(page.getByRole("button", { name: /unlock|recover/iu })).toHaveCount(0);
  const raw = (await readRawWorkspace(page)) as { meta?: unknown; records: unknown[] };
  expect(raw.meta).toBeUndefined();
  expect(raw.records).toEqual([]);
});

test("fails closed when an open empty tab observes an incompatible database without BroadcastChannel", async ({ context, page }) => {
  await context.addInitScript(() => {
    Object.defineProperty(globalThis, "BroadcastChannel", { configurable: true, value: undefined });
  });
  await page.goto("/workspace");
  await expect(page.getByRole("heading", { name: "Create a private workspace" })).toBeVisible();
  await page.evaluate(
    () =>
      new Promise<void>((resolve, reject) => {
        const request = indexedDB.open("openarc-vault", 2);
        request.onsuccess = () => {
          request.result.close();
          resolve();
        };
        request.onerror = () => reject(request.error);
        request.onblocked = () => reject(new Error("Future database upgrade was blocked"));
      }),
  );
  await expect(page.getByRole("heading", { name: "Local workspace could not start" })).toBeVisible({
    timeout: 4_500,
  });
  await expect(page.getByRole("button", { name: "Export opaque rescue" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Delete unreadable local data" })).toBeVisible();
  await expect(page.getByRole("button", { name: /create|unlock|import|recover/iu })).toHaveCount(0);
});

test("stale empty create observes a deletion marker before doing local work", async ({ context, page }) => {
  await context.addInitScript(() => {
    Object.defineProperty(globalThis, "BroadcastChannel", { configurable: true, value: undefined });
  });
  // Isolate submission before the 2-second poll. The separate no-BC test
  // exercises normal polling; a slower CI runner must not erase this setup.
  await page.addInitScript(() => {
    const schedule = window.setInterval.bind(window);
    window.setInterval = ((handler: TimerHandler, delay?: number, ...args: unknown[]) => {
      const timer = schedule(handler, delay, ...args);
      if (delay === 2_000) window.clearInterval(timer);
      return timer;
    }) as typeof window.setInterval;
  });
  await page.goto("/workspace");
  const markerPage = await context.newPage();
  await createUnlockedWorkspace(markerPage);
  await markerPage.close();
  await markVaultDeletingAndHold(page);

  await page.getByLabel("Workspace passphrase", { exact: false }).fill(localPassphrase);
  await page.getByLabel("Confirm passphrase").fill(localPassphrase);
  await page.getByRole("button", { name: "Create encrypted workspace" }).click();
  await expectDeletingWithoutAccessControls(page);

  await releaseVaultDeletionBlocker(page);
  await expect(page.getByRole("heading", { name: "Create a private workspace" })).toBeVisible();
});

test("locked unlock and import observe a deletion marker before credentials or files are processed", async ({
  context,
  page,
}) => {
  await context.addInitScript(() => {
    Object.defineProperty(globalThis, "BroadcastChannel", { configurable: true, value: undefined });
  });
  await createUnlockedWorkspace(page);
  await page.getByRole("button", { name: "Lock workspace" }).click();
  await markVaultDeletingAndHold(page);

  await page.getByLabel("Workspace passphrase", { exact: false }).fill(localPassphrase);
  await page.getByRole("button", { name: "Unlock workspace" }).click();
  await expectDeletingWithoutAccessControls(page);
  await releaseVaultDeletionBlocker(page);
  await expect(page.getByRole("heading", { name: "Create a private workspace" })).toBeVisible();

  await createUnlockedWorkspace(page);
  await page.getByRole("button", { name: "Lock workspace" }).click();
  await markVaultDeletingAndHold(page);
  await page.getByRole("button", { name: "Import backup" }).click();
  await page.getByLabel("Encrypted .openarc backup").setInputFiles({
    name: "must-not-be-parsed.openarc",
    mimeType: "application/json",
    buffer: Buffer.from("NOT_A_BACKUP_PRIVATE_CANARY"),
  });
  await page.getByLabel("Backup passphrase").fill(backupPassphrase);
  await page.getByLabel("New workspace passphrase").fill(restoredPassphrase);
  await page.getByLabel("Confirm new passphrase").fill(restoredPassphrase);
  await page.getByRole("button", { name: "Verify and restore backup" }).click();
  await expectDeletingWithoutAccessControls(page);
  await releaseVaultDeletionBlocker(page);
  await expect(page.getByRole("heading", { name: "Create a private workspace" })).toBeVisible();
});

test("an unlocked export that observes a deletion marker becomes non-interactive immediately", async ({
  context,
  page,
}) => {
  await context.addInitScript(() => {
    Object.defineProperty(globalThis, "BroadcastChannel", { configurable: true, value: undefined });
  });
  await createUnlockedWorkspace(page);
  await page.getByRole("button", { name: /05 Settings/u }).click();
  await markVaultDeletingAndHold(page);
  await page.getByLabel("Backup passphrase", { exact: true }).first().fill(backupPassphrase);
  const download = page.waitForEvent("download", { timeout: 750 }).then(() => true).catch(() => false);
  await page.getByRole("button", { name: "Download encrypted backup" }).click();
  await expectDeletingWithoutAccessControls(page);
  expect(await download).toBe(false);

  await releaseVaultDeletionBlocker(page);
  await expect(page.getByRole("heading", { name: "Create a private workspace" })).toBeVisible();
});

test("treats an incompatible database upgrade as fatal and still exports opaque rescue", async ({ page }, testInfo) => {
  await page.goto("/workspace");
  await page.getByLabel("Workspace passphrase", { exact: false }).fill(localPassphrase);
  await page.getByLabel("Confirm passphrase").fill(localPassphrase);
  await page.getByRole("button", { name: "Create encrypted workspace" }).click();
  await page.getByRole("checkbox", { name: /I saved it somewhere private/u }).check();
  await page.getByRole("button", { name: "Continue to workspace" }).click();
  await page.getByRole("button", { name: "Skip" }).click();
  await page.getByRole("button", { name: /02 Agents/u }).click();
  await page.getByRole("button", { name: "Add agent profile" }).click();
  await page.getByLabel("Display name").fill("FUTURE_DB_PRIVATE_CANARY");
  await page.getByRole("button", { name: "Encrypt and save" }).click();

  await page.evaluate(
    () =>
      new Promise<void>((resolve, reject) => {
        const request = indexedDB.open("openarc-vault", 2);
        request.onsuccess = () => {
          request.result.close();
          resolve();
        };
        request.onerror = () => reject(request.error);
        request.onblocked = () => undefined;
      }),
  );
  await expect(page.getByRole("heading", { name: "Local workspace could not start" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Deleting encrypted workspace" })).toHaveCount(0);
  await expect(page.getByText("FUTURE_DB_PRIVATE_CANARY")).toHaveCount(0);

  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export opaque rescue" }).click();
  const download = await downloadPromise;
  const rescuePath = testInfo.outputPath("future-database-rescue.json");
  await download.saveAs(rescuePath);
  const rescue = await readTextFile(rescuePath);
  expect(rescue).toContain("OPENARC-OPAQUE-RESCUE");
  expect(rescue).not.toContain("FUTURE_DB_PRIVATE_CANARY");
});

/**
 * P04-06c — the purchase review is hosted in the workspace, and fails closed.
 *
 * This build enables the encrypted workspace but not commerce actions, so the
 * Purchases view must not exist at all: no rail entry, no decision control, and
 * ZERO commerce or capability requests. A `?view=purchases` address must fall
 * back to the overview rather than mounting a surface this build disabled.
 */
test("offers no purchase view or decision control when commerce actions are disabled", async ({ page }) => {
  const commerceRequests: string[] = [];
  page.on("request", (request) => {
    const { pathname } = new URL(request.url());
    if (pathname.startsWith("/v2/")) commerceRequests.push(pathname);
  });

  await page.goto("/workspace?view=purchases");
  await page.getByLabel("Workspace passphrase", { exact: false }).fill(localPassphrase);
  await page.getByLabel("Confirm passphrase").fill(localPassphrase);
  await page.getByRole("button", { name: "Create encrypted workspace" }).click();
  await page.getByRole("checkbox", { name: /I saved it somewhere private/u }).check();
  await page.getByRole("button", { name: "Continue to workspace" }).click();
  await page.getByRole("button", { name: "Skip" }).click();
  await expect(page.getByText("UNLOCKED LOCALLY")).toBeVisible();

  // The disabled view is not registered, so the address resolves to Overview.
  await expect(page.getByRole("heading", { name: "Your agent evidence, held here." })).toBeVisible();
  await expect(page.getByRole("button", { name: "Purchases", exact: true })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: /Review purchase/iu })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Approve purchase" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Reject purchase" })).toHaveCount(0);
  expect(commerceRequests).toEqual([]);
});

test("workspace and recovery dialogs pass serious accessibility checks on mobile", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/workspace");
  await page.getByLabel("Workspace passphrase", { exact: false }).fill(localPassphrase);
  await page.getByLabel("Confirm passphrase").fill(localPassphrase);
  await page.getByRole("button", { name: "Create encrypted workspace" }).click();
  await expect(page.locator(".workspace-shell")).toHaveAttribute("inert", "");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog", { name: "Save this recovery secret now" })).toBeVisible();
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(results.violations.filter((violation) => ["serious", "critical"].includes(violation.impact ?? ""))).toEqual([]);
  await page.getByRole("checkbox", { name: /I saved it somewhere private/u }).check();
  await page.getByRole("button", { name: "Continue to workspace" }).click();
  await page.getByRole("button", { name: "Skip" }).click();
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  const tourTrigger = page.getByRole("button", { name: "Open workspace tour" });
  await tourTrigger.click();
  await expect(page.locator(".workspace-shell")).toHaveAttribute("inert", "");
  await page.keyboard.press("Shift+Tab");
  await expect(page.getByRole("button", { name: "Next" })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(tourTrigger).toBeFocused();
  await tourTrigger.click();
  const tourTitles = [
    "What OpenArc can prove",
    "Where private data lives",
    "Add an agent wallet label",
    "Permission before every refresh",
    "Read evidence and incomplete states",
    "Lock, export, recover, and delete",
  ];
  for (const [index, title] of tourTitles.entries()) {
    await expect(page.getByRole("heading", { name: title, exact: true })).toBeVisible();
    if (title === "Permission before every refresh") {
      await expect(page.getByRole("dialog")).toContainText("When Activity is enabled in this build");
    }
    await expect(page.getByText(`STEP ${index + 1} OF 6`)).toBeVisible();
    await page.getByRole("button", { name: index === tourTitles.length - 1 ? "Open workspace" : "Next" }).click();
  }
  await expect(tourTrigger).toBeFocused();
  for (const [navigationName, title] of [
    ["Overview", "Your agent evidence, held here."],
    ["Agents", "Agents"],
    ["Policies", "Policies"],
    ["Evidence", "Evidence"],
    ["Settings", "Settings"],
  ] as const) {
    await page.getByRole("button", { name: navigationName, exact: true }).click();
    await expect(page.getByRole("heading", { name: title, exact: true })).toBeVisible();
    await expect(page.getByText("ENABLED · LOCAL ONLY")).toBeVisible();
    await expect(page.getByRole("button", { name: `About ${title}` })).toBeVisible();
    await expect(page.getByRole("link", { name: "Learn how this works" })).toBeVisible();
  }
  await expect(page.getByText(/It does not protect an unlocked tab/u)).toBeVisible();
  await expect(page.getByRole("link", { name: "Read the evidence guide" })).toHaveAttribute("href", "/#fixture-explorer");
  await expect(page.getByRole("link", { name: "Review the pinned network registry" })).toHaveAttribute("href", "/#network");
  const tourClosedResults = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(tourClosedResults.violations.filter((violation) => ["serious", "critical"].includes(violation.impact ?? ""))).toEqual([]);
  const targets = page.locator("button:visible");
  for (let index = 0; index < (await targets.count()); index += 1) {
    const box = await targets.nth(index).boundingBox();
    expect(box?.height ?? 0).toBeGreaterThanOrEqual(44);
  }
});

async function unlock(page: Page, passphrase: string) {
  await page.getByLabel("Workspace passphrase", { exact: false }).fill(passphrase);
  await page.getByRole("button", { name: "Unlock workspace" }).click();
  // PBKDF2 is intentionally expensive; allow CPU-constrained parallel WebKit
  // workers to finish without weakening the production KDF or the assertion.
  await expect(page.getByText("UNLOCKED LOCALLY")).toBeVisible({ timeout: 15_000 });
}

async function createUnlockedWorkspace(page: Page) {
  await page.goto("/workspace");
  await page.getByLabel("Workspace passphrase", { exact: false }).fill(localPassphrase);
  await page.getByLabel("Confirm passphrase").fill(localPassphrase);
  await page.getByRole("button", { name: "Create encrypted workspace" }).click();
  await page.getByRole("checkbox", { name: /I saved it somewhere private/u }).check();
  await page.getByRole("button", { name: "Continue to workspace" }).click();
  await page.getByRole("button", { name: "Skip" }).click();
  await expect(page.getByText("Tour preference saved inside the encrypted workspace.")).toBeVisible();
}

async function markVaultDeletingAndHold(page: Page) {
  await page.evaluate(async () => {
    const request = indexedDB.open("openarc-vault", 1);
    const database = await new Promise<IDBDatabase>((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    const transaction = database.transaction("vaultMeta", "readwrite");
    const store = transaction.objectStore("vaultMeta");
    const read = store.get("active");
    const meta = await new Promise<Record<string, unknown>>((resolve, reject) => {
      read.onsuccess = () => resolve(read.result as Record<string, unknown>);
      read.onerror = () => reject(read.error);
    });
    store.put({
      ...meta,
      coordinationRevision: crypto.randomUUID().replaceAll("-", "").slice(0, 32),
      deletionPending: true,
    });
    await new Promise<void>((resolve, reject) => {
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error);
    });
    Object.assign(globalThis, { __openArcMarkerBlocker: database });
  });
}

async function releaseVaultDeletionBlocker(page: Page) {
  await page.evaluate(() => {
    const database = (globalThis as typeof globalThis & { __openArcMarkerBlocker?: IDBDatabase })
      .__openArcMarkerBlocker;
    database?.close();
  });
}

async function expectDeletingWithoutAccessControls(page: Page) {
  await expect(page.getByRole("heading", { name: "Deleting encrypted workspace" })).toBeVisible({ timeout: 4_500 });
  await expect(page.getByRole("button", { name: /unlock|create|import|recover/iu })).toHaveCount(0);
}

async function readRawWorkspace(page: Page): Promise<unknown> {
  return page.evaluate(async () => {
    const request = indexedDB.open("openarc-vault", 1);
    const database = await new Promise<IDBDatabase>((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    try {
      const transaction = database.transaction(["vaultMeta", "records"], "readonly");
      const metaRequest = transaction.objectStore("vaultMeta").get("active");
      const recordsRequest = transaction.objectStore("records").getAll();
      const [meta, records] = await Promise.all([
        new Promise((resolve, reject) => {
          metaRequest.onsuccess = () => resolve(metaRequest.result);
          metaRequest.onerror = () => reject(metaRequest.error);
        }),
        new Promise((resolve, reject) => {
          recordsRequest.onsuccess = () => resolve(recordsRequest.result);
          recordsRequest.onerror = () => reject(recordsRequest.error);
        }),
      ]);
      return { meta, records };
    } finally {
      database.close();
    }
  });
}

async function readTextFile(path: string): Promise<string> {
  const { readFile } = await import("node:fs/promises");
  return readFile(path, "utf8");
}
