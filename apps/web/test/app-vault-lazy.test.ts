import { readFile } from "node:fs/promises";
import path from "node:path";

import { describe, expect, it } from "vitest";

const srcDir = path.resolve(import.meta.dirname, "../src");
const source = (relative: string) => readFile(path.join(srcDir, relative), "utf8");
const staticVaultImport = /^\s*import\s[^;]*?from\s+["'](?:\.\.\/vault\/|\.\/vault\/)/mu;
const staticRelativeImport = /^\s*(?:import|export)\s(?!type\s)[^;]*?from\s+["'](\.{1,2}\/[^"']+)["']/gmu;

/** Follows value (non-type) relative static imports from one source file. */
async function staticClosure(entry: string): Promise<Set<string>> {
  const seen = new Set<string>();
  const pending = [entry];
  while (pending.length > 0) {
    const relative = pending.pop()!;
    if (seen.has(relative)) continue;
    seen.add(relative);
    const text = await source(relative);
    for (const match of text.matchAll(staticRelativeImport)) {
      const target = path.posix.normalize(path.posix.join(path.posix.dirname(relative), match[1]!));
      const base = target.replace(/\.js$/u, "");
      for (const candidate of [`${base}.ts`, `${base}.tsx`]) {
        if (await readFile(path.join(srcDir, candidate)).then(() => true, () => false)) {
          pending.push(candidate);
          break;
        }
      }
    }
  }
  return seen;
}

describe("PORT-08 Vault workspace code splitting", () => {
  it("App.tsx reaches the Vault workspace only through a dynamic import", async () => {
    const app = await source("App.tsx");
    expect(app).not.toMatch(staticVaultImport);
    expect(app).toContain('import("./vault/VaultWorkspace.js")');
  });

  it("no Vault workspace, storage or crypto module is in App.tsx's static import graph", async () => {
    const closure = [...await staticClosure("App.tsx")];
    expect(closure.filter((file) => file.startsWith("vault/"))).toEqual([]);
  });

  /**
   * P04-06c mounts the purchase review inside the Vault workspace, which pulls
   * the protected console's review modules into the LAZY workspace chunk. That
   * direction is fine; the reverse is not. A public route must still download
   * no Vault code, and the protected console must still reach the Vault only
   * through type-only imports, which are erased at build time.
   */
  it("the workspace purchase review is reachable only through the lazy Vault entry", async () => {
    const workspaceClosure = await staticClosure("vault/VaultWorkspace.tsx");
    expect([...workspaceClosure]).toContain("vault/PurchasesPanel.tsx");
    expect([...workspaceClosure]).toContain("tenant/PurchaseReviewPanel.tsx");

    const appClosure = [...await staticClosure("App.tsx")];
    for (const module of [
      "vault/PurchasesPanel.tsx",
      "vault/purchase-binding.ts",
      "tenant/PurchaseReviewPanel.tsx",
      "tenant/purchase-controller.ts",
    ]) {
      expect(appClosure, `public entry must not statically reach ${module}`).not.toContain(module);
    }
  });

  it("the protected console still pulls no Vault module into its own chunk", async () => {
    const closure = [...await staticClosure("tenant/TenantApp.tsx")];
    expect(closure.filter((file) => file.startsWith("vault/"))).toEqual([]);
  });

  it("the session-end lock bridge stays dynamic and never pulls the workspace statically", async () => {
    const trigger = await source("app/vault-session-lock.ts");
    expect(trigger).not.toMatch(staticVaultImport);
    expect(trigger).toContain('import("../vault/session-bridge.js")');
    const bridgeClosure = await staticClosure("vault/session-bridge.ts");
    expect([...bridgeClosure]).not.toContain("vault/VaultWorkspace.tsx");
  });
});
