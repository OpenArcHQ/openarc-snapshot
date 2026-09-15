// PORT-08 compatibility rule (P08-01, §1.11 item 9): optional cross-check against the ROOT build's REAL sources,
// read only. Set OPENARC_ROOT_BUILD_DIR to a checkout of the ROOT build to enable it. Without it the dependent tests
// are skipped and the embedded re-derivation (root-build-reference.ts) still runs. Every pinned file is sha256-verified
// before anything is imported, so a drifted ROOT source fails loudly instead of silently changing what is checked.
// No local path is stored in this repository. Test-only; never imported by runtime code.
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";

export const ROOT_BUILD_DIR_ENV = "OPENARC_ROOT_BUILD_DIR";

/** ROOT build files (repo-relative) and the sha256 each had when P08-01 ported them. */
export const ROOT_BUILD_PINS = Object.freeze({
  "packages/shared/src/task-draft.ts": "e23d8fb6835759f401169a23e5c37dd3d482d0755a512f41ad67742a1434bb5b",
  "packages/shared/src/account-report-task.ts": "dbcf77c07f80226bcf160c90d4db19694b84e70224d54fe0508f5181607af81b",
  "packages/shared/src/research-run.ts": "9726ccd6ede6a328da7127e94a651a738cf60debf367242f159f883527ffcff2",
  "packages/shared/src/vault.ts": "f1f369b20df85ff59bee0e4a62aa332aa15677797fcba807ac721b173b3404bc",
  "apps/web/src/vault/types.ts": "6bb485ff6cb148c5b7439bb5467aa2440b74f6163ee568d76115f84df21ccaca",
  "apps/web/src/vault/service.ts": "379ab1d54abe054bd8e95ab88f822a75eac855d78ac3928dfd5101dece7e4e33",
  "apps/web/src/vault/task-drafts.ts": "b1abe6715b368791c094faa28dc5fe836119ab35c05883b67585465c35b54f25",
  "apps/web/src/vault/research-runs.ts": "7b231f57893075077157d093f34e8c3ac0f2b9b99f5b0abccfff5779900d7f44",
} as const);

export interface RootBuildContracts {
  WorkspaceRecordSchema: { safeParse(value: unknown): { success: boolean; data?: unknown } };
  accountReportDraftDigest(value: unknown): string;
  accountReportRequestDigest(value: unknown): string;
}

export async function loadRootBuild(): Promise<RootBuildContracts | null> {
  const directory = process.env[ROOT_BUILD_DIR_ENV];
  if (!directory) return null;
  for (const [file, pinned] of Object.entries(ROOT_BUILD_PINS)) {
    const actual = createHash("sha256").update(await readFile(path.join(directory, file))).digest("hex");
    if (actual !== pinned) {
      throw new Error(`ROOT build source ${file} drifted from its P08-01 sha256 pin (now ${actual}); re-review it first`);
    }
  }
  const vault = (await import(/* @vite-ignore */ path.join(directory, "packages/shared/src/vault.ts"))) as
    Pick<RootBuildContracts, "WorkspaceRecordSchema">;
  const report = (await import(/* @vite-ignore */ path.join(directory, "packages/shared/src/account-report-task.ts"))) as
    Omit<RootBuildContracts, "WorkspaceRecordSchema">;
  return {
    WorkspaceRecordSchema: vault.WorkspaceRecordSchema,
    accountReportDraftDigest: report.accountReportDraftDigest,
    accountReportRequestDigest: report.accountReportRequestDigest,
  };
}
