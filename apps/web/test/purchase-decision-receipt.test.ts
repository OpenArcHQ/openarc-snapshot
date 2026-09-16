// P04-06b — the v6 purchase-decision receipt inside a real encrypted Vault.
//
// Two separate obligations are proved here.
//
// FIRST, compatibility in the forward direction: a Vault holding a v6 receipt
// survives every durable path this build offers — save, unlock, encrypted
// backup, import, recovery, passphrase change and opaque rescue — and none of
// those paths ever exposes the receipt's plaintext.
//
// SECOND, compatibility in the backward direction, stated honestly rather than
// wished away: a build whose record union predates v6 CANNOT read a Vault that
// holds one. It reports the incompatible-Vault state, never a wrong passphrase,
// and never writes. That is modelled with a receipt version THIS build does not
// know, which stands in exactly the same relation to this reader as a v6
// receipt does to a pre-v6 reader.
import "fake-indexeddb/auto";

import {
  PURCHASE_DECISION_APPROVE_PATH,
  PURCHASE_DECISION_DISCLOSURE,
  PURCHASE_DECISION_REJECT_PATH,
  WORKSPACE_RECORD_IDENTITIES,
  WorkspaceRecordSchema,
  classifyWorkspaceRecordIdentity,
  type PurchaseDecisionPermissionReceiptRecord,
  type WorkspaceRecord,
} from "@openarc/shared";
import { afterEach, describe, expect, it } from "vitest";

import { buildPurchaseDecisionReceipt } from "../src/api/purchase-decision-flow.js";
import { createManifestSentinel } from "../src/vault/crypto.js";
import { VAULT_DATABASE_NAME, readVaultSnapshot } from "../src/vault/db.js";
import {
  VAULT_INCOMPATIBLE_MESSAGE,
  VaultIncompatibleError,
  vaultErrorMessage,
} from "../src/vault/errors.js";
import {
  assertWorkspaceIntegrity,
  createLocalWorkspace,
  deleteWorkspaceRecords,
  exportLocalWorkspace,
  exportOpaqueRescue,
  importLocalWorkspace,
  recoverLocalWorkspace,
  saveWorkspaceRecords,
  unlockLocalWorkspace,
  updateWorkspacePassphrase,
} from "../src/vault/service.js";
import type { EncryptedEnvelope, UnlockedWorkspace } from "../src/vault/types.js";
import {
  deleteIndexedDb,
  readIndexedDbImage,
  seedIndexedDbImage,
  storeRows,
} from "./vault-compat/fixture-io.js";
import { referenceEncryptEnvelope, toB64u } from "./vault-compat/reference-codec.js";
import { ACTION, APPROVAL, ORG, actionMetadata, approvalMetadata } from "./action-test-fixtures.js";

const PASSPHRASE = "Purchase decision local test passphrase";
const NEW_PASSPHRASE = "Purchase decision replacement passphrase";
const BACKUP_PASSPHRASE = "Independent purchase decision backup passphrase";
const ORIGIN = "https://app.example.test";
const MUTATION = "9f1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e5f";

const subject = (decision: "approve" | "reject" = "approve") => ({
  decision,
  organizationId: ORG,
  actionId: ACTION,
  mutationId: MUTATION,
  action: actionMetadata() as never,
  approval: approvalMetadata() as never,
});

/** The receipt exactly as the flow builds it, with a fixed clock and record id. */
function receiptFor(
  workspace: UnlockedWorkspace,
  decision: "approve" | "reject" = "approve",
): PurchaseDecisionPermissionReceiptRecord {
  return buildPurchaseDecisionReceipt(workspace, ORIGIN, subject(decision), {
    now: () => "2026-09-15T09:00:00.000Z",
    id: () => "3f2a1b0c-9d8e-4f7a-8b6c-5d4e3f2a1b0c",
  });
}

async function savedReceipt(decision: "approve" | "reject" = "approve") {
  const created = await createLocalWorkspace(PASSPHRASE);
  const built = receiptFor(created, decision);
  const workspace = await saveWorkspaceRecords(created, [built]);
  // A write stamps the record with the NEW Vault revision, so the stored
  // receipt is the one to compare against; every disclosed field is untouched.
  const receipt = workspace.records.find(
    (record) => record.recordId === built.recordId,
  ) as PurchaseDecisionPermissionReceiptRecord;
  expect(receipt).toBeDefined();
  expect({ ...receipt, recordRevision: built.recordRevision }).toEqual(built);
  return { workspace, receipt };
}

afterEach(async () => {
  await deleteIndexedDb(VAULT_DATABASE_NAME);
});

describe("P04-06b v6 purchase-decision receipt in the encrypted Vault", { timeout: 60_000 }, () => {
  it("is an additive record identity this build knows, alongside the five it already had", () => {
    expect(WORKSPACE_RECORD_IDENTITIES).toContain("permission_receipt|openarc.permission-receipt.v6");
    for (const version of ["v1", "v2", "v3", "v4", "v5"]) {
      expect(WORKSPACE_RECORD_IDENTITIES).toContain(`permission_receipt|openarc.permission-receipt.${version}`);
    }
    expect(classifyWorkspaceRecordIdentity({
      kind: "permission_receipt", recordSchema: "openarc.permission-receipt.v6" })).toBe("known");
  });

  it("round-trips through save, unlock, backup, import, recovery, passphrase change and rescue", async () => {
    const saved = await savedReceipt();

    // Nothing the receipt carries is legible in the stored ciphertext.
    const raw = JSON.stringify(await readVaultSnapshot(saved.workspace.meta.vaultId,
      saved.workspace.meta.revision, saved.workspace.meta.coordinationRevision));
    for (const canary of [ORG, ACTION, APPROVAL, MUTATION, "openarc_purchase_decision",
      "openarc.permission-receipt.v6", PURCHASE_DECISION_APPROVE_PATH, "1750000"]) {
      expect(raw, `plaintext canary in the stored Vault: ${canary}`).not.toContain(canary);
    }

    const unlocked = await unlockLocalWorkspace(saved.workspace.meta, PASSPHRASE);
    expect(unlocked.records).toContainEqual(saved.receipt);

    const backup = await exportLocalWorkspace(unlocked, BACKUP_PASSPHRASE);
    expect(JSON.stringify(backup)).not.toContain(MUTATION);

    const imported = await importLocalWorkspace(backup, BACKUP_PASSPHRASE, NEW_PASSPHRASE, unlocked.meta);
    const importedReceipt = imported.records.find(
      (record) => record.recordId === saved.receipt.recordId);
    expect(importedReceipt).toMatchObject({
      kind: "permission_receipt", recordSchema: "openarc.permission-receipt.v6",
      released: saved.receipt.released, reviewed: saved.receipt.reviewed });

    const recovered = await recoverLocalWorkspace(imported.meta, imported.recoverySecret, PASSPHRASE);
    expect(recovered.records).toContainEqual(expect.objectContaining({
      recordSchema: "openarc.permission-receipt.v6", recordId: saved.receipt.recordId }));

    const changed = await updateWorkspacePassphrase(recovered, PASSPHRASE, NEW_PASSPHRASE);
    const reopened = await unlockLocalWorkspace(changed.meta, NEW_PASSPHRASE);
    expect(reopened.records).toContainEqual(expect.objectContaining({
      recordSchema: "openarc.permission-receipt.v6", recordId: saved.receipt.recordId }));
    expect(() => assertWorkspaceIntegrity(reopened.records)).not.toThrow();

    const rescue = await exportOpaqueRescue();
    expect(rescue.records).toEqual(storeRows((await readIndexedDbImage(VAULT_DATABASE_NAME))!, "records"));
    expect(JSON.stringify(rescue)).not.toContain(MUTATION);
  });

  it("stands alone: a decision receipt needs no observation, and deletes on its own", async () => {
    const saved = await savedReceipt("reject");
    expect(saved.receipt.destination.path).toBe(PURCHASE_DECISION_REJECT_PATH);
    expect(() => assertWorkspaceIntegrity(saved.workspace.records)).not.toThrow();
    const remaining = await deleteWorkspaceRecords(saved.workspace, [saved.receipt.recordId]);
    expect(remaining.records.some((record) => record.recordId === saved.receipt.recordId)).toBe(false);
  });

  it("records what the human saw, and the disclosure says plainly what leaves the browser", async () => {
    const saved = await savedReceipt();
    const action = actionMetadata() as Record<string, unknown>;
    expect(saved.receipt.reviewed).toEqual({
      listingId: action.listingId, listingVersion: action.listingVersion,
      providerId: action.providerId, amountAtomic: "1500000", feeAtomic: "250000",
      debitAtomic: "1750000", asset: "USDC", decimals: 6, networkId: "eip155:5042002",
      policyId: action.policyId, policyRevision: "1",
      approvalId: APPROVAL, approvalExpiresAt: "2026-01-01T00:15:00.000Z" });
    expect(saved.receipt.destination).toEqual({ origin: ORIGIN,
      path: PURCHASE_DECISION_APPROVE_PATH, method: "POST", upstreams: [] });
    expect(saved.receipt.releasedFields)
      .toEqual(["organizationId", "actionId", "decision", "mutationId"]);
    expect(saved.receipt.purpose).toBe(PURCHASE_DECISION_DISCLOSURE.purpose);
    expect(saved.receipt.purpose).toContain("leave this browser");
    expect(saved.receipt.purpose).toContain("OpenArc control API");
    expect(saved.receipt.outcome).toBe("approved");
  });

  it("omits an approval expiry the console never had, instead of inventing one", async () => {
    const created = await createLocalWorkspace(PASSPHRASE);
    const receipt = buildPurchaseDecisionReceipt(created, ORIGIN,
      { ...subject(), approval: null }, { now: () => "2026-09-15T09:00:00.000Z" });
    expect({ approvalId: receipt.reviewed.approvalId, approvalExpiresAt: receipt.reviewed.approvalExpiresAt })
      .toEqual({ approvalId: null, approvalExpiresAt: null });
    await expect(saveWorkspaceRecords(created, [receipt])).resolves.toBeDefined();
  });
});

/**
 * The forward-compatibility consequence, written down rather than assumed. A
 * Vault holding a v6 receipt is unreadable by any build released before v6
 * existed; that build reports the incompatible-Vault state and writes nothing.
 */
describe("P04-06b an older build cannot read a Vault holding a v6 receipt", { timeout: 60_000 }, () => {
  /** A receipt version this build does not know, standing in for v6 seen by a pre-v6 reader. */
  const unknownVersionReceipt = (receipt: PurchaseDecisionPermissionReceiptRecord) => ({
    ...receipt, recordSchema: "openarc.permission-receipt.v7",
    recordId: "4a3b2c1d-0e9f-4a8b-9c7d-6e5f4a3b2c1d" });

  it("classifies a receipt version outside its union as unknown, exactly as a pre-v6 build sees v6", async () => {
    const created = await createLocalWorkspace(PASSPHRASE);
    const future = unknownVersionReceipt(receiptFor(created));
    expect(classifyWorkspaceRecordIdentity(future)).toBe("unknown");
    expect(WorkspaceRecordSchema.safeParse(future).success).toBe(false);
    // A pre-v6 build's identity table is this one minus the v6 pair.
    const beforeV6 = WORKSPACE_RECORD_IDENTITIES
      .filter((identity) => identity !== "permission_receipt|openarc.permission-receipt.v6");
    expect(beforeV6).not.toContain("permission_receipt|openarc.permission-receipt.v6");
    expect(beforeV6.some((identity) => identity.startsWith("permission_receipt|"))).toBe(true);
  });

  it("reports VAULT_INCOMPATIBLE, never a wrong passphrase, and never writes", async () => {
    const created = await createLocalWorkspace(PASSPHRASE);
    const future = unknownVersionReceipt(receiptFor(created));
    const unlocked = await unlockLocalWorkspace(created.meta, PASSPHRASE);

    // Seed the record past every parser, exactly as a newer build would have
    // written it: AES-GCM under the same data key and the unchanged v1 record
    // AAD, with a freshly recomputed manifest sentinel.
    const image = (await readIndexedDbImage(VAULT_DATABASE_NAME))!;
    const envelope = await referenceEncryptEnvelope(unlocked.key, unlocked.meta.vaultId, future,
      unlocked.meta.revision, toB64u(new TextEncoder().encode("P0406BFUTURE")));
    const others = (storeRows(image, "records") as EncryptedEnvelope[])
      .filter((row) => row.id !== unlocked.meta.sentinelRecordId);
    const sentinel = await createManifestSentinel(unlocked.meta, unlocked.key,
      [...others, envelope], "2026-09-15T09:30:00.000Z");
    const seeded = { ...image, stores: image.stores.map((store) => store.name === "records"
      ? { ...store, rows: [...others, envelope, sentinel.envelope]
          .sort((left, right) => left.id.localeCompare(right.id)) }
      : store) };
    await deleteIndexedDb(VAULT_DATABASE_NAME);
    await seedIndexedDbImage(seeded);

    const failure = await unlockLocalWorkspace(unlocked.meta, PASSPHRASE)
      .then(() => null, (cause: unknown) => cause);
    expect(failure).toBeInstanceOf(VaultIncompatibleError);
    expect(failure).toMatchObject({ code: "VAULT_INCOMPATIBLE", source: "vault",
      reason: "unknown_record_identity", message: VAULT_INCOMPATIBLE_MESSAGE });
    expect(vaultErrorMessage(failure)).toBe(VAULT_INCOMPATIBLE_MESSAGE);
    expect(VAULT_INCOMPATIBLE_MESSAGE).not.toContain("Wrong passphrase");

    // The real wrong-passphrase path still fails first, on the key unwrap.
    await expect(unlockLocalWorkspace(unlocked.meta, "TEST-ONLY wrong passphrase"))
      .rejects.toMatchObject({ code: "INVALID_PASSPHRASE" });
    // An incompatible Vault is never rewritten, and opaque rescue still works.
    expect(await readIndexedDbImage(VAULT_DATABASE_NAME)).toEqual(seeded);
    const rescue = await exportOpaqueRescue();
    expect(rescue.records).toEqual(storeRows(seeded, "records"));
  });
});

/** Nothing above may be readable as a payment having happened. */
describe("P04-06b the receipt never describes a payment", () => {
  it("carries no payment outcome vocabulary in any disclosure field", () => {
    const forbidden = /\b(?:paid|settled|refunded|failed|released)\b/iu;
    for (const [field, text] of Object.entries(PURCHASE_DECISION_DISCLOSURE)) {
      expect(forbidden.test(text), `forbidden payment word in ${field}: ${text}`).toBe(false);
    }
  });

  it("has no field that could hold a payment, transfer or settlement claim", async () => {
    const saved = await savedReceipt();
    for (const extra of [{ transferId: MUTATION }, { paymentStatus: "paid" }, { amountPaid: "1750000" }]) {
      const widened = { ...saved.receipt, ...extra } as unknown as WorkspaceRecord;
      expect(WorkspaceRecordSchema.safeParse(widened).success).toBe(false);
      await expect(saveWorkspaceRecords(saved.workspace, [widened]))
        .rejects.toMatchObject({ code: "INVALID_BACKUP" });
    }
  });
});
