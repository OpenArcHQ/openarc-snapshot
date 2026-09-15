/**
 * P08-00 Vault compatibility freeze: golden fixture GENERATOR. Test-only; never imported by runtime code.
 *
 * This file is deliberately NOT a `*.test.ts` file, so the normal `vitest run` never executes it and the
 * compatibility tests only ever read the frozen files under `apps/web/test/fixtures/vault-compat/`.
 *
 * Regenerate (only when a reviewed, intentional fixture change is required; regeneration can never be used
 * to "fix" a failing compatibility test, because frozen fixtures must stay readable by every later build):
 *
 *   pnpm --filter @openarc/shared build
 *   cd apps/web && npx vitest run --config test/vault-compat/vitest.generate.config.ts
 *
 * Determinism check (writes to a scratch directory instead; the output must be byte-identical):
 *
 *   OPENARC_VAULT_COMPAT_OUT=/tmp/vault-compat-check npx vitest run --config test/vault-compat/vitest.generate.config.ts
 *
 * Deterministic randomness is injected only here, through test-local spies on the existing Web Crypto and
 * Date seams: `crypto.getRandomValues` (salts, IVs, revisions, recovery secret, opaque IDs),
 * `crypto.randomUUID` (vault, sentinel and service-created record IDs), `crypto.subtle.generateKey`
 * (the AES-GCM data key) and a fake system clock. No production source is changed or mocked otherwise.
 * Every injected value is an obviously synthetic TEST-ONLY pattern. The generated Vault goes through the
 * real integration service: create, save, save, unlock, export backup and export opaque rescue.
 */
import "fake-indexeddb/auto";

import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

import { afterAll, describe, expect, it, vi } from "vitest";
import {
  AGENT_REGISTRY_DISCLOSURE,
  AGENT_REGISTRY_EVIDENCE_PATH,
  ARC_ACCOUNT_SNAPSHOT_PATH,
  ARC_ERC8004,
  ARC_OBSERVATION_DISCLOSURE,
  ARC_TESTNET,
  ARC_TRANSACTION_EVIDENCE_PATH,
  CAPABILITIES_PATH,
  CAPABILITY_DISCLOSURE,
  GATEWAY_DISCLOSURE,
  GATEWAY_TRANSFER_PATH,
  JOB_DISCLOSURE,
  JOB_EVIDENCE_PATH,
  M01_FIXTURES,
  WorkspaceRecordSchema,
  type WorkspaceRecord,
} from "@openarc/shared";

import { decryptEncryptedBackup } from "../../src/vault/crypto.js";
import { VAULT_DATABASE_NAME } from "../../src/vault/db.js";
import {
  createAgentProfileRecord,
  createFixtureWorkspaceRecords,
  createLocalWorkspace,
  exportLocalWorkspace,
  exportOpaqueRescue,
  markTourSeen,
  saveWorkspaceRecords,
  unlockLocalWorkspace,
} from "../../src/vault/service.js";
import { jobTestEnvelope, JOB_TEST_REQUEST } from "../../../../test-fixtures/job-evidence.js";
import { GATEWAY_TEST_REQUEST, gatewayEnvelope } from "../gateway-test-fixtures.js";
import {
  VAULT_COMPAT_FILES,
  VAULT_COMPAT_FIXTURE_DIR,
  readIndexedDbImage,
  sha256Hex,
  type VaultCompatManifest,
} from "./fixture-io.js";

export const VAULT_COMPAT_SECRETS = Object.freeze({
  workspacePassphrase: "TEST-ONLY vault-compat workspace passphrase P08-00",
  backupPassphrase: "TEST-ONLY vault-compat backup passphrase P08-00",
});
const ORIGIN = "https://app.example.test";
const INTEGRATION_COMMIT = "0f5caa9";

/** Fixed, visibly synthetic record identifiers: 7e57 ("test") prefix, UUIDv4-shaped. */
const testId = (n: number) => `7e570000-0000-4000-8000-${n.toString(16).padStart(12, "0")}`;
const TEST_ONLY_PATTERN = new TextEncoder().encode("TESTONLY");
const TEST_ONLY_DATA_KEY = new TextEncoder().encode("TEST-ONLY-P08-00-VAULT-DATA-KEY!");

function installDeterministicSeams() {
  let randomCalls = 0;
  let uuidCalls = 0;
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.spyOn(crypto, "getRandomValues").mockImplementation(<T extends ArrayBufferView | null>(array: T): T => {
    if (!array) return array;
    randomCalls += 1;
    const bytes = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
    bytes.forEach((_, index) => { bytes[index] = TEST_ONLY_PATTERN[index % TEST_ONLY_PATTERN.length]!; });
    // A big-endian call counter in the trailing four bytes keeps every salt, IV and revision unique.
    for (let index = 0; index < Math.min(4, bytes.length); index += 1) {
      bytes[bytes.length - 1 - index] = (randomCalls >>> (8 * index)) & 0xff;
    }
    return array;
  });
  vi.spyOn(crypto, "randomUUID").mockImplementation(() => {
    uuidCalls += 1;
    return `7e57a000-0000-4000-8000-${uuidCalls.toString(16).padStart(12, "0")}` as `${string}-${string}-${string}-${string}-${string}`;
  });
  const importKey = crypto.subtle.importKey.bind(crypto.subtle);
  vi.spyOn(crypto.subtle, "generateKey").mockImplementation((async () =>
    importKey("raw", TEST_ONLY_DATA_KEY, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])) as unknown as typeof crypto.subtle.generateKey);
}

function at(time: string) {
  vi.setSystemTime(new Date(time));
}

function capabilityReceipts(recordRevision: string): unknown[] {
  const approvedAt = "2026-09-10T10:00:00Z";
  const base = { recordSchema: "openarc.permission-receipt.v1", kind: "permission_receipt", recordRevision,
    createdAt: approvedAt, connectorId: CAPABILITY_DISCLOSURE.connectorId,
    destination: { origin: ORIGIN, path: CAPABILITIES_PATH, method: "GET", upstreams: [] }, releasedFields: [],
    purpose: CAPABILITY_DISCLOSURE.purpose, credentials: CAPABILITY_DISCLOSURE.credentials,
    openArcRetention: CAPABILITY_DISCLOSURE.openArcRetention, providerRetention: CAPABILITY_DISCLOSURE.providerRetention,
    hostingMetadata: CAPABILITY_DISCLOSURE.hostingMetadata, approvedAt };
  return [
    { ...base, recordId: testId(0x101), updatedAt: "2026-09-10T10:00:01Z", outcome: "completed",
      resolvedAt: "2026-09-10T10:00:01Z", failureCode: null },
    { ...base, recordId: testId(0x102), updatedAt: "2026-09-10T10:00:02Z", outcome: "failed",
      resolvedAt: "2026-09-10T10:00:02Z", failureCode: "REQUEST_UNAVAILABLE" },
  ];
}

const arcAnchor = { blockNumber: "100", blockHash: `0x${"a".repeat(64)}`, blockTimestamp: "2026-09-10T11:59:59Z",
  finality: "deterministic", confirmations: "1" };
const arcSource = { sourceId: "arc_primary_rpc", origin: ARC_TESTNET.rpcHttp, explorerOrigin: ARC_TESTNET.explorerOrigin,
  network: ARC_TESTNET.caip2, sourceRevision: ARC_TESTNET.sourceRevision, observedAt: "2026-09-10T12:00:00Z",
  adapterVersion: "openarc.arc-observation.m04.v1" };

function arcObservationRecords(recordRevision: string): unknown[] {
  const approvedAt = "2026-09-10T12:00:00Z";
  const address = "0x1111111111111111111111111111111111111111";
  const transactionHash = `0x${"b".repeat(64)}`;
  const receiptBase = { recordSchema: "openarc.permission-receipt.v2", kind: "permission_receipt", recordRevision,
    createdAt: approvedAt, ...ARC_OBSERVATION_DISCLOSURE, approvedAt };
  const accountDestination = { origin: ORIGIN, path: ARC_ACCOUNT_SNAPSHOT_PATH, method: "POST", upstreams: [ARC_TESTNET.rpcHttp] };
  const accountReceipt = { ...receiptBase, recordId: testId(0x201), updatedAt: approvedAt,
    connectorId: "arc_account_snapshot", destination: accountDestination,
    releasedFields: ["network", "address"], released: { network: ARC_TESTNET.caip2, address },
    purpose: "Observe one public Arc Testnet address at one exact final block.",
    outcome: "completed", resolvedAt: approvedAt, failureCode: null };
  const pendingAccountReceipt = { ...accountReceipt, recordId: testId(0x203), outcome: "approved", resolvedAt: null,
    released: { network: ARC_TESTNET.caip2, address: "0x4444444444444444444444444444444444444444" } };
  const transactionReceipt = { ...receiptBase, recordId: testId(0x202), updatedAt: approvedAt,
    connectorId: "arc_transaction_evidence",
    destination: { origin: ORIGIN, path: ARC_TRANSACTION_EVIDENCE_PATH, method: "POST", upstreams: [ARC_TESTNET.rpcHttp] },
    releasedFields: ["network", "transactionHash"], released: { network: ARC_TESTNET.caip2, transactionHash },
    purpose: "Observe one public Arc Testnet transaction, receipt, anchor, fee, and USDC movement set.",
    outcome: "completed", resolvedAt: approvedAt, failureCode: null };
  const native = { baseUnits: "1000000000000000000", decimals: 18, decimal: "1" };
  const accountObservation = { recordSchema: "openarc.arc-observation-record.v1", kind: "arc_observation",
    recordId: testId(0x211), recordRevision, createdAt: approvedAt, updatedAt: approvedAt,
    permissionReceiptId: testId(0x201), observation: {
      schemaVersion: "openarc.arc-account-snapshot.v1", network: ARC_TESTNET.caip2, address, anchor: arcAnchor,
      nativeUsdc: { asset: "USDC", interface: "native", amount: native },
      erc20UsdcView: { asset: "USDC", interface: "erc20", contract: ARC_TESTNET.contracts.usdc,
        amount: { baseUnits: "1000000", decimals: 6, decimal: "1" }, relationship: "same_underlying_balance",
        truncatesSubMicroUsdc: true },
      source: arcSource,
      limitations: ["This is a read-only observation at one exact Arc Testnet block.",
        "The 6-decimal ERC-20 view truncates native precision below one micro-USDC.",
        "A public address is not proof that its owner or controller is an agent."] } };
  const zero = { baseUnits: "0", decimals: 18, decimal: "0" };
  const transactionObservation = { recordSchema: "openarc.arc-observation-record.v1", kind: "arc_observation",
    recordId: testId(0x212), recordRevision, createdAt: approvedAt, updatedAt: approvedAt,
    permissionReceiptId: testId(0x202), observation: {
      schemaVersion: "openarc.arc-transaction-evidence.v1", network: ARC_TESTNET.caip2,
      transaction: { hash: transactionHash, blockNumber: "100", blockHash: arcAnchor.blockHash, transactionIndex: "0",
        from: address, to: "0x2222222222222222222222222222222222222222", nativeValue: zero },
      receipt: { status: "success", gasUsed: "1", effectiveGasPrice: zero, fee: zero }, anchor: arcAnchor,
      movements: [], coverage: { totalLogs: 0, canonicalMovements: 0, corroboratedMovements: 0, unsupportedLogs: 0,
        completeForUsdcTransfers: true }, source: arcSource,
      limitations: ["This is a read-only observation of one Arc Testnet transaction and receipt.",
        "EIP-7708 system events are canonical; matching ERC-20 events are corroboration, not additional movements.",
        "Transaction inclusion does not prove intent, authorization, fulfillment, or service quality."] } };
  return [accountReceipt, transactionReceipt, pendingAccountReceipt, accountObservation, transactionObservation];
}

function registryRecords(recordRevision: string, linkedAgentProfileRecordId: string): unknown[] {
  const approvedAt = "2026-09-11T12:00:00Z";
  return [
    { recordSchema: "openarc.permission-receipt.v3", kind: "permission_receipt", recordId: testId(0x301), recordRevision,
      createdAt: approvedAt, updatedAt: approvedAt, connectorId: "arc_agent_registry_evidence",
      destination: { origin: ORIGIN, path: AGENT_REGISTRY_EVIDENCE_PATH, method: "POST", upstreams: [ARC_TESTNET.rpcHttp] },
      releasedFields: ["network", "agentId"], released: { network: ARC_TESTNET.caip2, agentId: "1" },
      purpose: "Observe one ERC-8004 agent identity and optional exact observer or validator claims at one final Arc Testnet block.",
      ...AGENT_REGISTRY_DISCLOSURE, approvedAt, outcome: "completed", resolvedAt: approvedAt, failureCode: null },
    { recordSchema: "openarc.agent-registry-observation-record.v1", kind: "agent_registry_observation",
      recordId: testId(0x311), recordRevision, createdAt: approvedAt, updatedAt: approvedAt,
      permissionReceiptId: testId(0x301), linkedAgentProfileRecordId, observation: {
        schemaVersion: "openarc.agent-registry-evidence.v1", network: ARC_TESTNET.caip2, agentId: "1",
        anchor: { ...arcAnchor, blockHash: `0x${"b".repeat(64)}`, blockTimestamp: approvedAt },
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
            validation: ARC_TESTNET.contracts.erc8004ValidationRegistry }, observedAt: approvedAt,
          adapterVersion: "openarc.agent-registry-evidence.m05.v1" },
        limitations: ["ERC-8004 is a draft standard; registry facts may change before finalization.",
          "Identity ownership and metadata are registry claims, not proof of safety, quality, or control.",
          "Feedback is one observer's claim and validation is one validator's response; neither is a universal score.",
          "Metadata is untrusted external text and was not fetched or rendered by OpenArc."] } },
  ];
}

function jobRecords(recordRevision: string, linkedActionRecordId: string): unknown[] {
  const approvedAt = "2026-09-12T12:00:00Z";
  return [
    { recordSchema: "openarc.permission-receipt.v4", kind: "permission_receipt", recordId: testId(0x401), recordRevision,
      createdAt: approvedAt, updatedAt: approvedAt, connectorId: "arc_job_evidence",
      destination: { origin: ORIGIN, path: JOB_EVIDENCE_PATH, method: "POST", upstreams: [ARC_TESTNET.rpcHttp] },
      releasedFields: ["network", "jobId"], released: { ...JOB_TEST_REQUEST },
      purpose: "Observe one job on the reviewed Arc Testnet reference contract and an optional exact submission receipt.",
      ...JOB_DISCLOSURE, approvedAt, outcome: "completed", resolvedAt: approvedAt, failureCode: null },
    { recordSchema: "openarc.job-observation-record.v1", kind: "job_observation", recordId: testId(0x411), recordRevision,
      createdAt: approvedAt, updatedAt: approvedAt, permissionReceiptId: testId(0x401),
      linkedActionRecordId, linkBasis: "explicit_local_confirmation", observation: jobTestEnvelope().data },
  ];
}

function gatewayRecords(recordRevision: string): unknown[] {
  const approvedAt = "2026-09-13T12:00:00Z";
  return [
    { recordSchema: "openarc.x402-bundle-record.v1", kind: "x402_bundle", recordId: testId(0x501), recordRevision,
      createdAt: "2026-09-05T12:03:00Z", updatedAt: "2026-09-05T12:03:00Z",
      bundle: { schemaVersion: "openarc.x402-receipt-bundle.v1", bundleId: testId(0x5b1),
        capturedAt: "2026-09-05T12:03:00Z", provenance: "imported_metadata", authentication: "not_verified",
        resource: { originDigest: `sha256:${"b".repeat(64)}`, resourceDigest: `sha256:${"c".repeat(64)}` },
        responseMetadata: { respondedAt: "2026-09-05T12:01:00Z", httpStatus: 200, reportedSuccess: true,
          responseDigest: `sha256:${"d".repeat(64)}`, transferId: GATEWAY_TEST_REQUEST.transferId } } },
    { recordSchema: "openarc.permission-receipt.v5", kind: "permission_receipt", recordId: testId(0x502), recordRevision,
      createdAt: approvedAt, updatedAt: approvedAt, connectorId: "circle_gateway_transfer",
      destination: { origin: ORIGIN, path: GATEWAY_TRANSFER_PATH, method: "POST",
        upstreams: ["https://gateway-api-testnet.circle.com"] },
      releasedFields: ["network", "transferId"], released: { ...GATEWAY_TEST_REQUEST },
      purpose: "Read one exact Circle Gateway Arc Testnet transfer; this does not verify fulfillment.",
      ...GATEWAY_DISCLOSURE, approvedAt, outcome: "completed", resolvedAt: approvedAt, failureCode: null },
    { recordSchema: "openarc.gateway-observation-record.v1", kind: "gateway_observation", recordId: testId(0x511),
      recordRevision, createdAt: approvedAt, updatedAt: approvedAt, permissionReceiptId: testId(0x502),
      linkedBundleRecordId: testId(0x501), linkBasis: "explicit_local_confirmation", observation: gatewayEnvelope().data },
  ];
}

function agentImportAndPolicyRecords(recordRevision: string, profileRecordId: string): unknown[] {
  const createdAt = "2026-09-14T12:00:00Z";
  return [
    { recordSchema: "openarc.agent-import-record.v1", kind: "agent_import", recordId: testId(0x601), recordRevision,
      createdAt, updatedAt: createdAt, linkedAgentProfileRecordId: profileRecordId, linkBasis: "explicit_local_confirmation",
      report: { schemaVersion: "openarc.agent-import.v1", importId: testId(0x6a1), capturedAt: "2026-09-14T11:00:00Z",
        connectorId: "synthetic-agent-v1", authentication: "not_verified",
        events: [{ eventId: testId(0x6e1), actionId: "synthetic-action", occurredAt: "2026-09-14T10:59:00Z",
          network: ARC_TESTNET.caip2, asset: ARC_TESTNET.contracts.usdc, decimals: 6,
          payer: `0x${"11".repeat(20)}`, recipient: `0x${"22".repeat(20)}`, amountBaseUnits: "9007199254740993000",
          reportedStatus: "attempted", contract: null, serviceDigest: null, authorizationNonce: null,
          authorizationDomainDigest: null, approval: "not_supplied" }] } },
    { recordSchema: "openarc.agent-policy-record.v2", kind: "agent_monitoring_policy", recordId: testId(0x701),
      recordRevision, createdAt, updatedAt: createdAt,
      policy: { schemaVersion: "openarc.agent-policy.v2", policyId: testId(0x7a1), revision: 1,
        name: "TEST-ONLY local review policy", agentProfileRecordId: profileRecordId, enabled: true,
        validAfter: "2026-09-01T00:00:00Z", validBefore: "2026-10-01T00:00:00Z", perActionLimit: "1000",
        dailyLimit: "1000000", allowRecipients: [], blockRecipients: [], allowContracts: [], blockContracts: [],
        allowServices: [], blockServices: [], requireApproval: true, mode: "local_monitoring_only" } },
  ];
}

function jsonFile(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function countByKind(records: readonly WorkspaceRecord[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const record of records) counts[record.kind] = (counts[record.kind] ?? 0) + 1;
  return Object.fromEntries(Object.entries(counts).sort(([left], [right]) => left.localeCompare(right)));
}

describe("P08-00 vault compatibility fixture generator", () => {
  afterAll(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("writes deterministic golden fixtures from the current integration build", async () => {
    const outDir = process.env.OPENARC_VAULT_COMPAT_OUT ?? VAULT_COMPAT_FIXTURE_DIR;
    installDeterministicSeams();

    at("2026-09-15T09:00:00.000Z");
    const created = await createLocalWorkspace(VAULT_COMPAT_SECRETS.workspacePassphrase);

    at("2026-09-15T09:05:00.000Z");
    const revision = created.meta.revision;
    const m01 = createFixtureWorkspaceRecords(M01_FIXTURES[0]!, revision);
    const m01Agent = m01.find((record) => record.kind === "agent_profile")!;
    const m01Action = m01.find((record) => record.kind === "action_envelope")!;
    const walletAgent = createAgentProfileRecord({ displayName: "TEST-ONLY wallet agent",
      walletAddress: `0x${"5".repeat(40)}`, frameworkLabel: "TEST-ONLY framework",
      purposeNote: "TEST-ONLY purpose note" }, revision);
    const records = [
      ...m01,
      walletAgent,
      ...capabilityReceipts(revision),
      ...arcObservationRecords(revision),
      ...registryRecords(revision, m01Agent.recordId),
      ...jobRecords(revision, m01Action.recordId),
      ...gatewayRecords(revision),
      ...agentImportAndPolicyRecords(revision, walletAgent.recordId),
    ].map((record) => WorkspaceRecordSchema.parse(record));
    const firstSave = await saveWorkspaceRecords(created, records);

    at("2026-09-15T09:10:00.000Z");
    const settings = firstSave.records.find((record) => record.kind === "workspace_settings")!;
    const secondSave = await saveWorkspaceRecords(firstSave, [markTourSeen(settings)]);

    at("2026-09-15T09:15:00.000Z");
    const unlocked = await unlockLocalWorkspace(secondSave.meta, VAULT_COMPAT_SECRETS.workspacePassphrase);
    expect(unlocked.records).toEqual(secondSave.records);
    const kinds = new Set(unlocked.records.map((record) => record.kind));
    expect(kinds.size).toBe(14);
    const image = await readIndexedDbImage(VAULT_DATABASE_NAME);
    const backup = await exportLocalWorkspace(unlocked, VAULT_COMPAT_SECRETS.backupPassphrase);
    const logical = (await decryptEncryptedBackup(backup, VAULT_COMPAT_SECRETS.backupPassphrase)).archive;

    at("2026-09-15T09:20:00.000Z");
    const rescue = await exportOpaqueRescue();

    const contents: Record<string, string> = {
      [VAULT_COMPAT_FILES.snapshot]: jsonFile(image),
      [VAULT_COMPAT_FILES.expectedRecords]: jsonFile(unlocked.records),
      // Byte-identical to the browser download: VaultWorkspace `downloadJson` uses JSON.stringify(value).
      [VAULT_COMPAT_FILES.encryptedBackup]: JSON.stringify(backup),
      [VAULT_COMPAT_FILES.logicalBackup]: jsonFile(logical),
      [VAULT_COMPAT_FILES.opaqueRescue]: JSON.stringify(rescue),
    };
    const manifest: VaultCompatManifest = {
      packet: "P08-00",
      warning: "TEST-ONLY synthetic fixtures. Secrets below protect only these files. Never regenerate to make a compatibility test pass.",
      integrationCommit: INTEGRATION_COMMIT,
      generator: "apps/web/test/vault-compat/generate-fixtures.ts",
      command: "cd apps/web && npx vitest run --config test/vault-compat/vitest.generate.config.ts",
      secrets: { ...VAULT_COMPAT_SECRETS, recoverySecret: created.recoverySecret },
      recordCountsByKind: countByKind(unlocked.records),
      receiptSchemas: [...new Set(unlocked.records.flatMap((record) =>
        record.kind === "permission_receipt" ? [record.recordSchema] : []))].sort(),
      files: Object.fromEntries(Object.entries(contents).sort(([left], [right]) => left.localeCompare(right))
        .map(([name, text]) => [name, { bytes: Buffer.byteLength(text), sha256: sha256Hex(text) }])),
    };
    await mkdir(outDir, { recursive: true });
    for (const [name, text] of Object.entries(contents)) await writeFile(path.join(outDir, name), text);
    await writeFile(path.join(outDir, "manifest.json"), jsonFile(manifest));
  }, 120_000);
});
