import {
  ARC_TESTNET,
  accountReportDraftDigest,
  ActionEnvelopeRecordSchema,
  AgentProfileRecordSchema,
  AgentImportRecordSchema, AgentImportSchema, AgentMonitoringPolicyRecordSchema, AgentMonitoringPolicySchema,
  AGENT_POLICY_MAX_EVENTS, compareIsoTimestamps, IsoTimestampSchema,
  EvidenceRecordRecordSchema,
  MonitoringPolicyRecordSchema,
  MonitoringPolicySchema,
  WorkspaceRecordSchema,
  WorkspaceSettingsRecordSchema,
  reconcileAction,
  type AgentProfileRecord,
  type AgentImportRecord, type AgentMonitoringPolicyRecord,
  type EvidenceFixture,
  type MonitoringPolicyRecord,
  type WorkspaceRecord,
} from "@openarc/shared";

import {
  authenticateVaultSnapshot,
  assertWorkspaceRecordCapacity,
  assertLogicalBackupCapacity,
  changeVaultPassphrase,
  createEncryptedBackup,
  createManifestSentinel,
  createRevision,
  createVaultMaterial,
  decryptEncryptedBackup,
  encryptWorkspaceRecord,
  recoverVaultSnapshot,
  unlockVaultSnapshot,
} from "./crypto.js";
import {
  deleteLocalVault,
  initializeVault,
  markVaultDeleting,
  readVaultMeta,
  readOpaqueVaultSnapshot,
  readVaultSnapshot,
  removeEncryptedRecords,
  replaceVault,
  signalVaultLock,
  writeEncryptedRecords,
} from "./db.js";
import { VaultError } from "./errors.js";
import { assertResearchChanges, assertRootKindsReadOnly, assertTaskDraftChanges } from "./root-kinds.js";
import {
  VAULT_MAX_BACKUP_BYTES,
  VAULT_MAX_RESCUE_BYTES,
  type CreatedWorkspace,
  type EncryptedEnvelope,
  type OpaqueVaultRescue,
  type PublicVaultMeta,
  type UnlockedWorkspace,
  type VaultBackupFile,
} from "./types.js";

export interface AgentProfileDraft {
  displayName: string;
  walletAddress: string;
  frameworkLabel: string;
  purposeNote: string;
}

export interface MonitoringPolicyDraft {
  label: string;
  maximumAmountBaseUnits: string;
  allowedRecipient: string;
  expiresAt: string;
}

export async function bootstrapWorkspace(): Promise<PublicVaultMeta | null> {
  return readVaultMeta();
}

export async function createLocalWorkspace(
  passphrase: string,
  assertActive: () => void = () => undefined,
  signal?: AbortSignal,
): Promise<CreatedWorkspace> {
  const created = await createVaultMaterial(passphrase);
  const now = new Date().toISOString();
  const settings = WorkspaceSettingsRecordSchema.parse({
    recordSchema: "openarc.workspace-record.v1",
    recordId: crypto.randomUUID(),
    recordRevision: created.meta.revision,
    kind: "workspace_settings",
    tourSeen: false,
    defaultView: "overview",
    createdAt: now,
    updatedAt: now,
  });
  const usedIvs = new Set<string>();
  const encryptedSettings = await encryptWorkspaceRecord(created.meta, created.key, settings, usedIvs);
  const sentinel = await createManifestSentinel(
    created.meta,
    created.key,
    [encryptedSettings],
    now,
    usedIvs,
  );
  const records: WorkspaceRecord[] = [sentinel.record, settings];
  assertWorkspaceIntegrity(records);
  await initializeVault(created.meta, [sentinel.envelope, encryptedSettings], assertActive, signal);
  return { meta: created.meta, key: created.key, records, recoverySecret: created.recoverySecret };
}

export async function unlockLocalWorkspace(
  meta: PublicVaultMeta,
  passphrase: string,
): Promise<UnlockedWorkspace> {
  const snapshot = await readVaultSnapshot(meta.vaultId, meta.revision, meta.coordinationRevision);
  const unlocked = await unlockVaultSnapshot(snapshot.meta, snapshot.records, passphrase);
  assertWorkspaceIntegrity(unlocked.records);
  // Decryption is asynchronous. A peer may commit a lock, replacement, save or
  // deletion after the initial snapshot was read but before it can be revealed.
  const current = await readVaultMeta();
  if (
    !current ||
    current.vaultId !== snapshot.meta.vaultId ||
    current.revision !== snapshot.meta.revision ||
    current.coordinationRevision !== snapshot.meta.coordinationRevision ||
    current.deletionPending
  ) {
    throw new VaultError("VAULT_CONFLICT", "The workspace changed while unlocking. Unlock again to load the current revision.");
  }
  return unlocked;
}

export async function saveWorkspaceRecords(
  unlocked: UnlockedWorkspace,
  changedRecords: readonly WorkspaceRecord[],
  assertActive: () => void = () => undefined,
  signal?: AbortSignal,
): Promise<UnlockedWorkspace> {
  if (changedRecords.some((record) => record.kind === "sentinel")) {
    throw new VaultError("INVALID_BACKUP", "The workspace sentinel cannot be edited.");
  }
  const snapshot = await readVaultSnapshot(
    unlocked.meta.vaultId,
    unlocked.meta.revision,
    unlocked.meta.coordinationRevision,
  );
  const authenticated = await authenticateVaultSnapshot(snapshot.meta, snapshot.records, unlocked.key);
  assertWorkspaceIntegrity(authenticated.records);
  const meta = nextMeta(unlocked.meta);
  const versionedChanges = changedRecords.map((record) => versionRecord(record, meta.revision));
  assertAgentRecordChanges(authenticated.records, versionedChanges);
  // P08-01: ROOT's write-side rules (in ROOT's order), then this build's read-only rule for ROOT-build kinds.
  assertTaskDraftChanges(authenticated.records, versionedChanges);
  assertResearchChanges(authenticated.records, versionedChanges);
  assertRootKindsReadOnly(authenticated.records, versionedChanges);
  const changedIds = new Set(versionedChanges.map((record) => record.recordId));
  if (changedIds.size !== changedRecords.length) {
    throw new VaultError("INVALID_BACKUP", "A workspace write contains duplicate record IDs.");
  }
  const recordsWithoutSentinel = [
    ...versionedChanges,
    ...authenticated.records.filter((record) => !changedIds.has(record.recordId)),
  ].filter((record) => record.kind !== "sentinel");
  assertWorkspaceRecordCapacity(recordsWithoutSentinel);
  assertLogicalBackupCapacity(recordsWithoutSentinel);
  assertWorkspaceRelationships(recordsWithoutSentinel, false);
  const usedIvs = new Set(snapshot.records.map((record) => record.iv));
  const encrypted: Awaited<ReturnType<typeof encryptWorkspaceRecord>>[] = [];
  for (const record of versionedChanges) {
    encrypted.push(await encryptWorkspaceRecord(meta, unlocked.key, record, usedIvs));
  }
  const changedEnvelopeIds = new Set(encrypted.map((record) => record.id));
  const combinedEnvelopes = [
    ...encrypted,
    ...snapshot.records.filter(
      (record) => record.id !== unlocked.meta.sentinelRecordId && !changedEnvelopeIds.has(record.id),
    ),
  ];
  const oldSentinel = authenticated.records.find((record) => record.kind === "sentinel");
  if (!oldSentinel) invalidRelationships();
  const sentinel = await createManifestSentinel(
    meta,
    unlocked.key,
    combinedEnvelopes,
    oldSentinel.createdAt,
    usedIvs,
  );
  const records = [sentinel.record, ...recordsWithoutSentinel];
  assertWorkspaceIntegrity(records);
  await writeEncryptedRecords(
    [...encrypted, sentinel.envelope],
    meta,
    snapshot.meta,
    assertActive,
    signal,
  );
  return { meta, key: unlocked.key, records: sortRecords(records) };
}

export async function deleteWorkspaceRecords(
  unlocked: UnlockedWorkspace,
  ids: readonly string[],
  assertActive: () => void = () => undefined,
  signal?: AbortSignal,
): Promise<UnlockedWorkspace> {
  const snapshot = await readVaultSnapshot(
    unlocked.meta.vaultId,
    unlocked.meta.revision,
    unlocked.meta.coordinationRevision,
  );
  const authenticated = await authenticateVaultSnapshot(snapshot.meta, snapshot.records, unlocked.key);
  assertWorkspaceIntegrity(authenticated.records);
  const idSet = new Set(ids);
  const removed = authenticated.records.filter((record) => idSet.has(record.recordId));
  if (removed.some((record) => record.kind === "sentinel" || record.kind === "workspace_settings")) {
    throw new VaultError("INVALID_BACKUP", "Core workspace records cannot be deleted.");
  }
  const recordsWithoutSentinel = authenticated.records.filter(
    (record) => record.kind !== "sentinel" && !idSet.has(record.recordId),
  );
  assertLogicalBackupCapacity(recordsWithoutSentinel);
  const meta = nextMeta(unlocked.meta);
  const remainingEnvelopes = snapshot.records.filter(
    (record) => record.id !== unlocked.meta.sentinelRecordId && !idSet.has(record.id),
  );
  const oldSentinel = authenticated.records.find((record) => record.kind === "sentinel");
  if (!oldSentinel) invalidRelationships();
  const sentinel = await createManifestSentinel(
    meta,
    unlocked.key,
    remainingEnvelopes,
    oldSentinel.createdAt,
    new Set(snapshot.records.map((record) => record.iv)),
  );
  const records = [sentinel.record, ...recordsWithoutSentinel];
  assertWorkspaceIntegrity(records);
  await removeEncryptedRecords(
    ids,
    [sentinel.envelope],
    meta,
    snapshot.meta,
    assertActive,
    signal,
  );
  return { meta, key: unlocked.key, records: sortRecords(records) };
}

export async function updateWorkspacePassphrase(
  unlocked: UnlockedWorkspace,
  currentPassphrase: string,
  nextPassphrase: string,
  assertActive: () => void = () => undefined,
  signal?: AbortSignal,
): Promise<UnlockedWorkspace> {
  const snapshot = await readVaultSnapshot(
    unlocked.meta.vaultId,
    unlocked.meta.revision,
    unlocked.meta.coordinationRevision,
  );
  const changed = await changeVaultPassphrase(
    snapshot.meta,
    snapshot.records,
    currentPassphrase,
    nextPassphrase,
  );
  const oldSentinel = changed.records.find((record) => record.kind === "sentinel");
  if (!oldSentinel) invalidRelationships();
  const nonSentinelEnvelopes = snapshot.records.filter(
    (record) => record.id !== snapshot.meta.sentinelRecordId,
  );
  const sentinel = await createManifestSentinel(
    changed.meta,
    changed.key,
    nonSentinelEnvelopes,
    oldSentinel.createdAt,
    new Set(snapshot.records.map((record) => record.iv)),
  );
  const records = [sentinel.record, ...changed.records.filter((record) => record.kind !== "sentinel")];
  assertWorkspaceIntegrity(records);
  await writeEncryptedRecords([sentinel.envelope], changed.meta, snapshot.meta, assertActive, signal);
  return { meta: changed.meta, key: changed.key, records: sortRecords(records) };
}

export async function signalWorkspaceLock(
  meta: PublicVaultMeta,
): Promise<PublicVaultMeta> {
  return signalVaultLock(meta);
}

export async function recoverLocalWorkspace(
  meta: PublicVaultMeta,
  recoverySecret: string,
  nextPassphrase: string,
  assertActive: () => void = () => undefined,
  signal?: AbortSignal,
): Promise<CreatedWorkspace> {
  const snapshot = await readVaultSnapshot(meta.vaultId, meta.revision, meta.coordinationRevision);
  const recovered = await recoverVaultSnapshot(
    snapshot.meta,
    snapshot.records,
    recoverySecret,
    nextPassphrase,
  );
  const oldSentinel = recovered.records.find((record) => record.kind === "sentinel");
  if (!oldSentinel) invalidRelationships();
  const nonSentinelEnvelopes = snapshot.records.filter(
    (record) => record.id !== snapshot.meta.sentinelRecordId,
  );
  const sentinel = await createManifestSentinel(
    recovered.meta,
    recovered.key,
    nonSentinelEnvelopes,
    oldSentinel.createdAt,
    new Set(snapshot.records.map((record) => record.iv)),
  );
  const records = [sentinel.record, ...recovered.records.filter((record) => record.kind !== "sentinel")];
  assertWorkspaceIntegrity(records);
  await writeEncryptedRecords(
    [sentinel.envelope],
    recovered.meta,
    snapshot.meta,
    assertActive,
    signal,
  );
  return { ...recovered, records: sortRecords(records) };
}

export async function exportLocalWorkspace(
  unlocked: UnlockedWorkspace,
  backupPassphrase: string,
): Promise<VaultBackupFile> {
  const snapshot = await readVaultSnapshot(
    unlocked.meta.vaultId,
    unlocked.meta.revision,
    unlocked.meta.coordinationRevision,
  );
  return createEncryptedBackup(snapshot.meta, snapshot.records, unlocked.key, backupPassphrase);
}

export async function parseBackupFile(file: File): Promise<unknown> {
  if (file.size > VAULT_MAX_BACKUP_BYTES) {
    throw new VaultError("INVALID_BACKUP", "Encrypted workspace backups are limited to 32 MiB.");
  }
  try {
    return JSON.parse(await file.text()) as unknown;
  } catch {
    throw new VaultError("INVALID_BACKUP", "The selected file is not a valid encrypted OpenArc backup.");
  }
}

export async function exportOpaqueRescue(): Promise<OpaqueVaultRescue> {
  const snapshot = await readOpaqueVaultSnapshot();
  const rescue: OpaqueVaultRescue = {
    magic: "OPENARC-OPAQUE-RESCUE",
    version: 1,
    exportedAt: new Date().toISOString(),
    warning: "ENCRYPTED_RESCUE_NOT_IMPORTABLE_BY_THIS_BUILD",
    vaultMeta: snapshot.vaultMeta,
    records: snapshot.records,
  };
  if (new TextEncoder().encode(JSON.stringify(rescue)).byteLength > VAULT_MAX_RESCUE_BYTES) {
    throw new VaultError("VAULT_CAPACITY", "The opaque encrypted rescue exceeds the 64 MiB safety limit.");
  }
  return rescue;
}

export async function importLocalWorkspace(
  backupInput: unknown,
  backupPassphrase: string,
  newWorkspacePassphrase: string,
  expectedCurrent: PublicVaultMeta | null,
  assertActive: () => void = () => undefined,
  signal?: AbortSignal,
): Promise<CreatedWorkspace> {
  const verified = await decryptEncryptedBackup(backupInput, backupPassphrase);
  assertWorkspaceRelationships(verified.records, false);
  const created = await createVaultMaterial(newWorkspacePassphrase);
  const versionedRecords = verified.records.map((record) => versionRecord(record, created.meta.revision));
  const usedIvs = new Set<string>();
  const encrypted: EncryptedEnvelope[] = [];
  for (const record of versionedRecords) {
    encrypted.push(await encryptWorkspaceRecord(created.meta, created.key, record, usedIvs));
  }
  const sentinel = await createManifestSentinel(
    created.meta,
    created.key,
    encrypted,
    new Date().toISOString(),
    usedIvs,
  );
  const records = [sentinel.record, ...versionedRecords];
  assertWorkspaceIntegrity(records);
  const meta = await replaceVault(
    { vault: created.meta, records: [sentinel.envelope, ...encrypted] },
    expectedCurrent === null
      ? null
      : {
          vaultId: expectedCurrent.vaultId,
          revision: expectedCurrent.revision,
          coordinationRevision: expectedCurrent.coordinationRevision,
        },
    assertActive,
    signal,
  );
  return {
    meta,
    key: created.key,
    records: sortRecords(records),
    recoverySecret: created.recoverySecret,
  };
}

export async function destroyLocalWorkspace(onBlocked?: () => void): Promise<void> {
  await deleteLocalVault(onBlocked);
}

export async function prepareLocalWorkspaceDeletion(meta: PublicVaultMeta): Promise<PublicVaultMeta> {
  return markVaultDeleting(meta.vaultId);
}

export class AgentImportIdentityError extends VaultError {
  constructor(readonly reason: "DUPLICATE_IMPORT" | "IMPORT_ID_CONFLICT") {
    super("INVALID_BACKUP", reason === "DUPLICATE_IMPORT"
      ? "This report is already stored. Duplicate import identities cannot be saved again."
      : "This import identity is already stored with different content. Existing evidence was not overwritten.");
    this.name = "AgentImportIdentityError";
  }
}

/** Pure preparation for an explicit local preview/save; it never contacts a source. */
export function prepareLocalAgentImport(workspace: UnlockedWorkspace, report: unknown,
  agentProfileRecordId: string, explicitConfirmation: boolean, now = new Date().toISOString()): AgentImportRecord {
  const parsed = AgentImportSchema.safeParse(report);
  if (!parsed.success || !IsoTimestampSchema.safeParse(now).success) {
    throw new VaultError("INVALID_BACKUP", "The report is not supported normalized local metadata.");
  }
  if (explicitConfirmation !== true || !workspace.records.some((record) =>
    record.kind === "agent_profile" && record.recordId === agentProfileRecordId)) {
    throw new VaultError("INVALID_BACKUP", "Explicitly associate this report with an existing local agent profile.");
  }
  if (compareIsoTimestamps(parsed.data.capturedAt, now) > 0) {
    throw new VaultError("INVALID_BACKUP", "The report capture is in the future. Nothing was saved.");
  }
  const duplicate = workspace.records.find((record) => record.kind === "agent_import" && record.report.importId === parsed.data.importId);
  if (duplicate?.kind === "agent_import") {
    throw new AgentImportIdentityError(JSON.stringify(duplicate.report) === JSON.stringify(parsed.data) ? "DUPLICATE_IMPORT" : "IMPORT_ID_CONFLICT");
  }
  const record = AgentImportRecordSchema.parse({ recordSchema: "openarc.agent-import-record.v1", kind: "agent_import",
    recordId: crypto.randomUUID(), recordRevision: workspace.meta.revision, createdAt: now, updatedAt: now,
    report: parsed.data, linkedAgentProfileRecordId: agentProfileRecordId, linkBasis: "explicit_local_confirmation" });
  assertWorkspaceRecordCapacity([...workspace.records, record]);
  assertAgentEventCapacity([...workspace.records, record]);
  return record;
}

/** Policy identity is immutable; the helper owns revision advancement, not imported/UI input. */
export function prepareAgentMonitoringPolicyRecord(workspace: UnlockedWorkspace, policy: unknown,
  existing?: AgentMonitoringPolicyRecord, now = new Date().toISOString()): AgentMonitoringPolicyRecord {
  const parsed = AgentMonitoringPolicySchema.safeParse(policy);
  if (!parsed.success || !IsoTimestampSchema.safeParse(now).success) {
    throw new VaultError("INVALID_BACKUP", "The local monitoring policy does not match its supported contract.");
  }
  if (!workspace.records.some((record) => record.kind === "agent_profile" && record.recordId === parsed.data.agentProfileRecordId)) {
    throw new VaultError("INVALID_BACKUP", "A local monitoring policy requires an existing agent profile.");
  }
  const stored = existing ? workspace.records.find((record) => record.recordId === existing.recordId) : undefined;
  if (existing && (!stored || stored.kind !== "agent_monitoring_policy" ||
    JSON.stringify(stored) !== JSON.stringify(existing) || stored.policy.policyId !== parsed.data.policyId ||
    compareIsoTimestamps(now, stored.updatedAt) < 0)) {
    throw new VaultError("INVALID_BACKUP", "The policy identity, revision or timestamp changed. Reload before editing.");
  }
  if (!existing && workspace.records.some((record) =>
    record.kind === "agent_monitoring_policy" && record.policy.policyId === parsed.data.policyId)) {
    throw new VaultError("INVALID_BACKUP", "This policy identity is already stored. Edit the existing policy instead.");
  }
  const result = AgentMonitoringPolicyRecordSchema.parse({ recordSchema: "openarc.agent-policy-record.v2", kind: "agent_monitoring_policy",
    recordId: existing?.recordId ?? crypto.randomUUID(), recordRevision: workspace.meta.revision,
    createdAt: existing?.createdAt ?? now, updatedAt: now,
    policy: { ...parsed.data, revision: existing ? existing.policy.revision + 1 : 1 } });
  assertWorkspaceRecordCapacity([...workspace.records.filter((record) => record.recordId !== result.recordId), result]);
  return result;
}

function assertAgentEventCapacity(records: readonly WorkspaceRecord[]): void {
  const events = records.reduce((total, record) => total + (record.kind === "agent_import" ? record.report.events.length : 0), 0);
  if (events > AGENT_POLICY_MAX_EVENTS) throw new VaultError("VAULT_CAPACITY", "At most 512 imported events may be stored. No events were truncated.");
}

function assertAgentRecordChanges(previous: readonly WorkspaceRecord[], changes: readonly WorkspaceRecord[]): void {
  const byId = new Map(previous.map((record) => [record.recordId, record]));
  const imports = previous.filter((record) => record.kind === "agent_import");
  for (const changed of changes) {
    const old = byId.get(changed.recordId);
    if (changed.kind === "agent_import") {
      const duplicate = imports.find((record) => record.report.importId === changed.report.importId);
      if (duplicate) throw new AgentImportIdentityError(JSON.stringify(duplicate.report) === JSON.stringify(changed.report)
        ? "DUPLICATE_IMPORT" : "IMPORT_ID_CONFLICT");
      if (old) throw new VaultError("INVALID_BACKUP", "An import must have a new immutable local record identity.");
      if (compareIsoTimestamps(changed.report.capturedAt, new Date().toISOString()) > 0) {
        throw new VaultError("INVALID_BACKUP", "Future-captured reports cannot be saved.");
      }
    }
    if (old?.kind === "agent_import") throw new VaultError("INVALID_BACKUP", "Imported reports cannot be overwritten or reclassified.");
    if (changed.kind === "agent_monitoring_policy") {
      if (old && (old.kind !== "agent_monitoring_policy" || old.policy.policyId !== changed.policy.policyId ||
        changed.policy.revision !== old.policy.revision + 1 || changed.createdAt !== old.createdAt ||
        compareIsoTimestamps(changed.updatedAt, old.updatedAt) < 0)) {
        throw new VaultError("INVALID_BACKUP", "A policy edit must preserve its identity and creation time and increment its revision exactly once.");
      }
      if (!old && changed.policy.revision !== 1) throw new VaultError("INVALID_BACKUP", "A new local monitoring policy begins at revision one.");
    }
    if (old?.kind === "agent_monitoring_policy" && changed.kind !== "agent_monitoring_policy") {
      throw new VaultError("INVALID_BACKUP", "Local monitoring policy records cannot be reclassified.");
    }
  }
}

export function createAgentProfileRecord(
  draft: AgentProfileDraft,
  recordRevision: string,
  existing?: AgentProfileRecord,
): AgentProfileRecord {
  const now = new Date().toISOString();
  return AgentProfileRecordSchema.parse({
    recordSchema: "openarc.workspace-record.v1",
    recordId: existing?.recordId ?? crypto.randomUUID(),
    recordRevision,
    kind: "agent_profile",
    agentId: existing?.agentId ?? opaqueId("agent"),
    displayName: draft.displayName,
    wallets:
      draft.walletAddress.trim() === ""
        ? []
        : [
            {
              network: ARC_TESTNET.caip2,
              address: draft.walletAddress.trim().toLowerCase(),
              classificationSource: "owner_supplied",
            },
          ],
    frameworkLabel: emptyToNull(draft.frameworkLabel),
    purposeNote: emptyToNull(draft.purposeNote),
    policyRecordIds: existing?.policyRecordIds ?? [],
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  });
}

export function createMonitoringPolicyRecord(
  draft: MonitoringPolicyDraft,
  recordRevision: string,
  existing?: MonitoringPolicyRecord,
): MonitoringPolicyRecord {
  const now = new Date().toISOString();
  const policy = MonitoringPolicySchema.parse({
    schemaVersion: "openarc.policy.v1",
    policyId: existing?.policy.policyId ?? opaqueId("pol"),
    label: draft.label,
    mode: "local_monitoring_only",
    enabled: true,
    actionKind: "paid_api_request",
    network: ARC_TESTNET.caip2,
    asset: ARC_TESTNET.contracts.usdc.toLowerCase(),
    maximumAmountBaseUnits: draft.maximumAmountBaseUnits.trim(),
    allowedRecipients:
      draft.allowedRecipient.trim() === ""
        ? []
        : [draft.allowedRecipient.trim().toLowerCase()],
    expiresAt: emptyToNull(draft.expiresAt),
  });
  return MonitoringPolicyRecordSchema.parse({
    recordSchema: "openarc.workspace-record.v1",
    recordId: existing?.recordId ?? crypto.randomUUID(),
    recordRevision,
    kind: "monitoring_policy",
    revision: (existing?.revision ?? 0) + 1,
    policy,
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  });
}

export function createFixtureWorkspaceRecords(
  fixture: EvidenceFixture,
  recordRevision: string,
): WorkspaceRecord[] {
  const now = new Date().toISOString();
  const result = reconcileAction({
    action: fixture.action,
    evidence: fixture.evidence,
    policies: fixture.policies,
    evaluatedAt: fixture.evaluatedAt,
  });
  const policies = fixture.policies.map((policy) =>
    MonitoringPolicyRecordSchema.parse({
      recordSchema: "openarc.workspace-record.v1",
      recordId: crypto.randomUUID(),
      recordRevision,
      kind: "monitoring_policy",
      revision: 1,
      policy,
      createdAt: now,
      updatedAt: now,
    }),
  );
  const agent = AgentProfileRecordSchema.parse({
    recordSchema: "openarc.workspace-record.v1",
    recordId: crypto.randomUUID(),
    recordRevision,
    kind: "agent_profile",
    agentId: fixture.action.agentId,
    displayName: `${fixture.title} agent`,
    wallets: [],
    frameworkLabel: "Synthetic M01 fixture",
    purposeNote: "Local fixture context. This is not a discovered or verified identity.",
    policyRecordIds: policies.map((record) => record.recordId),
    createdAt: now,
    updatedAt: now,
  });
  return [
    agent,
    ...policies,
    ActionEnvelopeRecordSchema.parse({
      recordSchema: "openarc.workspace-record.v1",
      recordId: crypto.randomUUID(),
      recordRevision,
      kind: "action_envelope",
      action: {
        ...fixture.action,
        policyEvaluation: result.policyEvaluation,
        reconciliation: result,
      },
      createdAt: now,
      updatedAt: now,
    }),
    ...fixture.evidence.map((evidence) =>
      EvidenceRecordRecordSchema.parse({
        recordSchema: "openarc.workspace-record.v1",
        recordId: crypto.randomUUID(),
        recordRevision,
        kind: "evidence_record",
        evidence,
        createdAt: now,
        updatedAt: now,
      }),
    ),
  ];
}

export function markTourSeen(record: WorkspaceRecord): WorkspaceRecord {
  if (record.kind !== "workspace_settings") {
    throw new VaultError("INVALID_BACKUP", "Workspace settings are missing.");
  }
  return WorkspaceSettingsRecordSchema.parse({
    ...record,
    tourSeen: true,
    updatedAt: new Date().toISOString(),
  });
}

export function assertWorkspaceIntegrity(records: readonly WorkspaceRecord[]): void {
  assertWorkspaceRelationships(records, true);
}

function assertWorkspaceRelationships(
  records: readonly WorkspaceRecord[],
  requireSentinel: boolean,
): void {
  let parsedRecords: WorkspaceRecord[];
  try {
    parsedRecords = records.map((record) => WorkspaceRecordSchema.parse(record));
  } catch {
    invalidRelationships();
  }
  assertWorkspaceRecordCapacity(parsedRecords);
  assertAgentEventCapacity(parsedRecords);
  const recordIds = parsedRecords.map((record) => record.recordId);
  if (new Set(recordIds).size !== recordIds.length) invalidRelationships();
  const sentinels = parsedRecords.filter((record) => record.kind === "sentinel");
  const settings = parsedRecords.filter((record) => record.kind === "workspace_settings");
  if (sentinels.length !== (requireSentinel ? 1 : 0) || settings.length !== 1) {
    invalidRelationships();
  }

  const agents = parsedRecords.filter((record) => record.kind === "agent_profile");
  const policies = parsedRecords.filter((record) => record.kind === "monitoring_policy");
  const actions = parsedRecords.filter((record) => record.kind === "action_envelope");
  const evidence = parsedRecords.filter((record) => record.kind === "evidence_record");
  const permissions = parsedRecords.filter((record) => record.kind === "permission_receipt");
  const observations = parsedRecords.filter((record) => record.kind === "arc_observation");
  const registryObservations = parsedRecords.filter((record) => record.kind === "agent_registry_observation");
  const jobObservations = parsedRecords.filter((record) => record.kind === "job_observation");
  const bundles = parsedRecords.filter((record) => record.kind === "x402_bundle");
  const gatewayObservations = parsedRecords.filter((record) => record.kind === "gateway_observation");
  const agentImports = parsedRecords.filter((record) => record.kind === "agent_import");
  const agentPolicies = parsedRecords.filter((record) => record.kind === "agent_monitoring_policy");
  requireUnique(agentImports.map((record) => record.report.importId));
  requireUnique(agentPolicies.map((record) => record.policy.policyId));
  const localAgentRecordIds = new Set(agents.map((record) => record.recordId));
  // P08-01: ROOT relationship rules for task_draft / task_report / research_run, verbatim from
  // apps/web/src/vault/service.ts:698-715 of the ROOT build (sha256 379ab1d5...). Neither looser nor stricter.
  const taskDrafts = parsedRecords.filter((record) => record.kind === "task_draft");
  requireUnique(taskDrafts.map(record => record.taskId));
  if (taskDrafts.some(record => !localAgentRecordIds.has(record.agentProfileRecordId))) invalidRelationships();
  const reports = parsedRecords.filter(record => record.kind === "task_report");
  for (const run of parsedRecords.filter(record => record.kind === "research_run")) {
    const draft = taskDrafts.find(record => record.recordId === run.taskDraftRecordId);
    if (!draft || run.taskDigest !== accountReportDraftDigest(draft)) invalidRelationships();
  }
  requireUnique(reports.map(record => record.observationRecordId));
  for (const report of reports) {
    const draft = taskDrafts.find(record => record.recordId === report.taskDraftRecordId);
    const observation = observations.find(record => record.recordId === report.observationRecordId)?.observation;
    if (!draft || report.request.taskId !== draft.taskId ||
      report.request.agentProfileRecordId !== draft.agentProfileRecordId ||
      report.request.taskDigest !== accountReportDraftDigest(draft) ||
      !observation || observation.schemaVersion !== "openarc.arc-account-snapshot.v1" ||
      observation.address !== report.request.address || observation.network !== report.request.network) invalidRelationships();
  }
  if (agentImports.some((record) => !localAgentRecordIds.has(record.linkedAgentProfileRecordId)) ||
    agentPolicies.some((record) => !localAgentRecordIds.has(record.policy.agentProfileRecordId))) invalidRelationships();
  requireUnique(bundles.map((record) => record.bundle.bundleId));
  requireUnique(gatewayObservations.map((record) => record.permissionReceiptId));
  requireUnique(agents.map((record) => record.agentId));
  requireUnique(policies.map((record) => record.policy.policyId));
  requireUnique(actions.map((record) => record.action.actionId));
  requireUnique(evidence.map((record) => record.evidence.evidenceId));
  requireUnique(observations.map((record) => record.permissionReceiptId));
  requireUnique(registryObservations.map((record) => record.permissionReceiptId));
  requireUnique(jobObservations.map((record) => record.permissionReceiptId));

  const permissionById = new Map(permissions.map((record) => [record.recordId, record]));
  for (const observation of observations) {
    const permission = permissionById.get(observation.permissionReceiptId);
    if (!permission || permission.recordSchema !== "openarc.permission-receipt.v2" ||
      permission.outcome !== "completed") invalidRelationships();
    if (observation.observation.schemaVersion === "openarc.arc-account-snapshot.v1") {
      if (permission.connectorId !== "arc_account_snapshot" ||
        permission.released.address !== observation.observation.address ||
        permission.released.network !== observation.observation.network) invalidRelationships();
    } else if (permission.connectorId !== "arc_transaction_evidence" ||
      permission.released.transactionHash !== observation.observation.transaction.hash ||
      permission.released.network !== observation.observation.network) invalidRelationships();
  }

  const agentRecordIds = new Set(agents.map((record) => record.recordId));
  for (const observation of registryObservations) {
    const permission = permissionById.get(observation.permissionReceiptId);
    if (!permission || permission.recordSchema !== "openarc.permission-receipt.v3" ||
      permission.connectorId !== "arc_agent_registry_evidence" || permission.outcome !== "completed" ||
      permission.released.network !== observation.observation.network ||
      permission.released.agentId !== observation.observation.agentId ||
      (permission.released.feedbackQuery?.clientAddress ?? null) !== (observation.observation.feedback?.observer ?? null) ||
      (permission.released.feedbackQuery?.feedbackIndex ?? null) !== (observation.observation.feedback?.feedbackIndex ?? null) ||
      (permission.released.validationRequestHash ?? null) !== (observation.observation.validation?.requestHash ?? null) ||
      (observation.linkedAgentProfileRecordId !== null && !agentRecordIds.has(observation.linkedAgentProfileRecordId))) {
      invalidRelationships();
    }
  }

  const actionRecordIds = new Set(actions.map((record) => record.recordId));
  for (const observation of jobObservations) {
    const permission = permissionById.get(observation.permissionReceiptId);
    const deliverable = observation.observation.deliverable;
    if (!permission || permission.recordSchema !== "openarc.permission-receipt.v4" ||
      permission.outcome !== "completed" || permission.released.network !== observation.observation.network ||
      permission.released.jobId !== observation.observation.jobId ||
      (permission.released.submissionTransactionHash ?? null) !==
        (deliverable.availability === "submission_event" ? deliverable.transactionHash : null) ||
      (observation.linkedActionRecordId !== null && !actionRecordIds.has(observation.linkedActionRecordId))) {
      invalidRelationships();
    }
  }

  const policyRecordIds = new Set(policies.map((record) => record.recordId));
  const bundleRecordIds = new Set(bundles.map((record) => record.recordId));
  for (const observation of gatewayObservations) {
    const permission = permissionById.get(observation.permissionReceiptId);
    if (!permission || permission.recordSchema !== "openarc.permission-receipt.v5" ||
      permission.outcome !== "completed" || permission.released.network !== observation.observation.network ||
      permission.released.transferId !== observation.observation.transfer.id ||
      (observation.linkedBundleRecordId !== null && !bundleRecordIds.has(observation.linkedBundleRecordId))) {
      invalidRelationships();
    }
  }
  const policyIds = new Set(policies.map((record) => record.policy.policyId));
  const policyRecordIdByPolicyId = new Map(
    policies.map((record) => [record.policy.policyId, record.recordId]),
  );
  const agentIds = new Set(agents.map((record) => record.agentId));
  const agentById = new Map(agents.map((record) => [record.agentId, record]));
  const evidenceById = new Map(evidence.map((record) => [record.evidence.evidenceId, record.evidence]));
  const referencedEvidenceIds = new Set<string>();
  for (const agent of agents) {
    if (agent.policyRecordIds.some((recordId) => !policyRecordIds.has(recordId))) invalidRelationships();
  }
  for (const actionRecord of actions) {
    const action = actionRecord.action;
    if (!agentIds.has(action.agentId)) invalidRelationships();
    const relationships = [
      [action.intentEvidenceIds, new Set(["intent"])],
      [action.attemptEvidenceIds, new Set(["attempt"])],
      [action.paymentEvidenceIds, new Set(["payment_requirement", "authorization"])],
      [action.fulfillmentEvidenceIds, new Set(["fulfillment"])],
      [action.settlementEvidenceIds, new Set(["settlement", "refund"])],
    ] as const;
    const ids = relationships.flatMap(([relationshipIds]) => relationshipIds);
    ids.forEach((id) => referencedEvidenceIds.add(id));
    if (ids.some((id) => evidenceById.get(id)?.actionId !== action.actionId)) invalidRelationships();
    for (const [relationshipIds, allowedTypes] of relationships) {
      if (relationshipIds.some((id) => !allowedTypes.has(evidenceById.get(id)?.evidenceType ?? ""))) {
        invalidRelationships();
      }
    }
    const relationshipIdSet = new Set(ids);
    if (
      action.states.some((transition) =>
        transition.evidenceIds.some((id) => !relationshipIdSet.has(id) || !evidenceById.has(id)),
      )
    ) {
      invalidRelationships();
    }
    for (const evaluation of [action.policyEvaluation, action.reconciliation?.policyEvaluation]) {
      if (
        evaluation?.matchedPolicyIds.some((policyId) => {
          const recordId = policyRecordIdByPolicyId.get(policyId);
          return (
            !policyIds.has(policyId) ||
            !recordId ||
            !agentById.get(action.agentId)?.policyRecordIds.includes(recordId)
          );
        })
      ) {
        invalidRelationships();
      }
    }
    if (action.reconciliation) {
      const resultEvidenceIds = new Set(action.reconciliation.evidenceIds);
      if ([...resultEvidenceIds].some((id) => !relationshipIdSet.has(id))) invalidRelationships();
      if (
        action.reconciliation.conflicts.some((conflict) =>
          conflict.evidenceIds.some((id) => !resultEvidenceIds.has(id)),
        )
      ) {
        invalidRelationships();
      }
    }
    if (!action.reconciliation || !action.policyEvaluation) invalidRelationships();
    try {
      const linkedPolicyRecordIds = new Set(
        agentById.get(action.agentId)?.policyRecordIds ?? [],
      );
      const recomputed = reconcileAction({
        action: { ...action, reconciliation: null, policyEvaluation: null },
        evidence: ids.map((id) => evidenceById.get(id)),
        policies: policies
          .filter((record) => linkedPolicyRecordIds.has(record.recordId))
          .map((record) => record.policy),
        evaluatedAt: action.reconciliation.evaluatedAt,
      });
      if (
        JSON.stringify(recomputed) !== JSON.stringify(action.reconciliation) ||
        JSON.stringify(recomputed.policyEvaluation) !== JSON.stringify(action.policyEvaluation)
      ) {
        invalidRelationships();
      }
    } catch {
      invalidRelationships();
    }
  }
  const actionIds = new Set(actions.map((record) => record.action.actionId));
  if (evidence.some((record) => !actionIds.has(record.evidence.actionId))) invalidRelationships();
  if (evidence.some((record) => !referencedEvidenceIds.has(record.evidence.evidenceId))) {
    invalidRelationships();
  }
}

function sortRecords(records: readonly WorkspaceRecord[]): WorkspaceRecord[] {
  return [...records].sort((left, right) => left.recordId.localeCompare(right.recordId));
}

function nextMeta(meta: PublicVaultMeta): PublicVaultMeta {
  return { ...meta, revision: createRevision() };
}

function versionRecord(record: WorkspaceRecord, revision: string): WorkspaceRecord {
  try {
    return WorkspaceRecordSchema.parse({ ...record, recordRevision: revision });
  } catch {
    invalidRelationships();
  }
}

function opaqueId(prefix: "agent" | "pol"): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return `${prefix}_${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function emptyToNull(value: string): string | null {
  const normalized = value.trim();
  return normalized === "" ? null : normalized;
}

function requireUnique(values: readonly string[]): void {
  if (new Set(values).size !== values.length) invalidRelationships();
}

function invalidRelationships(): never {
  throw new VaultError("INVALID_BACKUP", "Encrypted workspace records have invalid relationships.");
}
