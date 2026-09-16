import { z } from "zod";

import {
  ActionEnvelopeSchema,
  EvidenceRecordSchema,
  MonitoringPolicySchema,
} from "./evidence.js";
import { ARC_TESTNET } from "./network.js";
import { ArcAccountSnapshotSchema, ArcTransactionEvidenceSchema } from "./arc-observation.js";
import { StoredAgentRegistryEvidenceSchema } from "./agent-registry-evidence.js";
import { JobEvidenceSchema } from "./job-evidence.js";
import { X402ReceiptBundleSchema, GatewayTransferObservationSchema } from "./x402-evidence.js";
import { AgentImportSchema } from "./agent-import.js";
import { AgentMonitoringPolicySchema } from "./agent-policy.js";
import { PermissionReceiptRecordSchema } from "./permission.js";
import { ResearchRunRecordSchema, TaskDraftRecordSchema, TaskReportRecordSchema } from "./vault-root-kinds.js";
import { VaultRevisionSchema, WorkspaceRecordIdSchema } from "./workspace-primitives.js";
// P08-01: stored contracts of the ROOT-build kinds (read-only in this build). The SHA-256 helper stays module-private.
export {
  AccountReportTaskRequestSchema,
  ResearchInputSchema,
  ResearchResultSchema,
  ResearchRunRecordSchema,
  TaskDraftRecordSchema,
  TaskReportRecordSchema,
  WebResearchResultSchema,
  accountReportDraftDigest,
  accountReportRequestDigest,
  type AccountReportTaskRequest,
  type ResearchInput,
  type ResearchResult,
  type ResearchRunRecord,
  type TaskDraftRecord,
  type TaskReportRecord,
} from "./vault-root-kinds.js";
export { VaultRevisionSchema, WorkspaceRecordIdSchema } from "./workspace-primitives.js";
import {
  EvmAddressSchema,
  IsoTimestampSchema,
  Sha256DigestSchema,
  compareIsoTimestamps,
} from "./primitives.js";

const boundedText = (maximum: number) => z.string().trim().min(1).max(maximum);
const nullableText = (maximum: number) => z.string().trim().max(maximum).nullable();
const uniqueArray = <T extends z.ZodType>(item: T, maximum: number) =>
  z.array(item).max(maximum).refine((items) => new Set(items).size === items.length, {
    message: "Expected unique values",
  });

export const AgentIdSchema = z.string().regex(/^agent_[0-9a-f]{32}$/u);
export const WorkspaceRecordSchemaVersion = "openarc.workspace-record.v1" as const;

const recordBase = {
  recordSchema: z.literal(WorkspaceRecordSchemaVersion),
  recordId: WorkspaceRecordIdSchema,
  recordRevision: VaultRevisionSchema,
  createdAt: IsoTimestampSchema,
  updatedAt: IsoTimestampSchema,
};

export const AgentProfileRecordSchema = z.strictObject({
  ...recordBase,
  kind: z.literal("agent_profile"),
  agentId: AgentIdSchema,
  displayName: boundedText(80),
  wallets: z
    .array(
      z.strictObject({
        network: z.literal(ARC_TESTNET.caip2),
        address: EvmAddressSchema,
        classificationSource: z.literal("owner_supplied"),
      }),
    )
    .max(8),
  frameworkLabel: nullableText(80),
  purposeNote: nullableText(500),
  policyRecordIds: uniqueArray(WorkspaceRecordIdSchema, 32),
});

export const MonitoringPolicyRecordSchema = z.strictObject({
  ...recordBase,
  kind: z.literal("monitoring_policy"),
  revision: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  policy: MonitoringPolicySchema,
});

export const EvidenceRecordRecordSchema = z.strictObject({
  ...recordBase,
  kind: z.literal("evidence_record"),
  evidence: EvidenceRecordSchema,
});

export const ActionEnvelopeRecordSchema = z.strictObject({
  ...recordBase,
  kind: z.literal("action_envelope"),
  action: ActionEnvelopeSchema,
});

export const WorkspaceSettingsRecordSchema = z.strictObject({
  ...recordBase,
  kind: z.literal("workspace_settings"),
  tourSeen: z.boolean(),
  defaultView: z.enum(["overview", "agents", "policies", "evidence", "settings"]),
});

export const ArcObservationRecordSchema = z.strictObject({
  ...recordBase,
  recordSchema: z.literal("openarc.arc-observation-record.v1"),
  kind: z.literal("arc_observation"),
  permissionReceiptId: WorkspaceRecordIdSchema,
  observation: z.union([ArcAccountSnapshotSchema, ArcTransactionEvidenceSchema]),
});

export const AgentRegistryObservationRecordSchema = z.strictObject({
  ...recordBase,
  recordSchema: z.literal("openarc.agent-registry-observation-record.v1"),
  kind: z.literal("agent_registry_observation"),
  permissionReceiptId: WorkspaceRecordIdSchema,
  linkedAgentProfileRecordId: WorkspaceRecordIdSchema.nullable(),
  // New observations are v2; original M05 v1 records stay readable as unattributed legacy data.
  observation: StoredAgentRegistryEvidenceSchema,
});

export const JobObservationRecordSchema = z.strictObject({
  ...recordBase,
  recordSchema: z.literal("openarc.job-observation-record.v1"),
  kind: z.literal("job_observation"),
  permissionReceiptId: WorkspaceRecordIdSchema,
  // This relationship is an explicit local user claim, never an onchain inference.
  linkedActionRecordId: WorkspaceRecordIdSchema.nullable(),
  linkBasis: z.literal("explicit_local_confirmation").nullable(),
  observation: JobEvidenceSchema,
}).superRefine((record, context) => {
  if ((record.linkedActionRecordId === null) !== (record.linkBasis === null)) {
    context.addIssue({ code: "custom", message: "A local action link requires explicit confirmation" });
  }
});

export const X402BundleRecordSchema = z.strictObject({
  ...recordBase,
  recordSchema: z.literal("openarc.x402-bundle-record.v1"),
  kind: z.literal("x402_bundle"),
  bundle: X402ReceiptBundleSchema,
});

export const GatewayObservationRecordSchema = z.strictObject({
  ...recordBase,
  recordSchema: z.literal("openarc.gateway-observation-record.v1"),
  kind: z.literal("gateway_observation"),
  permissionReceiptId: WorkspaceRecordIdSchema,
  linkedBundleRecordId: WorkspaceRecordIdSchema.nullable(),
  linkBasis: z.literal("explicit_local_confirmation").nullable(),
  observation: GatewayTransferObservationSchema,
}).superRefine((record, context) => {
  if ((record.linkedBundleRecordId === null) !== (record.linkBasis === null)) {
    context.addIssue({ code: "custom", message: "A bundle association requires explicit local confirmation" });
  }
});

export const AgentImportRecordSchema = z.strictObject({
  ...recordBase,
  recordSchema: z.literal("openarc.agent-import-record.v1"),
  kind: z.literal("agent_import"),
  report: AgentImportSchema,
  linkedAgentProfileRecordId: WorkspaceRecordIdSchema,
  linkBasis: z.literal("explicit_local_confirmation"),
}).superRefine((record, context) => {
  if (IsoTimestampSchema.safeParse(record.createdAt).success && IsoTimestampSchema.safeParse(record.report.capturedAt).success &&
    compareIsoTimestamps(record.report.capturedAt, record.createdAt) > 0) {
    context.addIssue({ code: "custom", path: ["report", "capturedAt"], message: "An import capture cannot follow local record creation" });
  }
});

export const AgentMonitoringPolicyRecordSchema = z.strictObject({
  ...recordBase,
  recordSchema: z.literal("openarc.agent-policy-record.v2"),
  kind: z.literal("agent_monitoring_policy"),
  policy: AgentMonitoringPolicySchema,
});

export const SentinelRecordSchema = z.strictObject({
  ...recordBase,
  kind: z.literal("sentinel"),
  marker: z.literal("OPENARC_VAULT_SENTINEL_V1"),
  vaultRevision: VaultRevisionSchema,
  manifest: z
    .array(
      z.strictObject({
        recordId: WorkspaceRecordIdSchema,
        revision: VaultRevisionSchema,
        digest: Sha256DigestSchema,
      }),
    )
    .max(6_601)
    .refine(
      (entries) =>
        entries.every((entry, index) => index === 0 || entries[index - 1]!.recordId < entry.recordId),
      { message: "Manifest entries must use unique canonical record-ID order" },
    ),
});

const WorkspaceRecordVariantSchema = z.union([
  AgentProfileRecordSchema,
  MonitoringPolicyRecordSchema,
  EvidenceRecordRecordSchema,
  ActionEnvelopeRecordSchema,
  WorkspaceSettingsRecordSchema,
  SentinelRecordSchema,
  PermissionReceiptRecordSchema,
  ArcObservationRecordSchema,
  AgentRegistryObservationRecordSchema,
  JobObservationRecordSchema,
  X402BundleRecordSchema,
  GatewayObservationRecordSchema,
  AgentImportRecordSchema,
  AgentMonitoringPolicyRecordSchema,
  // P08-01 additive members, in ROOT's union order. Existing members above are unchanged.
  TaskDraftRecordSchema,
  TaskReportRecordSchema,
  ResearchRunRecordSchema,
]);

/**
 * Every `kind|recordSchema` pair this build's union knows. A decrypted, authenticated record whose pair is NOT listed
 * was written by a newer or different build; one whose pair is listed but fails its schema carries content this
 * build's rules do not accept. Neither is a wrong passphrase. Kept in lock-step with the union by
 * test/vault-root-kinds.test.ts.
 */
export const WORKSPACE_RECORD_IDENTITIES = Object.freeze([
  "action_envelope|openarc.workspace-record.v1",
  "agent_import|openarc.agent-import-record.v1",
  "agent_monitoring_policy|openarc.agent-policy-record.v2",
  "agent_profile|openarc.workspace-record.v1",
  "agent_registry_observation|openarc.agent-registry-observation-record.v1",
  "arc_observation|openarc.arc-observation-record.v1",
  "evidence_record|openarc.workspace-record.v1",
  "gateway_observation|openarc.gateway-observation-record.v1",
  "job_observation|openarc.job-observation-record.v1",
  "monitoring_policy|openarc.workspace-record.v1",
  "permission_receipt|openarc.permission-receipt.v1",
  "permission_receipt|openarc.permission-receipt.v2",
  "permission_receipt|openarc.permission-receipt.v3",
  "permission_receipt|openarc.permission-receipt.v4",
  "permission_receipt|openarc.permission-receipt.v5",
  "permission_receipt|openarc.permission-receipt.v6",
  "research_run|openarc.research-run.v1",
  "sentinel|openarc.workspace-record.v1",
  "task_draft|openarc.task-draft-record.v1",
  "task_report|openarc.task-report-record.v1",
  "workspace_settings|openarc.workspace-record.v1",
  "x402_bundle|openarc.x402-bundle-record.v1",
] as const);
const knownRecordIdentities = new Set<string>(WORKSPACE_RECORD_IDENTITIES);

export type WorkspaceRecordIdentityClass = "known" | "unknown" | "malformed";

/** Classifies only the identity pair of an untrusted value. It never inspects or returns any other field. */
export function classifyWorkspaceRecordIdentity(value: unknown): WorkspaceRecordIdentityClass {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return "malformed";
  const { kind, recordSchema } = value as { kind?: unknown; recordSchema?: unknown };
  if (typeof kind !== "string" || typeof recordSchema !== "string") return "malformed";
  return knownRecordIdentities.has(`${kind}|${recordSchema}`) ? "known" : "unknown";
}

export const WorkspaceRecordSchema = WorkspaceRecordVariantSchema.superRefine((record, context) => {
  if (!IsoTimestampSchema.safeParse(record.updatedAt).success || !IsoTimestampSchema.safeParse(record.createdAt).success) return;
  if (compareIsoTimestamps(record.updatedAt, record.createdAt) < 0) {
    context.addIssue({
      code: "custom",
      message: "Record update time cannot predate record creation",
      path: ["updatedAt"],
    });
  }
});

export type ActionEnvelopeRecord = z.infer<typeof ActionEnvelopeRecordSchema>;
export type AgentProfileRecord = z.infer<typeof AgentProfileRecordSchema>;
export type EvidenceRecordRecord = z.infer<typeof EvidenceRecordRecordSchema>;
export type MonitoringPolicyRecord = z.infer<typeof MonitoringPolicyRecordSchema>;
export type SentinelRecord = z.infer<typeof SentinelRecordSchema>;
export type WorkspaceRecord = z.infer<typeof WorkspaceRecordSchema>;
export type WorkspaceSettingsRecord = z.infer<typeof WorkspaceSettingsRecordSchema>;
export type ArcObservationRecord = z.infer<typeof ArcObservationRecordSchema>;
export type AgentRegistryObservationRecord = z.infer<typeof AgentRegistryObservationRecordSchema>;
export type JobObservationRecord = z.infer<typeof JobObservationRecordSchema>;
export type X402BundleRecord = z.infer<typeof X402BundleRecordSchema>;
export type GatewayObservationRecord = z.infer<typeof GatewayObservationRecordSchema>;
export type AgentImportRecord = z.infer<typeof AgentImportRecordSchema>;
export type AgentMonitoringPolicyRecord = z.infer<typeof AgentMonitoringPolicyRecordSchema>;
