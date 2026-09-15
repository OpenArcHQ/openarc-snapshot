// P08-00 Vault compatibility freeze for the shared record parser. The plaintext records below were frozen from an
// encrypted Vault written by integration build 0f5caa9 (apps/web/test/fixtures/vault-compat). Every literal checked
// here is stored inside existing encrypted Vaults and backups: see
// PORT-08 Vault compatibility rules §1.9 and §1.11 item 9.
import { readFile } from "node:fs/promises";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  AGENT_REGISTRY_DISCLOSURE,
  ARC_OBSERVATION_DISCLOSURE,
  CAPABILITY_DISCLOSURE,
  GATEWAY_DISCLOSURE,
  JOB_DISCLOSURE,
} from "../src/permission.js";
import { SentinelRecordSchema, WorkspaceRecordSchema, WorkspaceRecordSchemaVersion } from "../src/vault.js";

const rule = (identifier: string) =>
  `COMPAT RULE PORT-08 Vault compatibility rules §1.11 item 9: ${identifier} is stored inside existing encrypted ` +
  "Vaults and backups. Changing it makes WorkspaceRecordSchema reject them, which fails the whole unlock and import. " +
  "Keep it byte-for-byte; add a new additive union member instead (P08-01)";

type JsonRecord = Record<string, unknown> & { kind: string; recordSchema: string; recordId: string };
const records = JSON.parse(await readFile(path.resolve(import.meta.dirname,
  "../../../apps/web/test/fixtures/vault-compat/vault-snapshot.v1.expected-records.json"), "utf8")) as JsonRecord[];

const RECORD_SCHEMAS = [
  "openarc.workspace-record.v1", "openarc.permission-receipt.v1", "openarc.permission-receipt.v2",
  "openarc.permission-receipt.v3", "openarc.permission-receipt.v4", "openarc.permission-receipt.v5",
  "openarc.arc-observation-record.v1", "openarc.agent-registry-observation-record.v1", "openarc.job-observation-record.v1",
  "openarc.x402-bundle-record.v1", "openarc.gateway-observation-record.v1", "openarc.agent-import-record.v1",
  "openarc.agent-policy-record.v2",
];

const ARC_RETENTION = "No request or response body is retained by the OpenArc API. The approved result is stored only in the encrypted local workspace.";
const ARC_HOSTING = "OpenArc, its hosting provider, and the Arc RPC receive ordinary network metadata, including IP and user-agent where applicable.";
const ARC_RPC = "https://rpc.testnet.arc.io";
const RECEIPTS: Record<string, Record<string, unknown>> = {
  "openarc.permission-receipt.v1|openarc_capabilities": {
    destination: { path: "/v1/private/capabilities", method: "GET", upstreams: [] }, releasedFields: [],
    purpose: "Inspect enabled OpenArc connections and limits.", credentials: "omit",
    openArcRetention: "No private workspace fields or response bodies are retained by the OpenArc API.",
    providerRetention: "No upstream provider is contacted by this check.",
    hostingMetadata: "OpenArc and its hosting provider receive ordinary network metadata, including IP and user-agent." },
  "openarc.permission-receipt.v2|arc_account_snapshot": {
    destination: { path: "/v1/private/arc/account-snapshot", method: "POST", upstreams: [ARC_RPC] }, releasedFields: ["network", "address"],
    purpose: "Observe one public Arc Testnet address at one exact final block.", credentials: "omit", openArcRetention: ARC_RETENTION,
    providerRetention: "Arc's public RPC receives the released public identifier under Arc's current terms and privacy policy.",
    hostingMetadata: ARC_HOSTING },
  "openarc.permission-receipt.v2|arc_transaction_evidence": {
    destination: { path: "/v1/private/arc/transaction-evidence", method: "POST", upstreams: [ARC_RPC] },
    releasedFields: ["network", "transactionHash"],
    purpose: "Observe one public Arc Testnet transaction, receipt, anchor, fee, and USDC movement set.", credentials: "omit",
    openArcRetention: ARC_RETENTION,
    providerRetention: "Arc's public RPC receives the released public identifier under Arc's current terms and privacy policy.",
    hostingMetadata: ARC_HOSTING },
  "openarc.permission-receipt.v3|arc_agent_registry_evidence": {
    destination: { path: "/v1/private/arc/agent-registry-evidence", method: "POST", upstreams: [ARC_RPC] },
    releasedFields: ["network", "agentId"],
    purpose: "Observe one ERC-8004 agent identity and optional exact observer or validator claims at one final Arc Testnet block.",
    credentials: "omit", openArcRetention: ARC_RETENTION,
    providerRetention: "Arc's public RPC receives the released public registry identifiers under Arc's current terms and privacy policy.",
    hostingMetadata: ARC_HOSTING },
  "openarc.permission-receipt.v4|arc_job_evidence": {
    destination: { path: "/v1/private/arc/job-evidence", method: "POST", upstreams: [ARC_RPC] }, releasedFields: ["network", "jobId"],
    purpose: "Observe one job on the reviewed Arc Testnet reference contract and an optional exact submission receipt.",
    credentials: "omit", openArcRetention: ARC_RETENTION,
    providerRetention: "Arc's public RPC receives the job ID and optional submission transaction hash under Arc's current terms and privacy policy.",
    hostingMetadata: ARC_HOSTING },
  "openarc.permission-receipt.v5|circle_gateway_transfer": {
    destination: { path: "/v1/private/gateway/transfer", method: "POST", upstreams: ["https://gateway-api-testnet.circle.com"] },
    releasedFields: ["network", "transferId"],
    purpose: "Read one exact Circle Gateway Arc Testnet transfer; this does not verify fulfillment.", credentials: "omit",
    openArcRetention: ARC_RETENTION,
    providerRetention: "Circle Gateway receives the exact transfer UUID under Circle's current terms and privacy policy. Provider retention is not controlled by OpenArc.",
    hostingMetadata: "OpenArc, its hosting provider, and Circle Gateway receive ordinary network metadata, including IP and user-agent where applicable." },
};
const DISCLOSURE_FIELDS = ["purpose", "credentials", "openArcRetention", "providerRetention", "hostingMetadata"] as const;

const EMBEDDED_LITERALS = [
  "adapterVersion=openarc.agent-registry-evidence.m05.v1", "adapterVersion=openarc.arc-observation.m04.v1",
  "adapterVersion=openarc.gateway-transfer.m07.v1", "adapterVersion=openarc.job-evidence.m06.v1",
  "ruleVersion=openarc.reconcile.v1", "schemaVersion=openarc.action.v1", "schemaVersion=openarc.agent-import.v1",
  "schemaVersion=openarc.agent-policy.v2", "schemaVersion=openarc.agent-registry-evidence.v1",
  "schemaVersion=openarc.arc-account-snapshot.v1", "schemaVersion=openarc.arc-transaction-evidence.v1",
  "schemaVersion=openarc.evidence.v1", "schemaVersion=openarc.gateway-transfer-observation.v1",
  "schemaVersion=openarc.job-evidence.v1", "schemaVersion=openarc.policy.v1", "schemaVersion=openarc.reconciliation.v1",
  "schemaVersion=openarc.x402-receipt-bundle.v1",
];

function literalPaths(value: unknown, trail: (string | number)[] = []): { path: (string | number)[]; entry: string }[] {
  if (Array.isArray(value)) return value.flatMap((item, index) => literalPaths(item, [...trail, index]));
  if (!value || typeof value !== "object") return [];
  return Object.entries(value).flatMap(([key, child]) => [
    ...(["schemaVersion", "ruleVersion", "adapterVersion"].includes(key) && typeof child === "string" && child.startsWith("openarc.")
      ? [{ path: [...trail, key], entry: `${key}=${child}` }] : []),
    ...literalPaths(child, [...trail, key]),
  ]);
}

function withValueAt(record: JsonRecord, at: (string | number)[], next: unknown): unknown {
  const copy = structuredClone(record) as Record<string | number, unknown>;
  let cursor = copy;
  for (const segment of at.slice(0, -1)) cursor = cursor[segment] as Record<string | number, unknown>;
  cursor[at.at(-1)!] = next;
  return copy;
}

describe("P08-00 frozen shared Vault record literals", () => {
  it("parses every frozen plaintext record unchanged", () => {
    expect(records).toHaveLength(28);
    for (const record of records) {
      const parsed = WorkspaceRecordSchema.safeParse(record);
      expect(parsed.success, rule(`${record.kind} ${record.recordId}`)).toBe(true);
      expect(parsed.data, rule(`${record.kind} ${record.recordId} (no transform)`)).toEqual(record);
    }
  });

  it("freezes every recordSchema literal and rejects any substitution", () => {
    expect(WorkspaceRecordSchemaVersion, rule("openarc.workspace-record.v1")).toBe("openarc.workspace-record.v1");
    expect([...new Set(records.map((record) => record.recordSchema))].sort(), rule("the recordSchema literal set")).toEqual([...RECORD_SCHEMAS].sort());
    for (const record of records) {
      for (const replacement of [...RECORD_SCHEMAS.filter((literal) => literal !== record.recordSchema),
        `${record.recordSchema}x`, record.recordSchema.replace(/\.v(\d+)$/u, ".v9")]) {
        expect(WorkspaceRecordSchema.safeParse({ ...record, recordSchema: replacement }).success,
          rule(`${record.kind} recordSchema ${record.recordSchema} (tried ${replacement})`)).toBe(false);
      }
    }
  });

  it("rejects an unknown kind as a whole-record failure (the closed union)", () => {
    const settings = records.find((record) => record.kind === "workspace_settings")!;
    for (const kind of ["task_draft", "task_report", "research_run", "private_note"]) {
      expect(WorkspaceRecordSchema.safeParse({ ...settings, kind }).success, rule(`closed kind union (${kind})`)).toBe(false);
    }
  });

  it("freezes permission receipt disclosure text, destinations and released field tuples for v1-v5", () => {
    expect(CAPABILITY_DISCLOSURE, rule("CAPABILITY_DISCLOSURE")).toEqual({ connectorId: "openarc_capabilities",
      ...Object.fromEntries(DISCLOSURE_FIELDS.filter((field) => field !== "purpose")
        .map((field) => [field, RECEIPTS["openarc.permission-receipt.v1|openarc_capabilities"]![field]])),
      purpose: "Inspect enabled OpenArc connections and limits." });
    expect(ARC_OBSERVATION_DISCLOSURE, rule("ARC_OBSERVATION_DISCLOSURE")).toEqual({ credentials: "omit", openArcRetention: ARC_RETENTION,
      providerRetention: RECEIPTS["openarc.permission-receipt.v2|arc_account_snapshot"]!.providerRetention, hostingMetadata: ARC_HOSTING });
    expect(AGENT_REGISTRY_DISCLOSURE, rule("AGENT_REGISTRY_DISCLOSURE")).toEqual({ credentials: "omit", openArcRetention: ARC_RETENTION,
      providerRetention: RECEIPTS["openarc.permission-receipt.v3|arc_agent_registry_evidence"]!.providerRetention, hostingMetadata: ARC_HOSTING });
    expect(JOB_DISCLOSURE, rule("JOB_DISCLOSURE")).toEqual({ credentials: "omit", openArcRetention: ARC_RETENTION,
      providerRetention: RECEIPTS["openarc.permission-receipt.v4|arc_job_evidence"]!.providerRetention, hostingMetadata: ARC_HOSTING });
    const gateway = RECEIPTS["openarc.permission-receipt.v5|circle_gateway_transfer"]!;
    expect(GATEWAY_DISCLOSURE, rule("GATEWAY_DISCLOSURE")).toEqual({ credentials: "omit", openArcRetention: ARC_RETENTION,
      providerRetention: gateway.providerRetention, hostingMetadata: gateway.hostingMetadata });

    const receipts = records.filter((record) => record.kind === "permission_receipt");
    expect([...new Set(receipts.map((receipt) => `${receipt.recordSchema}|${String(receipt.connectorId)}`))].sort(),
      rule("receipt version/connector pairs")).toEqual(Object.keys(RECEIPTS).sort());
    for (const receipt of receipts) {
      const key = `${receipt.recordSchema}|${String(receipt.connectorId)}`;
      const frozen = RECEIPTS[key]!;
      const destination = receipt.destination as Record<string, unknown>;
      expect({ path: destination.path, method: destination.method, upstreams: destination.upstreams }, rule(`${key} destination`))
        .toEqual(frozen.destination);
      expect(receipt.releasedFields, rule(`${key} releasedFields`)).toEqual(frozen.releasedFields);
      for (const field of DISCLOSURE_FIELDS) {
        expect(receipt[field], rule(`${key} ${field} text`)).toBe(frozen[field]);
        expect(WorkspaceRecordSchema.safeParse({ ...receipt, [field]: `${String(receipt[field])} ` }).success,
          rule(`${key} ${field} literal (one appended character)`)).toBe(false);
      }
      for (const [name, changed] of [["path", `${String(destination.path)}/v2`], ["method", "PUT"], ["upstreams", ["https://example.test"]]] as const) {
        expect(WorkspaceRecordSchema.safeParse({ ...receipt, destination: { ...destination, [name]: changed } }).success,
          rule(`${key} destination.${name}`)).toBe(false);
      }
    }
  });

  it("freezes every embedded payload schema, rule and adapter literal", () => {
    const found = records.flatMap((record) => literalPaths(record).map(({ entry }) => entry));
    expect([...new Set(found)].sort(), rule("embedded payload literal set")).toEqual([...EMBEDDED_LITERALS].sort());
    for (const record of records) {
      for (const { path: at, entry } of literalPaths(record)) {
        const [, literal] = entry.split("=");
        expect(WorkspaceRecordSchema.safeParse(withValueAt(record, at, `${literal!}x`)).success,
          rule(`${record.kind} ${at.join(".")} ${literal!}`)).toBe(false);
      }
    }
  });

  it("freezes the sentinel marker and the 6,601-entry manifest maximum", () => {
    const sentinel = records.find((record) => record.kind === "sentinel")!;
    expect(sentinel.marker, rule("OPENARC_VAULT_SENTINEL_V1")).toBe("OPENARC_VAULT_SENTINEL_V1");
    expect(SentinelRecordSchema.safeParse({ ...sentinel, marker: "OPENARC_VAULT_SENTINEL_V2" }).success, rule("sentinel marker")).toBe(false);
    const manifest = (count: number) => Array.from({ length: count }, (_, index) => ({
      recordId: `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`, revision: "A".repeat(32),
      digest: `sha256:${"0".repeat(64)}` }));
    expect(SentinelRecordSchema.safeParse({ ...sentinel, manifest: manifest(6_601) }).success, rule("manifest maximum 6601")).toBe(true);
    expect(SentinelRecordSchema.safeParse({ ...sentinel, manifest: manifest(6_602) }).success, rule("manifest maximum 6601")).toBe(false);
  });
});
