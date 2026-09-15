// PORT-08 compatibility rule (packet P08-01, §1.11 item 9): the ROOT build's Vault record kinds are additive union
// members whose stored contracts, digests and literals match the ROOT build exactly: neither looser (a Vault the ROOT
// build rejects must not open here) nor stricter (a Vault the ROOT build wrote must open here).
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";

import { sha256 as viemSha256, stringToHex } from "viem";
import { describe, expect, it } from "vitest";

import { loadRootBuild } from "../../../apps/web/test/vault-compat/root-build-source.js";
import { buildRootKindRecords } from "../../../apps/web/test/vault-compat/root-kind-records.js";
import { WORKSPACE_RECORD_IDENTITIES, WorkspaceRecordSchema, classifyWorkspaceRecordIdentity } from "../src/vault.js";
import { accountReportDraftDigest, accountReportRequestDigest, sha256HexUtf8 } from "../src/vault-root-kinds.js";

const rule = (identifier: string) =>
  `PORT-08 compatibility rule (P08-01, §1.11 item 9): ${identifier} must match the ROOT build's stored contract exactly`;

type Plain = Record<string, unknown> & { recordId: string; kind: string };
type FrozenRecord = Plain & { observation?: { schemaVersion: string; network: string; address: string }; wallets?: unknown[] };

const frozen = JSON.parse(await readFile(path.resolve(import.meta.dirname,
  "../../../apps/web/test/fixtures/vault-compat/vault-snapshot.v1.expected-records.json"), "utf8")) as FrozenRecord[];
const account = frozen.find((record) => record.kind === "arc_observation" &&
  record.observation?.schemaVersion === "openarc.arc-account-snapshot.v1")!;
const agent = frozen.find((record) => record.kind === "agent_profile" && (record.wallets?.length ?? 0) > 0)!;
const revision = frozen[0]!.recordRevision as string;
const built = buildRootKindRecords({ recordRevision: revision, agentProfileRecordId: agent.recordId,
  accountObservationRecordId: account.recordId, accountSnapshot: account.observation! });
const draft = built.task_draft as Plain;
const report = built.task_report as Plain;
const run = built.research_run as Plain;
const request = report.request as Record<string, unknown>;
const snapshot = run.result as Record<string, unknown>;

/** The ROOT build's exact digest expression, executed with viem as the ROOT build does. */
const viemRootDigest = (value: unknown) => `sha256:${viemSha256(stringToHex(JSON.stringify(value))).slice(2)}`;
const nodeHex = (value: string) => createHash("sha256").update(value, "utf8").digest("hex");

const later = "2026-09-14T13:05:00Z";
const earlier = "2026-09-14T12:00:00Z";
const webQuery = "TEST-ONLY public research query";
const webResult = { schemaVersion: "openarc.web-research.v1", provider: "tavily", query: webQuery, observedAt: later, credits: 1,
  payment: "free_provider_credit", results: [{ title: "Source", url: "https://example.com/a", excerpt: "untrusted excerpt" }] };
const webRun: Plain = { ...run, input: { operation: "web_research", query: webQuery }, result: webResult };
const cancelled: Plain = { ...draft, state: "cancelled", updatedAt: later, cancelledAt: later };
const withRequest = (patch: Record<string, unknown>): Plain => {
  const nextRequest = { ...request, ...patch };
  return { ...report, request: nextRequest, requestDigest: viemRootDigest([nextRequest.schemaVersion, nextRequest.taskId,
    nextRequest.agentProfileRecordId, nextRequest.taskDigest, nextRequest.operation, nextRequest.network, nextRequest.address]) };
};

/** [label, record, accepted by the ROOT build, parsed form differs from input (a ROOT trim transform)]. */
const CORPUS: [string, Plain, boolean, boolean?][] = [
  ["task_draft as written", draft, true],
  ["task_draft cancelled", cancelled, true],
  ["task_draft untrimmed instructions are trimmed on parse", { ...draft, instructions: "  padded intent  " }, true, true],
  ["task_draft whitespace-only instructions", { ...draft, instructions: "   " }, false],
  ["task_draft 2000-character instructions", { ...draft, instructions: "x".repeat(2000) }, true],
  ["task_draft 2001-character instructions", { ...draft, instructions: "x".repeat(2001) }, false],
  ["task_draft extra key", { ...draft, extra: true }, false],
  ["task_draft updated while still a draft", { ...draft, updatedAt: later }, false],
  ["task_draft draft carrying cancelledAt", { ...draft, cancelledAt: draft.createdAt }, false],
  ["task_draft cancelledAt differs from updatedAt", { ...cancelled, cancelledAt: draft.createdAt }, false],
  ["task_draft cancellation predates creation", { ...cancelled, updatedAt: earlier, cancelledAt: earlier }, false],
  ["task_draft uppercase taskId", { ...draft, taskId: "task_7E570000000040008000000000000901" }, false],
  ["task_draft other network", { ...draft, network: "eip155:1" }, false],
  ["task_draft dispatched execution", { ...draft, execution: "dispatched" }, false],
  ["task_draft future recordSchema", { ...draft, recordSchema: "openarc.task-draft-record.v2" }, false],
  ["task_report as written", report, true],
  ["task_report tampered requestDigest", { ...report, requestDigest: `sha256:${"0".repeat(64)}` }, false],
  ["task_report tampered request without a new requestDigest", { ...report, request: { ...request, taskDigest: `sha256:${"1".repeat(64)}` } }, false],
  ["task_report consistent request with another taskDigest (a relationship rule, not schema)", withRequest({ taskDigest: `sha256:${"1".repeat(64)}` }), true],
  ["task_report updated after creation", { ...report, updatedAt: later }, false],
  ["task_report payment requested", { ...report, payment: "requested" }, false],
  ["task_report request extra key", withRequest({ extra: 1 }), false],
  ["task_report request other operation", withRequest({ operation: "arc_transaction_report" }), false],
  ["research_run completed account investigation", run, true],
  ["research_run approved", { ...run, state: "approved", result: null, updatedAt: run.createdAt }, true],
  ["research_run approved then updated", { ...run, state: "approved", result: null }, false],
  ["research_run unavailable", { ...run, state: "unavailable", result: null }, true],
  ["research_run completed without result", { ...run, result: null }, false],
  ["research_run unavailable with a result", { ...run, state: "unavailable" }, false],
  ["research_run result for another address", { ...run, input: { ...(run.input as object), address: `0x${"2".repeat(40)}` } }, false],
  ["research_run web research completed", webRun, true],
  ["research_run web query mismatch", { ...webRun, input: { operation: "web_research", query: "another query" } }, false],
  ["research_run web query with a control character", { ...webRun, input: { operation: "web_research", query: "badquery" },
    result: { ...webResult, query: "badquery" } }, false],
  ["research_run web query too short", { ...webRun, input: { operation: "web_research", query: "ab" }, result: { ...webResult, query: "ab" } }, false],
  ["research_run web http source", { ...webRun, result: { ...webResult, results: [{ title: "S", url: "http://example.com/a", excerpt: "" }] } }, false],
  ["research_run web .local source", { ...webRun, result: { ...webResult, results: [{ title: "S", url: "https://printer.local/a", excerpt: "" }] } }, false],
  ["research_run web host without TLD", { ...webRun, result: { ...webResult, results: [{ title: "S", url: "https://intranet/a", excerpt: "" }] } }, false],
  ["research_run web six results", { ...webRun, result: { ...webResult, results: Array.from({ length: 6 }, () => webResult.results[0]) } }, false],
  ["research_run web 1601-character excerpt", { ...webRun, result: { ...webResult, results: [{ title: "S", url: "https://example.com/a", excerpt: "x".repeat(1601) }] } }, false],
  ["research_run web other provider", { ...webRun, result: { ...webResult, provider: "other" } }, false],
  ["research_run paid", { ...run, payment: "requested" }, false],
  ["research_run *-record literal instead of the stored one", { ...run, recordSchema: "openarc.research-run-record.v1" }, false],
];

const rootBuild = await loadRootBuild();

describe("P08-01 ROOT-build Vault kinds in the shared record union", () => {
  it("computes SHA-256 exactly like node:crypto for boundary lengths, multi-block, non-ASCII and lone-surrogate input", () => {
    expect(sha256HexUtf8("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(sha256HexUtf8("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    for (let length = 0; length <= 300; length += 1) expect(sha256HexUtf8("a".repeat(length)), `length ${length}`).toBe(nodeHex("a".repeat(length)));
    let seed = 0x5eed;
    const next = () => (seed = (seed * 1_103_515_245 + 12_345) % 2 ** 31);
    const alphabet = ["a", "Z", "0", " ", "\"", "\\", " ", "", "é", "—", "日", "\u{1F512}", "\ud800", "\udfff", "￿"];
    for (let sample = 0; sample < 400; sample += 1) {
      const value = Array.from({ length: next() % 260 }, () => alphabet[next() % alphabet.length]).join("");
      expect(sha256HexUtf8(value), `sample ${sample}`).toBe(nodeHex(value));
    }
    const large = "OpenArc ✓ 日本語 ".repeat(20_000);
    expect(sha256HexUtf8(large)).toBe(nodeHex(large));
  });

  it("reproduces the ROOT build's viem digests for task drafts and report requests, including non-ASCII intent", () => {
    for (const candidate of [draft, cancelled, { ...draft, instructions: "Prüfe Konto — 日本語 \u{1F512} \"quoted\" \\ end" }]) {
      const expected = viemRootDigest(["openarc.private-task.v1", candidate.taskId, candidate.agentProfileRecordId,
        candidate.createdAt, candidate.instructions]);
      expect(accountReportDraftDigest(candidate), rule("accountReportDraftDigest")).toBe(expected);
    }
    expect(request.taskDigest, rule("builder task digest")).toBe(accountReportDraftDigest(draft));
    expect(accountReportRequestDigest(request), rule("accountReportRequestDigest")).toBe(viemRootDigest([request.schemaVersion,
      request.taskId, request.agentProfileRecordId, request.taskDigest, request.operation, request.network, request.address]));
    expect(report.requestDigest).toBe(accountReportRequestDigest(request));
    // The digest covers the parsed (trimmed) instructions, as the ROOT build's parse-first digest does.
    expect(accountReportDraftDigest({ ...draft, instructions: `  ${draft.instructions as string}  ` })).toBe(accountReportDraftDigest(draft));
    expect(() => accountReportDraftDigest({ ...draft, kind: "task_report" })).toThrow();
  });

  it.each(CORPUS)("accepts or rejects exactly as the ROOT build: %s", (label, record, accepted, transformed) => {
    const parsed = WorkspaceRecordSchema.safeParse(record);
    expect(parsed.success, rule(label)).toBe(accepted);
    if (accepted && !transformed) expect(parsed.data, rule(`${label} (no transform)`)).toEqual(record);
    if (transformed) expect(parsed.data).toMatchObject({ instructions: "padded intent" });
  });

  it.skipIf(rootBuild === null)("agrees with the ROOT build's own pinned WorkspaceRecordSchema on every corpus entry", () => {
    for (const [label, record] of CORPUS) {
      const ours = WorkspaceRecordSchema.safeParse(record);
      const theirs = rootBuild!.WorkspaceRecordSchema.safeParse(record);
      expect(ours.success, rule(`ROOT parity: ${label}`)).toBe(theirs.success);
      if (ours.success) expect(ours.data, rule(`ROOT parity data: ${label}`)).toEqual(theirs.data);
    }
    expect(rootBuild!.accountReportDraftDigest(draft)).toBe(accountReportDraftDigest(draft));
    expect(rootBuild!.accountReportRequestDigest(request)).toBe(accountReportRequestDigest(request));
  });

  it("appends the three members after the existing fourteen and keeps the identity table in lock-step with the union", () => {
    interface ZodNode { _zod: { def: { type: string; options?: ZodNode[]; shape?: Record<string, ZodNode>; values?: unknown[] } } }
    const identitiesOf = (node: ZodNode): string[] => {
      const def = node._zod.def;
      if (def.type === "union") return (def.options ?? []).flatMap(identitiesOf);
      if (def.type === "object" && def.shape?.kind && def.shape.recordSchema) {
        return [`${String(def.shape.kind._zod.def.values?.[0])}|${String(def.shape.recordSchema._zod.def.values?.[0])}`];
      }
      throw new Error(`Unexpected union member ${def.type}`);
    };
    const options = (WorkspaceRecordSchema as unknown as ZodNode)._zod.def.options!;
    expect(options).toHaveLength(17);
    expect(options.slice(14).flatMap(identitiesOf), rule("additive member order")).toEqual([
      "task_draft|openarc.task-draft-record.v1", "task_report|openarc.task-report-record.v1", "research_run|openarc.research-run.v1"]);
    const identities = identitiesOf(WorkspaceRecordSchema as unknown as ZodNode);
    // Only the v2 receipt pair is shared by two members (account snapshot and transaction evidence connectors).
    expect(identities.filter((identity, index) => identities.indexOf(identity) !== index), rule("shared identity pairs"))
      .toEqual(["permission_receipt|openarc.permission-receipt.v2"]);
    expect([...new Set(identities)].sort(), rule("WORKSPACE_RECORD_IDENTITIES")).toEqual([...WORKSPACE_RECORD_IDENTITIES].sort());
    expect(Object.isFrozen(WORKSPACE_RECORD_IDENTITIES)).toBe(true);
  });

  it("classifies only the identity pair of an untrusted value", () => {
    for (const record of [...frozen, draft, report, run]) expect(classifyWorkspaceRecordIdentity(record), record.kind).toBe("known");
    expect(classifyWorkspaceRecordIdentity({ ...report, requestDigest: `sha256:${"0".repeat(64)}` })).toBe("known");
    for (const value of [{ ...draft, recordSchema: "openarc.task-draft-record.v2" }, { ...draft, kind: "private_note" },
      { kind: "sentinel", recordSchema: "openarc.workspace-record.v2" }, { kind: "task_draft", recordSchema: "openarc.workspace-record.v1" }]) {
      expect(classifyWorkspaceRecordIdentity(value)).toBe("unknown");
    }
    for (const value of [null, "task_draft", [], {}, { kind: "task_draft" }, { kind: 1, recordSchema: "openarc.task-draft-record.v1" }]) {
      expect(classifyWorkspaceRecordIdentity(value)).toBe("malformed");
    }
    expect(snapshot.schemaVersion).toBe("openarc.arc-account-snapshot.v1");
  });
});
