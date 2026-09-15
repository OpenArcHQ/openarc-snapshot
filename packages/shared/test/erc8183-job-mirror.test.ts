import { encodeAbiParameters, encodeEventTopics, parseAbi, type Hex } from "viem";
import { describe, expect, it } from "vitest";

import {
  ERC8183_ARC_TESTNET_DEPLOYMENT as M,
  Erc8183LogDecodeError,
  Erc8183ManifestError,
  decodeErc8183Log,
  parseErc8183MirrorStatus,
  projectErc8183JobMirror,
  type Erc8183JobProjection,
  type Erc8183LogPage,
  type Erc8183MirrorInput,
  type Erc8183MirrorProjection,
  type Erc8183MirrorStatus,
  type Erc8183RawLog,
} from "../src/index.js";

// Independent encoder: viem ABI from the verified deployed declarations.
const ABI = parseAbi([
  "event JobCreated(uint256 indexed jobId, address indexed client, address indexed provider, address evaluator, uint256 expiredAt, address hook)",
  "event ProviderSet(uint256 indexed jobId, address indexed provider)",
  "event BudgetSet(uint256 indexed jobId, uint256 amount)",
  "event JobFunded(uint256 indexed jobId, address indexed client, uint256 amount)",
  "event JobSubmitted(uint256 indexed jobId, address indexed provider, bytes32 deliverable)",
  "event JobCompleted(uint256 indexed jobId, address indexed evaluator, bytes32 reason)",
  "event JobRejected(uint256 indexed jobId, address indexed rejector, bytes32 reason)",
  "event JobExpired(uint256 indexed jobId)",
  "event PaymentReleased(uint256 indexed jobId, address indexed provider, uint256 amount)",
  "event EvaluatorFeePaid(uint256 indexed jobId, address indexed evaluator, uint256 amount)",
  "event Refunded(uint256 indexed jobId, address indexed client, uint256 amount)",
  "event Upgraded(address indexed implementation)",
  "event Transfer(address indexed from, address indexed to, uint256 value)",
  "event Approval(address indexed owner, address indexed spender, uint256 value)",
]);
type EventName = (typeof ABI)[number]["name"];

const PROXY = M.proxy.address;
const USDC = M.paymentToken.address;
const NATIVE = M.paymentToken.systemEmitter;
const CLIENT = "0x00000000000000000000000000000000000000c1";
const PROVIDER = "0x00000000000000000000000000000000000000b2";
const EVALUATOR = "0x00000000000000000000000000000000000000e3";
const TREASURY = M.governance.platformTreasury;
const ZERO = "0x0000000000000000000000000000000000000000";
const DIGEST = `0x${"d1".repeat(32)}` as Hex;
const REASON = `0x${"5e".repeat(32)}` as Hex;
const NATIVE_SCALE = 1_000_000_000_000n;

const blockHash = (block: number) => `0x${block.toString(16).padStart(64, "0")}`;
const txHash = (tag: string) =>
  `0x${[...tag].map((char) => char.charCodeAt(0).toString(16).padStart(2, "0")).join("").padEnd(64, "0").slice(0, 64)}`;

interface Emit { name: EventName; args: Record<string, unknown>; address?: string }

/** Encodes a whole transaction's logs with consecutive log indexes starting at `firstIndex`. */
function tx(block: number, tag: string, emits: Emit[], firstIndex = 0): Erc8183RawLog[] {
  return emits.map(({ name, args, address }, offset) => {
    const item = ABI.find((entry) => entry.name === name);
    if (item === undefined) throw new Error(name);
    const topics = encodeEventTopics({ abi: [item], eventName: name, args } as never) as Hex[];
    const plain = item.inputs.filter((input) => !("indexed" in input && input.indexed));
    const data = encodeAbiParameters(plain, plain.map((input) => args[input.name as string]) as never);
    const defaultAddress = name === "Transfer" || name === "Approval" ? USDC : PROXY;
    return {
      address: address ?? defaultAddress, topics, data, blockNumber: `0x${block.toString(16)}`, blockHash: blockHash(block),
      transactionHash: txHash(tag), transactionIndex: "0x0", logIndex: `0x${(firstIndex + offset).toString(16)}`,
    };
  });
}

const created = (jobId: bigint, extra: Partial<Record<string, unknown>> = {}): Emit => ({ name: "JobCreated",
  args: { jobId, client: CLIENT, provider: PROVIDER, evaluator: EVALUATOR, expiredAt: 2_000_000_000n, hook: ZERO, ...extra } });
const budget = (jobId: bigint, amount: bigint): Emit => ({ name: "BudgetSet", args: { jobId, amount } });
const funded = (jobId: bigint, amount: bigint): Emit => ({ name: "JobFunded", args: { jobId, client: CLIENT, amount } });
const submitted = (jobId: bigint): Emit => ({ name: "JobSubmitted", args: { jobId, provider: PROVIDER, deliverable: DIGEST } });
const transfers = (from: string, to: string, value: bigint): Emit[] => [
  { name: "Transfer", address: NATIVE, args: { from, to, value: value * NATIVE_SCALE } },
  { name: "Transfer", address: USDC, args: { from, to, value } },
];
const approval = (value: bigint): Emit => ({ name: "Approval", args: { owner: CLIENT, spender: PROXY, value } });

function page(from: number, to: number, logs: Erc8183RawLog[], outcome: Erc8183LogPage["outcome"] = "complete"): Erc8183LogPage {
  return { fromBlock: String(from), toBlock: String(to), outcome, logs };
}

function input(pages: Erc8183LogPage[], extra: Partial<Erc8183MirrorInput> = {}): Erc8183MirrorInput {
  return {
    network: "eip155:5042002", startBlock: "1",
    finalized: { tag: "finalized", number: "1000", hash: blockHash(1000), timestamp: "1900000000" },
    pages, ...extra,
  };
}

const job = (projection: Erc8183MirrorProjection, id: string): Erc8183JobProjection => {
  const found = projection.jobs.find((candidate) => candidate.jobId === id);
  if (found === undefined) throw new Error(`job ${id} missing`);
  return found;
};

const known = (projection: Erc8183MirrorProjection, id: string) => {
  const status = job(projection, id).status;
  if (status.kind !== "known") throw new Error(`job ${id} is ${status.reason}`);
  return status;
};

/** Standard funded → submitted → completed lifecycle with fees and double transfers. */
function completedLifecycle(): Erc8183RawLog[] {
  return [
    ...tx(100, "create", [created(1n)]),
    ...tx(101, "budget", [budget(1n, 5_000_000n)]),
    ...tx(102, "approve", [approval(5_000_000n)]),
    ...tx(103, "fund", [...transfers(CLIENT, PROXY, 5_000_000n), funded(1n, 5_000_000n)]),
    ...tx(104, "submit", [submitted(1n)]),
    ...tx(105, "complete", [
      ...transfers(PROXY, TREASURY, 50_000n),
      ...transfers(PROXY, EVALUATOR, 50_000n),
      { name: "EvaluatorFeePaid", args: { jobId: 1n, evaluator: EVALUATOR, amount: 50_000n } },
      ...transfers(PROXY, PROVIDER, 4_900_000n),
      { name: "JobCompleted", args: { jobId: 1n, evaluator: EVALUATOR, reason: REASON } },
      { name: "PaymentReleased", args: { jobId: 1n, provider: PROVIDER, amount: 4_900_000n } },
    ]),
  ];
}

describe("decodeErc8183Log", () => {
  it("decodes every deployed event with the verified indexed layout", () => {
    const [log] = tx(100, "create", [created(186523n, { expiredAt: 1_900_000_600n })]);
    const decoded = decodeErc8183Log(M, log as Erc8183RawLog);
    expect(decoded.event).toEqual({ name: "JobCreated", jobId: 186523n, client: CLIENT, provider: PROVIDER, evaluator: EVALUATOR,
      expiredAt: 1_900_000_600n, hook: ZERO });
    expect(decoded.blockNumber).toBe("100");
    const refund = decodeErc8183Log(M, tx(1, "r", [{ name: "Refunded", args: { jobId: 9n, client: CLIENT, amount: 1_360_502n } }])[0] as Erc8183RawLog);
    expect(refund.event).toEqual({ name: "Refunded", jobId: 9n, client: CLIENT, amount: 1_360_502n });
  });

  it("rejects the ERC's non-deployed JobCreated topic, foreign contracts, and malformed shapes", () => {
    const [base] = tx(100, "create", [created(1n)]) as [Erc8183RawLog];
    const standardTopic = { ...base, topics: [M.nonDeployedStandardTopics.JobCreated, ...base.topics.slice(1)] };
    expect(() => decodeErc8183Log(M, standardTopic)).toThrow(/topic0:not_in_manifest/u);
    expect(() => decodeErc8183Log(M, { ...base, address: "0x0000000000000000000000000000000000000bad" })).toThrow(Erc8183LogDecodeError);
    expect(() => decodeErc8183Log(M, { ...base, data: `${base.data}00` })).toThrow(Erc8183LogDecodeError);
    expect(() => decodeErc8183Log(M, { ...base, topics: base.topics.slice(0, 3) })).toThrow(/JobCreated:shape/u);
    expect(() => decodeErc8183Log(M, { ...base, blockNumber: "100" })).toThrow(/blockNumber:quantity/u);
    expect(() => decodeErc8183Log(M, { ...base, logIndex: "0x01" })).toThrow(/logIndex:quantity/u);
    const dirtyAddress = { ...base, topics: [base.topics[0] as string, base.topics[1] as string, `0x${"ff".repeat(12)}${CLIENT.slice(2)}`, base.topics[3] as string] };
    expect(() => decodeErc8183Log(M, dirtyAddress)).toThrow(/address_padding/u);
  });
});

describe("projectErc8183JobMirror (P07-03)", () => {
  it("projects a full lifecycle and counts the double USDC Transfer once", () => {
    const projection = projectErc8183JobMirror(input([page(1, 1000, completedLifecycle())]));
    expect(projection.coverage).toEqual({ startBlock: "1", appliedThroughBlock: "1000", finalizedBlock: "1000", complete: true });
    expect(projection.holds).toEqual([]);
    const result = job(projection, "1");
    expect(result.status).toEqual({ kind: "known", status: "Completed", terminal: true, asOfBlock: "1000" });
    expect(result.canonicalId).toBe("eip155:5042002:erc8183:0x0747eef0706327138c69792bf28cd525089e4583:1");
    expect(result.funded?.amount).toBe("5000000");
    expect(result.completion).toMatchObject({ providerNet: "4900000", evaluatorFee: "50000", platformFee: "50000", reason: REASON });
    expect(result.deliverable?.digest).toBe(DIGEST);
    // 5 USDC in 6-decimal base units, never 5e18 + 5e6.
    expect(result.money).toEqual({ escrowed: "0", spent: "5000000", returned: "0", heldUnknown: "0" });
    expect(result.flags).toEqual([]);
    expect(result.refund).toEqual({ state: "not_applicable" });
  });

  it("flags a native 18-decimal Transfer without an ERC-20 twin instead of counting it", () => {
    const logs = [
      ...tx(100, "create", [created(1n)]),
      ...tx(101, "budget", [budget(1n, 5_000_000n)]),
      ...tx(103, "fund", [
        { name: "Transfer", address: NATIVE, args: { from: CLIENT, to: PROXY, value: 5_000_000n * NATIVE_SCALE } },
        { name: "Transfer", address: USDC, args: { from: CLIENT, to: PROXY, value: 4_000_000n } },
        funded(1n, 5_000_000n),
      ]),
    ];
    const result = job(projectErc8183JobMirror(input([page(1, 1000, logs)])), "1");
    expect(result.funded?.amount).toBe("5000000");
    expect(result.money.escrowed).toBe("5000000");
    expect(result.flags.map((flag) => flag.kind)).toEqual(["transfer_representation_mismatch", "transfer_representation_mismatch"]);
  });

  it("C2/C4: provider budget is repeatable, and a zero-budget job may submit from Open", () => {
    const logs = [
      ...tx(100, "create", [created(1n)]),
      ...tx(101, "b1", [budget(1n, 7n)]),
      ...tx(102, "b2", [budget(1n, 0n)]),
      ...tx(103, "submit", [submitted(1n)]),
    ];
    const result = job(projectErc8183JobMirror(input([page(1, 1000, logs)])), "1");
    expect(known(projectErc8183JobMirror(input([page(1, 1000, logs)])), "1").status).toBe("Submitted");
    expect(result.budget).toMatchObject({ current: "0", explicitlySet: true });
    expect(result.budget.history.map((entry) => entry.amount)).toEqual(["7", "0"]);
    expect(result.funded).toBeNull();
    expect(result.flags.map((flag) => flag.kind)).toEqual(["submitted_from_open_zero_budget"]);
  });

  it("holds submit from Open with a non-zero budget as a conflict", () => {
    const logs = [...tx(100, "c", [created(1n)]), ...tx(101, "b", [budget(1n, 1n)]), ...tx(102, "s", [submitted(1n)])];
    const status = job(projectErc8183JobMirror(input([page(1, 1000, logs)])), "1").status;
    expect(status).toMatchObject({ kind: "unknown", reason: "event_conflict", lastKnown: "Open" });
  });

  it("evaluator may reject after the deadline; the refund counts only when paired in the same tx", () => {
    const logs = [
      ...tx(100, "create", [created(1n, { expiredAt: 1_800_000_000n })]),
      ...tx(101, "budget", [budget(1n, 1_360_502n)]),
      ...tx(102, "fund", [funded(1n, 1_360_502n)]),
      ...tx(300, "reject", [
        ...transfers(PROXY, CLIENT, 1_360_502n),
        { name: "Refunded", args: { jobId: 1n, client: CLIENT, amount: 1_360_502n } },
        { name: "JobRejected", args: { jobId: 1n, rejector: EVALUATOR, reason: REASON } },
      ]),
    ];
    const blocks = [{ number: "102", hash: blockHash(102), timestamp: "1700000000" }, { number: "300", hash: blockHash(300), timestamp: "1800000001" }];
    const projection = projectErc8183JobMirror(input([page(1, 1000, logs)], { blocks }));
    const result = job(projection, "1");
    expect(result.status).toMatchObject({ kind: "known", status: "Rejected", terminal: true });
    expect(result.rejection).toMatchObject({ rejector: EVALUATOR, from: "Funded" });
    expect(result.refund).toEqual({ state: "refunded", amount: "1360502", cause: "rejected", transactionHash: txHash("reject") });
    expect(result.money).toEqual({ escrowed: "0", spent: "0", returned: "1360502", heldUnknown: "0" });
    expect(result.flags.map((flag) => flag.kind)).toEqual(["rejected_after_deadline"]);
  });

  it("a client may reject an Open job without any refund", () => {
    const logs = [...tx(100, "c", [created(1n)]), ...tx(101, "r", [{ name: "JobRejected", args: { jobId: 1n, rejector: CLIENT, reason: REASON } }])];
    const result = job(projectErc8183JobMirror(input([page(1, 1000, logs)])), "1");
    expect(result.status).toMatchObject({ kind: "known", status: "Rejected" });
    expect(result.refund).toEqual({ state: "not_applicable" });
    expect(result.money.returned).toBe("0");
  });

  it("a zero-budget funded job rejected by the evaluator records no refund", () => {
    const logs = [...tx(100, "c", [created(1n)]), ...tx(101, "f", [funded(1n, 0n)]),
      ...tx(102, "r", [{ name: "JobRejected", args: { jobId: 1n, rejector: EVALUATOR, reason: REASON } }])];
    const result = job(projectErc8183JobMirror(input([page(1, 1000, logs)])), "1");
    expect(result.refund).toEqual({ state: "none_zero_budget", cause: "rejected" });
  });

  it("an unpaired Refunded is held as unknown and never counted as returned", () => {
    const logs = [
      ...tx(100, "c", [created(1n)]), ...tx(101, "b", [budget(1n, 9n)]), ...tx(102, "f", [funded(1n, 9n)]),
      ...tx(200, "refund-only", [{ name: "Refunded", args: { jobId: 1n, client: CLIENT, amount: 9n } }]),
      ...tx(201, "reject-later", [{ name: "JobRejected", args: { jobId: 1n, rejector: EVALUATOR, reason: REASON } }]),
    ];
    const result = job(projectErc8183JobMirror(input([page(1, 1000, logs)])), "1");
    expect(result.status).toMatchObject({ kind: "unknown", reason: "refund_unpaired", lastKnown: "Funded" });
    expect(result.refund).toEqual({ state: "unknown", amount: "9", reason: "unpaired_refund" });
    expect(result.money).toEqual({ escrowed: "0", spent: "0", returned: "0", heldUnknown: "9" });
    expect(result.rejection).toBeNull();
  });

  it("a funded rejection without Refunded is held, not assumed refunded", () => {
    const logs = [...tx(100, "c", [created(1n)]), ...tx(101, "b", [budget(1n, 9n)]), ...tx(102, "f", [funded(1n, 9n)]),
      ...tx(103, "r", [{ name: "JobRejected", args: { jobId: 1n, rejector: EVALUATOR, reason: REASON } }])];
    const result = job(projectErc8183JobMirror(input([page(1, 1000, logs)])), "1");
    expect(result.status).toMatchObject({ kind: "unknown", reason: "refund_unpaired" });
    expect(result.refund).toEqual({ state: "unknown", amount: null, reason: "missing_refund_event" });
    expect(result.money).toMatchObject({ returned: "0", heldUnknown: "9" });
  });

  it("claimRefund: Refunded paired with JobExpired moves Funded/Submitted to Expired", () => {
    const logs = [...tx(100, "c", [created(1n, { expiredAt: 1_800_000_000n })]), ...tx(101, "b", [budget(1n, 9n)]),
      ...tx(102, "f", [funded(1n, 9n)]), ...tx(103, "s", [submitted(1n)]),
      ...tx(500, "claim", [{ name: "Refunded", args: { jobId: 1n, client: CLIENT, amount: 9n } }, { name: "JobExpired", args: { jobId: 1n } }])];
    const result = job(projectErc8183JobMirror(input([page(1, 1000, logs)])), "1");
    expect(result.status).toMatchObject({ kind: "known", status: "Expired", terminal: true });
    expect(result.expiry?.from).toBe("Submitted");
    expect(result.refund).toMatchObject({ state: "refunded", cause: "expired", amount: "9" });
    expect(result.money).toEqual({ escrowed: "0", spent: "0", returned: "9", heldUnknown: "0" });
    expect(result.derived).toEqual({ deadlineReachedAtFinalized: true, observation: null });
  });

  it("a passing deadline changes nothing without a JobExpired event", () => {
    const logs = [
      ...tx(100, "c1", [created(1n, { expiredAt: 1_850_000_000n })]), ...tx(101, "b1", [budget(1n, 9n)]), ...tx(102, "f1", [funded(1n, 9n)]),
      ...tx(103, "c2", [created(2n, { expiredAt: 1_850_000_000n })]),
      ...tx(104, "c3", [created(3n, { expiredAt: 1_950_000_000n })]),
    ];
    const projection = projectErc8183JobMirror(input([page(1, 1000, logs)]));
    expect(job(projection, "1").status).toMatchObject({ kind: "known", status: "Funded", terminal: false });
    expect(job(projection, "1").derived).toEqual({ deadlineReachedAtFinalized: true, observation: "deadline_reached_unclaimed" });
    expect(job(projection, "1").money).toEqual({ escrowed: "9", spent: "0", returned: "0", heldUnknown: "0" });
    expect(job(projection, "1").refund).toEqual({ state: "not_applicable" });
    expect(job(projection, "2").status).toMatchObject({ kind: "known", status: "Open" });
    expect(job(projection, "2").derived.observation).toBe("open_past_deadline");
    expect(job(projection, "3").derived).toEqual({ deadlineReachedAtFinalized: false, observation: null });
  });

  it("surfaces a budget change after client approval and a funded amount that differs from the agreement", () => {
    const logs = [
      ...tx(100, "c", [created(1n)]), ...tx(101, "b1", [budget(1n, 5_000_000n)]), ...tx(102, "approve", [approval(9_000_000n)]),
      ...tx(103, "b2", [budget(1n, 9_000_000n)]), ...tx(104, "f", [funded(1n, 9_000_000n)]),
    ];
    const result = job(projectErc8183JobMirror(input([page(1, 1000, logs)], { agreedBudgets: { "1": "5000000" } })), "1");
    expect(result.budget.history.map((entry) => [entry.amount, entry.afterClientApproval])).toEqual([["5000000", false], ["9000000", true]]);
    expect(result.flags.map((flag) => flag.kind)).toEqual(["budget_changed_after_approval", "funded_amount_differs_from_agreed"]);
    expect(result.funded?.amount).toBe("9000000");
  });

  it("does not flag an unchanged budget after approval", () => {
    const logs = [...tx(100, "c", [created(1n)]), ...tx(101, "b1", [budget(1n, 5n)]), ...tx(102, "a", [approval(5n)]),
      ...tx(103, "b2", [budget(1n, 5n)]), ...tx(104, "f", [funded(1n, 5n)])];
    const result = job(projectErc8183JobMirror(input([page(1, 1000, logs)], { agreedBudgets: { "1": "5" } })), "1");
    expect(result.flags).toEqual([]);
  });

  it("anchors on finalized: facts above it are unfinalized and never terminal", () => {
    const logs = completedLifecycle().map((log) => (log.transactionHash === txHash("complete")
      ? { ...log, blockNumber: "0x3ed", blockHash: blockHash(1005) } : log));
    const projection = projectErc8183JobMirror(input([page(1, 1010, logs)]));
    const result = job(projection, "1");
    expect(result.status).toEqual({ kind: "known", status: "Submitted", terminal: false, asOfBlock: "1000" });
    expect(result.completion).toBeNull();
    expect(result.money.spent).toBe("0");
    expect(result.unfinalized.map((fact) => fact.event)).toEqual(["EvaluatorFeePaid", "JobCompleted", "PaymentReleased"]);
    expect(projection.unfinalized).toHaveLength(3);
    expect(projection.coverage.appliedThroughBlock).toBe("1000");
    expect(projection.coverage.complete).toBe(true);
  });

  it("holds a page gap and applies nothing after it", () => {
    const projection = projectErc8183JobMirror(input([
      page(1, 100, tx(50, "c", [created(1n)])),
      page(201, 1000, tx(300, "b", [budget(1n, 5n)])),
    ]));
    expect(projection.holds).toEqual([{ kind: "gap", fromBlock: "101", toBlock: "200", detail: expect.any(String) }]);
    expect(projection.coverage).toMatchObject({ appliedThroughBlock: "100", complete: false });
    const result = job(projection, "1");
    expect(result.status).toMatchObject({ kind: "known", status: "Open", asOfBlock: "100" });
    expect(result.budget).toMatchObject({ current: "0", explicitlySet: false });
  });

  it("holds a failed (rate-limited) page as a gap, never as empty", () => {
    const projection = projectErc8183JobMirror(input([page(1, 100, tx(50, "c", [created(1n)])), page(101, 1000, [], "failed")]));
    expect(projection.holds.map((entry) => [entry.kind, entry.fromBlock, entry.toBlock])).toEqual([["page_failed", "101", "1000"]]);
    expect(projection.coverage).toMatchObject({ appliedThroughBlock: "100", complete: false });
  });

  it("holds unscanned finalized blocks as a trailing gap", () => {
    const projection = projectErc8183JobMirror(input([page(1, 500, tx(50, "c", [created(1n)]))]));
    expect(projection.holds.map((entry) => [entry.kind, entry.fromBlock, entry.toBlock])).toEqual([["gap", "501", "1000"]]);
    expect(projection.coverage.complete).toBe(false);
    expect(job(projection, "1").status).toMatchObject({ kind: "known", status: "Open", asOfBlock: "500" });
  });

  it("holds an out-of-order page and applies none of its logs", () => {
    const logs = [...tx(60, "b", [budget(1n, 5n)]), ...tx(50, "c", [created(1n)])];
    const projection = projectErc8183JobMirror(input([page(1, 1000, logs)]));
    expect(projection.holds.map((entry) => entry.kind)).toEqual(["page_out_of_order"]);
    expect(projection.jobs).toEqual([]);
    expect(projection.coverage).toMatchObject({ appliedThroughBlock: null, complete: false });
  });

  it("holds a page range wider than the 10,000-block RPC limit, a removed log, and a block-hash conflict", () => {
    const wide = projectErc8183JobMirror(input([page(1, 10001, [])]));
    expect(wide.holds.map((entry) => entry.kind)).toEqual(["page_range_invalid", "gap"]);

    const removed = tx(50, "c", [created(1n)]).map((log) => ({ ...log, removed: true }));
    expect(projectErc8183JobMirror(input([page(1, 1000, removed)])).holds.map((entry) => entry.kind)).toEqual(["log_removed"]);

    const forked = tx(1000, "c", [created(1n)]).map((log) => ({ ...log, blockHash: `0x${"99".repeat(32)}` }));
    const conflict = projectErc8183JobMirror(input([page(1, 1000, forked)]));
    expect(conflict.holds.map((entry) => entry.kind)).toEqual(["block_hash_conflict"]);
    expect(conflict.jobs).toEqual([]);
  });

  it("deduplicates identical overlapping pages and holds conflicting overlaps", () => {
    const shared = tx(450, "b", [budget(1n, 5n)]);
    const same = projectErc8183JobMirror(input([page(1, 500, [...tx(100, "c", [created(1n)]), ...shared]), page(400, 1000, shared)]));
    expect(same.holds).toEqual([]);
    expect(job(same, "1").budget.history).toHaveLength(1);

    const altered = tx(450, "b", [budget(1n, 6n)]);
    const conflicting = projectErc8183JobMirror(input([page(1, 500, [...tx(100, "c", [created(1n)]), ...shared]), page(400, 1000, altered)]));
    expect(conflicting.holds.map((entry) => entry.kind)).toEqual(["log_conflict"]);
    expect(conflicting.coverage.complete).toBe(false);
  });

  it("holds a proxy log with an unknown topic, including the ERC's five-argument JobCreated", () => {
    const [base] = tx(50, "c", [created(1n)]) as [Erc8183RawLog];
    const projection = projectErc8183JobMirror(input([page(1, 1000, [{ ...base, topics: [M.nonDeployedStandardTopics.JobCreated, ...base.topics.slice(1)] }])]));
    expect(projection.holds.map((entry) => entry.kind)).toEqual(["log_malformed"]);
    expect(projection.jobs).toEqual([]);
  });

  it("freezes application at an Upgraded event to a different implementation", () => {
    const logs = [
      ...tx(10, "upgrade-ok", [{ name: "Upgraded", args: { implementation: M.implementation.address } }]),
      ...tx(100, "c", [created(1n)]),
      ...tx(400, "upgrade-bad", [{ name: "Upgraded", args: { implementation: "0x00000000000000000000000000000000000000aa" } }]),
      ...tx(500, "b", [budget(1n, 5n)]),
    ];
    const projection = projectErc8183JobMirror(input([page(1, 1000, logs)]));
    expect(projection.holds.map((entry) => [entry.kind, entry.fromBlock])).toEqual([["implementation_changed", "400"]]);
    expect(projection.coverage).toMatchObject({ appliedThroughBlock: "399", complete: false });
    expect(job(projection, "1").budget.current).toBe("0");
  });

  it("holds jobs whose creation predates the mirror start as unknown", () => {
    const projection = projectErc8183JobMirror(input([page(500, 1000, tx(600, "b", [budget(7n, 5n)]))], { startBlock: "500" }));
    expect(job(projection, "7").status).toMatchObject({ kind: "unknown", reason: "created_before_mirror_start", lastKnown: null });
    expect(job(projection, "7").flags.map((flag) => flag.kind)).toEqual(["job_created_before_mirror_start"]);
  });

  it("flags non-zero hooks as unsupported", () => {
    const logs = tx(100, "c", [created(1n, { hook: "0x00000000000000000000000000000000000000cc" })]);
    expect(job(projectErc8183JobMirror(input([page(1, 1000, logs)])), "1").flags.map((flag) => flag.kind)).toEqual(["nonzero_hook"]);
  });

  it("holds a completion without PaymentReleased as unknown money", () => {
    const logs = [...tx(100, "c", [created(1n)]), ...tx(101, "b", [budget(1n, 9n)]), ...tx(102, "f", [funded(1n, 9n)]),
      ...tx(103, "s", [submitted(1n)]), ...tx(104, "done", [{ name: "JobCompleted", args: { jobId: 1n, evaluator: EVALUATOR, reason: REASON } }])];
    const result = job(projectErc8183JobMirror(input([page(1, 1000, logs)])), "1");
    expect(result.completion).toMatchObject({ providerNet: null, platformFee: null });
    expect(result.money).toEqual({ escrowed: "0", spent: "0", returned: "0", heldUnknown: "9" });
    expect(result.flags.map((flag) => flag.kind)).toEqual(["payment_release_missing"]);
  });

  it("is pure and deterministic: identical output for repeated and page-reordered input, deeply frozen", () => {
    const pages = [page(1, 300, completedLifecycle().slice(0, 6)), page(301, 1000, []), page(101, 110, completedLifecycle().slice(3))];
    const first = projectErc8183JobMirror(input(pages));
    const again = projectErc8183JobMirror(input(pages));
    const reordered = projectErc8183JobMirror(input([...pages].reverse()));
    expect(again).toEqual(first);
    expect(reordered).toEqual(first);
    expect(JSON.stringify(first)).toBe(JSON.stringify(reordered));
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first.jobs[0]?.money)).toBe(true);
    expect(job(first, "1").status).toMatchObject({ status: "Completed" });
  });

  it("throws for unknown networks and non-finalized anchors instead of projecting", () => {
    expect(() => projectErc8183JobMirror({ ...input([]), network: "eip155:1" })).toThrow(Erc8183ManifestError);
    expect(() => projectErc8183JobMirror({ ...input([]), finalized: { ...input([]).finalized, tag: "latest" as "finalized" } }))
      .toThrow(Erc8183LogDecodeError);
  });

  describe("unrepresentable states", () => {
    it("rejects provider acceptance, settled and disputed at the type and runtime level", () => {
      // @ts-expect-error — there is no provider-acceptance state on the deployed contract (C10)
      const accepted: Erc8183MirrorStatus = "Accepted";
      // @ts-expect-error — settlement is atomic inside complete; there is no Settled state (C10)
      const settled: Erc8183MirrorStatus = "Settled";
      // @ts-expect-error — there is no on-chain dispute (C8)
      const disputed: Erc8183MirrorStatus = "Disputed";
      for (const value of [accepted, settled, disputed, "ProviderAccepted", "accepted", "settled", "disputed", "Dispute", 3, null]) {
        expect(() => parseErc8183MirrorStatus(value), String(value)).toThrow(Erc8183LogDecodeError);
      }
      for (const status of M.statuses) expect(parseErc8183MirrorStatus(status)).toBe(status);
    });

    it("never emits a status, refund or flag outside the deployed vocabulary across every scenario", () => {
      const scenarios = [completedLifecycle(), [...tx(100, "c", [created(1n)]), ...tx(101, "s", [submitted(1n)])]];
      const allowed = new Set<string>(M.statuses);
      for (const logs of scenarios) {
        const text = JSON.stringify(projectErc8183JobMirror(input([page(1, 1000, logs)])), (_key, value: unknown) =>
          (typeof value === "bigint" ? value.toString() : value));
        expect(text.toLowerCase()).not.toMatch(/accept|settle|dispute/u);
        for (const projected of projectErc8183JobMirror(input([page(1, 1000, logs)])).jobs) {
          const status = projected.status.kind === "known" ? projected.status.status : projected.status.lastKnown;
          if (status !== null) expect(allowed.has(status)).toBe(true);
        }
      }
    });
  });
});
