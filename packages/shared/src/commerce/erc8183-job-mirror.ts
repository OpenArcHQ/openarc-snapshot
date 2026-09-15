import {
  ERC8183_TERMINAL_STATUSES,
  type Erc8183DeployedStatus,
  type Erc8183DeploymentManifest,
  erc8183CanonicalJobId,
  resolveErc8183Deployment,
} from "./erc8183-manifest.js";

/**
 * P07-03 — pure, read-only ERC-8183 job event mirror projection.
 *
 * Input: raw RPC-shaped logs grouped into scanned block-range pages, plus the
 * `finalized` block anchor and optional block metadata. There is no RPC
 * client, clock, randomness or I/O here: the same input always yields the
 * same projection. Amounts are exact uint256 decimal strings.
 *
 * Fail-closed rules:
 * - Only the contiguous, well-formed, finalized prefix of pages is applied.
 *   A missing, failed, overlapping-with-conflict or out-of-order page is an
 *   explicit hold; nothing after it is applied, and it is never read as empty.
 * - Facts above the finalized block are reported as unfinalized and never
 *   change status, let alone produce a terminal state.
 * - Status changes only through observed events. A passing deadline is a
 *   derived observation, not a transition.
 * - A refund counts only when `Refunded` is paired with `JobRejected` or
 *   `JobExpired` for the same job in the same transaction.
 * - ERC-20 (6-decimal) and native mirror (18-decimal) USDC transfers are
 *   corroboration only; the native mirror is never added.
 */

/** The only statuses a projected job may carry. Deliberately excludes accepted/settled/disputed (C8, C10). */
export type Erc8183MirrorStatus = Erc8183DeployedStatus;

export interface Erc8183RawLog {
  readonly address: string;
  readonly topics: readonly string[];
  readonly data: string;
  /** Hex quantities as returned by `eth_getLogs`. */
  readonly blockNumber: string;
  readonly blockHash: string;
  readonly transactionHash: string;
  readonly transactionIndex: string;
  readonly logIndex: string;
  readonly removed?: boolean;
}

export interface Erc8183LogPage {
  /** Inclusive decimal block range this page claims to cover. */
  readonly fromBlock: string;
  readonly toBlock: string;
  /** `failed` covers rate limits, timeouts and range errors: its range is a gap. */
  readonly outcome: "complete" | "failed";
  readonly logs: readonly Erc8183RawLog[];
}

export interface Erc8183BlockMetadata {
  readonly number: string;
  readonly hash: string;
  /** Unix seconds, decimal. */
  readonly timestamp: string;
}

export interface Erc8183MirrorInput {
  readonly network: string;
  /** First block the cursor is responsible for (decimal). */
  readonly startBlock: string;
  readonly finalized: Erc8183BlockMetadata & { readonly tag: "finalized" };
  readonly pages: readonly Erc8183LogPage[];
  /** Optional per-block metadata for deadline checks at event time. */
  readonly blocks?: readonly Erc8183BlockMetadata[];
  /** Optional off-chain agreed budgets per job ID (decimal base units). */
  readonly agreedBudgets?: Readonly<Record<string, string>>;
}

export type Erc8183HoldKind =
  | "gap"
  | "page_failed"
  | "page_out_of_order"
  | "page_range_invalid"
  | "log_outside_page"
  | "log_malformed"
  | "log_removed"
  | "log_conflict"
  | "block_hash_conflict"
  | "implementation_changed";

export interface Erc8183Hold {
  readonly kind: Erc8183HoldKind;
  readonly fromBlock: string;
  readonly toBlock: string;
  readonly detail: string;
}

export type Erc8183RiskFlagKind =
  | "budget_changed_after_approval"
  | "funded_amount_differs_from_agreed"
  | "submitted_from_open_zero_budget"
  | "rejected_after_deadline"
  | "nonzero_hook"
  | "refund_unpaired"
  | "payment_release_missing"
  | "transfer_representation_mismatch"
  | "job_event_conflict"
  | "job_created_before_mirror_start";

export interface Erc8183RiskFlag {
  readonly kind: Erc8183RiskFlagKind;
  readonly blockNumber: string;
  readonly transactionHash: string;
  readonly logIndex: string;
  readonly detail: string;
}

export interface Erc8183UnfinalizedFact {
  readonly jobId: string | null;
  readonly event: string;
  readonly blockNumber: string;
  readonly transactionHash: string;
  readonly logIndex: string;
}

export type Erc8183RefundFact =
  | { readonly state: "not_applicable" }
  | { readonly state: "none_zero_budget"; readonly cause: "rejected" | "expired" }
  | { readonly state: "refunded"; readonly amount: string; readonly cause: "rejected" | "expired"; readonly transactionHash: string }
  | { readonly state: "unknown"; readonly amount: string | null; readonly reason: "unpaired_refund" | "missing_refund_event" };

export type Erc8183JobStatusFact =
  | { readonly kind: "known"; readonly status: Erc8183MirrorStatus; readonly terminal: boolean; readonly asOfBlock: string }
  | { readonly kind: "unknown"; readonly reason: Erc8183UnknownReason; readonly lastKnown: Erc8183MirrorStatus | null; readonly asOfBlock: string };

export type Erc8183UnknownReason = "created_before_mirror_start" | "event_conflict" | "refund_unpaired";

export interface Erc8183EventRef {
  readonly blockNumber: string;
  readonly transactionHash: string;
  readonly logIndex: string;
}

export interface Erc8183JobProjection {
  readonly jobId: string;
  readonly canonicalId: string;
  readonly status: Erc8183JobStatusFact;
  readonly client: string | null;
  readonly provider: string | null;
  readonly evaluator: string | null;
  readonly hook: string | null;
  readonly expiredAt: string | null;
  readonly budget: {
    readonly current: string;
    readonly explicitlySet: boolean;
    readonly history: readonly (Erc8183EventRef & { readonly amount: string; readonly afterClientApproval: boolean })[];
  };
  readonly funded: (Erc8183EventRef & { readonly amount: string }) | null;
  readonly deliverable: (Erc8183EventRef & { readonly digest: string }) | null;
  readonly completion: (Erc8183EventRef & {
    readonly reason: string;
    readonly providerNet: string | null;
    readonly evaluatorFee: string;
    /** `funded - net - evaluatorFee`; null while net is unknown. */
    readonly platformFee: string | null;
  }) | null;
  readonly rejection: (Erc8183EventRef & { readonly rejector: string; readonly reason: string; readonly from: Erc8183MirrorStatus }) | null;
  readonly expiry: (Erc8183EventRef & { readonly from: Erc8183MirrorStatus }) | null;
  readonly refund: Erc8183RefundFact;
  /** Client-side money view. Held-unknown is never counted as returned or spent. */
  readonly money: { readonly escrowed: string; readonly spent: string; readonly returned: string; readonly heldUnknown: string };
  readonly derived: {
    readonly deadlineReachedAtFinalized: boolean | null;
    readonly observation: "deadline_reached_unclaimed" | "open_past_deadline" | null;
  };
  readonly flags: readonly Erc8183RiskFlag[];
  readonly unfinalized: readonly Erc8183UnfinalizedFact[];
}

export interface Erc8183MirrorProjection {
  readonly schemaVersion: "openarc.erc8183-job-mirror.v1";
  readonly network: string;
  readonly contract: string;
  readonly finalized: { readonly blockNumber: string; readonly blockHash: string; readonly timestamp: string };
  readonly coverage: {
    readonly startBlock: string;
    /** Last block whose logs were fully applied; null when no block was. */
    readonly appliedThroughBlock: string | null;
    readonly finalizedBlock: string;
    readonly complete: boolean;
  };
  readonly holds: readonly Erc8183Hold[];
  readonly jobs: readonly Erc8183JobProjection[];
  readonly unfinalized: readonly Erc8183UnfinalizedFact[];
}

// ───────────────────────── decoding ─────────────────────────

export type Erc8183DecodedEvent =
  | { readonly name: "JobCreated"; readonly jobId: bigint; readonly client: string; readonly provider: string; readonly evaluator: string; readonly expiredAt: bigint; readonly hook: string }
  | { readonly name: "ProviderSet"; readonly jobId: bigint; readonly provider: string }
  | { readonly name: "BudgetSet"; readonly jobId: bigint; readonly amount: bigint }
  | { readonly name: "JobFunded"; readonly jobId: bigint; readonly client: string; readonly amount: bigint }
  | { readonly name: "JobSubmitted"; readonly jobId: bigint; readonly provider: string; readonly deliverable: string }
  | { readonly name: "JobCompleted"; readonly jobId: bigint; readonly evaluator: string; readonly reason: string }
  | { readonly name: "JobRejected"; readonly jobId: bigint; readonly rejector: string; readonly reason: string }
  | { readonly name: "JobExpired"; readonly jobId: bigint }
  | { readonly name: "PaymentReleased"; readonly jobId: bigint; readonly provider: string; readonly amount: bigint }
  | { readonly name: "EvaluatorFeePaid"; readonly jobId: bigint; readonly evaluator: string; readonly amount: bigint }
  | { readonly name: "Refunded"; readonly jobId: bigint; readonly client: string; readonly amount: bigint }
  | { readonly name: "HookWhitelistUpdated"; readonly hook: string; readonly status: boolean }
  | { readonly name: "Upgraded"; readonly implementation: string }
  | { readonly name: "Transfer"; readonly representation: "erc20" | "native"; readonly from: string; readonly to: string; readonly value: bigint }
  | { readonly name: "Approval"; readonly owner: string; readonly spender: string; readonly value: bigint }
  | { readonly name: "Ignored" };

export interface Erc8183DecodedLog extends Erc8183EventRef {
  readonly block: bigint;
  readonly index: bigint;
  readonly blockHash: string;
  readonly transactionIndex: bigint;
  readonly event: Erc8183DecodedEvent;
}

export class Erc8183LogDecodeError extends Error {
  constructor(readonly detail: string) {
    super(`ERC-8183 log malformed: ${detail}`);
    this.name = "Erc8183LogDecodeError";
  }
}

const HEX_QUANTITY = /^0x(0|[1-9a-fA-F][0-9a-fA-F]{0,63})$/u;
const HASH32 = /^0x[0-9a-fA-F]{64}$/u;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/u;
const DECIMAL = /^(0|[1-9][0-9]{0,77})$/u;
const DATA = /^0x(?:[0-9a-fA-F]{64})*$/u;
const MAX_UINT256 = (1n << 256n) - 1n;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const NATIVE_SCALE = 1_000_000_000_000n;

function quantity(value: unknown, field: string): bigint {
  if (typeof value !== "string" || !HEX_QUANTITY.test(value)) throw new Erc8183LogDecodeError(`${field}:quantity`);
  return BigInt(value);
}

function decimal(value: unknown, field: string): bigint {
  if (typeof value !== "string" || !DECIMAL.test(value)) throw new Erc8183LogDecodeError(`${field}:decimal`);
  const parsed = BigInt(value);
  if (parsed > MAX_UINT256) throw new Erc8183LogDecodeError(`${field}:range`);
  return parsed;
}

function hash32(value: unknown, field: string): string {
  if (typeof value !== "string" || !HASH32.test(value)) throw new Erc8183LogDecodeError(`${field}:hash`);
  return value.toLowerCase();
}

function wordAddress(word: string, field: string): string {
  if (!/^0{24}/u.test(word)) throw new Erc8183LogDecodeError(`${field}:address_padding`);
  return `0x${word.slice(24)}`;
}

/** Decodes one RPC log against the manifest. Unknown topics from the proxy are malformed, never guessed. */
export function decodeErc8183Log(manifest: Erc8183DeploymentManifest, log: Erc8183RawLog): Erc8183DecodedLog {
  if (typeof log !== "object" || log === null) throw new Erc8183LogDecodeError("log:not_object");
  if (typeof log.address !== "string" || !ADDRESS.test(log.address)) throw new Erc8183LogDecodeError("address");
  if (!Array.isArray(log.topics) || log.topics.length > 4) throw new Erc8183LogDecodeError("topics");
  if (typeof log.data !== "string" || !DATA.test(log.data)) throw new Erc8183LogDecodeError("data");
  const topics = log.topics.map((topic, index) => hash32(topic, `topics[${index}]`));
  const words = (log.data.slice(2).toLowerCase().match(/.{64}/gu) ?? []);
  const ref = {
    block: quantity(log.blockNumber, "blockNumber"),
    index: quantity(log.logIndex, "logIndex"),
    transactionIndex: quantity(log.transactionIndex, "transactionIndex"),
    blockHash: hash32(log.blockHash, "blockHash"),
    transactionHash: hash32(log.transactionHash, "transactionHash"),
  };
  const base = { ...ref, blockNumber: ref.block.toString(), logIndex: ref.index.toString() };
  const address = log.address.toLowerCase();
  const topic0 = topics[0];
  const events = manifest.events;

  const shape = (topicCount: number, wordCount: number, name: string) => {
    if (topics.length !== topicCount || words.length !== wordCount) throw new Erc8183LogDecodeError(`${name}:shape`);
  };
  const t = (index: number) => (topics[index] as string).slice(2);
  const w = (index: number) => words[index] as string;
  const uint = (hex: string) => BigInt(`0x${hex}`);

  if (address === manifest.paymentToken.address || address === manifest.paymentToken.systemEmitter) {
    const representation = address === manifest.paymentToken.address ? "erc20" : "native";
    if (topic0 === events.Transfer.topic0) {
      shape(3, 1, "Transfer");
      return { ...base, event: { name: "Transfer", representation, from: wordAddress(t(1), "from"), to: wordAddress(t(2), "to"), value: uint(w(0)) } };
    }
    if (topic0 === events.Approval.topic0 && representation === "erc20") {
      shape(3, 1, "Approval");
      return { ...base, event: { name: "Approval", owner: wordAddress(t(1), "owner"), spender: wordAddress(t(2), "spender"), value: uint(w(0)) } };
    }
    return { ...base, event: { name: "Ignored" } };
  }
  if (address !== manifest.proxy.address) throw new Erc8183LogDecodeError("address:not_manifest_contract");

  switch (topic0) {
    case events.JobCreated.topic0:
      shape(4, 3, "JobCreated");
      return { ...base, event: { name: "JobCreated", jobId: uint(t(1)), client: wordAddress(t(2), "client"),
        provider: wordAddress(t(3), "provider"), evaluator: wordAddress(w(0), "evaluator"), expiredAt: uint(w(1)),
        hook: wordAddress(w(2), "hook") } };
    case events.ProviderSet.topic0:
      shape(3, 0, "ProviderSet");
      return { ...base, event: { name: "ProviderSet", jobId: uint(t(1)), provider: wordAddress(t(2), "provider") } };
    case events.BudgetSet.topic0:
      shape(2, 1, "BudgetSet");
      return { ...base, event: { name: "BudgetSet", jobId: uint(t(1)), amount: uint(w(0)) } };
    case events.JobFunded.topic0:
      shape(3, 1, "JobFunded");
      return { ...base, event: { name: "JobFunded", jobId: uint(t(1)), client: wordAddress(t(2), "client"), amount: uint(w(0)) } };
    case events.JobSubmitted.topic0:
      shape(3, 1, "JobSubmitted");
      return { ...base, event: { name: "JobSubmitted", jobId: uint(t(1)), provider: wordAddress(t(2), "provider"), deliverable: `0x${w(0)}` } };
    case events.JobCompleted.topic0:
      shape(3, 1, "JobCompleted");
      return { ...base, event: { name: "JobCompleted", jobId: uint(t(1)), evaluator: wordAddress(t(2), "evaluator"), reason: `0x${w(0)}` } };
    case events.JobRejected.topic0:
      shape(3, 1, "JobRejected");
      return { ...base, event: { name: "JobRejected", jobId: uint(t(1)), rejector: wordAddress(t(2), "rejector"), reason: `0x${w(0)}` } };
    case events.JobExpired.topic0:
      shape(2, 0, "JobExpired");
      return { ...base, event: { name: "JobExpired", jobId: uint(t(1)) } };
    case events.PaymentReleased.topic0:
      shape(3, 1, "PaymentReleased");
      return { ...base, event: { name: "PaymentReleased", jobId: uint(t(1)), provider: wordAddress(t(2), "provider"), amount: uint(w(0)) } };
    case events.EvaluatorFeePaid.topic0:
      shape(3, 1, "EvaluatorFeePaid");
      return { ...base, event: { name: "EvaluatorFeePaid", jobId: uint(t(1)), evaluator: wordAddress(t(2), "evaluator"), amount: uint(w(0)) } };
    case events.Refunded.topic0:
      shape(3, 1, "Refunded");
      return { ...base, event: { name: "Refunded", jobId: uint(t(1)), client: wordAddress(t(2), "client"), amount: uint(w(0)) } };
    case events.HookWhitelistUpdated.topic0: {
      shape(2, 1, "HookWhitelistUpdated");
      const flag = uint(w(0));
      if (flag > 1n) throw new Erc8183LogDecodeError("HookWhitelistUpdated:bool");
      return { ...base, event: { name: "HookWhitelistUpdated", hook: wordAddress(t(1), "hook"), status: flag === 1n } };
    }
    case events.Upgraded.topic0:
      shape(2, 0, "Upgraded");
      return { ...base, event: { name: "Upgraded", implementation: wordAddress(t(1), "implementation") } };
    default:
      // Includes the ERC's non-deployed five-argument JobCreated topic (C5) and any
      // RoleGranted/RoleRevoked governance log: never guessed, always held.
      throw new Erc8183LogDecodeError(`topic0:not_in_manifest:${topic0 ?? "none"}`);
  }
}

// ───────────────────────── projection ─────────────────────────

interface MutableJob {
  jobId: bigint;
  status: Erc8183MirrorStatus | null;
  unknown: Erc8183UnknownReason | null;
  asOf: bigint;
  client: string | null;
  provider: string | null;
  evaluator: string | null;
  hook: string | null;
  expiredAt: bigint | null;
  budget: bigint;
  explicitlySet: boolean;
  history: (Erc8183EventRef & { amount: string; afterClientApproval: boolean })[];
  funded: (Erc8183EventRef & { amount: string }) | null;
  fundedAmount: bigint;
  deliverable: (Erc8183EventRef & { digest: string }) | null;
  completion: Erc8183JobProjection["completion"];
  rejection: Erc8183JobProjection["rejection"];
  expiry: Erc8183JobProjection["expiry"];
  refund: Erc8183RefundFact;
  escrowed: bigint;
  spent: bigint;
  returned: bigint;
  heldUnknown: bigint;
  flags: Erc8183RiskFlag[];
  unfinalized: Erc8183UnfinalizedFact[];
}

const TERMINAL = new Set<Erc8183MirrorStatus>(ERC8183_TERMINAL_STATUSES);

function refOf(log: Erc8183DecodedLog): Erc8183EventRef {
  return { blockNumber: log.blockNumber, transactionHash: log.transactionHash, logIndex: log.logIndex };
}

function compareLogs(left: Erc8183DecodedLog, right: Erc8183DecodedLog): number {
  if (left.block !== right.block) return left.block < right.block ? -1 : 1;
  if (left.index !== right.index) return left.index < right.index ? -1 : 1;
  return 0;
}

function sameLog(left: Erc8183RawLog, right: Erc8183RawLog): boolean {
  return left.address.toLowerCase() === right.address.toLowerCase() && left.data.toLowerCase() === right.data.toLowerCase() &&
    left.blockHash.toLowerCase() === right.blockHash.toLowerCase() &&
    left.transactionHash.toLowerCase() === right.transactionHash.toLowerCase() &&
    left.topics.length === right.topics.length && left.topics.every((topic, index) => topic.toLowerCase() === right.topics[index]?.toLowerCase());
}

/**
 * Projects ERC-8183 job state from scanned log pages. Pure and deterministic.
 * Throws only for an unknown network or a malformed finalized anchor / start
 * block (caller configuration errors); every source problem becomes a hold.
 */
export function projectErc8183JobMirror(input: Erc8183MirrorInput): Erc8183MirrorProjection {
  const manifest = resolveErc8183Deployment(input.network);
  if (input.finalized?.tag !== "finalized") throw new Erc8183LogDecodeError("finalized:tag");
  const startBlock = decimal(input.startBlock, "startBlock");
  const finalizedBlock = decimal(input.finalized.number, "finalized.number");
  const finalizedHash = hash32(input.finalized.hash, "finalized.hash");
  const finalizedTimestamp = decimal(input.finalized.timestamp, "finalized.timestamp");
  const maxRange = BigInt(manifest.observation.maxLogRangeBlocks);

  const holds: Erc8183Hold[] = [];
  const hold = (kind: Erc8183HoldKind, from: bigint, to: bigint, detail: string) =>
    holds.push({ kind, fromBlock: from.toString(), toBlock: to.toString(), detail });

  // Block metadata: hash per number, conflicts are holds from that block.
  const blockMeta = new Map<bigint, { hash: string; timestamp: bigint }>();
  let stopAt: bigint | null = null; // first block that must not be applied
  const stop = (block: bigint) => { if (stopAt === null || block < stopAt) stopAt = block; };
  blockMeta.set(finalizedBlock, { hash: finalizedHash, timestamp: finalizedTimestamp });
  for (const meta of input.blocks ?? []) {
    let number: bigint; let hashValue: string; let timestamp: bigint;
    try {
      number = decimal(meta.number, "blocks.number");
      hashValue = hash32(meta.hash, "blocks.hash");
      timestamp = decimal(meta.timestamp, "blocks.timestamp");
    } catch {
      continue; // Unusable metadata only disables optional deadline checks.
    }
    const existing = blockMeta.get(number);
    if (existing !== undefined && (existing.hash !== hashValue || existing.timestamp !== timestamp)) {
      hold("block_hash_conflict", number, number, "block metadata disagrees");
      stop(number);
      continue;
    }
    blockMeta.set(number, { hash: hashValue, timestamp });
  }

  // Pages: validate, sort by range start, and walk contiguously.
  interface ParsedPage { from: bigint; to: bigint; page: Erc8183LogPage; ordinal: number }
  const parsedPages: ParsedPage[] = [];
  input.pages.forEach((page, ordinal) => {
    let from: bigint; let to: bigint;
    try {
      from = decimal(page.fromBlock, "page.fromBlock");
      to = decimal(page.toBlock, "page.toBlock");
    } catch {
      holds.push({ kind: "page_range_invalid", fromBlock: String(page.fromBlock), toBlock: String(page.toBlock), detail: `page ${ordinal}` });
      return;
    }
    if (to < from || to - from + 1n > maxRange) {
      hold("page_range_invalid", from, to, `page ${ordinal} exceeds ${maxRange} blocks or is inverted`);
      return;
    }
    parsedPages.push({ from, to, page, ordinal });
  });
  parsedPages.sort((left, right) => (left.from === right.from ? left.ordinal - right.ordinal : left.from < right.from ? -1 : 1));

  const accepted = new Map<string, { raw: Erc8183RawLog; decoded: Erc8183DecodedLog }>();
  let cursor = startBlock; // next block that still needs coverage
  for (const { from, to, page, ordinal } of parsedPages) {
    if (to < cursor && page.outcome !== "complete") continue; // a failed retry of already-covered blocks adds nothing
    if (from > cursor) {
      hold("gap", cursor, from - 1n, `no page covers blocks before page ${ordinal}`);
      stop(cursor);
      break;
    }
    if (page.outcome !== "complete") {
      hold("page_failed", from, to, `page ${ordinal} did not complete`);
      stop(cursor);
      break;
    }
    let pageOk = true;
    let previous: Erc8183DecodedLog | null = null;
    for (const raw of page.logs) {
      let decoded: Erc8183DecodedLog;
      try {
        decoded = decodeErc8183Log(manifest, raw);
      } catch (error) {
        const detail = error instanceof Erc8183LogDecodeError ? error.detail : "unknown";
        let block = from;
        try { block = quantity(raw?.blockNumber, "blockNumber"); } catch { /* keep page start */ }
        hold("log_malformed", block, block, detail);
        stop(block > cursor ? block : cursor);
        pageOk = false;
        break;
      }
      if (raw.removed === true) {
        hold("log_removed", decoded.block, decoded.block, `log ${decoded.logIndex} marked removed`);
        stop(decoded.block);
        pageOk = false;
        break;
      }
      if (decoded.block < from || decoded.block > to) {
        hold("log_outside_page", decoded.block, decoded.block, `page ${ordinal}`);
        stop(from > cursor ? from : cursor);
        pageOk = false;
        break;
      }
      if (previous !== null && compareLogs(previous, decoded) >= 0) {
        hold("page_out_of_order", from, to, `page ${ordinal} log ${decoded.logIndex} at block ${decoded.blockNumber}`);
        stop(from > cursor ? from : cursor);
        pageOk = false;
        break;
      }
      previous = decoded;
      const meta = blockMeta.get(decoded.block);
      if (meta !== undefined && meta.hash !== decoded.blockHash) {
        hold("block_hash_conflict", decoded.block, decoded.block, "log block hash disagrees with block metadata");
        stop(decoded.block);
        pageOk = false;
        break;
      }
      blockMeta.set(decoded.block, { hash: decoded.blockHash, timestamp: meta?.timestamp ?? -1n });
      const key = `${decoded.block}:${decoded.index}`;
      const existing = accepted.get(key);
      if (existing !== undefined) {
        if (!sameLog(existing.raw, raw)) {
          hold("log_conflict", decoded.block, decoded.block, `log ${decoded.logIndex} differs between overlapping pages`);
          stop(decoded.block);
          pageOk = false;
          break;
        }
        continue;
      }
      accepted.set(key, { raw, decoded });
    }
    if (!pageOk) break;
    if (to + 1n > cursor) cursor = to + 1n;
  }
  if (stopAt === null && cursor <= finalizedBlock) {
    hold("gap", cursor, finalizedBlock, "finalized blocks not yet scanned");
  }

  const ordered = [...accepted.values()].map((entry) => entry.decoded).sort(compareLogs);
  // The applied, trusted prefix: within coverage, before any hold, at or below finalized.
  const appliedLimit = (() => {
    let limit = cursor - 1n;
    if (stopAt !== null && stopAt - 1n < limit) limit = stopAt - 1n;
    return limit;
  })();

  const jobs = new Map<bigint, MutableJob>();
  const unfinalized: Erc8183UnfinalizedFact[] = [];
  const approvals = new Map<string, bigint>(); // client -> last approval block (proxy spender, value > 0)
  const expectedSlot = manifest.implementation.address;

  const ensureJob = (jobId: bigint, log: Erc8183DecodedLog): MutableJob => {
    let job = jobs.get(jobId);
    if (job === undefined) {
      job = {
        jobId, status: null, unknown: "created_before_mirror_start", asOf: log.block, client: null, provider: null,
        evaluator: null, hook: null, expiredAt: null, budget: 0n, explicitlySet: false, history: [], funded: null,
        fundedAmount: 0n, deliverable: null, completion: null, rejection: null, expiry: null,
        refund: { state: "not_applicable" }, escrowed: 0n, spent: 0n, returned: 0n, heldUnknown: 0n, flags: [], unfinalized: [],
      };
      job.flags.push({ kind: "job_created_before_mirror_start", ...refOf(log), detail: `${log.event.name} without JobCreated` });
      jobs.set(jobId, job);
    }
    return job;
  };
  const flag = (job: MutableJob, kind: Erc8183RiskFlagKind, log: Erc8183DecodedLog, detail: string) =>
    job.flags.push({ kind, ...refOf(log), detail });
  const conflict = (job: MutableJob, log: Erc8183DecodedLog, detail: string) => {
    flag(job, "job_event_conflict", log, detail);
    job.unknown = "event_conflict";
    job.asOf = log.block;
  };
  const timestampAt = (block: bigint): bigint | null => {
    const value = blockMeta.get(block)?.timestamp;
    return value === undefined || value < 0n ? null : value;
  };

  // Group applied logs by transaction to pair Refunded/EvaluatorFeePaid/PaymentReleased and transfers.
  const applied = ordered.filter((log) => log.block <= appliedLimit);
  for (const log of ordered) {
    if (log.block > appliedLimit && log.block <= finalizedBlock) continue; // held behind a gap
    if (log.block > finalizedBlock && log.event.name !== "Ignored" && log.event.name !== "Transfer" && log.event.name !== "Approval") {
      const event = log.event;
      const jobId = "jobId" in event ? event.jobId.toString() : null;
      const fact = { jobId, event: event.name, ...refOf(log) };
      unfinalized.push(fact);
    }
  }
  const finalizedApplied = applied.filter((log) => log.block <= finalizedBlock);

  const transactions: Erc8183DecodedLog[][] = [];
  for (const log of finalizedApplied) {
    const last = transactions.at(-1);
    if (last !== undefined && last[0]?.transactionHash === log.transactionHash) last.push(log);
    else transactions.push([log]);
  }

  let implementationStop: bigint | null = null;
  txLoop: for (const tx of transactions) {
    // Transfer corroboration: ERC-20 is authoritative; native mirror must pair and is never added.
    const erc20 = tx.filter((log) => log.event.name === "Transfer" && log.event.representation === "erc20");
    const native = tx.filter((log) => log.event.name === "Transfer" && log.event.representation === "native");
    const unmatchedErc20 = [...erc20]; // corroboration pool: each ERC-20 transfer backs at most one ACP amount
    const pairing = [...erc20]; // separate pool so pairing never consumes corroboration entries
    const nativeMismatch: Erc8183DecodedLog[] = [];
    for (const mirror of native) {
      if (mirror.event.name !== "Transfer") continue;
      const { from, to, value } = mirror.event;
      const at = pairing.findIndex((candidate) => candidate.event.name === "Transfer" && candidate.event.from === from &&
        candidate.event.to === to && candidate.event.value * NATIVE_SCALE === value);
      if (at === -1) nativeMismatch.push(mirror);
      else pairing.splice(at, 1);
    }

    for (const [position, log] of tx.entries()) {
      const event = log.event;
      if (event.name === "Ignored" || event.name === "Transfer") continue;
      if (event.name === "Approval") {
        if (event.spender === manifest.proxy.address && event.value > 0n) approvals.set(event.owner, log.block);
        if (event.spender === manifest.proxy.address && event.value === 0n) approvals.delete(event.owner);
        continue;
      }
      if (event.name === "Upgraded") {
        if (event.implementation !== expectedSlot) {
          hold("implementation_changed", log.block, finalizedBlock, `Upgraded to ${event.implementation}`);
          implementationStop = log.block;
          break txLoop;
        }
        continue;
      }
      if (event.name === "HookWhitelistUpdated") continue; // governance fact; jobs with non-zero hooks are flagged at creation
      const later = tx.slice(position + 1).filter((candidate) => "jobId" in candidate.event && candidate.event.jobId === event.jobId);
      const earlier = tx.slice(0, position).filter((candidate) => "jobId" in candidate.event && candidate.event.jobId === event.jobId);

      if (event.name === "JobCreated") {
        const existing = jobs.get(event.jobId);
        if (existing !== undefined) { conflict(existing, log, "duplicate JobCreated"); continue; }
        const job = ensureJob(event.jobId, log);
        job.flags.length = 0;
        Object.assign(job, { status: "Open", unknown: null, asOf: log.block, client: event.client, provider: event.provider,
          evaluator: event.evaluator, hook: event.hook, expiredAt: event.expiredAt });
        if (event.evaluator === ZERO_ADDRESS) conflict(job, log, "JobCreated with zero evaluator");
        if (event.hook !== ZERO_ADDRESS) flag(job, "nonzero_hook", log, `hook ${event.hook} is unsupported`);
        continue;
      }

      const job = ensureJob(event.jobId, log);
      if (job.unknown !== null) { job.asOf = log.block; continue; }
      const status = job.status as Erc8183MirrorStatus;
      job.asOf = log.block;

      switch (event.name) {
        case "ProviderSet":
          if (status !== "Open" || job.provider !== ZERO_ADDRESS || event.provider === ZERO_ADDRESS) {
            conflict(job, log, `ProviderSet from ${status}`);
          } else job.provider = event.provider;
          break;
        case "BudgetSet": {
          // C2: provider only, repeatable, any amount while Open.
          if (status !== "Open" || job.provider === ZERO_ADDRESS) { conflict(job, log, `BudgetSet from ${status}`); break; }
          const approvalBlock = job.client === null ? undefined : approvals.get(job.client);
          const afterClientApproval = approvalBlock !== undefined;
          if (afterClientApproval && (!job.explicitlySet || job.budget !== event.amount)) {
            flag(job, "budget_changed_after_approval", log,
              `budget ${job.budget} -> ${event.amount} after client approval at block ${approvalBlock}; fund pulls the current budget (C1/S1)`);
          }
          job.budget = event.amount;
          job.explicitlySet = true;
          job.history.push({ ...refOf(log), amount: event.amount.toString(), afterClientApproval });
          break;
        }
        case "JobFunded": {
          if (status !== "Open" || job.provider === ZERO_ADDRESS || event.client !== job.client || event.amount !== job.budget) {
            conflict(job, log, `JobFunded from ${status} or amount/client mismatch`);
            break;
          }
          const at = timestampAt(log.block);
          if (at !== null && job.expiredAt !== null && at >= job.expiredAt) { conflict(job, log, "JobFunded at or after deadline"); break; }
          const agreed = input.agreedBudgets?.[job.jobId.toString()];
          if (agreed !== undefined && (!DECIMAL.test(agreed) || BigInt(agreed) !== event.amount)) {
            flag(job, "funded_amount_differs_from_agreed", log, `funded ${event.amount}, agreed ${agreed}`);
          }
          if (event.amount > 0n) corroborate(job, log, unmatchedErc20, job.client, manifest.proxy.address, event.amount);
          job.status = "Funded";
          job.funded = { ...refOf(log), amount: event.amount.toString() };
          job.fundedAmount = event.amount;
          job.escrowed = event.amount;
          break;
        }
        case "JobSubmitted":
          if (event.provider !== job.provider) { conflict(job, log, "JobSubmitted by non-provider"); break; }
          if (status === "Funded") job.status = "Submitted";
          else if (status === "Open" && job.budget === 0n) {
            flag(job, "submitted_from_open_zero_budget", log, "C4: submit from Open with zero budget");
            job.status = "Submitted";
          } else { conflict(job, log, `JobSubmitted from ${status}`); break; }
          job.deliverable = { ...refOf(log), digest: event.deliverable };
          break;
        case "EvaluatorFeePaid":
          if (!later.some((candidate) => candidate.event.name === "JobCompleted")) conflict(job, log, "EvaluatorFeePaid without JobCompleted");
          break;
        case "JobCompleted": {
          if (status !== "Submitted" || event.evaluator !== job.evaluator) { conflict(job, log, `JobCompleted from ${status}`); break; }
          const fee = earlier.find((candidate) => candidate.event.name === "EvaluatorFeePaid");
          const evaluatorFee = fee?.event.name === "EvaluatorFeePaid" ? fee.event.amount : 0n;
          const release = later.find((candidate) => candidate.event.name === "PaymentReleased");
          const net = release?.event.name === "PaymentReleased" && release.event.provider === job.provider ? release.event.amount : null;
          job.status = "Completed";
          let platformFee: bigint | null = null;
          if (net === null) {
            flag(job, "payment_release_missing", log, "JobCompleted without matching PaymentReleased in the same transaction");
            job.heldUnknown = job.escrowed;
          } else if (net + evaluatorFee > job.fundedAmount) {
            conflict(job, log, "released amounts exceed funded amount");
            break;
          } else {
            platformFee = job.fundedAmount - net - evaluatorFee;
            job.spent = job.escrowed;
            if (net > 0n && job.provider !== null) corroborate(job, log, unmatchedErc20, manifest.proxy.address, job.provider, net);
          }
          job.escrowed = 0n;
          job.completion = { ...refOf(log), reason: event.reason, providerNet: net?.toString() ?? null,
            evaluatorFee: evaluatorFee.toString(), platformFee: platformFee?.toString() ?? null };
          break;
        }
        case "PaymentReleased":
          if (!earlier.some((candidate) => candidate.event.name === "JobCompleted")) conflict(job, log, "PaymentReleased without JobCompleted");
          break;
        case "Refunded": {
          const paired = later.find((candidate) => candidate.event.name === "JobRejected" || candidate.event.name === "JobExpired");
          if (paired === undefined) {
            flag(job, "refund_unpaired", log, "Refunded without JobRejected/JobExpired in the same transaction");
            job.refund = { state: "unknown", amount: event.amount.toString(), reason: "unpaired_refund" };
            job.heldUnknown = job.escrowed > 0n ? job.escrowed : event.amount;
            job.escrowed = 0n;
            job.unknown = "refund_unpaired";
          }
          break;
        }
        case "JobRejected": {
          const refunded = earlier.find((candidate) => candidate.event.name === "Refunded");
          if (status === "Open") {
            if (event.rejector !== job.client || refunded !== undefined) { conflict(job, log, "Open rejection by non-client or with refund"); break; }
            job.refund = { state: "not_applicable" };
          } else if (status === "Funded" || status === "Submitted") {
            if (event.rejector !== job.evaluator) { conflict(job, log, "Funded/Submitted rejection by non-evaluator"); break; }
            const at = timestampAt(log.block);
            if (at !== null && job.expiredAt !== null && at >= job.expiredAt) {
              flag(job, "rejected_after_deadline", log, "evaluator rejected after expiredAt (no deadline check on reject)");
            }
            if (!settleRefund(job, log, refunded, "rejected", unmatchedErc20)) break;
          } else { conflict(job, log, `JobRejected from ${status}`); break; }
          job.rejection = { ...refOf(log), rejector: event.rejector, reason: event.reason, from: status };
          job.status = "Rejected";
          break;
        }
        case "JobExpired": {
          if (status !== "Funded" && status !== "Submitted") { conflict(job, log, `JobExpired from ${status}`); break; }
          const at = timestampAt(log.block);
          if (at !== null && job.expiredAt !== null && at < job.expiredAt) { conflict(job, log, "JobExpired before expiredAt"); break; }
          const refunded = earlier.find((candidate) => candidate.event.name === "Refunded");
          if (!settleRefund(job, log, refunded, "expired", unmatchedErc20)) break;
          job.expiry = { ...refOf(log), from: status };
          job.status = "Expired";
          break;
        }
      }
    }

    const touched = new Set(tx.flatMap((log) => ("jobId" in log.event ? [log.event.jobId] : [])));
    for (const mirror of nativeMismatch) {
      for (const jobId of touched) {
        const job = jobs.get(jobId);
        if (job !== undefined) flag(job, "transfer_representation_mismatch", mirror, "native 18-decimal Transfer has no matching ERC-20 Transfer");
      }
    }
  }

  function corroborate(job: MutableJob, log: Erc8183DecodedLog, pool: Erc8183DecodedLog[], from: string | null, to: string, amount: bigint) {
    const tx = transactions.find((candidate) => candidate[0]?.transactionHash === log.transactionHash) ?? [];
    if (!tx.some((entry) => entry.event.name === "Transfer")) return; // transfers not in this scan: corroboration not observed
    const at = pool.findIndex((candidate) => candidate.event.name === "Transfer" && candidate.event.from === from &&
      candidate.event.to === to && candidate.event.value === amount);
    if (at === -1) flag(job, "transfer_representation_mismatch", log, `no ERC-20 Transfer of ${amount} ${from} -> ${to}`);
    else pool.splice(at, 1); // consumed once; never double counted
  }

  function settleRefund(job: MutableJob, log: Erc8183DecodedLog, refunded: Erc8183DecodedLog | undefined,
    cause: "rejected" | "expired", pool: Erc8183DecodedLog[]): boolean {
    if (refunded?.event.name === "Refunded") {
      if (refunded.event.client !== job.client || refunded.event.amount !== job.fundedAmount || job.fundedAmount === 0n) {
        conflict(job, log, "Refunded amount/client disagrees with funding");
        return false;
      }
      if (job.client !== null) corroborate(job, refunded, pool, manifest.proxy.address, job.client, refunded.event.amount);
      job.refund = { state: "refunded", amount: refunded.event.amount.toString(), cause, transactionHash: log.transactionHash };
      job.returned = refunded.event.amount;
      job.escrowed = 0n;
      return true;
    }
    if (job.fundedAmount === 0n && job.budget === 0n) {
      job.refund = { state: "none_zero_budget", cause };
      return true;
    }
    // Source always emits Refunded when budget > 0; absence is held, not assumed.
    job.refund = { state: "unknown", amount: null, reason: "missing_refund_event" };
    job.heldUnknown = job.escrowed;
    job.escrowed = 0n;
    flag(job, "refund_unpaired", log, `Job${cause === "rejected" ? "Rejected" : "Expired"} without Refunded for a funded budget`);
    job.unknown = "refund_unpaired";
    return false;
  }

  const effectiveApplied = implementationStop === null ? appliedLimit
    : (implementationStop - 1n < appliedLimit ? implementationStop - 1n : appliedLimit);
  const appliedThrough = effectiveApplied > finalizedBlock ? finalizedBlock : effectiveApplied;

  // Attach unfinalized facts to jobs, without touching status.
  for (const fact of unfinalized) {
    if (fact.jobId === null) continue;
    const job = jobs.get(BigInt(fact.jobId));
    if (job !== undefined) job.unfinalized.push(fact);
  }

  const projected = [...jobs.values()]
    .sort((left, right) => (left.jobId < right.jobId ? -1 : left.jobId > right.jobId ? 1 : 0))
    .map((job): Erc8183JobProjection => {
      const deadlineReached = job.expiredAt === null ? null : finalizedTimestamp >= job.expiredAt;
      let observation: Erc8183JobProjection["derived"]["observation"] = null;
      if (job.unknown === null && deadlineReached === true) {
        if (job.status === "Funded" || job.status === "Submitted") observation = "deadline_reached_unclaimed";
        else if (job.status === "Open") observation = "open_past_deadline";
      }
      const status: Erc8183JobStatusFact = job.unknown === null && job.status !== null
        ? { kind: "known", status: job.status, terminal: TERMINAL.has(job.status), asOfBlock: job.asOf > appliedThrough ? job.asOf.toString() : appliedThrough.toString() }
        : { kind: "unknown", reason: job.unknown ?? "created_before_mirror_start", lastKnown: job.status, asOfBlock: job.asOf.toString() };
      return deepFreeze({
        jobId: job.jobId.toString(),
        canonicalId: erc8183CanonicalJobId(manifest, job.jobId),
        status,
        client: job.client,
        provider: job.provider,
        evaluator: job.evaluator,
        hook: job.hook,
        expiredAt: job.expiredAt?.toString() ?? null,
        budget: { current: job.budget.toString(), explicitlySet: job.explicitlySet, history: job.history },
        funded: job.funded,
        deliverable: job.deliverable,
        completion: job.completion,
        rejection: job.rejection,
        expiry: job.expiry,
        refund: job.refund,
        money: { escrowed: job.escrowed.toString(), spent: job.spent.toString(), returned: job.returned.toString(),
          heldUnknown: job.heldUnknown.toString() },
        derived: { deadlineReachedAtFinalized: deadlineReached, observation },
        flags: job.flags,
        unfinalized: job.unfinalized,
      });
    });

  const complete = holds.length === 0;
  return deepFreeze({
    schemaVersion: "openarc.erc8183-job-mirror.v1",
    network: manifest.caip2,
    contract: manifest.proxy.address,
    finalized: { blockNumber: finalizedBlock.toString(), blockHash: finalizedHash, timestamp: finalizedTimestamp.toString() },
    coverage: {
      startBlock: startBlock.toString(),
      appliedThroughBlock: appliedThrough < startBlock ? null : appliedThrough.toString(),
      finalizedBlock: finalizedBlock.toString(),
      complete,
    },
    holds,
    jobs: projected,
    unfinalized,
  });
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

/** Runtime guard: only the six deployed statuses exist; accepted/settled/disputed are rejected. */
export function parseErc8183MirrorStatus(value: unknown): Erc8183MirrorStatus {
  const statuses: readonly string[] = ["Open", "Funded", "Submitted", "Completed", "Rejected", "Expired"];
  if (typeof value !== "string" || !statuses.includes(value)) {
    throw new Erc8183LogDecodeError(`status:not_deployed:${String(value)}`);
  }
  return value as Erc8183MirrorStatus;
}
