import { ARC_ERC8183, ARC_TESTNET } from "../network.js";

/**
 * P07-01 — pinned ERC-8183 deployment manifest.
 *
 * One reviewed Arc Testnet reference deployment only. There is deliberately no
 * mainnet entry and no default: unknown or missing chain ids always throw.
 * Every value below is a literal copied from PORT-07 contract research
 * (the PORT-07 ERC-8183 contract research) or the verified
 * deployed source whose SHA-256 is pinned here. Topics and selectors are
 * literals; the test suite recomputes each one with keccak-256 so this runtime
 * module carries no hashing dependency.
 */

export class Erc8183ManifestError extends Error {
  readonly code: "invalid_config" | "unknown_network";
  readonly issues: readonly string[];

  constructor(code: Erc8183ManifestError["code"], issues: readonly string[]) {
    super(`ERC-8183 manifest ${code}: ${issues.join(", ")}`);
    this.name = "Erc8183ManifestError";
    this.code = code;
    this.issues = Object.freeze([...issues]);
  }
}

export const ERC8183_ARC_TESTNET_CAIP2 = "eip155:5042002" as const;
export type Erc8183NetworkId = typeof ERC8183_ARC_TESTNET_CAIP2;

/** Deployed `enum JobStatus` (source lines 19–26), uint8 order preserved. */
export const ERC8183_DEPLOYED_STATUSES = ["Open", "Funded", "Submitted", "Completed", "Rejected", "Expired"] as const;
export type Erc8183DeployedStatus = (typeof ERC8183_DEPLOYED_STATUSES)[number];
export const ERC8183_TERMINAL_STATUSES = ["Completed", "Rejected", "Expired"] as const satisfies readonly Erc8183DeployedStatus[];

export interface Erc8183EventDefinition {
  readonly name: string;
  /** Canonical signature string; topic0 = keccak256(signature). */
  readonly signature: string;
  readonly topic0: `0x${string}`;
  /** Emitting contract role within this manifest. */
  readonly emitter: "proxy" | "usdc";
  /** Parameter layout from the verified source, in declaration order. */
  readonly params: readonly { readonly name: string; readonly type: "uint256" | "address" | "bytes32" | "bool"; readonly indexed: boolean }[];
}

export interface Erc8183FunctionDefinition {
  readonly name: string;
  readonly signature: string;
  readonly selector: `0x${string}`;
  readonly caller: "anyone" | "client" | "provider" | "evaluator" | "client_or_evaluator" | "admin" | "view";
}

const PINNED = Object.freeze({
  chainId: 5042002,
  chainIdHex: "0x4cef52",
  proxy: "0x0747eef0706327138c69792bf28cd525089e4583",
  implementation: "0xa316fd02827242d537f84730f8a37d0ba5fd351a",
  implementationSlot: "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
  sourceSha256: "a16ae3290855910a4c06a59fa691d1d2b56b534e744f15b6f73a6a06ccb1bec4",
  usdc: "0x3600000000000000000000000000000000000000",
  usdcSystemEmitter: "0xfffffffffffffffffffffffffffffffffffffffe",
  transferTopic: "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
} as const);

const u = (name: string) => ({ name, type: "uint256", indexed: false }) as const;
const ui = (name: string) => ({ name, type: "uint256", indexed: true }) as const;
const a = (name: string) => ({ name, type: "address", indexed: false }) as const;
const ai = (name: string) => ({ name, type: "address", indexed: true }) as const;
const b32 = (name: string) => ({ name, type: "bytes32", indexed: false }) as const;

/** Deployed event topics (§6 item 3), layout from verified source lines 50–64. */
const EVENTS = {
  JobCreated: { name: "JobCreated", signature: "JobCreated(uint256,address,address,address,uint256,address)",
    topic0: "0xb0f0239bfdd96453e24733e18bfc24b70d8fadf123dd977473518dd577ee79b9", emitter: "proxy",
    params: [ui("jobId"), ai("client"), ai("provider"), a("evaluator"), u("expiredAt"), a("hook")] },
  ProviderSet: { name: "ProviderSet", signature: "ProviderSet(uint256,address)",
    topic0: "0x9a87df076ea1725aba8ba29d32517ce37c9597d88cbf16ec6707892cc330ab69", emitter: "proxy",
    params: [ui("jobId"), ai("provider")] },
  BudgetSet: { name: "BudgetSet", signature: "BudgetSet(uint256,uint256)",
    topic0: "0x869e2577b006bf47ee981cf6fec2e25583548081c14b98deab587f77b5068038", emitter: "proxy",
    params: [ui("jobId"), u("amount")] },
  JobFunded: { name: "JobFunded", signature: "JobFunded(uint256,address,uint256)",
    topic0: "0xe3fbcc1ea1bdc559ec7f0347efde7655e58b5f45a30b0e4470a583c3ef5496b3", emitter: "proxy",
    params: [ui("jobId"), ai("client"), u("amount")] },
  JobSubmitted: { name: "JobSubmitted", signature: "JobSubmitted(uint256,address,bytes32)",
    topic0: "0x80c17db79857f338a6a6df68a6883ecc0ce78e2202fe61ed979733573f40538e", emitter: "proxy",
    params: [ui("jobId"), ai("provider"), b32("deliverable")] },
  JobCompleted: { name: "JobCompleted", signature: "JobCompleted(uint256,address,bytes32)",
    topic0: "0x0fd54bd364fa9e67f17b091aefe930932c09fe7651cf5ad02c71a418f3341444", emitter: "proxy",
    params: [ui("jobId"), ai("evaluator"), b32("reason")] },
  JobRejected: { name: "JobRejected", signature: "JobRejected(uint256,address,bytes32)",
    topic0: "0xae7362b1af91f4492868987b9c73990d780060811551b58728fbe96fd1bab275", emitter: "proxy",
    params: [ui("jobId"), ai("rejector"), b32("reason")] },
  JobExpired: { name: "JobExpired", signature: "JobExpired(uint256)",
    topic0: "0x97237956f8810192811e2c3f273fd02c5d6295206fdd9c62e6fe2bfc19ba9232", emitter: "proxy",
    params: [ui("jobId")] },
  PaymentReleased: { name: "PaymentReleased", signature: "PaymentReleased(uint256,address,uint256)",
    topic0: "0x21d71db5be59bb9fa133895586b7404307dd33fb93b16db09dc6f1d9d7d231b0", emitter: "proxy",
    params: [ui("jobId"), ai("provider"), u("amount")] },
  EvaluatorFeePaid: { name: "EvaluatorFeePaid", signature: "EvaluatorFeePaid(uint256,address,uint256)",
    topic0: "0x253dd534010ac976fa263caa123bae79b9c50292adf7ce67bdc5ec309f784e61", emitter: "proxy",
    params: [ui("jobId"), ai("evaluator"), u("amount")] },
  Refunded: { name: "Refunded", signature: "Refunded(uint256,address,uint256)",
    topic0: "0x7ca5472b7ea78c2c0141c5a12ee6d170cf4ce8ed06be3d22c8252ddfc7a6a2c4", emitter: "proxy",
    params: [ui("jobId"), ai("client"), u("amount")] },
  HookWhitelistUpdated: { name: "HookWhitelistUpdated", signature: "HookWhitelistUpdated(address,bool)",
    topic0: "0x7ee54953080e392a475a25b6acacb85417ca4e1953293c90934233ca13612510", emitter: "proxy",
    params: [ai("hook"), { name: "status", type: "bool", indexed: false }] },
  /** OpenZeppelin ERC1967Utils event, emitted by the proxy (D9). */
  Upgraded: { name: "Upgraded", signature: "Upgraded(address)",
    topic0: "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b", emitter: "proxy",
    params: [ai("implementation")] },
  /** ERC-20 events on the USDC interface; the native 18-decimal mirror shares topic0. */
  Transfer: { name: "Transfer", signature: "Transfer(address,address,uint256)",
    topic0: PINNED.transferTopic, emitter: "usdc", params: [ai("from"), ai("to"), u("value")] },
  Approval: { name: "Approval", signature: "Approval(address,address,uint256)",
    topic0: "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925", emitter: "usdc",
    params: [ai("owner"), ai("spender"), u("value")] },
} as const satisfies Record<string, Erc8183EventDefinition>;

export type Erc8183EventName = keyof typeof EVENTS;

/** Selectors from §2.2 plus the view/admin surface the manifest monitors. */
const FUNCTIONS = {
  createJob: { name: "createJob", signature: "createJob(address,address,uint256,string,address)", selector: "0x41528812", caller: "anyone" },
  setProvider: { name: "setProvider", signature: "setProvider(uint256,address)", selector: "0xd0fae591", caller: "client" },
  setBudget: { name: "setBudget", signature: "setBudget(uint256,uint256,bytes)", selector: "0xdd4ae9d4", caller: "provider" },
  fund: { name: "fund", signature: "fund(uint256,bytes)", selector: "0xe25ba707", caller: "client" },
  submit: { name: "submit", signature: "submit(uint256,bytes32,bytes)", selector: "0x9e63798d", caller: "provider" },
  complete: { name: "complete", signature: "complete(uint256,bytes32,bytes)", selector: "0xd75bbdf3", caller: "evaluator" },
  reject: { name: "reject", signature: "reject(uint256,bytes32,bytes)", selector: "0x41dd26f5", caller: "client_or_evaluator" },
  claimRefund: { name: "claimRefund", signature: "claimRefund(uint256)", selector: "0x5b7baf64", caller: "anyone" },
  getJob: { name: "getJob", signature: "getJob(uint256)", selector: "0xbf22c457", caller: "view" },
  jobHasBudget: { name: "jobHasBudget", signature: "jobHasBudget(uint256)", selector: "0xfabc3329", caller: "view" },
  paymentToken: { name: "paymentToken", signature: "paymentToken()", selector: "0x3013ce29", caller: "view" },
  platformFeeBP: { name: "platformFeeBP", signature: "platformFeeBP()", selector: "0xff96092a", caller: "view" },
  evaluatorFeeBP: { name: "evaluatorFeeBP", signature: "evaluatorFeeBP()", selector: "0x2f0e31f4", caller: "view" },
  platformTreasury: { name: "platformTreasury", signature: "platformTreasury()", selector: "0xe138818c", caller: "view" },
  jobCounter: { name: "jobCounter", signature: "jobCounter()", selector: "0x50355d76", caller: "view" },
  whitelistedHooks: { name: "whitelistedHooks", signature: "whitelistedHooks(address)", selector: "0x6d3b96c3", caller: "view" },
  hasRole: { name: "hasRole", signature: "hasRole(bytes32,address)", selector: "0x91d14854", caller: "view" },
  UPGRADE_INTERFACE_VERSION: { name: "UPGRADE_INTERFACE_VERSION", signature: "UPGRADE_INTERFACE_VERSION()", selector: "0xad3cb1cc", caller: "view" },
} as const satisfies Record<string, Erc8183FunctionDefinition>;

export type Erc8183FunctionName = keyof typeof FUNCTIONS;

/** Where the deployed contract differs from the ERC normative text (§2.3). */
export const ERC8183_DEPLOYED_DEVIATIONS = Object.freeze([
  { id: "C1", status: "conflicting", summary: "fund(jobId, optParams) has no expectedBudget front-running guard and no zero-budget check." },
  { id: "C2", status: "conflicting", summary: "setBudget is callable by the provider only, repeatedly, while Open." },
  { id: "C3", status: "conflicting", summary: "setProvider(jobId, provider) takes no optParams and is not hooked." },
  { id: "C4", status: "conflicting", summary: "submit is allowed from Open when budget == 0." },
  { id: "C5", status: "conflicting", summary: "JobCreated carries a sixth `hook` argument; the ERC five-argument topic is never emitted." },
  { id: "C6", status: "conflicting", summary: "Hook data prepends msg.sender and createJob has an after-hook." },
  { id: "C7", status: "verified", summary: "Fees apply on completion only; evaluatorFeeBP is a deployed extension and both fees are admin-mutable without an event." },
  { id: "C8", status: "verified", summary: "There is no on-chain dispute function, state or event." },
  { id: "C9", status: "verified", summary: "createJob requires expiredAt > block.timestamp + 5 minutes." },
  { id: "C10", status: "conflicting", summary: "There is no provider-acceptance call and settlement is atomic inside complete; no accepted/settled/disputed facts exist." },
  { id: "C11", status: "conflicting", summary: "Refund exists only via evaluator reject or claimRefund after expiry; dispute is unsupported on chain." },
] as const);

/** Facts the research could not verify. Nothing in this module builds on them. */
export const ERC8183_UNVERIFIED_FACTS = Object.freeze([
  { id: "D12", summary: "Full role and HookWhitelistUpdated history (explorer index only)." },
  { id: "F2/Q1", summary: "Whether a `latest` block can differ from `finalized`; anchor on finalized until resolved." },
  { id: "Q2", summary: "No live claimRefund/JobExpired path has been observed on this deployment." },
  { id: "Q3", summary: "Whether any non-zero hook is whitelisted." },
  { id: "Q4", summary: "Whether any address other than the pinned admin holds a role." },
  { id: "Q7", summary: "Sign-off that a Draft-ERC reference deployment under one admin EOA is acceptable." },
  { id: "D13-hash", summary: "The parameter review block hash is recorded only truncated (0xe14b35cd…4a67); only its number is pinned." },
] as const);

export const ERC8183_UNSUPPORTED_ACTIONS = Object.freeze([
  "dispute", "provider_acceptance", "deadline_extension", "partial_refund", "client_cancel_after_funding",
  "budget_change_after_funding", "hooks", "admin_calls",
] as const);

export interface Erc8183DeploymentManifest {
  readonly id: "arc-testnet-erc8183-reference";
  readonly environment: "testnet";
  readonly caip2: Erc8183NetworkId;
  readonly chainId: 5042002;
  readonly chainIdHex: "0x4cef52";
  readonly specification: { readonly erc: "ERC-8183"; readonly status: "draft"; readonly abiVersion: "deployed-verified-source" };
  readonly proxy: {
    readonly address: typeof PINNED.proxy;
    readonly kind: "erc1967-uups";
    readonly runtimeCodeKeccak: `0x${string}`;
    readonly deploymentBlock: "33908011";
    readonly deploymentTransaction: `0x${string}`;
    readonly upgradedLogIndex: "34";
  };
  readonly implementation: {
    readonly address: typeof PINNED.implementation;
    readonly slot: typeof PINNED.implementationSlot;
    readonly runtimeCodeKeccak: `0x${string}`;
    readonly runtimeCodeBytes: 21560;
    readonly source: {
      readonly contractName: "AgenticCommerce";
      readonly path: "src/AgenticCommerce.sol";
      readonly sha256: typeof PINNED.sourceSha256;
      readonly compiler: "v0.8.28+commit.7893614a";
      readonly optimization: false;
      readonly evmVersion: "cancun";
      readonly verifiedAt: "2026-03-26T16:13:06Z";
    };
    readonly upgradeInterfaceVersion: "5.0.0";
  };
  readonly governance: {
    readonly admin: `0x${string}`;
    readonly adminIsEoa: true;
    readonly roles: { readonly DEFAULT_ADMIN_ROLE: `0x${string}`; readonly ADMIN_ROLE: `0x${string}` };
    readonly platformTreasury: `0x${string}`;
  };
  readonly paymentToken: {
    readonly symbol: "USDC";
    readonly address: typeof PINNED.usdc;
    readonly decimals: 6;
    /** Native 18-decimal mirror emitter; its Transfer logs are never counted. */
    readonly systemEmitter: typeof PINNED.usdcSystemEmitter;
    readonly systemEmitterDecimals: 18;
  };
  /** Reviewed at block 62293116; admin-mutable without an event (S6). */
  readonly reviewedParameters: {
    readonly blockNumber: "62293116";
    readonly platformFeeBP: "0";
    readonly evaluatorFeeBP: "0";
    readonly zeroHookWhitelisted: true;
  };
  readonly statuses: typeof ERC8183_DEPLOYED_STATUSES;
  readonly events: typeof EVENTS;
  /** The ERC text's five-argument JobCreated topic (C5). Never emitted here; never indexed. */
  readonly nonDeployedStandardTopics: { readonly JobCreated: `0x${string}` };
  readonly functions: typeof FUNCTIONS;
  readonly observation: {
    readonly anchorTag: "finalized";
    readonly maxLogRangeBlocks: 10000;
  };
  readonly canonicalJobIdPrefix: `eip155:5042002:erc8183:${typeof PINNED.proxy}:`;
  readonly deviations: typeof ERC8183_DEPLOYED_DEVIATIONS;
  readonly unsupportedActions: typeof ERC8183_UNSUPPORTED_ACTIONS;
  readonly unverified: typeof ERC8183_UNVERIFIED_FACTS;
  readonly reviewedAt: "2026-09-15";
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function buildArcTestnetEntry(): Erc8183DeploymentManifest {
  const issues: string[] = [];
  if (ARC_TESTNET.caip2 !== ERC8183_ARC_TESTNET_CAIP2) issues.push("ARC_TESTNET.caip2:drift");
  if (Number(ARC_TESTNET.chainId) !== PINNED.chainId || ARC_TESTNET.chainIdHex !== PINNED.chainIdHex) {
    issues.push("ARC_TESTNET.chainId:drift");
  }
  if (ARC_TESTNET.contracts.erc8183AgenticCommerce.toLowerCase() !== PINNED.proxy) issues.push("ARC_TESTNET.erc8183:drift");
  if (ARC_TESTNET.contracts.usdc.toLowerCase() !== PINNED.usdc) issues.push("ARC_TESTNET.usdc:drift");
  if (ARC_TESTNET.usdcSystemEmitter !== PINNED.usdcSystemEmitter) issues.push("ARC_TESTNET.usdcSystemEmitter:drift");
  if (ARC_TESTNET.transferTopic !== PINNED.transferTopic) issues.push("ARC_TESTNET.transferTopic:drift");
  if (ARC_ERC8183.implementation !== PINNED.implementation) issues.push("ARC_ERC8183.implementation:drift");
  if (ARC_ERC8183.implementationSlot !== PINNED.implementationSlot) issues.push("ARC_ERC8183.implementationSlot:drift");
  if (ARC_ERC8183.sourceSha256 !== PINNED.sourceSha256) issues.push("ARC_ERC8183.sourceSha256:drift");
  if (issues.length > 0) throw new Erc8183ManifestError("invalid_config", issues);

  const admin = "0xcbe5b97a069be3e4b5398663790731fb76ab620d" as const;
  return deepFreeze({
    id: "arc-testnet-erc8183-reference",
    environment: "testnet",
    caip2: ERC8183_ARC_TESTNET_CAIP2,
    chainId: PINNED.chainId,
    chainIdHex: PINNED.chainIdHex,
    specification: { erc: "ERC-8183", status: "draft", abiVersion: "deployed-verified-source" },
    proxy: {
      address: PINNED.proxy,
      kind: "erc1967-uups",
      runtimeCodeKeccak: "0x6fbb70f32c57790a7bc472b3fd6adb3bc22e911239f1a86f77898e69f62d5d13",
      deploymentBlock: "33908011",
      deploymentTransaction: "0x7b90975a892815bb98c361f899b762590a909a1f2e701628739546113e4e20da",
      upgradedLogIndex: "34",
    },
    implementation: {
      address: PINNED.implementation,
      slot: PINNED.implementationSlot,
      runtimeCodeKeccak: "0x7054f89cadf92af85003313db92e9b29ef670ee2c7a20b5295cdddf66ecaa4b3",
      runtimeCodeBytes: 21560,
      source: {
        contractName: "AgenticCommerce",
        path: "src/AgenticCommerce.sol",
        sha256: PINNED.sourceSha256,
        compiler: "v0.8.28+commit.7893614a",
        optimization: false,
        evmVersion: "cancun",
        verifiedAt: "2026-03-26T16:13:06Z",
      },
      upgradeInterfaceVersion: "5.0.0",
    },
    governance: {
      admin,
      adminIsEoa: true,
      roles: {
        DEFAULT_ADMIN_ROLE: "0x0000000000000000000000000000000000000000000000000000000000000000",
        ADMIN_ROLE: "0xa49807205ce4d355092ef5a8a18f56e8913cf4a201fbe287825b095693c21775",
      },
      platformTreasury: admin,
    },
    paymentToken: {
      symbol: "USDC",
      address: PINNED.usdc,
      decimals: 6,
      systemEmitter: PINNED.usdcSystemEmitter,
      systemEmitterDecimals: 18,
    },
    reviewedParameters: { blockNumber: "62293116", platformFeeBP: "0", evaluatorFeeBP: "0", zeroHookWhitelisted: true },
    statuses: ERC8183_DEPLOYED_STATUSES,
    events: EVENTS,
    nonDeployedStandardTopics: { JobCreated: "0xef137df1d007645178f3f70e5c306d8d0b84bb5c70cabda9bb0f8f3c71932a0f" },
    functions: FUNCTIONS,
    observation: { anchorTag: "finalized", maxLogRangeBlocks: 10000 },
    canonicalJobIdPrefix: `eip155:5042002:erc8183:${PINNED.proxy}:`,
    deviations: ERC8183_DEPLOYED_DEVIATIONS,
    unsupportedActions: ERC8183_UNSUPPORTED_ACTIONS,
    unverified: ERC8183_UNVERIFIED_FACTS,
    reviewedAt: "2026-09-15",
  } as const satisfies Erc8183DeploymentManifest);
}

export const ERC8183_ARC_TESTNET_DEPLOYMENT: Erc8183DeploymentManifest = buildArcTestnetEntry();

/** Data-driven, single entry. Adding a network means adding a reviewed entry here. */
const DEPLOYMENTS: readonly Erc8183DeploymentManifest[] = Object.freeze([ERC8183_ARC_TESTNET_DEPLOYMENT]);

export function listErc8183DeploymentNetworks(): readonly Erc8183NetworkId[] {
  return DEPLOYMENTS.map((entry) => entry.caip2);
}

/**
 * Resolves only an exact known CAIP-2 string (`eip155:5042002`), or the exact
 * numeric chain id 5042002. Anything else, including missing input, throws.
 */
export function resolveErc8183Deployment(network: unknown): Erc8183DeploymentManifest {
  let entry: Erc8183DeploymentManifest | undefined;
  if (typeof network === "string") entry = DEPLOYMENTS.find((candidate) => candidate.caip2 === network);
  else if (typeof network === "number" && Number.isSafeInteger(network)) {
    entry = DEPLOYMENTS.find((candidate) => candidate.chainId === network);
  } else if (network === undefined || network === null) {
    throw new Erc8183ManifestError("unknown_network", ["network:missing"]);
  }
  if (entry === undefined) throw new Erc8183ManifestError("unknown_network", ["network:not_in_manifest"]);
  return entry;
}

export function erc8183CanonicalJobId(manifest: Erc8183DeploymentManifest, jobId: bigint): string {
  if (jobId < 1n || jobId >= 1n << 256n) throw new Erc8183ManifestError("invalid_config", ["jobId:out_of_range"]);
  return `${manifest.canonicalJobIdPrefix}${jobId.toString()}`;
}

// ───────────────────────── Drift assessment ─────────────────────────

/** Read-only observations taken at one finalized anchor. Omitted fields are "unobserved". */
export interface Erc8183ObservedDeployment {
  readonly network: string;
  readonly anchor?: { readonly tag: string; readonly blockNumber: string; readonly blockHash: string };
  /** Raw 32-byte word from `eth_getStorageAt(proxy, implementationSlot)`. */
  readonly implementationSlotWord?: string;
  readonly proxyCodeKeccak?: string;
  readonly implementationCodeKeccak?: string;
  /** `hasRole(DEFAULT_ADMIN_ROLE, pinned admin)` and `hasRole(ADMIN_ROLE, pinned admin)`. */
  readonly pinnedAdminHasDefaultAdminRole?: boolean;
  readonly pinnedAdminHasAdminRole?: boolean;
  /** `getRoleAdmin(ADMIN_ROLE)`; the review found DEFAULT_ADMIN_ROLE (zero). */
  readonly adminRoleAdmin?: string;
  readonly platformFeeBP?: string;
  readonly evaluatorFeeBP?: string;
  readonly paymentToken?: string;
  readonly platformTreasury?: string;
}

export const ERC8183_DRIFT_FIELDS = [
  "anchor", "implementationSlot", "proxyCodeKeccak", "implementationCodeKeccak", "pinnedAdminHasDefaultAdminRole",
  "pinnedAdminHasAdminRole", "adminRoleAdmin", "platformFeeBP", "evaluatorFeeBP", "paymentToken", "platformTreasury",
] as const;
export type Erc8183DriftField = (typeof ERC8183_DRIFT_FIELDS)[number];

export interface Erc8183DriftCheck {
  readonly field: Erc8183DriftField;
  readonly outcome: "match" | "drift" | "unobserved" | "malformed";
  readonly expected: string;
  readonly observed: string | null;
}

export interface Erc8183DriftAssessment {
  readonly network: Erc8183NetworkId;
  /** `verified` only when every field is observed at a finalized anchor and matches. */
  readonly verdict: "verified" | "drifted" | "incomplete";
  readonly freezePreparation: boolean;
  readonly checks: readonly Erc8183DriftCheck[];
}

const HASH32 = /^0x[0-9a-fA-F]{64}$/u;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/u;
const DECIMAL = /^(0|[1-9][0-9]{0,77})$/u;

/**
 * Pure comparison of observed deployment facts against the manifest. The
 * result is never `verified` if anything drifted, is malformed, or was not
 * observed. Unknown networks throw.
 */
export function assessDeploymentDrift(observed: Erc8183ObservedDeployment): Erc8183DriftAssessment {
  const manifest = resolveErc8183Deployment(observed.network);
  const checks: Erc8183DriftCheck[] = [];
  const push = (field: Erc8183DriftField, expected: string, raw: unknown, valid: (value: string) => boolean,
    normalize: (value: string) => string = (value) => value.toLowerCase()) => {
    if (raw === undefined) {
      checks.push({ field, outcome: "unobserved", expected, observed: null });
      return;
    }
    const text = typeof raw === "boolean" ? String(raw) : raw;
    if (typeof text !== "string" || !valid(text)) {
      checks.push({ field, outcome: "malformed", expected, observed: typeof text === "string" ? text : null });
      return;
    }
    const value = normalize(text);
    checks.push({ field, outcome: value === expected ? "match" : "drift", expected, observed: value });
  };

  const anchor = observed.anchor;
  if (anchor === undefined) checks.push({ field: "anchor", outcome: "unobserved", expected: "finalized", observed: null });
  else if (!DECIMAL.test(anchor.blockNumber) || !HASH32.test(anchor.blockHash)) {
    checks.push({ field: "anchor", outcome: "malformed", expected: "finalized", observed: anchor.tag });
  } else checks.push({ field: "anchor", outcome: anchor.tag === "finalized" ? "match" : "drift", expected: "finalized", observed: anchor.tag });

  push("implementationSlot", `0x${"0".repeat(24)}${manifest.implementation.address.slice(2)}`,
    observed.implementationSlotWord, (value) => HASH32.test(value));
  push("proxyCodeKeccak", manifest.proxy.runtimeCodeKeccak, observed.proxyCodeKeccak, (value) => HASH32.test(value));
  push("implementationCodeKeccak", manifest.implementation.runtimeCodeKeccak, observed.implementationCodeKeccak,
    (value) => HASH32.test(value));
  push("pinnedAdminHasDefaultAdminRole", "true", observed.pinnedAdminHasDefaultAdminRole, (value) => value === "true" || value === "false");
  push("pinnedAdminHasAdminRole", "true", observed.pinnedAdminHasAdminRole, (value) => value === "true" || value === "false");
  push("adminRoleAdmin", manifest.governance.roles.DEFAULT_ADMIN_ROLE, observed.adminRoleAdmin, (value) => HASH32.test(value));
  push("platformFeeBP", manifest.reviewedParameters.platformFeeBP, observed.platformFeeBP, (value) => DECIMAL.test(value), (value) => value);
  push("evaluatorFeeBP", manifest.reviewedParameters.evaluatorFeeBP, observed.evaluatorFeeBP, (value) => DECIMAL.test(value), (value) => value);
  push("paymentToken", manifest.paymentToken.address, observed.paymentToken, (value) => ADDRESS.test(value));
  push("platformTreasury", manifest.governance.platformTreasury, observed.platformTreasury, (value) => ADDRESS.test(value));

  const bad = checks.some((check) => check.outcome === "drift" || check.outcome === "malformed");
  const missing = checks.some((check) => check.outcome === "unobserved");
  const verdict = bad ? "drifted" : missing ? "incomplete" : "verified";
  return Object.freeze({
    network: manifest.caip2,
    verdict,
    freezePreparation: verdict !== "verified",
    checks: Object.freeze(checks.map((check) => Object.freeze(check))),
  });
}
