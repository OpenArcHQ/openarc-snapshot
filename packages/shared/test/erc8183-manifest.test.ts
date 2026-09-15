import { keccak256, parseAbiItem, toBytes, toEventSelector, toFunctionSelector, type AbiEvent } from "viem";
import { describe, expect, it } from "vitest";

import {
  ARC_ERC8183,
  ARC_TESTNET,
  ERC8183_ARC_TESTNET_DEPLOYMENT as M,
  ERC8183_DEPLOYED_STATUSES,
  ERC8183_DRIFT_FIELDS,
  Erc8183ManifestError,
  assessDeploymentDrift,
  erc8183CanonicalJobId,
  listErc8183DeploymentNetworks,
  resolveErc8183Deployment,
  type Erc8183ObservedDeployment,
} from "../src/index.js";

/** Declarations copied from the verified deployed source (SHA-256 a16ae329…bec4), lines 50–64. */
const DEPLOYED_EVENT_DECLARATIONS: Record<string, string> = {
  JobCreated: "event JobCreated(uint256 indexed jobId, address indexed client, address indexed provider, address evaluator, uint256 expiredAt, address hook)",
  ProviderSet: "event ProviderSet(uint256 indexed jobId, address indexed provider)",
  BudgetSet: "event BudgetSet(uint256 indexed jobId, uint256 amount)",
  JobFunded: "event JobFunded(uint256 indexed jobId, address indexed client, uint256 amount)",
  JobSubmitted: "event JobSubmitted(uint256 indexed jobId, address indexed provider, bytes32 deliverable)",
  JobCompleted: "event JobCompleted(uint256 indexed jobId, address indexed evaluator, bytes32 reason)",
  JobRejected: "event JobRejected(uint256 indexed jobId, address indexed rejector, bytes32 reason)",
  JobExpired: "event JobExpired(uint256 indexed jobId)",
  PaymentReleased: "event PaymentReleased(uint256 indexed jobId, address indexed provider, uint256 amount)",
  EvaluatorFeePaid: "event EvaluatorFeePaid(uint256 indexed jobId, address indexed evaluator, uint256 amount)",
  Refunded: "event Refunded(uint256 indexed jobId, address indexed client, uint256 amount)",
  HookWhitelistUpdated: "event HookWhitelistUpdated(address indexed hook, bool status)",
  Upgraded: "event Upgraded(address indexed implementation)",
  Transfer: "event Transfer(address indexed from, address indexed to, uint256 value)",
  Approval: "event Approval(address indexed owner, address indexed spender, uint256 value)",
};

/** Pinned research values (§2.2 and §6), independent of the module under test. */
const RESEARCH_TOPICS: Record<string, string> = {
  JobCreated: "0xb0f0239bfdd96453e24733e18bfc24b70d8fadf123dd977473518dd577ee79b9",
  ProviderSet: "0x9a87df076ea1725aba8ba29d32517ce37c9597d88cbf16ec6707892cc330ab69",
  BudgetSet: "0x869e2577b006bf47ee981cf6fec2e25583548081c14b98deab587f77b5068038",
  JobFunded: "0xe3fbcc1ea1bdc559ec7f0347efde7655e58b5f45a30b0e4470a583c3ef5496b3",
  JobSubmitted: "0x80c17db79857f338a6a6df68a6883ecc0ce78e2202fe61ed979733573f40538e",
  JobCompleted: "0x0fd54bd364fa9e67f17b091aefe930932c09fe7651cf5ad02c71a418f3341444",
  JobRejected: "0xae7362b1af91f4492868987b9c73990d780060811551b58728fbe96fd1bab275",
  JobExpired: "0x97237956f8810192811e2c3f273fd02c5d6295206fdd9c62e6fe2bfc19ba9232",
  PaymentReleased: "0x21d71db5be59bb9fa133895586b7404307dd33fb93b16db09dc6f1d9d7d231b0",
  EvaluatorFeePaid: "0x253dd534010ac976fa263caa123bae79b9c50292adf7ce67bdc5ec309f784e61",
  Refunded: "0x7ca5472b7ea78c2c0141c5a12ee6d170cf4ce8ed06be3d22c8252ddfc7a6a2c4",
  HookWhitelistUpdated: "0x7ee54953080e392a475a25b6acacb85417ca4e1953293c90934233ca13612510",
  Upgraded: "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b",
  Transfer: "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
  Approval: "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
};

const RESEARCH_SELECTORS: Record<string, string> = {
  createJob: "0x41528812", setProvider: "0xd0fae591", setBudget: "0xdd4ae9d4", fund: "0xe25ba707",
  submit: "0x9e63798d", complete: "0xd75bbdf3", reject: "0x41dd26f5", claimRefund: "0x5b7baf64",
  getJob: "0xbf22c457", jobHasBudget: "0xfabc3329", paymentToken: "0x3013ce29", platformFeeBP: "0xff96092a",
  evaluatorFeeBP: "0x2f0e31f4", platformTreasury: "0xe138818c", jobCounter: "0x50355d76",
  whitelistedHooks: "0x6d3b96c3", hasRole: "0x91d14854", UPGRADE_INTERFACE_VERSION: "0xad3cb1cc",
};

describe("ERC-8183 deployment manifest (P07-01)", () => {
  it("pins exactly one Arc Testnet entry with the reviewed proxy, implementation and provenance", () => {
    expect(listErc8183DeploymentNetworks()).toEqual(["eip155:5042002"]);
    expect(M.caip2).toBe("eip155:5042002");
    expect(M.chainId).toBe(5042002);
    expect(M.chainIdHex).toBe("0x4cef52");
    expect(Number.parseInt(M.chainIdHex, 16)).toBe(M.chainId);
    expect(M.proxy.address).toBe("0x0747eef0706327138c69792bf28cd525089e4583");
    expect(M.proxy.address).toBe(ARC_TESTNET.contracts.erc8183AgenticCommerce.toLowerCase());
    expect(M.proxy.runtimeCodeKeccak).toBe("0x6fbb70f32c57790a7bc472b3fd6adb3bc22e911239f1a86f77898e69f62d5d13");
    expect(M.implementation.address).toBe("0xa316fd02827242d537f84730f8a37d0ba5fd351a");
    expect(M.implementation.address).toBe(ARC_ERC8183.implementation);
    expect(M.implementation.runtimeCodeKeccak).toBe("0x7054f89cadf92af85003313db92e9b29ef670ee2c7a20b5295cdddf66ecaa4b3");
    expect(M.implementation.runtimeCodeBytes).toBe(21560);
    expect(M.implementation.source.sha256).toBe("a16ae3290855910a4c06a59fa691d1d2b56b534e744f15b6f73a6a06ccb1bec4");
    expect(M.implementation.source.sha256).toBe(ARC_ERC8183.sourceSha256);
    expect(M.implementation.source.compiler).toBe("v0.8.28+commit.7893614a");
    expect(M.paymentToken).toEqual({ symbol: "USDC", address: "0x3600000000000000000000000000000000000000", decimals: 6,
      systemEmitter: "0xfffffffffffffffffffffffffffffffffffffffe", systemEmitterDecimals: 18 });
    expect(M.governance.admin).toBe("0xcbe5b97a069be3e4b5398663790731fb76ab620d");
    expect(M.reviewedParameters).toEqual({ blockNumber: "62293116", platformFeeBP: "0", evaluatorFeeBP: "0", zeroHookWhitelisted: true });
    expect(M.observation).toEqual({ anchorTag: "finalized", maxLogRangeBlocks: 10000 });
    expect(M.statuses).toEqual(["Open", "Funded", "Submitted", "Completed", "Rejected", "Expired"]);
    expect(ERC8183_DEPLOYED_STATUSES).toBe(M.statuses);
  });

  it("recomputes the EIP-1967 implementation slot and the AccessControl role ids", () => {
    const slot = BigInt(keccak256(toBytes("eip1967.proxy.implementation"))) - 1n;
    expect(`0x${slot.toString(16).padStart(64, "0")}`).toBe(M.implementation.slot);
    expect(M.implementation.slot).toBe("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc");
    expect(keccak256(toBytes("ADMIN_ROLE"))).toBe(M.governance.roles.ADMIN_ROLE);
    expect(M.governance.roles.DEFAULT_ADMIN_ROLE).toBe(`0x${"0".repeat(64)}`);
  });

  it("recomputes every event topic from its signature string and pins the deployed indexed layout", () => {
    expect(Object.keys(M.events).sort()).toEqual(Object.keys(DEPLOYED_EVENT_DECLARATIONS).sort());
    for (const [name, definition] of Object.entries(M.events)) {
      expect(keccak256(toBytes(definition.signature)), name).toBe(definition.topic0);
      expect(definition.topic0, name).toBe(RESEARCH_TOPICS[name]);
      expect(`${definition.name}(${definition.params.map((param) => param.type).join(",")})`).toBe(definition.signature);
      const declared = parseAbiItem(DEPLOYED_EVENT_DECLARATIONS[name] as string) as AbiEvent;
      expect(toEventSelector(declared), name).toBe(definition.topic0);
      expect(definition.params.map((param) => [param.name, param.type, param.indexed]), name)
        .toEqual(declared.inputs.map((input) => [input.name, input.type, input.indexed === true]));
    }
    expect(M.events.Transfer.topic0).toBe(ARC_TESTNET.transferTopic);
  });

  it("uses the deployed six-argument JobCreated topic, not the ERC text's five-argument form (C5)", () => {
    const standard = keccak256(toBytes("JobCreated(uint256,address,address,address,uint256)"));
    expect(standard).toBe("0xef137df1d007645178f3f70e5c306d8d0b84bb5c70cabda9bb0f8f3c71932a0f");
    expect(M.nonDeployedStandardTopics.JobCreated).toBe(standard);
    expect(M.events.JobCreated.topic0).not.toBe(standard);
    expect(Object.values(M.events).map((event) => event.topic0)).not.toContain(standard);
  });

  it("recomputes every function selector from its signature string", () => {
    expect(Object.keys(M.functions).sort()).toEqual(Object.keys(RESEARCH_SELECTORS).sort());
    for (const [name, definition] of Object.entries(M.functions)) {
      expect(keccak256(toBytes(definition.signature)).slice(0, 10), name).toBe(definition.selector);
      expect(toFunctionSelector(definition.signature), name).toBe(definition.selector);
      expect(definition.selector, name).toBe(RESEARCH_SELECTORS[name]);
    }
    // Deployed fund has no expectedBudget (C1); the ERC normative form is a different selector.
    expect(toFunctionSelector("fund(uint256,uint256,bytes)")).not.toBe(M.functions.fund.selector);
    expect(M.functions.setBudget.caller).toBe("provider");
    expect(M.functions.claimRefund.caller).toBe("anyone");
  });

  it("records deviations C1–C11, unsupported actions and unverified facts, and nothing named dispute/accept/settle", () => {
    expect(M.deviations.map((deviation) => deviation.id)).toEqual(["C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11"]);
    expect(M.unsupportedActions).toEqual(expect.arrayContaining(["dispute", "provider_acceptance", "hooks", "admin_calls"]));
    expect(M.unverified.map((fact) => fact.id)).toEqual(expect.arrayContaining(["D12", "F2/Q1", "Q2", "Q3", "Q4"]));
    const surface = [...Object.keys(M.events), ...Object.keys(M.functions), ...M.statuses].join(" ").toLowerCase();
    for (const word of ["dispute", "accept", "settle"]) expect(surface).not.toContain(word);
  });

  it("is deeply frozen", () => {
    expect(Object.isFrozen(M)).toBe(true);
    expect(Object.isFrozen(M.events.JobCreated.params[0])).toBe(true);
    expect(Object.isFrozen(M.functions)).toBe(true);
    expect(() => { (M.proxy as { address: string }).address = "0x0"; }).toThrow(TypeError);
  });

  it("has no mainnet entry and no default: every other network throws", () => {
    expect(resolveErc8183Deployment("eip155:5042002")).toBe(M);
    expect(resolveErc8183Deployment(5042002)).toBe(M);
    for (const network of ["eip155:1", 1, "eip155:8453", "5042002", "0x4cef52", "eip155:5042002 ", "EIP155:5042002",
      "arc-mainnet", "", 5042002.5, undefined, null, {}, 5042002n]) {
      expect(() => resolveErc8183Deployment(network), String(network)).toThrow(Erc8183ManifestError);
    }
    try {
      resolveErc8183Deployment(undefined);
    } catch (error) {
      expect(error).toMatchObject({ code: "unknown_network", issues: ["network:missing"] });
    }
  });

  it("builds canonical job ids only for positive uint256 ids", () => {
    expect(erc8183CanonicalJobId(M, 186510n)).toBe("eip155:5042002:erc8183:0x0747eef0706327138c69792bf28cd525089e4583:186510");
    expect(() => erc8183CanonicalJobId(M, 0n)).toThrow(Erc8183ManifestError);
    expect(() => erc8183CanonicalJobId(M, 1n << 256n)).toThrow(Erc8183ManifestError);
  });
});

describe("assessDeploymentDrift", () => {
  const good: Erc8183ObservedDeployment = Object.freeze({
    network: "eip155:5042002",
    anchor: { tag: "finalized", blockNumber: "62293262", blockHash: `0x${"ab".repeat(32)}` },
    implementationSlotWord: "0x000000000000000000000000A316fd02827242D537F84730F8a37D0BA5fd351a",
    proxyCodeKeccak: "0x6fbb70f32c57790a7bc472b3fd6adb3bc22e911239f1a86f77898e69f62d5d13",
    implementationCodeKeccak: "0x7054f89cadf92af85003313db92e9b29ef670ee2c7a20b5295cdddf66ecaa4b3",
    pinnedAdminHasDefaultAdminRole: true,
    pinnedAdminHasAdminRole: true,
    adminRoleAdmin: `0x${"0".repeat(64)}`,
    platformFeeBP: "0",
    evaluatorFeeBP: "0",
    paymentToken: "0x3600000000000000000000000000000000000000",
    platformTreasury: "0xcBe5B97a069be3E4B5398663790731fb76aB620D",
  });

  it("verifies only a fully observed, finalized, matching deployment", () => {
    const result = assessDeploymentDrift(good);
    expect(result.verdict).toBe("verified");
    expect(result.freezePreparation).toBe(false);
    expect(result.checks.map((check) => check.field)).toEqual([...ERC8183_DRIFT_FIELDS]);
    expect(result.checks.every((check) => check.outcome === "match")).toBe(true);
    expect(Object.isFrozen(result)).toBe(true);
  });

  const drifts: [string, Partial<Record<keyof Erc8183ObservedDeployment, unknown>>, string][] = [
    ["implementation slot", { implementationSlotWord: `0x${"0".repeat(24)}${"11".repeat(20)}` }, "implementationSlot"],
    ["implementation code hash", { implementationCodeKeccak: `0x${"22".repeat(32)}` }, "implementationCodeKeccak"],
    ["proxy code hash", { proxyCodeKeccak: `0x${"33".repeat(32)}` }, "proxyCodeKeccak"],
    ["admin lost default admin role", { pinnedAdminHasDefaultAdminRole: false }, "pinnedAdminHasDefaultAdminRole"],
    ["admin lost admin role", { pinnedAdminHasAdminRole: false }, "pinnedAdminHasAdminRole"],
    ["role admin changed", { adminRoleAdmin: `0x${"44".repeat(32)}` }, "adminRoleAdmin"],
    ["platform fee", { platformFeeBP: "250" }, "platformFeeBP"],
    ["evaluator fee", { evaluatorFeeBP: "1" }, "evaluatorFeeBP"],
    ["payment token", { paymentToken: "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238" }, "paymentToken"],
    ["treasury", { platformTreasury: "0x0000000000000000000000000000000000000001" }, "platformTreasury"],
    ["latest instead of finalized anchor", { anchor: { tag: "latest", blockNumber: "1", blockHash: `0x${"ab".repeat(32)}` } }, "anchor"],
  ];
  it.each(drifts)("reports drift and never verifies: %s", (_label, change, field) => {
    const result = assessDeploymentDrift({ ...good, ...change } as Erc8183ObservedDeployment);
    expect(result.verdict).toBe("drifted");
    expect(result.freezePreparation).toBe(true);
    expect(result.checks.filter((check) => check.outcome !== "match").map((check) => [check.field, check.outcome]))
      .toEqual([[field, "drift"]]);
  });

  it("treats malformed observations as drift", () => {
    for (const change of [{ implementationSlotWord: "0xa316" }, { platformFeeBP: "01" }, { platformFeeBP: "-1" },
      { paymentToken: "not-an-address" }, { pinnedAdminHasAdminRole: "yes" }, { anchor: { tag: "finalized", blockNumber: "0x1", blockHash: "0x" } }]) {
      const result = assessDeploymentDrift({ ...good, ...change } as Erc8183ObservedDeployment);
      expect(result.verdict, JSON.stringify(change)).toBe("drifted");
      expect(result.checks.some((check) => check.outcome === "malformed")).toBe(true);
    }
  });

  it("is incomplete, never verified, when any field is unobserved", () => {
    for (const field of Object.keys(good).filter((key) => key !== "network")) {
      const partial = { ...good } as Record<string, unknown>;
      delete partial[field];
      const result = assessDeploymentDrift(partial as unknown as Erc8183ObservedDeployment);
      expect(result.verdict, field).toBe("incomplete");
      expect(result.freezePreparation).toBe(true);
    }
    expect(assessDeploymentDrift({ network: "eip155:5042002" }).verdict).toBe("incomplete");
  });

  it("drift outranks incompleteness", () => {
    expect(assessDeploymentDrift({ network: "eip155:5042002", platformFeeBP: "1" }).verdict).toBe("drifted");
  });

  it("throws for unknown networks instead of assessing against a default", () => {
    expect(() => assessDeploymentDrift({ ...good, network: "eip155:1" })).toThrow(Erc8183ManifestError);
  });
});
