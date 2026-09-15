import { AGENT_REGISTRY_PROXIES, ARC_ERC8004_DEPLOYMENT, ARC_TESTNET, describeDeploymentCheck } from "@openarc/shared";
import { encodeAbiParameters, encodeEventTopics, parseAbiParameters } from "viem";
import { describe, expect, it } from "vitest";

import {
  AgentRegistryService,
  VALIDATION_RESPONSE_EVENT_ABI,
  VALIDATION_RESPONSE_TOPIC,
  attributeValidationStatus,
  type ValidationStatusReading,
} from "../src/arc/agent-registry-service.js";
import type { ArcRpcMethod, ArcRpcReader } from "../src/arc/rpc-client.js";
import { ApiBoundaryError } from "../src/http/errors.js";
import type { SourceLease } from "../src/limits/budget.js";

const signal = new AbortController().signal;
const lease = {} as SourceLease;
const owner = "0x1111111111111111111111111111111111111111";
const wallet = "0x2222222222222222222222222222222222222222";
const observer = "0x3333333333333333333333333333333333333333";
const validator = "0x4444444444444444444444444444444444444444";
const drifted = "0x5555555555555555555555555555555555555555";
const requestHash = `0x${"a".repeat(64)}` as const;
const responseHash = `0x${"b".repeat(64)}` as const;
const zeroHash = `0x${"0".repeat(64)}` as const;
const blockHash = `0x${"c".repeat(64)}`;
const anchor = { number: "0x64", hash: blockHash, timestamp: "0x6553f100" };

const encoded = (types: string, values: readonly unknown[]) =>
  encodeAbiParameters(parseAbiParameters(types), values);
const addressResult = (value: string) => encoded("address", [value]);
const stringResult = (value: string) => encoded("string", [value]);
const slotResult = (value: string) => `0x${"0".repeat(24)}${value.slice(2)}`;

type RegistryOverrides = Partial<Record<"identity" | "reputation" | "validation", string | Error>>;

class SequenceRpc implements ArcRpcReader {
  readonly calls: { method: ArcRpcMethod; params: readonly unknown[] }[] = [];
  constructor(private readonly sequence: readonly (unknown | Error)[]) {}
  async call(method: ArcRpcMethod, params: readonly unknown[]): Promise<unknown> {
    this.calls.push({ method, params });
    const next = this.sequence[this.calls.length - 1];
    if (next instanceof Error) throw next;
    if (next === undefined) throw new Error("Unexpected RPC call");
    return next;
  }
}

function sequence(mutations: { owner?: string; wallet?: string; metadata?: string; reputationBinding?: string;
  validationBinding?: string; validationAgentId?: bigint; validationResponse?: number; validationResponseHash?: string;
  implementations?: RegistryOverrides; proxyOwners?: RegistryOverrides; repeated?: unknown } = {}) {
  const implementation = (key: keyof RegistryOverrides) => {
    const value = mutations.implementations?.[key] ?? ARC_ERC8004_DEPLOYMENT.implementations[key];
    return value instanceof Error || value.length !== 42 ? value : slotResult(value);
  };
  const proxyOwner = (key: keyof RegistryOverrides) => {
    const value = mutations.proxyOwners?.[key] ?? ARC_ERC8004_DEPLOYMENT.proxyOwner;
    return value instanceof Error ? value : addressResult(value);
  };
  return new SequenceRpc([
    ARC_TESTNET.chainIdHex, anchor, addressResult(mutations.owner ?? owner),
    stringResult(mutations.metadata ?? "https://example.test/agent.json"), addressResult(mutations.wallet ?? wallet),
    addressResult(mutations.reputationBinding ?? ARC_TESTNET.contracts.erc8004IdentityRegistry),
    addressResult(mutations.validationBinding ?? ARC_TESTNET.contracts.erc8004IdentityRegistry),
    implementation("identity"), implementation("reputation"), implementation("validation"),
    proxyOwner("identity"), proxyOwner("reputation"), proxyOwner("validation"),
    encoded("int128 value, uint8 valueDecimals, string tag1, string tag2, bool isRevoked",
      [-1234n, 2, "quality", "delivery", false]),
    encoded("address validatorAddress, uint256 agentId, uint8 response, bytes32 responseHash, string tag, uint256 lastUpdate",
      [validator, mutations.validationAgentId ?? 1n, mutations.validationResponse ?? 87,
        mutations.validationResponseHash ?? responseHash, "benchmark", 123n]),
    mutations.repeated ?? anchor,
  ]);
}

const request = { network: ARC_TESTNET.caip2, agentId: "1",
  feedbackQuery: { clientAddress: observer, feedbackIndex: "0" }, validationRequestHash: requestHash } as const;

describe("M05 ERC-8004 agent evidence", () => {
  it("returns identity, an exact observer claim, and an explicit unobserved validation state at one final block", async () => {
    const rpc = sequence();
    const evidence = await new AgentRegistryService(rpc, () => "2026-09-04T12:00:00.000Z")
      .observe(request, lease, signal);
    expect(evidence.schemaVersion).toBe("openarc.agent-registry-evidence.v2");
    expect(evidence.identity).toEqual({ owner, agentWallet: wallet,
      metadata: { uri: "https://example.test/agent.json", kind: "https",
        trust: "untrusted_external_metadata", fetched: false } });
    expect(evidence.feedback).toMatchObject({ observer, value: "-1234", valueDecimals: 2, decimal: "-12.34",
      relationship: "observer_specific_claim" });
    // No log input exists in this adapter, so even a stored non-zero value is not attributed.
    expect(evidence.validation).toMatchObject({ state: "pending_or_unobserved", requestHash, namedValidator: validator,
      agentId: "1", relationship: "request_names_validator_without_observed_response" });
    expect(evidence.validation).not.toHaveProperty("response");
    expect(evidence.deployment.status).toBe("verified");
    expect(rpc.calls).toHaveLength(16);
    for (const call of rpc.calls.filter((entry) => entry.method === "eth_call")) {
      expect(call.params[1]).toBe("0x64");
      expect(Object.keys(call.params[0] as object).sort()).toEqual(["data", "to"]);
    }
    expect(rpc.calls.filter((entry) => entry.method === "eth_getStorageAt").map((entry) => entry.params)).toEqual([
      [AGENT_REGISTRY_PROXIES.identity, ARC_ERC8004_DEPLOYMENT.implementationSlot, "0x64"],
      [AGENT_REGISTRY_PROXIES.reputation, ARC_ERC8004_DEPLOYMENT.implementationSlot, "0x64"],
      [AGENT_REGISTRY_PROXIES.validation, ARC_ERC8004_DEPLOYMENT.implementationSlot, "0x64"],
    ]);
  });

  it("reports a getter response of 0 without an event as pending, never as a validator response", async () => {
    const evidence = await new AgentRegistryService(sequence({ validationResponse: 0, validationResponseHash: zeroHash }))
      .observe(request, lease, signal);
    expect(evidence.validation?.state).toBe("pending_or_unobserved");
    expect(JSON.stringify(evidence.validation)).not.toContain("validator_specific_response");
  });

  it("classifies malformed URI text without fetching it", async () => {
    const rpc = sequence({ metadata: "javascript:alert(1)" });
    const evidence = await new AgentRegistryService(rpc).observe(request, lease, signal);
    expect(evidence.identity.metadata).toEqual({ uri: "javascript:alert(1)", kind: "other",
      trust: "untrusted_external_metadata", fetched: false });
  });

  it.each([
    ["wrong reputation binding", sequence({ reputationBinding: observer }), "SOURCE_CONFLICT"],
    ["wrong validation binding", sequence({ validationBinding: observer }), "SOURCE_CONFLICT"],
    ["oversized metadata", sequence({ metadata: "x".repeat(4097) }), "SOURCE_MALFORMED"],
    ["validation belongs to another agent", sequence({ validationAgentId: 2n }), "SOURCE_CONFLICT"],
    ["anchor changed", sequence({ repeated: { ...anchor, hash: `0x${"d".repeat(64)}` } }), "SOURCE_CONFLICT"],
  ])("fails closed for %s", async (_name, rpc, code) => {
    await expect(new AgentRegistryService(rpc).observe(request, lease, signal)).rejects.toMatchObject({ code });
  });

  it("rejects owner or agent-wallet self feedback before reading a feedback claim", async () => {
    const rpc = sequence();
    await expect(new AgentRegistryService(rpc).observe({ ...request,
      feedbackQuery: { clientAddress: owner, feedbackIndex: "0" } }, lease, signal))
      .rejects.toMatchObject({ code: "SOURCE_CONFLICT" });
    expect(rpc.calls).toHaveLength(13);
  });

  it("preserves a sanitized not-found error for an unknown agent", async () => {
    const rpc = new SequenceRpc([ARC_TESTNET.chainIdHex, anchor, new ApiBoundaryError("SOURCE_NOT_FOUND")]);
    await expect(new AgentRegistryService(rpc).observe({ network: ARC_TESTNET.caip2, agentId: "999999" }, lease, signal))
      .rejects.toMatchObject({ code: "SOURCE_NOT_FOUND" });
  });
});

describe("ERC-8004 deployment pins", () => {
  it("verifies matching implementation slots and proxy owners", async () => {
    const evidence = await new AgentRegistryService(sequence()).observe(request, lease, signal);
    expect(evidence.deployment.status).toBe("verified");
    for (const key of ["identity", "reputation", "validation"] as const) {
      expect(evidence.deployment.registries[key]).toMatchObject({ implementation: "match", owner: "match",
        observedImplementation: ARC_ERC8004_DEPLOYMENT.implementations[key], observedOwner: ARC_ERC8004_DEPLOYMENT.proxyOwner });
    }
    expect(describeDeploymentCheck(evidence.deployment)).toEqual([]);
  });

  it("reports a different implementation slot as drift and not verified, with the reason", async () => {
    const evidence = await new AgentRegistryService(sequence({ implementations: { validation: drifted } }))
      .observe(request, lease, signal);
    expect(evidence.deployment.status).toBe("drift");
    expect(evidence.deployment.registries.validation).toMatchObject({ implementation: "drift",
      observedImplementation: drifted, pinnedImplementation: ARC_ERC8004_DEPLOYMENT.implementations.validation });
    expect(evidence.deployment.registries.identity.implementation).toBe("match");
    expect(describeDeploymentCheck(evidence.deployment)).toEqual([
      `validation implementation ${drifted} differs from reviewed pin ${ARC_ERC8004_DEPLOYMENT.implementations.validation}`,
    ]);
  });

  it("reports a changed proxy owner as drift", async () => {
    const evidence = await new AgentRegistryService(sequence({ proxyOwners: { identity: drifted } }))
      .observe(request, lease, signal);
    expect(evidence.deployment.status).toBe("drift");
    expect(evidence.deployment.registries.identity).toMatchObject({ owner: "drift", observedOwner: drifted });
  });

  it("reports an RPC error or malformed slot as unknown, not verified", async () => {
    const failed = await new AgentRegistryService(sequence({
      implementations: { identity: new ApiBoundaryError("SOURCE_UNAVAILABLE") } })).observe(request, lease, signal);
    expect(failed.deployment.status).toBe("unknown");
    expect(failed.deployment.registries.identity).toMatchObject({ implementation: "unknown", observedImplementation: null });
    expect(describeDeploymentCheck(failed.deployment)).toEqual(["identity implementation slot could not be read"]);

    const malformed = await new AgentRegistryService(sequence({
      implementations: { reputation: `0x${"f".repeat(64)}` } })).observe(request, lease, signal);
    expect(malformed.deployment.status).toBe("unknown");

    const ownerFailed = await new AgentRegistryService(sequence({
      proxyOwners: { validation: new ApiBoundaryError("SOURCE_MALFORMED") } })).observe(request, lease, signal);
    expect(ownerFailed.deployment.status).toBe("unknown");
  });

  it("lets drift win over unknown", async () => {
    const evidence = await new AgentRegistryService(sequence({ implementations: {
      identity: new ApiBoundaryError("SOURCE_UNAVAILABLE"), reputation: drifted } })).observe(request, lease, signal);
    expect(evidence.deployment.status).toBe("drift");
  });
});

describe("ValidationResponse attribution", () => {
  const status: ValidationStatusReading = { requestHash, validator, agentId: 1n, response: 0,
    responseHash: zeroHash, tag: "", lastUpdate: 123n };
  const responseLog = (overrides: { requestHash?: `0x${string}`; validator?: `0x${string}`; response?: number;
    address?: string; blockNumber?: string; removed?: boolean } = {}) => ({
    address: overrides.address ?? AGENT_REGISTRY_PROXIES.validation,
    topics: encodeEventTopics({ abi: VALIDATION_RESPONSE_EVENT_ABI, eventName: "ValidationResponse",
      args: { validatorAddress: overrides.validator ?? validator, agentId: 1n,
        requestHash: overrides.requestHash ?? requestHash } }),
    data: encoded("uint8, string, bytes32, string", [overrides.response ?? 0, "ipfs://response", zeroHash, ""]),
    transactionHash: `0x${"e".repeat(64)}`, blockNumber: overrides.blockNumber ?? "0x60", logIndex: "0x2",
    removed: overrides.removed ?? false,
  });

  it("uses the reviewed ValidationResponse topic", () => {
    expect(VALIDATION_RESPONSE_TOPIC.startsWith("0xafddf629")).toBe(true);
    expect(VALIDATION_RESPONSE_TOPIC.endsWith("49ae")).toBe(true);
  });

  it("treats getter 0 with no event as pending", () => {
    expect(attributeValidationStatus(status, [], 100n)).toMatchObject({ state: "pending_or_unobserved",
      namedValidator: validator });
  });

  it("attributes getter 0 with a matching event as a validator response of 0", () => {
    expect(attributeValidationStatus(status, [responseLog()], 100n)).toEqual({ state: "responded", requestHash,
      validator, agentId: "1", response: 0, responseHash: zeroHash, tag: "", lastUpdate: "123",
      responseEvent: { transactionHash: `0x${"e".repeat(64)}`, blockNumber: "96", logIndex: "2" },
      relationship: "validator_specific_response" });
  });

  it.each([
    ["a mismatched request hash", responseLog({ requestHash: `0x${"9".repeat(64)}` })],
    ["another emitter", responseLog({ address: observer })],
    ["a removed log", responseLog({ removed: true })],
    ["a log after the anchor", responseLog({ blockNumber: "0x65" })],
  ])("does not attribute %s", (_name, log) => {
    expect(attributeValidationStatus(status, [log], 100n).state).toBe("pending_or_unobserved");
  });

  it("fails closed when a matching event conflicts with the stored validator or latest response", () => {
    expect(() => attributeValidationStatus(status, [responseLog({ validator: observer })], 100n))
      .toThrow(expect.objectContaining({ code: "SOURCE_CONFLICT" }));
    expect(() => attributeValidationStatus(status, [responseLog({ response: 50 })], 100n))
      .toThrow(expect.objectContaining({ code: "SOURCE_CONFLICT" }));
  });
});
