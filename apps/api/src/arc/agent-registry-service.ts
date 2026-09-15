import {
  AGENT_REGISTRY_ADAPTER_VERSION,
  AGENT_REGISTRY_KEYS,
  AGENT_REGISTRY_LIMITATIONS,
  AGENT_REGISTRY_PROXIES,
  ARC_ERC8004,
  ARC_ERC8004_DEPLOYMENT,
  ARC_TESTNET,
  AgentRegistryEvidenceSchema,
  VALIDATION_PENDING_REASON,
  classifyAgentMetadataUri,
  compareDeploymentPin,
  deploymentStatus,
  type AgentRegistryDeploymentCheck,
  type AgentRegistryEvidence,
  type AgentRegistryEvidenceRequest,
  type AgentRegistryKey,
  type AgentRegistryValidationClaim,
} from "@openarc/shared";
import { decodeEventLog, decodeFunctionResult, encodeFunctionData, keccak256, toBytes, type Abi } from "viem";

import { ApiBoundaryError } from "../http/errors.js";
import type { SourceLease } from "../limits/budget.js";
import { parseHexQuantity, record } from "./quantities.js";
import type { ArcRpcReader } from "./rpc-client.js";
import { block, hash, requireChainId, requireSameBlock, type ParsedBlock } from "./validation.js";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

const identityAbi = [
  { type: "function", name: "ownerOf", stateMutability: "view",
    inputs: [{ name: "tokenId", type: "uint256" }], outputs: [{ name: "", type: "address" }] },
  { type: "function", name: "tokenURI", stateMutability: "view",
    inputs: [{ name: "tokenId", type: "uint256" }], outputs: [{ name: "", type: "string" }] },
  { type: "function", name: "getAgentWallet", stateMutability: "view",
    inputs: [{ name: "agentId", type: "uint256" }], outputs: [{ name: "", type: "address" }] },
] as const satisfies Abi;

const reputationAbi = [
  { type: "function", name: "getIdentityRegistry", stateMutability: "view", inputs: [],
    outputs: [{ name: "", type: "address" }] },
  { type: "function", name: "readFeedback", stateMutability: "view",
    inputs: [{ name: "agentId", type: "uint256" }, { name: "clientAddress", type: "address" },
      { name: "feedbackIndex", type: "uint64" }],
    outputs: [{ name: "value", type: "int128" }, { name: "valueDecimals", type: "uint8" },
      { name: "tag1", type: "string" }, { name: "tag2", type: "string" },
      { name: "isRevoked", type: "bool" }] },
] as const satisfies Abi;

const validationAbi = [
  { type: "function", name: "getIdentityRegistry", stateMutability: "view", inputs: [],
    outputs: [{ name: "", type: "address" }] },
  { type: "function", name: "getValidationStatus", stateMutability: "view",
    inputs: [{ name: "requestHash", type: "bytes32" }],
    outputs: [{ name: "validatorAddress", type: "address" }, { name: "agentId", type: "uint256" },
      { name: "response", type: "uint8" }, { name: "responseHash", type: "bytes32" },
      { name: "tag", type: "string" }, { name: "lastUpdate", type: "uint256" }] },
] as const satisfies Abi;

/** OpenZeppelin Ownable `owner()`, present on all three UUPS proxies. */
const ownableAbi = [
  { type: "function", name: "owner", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "address" }] },
] as const satisfies Abi;

export const VALIDATION_RESPONSE_EVENT_ABI = [
  { type: "event", name: "ValidationResponse", inputs: [
    { name: "validatorAddress", type: "address", indexed: true },
    { name: "agentId", type: "uint256", indexed: true },
    { name: "requestHash", type: "bytes32", indexed: true },
    { name: "response", type: "uint8", indexed: false },
    { name: "responseURI", type: "string", indexed: false },
    { name: "responseHash", type: "bytes32", indexed: false },
    { name: "tag", type: "string", indexed: false },
  ] },
] as const satisfies Abi;

export const VALIDATION_RESPONSE_TOPIC =
  keccak256(toBytes("ValidationResponse(address,uint256,bytes32,uint8,string,bytes32,string)"));

/** Decoded `getValidationStatus` storage. It cannot say whether a response was ever written. */
export interface ValidationStatusReading {
  requestHash: string;
  validator: string;
  agentId: bigint;
  response: number;
  responseHash: string;
  tag: string;
  lastUpdate: bigint;
}

/**
 * Attributes a validation response only from a supplied or observed ValidationResponse
 * log for the exact request hash, emitted by the pinned Validation registry at or before
 * the anchor. Logs for other request hashes are ignored, so they never attribute a
 * response. Without a matching log the state is explicitly pending_or_unobserved.
 */
export function attributeValidationStatus(status: ValidationStatusReading, logs: readonly unknown[],
  anchorNumber: bigint): AgentRegistryValidationClaim {
  const matches: { blockNumber: bigint; logIndex: bigint; transactionHash: string;
    response: number; responseHash: string; tag: string }[] = [];
  for (const raw of logs) {
    const log = record(raw);
    if (typeof log.address !== "string" || log.address.toLowerCase() !== AGENT_REGISTRY_PROXIES.validation) continue;
    if (!Array.isArray(log.topics) || typeof log.topics[0] !== "string" ||
      log.topics[0].toLowerCase() !== VALIDATION_RESPONSE_TOPIC) continue;
    if (log.removed !== false) continue;
    if (typeof log.data !== "string" || log.topics.some((topic) => typeof topic !== "string")) {
      throw new ApiBoundaryError("SOURCE_MALFORMED");
    }
    let args: { validatorAddress: string; agentId: bigint; requestHash: string; response: number;
      responseHash: string; tag: string };
    try {
      args = decodeEventLog({ abi: VALIDATION_RESPONSE_EVENT_ABI, eventName: "ValidationResponse", strict: true,
        data: log.data as `0x${string}`,
        topics: log.topics as [`0x${string}`, ...`0x${string}`[]] }).args;
    } catch { throw new ApiBoundaryError("SOURCE_MALFORMED"); }
    if (args.requestHash.toLowerCase() !== status.requestHash) continue;
    // Only the stored validator can write a response for this request; anything else is a conflicting source.
    if (args.validatorAddress.toLowerCase() !== status.validator || args.agentId !== status.agentId) {
      throw new ApiBoundaryError("SOURCE_CONFLICT");
    }
    const blockNumber = parseHexQuantity(log.blockNumber);
    if (blockNumber > anchorNumber) continue;
    matches.push({ blockNumber, logIndex: parseHexQuantity(log.logIndex), transactionHash: hash(log.transactionHash),
      response: args.response, responseHash: args.responseHash.toLowerCase(), tag: args.tag });
  }

  if (matches.length === 0) {
    return { state: "pending_or_unobserved", requestHash: status.requestHash, namedValidator: status.validator,
      agentId: status.agentId.toString(10), lastUpdate: status.lastUpdate.toString(10),
      relationship: "request_names_validator_without_observed_response", reason: VALIDATION_PENDING_REASON };
  }
  const latest = matches.reduce((current, candidate) =>
    candidate.blockNumber > current.blockNumber ||
    (candidate.blockNumber === current.blockNumber && candidate.logIndex > current.logIndex) ? candidate : current);
  // Storage keeps only the latest response. A different value means a newer response was not observed.
  if (latest.response !== status.response || latest.responseHash !== status.responseHash || latest.tag !== status.tag) {
    throw new ApiBoundaryError("SOURCE_CONFLICT");
  }
  return { state: "responded", requestHash: status.requestHash, validator: status.validator,
    agentId: status.agentId.toString(10), response: status.response, responseHash: status.responseHash,
    tag: status.tag, lastUpdate: status.lastUpdate.toString(10),
    responseEvent: { transactionHash: latest.transactionHash, blockNumber: latest.blockNumber.toString(10),
      logIndex: latest.logIndex.toString(10) },
    relationship: "validator_specific_response" };
}

/** M05 reads no event logs, so no response can be attributed from this adapter yet. */
const NO_OBSERVED_VALIDATION_LOGS: readonly unknown[] = Object.freeze([]);

function decode(abi: Abi, functionName: string, data: unknown): unknown {
  if (typeof data !== "string" || !/^0x(?:[0-9a-f]{2})*$/u.test(data)) {
    throw new ApiBoundaryError("SOURCE_MALFORMED");
  }
  try {
    const decodeResult = decodeFunctionResult as unknown as (options: {
      abi: Abi; functionName: string; data: `0x${string}`;
    }) => unknown;
    return decodeResult({ abi, functionName, data: data as `0x${string}` });
  }
  catch { throw new ApiBoundaryError("SOURCE_MALFORMED"); }
}

function fixedPoint(value: bigint, decimals: number): string {
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 18) throw new ApiBoundaryError("SOURCE_MALFORMED");
  if (decimals === 0) return value.toString(10);
  const negative = value < 0n;
  const digits = (negative ? -value : value).toString(10).padStart(decimals + 1, "0");
  const whole = digits.slice(0, -decimals).replace(/^0+(?=\d)/u, "");
  const fraction = digits.slice(-decimals).replace(/0+$/u, "");
  const unsigned = fraction ? `${whole}.${fraction}` : whole;
  return negative && unsigned !== "0" ? `-${unsigned}` : unsigned;
}

export class AgentRegistryService {
  constructor(private readonly rpc: ArcRpcReader, private readonly now: () => string = () => new Date().toISOString()) {}

  private async contractCall(abi: Abi, functionName: string, args: readonly unknown[], to: string,
    blockNumber: string, lease: SourceLease, signal: AbortSignal, revertAsNotFound = false): Promise<unknown> {
    let data: `0x${string}`;
    try { data = encodeFunctionData({ abi, functionName, args }); }
    catch { throw new ApiBoundaryError("INTERNAL_ERROR"); }
    const result = await this.rpc.call("eth_call", [{ to, data }, blockNumber], lease, signal,
      revertAsNotFound ? { revertAsNotFound: true } : undefined);
    return decode(abi, functionName, result);
  }

  /** A failed or malformed read is recorded as unknown (never verified) instead of hiding the evidence. */
  private async optionalRead(read: () => Promise<`0x${string}`>, signal: AbortSignal): Promise<`0x${string}` | null> {
    try { return await read(); }
    catch (error) {
      if (signal.aborted || !(error instanceof ApiBoundaryError)) throw error;
      return null;
    }
  }

  private async readImplementation(proxy: string, anchor: ParsedBlock, lease: SourceLease,
    signal: AbortSignal): Promise<`0x${string}`> {
    const slot = await this.rpc.call("eth_getStorageAt",
      [proxy, ARC_ERC8004_DEPLOYMENT.implementationSlot, anchor.numberHex], lease, signal);
    if (typeof slot !== "string" || !/^0x0{24}[0-9a-f]{40}$/u.test(slot)) throw new ApiBoundaryError("SOURCE_MALFORMED");
    return `0x${slot.slice(26)}`;
  }

  private async readDeployment(anchor: ParsedBlock, lease: SourceLease,
    signal: AbortSignal): Promise<AgentRegistryDeploymentCheck> {
    const implementations = {} as Record<AgentRegistryKey, `0x${string}` | null>;
    const owners = {} as Record<AgentRegistryKey, `0x${string}` | null>;
    for (const key of AGENT_REGISTRY_KEYS) {
      implementations[key] = await this.optionalRead(() =>
        this.readImplementation(AGENT_REGISTRY_PROXIES[key], anchor, lease, signal), signal);
    }
    for (const key of AGENT_REGISTRY_KEYS) {
      owners[key] = await this.optionalRead(async () => this.requireAddress(await this.contractCall(ownableAbi, "owner", [],
        AGENT_REGISTRY_PROXIES[key], anchor.numberHex, lease, signal)), signal);
    }
    const check = (key: AgentRegistryKey) => {
      const pinnedImplementation = ARC_ERC8004_DEPLOYMENT.implementations[key];
      const pinnedOwner = ARC_ERC8004_DEPLOYMENT.proxyOwner;
      return { proxy: AGENT_REGISTRY_PROXIES[key], pinnedImplementation, observedImplementation: implementations[key],
        implementation: compareDeploymentPin(implementations[key], pinnedImplementation),
        pinnedOwner, observedOwner: owners[key], owner: compareDeploymentPin(owners[key], pinnedOwner) };
    };
    const registries = { identity: check("identity"), reputation: check("reputation"), validation: check("validation") };
    return { status: deploymentStatus(registries), implementationSlot: ARC_ERC8004_DEPLOYMENT.implementationSlot,
      sourceRevision: ARC_ERC8004_DEPLOYMENT.sourceRevision, reviewedAt: ARC_ERC8004_DEPLOYMENT.reviewedAt, registries };
  }

  async observe(input: AgentRegistryEvidenceRequest, lease: SourceLease,
    signal: AbortSignal): Promise<AgentRegistryEvidence> {
    requireChainId(await this.rpc.call("eth_chainId", [], lease, signal));
    const anchor = block(await this.rpc.call("eth_getBlockByNumber", ["latest", false], lease, signal));
    const agentId = BigInt(input.agentId);
    const identity = AGENT_REGISTRY_PROXIES.identity;
    const reputation = AGENT_REGISTRY_PROXIES.reputation;
    const validation = AGENT_REGISTRY_PROXIES.validation;

    const owner = this.requireAddress(await this.contractCall(identityAbi, "ownerOf", [agentId], identity,
      anchor.numberHex, lease, signal, true));
    const metadataUri = this.requireString(await this.contractCall(identityAbi, "tokenURI", [agentId], identity,
      anchor.numberHex, lease, signal), 4096);
    const agentWallet = this.requireAddress(await this.contractCall(identityAbi, "getAgentWallet", [agentId], identity,
      anchor.numberHex, lease, signal));
    const reputationBinding = this.requireAddress(await this.contractCall(reputationAbi, "getIdentityRegistry", [], reputation,
      anchor.numberHex, lease, signal));
    const validationBinding = this.requireAddress(await this.contractCall(validationAbi, "getIdentityRegistry", [], validation,
      anchor.numberHex, lease, signal));
    if (reputationBinding !== identity || validationBinding !== identity) throw new ApiBoundaryError("SOURCE_CONFLICT");
    // Proxies are upgradeable by one owner: re-read implementation and owner at this exact anchor.
    const deployment = await this.readDeployment(anchor, lease, signal);

    let feedback: AgentRegistryEvidence["feedback"] = null;
    if (input.feedbackQuery) {
      const observer = input.feedbackQuery.clientAddress;
      if (observer === owner || observer === agentWallet) throw new ApiBoundaryError("SOURCE_CONFLICT");
      const decoded = await this.contractCall(reputationAbi, "readFeedback",
        [agentId, observer, BigInt(input.feedbackQuery.feedbackIndex)], reputation,
        anchor.numberHex, lease, signal, true);
      if (!Array.isArray(decoded) || decoded.length !== 5 || typeof decoded[0] !== "bigint" ||
        typeof decoded[1] !== "number" || typeof decoded[2] !== "string" || typeof decoded[3] !== "string" ||
        typeof decoded[4] !== "boolean") throw new ApiBoundaryError("SOURCE_MALFORMED");
      feedback = { observer, feedbackIndex: input.feedbackQuery.feedbackIndex, value: decoded[0].toString(10),
        valueDecimals: decoded[1], decimal: fixedPoint(decoded[0], decoded[1]), tag1: this.requireString(decoded[2], 160),
        tag2: this.requireString(decoded[3], 160), revoked: decoded[4], relationship: "observer_specific_claim" };
    }

    let validationClaim: AgentRegistryEvidence["validation"] = null;
    if (input.validationRequestHash) {
      const decoded = await this.contractCall(validationAbi, "getValidationStatus", [input.validationRequestHash], validation,
        anchor.numberHex, lease, signal);
      if (!Array.isArray(decoded) || decoded.length !== 6 || typeof decoded[0] !== "string" ||
        typeof decoded[1] !== "bigint" || typeof decoded[2] !== "number" || typeof decoded[3] !== "string" ||
        typeof decoded[4] !== "string" || typeof decoded[5] !== "bigint") throw new ApiBoundaryError("SOURCE_MALFORMED");
      const validator = this.requireAddress(decoded[0]);
      if (validator === ZERO_ADDRESS) throw new ApiBoundaryError("SOURCE_NOT_FOUND");
      if (decoded[1] !== agentId) throw new ApiBoundaryError("SOURCE_CONFLICT");
      if (!/^0x[0-9a-f]{64}$/u.test(decoded[3])) throw new ApiBoundaryError("SOURCE_MALFORMED");
      validationClaim = attributeValidationStatus({ requestHash: input.validationRequestHash, validator, agentId,
        response: decoded[2], responseHash: decoded[3], tag: this.requireString(decoded[4], 160), lastUpdate: decoded[5] },
      NO_OBSERVED_VALIDATION_LOGS, anchor.number);
    }

    const repeated = block(await this.rpc.call("eth_getBlockByNumber", [anchor.numberHex, false], lease, signal));
    requireSameBlock(anchor, repeated);
    return AgentRegistryEvidenceSchema.parse({
      schemaVersion: "openarc.agent-registry-evidence.v2", network: ARC_TESTNET.caip2, agentId: input.agentId,
      anchor: { blockNumber: anchor.numberDecimal, blockHash: anchor.hash, blockTimestamp: anchor.timestamp,
        finality: "deterministic", confirmations: "1" },
      identity: { owner, agentWallet,
        metadata: { uri: metadataUri, kind: classifyAgentMetadataUri(metadataUri),
          trust: "untrusted_external_metadata", fetched: false } },
      feedback, validation: validationClaim, deployment,
      source: { sourceId: "arc_primary_rpc", registrySourceId: "erc8004_registries",
        origin: ARC_TESTNET.rpcHttp, explorerOrigin: ARC_TESTNET.explorerOrigin, network: ARC_TESTNET.caip2,
        sourceRevision: ARC_ERC8004.sourceRevision, reviewedAt: ARC_ERC8004.reviewedAt,
        specificationStatus: ARC_ERC8004.specificationStatus, contractsRevision: ARC_ERC8004.contractsRevision,
        registries: { identity, reputation, validation }, observedAt: this.now(),
        adapterVersion: AGENT_REGISTRY_ADAPTER_VERSION },
      limitations: [...AGENT_REGISTRY_LIMITATIONS],
    });
  }

  private requireAddress(value: unknown): `0x${string}` {
    if (typeof value !== "string" || !/^0x[0-9a-fA-F]{40}$/u.test(value)) throw new ApiBoundaryError("SOURCE_MALFORMED");
    return value.toLowerCase() as `0x${string}`;
  }

  private requireString(value: unknown, maximum: number): string {
    if (typeof value !== "string" || value.length > maximum) throw new ApiBoundaryError("SOURCE_MALFORMED");
    return value;
  }
}
