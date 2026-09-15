import { z } from "zod";

import { API_SCHEMA_VERSION, ApiMetaSchema } from "./api.js";
import { ArcAnchorSchema } from "./arc-observation.js";
import { ARC_ERC8004, ARC_ERC8004_DEPLOYMENT, ARC_TESTNET } from "./network.js";
import {
  EvmAddressSchema,
  IsoTimestampSchema,
  SignedCanonicalDecimalSchema,
  SignedCanonicalIntegerSchema,
  TransactionHashSchema,
  Uint256DecimalSchema,
  Uint64DecimalSchema,
} from "./primitives.js";

export const AGENT_REGISTRY_EVIDENCE_PATH = "/v1/private/arc/agent-registry-evidence" as const;

export const AgentRegistryEvidenceRequestSchema = z.strictObject({
  network: z.literal(ARC_TESTNET.caip2),
  agentId: Uint256DecimalSchema,
  feedbackQuery: z.strictObject({
    clientAddress: EvmAddressSchema,
    feedbackIndex: Uint64DecimalSchema,
  }).optional(),
  validationRequestHash: TransactionHashSchema.optional(),
});

function agentRegistrySourceSchema<Adapter extends string>(adapterVersion: Adapter) {
  return z.strictObject({
    sourceId: z.literal("arc_primary_rpc"),
    registrySourceId: z.literal("erc8004_registries"),
    origin: z.literal(ARC_TESTNET.rpcHttp),
    explorerOrigin: z.literal(ARC_TESTNET.explorerOrigin),
    network: z.literal(ARC_TESTNET.caip2),
    sourceRevision: z.literal(ARC_ERC8004.sourceRevision),
    reviewedAt: z.literal(ARC_ERC8004.reviewedAt),
    specificationStatus: z.literal(ARC_ERC8004.specificationStatus),
    contractsRevision: z.literal(ARC_ERC8004.contractsRevision),
    registries: z.strictObject({
      identity: z.literal(ARC_TESTNET.contracts.erc8004IdentityRegistry.toLowerCase()),
      reputation: z.literal(ARC_TESTNET.contracts.erc8004ReputationRegistry.toLowerCase()),
      validation: z.literal(ARC_TESTNET.contracts.erc8004ValidationRegistry.toLowerCase()),
    }),
    observedAt: IsoTimestampSchema,
    adapterVersion: z.literal(adapterVersion),
  });
}

export const AGENT_REGISTRY_ADAPTER_VERSION = "openarc.agent-registry-evidence.m05.v2" as const;
export const AgentRegistrySourceSchema = agentRegistrySourceSchema(AGENT_REGISTRY_ADAPTER_VERSION);
const LegacyAgentRegistrySourceSchema = agentRegistrySourceSchema("openarc.agent-registry-evidence.m05.v1");

const metadataUri = z.string().max(4096);
export type AgentMetadataUriKind = "none" | "https" | "ipfs" | "data" | "other";

function hasUnsafeUriCharacters(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (codePoint !== undefined && (codePoint <= 0x20 || codePoint === 0x7f)) return true;
  }
  return false;
}

function hasSafeHttpsAuthority(uri: string): boolean {
  const remainder = uri.slice("https://".length);
  const boundary = remainder.search(/[/?#]/u);
  const authority = boundary === -1 ? remainder : remainder.slice(0, boundary);
  if (!authority || authority.includes("@")) return false;

  const ipv6Authority = /^\[[0-9a-f:.]+\](?::([0-9]{1,5}))?$/iu.exec(authority);
  const hostAuthority = /^([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::([0-9]{1,5}))?$/iu.exec(authority);
  const port = ipv6Authority?.[1] ?? hostAuthority?.[2];
  return (ipv6Authority !== null || hostAuthority !== null) && (port === undefined || Number(port) <= 65_535);
}

export function classifyAgentMetadataUri(uri: string): AgentMetadataUriKind {
  if (uri === "") return "none";
  if (hasUnsafeUriCharacters(uri)) return "other";
  if (uri.startsWith("https://") && hasSafeHttpsAuthority(uri)) return "https";
  if (uri.startsWith("ipfs://") && uri.length > "ipfs://".length) return "ipfs";
  if (uri.startsWith("data:") && uri.length > "data:".length) return "data";
  return "other";
}

const AgentMetadataSchema = z.strictObject({
  uri: metadataUri,
  kind: z.enum(["none", "https", "ipfs", "data", "other"]),
  trust: z.literal("untrusted_external_metadata"),
  fetched: z.literal(false),
}).superRefine((metadata, context) => {
  if (metadata.kind !== classifyAgentMetadataUri(metadata.uri)) {
    context.addIssue({ code: "custom", message: "Metadata URI kind must match its untrusted text", path: ["kind"] });
  }
});

const IdentitySchema = z.strictObject({
  owner: EvmAddressSchema,
  agentWallet: EvmAddressSchema,
  metadata: AgentMetadataSchema,
});

const FeedbackClaimSchema = z.strictObject({
  observer: EvmAddressSchema,
  feedbackIndex: Uint64DecimalSchema,
  value: SignedCanonicalIntegerSchema,
  valueDecimals: z.number().int().min(0).max(18),
  decimal: SignedCanonicalDecimalSchema,
  tag1: z.string().max(160),
  tag2: z.string().max(160),
  revoked: z.boolean(),
  relationship: z.literal("observer_specific_claim"),
});

/**
 * `getValidationStatus` returns response 0 both for an unanswered request and for a
 * validator that responded 0. A response is attributed only when a matching
 * ValidationResponse event was supplied or observed; otherwise the state is explicit.
 */
export const VALIDATION_PENDING_REASON =
  "No ValidationResponse event for this request hash was supplied or observed. The registry getter returns 0 for both an unanswered request and a response of 0, so no validator response is attributed." as const;

const RespondedValidationClaimSchema = z.strictObject({
  state: z.literal("responded"),
  requestHash: TransactionHashSchema,
  validator: EvmAddressSchema,
  agentId: Uint256DecimalSchema,
  response: z.number().int().min(0).max(100),
  responseHash: TransactionHashSchema,
  tag: z.string().max(160),
  lastUpdate: Uint256DecimalSchema,
  responseEvent: z.strictObject({
    transactionHash: TransactionHashSchema,
    blockNumber: Uint256DecimalSchema,
    logIndex: Uint64DecimalSchema,
  }),
  relationship: z.literal("validator_specific_response"),
});

const PendingValidationClaimSchema = z.strictObject({
  state: z.literal("pending_or_unobserved"),
  requestHash: TransactionHashSchema,
  // Named by the request writer; the validator never consented and has made no attributed claim.
  namedValidator: EvmAddressSchema,
  agentId: Uint256DecimalSchema,
  lastUpdate: Uint256DecimalSchema,
  relationship: z.literal("request_names_validator_without_observed_response"),
  reason: z.literal(VALIDATION_PENDING_REASON),
});

export const AgentRegistryValidationClaimSchema = z.discriminatedUnion("state", [
  RespondedValidationClaimSchema, PendingValidationClaimSchema,
]);

export const AGENT_REGISTRY_KEYS = ["identity", "reputation", "validation"] as const;
export type AgentRegistryKey = typeof AGENT_REGISTRY_KEYS[number];
export type DeploymentCheckOutcome = "match" | "drift" | "unknown";

export const AGENT_REGISTRY_PROXIES = Object.freeze({
  identity: ARC_TESTNET.contracts.erc8004IdentityRegistry.toLowerCase(),
  reputation: ARC_TESTNET.contracts.erc8004ReputationRegistry.toLowerCase(),
  validation: ARC_TESTNET.contracts.erc8004ValidationRegistry.toLowerCase(),
} as const);
const proxies = AGENT_REGISTRY_PROXIES;

export function compareDeploymentPin(observed: string | null, pinned: string): DeploymentCheckOutcome {
  if (observed === null) return "unknown";
  return observed === pinned ? "match" : "drift";
}

function registryDeploymentCheckSchema(registry: AgentRegistryKey) {
  return z.strictObject({
    proxy: z.literal(proxies[registry]),
    pinnedImplementation: z.literal(ARC_ERC8004_DEPLOYMENT.implementations[registry]),
    observedImplementation: EvmAddressSchema.nullable(),
    implementation: z.enum(["match", "drift", "unknown"]),
    pinnedOwner: z.literal(ARC_ERC8004_DEPLOYMENT.proxyOwner),
    observedOwner: EvmAddressSchema.nullable(),
    owner: z.enum(["match", "drift", "unknown"]),
  }).superRefine((check, context) => {
    if (check.implementation !== compareDeploymentPin(check.observedImplementation, check.pinnedImplementation)) {
      context.addIssue({ code: "custom", path: ["implementation"], message: "Implementation outcome must match the observed slot" });
    }
    if (check.owner !== compareDeploymentPin(check.observedOwner, check.pinnedOwner)) {
      context.addIssue({ code: "custom", path: ["owner"], message: "Owner outcome must match the observed owner" });
    }
  });
}

export type AgentRegistryDeploymentStatus = "verified" | "drift" | "unknown";

export function deploymentStatus(registries: Record<AgentRegistryKey,
  { implementation: DeploymentCheckOutcome; owner: DeploymentCheckOutcome }>): AgentRegistryDeploymentStatus {
  const outcomes = AGENT_REGISTRY_KEYS.flatMap((key) => [registries[key].implementation, registries[key].owner]);
  if (outcomes.includes("drift")) return "drift";
  if (outcomes.includes("unknown")) return "unknown";
  return "verified";
}

export const AgentRegistryDeploymentCheckSchema = z.strictObject({
  status: z.enum(["verified", "drift", "unknown"]),
  implementationSlot: z.literal(ARC_ERC8004_DEPLOYMENT.implementationSlot),
  sourceRevision: z.literal(ARC_ERC8004_DEPLOYMENT.sourceRevision),
  reviewedAt: z.literal(ARC_ERC8004_DEPLOYMENT.reviewedAt),
  registries: z.strictObject({
    identity: registryDeploymentCheckSchema("identity"),
    reputation: registryDeploymentCheckSchema("reputation"),
    validation: registryDeploymentCheckSchema("validation"),
  }),
}).superRefine((check, context) => {
  if (check.status !== deploymentStatus(check.registries)) {
    context.addIssue({ code: "custom", path: ["status"], message: "Deployment status must follow every pin comparison" });
  }
});

export type AgentRegistryDeploymentCheck = z.infer<typeof AgentRegistryDeploymentCheckSchema>;

/** Human-readable reasons a deployment check is not verified. Empty only when verified. */
export function describeDeploymentCheck(check: AgentRegistryDeploymentCheck): string[] {
  const reasons: string[] = [];
  for (const key of AGENT_REGISTRY_KEYS) {
    const registry = check.registries[key];
    if (registry.implementation === "drift") {
      reasons.push(`${key} implementation ${registry.observedImplementation} differs from reviewed pin ${registry.pinnedImplementation}`);
    } else if (registry.implementation === "unknown") {
      reasons.push(`${key} implementation slot could not be read`);
    }
    if (registry.owner === "drift") {
      reasons.push(`${key} proxy owner ${registry.observedOwner} differs from reviewed pin ${registry.pinnedOwner}`);
    } else if (registry.owner === "unknown") {
      reasons.push(`${key} proxy owner could not be read`);
    }
  }
  return reasons;
}

const baseLimitations = [
  "ERC-8004 is a draft standard; registry facts may change before finalization.",
  "Identity ownership and metadata are registry claims, not proof of safety, quality, or control.",
  "Feedback is one observer's claim and validation is one validator's response; neither is a universal score.",
  "Metadata is untrusted external text and was not fetched or rendered by OpenArc.",
] as const;

export const AGENT_REGISTRY_LIMITATIONS = [
  ...baseLimitations,
  "A validation request without an observed ValidationResponse event is pending or unobserved, never a validator response of 0.",
  "The registries are owner-upgradeable proxies; implementation and owner were compared with reviewed pins at this block only.",
] as const;

export const AgentRegistryEvidenceSchema = z.strictObject({
  schemaVersion: z.literal("openarc.agent-registry-evidence.v2"),
  network: z.literal(ARC_TESTNET.caip2),
  agentId: Uint256DecimalSchema,
  anchor: ArcAnchorSchema,
  identity: IdentitySchema,
  feedback: FeedbackClaimSchema.nullable(),
  validation: AgentRegistryValidationClaimSchema.nullable(),
  deployment: AgentRegistryDeploymentCheckSchema,
  source: AgentRegistrySourceSchema,
  limitations: z.tuple([
    z.literal(AGENT_REGISTRY_LIMITATIONS[0]), z.literal(AGENT_REGISTRY_LIMITATIONS[1]),
    z.literal(AGENT_REGISTRY_LIMITATIONS[2]), z.literal(AGENT_REGISTRY_LIMITATIONS[3]),
    z.literal(AGENT_REGISTRY_LIMITATIONS[4]), z.literal(AGENT_REGISTRY_LIMITATIONS[5]),
  ]),
});

/**
 * Read-only compatibility for encrypted records saved by the original M05 adapter. Its
 * validation value came from the getter alone and has no deployment check, so the UI
 * must present it as unattributed legacy data. New API responses never use this shape.
 */
export const LegacyAgentRegistryEvidenceV1Schema = z.strictObject({
  schemaVersion: z.literal("openarc.agent-registry-evidence.v1"),
  network: z.literal(ARC_TESTNET.caip2),
  agentId: Uint256DecimalSchema,
  anchor: ArcAnchorSchema,
  identity: IdentitySchema,
  feedback: FeedbackClaimSchema.nullable(),
  validation: z.strictObject({
    requestHash: TransactionHashSchema,
    validator: EvmAddressSchema,
    agentId: Uint256DecimalSchema,
    response: z.number().int().min(0).max(100),
    responseHash: TransactionHashSchema,
    tag: z.string().max(160),
    lastUpdate: Uint256DecimalSchema,
    relationship: z.literal("validator_specific_response"),
  }).nullable(),
  source: LegacyAgentRegistrySourceSchema,
  limitations: z.tuple([
    z.literal(baseLimitations[0]), z.literal(baseLimitations[1]),
    z.literal(baseLimitations[2]), z.literal(baseLimitations[3]),
  ]),
});

export const StoredAgentRegistryEvidenceSchema = z.union([
  AgentRegistryEvidenceSchema, LegacyAgentRegistryEvidenceV1Schema,
]);

export const AgentRegistryEvidenceEnvelopeSchema = z.strictObject({
  ok: z.literal(true),
  data: AgentRegistryEvidenceSchema,
  meta: ApiMetaSchema.extend({ schemaVersion: z.literal(API_SCHEMA_VERSION) }),
});

export type AgentRegistryEvidenceRequest = z.infer<typeof AgentRegistryEvidenceRequestSchema>;
export type AgentRegistryEvidence = z.infer<typeof AgentRegistryEvidenceSchema>;
export type LegacyAgentRegistryEvidenceV1 = z.infer<typeof LegacyAgentRegistryEvidenceV1Schema>;
export type StoredAgentRegistryEvidence = z.infer<typeof StoredAgentRegistryEvidenceSchema>;
export type AgentRegistryValidationClaim = z.infer<typeof AgentRegistryValidationClaimSchema>;
export type AgentRegistryEvidenceEnvelope = z.infer<typeof AgentRegistryEvidenceEnvelopeSchema>;
