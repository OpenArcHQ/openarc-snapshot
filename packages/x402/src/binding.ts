import { getAddress, type Address, type Hex } from "viem";
import { z } from "zod";

import { CommerceActionIdSchema, CommerceGrantAttemptIdSchema, CommerceGrantIdSchema } from "@openarc/shared";

import { X402LaneError, issuePaths } from "./errors.js";
import { ARC_TESTNET_CAIP2, resolveLaneNetwork, type LaneNetworkId } from "./manifest.js";
import {
  digestCanonical,
  isBytes32,
  isLaneDigest,
  isStrictAddressString,
  parseAtomicAmount,
  parseNonce,
  sameAddress,
  type LaneDigest,
} from "./primitives.js";

export const LANE_BINDING_SCHEMA_VERSION = "openarc.x402.lane-binding.v1" as const;

export type LaneRole = "buyer" | "provider";

/**
 * Everything that must be durable BEFORE a signature leaves its holder
 * (contract §4.4, §8). It carries no signature, token or key material.
 */
export interface LanePaymentBinding {
  readonly schemaVersion: typeof LANE_BINDING_SCHEMA_VERSION;
  readonly role: LaneRole;
  readonly network: LaneNetworkId;
  readonly grantId: string;
  readonly actionId: string;
  readonly attemptId: string;
  /** OpenArc grant requirement digest, carried opaquely. */
  readonly grantRequirementDigest: LaneDigest;
  /** Lane-local digest of the exact `accepted` requirement. */
  readonly laneRequirementDigest: LaneDigest;
  readonly verifyingContract: Address;
  readonly asset: Address;
  readonly from: Address;
  readonly to: Address;
  readonly value: string;
  readonly validAfter: string;
  readonly validBefore: string;
  readonly nonce: Hex;
}

const BindingShapeSchema = z.strictObject({
  schemaVersion: z.literal(LANE_BINDING_SCHEMA_VERSION),
  role: z.enum(["buyer", "provider"]),
  network: z.literal(ARC_TESTNET_CAIP2),
  grantId: CommerceGrantIdSchema,
  actionId: CommerceActionIdSchema,
  attemptId: CommerceGrantAttemptIdSchema,
  grantRequirementDigest: z.string(),
  laneRequirementDigest: z.string(),
  verifyingContract: z.string(),
  asset: z.string(),
  from: z.string(),
  to: z.string(),
  value: z.string(),
  validAfter: z.string(),
  validBefore: z.string(),
  nonce: z.string(),
});

/** Re-validate a binding read back from durable storage (e.g. after a restart). */
export function parseLanePaymentBinding(input: unknown): LanePaymentBinding {
  const parsed = BindingShapeSchema.safeParse(input);
  if (!parsed.success) {
    throw new X402LaneError("invalid_binding", issuePaths(parsed.error.issues));
  }
  const value = parsed.data;
  const manifest = resolveLaneNetwork(value.network);
  const issues: string[] = [];
  if (!isLaneDigest(value.grantRequirementDigest)) issues.push("grantRequirementDigest:invalid");
  if (!isLaneDigest(value.laneRequirementDigest)) issues.push("laneRequirementDigest:invalid");
  if (!sameAddress(value.verifyingContract, manifest.eip712.verifyingContract)) {
    issues.push("verifyingContract:not_pinned");
  }
  if (!sameAddress(value.asset, manifest.asset.address)) issues.push("asset:not_pinned");
  if (!isStrictAddressString(value.from)) issues.push("from:invalid");
  if (!isStrictAddressString(value.to)) issues.push("to:invalid");
  if (isStrictAddressString(value.from) && isStrictAddressString(value.to) && sameAddress(value.from, value.to)) {
    issues.push("to:self_transfer");
  }
  for (const [field, positive] of [
    ["value", true],
    ["validAfter", false],
    ["validBefore", true],
  ] as const) {
    try {
      parseAtomicAmount(value[field], field, positive);
    } catch {
      issues.push(`${field}:invalid`);
    }
  }
  if (!isBytes32(value.nonce) || value.nonce !== value.nonce.toLowerCase()) {
    issues.push("nonce:invalid");
  }
  if (issues.length === 0 && BigInt(value.validBefore) <= BigInt(value.validAfter)) {
    issues.push("validBefore:not_after_validAfter");
  }
  if (issues.length > 0) {
    throw new X402LaneError("invalid_binding", issues);
  }
  return Object.freeze({
    ...value,
    network: manifest.caip2,
    grantRequirementDigest: value.grantRequirementDigest as LaneDigest,
    laneRequirementDigest: value.laneRequirementDigest as LaneDigest,
    verifyingContract: manifest.eip712.verifyingContract,
    asset: manifest.asset.address,
    from: getAddress(value.from),
    to: getAddress(value.to),
    nonce: parseNonce(value.nonce),
  });
}

export function digestLaneBinding(binding: LanePaymentBinding): LaneDigest {
  return digestCanonical(binding);
}

export const LANE_AUTHORIZATION_TYPES = Object.freeze({
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
} as const);

/**
 * The EIP-3009 `TransferWithAuthorization` typed data under the
 * `GatewayWalletBatched` v1 domain. `chainId` is the EVM chain id (5042002),
 * never the Gateway domain (26); `verifyingContract` is the GatewayWallet.
 */
export function buildLaneTypedData(binding: LanePaymentBinding) {
  const manifest = resolveLaneNetwork(binding.network);
  return {
    domain: {
      name: manifest.eip712.name,
      version: manifest.eip712.version,
      chainId: manifest.chainId,
      verifyingContract: manifest.eip712.verifyingContract,
    },
    types: LANE_AUTHORIZATION_TYPES,
    primaryType: "TransferWithAuthorization",
    message: {
      from: binding.from,
      to: binding.to,
      value: BigInt(binding.value),
      validAfter: BigInt(binding.validAfter),
      validBefore: BigInt(binding.validBefore),
      nonce: binding.nonce,
    },
  } as const;
}

export type LaneTypedData = ReturnType<typeof buildLaneTypedData>;
