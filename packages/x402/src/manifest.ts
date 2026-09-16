import { ARC_TESTNET } from "@openarc/shared";
import { getAddress, type Address } from "viem";

import { X402LaneError } from "./errors.js";

/**
 * The one network this lane may ever resolve. There is deliberately no mainnet
 * entry and no default: Circle publishes no Arc mainnet Gateway deployment
 * (docs/engineering/arc-mainnet-readiness-2026-09-15.md), and the SDK's own
 * defaults (`https://gateway-api.circle.com`, `rpc.testnet.arc.network`) must
 * be unreachable through this package.
 */
export const ARC_TESTNET_CAIP2 = "eip155:5042002" as const;
export type LaneNetworkId = typeof ARC_TESTNET_CAIP2;

/** Facilitator advertisement values re-verified live on 2026-09-15 (contract §3.1). */
const PINNED_GATEWAY_WALLET_LOWER = "0x0077777d7eba4688bdef3e311b846f25870a19b9";
const PINNED_USDC_LOWER = "0x3600000000000000000000000000000000000000";
const PINNED_CHAIN_ID = 5042002;

export interface LaneNetworkManifest {
  readonly id: "arc-testnet";
  readonly environment: "testnet";
  readonly caip2: LaneNetworkId;
  readonly chainId: typeof PINNED_CHAIN_ID;
  /** From `ARC_TESTNET` (docs.arc.io), never the SDK/viem default. */
  readonly rpcHttp: typeof ARC_TESTNET.rpcHttp;
  readonly facilitatorOrigin: "https://gateway-api-testnet.circle.com";
  readonly x402Version: 2;
  readonly scheme: "exact";
  readonly eip712: {
    readonly name: "GatewayWalletBatched";
    readonly version: "1";
    /** The GatewayWallet contract, NOT the USDC token. */
    readonly verifyingContract: Address;
  };
  readonly asset: {
    readonly symbol: "USDC";
    readonly address: Address;
    readonly decimals: 6;
  };
  /** Live `/v1/x402/supported` `extra.minValiditySeconds` (undocumented field). */
  readonly minValiditySeconds: 604800;
  readonly reviewedAt: "2026-09-15";
}

function buildArcTestnetEntry(): LaneNetworkManifest {
  if (ARC_TESTNET.caip2 !== ARC_TESTNET_CAIP2) {
    throw new X402LaneError("invalid_config", ["ARC_TESTNET.caip2:drift"]);
  }
  if (Number(ARC_TESTNET.chainId) !== PINNED_CHAIN_ID) {
    throw new X402LaneError("invalid_config", ["ARC_TESTNET.chainId:drift"]);
  }
  if (ARC_TESTNET.contracts.gatewayWallet.toLowerCase() !== PINNED_GATEWAY_WALLET_LOWER) {
    throw new X402LaneError("invalid_config", ["ARC_TESTNET.gatewayWallet:drift"]);
  }
  if (ARC_TESTNET.contracts.usdc.toLowerCase() !== PINNED_USDC_LOWER) {
    throw new X402LaneError("invalid_config", ["ARC_TESTNET.usdc:drift"]);
  }
  if (ARC_TESTNET.erc20UsdcDecimals !== 6) {
    throw new X402LaneError("invalid_config", ["ARC_TESTNET.erc20UsdcDecimals:drift"]);
  }
  return Object.freeze({
    id: "arc-testnet",
    environment: "testnet",
    caip2: ARC_TESTNET_CAIP2,
    chainId: PINNED_CHAIN_ID,
    rpcHttp: ARC_TESTNET.rpcHttp,
    facilitatorOrigin: "https://gateway-api-testnet.circle.com",
    x402Version: 2,
    scheme: "exact",
    eip712: Object.freeze({
      name: "GatewayWalletBatched",
      version: "1",
      verifyingContract: getAddress(PINNED_GATEWAY_WALLET_LOWER),
    }),
    asset: Object.freeze({
      symbol: "USDC",
      address: getAddress(PINNED_USDC_LOWER),
      decimals: 6,
    }),
    minValiditySeconds: 604800,
    reviewedAt: "2026-09-15",
  } as const);
}

export const ARC_TESTNET_LANE: LaneNetworkManifest = buildArcTestnetEntry();

/** Data-driven, single entry. Adding mainnet means adding a reviewed entry here. */
const LANE_NETWORKS: readonly LaneNetworkManifest[] = Object.freeze([ARC_TESTNET_LANE]);

export function listLaneNetworkIds(): readonly LaneNetworkId[] {
  return LANE_NETWORKS.map((entry) => entry.caip2);
}

/** Resolves only an exact, known CAIP-2 id. Missing or unknown always throws. */
export function resolveLaneNetwork(network: unknown): LaneNetworkManifest {
  if (typeof network !== "string") {
    throw new X402LaneError("unknown_network", ["network:missing"]);
  }
  const entry = LANE_NETWORKS.find((candidate) => candidate.caip2 === network);
  if (entry === undefined) {
    throw new X402LaneError("unknown_network", ["network:not_in_manifest"]);
  }
  return entry;
}

/**
 * Accepts only the manifest's exact facilitator origin string. No trailing
 * path, credentials, port, alternate host or mainnet origin is accepted.
 */
export function assertLaneFacilitatorOrigin(
  manifest: LaneNetworkManifest,
  origin: unknown,
): LaneNetworkManifest["facilitatorOrigin"] {
  if (typeof origin !== "string" || origin !== manifest.facilitatorOrigin) {
    throw new X402LaneError("facilitator_origin_rejected", ["facilitatorOrigin:not_pinned"]);
  }
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    throw new X402LaneError("facilitator_origin_rejected", ["facilitatorOrigin:unparseable"]);
  }
  if (parsed.protocol !== "https:" || parsed.origin !== manifest.facilitatorOrigin) {
    throw new X402LaneError("facilitator_origin_rejected", ["facilitatorOrigin:not_https_origin"]);
  }
  return manifest.facilitatorOrigin;
}
