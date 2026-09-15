import { z } from "zod";

import { EvmAddressSchema } from "./primitives.js";

const ArcTestnetContractsSchema = z.strictObject({
  usdc: EvmAddressSchema,
  gatewayWallet: EvmAddressSchema,
  gatewayMinter: EvmAddressSchema,
  erc8004IdentityRegistry: EvmAddressSchema,
  erc8004ReputationRegistry: EvmAddressSchema,
  erc8004ValidationRegistry: EvmAddressSchema,
  erc8183AgenticCommerce: EvmAddressSchema,
});

export const ArcTestnetConfigSchema = z.strictObject({
  id: z.literal("arc-testnet"),
  environment: z.literal("testnet"),
  chainId: z.literal("5042002"),
  chainIdHex: z.literal("0x4cef52"),
  caip2: z.literal("eip155:5042002"),
  currencySymbol: z.literal("USDC"),
  nativeDecimals: z.literal(18),
  erc20UsdcDecimals: z.literal(6),
  rpcHttp: z.literal("https://rpc.testnet.arc.io"),
  rpcWebSocket: z.literal("wss://rpc.testnet.arc.io"),
  explorerOrigin: z.literal("https://testnet.arcscan.app"),
  faucetOrigin: z.literal("https://faucet.circle.com"),
  usdcSystemEmitter: z.literal("0xfffffffffffffffffffffffffffffffffffffffe"),
  transferTopic: z.literal("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"),
  gatewayDomain: z.literal("26"),
  finality: z.literal("deterministic"),
  executionBaseline: z.literal("osaka"),
  contracts: ArcTestnetContractsSchema,
  reviewedAt: z.literal("2026-09-03"),
  sourceRevision: z.literal("arc-docs-2026-09-03"),
});

const parsedArcTestnet = ArcTestnetConfigSchema.parse({
  id: "arc-testnet",
  environment: "testnet",
  chainId: "5042002",
  chainIdHex: "0x4cef52",
  caip2: "eip155:5042002",
  currencySymbol: "USDC",
  nativeDecimals: 18,
  erc20UsdcDecimals: 6,
  rpcHttp: "https://rpc.testnet.arc.io",
  rpcWebSocket: "wss://rpc.testnet.arc.io",
  explorerOrigin: "https://testnet.arcscan.app",
  faucetOrigin: "https://faucet.circle.com",
  usdcSystemEmitter: "0xfffffffffffffffffffffffffffffffffffffffe",
  transferTopic: "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
  gatewayDomain: "26",
  finality: "deterministic",
  executionBaseline: "osaka",
  contracts: {
    usdc: "0x3600000000000000000000000000000000000000",
    gatewayWallet: "0x0077777d7EBA4688BDeF3E311b846F25870A19B9",
    gatewayMinter: "0x0022222ABE238Cc2C7Bb1f21003F0a260052475B",
    erc8004IdentityRegistry: "0x8004A818BFB912233c491871b3d84c89A494BD9e",
    erc8004ReputationRegistry: "0x8004B663056A597Dffe9eCcC1965A193B7388713",
    erc8004ValidationRegistry: "0x8004Cb1BF31DAf7788923b405b754f57acEB4272",
    erc8183AgenticCommerce: "0x0747EEf0706327138c69792bF28Cd525089e4583",
  },
  reviewedAt: "2026-09-03",
  sourceRevision: "arc-docs-2026-09-03",
});

export const ARC_TESTNET = Object.freeze({
  ...parsedArcTestnet,
  contracts: Object.freeze({ ...parsedArcTestnet.contracts }),
});

export const ARC_ERC8004 = Object.freeze({
  reviewedAt: "2026-09-04",
  sourceRevision: "arc-erc8004-docs-2026-09-04",
  specificationStatus: "draft",
  contractsRevision: "b9e466c250744a7e06b13dff9d3c2844ed64f825",
} as const);

/**
 * Reviewed ERC-1967/UUPS deployment pins for the three ERC-8004 proxies. One EOA can
 * upgrade them, so every observation re-reads the implementation slot and owner at its
 * anchor and reports any difference as drift. Source: PORT-06 contract research
 * 2026-09-15, facts D7 and D13 (read-only eth_getStorageAt / owner() calls).
 */
export const ARC_ERC8004_DEPLOYMENT = Object.freeze({
  reviewedAt: "2026-09-15",
  sourceRevision: "port06-identity-reputation-contract-2026-09-15",
  implementationSlot: "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
  proxyOwner: "0x547289319c3e6aedb179c0b8e8af0b5acd062603",
  implementations: Object.freeze({
    identity: "0x7274e874ca62410a93bd8bf61c69d8045e399c02",
    reputation: "0x16e0fa7f7c56b9a767e34b192b51f921be31da34",
    validation: "0xdb31f5d9167f8ebc8b30fbbf814c4d297c2d7f99",
  } as const),
} as const);

/** Reviewed deployed reference, not an assertion about every ERC-8183 deployment. */
export const ARC_ERC8183 = Object.freeze({
  reviewedAt: "2026-09-04",
  sourceRevision: "arc-erc8183-reference-2026-09-04",
  implementation: "0xa316fd02827242d537f84730f8a37d0ba5fd351a",
  implementationSlot: "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
  sourceSha256: "a16ae3290855910a4c06a59fa691d1d2b56b534e744f15b6f73a6a06ccb1bec4",
} as const);

/**
 * M00 intentionally exports one network only. Public-mainnet parameters and
 * contract addresses were not published in the official Arc references at the
 * review date, so no placeholder or copied Testnet config is allowed here.
 */
export const NETWORKS = Object.freeze({ arcTestnet: ARC_TESTNET });

export type ArcTestnetConfig = z.infer<typeof ArcTestnetConfigSchema>;
