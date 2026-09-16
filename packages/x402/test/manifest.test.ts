import { readFileSync, readdirSync } from "node:fs";

import { ARC_TESTNET } from "@openarc/shared";
import { describe, expect, it } from "vitest";

import {
  ARC_TESTNET_LANE,
  X402LaneError,
  assertLaneFacilitatorOrigin,
  listLaneNetworkIds,
  resolveLaneNetwork,
} from "../src/index.js";

function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (error) {
    return error instanceof X402LaneError ? error.code : "non_lane_error";
  }
  return "no_throw";
}

describe("network manifest", () => {
  it("pins exactly one Arc Testnet entry with the verified facilitator values", () => {
    expect(listLaneNetworkIds()).toEqual(["eip155:5042002"]);
    expect(ARC_TESTNET_LANE).toEqual({
      id: "arc-testnet",
      environment: "testnet",
      caip2: "eip155:5042002",
      chainId: 5042002,
      rpcHttp: "https://rpc.testnet.arc.io",
      facilitatorOrigin: "https://gateway-api-testnet.circle.com",
      x402Version: 2,
      scheme: "exact",
      eip712: {
        name: "GatewayWalletBatched",
        version: "1",
        verifyingContract: "0x0077777d7EBA4688BDeF3E311b846F25870A19B9",
      },
      asset: { symbol: "USDC", address: "0x3600000000000000000000000000000000000000", decimals: 6 },
      minValiditySeconds: 604800,
      reviewedAt: "2026-09-15",
    });
    expect(ARC_TESTNET_LANE.rpcHttp).toBe(ARC_TESTNET.rpcHttp);
    expect(Object.isFrozen(ARC_TESTNET_LANE)).toBe(true);
    expect(Object.isFrozen(ARC_TESTNET_LANE.eip712)).toBe(true);
  });

  it("resolves the testnet id and nothing else, never falling back to mainnet", () => {
    expect(resolveLaneNetwork("eip155:5042002")).toBe(ARC_TESTNET_LANE);
    for (const candidate of [
      undefined,
      null,
      "",
      5042002,
      "eip155:1",
      "eip155:1243",
      "eip155:8453",
      "eip155:84532",
      "arc-mainnet",
      "arc",
      "mainnet",
      "eip155:5042002 ",
      "EIP155:5042002",
      "eip155:*",
      "__proto__",
      "toString",
      "constructor",
    ]) {
      expect(codeOf(() => resolveLaneNetwork(candidate))).toBe("unknown_network");
    }
  });

  it("contains no mainnet or SDK-default endpoint anywhere in the manifest", () => {
    const serialised = JSON.stringify(ARC_TESTNET_LANE).toLowerCase();
    expect(serialised).not.toContain("mainnet");
    expect(serialised).not.toContain("gateway-api.circle.com");
    expect(serialised).not.toContain("arc.network");
  });

  it("accepts only the exact pinned facilitator origin", () => {
    expect(assertLaneFacilitatorOrigin(ARC_TESTNET_LANE, "https://gateway-api-testnet.circle.com")).toBe(
      "https://gateway-api-testnet.circle.com",
    );
    for (const origin of [
      undefined,
      "",
      "https://gateway-api.circle.com",
      "https://gateway-api-testnet.circle.com/",
      "https://gateway-api-testnet.circle.com/v1",
      "http://gateway-api-testnet.circle.com",
      "https://GATEWAY-API-TESTNET.circle.com",
      "https://gateway-api-testnet.circle.com:443",
      "https://user@gateway-api-testnet.circle.com",
      "https://gateway-api-testnet.circle.com.evil.example",
    ]) {
      expect(codeOf(() => assertLaneFacilitatorOrigin(ARC_TESTNET_LANE, origin))).toBe(
        "facilitator_origin_rejected",
      );
    }
  });
});

describe("static source guard", () => {
  const srcDir = new URL("../src/", import.meta.url);
  const sources = readdirSync(srcDir)
    .filter((name) => name.endsWith(".ts"))
    .map((name) => ({ name, text: readFileSync(new URL(name, srcDir), "utf8") }));

  it("never references a mainnet or SDK-default endpoint, pay(), fallbacks, hooks or console", () => {
    expect(sources.length).toBeGreaterThan(5);
    for (const { name, text } of sources) {
      const code = text.replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gmu, "");
      for (const forbidden of [
        "gateway-api.circle.com",
        "arc.network",
        "GatewayClient",
        ".pay(",
        "BatchFacilitatorClient",
        "x402ResourceServer",
        "createGatewayMiddleware",
        "registerBatchScheme",
        "CompositeEvmScheme",
        "fallbackScheme",
        "onSettleFailure",
        "onVerifyFailure",
        "onPaymentResponse",
        "console.",
        "globalThis.fetch",
        "@circle-fin/x402-batching",
      ]) {
        expect({ name, forbidden, present: code.includes(forbidden) }).toEqual({ name, forbidden, present: false });
      }
    }
  });
});
