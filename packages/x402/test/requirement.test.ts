import { describe, expect, it } from "vitest";

import {
  X402LaneError,
  decodeLanePaymentRequiredHeader,
  parseAtomicAmount,
  parseLanePaymentRequired,
  parseLaneRequirement,
} from "../src/index.js";
import {
  GATEWAY_WALLET,
  MAINNET_GATEWAY_WALLET,
  USDC,
  paymentRequiredEnvelope,
  rawRequirement,
  throwawayAccount,
} from "./fixtures.js";

const PAY_TO = throwawayAccount().account.address;

function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (error) {
    return error instanceof X402LaneError ? error.code : "non_lane_error";
  }
  return "no_throw";
}

describe("lane requirement parser", () => {
  it("accepts the exact SDK-shaped Arc Testnet requirement", () => {
    const requirement = parseLaneRequirement(rawRequirement(PAY_TO));
    expect(requirement.network).toBe("eip155:5042002");
    expect(requirement.amount).toBe("10000");
    expect(requirement.payTo).toBe(PAY_TO);
    expect(requirement.verifyingContract).toBe(GATEWAY_WALLET);
    expect(requirement.digest).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(Object.isFrozen(requirement.accepted.extra)).toBe(true);
    // Lower-case pinned values (as served by /supported) are equally accepted.
    expect(
      parseLaneRequirement(
        rawRequirement(PAY_TO, {
          extra: { name: "GatewayWalletBatched", version: "1", verifyingContract: GATEWAY_WALLET.toLowerCase() },
        }),
      ).verifyingContract,
    ).toBe(GATEWAY_WALLET);
  });

  it.each([
    ["scheme", { scheme: "upto" }],
    ["network base sepolia", { network: "eip155:84532" }],
    ["network ethereum mainnet", { network: "eip155:1" }],
    ["network unverified arc mainnet id", { network: "eip155:1243" }],
    ["network v1 name", { network: "arc-testnet" }],
    ["asset other token", { asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e" }],
    ["asset gateway wallet", { asset: GATEWAY_WALLET }],
    ["asset bad checksum", { asset: "0x3600000000000000000000000000000000000000".replace("0x36", "0xZ6") }],
    ["payTo zero", { payTo: "0x0000000000000000000000000000000000000000" }],
    ["payTo gateway wallet", { payTo: GATEWAY_WALLET }],
    ["payTo usdc", { payTo: USDC }],
    ["payTo bad checksum", { payTo: `0x${PAY_TO.slice(2).toLowerCase().replace(/[a-f]/u, "A")}` }],
    ["maxTimeoutSeconds float", { maxTimeoutSeconds: 604900.5 }],
    ["maxTimeoutSeconds string", { maxTimeoutSeconds: "604900" }],
    ["maxTimeoutSeconds huge", { maxTimeoutSeconds: 31_536_000 }],
    ["maxTimeoutSeconds zero", { maxTimeoutSeconds: 0 }],
    ["extra name", { extra: { name: "USD Coin", version: "1", verifyingContract: GATEWAY_WALLET } }],
    ["extra version", { extra: { name: "GatewayWalletBatched", version: "2", verifyingContract: GATEWAY_WALLET } }],
    [
      "extra mainnet verifying contract",
      { extra: { name: "GatewayWalletBatched", version: "1", verifyingContract: MAINNET_GATEWAY_WALLET } },
    ],
    ["extra usdc as verifying contract", { extra: { name: "GatewayWalletBatched", version: "1", verifyingContract: USDC } }],
    ["extra missing", { extra: undefined }],
  ])("rejects non-pinned field: %s", (_label, overrides) => {
    expect(codeOf(() => parseLaneRequirement(rawRequirement(PAY_TO, overrides)))).toBe("invalid_requirement");
  });

  it.each([
    ["decimal float", "0.01"],
    ["dollar price", "$0.01"],
    ["exponent", "1e6"],
    ["negative", "-1"],
    ["leading zero", "010000"],
    ["leading space", " 10000"],
    ["trailing newline", "10000\n"],
    ["hex", "0x2710"],
    ["zero", "0"],
    ["uint256 overflow", (1n << 256n).toString()],
    ["empty", ""],
  ])("rejects non-integer-string amount: %s", (_label, amount) => {
    expect(codeOf(() => parseLaneRequirement(rawRequirement(PAY_TO, { amount })))).toBe("invalid_requirement");
  });

  it("rejects numeric (float-path) amounts outright", () => {
    expect(codeOf(() => parseLaneRequirement(rawRequirement(PAY_TO, { amount: 10000 })))).toBe("invalid_requirement");
    expect(codeOf(() => parseAtomicAmount(0.01, "amount", true))).toBe("invalid_amount");
    expect(parseAtomicAmount(((1n << 256n) - 1n).toString(), "amount", true)).toBe(((1n << 256n) - 1n).toString());
  });

  it.each(["facilitatorUrl", "facilitatorOrigin", "origin", "url", "rpcUrl", "calldata", "data", "chainId", "decimals"])(
    "rejects client-supplied override key %s at root and in extra",
    (key) => {
      expect(codeOf(() => parseLaneRequirement({ ...rawRequirement(PAY_TO), [key]: "x" }))).toBe("invalid_requirement");
      const base = rawRequirement(PAY_TO);
      expect(codeOf(() => parseLaneRequirement({ ...base, extra: { ...base.extra, [key]: "x" } }))).toBe(
        "invalid_requirement",
      );
    },
  );

  it("rejects a JSON __proto__ key and non-plain inputs", () => {
    const polluted = JSON.parse(
      JSON.stringify(rawRequirement(PAY_TO)).replace("{", '{"__proto__":{"payTo":"0x0"},'),
    ) as unknown;
    expect(codeOf(() => parseLaneRequirement(polluted))).toBe("invalid_requirement");
    expect(codeOf(() => parseLaneRequirement(null))).toBe("invalid_requirement");
    expect(codeOf(() => parseLaneRequirement([rawRequirement(PAY_TO)]))).toBe("invalid_requirement");
  });

  it("never echoes received values in error issues", () => {
    try {
      parseLaneRequirement(rawRequirement(PAY_TO, { amount: "0.013371337", payTo: "0xdeadbeefdeadbeef" }));
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(X402LaneError);
      expect(String((error as Error).message)).not.toContain("0.013371337");
      expect(String((error as Error).message)).not.toContain("deadbeef");
    }
  });
});

describe("PAYMENT-REQUIRED envelope", () => {
  it("accepts exactly one v2 lane requirement and round-trips the base64 header", () => {
    const envelope = paymentRequiredEnvelope(PAY_TO);
    const parsed = parseLanePaymentRequired(envelope);
    expect(parsed.requirement.payTo).toBe(PAY_TO);
    const header = Buffer.from(JSON.stringify(envelope), "utf8").toString("base64");
    expect(decodeLanePaymentRequiredHeader(header).requirement.digest).toBe(parsed.requirement.digest);
  });

  it("rejects v1, multiple accepts, extensions, bad resource and bad base64", () => {
    const envelope = paymentRequiredEnvelope(PAY_TO);
    const cases: unknown[] = [
      { ...envelope, x402Version: 1 },
      { ...envelope, accepts: [...envelope.accepts, rawRequirement(PAY_TO, { network: "eip155:84532" })] },
      { ...envelope, accepts: [] },
      { ...envelope, extensions: { bazaar: {} } },
      { ...envelope, resource: { url: "javascript:alert(1)" } },
      { ...envelope, facilitatorUrl: "https://gateway-api.circle.com" },
    ];
    for (const candidate of cases) {
      expect(codeOf(() => parseLanePaymentRequired(candidate))).toBe("invalid_payment_required");
    }
    expect(codeOf(() => parseLanePaymentRequired({ ...envelope, accepts: [rawRequirement(PAY_TO, { scheme: "upto" })] }))).toBe(
      "invalid_requirement",
    );
    for (const header of ["", "not base64!", "e30", Buffer.from("[1]").toString("base64")]) {
      expect(codeOf(() => decodeLanePaymentRequiredHeader(header))).toMatch(/^invalid_payment_required$/u);
    }
  });
});
