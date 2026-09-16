import type { Address } from "viem";
import { z } from "zod";

import { X402LaneError, issuePaths } from "./errors.js";
import { ARC_TESTNET_CAIP2, resolveLaneNetwork, type LaneNetworkId } from "./manifest.js";
import {
  decodeBase64Json,
  digestCanonical,
  isPlainObject,
  isStrictAddressString,
  parseAddress,
  parseAtomicAmount,
  sameAddress,
  type LaneDigest,
} from "./primitives.js";

/**
 * Upper bound on a seller's `maxTimeoutSeconds`: 7 days plus at most one hour.
 * The SDK middleware emits 604900. The SDK signer uses
 * `max(maxTimeoutSeconds, 604900)` as the signature lifetime, so an unbounded
 * seller value would silently lengthen buyer exposure; the facilitator's own
 * upper bound is UNVERIFIED (contract §4.3), so the lane refuses anything larger.
 */
export const LANE_MAX_REQUIREMENT_TIMEOUT_SECONDS = 604800 + 3600;

const RawRequirementSchema = z.strictObject({
  scheme: z.literal("exact"),
  network: z.literal(ARC_TESTNET_CAIP2),
  asset: z.string(),
  amount: z.string(),
  payTo: z.string(),
  maxTimeoutSeconds: z.number().int().min(1).max(LANE_MAX_REQUIREMENT_TIMEOUT_SECONDS),
  extra: z.strictObject({
    name: z.literal("GatewayWalletBatched"),
    version: z.literal("1"),
    verifyingContract: z.string(),
  }),
});

/** The requirement exactly as the seller published it (echoed as `accepted`). */
export type RawLaneRequirement = z.infer<typeof RawRequirementSchema>;

export interface LaneRequirement {
  readonly network: LaneNetworkId;
  readonly scheme: "exact";
  readonly asset: Address;
  /** Canonical positive uint256 atomic string (USDC 6 dp). */
  readonly amount: string;
  readonly payTo: Address;
  readonly maxTimeoutSeconds: number;
  readonly verifyingContract: Address;
  readonly accepted: Readonly<RawLaneRequirement>;
  /** Lane-local digest of `accepted`. Not claimed equal to OpenArc's requirementDigest. */
  readonly digest: LaneDigest;
}

function freezeRaw(raw: RawLaneRequirement): Readonly<RawLaneRequirement> {
  return Object.freeze({ ...raw, extra: Object.freeze({ ...raw.extra }) });
}

/**
 * Strictly parse one x402 v2 payment requirement for this lane. Anything that
 * is not exactly Arc Testnet / `exact` / the pinned GatewayWallet and USDC is
 * rejected, as is every unknown key (so no origin, RPC, calldata, chain id or
 * facilitator override is representable).
 */
export function parseLaneRequirement(input: unknown): LaneRequirement {
  if (!isPlainObject(input) || !isPlainObject(input.extra)) {
    throw new X402LaneError("invalid_requirement", ["<root>:not_plain_object"]);
  }
  const parsed = RawRequirementSchema.safeParse(input);
  if (!parsed.success) {
    throw new X402LaneError("invalid_requirement", issuePaths(parsed.error.issues));
  }
  const raw = parsed.data;
  const manifest = resolveLaneNetwork(raw.network);
  const issues: string[] = [];

  if (!isStrictAddressString(raw.asset) || !sameAddress(raw.asset, manifest.asset.address)) {
    issues.push("asset:not_pinned_usdc");
  }
  if (
    !isStrictAddressString(raw.extra.verifyingContract) ||
    !sameAddress(raw.extra.verifyingContract, manifest.eip712.verifyingContract)
  ) {
    issues.push("extra.verifyingContract:not_pinned_gateway_wallet");
  }
  let amount = "";
  try {
    amount = parseAtomicAmount(raw.amount, "amount", true);
  } catch (error) {
    issues.push(...(error instanceof X402LaneError ? error.issues : ["amount:invalid"]));
  }
  let payTo: Address | undefined;
  try {
    payTo = parseAddress(raw.payTo, "payTo");
    if (
      sameAddress(payTo, manifest.eip712.verifyingContract) ||
      sameAddress(payTo, manifest.asset.address)
    ) {
      issues.push("payTo:contract_address");
    }
  } catch (error) {
    issues.push(...(error instanceof X402LaneError ? error.issues : ["payTo:invalid"]));
  }
  if (issues.length > 0 || payTo === undefined) {
    throw new X402LaneError("invalid_requirement", issues);
  }

  const accepted = freezeRaw(raw);
  return Object.freeze({
    network: manifest.caip2,
    scheme: "exact",
    asset: manifest.asset.address,
    amount,
    payTo,
    maxTimeoutSeconds: raw.maxTimeoutSeconds,
    verifyingContract: manifest.eip712.verifyingContract,
    accepted,
    digest: digestCanonical(accepted),
  });
}

export interface LaneResource {
  readonly url: string;
  readonly description?: string;
  readonly mimeType?: string;
}

const ResourceSchema = z.strictObject({
  url: z.string().min(1).max(2048),
  description: z.string().max(1024).optional(),
  mimeType: z.string().max(255).optional(),
});

const PaymentRequiredSchema = z.strictObject({
  x402Version: z.literal(2),
  error: z.string().max(1024).optional(),
  resource: ResourceSchema,
  accepts: z.array(z.unknown()).length(1),
  extensions: z.record(z.string(), z.unknown()).optional(),
});

export interface LanePaymentRequired {
  readonly x402Version: 2;
  readonly resource: LaneResource;
  readonly requirement: LaneRequirement;
}

export function parseLaneResource(input: unknown): LaneResource {
  const parsed = ResourceSchema.safeParse(input);
  if (!parsed.success) {
    throw new X402LaneError("invalid_payment_required", issuePaths(parsed.error.issues));
  }
  let url: URL;
  try {
    url = new URL(parsed.data.url);
  } catch {
    throw new X402LaneError("invalid_payment_required", ["resource.url:unparseable"]);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new X402LaneError("invalid_payment_required", ["resource.url:not_http"]);
  }
  const resource: { url: string; description?: string; mimeType?: string } = {
    url: parsed.data.url,
  };
  if (parsed.data.description !== undefined) resource.description = parsed.data.description;
  if (parsed.data.mimeType !== undefined) resource.mimeType = parsed.data.mimeType;
  return Object.freeze(resource);
}

/**
 * Parse a v2 `PAYMENT-REQUIRED` envelope. Exactly one `accepts` entry is
 * allowed (the seller must pin `networks: ['eip155:5042002']`), and any
 * non-empty `extensions` object is refused because its behaviour is unreviewed.
 */
export function parseLanePaymentRequired(input: unknown): LanePaymentRequired {
  if (!isPlainObject(input)) {
    throw new X402LaneError("invalid_payment_required", ["<root>:not_plain_object"]);
  }
  const parsed = PaymentRequiredSchema.safeParse(input);
  if (!parsed.success) {
    throw new X402LaneError("invalid_payment_required", issuePaths(parsed.error.issues));
  }
  if (parsed.data.extensions !== undefined && Object.keys(parsed.data.extensions).length > 0) {
    throw new X402LaneError("invalid_payment_required", ["extensions:not_empty"]);
  }
  return Object.freeze({
    x402Version: 2,
    resource: parseLaneResource(parsed.data.resource),
    requirement: parseLaneRequirement(parsed.data.accepts[0]),
  });
}

export function decodeLanePaymentRequiredHeader(header: unknown): LanePaymentRequired {
  const decoded = decodeBase64Json(header);
  if (decoded === undefined) {
    throw new X402LaneError("invalid_payment_required", ["header:not_base64_json"]);
  }
  return parseLanePaymentRequired(decoded);
}
