import { getAddress, isAddress, sha256, stringToBytes, type Address, type Hex } from "viem";

import { X402LaneError } from "./errors.js";

export const UINT256_MAX = (1n << 256n) - 1n;

const ATOMIC_PATTERN = /^(?:0|[1-9][0-9]{0,77})(?![\s\S])/u;
const ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}(?![\s\S])/u;
const BYTES32_PATTERN = /^0x[0-9a-fA-F]{64}(?![\s\S])/u;
const SIGNATURE_PATTERN = /^0x[0-9a-fA-F]{130}(?![\s\S])/u;
const UUID_PATTERN = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![\s\S])/u;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}(?![\s\S])/u;

export type LaneDigest = `sha256:${string}`;

/**
 * Exact canonical uint256 decimal string. Numbers, floats, exponents, signs,
 * whitespace and leading zeros are all rejected: no float path exists.
 */
export function parseAtomicAmount(value: unknown, field: string, positive: boolean): string {
  if (typeof value !== "string" || !ATOMIC_PATTERN.test(value)) {
    throw new X402LaneError("invalid_amount", [`${field}:not_canonical_integer_string`]);
  }
  const parsed = BigInt(value);
  if (parsed > UINT256_MAX || (positive && parsed === 0n)) {
    throw new X402LaneError("invalid_amount", [`${field}:out_of_range`]);
  }
  return value;
}

export function isStrictAddressString(value: unknown): value is string {
  return typeof value === "string" && ADDRESS_PATTERN.test(value) && isAddress(value, { strict: true });
}

/** Strict 20-byte address (mixed case must carry a valid checksum); never zero. */
export function parseAddress(value: unknown, field: string): Address {
  if (!isStrictAddressString(value)) {
    throw new X402LaneError("invalid_address", [`${field}:invalid`]);
  }
  const address = getAddress(value);
  if (BigInt(address) === 0n) {
    throw new X402LaneError("invalid_address", [`${field}:zero`]);
  }
  return address;
}

export function sameAddress(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

/** Caller-supplied 32-byte nonce, normalised to lower case; all-zero rejected. */
export function parseNonce(value: unknown): Hex {
  if (typeof value !== "string" || !BYTES32_PATTERN.test(value)) {
    throw new X402LaneError("invalid_nonce", ["nonce:not_bytes32"]);
  }
  const nonce = value.toLowerCase() as Hex;
  if (BigInt(nonce) === 0n) {
    throw new X402LaneError("invalid_nonce", ["nonce:zero"]);
  }
  return nonce;
}

export function isBytes32(value: unknown): value is Hex {
  return typeof value === "string" && BYTES32_PATTERN.test(value);
}

export function isSignatureHex(value: unknown): value is Hex {
  return typeof value === "string" && SIGNATURE_PATTERN.test(value);
}

export function isUuid(value: unknown): value is string {
  return typeof value === "string" && UUID_PATTERN.test(value);
}

export function isLaneDigest(value: unknown): value is LaneDigest {
  return typeof value === "string" && DIGEST_PATTERN.test(value);
}

/** Unix seconds as bigint. Accepts a non-negative safe integer or bigint only. */
export function parseUnixSeconds(value: unknown, field: string): bigint {
  if (typeof value === "bigint" && value >= 0n) return value;
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    return BigInt(value);
  }
  throw new X402LaneError("invalid_clock", [`${field}:not_unix_seconds`]);
}

/** Deterministic JSON: sorted keys; only strings, safe integers, booleans, null, arrays, plain objects. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new X402LaneError("invalid_binding", ["canonical:non_integer_number"]);
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  if (typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    return `{${keys
      .filter((key) => record[key] !== undefined)
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(",")}}`;
  }
  throw new X402LaneError("invalid_binding", ["canonical:unsupported_value"]);
}

export function digestCanonical(value: unknown): LaneDigest {
  return `sha256:${sha256(stringToBytes(canonicalJson(value))).slice(2)}`;
}

const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![\s\S])/u;
const MAX_HEADER_LENGTH = 16_384;

export function encodeBase64Json(value: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** Strict standard base64 of UTF-8 JSON. Returns `undefined` on any defect. */
export function decodeBase64Json(value: unknown): unknown {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_HEADER_LENGTH) {
    return undefined;
  }
  if (!BASE64_PATTERN.test(value)) return undefined;
  try {
    const binary = atob(value);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
  } catch {
    return undefined;
  }
}

/** True only for a plain JSON object (rejects arrays, class instances, null-prototype tricks). */
export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}
