/**
 * Bounded commerce authorization-grant token primitives.
 *
 * Pure generation and hashing only. This module does NOT issue, reserve,
 * claim, deliver, persist, transport, authorize or log a grant; no DB, HTTP,
 * runtime authority, source key, wallet, clock, network, env, log or payment
 * behavior lives here. A token here confers NO actual grant authority.
 */
import { createHash, randomBytes } from "node:crypto";

import { CommerceGrantTokenSchema } from "@openarc/shared";

/** Fixed hash version for the persisted SHA-256 grant token digests. */
export const COMMERCE_GRANT_HASH_VERSION = 1 as const;

/** Exact UTF-8 domain prefix, NUL-separated from the full canonical token. */
export const COMMERCE_GRANT_TOKEN_DOMAIN =
  "openarc.control.authorization-grant.v1" as const;

export type CommerceGrantCryptoErrorCode = "INVALID_TOKEN" | "CRYPTO_FAILURE";

/** Fixed, small, input-free error surface. Never echoes input or cause. */
export class CommerceGrantCryptoError extends Error {
  readonly code: CommerceGrantCryptoErrorCode;
  constructor(code: CommerceGrantCryptoErrorCode) {
    super(code);
    this.name = "CommerceGrantCryptoError";
    this.code = code;
  }
}

function fail(code: CommerceGrantCryptoErrorCode): never {
  throw new CommerceGrantCryptoError(code);
}

const NUL = "\u0000";
const PAYLOAD_BYTES = 32;
const GRANT_TOKEN_PREFIX = "oag_v1_";

/**
 * Generate a fresh 256-bit CSPRNG secret: exactly 43 canonical base64url
 * characters with zero padding bits and no byte masking. The full prefixed
 * token is validated against the accepted shared schema before it is returned,
 * and the entropy buffer is always zeroed, including on failure.
 */
export function generateCommerceGrantToken(): string {
  let entropy: Buffer;
  try {
    entropy = randomBytes(PAYLOAD_BYTES);
  } catch {
    return fail("CRYPTO_FAILURE");
  }
  try {
    if (entropy.length !== PAYLOAD_BYTES) return fail("CRYPTO_FAILURE");
    const token = `${GRANT_TOKEN_PREFIX}${entropy.toString("base64url")}`;
    const parsed = CommerceGrantTokenSchema.safeParse(token);
    if (!parsed.success || parsed.data !== token) return fail("CRYPTO_FAILURE");
    return token;
  } finally {
    entropy.fill(0);
  }
}

/**
 * Hash an exact canonical `oag_v1_` grant token as
 * `SHA256(UTF8(domain) || NUL || UTF8(full canonical token))` and return
 * 64 lower-case hex characters. Malformed input is rejected before any hash
 * primitive runs, and every failure is a fixed, non-echoing error with no raw
 * error or cause leak. No trim, normalize, pepper or fallback occurs.
 */
export function hashCommerceGrantToken(value: unknown): string {
  const parsed = CommerceGrantTokenSchema.safeParse(value);
  if (!parsed.success) return fail("INVALID_TOKEN");
  try {
    return createHash("sha256")
      .update(`${COMMERCE_GRANT_TOKEN_DOMAIN}${NUL}${parsed.data}`, "utf8")
      .digest("hex");
  } catch {
    return fail("CRYPTO_FAILURE");
  }
}
