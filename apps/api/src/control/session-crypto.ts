/**
 * Bounded commerce-session token primitives.
 *
 * Pure generation and hashing only. This module does NOT issue, persist,
 * transport, authorize or log a session; no DB, HTTP, runtime authority,
 * clock or payment behavior lives here.
 */
import { createHash, randomBytes } from "node:crypto";

import {
  CommerceControlHandoffTokenSchema,
  CommerceControlSessionTokenSchema,
} from "@openarc/shared";

/** Fixed hash version for the persisted SHA-256 token digests. */
export const COMMERCE_CONTROL_HASH_VERSION = 1 as const;

/** Exact UTF-8 domain prefixes, NUL-separated from the full canonical token. */
export const COMMERCE_CONTROL_HANDOFF_DOMAIN =
  "openarc.control.commerce-handoff.v1" as const;
export const COMMERCE_CONTROL_SESSION_DOMAIN =
  "openarc.control.commerce-session.v1" as const;

export type CommerceControlCryptoErrorCode =
  | "INVALID_TOKEN"
  | "CRYPTO_FAILURE";

/** Fixed, small, input-free error surface. Never echoes input or cause. */
export class CommerceControlCryptoError extends Error {
  readonly code: CommerceControlCryptoErrorCode;
  constructor(code: CommerceControlCryptoErrorCode) {
    super(code);
    this.name = "CommerceControlCryptoError";
    this.code = code;
  }
}

function fail(code: CommerceControlCryptoErrorCode): never {
  throw new CommerceControlCryptoError(code);
}

const NUL = "\u0000";
const PAYLOAD_BYTES = 32;

/**
 * Generate a fresh 256-bit CSPRNG secret: exactly 43 canonical base64url
 * characters with zero padding bits and no byte masking. The full prefixed
 * token is validated against the accepted shared schema before it is returned.
 */
function generateToken(
  prefix: string,
  schema: {
    safeParse(value: unknown): { success: boolean; data?: string };
  },
): string {
  let entropy: Buffer;
  try {
    entropy = randomBytes(PAYLOAD_BYTES);
  } catch {
    return fail("CRYPTO_FAILURE");
  }
  try {
    if (entropy.length !== PAYLOAD_BYTES) return fail("CRYPTO_FAILURE");
    const token = `${prefix}${entropy.toString("base64url")}`;
    const parsed = schema.safeParse(token);
    if (!parsed.success || parsed.data !== token) return fail("CRYPTO_FAILURE");
    return token;
  } finally {
    entropy.fill(0);
  }
}

/**
 * Hash an exact canonical token as `SHA256(UTF8(domain) || NUL || UTF8(token))`
 * and return 64 lower-case hex characters. Any malformed value rejects with a
 * fixed, non-echoing error; no trim, normalize or fallback occurs.
 */
function hashToken(
  domain: string,
  schema: {
    safeParse(value: unknown): { success: boolean; data?: string };
  },
  value: unknown,
): string {
  const parsed = schema.safeParse(value);
  if (!parsed.success) return fail("INVALID_TOKEN");
  return createHash("sha256")
    .update(`${domain}${NUL}${parsed.data}`, "utf8")
    .digest("hex");
}

/** Generate a fresh canonical `oach_v1_` handoff token. */
export function generateCommerceHandoffToken(): string {
  return generateToken("oach_v1_", CommerceControlHandoffTokenSchema);
}

/** Hash a canonical `oach_v1_` handoff token for persistence. */
export function hashCommerceHandoffToken(value: unknown): string {
  return hashToken(
    COMMERCE_CONTROL_HANDOFF_DOMAIN,
    CommerceControlHandoffTokenSchema,
    value,
  );
}

/** Generate a fresh canonical `oacs_v1_` commerce session token. */
export function generateCommerceSessionToken(): string {
  return generateToken("oacs_v1_", CommerceControlSessionTokenSchema);
}

/** Hash a canonical `oacs_v1_` commerce session token for persistence. */
export function hashCommerceSessionToken(value: unknown): string {
  return hashToken(
    COMMERCE_CONTROL_SESSION_DOMAIN,
    CommerceControlSessionTokenSchema,
    value,
  );
}
