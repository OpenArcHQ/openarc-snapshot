/**
 * Canonical tenant idempotency key: unpadded base64url of exactly 32 random
 * bytes, whose final character carries zero padding bits. It is a correlation
 * value, never a credential.
 */
import { randomBytes } from "node:crypto";

const CANONICAL = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048](?![\s\S])/u;

export function createIdempotencyKey(): string {
  const bytes = randomBytes(32);
  bytes[31] = (bytes[31] as number) & 0b11;
  const key = bytes.toString("base64url");
  if (!CANONICAL.test(key)) throw new Error("IDEMPOTENCY_KEY_NOT_CANONICAL");
  return key;
}
