import { z } from "zod";

/**
 * Bounded commerce grant-token primitives.
 *
 * These are browser-safe, strict Zod contracts for a canonical grant
 * correlation id and a raw `oag_v1_` grant token grammar only. This module
 * neither issues, reserves, claims, delivers, persists, authorizes nor
 * authenticates anything: a parsed token proves no live grant authority, and
 * the future server must bind the principal, scope and tenant.
 *
 * Exactly two exports exist here: the grant id schema/type and the grant token
 * schema/type. No status DTO, receipt, delivery, machine/session/provider
 * namespace or generic opaque credential is representable.
 */

/**
 * Exact lower-case canonical UUIDv4. The version nibble is fixed to `4` and
 * the variant nibble to `8`, `9`, `a` or `b`. `(?![\s\S])` pins the absolute
 * end of input so a trailing newline cannot satisfy `$`. The `openarc:grant:`
 * prefix is literal and no other namespace is accepted.
 */
const GRANT_UUID_PATTERN =
  "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";

export const CommerceGrantIdSchema = z
  .string()
  .regex(
    new RegExp(`^openarc:grant:${GRANT_UUID_PATTERN}(?![\\s\\S])`),
    "Expected a canonical openarc:grant: UUIDv4",
  );

export type CommerceGrantId = z.infer<typeof CommerceGrantIdSchema>;

/**
 * Canonical unpadded base64url encoding of exactly 32 bytes: 43 characters
 * whose final character carries zero padding bits, so only the low two bits of
 * the final base64 index may be zero. Since 32 bytes is `256 = 6 * 42 + 4`
 * bits, 42 full characters carry 252 bits and the final character encodes the
 * remaining 4 bits, of which the low 2 are padding. `(?![\s\S])` again pins the
 * absolute end so a trailing LF cannot satisfy `$`. The accepted session-token
 * grammar is reused verbatim with the distinct `oag_v1_` prefix.
 */
const BASE64URL_FINAL_ALPHABET = "AEIMQUYcgkosw048";
const SECRET_MATERIAL_PATTERN = `[A-Za-z0-9_-]{42}[${BASE64URL_FINAL_ALPHABET}](?![\\s\\S])`;

/**
 * Raw grant token `oag_v1_<43base64url>`. Its distinct namespace cannot accept
 * `oach_v1_`/`oacs_v1_` commerce tokens, machine `oas_ag_`/`oas_pr_`/`oac_*`
 * tokens or any handoff/session/machine/provider namespace.
 */
export const CommerceGrantTokenSchema = z
  .string()
  .regex(
    new RegExp(`^oag_v1_${SECRET_MATERIAL_PATTERN}`),
    "Expected a canonical oag_v1_ grant token",
  );

export type CommerceGrantToken = z.infer<typeof CommerceGrantTokenSchema>;
