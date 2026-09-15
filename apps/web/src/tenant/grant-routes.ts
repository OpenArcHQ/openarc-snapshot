import { CommerceGrantIdSchema } from "@openarc/shared";

/**
 * Protected authorization-grant route parser.
 *
 * The two protected routes root under `/app/grants`:
 *   - `/app/grants`           (grant lookup by exact id — NO list, NO request)
 *   - `/app/grants/:grantId`  (one grant detail + the revoke flow)
 *
 * There is deliberately no queue, page or list route: the accepted grant store
 * exposes no list method and the frozen nine-route registry publishes no browser
 * list endpoint, so this console can only open a grant whose exact canonical id
 * the operator already holds. Inventing a list would mean inventing data.
 *
 * A dynamic id is decoded EXACTLY once and must round-trip to its own canonical
 * percent-encoding: residual escapes, slashes, backslashes, control characters,
 * non-ASCII lookalikes and unknown suffixes are rejected without constructing
 * any grant client or issuing any request.
 *
 * Opening one of these routes connects no wallet, signs nothing, moves no money
 * and completes no purchase. Revoking a grant retires permission; it never
 * refunds, releases or cancels a payment.
 */

export const GRANT_ROOTS_PATH = "/app/grants" as const;

export type GrantRoute =
  | { readonly kind: "lookup" }
  | { readonly kind: "detail"; readonly grantId: string }
  | { readonly kind: "invalid" };

/** A stable href for a parsed route; a detail route always re-encodes once. */
export function grantRouteHref(route: GrantRoute): string {
  switch (route.kind) {
    case "lookup":
      return GRANT_ROOTS_PATH;
    case "detail":
      return `${GRANT_ROOTS_PATH}/${encodeURIComponent(route.grantId)}`;
    case "invalid":
      return GRANT_ROOTS_PATH;
  }
}

function hasControlCharacter(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (codePoint === undefined) continue;
    if (codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f)) {
      return true;
    }
  }
  return false;
}

type IdSchema = { safeParse(value: unknown): { success: true; data: string } | { success: false } };

/**
 * Rejects any segment that is not the canonical single encoding of the given
 * id. `%25` (a literal percent sign) would decode to a residual escape, a
 * slash/backslash cannot appear in a path segment, and a non-ASCII character
 * would be a lookalike. The round-trip re-encode check also rejects a segment
 * whose escapes are non-canonical.
 */
function decodeCanonicalId(rawSegment: string, schema: IdSchema): string | null {
  if (rawSegment.length === 0) return null;
  if (rawSegment.includes("/") || rawSegment.includes("\\")) return null;
  if (hasControlCharacter(rawSegment)) return null;
  if (!/^[\x20-\x7e]*$/u.test(rawSegment)) return null;
  if (rawSegment.includes("%25")) return null;
  let decoded: string;
  try {
    decoded = decodeURIComponent(rawSegment);
  } catch {
    return null;
  }
  if (decoded.includes("%") || decoded.includes("/") || decoded.includes("\\")) return null;
  const parsed = schema.safeParse(decoded);
  if (!parsed.success) return null;
  if (encodeURIComponent(parsed.data) !== rawSegment) return null;
  return parsed.data;
}

/**
 * Parses a pathname into a grant route, or returns null when the pathname is
 * not part of the grant subtree at all. A pathname inside the subtree whose
 * dynamic segment is malformed yields `{ kind: "invalid" }` so the caller can
 * render an honest unavailable state without any request.
 */
export function parseGrantRoute(pathname: string): GrantRoute | null {
  const normalized = pathname.replace(/\/+$/u, "") || "/";
  if (normalized === GRANT_ROOTS_PATH) return { kind: "lookup" };
  if (!normalized.startsWith(`${GRANT_ROOTS_PATH}/`)) return null;
  const rest = normalized.slice(GRANT_ROOTS_PATH.length + 1);
  if (rest.includes("/")) return { kind: "invalid" };
  const grantId = decodeCanonicalId(rest, CommerceGrantIdSchema);
  if (grantId === null) return { kind: "invalid" };
  return { kind: "detail", grantId };
}

/** True for any pathname in the protected authorization-grant subtree. */
export function isGrantPath(pathname: string): boolean {
  return parseGrantRoute(pathname) !== null;
}
