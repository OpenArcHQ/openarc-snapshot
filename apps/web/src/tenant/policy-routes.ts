import { CommercePolicyIdSchema } from "@openarc/shared";

/**
 * Protected policy-rules route parser.
 *
 * The three protected routes root under `/app/budgets`:
 *   - `/app/budgets`                 (bounded owner root list)
 *   - `/app/budgets/new`             (first-revision create form)
 *   - `/app/budgets/:policyId`       (root detail + immutable revision history)
 *
 * `/new` is matched BEFORE the dynamic id branch so it can never be read as a
 * policy id. A dynamic id is decoded EXACTLY once and must round-trip to its
 * own canonical percent-encoding: residual escapes, slashes, backslashes,
 * control characters, non-ASCII lookalikes and unknown suffixes are rejected
 * without constructing any policy client or issuing any request.
 *
 * These routes manage policy RULES only. No funds are reserved, committed,
 * moved or executed here, and no budget/counter is implied.
 */

export const POLICY_ROOTS_PATH = "/app/budgets" as const;
export const POLICY_NEW_PATH = "/app/budgets/new" as const;

export type PolicyRoute =
  | { readonly kind: "roots" }
  | { readonly kind: "new" }
  | { readonly kind: "detail"; readonly policyId: string }
  | { readonly kind: "invalid" };

/** A stable href for a parsed route; a detail route always re-encodes once. */
export function policyRouteHref(route: PolicyRoute): string {
  switch (route.kind) {
    case "roots":
      return POLICY_ROOTS_PATH;
    case "new":
      return POLICY_NEW_PATH;
    case "detail":
      return `${POLICY_ROOTS_PATH}/${encodeURIComponent(route.policyId)}`;
    case "invalid":
      return POLICY_ROOTS_PATH;
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

/**
 * Rejects any segment that is not the canonical single encoding of a policy
 * id. `%25` (a literal percent sign) would decode to a residual escape, a
 * slash/backslash cannot appear in a path segment, and a non-ASCII character
 * would be a lookalike. The round-trip re-encode check also rejects a segment
 * whose escapes are non-canonical.
 */
function decodeCanonicalPolicyId(rawSegment: string): string | null {
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
  const parsed = CommercePolicyIdSchema.safeParse(decoded);
  if (!parsed.success) return null;
  if (encodeURIComponent(parsed.data) !== rawSegment) return null;
  return parsed.data;
}

/**
 * Parses a pathname into a policy route, or returns null when the pathname is
 * not part of the policy subtree at all. A pathname inside the subtree whose
 * dynamic segment is malformed yields `{ kind: "invalid" }` so the caller can
 * render an honest unavailable state without any request.
 */
export function parsePolicyRoute(pathname: string): PolicyRoute | null {
  const normalized = pathname.replace(/\/+$/u, "") || "/";
  if (normalized === POLICY_ROOTS_PATH) return { kind: "roots" };
  if (!normalized.startsWith(`${POLICY_ROOTS_PATH}/`)) return null;
  const rest = normalized.slice(POLICY_ROOTS_PATH.length + 1);
  if (rest === "new") return { kind: "new" };
  if (rest.includes("/")) return { kind: "invalid" };
  const policyId = decodeCanonicalPolicyId(rest);
  if (policyId === null) return { kind: "invalid" };
  return { kind: "detail", policyId };
}

/** True for any pathname in the protected policy subtree. */
export function isPolicyPath(pathname: string): boolean {
  return parsePolicyRoute(pathname) !== null;
}
