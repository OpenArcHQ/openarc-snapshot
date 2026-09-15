import { CommerceActionIdSchema, CommerceApprovalIdSchema } from "@openarc/shared";

/**
 * Protected commerce action/approval route parser.
 *
 * The five protected routes root under `/app/actions`:
 *   - `/app/actions`                        (bounded action queue)
 *   - `/app/actions/approvals`              (bounded approval queue)
 *   - `/app/actions/exposure`               (exact server exposure view)
 *   - `/app/actions/:actionId`              (one action detail + decisions)
 *   - `/app/actions/approvals/:approvalId`  (one approval detail)
 *
 * The literal `approvals` and `exposure` segments are matched BEFORE the
 * dynamic id branch so neither can ever be read as an action id. A dynamic id
 * is decoded EXACTLY once and must round-trip to its own canonical
 * percent-encoding: residual escapes, slashes, backslashes, control characters,
 * non-ASCII lookalikes and unknown suffixes are rejected without constructing
 * any action client or issuing any request.
 *
 * These routes review and decide pending commerce actions. Opening one connects
 * no wallet, signs nothing, moves no money and completes no purchase.
 */

export const ACTION_ROOTS_PATH = "/app/actions" as const;
export const ACTION_APPROVALS_PATH = "/app/actions/approvals" as const;
export const ACTION_EXPOSURE_PATH = "/app/actions/exposure" as const;

export type ActionRoute =
  | { readonly kind: "queue" }
  | { readonly kind: "approvals" }
  | { readonly kind: "exposure" }
  | { readonly kind: "detail"; readonly actionId: string }
  | { readonly kind: "approval-detail"; readonly approvalId: string }
  | { readonly kind: "invalid" };

/** A stable href for a parsed route; a detail route always re-encodes once. */
export function actionRouteHref(route: ActionRoute): string {
  switch (route.kind) {
    case "queue":
      return ACTION_ROOTS_PATH;
    case "approvals":
      return ACTION_APPROVALS_PATH;
    case "exposure":
      return ACTION_EXPOSURE_PATH;
    case "detail":
      return `${ACTION_ROOTS_PATH}/${encodeURIComponent(route.actionId)}`;
    case "approval-detail":
      return `${ACTION_APPROVALS_PATH}/${encodeURIComponent(route.approvalId)}`;
    case "invalid":
      return ACTION_ROOTS_PATH;
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
 * Parses a pathname into an action route, or returns null when the pathname is
 * not part of the action subtree at all. A pathname inside the subtree whose
 * dynamic segment is malformed yields `{ kind: "invalid" }` so the caller can
 * render an honest unavailable state without any request.
 */
export function parseActionRoute(pathname: string): ActionRoute | null {
  const normalized = pathname.replace(/\/+$/u, "") || "/";
  if (normalized === ACTION_ROOTS_PATH) return { kind: "queue" };
  if (!normalized.startsWith(`${ACTION_ROOTS_PATH}/`)) return null;
  const rest = normalized.slice(ACTION_ROOTS_PATH.length + 1);
  if (rest === "approvals") return { kind: "approvals" };
  if (rest === "exposure") return { kind: "exposure" };
  if (rest.startsWith("approvals/")) {
    const approvalSegment = rest.slice("approvals/".length);
    if (approvalSegment.includes("/")) return { kind: "invalid" };
    const approvalId = decodeCanonicalId(approvalSegment, CommerceApprovalIdSchema);
    if (approvalId === null) return { kind: "invalid" };
    return { kind: "approval-detail", approvalId };
  }
  if (rest.includes("/")) return { kind: "invalid" };
  const actionId = decodeCanonicalId(rest, CommerceActionIdSchema);
  if (actionId === null) return { kind: "invalid" };
  return { kind: "detail", actionId };
}

/** True for any pathname in the protected commerce-action subtree. */
export function isActionPath(pathname: string): boolean {
  return parseActionRoute(pathname) !== null;
}
