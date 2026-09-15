import { CommerceControlSessionIdSchema } from "@openarc/shared";

/**
 * Protected commerce-session route parser.
 *
 * The three protected routes root under `/app/sessions`:
 *   - `/app/sessions`                 (bounded owner/operator session list)
 *   - `/app/sessions/new`             (human issue form)
 *   - `/app/sessions/:sessionId`      (one session detail + revoke)
 *
 * `/new` is matched BEFORE the dynamic id branch so it can never be read as a
 * session id. A dynamic id is decoded EXACTLY once and must round-trip to its
 * own canonical percent-encoding: residual escapes, slashes, backslashes,
 * control characters, non-ASCII lookalikes and unknown suffixes are rejected
 * without constructing any session client or issuing any request.
 *
 * These routes manage one-time human handoff sessions only. No wallet is
 * connected or signed, no money is reserved and no purchase is made.
 */

export const SESSION_ROOTS_PATH = "/app/sessions" as const;
export const SESSION_NEW_PATH = "/app/sessions/new" as const;

export type SessionRoute =
  | { readonly kind: "roots" }
  | { readonly kind: "new" }
  | { readonly kind: "detail"; readonly sessionId: string }
  | { readonly kind: "invalid" };

/** A stable href for a parsed route; a detail route always re-encodes once. */
export function sessionRouteHref(route: SessionRoute): string {
  switch (route.kind) {
    case "roots":
      return SESSION_ROOTS_PATH;
    case "new":
      return SESSION_NEW_PATH;
    case "detail":
      return `${SESSION_ROOTS_PATH}/${encodeURIComponent(route.sessionId)}`;
    case "invalid":
      return SESSION_ROOTS_PATH;
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
 * Rejects any segment that is not the canonical single encoding of a session
 * id. `%25` (a literal percent sign) would decode to a residual escape, a
 * slash/backslash cannot appear in a path segment, and a non-ASCII character
 * would be a lookalike. The round-trip re-encode check also rejects a segment
 * whose escapes are non-canonical.
 */
function decodeCanonicalSessionId(rawSegment: string): string | null {
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
  const parsed = CommerceControlSessionIdSchema.safeParse(decoded);
  if (!parsed.success) return null;
  if (encodeURIComponent(parsed.data) !== rawSegment) return null;
  return parsed.data;
}

/**
 * Parses a pathname into a session route, or returns null when the pathname is
 * not part of the session subtree at all. A pathname inside the subtree whose
 * dynamic segment is malformed yields `{ kind: "invalid" }` so the caller can
 * render an honest unavailable state without any request.
 */
export function parseSessionRoute(pathname: string): SessionRoute | null {
  const normalized = pathname.replace(/\/+$/u, "") || "/";
  if (normalized === SESSION_ROOTS_PATH) return { kind: "roots" };
  if (!normalized.startsWith(`${SESSION_ROOTS_PATH}/`)) return null;
  const rest = normalized.slice(SESSION_ROOTS_PATH.length + 1);
  if (rest === "new") return { kind: "new" };
  if (rest.includes("/")) return { kind: "invalid" };
  const sessionId = decodeCanonicalSessionId(rest);
  if (sessionId === null) return { kind: "invalid" };
  return { kind: "detail", sessionId };
}

/** True for any pathname in the protected commerce-session subtree. */
export function isSessionPath(pathname: string): boolean {
  return parseSessionRoute(pathname) !== null;
}
