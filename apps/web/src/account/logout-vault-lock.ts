import { AccountApiError } from "./auth-client.js";

/**
 * A failed logout still locks the Vault once the logout request may have left
 * the browser (lost response, server error, abort mid-request): the session is
 * treated as ended locally. A pre-send failure or an account-changed refusal
 * (raised before the request) never sent anything; an account change is locked
 * through the identity watcher instead.
 */
export function logoutFailureLocksVault(sent: boolean, error: unknown): boolean {
  if (!sent) return false;
  return !(error instanceof AccountApiError && error.failure.kind === "pre-send");
}
