import { accountAccessEnabled } from "../account/availability.js";
import { apiBoundaryEnabled } from "../app/availability.js";
import { commerceActionsEnabled } from "./action-availability.js";
import { commerceSessionsEnabled } from "./session-availability.js";
import { tenantReadsEnabled } from "./availability.js";

/**
 * The authorization-grant console is a strict superset of the commerce-action
 * console, which is itself a superset of the protected tenant reads and the API
 * privacy boundary. It mounts only when the grant flag is exactly true AND
 * account access, tenant reads, the API boundary, commerce sessions and
 * commerce actions are all enabled.
 *
 * The session and action prerequisites are real, not decorative: a grant exists
 * only because an agent holding a live commerce session issued it against an
 * already-approved commerce action, so a deployment without either surface has
 * nothing a buyer could read or revoke here.
 *
 * It deliberately does NOT depend on `VITE_TENANT_WRITES_ENABLED`, the machine
 * credential flag, the listing flag, the policy flag, Vault, wallet or market
 * flags: grant revocation has its own server authority and its own separate,
 * public, credentialless capability probe.
 *
 * All values default to false so a disabled deployment constructs no grant
 * controller, no grant client and no stylesheet, and makes ZERO grant or
 * grant-capability requests — the capability probe included.
 */
export function commerceGrantsEnabled(
  grants: string | boolean | undefined,
  actions: string | boolean | undefined,
  sessions: string | boolean | undefined,
  reads: string | boolean | undefined,
  account: string | boolean | undefined,
  apiBoundary: string | boolean | undefined,
): boolean {
  return (
    commerceGrantsFlagValue(grants) &&
    commerceActionsEnabled(actions, reads, account, apiBoundary) &&
    commerceSessionsEnabled(sessions, reads, account, apiBoundary) &&
    tenantReadsEnabled(reads) &&
    accountAccessEnabled(account) &&
    apiBoundaryEnabled(apiBoundary)
  );
}

function commerceGrantsFlagValue(value: string | boolean | undefined): boolean {
  return value === true || value === "true";
}

export function commerceGrantsFlag(): string | boolean | undefined {
  const env = (import.meta as unknown as { env?: Record<string, string | boolean | undefined> })
    .env;
  return env?.VITE_COMMERCE_GRANTS_ENABLED;
}

/** Reads the effective flag from the Vite environment (default false). */
export function commerceGrantsEnabledFromEnv(): boolean {
  const env = (import.meta as unknown as { env?: Record<string, string | boolean | undefined> })
    .env;
  return commerceGrantsEnabled(
    env?.VITE_COMMERCE_GRANTS_ENABLED,
    env?.VITE_COMMERCE_ACTIONS_ENABLED,
    env?.VITE_COMMERCE_SESSIONS_ENABLED,
    env?.VITE_TENANT_READS_ENABLED,
    env?.VITE_ACCOUNT_ACCESS_ENABLED,
    env?.VITE_API_BOUNDARY_ENABLED,
  );
}
