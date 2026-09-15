import { accountAccessEnabled } from "../account/availability.js";
import { apiBoundaryEnabled } from "../app/availability.js";
import { tenantReadsEnabled } from "./availability.js";

/**
 * The commerce-session console is a strict superset of the protected tenant
 * reads and the API privacy boundary: it mounts only when the session flag is
 * exactly true AND account access, tenant reads and the API boundary are all
 * enabled.
 *
 * It deliberately does NOT depend on VITE_TENANT_WRITES_ENABLED, the machine
 * credential flag, the listing flag, the policy flag, Vault, wallet or market
 * flags: session issuance has its own server authority and its own separate,
 * public, credentialless capability probe.
 *
 * All values default to false so a disabled deployment constructs no session
 * controller and makes ZERO session or session-capability requests.
 */
export function commerceSessionsEnabled(
  sessions: string | boolean | undefined,
  reads: string | boolean | undefined,
  account: string | boolean | undefined,
  apiBoundary: string | boolean | undefined,
): boolean {
  return (
    commerceSessionsFlagValue(sessions) &&
    tenantReadsEnabled(reads) &&
    accountAccessEnabled(account) &&
    apiBoundaryEnabled(apiBoundary)
  );
}

function commerceSessionsFlagValue(value: string | boolean | undefined): boolean {
  return value === true || value === "true";
}

export function commerceSessionsFlag(): string | boolean | undefined {
  const env = (import.meta as unknown as { env?: Record<string, string | boolean | undefined> }).env;
  return env?.VITE_COMMERCE_SESSIONS_ENABLED;
}

/** Reads the effective flag from the Vite environment (default false). */
export function commerceSessionsEnabledFromEnv(): boolean {
  const env = (import.meta as unknown as { env?: Record<string, string | boolean | undefined> }).env;
  return commerceSessionsEnabled(
    env?.VITE_COMMERCE_SESSIONS_ENABLED,
    env?.VITE_TENANT_READS_ENABLED,
    env?.VITE_ACCOUNT_ACCESS_ENABLED,
    env?.VITE_API_BOUNDARY_ENABLED,
  );
}
