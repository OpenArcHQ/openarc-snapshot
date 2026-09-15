import { accountAccessEnabled } from "../account/availability.js";
import { apiBoundaryEnabled } from "../app/availability.js";
import { tenantReadsEnabled } from "./availability.js";

/**
 * The commerce action/approval console is a strict superset of the protected
 * tenant reads and the API privacy boundary: it mounts only when the action
 * flag is exactly true AND account access, tenant reads and the API boundary
 * are all enabled.
 *
 * It deliberately does NOT depend on `VITE_TENANT_WRITES_ENABLED`, the machine
 * credential flag, the listing flag, the policy flag, the commerce-session
 * flag, Vault, wallet or market flags: action decisions have their own server
 * authority and their own separate, public, credentialless capability probe.
 *
 * All values default to false so a disabled deployment constructs no action
 * controller and makes ZERO action or action-capability requests.
 */
export function commerceActionsEnabled(
  actions: string | boolean | undefined,
  reads: string | boolean | undefined,
  account: string | boolean | undefined,
  apiBoundary: string | boolean | undefined,
): boolean {
  return (
    commerceActionsFlagValue(actions) &&
    tenantReadsEnabled(reads) &&
    accountAccessEnabled(account) &&
    apiBoundaryEnabled(apiBoundary)
  );
}

function commerceActionsFlagValue(value: string | boolean | undefined): boolean {
  return value === true || value === "true";
}

export function commerceActionsFlag(): string | boolean | undefined {
  const env = (import.meta as unknown as { env?: Record<string, string | boolean | undefined> })
    .env;
  return env?.VITE_COMMERCE_ACTIONS_ENABLED;
}

/** Reads the effective flag from the Vite environment (default false). */
export function commerceActionsEnabledFromEnv(): boolean {
  const env = (import.meta as unknown as { env?: Record<string, string | boolean | undefined> })
    .env;
  return commerceActionsEnabled(
    env?.VITE_COMMERCE_ACTIONS_ENABLED,
    env?.VITE_TENANT_READS_ENABLED,
    env?.VITE_ACCOUNT_ACCESS_ENABLED,
    env?.VITE_API_BOUNDARY_ENABLED,
  );
}
