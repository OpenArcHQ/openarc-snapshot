import { accountAccessEnabled } from "../account/availability.js";
import { apiBoundaryEnabled } from "../app/availability.js";
import { tenantReadsEnabled } from "./availability.js";

/**
 * The policy-rules console is a strict superset of the protected tenant reads
 * and the API privacy boundary: it mounts only when the policy flag is exactly
 * true AND account access, tenant reads and the API boundary are all enabled.
 * It deliberately does NOT depend on `VITE_TENANT_WRITES_ENABLED`, the machine
 * credential flag, the listing flag, Vault, wallet or a session flag: policy
 * writes have their own server authority and their own capability probe.
 *
 * All values default to false so a disabled deployment constructs no policy
 * controller and makes ZERO policy or capability requests.
 */
export function policyManagementEnabled(
  policy: string | boolean | undefined,
  reads: string | boolean | undefined,
  account: string | boolean | undefined,
  apiBoundary: string | boolean | undefined,
): boolean {
  return (
    policyFlagValue(policy) &&
    tenantReadsEnabled(reads) &&
    accountAccessEnabled(account) &&
    apiBoundaryEnabled(apiBoundary)
  );
}

function policyFlagValue(value: string | boolean | undefined): boolean {
  return value === true || value === "true";
}

export function policyManagementFlag(): string | boolean | undefined {
  const env = (import.meta as unknown as { env?: Record<string, string | boolean | undefined> }).env;
  return env?.VITE_POLICY_MANAGEMENT_ENABLED;
}

/** Reads the effective flag from the Vite environment (default false). */
export function policyManagementEnabledFromEnv(): boolean {
  const env = (import.meta as unknown as { env?: Record<string, string | boolean | undefined> }).env;
  return policyManagementEnabled(
    env?.VITE_POLICY_MANAGEMENT_ENABLED,
    env?.VITE_TENANT_READS_ENABLED,
    env?.VITE_ACCOUNT_ACCESS_ENABLED,
    env?.VITE_API_BOUNDARY_ENABLED,
  );
}
