import { describe, expect, it } from "vitest";
import { ZodError } from "zod";

import { loadConfig } from "../src/config.js";

/**
 * Configuration dependency matrix for COMMERCE_PAYMENTS_ENABLED.
 *
 * The flag DEFAULTS OFF. Enabling it requires AUTH_ENABLED, the commerce
 * session, commerce action AND authorization grant families, and the dedicated
 * restricted TENANT_DATABASE_URL (never the auth URL). Messages are fixed and
 * never echo a URL or a secret.
 */

const SECRET = "synthetic_auth_secret_for_payment_config_0123456789";
const AUTH_URL = "postgres://openarc_auth_app:x@127.0.0.1:5432/openarc_auth_test";
const TENANT_URL = "postgres://openarc_tenant_app:y@127.0.0.1:5432/openarc_auth_test";

function base(overrides: Record<string, string> = {}): Record<string, string> {
  return {
    NODE_ENV: "test",
    APP_ORIGIN: "http://localhost:5183",
    COMMIT_SHA: "0123456789abcdef0123456789abcdef01234567",
    AUTH_ENABLED: "true",
    AUTH_DATABASE_URL: AUTH_URL,
    AUTH_SECRET: SECRET,
    AUTH_RP_ID: "localhost",
    ...overrides,
  };
}

function enabled(overrides: Record<string, string> = {}): Record<string, string> {
  return base({
    COMMERCE_SESSIONS_ENABLED: "true",
    COMMERCE_ACTIONS_ENABLED: "true",
    COMMERCE_GRANTS_ENABLED: "true",
    COMMERCE_PAYMENTS_ENABLED: "true",
    TENANT_DATABASE_URL: TENANT_URL,
    ...overrides,
  });
}

function rejectionOf(input: Record<string, string>): ZodError {
  try {
    loadConfig(input);
  } catch (error) {
    expect(error).toBeInstanceOf(ZodError);
    return error as ZodError;
  }
  throw new Error("expected config rejection");
}

function paths(input: Record<string, string>): string[] {
  return rejectionOf(input).issues.map((issue) => issue.path.join("."));
}

describe("COMMERCE_PAYMENTS_ENABLED", () => {
  it("defaults off in the empty and the authenticated configuration", () => {
    expect(loadConfig({ NODE_ENV: "test" }).COMMERCE_PAYMENTS_ENABLED).toBe(false);
    expect(loadConfig(base()).COMMERCE_PAYMENTS_ENABLED).toBe(false);
    // Enabling every prerequisite family alone never turns payments on.
    expect(loadConfig(enabled({ COMMERCE_PAYMENTS_ENABLED: "false" })).COMMERCE_PAYMENTS_ENABLED).toBe(false);
  });

  it("accepts the full grant, action and session chain on a dedicated tenant URL", () => {
    const config = loadConfig(enabled());
    expect(config.COMMERCE_PAYMENTS_ENABLED).toBe(true);
    expect(config.COMMERCE_GRANTS_ENABLED).toBe(true);
  });

  it("refuses enabling payments unless the grant family is enabled", () => {
    expect(paths(enabled({ COMMERCE_GRANTS_ENABLED: "false" }))).toEqual(["COMMERCE_PAYMENTS_ENABLED"]);
  });

  it("refuses enabling payments unless the action family is enabled", () => {
    const issues = paths(enabled({ COMMERCE_ACTIONS_ENABLED: "false" }));
    expect(issues).toContain("COMMERCE_PAYMENTS_ENABLED");
  });

  it("refuses enabling payments without the session family, authentication or a tenant URL", () => {
    expect(paths(enabled({ COMMERCE_SESSIONS_ENABLED: "false" }))).toContain("COMMERCE_PAYMENTS_ENABLED");
    const noTenant = enabled();
    delete noTenant["TENANT_DATABASE_URL"];
    expect(paths(noTenant)).toContain("COMMERCE_PAYMENTS_ENABLED");
    expect(paths(enabled({ AUTH_ENABLED: "false" }))).toContain("COMMERCE_PAYMENTS_ENABLED");
  });

  it("refuses reusing the auth URL as the payment connection", () => {
    expect(paths(enabled({ TENANT_DATABASE_URL: AUTH_URL }))).toContain("TENANT_DATABASE_URL");
  });

  it("accepts only the exact true/false strings", () => {
    for (const value of ["TRUE", "1", "yes", " true"]) {
      expect(paths(base({ COMMERCE_PAYMENTS_ENABLED: value }))).toContain("COMMERCE_PAYMENTS_ENABLED");
    }
  });

  it("never echoes a URL or a secret in a refusal", () => {
    const serialized = JSON.stringify(rejectionOf(enabled({ COMMERCE_GRANTS_ENABLED: "false", TENANT_DATABASE_URL: AUTH_URL })).issues);
    expect(serialized).not.toContain(AUTH_URL);
    expect(serialized).not.toContain(TENANT_URL);
    expect(serialized).not.toContain(SECRET);
  });
});
