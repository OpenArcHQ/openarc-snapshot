import { describe, expect, it } from "vitest";
import { ZodError } from "zod";

import { loadConfig } from "../src/config.js";

/**
 * Configuration dependency matrix for COMMERCE_SESSIONS_ENABLED.
 *
 * The flag defaults off and preserves legacy default mode. Enabling it requires
 * AUTH_ENABLED and the dedicated restricted TENANT_DATABASE_URL, but is
 * deliberately INDEPENDENT of TENANT_READS/TENANT_WRITES, marketplace,
 * moderation, policy management and machine flags. Reusing the AUTH_DATABASE_URL
 * as the session connection is rejected. Failure messages are fixed and never
 * echo a URL or a secret.
 */

const ORIGIN = "http://localhost:5183";
const RP_ID = "localhost";
const SHA = "0123456789abcdef0123456789abcdef01234567";
const SECRET = "synthetic_auth_secret_for_session_config_0123456789";
const AUTH_URL = "postgres://openarc_auth_app:x@127.0.0.1:5432/openarc_auth_test";
const TENANT_URL = "postgres://openarc_tenant_app:y@127.0.0.1:5432/openarc_auth_test";

function base(overrides: Record<string, string> = {}): Record<string, string> {
  return {
    NODE_ENV: "test",
    APP_ORIGIN: ORIGIN,
    COMMIT_SHA: SHA,
    AUTH_ENABLED: "true",
    AUTH_DATABASE_URL: AUTH_URL,
    AUTH_SECRET: SECRET,
    AUTH_RP_ID: RP_ID,
    ...overrides,
  };
}

function issues(input: Record<string, string>): string[] {
  try {
    loadConfig(input);
  } catch (error) {
    expect(error).toBeInstanceOf(ZodError);
    return (error as ZodError).issues.map((issue) => issue.path.join("."));
  }
  throw new Error("expected config rejection");
}

function rejectionMessage(input: Record<string, string>): string {
  try {
    loadConfig(input);
  } catch (error) {
    return JSON.stringify((error as ZodError).issues);
  }
  throw new Error("expected config rejection");
}

describe("commerce session configuration", () => {
  it("defaults the flag off and preserves legacy default mode", () => {
    expect(loadConfig(base()).COMMERCE_SESSIONS_ENABLED).toBe(false);
    expect(
      loadConfig(base({ COMMERCE_SESSIONS_ENABLED: "false" }))
        .COMMERCE_SESSIONS_ENABLED,
    ).toBe(false);
  });

  it("enables with auth plus a dedicated restricted database, no other flags", () => {
    const config = loadConfig(
      base({
        TENANT_DATABASE_URL: TENANT_URL,
        COMMERCE_SESSIONS_ENABLED: "true",
      }),
    );
    expect(config.COMMERCE_SESSIONS_ENABLED).toBe(true);
    expect(config.TENANT_READS_ENABLED).toBe(false);
    expect(config.TENANT_WRITES_ENABLED).toBe(false);
    expect(config.MARKET_CATALOG_ENABLED).toBe(false);
    expect(config.LISTING_MANAGEMENT_ENABLED).toBe(false);
    expect(config.MARKET_MODERATION_ENABLED).toBe(false);
    expect(config.POLICY_MANAGEMENT_ENABLED).toBe(false);
    expect(config.MACHINE_CREDENTIAL_MANAGEMENT_ENABLED).toBe(false);
    expect(config.MACHINE_SESSION_EXCHANGE_ENABLED).toBe(false);
  });

  it("enables with every independent tenant/market/machine/policy flag explicitly off", () => {
    const config = loadConfig(
      base({
        TENANT_READS_ENABLED: "false",
        TENANT_WRITES_ENABLED: "false",
        MARKET_CATALOG_ENABLED: "false",
        LISTING_MANAGEMENT_ENABLED: "false",
        MARKET_MODERATION_ENABLED: "false",
        POLICY_MANAGEMENT_ENABLED: "false",
        MACHINE_CREDENTIAL_MANAGEMENT_ENABLED: "false",
        MACHINE_SESSION_EXCHANGE_ENABLED: "false",
        TENANT_DATABASE_URL: TENANT_URL,
        COMMERCE_SESSIONS_ENABLED: "true",
      }),
    );
    expect(config.COMMERCE_SESSIONS_ENABLED).toBe(true);
  });

  it("does not require the session flag when the other families are enabled", () => {
    const config = loadConfig(
      base({ TENANT_DATABASE_URL: TENANT_URL }),
    );
    expect(config.COMMERCE_SESSIONS_ENABLED).toBe(false);
    expect(config.POLICY_MANAGEMENT_ENABLED).toBe(false);
  });

  it("rejects enabled without authentication", () => {
    expect(
      issues({
        ...base({ AUTH_ENABLED: "false" }),
        TENANT_DATABASE_URL: TENANT_URL,
        COMMERCE_SESSIONS_ENABLED: "true",
      }),
    ).toContain("COMMERCE_SESSIONS_ENABLED");
  });

  it("rejects enabled without a dedicated restricted database URL", () => {
    expect(
      issues(base({ COMMERCE_SESSIONS_ENABLED: "true" })),
    ).toContain("COMMERCE_SESSIONS_ENABLED");
  });

  it("rejects reusing the auth connection as the session connection", () => {
    expect(
      issues(
        base({
          TENANT_DATABASE_URL: AUTH_URL,
          COMMERCE_SESSIONS_ENABLED: "true",
        }),
      ),
    ).toContain("TENANT_DATABASE_URL");
  });

  it("never echoes the URL or a secret in a fixed rejection message", () => {
    const message = rejectionMessage(
      base({
        TENANT_DATABASE_URL: AUTH_URL,
        COMMERCE_SESSIONS_ENABLED: "true",
      }),
    );
    expect(message).not.toContain(AUTH_URL);
    expect(message).not.toContain(TENANT_URL);
    expect(message).not.toContain(SECRET);
    expect(message).toContain("dedicated restricted role connection");
  });

  it("rejects a non-postgres URL shape through the existing validation", () => {
    expect(
      issues(
        base({
          TENANT_DATABASE_URL: "mysql://openarc_tenant_app:y@127.0.0.1:3306/db",
          COMMERCE_SESSIONS_ENABLED: "true",
        }),
      ),
    ).toContain("TENANT_DATABASE_URL");
  });

  it("keeps the flag closed with no database configuration", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      APP_ORIGIN: ORIGIN,
      COMMIT_SHA: SHA,
    });
    expect(config.COMMERCE_SESSIONS_ENABLED).toBe(false);
    expect(config.AUTH_DATABASE_URL).toBeUndefined();
    expect(config.TENANT_DATABASE_URL).toBeUndefined();
  });
});
