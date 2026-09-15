import { describe, expect, it } from "vitest";
import { ZodError } from "zod";

import { loadConfig } from "../src/config.js";

/**
 * Configuration dependency matrix for COMMERCE_GRANTS_ENABLED.
 *
 * The flag DEFAULTS OFF and preserves legacy default mode. Enabling it requires
 * AUTH_ENABLED, COMMERCE_SESSIONS_ENABLED (the agent audience presents a
 * commerce-session bearer), COMMERCE_ACTIONS_ENABLED (every grant is bound to a
 * reserved action) and the dedicated restricted TENANT_DATABASE_URL. Reusing
 * AUTH_DATABASE_URL as the grant connection is rejected. Failure messages are
 * fixed and never echo a URL or a secret.
 */

const ORIGIN = "http://localhost:5183";
const RP_ID = "localhost";
const SHA = "0123456789abcdef0123456789abcdef01234567";
const SECRET = "synthetic_auth_secret_for_grant_config_012345678901";
const AUTH_URL = "postgres://openarc_auth_app:x@127.0.0.1:5432/openarc_auth_test";
const TENANT_URL =
  "postgres://openarc_tenant_app:y@127.0.0.1:5432/openarc_auth_test";

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

function enabled(overrides: Record<string, string> = {}): Record<string, string> {
  return base({
    COMMERCE_SESSIONS_ENABLED: "true",
    COMMERCE_ACTIONS_ENABLED: "true",
    COMMERCE_GRANTS_ENABLED: "true",
    TENANT_DATABASE_URL: TENANT_URL,
    ...overrides,
  });
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

function messages(input: Record<string, string>): string[] {
  try {
    loadConfig(input);
  } catch (error) {
    expect(error).toBeInstanceOf(ZodError);
    return (error as ZodError).issues.map((issue) => issue.message);
  }
  throw new Error("expected config rejection");
}

describe("COMMERCE_GRANTS_ENABLED", () => {
  it("defaults to false in a bare environment", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      APP_ORIGIN: ORIGIN,
      COMMIT_SHA: SHA,
    });
    expect(config.COMMERCE_GRANTS_ENABLED).toBe(false);
    // The lane ships disabled: no other default flag is flipped on with it.
    expect(config.COMMERCE_ACTIONS_ENABLED).toBe(false);
    expect(config.COMMERCE_SESSIONS_ENABLED).toBe(false);
    expect(config.AUTH_ENABLED).toBe(false);
  });

  it("stays false for an explicit `false` and rejects an unknown value", () => {
    expect(
      loadConfig(base({ COMMERCE_GRANTS_ENABLED: "false" }))
        .COMMERCE_GRANTS_ENABLED,
    ).toBe(false);
    for (const value of ["yes", "TRUE", "1", "on"]) {
      expect([value, issues(base({ COMMERCE_GRANTS_ENABLED: value }))]).toEqual([
        value,
        expect.arrayContaining(["COMMERCE_GRANTS_ENABLED"]),
      ]);
    }
  });

  it("requires authentication, sessions, actions and a restricted URL", () => {
    expect(
      messages(
        base({ COMMERCE_GRANTS_ENABLED: "true", AUTH_ENABLED: "false" }),
      ),
    ).toContain("Commerce grants require authentication");
    expect(
      messages(
        enabled({ COMMERCE_SESSIONS_ENABLED: "false", COMMERCE_ACTIONS_ENABLED: "false" }),
      ),
    ).toContain("Commerce grants require the commerce session family");
    expect(messages(enabled({ COMMERCE_ACTIONS_ENABLED: "false" }))).toContain(
      "Commerce grants require the commerce action family",
    );
    const missingUrl = enabled();
    delete missingUrl["TENANT_DATABASE_URL"];
    expect(messages(missingUrl)).toContain(
      "Commerce grants require a dedicated restricted database URL",
    );
  });

  it("rejects reusing the auth connection as the grant connection", () => {
    const shared = enabled({ TENANT_DATABASE_URL: AUTH_URL });
    expect(messages(shared)).toContain(
      "Commerce grants require a dedicated restricted role connection",
    );
    expect(issues(shared)).toContain("TENANT_DATABASE_URL");
  });

  it("never echoes a URL or a secret in a rejection message", () => {
    const shared = enabled({ TENANT_DATABASE_URL: AUTH_URL });
    for (const message of messages(shared)) {
      expect(message).not.toContain(AUTH_URL);
      expect(message).not.toContain(SECRET);
      expect(message).not.toContain("postgres://");
    }
  });

  it("loads with the full dependency chain satisfied", () => {
    const config = loadConfig(enabled());
    expect(config.COMMERCE_GRANTS_ENABLED).toBe(true);
    expect(config.COMMERCE_ACTIONS_ENABLED).toBe(true);
    expect(config.COMMERCE_SESSIONS_ENABLED).toBe(true);
    expect(config.TENANT_DATABASE_URL).toBe(TENANT_URL);
  });

  it("leaves every other family untouched when grants are enabled", () => {
    const config = loadConfig(enabled());
    expect(config.POLICY_MANAGEMENT_ENABLED).toBe(false);
    expect(config.MARKET_CATALOG_ENABLED).toBe(false);
    expect(config.ARC_OBSERVATION_ENABLED).toBe(false);
    expect(config.GATEWAY_EVIDENCE_ENABLED).toBe(false);
  });
});
