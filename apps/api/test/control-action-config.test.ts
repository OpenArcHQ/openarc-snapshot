import { describe, expect, it } from "vitest";
import { ZodError } from "zod";

import { loadConfig } from "../src/config.js";

/**
 * Configuration dependency matrix for COMMERCE_ACTIONS_ENABLED.
 *
 * The flag DEFAULTS OFF and preserves legacy default mode. Enabling it requires
 * AUTH_ENABLED, COMMERCE_SESSIONS_ENABLED (the agent audience presents a
 * commerce-session bearer) and the dedicated restricted TENANT_DATABASE_URL.
 * Reusing AUTH_DATABASE_URL as the action connection is rejected. Failure
 * messages are fixed and never echo a URL or a secret.
 */

const ORIGIN = "http://localhost:5183";
const RP_ID = "localhost";
const SHA = "0123456789abcdef0123456789abcdef01234567";
const SECRET = "synthetic_auth_secret_for_action_config_01234567890";
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

describe("COMMERCE_ACTIONS_ENABLED", () => {
  it("defaults to false in a bare environment", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      APP_ORIGIN: ORIGIN,
      COMMIT_SHA: SHA,
    });
    expect(config.COMMERCE_ACTIONS_ENABLED).toBe(false);
    // The lane ships disabled: no other default flag is flipped on with it.
    expect(config.COMMERCE_SESSIONS_ENABLED).toBe(false);
    expect(config.AUTH_ENABLED).toBe(false);
  });

  it("stays false for an explicit `false` and for an unknown value", () => {
    expect(
      loadConfig(base({ COMMERCE_ACTIONS_ENABLED: "false" }))
        .COMMERCE_ACTIONS_ENABLED,
    ).toBe(false);
    expect(issues(base({ COMMERCE_ACTIONS_ENABLED: "yes" }))).toContain(
      "COMMERCE_ACTIONS_ENABLED",
    );
    expect(issues(base({ COMMERCE_ACTIONS_ENABLED: "TRUE" }))).toContain(
      "COMMERCE_ACTIONS_ENABLED",
    );
  });

  it("requires authentication, the session family and a restricted database", () => {
    const withoutAuth = issues({
      NODE_ENV: "test",
      APP_ORIGIN: ORIGIN,
      COMMIT_SHA: SHA,
      COMMERCE_ACTIONS_ENABLED: "true",
    });
    expect(withoutAuth).toContain("COMMERCE_ACTIONS_ENABLED");

    const withoutSessions = issues(
      base({
        COMMERCE_ACTIONS_ENABLED: "true",
        TENANT_DATABASE_URL: TENANT_URL,
      }),
    );
    expect(withoutSessions).toContain("COMMERCE_ACTIONS_ENABLED");
    expect(
      messages(
        base({
          COMMERCE_ACTIONS_ENABLED: "true",
          TENANT_DATABASE_URL: TENANT_URL,
        }),
      ),
    ).toContain("Commerce actions require the commerce session family");

    const withoutDatabase = issues(
      base({
        COMMERCE_ACTIONS_ENABLED: "true",
        COMMERCE_SESSIONS_ENABLED: "true",
      }),
    );
    expect(withoutDatabase).toContain("COMMERCE_ACTIONS_ENABLED");
  });

  it("rejects reusing the auth connection as the restricted action connection", () => {
    const reused = issues(
      base({
        COMMERCE_ACTIONS_ENABLED: "true",
        COMMERCE_SESSIONS_ENABLED: "true",
        TENANT_DATABASE_URL: AUTH_URL,
      }),
    );
    expect(reused).toContain("TENANT_DATABASE_URL");
  });

  it("accepts the fully satisfied configuration", () => {
    const config = loadConfig(
      base({
        COMMERCE_ACTIONS_ENABLED: "true",
        COMMERCE_SESSIONS_ENABLED: "true",
        TENANT_DATABASE_URL: TENANT_URL,
      }),
    );
    expect(config.COMMERCE_ACTIONS_ENABLED).toBe(true);
    // Enabling the control surface never enables an unrelated lane.
    expect(config.GATEWAY_EVIDENCE_ENABLED).toBe(false);
    expect(config.MARKET_CATALOG_ENABLED).toBe(false);
    expect(config.LISTING_MANAGEMENT_ENABLED).toBe(false);
    expect(config.ARC_OBSERVATION_ENABLED).toBe(false);
  });

  it("never echoes a URL or secret in a rejection message", () => {
    const all = messages(
      base({
        COMMERCE_ACTIONS_ENABLED: "true",
        TENANT_DATABASE_URL: AUTH_URL,
      }),
    ).join(" ");
    expect(all).not.toContain(AUTH_URL);
    expect(all).not.toContain(TENANT_URL);
    expect(all).not.toContain(SECRET);
  });

  it("leaves the session family independently configurable", () => {
    const sessionsOnly = loadConfig(
      base({
        COMMERCE_SESSIONS_ENABLED: "true",
        TENANT_DATABASE_URL: TENANT_URL,
      }),
    );
    expect(sessionsOnly.COMMERCE_SESSIONS_ENABLED).toBe(true);
    expect(sessionsOnly.COMMERCE_ACTIONS_ENABLED).toBe(false);
  });
});
