import { afterEach, describe, expect, it } from "vitest";

import { PAYMENT_CAPABILITIES_PATH, PAYMENT_ROUTES } from "@openarc/shared";

import { createApp } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import {
  ATTEMPT,
  LISTING,
  MACHINE_AGENT_TOKEN,
  ORG,
  SESSION_TOKEN,
} from "./payment-fixtures.js";

/**
 * Whole-app wiring for the migration-0015 payment lane in DEFAULT mode: the five
 * exact targets are installed behind the gate and answer a real API error
 * envelope (never HTML, never 200), the capability manifest reports
 * `built_disabled`, readiness never mentions the payment database, and no
 * observation path exists.
 */

const ORIGIN = "http://localhost:5173";
const SHA = "0123456789abcdef0123456789abcdef01234567";

const apps: ReturnType<typeof createApp>[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map(async (app) => app.close()));
});

function defaultApp(): ReturnType<typeof createApp> {
  const app = createApp({
    config: loadConfig({ NODE_ENV: "test", COMMIT_SHA: SHA, APP_ORIGIN: ORIGIN }),
    logger: false,
  });
  apps.push(app);
  return app;
}

function concrete(path: string): string {
  return path
    .replace(":organizationId", ORG)
    .replace(":listingId", LISTING)
    .replace(":version", "1")
    .replace(":attemptId", ATTEMPT);
}

describe("the payment lane ships disabled", () => {
  it("answers every frozen target with a JSON API error, never HTML or 200", async () => {
    const app = defaultApp();
    for (const route of PAYMENT_ROUTES) {
      for (const headers of [
        { authorization: `Bearer ${SESSION_TOKEN}` },
        { authorization: `Bearer ${MACHINE_AGENT_TOKEN}` },
        { origin: ORIGIN, "x-openarc-client": "browser-v1" },
      ]) {
        const response = await app.inject({
          method: route.method,
          url: concrete(route.path),
          headers: { ...headers, ...(route.method === "POST" ? { "content-type": "application/json" } : {}) },
          ...(route.method === "POST" ? { payload: {} } : {}),
        });
        expect([route.id, response.statusCode >= 400]).toEqual([route.id, true]);
        expect(response.headers["content-type"]).toContain("application/json");
        expect(response.body.toLowerCase()).not.toContain("<html");
        expect((response.json() as { ok?: unknown }).ok).toBe(false);
        expect(response.body).not.toContain(SESSION_TOKEN);
        expect(response.body).not.toContain(MACHINE_AGENT_TOKEN);
      }
    }
  });

  it("publishes the payment manifest as built_disabled", async () => {
    const app = defaultApp();
    const response = await app.inject({ method: "GET", url: PAYMENT_CAPABILITIES_PATH });
    expect(response.statusCode).toBe(200);
    const body = response.json() as { data: { capabilities: { state: string }[] } };
    expect(body.data.capabilities.map((entry) => entry.state)).toEqual(["built_disabled", "built_disabled"]);
  });

  it("keeps the payment database out of readiness while the gate is off", async () => {
    const app = defaultApp();
    const response = await app.inject({ method: "GET", url: "/readyz" });
    expect(response.body).not.toContain("commercePaymentDatabase");
  });

  it("keeps unrouted agent payment paths on the bounded 404 surface", async () => {
    const app = defaultApp();
    for (const url of [
      `/v2/agent/commerce-payment-attempts/${ATTEMPT}/observe`,
      "/v2/agent/commerce-payment-requirements/extra",
    ]) {
      const response = await app.inject({ method: "POST", url, headers: { "content-type": "application/json" }, payload: {} });
      expect([url, response.statusCode]).toEqual([url, 404]);
      expect(response.headers["content-type"]).toContain("application/json");
    }
  });
});
