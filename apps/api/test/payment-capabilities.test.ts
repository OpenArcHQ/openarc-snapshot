import { afterEach, describe, expect, it } from "vitest";
import Fastify, { type FastifyInstance } from "fastify";

import {
  PAYMENT_CAPABILITIES_PATH,
  PAYMENT_CAPABILITY_DEPENDENCY_ORDER,
  PAYMENT_CAPABILITY_VERSION,
  PAYMENT_ROUTES,
  PaymentCapabilityManifestSchema,
} from "@openarc/shared";

import { AuthApiError, authErrorEnvelope } from "../src/auth/errors.js";
import {
  buildPaymentCapabilityManifest,
  paymentCapabilityState,
  registerPaymentCapabilities,
  type PaymentCapabilityFlags,
} from "../src/commerce/payment-capabilities.js";
import { BUILD_SHA, MUTATION, ORIGIN } from "./payment-fixtures.js";

/**
 * Public payment capability metadata: the frozen two-family / five-route
 * manifest, `built_disabled` by default with zero probes, and the
 * dependency-derived `enabled` / `unavailable` states. Availability only.
 */

const apps: FastifyInstance[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map(async (app) => app.close()));
});

const OFF: PaymentCapabilityFlags = {
  authEnabled: false,
  commerceSessionsEnabled: false,
  commerceActionsEnabled: false,
  commerceGrantsEnabled: false,
  commercePaymentsEnabled: false,
};

const ON: PaymentCapabilityFlags = {
  authEnabled: true,
  commerceSessionsEnabled: true,
  commerceActionsEnabled: true,
  commerceGrantsEnabled: true,
  commercePaymentsEnabled: true,
};

function build(flags: PaymentCapabilityFlags, ready: Partial<Record<"auth" | "session" | "action" | "grant" | "payment", boolean>> = {}) {
  const probes = { auth: 0, session: 0, action: 0, grant: 0, payment: 0 };
  const probe = (key: keyof typeof probes) => async () => {
    probes[key] += 1;
    return ready[key] ?? true;
  };
  const app = Fastify({ logger: false, exposeHeadRoutes: false, genReqId: () => MUTATION });
  app.setErrorHandler((cause, request, reply) => {
    if (cause instanceof AuthApiError) {
      return reply.code(cause.status).send(authErrorEnvelope(cause, request.id, BUILD_SHA));
    }
    return reply.code(500).send({ ok: false });
  });
  registerPaymentCapabilities(app, {
    flags,
    readiness: {
      authReady: probe("auth"),
      sessionReady: probe("session"),
      actionReady: probe("action"),
      grantReady: probe("grant"),
      paymentReady: probe("payment"),
    },
    buildSha: BUILD_SHA,
    appOrigin: ORIGIN,
  });
  apps.push(app);
  return { app, probes };
}

async function states(app: FastifyInstance): Promise<string[]> {
  const response = await app.inject({ method: "GET", url: PAYMENT_CAPABILITIES_PATH });
  expect(response.statusCode).toBe(200);
  const body = response.json() as { data: unknown };
  const manifest = PaymentCapabilityManifestSchema.parse(body.data);
  expect(manifest.capabilityVersion).toBe(PAYMENT_CAPABILITY_VERSION);
  expect(manifest.routes).toEqual(PAYMENT_ROUTES);
  for (const entry of manifest.capabilities) {
    expect(entry.dependencies).toEqual(PAYMENT_CAPABILITY_DEPENDENCY_ORDER);
  }
  return manifest.capabilities.map((entry) => `${entry.family}:${entry.audience}:${entry.state}`);
}

describe("payment capability manifest", () => {
  it("is built_disabled by default and runs zero readiness probes", async () => {
    const { app, probes } = build(OFF);
    expect(await states(app)).toEqual([
      "commerce_payment_terms:browser:built_disabled",
      "commerce_payment_attempt:agent:built_disabled",
    ]);
    expect(probes).toEqual({ auth: 0, session: 0, action: 0, grant: 0, payment: 0 });
  });

  it("stays built_disabled with every prerequisite enabled but the payment gate off", async () => {
    const { app, probes } = build({ ...ON, commercePaymentsEnabled: false });
    expect((await states(app)).every((state) => state.endsWith(":built_disabled"))).toBe(true);
    expect(probes.payment).toBe(0);
  });

  it("is enabled only when the gate, every prerequisite and every dependency are ready", async () => {
    const { app, probes } = build(ON);
    expect((await states(app)).every((state) => state.endsWith(":enabled"))).toBe(true);
    expect(probes).toEqual({ auth: 1, session: 1, action: 1, grant: 1, payment: 1 });
  });

  it("is unavailable when a dependency is unready or the grant prerequisite is off", async () => {
    for (const key of ["auth", "session", "action", "grant", "payment"] as const) {
      const { app } = build(ON, { [key]: false });
      expect((await states(app)).every((state) => state.endsWith(":unavailable"))).toBe(true);
    }
    const { app, probes } = build({ ...ON, commerceGrantsEnabled: false });
    expect((await states(app)).every((state) => state.endsWith(":unavailable"))).toBe(true);
    expect(probes.payment).toBe(0);
  });

  it("derives one shared state and parses the frozen manifest for every state", () => {
    const allReady = { authReady: true, sessionReady: true, actionReady: true, grantReady: true, paymentReady: true };
    expect(paymentCapabilityState(OFF, allReady)).toBe("built_disabled");
    expect(paymentCapabilityState(ON, allReady)).toBe("enabled");
    expect(paymentCapabilityState(ON, { ...allReady, paymentReady: false })).toBe("unavailable");
    for (const state of ["enabled", "built_disabled", "unavailable"] as const) {
      expect(buildPaymentCapabilityManifest(state).capabilities.map((entry) => entry.state)).toEqual([state, state]);
    }
  });

  it("is a credentialless, query-free GET", async () => {
    const { app } = build(OFF);
    expect((await app.inject({ method: "GET", url: `${PAYMENT_CAPABILITIES_PATH}?x=1` })).statusCode).toBe(400);
    expect((await app.inject({ method: "POST", url: PAYMENT_CAPABILITIES_PATH })).statusCode).toBe(405);
    for (const headers of [{ cookie: "openarc_session=abc" }, { authorization: "Bearer x" }, { "idempotency-key": "A".repeat(43) }, { "x-unknown": "1" }]) {
      expect((await app.inject({ method: "GET", url: PAYMENT_CAPABILITIES_PATH, headers })).statusCode).toBe(400);
    }
    expect((await app.inject({ method: "GET", url: PAYMENT_CAPABILITIES_PATH, headers: { origin: "https://evil.example" } })).statusCode).toBe(403);
  });
});
