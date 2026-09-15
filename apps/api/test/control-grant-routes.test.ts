import { connect } from "node:net";

import { afterEach, describe, expect, it } from "vitest";
import Fastify, { type FastifyInstance } from "fastify";

import { API_MAX_REQUEST_BYTES, GRANT_ROUTES } from "@openarc/shared";

import {
  AUTH_ERRORS,
  AuthApiError,
  authErrorEnvelope,
} from "../src/auth/errors.js";
import {
  GRANT_AGENT_GRANTS,
  GRANT_AGENT_MUTATION_PREFIX,
  GRANT_CONTROL_PREFIX,
  GRANT_PROVIDER_ATTEMPT_PREFIX,
  GRANT_PROVIDER_GRANTS,
  grantRouteTemplates,
  registerCommerceGrantRoutes,
} from "../src/control/grant-routes.js";
import type { CommerceGrantService } from "../src/control/grant-service.js";
import {
  ACTION,
  ATTEMPT,
  BUILD_SHA,
  CLAIM_DIGEST,
  CLAIMED,
  COOKIE,
  CSRF,
  GRANT,
  GRANT_TOKEN,
  IDEMPOTENCY,
  MACHINE_AGENT_TOKEN,
  MUTATION,
  ORG,
  ORIGIN,
  PROVIDER_TOKEN,
  SESSION_TOKEN,
  claimedProviderView,
  grantMetadata,
  grantReceipt,
  providerAttemptStatus,
  providerView,
} from "./grant-fixtures.js";

/**
 * HTTP-inject coverage for the nine-route authorization-grant surface.
 *
 * The CommerceGrantService is HONESTLY MOCKED: these tests prove the exact
 * nine-route inventory, browser/agent/provider audience separation in ALL SIX
 * directions, transport strictness, path canonicality, the default-off gate,
 * the envelope shape and that no credential ever reaches a response body.
 * Injected fakes are never a production path and nothing here performs a
 * payment, settlement or delivery.
 */

const CLIENT = { origin: ORIGIN, "x-openarc-client": "browser-v1" };

const ISSUE_URL = GRANT_AGENT_GRANTS;
const REPLACE_URL = `${GRANT_AGENT_GRANTS}/${GRANT}/replace`;
const AGENT_MUTATION_URL = `${GRANT_AGENT_MUTATION_PREFIX}/${MUTATION}`;
const INTROSPECT_URL = `${GRANT_PROVIDER_GRANTS}/introspect`;
const CLAIM_URL = `${GRANT_PROVIDER_GRANTS}/claim`;
const ATTEMPT_URL = `${GRANT_PROVIDER_ATTEMPT_PREFIX}/${ATTEMPT}`;
const DETAIL_URL = `${GRANT_CONTROL_PREFIX}/${ORG}/grants/${GRANT}`;
const HUMAN_MUTATION_URL = `${GRANT_CONTROL_PREFIX}/${ORG}/grant-mutations/${MUTATION}`;
const REVOKE_URL = `${GRANT_CONTROL_PREFIX}/${ORG}/grants/${GRANT}/revoke`;

class FakeService {
  readonly calls: string[] = [];

  async issue(): Promise<unknown> {
    this.calls.push("issue");
    return {
      replayed: false,
      metadata: grantMetadata(),
      receipt: grantReceipt("control.grant.issue"),
      grantToken: GRANT_TOKEN,
    };
  }
  async replace(): Promise<unknown> {
    this.calls.push("replace");
    return {
      replayed: true,
      metadata: grantMetadata({ generation: "2" }),
      receipt: grantReceipt("control.grant.replace"),
    };
  }
  async getAgentMutationStatus(): Promise<unknown> {
    this.calls.push("getAgentMutationStatus");
    return { status: "not_found" };
  }
  async introspect(): Promise<unknown> {
    this.calls.push("introspect");
    return { item: providerView() };
  }
  async claim(): Promise<unknown> {
    this.calls.push("claim");
    return {
      replayed: false,
      item: claimedProviderView(),
      attemptId: ATTEMPT,
      claimedAt: CLAIMED,
      claimDigest: CLAIM_DIGEST,
      receipt: grantReceipt("control.grant.claim"),
    };
  }
  async getProviderAttemptStatus(): Promise<unknown> {
    this.calls.push("getProviderAttemptStatus");
    return { attemptId: ATTEMPT, item: providerAttemptStatus() };
  }
  async getGrant(): Promise<unknown> {
    this.calls.push("getGrant");
    return { organizationId: ORG, grantId: GRANT, item: grantMetadata() };
  }
  async getHumanMutationStatus(): Promise<unknown> {
    this.calls.push("getHumanMutationStatus");
    return { status: "not_found" };
  }
  async revoke(): Promise<unknown> {
    this.calls.push("revoke");
    return {
      replayed: false,
      metadata: grantMetadata({
        status: "revoked",
        revokedAt: CLAIMED,
        updatedAt: CLAIMED,
      }),
      receipt: grantReceipt("control.grant.revoke"),
      released: true,
      actionStatus: "cancelled",
    };
  }
}

const apps: FastifyInstance[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map(async (app) => app.close()));
});

function build(
  options: { readonly enabled?: boolean; readonly spaFallback?: boolean } = {},
): { app: FastifyInstance; service: FakeService } {
  const service = new FakeService();
  const app = Fastify({
    logger: false,
    bodyLimit: API_MAX_REQUEST_BYTES,
    exposeHeadRoutes: false,
    genReqId: () => MUTATION,
  });
  app.setErrorHandler((cause, request, reply) => {
    if (cause instanceof AuthApiError) {
      return reply
        .code(cause.status)
        .send(authErrorEnvelope(cause, request.id, BUILD_SHA));
    }
    const code =
      typeof cause === "object" && cause !== null && "code" in cause
        ? (cause as { code?: unknown }).code
        : null;
    const mapped =
      code === "FST_ERR_CTP_BODY_TOO_LARGE"
        ? AUTH_ERRORS.tooLarge()
        : AUTH_ERRORS.invalidRequest();
    return reply
      .code(mapped.status)
      .send(authErrorEnvelope(mapped, request.id, BUILD_SHA));
  });
  registerCommerceGrantRoutes(app, {
    appOrigin: ORIGIN,
    cookieNames: { session: "openarc_session", binding: "openarc_binding" },
    service: service as unknown as CommerceGrantService,
    buildSha: BUILD_SHA,
    enabled: options.enabled ?? true,
  });
  if (options.spaFallback === true) {
    // A hostile catch-all registered AFTER the API family. It must never be
    // able to answer one of the nine API targets with an HTML 200.
    app.setNotFoundHandler((_request, reply) =>
      reply.code(200).type("text/html").send("<!doctype html><html></html>"),
    );
  } else {
    app.setNotFoundHandler((request, reply) =>
      reply
        .code(404)
        .send(
          authErrorEnvelope(
            AUTH_ERRORS.featureDisabled(),
            request.id,
            BUILD_SHA,
          ),
        ),
    );
  }
  apps.push(app);
  return { app, service };
}

function readHeaders(extra: Record<string, string> = {}) {
  return { ...CLIENT, cookie: COOKIE, ...extra };
}

function writeHeaders(extra: Record<string, string> = {}) {
  return {
    ...CLIENT,
    "content-type": "application/json",
    cookie: COOKIE,
    "x-openarc-csrf": CSRF,
    "idempotency-key": IDEMPOTENCY,
    ...extra,
  };
}

function agentReadHeaders(extra: Record<string, string> = {}) {
  return { authorization: `Bearer ${SESSION_TOKEN}`, ...extra };
}

function agentWriteHeaders(extra: Record<string, string> = {}) {
  return {
    authorization: `Bearer ${SESSION_TOKEN}`,
    "content-type": "application/json",
    "idempotency-key": IDEMPOTENCY,
    ...extra,
  };
}

function providerReadHeaders(extra: Record<string, string> = {}) {
  return { authorization: `Bearer ${PROVIDER_TOKEN}`, ...extra };
}

/** Introspection is a read-only POST: JSON body, and NO idempotency key. */
function providerIntrospectHeaders(extra: Record<string, string> = {}) {
  return {
    authorization: `Bearer ${PROVIDER_TOKEN}`,
    "content-type": "application/json",
    ...extra,
  };
}

function providerWriteHeaders(extra: Record<string, string> = {}) {
  return {
    authorization: `Bearer ${PROVIDER_TOKEN}`,
    "content-type": "application/json",
    "idempotency-key": IDEMPOTENCY,
    ...extra,
  };
}

function errorCode(response: { json: () => unknown }): string {
  const body = response.json() as { error?: { code?: string } };
  return body.error?.code ?? "";
}

interface Target {
  readonly id: string;
  readonly method: "GET" | "POST";
  readonly url: string;
  readonly audience: "browser" | "agent" | "provider";
  readonly payload?: Record<string, unknown>;
}

const CLAIM_BODY = {
  mutationId: MUTATION,
  grantToken: GRANT_TOKEN,
  expectedActionId: ACTION,
  attemptId: ATTEMPT,
};

const AGENT_TARGETS: readonly Target[] = [
  {
    id: "grant_issue",
    method: "POST",
    url: ISSUE_URL,
    audience: "agent",
    payload: { mutationId: MUTATION, actionId: ACTION },
  },
  {
    id: "grant_replace",
    method: "POST",
    url: REPLACE_URL,
    audience: "agent",
    payload: { mutationId: MUTATION },
  },
  {
    id: "agent_grant_mutation_status",
    method: "GET",
    url: AGENT_MUTATION_URL,
    audience: "agent",
  },
];

const PROVIDER_TARGETS: readonly Target[] = [
  {
    id: "provider_grant_introspect",
    method: "POST",
    url: INTROSPECT_URL,
    audience: "provider",
    payload: { grantToken: GRANT_TOKEN },
  },
  {
    id: "provider_grant_claim",
    method: "POST",
    url: CLAIM_URL,
    audience: "provider",
    payload: CLAIM_BODY,
  },
  {
    id: "provider_grant_attempt_status",
    method: "GET",
    url: ATTEMPT_URL,
    audience: "provider",
  },
];

const BROWSER_TARGETS: readonly Target[] = [
  { id: "grant_detail", method: "GET", url: DETAIL_URL, audience: "browser" },
  {
    id: "grant_mutation_status",
    method: "GET",
    url: HUMAN_MUTATION_URL,
    audience: "browser",
  },
  {
    id: "grant_revoke",
    method: "POST",
    url: REVOKE_URL,
    audience: "browser",
    payload: { mutationId: MUTATION },
  },
];

const ALL_TARGETS: readonly Target[] = [
  ...AGENT_TARGETS,
  ...PROVIDER_TARGETS,
  ...BROWSER_TARGETS,
];

/** The exact valid headers for a target's own audience. */
function validHeaders(target: Target): Record<string, string> {
  if (target.audience === "browser") {
    return target.method === "GET" ? readHeaders() : writeHeaders();
  }
  if (target.audience === "agent") {
    return target.method === "GET" ? agentReadHeaders() : agentWriteHeaders();
  }
  if (target.method === "GET") return providerReadHeaders();
  return target.id === "provider_grant_introspect"
    ? providerIntrospectHeaders()
    : providerWriteHeaders();
}

async function callTarget(
  app: FastifyInstance,
  target: Target,
  headers: Record<string, string>,
) {
  return app.inject({
    method: target.method,
    url: target.url,
    headers,
    ...(target.payload !== undefined ? { payload: target.payload } : {}),
  });
}

/** Exact raw request so a bare `?` survives client-side URL normalization. */
function rawHttp(
  port: number,
  method: string,
  path: string,
  headers: readonly string[],
): Promise<{ status: number; text: string }> {
  const lines = [
    `${method} ${path} HTTP/1.1`,
    "Host: 127.0.0.1",
    ...headers,
    "content-length: 0",
    "connection: close",
    "",
    "",
  ];
  return new Promise((resolve, reject) => {
    const socket = connect({ port, host: "127.0.0.1" });
    let text = "";
    socket.on("connect", () => socket.end(lines.join("\r\n")));
    socket.on("data", (chunk) => {
      text += chunk.toString("utf8");
    });
    socket.on("end", () => {
      const status = Number.parseInt(text.split(" ")[1] ?? "0", 10);
      resolve({ status, text });
    });
    socket.on("error", reject);
  });
}

async function listen(app: FastifyInstance): Promise<number> {
  await app.listen({ port: 0, host: "127.0.0.1" });
  const address = app.server.address();
  return typeof address === "object" && address !== null ? address.port : 0;
}

describe("authorization-grant route registry", () => {
  it("registers exactly the nine frozen descriptors and no tenth", () => {
    const templates = grantRouteTemplates();
    expect(templates).toHaveLength(9);
    expect(GRANT_ROUTES).toHaveLength(9);
    expect(templates.map((route) => route.id)).toEqual(
      GRANT_ROUTES.map((route) => route.id),
    );
    expect(new Set(templates.map((route) => route.path)).size).toBe(9);
    for (const [index, route] of templates.entries()) {
      const frozen = GRANT_ROUTES[index];
      expect(route.method).toBe(frozen?.method);
      expect(route.audience).toBe(frozen?.audience);
      // The registered template is the frozen path with the frozen parameters.
      expect(route.path).toBe(frozen?.path);
    }
    expect(
      templates.filter((route) => route.audience === "agent"),
    ).toHaveLength(3);
    expect(
      templates.filter((route) => route.audience === "provider"),
    ).toHaveLength(3);
    expect(
      templates.filter((route) => route.audience === "browser"),
    ).toHaveLength(3);
    // No provider route may live under the seller browser listing prefix.
    for (const route of templates) {
      if (route.audience !== "provider") continue;
      expect(route.path.startsWith("/v2/provider/organizations/")).toBe(false);
      expect(route.path.startsWith("/v2/provider/grant")).toBe(true);
    }
  });

  it("serves all nine targets on their own audience", async () => {
    const { app, service } = build();
    for (const target of ALL_TARGETS) {
      const response = await callTarget(app, target, validHeaders(target));
      expect([target.id, response.statusCode]).toEqual([target.id, 200]);
      expect(response.headers["content-type"]).toContain("application/json");
    }
    expect(service.calls).toEqual([
      "issue",
      "replace",
      "getAgentMutationStatus",
      "introspect",
      "claim",
      "getProviderAttemptStatus",
      "getGrant",
      "getHumanMutationStatus",
      "revoke",
    ]);
  });

  it("rejects an unregistered tenth target under the same roots", async () => {
    const { app, service } = build();
    for (const url of [
      `${GRANT_CONTROL_PREFIX}/${ORG}/grants`,
      `${GRANT_CONTROL_PREFIX}/${ORG}/grants/${GRANT}/settle`,
      `${GRANT_CONTROL_PREFIX}/${ORG}/grants/${GRANT}/refund`,
      `${GRANT_AGENT_GRANTS}/${GRANT}`,
      `${GRANT_AGENT_GRANTS}/${GRANT}/claim`,
      `${GRANT_PROVIDER_GRANTS}/settle`,
      `${GRANT_PROVIDER_GRANTS}/release`,
      GRANT_PROVIDER_GRANTS,
      "/v2/provider/organizations/grants/claim",
    ]) {
      const response = await app.inject({
        method: "GET",
        url,
        headers: readHeaders(),
      });
      expect([url, response.statusCode]).toEqual([url, 404]);
    }
    expect(service.calls).toEqual([]);
  });

  it("rejects the wrong method on every frozen target", async () => {
    const { app, service } = build();
    for (const target of ALL_TARGETS) {
      const wrong = target.method === "GET" ? "POST" : "GET";
      const response = await app.inject({
        method: wrong,
        url: target.url,
        headers: validHeaders(target),
        ...(wrong === "POST" ? { payload: {} } : {}),
      });
      expect([target.id, response.statusCode]).toEqual([target.id, 405]);
    }
    expect(service.calls).toEqual([]);
  });
});

describe("audience separation in all six directions", () => {
  it("never lets a browser cookie authorize an agent route", async () => {
    const { app, service } = build();
    for (const target of AGENT_TARGETS) {
      const headers = validHeaders(target);
      for (const hostile of [
        { cookie: COOKIE },
        { "x-openarc-csrf": CSRF },
        { origin: ORIGIN },
        { "x-openarc-client": "browser-v1" },
      ]) {
        const response = await callTarget(app, target, {
          ...headers,
          ...hostile,
        });
        expect([target.id, response.statusCode]).toEqual([target.id, 400]);
      }
    }
    // A cookie-only agent request is rejected as malformed BEFORE any bearer is
    // considered: the cookie never becomes authority.
    const cookieOnly = await app.inject({
      method: "GET",
      url: AGENT_MUTATION_URL,
      headers: { cookie: COOKIE },
    });
    expect(cookieOnly.statusCode).toBe(400);
    expect(service.calls).toEqual([]);
  });

  it("never lets a browser cookie authorize a provider route", async () => {
    const { app, service } = build();
    for (const target of PROVIDER_TARGETS) {
      const headers = validHeaders(target);
      for (const hostile of [
        { cookie: COOKIE },
        { "x-openarc-csrf": CSRF },
        { origin: ORIGIN },
      ]) {
        const response = await callTarget(app, target, {
          ...headers,
          ...hostile,
        });
        expect([target.id, response.statusCode]).toEqual([target.id, 400]);
      }
      const cookieOnly = await callTarget(app, target, { cookie: COOKIE });
      expect([target.id, cookieOnly.statusCode]).toEqual([target.id, 400]);
    }
    expect(service.calls).toEqual([]);
  });

  it("never lets a commerce-session bearer authorize a browser route", async () => {
    const { app, service } = build();
    for (const target of BROWSER_TARGETS) {
      const response = await callTarget(app, target, {
        ...validHeaders(target),
        authorization: `Bearer ${SESSION_TOKEN}`,
      });
      expect([target.id, response.statusCode]).toEqual([target.id, 400]);
      expect(errorCode(response)).toBe("INVALID_REQUEST");
      // A bearer alone, with no cookie at all, is equally inert.
      const bare = await callTarget(app, target, {
        ...CLIENT,
        authorization: `Bearer ${SESSION_TOKEN}`,
        ...(target.method === "POST"
          ? {
              "content-type": "application/json",
              "x-openarc-csrf": CSRF,
              "idempotency-key": IDEMPOTENCY,
            }
          : {}),
      });
      expect([target.id, bare.statusCode]).toEqual([target.id, 400]);
    }
    expect(service.calls).toEqual([]);
  });

  it("never lets a commerce-session bearer authorize a provider route", async () => {
    const { app, service } = build();
    for (const target of PROVIDER_TARGETS) {
      const response = await callTarget(app, target, {
        ...validHeaders(target),
        authorization: `Bearer ${SESSION_TOKEN}`,
      });
      expect([target.id, response.statusCode]).toEqual([target.id, 401]);
      expect(errorCode(response)).toBe("UNAUTHENTICATED");
    }
    expect(service.calls).toEqual([]);
  });

  it("never lets a provider session authorize an agent route", async () => {
    const { app, service } = build();
    for (const target of AGENT_TARGETS) {
      const response = await callTarget(app, target, {
        ...validHeaders(target),
        authorization: `Bearer ${PROVIDER_TOKEN}`,
      });
      expect([target.id, response.statusCode]).toEqual([target.id, 401]);
      expect(errorCode(response)).toBe("UNAUTHENTICATED");
    }
    expect(service.calls).toEqual([]);
  });

  it("never lets a provider session authorize a browser route", async () => {
    const { app, service } = build();
    for (const target of BROWSER_TARGETS) {
      const response = await callTarget(app, target, {
        ...validHeaders(target),
        authorization: `Bearer ${PROVIDER_TOKEN}`,
      });
      expect([target.id, response.statusCode]).toEqual([target.id, 400]);
      expect(errorCode(response)).toBe("INVALID_REQUEST");
    }
    expect(service.calls).toEqual([]);
  });

  it("rejects a machine agent-session token on both headless families", async () => {
    const { app, service } = build();
    for (const target of [...AGENT_TARGETS, ...PROVIDER_TARGETS]) {
      const response = await callTarget(app, target, {
        ...validHeaders(target),
        authorization: `Bearer ${MACHINE_AGENT_TOKEN}`,
      });
      expect([target.id, response.statusCode]).toEqual([target.id, 401]);
    }
    expect(service.calls).toEqual([]);
  });
});

describe("the provider lane needs BOTH factors", () => {
  it("refuses a claim carrying only the buyer grant token", async () => {
    const { app, service } = build();
    for (const target of [
      PROVIDER_TARGETS[1] as Target,
      PROVIDER_TARGETS[0] as Target,
    ]) {
      const response = await app.inject({
        method: "POST",
        url: target.url,
        headers: {
          "content-type": "application/json",
          ...(target.id === "provider_grant_claim"
            ? { "idempotency-key": IDEMPOTENCY }
            : {}),
        },
        payload: target.payload as Record<string, unknown>,
      });
      // No provider session at all: refused before the service is ever reached.
      expect([target.id, response.statusCode]).toEqual([target.id, 401]);
      expect(errorCode(response)).toBe("UNAUTHENTICATED");
    }
    expect(service.calls).toEqual([]);
  });

  it("never carries the buyer grant token in a path or a query", async () => {
    const { app, service } = build();
    for (const url of [
      `${GRANT_PROVIDER_GRANTS}/${GRANT_TOKEN}`,
      `${GRANT_PROVIDER_GRANTS}/claim?grantToken=${GRANT_TOKEN}`,
      `${GRANT_PROVIDER_ATTEMPT_PREFIX}/${ATTEMPT}?grantToken=${GRANT_TOKEN}`,
    ]) {
      const response = await app.inject({
        method: "GET",
        url,
        headers: providerReadHeaders(),
      });
      expect(response.statusCode).toBeGreaterThanOrEqual(400);
      expect(response.body).not.toContain(GRANT_TOKEN);
    }
    expect(service.calls).toEqual([]);
  });
});

describe("transport strictness", () => {
  it("rejects a foreign Origin and a missing browser marker", async () => {
    const { app, service } = build();
    for (const target of BROWSER_TARGETS) {
      const foreign = await callTarget(app, target, {
        ...validHeaders(target),
        origin: "https://evil.example",
      });
      expect([target.id, foreign.statusCode]).toEqual([target.id, 403]);
      expect(errorCode(foreign)).toBe("INVALID_ORIGIN");
      const headers = { ...validHeaders(target) } as Record<string, string>;
      delete headers["x-openarc-client"];
      const unmarked = await callTarget(app, target, headers);
      expect([target.id, unmarked.statusCode]).toEqual([target.id, 403]);
      expect(errorCode(unmarked)).toBe("INVALID_ORIGIN");
    }
    expect(service.calls).toEqual([]);
  });

  it("rejects a browser write missing CSRF or the idempotency key", async () => {
    const { app, service } = build();
    const target = BROWSER_TARGETS[2] as Target;
    for (const missing of ["x-openarc-csrf", "idempotency-key"]) {
      const headers = { ...writeHeaders() } as Record<string, string>;
      delete headers[missing];
      const response = await callTarget(app, target, headers);
      expect([missing, response.statusCode]).toEqual([missing, 400]);
    }
    expect(service.calls).toEqual([]);
  });

  it("rejects a headless mutation missing the idempotency key", async () => {
    const { app, service } = build();
    for (const target of [
      AGENT_TARGETS[0] as Target,
      AGENT_TARGETS[1] as Target,
      PROVIDER_TARGETS[1] as Target,
    ]) {
      const headers = { ...validHeaders(target) } as Record<string, string>;
      delete headers["idempotency-key"];
      const response = await callTarget(app, target, headers);
      expect([target.id, response.statusCode]).toEqual([target.id, 400]);
    }
    expect(service.calls).toEqual([]);
  });

  it("rejects an idempotency key on the read-only introspection POST", async () => {
    const { app, service } = build();
    const target = PROVIDER_TARGETS[0] as Target;
    const response = await callTarget(app, target, {
      ...providerIntrospectHeaders(),
      "idempotency-key": IDEMPOTENCY,
    });
    expect(response.statusCode).toBe(400);
    expect(service.calls).toEqual([]);
  });

  it("rejects an oversized body on every write in all three families", async () => {
    const { app, service } = build();
    const oversized = { mutationId: MUTATION, pad: "x".repeat(API_MAX_REQUEST_BYTES) };
    for (const target of ALL_TARGETS) {
      if (target.method !== "POST") continue;
      const response = await app.inject({
        method: "POST",
        url: target.url,
        headers: validHeaders(target),
        payload: oversized,
      });
      expect([target.id, response.statusCode]).toEqual([target.id, 413]);
      expect(errorCode(response)).toBe("REQUEST_TOO_LARGE");
    }
    expect(service.calls).toEqual([]);
  });

  it("rejects a declared content-length above the exact body ceiling", async () => {
    const { app, service } = build();
    for (const target of ALL_TARGETS) {
      if (target.method !== "POST") continue;
      const response = await app.inject({
        method: "POST",
        url: target.url,
        headers: {
          ...validHeaders(target),
          "content-length": String(API_MAX_REQUEST_BYTES + 1),
        },
        payload: target.payload as Record<string, unknown>,
      });
      expect([target.id, response.statusCode]).toEqual([target.id, 413]);
    }
    expect(service.calls).toEqual([]);
  });

  it("rejects a query on every target, including a bare `?`", async () => {
    const { app, service } = build();
    for (const target of ALL_TARGETS) {
      const response = await app.inject({
        method: target.method,
        url: `${target.url}?limit=1`,
        headers: validHeaders(target),
        ...(target.payload !== undefined ? { payload: target.payload } : {}),
      });
      expect([target.id, response.statusCode]).toEqual([target.id, 400]);
    }
    expect(service.calls).toEqual([]);

    const port = await listen(app);
    for (const url of [
      `${DETAIL_URL}?`,
      `${AGENT_MUTATION_URL}?`,
      `${ATTEMPT_URL}?`,
    ]) {
      const raw = await rawHttp(port, "GET", url, [
        `origin: ${ORIGIN}`,
        "x-openarc-client: browser-v1",
        `cookie: ${COOKIE}`,
      ]);
      expect([url, raw.status]).toEqual([url, 400]);
    }
  });

  it("rejects non-canonical and lookalike path parameters", async () => {
    const { app, service } = build();
    for (const url of [
      `${GRANT_CONTROL_PREFIX}/${ORG}/grants/openarc:grant:not-a-uuid`,
      `${GRANT_CONTROL_PREFIX}/${ORG}/grants/${GRANT.toUpperCase()}`,
      `${GRANT_CONTROL_PREFIX}/${ORG}/grant-mutations/${MUTATION}x`,
      `${GRANT_CONTROL_PREFIX}/${ORG}/grants/${encodeURIComponent(GRANT)}%2f`,
    ]) {
      const response = await app.inject({
        method: "GET",
        url,
        headers: readHeaders(),
      });
      expect([url, response.statusCode]).toBeTruthy();
      expect(response.statusCode).toBeGreaterThanOrEqual(400);
    }
    for (const url of [
      `${GRANT_PROVIDER_ATTEMPT_PREFIX}/not-a-uuid`,
      `${GRANT_PROVIDER_ATTEMPT_PREFIX}/${ATTEMPT.toUpperCase()}`,
    ]) {
      const response = await app.inject({
        method: "GET",
        url,
        headers: providerReadHeaders(),
      });
      expect([url, response.statusCode]).toEqual([url, 400]);
    }
    expect(service.calls).toEqual([]);
  });
});

describe("default-off gate", () => {
  it("answers every one of the nine targets with the disabled error and zero service calls", async () => {
    const { app, service } = build({ enabled: false });
    for (const target of ALL_TARGETS) {
      const response = await callTarget(app, target, validHeaders(target));
      expect([target.id, response.statusCode]).toEqual([target.id, 503]);
      expect([target.id, errorCode(response)]).toEqual([
        target.id,
        "FEATURE_DISABLED",
      ]);
      const body = response.json() as { ok?: unknown };
      expect(body.ok).toBe(false);
    }
    expect(service.calls).toEqual([]);
  });

  it("keeps the disabled surface a real API error even behind an HTML fallback", async () => {
    const { app, service } = build({ enabled: false, spaFallback: true });
    for (const target of ALL_TARGETS) {
      const response = await callTarget(app, target, readHeaders());
      expect([target.id, response.statusCode]).toEqual([target.id, 503]);
      expect(response.headers["content-type"]).toContain("application/json");
      expect(response.body).not.toContain("<!doctype html>");
    }
    expect(service.calls).toEqual([]);
  });

  it("claims every frozen target so a fallback can only answer paths the API never claimed", async () => {
    const { app } = build({ spaFallback: true });
    // A path outside the frozen registry falls through to the hostile catch-all.
    // That is exactly why the assertions below matter: they pin that no FROZEN
    // target can ever reach it, enabled or disabled.
    const unclaimed = await app.inject({
      method: "GET",
      url: `${GRANT_CONTROL_PREFIX}/${ORG}/grants/${GRANT}/settle`,
      headers: readHeaders(),
    });
    expect(unclaimed.statusCode).toBe(200);
    for (const target of ALL_TARGETS) {
      const claimed = await app.inject({
        method: target.method,
        url: target.url,
        headers:
          target.method === "GET"
            ? readHeaders()
            : writeHeaders({ "content-type": "text/plain" }),
        ...(target.payload !== undefined ? { payload: target.payload } : {}),
      });
      expect([target.id, claimed.body.includes("<!doctype html>")]).toEqual([
        target.id,
        false,
      ]);
    }
  });
});

describe("errors and responses never echo input or leak a secret", () => {
  it("returns only the fixed catalog envelope for a rejected request", async () => {
    const { app } = build();
    const marker = "canary-input-value";
    const response = await app.inject({
      method: "GET",
      url: `${DETAIL_URL}?after=${marker}`,
      headers: readHeaders({ origin: `https://${marker}.example` }),
    });
    expect(response.statusCode).toBeGreaterThanOrEqual(400);
    expect(response.body).not.toContain(marker);
    expect(response.body).not.toContain(COOKIE);
    expect(response.body).not.toContain(CSRF);
    expect(response.body).not.toContain(SESSION_TOKEN);
    expect(response.body).not.toContain(PROVIDER_TOKEN);
    const body = response.json() as {
      error?: { code?: string; message?: string; retryable?: boolean };
    };
    expect(body.error?.retryable).toBe(false);
    expect(Object.keys(body.error ?? {}).sort()).toEqual([
      "code",
      "message",
      "retryable",
    ]);
  });

  it("never echoes a presented credential in any success body", async () => {
    const { app } = build();
    for (const target of ALL_TARGETS) {
      const response = await callTarget(app, target, validHeaders(target));
      expect([target.id, response.statusCode]).toEqual([target.id, 200]);
      expect(response.body).not.toContain(SESSION_TOKEN);
      expect(response.body).not.toContain(PROVIDER_TOKEN);
      expect(response.body).not.toContain(IDEMPOTENCY);
      expect(response.body).not.toContain(CSRF);
      expect(response.body).not.toContain("openarc_session");
      // No token hash, salt, pepper or digest-of-secret leaf is representable.
      expect(response.body).not.toContain("tokenHash");
      expect(response.body).not.toContain("grantTokenHash");
      expect(response.body).not.toContain("sessionHash");
    }
  });

  it("delivers the one-shot grant token ONLY on a first agent issue", async () => {
    const { app } = build();
    const issued = await callTarget(
      app,
      AGENT_TARGETS[0] as Target,
      agentWriteHeaders(),
    );
    expect(issued.statusCode).toBe(200);
    // Exactly one first-delivery response carries the raw secret.
    expect(issued.body).toContain(GRANT_TOKEN);
    const issuedBody = issued.json() as { data?: Record<string, unknown> };
    expect(issuedBody.data?.["replayed"]).toBe(false);

    // Every other response on this surface — replay, status, detail, revoke,
    // introspection, claim, attempt recovery — is structurally incapable of it.
    for (const target of ALL_TARGETS) {
      if (target.id === "grant_issue") continue;
      const response = await callTarget(app, target, validHeaders(target));
      expect([target.id, response.statusCode]).toEqual([target.id, 200]);
      expect([target.id, response.body.includes(GRANT_TOKEN)]).toEqual([
        target.id,
        false,
      ]);
      expect([target.id, response.body.includes("grantToken")]).toEqual([
        target.id,
        false,
      ]);
    }
  });

  it("writes no credential to stdout, stderr or the console", async () => {
    const { app } = build();
    const captured: string[] = [];
    const stdout = process.stdout.write.bind(process.stdout);
    const stderr = process.stderr.write.bind(process.stderr);
    const consoleMethods = ["log", "info", "warn", "error", "debug"] as const;
    const originals = consoleMethods.map((name) => console[name]);
    process.stdout.write = ((chunk: unknown, ...rest: unknown[]) => {
      captured.push(String(chunk));
      return (stdout as (...args: never[]) => boolean)(
        chunk as never,
        ...(rest as never[]),
      );
    }) as typeof process.stdout.write;
    process.stderr.write = ((chunk: unknown, ...rest: unknown[]) => {
      captured.push(String(chunk));
      return (stderr as (...args: never[]) => boolean)(
        chunk as never,
        ...(rest as never[]),
      );
    }) as typeof process.stderr.write;
    for (const name of consoleMethods) {
      console[name] = ((...args: unknown[]) => {
        captured.push(args.map((entry) => String(entry)).join(" "));
      }) as typeof console.log;
    }
    try {
      // A full successful round, plus a rejected request of each audience.
      for (const target of ALL_TARGETS) {
        await callTarget(app, target, validHeaders(target));
      }
      await callTarget(app, BROWSER_TARGETS[0] as Target, readHeaders({ origin: "https://evil.example" }));
      await callTarget(app, AGENT_TARGETS[2] as Target, agentReadHeaders({ cookie: COOKIE }));
      await callTarget(app, PROVIDER_TARGETS[1] as Target, providerWriteHeaders({ origin: ORIGIN }));
    } finally {
      process.stdout.write = stdout as typeof process.stdout.write;
      process.stderr.write = stderr as typeof process.stderr.write;
      for (const [index, name] of consoleMethods.entries()) {
        console[name] = originals[index] as typeof console.log;
      }
    }
    const log = captured.join("\n");
    for (const secret of [
      SESSION_TOKEN,
      PROVIDER_TOKEN,
      GRANT_TOKEN,
      IDEMPOTENCY,
      CSRF,
      COOKIE,
      "oag_v1_",
      "oacs_v1_",
      "oas_pr_",
    ]) {
      expect([secret, log.includes(secret)]).toEqual([secret, false]);
    }
  });

  it("keeps exact integer money strings on the provider projection", async () => {
    const { app } = build();
    const response = await callTarget(
      app,
      PROVIDER_TARGETS[0] as Target,
      providerIntrospectHeaders(),
    );
    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      data?: { item?: Record<string, unknown> };
    };
    expect(body.data?.item?.["amountAtomic"]).toBe(
      "123456789012345678901234567890",
    );
    expect(body.data?.item?.["debitAtomic"]).toBe(
      "123456789012345678901234567891",
    );
    // The raw text must carry the digits verbatim: no float round-trip.
    expect(response.body).toContain('"123456789012345678901234567891"');
    expect(response.body).not.toContain("1.2345678901234568e+29");
  });
});
