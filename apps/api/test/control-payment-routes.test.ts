import { connect } from "node:net";

import { afterEach, describe, expect, it } from "vitest";
import Fastify, { type FastifyInstance } from "fastify";

import { API_MAX_REQUEST_BYTES, PAYMENT_ROUTES } from "@openarc/shared";

import {
  AUTH_ERRORS,
  AuthApiError,
  authErrorEnvelope,
} from "../src/auth/errors.js";
import {
  PAYMENT_AGENT_ATTEMPTS,
  PAYMENT_AGENT_REQUIREMENTS,
  PAYMENT_PROVIDER_PREFIX,
  paymentRouteTemplates,
  registerCommercePaymentRoutes,
} from "../src/control/payment-routes.js";
import {
  outcomeUnknown,
  type CommercePaymentService,
} from "../src/control/payment-service.js";
import {
  ATTEMPT,
  BUILD_SHA,
  COOKIE,
  CSRF,
  GRANT_TOKEN,
  IDEMPOTENCY,
  LISTING,
  MACHINE_AGENT_TOKEN,
  MUTATION,
  ORG,
  ORIGIN,
  PROVIDER_TOKEN,
  SESSION_TOKEN,
  attemptRecord,
  dispatchedAttempt,
  termsData,
  verifiedRequirement,
} from "./payment-fixtures.js";

/**
 * HTTP-inject coverage for the five-route migration-0015 payment surface.
 *
 * The service is HONESTLY MOCKED: these tests prove the exact inventory, the
 * default-off gate, browser/agent audience separation (cookie on agent routes,
 * `oas_ag_`, provider and grant credentials, bearer on the browser route),
 * transport strictness, path canonicality, the absence of an observation route
 * and that no credential reaches a response body or a log line. Nothing here
 * signs, sends or settles anything.
 */

const TERMS_URL = `${PAYMENT_PROVIDER_PREFIX}/${ORG}/listings/${LISTING}/versions/1/payment-terms`;
const REQUIREMENT_URL = PAYMENT_AGENT_REQUIREMENTS;
const PERSIST_URL = PAYMENT_AGENT_ATTEMPTS;
const DISPATCH_URL = `${PAYMENT_AGENT_ATTEMPTS}/${ATTEMPT}/dispatch`;
const DETAIL_URL = `${PAYMENT_AGENT_ATTEMPTS}/${ATTEMPT}`;

class FakeService {
  readonly calls: string[] = [];
  failWith: Error | null = null;

  #answer<T>(name: string, value: T): T {
    this.calls.push(name);
    if (this.failWith !== null) throw this.failWith;
    return value;
  }
  async recordListingPaymentTerms(): Promise<unknown> {
    return this.#answer("terms", termsData());
  }
  async registerRequirement(): Promise<unknown> {
    return this.#answer("requirement", verifiedRequirement());
  }
  async persistAttempt(): Promise<unknown> {
    return this.#answer("persist", { replayed: false, attempt: attemptRecord() });
  }
  async dispatchAttempt(): Promise<unknown> {
    return this.#answer("dispatch", { attempt: dispatchedAttempt() });
  }
  async getAttempt(): Promise<unknown> {
    return this.#answer("detail", { attemptId: ATTEMPT, item: null });
  }
}

const apps: FastifyInstance[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map(async (app) => app.close()));
});

function build(options: { enabled?: boolean; spaFallback?: boolean } = {}): {
  app: FastifyInstance;
  service: FakeService;
  logs: string[];
} {
  const service = new FakeService();
  const logs: string[] = [];
  const app = Fastify({
    logger: {
      level: "trace",
      stream: {
        write: (line: string) => {
          logs.push(line);
        },
      },
    },
    bodyLimit: API_MAX_REQUEST_BYTES,
    exposeHeadRoutes: false,
    genReqId: () => MUTATION,
  });
  app.setErrorHandler((cause, request, reply) => {
    if (cause instanceof AuthApiError) {
      return reply.code(cause.status).send(authErrorEnvelope(cause, request.id, BUILD_SHA));
    }
    const code =
      typeof cause === "object" && cause !== null && "code" in cause
        ? (cause as { code?: unknown }).code
        : null;
    const mapped =
      code === "FST_ERR_CTP_BODY_TOO_LARGE"
        ? AUTH_ERRORS.tooLarge()
        : code === "FST_ERR_CTP_INVALID_MEDIA_TYPE"
          ? AUTH_ERRORS.unsupportedMedia()
          : AUTH_ERRORS.invalidRequest();
    return reply.code(mapped.status).send(authErrorEnvelope(mapped, request.id, BUILD_SHA));
  });
  registerCommercePaymentRoutes(app, {
    appOrigin: ORIGIN,
    cookieNames: { session: "openarc_session", binding: "openarc_binding" },
    service: service as unknown as CommercePaymentService,
    buildSha: BUILD_SHA,
    enabled: options.enabled ?? true,
  });
  if (options.spaFallback === true) {
    app.setNotFoundHandler((_request, reply) =>
      reply.code(200).type("text/html").send("<!doctype html><html></html>"),
    );
  } else {
    app.setNotFoundHandler((request, reply) =>
      reply.code(404).send(authErrorEnvelope(AUTH_ERRORS.featureDisabled(), request.id, BUILD_SHA)),
    );
  }
  apps.push(app);
  return { app, service, logs };
}

function without(headers: Record<string, string>, name: string): Record<string, string> {
  const copy = { ...headers };
  delete copy[name];
  return copy;
}

const agentWrite = (extra: Record<string, string> = {}): Record<string, string> => ({
  authorization: `Bearer ${SESSION_TOKEN}`,
  "content-type": "application/json",
  ...extra,
});

const agentRead = (extra: Record<string, string> = {}): Record<string, string> => ({
  authorization: `Bearer ${SESSION_TOKEN}`,
  ...extra,
});

const browserWrite = (extra: Record<string, string> = {}): Record<string, string> => ({
  origin: ORIGIN,
  "x-openarc-client": "browser-v1",
  cookie: COOKIE,
  "x-openarc-csrf": CSRF,
  "idempotency-key": IDEMPOTENCY,
  "content-type": "application/json",
  ...extra,
});

const AGENT_WRITES = [REQUIREMENT_URL, PERSIST_URL, DISPATCH_URL] as const;

function errorCode(body: string): string | undefined {
  return (JSON.parse(body) as { error?: { code?: string } }).error?.code;
}

describe("payment route inventory and default-off gate", () => {
  it("registers exactly the five frozen registry templates", () => {
    const { app } = build();
    expect(paymentRouteTemplates().map((route) => [route.id, route.method, route.path])).toEqual(
      PAYMENT_ROUTES.map((route) => [route.id, route.method, route.path]),
    );
    expect(PAYMENT_ROUTES).toHaveLength(5);
    for (const route of PAYMENT_ROUTES) {
      expect(app.hasRoute({ method: route.method, url: route.path })).toBe(true);
    }
  });

  it("answers every target FEATURE_DISABLED before any service work while off, even behind a hostile SPA fallback", async () => {
    const { app, service } = build({ enabled: false, spaFallback: true });
    const targets = [
      { method: "POST" as const, url: TERMS_URL, headers: browserWrite() },
      { method: "POST" as const, url: REQUIREMENT_URL, headers: agentWrite() },
      { method: "POST" as const, url: PERSIST_URL, headers: agentWrite() },
      { method: "POST" as const, url: DISPATCH_URL, headers: agentWrite() },
      { method: "GET" as const, url: DETAIL_URL, headers: agentRead() },
    ];
    for (const target of targets) {
      const response = await app.inject({
        ...target,
        ...(target.method === "POST" ? { payload: {} } : {}),
      });
      // The accepted fixed disabled error, exactly as the grant family answers.
      expect([target.url, response.statusCode]).toEqual([target.url, AUTH_ERRORS.featureDisabled().status]);
      expect(response.headers["content-type"]).toContain("application/json");
      expect(response.body.toLowerCase()).not.toContain("<html");
      expect(errorCode(response.body)).toBe("FEATURE_DISABLED");
    }
    expect(service.calls).toEqual([]);
  });

  it("has no observation, settlement or release route", async () => {
    const { app, service } = build({ spaFallback: false });
    for (const url of [
      `${PAYMENT_AGENT_ATTEMPTS}/${ATTEMPT}/observe`,
      `${PAYMENT_AGENT_ATTEMPTS}/${ATTEMPT}/observation`,
      `${PAYMENT_AGENT_ATTEMPTS}/${ATTEMPT}/settle`,
      `${PAYMENT_AGENT_ATTEMPTS}/${ATTEMPT}/release`,
    ]) {
      const response = await app.inject({ method: "POST", url, headers: agentWrite(), payload: {} });
      expect([url, response.statusCode]).toEqual([url, 404]);
    }
    expect(service.calls).toEqual([]);
  });
});

describe("agent audience: exactly one oacs_v1_ commerce session bearer", () => {
  it("serves every agent route with a canonical commerce session", async () => {
    const { app, service } = build();
    for (const url of AGENT_WRITES) {
      const response = await app.inject({ method: "POST", url, headers: agentWrite(), payload: {} });
      expect([url, response.statusCode]).toEqual([url, 200]);
      expect(response.json()).toMatchObject({ ok: true });
      expect(response.headers["cache-control"]).toBe("no-store");
    }
    const read = await app.inject({ method: "GET", url: DETAIL_URL, headers: agentRead() });
    expect(read.statusCode).toBe(200);
    expect(read.json()).toMatchObject({ ok: true, data: { attemptId: ATTEMPT, item: null } });
    expect(service.calls).toEqual(["requirement", "persist", "dispatch", "detail"]);
  });

  it("rejects oas_ag_, oas_pr_, a grant token and a missing bearer with 401 before the service", async () => {
    const { app, service } = build();
    for (const authorization of [
      `Bearer ${MACHINE_AGENT_TOKEN}`,
      `Bearer ${PROVIDER_TOKEN}`,
      `Bearer ${GRANT_TOKEN}`,
      `Bearer ${SESSION_TOKEN.slice(0, -1)}`,
      SESSION_TOKEN,
    ]) {
      for (const url of AGENT_WRITES) {
        const response = await app.inject({ method: "POST", url, headers: agentWrite({ authorization }), payload: {} });
        expect([url, response.statusCode]).toEqual([url, 401]);
      }
      const read = await app.inject({ method: "GET", url: DETAIL_URL, headers: agentRead({ authorization }) });
      expect(read.statusCode).toBe(401);
    }
    const missing = await app.inject({ method: "POST", url: PERSIST_URL, headers: without(agentWrite(), "authorization"), payload: {} });
    expect(missing.statusCode).toBe(401);
    expect(service.calls).toEqual([]);
  });

  it("rejects a browser cookie, Origin, CSRF, client marker or proxy credential on every agent route", async () => {
    const { app, service } = build();
    for (const [name, value] of [
      ["cookie", COOKIE],
      ["origin", ORIGIN],
      ["x-openarc-csrf", CSRF],
      ["x-openarc-client", "browser-v1"],
      ["sec-fetch-site", "same-origin"],
      ["proxy-authorization", "Basic abc"],
    ] as const) {
      for (const url of AGENT_WRITES) {
        const response = await app.inject({ method: "POST", url, headers: agentWrite({ [name]: value }), payload: {} });
        expect([name, url, response.statusCode]).toEqual([name, url, 400]);
      }
      const read = await app.inject({ method: "GET", url: DETAIL_URL, headers: agentRead({ [name]: value }) });
      expect([name, read.statusCode]).toEqual([name, 400]);
    }
    expect(service.calls).toEqual([]);
  });

  it("rejects an Idempotency-Key, a query string, a wrong verb and a non-JSON body on agent writes", async () => {
    const { app, service } = build();
    for (const url of AGENT_WRITES) {
      const keyed = await app.inject({ method: "POST", url, headers: agentWrite({ "idempotency-key": IDEMPOTENCY }), payload: {} });
      expect(keyed.statusCode).toBe(400);
      const query = await app.inject({ method: "POST", url: `${url}?x=1`, headers: agentWrite(), payload: {} });
      expect(query.statusCode).toBe(400);
      const verb = await app.inject({ method: "PUT", url, headers: agentWrite(), payload: {} });
      expect(verb.statusCode).toBe(405);
      const text = await app.inject({ method: "POST", url, headers: agentWrite({ "content-type": "text/plain" }), payload: "{}" });
      expect(text.statusCode).toBe(415);
    }
    const readPost = await app.inject({ method: "POST", url: DETAIL_URL, headers: agentWrite(), payload: {} });
    expect(readPost.statusCode).toBe(405);
    const readQuery = await app.inject({ method: "GET", url: `${DETAIL_URL}?x=1`, headers: agentRead() });
    expect(readQuery.statusCode).toBe(400);
    expect(service.calls).toEqual([]);
  });

  it("rejects non-canonical attempt ids and extra segments", async () => {
    const { app, service } = build();
    for (const url of [
      `${PAYMENT_AGENT_ATTEMPTS}/12345678-1234-1234-8123-123456789abc/dispatch`,
      `${PAYMENT_AGENT_ATTEMPTS}/NOT-AN-ID/dispatch`,
      `${PAYMENT_AGENT_ATTEMPTS}/${ATTEMPT.toUpperCase()}/dispatch`,
    ]) {
      const response = await app.inject({ method: "POST", url, headers: agentWrite(), payload: {} });
      expect([url, response.statusCode]).toEqual([url, 400]);
    }
    const extra = await app.inject({ method: "POST", url: `${DISPATCH_URL}/extra`, headers: agentWrite(), payload: {} });
    expect(extra.statusCode).toBe(404);
    expect(service.calls).toEqual([]);
  });
});

describe("browser audience: the seller terms record", () => {
  it("serves a cookie + Origin + marker + CSRF + idempotency write", async () => {
    const { app, service } = build();
    const response = await app.inject({ method: "POST", url: TERMS_URL, headers: browserWrite(), payload: {} });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ ok: true, data: { replayed: false } });
    expect(service.calls).toEqual(["terms"]);
  });

  it("rejects every bearer namespace and every missing browser guard before the service", async () => {
    const { app, service } = build();
    const cases: readonly [Record<string, string>, number][] = [
      [browserWrite({ authorization: `Bearer ${SESSION_TOKEN}` }), 400],
      [browserWrite({ authorization: `Bearer ${MACHINE_AGENT_TOKEN}` }), 400],
      [browserWrite({ authorization: `Bearer ${PROVIDER_TOKEN}` }), 400],
      [browserWrite({ "proxy-authorization": "Basic abc" }), 400],
      [without(browserWrite(), "x-openarc-csrf"), 400],
      [without(browserWrite(), "idempotency-key"), 400],
      [browserWrite({ "idempotency-key": "short" }), 400],
      [browserWrite({ origin: "https://evil.example" }), 403],
      [without(browserWrite(), "origin"), 403],
      [without(browserWrite(), "x-openarc-client"), 403],
      [browserWrite({ "sec-fetch-site": "cross-site" }), 403],
      [browserWrite({ "content-type": "text/plain" }), 415],
    ];
    for (const [headers, status] of cases) {
      const response = await app.inject({ method: "POST", url: TERMS_URL, headers, payload: {} });
      expect([headers, response.statusCode]).toEqual([headers, status]);
    }
    const get = await app.inject({ method: "GET", url: TERMS_URL, headers: without(browserWrite(), "content-type") });
    expect(get.statusCode).toBe(405);
    const query = await app.inject({ method: "POST", url: `${TERMS_URL}?x=1`, headers: browserWrite(), payload: {} });
    expect(query.statusCode).toBe(400);
    expect(service.calls).toEqual([]);
  });

  it("rejects non-canonical organization, listing and version path segments", async () => {
    const { app, service } = build();
    for (const url of [
      `${PAYMENT_PROVIDER_PREFIX}/${ORG}/listings/${LISTING}/versions/0/payment-terms`,
      `${PAYMENT_PROVIDER_PREFIX}/${ORG}/listings/${LISTING}/versions/01/payment-terms`,
      `${PAYMENT_PROVIDER_PREFIX}/12345678-1234-4234-8123-123456789abc/listings/${LISTING}/versions/1/payment-terms`,
      `${PAYMENT_PROVIDER_PREFIX}/${ORG}/listings/openarc:provider:12345678-1234-4234-8123-123456789abc/versions/1/payment-terms`,
    ]) {
      const response = await app.inject({ method: "POST", url, headers: browserWrite(), payload: {} });
      expect([url, response.statusCode]).toEqual([url, 400]);
    }
    expect(service.calls).toEqual([]);
  });
});

/**
 * light-my-request drops a bare trailing `?`, so the bare-query refusal is
 * proven over a real loopback socket against the listening app.
 */
async function rawStatus(port: number, request: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = connect(port, "127.0.0.1", () => {
      socket.write(request);
    });
    let data = "";
    socket.on("data", (chunk: Buffer) => {
      data += chunk.toString("utf8");
    });
    socket.on("end", () => resolve(data.split("\r\n", 1)[0] ?? ""));
    socket.on("error", reject);
  });
}

describe("bare query refusal over a real socket", () => {
  it("rejects a bare ? on the agent writes, the agent read and the seller write", async () => {
    const { app, service } = build();
    await app.listen({ host: "127.0.0.1", port: 0 });
    const address = app.server.address();
    const port = typeof address === "object" && address !== null ? address.port : 0;
    const post = (url: string, headers: string) =>
      `POST ${url}? HTTP/1.1\r\nHost: 127.0.0.1\r\n${headers}Content-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}`;
    const bearer = `Authorization: Bearer ${SESSION_TOKEN}\r\n`;
    for (const url of AGENT_WRITES) {
      expect([url, await rawStatus(port, post(url, bearer))]).toEqual([url, "HTTP/1.1 400 Bad Request"]);
    }
    expect(
      await rawStatus(port, `GET ${DETAIL_URL}? HTTP/1.1\r\nHost: 127.0.0.1\r\n${bearer}Connection: close\r\n\r\n`),
    ).toBe("HTTP/1.1 400 Bad Request");
    const browserHeaders =
      `Origin: ${ORIGIN}\r\nX-OpenArc-Client: browser-v1\r\nCookie: ${COOKIE}\r\nX-OpenArc-CSRF: ${CSRF}\r\nIdempotency-Key: ${IDEMPOTENCY}\r\n`;
    expect(await rawStatus(port, post(TERMS_URL, browserHeaders))).toBe("HTTP/1.1 400 Bad Request");
    expect(service.calls).toEqual([]);
  });
});

describe("error envelopes and secret discipline", () => {
  it("keeps an unknown outcome a non-retryable 500 and a refused dispatch a non-retryable 409", async () => {
    const { app, service } = build();
    service.failWith = outcomeUnknown();
    const unknown = await app.inject({ method: "POST", url: DISPATCH_URL, headers: agentWrite(), payload: {} });
    expect(unknown.statusCode).toBe(500);
    expect(unknown.json()).toMatchObject({ ok: false, error: { code: "INTERNAL_ERROR", retryable: false } });
    service.failWith = new AuthApiError("POLICY_DENIED", 409, "INVALID_REQUEST");
    const again = await app.inject({ method: "POST", url: DISPATCH_URL, headers: agentWrite(), payload: {} });
    expect(again.statusCode).toBe(409);
    expect(again.json()).toMatchObject({ ok: false, error: { code: "POLICY_DENIED", retryable: false } });
    expect(again.body).not.toContain('"data"');
  });

  it("never writes a credential into a response body or a log line", async () => {
    const { app, logs } = build();
    const bodies: string[] = [];
    const requests = [
      { method: "POST" as const, url: TERMS_URL, headers: browserWrite(), payload: {} },
      { method: "POST" as const, url: TERMS_URL, headers: browserWrite({ authorization: `Bearer ${SESSION_TOKEN}` }), payload: {} },
      { method: "POST" as const, url: PERSIST_URL, headers: agentWrite(), payload: {} },
      { method: "POST" as const, url: PERSIST_URL, headers: agentWrite({ authorization: `Bearer ${MACHINE_AGENT_TOKEN}` }), payload: {} },
      { method: "POST" as const, url: DISPATCH_URL, headers: agentWrite({ cookie: COOKIE }), payload: {} },
      { method: "GET" as const, url: DETAIL_URL, headers: agentRead() },
    ];
    for (const request of requests) {
      bodies.push((await app.inject(request)).body);
    }
    const everything = [...bodies, ...logs].join("\n");
    expect(logs.length).toBeGreaterThan(0);
    for (const secret of [SESSION_TOKEN, MACHINE_AGENT_TOKEN, PROVIDER_TOKEN, GRANT_TOKEN, CSRF, COOKIE, IDEMPOTENCY]) {
      expect(everything).not.toContain(secret);
    }
  });
});
