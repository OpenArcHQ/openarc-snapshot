import { connect } from "node:net";

import { afterEach, describe, expect, it } from "vitest";
import Fastify, { type FastifyInstance } from "fastify";

import { API_MAX_REQUEST_BYTES, SESSION_ROUTES } from "@openarc/shared";

import { AUTH_ERRORS, AuthApiError, authErrorEnvelope } from "../src/auth/errors.js";
import {
  COMMERCE_SESSION_AGENT_EXCHANGE,
  COMMERCE_SESSION_AGENT_MUTATION_PREFIX,
  COMMERCE_SESSION_CONTROL_PREFIX,
  registerCommerceSessionRoutes,
} from "../src/control/session-routes.js";
import type { CommerceSessionService } from "../src/control/session-service.js";

/**
 * HTTP-inject and raw-TCP coverage for the commerce-session surface.
 *
 * The CommerceSessionService is HONESTLY MOCKED here: these tests prove the
 * seven-route inventory, transport strictness, path/query canonicality,
 * envelope shape and credential denial. Injected fakes are never a production
 * path.
 */

const ORIGIN = "http://localhost:5183";
const BUILD_SHA = "0123456789abcdef0123456789abcdef01234567";
const CLIENT = { origin: ORIGIN, "x-openarc-client": "browser-v1" };
const COOKIE = "openarc_session=abc";
const CSRF = "csrf-token-value";
const IDEMPOTENCY = "A".repeat(43);
const MUTATION = "12345678-1234-4234-8123-123456789abc";
const ORG = `openarc:org:${MUTATION}`;
const AGENT = `openarc:agent:${MUTATION}`;
const POLICY = `openarc:policy:${MUTATION}`;
const SESSION = MUTATION;
const ISSUED = "2026-01-01T00:00:00.000Z";
const EXPIRES = "2026-01-01T00:05:00.000Z";
const HANDOFF_EXPIRES = "2026-01-01T00:00:10.000Z";
const AGENT_TOKEN = `oas_ag_${"A".repeat(43)}`;
const HANDOFF_TOKEN = `oach_v1_${"A".repeat(43)}`;
const SESSION_TOKEN = `oacs_v1_${"E".repeat(43)}`;

const LIST_URL = `${COMMERCE_SESSION_CONTROL_PREFIX}/${ORG}/commerce-sessions`;
const STATUS_URL = `${LIST_URL}/${SESSION}`;
const REVOKE_URL = `${STATUS_URL}/revoke`;
const HUMAN_MUTATION_URL = `${COMMERCE_SESSION_CONTROL_PREFIX}/${ORG}/commerce-session-mutations/${MUTATION}`;
const AGENT_MUTATION_URL = `${COMMERCE_SESSION_AGENT_MUTATION_PREFIX}/${MUTATION}`;

function metadata(overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: "openarc.control.commerce-session.v1",
    sessionId: SESSION,
    organizationId: ORG,
    subjectAgentId: AGENT,
    policyId: POLICY,
    scopes: ["commerce.authorize"],
    networkId: "eip155:5042002",
    asset: "USDC",
    representation: "erc20",
    decimals: 6,
    issuedAt: ISSUED,
    expiresAt: EXPIRES,
    exchangedAt: null,
    revokedAt: null,
    ...overrides,
  };
}

function receipt(operation: string) {
  return {
    mutationId: MUTATION,
    operation,
    resourceType: "commerce_session",
    resourceId: SESSION,
    committedAt: ISSUED,
  };
}

class FakeService {
  readonly calls: string[] = [];

  async issue(): Promise<unknown> {
    this.calls.push("issue");
    return {
      organizationId: ORG,
      replayed: false,
      metadata: metadata(),
      receipt: receipt("control.commerce_session.issue"),
      delivery: {
        state: "available_once",
        handoffToken: HANDOFF_TOKEN,
        handoffExpiresAt: HANDOFF_EXPIRES,
      },
    };
  }
  async revoke(): Promise<unknown> {
    this.calls.push("revoke");
    return {
      organizationId: ORG,
      replayed: false,
      metadata: metadata({ revokedAt: "2026-01-01T00:01:00.000Z" }),
      receipt: receipt("control.commerce_session.revoke"),
    };
  }
  async list(): Promise<unknown> {
    this.calls.push("list");
    return { organizationId: ORG, items: [], nextCursor: null };
  }
  async getStatus(): Promise<unknown> {
    this.calls.push("status");
    return { organizationId: ORG, item: null };
  }
  async getHumanMutationStatus(): Promise<unknown> {
    this.calls.push("humanStatus");
    return { organizationId: ORG, mutationId: MUTATION, status: "not_found" };
  }
  async exchange(): Promise<unknown> {
    this.calls.push("exchange");
    return {
      organizationId: ORG,
      replayed: false,
      metadata: metadata({ exchangedAt: "2026-01-01T00:00:30.000Z" }),
      receipt: receipt("control.commerce_session.exchange"),
      delivery: { state: "available_once", sessionToken: SESSION_TOKEN },
    };
  }
  async getAgentMutationStatus(): Promise<unknown> {
    this.calls.push("agentStatus");
    return { organizationId: ORG, mutationId: MUTATION, status: "not_found" };
  }
}

const apps: FastifyInstance[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map(async (app) => app.close()));
});

function build(options: {
  readonly enabled?: boolean;
  readonly maxResponseBytes?: number;
} = {}): {
  app: FastifyInstance;
  service: FakeService;
} {
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
        : code === "FST_ERR_CTP_INVALID_MEDIA_TYPE" ||
            code === "FST_ERR_CTP_INVALID_JSON" ||
            code === "FST_ERR_BAD_URL"
          ? AUTH_ERRORS.invalidRequest()
          : AUTH_ERRORS.invalidRequest();
    return reply
      .code(mapped.status)
      .send(authErrorEnvelope(mapped, request.id, BUILD_SHA));
  });
  app.setNotFoundHandler((request, reply) =>
    reply.code(404).send(authErrorEnvelope(AUTH_ERRORS.featureDisabled(), request.id, BUILD_SHA)),
  );
  registerCommerceSessionRoutes(app, {
    appOrigin: ORIGIN,
    cookieNames: { session: "openarc_session", binding: "openarc_binding" },
    service: service as unknown as CommerceSessionService,
    buildSha: BUILD_SHA,
    enabled: options.enabled ?? true,
    ...(options.maxResponseBytes !== undefined
      ? { maxResponseBytes: options.maxResponseBytes }
      : {}),
  });
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

function agentWriteHeaders(extra: Record<string, string> = {}) {
  return {
    authorization: `Bearer ${AGENT_TOKEN}`,
    "content-type": "application/json",
    "idempotency-key": IDEMPOTENCY,
    ...extra,
  };
}

function errorCode(response: { json: () => unknown }): string {
  const body = response.json() as { error?: { code?: string } };
  return body.error?.code ?? "";
}

function rawHttp(
  port: number,
  method: string,
  path: string,
  headers: readonly string[],
  body = "",
): Promise<{ status: number; text: string }> {
  const payload = Buffer.from(body, "utf8");
  const lines = [
    `${method} ${path} HTTP/1.1`,
    "Host: 127.0.0.1",
    ...headers,
    `content-length: ${payload.byteLength}`,
    "connection: close",
    "",
    "",
  ];
  return new Promise((resolve, reject) => {
    const socket = connect({ port, host: "127.0.0.1" });
    let text = "";
    socket.on("connect", () => socket.end(`${lines.join("\r\n")}${body}`));
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

/** Start the app on an ephemeral port and return it, for exact raw targets. */
async function listen(app: FastifyInstance): Promise<number> {
  await app.listen({ port: 0, host: "127.0.0.1" });
  const address = app.server.address();
  return typeof address === "object" && address !== null ? address.port : 0;
}

describe("commerce-session route registry", () => {
  it("registers NO route while disabled", async () => {
    const { app } = build({ enabled: false });
    for (const response of await Promise.all([
      app.inject({ method: "GET", url: LIST_URL, headers: readHeaders() }),
      app.inject({ method: "POST", url: COMMERCE_SESSION_AGENT_EXCHANGE, headers: agentWriteHeaders(), payload: {} }),
    ])) {
      expect(response.statusCode).toBe(404);
    }
  });

  it("accepts the five browser management targets", async () => {
    const { app } = build();
    const list = await app.inject({ method: "GET", url: LIST_URL, headers: readHeaders() });
    expect(list.statusCode).toBe(200);
    const issue = await app.inject({
      method: "POST",
      url: LIST_URL,
      headers: writeHeaders(),
      payload: { mutationId: MUTATION, subjectAgentId: AGENT, policyId: POLICY },
    });
    expect(issue.statusCode).toBe(200);
    const status = await app.inject({ method: "GET", url: STATUS_URL, headers: readHeaders() });
    expect(status.statusCode).toBe(200);
    const revoke = await app.inject({
      method: "POST",
      url: REVOKE_URL,
      headers: writeHeaders(),
      payload: { mutationId: MUTATION },
    });
    expect(revoke.statusCode).toBe(200);
    const human = await app.inject({
      method: "GET",
      url: HUMAN_MUTATION_URL,
      headers: readHeaders(),
    });
    expect(human.statusCode).toBe(200);
  });

  it("accepts the two agent exchange targets", async () => {
    const { app } = build();
    const exchange = await app.inject({
      method: "POST",
      url: COMMERCE_SESSION_AGENT_EXCHANGE,
      headers: agentWriteHeaders(),
      payload: { mutationId: MUTATION, handoffToken: HANDOFF_TOKEN },
    });
    expect(exchange.statusCode).toBe(200);
    const status = await app.inject({
      method: "GET",
      url: AGENT_MUTATION_URL,
      headers: { authorization: `Bearer ${AGENT_TOKEN}` },
    });
    expect(status.statusCode).toBe(200);
  });
});

describe("human transport strictness", () => {
  it("rejects a foreign Origin and a missing browser marker", async () => {
    const { app } = build();
    const foreign = await app.inject({
      method: "GET",
      url: LIST_URL,
      headers: { origin: "https://evil.example", "x-openarc-client": "browser-v1", cookie: COOKIE },
    });
    expect(foreign.statusCode).toBe(403);
    expect(errorCode(foreign)).toBe("INVALID_ORIGIN");
    const noMarker = await app.inject({
      method: "GET",
      url: LIST_URL,
      headers: { origin: ORIGIN, cookie: COOKIE },
    });
    expect(noMarker.statusCode).toBe(403);
  });

  it("rejects Authorization on the human family", async () => {
    const { app } = build();
    const response = await app.inject({
      method: "GET",
      url: LIST_URL,
      headers: readHeaders({ authorization: `Bearer ${AGENT_TOKEN}` }),
    });
    expect(response.statusCode).toBe(400);
  });

  it("rejects unknown and bare queries on the list route", async () => {
    const { app } = build();
    const unknown = await app.inject({
      method: "GET",
      url: `${LIST_URL}?bogus=1`,
      headers: readHeaders(),
    });
    expect(unknown.statusCode).toBe(400);
    // An injector normalizes a bare `?` away; assert the exact raw target.
    const port = await listen(app);
    const bare = await rawHttp(port, "GET", `${LIST_URL}?`, [
      `origin: ${ORIGIN}`,
      "x-openarc-client: browser-v1",
      `cookie: ${COOKIE}`,
    ]);
    expect(bare.status).toBe(400);
  });

  it("allows the canonical list query only", async () => {
    const { app } = build();
    const ok = await app.inject({
      method: "GET",
      url: `${LIST_URL}?limit=25&afterSessionId=${SESSION}`,
      headers: readHeaders(),
    });
    expect(ok.statusCode).toBe(200);
    const badLimit = await app.inject({
      method: "GET",
      url: `${LIST_URL}?limit=51`,
      headers: readHeaders(),
    });
    expect(badLimit.statusCode).toBe(400);
  });

  it("rejects any query on status, revoke and human mutation targets", async () => {
    const { app } = build();
    const port = await listen(app);
    const headers = [
      `origin: ${ORIGIN}`,
      "x-openarc-client: browser-v1",
      `cookie: ${COOKIE}`,
    ];
    const withQuery = await rawHttp(port, "GET", `${STATUS_URL}?x=1`, headers);
    expect(withQuery.status).toBe(400);
    const bare = await rawHttp(port, "GET", `${HUMAN_MUTATION_URL}?`, headers);
    expect(bare.status).toBe(400);
  });

  it("requires CSRF and idempotency on writes", async () => {
    const { app } = build();
    const noCsrf = await app.inject({
      method: "POST",
      url: LIST_URL,
      headers: {
        ...CLIENT,
        "content-type": "application/json",
        cookie: COOKIE,
        "idempotency-key": IDEMPOTENCY,
      },
      payload: { mutationId: MUTATION, subjectAgentId: AGENT, policyId: POLICY },
    });
    expect(noCsrf.statusCode).toBe(400);
    const noKey = await app.inject({
      method: "POST",
      url: LIST_URL,
      headers: {
        ...CLIENT,
        "content-type": "application/json",
        cookie: COOKIE,
        "x-openarc-csrf": CSRF,
      },
      payload: { mutationId: MUTATION, subjectAgentId: AGENT, policyId: POLICY },
    });
    expect(noKey.statusCode).toBe(400);
  });

  it("detects a duplicate critical header on the raw wire", async () => {
    const { app } = build();
    const port = await listen(app);
    const response = await rawHttp(port, "GET", LIST_URL, [
      "origin: " + ORIGIN,
      "x-openarc-client: browser-v1",
      "x-openarc-client: browser-v1",
      "cookie: " + COOKIE,
    ]);
    expect(response.status).toBe(400);
  });
});

describe("agent transport strictness", () => {
  it("rejects long-lived, provider and commerce session tokens", async () => {
    const { app } = build();
    for (const token of [
      `oac_ag_${MUTATION}_${"A".repeat(43)}`,
      `oas_pr_${"A".repeat(43)}`,
      `oacs_v1_${"A".repeat(43)}`,
    ]) {
      const response = await app.inject({
        method: "POST",
        url: COMMERCE_SESSION_AGENT_EXCHANGE,
        headers: agentWriteHeaders({ authorization: `Bearer ${token}` }),
        payload: { mutationId: MUTATION, handoffToken: HANDOFF_TOKEN },
      });
      expect(response.statusCode).toBe(401);
    }
  });

  it("rejects browser credentials on the agent family", async () => {
    const { app } = build();
    for (const extra of [
      { cookie: COOKIE },
      { origin: ORIGIN },
      { "x-openarc-csrf": CSRF },
      { "proxy-authorization": "Basic x" },
    ]) {
      const response = await app.inject({
        method: "POST",
        url: COMMERCE_SESSION_AGENT_EXCHANGE,
        headers: agentWriteHeaders(extra),
        payload: { mutationId: MUTATION, handoffToken: HANDOFF_TOKEN },
      });
      expect(response.statusCode).toBe(400);
    }
  });

  it("requires a canonical idempotency key and a strict body on exchange", async () => {
    const { app } = build();
    const noKey = await app.inject({
      method: "POST",
      url: COMMERCE_SESSION_AGENT_EXCHANGE,
      headers: {
        authorization: `Bearer ${AGENT_TOKEN}`,
        "content-type": "application/json",
      },
      payload: { mutationId: MUTATION, handoffToken: HANDOFF_TOKEN },
    });
    expect(noKey.statusCode).toBe(400);
    const extraField = await app.inject({
      method: "POST",
      url: COMMERCE_SESSION_AGENT_EXCHANGE,
      headers: agentWriteHeaders(),
      payload: { mutationId: MUTATION, handoffToken: HANDOFF_TOKEN, extra: 1 },
    });
    // The service (not the route) owns strict body parsing; the fake accepts it.
    expect(extraField.statusCode).toBe(200);
  });

  it("rejects a query and an idempotency key on agent status", async () => {
    const { app } = build();
    const query = await app.inject({
      method: "GET",
      url: `${AGENT_MUTATION_URL}?x=1`,
      headers: { authorization: `Bearer ${AGENT_TOKEN}` },
    });
    expect(query.statusCode).toBe(400);
    const idempotency = await app.inject({
      method: "GET",
      url: AGENT_MUTATION_URL,
      headers: {
        authorization: `Bearer ${AGENT_TOKEN}`,
        "idempotency-key": IDEMPOTENCY,
      },
    });
    expect(idempotency.statusCode).toBe(400);
  });
});

describe("path canonicality", () => {
  it("rejects extra segments and encoded aliases", async () => {
    const { app } = build();
    const extra = await app.inject({
      method: "GET",
      url: `${LIST_URL}/extra`,
      headers: readHeaders(),
    });
    expect(extra.statusCode).toBe(400);
    // A single canonical percent-encoding decodes exactly once to the canonical
    // organization id and is accepted; a double-encoded residual alias is not.
    const canonical = await app.inject({
      method: "GET",
      url: `${COMMERCE_SESSION_CONTROL_PREFIX}/${encodeURIComponent(ORG)}/commerce-sessions`,
      headers: readHeaders(),
    });
    expect(canonical.statusCode).toBe(200);
    const encoded = await app.inject({
      method: "GET",
      url: `${COMMERCE_SESSION_CONTROL_PREFIX}/${encodeURIComponent(
        encodeURIComponent(ORG),
      )}/commerce-sessions`,
      headers: readHeaders(),
    });
    expect(encoded.statusCode).toBe(400);
  });
});

describe("frozen transport evidence", () => {
  it("rejects a duplicate human Cookie on the raw wire before the service", async () => {
    const { app, service } = build();
    const port = await listen(app);
    const response = await rawHttp(port, "GET", LIST_URL, [
      `origin: ${ORIGIN}`,
      "x-openarc-client: browser-v1",
      `cookie: ${COOKIE}`,
      `cookie: ${COOKIE}`,
    ]);
    expect(response.status).toBe(400);
    expect(service.calls).toEqual([]);
  });

  it("rejects a duplicate human Origin on the raw wire before the service", async () => {
    const { app, service } = build();
    const port = await listen(app);
    const response = await rawHttp(port, "GET", LIST_URL, [
      `origin: ${ORIGIN}`,
      `origin: ${ORIGIN}`,
      "x-openarc-client: browser-v1",
      `cookie: ${COOKIE}`,
    ]);
    expect(response.status).toBe(400);
    expect(service.calls).toEqual([]);
  });

  it("rejects a duplicate agent Authorization and Idempotency-Key before the service", async () => {
    for (const duplicate of [
      [
        `authorization: Bearer ${AGENT_TOKEN}`,
        `authorization: Bearer ${AGENT_TOKEN}`,
        "content-type: application/json",
        `idempotency-key: ${IDEMPOTENCY}`,
      ],
      [
        `authorization: Bearer ${AGENT_TOKEN}`,
        "content-type: application/json",
        `idempotency-key: ${IDEMPOTENCY}`,
        `idempotency-key: ${IDEMPOTENCY}`,
      ],
    ]) {
      const { app, service } = build();
      const port = await listen(app);
      const response = await rawHttp(
        port,
        "POST",
        COMMERCE_SESSION_AGENT_EXCHANGE,
        duplicate,
        JSON.stringify({ mutationId: MUTATION, handoffToken: HANDOFF_TOKEN }),
      );
      expect(response.status).toBe(400);
      expect(service.calls).toEqual([]);
    }
  });

  it("rejects unsupported methods for every registry route before the service", async () => {
    const { app, service } = build();
    for (const route of SESSION_ROUTES) {
      const isAgent = route.family === "commerce_session_exchange";
      const headers = isAgent
        ? {
            authorization: `Bearer ${AGENT_TOKEN}`,
            "content-type": "application/json",
            "idempotency-key": IDEMPOTENCY,
          }
        : { origin: ORIGIN, "x-openarc-client": "browser-v1", cookie: COOKIE };
      const url = route.path
        .replace(":organizationId", ORG)
        .replace(":sessionId", SESSION)
        .replace(":mutationId", MUTATION);
      for (const method of ["HEAD", "OPTIONS", "PUT", "DELETE"] as const) {
        const response = await app.inject({ method, url, headers });
        expect(
          response.statusCode,
          `${method} ${url} -> ${errorCode(response)}`,
        ).toBe(405);
      }
    }
    expect(service.calls).toEqual([]);
  });

  it("rejects a representative >16KiB body as a fixed REQUEST_TOO_LARGE", async () => {
    const { app } = build();
    const port = await listen(app);
    const oversized = JSON.stringify({
      mutationId: MUTATION,
      handoffToken: HANDOFF_TOKEN,
      padding: "a".repeat(API_MAX_REQUEST_BYTES),
    });
    expect(Buffer.byteLength(oversized, "utf8")).toBeGreaterThan(
      API_MAX_REQUEST_BYTES,
    );
    const response = await rawHttp(
      port,
      "POST",
      COMMERCE_SESSION_AGENT_EXCHANGE,
      [
        `authorization: Bearer ${AGENT_TOKEN}`,
        "content-type: application/json",
        `idempotency-key: ${IDEMPOTENCY}`,
      ],
      oversized,
    );
    expect(response.status).toBe(413);
  });

  it("rejects a >16KiB human issue body as a fixed REQUEST_TOO_LARGE", async () => {
    const { app } = build();
    const port = await listen(app);
    const oversized = JSON.stringify({
      mutationId: MUTATION,
      subjectAgentId: AGENT,
      policyId: POLICY,
      padding: "a".repeat(API_MAX_REQUEST_BYTES),
    });
    const response = await rawHttp(port, "POST", LIST_URL, [
      `origin: ${ORIGIN}`,
      "x-openarc-client: browser-v1",
      `cookie: ${COOKIE}`,
      "content-type: application/json",
      `x-openarc-csrf: ${CSRF}`,
      `idempotency-key: ${IDEMPOTENCY}`,
    ], oversized);
    expect(response.status).toBe(413);
  });

  it("caps an oversized fake service response with the fixed 500", async () => {
    const { app } = build({ maxResponseBytes: 16 });
    const response = await app.inject({
      method: "GET",
      url: LIST_URL,
      headers: readHeaders(),
    });
    expect(response.statusCode).toBe(500);
    expect(errorCode(response)).toBe("INTERNAL_ERROR");
  });

  it("sends no cookie, no CORS grant and no-store on fresh issue and exchange", async () => {
    const { app } = build();
    const issue = await app.inject({
      method: "POST",
      url: LIST_URL,
      headers: writeHeaders(),
      payload: { mutationId: MUTATION, subjectAgentId: AGENT, policyId: POLICY },
    });
    const exchange = await app.inject({
      method: "POST",
      url: COMMERCE_SESSION_AGENT_EXCHANGE,
      headers: agentWriteHeaders(),
      payload: { mutationId: MUTATION, handoffToken: HANDOFF_TOKEN },
    });
    for (const response of [issue, exchange]) {
      expect(response.statusCode).toBe(200);
      expect(response.headers["cache-control"]).toBe("no-store");
      expect(response.headers["set-cookie"]).toBeUndefined();
      expect(response.headers["access-control-allow-origin"]).toBeUndefined();
      expect(response.headers["access-control-allow-credentials"]).toBeUndefined();
    }
  });
});
