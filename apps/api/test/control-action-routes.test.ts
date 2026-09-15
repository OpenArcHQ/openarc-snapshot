import { connect } from "node:net";

import { afterEach, describe, expect, it } from "vitest";
import Fastify, { type FastifyInstance } from "fastify";

import { ACTION_ROUTES, API_MAX_REQUEST_BYTES } from "@openarc/shared";

import {
  AUTH_ERRORS,
  AuthApiError,
  authErrorEnvelope,
} from "../src/auth/errors.js";
import {
  ACTION_AGENT_ACTIONS,
  ACTION_AGENT_MUTATION_PREFIX,
  ACTION_CONTROL_PREFIX,
  actionRouteTemplates,
  registerCommerceActionRoutes,
} from "../src/control/action-routes.js";
import type { CommerceActionService } from "../src/control/action-service.js";
import {
  ACTION,
  APPROVAL,
  AGENT,
  AGENT_TOKEN,
  BUILD_SHA,
  COOKIE,
  CSRF,
  IDEMPOTENCY,
  MUTATION,
  ORG,
  ORIGIN,
  POLICY,
  SESSION_TOKEN,
  actionMetadata,
  actionReceipt,
  approvalMetadata,
  exposureView,
} from "./action-fixtures.js";

/**
 * HTTP-inject coverage for the twelve-route commerce-action surface.
 *
 * The CommerceActionService is HONESTLY MOCKED: these tests prove the exact
 * twelve-route inventory, browser/agent audience separation in BOTH directions,
 * transport strictness, path/query canonicality, the default-off gate and the
 * envelope shape. Injected fakes are never a production path and nothing here
 * performs a payment, settlement or delivery.
 */

const CLIENT = { origin: ORIGIN, "x-openarc-client": "browser-v1" };

const ACTIONS_URL = `${ACTION_CONTROL_PREFIX}/${ORG}/actions`;
const ACTION_URL = `${ACTIONS_URL}/${ACTION}`;
const APPROVE_URL = `${ACTION_URL}/approve`;
const REJECT_URL = `${ACTION_URL}/reject`;
const CANCEL_URL = `${ACTION_URL}/cancel`;
const APPROVALS_URL = `${ACTION_CONTROL_PREFIX}/${ORG}/approvals`;
const APPROVAL_URL = `${APPROVALS_URL}/${APPROVAL}`;
const EXPOSURE_URL = `${ACTION_CONTROL_PREFIX}/${ORG}/agents/${AGENT}/policies/${POLICY}/exposure`;
const HUMAN_MUTATION_URL = `${ACTION_CONTROL_PREFIX}/${ORG}/action-mutations/${MUTATION}`;
const AGENT_ACTION_URL = `${ACTION_AGENT_ACTIONS}/${ACTION}`;
const AGENT_MUTATION_URL = `${ACTION_AGENT_MUTATION_PREFIX}/${MUTATION}`;

class FakeService {
  readonly calls: string[] = [];

  async listActions(): Promise<unknown> {
    this.calls.push("listActions");
    return { organizationId: ORG, items: [actionMetadata()], nextCursor: ACTION };
  }
  async listApprovals(): Promise<unknown> {
    this.calls.push("listApprovals");
    return {
      organizationId: ORG,
      items: [approvalMetadata()],
      nextCursor: APPROVAL,
    };
  }
  async getAction(): Promise<unknown> {
    this.calls.push("getAction");
    return { organizationId: ORG, actionId: ACTION, item: actionMetadata() };
  }
  async getApproval(): Promise<unknown> {
    this.calls.push("getApproval");
    return {
      organizationId: ORG,
      approvalId: APPROVAL,
      item: approvalMetadata(),
    };
  }
  async getExposure(): Promise<unknown> {
    this.calls.push("getExposure");
    return {
      organizationId: ORG,
      subjectAgentId: AGENT,
      policyId: POLICY,
      item: exposureView(),
    };
  }
  async getHumanMutationStatus(): Promise<unknown> {
    this.calls.push("getHumanMutationStatus");
    return { status: "not_found" };
  }
  async approve(): Promise<unknown> {
    this.calls.push("approve");
    return {
      replayed: false,
      metadata: actionMetadata(),
      receipt: actionReceipt("control.commerce_action.approve"),
    };
  }
  async reject(): Promise<unknown> {
    this.calls.push("reject");
    return {
      replayed: false,
      metadata: actionMetadata({ status: "rejected" }),
      receipt: actionReceipt("control.commerce_action.reject"),
    };
  }
  async cancel(): Promise<unknown> {
    this.calls.push("cancel");
    return {
      replayed: false,
      metadata: actionMetadata({ status: "cancelled" }),
      receipt: actionReceipt("control.commerce_action.cancel"),
    };
  }
  async authorize(): Promise<unknown> {
    this.calls.push("authorize");
    return {
      replayed: false,
      metadata: actionMetadata(),
      receipt: actionReceipt("control.commerce_action.authorize"),
    };
  }
  async getAgentAction(): Promise<unknown> {
    this.calls.push("getAgentAction");
    return { organizationId: ORG, actionId: ACTION, item: actionMetadata() };
  }
  async getAgentMutationStatus(): Promise<unknown> {
    this.calls.push("getAgentMutationStatus");
    return { status: "not_found" };
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
  registerCommerceActionRoutes(app, {
    appOrigin: ORIGIN,
    cookieNames: { session: "openarc_session", binding: "openarc_binding" },
    service: service as unknown as CommerceActionService,
    buildSha: BUILD_SHA,
    enabled: options.enabled ?? true,
  });
  if (options.spaFallback === true) {
    // A hostile catch-all registered AFTER the API family. It must never be
    // able to answer one of the twelve API targets with an HTML 200.
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

function errorCode(response: { json: () => unknown }): string {
  const body = response.json() as { error?: { code?: string } };
  return body.error?.code ?? "";
}

/** Every browser target, with its frozen method and a valid browser request. */
const BROWSER_TARGETS: readonly {
  id: string;
  method: "GET" | "POST";
  url: string;
  payload?: Record<string, unknown>;
}[] = [
  { id: "action_list", method: "GET", url: ACTIONS_URL },
  { id: "action_detail", method: "GET", url: ACTION_URL },
  { id: "approval_list", method: "GET", url: APPROVALS_URL },
  { id: "approval_detail", method: "GET", url: APPROVAL_URL },
  { id: "action_exposure", method: "GET", url: EXPOSURE_URL },
  { id: "action_mutation_status", method: "GET", url: HUMAN_MUTATION_URL },
  {
    id: "action_approve",
    method: "POST",
    url: APPROVE_URL,
    payload: { mutationId: MUTATION },
  },
  {
    id: "action_reject",
    method: "POST",
    url: REJECT_URL,
    payload: { mutationId: MUTATION },
  },
  {
    id: "action_cancel",
    method: "POST",
    url: CANCEL_URL,
    payload: { mutationId: MUTATION },
  },
];

const AGENT_TARGETS: readonly {
  id: string;
  method: "GET" | "POST";
  url: string;
  payload?: Record<string, unknown>;
}[] = [
  {
    id: "action_authorize",
    method: "POST",
    url: ACTION_AGENT_ACTIONS,
    payload: { mutationId: MUTATION, actionId: ACTION, requirementId: ACTION },
  },
  { id: "agent_action_detail", method: "GET", url: AGENT_ACTION_URL },
  {
    id: "agent_action_mutation_status",
    method: "GET",
    url: AGENT_MUTATION_URL,
  },
];

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

describe("commerce-action route registry", () => {
  it("registers exactly the twelve frozen descriptors and no thirteenth", () => {
    const templates = actionRouteTemplates();
    expect(templates).toHaveLength(12);
    expect(ACTION_ROUTES).toHaveLength(12);
    expect(templates.map((route) => route.id)).toEqual(
      ACTION_ROUTES.map((route) => route.id),
    );
    expect(new Set(templates.map((route) => route.path)).size).toBe(12);
    for (const [index, route] of templates.entries()) {
      const frozen = ACTION_ROUTES[index];
      expect(route.method).toBe(frozen?.method);
      expect(route.audience).toBe(frozen?.audience);
      // The registered template is the frozen path with the frozen parameters.
      expect(route.path).toBe(frozen?.path);
    }
    expect(
      templates.filter((route) => route.audience === "browser"),
    ).toHaveLength(9);
    expect(
      templates.filter((route) => route.audience === "agent"),
    ).toHaveLength(3);
  });

  it("serves all nine browser management targets", async () => {
    const { app, service } = build();
    for (const target of BROWSER_TARGETS) {
      const response = await app.inject({
        method: target.method,
        url: target.url,
        headers: target.method === "GET" ? readHeaders() : writeHeaders(),
        ...(target.payload !== undefined ? { payload: target.payload } : {}),
      });
      expect([target.id, response.statusCode]).toEqual([target.id, 200]);
      expect(response.headers["content-type"]).toContain("application/json");
    }
    expect(service.calls).toHaveLength(9);
  });

  it("serves all three agent authorization targets", async () => {
    const { app, service } = build();
    for (const target of AGENT_TARGETS) {
      const response = await app.inject({
        method: target.method,
        url: target.url,
        headers:
          target.method === "GET" ? agentReadHeaders() : agentWriteHeaders(),
        ...(target.payload !== undefined ? { payload: target.payload } : {}),
      });
      expect([target.id, response.statusCode]).toEqual([target.id, 200]);
    }
    expect(service.calls).toEqual([
      "authorize",
      "getAgentAction",
      "getAgentMutationStatus",
    ]);
  });

  it("rejects an unregistered thirteenth target under the same roots", async () => {
    const { app, service } = build();
    for (const url of [
      `${ACTION_CONTROL_PREFIX}/${ORG}/actions/${ACTION}/settle`,
      `${ACTION_CONTROL_PREFIX}/${ORG}/actions/${ACTION}/refund`,
      `${ACTION_CONTROL_PREFIX}/${ORG}/grants`,
      `${ACTION_AGENT_ACTIONS}/${ACTION}/pay`,
      "/v2/agent/commerce-action-grants",
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
    for (const target of [...BROWSER_TARGETS, ...AGENT_TARGETS]) {
      const wrong = target.method === "GET" ? "POST" : "GET";
      const agent = AGENT_TARGETS.some((entry) => entry.id === target.id);
      const response = await app.inject({
        method: wrong,
        url: target.url,
        headers:
          wrong === "GET"
            ? agent
              ? agentReadHeaders()
              : readHeaders()
            : agent
              ? agentWriteHeaders()
              : writeHeaders(),
        ...(wrong === "POST" ? { payload: {} } : {}),
      });
      expect([target.id, response.statusCode]).toEqual([target.id, 405]);
    }
    expect(service.calls).toEqual([]);
  });
});

describe("browser and agent families stay strictly separate", () => {
  it("never lets a commerce-session bearer authorize a browser route", async () => {
    const { app, service } = build();
    for (const target of BROWSER_TARGETS) {
      const headers =
        target.method === "GET"
          ? readHeaders({ authorization: `Bearer ${SESSION_TOKEN}` })
          : writeHeaders({ authorization: `Bearer ${SESSION_TOKEN}` });
      const response = await app.inject({
        method: target.method,
        url: target.url,
        headers,
        ...(target.payload !== undefined ? { payload: target.payload } : {}),
      });
      expect([target.id, response.statusCode]).toEqual([target.id, 400]);
      expect(errorCode(response)).toBe("INVALID_REQUEST");
    }
    // A bearer alone, with no cookie at all, is equally inert.
    const bare = await app.inject({
      method: "GET",
      url: ACTIONS_URL,
      headers: { ...CLIENT, authorization: `Bearer ${SESSION_TOKEN}` },
    });
    expect(bare.statusCode).toBe(400);
    expect(service.calls).toEqual([]);
  });

  it("never lets a browser cookie or CSRF authorize an agent route", async () => {
    const { app, service } = build();
    for (const target of AGENT_TARGETS) {
      const cookied = await app.inject({
        method: target.method,
        url: target.url,
        headers:
          target.method === "GET"
            ? agentReadHeaders({ cookie: COOKIE })
            : agentWriteHeaders({ cookie: COOKIE }),
        ...(target.payload !== undefined ? { payload: target.payload } : {}),
      });
      expect([target.id, cookied.statusCode]).toEqual([target.id, 400]);
      const csrfed = await app.inject({
        method: target.method,
        url: target.url,
        headers:
          target.method === "GET"
            ? agentReadHeaders({ "x-openarc-csrf": CSRF })
            : agentWriteHeaders({ "x-openarc-csrf": CSRF }),
        ...(target.payload !== undefined ? { payload: target.payload } : {}),
      });
      expect([target.id, csrfed.statusCode]).toEqual([target.id, 400]);
      const origined = await app.inject({
        method: target.method,
        url: target.url,
        headers:
          target.method === "GET"
            ? agentReadHeaders({ origin: ORIGIN })
            : agentWriteHeaders({ origin: ORIGIN }),
        ...(target.payload !== undefined ? { payload: target.payload } : {}),
      });
      expect([target.id, origined.statusCode]).toEqual([target.id, 400]);
    }
    // A cookie-only agent request is rejected as malformed for this family
    // BEFORE any bearer is considered: the cookie never becomes authority.
    const cookieOnly = await app.inject({
      method: "GET",
      url: AGENT_ACTION_URL,
      headers: { cookie: COOKIE },
    });
    expect(cookieOnly.statusCode).toBe(400);
    // With no credential at all the agent family is unauthenticated.
    const noCredential = await app.inject({
      method: "GET",
      url: AGENT_ACTION_URL,
      headers: {},
    });
    expect(noCredential.statusCode).toBe(401);
    expect(errorCode(noCredential)).toBe("UNAUTHENTICATED");
    expect(service.calls).toEqual([]);
  });

  it("rejects a machine agent-session token on the agent action family", async () => {
    const { app, service } = build();
    const response = await app.inject({
      method: "GET",
      url: AGENT_ACTION_URL,
      headers: { authorization: `Bearer ${AGENT_TOKEN}` },
    });
    expect(response.statusCode).toBe(401);
    expect(errorCode(response)).toBe("UNAUTHENTICATED");
    expect(service.calls).toEqual([]);
  });
});

describe("browser transport strictness", () => {
  it("rejects a foreign Origin and a missing browser marker", async () => {
    const { app, service } = build();
    const foreign = await app.inject({
      method: "GET",
      url: ACTIONS_URL,
      headers: {
        origin: "https://evil.example",
        "x-openarc-client": "browser-v1",
        cookie: COOKIE,
      },
    });
    expect(foreign.statusCode).toBe(403);
    expect(errorCode(foreign)).toBe("INVALID_ORIGIN");
    const noMarker = await app.inject({
      method: "GET",
      url: ACTIONS_URL,
      headers: { origin: ORIGIN, cookie: COOKIE },
    });
    expect(noMarker.statusCode).toBe(403);
    const crossSite = await app.inject({
      method: "POST",
      url: APPROVE_URL,
      headers: writeHeaders({ "sec-fetch-site": "cross-site" }),
      payload: { mutationId: MUTATION },
    });
    expect(crossSite.statusCode).toBe(403);
    expect(service.calls).toEqual([]);
  });

  it("rejects every write that is missing CSRF or the idempotency key", async () => {
    const { app, service } = build();
    for (const url of [APPROVE_URL, REJECT_URL, CANCEL_URL]) {
      const noCsrf = await app.inject({
        method: "POST",
        url,
        headers: {
          ...CLIENT,
          "content-type": "application/json",
          cookie: COOKIE,
          "idempotency-key": IDEMPOTENCY,
        },
        payload: { mutationId: MUTATION },
      });
      expect([url, noCsrf.statusCode]).toEqual([url, 400]);
      const noIdempotency = await app.inject({
        method: "POST",
        url,
        headers: {
          ...CLIENT,
          "content-type": "application/json",
          cookie: COOKIE,
          "x-openarc-csrf": CSRF,
        },
        payload: { mutationId: MUTATION },
      });
      expect([url, noIdempotency.statusCode]).toEqual([url, 400]);
      const badMedia = await app.inject({
        method: "POST",
        url,
        headers: writeHeaders({ "content-type": "text/plain" }),
        payload: "x",
      });
      expect([url, badMedia.statusCode]).toEqual([url, 415]);
    }
    expect(service.calls).toEqual([]);
  });

  it("rejects an oversized body on every write in both families", async () => {
    const { app, service } = build();
    const oversized = "B".repeat(API_MAX_REQUEST_BYTES + 512);
    for (const url of [APPROVE_URL, REJECT_URL, CANCEL_URL]) {
      const response = await app.inject({
        method: "POST",
        url,
        headers: writeHeaders(),
        payload: { mutationId: MUTATION, padding: oversized },
      });
      expect([url, response.statusCode]).toEqual([url, 413]);
      expect(errorCode(response)).toBe("REQUEST_TOO_LARGE");
    }
    const agent = await app.inject({
      method: "POST",
      url: ACTION_AGENT_ACTIONS,
      headers: agentWriteHeaders(),
      payload: { mutationId: MUTATION, padding: oversized },
    });
    expect(agent.statusCode).toBe(413);
    expect(service.calls).toEqual([]);
  });

  it("rejects a declared content-length above the exact body ceiling", async () => {
    const { app, service } = build();
    const response = await app.inject({
      method: "POST",
      url: APPROVE_URL,
      headers: writeHeaders({
        "content-length": String(API_MAX_REQUEST_BYTES + 1),
      }),
      payload: { mutationId: MUTATION },
    });
    expect(response.statusCode).toBe(413);
    expect(service.calls).toEqual([]);
  });
});

describe("path and query canonicality", () => {
  it("rejects a malformed query, cursor or limit on both list routes", async () => {
    const { app, service } = build();
    const cases: readonly string[] = [
      `${ACTIONS_URL}?limit=`,
      `${ACTIONS_URL}?limit=0`,
      `${ACTIONS_URL}?limit=51`,
      `${ACTIONS_URL}?limit=07`,
      `${ACTIONS_URL}?limit=5&limit=6`,
      `${ACTIONS_URL}?limit=5%0A`,
      `${ACTIONS_URL}?unknown=1`,
      `${ACTIONS_URL}?afterActionId=nope`,
      `${ACTIONS_URL}?afterApprovalId=${APPROVAL}`,
      `${APPROVALS_URL}?limit=51`,
      `${APPROVALS_URL}?afterApprovalId=nope`,
      `${APPROVALS_URL}?afterActionId=${ACTION}`,
    ];
    for (const url of cases) {
      const response = await app.inject({
        method: "GET",
        url,
        headers: readHeaders(),
      });
      expect([url, response.statusCode]).toEqual([url, 400]);
      expect(errorCode(response)).toBe("INVALID_REQUEST");
    }
    expect(service.calls).toEqual([]);
  });

  it("rejects a bare `?` target on the raw wire", async () => {
    const { app, service } = build();
    const port = await listen(app);
    const response = await rawHttp(port, "GET", `${ACTIONS_URL}?`, [
      `origin: ${ORIGIN}`,
      "x-openarc-client: browser-v1",
      `cookie: ${COOKIE}`,
    ]);
    expect(response.status).toBe(400);
    expect(response.text).toContain("INVALID_REQUEST");
    expect(service.calls).toEqual([]);
  });

  it("accepts only the exact canonical cursor and limit pair", async () => {
    const { app, service } = build();
    const actions = await app.inject({
      method: "GET",
      url: `${ACTIONS_URL}?afterActionId=${ACTION}&limit=50`,
      headers: readHeaders(),
    });
    expect(actions.statusCode).toBe(200);
    const approvals = await app.inject({
      method: "GET",
      url: `${APPROVALS_URL}?afterApprovalId=${APPROVAL}&limit=1`,
      headers: readHeaders(),
    });
    expect(approvals.statusCode).toBe(200);
    expect(service.calls).toEqual(["listActions", "listApprovals"]);
  });

  it("rejects a query on every non-list target", async () => {
    const { app, service } = build();
    for (const url of [
      ACTION_URL,
      APPROVAL_URL,
      EXPOSURE_URL,
      HUMAN_MUTATION_URL,
      AGENT_ACTION_URL,
      AGENT_MUTATION_URL,
    ]) {
      const response = await app.inject({
        method: "GET",
        url: `${url}?limit=1`,
        headers: url.startsWith("/v2/agent/")
          ? agentReadHeaders()
          : readHeaders(),
      });
      expect([url, response.statusCode]).toEqual([url, 400]);
    }
    expect(service.calls).toEqual([]);
  });

  it("rejects non-canonical and lookalike path parameters", async () => {
    const { app, service } = build();
    const cases: readonly string[] = [
      `${ACTION_CONTROL_PREFIX}/${ORG}/actions/openarc:action:not-a-uuid`,
      `${ACTION_CONTROL_PREFIX}/${ORG}/actions/${ACTION.toUpperCase()}`,
      `${ACTION_CONTROL_PREFIX}/${ORG}/actions/${encodeURIComponent(ACTION)}%00`,
      `${ACTION_CONTROL_PREFIX}/${ORG}/approvals/${ACTION}`,
      `${ACTION_CONTROL_PREFIX}/${ORG}/agents/${AGENT}/policies/${POLICY}/exposures`,
      `${ACTION_CONTROL_PREFIX}/${ORG}/agents/${AGENT}/exposure`,
      `${ACTION_CONTROL_PREFIX}/${ORG}/action-mutations/${ACTION}`,
      `${ACTION_AGENT_MUTATION_PREFIX}/${ACTION}`,
    ];
    for (const url of cases) {
      const response = await app.inject({
        method: "GET",
        url,
        headers: url.startsWith("/v2/agent/")
          ? agentReadHeaders()
          : readHeaders(),
      });
      expect([url, response.statusCode >= 400]).toEqual([url, true]);
      expect([url, response.statusCode]).not.toEqual([url, 200]);
    }
    expect(service.calls).toEqual([]);
  });
});

describe("default-off gate", () => {
  it("answers every one of the twelve targets with the disabled error and zero service calls", async () => {
    const { app, service } = build({ enabled: false });
    for (const target of [...BROWSER_TARGETS, ...AGENT_TARGETS]) {
      const agent = AGENT_TARGETS.some((entry) => entry.id === target.id);
      const response = await app.inject({
        method: target.method,
        url: target.url,
        headers:
          target.method === "GET"
            ? agent
              ? agentReadHeaders()
              : readHeaders()
            : agent
              ? agentWriteHeaders()
              : writeHeaders(),
        ...(target.payload !== undefined ? { payload: target.payload } : {}),
      });
      expect([target.id, response.statusCode]).toEqual([target.id, 503]);
      expect([target.id, errorCode(response)]).toEqual([
        target.id,
        "FEATURE_DISABLED",
      ]);
      const body = response.json() as { ok?: unknown; error?: unknown };
      expect(body.ok).toBe(false);
    }
    expect(service.calls).toEqual([]);
  });

  it("keeps the disabled surface a real API error even behind an HTML fallback", async () => {
    const { app, service } = build({ enabled: false, spaFallback: true });
    for (const target of [...BROWSER_TARGETS, ...AGENT_TARGETS]) {
      const response = await app.inject({
        method: target.method,
        url: target.url,
        headers: readHeaders(),
        ...(target.payload !== undefined ? { payload: target.payload } : {}),
      });
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
      url: `${ACTION_CONTROL_PREFIX}/${ORG}/actions/${ACTION}/settle`,
      headers: readHeaders(),
    });
    expect(unclaimed.statusCode).toBe(200);
    for (const target of [...BROWSER_TARGETS, ...AGENT_TARGETS]) {
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

describe("errors never echo input or leak a secret", () => {
  it("returns only the fixed catalog envelope for a rejected request", async () => {
    const { app } = build();
    const marker = "canary-input-value";
    const response = await app.inject({
      method: "GET",
      url: `${ACTIONS_URL}?afterActionId=${marker}`,
      headers: readHeaders({ origin: `https://${marker}.example` }),
    });
    expect(response.statusCode).toBeGreaterThanOrEqual(400);
    expect(response.body).not.toContain(marker);
    expect(response.body).not.toContain(COOKIE);
    expect(response.body).not.toContain(CSRF);
    expect(response.body).not.toContain(SESSION_TOKEN);
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

  it("never echoes the presented bearer, cookie or CSRF in any success body", async () => {
    const { app } = build();
    const browser = await app.inject({
      method: "POST",
      url: APPROVE_URL,
      headers: writeHeaders(),
      payload: { mutationId: MUTATION },
    });
    const agent = await app.inject({
      method: "POST",
      url: ACTION_AGENT_ACTIONS,
      headers: agentWriteHeaders(),
      payload: {
        mutationId: MUTATION,
        actionId: ACTION,
        requirementId: ACTION,
      },
    });
    for (const response of [browser, agent]) {
      expect(response.statusCode).toBe(200);
      expect(response.body).not.toContain(SESSION_TOKEN);
      expect(response.body).not.toContain(IDEMPOTENCY);
      expect(response.body).not.toContain(CSRF);
      expect(response.body).not.toContain("openarc_session");
      // No token, grant, payment or settlement leaf is representable.
      expect(response.body).not.toContain("grant");
      expect(response.body).not.toContain("payment");
      expect(response.body).not.toContain("settlement");
    }
  });

  it("keeps exact integer money strings on the wire", async () => {
    const { app } = build();
    const response = await app.inject({
      method: "GET",
      url: EXPOSURE_URL,
      headers: readHeaders(),
    });
    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      data?: { item?: Record<string, unknown> };
    };
    expect(body.data?.item?.["committedAtomic"]).toBe(
      "123456789012345678901234567890",
    );
    expect(body.data?.item?.["totalExposureAtomic"]).toBe(
      "123456789012345678901234567891",
    );
    // The raw text must carry the digits verbatim: no float round-trip.
    expect(response.body).toContain('"123456789012345678901234567891"');
    expect(response.body).not.toContain("1.2345678901234568e+29");
  });
});
