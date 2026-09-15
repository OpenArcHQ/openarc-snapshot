import { connect } from "node:net";

import { afterEach, describe, expect, it } from "vitest";
import Fastify, { type FastifyInstance } from "fastify";

import {
  API_MAX_REQUEST_BYTES,
  COMMERCE_API_SCHEMA_VERSION,
  type CommercePolicyHistoryPage,
  type CommercePolicyMutationResult,
  type CommercePolicyMutationStatus,
  type CommercePolicyRevisionDetail,
  type CommercePolicyRootDetail,
  type CommercePolicyRootPage,
} from "@openarc/shared";

import { AUTH_ERRORS, AuthApiError, authErrorEnvelope } from "../src/auth/errors.js";
import type { PolicyService } from "../src/control/service.js";
import {
  CONTROL_ROUTE_PREFIX,
  CONTROL_ROUTE_REGISTRY,
  isForbiddenRequestTarget,
  registerPolicyRoutes,
} from "../src/control/routes.js";

/**
 * HTTP-inject and raw-TCP coverage for the protected control policy family.
 *
 * The PolicyService is HONESTLY MOCKED here (labelled): these tests prove
 * transport strictness, path/query canonicality, envelope shape, credential
 * denial, duplicate-header detection, fail-closed error mapping and log
 * hygiene. The routes are registered in an ISOLATED Fastify fixture; this does
 * not wire the production app and does not establish runtime acceptance. Real
 * roles, sessions, locks and SQL enforcement are a separately owned REAL-PG
 * packet.
 */

const ORIGIN = "http://localhost:5183";
const BUILD_SHA = "0123456789abcdef0123456789abcdef01234567";
const CLIENT = { origin: ORIGIN, "x-openarc-client": "browser-v1" };
const COOKIE = "openarc_session=abc";
const CSRF = "csrf-token-value";
const IDEMPOTENCY = "A".repeat(43);

const MUTATION = "12345678-1234-4234-8123-123456789abc";
const MUTATION2 = "22345678-1234-4234-8123-123456789abc";
const ORG = `openarc:org:${MUTATION}`;
const AGENT = `openarc:agent:${MUTATION}`;
const POLICY = `openarc:policy:${MUTATION}`;
const POLICY2 = `openarc:policy:${MUTATION2}`;
const PROVIDER = `openarc:provider:${MUTATION}`;
const ISO = "2026-01-01T00:00:00.000Z";
const DIGEST = `sha256:${"1".repeat(64)}`;

function content(): Record<string, unknown> {
  return {
    organizationId: ORG,
    subjectAgentId: AGENT,
    networkId: "eip155:5042002",
    asset: "USDC",
    representation: "erc20",
    decimals: 6,
    perActionLimit: "1000000",
    rollingLimit: null,
    rollingWindowSeconds: null,
    feeLimit: "10000",
    allowedProviderIds: [PROVIDER],
    allowedListingIds: [],
    approval: { mode: "none", threshold: null, separateApprover: false },
    expiresAt: null,
  };
}

function rootItem(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: "openarc.control.policy-root.v1",
    policyId: POLICY,
    organizationId: ORG,
    subjectAgentId: AGENT,
    currentRevision: "1",
    status: "active",
    createdAt: ISO,
    updatedAt: ISO,
    ...overrides,
  };
}

function summaryItem(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    policyId: POLICY,
    organizationId: ORG,
    subjectAgentId: AGENT,
    revision: "1",
    digest: DIGEST,
    createdAt: ISO,
    expiresAt: null,
    ...overrides,
  };
}

function revisionItem(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: "openarc.control.policy.v1",
    policyId: POLICY,
    revision: "1",
    ...content(),
    createdAt: ISO,
    digest: DIGEST,
    ...overrides,
  };
}

function mutationResult(
  operation = "control.policy.create",
  resourceType = "budget_policy",
  resourceId = POLICY,
): CommercePolicyMutationResult {
  return {
    organizationId: ORG,
    replayed: false,
    receipt: {
      mutationId: MUTATION,
      operation: operation as CommercePolicyMutationResult["receipt"]["operation"],
      resourceType: resourceType as CommercePolicyMutationResult["receipt"]["resourceType"],
      resourceId,
      committedAt: ISO,
    },
  } as CommercePolicyMutationResult;
}

class FakePolicyService {
  calls: Array<{ name: string; request?: unknown; organizationId?: unknown }> = [];
  error: AuthApiError | undefined;
  rootPage: CommercePolicyRootPage = {
    organizationId: ORG,
    items: [rootItem() as never],
    nextCursor: null,
  };
  rootDetail: CommercePolicyRootDetail = {
    organizationId: ORG,
    policyId: POLICY,
    item: rootItem() as never,
  };
  historyPage: CommercePolicyHistoryPage = {
    organizationId: ORG,
    policyId: POLICY,
    items: [summaryItem() as never],
    nextCursor: null,
  };
  revisionDetail: CommercePolicyRevisionDetail = {
    organizationId: ORG,
    policyId: POLICY,
    revision: "1",
    item: revisionItem() as never,
  };
  mutationResult: CommercePolicyMutationResult = mutationResult();
  statusResult: CommercePolicyMutationStatus = {
    organizationId: ORG,
    mutationId: MUTATION,
    status: "not_found",
  };

  #record(name: string, request?: unknown, organizationId?: unknown): void {
    this.calls.push({ name, request, organizationId });
    if (this.error) throw this.error;
  }

  async listPolicyRoots(_ctx: unknown, request: unknown): Promise<CommercePolicyRootPage> {
    this.#record("listPolicyRoots", request);
    return this.rootPage;
  }
  async createPolicy(
    _ctx: unknown,
    organizationId: unknown,
    request: unknown,
  ): Promise<CommercePolicyMutationResult> {
    this.#record("createPolicy", request, organizationId);
    return this.mutationResult;
  }
  async getPolicyRoot(_ctx: unknown, request: unknown): Promise<CommercePolicyRootDetail> {
    this.#record("getPolicyRoot", request);
    return this.rootDetail;
  }
  async listPolicyRevisions(
    _ctx: unknown,
    request: unknown,
  ): Promise<CommercePolicyHistoryPage> {
    this.#record("listPolicyRevisions", request);
    return this.historyPage;
  }
  async appendPolicyRevision(
    _ctx: unknown,
    organizationId: unknown,
    _policyId: unknown,
    request: unknown,
  ): Promise<CommercePolicyMutationResult> {
    this.#record("appendPolicyRevision", request, organizationId);
    return mutationResult(
      "control.policy.revision.create",
      "budget_policy_revision",
      `${POLICY}@2`,
    );
  }
  async getPolicyRevision(
    _ctx: unknown,
    request: unknown,
  ): Promise<CommercePolicyRevisionDetail> {
    this.#record("getPolicyRevision", request);
    return this.revisionDetail;
  }
  async pausePolicy(
    _ctx: unknown,
    organizationId: unknown,
    _policyId: unknown,
    request: unknown,
  ): Promise<CommercePolicyMutationResult> {
    this.#record("pausePolicy", request, organizationId);
    return mutationResult("control.policy.pause", "budget_policy", POLICY);
  }
  async resumePolicy(
    _ctx: unknown,
    organizationId: unknown,
    _policyId: unknown,
    request: unknown,
  ): Promise<CommercePolicyMutationResult> {
    this.#record("resumePolicy", request, organizationId);
    return mutationResult("control.policy.resume", "budget_policy", POLICY);
  }
  async revokePolicy(
    _ctx: unknown,
    organizationId: unknown,
    _policyId: unknown,
    request: unknown,
  ): Promise<CommercePolicyMutationResult> {
    this.#record("revokePolicy", request, organizationId);
    return mutationResult("control.policy.revoke", "budget_policy", POLICY);
  }
  async getPolicyMutationStatus(
    _ctx: unknown,
    request: unknown,
  ): Promise<CommercePolicyMutationStatus> {
    this.#record("getPolicyMutationStatus", request);
    return this.statusResult;
  }
}

const apps: FastifyInstance[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map(async (app) => app.close()));
});

function build(options: {
  readonly enabled?: boolean;
  readonly maxResponseBytes?: number;
} = {}): { app: FastifyInstance; service: FakePolicyService } {
  const service = new FakePolicyService();
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
  app.setNotFoundHandler((request, reply) => {
    const mapped = new AuthApiError("FEATURE_DISABLED", 404, "NOT_FOUND");
    return reply
      .code(mapped.status)
      .send(authErrorEnvelope(mapped, request.id, BUILD_SHA));
  });
  registerPolicyRoutes(app, {
    appOrigin: ORIGIN,
    cookieNames: { session: "openarc_session", binding: "openarc_binding" },
    service: service as unknown as PolicyService,
    buildSha: BUILD_SHA,
    enabled: options.enabled ?? true,
    ...(options.maxResponseBytes !== undefined
      ? { maxResponseBytes: options.maxResponseBytes }
      : {}),
  });
  apps.push(app);
  return { app, service };
}

function readHeaders(extra: Record<string, string | string[]> = {}) {
  return { ...CLIENT, cookie: COOKIE, ...extra };
}

function writeHeaders(extra: Record<string, string | string[]> = {}) {
  return {
    ...CLIENT,
    "content-type": "application/json",
    cookie: COOKIE,
    "x-openarc-csrf": CSRF,
    "idempotency-key": IDEMPOTENCY,
    ...extra,
  };
}

const PREFIX = CONTROL_ROUTE_PREFIX;
const ROOTS = `${PREFIX}/${ORG}/policies`;
const ROOT = `${ROOTS}/${POLICY}`;
const REVISIONS = `${ROOT}/revisions`;
const REVISION = `${REVISIONS}/1`;
const PAUSE = `${ROOT}/pause`;
const RESUME = `${ROOT}/resume`;
const REVOKE = `${ROOT}/revoke`;
const MUTATION_URL = `${PREFIX}/${ORG}/policy-mutations/${MUTATION}`;

const CREATE_BODY = { mutationId: MUTATION, content: content() };
const APPEND_BODY = {
  mutationId: MUTATION,
  expectedRevision: "1",
  expectedUpdatedAt: ISO,
  content: content(),
};
const TRANSITION_BODY = {
  mutationId: MUTATION,
  expectedRevision: "1",
  expectedUpdatedAt: ISO,
};

function v2ErrorCode(response: { json: () => unknown }): string {
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
    `Content-Length: ${payload.byteLength}`,
    "Connection: close",
    "",
    "",
  ];
  const wire = Buffer.concat([Buffer.from(lines.join("\r\n"), "utf8"), payload]);
  return new Promise((resolve, reject) => {
    const socket = connect({ host: "127.0.0.1", port });
    const chunks: Buffer[] = [];
    socket.on("connect", () => socket.write(wire));
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.on("error", reject);
    socket.on("end", () => {
      const text = Buffer.concat(chunks).toString("utf8");
      resolve({ status: Number.parseInt(text.slice(9, 12), 10), text });
    });
  });
}

async function listeningPort(app: FastifyInstance): Promise<number> {
  await app.listen({ port: 0, host: "127.0.0.1" });
  const address = app.server.address();
  if (address === null || typeof address === "string") {
    throw new Error("expected a TCP address");
  }
  return address.port;
}

describe("control success envelopes", () => {
  it("serves all ten routes with a strict v2 envelope and no Set-Cookie", async () => {
    const { app, service } = build();
    const cases: ReadonlyArray<{
      readonly method: "GET" | "POST";
      readonly url: string;
      readonly call: string;
      readonly body?: unknown;
      readonly headers?: Record<string, string>;
    }> = [
      { method: "GET", url: ROOTS, call: "listPolicyRoots" },
      { method: "POST", url: ROOTS, call: "createPolicy", body: CREATE_BODY },
      { method: "GET", url: ROOT, call: "getPolicyRoot" },
      { method: "GET", url: REVISIONS, call: "listPolicyRevisions" },
      { method: "POST", url: REVISIONS, call: "appendPolicyRevision", body: APPEND_BODY },
      { method: "GET", url: REVISION, call: "getPolicyRevision" },
      { method: "POST", url: PAUSE, call: "pausePolicy", body: TRANSITION_BODY },
      { method: "POST", url: RESUME, call: "resumePolicy", body: TRANSITION_BODY },
      { method: "POST", url: REVOKE, call: "revokePolicy", body: TRANSITION_BODY },
      { method: "GET", url: MUTATION_URL, call: "getPolicyMutationStatus" },
    ];
    for (const entry of cases) {
      const response = await app.inject({
        method: entry.method,
        url: entry.url,
        headers: entry.method === "GET" ? readHeaders() : writeHeaders(),
        ...(entry.body !== undefined ? { payload: entry.body } : {}),
      });
      expect(response.statusCode, `${entry.method} ${entry.url}`).toBe(200);
      const parsed = response.json() as { meta: { schemaVersion: string } };
      expect(parsed.meta.schemaVersion).toBe(COMMERCE_API_SCHEMA_VERSION);
      expect(response.headers["set-cookie"]).toBeUndefined();
      expect(response.headers["access-control-allow-origin"]).toBeUndefined();
      expect(service.calls.at(-1)?.name).toBe(entry.call);
    }
  });

  it("exposes exactly the ten frozen registry paths", () => {
    expect(Object.keys(CONTROL_ROUTE_REGISTRY)).toHaveLength(10);
    expect(new Set(Object.values(CONTROL_ROUTE_REGISTRY))).toEqual(
      new Set([
        `${PREFIX}/:organizationId/policies`,
        `${PREFIX}/:organizationId/policies/:policyId`,
        `${PREFIX}/:organizationId/policies/:policyId/revisions`,
        `${PREFIX}/:organizationId/policies/:policyId/revisions/:revision`,
        `${PREFIX}/:organizationId/policies/:policyId/pause`,
        `${PREFIX}/:organizationId/policies/:policyId/resume`,
        `${PREFIX}/:organizationId/policies/:policyId/revoke`,
        `${PREFIX}/:organizationId/policy-mutations/:mutationId`,
      ]),
    );
  });

  it("passes only the parsed canonical list query to the service", async () => {
    const { app, service } = build();
    const roots = await app.inject({
      method: "GET",
      url: `${ROOTS}?limit=10&afterPolicyId=${POLICY2}`,
      headers: readHeaders(),
    });
    expect(roots.statusCode).toBe(200);
    expect(service.calls[0]?.request).toMatchObject({
      organizationId: ORG,
      limit: "10",
      afterPolicyId: POLICY2,
    });
    const history = await app.inject({
      method: "GET",
      url: `${REVISIONS}?limit=1&afterRevision=1`,
      headers: readHeaders(),
    });
    expect(history.statusCode).toBe(200);
    expect(service.calls[1]?.request).toMatchObject({
      organizationId: ORG,
      policyId: POLICY,
      limit: "1",
      afterRevision: "1",
    });
  });
});

describe("control strict query parsing", () => {
  const badQueries = [
    "?limit=1&limit=2",
    "?limit=1&unknown=2",
    "?limit=",
    "?limit=%zz",
    "?limit=0",
    "?limit=51",
    "?limit=01",
    "?limit=+1",
    "?limit=1e1",
    "?limit=1.0",
    "?afterPolicyId=openarc%3Apolicy%3Abad",
  ];

  it("rejects repeated, unknown, empty, noncanonical and bare queries on the list", async () => {
    const { app, service } = build();
    for (const query of badQueries) {
      const response = await app.inject({
        method: "GET",
        url: `${ROOTS}${query}`,
        headers: readHeaders(),
      });
      expect(response.statusCode, query).toBe(400);
    }
    const bare = await rawHttp(
      await listeningPort(app),
      "GET",
      `${ROOTS}?`,
      [`Origin: ${ORIGIN}`, "X-OpenArc-Client: browser-v1", `Cookie: ${COOKIE}`],
    );
    expect(bare.status).toBe(400);
    expect(service.calls).toEqual([]);
  });

  it("permits only afterRevision/limit on history and no query on detail/status/transitions", async () => {
    const { app, service } = build();
    for (const query of ["?afterPolicyId=" + POLICY, "?limit=1&limit=2"]) {
      const response = await app.inject({
        method: "GET",
        url: `${REVISIONS}${query}`,
        headers: readHeaders(),
      });
      expect(response.statusCode, query).toBe(400);
    }
    for (const target of [ROOT, REVISION, MUTATION_URL]) {
      const response = await app.inject({
        method: "GET",
        url: `${target}?limit=1`,
        headers: readHeaders(),
      });
      expect(response.statusCode, target).toBe(400);
    }
    expect(service.calls).toEqual([]);
  });

  it("rejects a bare empty query request target directly", () => {
    expect(isForbiddenRequestTarget(`${ROOT}?`)).toBe(true);
    expect(isForbiddenRequestTarget(`${PAUSE}?`)).toBe(true);
    expect(isForbiddenRequestTarget(ROOTS)).toBe(false);
  });
});

describe("control strict path parsing", () => {
  it("rejects encoded separators, double encoding, controls and unknown keywords", async () => {
    const { app, service } = build();
    const targets = [
      `${PREFIX}/openarc%3Aorg%3A11111111-1111-4111-8111-111111111111%2Fpolicies`,
      `${PREFIX}/openarc%253Aorg%253A11111111-1111-4111-8111-111111111111/policies`,
      `${ROOTS}/%2e%2e`,
      `${ROOTS}/not-a-policy`,
      `${PREFIX}/${ORG}/policiesXYZ`,
      `${PREFIX}/${ORG}/machine`,
      `${ROOT}/revisions/1/extra`,
      `${ROOT}/revisions/01`,
      `${PREFIX}/${ORG}/policy-mutations/not-a-mutation`,
    ];
    for (const target of targets) {
      const response = await app.inject({
        method: "GET",
        url: target,
        headers: readHeaders(),
      });
      expect([400, 404], target).toContain(response.statusCode);
    }
    expect(service.calls).toEqual([]);
  });

  it("accepts typed lowercase UUID versions 1-8 and rejects version 9/0", async () => {
    const { app } = build();
    const versions = ["1", "2", "3", "4", "5", "6", "7", "8"];
    for (const version of versions) {
      const org = `openarc:org:12345678-1234-${version}234-8123-123456789abc`;
      const response = await app.inject({
        method: "GET",
        url: `${PREFIX}/${org}/policies`,
        headers: readHeaders(),
      });
      expect(response.statusCode, version).toBe(200);
    }
    for (const version of ["0", "9"]) {
      const org = `openarc:org:12345678-1234-${version}234-8123-123456789abc`;
      const response = await app.inject({
        method: "GET",
        url: `${PREFIX}/${org}/policies`,
        headers: readHeaders(),
      });
      expect(response.statusCode, version).toBe(400);
    }
  });

  it("accepts successful percent-encoded canonical typed ids across the ten routes", async () => {
    const { app, service } = build();
    const encOrg = encodeURIComponent(ORG);
    const encPolicy = encodeURIComponent(POLICY);
    const encMutation = encodeURIComponent(MUTATION);
    const cases: ReadonlyArray<{
      readonly method: "GET" | "POST";
      readonly url: string;
      readonly call: string;
      readonly body?: unknown;
    }> = [
      { method: "GET", url: `${PREFIX}/${encOrg}/policies`, call: "listPolicyRoots" },
      {
        method: "POST",
        url: `${PREFIX}/${encOrg}/policies`,
        call: "createPolicy",
        body: CREATE_BODY,
      },
      {
        method: "GET",
        url: `${PREFIX}/${encOrg}/policies/${encPolicy}`,
        call: "getPolicyRoot",
      },
      {
        method: "GET",
        url: `${PREFIX}/${encOrg}/policies/${encPolicy}/revisions`,
        call: "listPolicyRevisions",
      },
      {
        method: "POST",
        url: `${PREFIX}/${encOrg}/policies/${encPolicy}/revisions`,
        call: "appendPolicyRevision",
        body: APPEND_BODY,
      },
      {
        method: "GET",
        url: `${PREFIX}/${encOrg}/policies/${encPolicy}/revisions/%31`,
        call: "getPolicyRevision",
      },
      {
        method: "POST",
        url: `${PREFIX}/${encOrg}/policies/${encPolicy}/pause`,
        call: "pausePolicy",
        body: TRANSITION_BODY,
      },
      {
        method: "POST",
        url: `${PREFIX}/${encOrg}/policies/${encPolicy}/resume`,
        call: "resumePolicy",
        body: TRANSITION_BODY,
      },
      {
        method: "POST",
        url: `${PREFIX}/${encOrg}/policies/${encPolicy}/revoke`,
        call: "revokePolicy",
        body: TRANSITION_BODY,
      },
      {
        method: "GET",
        url: `${PREFIX}/${encOrg}/policy-mutations/${encMutation}`,
        call: "getPolicyMutationStatus",
      },
    ];
    for (const entry of cases) {
      const response = await app.inject({
        method: entry.method,
        url: entry.url,
        headers: entry.method === "GET" ? readHeaders() : writeHeaders(),
        ...(entry.body !== undefined ? { payload: entry.body } : {}),
      });
      expect(response.statusCode, `${entry.method} ${entry.url}`).toBe(200);
      expect(service.calls.at(-1)?.name).toBe(entry.call);
    }
  });

  it("keeps lookalike prefixes on the ordinary 404", async () => {
    const { app } = build();
    const response = await app.inject({
      method: "GET",
      url: `${PREFIX}XYZ/${ORG}/policies`,
      headers: readHeaders(),
    });
    expect(response.statusCode).toBe(404);
  });
});

describe("control transport enforcement", () => {
  it("rejects wrong methods including HEAD and OPTIONS with a fixed 405", async () => {
    const { app, service } = build();
    for (const method of ["PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"] as const) {
      const response = await app.inject({ method, url: ROOTS, headers: readHeaders() });
      expect(response.statusCode, method).toBe(405);
      expect(v2ErrorCode(response)).toBe("INVALID_REQUEST");
    }
    expect(service.calls).toEqual([]);
  });

  it("rejects wrong verbs on read-only detail/status and write-only lifecycle routes", async () => {
    const { app, service } = build();
    // Read-only routes: any write verb is a fixed 405.
    for (const target of [ROOT, REVISION, MUTATION_URL]) {
      for (const method of ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"] as const) {
        const response = await app.inject({
          method,
          url: target,
          headers: writeHeaders(),
          payload: TRANSITION_BODY,
        });
        expect(response.statusCode, `${method} ${target}`).toBe(405);
        expect(v2ErrorCode(response), `${method} ${target}`).toBe("INVALID_REQUEST");
      }
    }
    // Write-only lifecycle routes: a GET (and other non-POST verbs) is 405.
    for (const target of [PAUSE, RESUME, REVOKE]) {
      for (const method of ["GET", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"] as const) {
        const response = await app.inject({
          method,
          url: target,
          headers: readHeaders(),
        });
        expect(response.statusCode, `${method} ${target}`).toBe(405);
        expect(v2ErrorCode(response), `${method} ${target}`).toBe("INVALID_REQUEST");
      }
    }
    expect(service.calls).toEqual([]);
  });

  it("denies a foreign origin, credentials, unexpected client and bad media", async () => {
    const { app, service } = build();
    const cases: Array<Record<string, string | string[]>> = [
      writeHeaders({ origin: "https://evil.example" }),
      writeHeaders({ authorization: "Bearer x" }),
      writeHeaders({ "proxy-authorization": "Bearer x" }),
      writeHeaders({ "x-openarc-client": "machine-v1" }),
      writeHeaders({ "content-type": "text/plain" }),
      writeHeaders({ "idempotency-key": "short" }),
      writeHeaders({ "idempotency-key": [`${"A".repeat(42)}B`] }),
    ];
    for (const headers of cases) {
      const response = await app.inject({
        method: "POST",
        url: ROOTS,
        headers: headers as Record<string, string>,
        payload: CREATE_BODY,
      });
      expect([400, 403, 415], JSON.stringify(headers)).toContain(response.statusCode);
    }
    const originless = await app.inject({
      method: "POST",
      url: ROOTS,
      headers: {
        "x-openarc-client": "browser-v1",
        "sec-fetch-site": "same-origin",
        "content-type": "application/json",
        cookie: COOKIE,
        "x-openarc-csrf": CSRF,
        "idempotency-key": IDEMPOTENCY,
      },
      payload: CREATE_BODY,
    });
    expect(originless.statusCode).toBe(403);
    expect(service.calls).toEqual([]);
  });

  it("allows an originless same-origin read and denies foreign metadata", async () => {
    const { app } = build();
    const allowed = await app.inject({
      method: "GET",
      url: ROOTS,
      headers: {
        "x-openarc-client": "browser-v1",
        "sec-fetch-site": "same-origin",
        cookie: COOKIE,
      },
    });
    expect(allowed.statusCode).toBe(200);
    const denied = await app.inject({
      method: "GET",
      url: ROOTS,
      headers: {
        "x-openarc-client": "browser-v1",
        "sec-fetch-site": "cross-site",
        cookie: COOKIE,
      },
    });
    expect(denied.statusCode).toBe(403);
  });

  it("rejects read-side credential and write-authority headers and GET body", async () => {
    const { app, service } = build();
    for (const extra of [
      { authorization: "Bearer x" },
      { "proxy-authorization": "Bearer x" },
      { "idempotency-key": IDEMPOTENCY },
      { "x-openarc-csrf": CSRF },
    ]) {
      const response = await app.inject({
        method: "GET",
        url: ROOTS,
        headers: readHeaders(extra),
      });
      expect(response.statusCode, JSON.stringify(extra)).toBe(400);
    }
    const withBody = await app.inject({
      method: "GET",
      url: ROOTS,
      headers: readHeaders({ "content-length": "2" }),
      payload: "{}",
    });
    expect(withBody.statusCode).toBe(400);
    expect(service.calls).toEqual([]);
  });

  it("rejects a real HTTP request with duplicate critical header lines", async () => {
    const { app, service } = build();
    const port = await listeningPort(app);
    const payload = JSON.stringify(CREATE_BODY);
    const base = [
      `Origin: ${ORIGIN}`,
      "X-OpenArc-Client: browser-v1",
      "Content-Type: application/json",
      `Cookie: ${COOKIE}`,
      `X-OpenArc-Csrf: ${CSRF}`,
      `Idempotency-Key: ${IDEMPOTENCY}`,
    ];
    const duplicates: ReadonlyArray<readonly string[]> = [
      [...base, "Content-Type: text/plain"],
      [...base, "Authorization: Bearer x"],
      [...base, "Origin: https://evil.example"],
      [...base, `Idempotency-Key: ${IDEMPOTENCY}`],
    ];
    for (const headers of duplicates) {
      const response = await rawHttp(port, "POST", ROOTS, headers, payload);
      expect([400, 403, 415], headers.join("|")).toContain(response.status);
    }
    expect(service.calls).toEqual([]);
  });

  it("rejects a real HTTP request carrying a duplicated Cookie line before the service", async () => {
    const { app, service } = build();
    const port = await listeningPort(app);
    const response = await rawHttp(
      port,
      "GET",
      ROOTS,
      [
        `Origin: ${ORIGIN}`,
        "X-OpenArc-Client: browser-v1",
        `Cookie: ${COOKIE}`,
        "Cookie: openarc_benign=1",
      ],
      "",
    );
    expect(response.status).toBe(400);
    expect(service.calls).toEqual([]);
  });

  it("returns a bounded v2 error for a pre-handler parser failure without echoing input", async () => {
    const { app, service } = build();
    const canary = "PRIVATE_BODY_CANARY";
    const response = await app.inject({
      method: "POST",
      url: ROOTS,
      headers: writeHeaders(),
      payload: `{ "mutationId": "${MUTATION}", "canary": "${canary}"`,
    });
    expect(response.statusCode).toBe(400);
    expect(v2ErrorCode(response)).toBe("INVALID_REQUEST");
    expect(response.body).not.toContain(canary);
    expect(service.calls).toEqual([]);
  });

  it("rejects an oversized body with a fixed bounded error", async () => {
    const { app, service } = build();
    const response = await app.inject({
      method: "POST",
      url: ROOTS,
      headers: writeHeaders(),
      payload: JSON.stringify({ ...CREATE_BODY, pad: "x".repeat(20_000) }),
    });
    expect(response.statusCode).toBe(413);
    expect(service.calls).toEqual([]);
  });

  it("forwards the whole body to the service and takes no operation from it", async () => {
    const { app, service } = build();
    // The ROUTE does not interpret the body: it forwards it unchanged to the
    // service, which owns strict schema parsing. The route-visible proof here
    // is that a body-supplied `operation` is merely carried, never consulted
    // for dispatch; the strict rejection is proven in the service suite.
    const extra = await app.inject({
      method: "POST",
      url: ROOTS,
      headers: writeHeaders(),
      payload: { ...CREATE_BODY, operation: "control.policy.revoke" },
    });
    expect(extra.statusCode).toBe(200);
    expect(service.calls.at(-1)?.name).toBe("createPolicy");
    expect(service.calls.at(-1)?.request).toMatchObject({
      body: { operation: "control.policy.revoke" },
    });
  });
});

describe("control error and response integrity", () => {
  it("maps service errors without echoing detail", async () => {
    const { app, service } = build();
    service.error = AUTH_ERRORS.internal();
    const response = await app.inject({ method: "GET", url: ROOTS, headers: readHeaders() });
    expect(response.statusCode).toBe(500);
    expect(v2ErrorCode(response)).toBe("INTERNAL_ERROR");
    expect(response.body).not.toContain(POLICY);
  });

  it("fails closed when the serialized envelope exceeds the response bound", async () => {
    const { app } = build({ maxResponseBytes: 16 });
    const response = await app.inject({ method: "GET", url: ROOTS, headers: readHeaders() });
    expect(response.statusCode).toBe(500);
  });

  it("never echoes the cookie, CSRF or idempotency key on success", async () => {
    const { app } = build();
    const response = await app.inject({
      method: "POST",
      url: ROOTS,
      headers: writeHeaders(),
      payload: CREATE_BODY,
    });
    expect(response.statusCode).toBe(200);
    expect(response.body).not.toContain(IDEMPOTENCY);
    expect(response.body).not.toContain(CSRF);
    expect(response.body).not.toContain("openarc_session");
    expect(response.body).not.toContain(COOKIE);
  });
});

describe("control disabled family", () => {
  it("registers no route and returns the ordinary 404 with no service call", async () => {
    const { app, service } = build({ enabled: false });
    for (const [method, target] of [
      ["GET", ROOTS],
      ["POST", ROOTS],
      ["GET", ROOT],
      ["GET", REVISIONS],
      ["GET", REVISION],
      ["GET", MUTATION_URL],
      ["POST", PAUSE],
    ] as const) {
      const response = await app.inject({
        method,
        url: target,
        headers: method === "POST" ? writeHeaders() : readHeaders(),
        ...(method === "POST" ? { payload: CREATE_BODY } : {}),
      });
      expect(response.statusCode, target).toBe(404);
    }
    expect(service.calls).toEqual([]);
  });
});
