import {
  API_CLIENT_HEADER,
  API_MAX_RESPONSE_BYTES,
  COMMERCE_API_SCHEMA_VERSION,
  CommerceApiMetaSchema,
  CommerceControlSessionExchangeResultResponseSchema,
  CommerceControlSessionIdSchema,
  CommerceControlSessionIssueResultResponseSchema,
  CommerceControlSessionListLimitSchema,
  CommerceControlSessionListResponseSchema,
  CommerceControlSessionMutationStatusResponseSchema,
  CommerceControlSessionRevokeResultResponseSchema,
  CommerceControlSessionStatusResponseSchema,
  CommerceMachineSessionTokenSchema,
  CommerceOrganizationIdSchema,
  CommerceTenantIdempotencyKeySchema,
  CommerceTenantMutationIdSchema,
  type CommerceApiMeta,
} from "@openarc/shared";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { ZodType } from "zod";

import { AUTH_ERRORS, AuthApiError } from "../auth/errors.js";
import { parseAuthCookies, type AuthCookieNames } from "../auth/cookies.js";
import type { AuthRequestContext } from "../auth/service.js";
import { decodePathSegment } from "../tenant/routes.js";
import type { CommerceSessionService } from "./session-service.js";

/**
 * Exact protected commerce-session surface.
 *
 * SEVEN routes in two frozen families, taken from the accepted shared
 * `SESSION_ROUTES` registry (five browser management + two agent exchange). The
 * browser family is cookie-only with the exact browser marker, an exact
 * configured Origin and CSRF on writes; `Authorization`/`Proxy-Authorization`
 * are rejected, no response sets a cookie and there is no CORS grant. The agent
 * family accepts exactly ONE `Authorization: Bearer oas_ag_...` session token
 * and rejects every browser/Origin/Fetch-metadata/CSRF/cookie/proxy credential.
 * Raw duplicate critical headers are rejected before body parsing. Every path
 * parameter is decoded exactly once from the bounded raw URL; unknown keywords,
 * extra segments, residual escapes and lookalikes fail closed. The ONLY query
 * accepted anywhere is `afterSessionId`/`limit` on the list route; every other
 * target, including a bare `?`, is rejected. Default-disabled registration
 * installs NO route.
 */

export const COMMERCE_SESSION_CONTROL_PREFIX =
  "/v2/control/organizations" as const;
export const COMMERCE_SESSION_AGENT_EXCHANGE =
  "/v2/agent/commerce-sessions/exchange" as const;
export const COMMERCE_SESSION_AGENT_MUTATION_PREFIX =
  "/v2/agent/commerce-session-mutations" as const;

const MAX_REQUEST_URL_BYTES = 2048;
const MAX_PATH_PARAM_BYTES = 512;
const ENCODED_CHARACTER = /^(?:[^%\s]|%[0-9A-Fa-f]{2})*$/u;

/**
 * Critical security headers whose wire occurrence count must be at most one.
 * `request.raw.rawHeaders` is authoritative because Node may collapse some
 * duplicates in the normalized header map.
 */
const CRITICAL_HEADER_NAMES: ReadonlySet<string> = new Set([
  "origin",
  "x-openarc-client",
  "sec-fetch-site",
  "sec-fetch-mode",
  "sec-fetch-dest",
  "sec-fetch-user",
  "authorization",
  "proxy-authorization",
  "cookie",
  "content-type",
  "content-length",
  "transfer-encoding",
  "idempotency-key",
  "x-openarc-csrf",
]);

/** Browser-only headers that the agent family must never accept. */
const AGENT_FORBIDDEN_HEADERS: readonly string[] = [
  "cookie",
  "origin",
  "x-openarc-client",
  "x-openarc-csrf",
  "sec-fetch-site",
  "sec-fetch-mode",
  "sec-fetch-dest",
  "sec-fetch-user",
  "proxy-authorization",
];

export interface CommerceSessionRoutesOptions {
  appOrigin: string;
  cookieNames: AuthCookieNames;
  service: CommerceSessionService;
  buildSha: string;
  enabled: boolean;
  maxResponseBytes?: number;
}

type ParsedSessionPath =
  | { readonly kind: "list"; readonly organizationId: string }
  | { readonly kind: "issue"; readonly organizationId: string }
  | {
      readonly kind: "status";
      readonly organizationId: string;
      readonly sessionId: string;
    }
  | {
      readonly kind: "revoke";
      readonly organizationId: string;
      readonly sessionId: string;
    }
  | {
      readonly kind: "human_mutation";
      readonly organizationId: string;
      readonly mutationId: string;
    }
  | { readonly kind: "agent_exchange" }
  | { readonly kind: "agent_mutation"; readonly mutationId: string };

interface SessionQuery {
  readonly value: Map<string, string>;
}

function invalidRequest(): AuthApiError {
  return AUTH_ERRORS.invalidRequest();
}

function methodNotAllowed(): AuthApiError {
  return new AuthApiError("INVALID_REQUEST", 405, "METHOD_NOT_ALLOWED");
}

function originRejected(): AuthApiError {
  return AUTH_ERRORS.originRejected();
}

function strictHeader(headers: Record<string, unknown>, key: string): unknown {
  const value = headers[key];
  if (Array.isArray(value)) throw invalidRequest();
  return value;
}

function hasControlCharacter(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (codePoint === undefined) continue;
    if (codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f)) {
      return true;
    }
  }
  return false;
}

function rawRequestUrl(request: FastifyRequest): string {
  const raw = request.raw.url;
  return typeof raw === "string" && raw.length > 0 ? raw : request.url;
}

function rawPath(url: string): string {
  const queryIndex = url.indexOf("?");
  return queryIndex === -1 ? url : url.slice(0, queryIndex);
}

function enforceNoDuplicateCriticalHeaders(request: FastifyRequest): void {
  const raw = request.raw.rawHeaders;
  if (!Array.isArray(raw)) return;
  const seen = new Set<string>();
  for (let index = 0; index + 1 < raw.length; index += 2) {
    const name = raw[index];
    if (typeof name !== "string") continue;
    const lower = name.toLowerCase();
    if (!CRITICAL_HEADER_NAMES.has(lower)) continue;
    if (seen.has(lower)) throw invalidRequest();
    seen.add(lower);
  }
}

function requireCanonical<T>(schema: ZodType<T>, value: string): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw invalidRequest();
  return parsed.data;
}

function decodeSegment(segment: string): string {
  return decodePathSegment(segment, MAX_PATH_PARAM_BYTES);
}

/**
 * Exact decode-once matcher for the seven frozen path shapes. Every segment is
 * bound/control/escape checked, decoded exactly once and validated against the
 * accepted canonical id schema. Unknown keywords, extra segments and other
 * HTTP verbs fail closed.
 */
function parseSessionPath(rawUrl: string): ParsedSessionPath {
  if (Buffer.byteLength(rawUrl, "utf8") > MAX_REQUEST_URL_BYTES) {
    throw invalidRequest();
  }
  if (hasControlCharacter(rawUrl)) throw invalidRequest();
  const path = rawPath(rawUrl);
  const agentExchange = COMMERCE_SESSION_AGENT_EXCHANGE;
  if (path === agentExchange) return { kind: "agent_exchange" };
  const agentMutationPrefix = `${COMMERCE_SESSION_AGENT_MUTATION_PREFIX}/`;
  if (path.startsWith(agentMutationPrefix)) {
    const rest = path.slice(agentMutationPrefix.length).split("/");
    if (rest.length !== 1 || rest[0] === undefined || rest[0].length === 0) {
      throw invalidRequest();
    }
    const mutationId = requireCanonical(
      CommerceTenantMutationIdSchema,
      decodeSegment(rest[0]),
    );
    return { kind: "agent_mutation", mutationId };
  }
  const prefix = `${COMMERCE_SESSION_CONTROL_PREFIX}/`;
  if (!path.startsWith(prefix)) throw invalidRequest();
  const segments = path.slice(prefix.length).split("/");
  for (const segment of segments) {
    if (segment.length === 0) throw invalidRequest();
  }
  const organizationId = requireCanonical(
    CommerceOrganizationIdSchema,
    decodeSegment(segments[0] as string),
  );
  const second = segments[1];
  if (second === "commerce-sessions") {
    if (segments.length === 2) {
      // GET list and POST issue share this target; the method decides.
      return { kind: "list", organizationId };
    }
    if (segments[2] === undefined) throw invalidRequest();
    const sessionId = requireCanonical(
      CommerceControlSessionIdSchema,
      decodeSegment(segments[2]),
    );
    if (segments.length === 3) return { kind: "status", organizationId, sessionId };
    if (segments.length === 4 && segments[3] === "revoke") {
      return { kind: "revoke", organizationId, sessionId };
    }
    throw invalidRequest();
  }
  if (second === "commerce-session-mutations") {
    if (segments.length !== 3 || segments[2] === undefined) throw invalidRequest();
    const mutationId = requireCanonical(
      CommerceTenantMutationIdSchema,
      decodeSegment(segments[2]),
    );
    return { kind: "human_mutation", organizationId, mutationId };
  }
  throw invalidRequest();
}

/**
 * Parse a bounded raw query string. Invalid percent-encoding, empty
 * keys/values, duplicate keys, unknown keys, control characters and a bare `?`
 * fail closed; an empty or absent value is never coerced into a default.
 */
function parseQuery(url: string, allowedKeys: readonly string[]): SessionQuery {
  const queryIndex = url.indexOf("?");
  if (queryIndex === -1) return { value: new Map() };
  const raw = url.slice(queryIndex + 1);
  if (raw.length === 0 || raw.includes("#")) throw invalidRequest();
  for (const pair of raw.split("&")) {
    if (pair.length === 0) throw invalidRequest();
    const separator = pair.indexOf("=");
    if (separator <= 0) throw invalidRequest();
    const key = pair.slice(0, separator);
    const value = pair.slice(separator + 1);
    if (
      value.length === 0 ||
      !ENCODED_CHARACTER.test(key) ||
      !ENCODED_CHARACTER.test(value)
    ) {
      throw invalidRequest();
    }
  }
  const params = new URLSearchParams(raw);
  const result = new Map<string, string>();
  for (const key of new Set(params.keys())) {
    const values = params.getAll(key);
    if (values.length !== 1) throw invalidRequest();
    if (!allowedKeys.includes(key)) throw invalidRequest();
    const value = values[0];
    if (value === undefined || hasControlCharacter(value)) throw invalidRequest();
    result.set(key, value);
  }
  return { value: result };
}

function parseListQuery(url: string): {
  afterSessionId?: string;
  limit?: string;
} {
  const query = parseQuery(url, ["afterSessionId", "limit"]);
  const after = query.value.get("afterSessionId");
  const limit = query.value.get("limit");
  if (after !== undefined) {
    requireCanonical(CommerceControlSessionIdSchema, after);
  }
  if (limit !== undefined) {
    requireCanonical(CommerceControlSessionListLimitSchema, limit);
  }
  return {
    ...(after !== undefined ? { afterSessionId: after } : {}),
    ...(limit !== undefined ? { limit } : {}),
  };
}

function requestContext(
  request: FastifyRequest,
  names: AuthCookieNames,
): AuthRequestContext {
  let cookies;
  try {
    cookies = parseAuthCookies(request.headers.cookie, names);
  } catch {
    throw invalidRequest();
  }
  return { peerIp: request.ip, cookies };
}

function enforceFetchMetadata(
  request: FastifyRequest,
  options: CommerceSessionRoutesOptions,
  allowOriginlessSameOrigin: boolean,
): void {
  const origin = strictHeader(request.headers, "origin");
  const site = strictHeader(request.headers, "sec-fetch-site");
  const mode = strictHeader(request.headers, "sec-fetch-mode");
  const destination = strictHeader(request.headers, "sec-fetch-dest");
  if (origin === options.appOrigin) {
    // exact same-origin request
  } else if (allowOriginlessSameOrigin && origin === undefined && site === "same-origin") {
    // Same-origin browser GETs normally omit Origin; allow originless reads
    // ONLY with an explicit same-origin fetch site.
  } else {
    throw originRejected();
  }
  if (site !== undefined && site !== "same-origin") throw originRejected();
  if (mode !== undefined && mode !== "cors" && mode !== "same-origin") {
    throw originRejected();
  }
  if (destination !== undefined && destination !== "empty") throw originRejected();
}

function enforceBrowserOrigin(
  request: FastifyRequest,
  options: CommerceSessionRoutesOptions,
  allowOriginlessSameOrigin: boolean,
): void {
  enforceNoDuplicateCriticalHeaders(request);
  if (Buffer.byteLength(rawRequestUrl(request), "utf8") > MAX_REQUEST_URL_BYTES) {
    throw invalidRequest();
  }
  if (strictHeader(request.headers, "authorization") !== undefined) {
    throw invalidRequest();
  }
  if (strictHeader(request.headers, "proxy-authorization") !== undefined) {
    throw invalidRequest();
  }
  if (strictHeader(request.headers, "x-openarc-client") !== API_CLIENT_HEADER) {
    throw originRejected();
  }
  enforceFetchMetadata(request, options, allowOriginlessSameOrigin);
}

function enforceHumanReadTransport(
  request: FastifyRequest,
  options: CommerceSessionRoutesOptions,
): void {
  enforceBrowserOrigin(request, options, true);
  if (request.method !== "GET") throw methodNotAllowed();
  const contentLength = strictHeader(request.headers, "content-length");
  if (contentLength !== undefined && contentLength !== "0") throw invalidRequest();
  if (strictHeader(request.headers, "transfer-encoding") !== undefined) {
    throw invalidRequest();
  }
  if (strictHeader(request.headers, "idempotency-key") !== undefined) {
    throw invalidRequest();
  }
  if (strictHeader(request.headers, "x-openarc-csrf") !== undefined) {
    throw invalidRequest();
  }
}

function enforceHumanWriteTransport(
  request: FastifyRequest,
  options: CommerceSessionRoutesOptions,
): void {
  enforceBrowserOrigin(request, options, false);
  if (request.method !== "POST") throw methodNotAllowed();
  if (rawRequestUrl(request).includes("?")) throw invalidRequest();
  const contentType = strictHeader(request.headers, "content-type");
  if (
    typeof contentType !== "string" ||
    !/^application\/json(?:; *charset=utf-8)?$/iu.test(contentType)
  ) {
    throw AUTH_ERRORS.unsupportedMedia();
  }
  if (strictHeader(request.headers, "transfer-encoding") !== undefined) {
    throw invalidRequest();
  }
  const contentLength = strictHeader(request.headers, "content-length");
  if (
    contentLength !== undefined &&
    (typeof contentLength !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(contentLength))
  ) {
    throw invalidRequest();
  }
  const idempotency = strictHeader(request.headers, "idempotency-key");
  if (
    typeof idempotency !== "string" ||
    !CommerceTenantIdempotencyKeySchema.safeParse(idempotency).success
  ) {
    throw invalidRequest();
  }
  const csrf = strictHeader(request.headers, "x-openarc-csrf");
  if (typeof csrf !== "string" || csrf.length === 0) throw invalidRequest();
}

function agentBearer(request: FastifyRequest): string {
  const authorization = strictHeader(request.headers, "authorization");
  if (typeof authorization !== "string") throw AUTH_ERRORS.unauthenticated();
  const match = /^Bearer ([A-Za-z0-9_-]{1,1024})$/u.exec(authorization);
  if (match === null) throw AUTH_ERRORS.unauthenticated();
  const token = match[1] as string;
  if (
    !CommerceMachineSessionTokenSchema.safeParse(token).success ||
    !token.startsWith("oas_ag_")
  ) {
    throw AUTH_ERRORS.unauthenticated();
  }
  return token;
}

function enforceAgentTransport(request: FastifyRequest): string {
  enforceNoDuplicateCriticalHeaders(request);
  if (Buffer.byteLength(rawRequestUrl(request), "utf8") > MAX_REQUEST_URL_BYTES) {
    throw invalidRequest();
  }
  for (const name of AGENT_FORBIDDEN_HEADERS) {
    if (strictHeader(request.headers, name) !== undefined) throw invalidRequest();
  }
  return agentBearer(request);
}

function enforceAgentStatusTransport(request: FastifyRequest): string {
  const token = enforceAgentTransport(request);
  if (request.method !== "GET") throw methodNotAllowed();
  if (rawRequestUrl(request).includes("?")) throw invalidRequest();
  if (strictHeader(request.headers, "idempotency-key") !== undefined) {
    throw invalidRequest();
  }
  const contentLength = strictHeader(request.headers, "content-length");
  if (contentLength !== undefined && contentLength !== "0") throw invalidRequest();
  if (strictHeader(request.headers, "transfer-encoding") !== undefined) {
    throw invalidRequest();
  }
  return token;
}

function enforceAgentExchangeTransport(request: FastifyRequest): string {
  const token = enforceAgentTransport(request);
  if (request.method !== "POST") throw methodNotAllowed();
  if (rawRequestUrl(request).includes("?")) throw invalidRequest();
  const contentType = strictHeader(request.headers, "content-type");
  if (
    typeof contentType !== "string" ||
    !/^application\/json(?:; *charset=utf-8)?$/iu.test(contentType)
  ) {
    throw AUTH_ERRORS.unsupportedMedia();
  }
  if (strictHeader(request.headers, "transfer-encoding") !== undefined) {
    throw invalidRequest();
  }
  const contentLength = strictHeader(request.headers, "content-length");
  if (
    contentLength !== undefined &&
    (typeof contentLength !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(contentLength))
  ) {
    throw invalidRequest();
  }
  const idempotency = strictHeader(request.headers, "idempotency-key");
  if (
    typeof idempotency !== "string" ||
    !CommerceTenantIdempotencyKeySchema.safeParse(idempotency).success
  ) {
    throw invalidRequest();
  }
  return token;
}

function meta(request: FastifyRequest, buildSha: string): CommerceApiMeta {
  return CommerceApiMetaSchema.parse({
    schemaVersion: COMMERCE_API_SCHEMA_VERSION,
    requestId: request.id,
    buildSha,
  });
}

function sendEnvelope<T>(
  request: FastifyRequest,
  reply: FastifyReply,
  options: CommerceSessionRoutesOptions,
  schema: ZodType<{ ok: true; data: T; meta: CommerceApiMeta }>,
  data: T,
): FastifyReply {
  const envelope = schema.parse({ ok: true, data, meta: meta(request, options.buildSha) });
  const serialized = JSON.stringify(envelope);
  const limit = options.maxResponseBytes ?? API_MAX_RESPONSE_BYTES;
  if (Buffer.byteLength(serialized, "utf8") > limit) throw AUTH_ERRORS.internal();
  return reply
    .type("application/json; charset=utf-8")
    .header("Cache-Control", "no-store")
    .send(serialized);
}

/**
 * Register the seven frozen commerce-session routes. Exported for the future
 * runtime packet and deliberately NOT invoked by any current source file.
 */
export function registerCommerceSessionRoutes(
  app: FastifyInstance,
  options: CommerceSessionRoutesOptions,
): void {
  if (!options.enabled) return;

  const humanList = `${COMMERCE_SESSION_CONTROL_PREFIX}/:organizationId/commerce-sessions`;
  const humanStatus = `${COMMERCE_SESSION_CONTROL_PREFIX}/:organizationId/commerce-sessions/:sessionId`;
  const humanRevoke = `${COMMERCE_SESSION_CONTROL_PREFIX}/:organizationId/commerce-sessions/:sessionId/revoke`;
  const humanMutation = `${COMMERCE_SESSION_CONTROL_PREFIX}/:organizationId/commerce-session-mutations/:mutationId`;

  app.all(
    humanList,
    {
      onRequest: async (request) => {
        const path = parseSessionPath(rawRequestUrl(request));
        if (path.kind === "list" && request.method === "GET") {
          enforceHumanReadTransport(request, options);
          parseListQuery(rawRequestUrl(request));
          return;
        }
        if (path.kind === "list" && request.method === "POST") {
          enforceHumanWriteTransport(request, options);
          return;
        }
        throw methodNotAllowed();
      },
    },
    async (request, reply) => {
      const path = parseSessionPath(rawRequestUrl(request));
      if (path.kind === "list" && request.method === "GET") {
        const query = parseListQuery(rawRequestUrl(request));
        const data = await options.service.list(
          requestContext(request, options.cookieNames),
          {
            organizationId: path.organizationId,
            ...(query.afterSessionId !== undefined
              ? { afterSessionId: query.afterSessionId }
              : {}),
            ...(query.limit !== undefined ? { limit: query.limit } : {}),
          },
        );
        return sendEnvelope(
          request,
          reply,
          options,
          CommerceControlSessionListResponseSchema,
          data,
        );
      }
      if (path.kind !== "list") throw invalidRequest();
      const data = await options.service.issue(
        requestContext(request, options.cookieNames),
        path.organizationId,
        {
          csrf: strictHeader(request.headers, "x-openarc-csrf"),
          idempotencyKey: strictHeader(request.headers, "idempotency-key"),
          body: request.body,
        },
      );
      return sendEnvelope(
        request,
        reply,
        options,
        CommerceControlSessionIssueResultResponseSchema,
        data,
      );
    },
  );

  app.all(
    humanStatus,
    {
      onRequest: async (request) => {
        const path = parseSessionPath(rawRequestUrl(request));
        if (path.kind !== "status") throw invalidRequest();
        if (rawRequestUrl(request).includes("?")) throw invalidRequest();
        enforceHumanReadTransport(request, options);
      },
    },
    async (request, reply) => {
      const path = parseSessionPath(rawRequestUrl(request));
      if (path.kind !== "status") throw invalidRequest();
      const data = await options.service.getStatus(
        requestContext(request, options.cookieNames),
        {
          organizationId: path.organizationId,
          sessionId: path.sessionId,
        },
      );
      return sendEnvelope(
        request,
        reply,
        options,
        CommerceControlSessionStatusResponseSchema,
        data,
      );
    },
  );

  app.all(
    humanRevoke,
    {
      onRequest: async (request) => {
        const path = parseSessionPath(rawRequestUrl(request));
        if (path.kind !== "revoke") throw invalidRequest();
        enforceHumanWriteTransport(request, options);
      },
    },
    async (request, reply) => {
      const path = parseSessionPath(rawRequestUrl(request));
      if (path.kind !== "revoke") throw invalidRequest();
      const data = await options.service.revoke(
        requestContext(request, options.cookieNames),
        path.organizationId,
        path.sessionId,
        {
          csrf: strictHeader(request.headers, "x-openarc-csrf"),
          idempotencyKey: strictHeader(request.headers, "idempotency-key"),
          body: request.body,
        },
      );
      return sendEnvelope(
        request,
        reply,
        options,
        CommerceControlSessionRevokeResultResponseSchema,
        data,
      );
    },
  );

  app.all(
    humanMutation,
    {
      onRequest: async (request) => {
        const path = parseSessionPath(rawRequestUrl(request));
        if (path.kind !== "human_mutation") throw invalidRequest();
        if (rawRequestUrl(request).includes("?")) throw invalidRequest();
        enforceHumanReadTransport(request, options);
      },
    },
    async (request, reply) => {
      const path = parseSessionPath(rawRequestUrl(request));
      if (path.kind !== "human_mutation") throw invalidRequest();
      const data = await options.service.getHumanMutationStatus(
        requestContext(request, options.cookieNames),
        {
          organizationId: path.organizationId,
          mutationId: path.mutationId,
        },
      );
      return sendEnvelope(
        request,
        reply,
        options,
        CommerceControlSessionMutationStatusResponseSchema,
        data,
      );
    },
  );

  app.all(
    COMMERCE_SESSION_AGENT_EXCHANGE,
    {
      onRequest: async (request) => {
        const path = parseSessionPath(rawRequestUrl(request));
        if (path.kind !== "agent_exchange") throw invalidRequest();
        enforceAgentExchangeTransport(request);
      },
    },
    async (request, reply) => {
      const token = enforceAgentExchangeTransport(request);
      const data = await options.service.exchange(token, request.ip, {
        idempotencyKey: strictHeader(request.headers, "idempotency-key"),
        body: request.body,
      });
      return sendEnvelope(
        request,
        reply,
        options,
        CommerceControlSessionExchangeResultResponseSchema,
        data,
      );
    },
  );

  app.all(
    `${COMMERCE_SESSION_AGENT_MUTATION_PREFIX}/:mutationId`,
    {
      onRequest: async (request) => {
        const path = parseSessionPath(rawRequestUrl(request));
        if (path.kind !== "agent_mutation") throw invalidRequest();
        enforceAgentStatusTransport(request);
      },
    },
    async (request, reply) => {
      const path = parseSessionPath(rawRequestUrl(request));
      if (path.kind !== "agent_mutation") throw invalidRequest();
      const token = enforceAgentStatusTransport(request);
      const data = await options.service.getAgentMutationStatus(
        token,
        request.ip,
        path.mutationId,
      );
      return sendEnvelope(
        request,
        reply,
        options,
        CommerceControlSessionMutationStatusResponseSchema,
        data,
      );
    },
  );
}
