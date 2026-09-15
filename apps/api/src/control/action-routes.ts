import {
  ACTION_ROUTES,
  API_CLIENT_HEADER,
  API_MAX_REQUEST_BYTES,
  API_MAX_RESPONSE_BYTES,
  COMMERCE_API_SCHEMA_VERSION,
  CommerceActionDetailResponseSchema,
  CommerceActionIdSchema,
  CommerceActionMutationDataResponseSchema,
  CommerceActionMutationStatusResponseSchema,
  CommerceActionPageResponseSchema,
  CommerceAgentIdSchema,
  CommerceApiMetaSchema,
  CommerceApprovalDetailResponseSchema,
  CommerceApprovalIdSchema,
  CommerceApprovalPageResponseSchema,
  CommerceExposureDataResponseSchema,
  CommerceOrganizationIdSchema,
  CommercePolicyIdSchema,
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
import type { CommerceActionService } from "./action-service.js";

/**
 * Exact protected commerce-action surface.
 *
 * TWELVE routes in two strictly separated frozen families, taken from the
 * accepted shared `ACTION_ROUTES` registry: nine `commerce_action_management`
 * BROWSER routes and three `commerce_action_authorization` AGENT routes. No
 * thirteenth route, capability/manifest/health/fallback descriptor or
 * payment/grant/provider route is registered here.
 *
 * The browser family is cookie-only with the exact browser marker, an exact
 * configured Origin and CSRF on every write; `Authorization` and
 * `Proxy-Authorization` are rejected outright, no response sets a cookie and
 * there is no CORS grant. The agent family accepts exactly ONE
 * `Authorization: Bearer oacs_v1_...` commerce-session token and rejects every
 * cookie, Origin, Fetch-metadata, CSRF and proxy credential. The two families
 * can therefore never authorize each other: a browser cookie is inert on an
 * agent route and a bearer is inert on a browser route.
 *
 * Raw duplicate critical headers are rejected before body parsing. Every path
 * parameter is decoded exactly once from the bounded raw URL; unknown keywords,
 * extra segments, residual escapes and lookalikes fail closed. The ONLY queries
 * accepted anywhere are `afterActionId`/`limit` on the action list and
 * `afterApprovalId`/`limit` on the approval list; every other query target,
 * including a bare `?`, is rejected.
 *
 * Registration ALWAYS installs exactly these twelve exact targets. While the
 * family is gated off every one of them answers with the accepted
 * `FEATURE_DISABLED` API error envelope BEFORE any service, store, limiter or
 * cookie work, so a static/SPA fallback can never capture an API path and turn
 * it into an HTML 200. No route here implies a payment, settlement, delivery or
 * grant.
 */

export const ACTION_CONTROL_PREFIX = "/v2/control/organizations" as const;
export const ACTION_AGENT_ACTIONS = "/v2/agent/commerce-actions" as const;
export const ACTION_AGENT_MUTATION_PREFIX =
  "/v2/agent/commerce-action-mutations" as const;

const MAX_REQUEST_URL_BYTES = 2048;
const MAX_PATH_PARAM_BYTES = 512;
/** Exact body ceiling for the four action writes. */
export const ACTION_MAX_REQUEST_BYTES = API_MAX_REQUEST_BYTES;
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

export interface CommerceActionRoutesOptions {
  appOrigin: string;
  cookieNames: AuthCookieNames;
  service: CommerceActionService;
  buildSha: string;
  enabled: boolean;
  maxResponseBytes?: number;
}

type ParsedActionPath =
  | { readonly kind: "action_list"; readonly organizationId: string }
  | {
      readonly kind: "action_detail";
      readonly organizationId: string;
      readonly actionId: string;
    }
  | {
      readonly kind: "action_approve";
      readonly organizationId: string;
      readonly actionId: string;
    }
  | {
      readonly kind: "action_reject";
      readonly organizationId: string;
      readonly actionId: string;
    }
  | {
      readonly kind: "action_cancel";
      readonly organizationId: string;
      readonly actionId: string;
    }
  | { readonly kind: "approval_list"; readonly organizationId: string }
  | {
      readonly kind: "approval_detail";
      readonly organizationId: string;
      readonly approvalId: string;
    }
  | {
      readonly kind: "action_exposure";
      readonly organizationId: string;
      readonly subjectAgentId: string;
      readonly policyId: string;
    }
  | {
      readonly kind: "action_mutation_status";
      readonly organizationId: string;
      readonly mutationId: string;
    }
  | { readonly kind: "action_authorize" }
  | { readonly kind: "agent_action_detail"; readonly actionId: string }
  | {
      readonly kind: "agent_action_mutation_status";
      readonly mutationId: string;
    };

function invalidRequest(): AuthApiError {
  return AUTH_ERRORS.invalidRequest();
}

function methodNotAllowed(): AuthApiError {
  return new AuthApiError("INVALID_REQUEST", 405, "METHOD_NOT_ALLOWED");
}

function originRejected(): AuthApiError {
  return AUTH_ERRORS.originRejected();
}

/** The accepted fixed disabled error for a gated-off action route. */
function featureDisabled(): AuthApiError {
  return AUTH_ERRORS.featureDisabled();
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
 * Exact decode-once matcher for the twelve frozen path shapes. Every segment is
 * bound/control/escape checked, decoded exactly once and validated against the
 * accepted canonical id schema. Unknown keywords, extra segments and lookalike
 * targets fail closed.
 */
export function parseActionPath(rawUrl: string): ParsedActionPath {
  if (Buffer.byteLength(rawUrl, "utf8") > MAX_REQUEST_URL_BYTES) {
    throw invalidRequest();
  }
  if (hasControlCharacter(rawUrl)) throw invalidRequest();
  const path = rawPath(rawUrl);

  // Agent family first: its roots are exact and distinct from the browser root.
  const agentMutationPrefix = `${ACTION_AGENT_MUTATION_PREFIX}/`;
  if (path.startsWith(agentMutationPrefix)) {
    const rest = path.slice(agentMutationPrefix.length).split("/");
    if (rest.length !== 1 || rest[0] === undefined || rest[0].length === 0) {
      throw invalidRequest();
    }
    return {
      kind: "agent_action_mutation_status",
      mutationId: requireCanonical(
        CommerceTenantMutationIdSchema,
        decodeSegment(rest[0]),
      ),
    };
  }
  if (path === ACTION_AGENT_ACTIONS) return { kind: "action_authorize" };
  const agentActionPrefix = `${ACTION_AGENT_ACTIONS}/`;
  if (path.startsWith(agentActionPrefix)) {
    const rest = path.slice(agentActionPrefix.length).split("/");
    if (rest.length !== 1 || rest[0] === undefined || rest[0].length === 0) {
      throw invalidRequest();
    }
    return {
      kind: "agent_action_detail",
      actionId: requireCanonical(
        CommerceActionIdSchema,
        decodeSegment(rest[0]),
      ),
    };
  }

  const prefix = `${ACTION_CONTROL_PREFIX}/`;
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
  if (second === "actions") {
    if (segments.length === 2) return { kind: "action_list", organizationId };
    if (segments[2] === undefined) throw invalidRequest();
    const actionId = requireCanonical(
      CommerceActionIdSchema,
      decodeSegment(segments[2]),
    );
    if (segments.length === 3) {
      return { kind: "action_detail", organizationId, actionId };
    }
    if (segments.length === 4) {
      const decision = segments[3];
      if (decision === "approve") {
        return { kind: "action_approve", organizationId, actionId };
      }
      if (decision === "reject") {
        return { kind: "action_reject", organizationId, actionId };
      }
      if (decision === "cancel") {
        return { kind: "action_cancel", organizationId, actionId };
      }
    }
    throw invalidRequest();
  }
  if (second === "approvals") {
    if (segments.length === 2) return { kind: "approval_list", organizationId };
    if (segments.length !== 3 || segments[2] === undefined) {
      throw invalidRequest();
    }
    return {
      kind: "approval_detail",
      organizationId,
      approvalId: requireCanonical(
        CommerceApprovalIdSchema,
        decodeSegment(segments[2]),
      ),
    };
  }
  if (second === "action-mutations") {
    if (segments.length !== 3 || segments[2] === undefined) {
      throw invalidRequest();
    }
    return {
      kind: "action_mutation_status",
      organizationId,
      mutationId: requireCanonical(
        CommerceTenantMutationIdSchema,
        decodeSegment(segments[2]),
      ),
    };
  }
  if (second === "agents") {
    if (
      segments.length !== 6 ||
      segments[2] === undefined ||
      segments[3] !== "policies" ||
      segments[4] === undefined ||
      segments[5] !== "exposure"
    ) {
      throw invalidRequest();
    }
    return {
      kind: "action_exposure",
      organizationId,
      subjectAgentId: requireCanonical(
        CommerceAgentIdSchema,
        decodeSegment(segments[2]),
      ),
      policyId: requireCanonical(
        CommercePolicyIdSchema,
        decodeSegment(segments[4]),
      ),
    };
  }
  throw invalidRequest();
}

/**
 * Parse a bounded raw query string. Invalid percent-encoding, empty
 * keys/values, duplicate keys, unknown keys, control characters and a bare `?`
 * fail closed; an empty or absent value is never coerced into a default.
 */
function parseQuery(
  url: string,
  allowedKeys: readonly string[],
): Map<string, string> {
  const queryIndex = url.indexOf("?");
  if (queryIndex === -1) return new Map();
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
    if (value === undefined || hasControlCharacter(value)) {
      throw invalidRequest();
    }
    result.set(key, value);
  }
  return result;
}

/** Canonical 1..50 wire limit. No default, coercion or leading zero. */
const LIMIT_PATTERN = /^(?:[1-9]|[1-4][0-9]|50)(?![\s\S])/u;

function parseActionListQuery(url: string): {
  afterActionId?: string;
  limit?: string;
} {
  const query = parseQuery(url, ["afterActionId", "limit"]);
  const after = query.get("afterActionId");
  const limit = query.get("limit");
  if (after !== undefined) requireCanonical(CommerceActionIdSchema, after);
  if (limit !== undefined && !LIMIT_PATTERN.test(limit)) throw invalidRequest();
  return {
    ...(after !== undefined ? { afterActionId: after } : {}),
    ...(limit !== undefined ? { limit } : {}),
  };
}

function parseApprovalListQuery(url: string): {
  afterApprovalId?: string;
  limit?: string;
} {
  const query = parseQuery(url, ["afterApprovalId", "limit"]);
  const after = query.get("afterApprovalId");
  const limit = query.get("limit");
  if (after !== undefined) requireCanonical(CommerceApprovalIdSchema, after);
  if (limit !== undefined && !LIMIT_PATTERN.test(limit)) throw invalidRequest();
  return {
    ...(after !== undefined ? { afterApprovalId: after } : {}),
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
  options: CommerceActionRoutesOptions,
  allowOriginlessSameOrigin: boolean,
): void {
  const origin = strictHeader(request.headers, "origin");
  const site = strictHeader(request.headers, "sec-fetch-site");
  const mode = strictHeader(request.headers, "sec-fetch-mode");
  const destination = strictHeader(request.headers, "sec-fetch-dest");
  if (origin === options.appOrigin) {
    // exact same-origin request
  } else if (
    allowOriginlessSameOrigin &&
    origin === undefined &&
    site === "same-origin"
  ) {
    // Same-origin browser GETs normally omit Origin; allow originless reads
    // ONLY with an explicit same-origin fetch site.
  } else {
    throw originRejected();
  }
  if (site !== undefined && site !== "same-origin") throw originRejected();
  if (mode !== undefined && mode !== "cors" && mode !== "same-origin") {
    throw originRejected();
  }
  if (destination !== undefined && destination !== "empty") {
    throw originRejected();
  }
}

function enforceBrowserOrigin(
  request: FastifyRequest,
  options: CommerceActionRoutesOptions,
  allowOriginlessSameOrigin: boolean,
): void {
  enforceNoDuplicateCriticalHeaders(request);
  if (
    Buffer.byteLength(rawRequestUrl(request), "utf8") > MAX_REQUEST_URL_BYTES
  ) {
    throw invalidRequest();
  }
  // A bearer can never reach the browser family, even alongside a valid cookie.
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

function enforceBrowserReadTransport(
  request: FastifyRequest,
  options: CommerceActionRoutesOptions,
): void {
  enforceBrowserOrigin(request, options, true);
  if (request.method !== "GET") throw methodNotAllowed();
  const contentLength = strictHeader(request.headers, "content-length");
  if (contentLength !== undefined && contentLength !== "0") {
    throw invalidRequest();
  }
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

/** Shared bounded body/content checks for both write families. */
function enforceWriteBody(request: FastifyRequest): void {
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
  if (contentLength !== undefined) {
    if (
      typeof contentLength !== "string" ||
      !/^(?:0|[1-9][0-9]{0,9})(?![\s\S])/u.test(contentLength)
    ) {
      throw invalidRequest();
    }
    if (Number(contentLength) > ACTION_MAX_REQUEST_BYTES) {
      throw AUTH_ERRORS.tooLarge();
    }
  }
  const idempotency = strictHeader(request.headers, "idempotency-key");
  if (
    typeof idempotency !== "string" ||
    !CommerceTenantIdempotencyKeySchema.safeParse(idempotency).success
  ) {
    throw invalidRequest();
  }
}

function enforceBrowserWriteTransport(
  request: FastifyRequest,
  options: CommerceActionRoutesOptions,
): void {
  enforceBrowserOrigin(request, options, false);
  if (request.method !== "POST") throw methodNotAllowed();
  if (rawRequestUrl(request).includes("?")) throw invalidRequest();
  enforceWriteBody(request);
  const csrf = strictHeader(request.headers, "x-openarc-csrf");
  if (typeof csrf !== "string" || csrf.length === 0) throw invalidRequest();
}

/**
 * Exactly ONE `Authorization: Bearer oacs_v1_<43 base64url>` commerce-session
 * token. The raw token is returned to the caller for hashing and is never
 * logged, echoed or persisted here.
 */
function agentBearer(request: FastifyRequest): string {
  const authorization = strictHeader(request.headers, "authorization");
  if (typeof authorization !== "string") throw AUTH_ERRORS.unauthenticated();
  const match = /^Bearer (oacs_v1_[A-Za-z0-9_-]{43})(?![\s\S])/u.exec(
    authorization,
  );
  if (match === null) throw AUTH_ERRORS.unauthenticated();
  return match[1] as string;
}

function enforceAgentTransport(request: FastifyRequest): string {
  enforceNoDuplicateCriticalHeaders(request);
  if (
    Buffer.byteLength(rawRequestUrl(request), "utf8") > MAX_REQUEST_URL_BYTES
  ) {
    throw invalidRequest();
  }
  // A browser cookie/CSRF/Origin can never reach the agent family.
  for (const name of AGENT_FORBIDDEN_HEADERS) {
    if (strictHeader(request.headers, name) !== undefined) {
      throw invalidRequest();
    }
  }
  return agentBearer(request);
}

function enforceAgentReadTransport(request: FastifyRequest): string {
  const token = enforceAgentTransport(request);
  if (request.method !== "GET") throw methodNotAllowed();
  if (rawRequestUrl(request).includes("?")) throw invalidRequest();
  if (strictHeader(request.headers, "idempotency-key") !== undefined) {
    throw invalidRequest();
  }
  const contentLength = strictHeader(request.headers, "content-length");
  if (contentLength !== undefined && contentLength !== "0") {
    throw invalidRequest();
  }
  if (strictHeader(request.headers, "transfer-encoding") !== undefined) {
    throw invalidRequest();
  }
  return token;
}

function enforceAgentWriteTransport(request: FastifyRequest): string {
  const token = enforceAgentTransport(request);
  if (request.method !== "POST") throw methodNotAllowed();
  if (rawRequestUrl(request).includes("?")) throw invalidRequest();
  enforceWriteBody(request);
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
  options: CommerceActionRoutesOptions,
  schema: ZodType<{ ok: true; data: T; meta: CommerceApiMeta }>,
  data: T,
): FastifyReply {
  const envelope = schema.parse({
    ok: true,
    data,
    meta: meta(request, options.buildSha),
  });
  const serialized = JSON.stringify(envelope);
  const limit = options.maxResponseBytes ?? API_MAX_RESPONSE_BYTES;
  if (Buffer.byteLength(serialized, "utf8") > limit) throw AUTH_ERRORS.internal();
  return reply
    .type("application/json; charset=utf-8")
    .header("Cache-Control", "no-store")
    .send(serialized);
}

/** Route template for each frozen descriptor id, in the frozen order. */
const ROUTE_TEMPLATES: Readonly<Record<string, string>> = Object.freeze({
  action_list: `${ACTION_CONTROL_PREFIX}/:organizationId/actions`,
  action_detail: `${ACTION_CONTROL_PREFIX}/:organizationId/actions/:actionId`,
  approval_list: `${ACTION_CONTROL_PREFIX}/:organizationId/approvals`,
  approval_detail: `${ACTION_CONTROL_PREFIX}/:organizationId/approvals/:approvalId`,
  action_exposure: `${ACTION_CONTROL_PREFIX}/:organizationId/agents/:subjectAgentId/policies/:policyId/exposure`,
  action_mutation_status: `${ACTION_CONTROL_PREFIX}/:organizationId/action-mutations/:mutationId`,
  action_approve: `${ACTION_CONTROL_PREFIX}/:organizationId/actions/:actionId/approve`,
  action_reject: `${ACTION_CONTROL_PREFIX}/:organizationId/actions/:actionId/reject`,
  action_cancel: `${ACTION_CONTROL_PREFIX}/:organizationId/actions/:actionId/cancel`,
  action_authorize: ACTION_AGENT_ACTIONS,
  agent_action_detail: `${ACTION_AGENT_ACTIONS}/:actionId`,
  agent_action_mutation_status: `${ACTION_AGENT_MUTATION_PREFIX}/:mutationId`,
});

/**
 * The exact registered templates, derived from the frozen shared registry and
 * asserted against it. Drift in either direction fails closed at registration.
 */
export function actionRouteTemplates(): readonly {
  id: string;
  method: "GET" | "POST";
  path: string;
  audience: "browser" | "agent";
}[] {
  return ACTION_ROUTES.map((route) => {
    const template = ROUTE_TEMPLATES[route.id];
    if (template === undefined) {
      throw new Error("COMMERCE_ACTION_ROUTE_REGISTRY_DRIFT");
    }
    return {
      id: route.id,
      method: route.method,
      path: template,
      audience: route.audience,
    };
  });
}

export function registerCommerceActionRoutes(
  app: FastifyInstance,
  options: CommerceActionRoutesOptions,
): void {
  // The exact twelve targets are ALWAYS installed. While gated off each one
  // answers the accepted disabled API error before any service/store/cookie
  // work, so no static or SPA fallback can answer an API path with HTML.
  if (!options.enabled) {
    for (const route of actionRouteTemplates()) {
      app.all(
        route.path,
        {
          onRequest: async () => {
            throw featureDisabled();
          },
        },
        async () => undefined,
      );
    }
    return;
  }

  const browserRead = (
    expected: ParsedActionPath["kind"],
    allowQuery: boolean,
  ) =>
    async (request: FastifyRequest): Promise<void> => {
      const path = parseActionPath(rawRequestUrl(request));
      if (path.kind !== expected) throw invalidRequest();
      if (!allowQuery && rawRequestUrl(request).includes("?")) {
        throw invalidRequest();
      }
      enforceBrowserReadTransport(request, options);
    };

  const browserWrite =
    (expected: ParsedActionPath["kind"]) =>
    async (request: FastifyRequest): Promise<void> => {
      const path = parseActionPath(rawRequestUrl(request));
      if (path.kind !== expected) throw invalidRequest();
      enforceBrowserWriteTransport(request, options);
    };

  /* -- commerce_action_management (browser) --------------------------- */

  app.all(
    ROUTE_TEMPLATES["action_list"] as string,
    {
      onRequest: async (request) => {
        await browserRead("action_list", true)(request);
        parseActionListQuery(rawRequestUrl(request));
      },
    },
    async (request, reply) => {
      const path = parseActionPath(rawRequestUrl(request));
      if (path.kind !== "action_list") throw invalidRequest();
      const query = parseActionListQuery(rawRequestUrl(request));
      const data = await options.service.listActions(
        requestContext(request, options.cookieNames),
        {
          organizationId: path.organizationId,
          ...(query.afterActionId !== undefined
            ? { afterActionId: query.afterActionId }
            : {}),
          ...(query.limit !== undefined ? { limit: query.limit } : {}),
        },
      );
      return sendEnvelope(
        request,
        reply,
        options,
        CommerceActionPageResponseSchema,
        data,
      );
    },
  );

  app.all(
    ROUTE_TEMPLATES["action_detail"] as string,
    { onRequest: browserRead("action_detail", false) },
    async (request, reply) => {
      const path = parseActionPath(rawRequestUrl(request));
      if (path.kind !== "action_detail") throw invalidRequest();
      const data = await options.service.getAction(
        requestContext(request, options.cookieNames),
        { organizationId: path.organizationId, actionId: path.actionId },
      );
      return sendEnvelope(
        request,
        reply,
        options,
        CommerceActionDetailResponseSchema,
        data,
      );
    },
  );

  app.all(
    ROUTE_TEMPLATES["approval_list"] as string,
    {
      onRequest: async (request) => {
        await browserRead("approval_list", true)(request);
        parseApprovalListQuery(rawRequestUrl(request));
      },
    },
    async (request, reply) => {
      const path = parseActionPath(rawRequestUrl(request));
      if (path.kind !== "approval_list") throw invalidRequest();
      const query = parseApprovalListQuery(rawRequestUrl(request));
      const data = await options.service.listApprovals(
        requestContext(request, options.cookieNames),
        {
          organizationId: path.organizationId,
          ...(query.afterApprovalId !== undefined
            ? { afterApprovalId: query.afterApprovalId }
            : {}),
          ...(query.limit !== undefined ? { limit: query.limit } : {}),
        },
      );
      return sendEnvelope(
        request,
        reply,
        options,
        CommerceApprovalPageResponseSchema,
        data,
      );
    },
  );

  app.all(
    ROUTE_TEMPLATES["approval_detail"] as string,
    { onRequest: browserRead("approval_detail", false) },
    async (request, reply) => {
      const path = parseActionPath(rawRequestUrl(request));
      if (path.kind !== "approval_detail") throw invalidRequest();
      const data = await options.service.getApproval(
        requestContext(request, options.cookieNames),
        { organizationId: path.organizationId, approvalId: path.approvalId },
      );
      return sendEnvelope(
        request,
        reply,
        options,
        CommerceApprovalDetailResponseSchema,
        data,
      );
    },
  );

  app.all(
    ROUTE_TEMPLATES["action_exposure"] as string,
    { onRequest: browserRead("action_exposure", false) },
    async (request, reply) => {
      const path = parseActionPath(rawRequestUrl(request));
      if (path.kind !== "action_exposure") throw invalidRequest();
      const data = await options.service.getExposure(
        requestContext(request, options.cookieNames),
        {
          organizationId: path.organizationId,
          subjectAgentId: path.subjectAgentId,
          policyId: path.policyId,
        },
      );
      return sendEnvelope(
        request,
        reply,
        options,
        CommerceExposureDataResponseSchema,
        data,
      );
    },
  );

  app.all(
    ROUTE_TEMPLATES["action_mutation_status"] as string,
    { onRequest: browserRead("action_mutation_status", false) },
    async (request, reply) => {
      const path = parseActionPath(rawRequestUrl(request));
      if (path.kind !== "action_mutation_status") throw invalidRequest();
      const data = await options.service.getHumanMutationStatus(
        requestContext(request, options.cookieNames),
        { organizationId: path.organizationId, mutationId: path.mutationId },
      );
      return sendEnvelope(
        request,
        reply,
        options,
        CommerceActionMutationStatusResponseSchema,
        data,
      );
    },
  );

  for (const decision of ["approve", "reject", "cancel"] as const) {
    const kind = `action_${decision}` as const;
    app.all(
      ROUTE_TEMPLATES[kind] as string,
      { onRequest: browserWrite(kind) },
      async (request, reply) => {
        const path = parseActionPath(rawRequestUrl(request));
        if (path.kind !== kind) throw invalidRequest();
        const ctx = requestContext(request, options.cookieNames);
        const envelope = {
          csrf: strictHeader(request.headers, "x-openarc-csrf"),
          idempotencyKey: strictHeader(request.headers, "idempotency-key"),
          body: request.body,
        };
        const data =
          decision === "approve"
            ? await options.service.approve(
                ctx,
                path.organizationId,
                path.actionId,
                envelope,
              )
            : decision === "reject"
              ? await options.service.reject(
                  ctx,
                  path.organizationId,
                  path.actionId,
                  envelope,
                )
              : await options.service.cancel(
                  ctx,
                  path.organizationId,
                  path.actionId,
                  envelope,
                );
        return sendEnvelope(
          request,
          reply,
          options,
          CommerceActionMutationDataResponseSchema,
          data,
        );
      },
    );
  }

  /* -- commerce_action_authorization (agent) -------------------------- */

  app.all(
    ROUTE_TEMPLATES["action_authorize"] as string,
    {
      onRequest: async (request) => {
        const path = parseActionPath(rawRequestUrl(request));
        if (path.kind !== "action_authorize") throw invalidRequest();
        enforceAgentWriteTransport(request);
      },
    },
    async (request, reply) => {
      const token = enforceAgentWriteTransport(request);
      const data = await options.service.authorize(token, request.ip, {
        idempotencyKey: strictHeader(request.headers, "idempotency-key"),
        body: request.body,
      });
      return sendEnvelope(
        request,
        reply,
        options,
        CommerceActionMutationDataResponseSchema,
        data,
      );
    },
  );

  app.all(
    ROUTE_TEMPLATES["agent_action_detail"] as string,
    {
      onRequest: async (request) => {
        const path = parseActionPath(rawRequestUrl(request));
        if (path.kind !== "agent_action_detail") throw invalidRequest();
        enforceAgentReadTransport(request);
      },
    },
    async (request, reply) => {
      const path = parseActionPath(rawRequestUrl(request));
      if (path.kind !== "agent_action_detail") throw invalidRequest();
      const token = enforceAgentReadTransport(request);
      const data = await options.service.getAgentAction(token, request.ip, {
        actionId: path.actionId,
      });
      return sendEnvelope(
        request,
        reply,
        options,
        CommerceActionDetailResponseSchema,
        data,
      );
    },
  );

  app.all(
    ROUTE_TEMPLATES["agent_action_mutation_status"] as string,
    {
      onRequest: async (request) => {
        const path = parseActionPath(rawRequestUrl(request));
        if (path.kind !== "agent_action_mutation_status") {
          throw invalidRequest();
        }
        enforceAgentReadTransport(request);
      },
    },
    async (request, reply) => {
      const path = parseActionPath(rawRequestUrl(request));
      if (path.kind !== "agent_action_mutation_status") throw invalidRequest();
      const token = enforceAgentReadTransport(request);
      const data = await options.service.getAgentMutationStatus(
        token,
        request.ip,
        { mutationId: path.mutationId },
      );
      return sendEnvelope(
        request,
        reply,
        options,
        CommerceActionMutationStatusResponseSchema,
        data,
      );
    },
  );
}
