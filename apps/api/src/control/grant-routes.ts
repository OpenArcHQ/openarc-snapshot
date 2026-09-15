import {
  API_CLIENT_HEADER,
  API_MAX_REQUEST_BYTES,
  API_MAX_RESPONSE_BYTES,
  COMMERCE_API_SCHEMA_VERSION,
  CommerceApiMetaSchema,
  CommerceGrantAgentMutationStatusResponseSchema,
  CommerceGrantAttemptIdSchema,
  CommerceGrantDetailResponseSchema,
  CommerceGrantHumanMutationStatusResponseSchema,
  CommerceGrantIdSchema,
  CommerceGrantIssueDataResponseSchema,
  CommerceGrantProviderAttemptStatusDataResponseSchema,
  CommerceGrantProviderClaimDataResponseSchema,
  CommerceGrantProviderIntrospectionResponseSchema,
  CommerceGrantReplaceDataResponseSchema,
  CommerceGrantRevokeDataResponseSchema,
  CommerceOrganizationIdSchema,
  CommerceTenantIdempotencyKeySchema,
  CommerceTenantMutationIdSchema,
  GRANT_ROUTES,
  type CommerceApiMeta,
} from "@openarc/shared";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { ZodType } from "zod";

import { AUTH_ERRORS, AuthApiError } from "../auth/errors.js";
import { parseAuthCookies, type AuthCookieNames } from "../auth/cookies.js";
import type { AuthRequestContext } from "../auth/service.js";
import { decodePathSegment } from "../tenant/routes.js";
import type { CommerceGrantService } from "./grant-service.js";

/**
 * Exact protected authorization-grant surface.
 *
 * NINE routes in three strictly separated frozen families, taken from the
 * accepted shared `GRANT_ROUTES` registry: three `commerce_grant_authorization`
 * AGENT routes, three `commerce_grant_claim` PROVIDER routes and three
 * `commerce_grant_management` BROWSER routes. No tenth route,
 * capability/manifest/health/fallback descriptor and no payment, settlement,
 * delivery or refund route is registered here.
 *
 * THREE disjoint credential classes, pinned to three disjoint path prefixes:
 *
 *   * browser (`/v2/control/organizations/`) is cookie-only with the exact
 *     browser marker, an exact configured Origin and CSRF on every write;
 *     `Authorization` and `Proxy-Authorization` are rejected outright, no
 *     response sets a cookie and there is no CORS grant;
 *   * agent (`/v2/agent/`) accepts exactly ONE
 *     `Authorization: Bearer oacs_v1_...` commerce-session token and rejects
 *     every cookie, Origin, Fetch-metadata, CSRF and proxy credential;
 *   * provider (`/v2/provider/grant`) accepts exactly ONE
 *     `Authorization: Bearer oas_pr_...` provider-session token with the same
 *     browser-header rejection, AND requires the buyer's one-use `oag_v1_`
 *     token in the BODY of the two claim-family POSTs. Neither factor alone
 *     authorizes anything: a provider session with no token cannot name a
 *     grant, and a token with no provider session is refused before any store
 *     work. A raw grant secret therefore never appears in a path, a query
 *     string, a log line or a referrer.
 *
 * No two families can authorize each other: a browser cookie is inert on agent
 * and provider routes, a commerce bearer is inert on browser and provider
 * routes, and a provider session is inert on agent and browser routes. The
 * provider prefix is deliberately `/v2/provider/grant...`, disjoint from the
 * browser-audience listing-management prefix `/v2/provider/organizations/`.
 *
 * Raw duplicate critical headers are rejected before body parsing. Every path
 * parameter is decoded exactly once from the bounded raw URL; unknown keywords,
 * extra segments, residual escapes and lookalikes fail closed. NO query string
 * is accepted anywhere on this surface — the accepted grant store exposes no
 * list or page method, so no cursor or limit exists — and a bare `?` is
 * rejected.
 *
 * Registration ALWAYS installs exactly these nine exact targets. While the
 * family is gated off every one of them answers with the accepted
 * `FEATURE_DISABLED` API error envelope BEFORE any service, store, limiter or
 * cookie work, so a static/SPA fallback can never capture an API path and turn
 * it into an HTML 200.
 */

export const GRANT_CONTROL_PREFIX = "/v2/control/organizations" as const;
export const GRANT_AGENT_GRANTS = "/v2/agent/commerce-grants" as const;
export const GRANT_AGENT_MUTATION_PREFIX =
  "/v2/agent/commerce-grant-mutations" as const;
export const GRANT_PROVIDER_GRANTS = "/v2/provider/grants" as const;
export const GRANT_PROVIDER_ATTEMPT_PREFIX =
  "/v2/provider/grant-attempts" as const;

const MAX_REQUEST_URL_BYTES = 2048;
const MAX_PATH_PARAM_BYTES = 512;
/** Exact body ceiling for the four grant writes and the read-only claim POST. */
export const GRANT_MAX_REQUEST_BYTES = API_MAX_REQUEST_BYTES;

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

/** Browser-only headers the headless (agent and provider) families reject. */
const HEADLESS_FORBIDDEN_HEADERS: readonly string[] = [
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

export interface CommerceGrantRoutesOptions {
  appOrigin: string;
  cookieNames: AuthCookieNames;
  service: CommerceGrantService;
  buildSha: string;
  enabled: boolean;
  maxResponseBytes?: number;
}

type ParsedGrantPath =
  | { readonly kind: "grant_issue" }
  | { readonly kind: "grant_replace"; readonly grantId: string }
  | {
      readonly kind: "agent_grant_mutation_status";
      readonly mutationId: string;
    }
  | { readonly kind: "provider_grant_introspect" }
  | { readonly kind: "provider_grant_claim" }
  | {
      readonly kind: "provider_grant_attempt_status";
      readonly attemptId: string;
    }
  | {
      readonly kind: "grant_detail";
      readonly organizationId: string;
      readonly grantId: string;
    }
  | {
      readonly kind: "grant_mutation_status";
      readonly organizationId: string;
      readonly mutationId: string;
    }
  | {
      readonly kind: "grant_revoke";
      readonly organizationId: string;
      readonly grantId: string;
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

/** The accepted fixed disabled error for a gated-off grant route. */
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
 * Exact decode-once matcher for the nine frozen path shapes. Every segment is
 * bound/control/escape checked, decoded exactly once and validated against the
 * accepted canonical id schema. Unknown keywords, extra segments and lookalike
 * targets fail closed.
 */
export function parseGrantPath(rawUrl: string): ParsedGrantPath {
  if (Buffer.byteLength(rawUrl, "utf8") > MAX_REQUEST_URL_BYTES) {
    throw invalidRequest();
  }
  if (hasControlCharacter(rawUrl)) throw invalidRequest();
  const path = rawPath(rawUrl);

  // Agent family first: its roots are exact and distinct from every other root.
  const agentMutationPrefix = `${GRANT_AGENT_MUTATION_PREFIX}/`;
  if (path.startsWith(agentMutationPrefix)) {
    const rest = path.slice(agentMutationPrefix.length).split("/");
    if (rest.length !== 1 || rest[0] === undefined || rest[0].length === 0) {
      throw invalidRequest();
    }
    return {
      kind: "agent_grant_mutation_status",
      mutationId: requireCanonical(
        CommerceTenantMutationIdSchema,
        decodeSegment(rest[0]),
      ),
    };
  }
  if (path === GRANT_AGENT_GRANTS) return { kind: "grant_issue" };
  const agentGrantPrefix = `${GRANT_AGENT_GRANTS}/`;
  if (path.startsWith(agentGrantPrefix)) {
    const rest = path.slice(agentGrantPrefix.length).split("/");
    if (
      rest.length !== 2 ||
      rest[0] === undefined ||
      rest[0].length === 0 ||
      rest[1] !== "replace"
    ) {
      throw invalidRequest();
    }
    return {
      kind: "grant_replace",
      grantId: requireCanonical(CommerceGrantIdSchema, decodeSegment(rest[0])),
    };
  }

  // Provider family. `/v2/provider/grants` and `/v2/provider/grant-attempts`
  // are both disjoint from the seller browser prefix `/v2/provider/organizations/`.
  const providerAttemptPrefix = `${GRANT_PROVIDER_ATTEMPT_PREFIX}/`;
  if (path.startsWith(providerAttemptPrefix)) {
    const rest = path.slice(providerAttemptPrefix.length).split("/");
    if (rest.length !== 1 || rest[0] === undefined || rest[0].length === 0) {
      throw invalidRequest();
    }
    return {
      kind: "provider_grant_attempt_status",
      attemptId: requireCanonical(
        CommerceGrantAttemptIdSchema,
        decodeSegment(rest[0]),
      ),
    };
  }
  if (path === `${GRANT_PROVIDER_GRANTS}/introspect`) {
    return { kind: "provider_grant_introspect" };
  }
  if (path === `${GRANT_PROVIDER_GRANTS}/claim`) {
    return { kind: "provider_grant_claim" };
  }
  if (path === GRANT_PROVIDER_GRANTS || path.startsWith(`${GRANT_PROVIDER_GRANTS}/`)) {
    // Any other target under the provider grant root is unknown, never a
    // lookalike that a live route could serve.
    throw invalidRequest();
  }

  const prefix = `${GRANT_CONTROL_PREFIX}/`;
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
  if (second === "grants") {
    if (segments.length < 3 || segments[2] === undefined) {
      throw invalidRequest();
    }
    const grantId = requireCanonical(
      CommerceGrantIdSchema,
      decodeSegment(segments[2]),
    );
    if (segments.length === 3) {
      return { kind: "grant_detail", organizationId, grantId };
    }
    if (segments.length === 4 && segments[3] === "revoke") {
      return { kind: "grant_revoke", organizationId, grantId };
    }
    throw invalidRequest();
  }
  if (second === "grant-mutations") {
    if (segments.length !== 3 || segments[2] === undefined) {
      throw invalidRequest();
    }
    return {
      kind: "grant_mutation_status",
      organizationId,
      mutationId: requireCanonical(
        CommerceTenantMutationIdSchema,
        decodeSegment(segments[2]),
      ),
    };
  }
  throw invalidRequest();
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
  options: CommerceGrantRoutesOptions,
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
  options: CommerceGrantRoutesOptions,
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
  options: CommerceGrantRoutesOptions,
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

/** Shared bounded content checks for every JSON body on this surface. */
function enforceJsonBody(request: FastifyRequest): void {
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
    if (Number(contentLength) > GRANT_MAX_REQUEST_BYTES) {
      throw AUTH_ERRORS.tooLarge();
    }
  }
}

/** A mutation body additionally requires the canonical idempotency key. */
function enforceMutationBody(request: FastifyRequest): void {
  enforceJsonBody(request);
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
  options: CommerceGrantRoutesOptions,
): void {
  enforceBrowserOrigin(request, options, false);
  if (request.method !== "POST") throw methodNotAllowed();
  if (rawRequestUrl(request).includes("?")) throw invalidRequest();
  enforceMutationBody(request);
  const csrf = strictHeader(request.headers, "x-openarc-csrf");
  if (typeof csrf !== "string" || csrf.length === 0) throw invalidRequest();
}

/**
 * Exactly ONE `Authorization: Bearer <prefixed 43 base64url>` headless token of
 * the requested namespace. The raw token is returned to the caller for hashing
 * and is never logged, echoed or persisted here.
 */
function headlessBearer(
  request: FastifyRequest,
  pattern: RegExp,
): string {
  const authorization = strictHeader(request.headers, "authorization");
  if (typeof authorization !== "string") throw AUTH_ERRORS.unauthenticated();
  const match = pattern.exec(authorization);
  if (match === null) throw AUTH_ERRORS.unauthenticated();
  return match[1] as string;
}

const AGENT_BEARER = /^Bearer (oacs_v1_[A-Za-z0-9_-]{43})(?![\s\S])/u;
const PROVIDER_BEARER = /^Bearer (oas_pr_[A-Za-z0-9_-]{43})(?![\s\S])/u;

function enforceHeadlessTransport(
  request: FastifyRequest,
  pattern: RegExp,
): string {
  enforceNoDuplicateCriticalHeaders(request);
  if (
    Buffer.byteLength(rawRequestUrl(request), "utf8") > MAX_REQUEST_URL_BYTES
  ) {
    throw invalidRequest();
  }
  // A browser cookie/CSRF/Origin can never reach a headless family.
  for (const name of HEADLESS_FORBIDDEN_HEADERS) {
    if (strictHeader(request.headers, name) !== undefined) {
      throw invalidRequest();
    }
  }
  return headlessBearer(request, pattern);
}

function enforceHeadlessReadTransport(
  request: FastifyRequest,
  pattern: RegExp,
): string {
  const token = enforceHeadlessTransport(request, pattern);
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

function enforceHeadlessWriteTransport(
  request: FastifyRequest,
  pattern: RegExp,
): string {
  const token = enforceHeadlessTransport(request, pattern);
  if (request.method !== "POST") throw methodNotAllowed();
  if (rawRequestUrl(request).includes("?")) throw invalidRequest();
  enforceMutationBody(request);
  return token;
}

/**
 * Provider introspection is a READ that must carry the one-use secret in a
 * body, so it is a POST with no idempotency key: it commits nothing, and
 * accepting a mutation key here would imply a replayable write.
 */
function enforceProviderReadPostTransport(request: FastifyRequest): string {
  const token = enforceHeadlessTransport(request, PROVIDER_BEARER);
  if (request.method !== "POST") throw methodNotAllowed();
  if (rawRequestUrl(request).includes("?")) throw invalidRequest();
  if (strictHeader(request.headers, "idempotency-key") !== undefined) {
    throw invalidRequest();
  }
  enforceJsonBody(request);
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
  options: CommerceGrantRoutesOptions,
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
  if (Buffer.byteLength(serialized, "utf8") > limit) {
    throw AUTH_ERRORS.internal();
  }
  return reply
    .type("application/json; charset=utf-8")
    .header("Cache-Control", "no-store")
    .send(serialized);
}

/** Route template for each frozen descriptor id, in the frozen order. */
const ROUTE_TEMPLATES: Readonly<Record<string, string>> = Object.freeze({
  grant_issue: GRANT_AGENT_GRANTS,
  grant_replace: `${GRANT_AGENT_GRANTS}/:grantId/replace`,
  agent_grant_mutation_status: `${GRANT_AGENT_MUTATION_PREFIX}/:mutationId`,
  provider_grant_introspect: `${GRANT_PROVIDER_GRANTS}/introspect`,
  provider_grant_claim: `${GRANT_PROVIDER_GRANTS}/claim`,
  provider_grant_attempt_status: `${GRANT_PROVIDER_ATTEMPT_PREFIX}/:attemptId`,
  grant_detail: `${GRANT_CONTROL_PREFIX}/:organizationId/grants/:grantId`,
  grant_mutation_status: `${GRANT_CONTROL_PREFIX}/:organizationId/grant-mutations/:mutationId`,
  grant_revoke: `${GRANT_CONTROL_PREFIX}/:organizationId/grants/:grantId/revoke`,
});

/**
 * The exact registered templates, derived from the frozen shared registry and
 * asserted against it. Drift in either direction fails closed at registration.
 */
export function grantRouteTemplates(): readonly {
  id: string;
  method: "GET" | "POST";
  path: string;
  audience: "browser" | "agent" | "provider";
}[] {
  return GRANT_ROUTES.map((route) => {
    const template = ROUTE_TEMPLATES[route.id];
    if (template === undefined || template !== route.path) {
      throw new Error("COMMERCE_GRANT_ROUTE_REGISTRY_DRIFT");
    }
    return {
      id: route.id,
      method: route.method,
      path: template,
      audience: route.audience,
    };
  });
}

export function registerCommerceGrantRoutes(
  app: FastifyInstance,
  options: CommerceGrantRoutesOptions,
): void {
  // The exact nine targets are ALWAYS installed. While gated off each one
  // answers the accepted disabled API error before any service/store/cookie
  // work, so no static or SPA fallback can answer an API path with HTML.
  const templates = grantRouteTemplates();
  if (!options.enabled) {
    for (const route of templates) {
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

  const expectPath = (
    request: FastifyRequest,
    expected: ParsedGrantPath["kind"],
  ): ParsedGrantPath => {
    const path = parseGrantPath(rawRequestUrl(request));
    if (path.kind !== expected) throw invalidRequest();
    // No grant route accepts a query string of any kind.
    if (rawRequestUrl(request).includes("?")) throw invalidRequest();
    return path;
  };

  /* -- commerce_grant_authorization (agent) --------------------------- */

  app.all(
    ROUTE_TEMPLATES["grant_issue"] as string,
    {
      onRequest: async (request) => {
        expectPath(request, "grant_issue");
        enforceHeadlessWriteTransport(request, AGENT_BEARER);
      },
    },
    async (request, reply) => {
      const token = enforceHeadlessWriteTransport(request, AGENT_BEARER);
      const data = await options.service.issue(token, request.ip, {
        idempotencyKey: strictHeader(request.headers, "idempotency-key"),
        body: request.body,
      });
      return sendEnvelope(
        request,
        reply,
        options,
        CommerceGrantIssueDataResponseSchema,
        data,
      );
    },
  );

  app.all(
    ROUTE_TEMPLATES["grant_replace"] as string,
    {
      onRequest: async (request) => {
        expectPath(request, "grant_replace");
        enforceHeadlessWriteTransport(request, AGENT_BEARER);
      },
    },
    async (request, reply) => {
      const path = expectPath(request, "grant_replace");
      if (path.kind !== "grant_replace") throw invalidRequest();
      const token = enforceHeadlessWriteTransport(request, AGENT_BEARER);
      const data = await options.service.replace(
        token,
        request.ip,
        path.grantId,
        {
          idempotencyKey: strictHeader(request.headers, "idempotency-key"),
          body: request.body,
        },
      );
      return sendEnvelope(
        request,
        reply,
        options,
        CommerceGrantReplaceDataResponseSchema,
        data,
      );
    },
  );

  app.all(
    ROUTE_TEMPLATES["agent_grant_mutation_status"] as string,
    {
      onRequest: async (request) => {
        expectPath(request, "agent_grant_mutation_status");
        enforceHeadlessReadTransport(request, AGENT_BEARER);
      },
    },
    async (request, reply) => {
      const path = expectPath(request, "agent_grant_mutation_status");
      if (path.kind !== "agent_grant_mutation_status") throw invalidRequest();
      const token = enforceHeadlessReadTransport(request, AGENT_BEARER);
      const data = await options.service.getAgentMutationStatus(
        token,
        request.ip,
        { mutationId: path.mutationId },
      );
      return sendEnvelope(
        request,
        reply,
        options,
        CommerceGrantAgentMutationStatusResponseSchema,
        data,
      );
    },
  );

  /* -- commerce_grant_claim (provider) -------------------------------- */

  app.all(
    ROUTE_TEMPLATES["provider_grant_introspect"] as string,
    {
      onRequest: async (request) => {
        expectPath(request, "provider_grant_introspect");
        enforceProviderReadPostTransport(request);
      },
    },
    async (request, reply) => {
      const token = enforceProviderReadPostTransport(request);
      const data = await options.service.introspect(token, request.ip, {
        body: request.body,
      });
      return sendEnvelope(
        request,
        reply,
        options,
        CommerceGrantProviderIntrospectionResponseSchema,
        data,
      );
    },
  );

  app.all(
    ROUTE_TEMPLATES["provider_grant_claim"] as string,
    {
      onRequest: async (request) => {
        expectPath(request, "provider_grant_claim");
        enforceHeadlessWriteTransport(request, PROVIDER_BEARER);
      },
    },
    async (request, reply) => {
      const token = enforceHeadlessWriteTransport(request, PROVIDER_BEARER);
      const data = await options.service.claim(token, request.ip, {
        idempotencyKey: strictHeader(request.headers, "idempotency-key"),
        body: request.body,
      });
      return sendEnvelope(
        request,
        reply,
        options,
        CommerceGrantProviderClaimDataResponseSchema,
        data,
      );
    },
  );

  app.all(
    ROUTE_TEMPLATES["provider_grant_attempt_status"] as string,
    {
      onRequest: async (request) => {
        expectPath(request, "provider_grant_attempt_status");
        enforceHeadlessReadTransport(request, PROVIDER_BEARER);
      },
    },
    async (request, reply) => {
      const path = expectPath(request, "provider_grant_attempt_status");
      if (path.kind !== "provider_grant_attempt_status") {
        throw invalidRequest();
      }
      const token = enforceHeadlessReadTransport(request, PROVIDER_BEARER);
      const data = await options.service.getProviderAttemptStatus(
        token,
        request.ip,
        { attemptId: path.attemptId },
      );
      return sendEnvelope(
        request,
        reply,
        options,
        CommerceGrantProviderAttemptStatusDataResponseSchema,
        data,
      );
    },
  );

  /* -- commerce_grant_management (browser) ---------------------------- */

  app.all(
    ROUTE_TEMPLATES["grant_detail"] as string,
    {
      onRequest: async (request) => {
        expectPath(request, "grant_detail");
        enforceBrowserReadTransport(request, options);
      },
    },
    async (request, reply) => {
      const path = expectPath(request, "grant_detail");
      if (path.kind !== "grant_detail") throw invalidRequest();
      const data = await options.service.getGrant(
        requestContext(request, options.cookieNames),
        { organizationId: path.organizationId, grantId: path.grantId },
      );
      return sendEnvelope(
        request,
        reply,
        options,
        CommerceGrantDetailResponseSchema,
        data,
      );
    },
  );

  app.all(
    ROUTE_TEMPLATES["grant_mutation_status"] as string,
    {
      onRequest: async (request) => {
        expectPath(request, "grant_mutation_status");
        enforceBrowserReadTransport(request, options);
      },
    },
    async (request, reply) => {
      const path = expectPath(request, "grant_mutation_status");
      if (path.kind !== "grant_mutation_status") throw invalidRequest();
      const data = await options.service.getHumanMutationStatus(
        requestContext(request, options.cookieNames),
        { organizationId: path.organizationId, mutationId: path.mutationId },
      );
      return sendEnvelope(
        request,
        reply,
        options,
        CommerceGrantHumanMutationStatusResponseSchema,
        data,
      );
    },
  );

  app.all(
    ROUTE_TEMPLATES["grant_revoke"] as string,
    {
      onRequest: async (request) => {
        expectPath(request, "grant_revoke");
        enforceBrowserWriteTransport(request, options);
      },
    },
    async (request, reply) => {
      const path = expectPath(request, "grant_revoke");
      if (path.kind !== "grant_revoke") throw invalidRequest();
      const data = await options.service.revoke(
        requestContext(request, options.cookieNames),
        path.organizationId,
        path.grantId,
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
        CommerceGrantRevokeDataResponseSchema,
        data,
      );
    },
  );
}
