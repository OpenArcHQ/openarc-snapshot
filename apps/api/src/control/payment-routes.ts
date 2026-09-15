import {
  API_CLIENT_HEADER,
  API_MAX_REQUEST_BYTES,
  API_MAX_RESPONSE_BYTES,
  COMMERCE_API_SCHEMA_VERSION,
  CommerceApiMetaSchema,
  CommerceGrantAttemptIdSchema,
  CommerceListingIdSchema,
  CommerceListingVersionSchema,
  CommerceOrganizationIdSchema,
  CommercePaymentAttemptDispatchDataResponseSchema,
  CommercePaymentAttemptPersistDataResponseSchema,
  CommercePaymentAttemptReadDataResponseSchema,
  CommercePaymentRequirementResponseSchema,
  CommercePaymentTermsDataResponseSchema,
  CommerceTenantIdempotencyKeySchema,
  PAYMENT_ROUTES,
  type CommerceApiMeta,
} from "@openarc/shared";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { ZodType } from "zod";

import { AUTH_ERRORS, AuthApiError } from "../auth/errors.js";
import { parseAuthCookies, type AuthCookieNames } from "../auth/cookies.js";
import type { AuthRequestContext } from "../auth/service.js";
import { decodePathSegment } from "../tenant/routes.js";
import type { CommercePaymentService } from "./payment-service.js";

/**
 * Exact protected migration-0015 payment surface.
 *
 * FIVE routes in two strictly separated frozen families, taken from the shared
 * `PAYMENT_ROUTES` registry: one `commerce_payment_terms` BROWSER route and four
 * `commerce_payment_attempt` AGENT routes. There is NO observation route (the
 * recorder is migrator-private), no settlement, release or refund route and no
 * capability/health/fallback descriptor here.
 *
 * TWO disjoint credential classes:
 *
 *   * browser (`/v2/provider/organizations/.../payment-terms`) is cookie-only
 *     with the exact browser marker, an exact configured Origin, CSRF and an
 *     Idempotency-Key; `Authorization` and `Proxy-Authorization` are rejected
 *     outright;
 *   * agent (`/v2/agent/commerce-payment-...`) accepts exactly ONE
 *     `Authorization: Bearer oacs_v1_...` commerce-session token and rejects
 *     every cookie, Origin, Fetch-metadata, CSRF and proxy credential. An
 *     `oas_ag_` machine credential and an `oas_pr_` provider session are
 *     refused. The agent writes carry their own canonical ids (requirement id,
 *     attempt id) as the natural replay key, so an Idempotency-Key header is
 *     rejected rather than silently ignored.
 *
 * Raw duplicate critical headers are rejected before body parsing; every path
 * parameter is decoded exactly once and validated; no query string is accepted
 * anywhere. Registration ALWAYS installs exactly these five targets; while the
 * family is gated off each answers `FEATURE_DISABLED` before any service,
 * store, limiter or cookie work.
 */

export const PAYMENT_AGENT_REQUIREMENTS =
  "/v2/agent/commerce-payment-requirements" as const;
export const PAYMENT_AGENT_ATTEMPTS = "/v2/agent/commerce-payment-attempts" as const;
export const PAYMENT_PROVIDER_PREFIX = "/v2/provider/organizations" as const;

const MAX_REQUEST_URL_BYTES = 2048;
const MAX_PATH_PARAM_BYTES = 512;
export const PAYMENT_MAX_REQUEST_BYTES = API_MAX_REQUEST_BYTES;

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

export interface CommercePaymentRoutesOptions {
  appOrigin: string;
  cookieNames: AuthCookieNames;
  service: CommercePaymentService;
  buildSha: string;
  enabled: boolean;
  maxResponseBytes?: number;
}

type ParsedPaymentPath =
  | { readonly kind: "listing_payment_terms_record"; readonly organizationId: string; readonly listingId: string; readonly version: string }
  | { readonly kind: "payment_requirement_register" }
  | { readonly kind: "payment_attempt_persist" }
  | { readonly kind: "payment_attempt_dispatch"; readonly attemptId: string }
  | { readonly kind: "payment_attempt_detail"; readonly attemptId: string };

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
 * Exact decode-once matcher for the five frozen path shapes. Unknown keywords,
 * extra segments and lookalike targets fail closed.
 */
export function parsePaymentPath(rawUrl: string): ParsedPaymentPath {
  if (Buffer.byteLength(rawUrl, "utf8") > MAX_REQUEST_URL_BYTES) {
    throw invalidRequest();
  }
  if (hasControlCharacter(rawUrl)) throw invalidRequest();
  const path = rawPath(rawUrl);

  if (path === PAYMENT_AGENT_REQUIREMENTS) {
    return { kind: "payment_requirement_register" };
  }
  if (path === PAYMENT_AGENT_ATTEMPTS) return { kind: "payment_attempt_persist" };
  const attemptPrefix = `${PAYMENT_AGENT_ATTEMPTS}/`;
  if (path.startsWith(attemptPrefix)) {
    const rest = path.slice(attemptPrefix.length).split("/");
    if (rest[0] === undefined || rest[0].length === 0) throw invalidRequest();
    const attemptId = requireCanonical(
      CommerceGrantAttemptIdSchema,
      decodeSegment(rest[0]),
    );
    if (rest.length === 1) return { kind: "payment_attempt_detail", attemptId };
    if (rest.length === 2 && rest[1] === "dispatch") {
      return { kind: "payment_attempt_dispatch", attemptId };
    }
    throw invalidRequest();
  }

  const providerPrefix = `${PAYMENT_PROVIDER_PREFIX}/`;
  if (!path.startsWith(providerPrefix)) throw invalidRequest();
  const segments = path.slice(providerPrefix.length).split("/");
  if (
    segments.length !== 6 ||
    segments.some((segment) => segment.length === 0) ||
    segments[1] !== "listings" ||
    segments[3] !== "versions" ||
    segments[5] !== "payment-terms"
  ) {
    throw invalidRequest();
  }
  return {
    kind: "listing_payment_terms_record",
    organizationId: requireCanonical(
      CommerceOrganizationIdSchema,
      decodeSegment(segments[0] as string),
    ),
    listingId: requireCanonical(
      CommerceListingIdSchema,
      decodeSegment(segments[2] as string),
    ),
    version: requireCanonical(
      CommerceListingVersionSchema,
      decodeSegment(segments[4] as string),
    ),
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
    if (Number(contentLength) > PAYMENT_MAX_REQUEST_BYTES) {
      throw AUTH_ERRORS.tooLarge();
    }
  }
}

function enforceBrowserWriteTransport(
  request: FastifyRequest,
  options: CommercePaymentRoutesOptions,
): void {
  enforceNoDuplicateCriticalHeaders(request);
  if (Buffer.byteLength(rawRequestUrl(request), "utf8") > MAX_REQUEST_URL_BYTES) {
    throw invalidRequest();
  }
  // No bearer of any namespace can reach the browser family.
  if (strictHeader(request.headers, "authorization") !== undefined) {
    throw invalidRequest();
  }
  if (strictHeader(request.headers, "proxy-authorization") !== undefined) {
    throw invalidRequest();
  }
  if (strictHeader(request.headers, "x-openarc-client") !== API_CLIENT_HEADER) {
    throw originRejected();
  }
  const origin = strictHeader(request.headers, "origin");
  const site = strictHeader(request.headers, "sec-fetch-site");
  const mode = strictHeader(request.headers, "sec-fetch-mode");
  const destination = strictHeader(request.headers, "sec-fetch-dest");
  if (origin !== options.appOrigin) throw originRejected();
  if (site !== undefined && site !== "same-origin") throw originRejected();
  if (mode !== undefined && mode !== "cors" && mode !== "same-origin") {
    throw originRejected();
  }
  if (destination !== undefined && destination !== "empty") {
    throw originRejected();
  }
  if (request.method !== "POST") throw methodNotAllowed();
  if (rawRequestUrl(request).includes("?")) throw invalidRequest();
  enforceJsonBody(request);
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

const AGENT_BEARER = /^Bearer (oacs_v1_[A-Za-z0-9_-]{43})(?![\s\S])/u;

function enforceAgentTransport(request: FastifyRequest): string {
  enforceNoDuplicateCriticalHeaders(request);
  if (Buffer.byteLength(rawRequestUrl(request), "utf8") > MAX_REQUEST_URL_BYTES) {
    throw invalidRequest();
  }
  for (const name of HEADLESS_FORBIDDEN_HEADERS) {
    if (strictHeader(request.headers, name) !== undefined) {
      throw invalidRequest();
    }
  }
  const authorization = strictHeader(request.headers, "authorization");
  if (typeof authorization !== "string") throw AUTH_ERRORS.unauthenticated();
  const match = AGENT_BEARER.exec(authorization);
  if (match === null) throw AUTH_ERRORS.unauthenticated();
  return match[1] as string;
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
  options: CommercePaymentRoutesOptions,
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

const ROUTE_TEMPLATES: Readonly<Record<string, string>> = Object.freeze({
  listing_payment_terms_record: `${PAYMENT_PROVIDER_PREFIX}/:organizationId/listings/:listingId/versions/:version/payment-terms`,
  payment_requirement_register: PAYMENT_AGENT_REQUIREMENTS,
  payment_attempt_persist: PAYMENT_AGENT_ATTEMPTS,
  payment_attempt_dispatch: `${PAYMENT_AGENT_ATTEMPTS}/:attemptId/dispatch`,
  payment_attempt_detail: `${PAYMENT_AGENT_ATTEMPTS}/:attemptId`,
});

/** Registered templates derived from, and asserted against, the registry. */
export function paymentRouteTemplates(): readonly {
  id: string;
  method: "GET" | "POST";
  path: string;
  audience: "browser" | "agent";
}[] {
  return PAYMENT_ROUTES.map((route) => {
    const template = ROUTE_TEMPLATES[route.id];
    if (template === undefined || template !== route.path) {
      throw new Error("COMMERCE_PAYMENT_ROUTE_REGISTRY_DRIFT");
    }
    return {
      id: route.id,
      method: route.method,
      path: template,
      audience: route.audience,
    };
  });
}

export function registerCommercePaymentRoutes(
  app: FastifyInstance,
  options: CommercePaymentRoutesOptions,
): void {
  const templates = paymentRouteTemplates();
  if (!options.enabled) {
    for (const route of templates) {
      app.all(
        route.path,
        {
          onRequest: async () => {
            throw AUTH_ERRORS.featureDisabled();
          },
        },
        async () => undefined,
      );
    }
    return;
  }

  const expectPath = <K extends ParsedPaymentPath["kind"]>(
    request: FastifyRequest,
    expected: K,
  ): Extract<ParsedPaymentPath, { kind: K }> => {
    const path = parsePaymentPath(rawRequestUrl(request));
    if (path.kind !== expected) throw invalidRequest();
    if (rawRequestUrl(request).includes("?")) throw invalidRequest();
    return path as Extract<ParsedPaymentPath, { kind: K }>;
  };

  /* -- commerce_payment_terms (browser) ------------------------------- */

  app.all(
    ROUTE_TEMPLATES["listing_payment_terms_record"] as string,
    {
      onRequest: async (request) => {
        expectPath(request, "listing_payment_terms_record");
        enforceBrowserWriteTransport(request, options);
      },
    },
    async (request, reply) => {
      const path = expectPath(request, "listing_payment_terms_record");
      const data = await options.service.recordListingPaymentTerms(
        requestContext(request, options.cookieNames),
        path.organizationId,
        path.listingId,
        path.version,
        {
          csrf: strictHeader(request.headers, "x-openarc-csrf"),
          idempotencyKey: strictHeader(request.headers, "idempotency-key"),
          body: request.body,
        },
      );
      return sendEnvelope(request, reply, options, CommercePaymentTermsDataResponseSchema, data);
    },
  );

  /* -- commerce_payment_attempt (agent) ------------------------------- */

  app.all(
    ROUTE_TEMPLATES["payment_requirement_register"] as string,
    {
      onRequest: async (request) => {
        expectPath(request, "payment_requirement_register");
        enforceAgentWriteTransport(request);
      },
    },
    async (request, reply) => {
      const token = enforceAgentWriteTransport(request);
      const data = await options.service.registerRequirement(token, request.ip, {
        body: request.body,
      });
      return sendEnvelope(request, reply, options, CommercePaymentRequirementResponseSchema, data);
    },
  );

  app.all(
    ROUTE_TEMPLATES["payment_attempt_persist"] as string,
    {
      onRequest: async (request) => {
        expectPath(request, "payment_attempt_persist");
        enforceAgentWriteTransport(request);
      },
    },
    async (request, reply) => {
      const token = enforceAgentWriteTransport(request);
      const data = await options.service.persistAttempt(token, request.ip, {
        body: request.body,
      });
      return sendEnvelope(request, reply, options, CommercePaymentAttemptPersistDataResponseSchema, data);
    },
  );

  app.all(
    ROUTE_TEMPLATES["payment_attempt_dispatch"] as string,
    {
      onRequest: async (request) => {
        expectPath(request, "payment_attempt_dispatch");
        enforceAgentWriteTransport(request);
      },
    },
    async (request, reply) => {
      const path = expectPath(request, "payment_attempt_dispatch");
      const token = enforceAgentWriteTransport(request);
      const data = await options.service.dispatchAttempt(
        token,
        request.ip,
        path.attemptId,
        { body: request.body },
      );
      return sendEnvelope(request, reply, options, CommercePaymentAttemptDispatchDataResponseSchema, data);
    },
  );

  app.all(
    ROUTE_TEMPLATES["payment_attempt_detail"] as string,
    {
      onRequest: async (request) => {
        expectPath(request, "payment_attempt_detail");
        enforceAgentReadTransport(request);
      },
    },
    async (request, reply) => {
      const path = expectPath(request, "payment_attempt_detail");
      const token = enforceAgentReadTransport(request);
      const data = await options.service.getAttempt(token, request.ip, {
        attemptId: path.attemptId,
      });
      return sendEnvelope(request, reply, options, CommercePaymentAttemptReadDataResponseSchema, data);
    },
  );
}
