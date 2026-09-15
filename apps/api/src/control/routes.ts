import {
  API_CLIENT_HEADER,
  API_MAX_RESPONSE_BYTES,
  COMMERCE_API_SCHEMA_VERSION,
  CommerceApiMetaSchema,
  CommerceOrganizationIdSchema,
  CommercePolicyIdSchema,
  CommercePolicyRevisionNumberSchema,
  CommercePolicyHistoryPageResponseSchema,
  CommercePolicyMutationResultResponseSchema,
  CommercePolicyMutationStatusResponseSchema,
  CommercePolicyRevisionDetailResponseSchema,
  CommercePolicyRootDetailResponseSchema,
  CommercePolicyRootPageResponseSchema,
  CommerceTenantIdempotencyKeySchema,
  CommerceTenantMutationIdSchema,
  CONTROL_ROUTES,
  type CommerceApiMeta,
} from "@openarc/shared";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { ZodType } from "zod";

import { AUTH_ERRORS, AuthApiError } from "../auth/errors.js";
import { parseAuthCookies, type AuthCookieNames } from "../auth/cookies.js";
import type { AuthRequestContext } from "../auth/service.js";
import { decodePathSegment } from "../tenant/routes.js";
import type { PolicyService } from "./service.js";

/**
 * Exact protected control policy management surface.
 *
 * Ten routes only, under `/v2/control/organizations/:organizationId`, taken
 * verbatim from the accepted shared `CONTROL_ROUTES` registry:
 *   GET  /policies
 *   POST /policies
 *   GET  /policies/:policyId
 *   GET  /policies/:policyId/revisions
 *   POST /policies/:policyId/revisions
 *   GET  /policies/:policyId/revisions/:revision
 *   POST /policies/:policyId/pause
 *   POST /policies/:policyId/resume
 *   POST /policies/:policyId/revoke
 *   GET  /policy-mutations/:mutationId
 *
 * Transport is cookie-only human auth with the exact browser marker. A POST
 * requires the exact configured Origin; a GET may omit Origin ONLY when
 * `Sec-Fetch-Site: same-origin`, while any supplied foreign Origin is denied.
 * `Authorization` and `Proxy-Authorization` are rejected, unexpected credential
 * metadata fails closed, and a raw duplicate critical header scan runs before
 * framework normalization. The path is parsed exactly once from the bounded raw
 * URL; residual escapes, separators, controls, extra segments and lookalikes
 * fail closed. No response on this surface can set a cookie and there is no
 * CORS grant. The default-disabled registration installs NO route.
 */

export const CONTROL_ROUTE_PREFIX = "/v2/control/organizations" as const;

export type ControlRouteId =
  | "policy_roots"
  | "policy_create"
  | "policy_root"
  | "policy_revisions"
  | "policy_revision_create"
  | "policy_revision"
  | "policy_pause"
  | "policy_resume"
  | "policy_revoke"
  | "policy_mutation_status";

/**
 * The ten exact control-route templates, keyed by the accepted frozen registry
 * id. The paths are copied from the shared `CONTROL_ROUTES` inventory (not
 * re-derived by string concatenation) so drift is impossible.
 */
export const CONTROL_ROUTE_REGISTRY: Readonly<Record<ControlRouteId, string>> =
  Object.freeze(
    Object.fromEntries(
      CONTROL_ROUTES.map((route) => [route.id, route.path]),
    ) as Record<ControlRouteId, string>,
  );

const MAX_REQUEST_URL_BYTES = 2048;
const MAX_PATH_PARAM_BYTES = 512;
const CANONICAL_LIMIT = /^(?:[1-9]|[1-4][0-9]|50)$/u;
const ENCODED_CHARACTER = /^(?:[^%\s]|%[0-9A-Fa-f]{2})*$/u;

/**
 * Critical security headers whose wire occurrence count must be at most one.
 * `request.raw.rawHeaders` is authoritative because Node may collapse some
 * duplicates (notably Content-Type) in the normalized header map.
 */
const CRITICAL_HEADER_NAMES: ReadonlySet<string> = new Set([
  "origin",
  "x-openarc-client",
  "sec-fetch-site",
  "sec-fetch-mode",
  "sec-fetch-dest",
  "authorization",
  "proxy-authorization",
  "cookie",
  "content-type",
  "content-length",
  "transfer-encoding",
  "idempotency-key",
  "x-openarc-csrf",
]);

export interface PolicyRoutesOptions {
  appOrigin: string;
  cookieNames: AuthCookieNames;
  service: PolicyService;
  buildSha: string;
  enabled: boolean;
  maxResponseBytes?: number;
}

type ParsedPolicyPath =
  | { readonly kind: "roots"; readonly organizationId: string }
  | {
      readonly kind: "root";
      readonly organizationId: string;
      readonly policyId: string;
    }
  | {
      readonly kind: "revisions";
      readonly organizationId: string;
      readonly policyId: string;
    }
  | {
      readonly kind: "revision";
      readonly organizationId: string;
      readonly policyId: string;
      readonly revision: string;
    }
  | {
      readonly kind: "transition";
      readonly organizationId: string;
      readonly policyId: string;
      readonly transition: "pause" | "resume" | "revoke";
    }
  | {
      readonly kind: "mutation";
      readonly organizationId: string;
      readonly mutationId: string;
    };

interface PolicyQuery {
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

/**
 * True when an exact request target is unacceptable for a write/query-free
 * route: over the URL byte bound or carrying ANY query, including a bare `?`.
 * Exported so the bare-`?` rule can be tested directly (some HTTP injectors
 * normalize an empty query away on the wire, while a real request target
 * preserves it).
 */
export function isForbiddenRequestTarget(url: string): boolean {
  return (
    Buffer.byteLength(url, "utf8") > MAX_REQUEST_URL_BYTES || url.includes("?")
  );
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

/**
 * Exact decode-once matcher for the six frozen control path shapes. Every
 * segment is bound/control/escape checked, decoded exactly once, and validated
 * against the accepted canonical id schema. Unknown keywords, extra segments
 * and separators fail closed.
 */
function parsePolicyPath(rawUrl: string): ParsedPolicyPath {
  if (Buffer.byteLength(rawUrl, "utf8") > MAX_REQUEST_URL_BYTES) {
    throw invalidRequest();
  }
  if (hasControlCharacter(rawUrl)) throw invalidRequest();
  const queryIndex = rawUrl.indexOf("?");
  const path = queryIndex === -1 ? rawUrl : rawUrl.slice(0, queryIndex);
  const prefix = `${CONTROL_ROUTE_PREFIX}/`;
  if (!path.startsWith(prefix)) throw invalidRequest();
  const segments = path.slice(prefix.length).split("/");
  for (const segment of segments) {
    if (segment.length === 0) throw invalidRequest();
  }
  const organizationId = requireCanonical(
    CommerceOrganizationIdSchema,
    decodePathSegment(segments[0] as string, MAX_PATH_PARAM_BYTES),
  );
  const second = segments[1];
  if (second === "policies") {
    if (segments.length === 2) return { kind: "roots", organizationId };
    if (segments[2] === undefined) throw invalidRequest();
    const policyId = requireCanonical(
      CommercePolicyIdSchema,
      decodePathSegment(segments[2], MAX_PATH_PARAM_BYTES),
    );
    if (segments.length === 3) return { kind: "root", organizationId, policyId };
    if (segments[3] === "revisions") {
      if (segments.length === 4) {
        return { kind: "revisions", organizationId, policyId };
      }
      if (segments.length === 5 && segments[4] !== undefined) {
        const revision = requireCanonical(
          CommercePolicyRevisionNumberSchema,
          decodePathSegment(segments[4], MAX_PATH_PARAM_BYTES),
        );
        return { kind: "revision", organizationId, policyId, revision };
      }
      throw invalidRequest();
    }
    if (segments.length !== 4) throw invalidRequest();
    if (segments[3] === "pause" || segments[3] === "resume" || segments[3] === "revoke") {
      return { kind: "transition", organizationId, policyId, transition: segments[3] };
    }
    throw invalidRequest();
  }
  if (second === "policy-mutations") {
    if (segments.length !== 3 || segments[2] === undefined) throw invalidRequest();
    const mutationId = requireCanonical(
      CommerceTenantMutationIdSchema,
      decodePathSegment(segments[2], MAX_PATH_PARAM_BYTES),
    );
    return { kind: "mutation", organizationId, mutationId };
  }
  throw invalidRequest();
}

/**
 * Parse a bounded raw query string. Invalid percent-encoding, empty
 * keys/values, duplicate keys, unknown keys and control characters fail closed;
 * an empty or absent value is never coerced into a default.
 */
function parseQuery(
  url: string,
  allowedKeys: readonly string[],
  requireNoQuery: boolean,
): PolicyQuery {
  const queryIndex = url.indexOf("?");
  if (queryIndex === -1) return { value: new Map() };
  if (requireNoQuery) throw invalidRequest();
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
  return { value: result };
}

function parseLimit(query: PolicyQuery): string | undefined {
  const raw = query.value.get("limit");
  if (raw === undefined) return undefined;
  if (!CANONICAL_LIMIT.test(raw)) throw invalidRequest();
  return raw;
}

function parseOptionalCursor(
  query: PolicyQuery,
  key: string,
  schema: ZodType,
): string | undefined {
  const raw = query.value.get(key);
  if (raw === undefined) return undefined;
  if (!schema.safeParse(raw).success) throw invalidRequest();
  return raw;
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
  options: PolicyRoutesOptions,
  allowOriginless: boolean,
): void {
  const origin = strictHeader(request.headers, "origin");
  const site = strictHeader(request.headers, "sec-fetch-site");
  const mode = strictHeader(request.headers, "sec-fetch-mode");
  const destination = strictHeader(request.headers, "sec-fetch-dest");
  if (origin === options.appOrigin) {
    // exact same-origin request
  } else if (allowOriginless && origin === undefined && site === "same-origin") {
    // originless read ONLY with an explicit same-origin fetch site
  } else {
    throw originRejected();
  }
  if (site !== undefined && site !== "same-origin") throw originRejected();
  if (mode !== undefined && mode !== "cors" && mode !== "same-origin") {
    throw originRejected();
  }
  if (destination !== undefined && destination !== "empty") throw originRejected();
}

function enforceReadTransport(
  request: FastifyRequest,
  options: PolicyRoutesOptions,
): void {
  enforceNoDuplicateCriticalHeaders(request);
  const url = rawRequestUrl(request);
  if (Buffer.byteLength(url, "utf8") > MAX_REQUEST_URL_BYTES) throw invalidRequest();
  if (request.method !== "GET") throw methodNotAllowed();
  if (strictHeader(request.headers, "authorization") !== undefined) {
    throw invalidRequest();
  }
  if (strictHeader(request.headers, "proxy-authorization") !== undefined) {
    throw invalidRequest();
  }
  if (strictHeader(request.headers, "x-openarc-client") !== API_CLIENT_HEADER) {
    throw originRejected();
  }
  enforceFetchMetadata(request, options, true);
  if (strictHeader(request.headers, "idempotency-key") !== undefined) {
    throw invalidRequest();
  }
  if (strictHeader(request.headers, "x-openarc-csrf") !== undefined) {
    throw invalidRequest();
  }
  const contentLength = strictHeader(request.headers, "content-length");
  if (contentLength !== undefined && contentLength !== "0") throw invalidRequest();
  if (strictHeader(request.headers, "transfer-encoding") !== undefined) {
    throw invalidRequest();
  }
}

function enforceWriteTransport(
  request: FastifyRequest,
  options: PolicyRoutesOptions,
): void {
  enforceNoDuplicateCriticalHeaders(request);
  const url = rawRequestUrl(request);
  if (isForbiddenRequestTarget(url)) throw invalidRequest();
  if (request.method !== "POST") throw methodNotAllowed();
  if (strictHeader(request.headers, "authorization") !== undefined) {
    throw invalidRequest();
  }
  if (strictHeader(request.headers, "proxy-authorization") !== undefined) {
    throw invalidRequest();
  }
  if (strictHeader(request.headers, "x-openarc-client") !== API_CLIENT_HEADER) {
    throw originRejected();
  }
  enforceFetchMetadata(request, options, false);
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
    (typeof contentLength !== "string" ||
      !/^(?:0|[1-9][0-9]*)$/u.test(contentLength))
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
  options: PolicyRoutesOptions,
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
  return reply.type("application/json; charset=utf-8").send(serialized);
}

export function registerPolicyRoutes(
  app: FastifyInstance,
  options: PolicyRoutesOptions,
): void {
  if (!options.enabled) {
    // Default-off: register NOTHING. A request yields the framework's ordinary
    // 404 rather than a simulated disabled-route response.
    return;
  }

  const dispatch = (
    request: FastifyRequest,
    reply: FastifyReply,
    expected: ParsedPolicyPath["kind"],
  ): Promise<FastifyReply> => {
    const path = parsePolicyPath(rawRequestUrl(request));
    if (path.kind !== expected) throw invalidRequest();

    if (path.kind === "roots") {
      if (request.method === "GET") {
        const query = parseQuery(
          rawRequestUrl(request),
          ["afterPolicyId", "limit"],
          false,
        );
        const afterPolicyId = parseOptionalCursor(
          query,
          "afterPolicyId",
          CommercePolicyIdSchema,
        );
        const limit = parseLimit(query);
        return options.service
          .listPolicyRoots(requestContext(request, options.cookieNames), {
            organizationId: path.organizationId,
            ...(afterPolicyId !== undefined ? { afterPolicyId } : {}),
            ...(limit !== undefined ? { limit } : {}),
          })
          .then((data) =>
            sendEnvelope(
              request,
              reply,
              options,
              CommercePolicyRootPageResponseSchema,
              data,
            ),
          );
      }
      return options.service
        .createPolicy(
          requestContext(request, options.cookieNames),
          path.organizationId,
          {
            csrf: strictHeader(request.headers, "x-openarc-csrf"),
            idempotencyKey: strictHeader(request.headers, "idempotency-key"),
            body: request.body,
          },
        )
        .then((data) =>
          sendEnvelope(
            request,
            reply,
            options,
            CommercePolicyMutationResultResponseSchema,
            data,
          ),
        );
    }

    if (path.kind === "root") {
      if (isForbiddenRequestTarget(rawRequestUrl(request))) throw invalidRequest();
      return options.service
        .getPolicyRoot(requestContext(request, options.cookieNames), {
          organizationId: path.organizationId,
          policyId: path.policyId,
        })
        .then((data) =>
          sendEnvelope(
            request,
            reply,
            options,
            CommercePolicyRootDetailResponseSchema,
            data,
          ),
        );
    }

    if (path.kind === "revisions") {
      if (request.method === "GET") {
        const query = parseQuery(
          rawRequestUrl(request),
          ["afterRevision", "limit"],
          false,
        );
        const afterRevision = parseOptionalCursor(
          query,
          "afterRevision",
          CommercePolicyRevisionNumberSchema,
        );
        const limit = parseLimit(query);
        return options.service
          .listPolicyRevisions(requestContext(request, options.cookieNames), {
            organizationId: path.organizationId,
            policyId: path.policyId,
            ...(afterRevision !== undefined ? { afterRevision } : {}),
            ...(limit !== undefined ? { limit } : {}),
          })
          .then((data) =>
            sendEnvelope(
              request,
              reply,
              options,
              CommercePolicyHistoryPageResponseSchema,
              data,
            ),
          );
      }
      return options.service
        .appendPolicyRevision(
          requestContext(request, options.cookieNames),
          path.organizationId,
          path.policyId,
          {
            csrf: strictHeader(request.headers, "x-openarc-csrf"),
            idempotencyKey: strictHeader(request.headers, "idempotency-key"),
            body: request.body,
          },
        )
        .then((data) =>
          sendEnvelope(
            request,
            reply,
            options,
            CommercePolicyMutationResultResponseSchema,
            data,
          ),
        );
    }

    if (path.kind === "revision") {
      if (isForbiddenRequestTarget(rawRequestUrl(request))) throw invalidRequest();
      return options.service
        .getPolicyRevision(requestContext(request, options.cookieNames), {
          organizationId: path.organizationId,
          policyId: path.policyId,
          revision: path.revision,
        })
        .then((data) =>
          sendEnvelope(
            request,
            reply,
            options,
            CommercePolicyRevisionDetailResponseSchema,
            data,
          ),
        );
    }

    if (path.kind === "transition") {
      if (isForbiddenRequestTarget(rawRequestUrl(request))) throw invalidRequest();
      const ctx = requestContext(request, options.cookieNames);
      const envelope = {
        csrf: strictHeader(request.headers, "x-openarc-csrf"),
        idempotencyKey: strictHeader(request.headers, "idempotency-key"),
        body: request.body,
      };
      const transition =
        path.transition === "pause"
          ? options.service.pausePolicy(
              ctx,
              path.organizationId,
              path.policyId,
              envelope,
            )
          : path.transition === "resume"
            ? options.service.resumePolicy(
                ctx,
                path.organizationId,
                path.policyId,
                envelope,
              )
            : options.service.revokePolicy(
                ctx,
                path.organizationId,
                path.policyId,
                envelope,
              );
      return transition.then((data) =>
          sendEnvelope(
            request,
            reply,
            options,
            CommercePolicyMutationResultResponseSchema,
            data,
          ),
        );
    }

    if (isForbiddenRequestTarget(rawRequestUrl(request))) throw invalidRequest();
    return options.service
      .getPolicyMutationStatus(requestContext(request, options.cookieNames), {
        organizationId: path.organizationId,
        mutationId: path.mutationId,
      })
      .then((data) =>
        sendEnvelope(
          request,
          reply,
          options,
          CommercePolicyMutationStatusResponseSchema,
          data,
        ),
      );
  };

  const register = (
    descriptor: (typeof CONTROL_ROUTES)[number],
    allowed: "read" | "write" | "both",
    expected: ParsedPolicyPath["kind"],
  ): void => {
    app.all(
      descriptor.path,
      {
        onRequest: async (request) => {
          if (allowed === "both") {
            if (request.method === "GET") enforceReadTransport(request, options);
            else if (request.method === "POST") enforceWriteTransport(request, options);
            else throw methodNotAllowed();
            return;
          }
          if (allowed === "read") enforceReadTransport(request, options);
          else enforceWriteTransport(request, options);
        },
      },
      async (request, reply) => dispatch(request, reply, expected),
    );
  };

  const byId = new Map(CONTROL_ROUTES.map((route) => [route.id, route]));
  const require = (id: string): (typeof CONTROL_ROUTES)[number] => {
    const descriptor = byId.get(id);
    if (descriptor === undefined) {
      throw new Error("Control route registry is inconsistent");
    }
    return descriptor;
  };
  // `policy_roots` covers GET /policies and POST /policies; `policy_revisions`
  // covers GET/POST /policies/:policyId/revisions. The two POST descriptors
  // (`policy_create`, `policy_revision_create`) share those paths, so only the
  // combined "both" registration is installed; the per-descriptor method is
  // enforced from the frozen registry entry at request time.
  register(require("policy_roots"), "both", "roots");
  register(require("policy_revisions"), "both", "revisions");
  register(require("policy_root"), "read", "root");
  register(require("policy_revision"), "read", "revision");
  register(require("policy_pause"), "write", "transition");
  register(require("policy_resume"), "write", "transition");
  register(require("policy_revoke"), "write", "transition");
  register(require("policy_mutation_status"), "read", "mutation");
}
