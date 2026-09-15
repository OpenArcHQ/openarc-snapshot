import {
  API_CLIENT_HEADER,
  API_MAX_RESPONSE_BYTES,
  COMMERCE_CAPABILITY_ENVIRONMENT,
  COMMERCE_CAPABILITY_NETWORK,
  COMMERCE_API_SCHEMA_VERSION,
  CommerceApiMetaSchema,
  SESSION_CAPABILITIES_PATH,
  SESSION_CAPABILITY_AUDIENCE,
  SESSION_CAPABILITY_DEPENDENCIES,
  SESSION_CAPABILITY_FAMILY_ORDER,
  SESSION_CAPABILITY_VERSION,
  SESSION_ROUTES,
  SessionCapabilitiesSuccessEnvelopeSchema,
  SessionCapabilityManifestSchema,
  type SessionCapabilityFamily,
  type SessionCapabilityManifest,
  type SessionCapabilityState,
} from "@openarc/shared";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { AUTH_ERRORS, AuthApiError } from "../auth/errors.js";

/**
 * Public, credentialless commerce-session capability metadata surface.
 *
 * `GET /v2/public/session-capabilities` ALWAYS registers and publishes the
 * exact accepted shared session registry: version
 * `openarc.capabilities.commerce-sessions.v1`, the frozen two-family inventory
 * commerce_session_management/browser and commerce_session_exchange/agent with
 * the shared five-dependency array auth/tenantDatabase/machineDatabase/
 * policyDatabase/commerceSessionDatabase, and the exact seven frozen route
 * descriptors.
 *
 * With `COMMERCE_SESSIONS_ENABLED=false` it returns the accepted manifest with
 * BOTH families `built_disabled` and performs ZERO database or readiness-callback
 * calls. When enabled with `AUTH_ENABLED` and a healthy runtime both families
 * share the single `enabled` state; a missing/failed auth or session dependency
 * yields the shared `unavailable` state. The latter composes the declared
 * tenant/machine/policy/commerceSession database dependencies through the
 * accepted session store readiness - it does NOT consult the old HTTP tenant
 * read/write, machine issuance/exchange, policy, market, wallet or ARC
 * observation flags/callbacks.
 *
 * The manifest is availability metadata ONLY. It grants no role, payment or
 * execution authority, exposes no live handler by itself and performs no
 * automatic network/provider/RPC request. Only the two explicit flags, the
 * readiness callbacks actually required, the build SHA and the exact app origin
 * cross this boundary; the full config, secrets, DB URLs and private identities
 * never do.
 *
 * Readiness is joined from at most ONE bounded, app-wide in-flight batch of the
 * read-only probes an enabled family actually requires. Concurrent requests
 * share that batch; when it actually settles the reference is cleared so a
 * later request re-checks. A fixed 2000ms response deadline fails closed for a
 * still-unresolved dependency without demoting one that already settled
 * independently and without starting a second overlapping batch. The response
 * result is snapshotted at the deadline. There is no cache and no background
 * timer.
 *
 * Transport reuses the accepted policy capability allowlist exactly: the same
 * transport-critical/credential headers, the single optional browser marker and
 * the exact eight opaque Railway/proxy metadata exceptions (no new wildcard).
 */

export const SESSION_CAPABILITIES_ROUTE = SESSION_CAPABILITIES_PATH;

const MAX_REQUEST_URL_BYTES = 2048;
const READINESS_DEADLINE_MS = 2000;

/** Exactly the public transport-critical header names counted on the wire. */
const PUBLIC_CRITICAL_HEADERS: ReadonlySet<string> = new Set([
  "origin",
  "cookie",
  "authorization",
  "proxy-authorization",
  "x-openarc-csrf",
  "idempotency-key",
  "x-openarc-client",
  "content-length",
  "transfer-encoding",
  "content-type",
]);

/**
 * Optional single browser marker: absent or exactly `browser-v1`. Every other
 * client-metadata name is rejected; no other client metadata is inspected.
 */
const ALLOWED_CLIENT_HEADER_NAMES: ReadonlySet<string> = new Set([
  "x-openarc-client",
]);

/**
 * Untrusted, informational proxy metadata inserted by a SECOND edge (Railway)
 * after nginx has already stripped the incoming transport headers. These are
 * not authoritative for anything: they are ignored, never trusted, persisted,
 * echoed, logged, used as requestId/principal/client identity, involved in
 * routing/origin checks or readiness, and their contents are deliberately not
 * validated because they have no semantics on this route. Existing server
 * limits bound the total header count. The exact six documented Railway names
 * plus the two standard proxy metadata names are allowed; there is NO wildcard
 * `x-railway`/`x-forwarded` allowance and no debug-header special treatment.
 */
const IGNORED_TRANSPORT_HEADERS: ReadonlySet<string> = new Set([
  // Documented Railway second-edge request headers.
  "x-real-ip",
  "x-forwarded-proto",
  "x-forwarded-host",
  "x-railway-edge",
  "x-request-start",
  "x-railway-request-id",
  // Standard opaque proxy metadata, not authorization.
  "x-forwarded-for",
  "forwarded",
]);

/** The explicit flags app.ts may pass. Never the full config object. */
export interface SessionCapabilityFlags {
  readonly authEnabled: boolean;
  readonly commerceSessionsEnabled: boolean;
}

/**
 * Existing readiness callbacks, each may be absent. Only `authReady` and
 * `sessionReady` are accepted: the accepted `CommerceSessionStore.readiness`
 * already composes the tenant/machine/policy/credential/commerceSession schema
 * readiness, so no old HTTP tenant/machine/policy callback is accepted.
 */
export interface SessionCapabilityReadiness {
  readonly authReady?: () => Promise<boolean>;
  readonly sessionReady?: () => Promise<boolean>;
}

export interface RegisterSessionCapabilitiesOptions {
  readonly flags: SessionCapabilityFlags;
  readonly readiness: SessionCapabilityReadiness;
  readonly buildSha: string;
  readonly appOrigin: string;
  readonly maxResponseBytes?: number;
}

type ReadinessKey = "authReady" | "sessionReady";

interface ReadinessResult {
  readonly authReady: boolean;
  readonly sessionReady: boolean;
}

type MutableReadinessResult = {
  -readonly [K in keyof ReadinessResult]: ReadinessResult[K];
};

interface ReadinessBatch {
  readonly promise: Promise<ReadinessResult>;
  /**
   * The in-progress result object. Only this batch's own callback settlement
   * mutates it, so the frozen deadline snapshot stays a stable copy even if
   * settlement lands later.
   */
  readonly result: MutableReadinessResult;
}

function unready(): MutableReadinessResult {
  return { authReady: false, sessionReady: false };
}

/** Frozen copy so a deadline snapshot cannot be mutated by late settlement. */
function snapshot(result: ReadinessResult): ReadinessResult {
  return Object.freeze({
    authReady: result.authReady === true,
    sessionReady: result.sessionReady === true,
  });
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

function rawRequestUrl(request: FastifyRequest): string {
  const raw = request.raw.url;
  return typeof raw === "string" && raw.length > 0 ? raw : request.url;
}

function enforceNoDuplicateCriticalHeaders(request: FastifyRequest): void {
  const raw = request.raw.rawHeaders;
  if (!Array.isArray(raw)) return;
  const seen = new Set<string>();
  for (let index = 0; index + 1 < raw.length; index += 2) {
    const name = raw[index];
    if (typeof name !== "string") continue;
    const lower = name.toLowerCase();
    if (!PUBLIC_CRITICAL_HEADERS.has(lower)) continue;
    if (seen.has(lower)) throw invalidRequest();
    seen.add(lower);
  }
}

/**
 * Reject any header that is neither a fixed transport/negotiation header nor
 * the single optional browser marker. This is an allowlist, so arbitrary
 * client metadata (cookies, credentials, CSRF, idempotency, unknown client
 * headers) fails closed. Duplicate wire occurrences of critical names are
 * already rejected before this normalized check.
 */
function enforceAllowedHeaders(request: FastifyRequest): void {
  for (const name of Object.keys(request.headers)) {
    if (ALLOWED_CLIENT_HEADER_NAMES.has(name)) continue;
    if (PUBLIC_CRITICAL_HEADERS.has(name)) continue;
    if (IGNORED_TRANSPORT_HEADERS.has(name)) continue;
    if (
      name === "host" ||
      name === "accept" ||
      name === "accept-encoding" ||
      name === "accept-language" ||
      name === "user-agent" ||
      name === "connection" ||
      name === "sec-fetch-site" ||
      name === "sec-fetch-mode" ||
      name === "sec-fetch-dest"
    ) {
      continue;
    }
    throw invalidRequest();
  }
}

function enforceTransport(request: FastifyRequest, appOrigin: string): void {
  enforceNoDuplicateCriticalHeaders(request);
  const url = rawRequestUrl(request);
  if (Buffer.byteLength(url, "utf8") > MAX_REQUEST_URL_BYTES) throw invalidRequest();
  if (url.includes("?")) throw invalidRequest();
  if (request.method !== "GET") throw methodNotAllowed();
  enforceAllowedHeaders(request);

  // Credential and anti-forgery headers are never accepted on this public,
  // credentialless surface, even though Node may have collapsed a duplicate.
  for (const name of [
    "cookie",
    "authorization",
    "proxy-authorization",
    "x-openarc-csrf",
    "idempotency-key",
  ]) {
    if (strictHeader(request.headers, name) !== undefined) throw invalidRequest();
  }

  const client = strictHeader(request.headers, "x-openarc-client");
  if (client !== undefined && client !== API_CLIENT_HEADER) throw invalidRequest();
  const origin = strictHeader(request.headers, "origin");
  const site = strictHeader(request.headers, "sec-fetch-site");
  if (origin !== undefined && origin !== appOrigin) throw originRejected();
  if (site !== undefined && site !== "same-origin") throw originRejected();

  const contentLength = strictHeader(request.headers, "content-length");
  if (contentLength !== undefined && contentLength !== "0") throw invalidRequest();
  if (strictHeader(request.headers, "transfer-encoding") !== undefined) {
    throw invalidRequest();
  }
}

function meta(request: FastifyRequest, buildSha: string) {
  return CommerceApiMetaSchema.parse({
    schemaVersion: COMMERCE_API_SCHEMA_VERSION,
    requestId: request.id,
    buildSha,
  });
}

function sendEnvelope(
  request: FastifyRequest,
  reply: FastifyReply,
  buildSha: string,
  manifest: SessionCapabilityManifest,
  maxResponseBytes: number,
): FastifyReply {
  const envelope = SessionCapabilitiesSuccessEnvelopeSchema.parse({
    ok: true,
    data: manifest,
    meta: meta(request, buildSha),
  });
  const serialized = JSON.stringify(envelope);
  if (Buffer.byteLength(serialized, "utf8") > maxResponseBytes) {
    throw AUTH_ERRORS.internal();
  }
  return reply.type("application/json; charset=utf-8").send(serialized);
}

/**
 * True when the runtime dependencies are actually required: only when the
 * session family is enabled AND its auth prerequisite holds. With the flag off
 * no probe is ever needed.
 */
function enabled(flags: SessionCapabilityFlags): boolean {
  return flags.commerceSessionsEnabled && flags.authEnabled;
}

function requiredDependencies(
  flags: SessionCapabilityFlags,
): Record<ReadinessKey, boolean> {
  const active = enabled(flags);
  return { authReady: active, sessionReady: active };
}

/** Only the callbacks whose dependency is actually required are invoked. */
function readinessCallbacksNeeded(flags: SessionCapabilityFlags): ReadinessKey[] {
  const required = requiredDependencies(flags);
  const keys: ReadinessKey[] = [];
  if (required.authReady) keys.push("authReady");
  if (required.sessionReady) keys.push("sessionReady");
  return keys;
}

/**
 * One shared state for BOTH families from the single flag + runtime readiness.
 *
 * Flag OFF is always `built_disabled` independent of dependencies. With the
 * flag ON, a missing auth prerequisite or an unready/unavailable auth or
 * session dependency yields `unavailable`; only a fully gate-satisfied and
 * runtime-ready family is `enabled`.
 */
export function sessionCapabilityState(
  flags: SessionCapabilityFlags,
  readinessResult: ReadinessResult,
): SessionCapabilityState {
  if (!flags.commerceSessionsEnabled) return "built_disabled";
  const flagsSatisfied = flags.authEnabled;
  const runtimeSatisfied =
    readinessResult.authReady === true && readinessResult.sessionReady === true;
  return flagsSatisfied && runtimeSatisfied ? "enabled" : "unavailable";
}

/**
 * Pure availability builder. Returns the full fixed manifest using the exact
 * accepted shared registry; callers cannot receive a partially populated or
 * caller-extended object. The result is parsed through the strict shared
 * manifest schema so a drift in constants/order/state fails closed.
 */
export function buildSessionCapabilityManifest(
  state: SessionCapabilityState,
): SessionCapabilityManifest {
  const capabilities = SESSION_CAPABILITY_FAMILY_ORDER.map(
    (family: SessionCapabilityFamily) =>
      Object.freeze({
        family,
        audience: SESSION_CAPABILITY_AUDIENCE[family],
        state,
        dependencies: [...SESSION_CAPABILITY_DEPENDENCIES[family]],
      }),
  );
  return SessionCapabilityManifestSchema.parse({
    capabilityVersion: SESSION_CAPABILITY_VERSION,
    environment: COMMERCE_CAPABILITY_ENVIRONMENT,
    network: COMMERCE_CAPABILITY_NETWORK,
    capabilities,
    routes: SESSION_ROUTES,
  });
}

export function registerSessionCapabilities(
  app: FastifyInstance,
  options: RegisterSessionCapabilitiesOptions,
): void {
  const { flags, readiness, appOrigin } = options;
  const maxResponseBytes = options.maxResponseBytes ?? API_MAX_RESPONSE_BYTES;
  const callbacksNeeded = readinessCallbacksNeeded(flags);
  const required = requiredDependencies(flags);

  // App-wide single in-flight batch holder. Never accumulates, never queues.
  let inflight: ReadinessBatch | null = null;

  const startBatch = (): ReadinessBatch => {
    const result = unready();
    const work: Array<Promise<void>> = [];

    for (const key of callbacksNeeded) {
      if (required[key] !== true) continue;
      const callback = readiness[key];
      if (callback === undefined) continue;
      work.push(
        Promise.resolve()
          .then(() => callback())
          .then((ready) => {
            result[key] = ready === true;
          })
          .catch(() => {
            result[key] = false;
          }),
      );
    }

    const promise: Promise<ReadinessResult> = Promise.all(work).then(() =>
      snapshot(result),
    );
    return { promise, result };
  };

  const joinBatch = (): ReadinessBatch => {
    if (inflight !== null) return inflight;
    const batch = startBatch();
    inflight = batch;
    void batch.promise.finally(() => {
      if (inflight === batch) {
        inflight = null;
      }
    });
    return batch;
  };

  const boundedReadiness = async (): Promise<ReadinessResult> => {
    if (callbacksNeeded.length === 0) return snapshot(unready());
    const batch = joinBatch();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<ReadinessResult>((resolve) => {
      timer = setTimeout(
        () => resolve(snapshot(batch.result)),
        READINESS_DEADLINE_MS,
      );
      if (
        typeof timer === "object" &&
        timer !== null &&
        "unref" in timer &&
        typeof (timer as { unref?: unknown }).unref === "function"
      ) {
        (timer as { unref: () => void }).unref();
      }
    });
    try {
      return await Promise.race([batch.promise, deadline]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  };

  app.all(
    SESSION_CAPABILITIES_PATH,
    {
      onRequest: async (request) => {
        enforceTransport(request, appOrigin);
      },
    },
    async (request, reply) => {
      const readinessResult = await boundedReadiness();
      const state = sessionCapabilityState(flags, readinessResult);
      const manifest = buildSessionCapabilityManifest(state);
      return sendEnvelope(
        request,
        reply,
        options.buildSha,
        manifest,
        maxResponseBytes,
      );
    },
  );
}
