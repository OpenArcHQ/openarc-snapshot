import {
  ACTION_CAPABILITIES_PATH,
  ACTION_CAPABILITY_AUDIENCE,
  ACTION_CAPABILITY_DEPENDENCIES,
  ACTION_CAPABILITY_FAMILY_ORDER,
  ACTION_CAPABILITY_VERSION,
  ACTION_ROUTES,
  ActionCapabilitiesSuccessEnvelopeSchema,
  ActionCapabilityManifestSchema,
  API_CLIENT_HEADER,
  API_MAX_RESPONSE_BYTES,
  COMMERCE_API_SCHEMA_VERSION,
  COMMERCE_CAPABILITY_ENVIRONMENT,
  COMMERCE_CAPABILITY_NETWORK,
  CommerceApiMetaSchema,
  type ActionCapabilityFamily,
  type ActionCapabilityManifest,
  type ActionCapabilityState,
} from "@openarc/shared";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { AUTH_ERRORS, AuthApiError } from "../auth/errors.js";

/**
 * Public, credentialless commerce-action capability metadata surface.
 *
 * `GET /v2/public/action-capabilities` ALWAYS registers and publishes the exact
 * accepted shared action registry: version
 * `openarc.capabilities.commerce-actions.v1`, the frozen two-family inventory
 * commerce_action_management/browser and commerce_action_authorization/agent
 * with the shared six-dependency array auth/tenantDatabase/machineDatabase/
 * policyDatabase/commerceSessionDatabase/commerceActionDatabase, and the exact
 * twelve frozen route descriptors.
 *
 * With the action gate off it returns the accepted manifest with BOTH families
 * `built_disabled` and performs ZERO database or readiness-callback calls. When
 * the gate is on with `AUTH_ENABLED`, the commerce-session prerequisite and a
 * healthy runtime, both families share the single `enabled` state; a missing or
 * failed dependency yields the shared `unavailable` state. The per-family state
 * is therefore derived from ACTUAL configured dependencies, never asserted.
 *
 * The manifest is availability metadata ONLY. It grants no role, permission,
 * payment or execution authority, exposes no live handler by itself and
 * performs no automatic network/provider/RPC request. An `enabled` action
 * surface does NOT mean a payment, settlement or delivery lane exists: the
 * listing payment lane remains unavailable and production authorization still
 * rejects unverified requirements.
 *
 * Only the explicit flags, the readiness callbacks actually required, the build
 * SHA and the exact app origin cross this boundary; the full config, secrets,
 * DB URLs and private identities never do. Transport reuses the accepted
 * capability allowlist exactly.
 */

export const ACTION_CAPABILITIES_ROUTE = ACTION_CAPABILITIES_PATH;

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

const ALLOWED_CLIENT_HEADER_NAMES: ReadonlySet<string> = new Set([
  "x-openarc-client",
]);

/**
 * Untrusted, informational proxy metadata inserted by a SECOND edge (Railway)
 * after nginx has already stripped the incoming transport headers. These are
 * ignored, never trusted, persisted, echoed, logged or used for routing,
 * identity or readiness. There is NO wildcard allowance.
 */
const IGNORED_TRANSPORT_HEADERS: ReadonlySet<string> = new Set([
  "x-real-ip",
  "x-forwarded-proto",
  "x-forwarded-host",
  "x-railway-edge",
  "x-request-start",
  "x-railway-request-id",
  "x-forwarded-for",
  "forwarded",
]);

/** The explicit flags app.ts may pass. Never the full config object. */
export interface ActionCapabilityFlags {
  readonly authEnabled: boolean;
  readonly commerceSessionsEnabled: boolean;
  readonly commerceActionsEnabled: boolean;
}

/**
 * Existing readiness callbacks, each may be absent. `actionReady` reflects the
 * ACTUAL configured commerce-action dependency (the runtime's own bounded
 * readiness), not a declaration.
 */
export interface ActionCapabilityReadiness {
  readonly authReady?: () => Promise<boolean>;
  readonly sessionReady?: () => Promise<boolean>;
  readonly actionReady?: () => Promise<boolean>;
}

export interface RegisterActionCapabilitiesOptions {
  readonly flags: ActionCapabilityFlags;
  readonly readiness: ActionCapabilityReadiness;
  readonly buildSha: string;
  readonly appOrigin: string;
  readonly maxResponseBytes?: number;
}

type ReadinessKey = "authReady" | "sessionReady" | "actionReady";

interface ReadinessResult {
  readonly authReady: boolean;
  readonly sessionReady: boolean;
  readonly actionReady: boolean;
}

type MutableReadinessResult = {
  -readonly [K in keyof ReadinessResult]: ReadinessResult[K];
};

interface ReadinessBatch {
  readonly promise: Promise<ReadinessResult>;
  readonly result: MutableReadinessResult;
}

function unready(): MutableReadinessResult {
  return { authReady: false, sessionReady: false, actionReady: false };
}

/** Frozen copy so a deadline snapshot cannot be mutated by late settlement. */
function snapshot(result: ReadinessResult): ReadinessResult {
  return Object.freeze({
    authReady: result.authReady === true,
    sessionReady: result.sessionReady === true,
    actionReady: result.actionReady === true,
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
 * the single optional browser marker. This is an allowlist, so arbitrary client
 * metadata (cookies, credentials, CSRF, idempotency, unknown client headers)
 * fails closed.
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
  if (Buffer.byteLength(url, "utf8") > MAX_REQUEST_URL_BYTES) {
    throw invalidRequest();
  }
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
    if (strictHeader(request.headers, name) !== undefined) {
      throw invalidRequest();
    }
  }

  const client = strictHeader(request.headers, "x-openarc-client");
  if (client !== undefined && client !== API_CLIENT_HEADER) {
    throw invalidRequest();
  }
  const origin = strictHeader(request.headers, "origin");
  const site = strictHeader(request.headers, "sec-fetch-site");
  if (origin !== undefined && origin !== appOrigin) throw originRejected();
  if (site !== undefined && site !== "same-origin") throw originRejected();

  const contentLength = strictHeader(request.headers, "content-length");
  if (contentLength !== undefined && contentLength !== "0") {
    throw invalidRequest();
  }
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
  manifest: ActionCapabilityManifest,
  maxResponseBytes: number,
): FastifyReply {
  const envelope = ActionCapabilitiesSuccessEnvelopeSchema.parse({
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
 * action family is enabled AND both of its declared prerequisites hold. With
 * the gate off no probe is ever needed.
 */
function enabled(flags: ActionCapabilityFlags): boolean {
  return (
    flags.commerceActionsEnabled &&
    flags.authEnabled &&
    flags.commerceSessionsEnabled
  );
}

function requiredDependencies(
  flags: ActionCapabilityFlags,
): Record<ReadinessKey, boolean> {
  const active = enabled(flags);
  return { authReady: active, sessionReady: active, actionReady: active };
}

/** Only the callbacks whose dependency is actually required are invoked. */
function readinessCallbacksNeeded(
  flags: ActionCapabilityFlags,
): ReadinessKey[] {
  const required = requiredDependencies(flags);
  const keys: ReadinessKey[] = [];
  if (required.authReady) keys.push("authReady");
  if (required.sessionReady) keys.push("sessionReady");
  if (required.actionReady) keys.push("actionReady");
  return keys;
}

/**
 * One shared state for BOTH families from the single gate + runtime readiness.
 *
 * Gate OFF is always `built_disabled` independent of dependencies. With the
 * gate ON, a missing auth/commerce-session prerequisite or an unready auth,
 * session or action dependency yields `unavailable`; only a fully
 * gate-satisfied and runtime-ready family is `enabled`. `enabled` is an
 * availability statement about this control surface, never a payment claim.
 */
export function actionCapabilityState(
  flags: ActionCapabilityFlags,
  readinessResult: ReadinessResult,
): ActionCapabilityState {
  if (!flags.commerceActionsEnabled) return "built_disabled";
  const flagsSatisfied = flags.authEnabled && flags.commerceSessionsEnabled;
  const runtimeSatisfied =
    readinessResult.authReady === true &&
    readinessResult.sessionReady === true &&
    readinessResult.actionReady === true;
  return flagsSatisfied && runtimeSatisfied ? "enabled" : "unavailable";
}

/**
 * Pure availability builder. Returns the full fixed manifest using the exact
 * accepted shared registry; callers cannot receive a partially populated or
 * caller-extended object. The result is parsed through the strict shared
 * manifest schema so a drift in constants/order/state fails closed.
 */
export function buildActionCapabilityManifest(
  state: ActionCapabilityState,
): ActionCapabilityManifest {
  const capabilities = ACTION_CAPABILITY_FAMILY_ORDER.map(
    (family: ActionCapabilityFamily) =>
      Object.freeze({
        family,
        audience: ACTION_CAPABILITY_AUDIENCE[family],
        state,
        dependencies: [...ACTION_CAPABILITY_DEPENDENCIES[family]],
      }),
  );
  return ActionCapabilityManifestSchema.parse({
    capabilityVersion: ACTION_CAPABILITY_VERSION,
    environment: COMMERCE_CAPABILITY_ENVIRONMENT,
    network: COMMERCE_CAPABILITY_NETWORK,
    capabilities,
    routes: ACTION_ROUTES,
  });
}

export function registerActionCapabilities(
  app: FastifyInstance,
  options: RegisterActionCapabilitiesOptions,
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
    ACTION_CAPABILITIES_PATH,
    {
      onRequest: async (request) => {
        enforceTransport(request, appOrigin);
      },
    },
    async (request, reply) => {
      const readinessResult = await boundedReadiness();
      const state = actionCapabilityState(flags, readinessResult);
      const manifest = buildActionCapabilityManifest(state);
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
