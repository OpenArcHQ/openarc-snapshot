import {
  API_CLIENT_HEADER,
  API_MAX_RESPONSE_BYTES,
  COMMERCE_CAPABILITY_ENVIRONMENT,
  COMMERCE_CAPABILITY_NETWORK,
  COMMERCE_API_SCHEMA_VERSION,
  CONTROL_CAPABILITIES_PATH,
  CONTROL_CAPABILITY_AUDIENCE,
  CONTROL_CAPABILITY_DEPENDENCIES,
  CONTROL_CAPABILITY_FAMILY_ORDER,
  CONTROL_CAPABILITY_VERSION,
  CONTROL_ROUTES,
  ControlCapabilitiesSuccessEnvelopeSchema,
  ControlCapabilityManifestSchema,
  CommerceApiMetaSchema,
  type ControlCapabilityFamily,
  type ControlCapabilityManifest,
  type ControlCapabilityState,
} from "@openarc/shared";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { AUTH_ERRORS, AuthApiError } from "../auth/errors.js";

/**
 * Public, credentialless control capability metadata surface.
 *
 * `GET /v2/public/control-capabilities` publishes the exact accepted shared
 * control registry: version `openarc.capabilities.control.v1`, the single
 * `policy_management` browser family with dependencies
 * auth/tenantDatabase/policyDatabase, and the fixed ten protected route
 * descriptors. It ALWAYS registers, even with the flag off: with
 * `POLICY_MANAGEMENT_ENABLED=false` it returns the accepted manifest whose one
 * family is `built_disabled` and performs ZERO database or readiness-callback
 * calls.
 *
 * The manifest is availability metadata ONLY. It grants no role, exposes no
 * live handler by itself, and never suggests financial execution, reservation
 * or enforcement. Only the enable flag plus the AUTH_ENABLED gating flag and
 * the readiness callbacks actually required cross this boundary; the full
 * config, secrets, DB URLs and private identities never do.
 *
 * Readiness is joined from at most ONE bounded, app-wide in-flight batch of the
 * read-only callback probes the enabled family actually requires. The family is
 * INDEPENDENT of tenant HTTP reads: the accepted `ControlPolicyStore.readiness`
 * already composes the restricted tenant database base readiness, so the single
 * `policyReady` callback covers BOTH the declared tenantDatabase and
 * policyDatabase requirements and is invoked exactly ONCE per batch. Concurrent
 * requests share that batch; when it settles the reference is cleared so a
 * later request re-checks. A response deadline (2s total) fails closed for a
 * still-unresolved dependency without demoting one that already settled to
 * `true` independently, and without starting a second overlapping batch. The
 * response result is snapshotted at the deadline so late settlement cannot
 * mutate an already-returned response. There is no success cache, principal
 * cache or background timer.
 */

export const CONTROL_CAPABILITIES_ROUTE = CONTROL_CAPABILITIES_PATH;

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
export interface ControlCapabilityFlags {
  readonly authEnabled: boolean;
  readonly policyManagementEnabled: boolean;
}

/**
 * Existing readiness callbacks, unchanged. Each may be absent. The control
 * family requires only `authReady` and `policyReady`: the accepted policy store
 * readiness already covers the dedicated restricted tenant database, so no
 * separate tenant callback is accepted or dereferenced.
 */
export interface ControlCapabilityReadiness {
  readonly authReady?: () => Promise<boolean>;
  readonly policyReady?: () => Promise<boolean>;
}

export interface RegisterControlCapabilitiesOptions {
  readonly flags: ControlCapabilityFlags;
  readonly readiness: ControlCapabilityReadiness;
  readonly buildSha: string;
  readonly appOrigin: string;
  readonly maxResponseBytes?: number;
}

type ReadinessKey = "authReady" | "policyReady";

type DependencyKey =
  | "authReady"
  | "tenantDatabaseReady"
  | "policyDatabaseReady";

interface ReadinessBatch {
  readonly promise: Promise<ReadinessResult>;
  /**
   * The in-progress result object. Only this batch's own callback settlement
   * mutates it, so the frozen deadline snapshot stays a stable copy even if
   * settlement lands later.
   */
  readonly result: MutableReadinessResult;
}

interface ReadinessResult {
  readonly authReady: boolean;
  readonly tenantDatabaseReady: boolean;
  readonly policyDatabaseReady: boolean;
}

type MutableReadinessResult = {
  -readonly [K in keyof ReadinessResult]: ReadinessResult[K];
};

function unready(): MutableReadinessResult {
  return {
    authReady: false,
    tenantDatabaseReady: false,
    policyDatabaseReady: false,
  };
}

/** Frozen copy so a deadline snapshot cannot be mutated by late settlement. */
function snapshot(result: ReadinessResult): ReadinessResult {
  return Object.freeze({
    authReady: result.authReady === true,
    tenantDatabaseReady: result.tenantDatabaseReady === true,
    policyDatabaseReady: result.policyDatabaseReady === true,
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
  manifest: ControlCapabilityManifest,
  maxResponseBytes: number,
): FastifyReply {
  const envelope = ControlCapabilitiesSuccessEnvelopeSchema.parse({
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
 * Which readiness dependencies an ENABLED (flag- and gate-satisfied) family
 * requires. The declared dependency registry still lists auth, tenantDatabase
 * and policyDatabase, but the single family is independent of tenant HTTP
 * reads: the accepted policy store readiness composes the restricted tenant
 * base readiness, so `policyReady` satisfies BOTH the tenantDatabase and
 * policyDatabase requirements. Only readiness for an enabled family is invoked;
 * a missing callback contributes `false` without invoking anything.
 */
function requiredDependencies(
  flags: ControlCapabilityFlags,
): Record<DependencyKey, boolean> {
  const enabled = flags.policyManagementEnabled && flags.authEnabled;
  return {
    authReady: enabled,
    tenantDatabaseReady: enabled,
    policyDatabaseReady: enabled,
  };
}

/**
 * The dependency labels each accepted callback satisfies. `authReady` satisfies
 * only auth; `policyReady` satisfies BOTH tenantDatabase and policyDatabase via
 * its own composed readiness, so it is invoked exactly once per batch and never
 * duplicated for the two labels.
 */
const CALLBACK_DEPENDENCIES: Readonly<
  Record<ReadinessKey, readonly DependencyKey[]>
> = Object.freeze({
  authReady: Object.freeze(["authReady"] as const),
  policyReady: Object.freeze([
    "tenantDatabaseReady",
    "policyDatabaseReady",
  ] as const),
});

/**
 * Only the callbacks whose dependency is actually required are invoked, in a
 * fixed order and at most once each.
 */
function readinessCallbacksNeeded(
  flags: ControlCapabilityFlags,
): ReadinessKey[] {
  const required = requiredDependencies(flags);
  const keys: ReadinessKey[] = [];
  if (required.authReady) keys.push("authReady");
  if (required.policyDatabaseReady) keys.push("policyReady");
  return keys;
}

/**
 * The one frozen policy-management family state.
 *
 * Flag OFF is always `built_disabled` independent of dependencies. With the
 * flag ON, a missing auth prerequisite or an unready/unavailable auth or policy
 * database dependency yields `unavailable`; only a fully gate-satisfied and
 * runtime-ready family is `enabled`. Tenant HTTP reads are deliberately NOT a
 * prerequisite: `policyReady` already covers the restricted tenant database.
 */
function familyState(
  flags: ControlCapabilityFlags,
  readinessResult: ReadinessResult,
): ControlCapabilityState {
  if (!flags.policyManagementEnabled) return "built_disabled";
  const flagsSatisfied = flags.authEnabled;
  const runtimeSatisfied =
    readinessResult.authReady === true &&
    readinessResult.tenantDatabaseReady === true &&
    readinessResult.policyDatabaseReady === true;
  return flagsSatisfied && runtimeSatisfied ? "enabled" : "unavailable";
}

/**
 * Pure availability builder. Returns the full fixed manifest using the exact
 * accepted shared registry; callers cannot receive a partially populated or
 * caller-extended object. The result is parsed through the strict shared
 * manifest schema so a drift in constants or state fails closed.
 */
export function buildControlCapabilityManifest(
  flags: ControlCapabilityFlags,
  readinessResult: ReadinessResult,
): ControlCapabilityManifest {
  const capabilities = CONTROL_CAPABILITY_FAMILY_ORDER.map(
    (family: ControlCapabilityFamily) =>
      Object.freeze({
        family,
        audience: CONTROL_CAPABILITY_AUDIENCE[family],
        state: familyState(flags, readinessResult),
        dependencies: [...CONTROL_CAPABILITY_DEPENDENCIES[family]],
      }),
  );
  return ControlCapabilityManifestSchema.parse({
    capabilityVersion: CONTROL_CAPABILITY_VERSION,
    environment: COMMERCE_CAPABILITY_ENVIRONMENT,
    network: COMMERCE_CAPABILITY_NETWORK,
    capabilities,
    routes: CONTROL_ROUTES,
  });
}

export function registerControlCapabilities(
  app: FastifyInstance,
  options: RegisterControlCapabilitiesOptions,
): void {
  const { flags, readiness, appOrigin } = options;
  const maxResponseBytes = options.maxResponseBytes ?? API_MAX_RESPONSE_BYTES;
  const callbacksNeeded = readinessCallbacksNeeded(flags);
  const required = requiredDependencies(flags);

  // App-wide single in-flight batch holder. Never accumulates, never queues.
  let inflight: ReadinessBatch | null = null;

  /**
   * One batch owns one mutable `result`. Each dependency writes its own
   * settled value as soon as it settles, so a deadline snapshot preserves
   * independently ready values while an unresolved dependency stays `false`
   * and cannot demote them.
   */
  const startBatch = (): ReadinessBatch => {
    const result = unready();
    const work: Array<Promise<void>> = [];

    for (const key of callbacksNeeded) {
      const callback = readiness[key];
      if (callback === undefined) continue;
      // A callback may satisfy more than one declared dependency label (the
      // composed policy readiness covers tenant + policy), but it is invoked
      // exactly once and all of its labels are written from that ONE result.
      const dependencies = CALLBACK_DEPENDENCIES[key].filter(
        (dependency) => required[dependency] === true,
      );
      if (dependencies.length === 0) continue;
      work.push(
        Promise.resolve()
          .then(() => callback())
          .then((ready) => {
            const settled = ready === true;
            for (const dependency of dependencies) {
              result[dependency] = settled;
            }
          })
          .catch(() => {
            for (const dependency of dependencies) {
              result[dependency] = false;
            }
          }),
      );
    }

    const promise: Promise<ReadinessResult> = Promise.all(work).then(() =>
      snapshot(result),
    );
    return { promise, result };
  };

  /**
   * Returns the single app-wide in-flight batch, creating one only when none
   * is active. Concurrent requests join the same batch; once it actually
   * settles its own reference is cleared so a later request re-checks.
   */
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
        // Snapshot at the deadline: dependencies that settled independently
        // are preserved, while still-unresolved ones remain `false` and fail
        // closed. The copy is frozen so late settlement cannot mutate a
        // response already returned.
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
      // The underlying batch keeps running to its actual settlement (one
      // in-flight batch), but the response fails closed after the deadline.
      return await Promise.race([batch.promise, deadline]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  };

  app.all(
    CONTROL_CAPABILITIES_PATH,
    {
      onRequest: async (request) => {
        enforceTransport(request, appOrigin);
      },
    },
    async (request, reply) => {
      const readinessResult = await boundedReadiness();
      const manifest = buildControlCapabilityManifest(flags, readinessResult);
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
