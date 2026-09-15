import {
  API_CLIENT_HEADER,
  API_MAX_RESPONSE_BYTES,
  COMMERCE_API_SCHEMA_VERSION,
  COMMERCE_CAPABILITY_ENVIRONMENT,
  COMMERCE_CAPABILITY_NETWORK,
  CommerceApiMetaSchema,
  PAYMENT_CAPABILITIES_PATH,
  PAYMENT_CAPABILITY_AUDIENCE,
  PAYMENT_CAPABILITY_DEPENDENCIES,
  PAYMENT_CAPABILITY_FAMILY_ORDER,
  PAYMENT_CAPABILITY_VERSION,
  PAYMENT_ROUTES,
  PaymentCapabilitiesSuccessEnvelopeSchema,
  PaymentCapabilityManifestSchema,
  type PaymentCapabilityFamily,
  type PaymentCapabilityManifest,
  type PaymentCapabilityState,
} from "@openarc/shared";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

import { AUTH_ERRORS, AuthApiError } from "../auth/errors.js";

/**
 * Public, credentialless payment capability metadata surface.
 *
 * `GET /v2/public/payment-capabilities` ALWAYS registers and publishes the
 * frozen two-family / five-route payment registry. With the payment gate off
 * both families are `built_disabled` and ZERO readiness callbacks run. With the
 * gate on AND its auth, commerce-session, commerce-action and grant
 * prerequisites, one shared state is derived from ACTUAL readiness: `enabled`
 * only when every dependency is ready, otherwise `unavailable`.
 *
 * Availability metadata only: it grants no authority, performs no network,
 * provider or RPC request, and an `enabled` state never means a payment was
 * made, settled or can settle. Transport reuses the accepted capability
 * allowlist exactly.
 */

export const PAYMENT_CAPABILITIES_ROUTE = PAYMENT_CAPABILITIES_PATH;

const MAX_REQUEST_URL_BYTES = 2048;
const READINESS_DEADLINE_MS = 2000;

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

const ALLOWED_PLAIN_HEADERS: ReadonlySet<string> = new Set([
  "host",
  "accept",
  "accept-encoding",
  "accept-language",
  "user-agent",
  "connection",
  "sec-fetch-site",
  "sec-fetch-mode",
  "sec-fetch-dest",
]);

/** The explicit flags app.ts may pass. Never the full config object. */
export interface PaymentCapabilityFlags {
  readonly authEnabled: boolean;
  readonly commerceSessionsEnabled: boolean;
  readonly commerceActionsEnabled: boolean;
  readonly commerceGrantsEnabled: boolean;
  readonly commercePaymentsEnabled: boolean;
}

export interface PaymentCapabilityReadiness {
  readonly authReady?: () => Promise<boolean>;
  readonly sessionReady?: () => Promise<boolean>;
  readonly actionReady?: () => Promise<boolean>;
  readonly grantReady?: () => Promise<boolean>;
  readonly paymentReady?: () => Promise<boolean>;
}

export interface RegisterPaymentCapabilitiesOptions {
  readonly flags: PaymentCapabilityFlags;
  readonly readiness: PaymentCapabilityReadiness;
  readonly buildSha: string;
  readonly appOrigin: string;
  readonly maxResponseBytes?: number;
}

type ReadinessKey = keyof PaymentCapabilityReadiness;

const READINESS_KEYS: readonly ReadinessKey[] = [
  "authReady",
  "sessionReady",
  "actionReady",
  "grantReady",
  "paymentReady",
];

type ReadinessResult = Readonly<Record<ReadinessKey, boolean>>;

function unready(): Record<ReadinessKey, boolean> {
  return {
    authReady: false,
    sessionReady: false,
    actionReady: false,
    grantReady: false,
    paymentReady: false,
  };
}

function snapshot(result: ReadinessResult): ReadinessResult {
  return Object.freeze({
    authReady: result.authReady === true,
    sessionReady: result.sessionReady === true,
    actionReady: result.actionReady === true,
    grantReady: result.grantReady === true,
    paymentReady: result.paymentReady === true,
  });
}

function invalidRequest(): AuthApiError {
  return AUTH_ERRORS.invalidRequest();
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

function enforceTransport(request: FastifyRequest, appOrigin: string): void {
  const raw = request.raw.rawHeaders;
  if (Array.isArray(raw)) {
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
  const url = rawRequestUrl(request);
  if (Buffer.byteLength(url, "utf8") > MAX_REQUEST_URL_BYTES) {
    throw invalidRequest();
  }
  if (url.includes("?")) throw invalidRequest();
  if (request.method !== "GET") {
    throw new AuthApiError("INVALID_REQUEST", 405, "METHOD_NOT_ALLOWED");
  }
  for (const name of Object.keys(request.headers)) {
    if (
      PUBLIC_CRITICAL_HEADERS.has(name) ||
      IGNORED_TRANSPORT_HEADERS.has(name) ||
      ALLOWED_PLAIN_HEADERS.has(name)
    ) {
      continue;
    }
    throw invalidRequest();
  }
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
  if (origin !== undefined && origin !== appOrigin) {
    throw AUTH_ERRORS.originRejected();
  }
  if (site !== undefined && site !== "same-origin") {
    throw AUTH_ERRORS.originRejected();
  }
  const contentLength = strictHeader(request.headers, "content-length");
  if (contentLength !== undefined && contentLength !== "0") {
    throw invalidRequest();
  }
  if (strictHeader(request.headers, "transfer-encoding") !== undefined) {
    throw invalidRequest();
  }
}

function prerequisitesSatisfied(flags: PaymentCapabilityFlags): boolean {
  return (
    flags.authEnabled &&
    flags.commerceSessionsEnabled &&
    flags.commerceActionsEnabled &&
    flags.commerceGrantsEnabled
  );
}

/**
 * One shared state for both families. Gate OFF is always `built_disabled`;
 * gate ON with any missing prerequisite or unready dependency is `unavailable`.
 */
export function paymentCapabilityState(
  flags: PaymentCapabilityFlags,
  readinessResult: ReadinessResult,
): PaymentCapabilityState {
  if (!flags.commercePaymentsEnabled) return "built_disabled";
  const runtimeSatisfied = READINESS_KEYS.every(
    (key) => readinessResult[key] === true,
  );
  return prerequisitesSatisfied(flags) && runtimeSatisfied
    ? "enabled"
    : "unavailable";
}

export function buildPaymentCapabilityManifest(
  state: PaymentCapabilityState,
): PaymentCapabilityManifest {
  const capabilities = PAYMENT_CAPABILITY_FAMILY_ORDER.map(
    (family: PaymentCapabilityFamily) =>
      Object.freeze({
        family,
        audience: PAYMENT_CAPABILITY_AUDIENCE[family],
        state,
        dependencies: [...PAYMENT_CAPABILITY_DEPENDENCIES[family]],
      }),
  );
  return PaymentCapabilityManifestSchema.parse({
    capabilityVersion: PAYMENT_CAPABILITY_VERSION,
    environment: COMMERCE_CAPABILITY_ENVIRONMENT,
    network: COMMERCE_CAPABILITY_NETWORK,
    capabilities,
    routes: PAYMENT_ROUTES,
  });
}

function sendEnvelope(
  request: FastifyRequest,
  reply: FastifyReply,
  buildSha: string,
  manifest: PaymentCapabilityManifest,
  maxResponseBytes: number,
): FastifyReply {
  const envelope = PaymentCapabilitiesSuccessEnvelopeSchema.parse({
    ok: true,
    data: manifest,
    meta: CommerceApiMetaSchema.parse({
      schemaVersion: COMMERCE_API_SCHEMA_VERSION,
      requestId: request.id,
      buildSha,
    }),
  });
  const serialized = JSON.stringify(envelope);
  if (Buffer.byteLength(serialized, "utf8") > maxResponseBytes) {
    throw AUTH_ERRORS.internal();
  }
  return reply.type("application/json; charset=utf-8").send(serialized);
}

export function registerPaymentCapabilities(
  app: FastifyInstance,
  options: RegisterPaymentCapabilitiesOptions,
): void {
  const { flags, readiness, appOrigin } = options;
  const maxResponseBytes = options.maxResponseBytes ?? API_MAX_RESPONSE_BYTES;
  // Probes are needed only when the gate AND every prerequisite flag are on.
  const callbacksNeeded: readonly ReadinessKey[] =
    flags.commercePaymentsEnabled && prerequisitesSatisfied(flags)
      ? READINESS_KEYS
      : [];

  let inflight: { promise: Promise<ReadinessResult>; result: Record<ReadinessKey, boolean> } | null =
    null;

  const joinBatch = () => {
    if (inflight !== null) return inflight;
    const result = unready();
    const work = callbacksNeeded.map((key) => {
      const callback = readiness[key];
      if (callback === undefined) return Promise.resolve();
      return Promise.resolve()
        .then(() => callback())
        .then((ready) => {
          result[key] = ready === true;
        })
        .catch(() => {
          result[key] = false;
        });
    });
    const batch = {
      promise: Promise.all(work).then(() => snapshot(result)),
      result,
    };
    inflight = batch;
    void batch.promise.finally(() => {
      if (inflight === batch) inflight = null;
    });
    return batch;
  };

  const boundedReadiness = async (): Promise<ReadinessResult> => {
    if (callbacksNeeded.length === 0) return snapshot(unready());
    const batch = joinBatch();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<ReadinessResult>((resolve) => {
      timer = setTimeout(() => resolve(snapshot(batch.result)), READINESS_DEADLINE_MS);
      timer.unref?.();
    });
    try {
      return await Promise.race([batch.promise, deadline]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  };

  app.all(
    PAYMENT_CAPABILITIES_PATH,
    {
      onRequest: async (request) => {
        enforceTransport(request, appOrigin);
      },
    },
    async (request, reply) => {
      const state = paymentCapabilityState(flags, await boundedReadiness());
      return sendEnvelope(
        request,
        reply,
        options.buildSha,
        buildPaymentCapabilityManifest(state),
        maxResponseBytes,
      );
    },
  );
}
