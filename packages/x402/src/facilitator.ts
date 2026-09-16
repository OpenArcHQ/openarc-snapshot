import { z } from "zod";

import type { PersistedLanePayment } from "./authorization.js";
import { parseLanePaymentBinding, type LanePaymentBinding } from "./binding.js";
import { X402LaneError } from "./errors.js";
import { assertLaneFacilitatorOrigin, resolveLaneNetwork, type LaneNetworkManifest } from "./manifest.js";
import { takeForDispatch } from "./payment-state.js";
import { isPlainObject, isStrictAddressString, isUuid, sameAddress } from "./primitives.js";
import {
  GATEWAY_SETTLE_ERROR_REASONS,
  classifyLaneAttempt,
  type GatewaySettleErrorReason,
  type LaneExposure,
  type LaneLookupObservation,
  type LaneSettleObservation,
  type LaneTransferRecord,
} from "./resolution.js";

export interface LaneFetchInit {
  readonly method: "GET" | "POST";
  readonly headers: Readonly<Record<string, string>>;
  readonly body?: string;
  readonly signal: AbortSignal;
  /** A redirect (e.g. to a mainnet origin) is an error, never followed. */
  readonly redirect: "error";
  readonly credentials: "omit";
}

export interface LaneFetchResponse {
  readonly status: number;
  text(): Promise<string>;
}

export type LaneFetch = (url: string, init: LaneFetchInit) => Promise<LaneFetchResponse>;

export interface LaneFacilitatorConfig {
  readonly network: string;
  readonly facilitatorOrigin: string;
  /** Required. There is no global-fetch default. */
  readonly fetch: LaneFetch;
  readonly timeoutMs: number;
}

export type LaneSupportedCheck =
  | { readonly outcome: "matches" }
  | { readonly outcome: "drift"; readonly fields: readonly string[] }
  | { readonly outcome: "unavailable"; readonly reason: "timeout" | "transport_error" | "http_error" | "malformed" };

/**
 * Exactly one facilitator, one network, no hooks, no fallback scheme, no retry.
 * Every method performs at most one HTTP request.
 */
export interface LaneFacilitatorClient {
  readonly network: LaneNetworkManifest["caip2"];
  readonly facilitatorOrigin: LaneNetworkManifest["facilitatorOrigin"];
  settle(payment: PersistedLanePayment): Promise<LaneSettleObservation>;
  lookupTransfers(binding: LanePaymentBinding): Promise<LaneLookupObservation>;
  resolveAttempt(
    binding: LanePaymentBinding,
    options: { readonly nowUnixSeconds: bigint | number; readonly settle?: LaneSettleObservation },
  ): Promise<LaneExposure>;
  checkSupported(): Promise<LaneSupportedCheck>;
}

const CONFIG_KEYS = new Set(["network", "facilitatorOrigin", "fetch", "timeoutMs"]);
const MAX_TIMEOUT_MS = 120_000;
const MAX_RESPONSE_CHARS = 1_048_576;

type RawResult =
  | { readonly kind: "response"; readonly status: number; readonly text: string }
  | { readonly kind: "timeout" }
  | { readonly kind: "transport_error" };

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

const TransferRecordSchema = z.object({
  id: z.string(),
  status: z.string(),
  fromAddress: z.string(),
  toAddress: z.string(),
  amount: z.string(),
  nonce: z.string(),
  sendingNetwork: z.string(),
  recipientNetwork: z.string(),
  txHash: z.string().nullable(),
});

const TransfersResponseSchema = z.object({
  transfers: z.array(z.unknown()).max(100),
  pagination: z.object({ next: z.string().optional() }).optional(),
});

export function createLaneFacilitatorClient(config: LaneFacilitatorConfig): LaneFacilitatorClient {
  if (!isPlainObject(config)) {
    throw new X402LaneError("invalid_config", ["<root>:not_plain_object"]);
  }
  const extraKeys = Object.keys(config).filter((key) => !CONFIG_KEYS.has(key));
  if (extraKeys.length > 0) {
    // Refuses fallbackScheme, facilitators[], onSettleFailure, retry, headers, url, ...
    throw new X402LaneError("invalid_config", extraKeys.map((key) => `${key}:not_allowed`));
  }
  const manifest = resolveLaneNetwork(config.network);
  const origin = assertLaneFacilitatorOrigin(manifest, config.facilitatorOrigin);
  if (typeof config.fetch !== "function") {
    throw new X402LaneError("invalid_config", ["fetch:required"]);
  }
  if (!Number.isSafeInteger(config.timeoutMs) || config.timeoutMs < 1 || config.timeoutMs > MAX_TIMEOUT_MS) {
    throw new X402LaneError("invalid_config", ["timeoutMs:out_of_range"]);
  }
  const fetchOnce = config.fetch;
  const timeoutMs = config.timeoutMs;

  async function requestOnce(pathAndQuery: string, method: "GET" | "POST", body?: string): Promise<RawResult> {
    const url = new URL(pathAndQuery, origin);
    if (url.origin !== origin) {
      throw new X402LaneError("facilitator_origin_rejected", ["url:origin_changed"]);
    }
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timedOut = new Promise<RawResult>((resolve) => {
      timer = setTimeout(() => {
        controller.abort();
        resolve({ kind: "timeout" });
      }, timeoutMs);
    });
    const headers: Record<string, string> = { Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const init: LaneFetchInit =
      body === undefined
        ? { method, headers, signal: controller.signal, redirect: "error", credentials: "omit" }
        : { method, headers, body, signal: controller.signal, redirect: "error", credentials: "omit" };
    const attempt = (async (): Promise<RawResult> => {
      try {
        const response = await fetchOnce(url.toString(), init);
        const text = await response.text();
        return { kind: "response", status: response.status, text };
      } catch {
        return controller.signal.aborted ? { kind: "timeout" } : { kind: "transport_error" };
      }
    })();
    try {
      return await Promise.race([attempt, timedOut]);
    } finally {
      clearTimeout(timer);
    }
  }

  function unknownSettle(
    reason: Extract<LaneSettleObservation, { outcome: "unknown" }>["reason"],
    httpStatus: number | null,
    errorReason: GatewaySettleErrorReason | "unrecognized" | null = null,
  ): LaneSettleObservation {
    return Object.freeze({ outcome: "unknown", reason, httpStatus, errorReason });
  }

  async function settle(payment: PersistedLanePayment): Promise<LaneSettleObservation> {
    const { record, wire } = takeForDispatch(payment, "provider");
    record.wire = null;
    const body = JSON.stringify({ paymentPayload: wire, paymentRequirements: wire.accepted });
    const raw = await requestOnce("/v1/x402/settle", "POST", body);
    if (raw.kind !== "response") return unknownSettle(raw.kind, null);
    if (raw.text.length > MAX_RESPONSE_CHARS) return unknownSettle("unexpected_response", raw.status);
    const data = parseJson(raw.text);
    if (!isPlainObject(data) || typeof data.success !== "boolean") {
      return unknownSettle("unexpected_response", raw.status);
    }
    if (data.success !== true) {
      const known = (GATEWAY_SETTLE_ERROR_REASONS as readonly string[]).includes(String(data.errorReason))
        ? (data.errorReason as GatewaySettleErrorReason)
        : "unrecognized";
      return unknownSettle("settle_error_reason", raw.status, known);
    }
    if (raw.status !== 200 || !isUuid(data.transaction) || typeof data.network !== "string") {
      return unknownSettle("incomplete_acceptance", raw.status);
    }
    if (data.network !== record.binding.network) {
      return unknownSettle("acceptance_mismatch", raw.status);
    }
    if (!isStrictAddressString(data.payer)) {
      return unknownSettle("incomplete_acceptance", raw.status);
    }
    if (!sameAddress(data.payer, record.binding.from)) {
      return unknownSettle("acceptance_mismatch", raw.status);
    }
    return Object.freeze({
      outcome: "accepted",
      transferId: data.transaction,
      network: record.binding.network,
      payer: record.binding.from,
    });
  }

  async function lookupTransfers(bindingInput: LanePaymentBinding): Promise<LaneLookupObservation> {
    const binding = parseLanePaymentBinding(bindingInput);
    const query = new URLSearchParams({ from: binding.from, nonce: binding.nonce, network: manifest.caip2 });
    const raw = await requestOnce(`/v1/x402/transfers?${query.toString().replaceAll("%3A", ":")}`, "GET");
    if (raw.kind !== "response") return Object.freeze({ kind: raw.kind });
    if (raw.status !== 200) return Object.freeze({ kind: "http_error", status: raw.status });
    if (raw.text.length > MAX_RESPONSE_CHARS) return Object.freeze({ kind: "malformed" });
    const parsed = TransfersResponseSchema.safeParse(parseJson(raw.text));
    if (!parsed.success) return Object.freeze({ kind: "malformed" });
    const transfers: LaneTransferRecord[] = [];
    for (const item of parsed.data.transfers) {
      const record = TransferRecordSchema.safeParse(item);
      if (!record.success) return Object.freeze({ kind: "malformed" });
      transfers.push(Object.freeze({ ...record.data }));
    }
    return Object.freeze({
      kind: "records",
      transfers: Object.freeze(transfers),
      hasMorePages: parsed.data.pagination?.next !== undefined,
    });
  }

  async function resolveAttempt(
    binding: LanePaymentBinding,
    options: { readonly nowUnixSeconds: bigint | number; readonly settle?: LaneSettleObservation },
  ): Promise<LaneExposure> {
    const lookup = await lookupTransfers(binding);
    return classifyLaneAttempt(
      options.settle === undefined
        ? { binding, nowUnixSeconds: options.nowUnixSeconds, lookup }
        : { binding, nowUnixSeconds: options.nowUnixSeconds, lookup, settle: options.settle },
    );
  }

  async function checkSupported(): Promise<LaneSupportedCheck> {
    const raw = await requestOnce("/v1/x402/supported", "GET");
    if (raw.kind !== "response") return Object.freeze({ outcome: "unavailable", reason: raw.kind });
    if (raw.status !== 200) return Object.freeze({ outcome: "unavailable", reason: "http_error" });
    const data = parseJson(raw.text);
    if (!isPlainObject(data) || !Array.isArray(data.kinds)) {
      return Object.freeze({ outcome: "unavailable", reason: "malformed" });
    }
    const kinds = data.kinds.filter((kind) => isPlainObject(kind) && kind.network === manifest.caip2);
    const kind = kinds[0];
    if (kinds.length !== 1 || !isPlainObject(kind)) {
      return Object.freeze({ outcome: "drift", fields: Object.freeze(["kinds:not_exactly_one"]) });
    }
    const fields: string[] = [];
    const extra = isPlainObject(kind.extra) ? kind.extra : {};
    if (kind.x402Version !== manifest.x402Version) fields.push("x402Version");
    if (kind.scheme !== manifest.scheme) fields.push("scheme");
    if (extra.name !== manifest.eip712.name) fields.push("extra.name");
    if (extra.version !== manifest.eip712.version) fields.push("extra.version");
    if (typeof extra.verifyingContract !== "string" || !sameAddress(extra.verifyingContract, manifest.eip712.verifyingContract)) {
      fields.push("extra.verifyingContract");
    }
    if (extra.minValiditySeconds !== manifest.minValiditySeconds) fields.push("extra.minValiditySeconds");
    const assets = Array.isArray(extra.assets) ? extra.assets : [];
    const usdc = assets.filter(
      (asset) =>
        isPlainObject(asset) &&
        typeof asset.address === "string" &&
        sameAddress(asset.address, manifest.asset.address) &&
        asset.decimals === manifest.asset.decimals,
    );
    if (usdc.length !== 1) fields.push("extra.assets");
    return fields.length === 0
      ? Object.freeze({ outcome: "matches" })
      : Object.freeze({ outcome: "drift", fields: Object.freeze(fields) });
  }

  return Object.freeze({
    network: manifest.caip2,
    facilitatorOrigin: origin,
    settle,
    lookupTransfers,
    resolveAttempt,
    checkSupported,
  });
}
