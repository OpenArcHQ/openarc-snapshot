/**
 * Reference x402 provider for the pinned Arc-testnet lane. TESTNET REFERENCE.
 *
 * It serves one paid resource — the deterministic integer sum already declared
 * by `tools/reference-provider` — and it exists to prove the buyer flow end to
 * end with NO network egress:
 *
 *   1. an unpaid request gets a 402 whose single requirement is built from the
 *      pinned lane manifest and whose `payTo` is the SELLER's recorded payment
 *      terms, passed in by the operator and never invented here. The envelope
 *      is re-parsed with `parseLaneRequirement` before it is served, so a
 *      misconfigured provider fails closed instead of advertising a bad term;
 *   2. a paid request is CLAIMED through the real OpenArc provider claim API
 *      before anything is delivered;
 *   3. the presented payment is verified offline by `packages/x402` against the
 *      exact issued requirement and the claimed grant;
 *   4. the payment is persisted provider-side, then settled EXACTLY ONCE
 *      through the injected facilitator transport.
 *
 * DELIVERY HAPPENS ONLY ON `accepted`. A timeout, a settle error reason, a 500,
 * an unreadable answer and every other outcome are `unknown` and HELD: the
 * resource is not served, and the lane never re-signs or re-sends. A second
 * paid request for the same attempt is refused before any facilitator call.
 *
 * Nothing here signs a buyer payment, moves funds, or contacts Circle, Gateway
 * or Arc. No signature, grant token or provider session is logged or returned.
 */
import {
  ARC_TESTNET_LANE,
  LANE_PAYMENT_HEADER,
  acceptReceivedLanePayment,
  createLaneFacilitatorClient,
  parseLanePaymentRequired,
  persistLanePayment,
  type LaneDigest,
  type LaneFetch,
  type LanePaymentRequired,
  type LaneSettleObservation,
} from "@openarc/x402";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

import { ReferenceProviderError, assertLoopbackBaseUrl } from "./loopback.js";
import { createProviderClaimClient, type GrantClaim } from "./claim-client.js";

/** Matches the accepted `tools/reference-provider` declared operation. */
export const REFERENCE_INPUT_SCHEMA = "openarc.reference-input.v1" as const;
export const REFERENCE_OUTPUT_SCHEMA = "openarc.reference-output.v1" as const;

/** The SDK middleware's own value; the lane's ceiling is 604800 + 3600. */
const REQUIREMENT_TIMEOUT_SECONDS = 604_900;
const MAX_BODY_BYTES = 32 * 1024;
const MAX_OPERAND = 1_000_000;
const ADDRESS = /^0x[0-9a-fA-F]{40}(?![\s\S])/u;
const UINT = /^[1-9][0-9]{0,77}(?![\s\S])/u;
const ATTEMPT_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\s\S])/u;
const ACTION_ID =
  /^openarc:action:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\s\S])/u;
const GRANT_TOKEN = /^oag_v1_[A-Za-z0-9_-]{43}(?![\s\S])/u;

export interface ReferenceProviderOptions {
  /** Loopback OpenArc API. Used only for the real provider claim. */
  readonly apiBaseUrl: string;
  /** Live `oas_pr_` provider session for the claim family. */
  readonly providerSessionToken: string;
  /** The seller's RECORDED pay-to. The provider never derives one itself. */
  readonly payToAddress: string;
  /** The listing's recorded atomic price. */
  readonly amountAtomic: string;
  /** Injected facilitator transport. There is no default and no global fetch. */
  readonly facilitator: LaneFetch;
  readonly facilitatorTimeoutMs?: number;
  readonly resourcePath?: string;
  readonly nowUnixSeconds?: () => number;
  /** Seam for tests: the real claim client is the default. */
  readonly claim?: GrantClaim;
}

export interface ReferenceProviderCounts {
  readonly requirementsServed: number;
  readonly paidRequests: number;
  readonly claims: number;
  readonly settles: number;
  readonly delivered: number;
  readonly refused: number;
  readonly held: number;
}

export interface ReferenceProvider {
  readonly url: string;
  readonly resourceUrl: string;
  counts(): ReferenceProviderCounts;
  close(): Promise<void>;
}

interface PaidRequestBody {
  readonly grantToken: string;
  readonly actionId: string;
  readonly attemptId: string;
  readonly input: { readonly a: number; readonly b: number };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parsePaidBody(value: unknown): PaidRequestBody | null {
  if (!isRecord(value) || !isRecord(value["input"])) return null;
  const grantToken = value["grantToken"];
  const actionId = value["actionId"];
  const attemptId = value["attemptId"];
  const a = value["input"]["a"];
  const b = value["input"]["b"];
  if (
    typeof grantToken !== "string" || !GRANT_TOKEN.test(grantToken) ||
    typeof actionId !== "string" || !ACTION_ID.test(actionId) ||
    typeof attemptId !== "string" || !ATTEMPT_ID.test(attemptId) ||
    typeof a !== "number" || !Number.isInteger(a) || a < 0 || a > MAX_OPERAND ||
    typeof b !== "number" || !Number.isInteger(b) || b < 0 || b > MAX_OPERAND
  ) {
    return null;
  }
  return { grantToken, actionId, attemptId, input: { a, b } };
}

function readBody(request: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("BODY_TOO_LARGE"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    request.on("error", () => reject(new Error("BODY_READ_FAILED")));
  });
}

function json(response: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    ...headers,
  });
  response.end(JSON.stringify(body));
}

function encodeEnvelope(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64");
}

export async function startReferenceProvider(
  options: ReferenceProviderOptions,
): Promise<ReferenceProvider> {
  if (typeof options.payToAddress !== "string" || !ADDRESS.test(options.payToAddress)) {
    throw new ReferenceProviderError("provider_misconfigured", "payToAddress");
  }
  if (typeof options.amountAtomic !== "string" || !UINT.test(options.amountAtomic)) {
    throw new ReferenceProviderError("provider_misconfigured", "amountAtomic");
  }
  if (typeof options.facilitator !== "function") {
    throw new ReferenceProviderError("provider_misconfigured", "facilitator");
  }
  // Refuses a public API host before the server ever listens.
  assertLoopbackBaseUrl(options.apiBaseUrl, "apiBaseUrl");

  const resourcePath = options.resourcePath ?? "/v1/sum";
  const now = options.nowUnixSeconds ?? (() => Math.floor(Date.now() / 1000));
  const claim: GrantClaim =
    options.claim ??
    createProviderClaimClient({
      apiBaseUrl: options.apiBaseUrl,
      providerSessionToken: options.providerSessionToken,
    });
  const facilitator = createLaneFacilitatorClient({
    network: ARC_TESTNET_LANE.caip2,
    facilitatorOrigin: ARC_TESTNET_LANE.facilitatorOrigin,
    fetch: options.facilitator,
    timeoutMs: options.facilitatorTimeoutMs ?? 2_000,
  });

  const counts = {
    requirementsServed: 0,
    paidRequests: 0,
    claims: 0,
    settles: 0,
    delivered: 0,
    refused: 0,
    held: 0,
  };
  /** Provider-side durable record. One attempt is settleable exactly once. */
  const attempts = new Map<string, { bindingDigest: LaneDigest; used: boolean }>();

  const server: Server = createServer((request, response) => {
    void handle(request, response).catch(() => {
      if (!response.headersSent) json(response, 500, { status: "refused", code: "provider_error" });
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  const origin = `http://127.0.0.1:${address.port}`;
  const resourceUrl = `${origin}${resourcePath}`;

  /** The exact envelope this provider issues, built from the pinned manifest. */
  function paymentRequiredEnvelope(): Record<string, unknown> {
    return {
      x402Version: ARC_TESTNET_LANE.x402Version,
      error: "payment_required",
      resource: {
        url: resourceUrl,
        description: "OpenArc reference sum",
        mimeType: "application/json",
      },
      accepts: [
        {
          scheme: ARC_TESTNET_LANE.scheme,
          network: ARC_TESTNET_LANE.caip2,
          asset: ARC_TESTNET_LANE.asset.address,
          amount: options.amountAtomic,
          payTo: options.payToAddress,
          maxTimeoutSeconds: REQUIREMENT_TIMEOUT_SECONDS,
          extra: {
            name: ARC_TESTNET_LANE.eip712.name,
            version: ARC_TESTNET_LANE.eip712.version,
            verifyingContract: ARC_TESTNET_LANE.eip712.verifyingContract,
          },
        },
      ],
    };
  }

  // Fail closed at start-up: an envelope this lane would not accept is never
  // served. A misconfigured pay-to that is structurally valid is still served
  // (only the buyer and the database can know the seller's recorded terms).
  const issued: LanePaymentRequired = parseLanePaymentRequired(paymentRequiredEnvelope());

  async function settleOnce(
    header: string,
    body: PaidRequestBody,
    grant: unknown,
  ): Promise<LaneSettleObservation> {
    const unpersisted = await acceptReceivedLanePayment({
      header,
      paymentRequired: issued,
      grant,
      attemptId: body.attemptId,
      nowUnixSeconds: now(),
    });
    const persisted = await persistLanePayment(unpersisted, async (record) => {
      if (attempts.has(body.attemptId)) throw new Error("ATTEMPT_ALREADY_PERSISTED");
      attempts.set(body.attemptId, { bindingDigest: record.bindingDigest, used: true });
      return { bindingDigest: record.bindingDigest };
    });
    counts.settles += 1;
    return facilitator.settle(persisted);
  }

  async function handlePaid(
    request: IncomingMessage,
    response: ServerResponse,
    header: string,
  ): Promise<void> {
    counts.paidRequests += 1;
    let parsedBody: unknown;
    try {
      parsedBody = JSON.parse(await readBody(request)) as unknown;
    } catch {
      counts.refused += 1;
      json(response, 400, { status: "refused", code: "invalid_body" });
      return;
    }
    const body = parsePaidBody(parsedBody);
    if (body === null) {
      counts.refused += 1;
      json(response, 400, { status: "refused", code: "invalid_body" });
      return;
    }
    // Exactly-once: a repeated paid request never reaches the facilitator.
    if (attempts.has(body.attemptId)) {
      counts.refused += 1;
      json(response, 409, { status: "refused", code: "attempt_already_settled" });
      return;
    }

    // The REAL claim, before any delivery.
    counts.claims += 1;
    const claimed = await claim({
      grantToken: body.grantToken,
      actionId: body.actionId,
      attemptId: body.attemptId,
    });
    if (claimed.outcome !== "claimed") {
      counts.refused += 1;
      json(response, 409, {
        status: "refused",
        code: "grant_claim_refused",
        claim: { httpStatus: claimed.httpStatus, code: claimed.code },
      });
      return;
    }

    let settled: LaneSettleObservation;
    try {
      settled = await settleOnce(header, body, claimed.grant);
    } catch (error) {
      // A rejected payment is refused WITHOUT settling. The grant is already
      // claimed and its exposure stays held; nothing is released here.
      counts.refused += 1;
      const code = (error as { code?: unknown }).code;
      json(response, 400, {
        status: "refused",
        code: "payment_rejected",
        lane: typeof code === "string" ? code : "invalid_payment_payload",
      });
      return;
    }

    if (settled.outcome !== "accepted") {
      // Unknown is HELD: no resource, no retry, no second send.
      counts.held += 1;
      json(response, 202, {
        status: "held",
        settlement: {
          outcome: "unknown",
          reason: settled.reason,
          httpStatus: settled.httpStatus,
          errorReason: settled.errorReason,
        },
      });
      return;
    }

    counts.delivered += 1;
    json(response, 200, {
      status: "delivered",
      result: {
        schemaVersion: REFERENCE_OUTPUT_SCHEMA,
        sum: body.input.a + body.input.b,
      },
      settlement: { outcome: "accepted", transferId: settled.transferId },
    });
  }

  async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const url = new URL(request.url ?? "/", origin);
    if (url.pathname !== resourcePath) {
      json(response, 404, { status: "refused", code: "not_found" });
      return;
    }
    const header = request.headers[LANE_PAYMENT_HEADER.toLowerCase()];
    if (typeof header === "string" && header.length > 0) {
      if (request.method !== "POST") {
        counts.refused += 1;
        json(response, 405, { status: "refused", code: "method_not_allowed" });
        return;
      }
      await handlePaid(request, response, header);
      return;
    }
    if (request.method !== "GET" && request.method !== "POST") {
      json(response, 405, { status: "refused", code: "method_not_allowed" });
      return;
    }
    counts.requirementsServed += 1;
    const envelope = paymentRequiredEnvelope();
    json(response, 402, envelope, { "PAYMENT-REQUIRED": encodeEnvelope(envelope) });
  }

  return {
    url: origin,
    resourceUrl,
    counts: () => Object.freeze({ ...counts }),
    close: async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
