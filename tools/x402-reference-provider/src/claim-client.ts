/**
 * The REAL OpenArc provider claim call.
 *
 * The provider claims the buyer's grant through the accepted
 * `commerce_grant_claim` family (`POST /v2/provider/grants/claim`) before it
 * delivers anything: the live `oas_pr_` provider session is the transport
 * factor and the buyer's one-use `oag_v1_` token is the body factor. Neither
 * the provider session nor the grant token is ever logged, returned or placed
 * in a URL, and a refusal carries only the HTTP status and the closed API code.
 */
import {
  CommerceGrantProviderClaimDataSchema,
  type CommerceGrantProviderView,
} from "@openarc/shared";
import { randomUUID } from "node:crypto";

import { sendHeadlessRequest } from "./http.js";
import { assertLoopbackBaseUrl } from "./loopback.js";
import { createIdempotencyKey } from "./idempotency.js";

export type GrantClaimResult =
  | { readonly outcome: "claimed"; readonly grant: CommerceGrantProviderView }
  | {
      readonly outcome: "refused";
      readonly httpStatus: number | null;
      readonly code: string;
    };

export interface GrantClaimInput {
  readonly grantToken: string;
  readonly actionId: string;
  readonly attemptId: string;
}

export type GrantClaim = (input: GrantClaimInput) => Promise<GrantClaimResult>;

export interface ProviderClaimClientOptions {
  /** Loopback OpenArc API base URL. A public host is refused. */
  readonly apiBaseUrl: string;
  /** Live `oas_pr_` provider session. Never logged or echoed. */
  readonly providerSessionToken: string;
  readonly timeoutMs?: number;
}

const PROVIDER_TOKEN = /^oas_pr_[A-Za-z0-9_-]{43}(?![\s\S])/u;
const MAX_RESPONSE_BYTES = 256 * 1024;

function errorCode(body: unknown): string {
  if (typeof body !== "object" || body === null) return "unreadable_response";
  const error = (body as { error?: unknown }).error;
  if (typeof error !== "object" || error === null) return "unreadable_response";
  const code = (error as { code?: unknown }).code;
  return typeof code === "string" ? code : "unreadable_response";
}

export function createProviderClaimClient(options: ProviderClaimClientOptions): GrantClaim {
  const base = assertLoopbackBaseUrl(options.apiBaseUrl, "apiBaseUrl");
  if (!PROVIDER_TOKEN.test(options.providerSessionToken)) {
    throw new Error("PROVIDER_SESSION_TOKEN_INVALID");
  }
  const token = options.providerSessionToken;
  const timeoutMs = options.timeoutMs ?? 10_000;

  return async (input) => {
    try {
      // Raw node:http: global fetch would add `sec-fetch-mode`, which the
      // provider claim route rejects outright.
      const response = await sendHeadlessRequest({
        url: new URL("/v2/provider/grants/claim", base).toString(),
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
          "idempotency-key": createIdempotencyKey(),
          accept: "application/json",
        },
        body: JSON.stringify({
          mutationId: randomUUID(),
          grantToken: input.grantToken,
          expectedActionId: input.actionId,
          attemptId: input.attemptId,
        }),
        timeoutMs,
      });
      const text = response.text;
      if (text.length > MAX_RESPONSE_BYTES) {
        return { outcome: "refused", httpStatus: response.status, code: "oversized_response" };
      }
      let body: unknown;
      try {
        body = JSON.parse(text) as unknown;
      } catch {
        return { outcome: "refused", httpStatus: response.status, code: "unreadable_response" };
      }
      if (response.status !== 200) {
        return { outcome: "refused", httpStatus: response.status, code: errorCode(body) };
      }
      const data = (body as { data?: unknown }).data;
      const parsed = CommerceGrantProviderClaimDataSchema.safeParse(data);
      if (!parsed.success) {
        return { outcome: "refused", httpStatus: response.status, code: "unreadable_response" };
      }
      if (parsed.data.attemptId !== input.attemptId) {
        return { outcome: "refused", httpStatus: response.status, code: "attempt_mismatch" };
      }
      if (parsed.data.item.actionId !== input.actionId) {
        return { outcome: "refused", httpStatus: response.status, code: "action_mismatch" };
      }
      return { outcome: "claimed", grant: parsed.data.item };
    } catch {
      // A transport failure or timeout is a refusal: nothing is delivered.
      return { outcome: "refused", httpStatus: null, code: "claim_transport_failed" };
    }
  };
}
