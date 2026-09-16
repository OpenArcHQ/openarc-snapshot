/**
 * Minimal agent client for the real OpenArc commerce surfaces.
 *
 * Exactly one credential class is ever presented: a single
 * `Authorization: Bearer oacs_v1_…` commerce session. No cookie, Origin, CSRF,
 * client marker or machine credential is sent, and the token never appears in a
 * URL, a query string or a returned value. Every response is parsed with the
 * accepted shared wire schemas, so a malformed or mis-bound answer is a refusal
 * rather than something the lane acts on.
 */
import {
  CommerceActionMutationDataSchema,
  CommerceGrantIssueDataSchema,
  CommercePaymentAttemptDispatchDataSchema,
  CommercePaymentAttemptPersistDataSchema,
  CommercePaymentAttemptReadDataSchema,
  CommercePaymentVerifiedRequirementSchema,
  type CommerceActionMutationData,
  type CommerceGrantIssueData,
  type CommercePaymentAttempt,
  type CommercePaymentAttemptPersistData,
  type CommercePaymentVerifiedRequirement,
} from "@openarc/shared";
import { randomBytes, randomUUID } from "node:crypto";
import type { ZodType } from "zod";

import { sendHeadlessRequest } from "./http.js";
import { assertLoopbackOrigin } from "./loopback.js";

const COMMERCE_TOKEN = /^oacs_v1_[A-Za-z0-9_-]{43}(?![\s\S])/u;
const MAX_RESPONSE_BYTES = 1_048_576;

export type ApiResult<T> =
  | { readonly ok: true; readonly httpStatus: number; readonly data: T }
  | {
      readonly ok: false;
      readonly httpStatus: number | null;
      readonly code: string;
      readonly retryable: boolean | null;
    };

export interface AgentApiOptions {
  readonly apiBaseUrl: string;
  readonly commerceSessionToken: string;
  readonly timeoutMs?: number;
}

function idempotencyKey(): string {
  const bytes = randomBytes(32);
  bytes[31] = (bytes[31] as number) & 0b11;
  return bytes.toString("base64url");
}

function errorOf(status: number, body: unknown): ApiResult<never> {
  if (typeof body === "object" && body !== null) {
    const error = (body as { error?: unknown }).error;
    if (typeof error === "object" && error !== null) {
      const code = (error as { code?: unknown }).code;
      const retryable = (error as { retryable?: unknown }).retryable;
      return {
        ok: false,
        httpStatus: status,
        code: typeof code === "string" ? code : "unreadable_response",
        retryable: typeof retryable === "boolean" ? retryable : null,
      };
    }
  }
  return { ok: false, httpStatus: status, code: "unreadable_response", retryable: null };
}

export class AgentApiClient {
  readonly #base: string;
  readonly #token: string;
  readonly #timeoutMs: number;

  constructor(options: AgentApiOptions) {
    this.#base = assertLoopbackOrigin(options.apiBaseUrl, "apiBaseUrl");
    if (!COMMERCE_TOKEN.test(options.commerceSessionToken)) {
      throw new Error("COMMERCE_SESSION_TOKEN_INVALID");
    }
    this.#token = options.commerceSessionToken;
    this.#timeoutMs = options.timeoutMs ?? 15_000;
  }

  async #send<T>(
    method: "GET" | "POST",
    path: string,
    schema: ZodType<T>,
    body: Record<string, unknown> | null,
    withIdempotency: boolean,
  ): Promise<ApiResult<T>> {
    const headers: Record<string, string> = {
      authorization: `Bearer ${this.#token}`,
      accept: "application/json",
    };
    if (body !== null) headers["content-type"] = "application/json";
    if (withIdempotency) headers["idempotency-key"] = idempotencyKey();
    let status: number;
    let text: string;
    try {
      // Raw node:http: global fetch would add `sec-fetch-mode`, which every
      // agent route rejects outright.
      const response = await sendHeadlessRequest({
        url: new URL(path, this.#base).toString(),
        method,
        headers,
        ...(body === null ? {} : { body: JSON.stringify(body) }),
        timeoutMs: this.#timeoutMs,
      });
      status = response.status;
      text = response.text;
    } catch {
      return { ok: false, httpStatus: null, code: "transport_failed", retryable: null };
    }
    if (text.length > MAX_RESPONSE_BYTES) {
      return { ok: false, httpStatus: status, code: "oversized_response", retryable: null };
    }
    let parsedBody: unknown;
    try {
      parsedBody = JSON.parse(text) as unknown;
    } catch {
      return { ok: false, httpStatus: status, code: "unreadable_response", retryable: null };
    }
    if (status !== 200) return errorOf(status, parsedBody);
    const data = (parsedBody as { data?: unknown }).data;
    const parsed = schema.safeParse(data);
    if (!parsed.success) {
      return { ok: false, httpStatus: status, code: "unreadable_response", retryable: null };
    }
    return { ok: true, httpStatus: status, data: parsed.data };
  }

  registerRequirement(
    requirementId: string,
    listingId: string,
  ): Promise<ApiResult<CommercePaymentVerifiedRequirement>> {
    return this.#send(
      "POST",
      "/v2/agent/commerce-payment-requirements",
      CommercePaymentVerifiedRequirementSchema,
      { requirementId, listingId },
      false,
    );
  }

  authorizeAction(
    actionId: string,
    requirementId: string,
  ): Promise<ApiResult<CommerceActionMutationData>> {
    return this.#send(
      "POST",
      "/v2/agent/commerce-actions",
      CommerceActionMutationDataSchema,
      { mutationId: randomUUID(), actionId, requirementId },
      true,
    );
  }

  issueGrant(actionId: string): Promise<ApiResult<CommerceGrantIssueData>> {
    return this.#send(
      "POST",
      "/v2/agent/commerce-grants",
      CommerceGrantIssueDataSchema,
      { mutationId: randomUUID(), actionId },
      true,
    );
  }

  persistAttempt(
    body: Record<string, unknown>,
  ): Promise<ApiResult<CommercePaymentAttemptPersistData>> {
    return this.#send(
      "POST",
      "/v2/agent/commerce-payment-attempts",
      CommercePaymentAttemptPersistDataSchema,
      body,
      false,
    );
  }

  async recordDispatch(
    attemptId: string,
    bindingDigest: string,
  ): Promise<ApiResult<CommercePaymentAttempt>> {
    const result = await this.#send(
      "POST",
      `/v2/agent/commerce-payment-attempts/${attemptId}/dispatch`,
      CommercePaymentAttemptDispatchDataSchema,
      { bindingDigest },
      false,
    );
    return result.ok ? { ok: true, httpStatus: result.httpStatus, data: result.data.attempt } : result;
  }

  async readAttempt(attemptId: string): Promise<ApiResult<CommercePaymentAttempt | null>> {
    const result = await this.#send(
      "GET",
      `/v2/agent/commerce-payment-attempts/${attemptId}`,
      CommercePaymentAttemptReadDataSchema,
      null,
      false,
    );
    return result.ok ? { ok: true, httpStatus: result.httpStatus, data: result.data.item } : result;
  }
}
