import {
  API_CLIENT_HEADER,
  API_MAX_RESPONSE_BYTES,
  COMMERCE_API_SCHEMA_VERSION,
  SESSION_CAPABILITIES_PATH,
  SESSION_ROUTES,
  SessionCapabilitiesSuccessEnvelopeSchema,
  CommerceApiErrorEnvelopeSchema,
  CommerceApiMetaSchema,
  CommerceControlSessionIssueBodySchema,
  CommerceControlSessionIssueResultResponseSchema,
  CommerceControlSessionListLimitSchema,
  CommerceControlSessionListRequestSchema,
  CommerceControlSessionListResponseSchema,
  CommerceControlSessionMutationStatusResponseSchema,
  CommerceControlSessionRequestSchema,
  CommerceControlSessionRevokeBodySchema,
  CommerceControlSessionRevokeResultResponseSchema,
  CommerceControlSessionStatusResponseSchema,
  CommerceOrganizationIdSchema,
  CommerceControlSessionIdSchema,
  CommerceTenantIdempotencyKeySchema,
  CommerceTenantMutationIdSchema,
  type CommerceApiErrorCode,
  type CommerceControlSessionIssueResult,
  type CommerceControlSessionList,
  type CommerceControlSessionMutationStatus,
  type CommerceControlSessionRevokeResult,
  type CommerceControlSessionStatus,
  type SessionCapabilityState,
} from "@openarc/shared";

// Own commerce-session transport.
//
// It is deliberately independent of the account, tenant read/write, machine
// credential, marketplace-listing and policy-management transports. Every path
// is built from the frozen SEVEN-entry `SESSION_ROUTES` registry plus ONE
// validated canonical id per segment, encoded exactly once. There is no
// caller-supplied URL, no bearer credential, no machine credential and no
// redirect following.
//
// Reads send only the same-origin browser cookie and the browser marker
// (`X-OpenArc-Client`); writes additionally send the transient CSRF token and
// an idempotency key as HTTP headers only. The SEPARATE, public,
// credentialless session-capability probe (credentials: "omit", no marker, no
// CSRF) decides only whether the surface is enabled and NEVER grants role
// authority. Raw one-time handoff tokens appear only in a fresh issue result;
// every other shape (list, status, receipt, replay) cannot represent them. This
// module never writes a secret to storage, the URL, history, a log or analytics.
//
// Every request is bounded to 10 seconds total and 64 KiB of streamed JSON,
// with no automatic retry. Error mapping is fixed and never echoes server text,
// raw ids or raw payloads.

/** Exactly the five browser commerce_session_management route ids. */
export const SESSION_ROUTE_IDS = Object.freeze(
  SESSION_ROUTES.filter((route) => route.family === "commerce_session_management").map(
    (route) => route.id,
  ),
);

export type SessionClientRouteId = (typeof SESSION_ROUTE_IDS)[number];

/** The exact logical operation a human write performs. */
export type SessionMutationOperation =
  | "control.commerce_session.issue"
  | "control.commerce_session.revoke";

export type SessionApiFailure =
  | { kind: "aborted" }
  | { kind: "pre-send" }
  | { kind: "outcome-unknown" }
  | { kind: "validation" }
  | { kind: "policy" }
  | { kind: "conflict" }
  | { kind: "not-found" }
  | { kind: "unauthenticated" }
  | { kind: "csrf" }
  | { kind: "forbidden" }
  | { kind: "feature-disabled" }
  | { kind: "unavailable" }
  | { kind: "invalid-response" };

export class SessionApiError extends Error {
  readonly failure: SessionApiFailure;

  constructor(failure: SessionApiFailure) {
    super(failure.kind);
    this.name = "SessionApiError";
    this.failure = failure;
  }
}

export type SessionFetch = typeof fetch;

type RuntimeSchema<T> = {
  safeParse(value: unknown): { success: true; data: T } | { success: false };
};

export const SESSION_PAGE_LIMIT = 50;
export const SESSION_MAX_BODY_BYTES = 16 * 1024;
export const SESSION_REQUEST_TIMEOUT_MS = 10_000;

const ROUTE_BY_ID = Object.freeze(
  Object.fromEntries(SESSION_ROUTES.map((route) => [route.id, route])),
) as Readonly<Record<string, (typeof SESSION_ROUTES)[number]>>;

function routeTemplate(id: SessionClientRouteId): string {
  const route = ROUTE_BY_ID[id];
  if (
    route === undefined ||
    route.family !== "commerce_session_management" ||
    route.audience !== "browser"
  ) {
    throw new SessionApiError({ kind: "pre-send" });
  }
  return route.path;
}

function fillPath(id: SessionClientRouteId, params: Readonly<Record<string, string>>): string {
  let path = routeTemplate(id);
  for (const [key, value] of Object.entries(params)) {
    path = path.replace(`:${key}`, encodeURIComponent(value));
  }
  if (path.includes(":")) throw new SessionApiError({ kind: "pre-send" });
  return path;
}

function scopedOrganization(id: string): string {
  const parsed = CommerceOrganizationIdSchema.safeParse(id);
  if (!parsed.success) throw new SessionApiError({ kind: "pre-send" });
  return parsed.data;
}

function scopedSession(id: string): string {
  const parsed = CommerceControlSessionIdSchema.safeParse(id);
  if (!parsed.success) throw new SessionApiError({ kind: "pre-send" });
  return parsed.data;
}

function scopedMutationId(mutationId: string): string {
  const parsed = CommerceTenantMutationIdSchema.safeParse(mutationId);
  if (!parsed.success) throw new SessionApiError({ kind: "pre-send" });
  return parsed.data;
}

function boundedLimit(limit: number | undefined): number {
  const value = limit ?? 25;
  if (!Number.isInteger(value) || value < 1 || value > SESSION_PAGE_LIMIT) {
    throw new SessionApiError({ kind: "pre-send" });
  }
  // The wire limit is a canonical string 1..50; re-validate it exactly.
  if (!CommerceControlSessionListLimitSchema.safeParse(String(value)).success) {
    throw new SessionApiError({ kind: "pre-send" });
  }
  return value;
}

/** Canonical ascending ordering for accepted session ids. */
function compareCanonicalId(left: string, right: string): number {
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

// A bounded page must not exceed the exact requested limit, and when a
// continuation cursor was requested its first row must strictly follow that
// cursor. This is a client-local binding on TOP of the shared page schema.
function assertPageBounds(
  items: readonly { metadata: { sessionId: string } }[],
  limit: number,
  cursor: string | null,
): void {
  if (items.length > limit) throw new SessionApiError({ kind: "invalid-response" });
  if (cursor === null) return;
  const first = items[0];
  if (first === undefined) return;
  if (compareCanonicalId(first.metadata.sessionId, cursor) <= 0) {
    throw new SessionApiError({ kind: "invalid-response" });
  }
}

interface WriteCommon {
  readonly csrfToken: string;
  readonly idempotencyKey: string;
  readonly signal: AbortSignal;
}

export interface SessionIssueRequest extends WriteCommon {
  readonly organizationId: string;
  readonly body: unknown;
}

export interface SessionRevokeRequest extends WriteCommon {
  readonly organizationId: string;
  readonly sessionId: string;
  readonly body: unknown;
}

export interface SessionClientOptions {
  readonly fetcher?: SessionFetch;
}

interface RequestInput {
  readonly method: "GET" | "POST";
  readonly path: string;
  readonly headers?: Record<string, string>;
  readonly body?: string;
  readonly signal: AbortSignal;
  readonly write: boolean;
}

export class SessionClient {
  readonly #fetcher: SessionFetch;

  constructor(options: SessionClientOptions = {}) {
    this.#fetcher = options.fetcher ?? fetch;
  }

  async listSessions(
    read: { organizationId: string; afterSessionId?: string | null; limit?: number },
    signal: AbortSignal,
  ): Promise<CommerceControlSessionList> {
    const request = parseRequest(CommerceControlSessionListRequestSchema, {
      organizationId: read.organizationId,
      ...(read.afterSessionId === undefined || read.afterSessionId === null
        ? {}
        : { afterSessionId: read.afterSessionId }),
      ...(read.limit === undefined ? {} : { limit: String(read.limit) }),
    });
    const organizationId = scopedOrganization(request.organizationId);
    const afterSessionId =
      request.afterSessionId === undefined ? null : scopedSession(request.afterSessionId);
    const limit = boundedLimit(read.limit);
    const query = new URLSearchParams();
    if (afterSessionId !== null) query.set("afterSessionId", afterSessionId);
    query.set("limit", String(limit));
    const decoded = await this.#request({
      method: "GET",
      path: `${fillPath("commerce_session_list", { organizationId })}?${query.toString()}`,
      signal,
      write: false,
    });
    const page = parseSuccessEnvelope(decoded, CommerceControlSessionListResponseSchema);
    if (page.organizationId !== organizationId) {
      throw new SessionApiError({ kind: "invalid-response" });
    }
    assertPageBounds(page.items, limit, afterSessionId);
    return page;
  }

  async readSession(
    read: { organizationId: string; sessionId: string },
    signal: AbortSignal,
  ): Promise<CommerceControlSessionStatus> {
    const request = parseRequest(CommerceControlSessionRequestSchema, read);
    const organizationId = scopedOrganization(request.organizationId);
    const sessionId = scopedSession(request.sessionId);
    const decoded = await this.#request({
      method: "GET",
      path: fillPath("commerce_session_status", { organizationId, sessionId }),
      signal,
      write: false,
    });
    const status = parseSuccessEnvelope(decoded, CommerceControlSessionStatusResponseSchema);
    if (status.organizationId !== organizationId) {
      throw new SessionApiError({ kind: "invalid-response" });
    }
    if (status.item !== null && status.item.metadata.sessionId !== sessionId) {
      throw new SessionApiError({ kind: "invalid-response" });
    }
    return status;
  }

  // Issues ONE fresh human handoff session. The database generates the
  // canonical session UUID and returns the raw `oach_v1_` handoff token exactly
  // once in the `available_once` delivery; a replay carries no secret.
  async issue(input: SessionIssueRequest): Promise<CommerceControlSessionIssueResult> {
    const organizationId = scopedOrganization(input.organizationId);
    const body = parseBody(CommerceControlSessionIssueBodySchema, input.body);
    return this.#write(
      fillPath("commerce_session_issue", { organizationId }),
      body,
      input,
      {
        organizationId,
        operation: "control.commerce_session.issue",
        mutationId: body.mutationId,
        expectedResourceId: null,
      },
      CommerceControlSessionIssueResultResponseSchema,
    );
  }

  async revoke(input: SessionRevokeRequest): Promise<CommerceControlSessionRevokeResult> {
    const organizationId = scopedOrganization(input.organizationId);
    const sessionId = scopedSession(input.sessionId);
    const body = parseBody(CommerceControlSessionRevokeBodySchema, input.body);
    return this.#write(
      fillPath("commerce_session_revoke", { organizationId, sessionId }),
      body,
      input,
      {
        organizationId,
        operation: "control.commerce_session.revoke",
        mutationId: body.mutationId,
        expectedResourceId: sessionId,
      },
      CommerceControlSessionRevokeResultResponseSchema,
    );
  }

  // Explicit status GET with the ORIGINAL mutation id. The receipt must bind
  // the exact operation and resource the original logical write targeted.
  async readMutationStatus(
    read: {
      organizationId: string;
      mutationId: string;
      operation: SessionMutationOperation;
      expectedResourceId: string | null;
      signal: AbortSignal;
    },
  ): Promise<CommerceControlSessionMutationStatus> {
    const organizationId = scopedOrganization(read.organizationId);
    const mutationId = scopedMutationId(read.mutationId);
    const decoded = await this.#request({
      method: "GET",
      path: fillPath("commerce_session_human_mutation_status", { organizationId, mutationId }),
      signal: read.signal,
      write: false,
    });
    const status = parseSuccessEnvelope(decoded, CommerceControlSessionMutationStatusResponseSchema);
    if (status.organizationId !== organizationId || status.mutationId !== mutationId) {
      throw new SessionApiError({ kind: "invalid-response" });
    }
    if (status.status === "committed") {
      const receipt = status.receipt;
      if (receipt.operation !== read.operation) {
        throw new SessionApiError({ kind: "invalid-response" });
      }
      if (receipt.mutationId !== mutationId) {
        throw new SessionApiError({ kind: "invalid-response" });
      }
      if (read.expectedResourceId !== null && receipt.resourceId !== read.expectedResourceId) {
        throw new SessionApiError({ kind: "invalid-response" });
      }
    }
    return status;
  }

  async #write<T>(
    path: string,
    body: { mutationId: string },
    common: WriteCommon,
    expected: {
      organizationId: string;
      operation: SessionMutationOperation;
      mutationId: string;
      expectedResourceId: string | null;
    },
    schema: {
      safeParse(value: unknown):
        | { success: true; data: { ok: true; data: T; meta: unknown } }
        | { success: false };
    },
  ): Promise<T> {
    if (common.csrfToken.length === 0) throw new SessionApiError({ kind: "pre-send" });
    if (!CommerceTenantIdempotencyKeySchema.safeParse(common.idempotencyKey).success) {
      throw new SessionApiError({ kind: "pre-send" });
    }
    let serialized: string;
    try {
      serialized = JSON.stringify(body);
    } catch {
      throw new SessionApiError({ kind: "pre-send" });
    }
    if (new TextEncoder().encode(serialized).byteLength > SESSION_MAX_BODY_BYTES) {
      throw new SessionApiError({ kind: "pre-send" });
    }
    const headers: Record<string, string> = {
      "X-OpenArc-Client": API_CLIENT_HEADER,
      "Content-Type": "application/json",
      Accept: "application/json",
      "X-OpenArc-CSRF": common.csrfToken,
      "Idempotency-Key": common.idempotencyKey,
    };
    const decoded = await this.#request({
      method: "POST",
      path,
      headers,
      body: serialized,
      signal: common.signal,
      write: true,
    });
    const result = parseSuccessEnvelope(decoded, schema);
    assertMutationBinding(result, expected);
    return result;
  }

  async #request(input: RequestInput): Promise<unknown> {
    if (input.signal.aborted) throw new SessionApiError({ kind: "aborted" });
    const fetcher = this.#fetcher;
    // ONE total deadline covers response headers AND the streamed body.
    const deadline = new AbortController();
    const timer = setTimeout(() => deadline.abort(), SESSION_REQUEST_TIMEOUT_MS);
    const combined = combineSignals(input.signal, deadline.signal);
    try {
      let response: Response;
      try {
        response = await fetcher(input.path, {
          method: input.method,
          headers:
            input.headers ??
            { "X-OpenArc-Client": API_CLIENT_HEADER, Accept: "application/json" },
          ...(input.body === undefined ? {} : { body: input.body }),
          credentials: "same-origin",
          cache: "no-store",
          redirect: "error",
          referrerPolicy: "no-referrer",
          signal: combined,
        });
      } catch {
        if (input.signal.aborted) throw new SessionApiError({ kind: "aborted" });
        if (input.write) throw new SessionApiError({ kind: "outcome-unknown" });
        throw new SessionApiError({ kind: "unavailable" });
      }
      let decoded: unknown;
      try {
        decoded = await decodeJson(response, combined);
      } catch (error) {
        if (input.signal.aborted) throw new SessionApiError({ kind: "aborted" });
        if (!response.ok) throw new SessionApiError(mapHttpFailure(response.status, undefined, input.write));
        if (error instanceof SessionApiError && error.failure.kind === "aborted") {
          throw new SessionApiError(input.write ? { kind: "outcome-unknown" } : { kind: "unavailable" });
        }
        throw new SessionApiError(input.write ? { kind: "outcome-unknown" } : { kind: "invalid-response" });
      }
      if (!response.ok) {
        throw new SessionApiError(mapHttpFailure(response.status, decoded, input.write));
      }
      return decoded;
    } finally {
      clearTimeout(timer);
    }
  }
}

function parseRequest<T>(schema: RuntimeSchema<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new SessionApiError({ kind: "pre-send" });
  return parsed.data;
}

function parseBody<T>(schema: RuntimeSchema<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new SessionApiError({ kind: "pre-send" });
  return parsed.data;
}

function parseSuccessEnvelope<T>(
  decoded: unknown,
  schema: {
    safeParse(value: unknown):
      | { success: true; data: { ok: true; data: T; meta: unknown } }
      | { success: false };
  },
): T {
  if (typeof decoded !== "object" || decoded === null) throw new SessionApiError({ kind: "invalid-response" });
  const record = decoded as { ok?: unknown; meta?: unknown };
  if (record.ok !== true) throw new SessionApiError({ kind: "invalid-response" });
  const keys = Object.keys(record).sort();
  if (keys.length !== 3 || keys[0] !== "data" || keys[1] !== "meta" || keys[2] !== "ok") {
    throw new SessionApiError({ kind: "invalid-response" });
  }
  const meta = CommerceApiMetaSchema.safeParse(record.meta);
  if (!meta.success || meta.data.schemaVersion !== COMMERCE_API_SCHEMA_VERSION) {
    throw new SessionApiError({ kind: "invalid-response" });
  }
  const parsed = schema.safeParse(decoded);
  if (!parsed.success) throw new SessionApiError({ kind: "invalid-response" });
  return parsed.data.data;
}

// The exact correlation a receipt must bind. `expectedResourceId` is null only
// for an issue, where the database generates the canonical session resource;
// the strict wire receipt already guarantees that resource is a canonical
// UUIDv4 and never a guessed mutation-derived id.
function assertMutationBinding(
  result: unknown,
  expected: {
    organizationId: string;
    operation: SessionMutationOperation;
    mutationId: string;
    expectedResourceId: string | null;
  },
): void {
  if (typeof result !== "object" || result === null) {
    throw new SessionApiError({ kind: "invalid-response" });
  }
  const outer = result as { organizationId?: unknown; receipt?: unknown };
  if (outer.organizationId !== expected.organizationId) {
    throw new SessionApiError({ kind: "invalid-response" });
  }
  if (typeof outer.receipt !== "object" || outer.receipt === null) {
    throw new SessionApiError({ kind: "invalid-response" });
  }
  const receipt = outer.receipt as { operation?: unknown; mutationId?: unknown; resourceId?: unknown };
  if (receipt.operation !== expected.operation) throw new SessionApiError({ kind: "invalid-response" });
  if (receipt.mutationId !== expected.mutationId) throw new SessionApiError({ kind: "invalid-response" });
  if (expected.expectedResourceId !== null && receipt.resourceId !== expected.expectedResourceId) {
    throw new SessionApiError({ kind: "invalid-response" });
  }
}

function mapHttpFailure(status: number, decoded: unknown, write: boolean): SessionApiFailure {
  const envelope = CommerceApiErrorEnvelopeSchema.safeParse(decoded);
  if (envelope.success) return mapErrorCode(envelope.data.error.code, write);
  switch (status) {
    case 400:
      return { kind: "validation" };
    case 401:
      return { kind: "unauthenticated" };
    case 403:
      return { kind: "forbidden" };
    case 404:
      return { kind: "not-found" };
    case 409:
      return { kind: "conflict" };
    case 429:
      return { kind: "unavailable" };
    case 503:
      return write ? { kind: "outcome-unknown" } : { kind: "unavailable" };
    default:
      if (status >= 500) return write ? { kind: "outcome-unknown" } : { kind: "unavailable" };
      return write ? { kind: "outcome-unknown" } : { kind: "invalid-response" };
  }
}

function mapErrorCode(code: CommerceApiErrorCode, write: boolean): SessionApiFailure {
  switch (code) {
    case "INVALID_REQUEST":
    case "UNSUPPORTED_MEDIA_TYPE":
    case "REQUEST_TOO_LARGE":
      return { kind: "validation" };
    case "POLICY_DENIED":
    case "APPROVAL_REQUIRED":
    case "BUDGET_LIMIT_EXCEEDED":
    case "GRANT_EXPIRED":
    case "GRANT_REVOKED":
    case "GRANT_ALREADY_USED":
      return { kind: "policy" };
    case "IDEMPOTENCY_CONFLICT":
    case "BUDGET_RESERVATION_CONFLICT":
    case "JOB_STATE_CONFLICT":
      return { kind: "conflict" };
    case "UNAUTHENTICATED":
      return { kind: "unauthenticated" };
    case "CSRF_REJECTED":
    case "INVALID_ORIGIN":
      return { kind: "csrf" };
    case "FORBIDDEN":
    case "TENANT_MISMATCH":
      return { kind: "forbidden" };
    case "FEATURE_DISABLED":
      return { kind: "feature-disabled" };
    case "SOURCE_UNAVAILABLE":
    case "INTERNAL_ERROR":
    case "RATE_LIMITED":
    default:
      return write ? { kind: "outcome-unknown" } : { kind: "unavailable" };
  }
}

async function decodeJson(response: Response, signal: AbortSignal): Promise<unknown> {
  const type = response.headers.get("content-type");
  if (!type || !/^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(type)) {
    throw new SessionApiError({ kind: "invalid-response" });
  }
  const length = response.headers.get("content-length");
  if (length !== null && (!/^(?:0|[1-9]\d{0,9})$/u.test(length) || Number(length) > API_MAX_RESPONSE_BYTES)) {
    throw new SessionApiError({ kind: "invalid-response" });
  }
  if (response.body === null) throw new SessionApiError({ kind: "invalid-response" });
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const next = await readOrAbort(reader, signal);
      if (next.done) break;
      if (signal.aborted) throw new SessionApiError({ kind: "aborted" });
      total += next.value.byteLength;
      if (total > API_MAX_RESPONSE_BYTES) throw new SessionApiError({ kind: "invalid-response" });
      chunks.push(next.value);
    }
  } catch (error) {
    if (error instanceof SessionApiError) throw error;
    if (signal.aborted) throw new SessionApiError({ kind: "aborted" });
    throw new SessionApiError({ kind: "invalid-response" });
  } finally {
    void reader.cancel().catch(() => undefined);
  }
  if (signal.aborted) throw new SessionApiError({ kind: "aborted" });
  if (length !== null && total !== Number(length)) throw new SessionApiError({ kind: "invalid-response" });
  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.length;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(combined));
  } catch {
    throw new SessionApiError({ kind: "invalid-response" });
  }
}

function combineSignals(caller: AbortSignal, deadline: AbortSignal): AbortSignal {
  const anySignal = (
    AbortSignal as unknown as { any?: (signals: AbortSignal[]) => AbortSignal }
  ).any;
  if (typeof anySignal === "function") return anySignal([caller, deadline]);
  const controller = new AbortController();
  const onAbort = () => controller.abort();
  if (caller.aborted || deadline.aborted) {
    controller.abort();
    return controller.signal;
  }
  caller.addEventListener("abort", onAbort, { once: true });
  deadline.addEventListener("abort", onAbort, { once: true });
  return controller.signal;
}

function readOrAbort(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  signal: AbortSignal,
): ReturnType<ReadableStreamDefaultReader<Uint8Array>["read"]> {
  if (signal.aborted) return Promise.reject(new SessionApiError({ kind: "aborted" }));
  return new Promise((resolve, reject) => {
    const onAbort = () => {
      void reader.cancel().catch(() => undefined);
      reject(new SessionApiError({ kind: "aborted" }));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    reader.read().then(
      (result) => {
        signal.removeEventListener("abort", onAbort);
        resolve(result);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

// Independent credentialless session-capability transport. It sends NO cookies,
// NO client marker, NO CSRF token and NO bearer credential: the session
// capability manifest is public and is used only to decide whether the session
// surface is enabled, never as a grant of role authority. A `built_disabled` or
// `unavailable` state is returned truthfully and never turned into a fabricated
// empty list.
export async function readCommerceSessionsCapability(
  signal: AbortSignal,
  fetcher: SessionFetch = fetch,
): Promise<SessionCapabilityState> {
  if (signal.aborted) throw new SessionApiError({ kind: "aborted" });
  const deadline = new AbortController();
  const timer = setTimeout(() => deadline.abort(), SESSION_REQUEST_TIMEOUT_MS);
  const combined = combineSignals(signal, deadline.signal);
  try {
    let response: Response;
    try {
      response = await fetcher(SESSION_CAPABILITIES_PATH, {
        method: "GET",
        credentials: "omit",
        cache: "no-store",
        redirect: "error",
        referrerPolicy: "no-referrer",
        signal: combined,
      });
    } catch {
      if (signal.aborted) throw new SessionApiError({ kind: "aborted" });
      throw new SessionApiError({ kind: "unavailable" });
    }
    let decoded: unknown;
    try {
      decoded = await decodeJson(response, combined);
    } catch (error) {
      if (signal.aborted) throw new SessionApiError({ kind: "aborted" });
      if (!response.ok) throw new SessionApiError(mapHttpFailure(response.status, undefined, false));
      if (error instanceof SessionApiError && error.failure.kind === "invalid-response") throw error;
      throw new SessionApiError({ kind: "unavailable" });
    }
    if (!response.ok) throw new SessionApiError(mapHttpFailure(response.status, decoded, false));
    const parsed = SessionCapabilitiesSuccessEnvelopeSchema.safeParse(decoded);
    if (!parsed.success) throw new SessionApiError({ kind: "invalid-response" });
    const entry = parsed.data.data.capabilities.find(
      (capability) => capability.family === "commerce_session_management",
    );
    if (entry === undefined) throw new SessionApiError({ kind: "invalid-response" });
    return entry.state;
  } finally {
    clearTimeout(timer);
  }
}

const IDEMPOTENCY_KEY_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function canonicalBase64Url(bytes: Uint8Array): string {
  let out = "";
  for (let index = 0; index < bytes.length; index += 3) {
    const b0 = bytes[index] as number;
    const b1 = index + 1 < bytes.length ? (bytes[index + 1] as number) : 0;
    const b2 = index + 2 < bytes.length ? (bytes[index + 2] as number) : 0;
    const triplet = (b0 << 16) | (b1 << 8) | b2;
    out += IDEMPOTENCY_KEY_ALPHABET[(triplet >> 18) & 0x3f];
    out += IDEMPOTENCY_KEY_ALPHABET[(triplet >> 12) & 0x3f];
    if (index + 1 < bytes.length) out += IDEMPOTENCY_KEY_ALPHABET[(triplet >> 6) & 0x3f];
    if (index + 2 < bytes.length) out += IDEMPOTENCY_KEY_ALPHABET[triplet & 0x3f];
  }
  return out;
}

function randomBytes(length: number, cryptoSource?: Crypto): Uint8Array {
  const source =
    cryptoSource ??
    (typeof globalThis.crypto === "undefined" ? undefined : globalThis.crypto);
  if (source === undefined) throw new SessionApiError({ kind: "pre-send" });
  const bytes = new Uint8Array(length);
  source.getRandomValues(bytes);
  return bytes;
}

/** One canonical RFC 4122 v4 UUID mutation id per logical write. */
export function createSessionMutationId(cryptoSource?: Crypto): string {
  const bytes = randomBytes(16, cryptoSource);
  bytes[6] = ((bytes[6] as number) & 0x0f) | 0x40;
  bytes[8] = ((bytes[8] as number) & 0x3f) | 0x80;
  const hex: string[] = [];
  for (const byte of bytes) hex.push(byte.toString(16).padStart(2, "0"));
  const raw = hex.join("");
  const candidate = `${raw.slice(0, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}-${raw.slice(16, 20)}-${raw.slice(20)}`;
  const parsed = CommerceTenantMutationIdSchema.safeParse(candidate);
  if (!parsed.success) throw new SessionApiError({ kind: "pre-send" });
  return parsed.data;
}

/** One canonical 43-character 32-byte base64url idempotency key per write. */
export function createSessionIdempotencyKey(cryptoSource?: Crypto): string {
  const bytes = randomBytes(32, cryptoSource);
  bytes[31] = (bytes[31] as number) & 0b11;
  const candidate = canonicalBase64Url(bytes);
  const parsed = CommerceTenantIdempotencyKeySchema.safeParse(candidate);
  if (!parsed.success) throw new SessionApiError({ kind: "pre-send" });
  return parsed.data;
}

export interface SessionCorrelation {
  readonly mutationId: string;
  readonly idempotencyKey: string;
}

export function createSessionCorrelation(cryptoSource?: Crypto): SessionCorrelation {
  return {
    mutationId: createSessionMutationId(cryptoSource),
    idempotencyKey: createSessionIdempotencyKey(cryptoSource),
  };
}
