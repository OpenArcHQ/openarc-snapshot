import {
  API_CLIENT_HEADER,
  API_MAX_RESPONSE_BYTES,
  COMMERCE_API_SCHEMA_VERSION,
  CommerceApiErrorEnvelopeSchema,
  CommerceApiMetaSchema,
  CommerceGrantDetailRequestSchema,
  CommerceGrantDetailResponseSchema,
  CommerceGrantHumanMutationRequestSchema,
  CommerceGrantHumanMutationStatusResponseSchema,
  CommerceGrantIdSchema,
  CommerceGrantRevokeBodySchema,
  CommerceGrantRevokeDataResponseSchema,
  CommerceOrganizationIdSchema,
  CommerceTenantIdempotencyKeySchema,
  CommerceTenantMutationIdSchema,
  GRANT_CAPABILITIES_PATH,
  GRANT_ROUTES,
  GrantCapabilitiesSuccessEnvelopeSchema,
  type CommerceApiErrorCode,
  type CommerceGrantDetail,
  type CommerceGrantHumanMutationStatus,
  type CommerceGrantRevokeData,
  type GrantCapabilityState,
} from "@openarc/shared";

// Own authorization-grant management transport.
//
// It is deliberately independent of the account, tenant read/write, machine
// credential, marketplace-listing, policy, commerce-session and commerce-action
// transports. Every path is built from the frozen NINE-entry `GRANT_ROUTES`
// registry, filtered to the THREE `commerce_grant_management` (browser)
// descriptors, plus ONE validated canonical id per segment, encoded exactly
// once. The three `commerce_grant_authorization` (agent) routes and the three
// `commerce_grant_claim` (provider) routes are headless and are refused here
// BEFORE any request is constructed: this module can never call them. The
// provider routes are the only two places a raw `oag_v1_` token is an inbound
// field anywhere on the grant wire, and this browser client cannot reach them.
//
// Reads send only the same-origin browser cookie and the browser marker
// (`X-OpenArc-Client`); the single revoke write additionally sends the
// transient CSRF token and an idempotency key as HTTP HEADERS ONLY — never in a
// URL, a query string, a body or a log. No shape on this wire can represent a
// raw grant token, cookie, CSRF value or session hash, and every decoded
// payload is additionally swept for grant-secret material before it is
// returned. The client never writes anything to storage, the URL, history, a
// log or analytics.
//
// Every request is bounded to 10 seconds total and to the shared response byte
// ceiling, with NO automatic retry and NO automatic resubmission. A revoke
// whose response is lost is reported as `outcome-unknown`; only an explicit,
// user-initiated status GET with the ORIGINAL mutation id can resolve it. Error
// mapping is fixed and never echoes server text, raw ids or raw payloads.
//
// Nothing here pays, settles, delivers, releases or refunds. Revocation is a
// flag; a grant already claimed keeps its claim fact and its held exposure.

/** Exactly the three browser `commerce_grant_management` route ids. */
export const GRANT_BROWSER_ROUTE_IDS: readonly string[] = Object.freeze(
  GRANT_ROUTES.filter((route) => route.family === "commerce_grant_management").map(
    (route) => route.id,
  ),
);

/** The three agent-audience ids this browser client must never call. */
export const GRANT_AGENT_ROUTE_IDS: readonly string[] = Object.freeze(
  GRANT_ROUTES.filter((route) => route.family === "commerce_grant_authorization").map(
    (route) => route.id,
  ),
);

/** The three provider-audience ids this browser client must never call. */
export const GRANT_PROVIDER_ROUTE_IDS: readonly string[] = Object.freeze(
  GRANT_ROUTES.filter((route) => route.family === "commerce_grant_claim").map(
    (route) => route.id,
  ),
);

export type GrantClientRouteId = (typeof GRANT_BROWSER_ROUTE_IDS)[number];

/**
 * The single logical operation a human grant write performs. The accepted
 * human mutation-status union admits no other operation, so a browser cookie
 * can never be handed an agent issue/replace or a provider claim receipt.
 */
export const GRANT_REVOKE_OPERATION = "control.grant.revoke" as const;

export type GrantMutationOperation = typeof GRANT_REVOKE_OPERATION;

export type GrantApiFailure =
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

export class GrantApiError extends Error {
  readonly failure: GrantApiFailure;

  constructor(failure: GrantApiFailure) {
    super(failure.kind);
    this.name = "GrantApiError";
    this.failure = failure;
  }
}

export type GrantFetch = typeof fetch;

type RuntimeSchema<T> = {
  safeParse(value: unknown): { success: true; data: T } | { success: false };
};

export const GRANT_MAX_BODY_BYTES = 16 * 1024;
export const GRANT_REQUEST_TIMEOUT_MS = 10_000;

const ROUTE_BY_ID = Object.freeze(
  Object.fromEntries(GRANT_ROUTES.map((route) => [route.id, route])),
) as Readonly<Record<string, (typeof GRANT_ROUTES)[number]>>;

/**
 * Resolves a frozen browser route template. An agent-audience id, a
 * provider-audience id, an unknown id or an inherited object property name is
 * refused BEFORE any request exists.
 */
function routeTemplate(id: GrantClientRouteId, method: "GET" | "POST"): string {
  if (!Object.hasOwn(ROUTE_BY_ID, id)) throw new GrantApiError({ kind: "pre-send" });
  const route = ROUTE_BY_ID[id];
  if (
    route === undefined ||
    route.family !== "commerce_grant_management" ||
    route.audience !== "browser" ||
    route.method !== method
  ) {
    throw new GrantApiError({ kind: "pre-send" });
  }
  return route.path;
}

function fillPath(
  id: GrantClientRouteId,
  method: "GET" | "POST",
  params: Readonly<Record<string, string>>,
): string {
  let path = routeTemplate(id, method);
  for (const [key, value] of Object.entries(params)) {
    path = path.replace(`:${key}`, encodeURIComponent(value));
  }
  if (path.includes(":")) throw new GrantApiError({ kind: "pre-send" });
  return path;
}

function scopedOrganization(id: string): string {
  const parsed = CommerceOrganizationIdSchema.safeParse(id);
  if (!parsed.success) throw new GrantApiError({ kind: "pre-send" });
  return parsed.data;
}

function scopedGrant(id: string): string {
  const parsed = CommerceGrantIdSchema.safeParse(id);
  if (!parsed.success) throw new GrantApiError({ kind: "pre-send" });
  return parsed.data;
}

function scopedMutationId(mutationId: string): string {
  const parsed = CommerceTenantMutationIdSchema.safeParse(mutationId);
  if (!parsed.success) throw new GrantApiError({ kind: "pre-send" });
  return parsed.data;
}

/**
 * The exact `oag_v1_<43 base64url>` grant-token grammar, restated locally so
 * this sweep never depends on a schema that might be relaxed elsewhere. It is
 * used ONLY to refuse secret-bearing material, never to accept it.
 */
const GRANT_SECRET_PATTERN = /oag_v1_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]/u;

/**
 * True when any string anywhere in a decoded payload looks like raw grant
 * secret material, or when any object key is a token-bearing name. The browser
 * family cannot represent a `grantToken` at all, so this is defence in depth on
 * top of the strict accepted schemas rather than the primary guarantee.
 */
export function containsGrantSecret(value: unknown, depth = 0): boolean {
  if (depth > 12) return true;
  if (typeof value === "string") return GRANT_SECRET_PATTERN.test(value);
  if (Array.isArray(value)) {
    return value.some((entry) => containsGrantSecret(entry, depth + 1));
  }
  if (typeof value === "object" && value !== null) {
    for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
      if (key === "grantToken" || key === "token" || key === "secret") return true;
      if (containsGrantSecret(entry, depth + 1)) return true;
    }
  }
  return false;
}

function assertNoGrantSecret<T>(value: T): T {
  if (containsGrantSecret(value)) throw new GrantApiError({ kind: "invalid-response" });
  return value;
}

export interface GrantRevokeRequest {
  readonly organizationId: string;
  readonly grantId: string;
  readonly csrfToken: string;
  readonly idempotencyKey: string;
  readonly signal: AbortSignal;
  readonly body: unknown;
}

export interface GrantClientOptions {
  readonly fetcher?: GrantFetch;
}

interface RequestInput {
  readonly method: "GET" | "POST";
  readonly path: string;
  readonly headers?: Record<string, string>;
  readonly body?: string;
  readonly signal: AbortSignal;
  readonly write: boolean;
}

export class GrantClient {
  readonly #fetcher: GrantFetch;

  constructor(options: GrantClientOptions = {}) {
    this.#fetcher = options.fetcher ?? fetch;
  }

  /**
   * One authorization grant, organization scoped. A missing grant and a
   * foreign grant are the same safe `null` item. The accepted metadata carries
   * no token, no token hash and no amount, so this read can expose neither a
   * grant secret nor an implied payment figure.
   */
  async readGrant(
    read: { organizationId: string; grantId: string },
    signal: AbortSignal,
  ): Promise<CommerceGrantDetail> {
    const request = parseRequest(CommerceGrantDetailRequestSchema, read);
    const organizationId = scopedOrganization(request.organizationId);
    const grantId = scopedGrant(request.grantId);
    const decoded = await this.#request({
      method: "GET",
      path: fillPath("grant_detail", "GET", { organizationId, grantId }),
      signal,
      write: false,
    });
    const detail = parseSuccessEnvelope(decoded, CommerceGrantDetailResponseSchema);
    if (detail.organizationId !== organizationId || detail.grantId !== grantId) {
      throw new GrantApiError({ kind: "invalid-response" });
    }
    return assertNoGrantSecret(detail);
  }

  /**
   * The single human grant write. Revocation is a flag, never an erasure: the
   * accepted body has no reason, force, release or cascade field, and a claimed
   * grant keeps `claimedAt` and its held exposure with `released` false.
   */
  async revoke(input: GrantRevokeRequest): Promise<CommerceGrantRevokeData> {
    const organizationId = scopedOrganization(input.organizationId);
    const grantId = scopedGrant(input.grantId);
    const body = parseBody(CommerceGrantRevokeBodySchema, input.body);
    if (input.csrfToken.length === 0) throw new GrantApiError({ kind: "pre-send" });
    if (!CommerceTenantIdempotencyKeySchema.safeParse(input.idempotencyKey).success) {
      throw new GrantApiError({ kind: "pre-send" });
    }
    let serialized: string;
    try {
      serialized = JSON.stringify(body);
    } catch {
      throw new GrantApiError({ kind: "pre-send" });
    }
    if (new TextEncoder().encode(serialized).byteLength > GRANT_MAX_BODY_BYTES) {
      throw new GrantApiError({ kind: "pre-send" });
    }
    // The CSRF token and idempotency key travel as HEADERS ONLY. They are never
    // placed in the path, the query string or the JSON body.
    const headers: Record<string, string> = {
      "X-OpenArc-Client": API_CLIENT_HEADER,
      "Content-Type": "application/json",
      Accept: "application/json",
      "X-OpenArc-CSRF": input.csrfToken,
      "Idempotency-Key": input.idempotencyKey,
    };
    const decoded = await this.#request({
      method: "POST",
      path: fillPath("grant_revoke", "POST", { organizationId, grantId }),
      headers,
      body: serialized,
      signal: input.signal,
      write: true,
    });
    const result = parseSuccessEnvelope(decoded, CommerceGrantRevokeDataResponseSchema);
    if (result.receipt.operation !== GRANT_REVOKE_OPERATION) {
      throw new GrantApiError({ kind: "invalid-response" });
    }
    if (result.receipt.mutationId !== body.mutationId) {
      throw new GrantApiError({ kind: "invalid-response" });
    }
    if (result.receipt.resourceId !== grantId) {
      throw new GrantApiError({ kind: "invalid-response" });
    }
    if (result.metadata.grantId !== grantId) {
      throw new GrantApiError({ kind: "invalid-response" });
    }
    if (result.metadata.organizationId !== organizationId) {
      throw new GrantApiError({ kind: "invalid-response" });
    }
    return assertNoGrantSecret(result);
  }

  /**
   * Explicit status GET with the ORIGINAL mutation id. It NEVER resubmits the
   * revoke and never mints a new id or key. The pure status union carries no
   * wrapper identity, so the receipt itself must bind the exact mutation,
   * operation and grant the original logical write targeted.
   */
  async readMutationStatus(read: {
    organizationId: string;
    mutationId: string;
    expectedResourceId: string;
    signal: AbortSignal;
  }): Promise<CommerceGrantHumanMutationStatus> {
    const request = parseRequest(CommerceGrantHumanMutationRequestSchema, {
      organizationId: read.organizationId,
      mutationId: read.mutationId,
    });
    const organizationId = scopedOrganization(request.organizationId);
    const mutationId = scopedMutationId(request.mutationId);
    const expectedResourceId = scopedGrant(read.expectedResourceId);
    const decoded = await this.#request({
      method: "GET",
      path: fillPath("grant_mutation_status", "GET", { organizationId, mutationId }),
      signal: read.signal,
      write: false,
    });
    const status = parseSuccessEnvelope(
      decoded,
      CommerceGrantHumanMutationStatusResponseSchema,
    );
    if (status.status === "committed") {
      const receipt = status.receipt;
      if (receipt.operation !== GRANT_REVOKE_OPERATION) {
        throw new GrantApiError({ kind: "invalid-response" });
      }
      if (receipt.mutationId !== mutationId) {
        throw new GrantApiError({ kind: "invalid-response" });
      }
      if (receipt.resourceId !== expectedResourceId) {
        throw new GrantApiError({ kind: "invalid-response" });
      }
    }
    return assertNoGrantSecret(status);
  }

  async #request(input: RequestInput): Promise<unknown> {
    if (input.signal.aborted) throw new GrantApiError({ kind: "aborted" });
    const fetcher = this.#fetcher;
    // ONE total deadline covers response headers AND the streamed body.
    const deadline = new AbortController();
    const timer = setTimeout(() => deadline.abort(), GRANT_REQUEST_TIMEOUT_MS);
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
        if (input.signal.aborted) throw new GrantApiError({ kind: "aborted" });
        // A revoke whose transport failed may still have been applied: it is
        // reported as unknown and is NEVER retried automatically.
        if (input.write) throw new GrantApiError({ kind: "outcome-unknown" });
        throw new GrantApiError({ kind: "unavailable" });
      }
      let decoded: unknown;
      try {
        decoded = await decodeJson(response, combined);
      } catch (error) {
        if (input.signal.aborted) throw new GrantApiError({ kind: "aborted" });
        if (!response.ok) {
          throw new GrantApiError(mapHttpFailure(response.status, undefined, input.write));
        }
        if (error instanceof GrantApiError && error.failure.kind === "aborted") {
          throw new GrantApiError(
            input.write ? { kind: "outcome-unknown" } : { kind: "unavailable" },
          );
        }
        throw new GrantApiError(
          input.write ? { kind: "outcome-unknown" } : { kind: "invalid-response" },
        );
      }
      if (!response.ok) {
        throw new GrantApiError(mapHttpFailure(response.status, decoded, input.write));
      }
      return decoded;
    } finally {
      clearTimeout(timer);
    }
  }
}

function parseRequest<T>(schema: RuntimeSchema<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new GrantApiError({ kind: "pre-send" });
  return parsed.data;
}

function parseBody<T>(schema: RuntimeSchema<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new GrantApiError({ kind: "pre-send" });
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
  if (typeof decoded !== "object" || decoded === null) {
    throw new GrantApiError({ kind: "invalid-response" });
  }
  const record = decoded as { ok?: unknown; meta?: unknown };
  if (record.ok !== true) throw new GrantApiError({ kind: "invalid-response" });
  const keys = Object.keys(record).sort();
  if (keys.length !== 3 || keys[0] !== "data" || keys[1] !== "meta" || keys[2] !== "ok") {
    throw new GrantApiError({ kind: "invalid-response" });
  }
  const meta = CommerceApiMetaSchema.safeParse(record.meta);
  if (!meta.success || meta.data.schemaVersion !== COMMERCE_API_SCHEMA_VERSION) {
    throw new GrantApiError({ kind: "invalid-response" });
  }
  const parsed = schema.safeParse(decoded);
  if (!parsed.success) throw new GrantApiError({ kind: "invalid-response" });
  return parsed.data.data;
}

function mapHttpFailure(status: number, decoded: unknown, write: boolean): GrantApiFailure {
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

/**
 * Fixed error mapping. `GRANT_EXPIRED`, `GRANT_REVOKED` and `GRANT_ALREADY_USED`
 * are policy refusals of the WRITE; none of them asserts that money moved back,
 * and none is ever rendered as a refund or a release.
 */
function mapErrorCode(code: CommerceApiErrorCode, write: boolean): GrantApiFailure {
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
    throw new GrantApiError({ kind: "invalid-response" });
  }
  const length = response.headers.get("content-length");
  if (
    length !== null &&
    (!/^(?:0|[1-9]\d{0,9})$/u.test(length) || Number(length) > API_MAX_RESPONSE_BYTES)
  ) {
    throw new GrantApiError({ kind: "invalid-response" });
  }
  if (response.body === null) throw new GrantApiError({ kind: "invalid-response" });
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const next = await readOrAbort(reader, signal);
      if (next.done) break;
      if (signal.aborted) throw new GrantApiError({ kind: "aborted" });
      total += next.value.byteLength;
      if (total > API_MAX_RESPONSE_BYTES) throw new GrantApiError({ kind: "invalid-response" });
      chunks.push(next.value);
    }
  } catch (error) {
    if (error instanceof GrantApiError) throw error;
    if (signal.aborted) throw new GrantApiError({ kind: "aborted" });
    throw new GrantApiError({ kind: "invalid-response" });
  } finally {
    void reader.cancel().catch(() => undefined);
  }
  if (signal.aborted) throw new GrantApiError({ kind: "aborted" });
  if (length !== null && total !== Number(length)) {
    throw new GrantApiError({ kind: "invalid-response" });
  }
  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.length;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(combined));
  } catch {
    throw new GrantApiError({ kind: "invalid-response" });
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
  if (signal.aborted) return Promise.reject(new GrantApiError({ kind: "aborted" }));
  return new Promise((resolve, reject) => {
    const onAbort = () => {
      void reader.cancel().catch(() => undefined);
      reject(new GrantApiError({ kind: "aborted" }));
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

/**
 * Independent credentialless grant-capability transport. It sends NO cookies,
 * NO client marker, NO CSRF token and NO bearer credential: the grant
 * capability manifest is public and decides only whether the browser grant
 * management surface is enabled — never a permission, a role, a live grant or a
 * spend authority. A `built_disabled` or `unavailable` state is returned
 * truthfully and is never turned into a fabricated grant record.
 */
export async function readCommerceGrantsCapability(
  signal: AbortSignal,
  fetcher: GrantFetch = fetch,
): Promise<GrantCapabilityState> {
  if (signal.aborted) throw new GrantApiError({ kind: "aborted" });
  const deadline = new AbortController();
  const timer = setTimeout(() => deadline.abort(), GRANT_REQUEST_TIMEOUT_MS);
  const combined = combineSignals(signal, deadline.signal);
  try {
    let response: Response;
    try {
      response = await fetcher(GRANT_CAPABILITIES_PATH, {
        method: "GET",
        credentials: "omit",
        cache: "no-store",
        redirect: "error",
        referrerPolicy: "no-referrer",
        signal: combined,
      });
    } catch {
      if (signal.aborted) throw new GrantApiError({ kind: "aborted" });
      throw new GrantApiError({ kind: "unavailable" });
    }
    let decoded: unknown;
    try {
      decoded = await decodeJson(response, combined);
    } catch (error) {
      if (signal.aborted) throw new GrantApiError({ kind: "aborted" });
      if (!response.ok) throw new GrantApiError(mapHttpFailure(response.status, undefined, false));
      if (error instanceof GrantApiError && error.failure.kind === "invalid-response") throw error;
      throw new GrantApiError({ kind: "unavailable" });
    }
    if (!response.ok) throw new GrantApiError(mapHttpFailure(response.status, decoded, false));
    const parsed = GrantCapabilitiesSuccessEnvelopeSchema.safeParse(decoded);
    if (!parsed.success) throw new GrantApiError({ kind: "invalid-response" });
    const entry = parsed.data.data.capabilities.find(
      (capability) => capability.family === "commerce_grant_management",
    );
    if (entry === undefined) throw new GrantApiError({ kind: "invalid-response" });
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
  if (source === undefined) throw new GrantApiError({ kind: "pre-send" });
  const bytes = new Uint8Array(length);
  source.getRandomValues(bytes);
  return bytes;
}

/** One canonical RFC 4122 v4 UUID mutation id per logical revoke. */
export function createGrantMutationId(cryptoSource?: Crypto): string {
  const bytes = randomBytes(16, cryptoSource);
  bytes[6] = ((bytes[6] as number) & 0x0f) | 0x40;
  bytes[8] = ((bytes[8] as number) & 0x3f) | 0x80;
  const hex: string[] = [];
  for (const byte of bytes) hex.push(byte.toString(16).padStart(2, "0"));
  const raw = hex.join("");
  const candidate = `${raw.slice(0, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}-${raw.slice(16, 20)}-${raw.slice(20)}`;
  const parsed = CommerceTenantMutationIdSchema.safeParse(candidate);
  if (!parsed.success) throw new GrantApiError({ kind: "pre-send" });
  return parsed.data;
}

/** One canonical 43-character 32-byte base64url idempotency key per revoke. */
export function createGrantIdempotencyKey(cryptoSource?: Crypto): string {
  const bytes = randomBytes(32, cryptoSource);
  bytes[31] = (bytes[31] as number) & 0b11;
  const candidate = canonicalBase64Url(bytes);
  const parsed = CommerceTenantIdempotencyKeySchema.safeParse(candidate);
  if (!parsed.success) throw new GrantApiError({ kind: "pre-send" });
  return parsed.data;
}

export interface GrantCorrelation {
  readonly mutationId: string;
  readonly idempotencyKey: string;
}

export function createGrantCorrelation(cryptoSource?: Crypto): GrantCorrelation {
  return {
    mutationId: createGrantMutationId(cryptoSource),
    idempotencyKey: createGrantIdempotencyKey(cryptoSource),
  };
}
