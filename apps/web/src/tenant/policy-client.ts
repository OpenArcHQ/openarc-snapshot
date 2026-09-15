import {
  API_CLIENT_HEADER,
  API_MAX_RESPONSE_BYTES,
  COMMERCE_API_SCHEMA_VERSION,
  CONTROL_CAPABILITIES_PATH,
  CONTROL_ROUTES,
  CommerceApiErrorEnvelopeSchema,
  CommerceApiMetaSchema,
  CommerceOrganizationIdSchema,
  CommercePolicyAppendBodySchema,
  CommercePolicyCreateBodySchema,
  CommercePolicyHistoryPageResponseSchema,
  CommercePolicyHistoryRequestSchema,
  CommercePolicyIdSchema,
  CommercePolicyListRequestSchema,
  CommercePolicyMutationResultResponseSchema,
  CommercePolicyMutationStatusResponseSchema,
  CommercePolicyRevisionDetailResponseSchema,
  CommercePolicyRevisionNumberSchema,
  CommercePolicyRevisionRequestSchema,
  CommercePolicyRootDetailResponseSchema,
  CommercePolicyRootPageResponseSchema,
  CommercePolicyRootRequestSchema,
  CommercePolicyTransitionBodySchema,
  CommerceTenantIdempotencyKeySchema,
  CommerceTenantMutationIdSchema,
  ControlCapabilitiesSuccessEnvelopeSchema,
  type CommerceApiErrorCode,
  type CommercePolicyHistoryPage,
  type CommercePolicyMutationResult,
  type CommercePolicyMutationStatus,
  type CommercePolicyRevisionDetail,
  type CommercePolicyRootDetail,
  type CommercePolicyRootPage,
  type ControlCapabilityState,
} from "@openarc/shared";

// Own policy-management transport for the ten frozen `policy_management`
// control routes. It is deliberately independent of the account, tenant
// read/write, machine-credential and marketplace-listing transports.
//
// Every path is built here from the frozen registry template plus ONE validated
// canonical id per segment, encoded exactly once. There is no caller-supplied
// URL, no bearer credential and no redirect following. Reads send only the
// same-origin browser marker (`X-OpenArc-Client`); writes additionally send the
// transient CSRF token and an idempotency key as HTTP headers only. The
// capability probe is a SEPARATE narrow transport that omits credentials.
//
// Every request is bounded to 10 seconds total and 64 KiB of streamed JSON,
// with no automatic retry. Error mapping is fixed and never echoes server text,
// raw ids or raw payloads.

export const POLICY_ROUTE_IDS = Object.freeze([
  "policy_roots",
  "policy_create",
  "policy_root",
  "policy_revisions",
  "policy_revision_create",
  "policy_revision",
  "policy_pause",
  "policy_resume",
  "policy_revoke",
  "policy_mutation_status",
] as const);

export type PolicyRouteId = (typeof POLICY_ROUTE_IDS)[number];

/** The exact logical operation a write performs (internal discriminator). */
export type PolicyMutationOperation =
  | "control.policy.create"
  | "control.policy.revision.create"
  | "control.policy.pause"
  | "control.policy.resume"
  | "control.policy.revoke";

export type PolicyApiFailure =
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

export class PolicyApiError extends Error {
  readonly failure: PolicyApiFailure;

  constructor(failure: PolicyApiFailure) {
    super(failure.kind);
    this.name = "PolicyApiError";
    this.failure = failure;
  }
}

export type PolicyFetch = typeof fetch;

type RuntimeSchema<T> = {
  safeParse(value: unknown): { success: true; data: T } | { success: false };
};

export const POLICY_PAGE_LIMIT = 50;
export const POLICY_MAX_BODY_BYTES = 16 * 1024;
export const POLICY_REQUEST_TIMEOUT_MS = 10_000;

const ROUTE_BY_ID = Object.freeze(
  Object.fromEntries(CONTROL_ROUTES.map((route) => [route.id, route])),
) as Readonly<Record<string, (typeof CONTROL_ROUTES)[number]>>;

function routeTemplate(id: PolicyRouteId): string {
  const route = ROUTE_BY_ID[id];
  if (
    route === undefined ||
    route.family !== "policy_management" ||
    route.audience !== "browser"
  ) {
    throw new PolicyApiError({ kind: "pre-send" });
  }
  return route.path;
}

function fillPath(id: PolicyRouteId, params: Readonly<Record<string, string>>): string {
  let path = routeTemplate(id);
  for (const [key, value] of Object.entries(params)) {
    path = path.replace(`:${key}`, encodeURIComponent(value));
  }
  if (path.includes(":")) throw new PolicyApiError({ kind: "pre-send" });
  return path;
}

function scopedOrganization(id: string): string {
  const parsed = CommerceOrganizationIdSchema.safeParse(id);
  if (!parsed.success) throw new PolicyApiError({ kind: "pre-send" });
  return parsed.data;
}

function scopedPolicy(id: string): string {
  const parsed = CommercePolicyIdSchema.safeParse(id);
  if (!parsed.success) throw new PolicyApiError({ kind: "pre-send" });
  return parsed.data;
}

function scopedRevision(revision: string): string {
  const parsed = CommercePolicyRevisionNumberSchema.safeParse(revision);
  if (!parsed.success) throw new PolicyApiError({ kind: "pre-send" });
  return parsed.data;
}

function scopedMutationId(mutationId: string): string {
  const parsed = CommerceTenantMutationIdSchema.safeParse(mutationId);
  if (!parsed.success) throw new PolicyApiError({ kind: "pre-send" });
  return parsed.data;
}

function boundedLimit(limit: number | undefined): number {
  const value = limit ?? 25;
  if (!Number.isInteger(value) || value < 1 || value > POLICY_PAGE_LIMIT) {
    throw new PolicyApiError({ kind: "pre-send" });
  }
  return value;
}

/** Canonical ascending ordering for accepted policy ids. */
function compareCanonicalId(left: string, right: string): number {
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

/** Numeric ascending ordering for accepted canonical revisions. */
function compareCanonicalRevision(left: string, right: string): number {
  const a = BigInt(left);
  const b = BigInt(right);
  return a === b ? 0 : a < b ? -1 : 1;
}

// A bounded page must not exceed the exact requested limit, and when a
// continuation cursor was requested its first row must strictly follow that
// cursor. This is a client-local binding on TOP of the shared page schema.
function assertPageBounds<Row>(
  items: readonly Row[],
  limit: number,
  cursor: string | null,
  keyOf: (row: Row) => string,
  compare: (left: string, right: string) => number,
): void {
  if (items.length > limit) throw new PolicyApiError({ kind: "invalid-response" });
  if (cursor === null) return;
  const first = items[0];
  if (first === undefined) return;
  if (compare(keyOf(first), cursor) <= 0) throw new PolicyApiError({ kind: "invalid-response" });
}

interface WriteCommon {
  readonly csrfToken: string;
  readonly idempotencyKey: string;
  readonly signal: AbortSignal;
}

export interface PolicyCreateRequest extends WriteCommon {
  readonly organizationId: string;
  readonly body: unknown;
}

export interface PolicyAppendRequest extends WriteCommon {
  readonly organizationId: string;
  readonly policyId: string;
  readonly body: unknown;
}

export interface PolicyTransitionRequest extends WriteCommon {
  readonly organizationId: string;
  readonly policyId: string;
  readonly body: unknown;
}

export interface PolicyClientOptions {
  readonly fetcher?: PolicyFetch;
}

interface RequestInput {
  readonly method: "GET" | "POST";
  readonly path: string;
  readonly headers?: Record<string, string>;
  readonly body?: string;
  readonly signal: AbortSignal;
  readonly write: boolean;
}

export class PolicyClient {
  readonly #fetcher: PolicyFetch;

  constructor(options: PolicyClientOptions = {}) {
    this.#fetcher = options.fetcher ?? fetch;
  }

  async listRoots(
    read: { organizationId: string; afterPolicyId?: string | null; limit?: number },
    signal: AbortSignal,
  ): Promise<CommercePolicyRootPage> {
    const request = parseRequest(CommercePolicyListRequestSchema, {
      organizationId: read.organizationId,
      ...(read.afterPolicyId === undefined || read.afterPolicyId === null
        ? {}
        : { afterPolicyId: read.afterPolicyId }),
      ...(read.limit === undefined ? {} : { limit: String(read.limit) }),
    });
    const organizationId = scopedOrganization(request.organizationId);
    const afterPolicyId =
      request.afterPolicyId === undefined ? null : scopedPolicy(request.afterPolicyId);
    const limit = boundedLimit(read.limit);
    const query = new URLSearchParams();
    if (afterPolicyId !== null) query.set("afterPolicyId", afterPolicyId);
    query.set("limit", String(limit));
    const decoded = await this.#request({
      method: "GET",
      path: `${fillPath("policy_roots", { organizationId })}?${query.toString()}`,
      signal,
      write: false,
    });
    const page = parseSuccessEnvelope(decoded, CommercePolicyRootPageResponseSchema);
    if (page.organizationId !== organizationId) {
      throw new PolicyApiError({ kind: "invalid-response" });
    }
    assertPageBounds(page.items, limit, afterPolicyId, (item) => item.policyId, compareCanonicalId);
    return page;
  }

  async readRoot(
    read: { organizationId: string; policyId: string },
    signal: AbortSignal,
  ): Promise<CommercePolicyRootDetail> {
    const request = parseRequest(CommercePolicyRootRequestSchema, read);
    const organizationId = scopedOrganization(request.organizationId);
    const policyId = scopedPolicy(request.policyId);
    const decoded = await this.#request({
      method: "GET",
      path: fillPath("policy_root", { organizationId, policyId }),
      signal,
      write: false,
    });
    const detail = parseSuccessEnvelope(decoded, CommercePolicyRootDetailResponseSchema);
    if (detail.organizationId !== organizationId || detail.policyId !== policyId) {
      throw new PolicyApiError({ kind: "invalid-response" });
    }
    return detail;
  }

  async listHistory(
    read: { organizationId: string; policyId: string; afterRevision?: string | null; limit?: number },
    signal: AbortSignal,
  ): Promise<CommercePolicyHistoryPage> {
    const request = parseRequest(CommercePolicyHistoryRequestSchema, {
      organizationId: read.organizationId,
      policyId: read.policyId,
      ...(read.afterRevision === undefined || read.afterRevision === null
        ? {}
        : { afterRevision: read.afterRevision }),
      ...(read.limit === undefined ? {} : { limit: String(read.limit) }),
    });
    const organizationId = scopedOrganization(request.organizationId);
    const policyId = scopedPolicy(request.policyId);
    const afterRevision =
      request.afterRevision === undefined ? null : scopedRevision(request.afterRevision);
    const limit = boundedLimit(read.limit);
    const query = new URLSearchParams();
    if (afterRevision !== null) query.set("afterRevision", afterRevision);
    query.set("limit", String(limit));
    const decoded = await this.#request({
      method: "GET",
      path: `${fillPath("policy_revisions", { organizationId, policyId })}?${query.toString()}`,
      signal,
      write: false,
    });
    const page = parseSuccessEnvelope(decoded, CommercePolicyHistoryPageResponseSchema);
    if (page.organizationId !== organizationId || page.policyId !== policyId) {
      throw new PolicyApiError({ kind: "invalid-response" });
    }
    assertPageBounds(page.items, limit, afterRevision, (item) => item.revision, compareCanonicalRevision);
    return page;
  }

  async readRevision(
    read: { organizationId: string; policyId: string; revision: string },
    signal: AbortSignal,
  ): Promise<CommercePolicyRevisionDetail> {
    const request = parseRequest(CommercePolicyRevisionRequestSchema, read);
    const organizationId = scopedOrganization(request.organizationId);
    const policyId = scopedPolicy(request.policyId);
    const revision = scopedRevision(request.revision);
    const decoded = await this.#request({
      method: "GET",
      path: fillPath("policy_revision", { organizationId, policyId, revision }),
      signal,
      write: false,
    });
    const detail = parseSuccessEnvelope(decoded, CommercePolicyRevisionDetailResponseSchema);
    if (
      detail.organizationId !== organizationId ||
      detail.policyId !== policyId ||
      detail.revision !== revision
    ) {
      throw new PolicyApiError({ kind: "invalid-response" });
    }
    return detail;
  }

  // Creates the first revision of a NEW policy. The database generates the
  // canonical `policyId`; it is never derived from the mutation id. The
  // committed receipt must therefore carry a canonical typed policy resource,
  // which the strict discriminated-union receipt schema enforces.
  async createRevision(input: PolicyCreateRequest): Promise<CommercePolicyMutationResult> {
    const organizationId = scopedOrganization(input.organizationId);
    const body = parseBody(CommercePolicyCreateBodySchema, input.body);
    if (body.content.organizationId !== organizationId) {
      throw new PolicyApiError({ kind: "pre-send" });
    }
    return this.#write(fillPath("policy_create", { organizationId }), body, input, {
      organizationId,
      operation: "control.policy.create",
      mutationId: body.mutationId,
      expectedResourceId: null,
    });
  }

  // Appends an immutable successor revision. The expected next resource is the
  // exact `policyId@(expectedRevision + 1)` the frozen CAS chain requires.
  async appendRevision(input: PolicyAppendRequest): Promise<CommercePolicyMutationResult> {
    const organizationId = scopedOrganization(input.organizationId);
    const policyId = scopedPolicy(input.policyId);
    const body = parseBody(CommercePolicyAppendBodySchema, input.body);
    if (body.content.organizationId !== organizationId) {
      throw new PolicyApiError({ kind: "pre-send" });
    }
    return this.#write(fillPath("policy_revision_create", { organizationId, policyId }), body, input, {
      organizationId,
      operation: "control.policy.revision.create",
      mutationId: body.mutationId,
      expectedResourceId: `${policyId}@${incrementRevision(body.expectedRevision)}`,
    });
  }

  async pause(input: PolicyTransitionRequest): Promise<CommercePolicyMutationResult> {
    return this.#transition("policy_pause", "control.policy.pause", input);
  }

  async resume(input: PolicyTransitionRequest): Promise<CommercePolicyMutationResult> {
    return this.#transition("policy_resume", "control.policy.resume", input);
  }

  async revoke(input: PolicyTransitionRequest): Promise<CommercePolicyMutationResult> {
    return this.#transition("policy_revoke", "control.policy.revoke", input);
  }

  async #transition(
    routeId: "policy_pause" | "policy_resume" | "policy_revoke",
    operation: PolicyMutationOperation,
    input: PolicyTransitionRequest,
  ): Promise<CommercePolicyMutationResult> {
    const organizationId = scopedOrganization(input.organizationId);
    const policyId = scopedPolicy(input.policyId);
    const body = parseBody(CommercePolicyTransitionBodySchema, input.body);
    return this.#write(fillPath(routeId, { organizationId, policyId }), body, input, {
      organizationId,
      operation,
      mutationId: body.mutationId,
      expectedResourceId: policyId,
    });
  }

  // Explicit status GET with the ORIGINAL mutation id. The receipt must bind
  // the exact operation and resource the original logical write targeted.
  async readMutationStatus(
    read: {
      organizationId: string;
      mutationId: string;
      operation: PolicyMutationOperation;
      expectedResourceId: string | null;
      signal: AbortSignal;
    },
  ): Promise<CommercePolicyMutationStatus> {
    const organizationId = scopedOrganization(read.organizationId);
    const mutationId = scopedMutationId(read.mutationId);
    const decoded = await this.#request({
      method: "GET",
      path: fillPath("policy_mutation_status", { organizationId, mutationId }),
      signal: read.signal,
      write: false,
    });
    const status = parseSuccessEnvelope(decoded, CommercePolicyMutationStatusResponseSchema);
    if (status.organizationId !== organizationId || status.mutationId !== mutationId) {
      throw new PolicyApiError({ kind: "invalid-response" });
    }
    if (status.status === "committed") {
      const receipt = status.receipt;
      if (receipt.operation !== read.operation) {
        throw new PolicyApiError({ kind: "invalid-response" });
      }
      if (receipt.mutationId !== mutationId) {
        throw new PolicyApiError({ kind: "invalid-response" });
      }
      if (read.expectedResourceId !== null && receipt.resourceId !== read.expectedResourceId) {
        throw new PolicyApiError({ kind: "invalid-response" });
      }
    }
    return status;
  }

  async #write(
    path: string,
    body: { mutationId: string },
    common: WriteCommon,
    expected: {
      organizationId: string;
      operation: PolicyMutationOperation;
      mutationId: string;
      expectedResourceId: string | null;
    },
  ): Promise<CommercePolicyMutationResult> {
    if (common.csrfToken.length === 0) throw new PolicyApiError({ kind: "pre-send" });
    if (!CommerceTenantIdempotencyKeySchema.safeParse(common.idempotencyKey).success) {
      throw new PolicyApiError({ kind: "pre-send" });
    }
    let serialized: string;
    try {
      serialized = JSON.stringify(body);
    } catch {
      throw new PolicyApiError({ kind: "pre-send" });
    }
    if (new TextEncoder().encode(serialized).byteLength > POLICY_MAX_BODY_BYTES) {
      throw new PolicyApiError({ kind: "pre-send" });
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
    const result = parseSuccessEnvelope(decoded, CommercePolicyMutationResultResponseSchema);
    assertMutationBinding(result, expected);
    return result;
  }

  async #request(input: RequestInput): Promise<unknown> {
    if (input.signal.aborted) throw new PolicyApiError({ kind: "aborted" });
    const fetcher = this.#fetcher;
    // ONE total deadline covers response headers AND the streamed body.
    const deadline = new AbortController();
    const timer = setTimeout(() => deadline.abort(), POLICY_REQUEST_TIMEOUT_MS);
    const combined = combineSignals(input.signal, deadline.signal);
    try {
      let response: Response;
      try {
        response = await fetcher(input.path, {
          method: input.method,
          headers: input.headers ?? { "X-OpenArc-Client": API_CLIENT_HEADER, Accept: "application/json" },
          ...(input.body === undefined ? {} : { body: input.body }),
          credentials: "same-origin",
          cache: "no-store",
          redirect: "error",
          referrerPolicy: "no-referrer",
          signal: combined,
        });
      } catch {
        if (input.signal.aborted) throw new PolicyApiError({ kind: "aborted" });
        if (input.write) throw new PolicyApiError({ kind: "outcome-unknown" });
        throw new PolicyApiError({ kind: "unavailable" });
      }
      let decoded: unknown;
      try {
        decoded = await decodeJson(response, combined);
      } catch (error) {
        if (input.signal.aborted) throw new PolicyApiError({ kind: "aborted" });
        if (!response.ok) throw new PolicyApiError(mapHttpFailure(response.status, undefined, input.write));
        if (error instanceof PolicyApiError && error.failure.kind === "aborted") {
          throw new PolicyApiError(input.write ? { kind: "outcome-unknown" } : { kind: "unavailable" });
        }
        throw new PolicyApiError(input.write ? { kind: "outcome-unknown" } : { kind: "invalid-response" });
      }
      if (!response.ok) {
        throw new PolicyApiError(mapHttpFailure(response.status, decoded, input.write));
      }
      return decoded;
    } finally {
      clearTimeout(timer);
    }
  }
}

function parseRequest<T>(schema: RuntimeSchema<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new PolicyApiError({ kind: "pre-send" });
  return parsed.data;
}

function parseBody<T>(schema: RuntimeSchema<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new PolicyApiError({ kind: "pre-send" });
  return parsed.data;
}

/** Exact expected successor revision: expectedRevision + 1, BigInt only. */
function incrementRevision(expectedRevision: string): string {
  const parsed = CommercePolicyRevisionNumberSchema.safeParse(expectedRevision);
  if (!parsed.success) throw new PolicyApiError({ kind: "pre-send" });
  return (BigInt(parsed.data) + 1n).toString();
}

function parseSuccessEnvelope<T>(
  decoded: unknown,
  schema: {
    safeParse(value: unknown):
      | { success: true; data: { ok: true; data: T; meta: unknown } }
      | { success: false };
  },
): T {
  if (typeof decoded !== "object" || decoded === null) throw new PolicyApiError({ kind: "invalid-response" });
  const record = decoded as { ok?: unknown; meta?: unknown };
  if (record.ok !== true) throw new PolicyApiError({ kind: "invalid-response" });
  const keys = Object.keys(record).sort();
  if (keys.length !== 3 || keys[0] !== "data" || keys[1] !== "meta" || keys[2] !== "ok") {
    throw new PolicyApiError({ kind: "invalid-response" });
  }
  const meta = CommerceApiMetaSchema.safeParse(record.meta);
  if (!meta.success || meta.data.schemaVersion !== COMMERCE_API_SCHEMA_VERSION) {
    throw new PolicyApiError({ kind: "invalid-response" });
  }
  const parsed = schema.safeParse(decoded);
  if (!parsed.success) throw new PolicyApiError({ kind: "invalid-response" });
  return parsed.data.data;
}

// The exact correlation a receipt must bind. `expectedResourceId` is null only
// for a create, where the database generates the canonical policy resource; the
// strict discriminated-union receipt schema already guarantees that resource is
// a canonical `openarc:policy:` id and never a guessed mutation-derived id.
function assertMutationBinding(
  result: CommercePolicyMutationResult,
  expected: {
    organizationId: string;
    operation: PolicyMutationOperation;
    mutationId: string;
    expectedResourceId: string | null;
  },
): void {
  if (result.organizationId !== expected.organizationId) {
    throw new PolicyApiError({ kind: "invalid-response" });
  }
  const receipt = result.receipt;
  if (receipt.operation !== expected.operation) throw new PolicyApiError({ kind: "invalid-response" });
  if (receipt.mutationId !== expected.mutationId) throw new PolicyApiError({ kind: "invalid-response" });
  if (expected.expectedResourceId !== null && receipt.resourceId !== expected.expectedResourceId) {
    throw new PolicyApiError({ kind: "invalid-response" });
  }
}

function mapHttpFailure(status: number, decoded: unknown, write: boolean): PolicyApiFailure {
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
    case 503:
      return write ? { kind: "outcome-unknown" } : { kind: "unavailable" };
    default:
      if (status >= 500) return write ? { kind: "outcome-unknown" } : { kind: "unavailable" };
      return write ? { kind: "outcome-unknown" } : { kind: "invalid-response" };
  }
}

function mapErrorCode(code: CommerceApiErrorCode, write: boolean): PolicyApiFailure {
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
    throw new PolicyApiError({ kind: "invalid-response" });
  }
  const length = response.headers.get("content-length");
  if (length !== null && (!/^(?:0|[1-9]\d{0,9})$/u.test(length) || Number(length) > API_MAX_RESPONSE_BYTES)) {
    throw new PolicyApiError({ kind: "invalid-response" });
  }
  if (response.body === null) throw new PolicyApiError({ kind: "invalid-response" });
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const next = await readOrAbort(reader, signal);
      if (next.done) break;
      if (signal.aborted) throw new PolicyApiError({ kind: "aborted" });
      total += next.value.byteLength;
      if (total > API_MAX_RESPONSE_BYTES) throw new PolicyApiError({ kind: "invalid-response" });
      chunks.push(next.value);
    }
  } catch (error) {
    if (error instanceof PolicyApiError) throw error;
    if (signal.aborted) throw new PolicyApiError({ kind: "aborted" });
    throw new PolicyApiError({ kind: "invalid-response" });
  } finally {
    void reader.cancel().catch(() => undefined);
  }
  if (signal.aborted) throw new PolicyApiError({ kind: "aborted" });
  if (length !== null && total !== Number(length)) throw new PolicyApiError({ kind: "invalid-response" });
  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.length;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(combined));
  } catch {
    throw new PolicyApiError({ kind: "invalid-response" });
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
  if (signal.aborted) return Promise.reject(new PolicyApiError({ kind: "aborted" }));
  return new Promise((resolve, reject) => {
    const onAbort = () => {
      void reader.cancel().catch(() => undefined);
      reject(new PolicyApiError({ kind: "aborted" }));
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

// Independent credentialless capability transport. It sends NO cookies, NO
// client marker, NO CSRF token and NO bearer credential: the control
// capability manifest is public and is used only to decide whether the policy
// surface is enabled, never as a grant of role authority. A `built_disabled`
// or `unavailable` state is returned truthfully and never turned into a
// fabricated empty catalogue.
export async function readPolicyManagementCapability(
  signal: AbortSignal,
  fetcher: PolicyFetch = fetch,
): Promise<ControlCapabilityState> {
  if (signal.aborted) throw new PolicyApiError({ kind: "aborted" });
  const deadline = new AbortController();
  const timer = setTimeout(() => deadline.abort(), POLICY_REQUEST_TIMEOUT_MS);
  const combined = combineSignals(signal, deadline.signal);
  try {
    let response: Response;
    try {
      response = await fetcher(CONTROL_CAPABILITIES_PATH, {
        method: "GET",
        credentials: "omit",
        cache: "no-store",
        redirect: "error",
        referrerPolicy: "no-referrer",
        signal: combined,
      });
    } catch {
      if (signal.aborted) throw new PolicyApiError({ kind: "aborted" });
      throw new PolicyApiError({ kind: "unavailable" });
    }
    let decoded: unknown;
    try {
      decoded = await decodeJson(response, combined);
    } catch (error) {
      if (signal.aborted) throw new PolicyApiError({ kind: "aborted" });
      if (!response.ok) throw new PolicyApiError(mapHttpFailure(response.status, undefined, false));
      if (error instanceof PolicyApiError && error.failure.kind === "invalid-response") throw error;
      throw new PolicyApiError({ kind: "unavailable" });
    }
    if (!response.ok) throw new PolicyApiError(mapHttpFailure(response.status, decoded, false));
    const parsed = ControlCapabilitiesSuccessEnvelopeSchema.safeParse(decoded);
    if (!parsed.success) throw new PolicyApiError({ kind: "invalid-response" });
    const entry = parsed.data.data.capabilities.find(
      (capability) => capability.family === "policy_management",
    );
    if (entry === undefined) throw new PolicyApiError({ kind: "invalid-response" });
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
  if (source === undefined) throw new PolicyApiError({ kind: "pre-send" });
  const bytes = new Uint8Array(length);
  source.getRandomValues(bytes);
  return bytes;
}

/** One canonical RFC 4122 v4 UUID mutation id per logical write. */
export function createPolicyMutationId(cryptoSource?: Crypto): string {
  const bytes = randomBytes(16, cryptoSource);
  bytes[6] = ((bytes[6] as number) & 0x0f) | 0x40;
  bytes[8] = ((bytes[8] as number) & 0x3f) | 0x80;
  const hex: string[] = [];
  for (const byte of bytes) hex.push(byte.toString(16).padStart(2, "0"));
  const raw = hex.join("");
  const candidate = `${raw.slice(0, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}-${raw.slice(16, 20)}-${raw.slice(20)}`;
  const parsed = CommerceTenantMutationIdSchema.safeParse(candidate);
  if (!parsed.success) throw new PolicyApiError({ kind: "pre-send" });
  return parsed.data;
}

/** One canonical 43-character 32-byte base64url idempotency key per write. */
export function createPolicyIdempotencyKey(cryptoSource?: Crypto): string {
  const bytes = randomBytes(32, cryptoSource);
  bytes[31] = (bytes[31] as number) & 0b11;
  const candidate = canonicalBase64Url(bytes);
  const parsed = CommerceTenantIdempotencyKeySchema.safeParse(candidate);
  if (!parsed.success) throw new PolicyApiError({ kind: "pre-send" });
  return parsed.data;
}

export interface PolicyCorrelation {
  readonly mutationId: string;
  readonly idempotencyKey: string;
}

export function createPolicyCorrelation(cryptoSource?: Crypto): PolicyCorrelation {
  return {
    mutationId: createPolicyMutationId(cryptoSource),
    idempotencyKey: createPolicyIdempotencyKey(cryptoSource),
  };
}
