import {
  ACTION_CAPABILITIES_PATH,
  ACTION_ROUTES,
  API_CLIENT_HEADER,
  API_MAX_RESPONSE_BYTES,
  ActionCapabilitiesSuccessEnvelopeSchema,
  COMMERCE_API_SCHEMA_VERSION,
  CommerceApiErrorEnvelopeSchema,
  CommerceApiMetaSchema,
  CommerceActionCancelBodySchema,
  CommerceActionDecisionBodySchema,
  CommerceActionDetailRequestSchema,
  CommerceActionDetailResponseSchema,
  CommerceActionIdSchema,
  CommerceActionListRequestSchema,
  CommerceActionMutationDataResponseSchema,
  CommerceActionMutationStatusResponseSchema,
  CommerceActionPageResponseSchema,
  CommerceAgentIdSchema,
  CommerceApprovalDetailRequestSchema,
  CommerceApprovalDetailResponseSchema,
  CommerceApprovalIdSchema,
  CommerceApprovalListRequestSchema,
  CommerceApprovalPageResponseSchema,
  CommerceExposureDataResponseSchema,
  CommerceExposureRequestSchema,
  CommerceOrganizationIdSchema,
  CommercePolicyIdSchema,
  CommerceTenantIdempotencyKeySchema,
  CommerceTenantMutationIdSchema,
  type ActionCapabilityState,
  type CommerceActionDetail,
  type CommerceActionMutationData,
  type CommerceActionMutationStatus,
  type CommerceActionPage,
  type CommerceApiErrorCode,
  type CommerceApprovalDetail,
  type CommerceApprovalPage,
  type CommerceExposureData,
} from "@openarc/shared";

// Own commerce-action/approval management transport.
//
// It is deliberately independent of the account, tenant read/write, machine
// credential, marketplace-listing, policy and commerce-session transports.
// Every path is built from the frozen TWELVE-entry `ACTION_ROUTES` registry,
// filtered to the NINE `commerce_action_management` (browser) descriptors, plus
// ONE validated canonical id per segment, encoded exactly once. The three
// `commerce_action_authorization` (agent) routes are headless and are refused
// here before any request is constructed: this module can never call them.
//
// Reads send only the same-origin browser cookie and the browser marker
// (`X-OpenArc-Client`); the three decision writes additionally send the
// transient CSRF token and an idempotency key as HTTP HEADERS ONLY — never in a
// URL, a query string, a body or a log. No shape on this wire can represent a
// raw token, cookie, CSRF value or session hash, and the client never writes
// anything to storage, the URL, history, a log or analytics.
//
// Every request is bounded to 10 seconds total and to the shared response byte
// ceiling, with NO automatic retry and NO automatic resubmission. A write whose
// response is lost is reported as `outcome-unknown`; only an explicit,
// user-initiated status GET with the ORIGINAL mutation id can resolve it. Error
// mapping is fixed and never echoes server text, raw ids or raw payloads.

/** Exactly the nine browser `commerce_action_management` route ids. */
export const ACTION_ROUTE_IDS: readonly string[] = Object.freeze(
  ACTION_ROUTES.filter((route) => route.family === "commerce_action_management").map(
    (route) => route.id,
  ),
);

/** The three agent-audience ids this browser client must never call. */
export const ACTION_AGENT_ROUTE_IDS: readonly string[] = Object.freeze(
  ACTION_ROUTES.filter((route) => route.family === "commerce_action_authorization").map(
    (route) => route.id,
  ),
);

export type ActionClientRouteId = (typeof ACTION_ROUTE_IDS)[number];

/** The exact logical operation a human decision write performs. */
export type ActionMutationOperation =
  | "control.commerce_action.approve"
  | "control.commerce_action.reject"
  | "control.commerce_action.cancel";

export type ActionDecisionKind = "approve" | "reject" | "cancel";

export const ACTION_DECISION_OPERATIONS: Readonly<
  Record<ActionDecisionKind, ActionMutationOperation>
> = Object.freeze({
  approve: "control.commerce_action.approve",
  reject: "control.commerce_action.reject",
  cancel: "control.commerce_action.cancel",
});

export type ActionApiFailure =
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

export class ActionApiError extends Error {
  readonly failure: ActionApiFailure;

  constructor(failure: ActionApiFailure) {
    super(failure.kind);
    this.name = "ActionApiError";
    this.failure = failure;
  }
}

export type ActionFetch = typeof fetch;

type RuntimeSchema<T> = {
  safeParse(value: unknown): { success: true; data: T } | { success: false };
};

/** Bounded page window. The wire limit is a canonical string 1..50. */
export const ACTION_PAGE_LIMIT = 50;
export const ACTION_DEFAULT_PAGE_LIMIT = 25;
export const ACTION_MAX_BODY_BYTES = 16 * 1024;
export const ACTION_REQUEST_TIMEOUT_MS = 10_000;

const ROUTE_BY_ID = Object.freeze(
  Object.fromEntries(ACTION_ROUTES.map((route) => [route.id, route])),
) as Readonly<Record<string, (typeof ACTION_ROUTES)[number]>>;

/**
 * Resolves a frozen browser route template. An agent-audience id, an unknown id
 * or an inherited object property name is refused BEFORE any request exists.
 */
function routeTemplate(id: ActionClientRouteId, method: "GET" | "POST"): string {
  if (!Object.hasOwn(ROUTE_BY_ID, id)) throw new ActionApiError({ kind: "pre-send" });
  const route = ROUTE_BY_ID[id];
  if (
    route === undefined ||
    route.family !== "commerce_action_management" ||
    route.audience !== "browser" ||
    route.method !== method
  ) {
    throw new ActionApiError({ kind: "pre-send" });
  }
  return route.path;
}

function fillPath(
  id: ActionClientRouteId,
  method: "GET" | "POST",
  params: Readonly<Record<string, string>>,
): string {
  let path = routeTemplate(id, method);
  for (const [key, value] of Object.entries(params)) {
    path = path.replace(`:${key}`, encodeURIComponent(value));
  }
  if (path.includes(":")) throw new ActionApiError({ kind: "pre-send" });
  return path;
}

function scopedOrganization(id: string): string {
  const parsed = CommerceOrganizationIdSchema.safeParse(id);
  if (!parsed.success) throw new ActionApiError({ kind: "pre-send" });
  return parsed.data;
}

function scopedAction(id: string): string {
  const parsed = CommerceActionIdSchema.safeParse(id);
  if (!parsed.success) throw new ActionApiError({ kind: "pre-send" });
  return parsed.data;
}

function scopedApproval(id: string): string {
  const parsed = CommerceApprovalIdSchema.safeParse(id);
  if (!parsed.success) throw new ActionApiError({ kind: "pre-send" });
  return parsed.data;
}

function scopedAgent(id: string): string {
  const parsed = CommerceAgentIdSchema.safeParse(id);
  if (!parsed.success) throw new ActionApiError({ kind: "pre-send" });
  return parsed.data;
}

function scopedPolicy(id: string): string {
  const parsed = CommercePolicyIdSchema.safeParse(id);
  if (!parsed.success) throw new ActionApiError({ kind: "pre-send" });
  return parsed.data;
}

function scopedMutationId(mutationId: string): string {
  const parsed = CommerceTenantMutationIdSchema.safeParse(mutationId);
  if (!parsed.success) throw new ActionApiError({ kind: "pre-send" });
  return parsed.data;
}

/**
 * The bounded 1..50 page window. There is NO unbounded mode: an absent limit
 * becomes the canonical default 25 and every value is re-validated against the
 * accepted canonical wire string before a query is built.
 */
function boundedLimit(limit: number | undefined): number {
  const value = limit ?? ACTION_DEFAULT_PAGE_LIMIT;
  if (!Number.isInteger(value) || value < 1 || value > ACTION_PAGE_LIMIT) {
    throw new ActionApiError({ kind: "pre-send" });
  }
  return value;
}

/** Canonical ascending ordering for accepted lexical keyset cursors. */
function compareCanonicalId(left: string, right: string): number {
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

/**
 * A bounded page must not exceed the exact requested limit, and when a
 * continuation cursor was requested its first row must strictly follow that
 * cursor. This is a client-local binding on TOP of the shared page schema.
 */
function assertPageBounds(ids: readonly string[], limit: number, cursor: string | null): void {
  if (ids.length > limit) throw new ActionApiError({ kind: "invalid-response" });
  if (cursor === null) return;
  const first = ids[0];
  if (first === undefined) return;
  if (compareCanonicalId(first, cursor) <= 0) {
    throw new ActionApiError({ kind: "invalid-response" });
  }
}

interface WriteCommon {
  readonly csrfToken: string;
  readonly idempotencyKey: string;
  readonly signal: AbortSignal;
}

export interface ActionDecisionRequest extends WriteCommon {
  readonly organizationId: string;
  readonly actionId: string;
  readonly body: unknown;
}

export interface ActionClientOptions {
  readonly fetcher?: ActionFetch;
}

interface RequestInput {
  readonly method: "GET" | "POST";
  readonly path: string;
  readonly headers?: Record<string, string>;
  readonly body?: string;
  readonly signal: AbortSignal;
  readonly write: boolean;
}

export class ActionClient {
  readonly #fetcher: ActionFetch;

  constructor(options: ActionClientOptions = {}) {
    this.#fetcher = options.fetcher ?? fetch;
  }

  /** Bounded action queue page. Never unbounded, never auto-paged. */
  async listActions(
    read: { organizationId: string; afterActionId?: string | null; limit?: number },
    signal: AbortSignal,
  ): Promise<CommerceActionPage> {
    const limit = boundedLimit(read.limit);
    const request = parseRequest(CommerceActionListRequestSchema, {
      organizationId: read.organizationId,
      ...(read.afterActionId === undefined || read.afterActionId === null
        ? {}
        : { afterActionId: read.afterActionId }),
      limit: String(limit),
    });
    const organizationId = scopedOrganization(request.organizationId);
    const afterActionId =
      request.afterActionId === undefined ? null : scopedAction(request.afterActionId);
    const query = new URLSearchParams();
    if (afterActionId !== null) query.set("afterActionId", afterActionId);
    query.set("limit", String(limit));
    const decoded = await this.#request({
      method: "GET",
      path: `${fillPath("action_list", "GET", { organizationId })}?${query.toString()}`,
      signal,
      write: false,
    });
    const page = parseSuccessEnvelope(decoded, CommerceActionPageResponseSchema);
    if (page.organizationId !== organizationId) {
      throw new ActionApiError({ kind: "invalid-response" });
    }
    assertPageBounds(page.items.map((item) => item.actionId), limit, afterActionId);
    return page;
  }

  async readAction(
    read: { organizationId: string; actionId: string },
    signal: AbortSignal,
  ): Promise<CommerceActionDetail> {
    const request = parseRequest(CommerceActionDetailRequestSchema, read);
    const organizationId = scopedOrganization(request.organizationId);
    const actionId = scopedAction(request.actionId);
    const decoded = await this.#request({
      method: "GET",
      path: fillPath("action_detail", "GET", { organizationId, actionId }),
      signal,
      write: false,
    });
    const detail = parseSuccessEnvelope(decoded, CommerceActionDetailResponseSchema);
    if (detail.organizationId !== organizationId || detail.actionId !== actionId) {
      throw new ActionApiError({ kind: "invalid-response" });
    }
    return detail;
  }

  /** Bounded approval queue page. Never unbounded, never auto-paged. */
  async listApprovals(
    read: { organizationId: string; afterApprovalId?: string | null; limit?: number },
    signal: AbortSignal,
  ): Promise<CommerceApprovalPage> {
    const limit = boundedLimit(read.limit);
    const request = parseRequest(CommerceApprovalListRequestSchema, {
      organizationId: read.organizationId,
      ...(read.afterApprovalId === undefined || read.afterApprovalId === null
        ? {}
        : { afterApprovalId: read.afterApprovalId }),
      limit: String(limit),
    });
    const organizationId = scopedOrganization(request.organizationId);
    const afterApprovalId =
      request.afterApprovalId === undefined ? null : scopedApproval(request.afterApprovalId);
    const query = new URLSearchParams();
    if (afterApprovalId !== null) query.set("afterApprovalId", afterApprovalId);
    query.set("limit", String(limit));
    const decoded = await this.#request({
      method: "GET",
      path: `${fillPath("approval_list", "GET", { organizationId })}?${query.toString()}`,
      signal,
      write: false,
    });
    const page = parseSuccessEnvelope(decoded, CommerceApprovalPageResponseSchema);
    if (page.organizationId !== organizationId) {
      throw new ActionApiError({ kind: "invalid-response" });
    }
    assertPageBounds(page.items.map((item) => item.approvalId), limit, afterApprovalId);
    return page;
  }

  async readApproval(
    read: { organizationId: string; approvalId: string },
    signal: AbortSignal,
  ): Promise<CommerceApprovalDetail> {
    const request = parseRequest(CommerceApprovalDetailRequestSchema, read);
    const organizationId = scopedOrganization(request.organizationId);
    const approvalId = scopedApproval(request.approvalId);
    const decoded = await this.#request({
      method: "GET",
      path: fillPath("approval_detail", "GET", { organizationId, approvalId }),
      signal,
      write: false,
    });
    const detail = parseSuccessEnvelope(decoded, CommerceApprovalDetailResponseSchema);
    if (detail.organizationId !== organizationId || detail.approvalId !== approvalId) {
      throw new ActionApiError({ kind: "invalid-response" });
    }
    return detail;
  }

  /**
   * The exact server exposure view. Every quantity stays a canonical string on
   * this boundary: the client never converts one to a JavaScript number.
   */
  async readExposure(
    read: { organizationId: string; subjectAgentId: string; policyId: string },
    signal: AbortSignal,
  ): Promise<CommerceExposureData> {
    const request = parseRequest(CommerceExposureRequestSchema, read);
    const organizationId = scopedOrganization(request.organizationId);
    const subjectAgentId = scopedAgent(request.subjectAgentId);
    const policyId = scopedPolicy(request.policyId);
    const decoded = await this.#request({
      method: "GET",
      path: fillPath("action_exposure", "GET", { organizationId, subjectAgentId, policyId }),
      signal,
      write: false,
    });
    const data = parseSuccessEnvelope(decoded, CommerceExposureDataResponseSchema);
    if (
      data.organizationId !== organizationId ||
      data.subjectAgentId !== subjectAgentId ||
      data.policyId !== policyId
    ) {
      throw new ActionApiError({ kind: "invalid-response" });
    }
    return data;
  }

  async approve(input: ActionDecisionRequest): Promise<CommerceActionMutationData> {
    return this.#decision("approve", "action_approve", CommerceActionDecisionBodySchema, input);
  }

  async reject(input: ActionDecisionRequest): Promise<CommerceActionMutationData> {
    return this.#decision("reject", "action_reject", CommerceActionDecisionBodySchema, input);
  }

  async cancel(input: ActionDecisionRequest): Promise<CommerceActionMutationData> {
    return this.#decision("cancel", "action_cancel", CommerceActionCancelBodySchema, input);
  }

  /**
   * Explicit status GET with the ORIGINAL mutation id. It NEVER resubmits the
   * decision and never mints a new id or key. The pure status union carries no
   * wrapper identity, so the receipt itself must bind the exact mutation,
   * operation and action the original logical write targeted.
   */
  async readMutationStatus(read: {
    organizationId: string;
    mutationId: string;
    operation: ActionMutationOperation;
    expectedResourceId: string;
    signal: AbortSignal;
  }): Promise<CommerceActionMutationStatus> {
    const organizationId = scopedOrganization(read.organizationId);
    const mutationId = scopedMutationId(read.mutationId);
    const expectedResourceId = scopedAction(read.expectedResourceId);
    const decoded = await this.#request({
      method: "GET",
      path: fillPath("action_mutation_status", "GET", { organizationId, mutationId }),
      signal: read.signal,
      write: false,
    });
    const status = parseSuccessEnvelope(decoded, CommerceActionMutationStatusResponseSchema);
    if (status.status === "committed") {
      const receipt = status.receipt;
      if (receipt.operation !== read.operation) {
        throw new ActionApiError({ kind: "invalid-response" });
      }
      if (receipt.mutationId !== mutationId) {
        throw new ActionApiError({ kind: "invalid-response" });
      }
      if (receipt.resourceId !== expectedResourceId) {
        throw new ActionApiError({ kind: "invalid-response" });
      }
    }
    return status;
  }

  async #decision(
    decision: ActionDecisionKind,
    routeId: ActionClientRouteId,
    bodySchema: RuntimeSchema<{ mutationId: string }>,
    input: ActionDecisionRequest,
  ): Promise<CommerceActionMutationData> {
    const organizationId = scopedOrganization(input.organizationId);
    const actionId = scopedAction(input.actionId);
    const body = parseBody(bodySchema, input.body);
    if (input.csrfToken.length === 0) throw new ActionApiError({ kind: "pre-send" });
    if (!CommerceTenantIdempotencyKeySchema.safeParse(input.idempotencyKey).success) {
      throw new ActionApiError({ kind: "pre-send" });
    }
    let serialized: string;
    try {
      serialized = JSON.stringify(body);
    } catch {
      throw new ActionApiError({ kind: "pre-send" });
    }
    if (new TextEncoder().encode(serialized).byteLength > ACTION_MAX_BODY_BYTES) {
      throw new ActionApiError({ kind: "pre-send" });
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
      path: fillPath(routeId, "POST", { organizationId, actionId }),
      headers,
      body: serialized,
      signal: input.signal,
      write: true,
    });
    const result = parseSuccessEnvelope(decoded, CommerceActionMutationDataResponseSchema);
    const expectedOperation = ACTION_DECISION_OPERATIONS[decision];
    if (result.receipt.operation !== expectedOperation) {
      throw new ActionApiError({ kind: "invalid-response" });
    }
    if (result.receipt.mutationId !== body.mutationId) {
      throw new ActionApiError({ kind: "invalid-response" });
    }
    if (result.receipt.resourceId !== actionId) {
      throw new ActionApiError({ kind: "invalid-response" });
    }
    if (result.metadata.exposureKey.organizationId !== organizationId) {
      throw new ActionApiError({ kind: "invalid-response" });
    }
    return result;
  }

  async #request(input: RequestInput): Promise<unknown> {
    if (input.signal.aborted) throw new ActionApiError({ kind: "aborted" });
    const fetcher = this.#fetcher;
    // ONE total deadline covers response headers AND the streamed body.
    const deadline = new AbortController();
    const timer = setTimeout(() => deadline.abort(), ACTION_REQUEST_TIMEOUT_MS);
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
        if (input.signal.aborted) throw new ActionApiError({ kind: "aborted" });
        // A decision whose transport failed may still have been applied: it is
        // reported as unknown and is NEVER retried automatically.
        if (input.write) throw new ActionApiError({ kind: "outcome-unknown" });
        throw new ActionApiError({ kind: "unavailable" });
      }
      let decoded: unknown;
      try {
        decoded = await decodeJson(response, combined);
      } catch (error) {
        if (input.signal.aborted) throw new ActionApiError({ kind: "aborted" });
        if (!response.ok) {
          throw new ActionApiError(mapHttpFailure(response.status, undefined, input.write));
        }
        if (error instanceof ActionApiError && error.failure.kind === "aborted") {
          throw new ActionApiError(
            input.write ? { kind: "outcome-unknown" } : { kind: "unavailable" },
          );
        }
        throw new ActionApiError(
          input.write ? { kind: "outcome-unknown" } : { kind: "invalid-response" },
        );
      }
      if (!response.ok) {
        throw new ActionApiError(mapHttpFailure(response.status, decoded, input.write));
      }
      return decoded;
    } finally {
      clearTimeout(timer);
    }
  }
}

function parseRequest<T>(schema: RuntimeSchema<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new ActionApiError({ kind: "pre-send" });
  return parsed.data;
}

function parseBody<T>(schema: RuntimeSchema<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new ActionApiError({ kind: "pre-send" });
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
    throw new ActionApiError({ kind: "invalid-response" });
  }
  const record = decoded as { ok?: unknown; meta?: unknown };
  if (record.ok !== true) throw new ActionApiError({ kind: "invalid-response" });
  const keys = Object.keys(record).sort();
  if (keys.length !== 3 || keys[0] !== "data" || keys[1] !== "meta" || keys[2] !== "ok") {
    throw new ActionApiError({ kind: "invalid-response" });
  }
  const meta = CommerceApiMetaSchema.safeParse(record.meta);
  if (!meta.success || meta.data.schemaVersion !== COMMERCE_API_SCHEMA_VERSION) {
    throw new ActionApiError({ kind: "invalid-response" });
  }
  const parsed = schema.safeParse(decoded);
  if (!parsed.success) throw new ActionApiError({ kind: "invalid-response" });
  return parsed.data.data;
}

function mapHttpFailure(status: number, decoded: unknown, write: boolean): ActionApiFailure {
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

function mapErrorCode(code: CommerceApiErrorCode, write: boolean): ActionApiFailure {
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
    throw new ActionApiError({ kind: "invalid-response" });
  }
  const length = response.headers.get("content-length");
  if (
    length !== null &&
    (!/^(?:0|[1-9]\d{0,9})$/u.test(length) || Number(length) > API_MAX_RESPONSE_BYTES)
  ) {
    throw new ActionApiError({ kind: "invalid-response" });
  }
  if (response.body === null) throw new ActionApiError({ kind: "invalid-response" });
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const next = await readOrAbort(reader, signal);
      if (next.done) break;
      if (signal.aborted) throw new ActionApiError({ kind: "aborted" });
      total += next.value.byteLength;
      if (total > API_MAX_RESPONSE_BYTES) throw new ActionApiError({ kind: "invalid-response" });
      chunks.push(next.value);
    }
  } catch (error) {
    if (error instanceof ActionApiError) throw error;
    if (signal.aborted) throw new ActionApiError({ kind: "aborted" });
    throw new ActionApiError({ kind: "invalid-response" });
  } finally {
    void reader.cancel().catch(() => undefined);
  }
  if (signal.aborted) throw new ActionApiError({ kind: "aborted" });
  if (length !== null && total !== Number(length)) {
    throw new ActionApiError({ kind: "invalid-response" });
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
    throw new ActionApiError({ kind: "invalid-response" });
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
  if (signal.aborted) return Promise.reject(new ActionApiError({ kind: "aborted" }));
  return new Promise((resolve, reject) => {
    const onAbort = () => {
      void reader.cancel().catch(() => undefined);
      reject(new ActionApiError({ kind: "aborted" }));
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
 * Independent credentialless action-capability transport. It sends NO cookies,
 * NO client marker, NO CSRF token and NO bearer credential: the action
 * capability manifest is public and decides only whether the browser management
 * surface is enabled — never a permission, a role or a spend authority. A
 * `built_disabled` or `unavailable` state is returned truthfully and is never
 * turned into a fabricated empty queue.
 */
export async function readCommerceActionsCapability(
  signal: AbortSignal,
  fetcher: ActionFetch = fetch,
): Promise<ActionCapabilityState> {
  if (signal.aborted) throw new ActionApiError({ kind: "aborted" });
  const deadline = new AbortController();
  const timer = setTimeout(() => deadline.abort(), ACTION_REQUEST_TIMEOUT_MS);
  const combined = combineSignals(signal, deadline.signal);
  try {
    let response: Response;
    try {
      response = await fetcher(ACTION_CAPABILITIES_PATH, {
        method: "GET",
        credentials: "omit",
        cache: "no-store",
        redirect: "error",
        referrerPolicy: "no-referrer",
        signal: combined,
      });
    } catch {
      if (signal.aborted) throw new ActionApiError({ kind: "aborted" });
      throw new ActionApiError({ kind: "unavailable" });
    }
    let decoded: unknown;
    try {
      decoded = await decodeJson(response, combined);
    } catch (error) {
      if (signal.aborted) throw new ActionApiError({ kind: "aborted" });
      if (!response.ok) throw new ActionApiError(mapHttpFailure(response.status, undefined, false));
      if (error instanceof ActionApiError && error.failure.kind === "invalid-response") throw error;
      throw new ActionApiError({ kind: "unavailable" });
    }
    if (!response.ok) throw new ActionApiError(mapHttpFailure(response.status, decoded, false));
    const parsed = ActionCapabilitiesSuccessEnvelopeSchema.safeParse(decoded);
    if (!parsed.success) throw new ActionApiError({ kind: "invalid-response" });
    const entry = parsed.data.data.capabilities.find(
      (capability) => capability.family === "commerce_action_management",
    );
    if (entry === undefined) throw new ActionApiError({ kind: "invalid-response" });
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
  if (source === undefined) throw new ActionApiError({ kind: "pre-send" });
  const bytes = new Uint8Array(length);
  source.getRandomValues(bytes);
  return bytes;
}

/** One canonical RFC 4122 v4 UUID mutation id per logical decision. */
export function createActionMutationId(cryptoSource?: Crypto): string {
  const bytes = randomBytes(16, cryptoSource);
  bytes[6] = ((bytes[6] as number) & 0x0f) | 0x40;
  bytes[8] = ((bytes[8] as number) & 0x3f) | 0x80;
  const hex: string[] = [];
  for (const byte of bytes) hex.push(byte.toString(16).padStart(2, "0"));
  const raw = hex.join("");
  const candidate = `${raw.slice(0, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}-${raw.slice(16, 20)}-${raw.slice(20)}`;
  const parsed = CommerceTenantMutationIdSchema.safeParse(candidate);
  if (!parsed.success) throw new ActionApiError({ kind: "pre-send" });
  return parsed.data;
}

/** One canonical 43-character 32-byte base64url idempotency key per decision. */
export function createActionIdempotencyKey(cryptoSource?: Crypto): string {
  const bytes = randomBytes(32, cryptoSource);
  bytes[31] = (bytes[31] as number) & 0b11;
  const candidate = canonicalBase64Url(bytes);
  const parsed = CommerceTenantIdempotencyKeySchema.safeParse(candidate);
  if (!parsed.success) throw new ActionApiError({ kind: "pre-send" });
  return parsed.data;
}

export interface ActionCorrelation {
  readonly mutationId: string;
  readonly idempotencyKey: string;
}

export function createActionCorrelation(cryptoSource?: Crypto): ActionCorrelation {
  return {
    mutationId: createActionMutationId(cryptoSource),
    idempotencyKey: createActionIdempotencyKey(cryptoSource),
  };
}
