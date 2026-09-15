import {
  CommerceOrganizationIdSchema,
  CommercePolicyAppendBodySchema,
  CommercePolicyCreateBodySchema,
  CommercePolicyHistoryPageSchema,
  CommercePolicyHistoryRequestSchema,
  CommercePolicyIdSchema,
  CommercePolicyListRequestSchema,
  CommercePolicyMutationReceiptSchema,
  CommercePolicyMutationRequestSchema,
  CommercePolicyMutationResultSchema,
  CommercePolicyMutationStatusSchema,
  CommercePolicyRevisionDetailSchema,
  CommercePolicyRevisionRequestSchema,
  CommercePolicyRevisionSchema,
  CommercePolicyRootDetailSchema,
  CommercePolicyRootPageSchema,
  CommercePolicyRootRequestSchema,
  CommercePolicyRootSchema,
  CommercePolicyTransitionBodySchema,
  CommerceTenantIdempotencyKeySchema,
  type CommercePolicyMutationResult,
  type CommercePolicyMutationStatus,
  type CommercePolicyRevisionDetail,
  type CommercePolicyRootDetail,
  type CommercePolicyHistoryPage,
  type CommercePolicyRootPage,
} from "@openarc/shared";
import { ControlPolicyStoreError } from "@openarc/db";
import type { ZodType } from "zod";

import { AUTH_ERRORS, AuthApiError } from "../auth/errors.js";
import type { AuthRequestContext } from "../auth/service.js";
import type { ControlPolicyAuthPort, ControlPolicyStorePort } from "./ports.js";

/**
 * Orchestration for the protected control policy management family.
 *
 * Read/status ordering is strict: parse the request BEFORE any auth work, then
 * `beginTenantRead`, exactly one accepted repository read, then
 * `finishTenantRead`, and only then validate/bind the returned DTO. Writes
 * parse, verify CSRF, begin, invoke exactly one accepted repository mutation,
 * and deliberately perform NO post-commit live-session check: the authoritative
 * SQL may revoke this very request's session at commit, so re-reading would
 * misreport a committed write.
 *
 * The operation and resource target are fixed by the ROUTE, never by the body:
 * a create binds `budget_policy`, an append binds
 * `budget_policy_revision` at `policyId@(expectedRevision+1)`, and each of the
 * three transitions binds `budget_policy` at `policyId`. A create id is taken
 * verbatim from the store receipt and NEVER regenerated. No method retries,
 * polls, substitutes an idempotency key, preflights latest state or acts on an
 * unknown outcome. `OUTCOME_UNKNOWN` maps to a fixed non-retryable 503;
 * recovery is an explicit status GET with the same logical mutation id.
 */

const CREATE_OPERATION = "control.policy.create" as const;
const REVISION_CREATE_OPERATION = "control.policy.revision.create" as const;
const PAUSE_OPERATION = "control.policy.pause" as const;
const RESUME_OPERATION = "control.policy.resume" as const;
const REVOKE_OPERATION = "control.policy.revoke" as const;

/** The five frozen operations, in the frozen order. */
const POLICY_OPERATIONS: ReadonlySet<string> = new Set([
  CREATE_OPERATION,
  REVISION_CREATE_OPERATION,
  PAUSE_OPERATION,
  RESUME_OPERATION,
  REVOKE_OPERATION,
]);

const DEFAULT_PAGE = 25;

interface PolicyWriteEnvelope {
  readonly csrf: unknown;
  readonly idempotencyKey: unknown;
  readonly body: unknown;
}

function invalidInput(): AuthApiError {
  return AUTH_ERRORS.invalidRequest();
}

function forbidden(): AuthApiError {
  return AUTH_ERRORS.forbidden();
}

function unauthenticated(): AuthApiError {
  return AUTH_ERRORS.unauthenticated();
}

function unavailable(): AuthApiError {
  return AUTH_ERRORS.unavailable();
}

function idempotencyConflict(): AuthApiError {
  return new AuthApiError("IDEMPOTENCY_CONFLICT", 409, "INVALID_REQUEST");
}

function policyDenied(): AuthApiError {
  return new AuthApiError("POLICY_DENIED", 409, "INVALID_REQUEST");
}

/**
 * A malformed/shape-invalid repository result (or a binding violation) is a
 * fixed 503. Frozen contract: invalid DB data is an unavailable dependency, not
 * a caller error and not a retryable-looking 5xx distinction.
 */
function projectionFailure(): AuthApiError {
  return AUTH_ERRORS.unavailable();
}

function mapStoreError(error: unknown): never {
  if (error instanceof AuthApiError) throw error;
  if (error instanceof ControlPolicyStoreError) {
    switch (error.code) {
      case "CONTROL_POLICY_STORE_INPUT_INVALID":
        throw invalidInput();
      case "CONTROL_POLICY_STORE_SESSION_INVALID":
        throw unauthenticated();
      case "CONTROL_POLICY_STORE_FORBIDDEN":
      case "CONTROL_POLICY_STORE_NOT_FOUND":
        // A cross-actor or unknown target is the same fixed denial: no
        // organization-existence oracle is exposed by the transport.
        throw forbidden();
      case "CONTROL_POLICY_STORE_CONFLICT":
        throw policyDenied();
      case "CONTROL_POLICY_STORE_IDEMPOTENCY_CONFLICT":
        throw idempotencyConflict();
      case "CONTROL_POLICY_STORE_UNAVAILABLE":
      case "CONTROL_POLICY_STORE_OUTCOME_UNKNOWN":
      default:
        throw unavailable();
    }
  }
  throw unavailable();
}

function parseRequest<T>(schema: ZodType<T>, input: unknown): T {
  const parsed = schema.safeParse(input);
  if (!parsed.success) throw invalidInput();
  return parsed.data;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Reject a store envelope that carries keys other than the accepted ones. A
 * page result is `{items, nextCursor}`; a mutation result is
 * `{replayed, receipt}`; a status is `{status}` or `{status, receipt}`. An
 * extra key is a malformed result and must not be silently stripped away
 * before validation.
 */
function requireExactKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
): void {
  const keys = Object.keys(value);
  if (keys.length !== allowed.length) throw projectionFailure();
  for (const key of keys) {
    if (!allowed.includes(key)) throw projectionFailure();
  }
}

/**
 * The bounded requested page size; absent means the frozen repository default
 * of 25. The wire `limit` is a canonical decimal STRING, so the numeric bound
 * is derived only from an already-validated helper value.
 */
function requestedLimit(limit: string | undefined): number {
  if (limit === undefined) return DEFAULT_PAGE;
  return Number(limit);
}

function numericRevision(value: string): bigint {
  return BigInt(value);
}

export class PolicyService {
  readonly #auth: ControlPolicyAuthPort;
  readonly #store: ControlPolicyStorePort;

  constructor(options: { auth: ControlPolicyAuthPort; store: ControlPolicyStorePort }) {
    this.#auth = options.auth;
    this.#store = options.store;
  }

  /* ---------------------------------------------------------------- */
  /* Reads                                                             */
  /* ---------------------------------------------------------------- */

  async listPolicyRoots(
    ctx: AuthRequestContext,
    request: unknown,
  ): Promise<CommercePolicyRootPage> {
    const parsed = parseRequest(CommercePolicyListRequestSchema, request);
    const input = {
      ...(parsed.afterPolicyId !== undefined
        ? { afterPolicyId: parsed.afterPolicyId }
        : {}),
      ...(parsed.limit !== undefined ? { limit: Number(parsed.limit) } : {}),
    };
    const begun = await this.#auth.beginTenantRead(ctx);
    let raw: unknown;
    try {
      raw = await this.#store.listPolicyRoots(
        begun.sessionHash,
        parsed.organizationId,
        input,
      );
    } catch (error) {
      mapStoreError(error);
    }
    await this.#auth.finishTenantRead(ctx, begun);
    if (!isRecord(raw)) throw projectionFailure();
    requireExactKeys(raw, ["items", "nextCursor"]);
    const page = CommercePolicyRootPageSchema.safeParse({
      organizationId: parsed.organizationId,
      items: raw["items"],
      nextCursor: raw["nextCursor"],
    });
    if (!page.success) throw projectionFailure();
    if (page.data.items.length > requestedLimit(parsed.limit)) {
      throw projectionFailure();
    }
    if (parsed.afterPolicyId !== undefined) {
      for (const item of page.data.items) {
        if (!(item.policyId > parsed.afterPolicyId)) {
          throw projectionFailure();
        }
      }
    }
    return page.data;
  }

  async getPolicyRoot(
    ctx: AuthRequestContext,
    request: unknown,
  ): Promise<CommercePolicyRootDetail> {
    const parsed = parseRequest(CommercePolicyRootRequestSchema, request);
    const begun = await this.#auth.beginTenantRead(ctx);
    let raw: unknown;
    try {
      raw = await this.#store.getPolicyRoot(
        begun.sessionHash,
        parsed.organizationId,
        parsed.policyId,
      );
    } catch (error) {
      mapStoreError(error);
    }
    await this.#auth.finishTenantRead(ctx, begun);
    if (raw === null) {
      const detail = CommercePolicyRootDetailSchema.safeParse({
        organizationId: parsed.organizationId,
        policyId: parsed.policyId,
        item: null,
      });
      if (!detail.success) throw projectionFailure();
      return detail.data;
    }
    // Parse the raw store object DIRECTLY against the strict accepted schema so
    // an extra key can never be stripped into a passing projection.
    const item = CommercePolicyRootSchema.safeParse(raw);
    if (!item.success) throw projectionFailure();
    if (
      item.data.organizationId !== parsed.organizationId ||
      item.data.policyId !== parsed.policyId
    ) {
      throw projectionFailure();
    }
    const detail = CommercePolicyRootDetailSchema.safeParse({
      organizationId: parsed.organizationId,
      policyId: parsed.policyId,
      item: item.data,
    });
    if (!detail.success) throw projectionFailure();
    return detail.data;
  }

  async listPolicyRevisions(
    ctx: AuthRequestContext,
    request: unknown,
  ): Promise<CommercePolicyHistoryPage> {
    const parsed = parseRequest(CommercePolicyHistoryRequestSchema, request);
    const input = {
      ...(parsed.afterRevision !== undefined
        ? { afterRevision: parsed.afterRevision }
        : {}),
      ...(parsed.limit !== undefined ? { limit: Number(parsed.limit) } : {}),
    };
    const begun = await this.#auth.beginTenantRead(ctx);
    let raw: unknown;
    try {
      raw = await this.#store.listPolicyRevisions(
        begun.sessionHash,
        parsed.organizationId,
        parsed.policyId,
        input,
      );
    } catch (error) {
      mapStoreError(error);
    }
    await this.#auth.finishTenantRead(ctx, begun);
    if (!isRecord(raw)) throw projectionFailure();
    requireExactKeys(raw, ["items", "nextCursor"]);
    const page = CommercePolicyHistoryPageSchema.safeParse({
      organizationId: parsed.organizationId,
      policyId: parsed.policyId,
      items: raw["items"],
      nextCursor: raw["nextCursor"],
    });
    if (!page.success) throw projectionFailure();
    if (page.data.items.length > requestedLimit(parsed.limit)) {
      throw projectionFailure();
    }
    if (parsed.afterRevision !== undefined) {
      for (const item of page.data.items) {
        if (!(numericRevision(item.revision) > numericRevision(parsed.afterRevision))) {
          throw projectionFailure();
        }
      }
    }
    return page.data;
  }

  async getPolicyRevision(
    ctx: AuthRequestContext,
    request: unknown,
  ): Promise<CommercePolicyRevisionDetail> {
    const parsed = parseRequest(CommercePolicyRevisionRequestSchema, request);
    const begun = await this.#auth.beginTenantRead(ctx);
    let raw: unknown;
    try {
      raw = await this.#store.getPolicyRevision(
        begun.sessionHash,
        parsed.organizationId,
        parsed.policyId,
        parsed.revision,
      );
    } catch (error) {
      mapStoreError(error);
    }
    await this.#auth.finishTenantRead(ctx, begun);
    if (raw === null) {
      const detail = CommercePolicyRevisionDetailSchema.safeParse({
        organizationId: parsed.organizationId,
        policyId: parsed.policyId,
        revision: parsed.revision,
        item: null,
      });
      if (!detail.success) throw projectionFailure();
      return detail.data;
    }
    const item = CommercePolicyRevisionSchema.safeParse(raw);
    if (!item.success) throw projectionFailure();
    if (
      item.data.organizationId !== parsed.organizationId ||
      item.data.policyId !== parsed.policyId ||
      item.data.revision !== parsed.revision
    ) {
      throw projectionFailure();
    }
    const detail = CommercePolicyRevisionDetailSchema.safeParse({
      organizationId: parsed.organizationId,
      policyId: parsed.policyId,
      revision: parsed.revision,
      item: item.data,
    });
    if (!detail.success) throw projectionFailure();
    return detail.data;
  }

  async getPolicyMutationStatus(
    ctx: AuthRequestContext,
    request: unknown,
  ): Promise<CommercePolicyMutationStatus> {
    const parsed = parseRequest(CommercePolicyMutationRequestSchema, request);
    const begun = await this.#auth.beginTenantRead(ctx);
    let raw: unknown;
    try {
      raw = await this.#store.getPolicyMutationStatus(
        begun.sessionHash,
        parsed.organizationId,
        parsed.mutationId,
      );
    } catch (error) {
      mapStoreError(error);
    }
    await this.#auth.finishTenantRead(ctx, begun);
    if (!isRecord(raw)) throw projectionFailure();
    if (raw["status"] === "not_found") {
      requireExactKeys(raw, ["status"]);
      const status = CommercePolicyMutationStatusSchema.safeParse({
        organizationId: parsed.organizationId,
        mutationId: parsed.mutationId,
        status: "not_found",
      });
      if (!status.success) throw projectionFailure();
      return status.data;
    }
    if (raw["status"] !== "committed") throw projectionFailure();
    requireExactKeys(raw, ["status", "receipt"]);
    // Validate the COMPLETE raw status object against the strict accepted
    // schema so an extra key can never be stripped into a passing projection.
    const status = CommercePolicyMutationStatusSchema.safeParse({
      organizationId: parsed.organizationId,
      mutationId: parsed.mutationId,
      status: "committed",
      receipt: raw["receipt"],
    });
    if (!status.success) throw projectionFailure();
    if (status.data.status !== "committed") throw projectionFailure();
    if (!POLICY_OPERATIONS.has(status.data.receipt.operation)) {
      throw projectionFailure();
    }
    return status.data;
  }

  /* ---------------------------------------------------------------- */
  /* Writes                                                            */
  /* ---------------------------------------------------------------- */

  async createPolicy(
    ctx: AuthRequestContext,
    organizationId: unknown,
    request: PolicyWriteEnvelope,
  ): Promise<CommercePolicyMutationResult> {
    const organization = parseRequest(CommerceOrganizationIdSchema, organizationId);
    const body = parseRequest(CommercePolicyCreateBodySchema, request.body);
    // Bind the caller-supplied content organization to the path organization
    // BEFORE any auth/store work: DB already defends this, but the service must
    // reject a cross-org body itself rather than forwarding it.
    if (body.content.organizationId !== organization) throw invalidInput();
    const authorized = await this.#authorize(ctx, request, body.mutationId);
    const raw = await this.#invoke(() =>
      this.#store.createPolicy(
        authorized.sessionHash,
        organization,
        body.content,
        authorized.metadata,
      ),
    );
    return this.#projectMutationResult({
      raw,
      organizationId: organization,
      invokedOperation: CREATE_OPERATION,
      requestMutationId: body.mutationId,
    });
  }

  async appendPolicyRevision(
    ctx: AuthRequestContext,
    organizationId: unknown,
    policyId: unknown,
    request: PolicyWriteEnvelope,
  ): Promise<CommercePolicyMutationResult> {
    const organization = parseRequest(CommerceOrganizationIdSchema, organizationId);
    const policy = parseRequest(CommercePolicyIdSchema, policyId);
    const body = parseRequest(CommercePolicyAppendBodySchema, request.body);
    const nextRevision = (BigInt(body.expectedRevision) + 1n).toString();
    if (body.content.organizationId !== organization) throw invalidInput();
    const authorized = await this.#authorize(ctx, request, body.mutationId);
    const raw = await this.#invoke(() =>
      this.#store.appendPolicyRevision(
        authorized.sessionHash,
        organization,
        policy,
        {
          expectedRevision: body.expectedRevision,
          expectedUpdatedAt: body.expectedUpdatedAt,
          content: body.content,
        },
        authorized.metadata,
      ),
    );
    return this.#projectMutationResult({
      raw,
      organizationId: organization,
      invokedOperation: REVISION_CREATE_OPERATION,
      requestMutationId: body.mutationId,
      expectedResourceId: `${policy}@${nextRevision}`,
    });
  }

  async pausePolicy(
    ctx: AuthRequestContext,
    organizationId: unknown,
    policyId: unknown,
    request: PolicyWriteEnvelope,
  ): Promise<CommercePolicyMutationResult> {
    return this.#transition(ctx, organizationId, policyId, request, PAUSE_OPERATION);
  }

  async resumePolicy(
    ctx: AuthRequestContext,
    organizationId: unknown,
    policyId: unknown,
    request: PolicyWriteEnvelope,
  ): Promise<CommercePolicyMutationResult> {
    return this.#transition(ctx, organizationId, policyId, request, RESUME_OPERATION);
  }

  async revokePolicy(
    ctx: AuthRequestContext,
    organizationId: unknown,
    policyId: unknown,
    request: PolicyWriteEnvelope,
  ): Promise<CommercePolicyMutationResult> {
    return this.#transition(ctx, organizationId, policyId, request, REVOKE_OPERATION);
  }

  /* ---------------------------------------------------------------- */
  /* Internal helpers                                                  */
  /* ---------------------------------------------------------------- */

  async #transition(
    ctx: AuthRequestContext,
    organizationId: unknown,
    policyId: unknown,
    request: PolicyWriteEnvelope,
    operation: string,
  ): Promise<CommercePolicyMutationResult> {
    const organization = parseRequest(CommerceOrganizationIdSchema, organizationId);
    const policy = parseRequest(CommercePolicyIdSchema, policyId);
    const body = parseRequest(CommercePolicyTransitionBodySchema, request.body);
    const authorized = await this.#authorize(ctx, request, body.mutationId);
    const raw = await this.#invoke(() =>
      this.#store.transitionPolicy(
        authorized.sessionHash,
        organization,
        policy,
        {
          operation,
          expectedRevision: body.expectedRevision,
          expectedUpdatedAt: body.expectedUpdatedAt,
        },
        authorized.metadata,
      ),
    );
    return this.#projectMutationResult({
      raw,
      organizationId: organization,
      invokedOperation: operation,
      requestMutationId: body.mutationId,
      expectedResourceId: policy,
    });
  }

  async #authorize(
    ctx: AuthRequestContext,
    request: PolicyWriteEnvelope,
    mutationId: string,
  ): Promise<{
    sessionHash: string;
    metadata: { idempotencyKey: string; mutationId: string };
  }> {
    const idempotencyKey = parseRequest(
      CommerceTenantIdempotencyKeySchema,
      request.idempotencyKey,
    );
    // Input validation is complete; now the exact accepted CSRF check, then the
    // live-session begin. No mutation happens unless both succeed.
    this.#auth.verifyCsrf(ctx.cookies, request.csrf);
    const begun = await this.#auth.beginTenantRead(ctx);
    return {
      sessionHash: begun.sessionHash,
      metadata: { idempotencyKey, mutationId },
    };
  }

  async #invoke(work: () => Promise<unknown>): Promise<unknown> {
    try {
      return await work();
    } catch (error) {
      mapStoreError(error);
    }
  }

  #projectMutationResult(input: {
    raw: unknown;
    organizationId: string;
    invokedOperation: string;
    requestMutationId: string;
    expectedResourceId?: string;
  }): CommercePolicyMutationResult {
    if (!isRecord(input.raw)) throw projectionFailure();
    requireExactKeys(input.raw, ["replayed", "receipt"]);
    // Validate the COMPLETE raw receipt against the strict accepted schema
    // FIRST, so an extra key can never be stripped into a passing projection.
    const receipt = CommercePolicyMutationReceiptSchema.safeParse(input.raw["receipt"]);
    if (!receipt.success) throw projectionFailure();
    if (receipt.data.operation !== input.invokedOperation) {
      throw projectionFailure();
    }
    if (receipt.data.mutationId !== input.requestMutationId) {
      throw projectionFailure();
    }
    if (
      input.expectedResourceId !== undefined &&
      receipt.data.resourceId !== input.expectedResourceId
    ) {
      throw projectionFailure();
    }
    const result = CommercePolicyMutationResultSchema.safeParse({
      organizationId: input.organizationId,
      replayed: input.raw["replayed"],
      receipt: receipt.data,
    });
    if (!result.success) throw projectionFailure();
    return result.data;
  }
}
