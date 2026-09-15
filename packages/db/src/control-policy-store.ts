import type { Pool } from 'pg';
import {
  CommercePolicyHistoryPageSchema,
  CommercePolicyMutationReceiptSchema,
  CommercePolicyRevisionNumberSchema,
  CommercePolicyRevisionSchema,
  CommercePolicyRevisionSummarySchema,
  CommercePolicyRootSchema,
  CommercePolicyRootPageSchema,
  IsoTimestampSchema,
  type CommercePolicyContent,
  type CommercePolicyRevision,
  type CommercePolicyRoot,
} from '@openarc/shared';
import {
  POLICY_EVENT_BY_OPERATION,
  POLICY_RESOURCE_BY_OPERATION,
  PolicyInputError,
  digestPolicyContent,
  digestPolicyCreateRequest,
  digestPolicyIdempotencyKey,
  digestPolicyRevisionCreateRequest,
  digestPolicySessionContext,
  digestPolicyTransitionRequest,
  parsePolicyContent,
  parsePolicyAppendRevision,
  parsePolicyId,
  parsePolicyOperation,
  parsePolicyRevisionNumber,
  policyRevisionResourceId,
  requireIdempotencyKey,
  requireMutationId,
  requirePolicyTimestamp,
  type PolicyOperation,
  type PolicyResourceType,
} from './control-policy-mutations.js';
import {
  TenantStore,
  type DurableMutationMetadata,
  type TenantClient,
  type TenantPool,
} from './tenant-store.js';

/**
 * Control policy repository over the restricted tenant pool. Every operation
 * runs in one connection/transaction through the reviewed SECURITY DEFINER
 * helpers and never migrates. Outputs strict-parse the frozen shared policy
 * DTOs; malformed driver rows collapse to a fixed UNAVAILABLE error.
 */

export const CONTROL_POLICY_STORE_ERROR_MESSAGES = {
  CONTROL_POLICY_STORE_INPUT_INVALID: 'ControlPolicyStore input is invalid.',
  CONTROL_POLICY_STORE_SESSION_INVALID: 'ControlPolicyStore session is not valid.',
  CONTROL_POLICY_STORE_FORBIDDEN: 'ControlPolicyStore caller is not permitted.',
  CONTROL_POLICY_STORE_NOT_FOUND: 'ControlPolicyStore target was not found.',
  CONTROL_POLICY_STORE_CONFLICT: 'ControlPolicyStore operation conflicts with existing state.',
  CONTROL_POLICY_STORE_IDEMPOTENCY_CONFLICT:
    'ControlPolicyStore mutation conflicts with an existing idempotency record.',
  CONTROL_POLICY_STORE_UNAVAILABLE: 'ControlPolicyStore is not available.',
  CONTROL_POLICY_STORE_OUTCOME_UNKNOWN:
    'ControlPolicyStore mutation outcome could not be confirmed; it may have committed.',
} as const;

export type ControlPolicyStoreErrorCode = keyof typeof CONTROL_POLICY_STORE_ERROR_MESSAGES;

/** Fixed, non-echoing repository error. Never carries driver detail. */
export class ControlPolicyStoreError extends Error {
  readonly code: ControlPolicyStoreErrorCode;

  constructor(code: ControlPolicyStoreErrorCode) {
    super(CONTROL_POLICY_STORE_ERROR_MESSAGES[code]);
    this.name = 'ControlPolicyStoreError';
    this.code = code;
  }
}

export interface ControlPolicyMutationReceipt {
  readonly mutationId: string;
  readonly operation: PolicyOperation;
  readonly resourceType: PolicyResourceType;
  readonly resourceId: string;
  readonly committedAt: string;
}

export interface ControlPolicyMutationResult {
  readonly replayed: boolean;
  readonly receipt: ControlPolicyMutationReceipt;
}

/** Bounded history metadata only; never contains allowlists or full content. */
export interface PolicyRevisionSummary {
  readonly policyId: string;
  readonly organizationId: string;
  readonly subjectAgentId: string;
  readonly revision: string;
  readonly digest: string;
  readonly createdAt: string;
  readonly expiresAt: string | null;
}

export interface PolicyRevisionCasFields {
  readonly expectedRevision: string;
  readonly expectedUpdatedAt: string;
}

export interface AppendPolicyRevisionInput {
  readonly expectedRevision: unknown;
  readonly expectedUpdatedAt: unknown;
  readonly content: unknown;
}

export interface TransitionPolicyInput {
  readonly operation: unknown;
  readonly expectedRevision: unknown;
  readonly expectedUpdatedAt: unknown;
}

export interface ListPolicyRootsInput {
  readonly afterPolicyId?: string;
  readonly limit?: number;
}

export interface ListPolicyRootsResult {
  readonly items: CommercePolicyRoot[];
  readonly nextCursor: string | null;
}

export interface ListPolicyRevisionsInput {
  readonly afterRevision?: string;
  readonly limit?: number;
}

export interface ListPolicyRevisionsResult {
  readonly items: PolicyRevisionSummary[];
  readonly nextCursor: string | null;
}

export type ControlPolicyMutationStatus =
  | { readonly status: 'committed'; readonly receipt: ControlPolicyMutationReceipt }
  | { readonly status: 'not_found' };

// Absolute-end pinned local leaves (Node `$` would accept a trailing newline).
const HEX64 = /^[0-9a-f]{64}$(?![\s\S])/;
const ORG_ID = /^openarc:org:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const AGENT_ID = /^openarc:agent:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const DEFAULT_PAGE = 25;
const MAX_PAGE = 50;

export const POLICY_STATEMENT_TIMEOUT_MS = 15000;
export const POLICY_LOCK_TIMEOUT_MS = 10000;

const PG_TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?([+-])(\d{2})(?::?(\d{2}))?$(?![\s\S])/;

function fail(code: ControlPolicyStoreErrorCode): never {
  throw new ControlPolicyStoreError(code);
}

function failOutput(): never {
  fail('CONTROL_POLICY_STORE_UNAVAILABLE');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireSessionHash(value: unknown): string {
  if (typeof value !== 'string' || !HEX64.test(value)) {
    fail('CONTROL_POLICY_STORE_INPUT_INVALID');
  }
  return value;
}

function requireOrganization(value: unknown): string {
  if (typeof value !== 'string' || !ORG_ID.test(value)) {
    fail('CONTROL_POLICY_STORE_INPUT_INVALID');
  }
  return value;
}

function parsePolicyIdInput(value: unknown): string {
  try {
    return parsePolicyId(value);
  } catch {
    fail('CONTROL_POLICY_STORE_INPUT_INVALID');
  }
}

function parseRevisionInput(value: unknown): string {
  try {
    return parsePolicyRevisionNumber(value);
  } catch {
    fail('CONTROL_POLICY_STORE_INPUT_INVALID');
  }
}

function parseAppendRevisionInput(value: unknown): string {
  try {
    return parsePolicyAppendRevision(value);
  } catch {
    fail('CONTROL_POLICY_STORE_INPUT_INVALID');
  }
}

function parseTimestampInput(value: unknown): string {
  try {
    return requirePolicyTimestamp(value);
  } catch {
    fail('CONTROL_POLICY_STORE_INPUT_INVALID');
  }
}

function parseContentInput(value: unknown): CommercePolicyContent {
  try {
    return parsePolicyContent(value);
  } catch {
    fail('CONTROL_POLICY_STORE_INPUT_INVALID');
  }
}

function parseStrictMetadata(value: unknown): DurableMutationMetadata {
  if (!isRecord(value)) fail('CONTROL_POLICY_STORE_INPUT_INVALID');
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    fail('CONTROL_POLICY_STORE_INPUT_INVALID');
  }
  const keys = Object.keys(value);
  if (keys.length !== 2 || !keys.includes('idempotencyKey') || !keys.includes('mutationId')) {
    fail('CONTROL_POLICY_STORE_INPUT_INVALID');
  }
  try {
    return {
      idempotencyKey: requireIdempotencyKey(value['idempotencyKey']),
      mutationId: requireMutationId(value['mutationId']),
    };
  } catch {
    fail('CONTROL_POLICY_STORE_INPUT_INVALID');
  }
}

function requireOptions(value: unknown, allowed: readonly string[]): Record<string, unknown> {
  if (value === undefined) return {};
  if (!isRecord(value)) fail('CONTROL_POLICY_STORE_INPUT_INVALID');
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    fail('CONTROL_POLICY_STORE_INPUT_INVALID');
  }
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) fail('CONTROL_POLICY_STORE_INPUT_INVALID');
  }
  return value;
}

function requirePage(value: unknown): number {
  if (value === undefined) return DEFAULT_PAGE;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1 || value > MAX_PAGE) {
    fail('CONTROL_POLICY_STORE_INPUT_INVALID');
  }
  return value;
}

function normalizeError(error: unknown): ControlPolicyStoreError {
  if (error instanceof ControlPolicyStoreError) return error;
  if (isRecord(error) && typeof error.code === 'string') {
    switch (error.code) {
      case '28000':
        return new ControlPolicyStoreError('CONTROL_POLICY_STORE_SESSION_INVALID');
      case '42501':
        return new ControlPolicyStoreError('CONTROL_POLICY_STORE_FORBIDDEN');
      case '23503':
        return new ControlPolicyStoreError('CONTROL_POLICY_STORE_NOT_FOUND');
      case '23505':
        return new ControlPolicyStoreError('CONTROL_POLICY_STORE_CONFLICT');
      case 'P0D01':
        return new ControlPolicyStoreError('CONTROL_POLICY_STORE_IDEMPOTENCY_CONFLICT');
      case '22023':
      case '22P02':
      case '22001':
      case '22003':
      case '23514':
        return new ControlPolicyStoreError('CONTROL_POLICY_STORE_INPUT_INVALID');
      default:
        return new ControlPolicyStoreError('CONTROL_POLICY_STORE_UNAVAILABLE');
    }
  }
  return new ControlPolicyStoreError('CONTROL_POLICY_STORE_UNAVAILABLE');
}

function daysInMonth(year: number, month: number): number {
  return new Date(Date.UTC(year, month, 0)).getUTCDate();
}

function canonicalTimestamp(value: unknown): string {
  if (value instanceof Date) {
    if (!Number.isFinite(value.getTime())) failOutput();
    return value.toISOString();
  }
  if (typeof value !== 'string') failOutput();
  const match = PG_TIMESTAMP.exec(value);
  if (match === null) failOutput();
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, fraction, sign, offHourText, offMinuteText] = match;
  const year = Number.parseInt(yearText ?? '', 10);
  const month = Number.parseInt(monthText ?? '', 10);
  const day = Number.parseInt(dayText ?? '', 10);
  const hour = Number.parseInt(hourText ?? '', 10);
  const minute = Number.parseInt(minuteText ?? '', 10);
  const second = Number.parseInt(secondText ?? '', 10);
  const offHour = Number.parseInt(offHourText ?? '0', 10);
  const offMinute = Number.parseInt(offMinuteText ?? '0', 10);
  if (
    !Number.isInteger(year) || !Number.isInteger(month) || !Number.isInteger(day) ||
    !Number.isInteger(hour) || !Number.isInteger(minute) || !Number.isInteger(second) ||
    !Number.isInteger(offHour) || !Number.isInteger(offMinute) ||
    year < 1 || year > 9999 || month < 1 || month > 12 || day < 1 ||
    day > daysInMonth(year, month) || hour > 23 || minute > 59 || second > 59 ||
    offHour > 23 || offMinute > 59
  ) {
    failOutput();
  }
  const micros = (fraction ?? '').padEnd(6, '0').slice(0, 6);
  const offsetMinutes = (sign === '-' ? -1 : 1) * (offHour * 60 + offMinute);
  const local = new Date(0);
  local.setUTCFullYear(year, month - 1, day);
  local.setUTCHours(hour, minute, second, 0);
  const utcMillis = local.getTime() - offsetMinutes * 60_000;
  const normalized = new Date(utcMillis);
  if (!Number.isFinite(normalized.getTime())) failOutput();
  const iso = normalized.toISOString();
  return `${iso.slice(0, 19)}.${micros}Z`;
}

function canonicalTimestampOrNull(value: unknown): string | null {
  if (value === null) return null;
  if (value === undefined) failOutput();
  return canonicalTimestamp(value);
}

function requireOutputBoolean(value: unknown): boolean {
  if (value !== true && value !== false) failOutput();
  return value;
}

function requireAtMostOne<T>(rows: readonly T[]): T | undefined {
  if (rows.length > 1) failOutput();
  return rows[0];
}

function requireExactlyOne<T>(rows: readonly T[]): T {
  if (rows.length !== 1) failOutput();
  return rows[0] as T;
}

function parseOutputPolicyId(value: unknown): string {
  try {
    return parsePolicyId(value);
  } catch {
    failOutput();
  }
}

function parseOutputRevision(value: unknown): string {
  try {
    return parsePolicyRevisionNumber(value);
  } catch {
    failOutput();
  }
}

function requireOutputOrganization(value: unknown): string {
  if (typeof value !== 'string' || !ORG_ID.test(value)) failOutput();
  return value;
}

function requireOutputAgent(value: unknown): string {
  if (typeof value !== 'string' || !AGENT_ID.test(value)) failOutput();
  return value;
}

function parseOutputOperation(value: unknown): PolicyOperation {
  try {
    return parsePolicyOperation(value);
  } catch {
    failOutput();
  }
}

function parseOutputTimestamp(value: unknown): string {
  const parsed = IsoTimestampSchema.safeParse(value);
  if (!parsed.success) failOutput();
  return parsed.data;
}

interface RootRow extends Record<string, unknown> {
  readonly out_policy_id: string;
  readonly out_organization_id: string;
  readonly out_subject_agent_id: string;
  readonly out_current_revision: string;
  readonly out_status: string;
  readonly out_created_at: string;
  readonly out_updated_at: string;
}

interface RevisionRow extends Record<string, unknown> {
  readonly out_policy_id: string;
  readonly out_organization_id: string;
  readonly out_revision: string;
  readonly out_subject_agent_id: string;
  readonly out_network_id: string;
  readonly out_asset: string;
  readonly out_representation: string;
  readonly out_decimals: number;
  readonly out_per_action_limit: string | null;
  readonly out_rolling_limit: string | null;
  readonly out_rolling_window_seconds: string | null;
  readonly out_fee_limit: string;
  readonly out_allowed_provider_ids: string[];
  readonly out_allowed_listing_ids: string[];
  readonly out_approval_mode: string;
  readonly out_approval_threshold: string | null;
  readonly out_approval_separate_approver: boolean;
  readonly out_expires_at: string | null;
  readonly out_digest: string;
  readonly out_created_at: string;
}

interface SummaryRow extends Record<string, unknown> {
  readonly out_policy_id: string;
  readonly out_organization_id: string;
  readonly out_subject_agent_id: string;
  readonly out_revision: string;
  readonly out_digest: string;
  readonly out_created_at: string;
  readonly out_expires_at: string | null;
}

interface ReceiptFields extends Record<string, unknown> {
  readonly out_mutation_id: string;
  readonly out_operation: string;
  readonly out_resource_type: string;
  readonly out_resource_id: string;
  readonly out_committed_at: string;
}

interface ReceiptRow extends ReceiptFields {
  readonly out_replayed: boolean;
}

type StatusRow = ReceiptFields;

const COMMIT_SQL = `SELECT out_replayed, out_mutation_id, out_operation, out_resource_type,
       out_resource_id, out_committed_at::text AS out_committed_at
  FROM openarc_durable.commit_policy_mutation(
    $1, $2, $3, $4, $5, $6::timestamptz, $7, $8, $9, $10, $11::smallint,
    $12, $13, $14, $15, $16::text[], $17::text[], $18, $19, $20::boolean,
    $21::timestamptz, $22, $23::uuid, $24, $25, $26)`;

export class ControlPolicyStore {
  readonly #pool: TenantPool;
  readonly #base: TenantStore;
  #initialized = false;

  constructor(pool: TenantPool) {
    if (pool === null || typeof pool !== 'object' || typeof pool.connect !== 'function') {
      fail('CONTROL_POLICY_STORE_INPUT_INVALID');
    }
    this.#pool = pool;
    this.#base = new TenantStore(pool);
  }

  async initialize(): Promise<void> {
    if (this.#initialized) return;
    await this.#baseChecks(() => this.#base.initialize());
    await this.#withTransaction(async (client) => {
      await this.#assertPolicyReady(client);
    });
    this.#initialized = true;
  }

  async readiness(): Promise<void> {
    await this.#baseChecks(() => this.#base.readiness());
    await this.#withTransaction(async (client) => {
      await this.#assertPolicyReady(client);
    });
  }

  async #baseChecks(run: () => Promise<void>): Promise<void> {
    try {
      await run();
    } catch {
      fail('CONTROL_POLICY_STORE_UNAVAILABLE');
    }
  }

  async createPolicy(
    sessionHash: unknown,
    organizationId: unknown,
    content: unknown,
    metadata: unknown,
  ): Promise<ControlPolicyMutationResult> {
    const hash = requireSessionHash(sessionHash);
    const organization = requireOrganization(organizationId);
    const parsedContent = parseContentInput(content);
    if (parsedContent.organizationId !== organization) {
      fail('CONTROL_POLICY_STORE_INPUT_INVALID');
    }
    const meta = parseStrictMetadata(metadata);
    const operation: PolicyOperation = 'control.policy.create';
    return this.#commit(operation, hash, organization, null, null, null, parsedContent, meta);
  }

  async appendPolicyRevision(
    sessionHash: unknown,
    organizationId: unknown,
    policyId: unknown,
    input: AppendPolicyRevisionInput,
    metadata: unknown,
  ): Promise<ControlPolicyMutationResult> {
    const hash = requireSessionHash(sessionHash);
    const organization = requireOrganization(organizationId);
    const policy = parsePolicyIdInput(policyId);
    if (!isRecord(input)) fail('CONTROL_POLICY_STORE_INPUT_INVALID');
    const keys = Object.keys(input);
    if (keys.length !== 3) fail('CONTROL_POLICY_STORE_INPUT_INVALID');
    for (const key of keys) {
      if (!['expectedRevision', 'expectedUpdatedAt', 'content'].includes(key)) {
        fail('CONTROL_POLICY_STORE_INPUT_INVALID');
      }
    }
    const expectedRevision = parseAppendRevisionInput(input['expectedRevision']);
    const expectedUpdatedAt = parseTimestampInput(input['expectedUpdatedAt']);
    const parsedContent = parseContentInput(input['content']);
    if (parsedContent.organizationId !== organization) {
      fail('CONTROL_POLICY_STORE_INPUT_INVALID');
    }
    const meta = parseStrictMetadata(metadata);
    const operation: PolicyOperation = 'control.policy.revision.create';
    return this.#commit(
      operation,
      hash,
      organization,
      policy,
      expectedRevision,
      expectedUpdatedAt,
      parsedContent,
      meta,
    );
  }

  async transitionPolicy(
    sessionHash: unknown,
    organizationId: unknown,
    policyId: unknown,
    input: TransitionPolicyInput,
    metadata: unknown,
  ): Promise<ControlPolicyMutationResult> {
    const hash = requireSessionHash(sessionHash);
    const organization = requireOrganization(organizationId);
    const policy = parsePolicyIdInput(policyId);
    if (!isRecord(input)) fail('CONTROL_POLICY_STORE_INPUT_INVALID');
    const keys = Object.keys(input);
    if (keys.length !== 3) fail('CONTROL_POLICY_STORE_INPUT_INVALID');
    for (const key of keys) {
      if (!['operation', 'expectedRevision', 'expectedUpdatedAt'].includes(key)) {
        fail('CONTROL_POLICY_STORE_INPUT_INVALID');
      }
    }
    let operation: PolicyOperation;
    try {
      operation = parsePolicyOperation(input['operation']);
    } catch {
      fail('CONTROL_POLICY_STORE_INPUT_INVALID');
    }
    if (operation === 'control.policy.create' || operation === 'control.policy.revision.create') {
      fail('CONTROL_POLICY_STORE_INPUT_INVALID');
    }
    const expectedRevision = parseRevisionInput(input['expectedRevision']);
    const expectedUpdatedAt = parseTimestampInput(input['expectedUpdatedAt']);
    const meta = parseStrictMetadata(metadata);
    return this.#commit(
      operation,
      hash,
      organization,
      policy,
      expectedRevision,
      expectedUpdatedAt,
      null,
      meta,
    );
  }

  async #commit(
    operation: PolicyOperation,
    hash: string,
    organization: string,
    policy: string | null,
    expectedRevision: string | null,
    expectedUpdatedAt: string | null,
    content: CommercePolicyContent | null,
    meta: DurableMutationMetadata,
  ): Promise<ControlPolicyMutationResult> {
    const sessionContextDigest = digestPolicySessionContext(operation, hash);
    const keyHash = digestPolicyIdempotencyKey(operation, meta.idempotencyKey);
    const contentDigest = content === null ? null : digestPolicyContent(content);
    const isContentOperation =
      operation === 'control.policy.create' || operation === 'control.policy.revision.create';
    if (isContentOperation && (content === null || contentDigest === null)) {
      fail('CONTROL_POLICY_STORE_INPUT_INVALID');
    }
    const resourceType = POLICY_RESOURCE_BY_OPERATION[operation];
    return this.#withTransaction(async (client) => {
      const actor = await this.#lockWriter(client, hash, organization);
      const context = {
        organizationId: organization,
        actorAccountId: actor,
        actorRole: 'policy_writer',
        sessionContextDigest,
        mutationId: meta.mutationId,
      };
      let requestDigest: string;
      if (operation === 'control.policy.create') {
        requestDigest = digestPolicyCreateRequest(context, content as CommercePolicyContent, contentDigest as string);
      } else if (operation === 'control.policy.revision.create') {
        requestDigest = digestPolicyRevisionCreateRequest(
          context,
          policy as string,
          { expectedRevision: expectedRevision as string, expectedUpdatedAt: expectedUpdatedAt as string },
          contentDigest as string,
        );
      } else {
        requestDigest = digestPolicyTransitionRequest(operation, context, policy as string, {
          expectedRevision: expectedRevision as string,
          expectedUpdatedAt: expectedUpdatedAt as string,
        });
      }
      const result = await client.query<ReceiptRow>(COMMIT_SQL, [
        operation,
        hash,
        organization,
        policy,
        expectedRevision,
        expectedUpdatedAt,
        content?.subjectAgentId ?? null,
        content?.networkId ?? null,
        content?.asset ?? null,
        content?.representation ?? null,
        content?.decimals ?? null,
        content?.perActionLimit ?? null,
        content?.rollingLimit ?? null,
        content?.rollingWindowSeconds ?? null,
        content?.feeLimit ?? null,
        content?.allowedProviderIds ?? null,
        content?.allowedListingIds ?? null,
        content?.approval.mode ?? null,
        content?.approval.threshold ?? null,
        content?.approval.separateApprover ?? null,
        content?.expiresAt ?? null,
        contentDigest,
        meta.mutationId,
        keyHash,
        requestDigest,
        sessionContextDigest,
      ]);
      const row = requireExactlyOne(result.rows);
      const receiptRevision =
        operation === 'control.policy.revision.create' && expectedRevision !== null
          ? (BigInt(expectedRevision) + 1n).toString()
          : expectedRevision;
      return {
        replayed: requireOutputBoolean(row.out_replayed),
        receipt: this.#projectReceipt(row, operation, resourceType, meta.mutationId, policy, receiptRevision),
      };
    });
  }

  async getPolicyRoot(
    sessionHash: unknown,
    organizationId: unknown,
    policyId: unknown,
  ): Promise<CommercePolicyRoot | null> {
    const hash = requireSessionHash(sessionHash);
    const organization = requireOrganization(organizationId);
    const policy = parsePolicyIdInput(policyId);
    return this.#withTransaction(async (client) => {
      const result = await client.query<RootRow>(
        `SELECT out_policy_id, out_organization_id, out_subject_agent_id, out_current_revision,
                out_status, out_created_at::text AS out_created_at, out_updated_at::text AS out_updated_at
           FROM openarc_durable.read_policy_root($1, $2, $3)`,
        [hash, organization, policy],
      );
      const row = requireAtMostOne(result.rows);
      if (row === undefined) return null;
      const item = this.#projectRoot(row);
      if (item.organizationId !== organization || item.policyId !== policy) failOutput();
      return item;
    });
  }

  async listPolicyRoots(
    sessionHash: unknown,
    organizationId: unknown,
    options?: ListPolicyRootsInput,
  ): Promise<ListPolicyRootsResult> {
    const hash = requireSessionHash(sessionHash);
    const organization = requireOrganization(organizationId);
    const parsedOptions = requireOptions(options, ['afterPolicyId', 'limit']);
    const limit = requirePage(parsedOptions['limit']);
    const after =
      parsedOptions['afterPolicyId'] === undefined
        ? null
        : parsePolicyIdInput(parsedOptions['afterPolicyId']);
    return this.#withTransaction(async (client) => {
      const result = await client.query<RootRow>(
        `SELECT out_policy_id, out_organization_id, out_subject_agent_id, out_current_revision,
                out_status, out_created_at::text AS out_created_at, out_updated_at::text AS out_updated_at
           FROM openarc_durable.list_policy_roots($1, $2, $3, $4)`,
        [hash, organization, after, limit + 1],
      );
      if (result.rows.length > limit + 1) failOutput();
      const projected = result.rows.map((row) => this.#projectRoot(row));
      // Validate the whole fetched lookahead (limit+1) BEFORE slicing: every
      // row must bind the requested organization and the ids must be strictly
      // ascending and unique. A malformed 51st/foreign/unordered row must fail
      // closed rather than be silently discarded by the slice.
      let previousRootId: string | undefined;
      for (const item of projected) {
        if (item.organizationId !== organization) failOutput();
        if (previousRootId !== undefined && !(previousRootId < item.policyId)) failOutput();
        previousRootId = item.policyId;
      }
      const visible = projected.slice(0, limit);
      const nextCursor =
        result.rows.length > limit ? visible[visible.length - 1]?.policyId ?? null : null;
      // The accepted page schema caps the VISIBLE page (<=50); parse it for the
      // cursor/organization leaves. Full lookahead binding/order was checked
      // above so the sentinel row is not projected into the page schema.
      const page = CommercePolicyRootPageSchema.safeParse({
        organizationId: organization,
        items: visible,
        nextCursor,
      });
      if (!page.success) failOutput();
      if (after !== null) {
        const first = visible[0]?.policyId;
        if (first !== undefined && first <= after) failOutput();
      }
      return { items: visible, nextCursor };
    });
  }

  async getPolicyRevision(
    sessionHash: unknown,
    organizationId: unknown,
    policyId: unknown,
    revision: unknown,
  ): Promise<CommercePolicyRevision | null> {
    const hash = requireSessionHash(sessionHash);
    const organization = requireOrganization(organizationId);
    const policy = parsePolicyIdInput(policyId);
    const parsedRevision = parseRevisionInput(revision);
    return this.#withTransaction(async (client) => {
      const result = await client.query<RevisionRow>(
        `SELECT out_policy_id, out_organization_id, out_revision, out_subject_agent_id,
                out_network_id, out_asset, out_representation, out_decimals,
                out_per_action_limit, out_rolling_limit, out_rolling_window_seconds,
                out_fee_limit, out_allowed_provider_ids, out_allowed_listing_ids,
                out_approval_mode, out_approval_threshold, out_approval_separate_approver,
                out_expires_at::text AS out_expires_at, out_digest,
                out_created_at::text AS out_created_at
           FROM openarc_durable.read_policy_revision($1, $2, $3, $4)`,
        [hash, organization, policy, parsedRevision],
      );
      const row = requireAtMostOne(result.rows);
      if (row === undefined) return null;
      const item = this.#projectRevision(row);
      if (
        item.organizationId !== organization ||
        item.policyId !== policy ||
        item.revision !== parsedRevision
      ) {
        failOutput();
      }
      return item;
    });
  }

  async listPolicyRevisions(
    sessionHash: unknown,
    organizationId: unknown,
    policyId: unknown,
    options?: ListPolicyRevisionsInput,
  ): Promise<ListPolicyRevisionsResult> {
    const hash = requireSessionHash(sessionHash);
    const organization = requireOrganization(organizationId);
    const policy = parsePolicyIdInput(policyId);
    const parsedOptions = requireOptions(options, ['afterRevision', 'limit']);
    const limit = requirePage(parsedOptions['limit']);
    const after =
      parsedOptions['afterRevision'] === undefined
        ? null
        : parseRevisionInput(parsedOptions['afterRevision']);
    return this.#withTransaction(async (client) => {
      const result = await client.query<SummaryRow>(
        `SELECT out_policy_id, out_organization_id, out_subject_agent_id, out_revision,
                out_digest, out_created_at::text AS out_created_at,
                out_expires_at::text AS out_expires_at
           FROM openarc_durable.list_policy_revisions($1, $2, $3, $4, $5)`,
        [hash, organization, policy, after, limit + 1],
      );
      if (result.rows.length > limit + 1) failOutput();
      const projected = result.rows.map((row) => this.#projectSummary(row));
      // Validate the whole fetched lookahead (limit+1) BEFORE slicing: every
      // row must bind the requested org/policy and one subject agent, and the
      // revisions must be numerically ascending and unique. A malformed 51st/
      // foreign/unordered/mixed-subject row must fail closed, not be dropped.
      let previousRevision: bigint | undefined;
      let pageSubject: string | undefined;
      for (const item of projected) {
        if (item.organizationId !== organization || item.policyId !== policy) failOutput();
        if (!CommercePolicyRevisionNumberSchema.safeParse(item.revision).success) failOutput();
        const currentRevision = BigInt(item.revision);
        if (previousRevision !== undefined && !(previousRevision < currentRevision)) failOutput();
        previousRevision = currentRevision;
        if (pageSubject === undefined) {
          pageSubject = item.subjectAgentId;
        } else if (item.subjectAgentId !== pageSubject) {
          failOutput();
        }
      }
      const visible = projected.slice(0, limit);
      const nextCursor =
        result.rows.length > limit ? visible[visible.length - 1]?.revision ?? null : null;
      // The accepted page schema caps the VISIBLE page (<=50); parse it for the
      // cursor/subject leaves. Full lookahead binding/order was checked above so
      // the sentinel row is not projected into the page schema.
      const page = CommercePolicyHistoryPageSchema.safeParse({
        organizationId: organization,
        policyId: policy,
        items: visible,
        nextCursor,
      });
      if (!page.success) failOutput();
      if (after !== null) {
        const first = visible[0]?.revision;
        if (first !== undefined) {
          if (!CommercePolicyRevisionNumberSchema.safeParse(first).success) failOutput();
          if (BigInt(first) <= BigInt(after)) failOutput();
        }
      }
      return { items: visible, nextCursor };
    });
  }

  async getPolicyMutationStatus(
    sessionHash: unknown,
    organizationId: unknown,
    mutationId: unknown,
  ): Promise<ControlPolicyMutationStatus> {
    const hash = requireSessionHash(sessionHash);
    const organization = requireOrganization(organizationId);
    let mutation: string;
    try {
      mutation = requireMutationId(mutationId);
    } catch {
      fail('CONTROL_POLICY_STORE_INPUT_INVALID');
    }
    return this.#withTransaction(async (client) => {
      const result = await client.query<StatusRow>(
        `SELECT out_mutation_id, out_operation, out_resource_type, out_resource_id,
                out_committed_at::text AS out_committed_at
           FROM openarc_durable.read_policy_mutation_status($1, $2, $3::uuid)`,
        [hash, organization, mutation],
      );
      const row = requireAtMostOne(result.rows);
      if (row === undefined) return { status: 'not_found' } as const;
      const operation = parseOutputOperation(row.out_operation);
      const resourceType = this.#parseResourceType(row.out_resource_type);
      return {
        status: 'committed' as const,
        receipt: this.#projectReceipt(row, operation, resourceType, mutation, null, null),
      };
    });
  }

  #parseResourceType(value: unknown): PolicyResourceType {
    if (value !== 'budget_policy' && value !== 'budget_policy_revision') failOutput();
    return value;
  }

  async #lockWriter(client: TenantClient, hash: string, organization: string): Promise<string> {
    const result = await client.query<{ out_actor: string }>(
      `SELECT out_actor FROM openarc_durable.lock_policy_writer($1, $2)`,
      [hash, organization],
    );
    const row = result.rows[0];
    if (row === undefined || typeof row.out_actor !== 'string') {
      fail('CONTROL_POLICY_STORE_FORBIDDEN');
    }
    return row.out_actor;
  }

  #projectReceipt(
    row: ReceiptFields,
    operation: PolicyOperation,
    resourceType: PolicyResourceType,
    expectedMutationId: string,
    policy: string | null,
    revision: string | null,
  ): ControlPolicyMutationReceipt {
    if (row.out_operation !== operation) failOutput();
    if (row.out_resource_type !== resourceType) failOutput();
    // Parse through the accepted strict discriminated receipt so an operation
    // and resourceType that individually parse but do not form an accepted
    // tuple (for example budget_policy_revision@1) are rejected. The requested
    // operation/resource is then bound to the parsed tuple.
    const parsed = CommercePolicyMutationReceiptSchema.safeParse({
      mutationId: row.out_mutation_id,
      operation,
      resourceType,
      resourceId: row.out_resource_id,
      committedAt: parseOutputTimestamp(canonicalTimestamp(row.out_committed_at)),
    });
    if (!parsed.success) failOutput();
    const receipt = parsed.data;
    if (receipt.mutationId !== expectedMutationId) failOutput();
    if (receipt.operation !== operation || receipt.resourceType !== resourceType) failOutput();
    if (resourceType === 'budget_policy') {
      if (policy !== null && receipt.resourceId !== policy) failOutput();
    } else {
      const expected =
        policy !== null && revision !== null ? policyRevisionResourceId(policy, revision) : null;
      if (expected !== null && receipt.resourceId !== expected) failOutput();
    }
    return receipt;
  }

  #projectRoot(row: RootRow): CommercePolicyRoot {
    const parsed = CommercePolicyRootSchema.safeParse({
      schemaVersion: 'openarc.control.policy-root.v1',
      policyId: parseOutputPolicyId(row.out_policy_id),
      organizationId: requireOutputOrganization(row.out_organization_id),
      subjectAgentId: requireOutputAgent(row.out_subject_agent_id),
      currentRevision: parseOutputRevision(row.out_current_revision),
      status: row.out_status,
      createdAt: canonicalTimestamp(row.out_created_at),
      updatedAt: canonicalTimestamp(row.out_updated_at),
    });
    if (!parsed.success) failOutput();
    return parsed.data;
  }

  #projectRevision(row: RevisionRow): CommercePolicyRevision {
    if (row.out_decimals !== 6) failOutput();
    const parsed = CommercePolicyRevisionSchema.safeParse({
      schemaVersion: 'openarc.control.policy.v1',
      policyId: parseOutputPolicyId(row.out_policy_id),
      revision: parseOutputRevision(row.out_revision),
      organizationId: requireOutputOrganization(row.out_organization_id),
      subjectAgentId: requireOutputAgent(row.out_subject_agent_id),
      networkId: row.out_network_id,
      asset: row.out_asset,
      representation: row.out_representation,
      decimals: row.out_decimals,
      perActionLimit: row.out_per_action_limit,
      rollingLimit: row.out_rolling_limit,
      rollingWindowSeconds: row.out_rolling_window_seconds,
      feeLimit: row.out_fee_limit,
      allowedProviderIds: row.out_allowed_provider_ids,
      allowedListingIds: row.out_allowed_listing_ids,
      approval: {
        mode: row.out_approval_mode,
        threshold: row.out_approval_threshold,
        separateApprover: row.out_approval_separate_approver,
      },
      expiresAt: canonicalTimestampOrNull(row.out_expires_at),
      createdAt: canonicalTimestamp(row.out_created_at),
      digest: row.out_digest,
    });
    if (!parsed.success) failOutput();
    return parsed.data;
  }

  #projectSummary(row: SummaryRow): PolicyRevisionSummary {
    // Require the exact seven known summary keys. Only rejecting non-`out_`
    // keys would silently discard an injected `out_private` column.
    const keys = Object.keys(row).sort();
    const expectedKeys = [
      'out_created_at',
      'out_digest',
      'out_expires_at',
      'out_organization_id',
      'out_policy_id',
      'out_revision',
      'out_subject_agent_id',
    ].sort();
    if (
      keys.length !== expectedKeys.length ||
      keys.some((key, index) => key !== expectedKeys[index])
    ) {
      failOutput();
    }
    // Parse through the accepted strict summary schema so the expiry>creation
    // rule and every leaf are enforced by the frozen contract, not a copy.
    const parsed = CommercePolicyRevisionSummarySchema.safeParse({
      policyId: row.out_policy_id,
      organizationId: row.out_organization_id,
      subjectAgentId: row.out_subject_agent_id,
      revision: row.out_revision,
      digest: row.out_digest,
      createdAt: canonicalTimestamp(row.out_created_at),
      expiresAt: canonicalTimestampOrNull(row.out_expires_at),
    });
    if (!parsed.success) failOutput();
    return parsed.data;
  }

  async #assertPolicyReady(client: TenantClient): Promise<void> {
    const tables = await client.query<{ n: number; all_enabled: boolean; all_forced: boolean }>(
      `SELECT count(*)::int AS n,
              bool_and(c.relrowsecurity) AS all_enabled,
              bool_and(c.relforcerowsecurity) AS all_forced
         FROM pg_class c
         JOIN pg_namespace ns ON ns.oid = c.relnamespace
        WHERE ns.nspname = 'openarc_tenant'
          AND c.relkind = 'r'
          AND c.relname IN ('budget_policy_roots', 'budget_policy_versions')`,
    );
    const state = tables.rows[0];
    if (state === undefined || state.n !== 2 || state.all_enabled !== true || state.all_forced !== true) {
      fail('CONTROL_POLICY_STORE_UNAVAILABLE');
    }
    const owners = await client.query<{ n: number }>(
      `SELECT count(*)::int AS n
         FROM pg_class c
         JOIN pg_namespace ns ON ns.oid = c.relnamespace
         JOIN pg_roles r ON r.oid = c.relowner
        WHERE ns.nspname = 'openarc_tenant'
          AND c.relkind = 'r'
          AND c.relname IN ('budget_policy_roots', 'budget_policy_versions')
          AND r.rolname = 'openarc_migrator'`,
    );
    if ((owners.rows[0]?.n ?? -1) !== 2) fail('CONTROL_POLICY_STORE_UNAVAILABLE');

    const access = await client.query<{ n: number }>(
      `WITH reachable AS (
         SELECT r.oid FROM pg_roles r
          WHERE r.oid = (SELECT oid FROM pg_roles WHERE rolname = current_user)
             OR pg_has_role(current_user, r.oid, 'MEMBER')
       )
       SELECT count(*)::int AS n
         FROM pg_class c
         JOIN pg_namespace ns ON ns.oid = c.relnamespace
        WHERE ns.nspname = 'openarc_tenant'
          AND c.relkind = 'r'
          AND c.relname IN ('budget_policy_roots', 'budget_policy_versions')
          AND EXISTS (
            SELECT 1 FROM reachable x
             WHERE has_table_privilege(x.oid, c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
          )`,
    );
    if ((access.rows[0]?.n ?? -1) !== 0) fail('CONTROL_POLICY_STORE_UNAVAILABLE');

    const runtimePolicies = await client.query<{ n: number }>(
      `SELECT count(*)::int AS n
         FROM pg_policy p
         JOIN pg_class c ON c.oid = p.polrelid
         JOIN pg_namespace ns ON ns.oid = c.relnamespace
         JOIN unnest(p.polroles) AS o ON true
         JOIN pg_roles r ON r.oid = o
        WHERE ns.nspname = 'openarc_tenant'
          AND c.relname IN ('budget_policy_roots', 'budget_policy_versions')
          AND r.rolname IN ('openarc_tenant_app', 'openarc_worker_app', 'openarc_auth_app')`,
    );
    if ((runtimePolicies.rows[0]?.n ?? -1) !== 0) fail('CONTROL_POLICY_STORE_UNAVAILABLE');

    await this.#assertPolicyIntegrity(client);
    await this.#assertPolicyHelpers(client);
  }

  /**
   * Actual pg_catalog checks for the DB8-owned integrity controls. A text-only
   * index scan or a missing helper would otherwise pass readiness while the
   * create/resume race guard, immutability triggers, current-pointer FK or
   * content CHECKs were dropped or disabled.
   */
  async #assertPolicyIntegrity(client: TenantClient): Promise<void> {
    // Validated constraints with the exact relationship/definition. Each tuple
    // pins the table, the constraint name, its type and a required fragment of
    // the server-rendered definition.
    const expectedConstraints: readonly {
      readonly table: string;
      readonly name: string;
      readonly type: string;
      readonly def: string;
    }[] = [
      {
        table: 'budget_policy_roots',
        name: 'budget_policy_roots_current_fk',
        type: 'f',
        def: 'FOREIGN KEY (organization_id, policy_id, current_revision) REFERENCES openarc_tenant.budget_policy_versions(organization_id, policy_id, revision)',
      },
      {
        table: 'budget_policy_versions',
        name: 'budget_policy_versions_content_valid',
        type: 'c',
        def: 'is_valid_policy_content(',
      },
      {
        table: 'budget_policy_versions',
        name: 'budget_policy_versions_root_fk',
        type: 'f',
        def: 'FOREIGN KEY (organization_id, policy_id, subject_agent_id) REFERENCES openarc_tenant.budget_policy_roots(organization_id, policy_id, subject_agent_id)',
      },
      {
        table: 'budget_policy_roots',
        name: 'budget_policy_roots_status_valid',
        type: 'c',
        def: "status = ANY (ARRAY['active'::text, 'paused'::text, 'revoked'::text])",
      },
      {
        table: 'budget_policy_roots',
        name: 'budget_policy_roots_subject_fk',
        type: 'f',
        def: 'FOREIGN KEY (organization_id, subject_agent_id) REFERENCES openarc_tenant.agents(organization_id, agent_id)',
      },
    ];
    const constraints = await client.query<{
      relname: string;
      conname: string;
      contype: string;
      convalidated: boolean;
      condef: string;
    }>(
      `SELECT c.relname, con.conname, con.contype, con.convalidated,
              pg_get_constraintdef(con.oid) AS condef
         FROM pg_constraint con
         JOIN pg_class c ON c.oid = con.conrelid
         JOIN pg_namespace ns ON ns.oid = c.relnamespace
        WHERE ns.nspname = 'openarc_tenant'
          AND c.relname IN ('budget_policy_roots', 'budget_policy_versions')
          AND con.conname = ANY ($1::text[])`,
      [expectedConstraints.map((entry) => entry.name)],
    );
    const constraintByName = new Map(constraints.rows.map((row) => [row.conname, row]));
    for (const expected of expectedConstraints) {
      const row = constraintByName.get(expected.name);
      if (row === undefined) fail('CONTROL_POLICY_STORE_UNAVAILABLE');
      if (
        row.relname !== expected.table ||
        row.contype !== expected.type ||
        row.convalidated !== true ||
        typeof row.condef !== 'string' ||
        !row.condef.includes(expected.def)
      ) {
        fail('CONTROL_POLICY_STORE_UNAVAILABLE');
      }
    }

    // Enabled row-level triggers attached to the exact expected function.
    const expectedTriggers: readonly {
      readonly table: string;
      readonly name: string;
      readonly func: string;
    }[] = [
      {
        table: 'budget_policy_versions',
        name: 'budget_policy_versions_immutable',
        func: 'openarc_tenant.reject_policy_version_mutation',
      },
      {
        table: 'budget_policy_roots',
        name: 'budget_policy_roots_mutation',
        func: 'openarc_tenant.enforce_policy_root_mutation',
      },
    ];
    const triggers = await client.query<{
      relname: string;
      tgname: string;
      tgenabled: string;
      tgtype: number;
      func: string;
    }>(
      `SELECT c.relname, t.tgname, t.tgenabled, t.tgtype,
              format('%I.%I', fn.nspname, f.proname) AS func
         FROM pg_trigger t
         JOIN pg_class c ON c.oid = t.tgrelid
         JOIN pg_namespace ns ON ns.oid = c.relnamespace
         JOIN pg_proc f ON f.oid = t.tgfoid
         JOIN pg_namespace fn ON fn.oid = f.pronamespace
        WHERE ns.nspname = 'openarc_tenant'
          AND NOT t.tgisinternal
          AND t.tgname = ANY ($1::text[])`,
      [expectedTriggers.map((entry) => entry.name)],
    );
    const triggerByName = new Map(triggers.rows.map((row) => [row.tgname, row]));
    for (const expected of expectedTriggers) {
      const row = triggerByName.get(expected.name);
      if (row === undefined) fail('CONTROL_POLICY_STORE_UNAVAILABLE');
      if (
        row.relname !== expected.table ||
        row.tgenabled !== 'O' ||
        row.func !== expected.func ||
        ((row.tgtype & 4) !== 4 && (row.tgtype & 8) !== 8 && (row.tgtype & 16) !== 16)
      ) {
        fail('CONTROL_POLICY_STORE_UNAVAILABLE');
      }
    }

    // Active unique index must be valid AND ready, not merely present as text.
    const activeIndex = await client.query<{
      indisunique: boolean;
      indisvalid: boolean;
      indisready: boolean;
      keydef: string;
      preddef: string;
    }>(
      `SELECT i.indisunique, i.indisvalid, i.indisready,
              pg_get_indexdef(i.indexrelid) AS keydef,
              coalesce(pg_get_expr(i.indpred, i.indrelid), '') AS preddef
         FROM pg_index i
         JOIN pg_class ic ON ic.oid = i.indexrelid
         JOIN pg_namespace ns ON ns.oid = ic.relnamespace
        WHERE ns.nspname = 'openarc_tenant' AND ic.relname = 'budget_policy_roots_one_active'`,
    );
    const active = activeIndex.rows[0];
    if (
      active === undefined ||
      active.indisunique !== true ||
      active.indisvalid !== true ||
      active.indisready !== true ||
      typeof active.keydef !== 'string' ||
      !active.keydef.includes('(organization_id, subject_agent_id)') ||
      typeof active.preddef !== 'string' ||
      active.preddef !== "(status = 'active'::text)"
    ) {
      fail('CONTROL_POLICY_STORE_UNAVAILABLE');
    }
  }

  async #assertPolicyHelpers(client: TenantClient): Promise<void> {
    const expected: readonly { name: string; args: string }[] = [
      { name: 'lock_policy_writer', args: 'session_hash text, organization_id text' },
      { name: 'lock_policy_reader', args: 'session_hash text, organization_id text' },
      {
        name: 'commit_policy_mutation',
        args: 'operation text, session_hash text, organization_id text, policy_id text, expected_revision text, expected_updated_at timestamp with time zone, subject_agent_id text, network_id text, asset text, representation text, decimals smallint, per_action_limit text, rolling_limit text, rolling_window_seconds text, fee_limit text, allowed_provider_ids text[], allowed_listing_ids text[], approval_mode text, approval_threshold text, approval_separate_approver boolean, expires_at timestamp with time zone, digest text, mutation_id uuid, key_hash text, request_digest text, session_context_digest text',
      },
      { name: 'read_policy_root', args: 'session_hash text, organization_id text, policy_id text' },
      { name: 'list_policy_roots', args: 'session_hash text, organization_id text, after_policy_id text, page_limit integer' },
      { name: 'read_policy_revision', args: 'session_hash text, organization_id text, policy_id text, revision text' },
      { name: 'list_policy_revisions', args: 'session_hash text, organization_id text, policy_id text, after_revision text, page_limit integer' },
      { name: 'read_policy_mutation_status', args: 'session_hash text, organization_id text, mutation_id uuid' },
    ];
    const helpers = await client.query<{
      proname: string;
      args: string;
      owner: string;
      prosecdef: boolean;
      config: string[];
      app_exec: boolean;
      public_grants: number;
      forbidden_grants: number;
    }>(
      `SELECT p.proname,
              pg_get_function_identity_arguments(p.oid) AS args,
              r.rolname AS owner,
              p.prosecdef,
              coalesce(p.proconfig, ARRAY[]::text[]) AS config,
              has_function_privilege('openarc_tenant_app', p.oid, 'EXECUTE') AS app_exec,
              (SELECT count(*)::int
                 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE') AS public_grants,
              (SELECT count(*)::int
                 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                 JOIN pg_roles gr ON gr.oid = a.grantee
                WHERE gr.rolname IN ('openarc_worker_app', 'openarc_auth_app')
                  AND a.privilege_type = 'EXECUTE') AS forbidden_grants
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         JOIN pg_roles r ON r.oid = p.proowner
        WHERE n.nspname = 'openarc_durable'
          AND p.prokind = 'f'
          AND p.proname IN (
            'lock_policy_writer', 'lock_policy_reader', 'commit_policy_mutation',
            'read_policy_root', 'list_policy_roots', 'read_policy_revision',
            'list_policy_revisions', 'read_policy_mutation_status'
          )
        ORDER BY p.proname, p.oid`,
    );
    const byName = new Map(helpers.rows.map((row) => [row.proname, row]));
    for (const spec of expected) {
      const row = byName.get(spec.name);
      if (row === undefined) fail('CONTROL_POLICY_STORE_UNAVAILABLE');
      if (
        row.args !== spec.args ||
        row.owner !== 'openarc_migrator' ||
        row.prosecdef !== true ||
        !Array.isArray(row.config) ||
        !row.config.includes('search_path=pg_catalog') ||
        row.app_exec !== true ||
        row.public_grants !== 0 ||
        row.forbidden_grants !== 0
      ) {
        fail('CONTROL_POLICY_STORE_UNAVAILABLE');
      }
    }
    if (helpers.rows.length !== expected.length) fail('CONTROL_POLICY_STORE_UNAVAILABLE');

    // Internal validators/triggers must actually exist with the expected
    // owner, fixed search_path and definer/invoker mode, and must expose no
    // execute privilege to the runtime, worker, auth or PUBLIC. A missing
    // helper must fail readiness rather than pass a permissive absence check.
    const expectedInternal: readonly {
      readonly schema: string;
      readonly name: string;
      readonly secdef: boolean;
    }[] = [
      { schema: 'openarc_durable', name: 'is_canonical_policy_id', secdef: false },
      { schema: 'openarc_durable', name: 'is_canonical_agent_id', secdef: false },
      { schema: 'openarc_durable', name: 'is_canonical_provider_id', secdef: false },
      { schema: 'openarc_durable', name: 'is_canonical_policy_revision', secdef: false },
      { schema: 'openarc_durable', name: 'is_canonical_uint256', secdef: false },
      { schema: 'openarc_durable', name: 'is_positive_uint256', secdef: false },
      { schema: 'openarc_durable', name: 'is_valid_policy_provider_list', secdef: false },
      { schema: 'openarc_durable', name: 'is_valid_policy_listing_list', secdef: false },
      { schema: 'openarc_durable', name: 'is_valid_policy_approval', secdef: false },
      { schema: 'openarc_durable', name: 'is_valid_policy_content', secdef: false },
      { schema: 'openarc_durable', name: 'assert_policy_content', secdef: false },
      { schema: 'openarc_durable', name: 'lock_policy_actor', secdef: true },
      { schema: 'openarc_tenant', name: 'reject_policy_version_mutation', secdef: false },
      { schema: 'openarc_tenant', name: 'enforce_policy_root_mutation', secdef: false },
    ];
    const internal = await client.query<{
      schema: string;
      name: string;
      owner: string;
      secdef: boolean;
      config: string[];
      exposed: boolean;
    }>(
      `SELECT n.nspname AS schema, p.proname AS name, r.rolname AS owner,
              p.prosecdef AS secdef,
              coalesce(p.proconfig, ARRAY[]::text[]) AS config,
              (has_function_privilege('openarc_tenant_app', p.oid, 'EXECUTE')
                OR has_function_privilege('openarc_worker_app', p.oid, 'EXECUTE')
                OR has_function_privilege('openarc_auth_app', p.oid, 'EXECUTE')
                OR EXISTS (
                  SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                   WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE'
                )) AS exposed
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         JOIN pg_roles r ON r.oid = p.proowner
        WHERE n.nspname IN ('openarc_durable', 'openarc_tenant')
          AND p.proname = ANY ($1::text[])`,
      [expectedInternal.map((entry) => entry.name)],
    );
    const internalByKey = new Map(internal.rows.map((row) => [`${row.schema}.${row.name}`, row]));
    for (const expected of expectedInternal) {
      const row = internalByKey.get(`${expected.schema}.${expected.name}`);
      if (row === undefined) fail('CONTROL_POLICY_STORE_UNAVAILABLE');
      if (
        row.owner !== 'openarc_migrator' ||
        row.secdef !== expected.secdef ||
        !Array.isArray(row.config) ||
        !row.config.includes('search_path=pg_catalog') ||
        row.exposed !== false
      ) {
        fail('CONTROL_POLICY_STORE_UNAVAILABLE');
      }
    }
  }

  async #withTransaction<T>(work: (client: TenantClient) => Promise<T>): Promise<T> {
    let client: TenantClient;
    try {
      client = await this.#pool.connect();
    } catch {
      fail('CONTROL_POLICY_STORE_UNAVAILABLE');
    }
    try {
      await client.query('BEGIN');
      await client.query(`SET LOCAL statement_timeout = '${POLICY_STATEMENT_TIMEOUT_MS}ms'`);
      await client.query(`SET LOCAL lock_timeout = '${POLICY_LOCK_TIMEOUT_MS}ms'`);
    } catch {
      this.#release(client, true);
      fail('CONTROL_POLICY_STORE_UNAVAILABLE');
    }
    let result: T;
    try {
      result = await work(client);
    } catch (error) {
      let rolledBack = false;
      try {
        await client.query('ROLLBACK');
        rolledBack = true;
      } catch {
        rolledBack = false;
      }
      this.#release(client, !rolledBack);
      throw normalizeError(error);
    }
    try {
      await client.query('COMMIT');
    } catch {
      this.#release(client, true);
      fail('CONTROL_POLICY_STORE_OUTCOME_UNKNOWN');
    }
    this.#release(client, false);
    return result;
  }

  #release(client: TenantClient, destroy: boolean): void {
    try {
      client.release(destroy);
    } catch {
      // A release failure after a confirmed outcome cannot change that outcome.
    }
  }
}

export function asControlPolicyPool(pool: Pool): TenantPool {
  return pool as unknown as TenantPool;
}

export { PolicyInputError, POLICY_EVENT_BY_OPERATION };
