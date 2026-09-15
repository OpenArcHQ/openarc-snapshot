import { createHash } from 'node:crypto';
import type { Pool } from 'pg';
import {
  CommerceActionMetadataSchema,
  CommerceApprovalMetadataSchema,
  compareIsoTimestamps,
  type CommerceActionMetadata,
  type CommerceActionStatus,
  type CommerceApprovalMetadata,
  type CommerceApprovalStatus,
} from '@openarc/shared';
import { loadMigrations } from './migrate.js';
import { TenantStore, type TenantClient, type TenantPool } from './tenant-store.js';
import { parseMutationId } from './tenant-durability.js';
import { CommerceSessionStore } from './control-session-store.js';
import { ControlPolicyStore } from './control-policy-store.js';
import { CredentialStore } from './credential-store.js';
import {
  CONTROL_ACTION_RESOURCE_TYPE,
  CommerceActionInputError,
  digestCommerceActionAuthorizeRequest,
  digestCommerceActionCancelRequest,
  digestCommerceActionDecisionRequest,
  digestCommerceActionHumanContext,
  digestCommerceActionIdempotencyKey,
  digestCommerceActionMachineContext,
  parseCommerceActionHash,
  parseCommerceActionId,
  parseCommerceActionMetadata,
  parseCommerceApprovalMetadata,
  parseCommerceRequirementId,
  requireIdempotencyKey,
  type CommerceActionOperation,
} from './control-action-mutations.js';

/**
 * ControlActionStore over the accepted restricted tenant pool. Every method
 * runs in one connection/transaction through the reviewed SECURITY DEFINER
 * helpers and never migrates. The production wrapper receives the literal
 * 'production' mode; there is no option selecting a fixture mode. Outputs
 * strict-parse the frozen shared action/approval DTOs and collapse any
 * malformed driver row to a fixed UNAVAILABLE error.
 */

export const CONTROL_ACTION_STORE_ERROR_MESSAGES = {
  CONTROL_ACTION_STORE_INPUT_INVALID: 'ControlActionStore input is invalid.',
  CONTROL_ACTION_STORE_SESSION_INVALID: 'ControlActionStore session is not valid.',
  CONTROL_ACTION_STORE_FORBIDDEN: 'ControlActionStore caller is not permitted.',
  CONTROL_ACTION_STORE_NOT_FOUND: 'ControlActionStore target was not found.',
  CONTROL_ACTION_STORE_CONFLICT: 'ControlActionStore operation conflicts with existing state.',
  CONTROL_ACTION_STORE_EXPIRED: 'ControlActionStore target authority has expired.',
  CONTROL_ACTION_STORE_REQUIREMENT_UNAVAILABLE:
    'ControlActionStore requirement is unavailable in production.',
  CONTROL_ACTION_STORE_BUDGET_DENIED: 'ControlActionStore budget denies the action.',
  CONTROL_ACTION_STORE_POTENTIAL_EXPOSURE:
    'ControlActionStore target has potential exposure and cannot be cancelled.',
  CONTROL_ACTION_STORE_IDEMPOTENCY_CONFLICT:
    'ControlActionStore mutation conflicts with an existing idempotency record.',
  CONTROL_ACTION_STORE_STALE_TERMS:
    'ControlActionStore pinned policy terms are no longer current.',
  CONTROL_ACTION_STORE_UNAVAILABLE: 'ControlActionStore is not available.',
  CONTROL_ACTION_STORE_OUTCOME_UNKNOWN:
    'ControlActionStore mutation outcome could not be confirmed; it may have committed.',
} as const;

export type ControlActionStoreErrorCode = keyof typeof CONTROL_ACTION_STORE_ERROR_MESSAGES;

/** Fixed, non-echoing repository error. Never carries driver detail. */
export class ControlActionStoreError extends Error {
  readonly code: ControlActionStoreErrorCode;

  constructor(code: ControlActionStoreErrorCode) {
    super(CONTROL_ACTION_STORE_ERROR_MESSAGES[code]);
    this.name = 'ControlActionStoreError';
    this.code = code;
  }
}

export interface CommerceActionMutationMetadata {
  readonly idempotencyKey: string;
  readonly mutationId: string;
}

export interface AuthorizeCommerceActionInput {
  readonly requirementId: string;
  readonly actionId: string;
}

export interface CommerceActionTransactionReceipt {
  readonly mutationId: string;
  readonly operation: CommerceActionOperation;
  readonly resourceType: typeof CONTROL_ACTION_RESOURCE_TYPE;
  readonly resourceId: string;
  readonly committedAt: string;
}

export interface CommerceActionMutationDbResult {
  readonly replayed: boolean;
  readonly metadata: CommerceActionMetadata;
  readonly receipt: CommerceActionTransactionReceipt;
}

export interface CommerceActionDecisionDbResult {
  readonly replayed: boolean;
  readonly metadata: CommerceActionMetadata;
  readonly receipt: CommerceActionTransactionReceipt;
}

export type CommerceActionMutationStatus =
  | { readonly status: 'committed'; readonly receipt: CommerceActionTransactionReceipt }
  | { readonly status: 'not_found' };

/**
 * Agent read of its own exact-commerce-session-bound action. `organizationId`
 * is always the DB-derived authenticated buyer org, even on not-found, so an
 * HTTP layer can build a strict detail response without caller-supplied org.
 */
export interface CommerceAgentActionRead {
  readonly organizationId: string;
  readonly actionId: string;
  readonly item: CommerceActionMetadata | null;
}

export interface CommerceExposureView {
  readonly organizationId: string;
  readonly subjectAgentId: string;
  readonly policyId: string;
  readonly policyRevision: string;
  readonly networkId: string;
  readonly asset: string;
  readonly representation: string;
  readonly decimals: number;
  readonly windowSeconds: string | null;
  readonly committedAtomic: string;
  readonly unresolvedAtomic: string;
  readonly totalExposureAtomic: string;
  readonly availableAtomic: string | null;
  readonly deficitAtomic: string;
  readonly asOf: string;
}

const ORG_ID = /^openarc:org:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const AGENT_ID = /^openarc:agent:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const POLICY_ID = /^openarc:policy:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
// Absolute-end canonical bounded decimal. A plain `$` would accept a trailing
// LF in JavaScript, relabeling a malformed operand as valid.
const DECIMAL = /^(0|[1-9][0-9]{0,127})$(?![\s\S])/;
// Frozen accepted policy rolling-window bound: canonical seconds 1..2592000.
const WINDOW_SECONDS = /^[1-9][0-9]{0,6}$(?![\s\S])/;
const WINDOW_SECONDS_MAX = 2592000n;
const EXPOSURE_IDENTITY = {
  networkId: 'eip155:5042002',
  asset: 'USDC',
  representation: 'erc20',
  decimals: 6,
} as const;

function fail(code: ControlActionStoreErrorCode): never {
  throw new ControlActionStoreError(code);
}

function failOutput(): never {
  fail('CONTROL_ACTION_STORE_UNAVAILABLE');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireHash(value: unknown): string {
  try {
    return parseCommerceActionHash(value);
  } catch {
    fail('CONTROL_ACTION_STORE_INPUT_INVALID');
  }
}

function requireOrganization(value: unknown): string {
  if (typeof value !== 'string' || !ORG_ID.test(value)) fail('CONTROL_ACTION_STORE_INPUT_INVALID');
  return value;
}

function requireAgent(value: unknown): string {
  if (typeof value !== 'string' || !AGENT_ID.test(value)) fail('CONTROL_ACTION_STORE_INPUT_INVALID');
  return value;
}

function requirePolicy(value: unknown): string {
  if (typeof value !== 'string' || !POLICY_ID.test(value)) {
    fail('CONTROL_ACTION_STORE_INPUT_INVALID');
  }
  return value;
}

function requireAction(value: unknown): string {
  try {
    return parseCommerceActionId(value);
  } catch {
    fail('CONTROL_ACTION_STORE_INPUT_INVALID');
  }
}

function requireRequirement(value: unknown): string {
  try {
    return parseCommerceRequirementId(value);
  } catch {
    fail('CONTROL_ACTION_STORE_INPUT_INVALID');
  }
}

function requireMetadata(value: unknown): CommerceActionMutationMetadata {
  if (!isRecord(value)) fail('CONTROL_ACTION_STORE_INPUT_INVALID');
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    fail('CONTROL_ACTION_STORE_INPUT_INVALID');
  }
  const keys = Object.keys(value);
  if (keys.length !== 2 || !keys.includes('idempotencyKey') || !keys.includes('mutationId')) {
    fail('CONTROL_ACTION_STORE_INPUT_INVALID');
  }
  let mutationId: string;
  try {
    mutationId = parseMutationId(value['mutationId']);
    requireIdempotencyKey(value['idempotencyKey']);
  } catch {
    fail('CONTROL_ACTION_STORE_INPUT_INVALID');
  }
  return { idempotencyKey: value['idempotencyKey'] as string, mutationId };
}

function requireExactlyOne<T>(rows: readonly T[]): T {
  if (rows.length !== 1 || rows[0] === undefined) failOutput();
  return rows[0];
}

function requireAtMostOne<T>(rows: readonly T[]): T | undefined {
  if (rows.length > 1) failOutput();
  return rows[0];
}

/**
 * Exact RAISE literals SQL10 uses for state conflicts and expiry under 23514.
 * Matching is on the full message, never a substring, so a CHECK constraint
 * whose name merely contains one of these words cannot be misread.
 */
const EXPIRED_23514 = new Set(['commerce_expired']);
const CONFLICT_23514 = new Set([
  'commerce_cancel_conflict',
  'commerce_decision_conflict',
]);

function classify23514(error: Record<string, unknown>): ControlActionStoreErrorCode {
  const message = error['message'];
  if (typeof message === 'string') {
    if (EXPIRED_23514.has(message)) return 'CONTROL_ACTION_STORE_EXPIRED';
    if (CONFLICT_23514.has(message)) return 'CONTROL_ACTION_STORE_CONFLICT';
  }
  return 'CONTROL_ACTION_STORE_INPUT_INVALID';
}

function normalizeError(error: unknown): ControlActionStoreError {
  if (error instanceof ControlActionStoreError) return error;
  if (error instanceof CommerceActionInputError) return new ControlActionStoreError('CONTROL_ACTION_STORE_INPUT_INVALID');
  if (isRecord(error) && typeof error.code === 'string') {
    switch (error.code) {
      case '28000':
        return new ControlActionStoreError('CONTROL_ACTION_STORE_SESSION_INVALID');
      case '42501':
        return new ControlActionStoreError('CONTROL_ACTION_STORE_FORBIDDEN');
      case '23503':
        return new ControlActionStoreError('CONTROL_ACTION_STORE_NOT_FOUND');
      case '23505':
        return new ControlActionStoreError('CONTROL_ACTION_STORE_CONFLICT');
      case 'P0D01':
        return new ControlActionStoreError('CONTROL_ACTION_STORE_IDEMPOTENCY_CONFLICT');
      case 'P0D10':
        return new ControlActionStoreError('CONTROL_ACTION_STORE_REQUIREMENT_UNAVAILABLE');
      case 'P0D11':
        return new ControlActionStoreError('CONTROL_ACTION_STORE_UNAVAILABLE');
      case 'P0D12':
        return new ControlActionStoreError('CONTROL_ACTION_STORE_BUDGET_DENIED');
      case 'P0D13':
        return new ControlActionStoreError('CONTROL_ACTION_STORE_POTENTIAL_EXPOSURE');
      case '40001':
        return new ControlActionStoreError('CONTROL_ACTION_STORE_STALE_TERMS');
      case '22023':
      case '22P02':
      case '22001':
      case '22003':
        return new ControlActionStoreError('CONTROL_ACTION_STORE_INPUT_INVALID');
      // SQLSTATE 23514 carries three semantically different families in SQL10:
      // expiry, state conflict, and genuine CHECK/operand violations. Collapsing
      // them all into INPUT_INVALID is wrong on the recovery path: a caller that
      // lost a response and retried was told to fix its input, when the truth
      // was that the target had already moved on and it must stop and reconcile
      // through the status read instead. The RAISE literals below are fixed,
      // internal and never caller-controlled; anything else stays INPUT_INVALID,
      // so an unrecognised CHECK violation still fails exactly as before.
      case '23514':
        return new ControlActionStoreError(classify23514(error));
      default:
        return new ControlActionStoreError('CONTROL_ACTION_STORE_UNAVAILABLE');
    }
  }
  return new ControlActionStoreError('CONTROL_ACTION_STORE_UNAVAILABLE');
}

const PG_TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?([+-])(\d{2})(?::?(\d{2}))?$/;

function daysInMonth(year: number, month: number): number {
  return new Date(Date.UTC(year, month, 0)).getUTCDate();
}

function iso(value: unknown): string {
  if (value instanceof Date) {
    if (!Number.isFinite(value.getTime())) failOutput();
    const text = value.toISOString();
    return `${text.slice(0, 19)}.${text.slice(20, 23)}000Z`;
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
  const normalized = new Date(local.getTime() - offsetMinutes * 60_000);
  if (!Number.isFinite(normalized.getTime())) failOutput();
  const base = normalized.toISOString();
  return `${base.slice(0, 19)}.${micros}Z`;
}

function isoOrNull(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  return iso(value);
}

interface ActionRow extends Record<string, unknown> {
  readonly out_replayed: boolean;
  readonly out_action_id: string;
  readonly out_organization_id: string;
  readonly out_subject_agent_id: string;
  readonly out_commerce_session_id: string;
  readonly out_status: string;
  readonly out_amount_atomic: string;
  readonly out_fee_atomic: string;
  readonly out_debit_atomic: string;
  readonly out_policy_id: string;
  readonly out_policy_revision: string;
  readonly out_provider_id: string;
  readonly out_listing_id: string;
  readonly out_listing_version: string;
  readonly out_requirement_id: string;
  readonly out_requirement_digest: string;
  readonly out_network_id: string;
  readonly out_asset: string;
  readonly out_representation: string;
  readonly out_decimals: number;
  readonly out_source_kind?: string;
  readonly out_reservation_id: string | null;
  readonly out_approval_id: string | null;
  readonly out_created_at: string | Date;
  readonly out_updated_at: string | Date;
  readonly out_expires_at: string | Date;
  readonly out_committed_at: string | Date;
}

export class ControlActionStore {
  readonly #pool: TenantPool;
  readonly #base: TenantStore;
  #initialized = false;

  constructor(pool: TenantPool) {
    if (pool === null || typeof pool !== 'object' || typeof pool.connect !== 'function') {
      fail('CONTROL_ACTION_STORE_INPUT_INVALID');
    }
    this.#pool = pool;
    this.#base = new TenantStore(pool);
  }

  async initialize(): Promise<void> {
    if (this.#initialized) return;
    await this.#baseChecks(() => this.#base.initialize());
    await this.#baseChecks(() => new CommerceSessionStore(this.#pool).initialize());
    await this.#baseChecks(() => new ControlPolicyStore(this.#pool).initialize());
    await this.#baseChecks(() => new CredentialStore(this.#pool).initialize());
    await this.#withTransaction(async (client) => {
      await this.#assertReady(client);
    });
    this.#initialized = true;
  }

  async readiness(): Promise<void> {
    await this.#baseChecks(() => this.#base.readiness());
    await this.#baseChecks(() => new CommerceSessionStore(this.#pool).readiness());
    await this.#baseChecks(() => new ControlPolicyStore(this.#pool).readiness());
    await this.#baseChecks(() => new CredentialStore(this.#pool).readiness());
    await this.#withTransaction(async (client) => {
      await this.#assertReady(client);
    });
  }

  async #baseChecks(run: () => Promise<void>): Promise<void> {
    try {
      await run();
    } catch {
      fail('CONTROL_ACTION_STORE_UNAVAILABLE');
    }
  }

  /**
   * Agent authorize. The input presents ONLY the commerce oacs_v1 token hash
   * and the immutable requirement/action ids; the production wrapper receives
   * the literal 'production' mode and never a caller-selected fixture flag.
   */
  async authorizeCommerceAction(
    commerceTokenHash: unknown,
    input: AuthorizeCommerceActionInput,
    metadata: unknown,
  ): Promise<CommerceActionMutationDbResult> {
    const tokenHash = requireHash(commerceTokenHash);
    if (!isRecord(input)) fail('CONTROL_ACTION_STORE_INPUT_INVALID');
    const inputKeys = Object.keys(input);
    for (const key of inputKeys) {
      if (key !== 'requirementId' && key !== 'actionId') {
        fail('CONTROL_ACTION_STORE_INPUT_INVALID');
      }
    }
    const requirementId = requireRequirement(input['requirementId']);
    const actionId = requireAction(input['actionId']);
    const meta = requireMetadata(metadata);
    const operation: CommerceActionOperation = 'control.commerce_action.authorize';
    const sessionContextDigest = digestCommerceActionMachineContext(tokenHash);
    const keyHash = digestCommerceActionIdempotencyKey(operation, meta.idempotencyKey);
    return this.#withTransaction(async (client) => {
      const context = await this.#resolveAuthorizeContext(client, tokenHash);
      const requirement = await this.#resolveRequirement(client, requirementId);
      const requestDigest = digestCommerceActionAuthorizeRequest({
        organizationId: context.organizationId,
        parentHumanAccountId: context.parentHumanAccountId,
        commerceSessionId: context.commerceSessionId,
        agentSessionId: context.agentSessionId,
        credentialId: context.credentialId,
        policyId: context.policyId,
        actionId,
        requirementId,
        requirementDigest: requirement.requirementDigest,
        amountAtomic: requirement.amountAtomic,
        feeAtomic: requirement.feeAtomic,
        networkId: requirement.networkId,
        asset: requirement.asset,
        representation: requirement.representation,
        decimals: requirement.decimals,
        sessionContextDigest,
        mutationId: meta.mutationId,
      });
      const result = await client.query<ActionRow>(
        `SELECT out_replayed, out_action_id, out_organization_id, out_subject_agent_id,
                out_commerce_session_id, out_status, out_amount_atomic, out_fee_atomic,
                out_debit_atomic, out_policy_id, out_policy_revision, out_provider_id,
                out_listing_id, out_listing_version, out_requirement_id, out_requirement_digest,
                out_network_id, out_asset, out_representation, out_decimals,
                out_reservation_id, out_approval_id,
                out_created_at::text AS out_created_at,
                out_updated_at::text AS out_updated_at,
                out_expires_at::text AS out_expires_at,
                out_committed_at::text AS out_committed_at
           FROM openarc_durable.authorize_commerce_action(
             $1, $2, $3, $4::uuid, $5, $6, $7)`,
        [tokenHash, requirementId, actionId, meta.mutationId, keyHash, requestDigest, sessionContextDigest],
      );
      const row = requireExactlyOne(result.rows);
      return this.#projectResult(row, operation, meta.mutationId, actionId);
    });
  }

  async approveCommerceAction(
    humanSessionHash: unknown,
    organizationId: unknown,
    actionId: unknown,
    metadata: unknown,
  ): Promise<CommerceActionDecisionDbResult> {
    return this.#decide(
      'control.commerce_action.approve',
      humanSessionHash,
      organizationId,
      actionId,
      metadata,
    );
  }

  async rejectCommerceAction(
    humanSessionHash: unknown,
    organizationId: unknown,
    actionId: unknown,
    metadata: unknown,
  ): Promise<CommerceActionDecisionDbResult> {
    return this.#decide(
      'control.commerce_action.reject',
      humanSessionHash,
      organizationId,
      actionId,
      metadata,
    );
  }

  async #decide(
    operation: Extract<
      CommerceActionOperation,
      'control.commerce_action.approve' | 'control.commerce_action.reject'
    >,
    humanSessionHash: unknown,
    organizationId: unknown,
    actionId: unknown,
    metadata: unknown,
  ): Promise<CommerceActionDecisionDbResult> {
    const hash = requireHash(humanSessionHash);
    const organization = requireOrganization(organizationId);
    const action = requireAction(actionId);
    const meta = requireMetadata(metadata);
    const sessionContextDigest = digestCommerceActionHumanContext(operation, hash);
    const keyHash = digestCommerceActionIdempotencyKey(operation, meta.idempotencyKey);
    return this.#withTransaction(async (client) => {
      const actor = await this.#lockHumanWriter(client, hash, organization);
      const requestDigest = digestCommerceActionDecisionRequest(
        operation,
        {
          organizationId: organization,
          actorAccountId: actor,
          sessionContextDigest,
          mutationId: meta.mutationId,
        },
        action,
      );
      const decision = operation === 'control.commerce_action.approve' ? 'approve' : 'reject';
      const result = await client.query<ActionRow>(
        `SELECT out_replayed, out_action_id, out_organization_id, out_subject_agent_id,
                out_commerce_session_id, out_status, out_amount_atomic, out_fee_atomic,
                out_debit_atomic, out_policy_id, out_policy_revision, out_provider_id,
                out_listing_id, out_listing_version, out_requirement_id, out_requirement_digest,
                out_network_id, out_asset, out_representation, out_decimals,
                out_reservation_id, out_approval_id,
                out_created_at::text AS out_created_at,
                out_updated_at::text AS out_updated_at,
                out_expires_at::text AS out_expires_at,
                out_committed_at::text AS out_committed_at
           FROM openarc_durable.decide_commerce_action(
             $1, $2, $3, $4, $5::uuid, $6, $7, $8)`,
        [hash, organization, action, decision, meta.mutationId, keyHash, requestDigest, sessionContextDigest],
      );
      const row = requireExactlyOne(result.rows);
      return this.#projectResult(row, operation, meta.mutationId, action);
    });
  }

  async cancelCommerceAction(
    humanSessionHash: unknown,
    organizationId: unknown,
    actionId: unknown,
    metadata: unknown,
  ): Promise<CommerceActionDecisionDbResult> {
    const operation: CommerceActionOperation = 'control.commerce_action.cancel';
    const hash = requireHash(humanSessionHash);
    const organization = requireOrganization(organizationId);
    const action = requireAction(actionId);
    const meta = requireMetadata(metadata);
    const sessionContextDigest = digestCommerceActionHumanContext(operation, hash);
    const keyHash = digestCommerceActionIdempotencyKey(operation, meta.idempotencyKey);
    return this.#withTransaction(async (client) => {
      const actor = await this.#lockHumanWriter(client, hash, organization);
      const requestDigest = digestCommerceActionCancelRequest(
        {
          organizationId: organization,
          actorAccountId: actor,
          sessionContextDigest,
          mutationId: meta.mutationId,
        },
        action,
      );
      const result = await client.query<ActionRow>(
        `SELECT out_replayed, out_action_id, out_organization_id, out_subject_agent_id,
                out_commerce_session_id, out_status, out_amount_atomic, out_fee_atomic,
                out_debit_atomic, out_policy_id, out_policy_revision, out_provider_id,
                out_listing_id, out_listing_version, out_requirement_id, out_requirement_digest,
                out_network_id, out_asset, out_representation, out_decimals,
                out_reservation_id, out_approval_id,
                out_created_at::text AS out_created_at,
                out_updated_at::text AS out_updated_at,
                out_expires_at::text AS out_expires_at,
                out_committed_at::text AS out_committed_at
           FROM openarc_durable.cancel_commerce_action(
             $1, $2, $3, $4::uuid, $5, $6, $7)`,
        [hash, organization, action, meta.mutationId, keyHash, requestDigest, sessionContextDigest],
      );
      const row = requireExactlyOne(result.rows);
      return this.#projectResult(row, operation, meta.mutationId, action);
    });
  }

  async readAction(
    humanSessionHash: unknown,
    organizationId: unknown,
    actionId: unknown,
  ): Promise<CommerceActionMetadata | null> {
    const hash = requireHash(humanSessionHash);
    const organization = requireOrganization(organizationId);
    const action = requireAction(actionId);
    return this.#withTransaction(async (client) => {
      const result = await client.query<Record<string, unknown>>(
        `SELECT out_action_id, out_organization_id, out_subject_agent_id, out_commerce_session_id,
                out_status, out_policy_id, out_policy_revision, out_provider_id, out_listing_id,
                out_listing_version, out_requirement_id, out_requirement_digest, out_network_id,
                out_asset, out_representation, out_decimals, out_amount_atomic, out_fee_atomic,
                out_debit_atomic, out_source_kind, out_reservation_id, out_approval_id,
                out_created_at::text AS out_created_at,
                out_updated_at::text AS out_updated_at,
                out_expires_at::text AS out_expires_at
           FROM openarc_durable.read_commerce_action($1, $2, $3)`,
        [hash, organization, action],
      );
      const row = requireAtMostOne(result.rows);
      if (row === undefined) return null;
      const metadata = this.#projectMetadata(row);
      if (metadata.actionId !== action || metadata.exposureKey.organizationId !== organization) {
        failOutput();
      }
      return metadata;
    });
  }

  /**
   * Agent read of its OWN action bound to the EXACT presented commerce session.
   * Only the unique oacs_v1 commerce token is accepted; a machine bearer or
   * human session hash is never commerce identity. A missing or foreign action
   * returns the DB-derived authenticated organization with a null item.
   */
  async readAgentAction(
    commerceTokenHash: unknown,
    actionId: unknown,
  ): Promise<CommerceAgentActionRead> {
    const token = requireHash(commerceTokenHash);
    const action = requireAction(actionId);
    return this.#withTransaction(async (client) => {
      const result = await client.query<Record<string, unknown>>(
        `SELECT out_organization_id, out_action_id, out_found, out_subject_agent_id,
                out_commerce_session_id, out_status, out_policy_id, out_policy_revision,
                out_provider_id, out_listing_id, out_listing_version, out_requirement_id,
                out_requirement_digest, out_network_id, out_asset, out_representation,
                out_decimals, out_amount_atomic, out_fee_atomic, out_debit_atomic,
                out_source_kind, out_reservation_id, out_approval_id,
                out_created_at::text AS out_created_at,
                out_updated_at::text AS out_updated_at,
                out_expires_at::text AS out_expires_at
           FROM openarc_durable.read_agent_commerce_action($1, $2)`,
        [token, action],
      );
      const row = requireExactlyOne(result.rows);
      const organization = requireOrganization(row['out_organization_id']);
      if (row['out_action_id'] !== action) failOutput();
      if (row['out_found'] !== true) {
        if (row['out_found'] !== false) failOutput();
        return { organizationId: organization, actionId: action, item: null };
      }
      const metadata = this.#projectMetadata(row);
      if (metadata.actionId !== action || metadata.exposureKey.organizationId !== organization) {
        failOutput();
      }
      return { organizationId: organization, actionId: action, item: metadata };
    });
  }

  async readApproval(
    humanSessionHash: unknown,
    organizationId: unknown,
    actionId: unknown,
  ): Promise<CommerceApprovalMetadata | null> {
    const hash = requireHash(humanSessionHash);
    const organization = requireOrganization(organizationId);
    const action = requireAction(actionId);
    return this.#withTransaction(async (client) => {
      const result = await client.query<Record<string, unknown>>(
        `SELECT out_approval_id, out_action_id, out_organization_id, out_subject_agent_id,
                out_commerce_session_id, out_status, out_policy_id, out_policy_revision, out_requested_by,
                out_separate_approver, out_decided_by, out_source_kind,
                out_created_at::text AS out_created_at,
                out_expires_at::text AS out_expires_at,
                out_decided_at::text AS out_decided_at
           FROM openarc_durable.read_commerce_approval($1, $2, $3)`,
        [hash, organization, action],
      );
      const row = requireAtMostOne(result.rows);
      if (row === undefined) return null;
      const parsed = CommerceApprovalMetadataSchema.safeParse({
        schemaVersion: 'openarc.control.approval.v1',
        approvalId: row['out_approval_id'],
        actionId: row['out_action_id'],
        organizationId: row['out_organization_id'],
        subjectAgentId: row['out_subject_agent_id'],
        commerceSessionId: row['out_commerce_session_id'],
        policyId: row['out_policy_id'],
        policyRevision: row['out_policy_revision'],
        requestedBy: row['out_requested_by'],
        separateApprover: row['out_separate_approver'],
        status: row['out_status'] as CommerceApprovalStatus,
        decidedBy: row['out_decided_by'],
        createdAt: iso(row['out_created_at']),
        expiresAt: iso(row['out_expires_at']),
        decidedAt: isoOrNull(row['out_decided_at']),
      });
      if (!parsed.success) failOutput();
      if (parsed.data.actionId !== action || parsed.data.organizationId !== organization) {
        failOutput();
      }
      return parseCommerceApprovalMetadata(parsed.data);
    });
  }

  async readExposure(
    humanSessionHash: unknown,
    organizationId: unknown,
    subjectAgentId: unknown,
    policyId: unknown,
  ): Promise<CommerceExposureView | null> {
    const hash = requireHash(humanSessionHash);
    const organization = requireOrganization(organizationId);
    const subject = requireAgent(subjectAgentId);
    const policy = requirePolicy(policyId);
    return this.#withTransaction(async (client) => {
      const result = await client.query<Record<string, unknown>>(
        `SELECT out_organization_id, out_subject_agent_id, out_policy_id, out_policy_revision,
                out_network_id, out_asset, out_representation, out_decimals, out_window_seconds,
                out_committed_atomic, out_unresolved_atomic, out_total_atomic,
                out_available_atomic, out_deficit_atomic,
                out_as_of::text AS out_as_of
           FROM openarc_durable.read_commerce_exposure($1, $2, $3, $4)`,
        [hash, organization, subject, policy],
      );
      const row = requireAtMostOne(result.rows);
      if (row === undefined) return null;
      // Validate the returned identity against the frozen allowed identity
      // BEFORE projecting: a wrong network/asset/representation/decimals is a
      // fixed UNAVAILABLE, never silently relabeled to the literal.
      if (
        row['out_network_id'] !== EXPOSURE_IDENTITY.networkId ||
        row['out_asset'] !== EXPOSURE_IDENTITY.asset ||
        row['out_representation'] !== EXPOSURE_IDENTITY.representation ||
        row['out_decimals'] !== EXPOSURE_IDENTITY.decimals
      ) {
        failOutput();
      }
      const committedAtomic = this.#requireDecimal(row['out_committed_atomic']);
      const unresolvedAtomic = this.#requireDecimal(row['out_unresolved_atomic']);
      const totalExposureAtomic = this.#requireDecimal(row['out_total_atomic']);
      // The bounded BigInt sum must be exact; no coercion or truncation.
      if (BigInt(committedAtomic) + BigInt(unresolvedAtomic) !== BigInt(totalExposureAtomic)) {
        failOutput();
      }
      const availableRaw = row['out_available_atomic'];
      const availableAtomic =
        availableRaw === null || availableRaw === undefined
          ? null
          : this.#requireDecimal(availableRaw);
      const deficitAtomic = this.#requireDecimal(row['out_deficit_atomic']);
      if (availableAtomic === null) {
        // No rolling cap: the projected deficit is exactly zero.
        if (deficitAtomic !== '0') failOutput();
      } else if (BigInt(deficitAtomic) > 0n && BigInt(availableAtomic) !== 0n) {
        // A positive deficit requires available exactly zero.
        failOutput();
      }
      const view: CommerceExposureView = {
        organizationId: requireOrganization(row['out_organization_id']),
        subjectAgentId: requireAgent(row['out_subject_agent_id']),
        policyId: requirePolicy(row['out_policy_id']),
        policyRevision: this.#requireVersion(row['out_policy_revision']),
        networkId: EXPOSURE_IDENTITY.networkId,
        asset: EXPOSURE_IDENTITY.asset,
        representation: EXPOSURE_IDENTITY.representation,
        decimals: EXPOSURE_IDENTITY.decimals,
        windowSeconds: this.#requireWindowSeconds(row['out_window_seconds']),
        committedAtomic,
        unresolvedAtomic,
        totalExposureAtomic,
        availableAtomic,
        deficitAtomic,
        asOf: iso(row['out_as_of']),
      };
      if (view.organizationId !== organization || view.subjectAgentId !== subject || view.policyId !== policy) {
        failOutput();
      }
      return view;
    });
  }

  async getHumanMutationStatus(
    humanSessionHash: unknown,
    organizationId: unknown,
    mutationId: unknown,
  ): Promise<CommerceActionMutationStatus> {
    const hash = requireHash(humanSessionHash);
    const organization = requireOrganization(organizationId);
    const mutation = requireMutationInput(mutationId);
    return this.#withTransaction(async (client) => {
      const result = await client.query<ReceiptRow>(
        `SELECT out_mutation_id, out_operation, out_resource_type, out_resource_id,
                out_committed_at::text AS out_committed_at
           FROM openarc_durable.read_human_commerce_action_mutation_status($1, $2, $3::uuid)`,
        [hash, organization, mutation],
      );
      return this.#projectStatus(mutation, requireAtMostOne(result.rows), 'human');
    });
  }

  async getAgentMutationStatus(
    commerceTokenHash: unknown,
    mutationId: unknown,
  ): Promise<CommerceActionMutationStatus> {
    const hash = requireHash(commerceTokenHash);
    const mutation = requireMutationInput(mutationId);
    return this.#withTransaction(async (client) => {
      const result = await client.query<ReceiptRow & { out_organization_id: string }>(
        `SELECT out_mutation_id, out_operation, out_resource_type, out_resource_id,
                out_committed_at::text AS out_committed_at, out_organization_id
           FROM openarc_durable.read_agent_commerce_action_mutation_status($1, $2::uuid)`,
        [hash, mutation],
      );
      const row = requireAtMostOne(result.rows);
      if (row === undefined) return { status: 'not_found' } as const;
      return this.#projectStatus(mutation, row, 'agent');
    });
  }

  async #resolveAuthorizeContext(
    client: TenantClient,
    tokenHash: string,
  ): Promise<{
    organizationId: string;
    parentHumanAccountId: string;
    commerceSessionId: string;
    agentSessionId: string;
    credentialId: string;
    policyId: string;
  }> {
    const result = await client.query<{
      out_organization_id: string;
      out_subject_agent_id: string;
      out_credential_id: string;
      out_issuer_account_id: string;
      out_parent_human_account_id: string;
      out_commerce_session_id: string;
      out_policy_id: string;
      out_agent_session_id: string;
    }>(
      `SELECT out_organization_id, out_subject_agent_id, out_credential_id,
              out_issuer_account_id, out_parent_human_account_id, out_commerce_session_id,
              out_policy_id, out_agent_session_id
         FROM openarc_durable.resolve_commerce_action_context($1)`,
      [tokenHash],
    );
    const row = requireExactlyOne(result.rows);
    if (
      !ORG_ID.test(row.out_organization_id) ||
      !AGENT_ID.test(row.out_subject_agent_id) ||
      !POLICY_ID.test(row.out_policy_id) ||
      typeof row.out_parent_human_account_id !== 'string' ||
      typeof row.out_commerce_session_id !== 'string' ||
      typeof row.out_agent_session_id !== 'string' ||
      typeof row.out_credential_id !== 'string'
    ) {
      fail('CONTROL_ACTION_STORE_FORBIDDEN');
    }
    return {
      organizationId: row.out_organization_id,
      parentHumanAccountId: row.out_parent_human_account_id,
      commerceSessionId: row.out_commerce_session_id,
      agentSessionId: row.out_agent_session_id,
      credentialId: row.out_credential_id,
      policyId: row.out_policy_id,
    };
  }

  async #resolveRequirement(
    client: TenantClient,
    requirementId: string,
  ): Promise<{
    requirementDigest: string;
    amountAtomic: string;
    feeAtomic: string;
    networkId: string;
    asset: string;
    representation: string;
    decimals: number;
    sellerOrganizationId: string;
  }> {
    const result = await client.query<{
      out_organization_id: string;
      out_requirement_id: string;
      out_seller_organization_id: string;
      out_provider_id: string;
      out_listing_id: string;
      out_listing_version: string;
      out_network_id: string;
      out_asset: string;
      out_representation: string;
      out_decimals: number;
      out_amount_atomic: string;
      out_fee_atomic: string;
      out_requirement_digest: string;
      out_source_kind: string;
      out_created_at: string;
      out_valid_until: string;
    }>(
      `SELECT out_organization_id, out_requirement_id, out_seller_organization_id,
              out_provider_id, out_listing_id,
              out_listing_version, out_network_id, out_asset, out_representation, out_decimals,
              out_amount_atomic, out_fee_atomic, out_requirement_digest, out_source_kind,
              out_created_at, out_valid_until
         FROM openarc_durable.resolve_commerce_requirement($1)`,
      [requirementId],
    );
    const row = requireExactlyOne(result.rows);
    if (
      typeof row.out_requirement_digest !== 'string' ||
      typeof row.out_amount_atomic !== 'string' ||
      typeof row.out_fee_atomic !== 'string' ||
      typeof row.out_seller_organization_id !== 'string' ||
      !ORG_ID.test(row.out_seller_organization_id) ||
      row.out_network_id !== 'eip155:5042002' ||
      row.out_asset !== 'USDC' ||
      row.out_representation !== 'erc20' ||
      row.out_decimals !== 6
    ) {
      failOutput();
    }
    return {
      requirementDigest: row.out_requirement_digest,
      amountAtomic: row.out_amount_atomic,
      feeAtomic: row.out_fee_atomic,
      networkId: row.out_network_id,
      asset: row.out_asset,
      representation: row.out_representation,
      decimals: row.out_decimals,
      sellerOrganizationId: row.out_seller_organization_id,
    };
  }

  async #lockHumanWriter(
    client: TenantClient,
    hash: string,
    organization: string,
  ): Promise<string> {
    const result = await client.query<{ out_actor: string; out_role: string }>(
      `SELECT out_actor, out_role FROM openarc_durable.lock_action_human($1, $2, true)`,
      [hash, organization],
    );
    const row = result.rows[0];
    if (row === undefined || typeof row.out_actor !== 'string') {
      fail('CONTROL_ACTION_STORE_FORBIDDEN');
    }
    return row.out_actor;
  }

  #projectResult(
    row: ActionRow,
    operation: CommerceActionOperation,
    mutationId: string,
    actionId: string,
  ): CommerceActionMutationDbResult {
    const metadata = this.#projectMetadata(row);
    if (metadata.actionId !== actionId) failOutput();
    const committedAt = iso(row.out_committed_at);
    const receipt = this.#receiptFrom(operation, mutationId, actionId, committedAt);
    const replayed = row.out_replayed === true;
    if (row.out_replayed !== true && row.out_replayed !== false) failOutput();
    return { replayed, metadata, receipt };
  }

  #projectMetadata(row: Record<string, unknown>): CommerceActionMetadata {
    const actionId = row['out_action_id'];
    const organizationId = row['out_organization_id'];
    const subjectAgentId = row['out_subject_agent_id'];
    const commerceSessionId = row['out_commerce_session_id'];
    const status = row['out_status'];
    const parsed = CommerceActionMetadataSchema.safeParse({
      schemaVersion: 'openarc.control.action.v1',
      actionId,
      exposureKey: {
        organizationId,
        subjectAgentId,
        networkId: row['out_network_id'],
        asset: row['out_asset'],
        representation: row['out_representation'],
        decimals: row['out_decimals'],
      },
      commerceSessionId,
      policyId: row['out_policy_id'],
      policyRevision: row['out_policy_revision'],
      providerId: row['out_provider_id'],
      listingId: row['out_listing_id'],
      listingVersion: row['out_listing_version'],
      requirementId: row['out_requirement_id'],
      requirementDigest: row['out_requirement_digest'],
      amountAtomic: row['out_amount_atomic'],
      feeAtomic: row['out_fee_atomic'],
      debitAtomic: row['out_debit_atomic'],
      status: status as CommerceActionStatus,
      reservationId: row['out_reservation_id'] ?? null,
      approvalId: row['out_approval_id'] ?? null,
      createdAt: iso(row['out_created_at']),
      updatedAt: iso(row['out_updated_at']),
      expiresAt: iso(row['out_expires_at']),
    });
    if (!parsed.success) failOutput();
    if (
      compareIsoTimestamps(parsed.data.updatedAt, parsed.data.createdAt) < 0 ||
      compareIsoTimestamps(parsed.data.expiresAt, parsed.data.createdAt) <= 0
    ) {
      failOutput();
    }
    return parseCommerceActionMetadata(parsed.data);
  }

  #receiptFrom(
    operation: CommerceActionOperation,
    mutationId: string,
    actionId: string,
    committedAt: string,
  ): CommerceActionTransactionReceipt {
    return {
      mutationId,
      operation,
      resourceType: CONTROL_ACTION_RESOURCE_TYPE,
      resourceId: actionId,
      committedAt,
    };
  }

  #projectStatus(
    mutation: string,
    row: ReceiptRow | undefined,
    reader: 'human' | 'agent',
  ): CommerceActionMutationStatus {
    if (row === undefined) return { status: 'not_found' } as const;
    if (row.out_mutation_id !== mutation) failOutput();
    const operation = this.#requireOperation(row.out_operation, reader);
    if (row.out_resource_type !== CONTROL_ACTION_RESOURCE_TYPE) failOutput();
    const actionId = requireAction(row.out_resource_id);
    const committedAt = iso(row.out_committed_at);
    return {
      status: 'committed' as const,
      receipt: this.#receiptFrom(operation, mutation, actionId, committedAt),
    };
  }

  /**
   * The agent status reader may only ever surface the authorize operation; the
   * human status reader may only ever surface approve/reject/cancel. The reader
   * is named explicitly so the two projections can never be transposed.
   */
  #requireOperation(value: unknown, reader: 'human' | 'agent'): CommerceActionOperation {
    if (reader === 'agent') {
      if (value !== 'control.commerce_action.authorize') failOutput();
      return value;
    }
    if (
      value !== 'control.commerce_action.approve' &&
      value !== 'control.commerce_action.reject' &&
      value !== 'control.commerce_action.cancel'
    ) {
      failOutput();
    }
    return value;
  }

  #requireVersion(value: unknown): string {
    if (typeof value !== 'string' || !/^[1-9][0-9]{0,8}$(?![\s\S])/.test(value)) failOutput();
    return value;
  }

  #requireWindowSeconds(value: unknown): string | null {
    if (value === null || value === undefined) return null;
    if (typeof value !== 'string' || !WINDOW_SECONDS.test(value) || BigInt(value) > WINDOW_SECONDS_MAX) {
      failOutput();
    }
    return value;
  }

  #requireDecimal(value: unknown): string {
    if (typeof value !== 'string' || !DECIMAL.test(value)) failOutput();
    return value;
  }

  async #withTransaction<T>(work: (client: TenantClient) => Promise<T>): Promise<T> {
    let client: TenantClient;
    try {
      client = await this.#pool.connect();
    } catch {
      fail('CONTROL_ACTION_STORE_UNAVAILABLE');
    }
    try {
      await client.query('BEGIN');
    } catch {
      client.release(true);
      fail('CONTROL_ACTION_STORE_UNAVAILABLE');
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
      client.release(!rolledBack);
      throw normalizeError(error);
    }
    try {
      await client.query('COMMIT');
    } catch {
      client.release(true);
      fail('CONTROL_ACTION_STORE_OUTCOME_UNKNOWN');
    }
    client.release(false);
    return result;
  }

  async #assertReady(client: TenantClient): Promise<void> {
    const EXPECTED_TABLES = [
      'commerce_exposure_locks',
      'commerce_requirement_references',
      'commerce_actions',
      'budget_reservations',
      'commerce_approvals',
      'budget_events',
    ];
    const tables = await client.query<{ n: number; all_enabled: boolean; all_forced: boolean; owned: number }>(
      `SELECT count(*)::int AS n,
              bool_and(c.relrowsecurity) AS all_enabled,
              bool_and(c.relforcerowsecurity) AS all_forced,
              count(*) FILTER (WHERE r.rolname = 'openarc_migrator')::int AS owned
         FROM pg_class c
         JOIN pg_namespace ns ON ns.oid = c.relnamespace
         JOIN pg_roles r ON r.oid = c.relowner
        WHERE ns.nspname = 'openarc_durable'
          AND c.relkind = 'r'
          AND c.relname = ANY ($1::text[])`,
      [EXPECTED_TABLES],
    );
    const state = tables.rows[0];
    if (
      state === undefined ||
      state.n !== EXPECTED_TABLES.length ||
      state.all_enabled !== true ||
      state.all_forced !== true ||
      state.owned !== EXPECTED_TABLES.length
    ) {
      fail('CONTROL_ACTION_STORE_UNAVAILABLE');
    }
    const access = await client.query<{ n: number }>(
      `WITH reachable AS (
         SELECT r.oid FROM pg_roles r
          WHERE r.oid = (SELECT oid FROM pg_roles WHERE rolname = current_user)
             OR pg_has_role(current_user, r.oid, 'MEMBER')
       )
       SELECT count(*)::int AS n
         FROM pg_class c
         JOIN pg_namespace ns ON ns.oid = c.relnamespace
        WHERE ns.nspname = 'openarc_durable'
          AND c.relkind = 'r'
          AND c.relname = ANY ($1::text[])
          AND EXISTS (
            SELECT 1 FROM reachable x
             WHERE has_table_privilege(x.oid, c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))`,
      [EXPECTED_TABLES],
    );
    if ((access.rows[0]?.n ?? -1) !== 0) fail('CONTROL_ACTION_STORE_UNAVAILABLE');
    await this.#assertHelpers(client);
  }

  async #assertHelpers(client: TenantClient): Promise<void> {
    const production: readonly { name: string; args: string }[] = [
      { name: 'authorize_commerce_action', args: 'commerce_token_hash text, requirement_id_input text, action_id_input text, mutation_id uuid, key_hash text, request_digest text, session_context_digest text' },
      { name: 'decide_commerce_action', args: 'human_session_hash text, organization_id text, action_id_input text, decision text, mutation_id uuid, key_hash text, request_digest text, session_context_digest text' },
      { name: 'cancel_commerce_action', args: 'human_session_hash text, organization_id text, action_id_input text, mutation_id uuid, key_hash text, request_digest text, session_context_digest text' },
      { name: 'read_commerce_action', args: 'human_session_hash text, organization_id text, action_id_input text' },
      { name: 'read_agent_commerce_action', args: 'commerce_token_hash text, action_id_input text' },
      { name: 'read_commerce_approval', args: 'human_session_hash text, organization_id text, action_id_input text' },
      { name: 'read_commerce_exposure', args: 'human_session_hash text, organization_id text, subject_agent_id_input text, policy_id_input text' },
      { name: 'read_human_commerce_action_mutation_status', args: 'human_session_hash text, organization_id text, mutation_id uuid' },
      { name: 'read_agent_commerce_action_mutation_status', args: 'commerce_token_hash text, mutation_id uuid' },
      { name: 'resolve_commerce_action_context', args: 'commerce_token_hash text' },
      { name: 'resolve_commerce_requirement', args: 'requirement_id_input text' },
    ];
    const rows = await client.query<{
      proname: string;
      args: string;
      owner: string;
      secdef: boolean;
      config: string[];
      app_exec: boolean;
      public_grants: number;
    }>(
      `SELECT p.proname, pg_get_function_identity_arguments(p.oid) AS args,
              r.rolname AS owner, p.prosecdef AS secdef,
              coalesce(p.proconfig, ARRAY[]::text[]) AS config,
              has_function_privilege('openarc_tenant_app', p.oid, 'EXECUTE') AS app_exec,
              (SELECT count(*)::int FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE') AS public_grants
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         JOIN pg_roles r ON r.oid = p.proowner
        WHERE n.nspname = 'openarc_durable'
          AND p.prokind = 'f'
          AND p.proname = ANY ($1::text[])`,
      [production.map((entry) => entry.name)],
    );
    const byName = new Map(rows.rows.map((row) => [`${row.proname}(${row.args})`, row]));
    for (const expected of production) {
      const row = byName.get(`${expected.name}(${expected.args})`);
      if (row === undefined) fail('CONTROL_ACTION_STORE_UNAVAILABLE');
      if (
        row.owner !== 'openarc_migrator' ||
        row.secdef !== true ||
        !row.config.includes('search_path=pg_catalog') ||
        row.public_grants !== 0 ||
        row.app_exec !== true
      ) {
        fail('CONTROL_ACTION_STORE_UNAVAILABLE');
      }
    }
    const privateHelpers: readonly { name: string; args: string }[] = [
      { name: 'authorize_commerce_action_core', args: 'mode text, commerce_token_hash text, requirement_id_input text, action_id_input text, mutation_id uuid, key_hash text, request_digest text, session_context_digest text' },
      { name: 'decide_commerce_action_core', args: 'mode text, human_session_hash text, organization_id text, action_id_input text, decision text, mutation_id uuid, key_hash text, request_digest text, session_context_digest text' },
      { name: 'cancel_commerce_action_core', args: 'human_session_hash text, organization_id text, action_id_input text, mutation_id uuid, key_hash text, request_digest text, session_context_digest text' },
      { name: 'lock_action_commerce', args: 'commerce_token_hash text, seller_organization_id text' },
      { name: 'lock_action_commerce_state', args: 'commerce_token_hash text, organization_id text' },
      { name: 'lock_action_decide_preamble', args: 'human_session_hash text, organization_id text, action_id_input text' },
      { name: 'assert_action_decide_current', args: 'organization_id text, action_id_input text' },
    ];
    const privateRows = await client.query<{
      proname: string;
      args: string;
      owner: string;
      config: string[];
      app_exec: boolean;
      public_grants: number;
    }>(
      `SELECT p.proname, pg_get_function_identity_arguments(p.oid) AS args,
              r.rolname AS owner,
              coalesce(p.proconfig, ARRAY[]::text[]) AS config,
              has_function_privilege('openarc_tenant_app', p.oid, 'EXECUTE') AS app_exec,
              (SELECT count(*)::int FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE') AS public_grants
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         JOIN pg_roles r ON r.oid = p.proowner
        WHERE n.nspname = 'openarc_durable'
          AND p.prokind = 'f'
          AND p.proname = ANY ($1::text[])`,
      [privateHelpers.map((entry) => entry.name)],
    );
    if (privateRows.rows.length !== privateHelpers.length) fail('CONTROL_ACTION_STORE_UNAVAILABLE');
    for (const row of privateRows.rows) {
      if (
        row.owner !== 'openarc_migrator' ||
        !row.config.includes('search_path=pg_catalog') ||
        row.public_grants !== 0 ||
        row.app_exec !== false
      ) {
        fail('CONTROL_ACTION_STORE_UNAVAILABLE');
      }
    }
    const applied = await client.query<{ id: string; checksum: string }>(
      `SELECT id, checksum FROM openarc_meta.schema_migrations ORDER BY id`,
    );
    let migrations: readonly { readonly id: string; readonly sql: string }[];
    try {
      migrations = loadMigrations();
    } catch {
      fail('CONTROL_ACTION_STORE_UNAVAILABLE');
    }
    if (applied.rows.length !== migrations.length) fail('CONTROL_ACTION_STORE_UNAVAILABLE');
    for (let index = 0; index < applied.rows.length; index += 1) {
      const record = applied.rows[index];
      const manifest = migrations[index];
      if (record === undefined || manifest === undefined || record.id !== manifest.id) {
        fail('CONTROL_ACTION_STORE_UNAVAILABLE');
      }
      const checksum = createHash('sha256').update(manifest.sql, 'utf8').digest('hex');
      if (record.checksum !== checksum) fail('CONTROL_ACTION_STORE_UNAVAILABLE');
    }
  }
}

interface ReceiptRow extends Record<string, unknown> {
  readonly out_mutation_id: string;
  readonly out_operation: string;
  readonly out_resource_type: string;
  readonly out_resource_id: string;
  readonly out_committed_at: string | Date;
}

function requireMutationInput(value: unknown): string {
  try {
    return parseMutationId(value);
  } catch {
    fail('CONTROL_ACTION_STORE_INPUT_INVALID');
  }
}

/** Structural adapter for callers that hold a raw `pg` Pool. */
export function asControlActionPool(pool: Pool): TenantPool {
  return pool as unknown as TenantPool;
}

export type { Pool };
