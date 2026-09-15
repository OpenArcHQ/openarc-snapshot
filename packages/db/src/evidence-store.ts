import { createHash } from 'node:crypto';
import type { Pool } from 'pg';
import {
  EVIDENCE_V2_FACT_KINDS,
  EVIDENCE_V2_KIND_SOURCE_CLASSES,
  EVIDENCE_V2_PAYMENT_CERTAINTIES,
  EvidenceV2FactSchema,
  EvidenceV2OperatorViewSchema,
  EvidenceV2SubjectSchema,
  type EvidenceV2Fact,
  type EvidenceV2FactKind,
  type EvidenceV2ForbiddenPaymentState,
  type EvidenceV2OperatorView,
  type EvidenceV2PaymentCertainty,
  type EvidenceV2Subject,
} from '@openarc/shared';
import { loadMigrations } from './migrate.js';
import { TenantStore, type TenantClient, type TenantPool } from './tenant-store.js';

/**
 * EvidenceStore: the schema16 append-only `openarc.evidence.v2` fact store and
 * its bounded operator reads.
 *
 * Guarantees, enforced in SQL and re-asserted here:
 *   * facts are append-only: no UPDATE, DELETE or TRUNCATE exists for any role,
 *     and the runtime has no table privilege at all;
 *   * recording is idempotent by evidence id: identical content replays and
 *     different content for the same id is a CONFLICT, never an overwrite; a
 *     re-observation or finality upgrade is a new fact with a new id;
 *   * the kind -> source-class authority matrix, chain-anchor rules, canonical
 *     id grammars, exact integer amounts and the closed payment certainty set
 *     (no settled, paid, released or refunded value) are CHECK constraints;
 *   * no signature, token, key or session hash is representable;
 *   * both reads assert the current human operator authority before AND after
 *     the projection and return the full operator view. Public and provider
 *     projections are applied by the API from packages/shared.
 *
 * The recorder is migrator-private in schema16. `recordFact` therefore only
 * succeeds through a principal that holds EXECUTE on it; the runtime principal
 * is decided in P05-02c. Every method runs one statement in one transaction and
 * makes no external call.
 */

export const EVIDENCE_STORE_ERROR_MESSAGES = {
  EVIDENCE_STORE_INPUT_INVALID: 'EvidenceStore input is invalid.',
  EVIDENCE_STORE_SECRET_REFUSED: 'EvidenceStore refused secret-shaped material.',
  EVIDENCE_STORE_SOURCE_FORBIDDEN: 'EvidenceStore source class is not permitted for this evidence.',
  EVIDENCE_STORE_CONFLICT: 'EvidenceStore evidence id already records different content.',
  EVIDENCE_STORE_NOT_FOUND: 'EvidenceStore target was not found.',
  EVIDENCE_STORE_SESSION_INVALID: 'EvidenceStore session is not valid.',
  EVIDENCE_STORE_FORBIDDEN: 'EvidenceStore caller is not permitted.',
  EVIDENCE_STORE_BOUND_EXCEEDED: 'EvidenceStore read exceeds its bound.',
  EVIDENCE_STORE_UNAVAILABLE: 'EvidenceStore is not available.',
  EVIDENCE_STORE_OUTCOME_UNKNOWN:
    'EvidenceStore write outcome could not be confirmed; it may have committed.',
} as const;

export type EvidenceStoreErrorCode = keyof typeof EVIDENCE_STORE_ERROR_MESSAGES;

/** Fixed, non-echoing repository error. Never carries driver or input detail. */
export class EvidenceStoreError extends Error {
  readonly code: EvidenceStoreErrorCode;

  constructor(code: EvidenceStoreErrorCode) {
    super(EVIDENCE_STORE_ERROR_MESSAGES[code]);
    this.name = 'EvidenceStoreError';
    this.code = code;
  }
}

/**
 * Exact schema16 RAISE literals, by SQLSTATE. Classification never inspects
 * any other message text, so driver detail cannot select a code.
 */
export const EVIDENCE_STORE_RAISE_LITERALS = {
  '22023': ['evidence_input_invalid'],
  '23505': ['evidence_id_conflict'],
  '23514': [
    'evidence_secret_material_refused',
    'evidence_source_class_forbidden',
    'evidence_fact_invalid',
    'evidence_fact_digest_invalid',
  ],
  '42501': ['evidence_facts_append_only', 'commerce_forbidden'],
  '28000': ['commerce_forbidden'],
  P0D11: ['evidence_read_bound_exceeded'],
} as const;

/** Accepted default page size, applied here when a list request omits `limit`. */
export const EVIDENCE_READ_DEFAULT_LIMIT = 25;
/** Hard page size, enforced here and again in SQL. */
export const EVIDENCE_READ_MAX_LIMIT = 50;
/** Facts about one subject returned by a subject read; one more fails closed. */
export const EVIDENCE_SUBJECT_READ_CAP = 200;
/** Local byte cap on the normalized payload JSON; SQL caps its jsonb text at 2048. */
export const EVIDENCE_NORMALIZED_MAX_BYTES = 1024;

/** The complete stored payment certainty value set. */
export const EVIDENCE_STORE_PAYMENT_CERTAINTIES = EVIDENCE_V2_PAYMENT_CERTAINTIES;
type IsNever<T> = [T] extends [never] ? true : false;
export type EvidenceStorePaymentCertaintyAdmitsNoSettlement = IsNever<
  Extract<(typeof EVIDENCE_STORE_PAYMENT_CERTAINTIES)[number], EvidenceV2ForbiddenPaymentState>
>;
/** Compile-time proof: a settled, paid, released or refunded certainty breaks the build here. */
export const EVIDENCE_STORE_PAYMENT_CERTAINTY_ADMITS_NO_SETTLEMENT: EvidenceStorePaymentCertaintyAdmitsNoSettlement = true;

export interface EvidenceRecordResult {
  readonly replayed: boolean;
  readonly evidenceId: string;
  readonly organizationId: string;
  /** Database-derived content digest used for replay comparison. */
  readonly factDigest: string;
  readonly recordedAt: string;
}

export interface EvidenceOperatorRecord {
  readonly operatorView: EvidenceV2OperatorView;
  readonly factDigest: string;
  readonly recordedAt: string;
}

export interface EvidenceSubjectRead {
  readonly organizationId: string;
  readonly subject: EvidenceV2Subject;
  /** Ordered by (observedAt, evidenceId); at most EVIDENCE_SUBJECT_READ_CAP. */
  readonly items: readonly EvidenceOperatorRecord[];
}

export interface EvidenceKindPage {
  readonly organizationId: string;
  readonly kind: EvidenceV2FactKind;
  /** Strictly ascending evidence id. */
  readonly items: readonly EvidenceOperatorRecord[];
  readonly nextCursor: string | null;
}

/** Accepted list request: exclusive lexical cursor plus a canonical string limit. */
export interface EvidenceKindListQuery {
  readonly afterEvidenceId?: string;
  readonly limit?: string;
}

const HEX64 = /^[0-9a-f]{64}$(?![\s\S])/;
const ORG_ID = /^openarc:org:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const EVIDENCE_ID = /^evd_[0-9a-f]{32}$(?![\s\S])/;
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$(?![\s\S])/;
// Canonical wire limit 1..50 with an absolute end: '05', ' 5', '5\n', '0' and '51' are refused.
const LIST_LIMIT = /^(?:[1-9]|[1-4][0-9]|50)$(?![\s\S])/;
const LONG_HEX_RUN = /[0-9a-fA-F]{40,}/;
const JWT_RUN = /eyJ[A-Za-z0-9_-]{8,}/;
const SUB_MICROSECOND = /\.[0-9]{7,}Z$/;
const LIST_KEYS = ['afterEvidenceId', 'limit'] as const;

function fail(code: EvidenceStoreErrorCode): never {
  throw new EvidenceStoreError(code);
}

function failInput(): never {
  fail('EVIDENCE_STORE_INPUT_INVALID');
}

function failOutput(): never {
  fail('EVIDENCE_STORE_UNAVAILABLE');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireHash(value: unknown): string {
  if (typeof value !== 'string' || !HEX64.test(value)) failInput();
  return value;
}

function requireOrganization(value: unknown): string {
  if (typeof value !== 'string' || !ORG_ID.test(value)) failInput();
  return value;
}

function requireKind(value: unknown): EvidenceV2FactKind {
  if (typeof value !== 'string' || !(EVIDENCE_V2_FACT_KINDS as readonly string[]).includes(value)) {
    failInput();
  }
  return value as EvidenceV2FactKind;
}

function requireSubject(value: unknown): EvidenceV2Subject {
  const parsed = EvidenceV2SubjectSchema.safeParse(value);
  if (!parsed.success) failInput();
  return parsed.data;
}

/**
 * Strict bounded query envelope. Only a plain object with the allowed keys is
 * accepted; an unknown key, a prototype-bearing object or a present key whose
 * value is `undefined` is a fixed input fault, never a silent default.
 */
function requireQueryShape(value: unknown): Record<string, unknown> {
  if (value === undefined || value === null) return {};
  if (!isRecord(value)) failInput();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) failInput();
  for (const key of Object.keys(value)) {
    if (!(LIST_KEYS as readonly string[]).includes(key)) failInput();
    if (value[key] === undefined) failInput();
  }
  return value;
}

/**
 * Canonical string limit 1..50 converted to the SQL integer. Absent means the
 * default 25, applied HERE and never by coercion. A number is refused.
 */
export function parseEvidenceListLimit(value: unknown): number {
  if (value === undefined) return EVIDENCE_READ_DEFAULT_LIMIT;
  if (typeof value !== 'string' || !LIST_LIMIT.test(value)) failInput();
  const limit = Number.parseInt(value, 10);
  if (!Number.isInteger(limit) || limit < 1 || limit > EVIDENCE_READ_MAX_LIMIT) failInput();
  return limit;
}

function requireCursor(value: unknown): string | null {
  if (value === undefined) return null;
  if (typeof value !== 'string' || !EVIDENCE_ID.test(value)) failInput();
  return value;
}

/**
 * Shape-level fact validation before any connection: the shared strict schema,
 * then the schema16 tightenings the database would otherwise refuse.
 */
function requireFact(value: unknown): EvidenceV2Fact {
  const parsed = EvidenceV2FactSchema.safeParse(value);
  if (!parsed.success) failInput();
  const fact = parsed.data;
  for (const text of [fact.source.sourceId, fact.source.origin, fact.source.adapterVersion]) {
    if (LONG_HEX_RUN.test(text) || JWT_RUN.test(text)) fail('EVIDENCE_STORE_SECRET_REFUSED');
  }
  for (const stamp of [fact.observedAt, fact.occurredAt]) {
    if (stamp !== null && SUB_MICROSECOND.test(stamp)) failInput();
  }
  if (Buffer.byteLength(JSON.stringify(fact.normalized), 'utf8') > EVIDENCE_NORMALIZED_MAX_BYTES) {
    failInput();
  }
  if (!(EVIDENCE_V2_KIND_SOURCE_CLASSES[fact.kind] as readonly string[]).includes(fact.source.class)) {
    fail('EVIDENCE_STORE_SOURCE_FORBIDDEN');
  }
  return fact;
}

function actorColumns(actor: EvidenceV2Fact['actor']): [string, string, string | null] {
  switch (actor.kind) {
    case 'human_account':
      return [actor.kind, actor.accountId, null];
    case 'agent':
      return [actor.kind, actor.agentId, null];
    case 'provider':
      return [actor.kind, actor.providerId, null];
    case 'system':
      return [actor.kind, actor.component, null];
    case 'external_party':
      return [actor.kind, actor.role, actor.address];
  }
}

/** The 25 recorder operands, in the exact schema16 parameter order. */
export function evidenceFactOperands(fact: EvidenceV2Fact): unknown[] {
  const [actorKind, actorId, actorAddress] = actorColumns(fact.actor);
  return [
    fact.schemaVersion,
    fact.evidenceId,
    fact.kind,
    fact.source.class,
    fact.source.sourceId,
    fact.source.origin,
    fact.source.adapterVersion,
    fact.subject.kind,
    fact.subject.canonicalId,
    fact.scope.organizationId,
    fact.scope.providerId,
    fact.scope.actionId,
    actorKind,
    actorId,
    actorAddress,
    fact.chain?.network ?? null,
    fact.chain?.blockNumber ?? null,
    fact.chain?.blockHash ?? null,
    fact.chain?.finality ?? null,
    fact.occurredAt,
    fact.observedAt,
    fact.digest,
    fact.dataClass,
    [...fact.limitations],
    JSON.stringify(fact.normalized),
  ];
}

function literalIn(error: Record<string, unknown>, literals: readonly string[]): string | null {
  const message = error['message'];
  return typeof message === 'string' && literals.includes(message) ? message : null;
}

/**
 * SQLSTATE 23514 carries four schema16 families plus genuine CHECK faults.
 * Only the exact RAISE literal selects a narrower code; anything else stays
 * INPUT_INVALID so an unrecognised CHECK violation still fails closed.
 */
function classify23514(error: Record<string, unknown>): EvidenceStoreErrorCode {
  switch (literalIn(error, EVIDENCE_STORE_RAISE_LITERALS['23514'])) {
    case 'evidence_secret_material_refused':
      return 'EVIDENCE_STORE_SECRET_REFUSED';
    case 'evidence_source_class_forbidden':
      return 'EVIDENCE_STORE_SOURCE_FORBIDDEN';
    default:
      return 'EVIDENCE_STORE_INPUT_INVALID';
  }
}

function classifyDatabaseError(error: Record<string, unknown>, code: string): EvidenceStoreErrorCode {
  switch (code) {
    case '28000':
      return 'EVIDENCE_STORE_SESSION_INVALID';
    case '42501':
      return 'EVIDENCE_STORE_FORBIDDEN';
    case '23503':
      return 'EVIDENCE_STORE_NOT_FOUND';
    case '23505':
      return literalIn(error, EVIDENCE_STORE_RAISE_LITERALS['23505']) === null
        ? 'EVIDENCE_STORE_UNAVAILABLE'
        : 'EVIDENCE_STORE_CONFLICT';
    case '23514':
      return classify23514(error);
    case 'P0D11':
      return literalIn(error, EVIDENCE_STORE_RAISE_LITERALS.P0D11) === null
        ? 'EVIDENCE_STORE_UNAVAILABLE'
        : 'EVIDENCE_STORE_BOUND_EXCEEDED';
    case '22023':
    case '22P02':
    case '22001':
    case '22003':
    case '22007':
    case '22008':
    case '23502':
      return 'EVIDENCE_STORE_INPUT_INVALID';
    default:
      return 'EVIDENCE_STORE_UNAVAILABLE';
  }
}

function normalizeError(error: unknown): EvidenceStoreError {
  if (error instanceof EvidenceStoreError) return error;
  if (isRecord(error) && typeof error['code'] === 'string') {
    return new EvidenceStoreError(classifyDatabaseError(error, error['code']));
  }
  return new EvidenceStoreError('EVIDENCE_STORE_UNAVAILABLE');
}

const PG_TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?([+-])(\d{2})(?::?(\d{2}))?$/;

function daysInMonth(year: number, month: number): number {
  return new Date(Date.UTC(year, month, 0)).getUTCDate();
}

/** PostgreSQL timestamptz text -> `YYYY-MM-DDTHH:MM:SS.ffffffZ`. */
function iso(value: unknown): string {
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
  return `${normalized.toISOString().slice(0, 19)}.${micros}Z`;
}

function isoOrNull(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  return iso(value);
}

const FACT_COLUMNS = `out_organization_id, out_found, out_evidence_id, out_schema_version, out_kind,
                out_source_class, out_source_id, out_source_origin, out_adapter_version,
                out_subject_kind, out_subject_canonical_id, out_provider_id, out_action_id,
                out_actor_kind, out_actor_id, out_actor_address, out_chain_network,
                out_chain_block_number, out_chain_block_hash, out_chain_finality,
                out_occurred_at::text AS out_occurred_at,
                out_observed_at::text AS out_observed_at,
                out_digest, out_data_class, out_limitations, out_normalized,
                out_payment_certainty, out_fact_digest,
                out_recorded_at::text AS out_recorded_at`;

function projectActor(row: Record<string, unknown>): unknown {
  const id = row['out_actor_id'];
  const address = row['out_actor_address'];
  const kind = row['out_actor_kind'];
  if (kind !== 'external_party' && address !== null) failOutput();
  switch (kind) {
    case 'human_account':
      return { kind, accountId: id };
    case 'agent':
      return { kind, agentId: id };
    case 'provider':
      return { kind, providerId: id };
    case 'system':
      return { kind, component: id };
    case 'external_party':
      return { kind, role: id, address };
    default:
      failOutput();
  }
}

function projectRecord(row: Record<string, unknown>, organization: string): EvidenceOperatorRecord {
  if (row['out_found'] !== true) failOutput();
  const chainValues = [
    row['out_chain_network'], row['out_chain_block_number'], row['out_chain_block_hash'], row['out_chain_finality'],
  ];
  const chain = chainValues.every((value) => value === null)
    ? null
    : {
        network: row['out_chain_network'],
        blockNumber: row['out_chain_block_number'],
        blockHash: row['out_chain_block_hash'],
        finality: row['out_chain_finality'],
      };
  const parsed = EvidenceV2OperatorViewSchema.safeParse({
    view: 'operator',
    schemaVersion: row['out_schema_version'],
    evidenceId: row['out_evidence_id'],
    kind: row['out_kind'],
    source: {
      class: row['out_source_class'],
      sourceId: row['out_source_id'],
      origin: row['out_source_origin'],
      adapterVersion: row['out_adapter_version'],
    },
    subject: { kind: row['out_subject_kind'], canonicalId: row['out_subject_canonical_id'] },
    scope: {
      organizationId: row['out_organization_id'],
      providerId: row['out_provider_id'],
      actionId: row['out_action_id'],
    },
    actor: projectActor(row),
    chain,
    occurredAt: isoOrNull(row['out_occurred_at']),
    observedAt: iso(row['out_observed_at']),
    digest: row['out_digest'],
    dataClass: row['out_data_class'],
    limitations: row['out_limitations'],
    normalized: row['out_normalized'],
  });
  if (!parsed.success) failOutput();
  const view = parsed.data;
  if (view.scope.organizationId !== organization) failOutput();
  // The generated certainty column must agree with the payload and stay in
  // the closed set; anything else is a malformed row, never a relabel.
  const certainty = row['out_payment_certainty'];
  if (view.kind === 'payment_observation') {
    if (
      typeof certainty !== 'string' ||
      !(EVIDENCE_STORE_PAYMENT_CERTAINTIES as readonly string[]).includes(certainty) ||
      certainty !== (view.normalized.certainty as EvidenceV2PaymentCertainty)
    ) {
      failOutput();
    }
  } else if (certainty !== null) {
    failOutput();
  }
  const factDigest = row['out_fact_digest'];
  if (typeof factDigest !== 'string' || !SHA256_DIGEST.test(factDigest)) failOutput();
  return { operatorView: view, factDigest, recordedAt: iso(row['out_recorded_at']) };
}

function requireUniformOrganization(rows: readonly Record<string, unknown>[], requested: string): string {
  const first = rows[0];
  if (first === undefined) failOutput();
  const organization = first['out_organization_id'];
  if (typeof organization !== 'string' || !ORG_ID.test(organization)) failOutput();
  for (const row of rows) {
    if (row['out_organization_id'] !== organization) failOutput();
  }
  if (organization !== requested) failOutput();
  return organization;
}

/** Rows are either exactly one not-found sentinel or only found rows. */
function foundRows(rows: readonly Record<string, unknown>[]): readonly Record<string, unknown>[] {
  if (rows.length === 1 && rows[0]?.['out_found'] === false) {
    const sentinel = rows[0];
    for (const [key, value] of Object.entries(sentinel)) {
      if (key !== 'out_organization_id' && key !== 'out_found' && value !== null) failOutput();
    }
    return [];
  }
  for (const row of rows) {
    if (row['out_found'] !== true) failOutput();
  }
  return rows;
}

export class EvidenceStore {
  readonly #pool: TenantPool;
  readonly #base: TenantStore;
  #initialized = false;

  constructor(pool: TenantPool) {
    if (pool === null || typeof pool !== 'object' || typeof pool.connect !== 'function') {
      failInput();
    }
    this.#pool = pool;
    this.#base = new TenantStore(pool);
  }

  async initialize(): Promise<void> {
    if (this.#initialized) return;
    await this.#baseChecks(() => this.#base.initialize());
    await this.#withTransaction(async (client) => {
      await this.#assertReady(client);
    }, 'read');
    this.#initialized = true;
  }

  async readiness(): Promise<void> {
    await this.#baseChecks(() => this.#base.readiness());
    await this.#withTransaction(async (client) => {
      await this.#assertReady(client);
    }, 'read');
  }

  async #baseChecks(run: () => Promise<void>): Promise<void> {
    try {
      await run();
    } catch {
      fail('EVIDENCE_STORE_UNAVAILABLE');
    }
  }

  /**
   * Record one evidence v2 fact through the migrator-private recorder. The
   * fact is fully validated before a connection is taken. Replays of identical
   * content return `replayed: true`; different content for the same evidence id
   * is CONFLICT. A lost COMMIT is OUTCOME_UNKNOWN: retry the identical fact.
   */
  async recordFact(input: unknown): Promise<EvidenceRecordResult> {
    const fact = requireFact(input);
    const operands = evidenceFactOperands(fact);
    return this.#withTransaction(async (client) => {
      const result = await client.query<Record<string, unknown>>(
        `SELECT out_replayed, out_evidence_id, out_organization_id, out_fact_digest,
                out_recorded_at::text AS out_recorded_at
           FROM openarc_durable.record_evidence_fact(
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
             $20::timestamptz, $21::timestamptz, $22, $23, $24::text[], $25::jsonb)`,
        operands,
      );
      if (result.rows.length !== 1 || result.rows[0] === undefined) failOutput();
      const row = result.rows[0];
      const replayed = row['out_replayed'];
      const factDigest = row['out_fact_digest'];
      if (
        (replayed !== true && replayed !== false) ||
        row['out_evidence_id'] !== fact.evidenceId ||
        row['out_organization_id'] !== fact.scope.organizationId ||
        typeof factDigest !== 'string' ||
        !SHA256_DIGEST.test(factDigest)
      ) {
        failOutput();
      }
      return {
        replayed,
        evidenceId: fact.evidenceId,
        organizationId: fact.scope.organizationId,
        factDigest,
        recordedAt: iso(row['out_recorded_at']),
      };
    }, 'write');
  }

  /**
   * Every fact the organization holds about one subject, in (observedAt,
   * evidenceId) order. Another organization's facts are indistinguishable from
   * none. More than EVIDENCE_SUBJECT_READ_CAP facts is BOUND_EXCEEDED.
   */
  async readBySubject(
    humanSessionHash: unknown,
    organizationId: unknown,
    subject: unknown,
  ): Promise<EvidenceSubjectRead> {
    const hash = requireHash(humanSessionHash);
    const organization = requireOrganization(organizationId);
    const parsedSubject = requireSubject(subject);
    return this.#withTransaction(async (client) => {
      const result = await client.query<Record<string, unknown>>(
        `SELECT ${FACT_COLUMNS}
           FROM openarc_durable.read_evidence_facts_by_subject($1, $2, $3, $4)`,
        [hash, organization, parsedSubject.kind, parsedSubject.canonicalId],
      );
      const rows = result.rows;
      if (rows.length === 0 || rows.length > EVIDENCE_SUBJECT_READ_CAP) failOutput();
      const authenticated = requireUniformOrganization(rows, organization);
      const items = foundRows(rows).map((row) => projectRecord(row, authenticated));
      for (let index = 0; index < items.length; index += 1) {
        const view = items[index]!.operatorView;
        if (view.subject.kind !== parsedSubject.kind || view.subject.canonicalId !== parsedSubject.canonicalId) {
          failOutput();
        }
        const previous = items[index - 1]?.operatorView;
        if (
          previous !== undefined &&
          !(previous.observedAt < view.observedAt ||
            (previous.observedAt === view.observedAt && previous.evidenceId < view.evidenceId))
        ) {
          failOutput();
        }
      }
      return { organizationId: authenticated, subject: parsedSubject, items };
    }, 'read');
  }

  /**
   * Bounded keyset page of one kind. `nextCursor` is non-null only when a
   * further page exists, and is then exactly the last returned evidence id.
   */
  async listByKind(
    humanSessionHash: unknown,
    organizationId: unknown,
    kind: unknown,
    query?: unknown,
  ): Promise<EvidenceKindPage> {
    const hash = requireHash(humanSessionHash);
    const organization = requireOrganization(organizationId);
    const parsedKind = requireKind(kind);
    const shape = requireQueryShape(query);
    const cursor = requireCursor(shape['afterEvidenceId']);
    const limit = parseEvidenceListLimit(shape['limit']);
    return this.#withTransaction(async (client) => {
      const result = await client.query<Record<string, unknown>>(
        `SELECT ${FACT_COLUMNS}
           FROM openarc_durable.list_evidence_facts($1, $2, $3, $4, $5::int)`,
        [hash, organization, parsedKind, cursor, limit],
      );
      const rows = result.rows;
      if (rows.length === 0 || rows.length > limit + 1) failOutput();
      const authenticated = requireUniformOrganization(rows, organization);
      const fetched = foundRows(rows).map((row) => projectRecord(row, authenticated));
      for (let index = 0; index < fetched.length; index += 1) {
        const view = fetched[index]!.operatorView;
        if (view.kind !== parsedKind) failOutput();
        if (cursor !== null && !(view.evidenceId > cursor)) failOutput();
        const previous = fetched[index - 1]?.operatorView;
        if (previous !== undefined && !(previous.evidenceId < view.evidenceId)) failOutput();
      }
      const hasMore = fetched.length > limit;
      const items = fetched.slice(0, limit);
      const last = items[items.length - 1];
      return {
        organizationId: authenticated,
        kind: parsedKind,
        items,
        nextCursor: hasMore && last !== undefined ? last.operatorView.evidenceId : null,
      };
    }, 'read');
  }

  async #withTransaction<T>(work: (client: TenantClient) => Promise<T>, mode: 'read' | 'write'): Promise<T> {
    let client: TenantClient;
    try {
      client = await this.#pool.connect();
    } catch {
      fail('EVIDENCE_STORE_UNAVAILABLE');
    }
    try {
      await client.query('BEGIN');
    } catch {
      client.release(true);
      fail('EVIDENCE_STORE_UNAVAILABLE');
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
      // A read commits nothing; only a write can have an unknown outcome.
      fail(mode === 'write' ? 'EVIDENCE_STORE_OUTCOME_UNKNOWN' : 'EVIDENCE_STORE_UNAVAILABLE');
    }
    client.release(false);
    return result;
  }

  async #assertReady(client: TenantClient): Promise<void> {
    const table = await client.query<{
      n: number; enabled: boolean; forced: boolean; owner: string;
    }>(
      `SELECT count(*)::int AS n,
              bool_and(c.relrowsecurity) AS enabled,
              bool_and(c.relforcerowsecurity) AS forced,
              min(r.rolname) AS owner
         FROM pg_class c
         JOIN pg_namespace ns ON ns.oid = c.relnamespace
         JOIN pg_roles r ON r.oid = c.relowner
        WHERE ns.nspname = 'openarc_durable' AND c.relkind = 'r' AND c.relname = 'evidence_facts'`,
    );
    const state = table.rows[0];
    if (
      state === undefined || state.n !== 1 || state.enabled !== true ||
      state.forced !== true || state.owner !== 'openarc_migrator'
    ) {
      fail('EVIDENCE_STORE_UNAVAILABLE');
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
        WHERE ns.nspname = 'openarc_durable' AND c.relkind = 'r' AND c.relname = 'evidence_facts'
          AND EXISTS (
            SELECT 1 FROM reachable x
             WHERE has_table_privilege(x.oid, c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))`,
    );
    if ((access.rows[0]?.n ?? -1) !== 0) fail('EVIDENCE_STORE_UNAVAILABLE');
    await this.#assertHelpers(client);
    await this.#assertConstraints(client);
    await this.#assertTriggers(client);
    await this.#assertMigrations(client);
  }

  async #assertHelpers(client: TenantClient): Promise<void> {
    // Every schema16 function, plus the reused schema11 resolver, with its exact
    // identity signature, owner, SECURITY DEFINER flag, volatility, pinned
    // search_path, no PUBLIC grant and the exact runtime EXECUTE expectation.
    interface Expected { name: string; args: string; secdef: boolean; runtime: boolean; volatile: 'i' | 's' | 'v' }
    const expected: readonly Expected[] = [
      { name: 'read_evidence_facts_by_subject', args: 'human_session_hash text, organization_id text, subject_kind_input text, subject_canonical_id_input text', secdef: true, runtime: true, volatile: 's' },
      { name: 'list_evidence_facts', args: 'human_session_hash text, organization_id text, kind_input text, after_evidence_id text, limit_count integer', secdef: true, runtime: true, volatile: 's' },
      { name: 'record_evidence_fact', args: 'schema_version_input text, evidence_id_input text, kind_input text, source_class_input text, source_id_input text, source_origin_input text, adapter_version_input text, subject_kind_input text, subject_canonical_id_input text, organization_id_input text, provider_id_input text, action_id_input text, actor_kind_input text, actor_id_input text, actor_address_input text, chain_network_input text, chain_block_number_input text, chain_block_hash_input text, chain_finality_input text, occurred_at_input timestamp with time zone, observed_at_input timestamp with time zone, digest_input text, data_class_input text, limitations_input text[], normalized_input jsonb', secdef: true, runtime: false, volatile: 'v' },
      { name: 'resolve_action_reader_org', args: 'session_hash text, organization_id text', secdef: true, runtime: false, volatile: 'v' },
      { name: 'is_canonical_evidence_id', args: 'value text', secdef: false, runtime: false, volatile: 'i' },
      { name: 'is_evidence_text_secret_free', args: 'value text, max_hex_run integer, max_token_run integer', secdef: false, runtime: false, volatile: 'i' },
      { name: 'is_valid_evidence_limitations', args: 'value text[]', secdef: false, runtime: false, volatile: 'i' },
      { name: 'is_evidence_payload_secret_free', args: 'value jsonb', secdef: false, runtime: false, volatile: 'i' },
      { name: 'is_evidence_kind_source_allowed', args: 'kind text, source_class text', secdef: false, runtime: false, volatile: 'i' },
      { name: 'is_evidence_subject_id', args: 'subject_kind text, canonical_id text', secdef: false, runtime: false, volatile: 'i' },
      { name: 'is_valid_evidence_normalized', args: 'kind text, normalized jsonb', secdef: false, runtime: false, volatile: 'i' },
      { name: 'evidence_fact_digest', args: 'fact openarc_durable.evidence_facts', secdef: false, runtime: false, volatile: 's' },
      { name: 'reject_evidence_fact_mutation', args: '', secdef: false, runtime: false, volatile: 'v' },
      { name: 'enforce_evidence_fact_insert', args: '', secdef: false, runtime: false, volatile: 'v' },
    ];
    const rows = await client.query<{
      proname: string; args: string; owner: string; secdef: boolean; volatile: string;
      config: string[]; app_exec: boolean; public_grants: number; source: string;
    }>(
      `SELECT p.proname, pg_get_function_identity_arguments(p.oid) AS args,
              r.rolname AS owner, p.prosecdef AS secdef, p.provolatile::text AS volatile,
              coalesce(p.proconfig, ARRAY[]::text[]) AS config,
              has_function_privilege('openarc_tenant_app', p.oid, 'EXECUTE') AS app_exec,
              (SELECT count(*)::int FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE') AS public_grants,
              p.prosrc AS source
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         JOIN pg_roles r ON r.oid = p.proowner
        WHERE n.nspname = 'openarc_durable'
          AND p.proname = ANY ($1::text[])`,
      [expected.map((entry) => entry.name)],
    );
    // Exactly one overload per inventoried name: an extra signature is not ready.
    if (rows.rows.length !== expected.length) fail('EVIDENCE_STORE_UNAVAILABLE');
    const byName = new Map(rows.rows.map((row) => [row.proname, row]));
    if (byName.size !== expected.length) fail('EVIDENCE_STORE_UNAVAILABLE');
    for (const entry of expected) {
      const row = byName.get(entry.name);
      if (
        row === undefined ||
        row.args !== entry.args ||
        row.owner !== 'openarc_migrator' ||
        row.secdef !== entry.secdef ||
        row.volatile !== entry.volatile ||
        row.config.length !== 1 ||
        row.config[0] !== 'search_path=pg_catalog' ||
        row.public_grants !== 0 ||
        row.app_exec !== entry.runtime
      ) {
        fail('EVIDENCE_STORE_UNAVAILABLE');
      }
    }
    // The SQL authority matrix must be exactly the shared contract's.
    const matrix = byName.get('is_evidence_kind_source_allowed')?.source ?? '';
    for (const kind of EVIDENCE_V2_FACT_KINDS) {
      const classes = EVIDENCE_V2_KIND_SOURCE_CLASSES[kind];
      const clause = classes.length === 1
        ? `WHEN '${kind}' THEN source_class = '${classes[0]}'`
        : `WHEN '${kind}' THEN source_class IN (${classes.map((value) => `'${value}'`).join(', ')})`;
      if (!matrix.includes(clause)) fail('EVIDENCE_STORE_UNAVAILABLE');
    }
    if ((matrix.match(/\bWHEN '/g) ?? []).length !== EVIDENCE_V2_FACT_KINDS.length) {
      fail('EVIDENCE_STORE_UNAVAILABLE');
    }
    // Both readers assert the preamble twice and are STABLE (checked above).
    for (const name of ['read_evidence_facts_by_subject', 'list_evidence_facts']) {
      const source = byName.get(name)?.source ?? '';
      if (source.split('openarc_durable.resolve_action_reader_org(').length - 1 !== 2) {
        fail('EVIDENCE_STORE_UNAVAILABLE');
      }
    }
  }

  async #assertConstraints(client: TenantClient): Promise<void> {
    const required = [
      'evidence_facts_derived_grant_expiry',
      'evidence_facts_chain_valid',
      'evidence_facts_kind_subject_valid',
      'evidence_facts_normalized_size',
      'evidence_facts_normalized_valid',
      'evidence_facts_payload_secret_free',
      'evidence_facts_payment_certainty_presence',
      'evidence_facts_payment_certainty_valid',
      'evidence_facts_source_class_allowed',
      'evidence_facts_text_secret_free',
    ];
    const rows = await client.query<{ conname: string; validated: boolean; def: string }>(
      `SELECT c.conname, c.convalidated AS validated, pg_get_constraintdef(c.oid) AS def
         FROM pg_constraint c
         JOIN pg_class t ON t.oid = c.conrelid
         JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'openarc_durable' AND t.relname = 'evidence_facts' AND c.contype = 'c'`,
    );
    const byName = new Map(rows.rows.map((row) => [row.conname, row]));
    for (const name of required) {
      if (byName.get(name)?.validated !== true) fail('EVIDENCE_STORE_UNAVAILABLE');
    }
    const certainty = byName.get('evidence_facts_payment_certainty_valid')?.def ?? '';
    const literals = [...certainty.matchAll(/'([^']*)'::text/g)].map((match) => match[1]).sort();
    if (JSON.stringify(literals) !== JSON.stringify([...EVIDENCE_STORE_PAYMENT_CERTAINTIES].sort())) {
      fail('EVIDENCE_STORE_UNAVAILABLE');
    }
  }

  async #assertTriggers(client: TenantClient): Promise<void> {
    // tgtype bits: ROW 1, BEFORE 2, INSERT 4, DELETE 8, UPDATE 16, TRUNCATE 32.
    const expected: readonly { trigger: string; type: number; fn: string }[] = [
      { trigger: 'evidence_facts_append_only', type: 1 + 2 + 8 + 16, fn: 'reject_evidence_fact_mutation' },
      { trigger: 'evidence_facts_no_truncate', type: 2 + 32, fn: 'reject_evidence_fact_mutation' },
      { trigger: 'evidence_facts_insert_digest', type: 1 + 2 + 4, fn: 'enforce_evidence_fact_insert' },
    ];
    const rows = await client.query<{ tgname: string; enabled: string; type: number; fn: string; fn_schema: string }>(
      `SELECT t.tgname, t.tgenabled::text AS enabled, t.tgtype::int AS type,
              p.proname AS fn, pn.nspname AS fn_schema
         FROM pg_trigger t
         JOIN pg_class c ON c.oid = t.tgrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
         JOIN pg_proc p ON p.oid = t.tgfoid
         JOIN pg_namespace pn ON pn.oid = p.pronamespace
        WHERE n.nspname = 'openarc_durable' AND c.relname = 'evidence_facts' AND NOT t.tgisinternal`,
    );
    if (rows.rows.length !== expected.length) fail('EVIDENCE_STORE_UNAVAILABLE');
    for (const entry of expected) {
      const row = rows.rows.find((candidate) => candidate.tgname === entry.trigger);
      if (
        row === undefined || row.enabled !== 'O' || row.type !== entry.type ||
        row.fn !== entry.fn || row.fn_schema !== 'openarc_durable'
      ) {
        fail('EVIDENCE_STORE_UNAVAILABLE');
      }
    }
  }

  async #assertMigrations(client: TenantClient): Promise<void> {
    const applied = await client.query<{ id: string; checksum: string }>(
      'SELECT id, checksum FROM openarc_meta.schema_migrations ORDER BY id',
    );
    let migrations: readonly { readonly id: string; readonly sql: string }[];
    try {
      migrations = loadMigrations();
    } catch {
      fail('EVIDENCE_STORE_UNAVAILABLE');
    }
    if (applied.rows.length !== migrations.length) fail('EVIDENCE_STORE_UNAVAILABLE');
    if (!migrations.some((migration) => migration.id === '0016_evidence_store')) {
      fail('EVIDENCE_STORE_UNAVAILABLE');
    }
    for (let index = 0; index < applied.rows.length; index += 1) {
      const record = applied.rows[index];
      const manifest = migrations[index];
      if (record === undefined || manifest === undefined || record.id !== manifest.id) {
        fail('EVIDENCE_STORE_UNAVAILABLE');
      }
      const checksum = createHash('sha256').update(manifest.sql, 'utf8').digest('hex');
      if (record.checksum !== checksum) fail('EVIDENCE_STORE_UNAVAILABLE');
    }
  }
}

/** Structural adapter for callers that hold a raw `pg` Pool. */
export function asEvidencePool(pool: Pool): TenantPool {
  return pool as unknown as TenantPool;
}
