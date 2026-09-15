import type { Pool } from 'pg';

/**
 * DB-derived outbox event inventory for the "no unprojectable event" guard.
 *
 * The permitted (resource_type, event_type) set is read from the LIVE
 * PostgreSQL catalog, never from a hand-maintained list: the migrated
 * `outbox_resource_matches_event` CHECK maps every event_type to exactly one
 * resource_type (`resource_type = CASE event_type WHEN ... THEN ... END`), and
 * `outbox_event_type_valid` / `outbox_resource_type_valid` bound both columns.
 * A future migration that adds an event type therefore changes this set
 * automatically, and the guard fails until the store and worker handle it.
 */

export interface OutboxEventPair {
  readonly resourceType: string;
  readonly eventType: string;
}

async function constraintDef(admin: Pool, name: string): Promise<string> {
  const result = await admin.query<{ def: string }>(
    `SELECT pg_get_constraintdef(c.oid) AS def
       FROM pg_constraint c
       JOIN pg_class t ON t.oid = c.conrelid
       JOIN pg_namespace n ON n.oid = t.relnamespace
      WHERE n.nspname = 'openarc_durable' AND t.relname = 'outbox_events'
        AND c.conname = $1 AND c.contype = 'c'`,
    [name],
  );
  if (result.rows.length !== 1) throw new Error(`outbox constraint ${name} not found`);
  return result.rows[0]!.def;
}

function literals(def: string): string[] {
  return [...def.matchAll(/'([^']*)'::text/g)].map((match) => match[1]!);
}

export async function readPermittedOutboxEventPairs(admin: Pool): Promise<OutboxEventPair[]> {
  const matches = await constraintDef(admin, 'outbox_resource_matches_event');
  const whenCount = (matches.match(/\bWHEN\b/g) ?? []).length;
  const pairs = [...matches.matchAll(/WHEN '([^']+)'::text THEN '([^']+)'::text/g)].map(
    (match) => ({ eventType: match[1]!, resourceType: match[2]! }),
  );
  // Fail loudly if the constraint shape ever changes so a pair cannot be missed.
  if (pairs.length === 0 || pairs.length !== whenCount) {
    throw new Error('outbox_resource_matches_event has an unrecognised shape');
  }
  const eventTypes = new Set(literals(await constraintDef(admin, 'outbox_event_type_valid')));
  const resourceTypes = new Set(literals(await constraintDef(admin, 'outbox_resource_type_valid')));
  const mappedEvents = new Set(pairs.map((pair) => pair.eventType));
  if (
    mappedEvents.size !== pairs.length ||
    mappedEvents.size !== eventTypes.size ||
    ![...eventTypes].every((eventType) => mappedEvents.has(eventType)) ||
    !pairs.every((pair) => resourceTypes.has(pair.resourceType))
  ) {
    throw new Error('outbox event/resource constraints disagree');
  }
  return pairs;
}

export function outboxPairKey(pair: OutboxEventPair): string {
  return `${pair.resourceType}|${pair.eventType}`;
}

function sampleUuid(seed: number): string {
  return `00000000-0000-4000-8000-${String(seed).padStart(12, '0')}`;
}

/**
 * A canonical resource id for a resource type. An unknown resource type throws,
 * so a newly permitted resource type fails the guard until it is handled here
 * AND in the store/worker.
 */
export function sampleResourceId(resourceType: string, seed: number): string {
  const id = sampleUuid(seed);
  switch (resourceType) {
    case 'organization':
      return `openarc:org:${id}`;
    case 'agent':
      return `openarc:agent:${id}`;
    case 'provider':
      return `openarc:provider:${id}`;
    case 'membership':
      return `openarc:account:${id}`;
    case 'agent_credential':
    case 'provider_credential':
    case 'commerce_session':
      return id;
    case 'listing':
      return `openarc:listing:${id}`;
    case 'listing_version':
      return `openarc:listing:${id}@2`;
    case 'budget_policy':
      return `openarc:policy:${id}`;
    case 'budget_policy_revision':
      return `openarc:policy:${id}@2`;
    case 'commerce_action':
      return `openarc:action:${id}`;
    case 'authorization_grant':
      return `openarc:grant:${id}`;
    default:
      throw new Error(`no canonical sample resource id for outbox resource type ${resourceType}`);
  }
}

/**
 * Insert one pending outbox row for a DB-permitted pair as the fixture
 * superuser. `session_replication_role = replica` skips only the FK/receipt
 * triggers (the row needs no seeded business chain); every CHECK constraint,
 * including the pair mapping and the per-resource shape checks, still applies,
 * so the row is exactly one the database itself accepts.
 */
export async function insertOutboxEventForPair(
  admin: Pool,
  organizationId: string,
  pair: OutboxEventPair,
  seed: number,
): Promise<string> {
  const eventId = sampleUuid(500_000 + seed);
  const client = await admin.connect();
  try {
    await client.query('BEGIN');
    await client.query('SET LOCAL session_replication_role = replica');
    await client.query(
      `INSERT INTO openarc_durable.outbox_events
         (event_id, organization_id, mutation_id, resource_type, resource_id, event_type,
          payload_version, state, available_at, attempt_count, lease_generation)
       VALUES ($1::uuid, $2, $3::uuid, $4, $5, $6, 1, 'pending',
               clock_timestamp() - interval '1 minute', 0, 0)`,
      [
        eventId,
        organizationId,
        sampleUuid(600_000 + seed),
        pair.resourceType,
        // outbox_resource_org_scope: an organization event names its own org.
        pair.resourceType === 'organization'
          ? organizationId
          : sampleResourceId(pair.resourceType, 700_000 + seed),
        pair.eventType,
      ],
    );
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
  return eventId;
}
