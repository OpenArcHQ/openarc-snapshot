import type { ClaimedOutboxEvent } from '@openarc/db';

/**
 * Allowlisted tenant notification handlers.
 *
 * LIMITATION: accepted notification success means allowlisted metadata was
 * validated and this worker consumed the durable event. These handlers do NOT
 * execute payments, materialize business projections, send notifications, call
 * providers, sign or broadcast, reconcile evidence, or claim any commerce side
 * effect. Future projection handlers are a separate phase.
 *
 * The registry is a fixed, closed union of resourceType+eventType pairs already
 * accepted by ClaimedOutboxEvent (the original tenant events, four
 * notification-only credential events, the market listing and listing-version
 * lifecycle events, the five control policy events, the three
 * notification-only commerce-session events, and the four notification-only
 * commerce-action events). There are no dynamic callbacks, user URLs or plugin
 * handlers, and the original event is never JSON-logged.
 */

export const INVALID_EVENT_MESSAGE = 'Durable notification event is invalid.';

/** Fixed, non-echoing invalid-event error. Never carries event detail. */
export class InvalidEventError extends Error {
  constructor() {
    super(INVALID_EVENT_MESSAGE);
    this.name = 'InvalidEventError';
  }
}

export interface NotificationHandlerContext {
  readonly signal: AbortSignal;
}

/** Pure validation/consumption handler. It never performs a side effect. */
export type NotificationHandler = (
  event: ClaimedOutboxEvent,
  context: NotificationHandlerContext,
) => void | Promise<void>;

export type NotificationEventKey =
  | 'organization|tenant.organization.created'
  | 'agent|tenant.agent.created'
  | 'agent|tenant.agent.updated'
  | 'provider|tenant.provider.created'
  | 'provider|tenant.provider.updated'
  | 'membership|tenant.membership.set'
  | 'agent_credential|tenant.agent.credential.created'
  | 'agent_credential|tenant.agent.credential.revoked'
  | 'provider_credential|tenant.provider.credential.created'
  | 'provider_credential|tenant.provider.credential.revoked'
  | 'listing|market.listing.created'
  | 'listing_version|market.listing.version.created'
  | 'listing_version|market.listing.origin_review.recorded'
  | 'listing_version|market.listing.version.published'
  | 'listing_version|market.listing.version.paused'
  | 'listing_version|market.listing.version.retired'
  | 'budget_policy|control.policy.created'
  | 'budget_policy_revision|control.policy.revision.created'
  | 'budget_policy|control.policy.paused'
  | 'budget_policy|control.policy.resumed'
  | 'budget_policy|control.policy.revoked'
  | 'commerce_session|control.commerce_session.issued'
  | 'commerce_session|control.commerce_session.exchanged'
  | 'commerce_session|control.commerce_session.revoked'
  | 'commerce_action|control.commerce_action.authorized'
  | 'commerce_action|control.commerce_action.approved'
  | 'commerce_action|control.commerce_action.rejected'
  | 'commerce_action|control.commerce_action.cancelled';

export type NotificationHandlerRegistry = Readonly<
  Record<NotificationEventKey, NotificationHandler>
>;

export const NOTIFICATION_EVENT_KEYS: readonly NotificationEventKey[] = [
  'organization|tenant.organization.created',
  'agent|tenant.agent.created',
  'agent|tenant.agent.updated',
  'provider|tenant.provider.created',
  'provider|tenant.provider.updated',
  'membership|tenant.membership.set',
  'agent_credential|tenant.agent.credential.created',
  'agent_credential|tenant.agent.credential.revoked',
  'provider_credential|tenant.provider.credential.created',
  'provider_credential|tenant.provider.credential.revoked',
  'listing|market.listing.created',
  'listing_version|market.listing.version.created',
  'listing_version|market.listing.origin_review.recorded',
  'listing_version|market.listing.version.published',
  'listing_version|market.listing.version.paused',
  'listing_version|market.listing.version.retired',
  'budget_policy|control.policy.created',
  'budget_policy_revision|control.policy.revision.created',
  'budget_policy|control.policy.paused',
  'budget_policy|control.policy.resumed',
  'budget_policy|control.policy.revoked',
  'commerce_session|control.commerce_session.issued',
  'commerce_session|control.commerce_session.exchanged',
  'commerce_session|control.commerce_session.revoked',
  'commerce_action|control.commerce_action.authorized',
  'commerce_action|control.commerce_action.approved',
  'commerce_action|control.commerce_action.rejected',
  'commerce_action|control.commerce_action.cancelled',
];

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ORG_ID = /^openarc:org:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const AGENT_ID = /^openarc:agent:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PROVIDER_ID = /^openarc:provider:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ACCOUNT_ID = /^openarc:account:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CREDENTIAL_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const LISTING_ID = /^openarc:listing:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
// Internal version resource: canonical listing id + '@' + canonical version >= 2.
const LISTING_VERSION_RESOURCE_MAX_LENGTH = 128;
const LISTING_VERSION_RESOURCE = /^openarc:listing:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}@(?!1$)[1-9][0-9]{0,8}$/;
// Lifecycle version resource: version >= 1 (the first draft can be reviewed,
// published, paused or retired), while the creation event still requires >= 2.
const LIFECYCLE_LISTING_VERSION_RESOURCE = /^openarc:listing:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}@[1-9][0-9]{0,8}$/;

function isListingVersionResource(value: string): boolean {
  return value.length <= LISTING_VERSION_RESOURCE_MAX_LENGTH && LISTING_VERSION_RESOURCE.test(value);
}

function isLifecycleListingVersionResource(value: string): boolean {
  return (
    value.length <= LISTING_VERSION_RESOURCE_MAX_LENGTH &&
    LIFECYCLE_LISTING_VERSION_RESOURCE.test(value)
  );
}

// Control policy root resource: canonical lower-case openarc:policy: UUID with
// an absolute end (a trailing newline can never satisfy the anchor).
const POLICY_ID = /^openarc:policy:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\s\S])/;
// Control policy revision resource: canonical root + '@' + canonical decimal
// 2..999999999 (so '@1', '@0', '@01', '@1000000000' and any extra '@' fail).
// The absolute end rejects a trailing newline or any other suffix.
const POLICY_REVISION_RESOURCE_MAX_LENGTH = 160;
const POLICY_REVISION_RESOURCE = /^openarc:policy:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}@([2-9][0-9]{0,8}|1[0-9]{1,8})(?![\s\S])/;

function isPolicyRevisionResource(value: string): boolean {
  return value.length <= POLICY_REVISION_RESOURCE_MAX_LENGTH && POLICY_REVISION_RESOURCE.test(value);
}

// Commerce session resource: a bare canonical lower-case UUIDv4 (version nibble
// exactly 4, variant 8/9/a/b) with an absolute end, so a trailing newline or any
// other suffix can never satisfy the anchor. This mirrors the durable outbox
// projection exactly, without the `$`-before-newline relaxation.
const COMMERCE_SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\s\S])/;

// Commerce action resource: the exact canonical lower-case openarc:action:
// prefix plus a UUIDv4 (version nibble exactly 4, variant 8/9/a/b) and an
// absolute end, so a trailing LF/CR, a suffix or any other coercion can never
// satisfy the anchor. This mirrors the accepted durable outbox type.
const COMMERCE_ACTION_ID = /^openarc:action:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\s\S])/;

// The exact safe metadata keyset accepted at the handler boundary. Anything
// else (a private canary, an internal digest, a raw body) is rejected rather
// than ignored, and the fixed error never echoes it.
const SAFE_METADATA_KEYS = [
  'attemptCount',
  'eventId',
  'eventType',
  'leaseGeneration',
  'leaseUntil',
  'mutationId',
  'organizationId',
  'payloadVersion',
  'resourceId',
  'resourceType',
] as const;

function hasOnlySafeMetadataKeys(raw: Record<string, unknown>): boolean {
  const keys = Object.keys(raw);
  if (keys.length !== SAFE_METADATA_KEYS.length) return false;
  for (const key of keys) {
    if (!(SAFE_METADATA_KEYS as readonly string[]).includes(key)) return false;
  }
  return true;
}
const DECIMAL = /^(0|[1-9][0-9]*)$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isString(value: unknown): value is string {
  return typeof value === 'string';
}

function isNotificationEventKey(value: string): value is NotificationEventKey {
  return (NOTIFICATION_EVENT_KEYS as readonly string[]).includes(value);
}

export function eventKeyOf(event: ClaimedOutboxEvent): NotificationEventKey {
  const key = `${event.resourceType}|${event.eventType}`;
  if (!isNotificationEventKey(key)) throw new InvalidEventError();
  return key;
}

/**
 * Identity usable for a fenced acknowledgement. A malformed identifier means
 * the worker fails closed with no acknowledgement at all.
 */
export function ackIdentityOf(
  raw: unknown,
): { readonly eventId: string; readonly leaseGeneration: string } | null {
  if (!isRecord(raw)) return null;
  const eventId = raw['eventId'];
  const leaseGeneration = raw['leaseGeneration'];
  if (!isString(eventId) || !UUID.test(eventId)) return null;
  if (!isString(leaseGeneration) || leaseGeneration.length > 20 || !DECIMAL.test(leaseGeneration)) {
    return null;
  }
  return { eventId, leaseGeneration };
}

/**
 * Validate the bounded allowlisted fields at the handler boundary, even though
 * the real store already validates. Unknown or mismatched events are rejected
 * safely with a fixed error that carries no event detail.
 */
export function validateNotification(raw: unknown): ClaimedOutboxEvent {
  if (!isRecord(raw)) throw new InvalidEventError();
  if (!hasOnlySafeMetadataKeys(raw)) throw new InvalidEventError();
  const eventId = raw['eventId'];
  const organizationId = raw['organizationId'];
  const mutationId = raw['mutationId'];
  const resourceType = raw['resourceType'];
  const resourceId = raw['resourceId'];
  const eventType = raw['eventType'];
  const payloadVersion = raw['payloadVersion'];
  const leaseGeneration = raw['leaseGeneration'];
  const leaseUntil = raw['leaseUntil'];
  const attemptCount = raw['attemptCount'];

  if (!isString(eventId) || !UUID.test(eventId)) throw new InvalidEventError();
  if (!isString(organizationId) || !ORG_ID.test(organizationId)) throw new InvalidEventError();
  if (!isString(mutationId) || !UUID.test(mutationId)) throw new InvalidEventError();
  if (payloadVersion !== 1) throw new InvalidEventError();
  if (!isString(leaseGeneration) || leaseGeneration.length > 20 || !DECIMAL.test(leaseGeneration)) {
    throw new InvalidEventError();
  }
  if (!isString(leaseUntil) || !Number.isFinite(Date.parse(leaseUntil))) {
    throw new InvalidEventError();
  }
  if (
    typeof attemptCount !== 'number' ||
    !Number.isInteger(attemptCount) ||
    attemptCount < 0 ||
    attemptCount > 5
  ) {
    throw new InvalidEventError();
  }
  if (!isString(resourceType) || !isString(eventType) || !isString(resourceId)) {
    throw new InvalidEventError();
  }

  const key = `${resourceType}|${eventType}`;
  if (!isNotificationEventKey(key)) throw new InvalidEventError();
  switch (key) {
    case 'organization|tenant.organization.created':
      if (!ORG_ID.test(resourceId)) throw new InvalidEventError();
      break;
    case 'agent|tenant.agent.created':
    case 'agent|tenant.agent.updated':
      if (!AGENT_ID.test(resourceId)) throw new InvalidEventError();
      break;
    case 'provider|tenant.provider.created':
    case 'provider|tenant.provider.updated':
      if (!PROVIDER_ID.test(resourceId)) throw new InvalidEventError();
      break;
    case 'membership|tenant.membership.set':
      if (!ACCOUNT_ID.test(resourceId)) throw new InvalidEventError();
      break;
    case 'agent_credential|tenant.agent.credential.created':
    case 'agent_credential|tenant.agent.credential.revoked':
    case 'provider_credential|tenant.provider.credential.created':
    case 'provider_credential|tenant.provider.credential.revoked':
      if (!CREDENTIAL_ID.test(resourceId)) throw new InvalidEventError();
      break;
    case 'listing|market.listing.created':
      if (!LISTING_ID.test(resourceId)) throw new InvalidEventError();
      break;
    case 'listing_version|market.listing.version.created':
      if (!isListingVersionResource(resourceId)) throw new InvalidEventError();
      break;
    case 'listing_version|market.listing.origin_review.recorded':
    case 'listing_version|market.listing.version.published':
    case 'listing_version|market.listing.version.paused':
    case 'listing_version|market.listing.version.retired':
      if (!isLifecycleListingVersionResource(resourceId)) throw new InvalidEventError();
      break;
    case 'budget_policy|control.policy.created':
    case 'budget_policy|control.policy.paused':
    case 'budget_policy|control.policy.resumed':
    case 'budget_policy|control.policy.revoked':
      if (!POLICY_ID.test(resourceId)) throw new InvalidEventError();
      break;
    case 'budget_policy_revision|control.policy.revision.created':
      if (!isPolicyRevisionResource(resourceId)) throw new InvalidEventError();
      break;
    case 'commerce_session|control.commerce_session.issued':
    case 'commerce_session|control.commerce_session.exchanged':
    case 'commerce_session|control.commerce_session.revoked':
      if (!COMMERCE_SESSION_ID.test(resourceId)) throw new InvalidEventError();
      break;
    case 'commerce_action|control.commerce_action.authorized':
    case 'commerce_action|control.commerce_action.approved':
    case 'commerce_action|control.commerce_action.rejected':
    case 'commerce_action|control.commerce_action.cancelled':
      if (!COMMERCE_ACTION_ID.test(resourceId)) throw new InvalidEventError();
      break;
    default:
      throw new InvalidEventError();
  }

  return raw as unknown as ClaimedOutboxEvent;
}

function consume(event: ClaimedOutboxEvent): void {
  validateNotification(event);
}

const DEFAULT_HANDLERS: Record<NotificationEventKey, NotificationHandler> = {
  'organization|tenant.organization.created': consume,
  'agent|tenant.agent.created': consume,
  'agent|tenant.agent.updated': consume,
  'provider|tenant.provider.created': consume,
  'provider|tenant.provider.updated': consume,
  'membership|tenant.membership.set': consume,
  'agent_credential|tenant.agent.credential.created': consume,
  'agent_credential|tenant.agent.credential.revoked': consume,
  'provider_credential|tenant.provider.credential.created': consume,
  'provider_credential|tenant.provider.credential.revoked': consume,
  'listing|market.listing.created': consume,
  'listing_version|market.listing.version.created': consume,
  'listing_version|market.listing.origin_review.recorded': consume,
  'listing_version|market.listing.version.published': consume,
  'listing_version|market.listing.version.paused': consume,
  'listing_version|market.listing.version.retired': consume,
  'budget_policy|control.policy.created': consume,
  'budget_policy_revision|control.policy.revision.created': consume,
  'budget_policy|control.policy.paused': consume,
  'budget_policy|control.policy.resumed': consume,
  'budget_policy|control.policy.revoked': consume,
  'commerce_session|control.commerce_session.issued': consume,
  'commerce_session|control.commerce_session.exchanged': consume,
  'commerce_session|control.commerce_session.revoked': consume,
  'commerce_action|control.commerce_action.authorized': consume,
  'commerce_action|control.commerce_action.approved': consume,
  'commerce_action|control.commerce_action.rejected': consume,
  'commerce_action|control.commerce_action.cancelled': consume,
};

/**
 * Build the fixed closed registry. Overrides are a controlled test seam for
 * bounded async handlers; they only replace an existing allowlisted key.
 */
export function createHandlerRegistry(
  overrides?: Partial<Record<NotificationEventKey, NotificationHandler>>,
): NotificationHandlerRegistry {
  const registry: Record<NotificationEventKey, NotificationHandler> = { ...DEFAULT_HANDLERS };
  if (overrides !== undefined) {
    for (const key of NOTIFICATION_EVENT_KEYS) {
      const override = overrides[key];
      if (override !== undefined) registry[key] = override;
    }
  }
  return Object.freeze(registry);
}
