-- OpenArc bounded action/reservation/approval core (schema10).
-- Additive over schema9. Owner: openarc_migrator. Runtime: openarc_tenant_app.
-- Six forced-RLS migrator-owned tables in openarc_durable plus narrow definer
-- helpers. This migration NEVER creates roles/schemas, calls a provider,
-- verifies a protocol requirement row, grants funds or records a payment.
--
-- The production listing paymentLane is literal 'unavailable', so the
-- tenant-runtime wrapper can never reserve. The single migrator-only core
-- helper accepts the CLOSED internal mode production|internal_fixture; only
-- internal_fixture admits an exact source_kind='internal_fixture' requirement
-- row, and then ONLY bypassing the unavailable payment-lane admission. Every
-- real current parent/credential/session/policy/listing/budget check below is
-- identical in both modes. There is no caller/environment/GUC/boolean fixture
-- flag and no runtime insert or promotion helper.

-- ---------------------------------------------------------------------------
-- Shared canonical validators for the action surface.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.is_canonical_action_id(value text)
RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT value IS NOT NULL
     AND value ~ '^openarc:action:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
$$;

CREATE FUNCTION openarc_durable.is_canonical_reservation_id(value text)
RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT value IS NOT NULL
     AND value ~ '^openarc:reservation:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
$$;

CREATE FUNCTION openarc_durable.is_canonical_approval_id(value text)
RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT value IS NOT NULL
     AND value ~ '^openarc:approval:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
$$;

CREATE FUNCTION openarc_durable.is_canonical_requirement_id(value text)
RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT value IS NOT NULL
     AND value ~ '^openarc:requirement:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
$$;

-- Canonical positive decimal of at most 128 digits (exact sum bound).
CREATE FUNCTION openarc_durable.is_canonical_exposure_total(value text)
RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT value IS NOT NULL AND value ~ '^(0|[1-9][0-9]{0,127})$';
$$;

CREATE FUNCTION openarc_durable.is_allowed_exposure_identity(
  network_id text, asset text, representation text, decimals smallint
) RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT network_id = 'eip155:5042002' AND asset = 'USDC'
     AND representation = 'erc20' AND decimals = 6;
$$;

-- Canonical source provenance. Only the honest internal fixture kind exists in
-- this packet; P04 adds genuine protocol verification.
CREATE FUNCTION openarc_durable.is_canonical_source_kind(value text)
RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT value IS NOT NULL AND value = 'internal_fixture';
$$;

-- ---------------------------------------------------------------------------
-- commerce_exposure_locks: stable six-field exposure identity. NEVER policy
-- root/revision/session scoped and contains no resettable spend authority or
-- counter. A row exists only to serialize concurrent authorization for one
-- subject exposure identity.
-- ---------------------------------------------------------------------------
CREATE TABLE openarc_durable.commerce_exposure_locks (
  organization_id text NOT NULL,
  subject_agent_id text NOT NULL,
  network_id text NOT NULL,
  asset text NOT NULL,
  representation text NOT NULL,
  decimals smallint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, subject_agent_id, network_id, asset, representation, decimals),
  CONSTRAINT commerce_exposure_locks_subject_fk FOREIGN KEY (organization_id, subject_agent_id)
    REFERENCES openarc_tenant.agents(organization_id, agent_id) ON DELETE RESTRICT,
  CONSTRAINT commerce_exposure_locks_subject_valid CHECK (openarc_durable.is_canonical_agent_id(subject_agent_id)),
  CONSTRAINT commerce_exposure_locks_identity_valid CHECK (
    openarc_durable.is_allowed_exposure_identity(network_id, asset, representation, decimals))
);

-- ---------------------------------------------------------------------------
-- commerce_requirement_references: immutable requirement binding. Initial
-- migration creates ZERO rows; privileged PG tests seed them explicitly as
-- migrator only. No runtime insert and no promotion helper exists. There is no
-- fake protocol verifier and no production 'verified' row.
-- ---------------------------------------------------------------------------
CREATE TABLE openarc_durable.commerce_requirement_references (
  organization_id text NOT NULL,
  requirement_id text NOT NULL,
  seller_organization_id text NOT NULL,
  provider_id text NOT NULL,
  listing_id text NOT NULL,
  listing_version text NOT NULL,
  network_id text NOT NULL,
  asset text NOT NULL,
  representation text NOT NULL,
  decimals smallint NOT NULL,
  amount_atomic text NOT NULL,
  fee_atomic text NOT NULL,
  requirement_digest text NOT NULL,
  source_kind text NOT NULL,
  created_at timestamptz NOT NULL,
  valid_until timestamptz NOT NULL,
  PRIMARY KEY (organization_id, requirement_id),
  CONSTRAINT commerce_requirement_references_unique UNIQUE (requirement_id),
  CONSTRAINT commerce_requirement_references_org_fk FOREIGN KEY (organization_id)
    REFERENCES openarc_tenant.organizations(organization_id) ON DELETE RESTRICT,
  CONSTRAINT commerce_requirement_references_seller_fk FOREIGN KEY (seller_organization_id)
    REFERENCES openarc_tenant.organizations(organization_id) ON DELETE RESTRICT,
  CONSTRAINT commerce_requirement_references_ownership_fk FOREIGN KEY (
    seller_organization_id, provider_id, listing_id)
    REFERENCES openarc_tenant.listings(organization_id, provider_id, listing_id) ON DELETE RESTRICT,
  CONSTRAINT commerce_requirement_references_listing_fk FOREIGN KEY (
    seller_organization_id, listing_id, listing_version)
    REFERENCES openarc_tenant.listing_versions(organization_id, listing_id, version) ON DELETE RESTRICT,
  -- Narrow immutable binding anchor for the commerce_actions composite FK: an
  -- action can only ever mirror the exact seller/provider/listing/version and
  -- financial identity of its immutable requirement.
  CONSTRAINT commerce_requirement_references_action_binding UNIQUE (
    organization_id, requirement_id, seller_organization_id, provider_id, listing_id,
    listing_version, network_id, asset, representation, decimals, amount_atomic,
    fee_atomic, requirement_digest),
  CONSTRAINT commerce_requirement_references_id_valid CHECK (openarc_durable.is_canonical_requirement_id(requirement_id)),
  CONSTRAINT commerce_requirement_references_provider_valid CHECK (openarc_durable.is_canonical_provider_id(provider_id)),
  CONSTRAINT commerce_requirement_references_listing_valid CHECK (openarc_durable.is_canonical_listing_id(listing_id)),
  CONSTRAINT commerce_requirement_references_version_valid CHECK (openarc_durable.is_canonical_listing_version(listing_version)),
  CONSTRAINT commerce_requirement_references_identity_valid CHECK (
    openarc_durable.is_allowed_exposure_identity(network_id, asset, representation, decimals)),
  CONSTRAINT commerce_requirement_references_amount_valid CHECK (openarc_durable.is_positive_uint256(amount_atomic)),
  CONSTRAINT commerce_requirement_references_fee_valid CHECK (openarc_durable.is_canonical_uint256(fee_atomic)),
  CONSTRAINT commerce_requirement_references_digest_valid CHECK (openarc_durable.is_canonical_sha256_digest(requirement_digest)),
  CONSTRAINT commerce_requirement_references_source_valid CHECK (openarc_durable.is_canonical_source_kind(source_kind)),
  CONSTRAINT commerce_requirement_references_window_valid CHECK (valid_until > created_at)
);

-- ---------------------------------------------------------------------------
-- commerce_actions: exact shared action metadata plus the immutable approving
-- parent human account, bound machine credential/session identifiers for exact
-- revalidation, canonical request/context digest version1 and immutable
-- source_kind provenance. PK(org, actionId); stable logical action uniqueness
-- survives new idempotency keys; no status deletion.
-- ---------------------------------------------------------------------------
CREATE TABLE openarc_durable.commerce_actions (
  organization_id text NOT NULL,
  action_id text NOT NULL,
  subject_agent_id text NOT NULL,
  parent_human_account_id text NOT NULL REFERENCES openarc_auth.accounts(account_id) ON DELETE RESTRICT,
  commerce_session_id uuid NOT NULL,
  agent_session_id uuid NOT NULL,
  credential_id uuid NOT NULL,
  policy_id text NOT NULL,
  policy_revision text NOT NULL,
  seller_organization_id text NOT NULL,
  provider_id text NOT NULL,
  listing_id text NOT NULL,
  listing_version text NOT NULL,
  requirement_id text NOT NULL,
  requirement_digest text NOT NULL,
  network_id text NOT NULL,
  asset text NOT NULL,
  representation text NOT NULL,
  decimals smallint NOT NULL,
  amount_atomic text NOT NULL,
  fee_atomic text NOT NULL,
  debit_atomic text NOT NULL,
  request_digest text NOT NULL,
  source_kind text NOT NULL,
  status text NOT NULL,
  reservation_id text,
  approval_id text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id, action_id),
  CONSTRAINT commerce_actions_id_valid CHECK (openarc_durable.is_canonical_action_id(action_id)),
  CONSTRAINT commerce_actions_subject_valid CHECK (openarc_durable.is_canonical_agent_id(subject_agent_id)),
  CONSTRAINT commerce_actions_parent_valid CHECK (parent_human_account_id ~ '^openarc:account:'),
  CONSTRAINT commerce_actions_policy_valid CHECK (openarc_durable.is_canonical_policy_id(policy_id)),
  CONSTRAINT commerce_actions_policy_revision_valid CHECK (openarc_durable.is_canonical_policy_revision(policy_revision)),
  CONSTRAINT commerce_actions_provider_valid CHECK (openarc_durable.is_canonical_provider_id(provider_id)),
  CONSTRAINT commerce_actions_listing_valid CHECK (openarc_durable.is_canonical_listing_id(listing_id)),
  CONSTRAINT commerce_actions_listing_version_valid CHECK (openarc_durable.is_canonical_listing_version(listing_version)),
  CONSTRAINT commerce_actions_requirement_valid CHECK (openarc_durable.is_canonical_requirement_id(requirement_id)),
  CONSTRAINT commerce_actions_requirement_digest_valid CHECK (openarc_durable.is_canonical_sha256_digest(requirement_digest)),
  CONSTRAINT commerce_actions_identity_valid CHECK (
    openarc_durable.is_allowed_exposure_identity(network_id, asset, representation, decimals)),
  CONSTRAINT commerce_actions_amount_valid CHECK (openarc_durable.is_positive_uint256(amount_atomic)),
  CONSTRAINT commerce_actions_fee_valid CHECK (openarc_durable.is_canonical_uint256(fee_atomic)),
  CONSTRAINT commerce_actions_debit_valid CHECK (
    debit_atomic ~ '^[1-9][0-9]{0,127}$' AND debit_atomic::numeric = amount_atomic::numeric + fee_atomic::numeric),
  CONSTRAINT commerce_actions_request_digest_valid CHECK (openarc_durable.is_canonical_hex64(request_digest)),
  CONSTRAINT commerce_actions_source_valid CHECK (openarc_durable.is_canonical_source_kind(source_kind)),
  CONSTRAINT commerce_actions_status_valid CHECK (status IN (
    'pending_approval', 'reserved_not_granted', 'rejected', 'cancelled', 'expired')),
  CONSTRAINT commerce_actions_expiry_valid CHECK (expires_at > created_at AND updated_at >= created_at),
  CONSTRAINT commerce_actions_session_fk FOREIGN KEY (organization_id, commerce_session_id)
    REFERENCES openarc_durable.commerce_sessions(organization_id, session_id) ON DELETE RESTRICT,
  CONSTRAINT commerce_actions_credential_fk FOREIGN KEY (organization_id, credential_id)
    REFERENCES openarc_durable.agent_credentials(organization_id, credential_id) ON DELETE RESTRICT,
  CONSTRAINT commerce_actions_agent_session_fk FOREIGN KEY (agent_session_id)
    REFERENCES openarc_durable.agent_sessions(session_id) ON DELETE RESTRICT,
  CONSTRAINT commerce_actions_policy_fk FOREIGN KEY (organization_id, policy_id)
    REFERENCES openarc_tenant.budget_policy_roots(organization_id, policy_id) ON DELETE RESTRICT,
  CONSTRAINT commerce_actions_policy_revision_fk FOREIGN KEY (organization_id, policy_id, policy_revision)
    REFERENCES openarc_tenant.budget_policy_versions(organization_id, policy_id, revision) ON DELETE RESTRICT,
  CONSTRAINT commerce_actions_requirement_fk FOREIGN KEY (organization_id, requirement_id)
    REFERENCES openarc_durable.commerce_requirement_references(organization_id, requirement_id) ON DELETE RESTRICT,
  CONSTRAINT commerce_actions_seller_org_fk FOREIGN KEY (seller_organization_id)
    REFERENCES openarc_tenant.organizations(organization_id) ON DELETE RESTRICT,
  -- Seller-side ownership FKs are anchored to the immutable seller org, never
  -- the buyer org, and the version FK pins the exact published version.
  CONSTRAINT commerce_actions_seller_ownership_fk FOREIGN KEY (
    seller_organization_id, provider_id, listing_id)
    REFERENCES openarc_tenant.listings(organization_id, provider_id, listing_id) ON DELETE RESTRICT,
  CONSTRAINT commerce_actions_seller_listing_fk FOREIGN KEY (
    seller_organization_id, listing_id, listing_version)
    REFERENCES openarc_tenant.listing_versions(organization_id, listing_id, version) ON DELETE RESTRICT,
  -- The action mirrors the immutable requirement seller/provider/listing/
  -- version/digest/amount/asset binding exactly. A tampered action binding is
  -- rejected by this composite FK, independent of the buyer-org requirement FK.
  CONSTRAINT commerce_actions_requirement_binding_fk FOREIGN KEY (
    organization_id, requirement_id, seller_organization_id, provider_id, listing_id,
    listing_version, network_id, asset, representation, decimals, amount_atomic,
    fee_atomic, requirement_digest)
    REFERENCES openarc_durable.commerce_requirement_references (
      organization_id, requirement_id, seller_organization_id, provider_id, listing_id,
      listing_version, network_id, asset, representation, decimals, amount_atomic,
      fee_atomic, requirement_digest) ON DELETE RESTRICT,
  CONSTRAINT commerce_actions_exposure_fk FOREIGN KEY (
    organization_id, subject_agent_id, network_id, asset, representation, decimals)
    REFERENCES openarc_durable.commerce_exposure_locks(
      organization_id, subject_agent_id, network_id, asset, representation, decimals) ON DELETE RESTRICT,
  CONSTRAINT commerce_actions_approval_shape CHECK (
    (status = 'pending_approval' AND approval_id IS NOT NULL AND reservation_id IS NULL)
    OR (status = 'reserved_not_granted' AND reservation_id IS NOT NULL)
    OR (status = 'rejected' AND approval_id IS NOT NULL AND reservation_id IS NULL)
    OR (status IN ('cancelled', 'expired') AND (approval_id IS NOT NULL OR reservation_id IS NOT NULL)))
);

CREATE INDEX commerce_actions_exposure_idx
  ON openarc_durable.commerce_actions (
    organization_id, subject_agent_id, network_id, asset, representation, decimals);

-- ---------------------------------------------------------------------------
-- budget_reservations: unique(org,action), same exposure identity plus
-- immutable debitAtomic and source_kind provenance. DB10 creates held and can
-- release only unclaimed held. No public claim/commit/unknown resolution helper
-- and no generic runtime 'set status' function exists.
-- ---------------------------------------------------------------------------
CREATE TABLE openarc_durable.budget_reservations (
  organization_id text NOT NULL,
  reservation_id text NOT NULL,
  action_id text NOT NULL,
  subject_agent_id text NOT NULL,
  network_id text NOT NULL,
  asset text NOT NULL,
  representation text NOT NULL,
  decimals smallint NOT NULL,
  debit_atomic text NOT NULL,
  source_kind text NOT NULL,
  status text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  claimed_at timestamptz,
  resolved_at timestamptz,
  PRIMARY KEY (organization_id, reservation_id),
  CONSTRAINT budget_reservations_id_valid CHECK (openarc_durable.is_canonical_reservation_id(reservation_id)),
  CONSTRAINT budget_reservations_action_unique UNIQUE (organization_id, action_id),
  CONSTRAINT budget_reservations_identity_valid CHECK (
    openarc_durable.is_allowed_exposure_identity(network_id, asset, representation, decimals)),
  CONSTRAINT budget_reservations_debit_valid CHECK (debit_atomic ~ '^[1-9][0-9]{0,127}$'),
  CONSTRAINT budget_reservations_source_valid CHECK (openarc_durable.is_canonical_source_kind(source_kind)),
  CONSTRAINT budget_reservations_status_valid CHECK (status IN (
    'held', 'claimed', 'unknown', 'committed', 'released')),
  CONSTRAINT budget_reservations_action_fk FOREIGN KEY (organization_id, action_id)
    REFERENCES openarc_durable.commerce_actions(organization_id, action_id) ON DELETE RESTRICT,
  CONSTRAINT budget_reservations_exposure_fk FOREIGN KEY (
    organization_id, subject_agent_id, network_id, asset, representation, decimals)
    REFERENCES openarc_durable.commerce_exposure_locks(
      organization_id, subject_agent_id, network_id, asset, representation, decimals) ON DELETE RESTRICT,
  CONSTRAINT budget_reservations_time_shape CHECK (
    (status = 'held' AND claimed_at IS NULL AND resolved_at IS NULL)
    OR (status IN ('claimed', 'unknown') AND claimed_at IS NOT NULL AND resolved_at IS NULL)
    OR (status IN ('committed', 'released') AND resolved_at IS NOT NULL))
);

-- ---------------------------------------------------------------------------
-- commerce_approvals: exact shared approval metadata, unique(org,action),
-- immutable source_kind provenance. Pending decisions reserve NOTHING.
-- ---------------------------------------------------------------------------
CREATE TABLE openarc_durable.commerce_approvals (
  organization_id text NOT NULL,
  approval_id text NOT NULL,
  action_id text NOT NULL,
  subject_agent_id text NOT NULL,
  commerce_session_id uuid NOT NULL,
  policy_id text NOT NULL,
  policy_revision text NOT NULL,
  requested_by text NOT NULL REFERENCES openarc_auth.accounts(account_id) ON DELETE RESTRICT,
  separate_approver boolean NOT NULL,
  status text NOT NULL,
  decided_by text REFERENCES openarc_auth.accounts(account_id) ON DELETE RESTRICT,
  source_kind text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  decided_at timestamptz,
  PRIMARY KEY (organization_id, approval_id),
  CONSTRAINT commerce_approvals_id_valid CHECK (openarc_durable.is_canonical_approval_id(approval_id)),
  CONSTRAINT commerce_approvals_action_unique UNIQUE (organization_id, action_id),
  CONSTRAINT commerce_approvals_subject_valid CHECK (openarc_durable.is_canonical_agent_id(subject_agent_id)),
  CONSTRAINT commerce_approvals_policy_valid CHECK (openarc_durable.is_canonical_policy_id(policy_id)),
  CONSTRAINT commerce_approvals_policy_revision_valid CHECK (openarc_durable.is_canonical_policy_revision(policy_revision)),
  CONSTRAINT commerce_approvals_source_valid CHECK (openarc_durable.is_canonical_source_kind(source_kind)),
  CONSTRAINT commerce_approvals_status_valid CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
  CONSTRAINT commerce_approvals_expiry_valid CHECK (expires_at > created_at),
  CONSTRAINT commerce_approvals_action_fk FOREIGN KEY (organization_id, action_id)
    REFERENCES openarc_durable.commerce_actions(organization_id, action_id) ON DELETE RESTRICT,
  CONSTRAINT commerce_approvals_session_fk FOREIGN KEY (organization_id, commerce_session_id)
    REFERENCES openarc_durable.commerce_sessions(organization_id, session_id) ON DELETE RESTRICT,
  CONSTRAINT commerce_approvals_decision_shape CHECK (
    (status = 'pending' AND decided_by IS NULL AND decided_at IS NULL)
    OR (status = 'expired' AND decided_by IS NULL AND decided_at IS NULL)
    OR (status IN ('approved', 'rejected') AND decided_by IS NOT NULL AND decided_at IS NOT NULL))
);

-- ---------------------------------------------------------------------------
-- budget_events: append-only committed/released evidence, bounded opaque
-- eventId, org/action/reservation binding + exposure identity + exact
-- amountAtomic + eventTime + eventKind. Unique committed event per action;
-- immutable rows. Committed rows are privileged fixtures until a later
-- accepted resolution helper exists.
-- ---------------------------------------------------------------------------
CREATE TABLE openarc_durable.budget_events (
  organization_id text NOT NULL,
  event_id uuid NOT NULL,
  action_id text NOT NULL,
  reservation_id text NOT NULL,
  subject_agent_id text NOT NULL,
  network_id text NOT NULL,
  asset text NOT NULL,
  representation text NOT NULL,
  decimals smallint NOT NULL,
  amount_atomic text NOT NULL,
  event_kind text NOT NULL,
  event_time timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, event_id),
  CONSTRAINT budget_events_event_id_valid CHECK (openarc_durable.is_canonical_uuid_v4(event_id::text)),
  CONSTRAINT budget_events_action_valid CHECK (openarc_durable.is_canonical_action_id(action_id)),
  CONSTRAINT budget_events_reservation_valid CHECK (openarc_durable.is_canonical_reservation_id(reservation_id)),
  CONSTRAINT budget_events_identity_valid CHECK (
    openarc_durable.is_allowed_exposure_identity(network_id, asset, representation, decimals)),
  CONSTRAINT budget_events_amount_valid CHECK (amount_atomic ~ '^[1-9][0-9]{0,127}$'),
  CONSTRAINT budget_events_kind_valid CHECK (event_kind IN ('committed', 'released')),
  CONSTRAINT budget_events_action_fk FOREIGN KEY (organization_id, action_id)
    REFERENCES openarc_durable.commerce_actions(organization_id, action_id) ON DELETE RESTRICT,
  CONSTRAINT budget_events_reservation_fk FOREIGN KEY (organization_id, reservation_id)
    REFERENCES openarc_durable.budget_reservations(organization_id, reservation_id) ON DELETE RESTRICT,
  CONSTRAINT budget_events_exposure_fk FOREIGN KEY (
    organization_id, subject_agent_id, network_id, asset, representation, decimals)
    REFERENCES openarc_durable.commerce_exposure_locks(
      organization_id, subject_agent_id, network_id, asset, representation, decimals) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX budget_events_one_committed_per_action
  ON openarc_durable.budget_events (organization_id, action_id)
  WHERE event_kind = 'committed';

CREATE INDEX budget_events_unresolved_idx
  ON openarc_durable.budget_events (organization_id, subject_agent_id, network_id, asset, representation, decimals);

-- ---------------------------------------------------------------------------
-- Immutability triggers. Actions may only advance through the closed lifecycle
-- edges and never delete; requirement/event rows are append-only.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.reject_requirement_mutation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'commerce_requirement_immutable' USING ERRCODE = '42501';
END;
$$;

CREATE TRIGGER commerce_requirement_references_immutable
  BEFORE UPDATE OR DELETE ON openarc_durable.commerce_requirement_references
  FOR EACH ROW EXECUTE FUNCTION openarc_durable.reject_requirement_mutation();

CREATE FUNCTION openarc_durable.reject_budget_event_mutation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'budget_event_immutable' USING ERRCODE = '42501';
END;
$$;

CREATE TRIGGER budget_events_immutable
  BEFORE UPDATE OR DELETE ON openarc_durable.budget_events
  FOR EACH ROW EXECUTE FUNCTION openarc_durable.reject_budget_event_mutation();

CREATE FUNCTION openarc_durable.enforce_commerce_action_mutation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'commerce_action_immutable' USING ERRCODE = '42501';
  END IF;
  IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
     OR NEW.action_id IS DISTINCT FROM OLD.action_id
     OR NEW.subject_agent_id IS DISTINCT FROM OLD.subject_agent_id
     OR NEW.parent_human_account_id IS DISTINCT FROM OLD.parent_human_account_id
     OR NEW.commerce_session_id IS DISTINCT FROM OLD.commerce_session_id
     OR NEW.agent_session_id IS DISTINCT FROM OLD.agent_session_id
     OR NEW.credential_id IS DISTINCT FROM OLD.credential_id
     OR NEW.policy_id IS DISTINCT FROM OLD.policy_id
     OR NEW.policy_revision IS DISTINCT FROM OLD.policy_revision
     OR NEW.seller_organization_id IS DISTINCT FROM OLD.seller_organization_id
     OR NEW.provider_id IS DISTINCT FROM OLD.provider_id
     OR NEW.listing_id IS DISTINCT FROM OLD.listing_id
     OR NEW.listing_version IS DISTINCT FROM OLD.listing_version
     OR NEW.requirement_id IS DISTINCT FROM OLD.requirement_id
     OR NEW.requirement_digest IS DISTINCT FROM OLD.requirement_digest
     OR NEW.network_id IS DISTINCT FROM OLD.network_id
     OR NEW.asset IS DISTINCT FROM OLD.asset
     OR NEW.representation IS DISTINCT FROM OLD.representation
     OR NEW.decimals IS DISTINCT FROM OLD.decimals
     OR NEW.amount_atomic IS DISTINCT FROM OLD.amount_atomic
     OR NEW.fee_atomic IS DISTINCT FROM OLD.fee_atomic
     OR NEW.debit_atomic IS DISTINCT FROM OLD.debit_atomic
     OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
     OR NEW.source_kind IS DISTINCT FROM OLD.source_kind
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
    RAISE EXCEPTION 'commerce_action_immutable' USING ERRCODE = '42501';
  END IF;
  IF NOT (NEW.updated_at > OLD.updated_at) THEN
    RAISE EXCEPTION 'commerce_action_clock_invalid' USING ERRCODE = '23514';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
       (OLD.status = 'pending_approval' AND NEW.status IN ('reserved_not_granted', 'rejected', 'cancelled', 'expired'))
       OR (OLD.status = 'reserved_not_granted' AND NEW.status IN ('cancelled', 'expired'))
       OR (OLD.status IN ('rejected', 'cancelled', 'expired') AND NEW.status = OLD.status)) THEN
    RAISE EXCEPTION 'commerce_action_status_invalid' USING ERRCODE = '23514';
  END IF;
  -- Binding fields move with the status and never re-point after being set.
  IF OLD.reservation_id IS NOT NULL AND NEW.reservation_id IS DISTINCT FROM OLD.reservation_id THEN
    RAISE EXCEPTION 'commerce_action_binding_immutable' USING ERRCODE = '42501';
  END IF;
  IF OLD.approval_id IS NOT NULL AND NEW.approval_id IS DISTINCT FROM OLD.approval_id THEN
    RAISE EXCEPTION 'commerce_action_binding_immutable' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER commerce_actions_mutation
  BEFORE UPDATE OR DELETE ON openarc_durable.commerce_actions
  FOR EACH ROW EXECUTE FUNCTION openarc_durable.enforce_commerce_action_mutation();

CREATE FUNCTION openarc_durable.enforce_budget_reservation_mutation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'budget_reservation_immutable' USING ERRCODE = '42501';
  END IF;
  IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
     OR NEW.reservation_id IS DISTINCT FROM OLD.reservation_id
     OR NEW.action_id IS DISTINCT FROM OLD.action_id
     OR NEW.subject_agent_id IS DISTINCT FROM OLD.subject_agent_id
     OR NEW.network_id IS DISTINCT FROM OLD.network_id
     OR NEW.asset IS DISTINCT FROM OLD.asset
     OR NEW.representation IS DISTINCT FROM OLD.representation
     OR NEW.decimals IS DISTINCT FROM OLD.decimals
     OR NEW.debit_atomic IS DISTINCT FROM OLD.debit_atomic
     OR NEW.source_kind IS DISTINCT FROM OLD.source_kind
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'budget_reservation_immutable' USING ERRCODE = '42501';
  END IF;
  IF NOT (
       (OLD.status = 'held' AND NEW.status IN ('held', 'claimed', 'unknown', 'committed', 'released'))
       OR (OLD.status IN ('claimed', 'unknown') AND NEW.status = OLD.status)
       OR (OLD.status IN ('committed', 'released') AND NEW.status = OLD.status)) THEN
    RAISE EXCEPTION 'budget_reservation_status_invalid' USING ERRCODE = '23514';
  END IF;
  IF OLD.claimed_at IS NOT NULL AND NEW.claimed_at IS DISTINCT FROM OLD.claimed_at THEN
    RAISE EXCEPTION 'budget_reservation_claim_immutable' USING ERRCODE = '42501';
  END IF;
  IF OLD.resolved_at IS NOT NULL AND NEW.resolved_at IS DISTINCT FROM OLD.resolved_at THEN
    RAISE EXCEPTION 'budget_reservation_resolution_immutable' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER budget_reservations_mutation
  BEFORE UPDATE OR DELETE ON openarc_durable.budget_reservations
  FOR EACH ROW EXECUTE FUNCTION openarc_durable.enforce_budget_reservation_mutation();

CREATE FUNCTION openarc_durable.enforce_commerce_approval_mutation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'commerce_approval_immutable' USING ERRCODE = '42501';
  END IF;
  IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
     OR NEW.approval_id IS DISTINCT FROM OLD.approval_id
     OR NEW.action_id IS DISTINCT FROM OLD.action_id
     OR NEW.subject_agent_id IS DISTINCT FROM OLD.subject_agent_id
     OR NEW.commerce_session_id IS DISTINCT FROM OLD.commerce_session_id
     OR NEW.policy_id IS DISTINCT FROM OLD.policy_id
     OR NEW.policy_revision IS DISTINCT FROM OLD.policy_revision
     OR NEW.requested_by IS DISTINCT FROM OLD.requested_by
     OR NEW.separate_approver IS DISTINCT FROM OLD.separate_approver
     OR NEW.source_kind IS DISTINCT FROM OLD.source_kind
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
    RAISE EXCEPTION 'commerce_approval_immutable' USING ERRCODE = '42501';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
       (OLD.status = 'pending' AND NEW.status IN ('approved', 'rejected', 'expired'))
       OR (OLD.status IN ('approved', 'rejected', 'expired') AND NEW.status = OLD.status)) THEN
    RAISE EXCEPTION 'commerce_approval_status_invalid' USING ERRCODE = '23514';
  END IF;
  IF OLD.decided_by IS NOT NULL AND NEW.decided_by IS DISTINCT FROM OLD.decided_by THEN
    RAISE EXCEPTION 'commerce_approval_decision_immutable' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER commerce_approvals_mutation
  BEFORE UPDATE OR DELETE ON openarc_durable.commerce_approvals
  FOR EACH ROW EXECUTE FUNCTION openarc_durable.enforce_commerce_approval_mutation();

-- ---------------------------------------------------------------------------
-- RLS: migrator-only. Runtime/worker/PUBLIC receive no direct privilege.
-- ---------------------------------------------------------------------------
ALTER TABLE openarc_durable.commerce_exposure_locks ENABLE ROW LEVEL SECURITY;
ALTER TABLE openarc_durable.commerce_exposure_locks FORCE ROW LEVEL SECURITY;
ALTER TABLE openarc_durable.commerce_requirement_references ENABLE ROW LEVEL SECURITY;
ALTER TABLE openarc_durable.commerce_requirement_references FORCE ROW LEVEL SECURITY;
ALTER TABLE openarc_durable.commerce_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE openarc_durable.commerce_actions FORCE ROW LEVEL SECURITY;
ALTER TABLE openarc_durable.budget_reservations ENABLE ROW LEVEL SECURITY;
ALTER TABLE openarc_durable.budget_reservations FORCE ROW LEVEL SECURITY;
ALTER TABLE openarc_durable.commerce_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE openarc_durable.commerce_approvals FORCE ROW LEVEL SECURITY;
ALTER TABLE openarc_durable.budget_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE openarc_durable.budget_events FORCE ROW LEVEL SECURITY;

CREATE POLICY commerce_exposure_locks_migrator ON openarc_durable.commerce_exposure_locks
  FOR ALL TO openarc_migrator USING (true) WITH CHECK (true);
CREATE POLICY commerce_requirement_references_migrator ON openarc_durable.commerce_requirement_references
  FOR ALL TO openarc_migrator USING (true) WITH CHECK (true);
CREATE POLICY commerce_actions_migrator ON openarc_durable.commerce_actions
  FOR ALL TO openarc_migrator USING (true) WITH CHECK (true);
CREATE POLICY budget_reservations_migrator ON openarc_durable.budget_reservations
  FOR ALL TO openarc_migrator USING (true) WITH CHECK (true);
CREATE POLICY commerce_approvals_migrator ON openarc_durable.commerce_approvals
  FOR ALL TO openarc_migrator USING (true) WITH CHECK (true);
CREATE POLICY budget_events_migrator ON openarc_durable.budget_events
  FOR ALL TO openarc_migrator USING (true) WITH CHECK (true);

REVOKE ALL ON TABLE openarc_durable.commerce_exposure_locks FROM PUBLIC;
REVOKE ALL ON TABLE openarc_durable.commerce_requirement_references FROM PUBLIC;
REVOKE ALL ON TABLE openarc_durable.commerce_actions FROM PUBLIC;
REVOKE ALL ON TABLE openarc_durable.budget_reservations FROM PUBLIC;
REVOKE ALL ON TABLE openarc_durable.commerce_approvals FROM PUBLIC;
REVOKE ALL ON TABLE openarc_durable.budget_events FROM PUBLIC;

-- The core definers lock subject/prerequisite rows with SELECT ... FOR UPDATE.
-- Under FORCE RLS that requires migrator UPDATE policies on the tenant rows the
-- helpers lock. These policies grant nothing to any runtime role (which holds
-- no table privilege and no policy) and do not widen runtime access.
CREATE POLICY listings_select_migrator ON openarc_tenant.listings
  FOR SELECT TO openarc_migrator USING (current_user = 'openarc_migrator');
CREATE POLICY listing_versions_select_migrator ON openarc_tenant.listing_versions
  FOR SELECT TO openarc_migrator USING (current_user = 'openarc_migrator');
CREATE POLICY listing_version_states_select_migrator ON openarc_tenant.listing_version_states
  FOR SELECT TO openarc_migrator USING (current_user = 'openarc_migrator');
CREATE POLICY listing_version_states_update_migrator ON openarc_tenant.listing_version_states
  FOR UPDATE TO openarc_migrator USING (current_user = 'openarc_migrator')
  WITH CHECK (current_user = 'openarc_migrator');
CREATE POLICY listing_origin_reviews_select_migrator ON openarc_tenant.listing_origin_reviews
  FOR SELECT TO openarc_migrator USING (current_user = 'openarc_migrator');
CREATE POLICY providers_update_migrator_actions ON openarc_tenant.providers
  FOR UPDATE TO openarc_migrator USING (current_user = 'openarc_migrator')
  WITH CHECK (current_user = 'openarc_migrator');
CREATE POLICY agents_update_migrator_actions ON openarc_tenant.agents
  FOR UPDATE TO openarc_migrator USING (current_user = 'openarc_migrator')
  WITH CHECK (current_user = 'openarc_migrator');
CREATE POLICY budget_policy_roots_update_migrator_actions ON openarc_tenant.budget_policy_roots
  FOR UPDATE TO openarc_migrator USING (current_user = 'openarc_migrator')
  WITH CHECK (current_user = 'openarc_migrator');
CREATE POLICY budget_policy_versions_select_migrator_actions ON openarc_tenant.budget_policy_versions
  FOR SELECT TO openarc_migrator USING (current_user = 'openarc_migrator');
CREATE POLICY memberships_update_migrator_actions ON openarc_tenant.memberships
  FOR UPDATE TO openarc_migrator USING (current_user = 'openarc_migrator')
  WITH CHECK (current_user = 'openarc_migrator');

-- ---------------------------------------------------------------------------
-- Closed operation / resource / event union extensions. Every old tuple is
-- retained verbatim; only the four action tuples are appended.
-- ---------------------------------------------------------------------------
ALTER TABLE openarc_durable.idempotency_records
  DROP CONSTRAINT idempotency_operation_valid,
  DROP CONSTRAINT idempotency_digest_version_valid,
  DROP CONSTRAINT idempotency_resource_type_valid,
  DROP CONSTRAINT idempotency_resource_matches_operation,
  DROP CONSTRAINT idempotency_market_resource_shape,
  DROP CONSTRAINT idempotency_policy_resource_shape,
  DROP CONSTRAINT idempotency_commerce_session_shape;

ALTER TABLE openarc_durable.idempotency_records
  ADD CONSTRAINT idempotency_operation_valid CHECK (operation IN (
    'tenant.organization.create',
    'tenant.agent.create',
    'tenant.agent.update',
    'tenant.provider.create',
    'tenant.provider.update',
    'tenant.membership.set',
    'tenant.agent.credential.issue',
    'tenant.agent.credential.revoke',
    'tenant.provider.credential.issue',
    'tenant.provider.credential.revoke',
    'market.listing.create',
    'market.listing.version.create',
    'market.listing.origin_review.record',
    'market.listing.version.publish',
    'market.listing.version.pause',
    'market.listing.version.retire',
    'control.policy.create',
    'control.policy.revision.create',
    'control.policy.pause',
    'control.policy.resume',
    'control.policy.revoke',
    'control.commerce_session.issue',
    'control.commerce_session.exchange',
    'control.commerce_session.revoke',
    'control.commerce_action.authorize',
    'control.commerce_action.approve',
    'control.commerce_action.reject',
    'control.commerce_action.cancel'
  )),
  ADD CONSTRAINT idempotency_digest_version_valid CHECK (digest_version IN (
    'tenant.organization.create.v1',
    'tenant.agent.create.v1',
    'tenant.agent.update.v1',
    'tenant.provider.create.v1',
    'tenant.provider.update.v1',
    'tenant.membership.set.v1',
    'tenant.agent.credential.issue.v1',
    'tenant.agent.credential.revoke.v1',
    'tenant.provider.credential.issue.v1',
    'tenant.provider.credential.revoke.v1',
    'market.listing.create.v1',
    'market.listing.version.create.v1',
    'market.listing.origin_review.record.v1',
    'market.listing.version.publish.v1',
    'market.listing.version.pause.v1',
    'market.listing.version.retire.v1',
    'control.policy.create.v1',
    'control.policy.revision.create.v1',
    'control.policy.pause.v1',
    'control.policy.resume.v1',
    'control.policy.revoke.v1',
    'control.commerce_session.issue.v1',
    'control.commerce_session.exchange.v1',
    'control.commerce_session.revoke.v1',
    'control.commerce_action.authorize.v1',
    'control.commerce_action.approve.v1',
    'control.commerce_action.reject.v1',
    'control.commerce_action.cancel.v1'
  )),
  ADD CONSTRAINT idempotency_resource_type_valid CHECK (resource_type IS NULL OR resource_type IN (
    'organization', 'agent', 'provider', 'membership',
    'agent_credential', 'provider_credential',
    'listing', 'listing_version',
    'budget_policy', 'budget_policy_revision',
    'commerce_session', 'commerce_action'
  )),
  ADD CONSTRAINT idempotency_resource_matches_operation CHECK (
    resource_type IS NULL OR resource_type = CASE operation
      WHEN 'tenant.organization.create' THEN 'organization'
      WHEN 'tenant.agent.create' THEN 'agent'
      WHEN 'tenant.agent.update' THEN 'agent'
      WHEN 'tenant.provider.create' THEN 'provider'
      WHEN 'tenant.provider.update' THEN 'provider'
      WHEN 'tenant.membership.set' THEN 'membership'
      WHEN 'tenant.agent.credential.issue' THEN 'agent_credential'
      WHEN 'tenant.agent.credential.revoke' THEN 'agent_credential'
      WHEN 'tenant.provider.credential.issue' THEN 'provider_credential'
      WHEN 'tenant.provider.credential.revoke' THEN 'provider_credential'
      WHEN 'market.listing.create' THEN 'listing'
      WHEN 'market.listing.version.create' THEN 'listing_version'
      WHEN 'market.listing.origin_review.record' THEN 'listing_version'
      WHEN 'market.listing.version.publish' THEN 'listing_version'
      WHEN 'market.listing.version.pause' THEN 'listing_version'
      WHEN 'market.listing.version.retire' THEN 'listing_version'
      WHEN 'control.policy.create' THEN 'budget_policy'
      WHEN 'control.policy.revision.create' THEN 'budget_policy_revision'
      WHEN 'control.policy.pause' THEN 'budget_policy'
      WHEN 'control.policy.resume' THEN 'budget_policy'
      WHEN 'control.policy.revoke' THEN 'budget_policy'
      WHEN 'control.commerce_session.issue' THEN 'commerce_session'
      WHEN 'control.commerce_session.exchange' THEN 'commerce_session'
      WHEN 'control.commerce_session.revoke' THEN 'commerce_session'
      WHEN 'control.commerce_action.authorize' THEN 'commerce_action'
      WHEN 'control.commerce_action.approve' THEN 'commerce_action'
      WHEN 'control.commerce_action.reject' THEN 'commerce_action'
      WHEN 'control.commerce_action.cancel' THEN 'commerce_action'
    END
  ),
  ADD CONSTRAINT idempotency_market_resource_shape CHECK (
    (resource_type = 'listing' AND resource_id IS NOT NULL AND listing_id = resource_id AND listing_version IS NULL)
    OR (resource_type = 'listing_version' AND listing_version IS NOT NULL
        AND openarc_durable.is_canonical_listing_id(listing_id)
        AND openarc_durable.is_canonical_listing_version(listing_version)
        AND resource_id = listing_id || '@' || listing_version
        AND CASE
          WHEN operation IN ('market.listing.version.create') THEN listing_version::numeric >= 2
          WHEN operation IN (
            'market.listing.origin_review.record',
            'market.listing.version.publish',
            'market.listing.version.pause',
            'market.listing.version.retire'
          ) THEN listing_version::numeric >= 1
          ELSE false
        END)
    OR (resource_type IS NULL OR resource_type NOT IN ('listing', 'listing_version'))
  ),
  ADD CONSTRAINT idempotency_policy_resource_shape CHECK (
    (resource_type = 'budget_policy' AND resource_id IS NOT NULL
     AND openarc_durable.is_canonical_policy_id(resource_id)
     AND policy_id = resource_id AND policy_revision IS NULL)
    OR (resource_type = 'budget_policy_revision' AND policy_revision IS NOT NULL
        AND openarc_durable.is_canonical_policy_id(policy_id)
        AND openarc_durable.is_canonical_policy_revision(policy_revision)
        AND resource_id = policy_id || '@' || policy_revision
        AND policy_revision::numeric >= 2)
    OR (resource_type IS NULL OR resource_type NOT IN ('budget_policy', 'budget_policy_revision'))
  ),
  ADD CONSTRAINT idempotency_commerce_session_shape CHECK (
    (resource_type = 'commerce_session'
     AND resource_id IS NOT NULL
     AND openarc_durable.is_canonical_commerce_session_id(resource_id))
    OR (resource_type = 'commerce_action'
        AND resource_id IS NOT NULL
        AND openarc_durable.is_canonical_action_id(resource_id))
    OR resource_type NOT IN ('commerce_session', 'commerce_action')
  );

ALTER TABLE openarc_durable.audit_events
  DROP CONSTRAINT audit_operation_valid,
  DROP CONSTRAINT audit_resource_type_valid,
  DROP CONSTRAINT audit_resource_matches_operation,
  DROP CONSTRAINT audit_policy_resource_shape,
  DROP CONSTRAINT audit_commerce_session_shape;

ALTER TABLE openarc_durable.audit_events
  ADD CONSTRAINT audit_operation_valid CHECK (operation IN (
    'tenant.organization.create',
    'tenant.agent.create',
    'tenant.agent.update',
    'tenant.provider.create',
    'tenant.provider.update',
    'tenant.membership.set',
    'tenant.agent.credential.issue',
    'tenant.agent.credential.revoke',
    'tenant.provider.credential.issue',
    'tenant.provider.credential.revoke',
    'market.listing.create',
    'market.listing.version.create',
    'market.listing.origin_review.record',
    'market.listing.version.publish',
    'market.listing.version.pause',
    'market.listing.version.retire',
    'control.policy.create',
    'control.policy.revision.create',
    'control.policy.pause',
    'control.policy.resume',
    'control.policy.revoke',
    'control.commerce_session.issue',
    'control.commerce_session.exchange',
    'control.commerce_session.revoke',
    'control.commerce_action.authorize',
    'control.commerce_action.approve',
    'control.commerce_action.reject',
    'control.commerce_action.cancel'
  )),
  ADD CONSTRAINT audit_resource_type_valid CHECK (resource_type IN (
    'organization', 'agent', 'provider', 'membership',
    'agent_credential', 'provider_credential',
    'listing', 'listing_version',
    'budget_policy', 'budget_policy_revision',
    'commerce_session', 'commerce_action'
  )),
  ADD CONSTRAINT audit_resource_matches_operation CHECK (
    resource_type = CASE operation
      WHEN 'tenant.organization.create' THEN 'organization'
      WHEN 'tenant.agent.create' THEN 'agent'
      WHEN 'tenant.agent.update' THEN 'agent'
      WHEN 'tenant.provider.create' THEN 'provider'
      WHEN 'tenant.provider.update' THEN 'provider'
      WHEN 'tenant.membership.set' THEN 'membership'
      WHEN 'tenant.agent.credential.issue' THEN 'agent_credential'
      WHEN 'tenant.agent.credential.revoke' THEN 'agent_credential'
      WHEN 'tenant.provider.credential.issue' THEN 'provider_credential'
      WHEN 'tenant.provider.credential.revoke' THEN 'provider_credential'
      WHEN 'market.listing.create' THEN 'listing'
      WHEN 'market.listing.version.create' THEN 'listing_version'
      WHEN 'market.listing.origin_review.record' THEN 'listing_version'
      WHEN 'market.listing.version.publish' THEN 'listing_version'
      WHEN 'market.listing.version.pause' THEN 'listing_version'
      WHEN 'market.listing.version.retire' THEN 'listing_version'
      WHEN 'control.policy.create' THEN 'budget_policy'
      WHEN 'control.policy.revision.create' THEN 'budget_policy_revision'
      WHEN 'control.policy.pause' THEN 'budget_policy'
      WHEN 'control.policy.resume' THEN 'budget_policy'
      WHEN 'control.policy.revoke' THEN 'budget_policy'
      WHEN 'control.commerce_session.issue' THEN 'commerce_session'
      WHEN 'control.commerce_session.exchange' THEN 'commerce_session'
      WHEN 'control.commerce_session.revoke' THEN 'commerce_session'
      WHEN 'control.commerce_action.authorize' THEN 'commerce_action'
      WHEN 'control.commerce_action.approve' THEN 'commerce_action'
      WHEN 'control.commerce_action.reject' THEN 'commerce_action'
      WHEN 'control.commerce_action.cancel' THEN 'commerce_action'
    END
  ),
  ADD CONSTRAINT audit_policy_resource_shape CHECK (
    (resource_type = 'budget_policy' AND openarc_durable.is_canonical_policy_id(resource_id)
     AND policy_id = resource_id AND policy_revision IS NULL)
    OR (resource_type = 'budget_policy_revision' AND policy_revision IS NOT NULL
        AND openarc_durable.is_canonical_policy_id(policy_id)
        AND openarc_durable.is_canonical_policy_revision(policy_revision)
        AND resource_id = policy_id || '@' || policy_revision
        AND policy_revision::numeric >= 2)
    OR (resource_type NOT IN ('budget_policy', 'budget_policy_revision'))
  ),
  ADD CONSTRAINT audit_commerce_session_shape CHECK (
    (resource_type = 'commerce_session'
     AND openarc_durable.is_canonical_commerce_session_id(resource_id))
    OR (resource_type = 'commerce_action'
        AND openarc_durable.is_canonical_action_id(resource_id))
    OR resource_type NOT IN ('commerce_session', 'commerce_action')
  );

ALTER TABLE openarc_durable.outbox_events
  DROP CONSTRAINT outbox_resource_type_valid,
  DROP CONSTRAINT outbox_event_type_valid,
  DROP CONSTRAINT outbox_resource_matches_event,
  DROP CONSTRAINT outbox_receipt_fk,
  DROP CONSTRAINT outbox_commerce_session_shape;

ALTER TABLE openarc_durable.outbox_events
  ADD CONSTRAINT outbox_resource_type_valid CHECK (resource_type IN (
    'organization', 'agent', 'provider', 'membership',
    'agent_credential', 'provider_credential',
    'listing', 'listing_version',
    'budget_policy', 'budget_policy_revision',
    'commerce_session', 'commerce_action'
  )),
  ADD CONSTRAINT outbox_event_type_valid CHECK (event_type IN (
    'tenant.organization.created',
    'tenant.agent.created',
    'tenant.agent.updated',
    'tenant.provider.created',
    'tenant.provider.updated',
    'tenant.membership.set',
    'tenant.agent.credential.created',
    'tenant.agent.credential.revoked',
    'tenant.provider.credential.created',
    'tenant.provider.credential.revoked',
    'market.listing.created',
    'market.listing.version.created',
    'market.listing.origin_review.recorded',
    'market.listing.version.published',
    'market.listing.version.paused',
    'market.listing.version.retired',
    'control.policy.created',
    'control.policy.revision.created',
    'control.policy.paused',
    'control.policy.resumed',
    'control.policy.revoked',
    'control.commerce_session.issued',
    'control.commerce_session.exchanged',
    'control.commerce_session.revoked',
    'control.commerce_action.authorized',
    'control.commerce_action.approved',
    'control.commerce_action.rejected',
    'control.commerce_action.cancelled'
  ));

ALTER TABLE openarc_durable.outbox_events
  DROP COLUMN receipt_operation;
ALTER TABLE openarc_durable.outbox_events
  ADD COLUMN receipt_operation text GENERATED ALWAYS AS (
    CASE event_type
      WHEN 'tenant.organization.created' THEN 'tenant.organization.create'
      WHEN 'tenant.agent.created' THEN 'tenant.agent.create'
      WHEN 'tenant.agent.updated' THEN 'tenant.agent.update'
      WHEN 'tenant.provider.created' THEN 'tenant.provider.create'
      WHEN 'tenant.provider.updated' THEN 'tenant.provider.update'
      WHEN 'tenant.membership.set' THEN 'tenant.membership.set'
      WHEN 'tenant.agent.credential.created' THEN 'tenant.agent.credential.issue'
      WHEN 'tenant.agent.credential.revoked' THEN 'tenant.agent.credential.revoke'
      WHEN 'tenant.provider.credential.created' THEN 'tenant.provider.credential.issue'
      WHEN 'tenant.provider.credential.revoked' THEN 'tenant.provider.credential.revoke'
      WHEN 'market.listing.created' THEN 'market.listing.create'
      WHEN 'market.listing.version.created' THEN 'market.listing.version.create'
      WHEN 'market.listing.origin_review.recorded' THEN 'market.listing.origin_review.record'
      WHEN 'market.listing.version.published' THEN 'market.listing.version.publish'
      WHEN 'market.listing.version.paused' THEN 'market.listing.version.pause'
      WHEN 'market.listing.version.retired' THEN 'market.listing.version.retire'
      WHEN 'control.policy.created' THEN 'control.policy.create'
      WHEN 'control.policy.revision.created' THEN 'control.policy.revision.create'
      WHEN 'control.policy.paused' THEN 'control.policy.pause'
      WHEN 'control.policy.resumed' THEN 'control.policy.resume'
      WHEN 'control.policy.revoked' THEN 'control.policy.revoke'
      WHEN 'control.commerce_session.issued' THEN 'control.commerce_session.issue'
      WHEN 'control.commerce_session.exchanged' THEN 'control.commerce_session.exchange'
      WHEN 'control.commerce_session.revoked' THEN 'control.commerce_session.revoke'
      WHEN 'control.commerce_action.authorized' THEN 'control.commerce_action.authorize'
      WHEN 'control.commerce_action.approved' THEN 'control.commerce_action.approve'
      WHEN 'control.commerce_action.rejected' THEN 'control.commerce_action.reject'
      WHEN 'control.commerce_action.cancelled' THEN 'control.commerce_action.cancel'
    END
  ) STORED;

ALTER TABLE openarc_durable.outbox_events
  ADD CONSTRAINT outbox_resource_matches_event CHECK (
    resource_type = CASE event_type
      WHEN 'tenant.organization.created' THEN 'organization'
      WHEN 'tenant.agent.created' THEN 'agent'
      WHEN 'tenant.agent.updated' THEN 'agent'
      WHEN 'tenant.provider.created' THEN 'provider'
      WHEN 'tenant.provider.updated' THEN 'provider'
      WHEN 'tenant.membership.set' THEN 'membership'
      WHEN 'tenant.agent.credential.created' THEN 'agent_credential'
      WHEN 'tenant.agent.credential.revoked' THEN 'agent_credential'
      WHEN 'tenant.provider.credential.created' THEN 'provider_credential'
      WHEN 'tenant.provider.credential.revoked' THEN 'provider_credential'
      WHEN 'market.listing.created' THEN 'listing'
      WHEN 'market.listing.version.created' THEN 'listing_version'
      WHEN 'market.listing.origin_review.recorded' THEN 'listing_version'
      WHEN 'market.listing.version.published' THEN 'listing_version'
      WHEN 'market.listing.version.paused' THEN 'listing_version'
      WHEN 'market.listing.version.retired' THEN 'listing_version'
      WHEN 'control.policy.created' THEN 'budget_policy'
      WHEN 'control.policy.revision.created' THEN 'budget_policy_revision'
      WHEN 'control.policy.paused' THEN 'budget_policy'
      WHEN 'control.policy.resumed' THEN 'budget_policy'
      WHEN 'control.policy.revoked' THEN 'budget_policy'
      WHEN 'control.commerce_session.issued' THEN 'commerce_session'
      WHEN 'control.commerce_session.exchanged' THEN 'commerce_session'
      WHEN 'control.commerce_session.revoked' THEN 'commerce_session'
      WHEN 'control.commerce_action.authorized' THEN 'commerce_action'
      WHEN 'control.commerce_action.approved' THEN 'commerce_action'
      WHEN 'control.commerce_action.rejected' THEN 'commerce_action'
      WHEN 'control.commerce_action.cancelled' THEN 'commerce_action'
    END
  ),
  ADD CONSTRAINT outbox_receipt_fk FOREIGN KEY (
    organization_id, mutation_id, resource_type, resource_id, receipt_operation
  ) REFERENCES openarc_durable.idempotency_records (
    organization_id, mutation_id, resource_type, resource_id, operation
  ) ON DELETE RESTRICT;

ALTER TABLE openarc_durable.outbox_events
  ADD CONSTRAINT outbox_commerce_session_shape CHECK (
    (resource_type = 'commerce_session'
     AND openarc_durable.is_canonical_commerce_session_id(resource_id))
    OR (resource_type = 'commerce_action'
        AND openarc_durable.is_canonical_action_id(resource_id))
    OR resource_type NOT IN ('commerce_session', 'commerce_action')
  );

-- ---------------------------------------------------------------------------
-- Immutable requirement binding resolution. No lock and no authority: returns
-- the stored binding so a digest can be constructed, and is revalidated by the
-- core under the full lock order. A missing row is an input fault.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.resolve_commerce_requirement(requirement_id_input text)
RETURNS TABLE(
  out_organization_id text,
  out_requirement_id text,
  out_seller_organization_id text,
  out_provider_id text,
  out_listing_id text,
  out_listing_version text,
  out_network_id text,
  out_asset text,
  out_representation text,
  out_decimals smallint,
  out_amount_atomic text,
  out_fee_atomic text,
  out_requirement_digest text,
  out_source_kind text,
  out_created_at timestamptz,
  out_valid_until timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF NOT openarc_durable.is_canonical_requirement_id(requirement_id_input) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
    SELECT r.organization_id, r.requirement_id, r.seller_organization_id, r.provider_id, r.listing_id,
           r.listing_version, r.network_id, r.asset, r.representation, r.decimals,
           r.amount_atomic, r.fee_atomic, r.requirement_digest, r.source_kind,
           r.created_at, r.valid_until
      FROM openarc_durable.commerce_requirement_references r
     WHERE r.requirement_id = requirement_id_input;
END;
$$;

-- ---------------------------------------------------------------------------
-- Current human authority preamble shared by decide/cancel/read. Mirrors the
-- accepted schema9 commerce preamble: current owner/operator, non-recovery;
-- fresh proof is required only for writers. Never a principal/role input.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.lock_action_human(
  session_hash text,
  organization_id text,
  require_fresh boolean
) RETURNS TABLE(out_actor text, out_role text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_actor text;
  v_method text;
  v_role text;
  v_status text;
  v_created_at timestamptz;
  v_expires_at timestamptz;
  v_now timestamptz;
BEGIN
  IF require_fresh IS NULL THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_canonical_org_id(organization_id) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  SELECT l.account_id, l.method, l.session_created_at, l.session_expires_at
    INTO v_actor, v_method, v_created_at, v_expires_at
    FROM openarc_tenant.lock_auth_session(session_hash, NULL) AS l;
  IF v_actor IS NULL OR v_method = 'recovery' THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;
  PERFORM 1 FROM openarc_tenant.organizations o
   WHERE o.organization_id = organization_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT m.role, m.status INTO v_role, v_status
    FROM openarc_tenant.memberships m
   WHERE m.organization_id = organization_id AND m.account_id = v_actor FOR UPDATE;
  IF NOT FOUND OR v_status <> 'active' OR v_role NOT IN ('owner', 'operator') THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT l.account_id, l.method, l.session_created_at, l.session_expires_at
    INTO v_actor, v_method, v_created_at, v_expires_at
    FROM openarc_tenant.lock_auth_session(session_hash, NULL) AS l;
  IF v_actor IS NULL OR v_method = 'recovery' THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;
  SELECT clock_timestamp() INTO v_now;
  IF NOT (v_expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;
  IF require_fresh AND NOT (v_created_at > v_now - interval '5 minutes') THEN
    RAISE EXCEPTION 'commerce_proof_stale' USING ERRCODE = '28000';
  END IF;
  out_actor := v_actor;
  out_role := v_role;
  RETURN NEXT;
END;
$$;

CREATE FUNCTION openarc_durable.lock_action_reader(
  session_hash text,
  organization_id text
) RETURNS TABLE(out_actor text, out_role text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_actor text;
  v_role text;
BEGIN
  SELECT l.out_actor, l.out_role INTO v_actor, v_role
    FROM openarc_durable.lock_action_human(session_hash, organization_id, false) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  out_actor := v_actor;
  out_role := v_role;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Full canonical lock sequence for a commerce-token-authorized exposure
-- subject. The caller presents ONLY the hash of the unique oacs_v1_ commerce
-- token (DB9 commerce_session_handoffs.token_hash, version 1, consumed). That
-- exact handoff row is the immutable lookup; the bound machine session and
-- credential are DB-derived from the resolved commerce session and are NEVER a
-- caller selection heuristic. Then lock ALL involved accounts sorted, the
-- organization, every involved membership sorted, the subject agent, the
-- credential, the exact machine session and the bound commerce session.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.lock_action_commerce(
  commerce_token_hash text,
  seller_organization_id text
)
RETURNS TABLE(
  out_organization_id text,
  out_subject_agent_id text,
  out_credential_id uuid,
  out_agent_session_id uuid,
  out_issuer_account_id text,
  out_machine_expires_at timestamptz,
  out_parent_human_account_id text,
  out_parent_human_session_hash text,
  out_commerce_session_id uuid,
  out_policy_id text,
  out_session_expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_org text;
  v_agent text;
  v_credential uuid;
  v_session uuid;
  v_expires timestamptz;
  v_issuer text;
  v_parent_account text;
  v_parent_hash text;
  v_commerce uuid;
  v_policy text;
  v_commerce_expires timestamptz;
  v_credential_expires timestamptz;
  v_credential_revoked timestamptz;
  v_machine record;
  v_role text;
  v_status text;
  v_now timestamptz;
  v_handoff record;
  v_commerce_revoked timestamptz;
  v_commerce_exchanged timestamptz;
  v_commerce_agent_session uuid;
  v_commerce_credential uuid;
  v_commerce_subject text;
  v_commerce_parent text;
  v_commerce_parent_hash text;
  v_commerce_policy text;
BEGIN
  IF NOT openarc_durable.is_canonical_hex64(commerce_token_hash) THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;
  -- Immutable lookup by the exact presented commerce token hash. A machine
  -- session hash cannot select a commerce session here.
  SELECT cs.organization_id, cs.subject_agent_id, cs.agent_session_id,
         cs.credential_id, cs.session_id, cs.parent_human_account_id,
         cs.parent_human_session_hash, cs.policy_id, cs.expires_at
    INTO v_org, v_agent, v_session, v_credential, v_commerce, v_parent_account,
         v_parent_hash, v_policy, v_commerce_expires
    FROM openarc_durable.commerce_session_handoffs h
    JOIN openarc_durable.commerce_sessions cs
      ON cs.organization_id = h.organization_id AND cs.session_id = h.session_id
   WHERE h.token_hash = commerce_token_hash AND h.token_hash_version = 1
     AND h.consumed_at IS NOT NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  IF v_agent IS NULL OR v_session IS NULL OR v_credential IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT c.issuer_account_id, c.expires_at, c.revoked_at
    INTO v_issuer, v_credential_expires, v_credential_revoked
    FROM openarc_durable.agent_credentials c
   WHERE c.organization_id = v_org AND c.credential_id = v_credential
     AND c.agent_id = v_agent;
  IF v_issuer IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- All involved accounts sorted (parent human + credential issuer).
  PERFORM 1 FROM openarc_auth.accounts a
   WHERE a.account_id IN (v_parent_account, v_issuer) AND a.status = 'active'
   ORDER BY a.account_id FOR UPDATE;
  IF (SELECT count(*) FROM openarc_auth.accounts a
       WHERE a.account_id IN (SELECT DISTINCT x FROM unnest(ARRAY[v_parent_account, v_issuer]) AS x)
         AND a.status = 'active')
     <> (SELECT count(DISTINCT x) FROM unnest(ARRAY[v_parent_account, v_issuer]) AS x) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- The parent human session is locked deterministically BEFORE either
  -- organization, so the combined org set below is the first organization lock.
  PERFORM 1 FROM openarc_auth.sessions hs
   WHERE hs.token_hash = v_parent_hash AND hs.account_id = v_parent_account
     AND hs.method <> 'recovery' FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- Both the buyer and the seller organization rows locked TOGETHER in sorted
  -- order. A reverse-owner pair can never deadlock on a partial org set.
  IF seller_organization_id IS NOT NULL
     AND NOT openarc_durable.is_canonical_org_id(seller_organization_id) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  PERFORM 1 FROM openarc_tenant.organizations o
   WHERE o.organization_id IN (v_org, COALESCE(seller_organization_id, v_org))
   ORDER BY o.organization_id FOR UPDATE;
  IF (SELECT count(*) FROM openarc_tenant.organizations o
       WHERE o.organization_id IN (
         SELECT DISTINCT x FROM unnest(ARRAY[v_org, COALESCE(seller_organization_id, v_org)]) AS x))
     <> (SELECT count(DISTINCT x) FROM unnest(
           ARRAY[v_org, COALESCE(seller_organization_id, v_org)]) AS x) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- All involved memberships sorted (parent human + issuer); both current.
  PERFORM 1 FROM openarc_tenant.memberships m
   WHERE m.organization_id = v_org
     AND m.account_id IN (v_parent_account, v_issuer)
   ORDER BY m.account_id FOR UPDATE;
  SELECT m.role, m.status INTO v_role, v_status
    FROM openarc_tenant.memberships m
   WHERE m.organization_id = v_org AND m.account_id = v_parent_account;
  IF v_role IS NULL OR v_status <> 'active' OR v_role NOT IN ('owner', 'operator') THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT m.role, m.status INTO v_role, v_status
    FROM openarc_tenant.memberships m
   WHERE m.organization_id = v_org AND m.account_id = v_issuer;
  IF v_role IS NULL OR v_status <> 'active' OR v_role NOT IN ('owner', 'operator') THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  PERFORM 1 FROM openarc_tenant.agents a
   WHERE a.organization_id = v_org AND a.agent_id = v_agent FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  IF (SELECT a.status FROM openarc_tenant.agents a
       WHERE a.organization_id = v_org AND a.agent_id = v_agent) <> 'active' THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  SELECT c.expires_at, c.revoked_at INTO v_credential_expires, v_credential_revoked
    FROM openarc_durable.agent_credentials c
   WHERE c.organization_id = v_org AND c.credential_id = v_credential FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT s.session_id, s.organization_id, s.agent_id, s.credential_id,
         s.expires_at, s.revoked_at
    INTO v_machine
    FROM openarc_durable.agent_sessions s
   WHERE s.session_id = v_session FOR UPDATE;
  IF NOT FOUND
     OR v_machine.organization_id IS DISTINCT FROM v_org
     OR v_machine.agent_id IS DISTINCT FROM v_agent
     OR v_machine.credential_id IS DISTINCT FROM v_credential THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT clock_timestamp() INTO v_now;
  IF v_credential_revoked IS NOT NULL OR NOT (v_credential_expires > v_now)
     OR v_machine.revoked_at IS NOT NULL OR NOT (v_machine.expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  out_organization_id := v_org;
  out_subject_agent_id := v_agent;
  out_credential_id := v_credential;
  out_agent_session_id := v_session;
  out_issuer_account_id := v_issuer;
  out_machine_expires_at := v_machine.expires_at;
  out_parent_human_account_id := v_parent_account;
  out_parent_human_session_hash := v_parent_hash;
  out_commerce_session_id := v_commerce;
  out_policy_id := v_policy;
  out_session_expires_at := NULL;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Current commerce-session-state lock/validation. Called on the active
-- authorization path AFTER policy/provider/listing/requirement and on the
-- replay/reader paths to assert the exact token's CURRENT revocation/exchange/
-- binding/expiry. It re-derives the immutable binding ids from the handoff and
-- denies a revoked/unexchanged/misbound/expired session. The parent human
-- session must be current (freshness is still not an agent requirement).
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.lock_action_commerce_state(
  commerce_token_hash text,
  organization_id text
) RETURNS timestamptz
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_handoff record;
  v_commerce record;
  v_now timestamptz;
BEGIN
  IF NOT openarc_durable.is_canonical_hex64(commerce_token_hash)
     OR NOT openarc_durable.is_canonical_org_id(organization_id) THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;
  SELECT h.session_id, h.token_hash, h.token_hash_version, h.consumed_at
    INTO v_handoff
    FROM openarc_durable.commerce_session_handoffs h
   WHERE h.organization_id = organization_id AND h.token_hash = commerce_token_hash
     AND h.token_hash_version = 1
   FOR UPDATE;
  IF NOT FOUND OR v_handoff.consumed_at IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT cs.* INTO v_commerce FROM openarc_durable.commerce_sessions cs
   WHERE cs.organization_id = organization_id AND cs.session_id = v_handoff.session_id
   FOR UPDATE;
  IF NOT FOUND
     OR v_commerce.revoked_at IS NOT NULL OR v_commerce.exchanged_at IS NULL
     OR v_commerce.agent_session_id IS NULL OR v_commerce.credential_id IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT clock_timestamp() INTO v_now;
  IF NOT (v_commerce.expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM openarc_auth.sessions hs
   WHERE hs.token_hash = v_commerce.parent_human_session_hash
     AND hs.account_id = v_commerce.parent_human_account_id
     AND hs.method <> 'recovery' AND hs.expires_at > v_now;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  RETURN v_commerce.expires_at;
END;
$$;

-- ---------------------------------------------------------------------------
-- Real current provider/listing/version/reviewed-origin binding lock. Requires
-- the exact published+active origin-approved version owned by an active
-- provider. This is independent of the allowlist dimension checks.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.lock_action_listing(
  org text,
  provider_input text,
  listing_input text,
  version_input text
) RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_provider_status text;
  v_active text;
  v_state record;
  v_review text;
BEGIN
  PERFORM 1 FROM openarc_tenant.providers p
   WHERE p.organization_id = org AND p.provider_id = provider_input FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT p.status INTO v_provider_status FROM openarc_tenant.providers p
   WHERE p.organization_id = org AND p.provider_id = provider_input;
  IF v_provider_status <> 'active' THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM openarc_tenant.listings l
   WHERE l.organization_id = org AND l.provider_id = provider_input
     AND l.listing_id = listing_input FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT l.active_version INTO v_active FROM openarc_tenant.listings l
   WHERE l.organization_id = org AND l.listing_id = listing_input;
  IF v_active IS NULL OR v_active <> version_input THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM openarc_tenant.listing_versions v
   WHERE v.organization_id = org AND v.listing_id = listing_input
     AND v.version = version_input AND v.provider_id = provider_input FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT st.status, st.origin_review_state, st.published_at INTO v_state
    FROM openarc_tenant.listing_version_states st
   WHERE st.organization_id = org AND st.listing_id = listing_input
     AND st.version = version_input FOR UPDATE;
  IF NOT FOUND OR v_state.status <> 'active' OR v_state.origin_review_state <> 'approved'
     OR v_state.published_at IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT r.decision INTO v_review
    FROM openarc_tenant.listing_origin_reviews r
   WHERE r.organization_id = org AND r.listing_id = listing_input
     AND r.version = version_input FOR UPDATE;
  IF v_review IS NULL OR v_review <> 'approved' THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  RETURN true;
END;
$$;

-- ---------------------------------------------------------------------------
-- Narrow immutable-binding resolution for the trusted API. Returns the ids a
-- authorize request digest needs WITHOUT locking or asserting authority. The
-- core revalidates every returned binding under the full canonical lock order.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.resolve_commerce_action_context(commerce_token_hash text)
RETURNS TABLE(
  out_organization_id text,
  out_subject_agent_id text,
  out_credential_id uuid,
  out_issuer_account_id text,
  out_parent_human_account_id text,
  out_commerce_session_id uuid,
  out_policy_id text,
  out_agent_session_id uuid
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF NOT openarc_durable.is_canonical_hex64(commerce_token_hash) THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;
  RETURN QUERY
    SELECT cs.organization_id, cs.subject_agent_id, cs.credential_id, c.issuer_account_id,
           cs.parent_human_account_id, cs.session_id, cs.policy_id, cs.agent_session_id
      FROM openarc_durable.commerce_session_handoffs h
      JOIN openarc_durable.commerce_sessions cs
        ON cs.organization_id = h.organization_id AND cs.session_id = h.session_id
      JOIN openarc_durable.agent_credentials c
        ON c.organization_id = cs.organization_id AND c.credential_id = cs.credential_id
       AND c.agent_id = cs.subject_agent_id
     WHERE h.token_hash = commerce_token_hash AND h.token_hash_version = 1
       AND h.consumed_at IS NOT NULL
       AND cs.agent_session_id IS NOT NULL AND cs.credential_id IS NOT NULL;
END;
$$;

-- ---------------------------------------------------------------------------
-- Exact bounded budget assessment over the stable exposure identity,
-- reproducing the frozen shared kernel. Returns the exposure totals and the
-- closed assessment. Reads at most 4096 committed-in-window and 4096
-- unresolved rows, detects limit+1 and fails closed rather than partial-sum.
-- Unresolved includes ALL held/claimed/unknown regardless of age.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.assess_action_budget(
  org text,
  subject text,
  network_input text,
  asset_input text,
  representation_input text,
  decimals_input smallint,
  window_seconds text,
  fee_limit text,
  per_action_limit text,
  rolling_limit text,
  approval_mode text,
  approval_threshold text,
  amount_input text,
  fee_input text
) RETURNS TABLE(
  out_debit text,
  out_committed text,
  out_unresolved text,
  out_total text,
  out_projected text,
  out_available text,
  out_deficit text,
  out_assessment text,
  out_reason text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_now timestamptz;
  v_cutoff timestamptz;
  v_committed_count integer;
  v_unresolved_count integer;
  v_committed numeric;
  v_unresolved numeric;
  v_debit numeric;
  v_total numeric;
  v_projected numeric;
  v_fee_limit numeric;
  v_per_action numeric;
  v_rolling numeric;
  v_available numeric;
  v_deficit numeric;
  v_assessment text;
  v_reason text;
BEGIN
  IF NOT openarc_durable.is_allowed_exposure_identity(network_input, asset_input, representation_input, decimals_input) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_positive_uint256(amount_input)
     OR NOT openarc_durable.is_canonical_uint256(fee_input) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF fee_limit IS NULL OR NOT openarc_durable.is_canonical_uint256(fee_limit) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF per_action_limit IS NOT NULL AND NOT openarc_durable.is_canonical_uint256(per_action_limit) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF rolling_limit IS NOT NULL AND NOT openarc_durable.is_canonical_uint256(rolling_limit) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF rolling_limit IS NULL THEN
    IF window_seconds IS NOT NULL THEN
      RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
    END IF;
  ELSE
    IF window_seconds IS NULL OR window_seconds !~ '^[1-9][0-9]{0,6}$'
       OR window_seconds::numeric < 1 OR window_seconds::numeric > 2592000 THEN
      RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
    END IF;
  END IF;
  IF approval_mode IS NULL
     OR NOT openarc_durable.is_valid_policy_approval(approval_mode, approval_threshold, false) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;

  SELECT clock_timestamp() INTO v_now;
  v_cutoff := v_now - make_interval(secs => COALESCE(window_seconds::integer, 0));

  SELECT count(*)::int, COALESCE(sum(e.amount_atomic::numeric), 0)
    INTO v_committed_count, v_committed
    FROM (SELECT b.amount_atomic
            FROM openarc_durable.budget_events b
           WHERE b.organization_id = org AND b.subject_agent_id = subject
             AND b.network_id = network_input AND b.asset = asset_input
             AND b.representation = representation_input AND b.decimals = decimals_input
             AND b.event_kind = 'committed' AND b.event_time <= v_now
             AND (rolling_limit IS NULL OR b.event_time > v_cutoff)
           LIMIT 4097) AS e;
  IF v_committed_count > 4096 THEN
    RAISE EXCEPTION 'commerce_exposure_unavailable' USING ERRCODE = 'P0D11';
  END IF;
  SELECT count(*)::int, COALESCE(sum(e.debit_atomic::numeric), 0)
    INTO v_unresolved_count, v_unresolved
    FROM (SELECT r.debit_atomic
            FROM openarc_durable.budget_reservations r
           WHERE r.organization_id = org AND r.subject_agent_id = subject
             AND r.network_id = network_input AND r.asset = asset_input
             AND r.representation = representation_input AND r.decimals = decimals_input
             AND r.status IN ('held', 'claimed', 'unknown')
           LIMIT 4097) AS e;
  IF v_unresolved_count > 4096 THEN
    RAISE EXCEPTION 'commerce_exposure_unavailable' USING ERRCODE = 'P0D11';
  END IF;

  v_debit := amount_input::numeric + fee_input::numeric;
  v_total := v_committed + v_unresolved;
  v_projected := v_total + v_debit;
  IF v_debit >= 10::numeric ^ 128 OR v_total >= 10::numeric ^ 128 OR v_projected >= 10::numeric ^ 128 THEN
    RAISE EXCEPTION 'commerce_arithmetic_overflow' USING ERRCODE = '22003';
  END IF;
  v_fee_limit := fee_limit::numeric;
  v_per_action := CASE WHEN per_action_limit IS NULL THEN NULL ELSE per_action_limit::numeric END;
  v_rolling := CASE WHEN rolling_limit IS NULL THEN NULL ELSE rolling_limit::numeric END;
  v_available := CASE WHEN v_rolling IS NULL THEN NULL
                      WHEN v_rolling > v_total THEN v_rolling - v_total ELSE 0 END;
  v_deficit := CASE WHEN v_rolling IS NULL THEN 0
                    WHEN v_total > v_rolling THEN v_total - v_rolling ELSE 0 END;

  IF fee_input::numeric > v_fee_limit THEN
    v_assessment := 'denied'; v_reason := 'fee_limit_exceeded';
  ELSIF v_per_action IS NOT NULL AND v_debit > v_per_action THEN
    v_assessment := 'denied'; v_reason := 'per_action_limit_exceeded';
  ELSIF v_deficit > 0 THEN
    v_assessment := 'denied'; v_reason := 'existing_exposure_deficit';
  ELSIF v_rolling IS NOT NULL AND v_projected > v_rolling THEN
    v_assessment := 'denied'; v_reason := 'rolling_limit_exceeded';
  ELSIF approval_mode = 'always'
     OR (approval_mode = 'above' AND approval_threshold IS NOT NULL
         AND v_debit > approval_threshold::numeric) THEN
    v_assessment := 'approval'; v_reason := 'approval_required';
  ELSE
    v_assessment := 'within'; v_reason := 'limits_satisfied';
  END IF;
  RETURN QUERY SELECT
    v_debit::text, v_committed::text, v_unresolved::text, v_total::text,
    v_projected::text,
    CASE WHEN v_available IS NULL THEN NULL ELSE v_available::text END,
    v_deficit::text, v_assessment, v_reason;
END;
$$;

-- ---------------------------------------------------------------------------
-- Bounded authorize core. `mode` is a CLOSED literal production|internal_fixture
-- and is never derived from a caller row, GUC, environment or SQL role. Both
-- modes run the identical real current parent/credential/session/policy/listing
-- /budget/requirement/idempotency/expiry checks. ONLY internal_fixture admits a
-- source_kind='internal_fixture' requirement row, and that admission bypasses
-- the unavailable payment lane. No other bypass exists.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.authorize_commerce_action_core(
  mode text,
  commerce_token_hash text,
  requirement_id_input text,
  action_id_input text,
  mutation_id uuid,
  key_hash text,
  request_digest text,
  session_context_digest text
) RETURNS TABLE(
  out_replayed boolean,
  out_action_id text,
  out_organization_id text,
  out_subject_agent_id text,
  out_commerce_session_id uuid,
  out_network_id text,
  out_asset text,
  out_representation text,
  out_decimals smallint,
  out_source_kind text,
  out_status text,
  out_amount_atomic text,
  out_fee_atomic text,
  out_debit_atomic text,
  out_policy_id text,
  out_policy_revision text,
  out_provider_id text,
  out_listing_id text,
  out_listing_version text,
  out_requirement_id text,
  out_requirement_digest text,
  out_reservation_id text,
  out_approval_id text,
  out_created_at timestamptz,
  out_updated_at timestamptz,
  out_expires_at timestamptz,
  out_committed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_chain record;
  v_requirement record;
  v_policy record;
  v_existing record;
  v_action record;
  v_parent_expires timestamptz;
  v_session_expires timestamptz;
  v_org text;
  v_subject text;
  v_network text := 'eip155:5042002';
  v_asset text := 'USDC';
  v_representation text := 'erc20';
  v_decimals smallint := 6;
  v_provider_allowed boolean;
  v_listing_allowed boolean;
  v_amount numeric;
  v_fee numeric;
  v_debit text;
  v_committed text;
  v_unresolved text;
  v_total text;
  v_projected text;
  v_available text;
  v_deficit text;
  v_assessment text;
  v_reason text;
  v_expires timestamptz;
  v_created_at timestamptz;
  v_updated_at timestamptz;
  v_committed_at timestamptz;
  v_status text;
  v_reservation_id text;
  v_approval_id text;
  v_action_uuid text;
  v_now timestamptz;
  v_replay record;
BEGIN
  IF mode IS DISTINCT FROM 'production' AND mode IS DISTINCT FROM 'internal_fixture' THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_canonical_hex64(commerce_token_hash)
     OR NOT openarc_durable.is_canonical_hex64(key_hash)
     OR NOT openarc_durable.is_canonical_hex64(request_digest)
     OR NOT openarc_durable.is_canonical_hex64(session_context_digest) THEN
    RAISE EXCEPTION 'commerce_metadata_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_canonical_requirement_id(requirement_id_input)
     OR NOT openarc_durable.is_canonical_action_id(action_id_input) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF mutation_id IS NULL OR NOT openarc_durable.is_canonical_uuid_v4(mutation_id::text) THEN
    RAISE EXCEPTION 'commerce_mutation_invalid' USING ERRCODE = '22023';
  END IF;

  -- Immutable requirement lookup FIRST (no lock, no authority). Its seller
  -- organization is needed to lock the buyer and seller organizations together
  -- in one sorted set. The requirement row is revalidated under the full order.
  SELECT * INTO v_requirement
    FROM openarc_durable.resolve_commerce_requirement(requirement_id_input) AS rq;
  IF v_requirement.out_requirement_id IS NULL THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  IF NOT openarc_durable.is_canonical_org_id(v_requirement.out_seller_organization_id) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- Current caller authentication (commerce token chain) BEFORE replay so an
  -- expired/revoked requester gets no replay disclosure. Both buyer and seller
  -- organizations are locked together inside the chain helper.
  SELECT * INTO v_chain
    FROM openarc_durable.lock_action_commerce(
      commerce_token_hash, v_requirement.out_seller_organization_id) AS c;
  IF v_chain.out_organization_id IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  v_org := v_chain.out_organization_id;
  v_subject := v_chain.out_subject_agent_id;
  IF v_requirement.out_organization_id IS DISTINCT FROM v_org THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- Same-key exact replay resolved BEFORE target actionability.
  SELECT r.* INTO v_existing
    FROM openarc_durable.idempotency_records r
   WHERE r.organization_id = v_org AND r.operation = 'control.commerce_action.authorize'
     AND r.key_hash = key_hash FOR UPDATE;
  IF FOUND THEN
    IF v_existing.request_digest = request_digest
       AND v_existing.mutation_id = mutation_id
       AND v_existing.actor_account_id = v_chain.out_parent_human_account_id
       AND v_existing.session_context_digest = session_context_digest
       AND v_existing.status = 'committed'
       AND v_existing.resource_type = 'commerce_action'
       AND v_existing.resource_id = action_id_input THEN
      SELECT a.* INTO v_action FROM openarc_durable.commerce_actions a
       WHERE a.organization_id = v_org AND a.action_id = action_id_input;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
      END IF;
      PERFORM 1 FROM openarc_durable.lock_action_commerce(
        commerce_token_hash, v_action.seller_organization_id) AS c
       WHERE c.out_organization_id = v_org;
      -- A revoked/unexchanged/expired current token must not disclose a
      -- committed receipt, even on an otherwise exact replay.
      PERFORM openarc_durable.lock_action_commerce_state(commerce_token_hash, v_org);
      out_replayed := true;
      out_action_id := v_action.action_id;
      out_organization_id := v_action.organization_id;
      out_subject_agent_id := v_action.subject_agent_id;
      out_commerce_session_id := v_action.commerce_session_id;
      out_network_id := v_action.network_id;
      out_asset := v_action.asset;
      out_representation := v_action.representation;
      out_decimals := v_action.decimals;
      out_source_kind := v_action.source_kind;
      out_status := v_action.status;
      out_amount_atomic := v_action.amount_atomic;
      out_fee_atomic := v_action.fee_atomic;
      out_debit_atomic := v_action.debit_atomic;
      out_policy_id := v_action.policy_id;
      out_policy_revision := v_action.policy_revision;
      out_provider_id := v_action.provider_id;
      out_listing_id := v_action.listing_id;
      out_listing_version := v_action.listing_version;
      out_requirement_id := v_action.requirement_id;
      out_requirement_digest := v_action.requirement_digest;
      out_reservation_id := v_action.reservation_id;
      out_approval_id := v_action.approval_id;
      out_created_at := v_action.created_at;
      out_updated_at := v_action.updated_at;
      out_expires_at := v_action.expires_at;
      out_committed_at := v_existing.committed_at;
      RETURN NEXT;
      RETURN;
    END IF;
    -- Do not disclose that a key is occupied while the presented commerce
    -- session is revoked/expired.  The exact replay path above already does
    -- this check before returning its receipt; conflict paths need the same
    -- current-state gate before exposing P0D01.
    PERFORM openarc_durable.lock_action_commerce_state(commerce_token_hash, v_org);
    RAISE EXCEPTION 'commerce_idempotency_conflict' USING ERRCODE = 'P0D01';
  END IF;
  PERFORM 1 FROM openarc_durable.idempotency_records r
   WHERE r.organization_id = v_org AND r.mutation_id = mutation_id FOR UPDATE;
  IF FOUND THEN
    PERFORM openarc_durable.lock_action_commerce_state(commerce_token_hash, v_org);
    RAISE EXCEPTION 'commerce_idempotency_conflict' USING ERRCODE = 'P0D01';
  END IF;

  -- Provenance admission for the already-resolved immutable requirement.
  IF mode = 'production' AND v_requirement.out_source_kind = 'internal_fixture' THEN
    RAISE EXCEPTION 'commerce_requirement_unavailable' USING ERRCODE = 'P0D10';
  END IF;

  -- Selected policy root/revision bound by the commerce session.
  SELECT r.current_revision, r.status, r.subject_agent_id INTO v_policy
    FROM openarc_tenant.budget_policy_roots r
   WHERE r.organization_id = v_org AND r.policy_id = v_chain.out_policy_id FOR UPDATE;
  IF NOT FOUND OR v_policy.status <> 'active' THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  IF v_policy.subject_agent_id IS DISTINCT FROM v_subject THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT v.* INTO v_policy
    FROM openarc_tenant.budget_policy_versions v
   WHERE v.organization_id = v_org AND v.policy_id = v_chain.out_policy_id
     AND v.revision = v_policy.current_revision FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  IF v_policy.subject_agent_id IS DISTINCT FROM v_subject
     OR v_policy.network_id IS DISTINCT FROM v_network
     OR v_policy.asset IS DISTINCT FROM v_asset
     OR v_policy.representation IS DISTINCT FROM v_representation
     OR v_policy.decimals IS DISTINCT FROM v_decimals THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT clock_timestamp() INTO v_now;
  IF v_policy.expires_at IS NOT NULL AND NOT (v_policy.expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_expired' USING ERRCODE = '23514';
  END IF;

  -- Policy scope exact interpretation: both allowlists empty deny; one nonempty
  -- restricts that dimension; both nonempty require intersection.
  IF cardinality(v_policy.allowed_provider_ids) = 0
     AND cardinality(v_policy.allowed_listing_ids) = 0 THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  v_provider_allowed := cardinality(v_policy.allowed_provider_ids) = 0
     OR v_requirement.out_provider_id = ANY (v_policy.allowed_provider_ids);
  v_listing_allowed := cardinality(v_policy.allowed_listing_ids) = 0
     OR v_requirement.out_listing_id = ANY (v_policy.allowed_listing_ids);
  IF NOT v_provider_allowed OR NOT v_listing_allowed THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- Real current published listing + approved exact origin + active provider.
  -- The listing/provider/version owners are the immutable SELLER organization,
  -- never the buyer organization.
  PERFORM openarc_durable.lock_action_listing(
    v_requirement.out_seller_organization_id, v_requirement.out_provider_id,
    v_requirement.out_listing_id,
    v_requirement.out_listing_version);

  -- Requirement row lock and exact binding revalidation.
  PERFORM 1 FROM openarc_durable.commerce_requirement_references r
   WHERE r.organization_id = v_org AND r.requirement_id = requirement_id_input FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  IF NOT (v_requirement.out_valid_until > v_now) THEN
    RAISE EXCEPTION 'commerce_expired' USING ERRCODE = '23514';
  END IF;

  -- Current commerce session state is locked/validated AFTER policy/listing/
  -- requirement, in the frozen order.
  v_session_expires := openarc_durable.lock_action_commerce_state(commerce_token_hash, v_org);
  SELECT hs.expires_at INTO v_parent_expires
    FROM openarc_auth.sessions hs
   WHERE hs.token_hash = v_chain.out_parent_human_session_hash
     AND hs.account_id = v_chain.out_parent_human_account_id
     AND hs.method <> 'recovery';
  IF v_parent_expires IS NULL OR NOT (v_parent_expires > v_now) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- Stable exposure row lock.
  INSERT INTO openarc_durable.commerce_exposure_locks (
    organization_id, subject_agent_id, network_id, asset, representation, decimals)
  VALUES (v_org, v_subject, v_network, v_asset, v_representation, v_decimals)
  ON CONFLICT DO NOTHING;
  PERFORM 1 FROM openarc_durable.commerce_exposure_locks e
   WHERE e.organization_id = v_org AND e.subject_agent_id = v_subject
     AND e.network_id = v_network AND e.asset = v_asset
     AND e.representation = v_representation AND e.decimals = v_decimals
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;

  v_amount := v_requirement.out_amount_atomic::numeric;
  v_fee := v_requirement.out_fee_atomic::numeric;
  v_debit := (v_amount + v_fee)::text;
  SELECT a.out_debit, a.out_committed, a.out_unresolved, a.out_total, a.out_projected,
         a.out_available, a.out_deficit, a.out_assessment, a.out_reason
    INTO v_debit, v_committed, v_unresolved, v_total, v_projected,
         v_available, v_deficit, v_assessment, v_reason
    FROM openarc_durable.assess_action_budget(
      v_org, v_subject, v_network, v_asset, v_representation, v_decimals,
      v_policy.rolling_window_seconds, v_policy.fee_limit, v_policy.per_action_limit,
      v_policy.rolling_limit, v_policy.approval_mode, v_policy.approval_threshold,
      v_requirement.out_amount_atomic, v_requirement.out_fee_atomic) AS a;
  IF v_assessment = 'denied' THEN
    RAISE EXCEPTION 'commerce_budget_denied' USING ERRCODE = 'P0D12';
  END IF;

  v_expires := LEAST(
    v_requirement.out_valid_until,
    v_session_expires,
    v_chain.out_machine_expires_at,
    COALESCE(v_policy.expires_at, 'infinity'::timestamptz),
    v_parent_expires
  );
  IF NOT (v_expires > v_now) THEN
    RAISE EXCEPTION 'commerce_expired' USING ERRCODE = '23514';
  END IF;

  v_action_uuid := substring(action_id_input FROM 16);
  v_approval_id := 'openarc:approval:' || v_action_uuid;
  v_created_at := v_now;
  v_updated_at := v_now;

  INSERT INTO openarc_durable.idempotency_records (
    organization_id, operation, key_hash, request_digest, digest_version,
    actor_account_id, session_context_digest, network, mutation_id, status
  ) VALUES (
    v_org, 'control.commerce_action.authorize', key_hash, request_digest,
    'control.commerce_action.authorize.v1', v_chain.out_parent_human_account_id,
    session_context_digest, v_network, mutation_id, 'pending'
  );

  IF v_assessment = 'approval' THEN
    v_status := 'pending_approval';
    v_reservation_id := NULL;
    INSERT INTO openarc_durable.commerce_actions (
      organization_id, action_id, subject_agent_id, parent_human_account_id,
      commerce_session_id, agent_session_id, credential_id, policy_id, policy_revision,
      seller_organization_id, provider_id, listing_id, listing_version,
      requirement_id, requirement_digest,
      network_id, asset, representation, decimals, amount_atomic, fee_atomic, debit_atomic,
      request_digest, source_kind, status, reservation_id, approval_id,
      created_at, updated_at, expires_at
    ) VALUES (
      v_org, action_id_input, v_subject, v_chain.out_parent_human_account_id,
      v_chain.out_commerce_session_id, v_chain.out_agent_session_id, v_chain.out_credential_id,
      v_chain.out_policy_id, v_policy.revision,
      v_requirement.out_seller_organization_id,
      v_requirement.out_provider_id, v_requirement.out_listing_id, v_requirement.out_listing_version,
      requirement_id_input, v_requirement.out_requirement_digest,
      v_network, v_asset, v_representation, v_decimals, v_requirement.out_amount_atomic,
      v_requirement.out_fee_atomic, (v_amount + v_fee)::text,
      request_digest, v_requirement.out_source_kind, v_status, NULL, v_approval_id,
      v_created_at, v_updated_at, v_expires
    );
    INSERT INTO openarc_durable.commerce_approvals (
      organization_id, approval_id, action_id, subject_agent_id, commerce_session_id,
      policy_id, policy_revision, requested_by, separate_approver, status, decided_by,
      source_kind, created_at, expires_at, decided_at
    ) VALUES (
      v_org, v_approval_id, action_id_input, v_subject, v_chain.out_commerce_session_id,
      v_chain.out_policy_id, v_policy.revision, v_chain.out_parent_human_account_id,
      v_policy.approval_separate_approver, 'pending', NULL,
      v_requirement.out_source_kind, v_created_at, v_expires, NULL
    );
  ELSE
    v_status := 'reserved_not_granted';
    v_reservation_id := 'openarc:reservation:' || v_action_uuid;
    INSERT INTO openarc_durable.commerce_actions (
      organization_id, action_id, subject_agent_id, parent_human_account_id,
      commerce_session_id, agent_session_id, credential_id, policy_id, policy_revision,
      seller_organization_id, provider_id, listing_id, listing_version,
      requirement_id, requirement_digest,
      network_id, asset, representation, decimals, amount_atomic, fee_atomic, debit_atomic,
      request_digest, source_kind, status, reservation_id, approval_id,
      created_at, updated_at, expires_at
    ) VALUES (
      v_org, action_id_input, v_subject, v_chain.out_parent_human_account_id,
      v_chain.out_commerce_session_id, v_chain.out_agent_session_id, v_chain.out_credential_id,
      v_chain.out_policy_id, v_policy.revision,
      v_requirement.out_seller_organization_id,
      v_requirement.out_provider_id, v_requirement.out_listing_id, v_requirement.out_listing_version,
      requirement_id_input, v_requirement.out_requirement_digest,
      v_network, v_asset, v_representation, v_decimals, v_requirement.out_amount_atomic,
      v_requirement.out_fee_atomic, (v_amount + v_fee)::text,
      request_digest, v_requirement.out_source_kind, v_status, v_reservation_id, NULL,
      v_created_at, v_updated_at, v_expires
    );
    INSERT INTO openarc_durable.budget_reservations (
      organization_id, reservation_id, action_id, subject_agent_id, network_id, asset,
      representation, decimals, debit_atomic, source_kind, status, created_at, claimed_at, resolved_at
    ) VALUES (
      v_org, v_reservation_id, action_id_input, v_subject, v_network, v_asset,
      v_representation, v_decimals, (v_amount + v_fee)::text, v_requirement.out_source_kind,
      'held', v_created_at, NULL, NULL
    );
  END IF;

  UPDATE openarc_durable.idempotency_records r
     SET status = 'committed', resource_type = 'commerce_action',
         resource_id = action_id_input, committed_at = clock_timestamp()
   WHERE r.organization_id = v_org AND r.operation = 'control.commerce_action.authorize'
     AND r.key_hash = key_hash
   RETURNING r.committed_at INTO v_committed_at;
  INSERT INTO openarc_durable.audit_events (
    organization_id, actor_account_id, operation, mutation_id, resource_type, resource_id, outcome
  ) VALUES (
    v_org, v_chain.out_parent_human_account_id, 'control.commerce_action.authorize', mutation_id,
    'commerce_action', action_id_input, 'committed'
  );
  INSERT INTO openarc_durable.outbox_events (
    organization_id, mutation_id, resource_type, resource_id, event_type, payload_version
  ) VALUES (
    v_org, mutation_id, 'commerce_action', action_id_input,
    'control.commerce_action.authorized', 1
  );

  -- Final recheck after every durable write and all lock waits.
  SELECT clock_timestamp() INTO v_now;
  IF NOT (v_expires > v_now) THEN
    RAISE EXCEPTION 'commerce_expired' USING ERRCODE = '23514';
  END IF;
  PERFORM 1 FROM openarc_tenant.budget_policy_roots r
   WHERE r.organization_id = v_org AND r.policy_id = v_chain.out_policy_id
     AND r.status = 'active' AND r.current_revision = v_policy.revision;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  -- Current SELLER provider/listing/version/origin authority AFTER every wait.
  PERFORM openarc_durable.lock_action_listing(
    v_requirement.out_seller_organization_id, v_requirement.out_provider_id,
    v_requirement.out_listing_id, v_requirement.out_listing_version);

  out_replayed := false;
  out_action_id := action_id_input;
  out_organization_id := v_org;
  out_subject_agent_id := v_subject;
  out_commerce_session_id := v_chain.out_commerce_session_id;
  out_network_id := v_network;
  out_asset := v_asset;
  out_representation := v_representation;
  out_decimals := v_decimals;
  out_source_kind := v_requirement.out_source_kind;
  out_status := v_status;
  out_amount_atomic := v_requirement.out_amount_atomic;
  out_fee_atomic := v_requirement.out_fee_atomic;
  out_debit_atomic := v_debit;
  out_policy_id := v_chain.out_policy_id;
  out_policy_revision := v_policy.revision;
  out_provider_id := v_requirement.out_provider_id;
  out_listing_id := v_requirement.out_listing_id;
  out_listing_version := v_requirement.out_listing_version;
  out_requirement_id := requirement_id_input;
  out_requirement_digest := v_requirement.out_requirement_digest;
  out_reservation_id := v_reservation_id;
  out_approval_id := CASE WHEN v_status = 'pending_approval' THEN v_approval_id ELSE NULL END;
  out_created_at := v_created_at;
  out_updated_at := v_updated_at;
  out_expires_at := v_expires;
  out_committed_at := v_committed_at;
  RETURN NEXT;
END;
$$;

-- Production tenant-runtime wrapper: passes the literal 'production' mode and
-- never caller data, a GUC, environment, callback or row field.
CREATE FUNCTION openarc_durable.authorize_commerce_action(
  commerce_token_hash text,
  requirement_id_input text,
  action_id_input text,
  mutation_id uuid,
  key_hash text,
  request_digest text,
  session_context_digest text
) RETURNS TABLE(
  out_replayed boolean,
  out_action_id text,
  out_organization_id text,
  out_subject_agent_id text,
  out_commerce_session_id uuid,
  out_network_id text,
  out_asset text,
  out_representation text,
  out_decimals smallint,
  out_source_kind text,
  out_status text,
  out_amount_atomic text,
  out_fee_atomic text,
  out_debit_atomic text,
  out_policy_id text,
  out_policy_revision text,
  out_provider_id text,
  out_listing_id text,
  out_listing_version text,
  out_requirement_id text,
  out_requirement_digest text,
  out_reservation_id text,
  out_approval_id text,
  out_created_at timestamptz,
  out_updated_at timestamptz,
  out_expires_at timestamptz,
  out_committed_at timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT * FROM openarc_durable.authorize_commerce_action_core(
    'production', commerce_token_hash, requirement_id_input, action_id_input,
    mutation_id, key_hash, request_digest, session_context_digest);
$$;

-- ---------------------------------------------------------------------------
-- Detect whether a reservation currently represents potential exposure and so
-- must never be released by cancel: claimed/unknown ALWAYS count indefinitely,
-- and a committed reservation is resolved. Only an unclaimed held reservation
-- is releasable.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.reservation_releasable(reservation_status text)
RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT reservation_status = 'held';
$$;

-- ---------------------------------------------------------------------------
-- Closed bound checks shared by decide/cancel time-sensitive revalidation.
-- These re-read current policy/listing/requirement state without asserting any
-- principal; authority is asserted by the caller preamble.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.assert_action_prereqs_current(
  org text,
  seller_org text,
  policy_input text,
  revision_input text,
  provider_input text,
  listing_input text,
  version_input text
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_status text;
  v_rev text;
  v_expires timestamptz;
  v_provider text;
  v_active text;
  v_st record;
  v_review text;
  v_now timestamptz;
BEGIN
  SELECT r.status, r.current_revision INTO v_status, v_rev
    FROM openarc_tenant.budget_policy_roots r
   WHERE r.organization_id = org AND r.policy_id = policy_input;
  IF v_status IS NULL OR v_status <> 'active' OR v_rev <> revision_input THEN
    RAISE EXCEPTION 'commerce_stale_terms' USING ERRCODE = '40001';
  END IF;
  SELECT v.expires_at INTO v_expires
    FROM openarc_tenant.budget_policy_versions v
   WHERE v.organization_id = org AND v.policy_id = policy_input AND v.revision = revision_input;
  SELECT clock_timestamp() INTO v_now;
  IF v_expires IS NOT NULL AND NOT (v_expires > v_now) THEN
    RAISE EXCEPTION 'commerce_expired' USING ERRCODE = '23514';
  END IF;
  SELECT p.status INTO v_provider FROM openarc_tenant.providers p
   WHERE p.organization_id = seller_org AND p.provider_id = provider_input;
  IF v_provider IS NULL OR v_provider <> 'active' THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT l.active_version INTO v_active FROM openarc_tenant.listings l
   WHERE l.organization_id = seller_org AND l.listing_id = listing_input
     AND l.provider_id = provider_input;
  IF v_active IS NULL OR v_active IS DISTINCT FROM version_input THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT st.status, st.origin_review_state, st.published_at INTO v_st
    FROM openarc_tenant.listing_version_states st
   WHERE st.organization_id = seller_org AND st.listing_id = listing_input AND st.version = version_input;
  IF NOT FOUND OR v_st.status <> 'active' OR v_st.origin_review_state <> 'approved'
     OR v_st.published_at IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT r.decision INTO v_review FROM openarc_tenant.listing_origin_reviews r
   WHERE r.organization_id = seller_org AND r.listing_id = listing_input AND r.version = version_input;
  IF v_review IS NULL OR v_review <> 'approved' THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- Full canonical decision chain lock. Resolves the immutable action bindings
-- WITHOUT authority, then locks every involved account sorted, the
-- organization, every involved membership sorted, the subject agent, the
-- credential, the exact machine session, the bound commerce session (CURRENT
-- revoked/exchange/binding/expiry), the selected policy root/revision, the
-- published listing/version/origin, the requirement and the stable exposure
-- row. The action/approval rows are locked by the caller AFTER this returns.
-- The original human session/account, revoked machine credential/session and
-- commerce revocation all deny a decision.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.lock_action_decision_chain(
  organization_id text,
  action_id_input text,
  decider_account_id text
) RETURNS TABLE(
  out_commerce_session_id uuid,
  out_parent_human_session_hash text,
  out_parent_human_account_id text,
  out_policy_id text,
  out_policy_revision text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_action record;
  v_credential_issuer text;
  v_credential_expires timestamptz;
  v_credential_revoked timestamptz;
  v_machine record;
  v_commerce record;
  v_parent_hash text;
  v_parent_account text;
  v_parent_actor text;
  v_parent_method text;
  v_role text;
  v_status text;
  v_policy record;
  v_requirement record;
  v_now timestamptz;
BEGIN
  IF NOT openarc_durable.is_canonical_org_id(organization_id)
     OR NOT openarc_durable.is_canonical_action_id(action_id_input) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  SELECT a.* INTO v_action FROM openarc_durable.commerce_actions a
   WHERE a.organization_id = organization_id AND a.action_id = action_id_input;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT c.issuer_account_id INTO v_credential_issuer
    FROM openarc_durable.agent_credentials c
   WHERE c.organization_id = organization_id AND c.credential_id = v_action.credential_id;
  IF v_credential_issuer IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT cs.parent_human_session_hash, cs.parent_human_account_id
    INTO v_parent_hash, v_parent_account
    FROM openarc_durable.commerce_sessions cs
   WHERE cs.organization_id = organization_id AND cs.session_id = v_action.commerce_session_id;
  IF v_parent_hash IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- All involved accounts sorted (decider already held by lock_action_human).
  PERFORM 1 FROM openarc_auth.accounts a
   WHERE a.account_id IN (v_action.parent_human_account_id, v_credential_issuer)
     AND a.status = 'active'
   ORDER BY a.account_id FOR UPDATE;
  IF (SELECT count(*) FROM openarc_auth.accounts a
       WHERE a.account_id IN (SELECT DISTINCT x FROM unnest(ARRAY[v_action.parent_human_account_id, v_credential_issuer]) AS x)
         AND a.status = 'active')
     <> (SELECT count(DISTINCT x) FROM unnest(ARRAY[v_action.parent_human_account_id, v_credential_issuer]) AS x) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM openarc_tenant.organizations o
   WHERE o.organization_id = organization_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM openarc_tenant.memberships m
   WHERE m.organization_id = organization_id
     AND m.account_id IN (v_action.parent_human_account_id, v_credential_issuer)
   ORDER BY m.account_id FOR UPDATE;
  SELECT m.role, m.status INTO v_role, v_status
    FROM openarc_tenant.memberships m
   WHERE m.organization_id = organization_id AND m.account_id = v_action.parent_human_account_id;
  IF v_role IS NULL OR v_status <> 'active' OR v_role NOT IN ('owner', 'operator') THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT m.role, m.status INTO v_role, v_status
    FROM openarc_tenant.memberships m
   WHERE m.organization_id = organization_id AND m.account_id = v_credential_issuer;
  IF v_role IS NULL OR v_status <> 'active' OR v_role NOT IN ('owner', 'operator') THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM openarc_tenant.agents a
   WHERE a.organization_id = organization_id AND a.agent_id = v_action.subject_agent_id FOR UPDATE;
  IF NOT FOUND OR (SELECT a.status FROM openarc_tenant.agents a
                    WHERE a.organization_id = organization_id AND a.agent_id = v_action.subject_agent_id) <> 'active' THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT c.expires_at, c.revoked_at INTO v_credential_expires, v_credential_revoked
    FROM openarc_durable.agent_credentials c
   WHERE c.organization_id = organization_id AND c.credential_id = v_action.credential_id
     AND c.agent_id = v_action.subject_agent_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT s.session_id, s.organization_id, s.agent_id, s.credential_id, s.expires_at, s.revoked_at
    INTO v_machine FROM openarc_durable.agent_sessions s
   WHERE s.session_id = v_action.agent_session_id FOR UPDATE;
  IF NOT FOUND
     OR v_machine.organization_id IS DISTINCT FROM organization_id
     OR v_machine.agent_id IS DISTINCT FROM v_action.subject_agent_id
     OR v_machine.credential_id IS DISTINCT FROM v_action.credential_id THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT cs.* INTO v_commerce FROM openarc_durable.commerce_sessions cs
   WHERE cs.organization_id = organization_id AND cs.session_id = v_action.commerce_session_id FOR UPDATE;
  IF NOT FOUND
     OR v_commerce.revoked_at IS NOT NULL
     OR v_commerce.exchanged_at IS NULL
     OR v_commerce.agent_session_id IS DISTINCT FROM v_action.agent_session_id
     OR v_commerce.credential_id IS DISTINCT FROM v_action.credential_id
     OR v_commerce.subject_agent_id IS DISTINCT FROM v_action.subject_agent_id
     OR v_commerce.policy_id IS DISTINCT FROM v_action.policy_id THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT l.account_id, l.method INTO v_parent_actor, v_parent_method
    FROM openarc_tenant.lock_auth_session(v_commerce.parent_human_session_hash, NULL) AS l;
  IF v_parent_actor IS NULL OR v_parent_actor <> v_commerce.parent_human_account_id
     OR v_parent_method = 'recovery' THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT r.current_revision, r.status, r.subject_agent_id INTO v_policy
    FROM openarc_tenant.budget_policy_roots r
   WHERE r.organization_id = organization_id AND r.policy_id = v_action.policy_id FOR UPDATE;
  IF NOT FOUND OR v_policy.status <> 'active' OR v_policy.current_revision <> v_action.policy_revision
     OR v_policy.subject_agent_id <> v_action.subject_agent_id THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM openarc_tenant.budget_policy_versions v
   WHERE v.organization_id = organization_id AND v.policy_id = v_action.policy_id
     AND v.revision = v_action.policy_revision FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  PERFORM openarc_durable.lock_action_listing(
    v_action.seller_organization_id, v_action.provider_id, v_action.listing_id,
    v_action.listing_version);
  PERFORM 1 FROM openarc_durable.commerce_requirement_references r
   WHERE r.organization_id = organization_id AND r.requirement_id = v_action.requirement_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT rq.* INTO v_requirement
    FROM openarc_durable.resolve_commerce_requirement(v_action.requirement_id) AS rq;
  SELECT clock_timestamp() INTO v_now;
  IF v_requirement.out_requirement_id IS NULL OR NOT (v_requirement.out_valid_until > v_now) THEN
    RAISE EXCEPTION 'commerce_expired' USING ERRCODE = '23514';
  END IF;
  IF v_credential_revoked IS NOT NULL OR NOT (v_credential_expires > v_now)
     OR v_machine.revoked_at IS NOT NULL OR NOT (v_machine.expires_at > v_now)
     OR NOT (v_commerce.expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  INSERT INTO openarc_durable.commerce_exposure_locks (
    organization_id, subject_agent_id, network_id, asset, representation, decimals)
  VALUES (organization_id, v_action.subject_agent_id, v_action.network_id, v_action.asset,
          v_action.representation, v_action.decimals)
  ON CONFLICT DO NOTHING;
  PERFORM 1 FROM openarc_durable.commerce_exposure_locks e
   WHERE e.organization_id = organization_id AND e.subject_agent_id = v_action.subject_agent_id
     AND e.network_id = v_action.network_id AND e.asset = v_action.asset
     AND e.representation = v_action.representation AND e.decimals = v_action.decimals FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;

  out_commerce_session_id := v_action.commerce_session_id;
  out_parent_human_session_hash := v_commerce.parent_human_session_hash;
  out_parent_human_account_id := v_commerce.parent_human_account_id;
  out_policy_id := v_action.policy_id;
  out_policy_revision := v_action.policy_revision;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Human decide core. mode is the same closed provenance gate: a production
-- decision can never approve/reserve an internal_fixture action. Current fresh
-- owner/operator (never viewer/provider) exact org/action, separate approver.
-- Approve redoes the budget check and creates the held reservation atomically;
-- reject marks approval/action rejected with NO reservation.
-- ---------------------------------------------------------------------------
-- ---------------------------------------------------------------------------
-- Complete decision preamble with the corrected global lock order. It resolves
-- the immutable action binding ids FIRST (no authority), then locks ALL
-- involved accounts (decider, original parent human, commerce parent, issuer)
-- together in sorted order, then both human sessions deterministically, the
-- organization, all memberships sorted, the subject agent, credential, machine
-- session, commerce session (current revocation/exchange/binding/expiry), the
-- selected policy root/revision, the published listing/version/origin, the
-- requirement and the stable exposure row. No partial lock helper runs before
-- the complete account set.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.lock_action_decide_preamble(
  human_session_hash text,
  organization_id text,
  action_id_input text
) RETURNS TABLE(out_actor text, out_role text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_action record;
  v_decider text;
  v_decider_method text;
  v_decider_created timestamptz;
  v_decider_expires timestamptz;
  v_parent_hash text;
  v_parent_account text;
  v_issuer text;
  v_involved text[];
  v_role text;
  v_status text;
  v_credential_expires timestamptz;
  v_credential_revoked timestamptz;
  v_machine record;
  v_commerce record;
  v_parent_actor text;
  v_parent_method text;
  v_policy record;
  v_requirement record;
  v_now timestamptz;
BEGIN
  IF NOT openarc_durable.is_canonical_hex64(human_session_hash) THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;
  IF NOT openarc_durable.is_canonical_org_id(organization_id)
     OR NOT openarc_durable.is_canonical_action_id(action_id_input) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;

  -- Immutable resolution, no locks and no authority.
  SELECT s.account_id, s.method, s.created_at, s.expires_at
    INTO v_decider, v_decider_method, v_decider_created, v_decider_expires
    FROM openarc_auth.sessions s WHERE s.token_hash = human_session_hash;
  IF v_decider IS NULL OR v_decider_method = 'recovery' THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;
  SELECT a.* INTO v_action FROM openarc_durable.commerce_actions a
   WHERE a.organization_id = organization_id AND a.action_id = action_id_input;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT cs.parent_human_session_hash, cs.parent_human_account_id
    INTO v_parent_hash, v_parent_account
    FROM openarc_durable.commerce_sessions cs
   WHERE cs.organization_id = organization_id AND cs.session_id = v_action.commerce_session_id;
  SELECT c.issuer_account_id INTO v_issuer
    FROM openarc_durable.agent_credentials c
   WHERE c.organization_id = organization_id AND c.credential_id = v_action.credential_id;
  IF v_parent_hash IS NULL OR v_parent_account IS NULL OR v_issuer IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- Lock ALL involved accounts TOGETHER in sorted order. Account ROWS are
  -- locked regardless of status so a later replay can recover the original
  -- receipt even after the original parent/issuer is suspended; only the
  -- CURRENT decider account must be active here.
  v_involved := ARRAY(
    SELECT DISTINCT x
      FROM unnest(ARRAY[v_decider, v_action.parent_human_account_id, v_parent_account, v_issuer]) AS x
     ORDER BY x
  );
  PERFORM 1 FROM openarc_auth.accounts a
   WHERE a.account_id = ANY (v_involved)
   ORDER BY a.account_id FOR UPDATE;
  IF (SELECT count(*) FROM openarc_auth.accounts a
       WHERE a.account_id = ANY (v_involved)) <> cardinality(v_involved) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  IF (SELECT a.status FROM openarc_auth.accounts a WHERE a.account_id = v_decider) <> 'active' THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- Both human sessions deterministically (decider + original parent). The
  -- parent session may legitimately be absent on replay (logout deletes it):
  -- its continued authority is asserted only for a NEW decision.
  PERFORM 1 FROM openarc_auth.sessions s
   WHERE s.token_hash IN (human_session_hash, v_parent_hash)
   ORDER BY s.token_hash FOR UPDATE;
  SELECT s.method, s.created_at, s.expires_at INTO v_decider_method, v_decider_created, v_decider_expires
    FROM openarc_auth.sessions s
   WHERE s.token_hash = human_session_hash AND s.account_id = v_decider;
  IF NOT FOUND OR v_decider_method = 'recovery' THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;
  SELECT clock_timestamp() INTO v_now;
  IF NOT (v_decider_expires > v_now) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;
  IF NOT (v_decider_created > v_now - interval '5 minutes') THEN
    RAISE EXCEPTION 'commerce_proof_stale' USING ERRCODE = '28000';
  END IF;

  -- Buyer and seller organization rows locked TOGETHER in sorted order, so a
  -- reverse decision pair can never deadlock on a partial org set.
  PERFORM 1 FROM openarc_tenant.organizations o
   WHERE o.organization_id IN (organization_id, v_action.seller_organization_id)
   ORDER BY o.organization_id FOR UPDATE;
  IF (SELECT count(*) FROM openarc_tenant.organizations o
       WHERE o.organization_id IN (
         SELECT DISTINCT x FROM unnest(ARRAY[organization_id, v_action.seller_organization_id]) AS x))
     <> (SELECT count(DISTINCT x) FROM unnest(
           ARRAY[organization_id, v_action.seller_organization_id]) AS x) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM openarc_tenant.memberships m
   WHERE m.organization_id = organization_id AND m.account_id = ANY (v_involved)
   ORDER BY m.account_id FOR UPDATE;
  SELECT m.role, m.status INTO v_role, v_status
    FROM openarc_tenant.memberships m
   WHERE m.organization_id = organization_id AND m.account_id = v_decider;
  IF v_role IS NULL OR v_status <> 'active' OR v_role NOT IN ('owner', 'operator') THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM openarc_tenant.agents a
   WHERE a.organization_id = organization_id AND a.agent_id = v_action.subject_agent_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM openarc_durable.agent_credentials c
   WHERE c.organization_id = organization_id AND c.credential_id = v_action.credential_id
     AND c.agent_id = v_action.subject_agent_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  PERFORM 1 FROM openarc_durable.agent_sessions s
   WHERE s.session_id = v_action.agent_session_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  out_actor := v_decider;
  out_role := v_role;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Full target-actionability assertion for a NEW decision. Runs AFTER the exact
-- idempotency replay test, so a current fresh decider can still recover an
-- original committed receipt even when the original parent/policy/credential
-- has since lapsed. The order is the frozen canonical order: parent human
-- session -> parent/issuer memberships -> subject agent -> credential ->
-- machine session -> selected policy -> seller provider/listing/version/origin
-- -> requirement -> commerce session -> stable exposure.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.assert_action_decide_current(
  organization_id text,
  action_id_input text
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_action record;
  v_parent_hash text;
  v_parent_account text;
  v_issuer text;
  v_role text;
  v_status text;
  v_credential_expires timestamptz;
  v_credential_revoked timestamptz;
  v_machine record;
  v_commerce record;
  v_parent_actor text;
  v_parent_method text;
  v_policy record;
  v_requirement record;
  v_now timestamptz;
BEGIN
  SELECT a.* INTO v_action FROM openarc_durable.commerce_actions a
   WHERE a.organization_id = organization_id AND a.action_id = action_id_input;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT cs.parent_human_session_hash, cs.parent_human_account_id
    INTO v_parent_hash, v_parent_account
    FROM openarc_durable.commerce_sessions cs
   WHERE cs.organization_id = organization_id AND cs.session_id = v_action.commerce_session_id;
  SELECT c.issuer_account_id INTO v_issuer
    FROM openarc_durable.agent_credentials c
   WHERE c.organization_id = organization_id AND c.credential_id = v_action.credential_id;
  IF v_parent_hash IS NULL OR v_parent_account IS NULL OR v_issuer IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- Original parent human session (already-sorted lock set) and its membership.
  SELECT l.account_id, l.method INTO v_parent_actor, v_parent_method
    FROM openarc_tenant.lock_auth_session(v_parent_hash, NULL) AS l;
  IF v_parent_actor IS NULL OR v_parent_actor <> v_parent_account OR v_parent_method = 'recovery' THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT m.role, m.status INTO v_role, v_status
    FROM openarc_tenant.memberships m
   WHERE m.organization_id = organization_id AND m.account_id = v_parent_account;
  IF v_role IS NULL OR v_status <> 'active' OR v_role NOT IN ('owner', 'operator') THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT m.role, m.status INTO v_role, v_status
    FROM openarc_tenant.memberships m
   WHERE m.organization_id = organization_id AND m.account_id = v_issuer;
  IF v_role IS NULL OR v_status <> 'active' OR v_role NOT IN ('owner', 'operator') THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  IF (SELECT a.status FROM openarc_tenant.agents a
       WHERE a.organization_id = organization_id AND a.agent_id = v_action.subject_agent_id) <> 'active' THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT c.expires_at, c.revoked_at INTO v_credential_expires, v_credential_revoked
    FROM openarc_durable.agent_credentials c
   WHERE c.organization_id = organization_id AND c.credential_id = v_action.credential_id
     AND c.agent_id = v_action.subject_agent_id;
  SELECT s.session_id, s.organization_id, s.agent_id, s.credential_id, s.expires_at, s.revoked_at
    INTO v_machine FROM openarc_durable.agent_sessions s
   WHERE s.session_id = v_action.agent_session_id;
  IF NOT FOUND
     OR v_machine.organization_id IS DISTINCT FROM organization_id
     OR v_machine.agent_id IS DISTINCT FROM v_action.subject_agent_id
     OR v_machine.credential_id IS DISTINCT FROM v_action.credential_id THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- Selected policy root/revision must still be the pinned current revision.
  SELECT r.current_revision, r.status, r.subject_agent_id INTO v_policy
    FROM openarc_tenant.budget_policy_roots r
   WHERE r.organization_id = organization_id AND r.policy_id = v_action.policy_id FOR UPDATE;
  IF NOT FOUND OR v_policy.status <> 'active' OR v_policy.current_revision <> v_action.policy_revision
     OR v_policy.subject_agent_id <> v_action.subject_agent_id THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM openarc_tenant.budget_policy_versions v
   WHERE v.organization_id = organization_id AND v.policy_id = v_action.policy_id
     AND v.revision = v_action.policy_revision FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- Seller provider/listing/version/origin, current.
  PERFORM openarc_durable.lock_action_listing(
    v_action.seller_organization_id, v_action.provider_id, v_action.listing_id,
    v_action.listing_version);

  -- Immutable requirement binding and current validity.
  PERFORM 1 FROM openarc_durable.commerce_requirement_references r
   WHERE r.organization_id = organization_id AND r.requirement_id = v_action.requirement_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT rq.* INTO v_requirement
    FROM openarc_durable.resolve_commerce_requirement(v_action.requirement_id) AS rq;

  -- Commerce session current-state lock comes AFTER policy/listing/requirement.
  SELECT cs.* INTO v_commerce FROM openarc_durable.commerce_sessions cs
   WHERE cs.organization_id = organization_id AND cs.session_id = v_action.commerce_session_id FOR UPDATE;
  IF NOT FOUND
     OR v_commerce.revoked_at IS NOT NULL OR v_commerce.exchanged_at IS NULL
     OR v_commerce.agent_session_id IS DISTINCT FROM v_action.agent_session_id
     OR v_commerce.credential_id IS DISTINCT FROM v_action.credential_id
     OR v_commerce.subject_agent_id IS DISTINCT FROM v_action.subject_agent_id
     OR v_commerce.policy_id IS DISTINCT FROM v_action.policy_id
     OR v_commerce.parent_human_account_id IS DISTINCT FROM v_parent_account THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT clock_timestamp() INTO v_now;
  IF v_requirement.out_requirement_id IS NULL
     OR v_requirement.out_seller_organization_id IS DISTINCT FROM v_action.seller_organization_id
     OR v_requirement.out_provider_id IS DISTINCT FROM v_action.provider_id
     OR v_requirement.out_listing_id IS DISTINCT FROM v_action.listing_id
     OR v_requirement.out_listing_version IS DISTINCT FROM v_action.listing_version
     OR NOT (v_requirement.out_valid_until > v_now) THEN
    RAISE EXCEPTION 'commerce_expired' USING ERRCODE = '23514';
  END IF;
  IF v_credential_revoked IS NOT NULL OR NOT (v_credential_expires > v_now)
     OR v_machine.revoked_at IS NOT NULL OR NOT (v_machine.expires_at > v_now)
     OR NOT (v_commerce.expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- Stable exposure row lock, last before the action/approval rows.
  INSERT INTO openarc_durable.commerce_exposure_locks (
    organization_id, subject_agent_id, network_id, asset, representation, decimals)
  VALUES (organization_id, v_action.subject_agent_id, v_action.network_id, v_action.asset,
          v_action.representation, v_action.decimals)
  ON CONFLICT DO NOTHING;
  PERFORM 1 FROM openarc_durable.commerce_exposure_locks e
   WHERE e.organization_id = organization_id AND e.subject_agent_id = v_action.subject_agent_id
     AND e.network_id = v_action.network_id AND e.asset = v_action.asset
     AND e.representation = v_action.representation AND e.decimals = v_action.decimals FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
END;
$$;

CREATE FUNCTION openarc_durable.decide_commerce_action_core(
  mode text,
  human_session_hash text,
  organization_id text,
  action_id_input text,
  decision text,
  mutation_id uuid,
  key_hash text,
  request_digest text,
  session_context_digest text
) RETURNS TABLE(
  out_replayed boolean,
  out_action_id text,
  out_organization_id text,
  out_subject_agent_id text,
  out_commerce_session_id uuid,
  out_network_id text,
  out_asset text,
  out_representation text,
  out_decimals smallint,
  out_source_kind text,
  out_amount_atomic text,
  out_fee_atomic text,
  out_debit_atomic text,
  out_policy_id text,
  out_policy_revision text,
  out_provider_id text,
  out_listing_id text,
  out_listing_version text,
  out_requirement_id text,
  out_requirement_digest text,
  out_status text,
  out_approval_id text,
  out_reservation_id text,
  out_decided_by text,
  out_created_at timestamptz,
  out_updated_at timestamptz,
  out_expires_at timestamptz,
  out_committed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_actor text;
  v_actor_role text;
  v_action record;
  v_approval record;
  v_existing record;
  v_requirement record;
  v_policy record;
  v_amount numeric;
  v_fee numeric;
  v_debit text;
  v_assessment text;
  v_expires timestamptz;
  v_now timestamptz;
  v_committed_at timestamptz;
  v_operation text;
  v_event text;
  v_committed text;
  v_unresolved text;
  v_total text;
  v_projected text;
  v_available text;
  v_deficit text;
  v_reason text;
  v_parent_role text;
  v_parent_status text;
  v_reservation_id text;
  v_recheck_actor text;
BEGIN
  IF mode IS DISTINCT FROM 'production' AND mode IS DISTINCT FROM 'internal_fixture' THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF decision IS DISTINCT FROM 'approve' AND decision IS DISTINCT FROM 'reject' THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_canonical_hex64(human_session_hash)
     OR NOT openarc_durable.is_canonical_hex64(key_hash)
     OR NOT openarc_durable.is_canonical_hex64(request_digest)
     OR NOT openarc_durable.is_canonical_hex64(session_context_digest) THEN
    RAISE EXCEPTION 'commerce_metadata_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_canonical_action_id(action_id_input) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF mutation_id IS NULL OR NOT openarc_durable.is_canonical_uuid_v4(mutation_id::text) THEN
    RAISE EXCEPTION 'commerce_mutation_invalid' USING ERRCODE = '22023';
  END IF;
  IF decision = 'approve' THEN
    v_operation := 'control.commerce_action.approve'; v_event := 'control.commerce_action.approved';
  ELSE
    v_operation := 'control.commerce_action.reject'; v_event := 'control.commerce_action.rejected';
  END IF;

  SELECT l.out_actor, l.out_role INTO v_actor, v_actor_role
    FROM openarc_durable.lock_action_decide_preamble(
      human_session_hash, organization_id, action_id_input) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  SELECT r.* INTO v_existing FROM openarc_durable.idempotency_records r
   WHERE r.organization_id = organization_id AND r.operation = v_operation
     AND r.key_hash = key_hash FOR UPDATE;
  IF FOUND THEN
    IF v_existing.request_digest = request_digest
       AND v_existing.mutation_id = mutation_id
       AND v_existing.actor_account_id = v_actor
       AND v_existing.session_context_digest = session_context_digest
       AND v_existing.status = 'committed'
       AND v_existing.resource_type = 'commerce_action'
       AND v_existing.resource_id = action_id_input THEN
      SELECT a.* INTO v_action FROM openarc_durable.commerce_actions a
       WHERE a.organization_id = organization_id AND a.action_id = action_id_input;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
      END IF;
      -- Fresh current caller proof after the idempotency wait, even on replay.
      SELECT l.out_actor INTO v_recheck_actor
        FROM openarc_durable.lock_action_human(human_session_hash, organization_id, true) AS l;
      IF v_recheck_actor IS NULL OR v_recheck_actor <> v_actor THEN
        RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
      END IF;
      out_replayed := true;
      out_action_id := v_action.action_id;
      out_organization_id := v_action.organization_id;
      out_subject_agent_id := v_action.subject_agent_id;
      out_commerce_session_id := v_action.commerce_session_id;
      out_network_id := v_action.network_id;
      out_asset := v_action.asset;
      out_representation := v_action.representation;
      out_decimals := v_action.decimals;
      out_source_kind := v_action.source_kind;
      out_amount_atomic := v_action.amount_atomic;
      out_fee_atomic := v_action.fee_atomic;
      out_debit_atomic := v_action.debit_atomic;
      out_policy_id := v_action.policy_id;
      out_policy_revision := v_action.policy_revision;
      out_provider_id := v_action.provider_id;
      out_listing_id := v_action.listing_id;
      out_listing_version := v_action.listing_version;
      out_requirement_id := v_action.requirement_id;
      out_requirement_digest := v_action.requirement_digest;
      out_status := v_action.status;
      out_approval_id := v_action.approval_id;
      out_reservation_id := v_action.reservation_id;
      out_decided_by := v_actor;
      out_created_at := v_action.created_at;
      out_updated_at := v_action.updated_at;
      out_expires_at := v_action.expires_at;
      out_committed_at := v_existing.committed_at;
      RETURN NEXT; RETURN;
    END IF;
    RAISE EXCEPTION 'commerce_idempotency_conflict' USING ERRCODE = 'P0D01';
  END IF;
  PERFORM 1 FROM openarc_durable.idempotency_records r
   WHERE r.organization_id = organization_id AND r.mutation_id = mutation_id FOR UPDATE;
  IF FOUND THEN
    RAISE EXCEPTION 'commerce_idempotency_conflict' USING ERRCODE = 'P0D01';
  END IF;

  -- The exact replay test above ran BEFORE any target actionability. Only now,
  -- for a genuinely NEW decision, read the immutable action/approval and run
  -- the full current target chain in the frozen order (policy/listing/
  -- requirement before commerce, then exposure), then re-lock the action and
  -- approval rows and re-validate pending/expiry after every wait.
  SELECT a.* INTO v_action FROM openarc_durable.commerce_actions a
   WHERE a.organization_id = organization_id AND a.action_id = action_id_input;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  IF mode = 'production' AND v_action.source_kind = 'internal_fixture' THEN
    RAISE EXCEPTION 'commerce_requirement_unavailable' USING ERRCODE = 'P0D10';
  END IF;
  SELECT ap.* INTO v_approval FROM openarc_durable.commerce_approvals ap
   WHERE ap.organization_id = organization_id AND ap.action_id = action_id_input;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  IF v_approval.status <> 'pending' OR v_action.status <> 'pending_approval' THEN
    RAISE EXCEPTION 'commerce_decision_conflict' USING ERRCODE = '23514';
  END IF;
  IF v_approval.separate_approver AND v_approval.requested_by = v_actor THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  PERFORM openarc_durable.assert_action_decide_current(organization_id, action_id_input);

  -- Re-lock the action and approval rows after the chain locks and re-check the
  -- pending shape/expiry with the DB clock.
  SELECT a.* INTO v_action FROM openarc_durable.commerce_actions a
   WHERE a.organization_id = organization_id AND a.action_id = action_id_input FOR UPDATE;
  SELECT ap.* INTO v_approval FROM openarc_durable.commerce_approvals ap
   WHERE ap.organization_id = organization_id AND ap.action_id = action_id_input FOR UPDATE;
  IF NOT FOUND
     OR v_approval.status <> 'pending' OR v_action.status <> 'pending_approval' THEN
    RAISE EXCEPTION 'commerce_decision_conflict' USING ERRCODE = '23514';
  END IF;
  SELECT clock_timestamp() INTO v_now;
  IF NOT (v_approval.expires_at > v_now) OR NOT (v_action.expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_expired' USING ERRCODE = '23514';
  END IF;
  SELECT rq.* INTO v_requirement FROM openarc_durable.resolve_commerce_requirement(v_action.requirement_id) AS rq;
  v_expires := LEAST(v_action.expires_at, v_approval.expires_at, v_requirement.out_valid_until);
  IF NOT (v_expires > v_now) THEN
    RAISE EXCEPTION 'commerce_expired' USING ERRCODE = '23514';
  END IF;

  IF decision = 'approve' THEN
    SELECT v.* INTO v_policy FROM openarc_tenant.budget_policy_versions v
     WHERE v.organization_id = organization_id AND v.policy_id = v_action.policy_id
       AND v.revision = v_action.policy_revision;
    v_amount := v_action.amount_atomic::numeric; v_fee := v_action.fee_atomic::numeric;
    SELECT a.out_debit, a.out_committed, a.out_unresolved, a.out_total, a.out_projected,
           a.out_available, a.out_deficit, a.out_assessment, a.out_reason
      INTO v_debit, v_committed, v_unresolved, v_total, v_projected,
           v_available, v_deficit, v_assessment, v_reason
      FROM openarc_durable.assess_action_budget(
        organization_id, v_action.subject_agent_id, v_action.network_id, v_action.asset,
        v_action.representation, v_action.decimals, v_policy.rolling_window_seconds,
        v_policy.fee_limit, v_policy.per_action_limit, v_policy.rolling_limit,
        v_policy.approval_mode, v_policy.approval_threshold,
        v_action.amount_atomic, v_action.fee_atomic) AS a;
    IF v_assessment = 'denied' THEN
      RAISE EXCEPTION 'commerce_budget_denied' USING ERRCODE = 'P0D12';
    END IF;
    -- The reservation id is generated only at the approved reserve step; a
    -- pending_approval action stores NULL and never a non-null rejected key.
    v_reservation_id := 'openarc:reservation:' || substring(action_id_input FROM 16);
    INSERT INTO openarc_durable.budget_reservations (
      organization_id, reservation_id, action_id, subject_agent_id, network_id, asset,
      representation, decimals, debit_atomic, source_kind, status, created_at, claimed_at, resolved_at
    ) VALUES (
      organization_id, v_reservation_id, action_id_input, v_action.subject_agent_id,
      v_action.network_id, v_action.asset, v_action.representation, v_action.decimals,
      (v_amount + v_fee)::text, v_action.source_kind, 'held', v_now, NULL, NULL
    );
    UPDATE openarc_durable.commerce_approvals ap
       SET status = 'approved', decided_by = v_actor, decided_at = clock_timestamp()
     WHERE ap.organization_id = organization_id AND ap.approval_id = v_action.approval_id;
    UPDATE openarc_durable.commerce_actions a
       SET status = 'reserved_not_granted', reservation_id = v_reservation_id,
           updated_at = clock_timestamp()
     WHERE a.organization_id = organization_id AND a.action_id = action_id_input;
  ELSE
    UPDATE openarc_durable.commerce_approvals ap
       SET status = 'rejected', decided_by = v_actor, decided_at = clock_timestamp()
     WHERE ap.organization_id = organization_id AND ap.approval_id = v_action.approval_id;
    UPDATE openarc_durable.commerce_actions a
       SET status = 'rejected', updated_at = clock_timestamp()
     WHERE a.organization_id = organization_id AND a.action_id = action_id_input;
    v_reservation_id := NULL;
  END IF;

  INSERT INTO openarc_durable.idempotency_records (
    organization_id, operation, key_hash, request_digest, digest_version,
    actor_account_id, session_context_digest, network, mutation_id, status
  ) VALUES (
    organization_id, v_operation, key_hash, request_digest, v_operation || '.v1',
    v_actor, session_context_digest, 'eip155:5042002', mutation_id, 'pending'
  );
  UPDATE openarc_durable.idempotency_records r
     SET status = 'committed', resource_type = 'commerce_action',
         resource_id = action_id_input, committed_at = clock_timestamp()
   WHERE r.organization_id = organization_id AND r.operation = v_operation
     AND r.key_hash = key_hash
   RETURNING r.committed_at INTO v_committed_at;
  INSERT INTO openarc_durable.audit_events (
    organization_id, actor_account_id, operation, mutation_id, resource_type, resource_id, outcome
  ) VALUES (
    organization_id, v_actor, v_operation, mutation_id, 'commerce_action', action_id_input, 'committed'
  );
  INSERT INTO openarc_durable.outbox_events (
    organization_id, mutation_id, resource_type, resource_id, event_type, payload_version
  ) VALUES (
    organization_id, mutation_id, 'commerce_action', action_id_input, v_event, 1
  );

  -- Final recheck: a FRESH current caller proof after every wait and durable
  -- write, plus the current target chain/time immediately before return. The
  -- transaction-start clock is never used as authority.
  SELECT l.out_actor INTO v_parent_role
    FROM openarc_durable.lock_action_human(human_session_hash, organization_id, true) AS l;
  IF v_parent_role IS NULL OR v_parent_role <> v_actor THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;
  SELECT clock_timestamp() INTO v_now;
  IF NOT (v_action.expires_at > v_now) OR NOT (v_approval.expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_expired' USING ERRCODE = '23514';
  END IF;
  PERFORM openarc_durable.assert_action_prereqs_current(
    organization_id, v_action.seller_organization_id, v_action.policy_id, v_action.policy_revision,
    v_action.provider_id, v_action.listing_id, v_action.listing_version);

  out_replayed := false;
  out_action_id := action_id_input;
  out_organization_id := organization_id;
  out_subject_agent_id := v_action.subject_agent_id;
  out_commerce_session_id := v_action.commerce_session_id;
  out_network_id := v_action.network_id;
  out_asset := v_action.asset;
  out_representation := v_action.representation;
  out_decimals := v_action.decimals;
  out_source_kind := v_action.source_kind;
  out_amount_atomic := v_action.amount_atomic;
  out_fee_atomic := v_action.fee_atomic;
  out_debit_atomic := v_action.debit_atomic;
  out_policy_id := v_action.policy_id;
  out_policy_revision := v_action.policy_revision;
  out_provider_id := v_action.provider_id;
  out_listing_id := v_action.listing_id;
  out_listing_version := v_action.listing_version;
  out_requirement_id := v_action.requirement_id;
  out_requirement_digest := v_action.requirement_digest;
  out_status := CASE WHEN decision = 'approve' THEN 'reserved_not_granted' ELSE 'rejected' END;
  out_approval_id := v_action.approval_id;
  out_reservation_id := v_reservation_id;
  out_decided_by := v_actor;
  out_created_at := v_action.created_at;
  out_updated_at := clock_timestamp();
  out_expires_at := v_action.expires_at;
  out_committed_at := v_committed_at;
  RETURN NEXT;
END;
$$;

CREATE FUNCTION openarc_durable.decide_commerce_action(
  human_session_hash text,
  organization_id text,
  action_id_input text,
  decision text,
  mutation_id uuid,
  key_hash text,
  request_digest text,
  session_context_digest text
) RETURNS TABLE(
  out_replayed boolean,
  out_action_id text,
  out_organization_id text,
  out_subject_agent_id text,
  out_commerce_session_id uuid,
  out_network_id text,
  out_asset text,
  out_representation text,
  out_decimals smallint,
  out_source_kind text,
  out_amount_atomic text,
  out_fee_atomic text,
  out_debit_atomic text,
  out_policy_id text,
  out_policy_revision text,
  out_provider_id text,
  out_listing_id text,
  out_listing_version text,
  out_requirement_id text,
  out_requirement_digest text,
  out_status text,
  out_approval_id text,
  out_reservation_id text,
  out_decided_by text,
  out_created_at timestamptz,
  out_updated_at timestamptz,
  out_expires_at timestamptz,
  out_committed_at timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT * FROM openarc_durable.decide_commerce_action_core(
    'production', human_session_hash, organization_id, action_id_input, decision,
    mutation_id, key_hash, request_digest, session_context_digest);
$$;

-- ---------------------------------------------------------------------------
-- Human cancel core. Current fresh owner/operator of the same organization may
-- cancel a pending or reserved action even after the original parent/policy is
-- dead; the old immutable ids are used only for binding, NOT continued
-- authority. Release is permitted ONLY for an unclaimed held reservation.
-- Claimed/unknown/committed ALWAYS count as potential exposure and reject the
-- cancellation without changing balances/state. A pending approval is closed to
-- a safe expired status with decision fields still NULL; the cancelled action
-- can never be decided. Cancellation is NOT an on-chain revocation.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.cancel_commerce_action_core(
  human_session_hash text,
  organization_id text,
  action_id_input text,
  mutation_id uuid,
  key_hash text,
  request_digest text,
  session_context_digest text
) RETURNS TABLE(
  out_replayed boolean,
  out_action_id text,
  out_organization_id text,
  out_subject_agent_id text,
  out_commerce_session_id uuid,
  out_network_id text,
  out_asset text,
  out_representation text,
  out_decimals smallint,
  out_source_kind text,
  out_amount_atomic text,
  out_fee_atomic text,
  out_debit_atomic text,
  out_policy_id text,
  out_policy_revision text,
  out_provider_id text,
  out_listing_id text,
  out_listing_version text,
  out_requirement_id text,
  out_requirement_digest text,
  out_status text,
  out_reservation_id text,
  out_approval_id text,
  out_cancelled_by text,
  out_created_at timestamptz,
  out_updated_at timestamptz,
  out_expires_at timestamptz,
  out_committed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_actor text;
  v_action record;
  v_reservation record;
  v_existing record;
  v_now timestamptz;
  v_committed_at timestamptz;
  v_recheck text;
BEGIN
  IF NOT openarc_durable.is_canonical_hex64(human_session_hash)
     OR NOT openarc_durable.is_canonical_hex64(key_hash)
     OR NOT openarc_durable.is_canonical_hex64(request_digest)
     OR NOT openarc_durable.is_canonical_hex64(session_context_digest) THEN
    RAISE EXCEPTION 'commerce_metadata_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_canonical_action_id(action_id_input) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF mutation_id IS NULL OR NOT openarc_durable.is_canonical_uuid_v4(mutation_id::text) THEN
    RAISE EXCEPTION 'commerce_mutation_invalid' USING ERRCODE = '22023';
  END IF;

  SELECT l.out_actor INTO v_actor
    FROM openarc_durable.lock_action_human(human_session_hash, organization_id, true) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  SELECT r.* INTO v_existing FROM openarc_durable.idempotency_records r
   WHERE r.organization_id = organization_id AND r.operation = 'control.commerce_action.cancel'
     AND r.key_hash = key_hash FOR UPDATE;
  IF FOUND THEN
    IF v_existing.request_digest = request_digest
       AND v_existing.mutation_id = mutation_id
       AND v_existing.actor_account_id = v_actor
       AND v_existing.session_context_digest = session_context_digest
       AND v_existing.status = 'committed'
       AND v_existing.resource_type = 'commerce_action'
       AND v_existing.resource_id = action_id_input THEN
      SELECT a.* INTO v_action FROM openarc_durable.commerce_actions a
       WHERE a.organization_id = organization_id AND a.action_id = action_id_input;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
      END IF;
      SELECT l.out_actor INTO v_recheck
        FROM openarc_durable.lock_action_human(human_session_hash, organization_id, true) AS l;
      IF v_recheck IS NULL OR v_recheck <> v_actor THEN
        RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
      END IF;
      out_replayed := true;
      out_action_id := v_action.action_id;
      out_organization_id := v_action.organization_id;
      out_subject_agent_id := v_action.subject_agent_id;
      out_commerce_session_id := v_action.commerce_session_id;
      out_network_id := v_action.network_id;
      out_asset := v_action.asset;
      out_representation := v_action.representation;
      out_decimals := v_action.decimals;
      out_source_kind := v_action.source_kind;
      out_amount_atomic := v_action.amount_atomic;
      out_fee_atomic := v_action.fee_atomic;
      out_debit_atomic := v_action.debit_atomic;
      out_policy_id := v_action.policy_id;
      out_policy_revision := v_action.policy_revision;
      out_provider_id := v_action.provider_id;
      out_listing_id := v_action.listing_id;
      out_listing_version := v_action.listing_version;
      out_requirement_id := v_action.requirement_id;
      out_requirement_digest := v_action.requirement_digest;
      out_status := v_action.status;
      out_reservation_id := v_action.reservation_id;
      out_approval_id := v_action.approval_id;
      out_cancelled_by := v_actor;
      out_created_at := v_action.created_at;
      out_updated_at := v_action.updated_at;
      out_expires_at := v_action.expires_at;
      out_committed_at := v_existing.committed_at;
      RETURN NEXT; RETURN;
    END IF;
    RAISE EXCEPTION 'commerce_idempotency_conflict' USING ERRCODE = 'P0D01';
  END IF;
  PERFORM 1 FROM openarc_durable.idempotency_records r
   WHERE r.organization_id = organization_id AND r.mutation_id = mutation_id FOR UPDATE;
  IF FOUND THEN
    RAISE EXCEPTION 'commerce_idempotency_conflict' USING ERRCODE = 'P0D01';
  END IF;

  SELECT a.* INTO v_action FROM openarc_durable.commerce_actions a
   WHERE a.organization_id = organization_id AND a.action_id = action_id_input FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  IF v_action.status NOT IN ('pending_approval', 'reserved_not_granted') THEN
    RAISE EXCEPTION 'commerce_cancel_conflict' USING ERRCODE = '23514';
  END IF;
  SELECT clock_timestamp() INTO v_now;

  IF v_action.status = 'reserved_not_granted' THEN
    SELECT b.* INTO v_reservation FROM openarc_durable.budget_reservations b
     WHERE b.organization_id = organization_id AND b.action_id = action_id_input FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
    END IF;
    IF NOT openarc_durable.reservation_releasable(v_reservation.status)
       OR v_reservation.claimed_at IS NOT NULL THEN
      RAISE EXCEPTION 'commerce_potential_exposure' USING ERRCODE = 'P0D13';
    END IF;
    UPDATE openarc_durable.budget_reservations b
       SET status = 'released', resolved_at = v_now
     WHERE b.organization_id = organization_id AND b.reservation_id = v_reservation.reservation_id;
    INSERT INTO openarc_durable.budget_events (
      organization_id, event_id, action_id, reservation_id, subject_agent_id,
      network_id, asset, representation, decimals, amount_atomic, event_kind, event_time)
    VALUES (
      organization_id, gen_random_uuid(), action_id_input, v_reservation.reservation_id,
      v_action.subject_agent_id, v_action.network_id, v_action.asset, v_action.representation,
      v_action.decimals, v_reservation.debit_atomic, 'released', v_now);
  ELSE
    UPDATE openarc_durable.commerce_approvals ap
       SET status = 'expired'
     WHERE ap.organization_id = organization_id AND ap.action_id = action_id_input
       AND ap.status = 'pending';
  END IF;

  UPDATE openarc_durable.commerce_actions a
     SET status = 'cancelled', updated_at = clock_timestamp()
   WHERE a.organization_id = organization_id AND a.action_id = action_id_input;

  INSERT INTO openarc_durable.idempotency_records (
    organization_id, operation, key_hash, request_digest, digest_version,
    actor_account_id, session_context_digest, network, mutation_id, status
  ) VALUES (
    organization_id, 'control.commerce_action.cancel', key_hash, request_digest,
    'control.commerce_action.cancel.v1', v_actor, session_context_digest,
    'eip155:5042002', mutation_id, 'pending'
  );
  UPDATE openarc_durable.idempotency_records r
     SET status = 'committed', resource_type = 'commerce_action',
         resource_id = action_id_input, committed_at = clock_timestamp()
   WHERE r.organization_id = organization_id AND r.operation = 'control.commerce_action.cancel'
     AND r.key_hash = key_hash
   RETURNING r.committed_at INTO v_committed_at;
  INSERT INTO openarc_durable.audit_events (
    organization_id, actor_account_id, operation, mutation_id, resource_type, resource_id, outcome
  ) VALUES (
    organization_id, v_actor, 'control.commerce_action.cancel', mutation_id,
    'commerce_action', action_id_input, 'committed'
  );
  INSERT INTO openarc_durable.outbox_events (
    organization_id, mutation_id, resource_type, resource_id, event_type, payload_version
  ) VALUES (
    organization_id, mutation_id, 'commerce_action', action_id_input,
    'control.commerce_action.cancelled', 1
  );

  SELECT l.out_actor INTO v_recheck
    FROM openarc_durable.lock_action_human(human_session_hash, organization_id, true) AS l;
  IF v_recheck IS NULL OR v_recheck <> v_actor THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;

  out_replayed := false;
  out_action_id := action_id_input;
  out_organization_id := organization_id;
  out_subject_agent_id := v_action.subject_agent_id;
  out_commerce_session_id := v_action.commerce_session_id;
  out_network_id := v_action.network_id;
  out_asset := v_action.asset;
  out_representation := v_action.representation;
  out_decimals := v_action.decimals;
  out_source_kind := v_action.source_kind;
  out_amount_atomic := v_action.amount_atomic;
  out_fee_atomic := v_action.fee_atomic;
  out_debit_atomic := v_action.debit_atomic;
  out_policy_id := v_action.policy_id;
  out_policy_revision := v_action.policy_revision;
  out_provider_id := v_action.provider_id;
  out_listing_id := v_action.listing_id;
  out_listing_version := v_action.listing_version;
  out_requirement_id := v_action.requirement_id;
  out_requirement_digest := v_action.requirement_digest;
  out_status := 'cancelled';
  out_reservation_id := v_action.reservation_id;
  out_approval_id := v_action.approval_id;
  out_cancelled_by := v_actor;
  out_created_at := v_action.created_at;
  out_updated_at := clock_timestamp();
  out_expires_at := v_action.expires_at;
  out_committed_at := v_committed_at;
  RETURN NEXT;
END;
$$;

CREATE FUNCTION openarc_durable.cancel_commerce_action(
  human_session_hash text,
  organization_id text,
  action_id_input text,
  mutation_id uuid,
  key_hash text,
  request_digest text,
  session_context_digest text
) RETURNS TABLE(
  out_replayed boolean,
  out_action_id text,
  out_organization_id text,
  out_subject_agent_id text,
  out_commerce_session_id uuid,
  out_network_id text,
  out_asset text,
  out_representation text,
  out_decimals smallint,
  out_source_kind text,
  out_amount_atomic text,
  out_fee_atomic text,
  out_debit_atomic text,
  out_policy_id text,
  out_policy_revision text,
  out_provider_id text,
  out_listing_id text,
  out_listing_version text,
  out_requirement_id text,
  out_requirement_digest text,
  out_status text,
  out_reservation_id text,
  out_approval_id text,
  out_cancelled_by text,
  out_created_at timestamptz,
  out_updated_at timestamptz,
  out_expires_at timestamptz,
  out_committed_at timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT * FROM openarc_durable.cancel_commerce_action_core(
    human_session_hash, organization_id, action_id_input, mutation_id,
    key_hash, request_digest, session_context_digest);
$$;

-- ---------------------------------------------------------------------------
-- Human action projection reader. Current owner/operator non-recovery; a
-- foreign/missing action returns no row. Binds the returned org/subject to the
-- requested values so a malformed row cannot cross orgs.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.read_commerce_action(
  human_session_hash text,
  organization_id text,
  action_id_input text
) RETURNS TABLE(
  out_action_id text,
  out_organization_id text,
  out_subject_agent_id text,
  out_commerce_session_id uuid,
  out_status text,
  out_policy_id text,
  out_policy_revision text,
  out_provider_id text,
  out_listing_id text,
  out_listing_version text,
  out_requirement_id text,
  out_requirement_digest text,
  out_network_id text,
  out_asset text,
  out_representation text,
  out_decimals smallint,
  out_amount_atomic text,
  out_fee_atomic text,
  out_debit_atomic text,
  out_source_kind text,
  out_reservation_id text,
  out_approval_id text,
  out_created_at timestamptz,
  out_updated_at timestamptz,
  out_expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_actor text;
BEGIN
  IF NOT openarc_durable.is_canonical_org_id(organization_id)
     OR NOT openarc_durable.is_canonical_action_id(action_id_input) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  SELECT l.out_actor INTO v_actor
    FROM openarc_durable.lock_action_reader(human_session_hash, organization_id) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
    SELECT a.action_id, a.organization_id, a.subject_agent_id, a.commerce_session_id,
           a.status, a.policy_id,
           a.policy_revision, a.provider_id, a.listing_id, a.listing_version,
           a.requirement_id, a.requirement_digest, a.network_id, a.asset,
           a.representation, a.decimals, a.amount_atomic, a.fee_atomic, a.debit_atomic,
           a.source_kind, a.reservation_id, a.approval_id, a.created_at, a.updated_at, a.expires_at
      FROM openarc_durable.commerce_actions a
     WHERE a.organization_id = organization_id AND a.action_id = action_id_input;
  PERFORM 1 FROM openarc_durable.lock_action_reader(human_session_hash, organization_id) AS l
   WHERE l.out_actor = v_actor;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- Agent read of its OWN bound action metadata. The presented unique oacs_v1
-- commerce token selects the buyer organization and exact commerce session;
-- only an action bound to that EXACT session is visible, never another valid
-- session by the same sponsor/agent. The reader returns exactly one context row
-- whose organization is DB-derived (never caller-supplied) plus nullable safe
-- metadata columns. A missing/foreign action is a safe not-found with the
-- authenticated organization still present. The current exact token chain is
-- revalidated after the read, including the not-found path.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.read_agent_commerce_action(
  commerce_token_hash text,
  action_id_input text
) RETURNS TABLE(
  out_organization_id text,
  out_action_id text,
  out_found boolean,
  out_subject_agent_id text,
  out_commerce_session_id uuid,
  out_status text,
  out_policy_id text,
  out_policy_revision text,
  out_provider_id text,
  out_listing_id text,
  out_listing_version text,
  out_requirement_id text,
  out_requirement_digest text,
  out_network_id text,
  out_asset text,
  out_representation text,
  out_decimals smallint,
  out_amount_atomic text,
  out_fee_atomic text,
  out_debit_atomic text,
  out_source_kind text,
  out_reservation_id text,
  out_approval_id text,
  out_created_at timestamptz,
  out_updated_at timestamptz,
  out_expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_chain record;
  v_action record;
  v_found boolean := false;
BEGIN
  IF NOT openarc_durable.is_canonical_hex64(commerce_token_hash)
     OR NOT openarc_durable.is_canonical_action_id(action_id_input) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO v_chain
    FROM openarc_durable.lock_action_commerce(commerce_token_hash, NULL) AS c;
  IF v_chain.out_organization_id IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  PERFORM openarc_durable.lock_action_commerce_state(
    commerce_token_hash, v_chain.out_organization_id);
  SELECT a.* INTO v_action FROM openarc_durable.commerce_actions a
   WHERE a.organization_id = v_chain.out_organization_id
     AND a.action_id = action_id_input
     AND a.commerce_session_id = v_chain.out_commerce_session_id
     AND a.subject_agent_id = v_chain.out_subject_agent_id;
  v_found := FOUND;
  -- Revalidate the CURRENT exact presented commerce token after the read,
  -- including the not-found path: a revoked/second live token for the same
  -- account/agent must not serve metadata.
  -- Revalidate the exact commerce session after the lookup, including the
  -- not-found path.  The plain binding resolver intentionally does not assert
  -- current revocation, so the final check must use the state-lock helper.
  PERFORM openarc_durable.lock_action_commerce_state(
    commerce_token_hash, v_chain.out_organization_id);
  out_organization_id := v_chain.out_organization_id;
  out_action_id := action_id_input;
  out_found := v_found;
  IF NOT v_found THEN
    RETURN NEXT;
    RETURN;
  END IF;
  out_subject_agent_id := v_action.subject_agent_id;
  out_commerce_session_id := v_action.commerce_session_id;
  out_status := v_action.status;
  out_policy_id := v_action.policy_id;
  out_policy_revision := v_action.policy_revision;
  out_provider_id := v_action.provider_id;
  out_listing_id := v_action.listing_id;
  out_listing_version := v_action.listing_version;
  out_requirement_id := v_action.requirement_id;
  out_requirement_digest := v_action.requirement_digest;
  out_network_id := v_action.network_id;
  out_asset := v_action.asset;
  out_representation := v_action.representation;
  out_decimals := v_action.decimals;
  out_amount_atomic := v_action.amount_atomic;
  out_fee_atomic := v_action.fee_atomic;
  out_debit_atomic := v_action.debit_atomic;
  out_source_kind := v_action.source_kind;
  out_reservation_id := v_action.reservation_id;
  out_approval_id := v_action.approval_id;
  out_created_at := v_action.created_at;
  out_updated_at := v_action.updated_at;
  out_expires_at := v_action.expires_at;
  RETURN NEXT;
END;
$$;

CREATE FUNCTION openarc_durable.read_commerce_approval(
  human_session_hash text,
  organization_id text,
  action_id_input text
) RETURNS TABLE(
  out_approval_id text,
  out_action_id text,
  out_organization_id text,
  out_subject_agent_id text,
  out_commerce_session_id uuid,
  out_status text,
  out_policy_id text,
  out_policy_revision text,
  out_requested_by text,
  out_separate_approver boolean,
  out_decided_by text,
  out_source_kind text,
  out_created_at timestamptz,
  out_expires_at timestamptz,
  out_decided_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_actor text;
BEGIN
  IF NOT openarc_durable.is_canonical_org_id(organization_id)
     OR NOT openarc_durable.is_canonical_action_id(action_id_input) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  SELECT l.out_actor INTO v_actor
    FROM openarc_durable.lock_action_reader(human_session_hash, organization_id) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
    SELECT ap.approval_id, ap.action_id, ap.organization_id, ap.subject_agent_id,
           ap.commerce_session_id, ap.status,
           ap.policy_id, ap.policy_revision, ap.requested_by, ap.separate_approver,
           ap.decided_by, ap.source_kind, ap.created_at, ap.expires_at, ap.decided_at
      FROM openarc_durable.commerce_approvals ap
     WHERE ap.organization_id = organization_id AND ap.action_id = action_id_input;
  PERFORM 1 FROM openarc_durable.lock_action_reader(human_session_hash, organization_id) AS l
   WHERE l.out_actor = v_actor;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- Exposure read. Current owner/operator non-recovery selects a current active
-- policy window for the named subject and returns the exact rolling committed
-- and ALL unresolved totals with DB asOf. A completeness-bound failure is
-- unavailable, never a misleading partial available amount.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.read_commerce_exposure(
  human_session_hash text,
  organization_id text,
  subject_agent_id_input text,
  policy_id_input text
) RETURNS TABLE(
  out_organization_id text,
  out_subject_agent_id text,
  out_policy_id text,
  out_policy_revision text,
  out_network_id text,
  out_asset text,
  out_representation text,
  out_decimals smallint,
  out_window_seconds text,
  out_committed_atomic text,
  out_unresolved_atomic text,
  out_total_atomic text,
  out_available_atomic text,
  out_deficit_atomic text,
  out_as_of timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_actor text;
  v_policy record;
  v_now timestamptz;
  v_cutoff timestamptz;
  v_committed_count integer;
  v_unresolved_count integer;
  v_committed numeric;
  v_unresolved numeric;
  v_total numeric;
  v_available text;
  v_deficit text;
BEGIN
  IF NOT openarc_durable.is_canonical_org_id(organization_id)
     OR NOT openarc_durable.is_canonical_agent_id(subject_agent_id_input)
     OR NOT openarc_durable.is_canonical_policy_id(policy_id_input) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  SELECT l.out_actor INTO v_actor
    FROM openarc_durable.lock_action_reader(human_session_hash, organization_id) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT v.* INTO v_policy
    FROM openarc_tenant.budget_policy_roots r
    JOIN openarc_tenant.budget_policy_versions v
      ON v.organization_id = r.organization_id AND v.policy_id = r.policy_id
     AND v.revision = r.current_revision
   WHERE r.organization_id = organization_id AND r.policy_id = policy_id_input
     AND r.status = 'active' AND r.subject_agent_id = subject_agent_id_input;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT clock_timestamp() INTO v_now;
  IF v_policy.expires_at IS NOT NULL AND NOT (v_policy.expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_expired' USING ERRCODE = '23514';
  END IF;
  v_cutoff := v_now - make_interval(secs => COALESCE(v_policy.rolling_window_seconds::integer, 0));
  SELECT count(*)::int, COALESCE(sum(e.amount_atomic::numeric), 0)
    INTO v_committed_count, v_committed
    FROM (SELECT b.amount_atomic FROM openarc_durable.budget_events b
           WHERE b.organization_id = organization_id AND b.subject_agent_id = subject_agent_id_input
             AND b.network_id = v_policy.network_id AND b.asset = v_policy.asset
             AND b.representation = v_policy.representation AND b.decimals = v_policy.decimals
             AND b.event_kind = 'committed' AND b.event_time <= v_now
             AND (v_policy.rolling_limit IS NULL OR b.event_time > v_cutoff)
           LIMIT 4097) AS e;
  IF v_committed_count > 4096 THEN
    RAISE EXCEPTION 'commerce_exposure_unavailable' USING ERRCODE = 'P0D11';
  END IF;
  SELECT count(*)::int, COALESCE(sum(e.debit_atomic::numeric), 0)
    INTO v_unresolved_count, v_unresolved
    FROM (SELECT r.debit_atomic FROM openarc_durable.budget_reservations r
           WHERE r.organization_id = organization_id AND r.subject_agent_id = subject_agent_id_input
             AND r.network_id = v_policy.network_id AND r.asset = v_policy.asset
             AND r.representation = v_policy.representation AND r.decimals = v_policy.decimals
             AND r.status IN ('held', 'claimed', 'unknown')
           LIMIT 4097) AS e;
  IF v_unresolved_count > 4096 THEN
    RAISE EXCEPTION 'commerce_exposure_unavailable' USING ERRCODE = 'P0D11';
  END IF;
  v_total := v_committed + v_unresolved;
  IF v_total >= 10::numeric ^ 128 THEN
    RAISE EXCEPTION 'commerce_arithmetic_overflow' USING ERRCODE = '22003';
  END IF;
  IF v_policy.rolling_limit IS NULL THEN
    v_available := NULL; v_deficit := '0';
  ELSE
    v_available := (CASE WHEN v_policy.rolling_limit::numeric > v_total
                         THEN v_policy.rolling_limit::numeric - v_total ELSE 0 END)::text;
    v_deficit := (CASE WHEN v_total > v_policy.rolling_limit::numeric
                       THEN v_total - v_policy.rolling_limit::numeric ELSE 0 END)::text;
  END IF;
  PERFORM 1 FROM openarc_durable.lock_action_reader(human_session_hash, organization_id) AS l
   WHERE l.out_actor = v_actor;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;
  out_organization_id := organization_id;
  out_subject_agent_id := subject_agent_id_input;
  out_policy_id := policy_id_input;
  out_policy_revision := v_policy.revision;
  out_network_id := v_policy.network_id;
  out_asset := v_policy.asset;
  out_representation := v_policy.representation;
  out_decimals := v_policy.decimals;
  out_window_seconds := v_policy.rolling_window_seconds;
  out_committed_atomic := v_committed::text;
  out_unresolved_atomic := v_unresolved::text;
  out_total_atomic := v_total::text;
  out_available_atomic := v_available;
  out_deficit_atomic := v_deficit;
  out_as_of := v_now;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Mutation status readers. Human status is bound to the exact presented human
-- session context digest and covers the human operations only. Agent status is
-- bound to the authorize operation and the exact presented commerce token
-- context. A foreign/missing receipt is a safe not_found.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.read_human_commerce_action_mutation_status(
  human_session_hash text,
  organization_id text,
  mutation_id uuid
) RETURNS TABLE(
  out_mutation_id uuid,
  out_operation text,
  out_resource_type text,
  out_resource_id text,
  out_committed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_actor text;
  v_found boolean := false;
  v_mutation_id uuid;
  v_operation text;
  v_resource_type text;
  v_resource_id text;
  v_committed_at timestamptz;
BEGIN
  IF NOT openarc_durable.is_canonical_org_id(organization_id) OR mutation_id IS NULL THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  SELECT l.out_actor INTO v_actor
    FROM openarc_durable.lock_action_reader(human_session_hash, organization_id) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT r.mutation_id, r.operation, r.resource_type, r.resource_id, r.committed_at
    INTO v_mutation_id, v_operation, v_resource_type, v_resource_id, v_committed_at
    FROM openarc_durable.idempotency_records r
   WHERE r.organization_id = organization_id AND r.mutation_id = mutation_id
     AND r.actor_account_id = v_actor AND r.status = 'committed'
     AND r.session_context_digest = encode(
       sha256(convert_to(
         (CASE r.operation
            WHEN 'control.commerce_action.approve' THEN 'openarc.control.commerce_action.approve.session.v1'
            WHEN 'control.commerce_action.reject' THEN 'openarc.control.commerce_action.reject.session.v1'
            WHEN 'control.commerce_action.cancel' THEN 'openarc.control.commerce_action.cancel.session.v1'
          END) || ':' || human_session_hash, 'UTF8')), 'hex')
     AND r.operation IN (
       'control.commerce_action.approve',
       'control.commerce_action.reject',
       'control.commerce_action.cancel');
  v_found := FOUND;
  SELECT l.out_actor INTO v_actor
    FROM openarc_durable.lock_action_reader(human_session_hash, organization_id) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;
  IF NOT v_found THEN RETURN; END IF;
  out_mutation_id := v_mutation_id;
  out_operation := v_operation;
  out_resource_type := v_resource_type;
  out_resource_id := v_resource_id;
  out_committed_at := v_committed_at;
  RETURN NEXT;
END;
$$;

CREATE FUNCTION openarc_durable.read_agent_commerce_action_mutation_status(
  commerce_token_hash text,
  mutation_id uuid
) RETURNS TABLE(
  out_mutation_id uuid,
  out_operation text,
  out_resource_type text,
  out_resource_id text,
  out_committed_at timestamptz,
  out_organization_id text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_chain record;
  v_found boolean := false;
  v_mutation_id uuid;
  v_operation text;
  v_resource_type text;
  v_resource_id text;
  v_committed_at timestamptz;
BEGIN
  IF NOT openarc_durable.is_canonical_hex64(commerce_token_hash) OR mutation_id IS NULL THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO v_chain
    FROM openarc_durable.lock_action_commerce(commerce_token_hash, NULL) AS c;
  IF v_chain.out_organization_id IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  PERFORM openarc_durable.lock_action_commerce_state(
    commerce_token_hash, v_chain.out_organization_id);
  SELECT r.mutation_id, r.operation, r.resource_type, r.resource_id, r.committed_at
    INTO v_mutation_id, v_operation, v_resource_type, v_resource_id, v_committed_at
    FROM openarc_durable.idempotency_records r
   WHERE r.organization_id = v_chain.out_organization_id AND r.mutation_id = mutation_id
     AND r.status = 'committed'
     AND r.operation = 'control.commerce_action.authorize'
     AND r.actor_account_id = v_chain.out_parent_human_account_id
     AND r.session_context_digest = encode(
       sha256(convert_to(
         'openarc.control.commerce_action.authorize.session.v1' || ':' || commerce_token_hash,
         'UTF8')),
       'hex');
  v_found := FOUND;
  -- Recheck the CURRENT exact presented commerce token authority AFTER the read,
  -- including the not-found path: a revoked/second live token for the same
  -- account/agent must not recover the original receipt.
  PERFORM openarc_durable.lock_action_commerce_state(
    commerce_token_hash, v_chain.out_organization_id);
  out_organization_id := v_chain.out_organization_id;
  IF NOT v_found THEN RETURN; END IF;
  out_mutation_id := v_mutation_id;
  out_operation := v_operation;
  out_resource_type := v_resource_type;
  out_resource_id := v_resource_id;
  out_committed_at := v_committed_at;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- ACLs. PUBLIC gets nothing. The internal core helpers, budget/exposure
-- routines, validators and resolution helpers remain EXECUTE-free for every
-- runtime role. Only the production wrappers and the runtime read helpers are
-- granted to the restricted tenant role.
-- ---------------------------------------------------------------------------
REVOKE ALL ON FUNCTION openarc_durable.is_canonical_action_id(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.is_canonical_reservation_id(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.is_canonical_approval_id(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.is_canonical_requirement_id(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.is_canonical_exposure_total(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.is_allowed_exposure_identity(text, text, text, smallint) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.is_canonical_source_kind(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.reject_requirement_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.reject_budget_event_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.enforce_commerce_action_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.enforce_budget_reservation_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.enforce_commerce_approval_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.resolve_commerce_requirement(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.lock_action_human(text, text, boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.lock_action_reader(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.lock_action_commerce(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.lock_action_commerce_state(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.lock_action_listing(text, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.resolve_commerce_action_context(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.assess_action_budget(text, text, text, text, text, smallint, text, text, text, text, text, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.reservation_releasable(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.assert_action_prereqs_current(text, text, text, text, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.lock_action_decision_chain(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.lock_action_decide_preamble(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.assert_action_decide_current(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.authorize_commerce_action_core(text, text, text, text, uuid, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.decide_commerce_action_core(text, text, text, text, text, uuid, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.cancel_commerce_action_core(text, text, text, uuid, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.authorize_commerce_action(text, text, text, uuid, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.decide_commerce_action(text, text, text, text, uuid, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.cancel_commerce_action(text, text, text, uuid, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.read_commerce_action(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.read_agent_commerce_action(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.read_commerce_approval(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.read_commerce_exposure(text, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.read_human_commerce_action_mutation_status(text, text, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.read_agent_commerce_action_mutation_status(text, uuid) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION openarc_durable.authorize_commerce_action(text, text, text, uuid, text, text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.decide_commerce_action(text, text, text, text, uuid, text, text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.cancel_commerce_action(text, text, text, uuid, text, text, text) TO openarc_tenant_app;
-- Narrow immutable/authority preambles the runtime repository needs to build a
-- request digest BEFORE the mutation. They assert no authority and are
-- revalidated inside the core under the full lock order.
GRANT EXECUTE ON FUNCTION openarc_durable.resolve_commerce_action_context(text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.resolve_commerce_requirement(text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.lock_action_human(text, text, boolean) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.read_commerce_action(text, text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.read_agent_commerce_action(text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.read_commerce_approval(text, text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.read_commerce_exposure(text, text, text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.read_human_commerce_action_mutation_status(text, text, uuid) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.read_agent_commerce_action_mutation_status(text, uuid) TO openarc_tenant_app;
