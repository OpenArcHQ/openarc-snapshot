-- OpenArc control policy budget foundation (schema8).
-- Additive over schema7. Owner: openarc_migrator. Runtime: openarc_tenant_app.
-- Two forced-RLS migrator-owned tables plus narrow definer helpers. This
-- migration NEVER creates roles/schemas, fetches an endpoint, records a
-- reservation/grant or executes any payment. It records declared policy
-- content only; it is not spend authority.

-- ---------------------------------------------------------------------------
-- Shared canonical validators for the policy content surface.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.is_canonical_policy_id(value text) RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT value IS NOT NULL
     AND value ~ '^openarc:policy:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
$$;

CREATE FUNCTION openarc_durable.is_canonical_agent_id(value text) RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT value IS NOT NULL
     AND value ~ '^openarc:agent:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
$$;

CREATE FUNCTION openarc_durable.is_canonical_provider_id(value text) RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT value IS NOT NULL
     AND value ~ '^openarc:provider:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
$$;

CREATE FUNCTION openarc_durable.is_canonical_policy_revision(value text) RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT value IS NOT NULL AND value ~ '^[1-9][0-9]{0,8}$';
$$;

-- Unsigned 256-bit canonical decimal including zero (fee limit may be zero).
CREATE FUNCTION openarc_durable.is_canonical_uint256(value text) RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT value IS NOT NULL
     AND value ~ '^(0|[1-9][0-9]{0,77})$'
     AND value::numeric <= 115792089237316195423570985008687907853269984665640564039457584007913129639935::numeric;
$$;

CREATE FUNCTION openarc_durable.is_positive_uint256(value text) RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT openarc_durable.is_canonical_uint256(value) AND value::numeric > 0;
$$;

-- Strictly ascending, duplicate-free, null-free, at most 64 canonical provider
-- ids. Empty is allowed (the shared array max has no min).
CREATE FUNCTION openarc_durable.is_valid_policy_provider_list(value text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT value IS NOT NULL
     AND cardinality(value) <= 64
     AND array_position(value, NULL) IS NULL
     AND (cardinality(value) = 0
          OR ((SELECT count(DISTINCT x) FROM unnest(value) AS x) = cardinality(value)
              AND value = (SELECT array_agg(x ORDER BY x) FROM unnest(value) AS x)
              AND NOT EXISTS (
                SELECT 1 FROM unnest(value) AS x
                 WHERE NOT openarc_durable.is_canonical_provider_id(x)
              )));
$$;

CREATE FUNCTION openarc_durable.is_valid_policy_listing_list(value text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT value IS NOT NULL
     AND cardinality(value) <= 128
     AND array_position(value, NULL) IS NULL
     AND (cardinality(value) = 0
          OR ((SELECT count(DISTINCT x) FROM unnest(value) AS x) = cardinality(value)
              AND value = (SELECT array_agg(x ORDER BY x) FROM unnest(value) AS x)
              AND NOT EXISTS (
                SELECT 1 FROM unnest(value) AS x
                 WHERE NOT openarc_durable.is_canonical_listing_id(x)
              )));
$$;

-- Exact approval/null matrix from the frozen shared schema.
CREATE FUNCTION openarc_durable.is_valid_policy_approval(
  mode text,
  threshold text,
  separate_approver boolean
) RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT mode IS NOT NULL
     AND (
       (mode = 'none' AND threshold IS NULL AND separate_approver = false)
       OR (mode = 'always' AND threshold IS NULL)
       OR (mode = 'above' AND threshold IS NOT NULL
           AND openarc_durable.is_positive_uint256(threshold))
     );
$$;

CREATE FUNCTION openarc_durable.is_valid_policy_content(
  subject_agent_id text,
  network_id text,
  asset text,
  representation text,
  decimals smallint,
  per_action_limit text,
  rolling_limit text,
  rolling_window_seconds text,
  fee_limit text,
  allowed_provider_ids text[],
  allowed_listing_ids text[],
  approval_mode text,
  approval_threshold text,
  approval_separate_approver boolean,
  expires_at timestamptz,
  created_at timestamptz
) RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT openarc_durable.is_canonical_agent_id(subject_agent_id)
     AND network_id = 'eip155:5042002'
     AND asset = 'USDC'
     AND representation = 'erc20'
     AND decimals = 6
     AND (per_action_limit IS NULL OR openarc_durable.is_canonical_uint256(per_action_limit))
     AND (rolling_limit IS NULL OR openarc_durable.is_canonical_uint256(rolling_limit))
     AND fee_limit IS NOT NULL
     AND openarc_durable.is_canonical_uint256(fee_limit)
     AND (per_action_limit IS NOT NULL OR rolling_limit IS NOT NULL)
     AND (
       (rolling_limit IS NULL AND rolling_window_seconds IS NULL)
       OR (rolling_limit IS NOT NULL AND rolling_window_seconds IS NOT NULL
           AND rolling_window_seconds ~ '^[1-9][0-9]{0,6}$'
           AND rolling_window_seconds::numeric BETWEEN 1 AND 2592000)
     )
     AND openarc_durable.is_valid_policy_provider_list(allowed_provider_ids)
     AND openarc_durable.is_valid_policy_listing_list(allowed_listing_ids)
     AND openarc_durable.is_valid_policy_approval(approval_mode, approval_threshold, approval_separate_approver)
     AND (expires_at IS NULL OR (created_at IS NOT NULL AND expires_at > created_at));
$$;

CREATE FUNCTION openarc_durable.assert_policy_content(
  subject_agent_id text,
  network_id text,
  asset text,
  representation text,
  decimals smallint,
  per_action_limit text,
  rolling_limit text,
  rolling_window_seconds text,
  fee_limit text,
  allowed_provider_ids text[],
  allowed_listing_ids text[],
  approval_mode text,
  approval_threshold text,
  approval_separate_approver boolean,
  expires_at timestamptz,
  created_at timestamptz
) RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF NOT openarc_durable.is_valid_policy_content(
       subject_agent_id, network_id, asset, representation, decimals,
       per_action_limit, rolling_limit, rolling_window_seconds, fee_limit,
       allowed_provider_ids, allowed_listing_ids, approval_mode,
       approval_threshold, approval_separate_approver, expires_at, created_at) THEN
    RAISE EXCEPTION 'policy_content_invalid' USING ERRCODE = '22023';
  END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- budget_policy_roots: stable policy/org/agent identity plus current revision
-- and lifecycle status. Root org/subject/policy id/creation are immutable.
-- ---------------------------------------------------------------------------
CREATE TABLE openarc_tenant.budget_policy_roots (
  organization_id text NOT NULL,
  policy_id text NOT NULL,
  subject_agent_id text NOT NULL,
  current_revision text NOT NULL,
  status text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, policy_id),
  CONSTRAINT budget_policy_roots_policy_unique UNIQUE (policy_id),
  CONSTRAINT budget_policy_roots_subject_unique UNIQUE (organization_id, policy_id, subject_agent_id),
  CONSTRAINT budget_policy_roots_subject_fk FOREIGN KEY (organization_id, subject_agent_id)
    REFERENCES openarc_tenant.agents(organization_id, agent_id) ON DELETE RESTRICT,
  CONSTRAINT budget_policy_roots_policy_id_valid CHECK (openarc_durable.is_canonical_policy_id(policy_id)),
  CONSTRAINT budget_policy_roots_subject_valid CHECK (openarc_durable.is_canonical_agent_id(subject_agent_id)),
  CONSTRAINT budget_policy_roots_revision_valid CHECK (openarc_durable.is_canonical_policy_revision(current_revision)),
  CONSTRAINT budget_policy_roots_status_valid CHECK (status IN ('active', 'paused', 'revoked')),
  CONSTRAINT budget_policy_roots_timestamps_valid CHECK (updated_at >= created_at)
);

-- ---------------------------------------------------------------------------
-- budget_policy_versions: immutable normalized policy revision content. No
-- arbitrary JSON; every field is a fixed column with an exact-key CHECK. A
-- version row can never be edited or deleted in place.
-- ---------------------------------------------------------------------------
CREATE TABLE openarc_tenant.budget_policy_versions (
  organization_id text NOT NULL,
  policy_id text NOT NULL,
  revision text NOT NULL,
  subject_agent_id text NOT NULL,
  network_id text NOT NULL,
  asset text NOT NULL,
  representation text NOT NULL,
  decimals smallint NOT NULL,
  per_action_limit text,
  rolling_limit text,
  rolling_window_seconds text,
  fee_limit text NOT NULL,
  allowed_provider_ids text[] NOT NULL,
  allowed_listing_ids text[] NOT NULL,
  approval_mode text NOT NULL,
  approval_threshold text,
  approval_separate_approver boolean NOT NULL,
  expires_at timestamptz,
  digest text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, policy_id, revision),
  CONSTRAINT budget_policy_versions_policy_unique UNIQUE (policy_id, revision),
  CONSTRAINT budget_policy_versions_root_fk FOREIGN KEY (organization_id, policy_id, subject_agent_id)
    REFERENCES openarc_tenant.budget_policy_roots(organization_id, policy_id, subject_agent_id)
    ON DELETE RESTRICT,
  CONSTRAINT budget_policy_versions_policy_id_valid CHECK (openarc_durable.is_canonical_policy_id(policy_id)),
  CONSTRAINT budget_policy_versions_revision_valid CHECK (openarc_durable.is_canonical_policy_revision(revision)),
  CONSTRAINT budget_policy_versions_digest_valid CHECK (openarc_durable.is_canonical_sha256_digest(digest)),
  CONSTRAINT budget_policy_versions_content_valid CHECK (openarc_durable.is_valid_policy_content(
    subject_agent_id, network_id, asset, representation, decimals,
    per_action_limit, rolling_limit, rolling_window_seconds, fee_limit,
    allowed_provider_ids, allowed_listing_ids, approval_mode,
    approval_threshold, approval_separate_approver, expires_at, created_at))
);

-- Current revision pointer: the root's current_revision must name a version of
-- this same org/policy (deferred so root+version1 can be created together).
ALTER TABLE openarc_tenant.budget_policy_roots
  ADD CONSTRAINT budget_policy_roots_current_fk FOREIGN KEY (organization_id, policy_id, current_revision)
    REFERENCES openarc_tenant.budget_policy_versions(organization_id, policy_id, revision)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE INDEX budget_policy_roots_org_idx
  ON openarc_tenant.budget_policy_roots (organization_id, policy_id);
CREATE INDEX budget_policy_versions_org_idx
  ON openarc_tenant.budget_policy_versions (organization_id, policy_id, revision);

-- At most ONE active policy root per payer organization/subject agent. This is
-- the atomic create/resume race guard: a second concurrent activation violates
-- the partial unique index and rolls back rather than leaving two active roots.
CREATE UNIQUE INDEX budget_policy_roots_one_active
  ON openarc_tenant.budget_policy_roots (organization_id, subject_agent_id)
  WHERE status = 'active';

-- Version content is immutable: reject UPDATE and DELETE for every caller
-- including ordinary migrator DML.
CREATE FUNCTION openarc_tenant.reject_policy_version_mutation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'policy_version_immutable' USING ERRCODE = '42501';
END;
$$;

CREATE TRIGGER budget_policy_versions_immutable
  BEFORE UPDATE OR DELETE ON openarc_tenant.budget_policy_versions
  FOR EACH ROW EXECUTE FUNCTION openarc_tenant.reject_policy_version_mutation();

-- Root identity/creation are immutable. current_revision may only advance by
-- exactly one; status may only follow the closed lifecycle edges; updated_at
-- must advance monotonically (microsecond CAS token).
CREATE FUNCTION openarc_tenant.enforce_policy_root_mutation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
     OR NEW.policy_id IS DISTINCT FROM OLD.policy_id
     OR NEW.subject_agent_id IS DISTINCT FROM OLD.subject_agent_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'policy_root_immutable' USING ERRCODE = '42501';
  END IF;
  IF NEW.current_revision::numeric < OLD.current_revision::numeric
     OR NEW.current_revision::numeric > OLD.current_revision::numeric + 1 THEN
    RAISE EXCEPTION 'policy_root_revision_invalid' USING ERRCODE = '23514';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status
     AND NOT (
       (OLD.status = 'active' AND NEW.status IN ('paused', 'revoked'))
       OR (OLD.status = 'paused' AND NEW.status IN ('active', 'revoked'))
     ) THEN
    RAISE EXCEPTION 'policy_root_status_invalid' USING ERRCODE = '23514';
  END IF;
  IF NOT (NEW.updated_at > OLD.updated_at) THEN
    RAISE EXCEPTION 'policy_root_clock_invalid' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER budget_policy_roots_mutation
  BEFORE UPDATE ON openarc_tenant.budget_policy_roots
  FOR EACH ROW EXECUTE FUNCTION openarc_tenant.enforce_policy_root_mutation();

-- ---------------------------------------------------------------------------
-- RLS: migrator-only policies; runtime/worker/PUBLIC receive no direct table
-- privilege. All runtime access is through the narrow definers below.
-- ---------------------------------------------------------------------------
ALTER TABLE openarc_tenant.budget_policy_roots ENABLE ROW LEVEL SECURITY;
ALTER TABLE openarc_tenant.budget_policy_roots FORCE ROW LEVEL SECURITY;
ALTER TABLE openarc_tenant.budget_policy_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE openarc_tenant.budget_policy_versions FORCE ROW LEVEL SECURITY;

CREATE POLICY budget_policy_roots_migrator ON openarc_tenant.budget_policy_roots
  FOR ALL TO openarc_migrator USING (true) WITH CHECK (true);
CREATE POLICY budget_policy_versions_migrator ON openarc_tenant.budget_policy_versions
  FOR ALL TO openarc_migrator USING (true) WITH CHECK (true);

-- Accepted migrator-only row-lock policy: the policy definer helpers lock the
-- subject agent row with SELECT ... FOR UPDATE, which under FORCE RLS requires
-- an UPDATE policy for the migrator. This grants NOTHING to any runtime role
-- (which holds no table privilege) and does not widen the runtime agents_update
-- policy; the helper-level role checks are retained.
CREATE POLICY agents_update_migrator ON openarc_tenant.agents
  FOR UPDATE TO openarc_migrator
  USING (current_user = 'openarc_migrator')
  WITH CHECK (current_user = 'openarc_migrator');

REVOKE ALL ON TABLE openarc_tenant.budget_policy_roots FROM PUBLIC;
REVOKE ALL ON TABLE openarc_tenant.budget_policy_versions FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Closed operation / resource / event union extensions.
-- ---------------------------------------------------------------------------
ALTER TABLE openarc_durable.idempotency_records
  DROP CONSTRAINT idempotency_operation_valid,
  DROP CONSTRAINT idempotency_digest_version_valid,
  DROP CONSTRAINT idempotency_resource_type_valid,
  DROP CONSTRAINT idempotency_resource_matches_operation,
  DROP CONSTRAINT idempotency_market_resource_shape;

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
    'control.policy.revoke'
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
    'control.policy.revoke.v1'
  )),
  ADD CONSTRAINT idempotency_resource_type_valid CHECK (resource_type IS NULL OR resource_type IN (
    'organization', 'agent', 'provider', 'membership',
    'agent_credential', 'provider_credential',
    'listing', 'listing_version',
    'budget_policy', 'budget_policy_revision'
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
  );

-- Typed generated policy link columns. A receipt cannot point at another org's
-- policy or a missing revision.
ALTER TABLE openarc_durable.idempotency_records
  ADD COLUMN policy_id text GENERATED ALWAYS AS (
    CASE WHEN resource_type IN ('budget_policy', 'budget_policy_revision')
         THEN split_part(resource_id, '@', 1) END
  ) STORED,
  ADD COLUMN policy_revision text GENERATED ALWAYS AS (
    CASE WHEN resource_type = 'budget_policy_revision'
         THEN split_part(resource_id, '@', 2) END
  ) STORED;

ALTER TABLE openarc_durable.idempotency_records
  ADD CONSTRAINT idempotency_policy_fk FOREIGN KEY (organization_id, policy_id)
    REFERENCES openarc_tenant.budget_policy_roots(organization_id, policy_id) ON DELETE RESTRICT,
  ADD CONSTRAINT idempotency_policy_revision_fk FOREIGN KEY (organization_id, policy_id, policy_revision)
    REFERENCES openarc_tenant.budget_policy_versions(organization_id, policy_id, revision) ON DELETE RESTRICT,
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
  );

ALTER TABLE openarc_durable.audit_events
  DROP CONSTRAINT audit_operation_valid,
  DROP CONSTRAINT audit_resource_type_valid,
  DROP CONSTRAINT audit_resource_matches_operation;

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
    'control.policy.revoke'
  )),
  ADD CONSTRAINT audit_resource_type_valid CHECK (resource_type IN (
    'organization', 'agent', 'provider', 'membership',
    'agent_credential', 'provider_credential',
    'listing', 'listing_version',
    'budget_policy', 'budget_policy_revision'
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
    END
  );

ALTER TABLE openarc_durable.audit_events
  ADD COLUMN policy_id text GENERATED ALWAYS AS (
    CASE WHEN resource_type IN ('budget_policy', 'budget_policy_revision')
         THEN split_part(resource_id, '@', 1) END
  ) STORED,
  ADD COLUMN policy_revision text GENERATED ALWAYS AS (
    CASE WHEN resource_type = 'budget_policy_revision'
         THEN split_part(resource_id, '@', 2) END
  ) STORED;

ALTER TABLE openarc_durable.audit_events
  ADD CONSTRAINT audit_policy_fk FOREIGN KEY (organization_id, policy_id)
    REFERENCES openarc_tenant.budget_policy_roots(organization_id, policy_id) ON DELETE RESTRICT,
  ADD CONSTRAINT audit_policy_revision_fk FOREIGN KEY (organization_id, policy_id, policy_revision)
    REFERENCES openarc_tenant.budget_policy_versions(organization_id, policy_id, revision) ON DELETE RESTRICT,
  ADD CONSTRAINT audit_policy_resource_shape CHECK (
    (resource_type = 'budget_policy' AND openarc_durable.is_canonical_policy_id(resource_id)
     AND policy_id = resource_id AND policy_revision IS NULL)
    OR (resource_type = 'budget_policy_revision' AND policy_revision IS NOT NULL
        AND openarc_durable.is_canonical_policy_id(policy_id)
        AND openarc_durable.is_canonical_policy_revision(policy_revision)
        AND resource_id = policy_id || '@' || policy_revision
        AND policy_revision::numeric >= 2)
    OR (resource_type NOT IN ('budget_policy', 'budget_policy_revision'))
  );

ALTER TABLE openarc_durable.outbox_events
  DROP CONSTRAINT outbox_resource_type_valid,
  DROP CONSTRAINT outbox_event_type_valid,
  DROP CONSTRAINT outbox_resource_matches_event,
  DROP CONSTRAINT outbox_receipt_fk;

ALTER TABLE openarc_durable.outbox_events
  ADD CONSTRAINT outbox_resource_type_valid CHECK (resource_type IN (
    'organization', 'agent', 'provider', 'membership',
    'agent_credential', 'provider_credential',
    'listing', 'listing_version',
    'budget_policy', 'budget_policy_revision'
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
    'control.policy.revoked'
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
    END
  ),
  ADD CONSTRAINT outbox_receipt_fk FOREIGN KEY (
    organization_id, mutation_id, resource_type, resource_id, receipt_operation
  ) REFERENCES openarc_durable.idempotency_records (
    organization_id, mutation_id, resource_type, resource_id, operation
  ) ON DELETE RESTRICT;

ALTER TABLE openarc_durable.outbox_events
  ADD COLUMN policy_id text GENERATED ALWAYS AS (
    CASE WHEN resource_type IN ('budget_policy', 'budget_policy_revision')
         THEN split_part(resource_id, '@', 1) END
  ) STORED,
  ADD COLUMN policy_revision text GENERATED ALWAYS AS (
    CASE WHEN resource_type = 'budget_policy_revision'
         THEN split_part(resource_id, '@', 2) END
  ) STORED;

ALTER TABLE openarc_durable.outbox_events
  ADD CONSTRAINT outbox_policy_fk FOREIGN KEY (organization_id, policy_id)
    REFERENCES openarc_tenant.budget_policy_roots(organization_id, policy_id) ON DELETE RESTRICT,
  ADD CONSTRAINT outbox_policy_revision_fk FOREIGN KEY (organization_id, policy_id, policy_revision)
    REFERENCES openarc_tenant.budget_policy_versions(organization_id, policy_id, revision) ON DELETE RESTRICT,
  ADD CONSTRAINT outbox_policy_resource_shape CHECK (
    (resource_type = 'budget_policy' AND openarc_durable.is_canonical_policy_id(resource_id)
     AND policy_id = resource_id AND policy_revision IS NULL)
    OR (resource_type = 'budget_policy_revision' AND policy_revision IS NOT NULL
        AND openarc_durable.is_canonical_policy_id(policy_id)
        AND openarc_durable.is_canonical_policy_revision(policy_revision)
        AND resource_id = policy_id || '@' || policy_revision
        AND policy_revision::numeric >= 2)
    OR (resource_type NOT IN ('budget_policy', 'budget_policy_revision'))
  );

-- ---------------------------------------------------------------------------
-- Private authority preamble. Resolves the session actor/role under the accepted
-- lock order and rechecks the SAME held session after waits. Readers are
-- owner/operator/viewer (recovery allowed); writers owner/operator ONLY with
-- fresh non-recovery proof. Fake role/org GUCs never establish authority.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.lock_policy_actor(
  session_hash text,
  organization_id text,
  require_proof boolean,
  allow_recovery boolean
) RETURNS TABLE(
  out_actor text,
  out_role text
)
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
  IF require_proof IS NULL OR allow_recovery IS NULL THEN
    RAISE EXCEPTION 'policy_actor_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_canonical_org_id(organization_id) THEN
    RAISE EXCEPTION 'policy_organization_invalid' USING ERRCODE = '22023';
  END IF;
  SELECT l.account_id, l.method, l.session_created_at, l.session_expires_at
    INTO v_actor, v_method, v_created_at, v_expires_at
    FROM openarc_tenant.lock_auth_session(session_hash, NULL) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'policy_session_invalid' USING ERRCODE = '28000';
  END IF;
  IF NOT allow_recovery AND v_method = 'recovery' THEN
    RAISE EXCEPTION 'policy_session_invalid' USING ERRCODE = '28000';
  END IF;
  PERFORM 1 FROM openarc_tenant.organizations o
   WHERE o.organization_id = organization_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'policy_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT m.role, m.status INTO v_role, v_status
    FROM openarc_tenant.memberships m
   WHERE m.organization_id = organization_id AND m.account_id = v_actor FOR UPDATE;
  IF NOT FOUND OR v_status <> 'active' THEN
    RAISE EXCEPTION 'policy_forbidden' USING ERRCODE = '42501';
  END IF;
  -- Re-resolve the SAME held session after the organization/membership waits.
  SELECT l.account_id, l.method, l.session_created_at, l.session_expires_at
    INTO v_actor, v_method, v_created_at, v_expires_at
    FROM openarc_tenant.lock_auth_session(session_hash, NULL) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'policy_session_invalid' USING ERRCODE = '28000';
  END IF;
  SELECT clock_timestamp() INTO v_now;
  IF NOT (v_expires_at > v_now) THEN
    RAISE EXCEPTION 'policy_session_invalid' USING ERRCODE = '28000';
  END IF;
  IF require_proof THEN
    IF v_method = 'recovery' OR NOT (v_created_at > v_now - interval '5 minutes') THEN
      RAISE EXCEPTION 'policy_proof_stale' USING ERRCODE = '28000';
    END IF;
  END IF;
  out_actor := v_actor;
  out_role := v_role;
  RETURN NEXT;
END;
$$;

CREATE FUNCTION openarc_durable.lock_policy_writer(
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
    FROM openarc_durable.lock_policy_actor(session_hash, organization_id, true, false) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'policy_forbidden' USING ERRCODE = '42501';
  END IF;
  IF v_role NOT IN ('owner', 'operator') THEN
    RAISE EXCEPTION 'policy_forbidden' USING ERRCODE = '42501';
  END IF;
  out_actor := v_actor;
  out_role := v_role;
  RETURN NEXT;
END;
$$;

CREATE FUNCTION openarc_durable.lock_policy_reader(
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
    FROM openarc_durable.lock_policy_actor(session_hash, organization_id, false, true) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'policy_forbidden' USING ERRCODE = '42501';
  END IF;
  IF v_role NOT IN ('owner', 'operator', 'viewer') THEN
    RAISE EXCEPTION 'policy_forbidden' USING ERRCODE = '42501';
  END IF;
  out_actor := v_actor;
  out_role := v_role;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Single closed-operation mutation helper for the five control policy
-- operations. One shared transaction body; operation/resource/event are pinned
-- by the closed union. Client never supplies digest/actor/id authority.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.commit_policy_mutation(
  operation text,
  session_hash text,
  organization_id text,
  policy_id text,
  expected_revision text,
  expected_updated_at timestamptz,
  subject_agent_id text,
  network_id text,
  asset text,
  representation text,
  decimals smallint,
  per_action_limit text,
  rolling_limit text,
  rolling_window_seconds text,
  fee_limit text,
  allowed_provider_ids text[],
  allowed_listing_ids text[],
  approval_mode text,
  approval_threshold text,
  approval_separate_approver boolean,
  expires_at timestamptz,
  digest text,
  mutation_id uuid,
  key_hash text,
  request_digest text,
  session_context_digest text
) RETURNS TABLE(
  out_replayed boolean,
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
  v_role text;
  v_agent_status text;
  v_subject text;
  v_current text;
  v_status text;
  v_updated_at timestamptz;
  v_existing record;
  v_policy_id text;
  v_next text;
  v_event text;
  v_resource_type text;
  v_resource_id text;
  v_committed_at timestamptz;
  v_new_updated timestamptz;
  v_recheck text;
BEGIN
  IF operation NOT IN (
    'control.policy.create',
    'control.policy.revision.create',
    'control.policy.pause',
    'control.policy.resume',
    'control.policy.revoke'
  ) THEN
    RAISE EXCEPTION 'policy_operation_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_canonical_org_id(organization_id) THEN
    RAISE EXCEPTION 'policy_organization_invalid' USING ERRCODE = '22023';
  END IF;
  IF mutation_id IS NULL OR NOT openarc_durable.is_canonical_uuid_v4(mutation_id::text) THEN
    RAISE EXCEPTION 'policy_mutation_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_canonical_hex64(key_hash)
     OR NOT openarc_durable.is_canonical_hex64(request_digest)
     OR NOT openarc_durable.is_canonical_hex64(session_context_digest) THEN
    RAISE EXCEPTION 'policy_metadata_invalid' USING ERRCODE = '22023';
  END IF;
  IF operation <> 'control.policy.create' THEN
    IF NOT openarc_durable.is_canonical_policy_id(policy_id) THEN
      RAISE EXCEPTION 'policy_id_invalid' USING ERRCODE = '22023';
    END IF;
    IF expected_updated_at IS NULL THEN
      RAISE EXCEPTION 'policy_cas_invalid' USING ERRCODE = '22023';
    END IF;
  END IF;
  IF operation IN ('control.policy.create', 'control.policy.revision.create') THEN
    IF NOT openarc_durable.is_canonical_sha256_digest(digest) THEN
      RAISE EXCEPTION 'policy_digest_invalid' USING ERRCODE = '22023';
    END IF;
  END IF;
  IF operation <> 'control.policy.create'
     AND NOT openarc_durable.is_canonical_policy_revision(expected_revision) THEN
    RAISE EXCEPTION 'policy_revision_invalid' USING ERRCODE = '22023';
  END IF;

  SELECT l.out_actor, l.out_role INTO v_actor, v_role
    FROM openarc_durable.lock_policy_writer(session_hash, organization_id) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'policy_forbidden' USING ERRCODE = '42501';
  END IF;

  IF operation = 'control.policy.create' THEN
    v_subject := subject_agent_id;
    IF NOT openarc_durable.is_valid_policy_content(
         subject_agent_id, network_id, asset, representation, decimals,
         per_action_limit, rolling_limit, rolling_window_seconds, fee_limit,
         allowed_provider_ids, allowed_listing_ids, approval_mode,
         approval_threshold, approval_separate_approver, expires_at, clock_timestamp()) THEN
      RAISE EXCEPTION 'policy_content_invalid' USING ERRCODE = '22023';
    END IF;
    SELECT a.status INTO v_agent_status
      FROM openarc_tenant.agents a
     WHERE a.organization_id = organization_id AND a.agent_id = subject_agent_id FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'policy_not_found' USING ERRCODE = '23503';
    END IF;
    IF v_agent_status <> 'active' THEN
      RAISE EXCEPTION 'policy_forbidden' USING ERRCODE = '42501';
    END IF;
    -- Same-key replay is checked BEFORE generating the derived root id and
    -- before any content/expiry validation so it can never regenerate a
    -- replay-sensitive id.
    SELECT * INTO v_existing
      FROM openarc_durable.idempotency_records r
     WHERE r.organization_id = organization_id AND r.operation = operation
       AND r.key_hash = key_hash FOR UPDATE;
    IF FOUND THEN
      IF v_existing.request_digest = request_digest
         AND v_existing.mutation_id = mutation_id
         AND v_existing.actor_account_id = v_actor
         AND v_existing.session_context_digest = session_context_digest
         AND v_existing.status = 'committed' THEN
        SELECT l.out_actor INTO v_recheck
          FROM openarc_durable.lock_policy_writer(session_hash, organization_id) AS l;
        IF v_recheck IS NULL OR v_recheck <> v_actor THEN
          RAISE EXCEPTION 'policy_session_invalid' USING ERRCODE = '28000';
        END IF;
        out_replayed := true;
        out_mutation_id := v_existing.mutation_id;
        out_operation := v_existing.operation;
        out_resource_type := v_existing.resource_type;
        out_resource_id := v_existing.resource_id;
        out_committed_at := v_existing.committed_at;
        RETURN NEXT;
        RETURN;
      END IF;
      RAISE EXCEPTION 'policy_idempotency_conflict' USING ERRCODE = 'P0D01';
    END IF;
    PERFORM 1 FROM openarc_durable.idempotency_records r
     WHERE r.organization_id = organization_id AND r.mutation_id = mutation_id FOR UPDATE;
    IF FOUND THEN
      RAISE EXCEPTION 'policy_idempotency_conflict' USING ERRCODE = 'P0D01';
    END IF;
    IF expires_at IS NOT NULL AND NOT (expires_at > clock_timestamp()) THEN
      RAISE EXCEPTION 'policy_expiry_invalid' USING ERRCODE = '22023';
    END IF;
    v_policy_id := 'openarc:policy:' || mutation_id::text;
    IF EXISTS (SELECT 1 FROM openarc_tenant.budget_policy_roots r WHERE r.policy_id = v_policy_id) THEN
      RAISE EXCEPTION 'policy_idempotency_conflict' USING ERRCODE = 'P0D01';
    END IF;
    INSERT INTO openarc_durable.idempotency_records (
      organization_id, operation, key_hash, request_digest, digest_version,
      actor_account_id, session_context_digest, network, mutation_id, status
    ) VALUES (
      organization_id, operation, key_hash, request_digest, operation || '.v1',
      v_actor, session_context_digest, 'eip155:5042002', mutation_id, 'pending'
    );
    INSERT INTO openarc_tenant.budget_policy_roots (
      organization_id, policy_id, subject_agent_id, current_revision, status
    ) VALUES (
      organization_id, v_policy_id, subject_agent_id, '1', 'active'
    );
    INSERT INTO openarc_tenant.budget_policy_versions (
      organization_id, policy_id, revision, subject_agent_id, network_id, asset,
      representation, decimals, per_action_limit, rolling_limit,
      rolling_window_seconds, fee_limit, allowed_provider_ids,
      allowed_listing_ids, approval_mode, approval_threshold,
      approval_separate_approver, expires_at, digest
    ) VALUES (
      organization_id, v_policy_id, '1', subject_agent_id, network_id, asset,
      representation, decimals, per_action_limit, rolling_limit,
      rolling_window_seconds, fee_limit, allowed_provider_ids,
      allowed_listing_ids, approval_mode, approval_threshold,
      approval_separate_approver, expires_at, digest
    );
    v_event := 'control.policy.created';
    v_resource_type := 'budget_policy';
    v_resource_id := v_policy_id;

  ELSIF operation = 'control.policy.revision.create' THEN
    SELECT r.subject_agent_id INTO v_subject
      FROM openarc_tenant.budget_policy_roots r
     WHERE r.organization_id = organization_id AND r.policy_id = policy_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'policy_not_found' USING ERRCODE = '23503';
    END IF;
    IF subject_agent_id IS DISTINCT FROM v_subject THEN
      RAISE EXCEPTION 'policy_subject_mismatch' USING ERRCODE = '22023';
    END IF;
    SELECT a.status INTO v_agent_status
      FROM openarc_tenant.agents a
     WHERE a.organization_id = organization_id AND a.agent_id = v_subject FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'policy_not_found' USING ERRCODE = '23503';
    END IF;
    IF v_agent_status <> 'active' THEN
      RAISE EXCEPTION 'policy_forbidden' USING ERRCODE = '42501';
    END IF;
    SELECT r.current_revision, r.status, r.updated_at
      INTO v_current, v_status, v_updated_at
      FROM openarc_tenant.budget_policy_roots r
     WHERE r.organization_id = organization_id AND r.policy_id = policy_id FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'policy_not_found' USING ERRCODE = '23503';
    END IF;
    -- Same-key replay BEFORE every CAS/status/expiry check.
    SELECT * INTO v_existing
      FROM openarc_durable.idempotency_records r
     WHERE r.organization_id = organization_id AND r.operation = operation
       AND r.key_hash = key_hash FOR UPDATE;
    IF FOUND THEN
      IF v_existing.request_digest = request_digest
         AND v_existing.mutation_id = mutation_id
         AND v_existing.actor_account_id = v_actor
         AND v_existing.session_context_digest = session_context_digest
         AND v_existing.status = 'committed' THEN
        SELECT l.out_actor INTO v_recheck
          FROM openarc_durable.lock_policy_writer(session_hash, organization_id) AS l;
        IF v_recheck IS NULL OR v_recheck <> v_actor THEN
          RAISE EXCEPTION 'policy_session_invalid' USING ERRCODE = '28000';
        END IF;
        out_replayed := true;
        out_mutation_id := v_existing.mutation_id;
        out_operation := v_existing.operation;
        out_resource_type := v_existing.resource_type;
        out_resource_id := v_existing.resource_id;
        out_committed_at := v_existing.committed_at;
        RETURN NEXT;
        RETURN;
      END IF;
      RAISE EXCEPTION 'policy_idempotency_conflict' USING ERRCODE = 'P0D01';
    END IF;
    PERFORM 1 FROM openarc_durable.idempotency_records r
     WHERE r.organization_id = organization_id AND r.mutation_id = mutation_id FOR UPDATE;
    IF FOUND THEN
      RAISE EXCEPTION 'policy_idempotency_conflict' USING ERRCODE = 'P0D01';
    END IF;
    IF v_status = 'revoked' THEN
      RAISE EXCEPTION 'policy_revoked' USING ERRCODE = '23514';
    END IF;
    IF NOT openarc_durable.is_valid_policy_content(
         subject_agent_id, network_id, asset, representation, decimals,
         per_action_limit, rolling_limit, rolling_window_seconds, fee_limit,
         allowed_provider_ids, allowed_listing_ids, approval_mode,
         approval_threshold, approval_separate_approver, expires_at, clock_timestamp()) THEN
      RAISE EXCEPTION 'policy_content_invalid' USING ERRCODE = '22023';
    END IF;
    IF expires_at IS NOT NULL AND NOT (expires_at > clock_timestamp()) THEN
      RAISE EXCEPTION 'policy_expiry_invalid' USING ERRCODE = '22023';
    END IF;
    IF v_current::numeric >= 999999999 THEN
      RAISE EXCEPTION 'policy_revision_exhausted' USING ERRCODE = '22003';
    END IF;
    IF v_current IS DISTINCT FROM expected_revision OR v_updated_at IS DISTINCT FROM expected_updated_at THEN
      RAISE EXCEPTION 'policy_cas_conflict' USING ERRCODE = '23505';
    END IF;
    v_next := (v_current::numeric + 1)::text;
    v_new_updated := GREATEST(clock_timestamp(), expected_updated_at + interval '1 microsecond');
    INSERT INTO openarc_durable.idempotency_records (
      organization_id, operation, key_hash, request_digest, digest_version,
      actor_account_id, session_context_digest, network, mutation_id, status
    ) VALUES (
      organization_id, operation, key_hash, request_digest, operation || '.v1',
      v_actor, session_context_digest, 'eip155:5042002', mutation_id, 'pending'
    );
    INSERT INTO openarc_tenant.budget_policy_versions (
      organization_id, policy_id, revision, subject_agent_id, network_id, asset,
      representation, decimals, per_action_limit, rolling_limit,
      rolling_window_seconds, fee_limit, allowed_provider_ids,
      allowed_listing_ids, approval_mode, approval_threshold,
      approval_separate_approver, expires_at, digest
    ) VALUES (
      organization_id, policy_id, v_next, subject_agent_id, network_id, asset,
      representation, decimals, per_action_limit, rolling_limit,
      rolling_window_seconds, fee_limit, allowed_provider_ids,
      allowed_listing_ids, approval_mode, approval_threshold,
      approval_separate_approver, expires_at, digest
    );
    UPDATE openarc_tenant.budget_policy_roots r
       SET current_revision = v_next, updated_at = v_new_updated
     WHERE r.organization_id = organization_id AND r.policy_id = policy_id
       AND r.current_revision = expected_revision AND r.updated_at = expected_updated_at;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'policy_cas_conflict' USING ERRCODE = '23505';
    END IF;
    v_event := 'control.policy.revision.created';
    v_resource_type := 'budget_policy_revision';
    v_resource_id := policy_id || '@' || v_next;

  ELSE
    -- pause / resume / revoke share one CAS+status path.
    SELECT r.subject_agent_id INTO v_subject
      FROM openarc_tenant.budget_policy_roots r
     WHERE r.organization_id = organization_id AND r.policy_id = policy_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'policy_not_found' USING ERRCODE = '23503';
    END IF;
    PERFORM 1 FROM openarc_tenant.agents a
     WHERE a.organization_id = organization_id AND a.agent_id = v_subject FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'policy_not_found' USING ERRCODE = '23503';
    END IF;
    SELECT r.current_revision, r.status, r.updated_at
      INTO v_current, v_status, v_updated_at
      FROM openarc_tenant.budget_policy_roots r
     WHERE r.organization_id = organization_id AND r.policy_id = policy_id FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'policy_not_found' USING ERRCODE = '23503';
    END IF;
    -- Same-key replay BEFORE the current status/CAS/expiry checks so a receipt
    -- stays recoverable after the root was later paused/resumed/revoked.
    SELECT * INTO v_existing
      FROM openarc_durable.idempotency_records r
     WHERE r.organization_id = organization_id AND r.operation = operation
       AND r.key_hash = key_hash FOR UPDATE;
    IF FOUND THEN
      IF v_existing.request_digest = request_digest
         AND v_existing.mutation_id = mutation_id
         AND v_existing.actor_account_id = v_actor
         AND v_existing.session_context_digest = session_context_digest
         AND v_existing.status = 'committed' THEN
        SELECT l.out_actor INTO v_recheck
          FROM openarc_durable.lock_policy_writer(session_hash, organization_id) AS l;
        IF v_recheck IS NULL OR v_recheck <> v_actor THEN
          RAISE EXCEPTION 'policy_session_invalid' USING ERRCODE = '28000';
        END IF;
        out_replayed := true;
        out_mutation_id := v_existing.mutation_id;
        out_operation := v_existing.operation;
        out_resource_type := v_existing.resource_type;
        out_resource_id := v_existing.resource_id;
        out_committed_at := v_existing.committed_at;
        RETURN NEXT;
        RETURN;
      END IF;
      RAISE EXCEPTION 'policy_idempotency_conflict' USING ERRCODE = 'P0D01';
    END IF;
    PERFORM 1 FROM openarc_durable.idempotency_records r
     WHERE r.organization_id = organization_id AND r.mutation_id = mutation_id FOR UPDATE;
    IF FOUND THEN
      RAISE EXCEPTION 'policy_idempotency_conflict' USING ERRCODE = 'P0D01';
    END IF;
    IF operation = 'control.policy.pause' THEN
      IF v_status <> 'active' THEN
        RAISE EXCEPTION 'policy_pause_invalid' USING ERRCODE = '23514';
      END IF;
    ELSIF operation = 'control.policy.resume' THEN
      IF v_status <> 'paused' THEN
        RAISE EXCEPTION 'policy_resume_invalid' USING ERRCODE = '23514';
      END IF;
      -- The current revision content must not be expired to resume.
      IF EXISTS (
        SELECT 1 FROM openarc_tenant.budget_policy_versions v
         WHERE v.organization_id = organization_id AND v.policy_id = policy_id
           AND v.revision = v_current
           AND v.expires_at IS NOT NULL
           AND NOT (v.expires_at > clock_timestamp())
      ) THEN
        RAISE EXCEPTION 'policy_expired' USING ERRCODE = '23514';
      END IF;
    ELSE
      IF v_status NOT IN ('active', 'paused') THEN
        RAISE EXCEPTION 'policy_revoke_invalid' USING ERRCODE = '23514';
      END IF;
    END IF;
    IF v_current IS DISTINCT FROM expected_revision OR v_updated_at IS DISTINCT FROM expected_updated_at THEN
      RAISE EXCEPTION 'policy_cas_conflict' USING ERRCODE = '23505';
    END IF;
    v_new_updated := GREATEST(clock_timestamp(), expected_updated_at + interval '1 microsecond');
    INSERT INTO openarc_durable.idempotency_records (
      organization_id, operation, key_hash, request_digest, digest_version,
      actor_account_id, session_context_digest, network, mutation_id, status
    ) VALUES (
      organization_id, operation, key_hash, request_digest, operation || '.v1',
      v_actor, session_context_digest, 'eip155:5042002', mutation_id, 'pending'
    );
    UPDATE openarc_tenant.budget_policy_roots r
       SET status = CASE operation
             WHEN 'control.policy.pause' THEN 'paused'
             WHEN 'control.policy.resume' THEN 'active'
             ELSE 'revoked'
           END,
           updated_at = v_new_updated
     WHERE r.organization_id = organization_id AND r.policy_id = policy_id
       AND r.current_revision = expected_revision AND r.updated_at = expected_updated_at;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'policy_cas_conflict' USING ERRCODE = '23505';
    END IF;
    v_event := CASE operation
      WHEN 'control.policy.pause' THEN 'control.policy.paused'
      WHEN 'control.policy.resume' THEN 'control.policy.resumed'
      ELSE 'control.policy.revoked'
    END;
    v_resource_type := 'budget_policy';
    v_resource_id := policy_id;
  END IF;

  UPDATE openarc_durable.idempotency_records r
     SET status = 'committed', resource_type = v_resource_type,
         resource_id = v_resource_id, committed_at = clock_timestamp()
   WHERE r.organization_id = organization_id AND r.operation = operation
     AND r.key_hash = key_hash
   RETURNING r.committed_at INTO v_committed_at;

  INSERT INTO openarc_durable.audit_events (
    organization_id, actor_account_id, operation, mutation_id, resource_type, resource_id, outcome
  ) VALUES (
    organization_id, v_actor, operation, mutation_id, v_resource_type, v_resource_id, 'committed'
  );
  INSERT INTO openarc_durable.outbox_events (
    organization_id, mutation_id, resource_type, resource_id, event_type, payload_version
  ) VALUES (
    organization_id, mutation_id, v_resource_type, v_resource_id, v_event, 1
  );

  SELECT l.out_actor INTO v_recheck
    FROM openarc_durable.lock_policy_writer(session_hash, organization_id) AS l;
  IF v_recheck IS NULL OR v_recheck <> v_actor THEN
    RAISE EXCEPTION 'policy_session_invalid' USING ERRCODE = '28000';
  END IF;
  IF operation IN ('control.policy.create', 'control.policy.revision.create') THEN
    SELECT a.status INTO v_agent_status
      FROM openarc_tenant.agents a
     WHERE a.organization_id = organization_id AND a.agent_id = v_subject;
    IF v_agent_status IS NULL OR v_agent_status <> 'active' THEN
      RAISE EXCEPTION 'policy_forbidden' USING ERRCODE = '42501';
    END IF;
  END IF;

  out_replayed := false;
  out_mutation_id := mutation_id;
  out_operation := operation;
  out_resource_type := v_resource_type;
  out_resource_id := v_resource_id;
  out_committed_at := v_committed_at;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Read helpers. Owner/operator/viewer; recovery sessions may read. Every read
-- rechecks the held session after the result query, even for empty/missing.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.read_policy_root(
  session_hash text,
  organization_id text,
  policy_id text
) RETURNS TABLE(
  out_policy_id text,
  out_organization_id text,
  out_subject_agent_id text,
  out_current_revision text,
  out_status text,
  out_created_at timestamptz,
  out_updated_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_actor text;
  v_recheck text;
BEGIN
  IF NOT openarc_durable.is_canonical_policy_id(policy_id) THEN
    RAISE EXCEPTION 'policy_id_invalid' USING ERRCODE = '22023';
  END IF;
  SELECT l.out_actor INTO v_actor
    FROM openarc_durable.lock_policy_reader(session_hash, organization_id) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'policy_forbidden' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
    SELECT r.policy_id, r.organization_id, r.subject_agent_id, r.current_revision,
           r.status, r.created_at, r.updated_at
      FROM openarc_tenant.budget_policy_roots r
     WHERE r.organization_id = organization_id AND r.policy_id = policy_id;
  SELECT l.out_actor INTO v_recheck
    FROM openarc_durable.lock_policy_reader(session_hash, organization_id) AS l;
  IF v_recheck IS NULL OR v_recheck <> v_actor THEN
    RAISE EXCEPTION 'policy_session_invalid' USING ERRCODE = '28000';
  END IF;
END;
$$;

CREATE FUNCTION openarc_durable.list_policy_roots(
  session_hash text,
  organization_id text,
  after_policy_id text,
  page_limit integer
) RETURNS TABLE(
  out_policy_id text,
  out_organization_id text,
  out_subject_agent_id text,
  out_current_revision text,
  out_status text,
  out_created_at timestamptz,
  out_updated_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_actor text;
  v_recheck text;
  v_limit integer;
BEGIN
  IF page_limit IS NULL OR page_limit < 1 OR page_limit > 51 THEN
    RAISE EXCEPTION 'policy_page_invalid' USING ERRCODE = '22023';
  END IF;
  IF after_policy_id IS NOT NULL AND NOT openarc_durable.is_canonical_policy_id(after_policy_id) THEN
    RAISE EXCEPTION 'policy_page_invalid' USING ERRCODE = '22023';
  END IF;
  v_limit := page_limit;
  SELECT l.out_actor INTO v_actor
    FROM openarc_durable.lock_policy_reader(session_hash, organization_id) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'policy_forbidden' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
    SELECT r.policy_id, r.organization_id, r.subject_agent_id, r.current_revision,
           r.status, r.created_at, r.updated_at
      FROM openarc_tenant.budget_policy_roots r
     WHERE r.organization_id = organization_id
       AND (after_policy_id IS NULL OR r.policy_id > after_policy_id)
     ORDER BY r.policy_id
     LIMIT v_limit;
  SELECT l.out_actor INTO v_recheck
    FROM openarc_durable.lock_policy_reader(session_hash, organization_id) AS l;
  IF v_recheck IS NULL OR v_recheck <> v_actor THEN
    RAISE EXCEPTION 'policy_session_invalid' USING ERRCODE = '28000';
  END IF;
END;
$$;

CREATE FUNCTION openarc_durable.read_policy_revision(
  session_hash text,
  organization_id text,
  policy_id text,
  revision text
) RETURNS TABLE(
  out_policy_id text,
  out_organization_id text,
  out_revision text,
  out_subject_agent_id text,
  out_network_id text,
  out_asset text,
  out_representation text,
  out_decimals smallint,
  out_per_action_limit text,
  out_rolling_limit text,
  out_rolling_window_seconds text,
  out_fee_limit text,
  out_allowed_provider_ids text[],
  out_allowed_listing_ids text[],
  out_approval_mode text,
  out_approval_threshold text,
  out_approval_separate_approver boolean,
  out_expires_at timestamptz,
  out_digest text,
  out_created_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_actor text;
  v_recheck text;
BEGIN
  IF NOT openarc_durable.is_canonical_policy_id(policy_id) THEN
    RAISE EXCEPTION 'policy_id_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_canonical_policy_revision(revision) THEN
    RAISE EXCEPTION 'policy_revision_invalid' USING ERRCODE = '22023';
  END IF;
  SELECT l.out_actor INTO v_actor
    FROM openarc_durable.lock_policy_reader(session_hash, organization_id) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'policy_forbidden' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
    SELECT v.policy_id, v.organization_id, v.revision, v.subject_agent_id,
           v.network_id, v.asset, v.representation, v.decimals,
           v.per_action_limit, v.rolling_limit, v.rolling_window_seconds,
           v.fee_limit, v.allowed_provider_ids, v.allowed_listing_ids,
           v.approval_mode, v.approval_threshold, v.approval_separate_approver,
           v.expires_at, v.digest, v.created_at
      FROM openarc_tenant.budget_policy_versions v
     WHERE v.organization_id = organization_id AND v.policy_id = policy_id
       AND v.revision = revision;
  SELECT l.out_actor INTO v_recheck
    FROM openarc_durable.lock_policy_reader(session_hash, organization_id) AS l;
  IF v_recheck IS NULL OR v_recheck <> v_actor THEN
    RAISE EXCEPTION 'policy_session_invalid' USING ERRCODE = '28000';
  END IF;
END;
$$;

-- History is bounded to exact metadata summaries only (no allowlists/content).
CREATE FUNCTION openarc_durable.list_policy_revisions(
  session_hash text,
  organization_id text,
  policy_id text,
  after_revision text,
  page_limit integer
) RETURNS TABLE(
  out_policy_id text,
  out_organization_id text,
  out_subject_agent_id text,
  out_revision text,
  out_digest text,
  out_created_at timestamptz,
  out_expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_actor text;
  v_recheck text;
  v_limit integer;
BEGIN
  IF page_limit IS NULL OR page_limit < 1 OR page_limit > 51 THEN
    RAISE EXCEPTION 'policy_page_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_canonical_policy_id(policy_id) THEN
    RAISE EXCEPTION 'policy_id_invalid' USING ERRCODE = '22023';
  END IF;
  IF after_revision IS NOT NULL AND NOT openarc_durable.is_canonical_policy_revision(after_revision) THEN
    RAISE EXCEPTION 'policy_page_invalid' USING ERRCODE = '22023';
  END IF;
  v_limit := page_limit;
  SELECT l.out_actor INTO v_actor
    FROM openarc_durable.lock_policy_reader(session_hash, organization_id) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'policy_forbidden' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
    SELECT v.policy_id, v.organization_id, v.subject_agent_id, v.revision,
           v.digest, v.created_at, v.expires_at
      FROM openarc_tenant.budget_policy_versions v
     WHERE v.organization_id = organization_id AND v.policy_id = policy_id
       AND (after_revision IS NULL OR v.revision::numeric > after_revision::numeric)
     ORDER BY v.revision::numeric
     LIMIT v_limit;
  SELECT l.out_actor INTO v_recheck
    FROM openarc_durable.lock_policy_reader(session_hash, organization_id) AS l;
  IF v_recheck IS NULL OR v_recheck <> v_actor THEN
    RAISE EXCEPTION 'policy_session_invalid' USING ERRCODE = '28000';
  END IF;
END;
$$;

CREATE FUNCTION openarc_durable.read_policy_mutation_status(
  session_hash text,
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
  v_recheck text;
  v_found boolean := false;
  v_mutation_id uuid;
  v_operation text;
  v_resource_type text;
  v_resource_id text;
  v_committed_at timestamptz;
BEGIN
  IF NOT openarc_durable.is_canonical_org_id(organization_id) THEN
    RAISE EXCEPTION 'policy_organization_invalid' USING ERRCODE = '22023';
  END IF;
  IF mutation_id IS NULL THEN
    RAISE EXCEPTION 'policy_mutation_invalid' USING ERRCODE = '22023';
  END IF;
  SELECT l.out_actor INTO v_actor
    FROM openarc_durable.lock_policy_reader(session_hash, organization_id) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'policy_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT r.mutation_id, r.operation, r.resource_type, r.resource_id, r.committed_at
    INTO v_mutation_id, v_operation, v_resource_type, v_resource_id, v_committed_at
    FROM openarc_durable.idempotency_records r
   WHERE r.organization_id = organization_id AND r.mutation_id = mutation_id
     AND r.actor_account_id = v_actor AND r.status = 'committed'
     -- Exact presented session-context binding: the recorded digest must equal
     -- sha256(domain || ':' || session_hash) for THIS presenting session and the
     -- row's operation, byte-for-byte with TS digestPolicySessionContext. A
     -- different live session for the same account can never recover the
     -- receipt from account identity or session liveness alone.
     AND r.session_context_digest = encode(
       sha256(convert_to(
         (CASE r.operation
            WHEN 'control.policy.create' THEN 'openarc.control.policy.create.session.v1'
            WHEN 'control.policy.revision.create' THEN 'openarc.control.policy.revision.create.session.v1'
            WHEN 'control.policy.pause' THEN 'openarc.control.policy.pause.session.v1'
            WHEN 'control.policy.resume' THEN 'openarc.control.policy.resume.session.v1'
            WHEN 'control.policy.revoke' THEN 'openarc.control.policy.revoke.session.v1'
          END) || ':' || session_hash,
         'UTF8'
       )),
       'hex'
     )
     AND r.operation IN (
       'control.policy.create',
       'control.policy.revision.create',
       'control.policy.pause',
       'control.policy.resume',
       'control.policy.revoke'
     );
  v_found := FOUND;
  SELECT l.out_actor INTO v_recheck
    FROM openarc_durable.lock_policy_reader(session_hash, organization_id) AS l;
  IF v_recheck IS NULL OR v_recheck <> v_actor THEN
    RAISE EXCEPTION 'policy_session_invalid' USING ERRCODE = '28000';
  END IF;
  IF NOT v_found THEN
    RETURN;
  END IF;
  out_mutation_id := v_mutation_id;
  out_operation := v_operation;
  out_resource_type := v_resource_type;
  out_resource_id := v_resource_id;
  out_committed_at := v_committed_at;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- ACLs: PUBLIC gets nothing; only the restricted runtime may execute the
-- public helpers. Internal validators/private preamble remain grant-free.
-- ---------------------------------------------------------------------------
REVOKE ALL ON FUNCTION openarc_durable.is_canonical_policy_id(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.is_canonical_agent_id(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.is_canonical_provider_id(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.is_canonical_policy_revision(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.is_canonical_uint256(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.is_positive_uint256(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.is_valid_policy_provider_list(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.is_valid_policy_listing_list(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.is_valid_policy_approval(text, text, boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.is_valid_policy_content(text, text, text, text, smallint, text, text, text, text, text[], text[], text, text, boolean, timestamptz, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.assert_policy_content(text, text, text, text, smallint, text, text, text, text, text[], text[], text, text, boolean, timestamptz, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_tenant.reject_policy_version_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_tenant.enforce_policy_root_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.lock_policy_actor(text, text, boolean, boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.lock_policy_writer(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.lock_policy_reader(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.commit_policy_mutation(text, text, text, text, text, timestamptz, text, text, text, text, smallint, text, text, text, text, text[], text[], text, text, boolean, timestamptz, text, uuid, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.read_policy_root(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.list_policy_roots(text, text, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.read_policy_revision(text, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.list_policy_revisions(text, text, text, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.read_policy_mutation_status(text, text, uuid) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION openarc_durable.lock_policy_writer(text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.lock_policy_reader(text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.commit_policy_mutation(text, text, text, text, text, timestamptz, text, text, text, text, smallint, text, text, text, text, text[], text[], text, text, boolean, timestamptz, text, uuid, text, text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.read_policy_root(text, text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.list_policy_roots(text, text, text, integer) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.read_policy_revision(text, text, text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.list_policy_revisions(text, text, text, text, integer) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.read_policy_mutation_status(text, text, uuid) TO openarc_tenant_app;
