-- OpenArc explicit commerce-session persistence (schema9).
-- Additive over schema8. Owner: openarc_migrator. Runtime: openarc_tenant_app.
-- Two forced-RLS migrator-owned tables in openarc_durable plus narrow definer
-- helpers. This migration NEVER creates roles/schemas, reserves money, calls a
-- provider or records a payment. It stores the explicit, one-exchange
-- commerce-session binding only; it is not spend authority.

-- ---------------------------------------------------------------------------
-- Shared canonical validators for the commerce-session surface.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.is_canonical_commerce_session_id(value text)
RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT value IS NOT NULL
     AND value ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
$$;

-- ---------------------------------------------------------------------------
-- commerce_sessions: immutable sponsoring human identity (account + exact auth
-- session hash), subject agent, exact policy, scope/network/asset shape and the
-- one-time agent session + credential binding installed atomically on first
-- exchange. There is deliberately NO foreign key to openarc_auth.sessions: a
-- human logout/recovery deletes that parent and MUST NOT delete commerce
-- history, and RESTRICT would break logout. The retained hash+account are the
-- immutable validated evidence; a missing/deleted parent merely invalidates
-- future authority.
-- ---------------------------------------------------------------------------
CREATE TABLE openarc_durable.commerce_sessions (
  organization_id text NOT NULL,
  session_id uuid NOT NULL,
  parent_human_session_hash text NOT NULL,
  parent_human_account_id text NOT NULL REFERENCES openarc_auth.accounts(account_id) ON DELETE RESTRICT,
  subject_agent_id text NOT NULL,
  policy_id text NOT NULL,
  scope text NOT NULL,
  scope_version integer NOT NULL DEFAULT 1,
  network_id text NOT NULL,
  asset text NOT NULL,
  representation text NOT NULL,
  decimals smallint NOT NULL,
  issued_at timestamptz NOT NULL,
  initial_expires_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  exchanged_at timestamptz,
  agent_session_id uuid,
  credential_id uuid,
  revoked_at timestamptz,
  PRIMARY KEY (organization_id, session_id),
  CONSTRAINT commerce_sessions_session_unique UNIQUE (session_id),
  CONSTRAINT commerce_sessions_org_fk FOREIGN KEY (organization_id)
    REFERENCES openarc_tenant.organizations(organization_id) ON DELETE RESTRICT,
  CONSTRAINT commerce_sessions_subject_fk FOREIGN KEY (organization_id, subject_agent_id)
    REFERENCES openarc_tenant.agents(organization_id, agent_id) ON DELETE RESTRICT,
  CONSTRAINT commerce_sessions_policy_fk FOREIGN KEY (organization_id, policy_id)
    REFERENCES openarc_tenant.budget_policy_roots(organization_id, policy_id) ON DELETE RESTRICT,
  CONSTRAINT commerce_sessions_credential_fk FOREIGN KEY (organization_id, credential_id)
    REFERENCES openarc_durable.agent_credentials(organization_id, credential_id) ON DELETE RESTRICT,
  CONSTRAINT commerce_sessions_agent_session_fk FOREIGN KEY (agent_session_id)
    REFERENCES openarc_durable.agent_sessions(session_id) ON DELETE RESTRICT,
  CONSTRAINT commerce_sessions_id_valid CHECK (openarc_durable.is_canonical_commerce_session_id(session_id::text)),
  CONSTRAINT commerce_sessions_parent_hash_valid CHECK (openarc_durable.is_canonical_hex64(parent_human_session_hash)),
  CONSTRAINT commerce_sessions_subject_valid CHECK (openarc_durable.is_canonical_agent_id(subject_agent_id)),
  CONSTRAINT commerce_sessions_policy_valid CHECK (openarc_durable.is_canonical_policy_id(policy_id)),
  CONSTRAINT commerce_sessions_scope_valid CHECK (scope = 'commerce.authorize' AND scope_version = 1),
  CONSTRAINT commerce_sessions_network_valid CHECK (
    network_id = 'eip155:5042002' AND asset = 'USDC' AND representation = 'erc20' AND decimals = 6
  ),
  CONSTRAINT commerce_sessions_issuance_window CHECK (
    initial_expires_at > issued_at AND initial_expires_at <= issued_at + interval '900 seconds'
  ),
  CONSTRAINT commerce_sessions_expiry_valid CHECK (
    expires_at > issued_at AND expires_at <= initial_expires_at
  ),
  CONSTRAINT commerce_sessions_exchange_shape CHECK (
    (agent_session_id IS NULL AND credential_id IS NULL AND exchanged_at IS NULL)
    OR (agent_session_id IS NOT NULL AND credential_id IS NOT NULL AND exchanged_at IS NOT NULL
        AND exchanged_at >= issued_at AND exchanged_at < initial_expires_at
        AND exchanged_at <= expires_at)
  ),
  CONSTRAINT commerce_sessions_revocation_shape CHECK (
    revoked_at IS NULL
    OR (revoked_at >= issued_at
        AND (exchanged_at IS NULL OR revoked_at >= exchanged_at))
  )
);

-- ---------------------------------------------------------------------------
-- commerce_session_handoffs: exactly one row per session. The raw handoff
-- secret is represented only by its canonical hash. Handoff expiry is at most
-- issued+300s and never beyond the session's INITIAL expiry. The session token
-- hash is NULL until the single exchange and immutable thereafter.
-- ---------------------------------------------------------------------------
CREATE TABLE openarc_durable.commerce_session_handoffs (
  handoff_hash text NOT NULL,
  organization_id text NOT NULL,
  session_id uuid NOT NULL,
  hash_version integer NOT NULL DEFAULT 1,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  token_hash text,
  token_hash_version integer,
  PRIMARY KEY (handoff_hash),
  CONSTRAINT commerce_session_handoffs_session_unique UNIQUE (organization_id, session_id),
  CONSTRAINT commerce_session_handoffs_session_fk FOREIGN KEY (organization_id, session_id)
    REFERENCES openarc_durable.commerce_sessions(organization_id, session_id) ON DELETE RESTRICT,
  CONSTRAINT commerce_session_handoffs_token_unique UNIQUE (token_hash),
  CONSTRAINT commerce_session_handoffs_hash_valid CHECK (openarc_durable.is_canonical_hex64(handoff_hash)),
  CONSTRAINT commerce_session_handoffs_hash_version_valid CHECK (hash_version = 1),
  CONSTRAINT commerce_session_handoffs_window CHECK (
    expires_at > issued_at AND expires_at <= issued_at + interval '300 seconds'
  ),
  CONSTRAINT commerce_session_handoffs_consumption_shape CHECK (
    (consumed_at IS NULL AND token_hash IS NULL AND token_hash_version IS NULL)
    OR (consumed_at IS NOT NULL AND consumed_at >= issued_at
        AND token_hash IS NOT NULL AND openarc_durable.is_canonical_hex64(token_hash)
        AND token_hash_version = 1
        AND consumed_at <= expires_at)
  )
);

CREATE INDEX commerce_sessions_org_idx
  ON openarc_durable.commerce_sessions (organization_id, session_id);

-- ---------------------------------------------------------------------------
-- Immutability. The sponsorship identity, subject, policy and scope are frozen
-- at issue. Only the single exchange binding and a monotone shorten of
-- expires_at and the one-time revocation are accepted; every other change and
-- every delete is rejected.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.enforce_commerce_session_mutation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'commerce_session_immutable' USING ERRCODE = '42501';
  END IF;
  IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
     OR NEW.session_id IS DISTINCT FROM OLD.session_id
     OR NEW.parent_human_session_hash IS DISTINCT FROM OLD.parent_human_session_hash
     OR NEW.parent_human_account_id IS DISTINCT FROM OLD.parent_human_account_id
     OR NEW.subject_agent_id IS DISTINCT FROM OLD.subject_agent_id
     OR NEW.policy_id IS DISTINCT FROM OLD.policy_id
     OR NEW.scope IS DISTINCT FROM OLD.scope
     OR NEW.scope_version IS DISTINCT FROM OLD.scope_version
     OR NEW.network_id IS DISTINCT FROM OLD.network_id
     OR NEW.asset IS DISTINCT FROM OLD.asset
     OR NEW.representation IS DISTINCT FROM OLD.representation
     OR NEW.decimals IS DISTINCT FROM OLD.decimals
     OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
     OR NEW.initial_expires_at IS DISTINCT FROM OLD.initial_expires_at THEN
    RAISE EXCEPTION 'commerce_session_immutable' USING ERRCODE = '42501';
  END IF;
  -- expires_at may only be shortened (never extended past the issuance bound).
  IF NEW.expires_at > OLD.expires_at OR NEW.expires_at <= OLD.issued_at THEN
    RAISE EXCEPTION 'commerce_session_expiry_invalid' USING ERRCODE = '23514';
  END IF;
  -- The exchange binding is installed exactly once and is immutable after.
  IF OLD.exchanged_at IS NOT NULL THEN
    IF NEW.exchanged_at IS DISTINCT FROM OLD.exchanged_at
       OR NEW.agent_session_id IS DISTINCT FROM OLD.agent_session_id
       OR NEW.credential_id IS DISTINCT FROM OLD.credential_id THEN
      RAISE EXCEPTION 'commerce_session_binding_immutable' USING ERRCODE = '42501';
    END IF;
  ELSIF NEW.exchanged_at IS NOT NULL THEN
    IF NEW.exchanged_at < OLD.issued_at OR NEW.exchanged_at > OLD.expires_at THEN
      RAISE EXCEPTION 'commerce_session_exchange_invalid' USING ERRCODE = '23514';
    END IF;
    IF NEW.agent_session_id IS NULL OR NEW.credential_id IS NULL THEN
      RAISE EXCEPTION 'commerce_session_exchange_invalid' USING ERRCODE = '23514';
    END IF;
  ELSIF NEW.agent_session_id IS NOT NULL OR NEW.credential_id IS NOT NULL THEN
    RAISE EXCEPTION 'commerce_session_exchange_invalid' USING ERRCODE = '23514';
  END IF;
  -- Revocation is one-way and terminal.
  IF OLD.revoked_at IS NOT NULL THEN
    IF NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
      RAISE EXCEPTION 'commerce_session_revocation_immutable' USING ERRCODE = '42501';
    END IF;
  ELSIF NEW.revoked_at IS NOT NULL AND NEW.revoked_at < OLD.issued_at THEN
    RAISE EXCEPTION 'commerce_session_revocation_invalid' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER commerce_sessions_mutation
  BEFORE UPDATE OR DELETE ON openarc_durable.commerce_sessions
  FOR EACH ROW EXECUTE FUNCTION openarc_durable.enforce_commerce_session_mutation();

-- ---------------------------------------------------------------------------
-- Handoff immutability: append-once; only the single consumption transition
-- may set consumed_at/token_hash. No delete.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.enforce_commerce_handoff_mutation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'commerce_handoff_immutable' USING ERRCODE = '42501';
  END IF;
  IF NEW.handoff_hash IS DISTINCT FROM OLD.handoff_hash
     OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
     OR NEW.session_id IS DISTINCT FROM OLD.session_id
     OR NEW.hash_version IS DISTINCT FROM OLD.hash_version
     OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
    RAISE EXCEPTION 'commerce_handoff_immutable' USING ERRCODE = '42501';
  END IF;
  IF OLD.consumed_at IS NOT NULL THEN
    IF NEW.consumed_at IS DISTINCT FROM OLD.consumed_at
       OR NEW.token_hash IS DISTINCT FROM OLD.token_hash
       OR NEW.token_hash_version IS DISTINCT FROM OLD.token_hash_version THEN
      RAISE EXCEPTION 'commerce_handoff_consumed' USING ERRCODE = '42501';
    END IF;
  ELSIF NEW.consumed_at IS NOT NULL THEN
    IF NEW.token_hash IS NULL OR NEW.token_hash_version IS DISTINCT FROM 1 THEN
      RAISE EXCEPTION 'commerce_handoff_consumption_invalid' USING ERRCODE = '23514';
    END IF;
  ELSIF NEW.token_hash IS NOT NULL OR NEW.token_hash_version IS NOT NULL THEN
    RAISE EXCEPTION 'commerce_handoff_consumption_invalid' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER commerce_session_handoffs_mutation
  BEFORE UPDATE OR DELETE ON openarc_durable.commerce_session_handoffs
  FOR EACH ROW EXECUTE FUNCTION openarc_durable.enforce_commerce_handoff_mutation();

-- Handoff expiry may never exceed the session's INITIAL expiry. This is a
-- cross-row relationship, so it is enforced by trigger (an FK/table CHECK
-- cannot reference another row).
CREATE FUNCTION openarc_durable.enforce_commerce_handoff_window() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_initial timestamptz;
BEGIN
  SELECT s.initial_expires_at INTO v_initial
    FROM openarc_durable.commerce_sessions s
   WHERE s.organization_id = NEW.organization_id AND s.session_id = NEW.session_id;
  IF v_initial IS NULL THEN
    RAISE EXCEPTION 'commerce_handoff_session_missing' USING ERRCODE = '23503';
  END IF;
  IF NEW.expires_at > v_initial THEN
    RAISE EXCEPTION 'commerce_handoff_window_invalid' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER commerce_session_handoffs_window
  BEFORE INSERT ON openarc_durable.commerce_session_handoffs
  FOR EACH ROW EXECUTE FUNCTION openarc_durable.enforce_commerce_handoff_window();

-- Exchange binding must be the same organization/agent as the session and name
-- the credential that issued the exact bound machine session. The reference is
-- resolved server-side under lock and re-verified here.
CREATE FUNCTION openarc_durable.enforce_commerce_session_binding() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_agent_id text;
  v_credential_id uuid;
BEGIN
  IF NEW.exchanged_at IS NULL OR OLD.exchanged_at IS NOT NULL THEN
    RETURN NEW;
  END IF;
  SELECT s.agent_id, s.credential_id INTO v_agent_id, v_credential_id
    FROM openarc_durable.agent_sessions s
   WHERE s.session_id = NEW.agent_session_id AND s.organization_id = NEW.organization_id;
  IF v_agent_id IS NULL THEN
    RAISE EXCEPTION 'commerce_session_agent_session_invalid' USING ERRCODE = '23503';
  END IF;
  IF v_agent_id <> NEW.subject_agent_id OR v_credential_id <> NEW.credential_id THEN
    RAISE EXCEPTION 'commerce_session_binding_mismatch' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER commerce_sessions_binding
  BEFORE UPDATE ON openarc_durable.commerce_sessions
  FOR EACH ROW EXECUTE FUNCTION openarc_durable.enforce_commerce_session_binding();

ALTER TABLE openarc_durable.commerce_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE openarc_durable.commerce_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE openarc_durable.commerce_session_handoffs ENABLE ROW LEVEL SECURITY;
ALTER TABLE openarc_durable.commerce_session_handoffs FORCE ROW LEVEL SECURITY;

CREATE POLICY commerce_sessions_migrator ON openarc_durable.commerce_sessions
  FOR ALL TO openarc_migrator USING (true) WITH CHECK (true);
CREATE POLICY commerce_session_handoffs_migrator ON openarc_durable.commerce_session_handoffs
  FOR ALL TO openarc_migrator USING (true) WITH CHECK (true);

REVOKE ALL ON TABLE openarc_durable.commerce_sessions FROM PUBLIC;
REVOKE ALL ON TABLE openarc_durable.commerce_session_handoffs FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Closed operation / resource / event union extensions. All old tuples are
-- retained verbatim; only commerce-session tuples are appended.
-- ---------------------------------------------------------------------------
ALTER TABLE openarc_durable.idempotency_records
  DROP CONSTRAINT idempotency_operation_valid,
  DROP CONSTRAINT idempotency_digest_version_valid,
  DROP CONSTRAINT idempotency_resource_type_valid,
  DROP CONSTRAINT idempotency_resource_matches_operation,
  DROP CONSTRAINT idempotency_market_resource_shape,
  DROP CONSTRAINT idempotency_policy_resource_shape;

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
    'control.commerce_session.revoke'
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
    'control.commerce_session.revoke.v1'
  )),
  ADD CONSTRAINT idempotency_resource_type_valid CHECK (resource_type IS NULL OR resource_type IN (
    'organization', 'agent', 'provider', 'membership',
    'agent_credential', 'provider_credential',
    'listing', 'listing_version',
    'budget_policy', 'budget_policy_revision',
    'commerce_session'
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
  );

ALTER TABLE openarc_durable.idempotency_records
  ADD COLUMN commerce_session_id uuid GENERATED ALWAYS AS (
    CASE WHEN resource_type = 'commerce_session' THEN resource_id::uuid END
  ) STORED,
  ADD CONSTRAINT idempotency_commerce_session_fk FOREIGN KEY (organization_id, commerce_session_id)
    REFERENCES openarc_durable.commerce_sessions(organization_id, session_id) ON DELETE RESTRICT,
  ADD CONSTRAINT idempotency_commerce_session_shape CHECK (
    (resource_type = 'commerce_session'
     AND resource_id IS NOT NULL
     AND openarc_durable.is_canonical_commerce_session_id(resource_id))
    OR resource_type IS DISTINCT FROM 'commerce_session'
  );

ALTER TABLE openarc_durable.audit_events
  DROP CONSTRAINT audit_operation_valid,
  DROP CONSTRAINT audit_resource_type_valid,
  DROP CONSTRAINT audit_resource_matches_operation,
  DROP CONSTRAINT audit_policy_resource_shape;

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
    'control.commerce_session.revoke'
  )),
  ADD CONSTRAINT audit_resource_type_valid CHECK (resource_type IN (
    'organization', 'agent', 'provider', 'membership',
    'agent_credential', 'provider_credential',
    'listing', 'listing_version',
    'budget_policy', 'budget_policy_revision',
    'commerce_session'
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
  );

ALTER TABLE openarc_durable.audit_events
  ADD COLUMN commerce_session_id uuid GENERATED ALWAYS AS (
    CASE WHEN resource_type = 'commerce_session' THEN resource_id::uuid END
  ) STORED,
  ADD CONSTRAINT audit_commerce_session_fk FOREIGN KEY (organization_id, commerce_session_id)
    REFERENCES openarc_durable.commerce_sessions(organization_id, session_id) ON DELETE RESTRICT,
  ADD CONSTRAINT audit_commerce_session_shape CHECK (
    (resource_type = 'commerce_session'
     AND openarc_durable.is_canonical_commerce_session_id(resource_id))
    OR resource_type IS DISTINCT FROM 'commerce_session'
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
    'budget_policy', 'budget_policy_revision',
    'commerce_session'
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
    'control.commerce_session.revoked'
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
    END
  ),
  ADD CONSTRAINT outbox_receipt_fk FOREIGN KEY (
    organization_id, mutation_id, resource_type, resource_id, receipt_operation
  ) REFERENCES openarc_durable.idempotency_records (
    organization_id, mutation_id, resource_type, resource_id, operation
  ) ON DELETE RESTRICT;

ALTER TABLE openarc_durable.outbox_events
  ADD COLUMN commerce_session_id uuid GENERATED ALWAYS AS (
    CASE WHEN resource_type = 'commerce_session' THEN resource_id::uuid END
  ) STORED,
  ADD CONSTRAINT outbox_commerce_session_fk FOREIGN KEY (organization_id, commerce_session_id)
    REFERENCES openarc_durable.commerce_sessions(organization_id, session_id) ON DELETE RESTRICT,
  ADD CONSTRAINT outbox_commerce_session_shape CHECK (
    (resource_type = 'commerce_session'
     AND openarc_durable.is_canonical_commerce_session_id(resource_id))
    OR resource_type IS DISTINCT FROM 'commerce_session'
  );

-- ---------------------------------------------------------------------------
-- Human authority preambles. A writer must be current owner/operator with
-- non-recovery fresh proof (<5 min at final DB time); a reader must be current
-- owner/operator non-recovery with NO fresh-proof requirement. Viewer and
-- provider roles are denied. Sorted account locking is retained for the
-- exchange pair below.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.lock_commerce_human(
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
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_canonical_org_id(organization_id) THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '22023';
  END IF;
  SELECT l.account_id, l.method, l.session_created_at, l.session_expires_at
    INTO v_actor, v_method, v_created_at, v_expires_at
    FROM openarc_tenant.lock_auth_session(session_hash, NULL) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;
  IF v_method = 'recovery' THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
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
  -- Re-resolve the SAME held session after the organization/membership waits.
  SELECT l.account_id, l.method, l.session_created_at, l.session_expires_at
    INTO v_actor, v_method, v_created_at, v_expires_at
    FROM openarc_tenant.lock_auth_session(session_hash, NULL) AS l;
  IF v_actor IS NULL OR v_method = 'recovery' THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;
  SELECT clock_timestamp() INTO v_now;
  IF NOT (v_expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;
  IF require_fresh AND NOT (v_created_at > v_now - interval '5 minutes') THEN
    RAISE EXCEPTION 'commerce_proof_stale' USING ERRCODE = '28000';
  END IF;
  out_actor := v_actor;
  out_role := v_role;
  RETURN NEXT;
END;
$$;

-- Human status/list reader: current owner/operator, non-recovery, no proof age.
CREATE FUNCTION openarc_durable.lock_commerce_reader(
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
  v_recheck text;
BEGIN
  SELECT l.out_actor, l.out_role INTO v_actor, v_recheck
    FROM openarc_durable.lock_commerce_human(session_hash, organization_id, false) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  out_actor := v_actor;
  out_role := v_recheck;
  RETURN NEXT;
END;
$$;

-- Human writer preamble: current owner/operator with non-recovery fresh proof.
CREATE FUNCTION openarc_durable.lock_commerce_writer(
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
    FROM openarc_durable.lock_commerce_human(session_hash, organization_id, true) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  out_actor := v_actor;
  out_role := v_role;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Human issue. Current owner/operator fresh proof; active same-org subject
-- agent and current policy root/revision. Duration 1..900 (default 300); the
-- session expiry is min(now+duration, parent human session expiry, current
-- policy expiry); handoff expiry is min(now+300, session expiry). The session
-- id is derived from the checked mutation id so an idempotent retry is stable.
-- The regenerated handoff hash is NOT part of the logical request digest, so a
-- retry returns replayed with the ORIGINAL record and never a new secret.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.issue_commerce_session(
  human_session_hash text,
  organization_id text,
  subject_agent_id text,
  policy_id_input text,
  duration_seconds integer,
  handoff_hash text,
  mutation_id uuid,
  key_hash text,
  request_digest text,
  session_context_digest text
) RETURNS TABLE(
  out_replayed boolean,
  out_session_id uuid,
  out_organization_id text,
  out_subject_agent_id text,
  out_policy_id text,
  out_issued_at timestamptz,
  out_initial_expires_at timestamptz,
  out_expires_at timestamptz,
  out_exchanged_at timestamptz,
  out_agent_session_id uuid,
  out_credential_id uuid,
  out_revoked_at timestamptz,
  out_handoff_expires_at timestamptz,
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
  v_policy_status text;
  v_policy_revision text;
  v_policy_expires timestamptz;
  v_human_expires timestamptz;
  v_existing record;
  v_session_id uuid;
  v_issued_at timestamptz;
  v_initial_expires timestamptz;
  v_session_expires timestamptz;
  v_handoff_expires timestamptz;
  v_committed_at timestamptz;
  v_now timestamptz;
  v_recheck text;
BEGIN
  IF NOT openarc_durable.is_canonical_hex64(human_session_hash) THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;
  IF NOT openarc_durable.is_canonical_org_id(organization_id)
     OR NOT openarc_durable.is_canonical_agent_id(subject_agent_id)
     OR NOT openarc_durable.is_canonical_policy_id(policy_id_input) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_canonical_hex64(handoff_hash) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF mutation_id IS NULL OR NOT openarc_durable.is_canonical_uuid_v4(mutation_id::text) THEN
    RAISE EXCEPTION 'commerce_mutation_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_canonical_hex64(key_hash)
     OR NOT openarc_durable.is_canonical_hex64(request_digest)
     OR NOT openarc_durable.is_canonical_hex64(session_context_digest) THEN
    RAISE EXCEPTION 'commerce_metadata_invalid' USING ERRCODE = '22023';
  END IF;
  IF duration_seconds IS NULL OR duration_seconds < 1 OR duration_seconds > 900 THEN
    RAISE EXCEPTION 'commerce_duration_invalid' USING ERRCODE = '22023';
  END IF;

  SELECT l.out_actor, l.out_role INTO v_actor, v_role
    FROM openarc_durable.lock_commerce_human(human_session_hash, organization_id, true) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- Same-key replay is resolved BEFORE any target state/expiry check so an
  -- already-committed receipt stays recoverable after later revoke/expiry.
  SELECT * INTO v_existing
    FROM openarc_durable.idempotency_records r
   WHERE r.organization_id = organization_id AND r.operation = 'control.commerce_session.issue'
     AND r.key_hash = key_hash FOR UPDATE;
  IF FOUND THEN
    IF v_existing.request_digest = request_digest
       AND v_existing.mutation_id = mutation_id
       AND v_existing.actor_account_id = v_actor
       AND v_existing.session_context_digest = session_context_digest
       AND v_existing.status = 'committed'
       AND v_existing.resource_type = 'commerce_session' THEN
      SELECT l.out_actor INTO v_recheck
        FROM openarc_durable.lock_commerce_human(human_session_hash, organization_id, false) AS l;
      IF v_recheck IS NULL OR v_recheck <> v_actor THEN
        RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
      END IF;
      SELECT s.session_id, s.organization_id, s.subject_agent_id, s.policy_id, s.issued_at,
             s.initial_expires_at, s.expires_at, s.exchanged_at,
             s.agent_session_id, s.credential_id, s.revoked_at,
             h.expires_at, r.committed_at
        INTO out_session_id, out_organization_id, out_subject_agent_id, out_policy_id, out_issued_at,
             out_initial_expires_at, out_expires_at, out_exchanged_at,
             out_agent_session_id, out_credential_id, out_revoked_at,
             out_handoff_expires_at, out_committed_at
        FROM openarc_durable.commerce_sessions s
        JOIN openarc_durable.commerce_session_handoffs h
          ON h.organization_id = s.organization_id AND h.session_id = s.session_id
        JOIN openarc_durable.idempotency_records r
          ON r.organization_id = s.organization_id AND r.mutation_id = v_existing.mutation_id
       WHERE s.organization_id = organization_id
         AND s.session_id = v_existing.resource_id::uuid
         AND r.operation = 'control.commerce_session.issue' AND r.key_hash = key_hash;
      out_replayed := true;
      RETURN NEXT;
      RETURN;
    END IF;
    RAISE EXCEPTION 'commerce_idempotency_conflict' USING ERRCODE = 'P0D01';
  END IF;
  PERFORM 1 FROM openarc_durable.idempotency_records r
   WHERE r.organization_id = organization_id AND r.mutation_id = mutation_id FOR UPDATE;
  IF FOUND THEN
    RAISE EXCEPTION 'commerce_idempotency_conflict' USING ERRCODE = 'P0D01';
  END IF;

  SELECT a.status INTO v_agent_status
    FROM openarc_tenant.agents a
   WHERE a.organization_id = organization_id AND a.agent_id = subject_agent_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  IF v_agent_status <> 'active' THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT r.current_revision, r.status INTO v_policy_revision, v_policy_status
    FROM openarc_tenant.budget_policy_roots r
   WHERE r.organization_id = organization_id AND r.policy_id = policy_id_input FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  IF v_policy_status <> 'active' THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT v.subject_agent_id, v.expires_at INTO out_subject_agent_id, v_policy_expires
    FROM openarc_tenant.budget_policy_versions v
   WHERE v.organization_id = organization_id AND v.policy_id = policy_id_input
     AND v.revision = v_policy_revision FOR UPDATE;
  IF NOT FOUND OR out_subject_agent_id <> subject_agent_id THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  -- The parent human session was live at lock time; re-read its expiry under
  -- the held lock for the min() bound (a deleted parent cannot appear here).
  SELECT l.session_expires_at INTO v_human_expires
    FROM openarc_tenant.lock_auth_session(human_session_hash, NULL) AS l;
  IF v_human_expires IS NULL THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;
  SELECT clock_timestamp() INTO v_now;
  IF v_policy_expires IS NOT NULL AND NOT (v_policy_expires > v_now) THEN
    RAISE EXCEPTION 'commerce_expired' USING ERRCODE = '23514';
  END IF;

  v_session_id := mutation_id;
  v_issued_at := v_now;
  v_initial_expires := LEAST(
    v_now + make_interval(secs => duration_seconds),
    v_human_expires,
    COALESCE(v_policy_expires, 'infinity'::timestamptz)
  );
  IF NOT (v_initial_expires > v_now) THEN
    RAISE EXCEPTION 'commerce_expired' USING ERRCODE = '23514';
  END IF;
  v_session_expires := v_initial_expires;
  v_handoff_expires := LEAST(v_now + interval '300 seconds', v_session_expires);
  IF NOT (v_handoff_expires > v_now) THEN
    RAISE EXCEPTION 'commerce_expired' USING ERRCODE = '23514';
  END IF;

  INSERT INTO openarc_durable.idempotency_records (
    organization_id, operation, key_hash, request_digest, digest_version,
    actor_account_id, session_context_digest, network, mutation_id, status
  ) VALUES (
    organization_id, 'control.commerce_session.issue', key_hash, request_digest,
    'control.commerce_session.issue.v1', v_actor, session_context_digest,
    'eip155:5042002', mutation_id, 'pending'
  );
  INSERT INTO openarc_durable.commerce_sessions (
    organization_id, session_id, parent_human_session_hash, parent_human_account_id,
    subject_agent_id, policy_id, scope, scope_version, network_id, asset,
    representation, decimals, issued_at, initial_expires_at, expires_at
  ) VALUES (
    organization_id, v_session_id, human_session_hash, v_actor,
    subject_agent_id, policy_id_input, 'commerce.authorize', 1, 'eip155:5042002',
    'USDC', 'erc20', 6, v_issued_at, v_initial_expires, v_session_expires
  );
  INSERT INTO openarc_durable.commerce_session_handoffs (
    handoff_hash, organization_id, session_id, hash_version, issued_at, expires_at
  ) VALUES (
    handoff_hash, organization_id, v_session_id, 1, v_issued_at, v_handoff_expires
  );
  UPDATE openarc_durable.idempotency_records r
     SET status = 'committed', resource_type = 'commerce_session',
         resource_id = v_session_id::text, committed_at = clock_timestamp()
   WHERE r.organization_id = organization_id AND r.operation = 'control.commerce_session.issue'
     AND r.key_hash = key_hash
   RETURNING r.committed_at INTO v_committed_at;
  INSERT INTO openarc_durable.audit_events (
    organization_id, actor_account_id, operation, mutation_id, resource_type, resource_id, outcome
  ) VALUES (
    organization_id, v_actor, 'control.commerce_session.issue', mutation_id,
    'commerce_session', v_session_id::text, 'committed'
  );
  INSERT INTO openarc_durable.outbox_events (
    organization_id, mutation_id, resource_type, resource_id, event_type, payload_version
  ) VALUES (
    organization_id, mutation_id, 'commerce_session', v_session_id::text,
    'control.commerce_session.issued', 1
  );

  SELECT l.out_actor INTO v_recheck
    FROM openarc_durable.lock_commerce_human(human_session_hash, organization_id, false) AS l;
  IF v_recheck IS NULL OR v_recheck <> v_actor THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;
  SELECT a.status INTO v_agent_status
    FROM openarc_tenant.agents a
   WHERE a.organization_id = organization_id AND a.agent_id = subject_agent_id;
  IF v_agent_status IS NULL OR v_agent_status <> 'active' THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  out_replayed := false;
  out_session_id := v_session_id;
  out_organization_id := organization_id;
  out_subject_agent_id := subject_agent_id;
  out_policy_id := policy_id_input;
  out_issued_at := v_issued_at;
  out_initial_expires_at := v_initial_expires;
  out_expires_at := v_session_expires;
  out_exchanged_at := NULL;
  out_agent_session_id := NULL;
  out_credential_id := NULL;
  out_revoked_at := NULL;
  out_handoff_expires_at := v_handoff_expires;
  out_committed_at := v_committed_at;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Machine exchange. Requires a current authenticated AGENT machine session
-- whose exact credential is active and whose CURRENT credential issuer still
-- holds owner/operator authority, plus possession of the not-yet-consumed
-- handoff. The approving human parent (retained at issue) must have a live
-- non-recovery session and CURRENT owner/operator role, but its proof does NOT
-- need to still be fresh. Binds the exact agent session + credential and the
-- session token hash exactly once, consumes the handoff atomically, and never
-- binds a second parent or creates a second session for one handoff. The
-- regenerated token hash is excluded from the logical request digest.
-- ---------------------------------------------------------------------------

-- Narrow immutable-ID resolution for the trusted API: returns the binding ids
-- an exchange request digest needs WITHOUT taking any lock or asserting any
-- authority. The exchange helper revalidates every returned binding under the
-- full canonical lock sequence; this read is never authorization.
CREATE FUNCTION openarc_durable.resolve_agent_session_context(agent_session_token_hash text)
RETURNS TABLE(
  out_organization_id text,
  out_agent_id text,
  out_credential_id uuid,
  out_issuer_account_id text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF NOT openarc_durable.is_canonical_hex64(agent_session_token_hash) THEN
    RAISE EXCEPTION 'commerce_token_invalid' USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
    SELECT s.organization_id, s.agent_id, s.credential_id, c.issuer_account_id
      FROM openarc_durable.agent_sessions s
      JOIN openarc_durable.agent_credentials c
        ON c.organization_id = s.organization_id AND c.credential_id = s.credential_id
     WHERE s.token_hash = agent_session_token_hash;
END;
$$;

CREATE FUNCTION openarc_durable.exchange_commerce_session(
  agent_session_hash text,
  handoff_hash text,
  token_hash text,
  mutation_id uuid,
  key_hash text,
  request_digest text,
  session_context_digest text
) RETURNS TABLE(
  out_replayed boolean,
  out_session_id uuid,
  out_organization_id text,
  out_subject_agent_id text,
  out_policy_id text,
  out_issued_at timestamptz,
  out_initial_expires_at timestamptz,
  out_expires_at timestamptz,
  out_exchanged_at timestamptz,
  out_agent_session_id uuid,
  out_credential_id uuid,
  out_revoked_at timestamptz,
  out_handoff_expires_at timestamptz,
  out_committed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_org text;
  v_agent_id text;
  v_credential_id uuid;
  v_agent_session_id uuid;
  v_agent_expires timestamptz;
  v_issuer text;
  v_parent_hash text;
  v_parent_account text;
  v_parent_actor text;
  v_parent_method text;
  v_parent_role text;
  v_parent_status text;
  v_issuer_role text;
  v_issuer_status text;
  v_session_id uuid;
  v_subject text;
  v_policy text;
  v_policy_status text;
  v_policy_revision text;
  v_policy_subject text;
  v_policy_expires timestamptz;
  v_human_expires timestamptz;
  v_credential_expires timestamptz;
  v_credential_revoked timestamptz;
  v_credential_scope text;
  v_credential_scope_version integer;
  v_credential_environment text;
  v_machine record;
  v_handoff record;
  v_session record;
  v_existing record;
  v_maybe_replay boolean := false;
  v_replay_status text;
  v_effective_expires timestamptz;
  v_final_expires timestamptz;
  v_final_revoked timestamptz;
  v_exchanged_at timestamptz;
  v_stored_expires timestamptz;
  v_committed_at timestamptz;
  v_now timestamptz;
  v_recheck text;
BEGIN
  IF NOT openarc_durable.is_canonical_hex64(agent_session_hash)
     OR NOT openarc_durable.is_canonical_hex64(handoff_hash)
     OR NOT openarc_durable.is_canonical_hex64(token_hash) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF mutation_id IS NULL OR NOT openarc_durable.is_canonical_uuid_v4(mutation_id::text) THEN
    RAISE EXCEPTION 'commerce_mutation_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_canonical_hex64(key_hash)
     OR NOT openarc_durable.is_canonical_hex64(request_digest)
     OR NOT openarc_durable.is_canonical_hex64(session_context_digest) THEN
    RAISE EXCEPTION 'commerce_metadata_invalid' USING ERRCODE = '22023';
  END IF;

  -- Resolve identifiers WITHOUT a lock; never authorize from this snapshot.
  SELECT s.organization_id, s.agent_id, s.credential_id, s.session_id, s.expires_at
    INTO v_org, v_agent_id, v_credential_id, v_agent_session_id, v_agent_expires
    FROM openarc_durable.agent_sessions s
   WHERE s.token_hash = agent_session_hash;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT c.issuer_account_id, c.expires_at, c.revoked_at
    INTO v_issuer, v_credential_expires, v_credential_revoked
    FROM openarc_durable.agent_credentials c
   WHERE c.organization_id = v_org AND c.credential_id = v_credential_id
     AND c.agent_id = v_agent_id;
  IF v_issuer IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT h.session_id, s.parent_human_session_hash, s.parent_human_account_id
    INTO v_session_id, v_parent_hash, v_parent_account
    FROM openarc_durable.commerce_session_handoffs h
    JOIN openarc_durable.commerce_sessions s
      ON s.session_id = h.session_id AND s.organization_id = h.organization_id
   WHERE h.handoff_hash = handoff_hash
     AND h.organization_id = v_org AND s.subject_agent_id = v_agent_id;
  IF v_session_id IS NULL THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;

  -- Lock BOTH involved accounts in sorted order (parent human + credential
  -- issuer may differ; neither is required to equal the other).
  PERFORM 1 FROM openarc_auth.accounts a
   WHERE a.account_id IN (v_parent_account, v_issuer)
     AND a.status = 'active'
   ORDER BY a.account_id FOR UPDATE;
  -- The two roles may be the SAME account; compare active rows to the distinct
  -- set of involved accounts so a shared account is locked once, not rejected.
  IF (SELECT count(*) FROM openarc_auth.accounts a
       WHERE a.account_id IN (SELECT DISTINCT x FROM unnest(ARRAY[v_parent_account, v_issuer]) AS x)
         AND a.status = 'active')
     <> (SELECT count(DISTINCT x) FROM unnest(ARRAY[v_parent_account, v_issuer]) AS x) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- Current requesting machine authority is ALWAYS required, including on the
  -- safe replay path: a live non-revoked credential with the exact
  -- scope/environment and a live non-revoked agent session bound to this
  -- org/agent/credential. Revoking the requesting credential/session denies
  -- even a committed replay.
  SELECT c.expires_at, c.revoked_at, c.scope, c.scope_version, c.environment
    INTO v_credential_expires, v_credential_revoked, v_credential_scope,
         v_credential_scope_version, v_credential_environment
    FROM openarc_durable.agent_credentials c
   WHERE c.organization_id = v_org AND c.credential_id = v_credential_id
     AND c.agent_id = v_agent_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT s.session_id, s.organization_id, s.agent_id, s.credential_id,
         s.expires_at, s.revoked_at, s.scope, s.scope_version, s.environment
    INTO v_machine
    FROM openarc_durable.agent_sessions s
   WHERE s.session_id = v_agent_session_id FOR UPDATE;
  IF NOT FOUND
     OR v_machine.organization_id IS DISTINCT FROM v_org
     OR v_machine.agent_id IS DISTINCT FROM v_agent_id
     OR v_machine.credential_id IS DISTINCT FROM v_credential_id
     OR v_machine.scope <> 'agent:self.read' OR v_machine.scope_version <> 1
     OR v_machine.environment <> 'eip155:5042002' THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT clock_timestamp() INTO v_now;
  IF v_credential_revoked IS NOT NULL OR NOT (v_credential_expires > v_now)
     OR v_credential_scope <> 'agent:self.read' OR v_credential_scope_version <> 1
     OR v_credential_environment <> 'eip155:5042002'
     OR v_machine.revoked_at IS NOT NULL OR NOT (v_machine.expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- A committed replay is resolved after the CURRENT REQUESTING machine
  -- principal chain (org/membership/subject/credential/agent session) but
  -- BEFORE the approving human parent's liveness/expiry and target policy
  -- state. This lets an already-committed receipt be found after the parent
  -- session expired or the policy was revoked, without new authority.
  SELECT r.status INTO v_replay_status
    FROM openarc_durable.idempotency_records r
   WHERE r.organization_id = v_org
     AND r.operation = 'control.commerce_session.exchange'
     AND r.key_hash = key_hash
     AND r.request_digest = request_digest
     AND r.mutation_id = mutation_id
     AND r.actor_account_id = v_issuer
     AND r.session_context_digest = session_context_digest
     AND r.status = 'committed'
     AND r.resource_type = 'commerce_session'
     AND r.resource_id::uuid = v_session_id;
  v_maybe_replay := FOUND;

  IF v_maybe_replay THEN
    -- Lock only the requesting-principal chain; never the dead parent session.
    PERFORM 1 FROM openarc_tenant.organizations o
     WHERE o.organization_id = v_org FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
    END IF;
    PERFORM 1 FROM openarc_tenant.memberships m
     WHERE m.organization_id = v_org AND m.account_id = v_issuer
       AND m.status = 'active' AND m.role IN ('owner', 'operator') FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
    END IF;
    PERFORM 1 FROM openarc_tenant.agents a
     WHERE a.organization_id = v_org AND a.agent_id = v_agent_id
       AND a.status = 'active' FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO v_existing
      FROM openarc_durable.idempotency_records r
     WHERE r.organization_id = v_org AND r.operation = 'control.commerce_session.exchange'
       AND r.key_hash = key_hash FOR UPDATE;
    IF NOT FOUND
       OR v_existing.request_digest <> request_digest
       OR v_existing.mutation_id <> mutation_id
       OR v_existing.actor_account_id <> v_issuer
       OR v_existing.session_context_digest <> session_context_digest
       OR v_existing.status <> 'committed' THEN
      RAISE EXCEPTION 'commerce_idempotency_conflict' USING ERRCODE = 'P0D01';
    END IF;
    SELECT * INTO v_session
      FROM openarc_durable.commerce_sessions s
     WHERE s.organization_id = v_org AND s.session_id = v_session_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
    END IF;
    SELECT h.expires_at INTO out_handoff_expires_at
      FROM openarc_durable.commerce_session_handoffs h
     WHERE h.handoff_hash = handoff_hash;
    out_replayed := true;
    out_session_id := v_session_id;
    out_organization_id := v_org;
    out_subject_agent_id := v_session.subject_agent_id;
    out_policy_id := v_session.policy_id;
    out_issued_at := v_session.issued_at;
    out_initial_expires_at := v_session.initial_expires_at;
    out_expires_at := v_session.expires_at;
    out_exchanged_at := v_session.exchanged_at;
    out_agent_session_id := v_session.agent_session_id;
    out_credential_id := v_session.credential_id;
    out_revoked_at := v_session.revoked_at;
    out_committed_at := v_existing.committed_at;
    RETURN NEXT;
    RETURN;
  END IF;

  -- Fresh exchange: the approving human parent must have a LIVE non-recovery
  -- session and CURRENT owner/operator authority. Proof freshness is
  -- deliberately NOT required at exchange or later authorization.
  SELECT l.account_id, l.method, l.session_expires_at
    INTO v_parent_actor, v_parent_method, v_human_expires
    FROM openarc_tenant.lock_auth_session(v_parent_hash, NULL) AS l;
  IF v_parent_actor IS NULL OR v_parent_actor <> v_parent_account
     OR v_parent_method = 'recovery' THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM openarc_tenant.organizations o
   WHERE o.organization_id = v_org FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  -- Sorted membership locks: (org, account) rows for parent human and issuer.
  PERFORM 1 FROM openarc_tenant.memberships m
   WHERE m.organization_id = v_org
     AND m.account_id IN (v_parent_account, v_issuer)
   ORDER BY m.account_id FOR UPDATE;
  SELECT m.role, m.status INTO v_parent_role, v_parent_status
    FROM openarc_tenant.memberships m
   WHERE m.organization_id = v_org AND m.account_id = v_parent_account;
  IF v_parent_role IS NULL OR v_parent_status <> 'active'
     OR v_parent_role NOT IN ('owner', 'operator') THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT m.role, m.status INTO v_issuer_role, v_issuer_status
    FROM openarc_tenant.memberships m
   WHERE m.organization_id = v_org AND m.account_id = v_issuer;
  IF v_issuer_role IS NULL OR v_issuer_status <> 'active'
     OR v_issuer_role NOT IN ('owner', 'operator') THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT a.status INTO v_parent_status FROM openarc_tenant.agents a
   WHERE a.organization_id = v_org AND a.agent_id = v_agent_id FOR UPDATE;
  IF NOT FOUND OR v_parent_status <> 'active' THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT c.expires_at, c.revoked_at INTO v_credential_expires, v_credential_revoked
    FROM openarc_durable.agent_credentials c
   WHERE c.organization_id = v_org AND c.credential_id = v_credential_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT s.session_id, s.organization_id, s.agent_id, s.credential_id,
         s.expires_at, s.revoked_at, s.scope, s.scope_version, s.environment
    INTO v_machine
    FROM openarc_durable.agent_sessions s
   WHERE s.session_id = v_agent_session_id FOR UPDATE;
  IF NOT FOUND
     OR v_machine.organization_id IS DISTINCT FROM v_org
     OR v_machine.agent_id IS DISTINCT FROM v_agent_id
     OR v_machine.credential_id IS DISTINCT FROM v_credential_id
     OR v_machine.scope <> 'agent:self.read' OR v_machine.scope_version <> 1
     OR v_machine.environment <> 'eip155:5042002' THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT s.policy_id, s.subject_agent_id INTO v_policy, v_subject
    FROM openarc_durable.commerce_sessions s
   WHERE s.organization_id = v_org AND s.session_id = v_session_id;
  IF v_policy IS NULL OR v_subject IS DISTINCT FROM v_agent_id THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT r.current_revision, r.status, r.subject_agent_id
    INTO v_policy_revision, v_policy_status, v_policy_subject
    FROM openarc_tenant.budget_policy_roots r
   WHERE r.organization_id = v_org AND r.policy_id = v_policy FOR UPDATE;
  IF NOT FOUND OR v_policy_status <> 'active' OR v_policy_subject <> v_agent_id THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT v.expires_at INTO v_policy_expires
    FROM openarc_tenant.budget_policy_versions v
   WHERE v.organization_id = v_org AND v.policy_id = v_policy
     AND v.revision = v_policy_revision FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT * INTO v_handoff
    FROM openarc_durable.commerce_session_handoffs h
   WHERE h.handoff_hash = handoff_hash FOR UPDATE;
  IF NOT FOUND
     OR v_handoff.organization_id IS DISTINCT FROM v_org
     OR v_handoff.session_id IS DISTINCT FROM v_session_id THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT * INTO v_session
    FROM openarc_durable.commerce_sessions s
   WHERE s.organization_id = v_org AND s.session_id = v_session_id FOR UPDATE;
  IF NOT FOUND OR v_session.parent_human_session_hash IS DISTINCT FROM v_parent_hash THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT * INTO v_existing
    FROM openarc_durable.idempotency_records r
   WHERE r.organization_id = v_org AND r.operation = 'control.commerce_session.exchange'
     AND r.key_hash = key_hash FOR UPDATE;
  IF FOUND THEN
    -- A concurrent committer won after our unresolved pre-check.
    IF v_existing.request_digest = request_digest
       AND v_existing.mutation_id = mutation_id
       AND v_existing.actor_account_id = v_issuer
       AND v_existing.session_context_digest = session_context_digest
       AND v_existing.status = 'committed'
       AND v_existing.resource_type = 'commerce_session'
       AND v_existing.resource_id::uuid = v_session_id THEN
      out_replayed := true;
      out_session_id := v_session_id;
      out_organization_id := v_org;
      out_subject_agent_id := v_session.subject_agent_id;
      out_policy_id := v_session.policy_id;
      out_issued_at := v_session.issued_at;
      out_initial_expires_at := v_session.initial_expires_at;
      out_expires_at := v_session.expires_at;
      out_exchanged_at := v_session.exchanged_at;
      out_agent_session_id := v_session.agent_session_id;
      out_credential_id := v_session.credential_id;
      out_revoked_at := v_session.revoked_at;
      out_handoff_expires_at := v_handoff.expires_at;
      out_committed_at := v_existing.committed_at;
      RETURN NEXT;
      RETURN;
    END IF;
    RAISE EXCEPTION 'commerce_idempotency_conflict' USING ERRCODE = 'P0D01';
  END IF;
  PERFORM 1 FROM openarc_durable.idempotency_records r
   WHERE r.organization_id = v_org AND r.mutation_id = mutation_id FOR UPDATE;
  IF FOUND THEN
    RAISE EXCEPTION 'commerce_idempotency_conflict' USING ERRCODE = 'P0D01';
  END IF;

  SELECT clock_timestamp() INTO v_now;
  IF v_credential_revoked IS NOT NULL OR NOT (v_credential_expires > v_now) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  IF v_handoff.consumed_at IS NOT NULL THEN
    RAISE EXCEPTION 'commerce_handoff_consumed' USING ERRCODE = '23514';
  END IF;
  IF NOT (v_handoff.expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_expired' USING ERRCODE = '23514';
  END IF;
  IF v_machine.revoked_at IS NOT NULL OR NOT (v_machine.expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  IF v_session.exchanged_at IS NOT NULL OR v_session.revoked_at IS NOT NULL
     OR v_session.agent_session_id IS NOT NULL OR v_session.credential_id IS NOT NULL THEN
    RAISE EXCEPTION 'commerce_handoff_consumed' USING ERRCODE = '23514';
  END IF;
  IF NOT (v_session.expires_at > v_now) OR NOT (v_machine.expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_expired' USING ERRCODE = '23514';
  END IF;
  IF v_policy_expires IS NOT NULL AND NOT (v_policy_expires > v_now) THEN
    RAISE EXCEPTION 'commerce_expired' USING ERRCODE = '23514';
  END IF;
  IF NOT (v_human_expires > v_now) THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;

  v_effective_expires := LEAST(
    v_session.expires_at, v_machine.expires_at, v_credential_expires,
    COALESCE(v_policy_expires, 'infinity'::timestamptz)
  );
  IF NOT (v_effective_expires > v_now) THEN
    RAISE EXCEPTION 'commerce_expired' USING ERRCODE = '23514';
  END IF;
  -- Pin the single exchange instant and the exact stored shortened expiry so
  -- the returned metadata echoes the durable row instead of a later clock read.
  v_exchanged_at := v_now;

  INSERT INTO openarc_durable.idempotency_records (
    organization_id, operation, key_hash, request_digest, digest_version,
    actor_account_id, session_context_digest, network, mutation_id, status
  ) VALUES (
    v_org, 'control.commerce_session.exchange', key_hash, request_digest,
    'control.commerce_session.exchange.v1', v_issuer, session_context_digest,
    'eip155:5042002', mutation_id, 'pending'
  );
  UPDATE openarc_durable.commerce_sessions s
     SET expires_at = LEAST(s.expires_at, v_effective_expires),
         exchanged_at = v_exchanged_at,
         agent_session_id = v_agent_session_id,
         credential_id = v_credential_id
   WHERE s.organization_id = v_org AND s.session_id = v_session_id
   RETURNING s.expires_at INTO v_stored_expires;
  UPDATE openarc_durable.commerce_session_handoffs h
     SET consumed_at = v_exchanged_at, token_hash = token_hash, token_hash_version = 1
   WHERE h.handoff_hash = handoff_hash;
  UPDATE openarc_durable.idempotency_records r
     SET status = 'committed', resource_type = 'commerce_session',
         resource_id = v_session_id::text, committed_at = clock_timestamp()
   WHERE r.organization_id = v_org AND r.operation = 'control.commerce_session.exchange'
     AND r.key_hash = key_hash
   RETURNING r.committed_at INTO v_committed_at;
  INSERT INTO openarc_durable.audit_events (
    organization_id, actor_account_id, operation, mutation_id, resource_type, resource_id, outcome
  ) VALUES (
    v_org, v_issuer, 'control.commerce_session.exchange', mutation_id,
    'commerce_session', v_session_id::text, 'committed'
  );
  INSERT INTO openarc_durable.outbox_events (
    organization_id, mutation_id, resource_type, resource_id, event_type, payload_version
  ) VALUES (
    v_org, mutation_id, 'commerce_session', v_session_id::text,
    'control.commerce_session.exchanged', 1
  );

  SELECT l.account_id, l.method INTO v_recheck, v_parent_method
    FROM openarc_tenant.lock_auth_session(v_parent_hash, NULL) AS l;
  IF v_recheck IS NULL OR v_recheck <> v_parent_account OR v_parent_method = 'recovery' THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;

  -- Final recheck after every durable write (idempotency/audit/outbox and the
  -- session/handoff binding). A lock wait may have pushed the clock past the
  -- handoff, machine session, credential, current policy or effective commerce
  -- expiry, or another worker may have consumed/changed state. Re-read a FRESH
  -- clock and revalidate all bindings; any failure rolls the whole exchange back.
  SELECT clock_timestamp() INTO v_now;
  SELECT c.expires_at, c.revoked_at, c.scope, c.scope_version, c.environment
    INTO v_credential_expires, v_credential_revoked, v_credential_scope,
         v_credential_scope_version, v_credential_environment
    FROM openarc_durable.agent_credentials c
   WHERE c.organization_id = v_org AND c.credential_id = v_credential_id;
  IF NOT FOUND
     OR v_credential_revoked IS NOT NULL OR NOT (v_credential_expires > v_now)
     OR v_credential_scope <> 'agent:self.read' OR v_credential_scope_version <> 1
     OR v_credential_environment <> 'eip155:5042002' THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT s.expires_at, s.revoked_at, s.credential_id, s.agent_id, s.organization_id
    INTO v_machine
    FROM openarc_durable.agent_sessions s
   WHERE s.session_id = v_agent_session_id;
  IF NOT FOUND
     OR v_machine.revoked_at IS NOT NULL OR NOT (v_machine.expires_at > v_now)
     OR v_machine.credential_id IS DISTINCT FROM v_credential_id
     OR v_machine.agent_id IS DISTINCT FROM v_agent_id
     OR v_machine.organization_id IS DISTINCT FROM v_org THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT h.consumed_at, h.token_hash, h.expires_at
    INTO v_handoff
    FROM openarc_durable.commerce_session_handoffs h
   WHERE h.handoff_hash = handoff_hash AND h.organization_id = v_org
     AND h.session_id = v_session_id;
  IF NOT FOUND OR v_handoff.consumed_at IS NULL OR v_handoff.token_hash IS DISTINCT FROM token_hash
     OR NOT (v_handoff.expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_expired' USING ERRCODE = '23514';
  END IF;
  SELECT r.current_revision, r.status, r.subject_agent_id
    INTO v_policy_revision, v_policy_status, v_policy_subject
    FROM openarc_tenant.budget_policy_roots r
   WHERE r.organization_id = v_org AND r.policy_id = v_policy;
  IF NOT FOUND OR v_policy_status <> 'active' OR v_policy_subject <> v_agent_id THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT v.expires_at INTO v_policy_expires
    FROM openarc_tenant.budget_policy_versions v
   WHERE v.organization_id = v_org AND v.policy_id = v_policy
     AND v.revision = v_policy_revision;
  IF NOT FOUND OR (v_policy_expires IS NOT NULL AND NOT (v_policy_expires > v_now)) THEN
    RAISE EXCEPTION 'commerce_expired' USING ERRCODE = '23514';
  END IF;
  SELECT s.expires_at, s.revoked_at
    INTO v_final_expires, v_final_revoked
    FROM openarc_durable.commerce_sessions s
   WHERE s.organization_id = v_org AND s.session_id = v_session_id;
  IF NOT FOUND OR v_final_revoked IS NOT NULL
     OR NOT (v_final_expires > v_now) THEN
    RAISE EXCEPTION 'commerce_expired' USING ERRCODE = '23514';
  END IF;

  out_replayed := false;
  out_session_id := v_session_id;
  out_organization_id := v_org;
  out_subject_agent_id := v_session.subject_agent_id;
  out_policy_id := v_session.policy_id;
  out_issued_at := v_session.issued_at;
  out_initial_expires_at := v_session.initial_expires_at;
  out_expires_at := v_stored_expires;
  out_exchanged_at := v_exchanged_at;
  out_agent_session_id := v_agent_session_id;
  out_credential_id := v_credential_id;
  out_revoked_at := NULL;
  out_handoff_expires_at := v_handoff.expires_at;
  out_committed_at := v_committed_at;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Human revoke. The CURRENT caller must be owner/operator with fresh proof.
-- The target may be ANY same-org delegation, including an expired or
-- parent-invalidated one: the target's dead parent is never locked. Lock order
-- is current caller first, then org/subject/policy/commerce. Revocation is
-- terminal and never deletes history.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.revoke_commerce_session(
  human_session_hash text,
  organization_id text,
  session_id_input uuid,
  mutation_id uuid,
  key_hash text,
  request_digest text,
  session_context_digest text
) RETURNS TABLE(
  out_replayed boolean,
  out_session_id uuid,
  out_organization_id text,
  out_subject_agent_id text,
  out_policy_id text,
  out_issued_at timestamptz,
  out_initial_expires_at timestamptz,
  out_expires_at timestamptz,
  out_exchanged_at timestamptz,
  out_agent_session_id uuid,
  out_credential_id uuid,
  out_revoked_at timestamptz,
  out_handoff_expires_at timestamptz,
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
  v_existing record;
  v_session record;
  v_committed_at timestamptz;
  v_now timestamptz;
  v_recheck text;
BEGIN
  IF NOT openarc_durable.is_canonical_hex64(human_session_hash) THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;
  IF NOT openarc_durable.is_canonical_org_id(organization_id) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF session_id_input IS NULL
     OR NOT openarc_durable.is_canonical_commerce_session_id(session_id_input::text) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF mutation_id IS NULL OR NOT openarc_durable.is_canonical_uuid_v4(mutation_id::text) THEN
    RAISE EXCEPTION 'commerce_mutation_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_canonical_hex64(key_hash)
     OR NOT openarc_durable.is_canonical_hex64(request_digest)
     OR NOT openarc_durable.is_canonical_hex64(session_context_digest) THEN
    RAISE EXCEPTION 'commerce_metadata_invalid' USING ERRCODE = '22023';
  END IF;

  SELECT l.out_actor, l.out_role INTO v_actor, v_role
    FROM openarc_durable.lock_commerce_human(human_session_hash, organization_id, true) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- Same-key replay BEFORE target state/expiry checks.
  SELECT * INTO v_existing
    FROM openarc_durable.idempotency_records r
   WHERE r.organization_id = organization_id AND r.operation = 'control.commerce_session.revoke'
     AND r.key_hash = key_hash FOR UPDATE;
  IF FOUND THEN
    IF v_existing.request_digest = request_digest
       AND v_existing.mutation_id = mutation_id
       AND v_existing.actor_account_id = v_actor
       AND v_existing.session_context_digest = session_context_digest
       AND v_existing.status = 'committed'
       AND v_existing.resource_type = 'commerce_session'
       AND v_existing.resource_id::uuid = session_id_input THEN
      SELECT l.out_actor INTO v_recheck
        FROM openarc_durable.lock_commerce_reader(human_session_hash, organization_id) AS l;
      IF v_recheck IS NULL OR v_recheck <> v_actor THEN
        RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
      END IF;
      SELECT s.* INTO v_session
        FROM openarc_durable.commerce_sessions s
       WHERE s.organization_id = organization_id AND s.session_id = session_id_input;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
      END IF;
      out_replayed := true;
      out_session_id := v_session.session_id;
      out_organization_id := organization_id;
      out_subject_agent_id := v_session.subject_agent_id;
      out_policy_id := v_session.policy_id;
      out_issued_at := v_session.issued_at;
      out_initial_expires_at := v_session.initial_expires_at;
      out_expires_at := v_session.expires_at;
      out_exchanged_at := v_session.exchanged_at;
      out_agent_session_id := v_session.agent_session_id;
      out_credential_id := v_session.credential_id;
      out_revoked_at := v_session.revoked_at;
      out_handoff_expires_at := NULL;
      out_committed_at := v_existing.committed_at;
      RETURN NEXT;
      RETURN;
    END IF;
    RAISE EXCEPTION 'commerce_idempotency_conflict' USING ERRCODE = 'P0D01';
  END IF;
  PERFORM 1 FROM openarc_durable.idempotency_records r
   WHERE r.organization_id = organization_id AND r.mutation_id = mutation_id FOR UPDATE;
  IF FOUND THEN
    RAISE EXCEPTION 'commerce_idempotency_conflict' USING ERRCODE = 'P0D01';
  END IF;

  SELECT s.* INTO v_session
    FROM openarc_durable.commerce_sessions s
   WHERE s.organization_id = organization_id AND s.session_id = session_id_input FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;

  INSERT INTO openarc_durable.idempotency_records (
    organization_id, operation, key_hash, request_digest, digest_version,
    actor_account_id, session_context_digest, network, mutation_id, status
  ) VALUES (
    organization_id, 'control.commerce_session.revoke', key_hash, request_digest,
    'control.commerce_session.revoke.v1', v_actor, session_context_digest,
    'eip155:5042002', mutation_id, 'pending'
  );
  IF v_session.revoked_at IS NULL THEN
    SELECT clock_timestamp() INTO v_now;
    UPDATE openarc_durable.commerce_sessions s
       SET revoked_at = v_now
     WHERE s.organization_id = organization_id AND s.session_id = session_id_input
       AND s.revoked_at IS NULL;
    IF NOT FOUND THEN
      SELECT s.* INTO v_session FROM openarc_durable.commerce_sessions s
       WHERE s.organization_id = organization_id AND s.session_id = session_id_input;
    ELSE
      v_session.revoked_at := v_now;
    END IF;
  END IF;
  UPDATE openarc_durable.idempotency_records r
     SET status = 'committed', resource_type = 'commerce_session',
         resource_id = session_id_input::text, committed_at = clock_timestamp()
   WHERE r.organization_id = organization_id AND r.operation = 'control.commerce_session.revoke'
     AND r.key_hash = key_hash
   RETURNING r.committed_at INTO v_committed_at;
  INSERT INTO openarc_durable.audit_events (
    organization_id, actor_account_id, operation, mutation_id, resource_type, resource_id, outcome
  ) VALUES (
    organization_id, v_actor, 'control.commerce_session.revoke', mutation_id,
    'commerce_session', session_id_input::text, 'committed'
  );
  INSERT INTO openarc_durable.outbox_events (
    organization_id, mutation_id, resource_type, resource_id, event_type, payload_version
  ) VALUES (
    organization_id, mutation_id, 'commerce_session', session_id_input::text,
    'control.commerce_session.revoked', 1
  );

  SELECT l.out_actor INTO v_recheck
    FROM openarc_durable.lock_commerce_human(human_session_hash, organization_id, false) AS l;
  IF v_recheck IS NULL OR v_recheck <> v_actor THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;

  out_replayed := false;
  out_session_id := v_session.session_id;
  out_organization_id := organization_id;
  out_subject_agent_id := v_session.subject_agent_id;
  out_policy_id := v_session.policy_id;
  out_issued_at := v_session.issued_at;
  out_initial_expires_at := v_session.initial_expires_at;
  out_expires_at := v_session.expires_at;
  out_exchanged_at := v_session.exchanged_at;
  out_agent_session_id := v_session.agent_session_id;
  out_credential_id := v_session.credential_id;
  out_revoked_at := v_session.revoked_at;
  out_handoff_expires_at := NULL;
  out_committed_at := v_committed_at;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Human status. Current owner/operator non-recovery; a missing/foreign session
-- returns no row (safe not_found). The session is re-read after the result so a
-- session that expired during the read cannot publish a status item.
-- ---------------------------------------------------------------------------

-- Shared private DB-time status derivation used by BOTH detail and list. It
-- never asserts authority and never blocks the current owner/operator from
-- inspecting invalidated/expired history. Precedence: revoked, expired
-- (including an unexchanged handoff that has lapsed), invalidated (dead parent
-- human session/role, subject agent, current policy, or the bound machine
-- session/credential), then handoff_pending/active.
CREATE FUNCTION openarc_durable.derive_commerce_session_status(
  organization_id text,
  session_id_input uuid
) RETURNS text
LANGUAGE sql STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT CASE
    WHEN s.session_id IS NULL THEN NULL
    WHEN s.revoked_at IS NOT NULL THEN 'revoked'
    WHEN clock_timestamp() >= s.expires_at THEN 'expired'
    WHEN s.exchanged_at IS NULL AND NOT EXISTS (
      SELECT 1 FROM openarc_durable.commerce_session_handoffs h
       WHERE h.organization_id = s.organization_id AND h.session_id = s.session_id
         AND h.expires_at > clock_timestamp()) THEN 'expired'
    WHEN NOT EXISTS (
      SELECT 1 FROM openarc_auth.sessions hs
       JOIN openarc_auth.accounts ha ON ha.account_id = hs.account_id
      WHERE hs.token_hash = s.parent_human_session_hash
        AND hs.account_id = s.parent_human_account_id
        AND hs.method <> 'recovery' AND ha.status = 'active'
        AND hs.expires_at > clock_timestamp()) THEN 'invalidated'
    WHEN NOT EXISTS (
      SELECT 1 FROM openarc_tenant.memberships m
       WHERE m.organization_id = s.organization_id
         AND m.account_id = s.parent_human_account_id
         AND m.status = 'active' AND m.role IN ('owner', 'operator')) THEN 'invalidated'
    WHEN NOT EXISTS (
      SELECT 1 FROM openarc_tenant.agents a
       WHERE a.organization_id = s.organization_id
         AND a.agent_id = s.subject_agent_id AND a.status = 'active') THEN 'invalidated'
    WHEN NOT EXISTS (
      SELECT 1 FROM openarc_tenant.budget_policy_roots r
       JOIN openarc_tenant.budget_policy_versions pv
         ON pv.organization_id = r.organization_id AND pv.policy_id = r.policy_id
        AND pv.revision = r.current_revision
       WHERE r.organization_id = s.organization_id AND r.policy_id = s.policy_id
         AND r.status = 'active' AND r.subject_agent_id = s.subject_agent_id
         AND (pv.expires_at IS NULL OR pv.expires_at > clock_timestamp())) THEN 'invalidated'
    WHEN s.exchanged_at IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM openarc_durable.agent_sessions ms
       JOIN openarc_durable.agent_credentials mc
         ON mc.organization_id = ms.organization_id AND mc.credential_id = ms.credential_id
      WHERE ms.session_id = s.agent_session_id AND ms.organization_id = s.organization_id
        AND ms.agent_id = s.subject_agent_id AND ms.credential_id = s.credential_id
        AND ms.revoked_at IS NULL AND ms.expires_at > clock_timestamp()
        AND ms.scope = 'agent:self.read' AND ms.scope_version = 1
        AND ms.environment = 'eip155:5042002'
        AND mc.revoked_at IS NULL AND mc.expires_at > clock_timestamp()
        AND mc.scope = 'agent:self.read' AND mc.scope_version = 1
        AND mc.environment = 'eip155:5042002') THEN 'invalidated'
    WHEN s.exchanged_at IS NULL THEN 'handoff_pending'
    ELSE 'active'
  END
  FROM (SELECT 1) AS anchor
  LEFT JOIN openarc_durable.commerce_sessions s
    ON s.organization_id = organization_id AND s.session_id = session_id_input;
$$;

CREATE FUNCTION openarc_durable.read_commerce_session(
  human_session_hash text,
  organization_id text,
  session_id_input uuid
) RETURNS TABLE(
  out_session_id uuid,
  out_organization_id text,
  out_subject_agent_id text,
  out_policy_id text,
  out_issued_at timestamptz,
  out_initial_expires_at timestamptz,
  out_expires_at timestamptz,
  out_exchanged_at timestamptz,
  out_agent_session_id uuid,
  out_credential_id uuid,
  out_revoked_at timestamptz,
  out_status text
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
  IF NOT openarc_durable.is_canonical_org_id(organization_id) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF session_id_input IS NULL
     OR NOT openarc_durable.is_canonical_commerce_session_id(session_id_input::text) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  SELECT l.out_actor INTO v_actor
    FROM openarc_durable.lock_commerce_reader(human_session_hash, organization_id) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
    SELECT s.session_id, s.organization_id, s.subject_agent_id, s.policy_id,
           s.issued_at, s.initial_expires_at, s.expires_at, s.exchanged_at,
           s.agent_session_id, s.credential_id, s.revoked_at,
           openarc_durable.derive_commerce_session_status(s.organization_id, s.session_id)
      FROM openarc_durable.commerce_sessions s
     WHERE s.organization_id = organization_id AND s.session_id = session_id_input;
  SELECT l.out_actor INTO v_recheck
    FROM openarc_durable.lock_commerce_reader(human_session_hash, organization_id) AS l;
  IF v_recheck IS NULL OR v_recheck <> v_actor THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;
END;
$$;

-- Human list: owner/operator non-recovery, keyset UUID ascending, limit 1..51
-- (repository fetches limit+1 for lookahead and validates before slicing).
CREATE FUNCTION openarc_durable.list_commerce_sessions(
  human_session_hash text,
  organization_id text,
  after_session_id uuid,
  page_limit integer
) RETURNS TABLE(
  out_session_id uuid,
  out_organization_id text,
  out_subject_agent_id text,
  out_policy_id text,
  out_issued_at timestamptz,
  out_initial_expires_at timestamptz,
  out_expires_at timestamptz,
  out_exchanged_at timestamptz,
  out_agent_session_id uuid,
  out_credential_id uuid,
  out_revoked_at timestamptz,
  out_status text
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
  IF NOT openarc_durable.is_canonical_org_id(organization_id) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF page_limit IS NULL OR page_limit < 1 OR page_limit > 51 THEN
    RAISE EXCEPTION 'commerce_page_invalid' USING ERRCODE = '22023';
  END IF;
  IF after_session_id IS NOT NULL
     AND NOT openarc_durable.is_canonical_commerce_session_id(after_session_id::text) THEN
    RAISE EXCEPTION 'commerce_page_invalid' USING ERRCODE = '22023';
  END IF;
  v_limit := page_limit;
  SELECT l.out_actor INTO v_actor
    FROM openarc_durable.lock_commerce_reader(human_session_hash, organization_id) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
    SELECT s.session_id, s.organization_id, s.subject_agent_id, s.policy_id,
           s.issued_at, s.initial_expires_at, s.expires_at, s.exchanged_at,
           s.agent_session_id, s.credential_id, s.revoked_at,
           openarc_durable.derive_commerce_session_status(s.organization_id, s.session_id)
      FROM openarc_durable.commerce_sessions s
     WHERE s.organization_id = organization_id
       AND (after_session_id IS NULL OR s.session_id > after_session_id)
     ORDER BY s.session_id
     LIMIT v_limit;
  SELECT l.out_actor INTO v_recheck
    FROM openarc_durable.lock_commerce_reader(human_session_hash, organization_id) AS l;
  IF v_recheck IS NULL OR v_recheck <> v_actor THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- Mutation status readers. Human status is bound to the same verified actor;
-- agent status is bound to the exact current agent session + credential
-- context. A foreign/missing receipt is a safe not_found.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.read_human_commerce_session_mutation_status(
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
  v_recheck text;
  v_found boolean := false;
  v_mutation_id uuid;
  v_operation text;
  v_resource_type text;
  v_resource_id text;
  v_committed_at timestamptz;
BEGIN
  IF NOT openarc_durable.is_canonical_org_id(organization_id) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF mutation_id IS NULL THEN
    RAISE EXCEPTION 'commerce_mutation_invalid' USING ERRCODE = '22023';
  END IF;
  SELECT l.out_actor INTO v_actor
    FROM openarc_durable.lock_commerce_reader(human_session_hash, organization_id) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT r.mutation_id, r.operation, r.resource_type, r.resource_id, r.committed_at
    INTO v_mutation_id, v_operation, v_resource_type, v_resource_id, v_committed_at
    FROM openarc_durable.idempotency_records r
   WHERE r.organization_id = organization_id AND r.mutation_id = mutation_id
     AND r.actor_account_id = v_actor AND r.status = 'committed'
     -- Exact presented session-context binding: the recorded digest must equal
     -- sha256(domain || ':' || session_hash) for THIS presenting human session
     -- and the row's operation, byte-for-byte with TS
     -- digestCommerceSessionHumanContext. A different LIVE session for the same
     -- account can never recover the receipt from account identity or session
     -- liveness alone. Exchange is a MACHINE context and is deliberately NOT
     -- readable through this human reader.
     AND r.session_context_digest = encode(
       sha256(convert_to(
         (CASE r.operation
            WHEN 'control.commerce_session.issue' THEN 'openarc.control.commerce_session.issue.session.v1'
            WHEN 'control.commerce_session.revoke' THEN 'openarc.control.commerce_session.revoke.session.v1'
          END) || ':' || human_session_hash,
         'UTF8'
       )),
       'hex'
     )
     AND r.operation IN (
       'control.commerce_session.issue',
       'control.commerce_session.revoke'
     );
  v_found := FOUND;
  SELECT l.out_actor INTO v_recheck
    FROM openarc_durable.lock_commerce_reader(human_session_hash, organization_id) AS l;
  IF v_recheck IS NULL OR v_recheck <> v_actor THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
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

CREATE FUNCTION openarc_durable.read_agent_commerce_session_mutation_status(
  agent_session_hash text,
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
  v_session record;
  v_issuer text;
  v_credential_expires timestamptz;
  v_found boolean := false;
  v_mutation_id uuid;
  v_operation text;
  v_resource_type text;
  v_resource_id text;
  v_committed_at timestamptz;
  v_now timestamptz;
BEGIN
  IF NOT openarc_durable.is_canonical_hex64(agent_session_hash) THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;
  IF mutation_id IS NULL THEN
    RAISE EXCEPTION 'commerce_mutation_invalid' USING ERRCODE = '22023';
  END IF;

  -- Resolve then lock in the accepted order; never authorize from the prelock.
  SELECT s.organization_id, s.agent_id, s.credential_id, s.session_id
    INTO v_session
    FROM openarc_durable.agent_sessions s
   WHERE s.token_hash = agent_session_hash AND s.revoked_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT c.issuer_account_id, c.expires_at INTO v_issuer, v_credential_expires
    FROM openarc_durable.agent_credentials c
   WHERE c.organization_id = v_session.organization_id
     AND c.credential_id = v_session.credential_id
     AND c.agent_id = v_session.agent_id AND c.revoked_at IS NULL;
  IF v_issuer IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM openarc_auth.accounts a
   WHERE a.account_id = v_issuer AND a.status = 'active' FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM openarc_tenant.organizations o
   WHERE o.organization_id = v_session.organization_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM openarc_tenant.memberships m
   WHERE m.organization_id = v_session.organization_id AND m.account_id = v_issuer
     AND m.status = 'active' AND m.role IN ('owner', 'operator') FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM openarc_tenant.agents a
   WHERE a.organization_id = v_session.organization_id AND a.agent_id = v_session.agent_id
     AND a.status = 'active' FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT clock_timestamp() INTO v_now;
  IF NOT (v_credential_expires > v_now) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT s.session_id, s.organization_id, s.agent_id, s.credential_id, s.expires_at, s.revoked_at
    INTO v_session
    FROM openarc_durable.agent_sessions s
   WHERE s.token_hash = agent_session_hash FOR UPDATE;
  IF NOT FOUND OR v_session.revoked_at IS NOT NULL OR NOT (v_session.expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  SELECT r.mutation_id, r.operation, r.resource_type, r.resource_id, r.committed_at
    INTO v_mutation_id, v_operation, v_resource_type, v_resource_id, v_committed_at
    FROM openarc_durable.idempotency_records r
    JOIN openarc_durable.commerce_sessions cs
      ON cs.organization_id = r.organization_id AND cs.session_id = r.commerce_session_id
   WHERE r.organization_id = v_session.organization_id AND r.mutation_id = mutation_id
     AND r.status = 'committed'
     AND r.operation = 'control.commerce_session.exchange'
     AND cs.agent_session_id = v_session.session_id
     AND cs.credential_id = v_session.credential_id;
  v_found := FOUND;
  -- Recheck the exact held agent session after the result read.
  PERFORM 1 FROM openarc_durable.agent_sessions s
   WHERE s.session_id = v_session.session_id AND s.revoked_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  IF NOT v_found THEN
    RETURN;
  END IF;
  out_mutation_id := v_mutation_id;
  out_operation := v_operation;
  out_resource_type := v_resource_type;
  out_resource_id := v_resource_id;
  out_committed_at := v_committed_at;
  out_organization_id := v_session.organization_id;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- ACLs: PUBLIC gets nothing; only the restricted runtime may execute the
-- public helpers. Internal validators/preamble remain grant-free.
-- ---------------------------------------------------------------------------
REVOKE ALL ON FUNCTION openarc_durable.is_canonical_commerce_session_id(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.enforce_commerce_session_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.enforce_commerce_handoff_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.enforce_commerce_handoff_window() FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.enforce_commerce_session_binding() FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.lock_commerce_human(text, text, boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.lock_commerce_reader(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.lock_commerce_writer(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.issue_commerce_session(text, text, text, text, integer, text, uuid, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.exchange_commerce_session(text, text, text, uuid, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.revoke_commerce_session(text, text, uuid, uuid, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.read_commerce_session(text, text, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.list_commerce_sessions(text, text, uuid, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.read_human_commerce_session_mutation_status(text, text, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.read_agent_commerce_session_mutation_status(text, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.resolve_agent_session_context(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.derive_commerce_session_status(text, uuid) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION openarc_durable.resolve_agent_session_context(text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.lock_commerce_reader(text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.lock_commerce_writer(text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.issue_commerce_session(text, text, text, text, integer, text, uuid, text, text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.exchange_commerce_session(text, text, text, uuid, text, text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.revoke_commerce_session(text, text, uuid, uuid, text, text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.read_commerce_session(text, text, uuid) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.list_commerce_sessions(text, text, uuid, integer) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.read_human_commerce_session_mutation_status(text, text, uuid) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.read_agent_commerce_session_mutation_status(text, uuid) TO openarc_tenant_app;
