-- OpenArc one-use authorization grants (schema12).
-- Additive over schema11. Owner: openarc_migrator. Runtime: openarc_tenant_app.
-- Three forced-RLS migrator-owned tables in openarc_durable plus narrow definer
-- helpers. This migration NEVER creates roles/schemas, calls a provider,
-- verifies a protocol requirement row, moves funds, settles, delivers or
-- records a payment. A claim is an opaque internal correlation only.
--
-- Authority model, frozen by the September13 review resolution:
--   * agent issue/replace authenticates the EXACT oacs_v1_ commerce-session
--     hash and its bound action; an old read-only machine bearer alone can
--     never authorize spending;
--   * a provider claim requires BOTH a current matching oas_pr_ provider
--     session under its existing provider:self.read scope AND the buyer's
--     exact one-use oag_v1_ grant token. Neither token alone permits a claim
--     and no existing credential scope or endpoint is widened here;
--   * human revoke is the same buyer organization with a current fresh
--     owner/operator non-recovery proof.
--
-- Token material is hash-only: the raw oag_v1_ secret is generated outside the
-- database, only its domain-separated hash is stored, and no status, replay,
-- projection or error path can reconstruct it. Retiring a generation is
-- one-way and a retired hash never becomes usable authority again.
--
-- The production listing paymentLane is literal 'unavailable' and production
-- has no verified requirement source, so the four tenant-runtime wrappers for
-- issue/replace/claim/introspect pass the literal 'production' mode and reject
-- 'internal_fixture' provenance exactly as schema10 does. The migrator-only
-- closed cores accept production|internal_fixture and can prove transaction
-- mechanics without ever minting runtime-valid authority. There is no caller,
-- environment, GUC, callback or boolean fixture flag, and no permissive
-- provider bypass. Human revoke is deliberately NOT provenance-gated: buyer
-- cleanup must never be blocked by the provenance of what it is retiring.

-- ---------------------------------------------------------------------------
-- Canonical grant identifier. Same lower-case UUIDv4 grammar as the schema10
-- action/reservation/approval ids under the distinct openarc:grant namespace.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.is_canonical_grant_id(value text)
RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT value IS NOT NULL
     AND value ~ '^openarc:grant:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
$$;

-- ---------------------------------------------------------------------------
-- Additive immutable binding anchors on the accepted schema10 tables. Neither
-- changes an existing column, constraint or trigger: they only publish the
-- exact tuples the grant composite foreign keys below reference, so a grant,
-- a claim and its action can never disagree about seller, provider, listing,
-- version, requirement, subject, commerce session or reservation. The
-- schema10 action trigger already forbids every one of these fields from
-- moving after insert, so the anchors are stable for the life of the row.
-- ---------------------------------------------------------------------------
ALTER TABLE openarc_durable.commerce_actions
  ADD CONSTRAINT commerce_actions_grant_binding UNIQUE (
    organization_id, action_id, subject_agent_id, commerce_session_id,
    seller_organization_id, provider_id, listing_id, listing_version,
    requirement_id, reservation_id);

ALTER TABLE openarc_durable.budget_reservations
  ADD CONSTRAINT budget_reservations_grant_binding UNIQUE (
    organization_id, reservation_id, action_id);

-- ---------------------------------------------------------------------------
-- authorization_grants: exactly one grant per buyer action. Every ownership,
-- financial and routing fact is mirrored from the immutable action (and so,
-- transitively, from the immutable requirement); no duplicate public buyer or
-- provider authority is representable and no reusable bearer scope exists.
-- Expiry is bounded by BOTH the current chain of authority and a hard 300
-- second ceiling, and is immutable, so a replacement can never extend it.
-- ---------------------------------------------------------------------------
CREATE TABLE openarc_durable.authorization_grants (
  organization_id text NOT NULL,
  grant_id text NOT NULL,
  action_id text NOT NULL,
  reservation_id text NOT NULL,
  subject_agent_id text NOT NULL,
  commerce_session_id uuid NOT NULL,
  seller_organization_id text NOT NULL,
  provider_id text NOT NULL,
  listing_id text NOT NULL,
  listing_version text NOT NULL,
  requirement_id text NOT NULL,
  source_kind text NOT NULL,
  current_generation integer NOT NULL,
  status text NOT NULL,
  issued_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  claimed_at timestamptz,
  revoked_at timestamptz,
  PRIMARY KEY (organization_id, grant_id),
  CONSTRAINT authorization_grants_grant_unique UNIQUE (grant_id),
  -- One grant per action, forever. A second issue, a new idempotency key or a
  -- replacement can never mint a second logical grant or a second reservation.
  CONSTRAINT authorization_grants_action_unique UNIQUE (organization_id, action_id),
  -- Binding anchor referenced by the claim composite foreign key below, so a
  -- claim can never disagree with its grant about action, reservation, seller,
  -- provider, listing, version or requirement.
  CONSTRAINT authorization_grants_claim_binding UNIQUE (
    organization_id, grant_id, action_id, reservation_id, seller_organization_id,
    provider_id, listing_id, listing_version, requirement_id),
  CONSTRAINT authorization_grants_id_valid CHECK (openarc_durable.is_canonical_grant_id(grant_id)),
  CONSTRAINT authorization_grants_action_valid CHECK (openarc_durable.is_canonical_action_id(action_id)),
  CONSTRAINT authorization_grants_reservation_valid CHECK (openarc_durable.is_canonical_reservation_id(reservation_id)),
  CONSTRAINT authorization_grants_subject_valid CHECK (openarc_durable.is_canonical_agent_id(subject_agent_id)),
  CONSTRAINT authorization_grants_provider_valid CHECK (openarc_durable.is_canonical_provider_id(provider_id)),
  CONSTRAINT authorization_grants_listing_valid CHECK (openarc_durable.is_canonical_listing_id(listing_id)),
  CONSTRAINT authorization_grants_version_valid CHECK (openarc_durable.is_canonical_listing_version(listing_version)),
  CONSTRAINT authorization_grants_requirement_valid CHECK (openarc_durable.is_canonical_requirement_id(requirement_id)),
  CONSTRAINT authorization_grants_source_valid CHECK (openarc_durable.is_canonical_source_kind(source_kind)),
  CONSTRAINT authorization_grants_generation_valid CHECK (
    current_generation BETWEEN 1 AND 2147483647),
  CONSTRAINT authorization_grants_status_valid CHECK (status IN ('issued', 'claimed', 'revoked')),
  -- Hard 300 second maximum validity plus a strictly future first issue.
  CONSTRAINT authorization_grants_window_valid CHECK (
    expires_at > issued_at AND expires_at <= issued_at + interval '300 seconds'),
  CONSTRAINT authorization_grants_clock_valid CHECK (
    updated_at >= issued_at
    AND (claimed_at IS NULL OR (claimed_at >= issued_at AND claimed_at < expires_at AND updated_at >= claimed_at))
    AND (revoked_at IS NULL OR (revoked_at >= issued_at AND updated_at >= revoked_at))
    AND (claimed_at IS NULL OR revoked_at IS NULL OR revoked_at >= claimed_at)),
  -- A revoked grant KEEPS a prior claimed_at: revocation never erases a claim
  -- fact or the exposure it may represent.
  CONSTRAINT authorization_grants_status_shape CHECK (
    (status = 'issued' AND claimed_at IS NULL AND revoked_at IS NULL)
    OR (status = 'claimed' AND claimed_at IS NOT NULL AND revoked_at IS NULL)
    OR (status = 'revoked' AND revoked_at IS NOT NULL)),
  CONSTRAINT authorization_grants_org_fk FOREIGN KEY (organization_id)
    REFERENCES openarc_tenant.organizations(organization_id) ON DELETE RESTRICT,
  CONSTRAINT authorization_grants_seller_org_fk FOREIGN KEY (seller_organization_id)
    REFERENCES openarc_tenant.organizations(organization_id) ON DELETE RESTRICT,
  CONSTRAINT authorization_grants_session_fk FOREIGN KEY (organization_id, commerce_session_id)
    REFERENCES openarc_durable.commerce_sessions(organization_id, session_id) ON DELETE RESTRICT,
  -- The grant mirrors the action binding EXACTLY, including its reservation.
  CONSTRAINT authorization_grants_action_binding_fk FOREIGN KEY (
    organization_id, action_id, subject_agent_id, commerce_session_id,
    seller_organization_id, provider_id, listing_id, listing_version,
    requirement_id, reservation_id)
    REFERENCES openarc_durable.commerce_actions (
      organization_id, action_id, subject_agent_id, commerce_session_id,
      seller_organization_id, provider_id, listing_id, listing_version,
      requirement_id, reservation_id) ON DELETE RESTRICT,
  CONSTRAINT authorization_grants_reservation_fk FOREIGN KEY (
    organization_id, reservation_id, action_id)
    REFERENCES openarc_durable.budget_reservations (
      organization_id, reservation_id, action_id) ON DELETE RESTRICT,
  CONSTRAINT authorization_grants_requirement_fk FOREIGN KEY (organization_id, requirement_id)
    REFERENCES openarc_durable.commerce_requirement_references(organization_id, requirement_id) ON DELETE RESTRICT
);

CREATE INDEX authorization_grants_action_idx
  ON openarc_durable.authorization_grants (organization_id, action_id);

-- ---------------------------------------------------------------------------
-- authorization_grant_tokens: append-only hash generations. The raw secret,
-- any salt, pepper, signature or request body is NEVER stored. token_hash is
-- globally unique so a regenerated hash colliding with ANY current or retired
-- hash fails closed, and the partial unique index below permits at most one
-- non-retired generation per grant, so a retired token can never reappear
-- after any number of rotations.
-- ---------------------------------------------------------------------------
CREATE TABLE openarc_durable.authorization_grant_tokens (
  organization_id text NOT NULL,
  grant_id text NOT NULL,
  generation integer NOT NULL,
  token_hash text NOT NULL,
  hash_version integer NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  retired_at timestamptz,
  PRIMARY KEY (organization_id, grant_id, generation),
  CONSTRAINT authorization_grant_tokens_hash_unique UNIQUE (token_hash),
  CONSTRAINT authorization_grant_tokens_hash_valid CHECK (openarc_durable.is_canonical_hex64(token_hash)),
  CONSTRAINT authorization_grant_tokens_version_valid CHECK (hash_version = 1),
  CONSTRAINT authorization_grant_tokens_generation_valid CHECK (
    generation BETWEEN 1 AND 2147483647),
  CONSTRAINT authorization_grant_tokens_retire_valid CHECK (
    retired_at IS NULL OR retired_at >= created_at),
  CONSTRAINT authorization_grant_tokens_grant_fk FOREIGN KEY (organization_id, grant_id)
    REFERENCES openarc_durable.authorization_grants(organization_id, grant_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX authorization_grant_tokens_one_live
  ON openarc_durable.authorization_grant_tokens (organization_id, grant_id)
  WHERE retired_at IS NULL;

-- ---------------------------------------------------------------------------
-- authorization_grant_claims: exactly one claim per grant, atomically binding
-- the grant, action, reservation, seller, provider, listing, version,
-- requirement, the exact claiming provider credential/session and the provider
-- attempt. The (seller org, provider, attempt) uniqueness stops one attempt
-- from claiming two grants. claim_digest is an opaque internal correlation
-- derived by the database from immutable facts: it is NOT a verified payment
-- nonce, signature, settlement or delivery evidence.
-- ---------------------------------------------------------------------------
CREATE TABLE openarc_durable.authorization_grant_claims (
  organization_id text NOT NULL,
  grant_id text NOT NULL,
  action_id text NOT NULL,
  reservation_id text NOT NULL,
  seller_organization_id text NOT NULL,
  provider_id text NOT NULL,
  listing_id text NOT NULL,
  listing_version text NOT NULL,
  requirement_id text NOT NULL,
  provider_credential_id uuid NOT NULL,
  provider_session_id uuid NOT NULL,
  attempt_id uuid NOT NULL,
  claim_digest text NOT NULL,
  claimed_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id, grant_id),
  CONSTRAINT authorization_grant_claims_attempt_unique UNIQUE (
    seller_organization_id, provider_id, attempt_id),
  CONSTRAINT authorization_grant_claims_attempt_valid CHECK (
    openarc_durable.is_canonical_uuid_v4(attempt_id::text)),
  CONSTRAINT authorization_grant_claims_digest_valid CHECK (
    openarc_durable.is_canonical_sha256_digest(claim_digest)),
  CONSTRAINT authorization_grant_claims_grant_fk FOREIGN KEY (
    organization_id, grant_id, action_id, reservation_id, seller_organization_id,
    provider_id, listing_id, listing_version, requirement_id)
    REFERENCES openarc_durable.authorization_grants (
      organization_id, grant_id, action_id, reservation_id, seller_organization_id,
      provider_id, listing_id, listing_version, requirement_id) ON DELETE RESTRICT,
  CONSTRAINT authorization_grant_claims_reservation_fk FOREIGN KEY (
    organization_id, reservation_id, action_id)
    REFERENCES openarc_durable.budget_reservations (
      organization_id, reservation_id, action_id) ON DELETE RESTRICT,
  CONSTRAINT authorization_grant_claims_credential_fk FOREIGN KEY (
    seller_organization_id, provider_credential_id)
    REFERENCES openarc_durable.provider_credentials(organization_id, credential_id) ON DELETE RESTRICT,
  CONSTRAINT authorization_grant_claims_session_fk FOREIGN KEY (provider_session_id)
    REFERENCES openarc_durable.provider_sessions(session_id) ON DELETE RESTRICT,
  CONSTRAINT authorization_grant_claims_provider_fk FOREIGN KEY (seller_organization_id, provider_id)
    REFERENCES openarc_tenant.providers(organization_id, provider_id) ON DELETE RESTRICT
);

CREATE INDEX authorization_grant_claims_attempt_idx
  ON openarc_durable.authorization_grant_claims (seller_organization_id, provider_id, attempt_id);

-- ---------------------------------------------------------------------------
-- Immutability and one-way transition triggers.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.enforce_authorization_grant_mutation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'authorization_grant_immutable' USING ERRCODE = '42501';
  END IF;
  IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
     OR NEW.grant_id IS DISTINCT FROM OLD.grant_id
     OR NEW.action_id IS DISTINCT FROM OLD.action_id
     OR NEW.reservation_id IS DISTINCT FROM OLD.reservation_id
     OR NEW.subject_agent_id IS DISTINCT FROM OLD.subject_agent_id
     OR NEW.commerce_session_id IS DISTINCT FROM OLD.commerce_session_id
     OR NEW.seller_organization_id IS DISTINCT FROM OLD.seller_organization_id
     OR NEW.provider_id IS DISTINCT FROM OLD.provider_id
     OR NEW.listing_id IS DISTINCT FROM OLD.listing_id
     OR NEW.listing_version IS DISTINCT FROM OLD.listing_version
     OR NEW.requirement_id IS DISTINCT FROM OLD.requirement_id
     OR NEW.source_kind IS DISTINCT FROM OLD.source_kind
     OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
     -- Immutable expiry: a replacement can never extend the original window.
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
    RAISE EXCEPTION 'authorization_grant_immutable' USING ERRCODE = '42501';
  END IF;
  IF NOT (NEW.updated_at > OLD.updated_at) THEN
    RAISE EXCEPTION 'authorization_grant_clock_invalid' USING ERRCODE = '23514';
  END IF;
  -- Generations advance by exactly one, only while the grant is still issued
  -- and never claimed, so a replacement cannot follow a claim or an exposure.
  IF NEW.current_generation IS DISTINCT FROM OLD.current_generation THEN
    IF NEW.current_generation <> OLD.current_generation + 1
       OR OLD.status <> 'issued' OR NEW.status <> 'issued'
       OR OLD.claimed_at IS NOT NULL OR NEW.claimed_at IS NOT NULL THEN
      RAISE EXCEPTION 'authorization_grant_generation_invalid' USING ERRCODE = '23514';
    END IF;
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
       (OLD.status = 'issued' AND NEW.status IN ('claimed', 'revoked'))
       OR (OLD.status = 'claimed' AND NEW.status = 'revoked')) THEN
    RAISE EXCEPTION 'authorization_grant_status_invalid' USING ERRCODE = '23514';
  END IF;
  -- A recorded claim or revocation instant never moves, so revocation retains
  -- the claim fact and a repeated revoke can release nothing.
  IF OLD.claimed_at IS NOT NULL AND NEW.claimed_at IS DISTINCT FROM OLD.claimed_at THEN
    RAISE EXCEPTION 'authorization_grant_claim_immutable' USING ERRCODE = '42501';
  END IF;
  IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    RAISE EXCEPTION 'authorization_grant_revocation_immutable' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER authorization_grants_mutation
  BEFORE UPDATE OR DELETE ON openarc_durable.authorization_grants
  FOR EACH ROW EXECUTE FUNCTION openarc_durable.enforce_authorization_grant_mutation();

CREATE FUNCTION openarc_durable.enforce_grant_token_mutation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'authorization_grant_token_immutable' USING ERRCODE = '42501';
  END IF;
  IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
     OR NEW.grant_id IS DISTINCT FROM OLD.grant_id
     OR NEW.generation IS DISTINCT FROM OLD.generation
     OR NEW.token_hash IS DISTINCT FROM OLD.token_hash
     OR NEW.hash_version IS DISTINCT FROM OLD.hash_version
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'authorization_grant_token_immutable' USING ERRCODE = '42501';
  END IF;
  -- Retirement is one-way: a retired generation never becomes usable again.
  IF OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at THEN
    RAISE EXCEPTION 'authorization_grant_token_retired' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER authorization_grant_tokens_mutation
  BEFORE UPDATE OR DELETE ON openarc_durable.authorization_grant_tokens
  FOR EACH ROW EXECUTE FUNCTION openarc_durable.enforce_grant_token_mutation();

CREATE FUNCTION openarc_durable.reject_grant_claim_mutation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'authorization_grant_claim_immutable' USING ERRCODE = '42501';
END;
$$;

CREATE TRIGGER authorization_grant_claims_immutable
  BEFORE UPDATE OR DELETE ON openarc_durable.authorization_grant_claims
  FOR EACH ROW EXECUTE FUNCTION openarc_durable.reject_grant_claim_mutation();

-- ---------------------------------------------------------------------------
-- RLS: migrator-only. Runtime/worker/PUBLIC receive no direct privilege.
-- ---------------------------------------------------------------------------
ALTER TABLE openarc_durable.authorization_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE openarc_durable.authorization_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE openarc_durable.authorization_grant_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE openarc_durable.authorization_grant_tokens FORCE ROW LEVEL SECURITY;
ALTER TABLE openarc_durable.authorization_grant_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE openarc_durable.authorization_grant_claims FORCE ROW LEVEL SECURITY;

CREATE POLICY authorization_grants_migrator ON openarc_durable.authorization_grants
  FOR ALL TO openarc_migrator USING (true) WITH CHECK (true);
CREATE POLICY authorization_grant_tokens_migrator ON openarc_durable.authorization_grant_tokens
  FOR ALL TO openarc_migrator USING (true) WITH CHECK (true);
CREATE POLICY authorization_grant_claims_migrator ON openarc_durable.authorization_grant_claims
  FOR ALL TO openarc_migrator USING (true) WITH CHECK (true);

REVOKE ALL ON TABLE openarc_durable.authorization_grants FROM PUBLIC;
REVOKE ALL ON TABLE openarc_durable.authorization_grant_tokens FROM PUBLIC;
REVOKE ALL ON TABLE openarc_durable.authorization_grant_claims FROM PUBLIC;

-- No new policy is added anywhere else. The schema5 provider credential and
-- provider session tables already carry migrator FOR ALL policies, and
-- schema10 already added the migrator tenant-side policies the listing and
-- policy locks need, so the claim core reaches every row it must lock without
-- widening any runtime access.

-- ---------------------------------------------------------------------------
-- Explicit action state extension. The accepted five-state enum gains exactly
-- one state, grant_issued, which like reserved_not_granted REQUIRES a non-null
-- reservation. No other status, shape or transition is loosened: the closed
-- schema10 edges are reproduced verbatim below and only the two new edges
--   reserved_not_granted -> grant_issued   (atomic issuance)
--   grant_issued        -> cancelled       (never-claimed safe cleanup)
-- are added, each additionally gated on the real grant row so a live grant can
-- never be mislabeled and a cancelled action can never hide one.
--
-- The schema10 cancel core accepts only pending_approval/reserved_not_granted
-- and therefore already fails closed for grant_issued; grant revoke owns the
-- safe cleanup path.
-- ---------------------------------------------------------------------------
ALTER TABLE openarc_durable.commerce_actions
  DROP CONSTRAINT commerce_actions_status_valid,
  DROP CONSTRAINT commerce_actions_approval_shape;

ALTER TABLE openarc_durable.commerce_actions
  ADD CONSTRAINT commerce_actions_status_valid CHECK (status IN (
    'pending_approval', 'reserved_not_granted', 'grant_issued',
    'rejected', 'cancelled', 'expired')),
  ADD CONSTRAINT commerce_actions_approval_shape CHECK (
    (status = 'pending_approval' AND approval_id IS NOT NULL AND reservation_id IS NULL)
    OR (status = 'reserved_not_granted' AND reservation_id IS NOT NULL)
    OR (status = 'grant_issued' AND reservation_id IS NOT NULL)
    OR (status = 'rejected' AND approval_id IS NOT NULL AND reservation_id IS NULL)
    OR (status IN ('cancelled', 'expired') AND (approval_id IS NOT NULL OR reservation_id IS NOT NULL)));

CREATE OR REPLACE FUNCTION openarc_durable.enforce_commerce_action_mutation() RETURNS trigger
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
       OR (OLD.status = 'reserved_not_granted' AND NEW.status IN ('grant_issued', 'cancelled', 'expired'))
       OR (OLD.status = 'grant_issued' AND NEW.status = 'cancelled')
       OR (OLD.status IN ('rejected', 'cancelled', 'expired') AND NEW.status = OLD.status)) THEN
    RAISE EXCEPTION 'commerce_action_status_invalid' USING ERRCODE = '23514';
  END IF;
  -- A real grant must already exist for this exact action before the action
  -- may be labeled grant_issued, so the label can never be minted alone.
  IF OLD.status = 'reserved_not_granted' AND NEW.status = 'grant_issued' THEN
    PERFORM 1 FROM openarc_durable.authorization_grants g
     WHERE g.organization_id = NEW.organization_id AND g.action_id = NEW.action_id
       AND g.grant_id IS NOT NULL AND g.status = 'issued';
    IF NOT FOUND THEN
      RAISE EXCEPTION 'commerce_action_grant_missing' USING ERRCODE = '23514';
    END IF;
  END IF;
  -- Cleanup may only cancel a granted action whose grant is already revoked
  -- and was NEVER claimed, so a possible payment is never relabeled cancelled.
  IF OLD.status = 'grant_issued' AND NEW.status = 'cancelled' THEN
    PERFORM 1 FROM openarc_durable.authorization_grants g
     WHERE g.organization_id = NEW.organization_id AND g.action_id = NEW.action_id
       AND g.status = 'revoked' AND g.claimed_at IS NULL;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'commerce_action_grant_live' USING ERRCODE = '23514';
    END IF;
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

-- ---------------------------------------------------------------------------
-- Closed operation / resource / event union extensions. Every accepted tuple
-- is retained VERBATIM; only the four grant operations, the four grant events
-- and the single authorization_grant resource type are appended, plus a
-- canonical grant-id shape check on each durable table. The unchanged market,
-- policy and commerce-session shape constraints are NOT touched. The
-- regenerated outbox receipt_operation mapping preserves every older mapping.
-- ---------------------------------------------------------------------------
ALTER TABLE openarc_durable.idempotency_records
  DROP CONSTRAINT idempotency_operation_valid,
  DROP CONSTRAINT idempotency_digest_version_valid,
  DROP CONSTRAINT idempotency_resource_type_valid,
  DROP CONSTRAINT idempotency_resource_matches_operation;

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
    'control.commerce_action.cancel',
    'control.grant.issue',
    'control.grant.replace',
    'control.grant.revoke',
    'control.grant.claim'
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
    'control.commerce_action.cancel.v1',
    'control.grant.issue.v1',
    'control.grant.replace.v1',
    'control.grant.revoke.v1',
    'control.grant.claim.v1'
  )),
  ADD CONSTRAINT idempotency_resource_type_valid CHECK (resource_type IS NULL OR resource_type IN (
    'organization', 'agent', 'provider', 'membership',
    'agent_credential', 'provider_credential',
    'listing', 'listing_version',
    'budget_policy', 'budget_policy_revision',
    'commerce_session', 'commerce_action', 'authorization_grant'
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
      WHEN 'control.grant.issue' THEN 'authorization_grant'
      WHEN 'control.grant.replace' THEN 'authorization_grant'
      WHEN 'control.grant.revoke' THEN 'authorization_grant'
      WHEN 'control.grant.claim' THEN 'authorization_grant'
    END
  ),
  ADD CONSTRAINT idempotency_grant_resource_shape CHECK (
    (resource_type = 'authorization_grant'
     AND resource_id IS NOT NULL
     AND openarc_durable.is_canonical_grant_id(resource_id))
    OR resource_type IS DISTINCT FROM 'authorization_grant'
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
    'control.policy.revoke',
    'control.commerce_session.issue',
    'control.commerce_session.exchange',
    'control.commerce_session.revoke',
    'control.commerce_action.authorize',
    'control.commerce_action.approve',
    'control.commerce_action.reject',
    'control.commerce_action.cancel',
    'control.grant.issue',
    'control.grant.replace',
    'control.grant.revoke',
    'control.grant.claim'
  )),
  ADD CONSTRAINT audit_resource_type_valid CHECK (resource_type IN (
    'organization', 'agent', 'provider', 'membership',
    'agent_credential', 'provider_credential',
    'listing', 'listing_version',
    'budget_policy', 'budget_policy_revision',
    'commerce_session', 'commerce_action', 'authorization_grant'
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
      WHEN 'control.grant.issue' THEN 'authorization_grant'
      WHEN 'control.grant.replace' THEN 'authorization_grant'
      WHEN 'control.grant.revoke' THEN 'authorization_grant'
      WHEN 'control.grant.claim' THEN 'authorization_grant'
    END
  ),
  ADD CONSTRAINT audit_grant_resource_shape CHECK (
    (resource_type = 'authorization_grant'
     AND openarc_durable.is_canonical_grant_id(resource_id))
    OR resource_type IS DISTINCT FROM 'authorization_grant'
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
    'commerce_session', 'commerce_action', 'authorization_grant'
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
    'control.commerce_action.cancelled',
    'control.grant.issued',
    'control.grant.replaced',
    'control.grant.revoked',
    'control.grant.claimed'
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
      WHEN 'control.grant.issued' THEN 'control.grant.issue'
      WHEN 'control.grant.replaced' THEN 'control.grant.replace'
      WHEN 'control.grant.revoked' THEN 'control.grant.revoke'
      WHEN 'control.grant.claimed' THEN 'control.grant.claim'
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
      WHEN 'control.grant.issued' THEN 'authorization_grant'
      WHEN 'control.grant.replaced' THEN 'authorization_grant'
      WHEN 'control.grant.revoked' THEN 'authorization_grant'
      WHEN 'control.grant.claimed' THEN 'authorization_grant'
    END
  ),
  ADD CONSTRAINT outbox_receipt_fk FOREIGN KEY (
    organization_id, mutation_id, resource_type, resource_id, receipt_operation
  ) REFERENCES openarc_durable.idempotency_records (
    organization_id, mutation_id, resource_type, resource_id, operation
  ) ON DELETE RESTRICT;

ALTER TABLE openarc_durable.outbox_events
  ADD CONSTRAINT outbox_grant_resource_shape CHECK (
    (resource_type = 'authorization_grant'
     AND openarc_durable.is_canonical_grant_id(resource_id))
    OR resource_type IS DISTINCT FROM 'authorization_grant'
  );

-- ---------------------------------------------------------------------------
-- Opaque internal claim correlation. Derived by the DATABASE from immutable
-- grant/action/provider/requirement/attempt facts plus the exact provider
-- session that claimed, so no caller price, origin or payload can influence
-- it. It proves no signature, payment, settlement or delivery.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.grant_claim_digest(
  grant_id_input text,
  action_id_input text,
  reservation_id_input text,
  seller_organization_id text,
  provider_id_input text,
  listing_id_input text,
  listing_version_input text,
  requirement_id_input text,
  requirement_digest_input text,
  amount_atomic_input text,
  fee_atomic_input text,
  provider_credential_id_input uuid,
  provider_session_id_input uuid,
  attempt_id_input uuid
) RETURNS text
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT 'sha256:' || encode(
    sha256(convert_to(
      'openarc.control.grant.claim.v1' || E'\n' ||
      grant_id_input || E'\n' || action_id_input || E'\n' || reservation_id_input || E'\n' ||
      seller_organization_id || E'\n' || provider_id_input || E'\n' ||
      listing_id_input || E'\n' || listing_version_input || E'\n' ||
      requirement_id_input || E'\n' || requirement_digest_input || E'\n' ||
      amount_atomic_input || E'\n' || fee_atomic_input || E'\n' ||
      provider_credential_id_input::text || E'\n' || provider_session_id_input::text || E'\n' ||
      attempt_id_input::text,
      'UTF8'
    )),
    'hex'
  );
$$;

-- ---------------------------------------------------------------------------
-- Buyer commerce chain for issue and replace. The caller presents ONLY the
-- exact consumed oacs_v1_ commerce token hash and the bound action id: an old
-- oas_ag_ read-only machine bearer can never select a commerce session here,
-- and every binding below is DB-derived, never a caller selection.
--
-- Frozen lock order: immutable lookups first, then the schema10 combined
-- helper (ALL involved accounts sorted -> parent human session -> buyer+seller
-- organizations TOGETHER sorted -> involved memberships -> buyer agent ->
-- buyer credential -> buyer machine session), then the buyer selected policy
-- root and its PINNED revision, the seller provider/listing/version/origin
-- review, the immutable requirement, the buyer commerce session, the stable
-- buyer exposure row and finally the action and its reservation. The grant,
-- token and claim rows are locked by the callers AFTER this whole set. No
-- partial prelock helper is introduced and no external call is made.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.lock_grant_commerce_chain(
  commerce_token_hash text,
  action_id_input text
) RETURNS TABLE(
  out_organization_id text,
  out_subject_agent_id text,
  out_parent_human_account_id text,
  out_commerce_session_id uuid,
  out_seller_organization_id text,
  out_provider_id text,
  out_listing_id text,
  out_listing_version text,
  out_requirement_id text,
  out_requirement_digest text,
  out_amount_atomic text,
  out_fee_atomic text,
  out_debit_atomic text,
  out_reservation_id text,
  out_action_status text,
  out_reservation_status text,
  out_reservation_claimed_at timestamptz,
  out_source_kind text,
  out_chain_expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_ctx record;
  v_chain record;
  v_action record;
  v_root record;
  v_policy record;
  v_requirement record;
  v_reservation record;
  v_session_expires timestamptz;
  v_parent_expires timestamptz;
  v_org text;
  v_now timestamptz;
BEGIN
  IF NOT openarc_durable.is_canonical_hex64(commerce_token_hash) THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;
  IF NOT openarc_durable.is_canonical_action_id(action_id_input) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;

  -- Immutable lookups first, without any lock or authority.
  SELECT * INTO v_ctx
    FROM openarc_durable.resolve_commerce_action_context(commerce_token_hash) AS c;
  IF v_ctx.out_organization_id IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  v_org := v_ctx.out_organization_id;
  SELECT a.* INTO v_action FROM openarc_durable.commerce_actions a
   WHERE a.organization_id = v_org AND a.action_id = action_id_input;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;

  -- Full combined schema10 chain, with both organizations locked together.
  SELECT * INTO v_chain
    FROM openarc_durable.lock_action_commerce(
      commerce_token_hash, v_action.seller_organization_id) AS c;
  IF v_chain.out_organization_id IS DISTINCT FROM v_org THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  -- The action must be bound to the EXACT presented commerce chain.
  IF v_action.commerce_session_id IS DISTINCT FROM v_chain.out_commerce_session_id
     OR v_action.credential_id IS DISTINCT FROM v_chain.out_credential_id
     OR v_action.agent_session_id IS DISTINCT FROM v_chain.out_agent_session_id
     OR v_action.subject_agent_id IS DISTINCT FROM v_chain.out_subject_agent_id
     OR v_action.policy_id IS DISTINCT FROM v_chain.out_policy_id
     OR v_action.parent_human_account_id IS DISTINCT FROM v_chain.out_parent_human_account_id THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- Buyer selected policy root and its PINNED revision.
  SELECT r.current_revision, r.status, r.subject_agent_id INTO v_root
    FROM openarc_tenant.budget_policy_roots r
   WHERE r.organization_id = v_org AND r.policy_id = v_action.policy_id FOR UPDATE;
  IF NOT FOUND OR v_root.status <> 'active'
     OR v_root.subject_agent_id IS DISTINCT FROM v_action.subject_agent_id
     OR v_root.current_revision IS DISTINCT FROM v_action.policy_revision THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT v.* INTO v_policy FROM openarc_tenant.budget_policy_versions v
   WHERE v.organization_id = v_org AND v.policy_id = v_action.policy_id
     AND v.revision = v_action.policy_revision FOR UPDATE;
  IF NOT FOUND
     OR v_policy.subject_agent_id IS DISTINCT FROM v_action.subject_agent_id
     OR v_policy.network_id IS DISTINCT FROM v_action.network_id
     OR v_policy.asset IS DISTINCT FROM v_action.asset
     OR v_policy.representation IS DISTINCT FROM v_action.representation
     OR v_policy.decimals IS DISTINCT FROM v_action.decimals THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT clock_timestamp() INTO v_now;
  IF v_policy.expires_at IS NOT NULL AND NOT (v_policy.expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_grant_expired' USING ERRCODE = 'P0D15';
  END IF;

  -- Real current SELLER provider/listing/version/approved origin.
  PERFORM openarc_durable.lock_action_listing(
    v_action.seller_organization_id, v_action.provider_id,
    v_action.listing_id, v_action.listing_version);

  -- Immutable requirement row and its exact binding.
  SELECT r.* INTO v_requirement
    FROM openarc_durable.commerce_requirement_references r
   WHERE r.organization_id = v_org AND r.requirement_id = v_action.requirement_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  IF v_requirement.seller_organization_id IS DISTINCT FROM v_action.seller_organization_id
     OR v_requirement.provider_id IS DISTINCT FROM v_action.provider_id
     OR v_requirement.listing_id IS DISTINCT FROM v_action.listing_id
     OR v_requirement.listing_version IS DISTINCT FROM v_action.listing_version
     OR v_requirement.requirement_digest IS DISTINCT FROM v_action.requirement_digest
     OR v_requirement.amount_atomic IS DISTINCT FROM v_action.amount_atomic
     OR v_requirement.fee_atomic IS DISTINCT FROM v_action.fee_atomic
     OR v_requirement.source_kind IS DISTINCT FROM v_action.source_kind THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  IF NOT (v_requirement.valid_until > v_now) THEN
    RAISE EXCEPTION 'commerce_grant_expired' USING ERRCODE = 'P0D15';
  END IF;

  -- Current buyer commerce session state, then the parent human session.
  v_session_expires := openarc_durable.lock_action_commerce_state(commerce_token_hash, v_org);
  SELECT hs.expires_at INTO v_parent_expires
    FROM openarc_auth.sessions hs
   WHERE hs.token_hash = v_chain.out_parent_human_session_hash
     AND hs.account_id = v_chain.out_parent_human_account_id
     AND hs.method <> 'recovery';
  IF v_parent_expires IS NULL OR NOT (v_parent_expires > v_now) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- Stable buyer exposure row, then the action and its reservation.
  PERFORM 1 FROM openarc_durable.commerce_exposure_locks e
   WHERE e.organization_id = v_org AND e.subject_agent_id = v_action.subject_agent_id
     AND e.network_id = v_action.network_id AND e.asset = v_action.asset
     AND e.representation = v_action.representation AND e.decimals = v_action.decimals
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT a.* INTO v_action FROM openarc_durable.commerce_actions a
   WHERE a.organization_id = v_org AND a.action_id = action_id_input FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  IF v_action.reservation_id IS NULL THEN
    RAISE EXCEPTION 'commerce_grant_conflict' USING ERRCODE = 'P0D14';
  END IF;
  SELECT b.* INTO v_reservation FROM openarc_durable.budget_reservations b
   WHERE b.organization_id = v_org AND b.reservation_id = v_action.reservation_id
     AND b.action_id = action_id_input FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;

  out_organization_id := v_org;
  out_subject_agent_id := v_action.subject_agent_id;
  out_parent_human_account_id := v_chain.out_parent_human_account_id;
  out_commerce_session_id := v_action.commerce_session_id;
  out_seller_organization_id := v_action.seller_organization_id;
  out_provider_id := v_action.provider_id;
  out_listing_id := v_action.listing_id;
  out_listing_version := v_action.listing_version;
  out_requirement_id := v_action.requirement_id;
  out_requirement_digest := v_action.requirement_digest;
  out_amount_atomic := v_action.amount_atomic;
  out_fee_atomic := v_action.fee_atomic;
  out_debit_atomic := v_action.debit_atomic;
  out_reservation_id := v_action.reservation_id;
  out_action_status := v_action.status;
  out_reservation_status := v_reservation.status;
  out_reservation_claimed_at := v_reservation.claimed_at;
  out_source_kind := v_action.source_kind;
  -- Every current bound of the chain of authority, with no external call.
  out_chain_expires_at := LEAST(
    v_action.expires_at,
    v_requirement.valid_until,
    v_session_expires,
    v_chain.out_machine_expires_at,
    COALESCE(v_policy.expires_at, 'infinity'::timestamptz),
    v_parent_expires);
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Provider identity resolution and lock for the historical attempt-status
-- reader. It authenticates the CURRENT oas_pr_ provider session under its
-- existing provider:self.read scope and yields the DB-derived seller
-- organization and provider. It reads no buyer-private field, needs no live
-- buyer chain (history must survive buyer revocation or expiry) and can never
-- claim, reserve, consume or revive anything.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.lock_grant_provider_identity(
  provider_session_hash text
) RETURNS TABLE(
  out_organization_id text,
  out_provider_id text,
  out_credential_id uuid,
  out_session_id uuid,
  out_session_expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_session record;
  v_credential record;
  v_issuer text;
  v_org text;
  v_provider text;
  v_credential_id uuid;
  v_role text;
  v_status text;
  v_now timestamptz;
BEGIN
  IF NOT openarc_durable.is_canonical_hex64(provider_session_hash) THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;
  SELECT s.organization_id, s.provider_id, s.credential_id
    INTO v_org, v_provider, v_credential_id
    FROM openarc_durable.provider_sessions s
   WHERE s.token_hash = provider_session_hash;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;
  SELECT c.issuer_account_id INTO v_issuer
    FROM openarc_durable.provider_credentials c
   WHERE c.organization_id = v_org AND c.credential_id = v_credential_id
     AND c.provider_id = v_provider;
  IF v_issuer IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM openarc_auth.accounts a
   WHERE a.account_id = v_issuer AND a.status = 'active' FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM openarc_tenant.organizations o
   WHERE o.organization_id = v_org FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT m.role, m.status INTO v_role, v_status FROM openarc_tenant.memberships m
   WHERE m.organization_id = v_org AND m.account_id = v_issuer FOR UPDATE;
  IF v_role IS NULL OR v_status <> 'active' OR v_role NOT IN ('owner', 'operator') THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM openarc_tenant.providers p
   WHERE p.organization_id = v_org AND p.provider_id = v_provider
     AND p.status = 'active' FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT c.* INTO v_credential FROM openarc_durable.provider_credentials c
   WHERE c.organization_id = v_org AND c.credential_id = v_credential_id FOR UPDATE;
  IF NOT FOUND OR v_credential.revoked_at IS NOT NULL
     OR v_credential.scope <> 'provider:self.read' OR v_credential.scope_version <> 1
     OR v_credential.environment <> 'eip155:5042002' THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT s.* INTO v_session FROM openarc_durable.provider_sessions s
   WHERE s.token_hash = provider_session_hash FOR UPDATE;
  IF NOT FOUND
     OR v_session.organization_id IS DISTINCT FROM v_org
     OR v_session.provider_id IS DISTINCT FROM v_provider
     OR v_session.credential_id IS DISTINCT FROM v_credential_id
     OR v_session.revoked_at IS NOT NULL
     OR v_session.scope <> 'provider:self.read' OR v_session.scope_version <> 1
     OR v_session.environment <> 'eip155:5042002' THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;
  SELECT clock_timestamp() INTO v_now;
  IF NOT (v_credential.expires_at > v_now) OR NOT (v_session.expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;
  out_organization_id := v_org;
  out_provider_id := v_provider;
  out_credential_id := v_credential_id;
  out_session_id := v_session.session_id;
  out_session_expires_at := v_session.expires_at;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- The full combined buyer/seller/account lock set for a provider-presented
-- grant, in the frozen order, BEFORE the grant row itself is locked:
--   ALL involved accounts sorted (buyer parent human, buyer credential issuer,
--   provider credential issuer)
--   -> the buyer parent human session (deterministic; a provider machine
--      credential never invents a live browser session it did not have)
--   -> buyer + seller organization rows TOGETHER sorted
--   -> every involved membership sorted by (organization, account)
--   -> buyer agent -> buyer credential -> buyer machine session
--   -> buyer selected policy root and PINNED revision
--   -> seller provider -> provider credential -> exact provider session
--   -> seller listing/version/origin review -> immutable requirement
--   -> buyer commerce session -> buyer stable exposure
--   -> action and reservation -> grant.
-- A reverse buyer/seller pair can never deadlock on a partial organization
-- set, no partial prelock helper is used and no external call is made.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.lock_grant_provider_chain(
  provider_session_hash text,
  grant_id_input text
) RETURNS TABLE(
  out_organization_id text,
  out_grant_id text,
  out_action_id text,
  out_reservation_id text,
  out_subject_agent_id text,
  out_commerce_session_id uuid,
  out_seller_organization_id text,
  out_provider_id text,
  out_listing_id text,
  out_listing_version text,
  out_requirement_id text,
  out_requirement_digest text,
  out_amount_atomic text,
  out_fee_atomic text,
  out_debit_atomic text,
  out_source_kind text,
  out_grant_status text,
  out_grant_generation integer,
  out_issued_at timestamptz,
  out_expires_at timestamptz,
  out_claimed_at timestamptz,
  out_revoked_at timestamptz,
  out_action_status text,
  out_reservation_status text,
  out_provider_credential_id uuid,
  out_provider_session_id uuid,
  out_provider_issuer_account_id text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_grant record;
  v_action record;
  v_root record;
  v_policy record;
  v_requirement record;
  v_reservation record;
  v_commerce record;
  v_credential record;
  v_session record;
  v_machine record;
  v_buyer_credential record;
  v_provider_org text;
  v_provider_id text;
  v_provider_credential_id uuid;
  v_provider_issuer text;
  v_buyer_issuer text;
  v_parent_hash text;
  v_org text;
  v_accounts text[];
  v_role text;
  v_status text;
  v_now timestamptz;
BEGIN
  IF NOT openarc_durable.is_canonical_hex64(provider_session_hash) THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;
  IF NOT openarc_durable.is_canonical_grant_id(grant_id_input) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;

  -- Immutable lookups first: grant, its action and the presented provider
  -- session identity. Nothing is locked and no authority is asserted yet.
  SELECT g.* INTO v_grant FROM openarc_durable.authorization_grants g
   WHERE g.grant_id = grant_id_input;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT a.* INTO v_action FROM openarc_durable.commerce_actions a
   WHERE a.organization_id = v_grant.organization_id AND a.action_id = v_grant.action_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT s.organization_id, s.provider_id, s.credential_id
    INTO v_provider_org, v_provider_id, v_provider_credential_id
    FROM openarc_durable.provider_sessions s
   WHERE s.token_hash = provider_session_hash;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;
  -- The grant delegates exactly one action to exactly one seller provider. A
  -- foreign provider, a foreign seller organization or any other listing can
  -- never satisfy the second factor.
  IF v_provider_org IS DISTINCT FROM v_grant.seller_organization_id
     OR v_provider_id IS DISTINCT FROM v_grant.provider_id THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT c.issuer_account_id INTO v_provider_issuer
    FROM openarc_durable.provider_credentials c
   WHERE c.organization_id = v_provider_org AND c.credential_id = v_provider_credential_id
     AND c.provider_id = v_provider_id;
  IF v_provider_issuer IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT c.issuer_account_id INTO v_buyer_issuer
    FROM openarc_durable.agent_credentials c
   WHERE c.organization_id = v_action.organization_id AND c.credential_id = v_action.credential_id
     AND c.agent_id = v_action.subject_agent_id;
  IF v_buyer_issuer IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- ALL involved accounts, sorted, all currently active.
  v_accounts := ARRAY[v_action.parent_human_account_id, v_buyer_issuer, v_provider_issuer];
  PERFORM 1 FROM openarc_auth.accounts a
   WHERE a.account_id = ANY (v_accounts) AND a.status = 'active'
   ORDER BY a.account_id FOR UPDATE;
  IF (SELECT count(*) FROM openarc_auth.accounts a
       WHERE a.account_id IN (SELECT DISTINCT x FROM unnest(v_accounts) AS x)
         AND a.status = 'active')
     <> (SELECT count(DISTINCT x) FROM unnest(v_accounts) AS x) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- The buyer parent human session, deterministically, BEFORE any organization.
  SELECT cs.parent_human_session_hash INTO v_parent_hash
    FROM openarc_durable.commerce_sessions cs
   WHERE cs.organization_id = v_action.organization_id
     AND cs.session_id = v_action.commerce_session_id;
  IF v_parent_hash IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM openarc_auth.sessions hs
   WHERE hs.token_hash = v_parent_hash
     AND hs.account_id = v_action.parent_human_account_id
     AND hs.method <> 'recovery' FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- Buyer and seller organization rows locked TOGETHER in sorted order.
  PERFORM 1 FROM openarc_tenant.organizations o
   WHERE o.organization_id IN (v_action.organization_id, v_grant.seller_organization_id)
   ORDER BY o.organization_id FOR UPDATE;
  IF (SELECT count(*) FROM openarc_tenant.organizations o
       WHERE o.organization_id IN (SELECT DISTINCT x FROM unnest(
         ARRAY[v_action.organization_id, v_grant.seller_organization_id]) AS x))
     <> (SELECT count(DISTINCT x) FROM unnest(
           ARRAY[v_action.organization_id, v_grant.seller_organization_id]) AS x) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- Every involved membership, sorted by (organization, account).
  PERFORM 1 FROM openarc_tenant.memberships m
   WHERE (m.organization_id = v_action.organization_id
          AND m.account_id IN (v_action.parent_human_account_id, v_buyer_issuer))
      OR (m.organization_id = v_grant.seller_organization_id
          AND m.account_id = v_provider_issuer)
   ORDER BY m.organization_id, m.account_id FOR UPDATE;
  FOR v_role, v_status IN
    SELECT m.role, m.status FROM openarc_tenant.memberships m
     WHERE (m.organization_id = v_action.organization_id
            AND m.account_id IN (v_action.parent_human_account_id, v_buyer_issuer))
        OR (m.organization_id = v_grant.seller_organization_id
            AND m.account_id = v_provider_issuer)
  LOOP
    IF v_status <> 'active' OR v_role NOT IN ('owner', 'operator') THEN
      RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
    END IF;
  END LOOP;
  -- Every required (organization, account) membership pair must exist. The
  -- required set is deduplicated so a same-organization buyer/seller chain or
  -- a shared owner account is counted exactly once.
  IF (SELECT count(*) FROM openarc_tenant.memberships m
       WHERE (m.organization_id = v_action.organization_id
              AND m.account_id IN (v_action.parent_human_account_id, v_buyer_issuer))
          OR (m.organization_id = v_grant.seller_organization_id
              AND m.account_id = v_provider_issuer))
     <> (SELECT count(*) FROM (
           SELECT v_action.organization_id AS o, v_action.parent_human_account_id AS a
           UNION
           SELECT v_action.organization_id, v_buyer_issuer
           UNION
           SELECT v_grant.seller_organization_id, v_provider_issuer) AS required) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- Buyer agent, buyer credential, buyer machine session.
  PERFORM 1 FROM openarc_tenant.agents a
   WHERE a.organization_id = v_action.organization_id
     AND a.agent_id = v_action.subject_agent_id AND a.status = 'active' FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT c.* INTO v_buyer_credential FROM openarc_durable.agent_credentials c
   WHERE c.organization_id = v_action.organization_id
     AND c.credential_id = v_action.credential_id FOR UPDATE;
  IF NOT FOUND OR v_buyer_credential.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT s.* INTO v_machine FROM openarc_durable.agent_sessions s
   WHERE s.session_id = v_action.agent_session_id FOR UPDATE;
  IF NOT FOUND
     OR v_machine.organization_id IS DISTINCT FROM v_action.organization_id
     OR v_machine.agent_id IS DISTINCT FROM v_action.subject_agent_id
     OR v_machine.credential_id IS DISTINCT FROM v_action.credential_id
     OR v_machine.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT clock_timestamp() INTO v_now;
  IF NOT (v_buyer_credential.expires_at > v_now) OR NOT (v_machine.expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- Buyer selected policy root and its PINNED revision.
  SELECT r.current_revision, r.status, r.subject_agent_id INTO v_root
    FROM openarc_tenant.budget_policy_roots r
   WHERE r.organization_id = v_action.organization_id
     AND r.policy_id = v_action.policy_id FOR UPDATE;
  IF NOT FOUND OR v_root.status <> 'active'
     OR v_root.subject_agent_id IS DISTINCT FROM v_action.subject_agent_id
     OR v_root.current_revision IS DISTINCT FROM v_action.policy_revision THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT v.* INTO v_policy FROM openarc_tenant.budget_policy_versions v
   WHERE v.organization_id = v_action.organization_id AND v.policy_id = v_action.policy_id
     AND v.revision = v_action.policy_revision FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  IF v_policy.expires_at IS NOT NULL AND NOT (v_policy.expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_grant_expired' USING ERRCODE = 'P0D15';
  END IF;

  -- Seller provider, provider credential, then the EXACT provider session.
  PERFORM 1 FROM openarc_tenant.providers p
   WHERE p.organization_id = v_provider_org AND p.provider_id = v_provider_id
     AND p.status = 'active' FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT c.* INTO v_credential FROM openarc_durable.provider_credentials c
   WHERE c.organization_id = v_provider_org AND c.credential_id = v_provider_credential_id
   FOR UPDATE;
  IF NOT FOUND OR v_credential.revoked_at IS NOT NULL
     OR v_credential.scope <> 'provider:self.read' OR v_credential.scope_version <> 1
     OR v_credential.environment <> 'eip155:5042002'
     OR NOT (v_credential.expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT s.* INTO v_session FROM openarc_durable.provider_sessions s
   WHERE s.token_hash = provider_session_hash FOR UPDATE;
  IF NOT FOUND
     OR v_session.organization_id IS DISTINCT FROM v_provider_org
     OR v_session.provider_id IS DISTINCT FROM v_provider_id
     OR v_session.credential_id IS DISTINCT FROM v_provider_credential_id
     OR v_session.revoked_at IS NOT NULL
     OR v_session.scope <> 'provider:self.read' OR v_session.scope_version <> 1
     OR v_session.environment <> 'eip155:5042002'
     OR NOT (v_session.expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;

  -- Seller listing/version/approved origin, then the immutable requirement.
  PERFORM openarc_durable.lock_action_listing(
    v_grant.seller_organization_id, v_grant.provider_id,
    v_grant.listing_id, v_grant.listing_version);
  SELECT r.* INTO v_requirement FROM openarc_durable.commerce_requirement_references r
   WHERE r.organization_id = v_action.organization_id
     AND r.requirement_id = v_action.requirement_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  IF v_requirement.requirement_digest IS DISTINCT FROM v_action.requirement_digest
     OR v_requirement.amount_atomic IS DISTINCT FROM v_action.amount_atomic
     OR v_requirement.fee_atomic IS DISTINCT FROM v_action.fee_atomic THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  IF NOT (v_requirement.valid_until > v_now) THEN
    RAISE EXCEPTION 'commerce_grant_expired' USING ERRCODE = 'P0D15';
  END IF;

  -- Buyer commerce session, then the stable buyer exposure row.
  SELECT cs.* INTO v_commerce FROM openarc_durable.commerce_sessions cs
   WHERE cs.organization_id = v_action.organization_id
     AND cs.session_id = v_action.commerce_session_id FOR UPDATE;
  IF NOT FOUND OR v_commerce.revoked_at IS NOT NULL OR v_commerce.exchanged_at IS NULL
     OR NOT (v_commerce.expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM openarc_durable.commerce_exposure_locks e
   WHERE e.organization_id = v_action.organization_id
     AND e.subject_agent_id = v_action.subject_agent_id
     AND e.network_id = v_action.network_id AND e.asset = v_action.asset
     AND e.representation = v_action.representation AND e.decimals = v_action.decimals
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;

  -- Action and reservation, then finally the grant row itself.
  SELECT a.* INTO v_action FROM openarc_durable.commerce_actions a
   WHERE a.organization_id = v_grant.organization_id AND a.action_id = v_grant.action_id
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT b.* INTO v_reservation FROM openarc_durable.budget_reservations b
   WHERE b.organization_id = v_grant.organization_id
     AND b.reservation_id = v_grant.reservation_id
     AND b.action_id = v_grant.action_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  v_org := v_grant.organization_id;
  SELECT g.* INTO v_grant FROM openarc_durable.authorization_grants g
   WHERE g.organization_id = v_org AND g.grant_id = grant_id_input
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;

  out_organization_id := v_grant.organization_id;
  out_grant_id := v_grant.grant_id;
  out_action_id := v_grant.action_id;
  out_reservation_id := v_grant.reservation_id;
  out_subject_agent_id := v_grant.subject_agent_id;
  out_commerce_session_id := v_grant.commerce_session_id;
  out_seller_organization_id := v_grant.seller_organization_id;
  out_provider_id := v_grant.provider_id;
  out_listing_id := v_grant.listing_id;
  out_listing_version := v_grant.listing_version;
  out_requirement_id := v_grant.requirement_id;
  out_requirement_digest := v_action.requirement_digest;
  out_amount_atomic := v_action.amount_atomic;
  out_fee_atomic := v_action.fee_atomic;
  out_debit_atomic := v_action.debit_atomic;
  out_source_kind := v_grant.source_kind;
  out_grant_status := v_grant.status;
  out_grant_generation := v_grant.current_generation;
  out_issued_at := v_grant.issued_at;
  out_expires_at := v_grant.expires_at;
  out_claimed_at := v_grant.claimed_at;
  out_revoked_at := v_grant.revoked_at;
  out_action_status := v_action.status;
  out_reservation_status := v_reservation.status;
  out_provider_credential_id := v_provider_credential_id;
  out_provider_session_id := v_session.session_id;
  out_provider_issuer_account_id := v_provider_issuer;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Atomic issuance. The agent presents the EXACT consumed oacs_v1_ commerce
-- token hash, the bound reserved action and the domain-separated hash of a raw
-- oag_v1_ secret generated outside the database. Grant ids derive from the
-- first-issue mutation id, so a retry cannot invent a different logical grant
-- and a new idempotency key can never mint a second grant or a second
-- reservation. The grant row, its first token generation and the action's
-- reserved_not_granted -> grant_issued transition commit together or not at
-- all. Nothing here reads, stores, logs or returns the raw secret.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.issue_authorization_grant_core(
  mode text,
  commerce_token_hash text,
  action_id_input text,
  token_hash_input text,
  token_hash_version integer,
  mutation_id uuid,
  key_hash text,
  request_digest text,
  session_context_digest text
) RETURNS TABLE(
  out_replayed boolean,
  out_organization_id text,
  out_grant_id text,
  out_action_id text,
  out_reservation_id text,
  out_subject_agent_id text,
  out_commerce_session_id uuid,
  out_provider_id text,
  out_listing_id text,
  out_listing_version text,
  out_generation integer,
  out_status text,
  out_issued_at timestamptz,
  out_updated_at timestamptz,
  out_expires_at timestamptz,
  out_claimed_at timestamptz,
  out_revoked_at timestamptz,
  out_committed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_chain record;
  v_existing record;
  v_grant record;
  v_grant_id text;
  v_expires timestamptz;
  v_now timestamptz;
  v_committed_at timestamptz;
BEGIN
  IF mode IS DISTINCT FROM 'production' AND mode IS DISTINCT FROM 'internal_fixture' THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_canonical_hex64(commerce_token_hash)
     OR NOT openarc_durable.is_canonical_hex64(token_hash_input)
     OR NOT openarc_durable.is_canonical_hex64(key_hash)
     OR NOT openarc_durable.is_canonical_hex64(request_digest)
     OR NOT openarc_durable.is_canonical_hex64(session_context_digest) THEN
    RAISE EXCEPTION 'commerce_metadata_invalid' USING ERRCODE = '22023';
  END IF;
  IF token_hash_version IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'commerce_metadata_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_canonical_action_id(action_id_input) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF mutation_id IS NULL OR NOT openarc_durable.is_canonical_uuid_v4(mutation_id::text) THEN
    RAISE EXCEPTION 'commerce_mutation_invalid' USING ERRCODE = '22023';
  END IF;

  -- Current caller authentication under the full frozen lock order BEFORE any
  -- replay disclosure, so an expired or revoked chain learns nothing.
  SELECT * INTO v_chain
    FROM openarc_durable.lock_grant_commerce_chain(commerce_token_hash, action_id_input) AS c;
  IF v_chain.out_organization_id IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  v_grant_id := 'openarc:grant:' || mutation_id::text;

  SELECT r.* INTO v_existing FROM openarc_durable.idempotency_records r
   WHERE r.organization_id = v_chain.out_organization_id
     AND r.operation = 'control.grant.issue' AND r.key_hash = key_hash FOR UPDATE;
  IF FOUND THEN
    IF v_existing.request_digest = request_digest
       AND v_existing.mutation_id = mutation_id
       AND v_existing.actor_account_id = v_chain.out_parent_human_account_id
       AND v_existing.session_context_digest = session_context_digest
       AND v_existing.status = 'committed'
       AND v_existing.resource_type = 'authorization_grant'
       AND v_existing.resource_id = v_grant_id THEN
      SELECT g.* INTO v_grant FROM openarc_durable.authorization_grants g
       WHERE g.organization_id = v_chain.out_organization_id AND g.grant_id = v_grant_id;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
      END IF;
      -- A safe receipt replay NEVER re-delivers a secret: no raw token and no
      -- token hash is representable in this projection.
      out_replayed := true;
      out_organization_id := v_grant.organization_id;
      out_grant_id := v_grant.grant_id;
      out_action_id := v_grant.action_id;
      out_reservation_id := v_grant.reservation_id;
      out_subject_agent_id := v_grant.subject_agent_id;
      out_commerce_session_id := v_grant.commerce_session_id;
      out_provider_id := v_grant.provider_id;
      out_listing_id := v_grant.listing_id;
      out_listing_version := v_grant.listing_version;
      out_generation := v_grant.current_generation;
      out_status := v_grant.status;
      out_issued_at := v_grant.issued_at;
      out_updated_at := v_grant.updated_at;
      out_expires_at := v_grant.expires_at;
      out_claimed_at := v_grant.claimed_at;
      out_revoked_at := v_grant.revoked_at;
      out_committed_at := v_existing.committed_at;
      RETURN NEXT;
      RETURN;
    END IF;
    RAISE EXCEPTION 'commerce_idempotency_conflict' USING ERRCODE = 'P0D01';
  END IF;
  PERFORM 1 FROM openarc_durable.idempotency_records r
   WHERE r.organization_id = v_chain.out_organization_id AND r.mutation_id = mutation_id
   FOR UPDATE;
  IF FOUND THEN
    RAISE EXCEPTION 'commerce_idempotency_conflict' USING ERRCODE = 'P0D01';
  END IF;

  -- Provenance admission. Production can never mint runtime-valid authority
  -- over an internal fixture requirement.
  IF mode = 'production' AND v_chain.out_source_kind = 'internal_fixture' THEN
    RAISE EXCEPTION 'commerce_requirement_unavailable' USING ERRCODE = 'P0D10';
  END IF;

  IF v_chain.out_action_status <> 'reserved_not_granted' THEN
    RAISE EXCEPTION 'commerce_grant_conflict' USING ERRCODE = 'P0D14';
  END IF;
  -- The existing reservation must still be held and never claimed. No second
  -- reservation is ever created here.
  IF v_chain.out_reservation_status <> 'held'
     OR v_chain.out_reservation_claimed_at IS NOT NULL THEN
    RAISE EXCEPTION 'commerce_grant_conflict' USING ERRCODE = 'P0D14';
  END IF;
  PERFORM 1 FROM openarc_durable.authorization_grants g
   WHERE g.organization_id = v_chain.out_organization_id
     AND g.action_id = action_id_input FOR UPDATE;
  IF FOUND THEN
    RAISE EXCEPTION 'commerce_grant_conflict' USING ERRCODE = 'P0D14';
  END IF;

  SELECT clock_timestamp() INTO v_now;
  -- Validity is the CURRENT chain of authority bounded by a hard 300 seconds.
  v_expires := LEAST(v_chain.out_chain_expires_at, v_now + interval '300 seconds');
  IF NOT (v_expires > v_now) THEN
    RAISE EXCEPTION 'commerce_grant_expired' USING ERRCODE = 'P0D15';
  END IF;

  INSERT INTO openarc_durable.idempotency_records (
    organization_id, operation, key_hash, request_digest, digest_version,
    actor_account_id, session_context_digest, network, mutation_id, status
  ) VALUES (
    v_chain.out_organization_id, 'control.grant.issue', key_hash, request_digest,
    'control.grant.issue.v1', v_chain.out_parent_human_account_id,
    session_context_digest, 'eip155:5042002', mutation_id, 'pending'
  );
  INSERT INTO openarc_durable.authorization_grants (
    organization_id, grant_id, action_id, reservation_id, subject_agent_id,
    commerce_session_id, seller_organization_id, provider_id, listing_id,
    listing_version, requirement_id, source_kind, current_generation, status,
    issued_at, updated_at, expires_at, claimed_at, revoked_at
  ) VALUES (
    v_chain.out_organization_id, v_grant_id, action_id_input, v_chain.out_reservation_id,
    v_chain.out_subject_agent_id, v_chain.out_commerce_session_id,
    v_chain.out_seller_organization_id, v_chain.out_provider_id, v_chain.out_listing_id,
    v_chain.out_listing_version, v_chain.out_requirement_id, v_chain.out_source_kind,
    1, 'issued', v_now, v_now, v_expires, NULL, NULL
  );
  INSERT INTO openarc_durable.authorization_grant_tokens (
    organization_id, grant_id, generation, token_hash, hash_version, created_at, retired_at
  ) VALUES (
    v_chain.out_organization_id, v_grant_id, 1, token_hash_input, token_hash_version,
    v_now, NULL
  );
  -- The action can never stay labeled reserved_not_granted while a real grant
  -- exists; the schema10 trigger only permits this exact edge.
  UPDATE openarc_durable.commerce_actions a
     SET status = 'grant_issued', updated_at = clock_timestamp()
   WHERE a.organization_id = v_chain.out_organization_id AND a.action_id = action_id_input;

  UPDATE openarc_durable.idempotency_records r
     SET status = 'committed', resource_type = 'authorization_grant',
         resource_id = v_grant_id, committed_at = clock_timestamp()
   WHERE r.organization_id = v_chain.out_organization_id
     AND r.operation = 'control.grant.issue' AND r.key_hash = key_hash
   RETURNING r.committed_at INTO v_committed_at;
  INSERT INTO openarc_durable.audit_events (
    organization_id, actor_account_id, operation, mutation_id, resource_type, resource_id, outcome
  ) VALUES (
    v_chain.out_organization_id, v_chain.out_parent_human_account_id, 'control.grant.issue',
    mutation_id, 'authorization_grant', v_grant_id, 'committed'
  );
  INSERT INTO openarc_durable.outbox_events (
    organization_id, mutation_id, resource_type, resource_id, event_type, payload_version
  ) VALUES (
    v_chain.out_organization_id, mutation_id, 'authorization_grant', v_grant_id,
    'control.grant.issued', 1
  );

  -- Final recheck after every durable write and all lock waits.
  SELECT clock_timestamp() INTO v_now;
  IF NOT (v_expires > v_now) THEN
    RAISE EXCEPTION 'commerce_grant_expired' USING ERRCODE = 'P0D15';
  END IF;
  PERFORM openarc_durable.lock_action_listing(
    v_chain.out_seller_organization_id, v_chain.out_provider_id,
    v_chain.out_listing_id, v_chain.out_listing_version);

  SELECT g.* INTO v_grant FROM openarc_durable.authorization_grants g
   WHERE g.organization_id = v_chain.out_organization_id AND g.grant_id = v_grant_id;
  out_replayed := false;
  out_organization_id := v_grant.organization_id;
  out_grant_id := v_grant.grant_id;
  out_action_id := v_grant.action_id;
  out_reservation_id := v_grant.reservation_id;
  out_subject_agent_id := v_grant.subject_agent_id;
  out_commerce_session_id := v_grant.commerce_session_id;
  out_provider_id := v_grant.provider_id;
  out_listing_id := v_grant.listing_id;
  out_listing_version := v_grant.listing_version;
  out_generation := v_grant.current_generation;
  out_status := v_grant.status;
  out_issued_at := v_grant.issued_at;
  out_updated_at := v_grant.updated_at;
  out_expires_at := v_grant.expires_at;
  out_claimed_at := v_grant.claimed_at;
  out_revoked_at := v_grant.revoked_at;
  out_committed_at := v_committed_at;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Replacement before any claim or exposure. It retires the current generation
-- and appends the next one on the SAME grant and the SAME reservation, and it
-- can never extend the original expiry (expires_at is immutable). A retired
-- hash is never usable again and a regenerated hash equal to any current or
-- retired hash fails closed on the global token-hash uniqueness.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.replace_authorization_grant_core(
  mode text,
  commerce_token_hash text,
  grant_id_input text,
  token_hash_input text,
  token_hash_version integer,
  mutation_id uuid,
  key_hash text,
  request_digest text,
  session_context_digest text
) RETURNS TABLE(
  out_replayed boolean,
  out_organization_id text,
  out_grant_id text,
  out_action_id text,
  out_reservation_id text,
  out_subject_agent_id text,
  out_commerce_session_id uuid,
  out_provider_id text,
  out_listing_id text,
  out_listing_version text,
  out_generation integer,
  out_status text,
  out_issued_at timestamptz,
  out_updated_at timestamptz,
  out_expires_at timestamptz,
  out_claimed_at timestamptz,
  out_revoked_at timestamptz,
  out_committed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_chain record;
  v_existing record;
  v_grant record;
  v_action_id text;
  v_org text;
  v_retired integer;
  v_now timestamptz;
  v_committed_at timestamptz;
BEGIN
  IF mode IS DISTINCT FROM 'production' AND mode IS DISTINCT FROM 'internal_fixture' THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_canonical_hex64(commerce_token_hash)
     OR NOT openarc_durable.is_canonical_hex64(token_hash_input)
     OR NOT openarc_durable.is_canonical_hex64(key_hash)
     OR NOT openarc_durable.is_canonical_hex64(request_digest)
     OR NOT openarc_durable.is_canonical_hex64(session_context_digest) THEN
    RAISE EXCEPTION 'commerce_metadata_invalid' USING ERRCODE = '22023';
  END IF;
  IF token_hash_version IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'commerce_metadata_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_canonical_grant_id(grant_id_input) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF mutation_id IS NULL OR NOT openarc_durable.is_canonical_uuid_v4(mutation_id::text) THEN
    RAISE EXCEPTION 'commerce_mutation_invalid' USING ERRCODE = '22023';
  END IF;

  -- Immutable lookup of the target grant's action, then the full buyer chain.
  SELECT g.organization_id, g.action_id INTO v_org, v_action_id
    FROM openarc_durable.authorization_grants g WHERE g.grant_id = grant_id_input;
  IF v_action_id IS NULL THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT * INTO v_chain
    FROM openarc_durable.lock_grant_commerce_chain(commerce_token_hash, v_action_id) AS c;
  IF v_chain.out_organization_id IS DISTINCT FROM v_org THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  SELECT r.* INTO v_existing FROM openarc_durable.idempotency_records r
   WHERE r.organization_id = v_org AND r.operation = 'control.grant.replace'
     AND r.key_hash = key_hash FOR UPDATE;
  IF FOUND THEN
    IF v_existing.request_digest = request_digest
       AND v_existing.mutation_id = mutation_id
       AND v_existing.actor_account_id = v_chain.out_parent_human_account_id
       AND v_existing.session_context_digest = session_context_digest
       AND v_existing.status = 'committed'
       AND v_existing.resource_type = 'authorization_grant'
       AND v_existing.resource_id = grant_id_input THEN
      SELECT g.* INTO v_grant FROM openarc_durable.authorization_grants g
       WHERE g.organization_id = v_org AND g.grant_id = grant_id_input;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
      END IF;
      out_replayed := true;
      out_organization_id := v_grant.organization_id;
      out_grant_id := v_grant.grant_id;
      out_action_id := v_grant.action_id;
      out_reservation_id := v_grant.reservation_id;
      out_subject_agent_id := v_grant.subject_agent_id;
      out_commerce_session_id := v_grant.commerce_session_id;
      out_provider_id := v_grant.provider_id;
      out_listing_id := v_grant.listing_id;
      out_listing_version := v_grant.listing_version;
      out_generation := v_grant.current_generation;
      out_status := v_grant.status;
      out_issued_at := v_grant.issued_at;
      out_updated_at := v_grant.updated_at;
      out_expires_at := v_grant.expires_at;
      out_claimed_at := v_grant.claimed_at;
      out_revoked_at := v_grant.revoked_at;
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

  IF mode = 'production' AND v_chain.out_source_kind = 'internal_fixture' THEN
    RAISE EXCEPTION 'commerce_requirement_unavailable' USING ERRCODE = 'P0D10';
  END IF;

  SELECT g.* INTO v_grant FROM openarc_durable.authorization_grants g
   WHERE g.organization_id = v_org AND g.grant_id = grant_id_input FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT clock_timestamp() INTO v_now;
  IF v_grant.status <> 'issued' OR v_grant.claimed_at IS NOT NULL
     OR v_grant.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'commerce_grant_conflict' USING ERRCODE = 'P0D14';
  END IF;
  -- Never after a claim OR after any exposure the claim may represent.
  PERFORM 1 FROM openarc_durable.authorization_grant_claims c
   WHERE c.organization_id = v_org AND c.grant_id = grant_id_input;
  IF FOUND THEN
    RAISE EXCEPTION 'commerce_grant_conflict' USING ERRCODE = 'P0D14';
  END IF;
  IF v_chain.out_action_status <> 'grant_issued' THEN
    RAISE EXCEPTION 'commerce_grant_conflict' USING ERRCODE = 'P0D14';
  END IF;
  IF v_chain.out_reservation_status <> 'held'
     OR v_chain.out_reservation_claimed_at IS NOT NULL THEN
    RAISE EXCEPTION 'commerce_potential_exposure' USING ERRCODE = 'P0D13';
  END IF;
  IF NOT (v_grant.expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_grant_expired' USING ERRCODE = 'P0D15';
  END IF;
  -- The current chain of authority must still cover the unchanged expiry.
  IF NOT (v_chain.out_chain_expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_grant_expired' USING ERRCODE = 'P0D15';
  END IF;
  IF v_grant.current_generation >= 2147483647 THEN
    RAISE EXCEPTION 'commerce_grant_conflict' USING ERRCODE = 'P0D14';
  END IF;

  INSERT INTO openarc_durable.idempotency_records (
    organization_id, operation, key_hash, request_digest, digest_version,
    actor_account_id, session_context_digest, network, mutation_id, status
  ) VALUES (
    v_org, 'control.grant.replace', key_hash, request_digest,
    'control.grant.replace.v1', v_chain.out_parent_human_account_id,
    session_context_digest, 'eip155:5042002', mutation_id, 'pending'
  );
  UPDATE openarc_durable.authorization_grant_tokens t
     SET retired_at = v_now
   WHERE t.organization_id = v_org AND t.grant_id = grant_id_input
     AND t.generation = v_grant.current_generation AND t.retired_at IS NULL;
  GET DIAGNOSTICS v_retired = ROW_COUNT;
  IF v_retired <> 1 THEN
    RAISE EXCEPTION 'commerce_grant_conflict' USING ERRCODE = 'P0D14';
  END IF;
  INSERT INTO openarc_durable.authorization_grant_tokens (
    organization_id, grant_id, generation, token_hash, hash_version, created_at, retired_at
  ) VALUES (
    v_org, grant_id_input, v_grant.current_generation + 1, token_hash_input,
    token_hash_version, v_now, NULL
  );
  UPDATE openarc_durable.authorization_grants g
     SET current_generation = g.current_generation + 1, updated_at = clock_timestamp()
   WHERE g.organization_id = v_org AND g.grant_id = grant_id_input;

  UPDATE openarc_durable.idempotency_records r
     SET status = 'committed', resource_type = 'authorization_grant',
         resource_id = grant_id_input, committed_at = clock_timestamp()
   WHERE r.organization_id = v_org AND r.operation = 'control.grant.replace'
     AND r.key_hash = key_hash
   RETURNING r.committed_at INTO v_committed_at;
  INSERT INTO openarc_durable.audit_events (
    organization_id, actor_account_id, operation, mutation_id, resource_type, resource_id, outcome
  ) VALUES (
    v_org, v_chain.out_parent_human_account_id, 'control.grant.replace', mutation_id,
    'authorization_grant', grant_id_input, 'committed'
  );
  INSERT INTO openarc_durable.outbox_events (
    organization_id, mutation_id, resource_type, resource_id, event_type, payload_version
  ) VALUES (
    v_org, mutation_id, 'authorization_grant', grant_id_input, 'control.grant.replaced', 1
  );

  SELECT clock_timestamp() INTO v_now;
  IF NOT (v_grant.expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_grant_expired' USING ERRCODE = 'P0D15';
  END IF;
  PERFORM openarc_durable.lock_action_listing(
    v_chain.out_seller_organization_id, v_chain.out_provider_id,
    v_chain.out_listing_id, v_chain.out_listing_version);

  SELECT g.* INTO v_grant FROM openarc_durable.authorization_grants g
   WHERE g.organization_id = v_org AND g.grant_id = grant_id_input;
  out_replayed := false;
  out_organization_id := v_grant.organization_id;
  out_grant_id := v_grant.grant_id;
  out_action_id := v_grant.action_id;
  out_reservation_id := v_grant.reservation_id;
  out_subject_agent_id := v_grant.subject_agent_id;
  out_commerce_session_id := v_grant.commerce_session_id;
  out_provider_id := v_grant.provider_id;
  out_listing_id := v_grant.listing_id;
  out_listing_version := v_grant.listing_version;
  out_generation := v_grant.current_generation;
  out_status := v_grant.status;
  out_issued_at := v_grant.issued_at;
  out_updated_at := v_grant.updated_at;
  out_expires_at := v_grant.expires_at;
  out_claimed_at := v_grant.claimed_at;
  out_revoked_at := v_grant.revoked_at;
  out_committed_at := v_committed_at;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Provider introspection. BOTH factors are required: a current matching
-- oas_pr_ provider session AND the buyer's exact non-retired oag_v1_ grant
-- token. It is strictly read-only: it consumes nothing, reserves nothing,
-- claims nothing and changes no row, so repeated introspection leaves the
-- grant, its generation and its reservation untouched. It discloses no buyer
-- organization, policy, parent, membership or account field.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.introspect_authorization_grant_core(
  mode text,
  provider_session_hash text,
  grant_token_hash text
) RETURNS TABLE(
  out_grant_id text,
  out_action_id text,
  out_provider_id text,
  out_listing_id text,
  out_listing_version text,
  out_requirement_id text,
  out_requirement_digest text,
  out_amount_atomic text,
  out_fee_atomic text,
  out_debit_atomic text,
  out_expires_at timestamptz,
  out_status text,
  out_claimed_attempt_id uuid
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_token record;
  v_chain record;
  v_attempt uuid;
  v_now timestamptz;
BEGIN
  IF mode IS DISTINCT FROM 'production' AND mode IS DISTINCT FROM 'internal_fixture' THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_canonical_hex64(provider_session_hash)
     OR NOT openarc_durable.is_canonical_hex64(grant_token_hash) THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;
  SELECT t.* INTO v_token FROM openarc_durable.authorization_grant_tokens t
   WHERE t.token_hash = grant_token_hash AND t.hash_version = 1;
  -- An unknown OR retired hash is uniformly denied: a retired generation never
  -- becomes authority again, and neither case discloses which it was.
  IF NOT FOUND OR v_token.retired_at IS NOT NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  SELECT * INTO v_chain
    FROM openarc_durable.lock_grant_provider_chain(provider_session_hash, v_token.grant_id) AS c;
  IF v_chain.out_grant_id IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  -- Re-assert the presented generation under the held locks.
  SELECT t.* INTO v_token FROM openarc_durable.authorization_grant_tokens t
   WHERE t.organization_id = v_chain.out_organization_id
     AND t.grant_id = v_chain.out_grant_id AND t.token_hash = grant_token_hash;
  IF NOT FOUND OR v_token.retired_at IS NOT NULL
     OR v_token.generation IS DISTINCT FROM v_chain.out_grant_generation THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  IF mode = 'production' AND v_chain.out_source_kind = 'internal_fixture' THEN
    RAISE EXCEPTION 'commerce_requirement_unavailable' USING ERRCODE = 'P0D10';
  END IF;

  SELECT c.attempt_id INTO v_attempt FROM openarc_durable.authorization_grant_claims c
   WHERE c.organization_id = v_chain.out_organization_id AND c.grant_id = v_chain.out_grant_id;
  SELECT clock_timestamp() INTO v_now;
  out_grant_id := v_chain.out_grant_id;
  out_action_id := v_chain.out_action_id;
  out_provider_id := v_chain.out_provider_id;
  out_listing_id := v_chain.out_listing_id;
  out_listing_version := v_chain.out_listing_version;
  out_requirement_id := v_chain.out_requirement_id;
  out_requirement_digest := v_chain.out_requirement_digest;
  out_amount_atomic := v_chain.out_amount_atomic;
  out_fee_atomic := v_chain.out_fee_atomic;
  out_debit_atomic := v_chain.out_debit_atomic;
  out_expires_at := v_chain.out_expires_at;
  -- Frozen projection priority: revoked -> claimed -> expired -> issued.
  out_status := CASE
    WHEN v_chain.out_grant_status = 'revoked' THEN 'revoked'
    WHEN v_chain.out_grant_status = 'claimed' THEN 'claimed'
    WHEN v_chain.out_expires_at <= v_now THEN 'expired'
    ELSE 'issued' END;
  out_claimed_attempt_id := v_attempt;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Atomic provider claim. BOTH factors are required and neither alone suffices.
-- Under the full frozen lock order it binds grant, action, reservation,
-- listing, version, requirement, the exact seller provider identity, the exact
-- claiming credential/session and the provider attempt in ONE compare-and-set,
-- so concurrent claims on separate connections produce exactly one winner. It
-- records no signature, payment, settlement or delivery.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.claim_authorization_grant_core(
  mode text,
  provider_session_hash text,
  grant_token_hash text,
  expected_action_id text,
  attempt_id_input uuid,
  mutation_id uuid,
  key_hash text,
  request_digest text,
  session_context_digest text
) RETURNS TABLE(
  out_replayed boolean,
  out_grant_id text,
  out_action_id text,
  out_provider_id text,
  out_listing_id text,
  out_listing_version text,
  out_requirement_id text,
  out_requirement_digest text,
  out_amount_atomic text,
  out_fee_atomic text,
  out_debit_atomic text,
  out_expires_at timestamptz,
  out_status text,
  out_attempt_id uuid,
  out_claimed_at timestamptz,
  out_claim_digest text,
  out_committed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_token record;
  v_chain record;
  v_existing record;
  v_claim record;
  v_digest text;
  v_org text;
  v_now timestamptz;
  v_committed_at timestamptz;
BEGIN
  IF mode IS DISTINCT FROM 'production' AND mode IS DISTINCT FROM 'internal_fixture' THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_canonical_hex64(provider_session_hash)
     OR NOT openarc_durable.is_canonical_hex64(grant_token_hash) THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;
  IF NOT openarc_durable.is_canonical_hex64(key_hash)
     OR NOT openarc_durable.is_canonical_hex64(request_digest)
     OR NOT openarc_durable.is_canonical_hex64(session_context_digest) THEN
    RAISE EXCEPTION 'commerce_metadata_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_canonical_action_id(expected_action_id) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF attempt_id_input IS NULL OR NOT openarc_durable.is_canonical_uuid_v4(attempt_id_input::text) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF mutation_id IS NULL OR NOT openarc_durable.is_canonical_uuid_v4(mutation_id::text) THEN
    RAISE EXCEPTION 'commerce_mutation_invalid' USING ERRCODE = '22023';
  END IF;

  SELECT t.* INTO v_token FROM openarc_durable.authorization_grant_tokens t
   WHERE t.token_hash = grant_token_hash AND t.hash_version = 1;
  IF NOT FOUND OR v_token.retired_at IS NOT NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  -- Second factor: the current matching provider session, under the full
  -- combined buyer/seller/account lock order, before any grant lock.
  SELECT * INTO v_chain
    FROM openarc_durable.lock_grant_provider_chain(provider_session_hash, v_token.grant_id) AS c;
  IF v_chain.out_grant_id IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  v_org := v_chain.out_organization_id;
  SELECT t.* INTO v_token FROM openarc_durable.authorization_grant_tokens t
   WHERE t.organization_id = v_org AND t.grant_id = v_chain.out_grant_id
     AND t.token_hash = grant_token_hash FOR UPDATE;
  IF NOT FOUND OR v_token.retired_at IS NOT NULL
     OR v_token.generation IS DISTINCT FROM v_chain.out_grant_generation THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  IF v_chain.out_action_id IS DISTINCT FROM expected_action_id THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;

  SELECT r.* INTO v_existing FROM openarc_durable.idempotency_records r
   WHERE r.organization_id = v_org AND r.operation = 'control.grant.claim'
     AND r.key_hash = key_hash FOR UPDATE;
  IF FOUND THEN
    -- A replay must present the EXACT original provider-session and request
    -- context; a new provider session yields a different context digest and is
    -- a conflict, never a second claim.
    IF v_existing.request_digest = request_digest
       AND v_existing.mutation_id = mutation_id
       AND v_existing.actor_account_id = v_chain.out_provider_issuer_account_id
       AND v_existing.session_context_digest = session_context_digest
       AND v_existing.status = 'committed'
       AND v_existing.resource_type = 'authorization_grant'
       AND v_existing.resource_id = v_chain.out_grant_id THEN
      SELECT c.* INTO v_claim FROM openarc_durable.authorization_grant_claims c
       WHERE c.organization_id = v_org AND c.grant_id = v_chain.out_grant_id;
      IF NOT FOUND OR v_claim.attempt_id IS DISTINCT FROM attempt_id_input THEN
        RAISE EXCEPTION 'commerce_idempotency_conflict' USING ERRCODE = 'P0D01';
      END IF;
      SELECT clock_timestamp() INTO v_now;
      out_replayed := true;
      out_grant_id := v_chain.out_grant_id;
      out_action_id := v_chain.out_action_id;
      out_provider_id := v_chain.out_provider_id;
      out_listing_id := v_chain.out_listing_id;
      out_listing_version := v_chain.out_listing_version;
      out_requirement_id := v_chain.out_requirement_id;
      out_requirement_digest := v_chain.out_requirement_digest;
      out_amount_atomic := v_chain.out_amount_atomic;
      out_fee_atomic := v_chain.out_fee_atomic;
      out_debit_atomic := v_chain.out_debit_atomic;
      out_expires_at := v_chain.out_expires_at;
      out_status := CASE
        WHEN v_chain.out_grant_status = 'revoked' THEN 'revoked'
        WHEN v_chain.out_grant_status = 'claimed' THEN 'claimed'
        WHEN v_chain.out_expires_at <= v_now THEN 'expired'
        ELSE 'issued' END;
      out_attempt_id := v_claim.attempt_id;
      out_claimed_at := v_claim.claimed_at;
      out_claim_digest := v_claim.claim_digest;
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

  IF mode = 'production' AND v_chain.out_source_kind = 'internal_fixture' THEN
    RAISE EXCEPTION 'commerce_requirement_unavailable' USING ERRCODE = 'P0D10';
  END IF;

  SELECT clock_timestamp() INTO v_now;
  -- One compare-and-set over the locked grant: a second concurrent claim on a
  -- separate connection observes 'claimed' here and loses.
  IF v_chain.out_grant_status <> 'issued' OR v_chain.out_claimed_at IS NOT NULL
     OR v_chain.out_revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'commerce_grant_conflict' USING ERRCODE = 'P0D14';
  END IF;
  IF NOT (v_chain.out_expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_grant_expired' USING ERRCODE = 'P0D15';
  END IF;
  IF v_chain.out_action_status <> 'grant_issued' THEN
    RAISE EXCEPTION 'commerce_grant_conflict' USING ERRCODE = 'P0D14';
  END IF;
  IF v_chain.out_reservation_status <> 'held' THEN
    RAISE EXCEPTION 'commerce_grant_conflict' USING ERRCODE = 'P0D14';
  END IF;

  v_digest := openarc_durable.grant_claim_digest(
    v_chain.out_grant_id, v_chain.out_action_id, v_chain.out_reservation_id,
    v_chain.out_seller_organization_id, v_chain.out_provider_id, v_chain.out_listing_id,
    v_chain.out_listing_version, v_chain.out_requirement_id, v_chain.out_requirement_digest,
    v_chain.out_amount_atomic, v_chain.out_fee_atomic,
    v_chain.out_provider_credential_id, v_chain.out_provider_session_id, attempt_id_input);

  INSERT INTO openarc_durable.idempotency_records (
    organization_id, operation, key_hash, request_digest, digest_version,
    actor_account_id, session_context_digest, network, mutation_id, status
  ) VALUES (
    v_org, 'control.grant.claim', key_hash, request_digest, 'control.grant.claim.v1',
    v_chain.out_provider_issuer_account_id, session_context_digest,
    'eip155:5042002', mutation_id, 'pending'
  );
  INSERT INTO openarc_durable.authorization_grant_claims (
    organization_id, grant_id, action_id, reservation_id, seller_organization_id,
    provider_id, listing_id, listing_version, requirement_id, provider_credential_id,
    provider_session_id, attempt_id, claim_digest, claimed_at
  ) VALUES (
    v_org, v_chain.out_grant_id, v_chain.out_action_id, v_chain.out_reservation_id,
    v_chain.out_seller_organization_id, v_chain.out_provider_id, v_chain.out_listing_id,
    v_chain.out_listing_version, v_chain.out_requirement_id,
    v_chain.out_provider_credential_id, v_chain.out_provider_session_id,
    attempt_id_input, v_digest, v_now
  );
  UPDATE openarc_durable.authorization_grants g
     SET status = 'claimed', claimed_at = v_now, updated_at = clock_timestamp()
   WHERE g.organization_id = v_org AND g.grant_id = v_chain.out_grant_id;
  UPDATE openarc_durable.budget_reservations b
     SET status = 'claimed', claimed_at = v_now
   WHERE b.organization_id = v_org AND b.reservation_id = v_chain.out_reservation_id
     AND b.action_id = v_chain.out_action_id;

  UPDATE openarc_durable.idempotency_records r
     SET status = 'committed', resource_type = 'authorization_grant',
         resource_id = v_chain.out_grant_id, committed_at = clock_timestamp()
   WHERE r.organization_id = v_org AND r.operation = 'control.grant.claim'
     AND r.key_hash = key_hash
   RETURNING r.committed_at INTO v_committed_at;
  INSERT INTO openarc_durable.audit_events (
    organization_id, actor_account_id, operation, mutation_id, resource_type, resource_id, outcome
  ) VALUES (
    v_org, v_chain.out_provider_issuer_account_id, 'control.grant.claim', mutation_id,
    'authorization_grant', v_chain.out_grant_id, 'committed'
  );
  INSERT INTO openarc_durable.outbox_events (
    organization_id, mutation_id, resource_type, resource_id, event_type, payload_version
  ) VALUES (
    v_org, mutation_id, 'authorization_grant', v_chain.out_grant_id,
    'control.grant.claimed', 1
  );

  -- Current seller authority after every durable write and all lock waits.
  PERFORM openarc_durable.lock_action_listing(
    v_chain.out_seller_organization_id, v_chain.out_provider_id,
    v_chain.out_listing_id, v_chain.out_listing_version);

  out_replayed := false;
  out_grant_id := v_chain.out_grant_id;
  out_action_id := v_chain.out_action_id;
  out_provider_id := v_chain.out_provider_id;
  out_listing_id := v_chain.out_listing_id;
  out_listing_version := v_chain.out_listing_version;
  out_requirement_id := v_chain.out_requirement_id;
  out_requirement_digest := v_chain.out_requirement_digest;
  out_amount_atomic := v_chain.out_amount_atomic;
  out_fee_atomic := v_chain.out_fee_atomic;
  out_debit_atomic := v_chain.out_debit_atomic;
  out_expires_at := v_chain.out_expires_at;
  out_status := 'claimed';
  out_attempt_id := attempt_id_input;
  out_claimed_at := v_now;
  out_claim_digest := v_digest;
  out_committed_at := v_committed_at;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Human revoke and safe never-claimed cleanup. It requires a CURRENT fresh
-- owner/operator non-recovery proof in the SAME buyer organization and then
-- works from immutable ids only, so it tolerates a dead original buyer chain,
-- a dead seller or a vanished provider. It is deliberately NOT provenance
-- gated: buyer cleanup must never be blocked by what it is retiring.
--
-- The grant is always marked revoked and its current token retired, so no new
-- use is possible. ONLY when the grant was never claimed and the reservation
-- is still held does it release the reservation, append exactly one released
-- budget event and cancel the action. A claimed, unknown or committed
-- reservation RETAINS its exposure and the action stays grant_issued: a
-- revoked display status never erases a possible payment, and a repeated
-- revoke can release nothing because revocation is one-way.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.revoke_authorization_grant(
  human_session_hash text,
  organization_id text,
  grant_id_input text,
  mutation_id uuid,
  key_hash text,
  request_digest text,
  session_context_digest text
) RETURNS TABLE(
  out_replayed boolean,
  out_organization_id text,
  out_grant_id text,
  out_action_id text,
  out_reservation_id text,
  out_subject_agent_id text,
  out_commerce_session_id uuid,
  out_provider_id text,
  out_listing_id text,
  out_listing_version text,
  out_generation integer,
  out_status text,
  out_issued_at timestamptz,
  out_updated_at timestamptz,
  out_expires_at timestamptz,
  out_claimed_at timestamptz,
  out_revoked_at timestamptz,
  out_action_status text,
  out_reservation_status text,
  out_released boolean,
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
  v_existing record;
  v_grant record;
  v_action record;
  v_reservation record;
  v_released boolean := false;
  v_now timestamptz;
  v_committed_at timestamptz;
BEGIN
  IF NOT openarc_durable.is_canonical_hex64(human_session_hash)
     OR NOT openarc_durable.is_canonical_hex64(key_hash)
     OR NOT openarc_durable.is_canonical_hex64(request_digest)
     OR NOT openarc_durable.is_canonical_hex64(session_context_digest) THEN
    RAISE EXCEPTION 'commerce_metadata_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_canonical_grant_id(grant_id_input) THEN
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
   WHERE r.organization_id = organization_id AND r.operation = 'control.grant.revoke'
     AND r.key_hash = key_hash FOR UPDATE;
  IF FOUND THEN
    IF v_existing.request_digest = request_digest
       AND v_existing.mutation_id = mutation_id
       AND v_existing.actor_account_id = v_actor
       AND v_existing.session_context_digest = session_context_digest
       AND v_existing.status = 'committed'
       AND v_existing.resource_type = 'authorization_grant'
       AND v_existing.resource_id = grant_id_input THEN
      SELECT g.* INTO v_grant FROM openarc_durable.authorization_grants g
       WHERE g.organization_id = organization_id AND g.grant_id = grant_id_input;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
      END IF;
      SELECT a.status INTO out_action_status FROM openarc_durable.commerce_actions a
       WHERE a.organization_id = organization_id AND a.action_id = v_grant.action_id;
      SELECT b.status INTO out_reservation_status FROM openarc_durable.budget_reservations b
       WHERE b.organization_id = organization_id AND b.reservation_id = v_grant.reservation_id;
      SELECT l.out_actor INTO v_recheck
        FROM openarc_durable.lock_action_human(human_session_hash, organization_id, true) AS l;
      IF v_recheck IS NULL OR v_recheck <> v_actor THEN
        RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
      END IF;
      out_replayed := true;
      out_organization_id := v_grant.organization_id;
      out_grant_id := v_grant.grant_id;
      out_action_id := v_grant.action_id;
      out_reservation_id := v_grant.reservation_id;
      out_subject_agent_id := v_grant.subject_agent_id;
      out_commerce_session_id := v_grant.commerce_session_id;
      out_provider_id := v_grant.provider_id;
      out_listing_id := v_grant.listing_id;
      out_listing_version := v_grant.listing_version;
      out_generation := v_grant.current_generation;
      out_status := v_grant.status;
      out_issued_at := v_grant.issued_at;
      out_updated_at := v_grant.updated_at;
      out_expires_at := v_grant.expires_at;
      out_claimed_at := v_grant.claimed_at;
      out_revoked_at := v_grant.revoked_at;
      out_released := out_reservation_status = 'released';
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

  -- Immutable id ordering: action, then reservation, then grant and its token.
  SELECT g.organization_id, g.action_id, g.reservation_id INTO v_grant
    FROM openarc_durable.authorization_grants g
   WHERE g.organization_id = organization_id AND g.grant_id = grant_id_input;
  IF v_grant.action_id IS NULL THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT a.* INTO v_action FROM openarc_durable.commerce_actions a
   WHERE a.organization_id = organization_id AND a.action_id = v_grant.action_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT b.* INTO v_reservation FROM openarc_durable.budget_reservations b
   WHERE b.organization_id = organization_id AND b.reservation_id = v_grant.reservation_id
     AND b.action_id = v_grant.action_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT g.* INTO v_grant FROM openarc_durable.authorization_grants g
   WHERE g.organization_id = organization_id AND g.grant_id = grant_id_input FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  -- Revocation is one-way; a repeated revoke never runs cleanup a second time.
  IF v_grant.status = 'revoked' OR v_grant.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'commerce_grant_conflict' USING ERRCODE = 'P0D14';
  END IF;

  SELECT clock_timestamp() INTO v_now;
  UPDATE openarc_durable.authorization_grants g
     SET status = 'revoked', revoked_at = v_now, updated_at = clock_timestamp()
   WHERE g.organization_id = organization_id AND g.grant_id = grant_id_input;
  UPDATE openarc_durable.authorization_grant_tokens t
     SET retired_at = v_now
   WHERE t.organization_id = organization_id AND t.grant_id = grant_id_input
     AND t.retired_at IS NULL;

  IF v_grant.claimed_at IS NULL
     AND openarc_durable.reservation_releasable(v_reservation.status)
     AND v_reservation.claimed_at IS NULL THEN
    v_released := true;
    UPDATE openarc_durable.budget_reservations b
       SET status = 'released', resolved_at = v_now
     WHERE b.organization_id = organization_id AND b.reservation_id = v_grant.reservation_id;
    INSERT INTO openarc_durable.budget_events (
      organization_id, event_id, action_id, reservation_id, subject_agent_id,
      network_id, asset, representation, decimals, amount_atomic, event_kind, event_time)
    VALUES (
      organization_id, gen_random_uuid(), v_action.action_id, v_reservation.reservation_id,
      v_action.subject_agent_id, v_action.network_id, v_action.asset, v_action.representation,
      v_action.decimals, v_reservation.debit_atomic, 'released', v_now);
    IF v_action.status = 'grant_issued' THEN
      UPDATE openarc_durable.commerce_actions a
         SET status = 'cancelled', updated_at = clock_timestamp()
       WHERE a.organization_id = organization_id AND a.action_id = v_action.action_id;
    END IF;
  END IF;

  INSERT INTO openarc_durable.idempotency_records (
    organization_id, operation, key_hash, request_digest, digest_version,
    actor_account_id, session_context_digest, network, mutation_id, status
  ) VALUES (
    organization_id, 'control.grant.revoke', key_hash, request_digest,
    'control.grant.revoke.v1', v_actor, session_context_digest,
    'eip155:5042002', mutation_id, 'pending'
  );
  UPDATE openarc_durable.idempotency_records r
     SET status = 'committed', resource_type = 'authorization_grant',
         resource_id = grant_id_input, committed_at = clock_timestamp()
   WHERE r.organization_id = organization_id AND r.operation = 'control.grant.revoke'
     AND r.key_hash = key_hash
   RETURNING r.committed_at INTO v_committed_at;
  INSERT INTO openarc_durable.audit_events (
    organization_id, actor_account_id, operation, mutation_id, resource_type, resource_id, outcome
  ) VALUES (
    organization_id, v_actor, 'control.grant.revoke', mutation_id,
    'authorization_grant', grant_id_input, 'committed'
  );
  INSERT INTO openarc_durable.outbox_events (
    organization_id, mutation_id, resource_type, resource_id, event_type, payload_version
  ) VALUES (
    organization_id, mutation_id, 'authorization_grant', grant_id_input,
    'control.grant.revoked', 1
  );

  SELECT l.out_actor INTO v_recheck
    FROM openarc_durable.lock_action_human(human_session_hash, organization_id, true) AS l;
  IF v_recheck IS NULL OR v_recheck <> v_actor THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;

  SELECT g.* INTO v_grant FROM openarc_durable.authorization_grants g
   WHERE g.organization_id = organization_id AND g.grant_id = grant_id_input;
  SELECT a.status INTO out_action_status FROM openarc_durable.commerce_actions a
   WHERE a.organization_id = organization_id AND a.action_id = v_grant.action_id;
  SELECT b.status INTO out_reservation_status FROM openarc_durable.budget_reservations b
   WHERE b.organization_id = organization_id AND b.reservation_id = v_grant.reservation_id;
  out_replayed := false;
  out_organization_id := v_grant.organization_id;
  out_grant_id := v_grant.grant_id;
  out_action_id := v_grant.action_id;
  out_reservation_id := v_grant.reservation_id;
  out_subject_agent_id := v_grant.subject_agent_id;
  out_commerce_session_id := v_grant.commerce_session_id;
  out_provider_id := v_grant.provider_id;
  out_listing_id := v_grant.listing_id;
  out_listing_version := v_grant.listing_version;
  out_generation := v_grant.current_generation;
  out_status := v_grant.status;
  out_issued_at := v_grant.issued_at;
  out_updated_at := v_grant.updated_at;
  out_expires_at := v_grant.expires_at;
  out_claimed_at := v_grant.claimed_at;
  out_revoked_at := v_grant.revoked_at;
  out_released := v_released;
  out_committed_at := v_committed_at;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Buyer grant projection for a current owner/operator non-recovery human. The
-- projected status follows the frozen priority revoked -> claimed -> expired
-- (DB clock) -> issued, so a revoked grant that was claimed still reports its
-- claim instant. No token hash, generation secret or provider-session material
-- is representable here. A missing or foreign grant returns no row and the
-- same current authority is revalidated after the projection.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.read_authorization_grant(
  human_session_hash text,
  organization_id text,
  grant_id_input text
) RETURNS TABLE(
  out_organization_id text,
  out_grant_id text,
  out_action_id text,
  out_reservation_id text,
  out_subject_agent_id text,
  out_commerce_session_id uuid,
  out_provider_id text,
  out_listing_id text,
  out_listing_version text,
  out_generation integer,
  out_status text,
  out_issued_at timestamptz,
  out_updated_at timestamptz,
  out_expires_at timestamptz,
  out_claimed_at timestamptz,
  out_revoked_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_actor text;
  v_grant record;
  v_now timestamptz;
BEGIN
  IF NOT openarc_durable.is_canonical_hex64(human_session_hash) THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;
  IF NOT openarc_durable.is_canonical_grant_id(grant_id_input) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  SELECT l.out_actor INTO v_actor
    FROM openarc_durable.lock_action_reader(human_session_hash, organization_id) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT g.* INTO v_grant FROM openarc_durable.authorization_grants g
   WHERE g.organization_id = organization_id AND g.grant_id = grant_id_input;
  IF FOUND THEN
    SELECT clock_timestamp() INTO v_now;
    out_organization_id := v_grant.organization_id;
    out_grant_id := v_grant.grant_id;
    out_action_id := v_grant.action_id;
    out_reservation_id := v_grant.reservation_id;
    out_subject_agent_id := v_grant.subject_agent_id;
    out_commerce_session_id := v_grant.commerce_session_id;
    out_provider_id := v_grant.provider_id;
    out_listing_id := v_grant.listing_id;
    out_listing_version := v_grant.listing_version;
    out_generation := v_grant.current_generation;
    out_status := CASE
      WHEN v_grant.status = 'revoked' THEN 'revoked'
      WHEN v_grant.status = 'claimed' THEN 'claimed'
      WHEN v_grant.expires_at <= v_now THEN 'expired'
      ELSE 'issued' END;
    out_issued_at := v_grant.issued_at;
    out_updated_at := v_grant.updated_at;
    out_expires_at := v_grant.expires_at;
    out_claimed_at := v_grant.claimed_at;
    out_revoked_at := v_grant.revoked_at;
  END IF;
  -- Revalidate the SAME current authority, including the not-found path.
  SELECT l.out_actor INTO v_actor
    FROM openarc_durable.lock_action_reader(human_session_hash, organization_id) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;
  IF out_grant_id IS NOT NULL THEN
    RETURN NEXT;
  END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- Provider historical claim recovery keyed by the provider's OWN attempt id.
-- A new valid session for the SAME provider may recover minimal claim history
-- after buyer revocation or expiry, because retirement alone is not evidence
-- of nonpayment. It revives no token and creates no authority: a retired or
-- revoked grant still reports its claim fact plus an explicit grantRevoked
-- flag. A missing attempt and a foreign attempt are INDISTINGUISHABLE, and the
-- same current provider authority is revalidated after the read including the
-- not-found path.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.read_provider_grant_attempt_status(
  provider_session_hash text,
  attempt_id_input uuid
) RETURNS TABLE(
  out_found boolean,
  out_attempt_id uuid,
  out_grant_id text,
  out_action_id text,
  out_provider_id text,
  out_listing_id text,
  out_listing_version text,
  out_claimed_at timestamptz,
  out_grant_revoked boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_identity record;
  v_recheck record;
  v_claim record;
  v_revoked_at timestamptz;
BEGIN
  IF attempt_id_input IS NULL
     OR NOT openarc_durable.is_canonical_uuid_v4(attempt_id_input::text) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO v_identity
    FROM openarc_durable.lock_grant_provider_identity(provider_session_hash) AS l;
  IF v_identity.out_provider_id IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT c.* INTO v_claim FROM openarc_durable.authorization_grant_claims c
   WHERE c.seller_organization_id = v_identity.out_organization_id
     AND c.provider_id = v_identity.out_provider_id
     AND c.attempt_id = attempt_id_input;
  IF FOUND THEN
    SELECT g.revoked_at INTO v_revoked_at FROM openarc_durable.authorization_grants g
     WHERE g.organization_id = v_claim.organization_id AND g.grant_id = v_claim.grant_id;
    out_found := true;
    out_attempt_id := v_claim.attempt_id;
    out_grant_id := v_claim.grant_id;
    out_action_id := v_claim.action_id;
    out_provider_id := v_claim.provider_id;
    out_listing_id := v_claim.listing_id;
    out_listing_version := v_claim.listing_version;
    out_claimed_at := v_claim.claimed_at;
    out_grant_revoked := v_revoked_at IS NOT NULL;
  ELSE
    out_found := false;
  END IF;
  SELECT * INTO v_recheck
    FROM openarc_durable.lock_grant_provider_identity(provider_session_hash) AS l;
  IF v_recheck.out_provider_id IS NULL
     OR v_recheck.out_provider_id <> v_identity.out_provider_id
     OR v_recheck.out_organization_id <> v_identity.out_organization_id THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Production tenant-runtime wrappers. Each passes the LITERAL 'production'
-- mode and never caller data, an environment value, a GUC, a callback or a row
-- field. The migrator-only cores are unreachable from PUBLIC, the auth, tenant
-- or worker runtime roles, directly or through role inheritance.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.issue_authorization_grant(
  commerce_token_hash text,
  action_id_input text,
  token_hash_input text,
  token_hash_version integer,
  mutation_id uuid,
  key_hash text,
  request_digest text,
  session_context_digest text
) RETURNS TABLE(
  out_replayed boolean,
  out_organization_id text,
  out_grant_id text,
  out_action_id text,
  out_reservation_id text,
  out_subject_agent_id text,
  out_commerce_session_id uuid,
  out_provider_id text,
  out_listing_id text,
  out_listing_version text,
  out_generation integer,
  out_status text,
  out_issued_at timestamptz,
  out_updated_at timestamptz,
  out_expires_at timestamptz,
  out_claimed_at timestamptz,
  out_revoked_at timestamptz,
  out_committed_at timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT * FROM openarc_durable.issue_authorization_grant_core(
    'production', commerce_token_hash, action_id_input, token_hash_input,
    token_hash_version, mutation_id, key_hash, request_digest, session_context_digest);
$$;

CREATE FUNCTION openarc_durable.replace_authorization_grant(
  commerce_token_hash text,
  grant_id_input text,
  token_hash_input text,
  token_hash_version integer,
  mutation_id uuid,
  key_hash text,
  request_digest text,
  session_context_digest text
) RETURNS TABLE(
  out_replayed boolean,
  out_organization_id text,
  out_grant_id text,
  out_action_id text,
  out_reservation_id text,
  out_subject_agent_id text,
  out_commerce_session_id uuid,
  out_provider_id text,
  out_listing_id text,
  out_listing_version text,
  out_generation integer,
  out_status text,
  out_issued_at timestamptz,
  out_updated_at timestamptz,
  out_expires_at timestamptz,
  out_claimed_at timestamptz,
  out_revoked_at timestamptz,
  out_committed_at timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT * FROM openarc_durable.replace_authorization_grant_core(
    'production', commerce_token_hash, grant_id_input, token_hash_input,
    token_hash_version, mutation_id, key_hash, request_digest, session_context_digest);
$$;

CREATE FUNCTION openarc_durable.introspect_authorization_grant(
  provider_session_hash text,
  grant_token_hash text
) RETURNS TABLE(
  out_grant_id text,
  out_action_id text,
  out_provider_id text,
  out_listing_id text,
  out_listing_version text,
  out_requirement_id text,
  out_requirement_digest text,
  out_amount_atomic text,
  out_fee_atomic text,
  out_debit_atomic text,
  out_expires_at timestamptz,
  out_status text,
  out_claimed_attempt_id uuid
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT * FROM openarc_durable.introspect_authorization_grant_core(
    'production', provider_session_hash, grant_token_hash);
$$;

CREATE FUNCTION openarc_durable.claim_authorization_grant(
  provider_session_hash text,
  grant_token_hash text,
  expected_action_id text,
  attempt_id_input uuid,
  mutation_id uuid,
  key_hash text,
  request_digest text,
  session_context_digest text
) RETURNS TABLE(
  out_replayed boolean,
  out_grant_id text,
  out_action_id text,
  out_provider_id text,
  out_listing_id text,
  out_listing_version text,
  out_requirement_id text,
  out_requirement_digest text,
  out_amount_atomic text,
  out_fee_atomic text,
  out_debit_atomic text,
  out_expires_at timestamptz,
  out_status text,
  out_attempt_id uuid,
  out_claimed_at timestamptz,
  out_claim_digest text,
  out_committed_at timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT * FROM openarc_durable.claim_authorization_grant_core(
    'production', provider_session_hash, grant_token_hash, expected_action_id,
    attempt_id_input, mutation_id, key_hash, request_digest, session_context_digest);
$$;

-- ---------------------------------------------------------------------------
-- Least privilege. PUBLIC receives nothing anywhere. Only the seven bounded
-- production entry points are executable by the restricted tenant runtime; the
-- closed cores, the lock chains, the provider identity resolver and the claim
-- digest helper stay migrator-private. No broad grant is added.
-- ---------------------------------------------------------------------------
REVOKE ALL ON FUNCTION openarc_durable.is_canonical_grant_id(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.enforce_authorization_grant_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.enforce_grant_token_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.reject_grant_claim_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.grant_claim_digest(
  text, text, text, text, text, text, text, text, text, text, text, uuid, uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.lock_grant_commerce_chain(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.lock_grant_provider_identity(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.lock_grant_provider_chain(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.issue_authorization_grant_core(
  text, text, text, text, integer, uuid, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.replace_authorization_grant_core(
  text, text, text, text, integer, uuid, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.introspect_authorization_grant_core(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.claim_authorization_grant_core(
  text, text, text, text, uuid, uuid, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.issue_authorization_grant(
  text, text, text, integer, uuid, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.replace_authorization_grant(
  text, text, text, integer, uuid, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.introspect_authorization_grant(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.claim_authorization_grant(
  text, text, text, uuid, uuid, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.revoke_authorization_grant(
  text, text, text, uuid, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.read_authorization_grant(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.read_provider_grant_attempt_status(text, uuid) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION openarc_durable.issue_authorization_grant(
  text, text, text, integer, uuid, text, text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.replace_authorization_grant(
  text, text, text, integer, uuid, text, text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.introspect_authorization_grant(text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.claim_authorization_grant(
  text, text, text, uuid, uuid, text, text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.revoke_authorization_grant(
  text, text, text, uuid, text, text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.read_authorization_grant(text, text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.read_provider_grant_attempt_status(text, uuid) TO openarc_tenant_app;
