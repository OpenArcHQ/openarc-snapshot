-- OpenArc verified requirement provenance and durable payment attempts (schema15).
-- Additive over schema14. Owner: openarc_migrator. Runtime: openarc_tenant_app.
-- This migration NEVER creates roles/schemas, calls a provider, Circle, Gateway
-- or Arc endpoint, signs, moves funds, settles or delivers. Migrations
-- 0001-0014 are untouched.
--
-- 1. Verified requirement provenance ('verified_listing').
--    A requirement row of this kind is admissible in production ONLY because
--    every term is derived server-side and re-proven by an insert trigger from
--    the seller's CURRENTLY published (active), origin-approved listing version
--    and the pinned Arc-testnet x402 lane manifest:
--      network eip155:5042002, scheme exact, x402Version 2, EIP-712 domain
--      GatewayWalletBatched v1, verifying contract (GatewayWallet)
--      0x0077777d7eba4688bdef3e311b846f25870a19b9, USDC
--      0x3600000000000000000000000000000000000000, 6 decimals, erc20.
--    amount_atomic is the listing's recorded fixed price atomicAmount (exact
--    text, never a float) and fee_atomic is '0' because the recorded price has
--    no fee component and an x402 exact authorization transfers exactly
--    `value`. No caller can supply an origin, price, network, asset, verifying
--    contract, pay-to address or calldata: the only registration paths take a
--    requirement id and a listing id (plus the buyer organization for the
--    migrator core, or the exact commerce token for the runtime registrar), and
--    the trigger refuses any row (including ordinary migrator DML) whose terms
--    differ from the server derivation. The pay-to address is the seller's own
--    immutable per-version payment terms (listing_version_payment_terms),
--    recorded by a fresh owner/provider_admin seller session; a version without
--    terms cannot back a verified requirement, and changing pay-to requires a new
--    listing version. `internal_fixture` is still refused on every
--    production path exactly as schema10/schema12 do (P0D10); there is no GUC,
--    flag, callback or bypass. The registration core is migrator-private; the
--    runtime registrar derives the buyer organization from the exact consumed
--    commerce token and asserts that authority before and after delegating.
--
-- 2. payment_attempts mirrors the accepted packages/x402 LaneExposure:
--      persisted  (durable binding, before any dispatch)
--      unknown    (dispatched; possibly exposed; held)
--      pending    (Gateway received/batched/confirmed; held)
--      committed  (one fully matching completed transfer; consumes exposure)
--    Edges: persisted->unknown (dispatch, exactly once); unknown->pending;
--    unknown->committed; pending->pending (forward status only);
--    pending->committed. There is NO release, failed, expired or cancelled
--    state and no edge out of unknown other than to pending or committed.
--    A durable attempt, in ANY state, forbids releasing its reservation or
--    moving its action to cancelled, expired or rejected, so no revoke, cancel,
--    expiry or cleanup ordering can release exposure once an attempt exists.
--    No raw signature, raw authorization payload or key material is
--    representable: only the lane binding digest and its non-secret fields.

-- ---------------------------------------------------------------------------
-- Closed source provenance set. internal_fixture keeps its schema10 meaning;
-- verified_listing is admissible only through the trigger below.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION openarc_durable.is_canonical_source_kind(value text)
RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT value IS NOT NULL AND value IN ('internal_fixture', 'verified_listing');
$$;

-- ---------------------------------------------------------------------------
-- Seller payment terms: one immutable pay-to address per listing version.
-- Stored in lowercase canonical form. Rows are created ONLY by
-- commit_listing_payment_terms (a fresh owner/provider_admin seller session)
-- and are never updated or deleted; a different pay-to needs a new version.
-- ---------------------------------------------------------------------------
CREATE TABLE openarc_tenant.listing_version_payment_terms (
  organization_id text NOT NULL,
  listing_id text NOT NULL,
  version text NOT NULL,
  provider_id text NOT NULL,
  pay_to_address text NOT NULL,
  recorded_by_account_id text NOT NULL REFERENCES openarc_auth.accounts(account_id) ON DELETE RESTRICT,
  mutation_id uuid NOT NULL,
  recorded_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id, listing_id, version),
  CONSTRAINT listing_version_payment_terms_mutation_unique UNIQUE (organization_id, mutation_id),
  CONSTRAINT listing_version_payment_terms_version_fk FOREIGN KEY (organization_id, listing_id, version)
    REFERENCES openarc_tenant.listing_versions(organization_id, listing_id, version) ON DELETE RESTRICT,
  CONSTRAINT listing_version_payment_terms_provider_fk FOREIGN KEY (organization_id, provider_id, listing_id)
    REFERENCES openarc_tenant.listings(organization_id, provider_id, listing_id) ON DELETE RESTRICT,
  CONSTRAINT listing_version_payment_terms_listing_valid CHECK (openarc_durable.is_canonical_listing_id(listing_id)),
  CONSTRAINT listing_version_payment_terms_version_valid CHECK (openarc_durable.is_canonical_listing_version(version)),
  CONSTRAINT listing_version_payment_terms_pay_to_valid CHECK (
    pay_to_address ~ '^0x[0-9a-f]{40}$'
    AND pay_to_address <> '0x0000000000000000000000000000000000000000'
    AND pay_to_address <> '0x0077777d7eba4688bdef3e311b846f25870a19b9'
    AND pay_to_address <> '0x3600000000000000000000000000000000000000')
);

-- Every terms row names its exact committed receipt.
ALTER TABLE openarc_tenant.listing_version_payment_terms
  ADD COLUMN recorded_resource_type text GENERATED ALWAYS AS ('listing_version') STORED,
  ADD COLUMN recorded_resource_id text GENERATED ALWAYS AS (listing_id || '@' || version) STORED,
  ADD COLUMN recorded_operation text GENERATED ALWAYS AS ('market.listing.payment_terms.record') STORED;

ALTER TABLE openarc_tenant.listing_version_payment_terms
  ADD CONSTRAINT listing_version_payment_terms_receipt_fk FOREIGN KEY (
    organization_id, mutation_id, recorded_resource_type, recorded_resource_id, recorded_operation
  ) REFERENCES openarc_durable.idempotency_records (
    organization_id, mutation_id, resource_type, resource_id, operation
  ) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION openarc_tenant.reject_listing_payment_terms_mutation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'listing_payment_terms_immutable' USING ERRCODE = '42501';
END;
$$;

CREATE TRIGGER listing_version_payment_terms_append_only
  BEFORE UPDATE OR DELETE ON openarc_tenant.listing_version_payment_terms
  FOR EACH ROW EXECUTE FUNCTION openarc_tenant.reject_listing_payment_terms_mutation();

ALTER TABLE openarc_tenant.listing_version_payment_terms ENABLE ROW LEVEL SECURITY;
ALTER TABLE openarc_tenant.listing_version_payment_terms FORCE ROW LEVEL SECURITY;
CREATE POLICY listing_version_payment_terms_migrator ON openarc_tenant.listing_version_payment_terms
  FOR ALL TO openarc_migrator USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE openarc_tenant.listing_version_payment_terms FROM PUBLIC;

-- The seller pay-to carried by a verified requirement (lowercase canonical).
-- NULL for internal_fixture rows; required for verified_listing rows.
ALTER TABLE openarc_durable.commerce_requirement_references
  ADD COLUMN pay_to_address text;

ALTER TABLE openarc_durable.commerce_requirement_references
  ADD CONSTRAINT commerce_requirement_references_pay_to_valid CHECK (
    pay_to_address IS NULL OR (
      pay_to_address ~ '^0x[0-9a-f]{40}$'
      AND pay_to_address <> '0x0000000000000000000000000000000000000000'
      AND pay_to_address <> '0x0077777d7eba4688bdef3e311b846f25870a19b9'
      AND pay_to_address <> '0x3600000000000000000000000000000000000000')),
  ADD CONSTRAINT commerce_requirement_references_verified_pay_to CHECK (
    source_kind IS DISTINCT FROM 'verified_listing' OR pay_to_address IS NOT NULL);

-- ---------------------------------------------------------------------------
-- Closed operation union extension for market.listing.payment_terms.record on
-- a listing_version resource (idempotency + audit). Every accepted tuple is
-- retained verbatim. No outbox event type is added, so the outbox claim
-- projection and worker handlers are unaffected.
-- ---------------------------------------------------------------------------
ALTER TABLE openarc_durable.idempotency_records
  DROP CONSTRAINT idempotency_operation_valid,
  DROP CONSTRAINT idempotency_digest_version_valid,
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
    'control.grant.claim',
    'market.listing.payment_terms.record'
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
    'control.grant.claim.v1',
    'market.listing.payment_terms.record.v1'
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
      WHEN 'market.listing.payment_terms.record' THEN 'listing_version'
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
            'market.listing.version.retire',
            'market.listing.payment_terms.record'
          ) THEN listing_version::numeric >= 1
          ELSE false
        END)
    OR (resource_type IS NULL OR resource_type NOT IN ('listing', 'listing_version'))
  );

ALTER TABLE openarc_durable.audit_events
  DROP CONSTRAINT audit_operation_valid,
  DROP CONSTRAINT audit_resource_matches_operation,
  DROP CONSTRAINT audit_market_resource_shape;

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
    'control.grant.claim',
    'market.listing.payment_terms.record'
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
      WHEN 'market.listing.payment_terms.record' THEN 'listing_version'
    END
  ),
  ADD CONSTRAINT audit_market_resource_shape CHECK (
    (resource_type = 'listing' AND listing_id = resource_id AND listing_version IS NULL)
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
            'market.listing.version.retire',
            'market.listing.payment_terms.record'
          ) THEN listing_version::numeric >= 1
          ELSE false
        END)
    OR (resource_type IS NULL OR resource_type NOT IN ('listing', 'listing_version'))
  );

-- ---------------------------------------------------------------------------
-- market.listing.payment_terms.record. Seller human authority mirrors the DB7
-- lifecycle writer (fresh non-recovery proof, active membership, active
-- provider owning the listing), narrowed to owner/provider_admin. Any
-- non-retired version may receive terms, exactly once. Lock order: auth
-- session, organization, membership, provider (lifecycle writer), then the
-- version row, its state row, the idempotency rows, then the new terms row.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.commit_listing_payment_terms(
  session_hash text,
  organization_id text,
  listing_id text,
  version text,
  pay_to_address_input text,
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
  out_pay_to_address text,
  out_recorded_at timestamptz,
  out_committed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_writer record;
  v_recheck record;
  v_version_provider text;
  v_status text;
  v_existing record;
  v_terms record;
  v_pay_to text;
  v_resource_id text;
  v_now timestamptz;
  v_committed_at timestamptz;
BEGIN
  IF NOT openarc_durable.is_canonical_hex64(key_hash)
     OR NOT openarc_durable.is_canonical_hex64(request_digest)
     OR NOT openarc_durable.is_canonical_hex64(session_context_digest) THEN
    RAISE EXCEPTION 'market_metadata_invalid' USING ERRCODE = '22023';
  END IF;
  IF mutation_id IS NULL OR NOT openarc_durable.is_canonical_uuid_v4(mutation_id::text) THEN
    RAISE EXCEPTION 'market_mutation_invalid' USING ERRCODE = '22023';
  END IF;
  IF NOT openarc_durable.is_canonical_listing_version(version)
     OR pay_to_address_input IS NULL OR pay_to_address_input !~ '^0x[0-9a-fA-F]{40}$' THEN
    RAISE EXCEPTION 'market_input_invalid' USING ERRCODE = '22023';
  END IF;
  v_pay_to := lower(pay_to_address_input);
  IF v_pay_to IN ('0x0000000000000000000000000000000000000000',
                  '0x0077777d7eba4688bdef3e311b846f25870a19b9',
                  '0x3600000000000000000000000000000000000000') THEN
    RAISE EXCEPTION 'market_input_invalid' USING ERRCODE = '22023';
  END IF;

  SELECT w.out_actor, w.out_role, w.out_provider_id INTO v_writer
    FROM openarc_durable.lock_lifecycle_writer(session_hash, organization_id, listing_id) AS w;
  IF v_writer.out_actor IS NULL OR v_writer.out_role NOT IN ('owner', 'provider_admin') THEN
    RAISE EXCEPTION 'market_forbidden' USING ERRCODE = '42501';
  END IF;

  SELECT v.provider_id INTO v_version_provider
    FROM openarc_tenant.listing_versions v
   WHERE v.organization_id = organization_id AND v.listing_id = listing_id AND v.version = version
   FOR UPDATE;
  IF NOT FOUND OR v_version_provider IS DISTINCT FROM v_writer.out_provider_id THEN
    RAISE EXCEPTION 'market_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT s.status INTO v_status
    FROM openarc_tenant.listing_version_states s
   WHERE s.organization_id = organization_id AND s.listing_id = listing_id AND s.version = version
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'market_not_found' USING ERRCODE = '23503';
  END IF;
  v_resource_id := listing_id || '@' || version;

  SELECT r.* INTO v_existing FROM openarc_durable.idempotency_records r
   WHERE r.organization_id = organization_id AND r.operation = 'market.listing.payment_terms.record'
     AND r.key_hash = key_hash FOR UPDATE;
  IF FOUND THEN
    IF v_existing.request_digest = request_digest
       AND v_existing.mutation_id = mutation_id
       AND v_existing.actor_account_id = v_writer.out_actor
       AND v_existing.session_context_digest = session_context_digest
       AND v_existing.status = 'committed'
       AND v_existing.resource_type = 'listing_version'
       AND v_existing.resource_id = v_resource_id THEN
      SELECT t.pay_to_address, t.recorded_at INTO v_terms
        FROM openarc_tenant.listing_version_payment_terms t
       WHERE t.organization_id = organization_id AND t.listing_id = listing_id AND t.version = version;
      SELECT w.out_actor, w.out_role INTO v_recheck
        FROM openarc_durable.lock_lifecycle_writer(session_hash, organization_id, listing_id) AS w;
      IF v_recheck.out_actor IS DISTINCT FROM v_writer.out_actor
         OR v_recheck.out_role NOT IN ('owner', 'provider_admin') THEN
        RAISE EXCEPTION 'market_session_invalid' USING ERRCODE = '28000';
      END IF;
      out_replayed := true;
      out_mutation_id := v_existing.mutation_id;
      out_operation := v_existing.operation;
      out_resource_type := v_existing.resource_type;
      out_resource_id := v_existing.resource_id;
      out_pay_to_address := v_terms.pay_to_address;
      out_recorded_at := v_terms.recorded_at;
      out_committed_at := v_existing.committed_at;
      RETURN NEXT;
      RETURN;
    END IF;
    RAISE EXCEPTION 'market_idempotency_conflict' USING ERRCODE = 'P0D01';
  END IF;
  PERFORM 1 FROM openarc_durable.idempotency_records r
   WHERE r.organization_id = organization_id AND r.mutation_id = mutation_id FOR UPDATE;
  IF FOUND THEN
    RAISE EXCEPTION 'market_idempotency_conflict' USING ERRCODE = 'P0D01';
  END IF;

  IF v_status = 'retired' THEN
    RAISE EXCEPTION 'market_version_retired' USING ERRCODE = '23514';
  END IF;
  -- One immutable terms row per version: a changed pay-to needs a new version.
  PERFORM 1 FROM openarc_tenant.listing_version_payment_terms t
   WHERE t.organization_id = organization_id AND t.listing_id = listing_id AND t.version = version;
  IF FOUND THEN
    RAISE EXCEPTION 'listing_payment_terms_immutable' USING ERRCODE = '23505';
  END IF;

  SELECT clock_timestamp() INTO v_now;
  INSERT INTO openarc_durable.idempotency_records (
    organization_id, operation, key_hash, request_digest, digest_version,
    actor_account_id, session_context_digest, network, mutation_id, status
  ) VALUES (
    organization_id, 'market.listing.payment_terms.record', key_hash, request_digest,
    'market.listing.payment_terms.record.v1', v_writer.out_actor, session_context_digest,
    'eip155:5042002', mutation_id, 'pending'
  );
  INSERT INTO openarc_tenant.listing_version_payment_terms (
    organization_id, listing_id, version, provider_id, pay_to_address,
    recorded_by_account_id, mutation_id, recorded_at
  ) VALUES (
    organization_id, listing_id, version, v_writer.out_provider_id, v_pay_to,
    v_writer.out_actor, mutation_id, v_now
  );
  UPDATE openarc_durable.idempotency_records r
     SET status = 'committed', resource_type = 'listing_version',
         resource_id = v_resource_id, committed_at = clock_timestamp()
   WHERE r.organization_id = organization_id AND r.operation = 'market.listing.payment_terms.record'
     AND r.key_hash = key_hash
   RETURNING r.committed_at INTO v_committed_at;
  INSERT INTO openarc_durable.audit_events (
    organization_id, actor_account_id, operation, mutation_id, resource_type, resource_id, outcome
  ) VALUES (
    organization_id, v_writer.out_actor, 'market.listing.payment_terms.record', mutation_id,
    'listing_version', v_resource_id, 'committed'
  );

  -- Current seller authority after every durable write and all lock waits.
  SELECT w.out_actor, w.out_role INTO v_recheck
    FROM openarc_durable.lock_lifecycle_writer(session_hash, organization_id, listing_id) AS w;
  IF v_recheck.out_actor IS DISTINCT FROM v_writer.out_actor
     OR v_recheck.out_role NOT IN ('owner', 'provider_admin') THEN
    RAISE EXCEPTION 'market_session_invalid' USING ERRCODE = '28000';
  END IF;

  out_replayed := false;
  out_mutation_id := mutation_id;
  out_operation := 'market.listing.payment_terms.record';
  out_resource_type := 'listing_version';
  out_resource_id := v_resource_id;
  out_pay_to_address := v_pay_to;
  out_recorded_at := v_now;
  out_committed_at := v_committed_at;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Frozen verified requirement digest. NOT generic JSON: it hashes the exact
-- newline-joined string below (no trailing newline) so the API and tests can
-- reproduce it byte for byte:
--   openarc.control.requirement.verified_listing.v1 \n sellerOrgId \n providerId
--   \n listingId \n version \n eip155:5042002 \n exact \n 2 \n
--   GatewayWalletBatched \n 1 \n 0x0077777d7eba4688bdef3e311b846f25870a19b9 \n
--   USDC \n 0x3600000000000000000000000000000000000000 \n 6 \n erc20 \n
--   payToAddress (lowercase 0x + 40 hex) \n amountAtomic \n feeAtomic
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.verified_requirement_digest(
  seller_organization_id text,
  provider_id_input text,
  listing_id_input text,
  listing_version_input text,
  pay_to_address_input text,
  amount_atomic_input text,
  fee_atomic_input text
) RETURNS text
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT 'sha256:' || encode(
    sha256(convert_to(
      'openarc.control.requirement.verified_listing.v1' || E'\n' ||
      seller_organization_id || E'\n' || provider_id_input || E'\n' ||
      listing_id_input || E'\n' || listing_version_input || E'\n' ||
      'eip155:5042002' || E'\n' || 'exact' || E'\n' || '2' || E'\n' ||
      'GatewayWalletBatched' || E'\n' || '1' || E'\n' ||
      '0x0077777d7eba4688bdef3e311b846f25870a19b9' || E'\n' ||
      'USDC' || E'\n' || '0x3600000000000000000000000000000000000000' || E'\n' ||
      '6' || E'\n' || 'erc20' || E'\n' ||
      lower(pay_to_address_input) || E'\n' ||
      amount_atomic_input || E'\n' || fee_atomic_input,
      'UTF8'
    )),
    'hex'
  );
$$;

-- ---------------------------------------------------------------------------
-- Verified requirement insert proof. Runs for EVERY insert of the new kind,
-- whoever issues it, and re-derives every term from current seller state.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.enforce_verified_requirement_insert() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_listing record;
  v_version record;
  v_state record;
  v_review record;
  v_provider_status text;
  v_pay_to text;
  v_now timestamptz;
BEGIN
  IF NEW.source_kind IS DISTINCT FROM 'verified_listing' THEN
    RETURN NEW;
  END IF;
  SELECT l.provider_id, l.active_version INTO v_listing
    FROM openarc_tenant.listings l
   WHERE l.organization_id = NEW.seller_organization_id AND l.listing_id = NEW.listing_id;
  IF NOT FOUND OR v_listing.provider_id IS DISTINCT FROM NEW.provider_id
     OR v_listing.active_version IS NULL
     OR v_listing.active_version IS DISTINCT FROM NEW.listing_version THEN
    RAISE EXCEPTION 'commerce_requirement_unverifiable' USING ERRCODE = '42501';
  END IF;
  SELECT p.status INTO v_provider_status
    FROM openarc_tenant.providers p
   WHERE p.organization_id = NEW.seller_organization_id AND p.provider_id = NEW.provider_id;
  IF v_provider_status IS DISTINCT FROM 'active' THEN
    RAISE EXCEPTION 'commerce_requirement_unverifiable' USING ERRCODE = '42501';
  END IF;
  SELECT v.provider_id, v.price, v.endpoint_contract INTO v_version
    FROM openarc_tenant.listing_versions v
   WHERE v.organization_id = NEW.seller_organization_id AND v.listing_id = NEW.listing_id
     AND v.version = NEW.listing_version;
  IF NOT FOUND OR v_version.provider_id IS DISTINCT FROM NEW.provider_id THEN
    RAISE EXCEPTION 'commerce_requirement_unverifiable' USING ERRCODE = '42501';
  END IF;
  SELECT s.status, s.origin_review_state, s.published_at, s.current_review_id INTO v_state
    FROM openarc_tenant.listing_version_states s
   WHERE s.organization_id = NEW.seller_organization_id AND s.listing_id = NEW.listing_id
     AND s.version = NEW.listing_version;
  IF NOT FOUND OR v_state.status IS DISTINCT FROM 'active'
     OR v_state.origin_review_state IS DISTINCT FROM 'approved'
     OR v_state.published_at IS NULL OR v_state.current_review_id IS NULL THEN
    RAISE EXCEPTION 'commerce_requirement_unverifiable' USING ERRCODE = '42501';
  END IF;
  -- The CURRENT review of this exact version must approve this exact endpoint.
  SELECT r.decision, r.reviewed_endpoint_digest INTO v_review
    FROM openarc_tenant.listing_origin_reviews r
   WHERE r.organization_id = NEW.seller_organization_id AND r.listing_id = NEW.listing_id
     AND r.version = NEW.listing_version AND r.review_id = v_state.current_review_id;
  IF NOT FOUND OR v_review.decision IS DISTINCT FROM 'approved'
     OR v_review.reviewed_endpoint_digest IS DISTINCT FROM openarc_durable.reviewed_endpoint_digest(
          NEW.listing_id, NEW.listing_version,
          v_version.endpoint_contract->>'origin', v_version.endpoint_contract->>'path') THEN
    RAISE EXCEPTION 'commerce_requirement_unverifiable' USING ERRCODE = '42501';
  END IF;
  -- The seller's own immutable payment terms for this exact version.
  SELECT t.pay_to_address INTO v_pay_to
    FROM openarc_tenant.listing_version_payment_terms t
   WHERE t.organization_id = NEW.seller_organization_id AND t.listing_id = NEW.listing_id
     AND t.version = NEW.listing_version AND t.provider_id = NEW.provider_id;
  IF NOT FOUND OR v_pay_to IS NULL OR NEW.pay_to_address IS DISTINCT FROM v_pay_to THEN
    RAISE EXCEPTION 'commerce_requirement_unverifiable' USING ERRCODE = '42501';
  END IF;
  -- Every financial and protocol term is the server derivation, exactly.
  IF NEW.network_id IS DISTINCT FROM 'eip155:5042002'
     OR NEW.asset IS DISTINCT FROM 'USDC'
     OR NEW.representation IS DISTINCT FROM 'erc20'
     OR NEW.decimals IS DISTINCT FROM 6::smallint
     OR (v_version.price->'amount'->>'networkId') IS DISTINCT FROM NEW.network_id
     OR (v_version.price->'amount'->>'asset') IS DISTINCT FROM NEW.asset
     OR (v_version.price->'amount'->>'representation') IS DISTINCT FROM NEW.representation
     OR (v_version.price->'amount'->'decimals') IS DISTINCT FROM '6'::jsonb
     OR (v_version.price->>'pricingModel') IS DISTINCT FROM 'fixed'
     OR NEW.amount_atomic IS DISTINCT FROM (v_version.price->'amount'->>'atomicAmount')
     OR NEW.fee_atomic IS DISTINCT FROM '0'
     OR NEW.requirement_digest IS DISTINCT FROM openarc_durable.verified_requirement_digest(
          NEW.seller_organization_id, NEW.provider_id, NEW.listing_id, NEW.listing_version,
          NEW.pay_to_address, NEW.amount_atomic, NEW.fee_atomic)
     OR NEW.valid_until IS DISTINCT FROM NEW.created_at + interval '900 seconds' THEN
    RAISE EXCEPTION 'commerce_requirement_unverifiable' USING ERRCODE = '42501';
  END IF;
  -- The creation instant is the database clock, never a back- or forward-dated
  -- caller value that could stretch the validity window.
  v_now := clock_timestamp();
  IF NOT (NEW.created_at <= v_now AND NEW.created_at > v_now - interval '60 seconds') THEN
    RAISE EXCEPTION 'commerce_requirement_unverifiable' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER commerce_requirement_references_verified
  BEFORE INSERT ON openarc_durable.commerce_requirement_references
  FOR EACH ROW EXECUTE FUNCTION openarc_durable.enforce_verified_requirement_insert();

-- ---------------------------------------------------------------------------
-- Migrator-private verified requirement registration. The caller names ONLY
-- the buyer organization, a fresh requirement id and the listing id; the
-- seller organization, provider, active version, price and every protocol term
-- are derived under lock. Lock order: buyer+seller organizations together
-- sorted, then the schema10 seller provider/listing/version/state/review lock,
-- then the new requirement row.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.register_verified_commerce_requirement_core(
  buyer_organization_id text,
  requirement_id_input text,
  listing_id_input text
) RETURNS TABLE(
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
  out_pay_to_address text,
  out_requirement_digest text,
  out_source_kind text,
  out_created_at timestamptz,
  out_valid_until timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_listing record;
  v_pay_to text;
  v_amount text;
  v_digest text;
  v_now timestamptz;
BEGIN
  IF NOT openarc_durable.is_canonical_org_id(buyer_organization_id)
     OR NOT openarc_durable.is_canonical_requirement_id(requirement_id_input)
     OR NOT openarc_durable.is_canonical_listing_id(listing_id_input) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  -- Immutable seller ownership lookup first, without lock or authority.
  SELECT l.organization_id, l.provider_id INTO v_listing
    FROM openarc_tenant.listings l
   WHERE l.listing_id = listing_id_input;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  PERFORM 1 FROM openarc_tenant.organizations o
   WHERE o.organization_id IN (buyer_organization_id, v_listing.organization_id)
   ORDER BY o.organization_id FOR UPDATE;
  IF (SELECT count(*) FROM openarc_tenant.organizations o
       WHERE o.organization_id IN (buyer_organization_id, v_listing.organization_id))
     <> (SELECT count(DISTINCT x) FROM unnest(
           ARRAY[buyer_organization_id, v_listing.organization_id]) AS x) THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT l.organization_id, l.provider_id, l.active_version INTO v_listing
    FROM openarc_tenant.listings l
   WHERE l.listing_id = listing_id_input;
  IF v_listing.active_version IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  -- Real current seller provider/listing/version/approved-origin authority.
  PERFORM openarc_durable.lock_action_listing(
    v_listing.organization_id, v_listing.provider_id, listing_id_input, v_listing.active_version);
  SELECT v.price->'amount'->>'atomicAmount' INTO v_amount
    FROM openarc_tenant.listing_versions v
   WHERE v.organization_id = v_listing.organization_id AND v.listing_id = listing_id_input
     AND v.version = v_listing.active_version;
  IF v_amount IS NULL OR NOT openarc_durable.is_positive_uint256(v_amount) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  -- The seller's immutable terms for the active version; none means no
  -- verified requirement can exist for it.
  SELECT t.pay_to_address INTO v_pay_to
    FROM openarc_tenant.listing_version_payment_terms t
   WHERE t.organization_id = v_listing.organization_id AND t.listing_id = listing_id_input
     AND t.version = v_listing.active_version AND t.provider_id = v_listing.provider_id;
  IF v_pay_to IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  v_digest := openarc_durable.verified_requirement_digest(
    v_listing.organization_id, v_listing.provider_id, listing_id_input,
    v_listing.active_version, v_pay_to, v_amount, '0');
  v_now := clock_timestamp();
  INSERT INTO openarc_durable.commerce_requirement_references (
    organization_id, requirement_id, seller_organization_id, provider_id, listing_id,
    listing_version, network_id, asset, representation, decimals, amount_atomic,
    fee_atomic, requirement_digest, source_kind, created_at, valid_until, pay_to_address
  ) VALUES (
    buyer_organization_id, requirement_id_input, v_listing.organization_id,
    v_listing.provider_id, listing_id_input, v_listing.active_version,
    'eip155:5042002', 'USDC', 'erc20', 6, v_amount, '0', v_digest,
    'verified_listing', v_now, v_now + interval '900 seconds', v_pay_to
  );
  out_organization_id := buyer_organization_id;
  out_requirement_id := requirement_id_input;
  out_seller_organization_id := v_listing.organization_id;
  out_provider_id := v_listing.provider_id;
  out_listing_id := listing_id_input;
  out_listing_version := v_listing.active_version;
  out_network_id := 'eip155:5042002';
  out_asset := 'USDC';
  out_representation := 'erc20';
  out_decimals := 6;
  out_amount_atomic := v_amount;
  out_fee_atomic := '0';
  out_pay_to_address := v_pay_to;
  out_requirement_digest := v_digest;
  out_source_kind := 'verified_listing';
  out_created_at := v_now;
  out_valid_until := v_now + interval '900 seconds';
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Runtime verified requirement registrar. The caller presents ONLY the exact
-- consumed oacs_v1_ commerce token hash, a fresh requirement id and a listing
-- id. The buyer organization is DB-derived from that token (never an input).
-- Authority is asserted BEFORE (a non-locking current commerce-session check,
-- then the schema10 combined chain lock) and AFTER (the locking commerce
-- session state check, in its frozen position after the listing and
-- requirement locks). Every term comes from the migrator core.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.register_verified_commerce_requirement(
  commerce_token_hash text,
  requirement_id_input text,
  listing_id_input text
) RETURNS TABLE(
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
  out_pay_to_address text,
  out_requirement_digest text,
  out_source_kind text,
  out_created_at timestamptz,
  out_valid_until timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_ctx record;
  v_session record;
  v_seller text;
  v_chain record;
  v_row record;
BEGIN
  IF NOT openarc_durable.is_canonical_hex64(commerce_token_hash) THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;
  IF NOT openarc_durable.is_canonical_requirement_id(requirement_id_input)
     OR NOT openarc_durable.is_canonical_listing_id(listing_id_input) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO v_ctx
    FROM openarc_durable.resolve_commerce_action_context(commerce_token_hash) AS c;
  IF v_ctx.out_organization_id IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  -- Authority BEFORE: the exact token's session must be exchanged, unrevoked
  -- and unexpired. Non-locking, so the frozen lock order is preserved.
  SELECT cs.revoked_at, cs.exchanged_at, cs.expires_at INTO v_session
    FROM openarc_durable.commerce_session_handoffs h
    JOIN openarc_durable.commerce_sessions cs
      ON cs.organization_id = h.organization_id AND cs.session_id = h.session_id
   WHERE h.organization_id = v_ctx.out_organization_id
     AND h.token_hash = commerce_token_hash AND h.token_hash_version = 1
     AND h.consumed_at IS NOT NULL;
  IF NOT FOUND OR v_session.revoked_at IS NOT NULL OR v_session.exchanged_at IS NULL
     OR NOT (v_session.expires_at > clock_timestamp()) THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT l.organization_id INTO v_seller
    FROM openarc_tenant.listings l WHERE l.listing_id = listing_id_input;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT * INTO v_chain
    FROM openarc_durable.lock_action_commerce(commerce_token_hash, v_seller) AS c;
  IF v_chain.out_organization_id IS DISTINCT FROM v_ctx.out_organization_id THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT * INTO v_row
    FROM openarc_durable.register_verified_commerce_requirement_core(
      v_chain.out_organization_id, requirement_id_input, listing_id_input) AS r;
  -- Authority AFTER, with the commerce session row locked.
  PERFORM openarc_durable.lock_action_commerce_state(
    commerce_token_hash, v_chain.out_organization_id);
  out_organization_id := v_row.out_organization_id;
  out_requirement_id := v_row.out_requirement_id;
  out_seller_organization_id := v_row.out_seller_organization_id;
  out_provider_id := v_row.out_provider_id;
  out_listing_id := v_row.out_listing_id;
  out_listing_version := v_row.out_listing_version;
  out_network_id := v_row.out_network_id;
  out_asset := v_row.out_asset;
  out_representation := v_row.out_representation;
  out_decimals := v_row.out_decimals;
  out_amount_atomic := v_row.out_amount_atomic;
  out_fee_atomic := v_row.out_fee_atomic;
  out_pay_to_address := v_row.out_pay_to_address;
  out_requirement_digest := v_row.out_requirement_digest;
  out_source_kind := v_row.out_source_kind;
  out_created_at := v_row.out_created_at;
  out_valid_until := v_row.out_valid_until;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Lane binding digest, reproducing packages/x402 digestLaneBinding exactly:
-- 'sha256:' || hex(sha256(canonical JSON)) with keys in JavaScript sort order
-- and every value a string. All inputs are CHECK-constrained to characters
-- JSON.stringify never escapes, and every column is NOT NULL.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.payment_attempt_binding_digest(
  action_id_input text,
  asset_input text,
  attempt_id_input text,
  from_input text,
  grant_id_input text,
  grant_requirement_digest_input text,
  lane_requirement_digest_input text,
  network_input text,
  nonce_input text,
  role_input text,
  schema_version_input text,
  to_input text,
  valid_after_input text,
  valid_before_input text,
  value_input text,
  verifying_contract_input text
) RETURNS text
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT 'sha256:' || encode(sha256(convert_to(
    '{"actionId":"' || action_id_input ||
    '","asset":"' || asset_input ||
    '","attemptId":"' || attempt_id_input ||
    '","from":"' || from_input ||
    '","grantId":"' || grant_id_input ||
    '","grantRequirementDigest":"' || grant_requirement_digest_input ||
    '","laneRequirementDigest":"' || lane_requirement_digest_input ||
    '","network":"' || network_input ||
    '","nonce":"' || nonce_input ||
    '","role":"' || role_input ||
    '","schemaVersion":"' || schema_version_input ||
    '","to":"' || to_input ||
    '","validAfter":"' || valid_after_input ||
    '","validBefore":"' || valid_before_input ||
    '","value":"' || value_input ||
    '","verifyingContract":"' || verifying_contract_input || '"}',
    'UTF8')), 'hex');
$$;

-- ---------------------------------------------------------------------------
-- payment_attempts: one durable buyer attempt per grant/action. Every binding
-- column is immutable; only the closed LaneExposure state columns advance.
-- ---------------------------------------------------------------------------
CREATE TABLE openarc_durable.payment_attempts (
  organization_id text NOT NULL,
  attempt_id uuid NOT NULL,
  role text NOT NULL,
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
  requirement_digest text NOT NULL,
  source_kind text NOT NULL,
  network_id text NOT NULL,
  asset_address text NOT NULL,
  verifying_contract text NOT NULL,
  payer_address text NOT NULL,
  pay_to_address text NOT NULL,
  value_atomic text NOT NULL,
  valid_after text NOT NULL,
  valid_before text NOT NULL,
  nonce text NOT NULL,
  lane_requirement_digest text NOT NULL,
  binding_digest text NOT NULL,
  state text NOT NULL,
  persisted_at timestamptz NOT NULL,
  dispatched_at timestamptz,
  observed_at timestamptz,
  transfer_id uuid,
  gateway_status text,
  batch_tx_hash text,
  PRIMARY KEY (organization_id, attempt_id),
  -- One attempt per one-use grant and per action, forever: an unknown attempt
  -- can never be retried with a fresh authorization.
  CONSTRAINT payment_attempts_grant_unique UNIQUE (organization_id, grant_id),
  CONSTRAINT payment_attempts_action_unique UNIQUE (organization_id, action_id),
  CONSTRAINT payment_attempts_attempt_valid CHECK (openarc_durable.is_canonical_uuid_v4(attempt_id::text)),
  CONSTRAINT payment_attempts_role_valid CHECK (role = 'buyer'),
  CONSTRAINT payment_attempts_grant_valid CHECK (openarc_durable.is_canonical_grant_id(grant_id)),
  CONSTRAINT payment_attempts_action_valid CHECK (openarc_durable.is_canonical_action_id(action_id)),
  CONSTRAINT payment_attempts_reservation_valid CHECK (openarc_durable.is_canonical_reservation_id(reservation_id)),
  CONSTRAINT payment_attempts_requirement_valid CHECK (openarc_durable.is_canonical_requirement_id(requirement_id)),
  CONSTRAINT payment_attempts_requirement_digest_valid CHECK (
    openarc_durable.is_canonical_sha256_digest(requirement_digest)),
  -- Durable attempts exist ONLY for verified provenance. Fixture provenance can
  -- never acquire a production-shaped payment record.
  CONSTRAINT payment_attempts_source_valid CHECK (source_kind = 'verified_listing'),
  CONSTRAINT payment_attempts_manifest_valid CHECK (
    network_id = 'eip155:5042002'
    AND asset_address = '0x3600000000000000000000000000000000000000'
    AND verifying_contract = '0x0077777d7EBA4688BDeF3E311b846F25870A19B9'),
  CONSTRAINT payment_attempts_payer_valid CHECK (
    payer_address ~ '^0x[0-9a-fA-F]{40}$'
    AND lower(payer_address) <> '0x0000000000000000000000000000000000000000'),
  CONSTRAINT payment_attempts_pay_to_valid CHECK (
    pay_to_address ~ '^0x[0-9a-fA-F]{40}$'
    AND lower(pay_to_address) <> '0x0000000000000000000000000000000000000000'
    AND lower(pay_to_address) <> '0x0077777d7eba4688bdef3e311b846f25870a19b9'
    AND lower(pay_to_address) <> '0x3600000000000000000000000000000000000000'
    AND lower(pay_to_address) <> lower(payer_address)),
  CONSTRAINT payment_attempts_value_valid CHECK (openarc_durable.is_positive_uint256(value_atomic)),
  CONSTRAINT payment_attempts_validity_valid CHECK (
    openarc_durable.is_canonical_uint256(valid_after)
    AND openarc_durable.is_positive_uint256(valid_before)
    AND valid_before::numeric > valid_after::numeric),
  CONSTRAINT payment_attempts_nonce_valid CHECK (
    nonce ~ '^0x[0-9a-f]{64}$'
    AND nonce <> '0x0000000000000000000000000000000000000000000000000000000000000000'),
  CONSTRAINT payment_attempts_lane_requirement_digest_valid CHECK (
    openarc_durable.is_canonical_sha256_digest(lane_requirement_digest)),
  -- The stored digest IS the lane binding digest of the stored fields: a row
  -- whose digest does not describe its own binding is unrepresentable.
  CONSTRAINT payment_attempts_binding_digest_valid CHECK (
    binding_digest = openarc_durable.payment_attempt_binding_digest(
      action_id, asset_address, attempt_id::text, payer_address, grant_id,
      requirement_digest, lane_requirement_digest, network_id, nonce, role,
      'openarc.x402.lane-binding.v1', pay_to_address, valid_after, valid_before,
      value_atomic, verifying_contract)),
  CONSTRAINT payment_attempts_state_valid CHECK (
    state IN ('persisted', 'unknown', 'pending', 'committed')),
  CONSTRAINT payment_attempts_state_shape CHECK (
    (state = 'persisted' AND dispatched_at IS NULL AND observed_at IS NULL
      AND transfer_id IS NULL AND gateway_status IS NULL AND batch_tx_hash IS NULL)
    OR (state = 'unknown' AND dispatched_at IS NOT NULL AND observed_at IS NULL
      AND transfer_id IS NULL AND gateway_status IS NULL AND batch_tx_hash IS NULL)
    OR (state = 'pending' AND dispatched_at IS NOT NULL AND observed_at IS NOT NULL
      AND transfer_id IS NOT NULL AND gateway_status IN ('received', 'batched', 'confirmed')
      AND (batch_tx_hash IS NULL OR batch_tx_hash ~ '^0x[0-9a-f]{64}$'))
    OR (state = 'committed' AND dispatched_at IS NOT NULL AND observed_at IS NOT NULL
      AND transfer_id IS NOT NULL AND gateway_status = 'completed'
      AND batch_tx_hash ~ '^0x[0-9a-f]{64}$')),
  CONSTRAINT payment_attempts_clock_valid CHECK (
    (dispatched_at IS NULL OR dispatched_at >= persisted_at)
    AND (observed_at IS NULL OR (dispatched_at IS NOT NULL AND observed_at >= dispatched_at))),
  CONSTRAINT payment_attempts_org_fk FOREIGN KEY (organization_id)
    REFERENCES openarc_tenant.organizations(organization_id) ON DELETE RESTRICT,
  CONSTRAINT payment_attempts_seller_org_fk FOREIGN KEY (seller_organization_id)
    REFERENCES openarc_tenant.organizations(organization_id) ON DELETE RESTRICT,
  CONSTRAINT payment_attempts_session_fk FOREIGN KEY (organization_id, commerce_session_id)
    REFERENCES openarc_durable.commerce_sessions(organization_id, session_id) ON DELETE RESTRICT,
  CONSTRAINT payment_attempts_requirement_fk FOREIGN KEY (organization_id, requirement_id)
    REFERENCES openarc_durable.commerce_requirement_references(organization_id, requirement_id) ON DELETE RESTRICT,
  -- The attempt mirrors the grant and action bindings EXACTLY.
  CONSTRAINT payment_attempts_grant_binding_fk FOREIGN KEY (
    organization_id, grant_id, action_id, reservation_id, seller_organization_id,
    provider_id, listing_id, listing_version, requirement_id)
    REFERENCES openarc_durable.authorization_grants (
      organization_id, grant_id, action_id, reservation_id, seller_organization_id,
      provider_id, listing_id, listing_version, requirement_id) ON DELETE RESTRICT,
  CONSTRAINT payment_attempts_action_binding_fk FOREIGN KEY (
    organization_id, action_id, subject_agent_id, commerce_session_id,
    seller_organization_id, provider_id, listing_id, listing_version,
    requirement_id, reservation_id)
    REFERENCES openarc_durable.commerce_actions (
      organization_id, action_id, subject_agent_id, commerce_session_id,
      seller_organization_id, provider_id, listing_id, listing_version,
      requirement_id, reservation_id) ON DELETE RESTRICT
);

-- One authorization nonce per payer, ever (contract §4.4: reuse is rejected
-- and one claim maps to one nonce).
CREATE UNIQUE INDEX payment_attempts_payer_nonce_unique
  ON openarc_durable.payment_attempts (lower(payer_address), nonce);

-- ---------------------------------------------------------------------------
-- Attempt mutation rule: no delete, immutable binding, closed LaneExposure
-- edges only, and an insert must mirror its action's amount, requirement
-- digest and provenance exactly.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.enforce_payment_attempt_mutation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_action record;
  v_old_rank integer;
  v_new_rank integer;
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'payment_attempt_immutable' USING ERRCODE = '42501';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.state IS DISTINCT FROM 'persisted' THEN
      RAISE EXCEPTION 'payment_attempt_state_invalid' USING ERRCODE = '23514';
    END IF;
    SELECT a.amount_atomic, a.requirement_digest, a.source_kind INTO v_action
      FROM openarc_durable.commerce_actions a
     WHERE a.organization_id = NEW.organization_id AND a.action_id = NEW.action_id;
    IF NOT FOUND
       OR v_action.amount_atomic IS DISTINCT FROM NEW.value_atomic
       OR v_action.requirement_digest IS DISTINCT FROM NEW.requirement_digest
       OR v_action.source_kind IS DISTINCT FROM NEW.source_kind THEN
      RAISE EXCEPTION 'payment_attempt_binding_invalid' USING ERRCODE = '23514';
    END IF;
    -- The payee is the seller-derived pay-to of the verified requirement.
    PERFORM 1 FROM openarc_durable.commerce_requirement_references r
     WHERE r.organization_id = NEW.organization_id AND r.requirement_id = NEW.requirement_id
       AND r.pay_to_address IS NOT NULL AND r.pay_to_address = lower(NEW.pay_to_address);
    IF NOT FOUND THEN
      RAISE EXCEPTION 'payment_attempt_binding_invalid' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
     OR NEW.attempt_id IS DISTINCT FROM OLD.attempt_id
     OR NEW.role IS DISTINCT FROM OLD.role
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
     OR NEW.requirement_digest IS DISTINCT FROM OLD.requirement_digest
     OR NEW.source_kind IS DISTINCT FROM OLD.source_kind
     OR NEW.network_id IS DISTINCT FROM OLD.network_id
     OR NEW.asset_address IS DISTINCT FROM OLD.asset_address
     OR NEW.verifying_contract IS DISTINCT FROM OLD.verifying_contract
     OR NEW.payer_address IS DISTINCT FROM OLD.payer_address
     OR NEW.pay_to_address IS DISTINCT FROM OLD.pay_to_address
     OR NEW.value_atomic IS DISTINCT FROM OLD.value_atomic
     OR NEW.valid_after IS DISTINCT FROM OLD.valid_after
     OR NEW.valid_before IS DISTINCT FROM OLD.valid_before
     OR NEW.nonce IS DISTINCT FROM OLD.nonce
     OR NEW.lane_requirement_digest IS DISTINCT FROM OLD.lane_requirement_digest
     OR NEW.binding_digest IS DISTINCT FROM OLD.binding_digest
     OR NEW.persisted_at IS DISTINCT FROM OLD.persisted_at THEN
    RAISE EXCEPTION 'payment_attempt_immutable' USING ERRCODE = '42501';
  END IF;
  -- Recorded facts never move once set.
  IF OLD.dispatched_at IS NOT NULL AND NEW.dispatched_at IS DISTINCT FROM OLD.dispatched_at THEN
    RAISE EXCEPTION 'payment_attempt_immutable' USING ERRCODE = '42501';
  END IF;
  IF OLD.transfer_id IS NOT NULL AND NEW.transfer_id IS DISTINCT FROM OLD.transfer_id THEN
    RAISE EXCEPTION 'payment_attempt_immutable' USING ERRCODE = '42501';
  END IF;
  IF OLD.batch_tx_hash IS NOT NULL AND NEW.batch_tx_hash IS DISTINCT FROM OLD.batch_tx_hash THEN
    RAISE EXCEPTION 'payment_attempt_immutable' USING ERRCODE = '42501';
  END IF;
  IF OLD.observed_at IS NOT NULL AND NOT (NEW.observed_at >= OLD.observed_at) THEN
    RAISE EXCEPTION 'payment_attempt_immutable' USING ERRCODE = '42501';
  END IF;
  v_old_rank := CASE OLD.gateway_status
    WHEN 'received' THEN 1 WHEN 'batched' THEN 2 WHEN 'confirmed' THEN 3
    WHEN 'completed' THEN 4 ELSE 0 END;
  v_new_rank := CASE NEW.gateway_status
    WHEN 'received' THEN 1 WHEN 'batched' THEN 2 WHEN 'confirmed' THEN 3
    WHEN 'completed' THEN 4 ELSE 0 END;
  -- The ONLY edges. No release, no failure, no expiry, nothing out of unknown
  -- except pending or committed, and nothing at all out of committed.
  IF NOT (
       (OLD.state = 'persisted' AND NEW.state = 'unknown')
       OR (OLD.state = 'unknown' AND NEW.state IN ('pending', 'committed'))
       OR (OLD.state = 'pending' AND NEW.state = 'pending'
           AND (v_new_rank > v_old_rank
                OR (v_new_rank = v_old_rank AND OLD.batch_tx_hash IS NULL
                    AND NEW.batch_tx_hash IS NOT NULL)))
       OR (OLD.state = 'pending' AND NEW.state = 'committed')) THEN
    RAISE EXCEPTION 'payment_attempt_state_invalid' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER payment_attempts_mutation
  BEFORE INSERT OR UPDATE OR DELETE ON openarc_durable.payment_attempts
  FOR EACH ROW EXECUTE FUNCTION openarc_durable.enforce_payment_attempt_mutation();

-- ---------------------------------------------------------------------------
-- Exposure guards on the accepted schema10/schema12 tables. These are separate
-- additive triggers: no existing trigger, constraint or function body in
-- 0010-0014 is loosened.
--   * A reservation with ANY durable attempt can never be released.
--   * A non-fixture reservation cannot advance past held (claimed, unknown,
--     committed) unless its attempt was durably dispatched first.
--   * A granted action with ANY durable attempt can never move to cancelled,
--     expired or rejected.
--   * A non-fixture grant can only be claimed by the attempt id its buyer
--     durably dispatched.
-- internal_fixture rows keep their exact accepted behaviour.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.enforce_reservation_payment_exposure() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NEW.status = 'released' AND EXISTS (
         SELECT 1 FROM openarc_durable.payment_attempts p
          WHERE p.organization_id = OLD.organization_id AND p.action_id = OLD.action_id) THEN
      RAISE EXCEPTION 'payment_attempt_exposure_held' USING ERRCODE = 'P0D13';
    END IF;
    IF OLD.status = 'held' AND NEW.status IN ('claimed', 'unknown', 'committed')
       AND OLD.source_kind IS DISTINCT FROM 'internal_fixture'
       AND NOT EXISTS (
         SELECT 1 FROM openarc_durable.payment_attempts p
          WHERE p.organization_id = OLD.organization_id AND p.action_id = OLD.action_id
            AND p.state <> 'persisted') THEN
      RAISE EXCEPTION 'payment_attempt_missing' USING ERRCODE = 'P0D14';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER budget_reservations_payment_exposure
  BEFORE UPDATE ON openarc_durable.budget_reservations
  FOR EACH ROW EXECUTE FUNCTION openarc_durable.enforce_reservation_payment_exposure();

CREATE FUNCTION openarc_durable.enforce_action_payment_exposure() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  -- Only the terminal non-success statuses are refused; a future success
  -- status (P04-04) is deliberately not blocked here.
  IF OLD.status = 'grant_issued' AND NEW.status IN ('cancelled', 'expired', 'rejected')
     AND EXISTS (
       SELECT 1 FROM openarc_durable.payment_attempts p
        WHERE p.organization_id = OLD.organization_id AND p.action_id = OLD.action_id) THEN
    RAISE EXCEPTION 'payment_attempt_exposure_held' USING ERRCODE = 'P0D13';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER commerce_actions_payment_exposure
  BEFORE UPDATE ON openarc_durable.commerce_actions
  FOR EACH ROW EXECUTE FUNCTION openarc_durable.enforce_action_payment_exposure();

CREATE FUNCTION openarc_durable.enforce_claim_payment_attempt() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_source text;
BEGIN
  SELECT g.source_kind INTO v_source
    FROM openarc_durable.authorization_grants g
   WHERE g.organization_id = NEW.organization_id AND g.grant_id = NEW.grant_id;
  IF v_source IS DISTINCT FROM 'internal_fixture' THEN
    PERFORM 1 FROM openarc_durable.payment_attempts p
     WHERE p.organization_id = NEW.organization_id AND p.grant_id = NEW.grant_id
       AND p.attempt_id = NEW.attempt_id AND p.state <> 'persisted';
    IF NOT FOUND THEN
      RAISE EXCEPTION 'payment_attempt_missing' USING ERRCODE = 'P0D14';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER authorization_grant_claims_payment_attempt
  BEFORE INSERT ON openarc_durable.authorization_grant_claims
  FOR EACH ROW EXECUTE FUNCTION openarc_durable.enforce_claim_payment_attempt();

-- ---------------------------------------------------------------------------
-- RLS: migrator-only. Runtime/worker/PUBLIC receive no direct privilege.
-- ---------------------------------------------------------------------------
ALTER TABLE openarc_durable.payment_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE openarc_durable.payment_attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY payment_attempts_migrator ON openarc_durable.payment_attempts
  FOR ALL TO openarc_migrator USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE openarc_durable.payment_attempts FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Human revoke, redefined ONLY to keep exposure held when a durable payment
-- attempt exists. The body is the accepted schema12 body verbatim except for
-- the attempt row lock (after the grant, in the frozen order) and the one added
-- release condition. A revoke still retires the token and marks the grant
-- revoked, so buyer cleanup is never blocked by an attempt.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION openarc_durable.revoke_authorization_grant(
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

  -- schema15: a durable payment attempt (in ANY state, including persisted)
  -- means a signature may have left the buyer, so exposure stays held. The
  -- attempt row is locked after the grant, in the frozen order.
  PERFORM 1 FROM openarc_durable.payment_attempts p
   WHERE p.organization_id = organization_id AND p.grant_id = grant_id_input FOR UPDATE;

  IF v_grant.claimed_at IS NULL
     AND openarc_durable.reservation_releasable(v_reservation.status)
     AND v_reservation.claimed_at IS NULL
     AND NOT EXISTS (
       SELECT 1 FROM openarc_durable.payment_attempts p
        WHERE p.organization_id = organization_id AND p.action_id = v_action.action_id) THEN
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
-- Buyer attempt persistence. The agent presents ONLY the exact consumed
-- oacs_v1_ commerce token hash, the grant id, its attempt id and the caller
-- variable lane fields (payer, pay-to, validity, nonce, lane requirement
-- digest) plus the lane binding digest it computed. Network, asset, verifying
-- contract, value, role, schema version, action id and the grant requirement
-- digest are DB-derived; the database recomputes the binding digest over the
-- derived and supplied fields and refuses any mismatch, so a caller cannot bind
-- a different amount, network, asset or contract.
--
-- Lock order: immutable lookups, then the full schema12 buyer chain (accounts,
-- parent human session, buyer+seller organizations, memberships, agent,
-- credential, machine session, policy, seller listing, requirement, commerce
-- session, exposure, action, reservation), then the grant, then the attempt.
-- No external call is made.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.persist_payment_attempt(
  commerce_token_hash text,
  grant_id_input text,
  attempt_id_input uuid,
  payer_address_input text,
  pay_to_address_input text,
  valid_after_input text,
  valid_before_input text,
  nonce_input text,
  lane_requirement_digest_input text,
  binding_digest_input text
) RETURNS TABLE(
  out_replayed boolean,
  out_organization_id text,
  out_attempt_id uuid,
  out_grant_id text,
  out_action_id text,
  out_provider_id text,
  out_listing_id text,
  out_listing_version text,
  out_requirement_id text,
  out_requirement_digest text,
  out_network_id text,
  out_asset_address text,
  out_verifying_contract text,
  out_payer_address text,
  out_pay_to_address text,
  out_value_atomic text,
  out_valid_after text,
  out_valid_before text,
  out_nonce text,
  out_lane_requirement_digest text,
  out_binding_digest text,
  out_state text,
  out_persisted_at timestamptz,
  out_dispatched_at timestamptz,
  out_observed_at timestamptz,
  out_transfer_id uuid,
  out_gateway_status text,
  out_batch_tx_hash text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_ctx record;
  v_ref record;
  v_chain record;
  v_grant record;
  v_attempt record;
  v_org text;
  v_now timestamptz;
  v_epoch numeric;
  v_digest text;
  v_pay_to text;
  v_replayed boolean := false;
BEGIN
  IF NOT openarc_durable.is_canonical_hex64(commerce_token_hash) THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;
  IF NOT openarc_durable.is_canonical_grant_id(grant_id_input)
     OR attempt_id_input IS NULL
     OR NOT openarc_durable.is_canonical_uuid_v4(attempt_id_input::text)
     OR payer_address_input IS NULL OR payer_address_input !~ '^0x[0-9a-fA-F]{40}$'
     OR pay_to_address_input IS NULL OR pay_to_address_input !~ '^0x[0-9a-fA-F]{40}$'
     OR valid_after_input IS NULL OR NOT openarc_durable.is_canonical_uint256(valid_after_input)
     OR valid_before_input IS NULL OR NOT openarc_durable.is_positive_uint256(valid_before_input)
     OR nonce_input IS NULL OR nonce_input !~ '^0x[0-9a-f]{64}$'
     OR NOT openarc_durable.is_canonical_sha256_digest(lane_requirement_digest_input)
     OR NOT openarc_durable.is_canonical_sha256_digest(binding_digest_input) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;

  -- Immutable lookups first, without lock or authority. A grant of another
  -- organization is indistinguishable from a missing grant.
  SELECT * INTO v_ctx
    FROM openarc_durable.resolve_commerce_action_context(commerce_token_hash) AS c;
  IF v_ctx.out_organization_id IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  v_org := v_ctx.out_organization_id;
  SELECT g.action_id INTO v_ref FROM openarc_durable.authorization_grants g
   WHERE g.organization_id = v_org AND g.grant_id = grant_id_input;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;

  SELECT * INTO v_chain
    FROM openarc_durable.lock_grant_commerce_chain(commerce_token_hash, v_ref.action_id) AS c;
  IF v_chain.out_organization_id IS DISTINCT FROM v_org THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  IF v_chain.out_source_kind IS DISTINCT FROM 'verified_listing' THEN
    RAISE EXCEPTION 'commerce_requirement_unavailable' USING ERRCODE = 'P0D10';
  END IF;

  SELECT g.* INTO v_grant FROM openarc_durable.authorization_grants g
   WHERE g.organization_id = v_org AND g.grant_id = grant_id_input FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  -- The payee must be the verified requirement's seller-derived pay-to
  -- (case-insensitive; the binding digest keeps the lane's checksum form).
  -- The requirement row is already locked by the chain above.
  SELECT r.pay_to_address INTO v_pay_to FROM openarc_durable.commerce_requirement_references r
   WHERE r.organization_id = v_org AND r.requirement_id = v_chain.out_requirement_id;
  IF v_pay_to IS NULL OR lower(pay_to_address_input) IS DISTINCT FROM v_pay_to THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;

  SELECT p.* INTO v_attempt FROM openarc_durable.payment_attempts p
   WHERE p.organization_id = v_org AND p.grant_id = grant_id_input FOR UPDATE;
  IF FOUND THEN
    -- Exact replay of the same durable binding returns the CURRENT row, in
    -- whatever state it has reached; anything else is a conflict and never a
    -- second attempt.
    IF v_attempt.attempt_id = attempt_id_input AND v_attempt.binding_digest = binding_digest_input THEN
      v_replayed := true;
    ELSE
      RAISE EXCEPTION 'payment_attempt_conflict' USING ERRCODE = 'P0D14';
    END IF;
  ELSE
    PERFORM 1 FROM openarc_durable.payment_attempts p
     WHERE p.organization_id = v_org AND p.attempt_id = attempt_id_input FOR UPDATE;
    IF FOUND THEN
      RAISE EXCEPTION 'payment_attempt_conflict' USING ERRCODE = 'P0D14';
    END IF;

    SELECT clock_timestamp() INTO v_now;
    IF v_grant.status <> 'issued' OR v_grant.claimed_at IS NOT NULL OR v_grant.revoked_at IS NOT NULL THEN
      RAISE EXCEPTION 'commerce_grant_conflict' USING ERRCODE = 'P0D14';
    END IF;
    IF NOT (v_grant.expires_at > v_now) OR NOT (v_chain.out_chain_expires_at > v_now) THEN
      RAISE EXCEPTION 'commerce_grant_expired' USING ERRCODE = 'P0D15';
    END IF;
    IF v_chain.out_action_status <> 'grant_issued' OR v_chain.out_reservation_status <> 'held'
       OR v_chain.out_reservation_claimed_at IS NOT NULL THEN
      RAISE EXCEPTION 'commerce_grant_conflict' USING ERRCODE = 'P0D14';
    END IF;
    -- Lane validity (contract §4.3): validAfter no later than now (plus skew),
    -- validBefore at least the 7-day floor and at most 7 days + 1 hour + skew.
    v_epoch := floor(extract(epoch FROM v_now));
    IF valid_after_input::numeric > v_epoch + 600
       OR valid_before_input::numeric - v_epoch < 604800
       OR valid_before_input::numeric - v_epoch > 609000
       OR NOT (valid_before_input::numeric > valid_after_input::numeric) THEN
      RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
    END IF;
    v_digest := openarc_durable.payment_attempt_binding_digest(
      v_ref.action_id::text, '0x3600000000000000000000000000000000000000',
      attempt_id_input::text, payer_address_input, grant_id_input,
      v_chain.out_requirement_digest, lane_requirement_digest_input, 'eip155:5042002',
      nonce_input, 'buyer', 'openarc.x402.lane-binding.v1', pay_to_address_input,
      valid_after_input, valid_before_input, v_chain.out_amount_atomic,
      '0x0077777d7EBA4688BDeF3E311b846F25870A19B9');
    IF v_digest IS DISTINCT FROM binding_digest_input THEN
      RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
    END IF;

    INSERT INTO openarc_durable.payment_attempts (
      organization_id, attempt_id, role, grant_id, action_id, reservation_id,
      subject_agent_id, commerce_session_id, seller_organization_id, provider_id,
      listing_id, listing_version, requirement_id, requirement_digest, source_kind,
      network_id, asset_address, verifying_contract, payer_address, pay_to_address,
      value_atomic, valid_after, valid_before, nonce, lane_requirement_digest,
      binding_digest, state, persisted_at
    ) VALUES (
      v_org, attempt_id_input, 'buyer', grant_id_input, v_ref.action_id,
      v_chain.out_reservation_id, v_chain.out_subject_agent_id, v_chain.out_commerce_session_id,
      v_chain.out_seller_organization_id, v_chain.out_provider_id, v_chain.out_listing_id,
      v_chain.out_listing_version, v_chain.out_requirement_id, v_chain.out_requirement_digest,
      v_chain.out_source_kind, 'eip155:5042002', '0x3600000000000000000000000000000000000000',
      '0x0077777d7EBA4688BDeF3E311b846F25870A19B9', payer_address_input, pay_to_address_input,
      v_chain.out_amount_atomic, valid_after_input, valid_before_input, nonce_input,
      lane_requirement_digest_input, v_digest, 'persisted', v_now
    );

    -- Current seller authority after every durable write and all lock waits.
    PERFORM openarc_durable.lock_action_listing(
      v_chain.out_seller_organization_id, v_chain.out_provider_id,
      v_chain.out_listing_id, v_chain.out_listing_version);
  END IF;

  SELECT p.* INTO v_attempt FROM openarc_durable.payment_attempts p
   WHERE p.organization_id = v_org AND p.grant_id = grant_id_input;
  out_replayed := v_replayed;
  out_organization_id := v_attempt.organization_id;
  out_attempt_id := v_attempt.attempt_id;
  out_grant_id := v_attempt.grant_id;
  out_action_id := v_attempt.action_id;
  out_provider_id := v_attempt.provider_id;
  out_listing_id := v_attempt.listing_id;
  out_listing_version := v_attempt.listing_version;
  out_requirement_id := v_attempt.requirement_id;
  out_requirement_digest := v_attempt.requirement_digest;
  out_network_id := v_attempt.network_id;
  out_asset_address := v_attempt.asset_address;
  out_verifying_contract := v_attempt.verifying_contract;
  out_payer_address := v_attempt.payer_address;
  out_pay_to_address := v_attempt.pay_to_address;
  out_value_atomic := v_attempt.value_atomic;
  out_valid_after := v_attempt.valid_after;
  out_valid_before := v_attempt.valid_before;
  out_nonce := v_attempt.nonce;
  out_lane_requirement_digest := v_attempt.lane_requirement_digest;
  out_binding_digest := v_attempt.binding_digest;
  out_state := v_attempt.state;
  out_persisted_at := v_attempt.persisted_at;
  out_dispatched_at := v_attempt.dispatched_at;
  out_observed_at := v_attempt.observed_at;
  out_transfer_id := v_attempt.transfer_id;
  out_gateway_status := v_attempt.gateway_status;
  out_batch_tx_hash := v_attempt.batch_tx_hash;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Buyer dispatch record. Written and COMMITTED before the process may send.
-- It moves persisted -> unknown exactly once. A second call, in any state, is
-- refused (P0D14) and never returns success, so a retry can never cause a
-- second send and an unknown attempt is never retried. It requires the grant
-- to still be issued, unclaimed, unrevoked and unexpired and the signature to
-- keep at least the 7-day floor. Same lock order as persistence.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.record_payment_attempt_dispatch(
  commerce_token_hash text,
  attempt_id_input uuid,
  binding_digest_input text
) RETURNS TABLE(
  out_organization_id text,
  out_attempt_id uuid,
  out_grant_id text,
  out_action_id text,
  out_provider_id text,
  out_listing_id text,
  out_listing_version text,
  out_requirement_id text,
  out_requirement_digest text,
  out_network_id text,
  out_asset_address text,
  out_verifying_contract text,
  out_payer_address text,
  out_pay_to_address text,
  out_value_atomic text,
  out_valid_after text,
  out_valid_before text,
  out_nonce text,
  out_lane_requirement_digest text,
  out_binding_digest text,
  out_state text,
  out_persisted_at timestamptz,
  out_dispatched_at timestamptz,
  out_observed_at timestamptz,
  out_transfer_id uuid,
  out_gateway_status text,
  out_batch_tx_hash text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_ctx record;
  v_ref record;
  v_chain record;
  v_grant record;
  v_attempt record;
  v_org text;
  v_now timestamptz;
BEGIN
  IF NOT openarc_durable.is_canonical_hex64(commerce_token_hash) THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;
  IF attempt_id_input IS NULL OR NOT openarc_durable.is_canonical_uuid_v4(attempt_id_input::text)
     OR NOT openarc_durable.is_canonical_sha256_digest(binding_digest_input) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO v_ctx
    FROM openarc_durable.resolve_commerce_action_context(commerce_token_hash) AS c;
  IF v_ctx.out_organization_id IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  v_org := v_ctx.out_organization_id;
  SELECT p.grant_id, p.action_id INTO v_ref FROM openarc_durable.payment_attempts p
   WHERE p.organization_id = v_org AND p.attempt_id = attempt_id_input;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;

  SELECT * INTO v_chain
    FROM openarc_durable.lock_grant_commerce_chain(commerce_token_hash, v_ref.action_id) AS c;
  IF v_chain.out_organization_id IS DISTINCT FROM v_org THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  IF v_chain.out_source_kind IS DISTINCT FROM 'verified_listing' THEN
    RAISE EXCEPTION 'commerce_requirement_unavailable' USING ERRCODE = 'P0D10';
  END IF;
  SELECT g.* INTO v_grant FROM openarc_durable.authorization_grants g
   WHERE g.organization_id = v_org AND g.grant_id = v_ref.grant_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  SELECT p.* INTO v_attempt FROM openarc_durable.payment_attempts p
   WHERE p.organization_id = v_org AND p.attempt_id = attempt_id_input FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  IF v_attempt.binding_digest IS DISTINCT FROM binding_digest_input THEN
    RAISE EXCEPTION 'payment_attempt_conflict' USING ERRCODE = 'P0D14';
  END IF;
  IF v_attempt.state <> 'persisted' OR v_attempt.dispatched_at IS NOT NULL THEN
    RAISE EXCEPTION 'payment_attempt_already_dispatched' USING ERRCODE = 'P0D14';
  END IF;

  SELECT clock_timestamp() INTO v_now;
  IF v_grant.status <> 'issued' OR v_grant.claimed_at IS NOT NULL OR v_grant.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'commerce_grant_conflict' USING ERRCODE = 'P0D14';
  END IF;
  IF NOT (v_grant.expires_at > v_now) OR NOT (v_chain.out_chain_expires_at > v_now) THEN
    RAISE EXCEPTION 'commerce_grant_expired' USING ERRCODE = 'P0D15';
  END IF;
  IF v_chain.out_action_status <> 'grant_issued' OR v_chain.out_reservation_status <> 'held' THEN
    RAISE EXCEPTION 'commerce_grant_conflict' USING ERRCODE = 'P0D14';
  END IF;
  IF v_attempt.valid_before::numeric - floor(extract(epoch FROM v_now)) < 604800 THEN
    RAISE EXCEPTION 'commerce_grant_expired' USING ERRCODE = 'P0D15';
  END IF;

  UPDATE openarc_durable.payment_attempts p
     SET state = 'unknown', dispatched_at = v_now
   WHERE p.organization_id = v_org AND p.attempt_id = attempt_id_input;

  PERFORM openarc_durable.lock_action_listing(
    v_chain.out_seller_organization_id, v_chain.out_provider_id,
    v_chain.out_listing_id, v_chain.out_listing_version);

  SELECT p.* INTO v_attempt FROM openarc_durable.payment_attempts p
   WHERE p.organization_id = v_org AND p.attempt_id = attempt_id_input;
  out_organization_id := v_attempt.organization_id;
  out_attempt_id := v_attempt.attempt_id;
  out_grant_id := v_attempt.grant_id;
  out_action_id := v_attempt.action_id;
  out_provider_id := v_attempt.provider_id;
  out_listing_id := v_attempt.listing_id;
  out_listing_version := v_attempt.listing_version;
  out_requirement_id := v_attempt.requirement_id;
  out_requirement_digest := v_attempt.requirement_digest;
  out_network_id := v_attempt.network_id;
  out_asset_address := v_attempt.asset_address;
  out_verifying_contract := v_attempt.verifying_contract;
  out_payer_address := v_attempt.payer_address;
  out_pay_to_address := v_attempt.pay_to_address;
  out_value_atomic := v_attempt.value_atomic;
  out_valid_after := v_attempt.valid_after;
  out_valid_before := v_attempt.valid_before;
  out_nonce := v_attempt.nonce;
  out_lane_requirement_digest := v_attempt.lane_requirement_digest;
  out_binding_digest := v_attempt.binding_digest;
  out_state := v_attempt.state;
  out_persisted_at := v_attempt.persisted_at;
  out_dispatched_at := v_attempt.dispatched_at;
  out_observed_at := v_attempt.observed_at;
  out_transfer_id := v_attempt.transfer_id;
  out_gateway_status := v_attempt.gateway_status;
  out_batch_tx_hash := v_attempt.batch_tx_hash;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Migrator-private post-dispatch observation. Records ONLY a positive
-- observation (pending or committed); an unknown classification is not
-- written because unknown is already the held state. The principal that may
-- record late observations (after the buyer chain has expired) is not settled
-- by the accepted contracts, so this is not granted to any runtime role.
-- Lock order (a suffix of the frozen order): buyer+seller organizations sorted,
-- exposure row, action, reservation, grant, attempt.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.record_payment_attempt_observation(
  organization_id text,
  attempt_id_input uuid,
  observed_state text,
  transfer_id_input uuid,
  gateway_status_input text,
  batch_tx_hash_input text
) RETURNS TABLE(
  out_organization_id text,
  out_attempt_id uuid,
  out_state text,
  out_dispatched_at timestamptz,
  out_observed_at timestamptz,
  out_transfer_id uuid,
  out_gateway_status text,
  out_batch_tx_hash text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_ref record;
  v_attempt record;
  v_now timestamptz;
BEGIN
  IF NOT openarc_durable.is_canonical_org_id(organization_id)
     OR attempt_id_input IS NULL OR NOT openarc_durable.is_canonical_uuid_v4(attempt_id_input::text)
     OR transfer_id_input IS NULL
     OR observed_state IS NULL OR observed_state NOT IN ('pending', 'committed')
     OR (observed_state = 'pending' AND (gateway_status_input IS NULL
         OR gateway_status_input NOT IN ('received', 'batched', 'confirmed')))
     OR (observed_state = 'committed' AND gateway_status_input IS DISTINCT FROM 'completed')
     OR (observed_state = 'committed' AND batch_tx_hash_input IS NULL)
     OR (batch_tx_hash_input IS NOT NULL AND batch_tx_hash_input !~ '^0x[0-9a-f]{64}$') THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  SELECT p.* INTO v_ref FROM openarc_durable.payment_attempts p
   WHERE p.organization_id = organization_id AND p.attempt_id = attempt_id_input;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_not_found' USING ERRCODE = '23503';
  END IF;
  PERFORM 1 FROM openarc_tenant.organizations o
   WHERE o.organization_id IN (v_ref.organization_id, v_ref.seller_organization_id)
   ORDER BY o.organization_id FOR UPDATE;
  PERFORM 1 FROM openarc_durable.commerce_exposure_locks e
   WHERE e.organization_id = v_ref.organization_id AND e.subject_agent_id = v_ref.subject_agent_id
     AND e.network_id = 'eip155:5042002' AND e.asset = 'USDC'
     AND e.representation = 'erc20' AND e.decimals = 6
   FOR UPDATE;
  PERFORM 1 FROM openarc_durable.commerce_actions a
   WHERE a.organization_id = v_ref.organization_id AND a.action_id = v_ref.action_id FOR UPDATE;
  PERFORM 1 FROM openarc_durable.budget_reservations b
   WHERE b.organization_id = v_ref.organization_id AND b.reservation_id = v_ref.reservation_id
   FOR UPDATE;
  PERFORM 1 FROM openarc_durable.authorization_grants g
   WHERE g.organization_id = v_ref.organization_id AND g.grant_id = v_ref.grant_id FOR UPDATE;
  SELECT p.* INTO v_attempt FROM openarc_durable.payment_attempts p
   WHERE p.organization_id = organization_id AND p.attempt_id = attempt_id_input FOR UPDATE;

  IF v_attempt.state = 'persisted' OR v_attempt.state = 'committed' THEN
    RAISE EXCEPTION 'payment_attempt_state_conflict' USING ERRCODE = 'P0D14';
  END IF;
  IF v_attempt.transfer_id IS NOT NULL AND v_attempt.transfer_id <> transfer_id_input THEN
    RAISE EXCEPTION 'payment_attempt_state_conflict' USING ERRCODE = 'P0D14';
  END IF;
  SELECT clock_timestamp() INTO v_now;
  BEGIN
    UPDATE openarc_durable.payment_attempts p
       SET state = observed_state,
           observed_at = v_now,
           transfer_id = transfer_id_input,
           gateway_status = gateway_status_input,
           batch_tx_hash = COALESCE(batch_tx_hash_input, p.batch_tx_hash)
     WHERE p.organization_id = organization_id AND p.attempt_id = attempt_id_input;
  EXCEPTION WHEN check_violation OR insufficient_privilege THEN
    RAISE EXCEPTION 'payment_attempt_state_conflict' USING ERRCODE = 'P0D14';
  END;

  SELECT p.* INTO v_attempt FROM openarc_durable.payment_attempts p
   WHERE p.organization_id = organization_id AND p.attempt_id = attempt_id_input;
  out_organization_id := v_attempt.organization_id;
  out_attempt_id := v_attempt.attempt_id;
  out_state := v_attempt.state;
  out_dispatched_at := v_attempt.dispatched_at;
  out_observed_at := v_attempt.observed_at;
  out_transfer_id := v_attempt.transfer_id;
  out_gateway_status := v_attempt.gateway_status;
  out_batch_tx_hash := v_attempt.batch_tx_hash;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Agent attempt projection (restart recovery). Scoped to the DB-derived buyer
-- organization AND the presenting subject agent: an attempt of another
-- organization or another agent returns no row, exactly like a missing one.
-- The current commerce authority is asserted before AND after the read,
-- including the not-found path. STABLE: PostgreSQL forbids it from writing.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.read_agent_payment_attempt(
  commerce_token_hash text,
  attempt_id_input uuid
) RETURNS TABLE(
  out_organization_id text,
  out_attempt_id uuid,
  out_grant_id text,
  out_action_id text,
  out_provider_id text,
  out_listing_id text,
  out_listing_version text,
  out_requirement_id text,
  out_requirement_digest text,
  out_network_id text,
  out_asset_address text,
  out_verifying_contract text,
  out_payer_address text,
  out_pay_to_address text,
  out_value_atomic text,
  out_valid_after text,
  out_valid_before text,
  out_nonce text,
  out_lane_requirement_digest text,
  out_binding_digest text,
  out_state text,
  out_persisted_at timestamptz,
  out_dispatched_at timestamptz,
  out_observed_at timestamptz,
  out_transfer_id uuid,
  out_gateway_status text,
  out_batch_tx_hash text
)
LANGUAGE plpgsql STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_chain record;
  v_attempt record;
  v_found boolean := false;
BEGIN
  IF NOT openarc_durable.is_canonical_hex64(commerce_token_hash) THEN
    RAISE EXCEPTION 'commerce_session_invalid' USING ERRCODE = '28000';
  END IF;
  IF attempt_id_input IS NULL OR NOT openarc_durable.is_canonical_uuid_v4(attempt_id_input::text) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO v_chain
    FROM openarc_durable.lock_action_commerce(commerce_token_hash, NULL) AS c;
  IF v_chain.out_organization_id IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  PERFORM openarc_durable.lock_action_commerce_state(
    commerce_token_hash, v_chain.out_organization_id);
  SELECT p.* INTO v_attempt FROM openarc_durable.payment_attempts p
   WHERE p.organization_id = v_chain.out_organization_id
     AND p.attempt_id = attempt_id_input
     AND p.subject_agent_id = v_chain.out_subject_agent_id;
  v_found := FOUND;
  PERFORM openarc_durable.lock_action_commerce_state(
    commerce_token_hash, v_chain.out_organization_id);
  IF NOT v_found THEN RETURN; END IF;
  out_organization_id := v_attempt.organization_id;
  out_attempt_id := v_attempt.attempt_id;
  out_grant_id := v_attempt.grant_id;
  out_action_id := v_attempt.action_id;
  out_provider_id := v_attempt.provider_id;
  out_listing_id := v_attempt.listing_id;
  out_listing_version := v_attempt.listing_version;
  out_requirement_id := v_attempt.requirement_id;
  out_requirement_digest := v_attempt.requirement_digest;
  out_network_id := v_attempt.network_id;
  out_asset_address := v_attempt.asset_address;
  out_verifying_contract := v_attempt.verifying_contract;
  out_payer_address := v_attempt.payer_address;
  out_pay_to_address := v_attempt.pay_to_address;
  out_value_atomic := v_attempt.value_atomic;
  out_valid_after := v_attempt.valid_after;
  out_valid_before := v_attempt.valid_before;
  out_nonce := v_attempt.nonce;
  out_lane_requirement_digest := v_attempt.lane_requirement_digest;
  out_binding_digest := v_attempt.binding_digest;
  out_state := v_attempt.state;
  out_persisted_at := v_attempt.persisted_at;
  out_dispatched_at := v_attempt.dispatched_at;
  out_observed_at := v_attempt.observed_at;
  out_transfer_id := v_attempt.transfer_id;
  out_gateway_status := v_attempt.gateway_status;
  out_batch_tx_hash := v_attempt.batch_tx_hash;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Least privilege. PUBLIC receives nothing anywhere. Only the three bounded
-- agent attempt entry points, the runtime requirement registrar and the seller
-- payment-terms writer are executable by the restricted tenant runtime; the
-- verified requirement registration core, the observation recorder, the digest
-- helpers and every trigger function stay migrator-private. The redefined
-- revoke keeps its accepted schema12 grants.
-- ---------------------------------------------------------------------------
REVOKE ALL ON FUNCTION openarc_durable.verified_requirement_digest(text, text, text, text, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_tenant.reject_listing_payment_terms_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.commit_listing_payment_terms(
  text, text, text, text, text, uuid, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.register_verified_commerce_requirement(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.enforce_verified_requirement_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.register_verified_commerce_requirement_core(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.payment_attempt_binding_digest(
  text, text, text, text, text, text, text, text, text, text, text, text, text, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.enforce_payment_attempt_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.enforce_reservation_payment_exposure() FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.enforce_action_payment_exposure() FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.enforce_claim_payment_attempt() FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.persist_payment_attempt(
  text, text, uuid, text, text, text, text, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.record_payment_attempt_dispatch(text, uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.record_payment_attempt_observation(
  text, uuid, text, uuid, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.read_agent_payment_attempt(text, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.revoke_authorization_grant(
  text, text, text, uuid, text, text, text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION openarc_durable.persist_payment_attempt(
  text, text, uuid, text, text, text, text, text, text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.record_payment_attempt_dispatch(text, uuid, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.read_agent_payment_attempt(text, uuid) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.commit_listing_payment_terms(
  text, text, text, text, text, uuid, text, text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.register_verified_commerce_requirement(text, text, text) TO openarc_tenant_app;
