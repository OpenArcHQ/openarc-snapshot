-- OpenArc settlement observation lease surface (schema17).
-- Additive over schema16. Owner: openarc_migrator. Observation principal:
-- openarc_worker_app (pre-provisioned by deployment; this migration NEVER
-- creates roles or schemas). Migrations 0001-0016 are untouched.
--
-- This migration NEVER calls a provider, Circle, Gateway or Arc endpoint,
-- signs, moves funds, settles or delivers. It adds no outbox event type, so
-- the outbox claim projection and the tenant notification handlers are
-- unaffected.
--
-- WHY THE WORKER ROLE, AND ONLY THE WORKER ROLE
-- 0015 left openarc_durable.record_payment_attempt_observation granted to
-- nobody because the principal was unsettled. Batched settlement can land up
-- to ~7 days after dispatch (the lane's 604800s minimum authorization
-- validity), long after the buyer's commerce session, its handoff token and
-- its grant have expired. Every existing runtime entry point on this table
-- (persist_payment_attempt, record_payment_attempt_dispatch,
-- read_agent_payment_attempt) derives its organization from a live consumed
-- commerce token, so NO request-serving path can still be authenticated when
-- the observation arrives. openarc_tenant_app therefore cannot be the
-- recorder, and is deliberately granted nothing here. The worker role is the
-- only pre-provisioned principal that runs without a caller session, already
-- polls durable work under a lease (0003 claim/complete/fail_outbox_job), and
-- holds no table privilege anywhere in openarc_durable. So the recorder, the
-- claim surface and the lease acknowledgements are granted to
-- openarc_worker_app and to nothing else.
--
-- WHAT THE WORKER CAN AND CANNOT DO
--   * It can lease attempts that are in state 'unknown' or 'pending' only.
--     'persisted' (never dispatched) and 'committed' (terminal) are not
--     selectable by any code path below, so a leased attempt is always one
--     that was really dispatched and is not already consumed.
--   * It can record ONLY a positive observation, through the unchanged 0015
--     recorder: 'pending' or 'committed'. There is no release, failure,
--     refund, expiry or cancellation input anywhere in this migration, and an
--     unclear answer is simply never written -- 'unknown' is already the held
--     state.
--   * It holds NO privilege on openarc_durable.payment_attempts or on the new
--     lease table; it reaches both only through the definer functions below.

-- ---------------------------------------------------------------------------
-- Observation leases. One row per attempt, created on first claim. The lease
-- is a SEPARATE table on purpose: the frozen 0015 payment_attempts_mutation
-- trigger admits an UPDATE only when it is a legal LaneExposure state edge, so
-- lease bookkeeping cannot live on the attempt row without loosening that
-- trigger. Nothing here can change an attempt's state.
-- ---------------------------------------------------------------------------
CREATE TABLE openarc_durable.payment_attempt_observation_leases (
  organization_id text NOT NULL,
  attempt_id uuid NOT NULL,
  lease_generation bigint NOT NULL DEFAULT 0,
  lease_until timestamptz,
  attempt_count integer NOT NULL DEFAULT 0,
  first_claimed_at timestamptz NOT NULL,
  last_claimed_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id, attempt_id),
  CONSTRAINT payment_attempt_observation_leases_attempt_fk FOREIGN KEY (organization_id, attempt_id)
    REFERENCES openarc_durable.payment_attempts(organization_id, attempt_id) ON DELETE RESTRICT,
  CONSTRAINT payment_attempt_observation_leases_generation_valid CHECK (lease_generation >= 0),
  -- Bounded retries: an attempt the transport can never answer about is
  -- leased at most this many times, then stops being claimable. It is NOT
  -- failed, released or dead-lettered: it simply stays held in its current
  -- state, which is the only safe disposition.
  CONSTRAINT payment_attempt_observation_leases_attempts_valid CHECK (attempt_count BETWEEN 0 AND 10),
  CONSTRAINT payment_attempt_observation_leases_clock_valid CHECK (
    last_claimed_at >= first_claimed_at
    AND (lease_until IS NULL OR lease_until > first_claimed_at))
);

-- Oldest-dispatched-first claim support.
CREATE INDEX payment_attempts_observation_pending
  ON openarc_durable.payment_attempts (dispatched_at, attempt_id)
  WHERE state IN ('unknown', 'pending');

-- ---------------------------------------------------------------------------
-- Lease mutation rule: no delete, immutable identity, monotonic generation and
-- attempt count. A lease can never be rewound to re-open a bounded retry.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.enforce_observation_lease_mutation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'observation_lease_immutable' USING ERRCODE = '42501';
  END IF;
  IF TG_OP = 'INSERT' THEN
    RETURN NEW;
  END IF;
  IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
     OR NEW.attempt_id IS DISTINCT FROM OLD.attempt_id
     OR NEW.first_claimed_at IS DISTINCT FROM OLD.first_claimed_at THEN
    RAISE EXCEPTION 'observation_lease_immutable' USING ERRCODE = '42501';
  END IF;
  IF NEW.lease_generation < OLD.lease_generation
     OR NEW.attempt_count < OLD.attempt_count
     OR NEW.last_claimed_at < OLD.last_claimed_at THEN
    RAISE EXCEPTION 'observation_lease_immutable' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER payment_attempt_observation_leases_mutation
  BEFORE INSERT OR UPDATE OR DELETE ON openarc_durable.payment_attempt_observation_leases
  FOR EACH ROW EXECUTE FUNCTION openarc_durable.enforce_observation_lease_mutation();

-- ---------------------------------------------------------------------------
-- RLS: migrator-only. Runtime, worker, auth and PUBLIC receive no direct
-- privilege on the lease table, exactly like payment_attempts.
-- ---------------------------------------------------------------------------
ALTER TABLE openarc_durable.payment_attempt_observation_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE openarc_durable.payment_attempt_observation_leases FORCE ROW LEVEL SECURITY;
CREATE POLICY payment_attempt_observation_leases_migrator
  ON openarc_durable.payment_attempt_observation_leases
  FOR ALL TO openarc_migrator USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE openarc_durable.payment_attempt_observation_leases FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Bounded observation claim. Leases up to claim_limit attempts that still need
-- observation, oldest dispatch first, with SKIP LOCKED so two workers never
-- observe the same attempt concurrently and one locked row cannot block the
-- queue. The state predicate is the ONLY selection rule and admits exactly
-- 'unknown' and 'pending': a 'persisted' or 'committed' attempt is
-- unreachable through this function.
--
-- It returns the non-secret binding fields the caller needs to ask its
-- transport about the attempt and to classify the answer. No signature,
-- authorization payload, token, session hash or key material is representable
-- in the result: the attempt table holds none.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.claim_payment_attempt_observations(claim_limit integer)
RETURNS TABLE(
  out_organization_id text,
  out_attempt_id uuid,
  out_grant_id text,
  out_action_id text,
  out_requirement_digest text,
  out_lane_requirement_digest text,
  out_network_id text,
  out_asset_address text,
  out_verifying_contract text,
  out_payer_address text,
  out_pay_to_address text,
  out_value_atomic text,
  out_valid_after text,
  out_valid_before text,
  out_nonce text,
  out_state text,
  out_dispatched_at timestamptz,
  out_lease_generation bigint,
  out_lease_until timestamptz,
  out_attempt_count integer
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_now timestamptz;
  v_row record;
  v_lease record;
BEGIN
  IF claim_limit IS NULL OR claim_limit < 1 OR claim_limit > 25 THEN
    RAISE EXCEPTION 'observation_claim_limit_invalid' USING ERRCODE = '22023';
  END IF;
  v_now := clock_timestamp();

  FOR v_row IN
    SELECT p.organization_id AS org, p.attempt_id AS id
      FROM openarc_durable.payment_attempts p
      LEFT JOIN openarc_durable.payment_attempt_observation_leases l
        ON l.organization_id = p.organization_id AND l.attempt_id = p.attempt_id
     WHERE p.state IN ('unknown', 'pending')
       AND coalesce(l.attempt_count, 0) < 10
       AND (l.lease_until IS NULL OR l.lease_until < v_now)
     ORDER BY p.dispatched_at, p.attempt_id
     LIMIT claim_limit
     FOR UPDATE OF p SKIP LOCKED
  LOOP
    INSERT INTO openarc_durable.payment_attempt_observation_leases AS l (
      organization_id, attempt_id, lease_generation, lease_until, attempt_count,
      first_claimed_at, last_claimed_at
    ) VALUES (
      v_row.org, v_row.id, 1, v_now + interval '120 seconds', 1, v_now, v_now
    )
    ON CONFLICT (organization_id, attempt_id) DO UPDATE
       SET lease_generation = l.lease_generation + 1,
           lease_until = v_now + interval '120 seconds',
           attempt_count = l.attempt_count + 1,
           last_claimed_at = v_now
    RETURNING l.lease_generation, l.lease_until, l.attempt_count INTO v_lease;

    SELECT p.organization_id, p.attempt_id, p.grant_id, p.action_id, p.requirement_digest,
           p.lane_requirement_digest, p.network_id, p.asset_address, p.verifying_contract,
           p.payer_address, p.pay_to_address, p.value_atomic, p.valid_after, p.valid_before,
           p.nonce, p.state, p.dispatched_at
      INTO out_organization_id, out_attempt_id, out_grant_id, out_action_id, out_requirement_digest,
           out_lane_requirement_digest, out_network_id, out_asset_address, out_verifying_contract,
           out_payer_address, out_pay_to_address, out_value_atomic, out_valid_after, out_valid_before,
           out_nonce, out_state, out_dispatched_at
      FROM openarc_durable.payment_attempts p
     WHERE p.organization_id = v_row.org AND p.attempt_id = v_row.id;

    out_lease_generation := v_lease.lease_generation;
    out_lease_until := v_lease.lease_until;
    out_attempt_count := v_lease.attempt_count;
    RETURN NEXT;
  END LOOP;
END;
$$;

-- ---------------------------------------------------------------------------
-- Fenced positive observation. It proves the caller still holds the exact
-- unexpired lease generation it claimed, then delegates to the UNCHANGED 0015
-- recorder, which keeps its own frozen lock order and its own state rules.
-- observed_state is passed straight through, so the recorder's closed
-- ('pending' | 'committed') input set is the only thing this can ever write:
-- there is no release, failure, refund or expiry path here.
-- A stale, expired or missing lease records NOTHING and returns no row.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.record_leased_payment_attempt_observation(
  organization_id_input text,
  attempt_id_input uuid,
  lease_generation_input bigint,
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
DECLARE
  v_lease record;
  v_result record;
BEGIN
  IF organization_id_input IS NULL
     OR NOT openarc_durable.is_canonical_org_id(organization_id_input)
     OR attempt_id_input IS NULL
     OR NOT openarc_durable.is_canonical_uuid_v4(attempt_id_input::text)
     OR lease_generation_input IS NULL OR lease_generation_input < 1 THEN
    RAISE EXCEPTION 'observation_lease_invalid' USING ERRCODE = '22023';
  END IF;

  -- Lock the lease FIRST, then re-check the generation against a FRESH DB
  -- clock after acquisition, so a caller that was blocked until its lease
  -- expired cannot record a late observation under a reclaimed lease.
  SELECT l.lease_generation, l.lease_until INTO v_lease
    FROM openarc_durable.payment_attempt_observation_leases l
   WHERE l.organization_id = organization_id_input AND l.attempt_id = attempt_id_input
   FOR UPDATE;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  IF v_lease.lease_generation <> lease_generation_input
     OR v_lease.lease_until IS NULL
     OR v_lease.lease_until <= clock_timestamp() THEN
    RETURN;
  END IF;

  SELECT * INTO v_result
    FROM openarc_durable.record_payment_attempt_observation(
      organization_id_input, attempt_id_input, observed_state,
      transfer_id_input, gateway_status_input, batch_tx_hash_input) AS r;

  -- The observation is recorded: the lease is consumed so no second worker
  -- re-observes the same attempt on this generation.
  UPDATE openarc_durable.payment_attempt_observation_leases l
     SET lease_until = NULL
   WHERE l.organization_id = organization_id_input AND l.attempt_id = attempt_id_input;

  out_organization_id := v_result.out_organization_id;
  out_attempt_id := v_result.out_attempt_id;
  out_state := v_result.out_state;
  out_dispatched_at := v_result.out_dispatched_at;
  out_observed_at := v_result.out_observed_at;
  out_transfer_id := v_result.out_transfer_id;
  out_gateway_status := v_result.out_gateway_status;
  out_batch_tx_hash := v_result.out_batch_tx_hash;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Fenced lease release for an UNCLEAR answer. It writes nothing to the
-- attempt: the attempt keeps its exact current state and stays held. Releasing
-- only ends the lease early so the attempt becomes claimable again before the
-- 120s expiry; the retry ceiling recorded in attempt_count is NOT rewound, so
-- releases can never produce an unbounded retry loop. A stale or missing lease
-- is a safe false.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.release_payment_attempt_observation_lease(
  organization_id_input text,
  attempt_id_input uuid,
  lease_generation_input bigint
) RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_lease record;
BEGIN
  IF organization_id_input IS NULL
     OR NOT openarc_durable.is_canonical_org_id(organization_id_input)
     OR attempt_id_input IS NULL
     OR NOT openarc_durable.is_canonical_uuid_v4(attempt_id_input::text)
     OR lease_generation_input IS NULL OR lease_generation_input < 1 THEN
    RAISE EXCEPTION 'observation_lease_invalid' USING ERRCODE = '22023';
  END IF;
  SELECT l.lease_generation, l.lease_until INTO v_lease
    FROM openarc_durable.payment_attempt_observation_leases l
   WHERE l.organization_id = organization_id_input AND l.attempt_id = attempt_id_input
   FOR UPDATE;
  IF NOT FOUND THEN
    RETURN false;
  END IF;
  IF v_lease.lease_generation <> lease_generation_input OR v_lease.lease_until IS NULL THEN
    RETURN false;
  END IF;
  UPDATE openarc_durable.payment_attempt_observation_leases l
     SET lease_until = NULL
   WHERE l.organization_id = organization_id_input AND l.attempt_id = attempt_id_input;
  RETURN true;
END;
$$;

-- ---------------------------------------------------------------------------
-- Least privilege. PUBLIC receives nothing. openarc_tenant_app receives
-- nothing at all from this migration: no request-serving path may record a
-- settlement observation. The observation recorder and its two lease
-- acknowledgements are executable ONLY by openarc_worker_app, which still
-- holds no table privilege anywhere in openarc_durable.
-- ---------------------------------------------------------------------------
REVOKE ALL ON FUNCTION openarc_durable.enforce_observation_lease_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.claim_payment_attempt_observations(integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.record_leased_payment_attempt_observation(
  text, uuid, bigint, text, uuid, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.release_payment_attempt_observation_lease(
  text, uuid, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.record_payment_attempt_observation(
  text, uuid, text, uuid, text, text) FROM PUBLIC;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'openarc_worker_app') THEN
    RAISE EXCEPTION 'openarc_worker_app role is required before schema17'
      USING ERRCODE = '42704';
  END IF;
END;
$$;

GRANT EXECUTE ON FUNCTION openarc_durable.claim_payment_attempt_observations(integer)
  TO openarc_worker_app;
GRANT EXECUTE ON FUNCTION openarc_durable.record_leased_payment_attempt_observation(
  text, uuid, bigint, text, uuid, text, text) TO openarc_worker_app;
GRANT EXECUTE ON FUNCTION openarc_durable.release_payment_attempt_observation_lease(
  text, uuid, bigint) TO openarc_worker_app;
-- The 0015 recorder itself, unchanged in behaviour, now has exactly one
-- principal: the worker role.
GRANT EXECUTE ON FUNCTION openarc_durable.record_payment_attempt_observation(
  text, uuid, text, uuid, text, text) TO openarc_worker_app;
