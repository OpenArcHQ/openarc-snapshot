-- OpenArc operator control-room READS (schema18).
-- Additive over schema17. Owner: openarc_migrator. Runtime: openarc_tenant_app.
--
-- This migration is READS ONLY. It creates NO table, NO column, NO constraint,
-- NO trigger, NO policy, NO role, NO index and NO outbox event type. It alters
-- no existing function body, no existing constraint and no existing trigger; it
-- never writes a row, never records durability or outbox evidence, never issues
-- or claims a grant, never releases, cancels or advances any state and never
-- moves funds. Every helper below is a SECURITY DEFINER STABLE projection over
-- frozen schema10/12/15 tables behind the schema11 human reader authority
-- (openarc_durable.resolve_action_reader_org -> lock_action_reader ->
-- lock_action_human: live non-recovery session, current ACTIVE owner/operator
-- membership), re-asserted AFTER the projection on EVERY path including the
-- not-found path, the empty page and the completeness-bound overflow, exactly
-- as the schema16 readers do.
--
-- The caller-supplied organization is only a lookup argument. Every projection
-- filters on the DB-DERIVED organization returned by the resolver, so another
-- organization's reservations, attempts and grants are indistinguishable from
-- missing: they simply never match.
--
-- Amounts are projected as EXACT integer text. No amount is ever divided, is
-- ever rounded and never passes through a floating-point type, and no column
-- below is a sum that folds one bucket into another.

-- ---------------------------------------------------------------------------
-- 1. Four-bucket exposure read.
--
-- The schema10 exposure read (read_commerce_exposure) and the schema10
-- authorize-path aggregate (assess_action_budget) both collapse
-- status IN ('held','claimed','unknown') into ONE `unresolved` numeric inside
-- PL/pgSQL, so no caller above the database can separate unknown money from
-- money that is merely outstanding. This read keeps the SAME accounting
-- sources and the SAME rolling window as the schema10 reader but projects the
-- four buckets separately:
--
--   out_held_atomic      budget_reservations.status = 'held'
--   out_claimed_atomic   budget_reservations.status = 'claimed'
--   out_unknown_atomic   budget_reservations.status = 'unknown'
--   out_committed_atomic budget_events.event_kind = 'committed', in window
--
-- No total, no available amount and no deficit is returned: an operator column
-- that folds `unknown` into anything is exactly the defect this read exists to
-- remove, and the caller must decide how to treat unknown money.
--
-- The fail-closed completeness bound of the schema10 exposure read is mirrored
-- EXACTLY: each accounting source is scanned under LIMIT 4097 and a count
-- above 4096 raises `commerce_exposure_unavailable` (P0D11) instead of
-- returning a partial sum. The bound is raised only AFTER the current
-- authority has been re-asserted, matching the schema16 ordering.
--
-- An unknown, inactive, foreign or non-matching policy under a valid current
-- authority is a safe not-found sentinel row, never an error that distinguishes
-- "absent" from "another organization's".
--
-- Unlike the schema10 spend-facing reader, an EXPIRED policy window is not an
-- error here. Expiry stops new spend; it does not retire money that is already
-- held, claimed, unknown or committed, and an operator chasing that money must
-- still be able to see it. The policy expiry is projected as its own column so
-- the caller can label the window rather than losing the buckets.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.read_commerce_exposure_buckets(
  human_session_hash text,
  organization_id text,
  subject_agent_id_input text,
  policy_id_input text
) RETURNS TABLE(
  out_organization_id text,
  out_found boolean,
  out_subject_agent_id text,
  out_policy_id text,
  out_policy_revision text,
  out_network_id text,
  out_asset text,
  out_representation text,
  out_decimals smallint,
  out_window_seconds text,
  out_held_atomic text,
  out_claimed_atomic text,
  out_unknown_atomic text,
  out_committed_atomic text,
  out_policy_expires_at timestamptz,
  out_as_of timestamptz
)
LANGUAGE plpgsql STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_org text;
  v_policy record;
  v_found boolean := false;
  v_now timestamptz;
  v_cutoff timestamptz;
  v_committed_count integer := 0;
  v_unresolved_count integer := 0;
  v_committed numeric := 0;
  v_held numeric := 0;
  v_claimed numeric := 0;
  v_unknown numeric := 0;
  v_overflow boolean := false;
BEGIN
  IF NOT openarc_durable.is_canonical_org_id(organization_id)
     OR NOT openarc_durable.is_canonical_agent_id(subject_agent_id_input)
     OR NOT openarc_durable.is_canonical_policy_id(policy_id_input) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  v_org := openarc_durable.resolve_action_reader_org(human_session_hash, organization_id);
  SELECT clock_timestamp() INTO v_now;
  -- The SAME current active policy selection the schema10 reader uses: the
  -- active root's current revision for this exact subject agent.
  SELECT v.* INTO v_policy
    FROM openarc_tenant.budget_policy_roots r
    JOIN openarc_tenant.budget_policy_versions v
      ON v.organization_id = r.organization_id AND v.policy_id = r.policy_id
     AND v.revision = r.current_revision
   WHERE r.organization_id = v_org AND r.policy_id = policy_id_input
     AND r.status = 'active' AND r.subject_agent_id = subject_agent_id_input;
  v_found := FOUND;
  IF v_found THEN
    v_cutoff := v_now - make_interval(secs => COALESCE(v_policy.rolling_window_seconds::integer, 0));
    -- Committed source, identical predicate and identical 4097 row bound to
    -- the schema10 exposure read.
    SELECT count(*)::int, COALESCE(sum(e.amount_atomic::numeric), 0)
      INTO v_committed_count, v_committed
      FROM (SELECT b.amount_atomic FROM openarc_durable.budget_events b
             WHERE b.organization_id = v_org AND b.subject_agent_id = subject_agent_id_input
               AND b.network_id = v_policy.network_id AND b.asset = v_policy.asset
               AND b.representation = v_policy.representation AND b.decimals = v_policy.decimals
               AND b.event_kind = 'committed' AND b.event_time <= v_now
               AND (v_policy.rolling_limit IS NULL OR b.event_time > v_cutoff)
             LIMIT 4097) AS e;
    -- Reservation source, identical predicate and identical 4097 row bound to
    -- the schema10 exposure read, but split into its three buckets instead of
    -- summed into one `unresolved` numeric.
    SELECT count(*)::int,
           COALESCE(sum(e.debit_atomic::numeric) FILTER (WHERE e.status = 'held'), 0),
           COALESCE(sum(e.debit_atomic::numeric) FILTER (WHERE e.status = 'claimed'), 0),
           COALESCE(sum(e.debit_atomic::numeric) FILTER (WHERE e.status = 'unknown'), 0)
      INTO v_unresolved_count, v_held, v_claimed, v_unknown
      FROM (SELECT r.status, r.debit_atomic FROM openarc_durable.budget_reservations r
             WHERE r.organization_id = v_org AND r.subject_agent_id = subject_agent_id_input
               AND r.network_id = v_policy.network_id AND r.asset = v_policy.asset
               AND r.representation = v_policy.representation AND r.decimals = v_policy.decimals
               AND r.status IN ('held', 'claimed', 'unknown')
             LIMIT 4097) AS e;
    v_overflow := v_committed_count > 4096 OR v_unresolved_count > 4096;
    IF NOT v_overflow
       AND (v_committed >= 10::numeric ^ 128 OR v_held >= 10::numeric ^ 128
            OR v_claimed >= 10::numeric ^ 128 OR v_unknown >= 10::numeric ^ 128) THEN
      RAISE EXCEPTION 'commerce_arithmetic_overflow' USING ERRCODE = '22003';
    END IF;
  END IF;
  -- Revalidate the SAME current authority after the projection on EVERY path,
  -- including not-found and the completeness overflow, before anything is
  -- returned or reported.
  PERFORM 1 WHERE openarc_durable.resolve_action_reader_org(
    human_session_hash, organization_id) = v_org;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;
  IF v_overflow THEN
    RAISE EXCEPTION 'commerce_exposure_unavailable' USING ERRCODE = 'P0D11';
  END IF;
  out_organization_id := v_org;
  out_as_of := v_now;
  IF NOT v_found THEN
    out_found := false;
    RETURN NEXT;
    RETURN;
  END IF;
  out_found := true;
  out_subject_agent_id := subject_agent_id_input;
  out_policy_id := policy_id_input;
  out_policy_revision := v_policy.revision;
  out_network_id := v_policy.network_id;
  out_asset := v_policy.asset;
  out_representation := v_policy.representation;
  out_decimals := v_policy.decimals;
  out_window_seconds := v_policy.rolling_window_seconds;
  out_held_atomic := v_held::text;
  out_claimed_atomic := v_claimed::text;
  out_unknown_atomic := v_unknown::text;
  out_committed_atomic := v_committed::text;
  out_policy_expires_at := v_policy.expires_at;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- 2. Bounded stuck/unknown operator queue for ONE organization.
--
-- There is no organization-wide reader over budget_reservations anywhere in
-- schema10..schema17: every reference is an internal `SELECT ... INTO` inside a
-- mutation. This is that reader, restricted to the entries an operator must
-- chase, across the three frozen sources:
--
--   budget_reservation   status = 'unknown'
--   payment_attempt      state IN ('unknown','pending') AND dispatched at or
--                        before (now - attempt_max_age_seconds)
--   authorization_grant  status = 'issued' AND never claimed AND expiring at
--                        or before (now + grant_expiry_window_seconds)
--
-- Both windows are caller-supplied and hard-bounded to 0..2592000 seconds. The
-- boundary is INCLUSIVE on both sides: an attempt dispatched exactly
-- attempt_max_age_seconds ago is in the queue, and a grant expiring exactly
-- grant_expiry_window_seconds from now is in the queue.
--
-- Ordering is the deterministic total order (kind ASC, entry_id ASC) and the
-- cursor is the exclusive keyset lower bound on that exact pair; both cursor
-- components are presented together or neither is. `limit_count` is the hard
-- page size 1..50 and at most limit_count + 1 rows are returned so the
-- repository can detect a further page without a count, an offset or a second
-- query. An authorized empty page is exactly one sentinel row.
--
-- Amounts are the exact integer strings already stored: the reservation debit,
-- the attempt value, and for a grant the debit of its bound action.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.list_operator_stuck_queue(
  human_session_hash text,
  organization_id text,
  attempt_max_age_seconds integer,
  grant_expiry_window_seconds integer,
  after_kind text,
  after_entry_id text,
  limit_count integer
) RETURNS TABLE(
  out_organization_id text,
  out_found boolean,
  out_kind text,
  out_entry_id text,
  out_status text,
  out_subject_agent_id text,
  out_action_id text,
  out_amount_atomic text,
  out_started_at timestamptz,
  out_expires_at timestamptz,
  out_as_of timestamptz
)
LANGUAGE plpgsql STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_org text;
  v_now timestamptz;
BEGIN
  IF NOT openarc_durable.is_canonical_org_id(organization_id) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF attempt_max_age_seconds IS NULL
     OR attempt_max_age_seconds < 0 OR attempt_max_age_seconds > 2592000
     OR grant_expiry_window_seconds IS NULL
     OR grant_expiry_window_seconds < 0 OR grant_expiry_window_seconds > 2592000 THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF (after_kind IS NULL) <> (after_entry_id IS NULL) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF after_kind IS NOT NULL THEN
    IF after_kind NOT IN ('authorization_grant', 'budget_reservation', 'payment_attempt') THEN
      RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
    END IF;
    IF NOT (
      (after_kind = 'authorization_grant'
        AND openarc_durable.is_canonical_grant_id(after_entry_id))
      OR (after_kind = 'budget_reservation'
        AND openarc_durable.is_canonical_reservation_id(after_entry_id))
      OR (after_kind = 'payment_attempt'
        AND openarc_durable.is_canonical_uuid_v4(after_entry_id))
    ) THEN
      RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
    END IF;
  END IF;
  IF limit_count IS NULL OR limit_count < 1 OR limit_count > 50 THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  v_org := openarc_durable.resolve_action_reader_org(human_session_hash, organization_id);
  SELECT clock_timestamp() INTO v_now;
  RETURN QUERY
    WITH entries AS (
      SELECT 'authorization_grant'::text AS kind, g.grant_id AS entry_id, g.status AS status,
             g.subject_agent_id AS subject_agent_id, g.action_id AS action_id,
             a.debit_atomic AS amount_atomic, g.issued_at AS started_at,
             g.expires_at AS expires_at
        FROM openarc_durable.authorization_grants g
        JOIN openarc_durable.commerce_actions a
          ON a.organization_id = g.organization_id AND a.action_id = g.action_id
       WHERE g.organization_id = v_org
         AND g.status = 'issued'
         AND g.claimed_at IS NULL
         AND g.expires_at <= v_now + make_interval(secs => grant_expiry_window_seconds)
      UNION ALL
      SELECT 'budget_reservation'::text, r.reservation_id, r.status,
             r.subject_agent_id, r.action_id, r.debit_atomic, r.claimed_at,
             NULL::timestamptz
        FROM openarc_durable.budget_reservations r
       WHERE r.organization_id = v_org
         AND r.status = 'unknown'
      UNION ALL
      SELECT 'payment_attempt'::text, p.attempt_id::text, p.state,
             p.subject_agent_id, p.action_id, p.value_atomic, p.dispatched_at,
             NULL::timestamptz
        FROM openarc_durable.payment_attempts p
       WHERE p.organization_id = v_org
         AND p.state IN ('unknown', 'pending')
         AND p.dispatched_at <= v_now - make_interval(secs => attempt_max_age_seconds)
    )
    SELECT v_org, true, e.kind, e.entry_id, e.status, e.subject_agent_id, e.action_id,
           e.amount_atomic, e.started_at, e.expires_at, v_now
      FROM entries e
     WHERE after_kind IS NULL
        OR (e.kind, e.entry_id) > (after_kind, after_entry_id)
     ORDER BY e.kind ASC, e.entry_id ASC
     LIMIT limit_count + 1;
  IF NOT FOUND THEN
    RETURN QUERY
      SELECT v_org, false, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text,
             NULL::text, NULL::timestamptz, NULL::timestamptz, v_now;
  END IF;
  PERFORM 1 WHERE openarc_durable.resolve_action_reader_org(
    human_session_hash, organization_id) = v_org;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- 3. Organization-wide authorization grant page.
--
-- schema12 exposes read_authorization_grant by grant id ONLY, so a control room
-- cannot enumerate the grants of the organization it already administers. This
-- is the missing page: the SAME projection and the SAME frozen derived status
-- priority (revoked -> claimed -> expired by DB clock -> issued) as the schema12
-- single-grant reader, keyset-paged over the lexical grant id with a hard
-- page cap of 50 and a strictly ascending deterministic order. No token hash,
-- generation secret or provider-session material is representable here, and no
-- status is filtered: every schema12 status is visible to the authorized
-- reader. An authorized empty page is exactly one sentinel row.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.list_authorization_grants(
  human_session_hash text,
  organization_id text,
  after_grant_id text,
  limit_count integer
) RETURNS TABLE(
  out_organization_id text,
  out_found boolean,
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
LANGUAGE plpgsql STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_org text;
  v_now timestamptz;
BEGIN
  IF NOT openarc_durable.is_canonical_org_id(organization_id) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF after_grant_id IS NOT NULL
     AND NOT openarc_durable.is_canonical_grant_id(after_grant_id) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF limit_count IS NULL OR limit_count < 1 OR limit_count > 50 THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  v_org := openarc_durable.resolve_action_reader_org(human_session_hash, organization_id);
  SELECT clock_timestamp() INTO v_now;
  RETURN QUERY
    SELECT v_org, true, g.grant_id, g.action_id, g.reservation_id, g.subject_agent_id,
           g.commerce_session_id, g.provider_id, g.listing_id, g.listing_version,
           g.current_generation,
           CASE
             WHEN g.status = 'revoked' THEN 'revoked'
             WHEN g.status = 'claimed' THEN 'claimed'
             WHEN g.expires_at <= v_now THEN 'expired'
             ELSE 'issued' END,
           g.issued_at, g.updated_at, g.expires_at, g.claimed_at, g.revoked_at
      FROM openarc_durable.authorization_grants g
     WHERE g.organization_id = v_org
       AND (after_grant_id IS NULL OR g.grant_id > after_grant_id)
     ORDER BY g.grant_id ASC
     LIMIT limit_count + 1;
  IF NOT FOUND THEN
    RETURN QUERY
      SELECT v_org, false, NULL::text, NULL::text, NULL::text, NULL::text, NULL::uuid,
             NULL::text, NULL::text, NULL::text, NULL::integer, NULL::text,
             NULL::timestamptz, NULL::timestamptz, NULL::timestamptz,
             NULL::timestamptz, NULL::timestamptz;
  END IF;
  PERFORM 1 WHERE openarc_durable.resolve_action_reader_org(
    human_session_hash, organization_id) = v_org;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- Least privilege. PUBLIC receives nothing. Only the three bounded operator
-- reads are executable by the restricted tenant runtime; the schema11
-- DB-derived authority resolver they call stays migrator-private exactly as it
-- already is. No table privilege, no role membership, no policy and no broad
-- grant is added anywhere, and no existing grant is widened.
-- ---------------------------------------------------------------------------
REVOKE ALL ON FUNCTION openarc_durable.read_commerce_exposure_buckets(text, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.list_operator_stuck_queue(text, text, integer, integer, text, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.list_authorization_grants(text, text, text, integer) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION openarc_durable.read_commerce_exposure_buckets(text, text, text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.list_operator_stuck_queue(text, text, integer, integer, text, text, integer) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.list_authorization_grants(text, text, text, integer) TO openarc_tenant_app;
