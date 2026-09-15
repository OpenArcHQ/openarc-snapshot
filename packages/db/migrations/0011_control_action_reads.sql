-- OpenArc bounded commerce action/approval READ queues (schema11).
-- Additive over schema10. Owner: openarc_migrator. Runtime: openarc_tenant_app.
--
-- This migration is READS ONLY. It creates NO table, NO trigger, NO policy, NO
-- role and NO union tuple; it never writes a row, never records durability or
-- outbox evidence, never grants spend authority, never issues a grant and
-- never moves funds. Every helper below is a SECURITY DEFINER projection over
-- the schema10 commerce_actions / commerce_approvals tables with the exact
-- accepted current-human-authority preamble (openarc_durable.lock_action_reader
-- -> lock_action_human: live non-recovery session, current active owner/operator
-- membership) revalidated AFTER the projection, including the empty/not-found
-- path, exactly as the schema10 readers do.
--
-- Paging is a lexical keyset over the (organization_id, <id>) primary key. The
-- caller presents the exclusive lower bound and a bounded 1..50 page size; the
-- helper fetches page size + 1 rows so the repository can detect a further page
-- without a count, an offset or a second query. There is NO server-side status
-- filter: every schema10 status is visible to the authorized reader.
--
-- The projections deliberately omit seller-internal ownership
-- (seller_organization_id), raw provenance (source_kind) and private digests
-- (request_digest); no token hash, credential or session material is
-- representable in any output column.

-- ---------------------------------------------------------------------------
-- Current human reader authority that also yields the DB-DERIVED organization.
-- The caller-supplied organization is only a lookup argument: the returned
-- organization is the one read back from the active owner/operator membership
-- row that actually authorized the read, so a projection wrapper never echoes
-- an unauthenticated caller value. Takes no lock beyond the frozen
-- organizations -> memberships order already taken by lock_action_human.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.resolve_action_reader_org(
  session_hash text,
  organization_id text
) RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_actor text;
  v_org text;
BEGIN
  IF NOT openarc_durable.is_canonical_org_id(organization_id) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  SELECT l.out_actor INTO v_actor
    FROM openarc_durable.lock_action_reader(session_hash, organization_id) AS l;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  SELECT m.organization_id INTO v_org
    FROM openarc_tenant.memberships m
   WHERE m.organization_id = organization_id
     AND m.account_id = v_actor
     AND m.status = 'active'
     AND m.role IN ('owner', 'operator');
  IF v_org IS NULL THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '42501';
  END IF;
  RETURN v_org;
END;
$$;

-- ---------------------------------------------------------------------------
-- Bounded lexical keyset action page. `after_action_id` is an EXCLUSIVE lower
-- bound (NULL starts at the first id); `limit_count` is the bounded accepted
-- page size 1..50 and the helper returns at most limit_count + 1 rows in
-- strictly ascending action id order so the repository can detect a further
-- page. An authorized empty page returns exactly one row carrying the
-- DB-derived organization with out_found = false and NULL projection columns.
-- No status is filtered.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.list_commerce_actions(
  human_session_hash text,
  organization_id text,
  after_action_id text,
  limit_count integer
) RETURNS TABLE(
  out_organization_id text,
  out_found boolean,
  out_action_id text,
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
  v_org text;
BEGIN
  IF NOT openarc_durable.is_canonical_org_id(organization_id) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF after_action_id IS NOT NULL
     AND NOT openarc_durable.is_canonical_action_id(after_action_id) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF limit_count IS NULL OR limit_count < 1 OR limit_count > 50 THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  v_org := openarc_durable.resolve_action_reader_org(human_session_hash, organization_id);
  RETURN QUERY
    SELECT v_org, true, a.action_id, a.subject_agent_id, a.commerce_session_id,
           a.status, a.policy_id, a.policy_revision, a.provider_id, a.listing_id,
           a.listing_version, a.requirement_id, a.requirement_digest, a.network_id,
           a.asset, a.representation, a.decimals, a.amount_atomic, a.fee_atomic,
           a.debit_atomic, a.reservation_id, a.approval_id,
           a.created_at, a.updated_at, a.expires_at
      FROM openarc_durable.commerce_actions a
     WHERE a.organization_id = v_org
       AND (after_action_id IS NULL OR a.action_id > after_action_id)
     ORDER BY a.action_id ASC
     LIMIT limit_count + 1;
  IF NOT FOUND THEN
    RETURN QUERY
      SELECT v_org, false, NULL::text, NULL::text, NULL::uuid, NULL::text, NULL::text,
             NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text,
             NULL::text, NULL::text, NULL::text, NULL::smallint, NULL::text, NULL::text,
             NULL::text, NULL::text, NULL::text,
             NULL::timestamptz, NULL::timestamptz, NULL::timestamptz;
  END IF;
  -- Revalidate the SAME current authority after the projection, including the
  -- empty page, so a session revoked or demoted mid-statement cannot return.
  PERFORM 1 WHERE openarc_durable.resolve_action_reader_org(
    human_session_hash, organization_id) = v_org;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- Bounded lexical keyset approval page. Same authority, same paging contract
-- and the same absence of any status filter; every schema10 approval status is
-- visible to the authorized reader.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.list_commerce_approvals(
  human_session_hash text,
  organization_id text,
  after_approval_id text,
  limit_count integer
) RETURNS TABLE(
  out_organization_id text,
  out_found boolean,
  out_approval_id text,
  out_action_id text,
  out_subject_agent_id text,
  out_commerce_session_id uuid,
  out_status text,
  out_policy_id text,
  out_policy_revision text,
  out_requested_by text,
  out_separate_approver boolean,
  out_decided_by text,
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
  v_org text;
BEGIN
  IF NOT openarc_durable.is_canonical_org_id(organization_id) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF after_approval_id IS NOT NULL
     AND NOT openarc_durable.is_canonical_approval_id(after_approval_id) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF limit_count IS NULL OR limit_count < 1 OR limit_count > 50 THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  v_org := openarc_durable.resolve_action_reader_org(human_session_hash, organization_id);
  RETURN QUERY
    SELECT v_org, true, ap.approval_id, ap.action_id, ap.subject_agent_id,
           ap.commerce_session_id, ap.status, ap.policy_id, ap.policy_revision,
           ap.requested_by, ap.separate_approver, ap.decided_by,
           ap.created_at, ap.expires_at, ap.decided_at
      FROM openarc_durable.commerce_approvals ap
     WHERE ap.organization_id = v_org
       AND (after_approval_id IS NULL OR ap.approval_id > after_approval_id)
     ORDER BY ap.approval_id ASC
     LIMIT limit_count + 1;
  IF NOT FOUND THEN
    RETURN QUERY
      SELECT v_org, false, NULL::text, NULL::text, NULL::text, NULL::uuid, NULL::text,
             NULL::text, NULL::text, NULL::text, NULL::boolean, NULL::text,
             NULL::timestamptz, NULL::timestamptz, NULL::timestamptz;
  END IF;
  PERFORM 1 WHERE openarc_durable.resolve_action_reader_org(
    human_session_hash, organization_id) = v_org;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- Approval detail keyed by the APPROVAL id. The schema10 reader
-- read_commerce_approval keys by action id and is untouched; this is the
-- approval-id lookup the accepted wire contract requires. Exactly one row is
-- always returned: the DB-derived organization plus out_found and nullable
-- projection columns, so an unknown approval under a valid current authority
-- is a safe not-found rather than an error, and the authority is revalidated
-- on the not-found path too.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.read_commerce_approval_by_id(
  human_session_hash text,
  organization_id text,
  approval_id_input text
) RETURNS TABLE(
  out_organization_id text,
  out_found boolean,
  out_approval_id text,
  out_action_id text,
  out_subject_agent_id text,
  out_commerce_session_id uuid,
  out_status text,
  out_policy_id text,
  out_policy_revision text,
  out_requested_by text,
  out_separate_approver boolean,
  out_decided_by text,
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
  v_org text;
  v_row openarc_durable.commerce_approvals%ROWTYPE;
BEGIN
  IF NOT openarc_durable.is_canonical_org_id(organization_id)
     OR NOT openarc_durable.is_canonical_approval_id(approval_id_input) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  v_org := openarc_durable.resolve_action_reader_org(human_session_hash, organization_id);
  SELECT ap.* INTO v_row
    FROM openarc_durable.commerce_approvals ap
   WHERE ap.organization_id = v_org AND ap.approval_id = approval_id_input;
  out_organization_id := v_org;
  IF NOT FOUND THEN
    out_found := false;
  ELSE
    out_found := true;
    out_approval_id := v_row.approval_id;
    out_action_id := v_row.action_id;
    out_subject_agent_id := v_row.subject_agent_id;
    out_commerce_session_id := v_row.commerce_session_id;
    out_status := v_row.status;
    out_policy_id := v_row.policy_id;
    out_policy_revision := v_row.policy_revision;
    out_requested_by := v_row.requested_by;
    out_separate_approver := v_row.separate_approver;
    out_decided_by := v_row.decided_by;
    out_created_at := v_row.created_at;
    out_expires_at := v_row.expires_at;
    out_decided_at := v_row.decided_at;
  END IF;
  PERFORM 1 WHERE openarc_durable.resolve_action_reader_org(
    human_session_hash, organization_id) = v_org;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Least privilege. PUBLIC receives nothing. The DB-derived authority resolver
-- stays migrator-private; only the three bounded read projections are
-- executable by the restricted tenant runtime. No table privilege, no policy
-- and no broad grant is added anywhere by this migration.
-- ---------------------------------------------------------------------------
REVOKE ALL ON FUNCTION openarc_durable.resolve_action_reader_org(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.list_commerce_actions(text, text, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.list_commerce_approvals(text, text, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.read_commerce_approval_by_id(text, text, text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION openarc_durable.list_commerce_actions(text, text, text, integer) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.list_commerce_approvals(text, text, text, integer) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.read_commerce_approval_by_id(text, text, text) TO openarc_tenant_app;
