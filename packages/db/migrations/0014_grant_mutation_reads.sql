-- OpenArc authorization-grant MUTATION-STATUS reads (schema14).
-- Additive over schema12. Owner: openarc_migrator. Runtime: openarc_tenant_app.
--
-- This migration is READS ONLY. It creates NO table, NO column, NO index, NO
-- constraint, NO trigger, NO policy and NO role; it alters nothing, relaxes
-- nothing, widens no existing grant, writes no row, records no durability or
-- outbox evidence, grants no spend authority, issues no grant, retires no
-- token and moves no funds. It adds exactly two SECURITY DEFINER projections
-- over the EXISTING schema3 `idempotency_records` evidence written by the
-- schema12 grant cores. Both are declared STABLE, so PostgreSQL itself forbids
-- them from writing and from issuing a FOR UPDATE of their own; the ONLY locks
-- taken anywhere below are the ones the EXISTING schema10 authority preambles
-- already take, in their existing frozen order.
--
-- WHY IT EXISTS. The frozen capability registry publishes
-- `grant_mutation_status` and `agent_grant_mutation_status`, and the grant
-- console's LOST-RESPONSE recovery depends on the browser one: it is the only
-- safe way a buyer learns whether a revoke whose HTTP response was lost
-- actually committed. Schema12 declared no such helper, so the API adapter had
-- to report the dependency UNAVAILABLE rather than fake a `not_found` -- a
-- false negative on a money-adjacent recovery read would tell a caller their
-- mutation does not exist when it may have committed. These two helpers make
-- the truthful answer possible and nothing more.
--
-- SHAPE. Both mirror the schema10 commerce-action mutation-status readers
-- exactly: committed-or-not-found (a committed receipt or zero rows, never a
-- third state), the SAME current-authority preamble revalidated AFTER the read
-- INCLUDING the not-found path, and no caller value in any output column.
--
-- AUDIENCE SPLIT. Schema12 records exactly four grant operations. The two that
-- a commerce-session BEARER performs are `control.grant.issue` and
-- `control.grant.replace`; the one a BROWSER human performs is
-- `control.grant.revoke`; `control.grant.claim` is a SELLER-side provider
-- operation that already has its own keyed recovery read
-- (`read_provider_grant_attempt_status`) and belongs to neither audience here.
-- The human reader therefore admits `control.grant.revoke` ALONE and the agent
-- reader admits `control.grant.issue` / `control.grant.replace` ALONE, exactly
-- as the accepted wire schemas restrict the two receipts. A buyer cookie can
-- never recover an agent-issued receipt and an agent bearer can never recover
-- the buyer's revoke receipt.
--
-- TWO INDEPENDENT BARRIERS. The audience split is enforced twice over. First
-- by the closed operation filter each reader applies. Second by the stored
-- `session_context_digest`:
-- schema12 stores sha256('<per-operation session domain>' || ':' ||
-- '<the exact presented hash>') on every grant idempotency row, so a receipt is
-- only reachable from the SAME secret the mutation itself was authorized with,
-- under the SAME operation's domain label. A second live session for the same
-- account, agent or organization -- and any other operation's row -- fails the
-- comparison and is an ordinary not-found. Note that issue/replace record the
-- buyer's parent human account as `actor_account_id`, so the operation filter
-- alone would not separate the audiences; the digest does, and both are
-- applied.
--
-- INDISTINGUISHABILITY. Under a valid current authority, an unknown mutation
-- id, another organization's mutation, another buyer's mutation, another
-- audience's mutation and a mutation authorized by a DIFFERENT session all
-- return the same empty result. An invalid, revoked or expired authority is a
-- fixed authority error that never depends on whether the row exists, because
-- the preamble runs BEFORE the read and is revalidated after it on every path.
--
-- NO SECRET IS REPRESENTABLE. The projection is the four schema3 receipt
-- columns (mutation id, operation, resource type, resource id) plus the commit
-- instant, and -- on the agent reader only -- the DB-DERIVED buyer
-- organization. `key_hash`, `request_digest`, `session_context_digest`,
-- `actor_account_id`, the grant token hash, the commerce token hash and the
-- human session hash are all omitted, so no token, hash, pepper or credential
-- secret can appear in any output column. The resource id is a canonical
-- `openarc:grant:` id, never a secret.

-- ---------------------------------------------------------------------------
-- Buyer lost-response recovery. Authority is the schema10 current human reader
-- preamble (`lock_action_reader` -> `lock_action_human`: live non-recovery
-- session, current ACTIVE owner/operator membership of the presented
-- organization) -- the same preamble the schema12 buyer grant projection uses,
-- and NOT the fresh-proof writer preamble: recovering the fact of a committed
-- revoke grants no new authority and must stay available after the five-minute
-- proof window that the revoke itself required.
--
-- The receipt is additionally bound to the actor that performed it, so one
-- owner cannot recover a co-owner's revoke receipt, and to the exact presented
-- browser session, so a second live session of the same buyer cannot.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.read_human_grant_mutation_status(
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
LANGUAGE plpgsql STABLE
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
     AND r.operation = 'control.grant.revoke'
     AND r.session_context_digest = encode(
       sha256(convert_to(
         'openarc.control.grant.revoke.session.v1' || ':' || human_session_hash, 'UTF8')), 'hex');
  v_found := FOUND;
  -- Recheck the CURRENT authority AFTER the read, including the not-found
  -- path: a session or membership that lapsed mid-statement must not recover
  -- a receipt and must not learn a miss either.
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

-- ---------------------------------------------------------------------------
-- Agent lost-response recovery. There is NO organization argument: the buyer
-- organization is DERIVED from the presented commerce session by the schema10
-- lock chain and echoed back, so the presenter can never widen its own scope
-- through a parameter. The current state of that EXACT bearer is revalidated
-- after the read on every path, so a revoked, expired or superseded token
-- never recovers the receipt its predecessor earned.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.read_agent_grant_mutation_status(
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
LANGUAGE plpgsql STABLE
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
     AND r.actor_account_id = v_chain.out_parent_human_account_id
     AND r.operation IN ('control.grant.issue', 'control.grant.replace')
     AND r.session_context_digest = encode(
       sha256(convert_to(
         (CASE r.operation
            WHEN 'control.grant.issue' THEN 'openarc.control.grant.issue.session.v1'
            WHEN 'control.grant.replace' THEN 'openarc.control.grant.replace.session.v1'
          END) || ':' || commerce_token_hash, 'UTF8')), 'hex');
  v_found := FOUND;
  -- Recheck the CURRENT exact presented commerce token authority AFTER the
  -- read, including the not-found path: a revoked/second live token for the
  -- same account/agent must not recover the original receipt.
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
-- Least privilege. PUBLIC receives nothing; only the restricted tenant runtime
-- role may execute the two bounded projections. No table privilege, no policy,
-- no role membership and no broad grant is added anywhere by this migration,
-- and no existing grant is widened.
-- ---------------------------------------------------------------------------
REVOKE ALL ON FUNCTION openarc_durable.read_human_grant_mutation_status(text, text, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.read_agent_grant_mutation_status(text, uuid) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION openarc_durable.read_human_grant_mutation_status(text, text, uuid) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.read_agent_grant_mutation_status(text, uuid) TO openarc_tenant_app;
