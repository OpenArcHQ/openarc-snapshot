-- OpenArc commerce-session BEARER read (schema13).
-- Additive over schema9. Owner: openarc_migrator. Runtime: openarc_tenant_app.
--
-- This migration is READS ONLY. It creates NO table, NO column, NO trigger, NO
-- policy, NO role, NO index and NO constraint; it alters nothing, relaxes
-- nothing, writes no row, records no durability/outbox evidence, grants no
-- spend authority, issues no grant and moves no funds. It adds exactly one
-- SECURITY DEFINER projection over the schema9 commerce_session_handoffs /
-- commerce_sessions tables.
--
-- WHY IT EXISTS. The schema9 reader `read_commerce_session` is keyed by a HUMAN
-- session hash plus an organization and a session id, so it cannot resolve an
-- agent that presents only its commerce-session BEARER token. The agent lane of
-- the commerce-action family authenticates exactly that bearer, so it needs the
-- one read that turns a presented commerce token hash into the session metadata
-- the service then judges. This is that read and nothing more.
--
-- RESOLUTION. Identical to the immutable lookup the schema10 authorization
-- path performs in `lock_action_commerce`: the exchanged (consumed) handoff row
-- carrying that exact `token_hash` at `token_hash_version = 1` names the
-- (organization_id, session_id) of the commerce session. Unlike that helper
-- this one is a READ: it is declared STABLE, so PostgreSQL itself forbids it
-- from writing, it takes NO row lock (no FOR UPDATE anywhere) and it mutates
-- nothing. `commerce_session_handoffs_token_unique` and the commerce_sessions
-- primary key together bound the result at one row.
--
-- REPORTING, NOT POLICY. A revoked, an expired and an exchange-shortened
-- session all still RESOLVE, carrying their real `revoked_at` / `expires_at`.
-- The store projects those values and the service rejects the session
-- explicitly; hiding a revoked row here would turn an explicit rejection into
-- an indistinguishable not-found and lose the reason. This helper therefore
-- asserts NO authority of its own: it never proves the presenter may act, never
-- checks a clock and never consults the parent human session. Every authority,
-- freshness and spend decision stays where it already is -- the schema10
-- authorization helpers, which re-lock and re-validate this same session.
--
-- INDISTINGUISHABILITY. The ONLY key is the presented bearer hash. A hash that
-- names no consumed handoff returns zero rows, whatever the reason: never
-- issued, still unexchanged (an unexchanged handoff has a NULL token_hash and
-- so can never match), a handoff hash rather than a token hash, a human or
-- machine session hash, or a canonical hash belonging to nothing at all. All of
-- them are the same empty result, so a caller learns nothing about another
-- organization's sessions from a miss. There is no organization argument to
-- echo and no caller value reaches the output: every projected column is read
-- from the commerce_sessions row the bearer itself resolved.
--
-- NO SECRET IS REPRESENTABLE. The projection omits `parent_human_session_hash`,
-- `parent_human_account_id`, the handoff `handoff_hash`, `token_hash` and
-- `token_hash_version`, and every scope/network constant the caller already
-- holds. No token, hash, digest, pepper or credential secret can appear in any
-- output column. The bound machine ids are returned so the repository can
-- verify the exchange binding is paired and canonical before projecting, and
-- they are then dropped from the safe metadata it returns.

-- ---------------------------------------------------------------------------
-- Bearer-keyed commerce-session projection. Input is the canonical sha-256 hex
-- digest of the presented `oacs_v1_` session token; a non-canonical input is a
-- fixed input error rather than a silent empty result, exactly as the schema9
-- and schema11 readers treat a malformed identifier. The output column set is
-- the SAME eleven columns the schema9 session readers project, minus the
-- human-only derived status, so the repository reuses its existing strict
-- keyset and metadata projection unchanged.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.read_commerce_session_by_token(
  commerce_token_hash text
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
  out_revoked_at timestamptz
)
LANGUAGE plpgsql STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
BEGIN
  IF commerce_token_hash IS NULL
     OR NOT openarc_durable.is_canonical_hex64(commerce_token_hash) THEN
    RAISE EXCEPTION 'commerce_input_invalid' USING ERRCODE = '22023';
  END IF;
  -- Immutable lookup by the EXACT presented commerce token hash. A machine
  -- session hash, a handoff hash or a human session hash cannot select a
  -- commerce session here, and an unexchanged handoff carries a NULL token_hash
  -- so it can never be reached. No lock is taken and no row is written.
  RETURN QUERY
    SELECT s.session_id, s.organization_id, s.subject_agent_id, s.policy_id,
           s.issued_at, s.initial_expires_at, s.expires_at, s.exchanged_at,
           s.agent_session_id, s.credential_id, s.revoked_at
      FROM openarc_durable.commerce_session_handoffs h
      JOIN openarc_durable.commerce_sessions s
        ON s.organization_id = h.organization_id AND s.session_id = h.session_id
     WHERE h.token_hash = commerce_token_hash
       AND h.token_hash_version = 1
       AND h.consumed_at IS NOT NULL;
END;
$$;

-- ---------------------------------------------------------------------------
-- Least privilege. PUBLIC receives nothing; only the restricted tenant runtime
-- role may execute the one bounded projection. No table privilege, no policy,
-- no role membership and no broad grant is added anywhere by this migration,
-- and no existing grant is widened.
-- ---------------------------------------------------------------------------
REVOKE ALL ON FUNCTION openarc_durable.read_commerce_session_by_token(text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION openarc_durable.read_commerce_session_by_token(text) TO openarc_tenant_app;
