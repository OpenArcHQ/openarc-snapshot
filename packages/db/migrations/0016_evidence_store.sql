-- OpenArc append-only evidence v2 store and bounded operator reads (schema16).
-- Additive over schema15. Owner: openarc_migrator. Runtime: openarc_tenant_app.
-- Migrations 0001-0015 are untouched. This migration NEVER creates roles or
-- schemas, calls a provider, Circle, Gateway or Arc endpoint, signs, moves
-- funds, settles, delivers or adds an outbox event type.
--
-- 1. openarc_durable.evidence_facts mirrors the packages/shared
--    `openarc.evidence.v2` fact column for column. It is APPEND-ONLY:
--      * a row trigger refuses every UPDATE and DELETE and a statement trigger
--        refuses TRUNCATE, for every role including the migrator and the
--        superuser;
--      * RLS is forced, the table is migrator-owned and PUBLIC holds nothing,
--        so no runtime role has any table privilege or any direct DML path;
--      * an insert trigger re-derives the stored content digest, so even
--        ordinary migrator DML cannot store a row whose digest does not
--        describe its own content.
--    A new observation of the same subject, including a finality upgrade, is
--    a NEW row with a NEW evidence id. Nothing is ever overwritten.
--
-- 2. CHECK constraints pin the shared contract: the kind -> source-class
--    authority matrix (EVIDENCE_V2_KIND_SOURCE_CLASSES) exactly, including
--    grant_state admitting local and openarc_derived where an openarc_derived
--    grant fact must carry status 'expired' (a derived expiry); the kind ->
--    subject-kind map; chain columns required for the onchain kinds and
--    forbidden otherwise; every canonical id grammar; exact integer strings for
--    every amount; the audience, provider-scope and action-scope rules; and a
--    strict per-kind shape plus a byte cap for the normalized payload.
--    Payment certainty is the closed set unknown, pending,
--    submitted_pending_chain, onchain_confirmed: there is no settled, paid,
--    released, refunded or failed value.
--
-- 3. No secret is representable. No column is named or shaped for a
--    signature, token, key or session hash; free text and identifier columns
--    refuse hex runs of 40 or more and JWT-like runs; hash-bearing columns and
--    every payload string refuse hex runs longer than 64 (a 65-byte signature
--    is 130 hex); payload object keys that name secret material are refused at
--    every depth.
--
-- 4. Write path. record_evidence_fact is a migrator-private SECURITY DEFINER
--    recorder, idempotent by evidence id: identical content (the same fact
--    digest) replays, different content for the same evidence id raises
--    'evidence_id_conflict'. The principal that may record at runtime is
--    decided in P05-02c. It is deliberately NOT granted to openarc_tenant_app
--    (or to any other role) here.
--
-- 5. Bounded operator reads, SECURITY DEFINER, STABLE, search_path pinned,
--    executable by openarc_tenant_app only. Authority is the accepted schema11
--    human reader preamble (resolve_action_reader_org -> lock_action_reader ->
--    lock_action_human: live non-recovery browser session and a current active
--    owner/operator membership), asserted BEFORE the projection and
--    revalidated AFTER it on every path, including not-found and bound
--    overflow. Both return the full operator shape; public and provider
--    projections stay in packages/shared and are applied by the API. Another
--    organization's evidence is indistinguishable from missing evidence.
--      * read_evidence_facts_by_subject: every fact about one subject, ordered
--        by (observed_at, evidence_id), capped at 200. A 201st fact fails closed
--        with 'evidence_read_bound_exceeded' rather than a silent truncation.
--      * list_evidence_facts: lexical keyset page over (organization, kind,
--        evidence id) with an exclusive cursor and a hard page size of 1..50;
--        it fetches page size + 1 so the repository detects a further page.

-- ---------------------------------------------------------------------------
-- Validators (IMMUTABLE, non-definer, migrator-private).
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.is_canonical_evidence_id(value text)
RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT value IS NOT NULL AND value ~ '^evd_[0-9a-f]{32}$';
$$;

-- Secret-shaped run refusal. NULL is admissible (nullable columns are
-- constrained separately). max_hex_run is the longest hexadecimal run allowed;
-- max_token_run, when not NULL, is the longest base64/base64url-like run
-- allowed. JWT-like runs are always refused. Never returns NULL.
CREATE FUNCTION openarc_durable.is_evidence_text_secret_free(
  value text,
  max_hex_run integer,
  max_token_run integer
) RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT CASE
    WHEN value IS NULL THEN true
    WHEN max_hex_run IS NULL OR max_hex_run < 1 OR max_hex_run > 200 THEN false
    WHEN max_token_run IS NOT NULL AND (max_token_run < 1 OR max_token_run > 200) THEN false
    ELSE value !~ ('[0-9a-fA-F]{' || (max_hex_run + 1)::text || ',}')
     AND value !~ 'eyJ[A-Za-z0-9_-]{8,}'
     AND (max_token_run IS NULL
          OR value !~ ('[A-Za-z0-9+/_-]{' || (max_token_run + 1)::text || ',}'))
  END;
$$;

-- Mirrors the shared `limitationsSchema`: 1..8 unique entries of trimmed
-- printable ASCII, 1..240 characters, with no secret-shaped run.
CREATE FUNCTION openarc_durable.is_valid_evidence_limitations(value text[])
RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT CASE
    WHEN value IS NULL THEN false
    WHEN cardinality(value) < 1 OR cardinality(value) > 8 THEN false
    WHEN array_ndims(value) <> 1 OR array_lower(value, 1) <> 1 THEN false
    WHEN array_position(value, NULL) IS NOT NULL THEN false
    ELSE (SELECT count(DISTINCT item) = count(*) FROM unnest(value) AS item)
     AND NOT EXISTS (
       SELECT 1 FROM unnest(value) AS item
        WHERE char_length(item) < 1 OR char_length(item) > 240
           OR item !~ '^[\x20-\x7e]+$'
           OR item <> btrim(item, ' ')
           OR NOT openarc_durable.is_evidence_text_secret_free(item, 39, 39))
  END;
$$;

-- Every payload string refuses hex runs longer than 64, base64-like runs longer
-- than 66 (a 0x-prefixed bytes32) and JWT-like runs; a canonical uint256
-- decimal (at most 78 digits) is the only exempt string. Every object key at
-- every depth refuses names of secret material and hex runs.
CREATE FUNCTION openarc_durable.is_evidence_payload_secret_free(value jsonb)
RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT CASE
    WHEN value IS NULL THEN false
    ELSE NOT EXISTS (
           SELECT 1
             FROM jsonb_path_query(value, 'strict $.**') AS item
            WHERE jsonb_typeof(item) = 'string'
              AND (item #>> '{}') !~ '^(0|[1-9][0-9]{0,77})$'
              AND NOT openarc_durable.is_evidence_text_secret_free(item #>> '{}', 64, 66))
     AND NOT EXISTS (
           SELECT 1
             FROM jsonb_path_query(value, 'strict $.**') AS item,
                  LATERAL jsonb_object_keys(
                    CASE WHEN jsonb_typeof(item) = 'object' THEN item ELSE '{}'::jsonb END) AS key
            WHERE key ~* '(signature|token|secret|password|private_?key|api_?key|session|authori[sz]ation|nonce|credential|mnemonic|seed|payload|cookie|bearer)'
               OR NOT openarc_durable.is_evidence_text_secret_free(key, 39, 39))
  END;
$$;

-- The authority matrix, exactly EVIDENCE_V2_KIND_SOURCE_CLASSES.
CREATE FUNCTION openarc_durable.is_evidence_kind_source_allowed(kind text, source_class text)
RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT coalesce(CASE kind
    WHEN 'authorization_decision' THEN source_class IN ('local', 'openarc_derived')
    WHEN 'grant_state' THEN source_class IN ('local', 'openarc_derived')
    WHEN 'listing_state' THEN source_class IN ('local', 'provider')
    WHEN 'budget_exposure' THEN source_class = 'local'
    WHEN 'payment_observation' THEN source_class IN ('facilitator', 'gateway')
    WHEN 'arc_transaction' THEN source_class = 'onchain'
    WHEN 'job_state' THEN source_class = 'onchain'
    WHEN 'job_refund' THEN source_class = 'onchain'
    WHEN 'provider_delivery' THEN source_class = 'provider'
    WHEN 'evaluator_result' THEN source_class = 'evaluator'
    ELSE false
  END, false);
$$;

-- Canonical subject ids, exactly the shared subject grammars.
CREATE FUNCTION openarc_durable.is_evidence_subject_id(subject_kind text, canonical_id text)
RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT coalesce(CASE subject_kind
    WHEN 'action' THEN openarc_durable.is_canonical_action_id(canonical_id)
    WHEN 'authorization_grant' THEN openarc_durable.is_canonical_grant_id(canonical_id)
    WHEN 'budget_reservation' THEN openarc_durable.is_canonical_reservation_id(canonical_id)
    WHEN 'listing' THEN canonical_id ~
      '^openarc:listing:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}:[1-9][0-9]{0,8}$'
    WHEN 'arc_transaction' THEN canonical_id ~ '^eip155:5042002:tx:0x[0-9a-f]{64}$'
    WHEN 'erc8183_job' THEN canonical_id ~ '^eip155:5042002:erc8183:0x[0-9a-f]{40}:[1-9][0-9]{0,77}$'
    ELSE false
  END, false);
$$;

-- Strict per-kind normalized payload shape: the exact key set, JSON types, the
-- closed enums, exact integer strings and canonical hashes/addresses of the
-- shared schema, plus the job terminal-flag rule. Never returns NULL.
CREATE FUNCTION openarc_durable.is_valid_evidence_normalized(kind text, normalized jsonb)
RETURNS boolean
LANGUAGE plpgsql IMMUTABLE
SET search_path = pg_catalog
AS $$
DECLARE
  v_keys text[];
  v_inner text[];
  v_exposure jsonb;
  v_bucket text;
  v_value text;
  v_uint256 constant text := '^(0|[1-9][0-9]{0,77})$';
  v_uint256_max constant numeric :=
    115792089237316195423570985008687907853269984665640564039457584007913129639935;
  v_bytes32 constant text := '^0x[0-9a-f]{64}$';
  v_address constant text := '^0x[0-9a-f]{40}$';
  v_transfer constant text :=
    '^([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$';
  v_statuses constant text[] := ARRAY['Open', 'Funded', 'Submitted', 'Completed', 'Rejected', 'Expired'];
BEGIN
  IF kind IS NULL OR normalized IS NULL OR jsonb_typeof(normalized) <> 'object' THEN
    RETURN false;
  END IF;
  SELECT coalesce(array_agg(k), ARRAY[]::text[]) INTO v_keys FROM jsonb_object_keys(normalized) AS k;

  CASE kind
  WHEN 'authorization_decision' THEN
    RETURN coalesce(v_keys @> ARRAY['decision'] AND v_keys <@ ARRAY['decision']
      AND jsonb_typeof(normalized -> 'decision') = 'string'
      AND normalized ->> 'decision' IN ('approval_requested', 'approved', 'rejected', 'authorized',
                                        'denied', 'expired', 'cancelled'), false);
  WHEN 'grant_state' THEN
    RETURN coalesce(v_keys @> ARRAY['status'] AND v_keys <@ ARRAY['status']
      AND jsonb_typeof(normalized -> 'status') = 'string'
      AND normalized ->> 'status' IN ('issued', 'replaced', 'claimed', 'revoked', 'expired'), false);
  WHEN 'listing_state' THEN
    RETURN coalesce(v_keys @> ARRAY['status'] AND v_keys <@ ARRAY['status']
      AND jsonb_typeof(normalized -> 'status') = 'string'
      AND normalized ->> 'status' IN ('draft', 'active', 'paused', 'retired'), false);
  WHEN 'budget_exposure' THEN
    IF NOT coalesce(v_keys @> ARRAY['exposure'] AND v_keys <@ ARRAY['exposure']
         AND jsonb_typeof(normalized -> 'exposure') = 'object', false) THEN
      RETURN false;
    END IF;
    v_exposure := normalized -> 'exposure';
    SELECT coalesce(array_agg(k), ARRAY[]::text[]) INTO v_inner FROM jsonb_object_keys(v_exposure) AS k;
    IF NOT coalesce(v_inner @> ARRAY['held', 'claimed', 'unknown', 'committed']
         AND v_inner <@ ARRAY['held', 'claimed', 'unknown', 'committed'], false) THEN
      RETURN false;
    END IF;
    FOREACH v_bucket IN ARRAY ARRAY['held', 'claimed', 'unknown', 'committed'] LOOP
      IF jsonb_typeof(v_exposure -> v_bucket) IS DISTINCT FROM 'string' THEN
        RETURN false;
      END IF;
      v_value := v_exposure ->> v_bucket;
      -- The grammar is checked before any cast, so a non-numeric string is a
      -- plain refusal and never a cast error.
      IF v_value !~ v_uint256 THEN
        RETURN false;
      END IF;
      IF v_value::numeric > v_uint256_max THEN
        RETURN false;
      END IF;
    END LOOP;
    RETURN true;
  WHEN 'payment_observation' THEN
    IF jsonb_typeof(normalized -> 'laneState') IS DISTINCT FROM 'string'
       OR jsonb_typeof(normalized -> 'certainty') IS DISTINCT FROM 'string' THEN
      RETURN false;
    END IF;
    IF normalized ->> 'laneState' = 'unknown' THEN
      RETURN coalesce(
        v_keys @> ARRAY['laneState', 'certainty', 'unknownReason']
        AND v_keys <@ ARRAY['laneState', 'certainty', 'unknownReason']
        AND normalized ->> 'certainty' = 'unknown'
        AND jsonb_typeof(normalized -> 'unknownReason') = 'string'
        AND normalized ->> 'unknownReason' IN ('timeout', 'transport_error', 'http_error',
          'malformed_response', 'not_found', 'not_found_after_expiry', 'nonce_already_used',
          'gateway_failed_not_terminal', 'ambiguous_records', 'record_mismatch',
          'completed_without_batch_hash', 'unrecognized_status'), false);
    END IF;
    IF normalized ->> 'laneState' NOT IN ('pending', 'committed') THEN
      RETURN false;
    END IF;
    IF NOT coalesce(
         v_keys @> ARRAY['laneState', 'certainty', 'gatewayStatus', 'transferId',
                         'batchTransactionHash', 'amountAtomic', 'payer', 'payTo']
         AND v_keys <@ ARRAY['laneState', 'certainty', 'gatewayStatus', 'transferId',
                             'batchTransactionHash', 'amountAtomic', 'payer', 'payTo']
         AND jsonb_typeof(normalized -> 'gatewayStatus') = 'string'
         AND jsonb_typeof(normalized -> 'transferId') = 'string'
         AND normalized ->> 'transferId' ~ v_transfer
         AND jsonb_typeof(normalized -> 'amountAtomic') = 'string'
         AND jsonb_typeof(normalized -> 'payer') = 'string'
         AND normalized ->> 'payer' ~ v_address
         AND jsonb_typeof(normalized -> 'payTo') = 'string'
         AND normalized ->> 'payTo' ~ v_address, false) THEN
      RETURN false;
    END IF;
    v_value := normalized ->> 'amountAtomic';
    IF v_value !~ v_uint256 THEN
      RETURN false;
    END IF;
    IF v_value::numeric > v_uint256_max THEN
      RETURN false;
    END IF;
    IF normalized ->> 'laneState' = 'pending' THEN
      RETURN coalesce(normalized ->> 'certainty' = 'pending'
        AND normalized ->> 'gatewayStatus' IN ('received', 'batched', 'confirmed')
        AND (jsonb_typeof(normalized -> 'batchTransactionHash') = 'null'
             OR (jsonb_typeof(normalized -> 'batchTransactionHash') = 'string'
                 AND normalized ->> 'batchTransactionHash' ~ v_bytes32)), false);
    END IF;
    RETURN coalesce(normalized ->> 'certainty' = 'submitted_pending_chain'
      AND normalized ->> 'gatewayStatus' = 'completed'
      AND jsonb_typeof(normalized -> 'batchTransactionHash') = 'string'
      AND normalized ->> 'batchTransactionHash' ~ v_bytes32, false);
  WHEN 'arc_transaction' THEN
    RETURN coalesce(v_keys @> ARRAY['transactionHash', 'receiptStatus']
      AND v_keys <@ ARRAY['transactionHash', 'receiptStatus']
      AND jsonb_typeof(normalized -> 'transactionHash') = 'string'
      AND normalized ->> 'transactionHash' ~ v_bytes32
      AND jsonb_typeof(normalized -> 'receiptStatus') = 'string'
      AND normalized ->> 'receiptStatus' IN ('success', 'reverted'), false);
  WHEN 'job_state' THEN
    IF jsonb_typeof(normalized -> 'knowledge') IS DISTINCT FROM 'string' THEN
      RETURN false;
    END IF;
    IF normalized ->> 'knowledge' = 'known' THEN
      RETURN coalesce(v_keys @> ARRAY['knowledge', 'status', 'terminal']
        AND v_keys <@ ARRAY['knowledge', 'status', 'terminal']
        AND jsonb_typeof(normalized -> 'status') = 'string'
        AND normalized ->> 'status' = ANY (v_statuses)
        AND jsonb_typeof(normalized -> 'terminal') = 'boolean'
        AND (normalized ->> 'terminal') = CASE
              WHEN normalized ->> 'status' IN ('Completed', 'Rejected', 'Expired') THEN 'true'
              ELSE 'false' END, false);
    END IF;
    RETURN coalesce(normalized ->> 'knowledge' = 'unknown'
      AND v_keys @> ARRAY['knowledge', 'reason', 'lastKnown']
      AND v_keys <@ ARRAY['knowledge', 'reason', 'lastKnown']
      AND jsonb_typeof(normalized -> 'reason') = 'string'
      AND normalized ->> 'reason' IN ('created_before_mirror_start', 'event_conflict', 'refund_unpaired')
      AND (jsonb_typeof(normalized -> 'lastKnown') = 'null'
           OR (jsonb_typeof(normalized -> 'lastKnown') = 'string'
               AND normalized ->> 'lastKnown' = ANY (v_statuses))), false);
  WHEN 'job_refund' THEN
    IF NOT coalesce(v_keys @> ARRAY['cause', 'amountAtomic', 'transactionHash']
         AND v_keys <@ ARRAY['cause', 'amountAtomic', 'transactionHash']
         AND jsonb_typeof(normalized -> 'cause') = 'string'
         AND normalized ->> 'cause' IN ('rejected', 'expired')
         AND jsonb_typeof(normalized -> 'transactionHash') = 'string'
         AND normalized ->> 'transactionHash' ~ v_bytes32
         AND jsonb_typeof(normalized -> 'amountAtomic') = 'string', false) THEN
      RETURN false;
    END IF;
    v_value := normalized ->> 'amountAtomic';
    IF v_value !~ v_uint256 THEN
      RETURN false;
    END IF;
    RETURN v_value::numeric <= v_uint256_max;
  WHEN 'provider_delivery' THEN
    RETURN coalesce(v_keys @> ARRAY['reported', 'responseDigest']
      AND v_keys <@ ARRAY['reported', 'responseDigest']
      AND jsonb_typeof(normalized -> 'reported') = 'string'
      AND normalized ->> 'reported' IN ('delivered', 'not_delivered')
      AND (jsonb_typeof(normalized -> 'responseDigest') = 'null'
           OR (jsonb_typeof(normalized -> 'responseDigest') = 'string'
               AND normalized ->> 'responseDigest' ~ '^sha256:[0-9a-f]{64}$')), false);
  WHEN 'evaluator_result' THEN
    RETURN coalesce(v_keys @> ARRAY['result'] AND v_keys <@ ARRAY['result']
      AND jsonb_typeof(normalized -> 'result') = 'string'
      AND normalized ->> 'result' IN ('accepted', 'rejected'), false);
  ELSE
    RETURN false;
  END CASE;
END;
$$;

-- ---------------------------------------------------------------------------
-- evidence_facts: one immutable row per evidence v2 fact.
-- ---------------------------------------------------------------------------
CREATE TABLE openarc_durable.evidence_facts (
  evidence_id text PRIMARY KEY,
  schema_version text NOT NULL,
  kind text NOT NULL,
  source_class text NOT NULL,
  source_id text NOT NULL,
  source_origin text NOT NULL,
  adapter_version text NOT NULL,
  subject_kind text NOT NULL,
  subject_canonical_id text NOT NULL,
  organization_id text NOT NULL,
  provider_id text,
  action_id text,
  actor_kind text NOT NULL,
  -- account/agent/provider id, system component, or external party role.
  actor_id text NOT NULL,
  actor_address text,
  chain_network text,
  chain_block_number text,
  chain_block_hash text,
  chain_finality text,
  occurred_at timestamptz,
  observed_at timestamptz NOT NULL,
  digest text,
  data_class text NOT NULL,
  limitations text[] NOT NULL,
  normalized jsonb NOT NULL,
  payment_certainty text GENERATED ALWAYS AS (
    CASE WHEN kind = 'payment_observation' THEN normalized ->> 'certainty' END) STORED,
  fact_digest text NOT NULL,
  recorded_at timestamptz NOT NULL,
  CONSTRAINT evidence_facts_org_fk FOREIGN KEY (organization_id)
    REFERENCES openarc_tenant.organizations(organization_id) ON DELETE RESTRICT,
  CONSTRAINT evidence_facts_evidence_id_valid CHECK (openarc_durable.is_canonical_evidence_id(evidence_id)),
  CONSTRAINT evidence_facts_schema_version_valid CHECK (schema_version = 'openarc.evidence.v2'),
  CONSTRAINT evidence_facts_kind_valid CHECK (kind IN (
    'authorization_decision', 'grant_state', 'listing_state', 'budget_exposure',
    'payment_observation', 'arc_transaction', 'job_state', 'job_refund',
    'provider_delivery', 'evaluator_result')),
  CONSTRAINT evidence_facts_source_class_valid CHECK (source_class IN (
    'local', 'signed', 'agent_reported', 'provider', 'facilitator', 'gateway',
    'onchain', 'evaluator', 'openarc_derived')),
  CONSTRAINT evidence_facts_source_class_allowed CHECK (
    openarc_durable.is_evidence_kind_source_allowed(kind, source_class)),
  -- An OpenArc-derived grant fact can only be a derived expiry.
  CONSTRAINT evidence_facts_derived_grant_expiry CHECK (
    NOT (kind = 'grant_state' AND source_class = 'openarc_derived')
    OR coalesce(normalized ->> 'status' = 'expired', false)),
  CONSTRAINT evidence_facts_source_id_valid CHECK (source_id ~ '^[a-z][a-z0-9._-]{1,63}$'),
  CONSTRAINT evidence_facts_source_origin_valid CHECK (
    char_length(source_origin) <= 120
    AND source_origin ~ '^(https://[a-z0-9]([a-z0-9.-]{0,98}[a-z0-9])?(:[1-9][0-9]{0,4})?|openarc:(control-plane|worker|reconciler|observer))$'),
  CONSTRAINT evidence_facts_adapter_version_valid CHECK (
    adapter_version ~ '^openarc\.[a-z0-9][a-z0-9.-]{0,78}\.v[1-9][0-9]{0,3}$'),
  CONSTRAINT evidence_facts_subject_valid CHECK (
    openarc_durable.is_evidence_subject_id(subject_kind, subject_canonical_id)),
  CONSTRAINT evidence_facts_kind_subject_valid CHECK (coalesce(CASE kind
    WHEN 'authorization_decision' THEN subject_kind = 'action'
    WHEN 'grant_state' THEN subject_kind = 'authorization_grant'
    WHEN 'listing_state' THEN subject_kind = 'listing'
    WHEN 'budget_exposure' THEN subject_kind IN ('action', 'budget_reservation')
    WHEN 'payment_observation' THEN subject_kind = 'action'
    WHEN 'arc_transaction' THEN subject_kind = 'arc_transaction'
    WHEN 'job_state' THEN subject_kind = 'erc8183_job'
    WHEN 'job_refund' THEN subject_kind = 'erc8183_job'
    WHEN 'provider_delivery' THEN subject_kind = 'action'
    WHEN 'evaluator_result' THEN subject_kind IN ('action', 'erc8183_job')
    ELSE false END, false)),
  CONSTRAINT evidence_facts_scope_valid CHECK (
    openarc_durable.is_canonical_org_id(organization_id)
    AND (provider_id IS NULL OR openarc_durable.is_canonical_provider_id(provider_id))
    AND (action_id IS NULL OR openarc_durable.is_canonical_action_id(action_id))),
  -- grant, listing and provider-delivery facts are provider scoped.
  CONSTRAINT evidence_facts_provider_scope_valid CHECK (
    kind NOT IN ('grant_state', 'listing_state', 'provider_delivery') OR provider_id IS NOT NULL),
  CONSTRAINT evidence_facts_action_scope_valid CHECK (
    subject_kind <> 'action' OR (action_id IS NOT NULL AND action_id = subject_canonical_id)),
  CONSTRAINT evidence_facts_actor_valid CHECK (coalesce(CASE actor_kind
    WHEN 'human_account' THEN actor_address IS NULL
      AND actor_id ~ '^openarc:account:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    WHEN 'agent' THEN actor_address IS NULL AND openarc_durable.is_canonical_agent_id(actor_id)
    WHEN 'provider' THEN actor_address IS NULL AND openarc_durable.is_canonical_provider_id(actor_id)
    WHEN 'system' THEN actor_address IS NULL AND actor_id IN ('api', 'worker', 'reconciler', 'observer')
    WHEN 'external_party' THEN actor_id IN ('facilitator', 'gateway', 'arc_chain', 'erc8183_client',
                                            'erc8183_provider', 'erc8183_evaluator')
      AND (actor_address IS NULL OR actor_address ~ '^0x[0-9a-f]{40}$')
    ELSE false END, false)),
  CONSTRAINT evidence_facts_provider_actor_valid CHECK (
    actor_kind <> 'provider' OR (provider_id IS NOT NULL AND actor_id = provider_id)),
  CONSTRAINT evidence_facts_provider_source_valid CHECK (
    source_class <> 'provider' OR actor_kind = 'provider'),
  CONSTRAINT evidence_facts_chain_valid CHECK (coalesce(CASE
    WHEN kind IN ('arc_transaction', 'job_state', 'job_refund') THEN
      chain_network = 'eip155:5042002'
      AND chain_block_hash ~ '^0x[0-9a-f]{64}$'
      AND chain_finality IN ('finalized', 'unfinalized')
      AND CASE WHEN chain_block_number ~ '^(0|[1-9][0-9]{0,19})$'
               THEN chain_block_number::numeric <= 18446744073709551615
               ELSE false END
    ELSE chain_network IS NULL AND chain_block_number IS NULL
      AND chain_block_hash IS NULL AND chain_finality IS NULL
    END, false)),
  CONSTRAINT evidence_facts_job_refund_finalized CHECK (
    kind <> 'job_refund' OR chain_finality = 'finalized'),
  CONSTRAINT evidence_facts_clock_valid CHECK (occurred_at IS NULL OR occurred_at <= observed_at),
  CONSTRAINT evidence_facts_digest_valid CHECK (
    digest IS NULL OR openarc_durable.is_canonical_sha256_digest(digest)),
  CONSTRAINT evidence_facts_data_class_valid CHECK (
    data_class = 'organization_protected'
    OR (data_class = 'public' AND kind IN ('listing_state', 'job_state', 'job_refund')
        AND NOT (kind = 'listing_state' AND normalized ->> 'status' = 'draft'))),
  CONSTRAINT evidence_facts_limitations_valid CHECK (
    openarc_durable.is_valid_evidence_limitations(limitations)),
  CONSTRAINT evidence_facts_normalized_size CHECK (octet_length(normalized::text) <= 2048),
  CONSTRAINT evidence_facts_normalized_valid CHECK (
    openarc_durable.is_valid_evidence_normalized(kind, normalized)),
  CONSTRAINT evidence_facts_arc_transaction_subject_valid CHECK (
    kind <> 'arc_transaction'
    OR coalesce(subject_canonical_id = 'eip155:5042002:tx:' || (normalized ->> 'transactionHash'), false)),
  CONSTRAINT evidence_facts_payment_limitation_valid CHECK (
    kind <> 'payment_observation' OR coalesce(CASE normalized ->> 'laneState'
      WHEN 'unknown' THEN
        'Payment outcome is unknown; the exposure may be spent and remains held.' = ANY (limitations)
      WHEN 'committed' THEN
        'Gateway reports completed; the batch transaction is not verified onchain.' = ANY (limitations)
      ELSE true END, false)),
  -- The complete payment certainty value set. No settled, paid, released,
  -- refunded or failed state is representable.
  CONSTRAINT evidence_facts_payment_certainty_valid CHECK (
    payment_certainty IS NULL
    OR payment_certainty IN ('unknown', 'pending', 'submitted_pending_chain', 'onchain_confirmed')),
  CONSTRAINT evidence_facts_payment_certainty_presence CHECK (
    (kind = 'payment_observation') = (payment_certainty IS NOT NULL)),
  CONSTRAINT evidence_facts_text_secret_free CHECK (
    openarc_durable.is_evidence_text_secret_free(evidence_id, 39, NULL)
    AND openarc_durable.is_evidence_text_secret_free(source_id, 39, NULL)
    AND openarc_durable.is_evidence_text_secret_free(source_origin, 39, NULL)
    AND openarc_durable.is_evidence_text_secret_free(adapter_version, 39, NULL)
    AND openarc_durable.is_evidence_text_secret_free(organization_id, 39, NULL)
    AND openarc_durable.is_evidence_text_secret_free(provider_id, 39, NULL)
    AND openarc_durable.is_evidence_text_secret_free(action_id, 39, NULL)
    AND openarc_durable.is_evidence_text_secret_free(actor_id, 39, NULL)
    AND openarc_durable.is_evidence_text_secret_free(actor_address, 40, NULL)
    AND openarc_durable.is_evidence_text_secret_free(subject_canonical_id, 64, NULL)
    AND openarc_durable.is_evidence_text_secret_free(chain_network, 39, NULL)
    AND openarc_durable.is_evidence_text_secret_free(chain_block_number, 39, NULL)
    AND openarc_durable.is_evidence_text_secret_free(chain_block_hash, 64, NULL)
    AND openarc_durable.is_evidence_text_secret_free(digest, 64, NULL)),
  CONSTRAINT evidence_facts_payload_secret_free CHECK (
    openarc_durable.is_evidence_payload_secret_free(normalized)),
  CONSTRAINT evidence_facts_fact_digest_valid CHECK (
    openarc_durable.is_canonical_sha256_digest(fact_digest))
);

CREATE INDEX evidence_facts_subject_idx ON openarc_durable.evidence_facts (
  organization_id, subject_kind, subject_canonical_id, observed_at, evidence_id);
CREATE INDEX evidence_facts_kind_idx ON openarc_durable.evidence_facts (
  organization_id, kind, evidence_id);

-- ---------------------------------------------------------------------------
-- Content digest. Every column of the fact (not recorded_at) in a fixed
-- positional JSON array, timestamps rendered in UTC with microseconds, so the
-- value never depends on TimeZone or DateStyle. Identical facts share a
-- digest; any content difference changes it.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.evidence_fact_digest(fact openarc_durable.evidence_facts)
RETURNS text
LANGUAGE sql STABLE
SET search_path = pg_catalog
AS $$
  SELECT 'sha256:' || encode(sha256(convert_to(jsonb_build_array(
    'openarc.evidence.v2.fact-digest.v1',
    fact.schema_version, fact.evidence_id, fact.kind, fact.source_class, fact.source_id,
    fact.source_origin, fact.adapter_version, fact.subject_kind, fact.subject_canonical_id,
    fact.organization_id, fact.provider_id, fact.action_id, fact.actor_kind, fact.actor_id,
    fact.actor_address, fact.chain_network, fact.chain_block_number, fact.chain_block_hash,
    fact.chain_finality,
    to_char(fact.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    to_char(fact.observed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    fact.digest, fact.data_class, to_jsonb(fact.limitations), fact.normalized)::text, 'UTF8')), 'hex');
$$;

-- ---------------------------------------------------------------------------
-- Append-only enforcement. Triggers fire for every role, the table owner and
-- the superuser included; only disabling them (an owner DDL act the readiness
-- check detects) could bypass them.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.reject_evidence_fact_mutation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'evidence_facts_append_only' USING ERRCODE = '42501';
END;
$$;

CREATE FUNCTION openarc_durable.enforce_evidence_fact_insert() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF NEW.fact_digest IS DISTINCT FROM openarc_durable.evidence_fact_digest(NEW) THEN
    RAISE EXCEPTION 'evidence_fact_digest_invalid' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER evidence_facts_append_only
  BEFORE UPDATE OR DELETE ON openarc_durable.evidence_facts
  FOR EACH ROW EXECUTE FUNCTION openarc_durable.reject_evidence_fact_mutation();

CREATE TRIGGER evidence_facts_no_truncate
  BEFORE TRUNCATE ON openarc_durable.evidence_facts
  FOR EACH STATEMENT EXECUTE FUNCTION openarc_durable.reject_evidence_fact_mutation();

CREATE TRIGGER evidence_facts_insert_digest
  BEFORE INSERT ON openarc_durable.evidence_facts
  FOR EACH ROW EXECUTE FUNCTION openarc_durable.enforce_evidence_fact_insert();

-- ---------------------------------------------------------------------------
-- RLS: migrator-only. Runtime, worker, auth and PUBLIC receive no privilege.
-- ---------------------------------------------------------------------------
ALTER TABLE openarc_durable.evidence_facts ENABLE ROW LEVEL SECURITY;
ALTER TABLE openarc_durable.evidence_facts FORCE ROW LEVEL SECURITY;
CREATE POLICY evidence_facts_migrator ON openarc_durable.evidence_facts
  FOR ALL TO openarc_migrator USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE openarc_durable.evidence_facts FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Migrator-private recorder. Idempotent by evidence id. Refusal families, all
-- with fixed literals: 'evidence_input_invalid' (22023),
-- 'evidence_secret_material_refused' (23514), 'evidence_source_class_forbidden'
-- (23514), 'evidence_fact_invalid' (23514), 'evidence_id_conflict' (23505).
-- An unknown organization is the ordinary foreign-key violation (23503).
-- NOT granted to openarc_tenant_app: the runtime recording principal is decided
-- in P05-02c.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.record_evidence_fact(
  schema_version_input text,
  evidence_id_input text,
  kind_input text,
  source_class_input text,
  source_id_input text,
  source_origin_input text,
  adapter_version_input text,
  subject_kind_input text,
  subject_canonical_id_input text,
  organization_id_input text,
  provider_id_input text,
  action_id_input text,
  actor_kind_input text,
  actor_id_input text,
  actor_address_input text,
  chain_network_input text,
  chain_block_number_input text,
  chain_block_hash_input text,
  chain_finality_input text,
  occurred_at_input timestamptz,
  observed_at_input timestamptz,
  digest_input text,
  data_class_input text,
  limitations_input text[],
  normalized_input jsonb
) RETURNS TABLE(
  out_replayed boolean,
  out_evidence_id text,
  out_organization_id text,
  out_fact_digest text,
  out_recorded_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_row openarc_durable.evidence_facts%ROWTYPE;
  v_existing record;
  v_inserted integer := 0;
  v_constraint text;
BEGIN
  IF schema_version_input IS NULL OR evidence_id_input IS NULL OR kind_input IS NULL
     OR source_class_input IS NULL OR source_id_input IS NULL OR source_origin_input IS NULL
     OR adapter_version_input IS NULL OR subject_kind_input IS NULL
     OR subject_canonical_id_input IS NULL OR organization_id_input IS NULL
     OR actor_kind_input IS NULL OR actor_id_input IS NULL OR observed_at_input IS NULL
     OR data_class_input IS NULL OR limitations_input IS NULL OR normalized_input IS NULL
     OR NOT openarc_durable.is_canonical_evidence_id(evidence_id_input)
     OR NOT openarc_durable.is_canonical_org_id(organization_id_input) THEN
    RAISE EXCEPTION 'evidence_input_invalid' USING ERRCODE = '22023';
  END IF;

  -- Secret-shaped material is refused before anything else is judged, so it
  -- is always reported as such and never as a generic shape fault.
  IF NOT (
       openarc_durable.is_evidence_text_secret_free(schema_version_input, 39, NULL)
       AND openarc_durable.is_evidence_text_secret_free(kind_input, 39, NULL)
       AND openarc_durable.is_evidence_text_secret_free(source_class_input, 39, NULL)
       AND openarc_durable.is_evidence_text_secret_free(source_id_input, 39, NULL)
       AND openarc_durable.is_evidence_text_secret_free(source_origin_input, 39, NULL)
       AND openarc_durable.is_evidence_text_secret_free(adapter_version_input, 39, NULL)
       AND openarc_durable.is_evidence_text_secret_free(subject_kind_input, 39, NULL)
       AND openarc_durable.is_evidence_text_secret_free(subject_canonical_id_input, 64, NULL)
       AND openarc_durable.is_evidence_text_secret_free(provider_id_input, 39, NULL)
       AND openarc_durable.is_evidence_text_secret_free(action_id_input, 39, NULL)
       AND openarc_durable.is_evidence_text_secret_free(actor_kind_input, 39, NULL)
       AND openarc_durable.is_evidence_text_secret_free(actor_id_input, 39, NULL)
       AND openarc_durable.is_evidence_text_secret_free(actor_address_input, 40, NULL)
       AND openarc_durable.is_evidence_text_secret_free(chain_network_input, 39, NULL)
       AND openarc_durable.is_evidence_text_secret_free(chain_block_number_input, 39, NULL)
       AND openarc_durable.is_evidence_text_secret_free(chain_block_hash_input, 64, NULL)
       AND openarc_durable.is_evidence_text_secret_free(chain_finality_input, 39, NULL)
       AND openarc_durable.is_evidence_text_secret_free(digest_input, 64, NULL)
       AND openarc_durable.is_evidence_text_secret_free(data_class_input, 39, NULL)
       AND NOT EXISTS (
         SELECT 1 FROM unnest(limitations_input) AS item
          WHERE NOT openarc_durable.is_evidence_text_secret_free(item, 39, 39))
       AND openarc_durable.is_evidence_payload_secret_free(normalized_input)) THEN
    RAISE EXCEPTION 'evidence_secret_material_refused' USING ERRCODE = '23514';
  END IF;

  IF NOT openarc_durable.is_evidence_kind_source_allowed(kind_input, source_class_input) THEN
    RAISE EXCEPTION 'evidence_source_class_forbidden' USING ERRCODE = '23514';
  END IF;

  v_row.evidence_id := evidence_id_input;
  v_row.schema_version := schema_version_input;
  v_row.kind := kind_input;
  v_row.source_class := source_class_input;
  v_row.source_id := source_id_input;
  v_row.source_origin := source_origin_input;
  v_row.adapter_version := adapter_version_input;
  v_row.subject_kind := subject_kind_input;
  v_row.subject_canonical_id := subject_canonical_id_input;
  v_row.organization_id := organization_id_input;
  v_row.provider_id := provider_id_input;
  v_row.action_id := action_id_input;
  v_row.actor_kind := actor_kind_input;
  v_row.actor_id := actor_id_input;
  v_row.actor_address := actor_address_input;
  v_row.chain_network := chain_network_input;
  v_row.chain_block_number := chain_block_number_input;
  v_row.chain_block_hash := chain_block_hash_input;
  v_row.chain_finality := chain_finality_input;
  v_row.occurred_at := occurred_at_input;
  v_row.observed_at := observed_at_input;
  v_row.digest := digest_input;
  v_row.data_class := data_class_input;
  v_row.limitations := limitations_input;
  v_row.normalized := normalized_input;
  v_row.fact_digest := openarc_durable.evidence_fact_digest(v_row);
  v_row.recorded_at := clock_timestamp();

  BEGIN
    INSERT INTO openarc_durable.evidence_facts (
      evidence_id, schema_version, kind, source_class, source_id, source_origin,
      adapter_version, subject_kind, subject_canonical_id, organization_id, provider_id,
      action_id, actor_kind, actor_id, actor_address, chain_network, chain_block_number,
      chain_block_hash, chain_finality, occurred_at, observed_at, digest, data_class,
      limitations, normalized, fact_digest, recorded_at)
    VALUES (
      v_row.evidence_id, v_row.schema_version, v_row.kind, v_row.source_class, v_row.source_id,
      v_row.source_origin, v_row.adapter_version, v_row.subject_kind, v_row.subject_canonical_id,
      v_row.organization_id, v_row.provider_id, v_row.action_id, v_row.actor_kind, v_row.actor_id,
      v_row.actor_address, v_row.chain_network, v_row.chain_block_number, v_row.chain_block_hash,
      v_row.chain_finality, v_row.occurred_at, v_row.observed_at, v_row.digest, v_row.data_class,
      v_row.limitations, v_row.normalized, v_row.fact_digest, v_row.recorded_at)
    ON CONFLICT (evidence_id) DO NOTHING;
    GET DIAGNOSTICS v_inserted = ROW_COUNT;
  EXCEPTION WHEN check_violation THEN
    GET STACKED DIAGNOSTICS v_constraint = CONSTRAINT_NAME;
    IF v_constraint IN ('evidence_facts_text_secret_free', 'evidence_facts_payload_secret_free') THEN
      RAISE EXCEPTION 'evidence_secret_material_refused' USING ERRCODE = '23514';
    ELSIF v_constraint IN ('evidence_facts_source_class_allowed', 'evidence_facts_derived_grant_expiry') THEN
      RAISE EXCEPTION 'evidence_source_class_forbidden' USING ERRCODE = '23514';
    END IF;
    RAISE EXCEPTION 'evidence_fact_invalid' USING ERRCODE = '23514';
  END;

  IF v_inserted = 1 THEN
    out_replayed := false;
    out_evidence_id := v_row.evidence_id;
    out_organization_id := v_row.organization_id;
    out_fact_digest := v_row.fact_digest;
    out_recorded_at := v_row.recorded_at;
    RETURN NEXT;
    RETURN;
  END IF;

  SELECT f.organization_id, f.fact_digest, f.recorded_at INTO v_existing
    FROM openarc_durable.evidence_facts f
   WHERE f.evidence_id = evidence_id_input;
  IF NOT FOUND OR v_existing.fact_digest IS DISTINCT FROM v_row.fact_digest THEN
    RAISE EXCEPTION 'evidence_id_conflict' USING ERRCODE = '23505';
  END IF;
  out_replayed := true;
  out_evidence_id := evidence_id_input;
  out_organization_id := v_existing.organization_id;
  out_fact_digest := v_existing.fact_digest;
  out_recorded_at := v_existing.recorded_at;
  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------
-- Operator read by subject. Exactly one sentinel row (out_found = false,
-- NULL projection columns, DB-derived organization) when the organization has
-- no fact about the subject. Another organization's facts never match.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.read_evidence_facts_by_subject(
  human_session_hash text,
  organization_id text,
  subject_kind_input text,
  subject_canonical_id_input text
) RETURNS TABLE(
  out_organization_id text,
  out_found boolean,
  out_evidence_id text,
  out_schema_version text,
  out_kind text,
  out_source_class text,
  out_source_id text,
  out_source_origin text,
  out_adapter_version text,
  out_subject_kind text,
  out_subject_canonical_id text,
  out_provider_id text,
  out_action_id text,
  out_actor_kind text,
  out_actor_id text,
  out_actor_address text,
  out_chain_network text,
  out_chain_block_number text,
  out_chain_block_hash text,
  out_chain_finality text,
  out_occurred_at timestamptz,
  out_observed_at timestamptz,
  out_digest text,
  out_data_class text,
  out_limitations text[],
  out_normalized jsonb,
  out_payment_certainty text,
  out_fact_digest text,
  out_recorded_at timestamptz
)
LANGUAGE plpgsql STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_org text;
  v_count integer := 0;
BEGIN
  IF NOT openarc_durable.is_canonical_org_id(organization_id)
     OR NOT openarc_durable.is_evidence_subject_id(subject_kind_input, subject_canonical_id_input) THEN
    RAISE EXCEPTION 'evidence_input_invalid' USING ERRCODE = '22023';
  END IF;
  v_org := openarc_durable.resolve_action_reader_org(human_session_hash, organization_id);
  -- 201 = the 200 cap + 1, so an overflow is detected without a count query.
  RETURN QUERY
    SELECT v_org, true, f.evidence_id, f.schema_version, f.kind, f.source_class, f.source_id,
           f.source_origin, f.adapter_version, f.subject_kind, f.subject_canonical_id,
           f.provider_id, f.action_id, f.actor_kind, f.actor_id, f.actor_address,
           f.chain_network, f.chain_block_number, f.chain_block_hash, f.chain_finality,
           f.occurred_at, f.observed_at, f.digest, f.data_class, f.limitations, f.normalized,
           f.payment_certainty, f.fact_digest, f.recorded_at
      FROM openarc_durable.evidence_facts f
     WHERE f.organization_id = v_org
       AND f.subject_kind = subject_kind_input
       AND f.subject_canonical_id = subject_canonical_id_input
     ORDER BY f.observed_at ASC, f.evidence_id ASC
     LIMIT 201;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  IF v_count = 0 THEN
    RETURN QUERY
      SELECT v_org, false, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text,
             NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text,
             NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text,
             NULL::text, NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::text,
             NULL::text[], NULL::jsonb, NULL::text, NULL::text, NULL::timestamptz;
  END IF;
  -- Revalidate the SAME current authority after the projection on every path,
  -- including not-found and overflow, before anything is returned or reported.
  PERFORM 1 WHERE openarc_durable.resolve_action_reader_org(
    human_session_hash, organization_id) = v_org;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;
  IF v_count > 200 THEN
    RAISE EXCEPTION 'evidence_read_bound_exceeded' USING ERRCODE = 'P0D11';
  END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- Operator page by organization and kind. Lexical keyset over evidence id;
-- `after_evidence_id` is an EXCLUSIVE lower bound (NULL starts at the first
-- id); `limit_count` is the hard page size 1..50 and at most limit_count + 1
-- rows are returned in strictly ascending evidence id order. An authorized
-- empty page is exactly one sentinel row.
-- ---------------------------------------------------------------------------
CREATE FUNCTION openarc_durable.list_evidence_facts(
  human_session_hash text,
  organization_id text,
  kind_input text,
  after_evidence_id text,
  limit_count integer
) RETURNS TABLE(
  out_organization_id text,
  out_found boolean,
  out_evidence_id text,
  out_schema_version text,
  out_kind text,
  out_source_class text,
  out_source_id text,
  out_source_origin text,
  out_adapter_version text,
  out_subject_kind text,
  out_subject_canonical_id text,
  out_provider_id text,
  out_action_id text,
  out_actor_kind text,
  out_actor_id text,
  out_actor_address text,
  out_chain_network text,
  out_chain_block_number text,
  out_chain_block_hash text,
  out_chain_finality text,
  out_occurred_at timestamptz,
  out_observed_at timestamptz,
  out_digest text,
  out_data_class text,
  out_limitations text[],
  out_normalized jsonb,
  out_payment_certainty text,
  out_fact_digest text,
  out_recorded_at timestamptz
)
LANGUAGE plpgsql STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_variable
DECLARE
  v_org text;
BEGIN
  IF NOT openarc_durable.is_canonical_org_id(organization_id)
     OR kind_input IS NULL
     OR kind_input NOT IN ('authorization_decision', 'grant_state', 'listing_state',
                           'budget_exposure', 'payment_observation', 'arc_transaction',
                           'job_state', 'job_refund', 'provider_delivery', 'evaluator_result') THEN
    RAISE EXCEPTION 'evidence_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF after_evidence_id IS NOT NULL
     AND NOT openarc_durable.is_canonical_evidence_id(after_evidence_id) THEN
    RAISE EXCEPTION 'evidence_input_invalid' USING ERRCODE = '22023';
  END IF;
  IF limit_count IS NULL OR limit_count < 1 OR limit_count > 50 THEN
    RAISE EXCEPTION 'evidence_input_invalid' USING ERRCODE = '22023';
  END IF;
  v_org := openarc_durable.resolve_action_reader_org(human_session_hash, organization_id);
  RETURN QUERY
    SELECT v_org, true, f.evidence_id, f.schema_version, f.kind, f.source_class, f.source_id,
           f.source_origin, f.adapter_version, f.subject_kind, f.subject_canonical_id,
           f.provider_id, f.action_id, f.actor_kind, f.actor_id, f.actor_address,
           f.chain_network, f.chain_block_number, f.chain_block_hash, f.chain_finality,
           f.occurred_at, f.observed_at, f.digest, f.data_class, f.limitations, f.normalized,
           f.payment_certainty, f.fact_digest, f.recorded_at
      FROM openarc_durable.evidence_facts f
     WHERE f.organization_id = v_org
       AND f.kind = kind_input
       AND (after_evidence_id IS NULL OR f.evidence_id > after_evidence_id)
     ORDER BY f.evidence_id ASC
     LIMIT limit_count + 1;
  IF NOT FOUND THEN
    RETURN QUERY
      SELECT v_org, false, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text,
             NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text,
             NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text,
             NULL::text, NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::text,
             NULL::text[], NULL::jsonb, NULL::text, NULL::text, NULL::timestamptz;
  END IF;
  PERFORM 1 WHERE openarc_durable.resolve_action_reader_org(
    human_session_hash, organization_id) = v_org;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'commerce_forbidden' USING ERRCODE = '28000';
  END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- Least privilege. PUBLIC receives nothing anywhere. Only the two bounded
-- operator reads are executable by the restricted tenant runtime. The recorder,
-- every validator, the digest helper and both trigger functions stay
-- migrator-private. No table privilege, no role membership and no broad grant
-- is added, and no existing grant is widened.
-- ---------------------------------------------------------------------------
REVOKE ALL ON FUNCTION openarc_durable.is_canonical_evidence_id(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.is_evidence_text_secret_free(text, integer, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.is_valid_evidence_limitations(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.is_evidence_payload_secret_free(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.is_evidence_kind_source_allowed(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.is_evidence_subject_id(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.is_valid_evidence_normalized(text, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.evidence_fact_digest(openarc_durable.evidence_facts) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.reject_evidence_fact_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.enforce_evidence_fact_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.record_evidence_fact(
  text, text, text, text, text, text, text, text, text, text, text, text, text, text, text,
  text, text, text, text, timestamptz, timestamptz, text, text, text[], jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.read_evidence_facts_by_subject(text, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION openarc_durable.list_evidence_facts(text, text, text, text, integer) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION openarc_durable.read_evidence_facts_by_subject(text, text, text, text) TO openarc_tenant_app;
GRANT EXECUTE ON FUNCTION openarc_durable.list_evidence_facts(text, text, text, text, integer) TO openarc_tenant_app;
