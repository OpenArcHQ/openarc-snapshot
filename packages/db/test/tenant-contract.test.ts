import { describe, expect, it } from 'vitest';
import { loadMigrations } from '../src/index.js';

/**
 * Structural checks for the frozen tenant SQL interface (schema2). These do
 * not replace the real PostgreSQL suite; they guard that the append-only
 * migration keeps the reviewed bridge/RLS contracts and never edits 0001.
 */

function tenantSql(): string {
  const migrations = loadMigrations();
  const tenant = migrations.find((migration) => migration.id === '0002_tenants');
  if (tenant === undefined) throw new Error('0002_tenants migration missing');
  return tenant.sql;
}

describe('tenant migration manifest', () => {
  it('appends 0002 without modifying 0001', () => {
    const migrations = loadMigrations();
    expect(migrations.map((migration) => migration.id)).toEqual([
      '0001_auth',
      '0002_tenants',
      '0003_durability',
      '0004_durable_tenant_mutations',
      '0005_machine_credentials',
      '0006_market',
      '0007_market_lifecycle',
      '0008_control_policies',
      '0009_control_sessions',
      '0010_control_actions',
      '0011_control_action_reads',
      '0012_authorization_grants',
      '0013_commerce_session_reads',
      '0014_grant_mutation_reads',
    ]);
    const auth = migrations[0];
    expect(auth?.sql).toContain('CREATE TABLE openarc_auth.accounts');
    expect(auth?.sql).not.toContain('openarc_tenant');
  });

  it('freezes the bridge signatures', () => {
    const sql = tenantSql();
    expect(sql).toContain(
      'CREATE FUNCTION openarc_tenant.lock_auth_session(\n  session_hash text,\n  additional_account_id text DEFAULT NULL\n)',
    );
    expect(sql).toContain(
      'CREATE FUNCTION openarc_tenant.list_account_organization_ids(\n  session_hash text,\n  after_organization_id text DEFAULT NULL,\n  page_size integer DEFAULT 50\n)',
    );
    expect(sql).toContain(
      'CREATE FUNCTION openarc_tenant.set_membership(\n  session_hash text,\n  organization_id text,\n  target_account_id text,\n  requested_role text,\n  requested_status text\n)',
    );
    expect(sql).toContain(
      'CREATE FUNCTION openarc_tenant.lock_organization_access(\n  session_hash text,\n  organization_id text\n)',
    );
    expect(sql).toContain(
      'CREATE FUNCTION openarc_tenant.current_context_access_kind() RETURNS text',
    );
  });

  it('defines owner, fixed search_path and restricted execution', () => {
    const sql = tenantSql();
    const definerCount = (sql.match(/^SECURITY DEFINER$/gm) ?? []).length;
    expect(definerCount).toBe(5);
    expect((sql.match(/^SET search_path = pg_catalog$/gm) ?? []).length).toBeGreaterThanOrEqual(6);
    expect(sql).toContain('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA openarc_tenant FROM PUBLIC');
    expect(sql).toContain(
      'GRANT EXECUTE ON FUNCTION openarc_tenant.lock_auth_session(text, text) TO openarc_tenant_app',
    );
    expect(sql).toContain(
      'GRANT EXECUTE ON FUNCTION openarc_tenant.lock_organization_access(text, text) TO openarc_tenant_app',
    );
    expect(sql).toContain(
      'GRANT EXECUTE ON FUNCTION openarc_tenant.current_context_access_kind() TO openarc_tenant_app',
    );
    expect(sql).not.toContain('CREATE ROLE');
  });

  it('enables and forces RLS on every tenant table with closed context', () => {
    const sql = tenantSql();
    for (const table of ['organizations', 'memberships', 'agents', 'providers']) {
      expect(sql).toContain(`ALTER TABLE openarc_tenant.${table} ENABLE ROW LEVEL SECURITY;`);
      expect(sql).toContain(`ALTER TABLE openarc_tenant.${table} FORCE ROW LEVEL SECURITY;`);
    }
    expect(sql).toContain("current_setting('openarc.account_id', true)");
    expect(sql).toContain("current_setting('openarc.organization_id', true)");
    expect(sql).toContain("current_setting('openarc.role', true)");
  });

  it('keeps auth tables out of tenant grants and never grants DELETE', () => {
    const sql = tenantSql();
    const grantLines = sql
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.startsWith('GRANT'));
    expect(grantLines.some((line) => /GRANT[^;]*DELETE/.test(line))).toBe(false);
    expect(grantLines.some((line) => /GRANT[^;]*openarc_auth\./.test(line))).toBe(false);
    expect(sql).toContain('GRANT USAGE ON SCHEMA openarc_auth TO openarc_tenant_app');
  });
});
