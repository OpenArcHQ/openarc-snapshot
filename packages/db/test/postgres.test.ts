import { createHash } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import {
  DatabaseFoundationError,
  createDatabasePool,
  loadMigrations,
  migrate,
  readSchemaVersion,
} from '../src/index.js';
import type { SqlMigration } from '../src/index.js';
import {
  adminPool,
  appUrl,
  ensureRoles,
  migratorUrl,
  resetSchema,
} from './postgres-fixture.js';

function checksum(sql: string): string {
  return createHash('sha256').update(sql, 'utf8').digest('hex');
}

async function expectError(promise: Promise<unknown>, code: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(DatabaseFoundationError);
    expect((error as DatabaseFoundationError).code).toBe(code);
    return;
  }
  throw new Error(`expected ${code}`);
}

let admin: Pool;

beforeAll(async () => {
  admin = adminPool();
  try {
    await ensureRoles(admin);
  } finally {
    await resetSchema(admin);
  }
});

afterAll(async () => {
  try {
    await resetSchema(admin);
  } finally {
    await admin.end();
  }
});

describe('postgres migrations', () => {
  it('rejects running as the auth runtime role', async () => {
    await resetSchema(admin);
    const pool = createDatabasePool(appUrl());
    try {
      await expectError(migrate(pool), 'MIGRATION_ROLE_INVALID');
    } finally {
      await pool.end();
    }
  });

  it('clean install then readSchemaVersion and rerun is idempotent', async () => {
    await resetSchema(admin);
    const pool = createDatabasePool(migratorUrl());
    try {
      await migrate(pool);
      expect(await readSchemaVersion(pool)).toBe(16);
      await migrate(pool);
      expect(await readSchemaVersion(pool)).toBe(16);
    } finally {
      await pool.end();
    }
  });

  it('rejects unknown/newer applied migrations', async () => {
    await resetSchema(admin);
    const pool = createDatabasePool(migratorUrl());
    try {
      await migrate(pool);
      const client = await pool.connect();
      await client.query(
        "INSERT INTO openarc_meta.schema_migrations (id, checksum) VALUES ('0002_fake', $1)",
        [checksum('SELECT 1;')],
      );
      client.release();
      await expectError(migrate(pool), 'MIGRATION_DB_NEWER');
    } finally {
      await pool.end();
    }
  });

  it('rejects checksum drift', async () => {
    await resetSchema(admin);
    const pool = createDatabasePool(migratorUrl());
    try {
      await migrate(pool);
      const client = await pool.connect();
      await client.query(
        "UPDATE openarc_meta.schema_migrations SET checksum = $1 WHERE id = '0001_auth'",
        [checksum('SELECT 0;')],
      );
      client.release();
      await expectError(migrate(pool), 'MIGRATION_CHECKSUM_DRIFT');
    } finally {
      await pool.end();
    }
  });

  it('rolls back a failing migration and allows retry', async () => {
    await resetSchema(admin);
    const pool = createDatabasePool(migratorUrl());
    try {
      const base = loadMigrations();
      await migrate(pool, base);
      const broken: SqlMigration[] = [
        ...base,
        {
          id: '0017_synthetic',
          sql: 'CREATE TABLE openarc_auth.synthetic_rollback (id int); SELECT 1/0;',
        },
      ];
      await expectError(migrate(pool, broken), 'MIGRATION_APPLY_FAILED');
      const client = await pool.connect();
      try {
        const table = await client.query<{ exists: boolean }>(
          "SELECT to_regclass('openarc_auth.synthetic_rollback') IS NOT NULL AS exists",
        );
        const meta = await client.query<{ n: number }>(
          "SELECT count(*)::int AS n FROM openarc_meta.schema_migrations WHERE id = '0017_synthetic'",
        );
        expect(table.rows[0]?.exists).toBe(false);
        expect(meta.rows[0]?.n).toBe(0);
      } finally {
        client.release();
      }
      expect(await readSchemaVersion(pool)).toBe(16);
      const fixed: SqlMigration[] = [
        ...base,
        { id: '0017_synthetic', sql: 'CREATE TABLE openarc_auth.synthetic_ok (id int);' },
      ];
      await migrate(pool, fixed);
      const check = await pool.connect();
      try {
        const result = await check.query<{ n: number }>(
          "SELECT count(*)::int AS n FROM openarc_meta.schema_migrations WHERE id = '0017_synthetic'",
        );
        expect(result.rows[0]?.n).toBe(1);
      } finally {
        check.release();
      }
    } finally {
      await pool.end();
    }
  });

  it('rejects missing earlier metadata', async () => {
    await resetSchema(admin);
    const pool = createDatabasePool(migratorUrl());
    try {
      const base = loadMigrations();
      await migrate(pool, base);
      const client = await pool.connect();
      try {
        await client.query("DELETE FROM openarc_meta.schema_migrations WHERE id = '0001_auth'");
        await client.query(
          "INSERT INTO openarc_meta.schema_migrations (id, checksum) VALUES ('0002_fake', $1)",
          [checksum('SELECT 1;')],
        );
      } finally {
        client.release();
      }
      await expectError(migrate(pool, base), 'MIGRATION_DB_MISMATCH');
    } finally {
      await pool.end();
    }
  });

  it('rejects a changed applied ID', async () => {
    await resetSchema(admin);
    const pool = createDatabasePool(migratorUrl());
    try {
      const base = loadMigrations();
      await migrate(pool, base);
      const client = await pool.connect();
      try {
        await client.query("UPDATE openarc_meta.schema_migrations SET id = '0017_renamed' WHERE id = '0001_auth'");
      } finally {
        client.release();
      }
      await expectError(migrate(pool, base), 'MIGRATION_DB_MISMATCH');
    } finally {
      await pool.end();
    }
  });

  it('applies a successful synthetic upgrade', async () => {
    await resetSchema(admin);
    const pool = createDatabasePool(migratorUrl());
    try {
      const base = loadMigrations();
      await migrate(pool, base);
      const upgrade: SqlMigration[] = [
        ...base,
        { id: '0017_upgrade', sql: 'CREATE TABLE openarc_auth.upgrade_ok (id int);' },
      ];
      await migrate(pool, upgrade);
      const client = await pool.connect();
      try {
        const table = await client.query<{ exists: boolean }>(
          "SELECT to_regclass('openarc_auth.upgrade_ok') IS NOT NULL AS exists",
        );
        expect(table.rows[0]?.exists).toBe(true);
      } finally {
        client.release();
      }
    } finally {
      await pool.end();
    }
  });

  it('serializes two concurrent migration callers', async () => {
    await resetSchema(admin);
    const first = createDatabasePool(migratorUrl());
    const second = createDatabasePool(migratorUrl());
    try {
      await Promise.all([migrate(first), migrate(second)]);
      expect(await readSchemaVersion(first)).toBe(16);
    } finally {
      await first.end();
      await second.end();
    }
  });

  it('forbids the runtime role from DDL and migration history writes', async () => {
    await resetSchema(admin);
    const migrator = createDatabasePool(migratorUrl());
    try {
      await migrate(migrator);
    } finally {
      await migrator.end();
    }
    const app = createDatabasePool(appUrl());
    try {
      const client = await app.connect();
      try {
        await expect(client.query('CREATE TABLE openarc_auth.nope (id int)')).rejects.toBeTruthy();
        await expect(
          client.query("INSERT INTO openarc_meta.schema_migrations (id, checksum) VALUES ('x', 'y')"),
        ).rejects.toBeTruthy();
      } finally {
        client.release();
      }
      expect(await readSchemaVersion(app)).toBe(16);
    } finally {
      await app.end();
    }
  });

  it('enforces account unique and format constraints', async () => {
    await resetSchema(admin);
    const pool = createDatabasePool(migratorUrl());
    try {
      await migrate(pool);
      const client = await pool.connect();
      const handle = 'A'.repeat(42) + 'A';
      const accountId = 'openarc:account:00000000-0000-1000-8000-000000000000';
      try {
        await client.query(
          'INSERT INTO openarc_auth.accounts (account_id, user_handle) VALUES ($1, $2)',
          [accountId, handle],
        );
        await expect(
          client.query(
            'INSERT INTO openarc_auth.accounts (account_id, user_handle) VALUES ($1, $2)',
            ['openarc:account:11111111-1111-1111-8111-111111111111', handle],
          ),
        ).rejects.toBeTruthy();
        await expect(
          client.query(
            'INSERT INTO openarc_auth.accounts (account_id, user_handle) VALUES ($1, $2)',
            ['not-an-account', 'B'.repeat(42) + 'A'],
          ),
        ).rejects.toBeTruthy();
      } finally {
        client.release();
      }
    } finally {
      await pool.end();
    }
  });

  it('enforces FK cascade and bounds', async () => {
    await resetSchema(admin);
    const pool = createDatabasePool(migratorUrl());
    try {
      await migrate(pool);
      const client = await pool.connect();
      const handle = 'C'.repeat(42) + 'A';
      const accountId = 'openarc:account:22222222-2222-2222-8222-222222222222';
      try {
        await client.query(
          'INSERT INTO openarc_auth.accounts (account_id, user_handle) VALUES ($1, $2)',
          [accountId, handle],
        );
        await expect(
          client.query(
            "INSERT INTO openarc_auth.passkeys (credential_id, account_id, public_key, counter, device_type, backed_up) VALUES ('cred', 'openarc:account:33333333-3333-3333-8333-333333333333', '\\x01', 0, 'singleDevice', false)",
          ),
        ).rejects.toBeTruthy();
        await expect(
          client.query(
            "INSERT INTO openarc_auth.passkeys (credential_id, account_id, public_key, counter, device_type, backed_up) VALUES ('cred', $1, '\\x01', 4294967296, 'singleDevice', false)",
            [accountId],
          ),
        ).rejects.toBeTruthy();
        await client.query(
          "INSERT INTO openarc_auth.passkeys (credential_id, account_id, public_key, counter, device_type, backed_up) VALUES ('cred', $1, '\\x01', 0, 'singleDevice', false)",
          [accountId],
        );
        await client.query('DELETE FROM openarc_auth.accounts WHERE account_id = $1', [accountId]);
        const remaining = await client.query('SELECT count(*)::int AS n FROM openarc_auth.passkeys');
        expect(remaining.rows[0]?.n).toBe(0);
      } finally {
        client.release();
      }
    } finally {
      await pool.end();
    }
  });

  it('enforces challenge, session, wallet and transport bounds', async () => {
    await resetSchema(admin);
    const pool = createDatabasePool(migratorUrl());
    try {
      await migrate(pool);
      const client = await pool.connect();
      const handle = 'D'.repeat(42) + 'A';
      const accountId = 'openarc:account:44444444-4444-4444-8444-444444444444';
      const hash = 'a'.repeat(64);
      try {
        await client.query(
          'INSERT INTO openarc_auth.accounts (account_id, user_handle) VALUES ($1, $2)',
          [accountId, handle],
        );
        await expect(
          client.query(
            "INSERT INTO openarc_auth.challenges (challenge_hash, binding_hash, kind, challenge, wallet_address, expires_at) VALUES ($1, $2, 'wallet_login', 'abc', '0xzz', now() + interval '1 minute')",
            [hash, hash],
          ),
        ).rejects.toBeTruthy();
        await expect(
          client.query(
            "INSERT INTO openarc_auth.challenges (challenge_hash, binding_hash, kind, challenge, wallet_address, expires_at) VALUES ($1, $2, 'wallet_login', 'abc', '0x' || repeat('1', 40), now() + interval '6 minutes')",
            [hash, hash],
          ),
        ).rejects.toBeTruthy();
        await expect(
          client.query(
            "INSERT INTO openarc_auth.sessions (token_hash, account_id, method, expires_at) VALUES ($1, $2, 'passkey', now() + interval '25 hours')",
            [hash, accountId],
          ),
        ).rejects.toBeTruthy();
        await expect(
          client.query(
            "INSERT INTO openarc_auth.sessions (token_hash, account_id, method, expires_at) VALUES ($1, $2, 'bogus', now() + interval '1 hour')",
            [hash, accountId],
          ),
        ).rejects.toBeTruthy();
        await expect(
          client.query(
            "INSERT INTO openarc_auth.wallets (address, chain_id, account_id) VALUES ('0x' || repeat('1', 40), 1, $1)",
            [accountId],
          ),
        ).rejects.toBeTruthy();
        await expect(
          client.query(
            "INSERT INTO openarc_auth.passkeys (credential_id, account_id, public_key, counter, device_type, backed_up, transports) VALUES ('cred2', $1, '\\x01', 0, 'singleDevice', false, ARRAY[ARRAY['usb']])",
            [accountId],
          ),
        ).rejects.toBeTruthy();
        await expect(
          client.query(
            "INSERT INTO openarc_auth.passkeys (credential_id, account_id, public_key, counter, device_type, backed_up, transports) VALUES ('cred3', $1, '\\x01', 0, 'singleDevice', false, ARRAY['usb', NULL])",
            [accountId],
          ),
        ).rejects.toBeTruthy();
        await client.query(
          "INSERT INTO openarc_auth.passkeys (credential_id, account_id, public_key, counter, device_type, backed_up, transports) VALUES ('cred4', $1, '\\x01', 0, 'singleDevice', false, ARRAY['usb','nfc'])",
          [accountId],
        );
        const valid = await client.query<{ n: number }>(
          "SELECT count(*)::int AS n FROM openarc_auth.passkeys WHERE credential_id = 'cred4'",
        );
        expect(valid.rows[0]?.n).toBe(1);
      } finally {
        client.release();
      }
    } finally {
      await pool.end();
    }
  });
});
