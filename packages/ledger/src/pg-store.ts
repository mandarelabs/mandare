import pg from 'pg';

import type { LedgerEntryV1 } from '@mandarelabs/spec';

import type { LedgerHead } from './entry.js';
import type { LedgerStore } from './store.js';

/**
 * Postgres team-mode store (BUILD-DECISIONS Q7). Storage enforcement is
 * TWO-layer, and both layers are red-team-tested:
 *
 * 1. Privilege separation: the door connects as an application role that
 *    holds ONLY `SELECT, INSERT` on the ledger tables (provisioned by
 *    `provisionPgLedger`, run once by an admin). UPDATE/DELETE/TRUNCATE die
 *    on missing grants before any trigger fires.
 * 2. `BEFORE UPDATE OR DELETE … RAISE EXCEPTION` triggers — so even roles
 *    with broader table grants (a sloppy migration, a DBA habit) cannot
 *    mutate history without EXPLICITLY dropping the triggers first.
 *
 * Documented boundary (same as Q7): a superuser can drop the triggers and
 * rewrite the file — that is exactly what witnessing (S6) exists to catch;
 * the red-team suite proves verification + recorded heads detect it.
 */

const { Pool } = pg;

/** Advisory lock key for seq allocation: 'mndr' as a 32-bit int, namespaced. */
const APPEND_LOCK_CLASS = 0x6d6e6472;
const APPEND_LOCK_ID = 1;

const PG_SCHEMA = `
CREATE TABLE IF NOT EXISTS ledger_entries (
  seq        BIGINT PRIMARY KEY CHECK (seq >= 1),
  entry_hash TEXT NOT NULL UNIQUE,
  prev_hash  TEXT NOT NULL,
  entry_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ledger_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE OR REPLACE FUNCTION mandare_ledger_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'ledger is append-only';
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION mandare_meta_write_once() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'ledger meta is write-once';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS ledger_entries_append_only ON ledger_entries;
CREATE TRIGGER ledger_entries_append_only
  BEFORE UPDATE OR DELETE ON ledger_entries
  FOR EACH ROW EXECUTE FUNCTION mandare_ledger_append_only();
DROP TRIGGER IF EXISTS ledger_meta_write_once ON ledger_meta;
CREATE TRIGGER ledger_meta_write_once
  BEFORE UPDATE OR DELETE ON ledger_meta
  FOR EACH ROW EXECUTE FUNCTION mandare_meta_write_once();
`;

/**
 * One-time admin provisioning: schema, append-only triggers, and the
 * least-privilege grants for the application role the door connects as.
 * The role itself (LOGIN, password/cert) is created by the operator's
 * deployment tooling — this function only scopes what it may do.
 */
export async function provisionPgLedger(
  adminConnectionString: string,
  options: { appRole: string }
): Promise<void> {
  const client = new pg.Client({ connectionString: adminConnectionString });
  await client.connect();
  try {
    await client.query(PG_SCHEMA);
    const role = client.escapeIdentifier(options.appRole);
    await client.query(`REVOKE ALL ON ledger_entries, ledger_meta FROM ${role};`);
    await client.query(`GRANT SELECT, INSERT ON ledger_entries, ledger_meta TO ${role};`);
  } finally {
    await client.end();
  }
}

export class PgStore implements LedgerStore {
  private readonly pool: pg.Pool;

  private constructor(pool: pg.Pool) {
    this.pool = pool;
    // node-postgres contract: idle-client failures (server restart, network
    // drop) are emitted on the pool and CRASH the process if unhandled. The
    // door must survive a database hiccup — the next query checks out a
    // fresh client and fails loudly in its own call path instead.
    this.pool.on('error', (error) => {
      console.error(`mandare pg-store: idle connection dropped (${error.message})`);
    });
  }

  /** Connect as the INSERT-only application role (never as an admin). */
  static connect(connectionString: string): PgStore {
    return new PgStore(new Pool({ connectionString, max: 4 }));
  }

  async appendWithLock(
    build: (head: LedgerHead | null) => LedgerEntryV1
  ): Promise<LedgerEntryV1> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      // Transaction-scoped advisory lock: serializes seq allocation across
      // all writer processes without needing UPDATE grants on any table.
      await client.query('SELECT pg_advisory_xact_lock($1, $2)', [
        APPEND_LOCK_CLASS,
        APPEND_LOCK_ID,
      ]);
      const entry = build(await headWithClient(client));
      await client.query(
        'INSERT INTO ledger_entries (seq, entry_hash, prev_hash, entry_json) VALUES ($1, $2, $3, $4)',
        [entry.seq, entry.entry_hash, entry.prev_hash, JSON.stringify(entry)]
      );
      await client.query('COMMIT');
      return entry;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async head(): Promise<LedgerHead | null> {
    return headWithClient(this.pool);
  }

  async readMetaRows(): Promise<Map<string, string> | null> {
    const result = await this.pool.query<{ key: string; value: string }>(
      'SELECT key, value FROM ledger_meta'
    );
    if (result.rows.length === 0) {
      return null;
    }
    return new Map(result.rows.map((row) => [row.key, row.value]));
  }

  async initMeta(rows: readonly [string, string][]): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      for (const [key, value] of rows) {
        await client.query('INSERT INTO ledger_meta (key, value) VALUES ($1, $2)', [key, value]);
      }
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async readAllEntries(): Promise<unknown[]> {
    const result = await this.pool.query<{ entry_json: string }>(
      'SELECT entry_json FROM ledger_entries ORDER BY seq ASC'
    );
    return result.rows.map((row) => JSON.parse(row.entry_json) as unknown);
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

async function headWithClient(
  queryable: pg.Pool | pg.PoolClient
): Promise<LedgerHead | null> {
  // seq is BIGINT; cast to int so pg returns a number, not a string. The
  // 2^31 ceiling matches the verifier's tree-size bound.
  const result = await queryable.query<{ seq: number; entry_hash: string }>(
    'SELECT seq::int AS seq, entry_hash FROM ledger_entries ORDER BY seq DESC LIMIT 1'
  );
  const row = result.rows[0];
  return row === undefined ? null : { seq: row.seq, entry_hash: row.entry_hash };
}
