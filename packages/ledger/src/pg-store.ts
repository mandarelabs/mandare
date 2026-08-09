import pg from 'pg';

import type { LedgerEntryV1 } from '@mandarelabs/spec';

import type { LedgerHead } from './entry.js';
import type { SpendCounter } from './projection.js';
import {
  runProjectedAppend,
  type AppendProjectedResult,
  type LedgerStore,
  type ProjectionTx,
  type Projector,
  type RevocationRecord,
} from './store.js';

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
-- Spend-counter PROJECTION (S2): derived from the ledger, rebuildable from
-- it at any time — deliberately mutable, so NO append-only protection here.
-- Integrity comes from replay(ledger) == counters, not from storage locks.
CREATE TABLE IF NOT EXISTS budget_counters (
  scope_key       TEXT PRIMARY KEY,
  reserved_micros BIGINT NOT NULL,
  settled_micros  BIGINT NOT NULL,
  intents         BIGINT NOT NULL
);
-- Revocation PROJECTION (S3): kill-switch state derived from the ledger's
-- agent.revoke / agent.reinstate entries — mutable/rebuildable, integrity
-- from replay(ledger) == this table, not from storage locks.
CREATE TABLE IF NOT EXISTS revocation_status (
  subject      TEXT PRIMARY KEY,
  revoked      BOOLEAN NOT NULL,
  status_index BIGINT NOT NULL,
  updated_at   TEXT NOT NULL,
  entry_hash   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS projection_meta (
  key   TEXT PRIMARY KEY,
  value BIGINT NOT NULL
);
`;

const PROJECTION_SEQ_KEY = 'spend_projection_seq';
const REVOCATION_INDEX_KEY = 'revocation_next_index';

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
    // The projections are mutable derived tables — the app role may maintain
    // them (incl. DELETE for rebuilds). The LEDGER grants above stay INSERT-only.
    await client.query(
      `REVOKE ALL ON budget_counters, revocation_status, projection_meta FROM ${role};`
    );
    await client.query(
      `GRANT SELECT, INSERT, UPDATE, DELETE ON budget_counters, revocation_status, projection_meta TO ${role};`
    );
  } finally {
    await client.end();
  }
}

/**
 * ROLLBACK that never masks the causal error: if the connection is already
 * gone, the rollback throws too, and we must surface the ORIGINAL failure.
 */
async function rollbackQuietly(client: pg.PoolClient): Promise<void> {
  try {
    await client.query('ROLLBACK');
  } catch {
    // The transaction is aborted regardless; the caller rethrows the cause.
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
      await rollbackQuietly(client);
      throw error;
    } finally {
      client.release();
    }
  }

  async appendProjected(
    build: (head: LedgerHead | null) => LedgerEntryV1,
    project: Projector
  ): Promise<AppendProjectedResult> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock($1, $2)', [
        APPEND_LOCK_CLASS,
        APPEND_LOCK_ID,
      ]);
      const result = await runProjectedAppend({
        tx: projectionTxWithClient(client),
        build,
        project,
        insert: async (entry) => {
          await client.query(
            'INSERT INTO ledger_entries (seq, entry_hash, prev_hash, entry_json) VALUES ($1, $2, $3, $4)',
            [entry.seq, entry.entry_hash, entry.prev_hash, JSON.stringify(entry)]
          );
        },
      });
      if (result.kind === 'refused') {
        // A refused reservation aborts EVERYTHING: no entry, no counter change.
        await rollbackQuietly(client);
        return result;
      }
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await rollbackQuietly(client);
      throw error;
    } finally {
      client.release();
    }
  }

  async runProjection<T>(fn: (tx: ProjectionTx) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock($1, $2)', [
        APPEND_LOCK_CLASS,
        APPEND_LOCK_ID,
      ]);
      const result = await fn(projectionTxWithClient(client));
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await rollbackQuietly(client);
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
      await rollbackQuietly(client);
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

  async readEntryHashes(): Promise<string[]> {
    const result = await this.pool.query<{ entry_hash: string }>(
      'SELECT entry_hash FROM ledger_entries ORDER BY seq ASC'
    );
    return result.rows.map((row) => row.entry_hash);
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

function projectionTxWithClient(client: pg.PoolClient): ProjectionTx {
  return {
    head: () => headWithClient(client),
    getCounter: async (key) => {
      const result = await client.query<{
        reserved_micros: string;
        settled_micros: string;
        intents: string;
      }>(
        'SELECT reserved_micros, settled_micros, intents FROM budget_counters WHERE scope_key = $1',
        [key]
      );
      const row = result.rows[0];
      // BIGINT arrives as string from node-postgres; micros stay far below
      // 2^53, so Number is exact here.
      return row === undefined
        ? null
        : {
            reservedMicros: Number(row.reserved_micros),
            settledMicros: Number(row.settled_micros),
            intents: Number(row.intents),
          };
    },
    putCounter: async (key, value) => {
      await client.query(
        `INSERT INTO budget_counters (scope_key, reserved_micros, settled_micros, intents)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (scope_key) DO UPDATE SET
           reserved_micros = EXCLUDED.reserved_micros,
           settled_micros = EXCLUDED.settled_micros,
           intents = EXCLUDED.intents`,
        [key, value.reservedMicros, value.settledMicros, value.intents]
      );
    },
    getEntryByHash: async (entryHash) => {
      const result = await client.query<{ entry_json: string }>(
        'SELECT entry_json FROM ledger_entries WHERE entry_hash = $1',
        [entryHash]
      );
      const row = result.rows[0];
      return row === undefined ? null : (JSON.parse(row.entry_json) as unknown);
    },
    getProjectionSeq: async () => {
      const result = await client.query<{ value: string }>(
        'SELECT value FROM projection_meta WHERE key = $1',
        [PROJECTION_SEQ_KEY]
      );
      const row = result.rows[0];
      return row === undefined ? 0 : Number(row.value);
    },
    setProjectionSeq: async (seq) => {
      await client.query(
        `INSERT INTO projection_meta (key, value) VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
        [PROJECTION_SEQ_KEY, seq]
      );
    },
    clearCounters: async () => {
      await client.query('DELETE FROM budget_counters');
    },
    readAllEntries: async () => {
      const result = await client.query<{ entry_json: string }>(
        'SELECT entry_json FROM ledger_entries ORDER BY seq ASC'
      );
      return result.rows.map((row) => JSON.parse(row.entry_json) as unknown);
    },
    readAllCounters: async () => {
      const result = await client.query<{
        scope_key: string;
        reserved_micros: string;
        settled_micros: string;
        intents: string;
      }>('SELECT scope_key, reserved_micros, settled_micros, intents FROM budget_counters');
      const counters = new Map<string, SpendCounter>();
      for (const row of result.rows) {
        counters.set(row.scope_key, {
          reservedMicros: Number(row.reserved_micros),
          settledMicros: Number(row.settled_micros),
          intents: Number(row.intents),
        });
      }
      return counters;
    },
    getRevocation: async (subject) => {
      const result = await client.query<{
        revoked: boolean;
        status_index: string;
        updated_at: string;
        entry_hash: string;
      }>(
        'SELECT revoked, status_index, updated_at, entry_hash FROM revocation_status WHERE subject = $1',
        [subject]
      );
      const row = result.rows[0];
      return row === undefined
        ? null
        : {
            subject,
            revoked: row.revoked,
            statusIndex: Number(row.status_index),
            updatedAt: row.updated_at,
            entryHash: row.entry_hash,
          };
    },
    putRevocation: async (record: RevocationRecord) => {
      await client.query(
        `INSERT INTO revocation_status (subject, revoked, status_index, updated_at, entry_hash)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (subject) DO UPDATE SET
           revoked = EXCLUDED.revoked,
           status_index = EXCLUDED.status_index,
           updated_at = EXCLUDED.updated_at,
           entry_hash = EXCLUDED.entry_hash`,
        [record.subject, record.revoked, record.statusIndex, record.updatedAt, record.entryHash]
      );
    },
    allocateStatusIndex: async () => {
      const result = await client.query<{ value: string }>(
        'SELECT value FROM projection_meta WHERE key = $1',
        [REVOCATION_INDEX_KEY]
      );
      const next = result.rows[0] === undefined ? 0 : Number(result.rows[0].value);
      await client.query(
        `INSERT INTO projection_meta (key, value) VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
        [REVOCATION_INDEX_KEY, next + 1]
      );
      return next;
    },
    readAllRevocations: async () => {
      const result = await client.query<{
        subject: string;
        revoked: boolean;
        status_index: string;
        updated_at: string;
        entry_hash: string;
      }>('SELECT subject, revoked, status_index, updated_at, entry_hash FROM revocation_status');
      return result.rows.map((row) => ({
        subject: row.subject,
        revoked: row.revoked,
        statusIndex: Number(row.status_index),
        updatedAt: row.updated_at,
        entryHash: row.entry_hash,
      }));
    },
    clearRevocations: async () => {
      await client.query('DELETE FROM revocation_status');
      await client.query('DELETE FROM projection_meta WHERE key = $1', [REVOCATION_INDEX_KEY]);
    },
  };
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
