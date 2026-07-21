import { DatabaseSync } from 'node:sqlite';

import type { LedgerEntryV1 } from '@mandarelabs/spec';

import type { LedgerHead } from './entry.js';
import type { LedgerStore } from './store.js';

/**
 * `LedgerStore` driver over `node:sqlite` — the same storage the sync
 * `Ledger` uses (schema and pragmas identical), exposed through the shared
 * driver interface so `AsyncLedger` runs unchanged on SQLite and Postgres.
 * The sync `Ledger` facade stays for the S0 gateway; S2 migrates the doors
 * to `AsyncLedger` + a store.
 */

const CREATE_SCHEMA = `
CREATE TABLE IF NOT EXISTS ledger_entries (
  seq        INTEGER PRIMARY KEY CHECK (seq >= 1),
  entry_hash TEXT NOT NULL UNIQUE,
  prev_hash  TEXT NOT NULL,
  entry_json TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS ledger_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
) STRICT;
CREATE TRIGGER IF NOT EXISTS ledger_entries_no_update
  BEFORE UPDATE ON ledger_entries
  BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS ledger_entries_no_delete
  BEFORE DELETE ON ledger_entries
  BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS ledger_meta_no_update
  BEFORE UPDATE ON ledger_meta
  BEGIN SELECT RAISE(ABORT, 'ledger meta is write-once'); END;
CREATE TRIGGER IF NOT EXISTS ledger_meta_no_delete
  BEFORE DELETE ON ledger_meta
  BEGIN SELECT RAISE(ABORT, 'ledger meta is write-once'); END;
`;

/**
 * Open the SQLite database with the ledger schema, append-only triggers, and
 * durability pragmas. Shared by `SqliteStore` and the sync `Ledger` so the
 * two never drift.
 */
export function openSqliteDatabase(dbPath: string): DatabaseSync {
  const db = new DatabaseSync(dbPath);
  db.exec('PRAGMA journal_mode = WAL;');
  // FULL, not WAL-default NORMAL: a committed intent entry must survive
  // power loss, or log-before-act (R3) silently breaks — the provider call
  // would have executed with its intent record gone.
  db.exec('PRAGMA synchronous = FULL;');
  // Contending writers wait instead of failing instantly with SQLITE_BUSY.
  db.exec('PRAGMA busy_timeout = 5000;');
  db.exec(CREATE_SCHEMA);
  return db;
}

export class SqliteStore implements LedgerStore {
  private readonly db: DatabaseSync;

  private constructor(db: DatabaseSync) {
    this.db = db;
  }

  static open(dbPath: string): SqliteStore {
    return new SqliteStore(openSqliteDatabase(dbPath));
  }

  // Methods are `async` so synchronous SQLite errors surface as rejections,
  // matching the driver contract exactly.
  async appendWithLock(build: (head: LedgerHead | null) => LedgerEntryV1): Promise<LedgerEntryV1> {
    this.db.exec('BEGIN IMMEDIATE;');
    try {
      const entry = build(this.headSync());
      this.db
        .prepare(
          'INSERT INTO ledger_entries (seq, entry_hash, prev_hash, entry_json) VALUES (?, ?, ?, ?)'
        )
        .run(entry.seq, entry.entry_hash, entry.prev_hash, JSON.stringify(entry));
      this.db.exec('COMMIT;');
      return entry;
    } catch (error) {
      this.db.exec('ROLLBACK;');
      throw error;
    }
  }

  head(): Promise<LedgerHead | null> {
    return Promise.resolve(this.headSync());
  }

  readMetaRows(): Promise<Map<string, string> | null> {
    const rows = this.db.prepare('SELECT key, value FROM ledger_meta').all() as {
      key: string;
      value: string;
    }[];
    return Promise.resolve(
      rows.length === 0 ? null : new Map(rows.map((row) => [row.key, row.value]))
    );
  }

  initMeta(rows: readonly [string, string][]): Promise<void> {
    const insert = this.db.prepare('INSERT INTO ledger_meta (key, value) VALUES (?, ?)');
    for (const [key, value] of rows) {
      insert.run(key, value);
    }
    return Promise.resolve();
  }

  readAllEntries(): Promise<unknown[]> {
    const rows = this.db
      .prepare('SELECT entry_json FROM ledger_entries ORDER BY seq ASC')
      .all() as { entry_json: string }[];
    return Promise.resolve(rows.map((row) => JSON.parse(row.entry_json) as unknown));
  }

  close(): Promise<void> {
    this.db.close();
    return Promise.resolve();
  }

  private headSync(): LedgerHead | null {
    const row = this.db
      .prepare('SELECT seq, entry_hash FROM ledger_entries ORDER BY seq DESC LIMIT 1')
      .get() as { seq: number; entry_hash: string } | undefined;
    return row === undefined ? null : { seq: row.seq, entry_hash: row.entry_hash };
  }
}
