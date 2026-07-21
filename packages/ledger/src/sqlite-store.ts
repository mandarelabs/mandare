import { DatabaseSync } from 'node:sqlite';

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
-- Spend-counter PROJECTION (S2): derived from the ledger, rebuildable from
-- it at any time — deliberately mutable, so NO append-only triggers here.
-- Integrity comes from replay(ledger) == counters, not from storage locks.
CREATE TABLE IF NOT EXISTS budget_counters (
  scope_key       TEXT PRIMARY KEY,
  reserved_micros INTEGER NOT NULL,
  settled_micros  INTEGER NOT NULL,
  intents         INTEGER NOT NULL
) STRICT;
-- Revocation PROJECTION (S3): kill-switch state derived from agent.revoke /
-- agent.reinstate entries — also mutable/rebuildable, integrity from
-- replay(ledger) == this table, not from storage locks.
CREATE TABLE IF NOT EXISTS revocation_status (
  subject      TEXT PRIMARY KEY,
  revoked      INTEGER NOT NULL,
  status_index INTEGER NOT NULL,
  updated_at   TEXT NOT NULL,
  entry_hash   TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS projection_meta (
  key   TEXT PRIMARY KEY,
  value INTEGER NOT NULL
) STRICT;
`;

const PROJECTION_SEQ_KEY = 'spend_projection_seq';
const REVOCATION_INDEX_KEY = 'revocation_next_index';

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
  /**
   * In-process transaction mutex. `node:sqlite` is ONE connection, and the
   * projected-append transaction awaits between BEGIN and COMMIT — two
   * concurrent calls would nest transactions and blow up. BEGIN IMMEDIATE
   * only locks out OTHER processes; this chain serializes our own
   * (red-team: the driver-level budget-race test rides on it).
   */
  private txQueue: Promise<unknown> = Promise.resolve();

  private constructor(db: DatabaseSync) {
    this.db = db;
  }

  static open(dbPath: string): SqliteStore {
    return new SqliteStore(openSqliteDatabase(dbPath));
  }

  private serialized<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.txQueue.then(fn, fn);
    this.txQueue = run.catch(() => undefined);
    return run;
  }

  // Methods are `async` so synchronous SQLite errors surface as rejections,
  // matching the driver contract exactly.
  appendWithLock(build: (head: LedgerHead | null) => LedgerEntryV1): Promise<LedgerEntryV1> {
    return this.serialized(() => {
      this.db.exec('BEGIN IMMEDIATE;');
      try {
        const entry = build(this.headSync());
        this.insertEntry(entry);
        this.db.exec('COMMIT;');
        return Promise.resolve(entry);
      } catch (error) {
        this.db.exec('ROLLBACK;');
        throw error;
      }
    });
  }

  appendProjected(
    build: (head: LedgerHead | null) => LedgerEntryV1,
    project: Projector
  ): Promise<AppendProjectedResult> {
    return this.serialized(async () => {
      this.db.exec('BEGIN IMMEDIATE;');
      try {
        const result = await runProjectedAppend({
          tx: this.projectionTx(),
          build,
          project,
          insert: (entry) => {
            this.insertEntry(entry);
            return Promise.resolve();
          },
        });
        if (result.kind === 'refused') {
          // A refused reservation aborts EVERYTHING: no entry, no counter change.
          this.db.exec('ROLLBACK;');
          return result;
        }
        this.db.exec('COMMIT;');
        return result;
      } catch (error) {
        this.db.exec('ROLLBACK;');
        throw error;
      }
    });
  }

  runProjection<T>(fn: (tx: ProjectionTx) => Promise<T>): Promise<T> {
    return this.serialized(async () => {
      this.db.exec('BEGIN IMMEDIATE;');
      try {
        const result = await fn(this.projectionTx());
        this.db.exec('COMMIT;');
        return result;
      } catch (error) {
        this.db.exec('ROLLBACK;');
        throw error;
      }
    });
  }

  private insertEntry(entry: LedgerEntryV1): void {
    this.db
      .prepare(
        'INSERT INTO ledger_entries (seq, entry_hash, prev_hash, entry_json) VALUES (?, ?, ?, ?)'
      )
      .run(entry.seq, entry.entry_hash, entry.prev_hash, JSON.stringify(entry));
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

  private projectionTx(): ProjectionTx {
    return {
      head: () => Promise.resolve(this.headSync()),
      getCounter: (key) => {
        const row = this.db
          .prepare(
            'SELECT reserved_micros, settled_micros, intents FROM budget_counters WHERE scope_key = ?'
          )
          .get(key) as
          | { reserved_micros: number; settled_micros: number; intents: number }
          | undefined;
        return Promise.resolve(
          row === undefined
            ? null
            : {
                reservedMicros: row.reserved_micros,
                settledMicros: row.settled_micros,
                intents: row.intents,
              }
        );
      },
      putCounter: (key, value) => {
        this.db
          .prepare(
            `INSERT INTO budget_counters (scope_key, reserved_micros, settled_micros, intents)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(scope_key) DO UPDATE SET
               reserved_micros = excluded.reserved_micros,
               settled_micros = excluded.settled_micros,
               intents = excluded.intents`
          )
          .run(key, value.reservedMicros, value.settledMicros, value.intents);
        return Promise.resolve();
      },
      getEntryByHash: (entryHash) => {
        const row = this.db
          .prepare('SELECT entry_json FROM ledger_entries WHERE entry_hash = ?')
          .get(entryHash) as { entry_json: string } | undefined;
        return Promise.resolve(
          row === undefined ? null : (JSON.parse(row.entry_json) as unknown)
        );
      },
      getProjectionSeq: () => {
        const row = this.db
          .prepare('SELECT value FROM projection_meta WHERE key = ?')
          .get(PROJECTION_SEQ_KEY) as { value: number } | undefined;
        return Promise.resolve(row?.value ?? 0);
      },
      setProjectionSeq: (seq) => {
        this.db
          .prepare(
            'INSERT INTO projection_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
          )
          .run(PROJECTION_SEQ_KEY, seq);
        return Promise.resolve();
      },
      clearCounters: () => {
        this.db.exec('DELETE FROM budget_counters;');
        return Promise.resolve();
      },
      readAllEntries: () => {
        const rows = this.db
          .prepare('SELECT entry_json FROM ledger_entries ORDER BY seq ASC')
          .all() as { entry_json: string }[];
        return Promise.resolve(rows.map((row) => JSON.parse(row.entry_json) as unknown));
      },
      readAllCounters: () => {
        const rows = this.db
          .prepare('SELECT scope_key, reserved_micros, settled_micros, intents FROM budget_counters')
          .all() as {
          scope_key: string;
          reserved_micros: number;
          settled_micros: number;
          intents: number;
        }[];
        const counters = new Map<string, SpendCounter>();
        for (const row of rows) {
          counters.set(row.scope_key, {
            reservedMicros: row.reserved_micros,
            settledMicros: row.settled_micros,
            intents: row.intents,
          });
        }
        return Promise.resolve(counters);
      },
      getRevocation: (subject) => {
        const row = this.db
          .prepare(
            'SELECT revoked, status_index, updated_at, entry_hash FROM revocation_status WHERE subject = ?'
          )
          .get(subject) as
          | { revoked: number; status_index: number; updated_at: string; entry_hash: string }
          | undefined;
        return Promise.resolve(
          row === undefined
            ? null
            : {
                subject,
                revoked: row.revoked !== 0,
                statusIndex: row.status_index,
                updatedAt: row.updated_at,
                entryHash: row.entry_hash,
              }
        );
      },
      putRevocation: (record: RevocationRecord) => {
        this.db
          .prepare(
            `INSERT INTO revocation_status (subject, revoked, status_index, updated_at, entry_hash)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(subject) DO UPDATE SET
               revoked = excluded.revoked,
               status_index = excluded.status_index,
               updated_at = excluded.updated_at,
               entry_hash = excluded.entry_hash`
          )
          .run(
            record.subject,
            record.revoked ? 1 : 0,
            record.statusIndex,
            record.updatedAt,
            record.entryHash
          );
        return Promise.resolve();
      },
      allocateStatusIndex: () => {
        const row = this.db
          .prepare('SELECT value FROM projection_meta WHERE key = ?')
          .get(REVOCATION_INDEX_KEY) as { value: number } | undefined;
        const next = row?.value ?? 0;
        this.db
          .prepare(
            'INSERT INTO projection_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
          )
          .run(REVOCATION_INDEX_KEY, next + 1);
        return Promise.resolve(next);
      },
      readAllRevocations: () => {
        const rows = this.db
          .prepare(
            'SELECT subject, revoked, status_index, updated_at, entry_hash FROM revocation_status'
          )
          .all() as {
          subject: string;
          revoked: number;
          status_index: number;
          updated_at: string;
          entry_hash: string;
        }[];
        return Promise.resolve(
          rows.map((row) => ({
            subject: row.subject,
            revoked: row.revoked !== 0,
            statusIndex: row.status_index,
            updatedAt: row.updated_at,
            entryHash: row.entry_hash,
          }))
        );
      },
      clearRevocations: () => {
        this.db.exec('DELETE FROM revocation_status;');
        this.db.prepare('DELETE FROM projection_meta WHERE key = ?').run(REVOCATION_INDEX_KEY);
        return Promise.resolve();
      },
    };
  }

  private headSync(): LedgerHead | null {
    const row = this.db
      .prepare('SELECT seq, entry_hash FROM ledger_entries ORDER BY seq DESC LIMIT 1')
      .get() as { seq: number; entry_hash: string } | undefined;
    return row === undefined ? null : { seq: row.seq, entry_hash: row.entry_hash };
  }
}
