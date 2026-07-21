import { DatabaseSync } from 'node:sqlite';

import type { LedgerEntryV1 } from '@mandarelabs/spec';

import { loadOrCreateDoorKey, type DoorKey } from './door-key.js';
import { buildEntry, type AppendInput, type LedgerHead } from './entry.js';
import { openSqliteDatabase } from './sqlite-store.js';
import { assertDoorOwnsMeta, metaFromRows, newMetaRows, type LedgerMeta } from './store.js';

export type { AppendInput, LedgerHead } from './entry.js';
export type { LedgerMeta } from './store.js';

/**
 * Append-only, hash-chained ledger on `node:sqlite` (BUILD-DECISIONS Q7) —
 * the SOLO-mode driver, synchronous like `node:sqlite` itself. The Postgres
 * team-mode driver lives in `pg-store.ts` behind the shared `LedgerStore`
 * interface; both produce identical chains via `buildEntry`.
 *
 * Integrity locks implemented at this tier:
 * - lock 1 (privilege separation): this module is meant to run inside a door
 *   process; the agent gets no handle to it.
 * - lock 2 (append-only): no update/delete API; SQLite triggers RAISE on
 *   UPDATE/DELETE; monotonic seq without gaps.
 * Locks 3–5 (log-before-act, witnessing, witness-ack) live in the doors (S2)
 * and the witness client (S6).
 */

export class Ledger {
  readonly doorId: string;
  readonly doorKeyId: string;
  readonly doorPublicKeyHex: string;

  private readonly db: DatabaseSync;
  private readonly doorKey: DoorKey;

  private constructor(db: DatabaseSync, doorKey: DoorKey, doorId: string) {
    this.db = db;
    this.doorKey = doorKey;
    this.doorId = doorId;
    this.doorKeyId = doorKey.keyId;
    this.doorPublicKeyHex = doorKey.publicKeyHex;
  }

  /**
   * Open (or create) a ledger for one door. One WRITING door key per ledger
   * DB at this tier; multi-door chains are verified via the key directory
   * (S1) — a multi-key writer arrives with the S3 keychain work.
   */
  static open(dbPath: string, options: { doorId: string; keyPath?: string }): Ledger {
    const db = openSqliteDatabase(dbPath);
    const doorKey = loadOrCreateDoorKey(options.keyPath ?? `${dbPath}.doorkey.pem`);
    const ledger = new Ledger(db, doorKey, options.doorId);
    ledger.initOrCheckMeta();
    return ledger;
  }

  append(input: AppendInput): LedgerEntryV1 {
    // BEGIN IMMEDIATE: take the write lock before reading the head so two
    // writer processes cannot race to the same seq.
    this.db.exec('BEGIN IMMEDIATE;');
    try {
      const entry = buildEntry(input, this.head(), this.doorId, this.doorKey);
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

  head(): LedgerHead | null {
    const row = this.db
      .prepare('SELECT seq, entry_hash FROM ledger_entries ORDER BY seq DESC LIMIT 1')
      .get() as { seq: number; entry_hash: string } | undefined;
    return row === undefined ? null : { seq: row.seq, entry_hash: row.entry_hash };
  }

  close(): void {
    this.db.close();
  }

  private initOrCheckMeta(): void {
    const existing = readMetaFromDb(this.db);
    if (existing === null) {
      const insert = this.db.prepare('INSERT INTO ledger_meta (key, value) VALUES (?, ?)');
      for (const [key, value] of newMetaRows(this.doorId, this.doorKey, new Date().toISOString())) {
        insert.run(key, value);
      }
      return;
    }
    assertDoorOwnsMeta(existing, this.doorKey, this.doorId);
  }
}

/**
 * Read a ledger file for verification/inspection. Entries are returned as
 * UNVALIDATED parsed JSON — verification (schema, chain, signatures) is the
 * verifier's job, and pre-validating here would mask tampering.
 *
 * TRUST WARNING: `meta.door_public_key` comes from the file itself. An
 * attacker with file access can re-sign the whole chain under a swapped key,
 * and self-anchored verification will pass (see red-team suite). Independent
 * verification MUST obtain the door key out-of-band (key directory — S1;
 * witnessed heads — S6). The meta value is a convenience anchor only.
 */
export function readLedger(dbPath: string): { meta: LedgerMeta; entries: unknown[] } {
  const db = new DatabaseSync(dbPath, { readOnly: true });
  try {
    const meta = readMetaFromDb(db);
    if (meta === null) {
      throw new Error(`${dbPath} has no ledger metadata — not a Mandare ledger?`);
    }
    const rows = db
      .prepare('SELECT entry_json FROM ledger_entries ORDER BY seq ASC')
      .all() as { entry_json: string }[];
    const entries = rows.map((row) => JSON.parse(row.entry_json) as unknown);
    return { meta, entries };
  } finally {
    db.close();
  }
}

function readMetaFromDb(db: DatabaseSync): LedgerMeta | null {
  const rows = db.prepare('SELECT key, value FROM ledger_meta').all() as {
    key: string;
    value: string;
  }[];
  if (rows.length === 0) {
    return null;
  }
  return metaFromRows(new Map(rows.map((row) => [row.key, row.value])));
}
