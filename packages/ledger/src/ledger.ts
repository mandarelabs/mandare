import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

import {
  GENESIS_PREV_HASH,
  bytesToBase64Url,
  computeEntryHash,
  hexToBytes,
  parseLedgerEntry,
  type LedgerAction,
  type LedgerCost,
  type LedgerEntryPreimage,
  type LedgerEntryV1,
} from '@mandarelabs/spec';

import { loadOrCreateDoorKey, type DoorKey } from './door-key.js';

/**
 * Append-only, hash-chained ledger on `node:sqlite` (BUILD-DECISIONS Q7).
 *
 * Integrity locks implemented at this tier:
 * - lock 1 (privilege separation): this module is meant to run inside a door
 *   process; the agent gets no handle to it.
 * - lock 2 (append-only): no update/delete API; SQLite triggers RAISE on
 *   UPDATE/DELETE; monotonic seq without gaps.
 * Locks 3–5 (log-before-act, witnessing, witness-ack) live in the doors (S2)
 * and the witness client (S6).
 */

export interface AppendInput {
  actor: string;
  mandate_id: string;
  action: LedgerAction;
  cost: LedgerCost;
  outcome_ref?: string;
  correction_of?: string;
  hw_counter?: number;
}

export interface LedgerHead {
  seq: number;
  entry_hash: string;
}

export interface LedgerMeta {
  schema_version: number;
  door_id: string;
  door_public_key: string;
  door_key_id: string;
  created_at: string;
}

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

const SALT_BYTES = 16;

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
   * Open (or create) a ledger for one door. One door per ledger DB at this
   * tier; multi-door ledgers arrive with S1.
   */
  static open(dbPath: string, options: { doorId: string; keyPath?: string }): Ledger {
    const db = new DatabaseSync(dbPath);
    db.exec('PRAGMA journal_mode = WAL;');
    // FULL, not WAL-default NORMAL: a committed intent entry must survive
    // power loss, or log-before-act (R3) silently breaks — the provider call
    // would have executed with its intent record gone.
    db.exec('PRAGMA synchronous = FULL;');
    // Contending writers wait instead of failing instantly with SQLITE_BUSY.
    db.exec('PRAGMA busy_timeout = 5000;');
    db.exec(CREATE_SCHEMA);
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
      const head = this.head();
      const preimage: LedgerEntryPreimage = {
        schema_version: 1,
        seq: head === null ? 1 : head.seq + 1,
        ...(input.hw_counter === undefined ? {} : { hw_counter: input.hw_counter }),
        ts: new Date().toISOString(),
        door_id: this.doorId,
        actor: input.actor,
        mandate_id: input.mandate_id,
        action: input.action,
        cost: input.cost,
        ...(input.outcome_ref === undefined ? {} : { outcome_ref: input.outcome_ref }),
        ...(input.correction_of === undefined ? {} : { correction_of: input.correction_of }),
        salt: randomBytes(SALT_BYTES).toString('hex'),
        prev_hash: head === null ? GENESIS_PREV_HASH : head.entry_hash,
      };
      const entryHash = computeEntryHash(preimage);
      const entry: LedgerEntryV1 = {
        ...preimage,
        entry_hash: entryHash,
        door_signature: {
          alg: 'EdDSA',
          key_id: this.doorKey.keyId,
          key_provenance: this.doorKey.provenance,
          value: bytesToBase64Url(this.doorKey.sign(hexToBytes(entryHash))),
        },
      };
      // Boundary validation before persisting — hostile input dies here (R4),
      // and nothing schema-invalid can ever enter the chain.
      parseLedgerEntry(entry);

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
      insert.run('schema_version', '1');
      insert.run('door_id', this.doorId);
      insert.run('door_public_key', this.doorKey.publicKeyHex);
      insert.run('door_key_id', this.doorKey.keyId);
      insert.run('created_at', new Date().toISOString());
      return;
    }
    if (existing.door_key_id !== this.doorKey.keyId) {
      throw new Error(
        `ledger was created by door key ${existing.door_key_id.slice(0, 12)}…, ` +
          `but the loaded key is ${this.doorKey.keyId.slice(0, 12)}… — refusing to write`
      );
    }
    if (existing.door_id !== this.doorId) {
      throw new Error(
        `ledger belongs to door '${existing.door_id}', not '${this.doorId}' — one door per ledger DB (S1 adds multi-door)`
      );
    }
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
  const map = new Map(rows.map((row) => [row.key, row.value]));
  const doorId = map.get('door_id');
  const doorPublicKey = map.get('door_public_key');
  const doorKeyId = map.get('door_key_id');
  const createdAt = map.get('created_at');
  const schemaVersion = map.get('schema_version');
  if (
    doorId === undefined ||
    doorPublicKey === undefined ||
    doorKeyId === undefined ||
    createdAt === undefined ||
    schemaVersion === undefined
  ) {
    throw new Error('ledger metadata is incomplete');
  }
  return {
    schema_version: Number(schemaVersion),
    door_id: doorId,
    door_public_key: doorPublicKey,
    door_key_id: doorKeyId,
    created_at: createdAt,
  };
}
