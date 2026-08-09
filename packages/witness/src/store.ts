import { DatabaseSync } from 'node:sqlite';

import type { EpochSummary, WitnessedHeadRecord } from '@mandarelabs/witness-protocol';
import type { TreeHead } from '@mandarelabs/verifier';

/**
 * Witness-side storage (reference implementation, single tenant): per-source
 * witnessed head history + anchoring epochs, over `node:sqlite` (Q7). The
 * head history is the witness's whole value — it gets the same storage-
 * enforced append-only posture as the ledger itself (integrity lock 2
 * applied to the witness): heads and sources refuse UPDATE/DELETE, and an
 * epoch's commitment columns are immutable (only its anchor receipt may
 * progress pending → confirmed).
 */

const CREATE_SCHEMA = `
CREATE TABLE IF NOT EXISTS witness_sources (
  source_id  TEXT PRIMARY KEY,
  public_key TEXT NOT NULL,
  first_seen TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS witness_heads (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  source_id       TEXT NOT NULL,
  size            INTEGER NOT NULL,
  root            TEXT NOT NULL,
  ts              TEXT NOT NULL,
  witnessed_at    TEXT NOT NULL,
  submission_json TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS witness_heads_by_source ON witness_heads (source_id, id);
CREATE TABLE IF NOT EXISTS witness_epochs (
  epoch          INTEGER PRIMARY KEY,
  created_at     TEXT NOT NULL,
  aggregate_size INTEGER NOT NULL,
  aggregate_root TEXT NOT NULL,
  leaves_json    TEXT NOT NULL,
  anchor_kind    TEXT,
  anchor_status  TEXT NOT NULL,
  ots_base64     TEXT
) STRICT;
CREATE TRIGGER IF NOT EXISTS witness_sources_no_update
  BEFORE UPDATE ON witness_sources
  BEGIN SELECT RAISE(ABORT, 'witness sources are write-once'); END;
CREATE TRIGGER IF NOT EXISTS witness_sources_no_delete
  BEFORE DELETE ON witness_sources
  BEGIN SELECT RAISE(ABORT, 'witness sources are write-once'); END;
CREATE TRIGGER IF NOT EXISTS witness_heads_no_update
  BEFORE UPDATE ON witness_heads
  BEGIN SELECT RAISE(ABORT, 'witnessed head history is append-only'); END;
CREATE TRIGGER IF NOT EXISTS witness_heads_no_delete
  BEFORE DELETE ON witness_heads
  BEGIN SELECT RAISE(ABORT, 'witnessed head history is append-only'); END;
CREATE TRIGGER IF NOT EXISTS witness_epochs_no_delete
  BEFORE DELETE ON witness_epochs
  BEGIN SELECT RAISE(ABORT, 'epochs are append-only'); END;
CREATE TRIGGER IF NOT EXISTS witness_epochs_guard_update
  BEFORE UPDATE ON witness_epochs
  BEGIN SELECT CASE WHEN
      OLD.epoch          IS NOT NEW.epoch          OR
      OLD.created_at     IS NOT NEW.created_at     OR
      OLD.aggregate_size IS NOT NEW.aggregate_size OR
      OLD.aggregate_root IS NOT NEW.aggregate_root OR
      OLD.leaves_json    IS NOT NEW.leaves_json
    THEN RAISE(ABORT, 'epoch commitments are immutable — only the anchor receipt may progress')
  END; END;
-- The anchor receipt PROGRESSES; it never regresses. A confirmed epoch is
-- frozen, and a set receipt cannot be nulled out — otherwise a witness-DB
-- attacker could quietly erase public-anchoring evidence (review S6-M4).
CREATE TRIGGER IF NOT EXISTS witness_epochs_anchor_progress
  BEFORE UPDATE ON witness_epochs
  BEGIN SELECT CASE WHEN
      (OLD.anchor_status = 'confirmed' AND (
         OLD.anchor_status IS NOT NEW.anchor_status OR
         OLD.anchor_kind   IS NOT NEW.anchor_kind   OR
         OLD.ots_base64    IS NOT NEW.ots_base64))
      OR (OLD.ots_base64 IS NOT NULL AND NEW.ots_base64 IS NULL)
      OR (NEW.anchor_status = 'none' AND OLD.anchor_status <> 'none')
    THEN RAISE(ABORT, 'the anchor receipt may only progress none→pending→confirmed and is frozen once confirmed')
  END; END;
`;

export interface EpochRow {
  epoch: number;
  created_at: string;
  aggregate: TreeHead;
  leaves: WitnessedHeadRecord[];
  anchor_kind: string | null;
  anchor_status: 'none' | 'pending' | 'confirmed';
  ots_base64: string | null;
}

export function epochSummary(row: EpochRow): EpochSummary {
  return {
    epoch: row.epoch,
    created_at: row.created_at,
    aggregate: { size: row.aggregate.size, root: row.aggregate.root },
    anchor_status: row.anchor_status,
    ots_base64: row.ots_base64,
    anchor_kind: row.anchor_kind,
  };
}

export class WitnessStore {
  private readonly db: DatabaseSync;

  constructor(dbPath: string) {
    this.db = new DatabaseSync(dbPath);
    this.db.exec('PRAGMA journal_mode = WAL;');
    // A witnessed head must survive power loss — the ack the door acted on
    // is a promise of durable recording (lock 5 depends on it).
    this.db.exec('PRAGMA synchronous = FULL;');
    this.db.exec('PRAGMA busy_timeout = 5000;');
    this.db.exec(CREATE_SCHEMA);
  }

  /** Registered public key for a source, or null on first contact. */
  sourcePublicKey(sourceId: string): string | null {
    const row = this.db
      .prepare('SELECT public_key FROM witness_sources WHERE source_id = ?')
      .get(sourceId) as { public_key: string } | undefined;
    return row?.public_key ?? null;
  }

  latestHead(sourceId: string): WitnessedHeadRecord | null {
    const row = this.db
      .prepare(
        'SELECT source_id, size, root, ts, witnessed_at FROM witness_heads WHERE source_id = ? ORDER BY id DESC LIMIT 1'
      )
      .get(sourceId) as
      | { source_id: string; size: number; root: string; ts: string; witnessed_at: string }
      | undefined;
    return row === undefined ? null : rowToRecord(row);
  }

  history(sourceId: string, limit: number): WitnessedHeadRecord[] {
    const rows = this.db
      .prepare(
        'SELECT source_id, size, root, ts, witnessed_at FROM witness_heads WHERE source_id = ? ORDER BY id DESC LIMIT ?'
      )
      .all(sourceId, limit) as {
      source_id: string;
      size: number;
      root: string;
      ts: string;
      witnessed_at: string;
    }[];
    return rows.map(rowToRecord).reverse();
  }

  /**
   * Record a witnessed head inside one IMMEDIATE transaction, re-checking
   * that the latest head is still the one the (async) verification ran
   * against — two concurrent submissions cannot both extend the same prev.
   * Returns false when the head moved (caller answers 409, client retries).
   */
  appendHead(args: {
    record: WitnessedHeadRecord;
    publicKey: string;
    submissionJson: string;
    expectedPrev: { size: number; root: string } | null;
  }): boolean {
    this.db.exec('BEGIN IMMEDIATE;');
    try {
      const latest = this.latestHead(args.record.source_id);
      const prevMatches =
        args.expectedPrev === null
          ? latest === null
          : latest !== null &&
            latest.head.size === args.expectedPrev.size &&
            latest.head.root === args.expectedPrev.root;
      if (!prevMatches) {
        this.db.exec('ROLLBACK;');
        return false;
      }
      this.db
        .prepare(
          'INSERT OR IGNORE INTO witness_sources (source_id, public_key, first_seen) VALUES (?, ?, ?)'
        )
        .run(args.record.source_id, args.publicKey, args.record.witnessed_at);
      this.db
        .prepare(
          'INSERT INTO witness_heads (source_id, size, root, ts, witnessed_at, submission_json) VALUES (?, ?, ?, ?, ?, ?)'
        )
        .run(
          args.record.source_id,
          args.record.head.size,
          args.record.head.root,
          args.record.ts,
          args.record.witnessed_at,
          args.submissionJson
        );
      this.db.exec('COMMIT;');
      return true;
    } catch (error) {
      this.db.exec('ROLLBACK;');
      throw error;
    }
  }

  /** Latest witnessed head per source — the aggregate's leaf set. */
  latestHeads(): WitnessedHeadRecord[] {
    const rows = this.db
      .prepare(
        `SELECT h.source_id, h.size, h.root, h.ts, h.witnessed_at
           FROM witness_heads h
           JOIN (SELECT source_id, MAX(id) AS max_id FROM witness_heads GROUP BY source_id) latest
             ON latest.max_id = h.id
          ORDER BY h.source_id`
      )
      .all() as { source_id: string; size: number; root: string; ts: string; witnessed_at: string }[];
    return rows.map(rowToRecord);
  }

  createEpoch(args: {
    createdAt: string;
    aggregate: TreeHead;
    leaves: WitnessedHeadRecord[];
  }): number {
    this.db.exec('BEGIN IMMEDIATE;');
    try {
      const row = this.db.prepare('SELECT COALESCE(MAX(epoch), 0) AS max FROM witness_epochs').get() as {
        max: number;
      };
      const epoch = row.max + 1;
      this.db
        .prepare(
          'INSERT INTO witness_epochs (epoch, created_at, aggregate_size, aggregate_root, leaves_json, anchor_kind, anchor_status, ots_base64) VALUES (?, ?, ?, ?, ?, NULL, ?, NULL)'
        )
        .run(epoch, args.createdAt, args.aggregate.size, args.aggregate.root, JSON.stringify(args.leaves), 'none');
      this.db.exec('COMMIT;');
      return epoch;
    } catch (error) {
      this.db.exec('ROLLBACK;');
      throw error;
    }
  }

  setEpochAnchor(
    epoch: number,
    anchor: { kind: string; status: 'pending' | 'confirmed'; otsBase64: string }
  ): void {
    this.db
      .prepare('UPDATE witness_epochs SET anchor_kind = ?, anchor_status = ?, ots_base64 = ? WHERE epoch = ?')
      .run(anchor.kind, anchor.status, anchor.otsBase64, epoch);
  }

  getEpoch(epoch: number): EpochRow | null {
    const row = this.db.prepare('SELECT * FROM witness_epochs WHERE epoch = ?').get(epoch) as
      | {
          epoch: number;
          created_at: string;
          aggregate_size: number;
          aggregate_root: string;
          leaves_json: string;
          anchor_kind: string | null;
          anchor_status: string;
          ots_base64: string | null;
        }
      | undefined;
    return row === undefined ? null : toEpochRow(row);
  }

  latestEpoch(): EpochRow | null {
    const row = this.db
      .prepare('SELECT * FROM witness_epochs ORDER BY epoch DESC LIMIT 1')
      .get() as
      | {
          epoch: number;
          created_at: string;
          aggregate_size: number;
          aggregate_root: string;
          leaves_json: string;
          anchor_kind: string | null;
          anchor_status: string;
          ots_base64: string | null;
        }
      | undefined;
    return row === undefined ? null : toEpochRow(row);
  }

  stats(): { sources: number; heads: number; epochs: number } {
    const sources = this.db.prepare('SELECT COUNT(*) AS n FROM witness_sources').get() as { n: number };
    const heads = this.db.prepare('SELECT COUNT(*) AS n FROM witness_heads').get() as { n: number };
    const epochs = this.db.prepare('SELECT COUNT(*) AS n FROM witness_epochs').get() as { n: number };
    return { sources: sources.n, heads: heads.n, epochs: epochs.n };
  }

  close(): void {
    this.db.close();
  }
}

function rowToRecord(row: {
  source_id: string;
  size: number;
  root: string;
  ts: string;
  witnessed_at: string;
}): WitnessedHeadRecord {
  return {
    source_id: row.source_id,
    head: { size: row.size, root: row.root },
    ts: row.ts,
    witnessed_at: row.witnessed_at,
  };
}

function toEpochRow(row: {
  epoch: number;
  created_at: string;
  aggregate_size: number;
  aggregate_root: string;
  leaves_json: string;
  anchor_kind: string | null;
  anchor_status: string;
  ots_base64: string | null;
}): EpochRow {
  const status = row.anchor_status;
  if (status !== 'none' && status !== 'pending' && status !== 'confirmed') {
    throw new Error(`epoch ${row.epoch} has a corrupt anchor_status '${status}'`);
  }
  return {
    epoch: row.epoch,
    created_at: row.created_at,
    aggregate: { size: row.aggregate_size, root: row.aggregate_root },
    leaves: JSON.parse(row.leaves_json) as WitnessedHeadRecord[],
    anchor_kind: row.anchor_kind,
    anchor_status: status,
    ots_base64: row.ots_base64,
  };
}
