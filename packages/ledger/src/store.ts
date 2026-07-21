import type { LedgerEntryV1 } from '@mandarelabs/spec';

import type { DoorKey } from './door-key.js';
import type { LedgerHead } from './entry.js';
import type { CounterKV, ProjectionRefusal, SpendCounter } from './projection.js';

/**
 * The thin driver interface behind the ledger (BUILD-DECISIONS Q7): SQLite
 * for solo mode, Postgres for team mode. A store persists rows — chain
 * semantics (hashing, signing, validation) live above it in the ledger and
 * are identical across drivers.
 *
 * Storage-enforcement duties of every driver (integrity lock 2):
 * - entries and meta must reject UPDATE/DELETE at the storage layer
 *   (SQLite triggers; Postgres INSERT-only grants + RAISE triggers);
 * - `seq` is the primary key: in-place replays die on the constraint;
 * - appends allocate seq under an exclusive lock so writers cannot race.
 */

export interface LedgerMeta {
  schema_version: number;
  door_id: string;
  door_public_key: string;
  door_key_id: string;
  created_at: string;
}

/** Result of an append that runs a projection guard inside the transaction. */
export type AppendProjectedResult =
  | { kind: 'appended'; entry: LedgerEntryV1 }
  | { kind: 'refused'; refusal: ProjectionRefusal };

export type Projector = (
  kv: CounterKV,
  entry: LedgerEntryV1
) => Promise<ProjectionRefusal | null>;

/** Counter-table view inside one store transaction (drivers implement). */
export interface ProjectionTx extends CounterKV {
  head(): Promise<LedgerHead | null>;
  /** Seq of the last entry the projection has applied; 0 for a fresh table. */
  getProjectionSeq(): Promise<number>;
  setProjectionSeq(seq: number): Promise<void>;
  clearCounters(): Promise<void>;
  readAllEntries(): Promise<unknown[]>;
  readAllCounters(): Promise<Map<string, SpendCounter>>;
}

/** The projection lags or leads the ledger — every caller must fail closed (R1). */
export class ProjectionStaleError extends Error {
  constructor(projectionSeq: number, headSeq: number) {
    super(
      `spend projection is at seq ${projectionSeq} but the ledger head is ${headSeq} — ` +
        'refusing to spend against stale counters (fail-closed); rebuild the projection from the ledger'
    );
    this.name = 'ProjectionStaleError';
  }
}

export interface LedgerStore {
  /**
   * Read the current head, build the next entry via `build`, and insert it —
   * all while holding the store's exclusive append lock, so two writer
   * processes can never allocate the same seq.
   */
  appendWithLock(build: (head: LedgerHead | null) => LedgerEntryV1): Promise<LedgerEntryV1>;
  /**
   * Append + counter projection in ONE transaction under the append lock:
   * staleness check → build → project (a refusal aborts everything — no
   * entry, no counter change) → insert → projection seq bump → commit.
   */
  appendProjected(
    build: (head: LedgerHead | null) => LedgerEntryV1,
    project: Projector
  ): Promise<AppendProjectedResult>;
  /** Run `fn` in a transaction that is exclusive with appends (rebuild/verify). */
  runProjection<T>(fn: (tx: ProjectionTx) => Promise<T>): Promise<T>;
  head(): Promise<LedgerHead | null>;
  /** Raw meta key/value rows; null when the store is empty (fresh ledger). */
  readMetaRows(): Promise<Map<string, string> | null>;
  /** Write meta once, at ledger creation. Write-once is storage-enforced. */
  initMeta(rows: readonly [string, string][]): Promise<void>;
  /** All entries in seq order, JSON-parsed but UNVALIDATED (verifier's job). */
  readAllEntries(): Promise<unknown[]>;
  close(): Promise<void>;
}

/**
 * Driver-shared body of `appendProjected` — drivers supply the transaction
 * plumbing and the row insert; ordering and fail-closed semantics live here
 * once so SQLite and Postgres cannot drift.
 */
export async function runProjectedAppend(args: {
  tx: ProjectionTx;
  build: (head: LedgerHead | null) => LedgerEntryV1;
  project: Projector;
  insert: (entry: LedgerEntryV1) => Promise<void>;
}): Promise<AppendProjectedResult> {
  const head = await args.tx.head();
  const headSeq = head?.seq ?? 0;
  const projectionSeq = await args.tx.getProjectionSeq();
  if (projectionSeq !== headSeq) {
    throw new ProjectionStaleError(projectionSeq, headSeq);
  }
  const entry = args.build(head);
  const refusal = await args.project(args.tx, entry);
  if (refusal !== null) {
    return { kind: 'refused', refusal };
  }
  await args.insert(entry);
  await args.tx.setProjectionSeq(entry.seq);
  return { kind: 'appended', entry };
}

/** Meta rows for a freshly created ledger. */
export function newMetaRows(doorId: string, doorKey: DoorKey, createdAt: string): [string, string][] {
  return [
    ['schema_version', '1'],
    ['door_id', doorId],
    ['door_public_key', doorKey.publicKeyHex],
    ['door_key_id', doorKey.keyId],
    ['created_at', createdAt],
  ];
}

/** Refuse to write into a ledger created by another door or another key. */
export function assertDoorOwnsMeta(meta: LedgerMeta, doorKey: DoorKey, doorId: string): void {
  if (meta.door_key_id !== doorKey.keyId) {
    throw new Error(
      `ledger was created by door key ${meta.door_key_id.slice(0, 12)}…, ` +
        `but the loaded key is ${doorKey.keyId.slice(0, 12)}… — refusing to write`
    );
  }
  if (meta.door_id !== doorId) {
    throw new Error(
      `ledger belongs to door '${meta.door_id}', not '${doorId}' — one door per ledger DB writes; multi-door chains are verified via the key directory`
    );
  }
}

/** Assemble typed meta from raw rows; throws on incomplete metadata. */
export function metaFromRows(rows: Map<string, string>): LedgerMeta {
  const doorId = rows.get('door_id');
  const doorPublicKey = rows.get('door_public_key');
  const doorKeyId = rows.get('door_key_id');
  const createdAt = rows.get('created_at');
  const schemaVersion = rows.get('schema_version');
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
