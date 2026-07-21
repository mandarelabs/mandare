import type { LedgerEntryV1 } from '@mandarelabs/spec';

import { loadOrCreateDoorKey, type DoorKey } from './door-key.js';
import { buildEntry, type AppendInput, type LedgerHead } from './entry.js';
import {
  assertDoorOwnsMeta,
  metaFromRows,
  newMetaRows,
  type AppendProjectedResult,
  type LedgerMeta,
  type LedgerStore,
  type ProjectionTx,
  type Projector,
} from './store.js';

/**
 * Ledger over any `LedgerStore` driver (BUILD-DECISIONS Q7) — used for the
 * Postgres team-mode store today. Chain semantics are identical to the sync
 * SQLite `Ledger`: both delegate to `buildEntry`, so the produced chains are
 * verifier-indistinguishable.
 */
export class AsyncLedger {
  readonly doorId: string;
  readonly doorKeyId: string;
  readonly doorPublicKeyHex: string;

  private readonly store: LedgerStore;
  private readonly doorKey: DoorKey;

  private constructor(store: LedgerStore, doorKey: DoorKey, doorId: string) {
    this.store = store;
    this.doorKey = doorKey;
    this.doorId = doorId;
    this.doorKeyId = doorKey.keyId;
    this.doorPublicKeyHex = doorKey.publicKeyHex;
  }

  static async open(
    store: LedgerStore,
    options: { doorId: string; keyPath: string }
  ): Promise<AsyncLedger> {
    try {
      const doorKey = loadOrCreateDoorKey(options.keyPath);
      const ledger = new AsyncLedger(store, doorKey, options.doorId);
      const existingRows = await store.readMetaRows();
      if (existingRows === null) {
        await store.initMeta(newMetaRows(options.doorId, doorKey, new Date().toISOString()));
      } else {
        assertDoorOwnsMeta(metaFromRows(existingRows), doorKey, options.doorId);
      }
      return ledger;
    } catch (error) {
      // A rejected open (wrong door key, foreign door id) must not leak the
      // store's connections — the caller never received a ledger to close.
      await store.close().catch(() => undefined);
      throw error;
    }
  }

  append(input: AppendInput): Promise<LedgerEntryV1> {
    return this.store.appendWithLock((head) =>
      buildEntry(input, head, this.doorId, this.doorKey)
    );
  }

  /**
   * Append with the spend projection in the SAME transaction (S2 budgets).
   * A projector refusal aborts everything — no entry, no counter change —
   * which is what makes concurrent cap overshoot impossible by construction.
   */
  appendProjected(input: AppendInput, project: Projector): Promise<AppendProjectedResult> {
    return this.store.appendProjected(
      (head) => buildEntry(input, head, this.doorId, this.doorKey),
      project
    );
  }

  /** Run a function inside a projection transaction (rebuild/verify/snapshot). */
  runProjection<T>(fn: (tx: ProjectionTx) => Promise<T>): Promise<T> {
    return this.store.runProjection(fn);
  }

  head(): Promise<LedgerHead | null> {
    return this.store.head();
  }

  /** Meta + unvalidated entries, for verification (same contract as readLedger). */
  async readAll(): Promise<{ meta: LedgerMeta; entries: unknown[] }> {
    const rows = await this.store.readMetaRows();
    if (rows === null) {
      throw new Error('ledger store has no metadata — not a Mandare ledger?');
    }
    return { meta: metaFromRows(rows), entries: await this.store.readAllEntries() };
  }

  close(): Promise<void> {
    return this.store.close();
  }
}
