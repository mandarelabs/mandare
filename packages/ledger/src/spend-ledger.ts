import { DatabaseSync } from 'node:sqlite';

import {
  dayKey,
  diffProjection,
  minuteKey,
  replaySpendCounters,
  totalKey,
  EMPTY_COUNTER,
  type ProjectionDivergence,
  type SpendCounter,
} from './projection.js';
import type { ProjectionTx } from './store.js';

/** Anything that can run a projection transaction (a store or an AsyncLedger). */
export interface ProjectionRunner {
  runProjection<T>(fn: (tx: ProjectionTx) => Promise<T>): Promise<T>;
}

/**
 * Projection lifecycle helpers shared by the gateway (startup) and the CLI
 * (`mandare verify --spend`): rebuild from the ledger, verify the red-team
 * invariant replay(ledger) == counters, and read spend snapshots for policy
 * evaluation.
 */

export type ProjectionVerdict =
  | { ok: true; counters: number }
  | { ok: false; stale: boolean; reason: string; divergences: ProjectionDivergence[] };

/** Rebuild the counter table from the ledger alone (the ground truth). */
export async function rebuildSpendProjection(store: ProjectionRunner): Promise<void> {
  await store.runProjection(async (tx) => {
    const replayed = await replaySpendCounters(await tx.readAllEntries());
    await tx.clearCounters();
    for (const [key, counter] of replayed) {
      await tx.putCounter(key, counter);
    }
    await tx.setProjectionSeq((await tx.head())?.seq ?? 0);
  });
}

/**
 * The invariant check: projection seq must match the head, and every stored
 * counter must equal a fresh replay of the ledger. Any divergence means the
 * counters were tampered with or the projection is buggy — callers fail
 * closed and alert (R1/R5).
 */
export async function verifySpendProjection(store: ProjectionRunner): Promise<ProjectionVerdict> {
  return store.runProjection(async (tx) => {
    const headSeq = (await tx.head())?.seq ?? 0;
    const projectionSeq = await tx.getProjectionSeq();
    const stale = projectionSeq !== headSeq;
    // ALWAYS diff stored vs. a fresh replay, even when the seq looks stale:
    // projection_meta is mutable, so an attacker who tampers with the
    // counters could also rewind the seq to disguise value divergence as
    // mere staleness — which would trigger a silent rebuild that erases the
    // evidence. Value divergence is reported regardless of the seq.
    const stored = await tx.readAllCounters();
    const replayed = await replaySpendCounters(await tx.readAllEntries());
    const divergences = diffProjection(stored, replayed);
    if (divergences.length > 0) {
      return {
        ok: false,
        stale,
        reason:
          `${divergences.length} counter(s) diverge from a fresh ledger replay — tampering or projection bug` +
          (stale ? ` (projection also at seq ${projectionSeq}, head ${headSeq})` : ''),
        divergences,
      };
    }
    if (stale) {
      return {
        ok: false,
        stale: true,
        reason: `projection is at seq ${projectionSeq} but the ledger head is ${headSeq} (stale); counters otherwise match the ledger`,
        divergences: [],
      };
    }
    return { ok: true, counters: stored.size };
  });
}

export interface SpendSnapshot {
  minuteIntents: number;
  day: SpendCounter;
  total: SpendCounter;
}

/**
 * Read the counters relevant to one (mandate, actor) pair for pre-call policy
 * evaluation. Advisory: the authoritative check re-runs under the append
 * lock at reservation time.
 */
export async function readSpendSnapshot(
  store: ProjectionRunner,
  args: { mandateId: string; actor: string; nowIso: string }
): Promise<SpendSnapshot> {
  return store.runProjection(async (tx) => ({
    minuteIntents: ((await tx.getCounter(minuteKey(args.actor, args.nowIso))) ?? EMPTY_COUNTER)
      .intents,
    day: (await tx.getCounter(dayKey(args.mandateId, args.nowIso))) ?? EMPTY_COUNTER,
    total: (await tx.getCounter(totalKey(args.mandateId))) ?? EMPTY_COUNTER,
  }));
}

/**
 * Read-only projection dump for a SQLite ledger file (CLI verify path —
 * must not create tables or otherwise write to the file being audited).
 * Missing projection tables read as an empty, never-written projection.
 */
export function readSpendProjectionSqlite(dbPath: string): {
  counters: Map<string, SpendCounter>;
  projectionSeq: number;
} {
  const db = new DatabaseSync(dbPath, { readOnly: true });
  try {
    const counters = new Map<string, SpendCounter>();
    let projectionSeq = 0;
    const hasTable = (name: string): boolean =>
      db
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?")
        .get(name) !== undefined;
    if (hasTable('budget_counters')) {
      const rows = db
        .prepare('SELECT scope_key, reserved_micros, settled_micros, intents FROM budget_counters')
        .all() as {
        scope_key: string;
        reserved_micros: number;
        settled_micros: number;
        intents: number;
      }[];
      for (const row of rows) {
        counters.set(row.scope_key, {
          reservedMicros: row.reserved_micros,
          settledMicros: row.settled_micros,
          intents: row.intents,
        });
      }
    }
    if (hasTable('projection_meta')) {
      const row = db
        .prepare('SELECT value FROM projection_meta WHERE key = ?')
        .get('spend_projection_seq') as { value: number } | undefined;
      projectionSeq = row?.value ?? 0;
    }
    return { counters, projectionSeq };
  } finally {
    db.close();
  }
}
