import { DatabaseSync } from 'node:sqlite';

import { diffRevocation, replayRevocation, type RevocationDivergence } from './revocation.js';
import type { ProjectionRunner } from './spend-ledger.js';
import type { RevocationRecord } from './store.js';

/**
 * Revocation-projection lifecycle helpers — the read the gateway does on
 * every request (is this subject killed?), plus rebuild/verify/list for the
 * CLI. The projection is exclusive with appends (shares the append lock), so
 * a read here never races a kill in flight.
 */

export type RevocationVerdict =
  | { ok: true; subjects: number }
  | { ok: false; stale: boolean; reason: string; divergences: RevocationDivergence[] };

/** One subject's current revocation record (null = never seen → not revoked). */
export async function readRevocationRecord(
  store: ProjectionRunner,
  subject: string
): Promise<RevocationRecord | null> {
  return store.runProjection((tx) => tx.getRevocation(subject));
}

/**
 * The gateway's per-request kill check. A subject is revoked iff it has a
 * record with `revoked === true`. Fail-closed is the CALLER's job: on any
 * error reading this, the caller must deny (R1).
 */
export async function isSubjectRevoked(
  store: ProjectionRunner,
  subject: string
): Promise<boolean> {
  return (await readRevocationRecord(store, subject))?.revoked === true;
}

export async function listRevocations(store: ProjectionRunner): Promise<RevocationRecord[]> {
  const records = await store.runProjection((tx) => tx.readAllRevocations());
  return records.sort((a, b) => a.statusIndex - b.statusIndex);
}

/** Rebuild the revocation table from the ledger alone (the ground truth). */
export async function rebuildRevocationProjection(store: ProjectionRunner): Promise<void> {
  await store.runProjection(async (tx) => {
    const replayed = await replayRevocation(await tx.readAllEntries());
    await tx.clearRevocations();
    // Re-apply in status-index order so the allocator counter lands where the
    // replay left it — indices stay identical to a from-scratch projection.
    const ordered = [...replayed.values()].sort((a, b) => a.statusIndex - b.statusIndex);
    for (const record of ordered) {
      await tx.allocateStatusIndex();
      await tx.putRevocation(record);
    }
  });
}

/**
 * The invariant check: every stored revocation record must equal a fresh
 * replay of the ledger. Divergence means the table was tampered with or the
 * projection is buggy — the CLI reports it and exits non-zero (R1/R5).
 */
export async function verifyRevocationProjection(
  store: ProjectionRunner
): Promise<RevocationVerdict> {
  return store.runProjection(async (tx) => {
    const storedList = await tx.readAllRevocations();
    const stored = new Map(storedList.map((record) => [record.subject, record]));
    const replayed = await replayRevocation(await tx.readAllEntries());
    const divergences = diffRevocation(stored, replayed);
    if (divergences.length > 0) {
      return {
        ok: false,
        stale: false,
        reason: `${divergences.length} revocation record(s) diverge from a fresh ledger replay — tampering or projection bug`,
        divergences,
      };
    }
    return { ok: true, subjects: stored.size };
  });
}

/**
 * Read-only projection dump for a SQLite ledger file (CLI verify path — must
 * not create tables or write to the file being audited). A missing table
 * reads as an empty, never-written revocation projection.
 */
export function readRevocationProjectionSqlite(dbPath: string): RevocationRecord[] {
  const db = new DatabaseSync(dbPath, { readOnly: true });
  try {
    const hasTable =
      db
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?")
        .get('revocation_status') !== undefined;
    if (!hasTable) {
      return [];
    }
    const rows = db
      .prepare('SELECT subject, revoked, status_index, updated_at, entry_hash FROM revocation_status')
      .all() as {
      subject: string;
      revoked: number;
      status_index: number;
      updated_at: string;
      entry_hash: string;
    }[];
    return rows.map((row) => ({
      subject: row.subject,
      revoked: row.revoked !== 0,
      statusIndex: row.status_index,
      updatedAt: row.updated_at,
      entryHash: row.entry_hash,
    }));
  } finally {
    db.close();
  }
}
