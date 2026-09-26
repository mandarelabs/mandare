import { canonicalJson } from '@mandarelabs/spec';

import type { VerifyFailure } from './index.js';

/**
 * Stored-row check (W-3, audit 2026-09) — pure and portable like
 * `verifyChain`, for anyone reading a ledger's storage directly.
 *
 * `verifyChain` proves the PARSED entries. That is only a proof about what a
 * reader sees if the stored text has exactly one reading. JSON with
 * duplicate keys does not: `JSON.parse` keeps the last value (what the
 * verifier hashes), SQLite's `json_extract` the first (what a SQL view
 * shows). A file-level attacker, no key needed, could prepend forged keys to
 * a genuine row: the chain stays VALID while every SQL reader renders the
 * forgery. So a row is accepted only when its text IS a deterministic
 * re-serialization of the value it parses to — canonical JSON (what doors
 * write since W-3) or `JSON.stringify` (rows written before) — and its
 * `seq` / `entry_hash` columns (what head/witness reads use) match it.
 */

export interface StoredEntryRow {
  /** The row's `seq` column. */
  seq: number;
  /** The row's `entry_hash` column. */
  entry_hash: string;
  /** The entry text exactly as persisted. */
  text: string;
}

export type StoredEntryParse = { ok: true; entry: unknown } | { ok: false; reason: string };

export type StoredEntriesResult =
  | { ok: true; entries: unknown[] }
  | { ok: false; entries: number; failure: VerifyFailure };

function hasSingleReading(text: string, parsed: unknown): boolean {
  try {
    return text === canonicalJson(parsed) || text === JSON.stringify(parsed);
  } catch {
    return false; // e.g. 1e400 parsed to Infinity: not canonicalizable, not ours
  }
}

/** Parse one stored row; refuse any text a second parser could read differently. */
export function parseStoredEntry(row: StoredEntryRow): StoredEntryParse {
  let parsed: unknown;
  try {
    parsed = JSON.parse(row.text) as unknown;
  } catch {
    return { ok: false, reason: 'stored entry is not valid JSON' };
  }
  if (!hasSingleReading(row.text, parsed)) {
    return {
      ok: false,
      reason:
        'stored text is not a single-reading encoding of the entry it parses to ' +
        '(duplicate keys or non-canonical JSON — parsers could disagree on its content)',
    };
  }
  const claimed = (typeof parsed === 'object' && parsed !== null ? parsed : {}) as {
    seq?: unknown;
    entry_hash?: unknown;
  };
  if (claimed.seq !== row.seq) {
    return { ok: false, reason: `seq column ${row.seq} does not match the stored entry's seq` };
  }
  if (claimed.entry_hash !== row.entry_hash) {
    return { ok: false, reason: "entry_hash column does not match the stored entry's entry_hash" };
  }
  return { ok: true, entry: parsed };
}

/** Parse every stored row in order; the first unsound one fails STORAGE_MISMATCH. */
export function parseStoredEntries(rows: readonly StoredEntryRow[]): StoredEntriesResult {
  const entries: unknown[] = [];
  for (const [index, row] of rows.entries()) {
    const parsed = parseStoredEntry(row);
    if (!parsed.ok) {
      return {
        ok: false,
        entries: rows.length,
        failure: { code: 'STORAGE_MISMATCH', index, seq: row.seq, reason: parsed.reason },
      };
    }
    entries.push(parsed.entry);
  }
  return { ok: true, entries };
}
