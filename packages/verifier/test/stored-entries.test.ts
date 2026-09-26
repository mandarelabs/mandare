import { describe, expect, test } from 'vitest';

import { canonicalJson } from '@mandarelabs/spec';

import { parseStoredEntries, parseStoredEntry } from '../src/index.js';

/**
 * W-3 (audit 2026-09): the stored text of an entry must have exactly ONE
 * reading. JSON with duplicate keys parses last-key-wins in JSON.parse (what
 * the verifier hashes) and first-key-wins in SQLite's json_extract (what a
 * SQL reader shows) — a file-level attacker could prepend forged keys that
 * every SQL view renders while the chain still verifies. A stored row is
 * accepted only when its text IS a deterministic re-serialization of the
 * value it parses to, and its seq / entry_hash columns match that value.
 */

const ENTRY = { seq: 1, entry_hash: 'a'.repeat(64), actor: 'did:example:real', cost: { amount: 5 } };

function row(text: string, overrides: Partial<{ seq: number; entry_hash: string }> = {}) {
  return { seq: ENTRY.seq, entry_hash: ENTRY.entry_hash, text, ...overrides };
}

describe('parseStoredEntry', () => {
  test('canonical JSON (what doors write since W-3) is accepted', () => {
    const parsed = parseStoredEntry(row(canonicalJson(ENTRY)));
    expect(parsed).toEqual({ ok: true, entry: ENTRY });
  });

  test('legacy JSON.stringify text (pre-W-3 rows) is accepted — also a single-reading encoding', () => {
    expect(parseStoredEntry(row(JSON.stringify(ENTRY))).ok).toBe(true);
  });

  test('DUPLICATE KEYS: forged keys prepended to a genuine entry are refused', () => {
    const forged = `{"actor":"did:example:evil","cost":{"amount":1},${canonicalJson(ENTRY).slice(1)}`;
    expect(JSON.parse(forged)).toEqual(ENTRY); // what the verifier would hash: the genuine entry…
    const parsed = parseStoredEntry(row(forged));
    expect(parsed.ok).toBe(false); // …but a SQL reader shows the forgery — refuse the row
    if (!parsed.ok) expect(parsed.reason).toMatch(/single reading|duplicate/i);
  });

  test('whitespace and other non-canonical spellings are refused', () => {
    expect(parseStoredEntry(row(JSON.stringify(ENTRY, null, 1))).ok).toBe(false);
    expect(parseStoredEntry(row(canonicalJson(ENTRY).replace('"did', '"\\u0064id'))).ok).toBe(false);
  });

  test('a non-finite number (1e400 → Infinity) is refused, not thrown', () => {
    expect(parseStoredEntry(row('{"entry_hash":"' + 'a'.repeat(64) + '","seq":1e400}')).ok).toBe(false);
  });

  test('text that is not JSON is refused, not thrown', () => {
    expect(parseStoredEntry(row('{"seq":1,')).ok).toBe(false);
  });

  test('seq column ≠ entry seq is refused', () => {
    const parsed = parseStoredEntry(row(canonicalJson(ENTRY), { seq: 2 }));
    expect(parsed.ok).toBe(false);
    if (!parsed.ok) expect(parsed.reason).toMatch(/seq/);
  });

  test('entry_hash column ≠ entry entry_hash is refused', () => {
    const parsed = parseStoredEntry(row(canonicalJson(ENTRY), { entry_hash: 'b'.repeat(64) }));
    expect(parsed.ok).toBe(false);
    if (!parsed.ok) expect(parsed.reason).toMatch(/entry_hash/);
  });
});

describe('parseStoredEntries', () => {
  test('all rows sound → the parsed entries, in order', () => {
    const second = { ...ENTRY, seq: 2, entry_hash: 'c'.repeat(64) };
    const result = parseStoredEntries([
      row(canonicalJson(ENTRY)),
      { seq: 2, entry_hash: second.entry_hash, text: canonicalJson(second) },
    ]);
    expect(result).toEqual({ ok: true, entries: [ENTRY, second] });
  });

  test('the first unsound row fails with STORAGE_MISMATCH, naming its index and seq', () => {
    const second = { ...ENTRY, seq: 2, entry_hash: 'c'.repeat(64) };
    const result = parseStoredEntries([
      row(canonicalJson(ENTRY)),
      { seq: 2, entry_hash: second.entry_hash, text: `{"actor":"x",${canonicalJson(second).slice(1)}` },
    ]);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.code).toBe('STORAGE_MISMATCH');
      expect(result.failure.index).toBe(1);
      expect(result.failure.seq).toBe(2);
      expect(result.entries).toBe(2);
    }
  });
});
