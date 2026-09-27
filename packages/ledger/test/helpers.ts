import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { LLM_CALL_INTENT } from '@mandarelabs/spec';

import { Ledger, type AppendInput } from '../src/ledger.js';

export function tempDbPath(): string {
  return join(mkdtempSync(join(tmpdir(), 'mandare-ledger-test-')), 'ledger.db');
}

export function sampleInput(overrides: Partial<AppendInput> = {}): AppendInput {
  return {
    actor: 'did:example:agent',
    mandate_id: 'mnd_test',
    action: { type: LLM_CALL_INTENT, target: 'openrouter.ai', request_hash: 'b'.repeat(64) },
    cost: { amount: 0, currency: 'USD', tokens_in: 0, tokens_out: 0 },
    ...overrides,
  };
}

/** Build a ledger DB with `length` chained entries; returns the closed DB path. */
export function buildChainDb(length: number): { dbPath: string; publicKeyHex: string } {
  const dbPath = tempDbPath();
  const ledger = Ledger.open(dbPath, { doorId: 'gateway:test' });
  for (let i = 0; i < length; i += 1) {
    ledger.append(sampleInput());
  }
  const publicKeyHex = ledger.doorPublicKeyHex;
  ledger.close();
  return { dbPath, publicKeyHex };
}

/**
 * SQL expression (SQLite + Postgres) for a forged `entry_hash`: the source
 * row's hash with its first `prefix.length` hex chars replaced by `prefix` —
 * or by `fallback` when the real hash already starts with `prefix`, so the
 * forgery is GUARANTEED to differ from the hash it was built from. A bare
 * `'aa' || substr(entry_hash, 3)` reproduces the original hash 1 time in 256
 * (hashes are random per run), and the W-3 no-collision trigger then refuses
 * the insert before the tamper ever reaches verification (CI flake,
 * 2026-09-27). The attack under test is unchanged: a new row, new hash.
 */
export function forgedHashSql(prefix: string, fallback: string): string {
  const hex = /^[0-9a-f]+$/;
  if (!hex.test(prefix) || !hex.test(fallback) || prefix.length !== fallback.length || prefix === fallback) {
    throw new Error('forgedHashSql: prefix and fallback must be distinct hex strings of equal length');
  }
  const rest = prefix.length + 1;
  return `(CASE WHEN substr(entry_hash, 1, ${prefix.length}) = '${prefix}' THEN '${fallback}' ELSE '${prefix}' END || substr(entry_hash, ${rest}))`;
}
