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
