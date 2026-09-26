import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { describe, expect, test } from 'vitest';

import { Ledger } from '@mandarelabs/ledger';
import { LLM_CALL_INTENT } from '@mandarelabs/spec';

import { runVerify } from '../src/verify.js';

function buildDb(entryCount: number): { dbPath: string; doorPublicKeyHex: string } {
  const dbPath = join(mkdtempSync(join(tmpdir(), 'mandare-cli-test-')), 'ledger.db');
  const ledger = Ledger.open(dbPath, { doorId: 'gateway:test' });
  for (let i = 0; i < entryCount; i += 1) {
    ledger.append({
      actor: 'did:example:agent',
      mandate_id: 'mnd_test',
      action: { type: LLM_CALL_INTENT, target: 'openrouter.ai', request_hash: 'b'.repeat(64) },
      cost: { amount: 0, currency: 'USD', tokens_in: 0, tokens_out: 0 },
    });
  }
  const doorPublicKeyHex = ledger.doorPublicKeyHex;
  ledger.close();
  return { dbPath, doorPublicKeyHex };
}

describe('mandare verify', () => {
  test('valid chain → exit 0, reports head and the SELF-ANCHORED caveat', async () => {
    const { dbPath } = buildDb(3);
    const output = await runVerify(dbPath);
    expect(output.exitCode).toBe(0);
    const text = output.lines.join('\n');
    expect(text).toContain('VALID');
    expect(text).toContain('SELF-ANCHORED');
    expect(output.json.result.ok).toBe(true);
  });

  test('out-of-band door key: correct key verifies, wrong key fails with KEY_MISMATCH', async () => {
    const { dbPath, doorPublicKeyHex } = buildDb(2);

    const withRealKey = await runVerify(dbPath, { doorPublicKey: doorPublicKeyHex });
    expect(withRealKey.exitCode).toBe(0);
    expect(withRealKey.lines.join('\n')).toContain('out-of-band');

    const otherDb = buildDb(1); // different ledger → different door key
    const withWrongKey = await runVerify(dbPath, { doorPublicKey: otherDb.doorPublicKeyHex });
    expect(withWrongKey.exitCode).toBe(1);
    expect(withWrongKey.lines.join('\n')).toContain('KEY_MISMATCH');
  });

  test('tampered chain → exit 1, names seq and reason', async () => {
    const { dbPath } = buildDb(3);
    const db = new DatabaseSync(dbPath);
    db.exec('DROP TRIGGER ledger_entries_no_update;');
    db.exec(
      "UPDATE ledger_entries SET entry_json = json_set(entry_json, '$.cost.amount', 42) WHERE seq = 2;"
    );
    db.close();

    const output = await runVerify(dbPath);
    expect(output.exitCode).toBe(1);
    const text = output.lines.join('\n');
    expect(text).toContain('INVALID');
    expect(text).toContain('ENTRY_HASH_MISMATCH');
    expect(text).toContain('seq 2');
  });

  test('W-3: forged duplicate keys (first-key-wins readers see a forgery) → exit 1, STORAGE_MISMATCH', async () => {
    const { dbPath, doorPublicKeyHex } = buildDb(3);
    const db = new DatabaseSync(dbPath);
    for (const { name } of db.prepare("SELECT name FROM sqlite_master WHERE type = 'trigger'").all() as {
      name: string;
    }[]) {
      db.exec(`DROP TRIGGER "${name}";`);
    }
    const { entry_json } = db.prepare('SELECT entry_json FROM ledger_entries WHERE seq = 2').get() as {
      entry_json: string;
    };
    db.prepare('UPDATE ledger_entries SET entry_json = ? WHERE seq = 2').run(
      `{"actor":"did:example:forged",${entry_json.slice(1)}`
    );
    db.close();

    const output = await runVerify(dbPath, { doorPublicKey: doorPublicKeyHex });
    expect(output.exitCode).toBe(1);
    const text = output.lines.join('\n');
    expect(text).toContain('INVALID');
    expect(text).toContain('STORAGE_MISMATCH');
    expect(text).toContain('seq 2');
  });

  test('missing file → throws (main maps to exit 1)', async () => {
    await expect(runVerify('/nonexistent/ledger.db')).rejects.toThrow();
  });
});
