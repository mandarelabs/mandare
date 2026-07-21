import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import EmbeddedPostgres from 'embedded-postgres';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';

import { LLM_CALL_INTENT } from '@mandarelabs/spec';
import { verifyChain } from '@mandarelabs/verifier';

import { AsyncLedger } from '../../src/async-ledger.js';
import { PgStore, provisionPgLedger } from '../../src/pg-store.js';
import type { AppendInput } from '../../src/entry.js';

/**
 * RED-TEAM SUITE, Postgres team-mode driver (rule R5, BUILD-DECISIONS Q7).
 * Same contract as the SQLite suite: every tamper technique must be blocked
 * by storage enforcement or FAIL VERIFICATION LOUDLY.
 *
 * Postgres storage enforcement is two-layer and both layers are tested:
 * 1. the application role holds only SELECT+INSERT (grants),
 * 2. BEFORE UPDATE/DELETE triggers RAISE even for roles with broader grants.
 * Documented boundary: a superuser who drops the triggers can rewrite
 * history — verification (and witnessing, S6) exists exactly for that; the
 * tests prove the rewrite is caught.
 *
 * Runs against a real embedded Postgres 17 (dev-only binaries) — no Docker,
 * no external service, works identically locally and in CI.
 */

const APP_ROLE = 'mandare_app';
const APP_PASSWORD = 'red-team-app-pw';
const PORT = 55440 + (process.pid % 100);

let embedded: InstanceType<typeof EmbeddedPostgres>;
let adminUrl: string;
let appUrl: string;
let ledger: AsyncLedger;
let store: PgStore;
let doorPublicKeyHex: string;

function sampleInput(overrides: Partial<AppendInput> = {}): AppendInput {
  return {
    actor: 'did:example:agent',
    mandate_id: 'mnd_test',
    action: { type: LLM_CALL_INTENT, target: 'openrouter.ai', request_hash: 'b'.repeat(64) },
    cost: { amount: 0, currency: 'USD', tokens_in: 0, tokens_out: 0 },
    ...overrides,
  };
}

async function adminClient(): Promise<pg.Client> {
  const client = new pg.Client({ connectionString: adminUrl });
  await client.connect();
  return client;
}

async function appClient(): Promise<pg.Client> {
  const client = new pg.Client({ connectionString: appUrl });
  await client.connect();
  return client;
}

async function verifyPg() {
  const { entries } = await ledger.readAll();
  return verifyChain(entries, { doorPublicKey: doorPublicKeyHex });
}

beforeAll(async () => {
  const workDir = mkdtempSync(join(tmpdir(), 'mandare-pg-redteam-'));
  embedded = new EmbeddedPostgres({
    databaseDir: join(workDir, 'pgdata'),
    user: 'postgres',
    password: 'postgres',
    port: PORT,
    persistent: false,
  });
  await embedded.initialise();
  await embedded.start();
  adminUrl = `postgresql://postgres:postgres@127.0.0.1:${PORT}/postgres`;
  appUrl = `postgresql://${APP_ROLE}:${APP_PASSWORD}@127.0.0.1:${PORT}/postgres`;

  const admin = await adminClient();
  await admin.query(`CREATE ROLE ${APP_ROLE} LOGIN PASSWORD '${APP_PASSWORD}'`);
  await admin.end();

  await provisionPgLedger(adminUrl, { appRole: APP_ROLE });

  store = PgStore.connect(appUrl);
  ledger = await AsyncLedger.open(store, {
    doorId: 'gateway:pg-test',
    keyPath: join(workDir, 'door.pem'),
  });
  doorPublicKeyHex = ledger.doorPublicKeyHex;
  for (let i = 0; i < 4; i += 1) {
    await ledger.append(sampleInput());
  }
}, 120_000);

afterAll(async () => {
  await store.close();
  await embedded.stop();
}, 60_000);

describe('privilege separation (layer 1: INSERT-only grants)', () => {
  test('app role cannot UPDATE entries', async () => {
    const client = await appClient();
    await expect(
      client.query("UPDATE ledger_entries SET entry_json = '{}' WHERE seq = 2")
    ).rejects.toThrow(/permission denied|append-only/);
    await client.end();
  });

  test('app role cannot DELETE entries', async () => {
    const client = await appClient();
    await expect(client.query('DELETE FROM ledger_entries WHERE seq = 2')).rejects.toThrow(
      /permission denied|append-only/
    );
    await client.end();
  });

  test('app role cannot TRUNCATE the ledger', async () => {
    const client = await appClient();
    await expect(client.query('TRUNCATE ledger_entries')).rejects.toThrow(/permission denied/);
    await client.end();
  });

  test('app role cannot rewrite meta (door key swap)', async () => {
    const client = await appClient();
    await expect(
      client.query("UPDATE ledger_meta SET value = 'ff' WHERE key = 'door_public_key'")
    ).rejects.toThrow(/permission denied|write-once/);
    await client.end();
  });

  test('app role cannot drop the append-only triggers', async () => {
    const client = await appClient();
    await expect(
      client.query('DROP TRIGGER ledger_entries_append_only ON ledger_entries')
    ).rejects.toThrow(/must be owner|permission denied/);
    await client.end();
  });
});

describe('append-only triggers (layer 2: holds even with table privileges)', () => {
  test('superuser UPDATE dies on the trigger', async () => {
    const client = await adminClient();
    await expect(
      client.query("UPDATE ledger_entries SET entry_json = '{}' WHERE seq = 2")
    ).rejects.toThrow(/append-only/);
    await client.end();
  });

  test('superuser DELETE dies on the trigger', async () => {
    const client = await adminClient();
    await expect(client.query('DELETE FROM ledger_entries WHERE seq = 2')).rejects.toThrow(
      /append-only/
    );
    await client.end();
  });

  test('superuser meta rewrite dies on the trigger', async () => {
    const client = await adminClient();
    await expect(
      client.query("UPDATE ledger_meta SET value = 'ff' WHERE key = 'door_public_key'")
    ).rejects.toThrow(/write-once/);
    await client.end();
  });
});

describe('in-place replay is impossible (PRIMARY KEY)', () => {
  test('same seq twice violates the constraint even for superuser', async () => {
    const client = await adminClient();
    await expect(
      client.query(`
        INSERT INTO ledger_entries (seq, entry_hash, prev_hash, entry_json)
        SELECT seq, 'bb' || substr(entry_hash, 3), prev_hash, entry_json
        FROM ledger_entries WHERE seq = 2
      `)
    ).rejects.toThrow(/duplicate key|unique/i);
    await client.end();
  });
});

describe('tampering past storage enforcement still fails verification', () => {
  /**
   * Attacker model from here on: full superuser — drops the triggers first
   * (the documented Q7 boundary). Each test restores the tampered rows so
   * later tests see the intact chain.
   */
  async function withTriggersDropped(fn: (client: pg.Client) => Promise<void>): Promise<void> {
    const client = await adminClient();
    await client.query('ALTER TABLE ledger_entries DISABLE TRIGGER ledger_entries_append_only');
    try {
      await fn(client);
    } finally {
      await client.query('ALTER TABLE ledger_entries ENABLE TRIGGER ledger_entries_append_only');
      await client.end();
    }
  }

  test('EDIT: modified entry content → ENTRY_HASH_MISMATCH', async () => {
    await withTriggersDropped(async (client) => {
      const original = await client.query<{ entry_json: string }>(
        'SELECT entry_json FROM ledger_entries WHERE seq = 2'
      );
      const forged = JSON.parse(original.rows[0]?.entry_json ?? '') as {
        cost: { amount: number };
      };
      forged.cost.amount = 999_999_999;
      await client.query('UPDATE ledger_entries SET entry_json = $1 WHERE seq = 2', [
        JSON.stringify(forged),
      ]);

      const result = await verifyPg();
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.failure.code).toBe('ENTRY_HASH_MISMATCH');
        expect(result.failure.seq).toBe(2);
      }

      await client.query('UPDATE ledger_entries SET entry_json = $1 WHERE seq = 2', [
        original.rows[0]?.entry_json,
      ]);
    });
  });

  test('DELETE: removed middle entry → SEQ_GAP', async () => {
    await withTriggersDropped(async (client) => {
      const original = await client.query(
        'SELECT seq, entry_hash, prev_hash, entry_json FROM ledger_entries WHERE seq = 2'
      );
      await client.query('DELETE FROM ledger_entries WHERE seq = 2');

      const result = await verifyPg();
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.failure.code).toBe('SEQ_GAP');

      const row = original.rows[0] as {
        seq: string;
        entry_hash: string;
        prev_hash: string;
        entry_json: string;
      };
      await client.query(
        'INSERT INTO ledger_entries (seq, entry_hash, prev_hash, entry_json) VALUES ($1, $2, $3, $4)',
        [row.seq, row.entry_hash, row.prev_hash, row.entry_json]
      );
    });
  });

  test('REPLAY: duplicated entry at a new seq → verification failure', async () => {
    await withTriggersDropped(async (client) => {
      await client.query(`
        INSERT INTO ledger_entries (seq, entry_hash, prev_hash, entry_json)
        SELECT 5, 'aa' || substr(entry_hash, 3), entry_hash, entry_json
        FROM ledger_entries WHERE seq = 2
      `);

      const result = await verifyPg();
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(['SEQ_GAP', 'ENTRY_HASH_MISMATCH', 'PREV_HASH_MISMATCH']).toContain(
          result.failure.code
        );
      }

      await client.query('DELETE FROM ledger_entries WHERE seq = 5');
    });
  });
});

describe('driver parity', () => {
  test('the Postgres-written chain verifies exactly like a SQLite one', async () => {
    const result = await verifyPg();
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.entries).toBe(4);
    }
    const { meta } = await ledger.readAll();
    expect(meta.door_id).toBe('gateway:pg-test');
    expect(meta.door_public_key).toBe(doorPublicKeyHex);
  });

  test('AsyncLedger refuses to write with a swapped door key (stolen-DB scenario)', async () => {
    const otherKeyPath = join(mkdtempSync(join(tmpdir(), 'mandare-pg-key-')), 'other.pem');
    // open() owns store cleanup on rejection — no manual close (review S1-L2).
    await expect(
      AsyncLedger.open(PgStore.connect(appUrl), {
        doorId: 'gateway:pg-test',
        keyPath: otherKeyPath,
      })
    ).rejects.toThrow(/refusing to write/);
  });

  test('concurrent appends never race to the same seq (advisory lock)', async () => {
    const before = await ledger.head();
    const entries = await Promise.all(
      Array.from({ length: 8 }, () => ledger.append(sampleInput()))
    );
    const seqs = entries.map((entry) => entry.seq).sort((a, b) => a - b);
    const base = (before?.seq ?? 0) + 1;
    expect(seqs).toEqual(Array.from({ length: 8 }, (_, i) => base + i));
    const result = await verifyPg();
    expect(result.ok).toBe(true);
  });
});
