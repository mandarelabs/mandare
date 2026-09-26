import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import EmbeddedPostgres from 'embedded-postgres';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';

import { LLM_CALL_INTENT, canonicalJson, computeEntryHash, hexToBytes } from '@mandarelabs/spec';
import {
  computeTreeHead,
  consistencyProof,
  parseStoredEntries,
  verifyChain,
  verifyConsistency,
} from '@mandarelabs/verifier';

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
  // Let client sockets finish tearing down before the server goes away —
  // on slow runners a fast shutdown mid-teardown sends FATAL 57P01 to
  // half-closed connections (observed on CI; the pool error handler covers
  // the production case, this covers the test race).
  await new Promise((resolve) => setTimeout(resolve, 250));
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
    // The W-3 BEFORE INSERT trigger refuses this first; disable it so the
    // PRIMARY KEY is proven as an independent layer (the trigger has its own tests).
    await client.query('ALTER TABLE ledger_entries DISABLE TRIGGER ledger_entries_no_replace');
    try {
      await expect(
        client.query(`
          INSERT INTO ledger_entries (seq, entry_hash, prev_hash, entry_json)
          SELECT seq, 'bb' || substr(entry_hash, 3), prev_hash, entry_json
          FROM ledger_entries WHERE seq = 2
        `)
      ).rejects.toThrow(/duplicate key|unique/i);
    } finally {
      await client.query('ALTER TABLE ledger_entries ENABLE TRIGGER ledger_entries_no_replace');
      await client.end();
    }
  });
});

describe('W-3: BEFORE INSERT parity — a re-insert is append-only, not just a key clash', () => {
  test('re-inserting an existing seq dies on the append-only trigger (superuser)', async () => {
    const client = await adminClient();
    await expect(
      client.query(`
        INSERT INTO ledger_entries (seq, entry_hash, prev_hash, entry_json)
        SELECT seq, 'cc' || substr(entry_hash, 3), prev_hash, entry_json
        FROM ledger_entries WHERE seq = 2
      `)
    ).rejects.toThrow(/append-only/);
    await client.end();
  });

  test('re-inserting an existing meta key dies on the write-once trigger (superuser)', async () => {
    const client = await adminClient();
    await expect(
      client.query("INSERT INTO ledger_meta (key, value) VALUES ('door_key_id', 'ff')")
    ).rejects.toThrow(/write-once/);
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

  test('DUPLICATE KEYS (W-3): forged keys prepended — chain VALID, stored-row check convicts', async () => {
    await withTriggersDropped(async (client) => {
      const original = await client.query<{ entry_json: string }>(
        'SELECT entry_json FROM ledger_entries WHERE seq = 2'
      );
      const text = original.rows[0]?.entry_json ?? '';
      const forged = `{"actor":"did:example:forged",${text.slice(1)}`;
      await client.query('UPDATE ledger_entries SET entry_json = $1 WHERE seq = 2', [forged]);

      expect((await verifyPg()).ok).toBe(true); // last-key-wins still hashes the genuine entry
      const stored = parseStoredEntries(await ledger.readAllRows());
      expect(stored.ok).toBe(false);
      if (!stored.ok) {
        expect(stored.failure.code).toBe('STORAGE_MISMATCH');
        expect(stored.failure.seq).toBe(2);
      }

      await client.query('UPDATE ledger_entries SET entry_json = $1 WHERE seq = 2', [text]);
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
  test('the Postgres door stores canonical JSON (W-3) and passes the stored-row check', async () => {
    const rows = await ledger.readAllRows();
    const stored = parseStoredEntries(rows);
    expect(stored.ok).toBe(true);
    if (stored.ok) {
      stored.entries.forEach((entry, index) => expect(rows[index]?.text).toBe(canonicalJson(entry)));
    }
  });

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

describe('witnessed-head detection (S6): the superuser rewrite that cannot hide', () => {
  /**
   * The Q7-documented boundary made concrete: a superuser drops the
   * triggers, doctors PG-stored history, and — holding the REAL door key —
   * re-signs a perfectly consistent chain. Self-anchored verification
   * passes. The witnessed head (RFC 6962 tree head recorded off-machine
   * BEFORE the tampering, SPEC §6 lock 4) convicts both flavors. The full
   * HTTP loop is red-teamed in packages/witness; this proves the detection
   * math against the Postgres driver's tamper paths.
   */
  async function resignedRows(mutate: (entries: LedgerEntryLike[]) => LedgerEntryLike[]) {
    const { entries } = await ledger.readAll();
    const doctored = mutate(entries as LedgerEntryLike[]);
    const signer = ledger.signer();
    let prevHash = '0'.repeat(64);
    return doctored.map((entry, index) => {
      const { entry_hash: _h, door_signature: _s, ...rest } = entry;
      const preimage = { ...rest, seq: index + 1, prev_hash: prevHash };
      const entryHash = computeEntryHash(preimage as Parameters<typeof computeEntryHash>[0]);
      prevHash = entryHash;
      return {
        ...preimage,
        entry_hash: entryHash,
        door_signature: {
          alg: 'EdDSA',
          key_id: signer.keyId,
          key_provenance: signer.provenance,
          value: Buffer.from(signer.sign(hexToBytes(entryHash))).toString('base64url'),
        },
      };
    });
  }

  async function replaceChain(rows: Awaited<ReturnType<typeof resignedRows>>): Promise<string[]> {
    const client = await adminClient();
    await client.query('ALTER TABLE ledger_entries DISABLE TRIGGER ledger_entries_append_only');
    const backup = await client.query<{ seq: number; entry_hash: string; prev_hash: string; entry_json: string }>(
      'SELECT seq, entry_hash, prev_hash, entry_json FROM ledger_entries ORDER BY seq'
    );
    await client.query('DELETE FROM ledger_entries');
    for (const row of rows) {
      await client.query(
        'INSERT INTO ledger_entries (seq, entry_hash, prev_hash, entry_json) VALUES ($1, $2, $3, $4)',
        [row.seq, row.entry_hash, row.prev_hash, JSON.stringify(row)]
      );
    }
    await client.query('ALTER TABLE ledger_entries ENABLE TRIGGER ledger_entries_append_only');
    await client.end();
    return backup.rows.map((row) => row.entry_json);
  }

  async function restoreChain(backupJson: string[]): Promise<void> {
    const client = await adminClient();
    await client.query('ALTER TABLE ledger_entries DISABLE TRIGGER ledger_entries_append_only');
    await client.query('DELETE FROM ledger_entries');
    for (const json of backupJson) {
      const row = JSON.parse(json) as { seq: number; entry_hash: string; prev_hash: string };
      await client.query(
        'INSERT INTO ledger_entries (seq, entry_hash, prev_hash, entry_json) VALUES ($1, $2, $3, $4)',
        [row.seq, row.entry_hash, row.prev_hash, json]
      );
    }
    await client.query('ALTER TABLE ledger_entries ENABLE TRIGGER ledger_entries_append_only');
    await client.end();
  }

  async function witnessVerdict(witnessed: {
    size: number;
    root: string;
  }): Promise<'consistent' | 'truncation' | 'fork'> {
    const hashes = await ledger.readEntryHashes();
    const local = await computeTreeHead(hashes);
    if (local.size < witnessed.size) return 'truncation';
    if (local.size === witnessed.size) {
      return local.root === witnessed.root ? 'consistent' : 'fork';
    }
    const proof = await consistencyProof(hashes, witnessed.size);
    const ok = await verifyConsistency({
      size1: witnessed.size,
      root1: witnessed.root,
      size2: local.size,
      root2: local.root,
      proof,
    });
    return ok ? 'consistent' : 'fork';
  }

  test('TRUNCATION-AFTER-WITNESS: self-anchored passes, witnessed head convicts', async () => {
    const witnessed = await computeTreeHead(await ledger.readEntryHashes());
    const rows = await resignedRows((entries) => entries.slice(0, entries.length - 2));
    const backup = await replaceChain(rows);
    try {
      expect((await verifyPg()).ok).toBe(true); // the lie is locally perfect
      expect(await witnessVerdict(witnessed)).toBe('truncation');
    } finally {
      await restoreChain(backup);
    }
  });

  test('REWRITE-AFTER-WITNESS: doctored amount, re-signed — fork detected', async () => {
    const witnessed = await computeTreeHead(await ledger.readEntryHashes());
    const rows = await resignedRows((entries) => {
      const doctored = [...entries];
      doctored[1] = {
        ...doctored[1]!,
        cost: { ...(doctored[1]!.cost as { amount: number }), amount: 1 },
      };
      return doctored;
    });
    const backup = await replaceChain(rows);
    try {
      expect((await verifyPg()).ok).toBe(true);
      expect(await witnessVerdict(witnessed)).toBe('fork');
    } finally {
      await restoreChain(backup);
    }
  });

  test('honest growth after witnessing stays consistent (no false positives)', async () => {
    const witnessed = await computeTreeHead(await ledger.readEntryHashes());
    await ledger.append(sampleInput());
    expect(await witnessVerdict(witnessed)).toBe('consistent');
  });
});

interface LedgerEntryLike {
  seq: number;
  entry_hash: string;
  prev_hash: string;
  door_signature: unknown;
  cost: unknown;
  [key: string]: unknown;
}
