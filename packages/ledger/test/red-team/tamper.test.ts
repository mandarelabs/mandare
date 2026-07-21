import { createPublicKey, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

import { describe, expect, test } from 'vitest';

import {
  GENESIS_PREV_HASH,
  base64UrlToBytes,
  bytesToBase64Url,
  bytesToHex,
  computeEntryHash,
  hexToBytes,
  sha256Hex,
  type LedgerEntryPreimage,
  type LedgerEntryV1,
} from '@mandarelabs/spec';
import { verifyChain } from '@mandarelabs/verifier';

import { readLedger } from '../../src/ledger.js';
import { buildChainDb } from '../helpers.js';

/**
 * RED-TEAM SUITE (rule R5) — permanent CI tests. Every tamper technique an
 * attacker with file access could try must either be blocked by storage
 * enforcement or FAIL VERIFICATION LOUDLY. If one of these tests starts
 * passing verification after a change, the change is wrong — do not adjust
 * the test.
 *
 * Attacker model here: file-level access to the SQLite DB, NO access to the
 * door private key. (A full-machine-root attacker incl. the door key is
 * outside the ledger's claimed local coverage — witnessing, S6, bounds it.)
 */

function rawDb(dbPath: string): DatabaseSync {
  return new DatabaseSync(dbPath);
}

/** Attackers drop the append-only triggers first — storage enforcement alone must never be the last line. */
function dropTriggers(db: DatabaseSync): void {
  db.exec('DROP TRIGGER ledger_entries_no_update;');
  db.exec('DROP TRIGGER ledger_entries_no_delete;');
}

async function verify(dbPath: string) {
  const { meta, entries } = readLedger(dbPath);
  return verifyChain(entries, { doorPublicKey: meta.door_public_key });
}

describe('storage enforcement (first line of defense)', () => {
  test('UPDATE on entries is blocked by trigger', () => {
    const { dbPath } = buildChainDb(3);
    const db = rawDb(dbPath);
    expect(() => db.exec("UPDATE ledger_entries SET entry_json = '{}' WHERE seq = 2;")).toThrow(
      /append-only/
    );
    db.close();
  });

  test('DELETE on entries is blocked by trigger', () => {
    const { dbPath } = buildChainDb(3);
    const db = rawDb(dbPath);
    expect(() => db.exec('DELETE FROM ledger_entries WHERE seq = 2;')).toThrow(/append-only/);
    db.close();
  });

  test('meta rewrite (door key swap) is blocked by trigger', () => {
    const { dbPath } = buildChainDb(1);
    const db = rawDb(dbPath);
    expect(() =>
      db.exec("UPDATE ledger_meta SET value = 'ff' WHERE key = 'door_public_key';")
    ).toThrow(/write-once/);
    db.close();
  });
});

describe('tampering past storage enforcement still fails verification', () => {
  test('EDIT: modified entry content → ENTRY_HASH_MISMATCH', async () => {
    const { dbPath } = buildChainDb(4);
    const db = rawDb(dbPath);
    dropTriggers(db);
    db.exec(`
      UPDATE ledger_entries
      SET entry_json = json_set(entry_json, '$.cost.amount', 999999999)
      WHERE seq = 2;
    `);
    db.close();

    const result = await verify(dbPath);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.code).toBe('ENTRY_HASH_MISMATCH');
      expect(result.failure.seq).toBe(2);
    }
  });

  test('DELETE: removed middle entry → SEQ_GAP', async () => {
    const { dbPath } = buildChainDb(4);
    const db = rawDb(dbPath);
    dropTriggers(db);
    db.exec('DELETE FROM ledger_entries WHERE seq = 2;');
    db.close();

    const result = await verify(dbPath);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.code).toBe('SEQ_GAP');
  });

  test('GAP INJECTION: entry appended beyond the head leaves a visible gap', async () => {
    const { dbPath } = buildChainDb(2);
    const db = rawDb(dbPath);
    // Attacker forges a plausible-looking future entry at seq 4 (seq 3 missing).
    db.exec(`
      INSERT INTO ledger_entries (seq, entry_hash, prev_hash, entry_json)
      SELECT 4, 'deadbeef' || substr(entry_hash, 9), entry_hash, entry_json
      FROM ledger_entries WHERE seq = 2;
    `);
    db.close();

    const result = await verify(dbPath);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.code).toBe('SEQ_GAP');
  });

  test('REPLAY: duplicating an existing entry at a new seq → PREV/HASH failure', async () => {
    const { dbPath } = buildChainDb(2);
    const db = rawDb(dbPath);
    // Replay entry 2's json at seq 3 (classic double-spend replay).
    db.exec(`
      INSERT INTO ledger_entries (seq, entry_hash, prev_hash, entry_json)
      SELECT 3, 'aa' || substr(entry_hash, 3), entry_hash, entry_json
      FROM ledger_entries WHERE seq = 2;
    `);
    db.close();

    const result = await verify(dbPath);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      // The replayed json still claims seq 2 → seq mismatch; a smarter
      // attacker editing seq in the json breaks entry_hash instead.
      expect(['SEQ_GAP', 'ENTRY_HASH_MISMATCH']).toContain(result.failure.code);
    }
  });

  test('REPLAY (in-place): same seq twice is impossible (PRIMARY KEY)', () => {
    const { dbPath } = buildChainDb(2);
    const db = rawDb(dbPath);
    expect(() =>
      db.exec(`
        INSERT INTO ledger_entries (seq, entry_hash, prev_hash, entry_json)
        SELECT seq, 'bb' || substr(entry_hash, 3), prev_hash, entry_json
        FROM ledger_entries WHERE seq = 2;
      `)
    ).toThrow(/UNIQUE|PRIMARY/i);
    db.close();
  });

  test('FORGE: attacker without the door key cannot produce a valid tail', async () => {
    const { dbPath } = buildChainDb(2);
    const db = rawDb(dbPath);
    dropTriggers(db);
    // Rebuild entry 2 with edited content AND recomputed-looking hashes, but
    // signed by nobody — the attacker has no door key.
    db.exec(`
      UPDATE ledger_entries
      SET entry_json = json_set(entry_json, '$.cost.amount', 0,
                                '$.door_signature.value', 'Zm9yZ2Vk')
      WHERE seq = 2;
    `);
    db.close();

    const result = await verify(dbPath);
    expect(result.ok).toBe(false);
  });
});

describe('key-swap forgery — why the door key must be anchored out-of-band', () => {
  test('FULL RE-SIGN + META KEY SWAP: self-anchored verify passes (documented boundary); the real key catches it', async () => {
    const { dbPath, publicKeyHex: realDoorKey } = buildChainDb(3);

    // Attacker capabilities: file access, own keypair — NOT the door key.
    const db = rawDb(dbPath);
    dropTriggers(db);
    db.exec('DROP TRIGGER ledger_meta_no_update;');
    db.exec('DROP TRIGGER ledger_meta_no_delete;');

    const { privateKey } = generateKeyPairSync('ed25519');
    const jwk = createPublicKey(privateKey).export({ format: 'jwk' });
    const attackerPub = base64UrlToBytes(jwk.x as string);
    const attackerPubHex = bytesToHex(attackerPub);
    const attackerKeyId = sha256Hex(attackerPub);

    // Rewrite the whole chain: zero every cost, recompute hashes, re-link,
    // re-sign under the attacker key — a COMPETENT forge, unlike the lazy
    // one above.
    const rows = db
      .prepare('SELECT seq, entry_json FROM ledger_entries ORDER BY seq ASC')
      .all() as { seq: number; entry_json: string }[];
    let prevHash = GENESIS_PREV_HASH;
    const update = db.prepare(
      'UPDATE ledger_entries SET entry_hash = ?, prev_hash = ?, entry_json = ? WHERE seq = ?'
    );
    for (const row of rows) {
      const original = JSON.parse(row.entry_json) as LedgerEntryV1;
      const { entry_hash: _oldHash, door_signature: _oldSig, ...rest } = original;
      const preimage: LedgerEntryPreimage = {
        ...rest,
        cost: { ...rest.cost, amount: 0 },
        prev_hash: prevHash,
      };
      const newHash = computeEntryHash(preimage);
      const signature = cryptoSign(null, hexToBytes(newHash), privateKey);
      const forged: LedgerEntryV1 = {
        ...preimage,
        entry_hash: newHash,
        door_signature: {
          alg: 'EdDSA',
          key_id: attackerKeyId,
          key_provenance: 'software',
          value: bytesToBase64Url(new Uint8Array(signature)),
        },
      };
      update.run(newHash, preimage.prev_hash, JSON.stringify(forged), row.seq);
      prevHash = newHash;
    }
    db.prepare("UPDATE ledger_meta SET value = ? WHERE key = 'door_public_key'").run(attackerPubHex);
    db.prepare("UPDATE ledger_meta SET value = ? WHERE key = 'door_key_id'").run(attackerKeyId);
    db.close();

    const { meta, entries } = readLedger(dbPath);

    // Self-anchored verification (key from the file itself) PASSES — honest
    // statement of the boundary: the file cannot vouch for its own author.
    const selfAnchored = await verifyChain(entries, { doorPublicKey: meta.door_public_key });
    expect(selfAnchored.ok).toBe(true);

    // Verification against the out-of-band real door key catches the forgery.
    const independent = await verifyChain(entries, { doorPublicKey: realDoorKey });
    expect(independent.ok).toBe(false);
    if (!independent.ok) expect(independent.failure.code).toBe('KEY_MISMATCH');
  });
});

describe('documented boundaries (closed by later sessions)', () => {
  test('TRUNCATION: dropping the tail is locally invisible — witnessing (S6) closes this', async () => {
    const { dbPath } = buildChainDb(4);
    const db = rawDb(dbPath);
    dropTriggers(db);
    db.exec('DELETE FROM ledger_entries WHERE seq > 2;');
    db.close();

    // Honest statement of the local boundary: a truncated chain is
    // internally consistent. The witnessed head (streamed off-machine,
    // SPEC §6 lock 4) is what makes truncation provable.
    const result = await verify(dbPath);
    expect(result.ok).toBe(true);
    expect(result.ok && result.entries).toBe(2);
  });

  test.todo('S6: verify against witnessed head detects truncation');
  test.todo('S6: ROLLBACK to an older full copy detected via witness/monotonic counter');
  test.todo('S1: cross-door entries and key rotation verified via key directory');
});
