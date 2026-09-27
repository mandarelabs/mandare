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
  canonicalJson,
  type LedgerEntryV1,
} from '@mandarelabs/spec';
import { parseStoredEntries, verifyChain } from '@mandarelabs/verifier';

import {
  computeTreeHead,
  consistencyProof,
  directoryFromPublicKeys,
  parseKeyDirectory,
  verifyConsistency,
} from '@mandarelabs/verifier';

import { loadOrCreateDoorKey, type DoorKey } from '../../src/door-key.js';
import { Ledger, readLedger, readLedgerRows } from '../../src/ledger.js';
import { buildChainDb, forgedHashSql, sampleInput } from '../helpers.js';

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

describe('W-3: no in-place rewrite with the triggers intact (INSERT OR REPLACE)', () => {
  // SQLite's REPLACE deletes the conflicting row WITHOUT firing DELETE
  // triggers (recursive_triggers is off), so UPDATE/DELETE triggers alone let
  // `INSERT OR REPLACE` rewrite history. BEFORE INSERT triggers close it.
  test('REPLACE of an existing seq is refused', () => {
    const { dbPath } = buildChainDb(3);
    const db = rawDb(dbPath);
    expect(() =>
      db.exec(`INSERT OR REPLACE INTO ledger_entries (seq, entry_hash, prev_hash, entry_json)
               SELECT seq, entry_hash, prev_hash, '{}' FROM ledger_entries WHERE seq = 2;`)
    ).toThrow(/append-only/);
    db.close();
  });

  test('REPLACE via an entry_hash collision at a NEW seq is refused (it would delete the old row)', () => {
    const { dbPath } = buildChainDb(3);
    const db = rawDb(dbPath);
    expect(() =>
      db.exec(`INSERT OR REPLACE INTO ledger_entries (seq, entry_hash, prev_hash, entry_json)
               SELECT 99, entry_hash, prev_hash, entry_json FROM ledger_entries WHERE seq = 2;`)
    ).toThrow(/append-only/);
    expect((db.prepare('SELECT COUNT(*) AS n FROM ledger_entries').get() as { n: number }).n).toBe(3);
    db.close();
  });

  test('REPLACE of a meta row (door_key_id repoint) is refused', () => {
    const { dbPath } = buildChainDb(1);
    const db = rawDb(dbPath);
    expect(() =>
      db.exec("INSERT OR REPLACE INTO ledger_meta (key, value) VALUES ('door_key_id', 'ff');")
    ).toThrow(/write-once/);
    db.close();
  });
});

describe('W-3: one stored text, one reading (duplicate-key parser differential)', () => {
  function forgeDuplicateKeys(dbPath: string, seq: number): void {
    const db = rawDb(dbPath);
    for (const { name } of db.prepare("SELECT name FROM sqlite_master WHERE type = 'trigger'").all() as {
      name: string;
    }[]) {
      db.exec(`DROP TRIGGER "${name}";`);
    }
    const { entry_json } = db.prepare('SELECT entry_json FROM ledger_entries WHERE seq = ?').get(seq) as {
      entry_json: string;
    };
    // First-key-wins readers (SQLite json_extract) see the forgery; last-key-wins
    // JSON.parse — what the verifier hashes — still sees the genuine entry.
    const forged = `{"actor":"did:example:forged","cost":{"amount":999000000,"currency":"EUR","tokens_in":0,"tokens_out":0},${entry_json.slice(1)}`;
    db.prepare('UPDATE ledger_entries SET entry_json = ? WHERE seq = ?').run(forged, seq);
    db.close();
  }

  test('DUPLICATE KEYS: the hash chain alone stays VALID — the stored-row check convicts', async () => {
    const { dbPath } = buildChainDb(3);
    forgeDuplicateKeys(dbPath, 2);

    // The differential, demonstrated: the chain verifies, SQL shows the forgery.
    expect((await verify(dbPath)).ok).toBe(true);
    const db = rawDb(dbPath);
    const shown = db.prepare("SELECT json_extract(entry_json, '$.actor') AS actor FROM ledger_entries WHERE seq = 2").get() as {
      actor: string;
    };
    db.close();
    expect(shown.actor).toBe('did:example:forged');

    const stored = parseStoredEntries(readLedgerRows(dbPath).rows);
    expect(stored.ok).toBe(false);
    if (!stored.ok) {
      expect(stored.failure.code).toBe('STORAGE_MISMATCH');
      expect(stored.failure.seq).toBe(2);
    }
  });

  test('the doors store canonical JSON, so an honest ledger passes the stored-row check', async () => {
    const { dbPath, publicKeyHex } = buildChainDb(3);
    const { rows } = readLedgerRows(dbPath);
    const stored = parseStoredEntries(rows);
    expect(stored.ok).toBe(true);
    if (stored.ok) {
      for (const [index, entry] of stored.entries.entries()) {
        expect(rows[index]?.text).toBe(canonicalJson(entry));
      }
      expect((await verifyChain(stored.entries, { doorPublicKey: publicKeyHex })).ok).toBe(true);
    }
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
      SELECT 4, ${forgedHashSql('deadbeef', 'feedface')}, entry_hash, entry_json
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
      SELECT 3, ${forgedHashSql('aa', 'bb')}, entry_hash, entry_json
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
    // The W-3 BEFORE INSERT trigger refuses this first; remove it so the
    // PRIMARY KEY is proven as an independent layer (the trigger has its own tests).
    db.exec('DROP TRIGGER ledger_entries_no_replace;');
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

  // S6 CLOSED THIS BOUNDARY: the witness service streams heads off-machine
  // and `mandare verify --witness` fetches them automatically. The full loop
  // (real ledger → WitnessClient → reference witness server → truncation and
  // real-door-key rewrite both convicted while self-anchored verification
  // passes) is red-teamed end-to-end in
  // packages/witness/test/red-team/witness.test.ts; the client's refusal
  // matrix (forged/replayed acks, history conflicts) lives in
  // packages/witness-protocol/test/client.test.ts; the Postgres driver's
  // witnessed-head detection is below in tamper-pg.test.ts.
});

/**
 * S1: the RFC 6962 tree head is the mechanism that turns "truncation is
 * locally invisible" into a DETECTED attack — provided a head recorded
 * earlier is available from somewhere the attacker cannot rewrite. Locally
 * that is a head the operator noted down (`mandare verify --prev-head`);
 * S6 streams the same heads to the witness service, closing the last gap
 * (an attacker who also controls the recorded head).
 */
describe('rollback & fork detection against a recorded tree head', () => {
  async function recordHead(dbPath: string) {
    const { entries } = readLedger(dbPath);
    return computeTreeHead((entries as { entry_hash: string }[]).map((e) => e.entry_hash));
  }

  test('TRUNCATION vs recorded head: shrunken ledger is caught by size alone', async () => {
    const { dbPath } = buildChainDb(4);
    const recorded = await recordHead(dbPath);

    const db = rawDb(dbPath);
    dropTriggers(db);
    db.exec('DELETE FROM ledger_entries WHERE seq > 2;');
    db.close();

    // Locally still a valid chain (the documented boundary above)…
    const result = await verify(dbPath);
    expect(result.ok).toBe(true);

    // …but against the recorded head the attack is visible: the tree shrank.
    const current = await recordHead(dbPath);
    expect(current.size).toBeLessThan(recorded.size);
  });

  test('ROLLBACK + regrow (fork) with the REAL door key: consistency proof fails', async () => {
    // The strongest rollback: the attacker restores an older copy and lets
    // the legitimate door keep appending — every signature is genuine, the
    // chain verifies, sizes match. Only the recorded head exposes the fork.
    const { dbPath } = buildChainDb(4);
    const recorded = await recordHead(dbPath);

    // Roll back to 3 entries (≈ restoring yesterday's backup).
    const db = rawDb(dbPath);
    dropTriggers(db);
    db.exec('DELETE FROM ledger_entries WHERE seq = 4;');
    db.close();

    // The real door appends a DIFFERENT entry 4 — an honest-looking fork.
    const ledger = Ledger.open(dbPath, { doorId: 'gateway:test' });
    ledger.append(sampleInput({ action: { type: 'llm.call.intent', target: 'openrouter.ai', request_hash: 'f'.repeat(64) } }));
    ledger.close();

    // Chain fully valid, same size as recorded…
    const result = await verify(dbPath);
    expect(result.ok).toBe(true);
    const current = await recordHead(dbPath);
    expect(current.size).toBe(recorded.size);

    // …but the recorded head is NOT a prefix of this history.
    const { entries } = readLedger(dbPath);
    const entryHashes = (entries as { entry_hash: string }[]).map((e) => e.entry_hash);
    const proof = await consistencyProof(entryHashes, recorded.size);
    expect(
      await verifyConsistency({
        size1: recorded.size,
        root1: recorded.root,
        size2: current.size,
        root2: current.root,
        proof,
      })
    ).toBe(false);

    // Control: an honest append-only continuation stays consistent.
    const honestRecorded = await recordHead(dbPath);
    const ledger2 = Ledger.open(dbPath, { doorId: 'gateway:test' });
    ledger2.append(sampleInput());
    ledger2.close();
    const { entries: grown } = readLedger(dbPath);
    const grownHashes = (grown as { entry_hash: string }[]).map((e) => e.entry_hash);
    const grownHead = await computeTreeHead(grownHashes);
    const honestProof = await consistencyProof(grownHashes, honestRecorded.size);
    expect(
      await verifyConsistency({
        size1: honestRecorded.size,
        root1: honestRecorded.root,
        size2: grownHead.size,
        root2: grownHead.root,
        proof: honestProof,
      })
    ).toBe(true);
  });
});

/**
 * S1: cross-door chains and key rotation, verified via the OUT-OF-BAND key
 * directory (SPEC §4 — one JWKS format for door and agent keys). The
 * directory is what `--door-key` graduates into: authorship comes from keys
 * the verifier obtained independently, never from the ledger file.
 */
describe('multi-door entries & key rotation via key directory', () => {
  /** Append a tail entry signed by a FOREIGN door key (a second, legitimate door). */
  function appendForeignDoorEntry(
    dbPath: string,
    options: { ts: string; doorId: string }
  ): { publicKeyHex: string } {
    const db = rawDb(dbPath);
    const head = db
      .prepare('SELECT seq, entry_hash, entry_json FROM ledger_entries ORDER BY seq DESC LIMIT 1')
      .get() as { seq: number; entry_hash: string; entry_json: string };

    const { privateKey } = generateKeyPairSync('ed25519');
    const jwk = createPublicKey(privateKey).export({ format: 'jwk' });
    const publicKey = base64UrlToBytes(jwk.x as string);
    const template = JSON.parse(head.entry_json) as LedgerEntryV1;
    const { entry_hash: _hash, door_signature: _sig, ...rest } = template;
    const preimage: LedgerEntryPreimage = {
      ...rest,
      seq: head.seq + 1,
      ts: options.ts,
      door_id: options.doorId,
      prev_hash: head.entry_hash,
    };
    const entryHash = computeEntryHash(preimage);
    const entry: LedgerEntryV1 = {
      ...preimage,
      entry_hash: entryHash,
      door_signature: {
        alg: 'EdDSA',
        key_id: sha256Hex(publicKey),
        key_provenance: 'software',
        value: bytesToBase64Url(new Uint8Array(cryptoSign(null, hexToBytes(entryHash), privateKey))),
      },
    };
    // Appending is LEGAL — no triggers dropped; multi-door is normal growth.
    db.prepare(
      'INSERT INTO ledger_entries (seq, entry_hash, prev_hash, entry_json) VALUES (?, ?, ?, ?)'
    ).run(entry.seq, entry.entry_hash, entry.prev_hash, JSON.stringify(entry));
    db.close();
    return { publicKeyHex: bytesToHex(publicKey) };
  }

  test('cross-door chain verifies ONLY when every signing key is in the directory', async () => {
    const { dbPath, publicKeyHex: doorAKey } = buildChainDb(2);
    const { publicKeyHex: doorBKey } = appendForeignDoorEntry(dbPath, {
      // After door A's entries: since W-4 a chain's timeline may not regress.
      ts: new Date(Date.now() + 60_000).toISOString(),
      doorId: 'vault:test',
    });

    const { entries } = readLedger(dbPath);
    const fullDirectory = await directoryFromPublicKeys([doorAKey, doorBKey]);
    const complete = await verifyChain(entries, { keyDirectory: fullDirectory });
    expect(complete.ok).toBe(true);

    // Directory missing door B (e.g. a rogue process signing with its own
    // key): the entry is rejected loudly, not trusted.
    const partialDirectory = await directoryFromPublicKeys([doorAKey]);
    const partial = await verifyChain(entries, { keyDirectory: partialDirectory });
    expect(partial.ok).toBe(false);
    if (!partial.ok) {
      expect(partial.failure.code).toBe('KEY_UNKNOWN');
      expect(partial.failure.seq).toBe(3);
    }
  });

  test('ROTATION: a rotated-out (stolen) door key cannot vouch for new entries', async () => {
    const { dbPath, publicKeyHex: doorAKey } = buildChainDb(2); // entries ts = now
    // Attacker stole door key A AFTER it was rotated out; forges a plausible
    // tail entry signed by... themselves they cannot (no key A here), but the
    // equivalent attack is an entry timestamped after A's exp. Rotation cutoff
    // is set to the past, so ALL of A's entries land outside its window.
    const rotationCutoff = Math.floor(Date.parse('2020-01-01T00:00:00Z') / 1000);
    const directory = await parseKeyDirectory({
      keys: [
        {
          kty: 'OKP',
          crv: 'Ed25519',
          x: hexKeyToB64Url(doorAKey),
          exp: rotationCutoff,
          'mnd:role': 'door',
        },
      ],
    });
    const { entries } = readLedger(dbPath);
    const result = await verifyChain(entries, { keyDirectory: directory });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.code).toBe('KEY_EXPIRED');
  });

  test('ROTATION + BACKDATE (W-4): a stolen rotated-out key writing behind the new key → TS_REGRESSION', async () => {
    // Door key A (the ledger's own) is rotated out at T; door key B takes over
    // and writes. A thief holding A appends a tail entry with ts BACKDATED into
    // A's window — the per-entry key-window check passes it (ts < exp), so the
    // only thing that can convict it is the timeline: it claims a time before
    // B's entry that precedes it in the chain.
    const { dbPath, publicKeyHex: doorAKey } = buildChainDb(2); // ts = now
    const now = Date.now();
    const rotationAt = Math.floor((now + 60_000) / 1000);
    const { publicKeyHex: doorBKey } = appendForeignDoorEntry(dbPath, {
      ts: new Date(now + 120_000).toISOString(), // B writes after the rotation
      doorId: 'gateway:test',
    });
    const stolenA = loadOrCreateDoorKey(`${dbPath}.doorkey.pem`);
    appendSignedEntry(dbPath, stolenA, new Date(now + 30_000).toISOString()); // inside A's window

    const directory = await parseKeyDirectory({
      keys: [
        { kty: 'OKP', crv: 'Ed25519', x: hexKeyToB64Url(doorAKey), exp: rotationAt, 'mnd:role': 'door' },
        { kty: 'OKP', crv: 'Ed25519', x: hexKeyToB64Url(doorBKey), nbf: rotationAt, 'mnd:role': 'door' },
      ],
    });
    const { entries } = readLedger(dbPath);
    const result = await verifyChain(entries, { keyDirectory: directory });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.code).toBe('TS_REGRESSION');
      expect(result.failure.seq).toBe(4);
    }
    // Control: without the thief's entry the rotated chain verifies.
    expect((await verifyChain(entries.slice(0, 3), { keyDirectory: directory })).ok).toBe(true);
  });

  /** Append a tail entry signed with `signer` (legal growth: no trigger dropped). */
  function appendSignedEntry(dbPath: string, signer: DoorKey, ts: string): void {
    const db = rawDb(dbPath);
    const head = db
      .prepare('SELECT seq, entry_hash, entry_json FROM ledger_entries ORDER BY seq DESC LIMIT 1')
      .get() as { seq: number; entry_hash: string; entry_json: string };
    const { entry_hash: _h, door_signature: _s, ...rest } = JSON.parse(head.entry_json) as LedgerEntryV1;
    const preimage: LedgerEntryPreimage = { ...rest, seq: head.seq + 1, ts, prev_hash: head.entry_hash };
    const entryHash = computeEntryHash(preimage);
    const entry: LedgerEntryV1 = {
      ...preimage,
      entry_hash: entryHash,
      door_signature: {
        alg: 'EdDSA',
        key_id: signer.keyId,
        key_provenance: signer.provenance,
        value: bytesToBase64Url(signer.sign(hexToBytes(entryHash))),
      },
    };
    db.prepare(
      'INSERT INTO ledger_entries (seq, entry_hash, prev_hash, entry_json) VALUES (?, ?, ?, ?)'
    ).run(entry.seq, entry.entry_hash, entry.prev_hash, canonicalJson(entry));
    db.close();
  }

  function hexKeyToB64Url(hex: string): string {
    return bytesToBase64Url(hexToBytes(hex));
  }
});
