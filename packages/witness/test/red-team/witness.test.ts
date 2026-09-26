import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { afterEach, describe, expect, test } from 'vitest';

import { Ledger, readLedger } from '@mandarelabs/ledger';
import {
  computeTreeHead,
  consistencyProof,
  verifyChain,
  verifyConsistency,
} from '@mandarelabs/verifier';
import {
  computeEntryHash,
  sha256Hex,
  hexToBytes,
  type LedgerEntryV1,
  type LedgerEntryPreimage,
} from '@mandarelabs/spec';
import {
  WITNESS_PROTOCOL,
  WitnessClient,
  fetchVerifiedWitnessedHead,
  signPayload,
  type HeadSubmissionPayload,
} from '@mandarelabs/witness-protocol';

import { startWitness, tempDir, type RunningWitness } from '../helpers.js';

/**
 * RED-TEAM SUITE (rule R5) — the witness closes the oldest documented
 * boundary in the stack (truncation, S0) and opens a NEW trust surface of
 * its own. Both must hold:
 *
 * 1. "The rewrite that can't hide": an attacker with file access AND the
 *    real door key doctors the ledger AFTER heads were witnessed —
 *    self-anchored verification passes, the witnessed history convicts.
 * 2. The witness itself resists: nobody can pollute another source's
 *    history, feed the witness a forked timeline, replay stale submissions,
 *    or forge aggregate inclusion.
 * 3. The wire stays content-free: witnessed material never lets a curious
 *    witness (or wire observer) confirm guessed ledger contents — the
 *    per-entry salt defeats the dictionary.
 */

let running: RunningWitness | null = null;
afterEach(async () => {
  await running?.close();
  running = null;
});

const SAMPLE = (i: number) => ({
  actor: 'did:example:agent',
  mandate_id: 'mnd_test',
  action: {
    type: 'llm.call.intent',
    target: 'api.example.com',
    request_hash: sha256Hex(`req-${i}`),
  },
  cost: { amount: 1000 + i, currency: 'EUR', tokens_in: 3, tokens_out: 7 },
});

function makeLedger(entries: number): { ledger: Ledger; dbPath: string } {
  const dbPath = join(tempDir(), 'ledger.db');
  const ledger = Ledger.open(dbPath, { doorId: 'gateway:test' });
  for (let i = 0; i < entries; i += 1) ledger.append(SAMPLE(i));
  return { ledger, dbPath };
}

function clientFor(ledger: Ledger, witness: RunningWitness): WitnessClient {
  return new WitnessClient({
    url: witness.url,
    signer: ledger.signer(),
    readEntryHashes: () => Promise.resolve(ledger.entryHashes()),
    witnessPublicKeyHex: witness.key.publicKeyHex,
  });
}

/** The competent local attacker: rewrites the DB and RE-SIGNS with the real door key. */
function rewriteAndResign(dbPath: string, ledger: Ledger, mutate: (entries: LedgerEntryV1[]) => LedgerEntryV1[]): void {
  const { entries } = readLedger(dbPath);
  const doctored = mutate(entries as LedgerEntryV1[]);
  const db = new DatabaseSync(dbPath);
  db.exec('DROP TRIGGER ledger_entries_no_update;');
  db.exec('DROP TRIGGER ledger_entries_no_delete;');
  db.exec('DELETE FROM ledger_entries;');
  const insert = db.prepare(
    'INSERT INTO ledger_entries (seq, entry_hash, prev_hash, entry_json) VALUES (?, ?, ?, ?)'
  );
  let prevHash = '0'.repeat(64);
  const signer = ledger.signer();
  doctored.forEach((entry, index) => {
    const { entry_hash: _h, door_signature: _s, ...rest } = entry;
    const preimage: LedgerEntryPreimage = { ...rest, seq: index + 1, prev_hash: prevHash };
    const entryHash = computeEntryHash(preimage);
    const resigned: LedgerEntryV1 = {
      ...preimage,
      entry_hash: entryHash,
      door_signature: {
        alg: 'EdDSA',
        key_id: signer.keyId,
        key_provenance: signer.provenance,
        value: Buffer.from(signer.sign(hexToBytes(entryHash))).toString('base64url'),
      },
    };
    insert.run(resigned.seq, resigned.entry_hash, resigned.prev_hash, JSON.stringify(resigned));
    prevHash = entryHash;
  });
  db.close();
}

/**
 * What `mandare verify --witness` computes, distilled. The source is the
 * key the chain verifies under — sha256(door_public_key) — never the file's
 * declared door_key_id (W-1: a repointed id would select an attacker's
 * parallel timeline). apps/cli's red-team drives the real binary.
 */
async function witnessVerdict(
  dbPath: string,
  witness: RunningWitness
): Promise<'consistent' | 'truncation' | 'fork'> {
  const { meta, entries } = readLedger(dbPath);
  const hashes = (entries as { entry_hash: string }[]).map((entry) => entry.entry_hash);
  const local = await computeTreeHead(hashes);
  const verified = await fetchVerifiedWitnessedHead({
    url: witness.url,
    sourceId: sha256Hex(hexToBytes(meta.door_public_key)),
    witnessPublicKeyHex: witness.key.publicKeyHex,
  });
  if (verified === null) throw new Error('no witnessed head');
  const recorded = verified.record.head;
  if (local.size < recorded.size) return 'truncation';
  if (local.size === recorded.size) {
    return local.root === recorded.root ? 'consistent' : 'fork';
  }
  const proof = await consistencyProof(hashes, recorded.size);
  const ok = await verifyConsistency({
    size1: recorded.size,
    root1: recorded.root,
    size2: local.size,
    root2: local.root,
    proof,
  });
  return ok ? 'consistent' : 'fork';
}

describe('the rewrite that cannot hide (locks 4+5 close the S0 truncation boundary)', () => {
  test('TRUNCATION-AFTER-WITNESS: self-anchored verify passes, the witness convicts', async () => {
    running = await startWitness();
    const { ledger, dbPath } = makeLedger(6);
    await clientFor(ledger, running).sync();

    // The attacker drops the newest 2 entries and re-signs — the strongest
    // local form (real door key, perfect internal consistency).
    rewriteAndResign(dbPath, ledger, (entries) => entries.slice(0, 4));

    const { meta, entries } = readLedger(dbPath);
    const selfAnchored = await verifyChain(entries, { doorPublicKey: meta.door_public_key });
    expect(selfAnchored.ok).toBe(true); // the lie is locally perfect…

    expect(await witnessVerdict(dbPath, running)).toBe('truncation'); // …and globally impossible
    ledger.close();
  });

  test('REWRITE-AFTER-WITNESS: doctored amount, re-signed chain — fork detected', async () => {
    running = await startWitness();
    const { ledger, dbPath } = makeLedger(6);
    await clientFor(ledger, running).sync();

    rewriteAndResign(dbPath, ledger, (entries) => {
      const doctored = [...entries];
      doctored[2] = {
        ...doctored[2]!,
        cost: { ...doctored[2]!.cost, amount: 1 }, // "we never spent that"
      };
      return doctored;
    });

    const { meta, entries } = readLedger(dbPath);
    expect((await verifyChain(entries, { doorPublicKey: meta.door_public_key })).ok).toBe(true);
    expect(await witnessVerdict(dbPath, running)).toBe('fork');
    ledger.close();
  });

  test('honest growth after witnessing stays consistent (no false positives)', async () => {
    running = await startWitness();
    const { ledger, dbPath } = makeLedger(3);
    await clientFor(ledger, running).sync();
    ledger.append(SAMPLE(99));
    expect(await witnessVerdict(dbPath, running)).toBe('consistent');
    ledger.close();
  });
});

describe('the witness as a trust surface', () => {
  test('FORGERY: a submission for another source (no door key) is refused', async () => {
    running = await startWitness();
    const { ledger } = makeLedger(3);
    await clientFor(ledger, running).sync();

    // The attacker knows the victim's source id and head, owns a different key.
    const { ledger: attacker } = makeLedger(1);
    const payload: HeadSubmissionPayload = {
      protocol: WITNESS_PROTOCOL,
      type: 'head.submit',
      source_id: ledger.doorKeyId, // victim's source
      door_public_key: attacker.signer().publicKeyHex, // attacker's key
      head: { size: 1, root: 'aa'.repeat(32) },
      prev: null,
      consistency_proof: [],
      ts: new Date().toISOString(),
    };
    const signed = await signPayload(payload, attacker.signer());
    const response = await fetch(`${running.url}/v1/heads`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(signed),
    });
    expect(response.status).toBe(403); // source_id ≠ sha256(door_public_key)
    ledger.close();
    attacker.close();
  });

  test('FORGERY: valid source id, tampered payload signature is refused', async () => {
    running = await startWitness();
    const { ledger } = makeLedger(2);
    const client = clientFor(ledger, running);
    await client.sync();

    const signer = ledger.signer();
    const payload: HeadSubmissionPayload = {
      protocol: WITNESS_PROTOCOL,
      type: 'head.submit',
      source_id: signer.keyId,
      door_public_key: signer.publicKeyHex,
      head: { size: 99, root: 'bb'.repeat(32) },
      prev: null,
      consistency_proof: [],
      ts: new Date().toISOString(),
    };
    const signed = await signPayload(payload, signer);
    signed.payload.head.size = 100; // tamper AFTER signing
    const response = await fetch(`${running.url}/v1/heads`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(signed),
    });
    expect(response.status).toBe(403);
    ledger.close();
  });

  test('SPLIT VIEW: a door-key-holding attacker cannot fork the witnessed history', async () => {
    running = await startWitness();
    const { ledger, dbPath } = makeLedger(5);
    await clientFor(ledger, running).sync();

    // Attacker rewrites locally (real key) and tries to CONTINUE streaming
    // from the doctored chain — the witness refuses the non-extension.
    rewriteAndResign(dbPath, ledger, (entries) => {
      const doctored = [...entries];
      doctored[1] = { ...doctored[1]!, cost: { ...doctored[1]!.cost, amount: 2 } };
      return doctored;
    });
    const doctored = Ledger.open(dbPath, { doorId: 'gateway:test' });
    doctored.append(SAMPLE(7)); // keep growing on the forked timeline
    const client = clientFor(doctored, running);
    await expect(client.sync()).rejects.toThrow(/rejected|refused|witness/i);

    // The witnessed history still names the HONEST head.
    const verified = await fetchVerifiedWitnessedHead({
      url: running.url,
      sourceId: doctored.doorKeyId,
      witnessPublicKeyHex: running.key.publicKeyHex,
    });
    expect(verified?.record.head.size).toBe(5);
    ledger.close();
    doctored.close();
  });

  test('REPLAY: an old captured submission cannot roll the witnessed head back', async () => {
    running = await startWitness();
    const { ledger } = makeLedger(2);
    const client = clientFor(ledger, running);
    await client.sync();

    // Capture-equivalent: rebuild the exact size-2 submission the client
    // sent (prev: null) and replay it after growth.
    const signer = ledger.signer();
    const oldHead = await computeTreeHead(ledger.entryHashes());
    ledger.append(SAMPLE(50));
    await client.sync(); // witness now at size 3

    const replay = await signPayload(
      {
        protocol: WITNESS_PROTOCOL,
        type: 'head.submit' as const,
        source_id: signer.keyId,
        door_public_key: signer.publicKeyHex,
        head: oldHead,
        prev: null,
        consistency_proof: [],
        ts: new Date().toISOString(),
      },
      signer
    );
    const response = await fetch(`${running.url}/v1/heads`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(replay),
    });
    expect(response.status).toBe(409);
    const verified = await fetchVerifiedWitnessedHead({
      url: running.url,
      sourceId: signer.keyId,
      witnessPublicKeyHex: running.key.publicKeyHex,
    });
    expect(verified?.record.head.size).toBe(3); // unchanged
    ledger.close();
  });

  test('STORAGE: witnessed history and epoch commitments refuse mutation', async () => {
    running = await startWitness();
    const { ledger } = makeLedger(2);
    await clientFor(ledger, running).sync();
    await running.witness.runAnchor();

    const raw = new DatabaseSync(running.dbPath);
    expect(() => raw.exec('UPDATE witness_heads SET size = 1;')).toThrow(/append-only/);
    expect(() => raw.exec('DELETE FROM witness_heads;')).toThrow(/append-only/);
    expect(() => raw.exec("UPDATE witness_sources SET public_key = 'ff';")).toThrow(/write-once/);
    expect(() => raw.exec("UPDATE witness_epochs SET aggregate_root = 'ff';")).toThrow(/immutable/);
    expect(() => raw.exec('DELETE FROM witness_epochs;')).toThrow(/append-only/);
    raw.close();
    ledger.close();
  });

  test('STORAGE: an anchor receipt may progress but never regress (M4)', async () => {
    running = await startWitness();
    const { ledger } = makeLedger(2);
    await clientFor(ledger, running).sync();
    await running.witness.runAnchor(); // MockAnchor lands a confirmed receipt

    const raw = new DatabaseSync(running.dbPath);
    // A confirmed epoch is frozen: no downgrade, no receipt erasure.
    expect(() => raw.exec("UPDATE witness_epochs SET anchor_status = 'pending' WHERE epoch = 1;")).toThrow(
      /may only progress/
    );
    expect(() => raw.exec("UPDATE witness_epochs SET anchor_status = 'none' WHERE epoch = 1;")).toThrow(
      /may only progress/
    );
    expect(() => raw.exec('UPDATE witness_epochs SET ots_base64 = NULL WHERE epoch = 1;')).toThrow(
      /may only progress/
    );
    expect(() => raw.exec("UPDATE witness_epochs SET anchor_kind = 'evil' WHERE epoch = 1;")).toThrow(
      /may only progress/
    );
    raw.close();
    ledger.close();
  });

  test('STORAGE: a pending receipt may advance to confirmed (the ONE legal progression)', async () => {
    running = await startWitness();
    const { ledger } = makeLedger(2);
    await clientFor(ledger, running).sync();
    const raw = new DatabaseSync(running.dbPath);
    // Hand-seed a PENDING epoch and prove the forward path is allowed.
    raw.exec(
      "INSERT INTO witness_epochs (epoch, created_at, aggregate_size, aggregate_root, leaves_json, anchor_kind, anchor_status, ots_base64) VALUES (2, '2026-08-09T10:00:00Z', 1, 'ab', '[]', 'opentimestamps', 'pending', 'proofbytes')"
    );
    expect(() =>
      raw.exec("UPDATE witness_epochs SET anchor_status = 'confirmed' WHERE epoch = 2;")
    ).not.toThrow();
    raw.close();
    ledger.close();
  });

  test('FORGERY: epoch inclusion for a source not in the epoch 404s', async () => {
    running = await startWitness();
    const { ledger } = makeLedger(2);
    await clientFor(ledger, running).sync();
    await running.witness.runAnchor();
    const response = await fetch(`${running.url}/v1/epochs/1/inclusion/${'d'.repeat(64)}`);
    expect(response.status).toBe(404);
    ledger.close();
  });

  test('SALT: witnessed material never confirms guessed entry contents', async () => {
    running = await startWitness();
    const { ledger, dbPath } = makeLedger(1);
    await clientFor(ledger, running).sync();

    // The attacker (a curious witness / wire observer) holds the streamed
    // head hash AND knows the entry's full business content — everything
    // except the 16-byte salt.
    const { entries } = readLedger(dbPath);
    const entry = entries[0] as LedgerEntryV1;
    const { entry_hash, door_signature: _sig, salt, ...known } = entry;

    // Dictionary attack over the guessable space: recompute the entry hash
    // for MANY guessed salts. None may match the witnessed hash unless the
    // guess IS the real 128-bit salt.
    let matches = 0;
    for (let guess = 0; guess < 4096; guess += 1) {
      const guessedSalt = guess.toString(16).padStart(32, '0');
      const candidate = computeEntryHash({ ...known, salt: guessedSalt } as LedgerEntryPreimage);
      if (candidate === entry_hash) matches += 1;
    }
    expect(matches).toBe(0);
    // Sanity: the REAL salt does reproduce the hash (the commitment is real).
    expect(computeEntryHash({ ...known, salt } as LedgerEntryPreimage)).toBe(entry_hash);
    ledger.close();
  });
});
