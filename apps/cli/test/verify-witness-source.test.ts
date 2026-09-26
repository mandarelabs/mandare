import { afterEach, describe, expect, test } from 'vitest';

import { Ledger, loadOrCreateDoorKey, readLedger } from '@mandarelabs/ledger';

import { runVerify, type VerifyOptions } from '../src/verify.js';
import {
  directoryFile,
  doctorAmount,
  honestLedger,
  rewitnessUnderFreshSource,
  rewriteAndResign,
  setMeta,
  startWitness,
  tmp,
  truncate,
  witnessCurrentTree,
  type WitnessFixture,
} from './helpers/witness-attacks.js';

/**
 * W-1 (audit 2026-09): `mandare verify --witness` must look the witnessed
 * head history up under the source the VERIFYING key defines — never under
 * the `door_key_id` the (untrusted) ledger file declares. Otherwise an
 * attacker re-witnesses a truncated or rewritten tree under a FRESH source,
 * repoints `ledger_meta.door_key_id`, and the witness check reports
 * CONSISTENT for a history it never saw. Same family as S8/C1 (the
 * certificate path's bound-source rule), applied to `verify --witness`.
 */

let witness: WitnessFixture;

afterEach(async () => {
  await witness?.server.close();
});

function witnessOption(): NonNullable<VerifyOptions['witness']> {
  return { url: witness.url, publicKeyHex: witness.publicKeyHex };
}

describe('W-1: verify --witness binds the witnessed source to the verifying key', () => {
  test('honest ledger: --door-key + --witness → exit 0, CONSISTENT', async () => {
    witness = await startWitness();
    const { dbPath, doorKey } = await honestLedger(witness, 5);
    const output = await runVerify(dbPath, { doorPublicKey: doorKey.publicKeyHex, witness: witnessOption() });
    expect(output.exitCode).toBe(0);
    expect(output.lines.join('\n')).toMatch(/witness:\s+CONSISTENT/);
    expect(output.json.witness?.source_id).toBe(doorKey.keyId);
    expect(output.json.witness?.source_mismatch).toBeNull();
  });

  test('baseline (no repoint): truncation still reports TRUNCATION DETECTED', async () => {
    witness = await startWitness();
    const { dbPath, doorKey } = await honestLedger(witness, 5);
    truncate(dbPath, 3);
    const output = await runVerify(dbPath, { doorPublicKey: doorKey.publicKeyHex, witness: witnessOption() });
    expect(output.exitCode).toBe(1);
    expect(output.lines.join('\n')).toContain('TRUNCATION DETECTED');
  });

  test('baseline (no repoint): an operator rewrite still reports FORK DETECTED', async () => {
    witness = await startWitness();
    const { dbPath, doorKey } = await honestLedger(witness, 5);
    rewriteAndResign(dbPath, doorKey, doctorAmount(1));
    const output = await runVerify(dbPath, { doorPublicKey: doorKey.publicKeyHex, witness: witnessOption() });
    expect(output.exitCode).toBe(1);
    expect(output.lines.join('\n')).toContain('FORK DETECTED');
  });

  test('truncate to 3, re-witness under a fresh key, repoint door_key_id → --door-key <real> exits 1', async () => {
    witness = await startWitness();
    const { dbPath, doorKey } = await honestLedger(witness, 5);
    truncate(dbPath, 3); // no key needed
    const fresh = await rewitnessUnderFreshSource(witness, dbPath);
    expect(readLedger(dbPath).meta.door_key_id).toBe(fresh.keyId); // the repoint took

    const output = await runVerify(dbPath, { doorPublicKey: doorKey.publicKeyHex, witness: witnessOption() });
    const text = output.lines.join('\n');
    expect(output.exitCode).toBe(1);
    expect(text).toContain('SOURCE MISMATCH');
    expect(text).toContain('TRUNCATION DETECTED'); // looked up under sha256(real key), not the repointed id
    expect(text).not.toMatch(/witness:\s+CONSISTENT/);
    expect(output.json.witness?.source_id).toBe(doorKey.keyId);
    expect(output.json.witness?.consistency?.status).toBe('rollback');
  });

  test('the same truncation self-anchored → exit 1 (declared source is not sha256(door_public_key))', async () => {
    witness = await startWitness();
    const { dbPath } = await honestLedger(witness, 5);
    truncate(dbPath, 3);
    await rewitnessUnderFreshSource(witness, dbPath);

    const output = await runVerify(dbPath, { witness: witnessOption() });
    const text = output.lines.join('\n');
    expect(output.exitCode).toBe(1);
    expect(text).toContain('SOURCE MISMATCH');
    expect(text).toContain('TRUNCATION DETECTED');
  });

  test('operator rewrite under the real key, re-witnessed under a fresh source + repoint → exit 1', async () => {
    witness = await startWitness();
    const { dbPath, doorKey } = await honestLedger(witness, 5);
    rewriteAndResign(dbPath, doorKey, doctorAmount(2));
    await rewitnessUnderFreshSource(witness, dbPath);

    const output = await runVerify(dbPath, { doorPublicKey: doorKey.publicKeyHex, witness: witnessOption() });
    const text = output.lines.join('\n');
    expect(output.exitCode).toBe(1);
    expect(text).toContain('FORK DETECTED');
    expect(text).not.toMatch(/witness:\s+CONSISTENT/);
  });

  test('directory mode: the source comes from the keys that signed the chain → exit 1', async () => {
    witness = await startWitness();
    const { dbPath, doorKey } = await honestLedger(witness, 5);
    truncate(dbPath, 3);
    await rewitnessUnderFreshSource(witness, dbPath);

    const output = await runVerify(dbPath, {
      keyDirectory: directoryFile(doorKey.publicKeyHex),
      witness: witnessOption(),
    });
    const text = output.lines.join('\n');
    expect(output.exitCode).toBe(1);
    expect(text).toContain('TRUNCATION DETECTED');
    expect(output.json.witness?.mode).toBe('directory');
  });

  test('directory mode: a ledger truncated to ZERO entries is checked against every directory key', async () => {
    witness = await startWitness();
    const { dbPath, doorKey } = await honestLedger(witness, 4);
    truncate(dbPath, 0);
    await rewitnessUnderFreshSource(witness, dbPath).catch(() => undefined);
    const output = await runVerify(dbPath, {
      keyDirectory: directoryFile(doorKey.publicKeyHex),
      witness: witnessOption(),
    });
    expect(output.exitCode).toBe(1);
    expect(output.lines.join('\n')).toContain('TRUNCATION DETECTED');
  });

  test('directory mode, empty chain: a never-witnessed directory key does not mask the verdict in --json', async () => {
    witness = await startWitness();
    const { dbPath, doorKey } = await honestLedger(witness, 0);
    await witnessCurrentTree(witness, dbPath, doorKey); // the empty tree, witnessed
    const stranger = loadOrCreateDoorKey(tmp('stranger.pem')); // in the directory, never witnessed
    const path = tmp('two-keys.json');
    (await import('node:fs')).writeFileSync(
      path,
      JSON.stringify({
        keys: [doorKey, stranger].map((key) => ({
          kty: 'OKP',
          crv: 'Ed25519',
          x: Buffer.from(key.publicKeyHex, 'hex').toString('base64url'),
        })),
      })
    );
    const output = await runVerify(dbPath, { keyDirectory: path, witness: witnessOption() });
    expect(output.exitCode).toBe(0);
    expect(output.json.witness?.consistency?.status).toBe('identical');
    expect(output.json.witness?.sources).toHaveLength(2);
  });

  test('self-anchored honest run labels the witness line as a self-declared source', async () => {
    witness = await startWitness();
    const { dbPath } = await honestLedger(witness, 3);
    const output = await runVerify(dbPath, { witness: witnessOption() });
    expect(output.exitCode).toBe(0);
    expect(output.lines.join('\n')).toMatch(/self-declared source — pass --door-key to bind/);
    expect(output.json.witness?.mode).toBe('self-declared');
  });

  test('a full re-key forgery passes self-anchored (unavoidable, labeled) but dies under --door-key <real>', async () => {
    witness = await startWitness();
    const { dbPath, doorKey } = await honestLedger(witness, 4);
    const forger = loadOrCreateDoorKey(tmp('forger.pem'));
    rewriteAndResign(dbPath, forger, (entries) => entries.slice(0, 2));
    setMeta(dbPath, { door_public_key: forger.publicKeyHex, door_key_id: forger.keyId });
    await witnessCurrentTree(witness, dbPath, forger);

    const selfAnchored = await runVerify(dbPath, { witness: witnessOption() });
    expect(selfAnchored.lines.join('\n')).toMatch(/self-declared source — pass --door-key to bind/);

    const bound = await runVerify(dbPath, { doorPublicKey: doorKey.publicKeyHex, witness: witnessOption() });
    expect(bound.exitCode).toBe(1);
  });
});

describe('W-4: a witnessed entry cannot claim a time after it was witnessed', () => {
  test('forward-dated entries (ts a day past the witness record) → exit 1, TIMELINE VIOLATION', async () => {
    witness = await startWitness();
    const dbPath = tmp('ledger.db');
    const ledger = Ledger.open(dbPath, { doorId: 'gateway:test' });
    for (let i = 0; i < 3; i += 1) {
      ledger.append({
        actor: 'did:example:agent',
        mandate_id: 'mnd_test',
        action: { type: 'llm.call.intent', target: 't', request_hash: 'e'.repeat(64) },
        cost: { amount: 1, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
      });
    }
    const doorKey = ledger.signer();
    ledger.close();
    const tomorrow = new Date(Date.now() + 86_400_000).toISOString();
    rewriteAndResign(dbPath, doorKey, (entries) =>
      entries.map((entry, i) => (i === 2 ? { ...entry, ts: tomorrow } : entry))
    );
    await witnessCurrentTree(witness, dbPath, doorKey); // witnessed NOW

    const output = await runVerify(dbPath, { doorPublicKey: doorKey.publicKeyHex, witness: witnessOption() });
    expect(output.exitCode).toBe(1);
    expect(output.lines.join('\n')).toContain('TIMELINE VIOLATION');
    expect(output.json.witness?.timeline_violation).toMatch(/seq 3/);
  });
});
