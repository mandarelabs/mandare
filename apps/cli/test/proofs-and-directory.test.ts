import { mkdtempSync, writeFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { describe, expect, test } from 'vitest';

import { Ledger } from '@mandarelabs/ledger';
import { LLM_CALL_INTENT } from '@mandarelabs/spec';
import { parseKeyDirectory, verifyInclusion } from '@mandarelabs/verifier';

import { buildDirectory } from '../src/directory.js';
import { parsePrevHead, runVerify } from '../src/verify.js';

/** Build a ledger with N entries; returns paths and the door key locations. */
function buildDb(entryCount: number): {
  dbPath: string;
  keyPath: string;
  dir: string;
  doorPublicKeyHex: string;
} {
  const dir = mkdtempSync(join(tmpdir(), 'mandare-cli-proofs-'));
  const dbPath = join(dir, 'ledger.db');
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
  return { dbPath, keyPath: `${dbPath}.doorkey.pem`, dir, doorPublicKeyHex };
}

describe('mandare verify — tree head and consistency (--prev-head)', () => {
  test('reports the RFC 6962 tree head on every valid verify', async () => {
    const { dbPath } = buildDb(4);
    const output = await runVerify(dbPath);
    expect(output.exitCode).toBe(0);
    expect(output.json.tree).toMatchObject({ size: 4 });
    expect(output.json.tree?.root).toMatch(/^[0-9a-f]{64}$/);
    expect(output.lines.join('\n')).toContain(`tree:     size=4 root=${output.json.tree?.root}`);
  });

  test('append-only growth is CONSISTENT against a recorded head', async () => {
    const { dbPath, keyPath } = buildDb(3);
    const first = await runVerify(dbPath);
    const recorded = first.json.tree;
    expect(recorded).toBeDefined();
    if (recorded === undefined) {
      return;
    }

    const ledger = Ledger.open(dbPath, { doorId: 'gateway:test', keyPath });
    ledger.append({
      actor: 'did:example:agent',
      mandate_id: 'mnd_test',
      action: { type: LLM_CALL_INTENT, target: 'openrouter.ai', request_hash: 'c'.repeat(64) },
      cost: { amount: 0, currency: 'USD', tokens_in: 0, tokens_out: 0 },
    });
    ledger.close();

    const second = await runVerify(dbPath, { prevHead: recorded });
    expect(second.exitCode).toBe(0);
    expect(second.json.consistency?.status).toBe('extended');
    expect(second.lines.join('\n')).toContain('CONSISTENT');
  });

  test('unchanged ledger is CONSISTENT (identical) against its own head', async () => {
    const { dbPath } = buildDb(2);
    const first = await runVerify(dbPath);
    const recorded = first.json.tree;
    if (recorded === undefined) {
      expect.unreachable('valid verify must report a tree head');
    }
    const second = await runVerify(dbPath, { prevHead: recorded });
    expect(second.exitCode).toBe(0);
    expect(second.json.consistency?.status).toBe('identical');
  });

  test('ROLLBACK: fewer entries than the recorded head → exit 1', async () => {
    const { dbPath } = buildDb(4);
    const before = await runVerify(dbPath);
    const recorded = before.json.tree;
    if (recorded === undefined) {
      expect.unreachable('valid verify must report a tree head');
    }

    const db = new DatabaseSync(dbPath);
    db.exec('DROP TRIGGER ledger_entries_no_delete;');
    db.exec('DELETE FROM ledger_entries WHERE seq > 2;');
    db.close();

    const after = await runVerify(dbPath, { prevHead: recorded });
    expect(after.exitCode).toBe(1);
    expect(after.json.consistency?.status).toBe('rollback');
    expect(after.lines.join('\n')).toContain('ROLLBACK DETECTED');
  });

  test('parsePrevHead validates its input shape', () => {
    expect(parsePrevHead(`3:${'a'.repeat(64)}`)).toEqual({ size: 3, root: 'a'.repeat(64) });
    expect(() => parsePrevHead('nope')).toThrow(/size/);
    expect(() => parsePrevHead('3:xyz')).toThrow(/size/);
  });
});

describe('mandare verify --prove (inclusion proofs)', () => {
  test('emits a verifiable inclusion proof for an entry', async () => {
    const { dbPath } = buildDb(5);
    const output = await runVerify(dbPath, { proveSeq: 3 });
    expect(output.exitCode).toBe(0);
    const proof = output.json.inclusion_proof;
    expect(proof).toBeDefined();
    if (proof === undefined) {
      return;
    }
    expect(proof).toMatchObject({ seq: 3, index: 2, tree_size: 5 });
    expect(
      await verifyInclusion({
        index: proof.index,
        treeSize: proof.tree_size,
        entryHash: proof.entry_hash,
        proof: proof.proof,
        root: proof.root,
      })
    ).toBe(true);
  });

  test('out-of-range seq → exit 1', async () => {
    const { dbPath } = buildDb(2);
    const output = await runVerify(dbPath, { proveSeq: 9 });
    expect(output.exitCode).toBe(1);
    expect(output.lines.join('\n')).toContain('out of range');
  });
});

describe('mandare directory + verify --key-directory', () => {
  test('directory built from the door PEM verifies the ledger (closes H1)', async () => {
    const { dbPath, keyPath, dir } = buildDb(3);
    const directoryPath = join(dir, 'directory.json');
    const built = await buildDirectory({ keyPaths: [keyPath], role: 'door', outPath: directoryPath });
    expect(built.exitCode).toBe(0);

    // The document is a valid JWKS in our verifier profile.
    const parsed = await parseKeyDirectory(JSON.parse(await readFile(directoryPath, 'utf8')));
    expect(parsed.keys).toHaveLength(1);
    expect(parsed.keys[0]?.role).toBe('door');

    const output = await runVerify(dbPath, { keyDirectory: directoryPath });
    expect(output.exitCode).toBe(0);
    expect(output.lines.join('\n')).toContain('key directory supplied out-of-band');
  });

  test("a FOREIGN directory rejects the ledger's signer (KEY_UNKNOWN)", async () => {
    const victim = buildDb(2);
    const attacker = buildDb(1); // unrelated door key
    const directoryPath = join(attacker.dir, 'directory.json');
    await buildDirectory({ keyPaths: [attacker.keyPath], outPath: directoryPath });

    const output = await runVerify(victim.dbPath, { keyDirectory: directoryPath });
    expect(output.exitCode).toBe(1);
    expect(output.lines.join('\n')).toContain('KEY_UNKNOWN');
  });

  test('directory output carries kid (RFC 7638 thumbprint), use, alg, and windows', async () => {
    const { keyPath } = buildDb(1);
    const built = await buildDirectory({ keyPaths: [keyPath], nbf: 100, exp: 200 });
    const jwks = JSON.parse(built.directoryJson) as {
      keys: { kid?: string; use?: string; alg?: string; nbf?: number; exp?: number }[];
    };
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]?.kid).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(jwks.keys[0]).toMatchObject({ use: 'sig', alg: 'EdDSA', nbf: 100, exp: 200 });
  });

  test('rejects non-Ed25519 and unreadable PEMs loudly', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'mandare-cli-dir-'));
    const badPath = join(dir, 'not-a-key.pem');
    writeFileSync(badPath, 'garbage');
    await expect(buildDirectory({ keyPaths: [badPath] })).rejects.toThrow(/not a readable PEM/);
  });
});
