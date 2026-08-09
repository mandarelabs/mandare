import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { afterEach, describe, expect, test, vi } from 'vitest';

import { Ledger, loadOrCreateDoorKey, readLedger } from '@mandarelabs/ledger';
import { computeEntryHash, hexToBytes, sha256Hex, type LedgerEntryV1 } from '@mandarelabs/spec';
import { buildWitnessServer, type WitnessServer } from '@mandarelabs/witness';
import { MockAnchor, WitnessClient } from '@mandarelabs/witness-protocol';

import { runCertify, runCertifyVerify } from '../src/certify.js';

/**
 * `mandare certify` end-to-end against the REAL witness server: an honest
 * ledger certifies and third-party-verifies; truncated and forked ledgers
 * are REFUSED at build time (no doomed certificate ships — S6 review M5),
 * and a tampered certificate fails third-party verification.
 */

let witness: WitnessServer | null = null;
let witnessUrl = '';
let witnessKeyHex = '';

afterEach(async () => {
  await witness?.close();
  witness = null;
  vi.restoreAllMocks();
});

function tmp(name: string): string {
  return join(mkdtempSync(join(tmpdir(), 'mandare-certify-test-')), name);
}

async function startWitness(): Promise<void> {
  const key = loadOrCreateDoorKey(tmp('witness.pem'));
  witnessKeyHex = key.publicKeyHex;
  witness = await buildWitnessServer({ dbPath: tmp('witness.db'), key, anchor: new MockAnchor() });
  witnessUrl = await witness.app.listen({ host: '127.0.0.1', port: 0 });
}

function makeLedger(): { dbPath: string; ledger: Ledger } {
  const dbPath = tmp('ledger.db');
  const ledger = Ledger.open(dbPath, { doorId: 'gateway:test' });
  return { dbPath, ledger };
}

async function stream(ledger: Ledger, count: number): Promise<void> {
  const client = new WitnessClient({
    url: witnessUrl,
    signer: ledger.signer(),
    readEntryHashes: () => Promise.resolve(ledger.entryHashes()),
    witnessPublicKeyHex: witnessKeyHex,
  });
  for (let i = 0; i < count; i += 1) {
    ledger.append({
      actor: 'did:example:agent',
      mandate_id: 'mnd_test',
      action: { type: 'llm.call.intent', target: 't', request_hash: sha256Hex(`c${i}`) },
      cost: { amount: 100 + i, currency: 'EUR', tokens_in: 1, tokens_out: 1 },
    });
    await client.sync();
  }
}

/** Rewrite + re-sign with the real door key (the strongest local attacker). */
function rewriteAndResign(dbPath: string, mutate: (entries: LedgerEntryV1[]) => LedgerEntryV1[]): void {
  const { entries } = readLedger(dbPath);
  const doctored = mutate(entries as LedgerEntryV1[]);
  const signer = loadOrCreateDoorKey(`${dbPath}.doorkey.pem`);
  const db = new DatabaseSync(dbPath);
  db.exec('DROP TRIGGER ledger_entries_no_update;');
  db.exec('DROP TRIGGER ledger_entries_no_delete;');
  db.exec('DELETE FROM ledger_entries;');
  const insert = db.prepare(
    'INSERT INTO ledger_entries (seq, entry_hash, prev_hash, entry_json) VALUES (?, ?, ?, ?)'
  );
  let prevHash = '0'.repeat(64);
  doctored.forEach((entry, index) => {
    const { entry_hash: _h, door_signature: _s, ...rest } = entry;
    const preimage = { ...rest, seq: index + 1, prev_hash: prevHash };
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

function certifyArgs(dbPath: string, extra: Partial<Parameters<typeof runCertify>[2]> = {}) {
  return {
    witnessUrl,
    witnessPublicKeyHex: witnessKeyHex,
    discloseSeqs: [] as number[],
    ...extra,
  };
}

describe('mandare certify', () => {
  test('honest ledger: certificate built + third-party verified', async () => {
    await startWitness();
    const { dbPath, ledger } = makeLedger();
    await stream(ledger, 5);
    ledger.close();
    const certPath = tmp('cert.json');
    vi.spyOn(console, 'log').mockImplementation(() => undefined);

    const code = await runCertify(process.env, dbPath, certifyArgs(dbPath, { discloseSeqs: [2, 4], outPath: certPath }));
    expect(code).toBe(0);

    const verifyCode = await runCertifyVerify(certPath, { witnessPublicKeyHex: witnessKeyHex, json: true });
    expect(verifyCode).toBe(0);
    const cert = JSON.parse(readFileSync(certPath, 'utf8')) as { disclosed: unknown[] };
    expect(cert.disclosed).toHaveLength(2);
  });

  test('TRUNCATION: a chain shorter than the witnessed head is REFUSED', async () => {
    await startWitness();
    const { dbPath, ledger } = makeLedger();
    await stream(ledger, 6);
    ledger.close();
    rewriteAndResign(dbPath, (entries) => entries.slice(0, 4)); // drop newest 2
    const errors: string[] = [];
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
      errors.push(String(chunk));
      return true;
    });
    const code = await runCertify(process.env, dbPath, certifyArgs(dbPath));
    expect(code).toBe(1);
    expect(errors.join('')).toMatch(/truncated/i);
  });

  test('FORK: a re-signed rewrite grown past the witnessed head is REFUSED (M5)', async () => {
    await startWitness();
    const { dbPath, ledger } = makeLedger();
    await stream(ledger, 5);
    ledger.close();
    // Rewrite a prefix, re-sign, then GROW to size 7 — size > witnessed, but
    // a fork, not an append-only extension.
    rewriteAndResign(dbPath, (entries) => {
      const doctored = [...entries];
      doctored[1] = { ...doctored[1]!, cost: { ...doctored[1]!.cost, amount: 3 } };
      return doctored;
    });
    const forked = Ledger.open(dbPath, { doorId: 'gateway:test' });
    forked.append({
      actor: 'a',
      mandate_id: 'm',
      action: { type: 'llm.call.intent', target: 't', request_hash: 'a'.repeat(64) },
      cost: { amount: 1, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
    });
    forked.append({
      actor: 'a',
      mandate_id: 'm',
      action: { type: 'llm.call.intent', target: 't', request_hash: 'a'.repeat(64) },
      cost: { amount: 1, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
    });
    forked.close();

    const errors: string[] = [];
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
      errors.push(String(chunk));
      return true;
    });
    const code = await runCertify(process.env, dbPath, certifyArgs(dbPath));
    expect(code).toBe(1);
    expect(errors.join('')).toMatch(/fork/i);
  });

  test('third-party rejects a certificate with a doctored disclosed entry', async () => {
    await startWitness();
    const { dbPath, ledger } = makeLedger();
    await stream(ledger, 4);
    ledger.close();
    const certPath = tmp('cert.json');
    vi.spyOn(console, 'log').mockImplementation(() => undefined);
    await runCertify(process.env, dbPath, certifyArgs(dbPath, { discloseSeqs: [2], outPath: certPath }));

    const cert = JSON.parse(readFileSync(certPath, 'utf8')) as {
      disclosed: { entry: { cost: { amount: number } } }[];
    };
    cert.disclosed[0]!.entry.cost.amount = 1;
    const doctoredPath = tmp('doctored.json');
    (await import('node:fs')).writeFileSync(doctoredPath, JSON.stringify(cert));

    const outputs: string[] = [];
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
      outputs.push(String(chunk));
      return true;
    });
    const code = await runCertifyVerify(doctoredPath, { witnessPublicKeyHex: witnessKeyHex });
    expect(code).toBe(1);
    expect(outputs.join('')).toMatch(/INVALID/);
  });
});
