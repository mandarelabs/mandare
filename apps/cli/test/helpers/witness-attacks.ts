import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { Ledger, loadOrCreateDoorKey, readLedger, type DoorKey } from '@mandarelabs/ledger';
import {
  bytesToBase64Url,
  computeEntryHash,
  hexToBytes,
  sha256Hex,
  type LedgerEntryPreimage,
  type LedgerEntryV1,
} from '@mandarelabs/spec';
import { buildWitnessServer, type WitnessServer } from '@mandarelabs/witness';
import { MockAnchor, WitnessClient } from '@mandarelabs/witness-protocol';

/**
 * Attack kit for the witness-source red-team (W-1): an honest door streaming
 * to a real reference witness, and the file-level / key-holding attackers
 * that doctor its ledger afterwards.
 */

export function tmp(name: string): string {
  return join(mkdtempSync(join(tmpdir(), 'mandare-witness-attack-')), name);
}

export interface WitnessFixture {
  server: WitnessServer;
  url: string;
  publicKeyHex: string;
}

export async function startWitness(): Promise<WitnessFixture> {
  const key = loadOrCreateDoorKey(tmp('witness.pem'));
  const server = await buildWitnessServer({ dbPath: tmp('witness.db'), key, anchor: new MockAnchor() });
  const url = await server.app.listen({ host: '127.0.0.1', port: 0 });
  return { server, url, publicKeyHex: key.publicKeyHex };
}

function streamTo(witness: WitnessFixture, signer: DoorKey, hashes: () => string[]): WitnessClient {
  return new WitnessClient({
    url: witness.url,
    signer,
    readEntryHashes: () => Promise.resolve(hashes()),
    witnessPublicKeyHex: witness.publicKeyHex,
  });
}

/** An honest door: `count` entries, each streamed to the witness. */
export async function honestLedger(
  witness: WitnessFixture,
  count: number
): Promise<{ dbPath: string; doorKey: DoorKey }> {
  const dbPath = tmp('ledger.db');
  const ledger = Ledger.open(dbPath, { doorId: 'gateway:test' });
  const client = streamTo(witness, ledger.signer(), () => ledger.entryHashes());
  for (let i = 0; i < count; i += 1) {
    ledger.append({
      actor: 'did:example:agent',
      mandate_id: 'mnd_test',
      action: { type: 'llm.call.intent', target: 't', request_hash: sha256Hex(`w${i}`) },
      cost: { amount: 100 + i, currency: 'EUR', tokens_in: 1, tokens_out: 1 },
    });
    await client.sync();
  }
  const doorKey = ledger.signer();
  ledger.close();
  return { dbPath, doorKey };
}

/** File-level access: every storage lock (trigger) is removable. */
export function openUnlocked(dbPath: string): DatabaseSync {
  const db = new DatabaseSync(dbPath);
  const triggers = db.prepare("SELECT name FROM sqlite_master WHERE type = 'trigger'").all() as {
    name: string;
  }[];
  for (const { name } of triggers) db.exec(`DROP TRIGGER "${name}";`);
  return db;
}

/** Drop the newest entries — needs no key at all. */
export function truncate(dbPath: string, keep: number): void {
  const db = openUnlocked(dbPath);
  db.prepare('DELETE FROM ledger_entries WHERE seq > ?').run(keep);
  db.close();
}

/** Overwrite ledger_meta rows (the file's self-declared identity). */
export function setMeta(dbPath: string, rows: Record<string, string>): void {
  const db = openUnlocked(dbPath);
  const upsert = db.prepare('INSERT OR REPLACE INTO ledger_meta (key, value) VALUES (?, ?)');
  for (const [key, value] of Object.entries(rows)) upsert.run(key, value);
  db.close();
}

/** Rewrite history and re-sign it with `signer` (the key-holding operator, or a forger). */
export function rewriteAndResign(
  dbPath: string,
  signer: DoorKey,
  mutate: (entries: LedgerEntryV1[]) => LedgerEntryV1[]
): void {
  const doctored = mutate(readLedger(dbPath).entries as LedgerEntryV1[]);
  const db = openUnlocked(dbPath);
  db.exec('DELETE FROM ledger_entries;');
  const insert = db.prepare(
    'INSERT INTO ledger_entries (seq, entry_hash, prev_hash, entry_json) VALUES (?, ?, ?, ?)'
  );
  let prevHash = '0'.repeat(64);
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
        value: bytesToBase64Url(signer.sign(hexToBytes(entryHash))),
      },
    };
    insert.run(resigned.seq, resigned.entry_hash, resigned.prev_hash, JSON.stringify(resigned));
    prevHash = entryHash;
  });
  db.close();
}

/** Amount of entry `index` doctored to 1 ("we never spent that"). */
export function doctorAmount(index: number): (entries: LedgerEntryV1[]) => LedgerEntryV1[] {
  return (entries) =>
    entries.map((entry, i) => (i === index ? { ...entry, cost: { ...entry.cost, amount: 1 } } : entry));
}

/** Witness the ledger's CURRENT tree under `signer`'s source. */
export async function witnessCurrentTree(
  witness: WitnessFixture,
  dbPath: string,
  signer: DoorKey
): Promise<void> {
  const hashes = (readLedger(dbPath).entries as LedgerEntryV1[]).map((entry) => entry.entry_hash);
  await streamTo(witness, signer, () => hashes).sync();
}

/**
 * The split timeline: witness the doctored tree under a FRESH key (the
 * reference witness registers any new source on first contact — correctly,
 * sources are self-authenticating), then repoint the file's declared source.
 */
export async function rewitnessUnderFreshSource(
  witness: WitnessFixture,
  dbPath: string
): Promise<DoorKey> {
  const fresh = loadOrCreateDoorKey(tmp('fresh.pem'));
  await witnessCurrentTree(witness, dbPath, fresh);
  setMeta(dbPath, { door_key_id: fresh.keyId });
  return fresh;
}

/** A one-key JWKS file (the out-of-band key directory). */
export function directoryFile(publicKeyHex: string): string {
  const path = tmp('directory.json');
  writeFileSync(
    path,
    JSON.stringify({
      keys: [{ kty: 'OKP', crv: 'Ed25519', x: bytesToBase64Url(hexToBytes(publicKeyHex)) }],
    })
  );
  return path;
}
