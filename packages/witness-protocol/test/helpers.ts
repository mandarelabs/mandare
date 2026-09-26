import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from 'node:crypto';

import { bytesToHex, sha256Hex, computeEntryHash, type LedgerEntryPreimage, type LedgerEntryV1, bytesToBase64Url } from '@mandarelabs/spec';

import type { HeadSigner } from '../src/signing.js';

/** A test Ed25519 signer with the exact structural shape of the ledger's DoorKey. */
export interface TestSigner extends HeadSigner {
  privateKey: KeyObject;
}

export function makeSigner(): TestSigner {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' });
  const raw = new Uint8Array(Buffer.from(jwk.x as string, 'base64url'));
  return {
    keyId: sha256Hex(raw),
    publicKeyHex: bytesToHex(raw),
    privateKey,
    sign: (data: Uint8Array) => new Uint8Array(cryptoSign(null, data, privateKey)),
  };
}

/**
 * Build a REAL, verifiable ledger chain in memory: schema-valid entries,
 * correct hashes, correct door signatures. What certificate verification
 * consumes — no SQLite needed at this layer.
 */
export function buildChain(signer: TestSigner, length: number): LedgerEntryV1[] {
  const entries: LedgerEntryV1[] = [];
  let prevHash = '0'.repeat(64);
  for (let seq = 1; seq <= length; seq += 1) {
    const preimage: LedgerEntryPreimage = {
      schema_version: 1,
      seq,
      ts: new Date().toISOString(),
      door_id: 'gateway:test',
      actor: 'did:example:agent',
      mandate_id: 'mnd_test',
      action: { type: 'llm.call.intent', target: 'api.example.com', request_hash: 'b'.repeat(64) },
      cost: { amount: 100 + seq, currency: 'EUR', tokens_in: 1, tokens_out: 1 },
      salt: bytesToHex(globalThis.crypto.getRandomValues(new Uint8Array(16))),
      prev_hash: prevHash,
    };
    const entryHash = computeEntryHash(preimage);
    entries.push({
      ...preimage,
      entry_hash: entryHash,
      door_signature: {
        alg: 'EdDSA',
        key_id: signer.keyId,
        key_provenance: 'software',
        value: bytesToBase64Url(
          new Uint8Array(cryptoSign(null, Buffer.from(entryHash, 'hex'), signer.privateKey))
        ),
      },
    });
    prevHash = entryHash;
  }
  return entries;
}

export function entryHashesOf(entries: readonly LedgerEntryV1[]): string[] {
  return entries.map((entry) => entry.entry_hash);
}

/**
 * W-2 "hexlify bomb": a ~100-byte OTS receipt whose op chain doubles the
 * message `hexlifyOps` times (hexlify = hex-encode = 2× length). Unbounded
 * op application turns N=40 into a 32 TiB message — a heap OOM, not an error.
 */
export function hexlifyBombProof(hexlifyOps: number, digest: Uint8Array = new Uint8Array(32).fill(0x11)): Uint8Array {
  const magic = [
    0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
    0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
  ];
  return Uint8Array.from([...magic, 0x01, 0x08, ...digest, ...hexlifyCalendarBody(hexlifyOps)]);
}

/** The same bomb as a calendar's POST /digest response body (no header, no digest). */
export function hexlifyCalendarBody(hexlifyOps: number): Uint8Array {
  const uri = [...new TextEncoder().encode('https://calendar.example')];
  const pendingTag = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
  const payload = [uri.length, ...uri];
  return Uint8Array.from([
    ...new Array<number>(hexlifyOps).fill(0xf3),
    0x00,
    ...pendingTag,
    payload.length,
    ...payload,
  ]);
}
