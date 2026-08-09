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
