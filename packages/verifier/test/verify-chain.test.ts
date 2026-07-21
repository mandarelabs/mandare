import type { webcrypto } from 'node:crypto';

import { beforeAll, describe, expect, test } from 'vitest';

import {
  GENESIS_PREV_HASH,
  bytesToBase64Url,
  bytesToHex,
  computeEntryHashAsync,
  hexToBytes,
  sha256HexAsync,
  LLM_CALL_INTENT,
  type LedgerEntryPreimage,
  type LedgerEntryV1,
} from '@mandarelabs/spec';

import { verifyChain } from '../src/index.js';

/**
 * These tests build chains from scratch with WebCrypto only — deliberately
 * independent of @mandarelabs/ledger, since the verifier must hold against
 * any writer implementation.
 */

let privateKey: webcrypto.CryptoKey;
let publicKeyHex: string;
let keyId: string;

beforeAll(async () => {
  const pair = (await globalThis.crypto.subtle.generateKey('Ed25519', true, [
    'sign',
    'verify',
  ])) as webcrypto.CryptoKeyPair;
  privateKey = pair.privateKey;
  const raw = new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', pair.publicKey));
  publicKeyHex = bytesToHex(raw);
  keyId = await sha256HexAsync(raw);
});

async function makeEntry(
  seq: number,
  prevHash: string,
  mutate?: (preimage: LedgerEntryPreimage) => LedgerEntryPreimage
): Promise<LedgerEntryV1> {
  let preimage: LedgerEntryPreimage = {
    schema_version: 1,
    seq,
    ts: '2026-07-21T12:00:00.000Z',
    door_id: 'gateway:test',
    actor: 'did:example:agent',
    mandate_id: 'mnd_test',
    action: { type: LLM_CALL_INTENT, target: 'openrouter.ai', request_hash: 'b'.repeat(64) },
    cost: { amount: 1500, currency: 'USD', tokens_in: 10, tokens_out: 20 },
    salt: seq.toString(16).padStart(32, '0'),
    prev_hash: prevHash,
  };
  if (mutate) {
    preimage = mutate(preimage);
  }
  const entryHash = await computeEntryHashAsync(preimage);
  const signature = await globalThis.crypto.subtle.sign(
    'Ed25519',
    privateKey,
    hexToBytes(entryHash) as Uint8Array<ArrayBuffer>
  );
  return {
    ...preimage,
    entry_hash: entryHash,
    door_signature: {
      alg: 'EdDSA',
      key_id: keyId,
      key_provenance: 'software',
      value: bytesToBase64Url(new Uint8Array(signature)),
    },
  };
}

async function makeChain(length: number): Promise<LedgerEntryV1[]> {
  const entries: LedgerEntryV1[] = [];
  let prevHash = GENESIS_PREV_HASH;
  for (let seq = 1; seq <= length; seq += 1) {
    const entry = await makeEntry(seq, prevHash);
    entries.push(entry);
    prevHash = entry.entry_hash;
  }
  return entries;
}

describe('verifyChain — intact chains', () => {
  test('accepts a valid chain and reports the head hash', async () => {
    const chain = await makeChain(5);
    const result = await verifyChain(chain, { doorPublicKey: publicKeyHex });
    expect(result).toEqual({ ok: true, entries: 5, headHash: chain[4]?.entry_hash });
  });

  test('accepts an empty ledger', async () => {
    const result = await verifyChain([], { doorPublicKey: publicKeyHex });
    expect(result).toEqual({ ok: true, entries: 0, headHash: null });
  });

  test('accepts the public key as raw bytes too', async () => {
    const chain = await makeChain(2);
    const result = await verifyChain(chain, { doorPublicKey: hexToBytes(publicKeyHex) });
    expect(result.ok).toBe(true);
  });
});

describe('verifyChain — tampered chains fail loudly', () => {
  test('edited field → ENTRY_HASH_MISMATCH at the edited seq', async () => {
    const chain = await makeChain(4);
    const victim = chain[2] as LedgerEntryV1;
    chain[2] = { ...victim, cost: { ...victim.cost, amount: 999_999_999 } };
    const result = await verifyChain(chain, { doorPublicKey: publicKeyHex });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.code).toBe('ENTRY_HASH_MISMATCH');
      expect(result.failure.seq).toBe(3);
    }
  });

  test('deleted middle entry → SEQ_GAP', async () => {
    const chain = await makeChain(4);
    chain.splice(1, 1);
    const result = await verifyChain(chain, { doorPublicKey: publicKeyHex });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.code).toBe('SEQ_GAP');
  });

  test('reordered entries → SEQ_GAP', async () => {
    const chain = await makeChain(3);
    [chain[1], chain[2]] = [chain[2] as LedgerEntryV1, chain[1] as LedgerEntryV1];
    const result = await verifyChain(chain, { doorPublicKey: publicKeyHex });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.code).toBe('SEQ_GAP');
  });

  test('rewritten history with consistent seqs → PREV_HASH_MISMATCH', async () => {
    const chain = await makeChain(3);
    // Attacker rebuilds entry 2 wholesale (valid hash+sig) but cannot know
    // the original's hash linkage seen by entry 3.
    chain[1] = await makeEntry(2, (chain[0] as LedgerEntryV1).entry_hash, (p) => ({
      ...p,
      cost: { ...p.cost, amount: 0 },
    }));
    const result = await verifyChain(chain, { doorPublicKey: publicKeyHex });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.code).toBe('PREV_HASH_MISMATCH');
      expect(result.failure.seq).toBe(3);
    }
  });

  test('chain not starting at 1 → SEQ_START', async () => {
    const chain = (await makeChain(3)).slice(1);
    const result = await verifyChain(chain, { doorPublicKey: publicKeyHex });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.code).toBe('SEQ_START');
  });

  test('first entry without genesis prev_hash → GENESIS_MISMATCH', async () => {
    const entry = await makeEntry(1, 'e'.repeat(64));
    const result = await verifyChain([entry], { doorPublicKey: publicKeyHex });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.code).toBe('GENESIS_MISMATCH');
  });

  test('signature from a different key → KEY_MISMATCH', async () => {
    const chain = await makeChain(1);
    const otherPair = (await globalThis.crypto.subtle.generateKey('Ed25519', true, [
      'sign',
      'verify',
    ])) as webcrypto.CryptoKeyPair;
    const otherRaw = new Uint8Array(
      await globalThis.crypto.subtle.exportKey('raw', otherPair.publicKey)
    );
    const result = await verifyChain(chain, { doorPublicKey: otherRaw });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.code).toBe('KEY_MISMATCH');
  });

  test('forged signature bytes → SIGNATURE_INVALID', async () => {
    const chain = await makeChain(1);
    const victim = chain[0] as LedgerEntryV1;
    chain[0] = {
      ...victim,
      door_signature: {
        ...victim.door_signature,
        value: bytesToBase64Url(new Uint8Array(64)),
      },
    };
    const result = await verifyChain(chain, { doorPublicKey: publicKeyHex });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.code).toBe('SIGNATURE_INVALID');
  });

  test('garbage rows → SCHEMA_INVALID', async () => {
    const result = await verifyChain([{ hello: 'world' }], { doorPublicKey: publicKeyHex });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.code).toBe('SCHEMA_INVALID');
  });
});
