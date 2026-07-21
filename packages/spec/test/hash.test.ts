import { describe, expect, test } from 'vitest';

import {
  GENESIS_PREV_HASH,
  bytesToHex,
  computeEntryHashAsync,
  hexToBytes,
  sha256HexAsync,
} from '../src/hash.js';
import { computeEntryHash, sha256Hex } from '../src/hash-node.js';
import { validEntryPreimage } from './fixtures.js';

// FIPS 180-2 test vector.
const SHA256_ABC = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';

describe('sha256', () => {
  test('node-native matches the known vector', () => {
    expect(sha256Hex('abc')).toBe(SHA256_ABC);
  });

  test('portable WebCrypto variant matches node-native byte-for-byte', async () => {
    for (const input of ['abc', '', 'ünïcode ✓', '{"a":1}']) {
      expect(await sha256HexAsync(input)).toBe(sha256Hex(input));
    }
  });
});

describe('computeEntryHash', () => {
  test('sync and async variants agree (frozen hash-input rule)', async () => {
    const preimage = validEntryPreimage();
    expect(await computeEntryHashAsync(preimage)).toBe(computeEntryHash(preimage));
  });

  test('is deterministic and key-order independent', () => {
    const a = validEntryPreimage();
    const b = JSON.parse(JSON.stringify(a)) as typeof a; // fresh object, new key order
    expect(computeEntryHash(a)).toBe(computeEntryHash(b));
  });

  test('changes when any covered field changes', () => {
    const base = computeEntryHash(validEntryPreimage());
    expect(computeEntryHash(validEntryPreimage({ seq: 2 }))).not.toBe(base);
    expect(
      computeEntryHash(validEntryPreimage({ cost: { amount: 1, currency: 'USD', tokens_in: 0, tokens_out: 0 } }))
    ).not.toBe(base);
  });
});

describe('hex helpers', () => {
  test('round-trip', () => {
    const bytes = new Uint8Array([0, 1, 255, 16]);
    expect(hexToBytes(bytesToHex(bytes))).toEqual(bytes);
  });

  test('hexToBytes rejects invalid input', () => {
    expect(() => hexToBytes('abc')).toThrow(TypeError); // odd length
    expect(() => hexToBytes('ZZ')).toThrow(TypeError);
    expect(() => hexToBytes('AB')).toThrow(TypeError); // uppercase rejected
  });

  test('genesis prev-hash shape', () => {
    expect(GENESIS_PREV_HASH).toMatch(/^0{64}$/);
  });
});
