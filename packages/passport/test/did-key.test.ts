import { describe, expect, it } from 'vitest';

import {
  base58Decode,
  base58Encode,
  didKeyFromPublicKey,
  generateEd25519KeyPair,
  didFromPublicJwk,
  publicKeyFromDidKey,
  rawPublicKeyFromJwk,
} from '../src/index.js';

describe('base58btc', () => {
  it('round-trips arbitrary bytes including leading zeros', () => {
    const cases = [
      Uint8Array.from([]),
      Uint8Array.from([0]),
      Uint8Array.from([0, 0, 1]),
      Uint8Array.from([255]),
      Uint8Array.from(Array.from({ length: 34 }, (_, i) => (i * 7) % 256)),
    ];
    for (const bytes of cases) {
      expect(base58Decode(base58Encode(bytes))).toEqual(bytes);
    }
  });

  it('encodes the Bitcoin-alphabet test vector', () => {
    // "Hello World!" — the canonical base58btc vector (draft-msporny-base58).
    const bytes = new TextEncoder().encode('Hello World!');
    expect(base58Encode(bytes)).toBe('2NEpo7TZRRrLZSi2U');
    expect(new TextDecoder().decode(base58Decode('2NEpo7TZRRrLZSi2U'))).toBe('Hello World!');
  });

  it('rejects characters outside the alphabet', () => {
    expect(() => base58Decode('0OIl')).toThrow(/invalid character/);
  });
});

describe('did:key (Ed25519 v1 profile)', () => {
  it('published did:key strings decode and re-encode to themselves', () => {
    // From the W3C did:key test suite (Ed25519).
    const published = 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp';
    const raw = publicKeyFromDidKey(published);
    expect(raw.length).toBe(32);
    expect(didKeyFromPublicKey(raw)).toBe(published);
  });

  it('round-trips generated keys and always yields the z6Mk prefix', async () => {
    const pair = await generateEd25519KeyPair();
    const did = didFromPublicJwk(pair.publicJwk);
    expect(did.startsWith('did:key:z6Mk')).toBe(true);
    expect(publicKeyFromDidKey(did)).toEqual(rawPublicKeyFromJwk(pair.publicJwk));
  });

  it('rejects non-did:key, non-base58btc, and non-Ed25519 inputs', () => {
    expect(() => publicKeyFromDidKey('did:web:example.com')).toThrow(/not a did:key/);
    expect(() => publicKeyFromDidKey('did:key:uABC')).toThrow(/base58btc/);
    // secp256k1 multicodec (0xe7 0x01) — same shape, wrong curve.
    const secpPrefixed = Uint8Array.from([0xe7, 0x01, ...new Uint8Array(33)]);
    const forged = `did:key:z${base58Encode(secpPrefixed)}`;
    expect(() => publicKeyFromDidKey(forged)).toThrow(/Ed25519/);
  });

  it('rejects keys of the wrong length', () => {
    expect(() => didKeyFromPublicKey(new Uint8Array(31))).toThrow(/32 bytes/);
  });
});
