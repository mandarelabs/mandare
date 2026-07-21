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

import {
  DirectoryParseError,
  directoryFromPublicKeys,
  parseKeyDirectory,
  verifyChain,
  type KeyDirectory,
} from '../src/index.js';

/**
 * Key-directory verification: multi-door chains, key rotation windows, and
 * hostile directory input. Chains are built from scratch (independent of the
 * ledger implementation), signed by whichever door key each test dictates.
 */

interface TestDoor {
  privateKey: webcrypto.CryptoKey;
  publicKey: Uint8Array;
  publicKeyHex: string;
  publicKeyB64Url: string;
  keyId: string;
}

let doorA: TestDoor;
let doorB: TestDoor;

async function makeDoor(): Promise<TestDoor> {
  const pair = (await globalThis.crypto.subtle.generateKey('Ed25519', true, [
    'sign',
    'verify',
  ])) as webcrypto.CryptoKeyPair;
  const raw = new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', pair.publicKey));
  return {
    privateKey: pair.privateKey,
    publicKey: raw,
    publicKeyHex: bytesToHex(raw),
    publicKeyB64Url: bytesToBase64Url(raw),
    keyId: await sha256HexAsync(raw),
  };
}

beforeAll(async () => {
  [doorA, doorB] = await Promise.all([makeDoor(), makeDoor()]);
});

async function makeEntry(
  seq: number,
  prevHash: string,
  door: TestDoor,
  options: { ts?: string; doorId?: string } = {}
): Promise<LedgerEntryV1> {
  const preimage: LedgerEntryPreimage = {
    schema_version: 1,
    seq,
    ts: options.ts ?? '2026-07-21T12:00:00.000Z',
    door_id: options.doorId ?? 'gateway:test',
    actor: 'did:example:agent',
    mandate_id: 'mnd_test',
    action: { type: LLM_CALL_INTENT, target: 'openrouter.ai', request_hash: 'b'.repeat(64) },
    cost: { amount: 1500, currency: 'USD', tokens_in: 10, tokens_out: 20 },
    salt: seq.toString(16).padStart(32, '0'),
    prev_hash: prevHash,
  };
  const entryHash = await computeEntryHashAsync(preimage);
  const signature = await globalThis.crypto.subtle.sign(
    'Ed25519',
    door.privateKey,
    hexToBytes(entryHash) as Uint8Array<ArrayBuffer>
  );
  return {
    ...preimage,
    entry_hash: entryHash,
    door_signature: {
      alg: 'EdDSA',
      key_id: door.keyId,
      key_provenance: 'software',
      value: bytesToBase64Url(new Uint8Array(signature)),
    },
  };
}

/** Chain where each entry names its signing door and timestamp. */
async function makeChain(
  spec: { door: () => TestDoor; ts?: string; doorId?: string }[]
): Promise<LedgerEntryV1[]> {
  const entries: LedgerEntryV1[] = [];
  let prevHash = GENESIS_PREV_HASH;
  for (const [i, step] of spec.entries()) {
    const entry = await makeEntry(i + 1, prevHash, step.door(), {
      ...(step.ts === undefined ? {} : { ts: step.ts }),
      ...(step.doorId === undefined ? {} : { doorId: step.doorId }),
    });
    entries.push(entry);
    prevHash = entry.entry_hash;
  }
  return entries;
}

describe('parseKeyDirectory — boundary validation (R4)', () => {
  test('parses a JWKS with Ed25519 keys and skips foreign key types', async () => {
    const directory = await parseKeyDirectory({
      keys: [
        { kty: 'RSA', n: 'xxx', e: 'AQAB' },
        {
          kty: 'OKP',
          crv: 'Ed25519',
          x: doorA.publicKeyB64Url,
          kid: 'door-a',
          use: 'sig',
          alg: 'EdDSA',
          'mnd:role': 'door',
        },
      ],
    });
    expect(directory.keys).toHaveLength(1);
    expect(directory.keys[0]).toMatchObject({
      keyId: doorA.keyId,
      kid: 'door-a',
      role: 'door',
    });
  });

  test('parses nbf/exp validity windows', async () => {
    const directory = await parseKeyDirectory({
      keys: [{ kty: 'OKP', crv: 'Ed25519', x: doorA.publicKeyB64Url, nbf: 100, exp: 200 }],
    });
    expect(directory.keys[0]).toMatchObject({ notBefore: 100, notAfter: 200 });
  });

  test.each([
    ['not an object', 42],
    ['missing keys array', {}],
    ['keys not an array', { keys: 'nope' }],
    ['key entry not an object', { keys: [null] }],
    ['Ed25519 key missing x', { keys: [{ kty: 'OKP', crv: 'Ed25519' }] }],
    ['x not base64url', { keys: [{ kty: 'OKP', crv: 'Ed25519', x: '!!!' }] }],
    ['x wrong length', { keys: [{ kty: 'OKP', crv: 'Ed25519', x: 'AAAA' }] }],
    ['exp before nbf', { keys: [{ kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43), nbf: 200, exp: 100 }] }],
    ['no Ed25519 keys at all', { keys: [{ kty: 'RSA', n: 'x', e: 'AQAB' }] }],
  ])('rejects hostile input: %s', async (_label, raw) => {
    await expect(parseKeyDirectory(raw)).rejects.toThrow(DirectoryParseError);
  });
});

describe('verifyChain with a key directory — multi-door', () => {
  test('chain signed by two doors verifies when both keys are in the directory', async () => {
    const chain = await makeChain([
      { door: () => doorA, doorId: 'gateway:main' },
      { door: () => doorA, doorId: 'gateway:main' },
      { door: () => doorB, doorId: 'vault:main' },
      { door: () => doorA, doorId: 'gateway:main' },
    ]);
    const directory = await directoryFromPublicKeys([doorA.publicKey, doorB.publicKey]);
    const result = await verifyChain(chain, { keyDirectory: directory });
    expect(result).toEqual({ ok: true, entries: 4, headHash: chain[3]?.entry_hash });
  });

  test('entry signed by a key outside the directory fails KEY_UNKNOWN', async () => {
    const chain = await makeChain([{ door: () => doorA }, { door: () => doorB }]);
    const directory = await directoryFromPublicKeys([doorA.publicKey]);
    const result = await verifyChain(chain, { keyDirectory: directory });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.code).toBe('KEY_UNKNOWN');
      expect(result.failure.seq).toBe(2);
    }
  });

  test('single-key mode still enforces exactly-one-key (KEY_MISMATCH)', async () => {
    const chain = await makeChain([{ door: () => doorA }, { door: () => doorB }]);
    const result = await verifyChain(chain, { doorPublicKey: doorA.publicKeyHex });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.code).toBe('KEY_MISMATCH');
  });
});

describe('verifyChain with a key directory — rotation windows', () => {
  const T1 = '2026-01-10T00:00:00.000Z';
  const T2 = '2026-06-10T00:00:00.000Z';
  const ROTATION = Date.parse('2026-03-01T00:00:00.000Z') / 1000;

  async function rotationDirectory(): Promise<KeyDirectory> {
    return parseKeyDirectory({
      keys: [
        // Door key A: rotated out on 2026-03-01.
        { kty: 'OKP', crv: 'Ed25519', x: doorA.publicKeyB64Url, exp: ROTATION, 'mnd:role': 'door' },
        // Door key B: valid from 2026-03-01.
        { kty: 'OKP', crv: 'Ed25519', x: doorB.publicKeyB64Url, nbf: ROTATION, 'mnd:role': 'door' },
      ],
    });
  }

  test('happy rotation: old key signs old entries, new key signs new entries', async () => {
    const chain = await makeChain([
      { door: () => doorA, ts: T1 },
      { door: () => doorA, ts: T1 },
      { door: () => doorB, ts: T2 },
    ]);
    const result = await verifyChain(chain, { keyDirectory: await rotationDirectory() });
    expect(result.ok).toBe(true);
  });

  test('RED-TEAM: stolen rotated-out key cannot sign new history (KEY_EXPIRED)', async () => {
    // Attacker holds door key A after rotation and forges a post-rotation entry.
    const chain = await makeChain([
      { door: () => doorA, ts: T1 },
      { door: () => doorA, ts: T2 }, // signed by A but timestamped after A's exp
    ]);
    const result = await verifyChain(chain, { keyDirectory: await rotationDirectory() });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.code).toBe('KEY_EXPIRED');
      expect(result.failure.seq).toBe(2);
    }
  });

  test('entry timestamped before a key becomes valid fails KEY_EXPIRED (nbf)', async () => {
    const chain = await makeChain([{ door: () => doorB, ts: T1 }]);
    const result = await verifyChain(chain, { keyDirectory: await rotationDirectory() });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.code).toBe('KEY_EXPIRED');
  });
});

describe('option validation', () => {
  test('requires exactly one of doorPublicKey / keyDirectory', async () => {
    const directory = await directoryFromPublicKeys([doorA.publicKey]);
    await expect(verifyChain([], {})).rejects.toThrow(/exactly one/);
    await expect(
      verifyChain([], { doorPublicKey: doorA.publicKeyHex, keyDirectory: directory })
    ).rejects.toThrow(/exactly one/);
  });
});
