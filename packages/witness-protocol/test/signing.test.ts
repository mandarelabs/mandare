import { describe, expect, test } from 'vitest';

import { signPayload, verifySignedPayload } from '../src/signing.js';
import { makeSigner } from './helpers.js';

describe('protocol message signing', () => {
  test('sign → verify round trip', async () => {
    const signer = makeSigner();
    const message = await signPayload({ hello: 'world', n: 42 }, signer);
    expect(await verifySignedPayload(message, signer.publicKeyHex)).toBe(true);
  });

  test('canonicalization: key order does not change the signature validity', async () => {
    const signer = makeSigner();
    const message = await signPayload({ b: 2, a: 1 }, signer);
    const reordered = { payload: { a: 1, b: 2 }, signature: message.signature };
    expect(await verifySignedPayload(reordered, signer.publicKeyHex)).toBe(true);
  });

  test('tampered payload fails', async () => {
    const signer = makeSigner();
    const message = await signPayload({ amount: 1 }, signer);
    const tampered = { payload: { amount: 2 }, signature: message.signature };
    expect(await verifySignedPayload(tampered, signer.publicKeyHex)).toBe(false);
  });

  test('wrong key fails', async () => {
    const signer = makeSigner();
    const other = makeSigner();
    const message = await signPayload({ amount: 1 }, signer);
    expect(await verifySignedPayload(message, other.publicKeyHex)).toBe(false);
  });

  test('malformed signature/key refuse without throwing (R4)', async () => {
    const signer = makeSigner();
    const message = await signPayload({ amount: 1 }, signer);
    expect(await verifySignedPayload({ ...message, signature: '!!!' }, signer.publicKeyHex)).toBe(false);
    expect(await verifySignedPayload(message, 'zz')).toBe(false);
    expect(await verifySignedPayload(message, '')).toBe(false);
  });
});
