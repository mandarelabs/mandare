import { describe, expect, it } from 'vitest';

import { signStripePayload, verifyStripeSignature } from '../src/webhook-signature.js';

const SECRET = 'whsec_unit_test';
const NOW_MS = 1_760_000_000_000;

function sign(payload: string, secret = SECRET, timestampSeconds = NOW_MS / 1000): string {
  return signStripePayload({ payload, secret, timestampSeconds });
}

describe('verifyStripeSignature', () => {
  const payload = Buffer.from('{"type":"issuing_authorization.request"}', 'utf8');

  it('accepts a correctly signed payload', () => {
    const verdict = verifyStripeSignature({
      payload,
      header: sign(payload.toString('utf8')),
      secret: SECRET,
      nowMs: NOW_MS,
    });
    expect(verdict).toEqual({ ok: true, timestamp: NOW_MS / 1000 });
  });

  it('accepts a rotation header with multiple v1 candidates', () => {
    const good = sign(payload.toString('utf8'));
    const [t, v1] = good.split(',');
    const header = `${t},v1=${'0'.repeat(64)},${v1},v0=${'1'.repeat(64)}`;
    expect(
      verifyStripeSignature({ payload, header, secret: SECRET, nowMs: NOW_MS }).ok
    ).toBe(true);
  });

  it('rejects a missing header', () => {
    const verdict = verifyStripeSignature({ payload, header: undefined, secret: SECRET, nowMs: NOW_MS });
    expect(verdict).toEqual({ ok: false, failure: 'HEADER_MISSING' });
  });

  it('rejects a tampered payload', () => {
    const verdict = verifyStripeSignature({
      payload: Buffer.from('{"type":"issuing_authorization.request","amount":1}', 'utf8'),
      header: sign(payload.toString('utf8')),
      secret: SECRET,
      nowMs: NOW_MS,
    });
    expect(verdict).toEqual({ ok: false, failure: 'SIGNATURE_MISMATCH' });
  });

  it('rejects a signature under the wrong secret', () => {
    const verdict = verifyStripeSignature({
      payload,
      header: sign(payload.toString('utf8'), 'whsec_attacker'),
      secret: SECRET,
      nowMs: NOW_MS,
    });
    expect(verdict).toEqual({ ok: false, failure: 'SIGNATURE_MISMATCH' });
  });

  it('rejects a VALID signature whose timestamp is outside tolerance (replay bound)', () => {
    const staleSeconds = NOW_MS / 1000 - 301;
    const verdict = verifyStripeSignature({
      payload,
      header: sign(payload.toString('utf8'), SECRET, staleSeconds),
      secret: SECRET,
      toleranceSeconds: 300,
      nowMs: NOW_MS,
    });
    expect(verdict).toEqual({ ok: false, failure: 'TIMESTAMP_OUT_OF_TOLERANCE' });
  });

  it('rejects malformed headers (no t, no v1, duplicate t, garbage)', () => {
    for (const header of [
      'v1=abc',
      `t=${NOW_MS / 1000}`,
      `t=1,t=2,v1=${'a'.repeat(64)}`,
      't=notanumber,v1=' + 'a'.repeat(64),
      'complete garbage',
      `t=${NOW_MS / 1000},v1=zz`,
    ]) {
      const verdict = verifyStripeSignature({ payload, header, secret: SECRET, nowMs: NOW_MS });
      expect(verdict.ok, header).toBe(false);
    }
  });

  it('binds the signature to the exact bytes (whitespace change breaks it)', () => {
    const verdict = verifyStripeSignature({
      payload: Buffer.from('{"type": "issuing_authorization.request"}', 'utf8'),
      header: sign(payload.toString('utf8')),
      secret: SECRET,
      nowMs: NOW_MS,
    });
    expect(verdict.ok).toBe(false);
  });
});
