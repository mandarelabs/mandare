import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { popPreimage, popProof, tokenAuthHeaders } from '../src/pop.js';

const CLAIMS = {
  tokenId: 'tok_abc123',
  method: 'post',
  path: '/v1/messages',
  timestamp: '2026-08-09T12:00:00.000Z',
  nonce: 'nonce-1',
};

describe('popPreimage', () => {
  it('is the canonical newline-joined preimage with an uppercased method', () => {
    expect(popPreimage(CLAIMS)).toBe(
      'tok_abc123\nPOST\n/v1/messages\n2026-08-09T12:00:00.000Z\nnonce-1'
    );
  });
});

describe('popProof', () => {
  it('matches node:crypto HMAC-SHA256 base64url exactly (the vault encoding)', async () => {
    const secret = 'per-token-secret-k';
    const expected = createHmac('sha256', secret)
      .update(popPreimage(CLAIMS), 'utf8')
      .digest('base64url');
    expect(await popProof(secret, CLAIMS)).toBe(expected);
  });

  it('matches the cross-language pinned vector (same one packages/sdk-py pins)', async () => {
    // Produced by the reference implementation; if either language drifts
    // from the vault encoding, its copy of this vector fails.
    expect(await popProof('s3cret', CLAIMS)).toBe('K6jPOJk3fZ43vUqSNvIGnrX0Jn-erMclkvHf8YhvZgE');
  });
});

describe('tokenAuthHeaders', () => {
  it('emits the four door headers with a verifiable proof', async () => {
    const headers = await tokenAuthHeaders({
      credentials: { tokenId: 'tok_1', popSecret: 's3cret' },
      method: 'POST',
      path: '/v1/messages',
      timestamp: CLAIMS.timestamp,
      nonce: 'n-1',
    });
    expect(headers['x-mandare-token']).toBe('tok_1');
    expect(headers['x-mandare-timestamp']).toBe(CLAIMS.timestamp);
    expect(headers['x-mandare-nonce']).toBe('n-1');
    const expected = createHmac('sha256', 's3cret')
      .update('tok_1\nPOST\n/v1/messages\n2026-08-09T12:00:00.000Z\nn-1', 'utf8')
      .digest('base64url');
    expect(headers['x-mandare-pop']).toBe(expected);
  });

  it('strips the query string from the signed path (door parity)', async () => {
    const headers = await tokenAuthHeaders({
      credentials: { tokenId: 'tok_1', popSecret: 's' },
      method: 'GET',
      path: '/healthz?probe=1',
      timestamp: CLAIMS.timestamp,
      nonce: 'n',
    });
    const expected = createHmac('sha256', 's')
      .update('tok_1\nGET\n/healthz\n2026-08-09T12:00:00.000Z\nn', 'utf8')
      .digest('base64url');
    expect(headers['x-mandare-pop']).toBe(expected);
  });

  it('generates a fresh nonce per call when none is injected', async () => {
    const credentials = { tokenId: 't', popSecret: 's' };
    const a = await tokenAuthHeaders({ credentials, method: 'POST', path: '/p' });
    const b = await tokenAuthHeaders({ credentials, method: 'POST', path: '/p' });
    expect(a['x-mandare-nonce']).not.toBe(b['x-mandare-nonce']);
  });
});
