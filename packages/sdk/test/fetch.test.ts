import { webcrypto } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import {
  InMemoryNonceStore,
  didKeyFromPublicKey,
  verifyMandareRequest,
} from '@mandarelabs/passport';

import { createMandareFetch } from '../src/fetch.js';
import { MandareGateway, MandareRefusedError } from '../src/client.js';

interface Captured {
  input: string | URL | Request;
  init: RequestInit | undefined;
}

function captureFetch(response: () => Response): { calls: Captured[]; fetch: typeof fetch } {
  const calls: Captured[] = [];
  const impl = (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    calls.push({ input, init });
    return Promise.resolve(response());
  };
  return { calls, fetch: impl as typeof fetch };
}

function capturedHeaders(captured: Captured): Headers {
  return new Headers(captured.init?.headers);
}

async function generateAgent(): Promise<{
  privateJwk: webcrypto.JsonWebKey;
  publicJwk: webcrypto.JsonWebKey;
  did: string;
}> {
  const pair = (await webcrypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])) as webcrypto.CryptoKeyPair;
  const privateJwk = await webcrypto.subtle.exportKey('jwk', pair.privateKey);
  const publicJwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
  const raw = Uint8Array.from(Buffer.from(publicJwk.x as string, 'base64url'));
  return { privateJwk, publicJwk, did: didKeyFromPublicKey(raw) };
}

describe('createMandareFetch — none mode', () => {
  it('passes requests through untouched', async () => {
    const { calls, fetch: stub } = captureFetch(() => new Response('{}'));
    const wrapped = createMandareFetch({ auth: { mode: 'none' }, fetch: stub });
    await wrapped('http://127.0.0.1:1/x', { method: 'POST', body: '{}' });
    expect(calls).toHaveLength(1);
    expect(new Headers(calls[0]?.init?.headers).has('x-mandare-token')).toBe(false);
  });
});

describe('createMandareFetch — token mode', () => {
  it('attaches the four PoP headers for the request path', async () => {
    const { calls, fetch: stub } = captureFetch(() => new Response('{}'));
    const wrapped = createMandareFetch({
      auth: { mode: 'token', credentials: { tokenId: 'tok_9', popSecret: 'k' } },
      fetch: stub,
    });
    await wrapped('http://127.0.0.1:8484/v1/messages?ignored=1', {
      method: 'POST',
      body: JSON.stringify({ model: 'm' }),
      headers: { 'content-type': 'application/json' },
    });
    const headers = capturedHeaders(calls[0] as Captured);
    expect(headers.get('x-mandare-token')).toBe('tok_9');
    expect(headers.get('x-mandare-pop')).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(headers.get('x-mandare-nonce')).not.toBeNull();
    expect(headers.get('x-mandare-timestamp')).toMatch(/Z$/);
    expect(headers.get('content-type')).toBe('application/json');
  });
});

describe('createMandareFetch — passport mode', () => {
  it('produces headers the door-side verifier accepts over the exact body', async () => {
    const agent = await generateAgent();
    const body = JSON.stringify({ model: 'claude-haiku-4-5', max_tokens: 8 });
    const { calls, fetch: stub } = captureFetch(() => new Response('{}'));
    const wrapped = createMandareFetch({
      auth: {
        mode: 'passport',
        identity: {
          credential: 'compact.sdjwt.credential~',
          agentDid: agent.did,
          privateJwk: agent.privateJwk,
          publicJwk: agent.publicJwk,
        },
      },
      fetch: stub,
    });
    const url = 'http://127.0.0.1:8484/v1/messages';
    await wrapped(url, { method: 'POST', body, headers: { 'content-type': 'application/json' } });

    const sent = capturedHeaders(calls[0] as Captured);
    const headerMap: Record<string, string> = {};
    sent.forEach((value, name) => {
      headerMap[name.toLowerCase()] = value;
    });
    expect(headerMap['x-mandare-passport']).toBe('compact.sdjwt.credential~');

    // The proof: the passport package's own verifier accepts what we sent.
    const verified = await verifyMandareRequest({
      method: 'POST',
      url,
      headers: headerMap,
      bodyBytes: new TextEncoder().encode(body),
      agentPublicJwk: agent.publicJwk,
      agentDid: agent.did,
      nonceStore: new InMemoryNonceStore(),
    });
    expect(typeof verified.nonce).toBe('string');
  });

  it('refuses a body it cannot sign exactly (stream) instead of sending', async () => {
    const agent = await generateAgent();
    const { calls, fetch: stub } = captureFetch(() => new Response('{}'));
    const wrapped = createMandareFetch({
      auth: {
        mode: 'passport',
        identity: {
          credential: 'c~',
          agentDid: agent.did,
          privateJwk: agent.privateJwk,
          publicJwk: agent.publicJwk,
        },
      },
      fetch: stub,
    });
    const stream = new ReadableStream({ start: (c) => c.close() });
    await expect(
      wrapped('http://127.0.0.1:8484/v1/messages', { method: 'POST', body: stream, duplex: 'half' } as RequestInit)
    ).rejects.toThrow(/cannot sign this body type exactly/);
    expect(calls).toHaveLength(0);
  });
});

describe('MandareGateway', () => {
  it('throws MandareRefusedError with the door refusal body', async () => {
    const refusal = { code: 'PER_DAY_EXCEEDED', reasons: ['cap'], denied_entry: 'a'.repeat(64) };
    const { fetch: stub } = captureFetch(
      () => new Response(JSON.stringify(refusal), { status: 403, headers: { 'content-type': 'application/json' } })
    );
    const gateway = new MandareGateway({ baseUrl: 'http://127.0.0.1:8484/', fetch: stub });
    const error = await gateway.messages({ model: 'm' }).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(MandareRefusedError);
    expect((error as MandareRefusedError).refusal.code).toBe('PER_DAY_EXCEEDED');
    expect((error as MandareRefusedError).refusal.denied_entry).toBe('a'.repeat(64));
  });
});
