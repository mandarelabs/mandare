import { describe, expect, it } from 'vitest';

import {
  InMemoryNonceStore,
  RequestSignatureError,
  generateEd25519KeyPair,
  didFromPublicJwk,
  signMandareRequest,
  verifyMandareRequest,
  type Ed25519KeyPairJwk,
} from '../src/index.js';

const URL_UNDER_TEST = 'http://127.0.0.1:8484/v1/messages';
const BODY = new TextEncoder().encode(JSON.stringify({ model: 'claude-haiku-4-5', max_tokens: 64 }));

interface Rig {
  agent: Ed25519KeyPairJwk;
  agentDid: string;
  headers: Record<string, string>;
  nonceStore: InMemoryNonceStore;
}

async function makeSignedRequest(overrides: { bodyBytes?: Uint8Array } = {}): Promise<Rig> {
  const agent = await generateEd25519KeyPair();
  const agentDid = didFromPublicJwk(agent.publicJwk);
  const headers = await signMandareRequest({
    method: 'POST',
    url: URL_UNDER_TEST,
    bodyBytes: overrides.bodyBytes ?? BODY,
    agentDid,
    agentPrivateJwk: agent.privateJwk,
    agentPublicJwk: agent.publicJwk,
    passport: 'passport-compact-goes-here',
  });
  return { agent, agentDid, headers, nonceStore: new InMemoryNonceStore() };
}

function verifyArgs(rig: Rig, overrides: Partial<Parameters<typeof verifyMandareRequest>[0]> = {}) {
  return {
    method: 'POST',
    url: URL_UNDER_TEST,
    headers: rig.headers,
    bodyBytes: BODY,
    agentPublicJwk: rig.agent.publicJwk,
    agentDid: rig.agentDid,
    nonceStore: rig.nonceStore,
    ...overrides,
  };
}

async function expectRefusal(promise: Promise<unknown>, code: string): Promise<void> {
  const error = await promise.then(
    () => null,
    (e: unknown) => e
  );
  expect(error).toBeInstanceOf(RequestSignatureError);
  expect((error as RequestSignatureError).code).toBe(code);
}

describe('RFC 9421 request signatures (web-bot-auth profile)', () => {
  it('signs and verifies a request end to end', async () => {
    const rig = await makeSignedRequest();
    const { nonce } = await verifyMandareRequest(verifyArgs(rig));
    expect(nonce.length).toBeGreaterThan(0);
  });

  it('refuses a body swap under a valid signature (Content-Digest, closes S3 HIGH-1)', async () => {
    const rig = await makeSignedRequest();
    const swapped = new TextEncoder().encode(
      JSON.stringify({ model: 'claude-haiku-4-5', max_tokens: 100000 })
    );
    await expectRefusal(
      verifyMandareRequest(verifyArgs(rig, { bodyBytes: swapped })),
      'BODY_DIGEST_MISMATCH'
    );
  });

  it('refuses a replayed request (single-use nonce)', async () => {
    const rig = await makeSignedRequest();
    await verifyMandareRequest(verifyArgs(rig));
    await expectRefusal(verifyMandareRequest(verifyArgs(rig)), 'REPLAYED_NONCE');
  });

  it('refuses a signature from a different key than the passport binds', async () => {
    const rig = await makeSignedRequest();
    const other = await generateEd25519KeyPair();
    await expectRefusal(
      verifyMandareRequest(verifyArgs(rig, { agentPublicJwk: other.publicJwk })),
      'WRONG_KEY'
    );
  });

  it('refuses a signature that does not cover the required components', async () => {
    const rig = await makeSignedRequest();
    const stripped = {
      ...rig.headers,
      'signature-input': rig.headers['signature-input']!.replace(' "content-digest"', ''),
    };
    await expectRefusal(
      verifyMandareRequest(verifyArgs(rig, { headers: stripped })),
      'COMPONENTS_NOT_COVERED'
    );
  });

  it('refuses a decoy-parameter Signature-Input that hides required components as param values', async () => {
    // A hostile signer covers ONLY @method but lists the other required names
    // as INNER-LIST PARAMETERS — a naive quoted-string scan would think they
    // were covered. (Not a valid signature here; the coverage gate must reject
    // it before crypto so a real such signature can never be accepted.)
    const rig = await makeSignedRequest();
    const spoofed = {
      ...rig.headers,
      'signature-input': rig.headers['signature-input']!.replace(
        /\([^)]*\)/,
        '("@method";a="@path";b="@authority";c="content-digest";d="signature-agent")'
      ),
    };
    await expectRefusal(
      verifyMandareRequest(verifyArgs(rig, { headers: spoofed })),
      'COMPONENTS_NOT_COVERED'
    );
  });

  it('refuses a request whose method or path differs from the signed one', async () => {
    const rig = await makeSignedRequest();
    await expectRefusal(
      verifyMandareRequest(verifyArgs(rig, { url: 'http://127.0.0.1:8484/v1/chat/completions' })),
      'BAD_SIGNATURE'
    );
  });

  it('refuses a signature-agent header naming a different agent', async () => {
    const rig = await makeSignedRequest();
    const other = await generateEd25519KeyPair();
    await expectRefusal(
      verifyMandareRequest(
        verifyArgs(rig, {
          agentDid: didFromPublicJwk(other.publicJwk),
          agentPublicJwk: other.publicJwk,
        })
      ),
      'SIGNATURE_AGENT_MISMATCH'
    );
  });

  it('refuses an unsigned request', async () => {
    const rig = await makeSignedRequest();
    const { signature: _drop, 'signature-input': _drop2, ...rest } = rig.headers;
    await expectRefusal(verifyMandareRequest(verifyArgs(rig, { headers: rest })), 'MISSING_SIGNATURE');
  });

  it('refuses an expired signature window', async () => {
    const agent = await generateEd25519KeyPair();
    const agentDid = didFromPublicJwk(agent.publicJwk);
    const headers = await signMandareRequest({
      method: 'POST',
      url: URL_UNDER_TEST,
      bodyBytes: BODY,
      agentDid,
      agentPrivateJwk: agent.privateJwk,
      agentPublicJwk: agent.publicJwk,
      passport: 'p',
      ttlSeconds: 5,
      nowMs: Date.now() - 60_000,
    });
    const rig: Rig = { agent, agentDid, headers, nonceStore: new InMemoryNonceStore() };
    await expectRefusal(verifyMandareRequest(verifyArgs(rig)), 'MALFORMED_SIGNATURE');
  });

  it('refuses a window longer than the ceiling', async () => {
    const agent = await generateEd25519KeyPair();
    const agentDid = didFromPublicJwk(agent.publicJwk);
    const headers = await signMandareRequest({
      method: 'POST',
      url: URL_UNDER_TEST,
      bodyBytes: BODY,
      agentDid,
      agentPrivateJwk: agent.privateJwk,
      agentPublicJwk: agent.publicJwk,
      passport: 'p',
      ttlSeconds: 3600,
    });
    const rig: Rig = { agent, agentDid, headers, nonceStore: new InMemoryNonceStore() };
    await expectRefusal(verifyMandareRequest(verifyArgs(rig)), 'SIGNATURE_WINDOW_INVALID');
  });
});
