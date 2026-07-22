import { afterEach, describe, expect, test } from 'vitest';

import {
  AGENT_REVOKE,
  AGENT_REINSTATE,
  agentSubject,
  doorSubject,
  revocationProjector,
} from '@mandarelabs/ledger';
import type { RequestClaims, VerifyResult } from '@mandarelabs/vault';

import type { GatewayVault } from '../src/auth.js';
import { anthropicBody, chatBody, openrouterOkFetch, openTestGateway, type TestGateway } from './helpers.js';

/** A GatewayVault stub returning a fixed verdict, recording the claims it saw. */
function stubVault(verdict: VerifyResult): GatewayVault & { seen: RequestClaims[] } {
  const seen: RequestClaims[] = [];
  return {
    seen,
    verifyRequest(claims) {
      seen.push(claims);
      return verdict;
    },
  };
}

function revokeEntry(target: string, type: string = AGENT_REVOKE) {
  return {
    actor: 'did:mandare:owner',
    mandate_id: 'mnd_kill',
    action: { type, target, request_hash: 'e'.repeat(64) },
    cost: { amount: 0, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
  };
}

describe('Host allowlist (DNS-rebinding defense)', () => {
  let tg: TestGateway;
  afterEach(() => tg.close());

  test('a foreign Host header is rejected before any route runs', async () => {
    tg = await openTestGateway({ fetchImpl: openrouterOkFetch() });
    const res = await tg.app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { host: 'evil.attacker.example' },
      payload: chatBody,
    });
    expect(res.statusCode).toBe(403);
    expect(res.json().error).toContain('host not allowed');
  });

  test('the publicBaseUrl host is auto-allowed (webhooks behind a real hostname)', async () => {
    tg = await openTestGateway({
      fetchImpl: openrouterOkFetch(),
      config: { publicBaseUrl: 'https://door.example.com' },
    });
    const allowed = await tg.app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { host: 'door.example.com' },
      payload: chatBody,
    });
    expect(allowed.statusCode).not.toBe(403);
    const foreign = await tg.app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { host: 'other.example.com' },
      payload: chatBody,
    });
    expect(foreign.statusCode).toBe(403);
  });

  test('localhost and 127.0.0.1 are always allowed', async () => {
    tg = await openTestGateway({ fetchImpl: openrouterOkFetch() });
    for (const host of ['localhost', '127.0.0.1:8484']) {
      const res = await tg.app.inject({
        method: 'POST',
        url: '/v1/chat/completions',
        headers: { host },
        payload: chatBody,
      });
      expect(res.statusCode).toBe(200);
    }
  });
});

describe('door-local token auth', () => {
  let tg: TestGateway;
  afterEach(() => tg.close());

  test("authMode 'token' with no vault fails closed (503)", async () => {
    tg = await openTestGateway({ config: { authMode: 'token' }, fetchImpl: openrouterOkFetch() });
    const res = await tg.app.inject({ method: 'POST', url: '/v1/chat/completions', payload: chatBody });
    expect(res.statusCode).toBe(503);
  });

  test('missing token headers → 401 when a token is required', async () => {
    const vault = stubVault({ ok: true, verified: { actor: 'x', mandateId: 'y', tokenId: 't' } });
    tg = await openTestGateway({ config: { authMode: 'token' }, vault, fetchImpl: openrouterOkFetch() });
    const res = await tg.app.inject({ method: 'POST', url: '/v1/chat/completions', payload: chatBody });
    expect(res.statusCode).toBe(401);
  });

  test('a vault-refused token → 401 with the refusal code', async () => {
    const vault = stubVault({ ok: false, refusal: { code: 'BAD_POP', reason: 'nope' } });
    tg = await openTestGateway({ config: { authMode: 'token' }, vault, fetchImpl: openrouterOkFetch() });
    const res = await tg.app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: {
        'x-mandare-token': 'tok',
        'x-mandare-timestamp': '2026-07-22T12:00:00Z',
        'x-mandare-nonce': 'n',
        'x-mandare-pop': 'p',
      },
      payload: chatBody,
    });
    expect(res.statusCode).toBe(401);
    expect(res.json().code).toBe('BAD_POP');
  });

  test('a token scoped to a DIFFERENT actor/mandate → 403', async () => {
    const vault = stubVault({
      ok: true,
      verified: { actor: 'did:someone:else', mandateId: 'mnd_other', tokenId: 't' },
    });
    tg = await openTestGateway({ config: { authMode: 'token' }, vault, fetchImpl: openrouterOkFetch() });
    const res = await tg.app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: {
        'x-mandare-token': 'tok',
        'x-mandare-timestamp': '2026-07-22T12:00:00Z',
        'x-mandare-nonce': 'n',
        'x-mandare-pop': 'p',
      },
      payload: chatBody,
    });
    expect(res.statusCode).toBe(403);
  });

  test('a valid token scoped to this door passes through to 200', async () => {
    const vault = stubVault({
      ok: true,
      verified: { actor: 'did:example:agent', mandateId: 'mnd_gateway_test', tokenId: 't' },
    });
    tg = await openTestGateway({ config: { authMode: 'token' }, vault, fetchImpl: openrouterOkFetch() });
    const res = await tg.app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: {
        'x-mandare-token': 'tok',
        'x-mandare-timestamp': '2026-07-22T12:00:00Z',
        'x-mandare-nonce': 'n',
        'x-mandare-pop': 'p',
      },
      payload: chatBody,
    });
    expect(res.statusCode).toBe(200);
  });

  test("authMode 'none' skips token auth even with a vault present", async () => {
    const vault = stubVault({ ok: false, refusal: { code: 'BAD_POP', reason: 'would refuse' } });
    tg = await openTestGateway({ config: { authMode: 'none' }, vault, fetchImpl: openrouterOkFetch() });
    const res = await tg.app.inject({ method: 'POST', url: '/v1/chat/completions', payload: chatBody });
    expect(res.statusCode).toBe(200);
    expect(vault.seen.length).toBe(0);
  });
});

describe('kill switch (revocation) enforcement', () => {
  let tg: TestGateway;
  afterEach(() => tg.close());

  test('a killed agent fails closed on its next call, and the refusal is a ledger entry', async () => {
    tg = await openTestGateway({ fetchImpl: openrouterOkFetch() });
    // Before the kill: the call succeeds.
    const before = await tg.app.inject({ method: 'POST', url: '/v1/messages', payload: anthropicBody });
    expect(before.statusCode).toBe(200);

    // Kill the agent (a separate door writes the revoke entry).
    await tg.ledger.appendProjected(revokeEntry(agentSubject(tg.config.actor)), revocationProjector());

    const after = await tg.app.inject({ method: 'POST', url: '/v1/messages', payload: anthropicBody });
    expect(after.statusCode).toBe(403);
    expect(after.json().code).toBe('AGENT_REVOKED');
    expect(after.json().denied_entry).toMatch(/^[0-9a-f]{64}$/);
  });

  test('reinstating the agent restores access', async () => {
    tg = await openTestGateway({ fetchImpl: openrouterOkFetch() });
    await tg.ledger.appendProjected(revokeEntry(agentSubject(tg.config.actor)), revocationProjector());
    const killed = await tg.app.inject({ method: 'POST', url: '/v1/messages', payload: anthropicBody });
    expect(killed.statusCode).toBe(403);

    await tg.ledger.appendProjected(
      revokeEntry(agentSubject(tg.config.actor), AGENT_REINSTATE),
      revocationProjector()
    );
    const restored = await tg.app.inject({ method: 'POST', url: '/v1/messages', payload: anthropicBody });
    expect(restored.statusCode).toBe(200);
  });

  test('killing the DOOR (kill --all) stops every call with DOOR_REVOKED', async () => {
    tg = await openTestGateway({ fetchImpl: openrouterOkFetch() });
    await tg.ledger.appendProjected(revokeEntry(doorSubject(tg.config.doorId)), revocationProjector());
    const res = await tg.app.inject({ method: 'POST', url: '/v1/messages', payload: anthropicBody });
    expect(res.statusCode).toBe(403);
    expect(res.json().code).toBe('DOOR_REVOKED');
  });
});
