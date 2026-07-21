import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, test } from 'vitest';

import { agentSubject, revocationProjector, AGENT_REVOKE } from '@mandarelabs/ledger';
import { Vault, hmacSha256, popPreimage, type ScopedTokenGrant } from '@mandarelabs/vault';

import { chatBody, openrouterOkFetch, openTestGateway, type TestGateway } from '../helpers.js';

/**
 * Red-team (rule R5): a vault-issued token that leaks out of the agent
 * process is dead paper. This drives a REAL vault + real proof-of-possession
 * signing through the gateway — no stubs — so the "stolen token" claim is
 * demonstrated, not asserted. Covers: token theft (id without secret),
 * request replay, cross-actor use, and post-kill access.
 */
describe('red-team: a stolen vault token is dead paper', () => {
  let dir: string;
  let vault: Vault;
  let tg: TestGateway;
  let grant: ScopedTokenGrant;

  const ACTOR = 'did:example:agent';
  const MANDATE = 'mnd_gateway_test';
  const PATH = '/v1/chat/completions';

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'mandare-theft-'));
    vault = Vault.open({
      backend: 'file',
      dbPath: join(dir, 'vault.db'),
      service: 'mandare-vault-test',
      account: 'master-key',
      masterKeyFile: join(dir, 'vault.masterkey'),
    });
    tg = await openTestGateway({
      config: { authMode: 'token' },
      vault,
      fetchImpl: openrouterOkFetch(),
    });
    grant = vault.issueToken({ actor: ACTOR, mandateId: MANDATE });
  });
  afterEach(async () => {
    await tg.close();
    vault.close();
    rmSync(dir, { recursive: true, force: true });
  });

  /** Headers a legitimate holder (who has the pop secret) would send. */
  function signedHeaders(
    over: { secret: string; tokenId: string; nonce: string; timestamp?: string }
  ): Record<string, string> {
    const timestamp = over.timestamp ?? new Date().toISOString();
    const pop = hmacSha256(
      over.secret,
      popPreimage({ tokenId: over.tokenId, method: 'POST', path: PATH, timestamp, nonce: over.nonce })
    );
    return {
      'x-mandare-token': over.tokenId,
      'x-mandare-timestamp': timestamp,
      'x-mandare-nonce': over.nonce,
      'x-mandare-pop': pop,
    };
  }

  function call(headers: Record<string, string>) {
    return tg.app.inject({ method: 'POST', url: PATH, headers, payload: chatBody });
  }

  test('the legitimate holder (with the pop secret) succeeds', async () => {
    const res = await call(
      signedHeaders({ secret: grant.popSecret, tokenId: grant.tokenId, nonce: 'legit-1' })
    );
    expect(res.statusCode).toBe(200);
  });

  test('a thief with the token id but NOT the pop secret is refused (binding)', async () => {
    const res = await call(
      signedHeaders({ secret: 'attacker-guess', tokenId: grant.tokenId, nonce: 'theft-1' })
    );
    expect(res.statusCode).toBe(401);
    expect(res.json().code).toBe('BAD_POP');
  });

  test('a captured valid request cannot be replayed (single-use nonce)', async () => {
    const headers = signedHeaders({ secret: grant.popSecret, tokenId: grant.tokenId, nonce: 'replay-1' });
    expect((await call(headers)).statusCode).toBe(200);
    const replay = await call(headers);
    expect(replay.statusCode).toBe(401);
    expect(replay.json().code).toBe('REPLAYED_NONCE');
  });

  test('a token minted for another actor cannot spend under this door', async () => {
    const other = vault.issueToken({ actor: 'did:example:other-agent', mandateId: MANDATE });
    const res = await call(
      signedHeaders({ secret: other.popSecret, tokenId: other.tokenId, nonce: 'cross-1' })
    );
    // Token verifies (valid pop), but it is scoped to a different actor → 403.
    expect(res.statusCode).toBe(403);
  });

  test('after mandare kill, a still-valid token is refused — the ledger is the authority', async () => {
    // A perfectly valid, correctly-signed request...
    const headers = signedHeaders({ secret: grant.popSecret, tokenId: grant.tokenId, nonce: 'post-kill' });
    // ...but the agent was killed on the ledger (its token PoP is still intact).
    await tg.ledger.appendProjected(
      {
        actor: 'did:mandare:owner',
        mandate_id: 'mnd_kill',
        action: { type: AGENT_REVOKE, target: agentSubject(ACTOR), request_hash: 'f'.repeat(64) },
        cost: { amount: 0, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
      },
      revocationProjector()
    );
    const res = await call(headers);
    expect(res.statusCode).toBe(403);
    expect(res.json().code).toBe('AGENT_REVOKED');
    expect(res.json().denied_entry).toMatch(/^[0-9a-f]{64}$/);
  });

  test('the vault also stops honoring a revoked actor’s tokens (belt-and-suspenders)', async () => {
    vault.revokeActorTokens(ACTOR);
    const res = await call(
      signedHeaders({ secret: grant.popSecret, tokenId: grant.tokenId, nonce: 'vault-revoke' })
    );
    expect(res.statusCode).toBe(401);
    expect(res.json().code).toBe('TOKEN_REVOKED');
  });
});
