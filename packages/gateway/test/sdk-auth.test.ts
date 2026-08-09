import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, test } from 'vitest';

import { createMandareFetch, MandareGateway, MandareRefusedError } from '@mandarelabs/sdk';
import { Vault, loadVaultConfigFromEnv } from '@mandarelabs/vault';

import { anthropicBody, anthropicOkFetch, openTestGateway, type TestGateway } from './helpers.js';
import { makePassportRig } from './passport-helpers.js';

/**
 * SDK ↔ door parity (S7). The Apache SDK re-states the token PoP wire
 * contract instead of importing the AGPL vault, so THIS suite is the drift
 * alarm: a real vault-issued token and a real passport rig, a real listening
 * gateway, and the SDK's signed fetch on the client side. If either side's
 * bytes move, these tests fail.
 */

let tg: TestGateway;
let vaultDir: string | null = null;
let baseUrl = '';

afterEach(async () => {
  await tg.close();
  if (vaultDir !== null) {
    rmSync(vaultDir, { recursive: true, force: true });
    vaultDir = null;
  }
});

function openFileVault(): Vault {
  vaultDir = mkdtempSync(join(tmpdir(), 'mandare-sdk-vault-'));
  return Vault.open(
    loadVaultConfigFromEnv({
      MANDARE_VAULT_BACKEND: 'file',
      MANDARE_VAULT_DB: join(vaultDir, 'vault.db'),
      MANDARE_VAULT_KEY_FILE: join(vaultDir, 'vault.masterkey'),
    })
  );
}

async function listen(gateway: TestGateway): Promise<string> {
  await gateway.app.listen({ port: 0, host: '127.0.0.1' });
  const address = gateway.app.server.address();
  if (address === null || typeof address === 'string') {
    throw new Error('gateway did not bind a TCP port');
  }
  return `http://127.0.0.1:${address.port}`;
}

describe('SDK token mode against a real vault-backed door', () => {
  test('a vault-issued token signed by the SDK is accepted; spend flows', async () => {
    const vault = openFileVault();
    const grant = vault.issueToken({ actor: 'did:example:agent', mandateId: 'mnd_gateway_test' });
    tg = await openTestGateway({
      config: { authMode: 'token' },
      vault,
      fetchImpl: anthropicOkFetch({ input_tokens: 10, output_tokens: 20 }),
    });
    baseUrl = await listen(tg);

    const gateway = new MandareGateway({
      baseUrl,
      auth: { mode: 'token', credentials: { tokenId: grant.tokenId, popSecret: grant.popSecret } },
    });
    const result = await gateway.messages<{ id: string }>(anthropicBody);
    expect(result.id).toBeDefined();
  });

  test('a 401 auth refusal surfaces as a TYPED MandareRefusedError via the client', async () => {
    const vault = openFileVault();
    const grant = vault.issueToken({ actor: 'did:example:agent', mandateId: 'mnd_gateway_test' });
    tg = await openTestGateway({
      config: { authMode: 'token' },
      vault,
      fetchImpl: anthropicOkFetch({ input_tokens: 10, output_tokens: 20 }),
    });
    baseUrl = await listen(tg);

    const gateway = new MandareGateway({
      baseUrl,
      auth: { mode: 'token', credentials: { tokenId: grant.tokenId, popSecret: 'wrong' } },
    });
    const error = await gateway.messages(anthropicBody).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(MandareRefusedError);
    expect((error as MandareRefusedError).status).toBe(401);
    expect((error as MandareRefusedError).refusal.code).toBe('BAD_POP');
    expect((error as MandareRefusedError).refusal.reasons.length).toBeGreaterThan(0);
  });

  test('the right token id with the wrong secret is dead paper (BAD_POP)', async () => {
    const vault = openFileVault();
    const grant = vault.issueToken({ actor: 'did:example:agent', mandateId: 'mnd_gateway_test' });
    tg = await openTestGateway({
      config: { authMode: 'token' },
      vault,
      fetchImpl: anthropicOkFetch({ input_tokens: 10, output_tokens: 20 }),
    });
    baseUrl = await listen(tg);

    const wrapped = createMandareFetch({
      auth: { mode: 'token', credentials: { tokenId: grant.tokenId, popSecret: 'not-the-secret' } },
    });
    const response = await wrapped(`${baseUrl}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(anthropicBody),
    });
    expect(response.status).toBe(401);
    expect(((await response.json()) as { code: string }).code).toBe('BAD_POP');
  });
});

describe('SDK passport mode against a real passport-verifying door', () => {
  test('an SDK-signed request under a real delegation credential is accepted', async () => {
    const rig = await makePassportRig();
    tg = await openTestGateway({
      config: { authMode: 'passport', trustedAuthorityDid: rig.authority.did },
      mandate: rig.mandate,
      fetchImpl: anthropicOkFetch({ input_tokens: 10, output_tokens: 20 }),
    });
    baseUrl = await listen(tg);

    const gateway = new MandareGateway({
      baseUrl,
      auth: {
        mode: 'passport',
        identity: {
          credential: rig.credential,
          agentDid: rig.agentDid,
          privateJwk: rig.agent.privateJwk,
          publicJwk: rig.agent.publicJwk,
        },
      },
    });
    const result = await gateway.messages<{ id: string }>(anthropicBody);
    expect(result.id).toBeDefined();
  });

  test('a body swapped between signing and sending is refused (Content-Digest)', async () => {
    const rig = await makePassportRig();
    tg = await openTestGateway({
      config: { authMode: 'passport', trustedAuthorityDid: rig.authority.did },
      mandate: rig.mandate,
      fetchImpl: anthropicOkFetch({ input_tokens: 10, output_tokens: 20 }),
    });
    baseUrl = await listen(tg);

    // A man-in-the-middle under the signed fetch: same headers, altered body.
    const tampering: typeof fetch = (input, init) =>
      fetch(input, {
        ...init,
        body: JSON.stringify({ ...anthropicBody, max_tokens: 999_999 }),
      });
    const wrapped = createMandareFetch({
      auth: {
        mode: 'passport',
        identity: {
          credential: rig.credential,
          agentDid: rig.agentDid,
          privateJwk: rig.agent.privateJwk,
          publicJwk: rig.agent.publicJwk,
        },
      },
      fetch: tampering,
    });
    const response = await wrapped(`${baseUrl}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(anthropicBody),
    });
    expect(response.status).toBe(401);
    expect(((await response.json()) as { code: string }).code).toBe('BODY_DIGEST_MISMATCH');
  });
});
