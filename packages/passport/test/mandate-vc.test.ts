import { describe, expect, it } from 'vitest';

import type { MandateV1 } from '@mandarelabs/spec';

import {
  generateEd25519KeyPair,
  didFromPublicJwk,
  issueMandateVc,
  signMandatePayload,
  verifyMandateVc,
  type Ed25519KeyPairJwk,
} from '../src/index.js';

const NOW_SECONDS = Math.floor(Date.parse('2026-07-22T12:00:00Z') / 1000);

async function makeSignedMandate(): Promise<{
  owner: Ed25519KeyPairJwk;
  mandate: MandateV1;
  compact: string;
}> {
  const owner = await generateEd25519KeyPair();
  const agent = await generateEd25519KeyPair();
  const unsigned = {
    schema_version: 1 as const,
    id: 'mnd_test_0001',
    principal: didFromPublicJwk(owner.publicJwk),
    agent: didFromPublicJwk(agent.publicJwk),
    purpose: 'test mandate',
    scopes: [
      {
        type: 'spend' as const,
        currency: 'EUR',
        per_tx_max: 5_000_000,
        per_day_max: 20_000_000,
        per_task_max: 20_000_000,
        total_cap: 100_000_000,
        rails: ['gateway' as const],
        counterparties: 'any' as const,
        categories: ['llm'],
      },
      { type: 'action' as const, classes: ['llm.call'] },
    ],
    approvals: { rules: [] },
    billing_identity: {
      legal_name: 'Example GmbH',
      vat_id: 'DE000000000',
      address: 'Musterstraße 1, 60311 Frankfurt',
    },
    valid_from: '2026-07-22T00:00:00Z',
    valid_until: '2026-07-23T00:00:00Z',
    revocation_ref: 'statuslist:agents#1',
  };
  const mandate = await signMandatePayload(unsigned, owner, 'software');
  const compact = await issueMandateVc(mandate, owner, NOW_SECONDS);
  return { owner, mandate, compact };
}

describe('mandate SD-JWT VC transport', () => {
  it('issues and verifies a mandate (envelope + detached signature), dormant billing_identity intact', async () => {
    const { mandate, compact } = await makeSignedMandate();
    const verified = await verifyMandateVc(compact, NOW_SECONDS);
    expect(verified).toEqual(mandate);
    expect(verified.billing_identity?.legal_name).toBe('Example GmbH');
  });

  it('refuses a tampered mandate payload (forged mandate signature)', async () => {
    const { compact } = await makeSignedMandate();
    const [jwt, ...rest] = compact.split('~');
    const [header, payloadB64, sig] = (jwt as string).split('.');
    const payload = JSON.parse(Buffer.from(payloadB64 as string, 'base64url').toString());
    payload.mandate.scopes[0].per_day_max = 20_000_000_000; // 20 000 EUR, please
    const forged = [
      [header, Buffer.from(JSON.stringify(payload)).toString('base64url'), sig].join('.'),
      ...rest,
    ].join('~');
    await expect(verifyMandateVc(forged, NOW_SECONDS)).rejects.toThrow();
  });

  it('refuses a mandate whose detached signature is from a different key', async () => {
    const { mandate } = await makeSignedMandate();
    const impostor = await generateEd25519KeyPair();
    // The impostor re-wraps the (validly owner-signed) mandate under its own
    // envelope — envelope iss must equal mandate.principal.
    await expect(issueMandateVc(mandate, impostor, NOW_SECONDS)).rejects.toThrow(
      /must be the mandate principal/
    );
  });

  it('refuses a mandate signed end-to-end by a non-principal key', async () => {
    const owner = await generateEd25519KeyPair();
    const impostor = await generateEd25519KeyPair();
    const agent = await generateEd25519KeyPair();
    const unsigned = {
      schema_version: 1 as const,
      id: 'mnd_test_0002',
      principal: didFromPublicJwk(owner.publicJwk),
      agent: didFromPublicJwk(agent.publicJwk),
      purpose: 'forged mandate',
      scopes: [{ type: 'action' as const, classes: ['llm.call'] }],
      approvals: { rules: [] },
      valid_from: '2026-07-22T00:00:00Z',
      valid_until: '2026-07-23T00:00:00Z',
      revocation_ref: 'statuslist:agents#2',
    };
    // The impostor cannot even produce the detached block for someone else's
    // principal DID.
    await expect(signMandatePayload(unsigned, impostor, 'software')).rejects.toThrow(
      /not the signing owner key/
    );
  });

  it('refuses non-did:key principals (v1 DID profile)', async () => {
    const owner = await generateEd25519KeyPair();
    const unsigned = {
      schema_version: 1 as const,
      id: 'mnd_test_0003',
      principal: 'did:mandare:dev-owner',
      agent: 'did:mandare:dev-agent',
      purpose: 'legacy dev mandate',
      scopes: [{ type: 'action' as const, classes: ['llm.call'] }],
      approvals: { rules: [] },
      valid_from: '2026-07-22T00:00:00Z',
      valid_until: '2026-07-23T00:00:00Z',
      revocation_ref: 'statuslist:dev#0',
    };
    await expect(signMandatePayload(unsigned, owner, 'software')).rejects.toThrow();
  });

  it('refuses an expired mandate envelope', async () => {
    const { compact } = await makeSignedMandate();
    const nowAfterExpiry = Math.floor(Date.parse('2026-07-24T00:00:01Z') / 1000);
    await expect(verifyMandateVc(compact, nowAfterExpiry)).rejects.toThrow(/expired/i);
  });
});
