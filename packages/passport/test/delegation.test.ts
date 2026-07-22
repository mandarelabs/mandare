import { describe, expect, it } from 'vitest';

import {
  AttestationAuthority,
  MockIdvProvider,
  generateEd25519KeyPair,
  didFromPublicJwk,
  issueDelegationCredential,
  verifyPassport,
  type Ed25519KeyPairJwk,
} from '../src/index.js';

const NOW_SECONDS = Math.floor(Date.parse('2026-07-22T12:00:00Z') / 1000);
const DAY_SECONDS = 86_400;

interface Actors {
  authority: AttestationAuthority;
  owner: Ed25519KeyPairJwk;
  ownerDid: string;
  agent: Ed25519KeyPairJwk;
  agentDid: string;
}

async function makeActors(): Promise<Actors> {
  const authorityKeys = await generateEd25519KeyPair();
  const owner = await generateEd25519KeyPair();
  const agent = await generateEd25519KeyPair();
  return {
    authority: new AttestationAuthority(authorityKeys),
    owner,
    ownerDid: didFromPublicJwk(owner.publicJwk),
    agent,
    agentDid: didFromPublicJwk(agent.publicJwk),
  };
}

async function issuePassport(actors: Actors, overrides: { attestation?: string } = {}) {
  const idv = new MockIdvProvider(() => new Date(NOW_SECONDS * 1000));
  const kyc = await idv.verifyOwner(actors.ownerDid);
  const attestation =
    overrides.attestation ?? (await actors.authority.attestOwner(actors.ownerDid, kyc, NOW_SECONDS));
  return issueDelegationCredential({
    ownerKeyPair: actors.owner,
    agentPublicJwk: actors.agent.publicJwk,
    attestation,
    revocationRef: 'statuslist:agents#0',
    keyProvenance: 'software',
    issuedAtSeconds: NOW_SECONDS,
    notBeforeSeconds: NOW_SECONDS - 60,
    expiresSeconds: NOW_SECONDS + 90 * DAY_SECONDS,
  });
}

describe('agent delegation credential (the passport chain)', () => {
  it('issues and verifies the full authority → owner → agent chain offline', async () => {
    const actors = await makeActors();
    const credential = await issuePassport(actors);
    const verified = await verifyPassport(credential, {
      trustedAuthorityDid: actors.authority.did,
      nowSeconds: NOW_SECONDS,
    });
    expect(verified.agentDid).toBe(actors.agentDid);
    expect(verified.ownerDid).toBe(actors.ownerDid);
    expect(verified.attestation.kyc.partner_id).toBe('mock:local');
    expect(verified.attestation.kyc.kyc_level).toBe(1);
    expect(verified.revocationRef).toBe('statuslist:agents#0');
    // The attestation record carries only the four SPEC §4 fields — no PII.
    expect(Object.keys(verified.attestation.kyc).sort()).toEqual([
      'date',
      'kyc_level',
      'partner_id',
      'ref_hash',
    ]);
  });

  it('refuses a credential whose payload was tampered with (forged claims)', async () => {
    const actors = await makeActors();
    const credential = await issuePassport(actors);
    const [jwt, ...rest] = credential.split('~');
    const [header, payloadB64, sig] = (jwt as string).split('.');
    const payload = JSON.parse(Buffer.from(payloadB64 as string, 'base64url').toString());
    payload.sub = 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp';
    const forged = [
      [header, Buffer.from(JSON.stringify(payload)).toString('base64url'), sig].join('.'),
      ...rest,
    ].join('~');
    await expect(
      verifyPassport(forged, { trustedAuthorityDid: actors.authority.did, nowSeconds: NOW_SECONDS })
    ).rejects.toThrow();
  });

  it('refuses a credential signed by a key that is not the owner it names', async () => {
    const actors = await makeActors();
    const impostor = await generateEd25519KeyPair();
    const idv = new MockIdvProvider(() => new Date(NOW_SECONDS * 1000));
    const kyc = await idv.verifyOwner(actors.ownerDid);
    const attestation = await actors.authority.attestOwner(actors.ownerDid, kyc, NOW_SECONDS);
    // The impostor signs a credential — its iss is the impostor's own DID,
    // which the attestation does not bind.
    const credential = await issueDelegationCredential({
      ownerKeyPair: impostor,
      agentPublicJwk: actors.agent.publicJwk,
      attestation,
      revocationRef: 'statuslist:agents#0',
      keyProvenance: 'software',
      issuedAtSeconds: NOW_SECONDS,
      notBeforeSeconds: NOW_SECONDS - 60,
      expiresSeconds: NOW_SECONDS + DAY_SECONDS,
    });
    await expect(
      verifyPassport(credential, {
        trustedAuthorityDid: actors.authority.did,
        nowSeconds: NOW_SECONDS,
      })
    ).rejects.toThrow(/different owner/);
  });

  it('refuses a chain countersigned by an untrusted authority (delegation-chain break)', async () => {
    const actors = await makeActors();
    const rogueAuthority = new AttestationAuthority(await generateEd25519KeyPair());
    const idv = new MockIdvProvider(() => new Date(NOW_SECONDS * 1000));
    const kyc = await idv.verifyOwner(actors.ownerDid);
    const rogueAttestation = await rogueAuthority.attestOwner(actors.ownerDid, kyc, NOW_SECONDS);
    const credential = await issuePassport(actors, { attestation: rogueAttestation });
    await expect(
      verifyPassport(credential, {
        trustedAuthorityDid: actors.authority.did,
        nowSeconds: NOW_SECONDS,
      })
    ).rejects.toThrow(/not the trusted attestation authority/);
  });

  it('refuses an expired credential', async () => {
    const actors = await makeActors();
    const credential = await issuePassport(actors);
    await expect(
      verifyPassport(credential, {
        trustedAuthorityDid: actors.authority.did,
        nowSeconds: NOW_SECONDS + 91 * DAY_SECONDS,
      })
    ).rejects.toThrow(/expired/i);
  });

  it('refuses a not-yet-valid credential', async () => {
    const actors = await makeActors();
    const credential = await issuePassport(actors);
    await expect(
      verifyPassport(credential, {
        trustedAuthorityDid: actors.authority.did,
        nowSeconds: NOW_SECONDS - DAY_SECONDS,
      })
    ).rejects.toThrow();
  });
});
