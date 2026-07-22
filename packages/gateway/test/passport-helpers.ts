import {
  AttestationAuthority,
  MockIdvProvider,
  didFromPublicJwk,
  generateEd25519KeyPair,
  issueDelegationCredential,
  signMandareRequest,
  type Ed25519KeyPairJwk,
} from '@mandarelabs/passport';
import type { MandateV1 } from '@mandarelabs/spec';

import { testMandate } from './helpers.js';

/**
 * A full passport-chain rig for gateway tests: real authority, real owner,
 * real agent keys, real SD-JWT credential, real RFC 9421 signatures — the
 * only fakes are the provider fetch and the clock-free defaults.
 */

export interface PassportRig {
  authority: AttestationAuthority;
  owner: Ed25519KeyPairJwk;
  ownerDid: string;
  agent: Ed25519KeyPairJwk;
  agentDid: string;
  credential: string;
  /** A schema-valid mandate binding THIS agent under THIS owner. */
  mandate: MandateV1;
}

const DAY_SECONDS = 86_400;

export async function makePassportRig(
  overrides: {
    credential?: (rig: Omit<PassportRig, 'credential' | 'mandate'>) => Promise<string>;
    mandate?: Partial<MandateV1>;
  } = {}
): Promise<PassportRig> {
  const authority = new AttestationAuthority(await generateEd25519KeyPair());
  const owner = await generateEd25519KeyPair();
  const ownerDid = didFromPublicJwk(owner.publicJwk);
  const agent = await generateEd25519KeyPair();
  const agentDid = didFromPublicJwk(agent.publicJwk);
  const base = { authority, owner, ownerDid, agent, agentDid };

  let credential: string;
  if (overrides.credential !== undefined) {
    credential = await overrides.credential(base);
  } else {
    const kyc = await new MockIdvProvider().verifyOwner(ownerDid);
    const nowSeconds = Math.floor(Date.now() / 1000);
    const attestation = await authority.attestOwner(ownerDid, kyc, nowSeconds);
    credential = await issueDelegationCredential({
      ownerKeyPair: owner,
      agentPublicJwk: agent.publicJwk,
      attestation,
      revocationRef: 'statuslist:agents#0',
      keyProvenance: 'software',
      issuedAtSeconds: nowSeconds,
      notBeforeSeconds: nowSeconds - 60,
      expiresSeconds: nowSeconds + DAY_SECONDS,
    });
  }

  const mandate = testMandate({
    principal: ownerDid,
    agent: agentDid,
    ...overrides.mandate,
  });
  return { ...base, credential, mandate };
}

export const INJECT_HOST = '127.0.0.1:8484';

/** Build fully signed inject options for a gateway request. */
export async function signedInject(
  rig: Pick<PassportRig, 'agent' | 'agentDid' | 'credential'>,
  args: {
    path: string;
    body: Record<string, unknown>;
    /** Post-signing header tampering (red-team hook). */
    mutateHeaders?: (headers: Record<string, string>) => Record<string, string>;
    /** Send different bytes than were signed (red-team hook). */
    sendBody?: string;
  }
): Promise<{ method: 'POST'; url: string; headers: Record<string, string>; payload: string }> {
  const bodyText = JSON.stringify(args.body);
  const headers = await signMandareRequest({
    method: 'POST',
    url: `http://${INJECT_HOST}${args.path}`,
    bodyBytes: new TextEncoder().encode(bodyText),
    agentDid: rig.agentDid,
    agentPrivateJwk: rig.agent.privateJwk,
    agentPublicJwk: rig.agent.publicJwk,
    passport: rig.credential,
  });
  const finalHeaders = args.mutateHeaders === undefined ? headers : args.mutateHeaders(headers);
  return {
    method: 'POST',
    url: args.path,
    headers: { ...finalHeaders, host: INJECT_HOST, 'content-type': 'application/json' },
    payload: args.sendBody ?? bodyText,
  };
}
