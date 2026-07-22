import type { webcrypto } from 'node:crypto';

import type { KeyProvenance } from '@mandarelabs/spec';

import { verifyOwnerAttestation, type OwnerAttestationClaims } from './attestation.js';
import { isDidKey } from './did-key.js';
import {
  didFromPublicJwk,
  rawPublicKeyFromJwk,
  type Ed25519KeyPairJwk,
} from './keys.js';
import { sdJwtIssuer, verifySelfIssued } from './sd-jwt.js';

/**
 * The Agent Delegation Credential — SPEC §4's passport core, as an SD-JWT VC
 * (Q2). The OWNER signs it; it binds the agent's did:key (and, via `cnf`, the
 * exact public key RFC 9421 request signatures must verify against), carries
 * the authority's countersignature over the owner (the attestation), and
 * points at its revocation slot in the SHARED status-list vocabulary.
 *
 * Chain on verify: trusted authority DID → attestation(sub=owner) →
 * credential iss=owner → sub=agent + cnf key. Break any link and the
 * credential is dead paper (red-team: delegation-chain break).
 */

export const AGENT_DELEGATION_VCT = 'urn:mandare:credential:agent-delegation';

export interface IssueDelegationInput {
  ownerKeyPair: Ed25519KeyPairJwk;
  agentPublicJwk: webcrypto.JsonWebKey;
  /** Compact owner attestation issued by the authority (countersignature). */
  attestation: string;
  /** Shared revocation vocabulary: `statuslist:<listId>#<index>`. */
  revocationRef: string;
  keyProvenance: KeyProvenance;
  issuedAtSeconds: number;
  notBeforeSeconds: number;
  expiresSeconds: number;
  /** Optional pointer to the mandate this delegation was created for. */
  mandateRef?: string;
}

export interface VerifiedPassport {
  agentDid: string;
  ownerDid: string;
  /** The ONLY key whose request signatures prove this agent's identity. */
  agentPublicJwk: webcrypto.JsonWebKey;
  revocationRef: string;
  attestation: OwnerAttestationClaims;
  keyProvenance: string;
  expiresSeconds: number;
  mandateRef: string | null;
}

export async function issueDelegationCredential(input: IssueDelegationInput): Promise<string> {
  const ownerDid = didFromPublicJwk(input.ownerKeyPair.publicJwk);
  const agentDid = didFromPublicJwk(input.agentPublicJwk);
  const issuer = sdJwtIssuer(input.ownerKeyPair.privateJwk);
  return issuer.issue({
    vct: AGENT_DELEGATION_VCT,
    iss: ownerDid,
    sub: agentDid,
    iat: input.issuedAtSeconds,
    nbf: input.notBeforeSeconds,
    exp: input.expiresSeconds,
    cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', x: input.agentPublicJwk.x } },
    attestation: input.attestation,
    revocation_ref: input.revocationRef,
    key_provenance: input.keyProvenance,
    ...(input.mandateRef === undefined ? {} : { mandate_ref: input.mandateRef }),
  });
}

export interface VerifyPassportOptions {
  trustedAuthorityDid: string;
  /** Injectable clock (epoch seconds) for tests; defaults to wall time. */
  nowSeconds?: number;
}

/**
 * Verify the full delegation chain OFFLINE. Throws on ANY broken link (R1:
 * an unverifiable passport is no passport). Revocation state is NOT checked
 * here — the caller checks the agent subject against the ledger projection,
 * which is the local, un-jammable authority.
 */
export async function verifyPassport(
  compact: string,
  options: VerifyPassportOptions
): Promise<VerifiedPassport> {
  const claims = await verifySelfIssued(compact, AGENT_DELEGATION_VCT, options.nowSeconds);

  const ownerDid = claims.iss;
  const agentDid = claims.sub;
  if (typeof ownerDid !== 'string' || !isDidKey(ownerDid)) {
    throw new Error('passport: iss (owner) must be a did:key');
  }
  if (typeof agentDid !== 'string' || !isDidKey(agentDid)) {
    throw new Error('passport: sub (agent) must be a did:key');
  }
  if (typeof claims.exp !== 'number' || typeof claims.nbf !== 'number') {
    throw new Error('passport: credential must carry nbf and exp');
  }

  // cnf key must BE the agent DID's key — otherwise a credential could bind
  // requests to a different key than the identity it names.
  const cnf = claims.cnf as { jwk?: webcrypto.JsonWebKey } | undefined;
  if (cnf?.jwk === undefined) {
    throw new Error('passport: credential carries no cnf confirmation key');
  }
  const agentPublicJwk = cnf.jwk;
  if (didFromPublicJwk(agentPublicJwk) !== agentDid) {
    throw new Error('passport: cnf key does not match the agent DID (key-substitution refused)');
  }
  rawPublicKeyFromJwk(agentPublicJwk); // throws unless a well-formed Ed25519 OKP key

  // The countersignature: authority → owner. Without it (or with the wrong
  // authority, or attesting a DIFFERENT owner) the chain is broken.
  if (typeof claims.attestation !== 'string' || claims.attestation.length === 0) {
    throw new Error('passport: credential is not countersigned (no attestation) — chain broken');
  }
  const attestation = await verifyOwnerAttestation(
    claims.attestation,
    options.trustedAuthorityDid,
    options.nowSeconds
  );
  if (attestation.ownerDid !== ownerDid) {
    throw new Error('passport: attestation binds a different owner than the credential issuer');
  }

  if (typeof claims.revocation_ref !== 'string' || claims.revocation_ref.length === 0) {
    throw new Error('passport: credential carries no revocation_ref');
  }
  if (typeof claims.key_provenance !== 'string') {
    throw new Error('passport: credential carries no key_provenance (R10)');
  }

  return {
    agentDid,
    ownerDid,
    agentPublicJwk,
    revocationRef: claims.revocation_ref,
    attestation,
    keyProvenance: claims.key_provenance,
    expiresSeconds: claims.exp,
    mandateRef: typeof claims.mandate_ref === 'string' ? claims.mandate_ref : null,
  };
}
