import { didFromPublicJwk } from './keys.js';
import { sdJwtIssuer, verifySelfIssued } from './sd-jwt.js';
import type { Ed25519KeyPairJwk } from './keys.js';
import type { KycAttestationRecord } from './idv.js';

/**
 * The attestation authority — LOCAL MODE (FOUNDER RULING, S4): a
 * self-contained authority key countersigns the owner after IDV. The chain it
 * anchors is SPEC §4's passport: authority → verified owner → agent. The
 * CLOUD authority (root keys offline/HSM, intermediate issuing keys) is a
 * later, separate private-repo service; verifiers only ever need the
 * authority DID they choose to trust, so swapping local → cloud changes no
 * verification code.
 */

export const OWNER_ATTESTATION_VCT = 'urn:mandare:attestation:owner-kyc';

export interface OwnerAttestationClaims {
  ownerDid: string;
  authorityDid: string;
  kyc: KycAttestationRecord;
  issuedAtSeconds: number;
}

export class AttestationAuthority {
  private readonly keyPair: Ed25519KeyPairJwk;
  readonly did: string;

  constructor(keyPair: Ed25519KeyPairJwk) {
    this.keyPair = keyPair;
    this.did = didFromPublicJwk(keyPair.publicJwk);
  }

  /**
   * Countersign an owner after IDV: "this owner DID is bound to a
   * KYC-verified human at level N". Carries ONLY the four attestation fields
   * (SPEC §4) — no PII, nothing selectively disclosable, no expiry (the
   * attestation states a past fact; revocation, if ever needed, goes through
   * the shared status-list vocabulary).
   */
  async attestOwner(ownerDid: string, kyc: KycAttestationRecord, iatSeconds: number): Promise<string> {
    const issuer = sdJwtIssuer(this.keyPair.privateJwk);
    const { kyc_level, partner_id, date, ref_hash } = kyc;
    return issuer.issue({
      vct: OWNER_ATTESTATION_VCT,
      iss: this.did,
      sub: ownerDid,
      iat: iatSeconds,
      kyc_level,
      partner_id,
      date,
      ref_hash,
    });
  }
}

/**
 * Verify an owner attestation OFFLINE and require it to be signed by the ONE
 * authority the verifier trusts. Returns the verified claims.
 */
export async function verifyOwnerAttestation(
  compact: string,
  trustedAuthorityDid: string,
  nowSeconds?: number
): Promise<OwnerAttestationClaims> {
  const claims = await verifySelfIssued(compact, OWNER_ATTESTATION_VCT, nowSeconds);
  if (claims.iss !== trustedAuthorityDid) {
    throw new Error(
      `attestation: issuer ${String(claims.iss)} is not the trusted attestation authority`
    );
  }
  const { sub, iat, kyc_level, partner_id, date, ref_hash } = claims;
  if (typeof sub !== 'string' || sub.length === 0) {
    throw new Error('attestation: missing owner (sub) claim');
  }
  if (
    typeof iat !== 'number' ||
    !Number.isSafeInteger(kyc_level as number) ||
    typeof partner_id !== 'string' ||
    typeof date !== 'string' ||
    typeof ref_hash !== 'string'
  ) {
    throw new Error('attestation: malformed KYC attestation record (R4)');
  }
  return {
    ownerDid: sub,
    authorityDid: trustedAuthorityDid,
    kyc: {
      kyc_level: kyc_level as number,
      partner_id,
      date,
      ref_hash,
    },
    issuedAtSeconds: iat,
  };
}
