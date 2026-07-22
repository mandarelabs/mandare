import { sha256HexAsync } from '@mandarelabs/spec';

/**
 * IDV/KYC boundary (FOUNDER RULING, S4): interface + mock provider, no live
 * partner. The attestation record carries ONLY {kyc_level, partner_id, date,
 * ref_hash} — never PII (SPEC §4: "PII stays with the IDV partner and the
 * owner"). A real partner (IDnow / Persona, EU-friendly) is a config swap
 * behind this interface once the company entity exists.
 */

export interface KycAttestationRecord {
  /** KYC assurance level the partner attested (1 = basic identity check). */
  kyc_level: number;
  /** Which partner performed the verification. */
  partner_id: string;
  /** ISO date (UTC) of the verification. */
  date: string;
  /**
   * sha256 hex of the partner's case reference — lets the owner or a court
   * correlate back to the partner's records WITHOUT Mandare storing any PII.
   */
  ref_hash: string;
}

export interface IdvProvider {
  readonly partnerId: string;
  /** Run (or look up) identity verification for an owner. Never returns PII. */
  verifyOwner(ownerDid: string): Promise<KycAttestationRecord>;
}

export const MOCK_IDV_PARTNER_ID = 'mock:local';
const MOCK_KYC_LEVEL = 1;

/**
 * The mock partner: deterministic per (owner, day), so re-issuing a passport
 * on the same day yields the same attestation record. It fabricates no PII —
 * there is none anywhere in the flow, which is exactly the production shape.
 */
export class MockIdvProvider implements IdvProvider {
  readonly partnerId = MOCK_IDV_PARTNER_ID;
  private readonly clock: () => Date;

  constructor(clock: () => Date = () => new Date()) {
    this.clock = clock;
  }

  async verifyOwner(ownerDid: string): Promise<KycAttestationRecord> {
    const date = this.clock().toISOString().slice(0, 10);
    return {
      kyc_level: MOCK_KYC_LEVEL,
      partner_id: this.partnerId,
      date,
      ref_hash: await sha256HexAsync(new TextEncoder().encode(`${this.partnerId}:${ownerDid}:${date}`)),
    };
  }
}
