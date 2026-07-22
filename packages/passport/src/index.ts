/**
 * @mandarelabs/passport — Mandare identity & delegation (Apache-2.0).
 *
 * did:key identities (v1 profile: Ed25519 only, offline-verifiable), the
 * owner→agent delegation credential chain (SD-JWT VC, authority-countersigned
 * after mock IDV), mandate SD-JWT VC transport, and RFC 9421 request
 * signatures. Everything here verifies OFFLINE and is embeddable by parties
 * who distrust us — hence Apache, like the verifier.
 */

export { base58Decode, base58Encode } from './base58.js';
export { DID_KEY_PREFIX, didKeyFromPublicKey, isDidKey, publicKeyFromDidKey } from './did-key.js';
export {
  didFromPublicJwk,
  generateEd25519KeyPair,
  importPrivateKey,
  importPublicKey,
  keyIdFromRawPublicKey,
  publicJwkFromDid,
  publicJwkFromRaw,
  rawPublicKeyFromJwk,
  signBytes,
  utf8Bytes,
  verifyBytes,
  type Ed25519KeyPairJwk,
} from './keys.js';
export {
  MOCK_IDV_PARTNER_ID,
  MockIdvProvider,
  type IdvProvider,
  type KycAttestationRecord,
} from './idv.js';
export {
  AttestationAuthority,
  OWNER_ATTESTATION_VCT,
  verifyOwnerAttestation,
  type OwnerAttestationClaims,
} from './attestation.js';
export {
  AGENT_DELEGATION_VCT,
  issueDelegationCredential,
  verifyPassport,
  type IssueDelegationInput,
  type VerifiedPassport,
  type VerifyPassportOptions,
} from './delegation.js';
export {
  MANDATE_VCT,
  issueMandateVc,
  signMandatePayload,
  verifyMandateVc,
} from './mandate-vc.js';
export {
  CONTENT_DIGEST_HEADER,
  DEFAULT_SIGNATURE_TTL_SECONDS,
  InMemoryNonceStore,
  MAX_SIGNATURE_LIFETIME_SECONDS,
  PASSPORT_HEADER,
  REQUIRED_COMPONENTS,
  RequestSignatureError,
  contentDigestHeaderValue,
  coveredComponents,
  signMandareRequest,
  verifyMandareRequest,
  type NonceStore,
  type RequestSignatureRefusalCode,
  type SignRequestInput,
  type VerifyRequestInput,
} from './request-signature.js';
export { unverifiedIssuerDid, unverifiedPayload } from './sd-jwt.js';
