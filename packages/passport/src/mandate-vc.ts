import {
  canonicalJson,
  parseMandate,
  base64UrlToBytes,
  bytesToBase64Url,
  type KeyProvenance,
  type MandateV1,
  type SignatureBlock,
} from '@mandarelabs/spec';

import { isDidKey } from './did-key.js';
import {
  didFromPublicJwk,
  keyIdFromRawPublicKey,
  publicJwkFromDid,
  rawPublicKeyFromJwk,
  signBytes,
  utf8Bytes,
  verifyBytes,
  type Ed25519KeyPairJwk,
} from './keys.js';
import { sdJwtIssuer, verifySelfIssued } from './sd-jwt.js';

/**
 * Mandate transport as SD-JWT VC (SPEC §5: "Signed JSON documents (SD-JWT
 * VC), signed by the owner key"; Q2). The FROZEN MandateV1 schema is the
 * payload contract and stays self-contained: the mandate JSON inside the VC
 * still carries its detached owner signature (Ed25519 over canonical JSON
 * without `signature`), so the extracted document verifies on its own — the
 * SD-JWT envelope adds the standards-world transport, it does not replace
 * the schema's signature. Both signatures are the SAME owner key.
 */

export const MANDATE_VCT = 'urn:mandare:credential:mandate';

/** Detached-sign a mandate payload (the S0-frozen convention, now with did:key). */
export async function signMandatePayload(
  mandate: Omit<MandateV1, 'signature'>,
  ownerKeyPair: Ed25519KeyPairJwk,
  keyProvenance: KeyProvenance
): Promise<MandateV1> {
  const ownerDid = didFromPublicJwk(ownerKeyPair.publicJwk);
  if (mandate.principal !== ownerDid) {
    throw new Error(
      `mandate: principal ${mandate.principal} is not the signing owner key's DID ${ownerDid}`
    );
  }
  const rawPublic = rawPublicKeyFromJwk(ownerKeyPair.publicJwk);
  const signature: SignatureBlock = {
    alg: 'EdDSA',
    key_id: await keyIdFromRawPublicKey(rawPublic),
    key_provenance: keyProvenance,
    value: bytesToBase64Url(
      await signBytes(ownerKeyPair.privateJwk, utf8Bytes(canonicalJson(mandate)))
    ),
  };
  return parseMandate({ ...mandate, signature });
}

const isoToEpochSeconds = (iso: string): number => Math.floor(Date.parse(iso) / 1000);

/** Wrap a signed mandate in its SD-JWT VC envelope (owner-signed). */
export async function issueMandateVc(
  mandate: MandateV1,
  ownerKeyPair: Ed25519KeyPairJwk,
  issuedAtSeconds: number
): Promise<string> {
  const ownerDid = didFromPublicJwk(ownerKeyPair.publicJwk);
  if (mandate.principal !== ownerDid) {
    throw new Error('mandate: envelope signer must be the mandate principal');
  }
  const issuer = sdJwtIssuer(ownerKeyPair.privateJwk);
  return issuer.issue({
    vct: MANDATE_VCT,
    iss: mandate.principal,
    sub: mandate.agent,
    iat: issuedAtSeconds,
    nbf: isoToEpochSeconds(mandate.valid_from),
    exp: isoToEpochSeconds(mandate.valid_until),
    mandate: mandate as unknown as Record<string, unknown>,
  });
}

/**
 * Verify a mandate VC fully OFFLINE and return the schema-validated mandate:
 * envelope signature (owner key from `iss` did:key) → frozen-schema parse
 * (R4) → envelope/payload consistency → detached owner signature over the
 * canonical payload. Throws on any failure; a mandate that does not verify
 * does not exist (R1).
 */
export async function verifyMandateVc(compact: string, nowSeconds?: number): Promise<MandateV1> {
  const claims = await verifySelfIssued(compact, MANDATE_VCT, nowSeconds);
  const mandate = parseMandate(claims.mandate);

  if (!isDidKey(mandate.principal) || !isDidKey(mandate.agent)) {
    throw new Error('mandate: v1 DID profile requires did:key principal and agent');
  }
  if (claims.iss !== mandate.principal || claims.sub !== mandate.agent) {
    throw new Error('mandate: envelope iss/sub do not match the mandate principal/agent');
  }

  const ownerJwk = publicJwkFromDid(mandate.principal);
  const expectedKeyId = await keyIdFromRawPublicKey(rawPublicKeyFromJwk(ownerJwk));
  if (mandate.signature.key_id !== expectedKeyId) {
    throw new Error('mandate: detached signature key_id is not the principal key (forgery refused)');
  }
  const { signature, ...unsigned } = mandate;
  const detachedValid = await verifyBytes(
    ownerJwk,
    utf8Bytes(canonicalJson(unsigned)),
    base64UrlToBytes(signature.value)
  );
  if (!detachedValid) {
    throw new Error('mandate: detached owner signature does not verify (forgery refused)');
  }
  return mandate;
}
