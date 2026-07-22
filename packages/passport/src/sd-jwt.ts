import type { webcrypto } from 'node:crypto';

import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { bytesToBase64Url, base64UrlToBytes } from '@mandarelabs/spec';

import { publicJwkFromDid } from './keys.js';
import { signBytes, utf8Bytes, verifyBytes } from './keys.js';

/**
 * Shared SD-JWT VC plumbing (BUILD-DECISIONS Q2: @sd-jwt/core +
 * @sd-jwt/sd-jwt-vc — "JWS with claims", never a hand-rolled format).
 *
 * All Mandare credentials are Ed25519 (EdDSA) and their issuers are did:key
 * DIDs, so verification is fully OFFLINE: the issuer's public key is derived
 * from the `iss` claim itself. Revocation deliberately does NOT use the
 * SD-JWT `status` fetch machinery — the gateway reads the local ledger
 * revocation projection directly (S3's rule: enforcement never touches the
 * bitstring, and never the network). Credentials carry the shared
 * `revocation_ref` vocabulary (`statuslist:<listId>#<index>`) instead; S6
 * adds the standard resolvable `status` claim when it hosts the lists.
 */

const SD_JWT_HASH_ALG = 'sha-256';
const SALT_BYTES = 16;

async function sha256Hasher(data: string | ArrayBuffer): Promise<Uint8Array> {
  const bytes = typeof data === 'string' ? utf8Bytes(data) : new Uint8Array(data);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as webcrypto.BufferSource));
}

function generateSalt(): string {
  const salt = new Uint8Array(SALT_BYTES);
  crypto.getRandomValues(salt);
  return bytesToBase64Url(salt);
}

/** An SD-JWT VC instance that signs with the given Ed25519 private JWK. */
export function sdJwtIssuer(privateJwk: webcrypto.JsonWebKey): SDJwtVcInstance {
  return new SDJwtVcInstance({
    hasher: sha256Hasher,
    hashAlg: SD_JWT_HASH_ALG,
    saltGenerator: generateSalt,
    signAlg: 'EdDSA',
    signer: async (data: string) => bytesToBase64Url(await signBytes(privateJwk, utf8Bytes(data))),
  });
}

/** An SD-JWT VC instance that verifies against ONE known Ed25519 public JWK. */
export function sdJwtVerifier(publicJwk: webcrypto.JsonWebKey): SDJwtVcInstance {
  return new SDJwtVcInstance({
    hasher: sha256Hasher,
    hashAlg: SD_JWT_HASH_ALG,
    verifier: async (data: string, signature: string) =>
      verifyBytes(publicJwk, utf8Bytes(data), base64UrlToBytes(signature)),
  });
}

/**
 * Extract the UNVERIFIED payload of a compact (SD-)JWT — used only to read
 * `iss` so the right verification key can be derived from the DID. Nothing
 * from this payload may be trusted until `verify` has passed (R4).
 */
export function unverifiedPayload(compact: string): Record<string, unknown> {
  const jwtPart = compact.split('~')[0] ?? '';
  const segments = jwtPart.split('.');
  if (segments.length !== 3) {
    throw new Error('sd-jwt: not a compact JWT (expected three dot-separated segments)');
  }
  const decoded = new TextDecoder().decode(base64UrlToBytes(segments[1] as string));
  const payload: unknown = JSON.parse(decoded);
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new Error('sd-jwt: payload is not a JSON object');
  }
  return payload as Record<string, unknown>;
}

/** Read `iss` (must be a did:key) from an unverified compact SD-JWT. */
export function unverifiedIssuerDid(compact: string): string {
  const payload = unverifiedPayload(compact);
  const iss = payload.iss;
  if (typeof iss !== 'string' || iss.length === 0) {
    throw new Error('sd-jwt: missing iss claim');
  }
  return iss;
}

/**
 * Verify a compact SD-JWT VC OFFLINE against the key its own `iss` did:key
 * encodes, and return the verified claims. The caller MUST then check that
 * `iss` is the party it expects (owner, authority, …) — this proves only
 * "signed by the key the iss DID names".
 */
export async function verifySelfIssued(
  compact: string,
  expectedVct: string,
  nowSeconds?: number
): Promise<Record<string, unknown>> {
  const issuerDid = unverifiedIssuerDid(compact);
  const instance = sdJwtVerifier(publicJwkFromDid(issuerDid));
  const result = await instance.verify(
    compact,
    nowSeconds === undefined ? undefined : { currentDate: nowSeconds }
  );
  const claims = result.payload as Record<string, unknown>;
  if (claims.vct !== expectedVct) {
    throw new Error(`sd-jwt: expected vct '${expectedVct}', got '${String(claims.vct)}'`);
  }
  return claims;
}
