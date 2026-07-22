import type { webcrypto } from 'node:crypto';

import { bytesToBase64Url, base64UrlToBytes, sha256HexAsync } from '@mandarelabs/spec';

import { didKeyFromPublicKey, publicKeyFromDidKey } from './did-key.js';

/**
 * Ed25519 key handling for passports — pure WebCrypto (Node ≥22.13), so this
 * package stays portable like the verifier. Keys are exchanged as JWKs (the
 * vault stores them as JWK JSON strings); DIDs are derived from the raw
 * public key bytes.
 */

export interface Ed25519KeyPairJwk {
  publicJwk: webcrypto.JsonWebKey;
  privateJwk: webcrypto.JsonWebKey;
}

const ED25519_ALG = { name: 'Ed25519' } as const;

export async function generateEd25519KeyPair(): Promise<Ed25519KeyPairJwk> {
  const pair = (await crypto.subtle.generateKey(ED25519_ALG, true, [
    'sign',
    'verify',
  ])) as webcrypto.CryptoKeyPair;
  return {
    publicJwk: await crypto.subtle.exportKey('jwk', pair.publicKey),
    privateJwk: await crypto.subtle.exportKey('jwk', pair.privateKey),
  };
}

export function rawPublicKeyFromJwk(jwk: webcrypto.JsonWebKey): Uint8Array {
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
    throw new Error('passport: expected an Ed25519 OKP JWK with an x member');
  }
  return base64UrlToBytes(jwk.x);
}

export function publicJwkFromRaw(rawPublicKey: Uint8Array): webcrypto.JsonWebKey {
  return { kty: 'OKP', crv: 'Ed25519', x: bytesToBase64Url(rawPublicKey) };
}

export function didFromPublicJwk(jwk: webcrypto.JsonWebKey): string {
  return didKeyFromPublicKey(rawPublicKeyFromJwk(jwk));
}

export function publicJwkFromDid(did: string): webcrypto.JsonWebKey {
  return publicJwkFromRaw(publicKeyFromDidKey(did));
}

/**
 * Mandare key_id — lowercase sha256 hex of the raw 32-byte public key. The
 * SAME derivation as ledger door keys and the S1 key directory, so one
 * identifier convention spans doors, owners, and agents.
 */
export async function keyIdFromRawPublicKey(rawPublicKey: Uint8Array): Promise<string> {
  return sha256HexAsync(rawPublicKey);
}

export async function importPrivateKey(privateJwk: webcrypto.JsonWebKey): Promise<webcrypto.CryptoKey> {
  return crypto.subtle.importKey('jwk', privateJwk, ED25519_ALG, false, ['sign']);
}

export async function importPublicKey(publicJwk: webcrypto.JsonWebKey): Promise<webcrypto.CryptoKey> {
  return crypto.subtle.importKey('jwk', publicJwk, ED25519_ALG, false, ['verify']);
}

export async function signBytes(privateJwk: webcrypto.JsonWebKey, data: Uint8Array): Promise<Uint8Array> {
  const key = await importPrivateKey(privateJwk);
  return new Uint8Array(await crypto.subtle.sign(ED25519_ALG, key, data as webcrypto.BufferSource));
}

export async function verifyBytes(
  publicJwk: webcrypto.JsonWebKey,
  data: Uint8Array,
  signature: Uint8Array
): Promise<boolean> {
  const key = await importPublicKey(publicJwk);
  return crypto.subtle.verify(ED25519_ALG, key, signature as webcrypto.BufferSource, data as webcrypto.BufferSource);
}

const textEncoder = new TextEncoder();

export function utf8Bytes(text: string): Uint8Array {
  return textEncoder.encode(text);
}
