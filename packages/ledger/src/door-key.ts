import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  type KeyObject,
} from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';

import { base64UrlToBytes, bytesToHex, sha256Hex, type KeyProvenance } from '@mandarelabs/spec';

/**
 * The door's Ed25519 signing key. Entries are signed by the DOOR, never the
 * agent (integrity lock 1) — the agent process must have no read access to
 * this key material.
 *
 * S3: key material now lives in the vault (OS keychain via @napi-rs/keyring,
 * BUILD-DECISIONS Q8). A vault-sourced key reports `provenance: 'keychain'`,
 * which flows into every entry's `door_signature.key_provenance`. The 0600
 * PEM file (`provenance: 'software'`) remains for headless/CI and the frozen
 * S0–S2 demos.
 */
export interface DoorKey {
  /** sha256 hex of the raw 32-byte public key. */
  readonly keyId: string;
  /** Raw 32-byte public key, lowercase hex. */
  readonly publicKeyHex: string;
  readonly provenance: KeyProvenance;
  sign(data: Uint8Array): Uint8Array;
}

const FILE_MODE_OWNER_ONLY = 0o600;

/** Load (or create) a door key from a 0600 PEM file — `provenance: 'software'`. */
export function loadOrCreateDoorKey(keyPath: string): DoorKey {
  const privateKey = existsSync(keyPath) ? loadKey(keyPath) : createKey(keyPath);
  return toDoorKey(privateKey, 'software');
}

/**
 * Build a door key from a PKCS8 PEM held OUTSIDE a file — e.g. one the vault
 * decrypted from the OS keychain. The caller states the provenance so entries
 * record where the key actually lives.
 */
export function doorKeyFromPem(pem: string, provenance: KeyProvenance): DoorKey {
  const key = createPrivateKey(pem);
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new Error(`door key is ${key.asymmetricKeyType}, expected ed25519`);
  }
  return toDoorKey(key, provenance);
}

/** A fresh Ed25519 private key as a PKCS8 PEM — for the vault to store. */
export function generateDoorKeyPem(): string {
  return generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
}

function loadKey(keyPath: string): KeyObject {
  const pem = readFileSync(keyPath, 'utf8');
  const key = createPrivateKey(pem);
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new Error(`door key at ${keyPath} is ${key.asymmetricKeyType}, expected ed25519`);
  }
  return key;
}

function createKey(keyPath: string): KeyObject {
  const { privateKey } = generateKeyPairSync('ed25519');
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  writeFileSync(keyPath, pem, { mode: FILE_MODE_OWNER_ONLY, flag: 'wx' });
  return privateKey;
}

function toDoorKey(privateKey: KeyObject, provenance: KeyProvenance): DoorKey {
  const publicJwk = createPublicKey(privateKey).export({ format: 'jwk' });
  if (typeof publicJwk.x !== 'string') {
    throw new Error('could not extract raw Ed25519 public key');
  }
  const rawPublicKey = base64UrlToBytes(publicJwk.x);
  return {
    keyId: sha256Hex(rawPublicKey),
    publicKeyHex: bytesToHex(rawPublicKey),
    provenance,
    sign: (data) => new Uint8Array(cryptoSign(null, data, privateKey)),
  };
}
