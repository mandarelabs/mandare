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
 * this key file.
 *
 * TODO(S3): move key material into the OS keychain via @napi-rs/keyring
 * (BUILD-DECISIONS Q8); `key_provenance` then becomes 'keychain'. The file
 * fallback stays for headless/CI environments.
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

export function loadOrCreateDoorKey(keyPath: string): DoorKey {
  const privateKey = existsSync(keyPath) ? loadKey(keyPath) : createKey(keyPath);
  return toDoorKey(privateKey);
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

function toDoorKey(privateKey: KeyObject): DoorKey {
  const publicJwk = createPublicKey(privateKey).export({ format: 'jwk' });
  if (typeof publicJwk.x !== 'string') {
    throw new Error('could not extract raw Ed25519 public key');
  }
  const rawPublicKey = base64UrlToBytes(publicJwk.x);
  return {
    keyId: sha256Hex(rawPublicKey),
    publicKeyHex: bytesToHex(rawPublicKey),
    provenance: 'software',
    sign: (data) => new Uint8Array(cryptoSign(null, data, privateKey)),
  };
}
