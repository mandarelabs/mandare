import { base58Decode, base58Encode } from './base58.js';

/**
 * did:key v1 profile (FOUNDER RULING, S4): Ed25519 only, multibase base58btc
 * + multicodec, for `principal` and `agent`. No resolver, no chain, no
 * network — the DID *is* the public key, verifiable offline. `did:web` is
 * documented as the future organization profile (it maps onto the S1 key
 * directory); out of scope for v1.
 */

export const DID_KEY_PREFIX = 'did:key:';
/** multicodec ed25519-pub = varint(0xed) = 0xed 0x01, then the 32 raw bytes. */
const ED25519_MULTICODEC = [0xed, 0x01] as const;
const ED25519_RAW_KEY_LENGTH = 32;
/** multibase prefix for base58btc. */
const MULTIBASE_BASE58BTC = 'z';

export function didKeyFromPublicKey(rawPublicKey: Uint8Array): string {
  if (rawPublicKey.length !== ED25519_RAW_KEY_LENGTH) {
    throw new Error(
      `did:key: Ed25519 public key must be ${ED25519_RAW_KEY_LENGTH} bytes, got ${rawPublicKey.length}`
    );
  }
  const prefixed = new Uint8Array(ED25519_MULTICODEC.length + rawPublicKey.length);
  prefixed.set(ED25519_MULTICODEC, 0);
  prefixed.set(rawPublicKey, ED25519_MULTICODEC.length);
  return `${DID_KEY_PREFIX}${MULTIBASE_BASE58BTC}${base58Encode(prefixed)}`;
}

export function isDidKey(did: string): boolean {
  return did.startsWith(`${DID_KEY_PREFIX}${MULTIBASE_BASE58BTC}`);
}

/**
 * Decode a did:key to the raw 32-byte Ed25519 public key. Throws on anything
 * that is not an Ed25519 did:key (R4: DIDs arrive from hostile inputs).
 */
export function publicKeyFromDidKey(did: string): Uint8Array {
  if (!did.startsWith(DID_KEY_PREFIX)) {
    throw new Error(`did:key: '${did.slice(0, 16)}…' is not a did:key`);
  }
  const multibase = did.slice(DID_KEY_PREFIX.length);
  if (!multibase.startsWith(MULTIBASE_BASE58BTC)) {
    throw new Error('did:key: v1 profile requires multibase base58btc (z…)');
  }
  const prefixed = base58Decode(multibase.slice(MULTIBASE_BASE58BTC.length));
  if (
    prefixed.length !== ED25519_MULTICODEC.length + ED25519_RAW_KEY_LENGTH ||
    prefixed[0] !== ED25519_MULTICODEC[0] ||
    prefixed[1] !== ED25519_MULTICODEC[1]
  ) {
    throw new Error('did:key: not an Ed25519 (multicodec 0xed01) key — v1 profile rejects it');
  }
  return prefixed.slice(ED25519_MULTICODEC.length);
}
