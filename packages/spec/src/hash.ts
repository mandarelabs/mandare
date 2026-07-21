import { canonicalJson } from './canonical.js';
import type { LedgerEntryPreimage } from './ledger-entry.js';

/**
 * Portable (WebCrypto) hashing — usable in Node, browsers, and edge runtimes.
 * The Node-native synchronous variants live in `hash-node.js`; both MUST
 * produce identical output (asserted by tests).
 */

/** prev_hash of the first entry in every chain: 64 zero hex chars. */
export const GENESIS_PREV_HASH = '0'.repeat(64);

const encoder = new TextEncoder();

export async function sha256HexAsync(data: string | Uint8Array): Promise<string> {
  const bytes = typeof data === 'string' ? encoder.encode(data) : data;
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>);
  return bytesToHex(new Uint8Array(digest));
}

/**
 * The frozen hash-input rule (SPEC §6): the entry hash covers the canonical
 * JSON of the entry WITHOUT `entry_hash` and `door_signature`.
 */
export async function computeEntryHashAsync(preimage: LedgerEntryPreimage): Promise<string> {
  return sha256HexAsync(canonicalJson(preimage));
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, '0');
  }
  return hex;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || /[^0-9a-f]/.test(hex)) {
    throw new TypeError('expected lowercase hex string of even length');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** base64url without padding (RFC 4648 §5) — signature encoding for SignatureBlock.value. */
export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export function base64UrlToBytes(value: string): Uint8Array {
  if (/[^A-Za-z0-9_-]/.test(value)) {
    throw new TypeError('expected base64url without padding');
  }
  const base64 = value.replaceAll('-', '+').replaceAll('_', '/');
  const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
