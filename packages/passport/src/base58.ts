/**
 * base58btc (Bitcoin alphabet) — the multibase encoding did:key uses.
 * Hand-rolled (~40 lines) rather than a dependency: the alphabet is fixed,
 * the inputs are 34-byte key blobs, and the supply-chain posture (Q24)
 * prefers auditable lines over another package.
 */

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE = 58n;

const CHAR_INDEX = new Map<string, number>([...ALPHABET].map((char, index) => [char, index]));

export function base58Encode(bytes: Uint8Array): string {
  let value = 0n;
  for (const byte of bytes) {
    value = value * 256n + BigInt(byte);
  }
  let encoded = '';
  while (value > 0n) {
    encoded = ALPHABET[Number(value % BASE)] + encoded;
    value /= BASE;
  }
  // Leading zero bytes encode as leading '1's (base58btc convention).
  for (const byte of bytes) {
    if (byte !== 0) {
      break;
    }
    encoded = `1${encoded}`;
  }
  return encoded;
}

export function base58Decode(text: string): Uint8Array {
  let value = 0n;
  for (const char of text) {
    const index = CHAR_INDEX.get(char);
    if (index === undefined) {
      throw new Error(`base58: invalid character '${char}'`);
    }
    value = value * BASE + BigInt(index);
  }
  const bytes: number[] = [];
  while (value > 0n) {
    bytes.unshift(Number(value % 256n));
    value /= 256n;
  }
  for (const char of text) {
    if (char !== '1') {
      break;
    }
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}
