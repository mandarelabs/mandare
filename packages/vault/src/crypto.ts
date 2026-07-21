import {
  createHmac,
  randomBytes,
  timingSafeEqual,
  createCipheriv,
  createDecipheriv,
} from 'node:crypto';

/**
 * Envelope encryption for at-rest secret storage (SPEC §3.1: "Storage
 * encrypted at rest; keys in OS keychain/KMS"). Every secret value in the
 * vault DB is ciphertext; the 32-byte master key that decrypts it lives in
 * the OS keychain (or, for headless mode, an explicit 0600 file). A leaked
 * vault DB file is inert without the master key.
 *
 * R2: this module is the ONLY place raw secret bytes are handled; callers
 * pass and receive opaque blobs.
 */

const IV_BYTES = 12; // GCM standard nonce length.
const TAG_BYTES = 16;
const KEY_BYTES = 32; // AES-256.
export const MASTER_KEY_BYTES = KEY_BYTES;

/**
 * AES-256-GCM encrypt. The `aad` (the secret's account name) is authenticated
 * but not encrypted — it binds each ciphertext to its slot so a DB-file
 * attacker cannot move a provider key's ciphertext into the door-key slot.
 * Returns `base64url(iv || ciphertext || tag)`.
 */
export function seal(masterKey: Buffer, aad: string, plaintext: string): string {
  assertMasterKey(masterKey);
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', masterKey, iv);
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, ciphertext, tag]).toString('base64url');
}

/** Reverse of {@link seal}. Throws on a wrong key, tampered blob, or wrong aad. */
export function open(masterKey: Buffer, aad: string, blob: string): string {
  assertMasterKey(masterKey);
  const bytes = Buffer.from(blob, 'base64url');
  if (bytes.length < IV_BYTES + TAG_BYTES) {
    throw new Error('vault: ciphertext is too short to be valid');
  }
  const iv = bytes.subarray(0, IV_BYTES);
  const tag = bytes.subarray(bytes.length - TAG_BYTES);
  const ciphertext = bytes.subarray(IV_BYTES, bytes.length - TAG_BYTES);
  const decipher = createDecipheriv('aes-256-gcm', masterKey, iv);
  decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

function assertMasterKey(masterKey: Buffer): void {
  if (masterKey.length !== KEY_BYTES) {
    throw new Error(`vault: master key must be ${KEY_BYTES} bytes, got ${masterKey.length}`);
  }
}

/** A fresh 32-byte master key. */
export function generateMasterKey(): Buffer {
  return randomBytes(KEY_BYTES);
}

/** A fresh per-token proof-of-possession secret (32 bytes, base64url). */
export function generatePopSecret(): string {
  return randomBytes(32).toString('base64url');
}

/** Random opaque identifier (token ids, nonces). */
export function randomId(bytes = 18): string {
  return randomBytes(bytes).toString('base64url');
}

/** HMAC-SHA256 → base64url, the proof-of-possession primitive (S3 precursor to RFC 9421). */
export function hmacSha256(secret: string, message: string): string {
  return createHmac('sha256', secret).update(message, 'utf8').digest('base64url');
}

/** Constant-time string compare — never leak a match via timing on token/PoP checks. */
export function constantTimeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) {
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}
