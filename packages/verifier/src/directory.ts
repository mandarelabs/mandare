import { base64UrlToBytes, bytesToHex, sha256HexAsync } from '@mandarelabs/spec';

/**
 * Mandare key directory (SPEC §4) — the out-of-band anchor that closes review
 * finding H1: `meta.door_public_key` inside a ledger file can be swapped by a
 * file-level attacker, so authorship must be proven against keys obtained
 * INDEPENDENTLY of the file.
 *
 * ONE directory format for the whole system: a JWK Set (RFC 7517), profiled
 * for RFC 9421 HTTP Message Signatures the way the Web Bot Auth key-directory
 * draft does (`/.well-known/http-message-signatures-directory`,
 * draft-meunier-web-bot-auth). Door keys ship in it today; agent passport
 * keys (S4) go into the SAME structure — never a door-only format.
 *
 * Profile:
 * - `keys[]` are standard JWKs. Mandare consumes `OKP`/`Ed25519` keys and
 *   skips other key types (standard JWKS must-ignore semantics).
 * - Per-key validity uses `nbf`/`exp` (NumericDate seconds), as in the Web
 *   Bot Auth directory draft. A key only vouches for entries whose `ts`
 *   falls inside its window — this is what makes rotation meaningful: a
 *   rotated-out (possibly stolen) key cannot sign new history.
 * - `kid` SHOULD be the RFC 7638 JWK thumbprint (base64url). Ledger entries
 *   are matched by `door_signature.key_id` = sha256 hex of the raw 32-byte
 *   public key, which is DERIVED from `x` — the directory needs no
 *   Mandare-specific id field.
 * - `mnd:role` ('door' | 'agent') is a private-use extension member
 *   (RFC 7517 §4 allows them); consumers that don't know it ignore it.
 */

export class DirectoryParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DirectoryParseError';
  }
}

/** A resolved Ed25519 verification key from a key directory. */
export interface DirectoryKey {
  /** sha256 hex of the raw 32-byte public key — matches entry `door_signature.key_id`. */
  keyId: string;
  /** Raw 32-byte Ed25519 public key. */
  publicKey: Uint8Array;
  /** Published JWK `kid`, if any (SHOULD be the RFC 7638 thumbprint). */
  kid?: string;
  /** Validity window start, epoch seconds (JWK `nbf`). */
  notBefore?: number;
  /** Validity window end, epoch seconds (JWK `exp`). */
  notAfter?: number;
  /** `mnd:role` extension: 'door' | 'agent' (free-form for forward compat). */
  role?: string;
}

export interface KeyDirectory {
  keys: DirectoryKey[];
}

const ED25519_KEY_BYTES = 32;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function optionalNumber(
  jwk: Record<string, unknown>,
  field: string,
  index: number
): number | undefined {
  const value = jwk[field];
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new DirectoryParseError(`keys[${index}].${field} must be a NumericDate (seconds)`);
  }
  return value;
}

function optionalString(
  jwk: Record<string, unknown>,
  field: string,
  index: number
): string | undefined {
  const value = jwk[field];
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'string') {
    throw new DirectoryParseError(`keys[${index}].${field} must be a string`);
  }
  return value;
}

/**
 * Parse and validate a key directory document (already JSON-parsed). Hostile
 * input dies here (rule R4): structural garbage throws DirectoryParseError;
 * non-Ed25519 keys are skipped per JWKS must-ignore semantics.
 */
export async function parseKeyDirectory(raw: unknown): Promise<KeyDirectory> {
  if (!isRecord(raw) || !Array.isArray(raw.keys)) {
    throw new DirectoryParseError('key directory must be a JWK Set: { "keys": [...] }');
  }
  const keys: DirectoryKey[] = [];
  for (const [index, jwkRaw] of raw.keys.entries()) {
    if (!isRecord(jwkRaw)) {
      throw new DirectoryParseError(`keys[${index}] is not an object`);
    }
    if (jwkRaw.kty !== 'OKP' || jwkRaw.crv !== 'Ed25519') {
      continue; // other key types are legal in a shared JWKS; not ours to judge
    }
    if (typeof jwkRaw.x !== 'string') {
      throw new DirectoryParseError(`keys[${index}]: OKP/Ed25519 key is missing string member "x"`);
    }
    let publicKey: Uint8Array;
    try {
      publicKey = base64UrlToBytes(jwkRaw.x);
    } catch {
      throw new DirectoryParseError(`keys[${index}].x is not valid base64url`);
    }
    if (publicKey.length !== ED25519_KEY_BYTES) {
      throw new DirectoryParseError(
        `keys[${index}].x decodes to ${publicKey.length} bytes, expected ${ED25519_KEY_BYTES}`
      );
    }
    const notBefore = optionalNumber(jwkRaw, 'nbf', index);
    const notAfter = optionalNumber(jwkRaw, 'exp', index);
    if (notBefore !== undefined && notAfter !== undefined && notAfter <= notBefore) {
      throw new DirectoryParseError(`keys[${index}]: exp must be after nbf`);
    }
    const kid = optionalString(jwkRaw, 'kid', index);
    const role = optionalString(jwkRaw, 'mnd:role', index);
    const keyId = await sha256HexAsync(publicKey);
    // Reject duplicates (review S1-M2): resolution is a keyId → key map, so
    // a second listing of the same key — e.g. with a wider validity window —
    // would silently override the first. Ambiguity dies loudly instead.
    if (keys.some((existing) => existing.keyId === keyId)) {
      throw new DirectoryParseError(
        `keys[${index}] duplicates key ${keyId.slice(0, 12)}… — one entry per key`
      );
    }
    keys.push({
      keyId,
      publicKey,
      ...(kid === undefined ? {} : { kid }),
      ...(notBefore === undefined ? {} : { notBefore }),
      ...(notAfter === undefined ? {} : { notAfter }),
      ...(role === undefined ? {} : { role }),
    });
  }
  if (keys.length === 0) {
    throw new DirectoryParseError('key directory contains no Ed25519 keys');
  }
  return { keys };
}

/** Build an in-memory directory from raw public keys (testing / single-key flows). */
export async function directoryFromPublicKeys(
  publicKeys: readonly (Uint8Array | string)[]
): Promise<KeyDirectory> {
  const keys = await Promise.all(
    publicKeys.map(async (key) => {
      const bytes = typeof key === 'string' ? hexToBytesStrict(key) : key;
      return { keyId: await sha256HexAsync(bytes), publicKey: bytes };
    })
  );
  return { keys };
}

function hexToBytesStrict(hex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new DirectoryParseError('public key hex must be 64 lowercase hex chars');
  }
  const bytes = new Uint8Array(ED25519_KEY_BYTES);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Debug/display helper: hex public keys in the directory, by keyId prefix. */
export function describeDirectory(directory: KeyDirectory): string[] {
  return directory.keys.map(
    (key) =>
      `${key.keyId.slice(0, 12)}… ${bytesToHex(key.publicKey).slice(0, 16)}…` +
      `${key.role === undefined ? '' : ` role=${key.role}`}` +
      `${key.notAfter === undefined ? '' : ` exp=${key.notAfter}`}`
  );
}
