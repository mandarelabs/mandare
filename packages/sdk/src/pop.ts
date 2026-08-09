/**
 * Client side of the vault's proof-of-possession scoped tokens (S3).
 *
 * WIRE CONTRACT (shared with `@mandarelabs/vault`, which is AGPL and
 * therefore re-stated here rather than imported): the agent presents four
 * headers; the proof is HMAC-SHA256 over a newline-joined preimage, keyed by
 * the per-token secret revealed once at mint time, base64url-encoded.
 * `packages/gateway` carries the cross-implementation parity test — any drift
 * between this file and the vault's verify side fails CI there.
 *
 * Implemented on WebCrypto only, like every embeddable Mandare package.
 */

export const TOKEN_HEADER = 'x-mandare-token';
export const TIMESTAMP_HEADER = 'x-mandare-timestamp';
export const NONCE_HEADER = 'x-mandare-nonce';
export const POP_HEADER = 'x-mandare-pop';

const encoder = new TextEncoder();

export interface TokenCredentials {
  /** Public token id (`mandare token issue` → `token_id`). */
  tokenId: string;
  /** Per-token secret revealed ONCE at mint time (`pop_secret`). */
  popSecret: string;
}

export interface PopClaims {
  tokenId: string;
  method: string;
  /** Request path WITHOUT the query string — both sides sign the same bytes. */
  path: string;
  /** ISO-8601 UTC timestamp; the door refuses stale ones (anti-replay). */
  timestamp: string;
  /** Single-use per token — the door refuses a reused nonce (anti-replay). */
  nonce: string;
}

/** The exact bytes the client HMACs — one canonical preimage, both sides. */
export function popPreimage(claims: PopClaims): string {
  return [
    claims.tokenId,
    claims.method.toUpperCase(),
    claims.path,
    claims.timestamp,
    claims.nonce,
  ].join('\n');
}

function base64UrlFromBytes(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function randomNonce(): string {
  const bytes = new Uint8Array(18);
  crypto.getRandomValues(bytes);
  return base64UrlFromBytes(bytes);
}

/** HMAC-SHA256(popSecret, preimage), base64url — the vault's exact encoding. */
export async function popProof(popSecret: string, claims: PopClaims): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(popSecret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(popPreimage(claims)));
  return base64UrlFromBytes(new Uint8Array(signature));
}

export interface TokenAuthInput {
  credentials: TokenCredentials;
  method: string;
  /** Path of the request; a query string, if any, is stripped before signing. */
  path: string;
  /** Injectable for tests; defaults to a fresh random nonce. */
  nonce?: string;
  /** Injectable for tests; defaults to now. */
  timestamp?: string;
}

/** The four headers a Mandare door requires in token auth mode. */
export async function tokenAuthHeaders(input: TokenAuthInput): Promise<Record<string, string>> {
  const claims: PopClaims = {
    tokenId: input.credentials.tokenId,
    method: input.method,
    path: input.path.split('?')[0] ?? '',
    timestamp: input.timestamp ?? new Date().toISOString(),
    nonce: input.nonce ?? randomNonce(),
  };
  return {
    [TOKEN_HEADER]: claims.tokenId,
    [TIMESTAMP_HEADER]: claims.timestamp,
    [NONCE_HEADER]: claims.nonce,
    [POP_HEADER]: await popProof(input.credentials.popSecret, claims),
  };
}
