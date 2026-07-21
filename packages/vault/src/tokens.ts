import { seal, open, generatePopSecret, hmacSha256, randomId, constantTimeEqual } from './crypto.js';
import type { VaultStore } from './store.js';

/**
 * Short-lived, proof-of-possession scoped tokens (SPEC §3.1: the vault "mints
 * short-lived scoped tokens (5–30 min)"). This is what an AGENT presents to a
 * door — never a raw provider key.
 *
 * WHY A STOLEN TOKEN IS DEAD PAPER. A token is a public id plus a per-token
 * secret `k`. Each request carries an HMAC(k, tokenId|method|path|timestamp|
 * nonce) proof. Leaking the token id alone (a log line, an LLM context) buys
 * nothing without `k` — the proof cannot be forged (POSSESSION). A captured
 * signed request cannot be replayed: its nonce is single-use and its timestamp
 * goes stale within seconds (REPLAY). And the whole token dies on TTL expiry
 * or a `mandare kill` (TTL / REVOCATION). Full-credential theft (id AND k) is
 * bounded by the ≤30-min TTL and by kill — an honest residual.
 *
 * SCOPE (honest residual): the proof binds POSSESSION and anti-REPLAY, NOT the
 * request BODY — the preimage covers method/path/timestamp/nonce but not the
 * payload, so an attacker who can intercept the agent→door channel could swap
 * the body under a valid proof. On the loopback-by-default door that requires
 * privileged local interception (a far larger compromise), so it is out of
 * scope for S3. S4 closes it: the passport's non-exportable agent key replaces
 * this HMAC `k` and RFC 9421 adds a Content-Digest over the body. This preimage
 * is the deliberate precursor to that signature.
 */

/** The ≤30-min ceiling is a SPEC invariant, not a tuning knob. */
export const MAX_TOKEN_TTL_SECONDS = 30 * 60;
export const DEFAULT_TOKEN_TTL_SECONDS = 15 * 60;
/** How far a request timestamp may drift before it is stale (anti-replay). */
export const MAX_REQUEST_SKEW_SECONDS = 120;

export interface IssueTokenInput {
  actor: string;
  mandateId: string;
  ttlSeconds?: number;
}

/** Returned ONCE at mint time; `popSecret` is revealed here and never again. */
export interface ScopedTokenGrant {
  tokenId: string;
  popSecret: string;
  actor: string;
  mandateId: string;
  issuedAt: string;
  expiresAt: string;
}

export interface RequestClaims {
  tokenId: string;
  method: string;
  path: string;
  /** ISO-8601 UTC timestamp the client stamped and signed. */
  timestamp: string;
  nonce: string;
  /** base64url HMAC proof of possession. */
  pop: string;
}

export interface VerifiedRequest {
  actor: string;
  mandateId: string;
  tokenId: string;
}

export type TokenRefusalCode =
  | 'MALFORMED_REQUEST'
  | 'UNKNOWN_TOKEN'
  | 'TOKEN_REVOKED'
  | 'TOKEN_EXPIRED'
  | 'STALE_REQUEST'
  | 'REPLAYED_NONCE'
  | 'BAD_POP';

export interface TokenRefusal {
  code: TokenRefusalCode;
  reason: string;
}

export type VerifyResult =
  | { ok: true; verified: VerifiedRequest }
  | { ok: false; refusal: TokenRefusal };

/** The exact bytes a client HMACs — one canonical preimage, both sides. */
export function popPreimage(claims: {
  tokenId: string;
  method: string;
  path: string;
  timestamp: string;
  nonce: string;
}): string {
  return [claims.tokenId, claims.method.toUpperCase(), claims.path, claims.timestamp, claims.nonce].join(
    '\n'
  );
}

function tokenAad(tokenId: string): string {
  return `token:${tokenId}`;
}

/** Opportunistically prune expired tokens/nonces every N verifications. */
const PRUNE_EVERY_N_VERIFIES = 256;

export class TokenService {
  private readonly store: VaultStore;
  private readonly masterKey: Buffer;
  private readonly clock: () => Date;
  private verifyCount = 0;

  constructor(store: VaultStore, masterKey: Buffer, clock: () => Date = () => new Date()) {
    this.store = store;
    this.masterKey = masterKey;
    this.clock = clock;
  }

  issue(input: IssueTokenInput): ScopedTokenGrant {
    const ttl = input.ttlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS;
    if (!Number.isFinite(ttl) || ttl <= 0 || ttl > MAX_TOKEN_TTL_SECONDS) {
      throw new Error(
        `vault: token TTL must be in (0, ${MAX_TOKEN_TTL_SECONDS}] seconds (SPEC caps scoped tokens at 30 min)`
      );
    }
    const now = this.clock();
    const tokenId = randomId();
    const popSecret = generatePopSecret();
    const issuedAt = now.toISOString();
    const expiresAt = new Date(now.getTime() + ttl * 1000).toISOString();
    this.store.putToken({
      tokenId,
      actor: input.actor,
      mandateId: input.mandateId,
      popCiphertext: seal(this.masterKey, tokenAad(tokenId), popSecret),
      issuedAt,
      expiresAt,
      revoked: false,
    });
    return { tokenId, popSecret, actor: input.actor, mandateId: input.mandateId, issuedAt, expiresAt };
  }

  verify(claims: RequestClaims): VerifyResult {
    // Opportunistic cleanup keeps the nonce/token tables from growing without
    // bound; it never removes a nonce that could still be replayed (see the
    // 2×-skew retention in claimNonce below).
    this.verifyCount += 1;
    if (this.verifyCount % PRUNE_EVERY_N_VERIFIES === 0) {
      this.prune();
    }
    if (
      !isNonEmptyString(claims.tokenId) ||
      !isNonEmptyString(claims.timestamp) ||
      !isNonEmptyString(claims.nonce) ||
      !isNonEmptyString(claims.pop) ||
      !isNonEmptyString(claims.method) ||
      !isNonEmptyString(claims.path)
    ) {
      return refuse('MALFORMED_REQUEST', 'token request is missing required proof fields');
    }
    const token = this.store.getToken(claims.tokenId);
    if (token === null) {
      return refuse('UNKNOWN_TOKEN', 'no such token — the vault never minted it, or it was pruned');
    }
    if (token.revoked) {
      return refuse('TOKEN_REVOKED', 'token has been revoked (killed) — the vault refuses to honor it');
    }
    const now = this.clock().getTime();
    if (now >= Date.parse(token.expiresAt)) {
      return refuse('TOKEN_EXPIRED', `token expired at ${token.expiresAt}`);
    }
    const stamped = Date.parse(claims.timestamp);
    if (Number.isNaN(stamped)) {
      return refuse('MALFORMED_REQUEST', 'request timestamp is not a valid instant');
    }
    if (Math.abs(now - stamped) > MAX_REQUEST_SKEW_SECONDS * 1000) {
      return refuse(
        'STALE_REQUEST',
        `request timestamp is outside the ±${MAX_REQUEST_SKEW_SECONDS}s freshness window — replay refused`
      );
    }
    // Verify the proof BEFORE burning the nonce, so a bad-PoP probe cannot
    // consume a legitimate client's future nonce.
    const popSecret = this.decryptPop(token.popCiphertext, claims.tokenId);
    const expected = hmacSha256(
      popSecret,
      popPreimage({
        tokenId: claims.tokenId,
        method: claims.method,
        path: claims.path,
        timestamp: claims.timestamp,
        nonce: claims.nonce,
      })
    );
    if (!constantTimeEqual(expected, claims.pop)) {
      return refuse('BAD_POP', 'proof of possession does not match — token id without its secret is dead paper');
    }
    // Single-use: claim the nonce only after the proof checks out. Retain it
    // for 2× the skew window (plus a margin) so it OUTLIVES every instant at
    // which a captured proof could still pass the freshness gate — a nonce
    // must never be pruned while a replay of it would still be considered
    // fresh (a client stamp up to +120s ahead stays fresh until +240s).
    const nonceExpiry = new Date(now + (2 * MAX_REQUEST_SKEW_SECONDS + 5) * 1000).toISOString();
    if (!this.store.claimNonce(nonceKey(claims.tokenId, claims.nonce), nonceExpiry)) {
      return refuse('REPLAYED_NONCE', 'this proof was already used once — replay refused');
    }
    return {
      ok: true,
      verified: { actor: token.actor, mandateId: token.mandateId, tokenId: token.tokenId },
    };
  }

  revokeActor(actor: string): number {
    return this.store.revokeActorTokens(actor);
  }

  revokeAll(): number {
    return this.store.revokeAllTokens();
  }

  /** Opportunistic cleanup of expired tokens and nonces. */
  prune(): void {
    const nowIso = this.clock().toISOString();
    this.store.deleteExpiredTokens(nowIso);
    this.store.pruneNonces(nowIso);
  }

  private decryptPop(ciphertext: string, tokenId: string): string {
    return open(this.masterKey, tokenAad(tokenId), ciphertext);
  }
}

function nonceKey(tokenId: string, nonce: string): string {
  return `${tokenId}:${nonce}`;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function refuse(code: TokenRefusalCode, reason: string): VerifyResult {
  return { ok: false, refusal: { code, reason } };
}
