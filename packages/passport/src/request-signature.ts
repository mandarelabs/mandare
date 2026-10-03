import type { webcrypto } from 'node:crypto';

import {
  HTTP_MESSAGE_SIGNATURE_TAG,
  SIGNATURE_AGENT_HEADER,
  generateNonce,
  signatureHeaders,
  verify as webBotAuthVerify,
} from 'web-bot-auth';

import {
  keyIdFromRawPublicKey,
  rawPublicKeyFromJwk,
  signBytes,
  utf8Bytes,
  verifyBytes,
} from './keys.js';

/**
 * RFC 9421 HTTP Message Signatures for Mandare doors (Q3). Signing and
 * verification use the `web-bot-auth` npm package's RFC 9421 primitives and
 * its `web-bot-auth` tag. Interoperability with Web Bot Auth verifiers is NOT
 * claimed: `Signature-Agent` here is the agent's did:key as a bare string and
 * `keyid` is the sha256 hex of the raw public key, where the Web Bot Auth
 * draft requires a dictionary of https URIs and a JWK thumbprint.
 *
 * This upgrades S3's HMAC proof-of-possession tokens to the passport's
 * ASYMMETRIC agent key and closes S3's known gap (HIGH-1): the signature
 * covers a `Content-Digest` over the exact request body, so an intercepted
 * request can neither be replayed (single-use nonce, bounded created/expires
 * window) nor have its body swapped under a valid proof.
 *
 * Covered components (all REQUIRED on verify — a signature that covers less
 * is refused, because `web-bot-auth` itself accepts whatever Signature-Input
 * declares): @method, @path, @authority, content-digest, signature-agent.
 */

export const REQUIRED_COMPONENTS = [
  '@method',
  '@path',
  '@authority',
  'content-digest',
  SIGNATURE_AGENT_HEADER,
] as const;

export const PASSPORT_HEADER = 'x-mandare-passport';
export const CONTENT_DIGEST_HEADER = 'content-digest';
/** Max seconds a signature may declare between created and expires. */
export const MAX_SIGNATURE_LIFETIME_SECONDS = 300;
export const DEFAULT_SIGNATURE_TTL_SECONDS = 30;

/** Standard base64 (with padding) — the sf-binary form RFC 9530 uses. */
function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

/** RFC 9530 Content-Digest value over exact body bytes: sha-256=:base64:. */
export async function contentDigestHeaderValue(bodyBytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bodyBytes as webcrypto.BufferSource));
  return `sha-256=:${bytesToBase64(digest)}:`;
}

export interface SignRequestInput {
  method: string;
  /** Absolute URL of the request (authority + path are covered). */
  url: string;
  /** Exact body bytes that will be sent. */
  bodyBytes: Uint8Array;
  agentDid: string;
  agentPrivateJwk: webcrypto.JsonWebKey;
  agentPublicJwk: webcrypto.JsonWebKey;
  /** Compact delegation credential presented alongside the signature. */
  passport: string;
  ttlSeconds?: number;
  /** Injectable clock for tests. */
  nowMs?: number;
}

/**
 * Produce every header a Mandare door requires: the passport, the
 * signature-agent identity, the content digest, and the RFC 9421 signature
 * over all of it.
 */
export async function signMandareRequest(input: SignRequestInput): Promise<Record<string, string>> {
  const nowMs = input.nowMs ?? Date.now();
  const ttl = input.ttlSeconds ?? DEFAULT_SIGNATURE_TTL_SECONDS;
  const keyid = await keyIdFromRawPublicKey(rawPublicKeyFromJwk(input.agentPublicJwk));
  const baseHeaders: Record<string, string> = {
    [SIGNATURE_AGENT_HEADER]: `"${input.agentDid}"`,
    [CONTENT_DIGEST_HEADER]: await contentDigestHeaderValue(input.bodyBytes),
    [PASSPORT_HEADER]: input.passport,
  };
  const signed = await signatureHeaders(
    { method: input.method, url: input.url, headers: baseHeaders },
    {
      keyid,
      alg: 'ed25519',
      sign: async (data: string) => signBytes(input.agentPrivateJwk, utf8Bytes(data)),
    },
    {
      created: new Date(nowMs),
      expires: new Date(nowMs + ttl * 1000),
      nonce: generateNonce(),
      components: [...REQUIRED_COMPONENTS],
    }
  );
  return {
    ...baseHeaders,
    signature: signed.Signature,
    'signature-input': signed['Signature-Input'],
  };
}

/** Single-use nonce claims — the vault's nonce table in production. */
export interface NonceStore {
  /** Returns false if the key was already claimed (replay). */
  claim(key: string, expiresAtIso: string): boolean;
}

export class InMemoryNonceStore implements NonceStore {
  private readonly claimed = new Map<string, number>();

  claim(key: string, expiresAtIso: string): boolean {
    const now = Date.now();
    for (const [existing, expiry] of this.claimed) {
      if (expiry <= now) {
        this.claimed.delete(existing);
      }
    }
    if (this.claimed.has(key)) {
      return false;
    }
    this.claimed.set(key, Date.parse(expiresAtIso));
    return true;
  }
}

export type RequestSignatureRefusalCode =
  | 'MISSING_SIGNATURE'
  | 'MALFORMED_SIGNATURE'
  | 'COMPONENTS_NOT_COVERED'
  | 'BODY_DIGEST_MISMATCH'
  | 'WRONG_KEY'
  | 'BAD_SIGNATURE'
  | 'SIGNATURE_WINDOW_INVALID'
  | 'REPLAYED_NONCE'
  | 'SIGNATURE_AGENT_MISMATCH';

export class RequestSignatureError extends Error {
  readonly code: RequestSignatureRefusalCode;

  constructor(code: RequestSignatureRefusalCode, message: string) {
    super(message);
    this.name = 'RequestSignatureError';
    this.code = code;
  }
}

export interface VerifyRequestInput {
  method: string;
  /** Absolute URL the door received the request at. */
  url: string;
  /** Lower-cased header map as received. */
  headers: Record<string, string>;
  /** Exact body bytes as received. */
  bodyBytes: Uint8Array;
  /** The verified passport's confirmation key — the ONLY acceptable signer. */
  agentPublicJwk: webcrypto.JsonWebKey;
  /** The verified passport's agent DID — must match signature-agent. */
  agentDid: string;
  nonceStore: NonceStore;
}

export type CoveredComponents =
  | { ok: true; names: string[] }
  | { ok: false; reason: 'unparseable' | 'parametrized' };

/**
 * The covered-component names from a Signature-Input inner list.
 *
 * SECURITY: RFC 8941 inner-list members may carry parameters, and
 * `http-message-sig` includes only the actual member in the signature base —
 * so a header like `("@method";a="@path";b="content-digest")` covers ONLY
 * `@method` while a naive quoted-string scrape would "see" all three names as
 * covered. We must therefore parse the list structurally and REFUSE any
 * parameter inside it: Mandare's signer never emits parametrized components,
 * so a parameter here is either a coverage-spoofing attack or malformed. This
 * closes the decoy-parameter bypass (would otherwise silently reopen S3's
 * body-binding gap). Parameters AFTER the closing paren (created/expires/
 * keyid/nonce/tag) are the signature params and are not our concern here.
 */
export function coveredComponents(signatureInput: string): CoveredComponents {
  const match = /\(([^)]*)\)/.exec(signatureInput);
  if (match === null) {
    return { ok: false, reason: 'unparseable' };
  }
  const inner = match[1] as string;
  // Any parameter marker inside the list means a member carries parameters
  // (or a bare-key boolean param) — refuse, we never sign that shape.
  if (inner.includes(';')) {
    return { ok: false, reason: 'parametrized' };
  }
  // With no parameters, every member is a plain quoted component name.
  const names: string[] = [];
  const tokens = inner.trim().split(/\s+/).filter((token) => token.length > 0);
  for (const token of tokens) {
    const quoted = /^"([^"]+)"$/.exec(token);
    if (quoted === null) {
      return { ok: false, reason: 'unparseable' };
    }
    names.push(quoted[1] as string);
  }
  return { ok: true, names };
}

/**
 * Verify an inbound door request end to end. Throws RequestSignatureError
 * with a stable code on ANY failure (fail-closed); returns the signature
 * nonce on success. Order mirrors S3's token verify: cheap structural checks
 * → cryptographic verify → nonce claimed LAST (a bad probe cannot burn a
 * legitimate nonce).
 */
export async function verifyMandareRequest(input: VerifyRequestInput): Promise<{ nonce: string }> {
  const signatureInput = input.headers['signature-input'];
  const signature = input.headers.signature;
  if (signatureInput === undefined || signature === undefined) {
    throw new RequestSignatureError('MISSING_SIGNATURE', 'request carries no RFC 9421 signature');
  }

  const covered = coveredComponents(signatureInput);
  if (!covered.ok) {
    if (covered.reason === 'parametrized') {
      throw new RequestSignatureError(
        'COMPONENTS_NOT_COVERED',
        'Signature-Input covers parametrized components — refusing (a parameter can hide a required component as a decoy value)'
      );
    }
    throw new RequestSignatureError('MALFORMED_SIGNATURE', 'Signature-Input is not parseable');
  }
  for (const component of REQUIRED_COMPONENTS) {
    if (!covered.names.includes(component)) {
      throw new RequestSignatureError(
        'COMPONENTS_NOT_COVERED',
        `signature does not cover required component '${component}' — refusing (a narrower signature binds nothing)`
      );
    }
  }

  const expectedAgent = `"${input.agentDid}"`;
  if (input.headers[SIGNATURE_AGENT_HEADER] !== expectedAgent) {
    throw new RequestSignatureError(
      'SIGNATURE_AGENT_MISMATCH',
      'signature-agent header does not name the passport agent'
    );
  }

  const expectedDigest = await contentDigestHeaderValue(input.bodyBytes);
  if (input.headers[CONTENT_DIGEST_HEADER] !== expectedDigest) {
    throw new RequestSignatureError(
      'BODY_DIGEST_MISMATCH',
      'content-digest does not match the received body — body swap refused'
    );
  }

  const expectedKeyId = await keyIdFromRawPublicKey(rawPublicKeyFromJwk(input.agentPublicJwk));
  let verifiedNonce: string | undefined;
  let verifiedExpires: Date | undefined;
  try {
    await webBotAuthVerify(
      { method: input.method, url: input.url, headers: input.headers },
      async (data, sig, params) => {
        if (params.tag !== HTTP_MESSAGE_SIGNATURE_TAG) {
          throw new RequestSignatureError('MALFORMED_SIGNATURE', 'unexpected signature tag');
        }
        if (params.keyid !== expectedKeyId) {
          throw new RequestSignatureError(
            'WRONG_KEY',
            'signature key is not the passport confirmation key'
          );
        }
        const lifetimeSeconds = (params.expires.getTime() - params.created.getTime()) / 1000;
        if (lifetimeSeconds <= 0 || lifetimeSeconds > MAX_SIGNATURE_LIFETIME_SECONDS) {
          throw new RequestSignatureError(
            'SIGNATURE_WINDOW_INVALID',
            `signature validity window must be within (0, ${MAX_SIGNATURE_LIFETIME_SECONDS}]s`
          );
        }
        if (typeof params.nonce !== 'string' || params.nonce.length === 0) {
          throw new RequestSignatureError('MALFORMED_SIGNATURE', 'signature carries no nonce');
        }
        const ok = await verifyBytes(input.agentPublicJwk, utf8Bytes(data), sig);
        if (!ok) {
          throw new RequestSignatureError(
            'BAD_SIGNATURE',
            'request signature does not verify against the passport key'
          );
        }
        verifiedNonce = params.nonce;
        verifiedExpires = params.expires;
      }
    );
  } catch (error) {
    if (error instanceof RequestSignatureError) {
      throw error;
    }
    // web-bot-auth's own refusals (expired, created-in-future, header parse).
    throw new RequestSignatureError(
      'MALFORMED_SIGNATURE',
      `signature rejected: ${error instanceof Error ? error.message : String(error)}`
    );
  }
  if (verifiedNonce === undefined || verifiedExpires === undefined) {
    throw new RequestSignatureError('MALFORMED_SIGNATURE', 'signature verification did not complete');
  }

  // Nonce claimed only AFTER the proof verified; retained past expiry so a
  // captured request outlives every instant it could still pass (S3 lesson).
  const NONCE_RETENTION_MARGIN_MS = 5_000;
  const retainUntil = new Date(verifiedExpires.getTime() + NONCE_RETENTION_MARGIN_MS).toISOString();
  if (!input.nonceStore.claim(`9421:${expectedKeyId}:${verifiedNonce}`, retainUntil)) {
    throw new RequestSignatureError('REPLAYED_NONCE', 'this signature was already used — replay refused');
  }
  return { nonce: verifiedNonce };
}
