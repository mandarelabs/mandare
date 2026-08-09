import { signMandareRequest } from '@mandarelabs/passport';
import type { webcrypto } from 'node:crypto';

import { tokenAuthHeaders, type TokenCredentials } from './pop.js';

/**
 * The adoption path: keep your existing Anthropic/OpenAI SDK, hand it a
 * Mandare-signed `fetch`. Every request leaving it carries the door's
 * required auth headers:
 *
 * - `none`     — pass-through (door in `none`/unauthenticated dev mode).
 * - `token`    — S3 proof-of-possession scoped token (four x-mandare-* headers).
 * - `passport` — S4 RFC 9421 request signature under the passport's agent
 *                key, incl. Content-Digest over the exact body bytes.
 *
 * The wrapper never buffers streams it cannot re-send and never guesses at
 * body bytes: a request whose body it cannot read exactly is REFUSED before
 * it leaves (fail closed) rather than sent unsigned to be refused by the
 * door — same outcome, clearer error, no half-signed traffic.
 */

export type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export interface PassportIdentity {
  /** Compact SD-JWT delegation credential (`mandare passport issue` output file). */
  credential: string;
  /** The agent's did:key. */
  agentDid: string;
  /** The agent key pair (`--agent-key-out` file: `{ privateJwk, publicJwk }`). */
  privateJwk: webcrypto.JsonWebKey;
  publicJwk: webcrypto.JsonWebKey;
}

export type MandareAuth =
  | { mode: 'none' }
  | { mode: 'token'; credentials: TokenCredentials }
  | { mode: 'passport'; identity: PassportIdentity };

export interface MandareFetchOptions {
  auth: MandareAuth;
  /** Underlying fetch; defaults to global fetch. */
  fetch?: FetchLike;
}

/** Body bytes exactly as fetch would send them, or null when there is no body. */
async function exactBodyBytes(input: string | URL | Request, init?: RequestInit): Promise<Uint8Array | null> {
  const body = init?.body;
  if (body !== undefined && body !== null) {
    if (typeof body === 'string') {
      return new TextEncoder().encode(body);
    }
    if (body instanceof Uint8Array) {
      return new Uint8Array(body);
    }
    if (body instanceof ArrayBuffer) {
      return new Uint8Array(body);
    }
    if (body instanceof URLSearchParams) {
      return new TextEncoder().encode(body.toString());
    }
    throw new Error(
      'mandare fetch: cannot sign this body type exactly (stream/FormData/Blob) — ' +
        'pass a string, Uint8Array, or ArrayBuffer so the signed digest matches the sent bytes'
    );
  }
  if (input instanceof Request) {
    if (input.body === null) {
      return null;
    }
    // Cloning keeps the original sendable; arrayBuffer() gives the exact bytes.
    return new Uint8Array(await input.clone().arrayBuffer());
  }
  return null;
}

function requestUrl(input: string | URL | Request): URL {
  if (input instanceof Request) {
    return new URL(input.url);
  }
  return input instanceof URL ? new URL(input.href) : new URL(input);
}

function requestMethod(input: string | URL | Request, init?: RequestInit): string {
  if (init?.method !== undefined) {
    return init.method.toUpperCase();
  }
  if (input instanceof Request) {
    return input.method.toUpperCase();
  }
  return 'GET';
}

function mergedHeaders(
  input: string | URL | Request,
  init: RequestInit | undefined,
  authHeaders: Record<string, string>
): Headers {
  const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
  for (const [name, value] of Object.entries(authHeaders)) {
    headers.set(name, value);
  }
  return headers;
}

/**
 * Wrap a fetch so every request is authenticated for a Mandare door. Works as
 * the `fetch` option of the official Anthropic/OpenAI SDK constructors and as
 * a drop-in for direct calls.
 */
export function createMandareFetch(options: MandareFetchOptions): FetchLike {
  const baseFetch: FetchLike = options.fetch ?? fetch;
  const auth = options.auth;
  if (auth.mode === 'none') {
    return baseFetch;
  }

  return async (input, init) => {
    const url = requestUrl(input);
    const method = requestMethod(input, init);

    let authHeaders: Record<string, string>;
    if (auth.mode === 'token') {
      authHeaders = await tokenAuthHeaders({
        credentials: auth.credentials,
        method,
        path: url.pathname,
      });
    } else {
      const bodyBytes = (await exactBodyBytes(input, init)) ?? new Uint8Array(0);
      authHeaders = await signMandareRequest({
        method,
        url: url.href,
        bodyBytes,
        agentDid: auth.identity.agentDid,
        agentPrivateJwk: auth.identity.privateJwk,
        agentPublicJwk: auth.identity.publicJwk,
        passport: auth.identity.credential,
      });
    }

    const headers = mergedHeaders(input, init, authHeaders);
    if (input instanceof Request && init === undefined) {
      // Re-issue the request with the auth headers attached; body is re-read
      // from the clone-safe original.
      const bodyBytes = await exactBodyBytes(input, undefined);
      return baseFetch(url.href, {
        method,
        headers,
        ...(bodyBytes === null ? {} : { body: bodyBytes as NonNullable<RequestInit['body']> }),
      });
    }
    return baseFetch(input, { ...init, headers });
  };
}
