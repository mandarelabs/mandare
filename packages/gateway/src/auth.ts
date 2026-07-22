import type { FastifyRequest } from 'fastify';

import type { RequestClaims, VerifyResult } from '@mandarelabs/vault';

import type { GatewayConfig } from './config.js';

/**
 * Door-local authentication for the spend routes (S3). Two cheap defenses the
 * S2 review asked for, plus the real one:
 *
 * - **Host allowlist** — a DNS-rebinding guard. The gateway is a LOCAL door;
 *   a browser tricked into POSTing to a rebound hostname must be rejected
 *   before any spend work.
 * - **Proof-of-possession token** — the caller proves it holds the per-token
 *   secret the vault minted (see @mandarelabs/vault). A leaked token id is
 *   dead paper without it.
 *
 * This is authentication of an authorized *holder*, not yet full actor
 * identity — that is S4's passport work. The boundary is explicit.
 */

export const TOKEN_HEADER = 'x-mandare-token';
export const TIMESTAMP_HEADER = 'x-mandare-timestamp';
export const NONCE_HEADER = 'x-mandare-nonce';
export const POP_HEADER = 'x-mandare-pop';

/** The narrow slice of the vault the gateway calls for auth. */
export interface GatewayVault {
  verifyRequest(claims: RequestClaims): VerifyResult;
}

/**
 * localhost forms are always allowed — this is a local door by design. Note
 * the Host allowlist is a DNS-rebinding defense against BROWSERS, not an auth
 * boundary against direct clients (which control the Host header): binding the
 * door to a non-loopback address without token auth is unsafe regardless (see
 * the startup guard in start.ts).
 */
const DEFAULT_ALLOWED_HOSTS = ['127.0.0.1', 'localhost', '::1', '[::1]'];

export function buildAllowedHosts(config: GatewayConfig): Set<string> {
  const hosts = new Set(DEFAULT_ALLOWED_HOSTS);
  hosts.add(config.host.toLowerCase());
  for (const host of config.allowedHosts) {
    hosts.add(host);
  }
  // The operator-declared public base URL (approval buttons, forwarded
  // Stripe webhooks) is by definition a name this door expects to be
  // reached under — allow it automatically, or every webhook behind a real
  // hostname 403s into the Stripe dashboard timeout default (a silent,
  // fail-closed outage of the card rail; review S5 LOW-4).
  if (config.publicBaseUrl !== null) {
    try {
      hosts.add(new URL(config.publicBaseUrl).hostname.toLowerCase());
    } catch {
      // An unparseable publicBaseUrl adds nothing (fail-closed).
    }
  }
  return hosts;
}

/** Extract the hostname from a Host header, dropping the port (IPv6-safe). */
export function hostnameOf(hostHeader: string): string {
  const trimmed = hostHeader.trim().toLowerCase();
  if (trimmed.startsWith('[')) {
    // IPv6 literal: [::1]:8484 → [::1]
    const end = trimmed.indexOf(']');
    return end === -1 ? trimmed : trimmed.slice(0, end + 1);
  }
  const colon = trimmed.indexOf(':');
  return colon === -1 ? trimmed : trimmed.slice(0, colon);
}

export function isHostAllowed(hostHeader: string | undefined, allowed: ReadonlySet<string>): boolean {
  if (hostHeader === undefined) {
    // No Host header at all: only same-origin tooling omits it; be strict.
    return false;
  }
  return allowed.has(hostnameOf(hostHeader));
}

/**
 * Pull the proof-of-possession claims off a request, or null if any are
 * missing/duplicated. The signed path excludes the query string (there is
 * none on the LLM routes) so the client and door agree on the preimage.
 */
export function extractRequestClaims(request: FastifyRequest): RequestClaims | null {
  const tokenId = singleHeader(request, TOKEN_HEADER);
  const timestamp = singleHeader(request, TIMESTAMP_HEADER);
  const nonce = singleHeader(request, NONCE_HEADER);
  const pop = singleHeader(request, POP_HEADER);
  if (tokenId === null || timestamp === null || nonce === null || pop === null) {
    return null;
  }
  return {
    tokenId,
    method: request.method,
    path: (request.url ?? '').split('?')[0] ?? '',
    timestamp,
    nonce,
    pop,
  };
}

function singleHeader(request: FastifyRequest, name: string): string | null {
  const value = request.headers[name];
  if (typeof value !== 'string' || value.length === 0) {
    return null;
  }
  return value;
}
