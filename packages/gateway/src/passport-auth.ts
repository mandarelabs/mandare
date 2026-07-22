import type { FastifyRequest } from 'fastify';

import {
  PASSPORT_HEADER,
  RequestSignatureError,
  verifyMandareRequest,
  verifyPassport,
  type NonceStore,
  type VerifiedPassport,
} from '@mandarelabs/passport';

/**
 * Passport authentication for the spend routes (S4). Replaces the S3 HMAC
 * proof-of-possession token when authMode='passport':
 *
 *   1. verify the presented delegation credential OFFLINE (authority →
 *      owner → agent chain, validity window);
 *   2. verify the RFC 9421 request signature with the credential's cnf key,
 *      covering method/path/authority/content-digest/signature-agent —
 *      the verified actor is now WHO, not just "an authorized holder", and
 *      the body is bound (closes S3's HIGH-1).
 *
 * Revocation is deliberately NOT checked here: the caller checks the agent
 * (and mandate) subjects against the ledger projection AFTER identity is
 * proven, so a killed agent's refusal can be attributed and recorded.
 */

export interface PassportAuthRefusal {
  status: 401 | 403;
  code: string;
  reason: string;
}

export type PassportAuthResult =
  | { ok: true; passport: VerifiedPassport }
  | { ok: false; refusal: PassportAuthRefusal };

function refuse(status: 401 | 403, code: string, reason: string): PassportAuthResult {
  return { ok: false, refusal: { status, code, reason } };
}

/** Single-valued lower-cased header map; duplicated security headers refuse. */
function singleValueHeaders(request: FastifyRequest): Record<string, string> | null {
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(request.headers)) {
    if (Array.isArray(value)) {
      if (name === 'signature' || name === 'signature-input' || name === PASSPORT_HEADER) {
        return null;
      }
      continue;
    }
    if (typeof value === 'string') {
      headers[name] = value;
    }
  }
  return headers;
}

export interface AuthenticateArgs {
  request: FastifyRequest;
  /** Exact received body bytes (captured by the raw-body parser). */
  rawBody: Uint8Array;
  trustedAuthorityDid: string;
  nonceStore: NonceStore;
}

export async function authenticatePassportRequest(args: AuthenticateArgs): Promise<PassportAuthResult> {
  const headers = singleValueHeaders(args.request);
  if (headers === null) {
    return refuse(401, 'MALFORMED_HEADERS', 'duplicated authentication headers');
  }
  const compact = headers[PASSPORT_HEADER];
  if (compact === undefined || compact.length === 0) {
    return refuse(401, 'PASSPORT_MISSING', `no ${PASSPORT_HEADER} header presented`);
  }

  let passport: VerifiedPassport;
  try {
    passport = await verifyPassport(compact, { trustedAuthorityDid: args.trustedAuthorityDid });
  } catch (error) {
    return refuse(
      401,
      'PASSPORT_INVALID',
      `delegation credential rejected: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  const host = headers.host ?? '';
  try {
    await verifyMandareRequest({
      method: args.request.method,
      url: `http://${host}${args.request.url}`,
      headers,
      bodyBytes: args.rawBody,
      agentPublicJwk: passport.agentPublicJwk,
      agentDid: passport.agentDid,
      nonceStore: args.nonceStore,
    });
  } catch (error: unknown) {
    if (error instanceof RequestSignatureError) {
      return refuse(401, error.code, error.message);
    }
    return refuse(401, 'SIGNATURE_REJECTED', 'request signature could not be verified');
  }
  return { ok: true, passport };
}
