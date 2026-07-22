import { createHmac, timingSafeEqual } from 'node:crypto';

/**
 * Stripe webhook signature verification (Q11) — MANDATORY on every event
 * before any processing. Hand-rolled against Stripe's documented scheme
 * (same class of decision as the RFC 6962 / did:key hand-rolls: a small,
 * fully-testable surface beats a large dependency):
 *
 *   Stripe-Signature: t=<unix seconds>,v1=<hex hmac>[,v1=…][,v0=…]
 *   expected = HMAC-SHA256(webhook_secret, `${t}.${raw body bytes}`)
 *
 * Rules (all fail-closed):
 * - the signature is computed over the EXACT raw bytes received — any
 *   re-serialization breaks it, so the route keeps the raw buffer;
 * - every present v1 is tried (Stripe sends multiples during secret
 *   rotation); comparison is constant-time on equal-length digests;
 * - the timestamp must be within the tolerance window of now — outside it a
 *   VALID signature is still refused (replay bound); Stripe's own guidance.
 */

export const DEFAULT_TOLERANCE_SECONDS = 300;

export type WebhookVerifyFailure =
  | 'HEADER_MISSING'
  | 'HEADER_MALFORMED'
  | 'TIMESTAMP_OUT_OF_TOLERANCE'
  | 'SIGNATURE_MISMATCH';

export type WebhookVerifyResult =
  | { ok: true; timestamp: number }
  | { ok: false; failure: WebhookVerifyFailure };

export function verifyStripeSignature(args: {
  payload: Buffer;
  header: string | undefined;
  secret: string;
  toleranceSeconds?: number;
  nowMs?: number;
}): WebhookVerifyResult {
  const { payload, header, secret } = args;
  const toleranceSeconds = args.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS;
  const nowMs = args.nowMs ?? Date.now();

  if (header === undefined || header === '') {
    return { ok: false, failure: 'HEADER_MISSING' };
  }
  let timestampRaw: string | null = null;
  const candidates: string[] = [];
  for (const part of header.split(',')) {
    const eq = part.indexOf('=');
    if (eq === -1) {
      continue;
    }
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (key === 't') {
      if (timestampRaw !== null) {
        // Two timestamps is not a Stripe header — refuse rather than guess
        // which one the signature covers.
        return { ok: false, failure: 'HEADER_MALFORMED' };
      }
      timestampRaw = value;
    } else if (key === 'v1' && /^[0-9a-f]{64}$/.test(value)) {
      candidates.push(value);
    }
  }
  if (timestampRaw === null || !/^\d{1,12}$/.test(timestampRaw) || candidates.length === 0) {
    return { ok: false, failure: 'HEADER_MALFORMED' };
  }
  const timestamp = Number(timestampRaw);
  if (Math.abs(nowMs / 1000 - timestamp) > toleranceSeconds) {
    return { ok: false, failure: 'TIMESTAMP_OUT_OF_TOLERANCE' };
  }
  const expected = createHmac('sha256', secret)
    .update(`${timestamp}.`)
    .update(payload)
    .digest();
  for (const candidate of candidates) {
    if (timingSafeEqual(expected, Buffer.from(candidate, 'hex'))) {
      return { ok: true, timestamp };
    }
  }
  return { ok: false, failure: 'SIGNATURE_MISMATCH' };
}

/** Sign a payload the way Stripe does — for tests, mocks, and the demo. */
export function signStripePayload(args: {
  payload: Buffer | string;
  secret: string;
  timestampSeconds?: number;
}): string {
  const timestamp = args.timestampSeconds ?? Math.floor(Date.now() / 1000);
  const body = typeof args.payload === 'string' ? Buffer.from(args.payload, 'utf8') : args.payload;
  const mac = createHmac('sha256', args.secret).update(`${timestamp}.`).update(body).digest('hex');
  return `t=${timestamp},v1=${mac}`;
}
