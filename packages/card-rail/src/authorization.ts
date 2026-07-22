import { canonicalJson, sha256Hex } from '@mandarelabs/spec';
import type { SpendScope } from '@mandarelabs/spec';

import { minorUnitsToMicros } from './amounts.js';
import type { SpendSnapshot } from '@mandarelabs/ledger';

/**
 * Parsing + arithmetic for `issuing_authorization.request` events — pure
 * functions, exhaustively unit-tested; the webhook route wires them to the
 * ledger. Boundary rule R4: the event is only accepted after its signature
 * verified, but its SHAPE is still validated field by field — a signed
 * surprise is still a surprise.
 */

export interface AuthorizationRequest {
  authorizationId: string;
  cardId: string;
  /** Requested amount in Mandare micros (from pending_request). */
  requestedMicros: number;
  /** Uppercase ISO currency of the pending request. */
  currency: string;
  /**
   * Stable merchant identity for counterparty checks + waivers; null when
   * the event names no network_id AND no merchant name (unidentifiable —
   * step-up waivers are refused for such merchants, fail-closed).
   */
  merchantKey: string | null;
  merchantName: string;
  isAmountControllable: boolean;
  apiVersion: string | null;
}

/** Extract and validate the fields the decision needs; null = malformed. */
export function parseAuthorizationEvent(event: unknown): AuthorizationRequest | null {
  if (typeof event !== 'object' || event === null) {
    return null;
  }
  const root = event as Record<string, unknown>;
  if (root.type !== 'issuing_authorization.request') {
    return null;
  }
  const data = (root.data as Record<string, unknown> | undefined)?.object as
    | Record<string, unknown>
    | undefined;
  if (typeof data !== 'object' || data === null) {
    return null;
  }
  const authorizationId = data.id;
  if (typeof authorizationId !== 'string' || authorizationId.length === 0) {
    return null;
  }
  const card = data.card;
  const cardId =
    typeof card === 'string'
      ? card
      : typeof card === 'object' && card !== null
        ? (card as Record<string, unknown>).id
        : undefined;
  if (typeof cardId !== 'string' || cardId.length === 0) {
    return null;
  }
  // The requested amount lives in pending_request on a request event — and
  // ONLY there (the top-level amount is 0 until the decision). No fallback:
  // a shape surprise (API drift, renamed field) must parse to null → decline,
  // because responding {approved:true} while metering a wrong amount would
  // approve the FULL request with a broken reservation (review MEDIUM-1).
  const pending = data.pending_request as Record<string, unknown> | undefined;
  if (typeof pending !== 'object' || pending === null) {
    return null;
  }
  const amountMinor = pending.amount;
  const currencyRaw = pending.currency;
  if (!Number.isSafeInteger(amountMinor) || (amountMinor as number) < 0) {
    return null;
  }
  if (typeof currencyRaw !== 'string' || !/^[a-zA-Z]{3}$/.test(currencyRaw)) {
    return null;
  }
  const merchant = data.merchant_data as Record<string, unknown> | undefined;
  const networkId = typeof merchant?.network_id === 'string' ? merchant.network_id : null;
  const name = typeof merchant?.name === 'string' && merchant.name.length > 0 ? merchant.name : null;
  return {
    authorizationId,
    cardId,
    requestedMicros: minorUnitsToMicros(amountMinor as number),
    currency: currencyRaw.toUpperCase(),
    // null = the merchant is UNIDENTIFIABLE — waivers must not pool such
    // merchants under a shared sentinel key (review LOW-3).
    merchantKey: networkId ?? name,
    merchantName: name ?? 'unknown merchant',
    isAmountControllable: pending.is_amount_controllable === true,
    apiVersion: typeof root.api_version === 'string' ? root.api_version : null,
  };
}

/** One request hash binds every ledger entry for this authorization (R2: hashes, not content). */
export function authorizationRequestHash(auth: AuthorizationRequest): string {
  return sha256Hex(
    canonicalJson({
      authorization_id: auth.authorizationId,
      card: auth.cardId,
      merchant: auth.merchantKey ?? auth.merchantName,
      amount_micros: auth.requestedMicros,
      currency: auth.currency,
    })
  );
}

export function decisionResponseHash(auth: AuthorizationRequest, approvedMicros: number): string {
  return sha256Hex(
    canonicalJson({
      authorization_id: auth.authorizationId,
      decision: 'approved',
      amount_micros: approvedMicros,
    })
  );
}

/** Budget-cap refusal codes where a partial approval is even meaningful. */
const PARTIALABLE_CODES = new Set([
  'PER_TX_EXCEEDED',
  'PER_DAY_EXCEEDED',
  'PER_TASK_EXCEEDED',
  'TOTAL_CAP_EXCEEDED',
]);

export function isPartialableRefusal(code: string | undefined): boolean {
  return code !== undefined && PARTIALABLE_CODES.has(code);
}

/**
 * The largest amount that still fits every cap given the current counters —
 * the partial-approval candidate for `is_amount_controllable` requests.
 * Floors at 0; the caller floors again to whole minor units and re-runs the
 * FULL policy order at the reduced amount (a partial must earn a real
 * allow, this arithmetic alone never admits it).
 */
export function maxApprovableMicros(scope: SpendScope, snapshot: SpendSnapshot): number {
  const consumed = (window: { reservedMicros: number; settledMicros: number }): number =>
    window.reservedMicros + window.settledMicros;
  const remaining = Math.min(
    scope.per_tx_max,
    scope.per_day_max - consumed(snapshot.day),
    scope.per_task_max - consumed(snapshot.total),
    scope.total_cap - consumed(snapshot.total)
  );
  return Math.max(0, remaining);
}
