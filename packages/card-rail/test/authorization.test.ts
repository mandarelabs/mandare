import { describe, expect, it } from 'vitest';

import {
  isPartialableRefusal,
  maxApprovableMicros,
  parseAuthorizationEvent,
} from '../src/authorization.js';
import { authorizationEvent } from './helpers.js';
import type { SpendScope } from '@mandarelabs/spec';

describe('parseAuthorizationEvent', () => {
  it('extracts the decision fields from a request event', () => {
    const auth = parseAuthorizationEvent(
      authorizationEvent({ authorizationId: 'iauth_1', cardId: 'ic_1', amountMinorUnits: 250 })
    );
    expect(auth).toMatchObject({
      authorizationId: 'iauth_1',
      cardId: 'ic_1',
      requestedMicros: 2_500_000,
      currency: 'EUR',
      merchantKey: 'net_acme_1',
      merchantName: 'ACME SaaS',
      isAmountControllable: false,
      apiVersion: '2026-test',
    });
  });

  it('accepts a card given as a bare id string', () => {
    const event = authorizationEvent({ authorizationId: 'iauth_2', cardId: 'ic_x', amountMinorUnits: 100 });
    const data = (event.data as { object: Record<string, unknown> }).object;
    data.card = 'ic_x';
    expect(parseAuthorizationEvent(event)?.cardId).toBe('ic_x');
  });

  it('falls back to the merchant name when network_id is absent', () => {
    const event = authorizationEvent({ authorizationId: 'iauth_3', cardId: 'ic_1', amountMinorUnits: 100 });
    const data = (event.data as { object: Record<string, unknown> }).object;
    delete ((data.merchant_data as Record<string, unknown>) ?? {}).network_id;
    expect(parseAuthorizationEvent(event)?.merchantKey).toBe('ACME SaaS');
  });

  it('rejects wrong event types and malformed shapes', () => {
    expect(parseAuthorizationEvent(null)).toBeNull();
    expect(parseAuthorizationEvent({ type: 'issuing_card.created' })).toBeNull();
    expect(parseAuthorizationEvent({ type: 'issuing_authorization.request' })).toBeNull();
    const noAmount = authorizationEvent({ authorizationId: 'iauth_4', cardId: 'ic_1', amountMinorUnits: 100 });
    const data = (noAmount.data as { object: Record<string, unknown> }).object;
    (data.pending_request as Record<string, unknown>).amount = 'lots';
    data.amount = 'lots';
    expect(parseAuthorizationEvent(noAmount)).toBeNull();
    const negative = authorizationEvent({ authorizationId: 'iauth_5', cardId: 'ic_1', amountMinorUnits: 100 });
    ((negative.data as { object: Record<string, unknown> }).object.pending_request as Record<string, unknown>).amount = -5;
    expect(parseAuthorizationEvent(negative)).toBeNull();
  });
});

describe('maxApprovableMicros (partial approvals)', () => {
  const scope: SpendScope = {
    type: 'spend',
    currency: 'EUR',
    per_tx_max: 10_000_000,
    per_day_max: 20_000_000,
    per_task_max: 20_000_000,
    total_cap: 20_000_000,
    rails: ['card'],
    counterparties: 'any',
    categories: [],
  };

  const snapshot = (dayUsed: number, totalUsed: number) => ({
    minuteIntents: 0,
    day: { reservedMicros: 0, settledMicros: dayUsed, intents: 1 },
    total: { reservedMicros: 0, settledMicros: totalUsed, intents: 1 },
  });

  it('is bounded by the tightest cap', () => {
    // €18 spent of €20 day cap → €2 remain, under the €10 per-tx cap.
    expect(maxApprovableMicros(scope, snapshot(18_000_000, 18_000_000))).toBe(2_000_000);
    // Nothing spent → per-tx cap binds.
    expect(maxApprovableMicros(scope, snapshot(0, 0))).toBe(10_000_000);
  });

  it('floors at zero when the cap is exhausted or exceeded', () => {
    expect(maxApprovableMicros(scope, snapshot(20_000_000, 20_000_000))).toBe(0);
    expect(maxApprovableMicros(scope, snapshot(25_000_000, 25_000_000))).toBe(0);
  });

  it('counts open reservations as consumed', () => {
    const withReservation = {
      minuteIntents: 0,
      day: { reservedMicros: 5_000_000, settledMicros: 10_000_000, intents: 2 },
      total: { reservedMicros: 5_000_000, settledMicros: 10_000_000, intents: 2 },
    };
    expect(maxApprovableMicros(scope, withReservation)).toBe(5_000_000);
  });
});

describe('isPartialableRefusal', () => {
  it('allows partials only for budget-cap refusals — never approval thresholds', () => {
    expect(isPartialableRefusal('PER_DAY_EXCEEDED')).toBe(true);
    expect(isPartialableRefusal('TOTAL_CAP_EXCEEDED')).toBe(true);
    expect(isPartialableRefusal('APPROVAL_REQUIRED')).toBe(false);
    expect(isPartialableRefusal('VELOCITY_EXCEEDED')).toBe(false);
    expect(isPartialableRefusal(undefined)).toBe(false);
  });
});
