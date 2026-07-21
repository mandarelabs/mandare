import { describe, expect, test } from 'vitest';

import {
  checkBudgets,
  formatMicros,
  type SpendCounterSnapshot,
  type SpendLimits,
} from '../src/index.js';

const limits: SpendLimits = {
  currency: 'EUR',
  perTxMicros: 5_000_000, // €5
  perDayMicros: 20_000_000, // €20
  perTaskMicros: 20_000_000,
  totalCapMicros: 100_000_000,
};

const velocity = { maxIntentsPerMinute: 100 };

function counters(overrides: Partial<SpendCounterSnapshot> = {}): SpendCounterSnapshot {
  return {
    minuteIntents: 0,
    day: { reservedMicros: 0, settledMicros: 0 },
    task: { reservedMicros: 0, settledMicros: 0 },
    total: { reservedMicros: 0, settledMicros: 0 },
    ...overrides,
  };
}

function check(args: {
  estimateMicros: number;
  counters?: SpendCounterSnapshot;
  currency?: string;
  limits?: SpendLimits;
}) {
  return checkBudgets({
    limits: args.limits ?? limits,
    velocity,
    counters: args.counters ?? counters(),
    estimateMicros: args.estimateMicros,
    currency: args.currency ?? 'EUR',
  });
}

describe('checkBudgets', () => {
  test('a fitting spend passes', () => {
    expect(check({ estimateMicros: 1_000_000 })).toBeNull();
  });

  test('zero estimate passes when caps are positive', () => {
    expect(check({ estimateMicros: 0 })).toBeNull();
  });

  test('currency mismatch refuses before any arithmetic', () => {
    expect(check({ estimateMicros: 0, currency: 'USD' })?.code).toBe('CURRENCY_MISMATCH');
  });

  test.each([-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53])(
    'invalid estimate %p refuses',
    (estimateMicros) => {
      expect(check({ estimateMicros })?.code).toBe('ESTIMATE_INVALID');
    }
  );

  test('per-tx cap is a hard ceiling on the estimate', () => {
    expect(check({ estimateMicros: 5_000_001 })?.code).toBe('PER_TX_EXCEEDED');
    expect(check({ estimateMicros: 5_000_000 })).toBeNull();
  });

  test('per-day counts reserved AND settled — an open reservation blocks the cap', () => {
    const nearCap = counters({
      day: { reservedMicros: 3_000_000, settledMicros: 16_500_000 },
    });
    expect(check({ estimateMicros: 500_000, counters: nearCap })).toBeNull();
    expect(check({ estimateMicros: 500_001, counters: nearCap })?.code).toBe('PER_DAY_EXCEEDED');
  });

  test('per-task window refuses when exceeded', () => {
    const used = counters({ task: { reservedMicros: 0, settledMicros: 19_000_000 } });
    expect(check({ estimateMicros: 1_000_001, counters: used })?.code).toBe('PER_TASK_EXCEEDED');
  });

  test('a positive per-task cap with NO task counter refuses, never skips (R1)', () => {
    expect(check({ estimateMicros: 0, counters: counters({ task: null }) })?.code).toBe(
      'PER_TASK_UNATTRIBUTABLE'
    );
  });

  test('per-task cap of 0 with no task counter is fine — nothing to enforce', () => {
    expect(
      check({
        estimateMicros: 1_000_000,
        counters: counters({ task: null }),
        limits: { ...limits, perTaskMicros: 0 },
      })
    ).toBeNull();
  });

  test('total cap refuses when exceeded', () => {
    const used = counters({ total: { reservedMicros: 0, settledMicros: 99_500_000 } });
    expect(check({ estimateMicros: 500_001, counters: used })?.code).toBe('TOTAL_CAP_EXCEEDED');
  });

  test('a cap of 0 permits nothing — 0 never means unlimited', () => {
    expect(
      check({ estimateMicros: 1, limits: { ...limits, perDayMicros: 0 } })?.code
    ).toBe('PER_DAY_EXCEEDED');
  });

  test('velocity refuses the call that would exceed the per-minute rate', () => {
    expect(check({ estimateMicros: 0, counters: counters({ minuteIntents: 99 }) })).toBeNull();
    expect(check({ estimateMicros: 0, counters: counters({ minuteIntents: 100 }) })?.code).toBe(
      'VELOCITY_EXCEEDED'
    );
  });

  test('refusal reasons are human-readable amounts, not micros', () => {
    const refusal = check({
      estimateMicros: 500_001,
      counters: counters({ day: { reservedMicros: 3_000_000, settledMicros: 16_500_000 } }),
    });
    expect(refusal?.reason).toContain('reserved 3.00 EUR');
    expect(refusal?.reason).toContain('settled 16.50 EUR');
    expect(refusal?.reason).toContain('cap 20.00 EUR');
  });
});

describe('formatMicros', () => {
  test('whole units keep two decimals', () => {
    expect(formatMicros(20_000_000, 'EUR')).toBe('20.00 EUR');
  });
  test('sub-cent amounts keep their precision', () => {
    expect(formatMicros(456, 'USD')).toBe('0.000456 USD');
  });
  test('trailing zeros beyond cents are trimmed', () => {
    expect(formatMicros(1_500_000, 'EUR')).toBe('1.50 EUR');
    expect(formatMicros(123_450, 'EUR')).toBe('0.12345 EUR');
  });
});
