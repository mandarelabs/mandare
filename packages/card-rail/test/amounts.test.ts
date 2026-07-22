import { describe, expect, it } from 'vitest';

import {
  isSupportedCardCurrency,
  microsToMinorUnitsFloor,
  minorUnitsToMicros,
} from '../src/amounts.js';

describe('amount conversion (minor units ↔ micros)', () => {
  it('converts cents to micros exactly', () => {
    expect(minorUnitsToMicros(0)).toBe(0);
    expect(minorUnitsToMicros(1)).toBe(10_000);
    expect(minorUnitsToMicros(1234)).toBe(12_340_000); // €12.34
  });

  it('floors micros to whole minor units (never rounds up past a cap)', () => {
    expect(microsToMinorUnitsFloor(9_999)).toBe(0);
    expect(microsToMinorUnitsFloor(10_000)).toBe(1);
    expect(microsToMinorUnitsFloor(19_999)).toBe(1);
    expect(microsToMinorUnitsFloor(12_345_678)).toBe(1234);
  });

  it('rejects non-integer and negative amounts', () => {
    expect(() => minorUnitsToMicros(1.5)).toThrow(RangeError);
    expect(() => minorUnitsToMicros(-1)).toThrow(RangeError);
    expect(() => microsToMinorUnitsFloor(Number.NaN)).toThrow(RangeError);
  });

  it('supports only two-decimal currencies (JPY et al. fail closed)', () => {
    expect(isSupportedCardCurrency('EUR')).toBe(true);
    expect(isSupportedCardCurrency('USD')).toBe(true);
    expect(isSupportedCardCurrency('JPY')).toBe(false);
    expect(isSupportedCardCurrency('BHD')).toBe(false);
    expect(isSupportedCardCurrency('eur')).toBe(false); // caller normalizes first
  });
});
