/**
 * Stripe amounts are integer MINOR units of their currency (cents for EUR);
 * Mandare budgets are integer MICRO-units (1 unit = 1_000_000 micros). The
 * conversion is exact only for currencies whose minor unit is 1/100 — the
 * ones this rail supports in v0. Anything else (zero-decimal JPY, three-
 * decimal BHD) fails CLOSED rather than mis-metering by 100× (R1).
 */

export const MICROS_PER_MINOR_UNIT = 10_000;

/** ISO 4217 currencies with a 1/100 minor unit that the rail accepts in v0. */
const TWO_DECIMAL_CURRENCIES = new Set(['EUR', 'USD', 'GBP', 'CHF', 'SEK', 'DKK', 'NOK', 'PLN', 'CZK']);

export function isSupportedCardCurrency(upperCaseCurrency: string): boolean {
  return TWO_DECIMAL_CURRENCIES.has(upperCaseCurrency);
}

export function minorUnitsToMicros(minorUnits: number): number {
  if (!Number.isSafeInteger(minorUnits) || minorUnits < 0) {
    throw new RangeError(`minor-unit amount must be a non-negative integer, got ${String(minorUnits)}`);
  }
  return minorUnits * MICROS_PER_MINOR_UNIT;
}

/** Floor to whole minor units — a partial approval can never round UP past a cap. */
export function microsToMinorUnitsFloor(micros: number): number {
  if (!Number.isSafeInteger(micros) || micros < 0) {
    throw new RangeError(`micro amount must be a non-negative integer, got ${String(micros)}`);
  }
  return Math.floor(micros / MICROS_PER_MINOR_UNIT);
}
