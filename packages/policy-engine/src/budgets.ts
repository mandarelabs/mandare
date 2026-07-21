import { CURRENCY_MICROS_PER_UNIT } from '@mandarelabs/spec';

/**
 * Pure budget arithmetic — the ONE function that decides whether a spend fits
 * its caps. It runs twice per call, by design:
 *
 *   1. in the gateway's pre-call policy evaluation (against a counter
 *      snapshot, for the full SPEC §5 order), and
 *   2. inside the ledger append transaction (against the authoritative
 *      counters under the write lock) — the reservation step that makes
 *      concurrent cap overshoot impossible by construction.
 *
 * Pure and side-effect-free so both call sites provably apply identical math.
 */

/** All amounts are integer micro-units (1 unit = 1_000_000 micros). */
export interface SpendLimits {
  currency: string;
  perTxMicros: number;
  perDayMicros: number;
  perTaskMicros: number;
  totalCapMicros: number;
}

export interface WindowCounter {
  reservedMicros: number;
  settledMicros: number;
}

export interface SpendCounterSnapshot {
  /** Intent entries recorded in the current UTC minute (velocity window). */
  minuteIntents: number;
  day: WindowCounter;
  /**
   * null = task attribution unavailable. v0 gateways pass the mandate-total
   * counter here (one mandate = one task until task attribution lands, S4);
   * a null with a positive per-task cap is refused, never skipped (R1).
   */
  task: WindowCounter | null;
  total: WindowCounter;
}

export interface VelocityLimit {
  maxIntentsPerMinute: number;
}

export type BudgetRefusalCode =
  | 'CURRENCY_MISMATCH'
  | 'ESTIMATE_INVALID'
  | 'PER_TX_EXCEEDED'
  | 'PER_DAY_EXCEEDED'
  | 'PER_TASK_EXCEEDED'
  | 'PER_TASK_UNATTRIBUTABLE'
  | 'TOTAL_CAP_EXCEEDED'
  | 'VELOCITY_EXCEEDED';

export interface BudgetRefusal {
  code: BudgetRefusalCode;
  reason: string;
}

/** Render micros as a human amount, e.g. 20_000_000 → '20.00 EUR'. */
export function formatMicros(micros: number, currency: string): string {
  const units = micros / CURRENCY_MICROS_PER_UNIT;
  const text = units.toFixed(6).replace(/(\.\d\d[0-9]*?)0+$/, '$1');
  return `${text} ${currency}`;
}

function windowRefusal(
  code: BudgetRefusalCode,
  label: string,
  window: WindowCounter,
  estimateMicros: number,
  capMicros: number,
  currency: string
): BudgetRefusal {
  return {
    code,
    reason:
      `${label} budget exceeded: reserved ${formatMicros(window.reservedMicros, currency)} ` +
      `+ settled ${formatMicros(window.settledMicros, currency)} ` +
      `+ estimate ${formatMicros(estimateMicros, currency)} ` +
      `> cap ${formatMicros(capMicros, currency)}`,
  };
}

function exceedsWindow(window: WindowCounter, estimateMicros: number, capMicros: number): boolean {
  return window.reservedMicros + window.settledMicros + estimateMicros > capMicros;
}

/**
 * null = the spend fits every cap; otherwise the first refusal in evaluation
 * order. Caps are literal: a cap of 0 permits nothing (fail-closed — there is
 * no "0 means unlimited" convention anywhere in Mandare).
 */
export function checkBudgets(args: {
  limits: SpendLimits;
  velocity: VelocityLimit;
  counters: SpendCounterSnapshot;
  estimateMicros: number;
  currency: string;
}): BudgetRefusal | null {
  const { limits, velocity, counters, estimateMicros, currency } = args;

  if (currency !== limits.currency) {
    return {
      code: 'CURRENCY_MISMATCH',
      reason: `estimate is in ${currency} but the mandate budgets ${limits.currency} — refusing to convert implicitly`,
    };
  }
  if (!Number.isSafeInteger(estimateMicros) || estimateMicros < 0) {
    return {
      code: 'ESTIMATE_INVALID',
      reason: `cost estimate must be a non-negative integer micro-amount, got ${String(estimateMicros)}`,
    };
  }
  if (estimateMicros > limits.perTxMicros) {
    return {
      code: 'PER_TX_EXCEEDED',
      reason: `per-transaction cap exceeded: estimate ${formatMicros(estimateMicros, currency)} > cap ${formatMicros(limits.perTxMicros, currency)}`,
    };
  }
  if (exceedsWindow(counters.day, estimateMicros, limits.perDayMicros)) {
    return windowRefusal('PER_DAY_EXCEEDED', 'per-day', counters.day, estimateMicros, limits.perDayMicros, currency);
  }
  if (counters.task === null) {
    // A positive task cap we cannot attribute is a refusal, not a skip (R1).
    if (limits.perTaskMicros > 0) {
      return {
        code: 'PER_TASK_UNATTRIBUTABLE',
        reason: 'mandate sets a per-task cap but no task counter was supplied — refusing (fail-closed)',
      };
    }
  } else if (exceedsWindow(counters.task, estimateMicros, limits.perTaskMicros)) {
    return windowRefusal('PER_TASK_EXCEEDED', 'per-task', counters.task, estimateMicros, limits.perTaskMicros, currency);
  }
  if (exceedsWindow(counters.total, estimateMicros, limits.totalCapMicros)) {
    return windowRefusal('TOTAL_CAP_EXCEEDED', 'total', counters.total, estimateMicros, limits.totalCapMicros, currency);
  }
  if (counters.minuteIntents + 1 > velocity.maxIntentsPerMinute) {
    return {
      code: 'VELOCITY_EXCEEDED',
      reason: `velocity cap exceeded: ${counters.minuteIntents} calls already this minute (max ${velocity.maxIntentsPerMinute}/min)`,
    };
  }
  return null;
}
