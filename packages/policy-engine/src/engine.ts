import type { MandateV1, SpendScope } from '@mandarelabs/spec';

import {
  checkBudgets,
  formatMicros,
  type SpendCounterSnapshot,
  type SpendLimits,
  type VelocityLimit,
  type WindowCounter,
} from './budgets.js';
import type { PolicyDecision, PolicyEngine, PolicyRequest } from './types.js';

/**
 * Mandate policy engine v0 — evaluates SPEC §5's order exactly:
 *
 *   identity valid → mandate valid & in window → scope match → budget check
 *   → counterparty check → approval threshold → allow.
 *
 * Every check that cannot be performed yet fails CLOSED with an honest code:
 * `verified_only` counterparties deny until the registry exists, and
 * above-threshold approvals deny until the CIBA-style push lands (S4).
 * Identity is the static configured actor until passports land (S4);
 * mandate signature verification also lands with SD-JWT in S4 — v0 trusts
 * the schema-validated mandate file the OPERATOR configured (not the agent).
 */

export type PolicyRefusalCode =
  | 'CONTEXT_INVALID'
  | 'IDENTITY_MISMATCH'
  | 'MANDATE_WINDOW_INVALID'
  | 'MANDATE_OUT_OF_WINDOW'
  | 'SCOPE_MISMATCH'
  | 'SCOPE_AMBIGUOUS'
  | 'COUNTERPARTY_DENIED'
  | 'COUNTERPARTY_UNVERIFIABLE'
  | 'APPROVAL_RULE_UNEVALUABLE'
  | 'APPROVAL_REQUIRED';

export interface MandatePolicyEngineOptions {
  mandate: MandateV1;
  velocity: VelocityLimit;
  /**
   * Which money rail this engine instance guards: 'gateway' (LLM spend, the
   * default) or 'card' (Stripe Issuing authorizations, S5). The SPEC §5
   * evaluation order is identical; only the spend-scope selection differs.
   */
  rail?: SpendRailName;
  /** Injectable clock for tests; defaults to wall time. */
  clock?: () => Date;
}

export type SpendRailName = 'gateway' | 'card';

/** The context shape `evaluate` requires (validated at the boundary, R4). */
export interface SpendEvaluationContext {
  estimateMicros: number;
  currency: string;
  /** Counterparty identifier — the provider host for llm.call. */
  counterparty: string;
  counters: SpendCounterSnapshot;
  /**
   * Set ONLY by the gateway after a human approval decision was verified and
   * recorded as a ledger entry (S4): the approval.granted entry hash. Its
   * presence waives the approval-threshold check for THIS evaluation —
   * nothing else. Never populated from agent input (R4: the context is
   * door-constructed, not caller-supplied).
   */
  approvedEntryHash?: string;
}

export function spendLimitsFromScope(scope: SpendScope): SpendLimits {
  return {
    currency: scope.currency,
    perTxMicros: scope.per_tx_max,
    perDayMicros: scope.per_day_max,
    perTaskMicros: scope.per_task_max,
    totalCapMicros: scope.total_cap,
  };
}

/**
 * The ONE way to pick the spend scope governing gateway llm spend — shared
 * by the engine and by gateways building their in-transaction reservation
 * guard, so both provably use the same limits. Ambiguity (multiple matching
 * scopes) returns 'ambiguous' and must deny (fail-closed, v0 never merges).
 */
export function selectGatewaySpendScope(
  mandate: MandateV1
): SpendScope | 'none' | 'ambiguous' {
  return selectRailSpendScope(mandate, 'gateway', 'llm');
}

/**
 * Card-rail twin of `selectGatewaySpendScope` (S5): exactly ONE spend scope
 * must cover the 'card' rail (category 'purchase', or uncategorized). The
 * same scope may also cover 'gateway' — that is the one-mandate-one-cap
 * cross-rail case, and both doors then reserve against the same counters.
 */
export function selectCardSpendScope(mandate: MandateV1): SpendScope | 'none' | 'ambiguous' {
  return selectRailSpendScope(mandate, 'card', 'purchase');
}

function selectRailSpendScope(
  mandate: MandateV1,
  rail: SpendRailName,
  category: string
): SpendScope | 'none' | 'ambiguous' {
  const matches = mandate.scopes.filter(
    (scope): scope is SpendScope =>
      scope.type === 'spend' &&
      scope.rails.includes(rail) &&
      (scope.categories.length === 0 || scope.categories.includes(category))
  );
  if (matches.length === 0) {
    return 'none';
  }
  if (matches.length > 1) {
    return 'ambiguous';
  }
  return matches[0] as SpendScope;
}

function deny(code: PolicyRefusalCode | string, reason: string): PolicyDecision {
  return { decision: 'deny', reasons: [reason], code };
}

function isWindowCounter(value: unknown): value is WindowCounter {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const counter = value as Record<string, unknown>;
  return (
    Number.isSafeInteger(counter.reservedMicros) &&
    (counter.reservedMicros as number) >= 0 &&
    Number.isSafeInteger(counter.settledMicros) &&
    (counter.settledMicros as number) >= 0
  );
}

function isCounterSnapshot(value: unknown): value is SpendCounterSnapshot {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const snapshot = value as Record<string, unknown>;
  return (
    Number.isSafeInteger(snapshot.minuteIntents) &&
    (snapshot.minuteIntents as number) >= 0 &&
    isWindowCounter(snapshot.day) &&
    (snapshot.task === null || isWindowCounter(snapshot.task)) &&
    isWindowCounter(snapshot.total)
  );
}

/** Boundary validation of the free-shaped Cedar context (R4). */
export function parseSpendContext(
  context: Readonly<Record<string, unknown>>
): SpendEvaluationContext | null {
  const { estimateMicros, currency, counterparty, counters, approvedEntryHash } = context;
  if (!Number.isSafeInteger(estimateMicros) || (estimateMicros as number) < 0) {
    return null;
  }
  if (typeof currency !== 'string' || !/^[A-Z]{3}$/.test(currency)) {
    return null;
  }
  if (typeof counterparty !== 'string' || counterparty.length === 0) {
    return null;
  }
  if (!isCounterSnapshot(counters)) {
    return null;
  }
  if (
    approvedEntryHash !== undefined &&
    (typeof approvedEntryHash !== 'string' || !/^[0-9a-f]{64}$/.test(approvedEntryHash))
  ) {
    return null;
  }
  return {
    estimateMicros: estimateMicros as number,
    currency,
    counterparty,
    counters,
    ...(approvedEntryHash === undefined ? {} : { approvedEntryHash }),
  };
}

/**
 * Parse an ISO timestamp, failing CLOSED on non-calendar strings: the schema
 * pattern admits shapes like 2026-13-01T00:00:00Z, which Date.parse turns
 * into NaN — and NaN comparisons are all false, which would silently skip
 * the validity window (the S1 H1 lesson, applied here from day one).
 */
function parseWindowInstant(value: string): number | null {
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
}

export class MandatePolicyEngine implements PolicyEngine {
  private readonly mandate: MandateV1;
  private readonly velocity: VelocityLimit;
  private readonly rail: SpendRailName;
  private readonly clock: () => Date;

  constructor(options: MandatePolicyEngineOptions) {
    this.mandate = options.mandate;
    this.velocity = options.velocity;
    this.rail = options.rail ?? 'gateway';
    this.clock = options.clock ?? ((): Date => new Date());
  }

  evaluate(request: PolicyRequest): Promise<PolicyDecision> {
    return Promise.resolve(this.evaluateSync(request));
  }

  private evaluateSync(request: PolicyRequest): PolicyDecision {
    const mandate = this.mandate;

    const context = parseSpendContext(request.context);
    if (context === null) {
      return deny(
        'CONTEXT_INVALID',
        'evaluation context is malformed (estimateMicros/currency/counterparty/counters) — refusing (fail-closed)'
      );
    }

    // 1. Identity valid (static actor identity until passports land, S4).
    if (request.principal !== mandate.agent) {
      return deny(
        'IDENTITY_MISMATCH',
        `principal ${request.principal} is not the mandated agent ${mandate.agent}`
      );
    }

    // 2. Mandate valid & in window.
    const from = parseWindowInstant(mandate.valid_from);
    const until = parseWindowInstant(mandate.valid_until);
    if (from === null || until === null) {
      return deny(
        'MANDATE_WINDOW_INVALID',
        'mandate validity window contains a non-calendar timestamp — refusing (fail-closed)'
      );
    }
    const now = this.clock().getTime();
    if (now < from || now > until) {
      return deny(
        'MANDATE_OUT_OF_WINDOW',
        `mandate ${mandate.id} is ${now < from ? 'not yet valid' : 'expired'} ` +
          `(valid ${mandate.valid_from} → ${mandate.valid_until})`
      );
    }

    // 3. Scope match: an action scope must grant the action class, and
    //    exactly ONE spend scope must cover the gateway rail (ambiguity
    //    denies — v0 does not merge or pick between overlapping budgets).
    const actionGranted = mandate.scopes.some(
      (scope) => scope.type === 'action' && scope.classes.includes(request.action)
    );
    if (!actionGranted) {
      return deny('SCOPE_MISMATCH', `no action scope grants '${request.action}'`);
    }
    const selected =
      this.rail === 'card' ? selectCardSpendScope(mandate) : selectGatewaySpendScope(mandate);
    if (selected === 'none') {
      return deny('SCOPE_MISMATCH', `no spend scope covers the '${this.rail}' rail for this spend`);
    }
    if (selected === 'ambiguous') {
      return deny(
        'SCOPE_AMBIGUOUS',
        'multiple spend scopes cover this call — v0 refuses ambiguous budgets (fail-closed)'
      );
    }
    const scope = selected;

    // 4. Budget check (pre-call estimate; the ledger transaction re-checks
    //    the same math under the write lock at reservation time).
    const refusal = checkBudgets({
      limits: spendLimitsFromScope(scope),
      velocity: this.velocity,
      counters: context.counters,
      estimateMicros: context.estimateMicros,
      currency: context.currency,
    });
    if (refusal !== null) {
      return deny(refusal.code, refusal.reason);
    }

    // 5. Counterparty check.
    if (scope.counterparties === 'allowlist') {
      if (!scope.counterparty_allowlist.includes(context.counterparty)) {
        return deny(
          'COUNTERPARTY_DENIED',
          `counterparty '${context.counterparty}' is not on the mandate allowlist`
        );
      }
    } else if (scope.counterparties === 'verified_only') {
      return deny(
        'COUNTERPARTY_UNVERIFIABLE',
        'mandate requires registry-verified counterparties, and the registry does not exist yet — refusing (fail-closed)'
      );
    }

    // 6. Approval threshold. A recorded human approval (the gateway sets
    //    approvedEntryHash only after the approval.granted ledger entry
    //    persisted) waives the threshold for this one evaluation; otherwise
    //    an over-threshold call denies with APPROVAL_REQUIRED — the gateway
    //    turns that into the CIBA-style hold-and-push (S4).
    for (const rule of mandate.approvals.rules) {
      if (rule.currency !== context.currency) {
        return deny(
          'APPROVAL_RULE_UNEVALUABLE',
          `approval rule is in ${rule.currency} but the call is budgeted in ${context.currency} — refusing (fail-closed)`
        );
      }
      if (context.approvedEntryHash === undefined && context.estimateMicros > rule.above) {
        return deny(
          'APPROVAL_REQUIRED',
          `estimate ${formatMicros(context.estimateMicros, context.currency)} exceeds the ` +
            `${formatMicros(rule.above, rule.currency)} approval threshold — async human approval required`
        );
      }
    }

    // 7. Execute.
    return {
      decision: 'allow',
      reasons: [
        `mandate ${mandate.id}: estimate ${formatMicros(context.estimateMicros, context.currency)} within ` +
          `per-tx ${formatMicros(scope.per_tx_max, scope.currency)}, ` +
          `day ${formatMicros(context.counters.day.reservedMicros + context.counters.day.settledMicros, scope.currency)} of ${formatMicros(scope.per_day_max, scope.currency)}, ` +
          `total ${formatMicros(context.counters.total.reservedMicros + context.counters.total.settledMicros, scope.currency)} of ${formatMicros(scope.total_cap, scope.currency)}`,
      ],
    };
  }
}
