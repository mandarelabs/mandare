/**
 * @mandarelabs/policy-engine (Apache-2.0) — the mandate enforcement point,
 * embeddable in third-party gateways and frameworks.
 *
 * The interface is deliberately Cedar-shaped — (principal, action, resource,
 * context) → decision (BUILD-DECISIONS Q9). Budgets and velocity are STATEFUL
 * and quantitative: `checkBudgets` is the pure arithmetic, and the ledger
 * calls it again inside the append transaction (reservation), which is why
 * this is custom TS and not Cedar/OPA.
 *
 * The S0 allow-all `UnconfiguredPolicyEngine` stub is gone — S2 replaced it
 * with `MandatePolicyEngine`. A door with no mandate configured must keep its
 * spend path CLOSED, not fall back to allow-all.
 */

export type { PolicyDecision, PolicyEngine, PolicyRequest } from './types.js';
export {
  checkBudgets,
  formatMicros,
  type BudgetRefusal,
  type BudgetRefusalCode,
  type SpendCounterSnapshot,
  type SpendLimits,
  type VelocityLimit,
  type WindowCounter,
} from './budgets.js';
export {
  MandatePolicyEngine,
  parseSpendContext,
  selectCardSpendScope,
  selectGatewaySpendScope,
  spendLimitsFromScope,
  type MandatePolicyEngineOptions,
  type PolicyRefusalCode,
  type SpendEvaluationContext,
  type SpendRailName,
} from './engine.js';
