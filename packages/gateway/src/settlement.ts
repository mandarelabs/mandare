import {
  costUsdMicros,
  estimateTokensFromUtf8Bytes,
  usdMicrosToLedgerMicros,
  type ModelPricing,
} from './pricing.js';
import { emptyUsage, type ParsedUsage, type StreamUsageParser } from './providers/types.js';

/**
 * Settlement: turning what a provider reported into the RESULT entry's cost.
 * The reservation was the cap guard; settlement is unguarded by design, so
 * the one rule that keeps the caps honest is that an outcome the door cannot
 * see in full is never settled below what it reserved (R1).
 */

/** What settlement needs from the call plan. */
export interface SettlementPlan {
  /** null = unpriced (OpenRouter only — its reported cost is authoritative). */
  pricing: ModelPricing | null;
  usdPerLedgerUnit: number;
  /** The reservation in ledger micros: the floor for every outcome-unknown settle. */
  estimateLedgerMicros: number;
  /** Upper-bound input tokens for the whole request body (the reservation's input side). */
  inputTokensBound: number;
}

export interface Settlement {
  costMicros: number;
  tokensIn: number;
  tokensOut: number;
}

/** Every input token the provider billed, cache writes and reads included. */
export function billedInputTokens(usage: ParsedUsage): number {
  return usage.tokensIn + usage.cacheWriteTokens + usage.cacheReadTokens;
}

/** Authoritative usage → true cost. OpenRouter's reported cost wins (Q14). */
export function settlementMicros(usage: ParsedUsage, plan: SettlementPlan): number {
  if (usage.costUsdMicros !== null) {
    return usdMicrosToLedgerMicros(usage.costUsdMicros, plan.usdPerLedgerUnit);
  }
  if (plan.pricing !== null) {
    return usdMicrosToLedgerMicros(costUsdMicros(usage, plan.pricing), plan.usdPerLedgerUnit);
  }
  return plan.estimateLedgerMicros;
}

/**
 * Settle a stream once it is over (S-1). With the provider's final usage in
 * hand the cost is exact. Without it — the stream stalled, was cut, the client
 * hung up, or the endpoint never reports usage — the outcome is UNKNOWN: a
 * provider can bill cache writes, thinking and tool calls the door never saw
 * in full. That settles like any other outcome-unknown call: at the
 * reservation, raised (never lowered) by whatever the partial picture proves
 * was spent. A Storno entry can reconcile against provider billing later.
 */
export function streamSettlement(parser: StreamUsageParser, plan: SettlementPlan): Settlement {
  const usage = parser.usage();
  if (usage !== null && parser.hasFinalUsage()) {
    return {
      costMicros: settlementMicros(usage, plan),
      tokensIn: billedInputTokens(usage),
      tokensOut: usage.tokensOut,
    };
  }
  const partial: ParsedUsage = {
    ...(usage ?? emptyUsage()),
    // No input count at all ⇒ the reservation's own input bound (the whole
    // body), never a guess over one field of it.
    tokensIn: usage === null ? plan.inputTokensBound : usage.tokensIn,
    // A pre-final output count is stale; every observed output byte is a
    // token upper bound (tokens ≤ bytes).
    tokensOut: Math.max(
      usage?.tokensOut ?? 0,
      estimateTokensFromUtf8Bytes(parser.observedOutputBytes())
    ),
  };
  return {
    costMicros: Math.max(plan.estimateLedgerMicros, partialCostMicros(partial, plan)),
    tokensIn: billedInputTokens(partial),
    tokensOut: partial.tokensOut,
  };
}

/** What the partial picture alone proves was spent (ledger micros). */
function partialCostMicros(partial: ParsedUsage, plan: SettlementPlan): number {
  const reported =
    partial.costUsdMicros === null
      ? 0
      : usdMicrosToLedgerMicros(partial.costUsdMicros, plan.usdPerLedgerUnit);
  const priced =
    plan.pricing === null
      ? 0
      : usdMicrosToLedgerMicros(costUsdMicros(partial, plan.pricing), plan.usdPerLedgerUnit);
  return Math.max(reported, priced);
}
