import {
  estimateRequest,
  estimateTokensFromUtf8Bytes,
  findPricing,
  scalePricing,
  usdMicrosToLedgerMicros,
  REQUEST_OVERHEAD_TOKENS,
  type ModelPricing,
} from './pricing.js';
import type { ProviderAdapter } from './providers/types.js';

/**
 * The pre-flight reservation for one request: how much the intent entry
 * holds against the caps. It is the ONLY cap guard (settlement is unguarded
 * by design), so it must bound the whole billable request (S-2) — or the
 * request is refused before anything is forwarded.
 */
export type ReservationPlan =
  | {
      ok: true;
      /** The row settlement prices usage with; null ⇒ only a reported cost (or the reservation) settles. */
      pricing: ModelPricing | null;
      estimateLedgerMicros: number;
      /** Upper bound on billed input tokens — the stream settle's fallback. */
      inputTokensBound: number;
    }
  | { ok: false; code: 'MODEL_UNPRICED' | 'COST_UNBOUNDED'; reason: string };

export function planReservation(args: {
  adapter: ProviderAdapter;
  body: Readonly<Record<string, unknown>>;
  model: string;
  pricingTable: readonly ModelPricing[];
  perTxMaxMicros: number;
  usdPerLedgerUnit: number;
}): ReservationPlan {
  const { adapter, body, model } = args;
  const profiled = adapter.profileRequest(body);
  if (!profiled.ok) {
    return { ok: false, code: 'COST_UNBOUNDED', reason: profiled.reason };
  }
  const profile = profiled.profile;
  const models = [model, ...profile.fallbackModels];
  const rows = models.map((candidate) => findPricing(candidate, args.pricingTable));

  if (rows.some((row) => row === null)) {
    if (adapter.name !== 'openrouter') {
      // No price → no metering → no spend (R1).
      return {
        ok: false,
        code: 'MODEL_UNPRICED',
        reason: `model '${model}' has no pricing entry — cannot meter it (fail-closed); extend MANDARE_PRICING_PATH`,
      };
    }
    // OpenRouter's reported cost is authoritative (Q14): an unpriced model
    // (or fallback) reserves the full per-tx cap and settles what it reports.
    return {
      ok: true,
      pricing: null,
      estimateLedgerMicros: args.perTxMaxMicros,
      inputTokensBound:
        estimateTokensFromUtf8Bytes(Buffer.byteLength(JSON.stringify(body), 'utf8')) +
        REQUEST_OVERHEAD_TOKENS +
        profile.fixedInputTokens +
        profile.images * adapter.imageTokensCeiling,
    };
  }

  // Every candidate model is priced: reserve for the most expensive one a
  // router may fall back to, under any surcharge the request selects.
  let usdMicros = 0;
  let inputTokensBound = 0;
  const priced = (rows as ModelPricing[]).map((row) => scalePricing(row, profile.priceMultiplier));
  for (const row of priced) {
    const estimate = estimateRequest({
      body,
      pricing: row,
      profile,
      imageTokensCeiling: adapter.imageTokensCeiling,
    });
    if (!estimate.ok) {
      return { ok: false, code: 'COST_UNBOUNDED', reason: estimate.reason };
    }
    usdMicros = Math.max(usdMicros, estimate.usdMicros);
    inputTokensBound = Math.max(inputTokensBound, estimate.inputTokens);
  }
  return {
    ok: true,
    // With fallbacks the model that ran is unknown up front: settle from the
    // reported cost, else at the (worst-case) reservation — never at the
    // primary's cheaper rate.
    pricing: priced.length === 1 ? (priced[0] as ModelPricing) : null,
    estimateLedgerMicros: usdMicrosToLedgerMicros(usdMicros, args.usdPerLedgerUnit),
    inputTokensBound,
  };
}
