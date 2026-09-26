import {
  estimateRequest,
  findPricing,
  scalePricing,
  usdMicrosToLedgerMicros,
  type ModelPricing,
} from './pricing.js';
import {
  openrouterBaseModel,
  perImageUsdMicros,
  priceCeiling,
  withByokFee,
  withPriceCeiling,
  worstCaseRow,
} from './openrouter-spend.js';
import type { ProviderAdapter, RequestProfile } from './providers/types.js';

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
      /** What the door forwards: the agent's body, plus an OpenRouter price ceiling. */
      forwardBody: Record<string, unknown>;
    }
  | { ok: false; code: 'MODEL_UNPRICED' | 'COST_UNBOUNDED'; reason: string };

type Refusal = Extract<ReservationPlan, { ok: false }>;

const unbounded = (reason: string): Refusal => ({ ok: false, code: 'COST_UNBOUNDED', reason });

export function planReservation(args: {
  adapter: ProviderAdapter;
  body: Readonly<Record<string, unknown>>;
  model: string;
  pricingTable: readonly ModelPricing[];
  usdPerLedgerUnit: number;
}): ReservationPlan {
  const { adapter, body, model } = args;
  const profiled = adapter.profileRequest(body);
  if (!profiled.ok) {
    return unbounded(profiled.reason);
  }
  const profile = profiled.profile;
  const openrouter = adapter.name === 'openrouter';

  // Every candidate a router may run — the model and its fallbacks — must be
  // priced (R1): no price → no metering → no spend, on every provider. Since
  // S10-fix 2D that includes OpenRouter, whose reported cost is authoritative
  // at settlement (Q14) but bounded by nothing at reservation time.
  const rows: ModelPricing[] = [];
  for (const candidate of [model, ...profile.fallbackModels]) {
    const base = openrouter ? openrouterBaseModel(candidate) : { ok: true as const, model: candidate };
    if (!base.ok) {
      return unbounded(base.reason);
    }
    const row = findPricing(base.model, args.pricingTable);
    if (row === null) {
      return {
        ok: false,
        code: 'MODEL_UNPRICED',
        reason: `model '${candidate.slice(0, 128)}' has no pricing entry — cannot meter it (fail-closed); extend MANDARE_PRICING_PATH`,
      };
    }
    rows.push(scalePricing(row, profile.priceMultiplier));
  }

  // Reserve for the most a router may bill: every rate at the costliest
  // candidate's, under any surcharge the request selects.
  const row = worstCaseRow(rows, adapter.imageTokensCeiling);
  const plan = openrouter ? planOpenRouter(args, profile, row) : planDirect(args, profile, row);
  if (!plan.ok) {
    return plan;
  }
  return {
    ...plan,
    // With fallbacks the model that ran is unknown up front: settle from the
    // reported cost, else at the (worst-case) reservation — never at the
    // primary's cheaper rate.
    pricing: rows.length === 1 ? row : null,
  };
}

type Planned = Omit<Extract<ReservationPlan, { ok: true }>, 'pricing'> | Refusal;

function planDirect(
  args: { adapter: ProviderAdapter; body: Readonly<Record<string, unknown>>; usdPerLedgerUnit: number },
  profile: RequestProfile,
  row: ModelPricing
): Planned {
  const estimate = estimateRequest({
    body: args.body,
    pricing: row,
    profile,
    imageTokensCeiling: args.adapter.imageTokensCeiling,
  });
  if (!estimate.ok) {
    return unbounded(estimate.reason);
  }
  return {
    ok: true,
    estimateLedgerMicros: usdMicrosToLedgerMicros(estimate.usdMicros, args.usdPerLedgerUnit),
    inputTokensBound: estimate.inputTokens,
    forwardBody: { ...args.body },
  };
}

/**
 * OpenRouter: the row's rates hold only on endpoints priced at or below them,
 * only below the row's context window, and only for what `max_price` names —
 * so the call is forwarded under a price ceiling, refused past the window,
 * and reserved for cache writes, per-image fees and the BYOK fee on top.
 */
function planOpenRouter(
  args: { adapter: ProviderAdapter; body: Readonly<Record<string, unknown>>; usdPerLedgerUnit: number },
  profile: RequestProfile,
  row: ModelPricing
): Planned {
  const { adapter, body } = args;
  if (row.maxInputTokens === undefined) {
    return unbounded(
      `the pricing row for '${row.model}' names no context window (maxInputTokens) — through OpenRouter its long-context rate overrides are unbounded; refusing (fail-closed)`
    );
  }
  // OpenRouter enables prompt caching by model capability: a row that states
  // a cache-write rate says the model bills writes, breakpoint or not.
  const cacheWrite =
    profile.cacheWrite === 'none' && row.cacheWriteUsdPerM !== undefined ? '5m' : profile.cacheWrite;
  const estimate = estimateRequest({
    body,
    pricing: row,
    profile: { ...profile, cacheWrite },
    imageTokensCeiling: adapter.imageTokensCeiling,
  });
  if (!estimate.ok) {
    return unbounded(estimate.reason);
  }
  if (estimate.inputTokens >= row.maxInputTokens) {
    return unbounded(
      `the request may carry ${estimate.inputTokens} input tokens, at or past the ${row.maxInputTokens}-token window of '${row.model}' — OpenRouter bills long-context rates there that no row prices; refusing (fail-closed)`
    );
  }
  // An endpoint may bill images per image on top of their tokens: reserve
  // the per-image ceiling it is held to as well.
  const imageFees = profile.images * perImageUsdMicros(row, adapter.imageTokensCeiling);
  return {
    ok: true,
    estimateLedgerMicros: usdMicrosToLedgerMicros(
      withByokFee(estimate.usdMicros + imageFees),
      args.usdPerLedgerUnit
    ),
    inputTokensBound: estimate.inputTokens,
    forwardBody: withPriceCeiling(body, priceCeiling(row, profile.images, adapter.imageTokensCeiling)),
  };
}
