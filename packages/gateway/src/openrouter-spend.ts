import { cacheRates, type ModelPricing } from './pricing.js';
import { asRecord } from './providers/types.js';

/**
 * OpenRouter spend bounds (S10-fix 2D). OpenRouter's reported cost settles a
 * call unguarded (Q14), so the reservation has to bound whatever OpenRouter
 * can bill — across every model, endpoint, variant and key a request can end
 * up on. Source: openrouter.ai/docs (provider routing `max_price`, model
 * variants, service tiers, BYOK, usage accounting) and the public
 * `/api/v1/models/{id}/endpoints` pricing, as of 2026-09-26.
 *
 * - Model: only a priced row can run (no row ⇒ MODEL_UNPRICED; `openrouter/
 *   auto` can route anywhere, so no row prices it).
 * - Endpoint: `provider.max_price` holds every endpoint at or below the row's
 *   prompt/completion rates. Regional and priority-tier endpoints differ from
 *   list price only by a factor on those rates (their cache rates scale with
 *   them), so the ceiling excludes them.
 * - Dimensions `max_price` does not name are reserved or refused: cache writes
 *   at the row's write rate, reasoning budgets at the output rate, long-context
 *   overrides refused at the row's window, fee-adding variants refused.
 * - Key: a BYOK call pays the provider AND a fee on OpenRouter credits, so the
 *   reservation carries the fee on top of the list-price bound.
 */

/** OpenRouter's BYOK fee: 5% of what the call would cost on OpenRouter credits. */
export const BYOK_FEE_PERCENT = 5;

/** A reservation (USD micros) raised by the BYOK fee a call may add. */
export function withByokFee(usdMicros: number): number {
  return Math.ceil((usdMicros * (100 + BYOK_FEE_PERCENT)) / 100);
}

/**
 * Model-id variants that can only cost the same or less than the base model:
 * `:free` ($0, own rate limits) and `:floor` (price-sorted routing; admits the
 * discounted flex tier). Everything else is refused: `:online` adds per-result
 * web-search fees, `:nitro` admits priority (fast) tier endpoints, `:thinking`
 * / `:extended` / `:exacto` / `:batch` change what runs, and a suffix this code
 * has never seen is unknown.
 */
const COST_NEUTRAL_VARIANTS: ReadonlySet<string> = new Set(['free', 'floor']);

export type BaseModel = { ok: true; model: string } | { ok: false; reason: string };

/** The id a pricing row must match: the model without its cost-neutral variants. */
export function openrouterBaseModel(model: string): BaseModel {
  const [base = '', ...variants] = model.split(':');
  const costly = variants.find((variant) => !COST_NEUTRAL_VARIANTS.has(variant));
  if (costly !== undefined) {
    return {
      ok: false,
      reason: `model variant ':${costly.slice(0, 32)}' on '${base.slice(0, 64)}' can add fees no price table bounds (web search, priority tiers) — refusing (fail-closed)`,
    };
  }
  return { ok: true, model: base };
}

function maxOf(values: readonly number[]): number {
  return Math.max(...values);
}

/**
 * The most any candidate can bill per unit: each rate at its maximum across
 * the candidates (a router may fall back to any of them, on any endpoint
 * under the ceiling), the output ceiling at its maximum, and the context
 * window at its MINIMUM (long-context rates may start at the smallest edge).
 */
export function worstCaseRow(rows: readonly ModelPricing[], imageTokensCeiling: number): ModelPricing {
  if (rows.length === 1) {
    return rows[0] as ModelPricing;
  }
  const rates = rows.map(cacheRates);
  const windows = rows.map((row) => row.maxInputTokens);
  const audioIn = rows.flatMap((row) => (row.audioInUsdPerM === undefined ? [] : [row.audioInUsdPerM]));
  const audioOut = rows.flatMap((row) => (row.audioOutUsdPerM === undefined ? [] : [row.audioOutUsdPerM]));
  return {
    model: rows.map((row) => row.model).join(' | '),
    inUsdPerM: maxOf(rows.map((row) => row.inUsdPerM)),
    outUsdPerM: maxOf(rows.map((row) => row.outUsdPerM)),
    // Stated only if some row states one: a stated write rate is what makes
    // the reservation assume cache writes without a breakpoint.
    ...(rows.some((row) => row.cacheWriteUsdPerM !== undefined)
      ? { cacheWriteUsdPerM: maxOf(rates.map((rate) => rate.write5m)) }
      : {}),
    cacheWrite1hUsdPerM: maxOf(rates.map((rate) => rate.write1h)),
    cacheReadUsdPerM: maxOf(rates.map((rate) => rate.read)),
    ...(audioIn.length === rows.length ? { audioInUsdPerM: maxOf(audioIn) } : {}),
    ...(audioOut.length === rows.length ? { audioOutUsdPerM: maxOf(audioOut) } : {}),
    maxOutputTokens: maxOf(rows.map((row) => row.maxOutputTokens)),
    ...(windows.every((window): window is number => window !== undefined)
      ? { maxInputTokens: Math.min(...windows) }
      : {}),
    maxImageTokens: maxOf(rows.map((row) => row.maxImageTokens ?? imageTokensCeiling)),
  };
}

/** A per-image fee ceiling (USD micros): the image's token ceiling at the input rate. */
export function perImageUsdMicros(row: ModelPricing, imageTokensCeiling: number): number {
  return Math.ceil((row.maxImageTokens ?? imageTokensCeiling) * row.inUsdPerM);
}

/** `provider.max_price`: USD per million tokens, per request, per image. */
export interface PriceCeiling {
  prompt: number;
  completion: number;
  request: number;
  image?: number;
  audio?: number;
}

export function priceCeiling(row: ModelPricing, images: number, imageTokensCeiling: number): PriceCeiling {
  return {
    prompt: row.inUsdPerM,
    completion: row.outUsdPerM,
    request: 0,
    ...(images > 0 ? { image: perImageUsdMicros(row, imageTokensCeiling) / 1_000_000 } : {}),
  };
}

/** The `max_price` fields OpenRouter defines; anything else an agent sends is dropped. */
const MAX_PRICE_FIELDS = ['prompt', 'completion', 'request', 'image', 'audio'] as const;

/** An agent-supplied price (number or numeric string, per the OpenRouter schema), or null. */
function agentPrice(value: unknown): number | null {
  const parsed =
    typeof value === 'number' ? value : typeof value === 'string' && /^\d+(\.\d+)?$/.test(value) ? Number(value) : NaN;
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
}

/**
 * The body to forward: the agent's own `provider.max_price` merged field by
 * field with the door's ceiling under min() — an agent can lower the ceiling,
 * never raise it (R4). Agent fields the door does not set are kept only when
 * they are valid prices (they can only narrow routing further); keys
 * OpenRouter does not define are dropped.
 */
export function withPriceCeiling(
  body: Readonly<Record<string, unknown>>,
  ceiling: PriceCeiling
): Record<string, unknown> {
  const provider = asRecord(body.provider) ?? {};
  const agentRecord = asRecord(provider.max_price);
  const agent = agentRecord === null || Array.isArray(agentRecord) ? {} : agentRecord;
  const merged: Record<string, number> = {};
  for (const key of MAX_PRICE_FIELDS) {
    const ours = ceiling[key];
    const theirs = agentPrice(agent[key]);
    if (ours !== undefined) {
      merged[key] = theirs === null ? ours : Math.min(theirs, ours);
    } else if (theirs !== null) {
      merged[key] = theirs;
    }
  }
  return { ...body, provider: { ...provider, max_price: merged } };
}
