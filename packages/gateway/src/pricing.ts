import { readFileSync } from 'node:fs';

import { PLAIN_TEXT_PROFILE, type RequestProfile } from './providers/types.js';

/**
 * Model pricing for pre-flight cost RESERVATION and for token-based true-up
 * on providers that do not return an authoritative cost (Anthropic, OpenAI).
 * OpenRouter responses carry an authoritative `usage.cost` and never touch
 * this table for settlement (BUILD-DECISIONS Q14/Q16).
 *
 * Fail-closed contract: a model with no pricing entry CANNOT be metered on a
 * direct provider, so the gateway refuses it (unknown price ⇒ unbounded
 * spend ⇒ no). Operators extend the table via MANDARE_PRICING_PATH.
 *
 * Prices are USD per MILLION tokens (integers keep the math exact); pinned
 * 2026-07 from the public provider price pages — the table is config, not
 * truth, and true costs land at settlement.
 */

export interface ModelPricing {
  /** Longest matching prefix wins, e.g. 'claude-haiku-4-5'. */
  prefix: string;
  inUsdPerM: number;
  outUsdPerM: number;
  /** Defaults: write 1.25× input, read 0.1× input (both providers' shape). */
  cacheWriteUsdPerM?: number;
  /** 1-hour-TTL cache write (Anthropic). Default: 2× input. */
  cacheWrite1hUsdPerM?: number;
  cacheReadUsdPerM?: number;
  /** Hard model output ceiling — the reservation bound when the request sets no max. */
  maxOutputTokens: number;
  /**
   * Context window (input tokens). Bounds a request carrying media whose
   * token cost its bytes do not show (PDFs, uploaded files): absent ⇒ such a
   * request is refused, never reserved at a guess (S-2).
   */
  maxInputTokens?: number;
  /** Per-image token ceiling for this model; absent ⇒ the provider's documented maximum. */
  maxImageTokens?: number;
}

export const DEFAULT_PRICING: readonly ModelPricing[] = [
  { prefix: 'claude-haiku-4-5', inUsdPerM: 1, outUsdPerM: 5, maxOutputTokens: 64_000, maxInputTokens: 200_000 },
  { prefix: 'claude-sonnet-4-5', inUsdPerM: 3, outUsdPerM: 15, maxOutputTokens: 64_000, maxInputTokens: 200_000 },
  { prefix: 'claude-opus-4-5', inUsdPerM: 5, outUsdPerM: 25, maxOutputTokens: 64_000, maxInputTokens: 200_000 },
  { prefix: 'claude-opus-4-1', inUsdPerM: 15, outUsdPerM: 75, maxOutputTokens: 32_000, maxInputTokens: 200_000 },
  { prefix: 'gpt-5-nano', inUsdPerM: 0.05, outUsdPerM: 0.4, maxOutputTokens: 128_000, maxInputTokens: 400_000 },
  { prefix: 'gpt-5-mini', inUsdPerM: 0.25, outUsdPerM: 2, maxOutputTokens: 128_000, maxInputTokens: 400_000 },
  { prefix: 'gpt-5', inUsdPerM: 1.25, outUsdPerM: 10, maxOutputTokens: 128_000, maxInputTokens: 400_000 },
  { prefix: 'gpt-4o-mini', inUsdPerM: 0.15, outUsdPerM: 0.6, maxOutputTokens: 16_384, maxInputTokens: 128_000 },
  { prefix: 'gpt-4o', inUsdPerM: 2.5, outUsdPerM: 10, maxOutputTokens: 16_384, maxInputTokens: 128_000 },
  { prefix: 'gpt-4.1-mini', inUsdPerM: 0.4, outUsdPerM: 1.6, maxOutputTokens: 32_768, maxInputTokens: 1_047_576 },
  { prefix: 'gpt-4.1', inUsdPerM: 2, outUsdPerM: 8, maxOutputTokens: 32_768, maxInputTokens: 1_047_576 },
];

/** Strip a provider org prefix ('anthropic/claude-…' → 'claude-…'). */
function bareModel(model: string): string {
  const slash = model.lastIndexOf('/');
  return slash === -1 ? model : model.slice(slash + 1);
}

export function findPricing(
  model: string,
  table: readonly ModelPricing[] = DEFAULT_PRICING
): ModelPricing | null {
  const bare = bareModel(model);
  let best: ModelPricing | null = null;
  for (const entry of table) {
    if (bare.startsWith(entry.prefix) && (best === null || entry.prefix.length > best.prefix.length)) {
      best = entry;
    }
  }
  return best;
}

/** Merge an operator-supplied JSON pricing file over the defaults (R4: validated). */
export function loadPricingTable(path: string): ModelPricing[] {
  const parsed: unknown = JSON.parse(readFileSync(path, 'utf8'));
  if (!Array.isArray(parsed)) {
    throw new Error(`pricing file ${path} must be a JSON array`);
  }
  const extra = parsed.map((row: unknown, index): ModelPricing => {
    const record = row as Record<string, unknown>;
    if (
      typeof record?.prefix !== 'string' ||
      record.prefix.length === 0 ||
      typeof record.inUsdPerM !== 'number' ||
      typeof record.outUsdPerM !== 'number' ||
      !Number.isInteger(record.maxOutputTokens) ||
      (record.maxOutputTokens as number) < 1
    ) {
      throw new Error(`pricing file ${path}: entry ${index} is malformed`);
    }
    return record as unknown as ModelPricing;
  });
  return [...extra, ...DEFAULT_PRICING];
}

export interface UsageTokens {
  tokensIn: number;
  tokensOut: number;
  cacheWriteTokens: number;
  cacheReadTokens: number;
}

const USD_MICROS_PER_UNIT = 1_000_000;
const TOKENS_PER_MILLION = 1_000_000;

/** Cache rates for a row, filling the documented defaults. */
function cacheRates(pricing: ModelPricing): { write5m: number; write1h: number; read: number } {
  return {
    write5m: pricing.cacheWriteUsdPerM ?? pricing.inUsdPerM * 1.25,
    write1h: pricing.cacheWrite1hUsdPerM ?? pricing.inUsdPerM * 2,
    read: pricing.cacheReadUsdPerM ?? pricing.inUsdPerM * 0.1,
  };
}

/** USD micros for a token usage under a pricing entry (ceil — never undercount). */
export function costUsdMicros(usage: UsageTokens, pricing: ModelPricing): number {
  const rates = cacheRates(pricing);
  const usd =
    (usage.tokensIn * pricing.inUsdPerM +
      usage.tokensOut * pricing.outUsdPerM +
      usage.cacheWriteTokens * rates.write5m +
      usage.cacheReadTokens * rates.read) /
    TOKENS_PER_MILLION;
  return Math.ceil(usd * USD_MICROS_PER_UNIT);
}

/** A row with every rate scaled (a request-selected surcharge, e.g. US-only inference). */
export function scalePricing(pricing: ModelPricing, multiplier: number): ModelPricing {
  if (multiplier === 1) {
    return pricing;
  }
  const rates = cacheRates(pricing);
  return {
    ...pricing,
    inUsdPerM: pricing.inUsdPerM * multiplier,
    outUsdPerM: pricing.outUsdPerM * multiplier,
    cacheWriteUsdPerM: rates.write5m * multiplier,
    cacheWrite1hUsdPerM: rates.write1h * multiplier,
    cacheReadUsdPerM: rates.read * multiplier,
  };
}

/**
 * Prompt tokens a provider adds that are not in the request bytes: the
 * tool-use system prompt (≤ 804 tokens on any Claude model, per the
 * Anthropic pricing page) and chat-format role/turn tokens.
 */
export const REQUEST_OVERHEAD_TOKENS = 1_024;

export type RequestEstimate =
  | {
      ok: true;
      /** Upper bound on billed input tokens (also the stream settle's fallback). */
      inputTokens: number;
      /** Upper bound on billed output tokens. */
      outputTokens: number;
      usdMicros: number;
    }
  | { ok: false; reason: string };

/**
 * Tokenizer-free pre-flight estimate (Q16 allows estimation ONLY here and
 * for aborted streams). The reservation is the ONLY cap guard — settlement
 * applies the provider's bill unguarded, by design — so this must be a TRUE
 * UPPER BOUND on everything the provider can bill for the request:
 *
 * - Input: the UTF-8 bytes of the WHOLE body. A byte-level BPE tokenizer
 *   never emits more tokens than bytes (the base vocabulary is the 256 single
 *   bytes; merges only reduce the count), so this over-counts every script
 *   (S8/S1) — and, unlike `messages`+`system` alone, it covers `tools`,
 *   `response_format` and every other text a provider prices as input (S-2).
 *   Plus the provider's hidden prompt overhead, media at the per-image
 *   ceiling, and — for media only the context window bounds — that window.
 * - Input rate: the cache-WRITE rate when the request asks for cache writes.
 * - Output: the requested cap (never trimmed to a table value that may be
 *   stale) × every completion (`n`), plus prompt bytes billed at the output
 *   rate (predicted outputs).
 *
 * A request this cannot bound (unsized media on a row with no context
 * window) returns ok:false and is refused.
 */
export function estimateRequest(args: {
  body: Readonly<Record<string, unknown>>;
  pricing: ModelPricing;
  profile?: RequestProfile;
  /** Per-image ceiling when the row names none (the adapter's provider maximum). */
  imageTokensCeiling?: number;
}): RequestEstimate {
  const { body, pricing } = args;
  const profile = args.profile ?? PLAIN_TEXT_PROFILE;
  const imageTokens = pricing.maxImageTokens ?? args.imageTokensCeiling ?? 0;
  let inputTokens =
    estimateTokensFromUtf8Bytes(Buffer.byteLength(JSON.stringify(body), 'utf8')) +
    REQUEST_OVERHEAD_TOKENS +
    profile.fixedInputTokens +
    profile.images * imageTokens;
  if (profile.unsizedInput) {
    if (pricing.maxInputTokens === undefined) {
      return {
        ok: false,
        reason: `the request carries media only a context window can bound (PDFs, uploaded files), and the pricing row for '${pricing.prefix}' names none — refusing (fail-closed)`,
      };
    }
    inputTokens = Math.max(inputTokens, pricing.maxInputTokens);
  }
  const outputTokens =
    (requestedOutputCap(body) ?? pricing.maxOutputTokens) * profile.completions +
    estimateTokensFromUtf8Bytes(profile.outputRateBytes);
  const usd =
    (inputTokens * reservationInputRate(pricing, profile.cacheWrite) +
      outputTokens * pricing.outUsdPerM) /
    TOKENS_PER_MILLION;
  return { ok: true, inputTokens, outputTokens, usdMicros: Math.ceil(usd * USD_MICROS_PER_UNIT) };
}

/** The pre-flight estimate in USD micros for a request with no hidden parts. */
export function estimateUsdMicros(args: {
  body: Readonly<Record<string, unknown>>;
  pricing: ModelPricing;
}): number {
  const estimate = estimateRequest(args);
  if (!estimate.ok) {
    throw new Error(estimate.reason);
  }
  return estimate.usdMicros;
}

/**
 * The output cap the provider enforces. With both fields set, the larger
 * (a provider honoring either can never bill past it).
 */
function requestedOutputCap(body: Readonly<Record<string, unknown>>): number | null {
  const caps = [body.max_tokens, body.max_completion_tokens].filter(
    (value): value is number => typeof value === 'number' && Number.isInteger(value) && value > 0
  );
  return caps.length === 0 ? null : Math.max(...caps);
}

/** Input priced at the highest rate the request can trigger (cache writes cost more). */
function reservationInputRate(pricing: ModelPricing, cacheWrite: RequestProfile['cacheWrite']): number {
  const rates = cacheRates(pricing);
  if (cacheWrite === '1h') {
    return Math.max(pricing.inUsdPerM, rates.write5m, rates.write1h);
  }
  if (cacheWrite === '5m') {
    return Math.max(pricing.inUsdPerM, rates.write5m);
  }
  return pricing.inUsdPerM;
}

/**
 * Upper-bound token count from a UTF-8 byte length — used to settle a stream
 * that carried no authoritative usage (aborted, or a usage-less endpoint).
 * A byte-level BPE tokenizer never emits more tokens than the input's UTF-8
 * byte count (see estimateUsdMicros), so counting bytes can never UNDER-record
 * spend at settlement, for any script (S8/S1). Over-recording on an aborted
 * stream is the safe direction for a cap; the true-up reconciles later.
 */
export function estimateTokensFromUtf8Bytes(utf8Bytes: number): number {
  return utf8Bytes;
}

/**
 * Convert USD micros into the ledger currency at the operator-configured
 * rate (usdPerLedgerUnit = how many USD one ledger unit buys). Ceil — the
 * ledger never under-records spend.
 */
export function usdMicrosToLedgerMicros(usdMicros: number, usdPerLedgerUnit: number): number {
  if (!(usdPerLedgerUnit > 0)) {
    throw new Error('usdPerLedgerUnit must be positive');
  }
  // Tiny epsilon strips float noise (1_160_000/1.16 → 1_000_000.0000000001)
  // before the conservative ceil.
  return Math.ceil(usdMicros / usdPerLedgerUnit - 1e-6);
}
