import { PLAIN_TEXT_PROFILE, type RequestProfile } from './providers/types.js';
import type { ModelPricing } from './pricing-table.js';

/**
 * Cost math over the price table (pricing-table.ts): the pre-flight
 * RESERVATION (the only cap guard) and the token-based settlement for
 * providers that return no cost. The table is config, not truth — true costs
 * land at settlement, and a Storno entry reconciles against provider billing.
 */

export { DEFAULT_PRICING, findPricing, loadPricingTable } from './pricing-table.js';
export type { ModelPricing } from './pricing-table.js';

export interface UsageTokens {
  /** Uncached input tokens (audio included — see audioInTokens). */
  tokensIn: number;
  /** Output tokens (audio included — see audioOutTokens). */
  tokensOut: number;
  /** Cache-write tokens, every TTL (the 1-hour share is cacheWrite1hTokens). */
  cacheWriteTokens: number;
  cacheReadTokens: number;
  /** Of cacheWriteTokens: written with the 1-hour TTL (billed at 2× input, not 1.25×). */
  cacheWrite1hTokens?: number;
  /** Of tokensIn / tokensOut: audio tokens, billed at audio rates. */
  audioInTokens?: number;
  audioOutTokens?: number;
  /** Anthropic server-side web searches (a per-request fee on top of tokens). */
  webSearchRequests?: number;
}

const USD_MICROS_PER_UNIT = 1_000_000;
const TOKENS_PER_MILLION = 1_000_000;

/** Anthropic web search: $10 per 1,000 searches, on top of tokens (Anthropic pricing page, 2026-09). */
export const WEB_SEARCH_USD_MICROS_PER_REQUEST = 10_000;

/**
 * Audio tokens on a row that names no audio rate: deliberately high ($100/M
 * in, $200/M out — at or above every audio token rate OpenAI has published),
 * so an unpriced dimension is over-recorded, never billed as text. Requests
 * that ask for audio are refused at the door (S-2); this is the backstop.
 */
const AUDIO_IN_FALLBACK_USD_PER_M = 100;
const AUDIO_OUT_FALLBACK_USD_PER_M = 200;

/**
 * Cache rates for a row, filling the documented multipliers. A read with no
 * stated rate is priced at the full input rate: the old 0.1× default
 * under-recorded gpt-4o (0.5×) and gpt-4.1 (0.25×) five- and 2.5-fold (S-4).
 */
export function cacheRates(pricing: ModelPricing): { write5m: number; write1h: number; read: number } {
  return {
    write5m: pricing.cacheWriteUsdPerM ?? pricing.inUsdPerM * 1.25,
    write1h: pricing.cacheWrite1hUsdPerM ?? pricing.inUsdPerM * 2,
    read: pricing.cacheReadUsdPerM ?? pricing.inUsdPerM,
  };
}

/** A sub-count can never exceed the count it is part of (hostile usage stays sane). */
function share(part: number | undefined, whole: number): number {
  return Math.min(part ?? 0, whole);
}

/** USD micros for a token usage under a pricing entry (ceil — never undercount). */
export function costUsdMicros(usage: UsageTokens, pricing: ModelPricing): number {
  const rates = cacheRates(pricing);
  const write1h = share(usage.cacheWrite1hTokens, usage.cacheWriteTokens);
  const audioIn = share(usage.audioInTokens, usage.tokensIn);
  const audioOut = share(usage.audioOutTokens, usage.tokensOut);
  const tokenUsd =
    ((usage.tokensIn - audioIn) * pricing.inUsdPerM +
      audioIn * (pricing.audioInUsdPerM ?? AUDIO_IN_FALLBACK_USD_PER_M) +
      (usage.tokensOut - audioOut) * pricing.outUsdPerM +
      audioOut * (pricing.audioOutUsdPerM ?? AUDIO_OUT_FALLBACK_USD_PER_M) +
      (usage.cacheWriteTokens - write1h) * rates.write5m +
      write1h * rates.write1h +
      usage.cacheReadTokens * rates.read) /
    TOKENS_PER_MILLION;
  return (
    Math.ceil(tokenUsd * USD_MICROS_PER_UNIT) +
    (usage.webSearchRequests ?? 0) * WEB_SEARCH_USD_MICROS_PER_REQUEST
  );
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
    audioInUsdPerM: (pricing.audioInUsdPerM ?? AUDIO_IN_FALLBACK_USD_PER_M) * multiplier,
    audioOutUsdPerM: (pricing.audioOutUsdPerM ?? AUDIO_OUT_FALLBACK_USD_PER_M) * multiplier,
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
 *   stale) × every completion (`n`), plus a budget the provider may spend
 *   outside the cap (OpenRouter reasoning), plus prompt bytes billed at the
 *   output rate (predicted outputs).
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
        reason: `the request carries media only a context window can bound (PDFs, uploaded files), and the pricing row for '${pricing.model}' names none — refusing (fail-closed)`,
      };
    }
    inputTokens = Math.max(inputTokens, pricing.maxInputTokens);
  }
  const outputTokens =
    (requestedOutputCap(body) ?? pricing.maxOutputTokens) * profile.completions +
    profile.extraOutputTokens +
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
