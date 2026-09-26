import type { UsageTokens } from '../pricing.js';
import type { SseEvent } from '../sse.js';

/**
 * Provider adapters are deliberately THIN: Mandare proxies each provider's
 * NATIVE protocol (no lossy unified-API transform — agents point their SDK
 * base URL at the gateway and everything else passes through). An adapter
 * only knows how to (a) shape the outgoing request so usage accounting is
 * included, and (b) extract usage/cost from responses and streams per the
 * BUILD-DECISIONS Q16 rules.
 */

export type ProviderName = 'anthropic' | 'openai' | 'openrouter';

export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

export interface ParsedUsage extends UsageTokens {
  /** Authoritative provider-reported cost in USD micros (OpenRouter only). */
  costUsdMicros: number | null;
  /**
   * The reported cost is only PART of the bill (a BYOK call whose upstream
   * provider cost is missing): settlement treats the outcome as unknown and
   * never settles below the reservation.
   */
  costIsPartial?: true;
}

export interface StreamUsageParser {
  onEvent(event: SseEvent): void;
  /** Best usage picture so far; null if none seen yet. */
  usage(): ParsedUsage | null;
  /**
   * True once the provider's AUTHORITATIVE end-of-stream usage has arrived
   * together with its end-of-stream marker (Anthropic: a usage-carrying
   * `message_delta` and `message_stop`; OpenAI-like: the usage chunk and
   * `[DONE]`). Anything less is a partial picture, and a partial picture is
   * never allowed to settle a call below its reservation (S-1).
   */
  hasFinalUsage(): boolean;
  /**
   * UTF-8 bytes of generated output observed across EVERY delta type (text,
   * thinking, tool-call JSON, refusals) — the token upper bound used when a
   * stream ends without its final usage (Q16, S-1).
   */
  observedOutputBytes(): number;
}

/**
 * What a request can be billed for BEYOND its own bytes (S-2). The estimator
 * bounds text by its UTF-8 bytes (tokens ≤ bytes); this profile carries the
 * parts that bound does not cover, as found by the provider's adapter.
 */
export interface RequestProfile {
  /** Image inputs, each priced at the model's (or provider's) per-image token ceiling. */
  images: number;
  /** Fixed hidden prompt tokens (built-in tool definitions and their system prompts). */
  fixedInputTokens: number;
  /** Media whose token cost only the context window bounds (PDFs, uploaded files, encrypted thinking). */
  unsizedInput: boolean;
  /** Completions generated per request (OpenAI `n`), each with the full output budget. */
  completions: number;
  /** Request bytes the provider bills at the OUTPUT rate (predicted outputs). */
  outputRateBytes: number;
  /** Output tokens a request may add beyond its output cap (an OpenRouter reasoning budget). */
  extraOutputTokens: number;
  /** Prompt-cache writes the request asks for: input priced at the write rate. */
  cacheWrite: 'none' | '5m' | '1h';
  /** Rate multiplier the request selects (Anthropic `inference_geo: "us"` → 1.1). */
  priceMultiplier: number;
  /** Models a router may fall back to (OpenRouter `models`): priced at the most expensive. */
  fallbackModels: readonly string[];
}

export type ProfileResult =
  | { ok: true; profile: RequestProfile }
  /** A billable part the door cannot bound — refused (COST_UNBOUNDED), never forwarded. */
  | { ok: false; reason: string };

export const PLAIN_TEXT_PROFILE: RequestProfile = {
  images: 0,
  fixedInputTokens: 0,
  unsizedInput: false,
  completions: 1,
  outputRateBytes: 0,
  extraOutputTokens: 0,
  cacheWrite: 'none',
  priceMultiplier: 1,
  fallbackModels: [],
};

export interface ProviderAdapter {
  name: ProviderName;
  /** Appended to the provider base URL, e.g. '/messages'. */
  endpointPath: string;
  /** Per-image token ceiling when the pricing row names none (provider-documented maximum). */
  imageTokensCeiling: number;
  headers(apiKey: string): Record<string, string>;
  /** Q16 injections (e.g. stream_options.include_usage). Returns a NEW object. */
  prepareBody(body: Readonly<Record<string, unknown>>, stream: boolean): Record<string, unknown>;
  /** Classify what the request can be billed for beyond its bytes (S-2). */
  profileRequest(body: Readonly<Record<string, unknown>>): ProfileResult;
  parseUsageFromJson(bodyText: string): ParsedUsage | null;
  newStreamParser(): StreamUsageParser;
}

export function emptyUsage(): ParsedUsage {
  return {
    tokensIn: 0,
    tokensOut: 0,
    cacheWriteTokens: 0,
    cacheReadTokens: 0,
    costUsdMicros: null,
  };
}

export function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null
    ? (value as Record<string, unknown>)
    : null;
}

export function nonNegativeInt(value: unknown): number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : 0;
}

/**
 * UTF-8 byte total of every string inside a stream delta, skipping keys that
 * carry protocol metadata rather than generated output. Counting by exclusion
 * keeps the bound conservative for delta shapes this code has never seen: a
 * new output channel is counted by default instead of silently dropped.
 */
export function outputBytesIn(value: unknown, skipKeys: ReadonlySet<string>): number {
  let total = 0;
  const pending: unknown[] = [value];
  while (pending.length > 0) {
    const next = pending.pop();
    if (typeof next === 'string') {
      total += Buffer.byteLength(next, 'utf8');
    } else if (Array.isArray(next)) {
      for (const item of next) pending.push(item);
    } else if (typeof next === 'object' && next !== null) {
      for (const [key, child] of Object.entries(next)) {
        if (!skipKeys.has(key)) {
          pending.push(child);
        }
      }
    }
  }
  return total;
}
