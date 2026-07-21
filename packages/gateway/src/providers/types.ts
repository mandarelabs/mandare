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
}

export interface StreamUsageParser {
  onEvent(event: SseEvent): void;
  /** Best usage picture so far; null if none seen yet. */
  usage(): ParsedUsage | null;
  /** Assistant text characters observed — aborted-stream estimation (Q16). */
  observedTextChars(): number;
}

export interface ProviderAdapter {
  name: ProviderName;
  /** Appended to the provider base URL, e.g. '/messages'. */
  endpointPath: string;
  headers(apiKey: string): Record<string, string>;
  /** Q16 injections (e.g. stream_options.include_usage). Returns a NEW object. */
  prepareBody(body: Readonly<Record<string, unknown>>, stream: boolean): Record<string, unknown>;
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
