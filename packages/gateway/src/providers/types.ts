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
      pending.push(...next);
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
