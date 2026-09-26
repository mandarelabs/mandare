import type { SseEvent } from '../sse.js';
import { ANTHROPIC_IMAGE_TOKENS_MAX, profileAnthropicRequest } from './anthropic-profile.js';
import {
  asRecord,
  emptyUsage,
  nonNegativeInt,
  outputBytesIn,
  type ParsedUsage,
  type ProviderAdapter,
  type StreamUsageParser,
} from './types.js';

/**
 * Anthropic Messages API adapter. Usage true-up per BUILD-DECISIONS Q16:
 * merge `message_start` (input tokens, incl. cache fields) with the FINAL
 * `message_delta` (cumulative output tokens) — the final delta's usage is
 * authoritative for output. Anthropic returns no cost, so settlement prices
 * the token counts through the pricing table.
 */

function usageFromRecord(usage: Record<string, unknown>, into: ParsedUsage): ParsedUsage {
  // The TTL breakdown: the 1-hour share bills at 2× input, not 1.25× (S-4).
  const creation = asRecord(usage.cache_creation);
  const oneHour = creation === null ? null : nonNegativeInt(creation.ephemeral_1h_input_tokens);
  const fiveMinute = creation === null ? 0 : nonNegativeInt(creation.ephemeral_5m_input_tokens);
  const cacheWriteTokens =
    'cache_creation_input_tokens' in usage
      ? nonNegativeInt(usage.cache_creation_input_tokens)
      : into.cacheWriteTokens;
  // Server-side tools bill per use on top of tokens (web search: $10/1,000).
  const webSearches = asRecord(usage.server_tool_use)?.web_search_requests;
  return {
    ...into,
    tokensIn: 'input_tokens' in usage ? nonNegativeInt(usage.input_tokens) : into.tokensIn,
    tokensOut: 'output_tokens' in usage ? nonNegativeInt(usage.output_tokens) : into.tokensOut,
    // A breakdown that exceeds the total wins: never under-count a write.
    cacheWriteTokens: Math.max(cacheWriteTokens, fiveMinute + (oneHour ?? 0)),
    cacheReadTokens:
      'cache_read_input_tokens' in usage
        ? nonNegativeInt(usage.cache_read_input_tokens)
        : into.cacheReadTokens,
    ...(oneHour === null ? {} : { cacheWrite1hTokens: oneHour }),
    ...(webSearches === undefined ? {} : { webSearchRequests: nonNegativeInt(webSearches) }),
    costUsdMicros: null,
  };
}

/**
 * Delta keys that are protocol metadata, not generated output. Everything else
 * in a `content_block_delta` counts: text, thinking, tool-input JSON — and any
 * delta type added later (S-1: counting only `text` let thinking and tool
 * calls stream for free).
 */
const NON_OUTPUT_DELTA_KEYS: ReadonlySet<string> = new Set(['type', 'signature']);

class AnthropicStreamParser implements StreamUsageParser {
  private merged: ParsedUsage | null = null;
  private outputBytes = 0;
  private sawDeltaUsage = false;
  private sawStop = false;

  onEvent(event: SseEvent): void {
    const data = asRecord(safeJson(event.data));
    if (data === null) {
      return;
    }
    if (data.type === 'message_start') {
      const usage = asRecord(asRecord(data.message)?.usage);
      if (usage !== null) {
        this.merged = usageFromRecord(usage, this.merged ?? emptyUsage());
      }
      return;
    }
    if (data.type === 'message_delta') {
      const usage = asRecord(data.usage);
      if (usage !== null) {
        // Cumulative — each delta overwrites, the final one wins (Q16).
        this.merged = usageFromRecord(usage, this.merged ?? emptyUsage());
        this.sawDeltaUsage = true;
      }
      return;
    }
    if (data.type === 'message_stop') {
      this.sawStop = true;
      return;
    }
    if (data.type === 'content_block_delta') {
      // UTF-8 bytes, not UTF-16 length: the settle-side fallback treats this
      // as a token UPPER bound (tokens ≤ bytes), so a token-dense (CJK)
      // aborted stream cannot under-record output cost (S8/S1).
      this.outputBytes += outputBytesIn(data.delta, NON_OUTPUT_DELTA_KEYS);
    }
  }

  usage(): ParsedUsage | null {
    return this.merged;
  }

  hasFinalUsage(): boolean {
    return this.sawDeltaUsage && this.sawStop;
  }

  observedOutputBytes(): number {
    return this.outputBytes;
  }
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

export const anthropicAdapter: ProviderAdapter = {
  name: 'anthropic',
  // ANTHROPIC_BASE_URL convention excludes /v1, so the adapter carries it.
  endpointPath: '/v1/messages',
  imageTokensCeiling: ANTHROPIC_IMAGE_TOKENS_MAX,
  headers(apiKey: string): Record<string, string> {
    return {
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json',
    };
  },
  prepareBody(body, stream): Record<string, unknown> {
    return { ...body, stream };
  },
  profileRequest: profileAnthropicRequest,
  parseUsageFromJson(bodyText): ParsedUsage | null {
    const usage = asRecord(asRecord(safeJson(bodyText))?.usage);
    return usage === null ? null : usageFromRecord(usage, emptyUsage());
  },
  newStreamParser(): StreamUsageParser {
    return new AnthropicStreamParser();
  },
};
