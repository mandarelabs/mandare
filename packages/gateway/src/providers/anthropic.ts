import type { SseEvent } from '../sse.js';
import {
  asRecord,
  emptyUsage,
  nonNegativeInt,
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
  return {
    ...into,
    tokensIn: 'input_tokens' in usage ? nonNegativeInt(usage.input_tokens) : into.tokensIn,
    tokensOut: 'output_tokens' in usage ? nonNegativeInt(usage.output_tokens) : into.tokensOut,
    cacheWriteTokens:
      'cache_creation_input_tokens' in usage
        ? nonNegativeInt(usage.cache_creation_input_tokens)
        : into.cacheWriteTokens,
    cacheReadTokens:
      'cache_read_input_tokens' in usage
        ? nonNegativeInt(usage.cache_read_input_tokens)
        : into.cacheReadTokens,
    costUsdMicros: null,
  };
}

class AnthropicStreamParser implements StreamUsageParser {
  private merged: ParsedUsage | null = null;
  private textChars = 0;

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
      }
      return;
    }
    if (data.type === 'content_block_delta') {
      const delta = asRecord(data.delta);
      if (typeof delta?.text === 'string') {
        this.textChars += delta.text.length;
      }
    }
  }

  usage(): ParsedUsage | null {
    return this.merged;
  }

  observedTextChars(): number {
    return this.textChars;
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
  parseUsageFromJson(bodyText): ParsedUsage | null {
    const usage = asRecord(asRecord(safeJson(bodyText))?.usage);
    return usage === null ? null : usageFromRecord(usage, emptyUsage());
  },
  newStreamParser(): StreamUsageParser {
    return new AnthropicStreamParser();
  },
};
