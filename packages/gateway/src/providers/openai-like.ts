import type { SseEvent } from '../sse.js';
import {
  asRecord,
  emptyUsage,
  nonNegativeInt,
  type ParsedUsage,
  type ProviderAdapter,
  type ProviderName,
  type StreamUsageParser,
} from './types.js';

/**
 * Chat-completions adapter shared by OpenAI and OpenRouter (same wire shape).
 * Q16 rules:
 * - OpenAI streaming: inject `stream_options.include_usage` — the final data
 *   chunk before [DONE] carries `usage {prompt_tokens, completion_tokens}`.
 *   `prompt_tokens` INCLUDES cached tokens; `prompt_tokens_details.
 *   cached_tokens` splits them out for cache-read pricing.
 * - OpenRouter: additionally inject `usage.include` — its `usage.cost` (USD)
 *   is AUTHORITATIVE (Q14) and wins over any table-priced token math.
 */

const USD_MICROS_PER_UNIT = 1_000_000;

function usdToMicros(cost: unknown): number | null {
  if (typeof cost !== 'number' || !Number.isFinite(cost) || cost < 0) {
    return null;
  }
  return Math.round(cost * USD_MICROS_PER_UNIT);
}

function usageFromRecord(usage: Record<string, unknown>): ParsedUsage {
  const prompt = nonNegativeInt(usage.prompt_tokens);
  const cached = nonNegativeInt(asRecord(usage.prompt_tokens_details)?.cached_tokens);
  return {
    ...emptyUsage(),
    // Billable fresh input = prompt minus the cache-read share.
    tokensIn: Math.max(prompt - cached, 0),
    tokensOut: nonNegativeInt(usage.completion_tokens),
    cacheReadTokens: cached,
    costUsdMicros: usdToMicros(usage.cost),
  };
}

class OpenAiLikeStreamParser implements StreamUsageParser {
  private parsed: ParsedUsage | null = null;
  private textChars = 0;

  onEvent(event: SseEvent): void {
    if (event.data === '[DONE]') {
      return;
    }
    const data = asRecord(safeJson(event.data));
    if (data === null) {
      return;
    }
    const usage = asRecord(data.usage);
    if (usage !== null) {
      this.parsed = usageFromRecord(usage);
    }
    const choices = Array.isArray(data.choices) ? data.choices : [];
    for (const choice of choices) {
      const content = asRecord(asRecord(choice)?.delta)?.content;
      if (typeof content === 'string') {
        this.textChars += content.length;
      }
    }
  }

  usage(): ParsedUsage | null {
    return this.parsed;
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

export function createOpenAiLikeAdapter(name: Extract<ProviderName, 'openai' | 'openrouter'>): ProviderAdapter {
  return {
    name,
    endpointPath: '/chat/completions',
    headers(apiKey: string): Record<string, string> {
      return {
        authorization: `Bearer ${apiKey}`,
        'content-type': 'application/json',
      };
    },
    prepareBody(body, stream): Record<string, unknown> {
      const prepared: Record<string, unknown> = { ...body, stream };
      if (name === 'openrouter') {
        prepared.usage = { include: true };
      }
      if (stream) {
        const existing = asRecord(prepared.stream_options) ?? {};
        prepared.stream_options = { ...existing, include_usage: true };
      }
      return prepared;
    },
    parseUsageFromJson(bodyText): ParsedUsage | null {
      const usage = asRecord(asRecord(safeJson(bodyText))?.usage);
      return usage === null ? null : usageFromRecord(usage);
    },
    newStreamParser(): StreamUsageParser {
      return new OpenAiLikeStreamParser();
    },
  };
}

export const openaiAdapter = createOpenAiLikeAdapter('openai');
export const openrouterAdapter = createOpenAiLikeAdapter('openrouter');
