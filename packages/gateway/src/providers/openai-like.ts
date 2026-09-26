import type { SseEvent } from '../sse.js';
import { OPENAI_IMAGE_TOKENS_MAX, profileChatRequest } from './openai-profile.js';
import {
  asRecord,
  emptyUsage,
  nonNegativeInt,
  outputBytesIn,
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
 * - OpenRouter: additionally inject `usage.include` (deprecated, now always
 *   on; harmless) — its reported cost (USD) is AUTHORITATIVE (Q14) and wins
 *   over any table-priced token math; on BYOK calls that includes the
 *   provider's own bill (see reportedCost).
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
  const promptDetails = asRecord(usage.prompt_tokens_details);
  const cached = nonNegativeInt(promptDetails?.cached_tokens);
  // Audio tokens are part of prompt/completion tokens but bill at audio
  // rates (S-4); reasoning and predicted-output tokens are already in
  // completion_tokens at the output rate.
  const audioIn = nonNegativeInt(promptDetails?.audio_tokens);
  const audioOut = nonNegativeInt(asRecord(usage.completion_tokens_details)?.audio_tokens);
  return {
    ...emptyUsage(),
    // Billable fresh input = prompt minus the cache-read share.
    tokensIn: Math.max(prompt - cached, 0),
    tokensOut: nonNegativeInt(usage.completion_tokens),
    cacheReadTokens: cached,
    ...(audioIn === 0 ? {} : { audioInTokens: audioIn }),
    ...(audioOut === 0 ? {} : { audioOutTokens: audioOut }),
    ...reportedCost(usage),
  };
}

/**
 * The spend an OpenRouter usage block reports (S10-fix 2D). `cost` is what
 * OpenRouter charged the account; on a BYOK call that is only its fee, and
 * the provider bills the operator's own key `cost_details.
 * upstream_inference_cost` on top (usage-accounting docs). So:
 * - BYOK (`is_byok: true`): fee + upstream; either missing ⇒ the bill is
 *   only partly known and never settles below the reservation.
 * - Not BYOK (`is_byok: false`): `cost` — a non-BYOK upstream figure is what
 *   OpenRouter paid, already inside `cost`; adding it would double-count.
 * - `is_byok` absent: an upstream figure above `cost` can only be a BYOK
 *   bill (the fee is 5% of it), so fee + upstream; otherwise `cost`.
 */
function reportedCost(usage: Record<string, unknown>): Pick<ParsedUsage, 'costUsdMicros' | 'costIsPartial'> {
  const cost = usdToMicros(usage.cost);
  const upstream = usdToMicros(asRecord(usage.cost_details)?.upstream_inference_cost);
  if (usage.is_byok === true) {
    if (cost === null || upstream === null) {
      return { costUsdMicros: cost ?? upstream, costIsPartial: true };
    }
    return { costUsdMicros: cost + upstream };
  }
  if (usage.is_byok === undefined && cost !== null && upstream !== null && upstream > cost) {
    return { costUsdMicros: cost + upstream };
  }
  return { costUsdMicros: cost };
}

/**
 * Delta keys that are protocol metadata, not generated output. Content,
 * refusals, reasoning text and tool-call names/arguments all count (S-1:
 * counting only `content` let a stream of `tool_calls` settle for free).
 */
const NON_OUTPUT_DELTA_KEYS: ReadonlySet<string> = new Set(['role', 'type', 'id', 'index']);

class OpenAiLikeStreamParser implements StreamUsageParser {
  private parsed: ParsedUsage | null = null;
  private outputBytes = 0;
  private sawDone = false;

  onEvent(event: SseEvent): void {
    if (event.data === '[DONE]') {
      this.sawDone = true;
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
      // UTF-8 bytes (token upper bound) so a token-dense aborted stream
      // cannot under-record output cost at settlement (S8/S1).
      this.outputBytes += outputBytesIn(asRecord(choice)?.delta, NON_OUTPUT_DELTA_KEYS);
    }
  }

  usage(): ParsedUsage | null {
    return this.parsed;
  }

  hasFinalUsage(): boolean {
    return this.parsed !== null && this.sawDone;
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

export function createOpenAiLikeAdapter(name: Extract<ProviderName, 'openai' | 'openrouter'>): ProviderAdapter {
  return {
    name,
    endpointPath: '/chat/completions',
    imageTokensCeiling: OPENAI_IMAGE_TOKENS_MAX,
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
    profileRequest: (body) => profileChatRequest(body, name),
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
