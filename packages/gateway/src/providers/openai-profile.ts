import {
  asRecord,
  PLAIN_TEXT_PROFILE,
  type ProfileResult,
  type ProviderName,
  type RequestProfile,
} from './types.js';

/**
 * What a Chat Completions request (OpenAI or OpenRouter) can be billed for
 * beyond its own bytes (S-2). Source for image costs: OpenAI "Images and
 * vision → Calculating costs" (developers.openai.com, 2026-09).
 */

/**
 * The largest documented per-image cost: gpt-4o-mini's tile math, 2,833 base
 * tokens + 8 × 5,667 per 512-px tile (an image is scaled into 2048 px with
 * its short side ≤ 768 px: at most 2 × 4 tiles). Patch-based models stay far
 * below it (≤ 30,000 patches × 1.2). Rows may name a model's own ceiling.
 */
export const OPENAI_IMAGE_TOKENS_MAX = 48_169;

/** Parts whose billed tokens their own bytes bound. */
const TEXT_PARTS: ReadonlySet<string> = new Set(['text', 'refusal']);

/** Tool types that are plain text definitions (anything else is refused). */
const TEXT_TOOLS: ReadonlySet<string> = new Set(['function', 'custom']);

export function profileChatRequest(
  body: Readonly<Record<string, unknown>>,
  provider: Extract<ProviderName, 'openai' | 'openrouter'>
): ProfileResult {
  for (const tool of Array.isArray(body.tools) ? body.tools : []) {
    const type = asRecord(tool)?.type;
    if (typeof type !== 'string' || !TEXT_TOOLS.has(type)) {
      return {
        ok: false,
        reason: `tool type '${String(type).slice(0, 64)}' is not a plain function tool — its cost is not bounded by this door (fail-closed)`,
      };
    }
  }
  let images = 0;
  let unsizedInput = false;
  for (const message of Array.isArray(body.messages) ? body.messages : []) {
    const content = asRecord(message)?.content;
    if (!Array.isArray(content)) {
      continue; // a string (or null): its bytes bound it
    }
    for (const part of content) {
      const type = asRecord(part)?.type;
      if (typeof type !== 'string' || TEXT_PARTS.has(type)) {
        continue; // malformed parts are rejected by the provider unbilled
      }
      if (type === 'image_url') {
        images += 1;
      } else if (type === 'file' && provider === 'openai') {
        // A PDF: extracted text + an image per page — pages unknown.
        unsizedInput = true;
      } else {
        // input_audio (audio-rate tokens), OpenRouter files (parser-plugin
        // fees), and part types this code has never seen.
        return {
          ok: false,
          reason: `content part type '${type.slice(0, 64)}' is not metered by this door (fail-closed)`,
        };
      }
    }
  }
  return {
    ok: true,
    profile: {
      ...PLAIN_TEXT_PROFILE,
      images,
      unsizedInput,
      ...(provider === 'openrouter' ? openrouterExtras(body) : {}),
      completions: typeof body.n === 'number' && Number.isInteger(body.n) && body.n > 0 ? body.n : 1,
      // Rejected predicted-output tokens are billed at the completion rate.
      outputRateBytes:
        body.prediction === undefined ? 0 : Buffer.byteLength(JSON.stringify(body.prediction), 'utf8'),
      fallbackModels: Array.isArray(body.models)
        ? body.models.filter((model): model is string => typeof model === 'string')
        : [],
    },
  };
}

/**
 * What OpenRouter can bill beyond the OpenAI shape (S10-fix 2D):
 * - `cache_control` breakpoints (Anthropic models): the prompt is written to
 *   the cache at 1.25× input, or 2× with a 1-hour TTL.
 * - `reasoning.max_tokens`: on "most providers" the output cap covers
 *   reasoning (OpenRouter docs) — not all, so the budget is reserved on top.
 */
function openrouterExtras(
  body: Readonly<Record<string, unknown>>
): Pick<RequestProfile, 'cacheWrite' | 'extraOutputTokens'> {
  const reasoningBudget = asRecord(body.reasoning)?.max_tokens;
  return {
    cacheWrite: cacheWriteIn(body.messages),
    extraOutputTokens:
      typeof reasoningBudget === 'number' && Number.isInteger(reasoningBudget) && reasoningBudget > 0
        ? reasoningBudget
        : 0,
  };
}

/** The costliest cache write any `cache_control` breakpoint in the value asks for. */
function cacheWriteIn(value: unknown): RequestProfile['cacheWrite'] {
  let found: RequestProfile['cacheWrite'] = 'none';
  const pending: unknown[] = [value];
  while (pending.length > 0) {
    const next = pending.pop();
    if (Array.isArray(next)) {
      pending.push(...next);
      continue;
    }
    const record = asRecord(next);
    if (record === null) {
      continue;
    }
    if (record.cache_control !== undefined) {
      // Anything but the default 5-minute TTL is priced as the costlier 1h write.
      const ttl = asRecord(record.cache_control)?.ttl;
      if (ttl !== undefined && ttl !== '5m') {
        return '1h';
      }
      found = '5m';
    }
    pending.push(...Object.values(record));
  }
  return found;
}
