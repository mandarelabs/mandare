import { readFileSync } from 'node:fs';

/**
 * The price table: the ledger's truth whenever a provider returns no cost
 * (Anthropic, OpenAI). OpenRouter responses carry an authoritative
 * `usage.cost` and never touch it for settlement (BUILD-DECISIONS Q14/Q16).
 *
 * Fail-closed contract: a model with no row CANNOT be metered on a direct
 * provider, so the gateway refuses it (unknown price ⇒ unbounded spend ⇒ no).
 * Ids match EXACTLY (S-4): an unlisted variant — an audio or search model, a
 * pro tier, a snapshot nobody vetted — is unpriced, never billed at a
 * sibling's rate. Operators extend the table via MANDARE_PRICING_PATH.
 *
 * Prices are USD per MILLION tokens.
 */
export interface ModelPricing {
  /** Exact model id this row prices ('anthropic/' and 'openai/' org prefixes are stripped first). */
  model: string;
  /** Other exact ids billed at this row's rates (dated snapshots of an alias). */
  aliases?: readonly string[];
  inUsdPerM: number;
  outUsdPerM: number;
  /** 5-minute cache write. Default: 1.25× input. */
  cacheWriteUsdPerM?: number;
  /** 1-hour-TTL cache write (Anthropic). Default: 2× input. */
  cacheWrite1hUsdPerM?: number;
  /** Cache read. Default: the input rate — no discount is assumed that a row does not state. */
  cacheReadUsdPerM?: number;
  /** Audio tokens (OpenAI `*_tokens_details.audio_tokens`). Default: a deliberately high fallback. */
  audioInUsdPerM?: number;
  audioOutUsdPerM?: number;
  /** Model output ceiling — the reservation bound when the request sets no max. */
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

/** One Anthropic row: the pricing page lists all five rates per model. */
function claude(
  model: string,
  aliases: readonly string[],
  rates: readonly [input: number, write5m: number, write1h: number, read: number, output: number],
  limits: { maxOutputTokens: number; maxInputTokens: number }
): ModelPricing {
  const [inUsdPerM, cacheWriteUsdPerM, cacheWrite1hUsdPerM, cacheReadUsdPerM, outUsdPerM] = rates;
  return {
    model,
    aliases,
    inUsdPerM,
    outUsdPerM,
    cacheWriteUsdPerM,
    cacheWrite1hUsdPerM,
    cacheReadUsdPerM,
    ...limits,
  };
}

/** One OpenAI row: input, cached input, output (writes to OpenAI's cache are free). */
function gpt(
  model: string,
  aliases: readonly string[],
  rates: readonly [input: number, cachedInput: number, output: number],
  limits: { maxOutputTokens: number; maxInputTokens: number; maxImageTokens?: number }
): ModelPricing {
  const [inUsdPerM, cacheReadUsdPerM, outUsdPerM] = rates;
  return { model, aliases, inUsdPerM, outUsdPerM, cacheReadUsdPerM, ...limits };
}

const CLAUDE_1M = { maxOutputTokens: 128_000, maxInputTokens: 1_000_000 };
const CLAUDE_200K = { maxOutputTokens: 64_000, maxInputTokens: 200_000 };

/**
 * Defaults, from the providers' public pages as of 2026-09-26:
 * - Anthropic — platform.claude.com/docs/en/about-claude/pricing ("Model
 *   pricing": base input, 5m / 1h cache writes, cache hits, output) and
 *   /docs/en/about-claude/models/overview + /model-ids-and-versions (ids,
 *   context windows, max output). Claude 4.6+ has a 1M window at standard
 *   rates; older models' 1M window needs a beta header this door never
 *   forwards, so 200K.
 * - OpenAI — developers.openai.com/api/docs/pricing (Standard tier: input,
 *   cached input, output) and /guides/images-vision (tile math: 85 + 170 per
 *   512-px tile on gpt-4o/gpt-4.1, 70 + 140 on gpt-5, at most 8 tiles).
 */
export const DEFAULT_PRICING: readonly ModelPricing[] = [
  claude('claude-fable-5-1', [], [10, 12.5, 20, 0.25, 50], CLAUDE_1M),
  claude('claude-fable-5', [], [10, 12.5, 20, 1, 50], CLAUDE_1M),
  claude('claude-opus-5-5', [], [4, 5, 8, 0.2, 20], CLAUDE_1M),
  claude('claude-opus-5', [], [5, 6.25, 10, 0.5, 25], CLAUDE_1M),
  claude('claude-opus-4-8', [], [5, 6.25, 10, 0.5, 25], CLAUDE_1M),
  claude('claude-opus-4-7', [], [5, 6.25, 10, 0.5, 25], CLAUDE_1M),
  claude('claude-opus-4-6', [], [5, 6.25, 10, 0.5, 25], CLAUDE_1M),
  claude('claude-sonnet-5', [], [2, 2.5, 4, 0.2, 10], CLAUDE_1M),
  claude('claude-sonnet-4-6', [], [3, 3.75, 6, 0.3, 15], CLAUDE_1M),
  claude('claude-opus-4-5', ['claude-opus-4-5-20251101'], [5, 6.25, 10, 0.5, 25], CLAUDE_200K),
  claude('claude-sonnet-4-5', ['claude-sonnet-4-5-20250929'], [3, 3.75, 6, 0.3, 15], CLAUDE_200K),
  claude('claude-haiku-4-5', ['claude-haiku-4-5-20251001'], [1, 1.25, 2, 0.1, 5], CLAUDE_200K),
  claude('claude-opus-4-1', ['claude-opus-4-1-20250805'], [15, 18.75, 30, 1.5, 75], {
    maxOutputTokens: 32_000,
    maxInputTokens: 200_000,
  }),
  gpt('gpt-5', ['gpt-5-2025-08-07'], [1.25, 0.125, 10], {
    maxOutputTokens: 128_000,
    maxInputTokens: 400_000,
    maxImageTokens: 70 + 140 * 8,
  }),
  gpt('gpt-5-mini', ['gpt-5-mini-2025-08-07'], [0.25, 0.025, 2], {
    maxOutputTokens: 128_000,
    maxInputTokens: 400_000,
  }),
  gpt('gpt-5-nano', ['gpt-5-nano-2025-08-07'], [0.05, 0.005, 0.4], {
    maxOutputTokens: 128_000,
    maxInputTokens: 400_000,
  }),
  gpt('gpt-4.1', ['gpt-4.1-2025-04-14'], [2, 0.5, 8], {
    maxOutputTokens: 32_768,
    maxInputTokens: 1_047_576,
    maxImageTokens: 85 + 170 * 8,
  }),
  gpt('gpt-4.1-mini', ['gpt-4.1-mini-2025-04-14'], [0.4, 0.1, 1.6], {
    maxOutputTokens: 32_768,
    maxInputTokens: 1_047_576,
  }),
  gpt('gpt-4.1-nano', ['gpt-4.1-nano-2025-04-14'], [0.1, 0.025, 0.4], {
    maxOutputTokens: 32_768,
    maxInputTokens: 1_047_576,
  }),
  gpt('gpt-4o', ['gpt-4o-2024-08-06', 'gpt-4o-2024-11-20'], [2.5, 1.25, 10], {
    maxOutputTokens: 16_384,
    maxInputTokens: 128_000,
    maxImageTokens: 85 + 170 * 8,
  }),
  // The May-2024 snapshot bills 2× gpt-4o's input and has no cached rate.
  gpt('gpt-4o-2024-05-13', [], [5, 5, 15], {
    maxOutputTokens: 4_096,
    maxInputTokens: 128_000,
    maxImageTokens: 85 + 170 * 8,
  }),
  gpt('gpt-4o-mini', ['gpt-4o-mini-2024-07-18'], [0.15, 0.075, 0.6], {
    maxOutputTokens: 16_384,
    maxInputTokens: 128_000,
  }),
];

/**
 * The table holds Anthropic's and OpenAI's own prices, so only their org
 * prefixes ('anthropic/claude-…', 'openai/gpt-…', as OpenRouter spells them)
 * map onto it. Any other org keeps its prefix — and matches only a row an
 * operator wrote for exactly that id.
 */
function tableModelId(model: string): string {
  for (const org of ['anthropic/', 'openai/']) {
    if (model.startsWith(org)) {
      return model.slice(org.length);
    }
  }
  return model;
}

export function findPricing(
  model: string,
  table: readonly ModelPricing[] = DEFAULT_PRICING
): ModelPricing | null {
  const id = tableModelId(model);
  return table.find((row) => row.model === id || (row.aliases?.includes(id) ?? false)) ?? null;
}

const RATE_FIELDS = [
  'inUsdPerM',
  'outUsdPerM',
  'cacheWriteUsdPerM',
  'cacheWrite1hUsdPerM',
  'cacheReadUsdPerM',
  'audioInUsdPerM',
  'audioOutUsdPerM',
] as const;
const TOKEN_LIMIT_FIELDS = ['maxOutputTokens', 'maxInputTokens', 'maxImageTokens'] as const;
const REQUIRED_FIELDS = ['model', 'inUsdPerM', 'outUsdPerM', 'maxOutputTokens'] as const;
const KNOWN_FIELDS: ReadonlySet<string> = new Set(['model', 'aliases', ...RATE_FIELDS, ...TOKEN_LIMIT_FIELDS]);

/**
 * Merge an operator-supplied JSON pricing file over the defaults (operator
 * rows win). Validated at the boundary (R4): a row that could meter a spend
 * wrongly — a negative or non-finite rate, an unknown key, the retired
 * prefix-matching format — refuses to load rather than pricing anything.
 */
export function loadPricingTable(path: string): ModelPricing[] {
  const parsed: unknown = JSON.parse(readFileSync(path, 'utf8'));
  if (!Array.isArray(parsed)) {
    throw new Error(`pricing file ${path} must be a JSON array`);
  }
  const extra = parsed.map((row: unknown, index): ModelPricing => {
    const problem = rowProblem(row);
    if (problem !== null) {
      throw new Error(`pricing file ${path}: entry ${index} ${problem}`);
    }
    return row as ModelPricing;
  });
  return [...extra, ...DEFAULT_PRICING];
}

function rowProblem(row: unknown): string | null {
  if (typeof row !== 'object' || row === null || Array.isArray(row)) {
    return 'is not an object';
  }
  const record = row as Record<string, unknown>;
  if ('prefix' in record) {
    return "uses 'prefix' — rows now match EXACT model ids: rename it to 'model' (and list snapshots under 'aliases')";
  }
  const unknownKey = Object.keys(record).find((key) => !KNOWN_FIELDS.has(key));
  if (unknownKey !== undefined) {
    return `has an unknown key '${unknownKey}'`;
  }
  const missing = REQUIRED_FIELDS.find((key) => record[key] === undefined);
  if (missing !== undefined) {
    return `is missing '${missing}'`;
  }
  if (typeof record.model !== 'string' || record.model.length === 0) {
    return "needs a non-empty string 'model'";
  }
  if (
    record.aliases !== undefined &&
    (!Array.isArray(record.aliases) ||
      !record.aliases.every((alias) => typeof alias === 'string' && alias.length > 0))
  ) {
    return "needs 'aliases' to be an array of non-empty strings";
  }
  const badRate = RATE_FIELDS.find(
    (key) =>
      record[key] !== undefined &&
      !(typeof record[key] === 'number' && Number.isFinite(record[key]) && (record[key] as number) >= 0)
  );
  if (badRate !== undefined) {
    return `has an invalid '${badRate}' (a finite, non-negative USD-per-million number)`;
  }
  const badLimit = TOKEN_LIMIT_FIELDS.find(
    (key) => record[key] !== undefined && !(Number.isInteger(record[key]) && (record[key] as number) >= 1)
  );
  if (badLimit !== undefined) {
    return `has an invalid '${badLimit}' (a positive integer)`;
  }
  return null;
}
