import { readFileSync } from 'node:fs';

/**
 * Model pricing for pre-flight cost RESERVATION and for token-based true-up
 * on providers that do not return an authoritative cost (Anthropic, OpenAI).
 * OpenRouter responses carry an authoritative `usage.cost` and never touch
 * this table for settlement (BUILD-DECISIONS Q14/Q16).
 *
 * Fail-closed contract: a model with no pricing entry CANNOT be metered on a
 * direct provider, so the gateway refuses it (unknown price ⇒ unbounded
 * spend ⇒ no). Operators extend the table via MANDARE_PRICING_PATH.
 *
 * Prices are USD per MILLION tokens (integers keep the math exact); pinned
 * 2026-07 from the public provider price pages — the table is config, not
 * truth, and true costs land at settlement.
 */

export interface ModelPricing {
  /** Longest matching prefix wins, e.g. 'claude-haiku-4-5'. */
  prefix: string;
  inUsdPerM: number;
  outUsdPerM: number;
  /** Defaults: write 1.25× input, read 0.1× input (both providers' shape). */
  cacheWriteUsdPerM?: number;
  cacheReadUsdPerM?: number;
  /** Hard model output ceiling — the reservation bound when the request sets no max. */
  maxOutputTokens: number;
}

export const DEFAULT_PRICING: readonly ModelPricing[] = [
  { prefix: 'claude-haiku-4-5', inUsdPerM: 1, outUsdPerM: 5, maxOutputTokens: 64_000 },
  { prefix: 'claude-sonnet-4-5', inUsdPerM: 3, outUsdPerM: 15, maxOutputTokens: 64_000 },
  { prefix: 'claude-opus-4-5', inUsdPerM: 5, outUsdPerM: 25, maxOutputTokens: 64_000 },
  { prefix: 'claude-opus-4-1', inUsdPerM: 15, outUsdPerM: 75, maxOutputTokens: 32_000 },
  { prefix: 'gpt-5-nano', inUsdPerM: 0.05, outUsdPerM: 0.4, maxOutputTokens: 128_000 },
  { prefix: 'gpt-5-mini', inUsdPerM: 0.25, outUsdPerM: 2, maxOutputTokens: 128_000 },
  { prefix: 'gpt-5', inUsdPerM: 1.25, outUsdPerM: 10, maxOutputTokens: 128_000 },
  { prefix: 'gpt-4o-mini', inUsdPerM: 0.15, outUsdPerM: 0.6, maxOutputTokens: 16_384 },
  { prefix: 'gpt-4o', inUsdPerM: 2.5, outUsdPerM: 10, maxOutputTokens: 16_384 },
  { prefix: 'gpt-4.1-mini', inUsdPerM: 0.4, outUsdPerM: 1.6, maxOutputTokens: 32_768 },
  { prefix: 'gpt-4.1', inUsdPerM: 2, outUsdPerM: 8, maxOutputTokens: 32_768 },
];

/** Strip a provider org prefix ('anthropic/claude-…' → 'claude-…'). */
function bareModel(model: string): string {
  const slash = model.lastIndexOf('/');
  return slash === -1 ? model : model.slice(slash + 1);
}

export function findPricing(
  model: string,
  table: readonly ModelPricing[] = DEFAULT_PRICING
): ModelPricing | null {
  const bare = bareModel(model);
  let best: ModelPricing | null = null;
  for (const entry of table) {
    if (bare.startsWith(entry.prefix) && (best === null || entry.prefix.length > best.prefix.length)) {
      best = entry;
    }
  }
  return best;
}

/** Merge an operator-supplied JSON pricing file over the defaults (R4: validated). */
export function loadPricingTable(path: string): ModelPricing[] {
  const parsed: unknown = JSON.parse(readFileSync(path, 'utf8'));
  if (!Array.isArray(parsed)) {
    throw new Error(`pricing file ${path} must be a JSON array`);
  }
  const extra = parsed.map((row: unknown, index): ModelPricing => {
    const record = row as Record<string, unknown>;
    if (
      typeof record?.prefix !== 'string' ||
      record.prefix.length === 0 ||
      typeof record.inUsdPerM !== 'number' ||
      typeof record.outUsdPerM !== 'number' ||
      !Number.isInteger(record.maxOutputTokens) ||
      (record.maxOutputTokens as number) < 1
    ) {
      throw new Error(`pricing file ${path}: entry ${index} is malformed`);
    }
    return record as unknown as ModelPricing;
  });
  return [...extra, ...DEFAULT_PRICING];
}

export interface UsageTokens {
  tokensIn: number;
  tokensOut: number;
  cacheWriteTokens: number;
  cacheReadTokens: number;
}

const USD_MICROS_PER_UNIT = 1_000_000;
const TOKENS_PER_MILLION = 1_000_000;

/** USD micros for a token usage under a pricing entry (ceil — never undercount). */
export function costUsdMicros(usage: UsageTokens, pricing: ModelPricing): number {
  const cacheWrite = pricing.cacheWriteUsdPerM ?? pricing.inUsdPerM * 1.25;
  const cacheRead = pricing.cacheReadUsdPerM ?? pricing.inUsdPerM * 0.1;
  const usd =
    (usage.tokensIn * pricing.inUsdPerM +
      usage.tokensOut * pricing.outUsdPerM +
      usage.cacheWriteTokens * cacheWrite +
      usage.cacheReadTokens * cacheRead) /
    TOKENS_PER_MILLION;
  return Math.ceil(usd * USD_MICROS_PER_UNIT);
}

/**
 * Tokenizer-free pre-flight estimate (Q16 allows estimation ONLY here and
 * for aborted streams). The reservation is the cap guard, so the input side
 * must be a TRUE UPPER BOUND on token count — not a heuristic. A byte-level
 * BPE tokenizer (Anthropic/OpenAI) never emits MORE tokens than the UTF-8 byte
 * length of its input: the base vocabulary is the 256 single bytes and merges
 * only REDUCE the count, so tokens ≤ bytes for ANY input, adversarial included.
 * Counting UTF-8 bytes therefore over-reserves for every script.
 *
 * The old estimate (`chars/3` over the UTF-16 `.length`) held only for Latin
 * text: for CJK / many-bytes-per-token scripts it UNDER-counted by ~3×, so a
 * hijacked agent could shape `max_tokens:1` + a token-dense prompt to reserve
 * under the per-tx cap yet settle the true (2–3× larger) cost past it (S8/S1) —
 * settlement applies the real cost with no cap guard, by design. The byte bound
 * closes that. Output is already bounded by max_tokens or the model ceiling
 * (which dominates the reservation on any normal call), so this only tightens
 * the rare tiny-output + huge-input shape the attack needs; the extra headroom
 * on ordinary calls is released at settlement.
 */
export function estimateUsdMicros(args: {
  body: Record<string, unknown>;
  pricing: ModelPricing;
}): number {
  const inputText =
    JSON.stringify(args.body.messages ?? '') + JSON.stringify(args.body.system ?? '');
  const inputTokens = Buffer.byteLength(inputText, 'utf8');
  const requestedMax = args.body.max_tokens ?? args.body.max_completion_tokens;
  const outputTokens =
    Number.isInteger(requestedMax) && (requestedMax as number) > 0
      ? Math.min(requestedMax as number, args.pricing.maxOutputTokens)
      : args.pricing.maxOutputTokens;
  return costUsdMicros(
    { tokensIn: inputTokens, tokensOut: outputTokens, cacheWriteTokens: 0, cacheReadTokens: 0 },
    args.pricing
  );
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
