import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, test } from 'vitest';

import {
  costUsdMicros,
  estimateRequest,
  estimateUsdMicros,
  findPricing,
  loadPricingTable,
  usdMicrosToLedgerMicros,
  DEFAULT_PRICING,
  REQUEST_OVERHEAD_TOKENS,
  type ModelPricing,
} from '../src/pricing.js';
import { anthropicAdapter } from '../src/providers/anthropic.js';
import { openaiAdapter } from '../src/providers/openai-like.js';
import { PLAIN_TEXT_PROFILE } from '../src/providers/types.js';

describe('findPricing (S-4a: exact model ids, fail closed)', () => {
  test('exact ids and their documented dated aliases are priced', () => {
    expect(findPricing('gpt-5-mini')?.model).toBe('gpt-5-mini');
    expect(findPricing('gpt-5')?.model).toBe('gpt-5');
    expect(findPricing('claude-haiku-4-5-20251001')?.model).toBe('claude-haiku-4-5');
    expect(findPricing('gpt-4o-2024-08-06')?.model).toBe('gpt-4o');
  });

  test('the provider org prefixes the table prices are stripped; other orgs are not', () => {
    expect(findPricing('anthropic/claude-haiku-4-5')?.model).toBe('claude-haiku-4-5');
    expect(findPricing('openai/gpt-4o-mini')?.model).toBe('gpt-4o-mini');
    // A different org's model that happens to share a name is not OpenAI's price.
    expect(findPricing('someorg/gpt-4o')).toBeNull();
  });

  test('an unlisted variant is UNPRICED, never billed at a sibling rate', () => {
    for (const variant of [
      'gpt-4o-audio-preview', // audio tokens at ~16× the text rate
      'gpt-4o-mini-audio-preview',
      'gpt-4o-search-preview', // per-call search fees
      'gpt-5-pro', // 12× gpt-5's rates
      'gpt-5-2026-01-01', // a snapshot the table has not vetted
      'claude-haiku-4-5-20991231',
      'claude-opus-4-1-fast',
    ]) {
      expect(findPricing(variant)).toBeNull();
    }
  });

  test('a snapshot priced differently from its alias gets its own row', () => {
    const may2024 = findPricing('gpt-4o-2024-05-13');
    expect(may2024?.inUsdPerM).toBe(5);
    expect(may2024?.outUsdPerM).toBe(15);
  });

  test('unknown models return null — the gateway refuses them on direct providers', () => {
    expect(findPricing('openrouter/auto')).toBeNull();
    expect(findPricing('mystery-model-9000')).toBeNull();
  });
});

describe('per-model cache and fee rates (S-4b/c)', () => {
  const row = (model: string): ModelPricing => {
    const found = findPricing(model);
    if (found === null) throw new Error(`fixture: ${model} pricing missing`);
    return found;
  };

  test('cached input reads at each model\'s own rate (gpt-4o 0.5×, gpt-4.1 0.25×), not a flat 0.1×', () => {
    const cachedRead = { tokensIn: 0, tokensOut: 0, cacheWriteTokens: 0, cacheReadTokens: 8_000 };
    expect(costUsdMicros(cachedRead, row('gpt-4o'))).toBe(10_000); // 8k × $1.25/M
    expect(costUsdMicros(cachedRead, row('gpt-4.1'))).toBe(4_000); // 8k × $0.50/M
    expect(costUsdMicros(cachedRead, row('gpt-5'))).toBe(1_000); // 8k × $0.125/M
  });

  test('a row with no cache rates never discounts a read (conservative default)', () => {
    const bare: ModelPricing = { model: 'operator-model', inUsdPerM: 2, outUsdPerM: 8, maxOutputTokens: 1_000 };
    expect(costUsdMicros({ tokensIn: 0, tokensOut: 0, cacheWriteTokens: 0, cacheReadTokens: 1_000 }, bare)).toBe(2_000);
  });

  test('1-hour cache writes bill at the 1h rate (2× input), 5-minute ones at 1.25×', () => {
    const haiku = row('claude-haiku-4-5');
    const usage = {
      tokensIn: 0,
      tokensOut: 0,
      cacheWriteTokens: 10_000,
      cacheWrite1hTokens: 6_000,
      cacheReadTokens: 0,
    };
    // 4k × $1.25/M + 6k × $2/M.
    expect(costUsdMicros(usage, haiku)).toBe(5_000 + 12_000);
  });

  test('Anthropic web-search requests add $10 per 1,000 to the settled cost', () => {
    const usage = anthropicAdapter.parseUsageFromJson(
      JSON.stringify({ usage: { input_tokens: 100, output_tokens: 50, server_tool_use: { web_search_requests: 3 } } })
    );
    if (usage === null) throw new Error('fixture: usage must parse');
    // 100 × $1/M + 50 × $5/M + 3 × $0.01.
    expect(costUsdMicros(usage, row('claude-haiku-4-5'))).toBe(100 + 250 + 30_000);
  });

  test('OpenAI audio tokens (*_tokens_details) bill at audio rates, not as text', () => {
    const usage = openaiAdapter.parseUsageFromJson(
      JSON.stringify({
        usage: {
          prompt_tokens: 1_000,
          prompt_tokens_details: { cached_tokens: 0, audio_tokens: 800 },
          completion_tokens: 100,
          completion_tokens_details: { reasoning_tokens: 0, audio_tokens: 50 },
        },
      })
    );
    if (usage === null) throw new Error('fixture: usage must parse');
    const asText = costUsdMicros(
      { tokensIn: 1_000, tokensOut: 100, cacheWriteTokens: 0, cacheReadTokens: 0 },
      row('gpt-4o-mini')
    );
    // The row names no audio rate: the fallback ($100/M in, $200/M out) is
    // far above the text rate — 800 audio-in + 50 audio-out tokens alone ≈ $0.09.
    expect(costUsdMicros(usage, row('gpt-4o-mini'))).toBeGreaterThanOrEqual(800 * 100 + 50 * 200);
    expect(costUsdMicros(usage, row('gpt-4o-mini'))).toBeGreaterThan(100 * asText);
  });
});

describe('loadPricingTable (operator rows are config: validated at the boundary)', () => {
  const writeTable = (rows: unknown): string => {
    const path = join(mkdtempSync(join(tmpdir(), 'mandare-pricing-')), 'pricing.json');
    writeFileSync(path, JSON.stringify(rows));
    return path;
  };

  test('operator rows match exactly and win over the defaults', () => {
    const table = loadPricingTable(
      writeTable([{ model: 'gpt-4o', aliases: ['my-4o'], inUsdPerM: 3, outUsdPerM: 12, maxOutputTokens: 100 }])
    );
    expect(findPricing('gpt-4o', table)?.inUsdPerM).toBe(3);
    expect(findPricing('my-4o', table)?.inUsdPerM).toBe(3);
    expect(findPricing('gpt-4o-mini', table)?.inUsdPerM).toBe(0.15);
  });

  test('legacy prefix rows, negative or non-finite rates and unknown keys are refused', () => {
    const good = { model: 'm', inUsdPerM: 1, outUsdPerM: 1, maxOutputTokens: 10 };
    for (const bad of [
      { prefix: 'gpt-4o', inUsdPerM: 1, outUsdPerM: 1, maxOutputTokens: 10 },
      { ...good, inUsdPerM: -1 },
      { ...good, outUsdPerM: Number.POSITIVE_INFINITY },
      { ...good, cacheReadUsdPerM: 'cheap' },
      { ...good, maxInputTokens: 0 },
      { ...good, aliases: ['ok', 7] },
      { ...good, discount: 0.5 },
    ]) {
      expect(() => loadPricingTable(writeTable([bad]))).toThrow(/pricing file/);
    }
  });
});

describe('cost math (ceil — never undercount)', () => {
  const haiku = DEFAULT_PRICING.find((entry) => entry.model === 'claude-haiku-4-5');
  if (haiku === undefined) throw new Error('fixture: haiku pricing missing');

  test('token cost with cache fields', () => {
    const micros = costUsdMicros(
      { tokensIn: 1000, tokensOut: 2000, cacheWriteTokens: 1000, cacheReadTokens: 10_000 },
      haiku
    );
    // 1000×$1/M + 2000×$5/M + 1000×$1.25/M + 10000×$0.10/M = $0.01325.
    expect(micros).toBe(13_250);
  });

  test('estimate is conservative: byte-bound input + full max_tokens output', () => {
    const body = { messages: [{ role: 'user', content: 'hi' }], max_tokens: 1000 };
    const estimate = estimateUsdMicros({ body, pricing: haiku });
    // Output share alone: 1000×$5/M = $0.005 → ≥ 5_000 micros.
    expect(estimate).toBeGreaterThanOrEqual(5_000);
    expect(estimate).toBeLessThan(20_000);
  });

  test('a missing max_tokens reserves the full model output ceiling', () => {
    const body = { messages: [{ role: 'user', content: 'hi' }] };
    const estimate = estimateUsdMicros({ body, pricing: haiku });
    expect(estimate).toBeGreaterThanOrEqual(64_000 * 5); // 64k × $5/M in micros
  });

  test('S8/S1: the reservation is a true upper bound for token-dense (CJK) input', () => {
    const sonnet = DEFAULT_PRICING.find((entry) => entry.model === 'claude-sonnet-4-5');
    if (sonnet === undefined) throw new Error('fixture: sonnet pricing missing');
    // A hijacked agent maximizes token-dense input and kills the output side
    // (max_tokens:1) to slip the estimate under a per-tx cap. The reservation is
    // the cap guard and settlement applies the true cost with no guard, so the
    // estimate MUST already cover the real cost.
    const cjk = '预算'.repeat(20_000); // 40k CJK chars ≈ 120k UTF-8 bytes
    const body = { model: 'claude-sonnet-4-5', max_tokens: 1, messages: [{ role: 'user', content: cjk }] };
    const estimate = estimateUsdMicros({ body, pricing: sonnet });
    // Worst realistic tokenization: ~1 token per CJK char (real is ≤ this). The
    // OLD chars/3 (UTF-16) estimate reserved ~1/3 of this and let the settled
    // cost pierce the per-tx cap on a single call; the byte bound covers it.
    const trueCost = costUsdMicros(
      { tokensIn: cjk.length, tokensOut: 1, cacheWriteTokens: 0, cacheReadTokens: 0 },
      sonnet
    );
    expect(estimate).toBeGreaterThanOrEqual(trueCost);
  });

  test('S-2: the input bound is the WHOLE body — text moved out of `messages` is still counted', () => {
    const payload = 'Z'.repeat(50_000);
    const inMessages = estimateRequest({
      body: { max_tokens: 1, messages: [{ role: 'user', content: payload }] },
      pricing: haiku,
    });
    const inTools = estimateRequest({
      body: {
        max_tokens: 1,
        messages: [{ role: 'user', content: 'hi' }],
        tools: [{ name: 't', description: payload, input_schema: { type: 'object' } }],
      },
      pricing: haiku,
    });
    if (!inMessages.ok || !inTools.ok) throw new Error('fixture: estimates must be bounded');
    expect(inTools.inputTokens).toBeGreaterThanOrEqual(50_000 + REQUEST_OVERHEAD_TOKENS);
    expect(inTools.usdMicros).toBeGreaterThanOrEqual(inMessages.usdMicros - 100);
  });

  test('S-2: n completions multiply the output bound; predicted output is priced at the output rate', () => {
    const body = { max_tokens: 1_000, messages: [{ role: 'user', content: 'hi' }] };
    const one = estimateRequest({ body, pricing: haiku });
    const many = estimateRequest({ body, pricing: haiku, profile: { ...PLAIN_TEXT_PROFILE, completions: 128 } });
    const predicted = estimateRequest({
      body,
      pricing: haiku,
      profile: { ...PLAIN_TEXT_PROFILE, outputRateBytes: 10_000 },
    });
    if (!one.ok || !many.ok || !predicted.ok) throw new Error('fixture: estimates must be bounded');
    expect(many.outputTokens).toBe(128_000);
    expect(predicted.outputTokens).toBe(11_000);
  });

  test('S-2: the requested output cap is never trimmed to a (possibly stale) table ceiling', () => {
    const estimate = estimateRequest({
      body: { max_tokens: 100_000, messages: [{ role: 'user', content: 'hi' }] },
      pricing: haiku, // table ceiling 64k
    });
    if (!estimate.ok) throw new Error('fixture: estimate must be bounded');
    expect(estimate.outputTokens).toBe(100_000);
  });

  test('S-2: media only a context window bounds is refused on a row that names none', () => {
    const { maxInputTokens: _window, ...noWindow } = haiku;
    const body = { max_tokens: 10, messages: [{ role: 'user', content: 'x' }] };
    const profile = { ...PLAIN_TEXT_PROFILE, unsizedInput: true };
    expect(estimateRequest({ body, pricing: noWindow, profile }).ok).toBe(false);
    const bounded = estimateRequest({ body, pricing: haiku, profile });
    if (!bounded.ok) throw new Error('fixture: the default row names a window');
    expect(bounded.inputTokens).toBeGreaterThanOrEqual(200_000);
  });

  test('S-2: requested cache writes price the input at the write rate (1h = 2× input)', () => {
    const body = { max_tokens: 1, messages: [{ role: 'user', content: 'x'.repeat(10_000) }] };
    const plain = estimateRequest({ body, pricing: haiku });
    const oneHour = estimateRequest({ body, pricing: haiku, profile: { ...PLAIN_TEXT_PROFILE, cacheWrite: '1h' } });
    if (!plain.ok || !oneHour.ok) throw new Error('fixture: estimates must be bounded');
    expect(oneHour.usdMicros).toBeGreaterThanOrEqual(2 * plain.inputTokens);
  });

  test('currency conversion is explicit and ceils', () => {
    expect(usdMicrosToLedgerMicros(1_160_000, 1.16)).toBe(1_000_000); // $1.16 → €1.00
    expect(usdMicrosToLedgerMicros(100, 1.16)).toBe(87); // ceil(86.2)
    expect(usdMicrosToLedgerMicros(500, 1)).toBe(500);
    expect(() => usdMicrosToLedgerMicros(1, 0)).toThrow(/positive/);
  });
});
