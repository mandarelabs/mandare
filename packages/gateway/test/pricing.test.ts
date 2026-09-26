import { describe, expect, test } from 'vitest';

import {
  costUsdMicros,
  estimateRequest,
  estimateUsdMicros,
  findPricing,
  usdMicrosToLedgerMicros,
  DEFAULT_PRICING,
  REQUEST_OVERHEAD_TOKENS,
} from '../src/pricing.js';
import { PLAIN_TEXT_PROFILE } from '../src/providers/types.js';

describe('findPricing', () => {
  test('longest prefix wins (gpt-5-mini is not priced as gpt-5)', () => {
    expect(findPricing('gpt-5-mini')?.prefix).toBe('gpt-5-mini');
    expect(findPricing('gpt-5-2026-01-01')?.prefix).toBe('gpt-5');
    expect(findPricing('claude-haiku-4-5-20251001')?.prefix).toBe('claude-haiku-4-5');
  });

  test('provider org prefixes are stripped', () => {
    expect(findPricing('anthropic/claude-haiku-4-5')?.prefix).toBe('claude-haiku-4-5');
  });

  test('unknown models return null — the gateway refuses them on direct providers', () => {
    expect(findPricing('openrouter/auto')).toBeNull();
    expect(findPricing('mystery-model-9000')).toBeNull();
  });
});

describe('cost math (ceil — never undercount)', () => {
  const haiku = DEFAULT_PRICING.find((entry) => entry.prefix === 'claude-haiku-4-5');
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
    const sonnet = DEFAULT_PRICING.find((entry) => entry.prefix === 'claude-sonnet-4-5');
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
