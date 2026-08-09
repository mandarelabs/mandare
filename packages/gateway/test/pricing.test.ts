import { describe, expect, test } from 'vitest';

import {
  costUsdMicros,
  estimateUsdMicros,
  findPricing,
  usdMicrosToLedgerMicros,
  DEFAULT_PRICING,
} from '../src/pricing.js';

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

  test('currency conversion is explicit and ceils', () => {
    expect(usdMicrosToLedgerMicros(1_160_000, 1.16)).toBe(1_000_000); // $1.16 → €1.00
    expect(usdMicrosToLedgerMicros(100, 1.16)).toBe(87); // ceil(86.2)
    expect(usdMicrosToLedgerMicros(500, 1)).toBe(500);
    expect(() => usdMicrosToLedgerMicros(1, 0)).toThrow(/positive/);
  });
});
