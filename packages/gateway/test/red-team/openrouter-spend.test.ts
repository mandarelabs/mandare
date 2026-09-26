import { describe, expect, test } from 'vitest';

import { readLedger, verifySpendProjection, LLM_CALL_DENIED } from '@mandarelabs/ledger';
import { LLM_CALL_INTENT, LLM_CALL_RESULT, type LedgerEntryV1 } from '@mandarelabs/spec';

import { openTestGateway, type TestGateway } from '../helpers.js';
import { DEFAULT_PRICING, findPricing, REQUEST_OVERHEAD_TOKENS, type ModelPricing } from '../../src/pricing.js';
import { openrouterAdapter } from '../../src/providers/openai-like.js';
import type { FetchLike } from '../../src/providers/types.js';

/**
 * RED-TEAM (R1/R4/R5, S10-fix 2D): OpenRouter spend truth. The reservation is
 * the only cap guard and settlement takes OpenRouter's reported cost
 * unguarded (Q14), so the reservation must bound what OpenRouter can bill —
 * whichever model, endpoint, variant or key the call ends up on. A hijacked
 * agent picks the model id, the `models` fallbacks and `provider.*`; each
 * probe below is one way it tried to spend past the mandate (€5 per-tx, €20
 * per day, 1 USD per EUR).
 */

const PROMPT = { messages: [{ role: 'user', content: 'hi' }], max_tokens: 100 };
const HAIKU = 'anthropic/claude-haiku-4.5';

interface Upstream {
  fetchImpl: FetchLike;
  bodies: Record<string, unknown>[];
}

/** Records every forwarded body; answers with `respond(body)`. */
function upstream(respond: (body: Record<string, unknown>) => Response): Upstream {
  const bodies: Record<string, unknown>[] = [];
  return {
    bodies,
    fetchImpl: (_url, init) => {
      const body = JSON.parse(String(init.body)) as Record<string, unknown>;
      bodies.push(body);
      return Promise.resolve(respond(body));
    },
  };
}

function json(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), { status, headers: { 'content-type': 'application/json' } });
}

/** A success whose `usage` is exactly what the caller hands in. */
function usageReply(usage: Record<string, unknown>): Response {
  return json({ id: 'gen', choices: [{ message: { role: 'assistant', content: 'ok' } }], usage });
}

async function call(gw: TestGateway, payload: Record<string, unknown>) {
  return gw.app.inject({ method: 'POST', url: '/v1/chat/completions', payload });
}

function entriesOf(gw: TestGateway, type: string): LedgerEntryV1[] {
  return (readLedger(gw.dbPath).entries as LedgerEntryV1[]).filter((entry) => entry.action.type === type);
}

function settledTotal(gw: TestGateway): number {
  return entriesOf(gw, LLM_CALL_RESULT).reduce((sum, entry) => sum + entry.cost.amount, 0);
}

function maxPriceOf(body: Record<string, unknown> | undefined): unknown {
  return (body?.provider as { max_price?: unknown } | undefined)?.max_price;
}

/** Upper-bound input tokens the door must assume for a body (bytes + hidden prompt). */
function inputBound(body: Record<string, unknown>): number {
  return Buffer.byteLength(JSON.stringify(body), 'utf8') + REQUEST_OVERHEAD_TOKENS;
}

/** BYOK: the provider bills the operator's key, OpenRouter adds 5% of list price. */
const BYOK = 1.05;

describe('1. unpriced models are refused, never reserved at the per-tx cap', () => {
  test('openrouter/auto answering $50: 403 MODEL_UNPRICED, provider never called, refusal recorded', async () => {
    const provider = upstream(() => usageReply({ prompt_tokens: 10, completion_tokens: 10, cost: 50 }));
    const gw = await openTestGateway({ fetchImpl: provider.fetchImpl });
    const response = await call(gw, { model: 'openrouter/auto', ...PROMPT });
    expect(response.statusCode).toBe(403);
    expect(response.json().code).toBe('MODEL_UNPRICED');
    expect(provider.bodies).toHaveLength(0);
    expect(await verifySpendProjection(gw.ledger)).toMatchObject({ ok: true });
    await gw.close();
    expect(entriesOf(gw, LLM_CALL_DENIED)).toHaveLength(1);
    expect(entriesOf(gw, LLM_CALL_INTENT)).toHaveLength(0);
    expect(settledTotal(gw)).toBe(0);
  });

  test('a priced primary with an unpriced fallback in `models` is refused the same way', async () => {
    const provider = upstream(() => usageReply({ prompt_tokens: 10, completion_tokens: 10, cost: 50 }));
    const gw = await openTestGateway({ fetchImpl: provider.fetchImpl });
    for (const models of [['openrouter/auto'], ['meta-llama/llama-4-maverick'], [HAIKU, 'x-ai/grok-9']]) {
      const response = await call(gw, { model: HAIKU, models, ...PROMPT });
      expect(response.statusCode).toBe(403);
      expect(response.json().code).toBe('MODEL_UNPRICED');
    }
    expect(provider.bodies).toHaveLength(0);
    await gw.close();
    expect(entriesOf(gw, LLM_CALL_DENIED)).toHaveLength(3);
    expect(settledTotal(gw)).toBe(0);
  });
});

describe('2. every priced OpenRouter call carries a provider.max_price ceiling at the row rates', () => {
  test('the upstream body names prompt/completion at the row rates and request at 0 — no image ceiling without images', async () => {
    const provider = upstream(() => usageReply({ prompt_tokens: 10, completion_tokens: 10, cost: 0.00006 }));
    const gw = await openTestGateway({ fetchImpl: provider.fetchImpl });
    const response = await call(gw, { model: HAIKU, ...PROMPT });
    expect(response.statusCode).toBe(200);
    await gw.close();
    expect(maxPriceOf(provider.bodies[0])).toEqual({ prompt: 1, completion: 5, request: 0 });
  });

  test('a request with images gets a per-image ceiling, and the reservation holds it', async () => {
    const provider = upstream(() => usageReply({ prompt_tokens: 10, completion_tokens: 10, cost: 0.0001 }));
    const gw = await openTestGateway({ fetchImpl: provider.fetchImpl });
    const body = {
      model: HAIKU,
      max_tokens: 100,
      messages: [
        {
          role: 'user',
          content: [
            { type: 'text', text: 'what is this?' },
            { type: 'image_url', image_url: { url: 'https://example.com/a.png' } },
          ],
        },
      ],
    };
    const response = await call(gw, body);
    expect(response.statusCode).toBe(200);
    await gw.close();
    // Haiku names no per-image ceiling: the adapter's 48,169 tokens at $1/M.
    const perImageUsd = (openrouterAdapter.imageTokensCeiling * 1) / 1_000_000;
    expect(maxPriceOf(provider.bodies[0])).toEqual({ prompt: 1, completion: 5, request: 0, image: perImageUsd });
    // Tokens (write rate) + one image billed per image on top + output, with BYOK headroom.
    const worstUsdMicros =
      (inputBound(body) + openrouterAdapter.imageTokensCeiling) * 1.25 + perImageUsd * 1_000_000 + 100 * 5;
    expect(entriesOf(gw, LLM_CALL_INTENT)[0]?.cost.amount).toBeGreaterThanOrEqual(worstUsdMicros * BYOK);
  });

  test('an agent-supplied max_price is merged with min(): it can lower the ceiling, never raise it', async () => {
    const provider = upstream(() => usageReply({ prompt_tokens: 10, completion_tokens: 10, cost: 0.00006 }));
    const gw = await openTestGateway({ fetchImpl: provider.fetchImpl });
    const raised = await call(gw, {
      model: HAIKU,
      ...PROMPT,
      provider: { sort: 'throughput', max_price: { prompt: 0.5, completion: 100, request: 1 } },
    });
    expect(raised.statusCode).toBe(200);
    const garbage = await call(gw, {
      model: HAIKU,
      ...PROMPT,
      provider: { max_price: { prompt: 'cheap', completion: -1, request: null } },
    });
    expect(garbage.statusCode).toBe(200);
    const notAnObject = await call(gw, { model: HAIKU, ...PROMPT, provider: { max_price: 'none' } });
    expect(notAnObject.statusCode).toBe(200);
    await gw.close();
    expect(provider.bodies[0]?.provider).toEqual({
      sort: 'throughput',
      max_price: { prompt: 0.5, completion: 5, request: 0 },
    });
    expect(maxPriceOf(provider.bodies[1])).toEqual({ prompt: 1, completion: 5, request: 0 });
    expect(maxPriceOf(provider.bodies[2])).toEqual({ prompt: 1, completion: 5, request: 0 });
  });

  test('a provider preference that is not an object is a 400, never forwarded', async () => {
    const provider = upstream(() => usageReply({ cost: 0 }));
    const gw = await openTestGateway({ fetchImpl: provider.fetchImpl });
    for (const bad of ['anthropic', ['anthropic'], 7]) {
      const response = await call(gw, { model: HAIKU, ...PROMPT, provider: bad });
      expect(response.statusCode).toBe(400);
    }
    expect(provider.bodies).toHaveLength(0);
    await gw.close();
  });

  test('with fallbacks the ceiling is the most expensive candidate, and the reservation bounds it', async () => {
    const provider = upstream(() => usageReply({ prompt_tokens: 10, completion_tokens: 10, cost: 0.0002 }));
    const gw = await openTestGateway({ fetchImpl: provider.fetchImpl });
    const body = { model: HAIKU, models: ['anthropic/claude-sonnet-4.6'], ...PROMPT };
    const response = await call(gw, body);
    expect(response.statusCode).toBe(200);
    await gw.close();
    expect(maxPriceOf(provider.bodies[0])).toEqual({ prompt: 3, completion: 15, request: 0 });
    const worstUsdMicros = inputBound(body) * 3.75 + 100 * 15;
    expect(entriesOf(gw, LLM_CALL_INTENT)[0]?.cost.amount).toBeGreaterThanOrEqual(worstUsdMicros * BYOK);
  });

  test('a router that honors the ceiling never serves the pricier (regional / fast-tier) endpoint', async () => {
    // Endpoints in the router's preference order: a pinned premium endpoint
    // first (10× Haiku), then the list-price one. $/M rates.
    const endpoints = [
      { slug: 'anthropic/fast', prompt: 10, completion: 50 },
      { slug: 'anthropic', prompt: 1, completion: 5 },
    ];
    const served: string[] = [];
    const router = upstream((body) => {
      const ceiling = maxPriceOf(body) as { prompt: number; completion: number } | undefined;
      const endpoint = endpoints.find(
        (candidate) =>
          ceiling === undefined || (candidate.prompt <= ceiling.prompt && candidate.completion <= ceiling.completion)
      );
      if (endpoint === undefined) {
        return json({ error: { code: 404, message: 'No endpoints found matching your price constraints' } }, 404);
      }
      served.push(endpoint.slug);
      const [promptTokens, completionTokens] = [20, 100];
      const cost = (promptTokens * endpoint.prompt + completionTokens * endpoint.completion) / 1_000_000;
      return usageReply({ prompt_tokens: promptTokens, completion_tokens: completionTokens, cost });
    });
    const gw = await openTestGateway({ fetchImpl: router.fetchImpl });
    const response = await call(gw, { model: HAIKU, ...PROMPT, provider: { order: ['anthropic/fast'] } });
    expect(response.statusCode).toBe(200);
    await gw.close();
    expect(served).toEqual(['anthropic']);
    const [intent] = entriesOf(gw, LLM_CALL_INTENT);
    const [result] = entriesOf(gw, LLM_CALL_RESULT);
    expect(result?.cost.amount).toBe(20 * 1 + 100 * 5);
    expect(result?.cost.amount).toBeLessThanOrEqual(intent?.cost.amount ?? 0);
  });

  test('a ceiling no endpoint can meet fails upstream and settles 0', async () => {
    const provider = upstream(() =>
      json({ error: { code: 404, message: 'No endpoints found matching your price constraints' } }, 404)
    );
    const gw = await openTestGateway({ fetchImpl: provider.fetchImpl });
    const response = await call(gw, { model: HAIKU, ...PROMPT });
    expect(response.statusCode).toBe(404);
    expect(await verifySpendProjection(gw.ledger)).toMatchObject({ ok: true });
    await gw.close();
    expect(maxPriceOf(provider.bodies[0])).toEqual({ prompt: 1, completion: 5, request: 0 });
    expect(entriesOf(gw, LLM_CALL_RESULT).map((entry) => entry.cost.amount)).toEqual([0]);
  });
});

describe('3. BYOK: the provider bill counts, not just the OpenRouter fee', () => {
  const cases: { name: string; usage: Record<string, unknown>; settles: number }[] = [
    {
      name: 'BYOK (is_byok): fee + upstream',
      usage: { is_byok: true, cost: 0.00005, cost_details: { upstream_inference_cost: 0.001 } },
      settles: 1_050,
    },
    {
      name: 'non-BYOK reporting its upstream cost too: cost only (no double count)',
      usage: { is_byok: false, cost: 0.001, cost_details: { upstream_inference_cost: 0.001 } },
      settles: 1_000,
    },
    {
      name: 'the docs shape without is_byok (upstream ≫ cost is the BYOK signature): fee + upstream',
      usage: { cost: 0.00005, cost_details: { upstream_inference_cost: 0.001 } },
      settles: 1_050,
    },
    {
      name: 'no is_byok, upstream ≤ cost: cost only',
      usage: { cost: 0.001, cost_details: { upstream_inference_cost: 0.0009 } },
      settles: 1_000,
    },
    {
      name: 'non-BYOK with no cost_details at all: cost',
      usage: { cost: 0.001 },
      settles: 1_000,
    },
  ];
  for (const { name, usage, settles } of cases) {
    test(name, async () => {
      const provider = upstream(() => usageReply({ prompt_tokens: 10, completion_tokens: 10, ...usage }));
      const gw = await openTestGateway({ fetchImpl: provider.fetchImpl });
      expect((await call(gw, { model: HAIKU, ...PROMPT })).statusCode).toBe(200);
      await gw.close();
      expect(entriesOf(gw, LLM_CALL_RESULT)[0]?.cost.amount).toBe(settles);
    });
  }

  test.each([
    ['the upstream cost', { is_byok: true, cost: 0.00005 }],
    ['the fee', { is_byok: true, cost_details: { upstream_inference_cost: 0.001 } }],
  ])('BYOK with %s missing is outcome-unknown: never settled below the reservation', async (_missing, usage) => {
    const provider = upstream(() => usageReply({ prompt_tokens: 10, completion_tokens: 10, ...usage }));
    const gw = await openTestGateway({ fetchImpl: provider.fetchImpl });
    expect((await call(gw, { model: HAIKU, ...PROMPT })).statusCode).toBe(200);
    await gw.close();
    const [intent] = entriesOf(gw, LLM_CALL_INTENT);
    const [result] = entriesOf(gw, LLM_CALL_RESULT);
    expect(result?.cost.amount).toBeGreaterThanOrEqual(intent?.cost.amount ?? Infinity);
  });

  test('a BYOK stream settles fee + upstream from the final usage chunk', async () => {
    const chunks = [
      'data: {"choices":[{"delta":{"content":"ok"}}]}\n\n',
      `data: ${JSON.stringify({
        choices: [],
        usage: {
          prompt_tokens: 10,
          completion_tokens: 10,
          is_byok: true,
          cost: 0.00005,
          cost_details: { upstream_inference_cost: 0.001 },
        },
      })}\n\n`,
      'data: [DONE]\n\n',
    ];
    const gw = await openTestGateway({
      fetchImpl: () =>
        Promise.resolve(
          new Response(chunks.join(''), { status: 200, headers: { 'content-type': 'text/event-stream' } })
        ),
    });
    const address = await gw.app.listen({ host: '127.0.0.1', port: 0 });
    const response = await fetch(`${address}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: HAIKU, ...PROMPT, stream: true }),
    });
    await response.text();
    await gw.close();
    expect(entriesOf(gw, LLM_CALL_RESULT)[0]?.cost.amount).toBe(1_050);
  });

  test('the reservation covers a worst-case BYOK call: every bound token at the ceiling, plus the 5% fee', async () => {
    const provider = upstream(() => usageReply({ cost: 0 }));
    const gw = await openTestGateway({ fetchImpl: provider.fetchImpl });
    const body = { model: 'anthropic/claude-haiku-4-5', ...PROMPT };
    expect((await call(gw, body)).statusCode).toBe(200);
    await gw.close();
    // Haiku states a cache-write rate ($1.25/M): OpenRouter may write the prompt.
    const worstUpstreamUsdMicros = inputBound(body) * 1.25 + 100 * 5;
    expect(entriesOf(gw, LLM_CALL_INTENT)[0]?.cost.amount).toBeGreaterThanOrEqual(
      worstUpstreamUsdMicros * BYOK
    );
  });
});

describe('4. fee-adding variants are refused even when the base id is priced', () => {
  const refusedVariants = [
    `${HAIKU}:online`,
    `${HAIKU}:nitro`,
    `${HAIKU}:exacto`,
    `${HAIKU}:thinking`,
    `${HAIKU}:extended`,
    `${HAIKU}:batch`,
    `${HAIKU}:free:online`,
    `${HAIKU}:someday-new`,
  ];

  test.each(refusedVariants)('%s → COST_UNBOUNDED, provider never called', async (model) => {
    const provider = upstream(() => usageReply({ cost: 0.001 }));
    // An operator row naming the suffixed id does not make its per-use fees priced.
    const table: ModelPricing[] = [
      { model: model.slice('anthropic/'.length), inUsdPerM: 1, outUsdPerM: 5, maxOutputTokens: 64_000, maxInputTokens: 200_000 },
      ...DEFAULT_PRICING,
    ];
    const gw = await openTestGateway({ fetchImpl: provider.fetchImpl, pricingTable: table });
    const response = await call(gw, { model, ...PROMPT });
    expect(response.statusCode).toBe(403);
    expect(response.json().code).toBe('COST_UNBOUNDED');
    expect(provider.bodies).toHaveLength(0);
    await gw.close();
    expect(entriesOf(gw, LLM_CALL_DENIED)).toHaveLength(1);
  });

  test('a fee-adding variant hidden in `models` is refused too', async () => {
    const provider = upstream(() => usageReply({ cost: 0.001 }));
    const gw = await openTestGateway({ fetchImpl: provider.fetchImpl });
    const response = await call(gw, { model: HAIKU, models: [`${HAIKU}:online`], ...PROMPT });
    expect(response.statusCode).toBe(403);
    expect(response.json().code).toBe('COST_UNBOUNDED');
    expect(provider.bodies).toHaveLength(0);
    await gw.close();
  });

  test.each([`${HAIKU}:floor`, `${HAIKU}:free`])(
    '%s (price-sorted / free: can only cost less) runs under the base row ceiling',
    async (model) => {
      const provider = upstream(() => usageReply({ prompt_tokens: 10, completion_tokens: 10, cost: 0.00006 }));
      const gw = await openTestGateway({ fetchImpl: provider.fetchImpl });
      expect((await call(gw, { model, ...PROMPT })).statusCode).toBe(200);
      await gw.close();
      expect(provider.bodies[0]?.model).toBe(model);
      expect(maxPriceOf(provider.bodies[0])).toEqual({ prompt: 1, completion: 5, request: 0 });
    }
  );
});

describe('dimensions max_price does not bound are bounded by the reservation or refused', () => {
  test('long context: an input bound at the row window is refused (long-context override rates)', async () => {
    const provider = upstream(() => usageReply({ cost: 0.001 }));
    const gw = await openTestGateway({ fetchImpl: provider.fetchImpl });
    // Sonnet 4.5 bills 2×/1.5× above 200K prompt tokens on OpenRouter; its
    // row's window is 200K. ~200K bytes ⇒ the bound (not the likely count)
    // crosses it.
    const response = await call(gw, {
      model: 'anthropic/claude-sonnet-4.5',
      max_tokens: 100,
      messages: [{ role: 'user', content: 'a'.repeat(200_000) }],
    });
    expect(response.statusCode).toBe(403);
    expect(response.json().code).toBe('COST_UNBOUNDED');
    expect(provider.bodies).toHaveLength(0);
    await gw.close();
  });

  test('an operator row with no context window cannot run through OpenRouter (overrides unbounded)', async () => {
    const provider = upstream(() => usageReply({ cost: 0.001 }));
    const gw = await openTestGateway({
      fetchImpl: provider.fetchImpl,
      pricingTable: [{ model: 'google/gemini-9-pro', inUsdPerM: 1, outUsdPerM: 5, maxOutputTokens: 8_192 }],
    });
    const response = await call(gw, { model: 'google/gemini-9-pro', ...PROMPT });
    expect(response.statusCode).toBe(403);
    expect(response.json().code).toBe('COST_UNBOUNDED');
    expect(provider.bodies).toHaveLength(0);
    await gw.close();
  });

  test('cache_control with a 1h TTL reserves the prompt at the 1h write rate', async () => {
    const provider = upstream(() => usageReply({ cost: 0 }));
    const gw = await openTestGateway({ fetchImpl: provider.fetchImpl });
    const body = {
      model: 'anthropic/claude-haiku-4-5',
      max_tokens: 100,
      messages: [
        {
          role: 'user',
          content: [{ type: 'text', text: 'a long shared prefix', cache_control: { type: 'ephemeral', ttl: '1h' } }],
        },
      ],
    };
    expect((await call(gw, body)).statusCode).toBe(200);
    await gw.close();
    const worstUsdMicros = inputBound(body) * 2 + 100 * 5;
    expect(entriesOf(gw, LLM_CALL_INTENT)[0]?.cost.amount).toBeGreaterThanOrEqual(worstUsdMicros * BYOK);
  });

  test('a reasoning budget beyond max_tokens is reserved at the output rate', async () => {
    const provider = upstream(() => usageReply({ cost: 0 }));
    const gw = await openTestGateway({ fetchImpl: provider.fetchImpl });
    const body = { model: 'anthropic/claude-haiku-4-5', ...PROMPT, reasoning: { max_tokens: 50_000 } };
    expect((await call(gw, body)).statusCode).toBe(200);
    await gw.close();
    const worstUsdMicros = inputBound(body) * 1.25 + (100 + 50_000) * 5;
    expect(entriesOf(gw, LLM_CALL_INTENT)[0]?.cost.amount).toBeGreaterThanOrEqual(worstUsdMicros * BYOK);
  });
});

describe("5. OpenRouter's dotted Claude ids price at their dashed rows", () => {
  // Verified on openrouter.ai/api/v1/models (2026-09-26).
  const verified: [dotted: string, dashed: string][] = [
    ['anthropic/claude-fable-5.1', 'claude-fable-5-1'],
    ['anthropic/claude-opus-5.5', 'claude-opus-5-5'],
    ['anthropic/claude-opus-4.8', 'claude-opus-4-8'],
    ['anthropic/claude-opus-4.7', 'claude-opus-4-7'],
    ['anthropic/claude-opus-4.6', 'claude-opus-4-6'],
    ['anthropic/claude-sonnet-4.6', 'claude-sonnet-4-6'],
    ['anthropic/claude-opus-4.5', 'claude-opus-4-5'],
    ['anthropic/claude-sonnet-4.5', 'claude-sonnet-4-5'],
    ['anthropic/claude-haiku-4.5', 'claude-haiku-4-5'],
    ['anthropic/claude-opus-4.1', 'claude-opus-4-1'],
  ];
  test.each(verified)('%s → %s', (dotted, dashed) => {
    const row = findPricing(dotted);
    expect(row).not.toBeNull();
    expect(row?.model).toBe(dashed);
  });
});
