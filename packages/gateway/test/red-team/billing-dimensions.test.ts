import { describe, expect, test } from 'vitest';

import { readLedger } from '@mandarelabs/ledger';
import type { LedgerEntryV1 } from '@mandarelabs/spec';

import { anthropicBody, chatBody, openTestGateway, sseFetch } from '../helpers.js';
import { listenAndStream } from '../stream-helpers.js';
import type { FetchLike } from '../../src/providers/types.js';

/**
 * RED-TEAM (R1/R5, S-4): when a provider returns no cost, the price table IS
 * the ledger's truth — so every billing dimension an agent can choose must be
 * priced at what the provider actually bills. A hijacked agent picks the
 * model variant, asks for cached or cache-writing prompts, and triggers paid
 * server-side work; each probe below asserts the settled amount equals the
 * real bill, not a cheaper sibling's.
 */

function jsonProvider(payload: Record<string, unknown>): FetchLike {
  return () =>
    Promise.resolve(
      new Response(JSON.stringify(payload), { status: 200, headers: { 'content-type': 'application/json' } })
    );
}

function settledEntry(dbPath: string): LedgerEntryV1 {
  const { entries } = readLedger(dbPath);
  const result = (entries as LedgerEntryV1[]).find((entry) => entry.action.type === 'llm.call.result');
  if (result === undefined) throw new Error('no result entry');
  return result;
}

describe('agent-chosen billing dimensions settle at the real bill (S-4)', () => {
  test('S-4a: an unlisted model variant (audio preview) is refused MODEL_UNPRICED, not priced as its text sibling', async () => {
    let upstreamCalled = false;
    const gw = await openTestGateway({
      config: { chatProvider: 'openai' },
      fetchImpl: () => {
        upstreamCalled = true;
        return jsonProvider({ usage: { prompt_tokens: 10, completion_tokens: 10 } })('', {});
      },
    });
    for (const model of ['gpt-4o-audio-preview', 'gpt-5-pro', 'gpt-4o-mini-2099-01-01']) {
      const response = await gw.app.inject({
        method: 'POST',
        url: '/v1/chat/completions',
        payload: { ...chatBody, model },
      });
      expect(response.statusCode).toBe(403);
      expect(response.json().code).toBe('MODEL_UNPRICED');
    }
    expect(upstreamCalled).toBe(false);
    await gw.close();
  });

  test('S-4b: cached gpt-4o input settles at the 0.5× cached rate', async () => {
    const gw = await openTestGateway({
      config: { chatProvider: 'openai' },
      fetchImpl: jsonProvider({
        choices: [{ message: { role: 'assistant', content: 'ok' } }],
        usage: { prompt_tokens: 10_000, prompt_tokens_details: { cached_tokens: 8_000 }, completion_tokens: 100 },
      }),
    });
    const response = await gw.app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: { ...chatBody, model: 'gpt-4o' },
    });
    expect(response.statusCode).toBe(200);
    await gw.close();
    // 2,000 × $2.50/M + 8,000 × $1.25/M + 100 × $10/M = $0.016.
    expect(settledEntry(gw.dbPath).cost.amount).toBe(16_000);
  });

  test('S-4b: a 1-hour cache write settles at the 1h rate (2× input)', async () => {
    const gw = await openTestGateway({
      fetchImpl: jsonProvider({
        type: 'message',
        content: [],
        usage: {
          input_tokens: 10,
          cache_creation_input_tokens: 10_000,
          cache_creation: { ephemeral_5m_input_tokens: 0, ephemeral_1h_input_tokens: 10_000 },
          output_tokens: 10,
        },
      }),
    });
    const response = await gw.app.inject({ method: 'POST', url: '/v1/messages', payload: anthropicBody });
    expect(response.statusCode).toBe(200);
    await gw.close();
    // 10 × $1/M + 10,000 × $2/M + 10 × $5/M.
    expect(settledEntry(gw.dbPath).cost.amount).toBe(10 + 20_000 + 50);
  });

  test('S-4c: Anthropic web-search fees reach the settled cost (non-stream)', async () => {
    const gw = await openTestGateway({
      fetchImpl: jsonProvider({
        type: 'message',
        content: [],
        usage: { input_tokens: 100, output_tokens: 50, server_tool_use: { web_search_requests: 3 } },
      }),
    });
    const response = await gw.app.inject({ method: 'POST', url: '/v1/messages', payload: anthropicBody });
    expect(response.statusCode).toBe(200);
    await gw.close();
    // 100 × $1/M + 50 × $5/M + 3 × $0.01.
    expect(settledEntry(gw.dbPath).cost.amount).toBe(100 + 250 + 30_000);
  });

  test('S-4c: web-search fees reported in the final message_delta reach a streamed settle', async () => {
    const gw = await openTestGateway({
      fetchImpl: sseFetch([
        'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":100,"output_tokens":1}}}\n\n',
        'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":50,"server_tool_use":{"web_search_requests":2}}}\n\n',
        'event: message_stop\ndata: {"type":"message_stop"}\n\n',
      ]),
    });
    await listenAndStream(gw, '/v1/messages', anthropicBody);
    await gw.close();
    expect(settledEntry(gw.dbPath).cost.amount).toBe(100 + 250 + 20_000);
  });

  test('S-4c: OpenAI audio tokens settle at audio rates, not as text', async () => {
    const gw = await openTestGateway({
      config: { chatProvider: 'openai' },
      fetchImpl: jsonProvider({
        choices: [{ message: { role: 'assistant', content: 'ok' } }],
        usage: {
          prompt_tokens: 1_000,
          prompt_tokens_details: { audio_tokens: 800 },
          completion_tokens: 100,
          completion_tokens_details: { audio_tokens: 50 },
        },
      }),
    });
    const response = await gw.app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: { ...chatBody, model: 'gpt-4o-mini' },
    });
    expect(response.statusCode).toBe(200);
    await gw.close();
    // Text: 200 × $0.15/M + 50 × $0.60/M; audio at the $100/$200 fallback.
    expect(settledEntry(gw.dbPath).cost.amount).toBe(30 + 30 + 80_000 + 10_000);
  });

  test('US-only inference (inference_geo "us") settles at 1.1× — reserved and billed', async () => {
    const usage = { input_tokens: 1_000, output_tokens: 100 };
    const plain = await openTestGateway({ fetchImpl: jsonProvider({ type: 'message', content: [], usage }) });
    await plain.app.inject({ method: 'POST', url: '/v1/messages', payload: anthropicBody });
    await plain.close();
    const us = await openTestGateway({ fetchImpl: jsonProvider({ type: 'message', content: [], usage }) });
    await us.app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: { ...anthropicBody, inference_geo: 'us' },
    });
    await us.close();
    expect(settledEntry(plain.dbPath).cost.amount).toBe(1_500);
    expect(settledEntry(us.dbPath).cost.amount).toBe(1_650);
    const intent = (dbPath: string): number =>
      (readLedger(dbPath).entries[0] as LedgerEntryV1).cost.amount;
    expect(intent(us.dbPath)).toBeGreaterThanOrEqual(Math.floor(intent(plain.dbPath) * 1.1));
  });
});
