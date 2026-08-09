import { describe, expect, test } from 'vitest';

import { readLedger } from '@mandarelabs/ledger';
import type { LedgerEntryV1 } from '@mandarelabs/spec';

import { anthropicBody, chatBody, openTestGateway, sseFetch } from './helpers.js';
import type { FetchLike } from '../src/providers/types.js';

/**
 * Streaming true-up per BUILD-DECISIONS Q16, tested over a real socket
 * (streams hijack the reply, so inject() cannot see them).
 */

async function listenAndCall(
  gw: Awaited<ReturnType<typeof openTestGateway>>,
  path: string,
  body: Record<string, unknown>
): Promise<{ status: number; text: string; intentHeader: string | null }> {
  const address = await gw.app.listen({ host: '127.0.0.1', port: 0 });
  const response = await fetch(`${address}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ...body, stream: true }),
  });
  const text = await response.text();
  return {
    status: response.status,
    text,
    intentHeader: response.headers.get('x-mandare-intent-entry'),
  };
}

describe('streaming pass-through + usage tee', () => {
  test('openai: stream_options.include_usage is injected; final usage chunk settles the cost', async () => {
    let upstreamBody: Record<string, unknown> = {};
    const upstream: FetchLike = (url, init) => {
      upstreamBody = JSON.parse(String(init.body)) as Record<string, unknown>;
      return sseFetch([
        'data: {"choices":[{"delta":{"content":"Hel"}}]}\n\n',
        'data: {"choices":[{"delta":{"content":"lo"}}]}\n\n',
        'data: {"choices":[],"usage":{"prompt_tokens":1000,"completion_tokens":2000}}\n\n',
        'data: [DONE]\n\n',
      ])(url, init);
    };
    const gw = await openTestGateway({
      config: { chatProvider: 'openai' },
      fetchImpl: upstream,
    });
    const result = await listenAndCall(gw, '/v1/chat/completions', {
      ...chatBody,
      model: 'gpt-4o-mini',
    });
    await gw.close();

    expect(result.status).toBe(200);
    expect(result.intentHeader).toMatch(/^[0-9a-f]{64}$/);
    expect(result.text).toContain('"Hel"');
    expect(result.text).toContain('[DONE]');
    expect(result.text).toContain(': x-mandare-result-entry ');
    expect((upstreamBody.stream_options as { include_usage: boolean }).include_usage).toBe(true);

    const { entries } = readLedger(gw.dbPath);
    expect(entries).toHaveLength(2);
    const result_ = entries[1] as LedgerEntryV1;
    // gpt-4o-mini: 1000×$0.15/M + 2000×$0.60/M = $0.00135 → 1350 micros.
    expect(result_.cost.amount).toBe(1350);
    expect(result_.cost.tokens_in).toBe(1000);
    expect(result_.cost.tokens_out).toBe(2000);
  });

  test('anthropic: message_start input merges with the final message_delta output (Q16)', async () => {
    const gw = await openTestGateway({
      fetchImpl: sseFetch([
        'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":1000,"cache_read_input_tokens":0}}}\n\n',
        'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hi"}}\n\n',
        'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":40}}\n\n',
        'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":95}}\n\n',
        'event: message_stop\ndata: {"type":"message_stop"}\n\n',
      ]),
    });
    const result = await listenAndCall(gw, '/v1/messages', anthropicBody);
    await gw.close();

    expect(result.status).toBe(200);
    const { entries } = readLedger(gw.dbPath);
    const settled = entries[1] as LedgerEntryV1;
    // Final delta wins (cumulative): 1000×$1/M + 95×$5/M = $0.001475 → 1475.
    expect(settled.cost.amount).toBe(1475);
    expect(settled.cost.tokens_in).toBe(1000);
    expect(settled.cost.tokens_out).toBe(95);
  });

  test('openrouter stream: authoritative cost from the final usage chunk wins over table math', async () => {
    const gw = await openTestGateway({
      fetchImpl: sseFetch([
        'data: {"choices":[{"delta":{"content":"x"}}]}\n\n',
        'data: {"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":20,"cost":0.5}}\n\n',
        'data: [DONE]\n\n',
      ]),
    });
    const result = await listenAndCall(gw, '/v1/chat/completions', chatBody);
    await gw.close();
    expect(result.status).toBe(200);
    const { entries } = readLedger(gw.dbPath);
    expect((entries[1] as LedgerEntryV1).cost.amount).toBe(500_000); // $0.50
  });

  test('aborted stream (upstream dies mid-flight) settles from observed text, not zero (Q16)', async () => {
    const upstream: FetchLike = () => {
      const encoder = new TextEncoder();
      let sentChunk = false;
      const bodyStream = new ReadableStream<Uint8Array>({
        // pull-based so the chunk is DELIVERED before the stream errors.
        pull(controller) {
          if (!sentChunk) {
            sentChunk = true;
            controller.enqueue(
              encoder.encode(
                'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":600}}}\n\n' +
                  'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"partial output text"}}\n\n'
              )
            );
            return;
          }
          controller.error(new Error('connection reset (test)'));
        },
      });
      return Promise.resolve(
        new Response(bodyStream, { status: 200, headers: { 'content-type': 'text/event-stream' } })
      );
    };
    const gw = await openTestGateway({ fetchImpl: upstream });
    const result = await listenAndCall(gw, '/v1/messages', anthropicBody);
    await gw.close();

    expect(result.status).toBe(200); // headers were already committed
    const { entries } = readLedger(gw.dbPath);
    expect(entries).toHaveLength(2);
    const settled = entries[1] as LedgerEntryV1;
    // Estimation path: input 600 (from message_start), output = the observed
    // text's UTF-8 byte count as a token UPPER bound (S8/S1): 'partial output
    // text' = 19 bytes ⇒ 19 (never under-records a token-dense aborted stream).
    expect(settled.cost.tokens_in).toBe(600);
    expect(settled.cost.tokens_out).toBe(19);
    expect(settled.cost.amount).toBeGreaterThan(0);
    expect(settled.outcome_ref).toBe((entries[0] as LedgerEntryV1).entry_hash);
  });

  test('provider refusing the stream (non-200) is settled 0 and passed through buffered', async () => {
    const gw = await openTestGateway({
      fetchImpl: () =>
        Promise.resolve(
          new Response(JSON.stringify({ error: 'overloaded' }), {
            status: 529,
            headers: { 'content-type': 'application/json' },
          })
        ),
    });
    const result = await listenAndCall(gw, '/v1/messages', anthropicBody);
    await gw.close();
    expect(result.status).toBe(529);
    const { entries } = readLedger(gw.dbPath);
    expect((entries[1] as LedgerEntryV1).cost.amount).toBe(0);
  });
});
