import { describe, expect, test } from 'vitest';

import { verifySpendProjection } from '@mandarelabs/ledger';

import { anthropicBody, chatBody, openTestGateway } from '../helpers.js';
import {
  anthropicEvent,
  chatChunk,
  pacedSseFetch,
  reservedToday,
  settledPair,
  streamRequest,
} from '../stream-helpers.js';

/**
 * RED-TEAM (R1/R3/R5): a stream is the one call whose true cost arrives LAST —
 * in its final usage event. Everything before that is a partial picture, so
 * the settlement must never let "no authoritative usage" read as "cheap":
 *
 * - S-1: a stream that ends without its final usage (stalled, aborted, cut by
 *   the client, or a usage-less endpoint) settles at no less than the
 *   reservation — the same conservative rule as a non-stream "outcome
 *   unknown" — and the partial usage it did carry (cache writes, thinking,
 *   tool JSON) raises that floor, never lowers it.
 * - S-3: a client that hangs up mid-stream is noticed, the intent is settled
 *   (log-before-act: no intent left unpaired) and the reservation released;
 *   the handler never hangs on a drain that cannot come.
 *
 * A hijacked agent controls its own socket (stop reading, hang up) and the
 * request shape (what the provider streams back). These are its levers.
 */

const HAIKU_CACHE_WRITE_MICROS_PER_TOKEN = 1.25; // $1.25/M at 1 USD per ledger unit

describe('stream settlement under adversarial endings (S-1 / S-3)', () => {
  test('S-1: provider stalls after message_start carrying a large cache write — settles ≥ the reservation and ≥ the cache-write cost', async () => {
    const cacheWrite = 200_000;
    const upstream = pacedSseFetch(
      [
        anthropicEvent('message_start', {
          message: { usage: { input_tokens: 12, cache_creation_input_tokens: cacheWrite, output_tokens: 1 } },
        }),
      ],
      { intervalMs: 5, stallAfter: true }
    );
    const gw = await openTestGateway({
      fetchImpl: upstream,
      timeouts: { nonStreamMs: 5_000, streamIdleMs: 200 },
    });
    const address = await gw.app.listen({ host: '127.0.0.1', port: 0 });
    const client = await streamRequest(address, '/v1/messages', anthropicBody, 'read-all');
    expect(client.text).toContain('message_start');

    const { intent, result } = await settledPair(gw);
    // No final message_delta ⇒ no authoritative usage ⇒ never below the reservation…
    expect(result.cost.amount).toBeGreaterThanOrEqual(intent.cost.amount);
    // …and the cache write the provider DID report is billed, not dropped.
    expect(result.cost.amount).toBeGreaterThanOrEqual(cacheWrite * HAIKU_CACHE_WRITE_MICROS_PER_TOKEN);
    expect(result.cost.tokens_in).toBeGreaterThanOrEqual(cacheWrite + 12);
    expect(await reservedToday(gw)).toBe(0);
    expect(await verifySpendProjection(gw.ledger)).toMatchObject({ ok: true });
    await gw.close();
  }, 15_000);

  test('S-1: the client stops reading past streamIdleMs — the door cuts the stream, never hangs, and settles ≥ the reservation', async () => {
    const cacheWrite = 150_000;
    const bigDelta = anthropicEvent('content_block_delta', {
      index: 0,
      delta: { type: 'text_delta', text: 'x'.repeat(64 * 1024) },
    });
    const upstream = pacedSseFetch(
      [
        anthropicEvent('message_start', {
          message: { usage: { input_tokens: 12, cache_creation_input_tokens: cacheWrite, output_tokens: 1 } },
        }),
        // ~4 MB of output: far more than the socket buffers hold, so a client
        // that stops reading leaves the door waiting on backpressure.
        ...Array.from({ length: 64 }, () => bigDelta),
        anthropicEvent('message_delta', { usage: { output_tokens: 70_000 } }),
        anthropicEvent('message_stop', {}),
      ],
      { intervalMs: 1 }
    );
    const gw = await openTestGateway({
      fetchImpl: upstream,
      timeouts: { nonStreamMs: 5_000, streamIdleMs: 300 },
    });
    const address = await gw.app.listen({ host: '127.0.0.1', port: 0 });
    // The agent stops reading for 1.5 s (5× the idle window), then looks.
    const client = await streamRequest(address, '/v1/messages', anthropicBody, {
      stallForMs: 1_500,
      then: 'resume',
    });

    const { intent, result } = await settledPair(gw, 5_000);
    expect(result.cost.amount).toBeGreaterThanOrEqual(intent.cost.amount);
    expect(result.cost.amount).toBeGreaterThanOrEqual(cacheWrite * HAIKU_CACHE_WRITE_MICROS_PER_TOKEN);
    // The stalled client does not pin the socket (or the reservation): the
    // door cut the stream and closed the connection itself.
    expect(client.closedByServer).toBe(true);
    expect(client.text).not.toContain('message_stop');
    expect(upstream.aborted()).toBe(true);
    expect(await reservedToday(gw)).toBe(0);
    await gw.close();
  }, 20_000);

  test('S-1: a stream that ends WITHOUT its final usage (usage-less endpoint) settles ≥ the reservation, counting thinking + tool-JSON output', async () => {
    const thinking = 'reasoning '.repeat(400); // 4,000 bytes
    const toolJson = '{"query":"' + 'q'.repeat(3_000) + '"}';
    const upstream = pacedSseFetch(
      [
        anthropicEvent('message_start', { message: { usage: { input_tokens: 12, output_tokens: 1 } } }),
        anthropicEvent('content_block_delta', { index: 0, delta: { type: 'thinking_delta', thinking } }),
        anthropicEvent('content_block_delta', {
          index: 1,
          delta: { type: 'input_json_delta', partial_json: toolJson },
        }),
        anthropicEvent('content_block_delta', { index: 2, delta: { type: 'text_delta', text: 'ok' } }),
        // …and the stream simply ends: no message_delta, no message_stop.
      ],
      { intervalMs: 5 }
    );
    const gw = await openTestGateway({ fetchImpl: upstream });
    const address = await gw.app.listen({ host: '127.0.0.1', port: 0 });
    await streamRequest(address, '/v1/messages', anthropicBody, 'read-all');

    const { intent, result } = await settledPair(gw);
    expect(result.cost.amount).toBeGreaterThanOrEqual(intent.cost.amount);
    // Every output delta type is observed output, not just text.
    const observedBytes = Buffer.byteLength(thinking) + Buffer.byteLength(toolJson) + 2;
    expect(result.cost.tokens_out).toBeGreaterThanOrEqual(observedBytes);
    await gw.close();
  }, 15_000);

  test('S-1: an OpenAI stream of tool_calls with no usage chunk settles ≥ the reservation and counts the tool-call arguments', async () => {
    const args = '{"path":"' + 'p'.repeat(5_000) + '"}';
    const upstream = pacedSseFetch(
      [
        chatChunk({
          choices: [
            {
              index: 0,
              delta: { tool_calls: [{ index: 0, id: 'call_1', type: 'function', function: { name: 'read', arguments: '' } }] },
            },
          ],
        }),
        chatChunk({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: args } }] } }] }),
        'data: [DONE]\n\n',
      ],
      { intervalMs: 5 }
    );
    const gw = await openTestGateway({ config: { chatProvider: 'openai' }, fetchImpl: upstream });
    const address = await gw.app.listen({ host: '127.0.0.1', port: 0 });
    await streamRequest(
      address,
      '/v1/chat/completions',
      {
        ...chatBody,
        model: 'gpt-4o-mini',
        max_tokens: 4_000,
        tools: [
          {
            type: 'function',
            function: { name: 'read', description: 'd'.repeat(20_000), parameters: { type: 'object' } },
          },
        ],
      },
      'read-all'
    );

    const { intent, result } = await settledPair(gw);
    expect(result.cost.amount).toBeGreaterThanOrEqual(intent.cost.amount);
    expect(result.cost.tokens_out).toBeGreaterThanOrEqual(Buffer.byteLength(args));
    // Input is estimated from the WHOLE body (the 20 KB tool description too).
    expect(result.cost.tokens_in).toBeGreaterThanOrEqual(20_000);
    await gw.close();
  }, 15_000);

  test('S-3: the client hangs up mid-stream — the door notices, aborts upstream, settles the intent (R3) and releases the reservation', async () => {
    // A provider that would stream forever. The idle timer is far away, so
    // only the DISCONNECT itself can end this call in time.
    const upstream = pacedSseFetch(
      [
        anthropicEvent('message_start', { message: { usage: { input_tokens: 12, output_tokens: 1 } } }),
        ...Array.from({ length: 2_000 }, () =>
          anthropicEvent('content_block_delta', { index: 0, delta: { type: 'text_delta', text: 'tick ' } })
        ),
      ],
      { intervalMs: 20 }
    );
    const gw = await openTestGateway({
      fetchImpl: upstream,
      timeouts: { nonStreamMs: 30_000, streamIdleMs: 30_000 },
    });
    const address = await gw.app.listen({ host: '127.0.0.1', port: 0 });
    await streamRequest(address, '/v1/messages', anthropicBody, 'disconnect-after-first-chunk');

    const { intent, result } = await settledPair(gw, 3_000);
    expect(result.outcome_ref).toBe(intent.entry_hash);
    expect(result.cost.amount).toBeGreaterThanOrEqual(intent.cost.amount);
    expect(upstream.aborted()).toBe(true);
    expect(await reservedToday(gw)).toBe(0);
    expect(await verifySpendProjection(gw.ledger)).toMatchObject({ ok: true });
    await gw.close();
  }, 15_000);

  test('S-3: a hang-up while the door is blocked on backpressure — the drain wait races the close, nothing hangs', async () => {
    const upstream = pacedSseFetch(
      [
        anthropicEvent('message_start', { message: { usage: { input_tokens: 12, output_tokens: 1 } } }),
        ...Array.from({ length: 128 }, () =>
          anthropicEvent('content_block_delta', {
            index: 0,
            delta: { type: 'text_delta', text: 'y'.repeat(64 * 1024) },
          })
        ),
      ],
      { intervalMs: 1, stallAfter: true }
    );
    const gw = await openTestGateway({
      fetchImpl: upstream,
      timeouts: { nonStreamMs: 30_000, streamIdleMs: 30_000 },
    });
    const address = await gw.app.listen({ host: '127.0.0.1', port: 0 });
    await streamRequest(address, '/v1/messages', anthropicBody, { stallForMs: 300, then: 'disconnect' });

    const { intent, result } = await settledPair(gw, 3_000);
    expect(result.cost.amount).toBeGreaterThanOrEqual(intent.cost.amount);
    expect(await reservedToday(gw)).toBe(0);
    await gw.close();
  }, 15_000);
});
