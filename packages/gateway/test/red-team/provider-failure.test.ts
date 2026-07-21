import { describe, expect, test } from 'vitest';

import { readLedger, verifySpendProjection } from '@mandarelabs/ledger';
import type { LedgerEntryV1 } from '@mandarelabs/spec';

import { anthropicBody, openTestGateway } from '../helpers.js';
import type { FetchLike } from '../../src/providers/types.js';

/**
 * RED-TEAM (R1/R5): provider failures must fail CLOSED, never open. The
 * dangerous direction is a failure that (a) reopens budget headroom that
 * may actually have been spent, or (b) leaves spending unrecorded. Probes:
 * hang → timeout, malformed success bodies, lying usage, mid-stream death.
 */

describe('provider-failure probes (fail closed, never open)', () => {
  test('provider hang: the timeout fires and the outcome-unknown settle KEEPS the estimate charged', async () => {
    // Hangs until the caller's timeout signal fires (as real fetch would).
    const never: FetchLike = (_url, init) =>
      new Promise((_resolve, reject) => {
        (init.signal as AbortSignal | undefined)?.addEventListener('abort', () =>
          reject(new DOMException('timed out', 'TimeoutError'))
        );
      });
    const gw = await openTestGateway({
      fetchImpl: never,
      timeouts: { nonStreamMs: 200, streamIdleMs: 200 },
    });
    const response = await gw.app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: anthropicBody,
    });
    expect(response.statusCode).toBe(502);
    const { entries } = readLedger(gw.dbPath);
    expect(entries).toHaveLength(2);
    const [intent, result] = entries as [LedgerEntryV1, LedgerEntryV1];
    // Outcome unknown ⇒ the reservation settles AS SPEND (conservative),
    // pending a Storno correction against provider billing. Never 0.
    expect(result.cost.amount).toBe(intent.cost.amount);
    expect(result.cost.amount).toBeGreaterThan(0);
    expect(await verifySpendProjection(gw.ledger)).toMatchObject({ ok: true });
    await gw.close();
  });

  test('200 with a garbage body settles at the estimate, not at 0', async () => {
    const gw = await openTestGateway({
      fetchImpl: () =>
        Promise.resolve(
          new Response('this is not json', {
            status: 200,
            headers: { 'content-type': 'application/json' },
          })
        ),
    });
    const response = await gw.app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: anthropicBody,
    });
    expect(response.statusCode).toBe(200);
    const { entries } = readLedger(gw.dbPath);
    const [intent, result] = entries as [LedgerEntryV1, LedgerEntryV1];
    expect(result.cost.amount).toBe(intent.cost.amount);
    await gw.close();
  });

  test('lying usage (negative/NaN token counts) cannot poison the ledger or halt the door', async () => {
    const gw = await openTestGateway({
      fetchImpl: () =>
        Promise.resolve(
          new Response(
            JSON.stringify({
              usage: {
                input_tokens: -5000,
                output_tokens: Number.NaN,
                cache_read_input_tokens: 'evil',
              },
            }),
            { status: 200, headers: { 'content-type': 'application/json' } }
          )
        ),
    });
    const response = await gw.app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: anthropicBody,
    });
    expect(response.statusCode).toBe(200);
    const health = await gw.app.inject({ method: 'GET', url: '/healthz' });
    expect(health.json().halted).toBe(false);
    const { entries } = readLedger(gw.dbPath);
    const result = entries[1] as LedgerEntryV1;
    // Hostile fields sanitize to 0 — schema-valid entry, consistent projection.
    expect(result.cost.tokens_in).toBe(0);
    expect(result.cost.amount).toBe(0);
    expect(await verifySpendProjection(gw.ledger)).toMatchObject({ ok: true });
    await gw.close();
  });

  test('mid-stream death still settles from observed output — the stream is never free', async () => {
    const encoder = new TextEncoder();
    let sent = false;
    const dying: FetchLike = () =>
      Promise.resolve(
        new Response(
          new ReadableStream<Uint8Array>({
            pull(controller) {
              if (!sent) {
                sent = true;
                controller.enqueue(
                  encoder.encode(
                    'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":500}}}\n\n' +
                      'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"thirty characters of output..."}}\n\n'
                  )
                );
                return;
              }
              controller.error(new Error('provider died'));
            },
          }),
          { status: 200, headers: { 'content-type': 'text/event-stream' } }
        )
      );
    const gw = await openTestGateway({ fetchImpl: dying });
    const address = await gw.app.listen({ host: '127.0.0.1', port: 0 });
    await fetch(`${address}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...anthropicBody, stream: true }),
    }).then((response) => response.text());

    const { entries } = readLedger(gw.dbPath);
    expect(entries).toHaveLength(2);
    const result = entries[1] as LedgerEntryV1;
    expect(result.cost.amount).toBeGreaterThan(0); // estimated, never free
    expect(result.cost.tokens_in).toBe(500);
    expect(await verifySpendProjection(gw.ledger)).toMatchObject({ ok: true });
    await gw.close();
  });

  test('stream idle-timeout aborts a stalling provider and settles what was observed', async () => {
    const encoder = new TextEncoder();
    // Sends one event, then stalls. Honors the abort signal like real fetch:
    // aborting errors the body stream.
    const stalling: FetchLike = (_url, init) =>
      Promise.resolve(
        new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(
                encoder.encode(
                  'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":100}}}\n\n'
                )
              );
              (init.signal as AbortSignal | undefined)?.addEventListener('abort', () => {
                controller.error(new DOMException('aborted', 'AbortError'));
              });
              // …and never sends another byte or closes on its own.
            },
          }),
          { status: 200, headers: { 'content-type': 'text/event-stream' } }
        )
      );
    const gw = await openTestGateway({
      fetchImpl: stalling,
      timeouts: { nonStreamMs: 200, streamIdleMs: 200 },
    });
    const address = await gw.app.listen({ host: '127.0.0.1', port: 0 });
    const text = await fetch(`${address}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...anthropicBody, stream: true }),
    }).then((response) => response.text());
    expect(text).toContain('message_start');

    const { entries } = readLedger(gw.dbPath);
    expect(entries).toHaveLength(2); // intent + settled result, no dangling reservation
    expect(await verifySpendProjection(gw.ledger)).toMatchObject({ ok: true });
    await gw.close();
  }, 15_000);
});
