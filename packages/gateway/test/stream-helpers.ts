import { request as httpRequest } from 'node:http';

import { readSpendSnapshot } from '@mandarelabs/ledger';
import type { LedgerEntryV1 } from '@mandarelabs/spec';

import type { FetchLike } from '../src/providers/types.js';
import type { TestGateway } from './helpers.js';

/**
 * Streaming fixtures for the settlement red-team (S-1/S-3/S-5). Streams need a
 * real socket (the reply is hijacked), and the adversarial shapes — a client
 * that stops reading, a client that hangs up, a provider that stalls — need
 * control over both ends of the pipe.
 */

export const anthropicEvent = (type: string, payload: Record<string, unknown>): string =>
  `event: ${type}\ndata: ${JSON.stringify({ type, ...payload })}\n\n`;

export const chatChunk = (payload: Record<string, unknown>): string =>
  `data: ${JSON.stringify(payload)}\n\n`;

/**
 * A provider stream that behaves like real fetch: it honors the abort signal
 * (aborting errors the body), paces `blocks` `intervalMs` apart, and — with
 * `stallAfter` — keeps the connection open without another byte once they
 * are sent. `aborted()` reports whether the door cancelled it.
 */
export function pacedSseFetch(
  blocks: readonly string[],
  options: { intervalMs: number; stallAfter?: boolean }
): FetchLike & { aborted(): boolean } {
  let abortSeen = false;
  const fetchImpl: FetchLike = (_url, init) => {
    const encoder = new TextEncoder();
    const signal = init.signal ?? undefined;
    let timer: NodeJS.Timeout | undefined;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        let index = 0;
        const onAbort = (): void => {
          abortSeen = true;
          clearTimeout(timer);
          try {
            controller.error(new DOMException('aborted by the door', 'AbortError'));
          } catch {
            // already closed
          }
        };
        signal?.addEventListener('abort', onAbort, { once: true });
        const next = (): void => {
          if (index < blocks.length) {
            controller.enqueue(encoder.encode(blocks[index] as string));
            index += 1;
            timer = setTimeout(next, options.intervalMs);
            return;
          }
          if (options.stallAfter !== true) {
            signal?.removeEventListener('abort', onAbort);
            controller.close();
          }
        };
        next();
      },
      cancel() {
        abortSeen = true;
        clearTimeout(timer);
      },
    });
    return Promise.resolve(
      new Response(body, { status: 200, headers: { 'content-type': 'text/event-stream' } })
    );
  };
  return Object.assign(fetchImpl, { aborted: () => abortSeen });
}

export type ClientBehavior =
  /** Read the whole stream. */
  | 'read-all'
  /** Read the first chunk, then hang up (socket destroyed). */
  | 'disconnect-after-first-chunk'
  /**
   * Read the first chunk, stop reading (socket kept open) for `stallForMs`,
   * then either resume reading or hang up. A paused socket cannot observe the
   * server closing it, so a stall ends in a resume to see what the server did.
   */
  | { stallForMs: number; then: 'resume' | 'disconnect' };

export interface StreamClientResult {
  status: number;
  text: string;
  /** The SERVER closed the connection (observed from the client side). */
  closedByServer: boolean;
}

/**
 * Drive one streaming request with the given client behavior. Resolves when
 * the exchange is over from the client's point of view (or `giveUpMs`).
 */
export function streamRequest(
  address: string,
  path: string,
  body: Record<string, unknown>,
  behavior: ClientBehavior,
  giveUpMs = 5_000
): Promise<StreamClientResult> {
  const url = new URL(path, address);
  return new Promise((resolve) => {
    let status = 0;
    let text = '';
    let settled = false;
    let hungUp = false;
    const finish = (closedByServer: boolean): void => {
      if (!settled) {
        settled = true;
        clearTimeout(giveUp);
        resolve({ status, text, closedByServer });
      }
    };
    const giveUp = setTimeout(() => {
      hungUp = true;
      request.destroy();
      finish(false);
    }, giveUpMs);
    const request = httpRequest(
      {
        host: url.hostname,
        port: url.port,
        path: url.pathname,
        method: 'POST',
        headers: { 'content-type': 'application/json' },
      },
      (response) => {
        status = response.statusCode ?? 0;
        response.setEncoding('utf8');
        response.on('close', () => finish(!hungUp));
        response.once('data', (chunk: string) => {
          text += chunk;
          if (behavior === 'read-all') {
            response.on('data', (more: string) => (text += more));
            return;
          }
          response.pause();
          if (behavior === 'disconnect-after-first-chunk') {
            hungUp = true;
            request.destroy();
            finish(false);
            return;
          }
          setTimeout(() => {
            if (behavior.then === 'resume') {
              response.on('data', (more: string) => (text += more));
              response.resume();
              return;
            }
            hungUp = true;
            request.destroy();
            finish(false);
          }, behavior.stallForMs);
        });
      }
    );
    request.on('error', () => finish(!hungUp));
    request.end(JSON.stringify({ ...body, stream: true }));
  });
}

/** Poll until `probe` returns a value (not undefined) or the deadline passes. */
export async function waitFor<T>(
  probe: () => Promise<T | undefined>,
  timeoutMs: number,
  what: string
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await probe();
    if (value !== undefined) {
      return value;
    }
    if (Date.now() > deadline) {
      throw new Error(`timed out after ${timeoutMs}ms waiting for ${what}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

/** The intent + its settling result, once the result has been written. */
export async function settledPair(
  gw: TestGateway,
  timeoutMs = 3_000
): Promise<{ intent: LedgerEntryV1; result: LedgerEntryV1 }> {
  return waitFor(
    async () => {
      const { entries } = await gw.ledger.readAll();
      const typed = entries as LedgerEntryV1[];
      const intent = typed.find((entry) => entry.action.type === 'llm.call.intent');
      const result = typed.find((entry) => entry.action.type === 'llm.call.result');
      return intent !== undefined && result !== undefined ? { intent, result } : undefined;
    },
    timeoutMs,
    'the intent to be settled by a result entry'
  );
}

/** Today's open reservations for the test mandate (0 ⇒ every intent settled). */
export async function reservedToday(gw: TestGateway): Promise<number> {
  const snapshot = await readSpendSnapshot(gw.ledger, {
    mandateId: gw.mandate.id,
    actor: gw.config.actor,
    nowIso: new Date().toISOString(),
  });
  return snapshot.day.reservedMicros;
}
