import type { ServerResponse } from 'node:http';

/**
 * Small I/O primitives for proxying a provider stream to a client without
 * ever waiting on an event that cannot come (S-3). Each wait resolves on the
 * thing it waits for OR on the call's abort signal, which fires on the idle
 * deadline and on a client hang-up.
 */

/** An abort reason that reads like the timeout it is (error names reach the ledger's response hash). */
export function timeoutReason(what: string): DOMException {
  return new DOMException(`${what} within the deadline`, 'TimeoutError');
}

type ReadResult = Awaited<ReturnType<ReadableStreamDefaultReader<Uint8Array>['read']>>;

/**
 * The next provider chunk — or 'aborted' as soon as the signal fires, even
 * when the provider neither sends another byte nor honors the abort itself.
 */
export function nextChunk(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  signal: AbortSignal
): Promise<ReadResult | 'aborted'> {
  if (signal.aborted) {
    return Promise.resolve('aborted');
  }
  return new Promise((resolve, reject) => {
    const onAbort = (): void => resolve('aborted');
    signal.addEventListener('abort', onAbort, { once: true });
    reader.read().then(
      (result) => {
        signal.removeEventListener('abort', onAbort);
        resolve(result);
      },
      (error: unknown) => {
        signal.removeEventListener('abort', onAbort);
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    );
  });
}

/**
 * Wait for the client to drain its socket buffer — or to hang up, or for the
 * signal to fire. A destroyed socket never emits 'drain', so waiting on
 * 'drain' alone hung the handler (and pinned the reservation) forever.
 */
export function drainedOrDone(raw: ServerResponse, signal: AbortSignal): Promise<void> {
  if (raw.destroyed || signal.aborted) {
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    const done = (): void => {
      raw.off('drain', done);
      raw.off('close', done);
      signal.removeEventListener('abort', done);
      resolve();
    };
    raw.on('drain', done);
    raw.on('close', done);
    signal.addEventListener('abort', done);
  });
}
