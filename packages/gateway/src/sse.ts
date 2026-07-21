/**
 * Minimal incremental SSE parser — enough to TEE a provider stream: bytes
 * pass through to the client untouched while `data:` payloads feed the
 * per-provider usage parsers. Deliberately not a full EventSource
 * implementation (no retry/id handling — we never reconnect a proxied
 * stream).
 */

export interface SseEvent {
  event: string | null;
  data: string;
}

export class SseParser {
  private buffer = '';
  private readonly events: SseEvent[] = [];

  /** Feed a raw chunk; returns any COMPLETE events it closed. */
  push(chunk: string): SseEvent[] {
    this.buffer += chunk;
    const out: SseEvent[] = [];
    // Events are separated by a blank line (\n\n; tolerate \r\n).
    for (;;) {
      const boundary = this.buffer.search(/\r?\n\r?\n/);
      if (boundary === -1) {
        break;
      }
      const block = this.buffer.slice(0, boundary);
      this.buffer = this.buffer.slice(boundary).replace(/^\r?\n\r?\n/, '');
      const parsed = parseBlock(block);
      if (parsed !== null) {
        out.push(parsed);
      }
    }
    this.events.push(...out);
    return out;
  }

  all(): readonly SseEvent[] {
    return this.events;
  }
}

function parseBlock(block: string): SseEvent | null {
  let event: string | null = null;
  const dataLines: string[] = [];
  for (const line of block.split(/\r?\n/)) {
    if (line.startsWith('event:')) {
      event = line.slice('event:'.length).trim();
    } else if (line.startsWith('data:')) {
      dataLines.push(line.slice('data:'.length).replace(/^ /, ''));
    }
    // Comments (:) and other fields are ignored on purpose.
  }
  if (event === null && dataLines.length === 0) {
    return null;
  }
  return { event, data: dataLines.join('\n') };
}
