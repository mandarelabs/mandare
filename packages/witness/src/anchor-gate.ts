import { timingSafeEqual } from 'node:crypto';

import type { FastifyRequest } from 'fastify';

/**
 * Who may trigger an on-demand anchor run (W-5, audit 2026-09). Every run
 * cuts a new epoch, and certificates embed the LATEST one — so a drive-by
 * trigger loop keeps every new certificate's anchor pending (OTS needs
 * hours) and, in ots mode, hammers the public calendars from the witness.
 * The witness itself is a public service (doors on other hosts submit
 * heads), so this gate covers only this one operator action:
 *
 * - with an operator token configured: `Authorization: Bearer <token>`,
 *   from any address (a header a browser cannot add cross-origin without a
 *   preflight the witness never grants);
 * - without one: loopback callers only, naming a loopback Host (the DNS-
 *   rebinding guard the gateway uses), carrying `x-mandare-anchor: run`
 *   (CSRF: a custom header forces the same unanswered preflight).
 *
 * Throttling is separate (see `AnchorRunThrottle`) and applies either way.
 */

export const ANCHOR_RUN_HEADER = 'x-mandare-anchor';
const LOOPBACK_ADDRESSES = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]']);

export interface GateRefusal {
  status: 401 | 403;
  error: string;
}

function hostnameOf(hostHeader: string): string {
  const trimmed = hostHeader.trim().toLowerCase();
  if (trimmed.startsWith('[')) {
    const end = trimmed.indexOf(']');
    return end === -1 ? trimmed : trimmed.slice(0, end + 1);
  }
  const colon = trimmed.indexOf(':');
  return colon === -1 ? trimmed : trimmed.slice(0, colon);
}

function tokenMatches(presented: string, expected: string): boolean {
  const a = Buffer.from(presented);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** null = allowed; otherwise the refusal to send. */
export function anchorRunRefusal(request: FastifyRequest, token: string | null): GateRefusal | null {
  if (token !== null) {
    const header = request.headers.authorization ?? '';
    const presented = header.startsWith('Bearer ') ? header.slice('Bearer '.length) : '';
    return tokenMatches(presented, token) ? null : { status: 401, error: 'anchor run needs the operator bearer token' };
  }
  if (!LOOPBACK_ADDRESSES.has(request.ip)) {
    return {
      status: 403,
      error: 'anchor runs are loopback-only — set MANDARE_WITNESS_ANCHOR_TOKEN to trigger them remotely',
    };
  }
  if (!LOOPBACK_HOSTS.has(hostnameOf(request.headers.host ?? ''))) {
    return { status: 403, error: 'host not allowed' };
  }
  if (request.headers[ANCHOR_RUN_HEADER] !== 'run') {
    return { status: 403, error: `missing '${ANCHOR_RUN_HEADER}: run' header (CSRF guard)` };
  }
  return null;
}

/** At most one on-demand run per interval, whoever asks. */
export class AnchorRunThrottle {
  private lastRunAt = Number.NEGATIVE_INFINITY;

  constructor(private readonly minIntervalMs: number) {}

  /** Seconds to wait, or 0 when a run may start now (and is recorded). */
  take(now = Date.now()): number {
    const wait = this.lastRunAt + this.minIntervalMs - now;
    if (wait > 0) return Math.ceil(wait / 1000);
    this.lastRunAt = now;
    return 0;
  }
}
