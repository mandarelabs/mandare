/**
 * Refusals are evidence, so the door records them — but a refused agent that
 * keeps looping must not turn into one fsync'd ledger entry (and one witness
 * submission) per retry: ~3k entries/s were observed (S-6). Per (actor,
 * refusal code) a burst of DENIED_RECORD_BURST refusals is recorded, then
 * DENIED_RECORD_REFILL_PER_SECOND; beyond that the call is refused exactly
 * the same way, just not written again. The burst keeps every refusal of an
 * ordinary race on the ledger (the budget-race red-team counts them).
 *
 * Kill refusals keep their own, stricter throttle (one per second, door-wide).
 */

export const DENIED_RECORD_BURST = 32;
export const DENIED_RECORD_REFILL_PER_SECOND = 8;

/** Buckets are pruned (full ones first) past this many (actor, code) pairs. */
const MAX_TRACKED_PAIRS = 1_024;

interface Bucket {
  tokens: number;
  atMs: number;
}

export class DeniedCoalescer {
  private readonly buckets = new Map<string, Bucket>();

  constructor(private readonly now: () => number = Date.now) {}

  /** True when this refusal should be written to the ledger. */
  admit(actor: string, code: string): boolean {
    const key = `${actor}\u0000${code}`;
    const nowMs = this.now();
    const tokens = this.tokensAt(this.buckets.get(key), nowMs);
    const admitted = tokens >= 1;
    this.buckets.set(key, { tokens: admitted ? tokens - 1 : tokens, atMs: nowMs });
    if (this.buckets.size > MAX_TRACKED_PAIRS) {
      this.prune(nowMs);
    }
    return admitted;
  }

  private tokensAt(bucket: Bucket | undefined, nowMs: number): number {
    if (bucket === undefined) {
      return DENIED_RECORD_BURST;
    }
    const refill = (Math.max(nowMs - bucket.atMs, 0) / 1_000) * DENIED_RECORD_REFILL_PER_SECOND;
    return Math.min(DENIED_RECORD_BURST, bucket.tokens + refill);
  }

  /** Forget pairs whose bucket has refilled — they would start full anyway. */
  private prune(nowMs: number): void {
    for (const [key, bucket] of this.buckets) {
      if (this.tokensAt(bucket, nowMs) >= DENIED_RECORD_BURST) {
        this.buckets.delete(key);
      }
    }
  }
}
