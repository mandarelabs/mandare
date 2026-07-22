/**
 * Step-up approval waivers (S5). Stripe's authorization webhook must answer
 * within 2 seconds — a human cannot. So an over-threshold authorization is
 * DECLINED (fail-closed) while the S4 approval push goes out; when the human
 * taps Approve, the recorded `approval.granted` entry mints a WAIVER here,
 * and the RETRIED purchase (same card, same merchant, no larger amount)
 * consumes it — single-use, short-lived, in-memory.
 *
 * A door restart drops open waivers: the retry is declined again and a new
 * push goes out. Fail-closed, mildly annoying, never unsafe — the same
 * posture as the gateway's in-memory pending-approval map.
 */

export interface ApprovalWaiver {
  cardId: string;
  /** Merchant identity the human saw in the push (network id, or name). */
  merchantKey: string;
  /** The human approved THIS amount; a retry may not exceed it. */
  maxAmountMicros: number;
  /** Ledger hash of the approval.granted entry — the policy waiver token. */
  grantedEntryHash: string;
  expiresAtMs: number;
}

export class WaiverStore {
  private readonly waivers: ApprovalWaiver[] = [];
  private readonly ttlMs: number;
  private readonly clock: () => number;

  constructor(ttlMs: number, clock: () => number = () => Date.now()) {
    this.ttlMs = ttlMs;
    this.clock = clock;
  }

  grant(args: {
    cardId: string;
    merchantKey: string;
    maxAmountMicros: number;
    grantedEntryHash: string;
  }): ApprovalWaiver {
    const waiver: ApprovalWaiver = { ...args, expiresAtMs: this.clock() + this.ttlMs };
    this.waivers.push(waiver);
    return waiver;
  }

  /**
   * Find, consume, and return a matching live waiver — or null. Single-use:
   * a consumed waiver is gone even if the retried authorization later fails
   * some other check (fail-closed beats replayable).
   */
  consume(args: { cardId: string; merchantKey: string; amountMicros: number }): ApprovalWaiver | null {
    const now = this.clock();
    const index = this.waivers.findIndex(
      (waiver) =>
        waiver.expiresAtMs > now &&
        waiver.cardId === args.cardId &&
        waiver.merchantKey === args.merchantKey &&
        args.amountMicros <= waiver.maxAmountMicros
    );
    if (index === -1) {
      this.prune(now);
      return null;
    }
    const [waiver] = this.waivers.splice(index, 1);
    this.prune(now);
    return waiver ?? null;
  }

  pendingCount(): number {
    const now = this.clock();
    return this.waivers.filter((waiver) => waiver.expiresAtMs > now).length;
  }

  private prune(now: number): void {
    for (let i = this.waivers.length - 1; i >= 0; i -= 1) {
      if ((this.waivers[i] as ApprovalWaiver).expiresAtMs <= now) {
        this.waivers.splice(i, 1);
      }
    }
  }
}
