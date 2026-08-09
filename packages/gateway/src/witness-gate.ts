import type { MandateV1 } from '@mandarelabs/spec';
import type { SyncResult } from '@mandarelabs/witness-protocol';

/**
 * Witness-ack gating (S6, SPEC §6 lock 5): for actions above the mandate's
 * approval threshold — the mandate's own definition of "high-value" — the
 * door waits for a VERIFIED witness acknowledgment of the intent entry
 * before releasing the action. Where it matters, the tamper window is
 * exactly zero: by the time the action runs, an off-machine record already
 * pins the chain head that contains its intent. Low-stakes actions tolerate
 * the async streaming window (a documented, honest residual).
 *
 * Fail-closed (R1): no verified ack within the timeout ⇒ the action is
 * refused. A dead witness can never open the door — it can only keep
 * high-value actions shut, exactly as a dead vault does.
 */

/** What the gate needs from the witness client (structural — tests fake it). */
export interface WitnessAckClient {
  /** Force-sync the current ledger head and return the VERIFIED ack. */
  ackHead(): Promise<SyncResult>;
}

export type WitnessGateVerdict =
  | { ok: true; witnessedSize: number }
  | { ok: false; reason: string };

export interface WitnessGateOptions {
  client: WitnessAckClient;
  ackMode: 'off' | 'threshold' | 'all';
  ackTimeoutMs: number;
  ledgerCurrency: string;
}

export class WitnessGate {
  constructor(private readonly options: WitnessGateOptions) {}

  /**
   * Is this amount witness-gated under the given mandate? 'threshold' reuses
   * the mandate's approval rules (SPEC §5) — the same amounts that require a
   * human also require a witnessed head; no second threshold vocabulary.
   */
  isGated(amountMicros: number, mandate: MandateV1): boolean {
    switch (this.options.ackMode) {
      case 'off':
        return false;
      case 'all':
        return true;
      case 'threshold':
        return mandate.approvals.rules.some(
          (rule) => rule.currency === this.options.ledgerCurrency && amountMicros > rule.above
        );
    }
  }

  /** Obtain a verified ack for the CURRENT head (which includes the intent). */
  async requireAck(): Promise<WitnessGateVerdict> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(
        () => reject(new Error(`no witness ack within ${this.options.ackTimeoutMs}ms`)),
        this.options.ackTimeoutMs
      );
      timer.unref?.();
    });
    try {
      const result = await Promise.race([this.options.client.ackHead(), timeout]);
      return { ok: true, witnessedSize: result.head.size };
    } catch (error) {
      return {
        ok: false,
        reason: error instanceof Error ? error.message : 'witness ack failed',
      };
    } finally {
      clearTimeout(timer);
    }
  }
}
