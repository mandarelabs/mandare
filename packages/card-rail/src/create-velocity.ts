import type { LedgerEntryV1 } from '@mandarelabs/spec';

import { CARD_CREATE_INTENT } from './registry.js';

/**
 * Card-creation velocity (S-8). Creating a card is a real-world act — a
 * Stripe object with its own spending surface, and possibly a per-card fee —
 * so an agent may start at most MAX_CARD_CREATES_PER_MINUTE creations per
 * rolling minute. The window is a READ MODEL of the door's own
 * `card.create.intent` entries: rebuilt from the ledger at startup (like the
 * card registry), so restarting the door does not reopen it.
 */
export const MAX_CARD_CREATES_PER_MINUTE = 5;

const WINDOW_MS = 60_000;

export class CreateVelocity {
  private readonly startsByActor = new Map<string, number[]>();

  static fromEntries(entries: readonly unknown[], nowMs: number): CreateVelocity {
    const velocity = new CreateVelocity();
    for (const raw of entries) {
      const entry = raw as LedgerEntryV1;
      const atMs = Date.parse(entry?.ts ?? '');
      if (
        entry?.action?.type === CARD_CREATE_INTENT &&
        typeof entry.actor === 'string' &&
        nowMs - atMs < WINDOW_MS
      ) {
        velocity.startsByActor.set(entry.actor, [...(velocity.startsByActor.get(entry.actor) ?? []), atMs]);
      }
    }
    return velocity;
  }

  /**
   * Take one creation slot for `actor` at `nowMs`; false = the minute is full.
   * The slot is taken at CHECK time, so concurrent requests cannot all pass
   * the same half-empty window.
   */
  tryTake(actor: string, nowMs: number): boolean {
    const recent = (this.startsByActor.get(actor) ?? []).filter((atMs) => nowMs - atMs < WINDOW_MS);
    const admitted = recent.length < MAX_CARD_CREATES_PER_MINUTE;
    this.startsByActor.set(actor, admitted ? [...recent, nowMs] : recent);
    return admitted;
  }
}
