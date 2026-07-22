import type { LedgerEntryV1 } from '@mandarelabs/spec';

/**
 * Card → (actor, mandate) binding, derived from `card.create.result` ledger
 * entries. This is a READ MODEL of the ledger, not a second truth: it is
 * rebuilt from the entries at door startup and extended in-process as the
 * door creates cards. A card created outside this door process is simply
 * unknown until restart — and an unknown card's authorizations are DECLINED
 * (fail-closed), never guessed at.
 *
 * Revocation state deliberately does NOT live here: the webhook reads the
 * ledger's revocation projection per request, so `mandare kill` (another
 * process, same DB) bites without any cache invalidation protocol.
 */

export const CARD_CREATE_INTENT = 'card.create.intent';
export const CARD_CREATE_RESULT = 'card.create.result';
export const CARD_CREATE_DENIED = 'card.create.denied';

export interface CardBinding {
  cardId: string;
  actor: string;
  mandateId: string;
  createdEntryHash: string;
}

export class CardRegistry {
  private readonly byCardId = new Map<string, CardBinding>();

  static fromEntries(entries: readonly unknown[]): CardRegistry {
    const registry = new CardRegistry();
    for (const raw of entries) {
      const entry = raw as LedgerEntryV1;
      if (entry?.action?.type === CARD_CREATE_RESULT && typeof entry.action.target === 'string') {
        registry.add({
          cardId: entry.action.target,
          actor: entry.actor,
          mandateId: entry.mandate_id,
          createdEntryHash: entry.entry_hash,
        });
      }
    }
    return registry;
  }

  add(binding: CardBinding): void {
    this.byCardId.set(binding.cardId, binding);
  }

  get(cardId: string): CardBinding | null {
    return this.byCardId.get(cardId) ?? null;
  }

  /** All bindings for one actor / mandate — the kill fan-out reads this. */
  list(filter?: { actor?: string; mandateId?: string }): CardBinding[] {
    const all = [...this.byCardId.values()];
    if (filter === undefined) {
      return all;
    }
    return all.filter(
      (binding) =>
        (filter.actor === undefined || binding.actor === filter.actor) &&
        (filter.mandateId === undefined || binding.mandateId === filter.mandateId)
    );
  }

  size(): number {
    return this.byCardId.size;
  }
}
