import { describe, expect, it } from 'vitest';

import { WaiverStore } from '../src/waivers.js';

const HASH = 'a'.repeat(64);

describe('WaiverStore (step-up approval waivers)', () => {
  it('consumes a matching waiver exactly once', () => {
    const store = new WaiverStore(10_000, () => 1_000);
    store.grant({ cardId: 'ic_1', merchantKey: 'net_1', maxAmountMicros: 5_000_000, grantedEntryHash: HASH });
    const first = store.consume({ cardId: 'ic_1', merchantKey: 'net_1', amountMicros: 5_000_000 });
    expect(first?.grantedEntryHash).toBe(HASH);
    expect(store.consume({ cardId: 'ic_1', merchantKey: 'net_1', amountMicros: 5_000_000 })).toBeNull();
  });

  it('never matches a larger amount than the human approved', () => {
    const store = new WaiverStore(10_000, () => 1_000);
    store.grant({ cardId: 'ic_1', merchantKey: 'net_1', maxAmountMicros: 5_000_000, grantedEntryHash: HASH });
    expect(store.consume({ cardId: 'ic_1', merchantKey: 'net_1', amountMicros: 5_000_001 })).toBeNull();
    // The failed (larger) attempt must NOT have burned the waiver.
    expect(store.consume({ cardId: 'ic_1', merchantKey: 'net_1', amountMicros: 4_000_000 })).not.toBeNull();
  });

  it('binds to card AND merchant', () => {
    const store = new WaiverStore(10_000, () => 1_000);
    store.grant({ cardId: 'ic_1', merchantKey: 'net_1', maxAmountMicros: 5_000_000, grantedEntryHash: HASH });
    expect(store.consume({ cardId: 'ic_2', merchantKey: 'net_1', amountMicros: 1 })).toBeNull();
    expect(store.consume({ cardId: 'ic_1', merchantKey: 'net_2', amountMicros: 1 })).toBeNull();
  });

  it('expires after the TTL', () => {
    let now = 1_000;
    const store = new WaiverStore(10_000, () => now);
    store.grant({ cardId: 'ic_1', merchantKey: 'net_1', maxAmountMicros: 5_000_000, grantedEntryHash: HASH });
    now = 11_001;
    expect(store.consume({ cardId: 'ic_1', merchantKey: 'net_1', amountMicros: 1_000_000 })).toBeNull();
    expect(store.pendingCount()).toBe(0);
  });
});
