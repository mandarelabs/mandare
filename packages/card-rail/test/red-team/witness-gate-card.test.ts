import { describe, expect, test } from 'vitest';

import { CARD_AUTH_INTENT, CARD_AUTH_RESULT, readLedger } from '@mandarelabs/ledger';
import type { LedgerEntryV1, MandateV1 } from '@mandarelabs/spec';

import type { CardWitnessGate } from '../../src/types.js';
import { authorizationEvent, openTestRail, postWebhook } from '../helpers.js';

/**
 * RED-TEAM SUITE (rule R5): witness-ack gating on the CARD rail, lock 5.
 * A high-value authorization must be witnessed off-machine BEFORE Stripe
 * hears "approved" — and a dead/lying witness can only ever produce a
 * DECLINE, with the reservation released to zero (the cap never leaks).
 */

function entriesOfType(dbPath: string, type: string): LedgerEntryV1[] {
  const { entries } = readLedger(dbPath);
  return (entries as LedgerEntryV1[]).filter((entry) => entry.action.type === type);
}

function gateThat(behavior: 'ok' | 'dead' | 'hang-free-decline'): CardWitnessGate & { calls: number } {
  const gate = {
    calls: 0,
    isGated: (_amount: number, _mandate: MandateV1) => true,
    requireAck: async () => {
      gate.calls += 1;
      if (behavior === 'ok') return { ok: true as const, witnessedSize: 7 };
      return { ok: false as const, reason: 'witness unreachable (fail-closed)' };
    },
  };
  return gate;
}

describe('card rail witness-ack gating (lock 5)', () => {
  test('WITNESS DEAD: gated authorization DECLINES, reservation settles to zero', async () => {
    const gate = gateThat('dead');
    const rail = await openTestRail({ cards: ['ic_wg1'], deps: { witnessGate: gate } });
    try {
      const response = await postWebhook(
        rail.app,
        authorizationEvent({ authorizationId: 'iauth_wg1', cardId: 'ic_wg1', amountMinorUnits: 400 })
      );
      expect(response.statusCode).toBe(200);
      expect((response.json() as { approved: boolean }).approved).toBe(false);
      expect(gate.calls).toBe(1);

      // R3 intact: intent + zero-settlement pair; the €4 reservation is gone.
      const intents = entriesOfType(rail.dbPath, CARD_AUTH_INTENT);
      const results = entriesOfType(rail.dbPath, CARD_AUTH_RESULT);
      expect(intents).toHaveLength(1);
      expect(results).toHaveLength(1);
      expect(results[0]?.outcome_ref).toBe(intents[0]?.entry_hash);
      expect(results[0]?.cost.amount).toBe(0);
    } finally {
      await rail.close();
    }
  });

  test('WITNESS OK: the gated authorization approves at the network', async () => {
    const gate = gateThat('ok');
    const rail = await openTestRail({ cards: ['ic_wg2'], deps: { witnessGate: gate } });
    try {
      const response = await postWebhook(
        rail.app,
        authorizationEvent({ authorizationId: 'iauth_wg2', cardId: 'ic_wg2', amountMinorUnits: 400 })
      );
      expect((response.json() as { approved: boolean }).approved).toBe(true);
      expect(gate.calls).toBe(1);
      const results = entriesOfType(rail.dbPath, CARD_AUTH_RESULT);
      expect(results[0]?.cost.amount).toBe(4_000_000);
    } finally {
      await rail.close();
    }
  });

  test('UNGATED amounts skip the witness entirely (async window by design)', async () => {
    const gate = gateThat('dead');
    gate.isGated = () => false; // e.g. below the mandate threshold
    const rail = await openTestRail({ cards: ['ic_wg3'], deps: { witnessGate: gate } });
    try {
      const response = await postWebhook(
        rail.app,
        authorizationEvent({ authorizationId: 'iauth_wg3', cardId: 'ic_wg3', amountMinorUnits: 400 })
      );
      expect((response.json() as { approved: boolean }).approved).toBe(true);
      expect(gate.calls).toBe(0);
    } finally {
      await rail.close();
    }
  });

  test('NO GATE WIRED: the S0–S5 posture is unchanged (mounting without a gate works)', async () => {
    const rail = await openTestRail({ cards: ['ic_wg4'] });
    try {
      const response = await postWebhook(
        rail.app,
        authorizationEvent({ authorizationId: 'iauth_wg4', cardId: 'ic_wg4', amountMinorUnits: 400 })
      );
      expect((response.json() as { approved: boolean }).approved).toBe(true);
    } finally {
      await rail.close();
    }
  });

  test('DECLINED-BY-WITNESS authorization cannot be replayed into an approval', async () => {
    // After the zero-settlement the authorization id is DECIDED — a replay
    // (same signed webhook) must decline with zero new ledger writes even
    // if the witness has recovered.
    const gate = gateThat('dead');
    const rail = await openTestRail({ cards: ['ic_wg5'], deps: { witnessGate: gate } });
    try {
      const event = authorizationEvent({
        authorizationId: 'iauth_wg5',
        cardId: 'ic_wg5',
        amountMinorUnits: 400,
      });
      await postWebhook(rail.app, event);
      const before = readLedger(rail.dbPath).entries.length;

      gate.requireAck = async () => ({ ok: true, witnessedSize: 9 }); // witness back up
      const replay = await postWebhook(rail.app, event);
      expect((replay.json() as { approved: boolean }).approved).toBe(false);
      expect(readLedger(rail.dbPath).entries.length).toBe(before); // zero writes
    } finally {
      await rail.close();
    }
  });
});
