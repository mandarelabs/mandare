import { describe, expect, test } from 'vitest';

import { readLedger, verifySpendProjection, LLM_CALL_DENIED } from '@mandarelabs/ledger';
import { LLM_CALL_RESULT, type LedgerEntryV1 } from '@mandarelabs/spec';

import { anthropicBody, CHAT_RESERVATION_MICROS, chatBody, openTestGateway, testMandate } from '../helpers.js';
import { DENIED_RECORD_BURST, DENIED_RECORD_REFILL_PER_SECOND } from '../../src/denied-coalescer.js';
import type { FetchLike } from '../../src/providers/types.js';

/**
 * RED-TEAM (R5): the budget-race attack. A runaway (or malicious) agent
 * fires N calls CONCURRENTLY, hoping the pre-call checks all read the same
 * "plenty left" counter and collectively blow through the cap.
 *
 * The defense is structural: the reservation runs inside the ledger append
 * transaction under the write lock, so reservations serialize and the cap
 * arithmetic can never interleave. This test must stay green under ANY
 * scheduling — if it ever flakes, that is a real regression in the
 * reservation design, not a flaky test.
 */

const CAP_MICROS = 20_000_000; // €20 day cap (testMandate)
const PER_TX_MICROS = 5_000_000; // €5 per-tx cap (testMandate)
// What one chatBody call reserves: just under the per-tx cap, derived from the
// real reservation code (S10-fix 2D — no longer the cap an unpriced model got).
const RESERVATION_MICROS = CHAT_RESERVATION_MICROS;

function slowUpstream(costUsd: number, delayMs: number): FetchLike {
  return async () => {
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    return new Response(
      JSON.stringify({
        id: 'gen',
        choices: [{ message: { role: 'assistant', content: 'ok' } }],
        usage: { prompt_tokens: 10, completion_tokens: 10, cost: costUsd },
      }),
      { status: 200, headers: { 'content-type': 'application/json' } }
    );
  };
}

describe('budget-race attack (N concurrent calls vs the cap)', () => {
  test('25 fully-concurrent calls: reservations serialize, the cap is NEVER pierced', async () => {
    // 100ms upstream delay ⇒ every request holds its reservation while the
    // others arrive: the worst-case interleaving for a naive check-then-act.
    const gw = await openTestGateway({
      mandate: testMandate(),
      fetchImpl: slowUpstream(2, 100),
    });

    const responses = await Promise.all(
      Array.from({ length: 25 }, () =>
        gw.app.inject({ method: 'POST', url: '/v1/chat/completions', payload: chatBody })
      )
    );
    const completed = responses.filter((response) => response.statusCode === 200).length;
    const denied = responses.filter((response) => response.statusCode === 403).length;
    expect(completed + denied).toBe(25);

    // With full overlap only floor(20/4.999995) = 4 reservations fit; late
    // settles can free room for a few more, but the HARD invariants are:
    expect(Math.floor(CAP_MICROS / RESERVATION_MICROS)).toBe(4);
    expect(completed).toBeGreaterThanOrEqual(Math.floor(CAP_MICROS / RESERVATION_MICROS));
    expect(completed).toBeLessThanOrEqual(CAP_MICROS / 2_000_000); // settled ≤ cap
    expect(denied).toBeGreaterThan(0);

    // Ledger truth: settled spend ≤ cap, and at reserve time the guard saw
    // reserved+settled+estimate ≤ cap for every accepted intent.
    const { entries } = readLedger(gw.dbPath);
    const settledTotal = (entries as LedgerEntryV1[])
      .filter((entry) => entry.action.type === LLM_CALL_RESULT)
      .reduce((sum, entry) => sum + entry.cost.amount, 0);
    expect(settledTotal).toBeLessThanOrEqual(CAP_MICROS);

    // Every refusal left an auditable denied entry.
    const deniedEntries = (entries as LedgerEntryV1[]).filter(
      (entry) => entry.action.type === LLM_CALL_DENIED
    );
    expect(deniedEntries.length).toBe(denied);

    // And the projection still equals a fresh replay of the ledger.
    expect(await verifySpendProjection(gw.ledger)).toMatchObject({ ok: true });
    await gw.close();
  });

  test('sequential fill then concurrent burst: the last euro is not double-spendable', async () => {
    const gw = await openTestGateway({
      mandate: testMandate(),
      fetchImpl: slowUpstream(4.9, 50),
    });
    // Three sequential calls settle €14.70, leaving €5.30 — room for exactly
    // ONE more reservation.
    expect(Math.floor((CAP_MICROS - 3 * 4_900_000) / RESERVATION_MICROS)).toBe(1);
    for (let i = 0; i < 3; i += 1) {
      const response = await gw.app.inject({
        method: 'POST',
        url: '/v1/chat/completions',
        payload: chatBody,
      });
      expect(response.statusCode).toBe(200);
    }
    // Ten concurrent contenders for that last slot.
    const burst = await Promise.all(
      Array.from({ length: 10 }, () =>
        gw.app.inject({ method: 'POST', url: '/v1/chat/completions', payload: chatBody })
      )
    );
    const winners = burst.filter((response) => response.statusCode === 200);
    expect(winners).toHaveLength(1);
    expect(burst.filter((r) => r.statusCode === 403)).toHaveLength(9);

    const { entries } = readLedger(gw.dbPath);
    const settledTotal = (entries as LedgerEntryV1[])
      .filter((entry) => entry.action.type === LLM_CALL_RESULT)
      .reduce((sum, entry) => sum + entry.cost.amount, 0);
    expect(settledTotal).toBeLessThanOrEqual(CAP_MICROS);
    expect(settledTotal).toBe(4 * 4_900_000);
    expect(await verifySpendProjection(gw.ledger)).toMatchObject({ ok: true });
    await gw.close();
  }, 15_000);

  test('the reservation is the enforcement point: per-tx cap bounds every single reservation', async () => {
    const gw = await openTestGateway({ mandate: testMandate(), fetchImpl: slowUpstream(1, 10) });
    const { entries: before } = readLedger(gw.dbPath);
    expect(before).toHaveLength(0);
    const response = await gw.app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: chatBody,
    });
    expect(response.statusCode).toBe(200);
    const { entries } = readLedger(gw.dbPath);
    const intent = entries[0] as LedgerEntryV1;
    expect(intent.cost.amount).toBe(RESERVATION_MICROS);
    expect(intent.cost.amount).toBeLessThanOrEqual(PER_TX_MICROS);
    await gw.close();
  });
});

describe('refusal floods (S-6)', () => {
  test('a refused loop is coalesced per (actor, code): bounded DENIED writes, every call still refused', async () => {
    const tight = testMandate();
    (tight.scopes[0] as { per_tx_max: number }).per_tx_max = 100; // every call breaches it
    let upstreamCalls = 0;
    const gw = await openTestGateway({
      mandate: tight,
      fetchImpl: () => {
        upstreamCalls += 1;
        return Promise.reject(new Error('never reached'));
      },
    });
    const calls = 300;
    const started = Date.now();
    for (let i = 0; i < calls; i += 1) {
      const response = await gw.app.inject({ method: 'POST', url: '/v1/messages', payload: anthropicBody });
      expect(response.statusCode).toBe(403);
      expect(response.json().code).toBe('PER_TX_EXCEEDED');
    }
    const elapsedSeconds = (Date.now() - started) / 1000;
    const denied = ((await gw.ledger.readAll()).entries as LedgerEntryV1[]).filter(
      (entry) => entry.action.type === LLM_CALL_DENIED
    );
    // The first refusals are always on the ledger; the flood is not.
    expect(denied.length).toBeGreaterThan(0);
    expect(denied.length).toBeLessThan(calls);
    expect(denied.length).toBeLessThanOrEqual(
      DENIED_RECORD_BURST + Math.ceil(elapsedSeconds * DENIED_RECORD_REFILL_PER_SECOND) + 1
    );
    expect(upstreamCalls).toBe(0);

    // Another refusal code is its own bucket: recorded at once.
    const other = await gw.app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: { ...anthropicBody, model: 'claude-mystery-9' },
    });
    expect(other.json().code).toBe('MODEL_UNPRICED');
    expect(other.json().denied_entry).toMatch(/^[0-9a-f]{64}$/);
    expect(await verifySpendProjection(gw.ledger)).toMatchObject({ ok: true });
    await gw.close();
  }, 30_000);
});
