import { describe, expect, it } from 'vitest';

import {
  CARD_AUTH_DENIED,
  CARD_AUTH_INTENT,
  CARD_AUTH_RESULT,
  readLedger,
  verifySpendProjection,
} from '@mandarelabs/ledger';
import type { LedgerEntryV1 } from '@mandarelabs/spec';

import { authorizationEvent, openTestRail, postWebhook } from './helpers.js';

async function waitFor(predicate: () => boolean, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) {
      throw new Error('waitFor timed out');
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

function entriesOf(dbPath: string): LedgerEntryV1[] {
  return readLedger(dbPath).entries as LedgerEntryV1[];
}

describe('card rail — authorization decisions', () => {
  it('approves an in-cap purchase: intent reserves, result settles, counters == replay', async () => {
    const rail = await openTestRail({ cards: ['ic_1'] });
    try {
      const response = await postWebhook(
        rail.app,
        authorizationEvent({ authorizationId: 'iauth_ok', cardId: 'ic_1', amountMinorUnits: 250 })
      );
      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ approved: true });

      const entries = entriesOf(rail.dbPath);
      const intent = entries.find((entry) => entry.action.type === CARD_AUTH_INTENT);
      const result = entries.find((entry) => entry.action.type === CARD_AUTH_RESULT);
      expect(intent?.cost.amount).toBe(2_500_000);
      expect(intent?.action.target).toBe('iauth_ok');
      expect(result?.cost.amount).toBe(2_500_000);
      expect(result?.outcome_ref).toBe(intent?.entry_hash);
      expect(result?.actor).toBe(rail.mandate.agent);

      const verdict = await verifySpendProjection(rail.ledger);
      expect(verdict.ok).toBe(true);
    } finally {
      await rail.close();
    }
  });

  it('declines over the per-tx cap with the refusal on the ledger', async () => {
    const rail = await openTestRail({ cards: ['ic_1'] });
    try {
      const response = await postWebhook(
        rail.app,
        authorizationEvent({ authorizationId: 'iauth_big', cardId: 'ic_1', amountMinorUnits: 2_500 })
      );
      expect(response.json()).toEqual({ approved: false });
      const denied = entriesOf(rail.dbPath).find((entry) => entry.action.type === CARD_AUTH_DENIED);
      expect(denied?.cost.amount).toBe(25_000_000);
      // Refusals never touch the counters.
      const verdict = await verifySpendProjection(rail.ledger);
      expect(verdict.ok).toBe(true);
    } finally {
      await rail.close();
    }
  });

  it('declines an unknown card (never guesses a mandate)', async () => {
    const rail = await openTestRail();
    try {
      const response = await postWebhook(
        rail.app,
        authorizationEvent({ authorizationId: 'iauth_x', cardId: 'ic_unknown', amountMinorUnits: 100 })
      );
      expect(response.json()).toEqual({ approved: false });
      const denied = entriesOf(rail.dbPath).find((entry) => entry.action.type === CARD_AUTH_DENIED);
      expect(denied?.mandate_id).toBe('mnd_unknown');
    } finally {
      await rail.close();
    }
  });

  it('declines a currency the ledger does not run (no invented FX)', async () => {
    const rail = await openTestRail({ cards: ['ic_1'] });
    try {
      const usd = await postWebhook(
        rail.app,
        authorizationEvent({ authorizationId: 'iauth_usd', cardId: 'ic_1', amountMinorUnits: 100, currency: 'USD' })
      );
      expect(usd.json()).toEqual({ approved: false });
      const jpy = await postWebhook(
        rail.app,
        authorizationEvent({ authorizationId: 'iauth_jpy', cardId: 'ic_1', amountMinorUnits: 100, currency: 'JPY' })
      );
      expect(jpy.json()).toEqual({ approved: false });
    } finally {
      await rail.close();
    }
  });

  it('acknowledges and ignores non-authorization events', async () => {
    const rail = await openTestRail();
    try {
      const response = await postWebhook(rail.app, {
        id: 'evt_1',
        type: 'issuing_card.created',
        data: { object: { id: 'ic_1' } },
      });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ received: true });
      expect(entriesOf(rail.dbPath)).toHaveLength(0);
    } finally {
      await rail.close();
    }
  });

  it('approves a PARTIAL amount when the merchant allows it and a cap binds', async () => {
    const rail = await openTestRail({ cards: ['ic_1'] });
    try {
      // Consume €15 of the €20 cap in two approved (sub-threshold) purchases.
      for (const [id, cents] of [
        ['iauth_a', 750],
        ['iauth_b', 750],
      ] as const) {
        const ok = await postWebhook(
          rail.app,
          authorizationEvent({ authorizationId: id, cardId: 'ic_1', amountMinorUnits: cents })
        );
        expect(ok.json()).toEqual({ approved: true });
      }
      // €6 requested, €5 left, amount controllable → partial €5 approval.
      const partial = await postWebhook(
        rail.app,
        authorizationEvent({
          authorizationId: 'iauth_partial',
          cardId: 'ic_1',
          amountMinorUnits: 600,
          isAmountControllable: true,
        })
      );
      expect(partial.json()).toEqual({ approved: true, amount: 500 });

      // The same request WITHOUT amount control is a flat decline.
      const flat = await postWebhook(
        rail.app,
        authorizationEvent({ authorizationId: 'iauth_flat', cardId: 'ic_1', amountMinorUnits: 600 })
      );
      expect(flat.json()).toEqual({ approved: false });

      const verdict = await verifySpendProjection(rail.ledger);
      expect(verdict.ok).toBe(true);
    } finally {
      await rail.close();
    }
  });
});

describe('card rail — step-up approvals (decline now, approve, retry)', () => {
  it('declines over-threshold, pushes, and a granted approval waives ONE retry', async () => {
    const rail = await openTestRail({ cards: ['ic_1'] });
    try {
      // €9 > €8 threshold → decline + push.
      const first = await postWebhook(
        rail.app,
        authorizationEvent({ authorizationId: 'iauth_step1', cardId: 'ic_1', amountMinorUnits: 900 })
      );
      expect(first.json()).toEqual({ approved: false });
      await waitFor(() => rail.notifier.notifications.length === 1);
      expect(rail.notifier.notifications[0]?.title).toContain('9.00 EUR');

      // Human approves → approval.granted entry → waiver minted.
      rail.approvals.created[0]?.resolve('approved');
      await waitFor(() => rail.waivers.pendingCount() === 1);

      // The retry (a NEW authorization id — the retried purchase) passes.
      const retry = await postWebhook(
        rail.app,
        authorizationEvent({ authorizationId: 'iauth_step2', cardId: 'ic_1', amountMinorUnits: 900 })
      );
      expect(retry.json()).toEqual({ approved: true });

      // The waiver was single-use: a THIRD identical purchase declines again.
      const third = await postWebhook(
        rail.app,
        authorizationEvent({ authorizationId: 'iauth_step3', cardId: 'ic_1', amountMinorUnits: 900 })
      );
      expect(third.json()).toEqual({ approved: false });

      const entries = entriesOf(rail.dbPath);
      const types = entries.map((entry) => entry.action.type);
      expect(types).toContain('approval.requested');
      expect(types).toContain('approval.granted');
      const granted = entries.find((entry) => entry.action.type === 'approval.granted');
      expect(granted?.actor).toBe(rail.mandate.principal);
    } finally {
      await rail.close();
    }
  });

  it('a DENIED approval mints no waiver — the retry still declines', async () => {
    const rail = await openTestRail({ cards: ['ic_1'] });
    try {
      const first = await postWebhook(
        rail.app,
        authorizationEvent({ authorizationId: 'iauth_deny1', cardId: 'ic_1', amountMinorUnits: 900 })
      );
      expect(first.json()).toEqual({ approved: false });
      await waitFor(() => rail.notifier.notifications.length === 1);
      rail.approvals.created[0]?.resolve('denied');
      await waitFor(() =>
        entriesOf(rail.dbPath).some((entry) => entry.action.type === 'approval.denied')
      );
      expect(rail.waivers.pendingCount()).toBe(0);
      const retry = await postWebhook(
        rail.app,
        authorizationEvent({ authorizationId: 'iauth_deny2', cardId: 'ic_1', amountMinorUnits: 900 })
      );
      expect(retry.json()).toEqual({ approved: false });
    } finally {
      await rail.close();
    }
  });

  it('a waiver never covers a LARGER amount than the human approved', async () => {
    const rail = await openTestRail({ cards: ['ic_1'] });
    try {
      const first = await postWebhook(
        rail.app,
        authorizationEvent({ authorizationId: 'iauth_up1', cardId: 'ic_1', amountMinorUnits: 850 })
      );
      expect(first.json()).toEqual({ approved: false });
      await waitFor(() => rail.notifier.notifications.length === 1);
      rail.approvals.created[0]?.resolve('approved');
      await waitFor(() => rail.waivers.pendingCount() === 1);
      // Merchant retries HIGHER (€9.99 > approved €8.50) → declined, waiver intact.
      const higher = await postWebhook(
        rail.app,
        authorizationEvent({ authorizationId: 'iauth_up2', cardId: 'ic_1', amountMinorUnits: 999 })
      );
      expect(higher.json()).toEqual({ approved: false });
      expect(rail.waivers.pendingCount()).toBe(1);
    } finally {
      await rail.close();
    }
  });

  it('caps the approval backlog (no push flood)', async () => {
    const rail = await openTestRail({ cards: ['ic_1'], config: { maxPendingApprovals: 1 } });
    try {
      const first = await postWebhook(
        rail.app,
        authorizationEvent({ authorizationId: 'iauth_bl1', cardId: 'ic_1', amountMinorUnits: 900 })
      );
      expect(first.json()).toEqual({ approved: false });
      await waitFor(() => rail.approvals.pendingCount() === 1);
      const second = await postWebhook(
        rail.app,
        authorizationEvent({ authorizationId: 'iauth_bl2', cardId: 'ic_1', amountMinorUnits: 900 })
      );
      expect(second.json()).toEqual({ approved: false });
      // Only ONE push went out; the second decline was APPROVAL_BACKLOG.
      await waitFor(() => rail.notifier.notifications.length === 1);
      expect(rail.approvals.created).toHaveLength(1);
    } finally {
      await rail.close();
    }
  });
});
