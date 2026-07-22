import { describe, expect, test } from 'vitest';

import { CARD_CREATE_RESULT, signStripePayload } from '@mandarelabs/card-rail';
import { readLedger, spendProjector, verifySpendProjection } from '@mandarelabs/ledger';
import { canonicalJson, sha256Hex, type LedgerEntryV1, type MandateV1 } from '@mandarelabs/spec';

import { chatBody, openTestGateway, openrouterOkFetch, testMandate, type TestGateway } from './helpers.js';

/**
 * S5 cross-rail integration: ONE gateway process, ONE mandate, ONE cap —
 * LLM spend through /v1/chat/completions and card spend through the Stripe
 * authorization webhook draw down the SAME budget projection.
 */

const WEBHOOK_SECRET = 'whsec_gateway_mount_test';

function crossRailMandate(): MandateV1 {
  return testMandate({
    id: 'mnd_cross_rail',
    scopes: [
      {
        type: 'spend',
        currency: 'EUR',
        per_tx_max: 16_000_000, // €16
        per_day_max: 20_000_000, // €20 — THE cap
        per_task_max: 20_000_000,
        total_cap: 20_000_000,
        rails: ['gateway', 'card'],
        counterparties: 'any',
        categories: [],
      },
      { type: 'action', classes: ['llm.call', 'card.purchase', 'card.create'] },
    ],
    approvals: { rules: [{ above: 50_000_000, currency: 'EUR', method: 'push' }] },
  });
}

async function seedCard(gw: TestGateway, cardId: string): Promise<void> {
  const requestHash = sha256Hex(canonicalJson({ op: 'card.create', card: cardId }));
  const result = await gw.ledger.appendProjected(
    {
      actor: gw.mandate.agent,
      mandate_id: gw.mandate.id,
      action: {
        type: CARD_CREATE_RESULT,
        target: cardId,
        request_hash: requestHash,
        response_hash: sha256Hex(canonicalJson({ card: cardId })),
      },
      cost: { amount: 0, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
    },
    spendProjector()
  );
  expect(result.kind).toBe('appended');
}

async function postAuthorization(
  gw: TestGateway,
  authorizationId: string,
  amountMinorUnits: number
): Promise<{ statusCode: number; body: { approved: boolean } }> {
  const payload = JSON.stringify({
    id: `evt_${authorizationId}`,
    type: 'issuing_authorization.request',
    api_version: '2026-test',
    data: {
      object: {
        id: authorizationId,
        object: 'issuing.authorization',
        amount: amountMinorUnits,
        currency: 'eur',
        card: { id: 'ic_mount_1' },
        merchant_data: { name: 'ACME SaaS', network_id: 'net_acme' },
        pending_request: { amount: amountMinorUnits, currency: 'eur', is_amount_controllable: false },
      },
    },
  });
  const response = await gw.app.inject({
    method: 'POST',
    url: '/stripe/webhook',
    payload,
    headers: {
      'content-type': 'application/json',
      'stripe-signature': signStripePayload({ payload, secret: WEBHOOK_SECRET }),
    },
  });
  return { statusCode: response.statusCode, body: JSON.parse(response.body) };
}

describe('card rail mounted on the gateway (one door, one cap, both rails)', () => {
  test('LLM spend and card spend draw down the same €20 cap', async () => {
    const gw = await openTestGateway({
      mandate: crossRailMandate(),
      fetchImpl: openrouterOkFetch(15), // the LLM call settles €15
      config: {
        stripe: {
          apiKey: null,
          webhookSecret: WEBHOOK_SECRET,
          apiBase: 'https://stripe.example',
          apiVersion: null,
          cardholderId: null,
          webhookToleranceSeconds: 300,
          waiverTtlMs: 600_000,
        },
      },
    });
    try {
      await seedCard(gw, 'ic_mount_1');

      // Rail 1: the LLM call settles €15 of the €20 cap.
      const llm = await gw.app.inject({ method: 'POST', url: '/v1/chat/completions', payload: chatBody });
      expect(llm.statusCode).toBe(200);

      // Rail 2: a €4 card purchase fits (15 + 4 ≤ 20) → APPROVED.
      const inCap = await postAuthorization(gw, 'iauth_mount_ok', 400);
      expect(inCap.body).toEqual({ approved: true });

      // A further €2 would cross the cap LLM spend already consumed → DECLINED.
      const overCap = await postAuthorization(gw, 'iauth_mount_over', 200);
      expect(overCap.body).toEqual({ approved: false });

      const entries = readLedger(gw.dbPath).entries as LedgerEntryV1[];
      const types = entries.map((entry) => entry.action.type);
      expect(types).toContain('llm.call.result');
      expect(types).toContain('card.auth.result');
      expect(types).toContain('card.auth.denied');

      const verdict = await verifySpendProjection(gw.ledger);
      expect(verdict.ok).toBe(true);
    } finally {
      await gw.close();
    }
  });

  test('the rail does not mount without a webhook secret (frozen S2–S4 behavior)', async () => {
    const gw = await openTestGateway({ fetchImpl: openrouterOkFetch() });
    try {
      const response = await gw.app.inject({ method: 'POST', url: '/stripe/webhook', payload: {} });
      expect(response.statusCode).toBe(404);
      const cards = await gw.app.inject({ method: 'POST', url: '/cards' });
      expect(cards.statusCode).toBe(404);
    } finally {
      await gw.close();
    }
  });
});
