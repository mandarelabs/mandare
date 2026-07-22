import { createServer, type Server } from 'node:http';

import { afterEach, describe, expect, it } from 'vitest';

import { SUBJECT_REGISTER, cardSubject, readLedger } from '@mandarelabs/ledger';
import type { LedgerEntryV1 } from '@mandarelabs/spec';

import { CARD_CREATE_FAILED } from '../src/routes.js';
import { CARD_CREATE_INTENT, CARD_CREATE_RESULT } from '../src/registry.js';
import { StripeClient } from '../src/stripe-client.js';
import { authorizationEvent, openTestRail, postWebhook, testMandate, type TestRail } from './helpers.js';

/** Tiny mock Stripe: records requests, answers card create/cancel. */
async function startMockStripe(options: { failCreate?: boolean } = {}): Promise<{
  server: Server;
  baseUrl: string;
  requests: { method: string; url: string; body: string }[];
}> {
  const requests: { method: string; url: string; body: string }[] = [];
  let cardCounter = 0;
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      requests.push({ method: req.method ?? '', url: req.url ?? '', body });
      res.setHeader('content-type', 'application/json');
      if (req.url === '/v1/issuing/cards' && req.method === 'POST') {
        if (options.failCreate === true) {
          res.statusCode = 402;
          res.end(JSON.stringify({ error: { type: 'card_error', message: 'issuing not enabled' } }));
          return;
        }
        cardCounter += 1;
        res.statusCode = 200;
        res.end(
          JSON.stringify({
            id: `ic_mock_${cardCounter}`,
            object: 'issuing.card',
            last4: '4242',
            status: 'active',
            currency: 'eur',
          })
        );
        return;
      }
      if (/^\/v1\/issuing\/cards\/[^/]+$/.test(req.url ?? '') && req.method === 'POST') {
        res.statusCode = 200;
        res.end(JSON.stringify({ id: (req.url ?? '').split('/').pop(), object: 'issuing.card', last4: '4242', status: 'canceled', currency: 'eur' }));
        return;
      }
      res.statusCode = 404;
      res.end(JSON.stringify({ error: { message: 'not found' } }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address() as { port: number };
  return { server, baseUrl: `http://127.0.0.1:${address.port}`, requests };
}

describe('card rail — card creation (a mandate-checked, ledger-logged door op)', () => {
  let rail: TestRail | null = null;
  let mock: Awaited<ReturnType<typeof startMockStripe>> | null = null;

  afterEach(async () => {
    await rail?.close();
    rail = null;
    mock?.server.close();
    mock = null;
  });

  it('creates a card: intent → Stripe → result + revocation slot, then the card authorizes', async () => {
    mock = await startMockStripe();
    rail = await openTestRail({
      deps: { stripe: new StripeClient({ secretKey: 'sk_test_not_a_secret', baseUrl: mock.baseUrl }) },
    });
    const response = await rail.app.inject({ method: 'POST', url: '/cards' });
    expect(response.statusCode).toBe(201);
    const created = JSON.parse(response.body) as { card_id: string; last4: string };
    expect(created.card_id).toBe('ic_mock_1');
    expect(created.last4).toBe('4242');
    // R2: no PAN anywhere in the response.
    expect(response.body).not.toMatch(/\d{13,19}/);

    const entries = readLedger(rail.dbPath).entries as LedgerEntryV1[];
    const types = entries.map((entry) => entry.action.type);
    expect(types).toEqual([CARD_CREATE_INTENT, CARD_CREATE_RESULT, SUBJECT_REGISTER]);
    expect(entries[2]?.action.target).toBe(cardSubject('ic_mock_1'));

    // The Stripe-side belt: per-authorization limit == the €10 per-tx cap.
    const createRequest = mock.requests.find((request) => request.url === '/v1/issuing/cards');
    expect(createRequest?.body).toContain('spending_limits');
    expect(createRequest?.body).toContain('1000'); // €10.00 in cents

    // The freshly created card is immediately authorized-decidable.
    const auth = await postWebhook(
      rail.app,
      authorizationEvent({ authorizationId: 'iauth_new', cardId: 'ic_mock_1', amountMinorUnits: 100 })
    );
    expect(auth.json()).toEqual({ approved: true });
  });

  it("refuses creation when no action scope grants 'card.create'", async () => {
    mock = await startMockStripe();
    const mandate = testMandate({
      scopes: [
        {
          type: 'spend',
          currency: 'EUR',
          per_tx_max: 10_000_000,
          per_day_max: 20_000_000,
          per_task_max: 20_000_000,
          total_cap: 20_000_000,
          rails: ['gateway', 'card'],
          counterparties: 'any',
          categories: [],
        },
        { type: 'action', classes: ['llm.call', 'card.purchase'] }, // no card.create
      ],
    });
    rail = await openTestRail({
      mandate,
      deps: { stripe: new StripeClient({ secretKey: 'sk_test_not_a_secret', baseUrl: mock.baseUrl }) },
    });
    const response = await rail.app.inject({ method: 'POST', url: '/cards' });
    expect(response.statusCode).toBe(403);
    expect(JSON.parse(response.body).code).toBe('SCOPE_MISMATCH');
    expect(mock.requests).toHaveLength(0); // Stripe never called
  });

  it('refuses creation for an actor who is not the mandated agent', async () => {
    mock = await startMockStripe();
    rail = await openTestRail({
      actor: 'did:example:someone-else',
      deps: { stripe: new StripeClient({ secretKey: 'sk_test_not_a_secret', baseUrl: mock.baseUrl }) },
    });
    const response = await rail.app.inject({ method: 'POST', url: '/cards' });
    expect(response.statusCode).toBe(403);
    expect(JSON.parse(response.body).code).toBe('IDENTITY_MISMATCH');
    expect(mock.requests).toHaveLength(0);
  });

  it('settles a failed Stripe creation honestly (intent + failed outcome, nothing issued)', async () => {
    mock = await startMockStripe({ failCreate: true });
    rail = await openTestRail({
      deps: { stripe: new StripeClient({ secretKey: 'sk_test_not_a_secret', baseUrl: mock.baseUrl }) },
    });
    const response = await rail.app.inject({ method: 'POST', url: '/cards' });
    expect(response.statusCode).toBe(502);
    const entries = readLedger(rail.dbPath).entries as LedgerEntryV1[];
    expect(entries.map((entry) => entry.action.type)).toEqual([CARD_CREATE_INTENT, CARD_CREATE_FAILED]);
  });

  it('keeps creation closed without Stripe credentials (webhook decisions unaffected)', async () => {
    rail = await openTestRail({ cards: ['ic_1'] });
    const response = await rail.app.inject({ method: 'POST', url: '/cards' });
    expect(response.statusCode).toBe(503);
    const auth = await postWebhook(
      rail.app,
      authorizationEvent({ authorizationId: 'iauth_nostripe', cardId: 'ic_1', amountMinorUnits: 100 })
    );
    expect(auth.json()).toEqual({ approved: true });
  });
});
