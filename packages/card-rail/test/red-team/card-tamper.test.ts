import { describe, expect, it } from 'vitest';

import {
  AGENT_REVOKE,
  CARD_AUTH_INTENT,
  MapCounterKV,
  ProjectionIntegrityError,
  agentSubject,
  applySpendEntry,
  cardSubject,
  doorSubject,
  mandateSubject,
  readLedger,
  revocationProjector,
  verifySpendProjection,
  type AsyncLedger,
} from '@mandarelabs/ledger';
import { canonicalJson, sha256Hex, type LedgerEntryV1, type MandateV1 } from '@mandarelabs/spec';

import { signStripePayload } from '../../src/webhook-signature.js';
import { authorizationEvent, openTestRail, postWebhook, testRailConfig } from '../helpers.js';

/**
 * Card-rail red-team suite (R5): the attacks Q11's design must survive.
 * Forged/unsigned/replayed webhooks, killed subjects, races against one
 * cap, and card creation outside the mandate. Every case must fail LOUDLY
 * and CLOSED — never weaken these to make a change pass.
 */

function entryCount(dbPath: string): number {
  return readLedger(dbPath).entries.length;
}

async function kill(ledger: AsyncLedger, subject: string): Promise<void> {
  const requestHash = sha256Hex(canonicalJson({ op: AGENT_REVOKE, subject, reason: 'red-team' }));
  const result = await ledger.appendProjected(
    {
      actor: 'mandare:operator',
      mandate_id: 'mandare:kill',
      action: { type: AGENT_REVOKE, target: subject, request_hash: requestHash },
      cost: { amount: 0, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
    },
    revocationProjector()
  );
  expect(result.kind).toBe('appended');
}

describe('red-team: webhook forgery and replay', () => {
  it('an UNSIGNED webhook is rejected and touches nothing', async () => {
    const rail = await openTestRail({ cards: ['ic_1'] });
    try {
      const before = entryCount(rail.dbPath);
      const response = await postWebhook(
        rail.app,
        authorizationEvent({ authorizationId: 'iauth_f1', cardId: 'ic_1', amountMinorUnits: 100 }),
        { omitSignature: true }
      );
      expect(response.statusCode).toBe(400);
      expect(entryCount(rail.dbPath)).toBe(before);
    } finally {
      await rail.close();
    }
  });

  it('a FORGED signature (wrong secret) is rejected and touches nothing', async () => {
    const rail = await openTestRail({ cards: ['ic_1'] });
    try {
      const before = entryCount(rail.dbPath);
      const response = await postWebhook(
        rail.app,
        authorizationEvent({ authorizationId: 'iauth_f2', cardId: 'ic_1', amountMinorUnits: 100 }),
        { secret: 'whsec_attacker_guess' }
      );
      expect(response.statusCode).toBe(401);
      expect(entryCount(rail.dbPath)).toBe(before);
    } finally {
      await rail.close();
    }
  });

  it('a TAMPERED body under a valid signature is rejected (amount swap)', async () => {
    const rail = await openTestRail({ cards: ['ic_1'] });
    try {
      const event = authorizationEvent({ authorizationId: 'iauth_f3', cardId: 'ic_1', amountMinorUnits: 100 });
      const tampered = JSON.stringify(event).replace('"amount":100', '"amount":1');
      const response = await postWebhook(rail.app, event, { tamperBody: tampered });
      expect(response.statusCode).toBe(401);
      expect(entryCount(rail.dbPath)).toBe(2); // just the seeded card.create pair
    } finally {
      await rail.close();
    }
  });

  it('a REPLAYED webhook cannot reserve twice — and cannot even make the door write', async () => {
    const rail = await openTestRail({ cards: ['ic_1'] });
    try {
      const event = authorizationEvent({ authorizationId: 'iauth_r1', cardId: 'ic_1', amountMinorUnits: 200 });
      const payload = JSON.stringify(event);
      const header = signStripePayload({ payload, secret: testRailConfig().webhookSecret });
      const first = await rail.app.inject({
        method: 'POST',
        url: '/stripe/webhook',
        payload,
        headers: { 'content-type': 'application/json', 'stripe-signature': header },
      });
      expect(JSON.parse(first.body)).toEqual({ approved: true });
      const afterFirst = entryCount(rail.dbPath);

      // Same bytes, same valid signature, still inside the tolerance window.
      const replay = await rail.app.inject({
        method: 'POST',
        url: '/stripe/webhook',
        payload,
        headers: { 'content-type': 'application/json', 'stripe-signature': header },
      });
      expect(JSON.parse(replay.body)).toEqual({ approved: false });
      expect(entryCount(rail.dbPath)).toBe(afterFirst); // replay writes NOTHING

      const entries = readLedger(rail.dbPath).entries as LedgerEntryV1[];
      const intents = entries.filter((entry) => entry.action.type === CARD_AUTH_INTENT);
      expect(intents).toHaveLength(1); // exactly one reservation, ever

      const verdict = await verifySpendProjection(rail.ledger);
      expect(verdict.ok).toBe(true);
    } finally {
      await rail.close();
    }
  });

  it('a replay of a DECIDED authorization writes nothing even after the budget shifted (review LOW-1)', async () => {
    const rail = await openTestRail({ cards: ['ic_1'] });
    try {
      // Approve €6, then eat the rest of the €20 cap with two more €6 buys.
      const event = authorizationEvent({ authorizationId: 'iauth_shift', cardId: 'ic_1', amountMinorUnits: 600 });
      const payload = JSON.stringify(event);
      const header = signStripePayload({ payload, secret: testRailConfig().webhookSecret });
      const first = await rail.app.inject({
        method: 'POST',
        url: '/stripe/webhook',
        payload,
        headers: { 'content-type': 'application/json', 'stripe-signature': header },
      });
      expect(JSON.parse(first.body)).toEqual({ approved: true });
      for (const id of ['iauth_shift_b', 'iauth_shift_c']) {
        const more = await postWebhook(
          rail.app,
          authorizationEvent({ authorizationId: id, cardId: 'ic_1', amountMinorUnits: 600 })
        );
        expect(more.json()).toEqual({ approved: true });
      }
      const afterSpend = entryCount(rail.dbPath);
      // Now €6 no longer fits — but the REPLAY must be recognized as a
      // replay (no contradictory DENIED entry for an approved auth).
      const replay = await rail.app.inject({
        method: 'POST',
        url: '/stripe/webhook',
        payload,
        headers: { 'content-type': 'application/json', 'stripe-signature': header },
      });
      expect(JSON.parse(replay.body)).toEqual({ approved: false });
      expect(entryCount(rail.dbPath)).toBe(afterSpend);
    } finally {
      await rail.close();
    }
  });

  it('a signed request event WITHOUT pending_request is declined, never full-approved (review MEDIUM-1)', async () => {
    const rail = await openTestRail({ cards: ['ic_1'] });
    try {
      const event = authorizationEvent({ authorizationId: 'iauth_nopending', cardId: 'ic_1', amountMinorUnits: 100 });
      const data = (event.data as { object: Record<string, unknown> }).object;
      delete data.pending_request;
      data.amount = 0; // the real top-level amount at request time
      const before = entryCount(rail.dbPath);
      const response = await postWebhook(rail.app, event);
      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ approved: false });
      expect(entryCount(rail.dbPath)).toBe(before);
    } finally {
      await rail.close();
    }
  });

  it('an EXPIRED-timestamp replay is rejected even with a valid signature', async () => {
    const rail = await openTestRail({ cards: ['ic_1'] });
    try {
      const event = authorizationEvent({ authorizationId: 'iauth_r2', cardId: 'ic_1', amountMinorUnits: 100 });
      const payload = JSON.stringify(event);
      const header = signStripePayload({
        payload,
        secret: testRailConfig().webhookSecret,
        timestampSeconds: Math.floor(Date.now() / 1000) - 3_600,
      });
      const response = await postWebhook(rail.app, event, { header });
      expect(response.statusCode).toBe(400);
      expect(JSON.parse(JSON.stringify(response.json()))).toMatchObject({ code: 'TIMESTAMP_OUT_OF_TOLERANCE' });
    } finally {
      await rail.close();
    }
  });

  it('a chain carrying two intents for one authorization EXPLODES on replay', async () => {
    // The live projector refuses duplicates; if an attacker splices a second
    // intent into the file anyway, the projection replay must not "work".
    const kv = new MapCounterKV();
    const intent = (hash: string): LedgerEntryV1 =>
      ({
        schema_version: 1,
        seq: 1,
        ts: '2026-07-22T10:00:00Z',
        door_id: 'd',
        actor: 'a',
        mandate_id: 'm',
        action: { type: CARD_AUTH_INTENT, target: 'iauth_dup', request_hash: 'b'.repeat(64) },
        cost: { amount: 1, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
        salt: 'c'.repeat(32),
        prev_hash: '0'.repeat(64),
        entry_hash: hash,
        door_signature: { alg: 'EdDSA', key_id: 'k'.repeat(64), key_provenance: 'software', value: 'sig' },
      }) as LedgerEntryV1;
    await applySpendEntry(kv, intent('1'.repeat(64)));
    await expect(applySpendEntry(kv, intent('2'.repeat(64)))).rejects.toThrow(ProjectionIntegrityError);
  });
});

describe('red-team: killed subjects decline at the network', () => {
  const cases: [string, (mandate: MandateV1) => string, string][] = [
    ['agent', (mandate) => agentSubject(mandate.agent), 'AGENT'],
    ['mandate', (mandate) => mandateSubject(mandate.id), 'MANDATE'],
    ['card', () => cardSubject('ic_1'), 'CARD'],
    ['door (kill --all)', () => doorSubject(testRailConfig().doorId), 'DOOR'],
  ];
  for (const [label, subjectOf] of cases) {
    it(`a revoked ${label} is declined, refusal on the ledger`, async () => {
      const rail = await openTestRail({ cards: ['ic_1'] });
      try {
        await kill(rail.ledger, subjectOf(rail.mandate));
        const response = await postWebhook(
          rail.app,
          authorizationEvent({ authorizationId: `iauth_kill_${label}`, cardId: 'ic_1', amountMinorUnits: 100 })
        );
        expect(response.json()).toEqual({ approved: false });
        const entries = readLedger(rail.dbPath).entries as LedgerEntryV1[];
        expect(entries.some((entry) => entry.action.type === 'card.auth.denied')).toBe(true);
        expect(entries.some((entry) => entry.action.type === CARD_AUTH_INTENT)).toBe(false);
      } finally {
        await rail.close();
      }
    });
  }
});

describe('red-team: concurrency and scope', () => {
  it('N authorizations racing ONE cap admit exactly floor(cap/amount)', async () => {
    const rail = await openTestRail({ cards: ['ic_1'] });
    try {
      // €6 per purchase against the €20 cap: exactly 3 can ever be admitted.
      const results = await Promise.all(
        Array.from({ length: 20 }, (_, index) =>
          postWebhook(
            rail.app,
            authorizationEvent({
              authorizationId: `iauth_race_${index}`,
              cardId: 'ic_1',
              amountMinorUnits: 600,
            })
          )
        )
      );
      const approvals = results.filter((result) => (result.json() as { approved: boolean }).approved);
      expect(approvals).toHaveLength(3);

      const entries = readLedger(rail.dbPath).entries as LedgerEntryV1[];
      const intents = entries.filter((entry) => entry.action.type === CARD_AUTH_INTENT);
      expect(intents).toHaveLength(3);
      const settled = entries
        .filter((entry) => entry.action.type === 'card.auth.result')
        .reduce((sum, entry) => sum + entry.cost.amount, 0);
      expect(settled).toBe(18_000_000); // 3 × €6, never past €20

      const verdict = await verifySpendProjection(rail.ledger);
      expect(verdict.ok).toBe(true);
    } finally {
      await rail.close();
    }
  });

  it('a card bound to a DIFFERENT mandate is declined (no cross-mandate spend)', async () => {
    const rail = await openTestRail({
      seed: async (ledger, mandate) => {
        const { seedCard } = await import('../helpers.js');
        await seedCard(ledger, mandate, 'ic_other', { mandateId: 'mnd_someone_else' });
      },
    });
    try {
      const response = await postWebhook(
        rail.app,
        authorizationEvent({ authorizationId: 'iauth_cross', cardId: 'ic_other', amountMinorUnits: 100 })
      );
      expect(response.json()).toEqual({ approved: false });
      const denied = (readLedger(rail.dbPath).entries as LedgerEntryV1[]).find(
        (entry) => entry.action.type === 'card.auth.denied'
      );
      expect(denied?.mandate_id).toBe('mnd_someone_else');
    } finally {
      await rail.close();
    }
  });

  it("a mandate WITHOUT a card spend scope declines everything on the rail", async () => {
    const rail = await openTestRail({
      mandate: {
        schema_version: 1,
        id: 'mnd_gateway_only',
        principal: 'did:example:owner',
        agent: 'did:example:agent',
        purpose: 'gateway-only mandate',
        scopes: [
          {
            type: 'spend',
            currency: 'EUR',
            per_tx_max: 10_000_000,
            per_day_max: 20_000_000,
            per_task_max: 20_000_000,
            total_cap: 20_000_000,
            rails: ['gateway'], // no 'card'
            counterparties: 'any',
            categories: [],
          },
          { type: 'action', classes: ['llm.call', 'card.purchase', 'card.create'] },
        ],
        approvals: { rules: [] },
        valid_from: '2026-01-01T00:00:00Z',
        valid_until: '2036-01-01T00:00:00Z',
        revocation_ref: 'statuslist:0#3',
        signature: {
          alg: 'EdDSA',
          key_id: 'a'.repeat(64),
          key_provenance: 'software',
          value: 'dGVzdC1zaWduYXR1cmU',
        },
      },
      cards: ['ic_1'],
    });
    try {
      const auth = await postWebhook(
        rail.app,
        authorizationEvent({ authorizationId: 'iauth_noscope', cardId: 'ic_1', amountMinorUnits: 100 })
      );
      expect(auth.json()).toEqual({ approved: false });
      // Card creation is refused for the same reason (tested with Stripe
      // never being called — here the client is absent, 503 before mandate
      // checks would mask it, so assert the decline code path via webhook).
      const denied = (readLedger(rail.dbPath).entries as LedgerEntryV1[]).find(
        (entry) => entry.action.type === 'card.auth.denied'
      );
      expect(denied).toBeDefined();
    } finally {
      await rail.close();
    }
  });
});
