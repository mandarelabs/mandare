import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import Fastify, { type FastifyInstance } from 'fastify';

import { AsyncLedger, SqliteStore } from '@mandarelabs/ledger';
import { MandatePolicyEngine } from '@mandarelabs/policy-engine';
import type { MandateV1 } from '@mandarelabs/spec';

import { registerCardRail } from '../src/routes.js';
import { signStripePayload } from '../src/webhook-signature.js';
import { WaiverStore } from '../src/waivers.js';
import type { CardApprovalChannel, CardRailConfig, CardRailDeps, CardNotifier } from '../src/types.js';

export const TEST_WEBHOOK_SECRET = 'whsec_test_not_a_secret';

export function tempDbPath(): string {
  return join(mkdtempSync(join(tmpdir(), 'mandare-card-test-')), 'ledger.db');
}

export const FAKE_SIGNATURE = {
  alg: 'EdDSA',
  key_id: 'a'.repeat(64),
  key_provenance: 'software',
  value: 'dGVzdC1zaWduYXR1cmU',
} as const;

/** One €20 mandate covering BOTH rails — the S5 cross-rail shape. */
export function testMandate(overrides: Partial<MandateV1> = {}): MandateV1 {
  return {
    schema_version: 1,
    id: 'mnd_card_test',
    principal: 'did:example:owner',
    agent: 'did:example:agent',
    purpose: 'card rail tests',
    scopes: [
      {
        type: 'spend',
        currency: 'EUR',
        per_tx_max: 10_000_000, // €10
        per_day_max: 20_000_000, // €20
        per_task_max: 20_000_000,
        total_cap: 20_000_000,
        rails: ['gateway', 'card'],
        counterparties: 'any',
        categories: [],
      },
      { type: 'action', classes: ['llm.call', 'card.purchase', 'card.create'] },
    ],
    approvals: { rules: [{ above: 8_000_000, currency: 'EUR', method: 'push' }] },
    valid_from: '2026-01-01T00:00:00Z',
    valid_until: '2036-01-01T00:00:00Z',
    revocation_ref: 'statuslist:0#2',
    signature: FAKE_SIGNATURE,
    ...overrides,
  };
}

/**
 * Deterministic in-memory stand-in for the gateway's ApprovalService: the
 * test decides each approval by resolving the exposed resolver.
 */
export class MockApprovals implements CardApprovalChannel {
  readonly created: {
    id: string;
    input: Parameters<CardApprovalChannel['create']>[0];
    resolve: (outcome: 'approved' | 'denied' | 'timeout') => void;
  }[] = [];
  private counter = 0;
  private pending = 0;

  create(input: Parameters<CardApprovalChannel['create']>[0]) {
    this.counter += 1;
    this.pending += 1;
    let resolve!: (outcome: 'approved' | 'denied' | 'timeout') => void;
    const outcome = new Promise<'approved' | 'denied' | 'timeout'>((res) => {
      resolve = (value) => {
        this.pending -= 1;
        res(value);
      };
    });
    const record = { id: `apr_test_${this.counter}`, input, resolve };
    this.created.push(record);
    return {
      id: record.id,
      approveToken: `approve-${this.counter}`,
      denyToken: `deny-${this.counter}`,
      expiresAtIso: new Date(Date.now() + 60_000).toISOString(),
      outcome,
    };
  }

  pendingCount(): number {
    return this.pending;
  }
}

export class MockCardNotifier implements CardNotifier {
  readonly notifications: Parameters<CardNotifier['send']>[0][] = [];
  failNext = false;

  send(notification: Parameters<CardNotifier['send']>[0]): Promise<void> {
    if (this.failNext) {
      this.failNext = false;
      return Promise.reject(new Error('push channel down'));
    }
    this.notifications.push(notification);
    return Promise.resolve();
  }
}

export function testRailConfig(overrides: Partial<CardRailConfig> = {}): CardRailConfig {
  return {
    doorId: 'gateway:card-test',
    ledgerCurrency: 'EUR',
    maxIntentsPerMinute: 10_000,
    maxPendingApprovals: 8,
    approvalBaseUrl: 'http://127.0.0.1:0',
    webhookSecret: TEST_WEBHOOK_SECRET,
    webhookToleranceSeconds: 300,
    waiverTtlMs: 600_000,
    cardholderId: 'ich_test',
    ...overrides,
  };
}

export interface TestRail {
  app: FastifyInstance;
  ledger: AsyncLedger;
  mandate: MandateV1;
  approvals: MockApprovals;
  notifier: MockCardNotifier;
  waivers: WaiverStore;
  dbPath: string;
  close(): Promise<void>;
}

export async function openTestRail(options: {
  config?: Partial<CardRailConfig>;
  mandate?: MandateV1;
  deps?: Partial<CardRailDeps>;
  actor?: string;
  /** Card ids to bind (real card.create entries) BEFORE the rail mounts. */
  cards?: string[];
  /** Arbitrary ledger seeding BEFORE the rail mounts (after `cards`). */
  seed?: (ledger: AsyncLedger, mandate: MandateV1) => Promise<void>;
} = {}): Promise<TestRail> {
  const dbPath = tempDbPath();
  const store = SqliteStore.open(dbPath);
  const mandate = options.mandate ?? testMandate();
  const config = testRailConfig(options.config);
  const ledger = await AsyncLedger.open(store, {
    doorId: config.doorId,
    keyPath: `${dbPath}.doorkey.pem`,
  });
  for (const cardId of options.cards ?? []) {
    await seedCard(ledger, mandate, cardId);
  }
  if (options.seed !== undefined) {
    await options.seed(ledger, mandate);
  }
  const approvals = new MockApprovals();
  const notifier = new MockCardNotifier();
  const waivers = new WaiverStore(config.waiverTtlMs);
  const app = Fastify({ logger: false });
  await registerCardRail(app, {
    config,
    ledger,
    policy: new MandatePolicyEngine({
      mandate,
      velocity: { maxIntentsPerMinute: config.maxIntentsPerMinute },
      rail: 'card',
    }),
    mandate,
    stripe: null,
    approvals,
    notifier,
    waivers,
    authenticateCreate: () => Promise.resolve({ ok: true, actor: options.actor ?? mandate.agent }),
    ...options.deps,
  });
  await app.ready();
  return {
    app,
    ledger,
    mandate,
    approvals,
    notifier,
    waivers,
    dbPath,
    close: async () => {
      await app.close();
      await ledger.close();
    },
  };
}

/** A signed issuing_authorization.request event, Stripe-shaped. */
export function authorizationEvent(args: {
  authorizationId: string;
  cardId: string;
  amountMinorUnits: number;
  currency?: string;
  merchantName?: string;
  networkId?: string;
  isAmountControllable?: boolean;
}): Record<string, unknown> {
  return {
    id: `evt_${args.authorizationId}`,
    object: 'event',
    api_version: '2026-test',
    type: 'issuing_authorization.request',
    data: {
      object: {
        id: args.authorizationId,
        object: 'issuing.authorization',
        amount: args.amountMinorUnits,
        currency: (args.currency ?? 'EUR').toLowerCase(),
        card: { id: args.cardId, object: 'issuing.card', last4: '4242' },
        merchant_data: {
          category: 'computer_software_stores',
          city: 'Berlin',
          country: 'DE',
          name: args.merchantName ?? 'ACME SaaS',
          network_id: args.networkId ?? 'net_acme_1',
        },
        pending_request: {
          amount: args.amountMinorUnits,
          currency: (args.currency ?? 'EUR').toLowerCase(),
          is_amount_controllable: args.isAmountControllable ?? false,
          merchant_amount: args.amountMinorUnits,
          merchant_currency: (args.currency ?? 'EUR').toLowerCase(),
        },
      },
    },
  };
}

/** POST a signed webhook to the rail; `tamper` mutates AFTER signing. */
export async function postWebhook(
  app: FastifyInstance,
  event: Record<string, unknown>,
  options: { secret?: string; omitSignature?: boolean; tamperBody?: string; header?: string } = {}
): Promise<{ statusCode: number; json: () => unknown }> {
  const payload = JSON.stringify(event);
  const header =
    options.header ??
    signStripePayload({ payload, secret: options.secret ?? TEST_WEBHOOK_SECRET });
  const response = await app.inject({
    method: 'POST',
    url: '/stripe/webhook',
    payload: options.tamperBody ?? payload,
    headers: {
      'content-type': 'application/json',
      ...(options.omitSignature === true ? {} : { 'stripe-signature': header }),
    },
  });
  return { statusCode: response.statusCode, json: () => JSON.parse(response.body) };
}

/** Seed a card binding by appending a real card.create intent/result pair. */
export async function seedCard(
  ledger: AsyncLedger,
  mandate: MandateV1,
  cardId: string,
  options: { actor?: string; mandateId?: string } = {}
): Promise<void> {
  const { canonicalJson, sha256Hex } = await import('@mandarelabs/spec');
  const { spendProjector } = await import('@mandarelabs/ledger');
  const { CARD_CREATE_INTENT, CARD_CREATE_RESULT } = await import('../src/registry.js');
  const actor = options.actor ?? mandate.agent;
  const mandateId = options.mandateId ?? mandate.id;
  const requestHash = sha256Hex(canonicalJson({ op: 'card.create', card: cardId }));
  const intent = await ledger.appendProjected(
    {
      actor,
      mandate_id: mandateId,
      action: { type: CARD_CREATE_INTENT, target: 'stripe:issuing.card', request_hash: requestHash },
      cost: { amount: 0, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
    },
    spendProjector()
  );
  if (intent.kind !== 'appended') {
    throw new Error('seed intent refused');
  }
  const result = await ledger.appendProjected(
    {
      actor,
      mandate_id: mandateId,
      action: {
        type: CARD_CREATE_RESULT,
        target: cardId,
        request_hash: requestHash,
        response_hash: sha256Hex(canonicalJson({ card: cardId })),
      },
      cost: { amount: 0, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
      outcome_ref: intent.entry.entry_hash,
    },
    spendProjector()
  );
  if (result.kind !== 'appended') {
    throw new Error('seed result refused');
  }
}
