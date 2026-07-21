import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { AsyncLedger, SqliteStore } from '@mandarelabs/ledger';
import { MandatePolicyEngine, type PolicyEngine } from '@mandarelabs/policy-engine';
import type { MandateV1 } from '@mandarelabs/spec';

import type { GatewayConfig } from '../src/config.js';
import { buildGateway, type GatewayDeps } from '../src/server.js';
import type { FetchLike } from '../src/providers/types.js';

export function tempDbPath(): string {
  return join(mkdtempSync(join(tmpdir(), 'mandare-gateway-test-')), 'ledger.db');
}

export const FAKE_SIGNATURE = {
  alg: 'EdDSA',
  key_id: 'a'.repeat(64),
  key_provenance: 'software',
  value: 'dGVzdC1zaWduYXR1cmU',
} as const;

/** €-denominated test mandate; caps in EUR micros. */
export function testMandate(overrides: Partial<MandateV1> = {}): MandateV1 {
  return {
    schema_version: 1,
    id: 'mnd_gateway_test',
    principal: 'did:example:owner',
    agent: 'did:example:agent',
    purpose: 'gateway tests',
    scopes: [
      {
        type: 'spend',
        currency: 'EUR',
        per_tx_max: 5_000_000, // €5
        per_day_max: 20_000_000, // €20
        per_task_max: 100_000_000,
        total_cap: 100_000_000,
        rails: ['gateway'],
        counterparties: 'any',
        categories: ['llm'],
      },
      { type: 'action', classes: ['llm.call'] },
    ],
    approvals: { rules: [{ above: 5_000_000, currency: 'EUR', method: 'push' }] },
    valid_from: '2026-01-01T00:00:00Z',
    valid_until: '2036-01-01T00:00:00Z',
    revocation_ref: 'statuslist:0#1',
    signature: FAKE_SIGNATURE,
    ...overrides,
  };
}

export function testConfig(overrides: Partial<GatewayConfig> = {}): GatewayConfig {
  return {
    host: '127.0.0.1',
    port: 0,
    ledgerDbPath: tempDbPath(),
    doorId: 'gateway:test',
    actor: 'did:example:agent',
    mandatePath: null,
    ledgerCurrency: 'EUR',
    // 1 USD per EUR keeps test arithmetic transparent (1 USD micro = 1 EUR micro).
    usdPerLedgerUnit: 1,
    maxIntentsPerMinute: 10_000,
    pricingPath: null,
    anthropic: { baseUrl: 'https://anthropic.example', apiKey: 'test-key-not-a-secret' },
    openai: { baseUrl: 'https://openai.example/v1', apiKey: 'test-key-not-a-secret' },
    openrouter: { baseUrl: 'https://openrouter.example/api/v1', apiKey: 'test-key-not-a-secret' },
    chatProvider: 'openrouter',
    ...overrides,
  };
}

export interface TestGateway {
  app: ReturnType<typeof buildGateway>;
  ledger: AsyncLedger;
  config: GatewayConfig;
  mandate: MandateV1;
  dbPath: string;
  close(): Promise<void>;
}

export async function openTestGateway(options: {
  config?: Partial<GatewayConfig>;
  mandate?: MandateV1 | null;
  policy?: PolicyEngine;
  fetchImpl?: FetchLike;
  ledgerOverride?: GatewayDeps['ledger'];
  timeouts?: GatewayDeps['timeouts'];
} = {}): Promise<TestGateway> {
  const config = testConfig(options.config);
  const store = SqliteStore.open(config.ledgerDbPath);
  const ledger = await AsyncLedger.open(store, {
    doorId: config.doorId,
    keyPath: `${config.ledgerDbPath}.doorkey.pem`,
  });
  const mandate = options.mandate === undefined ? testMandate() : options.mandate;
  const policy =
    options.policy ??
    new MandatePolicyEngine({
      mandate: mandate ?? testMandate(),
      velocity: { maxIntentsPerMinute: config.maxIntentsPerMinute },
    });
  const app = buildGateway({
    config,
    ledger: options.ledgerOverride ?? ledger,
    policy,
    mandate,
    ...(options.fetchImpl === undefined ? {} : { fetchImpl: options.fetchImpl }),
    ...(options.timeouts === undefined ? {} : { timeouts: options.timeouts }),
  });
  return {
    app,
    ledger,
    config,
    mandate: mandate ?? testMandate(),
    dbPath: config.ledgerDbPath,
    close: async () => {
      await app.close();
      await ledger.close();
    },
  };
}

/** OpenRouter-shaped non-stream success with authoritative usage.cost (USD). */
export function openrouterOkFetch(costUsd = 0.000456): FetchLike {
  return () =>
    Promise.resolve(
      new Response(
        JSON.stringify({
          id: 'gen-1',
          choices: [{ message: { role: 'assistant', content: 'hello' } }],
          usage: { prompt_tokens: 12, completion_tokens: 34, cost: costUsd },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    );
}

/** Anthropic-shaped non-stream success with token usage (no cost field). */
export function anthropicOkFetch(usage: Record<string, number>): FetchLike {
  return () =>
    Promise.resolve(
      new Response(
        JSON.stringify({
          id: 'msg-1',
          type: 'message',
          content: [{ type: 'text', text: 'hello' }],
          usage,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    );
}

/** An SSE Response streaming the given event blocks. */
export function sseFetch(blocks: string[]): FetchLike {
  return () => {
    const encoder = new TextEncoder();
    const bodyStream = new ReadableStream<Uint8Array>({
      start(controller) {
        for (const block of blocks) {
          controller.enqueue(encoder.encode(block));
        }
        controller.close();
      },
    });
    return Promise.resolve(
      new Response(bodyStream, {
        status: 200,
        headers: { 'content-type': 'text/event-stream' },
      })
    );
  };
}

export const chatBody = {
  model: 'openrouter/auto',
  messages: [{ role: 'user', content: 'hi' }],
  max_tokens: 100,
};

export const anthropicBody = {
  model: 'claude-haiku-4-5',
  messages: [{ role: 'user', content: 'hi' }],
  max_tokens: 100,
};
