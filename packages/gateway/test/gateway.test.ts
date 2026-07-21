import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, test } from 'vitest';

import { Ledger, readLedger, type AppendInput } from '@mandarelabs/ledger';
import { UnconfiguredPolicyEngine, type PolicyEngine } from '@mandarelabs/policy-engine';
import { LLM_CALL_INTENT, LLM_CALL_RESULT, type LedgerEntryV1 } from '@mandarelabs/spec';
import { verifyChain } from '@mandarelabs/verifier';

import { loadConfigFromEnv, type GatewayConfig } from '../src/config.js';
import { buildGateway, type LedgerWriter } from '../src/server.js';
import type { FetchLike } from '../src/openrouter.js';

function tempDbPath(): string {
  return join(mkdtempSync(join(tmpdir(), 'mandare-gateway-test-')), 'ledger.db');
}

function testConfig(overrides: Partial<GatewayConfig> = {}): GatewayConfig {
  return {
    host: '127.0.0.1',
    port: 0,
    ledgerDbPath: tempDbPath(),
    doorId: 'gateway:test',
    actor: 'did:example:agent',
    mandateId: 'mnd_test',
    openrouterBaseUrl: 'https://openrouter.example',
    openrouterApiKey: 'test-key-not-a-secret',
    ...overrides,
  };
}

const okUpstream: FetchLike = () =>
  Promise.resolve(
    new Response(
      JSON.stringify({
        id: 'gen-1',
        choices: [{ message: { role: 'assistant', content: 'hello' } }],
        usage: { prompt_tokens: 12, completion_tokens: 34, cost: 0.000456 },
      }),
      { status: 200 }
    )
  );

const chatBody = { model: 'openrouter/auto', messages: [{ role: 'user', content: 'hi' }] };

describe('gateway walking skeleton', () => {
  test('happy path: intent + result entries chain, verify passes, cost recorded in micros', async () => {
    const config = testConfig();
    const ledger = Ledger.open(config.ledgerDbPath, { doorId: config.doorId });
    const app = buildGateway({
      config,
      ledger,
      policy: new UnconfiguredPolicyEngine(),
      fetchImpl: okUpstream,
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: chatBody,
    });
    expect(response.statusCode).toBe(200);
    expect(response.headers['x-mandare-intent-entry']).toMatch(/^[0-9a-f]{64}$/);
    await app.close();
    ledger.close();

    const { meta, entries } = readLedger(config.ledgerDbPath);
    expect(entries).toHaveLength(2);
    const [intent, result] = entries as [LedgerEntryV1, LedgerEntryV1];
    expect(intent.action.type).toBe(LLM_CALL_INTENT);
    expect(intent.action.response_hash).toBeUndefined();
    expect(result.action.type).toBe(LLM_CALL_RESULT);
    expect(result.outcome_ref).toBe(intent.entry_hash);
    expect(result.cost).toEqual({ amount: 456, currency: 'USD', tokens_in: 12, tokens_out: 34 });

    const verdict = await verifyChain(entries, { doorPublicKey: meta.door_public_key });
    expect(verdict.ok).toBe(true);
  });

  test('no API key → 503 and NOTHING written (fail-closed, R1)', async () => {
    const config = testConfig({ openrouterApiKey: null });
    const ledger = Ledger.open(config.ledgerDbPath, { doorId: config.doorId });
    const app = buildGateway({ config, ledger, policy: new UnconfiguredPolicyEngine() });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: chatBody,
    });
    expect(response.statusCode).toBe(503);
    expect(ledger.head()).toBeNull();
    await app.close();
    ledger.close();
  });

  test('policy deny → 403 before any ledger write or upstream call', async () => {
    const config = testConfig();
    const ledger = Ledger.open(config.ledgerDbPath, { doorId: config.doorId });
    const denyAll: PolicyEngine = {
      evaluate: () => Promise.resolve({ decision: 'deny', reasons: ['budget exhausted (test)'] }),
    };
    let upstreamCalled = false;
    const app = buildGateway({
      config,
      ledger,
      policy: denyAll,
      fetchImpl: () => {
        upstreamCalled = true;
        return okUpstream('', {});
      },
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: chatBody,
    });
    expect(response.statusCode).toBe(403);
    expect(upstreamCalled).toBe(false);
    expect(ledger.head()).toBeNull();
    await app.close();
    ledger.close();
  });

  test('throwing policy engine is treated as deny (fail-closed)', async () => {
    const config = testConfig();
    const ledger = Ledger.open(config.ledgerDbPath, { doorId: config.doorId });
    const broken: PolicyEngine = {
      evaluate: () => Promise.reject(new Error('policy backend down')),
    };
    const app = buildGateway({ config, ledger, policy: broken, fetchImpl: okUpstream });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: chatBody,
    });
    expect(response.statusCode).toBe(503);
    expect(ledger.head()).toBeNull();
    await app.close();
    ledger.close();
  });

  test('schema-invalid bodies are rejected (R4)', async () => {
    const config = testConfig();
    const ledger = Ledger.open(config.ledgerDbPath, { doorId: config.doorId });
    const app = buildGateway({ config, ledger, policy: new UnconfiguredPolicyEngine() });

    for (const payload of [
      {},
      { model: 'x' },
      { model: 'x', messages: [] },
      { model: 'x', messages: [{ role: 'user', content: 'hi' }], stream: true },
    ]) {
      const response = await app.inject({ method: 'POST', url: '/v1/chat/completions', payload });
      expect(response.statusCode).toBe(400);
    }
    expect(ledger.head()).toBeNull();
    await app.close();
    ledger.close();
  });

  test('non-canonicalizable body (1e400 → Infinity) → 400, nothing written (R4)', async () => {
    const config = testConfig();
    const ledger = Ledger.open(config.ledgerDbPath, { doorId: config.doorId });
    const app = buildGateway({
      config,
      ledger,
      policy: new UnconfiguredPolicyEngine(),
      fetchImpl: okUpstream,
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { 'content-type': 'application/json' },
      payload: '{"model":"x","messages":[1e400]}',
    });
    expect(response.statusCode).toBe(400);
    expect(ledger.head()).toBeNull();
    await app.close();
    ledger.close();
  });

  test('provider network failure records an outcome-unknown result entry, not silence', async () => {
    const config = testConfig();
    const ledger = Ledger.open(config.ledgerDbPath, { doorId: config.doorId });
    const app = buildGateway({
      config,
      ledger,
      policy: new UnconfiguredPolicyEngine(),
      fetchImpl: () => Promise.reject(new DOMException('timed out', 'TimeoutError')),
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: chatBody,
    });
    expect(response.statusCode).toBe(502);
    expect(response.json().error).toContain('outcome recorded as unknown');
    await app.close();
    ledger.close();

    const { entries } = readLedger(config.ledgerDbPath);
    expect(entries).toHaveLength(2);
    const result = entries[1] as LedgerEntryV1;
    expect(result.action.type).toBe(LLM_CALL_RESULT);
    expect(result.outcome_ref).toBe((entries[0] as LedgerEntryV1).entry_hash);
  });

  test('upstream error passes through and is still recorded as a result entry', async () => {
    const config = testConfig();
    const ledger = Ledger.open(config.ledgerDbPath, { doorId: config.doorId });
    const failingUpstream: FetchLike = () =>
      Promise.resolve(new Response(JSON.stringify({ error: 'rate limited' }), { status: 429 }));
    const app = buildGateway({
      config,
      ledger,
      policy: new UnconfiguredPolicyEngine(),
      fetchImpl: failingUpstream,
    });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: chatBody,
    });
    expect(response.statusCode).toBe(429);
    await app.close();
    ledger.close();

    const { entries } = readLedger(config.ledgerDbPath);
    expect(entries).toHaveLength(2);
    const result = entries[1] as LedgerEntryV1;
    expect(result.action.type).toBe(LLM_CALL_RESULT);
    expect(result.cost.amount).toBe(0);
  });

  test('result-write failure HALTS the gateway (no acting off the record)', async () => {
    const config = testConfig();
    const realLedger = Ledger.open(config.ledgerDbPath, { doorId: config.doorId });
    let appendCount = 0;
    const failingSecondWrite: LedgerWriter = {
      append(input: AppendInput) {
        appendCount += 1;
        if (appendCount >= 2) {
          throw new Error('disk full (test)');
        }
        return realLedger.append(input);
      },
    };
    const app = buildGateway({
      config,
      ledger: failingSecondWrite,
      policy: new UnconfiguredPolicyEngine(),
      fetchImpl: okUpstream,
    });

    const first = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: chatBody,
    });
    expect(first.statusCode).toBe(502);
    expect(first.json()).toMatchObject({ error: expect.stringContaining('halted') });

    const second = await app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: chatBody,
    });
    expect(second.statusCode).toBe(503);

    const health = await app.inject({ method: 'GET', url: '/healthz' });
    expect(health.json()).toMatchObject({ ok: false, halted: true });

    await app.close();
    realLedger.close();
  });
});

describe('config', () => {
  test('defaults are local-first and fail-closed', () => {
    const config = loadConfigFromEnv({});
    expect(config.host).toBe('127.0.0.1');
    expect(config.openrouterApiKey).toBeNull();
    expect(config.openrouterBaseUrl).toBe('https://openrouter.ai/api/v1');
  });

  test('rejects a malformed port', () => {
    expect(() => loadConfigFromEnv({ MANDARE_GATEWAY_PORT: 'abc' })).toThrow(/PORT/);
  });

  test('strips trailing slashes from the base URL', () => {
    const config = loadConfigFromEnv({ OPENROUTER_BASE_URL: 'http://127.0.0.1:9999/api/v1//' });
    expect(config.openrouterBaseUrl).toBe('http://127.0.0.1:9999/api/v1');
  });
});
