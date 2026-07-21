import { describe, expect, test } from 'vitest';

import {
  readLedger,
  replaySpendCounters,
  verifySpendProjection,
  LLM_CALL_DENIED,
  type AppendInput,
  type AppendProjectedResult,
  type Projector,
} from '@mandarelabs/ledger';
import { LLM_CALL_INTENT, LLM_CALL_RESULT, type LedgerEntryV1 } from '@mandarelabs/spec';
import { verifyChain } from '@mandarelabs/verifier';

import { loadConfigFromEnv } from '../src/config.js';
import {
  anthropicBody,
  anthropicOkFetch,
  chatBody,
  openTestGateway,
  openrouterOkFetch,
  testMandate,
} from './helpers.js';

describe('gateway S2 flow — reserve, forward, settle', () => {
  test('happy path (openrouter): intent reserves the estimate, result settles authoritative cost', async () => {
    const gw = await openTestGateway({ fetchImpl: openrouterOkFetch(0.000456) });
    const response = await gw.app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: chatBody,
    });
    expect(response.statusCode).toBe(200);
    expect(response.headers['x-mandare-intent-entry']).toMatch(/^[0-9a-f]{64}$/);
    expect(response.headers['x-mandare-result-entry']).toMatch(/^[0-9a-f]{64}$/);
    await gw.close();

    const { meta, entries } = readLedger(gw.dbPath);
    expect(entries).toHaveLength(2);
    const [intent, result] = entries as [LedgerEntryV1, LedgerEntryV1];
    expect(intent.action.type).toBe(LLM_CALL_INTENT);
    expect(intent.cost.amount).toBeGreaterThan(0); // the reservation
    expect(intent.cost.currency).toBe('EUR');
    expect(result.action.type).toBe(LLM_CALL_RESULT);
    expect(result.outcome_ref).toBe(intent.entry_hash);
    expect(result.cost.amount).toBe(456); // 0.000456 USD at 1 USD/EUR-unit
    expect(result.cost.tokens_in).toBe(12);
    expect(result.cost.tokens_out).toBe(34);

    expect((await verifyChain(entries, { doorPublicKey: meta.door_public_key })).ok).toBe(true);
  });

  test('happy path (anthropic): token usage priced through the table', async () => {
    const gw = await openTestGateway({
      fetchImpl: anthropicOkFetch({ input_tokens: 1000, output_tokens: 2000 }),
    });
    const response = await gw.app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: anthropicBody,
    });
    expect(response.statusCode).toBe(200);
    await gw.close();

    const { entries } = readLedger(gw.dbPath);
    const result = entries[1] as LedgerEntryV1;
    // haiku-4-5: 1000 in × $1/M + 2000 out × $5/M = $0.011 → 11_000 micros.
    expect(result.cost.amount).toBe(11_000);
    expect(result.cost.tokens_in).toBe(1000);
    expect(result.cost.tokens_out).toBe(2000);
  });

  test('cache tokens are billed at cache rates (anthropic)', async () => {
    const gw = await openTestGateway({
      fetchImpl: anthropicOkFetch({
        input_tokens: 1000,
        output_tokens: 0,
        cache_creation_input_tokens: 1000,
        cache_read_input_tokens: 10_000,
      }),
    });
    const response = await gw.app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: anthropicBody,
    });
    expect(response.statusCode).toBe(200);
    await gw.close();
    const { entries } = readLedger(gw.dbPath);
    const result = entries[1] as LedgerEntryV1;
    // 1000×$1/M + 1000×$1.25/M + 10000×$0.1/M = $0.00325 → 3250 micros.
    expect(result.cost.amount).toBe(3250);
    expect(result.cost.tokens_in).toBe(12_000);
  });

  test('no mandate → 503, spend path closed, NOTHING written (R1 — no allow-all fallback)', async () => {
    const gw = await openTestGateway({ mandate: null, fetchImpl: openrouterOkFetch() });
    const response = await gw.app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: chatBody,
    });
    expect(response.statusCode).toBe(503);
    expect((await gw.ledger.head())) .toBeNull();
    const health = await gw.app.inject({ method: 'GET', url: '/healthz' });
    expect(health.json().spend_path_open).toBe(false);
    await gw.close();
  });

  test('no provider credential → 503 and NOTHING written (R1)', async () => {
    const gw = await openTestGateway({
      config: { openrouter: { baseUrl: 'https://openrouter.example/api/v1', apiKey: null } },
    });
    const response = await gw.app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: chatBody,
    });
    expect(response.statusCode).toBe(503);
    expect(await gw.ledger.head()).toBeNull();
    await gw.close();
  });

  test('non-USD ledger without an FX rate → 503 (no invented rates, R1)', async () => {
    const gw = await openTestGateway({
      config: { usdPerLedgerUnit: null },
      fetchImpl: openrouterOkFetch(),
    });
    const response = await gw.app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: chatBody,
    });
    expect(response.statusCode).toBe(503);
    expect(response.json().error).toContain('MANDARE_USD_PER_LEDGER_UNIT');
    await gw.close();
  });

  test('mandate currency ≠ ledger currency → 503 (fail-closed, no implicit FX)', async () => {
    const gw = await openTestGateway({
      config: { ledgerCurrency: 'USD' },
      fetchImpl: openrouterOkFetch(),
    });
    const response = await gw.app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: chatBody,
    });
    expect(response.statusCode).toBe(503);
    expect(response.json().error).toContain('mandate budgets EUR');
    await gw.close();
  });

  test('unpriced model on a direct provider → 403 + DENIED entry (no metering = no spend)', async () => {
    const gw = await openTestGateway({ fetchImpl: anthropicOkFetch({}) });
    const response = await gw.app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: { ...anthropicBody, model: 'claude-mystery-9' },
    });
    expect(response.statusCode).toBe(403);
    expect(response.json().code).toBe('MODEL_UNPRICED');
    expect(response.json().denied_entry).toMatch(/^[0-9a-f]{64}$/);
    await gw.close();
    const { entries } = readLedger(gw.dbPath);
    expect(entries).toHaveLength(1);
    expect((entries[0] as LedgerEntryV1).action.type).toBe(LLM_CALL_DENIED);
  });

  test('per-tx breach denies BEFORE any upstream call, and the refusal is a ledger entry', async () => {
    let upstreamCalled = false;
    const tightMandate = testMandate();
    // €0.0001 per-tx cap — any real estimate breaches it.
    (tightMandate.scopes[0] as { per_tx_max: number }).per_tx_max = 100;
    const gw = await openTestGateway({
      mandate: tightMandate,
      fetchImpl: () => {
        upstreamCalled = true;
        return openrouterOkFetch()('', {});
      },
    });
    const response = await gw.app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: anthropicBody,
    });
    expect(response.statusCode).toBe(403);
    expect(response.json().code).toBe('PER_TX_EXCEEDED');
    expect(upstreamCalled).toBe(false);
    await gw.close();
    const { entries } = readLedger(gw.dbPath);
    expect(entries).toHaveLength(1);
    const denied = entries[0] as LedgerEntryV1;
    expect(denied.action.type).toBe(LLM_CALL_DENIED);
    expect(denied.cost.amount).toBeGreaterThan(100); // records the refused estimate
    // Denied entries never touch the counters.
    const counters = await replaySpendCounters(entries);
    expect([...counters.keys()].filter((key) => key.startsWith('mandate:'))).toHaveLength(0);
  });

  test('provider network failure settles at the RESERVED ESTIMATE, never 0 (outcome unknown ≠ free)', async () => {
    const gw = await openTestGateway({
      fetchImpl: () => Promise.reject(new DOMException('timed out', 'TimeoutError')),
    });
    const response = await gw.app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: anthropicBody,
    });
    expect(response.statusCode).toBe(502);
    expect(response.json().error).toContain('settled at the reserved estimate');
    const verdict = await verifySpendProjection(gw.ledger);
    expect(verdict).toMatchObject({ ok: true });
    await gw.close();

    const { entries } = readLedger(gw.dbPath);
    expect(entries).toHaveLength(2);
    const [intent, result] = entries as [LedgerEntryV1, LedgerEntryV1];
    expect(result.outcome_ref).toBe(intent.entry_hash);
    expect(result.cost.amount).toBe(intent.cost.amount); // conservative settle
  });

  test('provider 429 passes through, settles 0, releases the reservation', async () => {
    const gw = await openTestGateway({
      fetchImpl: () =>
        Promise.resolve(new Response(JSON.stringify({ error: 'rate limited' }), { status: 429 })),
    });
    const response = await gw.app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: anthropicBody,
    });
    expect(response.statusCode).toBe(429);
    await gw.close();
    const { entries } = readLedger(gw.dbPath);
    const result = entries[1] as LedgerEntryV1;
    expect(result.cost.amount).toBe(0);
    const counters = await replaySpendCounters(entries);
    for (const [key, counter] of counters) {
      if (key.startsWith('mandate:')) {
        expect(counter.reservedMicros).toBe(0); // released
        expect(counter.settledMicros).toBe(0);
      }
    }
  });

  test('result-write failure HALTS the gateway (no acting off the record)', async () => {
    const gw0 = await openTestGateway({});
    let appendCount = 0;
    const failingSecondWrite = {
      appendProjected(input: AppendInput, project: Projector): Promise<AppendProjectedResult> {
        appendCount += 1;
        if (appendCount >= 2) {
          throw new Error('disk full (test)');
        }
        return gw0.ledger.appendProjected(input, project);
      },
      runProjection: gw0.ledger.runProjection.bind(gw0.ledger),
    };
    const gw = await openTestGateway({
      ledgerOverride: failingSecondWrite,
      fetchImpl: openrouterOkFetch(),
      config: { ledgerDbPath: gw0.dbPath },
    });

    const first = await gw.app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: chatBody,
    });
    expect(first.statusCode).toBe(502);
    expect(first.json().error).toContain('halted');

    const second = await gw.app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      payload: chatBody,
    });
    expect(second.statusCode).toBe(503);
    const health = await gw.app.inject({ method: 'GET', url: '/healthz' });
    expect(health.json()).toMatchObject({ ok: false, halted: true });
    await gw.app.close();
    await gw0.close();
  });

  test('schema-invalid bodies are rejected with nothing written (R4)', async () => {
    const gw = await openTestGateway({});
    for (const payload of [
      {},
      { model: 'x' },
      { model: 'x', messages: [] },
      { model: 'x', messages: [{ role: 'user', content: 'hi' }], stream: 'yes' },
      { model: 'x', messages: [{ role: 'user', content: 'hi' }], max_tokens: 0 },
    ]) {
      const response = await gw.app.inject({ method: 'POST', url: '/v1/chat/completions', payload });
      expect(response.statusCode).toBe(400);
    }
    // Anthropic surface requires max_tokens.
    const noMax = await gw.app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: { model: 'claude-haiku-4-5', messages: [{ role: 'user', content: 'hi' }] },
    });
    expect(noMax.statusCode).toBe(400);
    expect(await gw.ledger.head()).toBeNull();
    await gw.close();
  });
});

describe('config', () => {
  test('defaults are local-first and fail-closed', () => {
    const config = loadConfigFromEnv({});
    expect(config.host).toBe('127.0.0.1');
    expect(config.mandatePath).toBeNull();
    expect(config.anthropic.apiKey).toBeNull();
    expect(config.ledgerCurrency).toBe('EUR');
    expect(config.usdPerLedgerUnit).toBeNull(); // EUR without a rate = closed
    expect(config.chatProvider).toBe('openai');
  });

  test('provider base-URL defaults follow each SDK convention (anthropic excludes /v1)', () => {
    const config = loadConfigFromEnv({});
    // Regression: an operator's ANTHROPIC_BASE_URL=https://api.anthropic.com
    // (the SDK convention) must resolve to /v1/messages, not /messages.
    expect(config.anthropic.baseUrl).toBe('https://api.anthropic.com');
    expect(config.openai.baseUrl).toBe('https://api.openai.com/v1');
    expect(config.openrouter.baseUrl).toBe('https://openrouter.ai/api/v1');
  });

  test('USD ledger needs no rate; EUR ledger takes the explicit one', () => {
    expect(loadConfigFromEnv({ MANDARE_LEDGER_CURRENCY: 'USD' }).usdPerLedgerUnit).toBe(1);
    expect(
      loadConfigFromEnv({ MANDARE_USD_PER_LEDGER_UNIT: '1.16' }).usdPerLedgerUnit
    ).toBeCloseTo(1.16);
    expect(() => loadConfigFromEnv({ MANDARE_USD_PER_LEDGER_UNIT: '-1' })).toThrow(/positive/);
  });

  test('chat provider prefers openrouter when its key exists, honors the override', () => {
    expect(loadConfigFromEnv({ OPENROUTER_API_KEY: 'k' }).chatProvider).toBe('openrouter');
    expect(
      loadConfigFromEnv({ OPENROUTER_API_KEY: 'k', MANDARE_CHAT_PROVIDER: 'openai' }).chatProvider
    ).toBe('openai');
  });

  test('rejects malformed port, velocity, currency', () => {
    expect(() => loadConfigFromEnv({ MANDARE_GATEWAY_PORT: 'abc' })).toThrow(/PORT/);
    expect(() => loadConfigFromEnv({ MANDARE_MAX_CALLS_PER_MINUTE: '0' })).toThrow(/CALLS/);
    expect(() => loadConfigFromEnv({ MANDARE_LEDGER_CURRENCY: 'eur' })).toThrow(/CURRENCY/);
  });
});

describe('budget exhaustion (the demo mechanic)', () => {
  test('a loop of calls dies when the day cap is reached — cap never pierced, refusal on the ledger', async () => {
    // 'openrouter/auto' is unpriced → each call reserves the FULL €5 per-tx
    // cap, then settles the authoritative €2.40. The reservation math dies
    // when settled + €5 would cross €20: after 7 completed calls (€16.80).
    // Conservative by design — the cap is NEVER pierced, even though the
    // per-call estimate is coarse.
    const gw = await openTestGateway({
      mandate: testMandate(),
      fetchImpl: openrouterOkFetch(2.4),
    });
    let denied: { code: string } | null = null;
    let completed = 0;
    for (let i = 0; i < 20 && denied === null; i += 1) {
      const response = await gw.app.inject({
        method: 'POST',
        url: '/v1/chat/completions',
        payload: chatBody,
      });
      if (response.statusCode === 200) {
        completed += 1;
      } else {
        expect(response.statusCode).toBe(403);
        denied = response.json();
      }
    }
    expect(completed).toBe(7);
    expect(denied?.code).toBe('PER_DAY_EXCEEDED');
    expect(await verifySpendProjection(gw.ledger)).toMatchObject({ ok: true });
    await gw.close();

    const { entries } = readLedger(gw.dbPath);
    // 7 × (intent+result) + 1 denied = 15 entries; settled spend ≤ cap.
    expect(entries).toHaveLength(15);
    const settled = (entries as LedgerEntryV1[])
      .filter((entry) => entry.action.type === LLM_CALL_RESULT)
      .reduce((sum, entry) => sum + entry.cost.amount, 0);
    expect(settled).toBe(7 * 2_400_000);
    expect(settled).toBeLessThanOrEqual(20_000_000);
    expect((entries.at(-1) as LedgerEntryV1).action.type).toBe(LLM_CALL_DENIED);
  });
});
