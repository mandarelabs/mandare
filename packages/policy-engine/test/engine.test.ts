import { describe, expect, test } from 'vitest';

import type { MandateV1 } from '@mandarelabs/spec';

import {
  MandatePolicyEngine,
  type PolicyRequest,
  type SpendCounterSnapshot,
} from '../src/index.js';

/**
 * Engine tests pin the SPEC §5 evaluation order: identity → window → scope →
 * budget → counterparty → approval. Each stage has a deny case, and the
 * fail-closed stages (verified_only, approval threshold, malformed window)
 * are proven to refuse rather than skip.
 */

const FAKE_SIGNATURE = {
  alg: 'EdDSA',
  key_id: 'a'.repeat(64),
  key_provenance: 'software',
  value: 'dGVzdC1zaWduYXR1cmU',
} as const;

function mandate(overrides: Partial<MandateV1> = {}): MandateV1 {
  return {
    schema_version: 1,
    id: 'mnd_engine_test',
    principal: 'did:example:owner',
    agent: 'did:example:agent',
    purpose: 'test mandate',
    scopes: [
      {
        type: 'spend',
        currency: 'EUR',
        per_tx_max: 5_000_000,
        per_day_max: 20_000_000,
        per_task_max: 20_000_000,
        total_cap: 100_000_000,
        rails: ['gateway'],
        counterparties: 'any',
        categories: ['llm'],
      },
      { type: 'action', classes: ['llm.call'] },
    ],
    approvals: { rules: [{ above: 4_000_000, currency: 'EUR', method: 'push' }] },
    valid_from: '2026-07-01T00:00:00Z',
    valid_until: '2026-12-31T00:00:00Z',
    revocation_ref: 'statuslist:0#1',
    signature: FAKE_SIGNATURE,
    ...overrides,
  };
}

const NOW = new Date('2026-07-21T12:00:00Z');

function engine(m: MandateV1 = mandate(), maxPerMinute = 100): MandatePolicyEngine {
  return new MandatePolicyEngine({
    mandate: m,
    velocity: { maxIntentsPerMinute: maxPerMinute },
    clock: () => NOW,
  });
}

function counters(overrides: Partial<SpendCounterSnapshot> = {}): SpendCounterSnapshot {
  return {
    minuteIntents: 0,
    day: { reservedMicros: 0, settledMicros: 0 },
    task: { reservedMicros: 0, settledMicros: 0 },
    total: { reservedMicros: 0, settledMicros: 0 },
    ...overrides,
  };
}

function request(overrides: {
  principal?: string;
  action?: string;
  estimateMicros?: number;
  currency?: string;
  counterparty?: string;
  counters?: SpendCounterSnapshot;
  context?: Record<string, unknown>;
}): PolicyRequest {
  return {
    principal: overrides.principal ?? 'did:example:agent',
    action: overrides.action ?? 'llm.call',
    resource: 'claude-haiku-4-5',
    context: overrides.context ?? {
      estimateMicros: overrides.estimateMicros ?? 100_000,
      currency: overrides.currency ?? 'EUR',
      counterparty: overrides.counterparty ?? 'api.anthropic.com',
      counters: overrides.counters ?? counters(),
    },
  };
}

describe('MandatePolicyEngine — SPEC §5 order', () => {
  test('a mandated, in-window, in-budget call is allowed with a readable reason', async () => {
    const decision = await engine().evaluate(request({}));
    expect(decision.decision).toBe('allow');
    expect(decision.reasons[0]).toContain('mnd_engine_test');
    expect(decision.reasons[0]).toContain('0.10 EUR');
  });

  test('malformed context refuses (fail-closed, R4)', async () => {
    for (const context of [
      {},
      { estimateMicros: -1, currency: 'EUR', counterparty: 'x', counters: counters() },
      { estimateMicros: 1, currency: 'eur', counterparty: 'x', counters: counters() },
      { estimateMicros: 1, currency: 'EUR', counterparty: '', counters: counters() },
      { estimateMicros: 1, currency: 'EUR', counterparty: 'x', counters: { bogus: true } },
      { estimateMicros: 1, currency: 'EUR', counterparty: 'x', counters: null },
    ]) {
      const decision = await engine().evaluate(request({ context }));
      expect(decision.decision).toBe('deny');
      expect(decision.code).toBe('CONTEXT_INVALID');
    }
  });

  test('1. wrong principal denies (identity precedes everything)', async () => {
    const decision = await engine().evaluate(request({ principal: 'did:example:impostor' }));
    expect(decision.code).toBe('IDENTITY_MISMATCH');
  });

  test('2. out-of-window mandate denies (expired and not-yet-valid)', async () => {
    const expired = mandate({ valid_until: '2026-07-20T00:00:00Z' });
    expect((await engine(expired).evaluate(request({}))).code).toBe('MANDATE_OUT_OF_WINDOW');
    const future = mandate({ valid_from: '2026-08-01T00:00:00Z' });
    expect((await engine(future).evaluate(request({}))).code).toBe('MANDATE_OUT_OF_WINDOW');
  });

  test('2b. non-calendar window timestamps deny, never skip (fail-closed)', async () => {
    const broken = mandate({ valid_until: '2026-13-01T00:00:00Z' });
    const decision = await engine(broken).evaluate(request({}));
    expect(decision.code).toBe('MANDATE_WINDOW_INVALID');
  });

  test('3. unmandated action class denies', async () => {
    const decision = await engine().evaluate(request({ action: 'file.write' }));
    expect(decision.code).toBe('SCOPE_MISMATCH');
  });

  test('3b. no gateway-rail spend scope denies', async () => {
    const cardOnly = mandate({
      scopes: [
        {
          type: 'spend',
          currency: 'EUR',
          per_tx_max: 1,
          per_day_max: 1,
          per_task_max: 1,
          total_cap: 1,
          rails: ['card'],
          counterparties: 'any',
          categories: [],
        },
        { type: 'action', classes: ['llm.call'] },
      ],
    });
    const decision = await engine(cardOnly).evaluate(request({}));
    expect(decision.code).toBe('SCOPE_MISMATCH');
  });

  test('3c. overlapping spend scopes deny as ambiguous (fail-closed)', async () => {
    const spend = mandate().scopes[0];
    const doubled = mandate({
      scopes: [spend, spend, { type: 'action', classes: ['llm.call'] }],
    } as Partial<MandateV1>);
    const decision = await engine(doubled).evaluate(request({}));
    expect(decision.code).toBe('SCOPE_AMBIGUOUS');
  });

  test('4. budget refusal carries the checkBudgets code', async () => {
    const decision = await engine().evaluate(
      request({ counters: counters({ day: { reservedMicros: 0, settledMicros: 20_000_000 } }) })
    );
    expect(decision.code).toBe('PER_DAY_EXCEEDED');
  });

  test('4b. velocity refusal', async () => {
    const decision = await engine(mandate(), 10).evaluate(
      request({ counters: counters({ minuteIntents: 10 }) })
    );
    expect(decision.code).toBe('VELOCITY_EXCEEDED');
  });

  test('5. allowlist counterparty mode enforces the list', async () => {
    const allowlisted = mandate({
      scopes: [
        {
          type: 'spend',
          currency: 'EUR',
          per_tx_max: 5_000_000,
          per_day_max: 20_000_000,
          per_task_max: 20_000_000,
          total_cap: 100_000_000,
          rails: ['gateway'],
          counterparties: 'allowlist',
          counterparty_allowlist: ['api.anthropic.com'],
          categories: ['llm'],
        },
        { type: 'action', classes: ['llm.call'] },
      ],
    });
    expect((await engine(allowlisted).evaluate(request({}))).decision).toBe('allow');
    const denied = await engine(allowlisted).evaluate(
      request({ counterparty: 'evil.example.com' })
    );
    expect(denied.code).toBe('COUNTERPARTY_DENIED');
  });

  test('5b. verified_only denies until the registry exists (fail-closed)', async () => {
    const verifiedOnly = mandate({
      scopes: [
        {
          type: 'spend',
          currency: 'EUR',
          per_tx_max: 5_000_000,
          per_day_max: 20_000_000,
          per_task_max: 20_000_000,
          total_cap: 100_000_000,
          rails: ['gateway'],
          counterparties: 'verified_only',
          categories: ['llm'],
        },
        { type: 'action', classes: ['llm.call'] },
      ],
    });
    const decision = await engine(verifiedOnly).evaluate(request({}));
    expect(decision.code).toBe('COUNTERPARTY_UNVERIFIABLE');
  });

  test('6. above the approval threshold denies with APPROVAL_REQUIRED (the gateway holds & pushes)', async () => {
    const decision = await engine().evaluate(request({ estimateMicros: 4_000_001 }));
    expect(decision.code).toBe('APPROVAL_REQUIRED');
    expect(decision.reasons[0]).toContain('approval');
  });

  test('6c. a recorded approval grant waives the threshold for that evaluation only', async () => {
    const contextWithGrant = (grant: string) => ({
      estimateMicros: 4_000_001,
      currency: 'EUR',
      counterparty: 'api.anthropic.com',
      counters: counters(),
      approvedEntryHash: grant,
    });
    const approved = await engine().evaluate(request({ context: contextWithGrant('a'.repeat(64)) }));
    expect(approved.decision).toBe('allow');
    // Garbage in the grant field is a malformed context, not a bypass (R4).
    const forged = await engine().evaluate(request({ context: contextWithGrant('not-a-hash') }));
    expect(forged.code).toBe('CONTEXT_INVALID');
  });

  test('6b. approval rule in a foreign currency denies as unevaluable (fail-closed)', async () => {
    const usdRule = mandate({
      approvals: { rules: [{ above: 1, currency: 'USD', method: 'push' }] },
    });
    const decision = await engine(usdRule).evaluate(request({}));
    expect(decision.code).toBe('APPROVAL_RULE_UNEVALUABLE');
  });

  test('order: identity is checked before the window, window before scope', async () => {
    const expired = mandate({ valid_until: '2026-07-20T00:00:00Z' });
    const decision = await engine(expired).evaluate(
      request({ principal: 'did:example:impostor' })
    );
    expect(decision.code).toBe('IDENTITY_MISMATCH');

    const expiredWrongAction = await engine(expired).evaluate(request({ action: 'file.write' }));
    expect(expiredWrongAction.code).toBe('MANDATE_OUT_OF_WINDOW');
  });
});
