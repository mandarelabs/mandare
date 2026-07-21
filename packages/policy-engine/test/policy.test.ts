import { describe, expect, test } from 'vitest';

import { UnconfiguredPolicyEngine, type PolicyRequest } from '../src/index.js';

const request: PolicyRequest = {
  principal: 'did:example:agent',
  action: 'llm.call',
  resource: 'openrouter/auto',
  context: { estimated_cost_micros: 0, currency: 'USD' },
};

describe('UnconfiguredPolicyEngine', () => {
  test('allows, but says loudly that nothing was checked', async () => {
    const decision = await new UnconfiguredPolicyEngine().evaluate(request);
    expect(decision.decision).toBe('allow');
    expect(decision.reasons.join(' ')).toMatch(/not configured/);
  });
});
