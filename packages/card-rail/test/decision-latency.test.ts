import { describe, expect, it } from 'vitest';

import { authorizationEvent, openTestRail, postWebhook } from './helpers.js';

/**
 * Q11: Stripe expects the authorization answer within 2 seconds — timeout
 * falls back to the dashboard default (which docs/CARD-RAIL.md requires to
 * be DECLINE). The decision path is fully local (HMAC verify → projection
 * reads → two fsync'd appends), so p99 should sit orders of magnitude under
 * the budget. The 500ms assertion is deliberately loose for slow CI
 * machines; the real numbers are recorded in TASKS.md.
 */
describe('authorization decision latency', () => {
  it('p99 stays well under the 2s webhook budget', async () => {
    const rail = await openTestRail({ cards: ['ic_1'] });
    try {
      const N = 200;
      const durationsMs: number[] = [];
      for (let index = 0; index < N; index += 1) {
        // €0.01 each — 200 × €0.01 = €2 stays far inside every cap.
        const started = process.hrtime.bigint();
        const response = await postWebhook(
          rail.app,
          authorizationEvent({ authorizationId: `iauth_bench_${index}`, cardId: 'ic_1', amountMinorUnits: 1 })
        );
        durationsMs.push(Number(process.hrtime.bigint() - started) / 1e6);
        expect((response.json() as { approved: boolean }).approved).toBe(true);
      }
      const sorted = [...durationsMs].sort((a, b) => a - b);
      const p50 = sorted[Math.floor(N * 0.5)] as number;
      const p99 = sorted[Math.floor(N * 0.99)] as number;
      // eslint-disable-next-line no-console
      console.log(`card decision latency over ${N} auths: p50=${p50.toFixed(2)}ms p99=${p99.toFixed(2)}ms`);
      expect(p99).toBeLessThan(500);
    } finally {
      await rail.close();
    }
  });
});
