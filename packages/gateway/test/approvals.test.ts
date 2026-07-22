import { describe, expect, test } from 'vitest';

import {
  APPROVAL_DENIED,
  APPROVAL_EXPIRED,
  APPROVAL_GRANTED,
  APPROVAL_REQUESTED,
  LLM_CALL_DENIED,
  readLedger,
} from '@mandarelabs/ledger';
import { LLM_CALL_RESULT, type LedgerEntryV1 } from '@mandarelabs/spec';

import {
  MockNotifier,
  anthropicBody,
  anthropicOkFetch,
  openTestGateway,
  testMandate,
} from './helpers.js';

/**
 * The S4 approval flow: an over-threshold call is HELD, the push carries
 * Approve/Deny capability tokens, the decision lands as a ledger entry, and
 * the held call resumes or is refused. Every exit is fail-closed.
 */

// €0.20 threshold, well under the €5 per-tx cap: the call passes budgets and
// trips ONLY the approval rule (SPEC §5 order: budget → counterparty → approval).
const approvalMandate = testMandate({
  approvals: { rules: [{ above: 200_000, currency: 'EUR', method: 'push' }] },
});
// haiku @ $5/M output: 60k max_tokens ⇒ ~$0.30 estimate — above €0.20.
const bigCall = { ...anthropicBody, max_tokens: 60_000 };

function entriesOfType(dbPath: string, type: string): LedgerEntryV1[] {
  const { entries } = readLedger(dbPath);
  return (entries as LedgerEntryV1[]).filter((entry) => entry.action.type === type);
}

describe('approval flow (held call → push → decision → ledger)', () => {
  test('approve: the held call proceeds and the whole trail is on the ledger', async () => {
    const notifier = new MockNotifier();
    const gw = await openTestGateway({
      mandate: approvalMandate,
      notifier,
      fetchImpl: anthropicOkFetch({ input_tokens: 10, output_tokens: 20 }),
    });
    try {
      const held = gw.app.inject({ method: 'POST', url: '/v1/messages', payload: bigCall });
      const push = await notifier.next();
      expect(push.title).toContain('approve');

      const decision = await gw.app.inject({
        method: 'POST',
        url: push.approveUrl.slice(push.approveUrl.indexOf('/approvals')),
        payload: JSON.parse(push.approveBody),
      });
      expect(decision.statusCode).toBe(200);
      expect(decision.json()).toEqual({ ok: true, decision: 'approved' });

      const response = await held;
      expect(response.statusCode).toBe(200);

      const requested = entriesOfType(gw.dbPath, APPROVAL_REQUESTED);
      const granted = entriesOfType(gw.dbPath, APPROVAL_GRANTED);
      const results = entriesOfType(gw.dbPath, LLM_CALL_RESULT);
      expect(requested).toHaveLength(1);
      expect(granted).toHaveLength(1);
      expect(granted[0]?.outcome_ref).toBe(requested[0]?.entry_hash);
      // The human decision is attributed to the accountable principal.
      expect(granted[0]?.actor).toBe(approvalMandate.principal);
      expect(results).toHaveLength(1);
    } finally {
      await gw.close();
    }
  });

  test('deny: refusal lands as approval.denied + llm.call.denied', async () => {
    const notifier = new MockNotifier();
    const gw = await openTestGateway({
      mandate: approvalMandate,
      notifier,
      fetchImpl: anthropicOkFetch({ input_tokens: 10, output_tokens: 20 }),
    });
    try {
      const held = gw.app.inject({ method: 'POST', url: '/v1/messages', payload: bigCall });
      const push = await notifier.next();
      const decision = await gw.app.inject({
        method: 'POST',
        url: `/approvals/${push.approvalId}`,
        payload: JSON.parse(push.denyBody),
      });
      expect(decision.json()).toEqual({ ok: true, decision: 'denied' });

      const response = await held;
      expect(response.statusCode).toBe(403);
      expect(response.json().code).toBe('APPROVAL_DENIED');

      expect(entriesOfType(gw.dbPath, APPROVAL_DENIED)).toHaveLength(1);
      expect(entriesOfType(gw.dbPath, LLM_CALL_DENIED)).toHaveLength(1);
      expect(entriesOfType(gw.dbPath, LLM_CALL_RESULT)).toHaveLength(0);
    } finally {
      await gw.close();
    }
  });

  test('timeout: no decision ⇒ fail-closed refusal with approval.expired on the ledger', async () => {
    const notifier = new MockNotifier();
    const gw = await openTestGateway({
      config: { approvalTimeoutMs: 250 },
      mandate: approvalMandate,
      notifier,
      fetchImpl: anthropicOkFetch({ input_tokens: 10, output_tokens: 20 }),
    });
    try {
      const response = await gw.app.inject({ method: 'POST', url: '/v1/messages', payload: bigCall });
      expect(response.statusCode).toBe(403);
      expect(response.json().code).toBe('APPROVAL_TIMEOUT');
      expect(entriesOfType(gw.dbPath, APPROVAL_EXPIRED)).toHaveLength(1);
      expect(entriesOfType(gw.dbPath, LLM_CALL_RESULT)).toHaveLength(0);
    } finally {
      await gw.close();
    }
  });

  test('no notifier configured: over-threshold denies outright (S2 behavior preserved)', async () => {
    const gw = await openTestGateway({
      mandate: approvalMandate,
      fetchImpl: anthropicOkFetch({ input_tokens: 10, output_tokens: 20 }),
    });
    try {
      const response = await gw.app.inject({ method: 'POST', url: '/v1/messages', payload: bigCall });
      expect(response.statusCode).toBe(403);
      expect(response.json().code).toBe('APPROVAL_REQUIRED');
      expect(entriesOfType(gw.dbPath, APPROVAL_REQUESTED)).toHaveLength(0);
    } finally {
      await gw.close();
    }
  });

  test('failed push: the call is refused, never silently held (fail-closed)', async () => {
    const notifier = new MockNotifier();
    notifier.failNext = true;
    const gw = await openTestGateway({
      mandate: approvalMandate,
      notifier,
      fetchImpl: anthropicOkFetch({ input_tokens: 10, output_tokens: 20 }),
    });
    try {
      const response = await gw.app.inject({ method: 'POST', url: '/v1/messages', payload: bigCall });
      expect(response.statusCode).toBe(403);
      expect(response.json().code).toBe('APPROVAL_PUSH_FAILED');
    } finally {
      await gw.close();
    }
  });

  test('in-scope small calls never touch the approval machinery', async () => {
    const notifier = new MockNotifier();
    const gw = await openTestGateway({
      mandate: approvalMandate,
      notifier,
      fetchImpl: anthropicOkFetch({ input_tokens: 10, output_tokens: 20 }),
    });
    try {
      const response = await gw.app.inject({
        method: 'POST',
        url: '/v1/messages',
        payload: anthropicBody, // 100 max_tokens ⇒ well under €0.20
      });
      expect(response.statusCode).toBe(200);
      expect(notifier.notifications).toHaveLength(0);
      expect(entriesOfType(gw.dbPath, APPROVAL_REQUESTED)).toHaveLength(0);
    } finally {
      await gw.close();
    }
  });
});
