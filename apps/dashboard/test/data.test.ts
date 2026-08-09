import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  AsyncLedger,
  SqliteStore,
  AGENT_REVOKE,
  LLM_CALL_DENIED,
  agentSubject,
  revocationProjector,
  spendProjector,
} from '@mandarelabs/ledger';
import { LLM_CALL_INTENT, LLM_CALL_RESULT } from '@mandarelabs/spec';

import { readApprovals, readSnapshot, readTrail } from '../src/lib/data';

/**
 * The dashboard's read layer against a REAL ledger — same store, same
 * projections the door writes. If the ledger schema or projection keys move,
 * this fails before a user sees a wrong fleet view.
 */

const AGENT = 'did:mandare:test-agent';
const MANDATE = 'mnd_dash_test';

describe('dashboard data layer over a real ledger', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mandare-dash-'));
  const dbPath = join(dir, 'ledger.db');
  let intentHash = '';

  beforeAll(async () => {
    const store = SqliteStore.open(dbPath);
    const ledger = await AsyncLedger.open(store, {
      doorId: 'gateway:dash-test',
      keyPath: `${dbPath}.doorkey.pem`,
    });
    const spend = spendProjector();
    const revocation = revocationProjector();

    const intent = await ledger.appendProjected(
      {
        actor: AGENT,
        mandate_id: MANDATE,
        action: { type: LLM_CALL_INTENT, target: 'anthropic:/v1/messages', request_hash: 'a'.repeat(64) },
        cost: { amount: 500_000, currency: 'EUR', tokens_in: 10, tokens_out: 0 },
      },
      spend
    );
    if (intent.kind !== 'appended') throw new Error('intent append refused');
    intentHash = intent.entry.entry_hash;

    const result = await ledger.appendProjected(
      {
        actor: AGENT,
        mandate_id: MANDATE,
        action: { type: LLM_CALL_RESULT, target: 'anthropic:/v1/messages', request_hash: 'a'.repeat(64) },
        cost: { amount: 300_000, currency: 'EUR', tokens_in: 10, tokens_out: 900 },
        outcome_ref: intentHash,
      },
      spend
    );
    if (result.kind !== 'appended') throw new Error('result append refused');

    const denied = await ledger.appendProjected(
      {
        actor: AGENT,
        mandate_id: MANDATE,
        action: { type: LLM_CALL_DENIED, target: 'anthropic:/v1/messages', request_hash: 'b'.repeat(64) },
        cost: { amount: 700_000, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
      },
      spend
    );
    if (denied.kind !== 'appended') throw new Error('denied append refused');

    const revoke = await ledger.appendProjected(
      {
        actor: 'mandare:operator',
        mandate_id: 'mandare:kill',
        action: { type: AGENT_REVOKE, target: agentSubject(AGENT), request_hash: 'c'.repeat(64) },
        cost: { amount: 0, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
      },
      revocation
    );
    if (revoke.kind !== 'appended') throw new Error('revoke append refused');

    await ledger.close();
  });

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('snapshot: agents, spend, refusals, revocation state', () => {
    const snapshot = readSnapshot(dbPath);
    expect(snapshot).not.toBeNull();
    expect(snapshot?.entryCount).toBe(4);
    expect(snapshot?.doorId).toBe('gateway:dash-test');

    const agent = snapshot?.agents.find((row) => row.actor === AGENT);
    expect(agent).toBeDefined();
    expect(agent?.settledMicros).toBe(300_000);
    expect(agent?.refusals).toBe(1);
    expect(agent?.revoked).toBe(true);

    const mandate = snapshot?.mandates.find((row) => row.mandateId === MANDATE);
    expect(mandate).toBeDefined();
    expect(mandate?.totalSettledMicros).toBe(300_000);
    // The intent's reservation was released on settlement.
    expect(mandate?.totalReservedMicros).toBe(0);
    expect(snapshot?.revokedSubjects.map((s) => s.subject)).toContain(agentSubject(AGENT));
  });

  it('trail: newest-first, typed rows, pagination boundary', () => {
    const rows = readTrail(dbPath, 10);
    expect(rows).toHaveLength(4);
    expect(rows[0]?.actionType).toBe(AGENT_REVOKE);
    expect(rows[3]?.actionType).toBe(LLM_CALL_INTENT);
    expect(rows[3]?.entryHash).toBe(intentHash);

    const page = readTrail(dbPath, 10, rows[0]?.seq);
    expect(page).toHaveLength(3);
    expect(page.every((row) => row.seq < (rows[0]?.seq ?? 0))).toBe(true);
  });

  it('approvals: empty on a ledger without approval entries', () => {
    expect(readApprovals(dbPath)).toHaveLength(0);
  });

  it('missing DB → null snapshot, empty trail (no throw)', () => {
    expect(readSnapshot(join(dir, 'nope.db'))).toBeNull();
    expect(readTrail(join(dir, 'nope.db'))).toHaveLength(0);
  });
});
