import { mkdtempSync, rmSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
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

describe('W-3: the dashboard renders the verified reading, never a second parser\'s', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mandare-dash-w3-'));
  const dbPath = join(dir, 'ledger.db');

  beforeAll(async () => {
    const store = SqliteStore.open(dbPath);
    const ledger = await AsyncLedger.open(store, { doorId: 'gateway:dash-w3', keyPath: `${dbPath}.doorkey.pem` });
    for (let i = 0; i < 3; i += 1) {
      await ledger.append({
        actor: AGENT,
        mandate_id: MANDATE,
        action: { type: LLM_CALL_RESULT, target: 'anthropic:/v1/messages', request_hash: 'd'.repeat(64) },
        cost: { amount: 1_000, currency: 'EUR', tokens_in: 1, tokens_out: 1 },
      });
    }
    await ledger.close();
    // File-level attacker (no key): drop the storage locks, prepend forged
    // duplicate keys to seq 2. json_extract (first key wins) would render
    // them; JSON.parse — what `mandare verify` hashes — would not.
    const db = new DatabaseSync(dbPath);
    for (const { name } of db.prepare("SELECT name FROM sqlite_master WHERE type = 'trigger'").all() as {
      name: string;
    }[]) {
      db.exec(`DROP TRIGGER "${name}";`);
    }
    const { entry_json } = db.prepare('SELECT entry_json FROM ledger_entries WHERE seq = 2').get() as {
      entry_json: string;
    };
    db.prepare('UPDATE ledger_entries SET entry_json = ? WHERE seq = 2').run(
      `{"actor":"did:example:forged","cost":{"amount":999000000,"currency":"EUR","tokens_in":0,"tokens_out":0},${entry_json.slice(1)}`
    );
    db.close();
  });

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('trail: the forged row is flagged as a storage mismatch, its forged fields never shown', () => {
    const rows = readTrail(dbPath, 10);
    expect(rows).toHaveLength(3);
    const forged = rows.find((row) => row.seq === 2);
    expect(forged?.storageOk).toBe(false);
    expect(forged?.actor).not.toBe('did:example:forged');
    expect(forged?.amountMicros).toBe(0);
    expect(rows.filter((row) => row.storageOk)).toHaveLength(2);
  });

  it('snapshot: the forged actor and amount never reach the fleet view; the mismatch is counted', () => {
    const snapshot = readSnapshot(dbPath);
    expect(snapshot?.agents.map((row) => row.actor)).not.toContain('did:example:forged');
    expect(snapshot?.agents.find((row) => row.actor === AGENT)?.settledMicros).toBe(2_000);
    expect(snapshot?.unreadableRows).toBe(1);
  });
});
