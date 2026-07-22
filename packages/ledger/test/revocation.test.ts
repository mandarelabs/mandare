import { DatabaseSync } from 'node:sqlite';

import { afterEach, beforeEach, describe, expect, test } from 'vitest';

import { LLM_CALL_INTENT } from '@mandarelabs/spec';

import { AsyncLedger } from '../src/async-ledger.js';
import { SqliteStore } from '../src/sqlite-store.js';
import { spendProjector } from '../src/projection.js';
import {
  AGENT_REINSTATE,
  AGENT_REVOKE,
  SUBJECT_REGISTER,
  agentSubject,
  mandateSubject,
  revocationProjector,
} from '../src/revocation.js';
import {
  isSubjectRevoked,
  listRevocations,
  rebuildRevocationProjection,
  verifyRevocationProjection,
} from '../src/revocation-ledger.js';
import { verifySpendProjection } from '../src/spend-ledger.js';
import { tempDbPath } from './helpers.js';

/**
 * The kill switch as a ledger projection: agent.revoke / agent.reinstate
 * entries drive a subject-keyed revocation table, verifiable against a fresh
 * replay — exactly the tamper-evidence guarantee the spend counters carry.
 */
describe('revocation projection', () => {
  let dbPath: string;
  let store: SqliteStore;
  let ledger: AsyncLedger;

  beforeEach(async () => {
    dbPath = tempDbPath();
    store = SqliteStore.open(dbPath);
    ledger = await AsyncLedger.open(store, { doorId: 'gateway:test', keyPath: `${dbPath}.key.pem` });
  });
  afterEach(async () => {
    await ledger.close();
  });

  function revokeInput(subject: string, type: string = AGENT_REVOKE) {
    return {
      actor: 'did:mandare:killer',
      mandate_id: 'mnd_kill',
      action: { type, target: subject, request_hash: 'c'.repeat(64) },
      cost: { amount: 0, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
    };
  }

  function spendIntent(estimate: number) {
    return {
      actor: 'did:mandare:agent',
      mandate_id: 'mnd_spend',
      action: { type: LLM_CALL_INTENT, target: 'api.anthropic.com', request_hash: 'd'.repeat(64) },
      cost: { amount: estimate, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
    };
  }

  test('a revoke entry marks the subject revoked; the gateway check sees it', async () => {
    const subject = agentSubject('did:mandare:agent-x');
    expect(await isSubjectRevoked(ledger, subject)).toBe(false);
    await ledger.appendProjected(revokeInput(subject), revocationProjector());
    expect(await isSubjectRevoked(ledger, subject)).toBe(true);
  });

  test('reinstate reverses a kill and reuses the same status index', async () => {
    const subject = agentSubject('did:mandare:agent-y');
    await ledger.appendProjected(revokeInput(subject), revocationProjector());
    const afterRevoke = await listRevocations(ledger);
    const indexBefore = afterRevoke[0]?.statusIndex;
    await ledger.appendProjected(revokeInput(subject, AGENT_REINSTATE), revocationProjector());
    expect(await isSubjectRevoked(ledger, subject)).toBe(false);
    const afterReinstate = await listRevocations(ledger);
    expect(afterReinstate[0]?.statusIndex).toBe(indexBefore);
  });

  test('status indices are assigned in ledger order', async () => {
    await ledger.appendProjected(revokeInput(agentSubject('a')), revocationProjector());
    await ledger.appendProjected(revokeInput(agentSubject('b')), revocationProjector());
    const records = await listRevocations(ledger);
    expect(records.map((r) => [r.subject, r.statusIndex])).toEqual([
      ['agent:a', 0],
      ['agent:b', 1],
    ]);
  });

  test('spend and revocation projections do not interfere across a shared seq', async () => {
    // Interleave a spend intent and a kill; each projection stays correct.
    await ledger.appendProjected(spendIntent(500_000), spendProjector());
    await ledger.appendProjected(revokeInput(agentSubject('victim')), revocationProjector());
    await ledger.appendProjected(spendIntent(500_000), spendProjector());

    expect((await verifySpendProjection(ledger)).ok).toBe(true);
    expect((await verifyRevocationProjection(ledger)).ok).toBe(true);
    expect(await isSubjectRevoked(ledger, agentSubject('victim'))).toBe(true);
  });

  test('verify holds after a revoke, and rebuild reproduces the projection', async () => {
    await ledger.appendProjected(revokeInput(agentSubject('one')), revocationProjector());
    await ledger.appendProjected(revokeInput(agentSubject('two')), revocationProjector());
    expect((await verifyRevocationProjection(ledger)).ok).toBe(true);

    await rebuildRevocationProjection(ledger);
    const verdict = await verifyRevocationProjection(ledger);
    expect(verdict.ok).toBe(true);
    if (verdict.ok) expect(verdict.subjects).toBe(2);
  });

  test('subject.register allocates an index at issuance without revoking (S4)', async () => {
    const subject = mandateSubject('mnd_registered');
    await ledger.appendProjected(revokeInput(subject, SUBJECT_REGISTER), revocationProjector());
    expect(await isSubjectRevoked(ledger, subject)).toBe(false);
    const records = await listRevocations(ledger);
    expect(records).toHaveLength(1);
    expect(records[0]?.statusIndex).toBe(0);
    // A later kill flips the SAME slot — one vocabulary, stable index.
    await ledger.appendProjected(revokeInput(subject), revocationProjector());
    expect(await isSubjectRevoked(ledger, subject)).toBe(true);
    expect((await listRevocations(ledger))[0]?.statusIndex).toBe(0);
    expect((await verifyRevocationProjection(ledger)).ok).toBe(true);
  });

  test('re-registering a revoked subject NEVER reinstates it', async () => {
    const subject = agentSubject('did:mandare:sneaky');
    await ledger.appendProjected(revokeInput(subject, SUBJECT_REGISTER), revocationProjector());
    await ledger.appendProjected(revokeInput(subject), revocationProjector());
    await ledger.appendProjected(revokeInput(subject, SUBJECT_REGISTER), revocationProjector());
    expect(await isSubjectRevoked(ledger, subject)).toBe(true);
    // Replay must agree (rebuild determinism with registration in the mix).
    await rebuildRevocationProjection(ledger);
    expect(await isSubjectRevoked(ledger, subject)).toBe(true);
    expect((await verifyRevocationProjection(ledger)).ok).toBe(true);
  });

  test('tampering with the revocation table is caught by the replay invariant', async () => {
    const subject = agentSubject('tampered');
    await ledger.appendProjected(revokeInput(subject), revocationProjector());
    await ledger.close();

    // Attacker flips a killed agent back to "not revoked" in the projection.
    const db = new DatabaseSync(dbPath);
    db.exec('UPDATE revocation_status SET revoked = 0;');
    db.close();

    store = SqliteStore.open(dbPath);
    ledger = await AsyncLedger.open(store, { doorId: 'gateway:test', keyPath: `${dbPath}.key.pem` });
    const verdict = await verifyRevocationProjection(ledger);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.divergences.length).toBe(1);
  });
});
