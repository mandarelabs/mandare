import { describe, expect, test } from 'vitest';

import { LLM_CALL_INTENT, LLM_CALL_RESULT } from '@mandarelabs/spec';

import { AsyncLedger } from '../src/async-ledger.js';
import {
  LLM_CALL_DENIED,
  ProjectionIntegrityError,
  dayKey,
  minuteKey,
  replaySpendCounters,
  spendProjector,
  totalKey,
} from '../src/projection.js';
import {
  readSpendSnapshot,
  rebuildSpendProjection,
  verifySpendProjection,
} from '../src/spend-ledger.js';
import { SqliteStore } from '../src/sqlite-store.js';
import { ProjectionStaleError } from '../src/store.js';
import { openSqliteDatabase } from '../src/sqlite-store.js';
import { sampleInput, tempDbPath } from './helpers.js';

/**
 * The budget projection is correctness-critical (R8: TDD, high coverage):
 * reservations must be atomic with the intent append, settlement must
 * release exactly the reservation, and the whole table must always equal a
 * fresh replay of the ledger.
 */

const MANDATE = 'mnd_projection_test';
const ACTOR = 'did:example:agent';

async function openLedger(): Promise<{ ledger: AsyncLedger; store: SqliteStore; dbPath: string }> {
  const dbPath = tempDbPath();
  const store = SqliteStore.open(dbPath);
  const ledger = await AsyncLedger.open(store, {
    doorId: 'gateway:test',
    keyPath: `${dbPath}.doorkey.pem`,
  });
  return { ledger, store, dbPath };
}

function intentInput(estimateMicros: number) {
  return sampleInput({
    mandate_id: MANDATE,
    actor: ACTOR,
    cost: { amount: estimateMicros, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
  });
}

function resultInput(intentHash: string, settledMicros: number) {
  return sampleInput({
    mandate_id: MANDATE,
    actor: ACTOR,
    action: {
      type: LLM_CALL_RESULT,
      target: 'openrouter.ai',
      request_hash: 'b'.repeat(64),
      response_hash: 'd'.repeat(64),
    },
    cost: { amount: settledMicros, currency: 'EUR', tokens_in: 10, tokens_out: 20 },
    outcome_ref: intentHash,
  });
}

async function reserve(ledger: AsyncLedger, estimateMicros: number) {
  return ledger.appendProjected(intentInput(estimateMicros), spendProjector());
}

describe('reserve → settle lifecycle', () => {
  test('an intent reserves its estimate; the paired result settles true cost', async () => {
    const { ledger, store } = await openLedger();

    const reserved = await ledger.appendProjected(intentInput(100_000), spendProjector());
    expect(reserved.kind).toBe('appended');
    const intent = reserved.kind === 'appended' ? reserved.entry : null;

    let snapshot = await readSpendSnapshot(store, {
      mandateId: MANDATE,
      actor: ACTOR,
      nowIso: intent?.ts ?? new Date().toISOString(),
    });
    expect(snapshot.day).toEqual({ reservedMicros: 100_000, settledMicros: 0, intents: 1 });
    expect(snapshot.total.reservedMicros).toBe(100_000);
    expect(snapshot.minuteIntents).toBe(1);

    const settled = await ledger.appendProjected(
      resultInput(intent?.entry_hash ?? '', 80_000),
      spendProjector()
    );
    expect(settled.kind).toBe('appended');

    snapshot = await readSpendSnapshot(store, {
      mandateId: MANDATE,
      actor: ACTOR,
      nowIso: intent?.ts ?? new Date().toISOString(),
    });
    expect(snapshot.day).toEqual({ reservedMicros: 0, settledMicros: 80_000, intents: 1 });
    expect(snapshot.total).toEqual({ reservedMicros: 0, settledMicros: 80_000, intents: 1 });

    expect(await verifySpendProjection(store)).toMatchObject({ ok: true });
    await ledger.close();
  });

  test('a guard refusal aborts everything: no entry, no counter change', async () => {
    const { ledger, store } = await openLedger();
    await reserve(ledger, 100_000);

    const refused = await ledger.appendProjected(
      intentInput(1_000_000),
      spendProjector((view) =>
        view.day.reservedMicros + view.day.settledMicros + view.estimateMicros > 500_000
          ? { code: 'PER_DAY_EXCEEDED', reason: 'cap 0.50 EUR (test)' }
          : null
      )
    );
    expect(refused).toEqual({
      kind: 'refused',
      refusal: { code: 'PER_DAY_EXCEEDED', reason: 'cap 0.50 EUR (test)' },
    });

    // Nothing moved: head unchanged, counters unchanged, invariant intact.
    expect((await ledger.head())?.seq).toBe(1);
    const snapshot = await readSpendSnapshot(store, {
      mandateId: MANDATE,
      actor: ACTOR,
      nowIso: new Date().toISOString(),
    });
    expect(snapshot.total.reservedMicros).toBe(100_000);
    expect(await verifySpendProjection(store)).toMatchObject({ ok: true });
    await ledger.close();
  });

  test('open reservations count against the guard view (concurrent overshoot dies here)', async () => {
    const { ledger } = await openLedger();
    const guard = spendProjector((view) =>
      view.total.reservedMicros + view.total.settledMicros + view.estimateMicros > 250_000
        ? { code: 'TOTAL_CAP_EXCEEDED', reason: 'total cap (test)' }
        : null
    );
    expect((await ledger.appendProjected(intentInput(100_000), guard)).kind).toBe('appended');
    expect((await ledger.appendProjected(intentInput(100_000), guard)).kind).toBe('appended');
    // 200k reserved, nothing settled — the third 100k must refuse.
    expect((await ledger.appendProjected(intentInput(100_000), guard)).kind).toBe('refused');
    await ledger.close();
  });

  test('denied entries are recorded but have zero counter effect', async () => {
    const { ledger, store } = await openLedger();
    const denied = await ledger.appendProjected(
      sampleInput({
        mandate_id: MANDATE,
        actor: ACTOR,
        action: { type: LLM_CALL_DENIED, target: 'openrouter.ai', request_hash: 'b'.repeat(64) },
        cost: { amount: 999_000, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
      }),
      spendProjector()
    );
    expect(denied.kind).toBe('appended');
    const snapshot = await readSpendSnapshot(store, {
      mandateId: MANDATE,
      actor: ACTOR,
      nowIso: new Date().toISOString(),
    });
    expect(snapshot.total).toEqual({ reservedMicros: 0, settledMicros: 0, intents: 0 });
    expect(snapshot.minuteIntents).toBe(0);
    expect(await verifySpendProjection(store)).toMatchObject({ ok: true });
    await ledger.close();
  });
});

describe('fail-closed integrity', () => {
  test('a plain append leaves the projection stale — the next projected append refuses', async () => {
    const { ledger } = await openLedger();
    await reserve(ledger, 1000);
    await ledger.append(sampleInput()); // bypasses the projection on purpose
    await expect(reserve(ledger, 1000)).rejects.toThrow(ProjectionStaleError);
    await ledger.close();
  });

  test('rebuild restores a stale projection from the ledger alone', async () => {
    const { ledger, store } = await openLedger();
    const reserved = await reserve(ledger, 5000);
    const intentHash = reserved.kind === 'appended' ? reserved.entry.entry_hash : '';
    await ledger.append(resultInput(intentHash, 4000)); // plain append → stale
    expect(await verifySpendProjection(store)).toMatchObject({ ok: false });

    await rebuildSpendProjection(store);
    expect(await verifySpendProjection(store)).toMatchObject({ ok: true });
    const snapshot = await readSpendSnapshot(store, {
      mandateId: MANDATE,
      actor: ACTOR,
      nowIso: new Date().toISOString(),
    });
    expect(snapshot.total).toEqual({ reservedMicros: 0, settledMicros: 4000, intents: 1 });
    await ledger.close();
  });

  test('settling the same intent twice is refused (fail-closed)', async () => {
    const { ledger } = await openLedger();
    const reserved = await reserve(ledger, 5000);
    const intentHash = reserved.kind === 'appended' ? reserved.entry.entry_hash : '';
    await ledger.appendProjected(resultInput(intentHash, 4000), spendProjector());
    await expect(
      ledger.appendProjected(resultInput(intentHash, 4000), spendProjector())
    ).rejects.toThrow(ProjectionIntegrityError);
    await ledger.close();
  });

  test('a ZERO-cost settlement is still final — a second result cannot re-add spend', async () => {
    // Provider-error settlements are 0; the settled flag must not depend on
    // a positive amount, or a duplicate result would double-count silently
    // while replay stays "consistent".
    const { ledger } = await openLedger();
    const reserved = await reserve(ledger, 5000);
    const intentHash = reserved.kind === 'appended' ? reserved.entry.entry_hash : '';
    await ledger.appendProjected(resultInput(intentHash, 0), spendProjector());
    await expect(
      ledger.appendProjected(resultInput(intentHash, 4000), spendProjector())
    ).rejects.toThrow(ProjectionIntegrityError);
    await ledger.close();
  });

  test('a result for an unknown intent is refused (fail-closed)', async () => {
    const { ledger } = await openLedger();
    await expect(
      ledger.appendProjected(resultInput('e'.repeat(64), 4000), spendProjector())
    ).rejects.toThrow(ProjectionIntegrityError);
    await ledger.close();
  });

  test('tampered counters diverge from replay and are detected (red-team invariant)', async () => {
    const { ledger, store, dbPath } = await openLedger();
    const reserved = await reserve(ledger, 5000);
    const intentHash = reserved.kind === 'appended' ? reserved.entry.entry_hash : '';
    await ledger.appendProjected(resultInput(intentHash, 5000), spendProjector());

    // Attacker resets the settled spend to reopen the budget.
    const db = openSqliteDatabase(dbPath);
    db.exec(`UPDATE budget_counters SET settled_micros = 0 WHERE scope_key = '${totalKey(MANDATE)}'`);
    db.close();

    const verdict = await verifySpendProjection(store);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) {
      expect(verdict.divergences.map((d) => d.key)).toContain(totalKey(MANDATE));
    }
    await ledger.close();
  });

  test('tampering CANNOT be disguised as staleness by also rewinding the projection seq', async () => {
    // The evidence-preservation control (divergence → refuse, don't rebuild)
    // must not be selectable by an attacker who rewinds projection_meta.
    const { ledger, store, dbPath } = await openLedger();
    const reserved = await reserve(ledger, 5000);
    const intentHash = reserved.kind === 'appended' ? reserved.entry.entry_hash : '';
    await ledger.appendProjected(resultInput(intentHash, 5000), spendProjector());

    const db = openSqliteDatabase(dbPath);
    db.exec(`UPDATE budget_counters SET settled_micros = 0 WHERE scope_key = '${totalKey(MANDATE)}'`);
    // …and rewind the projection seq, trying to make it look merely stale.
    db.exec(`UPDATE projection_meta SET value = 0 WHERE key = 'spend_projection_seq'`);
    db.close();

    const verdict = await verifySpendProjection(store);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) {
      // Divergence is still reported (not silently swallowed as staleness).
      expect(verdict.divergences.map((d) => d.key)).toContain(totalKey(MANDATE));
    }
    await ledger.close();
  });
});

describe('replay semantics', () => {
  test('settlement lands in the INTENT day bucket — midnight cannot reopen a cap', async () => {
    const baseIntent = {
      schema_version: 1,
      seq: 1,
      ts: '2026-07-21T23:59:30.000Z',
      door_id: 'gateway:test',
      actor: ACTOR,
      mandate_id: MANDATE,
      action: { type: LLM_CALL_INTENT, target: 'api.example', request_hash: 'b'.repeat(64) },
      cost: { amount: 7000, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
      salt: 'c'.repeat(32),
      prev_hash: '0'.repeat(64),
      entry_hash: 'a'.repeat(64),
      door_signature: { alg: 'EdDSA', key_id: 'f'.repeat(64), key_provenance: 'software', value: 'x' },
    };
    const result = {
      ...baseIntent,
      seq: 2,
      ts: '2026-07-22T00:00:10.000Z',
      action: {
        type: LLM_CALL_RESULT,
        target: 'api.example',
        request_hash: 'b'.repeat(64),
        response_hash: 'd'.repeat(64),
      },
      cost: { amount: 6500, currency: 'EUR', tokens_in: 1, tokens_out: 2 },
      outcome_ref: 'a'.repeat(64),
      entry_hash: 'b'.repeat(64),
    };
    const counters = await replaySpendCounters([baseIntent, result]);
    expect(counters.get(dayKey(MANDATE, baseIntent.ts))).toEqual({
      reservedMicros: 0,
      settledMicros: 6500,
      intents: 1,
    });
    expect(counters.has(dayKey(MANDATE, result.ts))).toBe(false);
    expect(counters.get(minuteKey(ACTOR, baseIntent.ts))?.intents).toBe(1);
  });

  test('scope keys survive hostile ids (no delimiter collisions)', () => {
    expect(dayKey('mnd|day:2026-01-01', '2026-07-21T00:00:00Z')).not.toBe(
      dayKey('mnd', '2026-01-01T00:00:00Z')
    );
  });
});
