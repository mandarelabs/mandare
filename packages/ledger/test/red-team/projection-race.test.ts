import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import EmbeddedPostgres from 'embedded-postgres';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';

import { LLM_CALL_INTENT, LLM_CALL_RESULT } from '@mandarelabs/spec';

import { AsyncLedger } from '../../src/async-ledger.js';
import { PgStore, provisionPgLedger } from '../../src/pg-store.js';
import { SqliteStore } from '../../src/sqlite-store.js';
import { spendProjector, totalKey, type SpendGuard } from '../../src/projection.js';
import { rebuildSpendProjection, verifySpendProjection } from '../../src/spend-ledger.js';
import { ProjectionStaleError } from '../../src/store.js';
import type { AppendInput } from '../../src/entry.js';

/**
 * RED-TEAM (R5): the budget-race attack at the DRIVER level, on BOTH stores.
 * The gateway-level race test proves the HTTP path; this one proves the
 * mechanism itself: reservations run under the store's append lock, so
 * N concurrent reservations against a cap admit EXACTLY floor(cap/estimate)
 * intents — an overshoot is structurally impossible, not just unlikely.
 *
 * Plus the projection-integrity invariant on Postgres: replay(ledger) ==
 * counters; tampered counters and stale projections are detected and fail
 * closed (the strategy frame for S2).
 */

const CAP = 1_000_000; // 1 unit cap
const ESTIMATE = 90_000; // 11 fit (990k), the 12th would cross

const capGuard: SpendGuard = (view) =>
  view.total.reservedMicros + view.total.settledMicros + view.estimateMicros > CAP
    ? { code: 'TOTAL_CAP_EXCEEDED', reason: 'red-team cap' }
    : null;

function intentInput(): AppendInput {
  return {
    actor: 'did:example:agent',
    mandate_id: 'mnd_race',
    action: { type: LLM_CALL_INTENT, target: 'api.example', request_hash: 'b'.repeat(64) },
    cost: { amount: ESTIMATE, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
  };
}

async function raceReservations(ledger: AsyncLedger, attempts: number) {
  const results = await Promise.all(
    Array.from({ length: attempts }, () =>
      ledger.appendProjected(intentInput(), spendProjector(capGuard))
    )
  );
  return {
    appended: results.filter((result) => result.kind === 'appended').length,
    refused: results.filter((result) => result.kind === 'refused').length,
  };
}

describe('budget race — SQLite driver', () => {
  test('40 concurrent reservations admit exactly floor(cap/estimate)', async () => {
    const dbPath = join(mkdtempSync(join(tmpdir(), 'mandare-race-')), 'ledger.db');
    const store = SqliteStore.open(dbPath);
    const ledger = await AsyncLedger.open(store, {
      doorId: 'gateway:race-test',
      keyPath: `${dbPath}.doorkey.pem`,
    });
    const { appended, refused } = await raceReservations(ledger, 40);
    expect(appended).toBe(Math.floor(CAP / ESTIMATE)); // 11 — exactly, always
    expect(refused).toBe(40 - appended);
    expect(await verifySpendProjection(ledger)).toMatchObject({ ok: true });
    await ledger.close();
  });
});

describe('budget race + projection integrity — Postgres driver', () => {
  const APP_ROLE = 'mandare_race_app';
  const APP_PASSWORD = 'red-team-race-pw';
  const PORT = 55640 + (process.pid % 100);

  let embedded: InstanceType<typeof EmbeddedPostgres>;
  let adminUrl: string;
  let ledger: AsyncLedger;
  let store: PgStore;

  beforeAll(async () => {
    const workDir = mkdtempSync(join(tmpdir(), 'mandare-pg-race-'));
    embedded = new EmbeddedPostgres({
      databaseDir: join(workDir, 'pgdata'),
      user: 'postgres',
      password: 'postgres',
      port: PORT,
      persistent: false,
    });
    await embedded.initialise();
    await embedded.start();
    adminUrl = `postgresql://postgres:postgres@127.0.0.1:${PORT}/postgres`;
    const admin = new pg.Client({ connectionString: adminUrl });
    await admin.connect();
    await admin.query(`CREATE ROLE ${APP_ROLE} LOGIN PASSWORD '${APP_PASSWORD}'`);
    await admin.end();
    await provisionPgLedger(adminUrl, { appRole: APP_ROLE });
    store = PgStore.connect(
      `postgresql://${APP_ROLE}:${APP_PASSWORD}@127.0.0.1:${PORT}/postgres`
    );
    ledger = await AsyncLedger.open(store, {
      doorId: 'gateway:pg-race-test',
      keyPath: join(workDir, 'door.pem'),
    });
  }, 120_000);

  afterAll(async () => {
    await ledger?.close();
    // Give client sockets a beat to settle before the server stops (S1 lesson).
    await new Promise((resolve) => setTimeout(resolve, 200));
    await embedded?.stop();
  }, 60_000);

  test('40 concurrent reservations admit exactly floor(cap/estimate)', async () => {
    const { appended, refused } = await raceReservations(ledger, 40);
    expect(appended).toBe(Math.floor(CAP / ESTIMATE));
    expect(refused).toBe(40 - appended);
    expect(await verifySpendProjection(ledger)).toMatchObject({ ok: true });
  }, 60_000);

  test('reserve → settle keeps replay(ledger) == counters across drivers', async () => {
    const reserved = await ledger.appendProjected(
      {
        actor: 'did:example:agent',
        mandate_id: 'mnd_settle',
        action: { type: LLM_CALL_INTENT, target: 'api.example', request_hash: 'c'.repeat(64) },
        cost: { amount: 50_000, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
      },
      spendProjector()
    );
    expect(reserved.kind).toBe('appended');
    const intentHash = reserved.kind === 'appended' ? reserved.entry.entry_hash : '';
    const settled = await ledger.appendProjected(
      {
        actor: 'did:example:agent',
        mandate_id: 'mnd_settle',
        action: {
          type: LLM_CALL_RESULT,
          target: 'api.example',
          request_hash: 'c'.repeat(64),
          response_hash: 'd'.repeat(64),
        },
        cost: { amount: 42_000, currency: 'EUR', tokens_in: 5, tokens_out: 9 },
        outcome_ref: intentHash,
      },
      spendProjector()
    );
    expect(settled.kind).toBe('appended');
    expect(await verifySpendProjection(ledger)).toMatchObject({ ok: true });
  }, 30_000);

  test('counter tampering (admin UPDATE) is detected by the replay invariant — fail closed + alert', async () => {
    const admin = new pg.Client({ connectionString: adminUrl });
    await admin.connect();
    await admin.query(`UPDATE budget_counters SET settled_micros = 0 WHERE scope_key = $1`, [
      totalKey('mnd_settle'),
    ]);
    await admin.end();

    const verdict = await verifySpendProjection(ledger);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) {
      expect(verdict.divergences.map((d) => d.key)).toContain(totalKey('mnd_settle'));
    }
    // Recovery is explicit, from the ledger alone.
    await rebuildSpendProjection(ledger);
    expect(await verifySpendProjection(ledger)).toMatchObject({ ok: true });
  }, 30_000);

  test('a projection left stale by an unprojected append refuses reservations (fail closed)', async () => {
    await ledger.append(intentInput()); // plain append bypasses the projection
    await expect(
      ledger.appendProjected(intentInput(), spendProjector(capGuard))
    ).rejects.toThrow(ProjectionStaleError);
    await rebuildSpendProjection(ledger);
    expect(await verifySpendProjection(ledger)).toMatchObject({ ok: true });
  }, 30_000);
});
