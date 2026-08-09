import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, test } from 'vitest';

import { Ledger, loadOrCreateDoorKey } from '@mandarelabs/ledger';
import { buildWitnessServer, type WitnessServer } from '@mandarelabs/witness';
import { MockAnchor, WitnessClient } from '@mandarelabs/witness-protocol';

import { WitnessGate } from '../src/witness-gate.js';

/**
 * Witness-ack latency benchmark (S6 exit criterion): the gate adds ONE
 * round trip — read hashes → tree head → signed submission → verified ack —
 * on top of the card rail's benched ~1ms decision path. Against a local
 * witness it must sit far inside Stripe's 2s budget (Q11), with headroom
 * for a same-region remote witness (network RTT adds on top; a ~10–50ms
 * WAN hop still leaves >20× margin).
 *
 * Realistic shape: the ledger GROWS by one entry before every gated ack
 * (an intent precedes each gate check), so each sync carries a real
 * consistency proof.
 */

const ITERATIONS = 200;
const SEED_ENTRIES = 500;

let witness: WitnessServer;
let ledger: Ledger;
let gate: WitnessGate;

beforeAll(async () => {
  const dir = mkdtempSync(join(tmpdir(), 'mandare-witness-bench-'));
  const key = loadOrCreateDoorKey(join(dir, 'witness.pem'));
  witness = await buildWitnessServer({
    dbPath: join(dir, 'witness.db'),
    key,
    anchor: new MockAnchor(),
  });
  const url = await witness.app.listen({ host: '127.0.0.1', port: 0 });

  ledger = Ledger.open(join(dir, 'ledger.db'), { doorId: 'gateway:bench' });
  for (let i = 0; i < SEED_ENTRIES; i += 1) {
    ledger.append({
      actor: 'did:example:agent',
      mandate_id: 'mnd_bench',
      action: { type: 'llm.call.intent', target: 'api.example.com', request_hash: 'b'.repeat(64) },
      cost: { amount: 1, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
    });
  }
  const client = new WitnessClient({
    url,
    signer: ledger.signer(),
    readEntryHashes: () => Promise.resolve(ledger.entryHashes()),
    witnessPublicKeyHex: key.publicKeyHex,
  });
  await client.sync(); // baseline witnessed head
  gate = new WitnessGate({
    client,
    ackMode: 'all',
    ackTimeoutMs: 2_000,
    ledgerCurrency: 'EUR',
  });
}, 60_000);

afterAll(async () => {
  ledger.close();
  await witness.close();
});

describe('witness-ack gating latency (lock 5 vs the 2s card budget)', () => {
  test(`${ITERATIONS} gated acks with per-ack ledger growth stay far under budget`, async () => {
    const samples: number[] = [];
    for (let i = 0; i < ITERATIONS; i += 1) {
      ledger.append({
        actor: 'did:example:agent',
        mandate_id: 'mnd_bench',
        action: { type: 'card.auth.intent', target: `iauth_${i}`, request_hash: 'c'.repeat(64) },
        cost: { amount: 100, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
      });
      const started = performance.now();
      const verdict = await gate.requireAck();
      samples.push(performance.now() - started);
      expect(verdict.ok).toBe(true);
    }
    samples.sort((a, b) => a - b);
    const p50 = samples[Math.floor(samples.length * 0.5)] ?? 0;
    const p99 = samples[Math.floor(samples.length * 0.99)] ?? 0;
    console.error(
      `witness-ack bench (${ITERATIONS} acks over a ${SEED_ENTRIES}+ entry ledger, local witness): ` +
        `p50=${p50.toFixed(2)}ms p99=${p99.toFixed(2)}ms`
    );
    // Generous CI bound; locally this runs at a few ms. The card rail's own
    // decision path is benched separately (~1ms p50) — together they stay
    // orders of magnitude inside the 2s budget.
    expect(p99).toBeLessThan(500);
  }, 120_000);
});
