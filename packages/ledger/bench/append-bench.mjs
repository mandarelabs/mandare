#!/usr/bin/env node
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';

import { Ledger, buildEntry, loadOrCreateDoorKey } from '@mandarelabs/ledger';

/**
 * Ledger append benchmark (S1, BUILD-DECISIONS Q1).
 *
 * Three layers, so the ceiling is attributable:
 *   1. sign-only        — native Ed25519 over 32-byte hashes (the Q1 claim)
 *   2. buildEntry       — canonical JSON + sha256 + sign + schema validation
 *   3. Ledger.append    — full path incl. SQLite WAL commit with
 *                         synchronous=FULL (one fsync per entry, by design:
 *                         log-before-act must survive power loss, rule R3)
 *
 * Run: pnpm --filter @mandarelabs/ledger bench   (build first)
 */

const ENTRIES = 10_000;

function input(i) {
  return {
    actor: 'did:example:agent',
    mandate_id: 'mnd_bench',
    action: {
      type: 'llm.call.intent',
      target: 'openrouter.ai',
      request_hash: i.toString(16).padStart(64, '0'),
    },
    cost: { amount: 1500, currency: 'USD', tokens_in: 100, tokens_out: 400 },
  };
}

function report(label, count, elapsedMs) {
  const perSecond = Math.round((count / elapsedMs) * 1000);
  console.log(
    `${label.padEnd(34)} ${String(count).padStart(7)} ops  ${elapsedMs.toFixed(0).padStart(6)} ms  ${String(perSecond).padStart(8)} ops/s`
  );
  return perSecond;
}

const workDir = mkdtempSync(join(tmpdir(), 'mandare-bench-'));
const results = {};

// 1. sign-only: native Ed25519, 32-byte payload (an entry hash).
{
  const { privateKey } = generateKeyPairSync('ed25519');
  const payload = Buffer.alloc(32, 7);
  // warmup
  for (let i = 0; i < 1000; i += 1) cryptoSign(null, payload, privateKey);
  const start = performance.now();
  for (let i = 0; i < ENTRIES; i += 1) {
    cryptoSign(null, payload, privateKey);
  }
  results.signOnly = report('sign-only (native Ed25519)', ENTRIES, performance.now() - start);
}

// 2. buildEntry: hash + canonicalize + sign + validate, no storage.
{
  const doorKey = loadOrCreateDoorKey(join(workDir, 'bench-build.pem'));
  let head = null;
  // warmup
  for (let i = 0; i < 500; i += 1) buildEntry(input(i), head, 'gateway:bench', doorKey);
  const start = performance.now();
  for (let i = 0; i < ENTRIES; i += 1) {
    const entry = buildEntry(input(i), head, 'gateway:bench', doorKey);
    head = { seq: entry.seq, entry_hash: entry.entry_hash };
  }
  results.buildEntry = report('buildEntry (hash+sign+validate)', ENTRIES, performance.now() - start);
}

// 3. full append: SQLite WAL, synchronous=FULL (production configuration).
{
  const ledger = Ledger.open(join(workDir, 'bench.db'), { doorId: 'gateway:bench' });
  for (let i = 0; i < 200; i += 1) ledger.append(input(i)); // warmup
  const start = performance.now();
  for (let i = 0; i < ENTRIES; i += 1) {
    ledger.append(input(i));
  }
  results.append = report('Ledger.append (fsync per entry)', ENTRIES, performance.now() - start);
  ledger.close();
}

console.log(
  `\nceiling attribution: signing supports ~${results.signOnly}/s, full entry construction ` +
    `~${results.buildEntry}/s, durable append ~${results.append}/s — the gap between 2 and 3 ` +
    'is the price of synchronous=FULL durability (R3), not crypto.'
);

rmSync(workDir, { recursive: true, force: true });
