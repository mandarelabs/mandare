#!/usr/bin/env node
/**
 * `docker compose run --rm demo` — the first thing a new user sees work:
 * a runaway agent loop hammers THEIR gateway until the mandate's day cap
 * refuses it, the refusal lands on the ledger, and verification proves the
 * chain, the counters, and (via the witness) that nothing was truncated or
 * rewritten. Demo 1, running in the user's own stack.
 *
 * Also runs outside compose: MANDARE_GATEWAY_URL / MANDARE_LEDGER_DB /
 * MANDARE_WITNESS_URL / MANDARE_WITNESS_PUBLIC_HEX (or _KEY) point it
 * anywhere. Asserts, not just prints (R7).
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const gatewayUrl = (process.env.MANDARE_GATEWAY_URL ?? 'http://gateway:8484').replace(/\/+$/, '');
const ledgerDb = process.env.MANDARE_LEDGER_DB ?? '/data/ledger.db';
const witnessUrl = process.env.MANDARE_WITNESS_URL ?? null;
const witnessKeyFile = process.env.MANDARE_WITNESS_PUBLIC_HEX ?? null;
const witnessKey =
  process.env.MANDARE_WITNESS_PUBLIC_KEY ??
  (witnessKeyFile !== null && existsSync(witnessKeyFile)
    ? readFileSync(witnessKeyFile, 'utf8').trim()
    : null);

function fail(message) {
  console.error(`\nDEMO FAIL: ${message}`);
  process.exit(1);
}
setTimeout(() => fail('timed out after 300s'), 300_000).unref();

console.log('════════════════════════════════════════════════════════════════════');
console.log(' MANDARE — a runaway agent loop dies at the cap, in YOUR stack');
console.log('════════════════════════════════════════════════════════════════════');
console.log();
console.log(`gateway: ${gatewayUrl}`);
console.log('the loop will NOT stop on its own — the mandate stops it.');
console.log();

let completed = 0;
let refusal = null;
for (let call = 1; call <= 2000; call += 1) {
  let response;
  try {
    response = await fetch(`${gatewayUrl}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        model: 'claude-haiku-4-5',
        max_tokens: 60_000,
        messages: [{ role: 'user', content: 'Continue the task. Generate as much as possible.' }],
      }),
    });
  } catch (error) {
    fail(`gateway unreachable at ${gatewayUrl}: ${error instanceof Error ? error.message : error}`);
  }
  if (response.status === 200) {
    completed += 1;
    await response.text();
    if (completed % 10 === 0 || completed <= 3) {
      console.log(`  call #${String(completed).padStart(3)}  200 OK`);
    }
    continue;
  }
  if (response.status === 403) {
    refusal = await response.json();
    console.log();
    console.log(`  call #${String(completed + 1).padStart(3)}  403 DENIED — THE LOOP DIES HERE`);
    console.log(`    code:   ${refusal.code}`);
    for (const reason of refusal.reasons ?? []) {
      console.log(`    reason: ${reason}`);
    }
    if (refusal.denied_entry) {
      console.log(`    the refusal itself is ledger entry ${refusal.denied_entry.slice(0, 16)}…`);
    }
    break;
  }
  fail(`unexpected status ${response.status}: ${await response.text()}`);
}

if (refusal === null) fail('the loop was never refused — the cap did not enforce');
if (!/EXCEEDED/.test(refusal.code ?? '')) fail(`refusal code ${refusal.code} is not a budget cap`);
if (!/^[0-9a-f]{64}$/.test(refusal.denied_entry ?? '')) fail('refusal was not recorded as a ledger entry');
console.log(`\n[demo] runaway made ${completed} calls before the mandate killed it.`);

const cli = join(root, 'apps/cli/dist/main.js');
console.log('\n$ mandare verify --db ledger.db --spend');
const spendOut = execFileSync('node', [cli, 'verify', '--db', ledgerDb, '--spend'], { encoding: 'utf8' });
console.log(spendOut);
if (!spendOut.includes('chain:    VALID')) fail('chain not VALID');
if (!spendOut.includes('counters: CONSISTENT')) fail('counters not CONSISTENT with a fresh ledger replay');
if (!spendOut.includes('DENIED')) fail('the refusal is missing from the spend trail');

if (witnessUrl !== null && witnessKey !== null && /^[0-9a-f]{64}$/.test(witnessKey)) {
  console.log(`$ mandare verify --db ledger.db --witness ${witnessUrl} --witness-key <out-of-band>`);
  // The door streams heads once per second (lock 4) — right after the last
  // append the witness may be one tick behind, so poll until the witnessed
  // history covers the chain (bounded; a dead witness still fails loudly).
  const deadline = Date.now() + 20_000;
  let witnessOut = '';
  let witnessOk = false;
  while (Date.now() < deadline) {
    try {
      witnessOut = execFileSync(
        'node',
        [cli, 'verify', '--db', ledgerDb, '--witness', witnessUrl, '--witness-key', witnessKey],
        { encoding: 'utf8' }
      );
      if (witnessOut.includes('CONSISTENT')) {
        witnessOk = true;
        break;
      }
    } catch (error) {
      witnessOut = `${error.stdout ?? ''}${error.stderr ?? ''}`;
    }
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  console.log(witnessOut);
  if (!witnessOk) fail('witnessed-head check did not come back CONSISTENT within 20s');
} else {
  console.log('(no witness configured — skipping the truncation/rewrite check)');
}

console.log('════════════════════════════════════════════════════════════════════');
console.log(` DEMO PASS: ${completed} calls, then a refusal WITH a receipt.`);
console.log(' The human signed once; the mandate did the saying-no.');
console.log(' Dashboard: http://127.0.0.1:8788 · Docs: https://mandare.dev');
console.log('════════════════════════════════════════════════════════════════════');
