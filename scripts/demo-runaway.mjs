#!/usr/bin/env node
/**
 * DEMO + ACCEPTANCE TEST (S2, rule R7): a runaway agent loop dies at €20.
 *
 * A scripted agent hammers the gateway with Anthropic-style calls (mock
 * provider, no secrets — enforcement is what's being demonstrated, not the
 * model). Every call reserves its estimated cost against the mandate's €20
 * day budget INSIDE the ledger transaction; when the next reservation would
 * cross the cap, the gateway refuses, records the refusal as a ledger entry,
 * and the loop dies mid-run. `mandare verify --spend` then shows the whole
 * intent/result trail INCLUDING the refused reservation, and proves the
 * budget counters equal a fresh replay of the ledger.
 *
 * Run: pnpm demo            (CI runs this — it asserts, not just prints)
 * Capture: MANDARE_DEMO_CAPTURE=docs/demos/S2-runaway-demo.txt pnpm demo
 */
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const workDir = mkdtempSync(join(tmpdir(), 'mandare-demo-'));
const dbPath = join(workDir, 'ledger.db');
const mandatePath = join(workDir, 'mandate.json');

const captured = [];
function log(line = '') {
  console.log(line);
  captured.push(line);
}

let gateway = null;
let mock = null;
function fail(message) {
  console.error(`DEMO FAIL: ${message}`);
  if (gateway !== null) gateway.kill('SIGKILL');
  if (mock !== null) mock.close();
  process.exit(1);
}
process.on('uncaughtException', (error) => fail(error.stack ?? String(error)));
setTimeout(() => fail('timed out after 120s'), 120_000).unref();

// The runaway workload: each call asks for the model's near-max output, so a
// single call costs ~€0.28 (claude-haiku-4-5: 60k out × $5/M + input, at
// 1.08 USD/EUR). ~71 calls fit under €20.
const MAX_TOKENS = 60_000;
const OUTPUT_TOKENS = 60_000;
const INPUT_TOKENS = 20;

log('════════════════════════════════════════════════════════════════════');
log(' MANDARE DEMO — a runaway agent loop dies at €20');
log('════════════════════════════════════════════════════════════════════');
log();

// 1. The mandate: €20/day is what the human signed. ---------------------------
execFileSync(
  'node',
  [
    join(root, 'scripts/dev-mandate.mjs'),
    '--out', mandatePath,
    '--per-tx', '5',
    '--per-day', '20',
    '--per-task', '20',
    '--total', '100',
    '--approval-above', '5',
  ],
  { stdio: 'inherit' }
);
log('[demo] mandate signed: €5/call · €20/day · €100 total — the human signs ONCE.');

// 2. Mock Anthropic (the runaway is real; the provider needn't be). ------------
mock = createServer((req, res) => {
  let body = '';
  req.on('data', (chunk) => (body += chunk));
  req.on('end', () => {
    res.setHeader('content-type', 'application/json');
    res.end(
      JSON.stringify({
        id: 'msg-demo',
        type: 'message',
        content: [{ type: 'text', text: '…more agent output…' }],
        usage: { input_tokens: INPUT_TOKENS, output_tokens: OUTPUT_TOKENS },
      })
    );
  });
});
await new Promise((resolve) => mock.listen(0, '127.0.0.1', resolve));

// 3. The gateway door. ---------------------------------------------------------
gateway = spawn('node', [join(root, 'packages/gateway/dist/start.js')], {
  env: {
    ...process.env,
    ANTHROPIC_BASE_URL: `http://127.0.0.1:${mock.address().port}`,
    ANTHROPIC_API_KEY: 'demo-key-not-a-secret',
    MANDARE_MANDATE_PATH: mandatePath,
    MANDARE_LEDGER_DB: dbPath,
    MANDARE_GATEWAY_PORT: '0',
    MANDARE_LEDGER_CURRENCY: 'EUR',
    MANDARE_USD_PER_LEDGER_UNIT: '1.08',
    MANDARE_MAX_CALLS_PER_MINUTE: '100000',
  },
  stdio: ['ignore', 'pipe', 'inherit'],
});
const gatewayUrl = await new Promise((resolve, reject) => {
  let output = '';
  gateway.stdout.on('data', (chunk) => {
    output += chunk;
    const match = output.match(/listening on (http:\/\/[\d.]+:\d+)/);
    if (match) resolve(match[1]);
  });
  gateway.on('exit', (code) => reject(new Error(`gateway exited early (code ${code})`)));
});
log(`[demo] gateway door up at ${gatewayUrl} (ledger: ${dbPath})`);
log();
log('[demo] releasing the runaway loop — it will NOT stop on its own…');
log();

// 4. The runaway loop. -----------------------------------------------------------
let completed = 0;
let refusal = null;
const startedAt = Date.now();
for (let call = 1; call <= 1000; call += 1) {
  const response = await fetch(`${gatewayUrl}/v1/messages`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      model: 'claude-haiku-4-5',
      max_tokens: MAX_TOKENS,
      messages: [{ role: 'user', content: 'Continue the task. Generate as much as possible.' }],
    }),
  });
  if (response.status === 200) {
    completed += 1;
    // Display only — the ledger is the truth shown at the end. Per call:
    // (20 in × $1/M + 60k out × $5/M) / 1.08 USD-per-EUR ≈ €0.2778.
    const spentEur = completed * 0.2778;
    if (completed % 10 === 0 || completed <= 3) {
      log(`  call #${String(completed).padStart(3)}  200 OK   — ~€${spentEur.toFixed(2)} spent so far`);
    }
    continue;
  }
  if (response.status === 403) {
    refusal = await response.json();
    log();
    log(`  call #${String(completed + 1).padStart(3)}  403 DENIED — THE LOOP DIES HERE`);
    log(`    code:   ${refusal.code}`);
    for (const reason of refusal.reasons) {
      log(`    reason: ${reason}`);
    }
    if (refusal.denied_entry) {
      log(`    the refusal itself is ledger entry ${refusal.denied_entry.slice(0, 16)}…`);
    }
    break;
  }
  fail(`unexpected status ${response.status}: ${await response.text()}`);
}
const seconds = ((Date.now() - startedAt) / 1000).toFixed(1);
log();
log(`[demo] runaway made ${completed} calls in ${seconds}s before the mandate killed it.`);

gateway.kill('SIGTERM');
await new Promise((resolve) => gateway.on('exit', resolve));
gateway = null;
mock.close();
mock = null;

// 5. The proof: mandare verify --spend. -------------------------------------------
log();
log(`$ mandare verify --db ledger.db --spend`);
const verify = await new Promise((resolve) => {
  const child = spawn(
    'node',
    [join(root, 'apps/cli/dist/main.js'), 'verify', '--db', dbPath, '--spend'],
    { stdio: ['ignore', 'pipe', 'pipe'] }
  );
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => (stdout += chunk));
  child.stderr.on('data', (chunk) => (stderr += chunk));
  child.on('exit', (code) => resolve({ code, stdout, stderr }));
});
for (const line of verify.stdout.trim().split('\n')) {
  log(line);
}
log();

// 6. ACCEPTANCE ASSERTIONS (this script IS the acceptance test, R7). ---------------
if (refusal === null) fail('the loop was never refused — the cap did not enforce');
if (refusal.code !== 'PER_DAY_EXCEEDED') fail(`refusal code ${refusal.code}, expected PER_DAY_EXCEEDED`);
if (!/^[0-9a-f]{64}$/.test(refusal.denied_entry ?? '')) fail('refusal was not recorded as a ledger entry');
if (verify.code !== 0) fail(`verify exited ${verify.code}: ${verify.stderr}`);
if (!verify.stdout.includes('chain:    VALID')) fail('chain not VALID');
if (!verify.stdout.includes('counters: CONSISTENT')) fail('counters not CONSISTENT with ledger replay');
if (!verify.stdout.includes('DENIED')) fail('refused reservation missing from the trail');
const settledMatch = verify.stdout.match(/settled ([\d.]+) EUR/);
if (settledMatch === null) fail('no settled total in spend report');
const settledEur = Number(settledMatch[1]);
if (!(settledEur > 19 && settledEur <= 20)) {
  fail(`settled €${settledEur} — expected the loop to die just under the €20 cap`);
}
if (completed < 60 || completed > 75) {
  fail(`completed ${completed} calls — outside the expected ~71-call window`);
}

log('════════════════════════════════════════════════════════════════════');
log(` DEMO PASS: ${completed} calls, €${settledEur} settled, call #${completed + 1} refused,`);
log(' refusal on the ledger, chain VALID, counters == replay(ledger).');
log(' The human signed once; the mandate did the saying-no.');
log('════════════════════════════════════════════════════════════════════');

if (process.env.MANDARE_DEMO_CAPTURE) {
  const capturePath = join(root, process.env.MANDARE_DEMO_CAPTURE);
  mkdirSync(dirname(capturePath), { recursive: true });
  writeFileSync(capturePath, `${captured.join('\n')}\n`);
  console.log(`\n[demo] terminal capture written to ${process.env.MANDARE_DEMO_CAPTURE}`);
}
rmSync(workDir, { recursive: true, force: true });
