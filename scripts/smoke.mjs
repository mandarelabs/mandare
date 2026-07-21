#!/usr/bin/env node
/**
 * Walking-skeleton smoke test — runs in CI with no secrets:
 *
 *   1. generate a signed dev mandate (the S2 gateway refuses to spend
 *      without one — no more allow-all stub),
 *   2. start a mock OpenRouter,
 *   3. start the real gateway pointed at it,
 *   4. send one chat completion through the door,
 *   5. `mandare verify --spend` → chain VALID + counters CONSISTENT (exit 0),
 *   6. tamper with the DB → `mandare verify` → chain INVALID (exit 1).
 */
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const workDir = mkdtempSync(join(tmpdir(), 'mandare-smoke-'));
const dbPath = join(workDir, 'ledger.db');
const mandatePath = join(workDir, 'mandate.json');

let gateway = null;
let mock = null;

function fail(message) {
  console.error(`SMOKE FAIL: ${message}`);
  if (gateway !== null) gateway.kill('SIGKILL');
  if (mock !== null) mock.close();
  process.exit(1);
}

process.on('uncaughtException', (error) => fail(error.stack ?? String(error)));
setTimeout(() => fail('timed out after 60s'), 60_000).unref();

// 1. Dev mandate ------------------------------------------------------------
execFileSync('node', [join(root, 'scripts/dev-mandate.mjs'), '--out', mandatePath], {
  stdio: 'inherit',
});

// 2. Mock OpenRouter ---------------------------------------------------------
mock = createServer((req, res) => {
  let body = '';
  req.on('data', (chunk) => (body += chunk));
  req.on('end', () => {
    if (req.url?.endsWith('/chat/completions') !== true) {
      res.statusCode = 404;
      return res.end('{"error":"not found"}');
    }
    res.setHeader('content-type', 'application/json');
    res.end(
      JSON.stringify({
        id: 'gen-mock-1',
        model: JSON.parse(body).model,
        choices: [{ message: { role: 'assistant', content: 'Hello from the mock provider.' } }],
        usage: { prompt_tokens: 7, completion_tokens: 6, cost: 0.000123 },
      })
    );
  });
});
await new Promise((resolve) => mock.listen(0, '127.0.0.1', resolve));
const mockPort = mock.address().port;
console.log(`[smoke] mock provider on 127.0.0.1:${mockPort}`);

// 3. Real gateway -------------------------------------------------------------
gateway = spawn('node', [join(root, 'packages/gateway/dist/start.js')], {
  env: {
    ...process.env,
    OPENROUTER_BASE_URL: `http://127.0.0.1:${mockPort}/api/v1`,
    OPENROUTER_API_KEY: 'smoke-test-key-not-a-secret',
    MANDARE_MANDATE_PATH: mandatePath,
    MANDARE_LEDGER_DB: dbPath,
    MANDARE_GATEWAY_PORT: '0',
    MANDARE_LEDGER_CURRENCY: 'EUR',
    MANDARE_USD_PER_LEDGER_UNIT: '1.08',
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
console.log(`[smoke] gateway on ${gatewayUrl}`);

// 4. One call through the door -------------------------------------------------
const response = await fetch(`${gatewayUrl}/v1/chat/completions`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    model: 'openrouter/auto',
    messages: [{ role: 'user', content: 'Say hello.' }],
  }),
});
if (response.status !== 200) fail(`gateway returned ${response.status}: ${await response.text()}`);
const intentEntry = response.headers.get('x-mandare-intent-entry');
const resultEntry = response.headers.get('x-mandare-result-entry');
if (!/^[0-9a-f]{64}$/.test(intentEntry ?? '')) fail('missing x-mandare-intent-entry header');
if (!/^[0-9a-f]{64}$/.test(resultEntry ?? '')) fail('missing x-mandare-result-entry header');
const completion = await response.json();
console.log(`[smoke] completion: "${completion.choices[0].message.content}"`);
console.log(`[smoke] intent=${intentEntry.slice(0, 12)}… result=${resultEntry.slice(0, 12)}…`);

const health = await (await fetch(`${gatewayUrl}/healthz`)).json();
if (health.ok !== true) fail(`healthz not ok: ${JSON.stringify(health)}`);
if (health.spend_path_open !== true) fail(`spend path not open: ${JSON.stringify(health)}`);

gateway.kill('SIGTERM');
await new Promise((resolve) => gateway.on('exit', resolve));
gateway = null;
mock.close();
mock = null;

// 5. Verify: chain VALID + counters CONSISTENT ---------------------------------
function runVerify(extraArgs = []) {
  return new Promise((resolve) => {
    const child = spawn(
      'node',
      [join(root, 'apps/cli/dist/main.js'), 'verify', '--db', dbPath, ...extraArgs],
      { stdio: ['ignore', 'pipe', 'pipe'] }
    );
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => (stdout += chunk));
    child.stderr.on('data', (chunk) => (stderr += chunk));
    child.on('exit', (code) => resolve({ code, stdout, stderr }));
  });
}

const clean = await runVerify(['--spend']);
console.log(clean.stdout.trim().split('\n').map((line) => `[verify] ${line}`).join('\n'));
if (clean.code !== 0) fail(`verify on untouched ledger exited ${clean.code}: ${clean.stderr}`);
if (!clean.stdout.includes('VALID')) fail('verify did not report VALID');
if (!clean.stdout.includes('counters: CONSISTENT')) fail('spend counters not CONSISTENT');

// 6. Tamper → verify must FAIL ---------------------------------------------------
const db = new DatabaseSync(dbPath);
db.exec('DROP TRIGGER ledger_entries_no_update;');
db.exec(
  "UPDATE ledger_entries SET entry_json = json_set(entry_json, '$.cost.amount', 0) WHERE seq = 2;"
);
db.close();
console.log('[smoke] tampered: rewrote cost of entry 2 to zero (attacker hiding spend)');

const tampered = await runVerify();
console.log(tampered.stdout.trim().split('\n').map((line) => `[verify] ${line}`).join('\n'));
if (tampered.code !== 1) fail(`verify on tampered ledger exited ${tampered.code}, expected 1`);
if (!tampered.stdout.includes('INVALID')) fail('verify did not report INVALID after tamper');

rmSync(workDir, { recursive: true, force: true });
console.log('\nSMOKE PASS: mandated call → reserve/settle entries → verify + counters OK → tamper detected.');
