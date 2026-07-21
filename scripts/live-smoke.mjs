#!/usr/bin/env node
/**
 * LIVE provider smoke — LOCAL ONLY, never CI (CI stays mock/no-secrets).
 * Reads provider keys from the repo-root `.env` (gitignored) and sends a few
 * REAL, tightly-capped calls through the gateway:
 *
 *   - Anthropic (required): one non-streaming + one streaming Haiku call,
 *     max_tokens 64, under a €0.50 mandate.
 *   - OpenAI (optional, if OPENAI_API_KEY is set): one gpt-4o-mini call.
 *
 * R2: keys stay in env vars handed to the child process; this script never
 * prints them, and the assertions below would fail the run if a key ever
 * appeared in gateway output.
 */
import { spawn, execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const envPath = join(root, '.env');
if (!existsSync(envPath)) {
  console.error('live-smoke: no .env at the repo root — nothing to test. See .env.example.');
  process.exit(2);
}
const env = { ...process.env };
for (const line of readFileSync(envPath, 'utf8').split('\n')) {
  const match = /^([A-Z0-9_]+)=(.*)$/.exec(line.trim());
  if (match && match[2] !== '') env[match[1]] = match[2];
}
if (!env.ANTHROPIC_API_KEY) {
  console.error('live-smoke: ANTHROPIC_API_KEY is empty in .env — fill it in first.');
  process.exit(2);
}

const workDir = mkdtempSync(join(tmpdir(), 'mandare-live-'));
const dbPath = join(workDir, 'ledger.db');
const mandatePath = join(workDir, 'mandate.json');
let gateway = null;

function fail(message) {
  console.error(`LIVE SMOKE FAIL: ${message}`);
  if (gateway !== null) gateway.kill('SIGKILL');
  process.exit(1);
}
process.on('uncaughtException', (error) => fail(error.stack ?? String(error)));
setTimeout(() => fail('timed out after 120s'), 120_000).unref();

// Tiny mandate: the whole live smoke cannot spend more than €0.50.
execFileSync(
  'node',
  [
    join(root, 'scripts/dev-mandate.mjs'),
    '--out', mandatePath,
    '--per-tx', '0.25',
    '--per-day', '0.5',
    '--per-task', '0.5',
    '--total', '0.5',
    '--approval-above', '0.25',
  ],
  { stdio: 'inherit' }
);

gateway = spawn('node', [join(root, 'packages/gateway/dist/start.js')], {
  env: {
    ...env,
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
    if (String(chunk).includes(env.ANTHROPIC_API_KEY)) {
      reject(new Error('gateway printed a credential (R2 violation)'));
    }
    const match = output.match(/listening on (http:\/\/[\d.]+:\d+)/);
    if (match) resolve(match[1]);
  });
  gateway.on('exit', (code) => reject(new Error(`gateway exited early (code ${code})`)));
});
console.log(`[live] gateway on ${gatewayUrl}`);

// 1. Real Anthropic call, non-streaming.
const HAIKU = 'claude-haiku-4-5';
const nonStream = await fetch(`${gatewayUrl}/v1/messages`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    model: HAIKU,
    max_tokens: 64,
    messages: [{ role: 'user', content: 'Reply with exactly: mandare live smoke ok' }],
  }),
});
const nonStreamBody = await nonStream.json();
if (nonStream.status !== 200) fail(`anthropic non-stream: ${nonStream.status} ${JSON.stringify(nonStreamBody)}`);
console.log(`[live] anthropic non-stream: "${nonStreamBody.content?.[0]?.text ?? '?'}"`);

// 2. Real Anthropic call, STREAMING (the S2 true-up path).
const streamResponse = await fetch(`${gatewayUrl}/v1/messages`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    model: HAIKU,
    max_tokens: 64,
    stream: true,
    messages: [{ role: 'user', content: 'Count from 1 to 5, digits only.' }],
  }),
});
if (streamResponse.status !== 200) fail(`anthropic stream: ${streamResponse.status}`);
const streamText = await streamResponse.text();
if (!streamText.includes('message_start')) fail('stream carried no message_start event');
if (!streamText.includes(': x-mandare-result-entry')) fail('stream missing result-entry trailer');
console.log('[live] anthropic stream: passed through, usage teed, result entry in trailer');

// 3. Optional OpenAI call.
if (env.OPENAI_API_KEY) {
  const openai = await fetch(`${gatewayUrl}/v1/chat/completions`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      model: 'gpt-4o-mini',
      max_tokens: 32,
      messages: [{ role: 'user', content: 'Reply with exactly: ok' }],
    }),
  });
  if (openai.status !== 200) fail(`openai: ${openai.status} ${await openai.text()}`);
  console.log('[live] openai non-stream: ok');
} else {
  console.log('[live] OPENAI_API_KEY empty — skipping the OpenAI leg');
}

gateway.kill('SIGTERM');
await new Promise((resolve) => gateway.on('exit', resolve));
gateway = null;

// 4. Proof.
const verify = execFileSync(
  'node',
  [join(root, 'apps/cli/dist/main.js'), 'verify', '--db', dbPath, '--spend'],
  { encoding: 'utf8' }
);
console.log(verify.trim().split('\n').map((line) => `[verify] ${line}`).join('\n'));
if (!verify.includes('chain:    VALID')) fail('chain not VALID');
if (!verify.includes('counters: CONSISTENT')) fail('counters not CONSISTENT');
if (verify.includes(env.ANTHROPIC_API_KEY)) fail('credential appeared in verify output (R2)');

rmSync(workDir, { recursive: true, force: true });
console.log('\nLIVE SMOKE PASS: real Haiku calls metered, true-up settled, ledger verified.');
