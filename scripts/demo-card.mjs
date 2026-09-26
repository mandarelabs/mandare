#!/usr/bin/env node
/**
 * DEMO 4 + ACCEPTANCE TEST (S5, rule R7): the card declines AT THE NETWORK.
 *
 * Under ONE signed €20 mandate covering BOTH money rails:
 *   1. the agent burns part of the cap on LLM calls through the gateway;
 *   2. it buys something with its mandate-issued virtual card — the
 *      issuing_authorization.request webhook consults the SAME budget, the
 *      purchase fits the remainder → APPROVED at the network;
 *   3. the next purchase would pierce the €20 the LLM calls already ate →
 *      DECLINED at the network, the refusal is a ledger entry;
 *   4. `mandare kill` → the card is revoked locally AND canceled at
 *      (mock-)Stripe; a further authorization is DECLINED;
 *   5. `mandare verify --spend` proves the whole thing: chain VALID,
 *      counters == replay, and the cross-rail split under one cap.
 *
 * CI-safe: mock LLM provider, mock Stripe, real webhook SIGNATURES (the
 * demo signs exactly like Stripe does). No secrets. ASSERTS everything.
 *
 * Run: pnpm demo:card
 * Capture: MANDARE_DEMO_CAPTURE=docs/demos/S5-card-demo.txt pnpm demo:card
 */
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const cardRail = await import(join(root, 'packages/card-rail/dist/index.js'));

const workDir = mkdtempSync(join(tmpdir(), 'mandare-card-demo-'));
const dbPath = join(workDir, 'ledger.db');
const cli = join(root, 'apps/cli/dist/main.js');
const WEBHOOK_SECRET = 'whsec_demo_not_a_secret';
const AGENT = 'did:mandare:demo-agent';

const captured = [];
function log(line = '') {
  console.log(line);
  captured.push(line);
}

let gateway = null;
let mockLlm = null;
let mockStripe = null;
function fail(message) {
  console.error(`DEMO FAIL: ${message}`);
  if (gateway !== null) gateway.kill('SIGKILL');
  mockLlm?.close();
  mockStripe?.close();
  process.exit(1);
}
process.on('uncaughtException', (error) => fail(error.stack ?? String(error)));
setTimeout(() => fail('timed out after 120s'), 120_000).unref();

log('════════════════════════════════════════════════════════════════════');
log(' MANDARE DEMO 4 — the card declines at the network');
log('════════════════════════════════════════════════════════════════════');
log();

// 1. ONE mandate, BOTH rails: €16/tx, €20/day — llm AND card. ----------------
const mandatePath = join(workDir, 'mandate.json');
execFileSync('node', [join(root, 'scripts/dev-mandate.mjs'),
  '--out', mandatePath, '--agent', AGENT, '--card',
  '--per-tx', '16', '--per-day', '20', '--per-task', '20', '--total', '20',
  '--approval-above', '100'], { stdio: 'ignore' });
log('[owner]  ONE €20 mandate signed — rails: gateway (LLM) AND card. One cap.');
log();

// 2. Mock LLM provider (OpenRouter-shaped, authoritative usage.cost). ---------
mockLlm = createServer((req, res) => {
  let body = '';
  req.on('data', (chunk) => (body += chunk));
  req.on('end', () => {
    res.setHeader('content-type', 'application/json');
    // Like OpenRouter: an endpoint serves only under the door's price ceiling.
    const ceiling = JSON.parse(body).provider?.max_price;
    if (!(ceiling?.prompt >= 1 && ceiling?.completion >= 6250)) {
      res.statusCode = 404;
      res.end(JSON.stringify({ error: { code: 404, message: 'No endpoints found matching your price constraints' } }));
      return;
    }
    res.end(JSON.stringify({
      id: 'gen-demo', object: 'chat.completion',
      choices: [{ message: { role: 'assistant', content: 'step done' } }],
      // 1 USD/EUR in the demo: each call settles €2.50 of the cap
      // (400 tokens at the $6,250/M ceiling; the prompt rounds away).
      usage: { prompt_tokens: 40, completion_tokens: 400, cost: 2.5 },
    }));
  });
});
await new Promise((resolve) => mockLlm.listen(0, '127.0.0.1', resolve));

// 3. Mock Stripe: creates virtual cards, records cancellations. ---------------
const stripeCalls = [];
mockStripe = createServer((req, res) => {
  let body = '';
  req.on('data', (chunk) => (body += chunk));
  req.on('end', () => {
    stripeCalls.push({ method: req.method, url: req.url, body });
    res.setHeader('content-type', 'application/json');
    if (req.url === '/v1/issuing/cards' && req.method === 'POST') {
      res.end(JSON.stringify({ id: 'ic_demo_1', object: 'issuing.card', last4: '4242', status: 'active', currency: 'eur' }));
      return;
    }
    if (/^\/v1\/issuing\/cards\/[^/]+$/.test(req.url ?? '') && req.method === 'POST') {
      res.end(JSON.stringify({ id: req.url.split('/').pop(), object: 'issuing.card', last4: '4242', status: 'canceled', currency: 'eur' }));
      return;
    }
    res.statusCode = 404;
    res.end(JSON.stringify({ error: { message: 'not found' } }));
  });
});
await new Promise((resolve) => mockStripe.listen(0, '127.0.0.1', resolve));
const stripeBase = `http://127.0.0.1:${mockStripe.address().port}`;

// 4. The door: gateway + card rail in ONE process, ONE ledger. ----------------
// Only a priced model runs through OpenRouter: its row sets the reservation
// (400 output tokens at $6,250/M = $2.50, plus prompt and the 5% BYOK
// headroom) and the provider.max_price ceiling the door forwards, so the
// €2.50 each call settles (OpenRouter's authoritative usage.cost) is within
// what was reserved. A row needs a context window to run through OpenRouter.
const pricingPath = join(workDir, 'pricing.json');
writeFileSync(pricingPath, JSON.stringify([
  { model: 'demo/agent-model', inUsdPerM: 1, outUsdPerM: 6250, maxOutputTokens: 8192, maxInputTokens: 128000 },
]));
const doorEnv = {
  ...process.env,
  MANDARE_LEDGER_DB: dbPath,
  MANDARE_DOOR_ID: 'gateway:local',
  MANDARE_ACTOR: AGENT,
  MANDARE_MANDATE_PATH: mandatePath,
  MANDARE_GATEWAY_PORT: '0',
  MANDARE_GATEWAY_AUTH: 'none',
  MANDARE_LEDGER_CURRENCY: 'EUR',
  MANDARE_USD_PER_LEDGER_UNIT: '1',
  OPENROUTER_API_KEY: 'sk-or-demo-not-a-secret',
  OPENROUTER_BASE_URL: `http://127.0.0.1:${mockLlm.address().port}/api/v1`,
  MANDARE_PRICING_PATH: pricingPath,
  ANTHROPIC_API_KEY: '', OPENAI_API_KEY: '',
  STRIPE_SECRET_KEY: 'sk_test_demo_not_a_secret',
  STRIPE_WEBHOOK_SECRET: WEBHOOK_SECRET,
  STRIPE_API_BASE: stripeBase,
  STRIPE_CARDHOLDER_ID: 'ich_demo',
};
gateway = spawn('node', [join(root, 'packages/gateway/dist/start.js')], {
  env: doorEnv, stdio: ['ignore', 'pipe', 'inherit'],
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
log(`[door]   one door process at ${gatewayUrl} — LLM proxy AND card rail, one ledger.`);
log();

// 5. The agent issues its card (a mandate-checked, ledger-logged door op). ----
const cardResponse = await fetch(`${gatewayUrl}/cards`, { method: 'POST' });
const card = await cardResponse.json();
log(`[agent]  virtual card issued: ${card.card_id} (…${card.last4}) — allowed because the mandate grants card.create.`);
log();

// 6. Rail 1 — the agent works: 6 LLM calls, €2.50 each. -----------------------
const llmStatuses = [];
for (let step = 1; step <= 6; step += 1) {
  const response = await fetch(`${gatewayUrl}/v1/chat/completions`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      model: 'demo/agent-model',
      max_tokens: 400,
      messages: [{ role: 'user', content: `step ${step}` }],
    }),
  });
  llmStatuses.push(response.status);
  log(`[agent]  LLM call ${step}/6 → ${response.status} (settled €2.50 of the €20 cap)`);
}
log('         €15.00 of the mandate consumed on the gateway rail.');
log();

// 7. Rail 2 — a purchase that FITS the remainder. -----------------------------
async function authorize(authorizationId, cents, merchant) {
  const payload = JSON.stringify({
    id: `evt_${authorizationId}`, object: 'event', api_version: '2026-demo',
    type: 'issuing_authorization.request',
    data: { object: {
      id: authorizationId, object: 'issuing.authorization',
      amount: cents, currency: 'eur',
      card: { id: card.card_id },
      merchant_data: { name: merchant, network_id: `net_${merchant.toLowerCase().replaceAll(' ', '_')}`, city: 'Berlin', country: 'DE', category: 'computer_software_stores' },
      pending_request: { amount: cents, currency: 'eur', is_amount_controllable: false },
    } },
  });
  const response = await fetch(`${gatewayUrl}/stripe/webhook`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'stripe-signature': cardRail.signStripePayload({ payload, secret: WEBHOOK_SECRET }),
    },
    body: payload,
  });
  return response.json();
}

const purchase1 = await authorize('iauth_demo_ok', 420, 'ACME SaaS');
log(`[card]   €4.20 at ACME SaaS  → issuing_authorization.request → ${purchase1.approved ? 'APPROVED' : 'DECLINED'} (15.00 + 4.20 ≤ 20.00)`);

// 8. The purchase that would pierce the cap the LLM calls already ate. --------
const purchase2 = await authorize('iauth_demo_over', 300, 'ACME SaaS');
log(`[card]   €3.00 at ACME SaaS  → issuing_authorization.request → ${purchase2.approved ? 'APPROVED' : 'DECLINED AT THE NETWORK'} (19.20 + 3.00 > 20.00)`);
log('         the refusal is a ledger entry, not a vanished toast.');
log();

// 9. The kill: local authority, cloud belt. -----------------------------------
// Spawned ASYNC: the kill's Stripe-cancel belt calls back into this
// process's mock Stripe server, so the demo's event loop must stay live.
log(`$ mandare kill ${AGENT}`);
const killOutput = await new Promise((resolve, reject) => {
  const child = spawn('node', [cli, 'kill', AGENT, '--reason', 'demo: task over'], {
    env: doorEnv, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = ''; let stderr = '';
  child.stdout.on('data', (chunk) => (stdout += chunk));
  child.stderr.on('data', (chunk) => (stderr += chunk));
  child.on('exit', (code) => (code === 0 ? resolve(stdout) : reject(new Error(`kill exited ${code}: ${stderr}`))));
});
for (const line of killOutput.trim().split('\n')) log(`  ${line}`);
const purchase3 = await authorize('iauth_demo_dead', 50, 'ACME SaaS');
log(`[card]   €0.50 post-kill     → issuing_authorization.request → ${purchase3.approved ? 'APPROVED' : 'DECLINED'} (agent + card revoked)`);
log();

gateway.kill('SIGTERM');
await new Promise((resolve) => gateway.on('exit', resolve));
gateway = null;
mockLlm.close(); mockLlm = null;
mockStripe.close(); mockStripe = null;

// 10. The proof. ---------------------------------------------------------------
log('$ mandare verify --db ledger.db --spend');
const verify = await new Promise((resolve) => {
  const child = spawn('node', [cli, 'verify', '--db', dbPath, '--spend'], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = ''; let stderr = '';
  child.stdout.on('data', (chunk) => (stdout += chunk));
  child.stderr.on('data', (chunk) => (stderr += chunk));
  child.on('exit', (code) => resolve({ code, stdout, stderr }));
});
for (const line of verify.stdout.trim().split('\n')) log(line);
log();

// 11. ACCEPTANCE ASSERTIONS (this script IS the acceptance test, R7). ---------
if (llmStatuses.some((status) => status !== 200)) fail(`LLM calls not all 200: ${llmStatuses}`);
if (cardResponse.status !== 201) fail(`card creation returned ${cardResponse.status}`);
if (purchase1.approved !== true) fail('the in-cap purchase was not approved');
if (purchase2.approved !== false) fail('the over-cap purchase was NOT declined at the network');
if (purchase3.approved !== false) fail('a post-kill authorization was not declined');
if (!killOutput.includes(`card killed:  ${card.card_id}`)) fail('kill did not revoke the card locally');
if (!stripeCalls.some((call) => call.url === `/v1/issuing/cards/${card.card_id}` && call.body.includes('canceled'))) {
  fail('kill did not cancel the card at Stripe (belt)');
}
if (verify.code !== 0) fail(`verify exited ${verify.code}: ${verify.stderr}`);
if (!verify.stdout.includes('chain:    VALID')) fail('chain not VALID');
if (!verify.stdout.includes('counters: CONSISTENT')) fail('spend counters not CONSISTENT with replay');
if (!/rails:\s+llm settled 15\.00 EUR.*card settled 4\.20 EUR.*one cap governs both/.test(verify.stdout)) {
  fail(`cross-rail totals not proven in verify output`);
}
if (!verify.stdout.includes('settled 19.20 EUR')) {
  fail('combined cross-rail total (15.00 + 4.20 = 19.20 EUR) not proven');
}
if (!verify.stdout.includes(`card:${card.card_id}`)) fail('the card revocation is not in the kill trail');

log('════════════════════════════════════════════════════════════════════');
log(' DEMO PASS: one €20 mandate governed BOTH rails — LLM calls ate');
log(' €15.00, a €4.20 purchase fit and was APPROVED at the network, the');
log(' next €3.00 was DECLINED at the network with the refusal on the');
log(' ledger, and `mandare kill` turned the card to dead plastic (local');
log(' revoke + Stripe cancel). mandare verify proves the cross-rail spend.');
log('════════════════════════════════════════════════════════════════════');

if (process.env.MANDARE_DEMO_CAPTURE) {
  const capturePath = join(root, process.env.MANDARE_DEMO_CAPTURE);
  mkdirSync(dirname(capturePath), { recursive: true });
  writeFileSync(capturePath, `${captured.join('\n')}\n`);
  console.log(`\n[demo] terminal capture written to ${process.env.MANDARE_DEMO_CAPTURE}`);
}
rmSync(workDir, { recursive: true, force: true });
