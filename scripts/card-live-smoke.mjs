#!/usr/bin/env node
/**
 * CARD RAIL LIVE SMOKE (local only, NEVER CI — CI stays no-secrets with the
 * mock-Stripe demo). Real Stripe TEST MODE end to end:
 *
 *   stripe listen (real webhook signatures, real delivery) → the door
 *   decides real issuing_authorization.request events created with the
 *   Issuing test helpers against a door-issued virtual card:
 *   in-cap approve → over-cap decline → kill → cancel + decline.
 *
 * Requires in .env: STRIPE_SECRET_KEY=sk_test_… (test mode ENFORCED).
 * Requires: the `stripe` CLI on PATH, Issuing enabled on the test account.
 *
 * R2: keys stay in env vars handed to child processes; never printed.
 */
import { spawn } from 'node:child_process';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

const envPath = join(root, '.env');
if (!existsSync(envPath)) {
  console.error('card-live-smoke: no .env at the repo root. See .env.example.');
  process.exit(2);
}
const env = { ...process.env };
for (const line of readFileSync(envPath, 'utf8').split('\n')) {
  const match = /^([A-Z0-9_]+)=(.*)$/.exec(line.trim());
  if (match && match[2] !== '') env[match[1]] = match[2];
}
const stripeKey = env.STRIPE_SECRET_KEY;
if (stripeKey === undefined) {
  console.error('card-live-smoke: STRIPE_SECRET_KEY missing from .env.');
  process.exit(2);
}
if (!stripeKey.startsWith('sk_test_')) {
  console.error('card-live-smoke: STRIPE_SECRET_KEY is not a TEST key (sk_test_…) — refusing (fail-closed).');
  process.exit(2);
}
try {
  execFileSync('stripe', ['version'], { stdio: 'ignore' });
} catch {
  console.error('card-live-smoke: the `stripe` CLI is not on PATH — install it for the listen forwarder.');
  process.exit(2);
}

const workDir = mkdtempSync(join(tmpdir(), 'mandare-card-live-'));
const dbPath = join(workDir, 'ledger.db');
const cli = join(root, 'apps/cli/dist/main.js');
const AGENT = 'did:mandare:live-smoke-agent';

let door = null;
let listener = null;
const children = [];
function shutdown() {
  for (const child of children) {
    try {
      child.kill('SIGTERM');
    } catch {
      /* already gone */
    }
  }
}
function fail(message) {
  console.error(`CARD LIVE SMOKE FAIL: ${message}`);
  shutdown();
  process.exit(1);
}
process.on('uncaughtException', (error) => fail(error.stack ?? String(error)));
setTimeout(() => fail('timed out after 300s'), 300_000).unref();

/** Minimal form-encoded Stripe call for smoke-only surfaces (test helpers). */
async function stripeApi(path, params) {
  const body = new URLSearchParams(params);
  const response = await fetch(`https://api.stripe.com${path}`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${stripeKey}`,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: body.toString(),
  });
  const json = await response.json();
  if (!response.ok) {
    throw new Error(`Stripe ${path} failed (HTTP ${response.status}): ${json.error?.message ?? 'unknown'}`);
  }
  return json;
}

console.log('card-live-smoke: real Stripe TEST MODE, real webhook signatures.');

// 1. Mandate: €5 total across the card rail. ----------------------------------
const mandatePath = join(workDir, 'mandate.json');
execFileSync('node', [join(root, 'scripts/dev-mandate.mjs'),
  '--out', mandatePath, '--agent', AGENT, '--card',
  '--per-tx', '5', '--per-day', '5', '--per-task', '5', '--total', '5',
  '--approval-above', '100'], { stdio: 'ignore' });

// 2. Cardholder (create one if the env does not name one). --------------------
let cardholderId = env.STRIPE_CARDHOLDER_ID;
if (cardholderId === undefined) {
  try {
    const cardholder = await stripeApi('/v1/issuing/cardholders', {
      name: 'Mandare Live Smoke',
      type: 'individual',
      'billing[address][line1]': 'Unter den Linden 1',
      'billing[address][city]': 'Berlin',
      'billing[address][postal_code]': '10117',
      'billing[address][country]': 'DE',
    });
    cardholderId = cardholder.id;
    console.log(`  cardholder created: ${cardholderId}`);
  } catch (error) {
    console.error(`card-live-smoke: could not create an Issuing cardholder — is Issuing enabled on this test account?`);
    console.error(`  ${error.message}`);
    process.exit(2);
  }
}

// 3. stripe listen → real signing secret BEFORE the door starts. --------------
const doorPort = 8491;
listener = spawn('stripe', ['listen',
  '--api-key', stripeKey,
  '--events', 'issuing_authorization.request',
  '--forward-to', `http://127.0.0.1:${doorPort}/stripe/webhook`], {
  stdio: ['ignore', 'pipe', 'pipe'],
});
children.push(listener);
const webhookSecret = await new Promise((resolve, reject) => {
  let output = '';
  const onData = (chunk) => {
    output += chunk;
    const match = output.match(/whsec_[A-Za-z0-9]+/);
    if (match) resolve(match[0]);
  };
  listener.stdout.on('data', onData);
  listener.stderr.on('data', onData);
  listener.on('exit', (code) => reject(new Error(`stripe listen exited early (code ${code})`)));
  setTimeout(() => reject(new Error('stripe listen produced no signing secret within 30s')), 30_000);
});
console.log('  stripe listen ready (signing secret received — not printed).');

// 4. The door: gateway + card rail against REAL test-mode Stripe. -------------
const doorEnv = {
  ...process.env,
  MANDARE_LEDGER_DB: dbPath,
  MANDARE_DOOR_ID: 'gateway:local',
  MANDARE_ACTOR: AGENT,
  MANDARE_MANDATE_PATH: mandatePath,
  MANDARE_GATEWAY_PORT: String(doorPort),
  MANDARE_GATEWAY_AUTH: 'none',
  MANDARE_LEDGER_CURRENCY: 'EUR',
  STRIPE_SECRET_KEY: stripeKey,
  STRIPE_WEBHOOK_SECRET: webhookSecret,
  STRIPE_CARDHOLDER_ID: cardholderId,
};
door = spawn('node', [join(root, 'packages/gateway/dist/start.js')], {
  env: doorEnv, stdio: ['ignore', 'pipe', 'inherit'],
});
children.push(door);
await new Promise((resolve, reject) => {
  let output = '';
  door.stdout.on('data', (chunk) => {
    output += chunk;
    if (output.includes('listening on')) resolve();
  });
  door.on('exit', (code) => reject(new Error(`door exited early (code ${code})`)));
});
console.log(`  door up on :${doorPort} — card rail ON.`);

// 5. Issue a REAL test-mode virtual card through the door. --------------------
const cardResponse = await fetch(`http://127.0.0.1:${doorPort}/cards`, { method: 'POST' });
if (cardResponse.status !== 201) fail(`card creation returned ${cardResponse.status}: ${await cardResponse.text()}`);
const card = await cardResponse.json();
console.log(`  virtual card issued via the door: ${card.card_id} (…${card.last4})`);

// 6. Real authorizations via the Issuing test helpers. ------------------------
async function testAuthorization(cents) {
  const started = Date.now();
  try {
    const authorization = await stripeApi('/v1/test_helpers/issuing/authorizations', {
      card: card.card_id,
      amount: String(cents),
      currency: 'eur',
      'merchant_data[name]': 'Mandare Live Smoke Store',
      'merchant_data[category]': 'computer_software_stores',
    });
    return { approved: authorization.approved === true, ms: Date.now() - started, error: null };
  } catch (error) {
    return { approved: false, ms: Date.now() - started, error: error.message };
  }
}

const inCap = await testAuthorization(200); // €2.00 of the €5 cap
console.log(`  €2.00 authorization → ${inCap.approved ? 'APPROVED' : `NOT approved (${inCap.error ?? 'declined'})`} (${inCap.ms}ms round-trip)`);
if (!inCap.approved) fail('the in-cap authorization was not approved');

const overCap = await testAuthorization(400); // €4.00 — would pierce €5
console.log(`  €4.00 authorization → ${overCap.approved ? 'APPROVED (WRONG)' : 'DECLINED at the network'} (${overCap.ms}ms round-trip)`);
if (overCap.approved) fail('the over-cap authorization was approved — cap not enforced');

// 7. Kill: local revoke + REAL Stripe cancel. ---------------------------------
const killOutput = await new Promise((resolve, reject) => {
  const child = spawn('node', [cli, 'kill', AGENT, '--reason', 'live smoke over'], {
    env: doorEnv, stdio: ['ignore', 'pipe', 'pipe'],
  });
  children.push(child);
  let stdout = '';
  child.stdout.on('data', (chunk) => (stdout += chunk));
  child.on('exit', (code) => (code === 0 ? resolve(stdout) : reject(new Error(`kill exited ${code}`))));
});
if (!killOutput.includes(`card killed:  ${card.card_id}`)) fail('kill did not revoke the card locally');
if (!killOutput.includes('canceled at Stripe')) fail('kill did not cancel the card at Stripe');
console.log(`  mandare kill → card revoked locally AND canceled at Stripe.`);

const postKill = await testAuthorization(50);
console.log(`  €0.50 post-kill  → ${postKill.approved ? 'APPROVED (WRONG)' : 'refused'} (${postKill.error === null ? 'declined by the door' : 'canceled card refused by Stripe'})`);
if (postKill.approved) fail('a post-kill authorization was approved');

// 8. Proof. -------------------------------------------------------------------
shutdown();
await new Promise((resolve) => setTimeout(resolve, 500));
const verify = execFileSync('node', [cli, 'verify', '--db', dbPath, '--spend'], { encoding: 'utf8' });
if (!verify.includes('chain:    VALID')) fail('chain not VALID');
if (!verify.includes('counters: CONSISTENT')) fail('counters not CONSISTENT');
if (!verify.includes(`card:${card.card_id}`)) fail('card revocation missing from the trail');
console.log('  mandare verify --spend: chain VALID, counters CONSISTENT, card in the kill trail.');

console.log('\nCARD LIVE SMOKE PASS — real test mode: approve, decline-at-network, kill, cancel, verify.');
writeFileSync(join(workDir, 'DONE'), 'ok\n');
rmSync(workDir, { recursive: true, force: true });
process.exit(0);
