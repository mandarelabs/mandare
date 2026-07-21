#!/usr/bin/env node
/**
 * DEMO 2 + ACCEPTANCE TEST (S3, rule R7): a stolen vault token is dead paper,
 * and one command kills a running agent mid-task.
 *
 * The agent authenticates to the gateway with a short-lived vault-issued
 * proof-of-possession token (provider keys stay in the vault; the agent never
 * sees them). We then show, end to end and with real crypto:
 *   1. the legitimate agent works (a correctly-signed call → 200);
 *   2. a THIEF who exfiltrated the token id but not its secret is refused
 *      (BAD_POP — binding);
 *   3. a captured request cannot be REPLAYED (single-use nonce);
 *   4. `mandare kill` mid-task → the running agent's very next (perfectly
 *      valid, freshly-signed) call fails closed, and the refusal lands on the
 *      ledger — the LOCAL, offline authority, honored without any cloud;
 *   5. `mandare verify` proves the whole sequence: chain VALID, spend counters
 *      == replay, revocation state == replay, and the IETF status-list
 *      bitstring S6 will publish.
 *
 * Runs with NO secrets and NO OS keychain — the vault uses its explicit file
 * backend (headless/CI mode). The script ASSERTS everything (R7).
 *
 * Run: pnpm demo:dead-paper
 * Capture: MANDARE_DEMO_CAPTURE=docs/demos/S3-dead-paper-demo.txt pnpm demo:dead-paper
 */
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const vault = await import(join(root, 'packages/vault/dist/index.js'));

const workDir = mkdtempSync(join(tmpdir(), 'mandare-deadpaper-'));
const dbPath = join(workDir, 'ledger.db');
const vaultDb = join(workDir, 'vault.db');
const masterKeyFile = join(workDir, 'vault.masterkey');
const mandatePath = join(workDir, 'mandate.json');
const cli = join(root, 'apps/cli/dist/main.js');

const ACTOR = 'did:mandare:dev-agent';

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

// The vault runs in explicit FILE-backend mode — no OS keychain in CI.
const vaultEnv = {
  MANDARE_VAULT: '1',
  MANDARE_VAULT_BACKEND: 'file',
  MANDARE_VAULT_DB: vaultDb,
  MANDARE_VAULT_KEY_FILE: masterKeyFile,
  MANDARE_LEDGER_DB: dbPath,
  MANDARE_DOOR_ID: 'gateway:local',
  MANDARE_LEDGER_CURRENCY: 'EUR',
};

log('════════════════════════════════════════════════════════════════════');
log(' MANDARE DEMO 2 — a stolen vault token is dead paper; kill halts an agent');
log('════════════════════════════════════════════════════════════════════');
log();

// 1. Mandate (the human signs once). -----------------------------------------
execFileSync(
  'node',
  [join(root, 'scripts/dev-mandate.mjs'), '--out', mandatePath, '--agent', ACTOR, '--per-day', '20'],
  { stdio: 'inherit' }
);
const mandateId = JSON.parse(readFileSync(mandatePath, 'utf8')).id;
log(`[demo] mandate ${mandateId} signed for ${ACTOR}.`);

// 2. Provider key goes INTO the vault (never in the gateway's env). -----------
execFileSync('node', [cli, 'vault', 'import-env'], {
  env: { ...process.env, ...vaultEnv, ANTHROPIC_API_KEY: 'sk-ant-demo-not-a-secret' },
  stdio: 'inherit',
});
log('[demo] provider key imported into the vault; .env can now drop it (R2).');
log();

// 3. Mock Anthropic (the provider needn't be real; enforcement is the point). -
mock = createServer((req, res) => {
  let body = '';
  req.on('data', (chunk) => (body += chunk));
  req.on('end', () => {
    res.setHeader('content-type', 'application/json');
    res.end(
      JSON.stringify({
        id: 'msg-demo',
        type: 'message',
        content: [{ type: 'text', text: 'agent output' }],
        usage: { input_tokens: 20, output_tokens: 50 },
      })
    );
  });
});
await new Promise((resolve) => mock.listen(0, '127.0.0.1', resolve));

// 4. Gateway in VAULT mode: door key + provider key from the vault, tokens
//    required on the spend routes. No provider key in this process's env.
gateway = spawn('node', [join(root, 'packages/gateway/dist/start.js')], {
  env: {
    ...process.env,
    ...vaultEnv,
    ANTHROPIC_BASE_URL: `http://127.0.0.1:${mock.address().port}`,
    MANDARE_GATEWAY_AUTH: 'token',
    MANDARE_MANDATE_PATH: mandatePath,
    MANDARE_GATEWAY_PORT: '0',
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
log(`[demo] gateway door up at ${gatewayUrl} (vault-backed, token auth REQUIRED).`);

// 5. Mint a short-lived scoped token for the agent. --------------------------
const grantJson = execFileSync(
  'node',
  [cli, 'token', 'issue', '--actor', ACTOR, '--mandate', mandateId, '--ttl', '900', '--json'],
  { env: { ...process.env, ...vaultEnv } }
);
const grant = JSON.parse(grantJson.toString());
log(`[demo] vault minted scoped token ${grant.token_id.slice(0, 12)}… (expires ${grant.expires_at}).`);
log('       the agent holds the pop_secret; the gateway never does.');
log();

const PATH = '/v1/messages';
function sign(popSecret, nonce) {
  const timestamp = new Date().toISOString();
  const pop = vault.hmacSha256(
    popSecret,
    vault.popPreimage({ tokenId: grant.token_id, method: 'POST', path: PATH, timestamp, nonce })
  );
  return {
    'content-type': 'application/json',
    'x-mandare-token': grant.token_id,
    'x-mandare-timestamp': timestamp,
    'x-mandare-nonce': nonce,
    'x-mandare-pop': pop,
  };
}
const messageBody = JSON.stringify({
  model: 'claude-haiku-4-5',
  max_tokens: 100,
  messages: [{ role: 'user', content: 'do the task' }],
});
function callWith(headers) {
  return fetch(`${gatewayUrl}${PATH}`, { method: 'POST', headers, body: messageBody });
}

// 6. The legitimate agent works. ---------------------------------------------
const legitHeaders = sign(grant.pop_secret, 'agent-call-1');
const legit = await callWith(legitHeaders);
log(`[agent]  legitimate signed call            → ${legit.status} ${legit.status === 200 ? 'OK' : 'UNEXPECTED'}`);

// 7. THEFT: the token id leaks; a thief lacks the pop secret. -----------------
const theft = await callWith(sign('attacker-guessed-secret', 'thief-call'));
const theftBody = await theft.json();
log(`[thief]  stolen token id, forged proof     → ${theft.status} ${theftBody.code} (binding: no pop secret)`);

// 8. REPLAY: the thief re-sends a captured valid request verbatim. -----------
const replay = await callWith(legitHeaders);
const replayBody = await replay.json();
log(`[thief]  replay of a captured request      → ${replay.status} ${replayBody.code} (single-use nonce)`);
log();

// 9. KILL mid-task. ----------------------------------------------------------
log(`$ mandare kill ${ACTOR}`);
const killOut = execFileSync('node', [cli, 'kill', ACTOR, '--reason', 'demo: compromised agent'], {
  env: { ...process.env, ...vaultEnv },
});
for (const line of killOut.toString().trim().split('\n')) log(`  ${line}`);
log();

// 10. The running agent's NEXT valid call fails closed. ----------------------
const afterKill = await callWith(sign(grant.pop_secret, 'agent-call-after-kill'));
const afterKillBody = await afterKill.json();
log(`[agent]  valid signed call AFTER the kill  → ${afterKill.status} ${afterKillBody.code}`);
log(`         the refusal is ledger entry ${(afterKillBody.denied_entry ?? '').slice(0, 16)}…`);
log();

gateway.kill('SIGTERM');
await new Promise((resolve) => gateway.on('exit', resolve));
gateway = null;
mock.close();
mock = null;

// 11. The proof. -------------------------------------------------------------
log('$ mandare verify --db ledger.db --spend');
const verify = await new Promise((resolve) => {
  const child = spawn('node', [cli, 'verify', '--db', dbPath, '--spend'], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => (stdout += chunk));
  child.stderr.on('data', (chunk) => (stderr += chunk));
  child.on('exit', (code) => resolve({ code, stdout, stderr }));
});
for (const line of verify.stdout.trim().split('\n')) log(line);
log();

// 12. ACCEPTANCE ASSERTIONS (this script IS the acceptance test, R7). ---------
if (legit.status !== 200) fail('the legitimate signed call was not honored');
if (theft.status !== 401 || theftBody.code !== 'BAD_POP') fail('token theft (no secret) was not refused with BAD_POP');
if (replay.status !== 401 || replayBody.code !== 'REPLAYED_NONCE') fail('request replay was not refused with REPLAYED_NONCE');
if (afterKill.status !== 403 || afterKillBody.code !== 'AGENT_REVOKED') fail('post-kill call was not refused with AGENT_REVOKED');
if (!/^[0-9a-f]{64}$/.test(afterKillBody.denied_entry ?? '')) fail('post-kill refusal was not recorded as a ledger entry');
if (verify.code !== 0) fail(`verify exited ${verify.code}: ${verify.stderr}`);
if (!verify.stdout.includes('chain:    VALID')) fail('chain not VALID');
if (!verify.stdout.includes('counters: CONSISTENT')) fail('spend counters not CONSISTENT');
if (!verify.stdout.includes('revocations: CONSISTENT')) fail('revocation projection not CONSISTENT with replay');
if (!/REVOKED\s+agent:did:mandare:dev-agent/.test(verify.stdout)) fail('the kill is not shown in the revocation trail');
if (!verify.stdout.includes('IETF Token Status List')) fail('the status-list bitstring (S6-publishable) was not rendered');

log('════════════════════════════════════════════════════════════════════');
log(' DEMO PASS: stolen token refused (binding + replay), kill halted the');
log(' running agent on its next call, refusal on the ledger, chain VALID,');
log(' spend + revocation == replay(ledger). Local authority, no cloud.');
log('════════════════════════════════════════════════════════════════════');

if (process.env.MANDARE_DEMO_CAPTURE) {
  const capturePath = join(root, process.env.MANDARE_DEMO_CAPTURE);
  mkdirSync(dirname(capturePath), { recursive: true });
  writeFileSync(capturePath, `${captured.join('\n')}\n`);
  console.log(`\n[demo] terminal capture written to ${process.env.MANDARE_DEMO_CAPTURE}`);
}
rmSync(workDir, { recursive: true, force: true });
