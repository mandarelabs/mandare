#!/usr/bin/env node
/**
 * DEMO 3 + ACCEPTANCE TEST (S4, rule R7): ONE signed mandate replaces 40
 * permission prompts.
 *
 * An agent with a verified PASSPORT (authority → KYC'd owner → agent, all
 * offline-verifiable did:key + SD-JWT) completes a multi-step task under a
 * single owner-signed mandate:
 *   1. every in-scope call proceeds with ZERO human interaction — the
 *      mandate is the standing answer to the permission prompt;
 *   2. one over-threshold call PAUSES: the gateway holds it, pushes an
 *      Approve/Deny notification (ntfy-shaped; file channel in CI), the
 *      human approves, the task continues;
 *   3. a second over-threshold call is DENIED by the human — the refusal is
 *      a ledger entry, not a vanished dialog box;
 *   4. `mandare verify` proves the WHOLE sequence: chain VALID, spend
 *      counters == replay, and the human decisions (approved AND denied) in
 *      the approval trail.
 *
 * Every call is authenticated with RFC 9421 request signatures (method,
 * path, authority, Content-Digest over the exact body) under the passport's
 * agent key — WHO did it is cryptographic, not configured. No secrets, no
 * OS keychain (file-backend vault), no real provider. ASSERTS everything.
 *
 * Run: pnpm demo:mandate
 * Capture: MANDARE_DEMO_CAPTURE=docs/demos/S4-mandate-demo.txt pnpm demo:mandate
 */
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const passport = await import(join(root, 'packages/passport/dist/index.js'));

const workDir = mkdtempSync(join(tmpdir(), 'mandare-mandate-demo-'));
const dbPath = join(workDir, 'ledger.db');
const notifyFile = join(workDir, 'approvals.jsonl');
const cli = join(root, 'apps/cli/dist/main.js');

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

const vaultEnv = {
  MANDARE_VAULT: '1',
  MANDARE_VAULT_BACKEND: 'file',
  MANDARE_VAULT_DB: join(workDir, 'vault.db'),
  MANDARE_VAULT_KEY_FILE: join(workDir, 'vault.masterkey'),
  MANDARE_LEDGER_DB: dbPath,
  MANDARE_DOOR_ID: 'gateway:local',
  MANDARE_LEDGER_CURRENCY: 'EUR',
};

log('════════════════════════════════════════════════════════════════════');
log(' MANDARE DEMO 3 — one signed mandate replaces 40 permission prompts');
log('════════════════════════════════════════════════════════════════════');
log();

// 1. Passport: authority countersigns the (mock-)KYC\'d owner; the owner
//    delegates to a fresh agent did:key. --------------------------------------
const passportJson = JSON.parse(
  execFileSync(
    'node',
    [cli, 'passport', 'issue', '--agent-name', 'demo-agent',
      '--out', join(workDir, 'agent.passport.sdjwt'),
      '--agent-key-out', join(workDir, 'agent.key.json'), '--json'],
    { env: { ...process.env, ...vaultEnv } }
  ).toString()
);
log(`[owner]  passport issued for agent ${passportJson.agent_did.slice(0, 24)}…`);
log(`         chain: authority → owner (KYC level ${passportJson.kyc.level}, ${passportJson.kyc.partner}) → agent`);

// 2. The ONE mandate the human signs: €5/tx, €20/day, approval above €0.25. ---
const mandatePath = join(workDir, 'task.mandate.sdjwt');
const mandateJson = JSON.parse(
  execFileSync(
    'node',
    [cli, 'mandate', 'issue', '--agent', passportJson.agent_did,
      '--purpose', 'Demo task: research briefing, multi-step',
      '--per-tx', '5', '--per-day', '20', '--approval-above', '0.25',
      '--out', mandatePath, '--json'],
    { env: { ...process.env, ...vaultEnv } }
  ).toString()
);
log(`[owner]  mandate ${mandateJson.mandate_id} signed ONCE: €5/tx, €20/day, ask me above €0.25.`);
log();

// 3. Mock provider + provider key into the vault. -----------------------------
execFileSync('node', [cli, 'vault', 'import-env'], {
  env: { ...process.env, ...vaultEnv, ANTHROPIC_API_KEY: 'sk-ant-demo-not-a-secret' },
  stdio: 'ignore',
});
mock = createServer((req, res) => {
  let body = '';
  req.on('data', (chunk) => (body += chunk));
  req.on('end', () => {
    res.setHeader('content-type', 'application/json');
    res.end(
      JSON.stringify({
        id: 'msg-demo',
        type: 'message',
        content: [{ type: 'text', text: 'step done' }],
        usage: { input_tokens: 25, output_tokens: 60 },
      })
    );
  });
});
await new Promise((resolve) => mock.listen(0, '127.0.0.1', resolve));

// 4. Gateway in PASSPORT mode with the file push channel. ---------------------
gateway = spawn('node', [join(root, 'packages/gateway/dist/start.js')], {
  env: {
    ...process.env,
    ...vaultEnv,
    ANTHROPIC_BASE_URL: `http://127.0.0.1:${mock.address().port}`,
    MANDARE_GATEWAY_AUTH: 'passport',
    MANDARE_TRUST_AUTHORITY: passportJson.authority_did,
    MANDARE_MANDATE_PATH: mandatePath,
    MANDARE_GATEWAY_PORT: '0',
    MANDARE_USD_PER_LEDGER_UNIT: '1.08',
    MANDARE_NOTIFIER: 'file',
    MANDARE_NOTIFY_FILE: notifyFile,
    MANDARE_APPROVAL_TIMEOUT_MS: '20000',
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
log(`[door]   gateway up at ${gatewayUrl} — passport auth (RFC 9421 + Content-Digest), push channel wired.`);
log();

// 5. The agent: passport + private key, signing every request. ----------------
const agentKey = JSON.parse(readFileSync(join(workDir, 'agent.key.json'), 'utf8'));
const credential = readFileSync(join(workDir, 'agent.passport.sdjwt'), 'utf8').trim();
const PATH = '/v1/messages';

async function agentCall(maxTokens, label) {
  const bodyText = JSON.stringify({
    model: 'claude-haiku-4-5',
    max_tokens: maxTokens,
    messages: [{ role: 'user', content: label }],
  });
  const headers = await passport.signMandareRequest({
    method: 'POST',
    url: `${gatewayUrl}${PATH}`,
    bodyBytes: new TextEncoder().encode(bodyText),
    agentDid: passportJson.agent_did,
    agentPrivateJwk: agentKey.privateJwk,
    agentPublicJwk: agentKey.publicJwk,
    passport: credential,
  });
  return fetch(`${gatewayUrl}${PATH}`, {
    method: 'POST',
    headers: { ...headers, 'content-type': 'application/json' },
    body: bodyText,
  });
}

/** The "human's phone": watch the push channel for the next notification. */
let notifyOffset = 0;
async function nextNotification() {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (existsSync(notifyFile)) {
      const lines = readFileSync(notifyFile, 'utf8').trim().split('\n').filter(Boolean);
      if (lines.length > notifyOffset) {
        const line = lines[notifyOffset];
        notifyOffset += 1;
        return JSON.parse(line);
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('no approval push arrived within 15s');
}

async function decide(notification, body) {
  const response = await fetch(`${gatewayUrl}/approvals/${notification.approvalId}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body,
  });
  return response;
}

// 6. The multi-step task: six in-scope calls, ZERO prompts. -------------------
const IN_SCOPE_STEPS = 6;
log(`[agent]  running the task: ${IN_SCOPE_STEPS} in-scope steps under the one mandate…`);
const inScopeStatuses = [];
for (let step = 1; step <= IN_SCOPE_STEPS; step += 1) {
  const response = await agentCall(200, `step ${step}: gather sources`);
  inScopeStatuses.push(response.status);
  log(`[agent]  step ${step}/${IN_SCOPE_STEPS}  signed call (~€0.001)          → ${response.status} OK — no human involved`);
}
log(`         ${IN_SCOPE_STEPS} calls, 0 permission prompts. The mandate IS the answer.`);
log();

// 7. Over-threshold call #1: pause → push → APPROVE → the task continues. -----
log('[agent]  step 7: big synthesis call (~€0.28, above the €0.25 threshold)…');
const heldApprove = agentCall(60_000, 'step 7: full synthesis');
const push1 = await nextNotification();
log(`[push]   → "${push1.title}"`);
log(`[human]  taps APPROVE on the phone.`);
const approveResponse = await decide(push1, push1.approveBody);
const approved = await heldApprove;
log(`[agent]  held call resumed                 → ${approved.status} OK (approval recorded on the ledger)`);
log();

// 8. Over-threshold call #2: pause → push → DENY → refusal on the ledger. -----
log('[agent]  step 8: ANOTHER big call (agent got ambitious)…');
const heldDeny = agentCall(60_000, 'step 8: unnecessary mega-run');
const push2 = await nextNotification();
log(`[push]   → "${push2.title}"`);
log('[human]  taps DENY.');
const denyResponse = await decide(push2, push2.denyBody);
const denied = await heldDeny;
const deniedBody = await denied.json();
log(`[agent]  held call refused                 → ${denied.status} ${deniedBody.code}`);
log(`         the "no" is ledger entry ${(deniedBody.denied_entry ?? '').slice(0, 16)}…`);
log();

gateway.kill('SIGTERM');
await new Promise((resolve) => gateway.on('exit', resolve));
gateway = null;
mock.close();
mock = null;

// 9. The proof: the whole sequence, human decisions included. -----------------
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

// 10. ACCEPTANCE ASSERTIONS (this script IS the acceptance test, R7). ---------
if (inScopeStatuses.some((status) => status !== 200)) fail(`in-scope calls not all 200: ${inScopeStatuses}`);
if (approveResponse.status !== 200) fail(`approve decision endpoint returned ${approveResponse.status}`);
if (approved.status !== 200) fail(`approved held call returned ${approved.status}`);
if (denyResponse.status !== 200) fail(`deny decision endpoint returned ${denyResponse.status}`);
if (denied.status !== 403 || deniedBody.code !== 'APPROVAL_DENIED') {
  fail(`denied call was not refused with APPROVAL_DENIED (got ${denied.status} ${deniedBody.code})`);
}
if (!/^[0-9a-f]{64}$/.test(deniedBody.denied_entry ?? '')) fail('the denial was not recorded as a ledger entry');
if (verify.code !== 0) fail(`verify exited ${verify.code}: ${verify.stderr}`);
if (!verify.stdout.includes('chain:    VALID')) fail('chain not VALID');
if (!verify.stdout.includes('counters: CONSISTENT')) fail('spend counters not CONSISTENT with replay');
if (!verify.stdout.includes('approvals:')) fail('approval trail missing from verify');
if (!/APPROVED by did:key:/.test(verify.stdout)) fail('the human APPROVAL is not proven in the trail');
if (!/DENIED by did:key:/.test(verify.stdout)) fail('the human DENIAL is not proven in the trail');

log('════════════════════════════════════════════════════════════════════');
log(` DEMO PASS: ${IN_SCOPE_STEPS} in-scope calls ran with zero prompts under ONE signed`);
log(' mandate; one over-threshold call paused for a real human APPROVE and');
log(' continued; a second was DENIED with the refusal on the ledger; and');
log(' mandare verify proves the whole sequence — human decisions included.');
log('════════════════════════════════════════════════════════════════════');

if (process.env.MANDARE_DEMO_CAPTURE) {
  const capturePath = join(root, process.env.MANDARE_DEMO_CAPTURE);
  mkdirSync(dirname(capturePath), { recursive: true });
  writeFileSync(capturePath, `${captured.join('\n')}\n`);
  console.log(`\n[demo] terminal capture written to ${process.env.MANDARE_DEMO_CAPTURE}`);
}
rmSync(workDir, { recursive: true, force: true });
