#!/usr/bin/env node
/**
 * Python client ↔ real door round-trip (S7): a vault-issued token, the
 * Python client's HMAC signing, a live token-auth gateway — accepted; the
 * wrong secret refused as BAD_POP. Skips loudly (exit 0) when python3 is
 * absent; CI has it.
 *
 * Run: pnpm sdk-py-smoke
 */
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

if (spawnSync('python3', ['--version']).status !== 0) {
  console.log('sdk-py smoke SKIPPED: python3 not available');
  process.exit(0);
}

const workDir = mkdtempSync(join(tmpdir(), 'mandare-pysdk-'));
const dbPath = join(workDir, 'ledger.db');
const mandatePath = join(workDir, 'mandate.json');

let gateway = null;
let mock = null;
function fail(message) {
  console.error(`SDK-PY SMOKE FAIL: ${message}`);
  if (gateway !== null) gateway.kill('SIGKILL');
  if (mock !== null) mock.close();
  process.exit(1);
}
process.on('uncaughtException', (error) => fail(error.stack ?? String(error)));
setTimeout(() => fail('timed out after 120s'), 120_000).unref();

execFileSync('node', [
  join(root, 'scripts/dev-mandate.mjs'),
  '--out', mandatePath,
  '--per-tx', '5', '--per-day', '20', '--per-task', '20', '--total', '100',
  '--approval-above', '5',
]);

mock = createServer((_req, res) => {
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify({
    id: 'msg-pysdk', type: 'message',
    content: [{ type: 'text', text: 'ok' }],
    usage: { input_tokens: 5, output_tokens: 50 },
  }));
});
await new Promise((resolve) => mock.listen(0, '127.0.0.1', resolve));

// Vault (file backend) + a real scoped token, exactly as an operator would.
const vaultEnv = {
  ...process.env,
  MANDARE_VAULT: '1',
  MANDARE_VAULT_BACKEND: 'file',
  MANDARE_VAULT_DB: join(workDir, 'vault.db'),
  MANDARE_VAULT_KEY_FILE: join(workDir, 'vault.masterkey'),
  MANDARE_LEDGER_DB: dbPath,
};
const { readFileSync } = await import('node:fs');
const mandateId = JSON.parse(readFileSync(mandatePath, 'utf8')).id;
// Vault mode ignores env provider keys — bootstrap the (fake) key into the
// vault exactly as an operator would.
execFileSync('node', [join(root, 'apps/cli/dist/main.js'), 'vault', 'import-env'], {
  env: { ...vaultEnv, ANTHROPIC_API_KEY: 'pysdk-smoke-not-a-secret' },
  stdio: 'pipe',
});
const grantJson = execFileSync(
  'node',
  [join(root, 'apps/cli/dist/main.js'), 'token', 'issue',
   '--actor', 'did:mandare:dev-agent', '--mandate', mandateId, '--json'],
  { env: vaultEnv, encoding: 'utf8' }
);
const grant = JSON.parse(grantJson);
const tokenFile = join(workDir, 'agent.token.json');
writeFileSync(tokenFile, grantJson, { mode: 0o600 });

gateway = spawn('node', [join(root, 'packages/gateway/dist/start.js')], {
  env: {
    ...vaultEnv,
    ANTHROPIC_BASE_URL: `http://127.0.0.1:${mock.address().port}`,
    MANDARE_MANDATE_PATH: mandatePath,
    MANDARE_GATEWAY_PORT: '0',
    MANDARE_LEDGER_CURRENCY: 'EUR',
    MANDARE_USD_PER_LEDGER_UNIT: '1.08',
    MANDARE_GATEWAY_AUTH: 'token',
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
  gateway.on('exit', (code) => reject(new Error(`gateway exited early (${code})`)));
});

const pyScript = `
import json, sys
sys.path.insert(0, ${JSON.stringify(join(root, 'packages/sdk-py'))})
from mandare_sdk import MandareClient, MandareRefused, TokenCredentials, load_token_file
# Refusal shape note: 403 policy denials carry {code, reasons[]}; 401 token
# refusals carry {code, reason} — the client normalizes both into MandareRefused.

creds = load_token_file(${JSON.stringify(tokenFile)})
client = MandareClient(${JSON.stringify('GATEWAY_URL')}, creds, timeout_seconds=15)
print("PY start", flush=True)
reply = client.messages({"model": "claude-haiku-4-5", "max_tokens": 64,
                         "messages": [{"role": "user", "content": "hi"}]})
print("PY first call ok", flush=True)
assert reply["id"] == "msg-pysdk", reply

thief = MandareClient(${JSON.stringify('GATEWAY_URL')},
                      TokenCredentials(creds.token_id, "wrong-secret"), timeout_seconds=15)
try:
    thief.messages({"model": "claude-haiku-4-5", "max_tokens": 64,
                    "messages": [{"role": "user", "content": "hi"}]})
    raise SystemExit("thief call was NOT refused")
except MandareRefused as refusal:
    assert refusal.code == "BAD_POP", refusal
    assert refusal.status == 401, refusal
print("PY OK")
`.replaceAll(JSON.stringify('GATEWAY_URL'), JSON.stringify(gatewayUrl));

// Async spawn, NOT spawnSync: the mock provider lives in THIS process, and a
// blocked event loop would deadlock gateway → mock → python (found the hard
// way — spawnSync starved the mock and every side waited on the other).
const py = await new Promise((resolve) => {
  const child = spawn('python3', ['-c', pyScript], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => (stdout += chunk));
  child.stderr.on('data', (chunk) => (stderr += chunk));
  child.on('exit', (status) => resolve({ status, stdout, stderr }));
});
if (py.status !== 0 || !py.stdout.includes('PY OK')) {
  fail(`python round-trip failed:\n${py.stdout}\n${py.stderr}`);
}
console.log('[sdk-py] real token accepted; wrong secret refused (BAD_POP)');

gateway.kill('SIGTERM');
await new Promise((resolve) => gateway.on('exit', resolve));
gateway = null;
mock.close();
mock = null;
rmSync(workDir, { recursive: true, force: true });
console.log('SDK-PY SMOKE PASS');
