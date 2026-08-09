#!/usr/bin/env node
/**
 * The compose topology WITHOUT docker: runs the exact container entry
 * scripts (witness-entry, mock-provider, gateway-entry) as local processes
 * against a temp data dir, then executes `scripts/compose-demo.mjs` against
 * them — proving the self-host wiring end-to-end wherever node runs. CI runs
 * this AND the real `docker compose` path; locally it is the fast check.
 *
 * Run: pnpm stack-smoke
 */
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dataDir = mkdtempSync(join(tmpdir(), 'mandare-stack-'));

const children = [];
function fail(message) {
  console.error(`STACK SMOKE FAIL: ${message}`);
  for (const child of children) child.kill('SIGKILL');
  process.exit(1);
}

// Fixed ports mirror compose.yaml; a squatter (often a stray from an aborted
// earlier run) causes confusing downstream failures — refuse up front.
const { createServer: createProbe } = await import('node:net');
for (const port of [9411, 18899, 18484]) {
  await new Promise((resolve) => {
    const probe = createProbe();
    probe.once('error', () => {
      fail(`port ${port} is already in use — kill the squatter first (lsof -ti :${port} | xargs kill)`);
    });
    probe.listen(port, '127.0.0.1', () => probe.close(resolve));
  });
}
process.on('uncaughtException', (error) => fail(error.stack ?? String(error)));
setTimeout(() => fail('timed out after 300s'), 300_000).unref();

function start(name, script, env, readyMatch) {
  const child = spawn('node', [join(root, script)], {
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  children.push(child);
  child.stderr.on('data', (chunk) => process.stderr.write(`[${name}] ${chunk}`));
  return new Promise((resolve, reject) => {
    let output = '';
    child.stdout.on('data', (chunk) => {
      output += chunk;
      process.stdout.write(`[${name}] ${chunk}`);
      const match = output.match(readyMatch);
      if (match) resolve(match);
    });
    child.on('exit', (code) => reject(new Error(`${name} exited early (${code})`)));
  });
}

// PARITY GUARD: the smoke must exercise the same security-relevant settings
// compose.yaml declares — a smoke that quietly runs a softer configuration
// vouches for nothing (S7 review H1). Grep-assert the exact lines.
const { readFileSync } = await import('node:fs');
const composeYaml = readFileSync(join(root, 'compose.yaml'), 'utf8');
for (const mirrored of [
  'MANDARE_GATEWAY_HOST: 0.0.0.0',
  'MANDARE_GATEWAY_ALLOW_INSECURE_BIND: "1"',
  'MANDARE_WITNESS_ACK_MODE: ${MANDARE_WITNESS_ACK_MODE:-threshold}',
  'MANDARE_WITNESS_DB: /witness-state/witness.db',
]) {
  if (!composeYaml.includes(mirrored)) {
    fail(`compose.yaml no longer declares '${mirrored}' — update this smoke to match reality`);
  }
}

// Same env contract as compose.yaml (asserted above), host-local ports, and
// the witness's private state split from the shared dir exactly as compose
// splits its volumes. Deliberately NO pre-created directories here: the
// entry scripts must create their own dirs, as they do in fresh containers
// (a pre-creating harness masked exactly that bug once).
const witnessEnv = {
  MANDARE_WITNESS_DB: join(dataDir, 'witness-state/witness.db'),
  MANDARE_WITNESS_KEY: join(dataDir, 'witness-state/witness-key.pem'),
  MANDARE_WITNESS_PUBLIC_HEX: join(dataDir, 'witness/public.hex'),
  MANDARE_WITNESS_ANCHOR: 'mock',
};
await start('witness', 'docker/witness-entry.mjs', witnessEnv, /witness listening on (http:\/\/[\d.:]+)/);
// witness-entry binds 0.0.0.0:9411 — reach it via loopback below.

await start('mock', 'scripts/mock-provider.mjs', { MOCK_PORT: '18899', MOCK_HOST: '127.0.0.1' }, /listening on/);

const gatewayEnv = {
  MANDARE_LEDGER_DB: join(dataDir, 'ledger.db'),
  MANDARE_MANDATE_PATH: join(dataDir, 'mandate.json'),
  // 0.0.0.0 + the explicit opt-out, exactly as the compose service runs.
  MANDARE_GATEWAY_HOST: '0.0.0.0',
  MANDARE_GATEWAY_ALLOW_INSECURE_BIND: '1',
  MANDARE_GATEWAY_PORT: '18484',
  MANDARE_LEDGER_CURRENCY: 'EUR',
  MANDARE_USD_PER_LEDGER_UNIT: '1.08',
  MANDARE_DEMO_PER_TX: '5',
  MANDARE_DEMO_PER_DAY: '20',
  MANDARE_DEMO_TOTAL: '100',
  ANTHROPIC_BASE_URL: 'http://127.0.0.1:18899',
  ANTHROPIC_API_KEY: 'stack-smoke-not-a-secret',
  MANDARE_WITNESS_URL: 'http://127.0.0.1:9411',
  MANDARE_WITNESS_PUBLIC_HEX: join(dataDir, 'witness/public.hex'),
  MANDARE_WITNESS_ACK_MODE: 'threshold',
  MANDARE_MAX_CALLS_PER_MINUTE: '100000',
  MANDARE_VAULT: undefined,
};
await start('gateway', 'docker/gateway-entry.mjs', gatewayEnv, /listening on (http:\/\/[\d.]+:\d+)/);

// The user-facing demo, exactly as `docker compose run --rm demo` runs it.
const demo = spawn('node', [join(root, 'scripts/compose-demo.mjs')], {
  env: {
    ...process.env,
    MANDARE_GATEWAY_URL: 'http://127.0.0.1:18484',
    MANDARE_LEDGER_DB: join(dataDir, 'ledger.db'),
    MANDARE_WITNESS_URL: 'http://127.0.0.1:9411',
    MANDARE_WITNESS_PUBLIC_HEX: join(dataDir, 'witness/public.hex'),
  },
  stdio: ['ignore', 'inherit', 'inherit'],
});
const demoCode = await new Promise((resolve) => demo.on('exit', resolve));
if (demoCode !== 0) fail(`compose-demo exited ${demoCode}`);

for (const child of children) child.kill('SIGTERM');
await Promise.all(children.map((child) => new Promise((resolve) => child.on('exit', resolve))));
rmSync(dataDir, { recursive: true, force: true });
console.log('\nSTACK SMOKE PASS: witness + mock + gateway entries wired exactly as compose runs them.');
