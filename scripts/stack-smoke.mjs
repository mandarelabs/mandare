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

/** `KEY: value` lines of one compose service's environment block, defaults resolved. */
function composeServiceEnv(yaml, service) {
  const block = new RegExp(`^  ${service}:\\n[\\s\\S]*?^    environment:\\n((?:      .*\\n|\\s*#.*\\n)+)`, 'm').exec(yaml);
  if (block === null) fail(`compose.yaml: no environment block for service ${service}`);
  const env = {};
  for (const line of block[1].split('\n')) {
    const match = /^      ([A-Z0-9_]+): (.*)$/.exec(line);
    if (match === null) continue;
    const raw = match[2].trim().replace(/^"(.*)"$/, '$1');
    const withDefault = /^\$\{[A-Z0-9_]+:-(.*)\}$/.exec(raw);
    env[match[1]] = withDefault === null ? raw : withDefault[1];
  }
  return env;
}

function start(name, script, env, readyMatch, baseEnv = process.env) {
  const child = spawn('node', [join(root, script)], {
    env: { ...baseEnv, ...env },
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

// The gateway's env comes FROM compose.yaml (D-1): every variable the
// compose service declares, with its `${VAR:-default}` default — no private
// overrides. Only topology differs (host paths, host-local ports/URLs), and
// the parent's MANDARE_* variables are scrubbed so a developer's shell cannot
// soften the run either (the velocity cap once hid behind exactly that).
const TOPOLOGY = {
  MANDARE_LEDGER_DB: join(dataDir, 'ledger.db'),
  MANDARE_MANDATE_PATH: join(dataDir, 'mandate.json'),
  MANDARE_GATEWAY_PORT: '18484',
  ANTHROPIC_BASE_URL: 'http://127.0.0.1:18899',
  OPENAI_BASE_URL: 'http://127.0.0.1:18899/v1',
  MANDARE_WITNESS_URL: 'http://127.0.0.1:9411',
  MANDARE_WITNESS_PUBLIC_HEX: join(dataDir, 'witness/public.hex'),
};
const composeGatewayEnv = composeServiceEnv(composeYaml, 'gateway');
for (const key of Object.keys(TOPOLOGY)) {
  if (!(key in composeGatewayEnv)) fail(`compose.yaml gateway no longer declares ${key} — update TOPOLOGY`);
}
const inheritedEnv = Object.fromEntries(
  Object.entries(process.env).filter(([key]) => !/^(MANDARE_|ANTHROPIC_|OPENAI_|OPENROUTER_)/.test(key))
);
const gatewayEnv = { ...composeGatewayEnv, ...TOPOLOGY };
console.log(`[stack] gateway env from compose.yaml: ${Object.keys(composeGatewayEnv).length} variables`);
await start('gateway', 'docker/gateway-entry.mjs', gatewayEnv, /listening on (http:\/\/[\d.]+:\d+)/, inheritedEnv);

// The user-facing demo, exactly as `docker compose run --rm demo` runs it.
const demo = spawn('node', [join(root, 'scripts/compose-demo.mjs')], {
  env: {
    ...inheritedEnv,
    MANDARE_GATEWAY_URL: 'http://127.0.0.1:18484',
    MANDARE_LEDGER_DB: join(dataDir, 'ledger.db'),
    MANDARE_WITNESS_URL: 'http://127.0.0.1:9411',
    MANDARE_WITNESS_PUBLIC_HEX: join(dataDir, 'witness/public.hex'),
  },
  stdio: ['ignore', 'pipe', 'inherit'],
});
let demoOut = '';
demo.stdout.on('data', (chunk) => {
  demoOut += chunk;
  process.stdout.write(chunk);
});
const demoCode = await new Promise((resolve) => demo.on('exit', resolve));
if (demoCode !== 0) fail(`compose-demo exited ${demoCode}`);

// DRIFT GUARD (D-1): the refusal the docker path prints is the one CI's
// compose-smoke greps and the one README / quickstart / Show HN promise.
const refused = /^ REFUSED: call #(\d+) (\S+)$/m.exec(demoOut);
if (refused === null) fail('compose-demo printed no REFUSED line');
const refusedLine = `REFUSED: call #${refused[1]} ${refused[2]}`;
if (!readFileSync(join(root, '.github/workflows/ci.yml'), 'utf8').includes(`grep -q "${refusedLine}"`)) {
  fail(`ci.yml compose-smoke does not assert '${refusedLine}' — update it to what the demo prints`);
}
for (const doc of ['README.md', 'apps/docs/content/docs/quickstart.mdx', 'docs/launch/SHOW-HN.md']) {
  if (!readFileSync(join(root, doc), 'utf8').includes(`call #${refused[1]}`)) {
    fail(`${doc} does not state the docker demo's real refusal (call #${refused[1]})`);
  }
}
console.log(`[stack] docker-path refusal '${refusedLine}' matches CI and the docs`);

for (const child of children) child.kill('SIGTERM');
await Promise.all(children.map((child) => new Promise((resolve) => child.on('exit', resolve))));
rmSync(dataDir, { recursive: true, force: true });
console.log('\nSTACK SMOKE PASS: witness + mock + gateway entries wired exactly as compose runs them.');
