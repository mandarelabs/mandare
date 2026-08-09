#!/usr/bin/env node
/**
 * Gateway container entry:
 *   1. wait for the witness's public key on the shared volume (fail closed
 *      after 60s — a configured witness that never appears must not silently
 *      degrade into an unwitnessed door),
 *   2. create the demo mandate on first run (none exists yet) so the stack
 *      works out of the box with zero secrets,
 *   3. start the real gateway (`packages/gateway/dist/start.js`).
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';

const mandatePath = process.env.MANDARE_MANDATE_PATH ?? '/data/mandate.json';
const publicHexPath = process.env.MANDARE_WITNESS_PUBLIC_HEX;
const witnessUrl = process.env.MANDARE_WITNESS_URL;

if (witnessUrl !== undefined && witnessUrl !== '' && publicHexPath !== undefined) {
  const deadline = Date.now() + 60_000;
  while (!existsSync(publicHexPath)) {
    if (Date.now() > deadline) {
      console.error(`gateway-entry: witness public key never appeared at ${publicHexPath} — refusing to start unwitnessed`);
      process.exit(1);
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  const publicKeyHex = readFileSync(publicHexPath, 'utf8').trim();
  if (!/^[0-9a-f]{64}$/.test(publicKeyHex)) {
    console.error(`gateway-entry: ${publicHexPath} does not contain a 64-hex Ed25519 key`);
    process.exit(1);
  }
  process.env.MANDARE_WITNESS_PUBLIC_KEY = publicKeyHex;
  console.log(`gateway-entry: witness key loaded (${publicKeyHex.slice(0, 12)}…)`);
}

if (!existsSync(mandatePath)) {
  const perTx = process.env.MANDARE_DEMO_PER_TX ?? '5';
  const perDay = process.env.MANDARE_DEMO_PER_DAY ?? '20';
  const total = process.env.MANDARE_DEMO_TOTAL ?? '100';
  execFileSync('node', [
    new URL('../scripts/dev-mandate.mjs', import.meta.url).pathname,
    '--out', mandatePath,
    '--per-tx', perTx,
    '--per-day', perDay,
    '--per-task', perDay,
    '--total', total,
    '--approval-above', perTx,
  ], { stdio: 'inherit' });
  console.log(`gateway-entry: demo mandate created at ${mandatePath} (€${perTx}/call · €${perDay}/day · €${total} total)`);
  console.log('gateway-entry: issue a real one with `mandare mandate issue` and replace the file.');
}

await import('../packages/gateway/dist/start.js');
