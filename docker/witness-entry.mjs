#!/usr/bin/env node
/**
 * Witness container entry: ensure the witness key exists, publish its PUBLIC
 * half onto the shared volume for the gateway/dashboard/demo containers,
 * then run the reference witness.
 *
 * The shared-volume key handoff is the SOLO-MODE stand-in for out-of-band
 * distribution: one machine, one operator, one trust domain. In team mode
 * the witness runs elsewhere and you carry MANDARE_WITNESS_PUBLIC_KEY over a
 * real out-of-band channel — a witness cannot vouch for itself.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

import { loadOrCreateDoorKey } from '../packages/ledger/dist/index.js';
import { runWitnessServe } from '../apps/cli/dist/witness-cmd.js';

const dbPath = process.env.MANDARE_WITNESS_DB ?? '/data/witness/witness.db';
const keyPath = process.env.MANDARE_WITNESS_KEY ?? '/data/witness/witness-key.pem';
const publicHexPath = process.env.MANDARE_WITNESS_PUBLIC_HEX ?? '/data/witness/public.hex';
const anchor = process.env.MANDARE_WITNESS_ANCHOR === 'ots' ? 'ots' : 'mock';

mkdirSync(dirname(keyPath), { recursive: true });
const key = loadOrCreateDoorKey(keyPath);
writeFileSync(publicHexPath, `${key.publicKeyHex}\n`);
console.log(`witness-entry: public key ${key.publicKeyHex} → ${publicHexPath}`);

process.exitCode = await runWitnessServe({
  dbPath,
  host: '0.0.0.0',
  port: 9411,
  keyPath,
  anchor,
  anchorIntervalHours: 24,
});
