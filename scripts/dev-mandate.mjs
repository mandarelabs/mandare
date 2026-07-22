#!/usr/bin/env node
/**
 * Dev-mandate generator: writes a schema-valid, Ed25519-signed mandate JSON
 * for local runs, the smoke test, and the runaway demo. The owner key is
 * generated ephemerally (or loaded from --owner-key PEM) — REAL signature,
 * dev-only trust: gateways verify mandate signatures from S4 (SD-JWT).
 *
 * Usage:
 *   node scripts/dev-mandate.mjs --out mandate.json \
 *     [--agent did:mandare:dev-agent] [--currency EUR] \
 *     [--per-tx 5] [--per-day 20] [--per-task 20] [--total 100] \
 *     [--approval-above 5] [--valid-hours 24] [--owner-key owner.pem]
 *
 * Cap flags are WHOLE currency units (converted to micros internally).
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as edSign,
} from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const spec = await import(join(root, 'packages', 'spec', 'dist', 'index.js'));

const MICROS = 1_000_000;

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  if (index === -1 || index + 1 >= process.argv.length) return fallback;
  return process.argv[index + 1];
}

function unitsToMicros(name, fallback) {
  const value = Number(arg(name, String(fallback)));
  if (!Number.isFinite(value) || value < 0) {
    console.error(`--${name} must be a non-negative number of currency units`);
    process.exit(2);
  }
  return Math.round(value * MICROS);
}

const outPath = arg('out', null);
if (outPath === null) {
  console.error('usage: dev-mandate.mjs --out <path> [caps…] — see file header');
  process.exit(2);
}
const agent = arg('agent', 'did:mandare:dev-agent');
const currency = arg('currency', 'EUR');
const validHours = Number(arg('valid-hours', '24'));
// --card: ONE spend scope covering BOTH rails (S5 cross-rail cap) + the
// card action classes. Default stays gateway-only for the frozen demos.
const withCard = process.argv.includes('--card');

// Owner key: ephemeral by default; --owner-key <pem> to reuse one.
const ownerKeyPath = arg('owner-key', null);
const privateKey =
  ownerKeyPath === null
    ? generateKeyPairSync('ed25519').privateKey
    : createPrivateKey(readFileSync(ownerKeyPath, 'utf8'));
// SPKI DER for Ed25519 = fixed 12-byte prefix + the 32 raw public key bytes.
const spkiDer = createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
const publicRaw = spkiDer.subarray(spkiDer.length - 32);

const now = Date.now();
const mandate = {
  schema_version: 1,
  id: `mnd_dev_${createHash('sha256').update(String(now)).digest('hex').slice(0, 12)}`,
  principal: 'did:mandare:dev-owner',
  agent,
  purpose: 'Development mandate: budgeted LLM calls through the local gateway',
  scopes: [
    {
      type: 'spend',
      currency,
      per_tx_max: unitsToMicros('per-tx', 5),
      per_day_max: unitsToMicros('per-day', 20),
      per_task_max: unitsToMicros('per-task', 20),
      total_cap: unitsToMicros('total', 100),
      rails: withCard ? ['gateway', 'card'] : ['gateway'],
      counterparties: 'any',
      categories: withCard ? [] : ['llm'],
    },
    {
      type: 'action',
      classes: withCard ? ['llm.call', 'card.purchase', 'card.create'] : ['llm.call'],
    },
  ],
  approvals: {
    rules: [{ above: unitsToMicros('approval-above', 5), currency, method: 'push' }],
  },
  valid_from: new Date(now - 60_000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
  valid_until: new Date(now + validHours * 3_600_000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
  revocation_ref: 'statuslist:dev#0',
};

// Sign canonical JSON of the mandate without `signature` (the S4 contract).
const canonical = spec.canonicalJson(mandate);
const signature = edSign(null, Buffer.from(canonical, 'utf8'), privateKey);

const signed = {
  ...mandate,
  signature: {
    alg: 'EdDSA',
    key_id: createHash('sha256').update(publicRaw).digest('hex'),
    key_provenance: 'software',
    value: signature.toString('base64url'),
  },
};

// Boundary-validate before writing — a dev tool must not emit invalid mandates.
spec.parseMandate(signed);
writeFileSync(outPath, `${JSON.stringify(signed, null, 2)}\n`);
console.log(`mandate ${signed.id} → ${outPath}`);
console.log(
  `  agent=${agent} caps: tx ${signed.scopes[0].per_tx_max / MICROS} / day ${signed.scopes[0].per_day_max / MICROS} / total ${signed.scopes[0].total_cap / MICROS} ${currency}`
);
