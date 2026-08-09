#!/usr/bin/env node
/**
 * Third-party check of a packaged OpenClaw skill: every file hash in the
 * `clawhub.skill.verify.v1` envelope must match the bytes on disk, and the
 * Ed25519 signature (when present) must verify over the canonical envelope
 * core. Anyone can run this before trusting a skill download — no Mandare
 * code required beyond Node.
 *
 * Usage: node scripts/verify-openclaw-skill.mjs <packaged-skill-dir>
 */
import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const dir = process.argv[2];
if (dir === undefined) {
  console.error('usage: verify-openclaw-skill.mjs <packaged-skill-dir>');
  process.exit(2);
}
if (!existsSync(join(dir, 'clawhub.skill.verify.v1.json'))) {
  console.error(
    `FAIL: ${dir} carries no clawhub.skill.verify.v1.json — not a PACKAGED skill.\n` +
      '  (Package one first: node scripts/package-openclaw-skill.mjs --out <dir>)'
  );
  process.exit(1);
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }
  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

const envelope = JSON.parse(readFileSync(join(dir, 'clawhub.skill.verify.v1.json'), 'utf8'));
if (envelope.schema !== 'clawhub.skill.verify.v1') {
  console.error(`FAIL: unexpected schema ${envelope.schema}`);
  process.exit(1);
}

let failures = 0;
for (const [rel, expected] of Object.entries(envelope.files)) {
  const actual = `sha256:${createHash('sha256').update(readFileSync(join(dir, rel))).digest('hex')}`;
  if (actual !== expected) {
    console.error(`FAIL: ${rel} hash mismatch\n  expected ${expected}\n  actual   ${actual}`);
    failures += 1;
  } else {
    console.log(`ok: ${rel}`);
  }
}

// ADDITIONS are tampering too: agents read whole skill directories, so a
// file the envelope never covered (injected instructions) must fail — as
// must a doctored SHA256SUMS (humans eyeball it). SHA256SUMS is DERIVED
// from the envelope, so recompute and compare rather than trust it.
function walk(base, current = base) {
  const entries = [];
  for (const name of readdirSync(current)) {
    const path = join(current, name);
    if (statSync(path).isDirectory()) {
      entries.push(...walk(base, path));
    } else {
      entries.push(relative(base, path));
    }
  }
  return entries;
}
const DERIVED = new Set(['clawhub.skill.verify.v1.json', 'SHA256SUMS']);
for (const rel of walk(dir)) {
  if (!DERIVED.has(rel) && envelope.files[rel] === undefined) {
    console.error(`FAIL: ${rel} is NOT covered by the envelope — an added file is a tampered package`);
    failures += 1;
  }
}
const expectedSums = `${Object.entries(envelope.files)
  .map(([rel, hash]) => `${hash.replace('sha256:', '')}  ${rel}`)
  .join('\n')}\n`;
if (existsSync(join(dir, 'SHA256SUMS'))) {
  const actualSums = readFileSync(join(dir, 'SHA256SUMS'), 'utf8');
  if (actualSums !== expectedSums) {
    console.error('FAIL: SHA256SUMS does not match the envelope (doctored checksum file)');
    failures += 1;
  } else {
    console.log('ok: SHA256SUMS matches the envelope');
  }
}

if (envelope.signature === null) {
  console.log('envelope: UNSIGNED (dev build — tagged releases are signed)');
} else {
  const { schema, skill, version, publisher, files } = envelope;
  const signedBytes = Buffer.from(canonicalJson({ schema, skill, version, publisher, files }), 'utf8');
  const publicKey = createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(envelope.signature.publicKeyHex, 'hex').toString('base64url') },
    format: 'jwk',
  });
  const ok = edVerify(null, signedBytes, publicKey, Buffer.from(envelope.signature.value, 'base64url'));
  if (!ok) {
    console.error('FAIL: envelope signature does not verify');
    failures += 1;
  } else {
    console.log(`envelope: signature VALID (ed25519, key ${envelope.signature.publicKeyHex.slice(0, 12)}…)`);
    console.log('  compare this key against the one published in the GitHub release / mandare.dev/security');
  }
}

if (failures > 0) {
  console.error(`\n${failures} check(s) FAILED — do not trust this skill package`);
  process.exit(1);
}
console.log('\nskill package VERIFIED');
