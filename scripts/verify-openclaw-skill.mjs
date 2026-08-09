#!/usr/bin/env node
/**
 * Third-party check of a packaged OpenClaw skill: every file hash in the
 * `clawhub.skill.verify.v1` envelope must match the bytes on disk, and the
 * Ed25519 signature (when present) must verify over the canonical envelope
 * core. Anyone can run this before trusting a skill download — no Mandare
 * code required beyond Node.
 *
 * Trust contract (S8/P1): a "VERIFIED" verdict (exit 0) requires the package
 * to be cryptographically bound to a publisher key you TRUST. You establish
 * trust by pinning that key with --expect-key <hex> (obtained out-of-band from
 * the GitHub release / mandare.dev/security). Without it the tool cannot know
 * whose signature it is looking at, so it refuses — an UNSIGNED package (a
 * re-packaged/tampered skill regenerates every hash + SHA256SUMS, so those
 * prove nothing) and a signature under an UNPINNED/attacker key both FAIL.
 * --allow-unsigned is a local-dev escape hatch ONLY (never for a download).
 *
 * Usage:
 *   node scripts/verify-openclaw-skill.mjs <packaged-skill-dir> --expect-key <hex>
 *   node scripts/verify-openclaw-skill.mjs <packaged-skill-dir> --allow-unsigned   # dev only
 */
import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

let dir;
let expectKey;
let allowUnsigned = false;
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i += 1) {
  const arg = argv[i];
  if (arg === '--expect-key') {
    expectKey = String(argv[i + 1] ?? '').toLowerCase();
    i += 1;
  } else if (arg === '--allow-unsigned') {
    allowUnsigned = true;
  } else if (dir === undefined) {
    dir = arg;
  } else {
    console.error(`unexpected argument: ${arg}`);
    process.exit(2);
  }
}
if (dir === undefined) {
  console.error(
    'usage: verify-openclaw-skill.mjs <packaged-skill-dir> [--expect-key <hex>] [--allow-unsigned]'
  );
  process.exit(2);
}
if (expectKey !== undefined && !/^[0-9a-f]{64}$/.test(expectKey)) {
  console.error('FAIL: --expect-key must be 64 lowercase hex chars (an Ed25519 public key)');
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
  if (allowUnsigned) {
    console.warn(
      'envelope: UNSIGNED — accepted ONLY because --allow-unsigned was passed (local dev build).\n' +
        '  NEVER trust an unsigned skill from a third party: a re-packaged/tampered skill\n' +
        '  regenerates every file hash and SHA256SUMS and produces exactly this envelope.'
    );
  } else {
    console.error(
      'FAIL: envelope is UNSIGNED — refusing. File hashes and SHA256SUMS are recomputed from\n' +
        '  the envelope, so a tampered/re-packaged skill reproduces them; only a publisher\n' +
        '  signature binds the package to a real publisher. Verify a signed release with\n' +
        '  --expect-key <hex>, or pass --allow-unsigned for your OWN local dev build.'
    );
    failures += 1;
  }
} else {
  const keyHex = String(envelope.signature.publicKeyHex ?? '').toLowerCase();
  let sigOk = false;
  if (/^[0-9a-f]{64}$/.test(keyHex)) {
    const { schema, skill, version, publisher, files } = envelope;
    const signedBytes = Buffer.from(canonicalJson({ schema, skill, version, publisher, files }), 'utf8');
    const publicKey = createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(keyHex, 'hex').toString('base64url') },
      format: 'jwk',
    });
    sigOk = edVerify(null, signedBytes, publicKey, Buffer.from(envelope.signature.value, 'base64url'));
  }
  if (!sigOk) {
    console.error('FAIL: envelope signature does not verify');
    failures += 1;
  } else if (expectKey === undefined) {
    // A self-consistent signature proves only that SOMEONE signed the package —
    // an attacker signs a tampered skill under their OWN key and embeds that key
    // in the envelope. With no pinned key there is no publisher to bind to, so
    // this is NOT a pass (S8/P1). The key is printed so the operator can pin it.
    console.error(
      `FAIL: signature is self-consistent (key ${keyHex.slice(0, 12)}…) but NO --expect-key was given.\n` +
        '  A tampered package can carry a valid signature under an ATTACKER key. Re-run with\n' +
        '  --expect-key <hex> using the key published in the GitHub release / mandare.dev/security.'
    );
    failures += 1;
  } else if (keyHex !== expectKey) {
    console.error(`FAIL: signed by an UNEXPECTED key\n  got      ${keyHex}\n  expected ${expectKey}`);
    failures += 1;
  } else {
    console.log(`envelope: signature VALID and matches --expect-key (ed25519, ${keyHex.slice(0, 12)}…)`);
  }
}

if (failures > 0) {
  console.error(`\n${failures} check(s) FAILED — do not trust this skill package`);
  process.exit(1);
}
console.log('\nskill package VERIFIED');
