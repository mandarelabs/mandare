#!/usr/bin/env node
/**
 * Release-side signing of the OpenClaw skill (release.yml's signing jobs and
 * skill-smoke run this exact path): package + sign the skill, pin-verify it
 * with the derived public key (the S8/P1 gate), and write that key's hex
 * OUTSIDE the package — the package must pass its own verifier as uploaded
 * (K-3: a RELEASE-KEY.hex inside it is an uncovered, added file).
 *
 * Usage:
 *   node scripts/sign-openclaw-skill-release.mjs --out <dir> --key <release-key.pem>
 *   node scripts/sign-openclaw-skill-release.mjs --out <dir> --ephemeral   # dry runs
 *
 * Output: <dir>/openclaw-skill/ (signed package) and <dir>/RELEASE-KEY.hex.
 */
import { execFileSync } from 'node:child_process';
import { createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

function argValue(flag) {
  const index = process.argv.indexOf(flag);
  return index === -1 ? undefined : process.argv[index + 1];
}

const outArg = argValue('--out');
const keyArg = argValue('--key');
const ephemeral = process.argv.includes('--ephemeral');
if (outArg === undefined || (keyArg === undefined) === !ephemeral) {
  console.error('usage: sign-openclaw-skill-release.mjs --out <dir> (--key <pem> | --ephemeral)');
  process.exit(2);
}

const outDir = resolve(outArg);
const packageDir = join(outDir, 'openclaw-skill');
const scratch = mkdtempSync(join(tmpdir(), 'mandare-skill-sign-'));
try {
  let keyPath = keyArg === undefined ? undefined : resolve(keyArg);
  if (ephemeral) {
    keyPath = join(scratch, 'ephemeral-release-key.pem');
    const { privateKey } = generateKeyPairSync('ed25519');
    writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    console.log('dry run: signing with an EPHEMERAL key');
  } else if (!existsSync(keyPath)) {
    console.error(`release key not found: ${keyPath}`);
    process.exit(1);
  }

  const publicJwk = createPublicKey(createPrivateKey(readFileSync(keyPath, 'utf8'))).export({ format: 'jwk' });
  const publicKeyHex = Buffer.from(publicJwk.x, 'base64url').toString('hex');

  mkdirSync(outDir, { recursive: true });
  execFileSync('node', [join(root, 'scripts/package-openclaw-skill.mjs'), '--out', packageDir], {
    stdio: 'inherit',
    env: { ...process.env, MANDARE_RELEASE_KEY_PEM: keyPath },
  });
  // The P1 gate: VERIFIED requires a signature from the PINNED key.
  execFileSync('node', [join(root, 'scripts/verify-openclaw-skill.mjs'), packageDir, '--expect-key', publicKeyHex], {
    stdio: 'inherit',
  });
  writeFileSync(join(outDir, 'RELEASE-KEY.hex'), `${publicKeyHex}\n`);
  console.log(`release public key: ${publicKeyHex} → ${join(outArg, 'RELEASE-KEY.hex')} (outside the package)`);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
