#!/usr/bin/env node
/**
 * Package the OpenClaw skill with its `clawhub.skill.verify.v1` trust
 * envelope (BUILD-DECISIONS Q18): sha256 of every skill file + an Ed25519
 * signature over the canonical envelope when a release key is provided.
 * ClawHub itself has no publisher signing chain yet — shipping one anyway is
 * the point (our signed-release posture exceeds the platform norm).
 *
 * Usage:
 *   node scripts/package-openclaw-skill.mjs [--out dist/openclaw-skill]
 *   MANDARE_RELEASE_KEY_PEM=path/to/release-key.pem  → signed envelope
 *   (no key → unsigned envelope with "signature": null; release.yml signs
 *    with the real key on tagged releases, S9)
 */
import { createHash, createPrivateKey, createPublicKey, sign as edSign } from 'node:crypto';
import { cpSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const skillDir = join(root, 'integrations/openclaw/mandare');
const outFlag = process.argv.indexOf('--out');
const outDir = resolve(root, outFlag === -1 ? 'dist/openclaw-skill' : process.argv[outFlag + 1]);

/** Stable key order so the signed bytes are reproducible. */
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

function listFiles(dir) {
  const files = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      files.push(...listFiles(path));
    } else {
      files.push(path);
    }
  }
  return files.sort();
}

const version = JSON.parse(readFileSync(join(root, 'apps/cli/package.json'), 'utf8')).version;

const files = {};
for (const path of listFiles(skillDir)) {
  const rel = relative(skillDir, path);
  files[rel] = `sha256:${createHash('sha256').update(readFileSync(path)).digest('hex')}`;
}

const core = {
  schema: 'clawhub.skill.verify.v1',
  skill: 'mandare',
  version,
  publisher: { github: 'mandarelabs', repository: 'https://github.com/mandarelabs/mandare' },
  files,
};

let signature = null;
let publicKeyHex = null;
const keyPath = process.env.MANDARE_RELEASE_KEY_PEM;
if (keyPath !== undefined && keyPath !== '') {
  const pem = readFileSync(keyPath, 'utf8');
  const privateKey = createPrivateKey(pem);
  if (privateKey.asymmetricKeyType !== 'ed25519') {
    console.error('release key must be Ed25519');
    process.exit(1);
  }
  const signedBytes = Buffer.from(canonicalJson(core), 'utf8');
  signature = edSign(null, signedBytes, privateKey).toString('base64url');
  const publicJwk = createPublicKey(privateKey).export({ format: 'jwk' });
  publicKeyHex = Buffer.from(publicJwk.x, 'base64url').toString('hex');
}

const envelope = {
  ...core,
  signature:
    signature === null
      ? null
      : { alg: 'ed25519', over: 'canonical-json(schema,skill,version,publisher,files)', publicKeyHex, value: signature },
};

rmSync(outDir, { recursive: true, force: true });
mkdirSync(outDir, { recursive: true });
cpSync(skillDir, outDir, { recursive: true });
writeFileSync(join(outDir, 'clawhub.skill.verify.v1.json'), `${JSON.stringify(envelope, null, 2)}\n`);

const sums = Object.entries(files)
  .map(([rel, hash]) => `${hash.replace('sha256:', '')}  ${rel}`)
  .join('\n');
writeFileSync(join(outDir, 'SHA256SUMS'), `${sums}\n`);

console.log(`skill packaged → ${relative(root, outDir)}`);
console.log(`  files: ${Object.keys(files).length}, version ${version}`);
console.log(
  signature === null
    ? '  envelope: UNSIGNED (set MANDARE_RELEASE_KEY_PEM to sign; release.yml signs tagged releases)'
    : `  envelope: signed (ed25519, key ${publicKeyHex.slice(0, 12)}…)`
);
