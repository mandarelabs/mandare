#!/usr/bin/env node
/**
 * License-boundary gate (LICENSING.md, BUILD-DECISIONS Q20): no Apache-2.0
 * package may depend on an AGPL package — runtime `dependencies` and
 * `peerDependencies` are checked. devDependencies are exempt (tests may
 * exercise AGPL code without it entering the published artifact).
 *
 * Belt-and-suspenders with Turborepo Boundaries tags; this script is the
 * authoritative CI gate.
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const APACHE = 'Apache-2.0';
const AGPL = 'AGPL-3.0-only';
const root = join(dirname(fileURLToPath(import.meta.url)), '..');

const packages = new Map();
for (const group of ['packages', 'apps']) {
  const groupDir = join(root, group);
  if (!existsSync(groupDir)) continue;
  for (const name of readdirSync(groupDir)) {
    const manifestPath = join(groupDir, name, 'package.json');
    if (!existsSync(manifestPath)) continue;
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    packages.set(manifest.name, {
      license: manifest.license,
      path: relative(root, manifestPath),
      runtimeDeps: Object.keys({ ...manifest.dependencies, ...manifest.peerDependencies }),
    });
  }
}

const violations = [];

for (const [name, info] of packages) {
  if (info.license !== APACHE && info.license !== AGPL) {
    violations.push(`${name} (${info.path}) declares unexpected license '${info.license}'`);
  }
  if (info.license !== APACHE) continue;
  for (const dep of info.runtimeDeps) {
    const target = packages.get(dep);
    if (target !== undefined && target.license !== APACHE) {
      violations.push(
        `${name} (Apache-2.0) depends on ${dep} (${target.license}) — ` +
          'Apache packages must never import AGPL code (LICENSING.md)'
      );
    }
  }
}

if (violations.length > 0) {
  console.error('LICENSE BOUNDARY VIOLATIONS:\n');
  for (const violation of violations) {
    console.error(`  ✗ ${violation}`);
  }
  process.exit(1);
}
console.log(`license boundaries OK (${packages.size} workspace packages checked)`);
