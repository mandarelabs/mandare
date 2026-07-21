#!/usr/bin/env node
/**
 * Claude Code PostToolUse hook (BUILD-SESSION-PLAN §2): after every Edit/Write
 * of a TypeScript source file, typecheck the containing package. Exit 2 blocks
 * and feeds the errors back to the session.
 */
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

let input = '';
for await (const chunk of process.stdin) {
  input += chunk;
}

let filePath;
try {
  filePath = JSON.parse(input)?.tool_input?.file_path;
} catch {
  process.exit(0);
}
if (typeof filePath !== 'string' || !/\.(ts|mts|cts)$/.test(filePath)) {
  process.exit(0);
}

const rel = relative(root, filePath);
const parts = rel.split(sep);
const isWorkspaceFile = (parts[0] === 'packages' || parts[0] === 'apps') && parts.length > 2;
if (!isWorkspaceFile || rel.startsWith('..')) {
  process.exit(0);
}
const packageDir = join(parts[0], parts[1]);
if (!existsSync(join(root, packageDir, 'package.json'))) {
  process.exit(0);
}

const result = spawnSync(
  'pnpm',
  ['--filter', `./${packageDir}`, 'run', '--if-present', 'typecheck'],
  { cwd: root, encoding: 'utf8', timeout: 120_000 }
);

if (result.status !== 0) {
  console.error(`typecheck failed for ${packageDir} after editing ${rel}:\n`);
  console.error((result.stdout ?? '') + (result.stderr ?? ''));
  process.exit(2);
}
process.exit(0);
