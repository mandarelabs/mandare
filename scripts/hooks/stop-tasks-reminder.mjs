#!/usr/bin/env node
/**
 * Claude Code Stop hook (BUILD-SESSION-PLAN §2): TASKS.md is the build log —
 * first thing a session reads, last thing it updates. If the tree has
 * uncommitted changes and TASKS.md isn't among them, nudge once.
 */
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

let input = '';
for await (const chunk of process.stdin) {
  input += chunk;
}
try {
  // Never loop: if we already blocked once this stop, let it through.
  if (JSON.parse(input)?.stop_hook_active === true) {
    process.exit(0);
  }
} catch {
  process.exit(0);
}

const status = spawnSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' });
if (status.status !== 0) {
  process.exit(0);
}
const dirtyFiles = status.stdout.split('\n').filter((line) => line.trim() !== '');
const hasSourceChanges = dirtyFiles.some((line) => !line.includes('TASKS.md'));
const touchedTasksMd = dirtyFiles.some((line) => line.includes('TASKS.md'));

if (hasSourceChanges && !touchedTasksMd) {
  console.error(
    'The tree has uncommitted changes but TASKS.md was not updated. ' +
      'Append a session-log entry to TASKS.md (what was done, decisions taken, next steps) ' +
      'per BUILD-SESSION-PLAN §2 — or commit the work — before ending the session.'
  );
  process.exit(2);
}
process.exit(0);
