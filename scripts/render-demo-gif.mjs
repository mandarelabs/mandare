#!/usr/bin/env node
// Renders the README demo GIF from the REAL Demo 1 terminal capture
// (docs/demos/S2-runaway-demo.txt — the CI-asserted acceptance run).
//
// The live run finishes in ~0.1s, far too fast to watch, so this script
// replays the captured output as an asciinema v2 cast with human-paced
// timing (<30s total) and renders it with `agg` (brew install agg).
// Content is the capture verbatim; the only additions are pacing and ANSI
// color on the DENIED/VALID markers.
//
// Usage: node scripts/render-demo-gif.mjs
// Output: docs/demos/runaway-demo.gif

import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const capture = readFileSync(
  path.join(root, 'docs/demos/S2-runaway-demo.txt'),
  'utf8',
);

const RED = '[1;31m';
const GREEN = '[1;32m';
const BOLD = '[1m';
const DIM = '[2m';
const RESET = '[0m';

const COLS = 104;
const ROWS = 30;

function colorize(line) {
  if (line.includes('403 DENIED')) return `${RED}${line}${RESET}`;
  if (/^\s*(code|reason):/.test(line)) return `${RED}${line}${RESET}`;
  if (line.includes('the refusal itself is ledger entry'))
    return `${BOLD}${line}${RESET}`;
  if (line.startsWith('chain:')) return `${GREEN}${line}${RESET}`;
  if (line.startsWith('$ ')) return `${BOLD}${line}${RESET}`;
  if (line.startsWith('═') || line.startsWith(' MANDARE DEMO'))
    return `${BOLD}${line}${RESET}`;
  if (line.startsWith('  #')) return `${DIM}${line}${RESET}`;
  return line;
}

// Pace each line: banner slow, runaway calls accelerating, the kill dwells,
// verify output brisk, final state holds.
function delayFor(line, prev) {
  if (line.startsWith('═')) return 0.05;
  if (line.includes('MANDARE DEMO')) return 0.1;
  if (line.includes('mandate signed')) return 1.0;
  if (line.includes('gateway door up')) return 0.5;
  if (line.includes('releasing the runaway')) return 0.9;
  const call = line.match(/^\s+call #\s*(\d+)/);
  if (call) {
    const n = Number(call[1]);
    if (n <= 3) return 0.45;
    if (n < 72) return 0.3;
    return 1.2; // the DENIED line lands after a beat
  }
  if (/^\s*(code|reason):/.test(line)) return 0.7;
  if (line.includes('the refusal itself')) return 0.8;
  if (line.includes('runaway made')) return 1.1;
  if (line.startsWith('$ ')) return 1.3;
  if (line.startsWith('spend:') || line.startsWith('trail:')) return 0.35;
  if (line.startsWith('  #')) return 0.07;
  if (prev.startsWith('$ ')) return 0.5;
  if (/^(ledger|door|entries|head|tree|chain|anchor|note|  mnd_)/.test(line))
    return 0.3;
  return 0.2;
}

const lines = capture.replace(/\n+$/, '').split('\n');
let t = 0.6;
const events = [];
let prev = '';
for (const line of lines) {
  t += delayFor(line, prev);
  events.push([Number(t.toFixed(3)), 'o', `${colorize(line)}\r\n`]);
  prev = line;
}
// Hold the final frame so the proof lands.
events.push([Number((t + 3.5).toFixed(3)), 'o', '']);

const header = {
  version: 2,
  width: COLS,
  height: ROWS,
  title: 'Mandare — a runaway agent loop dies at €20',
};
const cast =
  JSON.stringify(header) +
  '\n' +
  events.map((e) => JSON.stringify(e)).join('\n') +
  '\n';

const castPath = path.join(root, 'docs/demos/runaway-demo.cast');
const gifPath = path.join(root, 'docs/demos/runaway-demo.gif');
writeFileSync(castPath, cast);

execFileSync(
  'agg',
  [
    '--theme', 'dracula',
    '--font-size', '16',
    '--speed', '1',
    '--idle-time-limit', '4',
    castPath,
    gifPath,
  ],
  { stdio: 'inherit' },
);

console.log(`\nwrote ${gifPath} (total runtime ~${Math.ceil(t + 3.5)}s)`);
