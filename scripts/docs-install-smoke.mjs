#!/usr/bin/env node
/**
 * Clean-machine install acceptance (S7): a stranger following ONLY the
 * public docs gets a running gateway that stops a runaway agent at a budget.
 *
 * Two enforcement layers:
 *  1. The quickstart commands are asserted to appear VERBATIM in the docs
 *     (apps/docs quickstart page AND the README) — docs drift fails CI.
 *  2. The solo path is executed on a FRESH COPY of the repo (no node_modules,
 *     no build outputs, no prior state): `./install.sh`, then `pnpm demo` —
 *     the Demo 1 acceptance (runaway dies at €20, refusal on ledger,
 *     counters == replay) must pass from that copy.
 *
 * The docker path (`docker compose up -d --wait` + `docker compose run --rm
 * demo`) runs as its own CI job (compose-smoke) — same commands, real
 * containers.
 *
 * Run: pnpm docs-install-smoke   (~3–5 min: full fresh install + build)
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

function fail(message) {
  console.error(`DOCS-INSTALL SMOKE FAIL: ${message}`);
  process.exit(1);
}

// ——— 1. The documented quickstart, verbatim ————————————————————————————
const DOCKER_QUICKSTART = [
  'git clone https://github.com/mandarelabs/mandare && cd mandare',
  'docker compose up -d --wait',
  'docker compose run --rm demo',
];
const SOLO_QUICKSTART = ['./install.sh', 'pnpm demo'];

const quickstartDoc = readFileSync(join(root, 'apps/docs/content/docs/quickstart.mdx'), 'utf8');
const readme = readFileSync(join(root, 'README.md'), 'utf8');
for (const command of [...DOCKER_QUICKSTART, ...SOLO_QUICKSTART]) {
  if (!quickstartDoc.includes(command)) {
    fail(`docs quickstart no longer documents verbatim: ${command}`);
  }
  if (!readme.includes(command)) {
    fail(`README no longer documents verbatim: ${command}`);
  }
}
console.log(`[docs-install] ${DOCKER_QUICKSTART.length + SOLO_QUICKSTART.length} quickstart commands verbatim in docs + README`);

// ——— 2. Fresh-copy solo install, documented commands only ————————————————
const freshDir = mkdtempSync(join(tmpdir(), 'mandare-fresh-'));
console.log(`[docs-install] fresh copy → ${freshDir}`);
// Working tree minus state/artifacts — in CI (clean checkout) this equals a
// fresh clone; locally it additionally proves uncommitted work installs.
// Two-step: tar to buffer then extract (portable across BSD/GNU tar).
{
  const archive = execFileSync('tar', [
    '-C', root,
    '--exclude', './node_modules',
    '--exclude', '*/node_modules',
    '--exclude', './.git',
    '--exclude', '*/dist',
    '--exclude', '*/.next',
    '--exclude', '*/.source',
    '--exclude', '*/.turbo',
    '--exclude', './bin',
    '--exclude', '*.db',
    '--exclude', '*.db-*',
    '--exclude', '*.doorkey.pem',
    '--exclude', '*.masterkey',
    '--exclude', './.env',
    '-cf', '-', '.',
  ], { maxBuffer: 1024 * 1024 * 1024 });
  execFileSync('tar', ['-C', freshDir, '-xf', '-'], { input: archive, maxBuffer: 1024 * 1024 * 1024 });
}

const started = Date.now();
console.log('[docs-install] $ ./install.sh');
execFileSync('bash', ['./install.sh'], { cwd: freshDir, stdio: 'inherit' });

console.log('[docs-install] $ ./bin/mandare help');
execFileSync('./bin/mandare', ['help'], { cwd: freshDir, stdio: 'pipe' });

console.log('[docs-install] $ pnpm demo');
const demoOut = execFileSync('pnpm', ['demo'], { cwd: freshDir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });
process.stdout.write(demoOut.split('\n').slice(-8).join('\n'));
if (!demoOut.includes('DEMO PASS')) {
  fail('pnpm demo did not PASS from the fresh copy');
}
const minutes = ((Date.now() - started) / 60000).toFixed(1);
if (Date.now() - started > 10 * 60_000) {
  fail(`install + demo took ${minutes} min — the documented path must land inside ~10 minutes`);
}

rmSync(freshDir, { recursive: true, force: true });
console.log(`\nDOCS-INSTALL SMOKE PASS: documented solo path works on a clean copy in ${minutes} min.`);
