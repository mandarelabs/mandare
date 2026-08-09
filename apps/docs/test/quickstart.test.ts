import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * The quickstart page carries the EXACT commands the clean-machine CI job
 * executes (scripts/docs-install-smoke.mjs) — this guard makes docs edits
 * that would break that contract fail at the cheapest possible layer.
 */
const docsDir = join(dirname(fileURLToPath(import.meta.url)), '..');

describe('quickstart page', () => {
  const quickstart = readFileSync(join(docsDir, 'content/docs/quickstart.mdx'), 'utf8');

  it('documents the 3-command docker path verbatim', () => {
    expect(quickstart).toContain('git clone https://github.com/mandarelabs/mandare && cd mandare');
    expect(quickstart).toContain('docker compose up -d --wait');
    expect(quickstart).toContain('docker compose run --rm demo');
  });

  it('documents the solo path verbatim', () => {
    expect(quickstart).toContain('./install.sh');
    expect(quickstart).toContain('pnpm demo');
  });

  it('tells the truth about the dry-run (no secrets required)', () => {
    expect(quickstart.toLowerCase()).toContain('no api keys needed');
  });
});
