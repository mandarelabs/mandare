import { execFile } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, beforeEach, describe, expect, test } from 'vitest';

import { runVerify } from '../src/verify.js';

/**
 * K-4 (audit 2026-09): a flag VALUE that looks like `--help` must never turn
 * a kill into a silent, successful no-op. `--help` is honoured only as the
 * first token after the command; `--` ends flag parsing.
 */

const CLI = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'main.js');

function mandare(args: string[], env: Record<string, string>): Promise<{ code: number; stdout: string }> {
  return new Promise((resolve) => {
    execFile(process.execPath, [CLI, ...args], { env: { ...process.env, ...env }, timeout: 20_000 }, (error, stdout) => {
      const code = error === null ? 0 : typeof error.code === 'number' ? error.code : -1;
      resolve({ code, stdout });
    });
  });
}

describe('CLI argv hygiene (K-4)', { timeout: 30_000 }, () => {
  let dir: string;
  let env: Record<string, string>;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mandare-argv-'));
    env = { MANDARE_LEDGER_DB: join(dir, 'ledger.db'), MANDARE_DOOR_ID: 'gateway:test' };
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  test('kill with reason "--help" is a usage error, never a silent success', async () => {
    const result = await mandare(['kill', 'did:mandare:rogue', '--reason', '--help'], env);
    expect(result.code).toBe(2);
    expect(result.stdout).not.toContain('Usage');
    expect(existsSync(env.MANDARE_LEDGER_DB as string)).toBe(false);
  });

  test('--help later in the argv is not a global help switch', async () => {
    const result = await mandare(['kill', 'did:mandare:rogue', '--reason', 'stop', '--help'], env);
    expect(result.code).not.toBe(0);
  });

  test('--help as the first token after the command still prints usage', async () => {
    const result = await mandare(['kill', '--help'], env);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain('mandare kill');
  });

  test('-- ends flag parsing: a dash-leading reason is data', async () => {
    const result = await mandare(['kill', '--reason', 'stop', '--', 'did:mandare:rogue'], env);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain('KILLED did:mandare:rogue');
    const verified = await runVerify(env.MANDARE_LEDGER_DB as string);
    expect(verified.json.revocations?.subjects[0]?.subject).toBe('agent:did:mandare:rogue');
  });
});
