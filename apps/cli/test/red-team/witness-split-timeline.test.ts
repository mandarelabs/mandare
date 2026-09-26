import { execFile } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, test } from 'vitest';

import {
  doctorAmount,
  honestLedger,
  rewitnessUnderFreshSource,
  rewriteAndResign,
  startWitness,
  truncate,
  type WitnessFixture,
} from '../helpers/witness-attacks.js';

/**
 * RED-TEAM SUITE (rule R5) — "fresh-source split timeline" (W-1, audit
 * 2026-09). The attacker doctors a witnessed ledger, witnesses the doctored
 * tree under a FRESH source (the witness must accept it: sources are
 * self-authenticating), and repoints `ledger_meta.door_key_id` at it. The
 * real `mandare verify --witness` binary, given the real door key, must
 * still convict — exit 1 — because the witnessed history it consults is the
 * verifying key's, never the file's self-declared one. Sibling of the
 * certificate path's S8/C1 bound-source test.
 */

const CLI = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'dist', 'main.js');

let witness: WitnessFixture;

afterEach(async () => {
  await witness?.server.close();
});

function mandareVerify(dbPath: string, extra: string[]): Promise<{ code: number; stdout: string }> {
  const args = [CLI, 'verify', '--db', dbPath, '--witness', witness.url, '--witness-key', witness.publicKeyHex, ...extra];
  return new Promise((resolve) => {
    execFile(process.execPath, args, { timeout: 30_000 }, (error, stdout) => {
      const code = error === null ? 0 : typeof error.code === 'number' ? error.code : -1;
      resolve({ code, stdout });
    });
  });
}

// Each case spawns the real binary (cold Node start per run) — a generous budget, no retries.
describe('FRESH-SOURCE SPLIT TIMELINE: verify --witness cannot be repointed', { timeout: 30_000 }, () => {
  test('TRUNCATE + fresh source + repoint (no key needed) → exit 1, TRUNCATION DETECTED', async () => {
    witness = await startWitness();
    const { dbPath, doorKey } = await honestLedger(witness, 5);
    truncate(dbPath, 3);
    await rewitnessUnderFreshSource(witness, dbPath);

    const bound = await mandareVerify(dbPath, ['--door-key', doorKey.publicKeyHex]);
    expect(bound.code).toBe(1);
    expect(bound.stdout).toContain('TRUNCATION DETECTED');

    const selfAnchored = await mandareVerify(dbPath, []);
    expect(selfAnchored.code).toBe(1);
    expect(selfAnchored.stdout).toContain('SOURCE MISMATCH');
  });

  test('REWRITE under the real key + fresh source + repoint → exit 1, FORK DETECTED', async () => {
    witness = await startWitness();
    const { dbPath, doorKey } = await honestLedger(witness, 5);
    rewriteAndResign(dbPath, doorKey, doctorAmount(1));
    await rewitnessUnderFreshSource(witness, dbPath);

    const bound = await mandareVerify(dbPath, ['--door-key', doorKey.publicKeyHex]);
    expect(bound.code).toBe(1);
    expect(bound.stdout).toContain('FORK DETECTED');
    expect(bound.stdout).not.toMatch(/witness:\s+CONSISTENT/);
  });

  test('control: the honest ledger → exit 0 (no false positive)', async () => {
    witness = await startWitness();
    const { dbPath, doorKey } = await honestLedger(witness, 5);
    const bound = await mandareVerify(dbPath, ['--door-key', doorKey.publicKeyHex]);
    expect(bound.code).toBe(0);
    expect(bound.stdout).toMatch(/witness:\s+CONSISTENT/);
  });
});
