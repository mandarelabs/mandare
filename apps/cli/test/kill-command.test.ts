import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, test } from 'vitest';

import { runVerify } from '../src/verify.js';
import { runKill, runReinstate } from '../src/kill.js';

/**
 * `mandare kill` must work in LEGACY mode (no vault) too — the gateway's
 * revocation check runs in both modes, so the CLI must resolve the door key
 * the same way the gateway does (a 0600 PEM here). This locks the fix for the
 * review's HIGH-2 (kill silently inoperable when the gateway is not vault-mode).
 */
describe('mandare kill (legacy PEM mode, no vault)', () => {
  let dir: string;
  let env: Record<string, string | undefined>;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mandare-kill-test-'));
    // No MANDARE_VAULT ⇒ legacy mode: door key is the PEM next to the ledger.
    env = {
      MANDARE_LEDGER_DB: join(dir, 'ledger.db'),
      MANDARE_DOOR_ID: 'gateway:test',
      MANDARE_LEDGER_CURRENCY: 'EUR',
    };
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  test('writes an agent.revoke entry and verify shows the kill (no vault present)', async () => {
    const code = await runKill(env, { agent: 'did:mandare:rogue', reason: 'test' });
    expect(code).toBe(0);

    const out = await runVerify(env.MANDARE_LEDGER_DB as string);
    expect(out.exitCode).toBe(0);
    expect(out.json.revocations?.subjects[0]?.subject).toBe('agent:did:mandare:rogue');
    expect(out.json.revocations?.subjects[0]?.revoked).toBe(true);
    expect(out.json.revocations?.projection.status).toBe('consistent');
  });

  test('reinstate reverses the kill on the same ledger', async () => {
    await runKill(env, { agent: 'did:mandare:rogue' });
    const code = await runReinstate(env, { agent: 'did:mandare:rogue' });
    expect(code).toBe(0);

    const out = await runVerify(env.MANDARE_LEDGER_DB as string);
    expect(out.json.revocations?.subjects[0]?.revoked).toBe(false);
    expect(out.json.revocations?.projection.status).toBe('consistent');
  });

  test('kill --all revokes the door subject', async () => {
    const code = await runKill(env, { all: true });
    expect(code).toBe(0);
    const out = await runVerify(env.MANDARE_LEDGER_DB as string);
    expect(out.json.revocations?.subjects[0]?.subject).toBe('door:gateway:test');
  });
});
