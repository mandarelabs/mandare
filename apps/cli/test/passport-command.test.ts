import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, test } from 'vitest';

import { verifyMandateVc, verifyPassport, unverifiedPayload } from '@mandarelabs/passport';

import { runKill } from '../src/kill.js';
import { runMandateIssue, runPassportIssue } from '../src/passport-cmd.js';
import { runVerify } from '../src/verify.js';

/**
 * The S4 issuance flows end to end on a real (file-backend) vault + ledger:
 * passport issue → verifiable delegation chain; mandate issue → verifiable
 * SD-JWT VC; kill --mandate → refusal state on the ledger, same slot.
 */
describe('mandare passport/mandate issue (file-backend vault)', () => {
  let dir: string;
  let env: Record<string, string | undefined>;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mandare-passport-test-'));
    env = {
      MANDARE_LEDGER_DB: join(dir, 'ledger.db'),
      MANDARE_DOOR_ID: 'gateway:test',
      MANDARE_LEDGER_CURRENCY: 'EUR',
      MANDARE_VAULT: '1',
      MANDARE_VAULT_BACKEND: 'file',
      MANDARE_VAULT_DB: join(dir, 'vault.db'),
      MANDARE_VAULT_KEY_FILE: join(dir, 'vault.masterkey'),
    };
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  test('passport issue produces a verifiable chain, registers the agent, 0600-protects the key', async () => {
    const outPath = join(dir, 'demo.passport.sdjwt');
    const keyPath = join(dir, 'demo.agent-key.json');
    const code = await runPassportIssue(env, {
      agentName: 'demo',
      out: outPath,
      agentKeyOut: keyPath,
      json: true,
    });
    expect(code).toBe(0);

    const credential = readFileSync(outPath, 'utf8').trim();
    // The authority DID is discoverable from the embedded attestation's iss.
    const attestation = unverifiedPayload(credential).attestation as string;
    const authorityDid = unverifiedPayload(attestation).iss as string;
    const verified = await verifyPassport(credential, { trustedAuthorityDid: authorityDid });
    expect(verified.attestation.kyc.partner_id).toBe('mock:local');
    expect(verified.revocationRef).toMatch(/^statuslist:agents#\d+$/);

    // Agent key file is 0600 and holds a private JWK.
    expect(statSync(keyPath).mode & 0o777).toBe(0o600);
    const agentKey = JSON.parse(readFileSync(keyPath, 'utf8'));
    expect(agentKey.privateJwk.d).toBeDefined();

    // The registration is on the ledger, unrevoked.
    const out = await runVerify(env.MANDARE_LEDGER_DB as string);
    expect(out.exitCode).toBe(0);
    expect(out.json.revocations?.subjects[0]?.subject).toBe(`agent:${verified.agentDid}`);
    expect(out.json.revocations?.subjects[0]?.revoked).toBe(false);
  });

  test('a second issue for the same name changes NEITHER file (K-5)', async () => {
    const outPath = join(dir, 'twin.passport.sdjwt');
    const keyPath = join(dir, 'twin.agent-key.json');
    const options = { agentName: 'twin', out: outPath, agentKeyOut: keyPath, json: true };
    expect(await runPassportIssue(env, options)).toBe(0);
    const passportBefore = readFileSync(outPath, 'utf8');
    const keyBefore = readFileSync(keyPath, 'utf8');

    expect(await runPassportIssue(env, options)).toBe(1);
    // The passport still matches the key file: same agent, untouched bytes.
    expect(readFileSync(outPath, 'utf8')).toBe(passportBefore);
    expect(readFileSync(keyPath, 'utf8')).toBe(keyBefore);
    // Refused before the ledger: no second subject registered.
    const out = await runVerify(env.MANDARE_LEDGER_DB as string);
    expect(out.json.revocations?.subjects).toHaveLength(1);
  });

  test('an existing passport file alone also refuses, and writes no key (K-5)', async () => {
    const outPath = join(dir, 'solo.passport.sdjwt');
    const keyPath = join(dir, 'solo.agent-key.json');
    writeFileSync(outPath, 'someone else\'s passport\n');
    expect(await runPassportIssue(env, { agentName: 'solo', out: outPath, agentKeyOut: keyPath })).toBe(1);
    expect(readFileSync(outPath, 'utf8')).toBe("someone else's passport\n");
    expect(existsSync(keyPath)).toBe(false);
  });

  test('mandate issue → verifiable SD-JWT VC; kill --mandate flips its slot', async () => {
    const passportOut = join(dir, 'a.passport.sdjwt');
    await runPassportIssue(env, {
      agentName: 'a',
      out: passportOut,
      agentKeyOut: join(dir, 'a.key.json'),
      json: true,
    });
    const credential = readFileSync(passportOut, 'utf8').trim();
    const agentDid = unverifiedPayload(credential).sub as string;

    const mandatePath = join(dir, 'a.mandate.sdjwt');
    const code = await runMandateIssue(env, {
      agent: agentDid,
      out: mandatePath,
      approvalAbove: 1,
      json: true,
    });
    expect(code).toBe(0);

    const mandate = await verifyMandateVc(readFileSync(mandatePath, 'utf8').trim());
    expect(mandate.agent).toBe(agentDid);
    expect(mandate.approvals.rules[0]?.above).toBe(1_000_000);
    expect(mandate.revocation_ref).toMatch(/^statuslist:agents#\d+$/);

    // Kill the mandate: same subject slot flips to revoked.
    expect(await runKill(env, { mandate: mandate.id })).toBe(0);
    const out = await runVerify(env.MANDARE_LEDGER_DB as string);
    const record = out.json.revocations?.subjects.find(
      (subject) => subject.subject === `mandate:${mandate.id}`
    );
    expect(record?.revoked).toBe(true);
    expect(out.json.revocations?.projection.status).toBe('consistent');
  });
});
