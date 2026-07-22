import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, test } from 'vitest';

import {
  AGENT_REVOKE,
  APPROVAL_GRANTED,
  agentSubject,
  readLedger,
  revocationProjector,
} from '@mandarelabs/ledger';
import {
  MockIdvProvider,
  issueDelegationCredential,
  issueMandateVc,
  signMandatePayload,
  didFromPublicJwk,
  generateEd25519KeyPair,
  AttestationAuthority,
} from '@mandarelabs/passport';
import { LLM_CALL_RESULT, type LedgerEntryV1 } from '@mandarelabs/spec';

import { loadMandate } from '../../src/config.js';
import {
  MockNotifier,
  anthropicBody,
  anthropicOkFetch,
  openTestGateway,
  testMandate,
} from '../helpers.js';
import { makePassportRig, signedInject } from '../passport-helpers.js';

/**
 * S4 red-team suite (permanent, R5): forged mandate signatures, expired and
 * revoked mandates, scope escalation across identities, tampered/replayed
 * approvals, delegation-chain breaks, and signature replay/body-swap at the
 * door. Every attack must FAIL LOUDLY.
 */

const DAY_SECONDS = 86_400;

async function makeSignedMandateFile(perDayEur: number): Promise<{ path: string; compact: string }> {
  const owner = await generateEd25519KeyPair();
  const agent = await generateEd25519KeyPair();
  const now = Date.now();
  const iso = (ms: number): string => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const mandate = await signMandatePayload(
    {
      schema_version: 1,
      id: 'mnd_redteam',
      principal: didFromPublicJwk(owner.publicJwk),
      agent: didFromPublicJwk(agent.publicJwk),
      purpose: 'red-team mandate',
      scopes: [
        {
          type: 'spend',
          currency: 'EUR',
          per_tx_max: 5_000_000,
          per_day_max: perDayEur * 1_000_000,
          per_task_max: 20_000_000,
          total_cap: 100_000_000,
          rails: ['gateway'],
          counterparties: 'any',
          categories: ['llm'],
        },
        { type: 'action', classes: ['llm.call'] },
      ],
      approvals: { rules: [] },
      valid_from: iso(now - 60_000),
      valid_until: iso(now + DAY_SECONDS * 1000),
      revocation_ref: 'statuslist:agents#7',
    },
    owner,
    'software'
  );
  const compact = await issueMandateVc(mandate, owner, Math.floor(now / 1000));
  const path = join(mkdtempSync(join(tmpdir(), 'mandare-redteam-')), 'mandate.sdjwt');
  writeFileSync(path, compact);
  return { path, compact };
}

describe('red-team: forged mandate signature', () => {
  test('a tampered mandate VC (caps inflated) refuses to load', async () => {
    const { path, compact } = await makeSignedMandateFile(20);
    // Attacker rewrites the day cap 20 € → 20 000 € inside the envelope.
    const [jwt, ...rest] = compact.split('~');
    const [header, payloadB64, sig] = (jwt as string).split('.');
    const payload = JSON.parse(Buffer.from(payloadB64 as string, 'base64url').toString());
    payload.mandate.scopes[0].per_day_max = 20_000_000_000;
    const forged = [
      [header, Buffer.from(JSON.stringify(payload)).toString('base64url'), sig].join('.'),
      ...rest,
    ].join('~');
    writeFileSync(path, forged);
    await expect(loadMandate(path)).rejects.toThrow();
  });

  test('an intact signed mandate VC loads and round-trips its caps', async () => {
    const { path } = await makeSignedMandateFile(20);
    const mandate = await loadMandate(path);
    const spend = mandate.scopes[0] as { per_day_max: number };
    expect(spend.per_day_max).toBe(20_000_000);
  });
});

describe('red-team: expired mandate', () => {
  test('an expired mandate VC refuses to load (envelope exp)', async () => {
    const owner = await generateEd25519KeyPair();
    const agent = await generateEd25519KeyPair();
    const past = Date.now() - 10 * DAY_SECONDS * 1000;
    const iso = (ms: number): string => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
    const mandate = await signMandatePayload(
      {
        schema_version: 1,
        id: 'mnd_expired',
        principal: didFromPublicJwk(owner.publicJwk),
        agent: didFromPublicJwk(agent.publicJwk),
        purpose: 'expired mandate',
        scopes: [{ type: 'action', classes: ['llm.call'] }],
        approvals: { rules: [] },
        valid_from: iso(past),
        valid_until: iso(past + DAY_SECONDS * 1000),
        revocation_ref: 'statuslist:agents#8',
      },
      owner,
      'software'
    );
    const compact = await issueMandateVc(mandate, owner, Math.floor(past / 1000));
    const path = join(mkdtempSync(join(tmpdir(), 'mandare-redteam-')), 'expired.sdjwt');
    writeFileSync(path, compact);
    await expect(loadMandate(path)).rejects.toThrow(/expired/i);
  });

  test('an in-window-loaded but since-expired mandate is refused per-request by the engine', async () => {
    const rig = await makePassportRig({
      mandate: {
        valid_from: '2026-01-01T00:00:00Z',
        valid_until: '2026-01-02T00:00:00Z', // long past
      },
    });
    const gw = await openTestGateway({
      config: { authMode: 'passport', trustedAuthorityDid: rig.authority.did },
      mandate: rig.mandate,
      fetchImpl: anthropicOkFetch({ input_tokens: 1, output_tokens: 1 }),
    });
    try {
      const response = await gw.app.inject(
        await signedInject(rig, { path: '/v1/messages', body: anthropicBody })
      );
      expect(response.statusCode).toBe(403);
      expect(response.json().code).toBe('MANDATE_OUT_OF_WINDOW');
    } finally {
      await gw.close();
    }
  });
});

describe('red-team: scope escalation within one owner (wrong agent)', () => {
  test("an owner's agent A cannot spend under a mandate the owner wrote for agent B", async () => {
    // Same owner (so the owner-binding check passes) but the mandate names a
    // DIFFERENT agent than the one presenting — the identity check must catch
    // it, and the refusal is recorded against A's verified DID.
    const rig = await makePassportRig();
    const otherAgentDid = didFromPublicJwk((await generateEd25519KeyPair()).publicJwk);
    const mandate = { ...rig.mandate, agent: otherAgentDid };
    const gw = await openTestGateway({
      config: { authMode: 'passport', trustedAuthorityDid: rig.authority.did },
      mandate,
      fetchImpl: anthropicOkFetch({ input_tokens: 1, output_tokens: 1 }),
    });
    try {
      const response = await gw.app.inject(
        await signedInject(rig, { path: '/v1/messages', body: anthropicBody })
      );
      expect(response.statusCode).toBe(403);
      expect(response.json().code).toBe('IDENTITY_MISMATCH');
      const { entries } = readLedger(gw.dbPath);
      const denied = (entries as LedgerEntryV1[]).find((e) => e.action.type === 'llm.call.denied');
      expect(denied?.actor).toBe(rig.agentDid);
    } finally {
      await gw.close();
    }
  });
});

describe('red-team: delegation-chain break', () => {
  test('a credential without the authority countersignature is refused', async () => {
    const rig = await makePassportRig({
      credential: async (base) => {
        const kyc = await new MockIdvProvider().verifyOwner(base.ownerDid);
        const nowSeconds = Math.floor(Date.now() / 1000);
        // Signed by the owner but countersigned by a ROGUE authority.
        const rogue = new AttestationAuthority(await generateEd25519KeyPair());
        const attestation = await rogue.attestOwner(base.ownerDid, kyc, nowSeconds);
        return issueDelegationCredential({
          ownerKeyPair: base.owner,
          agentPublicJwk: base.agent.publicJwk,
          attestation,
          revocationRef: 'statuslist:agents#9',
          keyProvenance: 'software',
          issuedAtSeconds: nowSeconds,
          notBeforeSeconds: nowSeconds - 60,
          expiresSeconds: nowSeconds + DAY_SECONDS,
        });
      },
    });
    const gw = await openTestGateway({
      config: { authMode: 'passport', trustedAuthorityDid: rig.authority.did },
      mandate: rig.mandate,
      fetchImpl: anthropicOkFetch({ input_tokens: 1, output_tokens: 1 }),
    });
    try {
      const response = await gw.app.inject(
        await signedInject(rig, { path: '/v1/messages', body: anthropicBody })
      );
      expect(response.statusCode).toBe(401);
      expect(response.json().code).toBe('PASSPORT_INVALID');
    } finally {
      await gw.close();
    }
  });
});

describe('red-team: request signature replay and body swap at the door', () => {
  test('a captured signed request cannot be replayed', async () => {
    const rig = await makePassportRig();
    const gw = await openTestGateway({
      config: { authMode: 'passport', trustedAuthorityDid: rig.authority.did },
      mandate: rig.mandate,
      fetchImpl: anthropicOkFetch({ input_tokens: 1, output_tokens: 1 }),
    });
    try {
      const inject = await signedInject(rig, { path: '/v1/messages', body: anthropicBody });
      expect((await gw.app.inject(inject)).statusCode).toBe(200);
      const replay = await gw.app.inject(inject);
      expect(replay.statusCode).toBe(401);
      expect(replay.json().code).toBe('REPLAYED_NONCE');
    } finally {
      await gw.close();
    }
  });

  test('a body swapped under a valid signature is refused (Content-Digest)', async () => {
    const rig = await makePassportRig();
    const gw = await openTestGateway({
      config: { authMode: 'passport', trustedAuthorityDid: rig.authority.did },
      mandate: rig.mandate,
      fetchImpl: anthropicOkFetch({ input_tokens: 1, output_tokens: 1 }),
    });
    try {
      const inject = await signedInject(rig, {
        path: '/v1/messages',
        body: anthropicBody,
        sendBody: JSON.stringify({ ...anthropicBody, max_tokens: 64_000 }),
      });
      const response = await gw.app.inject(inject);
      expect(response.statusCode).toBe(401);
      expect(response.json().code).toBe('BODY_DIGEST_MISMATCH');
    } finally {
      await gw.close();
    }
  });
});

describe('red-team: scope escalation across identities (passport owner binding)', () => {
  test("agent A's passport countersigned by a DIFFERENT owner than the mandate principal is refused", async () => {
    // Owner O2 (also KYC'd by the trusted authority) issues a credential
    // naming agent A's key — but the door's mandate principal is owner O1.
    const rigMandate = await makePassportRig(); // provides authority + O1 mandate
    const o2 = await generateEd25519KeyPair();
    const rig = await makePassportRig({
      credential: async (base) => {
        const kyc = await new MockIdvProvider().verifyOwner(didFromPublicJwk(o2.publicJwk));
        const nowSeconds = Math.floor(Date.now() / 1000);
        const attestation = await rigMandate.authority.attestOwner(
          didFromPublicJwk(o2.publicJwk),
          kyc,
          nowSeconds
        );
        return issueDelegationCredential({
          ownerKeyPair: o2,
          agentPublicJwk: base.agent.publicJwk,
          attestation,
          revocationRef: 'statuslist:agents#11',
          keyProvenance: 'software',
          issuedAtSeconds: nowSeconds,
          notBeforeSeconds: nowSeconds - 60,
          expiresSeconds: nowSeconds + DAY_SECONDS,
        });
      },
    });
    // Door enforces O1's mandate for the SAME agent DID, trusts the authority.
    const mandate = { ...rigMandate.mandate, agent: rig.agentDid };
    const gw = await openTestGateway({
      config: { authMode: 'passport', trustedAuthorityDid: rigMandate.authority.did },
      mandate,
      fetchImpl: anthropicOkFetch({ input_tokens: 1, output_tokens: 1 }),
    });
    try {
      const response = await gw.app.inject(
        await signedInject(rig, { path: '/v1/messages', body: anthropicBody })
      );
      expect(response.statusCode).toBe(403);
      expect(response.json().code).toBe('OWNER_MISMATCH');
    } finally {
      await gw.close();
    }
  });
});

describe('red-team: kill during an approval hold', () => {
  test('a kill that lands WHILE a call is held closes the door on resume (HIGH-2)', async () => {
    const notifier = new MockNotifier();
    const approvalMandate = testMandate({
      approvals: { rules: [{ above: 200_000, currency: 'EUR', method: 'push' }] },
    });
    const gw = await openTestGateway({
      config: { approvalTimeoutMs: 10_000 },
      mandate: approvalMandate,
      notifier,
      fetchImpl: anthropicOkFetch({ input_tokens: 1, output_tokens: 1 }),
    });
    try {
      const held = gw.app.inject({
        method: 'POST',
        url: '/v1/messages',
        payload: { ...anthropicBody, max_tokens: 60_000 },
      });
      const push = await notifier.next();
      // Kill the agent DURING the hold, THEN the human approves.
      await gw.ledger.appendProjected(
        {
          actor: 'mandare:operator',
          mandate_id: 'mandare:kill',
          action: {
            type: AGENT_REVOKE,
            target: agentSubject(gw.config.actor),
            request_hash: 'd'.repeat(64),
          },
          cost: { amount: 0, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
        },
        revocationProjector()
      );
      const decision = await gw.app.inject({
        method: 'POST',
        url: `/approvals/${push.approvalId}`,
        payload: JSON.parse(push.approveBody),
      });
      expect(decision.statusCode).toBe(200); // the human's click is honored
      const response = await held;
      // …but the resumed call still fails closed — the kill wins.
      expect(response.statusCode).toBe(403);
      expect(response.json().code).toBe('AGENT_REVOKED');
      const { entries } = readLedger(gw.dbPath);
      const results = (entries as LedgerEntryV1[]).filter((e) => e.action.type === LLM_CALL_RESULT);
      expect(results).toHaveLength(0); // nothing spent after the kill
    } finally {
      await gw.close();
    }
  });
});

describe('red-team: approval flooding', () => {
  test('held calls are capped so a looping agent cannot flood pushes/holds (MEDIUM-2)', async () => {
    const notifier = new MockNotifier();
    const approvalMandate = testMandate({
      approvals: { rules: [{ above: 200_000, currency: 'EUR', method: 'push' }] },
    });
    const gw = await openTestGateway({
      config: { approvalTimeoutMs: 10_000, maxPendingApprovals: 2 },
      mandate: approvalMandate,
      notifier,
      fetchImpl: anthropicOkFetch({ input_tokens: 1, output_tokens: 1 }),
    });
    try {
      const bodies = { ...anthropicBody, max_tokens: 60_000 };
      // Two holds fill the cap; the third is refused without a push.
      const held1 = gw.app.inject({ method: 'POST', url: '/v1/messages', payload: bodies });
      const push1 = await notifier.next();
      const held2 = gw.app.inject({ method: 'POST', url: '/v1/messages', payload: bodies });
      const push2 = await notifier.next();
      const third = await gw.app.inject({ method: 'POST', url: '/v1/messages', payload: bodies });
      expect(third.statusCode).toBe(403);
      expect(third.json().code).toBe('APPROVAL_BACKLOG');
      expect(notifier.notifications).toHaveLength(0); // no third push

      // Deny the two holds so they resolve and the test ends deterministically.
      await gw.app.inject({
        method: 'POST',
        url: `/approvals/${push1.approvalId}`,
        payload: JSON.parse(push1.denyBody),
      });
      await gw.app.inject({
        method: 'POST',
        url: `/approvals/${push2.approvalId}`,
        payload: JSON.parse(push2.denyBody),
      });
      expect((await held1).statusCode).toBe(403);
      expect((await held2).statusCode).toBe(403);
    } finally {
      await gw.close();
    }
  });
});

describe('red-team: tampered / replayed approvals', () => {
  const approvalMandate = testMandate({
    approvals: { rules: [{ above: 200_000, currency: 'EUR', method: 'push' }] },
  });
  const bigCall = { ...anthropicBody, max_tokens: 60_000 };

  test('a forged decision token cannot decide; the real one still can', async () => {
    const notifier = new MockNotifier();
    const gw = await openTestGateway({
      mandate: approvalMandate,
      notifier,
      fetchImpl: anthropicOkFetch({ input_tokens: 1, output_tokens: 1 }),
    });
    try {
      const held = gw.app.inject({ method: 'POST', url: '/v1/messages', payload: bigCall });
      const push = await notifier.next();
      const forged = await gw.app.inject({
        method: 'POST',
        url: `/approvals/${push.approvalId}`,
        payload: { token: 'A'.repeat(43) },
      });
      expect(forged.statusCode).toBe(403);
      // The pending approval survives the probe; the legitimate deny lands.
      const legit = await gw.app.inject({
        method: 'POST',
        url: `/approvals/${push.approvalId}`,
        payload: JSON.parse(push.denyBody),
      });
      expect(legit.statusCode).toBe(200);
      expect((await held).statusCode).toBe(403);
    } finally {
      await gw.close();
    }
  });

  test('a replayed approval token cannot re-approve, and cannot approve a SECOND call', async () => {
    const notifier = new MockNotifier();
    const gw = await openTestGateway({
      mandate: approvalMandate,
      notifier,
      fetchImpl: anthropicOkFetch({ input_tokens: 1, output_tokens: 1 }),
    });
    try {
      const held1 = gw.app.inject({ method: 'POST', url: '/v1/messages', payload: bigCall });
      const push1 = await notifier.next();
      const approveBody = JSON.parse(push1.approveBody) as { token: string };
      expect(
        (await gw.app.inject({ method: 'POST', url: `/approvals/${push1.approvalId}`, payload: approveBody }))
          .statusCode
      ).toBe(200);
      expect((await held1).statusCode).toBe(200);

      // Replay the used token against the same approval: refused.
      const replay = await gw.app.inject({
        method: 'POST',
        url: `/approvals/${push1.approvalId}`,
        payload: approveBody,
      });
      expect(replay.statusCode).toBe(409);

      // A second held call gets fresh tokens; the OLD token cannot decide it.
      const held2 = gw.app.inject({ method: 'POST', url: '/v1/messages', payload: bigCall });
      const push2 = await notifier.next();
      const crossUse = await gw.app.inject({
        method: 'POST',
        url: `/approvals/${push2.approvalId}`,
        payload: approveBody,
      });
      expect(crossUse.statusCode).toBe(403);
      // Clean up: deny the second call so the test ends deterministically.
      await gw.app.inject({
        method: 'POST',
        url: `/approvals/${push2.approvalId}`,
        payload: JSON.parse(push2.denyBody),
      });
      expect((await held2).statusCode).toBe(403);

      // Exactly ONE grant on the ledger, and exactly one settled call.
      const { entries } = readLedger(gw.dbPath);
      const typed = entries as LedgerEntryV1[];
      expect(typed.filter((e) => e.action.type === APPROVAL_GRANTED)).toHaveLength(1);
      expect(typed.filter((e) => e.action.type === LLM_CALL_RESULT)).toHaveLength(1);
    } finally {
      await gw.close();
    }
  });
});
