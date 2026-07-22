import { describe, expect, test } from 'vitest';

import {
  AGENT_REVOKE,
  agentSubject,
  mandateSubject,
  readLedger,
  revocationProjector,
} from '@mandarelabs/ledger';
import { LLM_CALL_RESULT, type LedgerEntryV1 } from '@mandarelabs/spec';

import { anthropicBody, anthropicOkFetch, openTestGateway } from './helpers.js';
import { makePassportRig, signedInject } from './passport-helpers.js';

/**
 * Passport mode (S4): the verified actor comes from the delegation
 * credential + RFC 9421 request signature — WHO, not just an authorized
 * holder. Ledger entries carry the verified agent DID.
 */

describe('gateway passport mode', () => {
  test('a signed request under a valid passport chain proceeds; entries carry the verified DID', async () => {
    const rig = await makePassportRig();
    const gw = await openTestGateway({
      config: { authMode: 'passport', trustedAuthorityDid: rig.authority.did },
      mandate: rig.mandate,
      fetchImpl: anthropicOkFetch({ input_tokens: 10, output_tokens: 20 }),
    });
    try {
      const response = await gw.app.inject(
        await signedInject(rig, { path: '/v1/messages', body: anthropicBody })
      );
      expect(response.statusCode).toBe(200);
      const { entries } = readLedger(gw.dbPath);
      const result = (entries as LedgerEntryV1[]).find((e) => e.action.type === LLM_CALL_RESULT);
      expect(result?.actor).toBe(rig.agentDid);
    } finally {
      await gw.close();
    }
  });

  test('an unsigned request is refused before any spend work', async () => {
    const rig = await makePassportRig();
    const gw = await openTestGateway({
      config: { authMode: 'passport', trustedAuthorityDid: rig.authority.did },
      mandate: rig.mandate,
      fetchImpl: anthropicOkFetch({ input_tokens: 10, output_tokens: 20 }),
    });
    try {
      const response = await gw.app.inject({
        method: 'POST',
        url: '/v1/messages',
        payload: anthropicBody,
      });
      expect(response.statusCode).toBe(401);
      expect(response.json().code).toBe('PASSPORT_MISSING');
      expect(readLedger(gw.dbPath).entries).toHaveLength(0);
    } finally {
      await gw.close();
    }
  });

  test('no trust anchor configured ⇒ the spend path is closed (fail-closed)', async () => {
    const rig = await makePassportRig();
    const gw = await openTestGateway({
      config: { authMode: 'passport', trustedAuthorityDid: null },
      mandate: rig.mandate,
      fetchImpl: anthropicOkFetch({ input_tokens: 10, output_tokens: 20 }),
    });
    try {
      const response = await gw.app.inject(
        await signedInject(rig, { path: '/v1/messages', body: anthropicBody })
      );
      expect(response.statusCode).toBe(503);
      expect(response.json().error).toContain('MANDARE_TRUST_AUTHORITY');
    } finally {
      await gw.close();
    }
  });

  test('a killed agent still authenticates — and its refusal is recorded with its DID', async () => {
    const rig = await makePassportRig();
    const gw = await openTestGateway({
      config: { authMode: 'passport', trustedAuthorityDid: rig.authority.did },
      mandate: rig.mandate,
      fetchImpl: anthropicOkFetch({ input_tokens: 10, output_tokens: 20 }),
    });
    try {
      await gw.ledger.appendProjected(
        {
          actor: 'mandare:operator',
          mandate_id: 'mandare:kill',
          action: { type: AGENT_REVOKE, target: agentSubject(rig.agentDid), request_hash: 'a'.repeat(64) },
          cost: { amount: 0, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
        },
        revocationProjector()
      );
      const response = await gw.app.inject(
        await signedInject(rig, { path: '/v1/messages', body: anthropicBody })
      );
      expect(response.statusCode).toBe(403);
      expect(response.json().code).toBe('AGENT_REVOKED');
      const { entries } = readLedger(gw.dbPath);
      const denied = (entries as LedgerEntryV1[]).find((e) => e.action.type === 'llm.call.denied');
      expect(denied?.actor).toBe(rig.agentDid);
    } finally {
      await gw.close();
    }
  });

  test('a revoked mandate is refused instantly (kill --mandate)', async () => {
    const rig = await makePassportRig();
    const gw = await openTestGateway({
      config: { authMode: 'passport', trustedAuthorityDid: rig.authority.did },
      mandate: rig.mandate,
      fetchImpl: anthropicOkFetch({ input_tokens: 10, output_tokens: 20 }),
    });
    try {
      await gw.ledger.appendProjected(
        {
          actor: 'mandare:operator',
          mandate_id: 'mandare:kill',
          action: {
            type: AGENT_REVOKE,
            target: mandateSubject(rig.mandate.id),
            request_hash: 'b'.repeat(64),
          },
          cost: { amount: 0, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
        },
        revocationProjector()
      );
      const response = await gw.app.inject(
        await signedInject(rig, { path: '/v1/messages', body: anthropicBody })
      );
      expect(response.statusCode).toBe(403);
      expect(response.json().code).toBe('MANDATE_REVOKED');
    } finally {
      await gw.close();
    }
  });

  test('legacy token/none modes also refuse a revoked mandate', async () => {
    const gw = await openTestGateway({
      fetchImpl: anthropicOkFetch({ input_tokens: 10, output_tokens: 20 }),
    });
    try {
      await gw.ledger.appendProjected(
        {
          actor: 'mandare:operator',
          mandate_id: 'mandare:kill',
          action: {
            type: AGENT_REVOKE,
            target: mandateSubject(gw.mandate.id),
            request_hash: 'c'.repeat(64),
          },
          cost: { amount: 0, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
        },
        revocationProjector()
      );
      const response = await gw.app.inject({
        method: 'POST',
        url: '/v1/messages',
        payload: anthropicBody,
      });
      expect(response.statusCode).toBe(403);
      expect(response.json().code).toBe('MANDATE_REVOKED');
    } finally {
      await gw.close();
    }
  });
});
