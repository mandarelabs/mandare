import { describe, expect, test } from 'vitest';

import { LLM_CALL_DENIED, readLedger } from '@mandarelabs/ledger';
import { LLM_CALL_INTENT, LLM_CALL_RESULT, type LedgerEntryV1 } from '@mandarelabs/spec';
import type { GatewayConfig } from '../../src/config.js';
import type { WitnessDoorClient } from '../../src/server.js';

import {
  MockNotifier,
  anthropicBody,
  anthropicOkFetch,
  chatBody,
  openTestGateway,
  openrouterOkFetch,
  testMandate,
} from '../helpers.js';

/**
 * RED-TEAM SUITE (rule R5): witness-ack gating, lock 5. The gate must be
 * fail-closed in every direction — a dead, hanging, lying, or replaying
 * witness can only ever keep high-value actions SHUT; and low-stakes calls
 * must keep flowing through the async streaming window as designed.
 */

const WITNESS_CONFIG: Partial<GatewayConfig> = {
  witness: {
    url: 'http://witness.test',
    publicKeyHex: 'ab'.repeat(32),
    ackMode: 'all',
    ackTimeoutMs: 200,
    streamIntervalMs: 1000,
  },
};

function entriesOfType(dbPath: string, type: string): LedgerEntryV1[] {
  const { entries } = readLedger(dbPath);
  return (entries as LedgerEntryV1[]).filter((entry) => entry.action.type === type);
}

const okClient = (): WitnessDoorClient & { acks: number; nudges: number } => {
  const client = {
    acks: 0,
    nudges: 0,
    ackHead: async () => {
      client.acks += 1;
      return {
        head: { size: 1, root: 'ab'.repeat(32) },
        ack: {
          protocol: 'mandare-witness/1' as const,
          type: 'head.ack' as const,
          source_id: 'a'.repeat(64),
          head: { size: 1, root: 'ab'.repeat(32) },
          witnessed_at: new Date().toISOString(),
          witness_key_id: 'b'.repeat(64),
        },
      };
    },
    notifyAppend: () => {
      client.nudges += 1;
    },
  };
  return client;
};

describe('witness-ack gating fail-safe (lock 5)', () => {
  test('WITNESS DEAD: gated call refuses, reservation settles to ZERO, provider never called', async () => {
    let providerCalls = 0;
    const deadClient: WitnessDoorClient = {
      ackHead: () => Promise.reject(new Error('witness unreachable: connect ECONNREFUSED')),
      notifyAppend: () => undefined,
    };
    const gw = await openTestGateway({
      config: WITNESS_CONFIG,
      witness: deadClient,
      fetchImpl: (input, init) => {
        providerCalls += 1;
        return openrouterOkFetch()(input, init);
      },
    });
    try {
      const response = await gw.app.inject({
        method: 'POST',
        url: '/v1/chat/completions',
        payload: chatBody,
      });
      expect(response.statusCode).toBe(503);
      expect(response.json().code).toBe('WITNESS_UNAVAILABLE');
      expect(providerCalls).toBe(0); // NOTHING executed (R1)

      // R3 intact: the intent is paired with a zero settlement — the cap
      // releases, the refusal trail is on the ledger.
      const intents = entriesOfType(gw.dbPath, LLM_CALL_INTENT);
      const results = entriesOfType(gw.dbPath, LLM_CALL_RESULT);
      expect(intents).toHaveLength(1);
      expect(results).toHaveLength(1);
      expect(results[0]?.outcome_ref).toBe(intents[0]?.entry_hash);
      expect(results[0]?.cost.amount).toBe(0);
    } finally {
      await gw.close();
    }
  });

  test('WITNESS HANGING: the gate times out and fails closed', async () => {
    const hangingClient: WitnessDoorClient = {
      ackHead: () => new Promise(() => undefined),
      notifyAppend: () => undefined,
    };
    const gw = await openTestGateway({
      config: WITNESS_CONFIG,
      witness: hangingClient,
      fetchImpl: openrouterOkFetch(),
    });
    try {
      const response = await gw.app.inject({
        method: 'POST',
        url: '/v1/chat/completions',
        payload: chatBody,
      });
      expect(response.statusCode).toBe(503);
      expect(response.json().code).toBe('WITNESS_UNAVAILABLE');
    } finally {
      await gw.close();
    }
  });

  test('FORGED/REPLAYED ACK: a lying witness client error refuses the call', async () => {
    // The REAL WitnessClient throws BAD_ACK on forged or replayed acks
    // (red-teamed in witness-protocol); the gate must treat ANY ack failure
    // as unavailable — simulated here with the exact error it raises.
    const lyingClient: WitnessDoorClient = {
      ackHead: () => Promise.reject(new Error('witness ack does not match the submitted head')),
      notifyAppend: () => undefined,
    };
    const gw = await openTestGateway({
      config: WITNESS_CONFIG,
      witness: lyingClient,
      fetchImpl: openrouterOkFetch(),
    });
    try {
      const response = await gw.app.inject({
        method: 'POST',
        url: '/v1/chat/completions',
        payload: chatBody,
      });
      expect(response.statusCode).toBe(503);
      expect(response.json().code).toBe('WITNESS_UNAVAILABLE');
    } finally {
      await gw.close();
    }
  });

  test('WITNESS OK: the gated call proceeds; every append nudges the stream', async () => {
    const client = okClient();
    const gw = await openTestGateway({
      config: WITNESS_CONFIG,
      witness: client,
      fetchImpl: openrouterOkFetch(),
    });
    try {
      const response = await gw.app.inject({
        method: 'POST',
        url: '/v1/chat/completions',
        payload: chatBody,
      });
      expect(response.statusCode).toBe(200);
      expect(client.acks).toBe(1);
      expect(client.nudges).toBeGreaterThanOrEqual(2); // intent + result (lock 4)
    } finally {
      await gw.close();
    }
  });

  test('THRESHOLD MODE: low-stakes calls flow WITHOUT waiting for an ack (async window)', async () => {
    const client = okClient();
    const gw = await openTestGateway({
      config: {
        witness: { ...WITNESS_CONFIG.witness!, ackMode: 'threshold' },
      },
      witness: client,
      fetchImpl: openrouterOkFetch(),
    });
    try {
      // chatBody's estimate is far below the €5 approval threshold.
      const response = await gw.app.inject({
        method: 'POST',
        url: '/v1/chat/completions',
        payload: chatBody,
      });
      expect(response.statusCode).toBe(200);
      expect(client.acks).toBe(0); // not gated — streamed asynchronously
      expect(client.nudges).toBeGreaterThanOrEqual(2);
    } finally {
      await gw.close();
    }
  });

  test('THRESHOLD MODE: an approved high-value call still dies if the witness is down', async () => {
    // The S4 lesson (kill-during-hold) applied to lock 5: human approval is
    // NOT a bypass — the approved call must still obtain its witnessed head.
    const notifier = new MockNotifier();
    const deadClient: WitnessDoorClient = {
      ackHead: () => Promise.reject(new Error('witness unreachable')),
      notifyAppend: () => undefined,
    };
    const approvalMandate = testMandate({
      approvals: { rules: [{ above: 200_000, currency: 'EUR', method: 'push' }] },
    });
    const gw = await openTestGateway({
      config: {
        witness: { ...WITNESS_CONFIG.witness!, ackMode: 'threshold' },
      },
      witness: deadClient,
      mandate: approvalMandate,
      notifier,
      fetchImpl: anthropicOkFetch({ input_tokens: 10, output_tokens: 20 }),
    });
    try {
      const bigCall = { ...anthropicBody, max_tokens: 60_000 };
      const held = gw.app.inject({ method: 'POST', url: '/v1/messages', payload: bigCall });
      const push = await notifier.next();
      const decision = await gw.app.inject({
        method: 'POST',
        url: push.approveUrl.slice(push.approveUrl.indexOf('/approvals')),
        payload: JSON.parse(push.approveBody),
      });
      expect(decision.statusCode).toBe(200);

      const response = await held;
      expect(response.statusCode).toBe(503);
      expect(response.json().code).toBe('WITNESS_UNAVAILABLE');
      // The intent is settled to zero — approval granted, execution refused.
      const results = entriesOfType(gw.dbPath, LLM_CALL_RESULT);
      expect(results).toHaveLength(1);
      expect(results[0]?.cost.amount).toBe(0);
      expect(entriesOfType(gw.dbPath, LLM_CALL_DENIED)).toHaveLength(0);
    } finally {
      await gw.close();
    }
  });

  test('MISWIRED DOOR: witness config without a client refuses to build (no silent fail-open)', async () => {
    await expect(openTestGateway({ config: WITNESS_CONFIG })).rejects.toThrow(
      /refusing to build ungated/
    );
  });
});
