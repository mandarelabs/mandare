import { describe, expect, test } from 'vitest';

import { WitnessGate } from '../src/witness-gate.js';
import { loadConfigFromEnv } from '../src/config.js';
import { testMandate } from './helpers.js';
import type { SyncResult } from '@mandarelabs/witness-protocol';

const ACK: SyncResult = {
  head: { size: 3, root: 'ab'.repeat(32) },
  ack: {
    protocol: 'mandare-witness/1',
    type: 'head.ack',
    source_id: 'a'.repeat(64),
    head: { size: 3, root: 'ab'.repeat(32) },
    witnessed_at: '2026-08-09T10:00:00Z',
    witness_key_id: 'b'.repeat(64),
  },
};

describe('WitnessGate', () => {
  test("mode 'threshold' reuses the mandate approval rules — the mandate defines high-value", () => {
    const gate = new WitnessGate({
      client: { ackHead: async () => ACK },
      ackMode: 'threshold',
      ackTimeoutMs: 100,
      ledgerCurrency: 'EUR',
    });
    const mandate = testMandate(); // approval rule: above €5
    expect(gate.isGated(5_000_001, mandate)).toBe(true);
    expect(gate.isGated(5_000_000, mandate)).toBe(false); // at threshold = not above
    expect(gate.isGated(100, mandate)).toBe(false);
    // A mandate with no approval rules defines no high-value set.
    expect(gate.isGated(999_999_999, testMandate({ approvals: { rules: [] } }))).toBe(false);
    // A rule in another currency never matches this door's ledger currency.
    expect(
      gate.isGated(
        999_999_999,
        testMandate({ approvals: { rules: [{ above: 0, currency: 'USD', method: 'push' }] } })
      )
    ).toBe(false);
  });

  test("mode 'all' gates everything; 'off' gates nothing", () => {
    const base = { client: { ackHead: async () => ACK }, ackTimeoutMs: 100, ledgerCurrency: 'EUR' };
    expect(new WitnessGate({ ...base, ackMode: 'all' }).isGated(1, testMandate())).toBe(true);
    expect(new WitnessGate({ ...base, ackMode: 'off' }).isGated(1e9, testMandate())).toBe(false);
  });

  test('requireAck: verified ack passes through', async () => {
    const gate = new WitnessGate({
      client: { ackHead: async () => ACK },
      ackMode: 'all',
      ackTimeoutMs: 100,
      ledgerCurrency: 'EUR',
    });
    expect(await gate.requireAck()).toEqual({ ok: true, witnessedSize: 3 });
  });

  test('requireAck: a hanging witness fails closed at the timeout', async () => {
    const gate = new WitnessGate({
      client: { ackHead: () => new Promise(() => undefined) },
      ackMode: 'all',
      ackTimeoutMs: 50,
      ledgerCurrency: 'EUR',
    });
    const verdict = await gate.requireAck();
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/no witness ack within 50ms/);
  });

  test('requireAck: a throwing client fails closed with the reason', async () => {
    const gate = new WitnessGate({
      client: {
        ackHead: () => Promise.reject(new Error('witness ack signature is invalid')),
      },
      ackMode: 'all',
      ackTimeoutMs: 100,
      ledgerCurrency: 'EUR',
    });
    const verdict = await gate.requireAck();
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toMatch(/signature is invalid/);
  });
});

describe('witness config parsing', () => {
  const BASE = { MANDARE_LEDGER_CURRENCY: 'USD' };

  test('no witness env → null (S0–S5 posture unchanged)', () => {
    expect(loadConfigFromEnv({ ...BASE }).witness).toBeNull();
  });

  test('URL without the out-of-band key refuses to start', () => {
    expect(() =>
      loadConfigFromEnv({ ...BASE, MANDARE_WITNESS_URL: 'http://127.0.0.1:9411' })
    ).toThrow(/out-of-band/);
  });

  test('gating without a witness URL refuses to start (no silent fail-open)', () => {
    expect(() => loadConfigFromEnv({ ...BASE, MANDARE_WITNESS_ACK_MODE: 'all' })).toThrow(
      /requires MANDARE_WITNESS_URL/
    );
  });

  test('full config parses; mode defaults to threshold', () => {
    const config = loadConfigFromEnv({
      ...BASE,
      MANDARE_WITNESS_URL: 'http://127.0.0.1:9411/',
      MANDARE_WITNESS_PUBLIC_KEY: 'ab'.repeat(32),
    });
    expect(config.witness).toEqual({
      url: 'http://127.0.0.1:9411',
      publicKeyHex: 'ab'.repeat(32),
      ackMode: 'threshold',
      ackTimeoutMs: 1500,
      streamIntervalMs: 1000,
    });
  });

  test('malformed key / bad mode / bad timeout are refused', () => {
    const env = {
      ...BASE,
      MANDARE_WITNESS_URL: 'http://w',
      MANDARE_WITNESS_PUBLIC_KEY: 'ab'.repeat(32),
    };
    expect(() =>
      loadConfigFromEnv({ ...env, MANDARE_WITNESS_PUBLIC_KEY: 'not-hex' })
    ).toThrow(/out-of-band/);
    expect(() => loadConfigFromEnv({ ...env, MANDARE_WITNESS_ACK_MODE: 'sometimes' })).toThrow(
      /invalid MANDARE_WITNESS_ACK_MODE/
    );
    expect(() => loadConfigFromEnv({ ...env, MANDARE_WITNESS_ACK_TIMEOUT_MS: '5' })).toThrow(
      /≥ 50/
    );
  });
});
