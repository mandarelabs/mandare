import { statSync } from 'node:fs';

import { afterEach, describe, expect, test, vi } from 'vitest';

import { GENESIS_PREV_HASH, SchemaValidationError, isLedgerEntry } from '@mandarelabs/spec';
import { verifyChain } from '@mandarelabs/verifier';

import { Ledger, readLedger } from '../src/ledger.js';
import { sampleInput, tempDbPath } from './helpers.js';

describe('Ledger.append', () => {
  test('builds a chain the independent verifier accepts', async () => {
    const dbPath = tempDbPath();
    const ledger = Ledger.open(dbPath, { doorId: 'gateway:test' });
    for (let i = 0; i < 10; i += 1) {
      ledger.append(sampleInput());
    }
    ledger.close();

    const { meta, entries } = readLedger(dbPath);
    const result = await verifyChain(entries, { doorPublicKey: meta.door_public_key });
    expect(result).toMatchObject({ ok: true, entries: 10 });
  });

  test('chains seq and prev_hash correctly from genesis', () => {
    const ledger = Ledger.open(tempDbPath(), { doorId: 'gateway:test' });
    const first = ledger.append(sampleInput());
    const second = ledger.append(sampleInput());
    expect(first.seq).toBe(1);
    expect(first.prev_hash).toBe(GENESIS_PREV_HASH);
    expect(second.seq).toBe(2);
    expect(second.prev_hash).toBe(first.entry_hash);
    expect(isLedgerEntry(first)).toBe(true);
    ledger.close();
  });

  test('continues the chain across close/reopen with the same door key', () => {
    const dbPath = tempDbPath();
    const ledger = Ledger.open(dbPath, { doorId: 'gateway:test' });
    const first = ledger.append(sampleInput());
    const keyId = ledger.doorKeyId;
    ledger.close();

    const reopened = Ledger.open(dbPath, { doorId: 'gateway:test' });
    expect(reopened.doorKeyId).toBe(keyId);
    const second = reopened.append(sampleInput());
    expect(second.seq).toBe(2);
    expect(second.prev_hash).toBe(first.entry_hash);
    reopened.close();
  });

  test('rejects hostile input at the boundary without writing (R4)', () => {
    const ledger = Ledger.open(tempDbPath(), { doorId: 'gateway:test' });
    expect(() =>
      ledger.append(
        sampleInput({
          action: { type: 'llm.call.intent', target: 'x', request_hash: 'not-hex' },
        })
      )
    ).toThrow(SchemaValidationError);
    expect(ledger.head()).toBeNull();
    ledger.close();
  });

  test('rejects fractional cost amounts (micros are integers)', () => {
    const ledger = Ledger.open(tempDbPath(), { doorId: 'gateway:test' });
    expect(() =>
      ledger.append(
        sampleInput({ cost: { amount: 1.5, currency: 'USD', tokens_in: 0, tokens_out: 0 } })
      )
    ).toThrow(SchemaValidationError);
    ledger.close();
  });
});

describe('door key handling', () => {
  test('creates the key file with owner-only permissions', () => {
    const dbPath = tempDbPath();
    const ledger = Ledger.open(dbPath, { doorId: 'gateway:test' });
    ledger.close();
    const mode = statSync(`${dbPath}.doorkey.pem`).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  test('refuses to write with a different door key (stolen-DB scenario)', () => {
    const dbPath = tempDbPath();
    const ledger = Ledger.open(dbPath, { doorId: 'gateway:test' });
    ledger.append(sampleInput());
    ledger.close();

    expect(() =>
      Ledger.open(dbPath, { doorId: 'gateway:test', keyPath: `${tempDbPath()}.other.pem` })
    ).toThrow(/refusing to write/);
  });

  test('refuses a mismatched door id', () => {
    const dbPath = tempDbPath();
    Ledger.open(dbPath, { doorId: 'gateway:test' }).close();
    expect(() => Ledger.open(dbPath, { doorId: 'vault:other' })).toThrow(/one door per ledger/);
  });
});

describe('readLedger', () => {
  test('returns meta and raw entries read-only', () => {
    const dbPath = tempDbPath();
    const ledger = Ledger.open(dbPath, { doorId: 'gateway:test' });
    ledger.append(sampleInput());
    ledger.close();

    const { meta, entries } = readLedger(dbPath);
    expect(meta.door_id).toBe('gateway:test');
    expect(meta.door_public_key).toMatch(/^[0-9a-f]{64}$/);
    expect(entries).toHaveLength(1);
  });

  test('throws a clear error on a non-ledger file', () => {
    expect(() => readLedger('/dev/null')).toThrow();
  });
});

describe('W-4: the door never writes a timeline regression', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  test('a wall clock stepping BACK clamps the next ts to the previous one; the chain verifies', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const dbPath = tempDbPath();
    const ledger = Ledger.open(dbPath, { doorId: 'gateway:test' });
    vi.setSystemTime(new Date('2026-09-26T12:00:10.000Z'));
    const first = ledger.append(sampleInput());
    vi.setSystemTime(new Date('2026-09-26T12:00:02.000Z')); // NTP step back 8 s
    const second = ledger.append(sampleInput());
    vi.setSystemTime(new Date('2026-09-26T12:00:11.000Z'));
    const third = ledger.append(sampleInput());
    ledger.close();

    expect(second.ts).toBe(first.ts);
    expect(third.ts).toBe('2026-09-26T12:00:11.000Z');
    const { meta, entries } = readLedger(dbPath);
    expect((await verifyChain(entries, { doorPublicKey: meta.door_public_key })).ok).toBe(true);
  });
});
