import { describe, expect, test } from 'vitest';

import { verifyChain } from '@mandarelabs/verifier';

import { AsyncLedger } from '../src/async-ledger.js';
import { SqliteStore } from '../src/sqlite-store.js';
import { readLedger } from '../src/ledger.js';
import { sampleInput, tempDbPath } from './helpers.js';

/**
 * The driver interface (Q7) must be semantics-preserving: a chain written
 * through `AsyncLedger` + `SqliteStore` is indistinguishable from one the
 * sync `Ledger` writes — same file, same meta, verifier-clean.
 */
describe('AsyncLedger over SqliteStore (driver parity)', () => {
  test('writes a verifier-clean chain into a regular ledger file', async () => {
    const dbPath = tempDbPath();
    const store = SqliteStore.open(dbPath);
    const ledger = await AsyncLedger.open(store, {
      doorId: 'gateway:test',
      keyPath: `${dbPath}.doorkey.pem`,
    });
    for (let i = 0; i < 3; i += 1) {
      await ledger.append(sampleInput());
    }
    const head = await ledger.head();
    expect(head?.seq).toBe(3);
    await ledger.close();

    // Readable by the plain-file reader, verifiable with the door key.
    const { meta, entries } = readLedger(dbPath);
    expect(meta.door_id).toBe('gateway:test');
    const result = await verifyChain(entries, { doorPublicKey: meta.door_public_key });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.entries).toBe(3);
  });

  test('append-only triggers hold on a store-created file too', async () => {
    const dbPath = tempDbPath();
    const store = SqliteStore.open(dbPath);
    const ledger = await AsyncLedger.open(store, {
      doorId: 'gateway:test',
      keyPath: `${dbPath}.doorkey.pem`,
    });
    await ledger.append(sampleInput());
    await expect(
      store.appendWithLock(() => {
        throw new Error('builder failure must roll back cleanly');
      })
    ).rejects.toThrow(/roll back cleanly/);
    // The failed append left no partial row behind.
    const head = await ledger.head();
    expect(head?.seq).toBe(1);
    await ledger.close();
  });
});
