import { describe, expect, test } from 'vitest';

import {
  aggregateInclusionProof,
  aggregateLeafInput,
  buildAggregate,
  verifyAggregateInclusion,
} from '../src/aggregate.js';
import type { WitnessedHeadRecord } from '../src/messages.js';

function record(sourceByte: string, size: number): WitnessedHeadRecord {
  return {
    source_id: sourceByte.repeat(64),
    head: { size, root: 'ab'.repeat(32) },
    ts: '2026-08-09T10:00:00Z',
    witnessed_at: '2026-08-09T10:00:01Z',
  };
}

describe('anchoring aggregate', () => {
  test('deterministic: same records (any order) → same root', async () => {
    const records = [record('a', 5), record('b', 9), record('c', 2)];
    const one = await buildAggregate(records);
    const two = await buildAggregate([...records].reverse());
    expect(one.head).toEqual(two.head);
    expect(one.records.map((r) => r.source_id)).toEqual(two.records.map((r) => r.source_id));
  });

  test('every source proves inclusion; proofs do not transfer between leaves', async () => {
    const snapshot = await buildAggregate([record('a', 5), record('b', 9), record('c', 2)]);
    for (let i = 0; i < snapshot.records.length; i += 1) {
      const proof = await aggregateInclusionProof(snapshot, i);
      expect(
        await verifyAggregateInclusion({
          record: snapshot.records[i]!,
          leafIndex: i,
          aggregate: snapshot.head,
          proof,
        })
      ).toBe(true);
      // The same proof must NOT verify for a different record (the leaf input
      // is recomputed from the record — replay across leaves dies here).
      const other = snapshot.records[(i + 1) % snapshot.records.length]!;
      expect(
        await verifyAggregateInclusion({ record: other, leafIndex: i, aggregate: snapshot.head, proof })
      ).toBe(false);
    }
  });

  test('FORGERY: tampered head size/root in the leaf record fails', async () => {
    const snapshot = await buildAggregate([record('a', 5), record('b', 9)]);
    const proof = await aggregateInclusionProof(snapshot, 0);
    const genuine = snapshot.records[0]!;
    for (const forged of [
      { ...genuine, head: { ...genuine.head, size: genuine.head.size + 1 } },
      { ...genuine, head: { ...genuine.head, root: 'cd'.repeat(32) } },
      { ...genuine, witnessed_at: '2026-08-09T23:59:59Z' },
      { ...genuine, source_id: 'f'.repeat(64) },
    ]) {
      expect(
        await verifyAggregateInclusion({ record: forged, leafIndex: 0, aggregate: snapshot.head, proof })
      ).toBe(false);
    }
  });

  test('FORGERY: tampered proof nodes fail', async () => {
    const snapshot = await buildAggregate([record('a', 5), record('b', 9), record('c', 2)]);
    const proof = await aggregateInclusionProof(snapshot, 1);
    const tampered = [...proof];
    tampered[0] = 'ee'.repeat(32);
    expect(
      await verifyAggregateInclusion({
        record: snapshot.records[1]!,
        leafIndex: 1,
        aggregate: snapshot.head,
        proof: tampered,
      })
    ).toBe(false);
  });

  test('leaf input is domain-separated and salt-carrying', async () => {
    const leaf = await aggregateLeafInput(record('a', 5));
    expect(leaf).toMatch(/^[0-9a-f]{64}$/);
    // Different witnessed_at → different leaf (the timestamp is bound).
    const other = await aggregateLeafInput({ ...record('a', 5), witnessed_at: '2026-08-09T11:00:00Z' });
    expect(other).not.toBe(leaf);
  });
});
