import { describe, expect, test } from 'vitest';

import { bytesToHex, sha256HexAsync } from '@mandarelabs/spec';

import {
  EMPTY_TREE_ROOT,
  computeTreeHead,
  consistencyProof,
  inclusionProof,
  verifyConsistency,
  verifyInclusion,
} from '../src/merkle.js';

/**
 * RFC 6962 test vectors from the Certificate Transparency reference
 * implementation (transparency-dev/merkle, testonly/constants.go and
 * testonly/reference_test.go) — the de-facto interop vectors for RFC 6962
 * §2.1 hashing.
 *
 * NOTE: the reference vectors define leaves as arbitrary byte strings. Our
 * public API takes 32-byte entry hashes (hex), so vector tests go through a
 * hex round-trip of the raw leaf inputs — hexToBytes accepts any even-length
 * hex, and the empty leaf '' is valid input.
 */

/** Leaf inputs from testonly.LeafInputs(), hex-encoded. */
const LEAF_INPUTS = ['', '00', '10', '2021', '3031', '40414243', '5051525354555657', '606162636465666768696a6b6c6d6e6f'];

/** RootHashes()[n] = root of the tree over the first n leaf inputs. */
const ROOT_HASHES = [
  EMPTY_TREE_ROOT,
  '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
  'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
  'aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77',
  'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
  '4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4',
  '76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef',
  'ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c',
  '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
];

/** Inclusion proof vectors from TestRefInclusionProof. */
const INCLUSION_VECTORS: { index: number; size: number; proof: string[] }[] = [
  { index: 0, size: 1, proof: [] },
  {
    index: 0,
    size: 2,
    proof: ['96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7'],
  },
  {
    index: 1,
    size: 2,
    proof: ['6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d'],
  },
  {
    index: 2,
    size: 3,
    proof: ['fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125'],
  },
  {
    index: 1,
    size: 5,
    proof: [
      '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
      '5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e',
      'bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b',
    ],
  },
  {
    index: 0,
    size: 8,
    proof: [
      '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7',
      '5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e',
      '6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4',
    ],
  },
  {
    index: 5,
    size: 8,
    proof: [
      'bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b',
      'ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0',
      'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
    ],
  },
];

/** Consistency proof vectors from TestRefConsistencyProof. */
const CONSISTENCY_VECTORS: { size1: number; size2: number; proof: string[] }[] = [
  { size1: 1, size2: 1, proof: [] },
  {
    size1: 1,
    size2: 8,
    proof: [
      '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7',
      '5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e',
      '6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4',
    ],
  },
  {
    size1: 2,
    size2: 5,
    proof: [
      '5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e',
      'bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b',
    ],
  },
  {
    size1: 6,
    size2: 8,
    proof: [
      '0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a',
      'ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0',
      'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
    ],
  },
];

function leaves(size: number): string[] {
  return LEAF_INPUTS.slice(0, size);
}

/** Synthetic 32-byte leaf inputs, like real entry hashes. */
async function syntheticLeaves(size: number): Promise<string[]> {
  return Promise.all(
    Array.from({ length: size }, (_, i) => sha256HexAsync(`synthetic-entry-${i}`))
  );
}

describe('RFC 6962 tree heads (official root vectors)', () => {
  test('empty tree root is SHA-256 of the empty string', async () => {
    const head = await computeTreeHead([]);
    expect(head).toEqual({ size: 0, root: EMPTY_TREE_ROOT });
    expect(await sha256HexAsync(new Uint8Array(0))).toBe(EMPTY_TREE_ROOT);
  });

  for (let size = 1; size <= 8; size += 1) {
    test(`root of ${size}-leaf tree matches RootHashes()[${size}]`, async () => {
      const head = await computeTreeHead(leaves(size));
      expect(head).toEqual({ size, root: ROOT_HASHES[size] });
    });
  }
});

describe('inclusion proofs (official vectors)', () => {
  for (const vector of INCLUSION_VECTORS) {
    test(`PATH(${vector.index}, D[${vector.size}]) matches and verifies`, async () => {
      const proof = await inclusionProof(leaves(vector.size), vector.index);
      expect(proof).toEqual(vector.proof);
      expect(
        await verifyInclusion({
          index: vector.index,
          treeSize: vector.size,
          entryHash: LEAF_INPUTS[vector.index] as string,
          proof,
          root: ROOT_HASHES[vector.size] as string,
        })
      ).toBe(true);
    });
  }
});

describe('consistency proofs (official vectors)', () => {
  for (const vector of CONSISTENCY_VECTORS) {
    test(`PROOF(${vector.size1}, D[${vector.size2}]) matches and verifies`, async () => {
      const proof = await consistencyProof(leaves(vector.size2), vector.size1);
      expect(proof).toEqual(vector.proof);
      expect(
        await verifyConsistency({
          size1: vector.size1,
          root1: ROOT_HASHES[vector.size1] as string,
          size2: vector.size2,
          root2: ROOT_HASHES[vector.size2] as string,
          proof,
        })
      ).toBe(true);
    });
  }
});

describe('property sweep: every proof verifies at every size (synthetic 32-byte leaves)', () => {
  const SWEEP_SIZE = 33;
  // The sweeps are O(n³)-ish WebCrypto work and share a 2-core CI runner
  // with every other package's tests; the default 5s budget is a load
  // flake, not a property (first tripped when S5 added a test package to
  // the parallel set). Generous timeout — the ASSERTIONS are unchanged.
  const SWEEP_TIMEOUT_MS = 120_000;

  test('all inclusion proofs verify; wrong index/root/proof fail', { timeout: SWEEP_TIMEOUT_MS }, async () => {
    const entryHashes = await syntheticLeaves(SWEEP_SIZE);
    for (let size = 1; size <= SWEEP_SIZE; size += 1) {
      const prefix = entryHashes.slice(0, size);
      const { root } = await computeTreeHead(prefix);
      for (let index = 0; index < size; index += 1) {
        const proof = await inclusionProof(prefix, index);
        expect(
          await verifyInclusion({ index, treeSize: size, entryHash: prefix[index] as string, proof, root })
        ).toBe(true);
      }
    }
  });

  test('all consistency proofs verify across all size pairs', { timeout: SWEEP_TIMEOUT_MS }, async () => {
    const entryHashes = await syntheticLeaves(SWEEP_SIZE);
    const roots: string[] = [EMPTY_TREE_ROOT];
    for (let size = 1; size <= SWEEP_SIZE; size += 1) {
      roots.push((await computeTreeHead(entryHashes.slice(0, size))).root);
    }
    for (let size2 = 1; size2 <= SWEEP_SIZE; size2 += 1) {
      for (let size1 = 1; size1 <= size2; size1 += 1) {
        const proof = await consistencyProof(entryHashes.slice(0, size2), size1);
        expect(
          await verifyConsistency({
            size1,
            root1: roots[size1] as string,
            size2,
            root2: roots[size2] as string,
            proof,
          })
        ).toBe(true);
      }
    }
  });
});

describe('tampered proofs fail', () => {
  test('inclusion: flipped proof node, wrong leaf, wrong root all fail', async () => {
    const entryHashes = await syntheticLeaves(8);
    const { root } = await computeTreeHead(entryHashes);
    const proof = await inclusionProof(entryHashes, 3);
    const good = { index: 3, treeSize: 8, entryHash: entryHashes[3] as string, proof, root };

    expect(await verifyInclusion(good)).toBe(true);
    expect(await verifyInclusion({ ...good, entryHash: entryHashes[4] as string })).toBe(false);
    expect(await verifyInclusion({ ...good, root: EMPTY_TREE_ROOT })).toBe(false);
    expect(await verifyInclusion({ ...good, index: 4 })).toBe(false);
    const flipped = [...proof];
    flipped[0] = (await computeTreeHead([entryHashes[0] as string])).root;
    expect(await verifyInclusion({ ...good, proof: flipped })).toBe(false);
    expect(await verifyInclusion({ ...good, proof: proof.slice(1) })).toBe(false);
  });

  test('consistency: diverging history is rejected', async () => {
    const honest = await syntheticLeaves(6);
    const { root: root4 } = await computeTreeHead(honest.slice(0, 4));

    // Attacker rewrites entry 2 and regrows the tree to size 6.
    const rewritten = [...honest];
    rewritten[2] = await sha256HexAsync('forged-entry');
    const { root: forgedRoot6 } = await computeTreeHead(rewritten);
    const forgedProof = await consistencyProof(rewritten, 4);

    expect(
      await verifyConsistency({ size1: 4, root1: root4, size2: 6, root2: forgedRoot6, proof: forgedProof })
    ).toBe(false);
  });

  test('consistency: shrunk tree (rollback) is rejected', async () => {
    const entryHashes = await syntheticLeaves(6);
    const { root: root6 } = await computeTreeHead(entryHashes);
    const { root: root3 } = await computeTreeHead(entryHashes.slice(0, 3));
    expect(
      await verifyConsistency({ size1: 6, root1: root6, size2: 3, root2: root3, proof: [] })
    ).toBe(false);
  });

  test('consistency vs the empty tree requires the true empty root (review S1-M1)', async () => {
    const entryHashes = await syntheticLeaves(3);
    const { root } = await computeTreeHead(entryHashes);
    expect(
      await verifyConsistency({ size1: 0, root1: EMPTY_TREE_ROOT, size2: 3, root2: root, proof: [] })
    ).toBe(true);
    expect(
      await verifyConsistency({ size1: 0, root1: 'ab'.repeat(32), size2: 3, root2: root, proof: [] })
    ).toBe(false);
  });

  test('consistency: equal sizes require identical roots and empty proof', async () => {
    const entryHashes = await syntheticLeaves(3);
    const { root } = await computeTreeHead(entryHashes);
    expect(await verifyConsistency({ size1: 3, root1: root, size2: 3, root2: root, proof: [] })).toBe(true);
    expect(
      await verifyConsistency({ size1: 3, root1: root, size2: 3, root2: EMPTY_TREE_ROOT, proof: [] })
    ).toBe(false);
    expect(
      await verifyConsistency({ size1: 3, root1: root, size2: 3, root2: root, proof: [root] })
    ).toBe(false);
  });
});

describe('input validation', () => {
  test('rejects out-of-range indices and sizes', async () => {
    const entryHashes = await syntheticLeaves(3);
    await expect(inclusionProof(entryHashes, 3)).rejects.toThrow(/out of range/);
    await expect(consistencyProof(entryHashes, 0)).rejects.toThrow(/out of range/);
    await expect(consistencyProof(entryHashes, 4)).rejects.toThrow(/out of range/);
    await expect(computeTreeHead(['zz'])).rejects.toThrow();
  });

  test('verifiers return false (not throw) on malformed proof shapes', async () => {
    const entryHashes = await syntheticLeaves(2);
    const { root } = await computeTreeHead(entryHashes);
    expect(
      await verifyInclusion({ index: 5, treeSize: 2, entryHash: entryHashes[0] as string, proof: [], root })
    ).toBe(false);
    expect(
      await verifyConsistency({ size1: 1, root1: root, size2: 2, root2: root, proof: [] })
    ).toBe(false);
  });
});

describe('hex helpers round-trip', () => {
  test('bytesToHex output feeds back through the tree API', async () => {
    const bytes = new Uint8Array([0, 1, 2, 255]);
    const hex = bytesToHex(bytes);
    const head = await computeTreeHead([hex]);
    expect(head.size).toBe(1);
  });
});
