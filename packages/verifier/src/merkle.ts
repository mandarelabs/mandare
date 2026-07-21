import { bytesToHex, hexToBytes } from '@mandarelabs/spec';

/**
 * RFC 6962 Merkle tree over ledger entry hashes (hand-rolled, BUILD-DECISIONS
 * Q5). Portable: WebCrypto only, no Node-specific APIs.
 *
 * Tree contract (Mandare ledger profile):
 * - leaf index i (0-based) corresponds to the ledger entry with seq i + 1;
 * - the leaf INPUT is the raw 32 bytes of that entry's `entry_hash`;
 * - hashing follows RFC 6962 §2.1 exactly:
 *     MTH({})    = SHA-256()
 *     MTH({d0})  = SHA-256(0x00 || d0)
 *     MTH(D[n])  = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n])),
 *                  k = largest power of two < n
 *
 * A `TreeHead` {size, root} is the compact commitment to a ledger prefix.
 * Consistency proofs between two heads prove append-only growth — this is
 * the primitive that turns a recorded head into rollback/rewrite detection
 * (locally with `mandare verify --prev-head`, off-machine via the S6 witness).
 * Inclusion proofs support selective disclosure (SPEC §6): reveal one entry
 * plus its audit path, keep the rest private.
 *
 * NOTE (deviation from Q5's letter, logged in TASKS.md S1): inclusion proofs
 * are hand-rolled here too. @openzeppelin/merkle-tree builds a balanced
 * heap-array tree with commutative (sorted-pair) node hashing — structurally
 * incompatible with RFC 6962's split-at-power-of-two shape, so its inclusion
 * proofs cannot share a root with RFC 6962 consistency proofs.
 */

export interface TreeHead {
  /** Number of leaves (= ledger entries) committed to. */
  size: number;
  /** RFC 6962 Merkle tree hash, lowercase sha256 hex. */
  root: string;
}

/** MTH of the empty tree: SHA-256 of the empty string. */
export const EMPTY_TREE_ROOT = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

const LEAF_PREFIX = 0x00;
const NODE_PREFIX = 0x01;

/**
 * Sizes/indices are validated to stay below 2^31 so 32-bit bitwise operators
 * are safe. A ledger approaching 2^31 entries needs batching long before this
 * limit bites.
 */
const MAX_TREE_SIZE = 2 ** 31 - 1;

async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const joined = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.length;
  }
  const digest = await globalThis.crypto.subtle.digest('SHA-256', joined as Uint8Array<ArrayBuffer>);
  return new Uint8Array(digest);
}

function leafHash(leafInput: Uint8Array): Promise<Uint8Array> {
  return sha256(new Uint8Array([LEAF_PREFIX]), leafInput);
}

function nodeHash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return sha256(new Uint8Array([NODE_PREFIX]), left, right);
}

/** Largest power of two strictly smaller than n (n >= 2). */
function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) {
    k *= 2;
  }
  return k;
}

function checkSize(size: number, what: string): void {
  if (!Number.isInteger(size) || size < 0 || size > MAX_TREE_SIZE) {
    throw new RangeError(`${what} must be an integer in [0, 2^31): got ${size}`);
  }
}

function toLeafInputs(entryHashes: readonly string[]): Uint8Array[] {
  checkSize(entryHashes.length, 'tree size');
  return entryHashes.map((hex) => hexToBytes(hex));
}

/** MTH(D[n]) per RFC 6962 §2.1 over the leaf inputs [start, end). */
async function subtreeRoot(leaves: readonly Uint8Array[], start: number, end: number): Promise<Uint8Array> {
  const n = end - start;
  if (n === 0) {
    return sha256();
  }
  if (n === 1) {
    return leafHash(leaves[start] as Uint8Array);
  }
  const k = splitPoint(n);
  const [left, right] = await Promise.all([
    subtreeRoot(leaves, start, start + k),
    subtreeRoot(leaves, start + k, end),
  ]);
  return nodeHash(left, right);
}

/** Compute the tree head committing to the given ledger entry hashes. */
export async function computeTreeHead(entryHashes: readonly string[]): Promise<TreeHead> {
  const leaves = toLeafInputs(entryHashes);
  const root = await subtreeRoot(leaves, 0, leaves.length);
  return { size: leaves.length, root: bytesToHex(root) };
}

/**
 * Inclusion proof (audit path) for leaf `index` in the tree over
 * `entryHashes`, per RFC 6962 §2.1.1 PATH(m, D[n]).
 */
export async function inclusionProof(
  entryHashes: readonly string[],
  index: number
): Promise<string[]> {
  const leaves = toLeafInputs(entryHashes);
  checkSize(index, 'leaf index');
  if (index >= leaves.length) {
    throw new RangeError(`leaf index ${index} out of range for tree of size ${leaves.length}`);
  }
  const path = await subtreePath(leaves, index, 0, leaves.length);
  return path.map((node) => bytesToHex(node));
}

async function subtreePath(
  leaves: readonly Uint8Array[],
  index: number,
  start: number,
  end: number
): Promise<Uint8Array[]> {
  const n = end - start;
  if (n <= 1) {
    return [];
  }
  const k = splitPoint(n);
  if (index - start < k) {
    const path = await subtreePath(leaves, index, start, start + k);
    path.push(await subtreeRoot(leaves, start + k, end));
    return path;
  }
  const path = await subtreePath(leaves, index, start + k, end);
  path.push(await subtreeRoot(leaves, start, start + k));
  return path;
}

/**
 * Consistency proof PROOF(m, D[n]) between the tree of size `size1` (a prefix
 * of `entryHashes`) and the full tree, per RFC 6962 §2.1.2.
 */
export async function consistencyProof(
  entryHashes: readonly string[],
  size1: number
): Promise<string[]> {
  const leaves = toLeafInputs(entryHashes);
  checkSize(size1, 'size1');
  if (size1 === 0 || size1 > leaves.length) {
    throw new RangeError(`size1 ${size1} out of range for tree of size ${leaves.length}`);
  }
  const proof = await subtreeConsistency(leaves, 0, leaves.length, size1, true);
  return proof.map((node) => bytesToHex(node));
}

async function subtreeConsistency(
  leaves: readonly Uint8Array[],
  start: number,
  end: number,
  size1: number,
  haveRoot1: boolean
): Promise<Uint8Array[]> {
  const n = end - start;
  if (size1 === n) {
    return haveRoot1 ? [] : [await subtreeRoot(leaves, start, end)];
  }
  const k = splitPoint(n);
  if (size1 <= k) {
    const proof = await subtreeConsistency(leaves, start, start + k, size1, haveRoot1);
    proof.push(await subtreeRoot(leaves, start + k, end));
    return proof;
  }
  const proof = await subtreeConsistency(leaves, start + k, end, size1 - k, false);
  proof.push(await subtreeRoot(leaves, start, start + k));
  return proof;
}

export interface InclusionVerifyInput {
  /** 0-based leaf index the proof is for. */
  index: number;
  /** Total tree size the root commits to. */
  treeSize: number;
  /** The leaf INPUT (raw entry_hash), lowercase hex — NOT the leaf hash. */
  entryHash: string;
  /** Audit path, leaf-to-root, lowercase hex nodes. */
  proof: readonly string[];
  /** Expected tree root, lowercase hex. */
  root: string;
}

/**
 * Verify an inclusion proof without access to the other leaves
 * (RFC 6962 §2.1.1 verification; decomposition per the CT reference
 * implementation: inner path below the index/size fork, then the right
 * border).
 */
export async function verifyInclusion(input: InclusionVerifyInput): Promise<boolean> {
  const { index, treeSize, proof } = input;
  checkSize(treeSize, 'treeSize');
  checkSize(index, 'leaf index');
  if (index >= treeSize) {
    return false;
  }
  const inner = bitLength(index ^ (treeSize - 1));
  const border = onesCount(index >>> inner);
  if (proof.length !== inner + border) {
    return false;
  }
  const proofBytes = proof.map((hex) => hexToBytes(hex));
  let seed = await leafHash(hexToBytes(input.entryHash));
  seed = await chainInner(seed, proofBytes.slice(0, inner), index);
  seed = await chainBorderRight(seed, proofBytes.slice(inner));
  return bytesToHex(seed) === input.root;
}

export interface ConsistencyVerifyInput {
  size1: number;
  root1: string;
  size2: number;
  root2: string;
  /** Consistency proof nodes, lowercase hex. */
  proof: readonly string[];
}

/**
 * Verify that the tree (size2, root2) is an append-only extension of
 * (size1, root1), per RFC 6962 §2.1.2 verification (CT reference algorithm).
 */
export async function verifyConsistency(input: ConsistencyVerifyInput): Promise<boolean> {
  const { size1, size2, proof } = input;
  checkSize(size1, 'size1');
  checkSize(size2, 'size2');
  if (size2 < size1) {
    return false;
  }
  if (size1 === size2) {
    return proof.length === 0 && input.root1 === input.root2;
  }
  if (size1 === 0) {
    // Any tree is consistent with the empty tree; the proof carries nothing.
    return proof.length === 0;
  }

  const proofBytes = proof.map((hex) => hexToBytes(hex));
  // Decompose the path for leaf (size1 - 1) in the size2 tree, then skip the
  // levels below size1's largest complete subtree (shift).
  const shift = trailingZeros(size1);
  const inner = bitLength((size1 - 1) ^ (size2 - 1)) - shift;
  const border = onesCount((size1 - 1) >>> (shift + inner));

  let seed: Uint8Array;
  let rest: Uint8Array[];
  if (size1 === 1 << shift) {
    // size1 is a power of two: its root is a node of the size2 tree, so the
    // proof does not repeat it.
    seed = hexToBytes(input.root1);
    rest = proofBytes;
  } else {
    if (proofBytes.length === 0) {
      return false;
    }
    seed = proofBytes[0] as Uint8Array;
    rest = proofBytes.slice(1);
  }
  if (rest.length !== inner + border) {
    return false;
  }

  const mask = (size1 - 1) >>> shift;
  const innerNodes = rest.slice(0, inner);
  const borderNodes = rest.slice(inner);

  // Reconstruct root1: only the right-turn steps of the inner path exist in
  // the size1 tree.
  let hash1 = await chainInnerRight(seed, innerNodes, mask);
  hash1 = await chainBorderRight(hash1, borderNodes);
  if (bytesToHex(hash1) !== input.root1) {
    return false;
  }

  // Reconstruct root2 using the full path.
  let hash2 = await chainInner(seed, innerNodes, mask);
  hash2 = await chainBorderRight(hash2, borderNodes);
  return bytesToHex(hash2) === input.root2;
}

async function chainInner(seed: Uint8Array, nodes: Uint8Array[], index: number): Promise<Uint8Array> {
  let hash = seed;
  for (let i = 0; i < nodes.length; i += 1) {
    const sibling = nodes[i] as Uint8Array;
    hash = (index >>> i) & 1 ? await nodeHash(sibling, hash) : await nodeHash(hash, sibling);
  }
  return hash;
}

async function chainInnerRight(
  seed: Uint8Array,
  nodes: Uint8Array[],
  index: number
): Promise<Uint8Array> {
  let hash = seed;
  for (let i = 0; i < nodes.length; i += 1) {
    if ((index >>> i) & 1) {
      hash = await nodeHash(nodes[i] as Uint8Array, hash);
    }
  }
  return hash;
}

async function chainBorderRight(seed: Uint8Array, nodes: Uint8Array[]): Promise<Uint8Array> {
  let hash = seed;
  for (const node of nodes) {
    hash = await nodeHash(node, hash);
  }
  return hash;
}

function bitLength(x: number): number {
  return 32 - Math.clz32(x);
}

function onesCount(x: number): number {
  let count = 0;
  let value = x;
  while (value !== 0) {
    count += value & 1;
    value >>>= 1;
  }
  return count;
}

function trailingZeros(x: number): number {
  if (x === 0) {
    return 32;
  }
  return 31 - Math.clz32(x & -x);
}
