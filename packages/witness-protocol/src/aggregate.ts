import { base64UrlToBytes, bytesToBase64Url, canonicalJson, hexToBytes, sha256HexAsync } from '@mandarelabs/spec';
import { computeTreeHead, inclusionProof, verifyInclusion, type TreeHead } from '@mandarelabs/verifier';

import type { EpochSummary, WitnessedHeadRecord } from './messages.js';
import type { HeadSigner } from './signing.js';

/**
 * The anchoring aggregate (SPEC §3.2): one RFC 6962 tree over every source's
 * latest witnessed head, whose single root is what gets publicly anchored.
 * Anchoring N sources costs one public commitment, and each source can prove
 * its own head's inclusion without revealing that any other source exists —
 * the proof path is hashes only.
 */

/**
 * Leaf input for one source's witnessed head: sha256 of the canonical JSON of
 * the four binding fields. Domain-separated by the `leaf` tag so an aggregate
 * leaf can never be confused with a ledger entry hash, and salted transitively
 * (the root commits to salted entry hashes).
 */
export async function aggregateLeafInput(record: WitnessedHeadRecord): Promise<string> {
  return sha256HexAsync(
    canonicalJson({
      leaf: 'mandare-witness-aggregate/1',
      source_id: record.source_id,
      size: record.head.size,
      root: record.head.root,
      witnessed_at: record.witnessed_at,
    })
  );
}

export interface AggregateSnapshot {
  head: TreeHead;
  /** Records in leaf order (sorted by source_id — deterministic, rebuildable). */
  records: WitnessedHeadRecord[];
  /** Leaf inputs, index-aligned with `records`. */
  leafInputs: string[];
}

/** Build the aggregate tree over the given per-source heads (sorted by source_id). */
export async function buildAggregate(
  records: readonly WitnessedHeadRecord[]
): Promise<AggregateSnapshot> {
  const sorted = [...records].sort((a, b) => (a.source_id < b.source_id ? -1 : 1));
  const leafInputs = await Promise.all(sorted.map((record) => aggregateLeafInput(record)));
  const head = await computeTreeHead(leafInputs);
  return { head, records: sorted, leafInputs };
}

/** Inclusion proof for the leaf at `index` of a built aggregate. */
export async function aggregateInclusionProof(
  snapshot: AggregateSnapshot,
  index: number
): Promise<string[]> {
  return inclusionProof(snapshot.leafInputs, index);
}

/** Sign an epoch summary with the witness key (over the summary minus its signature). */
export async function signEpochSummary(
  summary: EpochSummary,
  signer: HeadSigner
): Promise<EpochSummary> {
  const { witness_signature: _drop, ...unsigned } = summary;
  const digest = hexToBytes(await sha256HexAsync(canonicalJson(unsigned)));
  const value = bytesToBase64Url(await signer.sign(digest));
  return { ...unsigned, witness_signature: { key_id: signer.keyId, value } };
}

/** Verify an epoch summary's witness signature against an out-of-band witness key. */
export async function verifyEpochSummary(
  summary: EpochSummary,
  witnessPublicKeyHex: string
): Promise<boolean> {
  const signature = summary.witness_signature;
  if (signature === undefined) {
    return false;
  }
  if (signature.key_id !== (await sha256HexAsync(hexToBytes(witnessPublicKeyHex)))) {
    return false;
  }
  const { witness_signature: _drop, ...unsigned } = summary;
  try {
    const key = await globalThis.crypto.subtle.importKey(
      'raw',
      hexToBytes(witnessPublicKeyHex) as Uint8Array<ArrayBuffer>,
      { name: 'Ed25519' },
      false,
      ['verify']
    );
    const digest = hexToBytes(await sha256HexAsync(canonicalJson(unsigned)));
    return await globalThis.crypto.subtle.verify(
      { name: 'Ed25519' },
      key,
      base64UrlToBytes(signature.value) as Uint8Array<ArrayBuffer>,
      digest as Uint8Array<ArrayBuffer>
    );
  } catch {
    return false;
  }
}

/**
 * Verify that a witnessed head is a leaf of an anchored aggregate root.
 * Recomputes the leaf input from the record itself — a proof for a DIFFERENT
 * head cannot be replayed onto this one (red-teamed).
 */
export async function verifyAggregateInclusion(args: {
  record: WitnessedHeadRecord;
  leafIndex: number;
  aggregate: TreeHead;
  proof: readonly string[];
}): Promise<boolean> {
  const leafInput = await aggregateLeafInput(args.record);
  return verifyInclusion({
    index: args.leafIndex,
    treeSize: args.aggregate.size,
    entryHash: leafInput,
    proof: args.proof,
    root: args.aggregate.root,
  });
}
