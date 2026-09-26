import { consistencyProof, verifyConsistency, type TreeHead } from '@mandarelabs/verifier';

/** Result of checking the current tree against a previously recorded head. */
export type ConsistencyStatus =
  | { status: 'extended'; prev: TreeHead }
  | { status: 'identical'; prev: TreeHead }
  | { status: 'rollback'; prev: TreeHead; reason: string }
  | { status: 'inconsistent'; prev: TreeHead; reason: string };

/** Hold the current tree to a recorded head: RFC 6962 append-only or bust. */
export async function checkConsistency(
  entryHashes: string[],
  current: TreeHead,
  prev: TreeHead
): Promise<ConsistencyStatus> {
  if (current.size < prev.size) {
    return {
      status: 'rollback',
      prev,
      reason: `ledger shrank from ${prev.size} to ${current.size} entries — rollback to an older copy`,
    };
  }
  if (current.size === prev.size) {
    return current.root === prev.root
      ? { status: 'identical', prev }
      : { status: 'inconsistent', prev, reason: 'same size but different root — history rewritten' };
  }
  if (prev.size === 0) {
    return { status: 'extended', prev };
  }
  const proof = await consistencyProof(entryHashes, prev.size);
  const consistent = await verifyConsistency({
    size1: prev.size,
    root1: prev.root,
    size2: current.size,
    root2: current.root,
    proof,
  });
  return consistent
    ? { status: 'extended', prev }
    : {
        status: 'inconsistent',
        prev,
        reason: 'recorded head is not a prefix of the current tree — history rewritten',
      };
}
