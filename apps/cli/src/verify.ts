import { readLedger } from '@mandarelabs/ledger';
import { verifyChain, type VerifyResult } from '@mandarelabs/verifier';

export interface VerifyCommandOutput {
  exitCode: 0 | 1;
  /** Human-readable lines (default output). */
  lines: string[];
  /** Machine-readable form (--json). */
  json: {
    db: string;
    door_id: string;
    door_key_id: string;
    result: VerifyResult;
  };
}

export async function runVerify(
  dbPath: string,
  options: { doorPublicKey?: string } = {}
): Promise<VerifyCommandOutput> {
  const { meta, entries } = readLedger(dbPath);
  // Out-of-band key beats the file's self-declared one: an attacker with file
  // access can re-sign the chain under a swapped key, so meta.door_public_key
  // only proves internal consistency, not authorship.
  const doorPublicKey = options.doorPublicKey ?? meta.door_public_key;
  const selfAnchored = options.doorPublicKey === undefined;
  const result = await verifyChain(entries, { doorPublicKey });

  const lines = [
    `ledger:   ${dbPath}`,
    `door:     ${meta.door_id} (key ${meta.door_key_id.slice(0, 12)}…)`,
    `entries:  ${result.entries}`,
  ];
  if (result.ok) {
    lines.push(
      `head:     ${result.headHash === null ? '(empty chain)' : result.headHash}`,
      'chain:    VALID — every entry hash-linked and door-signed',
      selfAnchored
        ? 'anchor:   SELF-ANCHORED — door key taken from the ledger file itself; pass --door-key <hex> from an independent source to verify authorship'
        : 'anchor:   door key supplied out-of-band',
      'note:     local verification cannot rule out tail truncation; witnessing (S6) closes that.'
    );
  } else {
    lines.push(
      `chain:    INVALID at seq ${result.failure.seq ?? '?'} (entry ${result.failure.index + 1} of ${result.entries})`,
      `reason:   [${result.failure.code}] ${result.failure.reason}`
    );
  }

  return {
    exitCode: result.ok ? 0 : 1,
    lines,
    json: { db: dbPath, door_id: meta.door_id, door_key_id: meta.door_key_id, result },
  };
}
