import { readFile } from 'node:fs/promises';

import { readLedger } from '@mandarelabs/ledger';

import { buildApprovalReport, type ApprovalReport } from './approval-report.js';
import { buildSpendReport, type SpendReport } from './spend-report.js';
import { buildRevocationReport, type RevocationReport } from './revocation-report.js';
import {
  computeTreeHead,
  consistencyProof,
  inclusionProof,
  parseKeyDirectory,
  verifyChain,
  verifyConsistency,
  type KeyDirectory,
  type TreeHead,
  type VerifyResult,
} from '@mandarelabs/verifier';
import { fetchVerifiedWitnessedHead, type WitnessedHeadRecord } from '@mandarelabs/witness-protocol';

/** Result of checking the current tree against a previously recorded head. */
export type ConsistencyStatus =
  | { status: 'extended'; prev: TreeHead }
  | { status: 'identical'; prev: TreeHead }
  | { status: 'rollback'; prev: TreeHead; reason: string }
  | { status: 'inconsistent'; prev: TreeHead; reason: string };

export interface InclusionProofOutput {
  seq: number;
  index: number;
  tree_size: number;
  entry_hash: string;
  root: string;
  proof: string[];
}

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
    tree?: TreeHead;
    consistency?: ConsistencyStatus;
    witness?: {
      url: string;
      record: WitnessedHeadRecord | null;
      consistency: ConsistencyStatus | null;
    };
    inclusion_proof?: InclusionProofOutput;
    spend?: SpendReport['json'];
    approvals?: ApprovalReport['json'];
    revocations?: RevocationReport['json'];
  };
}

export interface VerifyOptions {
  doorPublicKey?: string;
  /** Path or https URL of an out-of-band key directory (JWKS). */
  keyDirectory?: string;
  /** Previously recorded head to check append-only consistency against. */
  prevHead?: TreeHead;
  /** Produce an inclusion proof for this seq (1-based). */
  proveSeq?: number;
  /** Render the spend trail + budget-counter invariant check (S2). */
  spend?: boolean;
  /**
   * Check the local chain against the externally witnessed head history
   * (S6). Catches truncation and rewrite that self-anchored verification —
   * and even an out-of-band door key — structurally cannot: the witnessed
   * head lives where a local attacker can't rewrite it.
   */
  witness?: { url: string; publicKeyHex: string };
}

/**
 * Load a key directory from a local file or https URL. The whole point of the
 * directory is that it arrives OUT-OF-BAND — from a path/URL the verifier
 * trusts independently of the ledger file (closes S0 review finding H1).
 */
async function loadKeyDirectory(source: string): Promise<KeyDirectory> {
  let text: string;
  if (source.startsWith('https://') || source.startsWith('http://')) {
    const response = await fetch(source, {
      headers: { accept: 'application/http-message-signatures-directory+json, application/json' },
    });
    if (!response.ok) {
      throw new Error(`key directory fetch failed: ${response.status} ${response.statusText}`);
    }
    text = await response.text();
  } else {
    text = await readFile(source, 'utf8');
  }
  return parseKeyDirectory(JSON.parse(text) as unknown);
}

async function checkConsistency(
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

export async function runVerify(
  dbPath: string,
  options: VerifyOptions = {}
): Promise<VerifyCommandOutput> {
  const { meta, entries } = readLedger(dbPath);
  // iat for the status-list render only (does not affect the bitstring bytes).
  const nowSeconds = Math.floor(Date.now() / 1000);
  // Out-of-band anchors beat the file's self-declared key: an attacker with
  // file access can re-sign the chain under a swapped key, so
  // meta.door_public_key only proves internal consistency, not authorship.
  const directory =
    options.keyDirectory === undefined ? undefined : await loadKeyDirectory(options.keyDirectory);
  const selfAnchored = options.doorPublicKey === undefined && directory === undefined;
  const result = await verifyChain(
    entries,
    directory !== undefined
      ? { keyDirectory: directory }
      : { doorPublicKey: options.doorPublicKey ?? meta.door_public_key }
  );

  const lines = [
    `ledger:   ${dbPath}`,
    `door:     ${meta.door_id} (key ${meta.door_key_id.slice(0, 12)}…)`,
    `entries:  ${result.entries}`,
  ];
  const json: VerifyCommandOutput['json'] = {
    db: dbPath,
    door_id: meta.door_id,
    door_key_id: meta.door_key_id,
    result,
  };

  if (!result.ok) {
    lines.push(
      `chain:    INVALID at seq ${result.failure.seq ?? '?'} (entry ${result.failure.index + 1} of ${result.entries})`,
      `reason:   [${result.failure.code}] ${result.failure.reason}`
    );
    return { exitCode: 1, lines, json };
  }

  // Chain is valid — commit to it with an RFC 6962 tree head.
  const entryHashes = (entries as { entry_hash: string }[]).map((entry) => entry.entry_hash);
  const tree = await computeTreeHead(entryHashes);
  json.tree = tree;

  lines.push(
    `head:     ${result.headHash === null ? '(empty chain)' : result.headHash}`,
    `tree:     size=${tree.size} root=${tree.root}`,
    'chain:    VALID — every entry hash-linked and door-signed'
  );
  lines.push(
    selfAnchored
      ? 'anchor:   SELF-ANCHORED — door key taken from the ledger file itself; pass --door-key <hex> or --key-directory <path|url> from an independent source to verify authorship'
      : directory !== undefined
        ? `anchor:   key directory supplied out-of-band (${directory.keys.length} key${directory.keys.length === 1 ? '' : 's'})`
        : 'anchor:   door key supplied out-of-band'
  );

  let exitCode: 0 | 1 = 0;

  if (options.prevHead !== undefined) {
    const consistency = await checkConsistency(entryHashes, tree, options.prevHead);
    json.consistency = consistency;
    const prevLabel = `${consistency.prev.size}:${consistency.prev.root.slice(0, 12)}…`;
    switch (consistency.status) {
      case 'extended':
        lines.push(`prev:     CONSISTENT — current tree extends recorded head ${prevLabel} append-only`);
        break;
      case 'identical':
        lines.push(`prev:     CONSISTENT — tree unchanged since recorded head ${prevLabel}`);
        break;
      case 'rollback':
        lines.push(`prev:     ROLLBACK DETECTED — ${consistency.reason}`);
        exitCode = 1;
        break;
      case 'inconsistent':
        lines.push(`prev:     INCONSISTENT — ${consistency.reason}`);
        exitCode = 1;
        break;
    }
  } else {
    lines.push(
      'note:     record the tree head (size:root) after each verify — a later --prev-head check makes rollback and rewrites detectable; witnessing (S6) automates this off-machine.'
    );
  }

  if (options.witness !== undefined) {
    // The witnessed head is the recorded --prev-head nobody on this machine
    // can rewrite: fetched over the network, signature-verified against the
    // OUT-OF-BAND witness key, then held to the same RFC 6962 consistency
    // standard. Truncation shows up as the witnessed head EXCEEDING the
    // local tree; rewrite as a failed consistency proof.
    let record: WitnessedHeadRecord | null;
    try {
      const verified = await fetchVerifiedWitnessedHead({
        url: options.witness.url,
        sourceId: meta.door_key_id,
        witnessPublicKeyHex: options.witness.publicKeyHex,
      });
      record = verified?.record ?? null;
    } catch (error) {
      lines.push(
        `witness:  UNAVAILABLE — ${error instanceof Error ? error.message : String(error)} ` +
          '(cannot rule out truncation; treat as unverified)'
      );
      json.witness = { url: options.witness.url, record: null, consistency: null };
      return { exitCode: 1, lines, json };
    }
    if (record === null) {
      lines.push(
        'witness:  NO HISTORY — the witness has never seen this source; nothing to compare against'
      );
      json.witness = { url: options.witness.url, record: null, consistency: null };
      exitCode = 1;
    } else {
      const witnessConsistency = await checkConsistency(entryHashes, tree, record.head);
      json.witness = { url: options.witness.url, record, consistency: witnessConsistency };
      const headLabel = `${record.head.size}:${record.head.root.slice(0, 12)}… (witnessed ${record.witnessed_at})`;
      switch (witnessConsistency.status) {
        case 'extended':
        case 'identical':
          lines.push(`witness:  CONSISTENT — local tree extends the witnessed head ${headLabel} append-only`);
          break;
        case 'rollback':
          lines.push(
            `witness:  TRUNCATION DETECTED — the witness recorded head ${headLabel}, but the local ` +
              `ledger has only ${tree.size} entries; the newest entries were dropped after being witnessed`
          );
          exitCode = 1;
          break;
        case 'inconsistent':
          lines.push(
            `witness:  FORK DETECTED — the local chain is NOT an append-only extension of the ` +
              `witnessed head ${headLabel}; history was rewritten after being witnessed`
          );
          exitCode = 1;
          break;
      }
    }
  }

  if (options.spend === true) {
    const spendReport = await buildSpendReport(dbPath, entries);
    lines.push(...spendReport.lines);
    json.spend = spendReport.json;
    if (!spendReport.countersConsistent) {
      exitCode = 1;
    }
  }

  // Approvals are always surfaced when present — the human decisions are part
  // of the sequence being proven (Demo 3), never hidden behind a flag.
  const approvalReport = buildApprovalReport(entries);
  if (!approvalReport.empty) {
    lines.push(...approvalReport.lines);
    json.approvals = approvalReport.json;
  }

  // Revocation is always surfaced when a ledger has kills — a killed agent is
  // never something to hide behind a flag. Empty ledgers add no output.
  const revocationReport = await buildRevocationReport(dbPath, entries, nowSeconds);
  if (!revocationReport.empty) {
    lines.push(...revocationReport.lines);
    json.revocations = revocationReport.json;
    if (!revocationReport.consistent) {
      exitCode = 1;
    }
  }

  if (options.proveSeq !== undefined) {
    if (options.proveSeq < 1 || options.proveSeq > tree.size) {
      lines.push(`prove:    seq ${options.proveSeq} is out of range (1..${tree.size})`);
      exitCode = 1;
    } else {
      const index = options.proveSeq - 1;
      const proof = await inclusionProof(entryHashes, index);
      json.inclusion_proof = {
        seq: options.proveSeq,
        index,
        tree_size: tree.size,
        entry_hash: entryHashes[index] as string,
        root: tree.root,
        proof,
      };
      lines.push(
        `prove:    inclusion proof for seq ${options.proveSeq} (${proof.length} nodes) — see --json for the full proof`
      );
    }
  }

  return { exitCode, lines, json };
}

/** Parse the `--prev-head <size>:<roothex>` argument. */
export function parsePrevHead(value: string): TreeHead {
  const match = /^(\d{1,10}):([0-9a-f]{64})$/.exec(value);
  if (match === null) {
    throw new Error('--prev-head must be <size>:<64-hex-root>, e.g. 42:ab12…');
  }
  const size = Number.parseInt(match[1] as string, 10);
  if (size > 2 ** 31 - 1) {
    throw new Error('--prev-head size exceeds the maximum tree size (2^31 - 1)');
  }
  return { size, root: match[2] as string };
}
