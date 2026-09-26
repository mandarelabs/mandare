import type { LedgerMeta } from '@mandarelabs/ledger';
import { hexToBytes, sha256HexAsync, type LedgerEntryV1 } from '@mandarelabs/spec';
import type { KeyDirectory, TreeHead } from '@mandarelabs/verifier';
import { fetchVerifiedWitnessedHead, type WitnessedHeadRecord } from '@mandarelabs/witness-protocol';

import { checkConsistency, type ConsistencyStatus } from './consistency.js';

/**
 * `verify --witness` source binding (W-1, audit 2026-09). The witnessed head
 * history is only evidence about THIS ledger if it is looked up under the
 * source the verifying key defines. The file's own `ledger_meta.door_key_id`
 * is attacker-writable: re-witness a truncated or rewritten tree under a
 * fresh source (the witness registers any self-authenticating source on
 * first contact), repoint the meta row, and a lookup by the declared id
 * reports CONSISTENT for a timeline the witness never saw for the real key.
 * Same rule as S8/C1 on the certificate path: the source IS the key.
 */

export type WitnessBindingMode = 'door-key' | 'directory' | 'self-declared';

export interface WitnessBinding {
  mode: WitnessBindingMode;
  /** Sources whose witnessed history the local tree must extend. */
  sourceIds: string[];
  /** The source the ledger file declares (`ledger_meta.door_key_id`) — untrusted. */
  declared: string;
  /** Why the file's declared source was rejected (verification fails), or null. */
  mismatch: string | null;
}

const MODE_LABEL: Record<WitnessBindingMode, string> = {
  'door-key': 'bound to the out-of-band door key',
  directory: 'a key-directory key that signed this chain',
  'self-declared': 'self-declared source — pass --door-key to bind',
};

export interface WitnessSourceResult {
  source_id: string;
  record: WitnessedHeadRecord | null;
  consistency: ConsistencyStatus | null;
}

export interface WitnessJson {
  url: string;
  mode: WitnessBindingMode;
  /** The (first) bound source — never the file's declared id unless they agree. */
  source_id: string;
  source_mismatch: string | null;
  /** W-4: a witnessed entry claims a time after the witness recorded it. */
  timeline_violation: string | null;
  /** Verdict of the worst source (the only one, outside directory mode). */
  record: WitnessedHeadRecord | null;
  consistency: ConsistencyStatus | null;
  sources: WitnessSourceResult[];
}

export interface WitnessCheck {
  lines: string[];
  json: WitnessJson;
  failed: boolean;
  /** The witness could not be asked — verification stops, unverified. */
  unavailable: boolean;
}

async function keyIdOf(publicKeyHex: string): Promise<string> {
  return sha256HexAsync(hexToBytes(publicKeyHex));
}

/**
 * Derive the witnessed source(s) from the key the chain was verified
 * against. Door-key mode: sha256(--door-key). Directory mode: every key
 * that signed the (already verified) chain — all directory keys when the
 * chain is empty, so a ledger truncated to nothing still meets its history.
 * Self-anchored: sha256(meta.door_public_key), the key the chain verified
 * under — the declared id must agree, but the lookup never trusts it.
 */
export async function bindWitnessSources(
  meta: LedgerMeta,
  entries: readonly LedgerEntryV1[],
  options: { doorPublicKey?: string },
  directory: KeyDirectory | undefined
): Promise<WitnessBinding> {
  const declared = meta.door_key_id;
  if (directory !== undefined) {
    const signers = [...new Set(entries.map((entry) => entry.door_signature.key_id))];
    const sourceIds = signers.length > 0 ? signers : directory.keys.map((key) => key.keyId);
    const mismatch =
      signers.length > 0 && !signers.includes(declared)
        ? 'no entry in the chain was signed by that key'
        : null;
    return { mode: 'directory', sourceIds, declared, mismatch };
  }
  if (options.doorPublicKey !== undefined) {
    const bound = await keyIdOf(options.doorPublicKey);
    const mismatch = bound === declared ? null : `the out-of-band door key is source ${bound.slice(0, 12)}…`;
    return { mode: 'door-key', sourceIds: [bound], declared, mismatch };
  }
  const bound = await keyIdOf(meta.door_public_key);
  const mismatch =
    bound === declared
      ? null
      : `sha256(door_public_key) is ${bound.slice(0, 12)}… — the file's source identity is forged`;
  return { mode: 'self-declared', sourceIds: [bound], declared, mismatch };
}

const SEVERITY: Record<ConsistencyStatus['status'] | 'none', number> = {
  identical: 0,
  extended: 0,
  none: 1,
  rollback: 2,
  inconsistent: 3,
};

function severity(result: WitnessSourceResult): number {
  return SEVERITY[result.consistency?.status ?? 'none'];
}

function verdictLine(result: WitnessSourceResult, tree: TreeHead, prefix: string): string {
  const { record, consistency } = result;
  if (record === null || consistency === null) {
    return `witness:  ${prefix}NO HISTORY — the witness has never seen this source; nothing to compare against`;
  }
  const headLabel = `${record.head.size}:${record.head.root.slice(0, 12)}… (witnessed ${record.witnessed_at})`;
  switch (consistency.status) {
    case 'extended':
    case 'identical':
      return `witness:  ${prefix}CONSISTENT — local tree extends the witnessed head ${headLabel} append-only`;
    case 'rollback':
      return (
        `witness:  ${prefix}TRUNCATION DETECTED — the witness recorded head ${headLabel}, but the local ` +
        `ledger has only ${tree.size} entries; the newest entries were dropped after being witnessed`
      );
    case 'inconsistent':
      return (
        `witness:  ${prefix}FORK DETECTED — the local chain is NOT an append-only extension of the ` +
        `witnessed head ${headLabel}; history was rewritten after being witnessed`
      );
  }
}

/** Clock skew tolerated between the door and the witness host. */
export const WITNESS_CLOCK_SKEW_MS = 5 * 60 * 1000;

/**
 * W-4: every entry a witnessed head covers existed when the witness recorded
 * it, so none may claim a later `ts`. With the verifier's non-decreasing
 * timeline, checking the newest covered entry bounds them all. Only the
 * latest head is witness-SIGNED, so that is the one checked — a bound, not
 * a proof of when each entry was first seen.
 */
function timelineViolation(
  record: WitnessedHeadRecord,
  entries: readonly LedgerEntryV1[]
): string | null {
  const newest = entries[record.head.size - 1];
  if (newest === undefined) return null;
  const claimed = Date.parse(newest.ts);
  const witnessedAt = Date.parse(record.witnessed_at);
  if (claimed <= witnessedAt + WITNESS_CLOCK_SKEW_MS) return null;
  return (
    `entry seq ${newest.seq} claims ts ${newest.ts}, after the witness recorded it at ` +
    `${record.witnessed_at} (+${WITNESS_CLOCK_SKEW_MS / 60_000} min skew)`
  );
}

/**
 * The witnessed head is the recorded --prev-head nobody on this machine can
 * rewrite: fetched over the network, signature-verified against the
 * OUT-OF-BAND witness key, then held to the same RFC 6962 consistency
 * standard. Truncation shows up as the witnessed head EXCEEDING the local
 * tree; rewrite as a failed consistency proof.
 */
export async function checkWitness(
  witness: { url: string; publicKeyHex: string },
  binding: WitnessBinding,
  entries: readonly LedgerEntryV1[],
  tree: TreeHead
): Promise<WitnessCheck> {
  const entryHashes = entries.map((entry) => entry.entry_hash);
  const lines: string[] = [];
  const primary = binding.sourceIds[0] as string;
  const json: WitnessJson = {
    url: witness.url,
    mode: binding.mode,
    source_id: primary,
    source_mismatch: binding.mismatch,
    timeline_violation: null,
    record: null,
    consistency: null,
    sources: [],
  };
  if (binding.mismatch !== null) {
    lines.push(
      `witness:  SOURCE MISMATCH — the ledger file declares source ${binding.declared.slice(0, 12)}… ` +
        `(door_key_id), but ${binding.mismatch}; the witnessed history is looked up under the ` +
        'bound source instead'
    );
  }
  for (const sourceId of binding.sourceIds) {
    let record: WitnessedHeadRecord | null;
    try {
      const verified = await fetchVerifiedWitnessedHead({
        url: witness.url,
        sourceId,
        witnessPublicKeyHex: witness.publicKeyHex,
      });
      record = verified?.record ?? null;
    } catch (error) {
      lines.push(
        `witness:  UNAVAILABLE — ${error instanceof Error ? error.message : String(error)} ` +
          '(cannot rule out truncation; treat as unverified)'
      );
      return { lines, json, failed: true, unavailable: true };
    }
    const consistency = record === null ? null : await checkConsistency(entryHashes, tree, record.head);
    json.sources.push({ source_id: sourceId, record, consistency });
  }

  const multi = json.sources.length > 1;
  for (const result of json.sources) {
    lines.push(`witness:  source ${result.source_id.slice(0, 12)}… (${MODE_LABEL[binding.mode]})`);
    lines.push(verdictLine(result, tree, multi ? `[${result.source_id.slice(0, 12)}…] ` : ''));
  }
  for (const result of json.sources) {
    const violation =
      result.record !== null && severity(result) === 0 ? timelineViolation(result.record, entries) : null;
    if (violation !== null && json.timeline_violation === null) {
      json.timeline_violation = violation;
      lines.push(`witness:  TIMELINE VIOLATION — ${violation}`);
    }
  }
  const worst = json.sources.reduce((a, b) => (severity(b) > severity(a) ? b : a));
  json.record = worst.record;
  json.consistency = worst.consistency;

  // Directory mode may legitimately include keys with no history (e.g. an
  // empty chain checked against the whole directory): only require that at
  // least one bound source was witnessed, and that none contradicts us.
  const contradicted = json.sources.some((result) => severity(result) > 1);
  const witnessedAny = json.sources.some((result) => result.record !== null);
  const failed =
    binding.mismatch !== null || contradicted || !witnessedAny || json.timeline_violation !== null;
  return { lines, json, failed, unavailable: false };
}
