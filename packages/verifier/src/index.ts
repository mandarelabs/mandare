import {
  GENESIS_PREV_HASH,
  base64UrlToBytes,
  computeEntryHashAsync,
  hexToBytes,
  isLedgerEntry,
  sha256HexAsync,
  type LedgerEntryV1,
} from '@mandarelabs/spec';

/**
 * Pure chain verification (Apache-2.0). No I/O, no Node-only APIs — this
 * module must stay runnable in browsers and edge runtimes so that anyone,
 * including parties who distrust Mandare, can verify a ledger.
 *
 * What it proves (S0 tier): schema validity, seq continuity, prev-hash
 * linkage, entry-hash correctness, and door signatures. What it CANNOT prove
 * locally: tail truncation and rollback to an older copy — that is what
 * external witnessing exists for (SPEC §6 locks 4–5, lands in S6).
 */

export type VerifyFailureCode =
  | 'SCHEMA_INVALID'
  | 'SEQ_START'
  | 'SEQ_GAP'
  | 'GENESIS_MISMATCH'
  | 'PREV_HASH_MISMATCH'
  | 'ENTRY_HASH_MISMATCH'
  | 'KEY_MISMATCH'
  | 'SIGNATURE_INVALID';

export interface VerifyFailure {
  code: VerifyFailureCode;
  /** Position in the supplied array (0-based) where verification stopped. */
  index: number;
  /** seq claimed by the offending entry, when parseable. */
  seq: number | null;
  reason: string;
}

export type VerifyResult =
  | { ok: true; entries: number; headHash: string | null }
  | { ok: false; entries: number; failure: VerifyFailure };

export interface VerifyChainOptions {
  /** Raw 32-byte Ed25519 door public key, or its lowercase-hex encoding. */
  doorPublicKey: Uint8Array | string;
}

export async function verifyChain(
  entries: readonly unknown[],
  options: VerifyChainOptions
): Promise<VerifyResult> {
  const publicKeyBytes =
    typeof options.doorPublicKey === 'string'
      ? hexToBytes(options.doorPublicKey)
      : options.doorPublicKey;
  const expectedKeyId = await sha256HexAsync(publicKeyBytes);
  const verifyKey = await globalThis.crypto.subtle.importKey(
    'raw',
    publicKeyBytes as Uint8Array<ArrayBuffer>,
    { name: 'Ed25519' },
    false,
    ['verify']
  );

  let previous: LedgerEntryV1 | null = null;
  for (let index = 0; index < entries.length; index += 1) {
    const raw = entries[index];
    if (!isLedgerEntry(raw)) {
      return fail('SCHEMA_INVALID', index, claimedSeq(raw), 'entry does not match LedgerEntryV1');
    }
    const entry: LedgerEntryV1 = raw;

    const linkFailure = checkLink(entry, previous, index);
    if (linkFailure) {
      return { ok: false, entries: entries.length, failure: linkFailure };
    }

    const { entry_hash, door_signature, ...preimage } = entry;
    const recomputed = await computeEntryHashAsync(preimage);
    if (recomputed !== entry_hash) {
      return fail(
        'ENTRY_HASH_MISMATCH',
        index,
        entry.seq,
        `stored entry_hash ${entry_hash.slice(0, 12)}… does not match recomputed ${recomputed.slice(0, 12)}…`
      );
    }

    if (door_signature.key_id !== expectedKeyId) {
      return fail(
        'KEY_MISMATCH',
        index,
        entry.seq,
        `entry signed by key ${door_signature.key_id.slice(0, 12)}…, expected ${expectedKeyId.slice(0, 12)}…`
      );
    }

    const signatureValid = await globalThis.crypto.subtle.verify(
      'Ed25519',
      verifyKey,
      base64UrlToBytes(door_signature.value) as Uint8Array<ArrayBuffer>,
      hexToBytes(entry_hash) as Uint8Array<ArrayBuffer>
    );
    if (!signatureValid) {
      return fail('SIGNATURE_INVALID', index, entry.seq, 'door signature does not verify');
    }

    previous = entry;
  }

  function fail(
    code: VerifyFailureCode,
    index: number,
    seq: number | null,
    reason: string
  ): VerifyResult {
    return { ok: false, entries: entries.length, failure: { code, index, seq, reason } };
  }

  return { ok: true, entries: entries.length, headHash: previous?.entry_hash ?? null };
}

function checkLink(
  entry: LedgerEntryV1,
  previous: LedgerEntryV1 | null,
  index: number
): VerifyFailure | null {
  if (previous === null) {
    if (entry.seq !== 1) {
      return failure('SEQ_START', index, entry.seq, `chain starts at seq ${entry.seq}, expected 1`);
    }
    if (entry.prev_hash !== GENESIS_PREV_HASH) {
      return failure('GENESIS_MISMATCH', index, entry.seq, 'first entry prev_hash is not the genesis value');
    }
    return null;
  }
  if (entry.seq !== previous.seq + 1) {
    return failure(
      'SEQ_GAP',
      index,
      entry.seq,
      `seq jumps from ${previous.seq} to ${entry.seq} (gap or reorder)`
    );
  }
  if (entry.prev_hash !== previous.entry_hash) {
    return failure(
      'PREV_HASH_MISMATCH',
      index,
      entry.seq,
      `prev_hash does not match entry_hash of seq ${previous.seq}`
    );
  }
  return null;
}

function failure(
  code: VerifyFailureCode,
  index: number,
  seq: number | null,
  reason: string
): VerifyFailure {
  return { code, index, seq, reason };
}

function claimedSeq(raw: unknown): number | null {
  if (typeof raw === 'object' && raw !== null && 'seq' in raw) {
    const seq = (raw as { seq: unknown }).seq;
    return typeof seq === 'number' ? seq : null;
  }
  return null;
}
