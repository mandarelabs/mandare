import {
  GENESIS_PREV_HASH,
  base64UrlToBytes,
  computeEntryHashAsync,
  hexToBytes,
  isLedgerEntry,
  sha256HexAsync,
  type LedgerEntryV1,
} from '@mandarelabs/spec';

import type { DirectoryKey, KeyDirectory } from './directory.js';

export {
  DirectoryParseError,
  describeDirectory,
  directoryFromPublicKeys,
  parseKeyDirectory,
  type DirectoryKey,
  type KeyDirectory,
} from './directory.js';
export {
  parseStoredEntries,
  parseStoredEntry,
  type StoredEntriesResult,
  type StoredEntryParse,
  type StoredEntryRow,
} from './stored.js';
export {
  EMPTY_TREE_ROOT,
  computeTreeHead,
  consistencyProof,
  inclusionProof,
  verifyConsistency,
  verifyInclusion,
  type ConsistencyVerifyInput,
  type InclusionVerifyInput,
  type TreeHead,
} from './merkle.js';

/**
 * Pure chain verification (Apache-2.0). No I/O, no Node-only APIs — this
 * module must stay runnable in browsers and edge runtimes so that anyone,
 * including parties who distrust Mandare, can verify a ledger.
 *
 * What it proves (S0 tier): schema validity, seq continuity, prev-hash
 * linkage, entry-hash correctness, door signatures, and a non-decreasing
 * timeline (W-4). What it CANNOT prove
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
  | 'KEY_UNKNOWN'
  | 'KEY_EXPIRED'
  | 'SIGNATURE_INVALID'
  /** A stored row has more than one reading, or its columns disagree with it (W-3). */
  | 'STORAGE_MISMATCH'
  /** A signed entry claims a time before its predecessor, or no real instant (W-4). */
  | 'TS_REGRESSION';

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
  /**
   * Raw 32-byte Ed25519 door public key, or its lowercase-hex encoding.
   * Single-door mode: every entry must be signed by exactly this key.
   */
  doorPublicKey?: Uint8Array | string;
  /**
   * Key directory (multi-door / rotation mode): each entry's signing key is
   * resolved by `door_signature.key_id`; unknown keys fail KEY_UNKNOWN, and
   * entries timestamped outside a key's nbf/exp window fail KEY_EXPIRED.
   * Obtain the directory OUT-OF-BAND — never from the ledger file itself.
   */
  keyDirectory?: KeyDirectory;
}

/**
 * Per-entry signing-key resolution. Returns a failure code + reason instead
 * of a key when the entry's claimed key must be rejected.
 */
/** Portable stand-in for the WebCrypto CryptoKey type (lib-independent). */
type VerifyCryptoKey = Awaited<ReturnType<typeof globalThis.crypto.subtle.importKey>>;

interface KeyResolution {
  key?: VerifyCryptoKey;
  failure?: { code: VerifyFailureCode; reason: string };
}

interface KeyResolver {
  resolve(keyId: string, entryTs: string): Promise<KeyResolution>;
}

async function importVerifyKey(publicKey: Uint8Array): Promise<VerifyCryptoKey> {
  return globalThis.crypto.subtle.importKey(
    'raw',
    publicKey as Uint8Array<ArrayBuffer>,
    { name: 'Ed25519' },
    false,
    ['verify']
  );
}

async function singleKeyResolver(doorPublicKey: Uint8Array | string): Promise<KeyResolver> {
  const publicKeyBytes =
    typeof doorPublicKey === 'string' ? hexToBytes(doorPublicKey) : doorPublicKey;
  const expectedKeyId = await sha256HexAsync(publicKeyBytes);
  const verifyKey = await importVerifyKey(publicKeyBytes);
  return {
    resolve: (keyId) =>
      Promise.resolve(
        keyId === expectedKeyId
          ? { key: verifyKey }
          : {
              failure: {
                code: 'KEY_MISMATCH',
                reason: `entry signed by key ${keyId.slice(0, 12)}…, expected ${expectedKeyId.slice(0, 12)}…`,
              },
            }
      ),
  };
}

function directoryResolver(directory: KeyDirectory): KeyResolver {
  const byKeyId = new Map<string, DirectoryKey>(directory.keys.map((key) => [key.keyId, key]));
  const imported = new Map<string, Promise<VerifyCryptoKey>>();
  return {
    async resolve(keyId, entryTs) {
      const entry = byKeyId.get(keyId);
      if (entry === undefined) {
        return {
          failure: {
            code: 'KEY_UNKNOWN',
            reason: `entry signed by key ${keyId.slice(0, 12)}…, which is not in the key directory`,
          },
        };
      }
      const tsSeconds = Date.parse(entryTs) / 1000;
      // FAIL CLOSED (review S1-H1): the schema regex admits non-calendar
      // timestamps like 2026-13-01, which Date.parse turns into NaN — and
      // every NaN comparison is false, which would silently skip the
      // validity window. An unparseable ts must never pass a windowed key.
      if (!Number.isFinite(tsSeconds)) {
        return {
          failure: {
            code: 'KEY_EXPIRED',
            reason: `entry ts ${entryTs} is not a parseable instant — refusing key-window validation`,
          },
        };
      }
      if (entry.notBefore !== undefined && tsSeconds < entry.notBefore) {
        return {
          failure: {
            code: 'KEY_EXPIRED',
            reason: `entry ts ${entryTs} precedes key ${keyId.slice(0, 12)}… validity (nbf=${entry.notBefore})`,
          },
        };
      }
      if (entry.notAfter !== undefined && tsSeconds >= entry.notAfter) {
        return {
          failure: {
            code: 'KEY_EXPIRED',
            reason: `entry ts ${entryTs} is past key ${keyId.slice(0, 12)}… expiry (exp=${entry.notAfter}) — rotated-out keys cannot sign new history`,
          },
        };
      }
      let keyPromise = imported.get(keyId);
      if (keyPromise === undefined) {
        keyPromise = importVerifyKey(entry.publicKey);
        imported.set(keyId, keyPromise);
      }
      return { key: await keyPromise };
    },
  };
}

export async function verifyChain(
  entries: readonly unknown[],
  options: VerifyChainOptions
): Promise<VerifyResult> {
  if ((options.doorPublicKey === undefined) === (options.keyDirectory === undefined)) {
    throw new TypeError('verifyChain requires exactly one of doorPublicKey or keyDirectory');
  }
  const resolver =
    options.doorPublicKey !== undefined
      ? await singleKeyResolver(options.doorPublicKey)
      : directoryResolver(options.keyDirectory as KeyDirectory);

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

    const resolution = await resolver.resolve(door_signature.key_id, entry.ts);
    if (resolution.failure !== undefined || resolution.key === undefined) {
      const failureInfo = resolution.failure ?? {
        code: 'KEY_UNKNOWN' as const,
        reason: 'key resolution failed',
      };
      return fail(failureInfo.code, index, entry.seq, failureInfo.reason);
    }

    const signatureBytes = decodeSignature(door_signature.value);
    const signatureValid =
      signatureBytes !== null &&
      (await globalThis.crypto.subtle.verify(
        'Ed25519',
        resolution.key,
        signatureBytes as Uint8Array<ArrayBuffer>,
        hexToBytes(entry_hash) as Uint8Array<ArrayBuffer>
      ));
    if (!signatureValid) {
      return fail(
        'SIGNATURE_INVALID',
        index,
        entry.seq,
        signatureBytes === null ? 'door signature is not decodable base64url' : 'door signature does not verify'
      );
    }

    const timelineFailure = checkTimeline(entry, previous, index);
    if (timelineFailure) {
      return { ok: false, entries: entries.length, failure: timelineFailure };
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

/** base64url → bytes, or null for input that is schema-valid but undecodable (I-4). */
function decodeSignature(value: string): Uint8Array | null {
  try {
    return base64UrlToBytes(value);
  } catch {
    return null;
  }
}

/**
 * Timeline rule (W-4): an authentically signed entry may not claim a time
 * before its predecessor. Doors clamp `ts` to the previous entry's, so an
 * honest chain never regresses; what does is a key holder writing BEHIND
 * later history — e.g. a stolen rotated-out key appending after the new
 * key's entries, `ts` backdated into its own validity window so the
 * key-window check alone would pass. Fail closed on a `ts` that is not a
 * real instant (the schema regex admits 2026-13-01), as the window check does.
 */
function checkTimeline(
  entry: LedgerEntryV1,
  previous: LedgerEntryV1 | null,
  index: number
): VerifyFailure | null {
  const at = Date.parse(entry.ts);
  if (!Number.isFinite(at)) {
    return failure('TS_REGRESSION', index, entry.seq, `entry ts ${entry.ts} is not a parseable instant`);
  }
  if (previous !== null && at < Date.parse(previous.ts)) {
    return failure(
      'TS_REGRESSION',
      index,
      entry.seq,
      `entry ts ${entry.ts} is before seq ${previous.seq}'s ${previous.ts} — written behind later history`
    );
  }
  return null;
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
