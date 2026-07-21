import { createHash } from 'node:crypto';

import { canonicalJson } from './canonical.js';
import type { LedgerEntryPreimage } from './ledger-entry.js';

/**
 * Node-native synchronous hashing for hot paths (ledger writes). Must stay
 * byte-identical with the portable WebCrypto variants in `hash.js` — the
 * spec test suite asserts this. Browser/edge consumers should import only
 * from `hash.js` / `canonical.js` (bundlers tree-shake this module away;
 * `sideEffects: false`).
 */
export function sha256Hex(data: string | Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

/** Synchronous variant of the frozen hash-input rule (SPEC §6). */
export function computeEntryHash(preimage: LedgerEntryPreimage): string {
  return sha256Hex(canonicalJson(preimage));
}
