import { randomBytes } from 'node:crypto';

import {
  GENESIS_PREV_HASH,
  bytesToBase64Url,
  computeEntryHash,
  hexToBytes,
  parseLedgerEntry,
  type LedgerAction,
  type LedgerCost,
  type LedgerEntryPreimage,
  type LedgerEntryV1,
} from '@mandarelabs/spec';

import type { DoorKey } from './door-key.js';

/**
 * Pure entry construction — shared by every store driver so SQLite and
 * Postgres ledgers produce byte-identical chains. Hashing and signing rules
 * are the FROZEN contracts from packages/spec.
 */

export interface AppendInput {
  actor: string;
  mandate_id: string;
  action: LedgerAction;
  cost: LedgerCost;
  outcome_ref?: string;
  correction_of?: string;
  hw_counter?: number;
}

export interface LedgerHead {
  seq: number;
  entry_hash: string;
}

const SALT_BYTES = 16;

/** Build, hash, sign, and boundary-validate the next chain entry. */
export function buildEntry(
  input: AppendInput,
  head: LedgerHead | null,
  doorId: string,
  doorKey: DoorKey
): LedgerEntryV1 {
  const preimage: LedgerEntryPreimage = {
    schema_version: 1,
    seq: head === null ? 1 : head.seq + 1,
    ...(input.hw_counter === undefined ? {} : { hw_counter: input.hw_counter }),
    ts: new Date().toISOString(),
    door_id: doorId,
    actor: input.actor,
    mandate_id: input.mandate_id,
    action: input.action,
    cost: input.cost,
    ...(input.outcome_ref === undefined ? {} : { outcome_ref: input.outcome_ref }),
    ...(input.correction_of === undefined ? {} : { correction_of: input.correction_of }),
    salt: randomBytes(SALT_BYTES).toString('hex'),
    prev_hash: head === null ? GENESIS_PREV_HASH : head.entry_hash,
  };
  const entryHash = computeEntryHash(preimage);
  const entry: LedgerEntryV1 = {
    ...preimage,
    entry_hash: entryHash,
    door_signature: {
      alg: 'EdDSA',
      key_id: doorKey.keyId,
      key_provenance: doorKey.provenance,
      value: bytesToBase64Url(doorKey.sign(hexToBytes(entryHash))),
    },
  };
  // Boundary validation before persisting — hostile input dies here (R4),
  // and nothing schema-invalid can ever enter the chain.
  parseLedgerEntry(entry);
  return entry;
}
