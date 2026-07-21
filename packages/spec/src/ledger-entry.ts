import { type Static, Type } from '@sinclair/typebox';

import { CurrencyCode, IsoUtcTimestamp, SignatureBlock } from './signature.js';

/**
 * Ledger entry v1 — SPEC §6. One link of the tamper-evident chain, written
 * by a door (gateway/vault/connector) — never by the agent (integrity lock 1).
 *
 * FROZEN CONTRACT: changes require a TASKS.md decision entry and a
 * schema_version bump (rule R6).
 */

const Sha256Hex = Type.String({ pattern: '^[0-9a-f]{64}$' });

/**
 * Intent/result pairing (log-before-act, integrity lock 3): a door writes an
 * entry with action.type `<domain>.intent` BEFORE executing, then an entry
 * with `<domain>.result` whose `outcome_ref` is the intent's `entry_hash`.
 */
export const LLM_CALL_INTENT = 'llm.call.intent';
export const LLM_CALL_RESULT = 'llm.call.result';

export const LedgerAction = Type.Object(
  {
    /** Namespaced action type, e.g. 'llm.call.intent'. */
    type: Type.String({ minLength: 1 }),
    /** What the action touched, e.g. provider host or counterparty id. */
    target: Type.String({ minLength: 1 }),
    /** sha256 of the canonical request body (hashes only — never content, rule R2). */
    request_hash: Sha256Hex,
    /** Absent on intent entries (no response exists yet). */
    response_hash: Type.Optional(Sha256Hex),
  },
  { additionalProperties: false }
);
export type LedgerAction = Static<typeof LedgerAction>;

export const LedgerCost = Type.Object(
  {
    /** Integer micro-units of `currency` (see CURRENCY_MICROS_PER_UNIT). 0 when unknown/free. */
    amount: Type.Integer({ minimum: 0 }),
    currency: CurrencyCode,
    tokens_in: Type.Integer({ minimum: 0 }),
    tokens_out: Type.Integer({ minimum: 0 }),
  },
  { additionalProperties: false }
);
export type LedgerCost = Static<typeof LedgerCost>;

export const LedgerEntryV1 = Type.Object(
  {
    schema_version: Type.Literal(1),
    /** Strictly monotonic, starts at 1, no gaps (integrity lock 2). */
    seq: Type.Integer({ minimum: 1 }),
    /** Hardware monotonic counter (TPM/enclave) — Tier 3, absent in software mode. */
    hw_counter: Type.Optional(Type.Integer({ minimum: 0 })),
    ts: IsoUtcTimestamp,
    /** Which door wrote this entry (gateway/vault/card-connector instance id). */
    door_id: Type.String({ minLength: 1 }),
    /** Agent DID that caused the action. */
    actor: Type.String({ minLength: 1 }),
    mandate_id: Type.String({ minLength: 1 }),
    action: LedgerAction,
    cost: LedgerCost,
    /** On result entries: entry_hash of the paired intent entry. */
    outcome_ref: Type.Optional(Sha256Hex),
    /** Storno logic (GoBD): entry_hash of the entry this one corrects. Never edit — append. */
    correction_of: Type.Optional(Sha256Hex),
    /** Per-entry random salt (16 bytes hex) so streamed head hashes leak nothing. */
    salt: Type.String({ pattern: '^[0-9a-f]{32}$' }),
    /** entry_hash of the previous entry; GENESIS_PREV_HASH for seq 1. */
    prev_hash: Sha256Hex,
    /** sha256 of canonical JSON of this entry without entry_hash + door_signature. */
    entry_hash: Sha256Hex,
    /** Door-key Ed25519 signature over the raw 32 bytes of entry_hash. */
    door_signature: SignatureBlock,
  },
  { additionalProperties: false }
);
export type LedgerEntryV1 = Static<typeof LedgerEntryV1>;

/** The hash preimage: everything except the two fields derived from it. */
export type LedgerEntryPreimage = Omit<LedgerEntryV1, 'entry_hash' | 'door_signature'>;
