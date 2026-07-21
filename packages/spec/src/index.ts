/**
 * @mandarelabs/spec — the Mandare open contracts (Apache-2.0).
 *
 * Frozen contracts (rule R6): mandate schema (SPEC §5), ledger-entry schema
 * (SPEC §6), canonical JSON, and the entry-hash rule. Changes require a
 * TASKS.md decision entry and a schema_version bump.
 */

export { canonicalJson } from './canonical.js';
export {
  GENESIS_PREV_HASH,
  base64UrlToBytes,
  bytesToBase64Url,
  bytesToHex,
  computeEntryHashAsync,
  hexToBytes,
  sha256HexAsync,
} from './hash.js';
export { computeEntryHash, sha256Hex } from './hash-node.js';
export {
  CURRENCY_MICROS_PER_UNIT,
  CurrencyCode,
  IsoUtcTimestamp,
  KeyProvenance,
  SignatureBlock,
} from './signature.js';
export {
  ActionScope,
  ApprovalRule,
  BillingIdentity,
  CounterpartyMode,
  MandateScope,
  MandateV1,
  SpendRail,
  SpendScope,
} from './mandate.js';
export {
  LLM_CALL_INTENT,
  LLM_CALL_RESULT,
  LedgerAction,
  LedgerCost,
  LedgerEntryV1,
  type LedgerEntryPreimage,
} from './ledger-entry.js';
export {
  SchemaValidationError,
  isLedgerEntry,
  isMandate,
  parseLedgerEntry,
  parseMandate,
} from './validate.js';
