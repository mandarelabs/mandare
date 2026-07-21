/**
 * @mandarelabs/ledger — append-only, hash-chained, door-signed event store
 * (AGPL-3.0-only).
 */

export { Ledger, readLedger } from './ledger.js';
export type { AppendInput, LedgerHead, LedgerMeta } from './ledger.js';
export { AsyncLedger } from './async-ledger.js';
export { buildEntry } from './entry.js';
export { SqliteStore, openSqliteDatabase } from './sqlite-store.js';
export { PgStore, provisionPgLedger } from './pg-store.js';
export {
  ProjectionStaleError,
  assertDoorOwnsMeta,
  metaFromRows,
  newMetaRows,
  runProjectedAppend,
} from './store.js';
export type { AppendProjectedResult, LedgerStore, ProjectionTx, Projector } from './store.js';
export { loadOrCreateDoorKey } from './door-key.js';
export type { DoorKey } from './door-key.js';
export {
  EMPTY_COUNTER,
  LLM_CALL_DENIED,
  MapCounterKV,
  ProjectionIntegrityError,
  applySpendEntry,
  dayBucket,
  dayKey,
  diffProjection,
  intentKey,
  minuteBucket,
  minuteKey,
  replaySpendCounters,
  spendProjector,
  totalKey,
} from './projection.js';
export type {
  CounterKV,
  ProjectionDivergence,
  ProjectionRefusal,
  SpendCounter,
  SpendGuard,
  SpendGuardView,
} from './projection.js';
export {
  readSpendProjectionSqlite,
  readSpendSnapshot,
  rebuildSpendProjection,
  verifySpendProjection,
} from './spend-ledger.js';
export type { ProjectionRunner, ProjectionVerdict, SpendSnapshot } from './spend-ledger.js';
