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
export type {
  AppendProjectedResult,
  LedgerStore,
  ProjectionKV,
  ProjectionTx,
  Projector,
  RevocationKV,
  RevocationRecord,
} from './store.js';
export { loadOrCreateDoorKey, doorKeyFromPem, generateDoorKeyPem } from './door-key.js';
export type { DoorKey } from './door-key.js';
export {
  AGENT_REVOKE,
  AGENT_REINSTATE,
  agentSubject,
  doorSubject,
  mandateSubject,
  applyRevocationEntry,
  revocationProjector,
  replayRevocation,
  diffRevocation,
  MapRevocationKV,
} from './revocation.js';
export type { RevocationDivergence } from './revocation.js';
export {
  readRevocationRecord,
  isSubjectRevoked,
  listRevocations,
  rebuildRevocationProjection,
  verifyRevocationProjection,
  readRevocationProjectionSqlite,
} from './revocation-ledger.js';
export type { RevocationVerdict } from './revocation-ledger.js';
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
