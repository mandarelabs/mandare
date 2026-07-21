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
export { assertDoorOwnsMeta, metaFromRows, newMetaRows } from './store.js';
export type { LedgerStore } from './store.js';
export { loadOrCreateDoorKey } from './door-key.js';
export type { DoorKey } from './door-key.js';
