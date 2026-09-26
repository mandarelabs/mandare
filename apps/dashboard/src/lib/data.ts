import { DatabaseSync } from 'node:sqlite';
import { existsSync } from 'node:fs';

import { parseStoredEntry } from '@mandarelabs/verifier';

/**
 * Read side of the dashboard: direct READ-ONLY SQLite over the ledger and
 * its projections. The dashboard renders what the ledger PROVES, plus the
 * live projections the door maintains; it never writes through this module
 * (the only write surface is the kill action, which shells to the CLI — the
 * same local authority an operator uses).
 *
 * Entries are parsed in JS through the verifier's stored-row check — never
 * SQLite `json_extract` (W-3): JSON with duplicate keys reads first-key-wins
 * there but last-key-wins in the verifier, so a SQL view could render a
 * forgery under a green chain badge. A row the check refuses is shown as a
 * storage mismatch, with none of its claimed fields.
 */

export const CURRENCY_MICROS_PER_UNIT = 1_000_000;

export interface AgentRow {
  actor: string;
  revoked: boolean;
  revokedAt: string | null;
  settledMicros: number;
  refusals: number;
  entryCount: number;
  lastSeen: string;
  currency: string;
}

export interface MandateBudgetRow {
  mandateId: string;
  totalSettledMicros: number;
  totalReservedMicros: number;
  todaySettledMicros: number;
  todayReservedMicros: number;
  intents: number;
}

export interface TrailRow {
  seq: number;
  /** false ⇒ the stored text failed the stored-row check; fields are placeholders. */
  storageOk: boolean;
  ts: string;
  actor: string;
  actionType: string;
  target: string | null;
  amountMicros: number;
  currency: string;
  mandateId: string;
  entryHash: string;
}

export interface ApprovalRow {
  seq: number;
  ts: string;
  actionType: string;
  target: string | null;
  actor: string;
}

export interface LedgerSnapshot {
  dbPath: string;
  entryCount: number;
  /** Rows refused by the stored-row check — excluded from every figure below. */
  unreadableRows: number;
  doorId: string | null;
  agents: AgentRow[];
  mandates: MandateBudgetRow[];
  revokedSubjects: { subject: string; updatedAt: string }[];
}

export function ledgerDbPath(): string {
  return process.env.MANDARE_LEDGER_DB ?? './mandare-ledger.db';
}

export function openLedgerReadOnly(path: string): DatabaseSync {
  return new DatabaseSync(path, { readOnly: true });
}

function metaValue(db: DatabaseSync, key: string): string | null {
  try {
    const row = db.prepare('SELECT value FROM ledger_meta WHERE key = ?').get(key) as
      | { value: string }
      | undefined;
    return row?.value ?? null;
  } catch {
    return null;
  }
}

/** UTC day bucket, matching packages/ledger's projection keys. */
function todayBucket(): string {
  return new Date().toISOString().slice(0, 10);
}

const RESULT_TYPES = new Set(['llm.call.result', 'card.auth.result']);
const DENIED_TYPES = new Set(['llm.call.denied', 'card.auth.denied']);

/** The fields the dashboard shows, read from ONE verified parse of a stored row. */
interface EntryView {
  seq: number;
  entryHash: string;
  ts: string;
  actor: string;
  actionType: string;
  target: string | null;
  amountMicros: number;
  currency: string;
  mandateId: string;
}

type StoredRowRead = { ok: true; view: EntryView } | { ok: false; seq: number; entryHash: string };

interface RawRow {
  seq: number;
  entry_hash: string;
  entry_json: string;
}

function str(value: unknown, fallback: string): string {
  return typeof value === 'string' ? value : fallback;
}

function toView(row: RawRow): StoredRowRead {
  const parsed = parseStoredEntry({ seq: row.seq, entry_hash: row.entry_hash, text: row.entry_json });
  if (!parsed.ok) {
    return { ok: false, seq: row.seq, entryHash: row.entry_hash };
  }
  const entry = parsed.entry as {
    ts?: unknown;
    actor?: unknown;
    mandate_id?: unknown;
    action?: { type?: unknown; target?: unknown };
    cost?: { amount?: unknown; currency?: unknown };
  };
  const amount = entry.cost?.amount;
  return {
    ok: true,
    view: {
      seq: row.seq,
      entryHash: row.entry_hash,
      ts: str(entry.ts, ''),
      actor: str(entry.actor, ''),
      actionType: str(entry.action?.type, ''),
      target: typeof entry.action?.target === 'string' ? entry.action.target : null,
      amountMicros: typeof amount === 'number' && Number.isSafeInteger(amount) ? amount : 0,
      currency: str(entry.cost?.currency, 'EUR'),
      mandateId: str(entry.mandate_id, ''),
    },
  };
}

function readRows(db: DatabaseSync, sql: string, ...args: (string | number)[]): StoredRowRead[] {
  return (db.prepare(sql).all(...args) as unknown as RawRow[]).map(toView);
}

interface AgentTally {
  settled: number;
  refusals: number;
  entries: number;
  lastSeen: string;
  currency: string | null;
}

/** Per-actor figures over verified rows (the former SQL GROUP BY, same semantics). */
function tallyAgents(views: readonly EntryView[]): Map<string, AgentTally> {
  const byActor = new Map<string, AgentTally>();
  for (const view of views) {
    const tally = byActor.get(view.actor) ?? { settled: 0, refusals: 0, entries: 0, lastSeen: '', currency: null };
    byActor.set(view.actor, {
      settled: tally.settled + (RESULT_TYPES.has(view.actionType) ? view.amountMicros : 0),
      refusals: tally.refusals + (DENIED_TYPES.has(view.actionType) ? 1 : 0),
      entries: tally.entries + 1,
      lastSeen: view.ts > tally.lastSeen ? view.ts : tally.lastSeen,
      currency: tally.currency === null || view.currency > tally.currency ? view.currency : tally.currency,
    });
  }
  return byActor;
}

export function readSnapshot(path: string): LedgerSnapshot | null {
  if (!existsSync(path)) {
    return null;
  }
  const db = openLedgerReadOnly(path);
  try {
    const entryCount =
      (db.prepare('SELECT COUNT(*) AS n FROM ledger_entries').get() as { n: number }).n;

    const reads = readRows(db, 'SELECT seq, entry_hash, entry_json FROM ledger_entries ORDER BY seq ASC');
    const views = reads.flatMap((read) => (read.ok ? [read.view] : []));
    const agentRows = [...tallyAgents(views).entries()].sort(
      ([, a], [, b]) => b.settled - a.settled || b.entries - a.entries
    );

    const revocations = new Map<string, { revoked: boolean; updatedAt: string }>();
    try {
      for (const row of db
        .prepare('SELECT subject, revoked, updated_at FROM revocation_status')
        .all() as { subject: string; revoked: number; updated_at: string }[]) {
        revocations.set(row.subject, { revoked: row.revoked === 1, updatedAt: row.updated_at });
      }
    } catch {
      // Pre-S3 ledgers have no revocation table; every agent is unrevoked.
    }

    const agents: AgentRow[] = agentRows.map(([actor, row]) => {
      const revocation = revocations.get(`agent:${actor}`);
      return {
        actor,
        revoked: revocation?.revoked ?? false,
        revokedAt: revocation?.revoked === true ? revocation.updatedAt : null,
        settledMicros: row.settled,
        refusals: row.refusals,
        entryCount: row.entries,
        lastSeen: row.lastSeen,
        currency: row.currency ?? 'EUR',
      };
    });

    const counters = (() => {
      try {
        return db
          .prepare(
            'SELECT scope_key, reserved_micros, settled_micros, intents FROM budget_counters'
          )
          .all() as { scope_key: string; reserved_micros: number; settled_micros: number; intents: number }[];
      } catch {
        return [];
      }
    })();
    const today = todayBucket();
    const byMandate = new Map<string, MandateBudgetRow>();
    for (const counter of counters) {
      const match = /^mandate:([^|]+)\|(total|day:(.+))$/.exec(counter.scope_key);
      if (match === null) {
        continue;
      }
      const mandateId = decodeURIComponent(match[1] as string);
      const row = byMandate.get(mandateId) ?? {
        mandateId,
        totalSettledMicros: 0,
        totalReservedMicros: 0,
        todaySettledMicros: 0,
        todayReservedMicros: 0,
        intents: 0,
      };
      if (match[2] === 'total') {
        row.totalSettledMicros = counter.settled_micros;
        row.totalReservedMicros = counter.reserved_micros;
        row.intents = counter.intents;
      } else if (match[3] === today) {
        row.todaySettledMicros = counter.settled_micros;
        row.todayReservedMicros = counter.reserved_micros;
      }
      byMandate.set(mandateId, row);
    }

    const revokedSubjects = [...revocations.entries()]
      .filter(([, value]) => value.revoked)
      .map(([subject, value]) => ({ subject, updatedAt: value.updatedAt }))
      .sort((a, b) => (a.updatedAt < b.updatedAt ? 1 : -1));

    return {
      dbPath: path,
      entryCount,
      unreadableRows: reads.length - views.length,
      doorId: metaValue(db, 'door_id'),
      agents,
      mandates: [...byMandate.values()].sort((a, b) => b.totalSettledMicros - a.totalSettledMicros),
      revokedSubjects,
    };
  } finally {
    db.close();
  }
}

export function readTrail(path: string, limit = 50, beforeSeq?: number): TrailRow[] {
  if (!existsSync(path)) {
    return [];
  }
  const db = openLedgerReadOnly(path);
  try {
    const where = beforeSeq === undefined ? '' : 'WHERE seq < ?';
    const args = beforeSeq === undefined ? [limit] : [beforeSeq, limit];
    const sql = `SELECT seq, entry_hash, entry_json FROM ledger_entries ${where} ORDER BY seq DESC LIMIT ?`;
    return readRows(db, sql, ...args).map((read) =>
      read.ok
        ? { ...read.view, storageOk: true }
        : {
            seq: read.seq,
            storageOk: false,
            ts: '',
            actor: '—',
            actionType: 'storage mismatch',
            target: null,
            amountMicros: 0,
            currency: '',
            mandateId: '—',
            entryHash: read.entryHash,
          }
    );
  } finally {
    db.close();
  }
}

export function readApprovals(path: string, limit = 20): ApprovalRow[] {
  if (!existsSync(path)) {
    return [];
  }
  const db = openLedgerReadOnly(path);
  try {
    // LIKE only narrows the scan; the verified parse decides what an approval is.
    const sql = `SELECT seq, entry_hash, entry_json FROM ledger_entries
                 WHERE entry_json LIKE '%approval.%' ORDER BY seq DESC`;
    return readRows(db, sql)
      .flatMap((read) => (read.ok && read.view.actionType.startsWith('approval.') ? [read.view] : []))
      .slice(0, limit)
      .map((view) => ({
        seq: view.seq,
        ts: view.ts,
        actionType: view.actionType,
        target: view.target,
        actor: view.actor,
      }));
  } finally {
    db.close();
  }
}

export function formatAmount(micros: number, currency: string): string {
  const units = micros / CURRENCY_MICROS_PER_UNIT;
  return `${units.toFixed(4).replace(/(\.\d\d)00$/, '$1')} ${currency}`;
}
