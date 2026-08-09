import { DatabaseSync } from 'node:sqlite';
import { existsSync } from 'node:fs';

/**
 * Read side of the dashboard: direct READ-ONLY SQLite over the ledger and
 * its projections. The dashboard renders what the ledger PROVES, plus the
 * live projections the door maintains; it never writes through this module
 * (the only write surface is the kill action, which shells to the CLI — the
 * same local authority an operator uses).
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

const RESULT_TYPES = "('llm.call.result','card.auth.result')";
const DENIED_TYPES = "('llm.call.denied','card.auth.denied')";

export function readSnapshot(path: string): LedgerSnapshot | null {
  if (!existsSync(path)) {
    return null;
  }
  const db = openLedgerReadOnly(path);
  try {
    const entryCount =
      (db.prepare('SELECT COUNT(*) AS n FROM ledger_entries').get() as { n: number }).n;

    const agentRows = db
      .prepare(
        `SELECT
           json_extract(entry_json, '$.actor') AS actor,
           SUM(CASE WHEN json_extract(entry_json, '$.action.type') IN ${RESULT_TYPES}
                    THEN json_extract(entry_json, '$.cost.amount') ELSE 0 END) AS settled,
           SUM(CASE WHEN json_extract(entry_json, '$.action.type') IN ${DENIED_TYPES}
                    THEN 1 ELSE 0 END) AS refusals,
           COUNT(*) AS entries,
           MAX(json_extract(entry_json, '$.ts')) AS last_seen,
           MAX(json_extract(entry_json, '$.cost.currency')) AS currency
         FROM ledger_entries
         GROUP BY actor
         ORDER BY settled DESC, entries DESC`
      )
      .all() as {
      actor: string;
      settled: number | null;
      refusals: number;
      entries: number;
      last_seen: string;
      currency: string | null;
    }[];

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

    const agents: AgentRow[] = agentRows.map((row) => {
      const revocation = revocations.get(`agent:${row.actor}`);
      return {
        actor: row.actor,
        revoked: revocation?.revoked ?? false,
        revokedAt: revocation?.revoked === true ? revocation.updatedAt : null,
        settledMicros: row.settled ?? 0,
        refusals: row.refusals,
        entryCount: row.entries,
        lastSeen: row.last_seen,
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
    return (
      db
        .prepare(
          `SELECT seq, entry_hash,
                  json_extract(entry_json, '$.ts') AS ts,
                  json_extract(entry_json, '$.actor') AS actor,
                  json_extract(entry_json, '$.action.type') AS action_type,
                  json_extract(entry_json, '$.action.target') AS target,
                  json_extract(entry_json, '$.cost.amount') AS amount,
                  json_extract(entry_json, '$.cost.currency') AS currency,
                  json_extract(entry_json, '$.mandate_id') AS mandate_id
           FROM ledger_entries ${where}
           ORDER BY seq DESC LIMIT ?`
        )
        .all(...args) as {
        seq: number;
        entry_hash: string;
        ts: string;
        actor: string;
        action_type: string;
        target: string | null;
        amount: number;
        currency: string;
        mandate_id: string;
      }[]
    ).map((row) => ({
      seq: row.seq,
      ts: row.ts,
      actor: row.actor,
      actionType: row.action_type,
      target: row.target,
      amountMicros: row.amount,
      currency: row.currency,
      mandateId: row.mandate_id,
      entryHash: row.entry_hash,
    }));
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
    return (
      db
        .prepare(
          `SELECT seq,
                  json_extract(entry_json, '$.ts') AS ts,
                  json_extract(entry_json, '$.actor') AS actor,
                  json_extract(entry_json, '$.action.type') AS action_type,
                  json_extract(entry_json, '$.action.target') AS target
           FROM ledger_entries
           WHERE json_extract(entry_json, '$.action.type') LIKE 'approval.%'
           ORDER BY seq DESC LIMIT ?`
        )
        .all(limit) as { seq: number; ts: string; actor: string; action_type: string; target: string | null }[]
    ).map((row) => ({
      seq: row.seq,
      ts: row.ts,
      actor: row.actor,
      actionType: row.action_type,
      target: row.target,
    }));
  } finally {
    db.close();
  }
}

export function formatAmount(micros: number, currency: string): string {
  const units = micros / CURRENCY_MICROS_PER_UNIT;
  return `${units.toFixed(4).replace(/(\.\d\d)00$/, '$1')} ${currency}`;
}
