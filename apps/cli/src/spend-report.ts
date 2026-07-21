import {
  LLM_CALL_DENIED,
  diffProjection,
  readSpendProjectionSqlite,
  replaySpendCounters,
  type SpendCounter,
} from '@mandarelabs/ledger';
import { CURRENCY_MICROS_PER_UNIT, LLM_CALL_INTENT, LLM_CALL_RESULT } from '@mandarelabs/spec';

/**
 * `mandare verify --spend`: renders the spend trail (intents, settlements,
 * REFUSED reservations) and re-derives the budget counters from the ledger,
 * comparing them against the stored projection — the user-facing form of the
 * red-team invariant replay(ledger) == counters.
 */

const TRAIL_LENGTH = 12;

interface TrailEntry {
  seq: number;
  ts: string;
  action: { type: string };
  cost: { amount: number; currency: string };
  mandate_id: string;
}

export interface SpendReport {
  lines: string[];
  countersConsistent: boolean;
  json: {
    mandates: Record<
      string,
      { settled_micros: number; reserved_micros: number; intents: number; currency: string }
    >;
    denied_count: number;
    counters:
      | { status: 'consistent'; rows: number }
      | { status: 'divergent' | 'stale'; detail: string };
  };
}

function formatAmount(micros: number, currency: string): string {
  const units = micros / CURRENCY_MICROS_PER_UNIT;
  return `${units.toFixed(6).replace(/(\.\d\d[0-9]*?)0+$/, '$1')} ${currency}`;
}

function trailLine(entry: TrailEntry): string {
  const amount = formatAmount(entry.cost.amount, entry.cost.currency);
  switch (entry.action.type) {
    case LLM_CALL_INTENT:
      return `  #${entry.seq}  ${entry.ts}  INTENT   reserve ${amount}`;
    case LLM_CALL_RESULT:
      return `  #${entry.seq}  ${entry.ts}  RESULT   settle  ${amount}`;
    case LLM_CALL_DENIED:
      return `  #${entry.seq}  ${entry.ts}  DENIED   refused ${amount}  ← reservation REFUSED by policy`;
    default:
      return `  #${entry.seq}  ${entry.ts}  ${entry.action.type}`;
  }
}

export async function buildSpendReport(
  dbPath: string,
  entries: readonly unknown[]
): Promise<SpendReport> {
  const lines: string[] = [];
  const typed = entries as TrailEntry[];

  // Per-mandate totals from a pure replay of the ledger (the ground truth).
  const replayed = await replaySpendCounters(entries);
  const mandates: SpendReport['json']['mandates'] = {};
  for (const [key, counter] of replayed) {
    const match = /^mandate:(.+)\|total$/.exec(key);
    if (match === null) {
      continue;
    }
    const mandateId = decodeURIComponent(match[1] as string);
    const currency =
      typed.find((entry) => entry.mandate_id === mandateId)?.cost.currency ?? 'EUR';
    mandates[mandateId] = {
      settled_micros: counter.settledMicros,
      reserved_micros: counter.reservedMicros,
      intents: counter.intents,
      currency,
    };
  }
  const deniedCount = typed.filter((entry) => entry.action.type === LLM_CALL_DENIED).length;

  lines.push('spend:');
  if (Object.keys(mandates).length === 0) {
    lines.push('  (no spend entries)');
  }
  for (const [mandateId, totals] of Object.entries(mandates)) {
    lines.push(
      `  ${mandateId}: settled ${formatAmount(totals.settled_micros, totals.currency)}` +
        ` · open reservations ${formatAmount(totals.reserved_micros, totals.currency)}` +
        ` · ${totals.intents} call(s) · ${deniedCount} refused`
    );
  }

  const trail = typed.slice(-TRAIL_LENGTH);
  if (typed.length > trail.length) {
    lines.push(`trail:    (last ${trail.length} of ${typed.length} entries)`);
  } else {
    lines.push('trail:');
  }
  for (const entry of trail) {
    lines.push(trailLine(entry));
  }

  // The invariant, user-facing: stored counters must equal a fresh replay.
  const { counters: stored, projectionSeq } = readSpendProjectionSqlite(dbPath);
  let countersConsistent = true;
  let countersJson: SpendReport['json']['counters'];
  if (projectionSeq !== typed.length) {
    countersConsistent = false;
    countersJson = {
      status: 'stale',
      detail: `projection is at seq ${projectionSeq}, ledger has ${typed.length} entries`,
    };
    lines.push(
      `counters: STALE — projection at seq ${projectionSeq}, ledger at ${typed.length}; doors fail closed until it is rebuilt from the ledger`
    );
  } else {
    const divergences = diffProjection(stored, replayed as Map<string, SpendCounter>);
    if (divergences.length === 0) {
      countersJson = { status: 'consistent', rows: stored.size };
      lines.push(
        `counters: CONSISTENT — ${stored.size} counter row(s) equal a fresh replay of the ledger (counters are a projection, never a second truth)`
      );
    } else {
      countersConsistent = false;
      countersJson = {
        status: 'divergent',
        detail: divergences
          .map((divergence) => divergence.key)
          .slice(0, 5)
          .join(', '),
      };
      lines.push(
        `counters: DIVERGENT — ${divergences.length} row(s) differ from the ledger replay (tampering or projection bug); doors must fail closed`
      );
    }
  }

  return {
    lines,
    countersConsistent,
    json: { mandates, denied_count: deniedCount, counters: countersJson },
  };
}
