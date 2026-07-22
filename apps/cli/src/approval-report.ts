import {
  APPROVAL_DENIED,
  APPROVAL_EXPIRED,
  APPROVAL_GRANTED,
  APPROVAL_REQUESTED,
} from '@mandarelabs/ledger';
import { CURRENCY_MICROS_PER_UNIT, type LedgerEntryV1 } from '@mandarelabs/spec';

/**
 * `mandare verify` approval section: renders the human decisions inside a
 * task's sequence — every HELD call and what became of it (approved, denied,
 * expired, or still pending). This is Demo 3's proof obligation: "mandare
 * verify proves the whole sequence including the human decisions."
 */

export type ApprovalDecision = 'approved' | 'denied' | 'expired' | 'pending';

export interface ApprovalReport {
  lines: string[];
  /** True when the ledger has no approval entries at all (skip the section). */
  empty: boolean;
  json: {
    approvals: {
      requested_entry: string;
      requested_at: string;
      actor: string;
      mandate_id: string;
      target: string;
      amount_micros: number;
      currency: string;
      decision: ApprovalDecision;
      decided_by: string | null;
      decision_entry: string | null;
      decided_at: string | null;
    }[];
  };
}

const DECISION_BY_TYPE: Record<string, ApprovalDecision> = {
  [APPROVAL_GRANTED]: 'approved',
  [APPROVAL_DENIED]: 'denied',
  [APPROVAL_EXPIRED]: 'expired',
};

export function buildApprovalReport(entries: readonly unknown[]): ApprovalReport {
  const typed = entries as LedgerEntryV1[];
  const requests = typed.filter((entry) => entry.action.type === APPROVAL_REQUESTED);
  if (requests.length === 0) {
    return { empty: true, lines: [], json: { approvals: [] } };
  }
  const decisionsByRef = new Map<string, LedgerEntryV1>();
  for (const entry of typed) {
    if (DECISION_BY_TYPE[entry.action.type] !== undefined && entry.outcome_ref !== undefined) {
      decisionsByRef.set(entry.outcome_ref, entry);
    }
  }

  const lines = ['approvals:'];
  const json: ApprovalReport['json'] = { approvals: [] };
  for (const requested of requests) {
    const decision = decisionsByRef.get(requested.entry_hash) ?? null;
    const outcome: ApprovalDecision =
      decision === null ? 'pending' : (DECISION_BY_TYPE[decision.action.type] as ApprovalDecision);
    const amount = (requested.cost.amount / CURRENCY_MICROS_PER_UNIT).toFixed(4);
    lines.push(
      `  HELD      ~${amount} ${requested.cost.currency} → ${requested.action.target}  ` +
        `(agent ${requested.actor}, @ ${requested.ts}, entry ${requested.entry_hash.slice(0, 12)}…)`
    );
    lines.push(
      decision === null
        ? '    → PENDING — no decision recorded'
        : `    → ${outcome.toUpperCase()} by ${decision.actor} @ ${decision.ts} (entry ${decision.entry_hash.slice(0, 12)}…)`
    );
    json.approvals.push({
      requested_entry: requested.entry_hash,
      requested_at: requested.ts,
      actor: requested.actor,
      mandate_id: requested.mandate_id,
      target: requested.action.target,
      amount_micros: requested.cost.amount,
      currency: requested.cost.currency,
      decision: outcome,
      decided_by: decision?.actor ?? null,
      decision_entry: decision?.entry_hash ?? null,
      decided_at: decision?.ts ?? null,
    });
  }
  return { empty: false, lines, json };
}
