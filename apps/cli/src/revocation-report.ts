import {
  SUBJECT_REGISTER,
  diffRevocation,
  readRevocationProjectionSqlite,
  replayRevocation,
} from '@mandarelabs/ledger';
import { AGENT_STATUS_LIST_ID, buildStatusListPayload } from '@mandarelabs/vault';

/**
 * `mandare verify` revocation section: renders the kill trail, re-derives the
 * revocation state from the ledger, and checks it against the stored
 * projection (replay(ledger) == revocation). It also renders the IETF Token
 * Status List bitstring — the very artifact S6 will publish unchanged, proving
 * S3's local kill already speaks the external revocation vocabulary.
 */

export interface RevocationReport {
  lines: string[];
  /** True when there are no revocation entries at all (skip the section). */
  empty: boolean;
  consistent: boolean;
  json: {
    subjects: { subject: string; revoked: boolean; status_index: number; entry_hash: string }[];
    status_list: { id: string; bits: number; lst: string };
    projection: { status: 'consistent' | 'divergent'; detail?: string };
  };
}

export async function buildRevocationReport(
  dbPath: string,
  entries: readonly unknown[],
  nowSeconds: number
): Promise<RevocationReport> {
  const replayedMap = await replayRevocation(entries);
  const replayed = [...replayedMap.values()].sort((a, b) => a.statusIndex - b.statusIndex);
  if (replayed.length === 0) {
    return {
      lines: [],
      empty: true,
      consistent: true,
      json: {
        subjects: [],
        status_list: { id: AGENT_STATUS_LIST_ID, bits: 1, lst: '' },
        projection: { status: 'consistent' },
      },
    };
  }

  // Which entry produced each record's state tells "registered (issuance)"
  // apart from "reinstated (an authorized un-kill)".
  const entryTypeByHash = new Map<string, string>();
  for (const raw of entries) {
    const entry = raw as { entry_hash?: string; action?: { type?: string } };
    if (typeof entry?.entry_hash === 'string' && typeof entry?.action?.type === 'string') {
      entryTypeByHash.set(entry.entry_hash, entry.action.type);
    }
  }
  const lines: string[] = ['subjects:'];
  for (const record of replayed) {
    const state = record.revoked
      ? 'REVOKED   '
      : entryTypeByHash.get(record.entryHash) === SUBJECT_REGISTER
        ? 'registered'
        : 'reinstated';
    lines.push(
      `  ${state} ${record.subject}  (index ${record.statusIndex}, @ ${record.updatedAt}, entry ${record.entryHash.slice(0, 12)}…)`
    );
  }

  // The bitstring an external verifier / S6 consumes, built from the ledger
  // ground truth (never invented).
  const payload = buildStatusListPayload({
    listId: AGENT_STATUS_LIST_ID,
    slots: replayed.map((record) => ({ index: record.statusIndex, revoked: record.revoked })),
    issuer: 'mandare:local',
    iat: nowSeconds,
  });
  lines.push(
    `status:   IETF Token Status List — id=${AGENT_STATUS_LIST_ID} bits=${payload.status_list.bits} ` +
      `lst=${payload.status_list.lst} (S6 publishes this unchanged)`
  );

  // The invariant: the stored projection the gateway enforces must equal a
  // fresh replay of the ledger.
  const stored = new Map(readRevocationProjectionSqlite(dbPath).map((r) => [r.subject, r]));
  const divergences = diffRevocation(stored, replayedMap);
  const consistent = divergences.length === 0;
  lines.push(
    consistent
      ? `revocations: CONSISTENT — ${stored.size} record(s) equal a fresh replay of the ledger`
      : `revocations: DIVERGENT — ${divergences.length} record(s) differ from the ledger replay (tampering or bug); doors must fail closed`
  );

  return {
    lines,
    empty: false,
    consistent,
    json: {
      subjects: replayed.map((r) => ({
        subject: r.subject,
        revoked: r.revoked,
        status_index: r.statusIndex,
        entry_hash: r.entryHash,
      })),
      status_list: { id: AGENT_STATUS_LIST_ID, bits: payload.status_list.bits, lst: payload.status_list.lst },
      projection: consistent
        ? { status: 'consistent' }
        : { status: 'divergent', detail: divergences.map((d) => d.subject).slice(0, 5).join(', ') },
    },
  };
}
