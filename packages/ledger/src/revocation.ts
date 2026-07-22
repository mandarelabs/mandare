import type { LedgerEntryV1 } from '@mandarelabs/spec';

import type { ProjectionKV, RevocationKV, RevocationRecord } from './store.js';

/**
 * Revocation projection — the kill-switch surface (SPEC §4 revocation, §3.1
 * Kill Switch).
 *
 * ARCHITECTURE (binding, per the founder ruling): the AUTHORITY is a LOCAL,
 * offline, fail-closed door operation. `mandare kill <agent>` appends an
 * `agent.revoke` entry to the ledger and, in the SAME transaction, flips the
 * subject's bit in this projection. The gateway checks the projection on
 * every request — never the cloud — so a kill is immediate and un-jammable
 * and beats the shortest credential TTL.
 *
 * Like the spend counters, the revocation table is a DERIVED PROJECTION: a
 * fresh replay of the ledger's revoke/reinstate entries must reproduce it
 * exactly. The status-list bitstring an external verifier later consumes
 * (packages/vault) is rendered from this same state, so there is ONE
 * revocation vocabulary — the local kill's record is already the shape S6
 * publishes.
 */

/** A door revokes a subject's credentials (kill). target = the subject. */
export const AGENT_REVOKE = 'agent.revoke';
/** The authorized reversal of a revoke (un-kill). */
export const AGENT_REINSTATE = 'agent.reinstate';
/**
 * Registers a subject at ISSUANCE time (S4): allocates its status-list index
 * (so a credential/mandate can carry its `revocation_ref` from day one) and
 * puts the issuance itself on the record. Registration NEVER changes an
 * existing subject's state — re-registering a revoked subject is not a
 * reinstate.
 */
export const SUBJECT_REGISTER = 'subject.register';

/** Typed subjects keep agent / door / mandate namespaces from colliding. */
export function agentSubject(actorDid: string): string {
  return `agent:${actorDid}`;
}
export function doorSubject(doorId: string): string {
  return `door:${doorId}`;
}
export function mandateSubject(mandateId: string): string {
  return `mandate:${mandateId}`;
}

/**
 * Apply one entry's revocation effect. Revoke/reinstate reuse a subject's
 * status-list index across state changes (a credential keeps its slot);
 * first sighting allocates the next index in ledger order (deterministic on
 * replay). Non-revocation entries have no effect.
 */
export async function applyRevocationEntry(kv: ProjectionKV, entry: LedgerEntryV1): Promise<void> {
  const type = entry.action.type;
  if (type !== AGENT_REVOKE && type !== AGENT_REINSTATE && type !== SUBJECT_REGISTER) {
    return;
  }
  const subject = entry.action.target;
  const existing = await kv.getRevocation(subject);
  if (type === SUBJECT_REGISTER) {
    if (existing !== null) {
      // Idempotent and state-preserving: registration can never un-revoke.
      return;
    }
    await kv.putRevocation({
      subject,
      revoked: false,
      statusIndex: await kv.allocateStatusIndex(),
      updatedAt: entry.ts,
      entryHash: entry.entry_hash,
    });
    return;
  }
  const statusIndex = existing?.statusIndex ?? (await kv.allocateStatusIndex());
  await kv.putRevocation({
    subject,
    revoked: type === AGENT_REVOKE,
    statusIndex,
    updatedAt: entry.ts,
    entryHash: entry.entry_hash,
  });
}

/**
 * The revocation projector — passed to `appendProjected` for kill/reinstate
 * appends. It never refuses an append (revocation is the door's decision,
 * not a budget check); it just records the state change under the lock.
 */
export function revocationProjector() {
  return async (kv: ProjectionKV, entry: LedgerEntryV1): Promise<null> => {
    await applyRevocationEntry(kv, entry);
    return null;
  };
}

/** In-memory RevocationKV over a Map — replay and tests. */
export class MapRevocationKV implements RevocationKV {
  readonly records = new Map<string, RevocationRecord>();
  private nextIndex = 0;

  getRevocation(subject: string): Promise<RevocationRecord | null> {
    return Promise.resolve(this.records.get(subject) ?? null);
  }

  putRevocation(record: RevocationRecord): Promise<void> {
    this.records.set(record.subject, record);
    return Promise.resolve();
  }

  allocateStatusIndex(): Promise<number> {
    const index = this.nextIndex;
    this.nextIndex += 1;
    return Promise.resolve(index);
  }
}

/**
 * Rebuild the revocation table from ledger entries alone — the projection's
 * ground truth. Only revoke/reinstate entries have any effect; everything
 * else is skipped, so the spend entries between kills are inert here.
 */
export async function replayRevocation(
  entries: readonly unknown[]
): Promise<Map<string, RevocationRecord>> {
  const kv = new MapRevocationKV();
  for (const raw of entries) {
    const entry = raw as LedgerEntryV1;
    if (typeof entry?.action?.type === 'string') {
      // MapRevocationKV supplies only the revocation half of ProjectionKV;
      // applyRevocationEntry never touches the counter half.
      await applyRevocationEntry(kv as unknown as ProjectionKV, entry);
    }
  }
  return kv.records;
}

export interface RevocationDivergence {
  subject: string;
  stored: RevocationRecord | null;
  replayed: RevocationRecord | null;
}

/** Compare a stored revocation table against a fresh replay. Empty = invariant holds. */
export function diffRevocation(
  stored: ReadonlyMap<string, RevocationRecord>,
  replayed: ReadonlyMap<string, RevocationRecord>
): RevocationDivergence[] {
  const divergences: RevocationDivergence[] = [];
  const subjects = new Set([...stored.keys(), ...replayed.keys()]);
  for (const subject of subjects) {
    const a = stored.get(subject) ?? null;
    const b = replayed.get(subject) ?? null;
    if (
      a === null ||
      b === null ||
      a.revoked !== b.revoked ||
      a.statusIndex !== b.statusIndex ||
      a.updatedAt !== b.updatedAt ||
      a.entryHash !== b.entryHash
    ) {
      divergences.push({ subject, stored: a, replayed: b });
    }
  }
  return divergences;
}
