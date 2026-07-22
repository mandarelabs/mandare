import { LLM_CALL_INTENT, LLM_CALL_RESULT, type LedgerEntryV1 } from '@mandarelabs/spec';

/**
 * Spend-counter projection — the S2 budget surface.
 *
 * ARCHITECTURE (binding, decided before this session): counters are a DERIVED
 * PROJECTION of the ledger, never a second source of truth. Every counter
 * mutation happens in the SAME transaction as the ledger append that causes
 * it, and `replaySpendCounters(entries)` rebuilds the identical state from
 * the ledger alone. The red-team invariant is replay(ledger) == counters;
 * divergence means the projection was tampered with or is buggy → fail
 * closed and alert.
 *
 * Reservation semantics (kills the concurrent-overshoot race by construction):
 * - an INTENT entry carries the pre-flight cost estimate in `cost.amount`
 *   and RESERVES it against the day/total windows under the append lock;
 * - the paired RESULT entry (outcome_ref → intent) releases the reservation
 *   and settles the true cost — into the INTENT's day bucket, so a call
 *   authorized against day X's budget cannot dodge the cap at midnight;
 * - a DENIED entry records a refused reservation (its `cost.amount` is the
 *   refused estimate) and never touches the counters.
 */

/** Refused reservations are ledger entries too — audit trail includes the no. */
export const LLM_CALL_DENIED = 'llm.call.denied';

/**
 * Card rail (S5): a network authorization request is the INTENT (reserving
 * the requested amount under the same append lock as LLM spend — one
 * mandate, one cap, both rails), the door's approve decision is the RESULT
 * (settling the approved amount), and a decline is a DENIED entry with zero
 * counter effect. `action.target` on card auth entries is the Stripe
 * authorization id, which doubles as the replay guard: one reservation per
 * authorization, ever.
 */
export const CARD_AUTH_INTENT = 'card.auth.intent';
export const CARD_AUTH_RESULT = 'card.auth.result';
export const CARD_AUTH_DENIED = 'card.auth.denied';

export interface SpendCounter {
  reservedMicros: number;
  settledMicros: number;
  /** Number of intent entries recorded in this window (velocity source). */
  intents: number;
}

export const EMPTY_COUNTER: SpendCounter = { reservedMicros: 0, settledMicros: 0, intents: 0 };

export interface ProjectionRefusal {
  code: string;
  reason: string;
}

/** What a reservation guard sees: state BEFORE the intent it is judging. */
export interface SpendGuardView {
  estimateMicros: number;
  currency: string;
  day: SpendCounter;
  total: SpendCounter;
  minuteIntents: number;
}

export type SpendGuard = (view: SpendGuardView) => ProjectionRefusal | null;

/** Key-value view of the counter table inside one store transaction. */
export interface CounterKV {
  getCounter(key: string): Promise<SpendCounter | null>;
  putCounter(key: string, value: SpendCounter): Promise<void>;
  /** Parsed entry by entry_hash; null when unknown. */
  getEntryByHash(entryHash: string): Promise<unknown | null>;
}

/** The projection is corrupt/stale/impossible — callers must fail closed. */
export class ProjectionIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProjectionIntegrityError';
  }
}

const KEY_PREFIX_INTENT = 'intent:';
const KEY_PREFIX_CARD_AUTH = 'cardauth:';

function encode(part: string): string {
  return encodeURIComponent(part);
}

/** UTC day bucket from a Z-only ISO timestamp: '2026-07-21'. */
export function dayBucket(ts: string): string {
  return ts.slice(0, 10);
}

/** UTC minute bucket: '2026-07-21T12:34'. */
export function minuteBucket(ts: string): string {
  return ts.slice(0, 16);
}

export function dayKey(mandateId: string, ts: string): string {
  return `mandate:${encode(mandateId)}|day:${dayBucket(ts)}`;
}

export function totalKey(mandateId: string): string {
  return `mandate:${encode(mandateId)}|total`;
}

export function minuteKey(actor: string, ts: string): string {
  return `actor:${encode(actor)}|minute:${minuteBucket(ts)}`;
}

/** Per-intent marker row: open reservation amount + double-settle guard. */
export function intentKey(entryHash: string): string {
  return `${KEY_PREFIX_INTENT}${entryHash}`;
}

/**
 * Per-authorization single-use marker (card rail): written when a card
 * intent is applied, so a replayed authorization webhook can never reserve
 * twice — live appends refuse it in the projector, and a tampered chain
 * carrying two intents for one authorization explodes on replay.
 */
export function cardAuthKey(authorizationId: string): string {
  return `${KEY_PREFIX_CARD_AUTH}${encode(authorizationId)}`;
}

async function readCounter(kv: CounterKV, key: string): Promise<SpendCounter> {
  return (await kv.getCounter(key)) ?? EMPTY_COUNTER;
}

async function addTo(
  kv: CounterKV,
  key: string,
  delta: Partial<SpendCounter>
): Promise<void> {
  const current = await readCounter(kv, key);
  await kv.putCounter(key, {
    reservedMicros: current.reservedMicros + (delta.reservedMicros ?? 0),
    settledMicros: current.settledMicros + (delta.settledMicros ?? 0),
    intents: current.intents + (delta.intents ?? 0),
  });
}

function parseIntentEntry(value: unknown, entryHash: string): LedgerEntryV1 {
  if (typeof value !== 'object' || value === null) {
    throw new ProjectionIntegrityError(
      `result entry references intent ${entryHash.slice(0, 12)}… which is not in the ledger — refusing (fail-closed)`
    );
  }
  return value as LedgerEntryV1;
}

async function applyIntent(kv: CounterKV, entry: LedgerEntryV1): Promise<void> {
  const estimate = entry.cost.amount;
  await addTo(kv, dayKey(entry.mandate_id, entry.ts), { reservedMicros: estimate, intents: 1 });
  await addTo(kv, totalKey(entry.mandate_id), { reservedMicros: estimate, intents: 1 });
  await addTo(kv, minuteKey(entry.actor, entry.ts), { intents: 1 });
  const existing = await kv.getCounter(intentKey(entry.entry_hash));
  if (existing !== null) {
    throw new ProjectionIntegrityError(
      `intent ${entry.entry_hash.slice(0, 12)}… already has a reservation marker — projection corrupt`
    );
  }
  await kv.putCounter(intentKey(entry.entry_hash), {
    reservedMicros: estimate,
    settledMicros: 0,
    intents: 0,
  });
  if (entry.action.type === CARD_AUTH_INTENT) {
    // One reservation per network authorization, ever. The live projector
    // refuses a duplicate gracefully; a chain that somehow carries two
    // intents for one authorization is corrupt and must explode on replay.
    const authMarker = await kv.getCounter(cardAuthKey(entry.action.target));
    if (authMarker !== null) {
      throw new ProjectionIntegrityError(
        `card authorization ${entry.action.target} already has a reservation — duplicate intent (projection corrupt)`
      );
    }
    await kv.putCounter(cardAuthKey(entry.action.target), {
      reservedMicros: 0,
      settledMicros: 0,
      intents: 1,
    });
  }
}

async function applyResult(kv: CounterKV, entry: LedgerEntryV1): Promise<void> {
  const intentHash = entry.outcome_ref;
  if (intentHash === undefined) {
    throw new ProjectionIntegrityError(
      `result entry seq ${entry.seq} has no outcome_ref — cannot settle a reservation (fail-closed)`
    );
  }
  const intent = parseIntentEntry(await kv.getEntryByHash(intentHash), intentHash);
  const marker = await kv.getCounter(intentKey(intentHash));
  if (marker === null) {
    throw new ProjectionIntegrityError(
      `result entry seq ${entry.seq} settles intent ${intentHash.slice(0, 12)}… which has no reservation marker — projection corrupt`
    );
  }
  // `intents === 1` is the explicit settled flag: a zero-cost settlement
  // (provider error) must be just as final as a paid one, or a duplicate
  // result could re-add spend while replay stays "consistent".
  if (marker.intents !== 0) {
    throw new ProjectionIntegrityError(
      `intent ${intentHash.slice(0, 12)}… is already settled — duplicate result entry (fail-closed)`
    );
  }
  const reserved = marker.reservedMicros;
  const settled = entry.cost.amount;
  // Settle into the INTENT's buckets: the reservation was authorized against
  // that day's budget, and midnight must not reopen it.
  await addTo(kv, dayKey(intent.mandate_id, intent.ts), {
    reservedMicros: -reserved,
    settledMicros: settled,
  });
  await addTo(kv, totalKey(intent.mandate_id), {
    reservedMicros: -reserved,
    settledMicros: settled,
  });
  await kv.putCounter(intentKey(intentHash), {
    reservedMicros: 0,
    settledMicros: settled,
    intents: 1, // settled flag — see the duplicate-result guard above
  });
}

/**
 * Apply one entry's counter effects inside the append transaction. Unknown
 * action types have no effect (future doors project their own domains);
 * denied entries deliberately have no effect.
 */
export async function applySpendEntry(kv: CounterKV, entry: LedgerEntryV1): Promise<void> {
  const type = entry.action.type;
  if (type === LLM_CALL_INTENT || type === CARD_AUTH_INTENT) {
    await applyIntent(kv, entry);
  } else if (type === LLM_CALL_RESULT || type === CARD_AUTH_RESULT) {
    await applyResult(kv, entry);
  }
}

/**
 * The reservation projector: for INTENT entries, runs `guard` against the
 * pre-reservation counters UNDER THE APPEND LOCK — a refusal aborts the
 * whole transaction (no entry, no counter change). This is the second,
 * authoritative run of the budget arithmetic; the gateway's pre-call policy
 * evaluation is the first (advisory, unlocked) run.
 */
export function spendProjector(guard?: SpendGuard) {
  return async (kv: CounterKV, entry: LedgerEntryV1): Promise<ProjectionRefusal | null> => {
    const isIntent =
      entry.action.type === LLM_CALL_INTENT || entry.action.type === CARD_AUTH_INTENT;
    if (entry.action.type === CARD_AUTH_INTENT) {
      // Replay guard runs UNDER the append lock: a second webhook for the
      // same authorization id (Stripe redelivery or an attacker replay) is
      // refused gracefully here, never reserving twice.
      const authMarker = await kv.getCounter(cardAuthKey(entry.action.target));
      if (authMarker !== null) {
        return {
          code: 'AUTH_REPLAYED',
          reason: `card authorization ${entry.action.target} was already decided — refusing a second reservation`,
        };
      }
    }
    if (guard !== undefined && isIntent) {
      const view: SpendGuardView = {
        estimateMicros: entry.cost.amount,
        currency: entry.cost.currency,
        day: await readCounter(kv, dayKey(entry.mandate_id, entry.ts)),
        total: await readCounter(kv, totalKey(entry.mandate_id)),
        minuteIntents: (await readCounter(kv, minuteKey(entry.actor, entry.ts))).intents,
      };
      const refusal = guard(view);
      if (refusal !== null) {
        return refusal;
      }
    }
    await applySpendEntry(kv, entry);
    return null;
  };
}

/** In-memory CounterKV over a Map — replay and tests. */
export class MapCounterKV implements CounterKV {
  readonly counters = new Map<string, SpendCounter>();
  private readonly entriesByHash: Map<string, unknown>;

  constructor(entries: readonly unknown[] = []) {
    this.entriesByHash = new Map(
      entries
        .filter(
          (entry): entry is { entry_hash: string } =>
            typeof entry === 'object' &&
            entry !== null &&
            typeof (entry as { entry_hash?: unknown }).entry_hash === 'string'
        )
        .map((entry) => [entry.entry_hash, entry as unknown])
    );
  }

  getCounter(key: string): Promise<SpendCounter | null> {
    return Promise.resolve(this.counters.get(key) ?? null);
  }

  putCounter(key: string, value: SpendCounter): Promise<void> {
    this.counters.set(key, value);
    return Promise.resolve();
  }

  getEntryByHash(entryHash: string): Promise<unknown | null> {
    return Promise.resolve(this.entriesByHash.get(entryHash) ?? null);
  }
}

/**
 * Rebuild the full counter state from ledger entries alone — the projection's
 * ground truth. Zero-valued counters are dropped so the result compares
 * cleanly against a stored table that never materialized untouched windows.
 */
export async function replaySpendCounters(
  entries: readonly unknown[]
): Promise<Map<string, SpendCounter>> {
  const kv = new MapCounterKV(entries);
  for (const raw of entries) {
    // Replay trusts chain verification for integrity; here we only need the
    // spend-relevant fields, and structurally invalid entries simply have no
    // projection effect either live or on replay.
    const entry = raw as LedgerEntryV1;
    if (typeof entry?.action?.type === 'string') {
      await applySpendEntry(kv, entry);
    }
  }
  for (const [key, counter] of kv.counters) {
    if (counter.reservedMicros === 0 && counter.settledMicros === 0 && counter.intents === 0) {
      kv.counters.delete(key);
    }
  }
  return kv.counters;
}

export interface ProjectionDivergence {
  key: string;
  stored: SpendCounter | null;
  replayed: SpendCounter | null;
}

/** Compare stored counters against a fresh replay. Empty array = invariant holds. */
export function diffProjection(
  stored: ReadonlyMap<string, SpendCounter>,
  replayed: ReadonlyMap<string, SpendCounter>
): ProjectionDivergence[] {
  const divergences: ProjectionDivergence[] = [];
  const keys = new Set([...stored.keys(), ...replayed.keys()]);
  for (const key of keys) {
    const storedCounter = stored.get(key) ?? null;
    const replayedCounter = replayed.get(key) ?? null;
    const isZero = (counter: SpendCounter | null): boolean =>
      counter === null ||
      (counter.reservedMicros === 0 && counter.settledMicros === 0 && counter.intents === 0);
    if (isZero(storedCounter) && isZero(replayedCounter)) {
      continue;
    }
    if (
      storedCounter === null ||
      replayedCounter === null ||
      storedCounter.reservedMicros !== replayedCounter.reservedMicros ||
      storedCounter.settledMicros !== replayedCounter.settledMicros ||
      storedCounter.intents !== replayedCounter.intents
    ) {
      divergences.push({ key, stored: storedCounter, replayed: replayedCounter });
    }
  }
  return divergences;
}
