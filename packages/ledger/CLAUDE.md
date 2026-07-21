# @mandarelabs/ledger (AGPL-3.0-only)

Append-only, hash-chained, door-signed event store on `node:sqlite`
(zero native deps — supply-chain posture).

## Invariants

- **No update/delete path exists** — not in the API, and SQLite triggers RAISE
  on UPDATE/DELETE (`ledger is append-only`). Corrections are new entries
  referencing `correction_of`.
- seq starts at 1, strictly +1; `BEGIN IMMEDIATE` around head-read + insert.
- Entries are validated (`parseLedgerEntry`) BEFORE insert — nothing
  schema-invalid can enter the chain.
- One door per ledger DB WRITES; door-key/door-id mismatch on open →
  refuse to write. Multi-door chains + key rotation are verified via the
  key directory (S1, docs/KEY-DIRECTORY.md); a multi-key writer waits for
  the S3 keychain work.
- Door key: Ed25519 PKCS8 PEM next to the DB, mode 0600,
  `key_provenance: "software"`. TODO(S3): OS keychain via @napi-rs/keyring.

## Red-team suite (`test/red-team/`, rule R5)

Permanent CI gate (`pnpm red-team`). Attacker model: file access to the DB
(Postgres: up to superuser), no door key. Every technique must be blocked or
fail verification loudly.
**Never weaken these tests to make a change pass.** Documented boundary:
tail truncation is locally invisible — witnessing (S6) closes it; the test
stating that is intentional and load-bearing.

## Drivers (Q7, S1)

`LedgerStore` is the thin driver interface; chain semantics live in
`buildEntry` (shared, so all drivers emit byte-identical chains).

- `SqliteStore` / sync `Ledger` — solo mode (`node:sqlite`, zero native deps).
- `PgStore` + `AsyncLedger` — team mode. Provision as admin
  (`provisionPgLedger`: schema, RAISE triggers, INSERT-only grants), connect
  as the app role only. Superuser bypass is the documented Q7 boundary —
  witnessing (S6) exists for it; the PG red-team file proves detection.
- Red-team runs against BOTH drivers (`tamper.test.ts`, `tamper-pg.test.ts`);
  Postgres comes from `embedded-postgres` (dev-only binaries, no Docker).

Bench: `pnpm --filter @mandarelabs/ledger bench` (build first) — S1 numbers
in TASKS.md.

## Spend projection (S2 — `projection.ts` / `spend-ledger.ts`)

Budget counters are a DERIVED PROJECTION of the ledger, never a second
source of truth (binding architecture decision):

- `budget_counters` + `projection_meta` are deliberately MUTABLE (no
  append-only triggers); integrity comes from the invariant
  **replay(ledger) == counters**, enforced by `verifySpendProjection` and
  red-team-tested on both drivers (`projection-race.test.ts`).
- Every counter mutation happens in the SAME transaction as its ledger
  append (`appendProjected`). INTENT entries carry the estimate in
  `cost.amount` and RESERVE it; RESULT entries (via `outcome_ref`) release
  the reservation and settle true cost into the INTENT's day bucket;
  `llm.call.denied` entries record refusals with zero counter effect.
- Reservation guards run under the append lock — that is what makes
  concurrent cap overshoot structurally impossible (the race red-team
  asserts EXACT admission counts).
- Projection stale (seq ≠ head, e.g. after a plain `append`) ⇒
  `ProjectionStaleError`, callers fail closed; rebuild explicitly with
  `rebuildSpendProjection` (ledger is the ground truth).
- `SqliteStore` serializes its transactions through an internal promise
  queue — node:sqlite is ONE connection and projected appends await between
  BEGIN and COMMIT. Don't remove it; the race test exists because of it.

## Commands

`pnpm --filter @mandarelabs/ledger test | red-team`
(node:sqlite prints an ExperimentalWarning — known, harmless, Q7 accepts RC status.)
