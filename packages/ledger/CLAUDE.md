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

## Commands

`pnpm --filter @mandarelabs/ledger test | red-team`
(node:sqlite prints an ExperimentalWarning — known, harmless, Q7 accepts RC status.)
