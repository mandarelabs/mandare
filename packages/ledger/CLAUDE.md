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
- One door per ledger DB at this tier; door-key/door-id mismatch on open →
  refuse to write. Multi-door + key rotation is S1 scope.
- Door key: Ed25519 PKCS8 PEM next to the DB, mode 0600,
  `key_provenance: "software"`. TODO(S3): OS keychain via @napi-rs/keyring.

## Red-team suite (`test/red-team/`, rule R5)

Permanent CI gate (`pnpm red-team`). Attacker model: file access to the DB,
no door key. Every technique must be blocked or fail verification loudly.
**Never weaken these tests to make a change pass.** Documented boundary:
tail truncation is locally invisible — witnessing (S6) closes it; the test
stating that is intentional and load-bearing.

## S1 (next session) scope

Ed25519 signing benchmarks (10k entries/s target), RFC 6962 consistency
proofs (hand-rolled ~150 lines + RFC test vectors), rollback/replay red-team
todos, Postgres mode (INSERT-only grants + BEFORE UPDATE/DELETE triggers).

## Commands

`pnpm --filter @mandarelabs/ledger test | red-team`
(node:sqlite prints an ExperimentalWarning — known, harmless, Q7 accepts RC status.)
