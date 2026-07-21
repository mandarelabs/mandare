# @mandarelabs/cli (AGPL-3.0-only)

The `mandare` binary. S0: `verify` only.

```
mandare verify --db <path> [--door-key <hex>] [--json]
```

Without `--door-key`, verification is SELF-ANCHORED (door key read from the
ledger file itself): it proves internal consistency, NOT authorship — a
file-level attacker can re-sign the chain under a swapped key (see the
key-swap red-team test). The output says so; keep it. `--door-key` supplies
the raw Ed25519 public key from an independent source (key directory — S1;
witnessed heads — S6).

Exit codes are contract: 0 = chain valid · 1 = invalid/error · 2 = usage.
The smoke test and future CI/insurer tooling script against them.

- Zero runtime deps beyond workspace packages (arg parsing is hand-rolled —
  keep it that way until the command surface actually needs more).
- Composition rule: this package does I/O (read SQLite via
  `@mandarelabs/ledger`), the verifier stays pure. Don't move file access
  into the verifier.
- On success the output includes the truncation caveat (witnessing lands S6)
  — that honesty is deliberate; keep it.

Later sessions add: `mandare kill` (S3), `mandare export` (evidence packs),
`mandare mandate` (S4 issuance).
