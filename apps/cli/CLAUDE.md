# @mandarelabs/cli (AGPL-3.0-only)

The `mandare` binary. S1 surface: `verify`, `directory`.

```
mandare verify --db <path> [--door-key <hex>] [--key-directory <path|url>]
               [--prev-head <size>:<root>] [--prove <seq>] [--json]
mandare directory --key <pem> [--key ...] [--role door] [--nbf s] [--exp s] [--out f]
```

Without `--door-key`/`--key-directory`, verification is SELF-ANCHORED (door
key read from the ledger file itself): it proves internal consistency, NOT
authorship — a file-level attacker can re-sign the chain under a swapped key
(see the key-swap red-team test). The output says so; keep it. The key
directory (docs/KEY-DIRECTORY.md) is the canonical out-of-band anchor and
adds multi-door + rotation checks. `--prev-head` turns a recorded RFC 6962
tree head into rollback/rewrite detection; `--prove` emits inclusion proofs
for selective disclosure.

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
