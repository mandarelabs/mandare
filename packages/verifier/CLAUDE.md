# @mandarelabs/verifier (Apache-2.0)

Pure chain verification. **Anyone must be able to run this against a Mandare
ledger — including parties who distrust us.** That drives every constraint:

- **No I/O, no Node-only APIs** — WebCrypto (`globalThis.crypto.subtle`) only;
  must run in browsers/edge. The CLI does the file reading, not this package.
- **No AGPL imports, ever** (Apache boundary — CI-enforced). Depends only on
  `@mandarelabs/spec`.
- Tests build chains from scratch with WebCrypto, deliberately independent of
  `@mandarelabs/ledger` — the verifier must hold against ANY writer.

## Failure codes

`SCHEMA_INVALID · SEQ_START · SEQ_GAP · GENESIS_MISMATCH · PREV_HASH_MISMATCH
· ENTRY_HASH_MISMATCH · KEY_MISMATCH · SIGNATURE_INVALID` — first failure
wins, with seq + index + human reason. Red-team tests assert on these codes;
renaming one is a breaking change.

## Honest scope (do not oversell in docs)

Local verification proves internal consistency + authorship. It CANNOT detect
tail truncation or rollback to an older copy — external witnessing (S6) does.
The CLI prints this caveat on success; keep it.

## S1+: RFC 6962 consistency proofs land here (verify old-head ⊆ new-head).
