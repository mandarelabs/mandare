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
· ENTRY_HASH_MISMATCH · KEY_MISMATCH · KEY_UNKNOWN · KEY_EXPIRED
· SIGNATURE_INVALID` — first failure wins, with seq + index + human reason.
Red-team tests assert on these codes; renaming one is a breaking change.
`KEY_UNKNOWN`/`KEY_EXPIRED` only occur in key-directory mode.

## Honest scope (do not oversell in docs)

Local verification proves internal consistency + authorship. Tail truncation
and rollback are only detectable against a PREVIOUSLY RECORDED tree head
(consistency proof); without one they stay invisible — external witnessing
(S6) automates recording. The CLI prints this caveat on success; keep it.

## S1 modules

- `merkle.ts` — hand-rolled RFC 6962 tree over entry hashes: `computeTreeHead`,
  inclusion + consistency proofs and verifiers. Tested against the CT
  reference vectors (transparency-dev/merkle). NOTE: @openzeppelin/merkle-tree
  was evaluated and rejected — its balanced/commutative tree is structurally
  incompatible with RFC 6962 (TASKS.md S1 decision).
- `directory.ts` — key directory (JWKS, RFC 9421/Web-Bot-Auth profile), the
  out-of-band anchor closing H1. `verifyChain` accepts EITHER `doorPublicKey`
  or `keyDirectory` (multi-door + rotation windows). See docs/KEY-DIRECTORY.md.
