# @mandarelabs/witness-protocol (Apache-2.0)

The witness wire protocol (SPEC §3.2, §6 locks 4–5, §9.4). **Anyone must be
able to speak and CHECK this protocol without trusting Mandare** — that
drives every constraint:

- **Content-free by construction.** The only thing that ever leaves a door is
  `{size, 32-byte RFC 6962 root}` over entry hashes whose preimages carry a
  random 16-byte salt. If a change would put ledger content (or anything
  dictionary-testable) on this wire, the change is wrong.
- **No AGPL imports, ever** (Apache boundary — CI-enforced). Depends only on
  `spec`, `verifier`, TypeBox. The ledger's `DoorKey` is consumed
  STRUCTURALLY via the local `HeadSigner` interface — never import it.
- One signing rule: Ed25519 over `sha256(canonicalJson(payload))` — same as
  ledger entries. Verification paths never throw on hostile input; they
  refuse (R4).
- The client's offline story is a documented degradation, not a queue: the
  first sync after a gap witnesses the whole backlog via one consistency
  proof. Don't add a literal head queue — it buys nothing (the tree commits
  to every prior entry) and complicates catch-up.
- `ots.ts` is a HAND-ROLLED minimal OpenTimestamps client (TASKS.md S6
  decision — the npm client's dependency tree violates the Q24 posture). The
  emitted `.ots` bytes are the standard detached-proof format; keep them
  verifiable by stock OTS clients. Parse bounds (varuint/varbytes/depth/
  nodes) are load-bearing — calendar responses are external input.
- Certificate checks are labeled `proof` vs `recorder-attested`. Never
  promote a recorder-attested claim to proof — that distinction is the
  project's honesty rule in code.
