# @mandarelabs/witness (AGPL-3.0-only)

The reference witness server — single-tenant, open, self-hostable
(SPEC §3.2). The multi-tenant commercial witness lives OUTSIDE this repo and
speaks the same wire; nothing operational/billing-shaped belongs here.

Invariants:

- **The witness never sees ledger content.** It stores sizes, 32-byte salted
  roots, and signatures. Any endpoint that would accept or serve more is
  wrong by design.
- **Sources are self-authenticating**: `source_id == sha256(door pubkey)`,
  submissions verify against that key, and a registered source's key never
  changes.
- **Witnessed history is fork-free by construction**: every submission after
  the first must consistency-prove extension of the LAST witnessed head; the
  final prev-check + insert happens atomically in the store
  (`appendHead`'s BEGIN IMMEDIATE re-check) so concurrent submissions cannot
  fork either.
- **Storage gets the ledger's posture** (lock 2 applied to the witness):
  heads/sources refuse UPDATE/DELETE by trigger; epoch commitment columns
  are immutable — only the anchor receipt may progress. Red-teamed; never
  weaken the triggers to make a change pass.
- **Acks are promises of durable recording** — `synchronous = FULL` stays,
  because witness-ack gating (lock 5) releases money on the strength of an
  ack.
- Epoch inclusion proofs are rebuilt from stored leaves and the rebuild must
  reproduce the committed aggregate root (`epochInclusionFor` throws
  otherwise) — the witness holds ITSELF to its commitments.
