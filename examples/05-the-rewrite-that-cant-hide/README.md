# The rewrite that can't hide — witnessing an append-only ledger

A tamper-evident log has a classic blind spot: the operator. Hash chains and
signatures prove *someone with the key* wrote a consistent history — they
can't stop the key-holder from truncating the file, or rewriting an entry
and re-signing everything after it. The doctored copy is locally perfect.

This scenario stages exactly that worst case — the attacker steals the
ledger file **and** the door's signing key — and shows both forgeries being
convicted anyway.

## What happens

```
[door]     8 entries appended; every head streamed + acked to a witness
[witness]  knows ONLY sizes + 32-byte salted roots — zero ledger content

[attacker] copy A: newest 2 entries DROPPED, chain re-signed
[attacker] copy B: entry 4 cost rewritten €1.00 → €0.000001, chain re-signed

[verify]  truncated copy, self-anchored:  chain VALID — the lie is locally perfect
[verify]  rewritten copy, self-anchored:  chain VALID — the lie is locally perfect

[verify]  truncated copy, --witness:   TRUNCATION DETECTED (exit 1)
[verify]  rewritten copy, --witness:   FORK DETECTED (exit 1)
[verify]  honest copy,    --witness:   CONSISTENT (exit 0) — no false positives
```

The door streams each RFC 6962 tree head to an external **witness** as it
grows; the witness signs and stores the head history and can serve
consistency proofs over it. A truncated copy is smaller than the witnessed
head; a rewritten copy forks from it. Neither can be explained away — and
the witness learned nothing about ledger *contents*: sizes and salted
32-byte roots only. Proofs, not data.

The demo then goes two steps further:

- **Public anchoring**: epoch aggregate roots are anchored via
  OpenTimestamps toward Bitcoin finality, bounding even a
  witness-and-operator-colluding rewrite in time.
- **`mandare certify`**: a selective-disclosure integrity certificate — a
  third party verifies chain validity, witnessed consistency, and two
  disclosed entries with **no ledger access**; a doctored certificate fails.

## Honest limits (they're in the threat model, not under the rug)

The witness must live on infrastructure the operator can't silently rewrite
— in the solo single-host compose stack, a full-root operator controls both
sides, and the docs say so. High-value actions can be gated on a witness ack
(and a kill landing during the ack wait is re-checked); a dead witness fails
those actions closed but never blocks `mandare kill` — the kill switch stays
local and un-jammable.

## Run it

From the repo root (once): `./install.sh` — then:

```bash
./run.sh
```

Runs a real reference witness process; anchoring uses a mock adapter in the
demo (live deployments use OpenTimestamps — same interface). CI asserts
every conviction *and* the no-false-positive case. Captured output:
[`docs/demos/S6-witness-demo.txt`](../../docs/demos/S6-witness-demo.txt).

## Where to look in the code

- Witness protocol (Apache, embeddable): `packages/witness-protocol/src/`
- The certificate + third-party checks: `packages/witness-protocol/src/certificate.ts`
- OpenTimestamps client: `packages/witness-protocol/src/ots.ts`
- The demo script: `scripts/demo-witness.mjs`
