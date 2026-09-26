# Witnessing & public anchoring (S6)

The ledger is tamper-evident **locally** from S0: hash-chained, door-signed,
storage-enforced append-only. Two things local verification structurally
cannot prove were documented as open boundaries from day one:

- **Truncation** — dropping the newest entries leaves an internally perfect
  chain. Self-anchored `mandare verify` calls it VALID.
- **Authorship of history** — an attacker with the ledger file *and* the
  door key can rewrite an entry and re-sign the whole chain. Every signature
  verifies.

Witnessing closes both. This is integrity locks 4 and 5 (SPEC §6), and the
technical spine of *"we hold proofs, not data."*

## How it works

```
door (gateway/CLI)                    reference witness              public
──────────────────                    ─────────────────             ──────
append entry                          per-source witnessed
  └─ head = RFC 6962 tree             head history
     over entry hashes                (append-only storage,
       │  signed submission            consistency-ENFORCED
       ▼  {size, 32-byte root}         on every submission)
   POST /v1/heads  ────────────────►      │
       ▲                                  │ aggregate all sources
       └── signed ack ◄───────────────    │ into ONE Merkle tree
           (verified against the          ▼
            OUT-OF-BAND witness key)  aggregate root ──► OpenTimestamps
                                                          (daily, Bitcoin)
```

- **Content-free by wire format.** A submission is a tree size plus a
  32-byte root. Every entry hash commits to a random 16-byte salt in its
  preimage (`packages/spec`), so neither the root nor any proof node can be
  dictionary-tested against guessed entry contents (red-teamed). The witness
  learns *that* a ledger grew, never *what* it recorded.
- **Self-authenticating sources.** `source_id = sha256(door public key)` and
  every submission is signed by that key — nobody can write into another
  source's history (red-teamed).
- **Fork-free by construction.** Every submission after the first must carry
  an RFC 6962 consistency proof from the last witnessed head. The witness
  REFUSES anything that is not a provable append-only extension — a rewrite
  is rejected at submission time, not just detected later (red-teamed).
- **Verified acks.** The witness signs every ack and served head. Doors and
  verifiers check that signature against a witness public key obtained
  out-of-band (`MANDARE_WITNESS_PUBLIC_KEY` / `--witness-key`) — the same
  lesson as door keys: a channel cannot vouch for itself. Forged and
  replayed acks are refused (red-teamed).

## Detection: `mandare verify --witness`

```bash
mandare verify --db ledger.db --witness https://witness.example --witness-key <hex>
```

- Witnessed head size > local size → **TRUNCATION DETECTED** (exit 1).
- Local chain does not extend the witnessed head append-only → **FORK
  DETECTED** (exit 1).
- Witness unreachable → **UNAVAILABLE**, exit 1 — "cannot rule out
  truncation" is a failure, never a shrug.

Demo 5 (`pnpm demo:witness`, CI acceptance) shows both attacks passing
self-anchored verification and both convicted — including the strongest
local form, a re-signed chain under the REAL door key.

## Witness-ack gating (lock 5)

Streaming leaves an async window: entries appended after the last sync are
witnessed only on the next one. High-value actions do not tolerate that
window. With `MANDARE_WITNESS_ACK_MODE=threshold` (default when a witness is
configured), any action above the mandate's **approval threshold** — the
mandate's own definition of high-value; no second threshold vocabulary —
waits for a **verified witness ack of its intent entry** before executing:

- LLM path: reserve intent → ack the head containing it → forward.
- Card path: reserve intent → ack → settle → tell Stripe "approved".

No verified ack within `MANDARE_WITNESS_ACK_TIMEOUT_MS` (default 1500ms) ⇒
the reservation settles to ZERO and the action is refused
(`WITNESS_UNAVAILABLE` / a network decline). A dead witness can only keep
high-value doors shut — it can never open one, and it can never block
`mandare kill` (the kill switch is local by S3 ruling).

Measured cost (developer hardware, local witness, 500+ entry ledger): **p50
~15ms, p99 ~29ms** per gated ack — on top of the card rail's ~1ms decision
path, roughly 68× inside Stripe's 2s budget at p99. These figures are dev-box
measurements; the CI assertion is only p99 < 500ms (`test/witness-bench.test.ts`
prints the real numbers but does not gate on the specific values).
`MANDARE_WITNESS_ACK_MODE=all` gates every action; `off` streams without gating
(lock 4 only).

## Public anchoring

The witness periodically snapshots every source's latest witnessed head into
an **epoch**: one RFC 6962 tree over all sources, one root. That single root
is anchored via **OpenTimestamps** (BUILD-DECISIONS Q6): free, keyless, fine
for a daily cadence. A fresh receipt is **pending**: the calendars fold it
into a Bitcoin transaction within hours, and the witness polls them hourly
(`runUpgrade`, I-5) to store the Bitcoin attestation in the epoch receipt.
The emitted `.ots` receipt is the standard detached-proof format, verifiable
by any OTS client — and an offline verifier still reports even an upgraded
receipt as recorder-attested: confirm the block against a Bitcoin node.

- Adapter seam: `Anchor` interface in `@mandarelabs/witness-protocol`.
  `OpenTimestampsAnchor` (live), `MockAnchor` (CI/demos — its receipt says
  loudly it is NOT a public anchor), `BaseAnchor` (declared future EVM
  adapter, deliberately not built).
- Per-source privacy at the aggregate: an inclusion proof reveals hashes
  only — never another source's id or head. It does reveal the epoch's leaf
  count (`aggregate.size`) and this source's position among the id-sorted
  leaves (`leaf_index`), i.e. how many sources the witness aggregated that
  epoch (I-2). Both are needed to check the RFC 6962 inclusion proof.

## The integrity certificate (`mandare certify`, SPEC §9.4)

```bash
mandare certify --db ledger.db --witness <url> --witness-key <hex> \
  --disclose 3,5 --out certificate.json
mandare certify verify certificate.json --witness-key <hex>   # third party
```

The certificate states, checkably: **chain valid · sequence complete · heads
match independently witnessed history · root publicly anchored** — over
owner-SELECTED entries with inclusion proofs. A third party verifies it with
no ledger access and no Mandare service. Each check in the report is marked
`proof` (re-derived from the certificate alone) or `recorder-attested` (the
owner's verifier run over the full ledger — bounded by the witnessed history,
but not re-derivable without it). The S3 IETF Token Status List bitstring is
embedded **unchanged** — one revocation vocabulary from kill switch to
certificate.

## Running the reference witness

```bash
mandare witness serve --db witness.db --port 9411 --anchor ots
```

Prints its public key at startup — distribute it out-of-band. Single-tenant,
open (AGPL), self-hostable; also serves the RFC 9421 key directory and the
status list as static JSON (`--serve-directory`, `--serve-status-list`),
closing the S1/S3 hosting debt. The multi-tenant commercial witness is
explicitly OUT of this repository and speaks the same wire protocol.

The witness's own storage gets the ledger's posture: witnessed heads and
epoch commitments are storage-enforced append-only; only an anchor receipt
may progress (red-teamed).

## What witnessing does NOT cover (honest residuals, SPEC §6)

1. **A full-machine-root attacker acting entirely outside the doors** was
   never in the ledger's claimed coverage. Witnessing bounds what such an
   attacker can do to *recorded history after the fact*; it cannot make a
   machine you don't control tell the truth in real time.
2. **The async window for low-stakes actions.** Entries after the last
   witnessed head are covered only from the next head onward. That window is
   ~1s streaming cadence by default, zero for witness-ack-gated actions, and
   the price of offline operation otherwise.
3. **Offline mode degrades, honestly.** No connectivity ⇒ the ledger is
   local-chain tamper-evident (the S0–S5 posture); the first sync after
   reconnect witnesses the whole backlog at once via a consistency proof, so
   coverage has no holes — only the witnessed-at timeline does. High-value
   actions fail closed while offline (insurer-tier operation requires online
   witnessing as policy, SPEC §6).
4. **A malicious witness can lie by omission, not by forgery.** It cannot
   forge acks (doors verify signatures), cannot rewrite recorded heads
   (verifiers hold it to the same consistency proofs), and sees no content —
   but it can refuse service (⇒ high-value actions fail closed) or serve a
   stale head (bounded: it can never serve a head the door didn't sign).
   Running a second witness is the standard remedy and the protocol permits
   it (a door can stream to N witnesses independently).
