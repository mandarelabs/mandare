# A runaway agent loop dies at €20 — and the refusal is evidence

An agent stuck in a loop is the cheapest way to lose real money with LLMs:
each call looks reasonable, none of them stops, and the bill arrives later.
Prompting "please stay under budget" is not a control — the model can talk
itself (or be talked) out of it.

This scenario releases a deliberately runaway loop against a Mandare gateway
under a signed mandate: **€5 per call, €20 per day, €100 total**. The human
signed once. Nothing else was configured.

## What happens

```
  call #  1  200 OK   — ~€0.28 spent so far
  call # 70  200 OK   — ~€19.45 spent so far

  call # 72  403 DENIED — THE LOOP DIES HERE
    code:   PER_DAY_EXCEEDED
    reason: per-day budget exceeded: reserved 0.00 EUR + settled 19.723587 EUR
            + estimate 0.277803 EUR > cap 20.00 EUR
    the refusal itself is ledger entry 92938e3617eb03c8…
```

71 calls in ~0.1 seconds, then a hard stop — before the 72nd call reaches
any provider. The refusal is not a log line that scrolls away; it is a
signed, hash-chained ledger entry. `mandare verify --spend` then proves:

- **chain VALID** — every entry hash-linked and door-signed,
- **counters == replay(ledger)** — the budget counters are a derived
  projection of the ledger, recomputed from scratch and compared,
- the full INTENT/RESULT trail of every call, including the one that was
  refused.

## Why the cap actually holds (the part that's hard)

The naive design — check spend, then call — has a race: N parallel calls all
pass the check before any of them settles. Mandare **reserves** the
estimated cost inside the same database transaction that appends the INTENT
entry, under the ledger's write lock; the RESULT entry settles the true cost
and releases the reservation. Overshoot is impossible by construction, not
statistically — there is a red-team test that fires N concurrent calls at
the cap and asserts the exact admission count, on SQLite and Postgres.

Estimates are deliberately conservative (input tokens bounded by UTF-8 byte
length — a provable ceiling for byte-level BPE in any script), and unknown
outcomes settle at the reserved estimate, never zero: a timeout might have
billed, so it must not reopen the cap.

## Run it

From the repo root (once): `./install.sh` — then:

```bash
./run.sh
```

No API keys needed (mock provider). The script asserts every claim above and
exits non-zero if any of them fails — CI runs it on every push. Captured
output: [`docs/demos/S2-runaway-demo.txt`](../../docs/demos/S2-runaway-demo.txt).

## Where to look in the code

- Reservation inside the append transaction: `packages/ledger/src/spend-ledger.ts`
- Policy order (SPEC §5): `packages/policy-engine/src/engine.ts`
- The budget-race red-team test: `packages/gateway/test/red-team/budget-race.test.ts`
- The demo script itself: `scripts/demo-runaway.mjs`
