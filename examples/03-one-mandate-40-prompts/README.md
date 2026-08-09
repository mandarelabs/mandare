# One signed mandate replaces 40 permission prompts

The current answer to "should the agent be allowed to do this?" is a
permission prompt per action — which trains the human to click yes 40 times,
which is the same as no control at all. The alternative isn't more prompts;
it's **signed, machine-readable authority with a threshold for the cases
that genuinely deserve a human**.

Here the owner issues the agent a **passport** (a did:key identity with an
owner→agent delegation credential) and signs a **mandate** once: €5 per
transaction, €20 per day, *ask me above €0.25*.

## What happens

```
[agent]  step 1/6  signed call (~€0.001)   → 200 OK — no human involved
   …
[agent]  step 6/6  signed call (~€0.001)   → 200 OK — no human involved
         6 calls, 0 permission prompts. The mandate IS the answer.

[agent]  step 7: big synthesis call (~€0.28, above the €0.25 threshold)…
[push]   → "Mandare: approve ~0.2778 EUR?"
[human]  taps APPROVE on the phone.
[agent]  held call resumed                 → 200 OK

[agent]  step 8: ANOTHER big call (agent got ambitious)…
[human]  taps DENY.
[agent]  held call refused                 → 403 APPROVAL_DENIED
         the "no" is ledger entry c4a9958cd3beeeac…
```

In-scope work flows with zero interruptions. The over-threshold call is
**held** — the HTTP request literally waits — while a push notification
carries single-use Approve/Deny capability tokens to the human. Both
decisions land as ledger entries (`approval.granted`, `approval.denied`)
*before* the call resumes or is refused, attributed to the accountable
human, and `mandare verify` renders the whole approval trail.

## The details that keep it honest

- Every agent request is **RFC 9421-signed** under the passport's key, with
  a Content-Digest binding the exact body bytes — the door knows *who*, not
  just "someone with the config".
- An approval waives **only the threshold, only once**: the full policy
  order re-runs after the human decides (the budget may have moved while the
  call was held), and a kill landing during the hold is re-checked on resume.
- A looping agent can't flood the human: pending holds are capped, and past
  the cap it's an immediate recorded refusal, not a push.

## Run it

From the repo root (once): `./install.sh` — then:

```bash
./run.sh
```

The push channel is a file (CI mode) — the "phone tap" is scripted; wire
`MANDARE_NOTIFIER=ntfy` for real phone pushes. Mock provider, no API keys.
Captured output: [`docs/demos/S4-mandate-demo.txt`](../../docs/demos/S4-mandate-demo.txt).

## Where to look in the code

- Passport + delegation chain: `packages/passport/src/delegation.ts`
- Request signatures (RFC 9421 + Content-Digest): `packages/passport/src/request-signature.ts`
- The hold-push-decide flow: `packages/gateway/src/approvals.ts`
- Red-team suite (forged mandates, scope escalation, kill-during-hold):
  `packages/gateway/test/red-team/mandate-and-approval.test.ts`
- The demo script: `scripts/demo-mandate.mjs`
