# Card rail — Stripe Issuing door (S5)

The mandate that governs an agent's LLM spend also governs its card. One
spend scope with `rails: ["gateway", "card"]` gives one cap that BOTH rails
draw down; the enforcement point for the card is Stripe's real-time
authorization webhook — the purchase is approved or declined **at the
network**, not advisorily after the fact (SPEC §7, BUILD-DECISIONS Q11).

## Architecture

- The card rail is a Fastify plugin (`@mandarelabs/card-rail`) mounted on
  the **gateway's** app: one door process, one door key, one ledger. This is
  forced by S1's one-writing-door-per-ledger rule and is exactly what makes
  the cross-rail cap real — both rails reserve inside the same append
  transaction against the same `budget_counters`.
- Entries: `card.create.intent/result/failed` (creation is a
  mandate-checked, ledger-logged door op), `card.auth.intent` (the
  authorization request RESERVES the amount), `card.auth.result` (the
  approve decision SETTLES it), `card.auth.denied` (a decline, zero counter
  effect). `action.target` on auth entries is the Stripe authorization id
  and doubles as a projection-enforced single-use marker: one reservation
  per authorization, ever — replays are refused under the append lock and a
  spliced duplicate makes projection replay explode.
- Cards register a revocation slot at creation (`subject.register`,
  `card:<id>`) in the same status-list vocabulary as agents, doors, and
  mandates. `mandare kill` revokes the subject's cards (LOCAL authority)
  and best-effort cancels them at Stripe (belt, like OpenRouter
  `disableKey`).

## The 2-second budget (Q11)

Stripe expects the webhook answer within **2 seconds**; on timeout it
applies the dashboard default. The decision path is deliberately fully
local — HMAC verification, projection reads, two fsync'd appends — and is
continuously benchmarked by `test/decision-latency.test.ts` (p50 well under
5 ms on developer hardware; the CI assertion is p99 < 500 ms).

**Operator obligations (fail-safe on timeout):**

1. Set the Issuing authorization **timeout default to DECLINE** in the
   Stripe dashboard (do not rely on Autopilot approving). A crashed door
   then fails closed at the network too.
2. Monitor authorizations with `request_history.reason = "webhook_timeout"`
   — any occurrence means the door missed its budget and the dashboard
   default decided. Each such decline is invisible to the local ledger
   (the door never saw it decided), so timeouts are also the trigger to
   reconcile against Stripe's authorization list.
3. Respond-shape contract: `{"approved": bool}` (+ `"amount"` in minor
   units for partial approvals), echoing the event's `Stripe-Version`.

## Step-up approvals

A human cannot decide within 2 s, so over-threshold authorizations are
**declined immediately** while the S4 approval push goes out. A granted
approval is recorded on the ledger (`approval.granted`, attributed to the
mandate principal) and minted into a **single-use waiver** (card +
merchant + approved-amount ceiling, TTL `MANDARE_CARD_WAIVER_TTL_MS`,
default 10 min). The human then simply **retries the purchase**; the retry
consumes the waiver and passes the full policy order. Partials never apply
to approval thresholds — only to budget-cap refusals on
`is_amount_controllable` requests (fuel-pump semantics).

Waivers and pending approvals are in-memory: a door restart drops them, a
retry declines again, a new push goes out. Fail-closed, never unsafe.

## Configuration

| Env | Meaning |
|---|---|
| `STRIPE_WEBHOOK_SECRET` | webhook signing secret; **absent = the rail does not mount** |
| `STRIPE_SECRET_KEY` | API key for card create/cancel; absent = those ops closed, decisions still live |
| `STRIPE_CARDHOLDER_ID` | Issuing cardholder new cards belong to |
| `STRIPE_API_BASE` | injectable for mocks; default `https://api.stripe.com` |
| `STRIPE_API_VERSION` | optional pinned Stripe-Version for outbound calls |
| `STRIPE_WEBHOOK_TOLERANCE_SECONDS` | signature timestamp window (default 300) |
| `MANDARE_CARD_WAIVER_TTL_MS` | step-up waiver lifetime (default 600000) |

With `MANDARE_VAULT=1` the Stripe key and webhook secret are read from the
vault (`mandare vault import-env` recognizes both) — R2, nothing
agent-reachable holds them. Env-supplied `STRIPE_*` values are IGNORED in
vault mode (the startup banner says so).

**Host allowlist caveat:** the gateway's DNS-rebinding Host check applies to
`/stripe/webhook` too. Local `stripe listen` forwarding (localhost) passes
by default, but a deployment that receives webhooks on a real hostname must
add it to `MANDARE_GATEWAY_ALLOWED_HOSTS`, or every webhook 403s and each
authorization rides the dashboard timeout default (a silent, fail-closed
outage of the rail — watch `webhook_timeout`).

The door's `/healthz` reports `card_rail: { mounted, halted,
registered_cards }`; `halted: true` means a decision could not be recorded
and the card door is declining everything — investigate before restarting.

## Threat table

| Attack | Defense | Proven by |
|---|---|---|
| Forged/unsigned webhook | mandatory HMAC over exact raw bytes, constant-time; 4xx with ZERO ledger writes | red-team `card-tamper` |
| Replayed webhook of a DECIDED authorization (in-window) | early per-authorization marker check + the in-transaction single-use guard; decline, no writes — in every budget state | red-team |
| Replayed webhook of an UNDECIDED (step-up-declined) authorization | inherent: indistinguishable from a genuine retry; bounded by the signature gate, the approval-backlog cap, and the single-use waiver | accepted, this table |
| Replayed webhook (stale) | signature timestamp tolerance | red-team |
| Concurrent authorizations racing one cap | reservation under the append lock (S2 semantics) — exact admission count | red-team race (20-way) |
| Cross-rail overshoot (LLM + card) | both rails reserve in the same counters | gateway `card-rail-mount` test, Demo 4 |
| Killed agent/mandate/card/door | per-request read of the LOCAL revocation projection | red-team |
| Card from another mandate / unknown card | binding check against card.create.result lineage; decline | red-team |
| Currency confusion (JPY 100×, FX) | two-decimal allowlist + ledger-currency equality; decline | route tests |
| Door outage / webhook timeout | operator-set dashboard default DECLINE + `webhook_timeout` monitoring | this doc (operational) |
| Approval-threshold dodge via partials | partials restricted to budget-cap refusal codes | unit tests |

## Known gaps (scheduled)

- **Settlement true-up**: v0 settles at the authorized amount at decision
  time. Real captures (`issuing_transaction.created`, incl. partial
  reversals/multi-capture) reconcile in a later session via Storno
  corrections — conservative in the meantime (authorized ≥ captured).
- Webhook-timeout declines happen outside the door and are not ledger
  entries; reconciliation against Stripe's authorization list is manual.
- The card registry learns out-of-process card creations only on restart
  (their authorizations decline until then — fail-closed).
