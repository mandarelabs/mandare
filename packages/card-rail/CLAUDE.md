# @mandarelabs/card-rail (AGPL-3.0-only)

The second money door (S5): Stripe Issuing. Mounted ONTO the gateway's
Fastify app — one door process, one door key, one ledger — because S1 froze
"one writing door per ledger DB" and because the whole point is ONE budget
projection across rails. Never run this as a separate door against the same
ledger file.

```
issuing_authorization.request (signed webhook, ≤2s budget)
→ verify Stripe signature over EXACT raw bytes (forged/unsigned = 4xx,
  ZERO writes) → card→(actor,mandate) binding (unknown = decline)
→ revocation: door/agent/mandate/CARD from the LOCAL projection
→ currency sanity (two-decimal, == ledger currency; no invented FX)
→ policy.evaluate (SPEC §5, rail='card'; APPROVAL_REQUIRED ⇒ waiver check
  or decline-now + S4 push; cap refusal + is_amount_controllable ⇒ partial)
→ RESERVE: card.auth.intent, budget-guarded IN the append transaction
  (replay guard: one reservation per authorization id, ever)
→ SETTLE: card.auth.result BEFORE Stripe hears "approved"
  (unpersistable result ⇒ door halts, declines everything)
→ {approved, amount?}
```

## Hard rules

- **Signature verification is mandatory** — no webhook secret, no route.
  `webhook-signature.ts` is hand-rolled (HMAC v1 scheme, constant-time,
  tolerance window); its tests are the contract. Never "temporarily" skip it.
- **The 2s budget is Stripe's, not ours** (Q11): everything on the decision
  path must stay local. No network calls, no unbounded scans. The
  latency test asserts p99; keep it in the suite.
- **Stripe dashboard timeout default must be DECLINE** (docs/CARD-RAIL.md);
  monitor `request_history.reason=webhook_timeout`. A door outage then
  fails closed at the network too.
- **Step-up approvals decline first**: a human cannot answer in 2s. Decline
  → push → recorded approval.granted mints a single-use in-memory WAIVER
  (card+merchant+amount-ceiling+TTL) → the RETRY passes. Never hold the
  webhook; never auto-shrink an over-threshold amount to dodge approval
  (partials apply ONLY to budget-cap refusals).
- **One cap, both rails**: card.auth.* projects into the SAME
  `budget_counters` keys as llm.call.* (packages/ledger/projection.ts).
  Do not add card-only counter tables.
- **R2**: the door never returns a PAN; card creation responses carry id +
  last4 only. Stripe keys live in the vault (`provider:stripe`,
  `webhook:stripe`) or env for dev.

## Registry semantics

`CardRegistry` is a startup-rebuilt READ MODEL of card.create.result
entries, extended in-process on creation. `CreateVelocity` (S-8) is the
same kind of read model over card.create.intent entries: at most
`MAX_CARD_CREATES_PER_MINUTE` creations per agent per rolling minute. Cards created elsewhere are
unknown → their authorizations DECLINE until the door restarts. Revocation
is deliberately NOT cached — every authorization reads the projection, so
`mandare kill` (separate process, same DB) bites immediately.

## Testing

`test/helpers.ts` builds a real SQLite ledger + Fastify app per test.
`postWebhook` signs like Stripe does. Red-team suite (`pnpm red-team`):
forged/unsigned/tampered/replayed webhooks, killed subjects, the
20-way race against one cap (exact admission), cross-mandate cards.
