# The card declines at the network — one cap governs LLM and card spend

Give an agent a company card and you've given it a budget enforced by hope.
Card controls exist (per-card limits), but they live in a different system
than your LLM spend, so an agent with both rails has two half-budgets that
don't see each other.

This scenario runs **one door process** with both rails — the LLM proxy and
a Stripe Issuing card rail — writing to **one ledger** under **one €20
mandate**. The enforcement point for the card is Stripe's real-time
`issuing_authorization.request` webhook: approve/decline decided by the same
policy engine, inside Stripe's 2-second budget, *before the merchant sees an
authorization*.

## What happens

```
[agent]  LLM calls 1–6                → €15.00 of the €20 mandate consumed
[card]   €4.20 at ACME SaaS  → APPROVED   (15.00 + 4.20 ≤ 20.00)
[card]   €3.00 at ACME SaaS  → DECLINED AT THE NETWORK (19.20 + 3.00 > 20.00)
         the refusal is a ledger entry, not a vanished toast.

$ mandare kill did:mandare:demo-agent
    card killed:  ic_demo_1 — canceled at Stripe (belt-and-suspenders)
[card]   €0.50 post-kill     → DECLINED (agent + card revoked)
```

`mandare verify --spend` then shows the cross-rail arithmetic on one trail:

```
  mnd_dev_358867798869: settled 19.20 EUR · 7 call(s) · 2 refused
  rails:  llm settled 15.00 EUR · card settled 4.20 EUR · one cap governs both
```

## Why one ledger matters

Both rails **reserve inside the same append transaction**, so an LLM call
and a card authorization racing for the last euro cannot both win — the same
structural guarantee as the runaway-loop example, now spanning money that
moves through a card network. Card entries (`card.auth.intent` /
`card.auth.result`) are settled *before* Stripe hears "approved":
log-before-act, adapted to cards.

Also enforced on the card path: webhook signatures are mandatory (hand-rolled
Stripe-Signature verification over exact raw bytes; forged/unsigned webhooks
touch nothing), replayed authorizations are refused, unknown or cross-mandate
cards decline, and over-threshold purchases decline *now* and push the human
an approval — a granted approval mints a single-use waiver and the human
just retries the purchase.

## Run it

From the repo root (once): `./install.sh` — then:

```bash
./run.sh
```

The card network is simulated (signed webhooks against the real
verification path) — no Stripe account needed. CI asserts every step.
Captured output: [`docs/demos/S5-card-demo.txt`](../../docs/demos/S5-card-demo.txt).

## Where to look in the code

- The 2s decision path: `packages/card-rail/src/routes.ts`
- Stripe-Signature verification: `packages/card-rail/src/webhook-signature.ts`
- Step-up waivers: `packages/card-rail/src/waivers.ts`
- The demo script: `scripts/demo-card.mjs`
