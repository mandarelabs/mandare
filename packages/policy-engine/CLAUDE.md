# @mandarelabs/policy-engine (Apache-2.0)

The mandate enforcement point — designed for EMBEDDING in third-party
gateways/frameworks, hence Apache and dependency-light (spec only).

## Current state (S2)

- `MandatePolicyEngine` evaluates SPEC §5's order exactly: identity → mandate
  window → scope match → budget check → counterparty → approval threshold.
  Checks that cannot run yet fail CLOSED (`verified_only` → deny until the
  registry exists; above-approval-threshold → deny until CIBA push lands, S4).
- `checkBudgets` is the pure budget arithmetic. It runs TWICE per call: in the
  engine's pre-call evaluation, and again inside the ledger append transaction
  (the reservation step) — same function, provably same math. Keep it pure.
- The S0 `UnconfiguredPolicyEngine` stub is GONE. No mandate ⇒ spend path
  closed, never allow-all.

## Design constraints (BUILD-DECISIONS Q9 — do not re-litigate)

- Interface stays Cedar-shaped: `(principal, action, resource, context) →
  decision` so portable scope policies can move to cedar-wasm post-MVP.
- Budgets/velocity are STATEFUL and quantitative — counters live in the ledger
  DB as a projection (see `packages/ledger`), updated in the SAME transaction
  as the ledger write. That's why this is custom TS, not Cedar/OPA.
- Decisions carry human-readable `reasons` — they surface in approval pushes,
  denied ledger entries, and audit output.
- **Callers must treat a thrown evaluate() as deny (rule R1).**

## v0 semantics worth knowing

- Caps are literal: 0 = nothing allowed, never "unlimited".
- One mandate = one task until task attribution lands (S4): gateways pass the
  mandate-total counter as the task counter. A positive per-task cap with a
  null task counter REFUSES (`PER_TASK_UNATTRIBUTABLE`).
- Overlapping spend scopes deny (`SCOPE_AMBIGUOUS`) — v0 never merges budgets.
- Non-calendar validity timestamps deny (`MANDATE_WINDOW_INVALID`) — the S1
  H1 fail-open lesson, applied from day one.

## Boundary

Apache package: NEVER import from ledger/gateway/cli (AGPL). `spec` is fine.
