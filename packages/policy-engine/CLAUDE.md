# @mandarelabs/policy-engine (Apache-2.0)

The mandate enforcement point — designed for EMBEDDING in third-party
gateways/frameworks, hence Apache and dependency-light.

## Current state (S0)

Interface only + `UnconfiguredPolicyEngine` (allow-all, loudly labeled). It
exists so every door wires the enforcement call-site and fail-closed handling
now. **Callers must treat a thrown evaluate() as deny (rule R1).**

## Design constraints (BUILD-DECISIONS Q9 — do not re-litigate)

- Interface stays Cedar-shaped: `(principal, action, resource, context) →
  decision` so portable scope policies can move to cedar-wasm post-MVP.
- Budgets/velocity are STATEFUL and quantitative — counters must decrement in
  the SAME DB transaction as the ledger write. That's why this is custom TS,
  not Cedar/OPA.
- Decisions carry human-readable `reasons` — they surface in approval pushes
  and audit output.

## S2 scope (gateway+budgets session)

Real engine: mandate evaluation order per SPEC §5 (identity valid → mandate
valid & window → scope match → budget pre-check/true-up → counterparty →
approval threshold), budget counters in SQLite, velocity windows.
**Demo 1 acceptance: a runaway agent loop dies at the €20 cap.**

## Boundary

Apache package: NEVER import from ledger/gateway/cli (AGPL). `spec` is fine.
