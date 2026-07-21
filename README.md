# Mandare

**The accountability stack for AI agent fleets** — verified agent identity,
signed spending mandates, and a tamper-evident ledger of what your agents
actually did.

> **Status: pre-alpha.** A local gateway now ENFORCES signed spending
> mandates on real LLM traffic (Anthropic, OpenAI, OpenRouter — streaming
> included): every call reserves its estimated cost inside the ledger
> transaction, settles the true cost after, and dies at the cap. A runaway
> agent loop cannot outspend its mandate — that is the acceptance test
> (`pnpm demo`). Nothing here is production-ready yet.

## What exists today

- **Gateway** (`packages/gateway`) — Fastify door proxying the native
  Anthropic (`/v1/messages`) and OpenAI/OpenRouter (`/v1/chat/completions`)
  APIs, streaming pass-through with usage true-up. Log-before-act: an INTENT
  entry *reserves* the estimated cost before the call executes; a RESULT
  entry settles the true cost after; refused reservations are DENIED entries
  on the ledger. No ledger write → no call. Budget overshoot by concurrent
  calls is impossible by construction (reservations serialize under the
  append lock — red-team proven).
- **Policy engine** (`packages/policy-engine`, Apache-2.0) — mandate
  evaluation in SPEC order: identity → validity window → scope → budgets
  (per-tx / per-day / per-task / total + velocity) → counterparty →
  approval threshold. Cedar-shaped interface; checks that cannot run yet
  fail *closed*.
- **Vault** (`packages/vault`) — the credential door. Third-party keys and the
  door signing key live in the OS keychain (`@napi-rs/keyring`), encrypted at
  rest; agents never see a raw secret. It mints short-lived (≤30-min)
  proof-of-possession scoped tokens: a leaked token id without its secret is
  dead paper, replays are refused, and a kill makes it dead instantly.
- **Kill switch** (`mandare kill <agent>`) — the LOCAL, offline, un-jammable
  authority. It writes an `agent.revoke` entry to the ledger and flips a
  revocation projection in the same transaction; the gateway fails closed on
  its very next request, with no network round-trip. The revocation is an IETF
  Token Status List bitstring — the same vocabulary a witness service later
  publishes for external verifiers.
- **Ledger** (`packages/ledger`) — append-only SQLite/Postgres store, every
  entry hash-chained and Ed25519-signed. Budget counters AND revocation state
  are derived projections of the ledger, rebuildable from it and continuously
  checkable against a fresh replay (`mandare verify --spend`).
- **Verifier** (`packages/verifier`, Apache-2.0) — pure chain verification
  anyone can embed, including parties who distrust us.
- **Spec** (`packages/spec`, Apache-2.0) — the typed mandate and ledger-entry
  schemas. An open contract.
- **CLI** (`apps/cli`) — `mandare verify --db <path>` (RFC 6962 tree heads,
  `--key-directory`, `--prev-head` rollback detection, `--prove` inclusion
  proofs, `--spend` trail + counter invariant, plus the revocation trail +
  status list), `mandare kill`/`reinstate`/`token`/`vault`, and `mandare
  directory` (publish door keys as an RFC 9421-style JWKS — `docs/KEY-DIRECTORY.md`).

## The demo: a runaway loop dies at €20

```bash
pnpm install && pnpm build
pnpm demo
```

A scripted runaway agent hammers the gateway under a €20/day mandate. Call
#72 is refused mid-loop, the refusal itself becomes a ledger entry, and
`mandare verify --spend` proves the chain AND that the budget counters equal
a fresh replay of the ledger. Captured run: `docs/demos/S2-runaway-demo.txt`.

## The demo: a stolen token is dead paper

```bash
pnpm demo:dead-paper
```

An agent authenticates with a short-lived vault-issued proof-of-possession
token (the provider key stays in the vault). A thief who exfiltrates the token
id is refused (no secret → no proof); a captured request can't be replayed
(single-use nonce); then `mandare kill` mid-task makes the running agent's very
next call fail closed — the refusal lands on the ledger, and `mandare verify`
proves chain + spend + revocation all equal a fresh replay. Local authority, no
cloud. Captured run: `docs/demos/S3-dead-paper-demo.txt`.

## Quickstart (your own keys)

```bash
cp .env.example .env       # fill in ANTHROPIC_API_KEY (and/or OPENAI/OPENROUTER)
node scripts/dev-mandate.mjs --out mandate.json --per-day 20   # €20/day, signed
set -a; source .env; set +a
MANDARE_MANDATE_PATH=mandate.json MANDARE_LEDGER_DB=./ledger.db \
MANDARE_USD_PER_LEDGER_UNIT=1.08 node packages/gateway/dist/start.js

# Point any Anthropic-SDK agent at http://127.0.0.1:8484 — or:
curl -s localhost:8484/v1/messages -H 'content-type: application/json' \
  -d '{"model":"claude-haiku-4-5","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}'
node apps/cli/dist/main.js verify --db ./ledger.db --spend
```

## License

AGPL-3.0-only, **except** the packages listed in [LICENSING.md](LICENSING.md),
which are Apache-2.0 (spec, policy engine, verifier — the parts the ecosystem
must be able to embed and independently implement).

## Security

See [SECURITY.md](SECURITY.md). Signed releases, provenance, and the audit
trail are core to this project, not an afterthought.
