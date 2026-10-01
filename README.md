# Mandare

**Give your agents a budget they cannot talk their way out of.**

[![CI](https://github.com/mandarelabs/mandare/actions/workflows/ci.yml/badge.svg)](https://github.com/mandarelabs/mandare/actions/workflows/ci.yml)
[![License: AGPL-3.0 + Apache-2.0](https://img.shields.io/badge/license-AGPL--3.0%20%2B%20Apache--2.0-blue)](LICENSING.md)
[![npm](https://img.shields.io/npm/v/%40mandarelabs%2Fsdk?label=%40mandarelabs%2Fsdk)](https://www.npmjs.com/package/@mandarelabs/sdk)
[![Security review](https://img.shields.io/badge/security_review-AI--assisted,_audit_pending-lightgrey)](docs/SECURITY-REVIEW-S8.md)

Mandare is the accountability stack for AI agent fleets: signed agent
identity (**Passport**), signed machine-readable authority (**Mandate**), a
tamper-evident ledger of what agents actually did (**Ledger**), an offline
**kill switch** — and external **witnessing + public anchoring** so ledger
history cannot be truncated or rewritten without detection (with the witness
on separate infrastructure, not even by the operator — the solo compose
stack runs everything on one host and says so). Local-first: raw activity
never leaves your machine.

![A runaway agent loop dies at €20 in the no-docker demo — call #72 is refused, the refusal is written to the ledger, and `mandare verify` checks the chain](docs/demos/runaway-demo.gif)

<sub>Replay of the captured [Demo 1](docs/demos/S2-runaway-demo.txt) run
(`pnpm demo`, the no-docker path; the docker quickstart stops at call #24) — the
same script CI executes and asserts on every push. Regenerate:
`node scripts/render-demo-gif.mjs`.</sub>

## Quickstart — 3 commands, no API keys needed

Needs Docker with Compose v2 (`up --wait` needs v2.1.1+). The images build
locally on first run, which takes a few minutes.

```bash
git clone https://github.com/mandarelabs/mandare && cd mandare
```

```bash
docker compose up -d --wait
```

```bash
docker compose run --rm demo
```

The demo releases a runaway agent loop against **your** gateway, priced
against a bundled mock provider: the enforcement is real, the money isn't.
The €20/day mandate kills it mid-run: 23 calls settle €19.17, call #24's reservation would
cross €20 and is refused `403 PER_DAY_EXCEEDED`, the refusal is itself a ledger entry, and
`mandare verify` proves chain VALID, counters == replay(ledger), and the
witnessed head history covers the chain. Dashboard at
**http://127.0.0.1:8788**. Real providers: put keys in `.env`
([docs](apps/docs/content/docs/quickstart.mdx)).

When you're done, `docker compose down -v` removes the containers and the
demo volumes (`mandare-data`, `mandare-witness-state`).

No docker (Node ≥ 22.13 and pnpm 10; if pnpm is missing, `install.sh` runs
`corepack enable`, a global change):

```bash
./install.sh
```

```bash
pnpm demo
```

(`pnpm demo` runs a cheaper model and raises the gateway's default 60
calls/minute velocity limit so the budget is the only limit in play: 71 calls,
call #72 refused at the same €20 cap. The docker demo above runs the stack's
real defaults.)

`pnpm demo` runs without a witness, so `mandare verify` there can't see
entries dropped from the end of the ledger — refusals included — unless you
pass a saved `--prev-head`. The docker stack runs a witness, and
`pnpm demo:witness` shows it catching exactly that.

Or from npm (CLI + MCP server, no checkout; the MCP server reads the ledger
at `MANDARE_LEDGER_DB`, default `./mandare-ledger.db`):

```bash
npm i -g @mandarelabs/cli && mandare help
```

```bash
npx -y @mandarelabs/mcp-server
```

Where state lands: the CLI's vault (`./mandare-vault.db`, used by `passport
issue` and `vault …`) keeps its master key in the OS keychain by default;
`passport issue` writes the agent's credential and key under
`~/.mandare/agents/` by default; and unless `MANDARE_VAULT=1`, the door's private key sits
next to the ledger (`<ledger>.doorkey.pem`, mode 0600).

## Proofs, not data

Raw prompts and responses never leave your machine. What crosses a trust
boundary is only ever a **proof**: salted tree heads to the witness, an
integrity certificate to an auditor, a revocation bitstring to a verifier.

```
 agent (any SDK, base URL → the door)
   │  RFC 9421-signed request (passport)   or scoped PoP token
   ▼
 ┌──────────────── gateway door ────────────────┐
 │ kill-check → policy (mandate: caps/window/   │     ┌─ witness (external) ─┐
 │ scope/approval) → INTENT entry (reserves     │────▶│ salted head history, │
 │ cost in the ledger tx) → provider → RESULT   │ acks│ consistency-enforced,│
 │ entry (settles true cost)                    │◀────│ public anchor (OTS)  │
 └───────────────┬──────────────────────────────┘     └──────────────────────┘
                 ▼
        append-only ledger (SQLite/Postgres)
        hash-chained · door-signed · RFC 6962 tree
        budget counters + revocation = PROJECTIONS (replay-checkable)
                 ▼
   mandare verify · certify (third-party checkable) · dashboard · kill
```

Every door obeys three rules: **fail-closed on spend**, **log-before-act**,
and **agent input is hostile**. Refusals are ledger entries — the system keeps
its no's, and a witness keeps them from being quietly dropped.

## The five demos are the acceptance tests (CI runs all of them)

| # | Claim | Run |
|---|---|---|
| 1 | A runaway loop dies at €20, with proof | `pnpm demo` |
| 2 | A stolen token is dead paper; kill bites mid-task | `pnpm demo:dead-paper` |
| 3 | One signed mandate replaces 40 prompts; humans approve async | `pnpm demo:mandate` |
| 4 | The card declines AT THE NETWORK; one cap governs both rails | `pnpm demo:card` |
| 5 | Truncation and rewrites can't hide from an independent witness (verified with the door key held out-of-band) | `pnpm demo:witness` |

Each demo also exists as a self-contained, narrated scenario in
[`examples/`](examples/) — the story, the real captured output, and the code
to read next.

## Integrations

| Surface | Where | What |
|---|---|---|
| TypeScript SDK | `packages/sdk` (Apache-2.0) | A **signed fetch** for your existing Anthropic/OpenAI SDK (token PoP + passport RFC 9421) |
| Python client | `packages/sdk-py` (Apache-2.0) | Zero-dependency token-mode client (stdlib only) |
| MCP server | `packages/mcp-server` | The door as MCP tools: verify, budgets, issuance, kill — stdio, env-configured |
| OpenClaw skill | `integrations/openclaw` | Native AgentSkills skill (also works in Claude Code): budget awareness, honest refusals, proofs, kill |
| Self-host | `compose.yaml` + `install.sh` | gateway + witness + dashboard, no secrets needed for dry-run |
| Dashboard | `apps/dashboard` | Local-first fleet view over the ledger; zero telemetry |
| Docs | `apps/docs` → mandare.dev | Quickstart, concepts, threat model, reference |

## Security & provenance

- **Adversarially reviewed before launch — by AI, not yet by an external
  auditor**: four parallel AI-assisted review passes (crypto/integrity ·
  spend/enforcement · packaging/supply-chain · docs-vs-claims) were prompted
  to break the system. 15 findings — 3 HIGH — all fixed with regression tests
  or documented as accepted residuals, none silent. Full report:
  [`docs/SECURITY-REVIEW-S8.md`](docs/SECURITY-REVIEW-S8.md), including what
  was probed and held, the honest residuals, and the target list for the
  external audit. A second AI-assisted audit pass (2026-09) found further
  spend, witnessing and packaging defects; their fixes and red-team cases are
  logged in `TASKS.md` (S10-fix 2A–2D). The external audit is still pending.
- **Fail-closed by construction**: no mandate → no spend; ledger down → no
  action; witness dead → high-value actions refuse (the kill switch never
  depends on anything remote).
- **Red-team suites run in CI** (rule R5): edit/delete/truncate/rollback/
  replay/forge on SQLite AND Postgres, token theft + replay, signature
  coverage attacks, webhook forgery, budget races, witness split-view — and
  they may never be weakened to make a change pass.
- **Supply chain**: pnpm 10 with install scripts off, 3-day dependency
  cooldown, frozen lockfiles, hand-rolled security primitives pinned to
  official test vectors where they exist (RFC 6962 CT vectors, did:key/base58)
  and otherwise tested against the published wire scheme with adversarial
  round-trip suites (Stripe signatures, OpenTimestamps). From launch: npm
  Trusted Publishing (OIDC provenance), cosign-signed images, signed skill
  envelopes. Honest reproducibility bar in
  [`REPRODUCING.md`](REPRODUCING.md).
- **Verify without trusting us**: the verifier, passport, and witness
  protocol are Apache-2.0 and embeddable; `mandare certify` produces
  integrity certificates a third party checks with no ledger access.
- Vulnerabilities: see [`SECURITY.md`](SECURITY.md) (private reporting, safe
  harbor, 90-day disclosure).

## License

AGPL-3.0-only, **except** the embeddable packages listed in
[`LICENSING.md`](LICENSING.md) (spec, policy-engine, verifier, passport,
witness-protocol, sdk, sdk-py — Apache-2.0). The split is permanent; we do
not relicense.
