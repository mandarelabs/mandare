# Mandare

**Give your agents a budget they cannot talk their way out of.**

Mandare is the accountability stack for AI agent fleets: verified agent
identity (**Passport**), signed machine-readable authority (**Mandate**), a
tamper-evident ledger of what agents actually did (**Ledger**), an offline
**kill switch** — and external **witnessing + public anchoring** so ledger
history cannot be truncated or rewritten without detection (with the witness
on separate infrastructure, not even by the operator — the solo compose
stack runs everything on one host and says so). Local-first: raw activity
never leaves your machine.

> **Status: pre-launch.** All five core layers are built and red-team-tested;
> packaging (this repo, the docs, docker, MCP, SDKs) is fresh. Terminal
> captures of the five acceptance demos are in [`docs/demos/`](docs/demos/)
> — a demo GIF lands with the public release.

## Quickstart — 3 commands, no API keys needed

```bash
git clone https://github.com/mandarelabs/mandare && cd mandare
```

```bash
docker compose up -d --wait
```

```bash
docker compose run --rm demo
```

The demo releases a runaway agent loop against **your** gateway. The €20/day
mandate kills it mid-run: `403`, the refusal is itself a ledger entry, and
`mandare verify` proves chain VALID, counters == replay(ledger), and the
witnessed head history covers the chain. Dashboard at
**http://127.0.0.1:8788**. Real providers: put keys in `.env`
([docs](apps/docs/content/docs/quickstart.mdx)).

No docker:

```bash
./install.sh
```

```bash
pnpm demo
```

## How it works

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
and **agent input is hostile**. Refusals are recorded — the system keeps its
no's.

## The five demos are the acceptance tests (CI runs all of them)

| # | Claim | Run |
|---|---|---|
| 1 | A runaway loop dies at €20, with proof | `pnpm demo` |
| 2 | A stolen token is dead paper; kill bites mid-task | `pnpm demo:dead-paper` |
| 3 | One signed mandate replaces 40 prompts; humans approve async | `pnpm demo:mandate` |
| 4 | The card declines AT THE NETWORK; one cap governs both rails | `pnpm demo:card` |
| 5 | Truncation and rewrites can't hide from the witness | `pnpm demo:witness` |

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
