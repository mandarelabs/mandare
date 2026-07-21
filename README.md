# Mandare

**The accountability stack for AI agent fleets** — verified agent identity,
signed spending mandates, and a tamper-evident ledger of what your agents
actually did.

> **Status: pre-alpha.** This is the S0 walking skeleton: a local gateway that
> proxies one LLM provider, writes hash-chained entries to a local SQLite
> ledger *before and after* every call, and a `mandare verify` CLI that proves
> the chain hasn't been touched. Nothing here is production-ready yet.

## What exists today

- **Gateway** (`packages/gateway`) — Fastify proxy for OpenRouter chat
  completions. Log-before-act: an intent entry is chained *before* the call
  executes; a result entry (tokens + cost) after. No ledger write → no call.
- **Ledger** (`packages/ledger`) — append-only SQLite store (`node:sqlite`,
  no native deps). Every entry is hash-chained and Ed25519-signed by the door
  that wrote it.
- **Verifier** (`packages/verifier`, Apache-2.0) — pure chain verification
  anyone can embed, including parties who distrust us.
- **Spec** (`packages/spec`, Apache-2.0) — the typed mandate and ledger-entry
  schemas. An open contract.
- **CLI** (`apps/cli`) — `mandare verify --db <path>` (RFC 6962 tree heads,
  `--key-directory`, `--prev-head` rollback detection, `--prove` inclusion
  proofs) and `mandare directory` (publish door keys as an RFC 9421-style
  JWKS — see `docs/KEY-DIRECTORY.md`).

## Quickstart

```bash
pnpm install
pnpm build

# End-to-end walking skeleton against a mock provider (no API key needed):
pnpm smoke

# Real call (optional):
OPENROUTER_API_KEY=sk-or-... MANDARE_LEDGER_DB=./ledger.db \
  node packages/gateway/dist/start.js
curl -s localhost:8484/v1/chat/completions -H 'content-type: application/json' \
  -d '{"model":"openrouter/auto","messages":[{"role":"user","content":"hi"}]}'
node apps/cli/dist/main.js verify --db ./ledger.db
```

## License

AGPL-3.0-only, **except** the packages listed in [LICENSING.md](LICENSING.md),
which are Apache-2.0 (spec, policy engine, verifier — the parts the ecosystem
must be able to embed and independently implement).

## Security

See [SECURITY.md](SECURITY.md). Signed releases, provenance, and the audit
trail are core to this project, not an afterthought.
