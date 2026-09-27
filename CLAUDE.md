# Mandare — build guide for Claude Code sessions

**Mandare is the accountability stack for AI agent fleets:** verified agent
identity (Passport), signed machine-readable authority (Mandate), a
tamper-evident local ledger of what agents actually did (Ledger), and evidence
exports (Recourse). Local-first: raw activity never leaves the customer —
"we hold proofs, not data."

## Session protocol

1. **Read `TASKS.md` first** — it is the build log. What was done, decisions
   taken, what's next.
2. Implement to the current session's exit criteria. Do NOT re-litigate
   decided questions — the founder's decision docs are binding and live
   outside this repo; their operative content is captured in the rules below,
   TASKS.md decision entries, and package CLAUDE.md files.
3. **Update TASKS.md before finishing** (a Stop hook nudges you). Log: done /
   decisions (with reasons) / handoff for the next session.

## Publicity boundary

This repo goes public at launch, including its full git history. Engineering
content only — write all code, comments, commit messages, and TASKS.md entries
as if already public. Strategy/business content stays in the founder's private
notes (never committed here); future commercial/cloud service code belongs in a
separate private repo; secrets only in `.env`. Before the public flip (S9), run
a full history secret-scan (gitleaks) and a TASKS.md/commit-message review as
an explicit checklist item.

## The 10 engineering rules (binding — BUILD-DECISIONS §D)

- **R1 Fail-closed on spend:** gateway/vault down → no money moves. No exceptions.
- **R2 Secrets never leave the vault:** not in logs, errors, ledger entries (hashes only), or LLM context.
- **R3 Log-before-act** in every door: intent entry → execute → result entry. No entry → no action.
- **R4 Agent input is hostile:** no free-text control channels into policy/vault; schema-validated, allowlisted operations only. Prompt injection is assumed permanent.
- **R5 Red-team suite as CI:** tamper attempts (edit, delete, truncate, rollback, replay, gap-injection) are permanent tests that must fail loudly. Never weaken them to make a change pass.
- **R6 Schemas are frozen contracts** (`packages/spec`): changes need a TASKS.md decision entry + schema version bump, and plan mode.
- **R7 Every component ships its demo script** — the demos are the acceptance tests.
- **R8** Global rules apply (immutability, small files, early returns, boundary validation). TDD with high coverage for policy engine + chain/proof code; pragmatic elsewhere.
- **R9 Non-goals stay non-goals:** no own payment rail, no KYC stack, no CAPTCHA evasion, no token, no evals, no memory infra.
- **R10** `key_provenance` + version fields in every credential/entry schema.

## Repo map

| Path | License | What |
|---|---|---|
| `packages/spec` | Apache-2.0 | **Frozen contracts**: mandate + ledger-entry schemas (TypeBox), canonical JSON, hash rules |
| `packages/policy-engine` | Apache-2.0 | Cedar-shaped evaluation interface; S0 ships an allow-all `UnconfiguredPolicyEngine` stub |
| `packages/verifier` | Apache-2.0 | Pure `verifyChain` — portable (WebCrypto only), embeddable by parties who distrust us |
| `packages/ledger` | AGPL-3.0-only | Append-only SQLite store (`node:sqlite`), hash chain, Ed25519 door signing, spend + revocation projections |
| `packages/vault` | AGPL-3.0-only | Credential door: OS-keychain-backed encrypted store (`@napi-rs/keyring`), PoP scoped tokens, IETF status-list revocation |
| `packages/gateway` | AGPL-3.0-only | Fastify LLM proxy door: auth → kill check → policy → intent entry → forward → result entry; mounts the card rail |
| `packages/card-rail` | AGPL-3.0-only | Stripe Issuing door: mandate-checked virtual cards, real-time authorization webhook → approve/decline at the network |
| `packages/witness-protocol` | Apache-2.0 | Witness wire protocol: salted head submissions, signed acks, door-side client, `Anchor` interface (OpenTimestamps), integrity-certificate build/verify |
| `packages/witness` | AGPL-3.0-only | Reference witness server: per-source witnessed head history (consistency-enforced), aggregate Merkle tree, public anchoring, static key-directory/status-list hosting |
| `packages/sdk` | Apache-2.0 | TS SDK: signed fetch (token PoP + passport RFC 9421) for existing Anthropic/OpenAI SDKs |
| `packages/sdk-py` | Apache-2.0 | Zero-dep Python client (token mode; NOT a pnpm workspace member — no package.json) |
| `packages/mcp-server` | AGPL-3.0-only | MCP stdio server adapting the CLI (verify/budgets/issuance/kill); `server.json` prepared, unpublished |
| `apps/cli` | AGPL-3.0-only | `mandare` binary (`verify [--witness]`, `certify`, `witness serve`, `kill`, `reinstate`, `token`, `vault`) |
| `apps/dashboard` | AGPL-3.0-only | Next.js fleet view over the ledger (read-only SQLite + CLI shell for verify/kill); zero telemetry |
| `apps/docs` | AGPL-3.0-only | Fumadocs site (quickstart/concepts/threat-model/reference) → mandare.dev |
| `integrations/openclaw` | Apache-2.0 | Native AgentSkills skill + `clawhub.skill.verify.v1` trust envelope (packaged by scripts, unpublished) |
| `compose.yaml` + `Dockerfile` + `docker/` | — | Self-host stack: gateway + witness + dashboard + mock provider (dry-run needs no secrets) |
| `scripts/` | — | license-boundary gate, smoke E2Es (stack/skill/sdk-py/docs-install), demos, Claude hooks |

**License import direction (enforced by `scripts/check-license-boundaries.mjs`
+ turbo boundaries):** Apache packages may NEVER depend on AGPL packages.
AGPL→Apache is fine. Shared utils go in `packages/spec`. See LICENSING.md.

## Commands

```bash
pnpm build / typecheck / lint / test   # turbo across the workspace
pnpm red-team                          # tamper suite only (packages/ledger)
pnpm smoke                             # walking-skeleton E2E vs mock provider
pnpm demo:witness                      # Demo 5: the rewrite that can't hide (S6)
pnpm stack-smoke                       # compose topology WITHOUT docker (entry scripts E2E)
pnpm skill-smoke                       # OpenClaw skill commands E2E + trust envelope
pnpm sdk-py-smoke                      # Python client ↔ real token-auth door
pnpm docs-install-smoke                # fresh-copy install + Demo 1 from public docs (~4 min)
pnpm pack-install-smoke                # npm publish set packed + installed alone; CLI help + MCP tools/list
node scripts/check-license-boundaries.mjs
```

## Conventions

- ESM everywhere, TS strict + `exactOptionalPropertyTypes`; NodeNext modules
  (relative imports need `.js` extensions).
- Schemas: TypeBox (JSON Schema + static types from one source). Validate at
  every boundary (`parseLedgerEntry`, `parseMandate`, Fastify route schemas).
- **Money: integer MICRO-units** (1 unit = 1_000_000 micros;
  `CURRENCY_MICROS_PER_UNIT`). Never floats, never cents.
- Hashes: lowercase sha256 hex. Signatures: Ed25519, base64url. Timestamps:
  ISO-8601 UTC with `Z` only.
- Errors: fail closed on anything touching spend or the ledger; loud, typed
  failures (`VerifyFailureCode`, `SchemaValidationError`).
- No new dependencies with install scripts without a TASKS.md note. pnpm 10
  keeps scripts off; `minimumReleaseAge` cooldown is set in pnpm-workspace.yaml.
- Conventional commits (`feat:`/`fix:`/`test:`/`chore:`…).

## Plan-mode triggers

Required for: any change to `packages/spec` (schema freeze) · payment-rail
integrations (Stripe webhook flow) · anything reshaping the repo layout.

## Session roadmap (S0–S7 done ⇒ next: S8)

S1 ledger core hardening ✓ → S2 gateway+budgets (Demo: runaway loop dies at €20) ✓
→ S3 vault+kill switch (Demo: stolen token is dead paper) ✓ → S4
mandates+approvals (SD-JWT transport, passport identity, CIBA push) ✓ → S5 card
rail (Demo: the card declines at the network) ✓ → S6 witness+anchoring
(publishes the S3 revocation status list; closes the truncation boundary) ✓ →
S7 packaging (MCP server, OpenClaw skill, SDKs, compose self-host, dashboard,
docs site, clean-machine install smoke) ✓ → S8 parallel security/contract
review → S9 launch prep (publish npm/MCP/ClawHub, public flip). NOTHING is
published to any registry before S9.
