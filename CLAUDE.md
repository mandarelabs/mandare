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
as if already public. Strategy/business content belongs in `~/projects/tessera`
(never committed here); future commercial/cloud service code belongs in a
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
| `packages/gateway` | AGPL-3.0-only | Fastify LLM proxy door: auth → kill check → policy → intent entry → forward → result entry |
| `apps/cli` | AGPL-3.0-only | `mandare` binary (`verify`, `kill`, `reinstate`, `token`, `vault`; later `export`) |
| `scripts/` | — | license-boundary gate, smoke E2E, Claude hooks |

**License import direction (enforced by `scripts/check-license-boundaries.mjs`
+ turbo boundaries):** Apache packages may NEVER depend on AGPL packages.
AGPL→Apache is fine. Shared utils go in `packages/spec`. See LICENSING.md.

## Commands

```bash
pnpm build / typecheck / lint / test   # turbo across the workspace
pnpm red-team                          # tamper suite only (packages/ledger)
pnpm smoke                             # walking-skeleton E2E vs mock provider
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

## Session roadmap (S0–S3 done ⇒ next: S4)

S1 ledger core hardening ✓ → S2 gateway+budgets (Demo: runaway loop dies at €20) ✓
→ S3 vault+kill switch (Demo: stolen token is dead paper) ✓ → S4
mandates+approvals (SD-JWT transport, passport identity, CIBA push) → S5 card
rail → S6 witness+anchoring (publishes the S3 revocation status list) → S7
packaging/MCP/skill → S8 review → S9 launch prep.
