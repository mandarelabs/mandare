# TASKS — Mandare build log

Every session: read this first, update it last. Format per entry: scope ·
done · decisions (with reasons) · deviations · handoff.

---

## S0 — Scaffold + walking skeleton (2026-07-21)

**Scope:** monorepo init, licensing layout, CI skeleton, CLAUDE.md hierarchy,
`packages/spec` schemas, walking skeleton (gateway → ledger → `mandare verify`).

**Status: complete.** All exit criteria met: CI-equivalent checks green
locally (build/typecheck/lint/test/red-team/smoke), schemas typed AND
review-passed, walking skeleton runs end-to-end against a mock provider with
no secrets.

### Done

- pnpm 10 + Turborepo monorepo; TS strict/ESM/NodeNext; Vitest; ESLint 9 flat.
- Grafana-pattern licensing: root AGPL-3.0-only; Apache-2.0 for
  `spec`/`policy-engine`/`verifier` (per-package LICENSE + NOTICE);
  LICENSING.md; import direction enforced twice (turbo boundaries tags +
  `scripts/check-license-boundaries.mjs`), both negative-tested.
- `packages/spec`: MandateV1 + LedgerEntryV1 (TypeBox), canonical JSON
  (JCS-style, hand-rolled), sha256 sync (node) + async (WebCrypto, portable)
  asserted byte-identical, boundary parsers. 33 tests.
- `packages/ledger`: node:sqlite append-only store (WAL + synchronous=FULL +
  busy_timeout), UPDATE/DELETE triggers, BEGIN IMMEDIATE seq allocation,
  Ed25519 door key (PEM 0600, keychain TODO S3). Red-team suite: edit /
  delete / gap / replay / lazy-forge / competent-forge(key-swap) all
  caught; truncation documented as local boundary (S6 closes).
- `packages/verifier`: pure WebCrypto `verifyChain`, 8 failure codes, tests
  build chains independently of the ledger implementation.
- `packages/policy-engine`: Cedar-shaped interface + loud
  `UnconfiguredPolicyEngine` stub (real engine = S2).
- `packages/gateway`: Fastify v5 walking skeleton, OpenRouter non-streaming;
  flow: validate → policy (throw ⇒ deny) → intent entry → forward → result
  entry (fail ⇒ HALT). Fail-closed proven by tests (no key ⇒ 503 + zero
  writes; ledger down ⇒ 503; result-write failure ⇒ halt).
- `apps/cli`: `mandare verify --db [--door-key] [--json]`, exit codes 0/1/2.
- CI: ci.yml (node 22+24 matrix; typecheck/lint+license-gates/test/red-team/
  smoke jobs), release.yml stub (trusted-publishing TODOs, Q24), cla.yml
  (CLA Assistant Lite). `scripts/smoke.mjs` = clean-machine E2E incl. tamper
  detection. `.claude/settings.json` hooks (post-edit typecheck, Stop
  TASKS.md nudge). CLAUDE.md: root + 6 packages.
- Review pass (Code Reviewer subagent) on spec/ledger/verifier/gateway:
  1 HIGH + 3 MEDIUM + 1 LOW — all fixed same-session (see decisions 8–12).

### Decisions (S0 latitude; BUILD-DECISIONS untouched)

1. **TypeBox** for schemas (JSON Schema + static types, zero-dep; feeds
   Fastify/ajv validation directly).
2. **Money = integer MICRO-units** (1 unit = 1e6 micros), not cents — LLM
   per-call costs round to zero in cents. `CURRENCY_MICROS_PER_UNIT` in spec.
3. Intent/result pairing: `action.type` `llm.call.intent`/`llm.call.result`;
   result's `outcome_ref` = intent's `entry_hash`. `correction_of` also an
   entry-hash ref. `response_hash` optional (absent on intents).
4. Scopes discriminated on `type` (`spend`/`action`); allowlist counterparty
   mode requires non-empty `counterparty_allowlist` via schema union (other
   modes forbid the field).
5. Timestamps: ISO-8601 UTC `Z`-only, enforced by pattern (no ajv-formats dep).
6. Door key in 0600 PEM next to DB until S3 keychain; `key_provenance:
   'software'`. One door per ledger DB in S0 (multi-door = S1).
7. OpenRouter as S0 provider (Q14: authoritative `usage.cost`); streaming
   rejected until S2 true-up. Provider key from env until S3 vault.
8. **(review H1)** `meta.door_public_key` is a convenience anchor only —
   self-anchored verification proves consistency, NOT authorship (file-level
   attacker can re-sign under a swapped key; red-team test demonstrates it).
   CLI grew `--door-key` for out-of-band keys + a SELF-ANCHORED caveat line.
   S1's key directory + S6 witnessing are the real anchor.
9. **(review M1)** `PRAGMA synchronous = FULL` — WAL-default NORMAL could
   lose a committed intent on power loss, breaking log-before-act.
10. **(review M2)** Provider fetch failure ≠ "nothing executed": result entry
    records outcome-unknown (timeout may have billed); S2 true-up reconciles.
    Result-append failure in this path also halts.
11. **(review M4)** Canonicalization of hostile bodies (`1e400` → Infinity
    passes JSON.parse + ajv) now caught → 400, not unhandled 500.
12. Per-package `vitest` devDeps so `turbo boundaries` runs strict (it flags
    root-hoisted imports); `turbo boundaries` added to the lint gate.

### Deviations from BUILD-DECISIONS

None.

### Known debt (intentional, scheduled)

- Truncation/rollback invisible locally (S6 witnessing; red-team todos placed).
- `UnconfiguredPolicyEngine` allows everything, loudly (S2).
- Static actor/mandate identity from env (S3/S4).
- node:sqlite ExperimentalWarning noise (accepted, Q7; better-sqlite3 is the
  documented fallback if RC gaps bite).
- ~~CI workflows written but unverified against live GitHub runners until first push.~~
  Verified 2026-07-21: run 29832935883 all 4 jobs green (red-team 27s, node 22
  55s, node 24 51s, smoke 26s). Cosmetic: bump actions/checkout, setup-node,
  pnpm/action-setup to their Node-24 major versions in S1 (deprecation
  annotations for Node 20-targeting actions).

---

## → S1 handoff (ledger core)

Read BUILD-SESSION-PLAN S1 + BUILD-DECISIONS Q1/Q5/Q7. Inherit from S0:

1. **RFC 6962 consistency proofs** (hand-rolled ~150 lines + RFC test
   vectors, Q5) in `packages/verifier`; `@openzeppelin/merkle-tree`
   (SimpleMerkleTree, sha256) for inclusion proofs.
2. **10k-entry bench** of `Ledger.append` (Q1 expects native-sign throughput;
   signing, not SQLite, is the ceiling).
3. **Red-team todos**: rollback-to-older-copy and witnessed-head-truncation
   scaffolds exist in `test/red-team/tamper.test.ts`; multi-door/key-rotation
   todo too. Key directory design (S1) should give `mandare verify` its
   out-of-band `--door-key` source (decision 8).
4. **Postgres team mode** (Q7): INSERT-only grants + BEFORE UPDATE/DELETE
   RAISE triggers behind the same driver interface.
5. `mandare verify` extensions as proofs land (`--head`, consistency checks).
6. Keep the S0 red-team suite green untouched — it is the regression floor.

Working agreements that bind S1: entry-hash preimage and canonical JSON are
FROZEN (spec CLAUDE.md); door signs raw 32 bytes of entry_hash; genesis =
64 zeros; micros for money; hooks + TASKS.md protocol per root CLAUDE.md.
