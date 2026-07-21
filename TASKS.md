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

## S1 — Ledger core deepening (2026-07-21)

**Scope (per S0 handoff):** RFC 6962 proofs · 10k append bench · key
directory (closes H1) · rollback/replay + multi-door red-team ·
Postgres team mode · CI action bumps.

**Status: complete.** All exit criteria met: everything test-proven,
red-team green on SQLite AND Postgres, bench recorded, CI green on origin,
Code Reviewer pass done.

### Done

- `packages/verifier` + `merkle.ts`: hand-rolled RFC 6962 tree over entry
  hashes (leaf i = raw 32 bytes of seq i+1's `entry_hash`): `computeTreeHead`,
  inclusion + consistency proof generation AND verification (CT-style
  decomposition), pinned to the official reference vectors
  (transparency-dev/merkle roots + inclusion + consistency vectors) plus a
  full property sweep (every proof at every size ≤33, tamper mutations).
- `packages/verifier` + `directory.ts`: ONE key-directory format (SPEC §4):
  JWK Set profiled per RFC 9421 / Web-Bot-Auth
  `/.well-known/http-message-signatures-directory` — door keys now, agent
  passport keys in S4, same scheme. Per-key `nbf`/`exp` windows make
  rotation enforceable. `verifyChain` accepts `doorPublicKey` OR
  `keyDirectory`; new failure codes `KEY_UNKNOWN`, `KEY_EXPIRED`. Design
  doc: `docs/KEY-DIRECTORY.md`.
- `apps/cli`: `verify` now prints the RFC 6962 tree head, takes
  `--key-directory <path|url>` (H1 closed: real out-of-band source),
  `--prev-head <size>:<root>` (rollback + rewrite detection via consistency
  proofs), `--prove <seq>` (inclusion proof for selective disclosure).
  New `mandare directory` command builds the JWKS from door PEMs
  (public material only).
- `packages/ledger` driver split (Q7): pure `buildEntry` shared by all
  drivers; `LedgerStore` interface; `SqliteStore` (+ unchanged sync
  `Ledger` facade — S0 API stable, gateway untouched); `PgStore` +
  `AsyncLedger` for team mode. Postgres enforcement is two-layer:
  `provisionPgLedger` (admin, once) creates schema + `BEFORE UPDATE OR
  DELETE … RAISE EXCEPTION` triggers + INSERT-only grants for the app role;
  seq allocation via `pg_advisory_xact_lock`. Concurrency test proves no
  seq races.
- Red-team: SQLite suite grew rollback-to-older-copy (incl. the strongest
  form: real-door-key fork after restore — every signature valid, caught
  only by the recorded-head consistency proof), truncation-vs-recorded-head,
  cross-door directory verification, stolen-rotated-key (`KEY_EXPIRED`).
  New `tamper-pg.test.ts`: full PG suite (grants layer, trigger layer,
  superuser-bypass tampering caught by verification) on embedded
  Postgres 17 — runs identically locally and in CI, no Docker. S0 floor
  untouched and green (only the three `test.todo` scaffolds were replaced,
  as scoped; one S6 witness-service todo remains).
- **Bench (10k entries, Apple Silicon M-series, macOS, Node 24.9)**:
  sign-only (native Ed25519) **~37–38k ops/s** · buildEntry
  (canonicalize + sha256 + sign + validate) **~25k ops/s** · durable
  `Ledger.append` (WAL, synchronous=FULL ⇒ fsync/entry) **~10.5k ops/s**.
  Q1's "tens of thousands via native signing" confirmed; the append gap is
  the deliberate price of R3 durability, not crypto.
  Reproduce: `pnpm --filter @mandarelabs/ledger bench`.
- CI: checkout/setup-node/pnpm-action bumped to v7/v7/v6 (Node-24 majors)
  in ci.yml + release.yml.

### Decisions (S1 latitude; BUILD-DECISIONS untouched except one deviation)

1. **DEVIATION from Q5's letter (same spirit):** inclusion proofs are
   hand-rolled too, not @openzeppelin/merkle-tree. OZ's SimpleMerkleTree
   builds a balanced heap-array tree with commutative (sorted-pair) node
   hashing — structurally incompatible with RFC 6962's
   split-at-largest-power-of-two shape, so OZ inclusion proofs can never
   share a root with RFC 6962 consistency proofs. One tree, one head, both
   proof types hand-rolled against the official vectors (~40 extra lines).
2. New verifier surface is additive: `packages/spec` untouched (frozen floor
   trivially intact). Key-directory parsing lives in the verifier (portable,
   Apache, embeddable by distrusting parties), not spec — gateway imports it
   in S4 via the existing AGPL→Apache direction.
3. Directory profile: keys matched by derived `key_id` (sha256 of raw pub
   key from `x`) — no Mandare-specific id member needed; `kid` = RFC 7638
   thumbprint; `nbf`/`exp` NumericDate per Web-Bot-Auth draft; `mnd:role`
   private-use member. Non-Ed25519 JWKS entries are skipped (must-ignore),
   structural garbage throws (R4).
4. Writer stays one-door-per-DB; multi-door/rotation is a VERIFICATION
   concern in S1 (directory resolves per-entry keys). Multi-key writing
   waits for S3 keychain.
5. Sync `Ledger` kept as the SQLite facade (S0 API frozen for the gateway);
   `AsyncLedger` is the driver-generic path — S2 should migrate the gateway
   to it (or keep sync; decide when budgets land).
6. Dev-only exception to the no-install-scripts posture: `embedded-postgres`
   platform binaries (postinstall = dylib symlink fixup), allowlisted
   explicitly in `pnpm-workspace.yaml` `onlyBuiltDependencies`, exact-pinned
   (17.10.0-beta.17 = PG 17.10; the project's only release channel is
   prerelease-tagged). Runtime deps gained only `pg` (pure JS).
7. Consistency-vs-recorded-head semantics in CLI: size shrank ⇒ ROLLBACK;
   same size, different root ⇒ INCONSISTENT; grown ⇒ consistency proof must
   verify, else INCONSISTENT — all exit 1. Recorded heads are the local
   stand-in for the S6 witness.

### Review pass (Code Reviewer subagent, full S1 diff)

1 HIGH + 3 MEDIUM + 4 LOW; merkle math, keyId derivation (spoof-proof),
SQL-injection surfaces, and private-key handling explicitly confirmed clean.
Fixed same-session:

- **(H1)** KEY_EXPIRED bypass: schema regex admits non-calendar timestamps
  (`2026-13-01…`), `Date.parse` → NaN, NaN comparisons all false ⇒ validity
  windows silently skipped — fail-open. Fixed: unparseable ts now fails
  closed (KEY_EXPIRED) in directory mode; red-team case added.
- **(M1)** `verifyConsistency` with `size1=0` ignored `root1`; now requires
  the true empty-tree root.
- **(M2)** duplicate keys in a directory could silently widen a validity
  window (last-entry-wins map); `parseKeyDirectory` now rejects duplicates.
- **(M3)** `--prev-head` size now bounded to the 2^31−1 tree-size domain.
- **(L2)** `AsyncLedger.open` closes the store on rejected opens (pg pool
  leak on wrong-door-key retries).
- L1 (pg `seq::int` hard stop at 2^31 — fail-closed, accepted), L3
  (directory command leaks no private material — verified), L4 (harmless
  duplication) — no action, recorded here.

### Known debt (intentional, scheduled)

- Witness service + off-machine head recording: S6 (one red-team todo left).
- `ts` backdating into a rotated key's window bounded only by witnessing
  (documented in docs/KEY-DIRECTORY.md threat table).
- Gateway still on sync `Ledger`; migrate (or affirm) in S2.
- Directory serving (`/.well-known/...` hosting + content-type) is tooling
  output only; no server yet (S4 with passports).

---

## → S2 handoff (gateway + budgets)

Read BUILD-SESSION-PLAN S2 + BUILD-DECISIONS Q14 (authoritative provider
`usage.cost`) and the policy-engine stub notes. Demo target: **a runaway agent loop dies
at €20** — that demo is the acceptance test (R7).

Inherit from S1:

1. Real policy engine replaces `UnconfiguredPolicyEngine` (Cedar-shaped
   interface already in place): mandate spend scopes → pre-call budget
   check (estimate) → post-call true-up from provider `usage.cost`
   (OpenRouter authoritative, Q14). Micros only.
2. Budget state needs a persistent counter surface — decide: derive spend
   from the ledger itself (sum result entries per mandate; slower, zero new
   state) vs. a cache table (Redis optional per SPEC §11). Deriving from
   the ledger is the honest default; benchmark first (10k-entry scan cost).
3. Streaming responses were rejected in S0 until true-up exists — S2 is
   where true-up lands; revisit streaming.
4. Gateway ledger choice: stay on sync `Ledger` or move to
   `AsyncLedger` + store (PG-ready doors). If team mode should work E2E in
   S2, migrate now; the driver parity tests make it low-risk.
5. `mandare verify` is proof-complete for S2 demos: record head → run the
   runaway loop → verify --prev-head shows append-only growth; use it in
   the demo script.
6. Red-team floor now includes tamper-pg.test.ts — keep both drivers green;
   CI runs them in the red-team job unchanged (`pnpm red-team`).

**From the founder (nothing blocking, two decisions when convenient):**
- S2's budget-counter choice above (ledger-derived vs cache) if you have a
  preference; otherwise the session decides and logs it.
- An OpenRouter API key with a few € of credit for an OPTIONAL live smoke
  against the real provider (all CI stays mock/no-secrets regardless).

## → S1 handoff — ORIGINAL (superseded, kept for the record)

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
