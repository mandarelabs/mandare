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
- **(CI-caught, post-review)** `PgStore`'s pool had no `error` listener —
  per node-postgres semantics any idle-client drop (database restart under
  a live door) would CRASH the door process. Surfaced as 3 unhandled FATAL
  57P01s in the CI red-team teardown (mac timing hid it locally). Pool now
  logs and survives; teardown settles sockets before server stop. A good
  argument for keeping the red-team suite on a second OS.

### Known debt (intentional, scheduled)

- Witness service + off-machine head recording: S6 (one red-team todo left).
- `ts` backdating into a rotated key's window bounded only by witnessing
  (documented in docs/KEY-DIRECTORY.md threat table).
- Gateway still on sync `Ledger`; migrate (or affirm) in S2.
- Directory serving (`/.well-known/...` hosting + content-type) is tooling
  output only; no server yet (S4 with passports).

---

## S2 — Gateway + budgets (2026-07-21)

**Scope (per S1 handoff):** real policy engine (budgets/velocity, SPEC §5
order) replacing the allow-all stub · budget counters as a ledger projection
with reserve/settle · Anthropic + OpenAI adapters + streaming true-up
(OpenRouter mocked) · OpenRouter provisioning-key rail (mocked) · red-team
additions (budget race, hostile input, provider failures) · the recorded
demo (runaway loop dies at €20) as an acceptance test.

**Status: complete.** All exit criteria met: demo recorded + acceptance-
tested, red-team green (old + new) on both drivers, CI green on origin, Code
Reviewer pass done (findings fixed same session), live provider smoke passed
against real Anthropic + OpenAI. S0+S1 red-team floor untouched and green.

### Done

- **`packages/policy-engine`**: `MandatePolicyEngine` replaces the S0
  allow-all stub. Evaluates SPEC §5 order exactly (identity → mandate window
  → scope → budget → counterparty → approval threshold). `checkBudgets` is
  pure arithmetic, run pre-call by the engine AND again inside the ledger
  append transaction (same function, provably identical math). Fail-closed:
  `verified_only` counterparties deny until the registry exists;
  above-threshold approvals deny until the S4 push lands; non-calendar
  validity timestamps deny (S1 H1 lesson applied from day one); overlapping
  spend scopes deny as ambiguous (v0 never merges budgets). 35 tests.
- **`packages/ledger` spend projection** (`projection.ts` + `spend-ledger.ts`):
  the binding architecture — counters are a DERIVED PROJECTION of the ledger,
  never a second truth. `budget_counters` + `projection_meta` update in the
  SAME transaction as each append (`appendProjected`), rebuildable from the
  ledger alone, with `verifySpendProjection` enforcing replay(ledger) ==
  counters. INTENT entries RESERVE the estimate under the append lock; RESULT
  entries (via `outcome_ref`) release and settle true cost into the INTENT's
  day bucket (midnight cannot reopen a cap); `llm.call.denied` entries record
  refusals with zero counter effect. Stale projection (seq ≠ head) →
  `ProjectionStaleError`, callers fail closed. Both SQLite and Postgres
  drivers; `SqliteStore` serializes its transactions through an internal
  promise queue (node:sqlite is one connection, projected appends await
  between BEGIN and COMMIT).
- **`packages/gateway`**: full reserve→forward→settle flow. NATIVE provider
  surfaces (no lossy unified transform): `/v1/messages` (Anthropic, base URL
  WITHOUT /v1) and `/v1/chat/completions` (OpenAI/OpenRouter, base URL WITH
  /v1). Streaming passes through untouched while an SSE tee parses usage.
  True-up per Q16: OpenAI `stream_options.include_usage` final chunk;
  Anthropic `message_start` + final `message_delta` merge; OpenRouter
  `usage.cost` authoritative (Q14). Tokenizer-free estimation
  (`pricing.ts`) ONLY for pre-flight reservation and aborted streams.
  One ledger currency (default EUR); USD costs convert at the explicit
  operator-set `MANDARE_USD_PER_LEDGER_UNIT` (never an invented FX rate).
  `provisioning.ts`: OpenRouter per-agent capped keys (Q14, create/rotate/
  disable) — mock-tested, live deferred to the founder's account.
- **`apps/cli`**: `mandare verify --spend` renders the spend trail (INTENT
  reserve / RESULT settle / DENIED refusals) and re-derives counters from the
  ledger, comparing them against the stored projection — the user-facing
  replay(ledger) == counters check; stale/divergent exits 1.
- **Red-team additions** (all in CI via `pnpm red-team`): `budget-race`
  (N concurrent calls, cap provably never pierced — exact admission counts on
  SQLite AND Postgres), `hostile-input` (R4: meter-blinding, prototype
  poisoning, type confusion — forced `ajv coerceTypes: false`), `provider-
  failure` (hangs, garbage bodies, lying usage, mid-stream death — all fail
  closed, never 0-settle a real spend), and `projection-race` in the ledger
  (driver-level race + tamper-invariant on Postgres).
- **The demo** (`scripts/demo-runaway.mjs`, `pnpm demo`, CI job): a scripted
  runaway makes 71 calls under a €20/day mandate, call #72's reservation is
  refused, the refusal is a ledger entry, and `mandare verify --spend` proves
  chain VALID + counters == replay. The script ASSERTS all of it (R7).
  Terminal capture: `docs/demos/S2-runaway-demo.txt`.
- **Live provider smoke** (`scripts/live-smoke.mjs`, local only, never CI):
  real Haiku non-stream + stream + one OpenAI call under a €0.50 mandate.
  PASSED 2026-07-21 (Anthropic key + OpenAI key from `.env`; the true-up
  path settled real token costs, ledger verified). CI stays mock/no-secrets.
- Supporting: `scripts/dev-mandate.mjs` (Ed25519-signed dev mandates),
  updated `smoke.mjs` for the mandated gateway, `.env.example`, root
  CLAUDE.md "Publicity boundary" section, README/package-CLAUDE.md refresh.

### Decisions (S2 latitude; BUILD-DECISIONS untouched)

1. **Budget counters = ledger projection with reserve/settle** (the strategy
   frame, implemented as directed): pre-call check RESERVES the estimate;
   result SETTLES the true cost. Reservation runs inside the append
   transaction under the write lock, which kills the concurrent-overshoot
   race by construction — not statistically, structurally. Chosen over
   "derive spend by scanning the ledger each call" (the S1 honest default):
   the reservation semantics REQUIRE a running counter to reserve against,
   and a full-scan-per-call cannot hold an in-flight reservation.
2. **DENIED entries** (`llm.call.denied`): refusals are recorded on the
   ledger (with the refused estimate as `cost.amount`, zero counter effect)
   so `mandare verify` shows the no, not just the yeses. New action type,
   additive — `packages/spec` frozen contract untouched (action.type is an
   open string; the schema didn't change).
3. **One ledger currency + explicit USD rate.** Provider costs are USD;
   mandates are usually EUR. Rather than an implicit/invented FX rate (a
   silent spend error waiting to happen), the operator sets
   `MANDARE_USD_PER_LEDGER_UNIT` explicitly; absent it on a non-USD ledger,
   the spend path stays closed (R1). Mandate-currency ≠ ledger-currency also
   fails closed.
4. **Conservative settlement on unknown outcomes.** Provider fetch failure,
   body-read failure, or aborted stream → settle at the reserved estimate (or
   observed-token estimate), NEVER 0. "Outcome unknown" must not reopen the
   cap; a Storno correction reconciles later against provider billing.
   Provider 4xx/5xx (not billed) settle 0 and release the reservation.
5. **Native provider protocols, not a unified API.** Agents point their
   existing Anthropic/OpenAI SDK base URL at the gateway; we proxy the native
   wire shape and only inject the usage-accounting flags (Q16). Portkey's
   transforms weren't needed — the pass-through + usage-tee is smaller.
6. **coerceTypes OFF** at the Fastify/ajv boundary: `stream: "true"` must be
   a 400, not a silently-coerced boolean. The schema is a policy boundary
   (R4), proven by the hostile-input red-team.
7. **Anthropic base-URL convention excludes `/v1`** (matches the official
   SDK's `ANTHROPIC_BASE_URL`); the adapter path carries `/v1/messages`.
   OpenAI/OpenRouter base URLs include `/v1`. (Caught by the live smoke: an
   operator `ANTHROPIC_BASE_URL=https://api.anthropic.com` was resolving to
   `/messages` → 404. Regression test added.)

### Review pass (Code Reviewer subagent, full S2 diff)

1 HIGH + 3 MEDIUM + 3 LOW; reservation race, license direction, key leakage,
and 0-settle paths explicitly confirmed clean. Fixed same-session:

- **(HIGH)** a 200 whose body read failed mid-stream (timeout/reset after
  headers) left the intent unpaired and the gateway un-halted. Now settles
  conservatively at the reserved estimate; added a Fastify error handler so
  5xx bodies are generic (no raw exception text to callers, R2).
- **(MEDIUM)** double-settle guard was blind after a ZERO-cost settlement
  (provider errors settle 0). The intent marker now carries an explicit
  settled flag (`intents=1`); any second result for it is refused.
- **(MEDIUM)** tamper-evidence could be downgraded to "stale" (→ silent
  rebuild, evidence erased) by rewinding `projection_meta`.
  `verifySpendProjection` now diffs stored-vs-replay counters REGARDLESS of
  the seq; `start.ts` auto-rebuilds only on pure staleness.
- **(LOW)** streaming fetch gained a header-phase timeout (`AbortSignal.any`)
  so a socket-accepting/never-responding provider can't pin a reservation.
- **(LOW)** pg-store ROLLBACK wrapped so a dropped connection can't mask the
  causal error.
- **(MEDIUM, deferred to S3/S4 with a note — see handoff)** spend endpoints
  are unauthenticated; identity is the configured `MANDARE_ACTOR`, asserted
  not proven, and Host isn't validated (DNS-rebinding surface). Localhost
  default + budget-bounded damage make this acceptable for S2; real actor
  identity is explicitly S4 (passports), and a gateway bearer token + Host
  check is the smallest S3 hardening.
- **(LOW, accepted)** aborted-stream settlement counts only text deltas (not
  tool_use/thinking deltas) and the estimate ignores `tools` — both bounded
  by the output-ceiling-dominated estimate; noted for a later pass.

### Deviations from BUILD-DECISIONS

None. (OpenRouter live smoke deferred per the founder's mid-session update —
the adapter + provisioning rail are built and mock-tested; live OpenRouter
comes when the account exists.)

### Known debt (intentional, scheduled)

- Gateway spend endpoints unauthenticated; actor identity static/asserted
  (S4 passports; S3 can add a bearer token + Host check — see handoff).
- Provider credentials still from env (S3 vault).
- Aborted-stream token estimate ignores tool_use/thinking deltas and `tools`
  input (conservative-enough; later pass).
- OpenRouter rail live-untested until the founder's account exists.
- `mandare kill <agent>` stretch goal NOT done — full kill switch is S3.

---

## → S3 handoff (vault + kill switch)

Read BUILD-DECISIONS Q8 (keychain via @napi-rs/keyring), Q2/Q4 (SD-JWT for
S4 mandates — not S3), and this session's decisions above. Demo target for
S3: **a hijacked agent's credentials are un-hijackable + one command kills a
running agent's spend.**

Inherit from S2:

1. **Vault** replaces env-var provider keys (R2, Q8). Provider keys and the
   OpenRouter provisioning key move into the OS keychain (@napi-rs/keyring;
   `key_provenance` already in every schema). The gateway reads them from the
   vault at startup; nothing agent-reachable ever holds a raw key. The door
   key itself (currently 0600 PEM next to the DB) should move too.
2. **Kill switch** (`mandare kill <agent>`), the real one. S2 left the
   mechanism latent: a gateway-level disable is a policy-engine deny gate
   keyed by actor/mandate that flips WITHOUT a restart. Belt-and-suspenders
   with the OpenRouter rail: `OpenRouterProvisioningClient.disableKey` stops
   spend AT OpenRouter too (already built + mock-tested in
   `packages/gateway/src/provisioning.ts`). Kill must be: fail-closed,
   recorded as a ledger entry, and reversible only by an authorized
   out-of-band action.
3. **Gateway hardening the review flagged (small, do it here):** a
   `MANDARE_GATEWAY_TOKEN` bearer check on the two spend routes + a `Host`
   header allowlist (DNS-rebinding defense). Cheap, and it makes "which agent
   spent this" mean something before passports land in S4.
4. The reservation/settlement projection is the budget substrate the kill
   switch rides on — a killed agent's in-flight reservations should be
   released (or deliberately left to expire); decide and test.
5. Keep both red-team drivers green (`pnpm red-team` now includes the S2
   budget-race, hostile-input, provider-failure, and projection-race
   suites). Add: kill-switch race (a call in flight when the kill lands must
   not settle spend), and vault-miss (no key in the vault → spend path
   closed, same as S2's no-credential path).

**From the founder (one blocking-ish item, one optional):**
- **OpenRouter account + provisioning key** whenever convenient — unblocks
  the live OpenRouter smoke and the provisioning-rail demo (the code + mocked
  tests are done; only live verification waits). Read from `.env` only (R2).
- Confirm the S3 kill-switch UX: is `mandare kill <agent>` a local CLI
  command against the door, or does it also need the (S6) witness in the
  loop? S2 assumes local-CLI-against-the-door; flag if that's wrong.

---

## → S2 handoff (gateway + budgets) — ORIGINAL (superseded, kept for the record)

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
