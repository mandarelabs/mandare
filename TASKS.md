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
against real Anthropic + OpenAI + **OpenRouter** (the founder supplied the
OpenRouter key post-review; the runtime-call rail now settles from
OpenRouter's authoritative `usage.cost` live — 4-leg live smoke green). Only
the provisioning-KEY rail (creating per-agent capped keys) still awaits the
founder's provisioning key; the runtime rail is live-verified. S0+S1
red-team floor untouched and green.

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

## S3 — Vault + kill switch (2026-07-22)

**Scope (per S2 handoff + founder ruling):** `packages/vault` (OS-keychain
credential storage, credential injection, short-lived scoped tokens,
revocation status list, `mandare kill`) · gateway consumes vault credentials +
checks revocation per request · door-local auth for spend routes (S2's
deferred MEDIUM) · Demo 2 "stolen token is dead paper" as a CI acceptance test.

**Status: complete.** All exit criteria met: Demo 2 scripted + in CI; red-team
additions green on both drivers (token theft, replay, post-kill access,
keychain-unavailable fail-closed); Code Reviewer pass done (2 HIGH + 3 MEDIUM +
2 LOW, all fixed same session); full gate green (build/typecheck/lint/test/
red-team/smoke/demo/demo:dead-paper). S0–S2 red-team floor and Demo 1 untouched
and green.

### Done

- **`packages/vault`** (AGPL) — the credential door. A 32-byte MASTER KEY lives
  in the OS keychain (`@napi-rs/keyring`, Q8) and encrypts every secret in the
  vault SQLite DB (`crypto.ts`: AES-256-GCM, the account name as AAD so a
  DB-file attacker cannot move a provider-key ciphertext into the door-key
  slot). Holds provider keys, the OpenRouter provisioning key, the door signing
  key PEM, and the scoped-token registry. **Keychain-or-fail-closed** (R1):
  `MANDARE_VAULT_BACKEND=keychain` (default) + keychain unavailable ⇒
  `VaultKeychainUnavailableError`, never a silent plaintext fallback; headless/
  CI opt into `file` (0600 master-key file, enforced on read). `key_provenance`
  becomes `keychain`/`software` accordingly and flows into every ledger entry's
  `door_signature`.
- **Scoped tokens** (`tokens.ts`) — short-lived (≤30-min, SPEC ceiling)
  proof-of-possession tokens: a public id + a per-token HMAC secret `k`. Each
  request carries `HMAC(k, tokenId|method|path|timestamp|nonce)`. Verify order:
  known → not revoked → not expired → timestamp fresh (±120s) → PoP matches
  (constant-time) → nonce claimed (single-use, claimed only AFTER the PoP
  verifies so a bad-PoP probe can't burn a client's nonce). This is the S3
  precursor to S4's RFC 9421 request signatures.
- **Revocation as a ledger projection** (`packages/ledger/revocation.ts` +
  `revocation-ledger.ts`) — `agent.revoke` / `agent.reinstate` entries drive a
  subject-keyed `revocation_status` table, mirroring the S2 spend projection:
  `replay(ledger) == revocation_status` is the invariant. Status indices are
  assigned in ledger order (deterministic on rebuild). Shares the projection
  seq with the spend counters; spend and revoke entries are disjoint types, so
  the two projections stay mutually consistent under interleaving (proven).
  Both SQLite and Postgres drivers (grants + table added to `provisionPgLedger`).
- **ONE revocation vocabulary** — the IETF Token Status List / W3C Bitstring
  Status List (`@sd-jwt/jwt-status-list`, Q4). `vault/status-list.ts` renders
  the projection into the standard `status_list: {bits, lst}` payload S6 will
  publish unchanged; `revocation_ref = statuslist:<listId>#<index>` (already in
  the mandate schema). Enforcement never touches the bitstring — the gateway
  reads the subject-keyed table directly (fast, offline, dep-free).
- **`mandare kill <agent>` / `kill --all` / `reinstate`** (`apps/cli`) — the
  LOCAL, offline, un-jammable authority (founder ruling). Appends the revoke
  entry AND flips the projection in one `BEGIN IMMEDIATE` transaction, then
  tells the vault to stop honoring the actor's tokens (belt-and-suspenders).
  The door key is sourced exactly as the gateway sources it (vault in vault
  mode, legacy 0600 PEM otherwise), so kill is operable in either mode.
- **Gateway door-local auth + kill enforcement** (`server.ts`, `auth.ts`) — a
  Host-header allowlist (DNS-rebinding defense, localhost by default) always
  on; a per-request revocation check (agent + door subjects) via the ledger
  projection, run BEFORE token auth so a killed agent's refusal lands on the
  ledger as a DENIED entry even when its vault token is also revoked; then a
  proof-of-possession token check (required when a vault is wired; `authMode`
  = `auto`/`token`/`none`). Provider keys are sourced from the vault at
  startup (`MANDARE_VAULT=1`); nothing agent-reachable holds a raw key.
  Non-loopback bind without token auth refuses to start.
- **`mandare verify`** now renders the kill trail, the IETF status-list
  bitstring, and the `replay(ledger) == revocation` invariant (exits 1 on
  divergence). `mandare token issue` mints tokens; `mandare vault import-env` /
  `list` bootstrap and inspect the vault (names only, never values).
- **Demo 2** (`scripts/demo-dead-paper.mjs`, `pnpm demo:dead-paper`, CI job):
  real vault + real PoP signing end to end — legitimate call works; token id
  without the secret → BAD_POP; captured request replay → REPLAYED_NONCE;
  `mandare kill` mid-task → next valid call → 403 AGENT_REVOKED with the
  refusal on the ledger; `mandare verify` proves chain + spend + revocation ==
  replay. The script ASSERTS all of it (R7). Capture:
  `docs/demos/S3-dead-paper-demo.txt`.
- **Red-team additions** (CI via `pnpm red-team`): `vault/keychain-unavailable`
  (keychain backend + unavailable ⇒ fail closed, no plaintext fallback);
  `gateway/token-theft` (real vault: binding, replay, cross-actor, post-kill,
  vault-belt). Plus `ledger/revocation` + `gateway/auth-and-kill` unit suites.

### Decisions (S3 latitude; BUILD-DECISIONS untouched)

1. **Master key in the keychain, encrypted DB for everything else.** Keychains
   are awkward for many/short-lived items, so the keychain holds ONE
   high-value key and the vault DB stores every secret as AES-256-GCM
   ciphertext under it. Genuinely uses the keychain (Q8) and matches SPEC
   §3.1 "encrypted at rest; keys in OS keychain/KMS."
2. **Scoped tokens are proof-of-possession, not bearer.** "Dead paper" is a
   real property, not a slogan: a leaked token id can't be used without `k`
   (binding), a captured request can't be replayed (single-use nonce + skew),
   and TTL + kill close the rest. HMAC now, the passport's asymmetric key in
   S4 — the preimage is the deliberate precursor.
3. **Revocation = ledger projection, reusing the S2 pattern exactly.** The
   authoritative record is the `agent.revoke` ledger entry; the status table
   and the bitstring are both derived, so they can't drift and both carry the
   same tamper-evidence as the spend counters.
4. **Kill check runs BEFORE token auth** so the refusal is always recorded on
   the ledger (the demo/audit requirement), even though the kill also revokes
   the vault token. Bounded post-kill DENIED-flood via an in-memory throttle
   (≤1 recorded kill-refusal/sec) so a looping killed agent can't amplify
   fsync'd writes.
5. **Door key moved into the vault** (provenance `keychain`); the legacy 0600
   PEM path is retained so the frozen S0–S2 demos run unchanged.
6. **"If you have a vault, the door authenticates"** — `authMode: auto`
   requires a token iff a vault is wired, keeping Demo 1 (env keys, no vault)
   green while making real deployments authenticated by default.

### Deviations from BUILD-DECISIONS

None. (`@sd-jwt/jwt-status-list` is the Q4-decided library; `@napi-rs/keyring`
the Q8 one. Both ship prebuilt platform binaries — no install scripts, so the
supply-chain posture is unchanged; `@sd-jwt/jwt-status-list@0.19.0` carries a
deprecation notice but is the cooldown-eligible version and API-stable for our
use.)

### Review pass (Code Reviewer subagent, full S3 diff)

2 HIGH + 3 MEDIUM + 2 LOW. Core crypto (GCM/AAD/IV, constant-time PoP),
projector type-widening, projection integrity (`replay == projection`, shared
seq), fail-closed paths, concurrency, and R2 secret-handling explicitly
confirmed clean. Fixed same-session:

- **(HIGH-1)** PoP preimage does not cover the request body — an agent→door
  interceptor could swap the body under a valid proof. Loopback-mitigated
  (needs privileged local interception); the docstring's "binding" claim was
  corrected to POSSESSION+REPLAY and the body-digest scoped to S4 (RFC 9421
  Content-Digest), which is where the asymmetric agent key lands anyway.
- **(HIGH-2)** `mandare kill` was inoperable when the gateway ran in LEGACY
  mode: the CLI always took the door key from the vault, the gateway from a
  PEM ⇒ key mismatch ⇒ append refused. `openDoorContext` now resolves the key
  exactly as the gateway does (vault vs PEM); legacy-mode kill test added.
- **(MEDIUM-3)** nonce retention (125s) was shorter than the worst-case replay
  horizon (up to 240s), latent until pruning was wired. Retention → 2×skew;
  opportunistic prune (every 256 verifies) wired so the nonce table stays
  bounded AND replay-safe.
- **(MEDIUM-4)** post-kill DENIED entries were appended pre-auth and
  unthrottled — a looping killed agent could flood the append-only ledger.
  Now coalesced to ≤1 recorded kill-refusal/sec.
- **(MEDIUM-5)** the file-backend master key was read without checking its
  permissions. Now fails closed on anything looser than 0600 (POSIX); test
  added.
- **(LOW-6)** keychain "absent vs unavailable" was decided by error-message
  substring — fragile, could silently re-key. The real keyring returns `null`
  for absent and throws only on unavailability, so ANY throw is now fail-closed.
- **(LOW-7)** `0.0.0.0` removed from the Host allowlist defaults; a non-loopback
  bind without token auth now refuses to start.

### Known debt (intentional, scheduled)

- PoP does not bind the request body — S4 adds an RFC 9421 Content-Digest with
  the passport's asymmetric agent key (loopback-mitigated until then).
- The OpenRouter provisioning `disableKey` belt is not wired into `mandare
  kill` yet — it needs a per-agent key-hash mapping and the founder's
  provisioning key. The LOCAL authority (ledger revoke + vault token revoke) is
  complete without it.
- Nonce pruning is opportunistic (every 256 verifies); fine for a local door.
- Actor identity is still the static `config.actor`; a valid token proves an
  authorized HOLDER, not WHO — S4 passports.
- S6 will PUBLISH the status list unchanged and add a remote kill-trigger /
  fleet-fan-out channel — never the authority, never a dependency.

---

## S4 — Mandates + approvals + passport v1 (2026-07-22)

**Scope (per S3 handoff + founder rulings):** `packages/passport` (did:key v1,
owner→agent delegation credential as SD-JWT VC, mock IDV + local attestation
authority, mandate SD-JWT VC transport) · RFC 9421 request signatures via
web-bot-auth incl. Content-Digest (closes S3 HIGH-1) · gateway passport auth +
mandate revocation (reuse S3's status-list vocabulary) · CIBA-style async
approvals (ntfy default, pluggable) · Demo 3 "one signed mandate replaces 40
prompts" as a CI acceptance test · red-team additions · vault import-env + thin
.env.

**Status: complete.** All exit criteria met: Demo 3 scripted + captured +
in CI; red-team additions green on both drivers; full gate green
(build/typecheck/lint+license/test/red-team/smoke/demo×3); Code Reviewer pass
done (findings below). S0–S3 red-team floor and Demos 1–2 frozen and green.
Test totals: 466 unit/integration + all red-team suites.

### Done

- **`packages/passport`** (Apache-2.0, the new WHO layer) — offline-verifiable,
  embeddable like the verifier:
  - **did:key v1** (`did-key.ts` + hand-rolled `base58.ts`): Ed25519 only,
    multibase base58btc + multicodec `0xed01`, for `principal` and `agent`.
    Pinned to a published W3C did:key vector; rejects non-Ed25519 multicodecs
    (secp256k1 same-shape forgery caught), non-base58btc, wrong length. No
    resolver, no network (founder ruling 1).
  - **SD-JWT VCs** (Q2, `@sd-jwt/core` + `@sd-jwt/sd-jwt-vc`): all issuers are
    did:key, so verification is fully offline — the issuer key is derived from
    `iss`. Owner attestation (`attestation.ts`), agent delegation credential
    (`delegation.ts`, chain: authority → owner-attestation → owner-signed
    credential binding the agent's `cnf` key), mandate transport
    (`mandate-vc.ts`). Deliberately NOT using the SD-JWT `status` fetch —
    revocation enforcement reads the ledger projection (S3 rule); credentials
    carry `revocation_ref` in the shared vocabulary.
  - **Mock IDV** (`idv.ts`, founder ruling 2): `IdvProvider` interface +
    `MockIdvProvider`; attestation record is ONLY `{kyc_level, partner_id,
    date, ref_hash}` — no PII anywhere (that IS the production shape; real IDV
    is a config swap). Local attestation authority = self-contained key.
  - **RFC 9421 request signatures** (Q3, `request-signature.ts`,
    Cloudflare `web-bot-auth`): agents sign every request under the passport's
    asymmetric key over `@method/@path/@authority/content-digest/
    signature-agent`. Content-Digest (RFC 9530) over exact body bytes closes
    S3's HIGH-1 (body-swap). Verifier REQUIRES all five components (web-bot-auth
    accepts whatever Signature-Input declares; we don't), enforces keyid ==
    passport cnf key, bounded created/expires window, single-use nonce claimed
    LAST (a bad probe can't burn a client's nonce — the S3 lesson carried
    over).
- **Mandate SD-JWT VC** keeps the FROZEN `MandateV1` JSON self-contained: the
  detached owner signature inside the payload still verifies standalone; the
  SD-JWT envelope adds standards-world transport, not a replacement. Both
  signatures are the same owner key. `billing_identity` carried through
  (dormant). `packages/spec` untouched (R6).
- **`packages/gateway`**: new `authMode: 'passport'` — verify the delegation
  chain offline against `MANDARE_TRUST_AUTHORITY`, then the RFC 9421 signature
  with the cnf key over the EXACT raw body (a passport-mode content-type parser
  keeps the raw buffer in a WeakMap for the digest check); the verified actor
  DID flows into every ledger entry and the policy identity check (WHO, not a
  configured holder). Mandate revocation: `mandateSubject(mandate.id)` added to
  the per-request revocation check in ALL modes; `MANDATE_REVOKED` refusal
  recorded. Legacy token/none modes and Demos 1–2 unchanged (kill-before-auth
  ordering preserved).
- **CIBA approvals** (`approvals.ts` + gateway hold flow, Q10/Q19): over-
  threshold ⇒ `approval.requested` entry (log-before-act) → push via a
  pluggable `Notifier` (`NtfyNotifier` with HTTP action buttons /
  `FileNotifier` for CI) → the held HTTP request awaits → `POST /approvals/:id`
  with a single-use 256-bit capability token (sha256-hashed at rest,
  `timingSafeEqual`, one per Approve/Deny button) → `approval.granted`/
  `denied`/`expired` entry BEFORE the call resumes or is refused → policy
  re-evaluated with `context.approvedEntryHash` (waives ONLY the threshold,
  re-checks window/budget/velocity since time passed). Every exit fail-closed:
  no channel, failed push, failed entry, timeout → deny. Human decisions are
  attributed to the mandate principal (the accountable human).
- **`packages/policy-engine`**: `SpendEvaluationContext.approvedEntryHash`
  (optional, validated 64-hex at the R4 boundary; garbage ⇒ CONTEXT_INVALID,
  not a bypass); presence waives the approval-threshold rule for that one
  evaluation. The old flat `APPROVAL_REQUIRED` deny is now the gateway's
  hold-and-push trigger.
- **`packages/ledger`**: `subject.register` revocation entry — allocates a
  subject's status-list index at ISSUANCE (so a credential/mandate carries its
  `revocation_ref` from birth) and NEVER changes existing state (re-register of
  a revoked subject is not a reinstate — tested). Approval entry-type constants.
  Both drivers; the spend and revocation projections both ignore approval/
  register entries (no counter/status drift).
- **`apps/cli`**: `mandare passport issue` (owner + local authority keys as JWK
  pairs in the vault, mock IDV, fresh agent did:key, registered revocation
  slot, agent private key written 0600 once), `mandare mandate issue` (owner-
  signed SD-JWT VC, own revocation slot, dormant billing_identity supported),
  `mandare kill --mandate <id>` (the permission slip dies, the agent survives).
  `mandare verify` renders the approval trail (HELD → APPROVED/DENIED/PENDING
  by whom) and registered subjects. `loadMandate` FULL-verifies an SD-JWT VC
  file (envelope + schema + detached sig) and still accepts legacy JSON for the
  frozen demos.
- **`packages/vault`**: `getIdentityKey`/`putIdentityKey` (owner/authority JWK
  pairs), `claimSignatureNonce` (persistent single-use nonce table for RFC 9421
  — a door restart can't reopen a replay window; in-memory default for tests).
- **Demo 3** (`scripts/demo-mandate.mjs`, `pnpm demo:mandate`, CI job): a
  passport-carrying agent runs 6 in-scope steps under one mandate with ZERO
  prompts; step 7 (~€0.28, over the €0.25 threshold) pauses → file push →
  human APPROVE → continues; step 8 → human DENY → refusal on the ledger;
  `mandare verify --spend` proves chain VALID, counters == replay, and both
  human decisions in the approval trail. Every call RFC-9421-signed. ASSERTS
  everything (R7). Capture: `docs/demos/S4-mandate-demo.txt`.
- **Red-team additions** (`gateway/test/red-team/mandate-and-approval.test.ts`,
  in `pnpm red-team`): forged mandate signature (tampered VC won't load),
  expired mandate (envelope exp + per-request window), scope escalation (agent
  A's valid passport can't spend under B's mandate → IDENTITY_MISMATCH,
  attributed to A's verified DID), delegation-chain break (rogue authority →
  PASSPORT_INVALID), signature replay + body-swap at the door (REPLAYED_NONCE,
  BODY_DIGEST_MISMATCH), tampered/replayed approval (forged token can't decide,
  used token can't re-approve or approve a second call). Passport package has
  its own tamper suite (forged claims, wrong owner, untrusted authority,
  expired/not-yet-valid).
- **Vault bootstrap**: ran `mandare vault import-env` (keychain backend) — all
  four provider/management keys now live in the OS-keychain-backed vault
  (`./mandare-vault.db`, gitignored) — and thinned `.env` to bootstrap-only
  (no live secret values remain), per S3's design intent (R2).

### Decisions (S4 latitude; BUILD-DECISIONS untouched)

1. **One revocation vocabulary, three namespaces.** `subject.register` +
   `mandateSubject`/`agentSubject`/`doorSubject` reuse S3's status-list
   projection exactly — no second revocation machinery (founder ruling; Q4).
   Mandate kill flips a slot; agent/door kill flip theirs; all render into the
   same IETF bitstring S6 publishes.
2. **Mandate VC is transport, the detached signature is truth.** The frozen
   `MandateV1` stays self-verifying (detached Ed25519 over canonical JSON); the
   SD-JWT envelope wraps it for the OAuth/standards world. Two signatures, one
   owner key — no schema change (R6), and the S0-frozen mandate contract is
   intact.
3. **Approval decision = single-use capability token, not agent auth.** The
   HUMAN decides via a token minted into the push (hashed at rest, constant-
   time, one per button, dead after first use / timeout). Agent passports/
   tokens play no role at `/approvals` — the accountable human's click is the
   authority, recorded as a principal-attributed ledger entry.
4. **Approval waiver is per-evaluation and threshold-only.** A recorded
   `approval.granted` hash waives ONLY the threshold rule; the gateway re-runs
   the FULL SPEC §5 order afterward (window/budget/velocity may have moved
   while the call was held). The waiver field is validated at the R4 boundary.
5. **Passport mode parses its own JSON body** to keep the exact bytes for the
   Content-Digest check (Fastify's default parser discards them). Schema
   validation still applies to the parsed object; a non-JSON body is a 400.
6. **did:web documented as the future org profile** (maps onto the S1 key
   directory), out of scope now (founder ruling 1). did:key v1 is the whole
   identity surface for solo mode.

### Deviations from BUILD-DECISIONS

None. (`web-bot-auth` 0.1.3 is the Q3-decided library — unaudited, in our audit
scope per Q3; used only for the RFC 9421 sign/verify plumbing, with our own
required-component + window + nonce + digest enforcement layered on top.
`@sd-jwt/core`/`sd-jwt-vc` 0.20.0 are the Q2 libraries.)

### Review pass (Code Reviewer subagent, full S4 diff)

No CRITICAL. 2 HIGH + 3 MEDIUM + LOWs. Core crypto explicitly confirmed clean:
base58/did:key codec (zero-byte convention, multicodec+length pin), SD-JWT
algorithm-confusion neutralized (verifier always runs Ed25519 against the key
derived from `iss`; `alg:none` can't pass; `iat`/`nbf`/`exp` enforced),
detached-mandate preimage symmetry, Content-Digest over exact raw bytes,
approval token handling (unconditional `timingSafeEqual`, single-use,
decide-vs-timeout race safe), ledger-before-act ordering, R2, and the license
boundary. Fixed same-session with regression/red-team tests:

- **(HIGH-1)** RFC 9421 coverage bypass: `coveredComponents` regex-scraped
  quoted strings, so an inner-list member with DECOY PARAMETERS
  (`("@method";a="@path";b="content-digest")`) passed the required-component
  check while the signature actually covered only `@method` — silently
  reopening the body-binding gap. Now parses the inner list structurally and
  REFUSES any parameter inside it (we never sign parametrized components);
  red-team case added.
- **(HIGH-2)** A kill (agent/mandate/door) landing WHILE a call was HELD for
  approval was not re-checked on resume — an approve after the kill would
  spend. `revocationRefusal(actor)` now re-runs before the resumed call
  executes; "revoked instantly" holds even across a long approval window.
  Red-team case (kill-during-hold) added.
- **(MEDIUM-1)** The verified delegation chain wasn't bound to the mandate:
  any owner the authority ever attested could name the agent's key. Passport
  mode now requires `passport.ownerDid === mandate.principal` (for did:key
  principals) and, if the credential names a mandate, that it be this one
  (`OWNER_MISMATCH`/`MANDATE_MISMATCH`); red-team case added.
- **(MEDIUM-2)** Held calls reserve nothing, so they escaped the velocity
  counter — a looping agent could flood pushes (notification-fatigue phishing
  vector), sockets, and fsync'd `approval.requested` entries. Added
  `MANDARE_MAX_PENDING_APPROVALS` (default 8); over it, `APPROVAL_BACKLOG`
  DENIED without a push. Red-team case added.
- **(MEDIUM-3)** Approval capability tokens transit whatever ntfy server is
  configured; on the PUBLIC ntfy.sh the topic name is the only secret. Loud
  startup warning added when the public default is used (self-host / token-
  protect the topic for anything real).
- **(LOWs fixed)** agent-key file now written with `wx` (refuses to overwrite a
  private key, L3); `mandate issue --agent` validated as did:key (L6); in-memory
  nonce store in passport mode without a vault now warns at startup (L5).
- **(LOWs recorded, not actioned)** `@query` not in required components (no
  query-bearing routes yet, L1); pre-decode length bound on did:key (bounded by
  Node's header cap, L2); FileNotifier 0644 (CI-only, L4); corrupt vault
  identity-key JSON gives a raw crypto error not a clean message (L7); pre-auth
  throttled DENIED entries carry the asserted `config.actor` (L8).

### Known debt (intentional, scheduled)

- Approval pending map is in-memory: a gateway restart drops in-flight holds
  (they fail closed — the agent retries). Persistence is an S5+ nicety, not a
  correctness gap.
- `did:web` organization profile + a hosted attestation authority (cloud) are
  S5/S6 (private-repo service).
- OpenRouter provisioning `disableKey` still not wired into `mandare kill`
  (needs the per-agent key-hash map; the LOCAL authority is complete without it).
- ntfy is the only shipped Notifier adapter; Telegram (grammY) deferred — the
  interface is pluggable and file/mock cover CI. For real approvals, self-host
  ntfy or protect the topic (MEDIUM-3 warning fires otherwise).
- The remaining LOWs above (L1/L2/L4/L7/L8) — cosmetic/bounded, no correctness
  or spend impact.

---

## S5 — Card rail (2026-07-22)

**Scope (per S4 handoff + founder pick):** Stripe Issuing card rail (Q11/Q12) —
per-agent single-use virtual cards created only under a valid mandate ·
real-time `issuing_authorization.request` → policy decision (approve/decline/
partial) well under the 2s budget, webhook-signature verification mandatory ·
log-before-act adapted to cards · card spend settles into the SAME projection
as LLM spend (one mandate, one cap, both rails) · kill extends to cards ·
over-threshold reuses the S4 approval push · Demo 4 "the card declines at the
network" as a CI acceptance test · red-team additions. (Root CLAUDE.md's
plan-mode trigger for payment rails: the founder's S5 brief was the approved
plan — scope executed as specified, latitude decisions below.)

**Status: complete except the live smoke, which is BLOCKED ON the founder**
(one dashboard click — see "From the founder" below). CI green ON ORIGIN
(run 29932497770, all 4 jobs; the first push tripped a pre-existing 5s vitest
timeout on the S1 merkle property sweeps under the higher parallel load — a
budget bump, assertions untouched) and locally on the full gate
(build/typecheck/lint+license/test/red-team/smoke/demo×4); Demo 4
scripted + captured + in CI; Code Reviewer pass done (1 MEDIUM + 5 LOW, all
actionable ones fixed same session); decision path benchmarked p50 ~0.6–0.9ms /
p99 ~6–7ms over 200 authorizations (~300× under Stripe's 2s). S0–S4 red-team
floor and Demos 1–3 frozen and green. Test totals: 55 card-rail tests
(15 red-team) + the cross-rail gateway mount test on top of the S4 totals.

### Done

- **`packages/card-rail`** (AGPL) — the Stripe Issuing door, mounted ONTO the
  gateway's Fastify app: one door process, one door key, one ledger. This is
  forced by S1's one-writing-door-per-DB rule and is what makes the cross-rail
  cap real (both rails reserve inside the same append transaction). Rail
  mounts IFF `STRIPE_WEBHOOK_SECRET` AND a mandate exist (fail-closed on both).
  - `webhook-signature.ts`: HAND-ROLLED Stripe-Signature verification (HMAC v1
    scheme over exact raw bytes via an encapsulated raw-body parser scope,
    constant-time compare on pre-validated 64-hex candidates, two-sided
    timestamp tolerance, rotation multi-v1, duplicate-`t` refused). Forged/
    unsigned/tampered webhooks: 4xx and ZERO ledger writes.
  - `routes.ts` decision path: signature → card→(actor,mandate) binding
    (unknown/cross-mandate card ⇒ decline) → EARLY replay check → revocation
    (door/agent/mandate/CARD from the LOCAL projection — `mandare kill` from
    another process bites on the next authorization) → currency sanity
    (two-decimal allowlist, == ledger currency, no invented FX) → policy
    (SPEC §5 via `MandatePolicyEngine` with the new `rail: 'card'` option) →
    RESERVE `card.auth.intent` budget-guarded in the append transaction →
    SETTLE `card.auth.result` BEFORE Stripe hears "approved" → respond.
    Unpersistable result ⇒ the card door HALTS and declines everything
    (surfaced on /healthz `card_rail.halted`).
  - **Partial approvals** (Q11): budget-cap refusals on
    `is_amount_controllable` requests approve the largest amount that fits
    (floored to whole minor units) — only after the FULL policy order allows
    the reduced amount. Partials NEVER apply to approval thresholds (that
    would dodge the human).
  - **Step-up approvals**: 2s cannot hold a human, so over-threshold =
    DECLINE NOW + the S4 push (same ApprovalService instance, same
    `/approvals/:id` endpoint — one approval surface, two rails). A recorded
    `approval.granted` entry mints a SINGLE-USE in-memory waiver
    (card+merchant+amount-ceiling+TTL); the human just retries the purchase.
    No entry ⇒ no waiver; unidentifiable merchant ⇒ no waiver (fail-closed).
  - **Card creation** = a mandate-checked, ledger-logged door op:
    window + `card.create` action scope + identity + card spend scope checks →
    `card.create.intent` → Stripe create (virtual, with a Stripe-side
    per-authorization spending limit = the per-tx cap, belt only) →
    `card.create.result` (+ `subject.register` for the card's status-list
    slot at birth) — or `card.create.failed` settling the intent honestly.
    Response carries id + last4, NEVER a PAN (R2). Auth for the route is the
    gateway's own mode machinery (an `authenticateCreate` closure: none/
    token/passport).
- **`packages/ledger`**: `card.auth.intent/result/denied` project into the
  SAME `budget_counters` keys as LLM spend — no new tables in either driver.
  The auth entry's `target` (Stripe authorization id) doubles as a
  projection-enforced single-use marker (`cardauth:` rows): live appends
  refuse a duplicate under the lock (`AUTH_REPLAYED`), replay of a tampered
  chain carrying two intents for one authorization throws
  `ProjectionIntegrityError`. `cardSubject()` joins the one revocation
  vocabulary.
- **`packages/policy-engine`**: `rail?: 'gateway' | 'card'` option +
  `selectCardSpendScope` (rails includes 'card', category 'purchase' or
  uncategorized) — SPEC §5 order shared verbatim across rails.
- **`packages/vault` / gateway config**: `provider:stripe` + `webhook:stripe`
  slots; `vault import-env` recognizes `STRIPE_SECRET_KEY` /
  `STRIPE_WEBHOOK_SECRET`; vault mode sources both from the vault (env
  ignored, said out loud at startup).
- **`apps/cli`**: `mandare kill` fans out to the subject's cards — revoke
  entry per card (LOCAL authority; the webhook declines offline) + best-effort
  Stripe cancel (belt, like OpenRouter disableKey; its absence never blocks
  the kill). `mandare verify --spend` renders the card trail (CARD reserve/
  settle/refused lines) and a cross-rail split line ("llm settled X · card
  settled Y · one cap governs both").
- **Demo 4** (`scripts/demo-card.mjs`, `pnpm demo:card`, CI job): one €20
  mandate, both rails — 6 LLM calls settle €15.00 (mock OpenRouter,
  authoritative usage.cost), a €4.20 purchase APPROVES at the network
  (real signed webhook against the mounted rail), the next €3.00 DECLINES at
  the network with the refusal on the ledger, `mandare kill` revokes the card
  locally AND cancels it at (mock-)Stripe, a post-kill €0.50 declines, and
  `mandare verify --spend` proves chain VALID + counters == replay + the
  cross-rail totals (15.00 + 4.20 = 19.20 of 20). ASSERTS everything (R7).
  Capture: `docs/demos/S5-card-demo.txt`.
- **Red-team additions** (`packages/card-rail/test/red-team/`, in
  `pnpm red-team`): unsigned/forged/tampered webhook (zero writes) · replayed
  webhook — exactly one reservation ever, AND the budget-shifted replay of a
  decided authorization writes nothing · stale-timestamp replay · spliced
  duplicate-intent chain explodes on replay · revoked agent/mandate/card/door
  each decline with the refusal recorded · 20-way race against one cap admits
  EXACTLY 3×€6 (S2 reserve semantics) · cross-mandate card declined ·
  gateway-only mandate declines the whole rail · signed request event without
  `pending_request` declines (never full-approves).
- **Bench** (`test/decision-latency.test.ts`, runs in CI): 200 sequential
  authorization decisions through the full route — p50 0.61–0.92ms, p99
  6.2–7.1ms on Apple Silicon (assertion: p99 < 500ms for slow CI machines).
  The path is fully local by design; Q11's 2s budget has ~300× headroom.
- **Docs**: `docs/CARD-RAIL.md` — architecture, the 2s budget + the operator
  obligation to set the Stripe dashboard timeout default to DECLINE and
  monitor `request_history.reason=webhook_timeout` (fail-safe on timeout),
  step-up flow, threat table (incl. the accepted undecided-replay flavor),
  Host-allowlist caveat, known gaps. Package CLAUDE.md; root CLAUDE.md repo
  map + roadmap updated.
- **Live smoke** (`scripts/card-live-smoke.mjs`, `pnpm card-live-smoke`,
  local only): real test mode via `stripe listen` (real signatures) + Issuing
  test-helper authorizations against a door-issued card — approve, decline,
  kill+cancel, verify. Enforces `sk_test_` keys, never prints secrets.
  **BLOCKED at the account level**: Stripe answers "Your account is not set
  up to use Issuing" — the founder must enable Issuing on the test account
  (see below). The script fails closed with exactly that instruction.

### Decisions (S5 latitude; BUILD-DECISIONS untouched)

1. **The card rail is a plugin on the gateway, not a second door process.**
   S1 froze one writing door per ledger DB, and a separate process/ledger
   would fracture the single cap into two truths. One process, one key, one
   ledger; the rail is an encapsulated Fastify scope with its own raw-body
   parser (signature needs exact bytes).
2. **Card entries reuse the S2 spend projection verbatim** — intents reserve,
   results settle, denied entries are counter-inert; day/total keys are the
   same rows LLM spend uses, which IS the one-cap property. The only new
   projection state is the `cardauth:` single-use marker (a counter row, so
   replay(ledger) == counters covers it and no driver schema changed).
3. **Authorization ≈ spend, settled at decision time (conservative).** v0
   settles the approved amount when it approves; the capture-time true-up
   from `issuing_transaction.created` (partial captures, reversals) is
   scheduled work via Storno corrections. Authorized ≥ captured, so the cap
   never under-counts (R1).
4. **Step-up = decline-now + waiver-on-recorded-approval.** Stripe's 2s
   budget cannot hold a CIBA push, so the approve is asynchronous and the
   RETRY redeems it: single-use, card+merchant-bound, amount-ceilinged,
   TTL'd, minted only from a persisted approval.granted entry. In-memory by
   design (restart ⇒ decline again ⇒ new push; fail-closed).
5. **Hand-rolled webhook signature verification** (like RFC 6962/did:key):
   the scheme is ~60 lines with a complete adversarial test surface; zero new
   dependencies beats auditing the whole stripe SDK for one HMAC. The API
   client is likewise a minimal fetch/form-encoding wrapper over the four
   Issuing calls the door needs.
6. **Two-decimal currencies only** on the card rail in v0 — a zero-decimal
   currency (JPY) mis-metered 100× is a silent cap bypass; unsupported minor
   units decline (fail-closed).
7. **Unknown cards decline but are recorded** (`mnd_unknown`): a validly
   signed authorization for a card the door never issued is a real event on
   OUR Stripe account — evidence, not noise.

### Deviations from BUILD-DECISIONS

None. (Q11 followed: webhook decisioning within 2s, `{"approved":bool}` +
Stripe-Version echo, partial-amount support, `stripe trigger`/test-helper
testing path, `webhook_timeout` monitoring documented. Q12's Weavr fallback
untouched — Stripe test mode needs nothing but the Issuing toggle.)

### Review pass (Code Reviewer subagent, full S5 diff)

No CRITICAL/HIGH. 1 MEDIUM + 5 LOW. Explicitly confirmed clean: signature
crypto (equal-length constant-time, exact-byte binding, parser encapsulation),
the projection invariant on every path incl. halt-with-open-reservation,
waiver lifecycle (no mint without a persisted grant, no interleaving window),
cross-rail race safety (both rails serialize through the same store's
append transaction), R2/R3 everywhere, kill fan-out. Fixed same session with
regression/red-team tests:

- **(MEDIUM)** `parseAuthorizationEvent` fell back from `pending_request.amount`
  to the top-level `amount` — which is 0 on request events, so an API-shape
  surprise could approve the FULL amount while metering €0 (a `{approved:true}`
  with no `amount` field approves everything). Now: no `pending_request`, no
  parse — decline. Red-team case added.
- **(LOW-1)** replays were only refused at the reserve step, so a replay of a
  DECIDED authorization after the budget shifted would write a contradictory
  DENIED entry. An early marker check now declines any decided authorization
  with zero writes in every budget state. The undecided (step-up) flavor is
  bounded by a per-authorization in-flight dedupe: while the human decision
  is pending, a replay writes nothing, pushes nothing, and cannot create a
  second waiver path (after resolution, a re-request is indistinguishable
  from a genuine merchant retry — the human is simply asked again, which is
  the correct behavior). Red-team cases added for both flavors.
- **(LOW-2)** merchants with neither network_id nor name pooled under one
  sentinel waiver key — a waiver for merchant A could match merchant B.
  Unidentifiable merchants now get no waiver in either direction.
- **(LOW-3)** the gateway Host allowlist silently applies to /stripe/webhook —
  the `MANDARE_GATEWAY_PUBLIC_URL` hostname is now auto-allowed (with a
  regression test), so a deployment behind its declared public name cannot
  silently 403 its own webhooks; other hostnames still need
  `MANDARE_GATEWAY_ALLOWED_HOSTS` (documented).
- **(LOW-4)** the card door's halt was invisible — /healthz now reports
  `card_rail: {mounted, halted, registered_cards}`.
- **(LOW-5)** vault mode silently ignored env STRIPE_* — startup banner now
  says so explicitly.

### Known debt (intentional, scheduled)

- **Settlement true-up from `issuing_transaction.created`** (captures,
  partial reversals) — conservative authorized-amount settlement until then;
  reconcile via Storno corrections (S6+ or a later pass).
- Webhook-timeout declines happen at Stripe without the door seeing them —
  not ledger entries; reconciliation against Stripe's authorization list is
  a documented manual step until the true-up lands.
- Waivers + pending approvals in-memory (restart ⇒ re-decline + re-push;
  fail-closed) — persistence is a nicety, same S4 posture.
- The card registry learns out-of-process creations only on restart (their
  authorizations decline until then — fail-closed).
- A post-kill authorization decided while another process holds the SQLite
  write lock can wait up to busy_timeout — observed ~2s once in Demo 4
  (kill CLI + door on one DB); bounded and rare, but worth an eye when the
  witness (S6) adds more writers.
- Live smoke blocked on the founder's Issuing toggle (below).

---

## S6 — Witnessing + public anchoring (2026-08-09)

**Scope (per S5 handoff + SPEC §6 locks 4–5, §9.4):** the open witness
protocol + door client · a public reference witness server · public
anchoring behind an `Anchor` interface (OpenTimestamps) · witness-ack gating
(lock 5) on both rails · `mandare verify --witness` + `mandare certify` ·
Demo 5 "the rewrite that can't hide" · red-team + honest-degradation docs.

**Status: complete.** All exit criteria met: everything test-proven; Demo 5
scripted + captured + in CI; red-team green on SQLite AND Postgres; the
witness-ack path benchmarked (p50 ~15ms / p99 ~29ms per gated ack over a
500+ entry ledger — ~68× under Stripe's 2s budget at p99); Code Reviewer
pass done (2 HIGH + 3 MEDIUM + LOWs, ALL actionable ones fixed same session);
full local gate green (build/typecheck/lint+license/test/red-team/smoke/
demo×5). S0–S5 red-team floor and Demos 1–4 frozen and green. `packages/spec`
untouched (R6). Point restated at the top of the session and honored:
**self-anchored verification proves consistency, not authorship, and
truncation was the open boundary since S0 — witnessing closes both while
Mandare-the-company never sees ledger contents.**

### Done

- **`packages/witness-protocol`** (Apache-2.0, the inspectable/embeddable
  surface) — everything a party needs to SPEAK or CHECK the protocol without
  trusting us:
  - **Content-free wire** (`messages.ts`): a submission is `{size, 32-byte
    RFC 6962 root}` over entry hashes whose preimages carry a random 16-byte
    salt — the witness learns THAT a ledger grew, never WHAT it recorded. All
    schemas `additionalProperties:false`, bounded. Boundary parsers (R4).
  - **Self-authenticating sources**: `source_id = sha256(door pubkey)`; every
    submission Ed25519-signed over `sha256(canonicalJson(payload))` — one
    signing rule shared with ledger entries (`signing.ts`).
  - **Door client** (`client.ts`): streams heads per-entry/second, catches up
    after offline gaps in ONE consistency-proven sync (no literal queue — the
    tree commits to every prior entry), verifies every ack against an
    OUT-OF-BAND witness key. `fetchVerifiedWitnessedHead` is the standalone
    read used by verify/certify.
  - **Anchoring aggregate** (`aggregate.ts`): one RFC 6962 tree over all
    sources' latest witnessed heads; per-source inclusion proofs reveal
    hashes only. Epochs are witness-signed (`signEpochSummary`/
    `verifyEpochSummary`) so a relying party can't be handed a fabricated
    aggregate (review H2).
  - **`Anchor` interface** (`anchor.ts`, Q6): `OpenTimestampsAnchor` (live),
    `MockAnchor` (CI/demos — its receipt says loudly it is NOT public),
    `BaseAnchor` (declared future EVM stub, not built). `ots.ts` is a
    HAND-ROLLED minimal OpenTimestamps client — the npm `opentimestamps`
    0.4.9 drags in `request`/`bitcore-lib`/`bytebuffer`/the placeholder `fs`,
    exactly the surface Q24 refuses; the emitted `.ots` bytes stay verifiable
    by stock OTS clients. Parse bounds on every varuint/varbytes/depth/node.
  - **Integrity certificate** (`certificate.ts`, SPEC §9.4): build + verify.
    Third-party verification re-derives every proof-basis check (bundle
    signature, witnessed-head signature, witnessed consistency incl. the
    truncation direction, disclosed-entry hash+signature+inclusion,
    witness-signed aggregate inclusion) and labels the two claims it can't
    re-derive without the full ledger as `recorder-attested`; public-chain
    finality is `proof` ONLY on a verified Bitcoin attestation.
- **`packages/witness`** (AGPL) — the reference server, single-tenant, open,
  self-hostable (SPEC §3.2). Records per-source witnessed head history
  (consistency-ENFORCED on every submission — a rewrite is refused at
  submission time, not just detected later), aggregates + anchors, serves
  witnessed-head lookups + signed acks + witness-signed epoch inclusion, and
  hosts the S1 key directory + S3 status list as static JSON (closing that
  debt). Witness storage gets the ledger's posture: heads/sources
  append-only, epoch commitments immutable, the anchor receipt may only
  progress none→pending→confirmed and is frozen once confirmed (triggers).
  **The multi-tenant commercial witness is explicitly OUT of this repo** and
  speaks the same wire.
- **Witness-ack gating (lock 5)** — `packages/gateway/src/witness-gate.ts`
  wired into the LLM path (after the intent reservation, before execution)
  and the card path (`routes.ts` step 6b, before Stripe hears "approved").
  `ackMode: 'threshold'` reuses the mandate's approval rules as the
  high-value set (no second threshold vocabulary); no verified ack within
  the timeout ⇒ the reservation settles to ZERO and the action is refused
  (R1/R3). A dead witness closes high-value doors, never opens one, never
  blocks `mandare kill`. Streaming nudges on every append (lock 4). Config in
  `config.ts` (`MANDARE_WITNESS_*`), fail-closed on misconfiguration (gating
  without a URL, URL without an out-of-band key, client missing when
  configured — all refuse loudly).
- **CLI** (`apps/cli`): `mandare verify --witness <url> --witness-key <hex>`
  (TRUNCATION/FORK/CONSISTENT/UNAVAILABLE, exit 1 on anything but consistent);
  `mandare certify [--disclose …]` + `mandare certify verify <file>`;
  `mandare witness serve` (runs the reference witness, prints its public key
  for out-of-band distribution, OTS/mock anchor, optional directory/status
  hosting).
- **Demo 5** (`scripts/demo-witness.mjs`, `pnpm demo:witness`, CI job): heads
  streamed to the REAL `mandare witness serve` child process; a truncated
  copy and a real-door-key rewrite both pass self-anchored verification and
  both are CONVICTED by `mandare verify --witness`; the aggregate root is
  anchored; `mandare certify` emits a 2-of-8 selective-disclosure certificate
  a third party verifies with no ledger access; a doctored certificate is
  INVALID. ASSERTS everything (R7). Capture:
  `docs/demos/S6-witness-demo.txt`.
- **Red-team additions** (green on both drivers): truncation-after-witness +
  rewrite-after-witness (real-door-key, self-anchored-passes → witnessed-head
  convicts) on SQLite (`packages/witness`) AND Postgres (`tamper-pg.test.ts`);
  forged/replayed acks + history conflicts (`witness-protocol/client.test`);
  cross-source forgery, split-view, replay-rollback, salt-dictionary attack,
  aggregate inclusion-proof forgery, witness-storage mutation +
  anchor-regression (`packages/witness/test/red-team`); witness-unavailable
  fail-safe on both rails, threshold-mode async window, approve-then-
  witness-down still fails closed (`gateway`/`card-rail` red-team); certify
  refuses truncation/fork at build time (`apps/cli`). The S0 witness
  `test.todo` is retired with a pointer to the closing tests.
- **Docs**: `docs/WITNESSING.md` (architecture, detection, gating, anchoring,
  certificate, and the honest residuals stated plainly). Package CLAUDE.md ×2,
  root CLAUDE.md map + commands, LICENSING.md, `.env.example` witness block.

### Decisions (S6 latitude; BUILD-DECISIONS untouched)

1. **Public reference witness in THIS repo; commercial multi-tenant witness
   in the future private repo** (the S5 handoff default; the founder did not
   rule otherwise). The protocol + verification are Apache so distrusting
   parties can embed them; the reference server is AGPL.
2. **Hand-rolled OTS client** (like RFC 6962/did:key/Stripe-signature before
   it): the `opentimestamps` npm client's dependency tree violates the Q24
   supply-chain posture. ~450 lines with a full adversarial parse-bound test
   surface; the `.ots` artifact stays portable. Logged as a Q6-letter
   deviation, same spirit (the interface + the format are honored).
3. **Witness-ack gating reuses the mandate approval threshold** as its
   definition of high-value — one threshold vocabulary, set by the human who
   signed the mandate, not a second knob.
4. **Epochs are witness-signed** (added during the review pass): the
   certificate's anchoring claim must rest on a witness-attested aggregate,
   not a certificate-self-declared one.
5. **The certificate verdict gates on PROOF-basis checks only**;
   recorder-attested checks (chain validity needs the full ledger; public
   anchoring may be legitimately pending) are reported honestly and never
   silently pass — the project's honesty rule, in code.

### Deviations from BUILD-DECISIONS

None. (Q6 OpenTimestamps daily anchoring behind an `Anchor` interface, with
Base/EVM as a declared stub — honored; the hand-rolled client is a
same-spirit deviation from Q6's "vendor the npm client" letter, logged above
under decision 2 and in `packages/witness-protocol/CLAUDE.md`.)

### Review pass (Code Reviewer subagent, full S6 diff)

2 HIGH + 3 MEDIUM + LOWs. Core security explicitly confirmed clean:
content-free wire, source self-authentication, consistency-enforced witness
history (incl. the async-verification TOCTOU closed by `appendHead`'s
BEGIN IMMEDIATE re-check), verified acks, fail-closed gating on both rails,
OTS parse bounds, canonical-JSON signing, and the R5 suites (non-tautological,
S0–S5 floor untouched). Fixed same session with regression/red-team tests:

- **(HIGH-1)** the certificate verifier never bound
  `door_key_id == sha256(door_public_key)` — self-declared mode let an
  attacker name a victim's `source_id` while signing with their own key and
  mint a "VALID" certificate over the victim's witnessed, anchored history.
  Now the invariant is checked; impersonation forces the victim's key, at
  which point the bundle signature fails. Red-team case added.
- **(HIGH-2)** the anchored-head check trusted attacker-chosen epoch data
  (the `EpochSummary` carried no signature) and the mock/unknown-adapter
  branch claimed `basis:'proof'` for public anchoring that wasn't. Now the
  witness SIGNS every served epoch and the verifier checks it; the check
  splits into `witness-aggregated-head` (proof) and `public-anchor` (proof
  ONLY on a verified Bitcoin attestation; pending/mock reported as NOTE,
  never overclaimed). The verdict gates on proof-basis checks. Red-team case.
- **(MEDIUM-3)** unknown OTS attestation payloads were dropped
  (`payload.bytes(0)`), corrupting re-serialized receipts for
  litecoin/ethereum-style tags. `ByteReader.rest()` keeps the full opaque
  payload; round-trip test added.
- **(MEDIUM-4)** epoch anchor columns could regress (confirmed→none, receipt
  nulled) without tripping a trigger — a witness-DB attacker could erase
  anchoring evidence. New `witness_epochs_anchor_progress` trigger; red-team
  assertions for both the refused regressions and the one legal progression.
- **(MEDIUM-5)** `certify` embedded a consistency proof in the `size <
  witnessed` case without verifying it, shipping a doomed certificate for a
  prefix-rewritten-then-grown ledger. It now runs `verifyConsistency` and
  REFUSES a fork at build time (main path + `fetchAnchorInclusion`). Red-team
  cases (truncation + fork) added in `apps/cli`.
- **(LOWs fixed)** 409 `NOT_CONSISTENT` surfaces as `HISTORY_CONFLICT` not a
  misleading "moving head" (L7); non-JSON witness bodies raise `BAD_ACK` not a
  raw `SyntaxError` (L9); `revocation.lst`/`ots_base64` gained `maxLength`
  bounds (L11); the 503 witness reason to the (hostile) agent is now generic,
  detail server-side only (L12); a size-0 first head must carry the empty-tree
  root or it's a 400 (L13); the concurrent-move 409 re-reads the head for its
  body (L8); `--anchor-interval-hours 0|off` selects on-demand-only anchoring
  (L6, dead branch made reachable).
- **(LOW recorded, not actioned)** per-sync O(n) tree recompute is
  milliseconds at today's scale; an incremental/persistent Merkle state is
  the S7+ fix before large fleets (see handoff).

### Known debt (intentional, scheduled)

- **Per-sync O(n) tree recompute** (client streaming + gated acks): fine at
  hundreds/thousands of entries (benched); at 10^5–10^6 a persistent
  incremental Merkle state is warranted before the 1.5s ack timeout starts
  eating tree computation. S7+.
- **Second-witness redundancy** is protocol-permitted (a door can stream to N
  witnesses) but not wired into config — a single malicious witness can
  refuse service (⇒ high-value fail closed) but cannot forge or rewrite.
  Documented in WITNESSING.md; a multi-witness config knob is S7+.
- **OpenTimestamps live-smoke** (real calendars → real `.ots` → real Bitcoin
  upgrade) is not in CI (network + hours-to-confirm). The adapter is
  unit-tested against faked calendar responses end to end; a local
  `witness-live-smoke` against the public calendar pool is a founder-run
  check, like the card live-smoke.
- Still pending from S3: wiring OpenRouter `disableKey` into `mandare kill`.

---

## S7 — Packaging & distribution surfaces (2026-08-09)

**Scope (per S6 handoff + Q17/Q18/Q26/Q28/Q29):** MCP server · OpenClaw
native skill · TS SDK (+ Python client) · `docker compose up` self-host +
one-line solo installer · dashboard-lite · Fumadocs docs site · clean-machine
install smoke as CI · release.yml upgraded (dry-run only). NOTHING published
to any registry (repo private until S9).

**Status: complete.** All surfaces functional and test-proven E2E against the
real system; clean-machine install smoke + compose smoke enforced in CI;
MCP server and OpenClaw skill exercised end-to-end (a live gateway door is
killed through each); dashboard renders real ledger data (asserted in CI on
the compose stack); docs build green. Code Reviewer pass done (2 CRITICAL +
1 HIGH + 5 MEDIUM + 6 LOW — ALL fixed same session, zero open). Full local
gate green (build/typecheck/lint+license/test/red-team/smoke/demo×5 + four
new S7 smokes). S0–S6 red-team floor and Demos 1–5 frozen and green.
`packages/spec` untouched (R6). **CI green ON ORIGIN: run 31316026415, all
6 jobs** (incl. the first-ever real-docker compose-smoke). Two CI iteration
rounds, all fixes logged: ① witness-entry created only the key dir, not the
public-hex handoff dir on the OTHER volume (fresh containers crashed; the
stack-smoke harness had masked it by pre-creating dirs — it now creates
none, so entry scripts must own theirs); ② python unittest needs the
package dir as cwd; ③ the S5 card decision-latency bench needed a 30s
wall-clock test budget under the grown parallel load (p99 assertion
untouched — same class as the S5 merkle bump); ④ a PRE-EXISTING S5 flake
surfaced once: the R2 no-PAN scan matched a 13-digit run INSIDE a 64-hex
entry hash — assertion made hash-aware and STRENGTHENED (exact field
allowlist + hash-shape proofs + PAN-scan of everything else).

### Done

- **`packages/sdk`** (Apache-2.0) — the adoption path is ONE function:
  `createMandareFetch` returns a fetch-compatible signer for the door's auth
  modes (S3 token PoP headers; S4 passport RFC 9421 + Content-Digest via the
  Apache `@mandarelabs/passport` — never importing AGPL). Hand it to the
  official Anthropic/OpenAI SDK as `fetch` and keep your code. Plus
  `MandareGateway` (typed refusals: `MandareRefusedError` normalizes the 403
  `reasons[]` and 401 `reason` shapes), `loadPassportIdentity`,
  `tokenCredentialsFromIssueJson`. Fail-closed on unsignable bodies
  (streams/FormData refuse client-side before sending).
  **Wire-contract discipline:** the PoP preimage/encoding is re-stated (not
  imported — license direction) and `packages/gateway/test/sdk-auth.test.ts`
  is the drift alarm: real vault-minted token + real passport rig against a
  LISTENING door — accept, BAD_POP (raw + typed via the client), and
  body-swap-under-signature (BODY_DIGEST_MISMATCH) all proven.
- **`packages/sdk-py`** (Apache-2.0, zero dependencies, NOT a workspace
  member): stdlib-only Python client for token mode + dev mode
  (`MandareClient`, `MandareRefused`, `load_token_file`). Passport mode
  needs Ed25519 → stated TS-only limit, not hidden. A PINNED cross-language
  HMAC vector sits in both test suites; `pnpm sdk-py-smoke` runs the client
  against a real vault-backed token door (accept + BAD_POP).
- **`packages/mcp-server`** (AGPL) — Q17: stdio server on
  `@modelcontextprotocol/sdk` v1, a THIN adapter over the CLI (one authority
  surface, no second code path). Tools: verify, budget_status,
  issue_passport/mandate/token, kill, certify, gateway_health. Posture:
  paths/vault/witness config from OPERATOR env only — no tool accepts a
  filesystem path (R4); tool args zod-validated and passed as discrete argv
  (no shell); token grants written 0600 into `MANDARE_MCP_HOME` and returned
  BY PATH — `pop_secret` never enters model context (R2), `redactSecrets` as
  belt; **kill always on, reinstate opt-in** (`MANDARE_MCP_ALLOW_REINSTATE=1`,
  tool invisible otherwise) — a compromised MCP host may close doors, not
  reopen them. E2E test drives a LIVE gateway: spend → budget shows it →
  MCP kill → 403 AGENT_REVOKED → verify proves the trail. `server.json`
  (namespace `com.mandarelabs`) prepared, NOT published.
- **`integrations/openclaw`** (Apache-2.0) — Q18: native AgentSkills
  `SKILL.md` (serves OpenClaw via `metadata.openclaw` AND Claude Code) that
  shells to the CLI. Doctrine: **visibility and the kill switch, never
  authority** — budget checks, honest refusal handling (never route around a
  refusal), proofs/certificates, kill; issuance + reinstate are explicitly
  operator actions the skill refuses to run. Trust envelope
  `clawhub.skill.verify.v1`: sha256 per file + Ed25519 signature over the
  canonical core (packaging + independent verifier scripts); verifier
  refuses hash mismatches, ADDED files, and doctored SHA256SUMS.
  `pnpm skill-smoke` executes the documented commands VERBATIM against a
  live door (kill bites: 403 AGENT_REVOKED) and proves envelope
  tamper/injection/signing cases. Not published to ClawHub.
- **Self-host** — `Dockerfile` (single image, four roles) + `compose.yaml`:
  gateway + witness (own private state volume; public key handed off via the
  shared volume) + dashboard + mock provider + one-shot `demo` service. The
  quickstart is 3 commands and needs ZERO secrets — the mock provider stands
  in while enforcement (mandate, ledger, witness, refusal-at-cap) is real.
  Real providers via `.env` (key + base URL). All host ports loopback-only.
  `install.sh` = solo path (node ≥22.13 gate, frozen lockfile, repo-local
  `./bin/mandare`, no sudo). `scripts/stack-smoke.mjs` runs the EXACT
  container entry scripts as local processes (compose parity grep-asserted
  against compose.yaml) — the no-docker proof; the real docker path runs in
  CI (`compose-smoke`).
- **`apps/dashboard`** (AGPL, Next 15) — read-mostly fleet view: agents +
  revocation state, per-mandate settled/reserved (today/total), approval
  trail, paged ledger trail, and verification badges that shell the REAL
  `mandare verify --spend [--witness] --json` (10s cache) — the dashboard
  renders what an auditor's command proves, not a parallel truth. ONE write:
  the kill button → `mandare kill` via the CLI. Host allowlist middleware
  (DNS-rebinding guard mirroring the gateway's). Zero telemetry, system
  fonts, loopback bind by default. Data layer tested against a REAL ledger
  built by the actual store + projectors; badge translation unit-tested with
  fork/rollback fixtures.
- **`apps/docs`** (Fumadocs, Q26) — quickstart (the 3-command path,
  smoke-enforced), concepts, the five demos, self-hosting (vault bootstrap,
  witness key out-of-band, PG team mode), threat model WITH the honest
  residuals table, security/provenance page (Q24/Q25 posture), integrations
  (SDK/MCP/OpenClaw/providers), CLI + env reference. Builds statically
  (13 pages + search route); content tests pin the quickstart commands.
- **CI** — `docs-install-smoke` job: asserts the quickstart commands appear
  VERBATIM in docs + README, then executes the documented solo path
  (`./install.sh`, `pnpm demo`) on a FRESH COPY of the repo with a 10-minute
  ceiling — Demo 1 reproduced from public docs only. `compose-smoke` job:
  the real `docker compose up -d --wait` + `docker compose run --rm demo` +
  asserts the dashboard renders real ledger data (agent DID, chain VALID,
  BOTH green CONSISTENT badges) and gateway/witness health. The smoke job
  additionally runs stack/skill/sdk-py smokes + Python unit tests.
- **`release.yml`** — dry-run-only upgrade: `pnpm publish --dry-run` (pnpm,
  NOT npm — it rewrites `workspace:*`), pack artifacts with a
  workspace-protocol leak gate, skill packaging + SHA256SUMS, docker build
  (no push), `publish=true` hard-fails until S9. OIDC permission kept.

### Decisions (S7 latitude; BUILD-DECISIONS untouched)

1. **MCP server + dashboard shell to the CLI instead of growing a library
   surface.** The CLI is the product's local authority; one code path means
   the MCP/dashboard can never take a less-verified shortcut. (Dashboard
   resolution had to be bundler-proof — see review notes.)
2. **The skill grants visibility, never authority.** An agent that can mint
   its own mandates has no mandates; issuance/reinstate are operator-only,
   and the SKILL.md says so as instruction, not implication. Kill stays
   available to agents (closing doors is always allowed).
3. **MCP secrets go to 0600 files, never model context** (R2 applied to a
   new boundary): `mandare_issue_token` returns the grant file PATH; the
   test asserts mode 0600 and no `pop_secret` in tool output.
4. **Compose dry-run is the default experience**: mock provider + generated
   dev mandate, zero secrets, REAL enforcement — same posture as CI demos
   since S2. Real providers are an explicit `.env` opt-in (key + base URL
   together, so a real key can never silently hit the mock).
5. **Non-loopback bind opt-out** (`MANDARE_GATEWAY_ALLOW_INSECURE_BIND=1`):
   the S3 refuse-to-bind guard stays; container topologies where the network
   namespace is the boundary take an EXPLICIT env opt-out that logs a loud
   warning. compose.yaml carries the justification inline (review C1).
6. **Version pins for the doc stack**: next ~15.5 + fumadocs 15/11 (the
   API surface verified against installed types) + a scoped `@orama/orama`
   3.1.14 override and a files-thunk shim in `lib/source.ts` for a
   fumadocs-mdx↔core pairing bug inside the compatible peer range. All
   drop out at the S9 dependency pass (fumadocs 16 / next 16).
7. **Skill/MCP/registry artifacts are PREPARED, not published** — namespace
   `com.mandarelabs` (mandarelabs.com DNS verification at launch;
   `io.github.mandarelabs` is the documented fallback). Founder confirms at
   S9.
8. **sdk-py lives outside the pnpm workspace** (no package.json → invisible
   to turbo/license tooling); its Apache status is recorded in LICENSING.md
   and its tests run as an explicit CI step. Zero-dep stdlib is the
   supply-chain posture extended to Python.

### Deviations from BUILD-DECISIONS

None. (Q17 stdio + env auth + registry manifest honored; Q18's skill format
+ trust envelope honored and exceeded with signing; Q26 Fumadocs; Q28
Next.js App Router; Q29's README shape. Q24's publish flow is staged in
release.yml but intentionally not armed — publishing is an S9 launch act.)

### Review pass (Code Reviewer subagent, full S7 diff)

2 CRITICAL + 1 HIGH + 5 MEDIUM + 6 LOW; explicitly confirmed clean: PoP wire
contract across all three implementations (vector independently recomputed),
license boundary (sdk → passport only), MCP R2/R4 posture (no path args, no
shell, 0600 grants, reinstate gating), dashboard SQL parameterization +
schema/key parity with the ledger, compose port scoping + witness-key
handoff fail-closed, install.sh hygiene, smokes' assertions. ALL findings
fixed same session:

- **(C1)** compose.yaml ran the gateway on 0.0.0.0 without token auth — the
  S3 fail-closed guard (correctly) refuses that, so the flagship 3-command
  quickstart could not boot (reviewer reproduced). Fixed via decision 5
  (explicit loud opt-out set only in compose.yaml, justification inline);
  guard message now names the option.
- **(C2)** the dashboard witness badge derived "consistent" from a SUBSTRING
  match — `'inconsistent'` contains `'consistent'`, so a REWRITTEN ledger
  rendered a green witness badge (and healthy states rendered red). Fixed:
  typed `consistency.status` parsing ('extended'/'identical' are the only
  green states; absent record fails closed), extracted as a pure function
  with fork/rollback/no-record fixture tests, and the compose-smoke CI job
  now asserts BOTH green CONSISTENT badges on the healthy stack.
- **(H1)** stack-smoke claimed compose parity while quietly binding
  127.0.0.1 (masking C1). Now runs 0.0.0.0 + the same opt-out and
  grep-asserts the security-relevant compose.yaml lines it mirrors.
- **(M1)** release dry-run used npm, which does NOT rewrite `workspace:*` —
  the S9 flip would have shipped uninstallable tarballs with green CI.
  Switched to `pnpm publish/pack` + a tarball grep gate for the protocol.
- **(M2)** dashboard had no DNS-rebinding defense while exposing fleet data
  and the kill action. Host-allowlist middleware added (loopback +
  `MANDARE_DASHBOARD_ALLOWED_HOSTS`), tested.
- **(M3)** the skill envelope ignored ADDED files and a doctored
  SHA256SUMS. Verifier now enumerates the directory (uncovered file ⇒ FAIL)
  and recomputes SHA256SUMS from the envelope; injection case in the smoke.
- **(M4)** the TS SDK never surfaced 401 auth refusals as typed
  `MandareRefusedError` (singular `reason` shape); normalized both shapes +
  a live-door test via the client (python client already handled both).
- **(M5)** README/threat-model overclaimed the witness for the solo compose
  topology (witness key on the same host). Claims scoped; residual added to
  the threat model; witness state moved to its OWN volume so at least other
  containers cannot touch its key.
- **(LOWs)** `.dockerignore` now excludes `.env.*`; skill README's verify
  example targets a packaged dir and the verifier gives a clean
  not-a-packaged-skill error; MCP server accepts `MANDARE_WITNESS_PUBLIC_HEX`
  key files (docs said so; now true); `__pycache__`/`.source`/`bin`/
  masterkey patterns gitignored; sdk-py docstring attribution fixed; MCP
  witness-unconfigured error paths pinned by tests.

### Known debt (intentional, scheduled)

- **Compose/docker layer is CI-proven, not locally proven** (no container
  runtime on the dev machine): compose-smoke in CI is the binding check.
- Dashboard reads SQLite only (PG team-mode dashboard reads later); trail
  pagination is simple seq-cursor; kill button E2E is covered via the CLI
  path + CI compose assertions, not a browser test.
- Docs stack pins (next 15 / fumadocs 15 / orama override / files-thunk
  shim) drop out at the S9 dependency pass.
- Docker image is one fat image with dev node_modules (fast first `up`);
  slim per-service images via `pnpm deploy` are launch work.
- The `witness-live-smoke` against the public OTS calendar pool (S6 debt)
  still awaits a founder run; unchanged this session.
- Per-sync O(n) witness tree recompute + multi-witness config knob (S6
  debt) — untouched, still scheduled S8+.

---

## S8 — Adversarial pre-launch review (2026-08-09)

**Scope (per the S7→S8 handoff):** the last gate before the code goes public —
an independent, adversarial pass across four disjoint lenses (crypto/integrity ·
spend/enforcement · packaging/supply-chain · docs/claims), *find → verify → fix*,
not a build session. Frozen floor binding: S0–S7 red-team suites (both drivers)
and Demos 1–5 must end green and un-weakened.

**Status: complete.** All exit criteria met. Four parallel Agent-Teams reviewers
ran, each prompted to break the system; every reported finding was re-traced
against live code by the orchestrator and only fixed if it reproduced. **15
findings — 3 HIGH, 4 MEDIUM, 5 LOW, 3 INFO** — all CONFIRMED findings fixed with
a regression test that fails on pre-fix code, 2 documented as accepted residuals
with rationale (no silent won't-fix). Full local gate green
(build/typecheck/lint+license+boundaries/test/red-team/smoke/demo×5 +
stack/skill/sdk-py smokes); compose-smoke is CI-only (no local Docker — S7 debt).
S0–S7 red-team floor + Demos 1–5 frozen and green; `packages/spec` schema
untouched (R6 — the one spec edit is a comment). Written summary:
`docs/SECURITY-REVIEW-S8.md`.

### Findings + resolutions (full detail in docs/SECURITY-REVIEW-S8.md)

- **C1 — HIGH (crypto)** — the integrity certificate's **bound mode** bound only
  the bundle *signature* to the auditor's out-of-band door key, never the
  certified `door_key_id` that drives the witness/anchor/consistency checks. A
  key-holding operator could witness a curated/truncated tree under a FRESH
  `source_id`, self-declare it, sign the bundle with the trusted key, and pass
  verification over a parallel witnessed timeline — defeating the certificate's
  core purpose (bind to the operator's REAL witnessed history). FIXED: `bundleOk`
  now also requires `door_key_id == sha256(doorKey)` (no-op in self-declared
  mode). Red-team test `S8/C1` in `certificate.test.ts`.
- **S1 — HIGH (spend)** — the pre-flight reservation (the cap guard) estimated
  input tokens as `chars/3` over the UTF-16 length — a true bound only for Latin.
  CJK/token-dense input under-counted ~3×, so `max_tokens:1` + a token-dense
  prompt reserved under the per-tx cap while settlement (no cap guard, by design)
  applied the true 2–3× cost past it. FIXED: estimate input tokens as the UTF-8
  **byte length** — a provable upper bound (tokens ≤ bytes for byte-level BPE)
  for any script; same bound applied to the settle-side fallback
  (usage-less/aborted streams, `observedTextBytes`) so the ledger never
  under-records. Test `S8/S1` in `pricing.test.ts`; aborted-stream assertion in
  `streaming.test.ts` updated to the conservative value.
- **P1 — HIGH (packaging)** — `verify-openclaw-skill.mjs` blessed an UNSIGNED
  package as VERIFIED (exit 0), and when signed read the verifying key FROM THE
  ENVELOPE (no pinning) — so a re-packaged tampered `SKILL.md` (agent-executed
  instructions) or a self-signed one passed, fooling a CI gate keyed on exit
  code. FIXED: unsigned FAILS by default (`--allow-unsigned` = explicit dev
  escape); a VERIFIED verdict requires the key be PINNED via `--expect-key <hex>`
  and match. `skill-smoke.mjs` now exercises the downgrade/re-hash, unsigned,
  unpinned, and wrong-key attacks (all refused) plus the pinned-match pass.
- **C2 — MEDIUM (crypto)** — the gating `public-anchor` check graded
  `basis:'proof', ok:true` on the mere PRESENCE of a Bitcoin attestation tag
  committing the epoch root, never verifying the block against a chain
  (impossible offline). Solo topology (witness key on the same host) ⇒ operator
  forges "Bitcoin finality." FIXED: the OTS-with-Bitcoin-tag case is now
  `recorder-attested` ("verify the .ots against a node") and never gates the
  verdict; offline-detectable lies (doesn't commit the root, unparseable) still
  gate. Test `S8/C2`.
- **S2 — MEDIUM (spend)** — after a successful witness-ack, both rails executed
  with NO revocation re-check — a `mandare kill` landing during the ack wait was
  ignored for that in-flight high-value call (the exact class lock-5 promises a
  zero tamper window; inconsistent with the approval-hold HIGH-2 re-check).
  FIXED: both rails re-check revocation after the ack; killed mid-wait ⇒ settle
  the reservation to 0 and refuse/decline. Red-team `KILL DURING ACK` on gateway
  AND card rail.
- **C3 — LOW (crypto)** — the OTS parser silently dropped trailing bytes in
  bitcoin/pending attestation payloads (non-canonical `.ots` round-trips to
  different bytes). FIXED: assert the attestation payload is exhausted.
- **P2 — LOW (packaging)** — `web-bot-auth` (pre-1.0, unaudited, in the Apache
  signing path) floated under a caret. FIXED: pinned exact `0.1.3`; on the audit
  list.
- **D1 — MEDIUM (docs)** — README + Security page claimed "official test vectors"
  for Stripe signatures + OTS (+ canonical JSON) — none published; those use the
  documented wire scheme + adversarial round-trip suites. FIXED: reworded to the
  true split (RFC 6962 CT + did:key/base58 ARE official vectors).
- **D2 — MEDIUM (docs)** — "even the operator can't rewrite history" stated
  unconditionally on the overview + Concepts pages without the same-host
  solo-compose residual co-located. FIXED: residual co-located on
  `index.mdx`/`concepts.mdx` (team mode / second host vs. single-host solo).
- **D3 — LOW (docs)** — latency figures presented as "CI bench" while CI asserts
  only p99 < 500ms. FIXED: labeled developer-hardware; stated the CI assertion.
- **D4 — LOW (docs)** — LICENSING.md's "declares license in its package.json"
  false for `sdk-py` (pyproject) + OpenClaw skill (no manifest). FIXED: reworded.
- **D5 — INFO (docs)** — the frozen `SpendRail` union advertises unimplemented
  `x402`/`credits` rails. FIXED: a schema COMMENT marks them RESERVED (no
  schema_version bump — R6 intact).
- **P3 — INFO (packaging)** — the Docker image baked internal docs (`TASKS.md`,
  `CLAUDE.md`, `docs/`) via `COPY . .`. FIXED: added to `.dockerignore`.
- **C4 — LOW/INFO (crypto)** — RFC 9421 omits `@query`/uncovered headers.
  ACCEPTED RESIDUAL (verified): no door reads the query string — every security
  field comes from the content-digest-bound body. Kept as documented
  defense-in-depth guidance; keep doors deciding only on the signed body.
- **P4 — INFO (packaging)** — `@napi-rs/keyring` native binary in the vault
  process (no install script runs). ACCEPTED (design: OS keychain needs native
  code); added to the auditor's binary-provenance target list.

### Decisions (S8 latitude; BUILD-DECISIONS untouched)

1. **S1 fix = a true upper bound, not a better heuristic.** UTF-8 byte length is
   a provable token ceiling for byte-level BPE (Anthropic/OpenAI), so no script
   under-reserves — the property the pricing comment already claimed. Output is
   still bounded by max_tokens/the ceiling (which dominates ordinary calls), so
   the extra input headroom only bites the attack shape and is released at
   settlement.
2. **C2 fix = honesty over gating.** Offline, Bitcoin finality is unprovable
   (needs a node), so the anchor is reported (recorder-attested, "verify
   externally") and never gates the verdict; only offline-detectable
   contradictions gate. The verdict continues to gate strictly on proof-basis
   checks (the project's honesty rule, kept in code).
3. **P1 fix = trust must be pinned.** A VERIFIED verdict now requires a pinned
   publisher key; unsigned/unpinned/self-signed all fail closed. `--allow-unsigned`
   is the explicit local-dev escape (same posture as the gateway's insecure-bind
   opt-out). `release.yml` will run `verify --expect-key <release pubkey>` at S9.
4. **S2 fix = HIGH-2 parity for lock 5.** The approval-hold path already re-checks
   revocation on resume; the witness-ack path now does the same, so "revoked
   instantly" holds across the ack window on both rails.

### Deviations from BUILD-DECISIONS

None. The one `packages/spec` edit is a comment (D5); the schema and its
`schema_version` are unchanged (R6 honored).

### Known debt (carried, unchanged this session)

- Compose/Docker layer CI-proven only (no local runtime) — compose-smoke in CI is
  the binding check.
- `witness-live-smoke` (real OTS calendars → Bitcoin) still a founder run (S6).
- Stripe Issuing live smoke blocked on the founder's toggle (S5).
- OpenRouter `disableKey` belt into `mandare kill` (S3, oldest open item) — still
  needs the founder's per-agent key-hash mapping decision; local kill authority
  is complete without it.
- Per-sync O(n) witness tree recompute + multi-witness config knob (S6) — S9+.

---

## S9 — Launch preparation (2026-08-09)

**Scope (per the S8→S9 handoff, PREPARE half only):** the pre-flip secret-scan
gate · README as the conversion asset (Q29) · `examples/` · the Show HN draft ·
`release.yml` armed for Trusted Publishing/SLSA/cosign · the go-live runbook.
**Publish nothing** — the repo stays private; S9b is the flip.

**Status: complete.** Repo still private, no registry touched. Full local gate
green (typecheck/lint+license+boundaries/test; Demo 1 re-run green via
`examples/01`); **CI green on origin** (run 31320774255) and the **release
dry-run green** (run 31320779975: gate `publish=false (repo private=true)`,
ephemeral-key sign → P1 pin-verify "skill package VERIFIED", all four publish
jobs skipped — G8 validated). Frozen floor untouched — the only code edit this
session is one comment line (`apps/cli/src/directory.ts`).

### Done

- **Secret-scan gate** (`docs/launch/SECRET-SCAN-S9.md`): gitleaks 8.30.1 +
  trufflehog 3.96.0 over ALL 37 commits on all refs — **clean**. The 5 raw
  gitleaks hits are did:key PUBLIC keys (multibase `z6Mk…`, incl. the W3C
  reference vector), allowlisted with rationale in `.gitleaks.toml`
  (`useDefault = true`, one regex). `.env`/`*.db`/`*.pem` never committed;
  `.env.example` history only ever held empty placeholders; all 37 commit
  messages + TASKS.md reviewed against the publicity boundary — clean.
  Fixed at tip: the private strategy-repo path in CLAUDE.md and three stale
  "Tessera" codename uses (directory.ts, KEY-DIRECTORY.md ×2) → "Mandare
  Cloud"/neutral. OPEN founder decision **G-IDENT**: all commits are authored
  under the founder's personal account (handle + e-mail) — accept (recommended) or rewrite
  history pre-flip (hash-invalidation costs documented in the report).
- **README** rebuilt per the Q29 playbook: one-liner → 4 badges (CI, license,
  npm, security-review) → a **real <30s demo GIF** → 3-command quickstart →
  "Proofs, not data" architecture section → demos table (now linking
  `examples/`) → integrations → security section that now LEADS with the S8
  adversarial review link. The GIF (`docs/demos/runaway-demo.gif`, 2.0 MB,
  ~23 s) is a paced replay of the REAL captured Demo 1 output — generator
  committed as `scripts/render-demo-gif.mjs` (asciinema-cast synthesis +
  `agg`; capture content verbatim, only pacing + ANSI color added) and
  labeled as a replay in the README caption.
- **`examples/`** — five self-contained narrated scenarios, one per flagship
  demo (runaway-cap · dead-paper · one-mandate · card-at-network ·
  rewrite-can't-hide). Each = README (claim, threat, real captured output,
  design rationale, code pointers — all file paths verified) + `run.sh`
  delegating to the CI-asserted `pnpm demo*` script (no logic duplication).
  `examples/01/run.sh` executed green this session.
- **Show HN draft** (`docs/launch/SHOW-HN.md`): title (78 chars), body, the
  lead comment (AGPL/Apache rationale, honest threat model incl. the
  solo-compose residual, the S8 review with finding counts, supply-chain
  posture incl. the web-bot-auth caveat), posting logistics, and prepared
  answers for six predictable objections. NOT posted.
- **`release.yml` armed** (was: dispatch-only stub that always refused):
  tag-push `v*` trigger + dispatch; a `gate` job that computes the publish
  decision and **hard-fails any publish attempt while the repo is private**
  (structural publish-safety until the S9b flip — this replaces the old
  unconditional refusal); skill signing with `MANDARE_RELEASE_KEY_PEM` +
  the S8/P1 **pin-verify gate** (`verify-openclaw-skill.mjs --expect-key`)
  — dry runs use an EPHEMERAL Ed25519 key so sign→pin→verify is exercised
  without the secret, publish-mode fails without the real one; SLSA Build L3
  job (slsa-github-generator v2.1.0 over the SHA256SUMS subjects); npm
  Trusted Publishing job (OIDC, `pnpm publish --provenance` — pnpm for the
  workspace-range rewrite, S7 M1); GHCR + cosign keyless +
  attest-build-provenance; draft-only GitHub release. actionlint clean (one
  pre-existing info-level SC2035 on our own tgz glob).
- **`docs/launch/LAUNCH-CHECKLIST.md`** — the ordered S9b runbook: 8 gates
  (founder go, trademark, re-scan, CI, G-IDENT, namespace/Trusted
  Publishing, dependency-pin decision, release dry-run) · the four founder
  to-dos F1–F4 with status · the publish sequence (repo public → npm/GH
  release → MCP registry → docs site → Show HN → **ClawHub skill LAST,
  audit-gated**) · rollback notes stating honestly what cannot be undone
  (re-privating recalls nothing; Rekor entries are permanent; npm unpublish
  is restricted — deprecate + supersede is the real path).

### Decisions (S9 latitude; BUILD-DECISIONS untouched)

1. **No history rewrite for the codename residual.** "Tessera" in old
   revisions is a name, not a secret; purging it would invalidate every
   commit hash recorded in TASKS.md/SECURITY-REVIEW-S8.md and the CI-run
   associations. Fixed at tip, accepted in history, documented. The author
   EMAIL is different — personal data — so it's a founder gate (G-IDENT),
   not a session call.
2. **Publish-safety moved from "always refuse" to "refuse while private".**
   The old stub's unconditional exit-1 can't validate the real path; the
   gate keyed on `github.event.repository.private` lets the entire pipeline
   dry-run-validate now while making pre-flip publishing structurally
   impossible — same fail-closed posture as the doors.
3. **The demo GIF is a paced replay of the real capture, and says so.** The
   live run finishes in ~0.1 s (unwatchable); recreating a slower "live" run
   would be staging. Replaying the CI-asserted capture with honest labeling
   keeps the docs-vs-claims bar D1 set.
4. **Dependency pins ship as-is (G7, recommend-ship-pinned).** next 16 /
   fumadocs 16 / orama-override drops stay scheduled post-launch; a
   dependency pass on launch day is risk with no payoff (lockfile-frozen,
   cooldown-guarded).

### Deviations from BUILD-DECISIONS

None.

### Known debt (carried; owners unchanged)

- F1–F4 founder to-dos (namespace/Trusted Publishing + release secret ·
  Stripe Issuing toggle · OTS live-smoke · OpenRouter disableKey mapping).
- G2 trademark clearance + G5 G-IDENT — founder, pre-flip.
- External audit (Q27) — gates the ClawHub skill only (Phase 6), not launch.
- Compose/Docker still CI-proven only; per-sync O(n) witness recompute +
  multi-witness knob (S6) — post-launch.

---

## S10-fix 2A — Spend & enforcement (2026-09-26)

**Scope:** the spend/enforcement findings (S-1…S-8) of the second pre-launch
audit (2026-09): an adversarial pass that found ways for a hijacked agent to
spend past its mandate. Integrity/witness (W-*, I-*) and
surfaces/packaging/release/docs (K-*, R-*, D-*) are separate fix sessions;
nothing outside the spend path was touched except where a spend fix required
it (the pricing-file row format in `demo-card.mjs` and the env reference).
Branch `fix/spend-caps`.

**Status: all eight S-* fixed, test-first.** Every acceptance test was
written first and watched fail on the pre-fix code, then driven green.
`packages/spec` untouched (R6). No red-team assertion loosened (R5) — three
existing stream/idle assertions were TIGHTENED to "settled ≥ reservation".
Full local gate green: build · typecheck · lint (+ license boundaries +
turbo boundaries) · test **616** (was 570: gateway 125→169, card-rail 62→64)
· red-team **147** (was 119: gateway 44→72) · Python 6 (was 4) · all five
demos · smoke / stack-smoke / skill-smoke / sdk-py-smoke / docs-install-smoke.
Demo 1 keeps its outcome (71 calls, €19.723587 settled, call #72
PER_DAY_EXCEEDED); the per-call reservation moved €0.27786 → €0.278853 (whole
body + hidden-prompt allowance).

### Done

- **S-1 (CRITICAL) stream settles at ~0** — `settlement.ts`: a stream settles
  exactly only on the provider's final usage + end marker (Anthropic
  `message_delta` usage + `message_stop`; OpenAI-like usage chunk + `[DONE]`).
  Anything less — stalled, cut, hung up, usage-less — is outcome-unknown and
  settles at max(reservation, what the partial picture proves): cache writes
  from `message_start` carried (no longer hard-coded 0), EVERY output delta
  type counted (thinking, tool-input JSON, `tool_calls`, refusals — by
  exclusion of metadata keys, so new delta types count by default), missing
  input estimated from the whole body.
- **S-3 (HIGH) hang-ups never detected** — detected on the RESPONSE's
  `close` before `writableFinished` (the request's `close` already fired when
  Fastify read the body). `stream-io.ts`: every wait races the abort signal —
  the next provider chunk, and the drain wait (which also races the client's
  `close`); a client that never drains within streamIdleMs is disconnected;
  the provider stream is cancelled when the door stops early.
- **S-5 (MEDIUM) header timeout was a wall-clock kill** — the stream header
  deadline is a timer cleared when headers arrive; a stream request answered
  without a stream keeps a bounded body read.
- **S-2 (HIGH) reservation not an upper bound** — `request-schemas.ts`:
  closed per-provider allowlists (Anthropic / OpenAI / OpenRouter); Fastify's
  `removeAdditional` turned off so an unlisted field is a 400 naming it, not
  silently stripped. Adapter request profiles
  (`providers/*-profile.ts`) + `reservation.ts` + `estimateRequest()`: whole-
  body UTF-8 bytes + 1,024-token hidden-prompt allowance; images at the
  documented per-image ceiling (Anthropic 4,784; OpenAI 48,169 unless the row
  names less); PDFs/uploaded files/encrypted thinking at the model context
  window; built-in client tools at a fixed overhead; `n` × the output cap;
  predicted outputs at the output rate; `cache_control` at the write rate (1h
  = 2×); `inference_geo: "us"` at 1.1×; OpenRouter fallback `models` at the
  most expensive; server tools / audio / unknown content blocks refused as
  COST_UNBOUNDED (recorded, never forwarded). The requested output cap is no
  longer trimmed to a table ceiling.
- **S-4 (HIGH) price table under-records** — `pricing-table.ts`: exact model
  ids + listed dated aliases (an unlisted variant is MODEL_UNPRICED on a
  direct provider); only `anthropic/` and `openai/` org prefixes map onto the
  table. Every default row states its cache rates (cited from the provider
  pages as of 2026-09-26); a row without one reads at the full input rate. 1h
  cache writes settle at 2× from the TTL breakdown; Anthropic web-search
  requests ($10/1,000) and OpenAI audio tokens (audio rates, high fallback)
  reach the settled cost. Operator pricing files validated strictly (retired
  `prefix` format, unknown keys, negative/non-finite rates refuse to load).
  Current Claude and OpenAI chat models added.
- **S-6 (LOW) refusal floods** — `denied-coalescer.ts`: per (actor, code) a
  burst of 32 DENIED entries, then 8/s; kill refusals keep their door-wide
  throttle; human approval outcomes are always recorded.
- **S-7 (LOW) Python repr leak** — `TokenCredentials.pop_secret` is
  `repr=False`.
- **S-8 (LOW) unmetered card creation** — `create-velocity.ts`: at most 5
  creations per agent per rolling minute, counted from the door's own
  `card.create.intent` entries (rebuilt at startup, so a restart does not
  reopen the window); refused before any ledger write or Stripe call.
- Red-team additions: `stream-settlement` (S-1/S-3), `billing-dimensions`
  (S-4), S-2 probes in `hostile-input`, S-6 flood in `budget-race`.

### Decisions (fix-session latitude; BUILD-DECISIONS untouched)

1. **No final usage ⇒ never below the reservation** (the non-stream
   outcome-unknown rule, applied to streams). Over-recording a cut stream is
   the safe direction for a cap; a Storno entry reconciles later.
2. **Allowlist = refuse, not strip.** A stripped field silently turns the
   agent's request into a different one; a 400 naming the field is the loud,
   typed failure R4 asks for. Cost: new provider features need an allowlist +
   pricing change before they pass the door.
3. **Bound what bytes cannot, refuse what cannot be bounded.** Per-image
   ceilings and the context window come from provider documentation; per-use
   fees with injected content (server tools) and audio-rate tokens are
   refused rather than guessed at.
4. **S-6 is a burst limiter, not a 1-per-window throttle,** so the
   budget-race red-team's "every refusal left an auditable entry" (R5) holds
   while a loop is still bounded.
5. **S-8 velocity is a ledger read model,** like the card registry, not an
   in-memory counter that a restart resets.

### Deviations from BUILD-DECISIONS

None.

### Known debt / residuals (open, owners noted)

- ~~**Unpriced OpenRouter models** (incl. `openrouter/auto`) still reserve the
  per-tx cap while the reported cost settles unguarded: one such call can
  settle past the per-tx and day caps. Sibling of S-2, pre-existing S2 design
  (Q14). Options: price every OpenRouter model an operator allows and refuse
  the rest; or inject `provider.max_price` derived from the per-tx cap.
  Needs a decision — the budget-race red-team fixtures use `openrouter/auto`.~~
  **RESOLVED in S10-fix 2D** (fail-closed: refused MODEL_UNPRICED; priced
  calls carry a `provider.max_price` ceiling) — see below.
- `redacted_thinking` blocks reserve the context window (encrypted,
  plaintext size unknown) — safe, but heavy on 1M-context models.
- Card rail settles the authorized amount; Stripe over-/force-captures that
  never reach the webhook are not reconciled (audit note, not reproduced).
- `SseParser` keeps every event of a stream in memory (`all()`); bounded by
  stream length, minor.
- Docs/claims follow-ups for the docs session: demo captures show the
  4th-decimal reservation drift; "overshoot is prevented by construction"
  needs the unpriced-OpenRouter caveat until the residual above is closed.

---

## S10-fix 2D — OpenRouter spend truth (2026-09-26)

**Scope:** the one residual 2A recorded and did not fix (its first Known-debt
bullet): OpenRouter calls whose cost the reservation did not bound. The
reservation is the only cap guard and OpenRouter's reported cost settles a
call unguarded (Q14), so four holes on this rail let one call settle past the
per-tx, day and total caps. Reproduced first — `openrouter/auto` answering
`usage.cost` = $50 under the €5/€20 test mandate returned 200 and settled
€50 — then fixed test-first. Branch `fix/openrouter-spend` off `main`
(b45263a, 2A merged). `packages/spec` untouched (R6).

**Status: done.** New red-team suite `test/red-team/openrouter-spend.test.ts`
(43 tests; 39 failed on `main` before the fix — the 4 that passed are the
no-double-count guards, which already held). Full local gate green: build ·
typecheck · lint · test **659** (was 616; gateway 169→212) · red-team **190**
(was 147; gateway 72→115) · all five demos · smoke / stack-smoke / skill-smoke /
sdk-py-smoke / docs-install-smoke.

### Done

1. **Unpriced model / fallback** — `reservation.ts`: the OpenRouter exemption
   is gone. Every candidate (model + `models` fallbacks) needs a row on every
   provider, else 403 `MODEL_UNPRICED`, recorded, never forwarded.
   `openrouter/auto` is always unpriced (it routes anywhere) — `findPricing
   ('openrouter/auto') === null` stays.
2. **Price ceiling** — `openrouter-spend.ts`: every priced OpenRouter call is
   forwarded with `provider.max_price` = `{prompt, completion}` at the row's
   effective rates ($/M, after `scalePricing`), `request: 0`, and `image`
   ($/image = the row's per-image token ceiling at the input rate) only when
   the request carries images — that per-image fee is also reserved on top of
   the image tokens. With fallbacks the reservation and ceiling use a
   worst-case row (each rate at its max across candidates, window at its
   min). An agent's own `max_price` merges field by field under `min()`
   (lower yes, raise never; invalid values and undefined keys dropped);
   `provider` must be an object (400 otherwise).
3. **BYOK truth** — `openai-like.ts` `reportedCost`: `is_byok: true` settles
   `cost + cost_details.upstream_inference_cost`; `is_byok: false` settles
   `cost` (an upstream figure there is what OpenRouter paid, already inside
   `cost` — adding it double-counts); `is_byok` absent settles cost + upstream
   only when upstream > cost (the BYOK signature, the fee being 5% of it). A
   BYOK block missing either figure is `costIsPartial` → settles
   max(reservation, what it proves), never at the fee alone. The reservation
   carries the 5% BYOK fee on top of the list-price bound (`withByokFee`),
   since the door cannot know up front whether a key is BYOK.
4. **Fee-adding variants** — `openrouterBaseModel`: only `:free` and
   `:floor` (can only cost the same or less) map onto the base row; every
   other suffix — `:online` (web-search fees), `:nitro` (admits priority/fast
   tiers), `:exacto`, `:thinking`, `:extended`, `:batch`, unknown — is
   `COST_UNBOUNDED`, even when a row names the suffixed id exactly.
5. **Default rows** — dotted OpenRouter Claude ids as `aliases` on their
   dashed rows (fable-5.1, opus-5.5, opus-4.8/4.7/4.6/4.5/4.1, sonnet-4.6/
   4.5, haiku-4.5), each verified on `openrouter.ai/api/v1/models` with list
   rates equal to the row.
6. **Dimensions `max_price` does not name** (verified against
   `/api/v1/models/{id}/endpoints` for every default Claude row + gpt-5/
   5-mini/4o-mini/4.1, 2026-09-26: regional endpoints are +10% and the
   Anthropic fast tier 2× on prompt/completion, with their cache rates scaled
   by the same factor; cache reads ≤ prompt everywhere; no endpoint lists
   `internal_reasoning`; Sonnet 4.5 has a long-context override from 200K
   prompt tokens):
   - cache writes: `cache_control` anywhere in the body reserves the prompt at
     the write rate (any non-`5m` TTL at the 1h rate); a row that STATES a
     write rate reserves at it even without a breakpoint (OpenRouter enables
     caching by model capability);
   - long-context overrides: a row's `maxInputTokens` is where its rates stop
     holding — an OpenRouter request whose input bound reaches it is
     `COST_UNBOUNDED`, and a row with no window cannot run through OpenRouter;
   - reasoning: `reasoning.max_tokens` is reserved at the output rate on top
     of the output cap (OpenRouter: the cap covers reasoning on "most"
     providers — not all);
   - web search / plugins / server tools / audio: already refused (2A
     allowlist + `:online` above).
7. **Scripts + claims** — `scripts/smoke.mjs` uses `openai/gpt-4o-mini`.
   `demo-card.mjs`'s row got a window and a rate that makes the €2.50
   settlement fit its reservation (€2.626 reserved vs the ~€0.003 before —
   the demo used to settle ~800× its reservation); its mock serves only
   under the door's ceiling. Demo 4 keeps its numbers (LLM €15.00, card
   €4.20 approved / €3.00 declined, €19.20 settled). The overshoot sentence
   in `docs/launch/SHOW-HN.md` and `examples/01-runaway-budget-cap/README.md`
   now reads "Given a correct price table, …"; `threat-model.mdx:27` claims
   only the race closure, which is accurate — left as is. The env reference
   says OpenRouter rows need `maxInputTokens` and become `max_price`.

### Changed test assertions (R5 — nothing deleted, nothing loosened)

The shared chat fixture (`test/helpers.ts` `chatBody`) used `openrouter/auto`,
whose €5 reservation was the per-tx cap itself. It now uses
`test/per-tx-sized`, a test row (`$47,619/M` out, input free, 100-token max,
1M window) that `openTestGateway` loads by default (`TEST_PRICING`, new
`pricingTable` option); `CHAT_RESERVATION_MICROS` (= 4,999,995) is derived
from `planReservation` itself.
- `budget-race` 25-way race: `completed ≥ 4` → `completed ≥ floor(CAP /
  RESERVATION)` plus a new assertion that this is 4; cap-never-pierced,
  every-refusal-recorded and projection == replay unchanged.
- `budget-race` sequential fill + burst: new precondition assertion that the
  €5.30 remainder fits exactly one reservation; "exactly 1 winner of 10" and
  settled = 4 × €4.90 unchanged.
- `budget-race` per-tx bound: `intent ≤ per-tx` kept, plus `intent ===
  CHAT_RESERVATION_MICROS` (stronger).
- `gateway.test` budget exhaustion: new assertion that the derived admission
  count is 7; `completed === 7`, `PER_DAY_EXCEEDED`, 15 entries unchanged.
- `provider-failure` no-echo test: payload model `openrouter/auto` →
  `test/per-tx-sized` (an unpriced model is now refused before the throwing
  reservation under test is reached) and a new `status === 503` assertion.
- `witness-gate` threshold test: comment only ("just under" the €5
  threshold, not "far below").

### Decisions (fix-session latitude; BUILD-DECISIONS untouched)

1. **Retired: "OpenRouter is exempt — an unpriced model reserves the full
   per-tx cap."** It was never a recorded decision, only an S2 code comment
   (`git show cc55524:packages/gateway/src/server.ts`, line 662). Reserving the
   cap bounded nothing: settlement is unguarded, so the cap was only the
   reservation, never the bill. Replaced by the founder's DECISION (fail-
   closed, this session's prompt): unpriced OpenRouter models are refused
   like direct ones; operators price the OpenRouter models they allow via
   `MANDARE_PRICING_PATH`. **Q14 is unchanged** — OpenRouter's reported cost
   is still authoritative at settlement; it is now also bounded up front.
2. **Ceiling at the row, not at the per-tx cap** (the Alternative was not
   chosen): a row-rate ceiling excludes pricier endpoints without the live
   probe and without a per-dimension proof the cap-derived ceiling needed.
3. **BYOK fee headroom on every OpenRouter reservation (+5%).** The door
   cannot see which key an endpoint uses before the call.
4. **`maxInputTokens` is required for OpenRouter rows.** Without a window the
   long-context override threshold is unknown, so the call is unbounded.
5. **No live call.** The non-BYOK `upstream_inference_cost` question was
   settled from OpenRouter's typed response schema (`is_byok?: boolean`,
   `cost_details.upstream_inference_cost?`) and the rule is safe either way
   (`is_byok: false` ⇒ `cost` only); no spend was needed.

### Deviations from BUILD-DECISIONS

None.

### Residuals (open, owners noted)

- "Overshoot is prevented by construction" now holds on the LLM rail **given
  a correct price table** and OpenRouter honoring its own `max_price` — the
  same trust Q14 already places in its reported cost. What the table cannot
  know stays a premise: an endpoint billing cache reads above its prompt
  rate or cache writes above the row's multiplier (none does today), a new
  per-use fee on a plain text call, and a BYOK usage block that omits both
  `is_byok` and the upstream cost (undetectable; settles the fee only).
- Operator cost of fail-closed: `openrouter/auto`, `~…-latest` aliases and
  `:nitro`/`:online` variants no longer pass the door; OpenRouter Claude
  calls reserve input at 1.25× (stated write rate) plus 5%.
- **For 2C (docs owner):** `examples/01-runaway-budget-cap/README.md:43`
  claims the race test runs "on SQLite and Postgres", and `threat-model.mdx:27`
  says "a 20-way race test" — the test is 25-way on SQLite; check both. The
  threat model could also state the price-table premise explicitly. Only the
  two overshoot sentences were edited here.

---

## S10-fix 2B — Integrity, crypto & witnessing (2026-09-26)

**Scope:** the integrity/witness findings (W-1…W-5, I-1…I-5) of the second
pre-launch audit (2026-09). Spend (2A/2D) and surfaces/packaging/release/docs
(K-*, R-*, D-*) are other sessions; nothing outside the verify/witness/ledger
storage path was touched except the docs that described it. Branch
`fix/witness-verify` off `main` (3ab3030).

**Status: every W-* and I-* fixed test-first, except the spec half of I-4
(binding `key_provenance` into the hash preimage), deferred on purpose.**
Each acceptance test was written first and watched fail on the pre-fix code,
then driven green. **`packages/spec` untouched — no schema bump** (W-3 changes
stored bytes, not the hash preimage). No red-team assertion loosened (R5).
Full local gate green: build · typecheck · lint (+ license boundaries + turbo
boundaries) · test **726** (was 659: cli 24→43, verifier 62→76, ledger 71→82,
witness-protocol 46→56, witness 19→27, dashboard 17→22; embedded-Postgres
suites ran, 0 skipped) · red-team **210** (was 190: ledger 38→48, witness
12→19, cli 0→3 — a new red-team suite) · all five demos · smoke / stack-smoke /
skill-smoke / sdk-py-smoke / docs-install-smoke · Python unittests.

### Done

- **W-1 (HIGH) `verify --witness` trusted the file's source id** —
  `apps/cli/src/witness-check.ts`: the witnessed history is looked up under
  the source the VERIFYING key defines: sha256(`--door-key`); in directory
  mode every key that signed the chain (every directory key for an empty
  chain); self-anchored, sha256(`meta.door_public_key`), labeled
  "self-declared source — pass --door-key to bind". A declared
  `door_key_id` that disagrees is `SOURCE MISMATCH`, exit 1. `certify`
  refuses a meta whose `door_key_id` ≠ sha256(`door_public_key`). Dashboard:
  optional out-of-band `MANDARE_DOOR_PUBLIC_KEY`, the SELF-ANCHORED caveat
  otherwise, a red witness badge on a mismatch. Demo 5 gained copy C (the
  split timeline: truncate with no key, re-witness under a fresh source,
  repoint) and now verifies with `--door-key`. Red-team:
  `apps/cli/test/red-team/witness-split-timeline.test.ts` drives the built
  binary (2 of 3 cases fail on the pre-fix code); acceptance
  `apps/cli/test/verify-witness-source.test.ts` (10 cases).
- **W-2 (MEDIUM) OpenTimestamps hexlify bomb** — `ots.ts`: op message ≤ 4096
  bytes, result ≤ 4096 and non-empty (so hexlify input ≤ 2048), the
  python-opentimestamps bounds; calendar responses read through a 64 KiB
  bounded reader. `certificate.ts` parses a receipt only after the epoch is
  witness-signed and the leaf is proven in it. N=40 bomb → typed error in
  < 100 ms; bomb certificate → INVALID; red-team: a hostile calendar (bomb or
  endless stream) leaves the witness up with an honest `none` receipt.
  (Incidentally reproduced the audit's OOM: a stale build ran the bomb and
  the worker reached 3.7 GB before it was stopped.)
- **W-3 (MEDIUM) duplicate-key parser differential + INSERT OR REPLACE** —
  doors store `canonicalJson(entry)` (SQLite, sync Ledger, Postgres).
  Verifier `parseStoredEntry`/`parseStoredEntries` (pure, portable) accept a
  row only if its text is a single-reading encoding of what it parses to
  (canonical, or `JSON.stringify` for pre-fix rows) and its seq/entry_hash
  columns match; otherwise the new `STORAGE_MISMATCH`. `readLedgerRows` /
  `store.readAllRows` expose raw rows; `mandare verify` and `certify` run the
  check before the chain. BEFORE INSERT triggers refuse any insert colliding
  with an existing seq / entry_hash / meta key, on SQLite and Postgres. The
  dashboard parses rows in JS through `parseStoredEntry` (never
  `json_extract`) and flags refused rows. The threat-model trigger claim is
  now true and says the triggers are a speed bump.
- **W-4 (MEDIUM) rotated-out key + backdated ts** — `verifyChain` fails a
  validly signed entry dated before its predecessor, or not a real instant,
  with the new `TS_REGRESSION`; doors clamp the next ts to the head's (both
  drivers read it), so a wall clock stepping back cannot make an honest chain
  regress. `verify --witness`: the newest entry a witness-signed head covers
  may not claim a ts after `witnessed_at` + 5 min (`TIMELINE VIOLATION`).
  `KEY-DIRECTORY.md` states what is caught and the residual below. Red-team:
  ROTATION + BACKDATE (old key writes behind the new key's entry with ts
  inside its own window — the window check passes it, the timeline convicts).
- **W-5 (LOW) open `POST /v1/anchor/run`** — `anchor-gate.ts`: bearer token
  (`MANDARE_WITNESS_ANCHOR_TOKEN`) from anywhere, or loopback + loopback Host +
  `x-mandare-anchor: run`; one on-demand run per minute (429 + Retry-After).
- **I-1** — a disclosure past the witnessed head is recorder-attested "not
  witnessed"; an unanchored certificate gets a public-anchor NOTE;
  `certify verify` prints every residual (and includes them in `--json`).
- **I-2** — `WITNESSING.md` / `aggregate.ts` now say certificates reveal the
  epoch's source count and this source's rank (not who the others are).
- **I-3** — `--key-directory http://…` refused unless `--insecure-directory`;
  an opted-in run labels the anchor INSECURE.
- **I-4 (verifier half)** — an undecodable signature is `SIGNATURE_INVALID`,
  not a throw inside `verifyChain`.
- **I-5** — witness `runUpgrade()` upgrades pending OpenTimestamps receipts
  and stores the Bitcoin attestation; `mandare witness serve --anchor ots`
  (and compose) runs it hourly. "Bitcoin finality" claims reworded to
  "pending until the calendars' Bitcoin attestation lands (hours)".

### Changed test assertions (R5 — nothing deleted, nothing loosened)

- Both "in-place replay is impossible (PRIMARY KEY)" tests (SQLite, Postgres)
  now remove/disable the new `ledger_entries_no_replace` trigger first, so
  the PRIMARY KEY stays proven as an independent layer; the trigger has its
  own tests. The PK assertions are unchanged.
- `tamper.test.ts` cross-door fixture: the foreign entry was dated in the past
  (before the chain); it is now dated after it, since the timeline may not
  regress. Assertions unchanged.
- Witness red-team `witnessVerdict` distillation looks up
  sha256(`door_public_key`) instead of `meta.door_key_id` (tightened, mirrors
  the CLI).
- `server.test.ts` "anchor run with no sources" sends `x-mandare-anchor: run`;
  assertion (409) unchanged.
- The binary-driven CLI red-team suite has a 30 s per-test budget (two cold
  Node starts per case); no retries.

### Decisions (fix-session latitude; BUILD-DECISIONS untouched)

1. **A source mismatch fails verification** (exit 1), in every mode — a
   ledger whose declared source is not the verifying key's is not a
   warning-level oddity, it is the W-1 attack's fingerprint.
2. **W-3 needs no spec change.** The hash preimage is canonical JSON already;
   what changed is the stored text and the reader check. Pre-fix rows
   (`JSON.stringify`) are accepted because that encoding also has one
   reading. `STORAGE_MISMATCH` lives in the Apache verifier so third-party
   readers can run the same check.
3. **W-4 "better" option, bounded honestly.** Non-decreasing ts + a writer
   clamp is enforceable; "the first witnessed head covering each seq" is not —
   the witness serves per-record history unsigned — so the witness-time bound
   uses the latest signed head only. The remaining gap is documented, not
   papered over.
4. **W-5 gates one action, not the witness.** Doors on other hosts must keep
   submitting heads; only on-demand anchor runs are an operator action.
5. **The dashboard takes `@mandarelabs/verifier` as a runtime dependency**
   (AGPL → Apache is allowed) so it runs the exact row check `mandare verify`
   runs.
6. **I-4's preimage binding waits** for a deliberate spec session (R6: plan
   mode + schema bump), before Tier-3 attestation relies on
   `key_provenance`.

### Deviations from BUILD-DECISIONS

None.

### Residuals (open, owners noted)

- **W-4 backdated tail:** a thief holding a rotated-out key can append to a
  chain the successor key never wrote to (e.g. a rotated door's retired
  ledger), with ts inside the old window; the witness accepts the growth (the
  thief holds that key). Only `witnessed_at` > `exp` exposes it, and only the
  latest head is signed. Closing it needs signed per-record witness history
  (protocol change) — owner: next witness-protocol session.
- **W-1 directory mode** checks the history of keys that signed the presented
  chain. A multi-key chain truncated so that NO entry of the newest key
  remains is checked only against the older keys' histories. At this tier a
  ledger DB has one writer key (`assertDoorOwnsMeta`), so this needs a future
  multi-key writer to matter.
- **Self-anchored verification** still cannot catch a full re-key forgery
  (re-signed under a new key, meta and witness source all repointed) — now
  labeled as a self-declared source on every run.
- **`TS_REGRESSION` on pre-fix ledgers:** an honest ledger written before the
  clamp across a wall-clock step-back would now fail. None exist pre-launch.
- **I-4 spec half** (`key_provenance` outside the preimage) — see decision 6.
- **F3 (live OTS smoke)** is now able to pass as coded and has a command:
  `pnpm ots-live-smoke` (stamp), then again 3–6 h later (upgrade → PASS on a
  Bitcoin attestation). Proven here only against a local mock calendar; the
  public-calendar run is the founder's gate.
- `docs/VERIFY-YOURSELF.md` (untracked, founder's file) still carries
  pre-fix wording for the `verify --witness` row; not edited here.

### Go/no-go after 2B

Integrity side: **GO** — audit blocking items #4 (W-1) and #11 (W-2, W-3,
W-4) are fixed with red→green tests, W-5 and I-1…I-5 too. The launch as a
whole stays **NO-GO for Thu 2026-10-01** until 2C lands (K-1 wording, R-1,
D-1, R-2, R-3, G-1 if the rewrite is kept), CI is green on origin at the flip
SHA, G3/G8 are re-run there, and the founder gates (G1, G2, F1, G5) close.

---

## S10-fix 2B follow-up — real OpenTimestamps proofs (2026-09-27)

**Found by founder gate F3.** The first live run (`pnpm ots-live-smoke`)
stayed "still pending" for 17 h although both calendars had long since
served the Bitcoin proof (HTTP 200). Two bugs, both invisible to CI because
the mock calendar's proofs are shallow:

1. **The OTS parser refused every real Bitcoin proof.** A real upgrade is one
   long op chain — measured 70–75 levels for the calendar reply alone, ~90
   merged into the receipt — and the S6 nesting cap was 64 ("timestamp tree
   too deep"). Consequence beyond F3: no live witness could ever confirm an
   anchor, and a certificate carrying a real upgraded receipt would have been
   graded INVALID (proof-basis "unparseable"). Cap raised to 256
   (python-opentimestamps' deserialization limit); work stays bounded by the
   4096-node and 4096-byte op bounds (W-2), and a 300-op chain is still refused.
2. **Upgrade failures were silent.** One calendar erroring aborted the whole
   upgrade (so it could block another that had the proof), and `runUpgrade`
   logged the error into a disabled logger — the smoke reported "pending".
   Now each calendar is tried independently; no upgrade + any failure throws
   naming the calendar; `runUpgrade` returns `failures`; the smoke exits 1
   with `UPGRADE FAILED …`; `witness serve` logs them.

**Evidence:** golden fixture `packages/witness-protocol/test/fixtures/
ots-real-upgrade.json` (the real pending receipt + the Bitcoin-attested
replies from bob and finney, public proof data over a throwaway root); new
tests red on the old code (parse, full upgrade, one-failing-calendar,
failure reporting). The fixed smoke run against a COPY of the founder's state
PASSED (block 968682, 17.3 h), and both attested messages equal the Merkle
roots of Bitcoin blocks 968682 and 968707 (mempool.space). test **732** (was
726), red-team 210, Demo 5 green. The founder's own F3 run is still to do
(after this merges: `pnpm build`, then `pnpm ots-live-smoke`).

---

## S10-fix 2C — Surfaces, packaging, release & docs (2026-09-27)

**Scope:** the K-, R-, D-* findings of the second pre-launch audit (2026-09)
plus the doc drift it listed. Branch `fix/release-and-packaging` off `main`
(5f2e478). `packages/spec` untouched. No red-team assertion loosened (R5);
skill-smoke only gained cases.

**Status: every K-, R-, D-* fixed except the K-1 architecture (kill-only
path), which gates Phase 6 (ClawHub), not the flip.** Full local gate green:
build · typecheck · lint (+ license + turbo boundaries) · test **742** (was
732: cli 43→50, mcp-server 7→10) · red-team **210** · all five demos · smoke /
stack-smoke / skill-smoke / sdk-py-smoke / pack-install-smoke (new) /
docs-install-smoke (now genuinely fresh: 0 of 15 cached) · Python unittests.
actionlint clean.

### Done

- **R-1 (npm set uninstallable)** — `PUBLISH_PACKAGES` is the CLI's 12-package
  closure in dependency order (+ ledger, vault, card-rail, witness; mcp-server
  after cli). New `pnpm pack-install-smoke` (CI smoke job + release job):
  reads the list from release.yml, checks closure/order, packs, `npm install`s
  ONLY the tarballs into an empty dir, runs the installed `mandare help` and an
  MCP initialize + tools/list. Red on the old list (closure check, and E404 on
  `@mandarelabs/card-rail` when bypassed), green after. The same smoke caught
  three more first-publish blockers the audit missed: no package had a
  `repository` field (npm rejects `--provenance` when repository.url doesn't
  match), `@mandarelabs/mcp-server` lacked `mcpName` (MCP registry npm
  ownership check), and `server.json` used the pre-2025-09 snake_case schema
  with a >100-char description. All fixed; server.json validated against the
  published 2025-12-11 schema.
- **R-2 (Next criticals)** — lockfile-only refresh, no range changed,
  `minimumReleaseAge` respected: next 15.5.26, fastify 5.12.5, find-my-way,
  fast-uri, qs, hono, nanoid, js-yaml, sharp, image-size, vitest 3.2.7,
  brace-expansion. `pnpm audit --prod` 34 (2 critical) → 4 (0 critical): all
  postcss 8.4.31, pinned exactly by next, build-time only. Dev: vitest 4
  advisory (major). Transitive bumps were done with temporary overrides that
  were removed again (the lockfile keeps the resolutions; frozen install OK).
- **R-3 (unpinned actions)** — every `uses:` pinned by commit SHA with a
  `# vX.Y.Z` comment (first-party actions too); SLSA generator stays on its
  tag. Gate refuses publish from any ref that is not `refs/tags/v*`; every
  publish job needs a v* ref, and all but the reusable SLSA call run in the
  `release` environment. `.github/dependabot.yml` for github-actions.
- **R-4 (real key on dry runs)** — the release key is read by exactly one job,
  `sign-skill-release` (publish + v* tag + `release` environment), which only
  checks out, sets up Node and runs two dependency-free scripts. Dry runs sign
  in `sign-skill-dry` with an ephemeral key. build/test never see a key.
- **K-3** — `scripts/sign-openclaw-skill-release.mjs` writes `RELEASE-KEY.hex`
  BESIDE the package; build-and-pack re-verifies the downloaded package with
  that pin before hashing; the draft release attaches the skill tarball and
  the hex. Docs show `--expect-key` everywhere (pin source:
  mandare.dev/security + the release asset).
- **K-2 / K-7** — the verifier accepts only the packager's exact envelope
  serialization (extra keys, signature extras, duplicate keys fail), only
  regular files whose realpath is inside the package (any symlink fails), and
  a pinned key always requires a signature (`--allow-unsigned` no longer
  overrides `--expect-key`). skill-smoke: K-7, three injection variants, two
  symlink variants, and the release-signing K-3 case.
- **D-1 (docker demo died on velocity)** — compose-demo prices each runaway
  call higher (claude-sonnet-4-6 × 60k ≈ €0.84) so the €20 day cap fires
  first at the untouched default 60/min, requires `PER_DAY_EXCEEDED`, prints
  `REFUSED: call #24 PER_DAY_EXCEEDED` (23 calls, €19.167947). stack-smoke
  takes the gateway env from compose.yaml's own block (defaults resolved,
  parent MANDARE_* scrubbed) and fails if ci.yml or README / quickstart /
  SHOW-HN disagree with the printed refusal; CI greps the line. Red with the
  old model: `VELOCITY_EXCEEDED` at #61, as the audit reported. `pnpm demo`
  keeps its velocity override, now disclosed.
- **K-1 wording** — skill, skill README, OpenClaw and MCP pages now say the
  kill needs operator-level door access (the same key allows reinstate and
  arbitrary signed entries); the no-reinstate rule is an instruction, not a
  boundary; MCP `ALLOW_REINSTATE` is a tool-surface restriction only.
- **K-4** — CLI: `--help` only directly after the command, `--` ends flags;
  MCP: argv-bound strings may not start with `-`, and `mandare_kill` reports
  success only on a `KILLED` line.
- **K-5** — passport issue checks both paths before touching the ledger and
  creates both files atomically without overwrite (temp + link(2)).
- **K-6** — `*.agent-key.json`, `*.token.json`, `*.pem` gitignored; every
  `.dockerignore` secret pattern is `**/`-anchored; passport issue defaults
  to `~/.mandare/agents/` (0700), MCP home to `~/.mandare/mcp`.
- **R-5** — two-stage Dockerfile: production-only reinstall, runtime stage
  runs as `node`, `/data` + `/witness-state` pre-owned. The dashboard config
  moved to `next.config.mjs` because `next start` tries to install
  TypeScript for a `.ts` config — found by running the pruned tree locally
  (no docker on this machine; compose-smoke in CI is the real check).
- **Doc drift** — REPRODUCING (release.yml armed), install.sh (the corepack
  global write), quickstart (.env keys behind an open door don't hold; route
  to vault + auth; dashboard badge self-anchored unless
  `MANDARE_DOOR_PUBLIC_KEY`), W-1 caveats + `--door-key` on the witness claims
  (README #5, SHOW-HN, WITNESSING, cli ref, self-host, skill), new outcome
  codes in WITNESSING, "independent reviewers" → AI-assisted passes with the
  external audit pending (README, SHOW-HN, SECURITY-REVIEW-S8), Demo 1–4
  captures re-taken, LAUNCH-CHECKLIST (F1 ×12 + `release` environment secret,
  F3 DONE with the founder's evidence, PVR + org 2FA in Phase 1, docs deploy
  before the tag, K-1 kill-only path as a Phase 6 gate).

### Decisions (fix-session latitude; BUILD-DECISIONS untouched)

1. **D-1: make the docker demo hit the budget, don't restate the number.**
   The docker path is what Show HN readers run; it should show the product's
   headline stop, at the stack's real defaults. The velocity default is
   unchanged.
2. **The release key moves to an environment secret** on `release`, not a
   repo secret — so no job without that environment can read it at all.
3. **All actions are SHA-pinned**, first-party included; Dependabot keeps
   them current.
4. **Review wording**: the S8 and 2026-09 reviews are described as
   AI-assisted and not organisationally independent, per the audit's §4a.

### Deviations from BUILD-DECISIONS

None.

### Residuals (open, owners noted)

- **K-1 architecture** — a kill-only path (kill-only key or gateway endpoint
  that verifiers accept for `agent.revoke` alone, recording the invoking
  principal). Gates LAUNCH-CHECKLIST Phase 6 (ClawHub). Owner: a dedicated
  session; likely touches the key directory's role semantics — check R6 first.
- **Docker image not built locally** (no container runtime here): the R-5
  stages were simulated (production-only reinstall of a clean copy, stack
  topology + dashboard served from it); CI compose-smoke is the proof.
  Volumes created by the old root image need `docker compose down -v`.
- **The release workflow's new job graph has never run** — G8 (founder
  dispatch, publish=false) is its first execution; expected: gate, then
  `sign-skill-dry` → `build-and-pack` green, everything else skipped.
- **`docs/demos/runaway-demo.cast/.gif`** still show the pre-S8 5th-decimal
  estimate (regenerating needs the render toolchain; cosmetic).
- **postcss 8.4.31** (next's exact pin) and **vitest 3** advisories remain —
  build-time/dev only; G7 / a later dependency pass.

### Go/no-go after 2C

Code side: every audit blocking item owned by 2C (#5 K-1 wording, #6 R-1,
#7 D-1, #8 R-2, #9 R-3) is fixed and tested; with 2A/2B/2D merged the
audit's code blockers are closed. **The launch stays NO-GO for Thu
2026-10-01** until: CI is green on origin at the flip SHA (all 6 jobs,
incl. compose-smoke — never run with these changes), the founder re-runs G3
(both scanners) and G8 there, and the founder gates close — G1, G2
(trademark; unscoped npm `mandare`, PyPI `mandare`/`mandare-sdk` still
unclaimed), F1 (Trusted Publishing ×12, `release` environment + secret, MCP
DNS TXT), PVR + org 2FA, mandare.dev/security deployed, and G5 (the rewrite:
content scrub + fresh repo, its own pass).

---

## G5 — History rewritten (2026-09-27)

**Gate G5 (G-IDENT) closed by rewriting the history into a fresh repository.**
Before the flip, every commit carried the founder's personal account (handle +
e-mail) as author and committer, and three files quoted it. The whole history
was rewritten with `git filter-repo` on a mirror clone, then pushed to a NEW
private `mandarelabs/mandare`. The old repository was renamed to
`mandarelabs/mandare-private-archive` and stays private, so the old commits are
never reachable from the public repo by SHA or through old Actions runs.

- **Identity:** author and committer on all 77 commits of `main` =
  `Mandare Labs <arthur@mandarelabs.com>`. The `Co-Authored-By: Claude`
  trailers are kept (77/77).
- **Timestamps:** every offset normalised to `+0000`; the instants (epoch
  seconds) are unchanged, checked commit by commit.
- **Content scrub:** the one quoted string was replaced in every historical
  version of TASKS.md, `docs/launch/LAUNCH-CHECKLIST.md` and
  `docs/launch/SECRET-SCAN-S9.md` ("under the founder's personal account
  (handle + e-mail)"). The tree of the new `main` differs from the old one
  only in those 3 files (4 lines).
- **Verified on the rewritten mirror:** 0 hits for the handle/address in
  authors, committers, messages, every blob of every commit and every raw
  object. G3: `gitleaks git --log-opts="--all" .` → no leaks found (78
  commits); `trufflehog git file://. --no-update --fail` → 0 verified,
  0 unverified.
- **Pushed:** `main` only. The merged `fix/*` branches, the Dependabot branch
  and the `refs/pull/*` refs stay in the archive. There were no tags.

**Old → new SHAs.** Every commit SHA, CI run id and release-dry-run id recorded
earlier in this file, in `docs/SECURITY-REVIEW-S8.md` and in `docs/launch/*`
refers to the OLD history in the private archive. The recorded merge points
map as follows:

| Old (archive) | New | What |
|---|---|---|
| `cc55524` | `291ba80` | S9 |
| `8c05d20` | `eb92357` | S8 |
| `b45263a` | `73a7ee7` | S10-fix 2A merged |
| `3ab3030` | `0c06246` | S10-fix 2D merged |
| `013e44f` | `6c3097d` | S10-fix 2B merged |
| `5f2e478` | `7674601` | OTS depth-cap fix merged |
| `9af7acc` | `d773515` | S10-fix 2C merged |
| `8e56fcb` | `9bdca82` | G5 Step 0 (CLA allowlist + Show HN wording); old → new `main` |

**Consequences.**
- The new repo starts with no environments, secrets, branch settings, Actions
  history or PR history. F1 Parts 2–4 (`release` environment + secret, npm
  Trusted Publishing ×12, MCP DNS TXT) run on this repo.
- The `cla-signatures` branch was created at `9bdca82`. The CLA workflow's
  allowlist covers `dependabot[bot]`, `github-actions[bot]` and the
  maintainer account. Branch protection on `main` must not cover
  `cla-signatures`, because the action commits to it.
- Dependabot reopened its GitHub-Actions bump PR here. It stays unmerged until
  after v0.1.0 (its major bumps touch only the publish jobs, which the G8 dry
  run skips).
- G4 (CI on the new `main`) and G8 (release dry run) must be re-run on this
  repo; LAUNCH-STATUS records the run ids.

---

## CI flake fix — ledger red-team + MCP server (2026-09-27)

**Scope:** three CI tests that each failed once on 2026-09-27 and passed on
re-run with identical code. Branch `fix/test-flakes` off `main` (78bbffe).
Test code only: no `src/` file, no `packages/spec` file and no workflow
changed. No red-team assertion loosened (R5).

**Status: all three root causes found, reproduced locally, fixed.** Loops on
Node 22.23.3 and 24.21.0 (macOS arm64):
ledger suite 12/12 per version idle and 8/8 per version under 24 CPU hogs;
mcp-server 15/15 per version under the same load. Full local gate green
(build · typecheck · lint · test · red-team).

### Done

- **Ledger REPLAY (SQLite, Node 24 job, `ledger is append-only`).** The test
  forged the duplicated row's hash as `'aa' || substr(entry_hash, 3)`. Entry
  hashes are random per run, so 1 time in 256 the real hash already starts
  with `aa`. The "forgery" is then the original hash, and the W-3
  no-collision trigger refuses the INSERT before the tamper reaches
  verification. Reproduced with a 3000-iteration loop of the old SQL:
  15/3000 failures on Node 22 and 13/3000 on Node 24, each one exactly an
  `aa`-prefixed hash (errcode 1811, same message). The Postgres suite's
  REPLAY had the same flaw (only `append_only` is disabled there, so
  `no_replace` fired too). Fix: `forgedHashSql(prefix, fallback)` in
  `test/helpers.ts` swaps in the fallback when the real hash already
  carries the prefix. After the fix: 0/6000 inserts threw and 6000/6000
  forgeries were caught by verification, 21 of them through the fallback
  branch. Same assertions as before; the collision attack itself stays
  covered by the W-3 tests. GAP INJECTION's `deadbeef` forgery (2^-32) got
  the same guard.
- **Ledger projection-race (Postgres, same job, ECONNREFUSED
  127.0.0.1:55732).** Ports were `556xx + pid % 100`: inside Linux's
  ephemeral range, while turbo runs every package's tests at once. The CI
  log shows Postgres "could not bind IPv4 address 127.0.0.1: Address
  already in use", listening on ::1 only, and still "ready". Reproduced
  locally by holding the port: identical log lines, identical
  ECONNREFUSED. Fix: `test/pg-harness.ts` takes the port from `listen(0)`
  and starts Postgres with `listen_addresses=127.0.0.1` and no Unix
  socket. A lost race then makes the postmaster exit (FATAL "could not
  create any TCP/IP sockets") instead of coming up half-bound, and the
  harness retries on a new port. Checked with a forced collision. Both PG
  suites use it.
- **MCP `mandare_kill closes the LIVE door` (Node 22 job, 5030 ms).** No
  hang. The test runs two cold CLI child processes (kill, then verify); the
  gateway round-trip is ~5 ms. Across 18 CI jobs it took 1.4–5.0 s (median
  ~2.9 s), with a single CLI spawn at 0.6–2.5 s; locally it takes ~320 ms.
  Reproduced on Node 22 under 10× CPU oversubscription: 3.8–4.4 s, split
  evenly between the two spawns, and one timeout in four at 5004 ms. Fix:
  the three CLI-spawning describes get `CLI_TEST_TIMEOUT_MS = 20_000` (4×
  the worst observed). The raise is justified because the work is
  legitimate process start + module load on a loaded 4-vCPU runner. A real
  hang still fails, before the CLI's own 60 s timeout.

### Decisions

- **Keep the forgery attack, guard only the prefix.** Accepting the trigger
  error as a pass would weaken R5 (the test would stop proving that
  verification catches a replay that got past storage).
- **Kernel-assigned port + fail-loud bind over a Unix-socket connection.**
  The PG suites keep exercising the TCP connection strings that team mode
  uses in production.
- **Per-describe timeout, not a package-wide `testTimeout`.** The budget
  sits next to the explanation of why it is needed.

### Handoff

- `main` is meant to stay frozen before the flip. Merging this PR changes
  it, so G8 (`gh workflow run release.yml -R mandarelabs/mandare --ref main
  -f publish=false`) and G4 must be re-run on the new `main`, and the launch
  status board updated with the new run ids.

---

## S9b — Public launch (2026-10-01)

**Status: LAUNCH-CHECKLIST Phases 1–4 done.** The repo is public, v0.1.0 is
on npm, GHCR and the MCP registry, and the docs are live. Phase 5 (Show HN)
is the founder's. Phase 6 (ClawHub) stays gated on the external audit and
K-1.

### Gates (re-run on the flip SHA `9af84513c899ce1d19e918fa1deec8bad38dcbe1`)

- G3: gitleaks 8.30.1 (no leaks, 86 commits, all refs) and trufflehog
  3.96.0 (0 verified / 0 unverified) on a fresh mirror clone. Author and
  committer on every branch: `Mandare Labs` or the GitHub bots, all `+0000`.
- G4: CI run 36408533464, 6/6 jobs green. G8: release dry run 36412282213
  green.
- A content read of every branch, all history, PR texts, run logs,
  artifacts and media metadata found nothing that had to stay private.

### Phase 1 — flip

- Visibility public. Secret scanning + push protection, Dependabot alerts
  and Private Vulnerability Reporting enabled.
- Branch protection on `main`: the 6 CI jobs required, enforced for
  admins, no force-push, no deletion. `cla-signatures` is not covered (the
  CLA action commits to it).
- About: README one-liner, homepage mandarelabs.com/docs, topics
  `ai-agents`, `budget`, `audit-log`, `transparency-log`, `mcp`.

### Phase 1b — `release` environment (after the flip, before any tag)

- Required reviewer = the maintainer account, self-review allowed,
  `can_admins_bypass: false`, deployment policy = tags `v*` only.
- `MANDARE_RELEASE_KEY_PEM` set as an environment secret. No repo-level
  secrets exist.

### Phase 2 — v0.1.0

- Lightweight tag `v0.1.0` → `9af8451`. Release run 36814384048: gate
  (`publish=true`), sign-skill-release (envelope signed with key
  `19895f32…ca66e7a8`, pin-verified), build-and-pack, SLSA L3, npm
  publish, GHCR + cosign, GitHub release, all green on attempt 1.
- npm: 12 packages at `0.1.0`, `latest` = 0.1.0, published by GitHub
  Actions through Trusted Publishing with SLSA provenance.
- GHCR: `ghcr.io/mandarelabs/mandare:v0.1.0` =
  `sha256:552119b7e0edd97d2a41d30cc5c3631014aed95a48cd84de8ae910b165996bfc`,
  cosign keyless + build provenance attestation.
- GitHub release: https://github.com/mandarelabs/mandare/releases/tag/v0.1.0
  (12 tarballs, SHA256SUMS, `multiple.intoto.jsonl`, signed skill,
  `mcp-server.json`, `RELEASE-KEY.hex`).
- Verified as a stranger (fresh npm cache, logged out): `npm i -g
  @mandarelabs/cli && mandare help`; `npx -y @mandarelabs/mcp-server`
  `initialize` + `tools/list` (8 tools); `npm audit signatures` (186
  registry signatures, 41 attestations); the npm provenance bundle via
  `gh attestation verify --bundle … --digest-alg sha512`; `cosign verify`
  with the exact `release.yml@refs/tags/v0.1.0` identity; `gh attestation
  verify oci://ghcr.io/mandarelabs/mandare:v0.1.0`; `SHA256SUMS`; the
  release's `RELEASE-KEY.hex` equals mandare.dev/security.

### Phase 3 — MCP registry

- `com.mandarelabs/mandare` 0.1.0 published (DNS auth on mandarelabs.com),
  listed at `registry.modelcontextprotocol.io/v0/servers?search=mandare`.

### Phase 4 — docs

- mandarelabs.com/docs live; mandare.dev/security → `/docs/security` with
  the key hex. Every README link resolves publicly.

### Findings (none blocked the launch)

- **The release was published, not drafted.** `generator_generic_slsa3`
  with `upload-assets: true` creates the GitHub release for the tag
  (published) before the `release`-environment jobs run; the
  `github-release` job's `draft: true` then only adds files to it. Notes
  were added by hand right after. Fix for 0.1.1: set the generator's
  `draft-release: true`.
- **GHCR packages start private.** A first push from Actions creates a
  private org package; making it public needed the org's package-creation
  setting to allow public packages first. Done; one-way by design.
- **npm read-side lag.** Four packages answered 404 for `0.1.0` for up to
  ~6 minutes after a successful publish. Check the publish log before
  suspecting a failure.
- **`gh attestation verify <tarball>` returns 404 for npm tarballs.** npm
  provenance lives on the registry; verify with `npm audit signatures` or
  `--bundle` from `/-/npm/v1/attestations/…`. The checklist wording is
  fixed in this PR; REPRODUCING.md was already correct.
- **The registry tarball of `@mandarelabs/cli` differs in hash from the
  release asset:** npm reorders two dependencies in `package.json` when it
  publishes; the file contents are otherwise identical. Each copy is
  covered by its own provenance (npm provenance / SHA256SUMS + SLSA).
- Stale npm descriptions in `apps/cli` and `packages/policy-engine`
  shipped with 0.1.0; fixed in 0.1.1.

---

## README claims fix (2026-10-01)

**Scope:** docs only (`README.md`, `CLAUDE.md`). No code, no release.

- "verified agent identity" → "signed agent identity" in the README intro
  and CLAUDE.md. In 0.1.0, requests are signed by an agent key (did:key,
  RFC 9421) under a signed mandate, with revocation. Owner KYC goes through
  the pluggable IDV interface, and its only provider is the mock
  (`packages/passport/src/idv.ts`).
- The security badge now reads "AI-assisted, audit pending" (lightgrey) instead
  of a green "S8 adversarial". It still links to `docs/SECURITY-REVIEW-S8.md`.
- The quickstart now says how to tear down: `docker compose down -v` removes
  the containers and the `mandare-data` / `mandare-witness-state` volumes.
- **Open for 0.1.1:** the docs site still says "verified agent identity" in
  `apps/docs/app/(home)/page.tsx` and in the metadata description in
  `apps/docs/app/layout.tsx`.

---

## README fix #2 — independent test findings (2026-10-01)

**Scope:** docs only (`README.md`, one comment in `install.sh`). No code, no
release. An outside tester ran the README on a clean Mac (npm CLI, MCP
server, `./install.sh` + all 5 demos, dashboard, own tamper test): all
passed; the README stated a few things less carefully than the CLI does.

- Truncation condition stated: `pnpm demo` runs without a witness, so
  self-anchored `verify` can't see entries dropped from the end of the
  ledger (refusals included) without a saved `--prev-head`; the docker stack
  runs a witness and `pnpm demo:witness` shows it catching that. The hero
  caption no longer says verify "proves" the refusal; "keeps its no's" now
  names the witness as what keeps them.
- Hero caption names the no-docker run (#72) vs the docker quickstart (#24).
- Demo spend is priced against the bundled mock provider (stated).
- Prerequisites: Compose v2 (`up --wait` ≥ v2.1.1), images build locally on
  first run; no-docker path needs Node ≥ 22.13 + pnpm 10, `corepack enable`
  if pnpm is missing.
- "Or from npm" block (`@mandarelabs/cli`, `@mandarelabs/mcp-server`);
  `install.sh` comment no longer says "after npm launch".
- Where state lands: vault master key in the OS keychain by default,
  `~/.mandare/agents/`, `<ledger>.doorkey.pem` (0600).
- **Open for 0.1.1:** `@mandarelabs/cli` npm description still says "verify,
  and later: kill, export, mandate" (source `apps/cli/package.json` too);
  deprecated `@sd-jwt/types|utils|jwt-status-list` 0.19.0 deps print npm
  warnings on install; `mandare kill` prints `vault: legacy mode (no scoped
  tokens)` without explanation; the dashboard gives no hint that the refusal
  count may be stale when no witness is configured;
  `apps/docs/content/docs/integrations/mcp.mdx` still says "After npm launch
  this becomes `npx @mandarelabs/mcp-server`".

## Day 2 — Glama listing spec + race-test docs drift (2026-10-01)

**Scope:** metadata + docs only (`glama.json`, `threat-model.mdx`,
`examples/01-runaway-budget-cap/README.md`). No code, no spec change, no
release.

- **`glama.json` (repo root).** Glama lists a server in search only once it
  builds it and the server answers `tools/list`. Glama's published schema
  documents only `maintainers`; the build keys (`baseImage`, `nodeVersion`,
  `buildSteps`, `cmdArguments` behind `mcp-proxy`, `placeholderArguments`)
  are the ones Glama's own build spec uses, taken from servers Glama lists
  with built and scored tools (one of them a monorepo subfolder with no
  Dockerfile of its own, one with a root Dockerfile next to its
  `glama.json`). Decision: install the **published**
  `@mandarelabs/mcp-server@0.1.0` from npm into `.glama/` instead of
  building the monorepo (one npm install; `node:sqlite`, so no native
  build), and create an empty throwaway ledger there at build time with
  `Ledger.open` (door id `glama-demo`), so `mandare_verify` returns a real
  verdict in Glama's inspector. `MANDARE_MCP_HOME=/tmp/mandare-mcp` keeps
  issued artifacts out of the checkout (K-6). The root `Dockerfile` (the
  self-host stack) is untouched.
- **Proved locally** (macOS, Node 24.9): the two build steps run verbatim
  from `glama.json` in a fresh clone; the `cmdArguments` run verbatim under
  `mcp-proxy` and answer, over its streamable HTTP endpoint, `initialize`
  (`mandare` 0.1.0, tools capability), `tools/list` (8 tools),
  `resources/list` + `prompts/list` (-32601, no such capability declared)
  and `mandare_verify` (`ok: true`, 0 entries, counters consistent). Not
  proved: Glama's Linux image itself (no Docker on this Mac).
- **Docs drift (T1-2):** the threat model said "a 20-way race test admits
  exactly the calls that fit". Exact now: the gateway test is 25-way over
  HTTP on SQLite and asserts settled spend never passes the cap; the exact
  admission count (40-way) is the driver-level test
  (`packages/ledger/test/red-team/projection-race.test.ts`), on SQLite and
  Postgres. The example README's "on SQLite and Postgres" sentence and its
  code pointers say the same. `docs/CARD-RAIL.md` and the card-rail
  CLAUDE.md "20-way" are correct (the card-rail race test is 20-way).
- **Open for 0.1.1:** bump the `@mandarelabs/mcp-server@0.1.0` pin in
  `glama.json` with each release (Glama rebuilds on every push). The
  `mandare-docs` Vercel project needs a redeploy for the threat-model text.

## Web Bot Auth interop claim removed (2026-10-03)

**Scope:** one source comment + one design-doc sentence
(`packages/passport/src/request-signature.ts`, `docs/KEY-DIRECTORY.md`). No
code, no spec change, no release.

- The header comment in `request-signature.ts` called the RFC 9421 request
  signatures "wire-compatible" with the Web Bot Auth ecosystem. Checked
  against draft-ietf-webbotauth-httpsig-protocol-00 (2026-09-01): `keyid`
  MUST be a base64url JWK SHA-256 thumbprint (§5.2), and `Signature-Agent`
  is a Structured Fields dictionary of https URIs whose dictionary form
  signers MUST send (§5.2.1). Mandare sends `Signature-Agent` as a bare
  string holding the agent's did:key, and `keyid` is the sha256 hex of the
  raw public key. The door-side verifier also refuses parametrized covered
  components, which the draft's `"signature-agent";key="<label>"` is. The
  comment now says what is used (the `web-bot-auth` package's RFC 9421
  primitives and its tag) and that interoperability is not claimed.
- `docs/KEY-DIRECTORY.md` said agent passport keys are presented with a
  `Signature-Agent` header pointing at the directory. No door does that: the
  gateway verifies against the key in the presented passport. Reworded.
- No other tracked file carries the claim (README, docs-site content,
  `docs/*.md`, package READMEs grepped).
- **Open (decisions, not taken here):** (a) whether request signatures
  should conform to the draft (thumbprint `keyid`, dictionary
  `Signature-Agent`) — a wire change; (b) `docs/KEY-DIRECTORY.md` still says
  the directory is "profiled exactly like" the Web Bot Auth key directory,
  while `mandare directory` writes `"alg": "EdDSA"` and the draft restricts
  `alg` to the HTTP signature algorithm registry (§5.5.1) — not checked
  against a verifier; (c) the test label "(web-bot-auth profile)" in
  `packages/passport/test/request-signature.test.ts`.

---

## Docs — sitemap, llms.txt, share tags, journal links (2026-10-03)

**Scope:** `apps/docs` (three routes, metadata, four pages) and one design
doc (`docs/KEY-DIRECTORY.md`). No package code, no spec change, no new
dependency, no release.

- **`/docs/sitemap.xml`** (`app/docs/sitemap.ts`): one URL per page on
  `https://mandarelabs.com`, in sidebar order. `lastmod` is the commit date
  of the page's source file, read from git while the site is built
  (`lib/last-commit.ts`). It is left out when git cannot answer truthfully:
  no repository, a shallow clone, an untracked file.
- **`/docs/llms.txt` and `/docs/llms-full.txt`** (route handlers,
  `text/plain`). The summary line is the index page's own `description`.
  Decision: fumadocs-mdx 11.10.1 exposes the compiled body and the raw file
  (`page.data.content`), no Markdown export, so `lib/llms.ts` converts the
  source itself: frontmatter dropped, `<Callout>` turned into a blockquote,
  site-relative links made absolute. `test/llms.test.ts` runs that over
  every real page and fails if any other MDX syntax (imports, exports, JSX)
  survives; that is the signal to extend the converter or move to a remark
  pipeline.
- Decision: all three live under `/docs`. The marketing site proxies only
  that prefix, so a root-level `sitemap.ts` would be unreachable on
  mandarelabs.com.
- Decision: no `noindex`, `X-Robots-Tag` or robots rule for the deployment's
  own host. Proxied requests reach the app under that host, so a rule aimed
  at it would de-index the public docs. The canonicals handle the alias; the
  app's `(home)` page now has one too (`/docs`).
- **Share tags:** Open Graph and Twitter tags on every page
  (`lib/site.ts`), `og:url` equal to the canonical. Next replaces
  `openGraph`/`twitter` per segment instead of merging, so each page builds
  the complete set.
- **Journal:** a nav link, and one contextual link each in `demos.mdx`,
  `concepts.mdx` and `integrations/sdk.mdx`.
- **Wording:** "verified agent identity" → "signed agent identity" on the
  `(home)` page and in the default description. This closes the item left
  open by the README claims fix above. `openclaw.mdx` no longer says the
  ClawHub listing "goes live at launch"; it states the audit gate.
- **`docs/KEY-DIRECTORY.md`:** "profiled exactly like" → "modelled on",
  naming the draft and its date, plus a field-by-field comparison with
  `draft-ietf-webbotauth-httpsig-protocol-00` (2026-09-01). No
  interoperability is claimed.
- **Open:**
  - `mandare directory` writes `"alg": "EdDSA"`; the Web Bot Auth drafts
    restrict `alg` to the HTTP Signature Algorithms registry (`ed25519`).
    Now documented, not changed: it is a format decision. The header
    comment in `packages/verifier/src/directory.ts` still cites the
    replaced draft.
  - `git grep -i 'verified owner\|verified human\|verified identity'` still
    hits four code comments (`packages/gateway/src/server.ts`,
    `packages/passport/src/attestation.ts`). They describe the signature
    check and the passport chain's roles, not product copy; left for a
    session that owns those files.
  - No JSON-LD on docs pages yet.
  - Goes live with the next deploy of the docs app. Build it from a full
    clone, or the sitemap ships without `lastmod`.

---

## → S9b handoff (the public flip — the first irreversible session) — ORIGINAL (fulfilled — see the S9b log above)

Everything is staged; S9b executes `docs/launch/LAUNCH-CHECKLIST.md` top to
bottom and does nothing else. Before starting, confirm the Phase 0 gate table
is fully green — as of S9 end, G1/G2/G5/G6/G7 are OPEN (founder) and
G3/G4/G8 need a re-run at the flip commit. The publish sequence, rollback
notes, and the audit-gated ClawHub rule are all in the checklist; the Show HN
text is final in `docs/launch/SHOW-HN.md`. If any gate fails, stop — the flip
is the one step this project cannot take back.

---

## → S9 handoff (launch) — ORIGINAL (the PREPARE half fulfilled by S9 above; the flip is S9b)

S8 closed the review; the code is now internally consistent, honestly
documented, and green on both drivers. S9 is the LAUNCH flip — the first session
that publishes anything. Nothing was published in S0–S8.

Before flipping, in order:

1. **Pre-flip history secret scan.** Run **gitleaks** over the FULL history
   (`gitleaks detect --source . --log-opts="--all"`) — the S8 manual scan across
   36 commits was clean (only test fixtures/regex matched), but gitleaks is the
   binding check and its rule set is broader. Also review commit messages for the
   publicity boundary (no internal codenames/keys). Repo stays private until this
   passes.
2. **The four founder to-dos** (dashboard actions the build can't do):
   - Confirm the MCP/npm namespace `com.mandarelabs` + `@mandarelabs/*` (DNS
     verification against mandarelabs.com) and enable npm **Trusted Publishing**
     on the `mandarelabs` org; add the `MANDARE_RELEASE_KEY_PEM` repo secret when
     arming release.
   - Enable **Stripe Issuing** on the TEST account + set the webhook timeout
     default to DECLINE, then run `pnpm card-live-smoke` (S5 debt).
   - Run the **OpenTimestamps live-smoke** against the public calendar pool and
     confirm the `.ots` upgrades to a Bitcoin attestation after a few hours (S6
     debt).
   - Decide the **OpenRouter `disableKey`** per-agent key-hash mapping so the
     cloud belt can wire into `mandare kill` (S3 debt, oldest open item).
3. **Launch assets** (Q29 playbook): the README **<30s demo GIF** (the runaway
   loop dying at the cap — currently "lands with the public release"), the
   separate **`examples/`** artifacts, and the **Show HN** post (weekday
   ~14–16h CET; lead comment explains the AGPL/Apache split + threat model +
   the honest residuals from `docs/SECURITY-REVIEW-S8.md`).
4. **Arm `release.yml`:** flip `publish=true`, add the tag-push trigger + the SLSA
   job, and run `verify-openclaw-skill.mjs --expect-key <release pubkey>` on the
   packaged skill after signing (the P1 fix makes an unsigned/unpinned artifact
   fail the gate). Confirm the version pins that S7 scheduled to drop (next 16 /
   fumadocs 16 / orama override / files-thunk shim) at the S9 dependency pass.
5. **The external audit** (Q27: Radically Open Security / NLnet-NGI0) should run
   before the OpenClaw skill launch — `docs/SECURITY-REVIEW-S8.md` lists the seven
   targets it should focus on (web-bot-auth, the keyring binary, live Bitcoin
   anchoring, Stripe live, the compose topology, timing side channels, kill under
   a second writer).

---

## → S8 handoff (parallel security/contract/red-team review before launch) — ORIGINAL (fulfilled — see the S8 log above)

S8 is the Agent-Teams review phase (BUILD-DECISIONS session plan): several
INDEPENDENT full-context reviewers over the now-complete system, before S9
launch prep. Suggested split (adjust as the session sees fit):

1. **Crypto/protocol reviewer** — spec canonical forms, ledger chain +
   RFC 6962 proofs, passport/did:key/SD-JWT, RFC 9421 profile, witness
   protocol + certificate, OTS client parse bounds. Hunt for
   cross-component assumptions no single session could see.
2. **Spend-path reviewer** — reservation/settlement/true-up across gateway
   AND card rail, projection invariants, approval waivers, kill semantics,
   witness-ack gating; try to make money move without a matching entry.
3. **Packaging/supply-chain reviewer** — S7's surfaces with fresh eyes:
   SDK wire contracts, MCP tool posture (R4/R2), skill envelope, compose
   defaults, release.yml, dependency tree audit (Q24 posture), the
   `MANDARE_GATEWAY_ALLOW_INSECURE_BIND` opt-out's blast radius.
4. **Docs/claims reviewer** — every doc claim vs code (the S7 reviewer
   caught overclaims; do it systematically), threat-model completeness,
   REPRODUCING.md honesty.

Binding for S8: the red-team floor (S0–S7, both drivers) and Demos 1–5 are
frozen; findings get fixed same-session or become explicit, scheduled debt
with founder sign-off; TASKS.md logs every finding + resolution. Before S9:
the full-history secret scan (gitleaks) + commit-message review per the
publicity boundary, and the S9 checklist below.

**From the founder — needed for S9 (not blocking S8):**

- Confirm MCP/npm namespace: `com.mandarelabs` + `@mandarelabs/*` (DNS
  verification against mandarelabs.com) — S7 prepared manifests under it.
- Enable npm Trusted Publishing on the `mandarelabs` org + repo secrets for
  the release key (`MANDARE_RELEASE_KEY_PEM`) when armed.
- OpenTimestamps live-smoke (S6 debt) and the Stripe Issuing test-mode
  toggle + webhook-timeout default (S5 debt) remain open founder items.
- OpenRouter `disableKey` belt into `mandare kill` (S3 debt) — still the
  oldest open item; S8 could close it if the founder supplies the per-agent
  key-hash mapping decision.

---

## → S7 handoff (packaging + distribution) — ORIGINAL (fulfilled — see the S7 log above)

The accountability stack is functionally complete: Passport (WHO) · Mandate +
approvals (MAY) · Ledger + spend/revocation projections (DID) · vault + kill
(hard enforcement) · card rail (money) · witnessing + anchoring + integrity
certificate (proof). S7 is **packaging it so people can actually run it** —
BUILD-DECISIONS Q17/Q18/Q26/Q29 are the rulebook. Read the S6 decisions above
and SPEC §3.1 (SDKs & integrations), §11 (packaging), §12 (deployment modes).

Scope for S7:

1. **MCP server** (`@modelcontextprotocol/sdk` v1.x, Q17): a stdio server
   exposing the door as MCP tools (issue mandate/passport/token, verify,
   certify, kill, witness status). Auth via env for stdio. `server.json` +
   `mcp-publisher`, namespace `com.mandare/*` (or `io.github.*` pre-domain).
   The gateway/vault/ledger are already the right shape — MCP is a thin
   adapter over the CLI/library surface, not new logic.
2. **OpenClaw native skill** (Q18 — MCP alone is NOT sufficient, OpenClaw has
   no native MCP client): `SKILL.md` (AgentSkills spec) + `metadata.openclaw`
   block shelling to the `mandare` CLI. ClawHub trust envelope +
   published release hashes.
3. **`docker compose up` self-host** (SPEC §11, Q29): gateway + a Postgres
   (team mode) + the reference witness in one compose file; a one-line solo
   installer. This is the README's "3-command quickstart".
4. **Dashboard-lite** (Next.js App Router, Q28): read-only fleet view over
   the ledger — spend trail, kill state, witnessed-head status, certificate
   export button. "Blind hosting" (E2E) is post-MVP; start local-only.
5. **Docs site** (Fumadocs, Q26): the WITNESSING.md/CARD-RAIL.md/KEY-DIRECTORY.md
   content plus a getting-started, threat model, and the standards-mapping
   table (SPEC §10). Feeds the launch (Q29 playbook).
6. **Release mechanics** (Q24): npm Trusted Publishing (OIDC, provenance) for
   the Apache packages (`spec`, `policy-engine`, `verifier`, `passport`,
   `witness-protocol`); cosign-keyless + SLSA for the Docker images;
   `REPRODUCING.md` already sets the honest bar. Wire `release.yml` (the S0
   stub) to actually publish.

Inherit from S6:

- **Witnessing is an ADDITIONAL channel, never the authority** (S3 founder
  ruling, honored): a dead witness fails high-value actions closed but never
  blocks `mandare kill` or ungated calls. Keep that invariant in the MCP/
  compose wiring — the witness is a separate service, and the door degrades
  honestly without it.
- **The protocol + verification stay Apache and inspectable.** The MCP server
  and dashboard are AGPL doors; anything a distrusting relying party must run
  (verifier, passport, witness-protocol, certificate check) stays embeddable.
- **Keep BOTH red-team drivers green** (now includes the S6 witness suites)
  and every demo (now five) in CI. Any new packaging surface adds its own
  smoke, not a weakening of an existing gate.

**From the founder — needed for S7 (decisions, not blocking S7 start):**

- **Namespace + domain for MCP/npm publishing**: confirm `com.mandare/*` (DNS
  verification against `mandare.dev`/`mandarelabs.com`) vs `io.github.*` for
  the pre-domain window.
- **OpenTimestamps live-smoke**: run `pnpm` (once the `witness-live-smoke`
  script lands in S7) against the public calendar pool from a networked
  machine, then check the `.ots` upgraded to a Bitcoin attestation after a
  few hours — confirms the real anchoring path end to end.
- **Still open from S5**: enable Issuing on the Stripe TEST account for the
  card live-smoke (one dashboard click); set the Issuing webhook timeout
  default to DECLINE once real cards exist.
- **Still open from S3**: the OpenRouter `disableKey` belt into `mandare kill`
  (needs the per-agent key-hash map; the local authority is complete without
  it).

---

## → S6 handoff (witnessing + anchoring) — ORIGINAL (fulfilled — see the S6 log above)

Read SPEC §6 (witnessing = lock 4/5), the S1 key-directory design
(docs/KEY-DIRECTORY.md), and the S3 founder ruling (witness = ADDITIONAL
remote channel, never the authority, never a dependency). S6 closes the
oldest open boundary in the stack:

1. **The truncation boundary documented since S0 is what S6 closes.** A
   local attacker who truncates the ledger (or restores an older copy) is
   invisible to self-anchored verification; since S1 `mandare verify` prints
   the RFC 6962 tree head and `--prev-head` detects rollback ONLY if someone
   recorded the head elsewhere. S6 automates exactly that: a witness that
   records heads off-machine (periodic + on-demand), serves consistency
   proofs, and gives `verify` a default `--prev-head` source. One red-team
   todo has waited for this since S0 (`test/red-team/tamper.test.ts`).
2. **S3's revocation records are already shaped for S6 publishing**: the
   IETF Token Status List bitstring `mandare verify` renders
   (`vault/status-list.ts`) is the publishable artifact — S6 hosts it
   (agent + door + mandate + CARD subjects all share it) and adds the
   remote kill-trigger / fleet fan-out channel on top. Publishing changes
   NOTHING about S3 semantics — that was the design obligation, honor it.
3. **The S1 key directory wants hosting** (`/.well-known/
   http-message-signatures-directory` serving with correct content-type) —
   same service, closes the "directory serving is tooling output only" debt.
4. Card-rail notes for S6: webhook-timeout declines happen outside the
   ledger — a witness that also ingests Stripe's authorization list would
   close that reconciliation gap (optional, stretch). The `card.auth.*`
   entries verify like everything else; nothing card-specific blocks
   witnessing.
5. Keep BOTH red-team drivers green (now includes the S5 card suites). The
   witness is a NEW trust surface: red-team it (lying witness, stale head,
   split view) and keep the local-authority invariant — a dead witness must
   never close the door or block a kill.

**From the founder — needed for S5 completion + S6 (decisions, not blocking S6 start):**

- **Enable Issuing on the Stripe TEST account** (one dashboard visit:
  https://dashboard.stripe.com/issuing/overview → get started, test mode is
  self-serve). Then run `pnpm card-live-smoke` — everything else is ready
  and the script walks the whole flow (listen → issue → approve → decline →
  kill/cancel → verify). Until then the live-smoke exit criterion stays
  open; CI needs nothing.
- **Set the Issuing webhook timeout default to DECLINE** in the dashboard
  once real cards exist (docs/CARD-RAIL.md operator obligation #1).
- **Where should the witness live** (S6): the planned private-repo cloud
  service vs. a minimal public reference witness in this repo (SPEC §12
  deployment modes suggest both eventually) — S6 will default to a public
  minimal witness + the private service consuming the same protocol unless
  ruled otherwise.
- Still pending from S3: wiring OpenRouter `disableKey` into `mandare kill`
  (needs the per-agent key-hash map; the local authority is complete
  without it).

---

## → S5 handoff (money rails + registry, or witness — founder's call) — ORIGINAL (fulfilled — see the S5 log above)

Read SPEC §7 (money layer: card rail via Stripe Issuing, x402), §8 (registry &
certification), §6 continued (witnessing = S6), and the S4 decisions above.
S4 delivered the WHO (passport) and finished the MAY (mandate + approvals);
S5 is the founder's pick among the remaining layers.

Inherit from S4:

1. **Passport identity is live** — the verified actor is the agent's did:key,
   proven per-request (RFC 9421 + Content-Digest). Any new door (card auth
   webhook, x402 signer) should authenticate the same way; `packages/passport`
   is the shared, Apache, embeddable surface.
2. **One revocation vocabulary spans agents, doors, AND mandates** — new
   subject types (e.g. a card token) get a `subject.register` + a namespace
   helper; do NOT add a second projection.
3. **Approvals are a general hold-push-decide primitive**, not LLM-specific:
   the card-authorization webhook (Stripe's 2s budget, Q11) can reuse
   `ApprovalService` for step-up approval, and the Notifier interface is ready
   for the Telegram adapter if iOS delivery matters.
4. **Mandate ↔ passport binding is already enforced** (S4 review MEDIUM-1):
   passport mode requires the credential owner == mandate principal and, if the
   credential names a mandate, that it match. New doors should keep that
   invariant; issuing credentials WITH a `mandate_ref` (the CLI can populate
   it) tightens it further.
5. Keep BOTH red-team drivers green (now includes the S4 passport/approval/
   mandate-revocation suites). Any money rail adds its own tamper + fail-closed
   suite (R5/R7) and its acceptance demo (R7).

**From the founder — needed for S5 (decisions, not blocking):**
- **Which layer next:** money rails (Stripe Issuing card rail — apply EARLY per
  Q11, test mode is instant; or x402/CDP), OR the verified service registry
  (§8, feeds `counterparties: verified_only` which currently fails closed), OR
  jump to S6 witnessing. The card rail is the most demo-able "hard enforcement"
  story (auth-time decline), matches the "mandated payments" pitch, and its
  webhook reuses the approval primitive.
- **Stripe Connect/Issuing onboarding** (German UG/GmbH path, Q11) — start the
  KYB/use-case review now if the card rail is next; days-to-weeks lead time,
  but test mode needs nothing.
- **Real IDV partner** (IDnow/Persona, EU) — still stubbed as the mock provider;
  a config swap once the company entity exists. Not blocking passport issuance.
- **Still pending from S2/S3:** the OpenRouter provisioning key is live-verified;
  only wiring `disableKey` into `mandare kill` (the cloud belt) remains.

---

## → S4 handoff (mandates + approvals) — ORIGINAL (fulfilled — see the S4 log above)

Read BUILD-DECISIONS Q2 (`@sd-jwt/core` + `@sd-jwt/sd-jwt-vc` for credentials)
and Q4 (`@sd-jwt/jwt-status-list` — the SAME library S3 already uses), SPEC §4
(Passport) + §5 (approvals/CIBA), and the S3 decisions above. Demo target for
S4: **the human signs ONE mandate and rubber-stamps nothing; above-threshold
spend waits for one async approval; a revoked mandate is refused instantly.**

Inherit from S3:

1. **Mandate transport = SD-JWT VC** (Q2): verify the OWNER signature on the
   mandate (v0 trusts the operator-configured file; `packages/spec` mandate
   schema is FROZEN and already carries `revocation_ref` +
   `key_provenance`). The gateway's `loadMandate` is the seam.
2. **Reuse the S3 revocation vocabulary for MANDATE revocation** — this is the
   whole point of the "one vocabulary" ruling. Mandates get a status-list
   index; the gateway's per-request kill check already reads agent + door
   subjects (`server.ts`), so ADD `mandateSubject(mandate.id)` to that check
   and let `mandare kill --mandate <id>` (or the passport flow) revoke it. One
   revocation projection, more subject namespaces — no new machinery.
3. **Passport identity replaces the static actor.** The PoP token's HMAC `k`
   becomes the passport's non-exportable agent key with RFC 9421 request
   signatures, and the verified actor comes from the presented passport (not
   `config.actor`). Add a Content-Digest over the body at the same time —
   that closes S3's HIGH-1. The S3 token preimage
   (`tokenId|method|path|timestamp|nonce`) is the deliberate precursor; extend
   it, don't replace the model.
4. **CIBA-style async approval push.** The policy engine already denies
   above-threshold with `APPROVAL_REQUIRED` (fail-closed since S2); S4 lands
   the push + the resume/settle path.
5. Keep BOTH red-team drivers green (now includes the S3 vault
   keychain-unavailable and gateway token-theft/replay/post-kill suites). Add:
   mandate-revocation enforcement, and SD-JWT owner-signature tamper.

**From the founder — needed for S4 (decisions, not blocking the first steps):**
- **IDV/KYC partner** for the attestation flow (IDnow / Persona, EU-friendly per
  SPEC §4) — or defer the KYC binding and stub the attestation for S4, doing
  only the owner→agent delegation credential locally.
- **DID method profile** for `principal`/`agent` (SPEC §4 says "DID method
  profile lands in S4") — confirm `did:key` vs `did:web` vs a Mandare profile.
- **Still pending from S2/S3:** the OpenRouter **provisioning** key — to
  live-verify per-agent capped keys and wire `disableKey` into `mandare kill`
  as the cloud belt. The runtime rail is already live-verified; only
  provisioning waits.

---

## → S3 handoff (vault + kill switch) — ORIGINAL (fulfilled — see the S3 log above)

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

   **FOUNDER RULING (2026-07-22) — the kill-switch authority model, binding:**
   the **local CLI against the door IS the authority**, and this is
   architecturally required, not just acceptable: the kill switch must NEVER
   depend on the cloud — it works offline, fails closed, and a kill that
   needs a network round-trip is a kill that can be jammed. So S3 builds the
   authoritative kill as a purely local door operation. The S6 witness
   service later becomes an ADDITIONAL remote-trigger channel (kill from
   phone/dashboard, fleet-wide fan-out across nodes, published revocation
   status for external verifiers) — but it is never the authority and never a
   dependency. **Concrete S3 obligation:** design the revocation-status
   representation now so S6 can PUBLISH it without changing S3's semantics —
   i.e. the local kill writes a revocation record whose shape/meaning is
   already the one an external verifier will later consume (align with the
   W3C bitstring status list direction from BUILD-DECISIONS Q4, which S4 uses
   for mandate revocation — reuse that status-list shape for agent/door kill
   so there is one revocation vocabulary, not two). The kill must also beat
   the shortest credential TTL (a killed agent whose token is still valid for
   N seconds is not yet killed) — a note for when S3 vault tokens get TTLs.
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

**From the founder — RESOLVED (2026-07-22):**
- ✅ **OpenRouter runtime key supplied** and live-verified (4-leg live smoke
  green; runtime rail settles OpenRouter's authoritative `usage.cost`). Key
  in `.env` only (R2), never committed.
- ✅ **OpenRouter provisioning (now "Management") key supplied** and the
  provisioning rail is **live-verified** end-to-end (`pnpm provisioning-smoke`,
  local-only: create → getKey → disable → rotate → delete, account left
  clean). Findings folded into `provisioning.ts`:
  - **RENAME (2026-07-22):** OpenRouter renamed "provisioning keys" →
    "Management keys" (same function, elevated privileges; a Management key
    cannot call completion endpoints). The REST surface is UNCHANGED — same
    base/paths/response shape — verified live. Env var kept as
    `OPENROUTER_PROVISIONING_KEY` for continuity; noted in code comments.
  - **Response shape confirmed:** create returns `{ key: "<runtime>", data:
    { hash, name, label, limit, disabled, … } }` — runtime key is top-level
    `key`; `data.label` is only a MASKED display label (an early doc summary
    wrongly called `label` the key). Existing code was already correct.
  - **Eventual consistency:** OpenRouter's LIST endpoint lags (a just-
    created/updated key can be missing or show stale `disabled`). Added
    `getKey` (single read, immediately consistent) and made `disableKey`
    return the authoritative PATCH-response state; the client and smoke never
    confirm a mutation by re-listing. This matters for S3's kill switch —
    the kill-at-OpenRouter confirmation must read the mutation response, not
    the list.
- ✅ **Kill-switch UX confirmed:** local CLI against the door = authority
  (offline, fail-closed, un-jammable); S6 witness = additional remote-trigger
  + fleet-propagation channel, never the authority. Full ruling folded into
  S3 item 2 above, including the S3 obligation to design revocation status so
  S6 can publish it unchanged.

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
