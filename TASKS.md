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

## → S5 handoff (money rails + registry, or witness — founder's call)

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
