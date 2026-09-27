# S8 — Adversarial pre-launch security review

**Date:** 2026-08-09 · **Scope:** the complete Mandare system (S0–S7), the last
gate before the repository goes public. This was a separate, adversarial
pass — *find, verify, then fix* — not a build session. It was AI-assisted and
run inside the same build process (not organisationally independent); the
external audit is still pending. The frozen floor (all
S0–S7 red-team suites on both drivers, Demos 1–5) ended the session green and
un-weakened.

## Method

Four parallel AI reviewer agents (Agent-Teams) ran one per lens, each
prompted to **break the system, not bless it**, against now-disjoint package
sets. Every reported finding was then re-traced against the live code by the
orchestrator; only findings that reproduced were fixed. Each CONFIRMED code
finding ships a **regression test that fails on the pre-fix code and passes on
the fix**. Doc findings were corrected in place. Nothing was taken on the
strength of a report alone.

Baseline before any change: build · typecheck · lint (license boundaries + turbo
boundaries) · test · red-team (both SQLite and Postgres drivers) · Demos 1–5 ·
stack/skill/sdk-py smokes — all green. `release.yml`'s publish gate confirmed
disarmed (`workflow_dispatch` only; `if: inputs.publish → exit 1`). Full-history
secret scan clean across 36 commits (all matches are test fixtures/regex).

## Dimensions

1. **Crypto & integrity** — Ed25519, RFC 6962 proofs, canonical JSON, salting,
   the witness/certificate trust perimeter, key directory & rotation, selective
   disclosure. Goal: forge, replay, or mint a false integrity certificate.
2. **Spend & enforcement** — derived-projection budget, reserve/settle across the
   LLM + card rails, witness-ack gating, kill authority, fail-closed doors. Goal:
   overspend, double-spend, or act past a kill/revocation.
3. **Packaging & supply chain** — the Apache/AGPL boundary, dependency posture,
   install scripts, the OpenClaw skill verify envelope, MCP surface (R2/R4),
   compose bind guards, release readiness. Goal: smuggle code, leak a secret,
   ship a tamperable artifact.
4. **Docs-vs-reality** — every security claim backed by a test or honestly marked
   a residual. Goal: hunt overclaims the pitch/marketing could inherit.

## Findings & resolutions

15 findings: **3 HIGH · 4 MEDIUM · 5 LOW · 3 INFO.** All CONFIRMED findings are
fixed with a regression test; 2 are documented accepted residuals (below). No
silent "won't fix".

| ID | Sev | Dimension | Finding | Resolution |
|----|-----|-----------|---------|------------|
| **C1** | HIGH | crypto | Certificate **bound mode** bound only the bundle *signature* to the auditor's out-of-band door key, never the certified `door_key_id` that drives the witness/anchor/consistency checks. A key-holding operator could witness a curated/truncated tree under a **fresh source id**, self-declare it, and sign with the trusted key — passing verification over a parallel witnessed timeline. | FIXED: `bundleOk` now also requires `door_key_id == sha256(doorKey)`. No-op in self-declared mode; closes the stronger bound-mode path. Red-team test `S8/C1`. |
| **S1** | HIGH | spend | The pre-flight reservation (the cap guard) estimated input tokens as `chars/3` over the UTF-16 length — a true bound only for Latin. For CJK/token-dense input it **under-counted ~3×**, so `max_tokens:1` + a token-dense prompt could reserve under the per-tx cap while settlement (no cap guard, by design) applied the true 2–3× cost past it. | FIXED: estimate input tokens as the **UTF-8 byte length** — a provable upper bound (tokens ≤ bytes for byte-level BPE) for any script. Same bound applied to the settle-side fallback (usage-less/aborted streams) so the ledger never under-records. Test `S8/S1`. |
| **P1** | HIGH | packaging | The OpenClaw skill verifier (`verify-openclaw-skill.mjs`) blessed an **unsigned** package as "VERIFIED" (exit 0), and when signed read the verifying key **from the envelope itself** (no pinning). An attacker re-packages a tampered `SKILL.md` (agent-executed instructions) with no key — or self-signs — and the verifier + a CI gate keying on exit code pass. | FIXED: unsigned now FAILS by default (`--allow-unsigned` is an explicit dev escape); a VERIFIED verdict requires the signing key be **pinned** via `--expect-key <hex>` and match. Smoke now exercises the downgrade/re-hash, unsigned, unpinned, and wrong-key attacks. |
| **C2** | MED | crypto | The gating `public-anchor` check graded `basis:'proof', ok:true` on the mere **presence** of a Bitcoin attestation tag committing the epoch root — it never verified the block against a chain (impossible offline). In the solo topology (witness key on the same host) the operator could fabricate "Bitcoin finality." | FIXED: the OTS-with-Bitcoin-tag case is now `recorder-attested` ("verify the .ots against a node") and never gates the verdict; offline-detectable lies (receipt doesn't commit the root, unparseable) still gate as failures. Test `S8/C2`. |
| **S2** | MED | spend | After a successful witness-ack (`requireAck`), both rails executed with **no revocation re-check**. A `mandare kill` landing during the ack wait was ignored for that in-flight high-value call — the exact class lock-5 promises a zero tamper window, and inconsistent with the approval-hold path's HIGH-2 re-check. | FIXED: both rails re-check revocation after the ack; killed mid-wait ⇒ settle the reservation to 0 and refuse/decline. Red-team tests on gateway and card rail (`KILL DURING ACK`). |
| **D1** | MED | docs | README + Security page claimed hand-rolled primitives are pinned to **"official test vectors"** for Stripe signatures and OTS (and canonical JSON) — no such published vectors exist; those are tested against the documented wire scheme. | FIXED: reworded to the true split (RFC 6962 CT + did:key/base58 use official vectors; Stripe/OTS/canonical JSON use published-scheme + adversarial round-trip suites). |
| **D2** | MED | docs | The overview and Concepts pages stated "truncation and rewrites — **even by the operator** — are detectable" unconditionally; the same-host solo-compose residual (witness shares the machine → not detectable) was honest in three other places but not co-located here. | FIXED: the residual is now co-located on `index.mdx` and `concepts.mdx` (team mode / second host vs. single-host solo stack), linking the threat model. |
| **C3** | LOW | crypto | The OTS parser dropped trailing bytes in bitcoin/pending attestation payloads, so a non-canonical `.ots` re-serialized to different bytes (round-trip fidelity, not a forge). | FIXED: assert the attestation payload is exhausted (matches the top-level `!reader.exhausted` checks). |
| **P2** | LOW | packaging | `web-bot-auth ^0.1.3` — a pre-1.0, unaudited dep in the Apache request-signing path — floated under a caret (lockfile-pinned, but the spec was loose). | FIXED: pinned to exact `0.1.3`; flagged for the pre-launch audit list. |
| **D3** | LOW | docs | Precise latency figures ("p50 ~15ms/p99 ~29ms", "68× under budget", "p99 <10ms") were presented as "CI bench" results; CI asserts only p99 < 500ms. | FIXED: labeled developer-hardware measurements and stated the actual CI assertion. |
| **D4** | LOW | docs | LICENSING.md said each Apache package "declares license in its `package.json`" — false for `sdk-py` (pyproject.toml) and the OpenClaw skill (no manifest). | FIXED: reworded per manifest type. |
| **C4** | LOW/INFO | crypto | The RFC 9421 covered set omits `@query`/uncovered headers (body is bound via Content-Digest). A door deciding on the query string would act on unauthenticated input. | ACCEPTED RESIDUAL (verified): grep confirms **no door reads the query string**; every security field comes from the content-digest-bound body. Kept as documented defense-in-depth guidance. |
| **P3** | INFO | packaging | The Docker image baked internal build docs (`TASKS.md`, `CLAUDE.md`, `docs/`) via `COPY . .` — bloat, not a leak (real secret classes are `.dockerignore`d). | FIXED: added them to `.dockerignore`. |
| **P4** | INFO | packaging | `@napi-rs/keyring` ships a prebuilt native binary loaded into the vault process (correctly not in `onlyBuiltDependencies`, so no install script runs). | ACCEPTED (design): OS keychain needs native code; added to the audit-target list below. |
| **D5** | INFO | docs | The frozen Apache spec's `SpendRail` union advertises `x402`/`credits` rails nothing implements — a third party implementing "the open contract" could read the enum as capability. | FIXED: a schema comment marks them RESERVED/unimplemented (no schema_version bump — R6 intact). |

### What each reviewer confirmed is structurally sound (negative results)

Kept here so an auditor knows what was probed and held:

- **Crypto:** entry forgery (preimage/sig), Merkle second-preimage + proof
  forgery (domain-separated `0x00`/`0x01`, CT reference vectors, empty-tree +
  size-0 handling), did:key/base58 same-shape forgery, SD-JWT algorithm
  confusion / `alg:none` / issuer-key swap (Ed25519 hardcoded, `iss`-derived key,
  exp/nbf enforced by default), RFC 9421 replay + decoy-parameter coverage
  bypass, canonical-JSON Infinity/collision, vault AES-GCM ciphertext-move (AAD),
  witness ack replay / catch-up fork.
- **Spend:** concurrent overshoot and cross-rail race on one cap (reserve under
  `BEGIN IMMEDIATE` / advisory lock), double-settle and result-without-intent,
  card-webhook replay (early + in-txn `AUTH_REPLAYED` markers), midnight cap
  reopen, `projection_meta` rewind (always-diff `verifySpendProjection`),
  approve-after-kill / kill-during-hold / approval-token replay / step-up-waiver
  reuse, €0 card approve + currency confusion, FX invention.
- **Packaging:** MCP command injection (`execFile` discrete argv, zod-validated,
  no path args), `pop_secret`/key material into model context (R2), un-kill via
  compromised MCP host (env-gated reinstate), the Apache→AGPL boundary (per-pkg
  `turbo.json` tags + `turbo boundaries` + manifest script, all in CI), committed
  secrets, `install.sh` hygiene, `release.yml` publish gate + workspace-protocol
  leak gate, compose loopback binds + the scoped `ALLOW_INSECURE_BIND` opt-out,
  install-script posture.
- **Docs:** the 3-command quickstart runs verbatim in CI, all five demos run in
  CI, the policy engine implements SPEC §5 order, the Python SDK is stdlib-only,
  SLSA/cosign/Trusted-Publishing are correctly framed as from-launch against a
  dry-run `release.yml`, REPRODUCING.md's honest no-bit-for-bit bar holds.

## Accepted residuals (unchanged from prior sessions, re-confirmed)

The code still limits itself to exactly these; none were widened:

- A full-machine-root attacker acting **entirely outside Mandare's doors** was
  never in claimed coverage (the seatbelt boundary). Anything needing Mandare's
  credentials/money still hits write-ahead + witnessing.
- **Solo-compose topology:** the witness key lives on the same host, so a
  full-root operator can rewrite + re-witness consistently — team mode / a second
  host closes it. Now co-located in the docs (D2).
- Self-anchored verification proves **consistency, not authorship** (a file-level
  attacker can re-sign under a swapped key); witnessing closes it.
- Card settlement true-up from `issuing_transaction.created` is scheduled; v0
  settles the authorized amount (authorized ≥ captured, cap never under-counts).
- RFC 9421 omits `@query` (C4): safe today because no door decides on the query
  string; keep it that way.

## What an external auditor should still check

The formal third-party audit (Radically Open Security / NLnet-NGI0, per Q27)
should focus here before the OpenClaw skill launch:

1. **`web-bot-auth@0.1.3`** — the one unaudited third-party lib in the Apache
   request-signing path (in scope per Q3). Mandare layers its own required-
   component + window + nonce + digest enforcement on top; audit both.
2. **`@napi-rs/keyring` native binary** in the vault process (P4) — a prebuilt
   `.node` blob holding the master key; binary provenance / checksum-pinning.
3. **Public-chain anchoring end-to-end** — the offline verifier now honestly
   labels a Bitcoin attestation "verify externally" (C2). Confirm the
   `witness-live-smoke` path (real OTS calendars → real `.ots` → real Bitcoin
   upgrade) against a node; not in CI (network + hours-to-confirm).
4. **Stripe Issuing live path** (S5 debt) — the decision path is unit- and
   mock-webhook-tested; the live smoke is blocked on the founder's Issuing toggle.
5. **Compose/Docker topology** — CI-proven (`compose-smoke`), not locally
   reproducible on the dev machine; re-run on the auditor's own runtime.
6. **Timing side channels** in the constant-time comparisons (PoP HMAC, approval
   tokens, Stripe signature) under real load — the code uses `timingSafeEqual`
   on equal-length pre-validated inputs; confirm no length-leak upstream.
7. **The kill authority under a second writer** — S5 noted a post-kill
   authorization can wait up to `busy_timeout` when another process holds the
   SQLite write lock; bounded, but worth confirming when the witness adds writers.

## Files changed this session

Crypto: `packages/witness-protocol/src/certificate.ts` (C1, C2),
`packages/witness-protocol/src/ots.ts` (C3), `packages/witness-protocol/test/certificate.test.ts`.
Spend: `packages/gateway/src/pricing.ts`, `providers/{anthropic,openai-like,types}.ts`,
`src/server.ts`, `src/index.ts` (S1, S2), `packages/card-rail/src/routes.ts` (S2),
`packages/gateway/test/{pricing,streaming,red-team/witness-gate}.test.ts`,
`packages/card-rail/test/red-team/witness-gate-card.test.ts`.
Packaging: `scripts/verify-openclaw-skill.mjs`, `scripts/skill-smoke.mjs` (P1),
`packages/passport/package.json` + `pnpm-lock.yaml` (P2), `.dockerignore` (P3).
Docs: `README.md`, `LICENSING.md`, `apps/docs/content/docs/{index,concepts,security,threat-model}.mdx`,
`docs/WITNESSING.md` (D1–D4), `packages/spec/src/mandate.ts` (D5).
