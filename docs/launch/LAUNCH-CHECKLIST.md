# Launch checklist — the S9b go-live runbook

Prepared in S9 (2026-08-09). **Nothing below has been executed.** The repo is
private and no registry has been touched. This document is the ordered
runbook for S9b, the public flip — the first irreversible session.

Everything in Phase 0 must be green before Phase 1 starts. Phases 1–5 run in
order, ideally same-day. Phase 6 (the ClawHub skill) is deliberately LAST
and gated on the external audit — it does not block the launch.

---

## Phase 0 — Gates (all must pass; any red = no flip)

Statuses below were set 2026-08-09 and updated by the S10-fix sessions
(2026-09-26/27; see TASKS.md). Every fix commit moved the flip commit, so
G3, G4 and G8 must be re-run on the exact SHA that goes public.

| # | Gate | Status |
|---|---|---|
| G1 | **Founder go** — explicit, same-day decision to launch | OPEN |
| G2 | **Trademark clearance** — "Mandare" search (EUIPO + USPTO + npm/GitHub squatting check) before the name is public and expensive to change | OPEN (founder) |
| G3 | **Secret scan on the final commit** — `gitleaks git --log-opts="--all" .` AND `trufflehog git file://. --no-update --fail` both clean | S9 scan CLEAN (see [SECRET-SCAN-S9.md](SECRET-SCAN-S9.md)); re-run on the exact flip commit |
| G4 | **CI green on origin** at the flip commit (all jobs incl. compose-smoke — which now asserts `REFUSED: call #24 PER_DAY_EXCEEDED` — and the smoke job's `pack-install-smoke`) | re-check at flip |
| G5 | **Author-identity decision** (G-IDENT) — all 37 commits are under the founder's personal account (handle + e-mail); accept (recommended) or rewrite history BEFORE the flip, never after | **DONE 2026-09-27** — history rewritten into a fresh repo; old repo = private `mandarelabs/mandare-private-archive`; old → new SHAs in TASKS.md "G5 — History rewritten". Original note: a correct rewrite (a) changes author+committer on every commit, (b) scrubs the address from file CONTENTS too (this row, TASKS.md, SECRET-SCAN-S9.md), and (c) pushes to a BRAND-NEW repo that is then made public — a force-push to this repo leaves the old commits reachable by SHA and via old Actions runs. It stales the recorded commit/run ids. Last step before the flip, in its own pass, only on the founder's same-session go |
| G6 | **npm/MCP namespace + Trusted Publishing** (founder to-do F1 below) configured | OPEN |
| G7 | **Dependency-pin decision** — S7 deferred next 16 / fumadocs 16 / the orama override + files-thunk shim; currently still pinned (`next ~15.5.0`, `fumadocs ^15.8.5`). Decide: ship pinned (fine — lockfile-frozen) and upgrade post-launch, or run the upgrade pass in a session BEFORE the flip. Do NOT upgrade on launch day | OPEN — recommend ship-pinned. The in-range security refresh is DONE (S10-fix 2C: next 15.5.26, fastify 5.12.5; `pnpm audit --prod` 0 critical — the 4 left are next's build-time postcss pin) |
| G8 | **Release workflow dry-run green** — `gh workflow run release.yml` (publish=false) on origin; gate job must show `publish=false`; `sign-skill-dry` (ephemeral key) and `build-and-pack` (incl. `pack-install-smoke` and the as-uploaded skill re-verify) green; `sign-skill-release` and every publish job skipped | STALE — last green run 31320779975 (2026-08-09) predates the S10-fix job restructure. Re-run at the flip commit (founder) |

## The four founder dashboard to-dos (F1–F4)

These are the actions only the founder can perform; F1 gates the launch,
F2–F4 do not (they close debt and unlock live smokes).

| # | To-do | Blocks | Status 2026-08-09 |
|---|---|---|---|
| F1 | Confirm namespace `com.mandarelabs` + `@mandarelabs/*` (DNS TXT verification against mandarelabs.com for the MCP registry — not present as of 2026-09-26; npm org exists). Enable **npm Trusted Publishing** for all **12** publish packages (`release.yml` `PUBLISH_PACKAGES`: spec, policy-engine, verifier, passport, witness-protocol, sdk, ledger, vault, card-rail, witness, cli, mcp-server) with workflow `release.yml` and environment `release`; package settings: disallow tokens, require 2FA. Create the GitHub **environment `release`**: deployment rule = tags `v*` only (optionally a required reviewer). Put `MANDARE_RELEASE_KEY_PEM` on that environment as an **environment secret, not a repo secret** — only the isolated `sign-skill-release` job reads it (generate: `openssl genpkey -algorithm ed25519`; the public hex goes on mandare.dev/security and ships as the release's `RELEASE-KEY.hex`) | **Phase 2+3** | OPEN |
| F2 | Enable **Stripe Issuing** on the TEST account (dashboard → Issuing → get started) + set webhook-timeout default to DECLINE, then run `pnpm card-live-smoke` (S5 debt) | nothing (rail is mock-proven in CI) | OPEN |
| F3 | Run the **OpenTimestamps live-smoke** against the public calendar pool: `pnpm ots-live-smoke` (stamps one epoch root), then the same command again 3–6 h later — PASS when the receipt carries a Bitcoin attestation (the witness upgrade pass, I-5); confirm the written `.ots` with `ots verify` (S6 debt) | nothing (mock adapter proven in CI); nice before HN for honesty | **DONE 2026-09-27** (founder's machine): `pnpm ots-live-smoke` → "PASS: epoch 1 carries a Bitcoin attestation (block 968682) after 17.4 h"; receipt `~/.mandare/ots-live-smoke/epoch-1.ots` (not in the repo); both attested messages equal the Merkle roots of Bitcoin blocks 968682 and 968707 (mempool.space). The live run first exposed the OTS depth-cap bug, fixed in PR mandarelabs/mandare#4 (TASKS.md "S10-fix 2B follow-up") |
| F4 | Decide the **OpenRouter `disableKey`** per-agent key-hash mapping so the cloud belt wires into `mandare kill` (S3 debt, oldest open item) | nothing (local kill authority is complete) | OPEN |

---

## Phase 1 — Repo public flip

**Point of no return: anything ever pushed here may be cloned and cached the
moment this executes. G3 protects this step; do not skip the re-run.**

1. Re-run G3 (both scanners) + G4 (CI) on the exact HEAD going public.
2. GitHub → Settings → change visibility → public.
3. Immediately after the flip:
   - Enable **secret scanning + push protection** and Dependabot alerts
     (`.github/dependabot.yml` already keeps the SHA-pinned actions current).
   - Enable **Private Vulnerability Reporting** (SECURITY.md and
     mandare.dev/security tell reporters to use it; it is off today).
   - Org settings: **require two-factor authentication** for every member of
     `mandarelabs`, and disallow members creating public repositories.
   - Branch protection on `main` (require CI, no force-push, no deletion —
     force-push protection is also witness-hygiene for the repo itself).
   - About: description = the README one-liner; topics (`ai-agents`,
     `budget`, `audit-log`, `transparency-log`, `mcp`); link mandare.dev.
   - Confirm the README renders: badges resolve (CI badge goes green after
     the first public run; npm badge stays "not found" until Phase 2 — this
     window should be minutes, not days), the demo GIF plays.
4. Do NOT announce anything yet.

## Phase 2 — npm + GitHub release

1. Confirm F1 is done (Trusted Publishing for all 12 packages, the
   `release` environment with its v*-tag rule, the environment secret), and
   that mandare.dev/security is LIVE (Phase 4 step 1) — the release notes and
   the skill docs tell users to pin the key from there.
2. Tag: `git tag v0.1.0 && git push origin v0.1.0`.
3. The armed `release.yml` runs: gate (publish=true now legal) → build/test →
   skill signed with the RELEASE key + pin-verified (S8/P1 gate) → pack +
   SHA256SUMS → SLSA L3 provenance → npm publish (OIDC, provenance) for the
   12 packages in dependency order → GHCR image + cosign + attestation →
   **draft** GitHub release (tarballs, the signed skill as
   `openclaw-skill.tar.gz`, `RELEASE-KEY.hex`, SHA256SUMS, mcp-server.json).
   The key is read only by `sign-skill-release`; publish jobs refuse any ref
   that is not a v* tag.
4. Verify from a clean machine, as a user would:
   - `npm view @mandarelabs/spec` shows the version + provenance badge;
   - `gh attestation verify` against a downloaded tarball;
   - `cosign verify ghcr.io/mandarelabs/mandare:v0.1.0` (keyless, Rekor).
5. Founder reviews + publishes the draft GitHub release (artifacts +
   SHA256SUMS attached); check the attached `RELEASE-KEY.hex` equals the hex
   on mandare.dev/security, and paste it into the notes.

## Phase 3 — MCP registry

1. `mcp-publisher` publish of `packages/mcp-server/server.json` under
   `com.mandarelabs/*` (DNS verification from F1). The manifest uses the
   2025-12-11 schema and the npm package carries the matching `mcpName` —
   both checked by `pack-install-smoke`; re-check the registry's current
   schema version on the day.
2. Verify the listing resolves and the install instruction works against the
   published npm package (not a local build).
3. Submit to the secondary indexes (Glama, PulseMCP) — listing, not code.

## Phase 4 — Docs site

1. Deploy `apps/docs` to mandare.dev (static export; any host) and publish
   the release key hex at mandare.dev/security (P1 pinning source). **Do this
   before Phase 2's tag push** — today mandare.dev redirects to the marketing
   site and /security is a 404.
2. Check every README link resolves publicly (docs, SECURITY-REVIEW-S8,
   examples, LICENSING, REPRODUCING).

## Phase 5 — Show HN

1. Weekday, ~14:00–16:00 CET. Post exactly per
   [SHOW-HN.md](SHOW-HN.md) (title, body, then the lead comment
   immediately, from the founder's account).
2. Founder answers every comment through the day. No growth hacks, no vote
   asks — the security posture is the marketing.
3. Same-day mirrors AFTER HN is live (not before): r/LocalLLaMA or r/selfhosted
   (one, not both, per each sub's self-promo rules), the MCP/agents Discords.

## Phase 6 — ClawHub skill (LAST, audit-gated — does not block launch)

1. **Gate: the external audit** (Q27 — Radically Open Security / NLnet-NGI0
   route). Scope = the seven targets listed at the end of
   [SECURITY-REVIEW-S8.md](../SECURITY-REVIEW-S8.md). A skill is
   agent-executed instructions; it ships with the highest bar, not the lowest.
   **Also gated on the kill-only path (K-1):** today `mandare kill` needs the
   door signing key, which also permits `reinstate` and arbitrary signed
   entries, so a skill agent that can kill holds operator authority (the
   docs say so). Before promotion: a kill-only key or gateway endpoint that
   verifiers accept for `agent.revoke` alone, recording the invoking
   principal.
2. Publish the signed skill package (envelope already produced + pin-verified
   by `release.yml`) to ClawHub; the published release-key hex is the pin.
3. Update the docs' install page to the audited-and-signed framing.

---

## Rollback notes (what can and cannot be undone)

- **Repo flip:** going re-private stops NEW distribution but recalls nothing
  — clones, forks, and archive crawlers keep what they saw. That is why G3
  is a hard gate, not a formality. There is no secret-remediation-by-
  re-privating; assume everything public is permanent.
- **npm:** unpublish is restricted (72h/no-dependents policy); the working
  rollback is `npm deprecate <pkg>@<version> "reason"` + publish a fixed
  version. No tokens exist to leak or rotate (Trusted Publishing only).
- **GitHub release:** created as a DRAFT by the workflow — nothing is
  announced until the founder publishes it. A published release can be
  deleted, but attached artifacts may already be mirrored.
- **GHCR image:** tags can be deleted; the cosign signature in Rekor is a
  permanent public transparency-log entry (by design — do not plan on
  removing it, plan on superseding it).
- **SLSA/provenance attestations:** permanent once logged; supersede, don't
  retract.
- **MCP registry / ClawHub:** publish a superseding version; delisting is
  possible but cached indexes lag — treat like npm.
- **Release key compromise:** rotate = new key, publish new hex on
  mandare.dev/security + GitHub release, re-sign the skill, announce in
  SECURITY.md advisory format. The pin-verify gate means consumers notice.
- **HN goes badly:** nothing to roll back — answer honestly, file issues for
  real findings, treat public findings as free audit. Do not delete the post.

## What S9 already did (for the record)

- Full-history secret scan: CLEAN (gitleaks 8.30.1 + trufflehog 3.96.0, 37
  commits, all refs) — [SECRET-SCAN-S9.md](SECRET-SCAN-S9.md). Tip-level
  codename cleanups applied; `.gitleaks.toml` documents the did:key
  false-positive allowlist.
- README rebuilt as the conversion asset (badges, real demo GIF from the
  captured Demo 1 run, proofs-not-data section, S8 review prominent).
- `examples/` — five self-contained narrated scenarios wrapping the five
  CI-asserted demos.
- [SHOW-HN.md](SHOW-HN.md) drafted (title, body, lead comment, prepared
  answers). Not posted.
- `release.yml` armed: tag trigger + OIDC Trusted Publishing + SLSA L3 +
  cosign + the P1 pin-verify gate, structurally publish-proof while the repo
  is private (the `gate` job hard-fails any publish attempt pre-flip).
