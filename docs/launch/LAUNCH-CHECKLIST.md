# Launch checklist — the S9b go-live runbook

Prepared in S9 (2026-08-09). **Nothing below has been executed.** The repo is
private and no registry has been touched. This document is the ordered
runbook for S9b, the public flip — the first irreversible session.

Everything in Phase 0 must be green before Phase 1 starts. Phases 1–5 run in
order, ideally same-day. Phase 6 (the ClawHub skill) is deliberately LAST
and gated on the external audit — it does not block the launch.

---

## Phase 0 — Gates (all must pass; any red = no flip)

| # | Gate | Status 2026-08-09 |
|---|---|---|
| G1 | **Founder go** — explicit, same-day decision to launch | OPEN |
| G2 | **Trademark clearance** — "Mandare" search (EUIPO + USPTO + npm/GitHub squatting check) before the name is public and expensive to change | OPEN (founder) |
| G3 | **Secret scan on the final commit** — `gitleaks git --log-opts="--all" .` AND `trufflehog git file://. --no-update --fail` both clean | S9 scan CLEAN (see [SECRET-SCAN-S9.md](SECRET-SCAN-S9.md)); re-run on the exact flip commit |
| G4 | **CI green on origin** at the flip commit (all jobs incl. compose-smoke) | re-check at flip |
| G5 | **Author-identity decision** (G-IDENT) — all 37 commits are under the founder's personal account (handle + e-mail); accept (recommended) or rewrite history BEFORE the flip, never after | OPEN (founder) — see SECRET-SCAN-S9.md |
| G6 | **npm/MCP namespace + Trusted Publishing** (founder to-do F1 below) configured | OPEN |
| G7 | **Dependency-pin decision** — S7 deferred next 16 / fumadocs 16 / the orama override + files-thunk shim; currently still pinned (`next ~15.5.0`, `fumadocs ^15.8.5`). Decide: ship pinned (fine — lockfile-frozen) and upgrade post-launch, or run the upgrade pass in a session BEFORE the flip. Do NOT upgrade on launch day | OPEN — recommend ship-pinned |
| G8 | **Release workflow dry-run green** — `gh workflow run release.yml` (publish=false) on origin; gate job must show `publish=false`, all build/sign/pack/hash steps green | armed in S9; run recorded below |

## The four founder dashboard to-dos (F1–F4)

These are the actions only the founder can perform; F1 gates the launch,
F2–F4 do not (they close debt and unlock live smokes).

| # | To-do | Blocks | Status 2026-08-09 |
|---|---|---|---|
| F1 | Confirm namespace `com.mandarelabs` + `@mandarelabs/*` (DNS TXT verification against mandarelabs.com for the MCP registry; npm org exists); enable **npm Trusted Publishing** for the 8 publish packages on the `mandarelabs` org (disallow tokens, require 2FA); add repo secret `MANDARE_RELEASE_KEY_PEM` (generate: `openssl genpkey -algorithm ed25519`; publish the derived public key hex on mandare.dev/security at launch) | **Phase 2+3** | OPEN |
| F2 | Enable **Stripe Issuing** on the TEST account (dashboard → Issuing → get started) + set webhook-timeout default to DECLINE, then run `pnpm card-live-smoke` (S5 debt) | nothing (rail is mock-proven in CI) | OPEN |
| F3 | Run the **OpenTimestamps live-smoke** against the public calendar pool; confirm the `.ots` upgrades to a Bitcoin attestation after a few hours (S6 debt) | nothing (mock adapter proven in CI); nice before HN for honesty | OPEN |
| F4 | Decide the **OpenRouter `disableKey`** per-agent key-hash mapping so the cloud belt wires into `mandare kill` (S3 debt, oldest open item) | nothing (local kill authority is complete) | OPEN |

---

## Phase 1 — Repo public flip

**Point of no return: anything ever pushed here may be cloned and cached the
moment this executes. G3 protects this step; do not skip the re-run.**

1. Re-run G3 (both scanners) + G4 (CI) on the exact HEAD going public.
2. GitHub → Settings → change visibility → public.
3. Immediately after the flip:
   - Enable **secret scanning + push protection** and Dependabot alerts.
   - Branch protection on `main` (require CI, no force-push, no deletion —
     force-push protection is also witness-hygiene for the repo itself).
   - About: description = the README one-liner; topics (`ai-agents`,
     `budget`, `audit-log`, `transparency-log`, `mcp`); link mandare.dev.
   - Confirm the README renders: badges resolve (CI badge goes green after
     the first public run; npm badge stays "not found" until Phase 2 — this
     window should be minutes, not days), the demo GIF plays.
4. Do NOT announce anything yet.

## Phase 2 — npm + GitHub release

1. Confirm F1 is done (Trusted Publishing configured, secret set).
2. Tag: `git tag v0.1.0 && git push origin v0.1.0`.
3. The armed `release.yml` runs: gate (publish=true now legal) → build/test →
   skill signed with the RELEASE key + pin-verified (S8/P1 gate) → pack +
   SHA256SUMS → SLSA L3 provenance → npm publish (OIDC, provenance) for the
   8 packages → GHCR image + cosign + attestation → **draft** GitHub release.
4. Verify from a clean machine, as a user would:
   - `npm view @mandarelabs/spec` shows the version + provenance badge;
   - `gh attestation verify` against a downloaded tarball;
   - `cosign verify ghcr.io/mandarelabs/mandare:v0.1.0` (keyless, Rekor).
5. Founder reviews + publishes the draft GitHub release (artifacts +
   SHA256SUMS attached); paste the release public key hex into the notes and
   onto mandare.dev/security.

## Phase 3 — MCP registry

1. `mcp-publisher` publish of `packages/mcp-server/server.json` under
   `com.mandarelabs/*` (DNS verification from F1).
2. Verify the listing resolves and the install instruction works against the
   published npm package (not a local build).
3. Submit to the secondary indexes (Glama, PulseMCP) — listing, not code.

## Phase 4 — Docs site

1. Deploy `apps/docs` to mandare.dev (static export; any host). Publish the
   release key hex at mandare.dev/security (P1 pinning source).
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
