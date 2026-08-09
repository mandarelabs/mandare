# S9 pre-flip history secret scan

**Date:** 2026-08-09 · **Scope:** the full git history (all 37 commits on all
refs), every commit message, the tracked tree at tip, and TASKS.md — the gate
that protects the irreversible public flip.

## Verdict

**CLEAN, with one open founder decision (author identity in history).** No
secret of any class was ever committed. Two cosmetic publicity-boundary items
were found at tip and fixed this session; one residual (the old project
codename in historical commits) is accepted with rationale below.

## What ran

| Check | Tool / method | Result |
|---|---|---|
| Full-history secret scan | `gitleaks 8.30.1` — `gitleaks git --log-opts="--all"` | 5 raw hits, **all false positives** (see below); 0 after the documented allowlist |
| Full-history secret scan, second engine | `trufflehog 3.96.0` — `trufflehog git file://.` (all commits, ~800 detectors + live verification) | **0 findings** |
| Secret-file history check | `git log --all --diff-filter=A` for `.env`, `*.db`, `*.pem` | **Never committed**; `.gitignore` covers `.env` and `*.db` (vault DB, ledger DBs) |
| `.env.example` history | full patch review of every revision | Only empty placeholders were ever committed |
| Commit messages | manual review of all 37 subjects/bodies | Engineering content only; no keys, no strategy, no personal data |
| TASKS.md | manual review against the publicity boundary (root CLAUDE.md) | Clean — engineering log written as-if-public since S0 |
| Tracked tree at tip | file-by-file review of everything outside `packages/apps/scripts/docs` | Clean (`.claude/settings.json` is relative-path hooks only) |
| Codename / personal-identifier grep | `git grep -iE "tessera|<founder identifiers>"` over tip | 3 files matched — fixed at tip this session (below) |

## The five gitleaks hits — why they are false positives

All five matched rule `generic-api-key` on strings of the form
`z6Mk…` in `docs/demos/S4-mandate-demo.txt`,
`packages/passport/test/did-key.test.ts`, and
`packages/passport/test/delegation.test.ts`.

`z6Mk…` is the **did:key multibase form of an Ed25519 PUBLIC key**
(base58btc, multicodec `0xed01`) — a public identifier by construction, not
secret material. One of them (`z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp`)
is the published W3C did:key reference vector this repo pins its codec to.
Private keys never take this form here (agent/owner keys are JWK/PEM,
gitignored, written 0600).

The pattern is allowlisted in `.gitleaks.toml` with this rationale inline, so
the pre-flip gate is repeatable and future CI scans stay clean without
weakening any real rule (`useDefault = true`).

## Fixed at tip this session (publicity boundary, not secrets)

1. **`CLAUDE.md`** — referenced the founder's private strategy repo by local
   path. Reworded to a neutral description.
2. **`apps/cli/src/directory.ts` + `docs/KEY-DIRECTORY.md`** — three uses of
   the pre-rename project codename ("Tessera-hosted", "Tessera tenant",
   "Tessera countersigning") as if it were a product name. Renamed to
   "Mandare Cloud" / neutral wording.

## Accepted residuals (recorded, no action)

- **The codename "Tessera" appears in historical revisions** of the two files
  above (present since S1/S2). It is a name, not a secret — it reveals only
  that the project had a working title. Rewriting 37 commits to purge a word
  would invalidate every commit hash recorded in TASKS.md and
  `docs/SECURITY-REVIEW-S8.md`, the recorded CI run associations, and the
  reproducibility narrative — a real integrity cost for zero secret-value
  gain. Accepted.

## Open founder decision before the flip

- **Git author identity:** all 37 commits are authored
  under the founder's personal account (handle + e-mail). Going public publishes that personal
  email in every commit. Options:
  1. **Accept** (common in OSS; if the address is attached to the founder's
     GitHub account, commits attribute normally). Recommended, combined with
     switching future commits to the GitHub `noreply` address or a
     `mandarelabs.com` address.
  2. **Rewrite history** (`git filter-repo --email-callback`) before the flip
     — changes every commit hash, with the same integrity costs listed above
     (TASKS.md/S8-review hash references, CI run associations). Only worth it
     if the founder considers the address itself sensitive.

  This is gate G-IDENT in `docs/launch/LAUNCH-CHECKLIST.md`.

## Repeat before the flip

The flip runbook re-runs both engines on the final pre-flip commit:

```bash
gitleaks git --log-opts="--all" .
trufflehog git file://. --no-update --fail
```

Both must exit clean on the exact commit that goes public.
