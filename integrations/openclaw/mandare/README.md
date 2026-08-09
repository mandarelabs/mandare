# Mandare skill for OpenClaw (and Claude Code)

`SKILL.md` follows the AgentSkills format, so the same skill serves OpenClaw
(via the `metadata.openclaw` block) and Claude Code (drop the directory into
`.claude/skills/`). It shells to the `mandare` CLI — the skill carries **no
code of its own**, only instructions and the trust envelope.

## What it gives an agent

**Visibility and the kill switch, never authority.** An agent with this skill
can check its remaining budget, explain gateway refusals, verify the
tamper-evident ledger, export third-party-checkable integrity certificates,
and kill spend (its own or a subordinate agent's). It cannot issue passports,
mandates, or tokens, and it cannot reinstate anything — those are operator
actions, and the skill says so out loud. An agent that can widen its own
permissions has no permissions at all.

## Trust: what you can verify before installing

ClawHub scans uploads (VirusTotal Code Insight) but has no publisher signing
chain yet. **This skill ships one anyway** — our release posture exceeds the
platform norm, on purpose:

- `clawhub.skill.verify.v1.json` — the trust envelope: sha256 of every file
  in the skill, the release version, and (on tagged releases) an Ed25519
  signature over the canonical envelope by the Mandare release key.
- Release hashes are also published in the GitHub release's `SHA256SUMS`.
- Verify a downloaded/packaged copy before trusting it (the envelope ships
  with PACKAGED skills; package one from source with
  `node scripts/package-openclaw-skill.mjs`):

```bash
node scripts/package-openclaw-skill.mjs --out dist/openclaw-skill
node scripts/verify-openclaw-skill.mjs dist/openclaw-skill
```

The npm packages behind the CLI publish with npm Trusted Publishing (OIDC
provenance) — see `REPRODUCING.md` at the repo root for the full
supply-chain posture.

## Status

Prepared in-repo; **not yet published to ClawHub** (the repo goes public at
launch). The smoke test `scripts/skill-smoke.mjs` executes every command the
skill documents against a real gateway + ledger in CI, so the instructions
cannot drift from the product.
