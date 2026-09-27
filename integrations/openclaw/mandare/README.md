# Mandare skill for OpenClaw (and Claude Code)

`SKILL.md` follows the AgentSkills format, so the same skill serves OpenClaw
(via the `metadata.openclaw` block) and Claude Code (drop the directory into
`.claude/skills/`). It shells to the `mandare` CLI — the skill carries **no
code of its own**, only instructions and the trust envelope.

## What it gives an agent

**Visibility and proofs; the kill switch only with operator-level access.**
An agent with this skill can check its remaining budget, explain gateway
refusals, verify the tamper-evident ledger, and export third-party-checkable
integrity certificates — all of which need only the ledger file.

The kill switch is different: `mandare kill` signs a ledger entry with the
door's signing key, so it works only in an environment that can read that
key — and the same key also permits `mandare reinstate` and arbitrary signed
ledger entries. **Giving an agent the kill switch gives it operator-level
door access.** The skill instructs the agent never to issue passports,
mandates, or tokens, or to reinstate anything, and says why; that is an
instruction, not an enforced boundary. If the governed agent must not hold
operator authority, keep the door key out of its environment and leave the
kill to the human or a supervising process. (A kill-only path — a key or
endpoint that verifiers accept for revocations alone — is planned before the
skill is promoted on ClawHub.)

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
# a signed release: pin the release key published at mandare.dev/security
# (also attached to the GitHub release as RELEASE-KEY.hex)
node scripts/verify-openclaw-skill.mjs <skill-directory> --expect-key <release-key-hex>

# your own local, unsigned build only
node scripts/package-openclaw-skill.mjs --out dist/openclaw-skill
node scripts/verify-openclaw-skill.mjs dist/openclaw-skill --allow-unsigned
```

Without `--expect-key` a signed package fails on purpose: a self-consistent
signature proves only that *someone* signed it. Never use `--allow-unsigned`
on a download.

The npm packages behind the CLI publish with npm Trusted Publishing (OIDC
provenance) — see `REPRODUCING.md` at the repo root for the full
supply-chain posture.

## Status

Prepared in-repo; **not yet published to ClawHub** (the repo goes public at
launch). The smoke test `scripts/skill-smoke.mjs` executes every command the
skill documents against a real gateway + ledger in CI, so the instructions
cannot drift from the product.
