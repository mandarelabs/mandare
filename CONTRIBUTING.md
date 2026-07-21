# Contributing to Mandare

Thanks for your interest. Pre-alpha ground rules:

## Before you start

- Read [LICENSING.md](LICENSING.md) — the Apache/AGPL split and the import
  direction rule are enforced by CI and are non-negotiable.
- The schemas in `packages/spec` are **frozen contracts**. Changes require a
  logged decision (TASKS.md) and a schema version bump — open an issue first.

## Contributor License Agreement

We require a lightweight CLA ([CLA.md](CLA.md)) on your first pull request,
handled automatically by a bot comment — sign by replying as instructed. Why a
CLA and not just DCO: it grants the project the copyright and patent
permissions needed to keep the dual-license layout viable long-term.

## Development

```bash
pnpm install
pnpm build && pnpm typecheck && pnpm lint && pnpm test
pnpm smoke   # end-to-end walking skeleton
```

- TDD for policy-engine and chain/proof code (correctness-critical).
- Conventional commits (`feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`).
- No new dependencies with install scripts without a note in TASKS.md.
- Never commit secrets. The gateway must never log credentials (rule R2).

## Engineering rules

The 10 binding rules live in [CLAUDE.md](CLAUDE.md) §Rules. The short version:
fail closed on spend, log before act, treat agent input as hostile, and the
red-team suite must stay red for attackers.
