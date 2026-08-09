# Licensing

Mandare uses a dual-license layout (the "Grafana pattern"): the repository as a
whole is **AGPL-3.0-only**, with specific packages released under
**Apache-2.0** so they can be embedded anywhere — including in proprietary
gateways, frameworks, and verifier tools.

## Apache-2.0 packages

| Package | Path | Why Apache |
|---|---|---|
| `@mandarelabs/spec` | `packages/spec` | The schemas and hashing rules are an open contract; anyone must be able to implement them. |
| `@mandarelabs/policy-engine` | `packages/policy-engine` | Designed for embedding in third-party gateways and agent frameworks. |
| `@mandarelabs/verifier` | `packages/verifier` | Anyone must be able to verify a Mandare ledger — including parties who distrust us. |
| `@mandarelabs/passport` | `packages/passport` | Passports, delegation credentials, and RFC 9421 request signatures must be verifiable by any relying party — including parties who distrust us. |
| `@mandarelabs/witness-protocol` | `packages/witness-protocol` | The witness wire protocol, client, anchoring interface, and integrity-certificate verification must be inspectable and embeddable by anyone — including parties who distrust us. |

Planned Apache-2.0 packages (not yet created): `packages/sdk-ts`, `packages/sdk-py`.

Each Apache package carries its own `LICENSE` and `NOTICE` file and declares
`"license": "Apache-2.0"` in its `package.json`.

## AGPL-3.0-only packages

Everything not listed above, currently: `packages/ledger`, `packages/gateway`,
`packages/vault`, `packages/card-rail`, `packages/witness`, `apps/cli`.

## Import direction (enforced)

**Apache packages must never import AGPL code** — not at runtime, not in types.
AGPL code may freely import Apache packages. Shared utilities live in Apache
packages (`packages/spec`).

Enforcement is mechanical, not conventional:
- Turborepo Boundaries tags (`license:apache` may only depend on `license:apache`).
- `scripts/check-license-boundaries.mjs` walks the workspace dependency graph in CI and fails the build on violation.

This layout is permanent. We do not relicense (BUILD-DECISIONS Q20).
