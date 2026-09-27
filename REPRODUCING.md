# Reproducing Mandare builds

Our reproducibility bar (stated honestly, per BUILD-DECISIONS Q25): **pinned
lockfile + trusted-publishing provenance + independently rebuildable from the
tagged commit.** We do not claim bit-for-bit reproducibility.

## Rebuild any release

```bash
git clone https://github.com/mandarelabs/mandare
cd mandare
git checkout <release-tag>
corepack enable                # pins pnpm to the version in package.json
pnpm install --frozen-lockfile # exact locked dependency tree, scripts disabled
pnpm build && pnpm test && pnpm red-team
```

## Verify what npm serves you (once packages are published)

```bash
npm audit signatures                        # provenance + registry signatures
gh attestation verify oci://ghcr.io/mandarelabs/<image> --owner mandarelabs
```

Releases are published via npm Trusted Publishing (OIDC — no long-lived
tokens exist), with SLSA build provenance from the tagged GitHub Actions run.
The release workflow is `.github/workflows/release.yml`: it publishes only
from a `v*` tag on the public repository, through the `release` environment,
with every third-party action pinned by commit SHA. The npm set is the CLI's
full dependency closure plus the MCP server (12 packages); CI packs that set
and installs it into an empty directory on every push
(`pnpm pack-install-smoke`).

## Verify the OpenClaw skill package

```bash
node scripts/verify-openclaw-skill.mjs <skill-directory> --expect-key <release-key-hex>
```

The release key's public hex is attached to each GitHub release as
`RELEASE-KEY.hex` and published at mandare.dev/security; pin it from a
source other than the download you are checking.
