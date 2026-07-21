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
The release workflow is in `.github/workflows/release.yml`; it is currently a
stub and will be completed before the first published release.
