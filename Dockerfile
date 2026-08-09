# Mandare self-host image (S7, SPEC §11): ONE image, four roles — gateway,
# witness, dashboard, demo — selected by the compose service command. Built
# from source on the user's machine (`docker compose up` builds it); nothing
# is pulled from a registry until launch publishes signed images (Q24).
#
# v0 pragmatism, stated plainly: the image carries the full built monorepo
# including dev node_modules — simplest single-install build, fastest first
# `up`. Slim per-service images (pnpm deploy) are launch-time work.
FROM node:24-slim

ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
    NEXT_TELEMETRY_DISABLED=1 \
    NODE_ENV=production
RUN corepack enable

WORKDIR /app

# Manifests first so dependency layers cache across source edits.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json tsconfig.base.json eslint.config.js ./
COPY packages/spec/package.json packages/spec/
COPY packages/ledger/package.json packages/ledger/
COPY packages/verifier/package.json packages/verifier/
COPY packages/policy-engine/package.json packages/policy-engine/
COPY packages/gateway/package.json packages/gateway/
COPY packages/vault/package.json packages/vault/
COPY packages/passport/package.json packages/passport/
COPY packages/card-rail/package.json packages/card-rail/
COPY packages/witness/package.json packages/witness/
COPY packages/witness-protocol/package.json packages/witness-protocol/
COPY packages/sdk/package.json packages/sdk/
COPY packages/mcp-server/package.json packages/mcp-server/
COPY apps/cli/package.json apps/cli/
COPY apps/dashboard/package.json apps/dashboard/
COPY apps/docs/package.json apps/docs/
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile --prod=false

COPY . .
RUN pnpm build

# The demo mandate, ledgers, witness state live here (compose named volume).
VOLUME /data

# Default command shows what this image can do; compose overrides per service.
CMD ["node", "apps/cli/dist/main.js", "help"]
