# Mandare self-host image (S7, SPEC §11): ONE image, four roles — gateway,
# witness, dashboard, demo — selected by the compose service command. Built
# from source on the user's machine (`docker compose up` builds it); nothing
# is pulled from a registry until launch publishes signed images (Q24).
#
# Two stages (S10-fix R-5): `build` installs everything and compiles; the
# runtime stage carries the built tree with PRODUCTION dependencies only
# (no compilers, test runners or linters) and runs as the unprivileged
# `node` user. Per-service images (pnpm deploy) remain later work.
FROM node:24-slim AS build

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

# Drop dev dependencies: a clean production-only install from the same store.
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    rm -rf node_modules apps/*/node_modules packages/*/node_modules && \
    CI=true pnpm install --prod --frozen-lockfile --prefer-offline

FROM node:24-slim AS runtime

ENV NEXT_TELEMETRY_DISABLED=1 \
    NODE_ENV=production

WORKDIR /app
COPY --from=build --chown=node:node /app /app

# Named volumes inherit these directories' ownership on first use, so the
# unprivileged user can write the ledger, mandate and witness state.
RUN mkdir -p /data /witness-state && chown node:node /data /witness-state
USER node

# The demo mandate, ledgers, witness state live here (compose named volume).
VOLUME /data

# Default command shows what this image can do; compose overrides per service.
CMD ["node", "apps/cli/dist/main.js", "help"]
