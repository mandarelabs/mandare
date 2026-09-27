#!/usr/bin/env bash
# Mandare solo-mode installer (no docker): build from a checkout and link the
# `mandare` CLI. One line from a clone:
#
#   ./install.sh
#
# It writes into this checkout (./bin/mandare) and needs no sudo. One global
# side effect, only when pnpm is missing: `corepack enable` adds pnpm shims
# next to your node binary (skip it by installing pnpm 10 yourself first).
# After npm launch this script will also offer `npm i -g @mandarelabs/cli`;
# building from source stays the path you can verify (REPRODUCING.md).
set -euo pipefail

need_node="22.13.0"
if ! command -v node >/dev/null 2>&1; then
  echo "error: node is required (>= ${need_node}) — https://nodejs.org" >&2
  exit 1
fi
node_version="$(node --version | sed 's/^v//')"
if [ "$(printf '%s\n%s\n' "$need_node" "$node_version" | sort -V | head -1)" != "$need_node" ]; then
  echo "error: node ${node_version} is too old (need >= ${need_node})" >&2
  exit 1
fi

if ! command -v pnpm >/dev/null 2>&1; then
  echo "[install] pnpm not found — running 'corepack enable' (adds pnpm shims next to node; the one global write)"
  corepack enable >/dev/null 2>&1 || {
    echo "error: corepack enable failed — install pnpm 10 manually: https://pnpm.io/installation" >&2
    exit 1
  }
fi

echo "[install] installing dependencies (lockfile-exact, install scripts disabled)"
pnpm install --frozen-lockfile

echo "[install] building"
pnpm build

mkdir -p bin
cat > bin/mandare <<WRAP
#!/usr/bin/env bash
exec node "$(pwd)/apps/cli/dist/main.js" "\$@"
WRAP
chmod +x bin/mandare

echo
echo "mandare installed → $(pwd)/bin/mandare"
echo
echo "Try it:"
echo "  ./bin/mandare help"
echo "  pnpm demo          # the runaway loop dying at €20, locally"
echo
echo "Optional: add it to your PATH:"
echo "  export PATH=\"$(pwd)/bin:\$PATH\""
