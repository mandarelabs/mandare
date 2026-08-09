#!/usr/bin/env bash
# Runs Demo 5 — witnessed heads convict truncation and rewrites. No API keys.
set -euo pipefail
cd "$(dirname "$0")/../.."
exec pnpm demo:witness
