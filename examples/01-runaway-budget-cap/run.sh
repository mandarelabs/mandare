#!/usr/bin/env bash
# Runs Demo 1 — the runaway loop dies at €20. Mock provider, no API keys.
set -euo pipefail
cd "$(dirname "$0")/../.."
exec pnpm demo
