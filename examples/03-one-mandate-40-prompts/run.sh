#!/usr/bin/env bash
# Runs Demo 3 — one signed mandate, async human approvals. No API keys.
set -euo pipefail
cd "$(dirname "$0")/../.."
exec pnpm demo:mandate
