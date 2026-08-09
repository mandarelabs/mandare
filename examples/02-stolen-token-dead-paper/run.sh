#!/usr/bin/env bash
# Runs Demo 2 — stolen token refused, kill halts a running agent. No API keys.
set -euo pipefail
cd "$(dirname "$0")/../.."
exec pnpm demo:dead-paper
