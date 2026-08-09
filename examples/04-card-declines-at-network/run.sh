#!/usr/bin/env bash
# Runs Demo 4 — one cap across LLM + card rails, decline at the network.
# Simulated card network (signed webhooks), no Stripe account needed.
set -euo pipefail
cd "$(dirname "$0")/../.."
exec pnpm demo:card
