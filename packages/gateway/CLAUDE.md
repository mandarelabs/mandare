# @mandarelabs/gateway (AGPL-3.0-only)

The first door: local Fastify proxy for LLM traffic. The request flow in
`server.ts` is the CANONICAL door shape every later door (vault, card
connector) copies:

```
validate body (R4) → policy.evaluate (throw/deny ⇒ 403/503, nothing happens)
→ INTENT entry chained  (fail ⇒ 503 — no entry, no action; R1+R3)
→ forward to provider
→ RESULT entry chained  (fail ⇒ gateway HALTS — never act off the record)
→ pass response through with x-mandare-*-entry headers
```

## Hard rules

- **R2:** the provider key must NEVER appear in logs, errors, ledger entries,
  or responses. `start.ts` echoes config field-by-field for this reason.
- **Fail-closed (R1):** no credential → 503; ledger unreachable → 503; result
  write failed → halted=true and every subsequent request 503s. Do not add
  "graceful degradation" to any spend path.
- Localhost binding by default — this is a local door, not a public service.

## S0 scope notes

- One provider: OpenRouter, non-streaming (`stream: true` → 400). Its
  response carries authoritative `usage.cost` (USD) → micros in the ledger.
- Identity is static env config (`MANDARE_ACTOR`, `MANDARE_MANDATE_ID`
  defaulting to `mnd_dev_unmandated`) — honest placeholder until S3/S4.
- S2 adds: Anthropic/OpenAI adapters (port Portkey's MIT transforms
  selectively), streaming usage true-up rules (Q16: OpenAI include_usage
  final chunk; Anthropic message_start+message_delta merge; Gemini cumulative
  usageMetadata — last chunk only), real policy engine, OpenRouter
  provisioning-key rail.

## Testing

`buildGateway` takes injected `ledger`/`policy`/`fetchImpl` — tests fake the
provider and failure modes without network. Keep it that way.
