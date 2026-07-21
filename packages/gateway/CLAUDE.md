# @mandarelabs/gateway (AGPL-3.0-only)

The first door: local Fastify proxy for LLM traffic. The request flow in
`server.ts` is the CANONICAL door shape every later door (vault, card
connector) copies:

```
validate body (R4, coerceTypes OFF) → estimate cost (pricing.ts)
→ policy.evaluate (SPEC §5 order; deny ⇒ DENIED entry + 403)
→ RESERVE: INTENT entry carries the estimate, budget-guarded INSIDE the
  ledger transaction (refusal ⇒ DENIED entry + 403 — no entry, no counter
  change; concurrent cap overshoot impossible by construction)
→ forward (streaming passes through; an SSE tee parses usage per Q16)
→ SETTLE: RESULT entry with true cost releases the reservation
  (fail ⇒ gateway HALTS — never act off the record)
→ response with x-mandare-*-entry headers (streams: trailer SSE comment)
```

## Hard rules

- **R2:** provider keys must NEVER appear in logs, errors, ledger entries,
  or responses. `start.ts` echoes config field-by-field for this reason.
- **Fail-closed (R1):** no mandate / no credential / no FX rate / stale
  projection → 503; unpriced model on a direct provider → DENIED (no price =
  no metering = no spend); result write failed → halted. Outcome-unknown
  provider failures settle AT THE RESERVED ESTIMATE, never 0. Do not add
  "graceful degradation" to any spend path.
- Localhost binding by default — this is a local door, not a public service.

## S2 architecture notes

- NATIVE provider surfaces, no unified transform: `/v1/messages` (Anthropic,
  base URL convention WITHOUT /v1) and `/v1/chat/completions`
  (OpenAI/OpenRouter, base URLs WITH /v1). Agents just point their SDK base
  URL at the gateway.
- True-up per Q16: OpenAI stream_options.include_usage final chunk;
  Anthropic message_start + final message_delta merge; OpenRouter
  `usage.cost` is AUTHORITATIVE (Q14). Tokenizer-free estimation ONLY for
  pre-flight reservation and aborted streams (`pricing.ts`).
- One ledger currency (default EUR); provider USD costs convert at the
  explicit MANDARE_USD_PER_LEDGER_UNIT rate — never an invented default.
- `provisioning.ts`: OpenRouter per-agent capped keys (Q14, belt-and-
  suspenders with our metering). Mock-tested only until the founder's
  OpenRouter account exists.
- Identity is still static env config (`MANDARE_ACTOR`); mandate comes from
  MANDARE_MANDATE_PATH (schema-validated; signature verification lands with
  SD-JWT in S4). NO mandate ⇒ spend path closed — never allow-all.

## Red-team (`test/red-team/`, rule R5 — CI gate via `pnpm red-team`)

budget-race (concurrent overshoot must be impossible) · hostile-input (R4:
meter-blinding, prototype poisoning, type confusion — coerceTypes stays OFF)
· provider-failure (fail closed, never open). Never weaken these.

## Testing

`buildGateway` takes injected `ledger`/`policy`/`fetchImpl`/`timeouts` —
tests fake the provider and failure modes without network. Streaming tests
need a real socket (`app.listen`), inject() can't see hijacked replies.
