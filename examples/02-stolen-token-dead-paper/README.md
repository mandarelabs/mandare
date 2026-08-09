# A stolen credential is dead paper — and one command kills a running agent

Agent frameworks pass API keys around as env vars. Steal the env, own the
spend — and nothing in the transcript even shows it happened. This scenario
shows the opposite posture: the agent never holds a raw provider key at all,
and everything it does hold is worthless to a thief.

The gateway sources provider keys from a **vault** (AES-256-GCM, master key
in the OS keychain). The agent gets a **scoped token**: a public id plus a
private proof-of-possession secret, ≤30-minute TTL. Every request carries an
HMAC over `tokenId | method | path | timestamp | nonce` — single-use nonce,
±120s clock skew.

## What happens

```
[agent]  legitimate signed call            → 200 OK
[thief]  stolen token id, forged proof     → 401 BAD_POP (binding: no pop secret)
[thief]  replay of a captured request      → 401 REPLAYED_NONCE (single-use nonce)

$ mandare kill did:mandare:dev-agent
  KILLED did:mandare:dev-agent
    ledger entry: df0059cd23c51143…  (seq 3)
    vault:        1 live token(s) revoked
    status:       written to the LOCAL ledger — the gateway fails closed on
                  its next request (offline, un-jammable)

[agent]  valid signed call AFTER the kill  → 403 AGENT_REVOKED
         the refusal is ledger entry 6755e6ee1d565cc9…
```

Three failure modes, three distinct refusals, all recorded:

1. **Theft of the token id** fails — it's proof-of-possession, not bearer.
2. **Replay of a captured request** fails — the nonce is single-use (and a
   failed forgery can't burn a legitimate client's nonce; the nonce is
   claimed only *after* the proof verifies).
3. **A kill lands mid-task** — `mandare kill` appends a revocation entry to
   the local ledger and flips the projection in one transaction. No cloud
   round-trip: a kill that needs the network is a kill that can be jammed.

## The design rule underneath

Revocation is a **ledger projection**, exactly like the budget counters: the
authoritative record is the `agent.revoke` entry; the status table the
gateway checks per-request is derived from it, and `mandare verify` proves
`replay(ledger) == revocation_status`. The same records render into an IETF
Token Status List bitstring, so external verifiers consume the standard
vocabulary — one revocation mechanism, no drift.

## Run it

From the repo root (once): `./install.sh` — then:

```bash
./run.sh
```

Uses a real vault (file backend) and real PoP signing end to end; mock
provider, no API keys. CI asserts every step. Captured output:
[`docs/demos/S3-dead-paper-demo.txt`](../../docs/demos/S3-dead-paper-demo.txt).

## Where to look in the code

- Scoped tokens + verify order: `packages/vault/src/tokens.ts`
- Kill as a one-transaction ledger op: `packages/ledger/src/revocation-ledger.ts`
- Token-theft red-team suite: `packages/gateway/test/red-team/token-theft.test.ts`
- The demo script: `scripts/demo-dead-paper.mjs`
