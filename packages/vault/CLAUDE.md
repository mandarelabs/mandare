# @mandarelabs/vault (AGPL-3.0-only)

The credential door (SPEC §3.1). Holds every third-party secret and the door
signing key so nothing agent-reachable ever touches raw key material (R2), and
mints the short-lived tokens agents present to the gateway.

## Shape

```
master key (OS keychain via @napi-rs/keyring, or explicit 0600 file)
  └─ encrypts every secret value in the vault SQLite DB (AES-256-GCM,
     account name as AAD) — a leaked DB file is inert without the key
     ├─ provider keys        (provider:anthropic | openai | openrouter)
     ├─ provisioning key     (provisioning:openrouter)
     ├─ door signing key PEM  (door:<doorId>)
     └─ scoped-token registry (token_id → actor, mandate, sealed PoP secret k,
                               issued/expires, revoked)
```

## Hard rules

- **Keychain-or-fail-closed (R1):** `MANDARE_VAULT_BACKEND=keychain` (default)
  and the keychain is unavailable ⇒ `VaultKeychainUnavailableError`, the vault
  refuses to open. It NEVER silently downgrades to a plaintext file. Headless
  hosts opt into `file` on purpose (0600 master-key file, same trust model as
  the S0 door-key PEM). The `keychain` client is injectable so the fail-closed
  path is testable on any machine.
- **R2:** plaintext secret bytes exist only in-process, returned straight to
  the gateway for outbound provider headers. Nothing here is logged; ciphertext
  is bound to its slot by AAD so a DB-file attacker can't swap a provider key
  into the door-key slot.

## Scoped tokens = why a stolen token is dead paper

Proof-of-possession, an S3 precursor to S4's RFC 9421 request signatures. A
token is a public id + a per-token secret `k`; each request carries
`HMAC(k, tokenId|METHOD|path|timestamp|nonce)`.

- Leak the token id alone → no `k` → no valid proof (**binding**).
- Capture a signed request → its nonce is single-use and its timestamp goes
  stale in ±120s (**replay** refused).
- TTL ≤ 30 min (SPEC ceiling, enforced) and `mandare kill` flip the whole
  token dead (**TTL / revocation**).
- Honest residual: theft of id AND k is bounded only by TTL + kill — S4's
  non-exportable passport key closes it. Documented, not hidden.

## Revocation vocabulary (ONE, shared with S4/S6)

`status-list.ts` renders revocation state as an IETF Token Status List /
W3C Bitstring Status List (`@sd-jwt/jwt-status-list`, BUILD-DECISIONS Q4):
`status_list: { bits: 1, lst }`, `revocation_ref = statuslist:<listId>#<index>`.
The AUTHORITATIVE record is the ledger `agent.revoke` entry + its subject-keyed
projection (packages/ledger); this module only serializes it into the bytes S6
publishes unchanged. Enforcement never depends on the bitstring — the gateway
checks the ledger projection directly, offline and fail-closed.

## Testing

`Vault.open(config, { keychain, clock })` injects a fake keychain and clock, so
every path — keychain-unavailable, TTL expiry, replay — is deterministic with
no OS keychain and no wall-clock waits. Use `MANDARE_VAULT_BACKEND=file` for
integration-style tests that want a real master key.
