# Mandare key directory — design (S1)

**Status:** implemented (S1). Closes S0 review finding **H1** — `mandare
verify --door-key` needed a real out-of-band source; `meta.door_public_key`
inside the ledger file proves consistency, never authorship (a file-level
attacker re-signs the chain under a swapped key; the red-team suite
demonstrates it).

## One format for everything

Per SPEC §4, there is exactly ONE directory scheme in the system. It serves:

- **door keys** today (gateway/vault/connector signing keys — what the
  verifier anchors ledger authorship against), and
- **agent passport keys** from S4 on (presented via RFC 9421 HTTP Message
  Signatures with a `Signature-Agent` header pointing at the directory).

No door-only format exists, by design constraint.

## Format

A **JWK Set** (RFC 7517), profiled exactly like the Web Bot Auth key
directory (draft-meunier-web-bot-auth / http-message-signatures-directory),
which is how RFC 9421 verifiers already discover keys:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "<base64url raw 32-byte public key>",
      "kid": "<RFC 7638 JWK thumbprint, base64url>",
      "use": "sig",
      "alg": "EdDSA",
      "nbf": 1767225600,
      "exp": 1782950400,
      "mnd:role": "door"
    }
  ]
}
```

Profile rules (enforced by `parseKeyDirectory` in `@mandarelabs/verifier`):

- Consumers use `OKP`/`Ed25519` keys and **skip** other key types (standard
  JWKS must-ignore semantics — a shared JWKS may host foreign keys).
- **`nbf`/`exp`** (NumericDate seconds, per-key) bound what a key can vouch
  for: a ledger entry only verifies if its `ts` falls inside the signing
  key's window. This is what makes **rotation** enforceable — a rotated-out
  (possibly stolen) door key cannot sign new history (`KEY_EXPIRED`).
- **`kid`** SHOULD be the RFC 7638 thumbprint. Ledger entries are matched by
  `door_signature.key_id` = sha256 hex of the raw public key, which is
  *derived* from `x` — the directory needs no Mandare-specific id member.
- **`mnd:role`** (`door` | `agent`) is a private-use extension member
  (RFC 7517 §4); unknown consumers ignore it.
- Structural garbage is rejected loudly (`DirectoryParseError`, rule R4).

## Serving

- Self-hosted: `https://<operator-domain>/.well-known/http-message-signatures-directory`
  with content type `application/http-message-signatures-directory+json`.
- Tessera-hosted (later): same path under the operator's Tessera tenant.
- Local file: fine for air-gapped verification; the trust requirement is
  only that the channel is independent of the ledger file.

## Tooling

- **Publish:** `mandare directory --key <door.pem> [--key …] [--role door]
  [--nbf s] [--exp s] [--out directory.json]` — extracts public keys from
  door PEMs (private material never leaves the machine).
- **Verify:** `mandare verify --db ledger.db --key-directory <path|url>` —
  multi-door chains resolve per-entry by `key_id`; failures are
  `KEY_UNKNOWN` (signer not in directory) and `KEY_EXPIRED` (signed outside
  the key's validity window).

## Threat model recap

| Attack | Outcome |
|---|---|
| File attacker swaps `meta.door_public_key` + re-signs chain | Caught: directory key wins (`KEY_MISMATCH`/`KEY_UNKNOWN`) |
| Rogue process appends entries under its own key | Caught: `KEY_UNKNOWN` |
| Stolen rotated-out door key signs new entries | Caught: `KEY_EXPIRED` (post-`exp` timestamps) |
| Attacker controls the directory channel too | Out of scope for S1 — witnessing (S6) + Tessera countersigning bound it |

Backdating `ts` into the old key's window is bounded by witnessing (S6):
witnessed heads pin when the chain actually grew.
