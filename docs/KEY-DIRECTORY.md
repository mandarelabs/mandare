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
- **agent passport keys**: the format can carry them (`mnd:role: "agent"`),
  but doors do not resolve agent keys through the directory today. A door
  verifies the RFC 9421 request signature against the key in the presented
  passport, and `Signature-Agent` carries the agent's did:key, not a
  directory URL.

No door-only format exists, by design constraint.

## Format

A **JWK Set** (RFC 7517), modelled on the HTTP Message Signatures Directory
from the Web Bot Auth work: the individual Internet-Draft
`draft-meunier-http-message-signatures-directory` (last revision -05,
2 March 2026). It is not a conforming implementation of that draft or of its
successor — see [Relation to the Web Bot Auth drafts](#relation-to-the-web-bot-auth-drafts).
A directory with one door key:

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
  key's window (`KEY_EXPIRED` otherwise). `ts` is chosen by the signer, so
  the window alone only stops a rotated-out key that tells the truth about
  the time — see the threat-model recap for what bounds backdating.
- **`kid`** SHOULD be the RFC 7638 thumbprint. Ledger entries are matched by
  `door_signature.key_id` = sha256 hex of the raw public key, which is
  *derived* from `x` — the directory needs no Mandare-specific id member.
- **`mnd:role`** (`door` | `agent`) is a private-use extension member
  (RFC 7517 §4); unknown consumers ignore it.
- Structural garbage is rejected loudly (`DirectoryParseError`, rule R4).

## Relation to the Web Bot Auth drafts

The individual draft named above has been replaced. The directory format is
now §5.5 of the IETF Web Bot Auth working group's
`draft-ietf-webbotauth-httpsig-protocol` (-00, 1 September 2026). Compared
field by field with that revision on 2026-10-03: **no interoperability with
Web Bot Auth directories or verifiers is claimed, and none has been tested.**

Shared with the draft: the JWK Set container; the `kty`, `crv`, `x`, `kid`,
`use`, `nbf` and `exp` members of the draft's example entry, with `kid` as
the RFC 7638 thumbprint; the well-known path and the media type under
[Serving](#serving).

Different:

- **`alg`.** `mandare directory` writes `"alg": "EdDSA"`, the JOSE name. The
  draft (like the one it replaced) restricts `alg` to the HTTP Signature
  Algorithms registry of RFC 9421, where this key type is `ed25519`.
  `parseKeyDirectory` does not read `alg`.
- **Key selection.** The draft selects a key by matching a request's `keyid`
  against `kid`. Mandare's verifier does not select by `kid`; it matches a
  ledger entry's `door_signature.key_id` (sha256 hex of the raw public key)
  and accepts any string as `kid`.
- **What the keys verify.** The draft's keys verify HTTP request signatures.
  These keys verify door signatures on ledger entries, and `nbf`/`exp` bound
  an entry's `ts`. The draft carries `nbf`/`exp` in its example and gives
  rotation guidance, but defines no verifier rule for them.
- **Discovery and transport.** The draft resolves the directory from a
  `Signature-Agent` URL and requires HTTPS, a 200 response and no automatic
  redirects. `mandare verify --key-directory` takes a path or URL from the
  operator, also reads local files, refuses `http://` unless
  `--insecure-directory` is set, accepts any 2xx and follows redirects.
- **`mnd:role`** is a Mandare extension member; the draft does not define it.

## Serving

- Self-hosted: `https://<operator-domain>/.well-known/http-message-signatures-directory`
  with content type `application/http-message-signatures-directory+json`.
- Mandare Cloud-hosted (later): same path under the operator's tenant.
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
| Stolen rotated-out door key signs new entries with honest timestamps | Caught: `KEY_EXPIRED` (post-`exp` timestamps) |
| Same key, `ts` backdated into its window, appended after entries of the new key | Caught: `TS_REGRESSION` — doors never write a timestamp earlier than the previous entry's, and the verifier fails any regression (W-4) |
| Any entry claiming a `ts` after the witness recorded it | Caught by `verify --witness`: `TIMELINE VIOLATION` (latest witness-signed head, 5 min clock skew) |
| Same key, `ts` backdated into its window, appended to a ledger the new key never wrote to (e.g. the retired ledger of a rotated door) | **Not caught by verification** — see residual below |
| Attacker controls the directory channel too | Out of scope for S1 — witnessing (S6) + witness countersigning bound it |

**Residual (stated, not hidden — audit 2026-09, W-4).** A thief holding a
rotated-out key can append to the *tail* of a chain that the successor key
never wrote to, with `ts` backdated inside the old key's window. Each such
entry is internally valid, the timeline does not regress, and a witness
accepts the growth under the old key's source (the thief holds that key).
What exposes it is *when* the witness first saw it: the served head's
`witnessed_at` lands after the key's `exp`. `verify` does not fail on that
today — the witness serves per-record history unsigned, so only the latest
head's time is checkable. Mitigations until a signed-history check lands:
retire a rotated door's ledger (kill its agents, stop its witness stream)
and alert on any new witnessed head for a source whose key is past `exp`.
