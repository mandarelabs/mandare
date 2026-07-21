# @mandarelabs/spec (Apache-2.0)

**FROZEN CONTRACT (rule R6).** Any change to schemas, canonical JSON, or hash
rules requires: plan mode + a TASKS.md decision entry + a schema version bump.
Two independent implementations must produce identical hashes from this spec.

## Contents

- `mandate.ts` — MandateV1 (SPEC §5): scopes discriminated on `type`
  (`spend`/`action`), approvals, optional dormant `billing_identity`.
- `ledger-entry.ts` — LedgerEntryV1 (SPEC §6): intent/result pairing via
  `action.type` + `outcome_ref` (= intent's entry_hash); `correction_of` for
  Storno-style corrections; `salt` per entry; `hw_counter` reserved for Tier 3.
- `signature.ts` — SignatureBlock with `key_provenance` (R10:
  software|keychain|tpm), timestamp/currency primitives.
- `canonical.ts` — THE canonical JSON. Strict: rejects non-plain objects,
  non-finite numbers, undefined in arrays.
- `hash.ts` (portable WebCrypto, async) / `hash-node.ts` (node:crypto, sync) —
  must stay byte-identical; tests assert it.
- `validate.ts` — boundary parsers (R4).

## Invariants that must never drift

- `entry_hash = sha256(canonicalJson(entry minus entry_hash, door_signature))`.
- Door signature signs the RAW 32 BYTES of entry_hash (not the hex string).
- Money = integer micros (`CURRENCY_MICROS_PER_UNIT = 1e6`).
- Hex is lowercase; base64url unpadded; timestamps UTC `Z` only.
- Genesis `prev_hash` = 64 zeros.

## Portability

`canonical.ts`, `hash.ts`, schemas, `validate.ts` must not import Node-only
APIs — the browser/edge verifier depends on it. Node-only code goes in
`*-node.ts` files.

## Commands

`pnpm --filter @mandarelabs/spec build | typecheck | test | lint`
