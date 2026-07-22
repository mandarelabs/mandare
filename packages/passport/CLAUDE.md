# @mandarelabs/passport (Apache-2.0)

did:key identity + the delegation-credential chain + mandate SD-JWT transport
+ RFC 9421 request signatures. Everything verifies OFFLINE; embeddable by
parties who distrust us (same posture as `verifier`). NEVER import AGPL code.

Binding rulings (S4, founder):
- DID profile v1 = `did:key` ONLY (Ed25519, multibase base58btc + multicodec
  0xed01) for `principal` and `agent`. No resolver, no chain. `did:web` is the
  documented FUTURE organization profile (maps onto the S1 key directory) —
  out of scope.
- IDV/KYC is an interface + mock provider. Attestation records carry ONLY
  `{kyc_level, partner_id, date, ref_hash}` — never PII. The attestation
  authority runs in LOCAL mode (self-contained key); the cloud authority is a
  later, separate private-repo service.

Invariants:
- The passport chain is: trusted authority DID → owner attestation (sub=owner)
  → delegation credential (iss=owner, sub=agent, cnf=agent key). Any broken
  link ⇒ throw (no partial trust).
- Credentials carry `revocation_ref` in the SHARED status-list vocabulary
  (`statuslist:<listId>#<index>`); revocation ENFORCEMENT reads the ledger
  projection (never a fetch, never this package).
- Request signatures MUST cover @method, @path, @authority, content-digest,
  signature-agent — verifiers refuse narrower coverage (web-bot-auth itself
  accepts whatever Signature-Input declares; we do not).
- Mandate VCs keep the FROZEN MandateV1 JSON self-contained: the detached
  owner signature inside the payload stays valid on its own; the SD-JWT
  envelope is transport, not a replacement (both signed by the owner key).
- key_id convention everywhere: lowercase sha256 hex of the raw 32-byte
  public key (same as door keys / S1 directory).
