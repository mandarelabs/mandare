import { type Static, Type } from '@sinclair/typebox';

/**
 * Where the signing key material lives (rule R10: present in every
 * credential/entry schema from day one so Tier-3 hardware attestation slots
 * in without a migration).
 */
export const KeyProvenance = Type.Union(
  [Type.Literal('software'), Type.Literal('keychain'), Type.Literal('tpm')],
  { description: 'Storage class of the signing key material' }
);
export type KeyProvenance = Static<typeof KeyProvenance>;

/**
 * Detached Ed25519 signature block, shared by mandates and ledger entries.
 * `value` is the base64url-encoded signature over the object's frozen
 * preimage (for ledger entries: the raw 32 bytes of `entry_hash`).
 */
export const SignatureBlock = Type.Object(
  {
    alg: Type.Literal('EdDSA'),
    /** Key identifier: lowercase sha256 hex of the raw 32-byte Ed25519 public key. */
    key_id: Type.String({ pattern: '^[0-9a-f]{64}$' }),
    key_provenance: KeyProvenance,
    /** base64url, no padding. */
    value: Type.String({ pattern: '^[A-Za-z0-9_-]+$' }),
  },
  { additionalProperties: false }
);
export type SignatureBlock = Static<typeof SignatureBlock>;

/** ISO-8601 UTC timestamp with trailing Z — the only timestamp form Mandare uses. */
export const IsoUtcTimestamp = Type.String({
  pattern: '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,9})?Z$',
});

/** ISO-4217 alphabetic currency code. */
export const CurrencyCode = Type.String({ pattern: '^[A-Z]{3}$' });

/**
 * All monetary amounts in Mandare are integers in MICRO-units of the currency:
 * 1 currency unit = 1_000_000 micros (Google-Ads-style). Chosen over cents
 * because LLM per-call costs are routinely far below one cent and the ledger
 * must record them without rounding to zero.
 */
export const CURRENCY_MICROS_PER_UNIT = 1_000_000;
