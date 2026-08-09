import { type Static, Type } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';

/**
 * Wire messages of the Mandare witness protocol v1 (SPEC §3.2, §6 locks 4–5).
 *
 * The protocol is deliberately content-free: the ONLY thing a door ever sends
 * off-machine is an RFC 6962 tree head over its ledger's entry hashes — a
 * 32-byte root plus a size. Every entry hash commits to a random 16-byte salt
 * inside its preimage (packages/spec), so neither the root nor any proof node
 * derived from it can be reversed or dictionary-tested against guessed entry
 * contents. The witness learns THAT a ledger grew, never WHAT it recorded —
 * "we hold proofs, not data" as a wire format.
 *
 * Sources are self-authenticating: `source_id` is the sha256 of the door's
 * raw Ed25519 public key (identical to the ledger's `door_key_id`), and every
 * submission is signed by that key. Nobody can pollute another source's
 * witnessed history without its signing key.
 */

export const WITNESS_PROTOCOL = 'mandare-witness/1';

const Sha256Hex = Type.String({ pattern: '^[0-9a-f]{64}$' });
/** ISO-8601 UTC, Z only — same profile as the ledger-entry schema. */
const IsoUtc = Type.String({
  pattern: '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,3})?Z$',
});

/** RFC 6962 tree head: the compact, content-free commitment to a ledger prefix. */
export const TreeHeadSchema = Type.Object(
  {
    /** Number of leaves = ledger entries committed to (tree size 2^31-1 max). */
    size: Type.Integer({ minimum: 0, maximum: 2 ** 31 - 1 }),
    root: Sha256Hex,
  },
  { additionalProperties: false }
);
export type TreeHeadMessage = Static<typeof TreeHeadSchema>;

/**
 * A head submission. `prev` names the latest head the witness has recorded
 * for this source and `consistency_proof` proves the new head extends it
 * append-only — the witness REFUSES any submission that is not a provable
 * extension of what it already witnessed, so a source's witnessed history is
 * fork-free by construction, not by trust.
 */
export const HeadSubmissionPayload = Type.Object(
  {
    protocol: Type.Literal(WITNESS_PROTOCOL),
    type: Type.Literal('head.submit'),
    /** sha256 hex of the door's raw public key (== the ledger's door_key_id). */
    source_id: Sha256Hex,
    /** Raw 32-byte Ed25519 door public key, lowercase hex. */
    door_public_key: Sha256Hex,
    head: TreeHeadSchema,
    /** The witnessed head this submission extends; null on first contact. */
    prev: Type.Union([TreeHeadSchema, Type.Null()]),
    /** RFC 6962 consistency proof prev → head (empty when prev is null or sizes are equal). */
    consistency_proof: Type.Array(Sha256Hex, { maxItems: 64 }),
    ts: IsoUtc,
  },
  { additionalProperties: false }
);
export type HeadSubmissionPayload = Static<typeof HeadSubmissionPayload>;

/**
 * A witness acknowledgment: the witness's signed statement that it has
 * durably recorded `head` for `source_id`. Doors verify the signature against
 * an OUT-OF-BAND witness public key and match `head` against what they just
 * submitted — a replayed ack for an older head fails the match, a forged ack
 * fails the signature (both red-teamed).
 */
export const HeadAckPayload = Type.Object(
  {
    protocol: Type.Literal(WITNESS_PROTOCOL),
    type: Type.Literal('head.ack'),
    source_id: Sha256Hex,
    head: TreeHeadSchema,
    witnessed_at: IsoUtc,
    /** sha256 hex of the witness's raw public key. */
    witness_key_id: Sha256Hex,
  },
  { additionalProperties: false }
);
export type HeadAckPayload = Static<typeof HeadAckPayload>;

const SignatureB64Url = Type.String({ pattern: '^[A-Za-z0-9_-]{86}$' });

/** Envelope: payload + Ed25519 signature over sha256(canonicalJson(payload)). */
export const SignedHeadSubmission = Type.Object(
  { payload: HeadSubmissionPayload, signature: SignatureB64Url },
  { additionalProperties: false }
);
export type SignedHeadSubmission = Static<typeof SignedHeadSubmission>;

export const SignedHeadAck = Type.Object(
  { payload: HeadAckPayload, signature: SignatureB64Url },
  { additionalProperties: false }
);
export type SignedHeadAck = Static<typeof SignedHeadAck>;

/** One row of a source's witnessed head history, as served by the witness. */
export const WitnessedHeadRecord = Type.Object(
  {
    source_id: Sha256Hex,
    head: TreeHeadSchema,
    /** Door-claimed submission time. */
    ts: IsoUtc,
    /** Witness-side receive time — the time that counts for "already witnessed". */
    witnessed_at: IsoUtc,
  },
  { additionalProperties: false }
);
export type WitnessedHeadRecord = Static<typeof WitnessedHeadRecord>;

/**
 * An anchoring epoch: the witness's aggregate over every source's latest
 * witnessed head at snapshot time. The aggregate is itself an RFC 6962 tree
 * whose leaf inputs are `aggregateLeafInput(...)` of each per-source head;
 * its root is what gets publicly anchored (OpenTimestamps, Q6).
 */
/** Max serialized OTS receipt we accept (well above a real proof; parse-bound backstop, R4). */
const MAX_OTS_BASE64 = 4 * 1024 * 1024;

export const EpochSummary = Type.Object(
  {
    epoch: Type.Integer({ minimum: 1 }),
    created_at: IsoUtc,
    aggregate: TreeHeadSchema,
    anchor_status: Type.Union([
      Type.Literal('none'),
      Type.Literal('pending'),
      Type.Literal('confirmed'),
    ]),
    /** Anchor receipt (OpenTimestamps .ots bytes), base64 — null until anchored. */
    ots_base64: Type.Union([Type.String({ maxLength: MAX_OTS_BASE64 }), Type.Null()]),
    anchor_kind: Type.Union([Type.String({ minLength: 1, maxLength: 64 }), Type.Null()]),
    /**
     * The WITNESS's signature over this epoch summary (minus this field),
     * so a relying party cannot be handed an attacker-fabricated aggregate:
     * the aggregate root is witness-attested, not certificate-self-declared
     * (review S6-H2). Present on served epochs; absent on freshly built,
     * not-yet-served summaries.
     */
    witness_signature: Type.Optional(
      Type.Object(
        { key_id: Sha256Hex, value: Type.String({ pattern: '^[A-Za-z0-9_-]{86}$' }) },
        { additionalProperties: false }
      )
    ),
  },
  { additionalProperties: false }
);
export type EpochSummary = Static<typeof EpochSummary>;

/** Proof that one source's witnessed head is a leaf of an anchored epoch aggregate. */
export const EpochInclusion = Type.Object(
  {
    epoch: EpochSummary,
    leaf: WitnessedHeadRecord,
    leaf_index: Type.Integer({ minimum: 0 }),
    inclusion_proof: Type.Array(Sha256Hex, { maxItems: 64 }),
  },
  { additionalProperties: false }
);
export type EpochInclusion = Static<typeof EpochInclusion>;

export class WitnessMessageError extends Error {
  readonly errors: readonly string[];

  constructor(name: string, errors: readonly string[]) {
    super(`${name} validation failed: ${errors.join('; ')}`);
    this.name = 'WitnessMessageError';
    this.errors = errors;
  }
}

function parseAs<T extends import('@sinclair/typebox').TSchema>(
  schema: T,
  name: string,
  value: unknown
): Static<T> {
  if (Value.Check(schema, value)) {
    return value;
  }
  const errors = [...Value.Errors(schema, value)].map((e) => `${e.path || '/'}: ${e.message}`);
  throw new WitnessMessageError(name, errors);
}

/** Boundary parsers (R4): everything arriving over the wire is hostile. */
export function parseSignedHeadSubmission(value: unknown): SignedHeadSubmission {
  return parseAs(SignedHeadSubmission, 'SignedHeadSubmission', value);
}

export function parseSignedHeadAck(value: unknown): SignedHeadAck {
  return parseAs(SignedHeadAck, 'SignedHeadAck', value);
}

export function parseWitnessedHeadRecord(value: unknown): WitnessedHeadRecord {
  return parseAs(WitnessedHeadRecord, 'WitnessedHeadRecord', value);
}

export function parseEpochInclusion(value: unknown): EpochInclusion {
  return parseAs(EpochInclusion, 'EpochInclusion', value);
}
