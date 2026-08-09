/**
 * @mandarelabs/witness-protocol — the Mandare witness protocol (Apache-2.0).
 *
 * Everything a party needs to SPEAK or CHECK the witness protocol without
 * trusting Mandare: message shapes and boundary parsers, the signing rule,
 * the door-side client, the aggregate-tree encoding, the anchoring interface
 * (OpenTimestamps + mock), and integrity-certificate build/verify. The
 * reference witness SERVER lives in `@mandarelabs/witness` (AGPL); this
 * package is the inspectable, embeddable surface (SPEC §3.2, §6 locks 4–5,
 * §9.4).
 */

export {
  EpochInclusion,
  EpochSummary,
  HeadAckPayload,
  HeadSubmissionPayload,
  SignedHeadAck,
  SignedHeadSubmission,
  WITNESS_PROTOCOL,
  WitnessMessageError,
  WitnessedHeadRecord,
  parseEpochInclusion,
  parseSignedHeadAck,
  parseSignedHeadSubmission,
  parseWitnessedHeadRecord,
  type TreeHeadMessage,
} from './messages.js';
export { signPayload, verifySignedPayload, type HeadSigner, type SignedMessage } from './signing.js';
export {
  WitnessClient,
  WitnessSyncError,
  fetchVerifiedWitnessedHead,
  type SyncResult,
  type WitnessClientOptions,
  type WitnessSyncErrorCode,
} from './client.js';
export {
  aggregateInclusionProof,
  aggregateLeafInput,
  buildAggregate,
  signEpochSummary,
  verifyAggregateInclusion,
  verifyEpochSummary,
  type AggregateSnapshot,
} from './aggregate.js';
export {
  BaseAnchor,
  MockAnchor,
  OpenTimestampsAnchor,
  type Anchor,
  type AnchorReceipt,
  type OpenTimestampsAnchorOptions,
} from './anchor.js';
export {
  DEFAULT_CALENDARS,
  OtsError,
  applyOp,
  calendarSubmit,
  calendarUpgrade,
  collectBitcoin,
  collectPending,
  parseCalendarTimestamp,
  parseOtsProof,
  serializeOtsProof,
  type OtsAttestation,
  type OtsOp,
  type OtsProof,
  type OtsTimestamp,
  type PendingCommitment,
} from './ots.js';
export {
  CERTIFICATE_FORMAT,
  CERTIFICATE_RESIDUALS,
  buildIntegrityCertificate,
  parseIntegrityCertificate,
  verifyIntegrityCertificate,
  type BuildCertificateArgs,
  type CertificateCheck,
  type CertificateVerifyResult,
  type IntegrityCertificate,
  type VerifyCertificateOptions,
} from './certificate.js';
