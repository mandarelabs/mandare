/**
 * Approval-trail action types (S4, SPEC §5 approvals). These are ledger
 * ENTRY types, not projection inputs — the spend and revocation projections
 * both ignore them (no counter effect, no status effect). They exist so
 * `mandare verify` can prove the human decisions inside a task's sequence:
 * requested → granted/denied/expired, linked via outcome_ref.
 */

/** A call exceeded a mandate approval threshold and was HELD; push sent. */
export const APPROVAL_REQUESTED = 'approval.requested';
/** The human approved — the held call proceeds (entry BEFORE the resume, R3). */
export const APPROVAL_GRANTED = 'approval.granted';
/** The human denied — the held call is refused. */
export const APPROVAL_DENIED = 'approval.denied';
/** No decision within the window — fail-closed refusal (R1). */
export const APPROVAL_EXPIRED = 'approval.expired';

export const APPROVAL_ENTRY_TYPES = [
  APPROVAL_REQUESTED,
  APPROVAL_GRANTED,
  APPROVAL_DENIED,
  APPROVAL_EXPIRED,
] as const;
