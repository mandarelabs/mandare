import { StatusList, createHeaderAndPayload } from '@sd-jwt/jwt-status-list';

/**
 * Revocation status as an IETF Token Status List / W3C Bitstring Status List
 * (BUILD-DECISIONS Q4, @sd-jwt/jwt-status-list). This is the ONE revocation
 * vocabulary: S3 uses it for agent/door kill, S4 for mandate revocation, and
 * S6 publishes the very same bytes for external verifiers — the founder
 * ruling's "one revocation vocabulary, not two."
 *
 * The AUTHORITATIVE revocation record is the ledger `agent.revoke` entry and
 * its subject-keyed projection (packages/ledger); this module renders that
 * state into the standard bitstring artifact. A set bit (status 1) means
 * revoked. A credential points at its slot via `revocation_ref`
 * (`statuslist:<listId>#<index>`), already carried in the mandate schema.
 */

export const AGENT_STATUS_LIST_ID = 'agents';
export const STATUS_VALID = 0;
export const STATUS_REVOKED = 1;
/** One bit per status (revoked / not) — the revocation profile of the spec. */
const STATUS_BITS = 1;

export interface RevocationSlot {
  index: number;
  revoked: boolean;
}

/** The standard Token Status List payload (unsigned; S6 wraps it in a JWT). */
export interface StatusListPayload {
  iss: string;
  sub: string;
  iat: number;
  status_list: { bits: number; lst: string };
}

export interface BuildStatusListInput {
  listId: string;
  slots: readonly RevocationSlot[];
  issuer: string;
  /** Issued-at, epoch seconds (passed in so this stays a pure function). */
  iat: number;
  /** Absolute URI a verifier would resolve the list at; S6 hosts it. */
  subjectUri?: string;
}

/**
 * Build the standard bitstring payload from the current revocation slots.
 * The list is sized to the highest assigned index so slots are stable across
 * renders (a credential keeps its index for the life of the list).
 */
export function buildStatusListPayload(input: BuildStatusListInput): StatusListPayload {
  const size = input.slots.reduce((max, slot) => Math.max(max, slot.index + 1), 0);
  const statuses = new Array<number>(size).fill(STATUS_VALID);
  for (const slot of input.slots) {
    if (slot.index < 0 || !Number.isInteger(slot.index)) {
      throw new Error(`status list index must be a non-negative integer, got ${slot.index}`);
    }
    statuses[slot.index] = slot.revoked ? STATUS_REVOKED : STATUS_VALID;
  }
  const list = new StatusList(statuses, STATUS_BITS);
  const subject = input.subjectUri ?? `urn:mandare:statuslist:${input.listId}`;
  const { payload } = createHeaderAndPayload(
    list,
    { iss: input.issuer, sub: subject, iat: input.iat },
    { alg: 'EdDSA', typ: 'statuslist+jwt' }
  );
  // createHeaderAndPayload returns a loose JwtPayload; pin the standard fields
  // we rely on into our typed shape (this IS the IETF Token Status List form).
  const statusList = (payload as { status_list: { bits: number; lst: string } }).status_list;
  return {
    iss: input.issuer,
    sub: subject,
    iat: input.iat,
    status_list: { bits: statusList.bits, lst: statusList.lst },
  };
}

/** `statuslist:<listId>#<index>` → parts, or null if malformed. */
export function parseRevocationRef(ref: string): { listId: string; index: number } | null {
  const match = /^statuslist:([^#]+)#(\d+)$/.exec(ref);
  if (match === null) {
    return null;
  }
  const index = Number.parseInt(match[2] as string, 10);
  if (!Number.isSafeInteger(index)) {
    return null;
  }
  return { listId: match[1] as string, index };
}

export function formatRevocationRef(listId: string, index: number): string {
  return `statuslist:${listId}#${index}`;
}
