import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { appendFileSync } from 'node:fs';

/**
 * CIBA-style async human approval (SPEC §5 approvals, Q10/Q19). When a call
 * exceeds a mandate approval threshold the gateway HOLDS it, pushes a
 * notification with Approve/Deny action buttons, and resumes or refuses when
 * the decision lands — the decision itself becomes a ledger entry either way.
 *
 * The decision tokens are single-use capabilities: 256-bit random, one per
 * button, bound to one approval id, stored only as sha256 hashes, compared in
 * constant time, dead after first use or timeout (fail-closed: no decision =
 * deny). A captured push can therefore authorize exactly the one call it was
 * sent for, once.
 */

export interface ApprovalRequestNotification {
  approvalId: string;
  title: string;
  message: string;
  /** POST these to decide; body is the JSON below (ntfy http-action shape). */
  approveUrl: string;
  denyUrl: string;
  approveBody: string;
  denyBody: string;
  expiresAt: string;
}

/** Pluggable push channel (Q10/Q19): ntfy default, Telegram optional later. */
export interface Notifier {
  readonly name: string;
  send(notification: ApprovalRequestNotification): Promise<void>;
}

export type ApprovalOutcome = 'approved' | 'denied' | 'timeout';

export interface PendingApprovalInput {
  requestHash: string;
  estimateMicros: number;
  currency: string;
  model: string;
  target: string;
  actor: string;
  mandateId: string;
  thresholdMicros: number;
}

interface PendingApproval {
  id: string;
  input: PendingApprovalInput;
  approveTokenHash: Buffer;
  denyTokenHash: Buffer;
  createdAtMs: number;
  timer: NodeJS.Timeout;
  resolve: (outcome: ApprovalOutcome) => void;
  outcome: Promise<ApprovalOutcome>;
  decided: boolean;
}

export interface CreatedApproval {
  id: string;
  approveToken: string;
  denyToken: string;
  expiresAtIso: string;
  /** Resolves exactly once: approved, denied, or timeout (fail-closed). */
  outcome: Promise<ApprovalOutcome>;
}

export type DecisionRefusal = 'UNKNOWN_APPROVAL' | 'BAD_TOKEN' | 'ALREADY_DECIDED';

export type DecisionResult =
  | { ok: true; outcome: 'approved' | 'denied' }
  | { ok: false; refusal: DecisionRefusal };

const TOKEN_BYTES = 32;

function tokenHash(token: string): Buffer {
  return createHash('sha256').update(token, 'utf8').digest();
}

export class ApprovalService {
  private readonly pending = new Map<string, PendingApproval>();
  private readonly timeoutMs: number;

  constructor(timeoutMs: number) {
    this.timeoutMs = timeoutMs;
  }

  create(input: PendingApprovalInput): CreatedApproval {
    const id = `apr_${randomBytes(9).toString('base64url')}`;
    const approveToken = randomBytes(TOKEN_BYTES).toString('base64url');
    const denyToken = randomBytes(TOKEN_BYTES).toString('base64url');
    let resolve!: (outcome: ApprovalOutcome) => void;
    const outcome = new Promise<ApprovalOutcome>((res) => {
      resolve = res;
    });
    const createdAtMs = Date.now();
    // No decision within the window = deny (R1): the held call is refused
    // and the tokens die with the pending record.
    const timer = setTimeout(() => this.finish(id, 'timeout'), this.timeoutMs);
    timer.unref?.();
    this.pending.set(id, {
      id,
      input,
      approveTokenHash: tokenHash(approveToken),
      denyTokenHash: tokenHash(denyToken),
      createdAtMs,
      timer,
      resolve,
      outcome,
      decided: false,
    });
    return {
      id,
      approveToken,
      denyToken,
      expiresAtIso: new Date(createdAtMs + this.timeoutMs).toISOString(),
      outcome,
    };
  }

  /**
   * Apply a human decision. The token IS the authorization: whichever hash it
   * matches (approve/deny) is the decision taken; anything else is refused
   * without state change. Replay of a used token: ALREADY_DECIDED.
   */
  decide(approvalId: string, token: string): DecisionResult {
    const entry = this.pending.get(approvalId);
    if (entry === undefined) {
      return { ok: false, refusal: 'UNKNOWN_APPROVAL' };
    }
    if (typeof token !== 'string' || token.length === 0) {
      return { ok: false, refusal: 'BAD_TOKEN' };
    }
    const presented = tokenHash(token);
    const isApprove = timingSafeEqual(presented, entry.approveTokenHash);
    const isDeny = timingSafeEqual(presented, entry.denyTokenHash);
    if (!isApprove && !isDeny) {
      return { ok: false, refusal: 'BAD_TOKEN' };
    }
    if (entry.decided) {
      return { ok: false, refusal: 'ALREADY_DECIDED' };
    }
    const outcome = isApprove ? 'approved' : 'denied';
    this.finish(approvalId, outcome);
    return { ok: true, outcome };
  }

  /** Number of undecided approvals (test/ops introspection). */
  pendingCount(): number {
    let count = 0;
    for (const entry of this.pending.values()) {
      if (!entry.decided) count += 1;
    }
    return count;
  }

  private finish(approvalId: string, outcome: ApprovalOutcome): void {
    const entry = this.pending.get(approvalId);
    if (entry === undefined || entry.decided) {
      return;
    }
    entry.decided = true;
    clearTimeout(entry.timer);
    entry.resolve(outcome);
    // Keep the decided record briefly so a replayed token gets an honest
    // ALREADY_DECIDED (not UNKNOWN); then drop it.
    const RETAIN_DECIDED_MS = 60_000;
    const cleanup = setTimeout(() => this.pending.delete(approvalId), RETAIN_DECIDED_MS);
    cleanup.unref?.();
  }
}

// --- notifier adapters -------------------------------------------------------

/**
 * ntfy (Q10/Q19 default): a single self-hostable binary; action buttons POST
 * the decision straight to the gateway's /approvals endpoint. Zero third-party
 * dependency when self-hosted.
 */
export class NtfyNotifier implements Notifier {
  readonly name = 'ntfy';
  private readonly serverUrl: string;
  private readonly topic: string;
  private readonly fetchImpl: typeof fetch;

  constructor(serverUrl: string, topic: string, fetchImpl: typeof fetch = fetch) {
    this.serverUrl = serverUrl.replace(/\/+$/, '');
    this.topic = topic;
    this.fetchImpl = fetchImpl;
  }

  async send(notification: ApprovalRequestNotification): Promise<void> {
    const response = await this.fetchImpl(this.serverUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        topic: this.topic,
        title: notification.title,
        message: notification.message,
        priority: 4,
        actions: [
          {
            action: 'http',
            label: 'Approve',
            url: notification.approveUrl,
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: notification.approveBody,
            clear: true,
          },
          {
            action: 'http',
            label: 'Deny',
            url: notification.denyUrl,
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: notification.denyBody,
            clear: true,
          },
        ],
      }),
    });
    if (!response.ok) {
      throw new Error(`ntfy publish failed: ${response.status}`);
    }
  }
}

/**
 * File notifier — the CI/demo channel: appends each notification as one JSON
 * line; the "human" (demo script) watches the file and POSTs the decision,
 * exactly the shape the ntfy action button would send.
 */
export class FileNotifier implements Notifier {
  readonly name = 'file';
  private readonly path: string;

  constructor(path: string) {
    this.path = path;
  }

  send(notification: ApprovalRequestNotification): Promise<void> {
    appendFileSync(this.path, `${JSON.stringify(notification)}\n`);
    return Promise.resolve();
  }
}
