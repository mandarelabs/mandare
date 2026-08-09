import { computeTreeHead, consistencyProof, type TreeHead } from '@mandarelabs/verifier';

import {
  WITNESS_PROTOCOL,
  parseSignedHeadAck,
  parseWitnessedHeadRecord,
  type HeadAckPayload,
  type HeadSubmissionPayload,
  type SignedHeadAck,
  type WitnessedHeadRecord,
} from './messages.js';
import { signPayload, verifySignedPayload, type HeadSigner } from './signing.js';

/**
 * The door-side witness client (integrity lock 4): streams the ledger's
 * chain-head fingerprint to the witness, catches up after offline periods,
 * and obtains verified acks for witness-ack gating (lock 5).
 *
 * Offline behavior, stated honestly: there is no literal queue of unsent
 * heads. Because every tree head commits to EVERY entry before it, the first
 * successful sync after a gap witnesses the entire backlog at once — the
 * consistency proof against the last witnessed head proves the growth was
 * append-only. What an offline window costs is timeline granularity (no
 * witnessed_at timestamps DURING the gap), never coverage. High-value
 * actions don't tolerate even that window — they use `ackHead()` and fail
 * closed when no verified ack arrives (lock 5).
 */

export type WitnessSyncErrorCode =
  | 'UNREACHABLE'
  | 'REFUSED'
  | 'BAD_ACK'
  | 'HISTORY_CONFLICT';

export class WitnessSyncError extends Error {
  readonly code: WitnessSyncErrorCode;

  constructor(code: WitnessSyncErrorCode, message: string) {
    super(message);
    this.name = 'WitnessSyncError';
    this.code = code;
  }
}

export interface WitnessClientOptions {
  /** Witness base URL, e.g. http://127.0.0.1:9411. */
  url: string;
  /** The door key — submissions are signed, sources are self-authenticating. */
  signer: HeadSigner;
  /** Reads the ledger's entry hashes in seq order (injected: no AGPL import). */
  readEntryHashes: () => Promise<string[]>;
  /**
   * The witness's raw Ed25519 public key (hex), obtained OUT-OF-BAND. Every
   * ack and served head is verified against it; without it nothing the
   * witness says could be trusted, so it is required, not optional.
   */
  witnessPublicKeyHex: string;
  fetchImpl?: typeof fetch;
  requestTimeoutMs?: number;
}

export interface SyncResult {
  head: TreeHead;
  ack: HeadAckPayload;
}

/**
 * Fetch a source's latest witnessed head and VERIFY the witness signature on
 * it. Standalone (no door key needed) — verifiers, `mandare verify
 * --witness`, and `mandare certify` use this; the streaming client wraps it.
 * Returns the record plus the witness's signed statement of it (certificates
 * embed the latter verbatim), or null when the witness has never seen the
 * source.
 */
export async function fetchVerifiedWitnessedHead(args: {
  url: string;
  sourceId: string;
  witnessPublicKeyHex: string;
  fetchImpl?: typeof fetch;
  requestTimeoutMs?: number;
}): Promise<{ record: WitnessedHeadRecord; ack: SignedHeadAck } | null> {
  const fetchImpl = args.fetchImpl ?? fetch;
  let response: Response;
  try {
    response = await fetchImpl(`${args.url}/v1/sources/${args.sourceId}/head`, {
      signal: AbortSignal.timeout(args.requestTimeoutMs ?? 3000),
    });
  } catch (error) {
    throw new WitnessSyncError(
      'UNREACHABLE',
      `witness unreachable: ${error instanceof Error ? error.message : String(error)}`
    );
  }
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new WitnessSyncError('UNREACHABLE', `witness head lookup failed: ${response.status}`);
  }
  let body: { record?: unknown; ack?: unknown };
  try {
    body = (await response.json()) as { record?: unknown; ack?: unknown };
  } catch {
    throw new WitnessSyncError('BAD_ACK', 'witness returned a non-JSON body');
  }
  const record = parseWitnessedHeadRecord(body.record);
  const ack = parseSignedHeadAck(body.ack);
  if (!(await verifySignedPayload(ack, args.witnessPublicKeyHex))) {
    throw new WitnessSyncError('BAD_ACK', 'served head has an invalid witness signature');
  }
  if (
    ack.payload.source_id !== args.sourceId ||
    record.source_id !== args.sourceId ||
    ack.payload.head.size !== record.head.size ||
    ack.payload.head.root !== record.head.root
  ) {
    throw new WitnessSyncError('BAD_ACK', 'served head does not match its witness signature');
  }
  return { record, ack };
}

export class WitnessClient {
  readonly sourceId: string;
  private readonly options: WitnessClientOptions;
  private readonly fetchImpl: typeof fetch;
  private lastWitnessed: TreeHead | null = null;
  /** All syncs serialize through this chain — one submission in flight at a time. */
  private syncChain: Promise<unknown> = Promise.resolve();
  private timer: ReturnType<typeof setInterval> | null = null;
  private dirty = true;
  private syncFailureListener: ((error: unknown) => void) | null = null;

  constructor(options: WitnessClientOptions) {
    this.options = options;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.sourceId = options.signer.keyId;
  }

  /** Latest head the witness has verifiably recorded for this source (null = none). */
  async fetchWitnessedHead(): Promise<WitnessedHeadRecord | null> {
    const verified = await fetchVerifiedWitnessedHead({
      url: this.options.url,
      sourceId: this.sourceId,
      witnessPublicKeyHex: this.options.witnessPublicKeyHex,
      fetchImpl: this.fetchImpl,
      requestTimeoutMs: this.options.requestTimeoutMs ?? 3000,
    });
    return verified?.record ?? null;
  }

  /**
   * Read the ledger, submit the current head, verify the ack. Used by the
   * background stream, offline catch-up, and (forced) witness-ack gating —
   * one code path, so gating can never take a less-verified shortcut.
   */
  sync(): Promise<SyncResult> {
    const run = this.syncChain.then(() => this.syncOnce());
    // The chain must survive failures — keep it settled, propagate the error
    // only to this call's awaiter.
    this.syncChain = run.catch(() => undefined);
    return run;
  }

  /** Force an immediate sync and return the verified ack (lock 5 gating). */
  ackHead(): Promise<SyncResult> {
    return this.sync();
  }

  /** Mark the ledger as grown; the background loop syncs on its next tick. */
  notifyAppend(): void {
    this.dirty = true;
  }

  /**
   * Background streaming (per-second by default): sync whenever the ledger
   * grew, retry quietly while the witness is unreachable (offline mode is a
   * documented degradation, not an error state — SPEC §6 honest residuals).
   */
  start(intervalMs = 1000, onSyncFailure?: (error: unknown) => void): void {
    if (this.timer !== null) return;
    this.syncFailureListener = onSyncFailure ?? null;
    this.timer = setInterval(() => {
      if (!this.dirty) return;
      this.dirty = false;
      this.sync().catch((error: unknown) => {
        this.dirty = true; // still unsynced — retry next tick
        this.syncFailureListener?.(error);
      });
    }, intervalMs);
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  private async syncOnce(): Promise<SyncResult> {
    const hashes = await this.options.readEntryHashes();
    const head = await computeTreeHead(hashes);
    let prev = this.lastWitnessed;
    if (prev === null) {
      prev = (await this.fetchWitnessedHead())?.head ?? null;
    }
    let result = await this.submit(hashes, head, prev);
    if (result === 'stale-prev') {
      // Another writer (or a witness restart) moved the witnessed head under
      // us: re-fetch the authoritative latest and retry exactly once.
      this.lastWitnessed = null;
      const latest = (await this.fetchWitnessedHead())?.head ?? null;
      result = await this.submit(hashes, head, latest);
      if (result === 'stale-prev') {
        throw new WitnessSyncError('REFUSED', 'witness rejected the submission twice (moving head)');
      }
    }
    this.lastWitnessed = head;
    return { head, ack: result.ack };
  }

  private async submit(
    hashes: string[],
    head: TreeHead,
    prev: TreeHead | null
  ): Promise<{ ack: HeadAckPayload } | 'stale-prev'> {
    if (prev !== null) {
      if (prev.size > head.size) {
        throw new WitnessSyncError(
          'HISTORY_CONFLICT',
          `witness has already recorded size ${prev.size} but the local ledger has only ` +
            `${head.size} entries — the local chain LOST entries (truncation/rollback); refusing to submit`
        );
      }
      if (prev.size === head.size && prev.root !== head.root) {
        throw new WitnessSyncError(
          'HISTORY_CONFLICT',
          'witnessed head and local head have the same size but different roots — history rewritten'
        );
      }
    }
    const proof =
      prev === null || prev.size === 0 || prev.size === head.size
        ? []
        : await consistencyProof(hashes, prev.size);
    const payload: HeadSubmissionPayload = {
      protocol: WITNESS_PROTOCOL,
      type: 'head.submit',
      source_id: this.sourceId,
      door_public_key: this.options.signer.publicKeyHex,
      head,
      prev,
      consistency_proof: proof,
      ts: new Date().toISOString(),
    };
    const signed = await signPayload(payload, this.options.signer);
    const response = await this.request('/v1/heads', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(signed),
    });
    if (response.status === 409) {
      // The witness distinguishes a movable PREV_MISMATCH (catch up and
      // retry) from a NOT_CONSISTENT fork (the local chain contradicts the
      // witnessed history — never retryable, always fail closed loudly).
      const body = (await this.readJson(response)) as { code?: unknown };
      if (body?.code === 'NOT_CONSISTENT') {
        throw new WitnessSyncError(
          'HISTORY_CONFLICT',
          'local chain is not an append-only extension of the witnessed head — history rewritten'
        );
      }
      return 'stale-prev';
    }
    if (!response.ok) {
      throw new WitnessSyncError('REFUSED', `witness refused the head submission: ${response.status}`);
    }
    const ack = parseSignedHeadAck(await this.readJson(response));
    if (!(await verifySignedPayload(ack, this.options.witnessPublicKeyHex))) {
      throw new WitnessSyncError('BAD_ACK', 'witness ack signature is invalid — refusing to trust it');
    }
    if (
      ack.payload.source_id !== this.sourceId ||
      ack.payload.head.size !== head.size ||
      ack.payload.head.root !== head.root
    ) {
      // A REPLAYED ack (valid signature, older head) dies here: the ack must
      // name exactly the head this submission carried.
      throw new WitnessSyncError('BAD_ACK', 'witness ack does not match the submitted head');
    }
    return { ack: ack.payload };
  }

  private async request(path: string, init?: RequestInit): Promise<Response> {
    try {
      return await this.fetchImpl(`${this.options.url}${path}`, {
        ...init,
        signal: AbortSignal.timeout(this.options.requestTimeoutMs ?? 3000),
      });
    } catch (error) {
      throw new WitnessSyncError(
        'UNREACHABLE',
        `witness unreachable: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /** Parse a witness body as JSON; a non-JSON 200 is a broken witness, not a valid ack. */
  private async readJson(response: Response): Promise<unknown> {
    try {
      return await response.json();
    } catch {
      throw new WitnessSyncError('BAD_ACK', 'witness returned a non-JSON body');
    }
  }
}
