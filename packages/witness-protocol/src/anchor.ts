import {
  bytesToBase64Url,
  base64UrlToBytes,
  canonicalJson,
  hexToBytes,
  sha256HexAsync,
} from '@mandarelabs/spec';

import {
  DEFAULT_CALENDARS,
  OtsError,
  calendarSubmit,
  calendarUpgrade,
  collectBitcoin,
  collectPending,
  parseOtsProof,
  serializeOtsProof,
  type CalendarClientOptions,
  type OtsTimestamp,
} from './ots.js';

/**
 * Public anchoring behind one interface (BUILD-DECISIONS Q6): the witness
 * anchors its aggregate root daily; HOW is an adapter detail. OpenTimestamps
 * is the default (free, keyless, neutral); a Base/EVM adapter is a declared
 * future option, deliberately stubbed, not built.
 */

export interface AnchorReceipt {
  /** Adapter that produced this receipt ('opentimestamps' | 'mock' | ...). */
  kind: string;
  /** The anchored 32-byte digest, lowercase hex. */
  digest: string;
  status: 'pending' | 'confirmed';
  created_at: string;
  /** Portable proof artifact (.ots file bytes for OTS), base64url. */
  proof: string;
  /** Adapter detail once confirmed (e.g. 'bitcoin block 900001'). */
  detail: string | null;
}

export interface Anchor {
  readonly kind: string;
  /** Commit a 32-byte digest (hex) to the public anchor. */
  anchor(digestHex: string): Promise<AnchorReceipt>;
  /** Attempt to upgrade a pending receipt to confirmed; returns the input if unchanged. */
  upgrade(receipt: AnchorReceipt): Promise<AnchorReceipt>;
}

function requireDigestHex(digestHex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(digestHex)) {
    throw new Error('anchor digest must be 64 lowercase hex chars (sha256)');
  }
  return hexToBytes(digestHex);
}

export interface OpenTimestampsAnchorOptions extends CalendarClientOptions {
  calendars?: string[];
  /** How many calendars must accept the digest for anchor() to succeed. */
  minSuccesses?: number;
}

/**
 * The real adapter: submits the digest to the public calendar pool and emits
 * a standard detached `.ots` proof (pending until the calendars aggregate
 * into Bitcoin — hours; fine for a daily cadence, Q6). `upgrade()` polls the
 * calendars and merges Bitcoin attestations into the receipt.
 *
 * Network-touching by nature — CI and the demos use MockAnchor; this adapter
 * is exercised by the local witness live-smoke only.
 */
export class OpenTimestampsAnchor implements Anchor {
  readonly kind = 'opentimestamps';
  private readonly calendars: string[];
  private readonly minSuccesses: number;
  private readonly clientOptions: CalendarClientOptions;

  constructor(options: OpenTimestampsAnchorOptions = {}) {
    this.calendars = options.calendars ?? [...DEFAULT_CALENDARS];
    this.minSuccesses = options.minSuccesses ?? 1;
    this.clientOptions = {
      ...(options.fetchImpl === undefined ? {} : { fetchImpl: options.fetchImpl }),
      ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
    };
    if (this.calendars.length === 0 || this.minSuccesses < 1) {
      throw new Error('OpenTimestampsAnchor needs at least one calendar');
    }
  }

  async anchor(digestHex: string): Promise<AnchorReceipt> {
    const digest = requireDigestHex(digestHex);
    const branches: OtsTimestamp[] = [];
    const failures: string[] = [];
    for (const calendar of this.calendars) {
      try {
        branches.push(await calendarSubmit(calendar, digest, this.clientOptions));
      } catch (error) {
        failures.push(error instanceof Error ? error.message : String(error));
      }
    }
    if (branches.length < this.minSuccesses) {
      throw new OtsError(
        `only ${branches.length}/${this.calendars.length} calendars accepted the digest ` +
          `(need ${this.minSuccesses}): ${failures.join(' · ')}`
      );
    }
    const merged: OtsTimestamp = {
      msg: digest,
      attestations: branches.flatMap((branch) => branch.attestations),
      ops: branches.flatMap((branch) => branch.ops),
    };
    return {
      kind: this.kind,
      digest: digestHex,
      status: 'pending',
      created_at: new Date().toISOString(),
      proof: bytesToBase64Url(serializeOtsProof({ digest, timestamp: merged })),
      detail: null,
    };
  }

  async upgrade(receipt: AnchorReceipt): Promise<AnchorReceipt> {
    if (receipt.kind !== this.kind || receipt.status === 'confirmed') return receipt;
    const proof = await parseOtsProof(base64UrlToBytes(receipt.proof));
    let upgraded = false;
    const failures: string[] = [];
    // Each calendar independently: one that is down or answers garbage must
    // not block another that already has the Bitcoin proof.
    for (const pending of collectPending(proof.timestamp)) {
      let extension: OtsTimestamp | null;
      try {
        extension = await calendarUpgrade(pending, this.clientOptions);
      } catch (error) {
        failures.push(`${pending.uri}: ${error instanceof Error ? error.message : String(error)}`);
        continue;
      }
      if (extension !== null) {
        pending.stamp.attestations = pending.stamp.attestations.filter(
          (attestation) => attestation.kind !== 'pending' || attestation.uri !== pending.uri
        );
        pending.stamp.attestations.push(...extension.attestations);
        pending.stamp.ops.push(...extension.ops);
        upgraded = true;
      }
    }
    if (!upgraded) {
      // Every calendar still 404 is honest `pending`; a failure is not —
      // report it instead of letting it pass for "not yet".
      if (failures.length > 0) throw new OtsError(`no calendar upgraded the receipt: ${failures.join(' · ')}`);
      return receipt;
    }
    const bitcoin = collectBitcoin(proof.timestamp);
    return {
      ...receipt,
      status: bitcoin.length > 0 ? 'confirmed' : 'pending',
      proof: bytesToBase64Url(serializeOtsProof(proof)),
      detail:
        bitcoin.length > 0
          ? `bitcoin block ${Math.min(...bitcoin.map((attestation) => attestation.height))}`
          : receipt.detail,
    };
  }
}

/**
 * Deterministic in-process anchor for CI, tests, and the demos: "anchoring
 * happened" without a network. The proof is a self-describing digest
 * commitment — checkable, obviously NOT a public anchor, and it says so.
 */
export class MockAnchor implements Anchor {
  readonly kind = 'mock';

  async anchor(digestHex: string): Promise<AnchorReceipt> {
    requireDigestHex(digestHex);
    const created = new Date().toISOString();
    const commitment = await sha256HexAsync(
      canonicalJson({ mock_anchor: 1, digest: digestHex, created_at: created })
    );
    return {
      kind: this.kind,
      digest: digestHex,
      status: 'confirmed',
      created_at: created,
      proof: bytesToBase64Url(
        new TextEncoder().encode(
          canonicalJson({ mock_anchor: 1, digest: digestHex, created_at: created, commitment })
        )
      ),
      detail: 'mock anchor — NOT publicly anchored (CI/demo adapter)',
    };
  }

  upgrade(receipt: AnchorReceipt): Promise<AnchorReceipt> {
    return Promise.resolve(receipt);
  }
}

/**
 * Declared future adapter (Q6: "Base/EVM anchoring as later premium option").
 * Present so the seam is visible and typed; deliberately not implemented.
 */
export class BaseAnchor implements Anchor {
  readonly kind = 'base';

  anchor(): Promise<AnchorReceipt> {
    return Promise.reject(
      new Error('Base/EVM anchoring is a declared future adapter (BUILD-DECISIONS Q6) — not built')
    );
  }

  upgrade(): Promise<AnchorReceipt> {
    return Promise.reject(
      new Error('Base/EVM anchoring is a declared future adapter (BUILD-DECISIONS Q6) — not built')
    );
  }
}
