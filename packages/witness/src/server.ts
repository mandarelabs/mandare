import { readFile } from 'node:fs/promises';

import Fastify, { type FastifyInstance } from 'fastify';

import { sha256Hex, hexToBytes } from '@mandarelabs/spec';
import { EMPTY_TREE_ROOT, verifyConsistency } from '@mandarelabs/verifier';
import type { DoorKey } from '@mandarelabs/ledger';
import {
  WITNESS_PROTOCOL,
  WitnessMessageError,
  aggregateInclusionProof,
  buildAggregate,
  parseSignedHeadSubmission,
  signEpochSummary,
  signPayload,
  verifySignedPayload,
  type Anchor,
  type AnchorReceipt,
  type EpochInclusion,
  type EpochSummary,
  type HeadAckPayload,
  type HeadSigner,
  type SignedHeadAck,
  type WitnessedHeadRecord,
} from '@mandarelabs/witness-protocol';

import { AnchorRunThrottle, anchorRunRefusal } from './anchor-gate.js';
import { WitnessStore, epochSummary, type EpochRow } from './store.js';

/**
 * The reference witness server (SPEC §3.2, single tenant, open): records
 * per-source witnessed head history, refuses any submission that is not a
 * provable append-only extension of what it already witnessed, aggregates
 * all sources into one RFC 6962 tree, and anchors that one root publicly.
 *
 * What it never sees: ledger contents. Every submission is a tree size plus
 * a 32-byte root over salted entry hashes — "we hold proofs, not data" is
 * enforced by the wire format, not by policy.
 *
 * The commercial multi-tenant service (billing, ops, SLAs) is explicitly OUT
 * of this repository; it speaks this same protocol.
 */

export interface WitnessServerOptions {
  dbPath: string;
  /** The witness's own Ed25519 signing key (acks + served heads). */
  key: DoorKey;
  /** Public-anchoring adapter (OpenTimestamps live; mock in CI/demos). */
  anchor: Anchor;
  /** Serve this JWKS file at /.well-known/http-message-signatures-directory. */
  keyDirectoryPath?: string | null;
  /** Serve this IETF Token Status List JSON (S3 bitstring, unchanged) at /v1/status-list. */
  statusListPath?: string | null;
  /**
   * Operator bearer token for POST /v1/anchor/run (W-5). Absent ⇒ runs are
   * loopback-only with the `x-mandare-anchor: run` header (see anchor-gate).
   */
  anchorRunToken?: string | null;
  /** Minimum spacing between on-demand anchor runs (default 60 s). */
  anchorRunMinIntervalMs?: number;
  logger?: boolean;
}

const DEFAULT_ANCHOR_RUN_INTERVAL_MS = 60_000;

export interface WitnessServer {
  app: FastifyInstance;
  store: WitnessStore;
  /** Snapshot all sources' latest heads into an epoch and anchor its root. */
  runAnchor(): Promise<{ epoch: number; status: string }>;
  /**
   * Ask the anchor to upgrade every pending receipt (OpenTimestamps: fetch
   * the calendars' Bitcoin attestations) and store any progress (I-5).
   */
  runUpgrade(): Promise<{ checked: number; confirmed: number[] }>;
  close(): Promise<void>;
}

const HEX64 = /^[0-9a-f]{64}$/;

export async function buildWitnessServer(options: WitnessServerOptions): Promise<WitnessServer> {
  const store = new WitnessStore(options.dbPath);
  const app = Fastify({ logger: options.logger ?? false });
  const key = options.key;

  const ackFor = async (record: WitnessedHeadRecord): Promise<SignedHeadAck> => {
    const payload: HeadAckPayload = {
      protocol: WITNESS_PROTOCOL,
      type: 'head.ack',
      source_id: record.source_id,
      head: record.head,
      witnessed_at: record.witnessed_at,
      witness_key_id: key.keyId,
    };
    return signPayload(payload, key);
  };

  app.post('/v1/heads', async (request, reply) => {
    let signed;
    try {
      signed = parseSignedHeadSubmission(request.body);
    } catch (error) {
      const detail = error instanceof WitnessMessageError ? error.message : 'malformed submission';
      return reply.code(400).send({ error: detail });
    }
    const payload = signed.payload;

    // Sources are self-authenticating: the id IS the key hash, and the
    // submission must verify under that key. Nobody can write into another
    // source's history without its door key.
    if (sha256Hex(hexToBytes(payload.door_public_key)) !== payload.source_id) {
      return reply.code(403).send({ error: 'source_id does not match door_public_key' });
    }
    if (!(await verifySignedPayload(signed, payload.door_public_key))) {
      return reply.code(403).send({ error: 'submission signature invalid' });
    }
    const registeredKey = store.sourcePublicKey(payload.source_id);
    if (registeredKey !== null && registeredKey !== payload.door_public_key) {
      return reply.code(403).send({ error: 'source is registered under a different key' });
    }

    const latest = store.latestHead(payload.source_id);
    const conflict = (code: 'PREV_MISMATCH' | 'NOT_CONSISTENT', detail: string) =>
      // Re-read the head for the body so a concurrently-advanced head is
      // reported accurately (review S6-L8).
      reply.code(409).send({ error: detail, code, latest: store.latestHead(payload.source_id)?.head ?? null });

    if (latest === null) {
      if (payload.prev !== null) {
        return conflict('PREV_MISMATCH', 'no head witnessed yet for this source — submit with prev: null');
      }
      // A first head of size 0 must be the true empty-tree root, or every
      // later growth submission is unprovable and the source wedges at 409
      // forever (review S6-L13). Reject the malformed intake up front.
      if (payload.head.size === 0 && payload.head.root !== EMPTY_TREE_ROOT) {
        return reply.code(400).send({ error: 'size-0 head must carry the empty-tree root' });
      }
    } else {
      if (
        payload.prev === null ||
        payload.prev.size !== latest.head.size ||
        payload.prev.root !== latest.head.root
      ) {
        return conflict('PREV_MISMATCH', 'prev does not name the latest witnessed head — catch up first');
      }
      if (payload.head.size === latest.head.size && payload.head.root === latest.head.root) {
        // Idempotent re-submission (e.g. an ack lost to a timeout): re-ack
        // the recorded head, write nothing.
        return reply.code(200).send(await ackFor(latest));
      }
      if (payload.head.size <= latest.head.size) {
        return conflict(
          'NOT_CONSISTENT',
          `witnessed history is already at size ${latest.head.size} — a ledger never shrinks or forks`
        );
      }
      const consistent = await verifyConsistency({
        size1: latest.head.size,
        root1: latest.head.root,
        size2: payload.head.size,
        root2: payload.head.root,
        proof: payload.consistency_proof,
      });
      if (!consistent) {
        // The submitted tree does NOT extend the witnessed history — this is
        // the witness catching a rewrite at submission time (lock 4).
        return conflict(
          'NOT_CONSISTENT',
          'consistency proof does not extend the witnessed head — history rewrite refused'
        );
      }
    }

    const record: WitnessedHeadRecord = {
      source_id: payload.source_id,
      head: payload.head,
      ts: payload.ts,
      witnessed_at: new Date().toISOString(),
    };
    // Atomic re-check + insert: if a concurrent submission advanced the head
    // while signatures/proofs were being verified, refuse and let the client
    // catch up (its retry submits against the new head).
    const recorded = store.appendHead({
      record,
      publicKey: payload.door_public_key,
      submissionJson: JSON.stringify(signed),
      expectedPrev: latest === null ? null : { size: latest.head.size, root: latest.head.root },
    });
    if (!recorded) {
      return conflict('PREV_MISMATCH', 'witnessed head moved concurrently — catch up and retry');
    }
    return reply.code(200).send(await ackFor(record));
  });

  app.get<{ Params: { sourceId: string } }>('/v1/sources/:sourceId/head', async (request, reply) => {
    const { sourceId } = request.params;
    if (!HEX64.test(sourceId)) return reply.code(400).send({ error: 'bad source id' });
    const record = store.latestHead(sourceId);
    if (record === null) return reply.code(404).send({ error: 'no head witnessed for this source' });
    return reply.send({ record, ack: await ackFor(record) });
  });

  app.get<{ Params: { sourceId: string }; Querystring: { limit?: string } }>(
    '/v1/sources/:sourceId/history',
    async (request, reply) => {
      const { sourceId } = request.params;
      if (!HEX64.test(sourceId)) return reply.code(400).send({ error: 'bad source id' });
      const parsed = Number.parseInt(request.query.limit ?? '100', 10);
      const limit = Number.isInteger(parsed) ? Math.min(Math.max(parsed, 1), 1000) : 100;
      return reply.send({ records: store.history(sourceId, limit) });
    }
  );

  const runAnchor = async (): Promise<{ epoch: number; status: string }> => {
    const leaves = store.latestHeads();
    if (leaves.length === 0) {
      throw new Error('nothing to anchor — no witnessed sources yet');
    }
    const snapshot = await buildAggregate(leaves);
    const epoch = store.createEpoch({
      createdAt: new Date().toISOString(),
      aggregate: snapshot.head,
      leaves: snapshot.records,
    });
    try {
      const receipt = await options.anchor.anchor(snapshot.head.root);
      store.setEpochAnchor(epoch, {
        kind: receipt.kind,
        status: receipt.status,
        otsBase64: receipt.proof,
      });
      return { epoch, status: receipt.status };
    } catch (error) {
      // The epoch commitment stands (append-only); the anchor receipt just
      // isn't there yet. Honest state, retryable by the next run.
      app.log?.error?.(error);
      return { epoch, status: 'none' };
    }
  };

  // Without this, OpenTimestamps receipts stay `pending` forever and never
  // reach Bitcoin (audit 2026-09, I-5). A failed upgrade leaves the receipt
  // as it was — honest, retryable on the next run.
  const runUpgrade = async (): Promise<{ checked: number; confirmed: number[] }> => {
    const pending = store.pendingEpochs().filter(
      (row) => row.anchor_kind === options.anchor.kind && row.ots_base64 !== null
    );
    const confirmed: number[] = [];
    for (const row of pending) {
      const receipt: AnchorReceipt = {
        kind: options.anchor.kind,
        digest: row.aggregate.root,
        status: 'pending',
        created_at: row.created_at,
        proof: row.ots_base64 as string,
        detail: null,
      };
      try {
        const next = await options.anchor.upgrade(receipt);
        if (next.proof === receipt.proof && next.status === receipt.status) continue;
        store.setEpochAnchor(row.epoch, { kind: next.kind, status: next.status, otsBase64: next.proof });
        if (next.status === 'confirmed') confirmed.push(row.epoch);
      } catch (error) {
        app.log?.error?.(error);
      }
    }
    return { checked: pending.length, confirmed };
  };

  const anchorRunToken = options.anchorRunToken ?? null;
  const throttle = new AnchorRunThrottle(options.anchorRunMinIntervalMs ?? DEFAULT_ANCHOR_RUN_INTERVAL_MS);
  app.post('/v1/anchor/run', async (request, reply) => {
    const refusal = anchorRunRefusal(request, anchorRunToken);
    if (refusal !== null) {
      return reply.code(refusal.status).send({ error: refusal.error });
    }
    const waitSeconds = throttle.take();
    if (waitSeconds > 0) {
      return reply
        .code(429)
        .header('retry-after', String(waitSeconds))
        .send({ error: 'an anchor run just happened — retry later' });
    }
    try {
      const result = await runAnchor();
      return reply.code(200).send(result);
    } catch (error) {
      return reply.code(409).send({ error: error instanceof Error ? error.message : 'anchor failed' });
    }
  });

  app.get('/v1/epochs/latest', async (_request, reply) => {
    const row = store.latestEpoch();
    if (row === null) return reply.code(404).send({ error: 'no epoch yet' });
    return reply.send(await signEpochSummary(epochSummary(row), key));
  });

  app.get<{ Params: { epoch: string; sourceId: string } }>(
    '/v1/epochs/:epoch/inclusion/:sourceId',
    async (request, reply) => {
      const epochNumber = Number.parseInt(request.params.epoch, 10);
      const { sourceId } = request.params;
      if (!Number.isInteger(epochNumber) || epochNumber < 1 || !HEX64.test(sourceId)) {
        return reply.code(400).send({ error: 'bad epoch or source id' });
      }
      const row = store.getEpoch(epochNumber);
      if (row === null) return reply.code(404).send({ error: 'unknown epoch' });
      const inclusion = await epochInclusionFor(row, sourceId, key);
      if (inclusion === null) {
        return reply.code(404).send({ error: 'source is not a leaf of this epoch' });
      }
      return reply.send(inclusion);
    }
  );

  app.get('/v1/witness', async (_request, reply) => {
    // Convenience only — trust in the witness key must arrive OUT-OF-BAND
    // (the same lesson as the door key: a channel cannot vouch for itself).
    return reply.send({
      protocol: WITNESS_PROTOCOL,
      witness_key_id: key.keyId,
      public_key: key.publicKeyHex,
    });
  });

  app.get('/healthz', async (_request, reply) => {
    const stats = store.stats();
    return reply.send({
      status: 'ok',
      witness_key_id: key.keyId,
      sources: stats.sources,
      heads: stats.heads,
      epochs: stats.epochs,
    });
  });

  // Hosting debt from S1/S3 (TASKS.md S6 handoff): the key directory and the
  // IETF status list are static, owner-produced JSON — the witness serves
  // them read-only with the right content types. Files are read per request
  // so a republish is just a file replace.
  if (options.keyDirectoryPath != null) {
    const path = options.keyDirectoryPath;
    app.get('/.well-known/http-message-signatures-directory', async (_request, reply) => {
      const body = await readFile(path, 'utf8');
      return reply
        .header('content-type', 'application/http-message-signatures-directory+json')
        .send(body);
    });
  }
  if (options.statusListPath != null) {
    const path = options.statusListPath;
    app.get('/v1/status-list', async (_request, reply) => {
      const body = await readFile(path, 'utf8');
      return reply.header('content-type', 'application/json').send(body);
    });
  }

  return {
    app,
    store,
    runAnchor,
    runUpgrade,
    close: async () => {
      await app.close();
      store.close();
    },
  };
}

/**
 * Build the EpochInclusion bundle for one source of a stored epoch. The
 * epoch summary is witness-signed (when `signer` is given) so a relying
 * party can verify the aggregate root is genuinely the witness's, not a
 * fabrication (review S6-H2).
 */
export async function epochInclusionFor(
  row: EpochRow,
  sourceId: string,
  signer?: HeadSigner
): Promise<EpochInclusion | null> {
  const snapshot = await buildAggregate(row.leaves);
  if (snapshot.head.root !== row.aggregate.root || snapshot.head.size !== row.aggregate.size) {
    throw new Error(`epoch ${row.epoch} leaves do not rebuild its committed aggregate root`);
  }
  const index = snapshot.records.findIndex((leaf) => leaf.source_id === sourceId);
  if (index === -1) return null;
  const proof = await aggregateInclusionProof(snapshot, index);
  const epoch: EpochSummary =
    signer === undefined ? epochSummary(row) : await signEpochSummary(epochSummary(row), signer);
  return {
    epoch,
    leaf: snapshot.records[index] as WitnessedHeadRecord,
    leaf_index: index,
    inclusion_proof: proof,
  };
}
