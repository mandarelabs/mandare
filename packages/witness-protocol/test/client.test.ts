import { sign as cryptoSign } from 'node:crypto';

import { describe, expect, test } from 'vitest';

import { verifyConsistency } from '@mandarelabs/verifier';
import {
  bytesToBase64Url,
  computeEntryHash,
  type LedgerEntryPreimage,
  type LedgerEntryV1,
} from '@mandarelabs/spec';

import { WitnessClient, WitnessSyncError } from '../src/client.js';
import {
  WITNESS_PROTOCOL,
  parseSignedHeadSubmission,
  type SignedHeadAck,
  type WitnessedHeadRecord,
} from '../src/messages.js';
import { signPayload, verifySignedPayload } from '../src/signing.js';
import { buildChain, entryHashesOf, makeSigner, type TestSigner } from './helpers.js';

/**
 * An in-memory fake witness speaking the exact wire protocol (submission
 * verification, consistency enforcement, signed acks) so the client's
 * behavior — catch-up, ack verification, conflict detection — is tested
 * without HTTP. The REAL reference server gets its own end-to-end suite in
 * @mandarelabs/witness.
 */
class FakeWitness {
  latest: WitnessedHeadRecord | null = null;
  signer: TestSigner = makeSigner();
  /** Test hooks. */
  tamperAck: ((ack: SignedHeadAck) => SignedHeadAck | Promise<SignedHeadAck>) | null = null;
  refuseAll = false;

  fetchImpl = (async (input: Parameters<typeof fetch>[0], init?: RequestInit): Promise<Response> => {
    const url = String(input);
    if (this.refuseAll) return new Response('{}', { status: 503 });
    if (url.endsWith('/head') && init?.method === undefined) {
      if (this.latest === null) return new Response('{}', { status: 404 });
      return Response.json({ record: this.latest, ack: await this.ackFor(this.latest) });
    }
    if (url.endsWith('/v1/heads') && init?.method === 'POST') {
      const signed = parseSignedHeadSubmission(JSON.parse(String(init.body)));
      if (!(await verifySignedPayload(signed, signed.payload.door_public_key))) {
        return new Response('{}', { status: 403 });
      }
      const payload = signed.payload;
      const latest = this.latest;
      const prevMatches =
        payload.prev === null
          ? latest === null
          : latest !== null &&
            payload.prev.size === latest.head.size &&
            payload.prev.root === latest.head.root;
      if (!prevMatches) {
        return Response.json({ code: 'PREV_MISMATCH', latest: latest?.head ?? null }, { status: 409 });
      }
      if (latest !== null && payload.head.size === latest.head.size) {
        if (payload.head.root === latest.head.root) return Response.json(await this.ackFor(latest));
        return Response.json({ code: 'NOT_CONSISTENT' }, { status: 409 });
      }
      if (latest !== null) {
        const ok = await verifyConsistency({
          size1: latest.head.size,
          root1: latest.head.root,
          size2: payload.head.size,
          root2: payload.head.root,
          proof: payload.consistency_proof,
        });
        if (!ok) return Response.json({ code: 'NOT_CONSISTENT' }, { status: 409 });
      }
      this.latest = {
        source_id: payload.source_id,
        head: payload.head,
        ts: payload.ts,
        witnessed_at: new Date().toISOString(),
      };
      return Response.json(await this.ackFor(this.latest));
    }
    return new Response('{}', { status: 404 });
  }) as typeof fetch;

  private async ackFor(record: WitnessedHeadRecord): Promise<SignedHeadAck> {
    const payload: SignedHeadAck['payload'] = {
      protocol: WITNESS_PROTOCOL,
      type: 'head.ack',
      source_id: record.source_id,
      head: record.head,
      witnessed_at: record.witnessed_at,
      witness_key_id: this.signer.keyId,
    };
    const ack = await signPayload(payload, this.signer);
    return this.tamperAck === null ? ack : this.tamperAck(ack);
  }
}

function makeClient(witness: FakeWitness, hashes: () => string[], signer = makeSigner()) {
  return new WitnessClient({
    url: 'http://witness.test',
    signer,
    readEntryHashes: () => Promise.resolve(hashes()),
    witnessPublicKeyHex: witness.signer.publicKeyHex,
    fetchImpl: witness.fetchImpl,
  });
}

describe('WitnessClient', () => {
  test('first sync (TOFU), growth sync with proof, idempotent resync', async () => {
    const witness = new FakeWitness();
    const signer = makeSigner();
    const chain = buildChain(signer, 3);
    let hashes = entryHashesOf(chain);
    const client = makeClient(witness, () => hashes, signer);

    const first = await client.sync();
    expect(first.head.size).toBe(3);
    expect(first.ack.head.size).toBe(3);
    expect(witness.latest?.head.size).toBe(3);

    hashes = entryHashesOf(buildChainExtension(signer, chain, 2));
    const second = await client.sync();
    expect(second.head.size).toBe(5);

    // Unchanged ledger: idempotent, still acked.
    const third = await client.sync();
    expect(third.head.size).toBe(5);
  });

  test('offline catch-up: heads appended during the gap are witnessed in one sync', async () => {
    const witness = new FakeWitness();
    const signer = makeSigner();
    const chain = buildChain(signer, 2);
    let hashes = entryHashesOf(chain);
    const client = makeClient(witness, () => hashes, signer);
    await client.sync();

    witness.refuseAll = true; // the witness goes dark
    hashes = entryHashesOf(buildChainExtension(signer, chain, 4));
    await expect(client.sync()).rejects.toThrow(WitnessSyncError);

    witness.refuseAll = false; // reconnect: one sync covers the whole backlog
    const result = await client.sync();
    expect(result.head.size).toBe(6);
    expect(witness.latest?.head.size).toBe(6);
  });

  test('stale prev cache: client re-fetches and retries once', async () => {
    const witness = new FakeWitness();
    const signer = makeSigner();
    const chain = buildChain(signer, 2);
    let hashes = entryHashesOf(chain);
    const clientA = makeClient(witness, () => hashes, signer);
    await clientA.sync();

    // A second client (fresh cache) syncs after more growth — its first POST
    // matches; then break clientA's cache by advancing via clientB.
    hashes = entryHashesOf(buildChainExtension(signer, chain, 1));
    const clientB = makeClient(witness, () => hashes, signer);
    await clientB.sync();
    expect(witness.latest?.head.size).toBe(3);

    // clientA still believes prev is size 2 → 409 → refetch → success.
    const result = await clientA.sync();
    expect(result.head.size).toBe(3);
  });

  test('FORGED ack (wrong witness key) is refused', async () => {
    const witness = new FakeWitness();
    const rogue = makeSigner();
    witness.tamperAck = async (ack) => signPayload(ack.payload, rogue);
    const signer = makeSigner();
    const hashes = entryHashesOf(buildChain(signer, 2));
    const client = makeClient(witness, () => hashes, signer);
    await expect(client.sync()).rejects.toThrow(/signature is invalid/);
  });

  test('REPLAYED ack (older head, valid signature) is refused', async () => {
    const witness = new FakeWitness();
    const signer = makeSigner();
    const chain = buildChain(signer, 2);
    let hashes = entryHashesOf(chain);
    const client = makeClient(witness, () => hashes, signer);
    const first = await client.sync();

    // The witness now replays the FIRST ack for every later submission.
    const staleAckPayload = { ...first.ack };
    witness.tamperAck = () => signPayload(staleAckPayload, witness.signer);
    hashes = entryHashesOf(buildChainExtension(signer, chain, 2));
    await expect(client.sync()).rejects.toThrow(/does not match the submitted head/);
  });

  test('HISTORY_CONFLICT: witness is ahead of the local ledger (local truncation)', async () => {
    const witness = new FakeWitness();
    const signer = makeSigner();
    const chain = buildChain(signer, 5);
    let hashes = entryHashesOf(chain);
    const client = makeClient(witness, () => hashes, signer);
    await client.sync();

    hashes = hashes.slice(0, 3); // the local ledger LOST entries
    const fresh = makeClient(witness, () => hashes, signer);
    await expect(fresh.sync()).rejects.toThrow(/LOST entries/);
  });

  test('HISTORY_CONFLICT: same size, different root (local rewrite)', async () => {
    const witness = new FakeWitness();
    const signer = makeSigner();
    let hashes = entryHashesOf(buildChain(signer, 3));
    const client = makeClient(witness, () => hashes, signer);
    await client.sync();

    hashes = entryHashesOf(buildChain(signer, 3)); // different salts ⇒ different roots
    const fresh = makeClient(witness, () => hashes, signer);
    await expect(fresh.sync()).rejects.toThrow(/history rewritten/);
  });

  test('background loop: syncs when dirty, retries after failure', async () => {
    const witness = new FakeWitness();
    const signer = makeSigner();
    const chain = buildChain(signer, 1);
    let hashes = entryHashesOf(chain);
    const client = makeClient(witness, () => hashes, signer);
    const failures: unknown[] = [];
    client.start(10, (error) => failures.push(error));
    try {
      await waitFor(() => witness.latest?.head.size === 1);
      witness.refuseAll = true;
      hashes = entryHashesOf(buildChainExtension(signer, chain, 1));
      client.notifyAppend();
      await waitFor(() => failures.length > 0);
      witness.refuseAll = false;
      await waitFor(() => witness.latest?.head.size === 2);
    } finally {
      client.stop();
    }
  });
});

/** Extend an existing chain in place and return the full entry list. */
function buildChainExtension(
  signer: TestSigner,
  chain: ReturnType<typeof buildChain>,
  extra: number
): ReturnType<typeof buildChain> {
  const extension = buildChain(signer, chain.length + extra).slice(chain.length);
  // Rebuild the extension so it links to the existing chain's head.
  let prevHash = chain[chain.length - 1]?.entry_hash ?? '0'.repeat(64);
  const relinked = extension.map((entry) => {
    const rebuilt = rebuildEntry(signer, entry, prevHash);
    prevHash = rebuilt.entry_hash;
    return rebuilt;
  });
  chain.push(...relinked);
  return chain;
}

function rebuildEntry(
  signer: TestSigner,
  entry: ReturnType<typeof buildChain>[number],
  prevHash: string
): ReturnType<typeof buildChain>[number] {
  const { entry_hash: _hash, door_signature: _sig, ...preimage } = entry;
  return buildSigned(signer, { ...preimage, prev_hash: prevHash });
}

function buildSigned(signer: TestSigner, preimage: LedgerEntryPreimage): LedgerEntryV1 {
  const entryHash = computeEntryHash(preimage);
  return {
    ...preimage,
    entry_hash: entryHash,
    door_signature: {
      alg: 'EdDSA',
      key_id: signer.keyId,
      key_provenance: 'software',
      value: bytesToBase64Url(
        new Uint8Array(cryptoSign(null, Buffer.from(entryHash, 'hex'), signer.privateKey))
      ),
    },
  };
}

async function waitFor(condition: () => boolean, timeoutMs = 2000): Promise<void> {
  const start = Date.now();
  while (!condition()) {
    if (Date.now() - start > timeoutMs) throw new Error('waitFor timed out');
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}
