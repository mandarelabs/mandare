import { describe, expect, test } from 'vitest';

import { bytesToBase64Url, hexToBytes } from '@mandarelabs/spec';
import { computeTreeHead, consistencyProof, inclusionProof } from '@mandarelabs/verifier';

import {
  aggregateInclusionProof,
  buildAggregate,
  signEpochSummary,
} from '../src/aggregate.js';
import { MockAnchor } from '../src/anchor.js';
import { serializeOtsProof } from '../src/ots.js';
import {
  buildIntegrityCertificate,
  parseIntegrityCertificate,
  verifyIntegrityCertificate,
  type IntegrityCertificate,
} from '../src/certificate.js';
import { WITNESS_PROTOCOL, type WitnessedHeadRecord } from '../src/messages.js';
import { signPayload } from '../src/signing.js';
import { buildChain, entryHashesOf, makeSigner, type TestSigner } from './helpers.js';

/**
 * Full certificate lifecycle at the library level: a real chain, a witnessed
 * head, an anchored epoch, selective disclosure — built, then verified as a
 * THIRD PARTY would (no chain access), then attacked.
 */

interface Fixture {
  doorSigner: TestSigner;
  witnessSigner: TestSigner;
  certificate: IntegrityCertificate;
}

async function buildFixture(
  options: { discloseSeqs?: number[]; otsBitcoinAnchor?: boolean } = {}
): Promise<Fixture> {
  const doorSigner = makeSigner();
  const witnessSigner = makeSigner();
  const chain = buildChain(doorSigner, 6);
  const hashes = entryHashesOf(chain);
  const tree = await computeTreeHead(hashes);

  // The witness recorded the head at size 4 (streaming lags the tip a bit).
  const witnessedHead = await computeTreeHead(hashes.slice(0, 4));
  const record: WitnessedHeadRecord = {
    source_id: doorSigner.keyId,
    head: witnessedHead,
    ts: '2026-08-09T10:00:00Z',
    witnessed_at: '2026-08-09T10:00:01Z',
  };
  const ackPayload: import('../src/messages.js').HeadAckPayload = {
    protocol: WITNESS_PROTOCOL,
    type: 'head.ack',
    source_id: record.source_id,
    head: record.head,
    witnessed_at: record.witnessed_at,
    witness_key_id: witnessSigner.keyId,
  };
  const ack = await signPayload(ackPayload, witnessSigner);

  // One anchored epoch containing this source plus a stranger.
  const stranger: WitnessedHeadRecord = {
    source_id: 'f'.repeat(64),
    head: { size: 9, root: '77'.repeat(32) },
    ts: '2026-08-09T09:00:00Z',
    witnessed_at: '2026-08-09T09:00:02Z',
  };
  const snapshot = await buildAggregate([record, stranger]);
  const leafIndex = snapshot.records.findIndex((r) => r.source_id === record.source_id);
  const signedEpoch = options.otsBitcoinAnchor
    ? await signEpochSummary(
        {
          epoch: 1,
          created_at: '2026-08-09T10:05:00Z',
          aggregate: snapshot.head,
          anchor_status: 'confirmed',
          // A real .ots that commits the aggregate root AND carries a Bitcoin
          // attestation TAG — but nothing here proves the block exists (that
          // needs a node). C2: tag presence must NOT be graded 'proof' offline.
          ots_base64: bytesToBase64Url(
            serializeOtsProof({
              digest: hexToBytes(snapshot.head.root),
              timestamp: {
                msg: hexToBytes(snapshot.head.root),
                attestations: [{ kind: 'bitcoin', height: 812_345 }],
                ops: [],
              },
            })
          ),
          anchor_kind: 'opentimestamps',
        },
        witnessSigner
      )
    : await (async () => {
        const receipt = await new MockAnchor().anchor(snapshot.head.root);
        return signEpochSummary(
          {
            epoch: 1,
            created_at: '2026-08-09T10:05:00Z',
            aggregate: snapshot.head,
            anchor_status: receipt.status,
            ots_base64: receipt.proof,
            anchor_kind: receipt.kind,
          },
          witnessSigner
        );
      })();

  const discloseSeqs = options.discloseSeqs ?? [2, 5];
  const certificate = await buildIntegrityCertificate({
    ledger: {
      door_id: 'gateway:test',
      door_key_id: doorSigner.keyId,
      door_public_key: doorSigner.publicKeyHex,
    },
    treeHead: tree,
    entryCount: chain.length,
    witness: {
      record,
      ack,
      consistency_proof: await consistencyProof(hashes, witnessedHead.size),
    },
    anchor: {
      inclusion: {
        epoch: signedEpoch,
        leaf: record,
        leaf_index: leafIndex,
        inclusion_proof: await aggregateInclusionProof(snapshot, leafIndex),
      },
      consistency_proof: await consistencyProof(hashes, witnessedHead.size),
    },
    disclosed: await Promise.all(
      discloseSeqs.map(async (seq) => ({
        seq,
        entry: chain[seq - 1]!,
        inclusion_proof: await inclusionProof(hashes, seq - 1),
      }))
    ),
    revocation: { bits: 1, lst: 'eNrbuRgAAhcBXQ' },
    signer: doorSigner,
  });
  return { doorSigner, witnessSigner, certificate };
}

describe('integrity certificate', () => {
  test('round trip: build → serialize → parse → verify (all checks pass)', async () => {
    const { certificate, witnessSigner, doorSigner } = await buildFixture();
    const reparsed = parseIntegrityCertificate(JSON.parse(JSON.stringify(certificate)));
    const verdict = await verifyIntegrityCertificate(reparsed, {
      witnessPublicKeyHex: witnessSigner.publicKeyHex,
      doorPublicKeyHex: doorSigner.publicKeyHex,
    });
    expect(verdict.checks.map((c) => `${c.name}:${c.ok}`)).toEqual([
      'bundle-signature:true',
      'witnessed-head-signature:true',
      'witnessed-consistency:true',
      'disclosed-entry-seq-2:true',
      'disclosed-entry-seq-5:true',
      'witness-aggregated-head:true',
      'public-anchor:false', // mock anchor: aggregation proven, public-chain finality NOT (honest)
      'chain-valid-and-complete:true',
    ]);
    // The verdict gates on PROOF-basis checks; the mock anchor's public-anchor
    // check is recorder-attested and does NOT fail an otherwise-sound cert.
    expect(verdict.ok).toBe(true);
    expect(verdict.checks.find((c) => c.name === 'public-anchor')?.basis).toBe('recorder-attested');
    expect(verdict.checks.find((c) => c.name === 'chain-valid-and-complete')?.basis).toBe(
      'recorder-attested'
    );
  });

  test('S8/C1: bound mode refuses a certificate whose witnessed source is not the trusted door key', async () => {
    // The dishonest-operator attack: hold the trusted door key A, but launder a
    // curated/truncated history by witnessing it under a FRESH source id B, then
    // self-declare B in the certificate while signing the bundle with A. Pre-fix
    // this verified VALID — the witnessed history was B's parallel timeline, not
    // A's real (truncation-detecting) one.
    const trusted = makeSigner(); // A — the auditor's out-of-band door key
    const parallel = makeSigner(); // B — the fresh source the curated tree is witnessed under
    const witnessSigner = makeSigner();

    const chain = buildChain(trusted, 4); // every entry really signed by A
    const hashes = entryHashesOf(chain);
    const tree = await computeTreeHead(hashes);
    const witnessedHead = await computeTreeHead(hashes.slice(0, 3));

    const record: WitnessedHeadRecord = {
      source_id: parallel.keyId, // witnessed under B (first contact — witness acks)
      head: witnessedHead,
      ts: '2026-08-09T10:00:00Z',
      witnessed_at: '2026-08-09T10:00:01Z',
    };
    const ackPayload: import('../src/messages.js').HeadAckPayload = {
      protocol: WITNESS_PROTOCOL,
      type: 'head.ack',
      source_id: record.source_id,
      head: record.head,
      witnessed_at: record.witnessed_at,
      witness_key_id: witnessSigner.keyId,
    };
    const ack = await signPayload(ackPayload, witnessSigner);

    const certificate = await buildIntegrityCertificate({
      ledger: {
        door_id: 'gateway:test',
        door_key_id: parallel.keyId, // the parallel source B drives checks 2/3/5
        door_public_key: parallel.publicKeyHex,
      },
      treeHead: tree,
      entryCount: chain.length,
      witness: { record, ack, consistency_proof: await consistencyProof(hashes, witnessedHead.size) },
      anchor: null,
      disclosed: [{ seq: 2, entry: chain[1]!, inclusion_proof: await inclusionProof(hashes, 1) }],
      revocation: null,
      signer: trusted, // bundle signed by A → signature.key_id = sha256(A)
    });

    const verdict = await verifyIntegrityCertificate(certificate, {
      witnessPublicKeyHex: witnessSigner.publicKeyHex,
      doorPublicKeyHex: trusted.publicKeyHex, // auditor trusts A out-of-band
    });

    expect(verdict.ok).toBe(false);
    const bundle = verdict.checks.find((c) => c.name === 'bundle-signature');
    expect(bundle?.ok).toBe(false);
    expect(bundle?.detail).toMatch(/different source/i);
  });

  test('S8/C2: an OTS Bitcoin attestation is recorder-attested (verify externally), never proof', async () => {
    const { certificate, witnessSigner, doorSigner } = await buildFixture({ otsBitcoinAnchor: true });
    const verdict = await verifyIntegrityCertificate(certificate, {
      witnessPublicKeyHex: witnessSigner.publicKeyHex,
      doorPublicKeyHex: doorSigner.publicKeyHex,
    });
    const anchor = verdict.checks.find((c) => c.name === 'public-anchor');
    // The tag's mere presence is not offline-verifiable finality — report it,
    // never gate on it (pre-fix this was basis 'proof', ok true).
    expect(anchor?.basis).toBe('recorder-attested');
    expect(anchor?.ok).toBe(true);
    expect(anchor?.detail).toMatch(/verify the \.ots against a bitcoin node/i);
    // The otherwise-sound certificate still verifies (the anchor doesn't gate),
    // and the witness-signed aggregation proof still gates and passes.
    expect(verdict.ok).toBe(true);
    expect(verdict.checks.find((c) => c.name === 'witness-aggregated-head')?.ok).toBe(true);
  });

  test('HIGH-2: an attacker-fabricated (unsigned) epoch aggregate is refused', async () => {
    const { certificate, witnessSigner } = await buildFixture();
    const tampered = JSON.parse(JSON.stringify(certificate)) as IntegrityCertificate;
    // Strip the witness signature — a self-built aggregate has none.
    delete (tampered.anchor!.inclusion.epoch as { witness_signature?: unknown }).witness_signature;
    const verdict = await verifyIntegrityCertificate(tampered, {
      witnessPublicKeyHex: witnessSigner.publicKeyHex,
    });
    const check = verdict.checks.find((c) => c.name === 'witness-aggregated-head');
    expect(check?.ok).toBe(false);
    expect(check?.detail).toMatch(/NOT witness-signed/);
    expect(verdict.ok).toBe(false);
  });

  test('HIGH-1: a forged source identity (door_key_id ≠ sha256(door_public_key)) is refused', async () => {
    const { certificate, witnessSigner } = await buildFixture();
    const forged = JSON.parse(JSON.stringify(certificate)) as IntegrityCertificate;
    // Attacker keeps the victim's source_id/door_key_id but swaps in their key.
    const attacker = makeSigner();
    forged.ledger.door_public_key = attacker.publicKeyHex;
    const verdict = await verifyIntegrityCertificate(forged, {
      witnessPublicKeyHex: witnessSigner.publicKeyHex,
    });
    const check = verdict.checks.find((c) => c.name === 'bundle-signature');
    expect(check?.ok).toBe(false);
    expect(check?.detail).toMatch(/source identity is forged/);
    expect(verdict.ok).toBe(false);
  });

  test('selective disclosure: undisclosed entries appear nowhere in the certificate', async () => {
    const { certificate } = await buildFixture({ discloseSeqs: [3] });
    const rendered = JSON.stringify(certificate);
    expect(certificate.disclosed).toHaveLength(1);
    // Contents of other entries (actor/cost text is shared, but their unique
    // salts and hashes stay confined to proof nodes): the certificate carries
    // exactly ONE full entry object.
    expect(rendered.match(/"door_signature"/g)).toHaveLength(1);
    expect(rendered.match(/"salt"/g)).toHaveLength(1);
  });

  test('wrong witness key: witnessed-head check fails', async () => {
    const { certificate } = await buildFixture();
    const rogue = makeSigner();
    const verdict = await verifyIntegrityCertificate(certificate, {
      witnessPublicKeyHex: rogue.publicKeyHex,
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.checks.find((c) => c.name === 'witnessed-head-signature')?.ok).toBe(false);
  });

  test('TAMPER: modified disclosed entry fails its hash check', async () => {
    const { certificate, witnessSigner } = await buildFixture();
    const tampered = JSON.parse(JSON.stringify(certificate)) as IntegrityCertificate;
    (tampered.disclosed[0]!.entry as { cost: { amount: number } }).cost.amount = 999_999;
    const verdict = await verifyIntegrityCertificate(tampered, {
      witnessPublicKeyHex: witnessSigner.publicKeyHex,
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.checks.find((c) => c.name.startsWith('disclosed-entry-seq-2'))?.ok).toBe(false);
    // The bundle signature also breaks — tampering is doubly visible.
    expect(verdict.checks.find((c) => c.name === 'bundle-signature')?.ok).toBe(false);
  });

  test('TAMPER: certificate over a truncated tree fails witnessed-consistency', async () => {
    const { doorSigner, witnessSigner } = await buildFixture();
    // Rebuild a certificate whose tree_head is SMALLER than the witnessed
    // head — the truncation case a third party must catch.
    const chain = buildChain(doorSigner, 3);
    const hashes = entryHashesOf(chain);
    const tree = await computeTreeHead(hashes);
    const witnessedHead = await computeTreeHead([...hashes, 'aa'.repeat(32), 'bb'.repeat(32)]);
    const record: WitnessedHeadRecord = {
      source_id: doorSigner.keyId,
      head: witnessedHead,
      ts: '2026-08-09T10:00:00Z',
      witnessed_at: '2026-08-09T10:00:01Z',
    };
    const ackPayload: import('../src/messages.js').HeadAckPayload = {
      protocol: WITNESS_PROTOCOL,
      type: 'head.ack',
      source_id: record.source_id,
      head: record.head,
      witnessed_at: record.witnessed_at,
      witness_key_id: witnessSigner.keyId,
    };
    const ack = await signPayload(ackPayload, witnessSigner);
    const certificate = await buildIntegrityCertificate({
      ledger: {
        door_id: 'gateway:test',
        door_key_id: doorSigner.keyId,
        door_public_key: doorSigner.publicKeyHex,
      },
      treeHead: tree,
      entryCount: chain.length,
      witness: { record, ack, consistency_proof: [] },
      anchor: null,
      disclosed: [],
      revocation: null,
      signer: doorSigner,
    });
    const verdict = await verifyIntegrityCertificate(certificate, {
      witnessPublicKeyHex: witnessSigner.publicKeyHex,
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.checks.find((c) => c.name === 'witnessed-consistency')?.ok).toBe(false);
  });

  test('TAMPER: anchored leaf swapped for another source fails', async () => {
    const { certificate, witnessSigner } = await buildFixture();
    const tampered = JSON.parse(JSON.stringify(certificate)) as IntegrityCertificate;
    tampered.anchor!.inclusion.leaf = {
      ...tampered.anchor!.inclusion.leaf,
      source_id: 'f'.repeat(64),
    };
    const verdict = await verifyIntegrityCertificate(tampered, {
      witnessPublicKeyHex: witnessSigner.publicKeyHex,
    });
    expect(verdict.checks.find((c) => c.name === 'witness-aggregated-head')?.ok).toBe(false);
    expect(verdict.ok).toBe(false);
  });

  test('schema boundary: garbage refuses to parse (R4)', () => {
    expect(() => parseIntegrityCertificate({ format: 'nope' })).toThrow(/validation failed/);
    expect(() => parseIntegrityCertificate(null)).toThrow(/validation failed/);
  });
});
