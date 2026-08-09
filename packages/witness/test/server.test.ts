import { join } from 'node:path';
import { writeFileSync } from 'node:fs';

import { afterEach, describe, expect, test } from 'vitest';

import { Ledger } from '@mandarelabs/ledger';
import { computeTreeHead } from '@mandarelabs/verifier';
import {
  WitnessClient,
  parseEpochInclusion,
  parseSignedHeadAck,
  verifyAggregateInclusion,
  verifyEpochSummary,
  verifySignedPayload,
} from '@mandarelabs/witness-protocol';

import { startWitness, tempDir, type RunningWitness } from './helpers.js';

/**
 * End-to-end over the REAL reference server with a REAL SQLite ledger: the
 * exact wiring a solo deployment runs (Ledger → WitnessClient → HTTP →
 * WitnessStore), plus epochs, anchoring, and the hosting endpoints.
 */

let running: RunningWitness | null = null;
afterEach(async () => {
  await running?.close();
  running = null;
});

function makeLedger(entries: number): { ledger: Ledger; dbPath: string } {
  const dbPath = join(tempDir(), 'ledger.db');
  const ledger = Ledger.open(dbPath, { doorId: 'gateway:test' });
  for (let i = 0; i < entries; i += 1) {
    ledger.append({
      actor: 'did:example:agent',
      mandate_id: 'mnd_test',
      action: { type: 'llm.call.intent', target: 'api.example.com', request_hash: 'b'.repeat(64) },
      cost: { amount: 5, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
    });
  }
  return { ledger, dbPath };
}

function clientFor(ledger: Ledger, witness: RunningWitness): WitnessClient {
  return new WitnessClient({
    url: witness.url,
    signer: ledger.signer(),
    readEntryHashes: () => Promise.resolve(ledger.entryHashes()),
    witnessPublicKeyHex: witness.key.publicKeyHex,
  });
}

describe('reference witness server', () => {
  test('stream → witnessed head lookup → verified ack', async () => {
    running = await startWitness();
    const { ledger } = makeLedger(4);
    const client = clientFor(ledger, running);

    const result = await client.sync();
    expect(result.head.size).toBe(4);
    expect(result.ack.witness_key_id).toBe(running.key.keyId);

    // The served head verifies against the witness key and matches the chain.
    const response = await fetch(`${running.url}/v1/sources/${ledger.doorKeyId}/head`);
    const body = (await response.json()) as { record: unknown; ack: unknown };
    const ack = parseSignedHeadAck(body.ack);
    expect(await verifySignedPayload(ack, running.key.publicKeyHex)).toBe(true);
    const local = await computeTreeHead(ledger.entryHashes());
    expect(ack.payload.head).toEqual(local);
    ledger.close();
  });

  test('growth is consistency-proven; history accumulates', async () => {
    running = await startWitness();
    const { ledger } = makeLedger(2);
    const client = clientFor(ledger, running);
    await client.sync();
    for (let i = 0; i < 3; i += 1) {
      ledger.append({
        actor: 'did:example:agent',
        mandate_id: 'mnd_test',
        action: { type: 'llm.call.intent', target: 'api.example.com', request_hash: 'c'.repeat(64) },
        cost: { amount: 1, currency: 'EUR', tokens_in: 0, tokens_out: 0 },
      });
      await client.sync();
    }
    const history = (await (
      await fetch(`${running.url}/v1/sources/${ledger.doorKeyId}/history`)
    ).json()) as { records: { head: { size: number } }[] };
    expect(history.records.map((r) => r.head.size)).toEqual([2, 3, 4, 5]);
    ledger.close();
  });

  test('epochs: anchor run aggregates sources; inclusion proof verifies locally', async () => {
    running = await startWitness();
    const a = makeLedger(3);
    const b = makeLedger(5);
    await clientFor(a.ledger, running).sync();
    await clientFor(b.ledger, running).sync();

    const anchorResult = await running.witness.runAnchor();
    expect(anchorResult.epoch).toBe(1);
    expect(anchorResult.status).toBe('confirmed'); // MockAnchor

    const latest = (await (await fetch(`${running.url}/v1/epochs/latest`)).json()) as {
      epoch: number;
      aggregate: { size: number };
      anchor_status: string;
    };
    expect(latest.aggregate.size).toBe(2);
    expect(latest.anchor_status).toBe('confirmed');
    // The served epoch is witness-signed so a relying party can trust the
    // aggregate root is the witness's, not a fabrication (S6-H2).
    expect(await verifyEpochSummary(latest as never, running.key.publicKeyHex)).toBe(true);

    for (const { ledger } of [a, b]) {
      const inclusion = parseEpochInclusion(
        await (
          await fetch(`${running.url}/v1/epochs/1/inclusion/${ledger.doorKeyId}`)
        ).json()
      );
      expect(await verifyEpochSummary(inclusion.epoch, running.key.publicKeyHex)).toBe(true);
      expect(
        await verifyAggregateInclusion({
          record: inclusion.leaf,
          leafIndex: inclusion.leaf_index,
          aggregate: inclusion.epoch.aggregate,
          proof: inclusion.inclusion_proof,
        })
      ).toBe(true);
      ledger.close();
    }
  });

  test('a source never witnessed 404s; unknown epochs 404', async () => {
    running = await startWitness();
    expect((await fetch(`${running.url}/v1/sources/${'a'.repeat(64)}/head`)).status).toBe(404);
    expect((await fetch(`${running.url}/v1/epochs/latest`)).status).toBe(404);
    expect((await fetch(`${running.url}/v1/epochs/9/inclusion/${'a'.repeat(64)}`)).status).toBe(404);
  });

  test('anchor run with no sources refuses honestly', async () => {
    running = await startWitness();
    const response = await fetch(`${running.url}/v1/anchor/run`, { method: 'POST' });
    expect(response.status).toBe(409);
  });

  test('healthz reports the witness state', async () => {
    running = await startWitness();
    const { ledger } = makeLedger(1);
    await clientFor(ledger, running).sync();
    const health = (await (await fetch(`${running.url}/healthz`)).json()) as Record<string, unknown>;
    expect(health.status).toBe('ok');
    expect(health.sources).toBe(1);
    expect(health.heads).toBe(1);
    ledger.close();
  });

  test('hosting: key directory + status list served with correct content types', async () => {
    const dir = tempDir();
    const directoryPath = join(dir, 'directory.json');
    const statusPath = join(dir, 'status.json');
    writeFileSync(directoryPath, JSON.stringify({ keys: [] }));
    writeFileSync(statusPath, JSON.stringify({ status_list: { bits: 1, lst: 'eNrbuRgAAhcBXQ' } }));
    running = await startWitness({ keyDirectoryPath: directoryPath, statusListPath: statusPath });

    const directory = await fetch(`${running.url}/.well-known/http-message-signatures-directory`);
    expect(directory.headers.get('content-type')).toContain(
      'application/http-message-signatures-directory+json'
    );
    expect(await directory.json()).toEqual({ keys: [] });

    const status = await fetch(`${running.url}/v1/status-list`);
    expect(status.status).toBe(200);
    expect(((await status.json()) as { status_list: { bits: number } }).status_list.bits).toBe(1);
  });
});
