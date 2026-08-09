import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { loadOrCreateDoorKey, type DoorKey } from '@mandarelabs/ledger';
import { MockAnchor } from '@mandarelabs/witness-protocol';

import { buildWitnessServer, type WitnessServer } from '../src/server.js';

export function tempDir(): string {
  return mkdtempSync(join(tmpdir(), 'mandare-witness-test-'));
}

export interface RunningWitness {
  witness: WitnessServer;
  url: string;
  key: DoorKey;
  dbPath: string;
  close(): Promise<void>;
}

/** Start a real reference witness on an ephemeral port with a mock anchor. */
export async function startWitness(
  overrides: Partial<Parameters<typeof buildWitnessServer>[0]> = {}
): Promise<RunningWitness> {
  const dir = tempDir();
  const key = loadOrCreateDoorKey(join(dir, 'witness.pem'));
  const dbPath = join(dir, 'witness.db');
  const witness = await buildWitnessServer({
    dbPath,
    key,
    anchor: new MockAnchor(),
    ...overrides,
  });
  const url = await witness.app.listen({ host: '127.0.0.1', port: 0 });
  return {
    witness,
    url,
    key,
    dbPath,
    close: () => witness.close(),
  };
}
