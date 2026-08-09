import { loadOrCreateDoorKey } from '@mandarelabs/ledger';
import { buildWitnessServer } from '@mandarelabs/witness';
import { MockAnchor, OpenTimestampsAnchor, type Anchor } from '@mandarelabs/witness-protocol';

/**
 * `mandare witness serve` — run the open reference witness (SPEC §3.2).
 * Single tenant, self-hostable: record head submissions, serve witnessed-head
 * lookups + signed acks, anchor the aggregate root on a daily cadence
 * (OpenTimestamps by default; `--anchor mock` for offline/dev).
 *
 * The printed public key is what doors and verifiers must receive
 * OUT-OF-BAND (MANDARE_WITNESS_PUBLIC_KEY / --witness-key) — a witness, like
 * a door, cannot vouch for itself over its own channel.
 */
export interface WitnessServeOptions {
  dbPath: string;
  host: string;
  port: number;
  keyPath?: string;
  anchor: 'ots' | 'mock';
  anchorIntervalHours: number | null;
  keyDirectoryPath?: string;
  statusListPath?: string;
}

export async function runWitnessServe(options: WitnessServeOptions): Promise<number> {
  const key = loadOrCreateDoorKey(options.keyPath ?? `${options.dbPath}.witnesskey.pem`);
  const anchor: Anchor = options.anchor === 'mock' ? new MockAnchor() : new OpenTimestampsAnchor();
  const witness = await buildWitnessServer({
    dbPath: options.dbPath,
    key,
    anchor,
    keyDirectoryPath: options.keyDirectoryPath ?? null,
    statusListPath: options.statusListPath ?? null,
  });

  const address = await witness.app.listen({ host: options.host, port: options.port });
  console.log(`mandare witness listening on ${address}`);
  console.log(`  db=${options.dbPath} anchor=${options.anchor}`);
  console.log(`  witness_key_id=${key.keyId}`);
  console.log(`  public_key=${key.publicKeyHex}`);
  console.log(
    '  ^ distribute this public key OUT-OF-BAND (doors: MANDARE_WITNESS_PUBLIC_KEY; verifiers: --witness-key)'
  );

  let anchorTimer: ReturnType<typeof setInterval> | null = null;
  if (options.anchorIntervalHours !== null) {
    anchorTimer = setInterval(
      () => {
        witness.runAnchor().then(
          (result) => console.log(`witness: anchored epoch ${result.epoch} (${result.status})`),
          (error) =>
            console.error(
              `witness: anchor run failed: ${error instanceof Error ? error.message : String(error)}`
            )
        );
      },
      options.anchorIntervalHours * 60 * 60 * 1000
    );
    console.log(`  anchoring every ${options.anchorIntervalHours}h (also on demand: POST /v1/anchor/run)`);
  } else {
    console.log('  anchoring on demand only (POST /v1/anchor/run)');
  }

  await new Promise<void>((resolve) => {
    for (const signal of ['SIGINT', 'SIGTERM'] as const) {
      process.on(signal, () => resolve());
    }
  });
  if (anchorTimer !== null) clearInterval(anchorTimer);
  await witness.close();
  return 0;
}
