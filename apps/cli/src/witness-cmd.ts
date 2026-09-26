import { loadOrCreateDoorKey } from '@mandarelabs/ledger';
import { buildWitnessServer } from '@mandarelabs/witness';
import { MockAnchor, OpenTimestampsAnchor, type Anchor } from '@mandarelabs/witness-protocol';

/**
 * `mandare witness serve` — run the open reference witness (SPEC §3.2).
 * Single tenant, self-hostable: record head submissions, serve witnessed-head
 * lookups + signed acks, anchor the aggregate root on a daily cadence
 * (OpenTimestamps by default; `--anchor mock` for offline/dev), and upgrade
 * pending OpenTimestamps receipts to their Bitcoin attestations hourly.
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

const ON_DEMAND = "POST /v1/anchor/run — loopback with 'x-mandare-anchor: run', or MANDARE_WITNESS_ANCHOR_TOKEN";

function nonEmpty(value: string | undefined): string | null {
  return value === undefined || value === '' ? null : value;
}

/** How often pending OpenTimestamps receipts are re-checked against the calendars. */
const UPGRADE_INTERVAL_MS = 60 * 60 * 1000;

export async function runWitnessServe(options: WitnessServeOptions): Promise<number> {
  const key = loadOrCreateDoorKey(options.keyPath ?? `${options.dbPath}.witnesskey.pem`);
  const anchor: Anchor = options.anchor === 'mock' ? new MockAnchor() : new OpenTimestampsAnchor();
  const witness = await buildWitnessServer({
    dbPath: options.dbPath,
    key,
    anchor,
    keyDirectoryPath: options.keyDirectoryPath ?? null,
    statusListPath: options.statusListPath ?? null,
    // W-5: remote on-demand anchor runs need this operator token; without it
    // they are loopback-only (x-mandare-anchor: run) and throttled.
    anchorRunToken: nonEmpty(process.env.MANDARE_WITNESS_ANCHOR_TOKEN),
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
    console.log(`  anchoring every ${options.anchorIntervalHours}h (also on demand: ${ON_DEMAND})`);
  } else {
    console.log(`  anchoring on demand only (${ON_DEMAND})`);
  }

  // OpenTimestamps receipts start `pending`; calendars aggregate into Bitcoin
  // within hours. Poll them, or no receipt ever reaches Bitcoin (I-5).
  let upgradeTimer: ReturnType<typeof setInterval> | null = null;
  if (options.anchor === 'ots') {
    upgradeTimer = setInterval(() => {
      witness.runUpgrade().then(
        (result) => {
          if (result.confirmed.length > 0) {
            console.log(`witness: Bitcoin-attested epoch(s) ${result.confirmed.join(', ')}`);
          }
        },
        (error) =>
          console.error(`witness: upgrade run failed: ${error instanceof Error ? error.message : String(error)}`)
      );
    }, UPGRADE_INTERVAL_MS);
    console.log(`  upgrading pending OpenTimestamps receipts every ${UPGRADE_INTERVAL_MS / 60_000} min`);
  }

  await new Promise<void>((resolve) => {
    for (const signal of ['SIGINT', 'SIGTERM'] as const) {
      process.on(signal, () => resolve());
    }
  });
  if (anchorTimer !== null) clearInterval(anchorTimer);
  if (upgradeTimer !== null) clearInterval(upgradeTimer);
  await witness.close();
  return 0;
}
