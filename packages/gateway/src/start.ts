import { AsyncLedger, SqliteStore, rebuildSpendProjection, verifySpendProjection } from '@mandarelabs/ledger';
import { MandatePolicyEngine } from '@mandarelabs/policy-engine';

import { loadConfigFromEnv, loadMandate } from './config.js';
import { loadPricingTable, DEFAULT_PRICING } from './pricing.js';
import { buildGateway } from './server.js';

/**
 * `node dist/start.js` — dev/smoke entrypoint. R2: this file must never
 * print credentials; config echo below is allowlisted field by field.
 */
const config = loadConfigFromEnv(process.env);
const store = SqliteStore.open(config.ledgerDbPath);
const ledger = await AsyncLedger.open(store, {
  doorId: config.doorId,
  keyPath: `${config.ledgerDbPath}.doorkey.pem`,
});

// Projection integrity gate (R1): PURE staleness (counters still match the
// ledger, only the seq lags) → rebuild from the ledger and say so. ANY value
// divergence → REFUSE to start, because silently rebuilding would erase the
// evidence of tampering — and the verdict diffs values even when the seq
// looks stale, so a rewound seq cannot disguise divergence as staleness.
const verdict = await verifySpendProjection(ledger);
if (!verdict.ok) {
  if (verdict.divergences.length > 0 && process.env.MANDARE_REBUILD_PROJECTION !== '1') {
    console.error(`mandare gateway: spend projection DIVERGES from the ledger: ${verdict.reason}`);
    console.error(
      'refusing to start (fail-closed). Investigate, then restart with MANDARE_REBUILD_PROJECTION=1 to rebuild from the ledger.'
    );
    process.exit(1);
  }
  console.error(`mandare gateway: rebuilding spend projection (${verdict.reason})`);
  await rebuildSpendProjection(ledger);
}

const mandate = config.mandatePath === null ? null : loadMandate(config.mandatePath);
const policy =
  mandate === null
    ? // No mandate → no engine; the gateway keeps the spend path CLOSED and
      // this evaluate is never reached. Fail closed twice over.
      { evaluate: () => Promise.reject(new Error('no mandate configured')) }
    : new MandatePolicyEngine({
        mandate,
        velocity: { maxIntentsPerMinute: config.maxIntentsPerMinute },
      });

const pricingTable = config.pricingPath === null ? DEFAULT_PRICING : loadPricingTable(config.pricingPath);
const app = buildGateway({ config, ledger, policy, mandate, pricingTable });

const address = await app.listen({ host: config.host, port: config.port });
console.log(`mandare gateway listening on ${address}`);
console.log(`  door_id=${config.doorId} door_key_id=${ledger.doorKeyId.slice(0, 12)}…`);
console.log(`  ledger=${config.ledgerDbPath} currency=${config.ledgerCurrency}`);
console.log(
  `  mandate=${mandate === null ? 'ABSENT (spend path closed)' : mandate.id} ` +
    `providers: anthropic=${config.anthropic.apiKey === null ? 'absent' : 'present'} ` +
    `openai=${config.openai.apiKey === null ? 'absent' : 'present'} ` +
    `openrouter=${config.openrouter.apiKey === null ? 'absent' : 'present'}`
);

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    void app.close().then(async () => {
      await ledger.close();
      process.exit(0);
    });
  });
}
