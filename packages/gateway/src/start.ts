import { Ledger } from '@mandarelabs/ledger';
import { UnconfiguredPolicyEngine } from '@mandarelabs/policy-engine';

import { loadConfigFromEnv } from './config.js';
import { buildGateway } from './server.js';

/**
 * `node dist/start.js` — dev/smoke entrypoint. R2: this file must never
 * print credentials; config echo below is allowlisted field by field.
 */
const config = loadConfigFromEnv(process.env);
const ledger = Ledger.open(config.ledgerDbPath, { doorId: config.doorId });
const app = buildGateway({ config, ledger, policy: new UnconfiguredPolicyEngine() });

const address = await app.listen({ host: config.host, port: config.port });
console.log(`mandare gateway listening on ${address}`);
console.log(`  door_id=${config.doorId} door_key_id=${ledger.doorKeyId.slice(0, 12)}…`);
console.log(`  ledger=${config.ledgerDbPath}`);
console.log(`  provider=${config.openrouterBaseUrl} credential=${config.openrouterApiKey === null ? 'ABSENT (spend path closed)' : 'present'}`);

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    void app.close().then(() => {
      ledger.close();
      process.exit(0);
    });
  });
}
