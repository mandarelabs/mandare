import {
  AsyncLedger,
  SqliteStore,
  doorKeyFromPem,
  generateDoorKeyPem,
  rebuildRevocationProjection,
  rebuildSpendProjection,
  verifyRevocationProjection,
  verifySpendProjection,
  type DoorKey,
} from '@mandarelabs/ledger';
import { MandatePolicyEngine } from '@mandarelabs/policy-engine';
import { Vault, loadVaultConfigFromEnv } from '@mandarelabs/vault';
import { WitnessClient } from '@mandarelabs/witness-protocol';

import type { NonceStore } from '@mandarelabs/passport';

import { loadConfigFromEnv, loadMandate, type GatewayConfig, type ProviderEndpoint } from './config.js';
import { loadPricingTable, DEFAULT_PRICING } from './pricing.js';
import { buildGateway } from './server.js';
import { FileNotifier, NtfyNotifier, type Notifier } from './approvals.js';
import type { GatewayVault } from './auth.js';

/**
 * `node dist/start.js` — dev/smoke entrypoint. R2: this file must never
 * print credentials; the config echo below is allowlisted field by field.
 *
 * S3: set MANDARE_VAULT=1 to source the door key AND provider keys from the
 * vault (OS keychain by default; MANDARE_VAULT_BACKEND=file for headless/CI)
 * and require proof-of-possession tokens on the spend routes. Without it the
 * S2 behavior stands — env-var keys, a 0600 door-key PEM, no token auth —
 * which keeps the frozen Demo 1 working unchanged.
 */
const baseConfig = loadConfigFromEnv(process.env);
const useVault = process.env.MANDARE_VAULT === '1';

const legacyKeyPath = `${baseConfig.ledgerDbPath}.doorkey.pem`;
let vault: Vault | null = null;
let gatewayVault: GatewayVault | undefined;
let doorKey: DoorKey | undefined;
let config: GatewayConfig = baseConfig;

if (useVault) {
  vault = Vault.open(loadVaultConfigFromEnv(process.env));
  gatewayVault = vault;
  // Door key lives in the vault now (OS keychain) — generate-and-store once.
  let pem = vault.getDoorKeyPem(config.doorId);
  if (pem === null) {
    pem = generateDoorKeyPem();
    vault.putDoorKeyPem(config.doorId, pem);
  }
  doorKey = doorKeyFromPem(pem, vault.provenance);
  // Provider credentials come from the vault; nothing agent-reachable holds a
  // raw key, and neither does this process's env for the spend path.
  config = { ...baseConfig, ...withVaultProviderKeys(baseConfig, vault) };
}

const store = SqliteStore.open(config.ledgerDbPath);
const ledger = await AsyncLedger.open(
  store,
  doorKey === undefined
    ? { doorId: config.doorId, keyPath: legacyKeyPath }
    : { doorId: config.doorId, doorKey }
);

// Projection integrity gate (R1): PURE staleness (counters still match the
// ledger, only the seq lags) → rebuild BOTH projections from the ledger and
// say so. ANY value divergence → REFUSE to start, because silently rebuilding
// would erase the evidence of tampering.
const spendVerdict = await verifySpendProjection(ledger);
if (!spendVerdict.ok) {
  if (spendVerdict.divergences.length > 0 && process.env.MANDARE_REBUILD_PROJECTION !== '1') {
    console.error(`mandare gateway: spend projection DIVERGES from the ledger: ${spendVerdict.reason}`);
    console.error(
      'refusing to start (fail-closed). Investigate, then restart with MANDARE_REBUILD_PROJECTION=1 to rebuild from the ledger.'
    );
    process.exit(1);
  }
  console.error(`mandare gateway: rebuilding projections (${spendVerdict.reason})`);
  await rebuildSpendProjection(ledger);
  await rebuildRevocationProjection(ledger);
}
// Revocation is also a ledger projection — a tampered kill state must be
// caught with the same fail-closed rule (a "reinstated" killed agent is a
// security event, not a convenience).
const revVerdict = await verifyRevocationProjection(ledger);
if (!revVerdict.ok) {
  if (process.env.MANDARE_REBUILD_PROJECTION !== '1') {
    console.error(`mandare gateway: revocation projection DIVERGES from the ledger: ${revVerdict.reason}`);
    console.error('refusing to start (fail-closed). Restart with MANDARE_REBUILD_PROJECTION=1 to rebuild.');
    process.exit(1);
  }
  await rebuildRevocationProjection(ledger);
}

const mandate = config.mandatePath === null ? null : await loadMandate(config.mandatePath);
const policy =
  mandate === null
    ? // No mandate → no engine; the gateway keeps the spend path CLOSED and
      // this evaluate is never reached. Fail closed twice over.
      { evaluate: () => Promise.reject(new Error('no mandate configured')) }
    : new MandatePolicyEngine({
        mandate,
        velocity: { maxIntentsPerMinute: config.maxIntentsPerMinute },
      });

// Approval push channel (S4, Q10/Q19): ntfy for real deployments, file for
// CI/demos, none = above-threshold calls are denied outright.
let notifier: Notifier | undefined;
if (config.notifier === 'ntfy') {
  if (config.ntfyTopic === null) {
    console.error('mandare gateway: MANDARE_NOTIFIER=ntfy requires MANDARE_NTFY_TOPIC (fail-closed).');
    process.exit(1);
  }
  // The push carries single-use approve/deny capability tokens. On the PUBLIC
  // ntfy.sh the topic name is the only secret — anyone subscribed to the topic
  // can approve a held call before the human sees it. Warn loudly; self-host or
  // use an access-token-protected topic for anything real (MEDIUM-3).
  if (config.ntfyUrl === 'https://ntfy.sh') {
    console.warn(
      'mandare gateway: WARNING — MANDARE_NOTIFIER=ntfy is using the PUBLIC ntfy.sh. Approval\n' +
        '  capability tokens transit a public server where the topic name is the only secret.\n' +
        '  Self-host ntfy (MANDARE_NTFY_URL) or protect the topic before relying on approvals.'
    );
  }
  notifier = new NtfyNotifier(config.ntfyUrl, config.ntfyTopic);
} else if (config.notifier === 'file') {
  if (config.notifyFilePath === null) {
    console.error('mandare gateway: MANDARE_NOTIFIER=file requires MANDARE_NOTIFY_FILE (fail-closed).');
    process.exit(1);
  }
  notifier = new FileNotifier(config.notifyFilePath);
}

// Passport mode needs a trust anchor, and uses the vault's persistent nonce
// table so a door restart cannot reopen a signature-replay window.
if (config.authMode === 'passport' && config.trustedAuthorityDid === null) {
  console.error(
    'mandare gateway: MANDARE_GATEWAY_AUTH=passport requires MANDARE_TRUST_AUTHORITY (the attestation authority DID) — refusing to start (fail-closed).'
  );
  process.exit(1);
}
const nonceStore: NonceStore | undefined =
  vault === null ? undefined : { claim: (key, expiresAt) => (vault as Vault).claimSignatureNonce(key, expiresAt) };
// Passport mode without a vault-backed nonce table falls back to an in-memory
// store: a door restart forgets claimed nonces, reopening a replay window up
// to the remaining signature validity (≤300s). Warn (L5).
if (config.authMode === 'passport' && nonceStore === undefined) {
  console.warn(
    'mandare gateway: WARNING — passport mode without a vault uses an in-memory nonce store; a\n' +
      '  restart reopens a signature-replay window (≤300s). Wire a vault (MANDARE_VAULT=1) for a\n' +
      '  persistent nonce table.'
  );
}

// Witnessing (S6, locks 4–5): stream salted chain-head fingerprints to the
// external witness and gate high-value actions on its verified ack. The
// witness key arrives OUT-OF-BAND via env; a dead witness degrades honestly
// (heads catch up on reconnect, high-value actions fail closed meanwhile).
let witnessClient: WitnessClient | undefined;
if (config.witness !== null) {
  witnessClient = new WitnessClient({
    url: config.witness.url,
    signer: ledger.signer(),
    readEntryHashes: () => ledger.readEntryHashes(),
    witnessPublicKeyHex: config.witness.publicKeyHex,
  });
  let lastWitnessWarnAt = 0;
  witnessClient.start(config.witness.streamIntervalMs, (error) => {
    const now = Date.now();
    if (now - lastWitnessWarnAt > 60_000) {
      lastWitnessWarnAt = now;
      console.warn(
        `mandare gateway: witness sync failing (${error instanceof Error ? error.message : String(error)}) — ` +
          'heads will catch up on reconnect; high-value actions fail closed meanwhile'
      );
    }
  });
}

const pricingTable = config.pricingPath === null ? DEFAULT_PRICING : loadPricingTable(config.pricingPath);
const app = buildGateway({
  config,
  ledger,
  policy,
  mandate,
  pricingTable,
  ...(gatewayVault === undefined ? {} : { vault: gatewayVault }),
  ...(notifier === undefined ? {} : { notifier }),
  ...(nonceStore === undefined ? {} : { nonceStore }),
  ...(witnessClient === undefined ? {} : { witness: witnessClient }),
});

const tokenAuth =
  config.authMode === 'token' ||
  config.authMode === 'passport' ||
  (config.authMode === 'auto' && useVault);
// The Host allowlist stops browser DNS-rebinding, not direct clients that set
// their own Host header. Binding off-loopback WITHOUT token auth leaves the
// spend routes reachable by any host on the network — refuse to do it quietly.
// The ONE sanctioned exception is an explicit, loud operator opt-out for
// container deployments where the network namespace is the boundary and the
// published port is loopback-scoped (compose.yaml sets it, with the
// justification next to it). Silence is never an option; this banner is.
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);
const allowInsecureBind = process.env.MANDARE_GATEWAY_ALLOW_INSECURE_BIND === '1';
if (!LOOPBACK_HOSTS.has(config.host.toLowerCase()) && !tokenAuth) {
  if (!allowInsecureBind) {
    console.error(
      `mandare gateway: refusing to bind non-loopback host '${config.host}' without token auth — ` +
        'set MANDARE_GATEWAY_AUTH=token (and use a vault), bind 127.0.0.1, or — ONLY when the ' +
        'network boundary lives elsewhere (container network + loopback-published ports) — set ' +
        'MANDARE_GATEWAY_ALLOW_INSECURE_BIND=1 (fail-closed).'
    );
    process.exit(1);
  }
  console.warn(
    `mandare gateway: WARNING — bound to non-loopback '${config.host}' WITHOUT request auth ` +
      '(MANDARE_GATEWAY_ALLOW_INSECURE_BIND=1). Anything that can reach this port can spend under ' +
      'the mandate. Acceptable ONLY behind a container/network boundary; never expose this port.'
  );
}

const address = await app.listen({ host: config.host, port: config.port });
console.log(`mandare gateway listening on ${address}`);
console.log(`  door_id=${config.doorId} door_key_id=${ledger.doorKeyId.slice(0, 12)}… key_provenance=${ledger.doorKeyProvenance}`);
console.log(`  ledger=${config.ledgerDbPath} currency=${config.ledgerCurrency}`);
console.log(
  `  vault=${useVault ? 'ON' : 'off'} token_auth=${tokenAuth ? 'REQUIRED' : 'off'} ` +
    `mandate=${mandate === null ? 'ABSENT (spend path closed)' : mandate.id}`
);
console.log(
  `  providers: anthropic=${config.anthropic.apiKey === null ? 'absent' : 'present'} ` +
    `openai=${config.openai.apiKey === null ? 'absent' : 'present'} ` +
    `openrouter=${config.openrouter.apiKey === null ? 'absent' : 'present'}`
);
const cardRailOffReason =
  useVault && baseConfig.stripe.webhookSecret !== null && config.stripe.webhookSecret === null
    ? 'off (vault mode ignores env STRIPE_* — run `mandare vault import-env` to move them into the vault)'
    : 'off (no webhook secret / no mandate)';
console.log(
  `  card rail: ${
    config.stripe.webhookSecret === null || mandate === null
      ? cardRailOffReason
      : `ON — webhook decisions live; card creation ${
          config.stripe.apiKey === null || config.stripe.cardholderId === null ? 'CLOSED (no API key / cardholder)' : 'open'
        }`
  }`
);
console.log(
  `  witness: ${
    config.witness === null
      ? 'off (heads stay local — truncation detectable only via a recorded --prev-head)'
      : `ON — streaming to ${config.witness.url} (ack mode: ${config.witness.ackMode})`
  }`
);

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    witnessClient?.stop();
    void app.close().then(async () => {
      await ledger.close();
      vault?.close();
      process.exit(0);
    });
  });
}

/** Resolve provider endpoints' keys from the vault (R2: keys never via env here). */
function withVaultProviderKeys(
  base: GatewayConfig,
  v: Vault
): Pick<GatewayConfig, 'anthropic' | 'openai' | 'openrouter' | 'stripe'> {
  const withKey = (endpoint: ProviderEndpoint, key: string | null): ProviderEndpoint => ({
    ...endpoint,
    apiKey: key,
  });
  return {
    anthropic: withKey(base.anthropic, v.getProviderKey('anthropic')),
    openai: withKey(base.openai, v.getProviderKey('openai')),
    openrouter: withKey(base.openrouter, v.getProviderKey('openrouter')),
    stripe: {
      ...base.stripe,
      apiKey: v.getProviderKey('stripe'),
      webhookSecret: v.getStripeWebhookSecret(),
    },
  };
}
