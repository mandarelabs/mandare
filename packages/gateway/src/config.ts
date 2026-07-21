/**
 * Gateway configuration from environment. The provider key comes from env in
 * S0 ONLY — S3 moves credentials into the vault (agents never see them, and
 * neither does the environment of anything agent-reachable).
 */
export interface GatewayConfig {
  host: string;
  port: number;
  ledgerDbPath: string;
  doorId: string;
  /** S0: static dev identity; real passports/mandates land in S3/S4. */
  actor: string;
  mandateId: string;
  openrouterBaseUrl: string;
  /** null = no credential → the spend path stays closed (rule R1). */
  openrouterApiKey: string | null;
}

const DEFAULT_PORT = 8484;

export function loadConfigFromEnv(env: Record<string, string | undefined>): GatewayConfig {
  const port = env.MANDARE_GATEWAY_PORT === undefined ? DEFAULT_PORT : Number(env.MANDARE_GATEWAY_PORT);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(`invalid MANDARE_GATEWAY_PORT: ${env.MANDARE_GATEWAY_PORT}`);
  }
  return {
    // Localhost by design: the gateway is a local door, not a public service.
    host: env.MANDARE_GATEWAY_HOST ?? '127.0.0.1',
    port,
    ledgerDbPath: env.MANDARE_LEDGER_DB ?? './mandare-ledger.db',
    doorId: env.MANDARE_DOOR_ID ?? 'gateway:local',
    actor: env.MANDARE_ACTOR ?? 'did:mandare:dev-agent',
    mandateId: env.MANDARE_MANDATE_ID ?? 'mnd_dev_unmandated',
    openrouterBaseUrl: (env.OPENROUTER_BASE_URL ?? 'https://openrouter.ai/api/v1').replace(/\/+$/, ''),
    openrouterApiKey: env.OPENROUTER_API_KEY ?? null,
  };
}
