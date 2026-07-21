import {
  AsyncLedger,
  SqliteStore,
  doorKeyFromPem,
  generateDoorKeyPem,
  loadOrCreateDoorKey,
  type DoorKey,
} from '@mandarelabs/ledger';
import { Vault, loadVaultConfigFromEnv } from '@mandarelabs/vault';

/**
 * The door context shared by `mandare kill` / `reinstate`: the ledger the kill
 * is written to, and (in vault mode) the vault whose tokens are also revoked.
 * This is the LOCAL authority — no network, fail-closed, un-jammable.
 *
 * The door key MUST be the same one the gateway signs with, or the append is
 * rejected by the one-door-per-DB check. So we resolve it EXACTLY as the
 * gateway does: from the vault when `MANDARE_VAULT=1` (OS keychain), otherwise
 * from the legacy 0600 PEM next to the ledger. That makes kill operable in
 * whichever mode the gateway runs.
 */
export interface DoorContext {
  ledger: AsyncLedger;
  /** null in legacy mode: no vault, hence no scoped tokens to revoke. */
  vault: Vault | null;
  doorId: string;
  ledgerCurrency: string;
  killActor: string;
}

export interface DoorContextOptions {
  /** Overrides for env-derived defaults (CLI flags win). */
  dbPath?: string;
  doorId?: string;
}

export async function openDoorContext(
  env: Record<string, string | undefined>,
  options: DoorContextOptions = {}
): Promise<DoorContext> {
  const doorId = options.doorId ?? env.MANDARE_DOOR_ID ?? 'gateway:local';
  const dbPath = options.dbPath ?? env.MANDARE_LEDGER_DB ?? './mandare-ledger.db';
  const ledgerCurrency = env.MANDARE_LEDGER_CURRENCY ?? 'EUR';
  const killActor = env.MANDARE_KILL_ACTOR ?? 'mandare:operator';

  let vault: Vault | null = null;
  let doorKey: DoorKey;
  if (env.MANDARE_VAULT === '1') {
    // Vault mode: the door key lives in the vault (get-or-create). The gateway
    // reads the same key from the same vault.
    vault = Vault.open(loadVaultConfigFromEnv(env));
    let pem = vault.getDoorKeyPem(doorId);
    if (pem === null) {
      pem = generateDoorKeyPem();
      vault.putDoorKeyPem(doorId, pem);
    }
    doorKey = doorKeyFromPem(pem, vault.provenance);
  } else {
    // Legacy mode: the same 0600 PEM the legacy gateway uses. No vault ⇒ no
    // scoped tokens to revoke; the ledger revoke alone is the authority.
    doorKey = loadOrCreateDoorKey(`${dbPath}.doorkey.pem`);
  }

  const store = SqliteStore.open(dbPath);
  try {
    // AsyncLedger.open closes the store itself on a rejected open; we only
    // need to release the vault handle here.
    const ledger = await AsyncLedger.open(store, { doorId, doorKey });
    return { ledger, vault, doorId, ledgerCurrency, killActor };
  } catch (error) {
    vault?.close();
    throw error;
  }
}

export async function closeDoorContext(ctx: DoorContext): Promise<void> {
  await ctx.ledger.close();
  ctx.vault?.close();
}
