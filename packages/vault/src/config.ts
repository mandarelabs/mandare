import type { KeyProvenance } from '@mandarelabs/spec';

/**
 * Vault configuration. The backend decides WHERE the master key lives:
 *
 * - `keychain` (default, production): the master key is stored in the OS
 *   keychain via @napi-rs/keyring (BUILD-DECISIONS Q8). If the keychain is
 *   unavailable, the vault FAILS CLOSED — it never silently downgrades to a
 *   plaintext-on-disk key. `key_provenance` recorded as `keychain`.
 * - `file` (explicit, headless/CI): the master key lives in a 0600 file, the
 *   same trust model as the S0 door-key PEM. An operator must opt in
 *   deliberately (`MANDARE_VAULT_BACKEND=file`). `key_provenance` = `software`.
 *
 * The keychain backend is never a fallback of the file backend or vice versa:
 * a headless machine chooses `file` on purpose, and a machine that asked for
 * the keychain fails closed if it is missing.
 */
export type VaultBackend = 'keychain' | 'file';

export interface VaultConfig {
  backend: VaultBackend;
  /** SQLite file holding encrypted secrets + the token registry. */
  dbPath: string;
  /** Keychain service name (keychain backend). */
  service: string;
  /** Keychain account name for the master key (keychain backend). */
  account: string;
  /** 0600 master-key file (file backend). */
  masterKeyFile: string;
}

export const DEFAULT_VAULT_DB = './mandare-vault.db';
export const DEFAULT_VAULT_SERVICE = 'mandare-vault';
export const DEFAULT_VAULT_ACCOUNT = 'master-key';

export function provenanceFor(backend: VaultBackend): KeyProvenance {
  return backend === 'keychain' ? 'keychain' : 'software';
}

export function loadVaultConfigFromEnv(env: Record<string, string | undefined>): VaultConfig {
  const backendRaw = env.MANDARE_VAULT_BACKEND ?? 'keychain';
  if (backendRaw !== 'keychain' && backendRaw !== 'file') {
    throw new Error(
      `invalid MANDARE_VAULT_BACKEND: ${backendRaw} (expected 'keychain' or 'file')`
    );
  }
  const dbPath = env.MANDARE_VAULT_DB ?? DEFAULT_VAULT_DB;
  return {
    backend: backendRaw,
    dbPath,
    service: env.MANDARE_VAULT_SERVICE ?? DEFAULT_VAULT_SERVICE,
    account: env.MANDARE_VAULT_ACCOUNT ?? DEFAULT_VAULT_ACCOUNT,
    masterKeyFile: env.MANDARE_VAULT_KEY_FILE ?? `${dbPath}.masterkey`,
  };
}
