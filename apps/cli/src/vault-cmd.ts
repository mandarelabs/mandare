import { Vault, loadVaultConfigFromEnv } from '@mandarelabs/vault';

/**
 * `mandare vault import-env` — the one-time .env → vault bootstrap. Provider
 * keys move into the OS-keychain-backed vault; afterwards the operator removes
 * them from .env, so nothing agent-reachable (and no long-lived env) holds a
 * raw key (R2). `mandare vault list` shows which accounts are populated —
 * NEVER the secret values.
 */

export function runVaultImportEnv(env: Record<string, string | undefined>): number {
  const vault = Vault.open(loadVaultConfigFromEnv(env));
  try {
    const imported = vault.importFromEnv(env);
    if (imported.length === 0) {
      process.stdout.write(
        'no recognized provider keys found in the environment (ANTHROPIC_API_KEY, OPENAI_API_KEY, OPENROUTER_API_KEY, OPENROUTER_PROVISIONING_KEY)\n'
      );
      return 0;
    }
    process.stdout.write(`imported ${imported.length} credential(s) into the vault (provenance: ${vault.provenance}):\n`);
    for (const account of imported) {
      process.stdout.write(`  ${account}\n`);
    }
    process.stdout.write('\nNow REMOVE these keys from .env — the vault is their home (R2).\n');
    return 0;
  } finally {
    vault.close();
  }
}

export function runVaultList(env: Record<string, string | undefined>): number {
  const vault = Vault.open(loadVaultConfigFromEnv(env));
  try {
    const accounts = vault.listAccounts();
    process.stdout.write(`vault (provenance: ${vault.provenance}) holds ${accounts.length} secret(s):\n`);
    for (const account of accounts) {
      // Account names only — the values never leave the vault via this command.
      process.stdout.write(`  ${account}\n`);
    }
    return 0;
  } finally {
    vault.close();
  }
}
