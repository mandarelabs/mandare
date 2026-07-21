import type { KeyProvenance } from '@mandarelabs/spec';

import { seal, open } from './crypto.js';
import type { VaultStore } from './store.js';

/**
 * Encrypted key/value credential store. Values are sealed under the master
 * key with the account name as AAD (see crypto.ts), so a raw DB file yields
 * nothing and ciphertexts cannot be swapped between slots.
 *
 * R2: callers hand in and receive plaintext ONLY in-process; nothing here is
 * logged, and the gateway injects returned values straight into outbound
 * provider headers — never toward anything agent-reachable.
 */
export class SecretStore {
  private readonly store: VaultStore;
  private readonly masterKey: Buffer;
  private readonly provenance: KeyProvenance;
  private readonly clock: () => Date;

  constructor(
    store: VaultStore,
    masterKey: Buffer,
    provenance: KeyProvenance,
    clock: () => Date = () => new Date()
  ) {
    this.store = store;
    this.masterKey = masterKey;
    this.provenance = provenance;
    this.clock = clock;
  }

  set(account: string, value: string): void {
    this.store.putSecret(
      account,
      seal(this.masterKey, account, value),
      this.provenance,
      this.clock().toISOString()
    );
  }

  get(account: string): string | null {
    const row = this.store.getSecret(account);
    if (row === null) {
      return null;
    }
    return open(this.masterKey, account, row.ciphertext);
  }

  provenanceOf(account: string): KeyProvenance | null {
    return this.store.getSecret(account)?.provenance ?? null;
  }

  has(account: string): boolean {
    return this.store.getSecret(account) !== null;
  }

  delete(account: string): boolean {
    return this.store.deleteSecret(account);
  }

  list(): string[] {
    return this.store.listAccounts();
  }
}
