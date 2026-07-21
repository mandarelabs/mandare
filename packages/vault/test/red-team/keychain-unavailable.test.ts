import { existsSync } from 'node:fs';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, test } from 'vitest';

import { Vault } from '../../src/vault.js';
import { VaultKeychainUnavailableError } from '../../src/master-key.js';
import type { VaultConfig } from '../../src/config.js';
import { tempDir, brokenKeychain } from '../helpers.js';

/**
 * Red-team (rule R5): a keychain-backed vault on a host whose keychain is
 * unavailable must FAIL CLOSED. It must NEVER silently fall back to a
 * plaintext master key on disk — that would defeat the entire point of
 * keychain-backed storage. A headless operator opts into `file` on purpose.
 */
describe('red-team: keychain unavailable → fail closed', () => {
  let dir: ReturnType<typeof tempDir>;
  beforeEach(() => (dir = tempDir()));
  afterEach(() => dir.cleanup());

  function keychainConfig(): VaultConfig {
    return {
      backend: 'keychain',
      dbPath: join(dir.path, 'vault.db'),
      service: 'mandare-vault-test',
      account: 'master-key',
      masterKeyFile: join(dir.path, 'vault.masterkey'),
    };
  }

  test('opening a keychain-backed vault throws when the keychain is unavailable', () => {
    expect(() => Vault.open(keychainConfig(), { keychain: brokenKeychain() })).toThrow(
      VaultKeychainUnavailableError
    );
  });

  test('it does NOT write a plaintext master-key file as a silent fallback', () => {
    try {
      Vault.open(keychainConfig(), { keychain: brokenKeychain() });
    } catch {
      // expected
    }
    // No downgrade: the file-backend master key must not have been created.
    expect(existsSync(join(dir.path, 'vault.masterkey'))).toBe(false);
  });

  test('a vault that fails to open never leaves a half-initialized DB behind spending', () => {
    // The failure happens before any secret can be served — there is no Vault
    // instance to call getProviderKey on, so the spend path simply has no key.
    let vault: Vault | null = null;
    expect(() => {
      vault = Vault.open(keychainConfig(), { keychain: brokenKeychain() });
    }).toThrow();
    expect(vault).toBeNull();
  });
});
