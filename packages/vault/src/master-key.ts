import { createRequire } from 'node:module';
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';

import type { KeyProvenance } from '@mandarelabs/spec';

import { generateMasterKey, MASTER_KEY_BYTES } from './crypto.js';
import { provenanceFor, type VaultConfig } from './config.js';

/**
 * Master-key resolution. The 32-byte key that encrypts the vault DB comes
 * from the OS keychain (production) or an explicit 0600 file (headless/CI).
 * Both paths are get-or-create: first run mints a key and persists it.
 */

/** The keychain is missing or refused access — the vault fails CLOSED (R1). */
export class VaultKeychainUnavailableError extends Error {
  constructor(operation: string, cause: unknown) {
    const detail = cause instanceof Error ? cause.message : String(cause);
    // No secret material can appear here — this is a keychain access failure,
    // not a value dump.
    super(
      `vault: OS keychain unavailable (${operation}: ${detail}) — refusing to run without secure key storage (fail-closed). ` +
        `On a headless host, set MANDARE_VAULT_BACKEND=file to use an explicit 0600 master-key file instead.`
    );
    this.name = 'VaultKeychainUnavailableError';
  }
}

/**
 * The keychain operations the vault needs, injectable so the fail-closed path
 * is testable on any machine (the real backing is @napi-rs/keyring).
 */
export interface KeychainClient {
  get(service: string, account: string): string | null;
  set(service: string, account: string, value: string): void;
}

/** The production keychain client, backed by the OS keychain via @napi-rs/keyring. */
export function napiKeychain(): KeychainClient {
  return {
    get(service, account) {
      // Lazy require keeps the native module off the load path for file-backend
      // (headless/CI) runs that never touch the keychain.
      const { Entry } = loadKeyring();
      return new Entry(service, account).getPassword();
    },
    set(service, account, value) {
      const { Entry } = loadKeyring();
      new Entry(service, account).setPassword(value);
    },
  };
}

interface KeyringModule {
  Entry: new (
    service: string,
    account: string
  ) => { getPassword(): string; setPassword(value: string): void };
}

const requireCjs = createRequire(import.meta.url);
let cachedKeyring: KeyringModule | null = null;
function loadKeyring(): KeyringModule {
  if (cachedKeyring === null) {
    // Lazy require: file-backend (headless/CI) runs never load the native
    // module, so a missing platform binary can only ever affect a machine
    // that actually asked for the keychain.
    cachedKeyring = requireCjs('@napi-rs/keyring') as KeyringModule;
  }
  return cachedKeyring;
}

const FILE_MODE_OWNER_ONLY = 0o600;

export interface ResolvedMasterKey {
  key: Buffer;
  provenance: KeyProvenance;
}

export function resolveMasterKey(
  config: VaultConfig,
  keychain: KeychainClient = napiKeychain()
): ResolvedMasterKey {
  const key = config.backend === 'keychain' ? fromKeychain(config, keychain) : fromFile(config);
  return { key, provenance: provenanceFor(config.backend) };
}

function fromKeychain(config: VaultConfig, keychain: KeychainClient): Buffer {
  // @napi-rs/keyring returns null for an absent item and throws only when the
  // keychain itself is unavailable — so a throw is UNAMBIGUOUSLY "fail closed",
  // and we never misread an access failure as "absent" and silently re-key.
  let existing: string | null;
  try {
    existing = keychain.get(config.service, config.account);
  } catch (error) {
    throw new VaultKeychainUnavailableError('read master key', error);
  }
  if (existing !== null) {
    return decodeMasterKey(existing);
  }
  const fresh = generateMasterKey();
  try {
    keychain.set(config.service, config.account, fresh.toString('base64'));
  } catch (error) {
    throw new VaultKeychainUnavailableError('store master key', error);
  }
  return fresh;
}

function fromFile(config: VaultConfig): Buffer {
  if (existsSync(config.masterKeyFile)) {
    assertOwnerOnly(config.masterKeyFile);
    return decodeMasterKey(readFileSync(config.masterKeyFile, 'utf8').trim());
  }
  const fresh = generateMasterKey();
  writeFileSync(config.masterKeyFile, fresh.toString('base64'), {
    mode: FILE_MODE_OWNER_ONLY,
    flag: 'wx',
  });
  return fresh;
}

/**
 * The file-backend master key decrypts EVERYTHING in the vault, so it must be
 * owner-only (0600) — the trust model the config promises. If permissions have
 * drifted to group/other access (a careless copy, restore, or umask), fail
 * closed rather than silently trusting a readable key (R1/R2). POSIX only;
 * Windows mode bits are not meaningful.
 */
function assertOwnerOnly(path: string): void {
  if (process.platform === 'win32') {
    return;
  }
  const mode = statSync(path).mode & 0o777;
  if ((mode & 0o077) !== 0) {
    throw new Error(
      `vault: master-key file ${path} has permissions ${mode.toString(8).padStart(3, '0')} — ` +
        'it must be owner-only (600). Fix with `chmod 600` and rotate it if it was exposed (fail-closed).'
    );
  }
}

function decodeMasterKey(encoded: string): Buffer {
  const key = Buffer.from(encoded, 'base64');
  if (key.length !== MASTER_KEY_BYTES) {
    throw new Error(
      `vault: stored master key is ${key.length} bytes, expected ${MASTER_KEY_BYTES} — refusing (fail-closed)`
    );
  }
  return key;
}
