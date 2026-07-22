import type { KeyProvenance } from '@mandarelabs/spec';

import { loadVaultConfigFromEnv, type VaultConfig } from './config.js';
import { resolveMasterKey, napiKeychain, type KeychainClient } from './master-key.js';
import { SecretStore } from './secrets.js';
import { VaultStore } from './store.js';
import {
  TokenService,
  type IssueTokenInput,
  type RequestClaims,
  type ScopedTokenGrant,
  type VerifyResult,
} from './tokens.js';

/**
 * The vault door: OS-keychain-backed credential storage plus short-lived
 * proof-of-possession scoped tokens. Holds every third-party credential and
 * the door signing key so nothing agent-reachable ever sees raw secrets
 * (SPEC §3.1). The gateway reads provider keys from here at call time; the
 * kill switch tells it to stop honoring an actor's tokens.
 */

export type ProviderName = 'anthropic' | 'openai' | 'openrouter' | 'stripe';

// Stable account keys into the encrypted store.
const PROVISIONING_ACCOUNT = 'provisioning:openrouter';
/** Stripe webhook signing secret (S5 card rail) — verification key, not an API key. */
const STRIPE_WEBHOOK_ACCOUNT = 'webhook:stripe';

export function providerAccount(name: ProviderName): string {
  return `provider:${name}`;
}

export function doorAccount(doorId: string): string {
  return `door:${doorId}`;
}

/** Provider keys the .env bootstrap import recognizes. */
const ENV_KEY_ACCOUNTS: { env: string; account: string }[] = [
  { env: 'ANTHROPIC_API_KEY', account: providerAccount('anthropic') },
  { env: 'OPENAI_API_KEY', account: providerAccount('openai') },
  { env: 'OPENROUTER_API_KEY', account: providerAccount('openrouter') },
  { env: 'STRIPE_SECRET_KEY', account: providerAccount('stripe') },
  { env: 'STRIPE_WEBHOOK_SECRET', account: STRIPE_WEBHOOK_ACCOUNT },
  { env: 'OPENROUTER_PROVISIONING_KEY', account: PROVISIONING_ACCOUNT },
];

export interface VaultDeps {
  keychain?: KeychainClient;
  clock?: () => Date;
}

export class Vault {
  readonly provenance: KeyProvenance;

  private readonly store: VaultStore;
  private readonly secrets: SecretStore;
  private readonly tokens: TokenService;

  private constructor(
    store: VaultStore,
    secrets: SecretStore,
    tokens: TokenService,
    provenance: KeyProvenance
  ) {
    this.store = store;
    this.secrets = secrets;
    this.tokens = tokens;
    this.provenance = provenance;
  }

  /**
   * Open (or first-time initialize) the vault. Fails CLOSED if the configured
   * key backend is unavailable (a keychain-backed vault never silently falls
   * back to a plaintext file — the caller must choose `file` on purpose).
   */
  static open(config: VaultConfig, deps: VaultDeps = {}): Vault {
    const clock = deps.clock ?? ((): Date => new Date());
    // Resolve the master key FIRST — if the keychain is missing this throws
    // before any DB handle is created, so nothing spins up half-open.
    const { key, provenance } = resolveMasterKey(config, deps.keychain ?? napiKeychain());
    const store = VaultStore.open(config.dbPath);
    const secrets = new SecretStore(store, key, provenance, clock);
    const tokens = new TokenService(store, key, clock);
    return new Vault(store, secrets, tokens, provenance);
  }

  static openFromEnv(env: Record<string, string | undefined>, deps: VaultDeps = {}): Vault {
    return Vault.open(loadVaultConfigFromEnv(env), deps);
  }

  // --- provider credentials -------------------------------------------------

  getProviderKey(name: ProviderName): string | null {
    return this.secrets.get(providerAccount(name));
  }

  putProviderKey(name: ProviderName, value: string): void {
    this.secrets.set(providerAccount(name), value);
  }

  getProvisioningKey(): string | null {
    return this.secrets.get(PROVISIONING_ACCOUNT);
  }

  putProvisioningKey(value: string): void {
    this.secrets.set(PROVISIONING_ACCOUNT, value);
  }

  getStripeWebhookSecret(): string | null {
    return this.secrets.get(STRIPE_WEBHOOK_ACCOUNT);
  }

  putStripeWebhookSecret(value: string): void {
    this.secrets.set(STRIPE_WEBHOOK_ACCOUNT, value);
  }

  // --- door signing key -----------------------------------------------------

  getDoorKeyPem(doorId: string): string | null {
    return this.secrets.get(doorAccount(doorId));
  }

  putDoorKeyPem(doorId: string, pem: string): void {
    this.secrets.set(doorAccount(doorId), pem);
  }

  // --- identity keys (S4 passports) ------------------------------------------

  /**
   * Identity key pairs (owner / local attestation authority) live in the same
   * encrypted store, as JWK-pair JSON under `identity:*` accounts.
   */
  getIdentityKey(account: string): string | null {
    return this.secrets.get(account);
  }

  putIdentityKey(account: string, jwkPairJson: string): void {
    this.secrets.set(account, jwkPairJson);
  }

  // --- scoped tokens --------------------------------------------------------

  issueToken(input: IssueTokenInput): ScopedTokenGrant {
    return this.tokens.issue(input);
  }

  verifyRequest(claims: RequestClaims): VerifyResult {
    return this.tokens.verify(claims);
  }

  /** Kill assist: stop honoring one actor's tokens (the ledger is the authority). */
  revokeActorTokens(actor: string): number {
    return this.tokens.revokeActor(actor);
  }

  /** kill --all: stop honoring every token; the vault is halted. */
  revokeAllTokens(): number {
    return this.tokens.revokeAll();
  }

  /**
   * Persistent single-use nonce claim for RFC 9421 request signatures (S4).
   * Shares the vault's nonce table so a door RESTART cannot reopen a
   * signature-replay window (an in-memory store would forget claims).
   */
  claimSignatureNonce(key: string, expiresAtIso: string): boolean {
    return this.store.claimNonce(key, expiresAtIso);
  }

  prune(): void {
    this.tokens.prune();
  }

  // --- bootstrap ------------------------------------------------------------

  /**
   * One-time .env → vault migration. Provider keys demote to a bootstrap
   * import; after this the operator removes them from .env (R2). Returns the
   * accounts populated. Existing secrets are overwritten (idempotent re-run).
   */
  importFromEnv(env: Record<string, string | undefined>): string[] {
    const imported: string[] = [];
    for (const { env: name, account } of ENV_KEY_ACCOUNTS) {
      const value = env[name];
      if (value !== undefined && value !== '') {
        this.secrets.set(account, value);
        imported.push(account);
      }
    }
    return imported;
  }

  listAccounts(): string[] {
    return this.secrets.list();
  }

  close(): void {
    this.store.close();
  }
}
