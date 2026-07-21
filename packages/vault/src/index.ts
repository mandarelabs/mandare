/**
 * @mandarelabs/vault — OS-keychain-backed credential storage, credential
 * injection, and short-lived proof-of-possession scoped tokens (AGPL-3.0-only).
 *
 * The vault is a door: it holds every third-party credential and the door
 * signing key so nothing agent-reachable ever sees a raw secret (SPEC §3.1,
 * rule R2). It also mints the scoped tokens agents present to the gateway,
 * and stops honoring them on kill.
 */

export { Vault, providerAccount, doorAccount } from './vault.js';
export type { ProviderName, VaultDeps } from './vault.js';
export {
  loadVaultConfigFromEnv,
  provenanceFor,
  DEFAULT_VAULT_DB,
  DEFAULT_VAULT_SERVICE,
  DEFAULT_VAULT_ACCOUNT,
} from './config.js';
export type { VaultBackend, VaultConfig } from './config.js';
export {
  resolveMasterKey,
  napiKeychain,
  VaultKeychainUnavailableError,
} from './master-key.js';
export type { KeychainClient, ResolvedMasterKey } from './master-key.js';
export { VaultStore } from './store.js';
export type { SecretRow, TokenRow } from './store.js';
export { SecretStore } from './secrets.js';
export {
  TokenService,
  popPreimage,
  MAX_TOKEN_TTL_SECONDS,
  DEFAULT_TOKEN_TTL_SECONDS,
  MAX_REQUEST_SKEW_SECONDS,
} from './tokens.js';
export type {
  IssueTokenInput,
  RequestClaims,
  ScopedTokenGrant,
  VerifiedRequest,
  VerifyResult,
  TokenRefusal,
  TokenRefusalCode,
} from './tokens.js';
export {
  buildStatusListPayload,
  parseRevocationRef,
  formatRevocationRef,
  AGENT_STATUS_LIST_ID,
  STATUS_VALID,
  STATUS_REVOKED,
} from './status-list.js';
export type { RevocationSlot, StatusListPayload, BuildStatusListInput } from './status-list.js';
export {
  seal,
  open,
  hmacSha256,
  constantTimeEqual,
  generatePopSecret,
  generateMasterKey,
  randomId,
  MASTER_KEY_BYTES,
} from './crypto.js';
