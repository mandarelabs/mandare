/**
 * @mandarelabs/sdk — point your existing LLM SDK at an accountable door.
 *
 * The core surface is ONE function: `createMandareFetch` returns a
 * fetch-compatible function that authenticates every request for a Mandare
 * gateway (token PoP or passport RFC 9421 + Content-Digest). Hand it to the
 * official Anthropic/OpenAI SDK as the `fetch` option and keep the rest of
 * your code unchanged. `MandareGateway` adds thin typed helpers on top.
 */
export {
  createMandareFetch,
  type FetchLike,
  type MandareAuth,
  type MandareFetchOptions,
  type PassportIdentity,
} from './fetch.js';
export {
  MandareGateway,
  MandareRefusedError,
  parseRefusal,
  type GatewayHealth,
  type MandareGatewayOptions,
  type MandareRefusal,
} from './client.js';
export {
  NONCE_HEADER,
  POP_HEADER,
  TIMESTAMP_HEADER,
  TOKEN_HEADER,
  popPreimage,
  popProof,
  tokenAuthHeaders,
  type PopClaims,
  type TokenAuthInput,
  type TokenCredentials,
} from './pop.js';
export { loadPassportIdentity, tokenCredentialsFromIssueJson } from './identity.js';
