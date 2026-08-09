# @mandarelabs/sdk (Apache-2.0)

The developer-facing adoption path: a **signed fetch**. Agents keep their
existing Anthropic/OpenAI SDK and pass `createMandareFetch(...)` as its
`fetch` option; every request then carries what the door's auth mode
requires (S3 token PoP headers, or S4 RFC 9421 signature + Content-Digest
via `@mandarelabs/passport`).

Rules here:

- **Apache boundary:** may import `@mandarelabs/passport`/`spec` only —
  NEVER an AGPL package. The token PoP wire contract is re-stated in
  `src/pop.ts`; the byte-for-byte parity test against the vault's verify
  side lives in `packages/gateway/test/sdk-auth.test.ts` (AGPL side, where
  both may be imported).
- **WebCrypto only** in the portable core (`pop.ts`, `fetch.ts`); Node-only
  file helpers live in `identity.ts` behind lazy imports.
- **Fail closed on unsignable bodies:** streams/FormData/Blob cannot be
  digest-signed exactly, so passport mode refuses them before sending.
- The SDK adds NO policy. The door decides; the SDK makes calling it and
  reading refusals (`MandareRefusedError`) ergonomic.
