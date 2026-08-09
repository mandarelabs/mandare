/**
 * @mandarelabs/witness — the reference witness server (AGPL-3.0-only).
 *
 * Single-tenant, open, self-hostable. Speaks the protocol defined in
 * `@mandarelabs/witness-protocol` (Apache) — the commercial multi-tenant
 * witness service lives outside this repository and speaks the same wire.
 */

export { WitnessStore, epochSummary, type EpochRow } from './store.js';
export {
  buildWitnessServer,
  epochInclusionFor,
  type WitnessServer,
  type WitnessServerOptions,
} from './server.js';
