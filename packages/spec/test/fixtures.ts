import type { LedgerEntryPreimage, LedgerEntryV1 } from '../src/ledger-entry.js';
import { LLM_CALL_INTENT } from '../src/ledger-entry.js';
import type { MandateV1 } from '../src/mandate.js';
import type { SignatureBlock } from '../src/signature.js';
import { GENESIS_PREV_HASH } from '../src/hash.js';
import { computeEntryHash } from '../src/hash-node.js';

export const FAKE_SIGNATURE: SignatureBlock = {
  alg: 'EdDSA',
  key_id: 'a'.repeat(64),
  key_provenance: 'software',
  value: 'dGVzdC1zaWduYXR1cmU',
};

export function validMandate(overrides: Partial<MandateV1> = {}): MandateV1 {
  return {
    schema_version: 1,
    id: 'mnd_01J0000000000000000000000',
    principal: 'did:example:owner',
    agent: 'did:example:agent',
    purpose: 'Research assistant: LLM calls only',
    scopes: [
      {
        type: 'spend',
        currency: 'EUR',
        per_tx_max: 500_000, // €0.50 in micros
        per_day_max: 20_000_000, // €20.00
        per_task_max: 5_000_000,
        total_cap: 100_000_000,
        rails: ['gateway'],
        counterparties: 'any',
        categories: ['llm'],
      },
      { type: 'action', classes: ['llm.call'] },
    ],
    approvals: { rules: [{ above: 10_000_000, currency: 'EUR', method: 'push' }] },
    valid_from: '2026-07-21T00:00:00Z',
    valid_until: '2026-10-21T00:00:00Z',
    revocation_ref: 'statuslist:0#42',
    signature: FAKE_SIGNATURE,
    ...overrides,
  };
}

export function validEntryPreimage(
  overrides: Partial<LedgerEntryPreimage> = {}
): LedgerEntryPreimage {
  return {
    schema_version: 1,
    seq: 1,
    ts: '2026-07-21T12:00:00.000Z',
    door_id: 'gateway:test',
    actor: 'did:example:agent',
    mandate_id: 'mnd_01J0000000000000000000000',
    action: {
      type: LLM_CALL_INTENT,
      target: 'openrouter.ai',
      request_hash: 'b'.repeat(64),
    },
    cost: { amount: 0, currency: 'USD', tokens_in: 0, tokens_out: 0 },
    salt: 'c'.repeat(32),
    prev_hash: GENESIS_PREV_HASH,
    ...overrides,
  };
}

export function validEntry(overrides: Partial<LedgerEntryPreimage> = {}): LedgerEntryV1 {
  const preimage = validEntryPreimage(overrides);
  return {
    ...preimage,
    entry_hash: computeEntryHash(preimage),
    door_signature: FAKE_SIGNATURE,
  };
}
