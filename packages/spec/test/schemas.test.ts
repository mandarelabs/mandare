import { describe, expect, test } from 'vitest';

import {
  SchemaValidationError,
  isLedgerEntry,
  parseLedgerEntry,
  parseMandate,
} from '../src/validate.js';
import { validEntry, validMandate } from './fixtures.js';

describe('MandateV1', () => {
  test('accepts a valid mandate', () => {
    expect(parseMandate(validMandate())).toMatchObject({ schema_version: 1 });
  });

  test('rejects missing signature', () => {
    const { signature: _dropped, ...rest } = validMandate();
    expect(() => parseMandate(rest)).toThrow(SchemaValidationError);
  });

  test('rejects negative spend caps (amounts are unsigned micros)', () => {
    const mandate = validMandate();
    const spend = mandate.scopes[0];
    if (spend?.type !== 'spend') throw new Error('fixture shape changed');
    expect(() => parseMandate({ ...mandate, scopes: [{ ...spend, per_tx_max: -1 }] })).toThrow(
      SchemaValidationError
    );
  });

  test('rejects non-ISO-4217-shaped currency and non-UTC timestamps', () => {
    expect(() => parseMandate(validMandate({ valid_from: '2026-07-21T00:00:00+02:00' }))).toThrow(
      SchemaValidationError
    );
    const mandate = validMandate();
    const spend = mandate.scopes[0];
    if (spend?.type !== 'spend') throw new Error('fixture shape changed');
    expect(() => parseMandate({ ...mandate, scopes: [{ ...spend, currency: 'eur' }] })).toThrow(
      SchemaValidationError
    );
  });

  test('rejects unknown extra properties (agent input is hostile, R4)', () => {
    expect(() => parseMandate({ ...validMandate(), injected: 'x' })).toThrow(SchemaValidationError);
  });

  test('rejects empty scopes', () => {
    expect(() => parseMandate(validMandate({ scopes: [] }))).toThrow(SchemaValidationError);
  });

  test('allowlist counterparty mode REQUIRES a non-empty allowlist; other modes forbid it', () => {
    const mandate = validMandate();
    const spend = mandate.scopes[0];
    if (spend?.type !== 'spend') throw new Error('fixture shape changed');

    // allowlist mode without a list (or with an empty one) must not validate.
    expect(() =>
      parseMandate({ ...mandate, scopes: [{ ...spend, counterparties: 'allowlist' }] })
    ).toThrow(SchemaValidationError);
    expect(() =>
      parseMandate({
        ...mandate,
        scopes: [{ ...spend, counterparties: 'allowlist', counterparty_allowlist: [] }],
      })
    ).toThrow(SchemaValidationError);

    // allowlist mode with a real list validates.
    expect(
      parseMandate({
        ...mandate,
        scopes: [
          { ...spend, counterparties: 'allowlist', counterparty_allowlist: ['api.acme.example'] },
        ],
      }).scopes
    ).toHaveLength(1);

    // 'any'/'verified_only' must not carry a dangling allowlist.
    expect(() =>
      parseMandate({
        ...mandate,
        scopes: [{ ...spend, counterparties: 'any', counterparty_allowlist: ['api.acme.example'] }],
      })
    ).toThrow(SchemaValidationError);
  });
});

describe('LedgerEntryV1', () => {
  test('accepts a valid intent entry (no response_hash yet)', () => {
    const entry = validEntry();
    expect(entry.action.response_hash).toBeUndefined();
    expect(parseLedgerEntry(entry)).toMatchObject({ seq: 1 });
  });

  test('accepts a result entry with response_hash and outcome_ref', () => {
    const intent = validEntry();
    const result = validEntry({
      seq: 2,
      prev_hash: intent.entry_hash,
      action: { ...intent.action, type: 'llm.call.result', response_hash: 'd'.repeat(64) },
      outcome_ref: intent.entry_hash,
    });
    expect(parseLedgerEntry(result).outcome_ref).toBe(intent.entry_hash);
  });

  test('rejects seq 0, malformed hashes, and uppercase hex', () => {
    expect(isLedgerEntry({ ...validEntry(), seq: 0 })).toBe(false);
    expect(isLedgerEntry({ ...validEntry(), entry_hash: 'xyz' })).toBe(false);
    expect(isLedgerEntry({ ...validEntry(), prev_hash: 'A'.repeat(64) })).toBe(false);
  });

  test('rejects fractional cost amounts (micros are integers)', () => {
    const entry = validEntry();
    expect(isLedgerEntry({ ...entry, cost: { ...entry.cost, amount: 0.5 } })).toBe(false);
  });

  test('rejects extra properties', () => {
    expect(isLedgerEntry({ ...validEntry(), sneaky: true })).toBe(false);
  });

  test('key_provenance is constrained to the R10 vocabulary', () => {
    const entry = validEntry();
    expect(
      isLedgerEntry({
        ...entry,
        door_signature: { ...entry.door_signature, key_provenance: 'hsm' },
      })
    ).toBe(false);
  });
});
