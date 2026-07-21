import type { TSchema, Static } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';

import { LedgerEntryV1 } from './ledger-entry.js';
import { MandateV1 } from './mandate.js';

/** Boundary validation helpers (rule R4: agent input is hostile — validate everything). */

export class SchemaValidationError extends Error {
  readonly errors: readonly string[];

  constructor(schemaName: string, errors: readonly string[]) {
    super(`${schemaName} validation failed: ${errors.join('; ')}`);
    this.name = 'SchemaValidationError';
    this.errors = errors;
  }
}

function parseAs<T extends TSchema>(schema: T, schemaName: string, value: unknown): Static<T> {
  if (Value.Check(schema, value)) {
    return value;
  }
  const errors = [...Value.Errors(schema, value)].map(
    (e) => `${e.path || '/'}: ${e.message}`
  );
  throw new SchemaValidationError(schemaName, errors);
}

export function parseLedgerEntry(value: unknown): LedgerEntryV1 {
  return parseAs(LedgerEntryV1, 'LedgerEntryV1', value);
}

export function parseMandate(value: unknown): MandateV1 {
  return parseAs(MandateV1, 'MandateV1', value);
}

export function isLedgerEntry(value: unknown): value is LedgerEntryV1 {
  return Value.Check(LedgerEntryV1, value);
}

export function isMandate(value: unknown): value is MandateV1 {
  return Value.Check(MandateV1, value);
}
