import { type Static, Type } from '@sinclair/typebox';

import { CurrencyCode, IsoUtcTimestamp, SignatureBlock } from './signature.js';

/**
 * Mandate v1 — SPEC §5. The signed permission slip: what an agent may do,
 * spend, and where; valid until when. Signed by the owner key; transported
 * as SD-JWT VC (S4) — this schema is the payload contract.
 *
 * FROZEN CONTRACT: changes require a TASKS.md decision entry and a
 * schema_version bump (rule R6).
 */

/**
 * Spend rails. `gateway` (LLM) and `card` (Stripe Issuing) are IMPLEMENTED and
 * enforced end-to-end. `x402` and `credits` are RESERVED values in the frozen
 * contract (SPEC §7 roadmap): no door serves them yet, so a mandate that lists
 * them has no enforcing rail — the policy engine's rail selection matches only
 * the implemented rails. Kept in the union so adding those rails later needs no
 * schema_version bump (R6). Do not read the enum as a capability claim.
 */
export const SpendRail = Type.Union([
  Type.Literal('gateway'),
  Type.Literal('card'),
  Type.Literal('x402'),
  Type.Literal('credits'),
]);
export type SpendRail = Static<typeof SpendRail>;

export const CounterpartyMode = Type.Union([
  Type.Literal('allowlist'),
  Type.Literal('verified_only'),
  Type.Literal('any'),
]);
export type CounterpartyMode = Static<typeof CounterpartyMode>;

/** All *_max / *_cap amounts are integer micro-units (see CURRENCY_MICROS_PER_UNIT). */
const spendScopeCommon = {
  type: Type.Literal('spend'),
  currency: CurrencyCode,
  per_tx_max: Type.Integer({ minimum: 0 }),
  per_day_max: Type.Integer({ minimum: 0 }),
  per_task_max: Type.Integer({ minimum: 0 }),
  total_cap: Type.Integer({ minimum: 0 }),
  rails: Type.Array(SpendRail, { minItems: 1 }),
  categories: Type.Array(Type.String({ minLength: 1 })),
} as const;

/**
 * Discriminated on `counterparties`: allowlist mode REQUIRES a non-empty
 * `counterparty_allowlist`; the other modes forbid the field. Enforced in the
 * schema so "allowlist mode with no list" (an undefined, fail-open state) can
 * never reach the policy engine.
 */
export const SpendScope = Type.Union([
  Type.Object(
    {
      ...spendScopeCommon,
      counterparties: Type.Literal('allowlist'),
      counterparty_allowlist: Type.Array(Type.String({ minLength: 1 }), { minItems: 1 }),
    },
    { additionalProperties: false }
  ),
  Type.Object(
    {
      ...spendScopeCommon,
      counterparties: Type.Union([Type.Literal('verified_only'), Type.Literal('any')]),
    },
    { additionalProperties: false }
  ),
]);
export type SpendScope = Static<typeof SpendScope>;

export const ActionScope = Type.Object(
  {
    type: Type.Literal('action'),
    classes: Type.Array(Type.String({ minLength: 1 }), { minItems: 1 }),
  },
  { additionalProperties: false }
);
export type ActionScope = Static<typeof ActionScope>;

/** Discriminated on `type`; data{} and comms{} scopes join in a later version. */
export const MandateScope = Type.Union([SpendScope, ActionScope]);
export type MandateScope = Static<typeof MandateScope>;

export const ApprovalRule = Type.Object(
  {
    /** Threshold in integer micro-units of `currency`. */
    above: Type.Integer({ minimum: 0 }),
    currency: CurrencyCode,
    /** CIBA-style async human approval push — the only v1 method. */
    method: Type.Literal('push'),
  },
  { additionalProperties: false }
);
export type ApprovalRule = Static<typeof ApprovalRule>;

/** Optional B2B billing identity — dormant until merchant support (SPEC §5, R3 in SOLUTIONS-QA). */
export const BillingIdentity = Type.Object(
  {
    legal_name: Type.String({ minLength: 1 }),
    vat_id: Type.String({ minLength: 1 }),
    address: Type.String({ minLength: 1 }),
  },
  { additionalProperties: false }
);
export type BillingIdentity = Static<typeof BillingIdentity>;

export const MandateV1 = Type.Object(
  {
    schema_version: Type.Literal(1),
    id: Type.String({ minLength: 1 }),
    /** Owner DID (accountable human/org). DID method profile lands in S4. */
    principal: Type.String({ minLength: 1 }),
    /** Agent DID. */
    agent: Type.String({ minLength: 1 }),
    purpose: Type.String({ minLength: 1 }),
    scopes: Type.Array(MandateScope, { minItems: 1 }),
    approvals: Type.Object(
      { rules: Type.Array(ApprovalRule) },
      { additionalProperties: false }
    ),
    billing_identity: Type.Optional(BillingIdentity),
    valid_from: IsoUtcTimestamp,
    valid_until: IsoUtcTimestamp,
    /** Pointer into the status list used for revocation checks (S3/S4). */
    revocation_ref: Type.String({ minLength: 1 }),
    /** Owner-key signature over the canonical JSON of the mandate without `signature`. */
    signature: SignatureBlock,
  },
  { additionalProperties: false }
);
export type MandateV1 = Static<typeof MandateV1>;
