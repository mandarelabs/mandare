import { describe, expect, it } from 'vitest';

import { badgeFromVerifyJson, witnessVerdict, type VerifyJson } from '../src/lib/verify';

/**
 * S7 review C2 regression: the witness badge must come from the CLI's TYPED
 * consistency status. A forked/rewritten ledger ('inconsistent') or a
 * rollback may NEVER render green, and healthy states ('extended',
 * 'identical') may never render red. Fixtures mirror apps/cli/src/verify.ts
 * ConsistencyStatus exactly.
 */

const HEAD = { size: 10, root: 'a'.repeat(64) };

function report(witness: VerifyJson['witness']): VerifyJson {
  return {
    result: { ok: true, entries: 10 },
    tree: { size: 10, root: 'a'.repeat(64) },
    spend: { counters: { status: 'consistent' } },
    ...(witness === undefined ? {} : { witness }),
  };
}

describe('witnessVerdict', () => {
  it('extended and identical are the ONLY green states', () => {
    expect(witnessVerdict({ record: {}, consistency: { status: 'extended' } }).consistent).toBe(true);
    expect(witnessVerdict({ record: {}, consistency: { status: 'identical' } }).consistent).toBe(true);
  });

  it('a rewritten ledger (inconsistent) is RED — the C2 attack case', () => {
    const verdict = witnessVerdict({
      record: HEAD,
      consistency: { status: 'inconsistent', reason: 'same size but different root — history rewritten' },
    });
    expect(verdict.consistent).toBe(false);
    expect(verdict.detail).toContain('rewritten');
  });

  it('rollback is RED', () => {
    expect(
      witnessVerdict({ record: HEAD, consistency: { status: 'rollback', reason: 'shrunk' } }).consistent
    ).toBe(false);
  });

  it('no witnessed record is RED, not green-by-default', () => {
    expect(witnessVerdict({ record: null, consistency: null }).consistent).toBe(false);
    expect(witnessVerdict(undefined).consistent).toBe(false);
  });

  it('W-1: a source mismatch is RED even when the looked-up history is consistent', () => {
    const verdict = witnessVerdict({
      record: HEAD,
      consistency: { status: 'extended' },
      source_mismatch: 'the out-of-band door key is source 1234…',
    });
    expect(verdict.consistent).toBe(false);
    expect(verdict.detail).toContain('source mismatch');
  });

  it('unknown future statuses fail closed', () => {
    expect(witnessVerdict({ record: HEAD, consistency: { status: '???' } }).consistent).toBe(false);
  });
});

describe('badgeFromVerifyJson', () => {
  it('healthy witnessed report → all green', () => {
    const badge = badgeFromVerifyJson(report({ record: HEAD, consistency: { status: 'extended' } }), true, 'now');
    expect(badge.chainOk).toBe(true);
    expect(badge.countersConsistent).toBe(true);
    expect(badge.witness).toEqual({ configured: true, consistent: true, detail: 'extended' });
  });

  it('forked report → witness red even though the chain itself verifies', () => {
    const badge = badgeFromVerifyJson(
      report({ record: HEAD, consistency: { status: 'inconsistent', reason: 'history rewritten' } }),
      true,
      'now'
    );
    expect(badge.chainOk).toBe(true);
    expect(badge.witness.configured && badge.witness.consistent).toBe(false);
  });

  it('W-1: the badge says whether the door key was out-of-band or self-anchored', () => {
    const healthy = report({ record: HEAD, consistency: { status: 'extended' } });
    expect(badgeFromVerifyJson(healthy, true, 'now').anchor).toBe('self-anchored');
    expect(badgeFromVerifyJson(healthy, true, 'now', 'out-of-band').anchor).toBe('out-of-band');
  });

  it('unconfigured witness stays explicitly unconfigured', () => {
    const badge = badgeFromVerifyJson(report(undefined), false, 'now');
    expect(badge.witness).toEqual({ configured: false });
  });
});
