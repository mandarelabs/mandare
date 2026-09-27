import { readFileSync } from 'node:fs';

import { describe, expect, test } from 'vitest';

import { bytesToHex, hexToBytes } from '@mandarelabs/spec';

import {
  BITCOIN_ATTESTATION_TAG,
  OTS_HEADER_MAGIC,
  OtsError,
  applyOp,
  collectBitcoin,
  collectPending,
  parseCalendarTimestamp,
  parseOtsProof,
  serializeOtsProof,
  type OtsProof,
  type OtsTimestamp,
} from '../src/ots.js';
import { MockAnchor, OpenTimestampsAnchor, BaseAnchor } from '../src/anchor.js';
import { base64UrlToBytes } from '@mandarelabs/spec';
import { hexlifyBombProof, hexlifyCalendarBody } from './helpers.js';

const DIGEST = hexToBytes('11'.repeat(32));

function pendingProof(uri = 'https://calendar.example'): OtsProof {
  return {
    digest: DIGEST,
    timestamp: {
      msg: DIGEST,
      attestations: [],
      ops: [
        {
          op: { op: 'append', operand: hexToBytes('deadbeef') },
          stamp: {
            msg: new Uint8Array(0), // recomputed on parse
            attestations: [{ kind: 'pending', uri }],
            ops: [],
          },
        },
      ],
    },
  };
}

describe('OTS detached proof format', () => {
  test('serialize → parse round trip (pending attestation)', async () => {
    const bytes = serializeOtsProof(pendingProof());
    expect(bytes.slice(0, OTS_HEADER_MAGIC.length)).toEqual(OTS_HEADER_MAGIC);
    const parsed = await parseOtsProof(bytes);
    expect(bytesToHex(parsed.digest)).toBe(bytesToHex(DIGEST));
    const pending = collectPending(parsed.timestamp);
    expect(pending).toHaveLength(1);
    expect(pending[0]?.uri).toBe('https://calendar.example');
    // The commitment message is digest||deadbeef (append op applied).
    expect(bytesToHex(pending[0]!.commitment)).toBe(`${bytesToHex(DIGEST)}deadbeef`);
  });

  test('serialize → parse round trip (bitcoin attestation + sha256 op)', async () => {
    const proof: OtsProof = {
      digest: DIGEST,
      timestamp: {
        msg: DIGEST,
        attestations: [],
        ops: [
          {
            op: { op: 'sha256' },
            stamp: { msg: new Uint8Array(0), attestations: [{ kind: 'bitcoin', height: 900123 }], ops: [] },
          },
        ],
      },
    };
    const parsed = await parseOtsProof(serializeOtsProof(proof));
    expect(collectBitcoin(parsed.timestamp)).toEqual([{ height: 900123 }]);
    // The op result must be the actual sha256 of the digest bytes.
    const expected = await applyOp({ op: 'sha256' }, DIGEST);
    expect(bytesToHex(parsed.timestamp.ops[0]!.stamp.msg)).toBe(bytesToHex(expected));
  });

  test('multi-branch fork round trip', async () => {
    const branch = (operand: string, uri: string) => ({
      op: { op: 'prepend', operand: hexToBytes(operand) } as const,
      stamp: { msg: new Uint8Array(0), attestations: [{ kind: 'pending' as const, uri }], ops: [] },
    });
    const proof: OtsProof = {
      digest: DIGEST,
      timestamp: {
        msg: DIGEST,
        attestations: [],
        ops: [branch('aa', 'https://a.example'), branch('bb', 'https://b.example')],
      },
    };
    const parsed = await parseOtsProof(serializeOtsProof(proof));
    expect(collectPending(parsed.timestamp).map((p) => p.uri).sort()).toEqual([
      'https://a.example',
      'https://b.example',
    ]);
  });

  test('bad magic refused', async () => {
    const bytes = serializeOtsProof(pendingProof());
    bytes[0] = 0x01;
    await expect(parseOtsProof(bytes)).rejects.toThrow(OtsError);
  });

  test('truncated input refused', async () => {
    const bytes = serializeOtsProof(pendingProof());
    await expect(parseOtsProof(bytes.slice(0, bytes.length - 3))).rejects.toThrow(OtsError);
  });

  test('trailing garbage refused', async () => {
    const bytes = serializeOtsProof(pendingProof());
    const padded = new Uint8Array([...bytes, 0x00]);
    await expect(parseOtsProof(padded)).rejects.toThrow(/trailing/);
  });

  test('oversized varbytes refused (parse bound, R4)', async () => {
    // Hand-build: magic + version + sha256 tag + digest + append op with a
    // huge declared length.
    const bytes = [
      ...OTS_HEADER_MAGIC,
      0x01,
      0x08,
      ...DIGEST,
      0xf0, // append
      0xff, 0xff, 0x7f, // varuint 2097151 > MAX_VARBYTES
    ];
    await expect(parseOtsProof(Uint8Array.from(bytes))).rejects.toThrow(/exceeds bound/);
  });

  test('unknown attestation round-trips its full payload (M3)', async () => {
    // A litecoin/ethereum-style tag with an opaque payload must survive
    // parse → serialize unchanged, or the .ots stops verifying elsewhere.
    const unknownTag = 'ab'.repeat(8);
    const payloadHex = 'cafebabe1234';
    const proof: OtsProof = {
      digest: DIGEST,
      timestamp: {
        msg: DIGEST,
        attestations: [{ kind: 'unknown', tag: unknownTag, payload: payloadHex }],
        ops: [],
      },
    };
    const roundTripped = await parseOtsProof(serializeOtsProof(proof));
    const attestation = roundTripped.timestamp.attestations[0];
    expect(attestation?.kind).toBe('unknown');
    if (attestation?.kind === 'unknown') {
      expect(attestation.tag).toBe(unknownTag);
      expect(attestation.payload).toBe(payloadHex);
    }
    // And the serialized bytes are stable across a second round trip.
    const again = serializeOtsProof(roundTripped);
    expect(bytesToHex(again)).toBe(bytesToHex(serializeOtsProof(proof)));
  });

  test('calendar response parses against the submitted digest', async () => {
    // A calendar answers with ops only (no file header). Simulate: prepend
    // nonce then pending attestation.
    const inner: OtsTimestamp = {
      msg: new Uint8Array(0),
      attestations: [{ kind: 'pending', uri: 'https://cal.example' }],
      ops: [],
    };
    const wire: OtsProof['timestamp'] = {
      msg: DIGEST,
      attestations: [],
      ops: [{ op: { op: 'prepend', operand: hexToBytes('0102') }, stamp: inner }],
    };
    // Reuse the file serializer's timestamp section by serializing a full
    // proof and stripping header+version+tag+digest.
    const full = serializeOtsProof({ digest: DIGEST, timestamp: wire });
    const body = full.slice(OTS_HEADER_MAGIC.length + 1 + 1 + 32);
    const parsed = await parseCalendarTimestamp(body, DIGEST);
    const pending = collectPending(parsed);
    expect(pending).toHaveLength(1);
    expect(bytesToHex(pending[0]!.commitment)).toBe(`0102${bytesToHex(DIGEST)}`);
  });
});

describe('W-2: op results are length-bounded (hexlify bomb)', () => {
  // python-opentimestamps bounds every op: message and result <= 4096 bytes,
  // hexlify input <= 2048. Without the bound a ~100-byte receipt doubles its
  // message per hexlify op until the verifier (or the witness) dies of OOM.
  test('a modest hexlify chain past the 4096-byte result bound is refused (N=8 → 8 KiB)', async () => {
    await expect(parseOtsProof(hexlifyBombProof(8))).rejects.toBeInstanceOf(OtsError);
  });

  test('the N=40 bomb returns a typed parse error in < 100 ms', async () => {
    const started = performance.now();
    await expect(parseOtsProof(hexlifyBombProof(40))).rejects.toThrow(/exceeds|too long/i);
    expect(performance.now() - started).toBeLessThan(100);
  });

  test('ops inside the bound still apply (N=6: 32 B → 2 KiB)', async () => {
    const parsed = await parseOtsProof(hexlifyBombProof(6));
    expect(collectPending(parsed.timestamp)[0]?.commitment.length).toBe(32 * 2 ** 6);
  });

  test('append past the result bound is refused', async () => {
    await expect(
      applyOp({ op: 'append', operand: new Uint8Array(4096) }, new Uint8Array(32))
    ).rejects.toBeInstanceOf(OtsError);
  });

  test('a message over the bound is refused before any op runs', async () => {
    await expect(applyOp({ op: 'sha256' }, new Uint8Array(4097))).rejects.toBeInstanceOf(OtsError);
  });

  test('a calendar answering with the bomb is refused, not applied', async () => {
    await expect(parseCalendarTimestamp(hexlifyCalendarBody(40), DIGEST)).rejects.toBeInstanceOf(OtsError);
  });
});

describe('anchor adapters', () => {
  test('MockAnchor: instant confirmed receipt, digest-bound', async () => {
    const anchor = new MockAnchor();
    const receipt = await anchor.anchor('ab'.repeat(32));
    expect(receipt.status).toBe('confirmed');
    expect(receipt.digest).toBe('ab'.repeat(32));
    expect(receipt.detail).toMatch(/NOT publicly anchored/);
    expect(await anchor.upgrade(receipt)).toEqual(receipt);
  });

  test('MockAnchor refuses a malformed digest', async () => {
    await expect(new MockAnchor().anchor('xyz')).rejects.toThrow(/64 lowercase hex/);
  });

  test('BaseAnchor is a declared stub that refuses', async () => {
    await expect(new BaseAnchor().anchor()).rejects.toThrow(/future adapter/);
  });

  test('OpenTimestampsAnchor: stamps via calendars, emits a parseable pending .ots', async () => {
    const digestHex = 'cd'.repeat(32);
    const digest = hexToBytes(digestHex);
    // Fake calendar: answer with prepend(nonce) → pending attestation.
    const calendarBody = (() => {
      const stamp: OtsProof['timestamp'] = {
        msg: digest,
        attestations: [],
        ops: [
          {
            op: { op: 'prepend', operand: hexToBytes('aabb') },
            stamp: {
              msg: new Uint8Array(0),
              attestations: [{ kind: 'pending', uri: 'https://cal.test' }],
              ops: [],
            },
          },
        ],
      };
      const full = serializeOtsProof({ digest, timestamp: stamp });
      return full.slice(OTS_HEADER_MAGIC.length + 1 + 1 + 32);
    })();
    const fetchImpl = (async (url: Parameters<typeof fetch>[0]) => {
      expect(String(url)).toBe('https://cal.test/digest');
      return new Response(calendarBody, { status: 200 });
    }) as typeof fetch;
    const anchor = new OpenTimestampsAnchor({ calendars: ['https://cal.test'], fetchImpl });
    const receipt = await anchor.anchor(digestHex);
    expect(receipt.status).toBe('pending');
    const proof = await parseOtsProof(base64UrlToBytes(receipt.proof));
    expect(bytesToHex(proof.digest)).toBe(digestHex);
    expect(collectPending(proof.timestamp)).toHaveLength(1);
  });

  test('OpenTimestampsAnchor: fails when no calendar accepts (fail-closed)', async () => {
    const fetchImpl = (async () => new Response('down', { status: 503 })) as typeof fetch;
    const anchor = new OpenTimestampsAnchor({ calendars: ['https://cal.test'], fetchImpl });
    await expect(anchor.anchor('ee'.repeat(32))).rejects.toThrow(/0\/1 calendars/);
  });

  test('OpenTimestampsAnchor: upgrade merges a bitcoin attestation → confirmed', async () => {
    const digestHex = 'ef'.repeat(32);
    const digest = hexToBytes(digestHex);
    const mkBody = (stamp: OtsProof['timestamp']) =>
      serializeOtsProof({ digest, timestamp: stamp }).slice(OTS_HEADER_MAGIC.length + 1 + 1 + 32);
    const pendingBody = mkBody({
      msg: digest,
      attestations: [{ kind: 'pending', uri: 'https://cal.test' }],
      ops: [],
    });
    // The upgrade answer for commitment == digest: a bitcoin attestation.
    const upgradeStamp: OtsProof['timestamp'] = {
      msg: digest,
      attestations: [],
      ops: [
        {
          op: { op: 'sha256' },
          stamp: { msg: new Uint8Array(0), attestations: [{ kind: 'bitcoin', height: 812345 }], ops: [] },
        },
      ],
    };
    const upgradeBody = mkBody(upgradeStamp);
    const fetchImpl = (async (url: Parameters<typeof fetch>[0]) => {
      const u = String(url);
      if (u.endsWith('/digest')) return new Response(pendingBody, { status: 200 });
      expect(u).toBe(`https://cal.test/timestamp/${digestHex}`);
      return new Response(upgradeBody, { status: 200 });
    }) as typeof fetch;
    const anchor = new OpenTimestampsAnchor({ calendars: ['https://cal.test'], fetchImpl });
    const receipt = await anchor.anchor(digestHex);
    const upgraded = await anchor.upgrade(receipt);
    expect(upgraded.status).toBe('confirmed');
    expect(upgraded.detail).toBe('bitcoin block 812345');
    // The upgraded proof still parses and carries the bitcoin attestation.
    const proof = await parseOtsProof(base64UrlToBytes(upgraded.proof));
    expect(collectBitcoin(proof.timestamp)).toEqual([{ height: 812345 }]);
  });

  test('upgrade returns the receipt unchanged while calendars still answer 404', async () => {
    const digestHex = '1f'.repeat(32);
    const digest = hexToBytes(digestHex);
    const pendingBody = serializeOtsProof({
      digest,
      timestamp: { msg: digest, attestations: [{ kind: 'pending', uri: 'https://cal.test' }], ops: [] },
    }).slice(OTS_HEADER_MAGIC.length + 1 + 1 + 32);
    const fetchImpl = (async (url: Parameters<typeof fetch>[0]) => {
      if (String(url).endsWith('/digest')) {
        return new Response(pendingBody, { status: 200 });
      }
      return new Response('not ready', { status: 404 });
    }) as typeof fetch;
    const anchor = new OpenTimestampsAnchor({ calendars: ['https://cal.test'], fetchImpl });
    const receipt = await anchor.anchor(digestHex);
    expect(await anchor.upgrade(receipt)).toEqual(receipt);
  });
});

interface RealReply {
  calendar: string;
  commitment: string;
  body_hex: string;
  bitcoin_heights: number[];
}
const REAL = JSON.parse(readFileSync(new URL('./fixtures/ots-real-upgrade.json', import.meta.url), 'utf8')) as {
  digest: string;
  receipt_base64url: string;
  replies: RealReply[];
};

/** Serve the recorded calendar replies; `override` maps a calendar to a status to force. */
function recordedCalendars(override: Record<string, number> = {}): typeof fetch {
  return ((url: Parameters<typeof fetch>[0]) => {
    const u = String(url);
    const reply = REAL.replies.find((r) => u === `${r.calendar}/timestamp/${r.commitment}`);
    const forced = reply === undefined ? undefined : override[reply.calendar];
    if (forced !== undefined) return Promise.resolve(new Response('calendar trouble', { status: forced }));
    return Promise.resolve(
      reply === undefined ? new Response('', { status: 404 }) : new Response(hexToBytes(reply.body_hex), { status: 200 })
    );
  }) as typeof fetch;
}

const REAL_RECEIPT = {
  kind: 'opentimestamps',
  digest: REAL.digest,
  status: 'pending' as const,
  created_at: '2026-09-26T11:40:01.819Z',
  proof: REAL.receipt_base64url,
  detail: null,
};

describe('real calendar proofs (captured from the F3 live smoke, 2026-09-27)', () => {
  // A real Bitcoin upgrade path is one long op chain — 70–75 levels for the
  // calendar reply alone. The S6 depth cap of 64 refused every real proof,
  // so receipts stayed `pending` forever against the live calendars.
  test('real Bitcoin-attested calendar replies (70–75 ops deep) parse', async () => {
    for (const reply of REAL.replies) {
      const stamp = await parseCalendarTimestamp(hexToBytes(reply.body_hex), hexToBytes(reply.commitment));
      expect(collectBitcoin(stamp).map((b) => b.height)).toEqual(reply.bitcoin_heights);
    }
  });

  test('upgrading the real pending receipt with the real replies confirms it (and it re-parses)', async () => {
    const anchor = new OpenTimestampsAnchor({ calendars: REAL.replies.map((r) => r.calendar), fetchImpl: recordedCalendars() });
    const upgraded = await anchor.upgrade(REAL_RECEIPT);
    expect(upgraded.status).toBe('confirmed');
    expect(upgraded.detail).toBe('bitcoin block 968682');
    const reparsed = await parseOtsProof(base64UrlToBytes(upgraded.proof));
    expect(bytesToHex(reparsed.digest)).toBe(REAL.digest);
    expect(collectBitcoin(reparsed.timestamp).map((b) => b.height).sort()).toEqual([968682, 968707]);
  });

  test('one failing calendar does not block another that already has the proof', async () => {
    const anchor = new OpenTimestampsAnchor({
      calendars: REAL.replies.map((r) => r.calendar),
      fetchImpl: recordedCalendars({ 'https://bob.btc.calendar.opentimestamps.org': 500 }),
    });
    const upgraded = await anchor.upgrade(REAL_RECEIPT);
    expect(upgraded.status).toBe('confirmed');
    expect(upgraded.detail).toBe('bitcoin block 968707');
  });

  test('no calendar upgraded and one failed → upgrade throws naming it (never a silent "pending")', async () => {
    const anchor = new OpenTimestampsAnchor({
      calendars: REAL.replies.map((r) => r.calendar),
      fetchImpl: recordedCalendars({
        'https://bob.btc.calendar.opentimestamps.org': 404,
        'https://finney.calendar.eternitywall.com': 502,
      }),
    });
    await expect(anchor.upgrade(REAL_RECEIPT)).rejects.toThrow(/finney\.calendar\.eternitywall\.com.*502/);
  });

  test('the depth bound still holds: a 300-op chain is refused', async () => {
    const pendingTag = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
    const uri = [...new TextEncoder().encode('https://cal.test')];
    const body = Uint8Array.from([...new Array<number>(300).fill(0x08), 0x00, ...pendingTag, uri.length + 1, uri.length, ...uri]);
    await expect(parseCalendarTimestamp(body, DIGEST)).rejects.toThrow(/too deep/);
  });
});

describe('attestation tag constants', () => {
  test('bitcoin tag matches the published attestation tag', () => {
    expect(bytesToHex(BITCOIN_ATTESTATION_TAG)).toBe('0588960d73d71901');
  });
});
