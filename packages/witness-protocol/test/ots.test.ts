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

describe('attestation tag constants', () => {
  test('bitcoin tag matches the published attestation tag', () => {
    expect(bytesToHex(BITCOIN_ATTESTATION_TAG)).toBe('0588960d73d71901');
  });
});
