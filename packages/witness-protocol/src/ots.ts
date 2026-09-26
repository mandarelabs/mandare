import { bytesToHex, hexToBytes } from '@mandarelabs/spec';

/**
 * Minimal OpenTimestamps client — hand-rolled (deviation from Q6's letter,
 * same spirit; logged in TASKS.md S6). The npm `opentimestamps` 0.4.9 client
 * drags in deprecated `request`, `bitcore-lib`, `bytebuffer`, and the
 * placeholder package `fs` — exactly the dependency surface our supply-chain
 * posture (Q24) exists to refuse. The wire protocol underneath is small:
 * POST a 32-byte digest to a calendar, receive a serialized timestamp,
 * wrap it in the detached-proof file format. This module implements that
 * format faithfully so the emitted `.ots` bytes remain verifiable by ANY
 * standard OpenTimestamps client — the artifact is portable, only the
 * producer is ours.
 *
 * Format reference: the OpenTimestamps detached timestamp file layout as
 * implemented by python-opentimestamps (header magic, varuint/varbytes,
 * op tags, 8-byte attestation tags).
 */

export const OTS_HEADER_MAGIC = Uint8Array.from([
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
  0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
]);
const OTS_MAJOR_VERSION = 1;

const TAG_ATTESTATION = 0x00;
const TAG_FORK = 0xff;
const OP_SHA1 = 0x02;
const OP_RIPEMD160 = 0x03;
const OP_SHA256 = 0x08;
const OP_KECCAK256 = 0x67;
const OP_APPEND = 0xf0;
const OP_PREPEND = 0xf1;
const OP_REVERSE = 0xf2;
const OP_HEXLIFY = 0xf3;

export const PENDING_ATTESTATION_TAG = Uint8Array.from([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e]);
export const BITCOIN_ATTESTATION_TAG = Uint8Array.from([0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01]);

/** Parse bounds — calendar responses are external input (R4). */
const MAX_VARUINT = 2 ** 32;
const MAX_VARBYTES = 4096;
const MAX_DEPTH = 64;
const MAX_NODES = 4096;
/**
 * Op bounds, python-opentimestamps' `MAX_MSG_LENGTH` / `MAX_RESULT_LENGTH`
 * (W-2). Ops are applied while parsing, so without them a ~100-byte receipt
 * of chained `hexlify` ops (each doubles the message) allocates until the
 * process dies of OOM. 4096 bytes is far above any real calendar proof.
 */
const MAX_OP_MESSAGE = 4096;
const MAX_OP_RESULT = 4096;
/** A calendar response larger than this is refused unread (a real one is < 4 KiB). */
export const MAX_CALENDAR_RESPONSE_BYTES = 64 * 1024;

export class OtsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'OtsError';
  }
}

export type OtsAttestation =
  | { kind: 'pending'; uri: string }
  | { kind: 'bitcoin'; height: number }
  | { kind: 'unknown'; tag: string; payload: string };

export type OtsOp =
  | { op: 'sha256' }
  | { op: 'sha1' }
  | { op: 'ripemd160' }
  | { op: 'keccak256' }
  | { op: 'reverse' }
  | { op: 'hexlify' }
  | { op: 'append'; operand: Uint8Array }
  | { op: 'prepend'; operand: Uint8Array };

/** A timestamp tree node: proof branches from one message toward attestations. */
export interface OtsTimestamp {
  /** The message this node commits (the digest at the tree's root node). */
  msg: Uint8Array;
  attestations: OtsAttestation[];
  ops: { op: OtsOp; stamp: OtsTimestamp }[];
}

/** A parsed detached-proof file: sha256 digest + its timestamp tree. */
export interface OtsProof {
  digest: Uint8Array;
  timestamp: OtsTimestamp;
}

// --- byte plumbing -----------------------------------------------------------

class ByteWriter {
  private chunks: number[] = [];

  byte(value: number): void {
    this.chunks.push(value & 0xff);
  }

  bytes(value: Uint8Array): void {
    for (const b of value) this.chunks.push(b);
  }

  varuint(value: number): void {
    if (!Number.isInteger(value) || value < 0 || value >= MAX_VARUINT) {
      throw new OtsError(`varuint out of range: ${value}`);
    }
    if (value === 0) {
      this.byte(0);
      return;
    }
    let rest = value;
    while (rest > 0) {
      let b = rest & 0x7f;
      if (rest > 0x7f) b |= 0x80;
      this.byte(b);
      if (rest <= 0x7f) break;
      rest = Math.floor(rest / 128);
    }
  }

  varbytes(value: Uint8Array): void {
    this.varuint(value.length);
    this.bytes(value);
  }

  toBytes(): Uint8Array {
    return Uint8Array.from(this.chunks);
  }
}

class ByteReader {
  private offset = 0;

  constructor(private readonly data: Uint8Array) {}

  get exhausted(): boolean {
    return this.offset >= this.data.length;
  }

  byte(): number {
    if (this.offset >= this.data.length) throw new OtsError('unexpected end of input');
    const value = this.data[this.offset] as number;
    this.offset += 1;
    return value;
  }

  bytes(count: number): Uint8Array {
    if (this.offset + count > this.data.length) throw new OtsError('unexpected end of input');
    const slice = this.data.slice(this.offset, this.offset + count);
    this.offset += count;
    return slice;
  }

  varuint(): number {
    let value = 0;
    let shift = 1;
    for (;;) {
      const b = this.byte();
      value += (b & 0x7f) * shift;
      if (value >= MAX_VARUINT) throw new OtsError('varuint exceeds bound');
      if ((b & 0x80) === 0) return value;
      shift *= 128;
    }
  }

  varbytes(): Uint8Array {
    const length = this.varuint();
    if (length > MAX_VARBYTES) throw new OtsError(`varbytes length ${length} exceeds bound`);
    return this.bytes(length);
  }

  /** All remaining bytes (an unknown-attestation payload is opaque but must round-trip). */
  rest(): Uint8Array {
    return this.bytes(this.data.length - this.offset);
  }
}

// --- op application ----------------------------------------------------------

async function digestOf(algorithm: 'SHA-256' | 'SHA-1', data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await globalThis.crypto.subtle.digest(algorithm, data as Uint8Array<ArrayBuffer>));
}

/** Apply one proof op to a message (WebCrypto where possible; rare ops refused). */
export async function applyOp(op: OtsOp, msg: Uint8Array): Promise<Uint8Array> {
  if (msg.length > MAX_OP_MESSAGE) {
    throw new OtsError(`op message of ${msg.length} bytes exceeds the ${MAX_OP_MESSAGE}-byte bound`);
  }
  const resultLength = opResultLength(op, msg.length);
  if (resultLength !== null && (resultLength > MAX_OP_RESULT || resultLength === 0)) {
    throw new OtsError(
      `op '${op.op}' result of ${resultLength} bytes exceeds the ${MAX_OP_RESULT}-byte bound (or is empty)`
    );
  }
  return applyBoundedOp(op, msg);
}

/** Result length of the length-changing ops, known before running them; null for digests. */
function opResultLength(op: OtsOp, msgLength: number): number | null {
  switch (op.op) {
    case 'append':
    case 'prepend':
      return msgLength + op.operand.length;
    case 'hexlify':
      return msgLength * 2;
    case 'reverse':
      return msgLength;
    default:
      return null;
  }
}

async function applyBoundedOp(op: OtsOp, msg: Uint8Array): Promise<Uint8Array> {
  switch (op.op) {
    case 'sha256':
      return digestOf('SHA-256', msg);
    case 'sha1':
      return digestOf('SHA-1', msg);
    case 'append': {
      const out = new Uint8Array(msg.length + op.operand.length);
      out.set(msg, 0);
      out.set(op.operand, msg.length);
      return out;
    }
    case 'prepend': {
      const out = new Uint8Array(op.operand.length + msg.length);
      out.set(op.operand, 0);
      out.set(msg, op.operand.length);
      return out;
    }
    case 'reverse':
      return Uint8Array.from([...msg].reverse());
    case 'hexlify':
      return new TextEncoder().encode(bytesToHex(msg));
    case 'ripemd160':
    case 'keccak256':
      // Not needed by Bitcoin calendar proofs; refusing beats a wrong hash.
      throw new OtsError(`unsupported op '${op.op}' in proof`);
  }
}

// --- serialization -----------------------------------------------------------

function serializeOp(writer: ByteWriter, op: OtsOp): void {
  switch (op.op) {
    case 'sha1':
      writer.byte(OP_SHA1);
      return;
    case 'ripemd160':
      writer.byte(OP_RIPEMD160);
      return;
    case 'sha256':
      writer.byte(OP_SHA256);
      return;
    case 'keccak256':
      writer.byte(OP_KECCAK256);
      return;
    case 'reverse':
      writer.byte(OP_REVERSE);
      return;
    case 'hexlify':
      writer.byte(OP_HEXLIFY);
      return;
    case 'append':
      writer.byte(OP_APPEND);
      writer.varbytes(op.operand);
      return;
    case 'prepend':
      writer.byte(OP_PREPEND);
      writer.varbytes(op.operand);
      return;
  }
}

function serializeAttestation(writer: ByteWriter, attestation: OtsAttestation): void {
  const payload = new ByteWriter();
  if (attestation.kind === 'pending') {
    writer.bytes(PENDING_ATTESTATION_TAG);
    payload.varbytes(new TextEncoder().encode(attestation.uri));
  } else if (attestation.kind === 'bitcoin') {
    writer.bytes(BITCOIN_ATTESTATION_TAG);
    payload.varuint(attestation.height);
  } else {
    writer.bytes(hexToBytes(attestation.tag));
    payload.bytes(hexToBytes(attestation.payload));
  }
  writer.varbytes(payload.toBytes());
}

function serializeTimestamp(writer: ByteWriter, stamp: OtsTimestamp): void {
  if (stamp.attestations.length === 0 && stamp.ops.length === 0) {
    throw new OtsError('cannot serialize an empty timestamp node');
  }
  const branchTotal = stamp.attestations.length + stamp.ops.length;
  let emitted = 0;
  for (const attestation of stamp.attestations) {
    emitted += 1;
    if (emitted < branchTotal) writer.byte(TAG_FORK);
    writer.byte(TAG_ATTESTATION);
    serializeAttestation(writer, attestation);
  }
  for (const branch of stamp.ops) {
    emitted += 1;
    if (emitted < branchTotal) writer.byte(TAG_FORK);
    serializeOp(writer, branch.op);
    serializeTimestamp(writer, branch.stamp);
  }
}

/** Serialize a detached .ots proof file (sha256 file-hash profile). */
export function serializeOtsProof(proof: OtsProof): Uint8Array {
  if (proof.digest.length !== 32) throw new OtsError('digest must be 32 bytes (sha256)');
  const writer = new ByteWriter();
  writer.bytes(OTS_HEADER_MAGIC);
  writer.varuint(OTS_MAJOR_VERSION);
  writer.byte(OP_SHA256);
  writer.bytes(proof.digest);
  serializeTimestamp(writer, proof.timestamp);
  return writer.toBytes();
}

// --- deserialization ---------------------------------------------------------

interface ParseBudget {
  nodes: number;
}

function parseOpTag(reader: ByteReader, tag: number): OtsOp {
  switch (tag) {
    case OP_SHA1:
      return { op: 'sha1' };
    case OP_RIPEMD160:
      return { op: 'ripemd160' };
    case OP_SHA256:
      return { op: 'sha256' };
    case OP_KECCAK256:
      return { op: 'keccak256' };
    case OP_REVERSE:
      return { op: 'reverse' };
    case OP_HEXLIFY:
      return { op: 'hexlify' };
    case OP_APPEND:
      return { op: 'append', operand: reader.varbytes() };
    case OP_PREPEND:
      return { op: 'prepend', operand: reader.varbytes() };
    default:
      throw new OtsError(`unknown op tag 0x${tag.toString(16)}`);
  }
}

function parseAttestation(reader: ByteReader): OtsAttestation {
  const tag = reader.bytes(8);
  const payload = new ByteReader(reader.varbytes());
  const tagHex = bytesToHex(tag);
  if (tagHex === bytesToHex(PENDING_ATTESTATION_TAG)) {
    const uri = new TextDecoder().decode(payload.varbytes());
    // A canonical pending attestation payload is EXACTLY the calendar URI. Any
    // trailing bytes make a non-canonical .ots that would re-serialize to
    // different bytes (the serializer emits only the URI) — reject it, matching
    // the top-level `!reader.exhausted` checks, so round-trip fidelity holds
    // (S8/C3). The unknown-tag branch below keeps opaque payloads verbatim.
    if (!payload.exhausted) throw new OtsError('trailing bytes in pending attestation payload');
    return { kind: 'pending', uri };
  }
  if (tagHex === bytesToHex(BITCOIN_ATTESTATION_TAG)) {
    const height = payload.varuint();
    // A canonical Bitcoin attestation payload is EXACTLY the block height.
    if (!payload.exhausted) throw new OtsError('trailing bytes in bitcoin attestation payload');
    return { kind: 'bitcoin', height };
  }
  // Unknown attestation (litecoin/ethereum/… tags exist in the wild): keep
  // the FULL opaque payload so a re-serialized .ots stays byte-faithful for
  // stock OTS clients (review S6-M3).
  return { kind: 'unknown', tag: tagHex, payload: bytesToHex(payload.rest()) };
}

async function parseTimestamp(
  reader: ByteReader,
  msg: Uint8Array,
  depth: number,
  budget: ParseBudget
): Promise<OtsTimestamp> {
  if (depth > MAX_DEPTH) throw new OtsError('timestamp tree too deep');
  budget.nodes += 1;
  if (budget.nodes > MAX_NODES) throw new OtsError('timestamp tree too large');
  const stamp: OtsTimestamp = { msg, attestations: [], ops: [] };

  const branch = async (tag: number): Promise<void> => {
    if (tag === TAG_ATTESTATION) {
      stamp.attestations.push(parseAttestation(reader));
      return;
    }
    const op = parseOpTag(reader, tag);
    const result = await applyOp(op, msg);
    stamp.ops.push({ op, stamp: await parseTimestamp(reader, result, depth + 1, budget) });
  };

  let tag = reader.byte();
  while (tag === TAG_FORK) {
    await branch(reader.byte());
    tag = reader.byte();
  }
  await branch(tag);
  return stamp;
}

/**
 * Parse a calendar's POST /digest response: a serialized timestamp whose
 * initial message is the submitted digest.
 */
export async function parseCalendarTimestamp(
  data: Uint8Array,
  digest: Uint8Array
): Promise<OtsTimestamp> {
  const reader = new ByteReader(data);
  const stamp = await parseTimestamp(reader, digest, 0, { nodes: 0 });
  if (!reader.exhausted) throw new OtsError('trailing bytes after timestamp');
  return stamp;
}

/** Parse a detached .ots proof file (sha256 profile only — ours). */
export async function parseOtsProof(data: Uint8Array): Promise<OtsProof> {
  const reader = new ByteReader(data);
  const magic = reader.bytes(OTS_HEADER_MAGIC.length);
  if (bytesToHex(magic) !== bytesToHex(OTS_HEADER_MAGIC)) {
    throw new OtsError('not an OpenTimestamps proof (bad magic)');
  }
  const version = reader.varuint();
  if (version !== OTS_MAJOR_VERSION) throw new OtsError(`unsupported version ${version}`);
  const hashOp = reader.byte();
  if (hashOp !== OP_SHA256) throw new OtsError('only sha256 file digests are supported');
  const digest = reader.bytes(32);
  const timestamp = await parseTimestamp(reader, digest, 0, { nodes: 0 });
  if (!reader.exhausted) throw new OtsError('trailing bytes after proof');
  return { digest, timestamp };
}

// --- tree queries ------------------------------------------------------------

export interface PendingCommitment {
  uri: string;
  /** The message the calendar committed to (what /timestamp/<hex> is keyed by). */
  commitment: Uint8Array;
  stamp: OtsTimestamp;
}

/** All pending calendar attestations in a tree, with their commitment messages. */
export function collectPending(stamp: OtsTimestamp): PendingCommitment[] {
  const found: PendingCommitment[] = [];
  const walk = (node: OtsTimestamp): void => {
    for (const attestation of node.attestations) {
      if (attestation.kind === 'pending') {
        found.push({ uri: attestation.uri, commitment: node.msg, stamp: node });
      }
    }
    for (const branch of node.ops) walk(branch.stamp);
  };
  walk(stamp);
  return found;
}

/** All Bitcoin block attestations in a tree (non-empty ⇒ upgraded/confirmed). */
export function collectBitcoin(stamp: OtsTimestamp): { height: number }[] {
  const found: { height: number }[] = [];
  const walk = (node: OtsTimestamp): void => {
    for (const attestation of node.attestations) {
      if (attestation.kind === 'bitcoin') found.push({ height: attestation.height });
    }
    for (const branch of node.ops) walk(branch.stamp);
  };
  walk(stamp);
  return found;
}

// --- calendar HTTP -----------------------------------------------------------

/** The long-standing public calendar pool (same defaults as the official clients). */
export const DEFAULT_CALENDARS = [
  'https://alice.btc.calendar.opentimestamps.org',
  'https://bob.btc.calendar.opentimestamps.org',
  'https://finney.calendar.eternitywall.com',
];

const OTS_MIME = 'application/vnd.opentimestamps.v1';

export interface CalendarClientOptions {
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

/** Submit a digest to one calendar; returns its timestamp extension of the digest. */
export async function calendarSubmit(
  calendarUrl: string,
  digest: Uint8Array,
  options: CalendarClientOptions = {}
): Promise<OtsTimestamp> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const response = await fetchImpl(`${calendarUrl}/digest`, {
    method: 'POST',
    headers: { accept: OTS_MIME, 'content-type': 'application/octet-stream' },
    body: digest as Uint8Array<ArrayBuffer>,
    signal: AbortSignal.timeout(options.timeoutMs ?? 10_000),
  });
  if (!response.ok) {
    throw new OtsError(`calendar ${calendarUrl} refused digest: ${response.status}`);
  }
  return parseCalendarTimestamp(await readBoundedBody(response, calendarUrl), digest);
}

/** Read a calendar response, refusing (not buffering) anything over the size bound. */
async function readBoundedBody(response: Response, calendarUrl: string): Promise<Uint8Array> {
  const declared = Number(response.headers.get('content-length') ?? '0');
  if (declared > MAX_CALENDAR_RESPONSE_BYTES) {
    throw new OtsError(`calendar ${calendarUrl} response of ${declared} bytes exceeds the bound`);
  }
  if (response.body === null) return new Uint8Array(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > MAX_CALENDAR_RESPONSE_BYTES) {
      await reader.cancel().catch(() => undefined);
      throw new OtsError(`calendar ${calendarUrl} response exceeds ${MAX_CALENDAR_RESPONSE_BYTES} bytes`);
    }
    chunks.push(value);
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.length;
  }
  return body;
}

/**
 * Ask a calendar for the Bitcoin-attested extension of a pending commitment.
 * Returns null while the calendar has not yet aggregated into Bitcoin (404).
 */
export async function calendarUpgrade(
  pending: PendingCommitment,
  options: CalendarClientOptions = {}
): Promise<OtsTimestamp | null> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const response = await fetchImpl(
    `${pending.uri}/timestamp/${bytesToHex(pending.commitment)}`,
    { headers: { accept: OTS_MIME }, signal: AbortSignal.timeout(options.timeoutMs ?? 10_000) }
  );
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new OtsError(`calendar ${pending.uri} upgrade failed: ${response.status}`);
  }
  return parseCalendarTimestamp(await readBoundedBody(response, pending.uri), pending.commitment);
}
